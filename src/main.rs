use chrono::Local;
use failure::{format_err, Error};
use flate2::write::DeflateDecoder;
use log::debug;
use rayon::prelude::*;
use rbkcrack::{file, progress, Arguments, Attack, Data, Keys, KeystreamTab, Zreduction};
use structopt::StructOpt;

use std::io::prelude::*;
use std::process;
use std::sync::{Arc, Mutex, RwLock};

fn now() -> String {
    Local::now().format("%T").to_string()
}

fn find_keys(args: &Arguments) -> Result<Vec<Keys>, Error> {
    // load data
    let data = Data::new(args)?;

    // generate and reduce Zi[2,32) values
    let mut zr = Zreduction::new(&data.keystream);
    zr.generate();
    println!("Generated {} Z values.", zr.size());

    if data.keystream.len() > Attack::SIZE {
        println!(
            "[{}] Z reduction using {} extra bytes of known plaintext",
            now(),
            data.keystream.len() - Attack::SIZE
        );
        zr.reduce();
        println!("\n{} values remaining.", zr.size());
    }

    // iterate over remaining Zi[2,32) values
    let attack = Attack::new(&data, zr.get_index() + 1 - Attack::SIZE);
    let done = Arc::new(Mutex::new(0));
    let should_stop = Arc::new(RwLock::new(false));
    let size = zr.size();
    println!(
        "[{}] Attack on {} Z values at index {}",
        now(),
        size,
        data.offset + zr.get_index() as i32
    );

    let keysvec = zr
        .get_zi_2_32_vector()
        .into_par_iter()
        .filter_map(|&z| {
            if *should_stop.read().unwrap() {
                return None;
            }

            *done.lock().unwrap() += 1;
            progress(*done.lock().unwrap(), size);

            let mut attack = attack.clone();
            if attack.carry_out(z) {
                let possible_keys = attack.get_keys();

                if args.exhaustive {
                    println!("\rKeys: {}", possible_keys);
                } else {
                    *should_stop.write().unwrap() = true;
                }
                Some(possible_keys)
            } else {
                None
            }
        })
        .collect::<Vec<Keys>>();

    if size != 0 {
        println!();
    }

    // print the keys
    if keysvec.is_empty() {
        Err(format_err!("Could not find the keys."))
    } else {
        Ok(keysvec)
    }
}

fn decipher(args: &Arguments, keys: &mut Keys) -> Result<(), Error> {
    let mut ciphersize = 0;
    let cipherstream = if let Some(archivename) = &args.encryptedzip {
        file::open_zip_entry(archivename, &args.cipherfile, &mut ciphersize)?
    } else {
        file::open_raw_file(&args.cipherfile, &mut ciphersize)?
    };

    let mut decipheredstream = file::open_output(args.decipheredfile.as_ref().unwrap())?;
    let keystreamtab = KeystreamTab::new();

    let mut cipher = cipherstream.bytes();
    let mut i = 0;
    while i < Data::HEADER_SIZE {
        let p = cipher.next().unwrap().unwrap() ^ keystreamtab.get_byte(keys.get_z());
        keys.update(p);
        i += 1;
    }

    let mut vec = Vec::with_capacity(ciphersize - i);
    debug!("deciphering");
    for b in cipher.take(ciphersize - i) {
        let p: u8 = b.unwrap() ^ keystreamtab.get_byte(keys.get_z());
        keys.update(p);
        vec.push(p);
    }
    debug!("deciphered: {} bytes", vec.len());
    if args.unzip {
        debug!("decompressing");
        let mut deflater = DeflateDecoder::new(decipheredstream);
        deflater.write_all(&vec)?;
    } else {
        decipheredstream.write_all(&vec)?;
    }
    Ok(())
}

fn main() {
    env_logger::init();

    let args: Arguments = Arguments::from_args();

    let mut keysvec = vec![];

    if args.key.len() == 3 {
        keysvec.push(args.key.iter().cloned().collect::<Keys>());
    } else {
        match find_keys(&args) {
            Ok(v) => {
                println!("[{}] Keys", now());
                for keys in &v {
                    println!("{}", keys);
                }
                keysvec.extend(v);
            }
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    };

    if args.decipheredfile.is_some() {
        if keysvec.len() > 1 {
            println!("Deciphering data using the keys {}", keysvec[0]);
            println!("Use the command line option -k to provide other keys.");
        }
        decipher(&args, &mut keysvec[0]).unwrap_or_else(|e| {
            eprintln!("decipher error: {}", e);
            process::exit(1);
        });
        println!("Wrote deciphered text.");
    }
}
