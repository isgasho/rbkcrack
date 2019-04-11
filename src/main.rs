use chrono::Local;
use failure::Error;
use flate2::write::DeflateDecoder;
use log::debug;
use rayon::prelude::*;
use rbkcrack::{file, progress, Arguments, Attack, Data, Keys, KeystreamTab, Zreduction};
use structopt::StructOpt;

use std::io::prelude::*;
use std::io::stdout;
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
        // 将任务每 1000 个分为一组, 每组再并行检测
        // 保证顺序大抵是从小到大的
        .chunks(1000)
        .map(|chunk| {
            chunk
                .into_par_iter()
                .filter_map(|&z| {
                    if *should_stop.read().unwrap() {
                        return None;
                    }

                    *done.lock().unwrap() += 1;
                    progress(*done.lock().unwrap(), size);
                    stdout().flush().unwrap();

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
                .collect::<Vec<Keys>>()
        })
        .flatten()
        .collect::<Vec<_>>();

    if size != 0 {
        println!();
    }

    // return the keys
    Ok(keysvec)
}

fn decipher(args: &Arguments, keys: &mut Keys) -> Result<(), Error> {
    let mut cipher_size = 0;
    let cipher_stream =
        if let (Some(zip_path), Some(entry_name)) = (&args.cipher_zip, &args.cipher_file) {
            file::open_zip_entry(zip_path, entry_name, &mut cipher_size)?
        } else {
            file::open_raw_file(args.cipher_file.as_ref().unwrap(), &mut cipher_size)?
        };

    let mut deciphered_stream = file::open_output(args.deciphered_file.as_ref().unwrap())?;
    let keystreamtab = KeystreamTab::new();

    debug!("deciphering");
    let decrypted_text = cipher_stream
        .bytes()
        .take(cipher_size)
        .map(|b| {
            let p = b.unwrap() ^ keystreamtab.get_byte(keys.get_z());
            keys.update(p);
            p
        })
        .collect::<Vec<_>>();

    debug!(
        "deciphered: {} bytes",
        decrypted_text.len() - Data::HEADER_SIZE
    );
    if args.unzip {
        debug!("decompressing");
        let mut deflater = DeflateDecoder::new(deciphered_stream);
        deflater.write_all(&decrypted_text[Data::HEADER_SIZE..])?;
    } else {
        deciphered_stream.write_all(&decrypted_text[Data::HEADER_SIZE..])?;
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    env_logger::init();

    let args: Arguments = Arguments::from_args();

    debug!("{:?}", args);

    let mut keysvec = vec![];

    if args.keys.len() == 3 {
        keysvec.push(args.keys.iter().cloned().collect::<Keys>());
    } else {
        let result = find_keys(&args)?;
        if !result.is_empty() {
            println!("[{}] Keys", now());
            for keys in &result {
                println!("{}", keys);
            }
            keysvec.extend(result);
        } else {
            eprintln!("Could not find the keys.");
            process::exit(1);
        }
    };

    if args.deciphered_file.is_some() {
        if keysvec.len() > 1 {
            println!("Deciphering data using the keys {}", keysvec[0]);
            println!("Use the command line option -k to provide other keys.");
        }
        decipher(&args, &mut keysvec[0])?;
        println!("Wrote deciphered text.");
    }
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => (),
        Err(e) => eprintln!("{}", e),
    }
}
