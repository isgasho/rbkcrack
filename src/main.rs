use chrono::Local;
use clap::{load_yaml, App};
use failure::{format_err, Error};
use flate2::write::DeflateDecoder;
use log::debug;
use rbkcrack::{file, progress, Attack, Data, Keys, KeystreamTab, Zreduction};
use std::io::prelude::*;
use std::process;
use std::u32;
use std::usize;

fn now() -> String {
    Local::now().format("%T").to_string()
}

fn find_keys(
    cipherarchive: &str,
    plainarchive: &str,
    cipherfile: &str,
    plainfile: &str,
    offset: i32,
    plainsize: usize,
    exhaustive: bool,
) -> Result<Vec<Keys>, Error> {
    // load data
    let data = Data::new(
        cipherarchive,
        cipherfile,
        plainarchive,
        plainfile,
        offset,
        plainsize,
    )?;

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
    let mut attack = Attack::new(&data, zr.get_index() + 1 - Attack::SIZE);
    let mut done = 0;
    let mut keysvec = vec![];
    let size = zr.size();
    println!(
        "[{}] Attack on {} Z values at index {}",
        now(),
        size,
        data.offset + zr.get_index() as i32
    );

    // TODO: 并行
    for &it in zr.get_zi_2_32_vector() {
        if attack.carry_out(it) {
            let possible_keys = attack.get_keys();

            if exhaustive {
                keysvec.push(possible_keys);
                break;
            } else {
                println!("\nKeys: {}", possible_keys);
                keysvec.push(possible_keys);
            }
        }
        done += 1;
        progress(done, size);
    }

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

fn decipher(
    keys: &mut Keys,
    cipherarchive: &str,
    cipherfile: &str,
    decipheredfile: &str,
    unzip: bool,
) -> Result<(), Error> {
    let mut ciphersize = 0;
    let cipherstream = if cipherarchive.is_empty() {
        file::open_raw_file(cipherfile, &mut ciphersize)?
    } else {
        file::open_zip_entry(cipherarchive, cipherfile, &mut ciphersize)?
    };

    let mut decipheredstream = file::open_output(decipheredfile)?;
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
    if unzip {
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

    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let cipherarchive = matches.value_of("encryptedzip").unwrap_or("");
    let plainarchive = matches.value_of("plainzip").unwrap_or("");

    let cipherfile = matches.value_of("cipherfile").unwrap_or("");
    let plainfile = matches.value_of("plainfile").unwrap_or("");

    let offset = matches.value_of("offset").map_or(0, |s| {
        s.parse::<i32>().unwrap_or_else(|e| {
            eprintln!("offset error: {}", e);
            std::process::exit(1);
        })
    });
    let plainsize = matches.value_of("plainsize").map_or(usize::MAX, |s| {
        s.parse::<usize>().unwrap_or_else(|e| {
            eprintln!("plainsize error: {}", e);
            std::process::exit(1);
        })
    });
    let exhaustive = matches.occurrences_of("exhaustive") != 1;

    let mut keysvec = vec![];

    if matches.occurrences_of("key") != 0 {
        let keys = matches
            .values_of("key")
            .unwrap()
            .map(|s| {
                s.parse::<u32>().unwrap_or_else(|_e| {
                    u32::from_str_radix(s, 16).unwrap_or_else(|_e| {
                        eprintln!("key must be decimal or hexadecimal.");
                        process::exit(1);
                    })
                })
            })
            .collect::<Keys>();
        keysvec.push(keys);
    } else {
        match find_keys(
            cipherarchive,
            plainarchive,
            cipherfile,
            plainfile,
            offset,
            plainsize,
            exhaustive,
        ) {
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

    let unzip = matches.occurrences_of("unzip") != 0;
    let decipheredfile = matches.value_of("decipheredfile").unwrap_or("");
    if decipheredfile != "" {
        if keysvec.len() > 1 {
            println!("Deciphering data using the keys {}", keysvec[0]);
            println!("Use the command line option -k to provide other keys.");
        }
        decipher(
            &mut keysvec[0],
            cipherarchive,
            cipherfile,
            decipheredfile,
            unzip,
        )
        .unwrap_or_else(|e| {
            eprintln!("decipher error: {}", e);
            process::exit(1);
        });
        println!("Wrote deciphered text.");
    }
}
