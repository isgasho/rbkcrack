#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;
extern crate chrono;
extern crate rbkcrack;

use chrono::Local;
use clap::App;
use failure::Error;
use rbkcrack::{file, progress, Attack, Data, Keys, KeystreamTab, Zreduction};
use std::io::prelude::*;
use std::process;
use std::u32;

fn now() -> String {
    Local::now().format("%T").to_string()
}

fn find_keys(
    cipherarchive: &str,
    plainarchive: &str,
    cipherfile: &str,
    plainfile: &str,
    offset: i32,
) -> Result<Keys, Error> {
    // load data
    let data = Data::new(cipherarchive, cipherfile, plainarchive, plainfile, offset)?;

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
    let mut attack = Attack::new(&data, zr.get_index() - 11);
    let mut done = 1;
    let mut found = false;
    let size = zr.size();
    println!(
        "[{}] Attack on {} Z values at index {}",
        now(),
        size,
        data.offset + zr.get_index() as i32
    );

    for &it in zr.get_zi_2_32_vector() {
        if attack.carry_out(it) {
            found = true;
            break;
        }
        done += 1;
        progress(done, size);
    }
    println!();

    // print the keys
    if found {
        Ok(attack.get_keys())
    } else {
        Err(format_err!("Could not find the keys."))
    }
}

fn decipher(
    keys: &mut Keys,
    cipherarchive: &str,
    cipherfile: &str,
    decipheredfile: &str,
) -> Result<(), Error> {
    let cipherstream = if cipherarchive.is_empty() {
        file::open_input(cipherfile)?
    } else {
        file::open_input_zip_entry(cipherarchive, cipherfile)?
    };
    let ciphersize = cipherstream.len();
    let mut decipheredstream = file::open_output(decipheredfile)?;
    let keystreamtab = KeystreamTab::new();

    let mut cipher = cipherstream.iter();
    let mut i = 0;
    while i < Data::HEADER_SIZE {
        let p = cipher.next().unwrap() ^ keystreamtab.get_byte(keys.get_z());
        keys.update(p);
        i += 1;
    }

    let mut vec = Vec::with_capacity(ciphersize - i);
    while i < ciphersize {
        let p = cipher.next().unwrap() ^ keystreamtab.get_byte(keys.get_z());
        keys.update(p);
        vec.push(p);
        i += 1;
    }
    decipheredstream.write_all(&vec)?;

    Ok(())
}

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let cipherarchive = matches.value_of("encryptedzip").unwrap_or("");
    let plainarchive = matches.value_of("plainzip").unwrap_or("");

    let cipherfile = matches.value_of("cipherfile").unwrap();
    let plainfile = matches.value_of("plainfile").unwrap();
    let offset = matches
        .value_of("offset")
        .unwrap_or("0")
        .parse::<i32>()
        .unwrap_or_else(|e| {
            eprintln!("offset error: {}", e);
            std::process::exit(1);
        });

    let key = if matches.occurrences_of("key") != 0 {
        let key: Vec<&str> = matches.values_of("key").unwrap().collect();
        key.iter()
            .map(|s| {
                s.parse::<u32>().unwrap_or_else(|_e| {
                    u32::from_str_radix(s, 16).unwrap_or_else(|_e| {
                        eprintln!("key must be decimal or hexadecimal.");
                        process::exit(1);
                    })
                })
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };

    let mut keys = if key.len() == 3 {
        let mut k = Keys::new();
        k.set_keys(key[0], key[1], key[2]);
        k
    } else {
        match find_keys(cipherarchive, plainarchive, cipherfile, plainfile, offset) {
            Ok(keys) => {
                println!(
                    "[{}] Keys\n{:x} {:x} {:x}",
                    now(),
                    keys.get_x(),
                    keys.get_y(),
                    keys.get_z()
                );
                keys
            }
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1);
            }
        }
    };

    let decipheredfile = matches.value_of("decipheredfile").unwrap_or("");
    if decipheredfile != "" {
        decipher(&mut keys, cipherarchive, cipherfile, decipheredfile).unwrap_or_else(|e| {
            eprintln!("decipher error: {}", e);
            process::exit(1);
        });
        println!("Wrote deciphered text.");
    }
}
