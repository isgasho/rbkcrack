use crate::attack::Attack;
use crate::file::*;
use crate::Arguments;
use failure::{format_err, Error};
use log::debug;

pub struct Data {
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub keystream: Vec<u8>,
    pub offset: i32,
}

impl Data {
    pub const HEADER_SIZE: usize = 12;

    pub fn new(args: &Arguments) -> Result<Data, Error> {
        let offset = args.offset.unwrap_or(0);
        let plainsize = args.plainsize.unwrap_or(std::usize::MAX);

        // check that offset is not too small
        if Data::HEADER_SIZE as i32 + offset < 0 {
            return Err(format_err!("offset is too small"));
        }

        // load known plaintext
        let plaintext =
            if let (Some(archivename), Some(entryname)) = (&args.plainzip, &args.plainfile) {
                load_zip_entry(archivename, entryname, plainsize)?
            } else {
                load_raw_file(args.plainfile.as_ref().unwrap(), plainsize)?
            };
        debug!(
            "loaded plain {}, size {}",
            args.plainzip.as_ref().unwrap(),
            plaintext.len()
        );
        // check that plaintext is big enough
        if plaintext.len() < Attack::SIZE {
            return Err(format_err!("plaintext is too small"));
        }

        // load ciphertext needed by the attack
        let to_read = Data::HEADER_SIZE + offset as usize + plaintext.len();
        let ciphertext = if let Some(archivename) = &args.encryptedzip {
            load_zip_entry(archivename, &args.cipherfile, to_read)?
        } else {
            load_raw_file(&args.cipherfile, to_read)?
        };
        debug!(
            "loaded cipher {}, size {}",
            args.encryptedzip.as_ref().unwrap(),
            ciphertext.len()
        );

        // check that ciphertext is valid
        if plaintext.len() > ciphertext.len() {
            return Err(format_err!("ciphertext is smaller than plaintext"));
        } else if Data::HEADER_SIZE + offset as usize + plaintext.len() > ciphertext.len() {
            return Err(format_err!("offset is too large"));
        }

        // compute keystream
        let keystream = plaintext
            .iter()
            .zip(ciphertext.iter().skip(Data::HEADER_SIZE + offset as usize))
            .map(|(x, y)| x ^ y)
            .collect();
        Ok(Data {
            ciphertext,
            plaintext,
            keystream,
            offset,
        })
    }
}
