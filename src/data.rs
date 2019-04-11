use crate::attack::Attack;
use crate::file::*;
use crate::Arguments;
use failure::{format_err, Error};
use log::debug;

#[derive(Debug, Clone)]
pub struct Data {
    pub cipher_text: Vec<u8>,
    pub plain_text: Vec<u8>,
    pub keystream: Vec<u8>,
    pub offset: i32,
}

impl Data {
    pub const HEADER_SIZE: usize = 12;

    pub fn new(args: &Arguments) -> Result<Data, Error> {
        let offset = args.offset.unwrap_or(0);
        // check that offset is not too small
        if Data::HEADER_SIZE as i32 + offset < 0 {
            return Err(format_err!("offset is too small"));
        }

        let mut plain_text;
        let mut cipher_text;

        if args.auto {
            let (a, b) = auto_load_file(
                args.plain_zip.as_ref().unwrap(),
                args.cipher_zip.as_ref().unwrap(),
            )?;
            plain_text = a;
            cipher_text = b;
        } else {
            // load known plaintext
            plain_text = Self::load_plain(args)?;

            // load ciphertext needed by the attack
            cipher_text = Self::load_cipher(args, &plain_text)?;
        }

        // compute keystream
        let keystream = plain_text
            .iter()
            .zip(cipher_text.iter().skip(Data::HEADER_SIZE + offset as usize))
            .map(|(x, y)| x ^ y)
            .collect();
        Ok(Data {
            cipher_text,
            plain_text,
            keystream,
            offset,
        })
    }

    /// load known plaintext
    fn load_plain(args: &Arguments) -> Result<Vec<u8>, Error> {
        let plain_size = args.plain_size.unwrap_or(std::usize::MAX);

        let plain_text =
            if let (Some(zip_path), Some(entry_name)) = (&args.plain_zip, &args.plain_file) {
                read_zip_entry(zip_path, entry_name, plain_size)?
            } else {
                read_raw_file(args.plain_file.as_ref().unwrap(), plain_size)?
            };
        debug!(
            "loaded plain {}, size {}",
            args.plain_file.as_ref().unwrap(),
            plain_text.len()
        );
        // check that plaintext is big enough
        if plain_text.len() < Attack::SIZE {
            return Err(format_err!("plaintext is too small"));
        }
        Ok(plain_text)
    }

    /// load ciphertext needed by the attack
    fn load_cipher(args: &Arguments, plain_text: &[u8]) -> Result<Vec<u8>, Error> {
        let offset = args.offset.unwrap_or(0);
        let to_read = Data::HEADER_SIZE + offset as usize + plain_text.len();
        let cipher_text =
            if let (Some(zip_path), Some(entry_name)) = (&args.cipher_zip, &args.cipher_file) {
                read_zip_entry(zip_path, entry_name, to_read)?
            } else {
                read_raw_file(&args.cipher_file.as_ref().unwrap(), to_read)?
            };
        debug!(
            "loaded cipher {}, size {}",
            args.cipher_file.as_ref().unwrap(),
            cipher_text.len()
        );

        // check that ciphertext is valid
        if plain_text.len() > cipher_text.len() {
            return Err(format_err!("ciphertext is smaller than plaintext"));
        } else if Data::HEADER_SIZE + offset as usize + plain_text.len() > cipher_text.len() {
            return Err(format_err!("offset is too large"));
        }
        Ok(cipher_text)
    }
}
