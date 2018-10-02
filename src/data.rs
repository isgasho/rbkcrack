use super::attack::*;
use super::failure::Error;
use super::file::*;

pub struct Data {
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub keystream: Vec<u8>,
    pub offset: i32,
}

impl Data {
    pub const HEADER_SIZE: usize = 12;

    pub fn new(
        cipherarchive: &str,
        cipherfile: &str,
        plainarchive: &str,
        plainfile: &str,
        offset: i32,
    ) -> Result<Data, Error> {
        // check that offset is not too small
        if Data::HEADER_SIZE as i32 + offset < 0 {
            return Err(format_err!("offset is too small"));
        }

        // load known plaintext
        let plaintext = if plainarchive.is_empty() {
            load_file(plainfile, std::usize::MAX)?
        } else {
            load_zip_entry(plainarchive, plainfile, std::usize::MAX)?
        };

        // check that plaintext is big enough
        if plaintext.len() < Attack::SIZE {
            return Err(format_err!("plaintext is too small"));
        }

        // load ciphertext needed by the attack
        let to_read = Data::HEADER_SIZE + offset as usize + plaintext.len();
        let ciphertext = if cipherarchive.is_empty() {
            load_file(cipherfile, to_read)?
        } else {
            load_zip_entry(cipherarchive, cipherfile, to_read)?
        };

        // check that ciphertext is valid
        if plaintext.len() > ciphertext.len() {
            return Err(format_err!("ciphertext is smaller than plaintext"));
        } else if Data::HEADER_SIZE + offset as usize + plaintext.len()
            > ciphertext.len()
        {
            return Err(format_err!("offset is too large"));
        }

        // compute keystream
        let keystream = plaintext
            .iter()
            .zip(
                ciphertext
                    .iter()
                    .skip(Data::HEADER_SIZE + offset as usize),
            )
            .map(|(x, y)| x ^ y)
            .collect();
        Ok(Data{
            ciphertext,
            plaintext,
            keystream,
            offset,
        })
    }
}
