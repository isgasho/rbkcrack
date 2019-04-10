extern crate structopt;

use structopt::StructOpt;

pub use crate::attack::Attack;
pub use crate::data::Data;
pub use crate::keys::Keys;
pub use crate::keystream_tab::KeystreamTab;
pub use crate::zreduction::Zreduction;
use std::num::ParseIntError;

mod attack;
mod crc32_tab;
mod data;
mod keys;
mod keystream_tab;
mod mult_tab;
mod utils;
mod zreduction;

pub mod file;

fn parse_hex(src: &str) -> Result<u32, ParseIntError> {
    u32::from_str_radix(src, 16)
}

#[derive(StructOpt, Debug, Default)]
#[structopt(name = "rbkcrack")]
pub struct Arguments {
    /// File containing the ciphertext
    #[structopt(short = "c")]
    pub cipherfile: String,

    /// File containing the known plaintext
    #[structopt(short = "p", required_unless = "key")]
    pub plainfile: Option<String>,

    /// Internal password representation as three 32-bits integers in hexadecimal (requires -d)
    #[structopt(short = "k", parse(try_from_str = "parse_hex"))]
    pub key: Vec<u32>,

    /// Zip archive containing cipherfile
    #[structopt(short = "C")]
    pub encryptedzip: Option<String>,

    /// Zip archive containing plainfile
    #[structopt(short = "P")]
    pub plainzip: Option<String>,

    /// Known plaintext offset relative to ciphertext without encryption header (may be negative)
    #[structopt(short = "o", allow_hyphen_values = true)]
    pub offset: Option<i32>,

    /// Maximum number of bytes of plaintext to read
    #[structopt(short = "t")]
    pub plainsize: Option<usize>,

    /// Exhaustively try all the keys remaining after Z reduction
    #[structopt(short = "e")]
    pub exhaustive: bool,

    /// File to write the deciphered text
    #[structopt(short = "d")]
    pub decipheredfile: Option<String>,

    /// not only decipher but also unzip
    #[structopt(short = "u")]
    pub unzip: bool,
}

#[inline]
pub fn progress(done: usize, total: usize) {
    print!(
        "\r{:.2} % ({} / {})",
        done as f32 / total as f32 * 100.0,
        done,
        total
    );
}

#[cfg(test)]
mod tests {
    use super::{Attack, Data, Zreduction};
    use crate::Arguments;

    #[test]
    #[ignore]
    fn crack() {
        let data = Data::new(&Arguments {
            encryptedzip: Some("./example/cipher.zip".into()),
            cipherfile: "file".into(),
            plainzip: Some("./example/plain.zip".into()),
            plainfile: Some("file".into()),
            ..Default::default()
        })
        .unwrap();

        let mut zr = Zreduction::new(&data.keystream);
        zr.generate();
        zr.reduce();

        let mut attack = Attack::new(&data, zr.get_index() - 11);
        for &it in zr.get_zi_2_32_vector() {
            if attack.carry_out(it) {
                println!("\nfound!");
                break;
            }
        }

        let keys = attack.get_keys();

        assert_eq!(0x8879dfed, keys.get_x());
        assert_eq!(0x14335b6b, keys.get_y());
        assert_eq!(0x8dc58b53, keys.get_z());
    }
}
