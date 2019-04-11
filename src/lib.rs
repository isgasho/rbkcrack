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
    #[structopt(short = "c", required_unless = "auto", allow_hyphen_values = true)]
    pub cipher_file: Option<String>,

    /// File containing the known plaintext
    #[structopt(
        short = "p",
        raw(required_unless_one = r#"&["key", "auto"]"#),
        allow_hyphen_values = true
    )]
    pub plain_file: Option<String>,

    /// Internal password representation as three 32-bits integers in hexadecimal (requires -d)
    #[structopt(short = "k", parse(try_from_str = "parse_hex"))]
    pub key: Vec<u32>,

    /// Zip archive containing cipher_file
    #[structopt(short = "C")]
    pub cipher_zip: Option<String>,

    /// Zip archive containing plain_file
    #[structopt(short = "P")]
    pub plain_zip: Option<String>,

    /// Known plaintext offset relative to ciphertext without encryption header (may be negative)
    #[structopt(short = "o", allow_hyphen_values = true)]
    pub offset: Option<i32>,

    /// Maximum number of bytes of plaintext to read
    #[structopt(short = "t")]
    pub plain_size: Option<usize>,

    /// Exhaustively try all the keys remaining after Z reduction
    #[structopt(short = "e")]
    pub exhaustive: bool,

    /// File to write the deciphered text
    #[structopt(short = "d")]
    pub deciphered_file: Option<String>,

    /// Not only decipher but also unzip
    #[structopt(short = "u")]
    pub unzip: bool,

    /// Find entry by CRC32 automatically
    #[structopt(short = "a")]
    pub auto: bool,
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
            cipher_zip: Some("./example/cipher.zip".into()),
            cipher_file: Some("file".into()),
            plain_zip: Some("./example/plain.zip".into()),
            plain_file: Some("file".into()),
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
