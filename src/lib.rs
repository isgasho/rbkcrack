#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate chrono;
extern crate zip;

mod attack;
mod crc32_tab;
mod data;
mod keys;
mod keystream_tab;
mod mult_tab;
mod utils;
mod zreduction;

pub mod file;

pub use self::attack::Attack;
pub use self::data::Data;
pub use self::keys::Keys;
pub use self::keystream_tab::KeystreamTab;
pub use self::zreduction::Zreduction;

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

    #[test]
    #[ignore]
    fn crack() {
        let data = Data::new(
            "./example/cipher.zip",
            "file",
            "./example/plain.zip",
            "file",
            0,
        )
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
