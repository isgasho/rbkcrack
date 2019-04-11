use crate::crc32_tab::Crc32Tab;
use crate::keystream_tab::KeystreamTab;
use crate::mult_tab::MultTab;
use crate::utils::*;
use std::fmt;
use std::iter::FromIterator;

/// Keys defining the cipher state
pub struct Keys {
    x: u32,
    y: u32,
    z: u32,
    crc32tab: Crc32Tab,
    keystream: KeystreamTab,
}

impl Default for Keys {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<u32> for Keys {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        let mut key = Keys::new();
        let mut iter = iter.into_iter();
        key.set_keys(
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        );
        key
    }
}

impl fmt::Display for Keys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x} {:08x} {:08x}", self.x, self.y, self.z)
    }
}

impl Keys {
    /// Constructor
    pub fn new() -> Keys {
        Keys {
            x: 0x1234_5678,
            y: 0x2345_6789,
            z: 0x3456_7890,
            crc32tab: Crc32Tab::new(),
            keystream: KeystreamTab::new(),
        }
    }

    pub fn set_keys(&mut self, x: u32, y: u32, z: u32) {
        self.x = x;
        self.y = y;
        self.z = z;
    }

    // TODO: 这一堆 wrapping, 真的会溢出? 为啥会溢出?
    /// Update the state with a plaintext byte
    pub fn update(&mut self, p: u8) {
        self.x = self.crc32tab.crc32(self.x, p);
        self.y = (self.y + u32::from(lsb(self.x))).wrapping_mul(MultTab::MULT) + 1;
        self.z = self.crc32tab.crc32(self.z, msb(self.y));
    }

    /// Update the state backward with a ciphertext byte
    pub fn update_backword(&mut self, c: u8) {
        self.z = self.crc32tab.crc32inv(self.z, msb(self.y));
        self.y = (self.y - 1).wrapping_mul(MultTab::MULTINV) - u32::from(lsb(self.x));
        self.x = self
            .crc32tab
            .crc32inv(self.x, c ^ self.keystream.get_byte(self.z));
    }

    /// return X value
    #[inline]
    pub fn get_x(&self) -> u32 {
        self.x
    }

    /// return Y value
    #[inline]
    pub fn get_y(&self) -> u32 {
        self.y
    }

    /// return Z value
    #[inline]
    pub fn get_z(&self) -> u32 {
        self.z
    }
}

#[cfg(test)]
mod tests {
    use super::Keys;

    #[test]
    fn update() {
        let _key: Keys = Default::default();
        // TODO: Finish this
    }
}
