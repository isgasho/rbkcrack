use crate::crc32_tab::Crc32Tab;
use crate::data::Data;
use crate::keys::Keys;
use crate::keystream_tab::KeystreamTab;
use crate::mult_tab::MultTab;
use crate::utils::*;
use lazy_static::lazy_static;

#[derive(Debug, Clone)]
pub struct Attack<'a> {
    z_list: [u32; 12],
    y_list: [u32; 12],
    x_list: [u32; 12],
    data: &'a Data,
    index: usize,
}

lazy_static! {
    static ref MULTTAB: MultTab = MultTab::new();
    static ref CRC32TAB: Crc32Tab = Crc32Tab::new();
    static ref KEYSTREAMTAB: KeystreamTab = KeystreamTab::new();
}

impl<'a> Attack<'a> {
    pub const SIZE: usize = 12;

    pub fn new(data: &Data, index: usize) -> Attack {
        Attack {
            z_list: [0; 12],
            y_list: [0; 12],
            x_list: [0; 12],
            data,
            index,
        }
    }

    pub fn carry_out(&mut self, z11_2_32: u32) -> bool {
        self.z_list[11] = z11_2_32;
        self.explore_z_lists(11)
    }

    pub fn get_keys(&self) -> Keys {
        let mut keys = Keys::new();
        keys.set_keys(self.x_list[7], self.y_list[7], self.z_list[7]);

        // println!("({})", self.data.ciphertext[0]);
        for &i in self.data.ciphertext
            [0..(Data::HEADER_SIZE + self.data.offset as usize + self.index + 7)]
            .iter()
            .rev()
        {
            // println!("{}", i);
            keys.update_backword(i);
        }

        keys
    }

    fn explore_z_lists(&mut self, i: i32) -> bool {
        if i != 0 {
            // the Z-list is not complete so generate Z{i-1}[2,32) values
            let i = i as usize;

            // get Z{i-1}[10,32) from CRC32^-1
            let zim1_10_32 = CRC32TAB.get_zim1_10_32(self.z_list[i]);

            // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
            for &zim1_2_16 in KEYSTREAMTAB
                .get_zi_2_16_vector(self.data.keystream[self.index as usize + i - 1], zim1_10_32)
            {
                // add Z{i-1}[2,32) to the Z-list
                self.z_list[i - 1] = zim1_10_32 | zim1_2_16;

                // find Zi[0,2) from Crc32^1
                self.z_list[i] &= MASK_2_32;
                self.z_list[i] |= (CRC32TAB.crc32inv(self.z_list[i], 0) ^ self.z_list[i - 1]) >> 8;

                // get Y{i+1}[24,32)
                if i < 11 {
                    self.y_list[i + 1] = CRC32TAB.get_yi_24_32(self.z_list[i + 1], self.z_list[i]);
                }

                if self.explore_z_lists(i as i32 - 1) {
                    // println!("{}: 1 true", i);
                    return true;
                }
            }
            // println!("{}: 1 false", i);
            false
        } else {
            // the Z-list is complete so iterate over possible Y values

            // guess Y11[8,24) and keep prod == (Y11[8,32) - 1) * mult^-1
            let mut prod =
                (MULTTAB.get_multinv(msb(self.y_list[11])) << 24).wrapping_sub(MultTab::MULTINV);
            for y11_8_24 in (0..(1 << 24)).step_by(1 << 8) {
                // get possible Y11[0,8) values
                for &y11_0_8 in
                    MULTTAB.get_msb_prod_fiber3(msb(self.y_list[10]).wrapping_sub(msb(prod)))
                {
                    // filter Y11[0,8) using Y10[24,32)
                    if prod + MULTTAB.get_multinv(y11_0_8) - (self.y_list[10] & MASK_24_32)
                        <= MAXDIFF_0_24
                    {
                        self.y_list[11] =
                            u32::from(y11_0_8) | y11_8_24 | (self.y_list[11] & MASK_24_32);
                        if self.explore_y_lists(11) {
                            // println!("{}: 2 true", i);
                            return true;
                        }
                    }
                }

                prod = prod.wrapping_add(MultTab::MULTINV << 8);
            }
            // println!("{}: 2 false", i);
            false
        }
    }

    fn explore_y_lists(&mut self, i: i32) -> bool {
        if i != 3 {
            // the Y-list is not complete so generate Y{i-1} values
            let i = i as usize;
            let fy: u32 = (self.y_list[i as usize] - 1).wrapping_mul(MultTab::MULTINV);
            let ffy: u32 = (fy - 1).wrapping_mul(MultTab::MULTINV);

            // get possible LSB(Xi)
            for &xi_0_8 in
                MULTTAB.get_msb_prod_fiber2(msb(ffy.wrapping_sub(self.y_list[i - 2] & MASK_24_32)))
            {
                // compute corresponding Y{i-1}
                let yim1 = fy - u32::from(xi_0_8);

                // filter values with Y{i-2}[24,32)
                if ffy
                    .wrapping_sub(MULTTAB.get_multinv(xi_0_8))
                    .wrapping_sub(self.y_list[i - 2] & MASK_24_32)
                    <= MAXDIFF_0_24
                    && msb(yim1) == msb(self.y_list[i - 1])
                {
                    // add Y{i-1} to the Y-list
                    self.y_list[i as usize - 1] = yim1;

                    // set Xi value
                    self.x_list[i as usize] = u32::from(xi_0_8);

                    if self.explore_y_lists(i as i32 - 1) {
                        return true;
                    }
                }
            }

            false
        } else {
            self.test_x_list()
        }
    }

    fn test_x_list(&mut self) -> bool {
        // compute X7
        for i in 5..=7 {
            self.x_list[i] = (CRC32TAB.crc32(self.x_list[i-1], self.data.plaintext[self.index+i-1])
                & MASK_8_32) // discard the LSB
                | u32::from(lsb(self.x_list[i])); // set the LSB
        }

        let mut x = self.x_list[7];

        // compare 4 LSB(Xi) obtained from plaintext with those from the X-list
        for i in 8..=11 {
            x = CRC32TAB.crc32(x, self.data.plaintext[self.index + i - 1]);
            if lsb(x) != lsb(self.x_list[i]) {
                //println!("4");
                return false;
            }
        }

        // compute X3
        let mut x = self.x_list[7];
        for i in (3..=6).rev() {
            x = CRC32TAB.crc32inv(x, self.data.plaintext[self.index + i]);
        }

        // check that X3 fits with Y1[26,32)
        let y1_26_32 = CRC32TAB.get_yi_24_32(self.z_list[1], self.z_list[0]) & MASK_26_32;
        if ((self.y_list[3] - 1).wrapping_mul(MultTab::MULTINV) - u32::from(lsb(x)) - 1)
            .wrapping_mul(MultTab::MULTINV)
            - y1_26_32
            > MAXDIFF_0_26
        {
            //println!("5");
            return false;
        }

        // all tests passed so the keys are found
        true
    }
}

#[cfg(test)]
mod tests {
    use super::Attack;
    use super::Data;
    use crate::Arguments;

    #[test]
    fn test_x_list() {
        let data = Data::new(&Arguments {
            encryptedzip: Some("./example/cipher.zip".into()),
            cipherfile: "file".into(),
            plainzip: Some("./example/plain.zip".into()),
            plainfile: Some("file".into()),
            ..Default::default()
        })
        .unwrap();
        let mut attack = Attack::new(&data, 735115);
        attack.x_list = [
            2, 64, 347029520, 21996, 207, 3988292578, 881025314, 2807276851, 77, 60, 9, 187,
        ];
        attack.y_list = [
            64, 64, 838860800, 4085658340, 702500480, 2170229995, 2383027522, 2433410890,
            1767399924, 853191409, 3862839011, 2230629911,
        ];
        attack.z_list = [
            1092480552, 2001087864, 2524901027, 1811754778, 3216743481, 3305472034, 3752192579,
            1744967186, 3351227042, 4039650542, 237715486, 282349850,
        ];

        assert_eq!(true, attack.test_x_list());
    }

    #[test]
    fn explore_y_list() {
        let data = Data::new(&Arguments {
            encryptedzip: Some("./example/cipher.zip".into()),
            cipherfile: "file".into(),
            plainzip: Some("./example/plain.zip".into()),
            plainfile: Some("file".into()),
            ..Default::default()
        })
        .unwrap();
        let mut attack = Attack::new(&data, 735115);
        attack.x_list = [
            2, 64, 3414458384, 22000, 207, 3988292578, 881025314, 2807276851, 77, 60, 9, 187,
        ];
        attack.y_list = [
            64, 64, 838860800, 4085658340, 702500480, 2170229995, 2383027522, 2433410890,
            1767399924, 853191409, 3862839011, 2230629911,
        ];
        attack.z_list = [
            1092480552, 2001087864, 2524901027, 1811754778, 3216743481, 3305472034, 3752192579,
            1744967186, 3351227042, 4039650542, 237715486, 282349850,
        ];

        assert_eq!(true, attack.explore_y_lists(11));
    }

    #[test]
    fn get_keys() {
        let data = Data::new(&Arguments {
            encryptedzip: Some("./example/cipher.zip".into()),
            cipherfile: "file".into(),
            plainzip: Some("./example/plain.zip".into()),
            plainfile: Some("file".into()),
            ..Default::default()
        })
        .unwrap();
        let mut attack = Attack::new(&data, 735115);
        attack.x_list[7] = 2807276851;
        attack.y_list[7] = 2433410890;
        attack.z_list[7] = 1744967186;

        let keys = attack.get_keys();

        assert_eq!(0x8879dfed, keys.get_x());
        assert_eq!(0x14335b6b, keys.get_y());
        assert_eq!(0x8dc58b53, keys.get_z());
    }
}
