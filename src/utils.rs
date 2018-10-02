pub fn lsb(x: u32) -> u8 {
    x as u8
}

pub fn msb(x: u32) -> u8 {
    (x >> 24) as u8
}

pub const MASK_0_16: u32 = 0x0000_ffff;
pub const MASK_26_32: u32 = 0xfc00_0000;
pub const MASK_24_32: u32 = 0xff00_0000;
pub const MASK_10_32: u32 = 0xffff_fc00;
pub const MASK_8_32: u32 = 0xffff_ff00;
pub const MASK_2_32: u32 = 0xffff_fffc;

// maximum difference between integers A and B[x,32) where A = B + somebyte.
// So:
//  A - B[x,32) = B[0,x) + somebyte
//  A - B[x,32) <= mask[0,x) + 0xff
pub const MAXDIFF_0_24: u32 = 0x00ff_ffff + 0xff;
pub const MAXDIFF_0_26: u32 = 0x03ff_ffff + 0xff;