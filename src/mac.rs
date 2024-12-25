use arrayvec::ArrayVec;
use num_bigint::BigUint;

use crate::{cipher::ChaCha20, KEY_BYTES, NONCE_BYTES};

pub const BLOCK_BYTES: usize = 16;

fn clamp_r(r: &mut [u8; BLOCK_BYTES]) {
    r[3] &= 0xF;
    r[7] &= 0xF;
    r[11] &= 0xF;
    r[15] &= 0xF;
    r[4] &= 0b1111_1100;
    r[8] &= 0b1111_1100;
    r[12] &= 0b1111_1100;
}

fn r(key: &[u8; KEY_BYTES]) -> [u8; BLOCK_BYTES] {
    key[..BLOCK_BYTES].try_into().unwrap()
}

fn s(key: &[u8; KEY_BYTES]) -> [u8; BLOCK_BYTES] {
    key[BLOCK_BYTES..].try_into().unwrap()
}

/// `key`: Should be a one-time key generated from `poly1305_key_gen`
pub fn poly1305_mac(key: [u8; KEY_BYTES], msg: &[u8]) -> [u8; BLOCK_BYTES] {
    let mut r: [u8; BLOCK_BYTES] = r(&key);
    let s: [u8; BLOCK_BYTES] = s(&key);
    clamp_r(&mut r);
    let mut cum = BigUint::new(vec![0]);

    let r = BigUint::from_bytes_le(&r);
    let s = BigUint::from_bytes_le(&s);
    let p = BigUint::new(vec![2]).pow(130) - BigUint::new(vec![5]);

    const BLOCK_BYTES_PLUS_1: usize = BLOCK_BYTES + 1;
    msg.chunks(BLOCK_BYTES).for_each(|c| {
        let mut n: ArrayVec<u8, BLOCK_BYTES_PLUS_1> = c.try_into().unwrap();
        n.push(0x1);
        let n = BigUint::from_bytes_le(&n);
        cum += n;
        cum = (&r * &cum) % &p;
    });
    cum += &s;

    let mut cum = cum.to_bytes_le();
    cum.truncate(16);
    let n = 16 - cum.len();
    cum.extend(std::iter::repeat(0).take(n));
    cum.try_into().unwrap()
}

/// Generate a one-time key for `poly1305_mac`
pub fn poly1305_key_gen_8_byte_nonce(key: [u8; KEY_BYTES], nonce: [u8; 8]) -> [u8; KEY_BYTES] {
    let mut nonce: ArrayVec<u8, 12> = nonce.as_slice().try_into().unwrap();
    nonce.extend(std::iter::repeat(0).take(12 - 8));
    poly1305_key_gen(key, nonce.as_slice().try_into().unwrap())
}

/// Generate a one-time key for `poly1305_mac`
pub fn poly1305_key_gen(key: [u8; KEY_BYTES], nonce: [u8; NONCE_BYTES]) -> [u8; KEY_BYTES] {
    let counter = 0;
    let block = ChaCha20::new(key, nonce, counter);
    let block = block.next_nth_block(0);
    block.byte_vec()[..KEY_BYTES].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        assert_eq!(
            s(&key),
            [
                0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
                0xf5, 0x1b,
            ]
        );

        let mut r = r(&key);
        assert_eq!(
            r,
            [
                0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
                0x06, 0xa8,
            ]
        );
        let mut clamped_r = [
            0x8, 0x06, 0xd5, 0x40, 0x0e, 0x52, 0x44, 0x7c, 0x03, 0x6d, 0x55, 0x54, 0x08, 0xbe,
            0xd6, 0x85,
        ];
        clamped_r.reverse();
        clamp_r(&mut r);
        assert_eq!(r, clamped_r);

        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(key, msg);
        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9,
            ]
        );
    }

    #[test]
    fn test_key_gen() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        let key = poly1305_key_gen(key, nonce);
        assert_eq!(
            key,
            [
                0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
                0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
                0xfd, 0xd1, 0xa6, 0x46,
            ]
        );
    }
}
