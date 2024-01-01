use arrayvec::ArrayVec;
use num_bigint::BigUint;

fn clamp_r(r: &mut [u8; 16]) {
    r[3] &= 0xF;
    r[7] &= 0xF;
    r[11] &= 0xF;
    r[15] &= 0xF;
    r[4] &= 0b1111_1100;
    r[8] &= 0b1111_1100;
    r[12] &= 0b1111_1100;
}

fn r(key: &[u8; 32]) -> [u8; 16] {
    key[0..16].try_into().unwrap()
}

fn s(key: &[u8; 32]) -> [u8; 16] {
    key[16..32].try_into().unwrap()
}

pub fn poly1305_mac(key: [u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r: [u8; 16] = r(&key);
    let s: [u8; 16] = s(&key);
    clamp_r(&mut r);
    let mut cum = BigUint::new(vec![0]);

    let r = BigUint::from_bytes_le(&r);
    let s = BigUint::from_bytes_le(&s);
    let p = BigUint::new(vec![2]).pow(130) - BigUint::new(vec![5]);

    const BLOCK_SIZE: usize = 16;
    const BLOCK_SIZE_PLUS_1: usize = BLOCK_SIZE + 1;
    msg.chunks(BLOCK_SIZE).for_each(|c| {
        let mut n: ArrayVec<u8, BLOCK_SIZE_PLUS_1> = c.try_into().unwrap();
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
}
