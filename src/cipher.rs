use arrayvec::ArrayVec;
use rayon::prelude::*;

use crate::{KEY_BYTES, NONCE_BYTES, X_NONCE_BYTES};

const CONSTANT: &[u8; 16] = b"expand 32-byte k";
const BLOCK_SIZE: usize = 64;
const PAR_OUTER_CHUNK_SIZE: usize = 64;
const PAR_BLOCKS_THRESHOLD: usize = 320;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCipher {
    block: Block,
    leftover: Option<(State, usize)>,
}
impl StreamCipher {
    pub fn new(key: [u8; KEY_BYTES], nonce: [u8; NONCE_BYTES]) -> Self {
        let block = Block::new(key, nonce, 1);
        Self {
            block,
            leftover: None,
        }
    }
    pub fn new_x(key: [u8; KEY_BYTES], nonce: [u8; X_NONCE_BYTES]) -> Self {
        let subkey = hchacha20(key, nonce[..16].try_into().unwrap());
        Self::new(subkey, chacha20_nonce_from_xnonce(nonce))
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        let par = match PAR_BLOCKS_THRESHOLD < buf.chunks(BLOCK_SIZE).count() {
            true => ParOrNot::Parallel,
            false => ParOrNot::Serial,
        };
        self.encrypt_(buf, par)
    }

    fn encrypt_(&mut self, buf: &mut [u8], par: ParOrNot) {
        let mut pos = 0;

        // Consume the leftover
        if let Some((state, next)) = self.leftover.take() {
            let remaining = &state.byte_vec()[next..];

            let size = xor(buf, remaining);
            pos += size;

            let next = next + size;
            if next != state.byte_vec().len() {
                self.leftover = Some((state, next));
                return;
            }
        }
        assert!(self.leftover.is_none());

        let buf = &mut buf[pos..];

        // Milk the blocks
        let xor_full_block = |(i, c): (usize, &mut [u8])| {
            let state = self.block.next_nth_block(i as u32);
            let size = xor(c, &state.byte_vec());
            assert_eq!(size, state.byte_vec().len());
            assert_eq!(size, c.len());
        };
        match par {
            ParOrNot::Parallel => {
                // buf.par_chunks_exact_mut(BLOCK_SIZE)
                //     .enumerate()
                //     .for_each(xor_full_block);

                buf.par_chunks_mut(BLOCK_SIZE * PAR_OUTER_CHUNK_SIZE)
                    .enumerate()
                    .for_each(|(i, c)| {
                        c.chunks_exact_mut(BLOCK_SIZE)
                            .enumerate()
                            .map(|(j, c)| (j + i * PAR_OUTER_CHUNK_SIZE, c))
                            .for_each(xor_full_block);
                    });
            }
            ParOrNot::Serial => {
                buf.chunks_exact_mut(BLOCK_SIZE)
                    .enumerate()
                    .for_each(xor_full_block);
            }
        }

        // Last `buf` chuck
        let i = buf.chunks_exact(BLOCK_SIZE).count();
        let c = buf.chunks_exact_mut(BLOCK_SIZE).into_remainder();
        if !c.is_empty() {
            let state = self.block.next_nth_block(i as u32);
            let size = xor(c, &state.byte_vec());
            self.leftover = Some((state, size));
        }
        self.block
            .increment_counter(buf.chunks(BLOCK_SIZE).count() as u32);
    }

    pub fn block(&self) -> &Block {
        &self.block
    }
}

enum ParOrNot {
    Parallel,
    Serial,
}

fn xor(buf: &mut [u8], other: &[u8]) -> usize {
    let size = buf.len().min(other.len());

    let vec = other.iter().take(size).copied();
    buf.iter_mut()
        .take(size)
        .zip(vec)
        .for_each(|(b, s)| *b ^= s);

    size
}

pub(crate) fn chacha20_nonce_from_xnonce(nonce: [u8; X_NONCE_BYTES]) -> [u8; NONCE_BYTES] {
    let mut chacha20_nonce = [0; NONCE_BYTES];
    chacha20_nonce[4..].copy_from_slice(&nonce[16..]);
    chacha20_nonce
}

fn hchacha20(key: [u8; KEY_BYTES], nonce: [u8; 16]) -> [u8; KEY_BYTES] {
    let counter: [u8; size_of::<u32>()] = nonce[..size_of::<u32>()].try_into().unwrap();
    let counter = u32::from_le_bytes(counter);
    let nonce: [u8; 12] = nonce[size_of::<u32>()..].try_into().unwrap();
    let block = Block::new(key, nonce, counter);
    let mut state = block.next_nth_state(0);
    state.inner_block();

    let mut out = [0; KEY_BYTES];
    let mut out_pos = 0;
    for offset in [0, 12] {
        for i in 0..4 {
            let bytes = state.vec()[i + offset].to_le_bytes();
            out[out_pos..out_pos + size_of::<u32>()].copy_from_slice(&bytes);
            out_pos += size_of::<u32>();
        }
    }
    out
}
#[cfg(test)]
#[test]
fn test_h_cha_cha_20() {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59,
        0x27,
    ];
    let out = hchacha20(key, nonce);
    assert_eq!(
        out,
        [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ]
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    constant: [u32; 4],
    nonce: [u32; 3],
    key: [u32; 8],
    counter: u32,
}
impl Block {
    pub fn new(key: [u8; KEY_BYTES], nonce: [u8; NONCE_BYTES], counter: u32) -> Self {
        let constant = [
            u32::from_le_bytes(CONSTANT[0..4].try_into().unwrap()),
            u32::from_le_bytes(CONSTANT[4..8].try_into().unwrap()),
            u32::from_le_bytes(CONSTANT[8..12].try_into().unwrap()),
            u32::from_le_bytes(CONSTANT[12..16].try_into().unwrap()),
        ];
        let nonce = [
            u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
        ];
        let key = [
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];
        Self {
            constant,
            nonce,
            key,
            counter,
        }
    }

    pub fn next_nth_state(&self, n: u32) -> State {
        let b = self.counter.wrapping_add(n);

        let c = &self.constant;
        let n = &self.nonce;
        let k = &self.key;
        let b = [b];
        State::new([
            c[0], c[1], c[2], c[3], //
            k[0], k[1], k[2], k[3], //
            k[4], k[5], k[6], k[7], //
            b[0], n[0], n[1], n[2], //
        ])
    }

    pub fn next_nth_block(&self, n: u32) -> State {
        let mut state = self.next_nth_state(n);
        let mut working_state = state;

        working_state.inner_block();

        state.add(working_state.vec());

        state
    }

    pub fn increment_counter(&mut self, n: u32) {
        self.counter = self.counter.wrapping_add(n);
    }

    pub fn nonce(&self) -> [u8; NONCE_BYTES] {
        let nonce: ArrayVec<u8, 12> = self.nonce.iter().flat_map(|n| n.to_le_bytes()).collect();
        nonce.as_slice().try_into().unwrap()
    }

    pub fn key(&self) -> [u8; KEY_BYTES] {
        let key: ArrayVec<u8, 32> = self.key.iter().flat_map(|n| n.to_le_bytes()).collect();
        key.as_slice().try_into().unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    vec: [u32; 16],
}
impl State {
    pub fn new(vec: [u32; 16]) -> Self {
        Self { vec }
    }

    pub fn vec(&self) -> &[u32; 16] {
        &self.vec
    }

    pub fn byte_vec(&self) -> [u8; 64] {
        let vec: ArrayVec<u8, 64> = self.vec.iter().flat_map(|n| n.to_le_bytes()).collect();
        vec.as_slice().try_into().unwrap()
    }

    pub fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        assert!(a < 16);
        assert!(b < 16);
        assert!(c < 16);
        assert!(d < 16);
        assert!(a != b);
        assert!(a != c);
        assert!(a != d);
        assert!(b != c);
        assert!(b != d);
        assert!(c != d);

        let mut a_v = self.vec[a];
        let mut b_v = self.vec[b];
        let mut c_v = self.vec[c];
        let mut d_v = self.vec[d];
        quarter_round(&mut a_v, &mut b_v, &mut c_v, &mut d_v);
        self.vec[a] = a_v;
        self.vec[b] = b_v;
        self.vec[c] = c_v;
        self.vec[d] = d_v;
    }

    pub fn add(&mut self, vec: &[u32; 16]) {
        self.vec
            .iter_mut()
            .zip(vec)
            .for_each(|(a, b)| *a = a.wrapping_add(*b));
    }

    pub fn inner_block(&mut self) {
        for _ in 0..10 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);
            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }
    }
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    // 1
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);
    // 2
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);
    // 3
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);
    // 4
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarter_round() {
        let mut a = 0x11111111;
        let mut b = 0x01020304;
        let mut c = 0x9b8d6f43;
        let mut d = 0x01234567;
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }

    #[test]
    fn test_quarter_round_on_state() {
        let mut state = State::new([
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, //
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c, //
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, //
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320, //
        ]);
        state.quarter_round(2, 7, 8, 13);
        assert_eq!(
            state.vec(),
            &[
                0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, //
                0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2, //
                0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, //
                0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320, //
            ]
        )
    }

    #[test]
    fn test_block() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1;
        let block = Block::new(key, nonce, counter);
        let mut state = block.next_nth_state(0);
        assert_eq!(
            state.vec(),
            &[
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, //
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, //
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, //
                0x00000001, 0x09000000, 0x4a000000, 0x00000000, //
            ]
        );

        state.inner_block();
        assert_eq!(
            state.vec(),
            &[
                0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, //
                0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7, //
                0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, //
                0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2, //
            ]
        );

        assert_eq!(
            block.next_nth_block(0).vec(),
            &[
                0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, //
                0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3, //
                0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, //
                0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2, //
            ]
        );
    }

    #[test]
    fn test_cipher() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ciphertext = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut buf = *plaintext;
        let mut cipher = StreamCipher::new(key, nonce);
        cipher.encrypt(&mut buf);
        assert_eq!(buf, ciphertext);

        let mut buf = *plaintext;
        let mut cipher = StreamCipher::new(key, nonce);
        cipher.encrypt(&mut buf[..1]);
        cipher.encrypt(&mut buf[1..]);
        assert_eq!(buf, ciphertext);

        let mut buf = *plaintext;
        let mut cipher = StreamCipher::new(key, nonce);
        cipher.encrypt(&mut buf[..BLOCK_SIZE]);
        cipher.encrypt(&mut buf[BLOCK_SIZE..]);
        assert_eq!(buf, ciphertext);
    }
}

#[cfg(test)]
mod benches {
    use std::hint::black_box;

    use test::Bencher;

    use super::*;

    fn stream_cipher() -> StreamCipher {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        StreamCipher::new(key, nonce)
    }

    fn encrypt_round(buf: &mut [u8], par: ParOrNot) {
        let mut cipher = stream_cipher();
        cipher.encrypt_(buf, par);
        black_box(buf);
    }

    fn encrypt_round_auto(buf: &mut [u8]) {
        let mut cipher = stream_cipher();
        cipher.encrypt(buf);
        black_box(buf);
    }

    #[test]
    fn test_big() {
        let mut buf_s = [0; 1024];
        encrypt_round(&mut buf_s, ParOrNot::Serial);
        let mut buf_p = [0; 1024];
        encrypt_round(&mut buf_p, ParOrNot::Parallel);
        assert_eq!(buf_s, buf_p);
    }

    #[bench]
    fn bench_encrypt_0001_block(b: &mut Bencher) {
        let mut buf = [0];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0001_block_serial(b: &mut Bencher) {
        let mut buf = [0];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0001_block_par(b: &mut Bencher) {
        let mut buf = [0];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0002_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0002_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0002_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0004_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 3 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0004_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 3 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0004_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 3 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0008_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 7 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0008_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 7 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0008_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 7 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0256_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 255 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0256_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 255 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0256_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 255 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0320_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 319 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0320_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 319 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0320_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 319 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0384_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 383 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0384_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 383 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0384_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 383 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0512_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 511 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0512_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 511 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0512_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 511 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_0768_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 767 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_0768_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 767 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_0768_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 767 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_1024_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 1023 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_1024_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 1023 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_1024_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 1023 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }

    #[bench]
    fn bench_encrypt_2048_blocks(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 2047 + 1];
        b.iter(|| {
            encrypt_round_auto(&mut buf);
        });
    }
    #[bench]
    fn bench_encrypt_2048_blocks_serial(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 2047 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Serial);
        });
    }
    #[bench]
    fn bench_encrypt_2048_blocks_par(b: &mut Bencher) {
        let mut buf = [0; BLOCK_SIZE * 2047 + 1];
        b.iter(|| {
            encrypt_round(&mut buf, ParOrNot::Parallel);
        });
    }
}
