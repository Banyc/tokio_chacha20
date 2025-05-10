use crate::{mac::poly1305_key_gen, KEY_BYTES, NONCE_BYTES};

use super::{NonceReadCursor, ReadCursorState};

pub struct EncryptCursor {
    state: Option<ReadCursorState>,
}

impl EncryptCursor {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        let state = Some(ReadCursorState::Nonce(NonceReadCursor::new(key)));
        Self { state }
    }
    pub fn new_x(key: [u8; KEY_BYTES]) -> Self {
        let state = Some(ReadCursorState::Nonce(NonceReadCursor::new_x(key)));
        Self { state }
    }

    /// Return the amount of bytes read from `from` and the amount of bytes written to `to`
    pub fn encrypt(&mut self, from: &[u8], to: &mut [u8]) -> EncryptResult {
        let mut to_pos = if matches!(self.state.as_ref().unwrap(), ReadCursorState::Nonce(_)) {
            let ReadCursorState::Nonce(c) = self.state.take().unwrap() else {
                unreachable!();
            };
            let copy_n = c.remaining_nonce().len().min(to.len());
            to[..copy_n].copy_from_slice(&c.remaining_nonce()[..copy_n]);
            self.state = Some(c.consume_nonce(copy_n));
            let ran_out_write_buf = copy_n == to.len();
            if ran_out_write_buf {
                return EncryptResult {
                    read: 0,
                    written: copy_n,
                };
            }
            copy_n
        } else {
            0
        };
        let ReadCursorState::UserData(c) = self.state.as_mut().unwrap() else {
            panic!();
        };
        let to = &mut to[to_pos..];
        let copy_n = from.len().min(to.len());
        to[..copy_n].copy_from_slice(&from[..copy_n]);
        to_pos += copy_n;
        c.xor(&mut to[..copy_n]);
        EncryptResult {
            read: copy_n,
            written: to_pos,
        }
    }

    pub fn poly1305_key(&self) -> [u8; KEY_BYTES] {
        self.poly1305_key_map_nonce(|x| x)
    }

    pub fn poly1305_key_map_nonce(
        &self,
        map_nonce: impl Fn([u8; NONCE_BYTES]) -> [u8; NONCE_BYTES],
    ) -> [u8; KEY_BYTES] {
        let key = match self.state.as_ref().unwrap() {
            ReadCursorState::Nonce(c) => *c.key(),
            ReadCursorState::UserData(c) => c.cipher().block().key(),
        };
        let nonce = match self.state.as_ref().unwrap() {
            ReadCursorState::Nonce(c) => c.chacha20_nonce(),
            ReadCursorState::UserData(c) => c.cipher().block().nonce(),
        };
        poly1305_key_gen(key, map_nonce(nonce))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptResult {
    pub read: usize,
    pub written: usize,
}
