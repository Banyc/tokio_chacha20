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
    pub fn encrypt(&mut self, from: &[u8], to: &mut [u8]) -> (usize, usize) {
        let mut to_amt = 0;

        // Loop for state transitions from `Nonce` to `UserData`
        loop {
            match self.state.take().unwrap() {
                ReadCursorState::Nonce(c) => {
                    let n = c.remaining_nonce().len().min(to.len());
                    to[..n].copy_from_slice(&c.remaining_nonce()[..n]);
                    self.state = Some(c.consume_nonce(n));
                    to_amt += n;
                    if n == to.len() {
                        return (0, to_amt);
                    }
                }
                ReadCursorState::UserData(mut c) => {
                    let to = &mut to[to_amt..];
                    let n = from.len().min(to.len());
                    to[..n].copy_from_slice(&from[..n]);
                    to_amt += n;
                    c.xor(&mut to[..n]);
                    self.state = Some(ReadCursorState::UserData(c));
                    return (n, to_amt);
                }
            }
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
