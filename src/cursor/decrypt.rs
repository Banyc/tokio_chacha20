use std::io;

use crate::{mac::poly1305_key_gen, KEY_BYTES, NONCE_BYTES};

use super::{NonceWriteCursor, WriteCursorState};

pub struct DecryptCursor {
    state: Option<WriteCursorState>,
}

impl DecryptCursor {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        let state = Some(WriteCursorState::Nonce(NonceWriteCursor::new(key)));
        Self { state }
    }
    pub fn new_x(key: [u8; KEY_BYTES]) -> Self {
        let state = Some(WriteCursorState::Nonce(NonceWriteCursor::new_x(key)));
        Self { state }
    }

    /// Return the start index of the decrypted user data
    pub fn decrypt(&mut self, buf: &mut [u8]) -> DecryptResult {
        let mut pos = 0;

        // Loop for state transitions from `Nonce` to `UserData`
        loop {
            match self.state.take().unwrap() {
                WriteCursorState::Nonce(c) => {
                    let read_buf = &buf[..];
                    let mut rdr: io::Cursor<&[u8]> = io::Cursor::new(read_buf);
                    let c = c.collect_nonce_from(&mut rdr);
                    self.state = Some(c);
                    pos = rdr.position() as usize;
                    let ran_out_of_read_buf = pos == read_buf.len();
                    if ran_out_of_read_buf {
                        return DecryptResult::StillAtNonce;
                    }
                }
                WriteCursorState::UserData(mut c) => {
                    c.xor(&mut buf[pos..]);
                    self.state = Some(WriteCursorState::UserData(c));
                    return DecryptResult::WithUserData {
                        user_data_start: pos,
                    };
                }
            }
        }
    }

    pub fn remaining_nonce_size(&self) -> usize {
        match self.state.as_ref().unwrap() {
            WriteCursorState::Nonce(c) => c.remaining_nonce_size(),
            WriteCursorState::UserData(_) => 0,
        }
    }

    pub fn poly1305_key(&self) -> Option<[u8; KEY_BYTES]> {
        self.poly1305_key_map_nonce(|x| x)
    }

    pub fn poly1305_key_map_nonce(
        &self,
        map_nonce: impl Fn([u8; NONCE_BYTES]) -> [u8; NONCE_BYTES],
    ) -> Option<[u8; KEY_BYTES]> {
        let WriteCursorState::UserData(c) = self.state.as_ref().unwrap() else {
            return None;
        };
        let key = c.cipher().block().key();
        let nonce = c.cipher().block().nonce();
        Some(poly1305_key_gen(key, map_nonce(nonce)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptResult {
    StillAtNonce,
    WithUserData { user_data_start: usize },
}
