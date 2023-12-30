use std::io;

use super::{NonceWriteCursor, WriteCursorState};

pub struct DecryptCursor {
    state: Option<WriteCursorState>,
}

impl DecryptCursor {
    pub fn new(key: [u8; 32]) -> Self {
        let state = Some(WriteCursorState::Nonce(NonceWriteCursor::new(key)));
        Self { state }
    }

    /// Return the start index of the decrypted user data
    pub fn decrypt(&mut self, buf: &mut [u8]) -> Option<usize> {
        let mut pos = 0;

        // Loop for state transitions from `Nonce` to `UserData`
        loop {
            match self.state.take().unwrap() {
                WriteCursorState::Nonce(c) => {
                    let mut rdr: io::Cursor<&[u8]> = io::Cursor::new(buf);
                    let c = c.collect_nonce_from(&mut rdr);
                    self.state = Some(c);
                    pos = rdr.position() as usize;
                    if pos == rdr.get_ref().len() {
                        return None;
                    }
                }
                WriteCursorState::UserData(mut c) => {
                    c.xor(&mut buf[pos..]);
                    self.state = Some(WriteCursorState::UserData(c));
                    return Some(pos);
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
}
