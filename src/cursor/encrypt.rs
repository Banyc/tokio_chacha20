use std::io;

use super::{NonceReadCursor, ReadCursorState};

pub struct EncryptCursor {
    state: Option<ReadCursorState>,
}

impl EncryptCursor {
    pub fn new(key: [u8; 32]) -> Self {
        let state = Some(ReadCursorState::Nonce(NonceReadCursor::new(key)));
        Self { state }
    }

    /// Return the amount of bytes read from `from` and the amount of bytes written to `to`
    pub fn encrypt(&mut self, from: &[u8], to: &mut [u8]) -> io::Result<(usize, usize)> {
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
                        return Ok((0, to_amt));
                    }
                }
                ReadCursorState::UserData(mut c) => {
                    let to = &mut to[to_amt..];
                    let n = from.len().min(to.len());
                    to[..n].copy_from_slice(&from[..n]);
                    to_amt += n;
                    c.xor(&mut to[..n]);
                    self.state = Some(ReadCursorState::UserData(c));
                    return Ok((n, to_amt));
                }
            }
        }
    }
}
