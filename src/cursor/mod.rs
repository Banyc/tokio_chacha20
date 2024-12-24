mod nonce_read;
use std::io::{self, BufRead};

pub use nonce_read::{NonceReadCursor, ReadCursorState};
mod nonce_write;
pub use nonce_write::{NonceWriteCursor, WriteCursorState};
mod user_data;
pub use user_data::UserDataCursor;
mod decrypt;
pub use decrypt::DecryptCursor;
mod encrypt;
pub use encrypt::EncryptCursor;

use crate::{cipher::chacha20_nonce_from_xnonce, NONCE_BYTES, X_NONCE_BYTES};

#[derive(Debug, Clone)]
enum NonceCursor {
    Nonce(io::Cursor<[u8; NONCE_BYTES]>),
    XNonce(io::Cursor<[u8; X_NONCE_BYTES]>),
}
impl NonceCursor {
    pub fn consume(&mut self, amt: usize) {
        match self {
            NonceCursor::Nonce(cursor) => cursor.consume(amt),
            NonceCursor::XNonce(cursor) => cursor.consume(amt),
        }
    }
    pub fn complete(&self) -> bool {
        match self {
            NonceCursor::Nonce(cursor) => cursor.position() as usize == cursor.get_ref().len(),
            NonceCursor::XNonce(cursor) => cursor.position() as usize == cursor.get_ref().len(),
        }
    }
    pub fn remaining(&self) -> &[u8] {
        match self {
            NonceCursor::Nonce(cursor) => &cursor.get_ref()[cursor.position() as usize..],
            NonceCursor::XNonce(cursor) => &cursor.get_ref()[cursor.position() as usize..],
        }
    }
    pub fn remaining_mut(&mut self) -> &mut [u8] {
        match self {
            NonceCursor::Nonce(cursor) => {
                let pos = cursor.position() as usize;
                &mut cursor.get_mut()[pos..]
            }
            NonceCursor::XNonce(cursor) => {
                let pos = cursor.position() as usize;
                &mut cursor.get_mut()[pos..]
            }
        }
    }
    pub fn chacha20_nonce(&self) -> [u8; NONCE_BYTES] {
        match self {
            NonceCursor::Nonce(cursor) => *cursor.get_ref(),
            NonceCursor::XNonce(cursor) => chacha20_nonce_from_xnonce(*cursor.get_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::tests::create_random_config;

    use super::*;

    #[test]
    fn test_en_dec() {
        let config = create_random_config();

        let msg = b"Hello world!";
        let mut en = EncryptCursor::new(*config.key());
        let mut de = DecryptCursor::new(*config.key());
        let mut buf = [0; 1024];

        for _ in 0..1024 {
            let (_, n) = en.encrypt(msg, &mut buf);
            let i = de.decrypt(&mut buf[..n]).unwrap();
            assert_eq!(&buf[i..n], &msg[..]);

            let n = en.encrypt(msg, &mut []);
            assert_eq!(n, (0, 0));
        }
    }
}
