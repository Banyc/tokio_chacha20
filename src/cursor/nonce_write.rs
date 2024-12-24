use std::io::{self, Read};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{cipher::StreamCipher, KEY_BYTES, NONCE_BYTES, X_NONCE_BYTES};

use super::{user_data::UserDataCursor, NonceCursor};

#[derive(Debug, Clone)]
pub struct NonceWriteCursor {
    key: [u8; KEY_BYTES],
    nonce: NonceCursor,
}
impl NonceWriteCursor {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        let nonce = io::Cursor::new([0; NONCE_BYTES]);
        Self {
            key,
            nonce: NonceCursor::Nonce(nonce),
        }
    }
    pub fn new_x(key: [u8; KEY_BYTES]) -> Self {
        let nonce = io::Cursor::new([0; X_NONCE_BYTES]);
        Self {
            key,
            nonce: NonceCursor::XNonce(nonce),
        }
    }

    pub fn remaining_nonce_size(&self) -> usize {
        self.nonce.remaining().len()
    }

    pub fn collect_nonce_from(mut self, r: &mut io::Cursor<&[u8]>) -> WriteCursorState {
        let n = Read::read(r, self.nonce.remaining_mut()).unwrap();
        self.nonce.consume(n);

        if !self.nonce.complete() {
            return WriteCursorState::Nonce(self);
        }

        let cipher = match self.nonce {
            NonceCursor::Nonce(cursor) => StreamCipher::new(self.key, cursor.into_inner()),
            NonceCursor::XNonce(cursor) => StreamCipher::new_x(self.key, cursor.into_inner()),
        };
        let cursor = UserDataCursor::new(cipher);
        WriteCursorState::UserData(cursor)
    }

    pub async fn decode_nonce_from<R: AsyncRead + Unpin>(
        mut self,
        r: &mut R,
    ) -> io::Result<UserDataCursor> {
        AsyncReadExt::read_exact(r, self.nonce.remaining_mut()).await?;
        let cipher = match self.nonce {
            NonceCursor::Nonce(cursor) => StreamCipher::new(self.key, cursor.into_inner()),
            NonceCursor::XNonce(cursor) => StreamCipher::new_x(self.key, cursor.into_inner()),
        };
        let cursor = UserDataCursor::new(cipher);
        Ok(cursor)
    }
}

#[derive(Debug, Clone)]
pub enum WriteCursorState {
    Nonce(NonceWriteCursor),
    UserData(UserDataCursor),
}
