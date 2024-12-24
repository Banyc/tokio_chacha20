use std::io::{self};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{cipher::StreamCipher, KEY_BYTES, NONCE_BYTES, X_NONCE_BYTES};

use super::{user_data::UserDataCursor, NonceCursor};

#[derive(Debug, Clone)]
pub struct NonceReadCursor {
    key: [u8; KEY_BYTES],
    nonce: NonceCursor,
}
impl NonceReadCursor {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        let nonce: [u8; NONCE_BYTES] = rand::random();
        let nonce = io::Cursor::new(nonce);
        Self {
            key,
            nonce: NonceCursor::Nonce(nonce),
        }
    }
    pub fn new_x(key: [u8; KEY_BYTES]) -> Self {
        let nonce: [u8; X_NONCE_BYTES] = rand::random();
        let nonce = io::Cursor::new(nonce);
        Self {
            key,
            nonce: NonceCursor::XNonce(nonce),
        }
    }

    pub fn remaining_nonce(&self) -> &[u8] {
        self.nonce.remaining()
    }

    pub fn consume_nonce(mut self, amt: usize) -> ReadCursorState {
        self.nonce.consume(amt);
        if !self.nonce.complete() {
            return ReadCursorState::Nonce(self);
        }

        let cipher = match self.nonce {
            NonceCursor::Nonce(cursor) => StreamCipher::new(self.key, cursor.into_inner()),
            NonceCursor::XNonce(cursor) => StreamCipher::new_x(self.key, cursor.into_inner()),
        };
        let cursor = UserDataCursor::new(cipher);
        ReadCursorState::UserData(cursor)
    }

    pub async fn encode_nonce_to<W: AsyncWrite + Unpin>(
        self,
        w: &mut W,
    ) -> io::Result<UserDataCursor> {
        AsyncWriteExt::write_all(w, self.remaining_nonce()).await?;
        let cipher = match self.nonce {
            NonceCursor::Nonce(cursor) => StreamCipher::new(self.key, cursor.into_inner()),
            NonceCursor::XNonce(cursor) => StreamCipher::new_x(self.key, cursor.into_inner()),
        };
        Ok(UserDataCursor::new(cipher))
    }

    pub fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    pub fn chacha20_nonce(&self) -> [u8; NONCE_BYTES] {
        self.nonce.chacha20_nonce()
    }
}

#[derive(Debug, Clone)]
pub enum ReadCursorState {
    Nonce(NonceReadCursor),
    UserData(UserDataCursor),
}
