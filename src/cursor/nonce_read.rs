use std::io::{self, BufRead};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{cipher::StreamCipher, KEY_BYTES, NONCE_BYTES};

use super::user_data::UserDataCursor;

#[derive(Debug, Clone)]
pub struct NonceReadCursor {
    key: [u8; KEY_BYTES],
    nonce: io::Cursor<[u8; NONCE_BYTES]>,
}
impl NonceReadCursor {
    pub fn new(key: [u8; KEY_BYTES]) -> Self {
        let nonce: [u8; NONCE_BYTES] = rand::random();
        let nonce = io::Cursor::new(nonce);
        Self { key, nonce }
    }

    pub fn remaining_nonce(&self) -> &[u8] {
        &self.nonce.get_ref()[self.nonce.position() as usize..]
    }

    pub fn consume_nonce(mut self, amt: usize) -> ReadCursorState {
        self.nonce.consume(amt);
        if self.nonce.position() as usize != self.nonce.get_ref().len() {
            return ReadCursorState::Nonce(self);
        }

        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        let cursor = UserDataCursor::new(cipher);
        ReadCursorState::UserData(cursor)
    }

    pub async fn encode_nonce_to<W: AsyncWrite + Unpin>(
        self,
        w: &mut W,
    ) -> io::Result<UserDataCursor> {
        AsyncWriteExt::write_all(w, self.remaining_nonce()).await?;
        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        Ok(UserDataCursor::new(cipher))
    }

    pub fn key(&self) -> &[u8; KEY_BYTES] {
        &self.key
    }

    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        self.nonce.get_ref()
    }
}

#[derive(Debug, Clone)]
pub enum ReadCursorState {
    Nonce(NonceReadCursor),
    UserData(UserDataCursor),
}
