use std::io::{self, BufRead};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::cipher::StreamCipher;

use super::user_data::UserDataCursor;

#[derive(Debug, Clone)]
pub struct NonceReadCursor {
    key: [u8; 32],
    nonce: io::Cursor<[u8; 12]>,
}
impl NonceReadCursor {
    pub fn new(key: [u8; 32]) -> Self {
        let nonce: [u8; 12] = rand::random();
        let nonce = io::Cursor::new(nonce);
        Self { key, nonce }
    }

    pub fn remaining_nonce(&self) -> &[u8] {
        &self.nonce.get_ref()[self.nonce.position() as usize..]
    }

    pub fn consume_nonce(mut self, amt: usize) -> ReadCursor {
        self.nonce.consume(amt);
        if self.nonce.position() as usize != self.nonce.get_ref().len() {
            return ReadCursor::Nonce(self);
        }

        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        let cursor = UserDataCursor::new(cipher);
        ReadCursor::UserData(cursor)
    }

    pub async fn encode_nonce_to<W: AsyncWrite + Unpin>(
        self,
        w: &mut W,
    ) -> io::Result<UserDataCursor> {
        AsyncWriteExt::write_all(w, self.remaining_nonce()).await?;
        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        Ok(UserDataCursor::new(cipher))
    }
}

#[derive(Debug, Clone)]
pub enum ReadCursor {
    Nonce(NonceReadCursor),
    UserData(UserDataCursor),
}