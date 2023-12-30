use std::io::{self, Read};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::cipher::StreamCipher;

use super::user_data::UserDataCursor;

#[derive(Debug, Clone)]
pub struct NonceWriteCursor {
    key: [u8; 32],
    nonce: io::Cursor<[u8; 12]>,
}
impl NonceWriteCursor {
    pub fn new(key: [u8; 32]) -> Self {
        let nonce = io::Cursor::new([0; 12]);
        Self { key, nonce }
    }

    pub fn remaining_nonce_size(&self) -> usize {
        self.nonce.get_ref().len() - self.nonce.position() as usize
    }

    pub fn collect_nonce_from(mut self, r: &mut io::Cursor<&[u8]>) -> WriteCursor {
        let pos = self.nonce.position() as usize;
        let n = Read::read(r, &mut self.nonce.get_mut()[pos..]).unwrap();
        self.nonce.set_position((pos + n) as u64);

        if self.nonce.get_ref().len() != self.nonce.position() as usize {
            return WriteCursor::Nonce(self);
        }

        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        let cursor = UserDataCursor::new(cipher);
        WriteCursor::UserData(cursor)
    }

    pub async fn decode_nonce_from<R: AsyncRead + Unpin>(
        mut self,
        r: &mut R,
    ) -> io::Result<UserDataCursor> {
        let pos = self.nonce.position() as usize;
        AsyncReadExt::read_exact(r, &mut self.nonce.get_mut()[pos..]).await?;
        let cipher = StreamCipher::new(self.key, self.nonce.into_inner());
        let cursor = UserDataCursor::new(cipher);
        Ok(cursor)
    }
}

#[derive(Debug, Clone)]
pub enum WriteCursor {
    Nonce(NonceWriteCursor),
    UserData(UserDataCursor),
}
