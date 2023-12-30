use crate::cipher::StreamCipher;

#[derive(Debug, Clone)]
pub struct UserDataCursor {
    cipher: StreamCipher,
}
impl UserDataCursor {
    pub fn new(cipher: StreamCipher) -> Self {
        Self { cipher }
    }

    pub fn xor(&mut self, buf: &mut [u8]) {
        self.cipher.encrypt(buf);
    }
}
