mod nonce_read;
pub use nonce_read::{NonceReadCursor, ReadCursorState};
mod nonce_write;
pub use nonce_write::{NonceWriteCursor, WriteCursorState};
mod user_data;
pub use user_data::UserDataCursor;
mod decrypt;
pub use decrypt::DecryptCursor;
mod encrypt;
pub use encrypt::EncryptCursor;

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
