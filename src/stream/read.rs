use std::{io, pin::Pin, task::ready};

use arrayvec::ArrayVec;
use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    cursor::{NonceWriteCursor, WriteCursorState},
    KEY_BYTES,
};

#[derive(Debug)]
pub struct ReadHalf<R> {
    cursor: Option<WriteCursorState>,
    r: R,
}
impl<R> ReadHalf<R> {
    pub fn new(key: [u8; KEY_BYTES], r: R) -> Self {
        let cursor = NonceWriteCursor::new(key);
        let cursor = Some(WriteCursorState::Nonce(cursor));
        Self { cursor, r }
    }
    pub fn new_x(key: [u8; KEY_BYTES], r: R) -> Self {
        let cursor = NonceWriteCursor::new_x(key);
        let cursor = Some(WriteCursorState::Nonce(cursor));
        Self { cursor, r }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for ReadHalf<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Loop for state transitions from `Nonce` to `UserData`
        loop {
            match self.cursor.take().unwrap() {
                WriteCursorState::Nonce(c) => {
                    assert!(c.remaining_nonce_size() > 0);

                    // let mut buf = vec![0; self.remaining_nonce_size()];
                    let mut buf = ArrayVec::<u8, 12>::from_iter(
                        std::iter::repeat(0).take(c.remaining_nonce_size()),
                    );
                    let mut buf = ReadBuf::new(&mut buf);

                    // Collect nonce from `r`
                    let filled_len = buf.filled().len();
                    let ready = Pin::new(&mut self.r).poll_read(cx, &mut buf);

                    // Write nonce segments to the cursor
                    let mut rdr = io::Cursor::new(buf.filled());
                    let c = c.collect_nonce_from(&mut rdr);
                    assert_eq!(rdr.position() as usize, rdr.get_ref().len());
                    self.cursor = Some(c);

                    ready!(ready)?;

                    if buf.filled().len() == filled_len {
                        // `r` hits EOF
                        return Ok(()).into();
                    }
                }
                WriteCursorState::UserData(mut c) => {
                    // Read data from the `r`
                    let ready = Pin::new(&mut self.r).poll_read(cx, buf);

                    // Decrypt the read user data in place
                    c.xor(buf.filled_mut());

                    self.cursor = Some(WriteCursorState::UserData(c));
                    return ready;
                }
            }
        }
    }
}
