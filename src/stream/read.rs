use std::{io, pin::Pin, task::ready};

use arrayvec::ArrayVec;
use tokio::io::{AsyncRead, ReadBuf};

use crate::cursor::{NonceWriteCursor, WriteCursor};

#[derive(Debug)]
pub struct ReadHalf<R> {
    cursor: Option<WriteCursor>,
    r: R,
}
impl<R> ReadHalf<R> {
    pub fn new(key: [u8; 32], r: R) -> Self {
        let cursor = NonceWriteCursor::new(key);
        let cursor = Some(WriteCursor::Nonce(cursor));
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
                WriteCursor::Nonce(c) => {
                    // let mut buf = vec![0; self.remaining_nonce_size()];
                    let mut buf = ArrayVec::<u8, 12>::from_iter(
                        std::iter::repeat(0).take(c.remaining_nonce_size()),
                    );
                    let mut buf = ReadBuf::new(&mut buf);

                    // Collect nonce from `r`
                    let ready = Pin::new(&mut self.r).poll_read(cx, &mut buf);
                    let mut buf = io::Cursor::new(buf.filled());
                    let c = c.collect_nonce_from(&mut buf);
                    self.cursor = Some(c);

                    ready!(ready)?;
                }
                WriteCursor::UserData(mut c) => {
                    // Read data from the `r`
                    let ready = Pin::new(&mut self.r).poll_read(cx, buf);

                    // Decrypt the read user data in place
                    c.xor(buf.filled_mut());

                    self.cursor = Some(WriteCursor::UserData(c));
                    return ready;
                }
            }
        }
    }
}
