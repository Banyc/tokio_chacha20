use std::{
    pin::Pin,
    task::{ready, Poll},
};

use tokio::io::AsyncWrite;

use crate::cursor::{NonceReadCursor, ReadCursor};

#[derive(Debug)]
pub struct WriteHalf<W> {
    cursor: Option<ReadCursor>,
    w: W,
    buf: Option<Vec<u8>>,
}
impl<W> WriteHalf<W> {
    pub fn new(key: [u8; 32], w: W) -> Self {
        let cursor = NonceReadCursor::new(key);
        let cursor = Some(ReadCursor::Nonce(cursor));
        let buf = Some(vec![]);
        Self { cursor, w, buf }
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for WriteHalf<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // Loop for state transitions from `Nonce` to `UserData`
        loop {
            match self.cursor.take().unwrap() {
                ReadCursor::Nonce(c) => {
                    // Write nonce to `w`
                    let ready = Pin::new(&mut self.w).poll_write(cx, c.remaining_nonce());

                    // Mark part of the nonce as read
                    // And return the cursor
                    self.cursor = Some(if let Poll::Ready(Ok(amt)) = ready {
                        c.consume_nonce(amt)
                    } else {
                        ReadCursor::Nonce(c)
                    });

                    // Raise exception on either `Err` or `Pending`
                    let _ = ready!(ready)?;
                }
                ReadCursor::UserData(mut c) => {
                    // Reuse the inner buffer
                    let mut inner_buf = self.buf.take().unwrap();

                    // Fill the inner buffer with encrypted data if it's empty
                    if inner_buf.is_empty() {
                        inner_buf.extend(buf);
                        c.xor(&mut inner_buf);
                    }

                    // Return the cursor
                    self.cursor = Some(ReadCursor::UserData(c));

                    // Try to write `w` with the inner buffer
                    let ready = Pin::new(&mut self.w).poll_write(cx, &inner_buf);

                    // Remove the consumed data from the inner buffer
                    if let Poll::Ready(Ok(amt)) = ready {
                        inner_buf.drain(0..amt);
                    }

                    // Return the inner buffer
                    self.buf = Some(inner_buf);

                    let _ = ready!(ready)?;

                    // Do not allow caller to switch buffers until the inner buffer is fully consumed
                    if self.buf.as_ref().unwrap().is_empty() {
                        return Ok(buf.len()).into();
                    }
                }
            }
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}
