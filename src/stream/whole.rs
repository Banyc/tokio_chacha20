use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::KEY_BYTES;

use super::{read::ReadHalf, write::WriteHalf};

#[derive(Debug)]
pub struct WholeStream<R, W> {
    r: ReadHalf<R>,
    w: WriteHalf<W>,
}
impl<R, W> WholeStream<R, W> {
    pub fn new(r: ReadHalf<R>, w: WriteHalf<W>) -> Self {
        Self { r, w }
    }

    pub fn from_key_halves(key: [u8; KEY_BYTES], r: R, w: W) -> Self {
        let r = ReadHalf::new(key, r);
        let w = WriteHalf::new(key, w);
        Self { r, w }
    }
}
impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for WholeStream<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for WholeStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.w).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}
