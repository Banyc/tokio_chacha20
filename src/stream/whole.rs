use std::{marker::PhantomData, pin::Pin};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::KEY_BYTES;

use super::{read::ReadHalf, write::WriteHalf};

#[derive(Debug)]
pub struct DuplexStream<R, W> {
    r: R,
    w: W,
}
impl<R, W> DuplexStream<R, W> {
    pub fn new(r: R, w: W) -> Self {
        Self { r, w }
    }
}
impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for DuplexStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for DuplexStream<R, W> {
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

#[derive(Debug)]
pub struct WholeStream<R, W> {
    r: PhantomData<R>,
    w: PhantomData<W>,
}
impl<R, W> WholeStream<R, W> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(r: ReadHalf<R>, w: WriteHalf<W>) -> DuplexStream<ReadHalf<R>, WriteHalf<W>> {
        DuplexStream::new(r, w)
    }
    pub fn from_key_halves(
        key: [u8; KEY_BYTES],
        r: R,
        w: W,
    ) -> DuplexStream<ReadHalf<R>, WriteHalf<W>> {
        let r = ReadHalf::new(key, r);
        let w = WriteHalf::new(key, w);
        DuplexStream::new(r, w)
    }
    pub fn from_key_halves_x(
        key: [u8; KEY_BYTES],
        r: R,
        w: W,
    ) -> DuplexStream<ReadHalf<R>, WriteHalf<W>> {
        let r = ReadHalf::new_x(key, r);
        let w = WriteHalf::new_x(key, w);
        DuplexStream::new(r, w)
    }
}
