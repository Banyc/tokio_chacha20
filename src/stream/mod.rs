mod read;
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

pub use read::{Chacha20Reader, ReadHalf};
mod whole;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use whole::{DuplexStream, WholeStream};
mod write;
pub use write::{Chacha20Writer, WriteHalf};

use crate::{mac::Poly1305Hasher, KEY_BYTES};

#[derive(Debug)]
pub struct Poly1305Reader;
#[derive(Debug)]
pub struct Poly1305Writer;
#[derive(Debug)]
pub struct Poly1305Stream<S, Rw> {
    hasher: Poly1305Hasher,
    stream: S,
    _rw: Rw,
}
impl<S, Rw> Poly1305Stream<S, Rw> {
    pub fn new(one_time_key: [u8; KEY_BYTES], stream: S, rw: Rw) -> Self {
        let hasher = Poly1305Hasher::new(&one_time_key);
        Self {
            hasher,
            stream,
            _rw: rw,
        }
    }
}
impl<S> AsyncRead for Poly1305Stream<S, Poly1305Reader>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let start = buf.filled().len();
        ready!(Pin::new(&mut self.stream).poll_read(cx, buf))?;
        self.hasher.update(&buf.filled()[start..]);
        Ok(()).into()
    }
}
impl<S> AsyncWrite for Poly1305Stream<S, Poly1305Writer>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let n = ready!(Pin::new(&mut self.stream).poll_write(cx, buf))?;
        self.hasher.update(&buf[..n]);
        Ok(n).into()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::config::tests::create_random_config;

    use super::*;

    #[tokio::test]
    async fn test_halves() {
        let config = create_random_config();

        let (client, server) = tokio::io::duplex(1024);
        let mut client = WriteHalf::new(*config.key(), client);
        let mut server = ReadHalf::new(*config.key(), server);

        let data = b"Hello, world!";
        let mut buf = [0u8; 1024];

        for _ in 0..1024 {
            client.write_all(data).await.unwrap();
            server.read_exact(&mut buf[..data.len()]).await.unwrap();
            assert_eq!(&buf[..data.len()], data);
        }
    }

    #[tokio::test]
    async fn test_whole() {
        let config = create_random_config();

        let (client, server) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(client);
        let mut client = WholeStream::from_key_halves(*config.key(), r, w);
        let (r, w) = tokio::io::split(server);
        let mut server = WholeStream::from_key_halves(*config.key(), r, w);

        let data = b"Hello, world!";
        let mut buf = [0u8; 1024];

        for _ in 0..1024 {
            client.write_all(data).await.unwrap();
            server.read_exact(&mut buf[..data.len()]).await.unwrap();
            assert_eq!(&buf[..data.len()], data);
        }
    }
}
