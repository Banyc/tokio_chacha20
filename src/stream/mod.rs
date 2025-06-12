use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

mod read;
pub use read::{
    ChaCha20ReadStateConfig, ChaCha20Reader, ChaCha20ReaderConfig, NonceCiphertextReader,
    NonceCiphertextReaderConfig, TagReader,
};
mod duplex;
pub use duplex::DuplexStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
mod write;
pub use write::{
    ChaCha20WriteStateConfig, ChaCha20Writer, ChaCha20WriterConfig, NonceCiphertextTagWriter,
    NonceCiphertextTagWriterConfig,
};

use crate::{mac::Poly1305Hasher, KEY_BYTES, NONCE_BYTES, X_NONCE_BYTES};

#[derive(Debug, Clone)]
pub enum NonceBuf {
    Nonce(Box<[u8; NONCE_BYTES]>),
    XNonce(Box<[u8; X_NONCE_BYTES]>),
}

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
    use std::task::Waker;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        config::tests::create_random_config,
        stream::{read::NonceCiphertextReaderConfig, write::NonceCiphertextTagWriterConfig},
    };

    use super::*;

    #[tokio::test]
    async fn test_simplex_async() {
        let config = create_random_config();

        let (client, server) = tokio::io::duplex(1024);
        let (mut server, mut client) = same_key_nonce_ciphertext(config.key(), server, client);

        let data = b"Hello, world!";
        let mut buf = [0u8; 1024];

        for _ in 0..1024 {
            client.write_all(data).await.unwrap();
            server.read_exact(&mut buf[..data.len()]).await.unwrap();
            assert_eq!(&buf[..data.len()], data);
        }
    }

    #[test]
    fn test_simplex_polling() {
        let config = create_random_config();

        let msg = b"Hello world!";
        let mut nonce_ciphertext = vec![];

        let mut w = nonce_ciphertext_writer(config.key(), &mut nonce_ciphertext);
        unwrap_ready(Pin::new(&mut w).poll_write(&mut noop_context(), msg)).unwrap();

        let mut r = nonce_ciphertext_reader(config.key(), &nonce_ciphertext[..]);
        let mut read_buf = vec![0; 1024];
        let mut read_buf = ReadBuf::new(&mut read_buf);
        unwrap_ready(Pin::new(&mut r).poll_read(&mut noop_context(), &mut read_buf)).unwrap();
        assert_eq!(msg, read_buf.filled());
    }
    fn noop_context() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }
    fn unwrap_ready<T>(poll: Poll<T>) -> T {
        match poll {
            Poll::Ready(x) => x,
            Poll::Pending => panic!(),
        }
    }

    #[tokio::test]
    async fn test_duplex_async() {
        let config = create_random_config();

        let (client, server) = tokio::io::duplex(1024);
        let mut client = {
            let (r, w) = tokio::io::split(client);
            let (r, w) = same_key_nonce_ciphertext(config.key(), r, w);
            DuplexStream::new(r, w)
        };
        let mut server = {
            let (r, w) = tokio::io::split(server);
            let (r, w) = same_key_nonce_ciphertext(config.key(), r, w);
            DuplexStream::new(r, w)
        };

        let data = b"Hello, world!";
        let mut buf = [0u8; 1024];

        for _ in 0..1024 {
            client.write_all(data).await.unwrap();
            server.read_exact(&mut buf[..data.len()]).await.unwrap();
            assert_eq!(&buf[..data.len()], data);
        }
    }

    fn same_key_nonce_ciphertext<R, W>(
        key: &[u8; KEY_BYTES],
        r: R,
        w: W,
    ) -> (NonceCiphertextReader<R>, NonceCiphertextTagWriter<W>) {
        let r = nonce_ciphertext_reader(key, r);
        let w = nonce_ciphertext_writer(key, w);
        (r, w)
    }
    fn nonce_ciphertext_reader<R>(key: &[u8; KEY_BYTES], r: R) -> NonceCiphertextReader<R> {
        let reader_config = NonceCiphertextReaderConfig { hash: false };
        let nonce_buf = NonceBuf::Nonce(Box::new([0; NONCE_BYTES]));
        NonceCiphertextReader::new(&reader_config, Box::new(*key), nonce_buf, r)
    }
    fn nonce_ciphertext_writer<W>(key: &[u8; KEY_BYTES], w: W) -> NonceCiphertextTagWriter<W> {
        let writer_config = NonceCiphertextTagWriterConfig {
            write_nonce: true,
            write_tag: false,
            key,
        };
        let nonce = NonceBuf::Nonce(Box::new(rand::random()));
        NonceCiphertextTagWriter::new(&writer_config, nonce, w)
    }
}
