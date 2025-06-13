use std::{
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    task::{ready, Context, Poll},
};

use tokio::io::AsyncWrite;

use crate::{
    cipher::StreamCipher,
    mac::{poly1305_key_gen, Poly1305Hasher},
    stream::NonceBuf,
    KEY_BYTES,
};

#[derive(Debug, Clone)]
pub struct ChaCha20WriterConfig<'a> {
    pub state: &'a ChaCha20WriteStateConfig<'a>,
}
#[derive(Debug)]
pub struct ChaCha20Writer<W> {
    chacha20: ChaCha20WriteState,
    w: W,
}
impl<W> ChaCha20Writer<W> {
    pub fn new(config: &ChaCha20WriterConfig<'_>, w: W) -> Self {
        let chacha20 = ChaCha20WriteState::new(config.state);
        Self { chacha20, w }
    }
    pub fn into_inner(self) -> (W, Option<Poly1305Hasher>) {
        let hasher = self.chacha20.into_hasher();
        (self.w, hasher)
    }
}
impl<W> AsyncWrite for ChaCha20Writer<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.deref_mut();
        let mut w = Pin::new(&mut this.w);
        this.chacha20.poll(&mut w, buf, cx)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
pub struct ChaCha20WriteStateConfig<'a> {
    pub key: &'a [u8; KEY_BYTES],
    pub nonce: &'a NonceBuf,
    pub hash: bool,
}
#[derive(Debug, Clone)]
pub struct ChaCha20WriteState {
    cipher: StreamCipher,
    buf: Vec<u8>,
    buf_pos: usize,
    hasher: Option<Poly1305Hasher>,
}
impl ChaCha20WriteState {
    pub fn new(config: &ChaCha20WriteStateConfig<'_>) -> Self {
        let cipher = match config.nonce {
            NonceBuf::Nonce(nonce) => StreamCipher::new(*config.key, **nonce),
            NonceBuf::XNonce(nonce) => StreamCipher::new_x(*config.key, **nonce),
        };
        let hasher = if config.hash {
            let otk = poly1305_key_gen(cipher.block().key(), cipher.block().nonce());
            Some(Poly1305Hasher::new(&otk))
        } else {
            None
        };
        let buf = vec![];
        Self {
            cipher,
            buf,
            buf_pos: 0,
            hasher,
        }
    }
    pub fn into_hasher(self) -> Option<Poly1305Hasher> {
        self.hasher
    }
    pub fn poll<W>(
        &mut self,
        w: &mut W,
        buf: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            // Fill the inner buffer with encrypted data if it's empty
            if self.buf.len() == self.buf_pos {
                self.buf_pos = 0;
                self.buf.clear();
                self.buf.extend(buf);
                self.cipher.encrypt(&mut self.buf);
                if let Some(hasher) = self.hasher.as_mut() {
                    hasher.update(&self.buf);
                }
            }

            // Try to write `w` with the inner buffer
            let amt = ready!(Pin::new(&mut *w).poll_write(cx, &self.buf[self.buf_pos..]))?;

            // Remove the consumed data from the inner buffer
            self.buf_pos += amt;

            // Do not allow caller to switch buffers until the inner buffer is fully consumed
            if self.buf.len() == self.buf_pos {
                return Ok(buf.len()).into();
            }
        }
    }
}

#[derive(Debug)]
pub struct AllWriter<Buf, W> {
    buf: Buf,
    write_all: WriteAllState,
    w: W,
}
impl<Buf, W> AllWriter<Buf, W> {
    pub fn new(buf: Buf, w: W) -> Self {
        let write_all = WriteAllState::new();
        Self { buf, write_all, w }
    }
    pub fn into_inner(self) -> W {
        self.w
    }
}
impl<Buf, W> Future for AllWriter<Buf, W>
where
    Buf: AsRef<[u8]> + Unpin,
    W: AsyncWrite + Unpin,
{
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.deref_mut();
        ready!(this.write_all.poll(&mut this.w, this.buf.as_ref(), cx))?;
        Ok(()).into()
    }
}

#[derive(Debug, Clone)]
pub struct NonceCiphertextWriterConfig<'a> {
    pub key: &'a [u8; KEY_BYTES],
    pub write_nonce: bool,
    pub hash: bool,
}
#[derive(Debug)]
pub struct NonceCiphertextWriter<W> {
    nonce: Option<NonceBuf>,
    write_all_nonce: WriteAllState,
    chacha20: ChaCha20WriteState,
    w: W,
}
impl<W> NonceCiphertextWriter<W> {
    pub fn new(config: &NonceCiphertextWriterConfig<'_>, nonce: NonceBuf, w: W) -> Self {
        let chacha20_config = ChaCha20WriteStateConfig {
            key: config.key,
            nonce: &nonce,
            hash: config.hash,
        };
        let chacha20 = ChaCha20WriteState::new(&chacha20_config);
        let nonce = if config.write_nonce {
            Some(nonce)
        } else {
            None
        };
        Self {
            nonce,
            write_all_nonce: WriteAllState::new(),
            chacha20,
            w,
        }
    }
    pub fn into_inner(self) -> (W, Option<Poly1305Hasher>) {
        (self.w, self.chacha20.into_hasher())
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for NonceCiphertextWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.deref_mut();
        let mut w = Pin::new(&mut this.w);
        if let Some(nonce_buf) = &this.nonce {
            let nonce = match &nonce_buf {
                NonceBuf::Nonce(buf) => &buf[..],
                NonceBuf::XNonce(buf) => &buf[..],
            };
            ready!(this.write_all_nonce.poll(&mut w, nonce, cx))?;
        }
        let n = ready!(this.chacha20.poll(&mut w, buf, cx))?;
        Ok(n).into()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.w).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.w).poll_shutdown(cx)
    }
}

#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct WriteAllState {
    buf_pos: usize,
}
impl WriteAllState {
    pub fn new() -> Self {
        Self { buf_pos: 0 }
    }
    pub fn poll<W>(&mut self, w: &mut W, buf: &[u8], cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            let buf = &buf[self.buf_pos..];
            if buf.is_empty() {
                break;
            }
            let n = { ready!(Pin::new(&mut *w).poll_write(cx, buf))? };
            {
                self.buf_pos += n;
            }
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(()))
    }
}
