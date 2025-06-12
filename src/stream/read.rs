use std::{
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    task::{ready, Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    cipher::StreamCipher,
    mac::{poly1305_key_gen, Poly1305Hasher, BLOCK_BYTES},
    stream::NonceBuf,
    KEY_BYTES,
};

#[derive(Debug, Clone)]
pub struct ChaCha20ReaderConfig<'a> {
    pub state: &'a ChaCha20ReadStateConfig<'a>,
}
#[derive(Debug)]
pub struct ChaCha20Reader<R> {
    chacha20: ChaCha20ReadState,
    r: R,
}
impl<R> ChaCha20Reader<R> {
    pub fn new(config: &ChaCha20ReaderConfig<'_>, r: R) -> Self {
        let chacha20 = ChaCha20ReadState::new(config.state);
        Self { chacha20, r }
    }
}
impl<R> AsyncRead for ChaCha20Reader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.deref_mut();
        this.chacha20.poll(&mut this.r, cx, buf)
    }
}

#[derive(Debug, Clone)]
pub struct ChaCha20ReadStateConfig<'a> {
    pub key: &'a [u8; KEY_BYTES],
    pub nonce: &'a NonceBuf,
    pub hasher: bool,
}
#[derive(Debug)]
pub struct ChaCha20ReadState {
    cipher: StreamCipher,
    hasher: Option<Poly1305Hasher>,
}
impl ChaCha20ReadState {
    pub fn new(config: &ChaCha20ReadStateConfig<'_>) -> Self {
        let cipher = match config.nonce {
            NonceBuf::Nonce(nonce) => StreamCipher::new(*config.key, **nonce),
            NonceBuf::XNonce(nonce) => StreamCipher::new_x(*config.key, **nonce),
        };
        let hasher = if config.hasher {
            let otk = poly1305_key_gen(cipher.block().key(), cipher.block().nonce());
            Some(Poly1305Hasher::new(&otk))
        } else {
            None
        };
        Self { cipher, hasher }
    }
    pub fn poll<R>(
        &mut self,
        r: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin + ?Sized,
    {
        // Read data from the `r`
        ready!(Pin::new(&mut *r).poll_read(cx, buf))?;

        // Decrypt the read user data in place
        self.cipher.encrypt(buf.filled_mut());

        if let Some(hasher) = self.hasher.as_mut() {
            hasher.update(buf.filled());
        }

        Ok(()).into()
    }
}

#[derive(Debug)]
pub struct TagReader<R> {
    tag: Box<[u8; BLOCK_BYTES]>,
    read_exact_tag: ReadExactState,
    completed_tag: bool,
    r: R,
}
impl<R> TagReader<R> {
    pub fn new(r: R) -> Self {
        let tag = Box::new([0; BLOCK_BYTES]);
        let read_exact_tag = ReadExactState::new();
        Self {
            tag,
            read_exact_tag,
            completed_tag: false,
            r,
        }
    }
    pub fn tag(&self) -> Option<&[u8; BLOCK_BYTES]> {
        if !self.completed_tag {
            return None;
        }
        Some(&self.tag)
    }
}
impl<R> Future for TagReader<R>
where
    R: AsyncRead + Unpin,
{
    type Output = io::Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.deref_mut();
        ready!(this.read_exact_tag.poll(&mut this.r, &mut *this.tag, cx))?;
        self.completed_tag = true;
        Ok(()).into()
    }
}

#[derive(Debug, Clone)]
pub struct NonceCiphertextReaderConfig {
    pub hash: bool,
}
#[derive(Debug)]
pub struct NonceCiphertextReader<R> {
    nonce_buf: NonceBuf,
    read_exact_nonce: ReadExactState,
    key: Box<[u8; KEY_BYTES]>,
    chacha20: Option<ChaCha20ReadState>,
    hasher: bool,
    r: R,
}
impl<R> NonceCiphertextReader<R> {
    pub fn new(
        config: &NonceCiphertextReaderConfig,
        key: Box<[u8; KEY_BYTES]>,
        nonce_buf: NonceBuf,
        r: R,
    ) -> Self {
        let read_exact_nonce = ReadExactState::new();
        Self {
            nonce_buf,
            read_exact_nonce,
            key,
            chacha20: None,
            hasher: config.hash,
            r,
        }
    }
    pub fn finalize(&self) -> Option<[u8; BLOCK_BYTES]> {
        Some(self.chacha20.as_ref()?.hasher.as_ref()?.finalize())
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for NonceCiphertextReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.deref_mut();
        let nonce_buf = match &mut this.nonce_buf {
            NonceBuf::Nonce(buf) => &mut buf.as_mut()[..],
            NonceBuf::XNonce(buf) => &mut buf.as_mut()[..],
        };
        ready!(this.read_exact_nonce.poll(&mut this.r, nonce_buf, cx))?;
        let chacha20 = match this.chacha20.as_mut() {
            Some(chacha20) => chacha20,
            None => {
                let config = ChaCha20ReadStateConfig {
                    key: &this.key,
                    nonce: &this.nonce_buf,
                    hasher: this.hasher,
                };
                this.chacha20.get_or_insert(ChaCha20ReadState::new(&config))
            }
        };
        ready!(chacha20.poll(&mut this.r, cx, buf))?;
        Ok(()).into()
    }
}

#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct ReadExactState {
    buf_pos: usize,
}
impl ReadExactState {
    pub fn new() -> Self {
        Self { buf_pos: 0 }
    }
    pub fn poll<A>(
        &mut self,
        reader: &mut A,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>>
    where
        A: AsyncRead + Unpin + ?Sized,
    {
        let mut buf = ReadBuf::new(buf);
        buf.advance(self.buf_pos);
        loop {
            // if our buffer is empty, then we need to read some data to continue.
            let rem = buf.remaining();
            if rem != 0 {
                ready!(Pin::new(&mut *reader).poll_read(cx, &mut buf))?;
                self.buf_pos = buf.filled().len();
                if buf.remaining() == rem {
                    return Err(eof()).into();
                }
            } else {
                return Poll::Ready(Ok(buf.capacity()));
            }
        }
        fn eof() -> io::Error {
            io::Error::new(io::ErrorKind::UnexpectedEof, "early eof")
        }
    }
}
