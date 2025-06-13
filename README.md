# `tokio_chacha20`

ChaCha20 and Poly1305 primitives (primitives are not AEAD).

## How to use

Async:

```rust
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
```

Polling:

```rust
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
```

Cipher:

```rust
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
    let writer_config = NonceCiphertextWriterConfig {
        write_nonce: true,
        hash: false,
        key,
    };
    let nonce = NonceBuf::Nonce(Box::new(rand::random()));
    NonceCiphertextTagWriter::new(&writer_config, nonce, w)
}
```
