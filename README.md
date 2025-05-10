# `tokio_chacha20`

ChaCha20 and Poly1305 primitives (primitives are not AEAD).

## How to use

Async:

```rust
let config = create_random_config();

let (client, server) = tokio::io::duplex(1024);
let (r, w) = tokio::io::split(client);
let mut client = WholeStream::from_key_halves(*config.key(), r, w);
let (r, w) = tokio::io::split(server);
let mut server = WholeStream::from_key_halves(*config.key(), r, w);

let data = b"Hello, world!";
let mut buf = [0u8; 1024];
client.write_all(data).await.unwrap();
server.read_exact(&mut buf[..data.len()]).await.unwrap();
```

Polling:

```rust
let config = create_random_config();

let msg = b"Hello world!";
let mut en = EncryptCursor::new(*config.key());
let mut de = DecryptCursor::new(*config.key());
let mut buf = [0; 1024];

let EncryptResult { read, written } = en.encrypt(msg, &mut buf);
assert_eq!(read, msg.len());
let encrypted_buf = &mut buf[..written];
let decrypted_start = match de.decrypt(encrypted_buf) {
    DecryptResult::StillAtNonce => panic!(),
    DecryptResult::WithUserData { user_data_start } => user_data_start,
};
let decypted_buf = &encrypted_buf[decrypted_start..];
assert_eq!(decypted_buf, &msg[..]);
```
