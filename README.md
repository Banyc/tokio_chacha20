# `tokio_chacha20`

## How to use

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
