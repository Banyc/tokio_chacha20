mod read;
pub use read::ReadHalf;
mod whole;
pub use whole::WholeStream;
mod write;
pub use write::WriteHalf;

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
