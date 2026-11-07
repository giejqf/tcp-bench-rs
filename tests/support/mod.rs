use tokio::io::{AsyncRead, AsyncReadExt};

pub async fn request(stream: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() <= 32768);
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
    }
}
