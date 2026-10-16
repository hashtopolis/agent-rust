//! A one-shot plain HTTP server on 127.0.0.1 that records the request head it
//! receives, and a url where nothing listens.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Answers exactly one HTTP/1.1 request with `200` and a fixed body, and
/// hands back the request head it received.
pub struct OneShot {
    pub url: String,
    handle: JoinHandle<String>,
}

impl OneShot {
    pub async fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());

        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = read_request(&mut socket).await;

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();

            head
        });

        Self { url, handle }
    }

    /// The request line and headers, lowercased so checks need not care
    /// about header case.
    pub async fn request_head(self) -> String {
        self.handle.await.unwrap().to_lowercase()
    }
}

/// A url on 127.0.0.1 where nothing listens, so connecting fails fast.
pub async fn closed_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/server.php", listener.local_addr().unwrap());
    drop(listener);

    url
}

/// Reads the head and drains a `content-length` body, so closing the
/// socket afterwards cannot reset a client that is still sending.
async fn read_request(socket: &mut TcpStream) -> String {
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];

    let head_end = loop {
        if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }

        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed before the request head ended");
        received.extend_from_slice(&buf[..n]);
    };

    let head = String::from_utf8_lossy(&received[..head_end]).into_owned();
    let body_len = head
        .lines()
        .find_map(|line| {
            line.to_lowercase()
                .strip_prefix("content-length:")
                .map(|value| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);

    while received.len() < head_end + body_len {
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed before the request body ended");
        received.extend_from_slice(&buf[..n]);
    }

    head
}
