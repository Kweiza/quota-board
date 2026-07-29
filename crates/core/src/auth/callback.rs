use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A loopback HTTP listener that receives exactly one OAuth callback.
pub struct Callback {
    port: u16,
    listener: TcpListener,
}

impl Callback {
    /// **Must be called before the authorize URL is built** — `redirect_uri()`
    /// needs the port assigned here, and that exact string has to match
    /// byte-for-byte at token exchange time.
    pub async fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self { port, listener })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The socket binds to `127.0.0.1`, but the redirect_uri string is
    /// literally `localhost` — docs/design.md §10.3. The token exchange sends
    /// this same string back, so the two have to agree byte-for-byte.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}/callback", self.port)
    }

    /// Accepts a single `GET /callback`, replies with a 302, and returns its
    /// query parameters. Any other request (a browser's `/favicon.ico` probe,
    /// for instance) gets a 404 and the wait continues — this listener has
    /// exactly one shot at the real callback, and it must not spend it on
    /// incidental noise.
    pub async fn wait_for_code(self, done_url: &str) -> std::io::Result<HashMap<String, String>> {
        loop {
            let (mut sock, _) = self.listener.accept().await?;

            let mut buf = Vec::with_capacity(2048);
            let mut chunk = [0u8; 1024];
            let target = loop {
                let n = sock.read(&mut chunk).await?;
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..p]).to_string();
                    let mut parts = head.split_whitespace();
                    let method = parts.next().unwrap_or_default().to_string();
                    let t = parts.next().unwrap_or("/").to_string();
                    break if method == "GET" { Some(t) } else { None };
                }
                if buf.len() > 64 * 1024 {
                    break None; // a request that never sends a blank line — bail rather than grow forever
                }
            };

            let Some(target) = target else {
                let _ = sock
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = sock.shutdown().await;
                continue;
            };

            let parsed = match url::Url::parse(&format!("http://127.0.0.1:{}{}", self.port, target)) {
                Ok(u) => u,
                Err(_) => continue,
            };

            if parsed.path() != "/callback" {
                let _ = sock
                    .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = sock.shutdown().await;
                continue;
            }

            let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {done_url}\r\ncontent-length: 0\r\ncache-control: no-store\r\nconnection: close\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await?;
            sock.flush().await?;
            let _ = sock.shutdown().await;
            return Ok(params);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn send(port: u16, request_line: &str) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("{request_line}\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        s.flush().await.unwrap();
    }

    #[tokio::test]
    async fn returns_the_query_params_of_a_callback_request() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example").await });
        send(port, "GET /callback?code=abc123&state=xyz HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "abc123");
        assert_eq!(params.get("state").unwrap(), "xyz");
    }

    /// The browser probes the loopback origin for `/favicon.ico`. Spending the
    /// listener's one shot on that would stall the login forever.
    #[tokio::test]
    async fn favicon_probe_does_not_consume_the_single_shot() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example").await });
        send(port, "GET /favicon.ico HTTP/1.1").await;
        send(port, "GET /callback?code=real&state=s HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "real");
    }

    #[tokio::test]
    async fn percent_encoded_values_are_decoded() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example").await });
        send(port, "GET /callback?code=a%2Bb%2Fc&state=s HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "a+b/c");
    }

    #[tokio::test]
    async fn redirect_uri_uses_localhost_literal_and_the_real_port() {
        let cb = Callback::bind().await.unwrap();
        let uri = cb.redirect_uri();
        assert!(uri.starts_with("http://localhost:"), "docs/design.md §10.3: literally localhost");
        assert!(uri.ends_with("/callback"));
        assert!(uri.contains(&cb.port().to_string()), "must contain the actually assigned port");
    }
}
