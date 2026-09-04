use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The only loopback ports registered for OpenAI's Codex OAuth client.
pub const OPENAI_CALLBACK_PORTS: [u16; 2] = [1455, 1457];

/// How long the listener waits for a connected client to finish sending a
/// request line + headers before giving up on that one connection. Browsers
/// open speculative/preconnect sockets to a loopback origin that never carry
/// a request; without a bound, one of those would block the accept loop —
/// and with it, the real callback — forever. Short in tests so the covering
/// test doesn't have to sleep for the production value.
#[cfg(not(test))]
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const HEADER_READ_TIMEOUT: Duration = Duration::from_millis(200);

/// A loopback HTTP listener that receives exactly one OAuth callback whose
/// `state` matches the one the login flow started with.
pub struct Callback {
    port: u16,
    listener: TcpListener,
    callback_path: &'static str,
}

impl Callback {
    /// **Must be called before the authorize URL is built** — `redirect_uri()`
    /// needs the port assigned here, and that exact string has to match
    /// byte-for-byte at token exchange time.
    pub async fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            port,
            listener,
            callback_path: "/callback",
        })
    }

    /// Binds OpenAI's fixed allow-listed port, falling back from 1455 to 1457.
    /// An OS-assigned port cannot be used here: the authorization server would
    /// reject its redirect URI before the browser ever reached this listener.
    pub async fn bind_openai() -> std::io::Result<Self> {
        Self::bind_openai_ports(&OPENAI_CALLBACK_PORTS).await
    }

    pub(crate) async fn bind_openai_ports(ports: &[u16]) -> std::io::Result<Self> {
        let mut last_error = None;
        for port in ports {
            match TcpListener::bind(("127.0.0.1", *port)).await {
                Ok(listener) => {
                    let port = listener.local_addr()?.port();
                    return Ok(Self {
                        port,
                        listener,
                        callback_path: "/auth/callback",
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no OpenAI callback port was configured",
            )
        }))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The socket binds to `127.0.0.1`, but the redirect_uri string is
    /// literally `localhost` — docs/design.md §10.3. The token exchange sends
    /// this same string back, so the two have to agree byte-for-byte.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}{}", self.port, self.callback_path)
    }

    pub(crate) fn is_openai(&self) -> bool {
        self.callback_path == "/auth/callback"
    }

    /// Waits for a GET to this listener's provider-specific callback path whose
    /// `state` query parameter equals
    /// `expected_state`, 302-redirects it to `done_url`, and returns its query
    /// parameters. docs/design.md §10.3 puts this check in the loopback
    /// server itself, not only in the later token exchange — deliberately
    /// two layers, not redundant ones: this one guards the listener's single
    /// shot (see below), `exchange_code`'s guard is what actually keeps a
    /// mismatched code from ever reaching the token endpoint.
    ///
    /// Three kinds of requests do **not** consume the listener's one shot —
    /// each is answered and then the wait continues:
    /// - anything that isn't `GET /callback` (a browser's `/favicon.ico`
    ///   probe, for instance) gets a 404;
    /// - a `/callback` hit whose `state` does not match gets a 400
    ///   `Invalid state parameter`. Before this existed, a single stray or
    ///   forged request with the wrong state would consume the listener and
    ///   strand the real callback with nowhere to land — a denial of service
    ///   on the login flow, not just a wrong page;
    /// - a connection that never finishes sending a request within
    ///   [`HEADER_READ_TIMEOUT`] (again, a speculative/preconnect socket) is
    ///   simply dropped.
    ///
    /// Only a `/callback` request whose `state` matches completes the future.
    pub async fn wait_for_code(
        self,
        done_url: &str,
        expected_state: &str,
    ) -> std::io::Result<HashMap<String, String>> {
        loop {
            let (mut sock, _) = self.listener.accept().await?;

            let mut buf = Vec::with_capacity(2048);
            let mut chunk = [0u8; 1024];
            let header_result = tokio::time::timeout(HEADER_READ_TIMEOUT, async {
                loop {
                    let n = sock.read(&mut chunk).await?;
                    if n == 0 {
                        return Ok(None);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_string();
                        let mut parts = head.split_whitespace();
                        let method = parts.next().unwrap_or_default().to_string();
                        let t = parts.next().unwrap_or("/").to_string();
                        return Ok(if method == "GET" { Some(t) } else { None });
                    }
                    if buf.len() > 64 * 1024 {
                        return Ok(None); // a request that never sends a blank line — bail rather than grow forever
                    }
                }
            })
            .await;

            let target = match header_result {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    // Never finished sending a request within the timeout.
                    // Drop this connection and keep waiting — it must not
                    // block the real callback.
                    continue;
                }
            };

            let Some(target) = target else {
                let _ = sock
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = sock.shutdown().await;
                continue;
            };

            let parsed = match url::Url::parse(&format!("http://127.0.0.1:{}{}", self.port, target))
            {
                Ok(u) => u,
                Err(_) => continue,
            };

            if parsed.path() != self.callback_path {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                let _ = sock.shutdown().await;
                continue;
            }

            let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

            if params.get("state").map(String::as_str) != Some(expected_state) {
                // docs/design.md §10.3: 400 on a state mismatch, and the
                // listener keeps waiting rather than consuming its one shot
                // on what may be a stray or forged request.
                const BODY: &str = "Invalid state parameter";
                let resp = format!(
                    "HTTP/1.1 400 Bad Request\r\ncontent-length: {}\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n{}",
                    BODY.len(),
                    BODY
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
                continue;
            }

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
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(format!("{request_line}\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        s.flush().await.unwrap();
    }

    /// Sends a request and reads the response back, for tests that need to
    /// see what the listener replied (not just whether it completed).
    async fn send_and_read(port: u16, request_line: &str) -> String {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(format!("{request_line}\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        s.flush().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn returns_the_query_params_of_a_callback_request() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task =
            tokio::spawn(async move { cb.wait_for_code("https://done.example", "xyz").await });
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
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example", "s").await });
        send(port, "GET /favicon.ico HTTP/1.1").await;
        send(port, "GET /callback?code=real&state=s HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "real");
    }

    #[tokio::test]
    async fn percent_encoded_values_are_decoded() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example", "s").await });
        send(port, "GET /callback?code=a%2Bb%2Fc&state=s HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "a+b/c");
    }

    #[tokio::test]
    async fn redirect_uri_uses_localhost_literal_and_the_real_port() {
        let cb = Callback::bind().await.unwrap();
        let uri = cb.redirect_uri();
        assert!(
            uri.starts_with("http://localhost:"),
            "docs/design.md §10.3: literally localhost"
        );
        assert!(uri.ends_with("/callback"));
        assert!(
            uri.contains(&cb.port().to_string()),
            "must contain the actually assigned port"
        );
    }

    #[test]
    fn openai_ports_are_the_registered_pair_in_preference_order() {
        assert_eq!(OPENAI_CALLBACK_PORTS, [1455, 1457]);
    }

    #[tokio::test]
    async fn openai_callback_falls_back_and_uses_the_auth_callback_path() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first = occupied.local_addr().unwrap().port();
        let reserve_second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = reserve_second.local_addr().unwrap().port();
        drop(reserve_second);

        let cb = Callback::bind_openai_ports(&[first, second]).await.unwrap();
        assert_eq!(cb.port(), second);
        assert_eq!(
            cb.redirect_uri(),
            format!("http://localhost:{second}/auth/callback")
        );
        assert!(cb.is_openai());
    }

    #[tokio::test]
    async fn openai_listener_accepts_only_the_auth_callback_path() {
        let cb = Callback::bind_openai_ports(&[0]).await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example", "s").await });

        let response = send_and_read(port, "GET /callback?code=wrong&state=s HTTP/1.1").await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "wrong path was accepted: {response}"
        );
        send(port, "GET /auth/callback?code=real&state=s HTTP/1.1").await;
        assert_eq!(
            task.await.unwrap().unwrap().get("code").map(String::as_str),
            Some("real")
        );
    }

    /// docs/design.md §10.3: a wrong `state` gets 400 in the listener itself,
    /// and — critically — does not strand the real callback. Before this
    /// check existed, a single stray or forged request with the wrong state
    /// would consume the listener's one accept and the user would have to
    /// restart the whole login.
    #[tokio::test]
    async fn wrong_state_gets_400_and_the_listener_keeps_waiting_for_the_real_one() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task =
            tokio::spawn(async move { cb.wait_for_code("https://done.example", "expected").await });

        let resp = send_and_read(port, "GET /callback?code=x&state=wrong HTTP/1.1").await;
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "expected a 400, got: {resp}"
        );
        assert!(
            resp.contains("Invalid state parameter"),
            "expected the RFC-shaped body, got: {resp}"
        );

        send(port, "GET /callback?code=real&state=expected HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "real");
    }

    /// A browser's speculative/preconnect socket to the loopback origin can
    /// connect and never write anything. Without a timeout on the header
    /// read, that connection would sit in `sock.read().await` forever and
    /// the real callback — queued behind it — would never be accepted.
    #[tokio::test]
    async fn a_connection_that_never_sends_a_request_does_not_block_the_listener() {
        let cb = Callback::bind().await.unwrap();
        let port = cb.port();
        let task = tokio::spawn(async move { cb.wait_for_code("https://done.example", "s").await });

        // Connect and deliberately never write — simulates the stalled probe.
        let _stalled = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();

        send(port, "GET /callback?code=real&state=s HTTP/1.1").await;
        let params = task.await.unwrap().unwrap();
        assert_eq!(params.get("code").unwrap(), "real");
    }
}
