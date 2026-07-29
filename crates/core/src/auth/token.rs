use crate::auth::pkce::{AuthConfig, PendingAuth};
use chrono::{DateTime, TimeDelta, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const USER_AGENT: &str = concat!("quoata-board/", env!("CARGO_PKG_VERSION"));
/// docs/design.md §5.2: this is the only `anthropic-beta` value we ever send.
pub const ANTHROPIC_BETA: &str = "oauth-2025-04-20";
/// docs/design.md §10.5: treat a token as expired 5 minutes ahead of its
/// reported expiry, so a request in flight never straddles the boundary.
pub const EXPIRY_SKEW_SECS: i64 = 300;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("state mismatch — the callback cannot be trusted")]
    StateMismatch,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("OAuth error {status}: {code:?} {description:?}")]
    OAuth { status: u16, code: Option<String>, description: Option<String> },
    #[error("failed to parse the response: {0}")]
    Decode(String),
}

impl AuthError {
    /// Whether the refresh chain is permanently dead. docs/design.md §10.5 —
    /// the account is quarantined on the first strike, not retried.
    pub fn is_dead_grant(&self) -> bool {
        matches!(self, AuthError::OAuth { code, .. } if code.as_deref() == Some("invalid_grant"))
    }
    /// Whether the caller should retry once with the stored scopes sent back
    /// verbatim. docs/design.md §10.5.
    pub fn is_invalid_scope(&self) -> bool {
        matches!(self, AuthError::OAuth { status: 400, code, .. }
            if code.as_deref() == Some("invalid_scope"))
    }
}

/// The token bundle that goes into storage. docs/design.md §9.3.
///
/// `Debug` is hand-written, not derived — see below. `Serialize`/`Deserialize`
/// stay derived; the encrypted store (Task 10) needs the real values, only
/// *printing* them is the hazard.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token_expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
    pub client_id: String,
}

/// Redacts both token fields. A derived `Debug` would print `access_token`
/// and `refresh_token` in full — into a `tracing::debug!(?tokens)`, an
/// `assert_eq!` failure, an `unwrap_err()` on an `Ok` — any of which can land
/// in a log file or CI output. This is the redaction shape the rest of this
/// crate (Task 10's storage/refresh, Task 12's usage client) should copy for
/// any type that carries a live credential: hand-write `Debug`, never derive
/// it, print `"<redacted>"` for the sensitive fields.
impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .field("scopes", &self.scopes)
            .field("client_id", &self.client_id)
            .finish()
    }
}

impl TokenSet {
    pub fn needs_refresh(&self) -> bool {
        Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS) >= self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct AccountIdentity {
    pub uuid: String,
    pub email: String,
}

/// The HTTP seam — domain code never sees `reqwest` directly, so it can be
/// swapped for a mock in tests without any real network traffic.
pub trait TokenHttp: Send + Sync {
    fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<T, AuthError>> + Send;

    fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        bearer: &str,
    ) -> impl std::future::Future<Output = Result<T, AuthError>> + Send;

    fn user_agent(&self) -> &str;
}

pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    pub fn new() -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AuthError::Transport(e.to_string()))?;
        Ok(Self { client })
    }
}

/// On a non-2xx response, read the body so the RFC 6749 error code and
/// description survive. Calling `error_for_status()` instead would discard
/// the body along with that information, leaving failures undebuggable.
async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, AuthError> {
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| AuthError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        return Err(AuthError::OAuth {
            status,
            code: v.get("error").and_then(|x| x.as_str()).map(str::to_string),
            description: v.get("error_description").and_then(|x| x.as_str()).map(str::to_string),
        });
    }
    // Do not fold `text` into this message: on the 2xx branch it is the raw
    // token response body, and it can carry `access_token`/`refresh_token`
    // verbatim. `secrets` had exactly this defect once (a parse error that
    // embedded the value it failed to read) — the serde error alone is enough
    // to debug a schema mismatch without repeating it here.
    serde_json::from_str(&text).map_err(|e| AuthError::Decode(e.to_string()))
}

impl TokenHttp for ReqwestHttp {
    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T, AuthError> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| AuthError::Transport(e.to_string()))?;
        decode(resp).await
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str, bearer: &str) -> Result<T, AuthError> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(bearer)
            .header("anthropic-beta", ANTHROPIC_BETA)
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| AuthError::Transport(e.to_string()))?;
        decode(resp).await
    }

    fn user_agent(&self) -> &str {
        USER_AGENT
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    refresh_token_expires_in: Option<i64>,
    scope: Option<String>,
    account: Option<AccountBlock>,
}

#[derive(Deserialize)]
struct AccountBlock {
    uuid: String,
    email_address: Option<String>,
}

/// authorization_code → token exchange. docs/design.md §10.3.
///
/// **The body is JSON, not form-encoded.** It also carries `state`, which is
/// non-standard for a token request — but it is the shape this server
/// expects.
pub async fn exchange_code<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfig,
    pending: &PendingAuth,
    code: &str,
    returned_state: &str,
) -> Result<(TokenSet, Option<AccountIdentity>), AuthError> {
    // Validate state before the network call, not after — a mismatch here
    // means the code did not come from the authorize request we started, and
    // no response body can make that trustworthy.
    if returned_state != pending.state {
        return Err(AuthError::StateMismatch);
    }

    let body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": pending.redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": pending.verifier,
        "state": pending.state,
    });

    let r: TokenResponse = http.post_json(&cfg.token_url, &body).await?;

    let scopes = r
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|| cfg.scopes.clone());

    // Only the initial exchange falls back to 30 days when the field is
    // missing; a refresh must keep the previously stored value instead
    // (docs/design.md §10.5) — this function is only ever the initial path.
    let refresh_expiry = TimeDelta::seconds(r.refresh_token_expires_in.unwrap_or(2_592_000));

    let tokens = TokenSet {
        access_token: r.access_token,
        refresh_token: r.refresh_token,
        expires_at: Utc::now() + TimeDelta::seconds(r.expires_in),
        refresh_token_expires_at: Utc::now() + refresh_expiry,
        scopes,
        client_id: cfg.client_id.clone(),
    };

    let identity = r.account.map(|a| AccountIdentity { uuid: a.uuid, email: a.email_address.unwrap_or_default() });

    Ok((tokens, identity))
}

fn refresh_body(cfg: &AuthConfig, tokens: &TokenSet) -> serde_json::Value {
    serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": tokens.refresh_token,
        "client_id": cfg.client_id,
        // Send the stored scopes back verbatim. Falling back to a
        // hardcoded list here would silently narrow the scopes on every
        // refresh, and the narrowing is cumulative and invisible until
        // something that needed the dropped scope stops working.
        "scope": tokens.scopes.join(" "),
    })
}

/// refresh_token -> a new TokenSet. docs/design.md §10.5.
pub async fn refresh<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfig,
    tokens: &TokenSet,
) -> Result<TokenSet, AuthError> {
    let body = refresh_body(cfg, tokens);
    let r: TokenResponse = match http.post_json(&cfg.token_url, &body).await {
        Ok(r) => r,
        Err(e) if e.is_invalid_scope() => {
            // Retry exactly once with the identical body. This covers a
            // transient scope rejection from the server, not an attempt to
            // change the scopes — sending anything else here would defeat
            // the verbatim rule above.
            http.post_json(&cfg.token_url, &body).await?
        }
        Err(e) => return Err(e),
    };

    let scopes = r
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|| tokens.scopes.clone());

    Ok(TokenSet {
        access_token: r.access_token,
        refresh_token: r.refresh_token,
        expires_at: Utc::now() + TimeDelta::seconds(r.expires_in),
        // When absent, keep the previous value — do not fall back to 30
        // days. That fallback belongs only to the initial exchange
        // (see `exchange_code` above); reapplying it here would push the
        // expiry back on every refresh and the refresh token would never
        // actually expire.
        refresh_token_expires_at: match r.refresh_token_expires_in {
            Some(secs) => Utc::now() + TimeDelta::seconds(secs),
            None => tokens.refresh_token_expires_at,
        },
        scopes,
        client_id: cfg.client_id.clone(),
    })
}

/// Revokes the server-side token, e.g. on account deletion. Best-effort:
/// the result is discarded on purpose. A user deleting an account from this
/// app must not be blocked by the revocation endpoint being unreachable —
/// the local deletion proceeds either way.
pub async fn revoke<H: TokenHttp>(http: &H, cfg: &AuthConfig, refresh_token: &str) {
    let url = format!("{}/revoke", cfg.token_url);
    let body = serde_json::json!({
        "token": refresh_token,
        "token_type_hint": "refresh_token",
        "client_id": cfg.client_id,
    });
    let _: Result<serde_json::Value, _> = http.post_json(&url, &body).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::pkce::{AuthConfig, PendingAuth};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_json_string, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn pending() -> PendingAuth {
        PendingAuth {
            verifier: "test-verifier".into(),
            state: "test-state".into(),
            redirect_uri: "http://localhost:1234/callback".into(),
        }
    }

    async fn cfg_for(server: &MockServer) -> AuthConfig {
        AuthConfig { token_url: format!("{}/v1/oauth/token", server.uri()), ..AuthConfig::default() }
    }

    #[tokio::test]
    async fn exchange_sends_a_json_body_not_a_form() {
        let server = MockServer::start().await;
        let expected = serde_json::json!({
            "grant_type": "authorization_code",
            "code": "the-code",
            "redirect_uri": "http://localhost:1234/callback",
            "client_id": AuthConfig::default().client_id,
            "code_verifier": "test-verifier",
            "state": "test-state"
        })
        .to_string();

        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .and(body_json_string(expected))
            // Pins the wire user agent, not just the constant: if `ReqwestHttp`
            // ever stopped sending `USER_AGENT` (or sent something else, e.g.
            // "claude-code/1.0.0"), the mock would not match, the request
            // would get wiremock's default 404, and this test would fail —
            // unlike a test that only re-reads the constant back.
            .and(header("user-agent", USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at", "refresh_token": "rt",
                "expires_in": 27000, "refresh_token_expires_in": 2592000,
                "scope": "user:profile user:inference",
                "account": { "uuid": "acc-1", "email_address": "a@example.com" }
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let (tokens, identity) =
            exchange_code(&http, &cfg_for(&server).await, &pending(), "the-code", "test-state")
                .await
                .unwrap();

        assert_eq!(tokens.access_token, "at");
        assert_eq!(tokens.refresh_token, "rt");
        assert_eq!(tokens.scopes, vec!["user:profile", "user:inference"]);
        assert_eq!(identity.unwrap().uuid, "acc-1");
    }

    /// docs/design.md §10.3: validate `state` before accepting the code.
    #[tokio::test]
    async fn mismatched_state_is_rejected_before_any_network_call() {
        let server = MockServer::start().await; // no mock mounted — a call reaching it fails the test
        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "WRONG").await.unwrap_err();
        assert!(matches!(err, AuthError::StateMismatch));
    }

    /// docs/design.md §10.5: the RFC 6749 error code in a 400 body must survive.
    #[tokio::test]
    async fn error_body_is_preserved_not_discarded() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "authorization code expired"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state").await.unwrap_err();
        match err {
            AuthError::OAuth { code, status, .. } => {
                assert_eq!(code.as_deref(), Some("invalid_grant"));
                assert_eq!(status, 400);
            }
            other => panic!("expected an OAuth error, got {other:?}"),
        }
    }

    /// docs/design.md §10.5: fall back to 30 days when refresh_token_expires_in
    /// is absent, but only on the initial exchange.
    #[tokio::test]
    async fn missing_refresh_expiry_falls_back_to_thirty_days_on_initial_exchange() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at", "refresh_token": "rt",
                "expires_in": 27000, "scope": "user:profile"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let (tokens, _) =
            exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state").await.unwrap();
        let days = (tokens.refresh_token_expires_at - chrono::Utc::now()).num_days();
        assert!((29..=30).contains(&days), "expected roughly 30 days, got {days}");
    }

    /// A derived `Debug` would print both tokens verbatim into any
    /// `{:?}`/`?tokens` tracing call, `assert_eq!` failure, or `unwrap_err()`
    /// on an `Ok`. That is a wider aperture than the `Decode`-leak test below
    /// guards, since it fires on the success path, not just a parse failure.
    #[test]
    fn tokenset_debug_redacts_both_tokens() {
        let tokens = TokenSet {
            access_token: "sk-ant-access-SENTINEL".into(),
            refresh_token: "sk-ant-refresh-SENTINEL".into(),
            expires_at: chrono::Utc::now(),
            refresh_token_expires_at: chrono::Utc::now(),
            scopes: vec!["user:profile".into()],
            client_id: "client-1".into(),
        };
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("SENTINEL"), "Debug output leaked a token: {debug}");
        assert!(debug.contains("<redacted>"), "expected the redaction marker, got: {debug}");
        // Non-sensitive fields should still be visible — this is redaction,
        // not a black box.
        assert!(debug.contains("client-1"));
    }

    /// `secrets` once had a parse-failure path whose error message embedded
    /// the secret value it failed to read. Guard against the same shape here:
    /// a 2xx response that fails to deserialize must not echo the token it
    /// carries into the error.
    #[tokio::test]
    async fn decode_failure_on_a_2xx_body_does_not_leak_the_token_into_the_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            // "expires_in" is required by `TokenResponse` and is missing here,
            // so decoding fails even though the status is 200.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "sk-ant-LEAKED-TOKEN", "refresh_token": "rt"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state").await.unwrap_err();
        assert!(matches!(err, AuthError::Decode(_)), "expected a Decode error, got {err:?}");
        let msg = err.to_string();
        assert!(!msg.contains("LEAKED-TOKEN"), "the decode error exposed the access token: {msg}");
    }

    /// This only re-reads the constant, so on its own it is tautological: it
    /// cannot see what actually went out on the wire, and would stay green
    /// even if `ReqwestHttp::new` stopped applying `.user_agent(USER_AGENT)`
    /// to the client. Kept as a cheap sanity check on the constant's shape;
    /// `exchange_sends_a_json_body_not_a_form` and
    /// `get_json_sends_the_oauth_beta_header_and_no_claude_identifying_header`
    /// are what actually pin the wire behavior.
    #[tokio::test]
    async fn user_agent_is_ours_never_claude_code() {
        let http = ReqwestHttp::new().unwrap();
        assert!(http.user_agent().starts_with("quoata-board/"));
        assert!(!http.user_agent().contains("claude"));
    }

    #[derive(serde::Deserialize)]
    struct Ping {
        ok: bool,
    }

    /// `get_json` had no coverage at all before this. Captures the actual
    /// request `get_json` sends and inspects every header on it — not just
    /// the one this test happens to name — so a header added anywhere later
    /// that leaks "claude" (product name, package name, anything) would be
    /// caught here, not only a change to `user-agent` specifically.
    #[tokio::test]
    async fn get_json_sends_the_oauth_beta_header_and_no_claude_identifying_header() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        Mock::given(method("GET"))
            .and(path("/v1/ping"))
            .respond_with(move |req: &Request| {
                *captured_clone.lock().unwrap() = Some(req.clone());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true}))
            })
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let resp: Ping = http
            .get_json(&format!("{}/v1/ping", server.uri()), "bearer-token")
            .await
            .unwrap();
        assert!(resp.ok);

        let req = captured.lock().unwrap().take().expect("get_json never reached the mock");

        let beta = req.headers.get("anthropic-beta").expect("anthropic-beta header missing");
        assert_eq!(beta.to_str().unwrap(), ANTHROPIC_BETA);

        for (name, value) in req.headers.iter() {
            let v = value.to_str().unwrap_or_default().to_lowercase();
            assert!(!v.contains("claude"), "header `{name}` leaked a Claude-identifying value: {v}");
        }
    }

    fn tokens_with(scopes: &[&str]) -> TokenSet {
        TokenSet {
            access_token: "old-at".into(),
            refresh_token: "old-rt".into(),
            expires_at: Utc::now() - TimeDelta::seconds(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            client_id: AuthConfig::default().client_id,
        }
    }

    /// The single most important rule in docs/design.md §10.5: refresh must
    /// send back the scopes exactly as stored, not a hardcoded list.
    #[tokio::test]
    async fn refresh_sends_the_stored_scopes_verbatim() {
        let server = MockServer::start().await;
        let stored = ["user:profile", "user:inference", "user:mcp_servers"];
        let expected = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": "old-rt",
            "client_id": AuthConfig::default().client_id,
            "scope": "user:profile user:inference user:mcp_servers"
        })
        .to_string();

        Mock::given(method("POST"))
            .and(body_json_string(expected))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-at", "refresh_token": "new-rt",
                "expires_in": 27000,
                "scope": "user:profile user:inference user:mcp_servers"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let out = refresh(&http, &cfg_for(&server).await, &tokens_with(&stored))
            .await
            .unwrap();
        assert_eq!(out.access_token, "new-at");
        assert_eq!(out.scopes, stored);
    }

    /// When the refresh response omits `refresh_token_expires_in`, keep the
    /// previous value. Falling back to 30 days here would push the expiry
    /// back on every refresh, so the refresh token would never actually
    /// expire.
    #[tokio::test]
    async fn refresh_keeps_the_previous_refresh_expiry_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-at", "refresh_token": "new-rt",
                "expires_in": 27000, "scope": "user:profile"
            })))
            .mount(&server)
            .await;

        let before = tokens_with(&["user:profile"]);
        let http = ReqwestHttp::new().unwrap();
        let after = refresh(&http, &cfg_for(&server).await, &before).await.unwrap();
        assert_eq!(after.refresh_token_expires_at, before.refresh_token_expires_at);
    }

    /// docs/design.md §10.5: `invalid_scope` gets exactly one retry, using
    /// the stored scopes verbatim.
    #[tokio::test]
    async fn invalid_scope_is_retried_exactly_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_scope"
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "second-try", "refresh_token": "rt2",
                "expires_in": 27000, "scope": "user:profile"
            })))
            // Capped to one use, not just eventually asserted: a stray extra
            // retry would land here again and produce the same success body,
            // so the final `access_token` alone cannot tell "retried once"
            // apart from "retried twice". Capping turns a surplus retry into
            // an observable failure (the third call falls through to no
            // mock at all) instead of a silently identical success.
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let out = refresh(&http, &cfg_for(&server).await, &tokens_with(&["user:profile"]))
            .await
            .unwrap();
        assert_eq!(out.access_token, "second-try");
    }

    /// docs/design.md §10.5: `invalid_grant` is not retried — every retry
    /// would only burn a fresh 401/429, not recover the chain.
    #[tokio::test]
    async fn invalid_grant_fails_immediately_and_is_flagged_dead() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .expect(1) // must be called exactly once — no retry
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = refresh(&http, &cfg_for(&server).await, &tokens_with(&["user:profile"]))
            .await
            .unwrap_err();
        assert!(err.is_dead_grant());
    }

    #[test]
    fn needs_refresh_respects_the_five_minute_skew() {
        let mut t = tokens_with(&["user:profile"]);
        t.expires_at = Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS - 10);
        assert!(t.needs_refresh(), "inside the skew window still counts as needing a refresh");
        t.expires_at = Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS + 60);
        assert!(!t.needs_refresh());
    }
}
