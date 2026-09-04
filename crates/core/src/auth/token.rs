use crate::auth::pkce::PendingAuth;
use crate::provider::{Provider, ProviderSpec};
use chrono::{DateTime, TimeDelta, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const USER_AGENT: &str = concat!("quota-board/", env!("CARGO_PKG_VERSION"));
/// docs/design.md §5.2: this is the only `anthropic-beta` value we ever send.
pub const ANTHROPIC_BETA: &str = "oauth-2025-04-20";
/// docs/design.md §10.5: treat a token as expired 5 minutes ahead of its
/// reported expiry, so a request in flight never straddles the boundary.
pub const EXPIRY_SKEW_SECS: i64 = 300;

/// docs/design.md §10.6: `revoke` gets its own, shorter timeout than the
/// 30-second default baked into `ReqwestHttp`'s client. Task 18's settings
/// window awaits `revoke` directly when a user deletes an account; an
/// unreachable revoke endpoint must not hold that deletion hostage for as
/// long as an ordinary request is allowed to run. Keep this separate from
/// the client-level timeout — do not "unify" the two.
///
/// Short in tests so the covering tests don't have to wait out the
/// production value — same reasoning as `HEADER_READ_TIMEOUT` in
/// `callback.rs`.
#[cfg(not(test))]
const REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(test)]
const REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

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
    /// OpenAI's ID token carried no `chatgpt_user_id` and no namespaced
    /// `auth.user_id`. Anthropic returns `Ok(None)` instead when its measured
    /// `account` block is absent; its caller supplies that provider-specific
    /// refusal.
    /// **Never carries the body**: the body holds the tokens, and CLAUDE.md
    /// forbids a live credential reaching an error message.
    #[error("the token response carried no account identifier")]
    NoAccountIdentifier,
    /// A rotated OpenAI grant changed the user or workspace under the stored
    /// key. Keeping it would make one row act with another identity's token.
    #[error("the refreshed token belongs to a different account or workspace")]
    IdentityMismatch,
    #[error("the device code expired before it was approved")]
    DeviceCodeExpired,
    /// The issuer explicitly reported that this public client's device flow is
    /// unavailable. A host can offer a provider-specific explanation; parsing
    /// this out of server prose would make localization impossible.
    #[error("device-code login is not available")]
    DeviceCodeUnavailable,
}

impl AuthError {
    /// Whether the refresh chain is permanently dead for this provider.
    /// docs/design.md §10.5 — the account is quarantined on the first strike,
    /// not retried.
    ///
    /// A bare 401 is terminal at OpenAI's refresh endpoint. Anthropic's
    /// terminal contract is an explicit invalid-grant code; sharing OpenAI's
    /// status-only rule would quarantine a Claude account without evidence
    /// that its rotating chain is dead.
    pub fn is_dead_grant_for(&self, provider: Provider) -> bool {
        match self {
            AuthError::IdentityMismatch => true,
            AuthError::OAuth { status, code, .. } => {
                (*status == 401 && provider == Provider::Openai)
                    || matches!(
                        code.as_deref().map(str::to_ascii_lowercase).as_deref(),
                        Some(
                            "invalid_grant"
                                | "refresh_token_reused"
                                | "refresh_token_expired"
                                | "refresh_token_invalidated"
                        )
                    )
            }
            _ => false,
        }
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
    /// Returns the typed value **and** the raw body it was parsed from, from
    /// one parse of one response — not a second request. `exchange_code` needs
    /// both: the ordinary token fields, typed, and the raw body for
    /// `identity_from`'s per-provider walk, which must not depend on a struct
    /// field succeeding for a shape (OpenAI's) that has never been measured.
    fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<(T, serde_json::Value), AuthError>> + Send;

    /// OpenAI's authorization-code exchange transport:
    /// `application/x-www-form-urlencoded`, as opposed to Anthropic's JSON.
    fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<(T, serde_json::Value), AuthError>> + Send;

    /// A JSON POST whose status is part of the protocol rather than merely an
    /// error. OpenAI's device poll uses 403 and 404 for "not approved yet",
    /// and its refresh endpoint has provider-specific terminal error codes, so
    /// decoding every non-2xx into one generic OAuth error would discard the
    /// information those callers need.
    fn post_json_response(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<TokenHttpResponse, AuthError>> + Send;

    fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        bearer: &str,
    ) -> impl std::future::Future<Output = Result<T, AuthError>> + Send;

    fn user_agent(&self) -> &str;
}

/// Status and bytes from an auth POST.
///
/// Deliberately has no `Debug`: successful OpenAI token responses carry three
/// live credentials, and deriving it would make a log or assertion print all
/// of them. Callers parse the bytes immediately and never put them in an error.
pub struct TokenHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct ReqwestHttp {
    client: reqwest::Client,
}

/// Which root certificates TLS is verified against.
///
/// **This crate deliberately stops deciding.** The default is unchanged and is
/// what every desktop caller uses: `rustls-platform-verifier`, which asks the
/// operating system. But a host that knows its platform better than this crate
/// does can supply the roots itself, and one has to.
///
/// The measured reason, on Android 16 / API 36 (2026-08-02): the platform
/// verifier hands the chain to Android's `CertPathValidator`, which insists on
/// revocation information and answers
///
/// ```text
/// java.security.cert.CertPathValidatorException: Certificate does not specify OCSP responder
/// ```
///
/// for `api.anthropic.com` and `platform.claude.com` — surfacing as
/// `invalid peer certificate: Revoked`. In the same process and the same run,
/// `www.google.com` and `example.com` verified fine, so this is a property of
/// the certificates (no OCSP responder in their AIA extension, which is where
/// the web is going) rather than of the device. Apple's verifier accepts them,
/// which is why iOS never saw it.
///
/// [`TrustRoots::Only`] routes through rustls' own WebPKI verifier instead,
/// which checks the chain and the name and does not demand revocation data.
/// **It replaces the platform verifier rather than adding to it** — that is the
/// point, and it is also the cost: nothing the OS trusts is consulted unless
/// the caller passes it in.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum TrustRoots {
    /// Ask the operating system. The default, and unchanged behaviour.
    #[default]
    Platform,
    /// Trust exactly these DER-encoded certificates and nothing else.
    Only(Vec<Vec<u8>>),
}

/// Hand-written for legibility rather than for secrecy — root certificates are
/// public by definition, but a whole platform trust store is roughly 150 of
/// them and a `Debug` that prints every byte is a log nobody reads.
impl std::fmt::Debug for TrustRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform => f.write_str("TrustRoots::Platform"),
            Self::Only(roots) => write!(f, "TrustRoots::Only({} roots)", roots.len()),
        }
    }
}

impl ReqwestHttp {
    /// The operating system's trust store. What every desktop caller wants.
    pub fn new() -> Result<Self, AuthError> {
        Self::with_roots(TrustRoots::default())
    }

    /// The same client, with the caller choosing what TLS trusts.
    ///
    /// See [`TrustRoots`] for why a caller would ever pass anything but the
    /// default.
    pub fn with_roots(roots: TrustRoots) -> Result<Self, AuthError> {
        let builder = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            // No endpoint this application calls legitimately redirects.
            // Following a 307/308 on an auth POST replays its body — an
            // authorization code, verifier or refresh token — to the target.
            // On a usage GET it can send the bearer to a different path or
            // origin depending on the redirect. Refuse at the one client all
            // provider requests share rather than asking every caller to
            // remember which status codes preserve a body.
            .redirect(reqwest::redirect::Policy::none());

        if let TrustRoots::Only(ders) = roots {
            // Refused, not honoured. `tls_certs_only(<empty>)` builds happily
            // and then fails every connection with a certificate error, which
            // reads as "the server is broken" — and the real cause, a host that
            // read its trust store and got nothing back, is invisible from
            // there. The failure belongs where the mistake is.
            if ders.is_empty() {
                return Err(AuthError::Transport(
                    "no trust roots were supplied, which would trust nothing at all".into(),
                ));
            }
            let supplied = ders.len();
            let mut certs = Vec::with_capacity(supplied);
            for (i, der) in ders.iter().enumerate() {
                certs.push(reqwest::Certificate::from_der(der).map_err(|e| {
                    AuthError::Transport(format!("trust root {i} is not a certificate: {e}"))
                })?);
            }
            // `tls_certs_only`, not `add_root_certificate`: the latter *extends*
            // the platform verifier, which would keep the revocation demand this
            // exists to escape.
            //
            // The build is where a bad root actually surfaces. `from_der` above
            // keeps the DER and defers parsing, so garbage bytes sail through it
            // and come back out of `build()` as the word "builder error" with no
            // index and no cause — measured, not assumed. The index is lost
            // either way; saying *what kind* of input was rejected is the part
            // still worth keeping, because otherwise a host that read its trust
            // store badly gets a message that could mean anything.
            return builder
                .tls_certs_only(certs)
                .build()
                .map(|client| Self { client })
                .map_err(|e| {
                    AuthError::Transport(format!(
                        "one of the {supplied} supplied trust roots was rejected: {e}"
                    ))
                });
        }

        let client = builder.build().map_err(|e| AuthError::Transport(e.to_string()))?;
        Ok(Self { client })
    }

    /// Exposes the underlying client for `usage::http`, which needs the
    /// `Retry-After` header on a 429 — `get_json` decodes straight to `T` and
    /// has nowhere to hand that header back.
    pub fn raw_client(&self) -> &reqwest::Client {
        &self.client
    }
}

/// On a non-2xx response, read the body so the RFC 6749 error code and
/// description survive. Calling `error_for_status()` instead would discard
/// the body along with that information, leaving failures undebuggable.
///
/// Returns the typed value alongside the raw `Value` it was derived from —
/// one parse of one response, not a second request. `exchange_code` needs
/// both, and `TokenFields` deliberately carries no `account` field, so
/// deriving `T` here can never fail because of an `account` shape it does not
/// even declare (see `TokenFields`'s doc comment).
async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<(T, serde_json::Value), AuthError> {
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
    // Do not fold `text` into either message below: on the 2xx branch it is
    // the raw token response body, and it can carry `access_token`/
    // `refresh_token` verbatim. `secrets` had exactly this defect once (a
    // parse error that embedded the value it failed to read) — the serde
    // error alone is enough to debug a schema mismatch without repeating it
    // here.
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| AuthError::Decode(e.to_string()))?;
    let typed: T =
        serde_json::from_value(value.clone()).map_err(|e| AuthError::Decode(e.to_string()))?;
    Ok((typed, value))
}

impl TokenHttp for ReqwestHttp {
    async fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<(T, serde_json::Value), AuthError> {
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

    async fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<(T, serde_json::Value), AuthError> {
        let resp = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(|e| AuthError::Transport(e.to_string()))?;
        decode(resp).await
    }

    async fn post_json_response(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<TokenHttpResponse, AuthError> {
        let resp = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| AuthError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|e| AuthError::Transport(e.to_string()))?
            .to_vec();
        Ok(TokenHttpResponse { status, body })
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
        // The raw body is discarded here: nothing that calls `get_json` today
        // needs it. Kept as `Result<T, AuthError>` so this method's contract
        // does not change for whatever future caller reaches for it.
        decode(resp).await.map(|(typed, _raw)| typed)
    }

    fn user_agent(&self) -> &str {
        USER_AGENT
    }
}

/// Anthropic's measured token fields. OpenAI's response is deliberately a
/// different type in `auth::openai`: it has an ID token, no `expires_in`, and
/// different refresh semantics.
#[derive(Deserialize)]
struct TokenFields {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    refresh_token_expires_in: Option<i64>,
    scope: Option<String>,
}

/// Anthropic's measured `account` shape (§10.3). Read directly from the raw
/// body by `identity_from`, never as a field on `TokenFields` — see that
/// struct's doc comment for why.
#[derive(Deserialize)]
struct AccountBlock {
    uuid: String,
    email_address: Option<String>,
}

async fn post_token_request<H: TokenHttp>(
    http: &H,
    cfg: &ProviderSpec,
    json_body: &serde_json::Value,
) -> Result<(TokenFields, serde_json::Value), AuthError> {
    http.post_json(&cfg.token_url, json_body).await
}

/// authorization_code → token exchange. docs/design.md §10.3.
///
/// Anthropic's body is JSON and carries `state`, which is non-standard for a
/// token request but is the measured shape that server expects. OpenAI's
/// device exchange is form encoded and lives in `auth::openai`.
pub async fn exchange_code<H: TokenHttp>(
    http: &H,
    cfg: &ProviderSpec,
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

    let json_body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": pending.redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": pending.verifier,
        "state": pending.state,
    });
    let (r, raw) = post_token_request(http, cfg, &json_body).await?;

    let scopes = r
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_else(|| cfg.scopes.iter().map(|s| s.to_string()).collect());

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

    let identity = raw
        .get("account")
        .and_then(|a| serde_json::from_value::<AccountBlock>(a.clone()).ok())
        .map(|a| AccountIdentity {
            uuid: a.uuid,
            email: a.email_address.unwrap_or_default(),
        });

    Ok((tokens, identity))
}

/// refresh_token -> a new TokenSet. docs/design.md §10.5.
pub async fn refresh<H: TokenHttp>(
    http: &H,
    cfg: &ProviderSpec,
    tokens: &TokenSet,
) -> Result<TokenSet, AuthError> {
    // Send the stored scopes back verbatim. Falling back to a hardcoded list
    // here would silently narrow the scopes on every refresh, and the
    // narrowing is cumulative and invisible until something that needed the
    // dropped scope stops working.
    let scope = tokens.scopes.join(" ");
    let json_body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": tokens.refresh_token,
        "client_id": cfg.client_id,
        "scope": scope,
    });
    // The raw body is discarded here: `refresh` never derives an identity,
    // only `exchange_code`'s initial login does.
    let (r, _raw) = match post_token_request(http, cfg, &json_body).await {
        Ok(pair) => pair,
        Err(e) if e.is_invalid_scope() => {
            // Retry exactly once with the identical body. This covers a
            // transient scope rejection from the server, not an attempt to
            // change the scopes — sending anything else here would defeat
            // the verbatim rule above.
            post_token_request(http, cfg, &json_body).await?
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
/// the result is discarded on purpose, and the whole call is bounded by
/// [`REVOKE_TIMEOUT`]. A user deleting an account from this app must not be
/// blocked by the revocation endpoint being unreachable or slow — the local
/// deletion proceeds either way. docs/design.md §10.6.
///
/// Anthropic's measured JSON revoke. OpenAI's JSON sibling endpoint is a
/// separate function in `auth::openai`; this function never dispatches by
/// provider.
pub async fn revoke<H: TokenHttp>(http: &H, cfg: &ProviderSpec, refresh_token: &str) {
    let json_body = serde_json::json!({
        "token": refresh_token,
        "token_type_hint": "refresh_token",
        "client_id": cfg.client_id,
    });
    let call = http.post_json::<serde_json::Value>(&cfg.revoke_url, &json_body);
    let _ = tokio::time::timeout(REVOKE_TIMEOUT, call).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::pkce::PendingAuth;
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

    async fn cfg_for(server: &MockServer) -> ProviderSpec {
        ProviderSpec {
            token_url: format!("{}/v1/oauth/token", server.uri()),
            // Also pointed at the mock: `revoke_url` is no longer derived from
            // `token_url` (it is now its own field, since OpenAI's revoke
            // endpoint is a sibling of its token endpoint rather than a suffix
            // of it), so the tests exercising `revoke` need this set too.
            revoke_url: format!("{}/v1/oauth/token/revoke", server.uri()),
            ..ProviderSpec::anthropic()
        }
    }

    #[tokio::test]
    async fn exchange_sends_a_json_body_not_a_form() {
        let server = MockServer::start().await;
        let expected = serde_json::json!({
            "grant_type": "authorization_code",
            "code": "the-code",
            "redirect_uri": "http://localhost:1234/callback",
            "client_id": ProviderSpec::anthropic().client_id,
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
        let (tokens, identity) = exchange_code(
            &http,
            &cfg_for(&server).await,
            &pending(),
            "the-code",
            "test-state",
        )
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
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "WRONG")
            .await
            .unwrap_err();
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
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state")
            .await
            .unwrap_err();
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
            exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state")
                .await
                .unwrap();
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

    /// The mobile app already has Anthropic blobs under `<uuid>:tokens`.
    /// Provider support may add a second stored type, but it must not add a tag,
    /// rename a field or turn one of these values optional in the existing
    /// blob. A structural round-trip alone would miss all three changes; this
    /// pins the exact JSON object shape an older build wrote.
    #[test]
    fn anthropic_tokens_keep_the_existing_serialized_shape() {
        let tokens = TokenSet {
            access_token: "access-secret".into(),
            refresh_token: "refresh-secret".into(),
            expires_at: "2026-09-04T08:00:00Z".parse().unwrap(),
            refresh_token_expires_at: "2026-10-04T00:00:00Z".parse().unwrap(),
            scopes: vec!["user:profile".into()],
            client_id: "client-one".into(),
        };
        assert_eq!(
            serde_json::to_value(&tokens).unwrap(),
            serde_json::json!({
                "access_token": "access-secret",
                "refresh_token": "refresh-secret",
                "expires_at": "2026-09-04T08:00:00Z",
                "refresh_token_expires_at": "2026-10-04T00:00:00Z",
                "scopes": ["user:profile"],
                "client_id": "client-one"
            })
        );
    }

    /// `secrets` once had a parse-failure path whose error message embedded
    /// the secret value it failed to read. Guard against the same shape here:
    /// a 2xx response that fails to deserialize must not echo the token it
    /// carries into the error.
    #[tokio::test]
    async fn decode_failure_on_a_2xx_body_does_not_leak_the_token_into_the_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            // "expires_in" is required by `TokenFields` and is missing here,
            // so decoding fails even though the status is 200.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "sk-ant-LEAKED-TOKEN", "refresh_token": "rt"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(&http, &cfg_for(&server).await, &pending(), "c", "test-state")
            .await
            .unwrap_err();
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
        assert!(http.user_agent().starts_with("quota-board/"));
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
            client_id: ProviderSpec::anthropic().client_id,
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
            "client_id": ProviderSpec::anthropic().client_id,
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
        assert!(err.is_dead_grant_for(Provider::Anthropic));
    }

    /// A bare 401 means different things at the two refresh endpoints. OpenAI
    /// uses it for a dead rotating grant; Anthropic's observed terminal
    /// contract is the explicit invalid-grant code. A provider-free helper
    /// would quarantine Claude accounts on a response that does not establish
    /// that their refresh chain is dead.
    #[test]
    fn a_bare_401_is_terminal_only_for_openai() {
        let err = AuthError::OAuth {
            status: 401,
            code: None,
            description: None,
        };
        assert!(!err.is_dead_grant_for(Provider::Anthropic));
        assert!(err.is_dead_grant_for(Provider::Openai));
    }

    #[test]
    fn needs_refresh_respects_the_five_minute_skew() {
        let mut t = tokens_with(&["user:profile"]);
        t.expires_at = Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS - 10);
        assert!(t.needs_refresh(), "inside the skew window still counts as needing a refresh");
        t.expires_at = Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS + 60);
        assert!(!t.needs_refresh());
    }

    /// docs/design.md §10.6: pins the URL suffix and all three body keys.
    /// `revoke` swallows every outcome by design, so a wrong path or a
    /// misspelled key would otherwise never surface — the mock only
    /// matches the exact shape below, and `.expect(1)` fails the test if
    /// that shape was never hit.
    #[tokio::test]
    async fn revoke_sends_the_expected_path_and_body() {
        let server = MockServer::start().await;
        let expected = serde_json::json!({
            "token": "the-refresh-token",
            "token_type_hint": "refresh_token",
            "client_id": ProviderSpec::anthropic().client_id,
        })
        .to_string();

        Mock::given(method("POST"))
            .and(path("/v1/oauth/token/revoke"))
            .and(body_json_string(expected))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        revoke(&http, &cfg_for(&server).await, "the-refresh-token").await;
    }

    /// docs/design.md §10.6: a failing revoke must not propagate or block
    /// the caller. If a future change let the error escape (e.g. swapping
    /// the discarded `Result` for a `.unwrap()`), this would panic on the
    /// 500 below instead of returning normally.
    #[tokio::test]
    async fn revoke_swallows_a_server_error_and_returns_normally() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        // No `unwrap()` here on purpose: `revoke` returns `()` regardless
        // of outcome, so simply reaching this line is the assertion.
        revoke(&http, &cfg_for(&server).await, "rt").await;
    }

    /// docs/design.md §10.6: revoke must give up after its own timeout
    /// rather than hang — Task 18's account deletion is waiting on this
    /// call. If the `tokio::time::timeout` wrapper were removed, this test
    /// would take as long as the mocked delay (10x the test's
    /// `REVOKE_TIMEOUT`) instead of returning promptly.
    #[tokio::test]
    async fn revoke_gives_up_on_its_own_timeout_rather_than_hanging() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(REVOKE_TIMEOUT * 10))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let start = std::time::Instant::now();
        revoke(&http, &cfg_for(&server).await, "rt").await;
        assert!(
            start.elapsed() < REVOKE_TIMEOUT * 5,
            "revoke did not respect its own timeout: took {:?}",
            start.elapsed()
        );
    }
}

#[cfg(test)]
mod trust_root_tests {
    use super::*;

    /// A real root, so the conversion from DER is exercised on something that
    /// actually parses. Self-signed and expiring in 2126 — it is a *shape*, not
    /// a trust decision, and nothing verifies against it.
    const ROOT_DER: &[u8] = include_bytes!("../../tests/fixtures/self_signed_root.der");

    #[test]
    fn a_supplied_root_replaces_the_platform_verifier() {
        assert!(ReqwestHttp::with_roots(TrustRoots::Only(vec![ROOT_DER.to_vec()])).is_ok());
    }

    /// **Trusting nothing is not a configuration, it is a bug that has not
    /// happened yet.** A host that reads its platform trust store and finds it
    /// empty — an unreadable keystore, a wrong API, a stripped image — would
    /// otherwise get a client whose every request fails with a certificate
    /// error, which reads as "the server is broken" and is undiagnosable from
    /// the outside. Refusing at construction puts the failure where the cause
    /// is.
    #[test]
    fn an_empty_root_list_is_refused_rather_than_trusting_nothing() {
        // `match`, not `unwrap_err()`: `ReqwestHttp` has no `Debug` and must not
        // grow one — it owns a client whose configuration is nobody's business
        // in a log.
        let Err(err) = ReqwestHttp::with_roots(TrustRoots::Only(vec![])) else {
            panic!("an empty trust list was accepted");
        };
        assert!(
            err.to_string().contains("no trust roots"),
            "the message must name the cause: {err}"
        );
    }

    /// The same reasoning one step later: a host that hands over something that
    /// is not a certificate must be told so, not left with a client that fails
    /// every connection.
    ///
    /// It cannot say *which* one. `reqwest::Certificate::from_der` keeps the
    /// bytes and defers parsing, so garbage passes it and reappears out of
    /// `build()` as the bare words "builder error" — measured while writing
    /// this test, which is why the assertion is on the wording this crate adds
    /// rather than on reqwest's.
    #[test]
    fn a_root_that_is_not_a_certificate_is_refused() {
        let Err(err) = ReqwestHttp::with_roots(TrustRoots::Only(vec![b"nope".to_vec()])) else {
            panic!("a non-certificate was accepted as a trust root");
        };
        assert!(
            err.to_string().contains("trust root"),
            "the message must say which input was rejected: {err}"
        );
    }

    /// `new()` must keep meaning what it meant before this existed. Every
    /// desktop caller goes through it and none of them passes roots.
    #[test]
    fn the_default_is_still_the_platform_verifier() {
        assert_eq!(TrustRoots::default(), TrustRoots::Platform);
        assert!(ReqwestHttp::new().is_ok());
    }

    /// Root certificates are public by definition, but a `Debug` that prints
    /// every byte of a whole platform trust store is a log nobody can read.
    #[test]
    fn debug_reports_how_many_roots_rather_than_all_of_them() {
        let printed = format!("{:?}", TrustRoots::Only(vec![ROOT_DER.to_vec(); 3]));
        assert!(printed.contains('3'), "the count should survive: {printed}");
        assert!(printed.len() < 100, "Debug printed the certificates: {} bytes", printed.len());
    }
}
