use crate::auth::pkce::PendingAuth;
use crate::provider::{BodyStyle, Provider, ProviderSpec};
use chrono::{DateTime, TimeDelta, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const USER_AGENT: &str = concat!("quota-board/", env!("CARGO_PKG_VERSION"));
/// docs/design.md §5.2: this is the only `anthropic-beta` value we ever send.
pub const ANTHROPIC_BETA: &str = "oauth-2025-04-20";
/// docs/design.md §10.5: treat a token as expired 5 minutes ahead of its
/// reported expiry, so a request in flight never straddles the boundary.
pub const EXPIRY_SKEW_SECS: i64 = 300;
/// Provider-only marker produced by OpenAI's refresh adapter. OpenAI treats a
/// bare 401 and a changed refreshed identity as terminal; Anthropic does not,
/// so status alone cannot drive the shared predicate.
pub(crate) const OPENAI_DEAD_GRANT_CODE: &str = "openai_refresh_dead";

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
    OAuth {
        status: u16,
        code: Option<String>,
        description: Option<String>,
    },
    #[error("failed to parse the response: {0}")]
    Decode(String),
}

impl AuthError {
    /// Whether the refresh chain is permanently dead. docs/design.md §10.5 —
    /// the account is quarantined on the first strike, not retried.
    pub fn is_dead_grant(&self) -> bool {
        matches!(self, AuthError::OAuth { code, .. }
            if matches!(code.as_deref(), Some("invalid_grant") | Some(OPENAI_DEAD_GRANT_CODE)))
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
    /// one parse of one response — not a second request. Anthropic's
    /// `exchange_code` needs both the ordinary token fields and the measured
    /// `account` block kept outside `TokenFields`.
    fn post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<(T, serde_json::Value), AuthError>> + Send;

    /// OpenAI's authorization-code transport:
    /// `application/x-www-form-urlencoded`, as opposed to Anthropic's measured
    /// JSON shape.
    fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<(T, serde_json::Value), AuthError>> + Send;

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
            // OAuth POSTs must never be replayed automatically to a Location
            // chosen by a response. Besides hiding an obsolete endpoint, a
            // 307/308 could forward a refresh token to a different origin.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30));

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

        let client = builder
            .build()
            .map_err(|e| AuthError::Transport(e.to_string()))?;
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
const SENSITIVE_REQUEST_FIELDS: &[&str] = &[
    "access_token",
    "authorization_code",
    "code",
    "code_verifier",
    "device_auth_id",
    "id_token",
    "refresh_token",
    "requested_token",
    "subject_token",
    "token",
    "user_code",
];

fn redact_remote_echo(mut value: String, request_secrets: &[&str]) -> String {
    for secret in request_secrets.iter().filter(|value| !value.is_empty()) {
        value = value.replace(secret, "<redacted>");
    }
    value
}

fn json_request_secrets(body: &serde_json::Value) -> Vec<&str> {
    SENSITIVE_REQUEST_FIELDS
        .iter()
        .filter_map(|field| body.get(field).and_then(serde_json::Value::as_str))
        .collect()
}

fn form_request_secrets<'a>(form: &'a [(&str, &str)]) -> Vec<&'a str> {
    form.iter()
        .filter(|(field, _)| SENSITIVE_REQUEST_FIELDS.contains(field))
        .map(|(_, value)| *value)
        .collect()
}

async fn decode<T: DeserializeOwned>(
    resp: reqwest::Response,
    request_secrets: &[&str],
) -> Result<(T, serde_json::Value), AuthError> {
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| AuthError::Transport(e.to_string()))?;
    if !(200..300).contains(&status) {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
        let error = v.get("error");
        let code = error
            .and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("code").and_then(|v| v.as_str()))
            })
            .or_else(|| v.get("code").and_then(|value| value.as_str()))
            .map(str::to_string)
            .map(|value| redact_remote_echo(value, request_secrets));
        let description = v
            .get("error_description")
            .and_then(|value| value.as_str())
            .or_else(|| {
                error
                    .and_then(|value| value.get("message"))
                    .and_then(|value| value.as_str())
            })
            .map(str::to_string)
            .map(|value| redact_remote_echo(value, request_secrets));
        return Err(AuthError::OAuth {
            status,
            code,
            description,
        });
    }
    // Do not fold `text` into either message below: on the 2xx branch it is
    // the raw token response body, and it can carry `access_token`/
    // `refresh_token` verbatim. `secrets` had exactly this defect once (a
    // parse error that embedded the value it failed to read) — the serde
    // error alone is enough to debug a schema mismatch without repeating it
    // here.
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        AuthError::Decode(redact_remote_echo(e.to_string(), request_secrets))
    })?;
    let mut decode_secrets = request_secrets.to_vec();
    // A successful token response can carry credentials that did not exist in
    // the request. Serde may quote one in a later wrong-typed field's error, so
    // collect the reviewed top-level token fields before typed decoding.
    decode_secrets.extend(json_request_secrets(&value));
    let typed: T = serde_json::from_value(value.clone()).map_err(|e| {
        AuthError::Decode(redact_remote_echo(e.to_string(), &decode_secrets))
    })?;
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
        decode(resp, &json_request_secrets(body)).await
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
        decode(resp, &form_request_secrets(form)).await
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
        decode(resp, &[bearer]).await.map(|(typed, _raw)| typed)
    }

    fn user_agent(&self) -> &str {
        USER_AGENT
    }
}

/// Anthropic's token fields. `account` stays outside this struct so a malformed
/// identity block cannot hide otherwise valid token fields behind a generic
/// deserialization failure.
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

/// Anthropic's account identity, derived from its measured `account` block.
fn identity_from(
    provider: Provider,
    raw: &serde_json::Value,
) -> Result<Option<AccountIdentity>, AuthError> {
    match provider {
        Provider::Anthropic => Ok(raw
            .get("account")
            .and_then(|a| serde_json::from_value::<AccountBlock>(a.clone()).ok())
            .map(|a| AccountIdentity {
                uuid: a.uuid,
                email: a.email_address.unwrap_or_default(),
            })),
        Provider::Openai => Err(AuthError::Decode(
            "OpenAI authentication must use auth::openai".into(),
        )),
    }
}

/// authorization_code → token exchange. docs/design.md §10.3.
///
/// Anthropic's body is JSON and carries `state`, which is non-standard for a
/// token request but is the measured shape its server expects. Passing an
/// OpenAI provider/spec fails before the network; its protocol lives in
/// `auth::openai`.
pub async fn exchange_code<H: TokenHttp>(
    http: &H,
    cfg: &ProviderSpec,
    provider: Provider,
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
    if provider != Provider::Anthropic || cfg.body_style != BodyStyle::JsonWithState {
        return Err(AuthError::Decode(
            "OpenAI authentication must use auth::openai".into(),
        ));
    }

    let json_body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": pending.redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": pending.verifier,
        "state": pending.state,
    });
    let (r, raw): (TokenFields, _) = http.post_json(&cfg.token_url, &json_body).await?;

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

    let identity = identity_from(provider, &raw)?;

    Ok((tokens, identity))
}

/// refresh_token -> a new TokenSet. docs/design.md §10.5.
pub async fn refresh<H: TokenHttp>(
    http: &H,
    cfg: &ProviderSpec,
    tokens: &TokenSet,
) -> Result<TokenSet, AuthError> {
    if cfg.body_style != BodyStyle::JsonWithState {
        return Err(AuthError::Decode(
            "OpenAI authentication must use auth::openai".into(),
        ));
    }
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
    let request = || http.post_json::<TokenFields>(&cfg.token_url, &json_body);
    let (r, _raw) = match request().await {
        Ok(pair) => pair,
        Err(e) if e.is_invalid_scope() => {
            // Retry exactly once with the identical body. This covers a
            // transient scope rejection from the server, not an attempt to
            // change the scopes — sending anything else here would defeat
            // the verbatim rule above.
            request().await?
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
/// This is Anthropic-only and sends its measured JSON shape. An OpenAI spec
/// fails closed before the network; `auth::openai::revoke` owns OpenAI's
/// issuer-root JSON endpoint.
pub async fn revoke<H: TokenHttp>(http: &H, cfg: &ProviderSpec, refresh_token: &str) {
    if cfg.body_style != BodyStyle::JsonWithState {
        // Fail closed. OpenAI revocation is a separate JSON protocol at an
        // issuer-root endpoint and must go through `auth::openai::revoke`.
        return;
    }
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
    use crate::provider::Provider;
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
            ..Provider::Anthropic.spec()
        }
    }

    #[tokio::test]
    async fn exchange_sends_a_json_body_not_a_form() {
        let server = MockServer::start().await;
        let expected = serde_json::json!({
            "grant_type": "authorization_code",
            "code": "the-code",
            "redirect_uri": "http://localhost:1234/callback",
            "client_id": Provider::Anthropic.spec().client_id,
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
            Provider::Anthropic,
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

    /// The obsolete shared body-style branch sent plausible-looking requests
    /// to the wrong OpenAI endpoints. Keeping the old public Anthropic
    /// functions temporarily source-compatible is safe only if they refuse an
    /// OpenAI spec before touching the network.
    #[tokio::test]
    async fn legacy_anthropic_entry_points_fail_closed_for_openai() {
        let server = MockServer::start().await;
        let cfg = ProviderSpec {
            token_url: format!("{}/wrong-token", server.uri()),
            revoke_url: format!("{}/wrong-revoke", server.uri()),
            ..Provider::Openai.spec()
        };
        let http = ReqwestHttp::new().unwrap();

        assert!(exchange_code(
            &http,
            &cfg,
            Provider::Openai,
            &pending(),
            "code",
            "test-state"
        )
        .await
        .is_err());
        assert!(refresh(&http, &cfg, &tokens_with(&[])).await.is_err());
        revoke(&http, &cfg, "refresh-token").await;
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// docs/design.md §10.3: validate `state` before accepting the code.
    #[tokio::test]
    async fn mismatched_state_is_rejected_before_any_network_call() {
        let server = MockServer::start().await; // no mock mounted — a call reaching it fails the test
        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(
            &http,
            &cfg_for(&server).await,
            Provider::Anthropic,
            &pending(),
            "c",
            "WRONG",
        )
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
        let err = exchange_code(
            &http,
            &cfg_for(&server).await,
            Provider::Anthropic,
            &pending(),
            "c",
            "test-state",
        )
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

    /// OAuth servers are remote input and may echo a submitted credential in
    /// either error field. Both `Display` and derived `Debug` for `AuthError`
    /// are printable, so the transport must scrub request secrets before the
    /// error leaves it.
    #[tokio::test]
    async fn a_remote_error_cannot_echo_the_submitted_refresh_token() {
        const SECRET: &str = "refresh-SENTINEL-never-print";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": {
                    "code": format!("rejected-{SECRET}"),
                    "message": format!("could not rotate {SECRET}")
                }
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = http
            .post_json::<serde_json::Value>(
                &format!("{}/oauth/token", server.uri()),
                &serde_json::json!({ "grant_type": "refresh_token", "refresh_token": SECRET }),
            )
            .await
            .unwrap_err();
        for printed in [err.to_string(), format!("{err:?}")] {
            assert!(!printed.contains(SECRET), "remote echo leaked the token: {printed}");
            assert!(printed.contains("<redacted>"), "the sanitized error lost all context: {printed}");
        }
    }

    /// A 2xx body is still remote input. Serde includes a wrong-typed string in
    /// its error text, so an issuer that reflects the submitted token into such
    /// a field must be scrubbed just like a non-2xx OAuth error.
    #[tokio::test]
    async fn a_success_status_decode_error_cannot_echo_the_submitted_refresh_token() {
        const SECRET: &str = "refresh-SENTINEL-from-2xx";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-at",
                "refresh_token": "new-rt",
                "expires_in": SECRET
            })))
            .mount(&server)
            .await;

        let mut tokens = tokens_with(&["user:profile"]);
        tokens.refresh_token = SECRET.into();
        let err = refresh(&ReqwestHttp::new().unwrap(), &cfg_for(&server).await, &tokens)
            .await
            .unwrap_err();
        for printed in [err.to_string(), format!("{err:?}")] {
            assert!(!printed.contains(SECRET), "2xx decode error leaked the token: {printed}");
            assert!(printed.contains("<redacted>"), "the sanitized error lost all context: {printed}");
        }
    }

    /// The response can contain a newly issued credential that was not in the
    /// request. If another response field repeats it with the wrong type, serde
    /// includes that value in its error and request-only redaction cannot help.
    #[tokio::test]
    async fn a_success_status_decode_error_cannot_echo_a_new_response_token() {
        const NEW_SECRET: &str = "new-access-SENTINEL-from-2xx";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": NEW_SECRET,
                "refresh_token": "new-refresh",
                "expires_in": NEW_SECRET
            })))
            .mount(&server)
            .await;

        let err = refresh(
            &ReqwestHttp::new().unwrap(),
            &cfg_for(&server).await,
            &tokens_with(&["user:profile"]),
        )
        .await
        .unwrap_err();
        for printed in [err.to_string(), format!("{err:?}")] {
            assert!(
                !printed.contains(NEW_SECRET),
                "2xx decode error leaked the newly issued token: {printed}"
            );
            assert!(
                printed.contains("<redacted>"),
                "the sanitized error lost all context: {printed}"
            );
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
        let (tokens, _) = exchange_code(
            &http,
            &cfg_for(&server).await,
            Provider::Anthropic,
            &pending(),
            "c",
            "test-state",
        )
        .await
        .unwrap();
        let days = (tokens.refresh_token_expires_at - chrono::Utc::now()).num_days();
        assert!(
            (29..=30).contains(&days),
            "expected roughly 30 days, got {days}"
        );
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
        assert!(
            !debug.contains("SENTINEL"),
            "Debug output leaked a token: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "expected the redaction marker, got: {debug}"
        );
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
            // "expires_in" is required by `TokenFields` and is missing here,
            // so decoding fails even though the status is 200.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "sk-ant-LEAKED-TOKEN", "refresh_token": "rt"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = exchange_code(
            &http,
            &cfg_for(&server).await,
            Provider::Anthropic,
            &pending(),
            "c",
            "test-state",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AuthError::Decode(_)),
            "expected a Decode error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains("LEAKED-TOKEN"),
            "the decode error exposed the access token: {msg}"
        );
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

        let req = captured
            .lock()
            .unwrap()
            .take()
            .expect("get_json never reached the mock");

        let beta = req
            .headers
            .get("anthropic-beta")
            .expect("anthropic-beta header missing");
        assert_eq!(beta.to_str().unwrap(), ANTHROPIC_BETA);

        for (name, value) in req.headers.iter() {
            let v = value.to_str().unwrap_or_default().to_lowercase();
            assert!(
                !v.contains("claude"),
                "header `{name}` leaked a Claude-identifying value: {v}"
            );
        }
    }

    fn tokens_with(scopes: &[&str]) -> TokenSet {
        TokenSet {
            access_token: "old-at".into(),
            refresh_token: "old-rt".into(),
            expires_at: Utc::now() - TimeDelta::seconds(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            client_id: Provider::Anthropic.spec().client_id,
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
            "client_id": Provider::Anthropic.spec().client_id,
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
        let after = refresh(&http, &cfg_for(&server).await, &before)
            .await
            .unwrap();
        assert_eq!(
            after.refresh_token_expires_at,
            before.refresh_token_expires_at
        );
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
        let out = refresh(
            &http,
            &cfg_for(&server).await,
            &tokens_with(&["user:profile"]),
        )
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
        let err = refresh(
            &http,
            &cfg_for(&server).await,
            &tokens_with(&["user:profile"]),
        )
        .await
        .unwrap_err();
        assert!(err.is_dead_grant());
    }

    /// OpenAI's refresh protocol treats any 401 as terminal, but that rule is
    /// provider-specific. Applying it in `AuthError::is_dead_grant` to every
    /// OAuth response would quarantine an Anthropic account for a generic 401
    /// that carries no `invalid_grant` code.
    #[tokio::test]
    async fn an_arbitrary_anthropic_401_is_not_a_dead_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "unauthorized"
            })))
            .mount(&server)
            .await;

        let err = refresh(
            &ReqwestHttp::new().unwrap(),
            &cfg_for(&server).await,
            &tokens_with(&[]),
        )
        .await
        .unwrap_err();
        assert!(!err.is_dead_grant());
    }

    #[tokio::test]
    async fn the_auth_client_does_not_follow_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", format!("{}/target", server.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/target"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let result: Result<(serde_json::Value, serde_json::Value), AuthError> = http
            .post_json(
                &format!("{}/start", server.uri()),
                &serde_json::json!({ "token": "secret" }),
            )
            .await;
        assert!(matches!(result, Err(AuthError::OAuth { status: 307, .. })));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "the credential-bearing POST was replayed to Location"
        );
        assert_eq!(requests[0].url.path(), "/start");
    }

    #[test]
    fn needs_refresh_respects_the_five_minute_skew() {
        let mut t = tokens_with(&["user:profile"]);
        t.expires_at = Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS - 10);
        assert!(
            t.needs_refresh(),
            "inside the skew window still counts as needing a refresh"
        );
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
            "client_id": Provider::Anthropic.spec().client_id,
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
        assert!(
            printed.len() < 100,
            "Debug printed the certificates: {} bytes",
            printed.len()
        );
    }
}
