//! The OpenAI OAuth protocol used for Codex subscription accounts.
//!
//! This is deliberately separate from Anthropic's protocol in [`super::token`].
//! The two happen to use authorization-code PKCE, but the resemblance ends
//! there: OpenAI has fixed allow-listed callback ports, form-encoded code
//! exchange, JSON refresh and revocation, a device flow, and identity claims in
//! an ID token. Sharing the old provider/body-style switch made each of those
//! differences easy to erase accidentally.

use crate::auth::callback::Callback;
use crate::auth::pkce::{code_challenge_s256, random_urlsafe};
use crate::auth::token::{AuthError, TokenHttp, EXPIRY_SKEW_SECS};
use crate::provider::Provider;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;

pub const OPENAI_ISSUER: &str = "https://auth.openai.com";
pub const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const OPENAI_SCOPE: &str = "openid profile email offline_access";

const DEVICE_AUTH_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_DEVICE_INTERVAL_SECS: u64 = 5;
const MAX_DEVICE_INTERVAL_SECS: u64 = 15 * 60;

fn protocol_error(message: &'static str) -> AuthError {
    // Static reviewed text only. In particular, never attach a JWT or the raw
    // token response to a decode error.
    AuthError::Decode(message.into())
}

fn missing_token(field: &'static str) -> AuthError {
    AuthError::Decode(format!(
        "the OpenAI token response carried no nonempty {field}"
    ))
}

fn missing_claim(claim: &'static str) -> AuthError {
    AuthError::Decode(format!(
        "the OpenAI ID token carried no nonempty {claim} claim"
    ))
}

fn changed_identity() -> AuthError {
    // A retry can never repair a token that rotated onto a different identity.
    // A typed variant prevents an untrusted provider response from colliding
    // with an internal string marker and quarantining the wrong provider.
    AuthError::IdentityMismatch {
        provider: Provider::Openai,
    }
}

#[cfg(not(test))]
const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const REVOKE_TIMEOUT: Duration = Duration::from_millis(200);

/// The two values deployments may override without changing the protocol.
/// Endpoint paths and scopes are intentionally not configurable: they are the
/// contract observed in Codex 0.153.2, not provider metadata discovered at
/// runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiAuthConfig {
    pub issuer: String,
    pub client_id: String,
}

impl Default for OpenAiAuthConfig {
    fn default() -> Self {
        Self {
            issuer: OPENAI_ISSUER.into(),
            client_id: OPENAI_CLIENT_ID.into(),
        }
    }
}

impl OpenAiAuthConfig {
    fn endpoint(&self, path: &'static str) -> Result<String, AuthError> {
        let mut url = url::Url::parse(&self.issuer)
            .map_err(|_| protocol_error("the OpenAI issuer URL is invalid"))?;
        if url.host_str().is_none() || url.cannot_be_a_base() {
            return Err(protocol_error("the OpenAI issuer URL is invalid"));
        }
        // These are issuer-root endpoints. Retaining a path supplied on the
        // issuer would silently recreate the obsolete `/api/accounts/oauth/*`
        // endpoints this module replaced.
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url.to_string())
    }
}

/// Browser authorization state. The verifier is a live credential and is
/// therefore redacted from `Debug`, just like Anthropic's `PendingAuth`.
#[derive(Clone)]
pub struct OpenAiPendingAuth {
    verifier: String,
    state: String,
    redirect_uri: String,
}

impl std::fmt::Debug for OpenAiPendingAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiPendingAuth")
            .field("verifier", &"<redacted>")
            .field("state", &self.state)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl OpenAiPendingAuth {
    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

/// Identity asserted by the ID token returned over the TLS-protected token
/// exchange. `account_id` is the ChatGPT user id and remains the app's primary
/// account id; `workspace_id` is the selected ChatGPT workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiIdentity {
    pub account_id: String,
    /// `chatgpt_account_id`, when the issuer selected a workspace. Bearer-only
    /// usage requests are measured to work, so absence stays absent and is
    /// never replaced with the user id.
    pub workspace_id: Option<String>,
    pub email: String,
    pub plan_type: Option<String>,
    /// Present only when the claim was present. `Some(false)` and `None` are
    /// distinct evidence even though both omit the request header.
    pub is_fedramp: Option<bool>,
}

/// The persistable OpenAI token bundle.
///
/// There is deliberately no `id_token` field. It is used transiently to derive
/// and validate identity, then dropped before this value reaches `secrets`.
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenAiTokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub client_id: String,
    pub account_id: String,
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub is_fedramp: Option<bool>,
}

impl std::fmt::Debug for OpenAiTokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiTokenSet")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("client_id", &self.client_id)
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("is_fedramp", &self.is_fedramp)
            .finish()
    }
}

impl OpenAiTokenSet {
    pub fn needs_refresh(&self) -> bool {
        Utc::now() + TimeDelta::seconds(EXPIRY_SKEW_SECS) >= self.expires_at
    }
}

/// The user-facing half of device authorization. The two codes are credentials
/// for the in-flight login, so `Debug` redacts them even though the user code is
/// intentionally shown by the UI.
#[derive(Clone)]
pub struct DeviceCode {
    pub verification_url: String,
    pub user_code: String,
    pub expires_at: DateTime<Utc>,
    device_auth_id: String,
    interval: Duration,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("verification_url", &self.verification_url)
            .field("user_code", &"<redacted>")
            .field("device_auth_id", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("interval", &self.interval)
            .finish()
    }
}

impl DeviceCode {
    pub fn poll_interval(&self) -> Duration {
        self.interval
    }
}

fn bounded_device_interval(seconds: u64) -> Duration {
    Duration::from_secs(if seconds == 0 {
        DEFAULT_DEVICE_INTERVAL_SECS
    } else {
        seconds.min(MAX_DEVICE_INTERVAL_SECS)
    })
}

fn browser_authorize_url(
    cfg: &OpenAiAuthConfig,
    pending: &OpenAiPendingAuth,
) -> Result<String, AuthError> {
    let mut url = url::Url::parse(&cfg.endpoint("/oauth/authorize")?)
        .map_err(|_| protocol_error("the OpenAI authorize URL is invalid"))?;
    let challenge = code_challenge_s256(&pending.verifier);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &cfg.client_id);
        query.append_pair("redirect_uri", &pending.redirect_uri);
        query.append_pair("scope", OPENAI_SCOPE);
        query.append_pair("code_challenge", &challenge);
        query.append_pair("code_challenge_method", "S256");
        query.append_pair("id_token_add_organizations", "true");
        query.append_pair("state", &pending.state);
    }
    Ok(url.to_string())
}

/// Starts a browser PKCE flow against an OpenAI callback listener.
pub fn begin_browser(
    cfg: &OpenAiAuthConfig,
    callback: &Callback,
) -> Result<(OpenAiPendingAuth, String), AuthError> {
    if !callback.is_openai() {
        return Err(protocol_error(
            "OpenAI browser login requires the fixed OpenAI callback listener",
        ));
    }
    let pending = OpenAiPendingAuth {
        // Codex uses 64 random bytes for its verifier (86 base64url
        // characters), while state remains an independent 32-byte nonce.
        verifier: random_urlsafe(64),
        state: random_urlsafe(32),
        redirect_uri: callback.redirect_uri(),
    };
    let url = browser_authorize_url(cfg, &pending)?;
    Ok((pending, url))
}

#[derive(Deserialize)]
struct ProfileClaims {
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct AuthClaims {
    #[serde(default)]
    chatgpt_user_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    chatgpt_account_id: Option<String>,
    #[serde(default)]
    chatgpt_plan_type: Option<String>,
    #[serde(default)]
    chatgpt_account_is_fedramp: Option<bool>,
}

#[derive(Deserialize)]
struct IdClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(rename = "https://api.openai.com/profile", default)]
    profile: Option<ProfileClaims>,
    #[serde(rename = "https://api.openai.com/auth", default)]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
struct ExpiryClaims {
    #[serde(default)]
    exp: Option<i64>,
}

fn decode_jwt_payload<T: serde::de::DeserializeOwned>(jwt: &str) -> Result<T, AuthError> {
    let mut parts = jwt.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(protocol_error("an OpenAI JWT has an invalid format"));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(protocol_error("an OpenAI JWT has an invalid format"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| protocol_error("an OpenAI JWT payload is not valid base64url"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| protocol_error("an OpenAI JWT payload is not valid JSON"))
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

/// Reads the identity fields Codex 0.153.2 reads from the namespaced ID-token
/// claims. No signature verification is attempted here; the token arrives
/// directly from the configured HTTPS issuer and is not accepted from a user
/// or another process.
pub fn identity_from_id_token(id_token: &str) -> Result<OpenAiIdentity, AuthError> {
    let claims: IdClaims = decode_jwt_payload(id_token)?;
    let auth = claims
        .auth
        .ok_or_else(|| missing_claim("https://api.openai.com/auth"))?;
    let account_id = nonempty(auth.chatgpt_user_id)
        .or_else(|| nonempty(auth.user_id))
        .ok_or_else(|| missing_claim("chatgpt_user_id"))?;
    let workspace_id = nonempty(auth.chatgpt_account_id);
    let email = nonempty(claims.email)
        .or_else(|| claims.profile.and_then(|profile| nonempty(profile.email)))
        .unwrap_or_default();

    Ok(OpenAiIdentity {
        account_id,
        workspace_id,
        email,
        plan_type: nonempty(auth.chatgpt_plan_type),
        is_fedramp: auth.chatgpt_account_is_fedramp,
    })
}

fn access_token_expiry(access_token: &str) -> Result<DateTime<Utc>, AuthError> {
    let claims: ExpiryClaims = decode_jwt_payload(access_token)?;
    let expiry = claims
        .exp
        .ok_or_else(|| missing_claim("access token exp"))?;
    DateTime::from_timestamp(expiry, 0)
        .ok_or_else(|| protocol_error("the OpenAI access token expiration is invalid"))
}

#[derive(Deserialize)]
struct ExchangedTokens {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

fn require_token(value: &str, field: &'static str) -> Result<(), AuthError> {
    if value.trim().is_empty() {
        Err(missing_token(field))
    } else {
        Ok(())
    }
}

fn finish_exchange(
    cfg: &OpenAiAuthConfig,
    response: ExchangedTokens,
) -> Result<(OpenAiTokenSet, OpenAiIdentity), AuthError> {
    require_token(&response.id_token, "id_token")?;
    require_token(&response.access_token, "access_token")?;
    require_token(&response.refresh_token, "refresh_token")?;

    let identity = identity_from_id_token(&response.id_token)?;
    let expires_at = access_token_expiry(&response.access_token)?;
    let tokens = OpenAiTokenSet {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_at,
        client_id: cfg.client_id.clone(),
        account_id: identity.account_id.clone(),
        workspace_id: identity.workspace_id.clone(),
        is_fedramp: identity.is_fedramp,
    };
    Ok((tokens, identity))
}

async fn exchange_grant<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    redirect_uri: &str,
    verifier: &str,
    code: &str,
) -> Result<(OpenAiTokenSet, OpenAiIdentity), AuthError> {
    let endpoint = cfg.endpoint("/oauth/token")?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", verifier),
    ];
    let (response, _raw): (ExchangedTokens, _) = http.post_form(&endpoint, &form).await?;
    finish_exchange(cfg, response)
}

/// Exchanges a browser authorization code after validating the returned state.
pub async fn exchange_code<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    pending: &OpenAiPendingAuth,
    code: &str,
    returned_state: &str,
) -> Result<(OpenAiTokenSet, OpenAiIdentity), AuthError> {
    if returned_state != pending.state {
        return Err(AuthError::StateMismatch);
    }
    exchange_grant(http, cfg, &pending.redirect_uri, &pending.verifier, code).await
}

#[derive(Serialize)]
struct UserCodeRequest<'a> {
    client_id: &'a str,
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(default = "default_device_interval", deserialize_with = "deserialize_interval")]
    interval: u64,
}

fn default_device_interval() -> u64 {
    DEFAULT_DEVICE_INTERVAL_SECS
}

fn deserialize_interval<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(value) => value.trim().parse::<u64>().ok(),
        serde_json::Value::Number(value) => value.as_u64(),
        _ => None,
    }
    .filter(|seconds| *seconds > 0)
    .unwrap_or(DEFAULT_DEVICE_INTERVAL_SECS))
}

/// Requests a device code from OpenAI's JSON device-auth endpoint.
pub async fn request_device_code<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
) -> Result<DeviceCode, AuthError> {
    let endpoint = cfg.endpoint("/api/accounts/deviceauth/usercode")?;
    let body = serde_json::to_value(UserCodeRequest {
        client_id: &cfg.client_id,
    })
    .map_err(|_| protocol_error("the device-code request could not be encoded"))?;
    let (response, _raw): (UserCodeResponse, _) = http.post_json(&endpoint, &body).await?;
    require_token(&response.device_auth_id, "device_auth_id")?;
    require_token(&response.user_code, "user_code")?;
    Ok(DeviceCode {
        verification_url: cfg.endpoint("/codex/device")?,
        user_code: response.user_code,
        expires_at: Utc::now() + TimeDelta::seconds(DEVICE_AUTH_TIMEOUT.as_secs() as i64),
        device_auth_id: response.device_auth_id,
        interval: bounded_device_interval(response.interval),
    })
}

#[derive(Serialize)]
struct DevicePollRequest<'a> {
    device_auth_id: &'a str,
    user_code: &'a str,
}

#[derive(Deserialize)]
struct DevicePollResponse {
    authorization_code: String,
    code_challenge: String,
    code_verifier: String,
}

async fn poll_for_device_grant<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    device: &DeviceCode,
) -> Result<DevicePollResponse, AuthError> {
    let endpoint = cfg.endpoint("/api/accounts/deviceauth/token")?;
    loop {
        let body = serde_json::to_value(DevicePollRequest {
            device_auth_id: &device.device_auth_id,
            user_code: &device.user_code,
        })
        .map_err(|_| protocol_error("the device-code poll could not be encoded"))?;
        match http.post_json(&endpoint, &body).await {
            Ok((response, _raw)) => return Ok(response),
            Err(AuthError::OAuth {
                status: 403 | 404, ..
            }) => {
                tokio::time::sleep(device.interval).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn complete_device_code_with_timeout<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    device: &DeviceCode,
    timeout: Duration,
) -> Result<(OpenAiTokenSet, OpenAiIdentity), AuthError> {
    let grant = tokio::time::timeout(timeout, poll_for_device_grant(http, cfg, device))
        .await
        .map_err(|_| {
            AuthError::Transport("OpenAI device authorization timed out after 15 minutes".into())
        })??;
    require_token(&grant.authorization_code, "authorization_code")?;
    require_token(&grant.code_challenge, "code_challenge")?;
    require_token(&grant.code_verifier, "code_verifier")?;
    if code_challenge_s256(&grant.code_verifier) != grant.code_challenge {
        return Err(protocol_error(
            "the OpenAI device authorization PKCE values did not match",
        ));
    }
    let redirect_uri = cfg.endpoint("/deviceauth/callback")?;
    exchange_grant(
        http,
        cfg,
        &redirect_uri,
        &grant.code_verifier,
        &grant.authorization_code,
    )
    .await
}

/// Polls for at most fifteen minutes, then exchanges the issued device grant.
pub async fn complete_device_code<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    device: &DeviceCode,
) -> Result<(OpenAiTokenSet, OpenAiIdentity), AuthError> {
    let timeout = (device.expires_at - Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO);
    complete_device_code_with_timeout(http, cfg, device, timeout.min(DEVICE_AUTH_TIMEOUT)).await
}

#[derive(Serialize)]
struct RefreshRequest<'a> {
    client_id: &'a str,
    grant_type: &'static str,
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct RefreshResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

fn merge_refreshed_identity(
    next: &mut OpenAiTokenSet,
    new: OpenAiIdentity,
) -> Result<(), AuthError> {
    if new.account_id != next.account_id {
        return Err(changed_identity());
    }
    if matches!(
        (&next.workspace_id, &new.workspace_id),
        (Some(old), Some(new)) if old != new
    ) {
        return Err(changed_identity());
    }
    // Login owns workspace discovery because it updates both credentials and
    // Account metadata under one commit. Refresh can validate a known value,
    // but must not enrich None -> Some in the token alone: a later login would
    // still see legacy metadata and could replace that grant from a different
    // workspace. Cloning `next` from the stored set also preserves a known
    // workspace when the refreshed ID token omits the claim.
    if new.is_fedramp.is_some() {
        next.is_fedramp = new.is_fedramp;
    }
    Ok(())
}

/// Refreshes OpenAI tokens with the JSON shape used by Codex 0.153.2.
/// OpenAI does not accept the stored scope replay required by Anthropic.
pub async fn refresh<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    tokens: &OpenAiTokenSet,
) -> Result<OpenAiTokenSet, AuthError> {
    let endpoint = cfg.endpoint("/oauth/token")?;
    let body = serde_json::to_value(RefreshRequest {
        client_id: &tokens.client_id,
        grant_type: "refresh_token",
        refresh_token: &tokens.refresh_token,
    })
    .map_err(|_| protocol_error("the refresh request could not be encoded"))?;
    let (response, _raw): (RefreshResponse, _) = http.post_json(&endpoint, &body).await?;

    let access_token = response
        .access_token
        .ok_or_else(|| missing_token("access_token"))?;
    require_token(&access_token, "access_token")?;
    let expires_at = access_token_expiry(&access_token)?;

    let mut next = OpenAiTokenSet {
        access_token,
        refresh_token: tokens.refresh_token.clone(),
        expires_at,
        client_id: tokens.client_id.clone(),
        account_id: tokens.account_id.clone(),
        workspace_id: tokens.workspace_id.clone(),
        is_fedramp: tokens.is_fedramp,
    };

    if let Some(id_token) = response.id_token.as_deref() {
        require_token(id_token, "id_token")?;
        let identity = identity_from_id_token(id_token)?;
        merge_refreshed_identity(&mut next, identity)?;
    }

    next.refresh_token = match response.refresh_token {
        Some(value) => {
            require_token(&value, "refresh_token")?;
            value
        }
        None => tokens.refresh_token.clone(),
    };
    Ok(next)
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    token: &'a str,
    token_type_hint: &'static str,
    client_id: &'a str,
}

/// Best-effort refresh-token revocation. Local deletion must continue if the
/// issuer is unreachable, so both errors and the short timeout are swallowed.
pub async fn revoke<H: TokenHttp>(http: &H, cfg: &OpenAiAuthConfig, tokens: &OpenAiTokenSet) {
    let Ok(endpoint) = cfg.endpoint("/oauth/revoke") else {
        return;
    };
    let Ok(body) = serde_json::to_value(RevokeRequest {
        token: &tokens.refresh_token,
        token_type_hint: "refresh_token",
        client_id: &tokens.client_id,
    }) else {
        return;
    };
    let call = http.post_json::<serde_json::Value>(&endpoint, &body);
    let _ = tokio::time::timeout(REVOKE_TIMEOUT, call).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::{ReqwestHttp, USER_AGENT};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_json, body_string, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn cfg(server: &MockServer) -> OpenAiAuthConfig {
        OpenAiAuthConfig {
            issuer: server.uri(),
            ..OpenAiAuthConfig::default()
        }
    }

    fn jwt(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{payload}.test-signature")
    }

    fn identity_payload(account: &str, workspace: &str, fedramp: bool) -> serde_json::Value {
        json!({
            "email": "top@example.invalid",
            "https://api.openai.com/profile": { "email": "profile@example.invalid" },
            "https://api.openai.com/auth": {
                "chatgpt_user_id": account,
                "user_id": "fallback-user",
                "chatgpt_account_id": workspace,
                "chatgpt_plan_type": "plus",
                "chatgpt_account_is_fedramp": fedramp
            }
        })
    }

    fn access_token(exp: i64) -> String {
        jwt(json!({ "exp": exp }))
    }

    fn pending() -> OpenAiPendingAuth {
        OpenAiPendingAuth {
            verifier: "test-verifier".into(),
            state: "test-state".into(),
            redirect_uri: "http://localhost:1455/auth/callback".into(),
        }
    }

    fn token_set() -> OpenAiTokenSet {
        OpenAiTokenSet {
            access_token: access_token(Utc::now().timestamp() + 3600),
            refresh_token: "old-refresh".into(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            client_id: OPENAI_CLIENT_ID.into(),
            account_id: "user-1".into(),
            workspace_id: Some("workspace-1".into()),
            is_fedramp: Some(false),
        }
    }

    #[test]
    fn browser_authorization_uses_the_issuer_root_endpoint_and_exact_parameters() {
        let cfg = OpenAiAuthConfig::default();
        let url = browser_authorize_url(&cfg, &pending()).unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/oauth/authorize");
        let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query.len(), 8, "unexpected identifier was added: {query:?}");
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some(OPENAI_CLIENT_ID)
        );
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("http://localhost:1455/auth/callback")
        );
        assert_eq!(query.get("scope").map(String::as_str), Some(OPENAI_SCOPE));
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(
            query.get("id_token_add_organizations").map(String::as_str),
            Some("true")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("test-state"));
        let expected_challenge = code_challenge_s256("test-verifier");
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some(expected_challenge.as_str())
        );
        for forbidden in ["originator", "codex_cli_simplified_flow"] {
            assert!(
                !query.contains_key(forbidden),
                "impersonating query parameter {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn browser_flow_uses_a_64_byte_verifier_and_independent_32_byte_state() {
        let callback = Callback::bind_openai_ports(&[0]).await.unwrap();
        let (pending, url) = begin_browser(&OpenAiAuthConfig::default(), &callback).unwrap();
        assert_eq!(
            pending.verifier.len(),
            86,
            "64 base64url bytes have no padding"
        );
        assert_eq!(
            pending.state.len(),
            43,
            "32 base64url bytes have no padding"
        );
        assert_ne!(pending.verifier, pending.state);
        let parsed = url::Url::parse(&url).unwrap();
        let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let expected_challenge = code_challenge_s256(&pending.verifier);
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some(expected_challenge.as_str())
        );
    }

    #[test]
    fn id_claims_follow_codex_precedence_and_require_the_user_identifier() {
        let identity =
            identity_from_id_token(&jwt(identity_payload("user-1", "ws-1", true))).unwrap();
        assert_eq!(
            identity,
            OpenAiIdentity {
                account_id: "user-1".into(),
                workspace_id: Some("ws-1".into()),
                email: "top@example.invalid".into(),
                plan_type: Some("plus".into()),
                is_fedramp: Some(true),
            }
        );

        let fallback = jwt(json!({
            "email": "",
            "https://api.openai.com/profile": { "email": "profile@example.invalid" },
            "https://api.openai.com/auth": {
                "chatgpt_user_id": "",
                "user_id": "legacy-user",
                "chatgpt_account_id": "workspace"
            }
        }));
        let identity = identity_from_id_token(&fallback).unwrap();
        assert_eq!(identity.account_id, "legacy-user");
        assert_eq!(identity.email, "profile@example.invalid");
        assert_eq!(identity.workspace_id.as_deref(), Some("workspace"));
        assert_eq!(identity.is_fedramp, None);

        let without_workspace = identity_from_id_token(&jwt(json!({
            "https://api.openai.com/auth": { "chatgpt_user_id": "user" }
        })))
        .unwrap();
        assert_eq!(without_workspace.workspace_id, None);

        let error = identity_from_id_token(&jwt(json!({
            "https://api.openai.com/auth": { "chatgpt_account_id": "ws" }
        })))
        .unwrap_err();
        assert!(matches!(error, AuthError::Decode(_)));
        assert!(error.to_string().contains("claim"));
    }

    #[tokio::test]
    async fn code_exchange_uses_exact_form_wire_and_drops_the_id_token() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        let id_token = jwt(identity_payload("user-1", "workspace-1", false));
        let access = access_token(Utc::now().timestamp() + 3600);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |request: &Request| {
                *capture.lock().unwrap() = Some(request.clone());
                ResponseTemplate::new(200).set_body_json(json!({
                    "id_token": id_token,
                    "access_token": access,
                    "refresh_token": "refresh-SENTINEL"
                }))
            })
            .mount(&server)
            .await;

        let (tokens, identity) = exchange_code(
            &ReqwestHttp::new().unwrap(),
            &cfg(&server),
            &pending(),
            "code with spaces",
            "test-state",
        )
        .await
        .unwrap();
        assert_eq!(identity.account_id, "user-1");
        assert_eq!(tokens.workspace_id.as_deref(), Some("workspace-1"));

        let request = captured.lock().unwrap().take().unwrap();
        assert_eq!(request.headers["user-agent"].to_str().unwrap(), USER_AGENT);
        assert_eq!(
            request.headers["content-type"].to_str().unwrap(),
            "application/x-www-form-urlencoded"
        );
        for forbidden in ["originator", "anthropic-beta"] {
            assert!(
                !request.headers.contains_key(forbidden),
                "sent forbidden header {forbidden}"
            );
        }
        let form: HashMap<_, _> = url::form_urlencoded::parse(&request.body)
            .into_owned()
            .collect();
        assert_eq!(form.len(), 5, "unexpected token field: {form:?}");
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(
            form.get("code").map(String::as_str),
            Some("code with spaces")
        );
        assert_eq!(
            form.get("redirect_uri").map(String::as_str),
            Some(pending().redirect_uri())
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some(OPENAI_CLIENT_ID)
        );
        assert_eq!(
            form.get("code_verifier").map(String::as_str),
            Some("test-verifier")
        );
        assert!(!form.contains_key("scope"));
        assert!(!form.contains_key("state"));

        let stored = serde_json::to_value(&tokens).unwrap();
        assert!(
            stored.get("id_token").is_none(),
            "ID token became persistable: {stored}"
        );
    }

    #[tokio::test]
    async fn a_state_mismatch_never_reaches_the_token_endpoint() {
        let server = MockServer::start().await;
        let result = exchange_code(
            &ReqwestHttp::new().unwrap(),
            &cfg(&server),
            &pending(),
            "code",
            "wrong-state",
        )
        .await;
        assert!(matches!(result, Err(AuthError::StateMismatch)));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn persisted_tokens_redact_credentials_and_have_no_id_token_field() {
        let mut tokens = token_set();
        tokens.access_token = "access-SENTINEL".into();
        tokens.refresh_token = "refresh-SENTINEL".into();
        let debug = format!("{tokens:?}");
        assert!(
            !debug.contains("SENTINEL"),
            "Debug leaked a credential: {debug}"
        );
        assert!(debug.contains("<redacted>"));
        let stored = serde_json::to_value(tokens).unwrap();
        assert!(stored.get("id_token").is_none());
        assert_eq!(stored.get("is_fedramp"), Some(&json!(false)));
    }

    #[tokio::test]
    async fn refresh_is_json_has_no_scope_and_keeps_omitted_optional_tokens() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        let access = access_token(Utc::now().timestamp() + 7200);
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(move |request: &Request| {
                *capture.lock().unwrap() = Some(request.clone());
                ResponseTemplate::new(200).set_body_json(json!({ "access_token": access }))
            })
            .mount(&server)
            .await;

        let old = token_set();
        let refreshed = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &old)
            .await
            .unwrap();
        assert_eq!(refreshed.refresh_token, old.refresh_token);
        assert_eq!(refreshed.account_id, old.account_id);

        let request = captured.lock().unwrap().take().unwrap();
        assert_eq!(request.headers["user-agent"].to_str().unwrap(), USER_AGENT);
        assert_eq!(
            request.headers["content-type"].to_str().unwrap(),
            "application/json"
        );
        for forbidden in ["originator", "anthropic-beta"] {
            assert!(
                !request.headers.contains_key(forbidden),
                "sent forbidden header {forbidden}"
            );
        }
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body,
            json!({
                "client_id": OPENAI_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "old-refresh"
            })
        );
        assert!(body.get("scope").is_none());
    }

    #[tokio::test]
    async fn refresh_requires_a_new_nonempty_access_token_with_a_valid_expiry() {
        for response in [
            json!({}),
            json!({ "access_token": "" }),
            json!({
                "access_token": jwt(json!({ "sub": "no-exp" }))
            }),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&server)
                .await;
            assert!(
                refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &token_set())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn a_refreshed_id_token_must_keep_account_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token(Utc::now().timestamp() + 3600),
                "id_token": jwt(identity_payload("other-user", "workspace-1", false))
            })))
            .mount(&server)
            .await;
        let error = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &token_set())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::IdentityMismatch {
                provider: Provider::Openai
            }
        ));
    }

    #[tokio::test]
    async fn refresh_rejects_a_change_to_a_known_workspace() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token(Utc::now().timestamp() + 3600),
                "id_token": jwt(identity_payload("user-1", "other-workspace", false))
            })))
            .mount(&server)
            .await;
        let error = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &token_set())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::IdentityMismatch {
                provider: Provider::Openai
            }
        ));
    }

    #[tokio::test]
    async fn refresh_does_not_enrich_an_unknown_workspace() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token(Utc::now().timestamp() + 3600),
                "id_token": jwt(json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_user_id": "user-1",
                        "chatgpt_account_id": "workspace-1",
                        "chatgpt_account_is_fedramp": true
                    }
                }))
            })))
            .mount(&server)
            .await;

        let mut old = token_set();
        old.workspace_id = None;
        old.is_fedramp = None;
        let refreshed = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &old)
            .await
            .unwrap();
        assert_eq!(refreshed.workspace_id, None);
        assert_eq!(refreshed.is_fedramp, Some(true));
    }

    #[tokio::test]
    async fn refresh_preserves_a_known_workspace_when_the_new_claim_is_missing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": access_token(Utc::now().timestamp() + 3600),
                "id_token": jwt(json!({
                    "https://api.openai.com/auth": {
                        "chatgpt_user_id": "user-1"
                    }
                }))
            })))
            .mount(&server)
            .await;

        let old = token_set();
        let refreshed = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &old)
            .await
            .unwrap();
        assert_eq!(refreshed.workspace_id, old.workspace_id);
    }

    #[tokio::test]
    async fn refresh_preserves_missing_routing_claims_and_honors_explicit_false() {
        for (fedramp_claim, expected_fedramp) in
            [(None, Some(true)), (Some(false), Some(false))]
        {
            let server = MockServer::start().await;
            let mut auth = json!({ "chatgpt_user_id": "user-1" });
            if let Some(value) = fedramp_claim {
                auth.as_object_mut()
                    .unwrap()
                    .insert("chatgpt_account_is_fedramp".into(), json!(value));
            }
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": access_token(Utc::now().timestamp() + 3600),
                    "id_token": jwt(json!({ "https://api.openai.com/auth": auth }))
                })))
                .mount(&server)
                .await;

            let mut old = token_set();
            old.is_fedramp = Some(true);
            let refreshed = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &old)
                .await
                .unwrap();
            assert_eq!(
                refreshed.workspace_id, old.workspace_id,
                "an omitted workspace erased known routing context"
            );
            assert_eq!(
                refreshed.is_fedramp, expected_fedramp,
                "missing and explicit false FedRAMP claims were collapsed"
            );
        }
    }

    #[tokio::test]
    async fn openai_refresh_classifies_only_its_terminal_responses_as_dead() {
        for (status, body, dead) in [
            (
                401,
                json!({ "error": { "code": "anything", "message": "denied" } }),
                true,
            ),
            (400, json!({ "error": "invalid_grant" }), true),
            (
                400,
                json!({ "error": { "code": "refresh_token_reused" } }),
                true,
            ),
            (500, json!({ "error": "server_error" }), false),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let error = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &token_set())
                .await
                .unwrap_err();
            assert_eq!(
                error.is_dead_grant_for(Provider::Openai),
                dead,
                "wrong classification for HTTP {status}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn revoke_uses_the_root_json_endpoint_and_our_identity_only() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        Mock::given(method("POST"))
            .and(path("/oauth/revoke"))
            .and(body_json(json!({
                "token": "old-refresh",
                "token_type_hint": "refresh_token",
                "client_id": OPENAI_CLIENT_ID
            })))
            .respond_with(move |request: &Request| {
                *capture.lock().unwrap() = Some(request.clone());
                ResponseTemplate::new(200).set_body_json(json!({}))
            })
            .expect(1)
            .mount(&server)
            .await;

        revoke(&ReqwestHttp::new().unwrap(), &cfg(&server), &token_set()).await;
        let request = captured.lock().unwrap().take().unwrap();
        assert_eq!(request.headers["user-agent"].to_str().unwrap(), USER_AGENT);
        for forbidden in ["originator", "anthropic-beta"] {
            assert!(
                !request.headers.contains_key(forbidden),
                "sent forbidden header {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn device_request_uses_json_and_bounds_the_server_interval() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let capture = captured.clone();
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .and(header("content-type", "application/json"))
            .and(body_json(json!({ "client_id": OPENAI_CLIENT_ID })))
            .respond_with(move |request: &Request| {
                *capture.lock().unwrap() = Some(request.clone());
                ResponseTemplate::new(200).set_body_json(json!({
                    "device_auth_id": "device-secret",
                    "user_code": "ABCD-EFGH",
                    "interval": "0"
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let device = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&server))
            .await
            .unwrap();
        assert_eq!(
            device.verification_url,
            format!("{}/codex/device", server.uri())
        );
        assert_eq!(device.user_code, "ABCD-EFGH");
        assert_eq!(device.poll_interval(), Duration::from_secs(5));
        assert!(device.expires_at > Utc::now() + TimeDelta::minutes(14));
        let debug = format!("{device:?}");
        assert!(!debug.contains("ABCD-EFGH"));
        assert!(!debug.contains("device-secret"));
        let request = captured.lock().unwrap().take().unwrap();
        assert_eq!(request.headers["user-agent"].to_str().unwrap(), USER_AGENT);
        for forbidden in ["originator", "anthropic-beta"] {
            assert!(
                !request.headers.contains_key(forbidden),
                "sent forbidden header {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn a_missing_device_poll_interval_uses_the_safe_default() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_auth_id": "device-secret",
                "user_code": "ABCD-EFGH"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let device = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&server))
            .await
            .unwrap();
        assert_eq!(device.poll_interval(), Duration::from_secs(5));
    }

    #[test]
    fn device_poll_interval_is_bounded_at_both_ends() {
        assert_eq!(bounded_device_interval(0), Duration::from_secs(5));
        assert_eq!(
            bounded_device_interval(u64::MAX),
            Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn missing_zero_and_malformed_device_intervals_use_the_default() {
        for body in [
            json!({ "device_auth_id": "id", "user_code": "code" }),
            json!({ "device_auth_id": "id", "user_code": "code", "interval": 0 }),
            json!({ "device_auth_id": "id", "user_code": "code", "interval": "nope" }),
        ] {
            let parsed: UserCodeResponse = serde_json::from_value(body).unwrap();
            assert_eq!(parsed.interval, DEFAULT_DEVICE_INTERVAL_SECS);
        }
    }

    #[tokio::test]
    async fn device_flow_polls_pending_then_uses_the_device_redirect_for_exchange() {
        let server = MockServer::start().await;
        let verifier = "device-verifier";
        let challenge = code_challenge_s256(verifier);
        let poll_body = json!({ "device_auth_id": "device-id", "user_code": "USER-CODE" });
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .and(body_json(poll_body.clone()))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({ "error": "pending" })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .and(body_json(poll_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "authorization_code": "device-code",
                "code_challenge": challenge,
                "code_verifier": verifier
            })))
            .expect(1)
            .with_priority(2)
            .mount(&server)
            .await;
        let expected_form = format!(
            "grant_type=authorization_code&code=device-code&redirect_uri={}&client_id={OPENAI_CLIENT_ID}&code_verifier=device-verifier",
            url::form_urlencoded::byte_serialize(
                format!("{}/deviceauth/callback", server.uri()).as_bytes()
            )
            .collect::<String>()
        );
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string(expected_form))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id_token": jwt(identity_payload("user-1", "workspace-1", false)),
                "access_token": access_token(Utc::now().timestamp() + 3600),
                "refresh_token": "new-refresh"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let device = DeviceCode {
            verification_url: format!("{}/codex/device", server.uri()),
            user_code: "USER-CODE".into(),
            expires_at: Utc::now() + TimeDelta::minutes(15),
            device_auth_id: "device-id".into(),
            interval: Duration::from_millis(1),
        };
        let (tokens, _) = complete_device_code_with_timeout(
            &ReqwestHttp::new().unwrap(),
            &cfg(&server),
            &device,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(tokens.refresh_token, "new-refresh");
    }

    #[tokio::test]
    async fn device_polling_has_a_hard_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "error": "pending" })))
            .mount(&server)
            .await;
        let device = DeviceCode {
            verification_url: String::new(),
            user_code: "USER-CODE".into(),
            expires_at: Utc::now() + TimeDelta::minutes(15),
            device_auth_id: "device-id".into(),
            interval: Duration::from_millis(1),
        };
        let error = complete_device_code_with_timeout(
            &ReqwestHttp::new().unwrap(),
            &cfg(&server),
            &device,
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AuthError::Transport(_)));
        assert!(error.to_string().contains("timed out after 15 minutes"));
    }
}
