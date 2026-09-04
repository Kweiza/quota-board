//! OpenAI's device-code login and rotating token grant.
//!
//! This is deliberately separate from Anthropic's browser PKCE flow. The two
//! providers share OAuth vocabulary, but not a request protocol: OpenAI starts
//! with two JSON device endpoints, exchanges the resulting code as a form, and
//! refreshes and revokes with JSON. A single per-provider "body style" cannot
//! represent that sequence.

use crate::auth::token::{AuthError, TokenHttp, EXPIRY_SKEW_SECS};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const DEVICE_AUTH_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/usercode";
pub const DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
pub const DEVICE_VERIFY_URL: &str = "https://auth.openai.com/codex/device";
pub const DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const REVOKE_URL: &str = "https://auth.openai.com/oauth/revoke";

const DEVICE_LOGIN_SECS: i64 = 15 * 60;
const DEFAULT_DEVICE_INTERVAL_SECS: u64 = 5;
const MAX_DEVICE_INTERVAL_SECS: u64 = DEVICE_LOGIN_SECS as u64;

#[derive(Debug, Clone)]
pub struct OpenAiAuthConfig {
    pub client_id: String,
    pub device_auth_url: String,
    pub device_token_url: String,
    pub device_verify_url: String,
    pub device_redirect_uri: String,
    pub token_url: String,
    pub revoke_url: String,
}

impl Default for OpenAiAuthConfig {
    fn default() -> Self {
        Self {
            client_id: CLIENT_ID.into(),
            device_auth_url: DEVICE_AUTH_URL.into(),
            device_token_url: DEVICE_TOKEN_URL.into(),
            device_verify_url: DEVICE_VERIFY_URL.into(),
            device_redirect_uri: DEVICE_REDIRECT_URI.into(),
            token_url: TOKEN_URL.into(),
            revoke_url: REVOKE_URL.into(),
        }
    }
}

#[derive(Clone)]
pub struct DeviceLogin {
    pub verification_url: String,
    pub user_code: String,
    pub interval_secs: u64,
    pub expires_at: DateTime<Utc>,
    device_auth_id: String,
    next_poll_at: DateTime<Utc>,
}

impl std::fmt::Debug for DeviceLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceLogin")
            .field("verification_url", &self.verification_url)
            .field("user_code", &"<redacted>")
            .field("interval_secs", &self.interval_secs)
            .field("expires_at", &self.expires_at)
            .field("device_auth_id", &"<redacted>")
            .field("next_poll_at", &self.next_poll_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiIdentity {
    pub user_id: String,
    /// `chatgpt_account_id`, when the issuer selected a workspace. Bearer-only
    /// WHAM requests are measured to work, so absence stays absent and is
    /// never replaced with the user id.
    pub workspace_id: Option<String>,
    /// Present only when the claim was present. `Some(false)` and `None` are
    /// distinct evidence even though both omit the request header.
    pub is_fedramp: Option<bool>,
    pub email: String,
    pub plan_type: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OpenAiTokenSet {
    pub access_token: String,
    pub refresh_token: String,
    pub client_id: String,
    pub user_id: String,
    pub workspace_id: Option<String>,
    pub is_fedramp: Option<bool>,
}

impl std::fmt::Debug for OpenAiTokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiTokenSet")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("client_id", &self.client_id)
            .field("user_id", &self.user_id)
            .field("workspace_id", &self.workspace_id)
            .field("is_fedramp", &self.is_fedramp)
            .finish()
    }
}

impl OpenAiTokenSet {
    pub fn access_expires_at(&self) -> Option<DateTime<Utc>> {
        jwt_payload(&self.access_token)
            .ok()?
            .get("exp")?
            .as_i64()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
    }

    pub fn needs_refresh_at(&self, now: DateTime<Utc>) -> bool {
        self.access_expires_at()
            .is_some_and(|expires| now + TimeDelta::seconds(EXPIRY_SKEW_SECS) >= expires)
    }
}

#[derive(Debug)]
pub enum DeviceLoginPoll {
    Pending {
        retry_after_secs: u64,
    },
    Complete {
        tokens: Box<OpenAiTokenSet>,
        identity: Box<OpenAiIdentity>,
    },
}

pub async fn request_device_code<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    now: DateTime<Utc>,
) -> Result<DeviceLogin, AuthError> {
    let response = http
        .post_json_response(
            &cfg.device_auth_url,
            &serde_json::json!({ "client_id": cfg.client_id }),
        )
        .await?;
    if response.status == 404 {
        return Err(AuthError::DeviceCodeUnavailable);
    }
    if !(200..300).contains(&response.status) {
        return Err(oauth_error(response.status, &response.body));
    }
    let wire: UserCodeResponse =
        serde_json::from_slice(&response.body).map_err(|e| AuthError::Decode(e.to_string()))?;
    if wire.device_auth_id.is_empty() || wire.user_code.is_empty() {
        return Err(AuthError::Decode(
            "the device-code endpoint returned no code to enter".into(),
        ));
    }
    let interval_secs = wire
        .interval
        .as_deref()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_DEVICE_INTERVAL_SECS)
        .min(MAX_DEVICE_INTERVAL_SECS);
    Ok(DeviceLogin {
        verification_url: cfg.device_verify_url.clone(),
        user_code: wire.user_code,
        interval_secs,
        expires_at: now + TimeDelta::seconds(DEVICE_LOGIN_SECS),
        device_auth_id: wire.device_auth_id,
        next_poll_at: now,
    })
}

pub async fn poll_device_code<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    login: &mut DeviceLogin,
    now: DateTime<Utc>,
) -> Result<DeviceLoginPoll, AuthError> {
    if now >= login.expires_at {
        return Err(AuthError::DeviceCodeExpired);
    }
    if now < login.next_poll_at {
        let seconds = (login.next_poll_at - now).num_seconds().max(1) as u64;
        return Ok(DeviceLoginPoll::Pending {
            retry_after_secs: seconds,
        });
    }

    let response = http
        .post_json_response(
            &cfg.device_token_url,
            &serde_json::json!({
                "device_auth_id": login.device_auth_id,
                "user_code": login.user_code,
            }),
        )
        .await?;
    if matches!(response.status, 403 | 404) {
        login.next_poll_at = now + TimeDelta::seconds(login.interval_secs as i64);
        return Ok(DeviceLoginPoll::Pending {
            retry_after_secs: login.interval_secs,
        });
    }
    if !(200..300).contains(&response.status) {
        return Err(oauth_error(response.status, &response.body));
    }

    let code: DeviceCodeResponse =
        serde_json::from_slice(&response.body).map_err(|e| AuthError::Decode(e.to_string()))?;
    if code.authorization_code.is_empty() || code.code_verifier.is_empty() {
        return Err(AuthError::Decode(
            "the device poll returned no grant to exchange".into(),
        ));
    }

    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.authorization_code.as_str()),
        ("redirect_uri", cfg.device_redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("code_verifier", code.code_verifier.as_str()),
    ];
    let (wire, _raw): (TokenResponse, _) = http.post_form(&cfg.token_url, &form).await?;
    let identity = identity_from_id_token(&wire.id_token)?;
    let tokens = OpenAiTokenSet {
        access_token: wire.access_token,
        refresh_token: wire.refresh_token,
        client_id: cfg.client_id.clone(),
        user_id: identity.user_id.clone(),
        workspace_id: identity.workspace_id.clone(),
        is_fedramp: identity.is_fedramp,
    };
    Ok(DeviceLoginPoll::Complete {
        tokens: Box::new(tokens),
        identity: Box::new(identity),
    })
}

pub async fn refresh<H: TokenHttp>(
    http: &H,
    cfg: &OpenAiAuthConfig,
    tokens: &OpenAiTokenSet,
) -> Result<OpenAiTokenSet, AuthError> {
    // The client id belongs to the grant. Re-reading a newer configured value
    // would try to rotate an old chain as a different public client.
    let response = http
        .post_json_response(
            &cfg.token_url,
            &serde_json::json!({
                "client_id": tokens.client_id,
                "grant_type": "refresh_token",
                "refresh_token": tokens.refresh_token,
            }),
        )
        .await?;
    if !(200..300).contains(&response.status) {
        return Err(refresh_error(response.status, &response.body));
    }
    let wire: RefreshResponse =
        serde_json::from_slice(&response.body).map_err(|e| AuthError::Decode(e.to_string()))?;
    let mut next = tokens.clone();
    if let Some(id_token) = wire.id_token {
        let identity = identity_from_id_token(&id_token)?;
        if identity.user_id != tokens.user_id
            || matches!(
                (&tokens.workspace_id, &identity.workspace_id),
                (Some(old), Some(new)) if old != new
            )
        {
            return Err(AuthError::IdentityMismatch);
        }
        if identity.workspace_id.is_some() {
            next.workspace_id = identity.workspace_id;
        }
        if identity.is_fedramp.is_some() {
            next.is_fedramp = identity.is_fedramp;
        }
    }
    if let Some(access_token) = wire.access_token {
        next.access_token = access_token;
    }
    if let Some(refresh_token) = wire.refresh_token {
        next.refresh_token = refresh_token;
    }
    Ok(next)
}

pub async fn revoke<H: TokenHttp>(http: &H, cfg: &OpenAiAuthConfig, tokens: &OpenAiTokenSet) {
    let body = serde_json::json!({
        "token": tokens.refresh_token,
        "token_type_hint": "refresh_token",
        "client_id": tokens.client_id,
    });
    let call = http.post_json_response(&cfg.revoke_url, &body);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), call).await;
}

#[derive(Deserialize)]
struct UserCodeResponse {
    device_auth_id: String,
    #[serde(alias = "usercode")]
    user_code: String,
    #[serde(default)]
    interval: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    authorization_code: String,
    #[allow(dead_code)]
    code_challenge: String,
    code_verifier: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Default, Deserialize)]
struct RefreshResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

fn jwt_payload(token: &str) -> Result<serde_json::Value, AuthError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AuthError::Decode(
            "the token is not a three-part JWT".into(),
        ));
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(AuthError::Decode(
            "the token is not a three-part JWT".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| AuthError::Decode("the token payload is not base64url".into()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::Decode("the token payload is not a JSON object".into()))
}

fn identity_from_id_token(id_token: &str) -> Result<OpenAiIdentity, AuthError> {
    let payload = jwt_payload(id_token)?;
    let auth = payload.get("https://api.openai.com/auth");
    let user_id = auth
        .and_then(|v| v.get("chatgpt_user_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            auth
                .and_then(|v| v.get("user_id"))
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .ok_or(AuthError::NoAccountIdentifier)?;
    let workspace_id = auth
        .and_then(|v| v.get("chatgpt_account_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(OpenAiIdentity {
        user_id: user_id.to_string(),
        workspace_id,
        is_fedramp: auth
            .and_then(|v| v.get("chatgpt_account_is_fedramp"))
            .and_then(serde_json::Value::as_bool),
        email: payload
            .get("email")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                payload
                    .get("https://api.openai.com/profile")
                    .and_then(|v| v.get("email"))
                    .and_then(serde_json::Value::as_str)
            })
            .unwrap_or_default()
            .to_string(),
        plan_type: auth
            .and_then(|v| v.get("chatgpt_plan_type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

fn oauth_error(status: u16, body: &[u8]) -> AuthError {
    let value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    refresh_error_value(status, &value)
}

fn refresh_error(status: u16, body: &[u8]) -> AuthError {
    let value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    refresh_error_value(status, &value)
}

fn refresh_error_value(status: u16, body: &serde_json::Value) -> AuthError {
    let code = body
        .get("error")
        .and_then(|error| match error {
            serde_json::Value::String(s) => Some(s.as_str()),
            serde_json::Value::Object(map) => map.get("code").and_then(serde_json::Value::as_str),
            _ => None,
        })
        .or_else(|| body.get("code").and_then(serde_json::Value::as_str))
        .map(str::to_string);
    // Do not retain server prose here. Unlike the fixed code, it may echo a
    // submitted user code, verifier or refresh token, and `AuthError` is
    // routinely printed. The typed code and status are enough to classify and
    // localize every behavior this module exposes.
    AuthError::OAuth {
        status,
        code,
        description: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::{ReqwestHttp, USER_AGENT};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_string, header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const NOW: &str = "2026-09-04T00:00:00Z";

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    fn jwt(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("{header}.{body}.signature")
    }

    fn identity_payload(exp: i64, user: &str, workspace: &str) -> serde_json::Value {
        serde_json::json!({
            "exp": exp,
            "email": "person@example.com",
            "https://api.openai.com/auth": {
                "chatgpt_user_id": user,
                "chatgpt_account_id": workspace,
                "chatgpt_plan_type": "plus"
            }
        })
    }

    fn cfg(server: &MockServer) -> OpenAiAuthConfig {
        let base = server.uri();
        OpenAiAuthConfig {
            device_auth_url: format!("{base}/api/accounts/deviceauth/usercode"),
            device_token_url: format!("{base}/api/accounts/deviceauth/token"),
            token_url: format!("{base}/oauth/token"),
            revoke_url: format!("{base}/oauth/revoke"),
            ..OpenAiAuthConfig::default()
        }
    }

    fn tokens() -> OpenAiTokenSet {
        OpenAiTokenSet {
            access_token: jwt(serde_json::json!({ "exp": 1_788_600_000 })),
            refresh_token: "refresh-old".into(),
            client_id: CLIENT_ID.into(),
            user_id: "user-one".into(),
            workspace_id: Some("workspace-one".into()),
            is_fedramp: None,
        }
    }

    #[test]
    fn endpoints_are_the_ones_the_official_client_uses() {
        let c = OpenAiAuthConfig::default();
        assert_eq!(c.device_auth_url, DEVICE_AUTH_URL);
        assert_eq!(c.device_token_url, DEVICE_TOKEN_URL);
        assert_eq!(c.device_verify_url, DEVICE_VERIFY_URL);
        assert_eq!(c.device_redirect_uri, DEVICE_REDIRECT_URI);
        assert_eq!(c.token_url, TOKEN_URL);
        assert_eq!(c.revoke_url, REVOKE_URL);
    }

    #[tokio::test]
    async fn device_start_is_json_honest_and_uses_the_wire_interval_string() {
        let server = MockServer::start().await;
        let seen: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let capture = seen.clone();
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .and(header("content-type", "application/json"))
            .and(header("user-agent", USER_AGENT))
            .and(body_string(format!(r#"{{"client_id":"{CLIENT_ID}"}}"#)))
            .respond_with(move |r: &Request| {
                *capture.lock().unwrap() = Some(r.clone());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "device_auth_id": "device-secret",
                    "usercode": "ABCD-1234",
                    "interval": "7"
                }))
            })
            .expect(1)
            .mount(&server)
            .await;

        let got = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&server), at(NOW))
            .await
            .unwrap();
        assert_eq!(got.verification_url, DEVICE_VERIFY_URL);
        assert_eq!(got.user_code, "ABCD-1234");
        assert_eq!(got.interval_secs, 7);
        assert_eq!(
            got.expires_at,
            at(NOW) + chrono::TimeDelta::seconds(DEVICE_LOGIN_SECS)
        );

        let req = seen.lock().unwrap().take().unwrap();
        assert!(req.headers.get("originator").is_none());
        assert!(req.headers.get("x-openai-codex-luna-reserve").is_none());
    }

    #[tokio::test]
    async fn a_404_at_device_start_is_typed_as_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&server), at(NOW))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::DeviceCodeUnavailable),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_or_hostile_interval_uses_a_bounded_wait() {
        for (wire, expected) in [
            (serde_json::Value::Null, 5),
            (serde_json::json!("0"), 5),
            (serde_json::json!(u64::MAX.to_string()), 900),
        ] {
            let server = MockServer::start().await;
            let mut body = serde_json::json!({
                "device_auth_id": "device-secret", "user_code": "ABCD"
            });
            if !wire.is_null() {
                body["interval"] = wire;
            }
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let got = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&server), at(NOW))
                .await
                .unwrap();
            assert_eq!(got.interval_secs, expected);
        }
    }

    #[tokio::test]
    async fn pending_device_poll_obeys_the_server_interval_without_a_hot_loop() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_auth_id": "device-secret", "user_code": "ABCD", "interval": "5"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let mut login = request_device_code(&http, &cfg(&server), at(NOW))
            .await
            .unwrap();
        let first = poll_device_code(&http, &cfg(&server), &mut login, at(NOW))
            .await
            .unwrap();
        assert!(matches!(
            first,
            DeviceLoginPoll::Pending {
                retry_after_secs: 5
            }
        ));
        let early = poll_device_code(
            &http,
            &cfg(&server),
            &mut login,
            at(NOW) + chrono::TimeDelta::seconds(1),
        )
        .await
        .unwrap();
        assert!(matches!(
            early,
            DeviceLoginPoll::Pending {
                retry_after_secs: 4
            }
        ));
    }

    #[tokio::test]
    async fn an_expired_device_code_never_reaches_the_poll_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_auth_id": "device-secret", "user_code": "ABCD", "interval": "5"
            })))
            .mount(&server)
            .await;
        let http = ReqwestHttp::new().unwrap();
        let c = cfg(&server);
        let mut login = request_device_code(&http, &c, at(NOW)).await.unwrap();
        let before = server.received_requests().await.unwrap().len();
        let expires_at = login.expires_at;
        let err = poll_device_code(&http, &c, &mut login, expires_at)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::DeviceCodeExpired));
        assert_eq!(server.received_requests().await.unwrap().len(), before);
    }

    #[tokio::test]
    async fn approved_device_code_exchanges_as_form_and_keys_the_user_not_the_workspace() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_auth_id": "device-secret", "user_code": "ABCD", "interval": "5"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .and(body_string(
                r#"{"device_auth_id":"device-secret","user_code":"ABCD"}"#,
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_code": "authorization-secret",
                "code_challenge": "challenge",
                "code_verifier": "verifier-secret"
            })))
            .mount(&server)
            .await;
        let id = jwt(identity_payload(
            1_788_500_000,
            "user-person",
            "workspace-team",
        ));
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": id,
                "access_token": jwt(serde_json::json!({"exp": 1_788_600_000})),
                "refresh_token": "refresh-secret"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let c = cfg(&server);
        let mut login = request_device_code(&http, &c, at(NOW)).await.unwrap();
        let got = poll_device_code(&http, &c, &mut login, at(NOW))
            .await
            .unwrap();
        let DeviceLoginPoll::Complete { tokens, identity } = got else {
            panic!("the approved code did not complete")
        };
        assert_eq!(identity.user_id, "user-person");
        assert_eq!(identity.workspace_id.as_deref(), Some("workspace-team"));
        assert_eq!(tokens.user_id, "user-person");
        assert_eq!(tokens.workspace_id.as_deref(), Some("workspace-team"));

        let requests = server.received_requests().await.unwrap();
        let exchange = requests
            .iter()
            .find(|r| r.url.path() == "/oauth/token")
            .unwrap();
        let body = String::from_utf8(exchange.body.clone()).unwrap();
        assert!(body.contains("grant_type=authorization_code"), "{body}");
        assert!(
            body.contains("redirect_uri=https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback"),
            "{body}"
        );
        assert!(body.contains("code_verifier=verifier-secret"), "{body}");
        assert!(
            !body.contains("expires_in"),
            "the exchange must not require a field it never sends"
        );
    }

    #[test]
    fn access_expiry_comes_from_the_access_token() {
        let now = at(NOW);
        let mut t = tokens();
        let access_exp = now + chrono::TimeDelta::hours(8);
        t.access_token = jwt(serde_json::json!({"exp": access_exp.timestamp()}));
        assert_eq!(t.access_expires_at(), Some(access_exp));
        assert!(
            !t.needs_refresh_at(now),
            "the access token itself is still outside the refresh skew"
        );
    }

    /// The ID token is used once to establish the account identity, then
    /// discarded. Keeping three JWT-sized credentials in one serialized blob
    /// adds avoidable pressure against the Windows credential backend's
    /// 2,560-byte ceiling, while refresh and usage need only access + refresh.
    /// Legacy blobs remain readable because serde ignores the removed field.
    #[test]
    fn the_stored_shape_excludes_the_one_time_identity_token() {
        let value = serde_json::to_value(tokens()).unwrap();
        assert!(
            value.get("id_token").is_none(),
            "a one-time identity assertion was retained in the credential blob"
        );

        let mut legacy = value;
        legacy["id_token"] = serde_json::Value::String("legacy.identity.token".into());
        let restored: OpenAiTokenSet = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.user_id, "user-one");
    }

    #[test]
    fn padded_jwt_payloads_keep_user_and_workspace_distinct() {
        let raw = serde_json::to_vec(&identity_payload(
            1_788_500_000,
            "user-person",
            "workspace-team",
        ))
        .unwrap();
        let padded = base64::engine::general_purpose::URL_SAFE.encode(raw);
        let token = format!("e30.{padded}.signature");
        let identity = identity_from_id_token(&token).unwrap();
        assert_eq!(identity.user_id, "user-person");
        assert_eq!(identity.workspace_id.as_deref(), Some("workspace-team"));
    }

    #[test]
    fn a_namespaced_user_fallback_works_and_a_missing_workspace_stays_absent() {
        let without_user = jwt(serde_json::json!({
            "https://api.openai.com/auth": {"chatgpt_account_id": "workspace-one"}
        }));
        assert!(matches!(
            identity_from_id_token(&without_user),
            Err(AuthError::NoAccountIdentifier)
        ));
        let without_workspace = jwt(serde_json::json!({
            "https://api.openai.com/auth": {"user_id": "user-fallback"},
            "https://api.openai.com/profile": {"email": "profile@example.com"}
        }));
        let identity = identity_from_id_token(&without_workspace).unwrap();
        assert_eq!(identity.user_id, "user-fallback");
        assert_eq!(identity.workspace_id, None);
        assert_eq!(identity.email, "profile@example.com");
    }

    #[tokio::test]
    async fn refresh_is_json_and_preserves_every_optional_field_the_server_omits() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("content-type", "application/json"))
            .and(body_string(format!(
                r#"{{"client_id":"{CLIENT_ID}","grant_type":"refresh_token","refresh_token":"refresh-old"}}"#
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let old = tokens();
        let got = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &old)
            .await
            .unwrap();
        assert_eq!(got.access_token, old.access_token);
        assert_eq!(got.refresh_token, old.refresh_token);
    }

    #[tokio::test]
    async fn refresh_refuses_to_move_a_stored_key_to_another_workspace() {
        let server = MockServer::start().await;
        let changed = jwt(identity_payload(
            1_788_500_000,
            "user-one",
            "workspace-other",
        ));
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": changed
            })))
            .mount(&server)
            .await;
        let err = refresh(&ReqwestHttp::new().unwrap(), &cfg(&server), &tokens())
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::IdentityMismatch));
        assert!(
            err.is_dead_grant_for(crate::provider::Provider::Openai),
            "only a new login can resolve an identity change"
        );
    }

    #[test]
    fn every_observed_dead_refresh_code_is_terminal() {
        for (status, code) in [
            (400, "invalid_grant"),
            (400, "refresh_token_reused"),
            (400, "refresh_token_expired"),
            (400, "refresh_token_invalidated"),
            (401, "anything"),
        ] {
            let e = refresh_error(status, &serde_json::json!({"error":{"code":code}}));
            assert!(
                e.is_dead_grant_for(crate::provider::Provider::Openai),
                "{status} {code} was not terminal: {e:?}"
            );
        }
        let e = refresh_error(500, &serde_json::json!({"error":{"code":"server_error"}}));
        assert!(
            !e.is_dead_grant_for(crate::provider::Provider::Openai),
            "a server failure is not a dead credential"
        );
    }

    #[test]
    fn an_oauth_error_never_repeats_server_prose_that_echoed_a_secret() {
        let error = refresh_error(
            400,
            &serde_json::json!({
                "error": "invalid_grant",
                "error_description": "rejected refresh-secret-SENTINEL"
            }),
        );
        let printed = format!("{error:?} {error}");
        assert!(
            !printed.contains("SENTINEL"),
            "an auth error leaked server prose: {printed}"
        );
        assert!(error.is_dead_grant_for(crate::provider::Provider::Openai));
    }

    #[tokio::test]
    async fn revoke_is_json_at_the_official_sibling_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/revoke"))
            .and(header("content-type", "application/json"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "token": "refresh-old",
                "token_type_hint": "refresh_token",
                "client_id": CLIENT_ID,
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        revoke(&ReqwestHttp::new().unwrap(), &cfg(&server), &tokens()).await;
    }

    /// A 307 preserves the POST method and body. Following one here would send
    /// the device authorization request onward; on the exchange/refresh paths
    /// the same client would replay a code verifier or refresh token. The
    /// transport refuses all redirects so the target sees no request at all.
    #[tokio::test]
    async fn an_auth_redirect_never_replays_the_post_body_to_its_target() {
        let source = MockServer::start().await;
        let target = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/capture", target.uri())),
            )
            .expect(1)
            .mount(&source)
            .await;

        let err = request_device_code(&ReqwestHttp::new().unwrap(), &cfg(&source), at(NOW))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::OAuth { status: 307, .. }),
            "got {err:?}"
        );
        assert!(
            target.received_requests().await.unwrap().is_empty(),
            "the redirect target received the auth POST body"
        );
    }

    #[test]
    fn debug_redacts_both_stored_tokens_and_the_device_secrets() {
        let t = tokens();
        let printed = format!("{t:?}");
        for secret in [&t.access_token, &t.refresh_token] {
            assert!(
                !printed.contains(secret),
                "OpenAiTokenSet leaked a token: {printed}"
            );
        }
        assert!(printed.contains("<redacted>"));

        let d = DeviceLogin {
            verification_url: DEVICE_VERIFY_URL.into(),
            user_code: "USER-SECRET".into(),
            interval_secs: 5,
            expires_at: at(NOW) + chrono::TimeDelta::minutes(15),
            device_auth_id: "DEVICE-SECRET".into(),
            next_poll_at: at(NOW),
        };
        let printed = format!("{d:?}");
        assert!(!printed.contains("USER-SECRET"));
        assert!(!printed.contains("DEVICE-SECRET"));
    }

    fn refresh_error(status: u16, body: &serde_json::Value) -> AuthError {
        super::refresh_error_value(status, body)
    }
}
