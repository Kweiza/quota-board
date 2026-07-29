use crate::auth::token::{ReqwestHttp, ANTHROPIC_BETA};
use crate::model::UsageWindow;
use crate::usage::parse::{parse_usage, ParseError};

/// Spec §5.1. The single data source.
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("access token was rejected")]
    Unauthorized,
    #[error("throttled (retry_after={retry_after_secs}s)")]
    Throttled { retry_after_secs: i64 },
    #[error("response shape not recognized")]
    UnknownShape,
    #[error("HTTP {0}")]
    Status(u16),
    #[error("transport error: {0}")]
    Transport(String),
}

pub async fn fetch_usage(
    http: &ReqwestHttp,
    access_token: &str,
) -> Result<Vec<UsageWindow>, UsageError> {
    fetch_usage_at(http, USAGE_URL, access_token).await
}

/// The URL-taking form. Tests point this at a mock server.
pub async fn fetch_usage_at(
    http: &ReqwestHttp,
    url: &str,
    access_token: &str,
) -> Result<Vec<UsageWindow>, UsageError> {
    let resp = http
        .raw_client()
        .get(url)
        .bearer_auth(access_token)
        // Spec §5.2: this one header only. Nothing that identifies Claude Code.
        .header("anthropic-beta", ANTHROPIC_BETA)
        .header("Content-Type", "application/json")
        .send()
        .await
        .map_err(|e| UsageError::Transport(e.to_string()))?;

    let status = resp.status().as_u16();

    if status == 429 {
        // Absence of Retry-After is interpreted as 0 (budget exhausted) — the
        // more conservative reading.
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);
        return Err(UsageError::Throttled { retry_after_secs });
    }
    if status == 401 || status == 403 {
        return Err(UsageError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(UsageError::Status(status));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| UsageError::Transport(e.to_string()))?;

    // Task 4 split ParseError into two variants (UnknownShape,
    // UnreadableSource). The single-variant irrefutable pattern
    // (`|ParseError::UnknownShape|`) no longer compiles, so this must be a match.
    parse_usage(&body).map_err(|e| match e {
        ParseError::UnknownShape => UsageError::UnknownShape,
        // A window existed but could not be read — surface it rather than
        // demoting it to 0%.
        ParseError::UnreadableSource => UsageError::UnknownShape,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::ReqwestHttp;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn sends_our_own_user_agent_and_only_the_oauth_beta_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/oauth/usage"))
            .and(header("anthropic-beta", "oauth-2025-04-20"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "five_hour": { "utilization": 28, "resets_at": "2026-07-29T15:00:00Z" },
                "seven_day": null, "limits": []
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let w = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].percent, 28.0);
    }

    #[tokio::test]
    async fn a_429_becomes_throttled_with_its_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::Throttled { retry_after_secs: 42 }));
    }

    /// A 429 without Retry-After is interpreted as 0 (budget exhausted) —
    /// the more conservative reading.
    #[tokio::test]
    async fn a_429_without_retry_after_is_treated_as_saturated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::Throttled { retry_after_secs: 0 }));
    }

    #[tokio::test]
    async fn an_unparseable_body_is_unknown_shape_not_zero() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "maintenance"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::UnknownShape));
    }

    #[tokio::test]
    async fn a_401_is_reported_as_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::Unauthorized));
    }
}
