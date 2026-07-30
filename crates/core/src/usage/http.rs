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
    Throttled { retry_after_secs: u64 },
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
        // more conservative reading. Parsed as `u64`, not `i64`: a malformed
        // or hostile `Retry-After: -5` must not produce a negative value that
        // falls outside §6.2's two-value contract (0, or a positive count of
        // seconds) — parsing as unsigned makes a negative reading fail to
        // parse and fall through to the same 0 as an absent header, rather
        // than reaching a `Duration::from_secs` cast in the poller as a
        // multi-billion-year sleep.
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
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

    // Written as an exhaustive match, not `.map_err(|_| UsageError::UnknownShape)`:
    // if `ParseError` ever gains a third variant, this fails to compile until
    // that variant is given an explicit mapping here, instead of silently
    // inheriting `UnknownShape` for a case nobody has thought through yet.
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
    use crate::auth::token::{ReqwestHttp, ANTHROPIC_BETA, USER_AGENT};
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[tokio::test]
    async fn sends_our_own_user_agent_and_only_the_oauth_beta_header() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<Request>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();

        Mock::given(method("GET"))
            .and(path("/api/oauth/usage"))
            .and(header("anthropic-beta", ANTHROPIC_BETA))
            .and(header("authorization", "Bearer tok"))
            // Pins the wire user agent, not the constant. If `raw_client()` ever
            // stopped applying `USER_AGENT` — or sent something else, e.g.
            // "claude-code/1.0.0" — the request would miss this mock, take
            // wiremock's 404, and the `unwrap()` below would fail the test.
            .and(header("user-agent", USER_AGENT))
            .respond_with(move |req: &Request| {
                *captured_clone.lock().unwrap() = Some(req.clone());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "five_hour": { "utilization": 28, "resets_at": "2026-07-29T15:00:00Z" },
                    "seven_day": null, "limits": []
                }))
            })
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let w = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].percent, 28.0);

        // The "only the oauth beta header" half. wiremock matchers are
        // positive-only, so without this sweep the test passes happily while a
        // dozen Claude-identifying headers ride along beside the ones matched
        // above. Same shape as
        // `get_json_sends_the_oauth_beta_header_and_no_claude_identifying_header`
        // in `auth/token.rs`, and it catches headers this test does not name.
        //
        // Names are swept as well as values. Checking values alone let
        // `x-claude-code-version: 1.0.0` through — the value carries no
        // "claude" at all, and the header identifies Claude Code just as
        // plainly as a user agent would.
        let req = captured.lock().unwrap().take().expect("the request never reached the mock");
        for (name, value) in req.headers.iter() {
            let n = name.as_str().to_lowercase();
            let v = value.to_str().unwrap_or_default().to_lowercase();
            assert!(!n.contains("claude"), "header name `{n}` identifies Claude Code");
            assert!(!v.contains("claude"), "header `{n}` leaked a Claude-identifying value: {v}");
        }
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

    /// The other half of "never demote to 0%". `five_hour` is present but its
    /// `utilization` is not a number, so `parse_usage` reports
    /// `ParseError::UnreadableSource`.
    ///
    /// **This does not distinguish `UnreadableSource` from `UnknownShape`**,
    /// and cannot: both `ParseError` arms deliberately map to the same
    /// `UsageError::UnknownShape`, so the assertion is identical to its
    /// sibling's above. What it pins is the thing that matters at this layer —
    /// that a window present but unreadable becomes an error rather than
    /// falling through to a fabricated empty success, i.e. an implicit 0%. The
    /// distinction between the two parse failures is pinned where it is real,
    /// in `usage::parse`'s `unreadable_sources_yield_an_error_not_an_empty_success`.
    #[tokio::test]
    async fn an_unreadable_source_is_unknown_shape_not_zero() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "five_hour": { "utilization": "n/a" }
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
