use crate::auth::token::{ReqwestHttp, ANTHROPIC_BETA};
use crate::model::{ExtraLine, UsageWindow};
use crate::usage::parse::{parse_credit, parse_usage, ParseError};
use crate::usage::raw::RawResponse;

/// Spec §5.1. The single data source.
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("access token was rejected")]
    Unauthorized,
    /// The server is refusing OAuth for this account right now.
    ///
    /// Split out from `Unauthorized` because the two need opposite handling and
    /// arrive with the same status. Measured on a real account, 2026-08-01:
    ///
    /// ```json
    /// {"type":"error","error":{"type":"permission_error",
    ///  "message":"OAuth authentication is currently not allowed for this organization.",
    ///  "details":{"error_code":"oauth_not_allowed_for_organization"}}}
    /// ```
    ///
    /// The token is valid, so refreshing changes nothing and re-login changes
    /// nothing — the grant would be refused again.
    ///
    /// **Do not read the code's wording as the cause.** It names an
    /// organization, but the one case observed was a **lapsed subscription** on
    /// an ordinary personal account, and the message itself says "currently".
    /// Treating this as permanent was an error in an earlier revision;
    /// `scheduler` retries it with backoff rather than quarantining.
    #[error("OAuth is disabled for this account's organization")]
    OauthNotAllowed,
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
///
/// Signature unchanged on purpose: `crates/cli` (via `fetch_usage`) and the
/// tests below call this and must keep compiling. It is now a thin wrapper
/// over the capturing form.
pub async fn fetch_usage_at(
    http: &ReqwestHttp,
    url: &str,
    access_token: &str,
) -> Result<Vec<UsageWindow>, UsageError> {
    fetch_usage_captured_at(http, url, access_token).await.outcome
}

/// What one fetch produced: the parse outcome, plus the raw body if the
/// request got far enough to have one.
///
/// **Not a `Result`**, and that is the whole point. §5.5 lists "retain the raw
/// JSON so it can be inspected in a debug window" directly beside "treat
/// unrecognizable shapes as an `UNKNOWN_SHAPE` state" — the body the debug
/// window exists for is the body that *failed* to parse. A
/// `Result<(windows, raw), UsageError>` drops it on exactly that path.
pub struct CapturedFetch {
    /// `None` when no body was read at all — a transport failure, a 429, or a
    /// non-2xx status. **Never a fabricated empty body** (CLAUDE.md: never
    /// demote a missing value).
    pub raw: Option<RawResponse>,
    /// The optional line under the bars, when this account has one.
    ///
    /// Read beside `outcome` rather than folded into it: an account can have a
    /// perfectly readable extra line in a body whose windows fail to parse, and
    /// vice versa. Tying the two would drop one because the other broke.
    pub extra: Option<ExtraLine>,
    pub outcome: Result<Vec<UsageWindow>, UsageError>,
}

/// The capturing form. Same request, same status ladder, same `Retry-After`
/// reading — §4.3's URL-injection seam is untouched and no trait enters
/// `usage`.
pub async fn fetch_usage_captured_at(
    http: &ReqwestHttp,
    url: &str,
    access_token: &str,
) -> CapturedFetch {
    let (status, body) = match fetch_usage_body_at(http, url, access_token).await {
        Ok(pair) => pair,
        Err(e) => return CapturedFetch { raw: None, extra: None, outcome: Err(e) },
    };
    // Captured before parsing, deliberately: the body the debug window most
    // needs is the one `windows_from_body` is about to reject.
    let raw = Some(RawResponse::capture(status, &body));
    CapturedFetch {
        raw,
        extra: parse_credit(&body).map(ExtraLine::Credit),
        outcome: windows_from_body(&body),
    }
}

/// The request half: everything up to and including the 2xx body read.
///
/// Returns the status beside the body so the debug view reports the status that
/// actually arrived. A 2xx that is not 200 is precisely the drift §12.4 asks
/// this window to make visible, and a hardcoded 200 would hide it.
async fn fetch_usage_body_at(
    http: &ReqwestHttp,
    url: &str,
    access_token: &str,
) -> Result<(u16, serde_json::Value), UsageError> {
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
    // A 403 is not always the same thing as a 401, and the difference is
    // permanent versus transient — so this one status needs its body read
    // before it is classified. Everything else keeps the old ladder.
    //
    // Reading it cannot fail the request: a 403 whose body is missing,
    // truncated or not JSON falls through to `Unauthorized`, which is where it
    // used to go anyway. The only thing a body buys is the chance to recognise
    // the one code that must not be treated as recoverable.
    if status == 403 {
        let body = resp.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null);
        if is_oauth_not_allowed(&body) {
            return Err(UsageError::OauthNotAllowed);
        }
        return Err(UsageError::Unauthorized);
    }
    if status == 401 {
        return Err(UsageError::Unauthorized);
    }
    if !(200..300).contains(&status) {
        return Err(UsageError::Status(status));
    }

    // `resp.json()`, not `text()` + `from_str`: a 2xx body that is not JSON is
    // a `Transport` error today (-> `FailureKind::Network`, in
    // `FailureKind::from_usage_error`),
    // and reading the text first would reclassify it as `UnknownShape` — a
    // behaviour change smuggled into a debug-window task.
    let body = resp.json().await.map_err(|e| UsageError::Transport(e.to_string()))?;
    Ok((status, body))
}

/// Whether a 403 body carries the one error code that means "not this account,
/// right now", rather than "not with this token".
///
/// Named for what it detects and not for what the code says. The wire code is
/// `oauth_not_allowed_for_organization`, but the observed cause was a lapsed
/// subscription on an ordinary account — so a function called
/// `is_org_oauth_disabled` (which this was) teaches every later reader a wrong
/// cause.
///
/// Matched on `error_code` and **not** on `message`: the message is prose the
/// server is free to reword, and the code is the part documented as stable by
/// being a code at all. An unrecognised shape yields `false`, which routes to
/// `Unauthorized` — the pre-existing behaviour, so a server-side rename
/// degrades to what this function replaced rather than to something new.
fn is_oauth_not_allowed(body: &serde_json::Value) -> bool {
    body.get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("error_code"))
        .and_then(serde_json::Value::as_str)
        == Some("oauth_not_allowed_for_organization")
}

/// The parsing half, split out so a caller that captured the body can still
/// classify it.
fn windows_from_body(body: &serde_json::Value) -> Result<Vec<UsageWindow>, UsageError> {
    // Written as an exhaustive match, not `.map_err(|_| UsageError::UnknownShape)`:
    // if `ParseError` ever gains a third variant, this fails to compile until
    // that variant is given an explicit mapping here, instead of silently
    // inheriting `UnknownShape` for a case nobody has thought through yet.
    parse_usage(body).map_err(|e| match e {
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

    /// §5.5 puts "retain the raw JSON" beside "treat unrecognizable shapes as
    /// `UNKNOWN_SHAPE`", so the body the debug window most needs is the one the
    /// parser just rejected. A `Result<(windows, raw), _>` shape drops it at
    /// the `?`.
    #[tokio::test]
    async fn a_body_that_fails_to_parse_is_still_captured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "maintenance", "distinctive_marker": "SCHEMADRIFT"
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let got =
            fetch_usage_captured_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
                .await;

        assert!(matches!(got.outcome, Err(UsageError::UnknownShape)));
        let raw = got.raw.expect("the body that failed to parse is the one to keep");
        assert!(
            raw.body().contains("SCHEMADRIFT"),
            "the unparseable body was discarded: {}",
            raw.body()
        );
    }

    /// CLAUDE.md: never demote a missing value to a fabricated one. A 429 is
    /// answered before any body is read, so there is nothing to show — and
    /// "nothing" must not be rendered as an empty response.
    #[tokio::test]
    async fn a_throttled_fetch_captures_nothing_rather_than_an_empty_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "42"))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let got =
            fetch_usage_captured_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
                .await;

        assert!(matches!(got.outcome, Err(UsageError::Throttled { retry_after_secs: 42 })));
        assert!(got.raw.is_none(), "a 429 has no body to keep, and none may be invented");
    }

    /// Masking happens at capture, not at display: `RawResponse::capture` is
    /// the only constructor, so no caller can retain an unmasked body by
    /// forgetting a step.
    #[tokio::test]
    async fn a_captured_body_is_already_masked() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "five_hour": { "utilization": 28, "resets_at": "2026-07-29T15:00:00Z" },
                "seven_day": null, "limits": [],
                "account_owner": "sentinel.person@example.invalid",
                "spend": { "used": { "amount_minor": 8375, "currency": "USD" } }
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let raw = fetch_usage_captured_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .raw
            .expect("a 200 body must be captured");

        assert!(!raw.body().contains("sentinel.person"), "an address survived: {}", raw.body());
        assert!(!raw.body().contains("8375"), "an amount survived: {}", raw.body());
        // The other half: masking that removed the diagnosis would be useless.
        assert!(raw.body().contains("utilization"), "masking dropped the shape: {}", raw.body());
    }

    /// §12.4 asks this window to make schema drift visible, and a 2xx that is
    /// not 200 is exactly that. A hardcoded 200 would hide it.
    #[tokio::test]
    async fn the_captured_status_is_the_one_the_server_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
                "five_hour": { "utilization": 28, "resets_at": "2026-07-29T15:00:00Z" },
                "seven_day": null, "limits": []
            })))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let got =
            fetch_usage_captured_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
                .await;

        assert!(got.outcome.is_ok(), "a 202 is still a success on the status ladder");
        assert_eq!(got.raw.expect("a 2xx body must be captured").status, 202);
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

    /// The body is the one measured on a real account on 2026-08-01, verbatim.
    /// A hand-simplified body would test the parser against a shape the server
    /// does not send.
    const ORG_DISABLED_BODY: &str = r#"{
        "type": "error",
        "error": {
            "type": "permission_error",
            "message": "OAuth authentication is currently not allowed for this organization.",
            "details": {
                "error_visibility": "user_facing",
                "error_code": "oauth_not_allowed_for_organization"
            }
        },
        "request_id": "req_011CdbxpKgRdr6NWwLPok5WP"
    }"#;

    #[tokio::test]
    async fn a_403_naming_the_org_policy_is_not_merely_unauthorized() {
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/oauth/usage"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_raw(ORG_DISABLED_BODY, "application/json"),
            )
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(
            matches!(err, UsageError::OauthNotAllowed),
            "a 403 carrying oauth_not_allowed_for_organization must not be \
             classified as a recoverable auth failure, got {err:?}"
        );
    }

    /// The other side of the same branch: a 403 this code does not recognise
    /// must land exactly where it landed before this variant existed.
    #[tokio::test]
    async fn an_unrecognised_403_still_reports_unauthorized() {
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/oauth/usage"))
            .respond_with(ResponseTemplate::new(403).set_body_raw(
                r#"{"error":{"details":{"error_code":"something_else"}}}"#,
                "application/json",
            ))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::Unauthorized), "got {err:?}");
    }

    /// A 403 with no body at all, which is what a proxy or an outage produces.
    #[tokio::test]
    async fn a_403_with_no_body_reports_unauthorized_rather_than_panicking() {
        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/oauth/usage"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = fetch_usage_at(&http, &format!("{}/api/oauth/usage", server.uri()), "tok")
            .await
            .unwrap_err();
        assert!(matches!(err, UsageError::Unauthorized), "got {err:?}");
    }

    /// Matched on the code, not the prose — the message is the server's to
    /// reword and this must not depend on it.
    #[test]
    fn the_org_policy_is_recognised_by_code_and_not_by_message() {
        let real: serde_json::Value = serde_json::from_str(ORG_DISABLED_BODY).unwrap();
        assert!(is_oauth_not_allowed(&real));

        let reworded: serde_json::Value = serde_json::from_str(
            r#"{"error":{"message":"totally different prose",
                 "details":{"error_code":"oauth_not_allowed_for_organization"}}}"#,
        )
        .unwrap();
        assert!(is_oauth_not_allowed(&reworded), "the message must not matter");

        let right_message_wrong_code: serde_json::Value = serde_json::from_str(
            r#"{"error":{"message":"OAuth authentication is currently not allowed for this organization.",
                 "details":{"error_code":"renamed_upstream"}}}"#,
        )
        .unwrap();
        assert!(
            !is_oauth_not_allowed(&right_message_wrong_code),
            "a renamed code must degrade to Unauthorized, not be rescued by prose"
        );

        assert!(!is_oauth_not_allowed(&serde_json::Value::Null));
    }
}
