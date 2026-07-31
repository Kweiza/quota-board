//! docs/design.md §5.5: "Retain the raw JSON so it can be inspected in a debug
//! window." This module is that retention, plus the masking §5.5's debug window
//! is displayed through.
//!
//! **This lives in the core, not in `src-tauri`.** Same reasoning as
//! `snapshots.rs:1-11`: `src-tauri` has no test harness reachable from
//! `cargo test -p quoata-core`, and this module decides what a display surface
//! is allowed to show. CLAUDE.md records that the same redaction defect already
//! shipped twice in this repository, so the masking must sit where it can be
//! back-tested.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

/// Cap on one retained body, **after** masking. The real measured body is
/// ~1.6 KB (docs/research/usage-endpoint.md:85-158), so this is ~40x headroom
/// while still bounding a degenerate or hostile response. An unbounded string
/// per account is a memory leak in a process designed to run for weeks.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const EMAIL_MASK: &str = "<redacted:email>";
const TOKEN_MASK: &str = "<redacted:token>";
const KEY_MASK: &str = "<redacted:by-key-name>";
const TRUNCATION_MARKER: &str = "\n… truncated by quoata-board";

/// One account's last raw usage response, **already masked**.
///
/// `body` is private and there is no constructor that takes a `String`: the
/// only way to obtain one of these is [`RawResponse::capture`], which masks.
/// That is what makes "masked at capture, never at display" an invariant of the
/// type rather than a convention a caller has to remember.
#[derive(Clone, Serialize)]
pub struct RawResponse {
    pub captured_at: DateTime<Utc>,
    pub status: u16,
    /// True when the masked body was longer than [`MAX_BODY_BYTES`]. Surfaced
    /// so the debug window can say so rather than presenting a cut body as
    /// whole.
    pub truncated: bool,
    body: String,
}

/// Hand-written, never derived — the shape `TokenSet` establishes
/// (auth/token.rs:69-87).
///
/// The body here is masked, so this is not the "a credential field is present"
/// case. It is the weaker one: masking is best-effort against a schema we do
/// not own, so a `{:?}` of this value must not become the second display
/// surface nobody audited. The debug window is the only sanctioned way to read
/// the body; a log line, an `assert_eq!` failure or a panic message is not.
impl std::fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawResponse")
            .field("captured_at", &self.captured_at)
            .field("status", &self.status)
            .field("truncated", &self.truncated)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

impl RawResponse {
    /// Masks, then truncates, then stamps.
    ///
    /// **The order is load-bearing.** Truncating first can cut a credential in
    /// half and leave a fragment the masker no longer recognizes: an address
    /// cut to `alice@ex` has no dot in its domain, so `looks_like_email`
    /// rejects it and the local part ships. Masking first means truncation can
    /// only ever cut a placeholder.
    pub fn capture(status: u16, body: &Value) -> Self {
        let (body, truncated) = truncate_on_char_boundary(masked_text(body), MAX_BODY_BYTES);
        Self { captured_at: Utc::now(), status, truncated, body }
    }

    /// The masked body. There is no accessor for an unmasked one because no
    /// unmasked one is kept.
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// The last response per account, bounded on both axes.
#[derive(Debug, Default)]
pub struct RawLog {
    entries: HashMap<String, RawResponse>,
}

impl RawLog {
    /// Replaces this account's entry.
    ///
    /// **There is no entry cap, deliberately.** The key set is a subset of the
    /// registered accounts — `record` is only ever reached from `poll_claimed`
    /// with a uuid the scheduler owns — and `remove` is called when an account
    /// is deleted, so the map's size is the account count and nothing else.
    /// `snapshots` (crates/core/src/snapshots.rs:73-86) is the same shape for
    /// the same reason and has no cap either. An arbitrary cap with eviction
    /// was measured to be worse than the leak it prevents: with 20 accounts and
    /// a cap of 16, four accounts read "no response captured yet" forever
    /// despite polling successfully every cycle — a confidently wrong display,
    /// and design.md:531 puts **no limit on account count**. The real bound is
    /// [`MAX_BODY_BYTES`] per entry.
    pub fn record(&mut self, uuid: &str, resp: RawResponse) {
        self.entries.insert(uuid.to_string(), resp);
    }

    /// `None` means "nothing captured for this account yet". **Callers must
    /// render that as its own state**, never as an empty body — CLAUDE.md's
    /// "never demote a missing value" applies to a debug view exactly as it
    /// applies to a percentage.
    pub fn get(&self, uuid: &str) -> Option<&RawResponse> {
        self.entries.get(uuid)
    }

    /// Drops one account's entry. Called when an account is deleted, beside
    /// `snapshots::remove` — a deleted account's body must not be readable
    /// afterwards, and a uuid that is deleted and re-added must not show the
    /// body from before the deletion.
    pub fn remove(&mut self, uuid: &str) {
        self.entries.remove(uuid);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Key names whose value is masked whatever its shape. This is the only layer
/// that can catch a field the endpoint grows later — `scrub_text` recognizes
/// value *shapes*, so a future `"session_key": "9f3c…"` with no recognizable
/// shape would pass it untouched.
///
/// Checked against the measured key set (docs/research/usage-endpoint.md:25-43
/// and :85-158): none of the real keys contains any of these needles, so this
/// masks nothing diagnostic today. `credential` is spelled in full on purpose —
/// `credit` would swallow the real `used_credits` and `credits_ever_enabled`.
const SENSITIVE_KEY_NEEDLES: &[&str] = &[
    "token",
    "secret",
    "password",
    "passphrase",
    "authorization",
    "api_key",
    "apikey",
    "credential",
    "cookie",
    "session_key",
    "email",
];

fn key_is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_KEY_NEEDLES.iter().any(|n| k.contains(n))
}

/// Layer 1: replace the value under any sensitive key, whole. An object or
/// array under such a key is replaced entirely rather than walked, so nothing
/// nested under `"credentials"` survives.
fn mask_by_key(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if key_is_sensitive(k) {
                        (k.clone(), Value::String(KEY_MASK.to_string()))
                    } else {
                        (k.clone(), mask_by_key(v))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(mask_by_key).collect()),
        other => other.clone(),
    }
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
}

/// Anthropic's OAuth credentials are `sk-ant-oat01-…` (access) and
/// `sk-ant-ort01-…` (refresh) — the prefixes the snapshot cache's leak test
/// uses as sentinels (snapshots.rs:249-252).
fn looks_like_token(word: &str) -> bool {
    word.to_ascii_lowercase().starts_with("sk-ant")
}

fn looks_like_email(word: &str) -> bool {
    let mut parts = word.splitn(2, '@');
    let local = parts.next().unwrap_or_default();
    let Some(domain) = parts.next() else {
        return false;
    };
    if local.is_empty() || domain.contains('@') {
        return false;
    }
    match domain.rsplit_once('.') {
        Some((label, tld)) => {
            !label.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        }
        None => false,
    }
}

/// Layer 2: a lexical sweep over the serialized text. Runs unconditionally and
/// last, so it also catches a credential embedded in a longer string (the real
/// response carries prose — `spend.disclaimer`) and one that appears as a *key*
/// rather than a value.
fn scrub_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut prev_word_was_bearer = false;
    while !rest.is_empty() {
        let word_start = rest.find(is_word_char).unwrap_or(rest.len());
        out.push_str(&rest[..word_start]);
        rest = &rest[word_start..];
        if rest.is_empty() {
            break;
        }
        let word_end = rest.find(|c| !is_word_char(c)).unwrap_or(rest.len());
        let word = &rest[..word_end];
        rest = &rest[word_end..];

        if looks_like_token(word) || prev_word_was_bearer {
            out.push_str(TOKEN_MASK);
        } else if looks_like_email(word) {
            out.push_str(EMAIL_MASK);
        } else {
            out.push_str(word);
        }
        prev_word_was_bearer = word.eq_ignore_ascii_case("bearer");
    }
    out
}

/// Top-level subtrees whose numeric leaves are monetary (docs/design.md:266-270
/// names `spend{}` and `extra_usage{}` as present in the real body;
/// docs/research/usage-endpoint.md:143-156 is the measured shape).
const MONEY_SUBTREES: &[&str] = &["spend", "extra_usage"];

/// Money-carrying keys outside those subtrees — §5.5 names
/// `five_hour.limit_dollars/used_dollars/remaining_dollars`.
const MONEY_KEY_NEEDLES: &[&str] = &["dollars", "credits", "amount", "balance", "_minor"];

const MONEY_MASK: &str = "<redacted:amount>";

fn key_is_money(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    MONEY_SUBTREES.contains(&k.as_str()) || MONEY_KEY_NEEDLES.iter().any(|n| k.contains(n))
}

/// Layer 1b: inside a money subtree, replace **numbers only**.
///
/// Keys, `null`s, booleans and strings survive, so §12.4's schema-drift
/// question — did a field appear, disappear, or change from `null` to an
/// object? — is still answerable from the panel. What does not survive is the
/// magnitude, which the app never reads (`usage::parse` touches none of these
/// keys) and which is the one thing in this body that is nobody's business in a
/// screenshot pasted into a public issue.
fn mask_money(v: &Value, in_money: bool) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, child)| (k.clone(), mask_money(child, in_money || key_is_money(k))))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|c| mask_money(c, in_money)).collect()),
        Value::Number(_) if in_money => Value::String(MONEY_MASK.to_string()),
        other => other.clone(),
    }
}

/// All masking layers, then a canonical pretty-print.
///
/// The output is the body **as parsed and re-serialized**, not the bytes off
/// the wire: key order is normalized and duplicate keys collapse. The debug
/// window says so rather than claiming byte fidelity.
fn masked_text(body: &Value) -> String {
    let by_key = mask_money(&mask_by_key(body), false);
    // Never `unwrap`: `poll_claimed`'s doc comment in `src-tauri/src/state.rs`
    // records that a panic on this path ends polling for the life of the process.
    let pretty = serde_json::to_string_pretty(&by_key)
        .unwrap_or_else(|_| "<the response could not be re-serialized>".to_string());
    scrub_text(&pretty)
}

fn truncate_on_char_boundary(mut s: String, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s, false);
    }
    // `str::floor_char_boundary` is newer than this workspace's rust-version
    // (1.85), so the boundary is walked by hand.
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str(TRUNCATION_MARKER);
    (s, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    const ACCESS: &str = "sk-ant-oat01-SENTINELACCESS";
    const REFRESH: &str = "sk-ant-ort01-SENTINELREFRESH";
    const EMAIL: &str = "sentinel.person@example.invalid";

    /// The measured shape, docs/research/usage-endpoint.md:85-158, trimmed to
    /// the fields the assertions below name.
    fn observed_body() -> Value {
        serde_json::json!({
            "five_hour": {
                "utilization": 7.0,
                "resets_at": "2026-07-29T09:09:59.795962+00:00",
                "limit_dollars": null
            },
            "seven_day": null,
            "limits": [
                { "kind": "session", "group": "session", "percent": 7,
                  "severity": "normal", "resets_at": "2026-07-29T09:09:59.795962+00:00",
                  "scope": null, "is_active": false },
                { "kind": "weekly_scoped", "group": "weekly", "percent": 39,
                  "severity": "normal", "resets_at": "2026-08-01T10:00:00.796179+00:00",
                  "scope": { "model": { "id": null, "display_name": "Fable" }, "surface": null },
                  "is_active": true }
            ],
            "spend": {
                "used": { "amount_minor": 0, "currency": "USD", "exponent": 2 },
                "disclaimer": "Usage credits cover you when you hit your plan limits. [Learn more](https://support.claude.com/articles/12429409)",
                "can_toggle": false
            },
            "member_dashboard_available": false
        })
    }

    /// The measured body plus sentinels in every position a future schema could
    /// put one: a plain value, a value nested in an array element, a value
    /// under a credential-shaped key, and one embedded in prose.
    fn body_with_sentinels() -> Value {
        let mut v = observed_body();
        v["account_owner"] = serde_json::json!(EMAIL);
        v["access_token"] = serde_json::json!(ACCESS);
        v["limits"][1]["scope"]["model"]["display_name"] = serde_json::json!(REFRESH);
        v["spend"]["disclaimer"] = serde_json::json!(format!(
            "Contact {EMAIL} or present Bearer {ACCESS} to raise your limit."
        ));
        v["session"] = serde_json::json!([{ "authorization": format!("Bearer {REFRESH}") }]);
        v
    }

    /// Same shape as `snapshots::tests::the_cache_file_contains_no_token_material`
    /// (snapshots.rs:247-285), including the contiguous-run sweep, and for the
    /// same measured reason: a named-substring sweep alone cannot catch a
    /// truncated leak.
    #[test]
    fn masking_removes_every_token_and_email_including_truncated_runs() {
        let text = RawResponse::capture(200, &body_with_sentinels()).body().to_string();

        for forbidden in [ACCESS, REFRESH, EMAIL, "SENTINEL", "sentinel.person"] {
            assert!(!text.contains(forbidden), "the masked body contains {forbidden}: {text}");
        }

        const RUN: usize = 8;
        for secret in [ACCESS, REFRESH, EMAIL] {
            for window in secret.as_bytes().windows(RUN) {
                let run = std::str::from_utf8(window).expect("the fixtures are ASCII");
                assert!(
                    !text.contains(run),
                    "the masked body contains a {RUN}-character run of a secret ({run}): {text}"
                );
            }
        }
    }

    /// **The test that makes the one above mean something.** `fn mask(_) -> ""`
    /// passes every leak assertion; only this fails it. A debug window that
    /// masks the diagnosis away is not a debug window.
    #[test]
    fn masking_keeps_the_fields_the_debug_window_exists_to_show() {
        let text = RawResponse::capture(200, &body_with_sentinels()).body().to_string();
        for kept in [
            "five_hour",
            "utilization",
            "weekly_scoped",
            "resets_at",
            "2026-08-01T10:00:00.796179+00:00",
            "39",
            "member_dashboard_available",
        ] {
            assert!(!text.is_empty() && text.contains(kept), "masking dropped {kept}: {text}");
        }
    }

    /// The unmasked model name survives when it is not sentinel material — the
    /// measured `display_name` is a real public model name (research:165) and
    /// the parser keys its labels off it.
    #[test]
    fn masking_does_not_touch_ordinary_values() {
        let text = RawResponse::capture(200, &observed_body()).body().to_string();
        assert!(text.contains("Fable"), "a plain display_name was masked: {text}");
        assert!(text.contains("support.claude.com"), "a plain URL was masked: {text}");
        assert!(text.contains("USD"));
    }

    /// Layer 1's reason for existing. Neither value has a recognizable shape,
    /// so the lexical sweep cannot see them; only the key name can.
    #[test]
    fn a_value_under_a_credential_shaped_key_is_masked_whatever_its_shape() {
        let v = serde_json::json!({
            "five_hour": null,
            "session_key": 9_123_456_789_u64,
            "creds": { "api_key": { "nested": "PLAINTEXTVALUE" } }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(!text.contains("9123456789"), "a numeric secret survived: {text}");
        assert!(!text.contains("PLAINTEXTVALUE"), "a nested secret survived: {text}");
        assert!(!text.contains("nested"), "the whole subtree must go, not just its leaf: {text}");
    }

    #[test]
    fn a_body_past_the_cap_is_truncated_at_a_char_boundary_and_marked() {
        let v = serde_json::json!({ "five_hour": null, "pad": "\u{20ac}".repeat(MAX_BODY_BYTES) });
        let captured = RawResponse::capture(200, &v);
        assert!(captured.truncated, "an oversized body must report truncation");
        assert!(
            captured.body().len() <= MAX_BODY_BYTES + TRUNCATION_MARKER.len(),
            "the retained body is {} bytes, past the cap",
            captured.body().len()
        );
        // Reaching here at all proves the cut landed on a char boundary:
        // `String::truncate` panics otherwise.
        assert!(captured.body().ends_with(TRUNCATION_MARKER));
    }

    /// Places `EMAIL` so that [`MAX_BODY_BYTES`] falls *inside* it — after the
    /// `@` and before the final dot. That is the only cut that defeats
    /// `looks_like_email`, so a fixture that does not straddle proves nothing.
    fn body_with_a_straddling_address() -> Value {
        // The fragment a truncate-first implementation would leave behind:
        // "sentinel.person@ex" — 15 + 1 + 2 bytes.
        const CUT_OFFSET: usize = 18;
        let build = |pad: usize| {
            serde_json::json!({ "five_hour": null, "pad": "x".repeat(pad), "who": EMAIL })
        };
        let probe_pad = MAX_BODY_BYTES / 2;
        let probe = serde_json::to_string_pretty(&build(probe_pad)).expect("the probe serializes");
        let idx = probe.find(EMAIL).expect("the address is in the probe body");
        build(probe_pad + MAX_BODY_BYTES - CUT_OFFSET - idx)
    }

    /// Masking must run **before** truncation. With the order reversed an
    /// address straddling the cap is cut to `sentinel.person@ex`, which
    /// `looks_like_email` rejects, and the local part ships.
    #[test]
    fn truncation_cannot_cut_a_credential_out_of_its_mask() {
        let v = body_with_a_straddling_address();

        // The fixture is only meaningful if it really straddles the cap.
        let pretty = serde_json::to_string_pretty(&v).expect("the fixture serializes");
        let idx = pretty.find(EMAIL).expect("the address is in the fixture");
        assert!(
            idx < MAX_BODY_BYTES && MAX_BODY_BYTES < idx + EMAIL.len(),
            "the fixture must straddle the cap: address at {idx}, cap at {MAX_BODY_BYTES}"
        );

        let captured = RawResponse::capture(200, &v);
        assert!(captured.truncated);
        assert!(
            !captured.body().contains("sentinel.person"),
            "a straddling address survived truncation: {}",
            &captured.body()[captured.body().len().saturating_sub(120)..]
        );
    }

    #[test]
    fn debug_output_never_prints_the_body() {
        let v = serde_json::json!({ "five_hour": null, "marker": "DISTINCTIVEBODYTEXT" });
        let printed = format!("{:?}", RawResponse::capture(200, &v));
        assert!(!printed.contains("DISTINCTIVEBODYTEXT"), "Debug printed the body: {printed}");
        assert!(printed.contains("<redacted>"), "Debug must say the body was withheld: {printed}");
        assert!(printed.contains("status"), "Debug should keep the useful metadata: {printed}");
    }

    fn at(secs: i64) -> RawResponse {
        RawResponse {
            captured_at: Utc::now() + TimeDelta::seconds(secs),
            status: 200,
            truncated: false,
            body: format!("body-{secs}"),
        }
    }

    #[test]
    fn recording_the_same_account_twice_replaces_rather_than_grows() {
        let mut log = RawLog::default();
        log.record("a", at(0));
        log.record("a", at(1));
        assert_eq!(log.len(), 1);
        assert_eq!(log.get("a").unwrap().body(), "body-1");
    }

    /// The log holds one entry per account and `remove` is the only way out.
    /// There is no eviction: an account that polled successfully must never
    /// read as "nothing captured yet" (CLAUDE.md — never demote a missing
    /// value), and design.md:531 puts no limit on account count.
    #[test]
    fn every_account_that_polled_keeps_its_entry_however_many_there_are() {
        let mut log = RawLog::default();
        let v = serde_json::json!({ "five_hour": null });
        for _cycle in 0..3 {
            for i in 0..20 {
                log.record(&format!("uuid-{i}"), RawResponse::capture(200, &v));
            }
        }
        assert_eq!(log.len(), 20, "an account that polled lost its entry");
        for i in 0..20 {
            assert!(log.get(&format!("uuid-{i}")).is_some(), "uuid-{i} was evicted");
        }
    }

    #[test]
    fn removing_an_account_drops_its_capture() {
        let mut log = RawLog::default();
        log.record("a", at(0));
        log.record("b", at(1));
        log.remove("a");
        assert!(log.get("a").is_none(), "a deleted account's body must not stay readable");
        assert!(log.get("b").is_some(), "removing one account must not drop the others");
        log.remove("never-there");
        assert_eq!(log.len(), 1, "removing an unknown uuid must be a no-op");
    }

    /// CLAUDE.md: never demote a missing value to a fabricated one. An account
    /// that has not polled yet has *no* entry — not an empty body.
    #[test]
    fn an_account_with_no_capture_reads_as_absent_not_as_an_empty_body() {
        let log = RawLog::default();
        assert!(log.get("never-polled").is_none());
    }

    /// docs/design.md:266-270 (§5.5) names `spend{}`, `extra_usage{}` and
    /// `five_hour.*_dollars` as present in the real body, and
    /// docs/research/usage-endpoint.md:166 says a credit-enabled account
    /// carries values there. The panel's stated threat model is a screenshot
    /// pasted into a public issue, so the magnitudes go — but only the
    /// *numbers*: keys, `null`s, booleans and strings survive, which is
    /// everything §12.4's schema-drift question needs.
    #[test]
    fn money_amounts_are_masked_while_the_shape_around_them_survives() {
        let v = serde_json::json!({
            "five_hour": { "utilization": 7.0, "resets_at": "2026-07-29T09:09:59.795962+00:00",
                           "limit_dollars": 120.0, "used_dollars": 83.75,
                           "remaining_dollars": null },
            "extra_usage": { "is_enabled": true, "monthly_limit": 25000,
                             "used_credits": 18342, "utilization": 73.4, "currency": "USD",
                             "spend_limit_reached": false, "daily": null },
            "limits": [ { "kind": "weekly_scoped", "group": "weekly", "percent": 39,
                          "severity": "normal", "is_active": true } ],
            "spend": { "used": { "amount_minor": 8375, "currency": "USD", "exponent": 2 },
                       "limit": null, "percent": 69,
                       "balance": { "amount_minor": 3625, "currency": "USD", "exponent": 2 },
                       "disclaimer": "Usage credits cover you when you hit your plan limits.",
                       "enabled": true },
            "member_dashboard_available": false
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        for amount in ["8375", "83.75", "120.0", "18342", "25000", "3625", "73.4", "69"] {
            assert!(!text.contains(amount), "the amount {amount} survived: {text}");
        }
        // The half that keeps this from being "mask everything": the panel is
        // still able to answer "did the schema change?".
        for shape in ["spend", "extra_usage", "limit_dollars", "amount_minor", "USD",
                      "\"limit\": null", "\"remaining_dollars\": null", "spend_limit_reached",
                      "disclaimer", "member_dashboard_available"] {
            assert!(text.contains(shape), "the shape marker {shape} was lost: {text}");
        }
        // `limits[]` is not a money subtree: the percentages the app actually
        // displays must not be collateral damage.
        assert!(text.contains("\"percent\": 39"), "a limits[] percentage was masked: {text}");
        assert!(text.contains("\"utilization\": 7.0"), "five_hour.utilization was masked: {text}");
    }
}
