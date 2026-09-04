//! docs/design.md §5.5: "Retain the raw JSON so it can be inspected in a debug
//! window." This module is that retention, plus the masking §5.5's debug window
//! is displayed through.
//!
//! **This lives in the core, not in `src-tauri`.** Same reasoning as
//! `snapshots.rs:1-11`: `src-tauri` has no test harness reachable from
//! `cargo test -p quota-core`, and this module decides what a display surface
//! is allowed to show. AGENTS.md records that the same redaction defect already
//! shipped twice in this repository, so the masking must sit where it can be
//! back-tested.

use crate::provider::Provider;
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
const TRUNCATION_MARKER: &str = "\n… truncated by quota-board";

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

/// Same shape as `scheduler::EntryKey` and `snapshots::cache_key`: the primary
/// key is the pair, never the bare id alone (§9.3), or two accounts sharing an
/// id across providers would share one raw slot — each poll overwriting the
/// other's capture, and the debug panel showing whichever landed last
/// regardless of the row selected.
type RawKey = (Provider, String);

fn raw_key(provider: Provider, uuid: &str) -> RawKey {
    (provider, uuid.to_string())
}

/// The last response per account, bounded on both axes.
#[derive(Debug, Default)]
pub struct RawLog {
    entries: HashMap<RawKey, RawResponse>,
}

impl RawLog {
    /// Replaces this account's entry.
    ///
    /// **There is no entry cap, deliberately.** The key set is a subset of the
    /// registered accounts — `record` is only ever reached from `poll_claimed`
    /// with a (provider, uuid) pair the scheduler owns — and `remove` is
    /// called when an account is deleted, so the map's size is the account
    /// count and nothing else. `snapshots` (crates/core/src/snapshots.rs:73-86)
    /// is the same shape for the same reason and has no cap either. An
    /// arbitrary cap with eviction was measured to be worse than the leak it
    /// prevents: with 20 accounts and a cap of 16, four accounts read "no
    /// response captured yet" forever despite polling successfully every
    /// cycle — a confidently wrong display, and design.md:531 puts **no limit
    /// on account count**. The real bound is [`MAX_BODY_BYTES`] per entry.
    pub fn record(&mut self, provider: Provider, uuid: &str, resp: RawResponse) {
        self.entries.insert(raw_key(provider, uuid), resp);
    }

    /// `None` means "nothing captured for this account yet". **Callers must
    /// render that as its own state**, never as an empty body — AGENTS.md's
    /// "never demote a missing value" applies to a debug view exactly as it
    /// applies to a percentage.
    pub fn get(&self, provider: Provider, uuid: &str) -> Option<&RawResponse> {
        self.entries.get(&raw_key(provider, uuid))
    }

    /// Drops one account's entry. Called when an account is deleted, beside
    /// `snapshots::remove` — a deleted account's body must not be readable
    /// afterwards, and a (provider, uuid) pair that is deleted and re-added
    /// must not show the body from before the deletion.
    pub fn remove(&mut self, provider: Provider, uuid: &str) {
        self.entries.remove(&raw_key(provider, uuid));
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
/// Checked against both measured key sets (docs/research/usage-endpoint.md:25-43
/// and :85-158; docs/research/codex-usage-endpoint.md:93-99): apart from `_id`,
/// none of the real keys contains any of these needles, so this masks nothing
/// diagnostic today. `credential` is spelled in full on purpose — `credit` would
/// swallow the real `used_credits` and `credits_ever_enabled`.
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
    // The Codex body carries `account_id` and `user_id` at the top level, and
    // the research document says of that exact body: "This body carries
    // identifiers, so raw captures belong in `.local/`, never in this
    // repository" (codex-usage-endpoint.md:101-104). The debug panel exists to
    // be pasted into a public issue, which is the same disclosure.
    //
    // **`_id`, not `id`.** A bare `id` would also catch
    // `limits[].scope.model.id`, which the Anthropic body carries as a public
    // model identifier beside the `display_name` the parser reads — diagnostic,
    // not identifying. Every account-identifying key measured on either
    // endpoint takes the `_id` shape, and so would an `org_id` or a
    // `workspace_id` grown later, which is the whole reason this layer exists.
    "_id",
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

/// Keys that contain a [`MONEY_KEY_NEEDLES`] needle but name no amount.
/// Matched whole and case-insensitively, in the same style as
/// [`MONEY_SHAPE_KEYS`] and for the same reason: a substring rule here would
/// hand back the ground the needles are there to hold.
///
/// **This only stops a subtree from *becoming* money; it never leaves one.**
/// `key_is_money` is consulted as `in_money || key_is_money(k)`, so a key on
/// this list nested inside `spend{}` stays masked. Deny still wins from above.
///
/// - `rate_limit_reset_credits`: measured as `{ available_count: 1,
///   applicable_available_count: 0 }` (docs/research/codex-usage-endpoint.md,
///   "rate_limit_reset_credits") — a count of limit resets the account holds,
///   not a sum of money. It matches on the `credits` needle, and the two counts
///   under it are exactly what `usage::openai::parse_reset_credits` reads and
///   what the Codex row draws under its bars. Masking them repeats the
///   `decimal_places` incident recorded in [`MONEY_SHAPE_KEYS`]: the panel
///   could not show the numbers the UI beside it was showing.
const NOT_MONEY_KEYS: &[&str] = &["rate_limit_reset_credits"];

/// The **only** numbers allowed to survive inside a money subtree. Deny stays
/// the default: this is an exception list of keys that describe how to *read*
/// an amount, not an allowlist of keys that carry one. Matched whole and
/// case-insensitively, never as a substring — `amount_decimal_places` is an
/// amount and must keep failing this check.
///
/// Both entries are the same fact under the two spellings the endpoint could
/// use, and neither is a magnitude — each is a property of the currency, which
/// the unmasked sibling `currency` string already discloses:
///
/// - `exponent`: the minor-unit scale measured beside `amount_minor`
///   (docs/research/usage-endpoint.md:143-156). Without it `amount_minor` has
///   no meaning at all, and a silent change from 2 to 3 — cents to mills — is
///   exactly the encoding drift §12.4 asks this panel to answer. Masking it
///   produced `"decimal_places": "<redacted:amount>"` in the shipped window.
/// - `decimal_places`: the same scale as a display-precision spelling.
///
/// A key that cannot be justified in these terms is left masked.
const MONEY_SHAPE_KEYS: &[&str] = &["exponent", "decimal_places"];

fn key_is_money(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if NOT_MONEY_KEYS.contains(&k.as_str()) {
        return false;
    }
    MONEY_SUBTREES.contains(&k.as_str()) || MONEY_KEY_NEEDLES.iter().any(|n| k.contains(n))
}

/// A string that spells out a number, which is how the Codex body sends
/// `credits.balance` — `"0"`, quoted (measured, Spike F;
/// docs/research/codex-usage-endpoint.md, "`credits` and `spend_control`").
///
/// [`mask_money`] replaced numbers only, so an amount spelled as a string
/// walked straight through the layer written to stop it. The digit check keeps
/// this to values that are numeric in the ordinary sense: `f64` alone accepts
/// `"NaN"` and `"inf"`, and `currency: "USD"` and `spend.disclaimer`'s prose —
/// both of which §12.4's schema-drift question needs — must keep surviving.
fn is_numeric_string(s: &str) -> bool {
    let t = s.trim();
    t.chars().any(|c| c.is_ascii_digit()) && t.parse::<f64>().is_ok()
}

/// A bare number under a shape-describing key inside a money subtree.
///
/// Three conjuncts, each load-bearing: `key_is_money` is checked *first* so a
/// future money needle that collides with one of these names keeps masking;
/// the value must be a `Number`, so hanging a subtree off `exponent` later
/// cannot open an unmasked island in the middle of `spend{}`; and the name
/// must match a [`MONEY_SHAPE_KEYS`] entry whole.
fn is_money_shape_metadata(key: &str, value: &Value) -> bool {
    if key_is_money(key) || !value.is_number() {
        return false;
    }
    let k = key.to_ascii_lowercase();
    MONEY_SHAPE_KEYS.contains(&k.as_str())
}

/// Layer 1b: inside a money subtree, replace **the magnitudes only** — every
/// number, and a string that spells one out.
///
/// Keys, `null`s, booleans and non-numeric strings survive, so §12.4's
/// schema-drift question — did a field appear, disappear, or change from `null`
/// to an object? — is still answerable from the panel. What does not survive is
/// the magnitude, which the app never reads (neither `usage::anthropic` nor
/// `usage::openai` touches any of these keys) and which is the one thing in
/// this body that is nobody's business in a screenshot pasted into a public
/// issue.
///
/// [`MONEY_SHAPE_KEYS`] is the single, narrow exception: the scale that says
/// how to read an amount is not itself an amount.
fn mask_money(v: &Value, in_money: bool) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, child)| {
                    if in_money && is_money_shape_metadata(k, child) {
                        return (k.clone(), child.clone());
                    }
                    (k.clone(), mask_money(child, in_money || key_is_money(k)))
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|c| mask_money(c, in_money)).collect()),
        Value::Number(_) if in_money => Value::String(MONEY_MASK.to_string()),
        Value::String(s) if in_money && is_numeric_string(s) => {
            Value::String(MONEY_MASK.to_string())
        }
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
        log.record(Provider::Anthropic, "a", at(0));
        log.record(Provider::Anthropic, "a", at(1));
        assert_eq!(log.len(), 1);
        assert_eq!(log.get(Provider::Anthropic, "a").unwrap().body(), "body-1");
    }

    /// The log holds one entry per account and `remove` is the only way out.
    /// There is no eviction: an account that polled successfully must never
    /// read as "nothing captured yet" (AGENTS.md — never demote a missing
    /// value), and design.md:531 puts no limit on account count.
    #[test]
    fn every_account_that_polled_keeps_its_entry_however_many_there_are() {
        let mut log = RawLog::default();
        let v = serde_json::json!({ "five_hour": null });
        for _cycle in 0..3 {
            for i in 0..20 {
                log.record(Provider::Anthropic, &format!("uuid-{i}"), RawResponse::capture(200, &v));
            }
        }
        assert_eq!(log.len(), 20, "an account that polled lost its entry");
        for i in 0..20 {
            assert!(
                log.get(Provider::Anthropic, &format!("uuid-{i}")).is_some(),
                "uuid-{i} was evicted"
            );
        }
    }

    #[test]
    fn removing_an_account_drops_its_capture() {
        let mut log = RawLog::default();
        log.record(Provider::Anthropic, "a", at(0));
        log.record(Provider::Anthropic, "b", at(1));
        log.remove(Provider::Anthropic, "a");
        assert!(
            log.get(Provider::Anthropic, "a").is_none(),
            "a deleted account's body must not stay readable"
        );
        assert!(
            log.get(Provider::Anthropic, "b").is_some(),
            "removing one account must not drop the others"
        );
        log.remove(Provider::Anthropic, "never-there");
        assert_eq!(log.len(), 1, "removing an unknown uuid must be a no-op");
    }

    /// AGENTS.md: never demote a missing value to a fabricated one. An account
    /// that has not polled yet has *no* entry — not an empty body.
    #[test]
    fn an_account_with_no_capture_reads_as_absent_not_as_an_empty_body() {
        let log = RawLog::default();
        assert!(log.get(Provider::Anthropic, "never-polled").is_none());
    }

    /// §9.3: the primary key is the pair, not the bare id. Two accounts
    /// sharing an id across providers must not share a raw slot — otherwise
    /// each poll overwrites the other's capture, and `remove`ing one deletes
    /// both.
    #[test]
    fn two_providers_sharing_an_id_keep_separate_captures() {
        let mut log = RawLog::default();
        log.record(Provider::Anthropic, "same-id", at(0));
        log.record(Provider::Openai, "same-id", at(1));
        assert_eq!(log.len(), 2, "the two providers' captures collapsed into one");
        assert_eq!(log.get(Provider::Anthropic, "same-id").unwrap().body(), "body-0");
        assert_eq!(log.get(Provider::Openai, "same-id").unwrap().body(), "body-1");

        log.remove(Provider::Openai, "same-id");
        assert!(
            log.get(Provider::Anthropic, "same-id").is_some(),
            "removing the Openai account's capture removed the Anthropic one sharing its id"
        );
        assert!(log.get(Provider::Openai, "same-id").is_none());
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

    /// The measured body encodes money as a minor-unit integer plus a scale
    /// (docs/research/usage-endpoint.md:143-156 — `amount_minor` beside
    /// `exponent`). Masking the scale as if it were an amount is what produced
    /// `"decimal_places": "<redacted:amount>"` in the shipped panel: the one
    /// number that says *how to read* the amounts was the one number the panel
    /// could not show, so a change from cents to mills is undiagnosable.
    #[test]
    fn money_shape_metadata_survives_because_it_is_scale_not_magnitude() {
        let v = serde_json::json!({
            "five_hour": null,
            "spend": {
                "used": { "amount_minor": 8375, "currency": "USD", "exponent": 2,
                          "decimal_places": 2 }
            }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(!text.contains("8375"), "the amount survived: {text}");
        assert!(text.contains("\"exponent\": 2"), "the minor-unit scale was masked: {text}");
        assert!(
            text.contains("\"decimal_places\": 2"),
            "the display scale was masked: {text}"
        );
    }

    /// The exception is an explicit list of two keys, matched whole — not a
    /// posture change. Anything else inside a money subtree is still masked,
    /// including a key that merely *contains* one of the two names, because
    /// `amount_decimal_places` is an amount.
    #[test]
    fn a_number_inside_a_money_subtree_that_is_not_shape_metadata_is_still_masked() {
        let v = serde_json::json!({
            "five_hour": null,
            "spend": {
                "used": { "exponent": 2, "rounding_step": 5, "amount_decimal_places": 7 },
                "granted": 41
            }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(text.contains("\"exponent\": 2"), "the exception itself broke: {text}");
        for masked in ["rounding_step", "amount_decimal_places", "granted"] {
            assert!(
                text.contains(&format!("\"{masked}\": \"{MONEY_MASK}\"")),
                "{masked} was left visible inside a money subtree: {text}"
            );
        }
    }

    /// Isolates the **whole-name** conjunct, which nothing else can fail on.
    ///
    /// The test above reaches for `amount_decimal_places`, but that name also
    /// contains the `amount` money needle, so it stays masked whether the match
    /// is whole or substring — it proves the outcome without pinning the rule.
    /// `scale_exponent` contains no needle, so `key_is_money` lets it through
    /// and the whole-name check is the only thing standing between it and the
    /// panel. Loosen `MONEY_SHAPE_KEYS.contains` to a `.iter().any(|s|
    /// k.contains(s))` and this is the assertion that goes red.
    #[test]
    fn a_key_merely_containing_a_shape_name_is_not_the_shape_key() {
        let v = serde_json::json!({
            "five_hour": null,
            "spend": { "scale_exponent": 3, "decimal_places_hint": 4, "exponent": 2 }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(text.contains("\"exponent\": 2"), "the exception itself broke: {text}");
        for masked in ["scale_exponent", "decimal_places_hint"] {
            assert!(
                text.contains(&format!("\"{masked}\": \"{MONEY_MASK}\"")),
                "a substring of a shape key was treated as one: {masked} in {text}"
            );
        }
    }

    /// Isolates the **`key_is_money` first** conjunct.
    ///
    /// That guard exists for a collision that does not exist yet: no current
    /// [`MONEY_SHAPE_KEYS`] entry matches a money needle, so no fixture can
    /// exercise the ordering through `capture`. What *is* checkable — and what
    /// makes the ordering safe rather than merely present — is that the two
    /// lists stay disjoint. Add `exponent` to `MONEY_KEY_NEEDLES`, or a
    /// needle-matching name like `credits_exponent` to `MONEY_SHAPE_KEYS`, and
    /// this fails; without it that change would silently turn an amount key
    /// into an exempt one, which is the only way this exception list can leak.
    #[test]
    fn no_shape_key_is_also_a_money_key() {
        for shape in MONEY_SHAPE_KEYS {
            assert!(
                !key_is_money(shape),
                "`{shape}` is on both lists — `key_is_money` runs first, so it stays masked, but \
                 the exception silently stops meaning anything. Rename it or drop the needle."
            );
        }
    }

    /// The second body shape, run through the real masker.
    ///
    /// Every other test in this module builds an Anthropic-shaped fixture, so
    /// the whole Codex body went unchecked when the key changed. Both
    /// directions matter and they pull opposite ways:
    ///
    /// - `account_id` and `user_id` are the identifiers
    ///   docs/research/codex-usage-endpoint.md:101-104 says raw captures
    ///   belong in `.local/` for carrying. This panel is meant to be pasted
    ///   into a public issue.
    /// - `available_count` and `applicable_available_count` are the two numbers
    ///   the Codex row's own reset-credit line displays. Masking them is the
    ///   `decimal_places` failure recorded above, one provider over: the panel
    ///   could not answer a question about the line the widget draws.
    #[test]
    fn a_codex_body_masks_its_identifiers_and_keeps_the_counts_the_row_draws() {
        let v: Value = serde_json::from_str(include_str!("fixtures/openai_plus_zero.json"))
            .expect("the measured fixture parses");
        let text = RawResponse::capture(200, &v).body().to_string();

        for identifier in ["account_id", "user_id", "email"] {
            assert!(
                text.contains(&format!("\"{identifier}\": \"{KEY_MASK}\"")),
                "{identifier} reached the panel unmasked: {text}"
            );
        }
        // The fixture's ids are already placeholders, so the assertion above is
        // the real one; this catches a mask applied to the key but not to a
        // second occurrence of the value.
        assert!(!text.contains("user-REDACTED"), "an identifier value survived: {text}");
        assert!(!text.contains("redacted@example.com"), "the address survived: {text}");

        assert!(
            text.contains("\"available_count\": 1"),
            "the reset-credit count the row displays was masked: {text}"
        );
        assert!(
            text.contains("\"applicable_available_count\": 0"),
            "the applicable count the row displays was masked: {text}"
        );

        // `credits.balance` is a **string** in this body (measured, Spike F),
        // and it is a real balance on an account that has one. It is not read
        // by any parser, so nothing but the panel ever sees it.
        assert!(
            text.contains(&format!("\"balance\": \"{MONEY_MASK}\"")),
            "a monetary balance shipped because it was spelled as a string: {text}"
        );

        // §12.4's question must still be answerable: the shape survives.
        for shape in [
            "plan_type",
            "plus",
            "primary_window",
            "\"used_percent\": 0",
            "\"limit_window_seconds\": 604800",
            "\"secondary_window\": null",
            "rate_limit_reset_credits",
            "spend_control",
        ] {
            assert!(text.contains(shape), "the shape marker {shape} was lost: {text}");
        }
    }

    /// [`NOT_MONEY_KEYS`] stops a subtree from *becoming* money; it must never
    /// leave one. `rate_limit_reset_credits` is measured at the top level, but
    /// a body that later nested it under `spend{}` would carry amounts, and an
    /// exception that unmasked on the way down would open an island in the
    /// middle of the one subtree this module is most certain about.
    #[test]
    fn a_not_money_key_nested_inside_a_money_subtree_stays_masked() {
        let v = serde_json::json!({
            "five_hour": null,
            "spend": { "rate_limit_reset_credits": { "available_count": 7 } }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(!text.contains("7"), "the exception unmasked inside a money subtree: {text}");
        assert!(
            text.contains("available_count"),
            "the surrounding shape must still be readable: {text}"
        );
    }

    /// The exception is scoped to a bare number directly under the key. A
    /// subtree hung off `exponent` later must not become an unmasked island in
    /// the middle of a money subtree.
    #[test]
    fn a_shape_key_carrying_a_subtree_does_not_unmask_what_is_under_it() {
        let v = serde_json::json!({
            "five_hour": null,
            "spend": { "exponent": { "base": 10, "value": 2 } }
        });
        let text = RawResponse::capture(200, &v).body().to_string();
        assert!(!text.contains("10"), "a number under a shape-key subtree survived: {text}");
        assert!(text.contains("base"), "the surrounding shape must still be readable: {text}");
    }
}
