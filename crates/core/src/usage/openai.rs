//! The Codex usage response. **This file is the only place that knows it.**
//!
//! Measured shape (docs/research/codex-usage-endpoint.md):
//!
//! ```json
//! { "rate_limit": { "primary_window": { "used_percent": 0,
//!                                       "limit_window_seconds": 604800,
//!                                       "reset_after_seconds": 604800,
//!                                       "reset_at": 1786345526 },
//!                   "secondary_window": null },
//!   "rate_limit_reset_credits": { "available_count": 1,
//!                                 "applicable_available_count": 0 } }
//! ```

use crate::model::{ResetCredits, UsageWindow};
use crate::usage::anthropic::ParseError;
use chrono::{DateTime, Utc};
use serde_json::Value;

/// `reset_at` is **Unix epoch seconds**, unlike Anthropic's ISO-8601 string.
/// docs/design.md §5.4 carries both conventions for exactly this reason.
///
/// **Not special-cased for a closed window.** While a window is closed the
/// server reports `reset_at` as `now + reset_after_seconds`, so it advances
/// one second per second of wall clock; `formatReset` in the UI renders
/// `resets_at - now`, and the two cancel, leaving a steady countdown like
/// "7d 00h" rather than one that visibly drifts. Suppressing that would
/// require deciding a window is "closed" from `reset_after_seconds ==
/// limit_window_seconds`, which docs/research/codex-usage-endpoint.md records
/// as a hypothesis, not a measurement — so `reset_at` is passed through
/// exactly as the server sent it.
fn parse_reset(v: &Value) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(v.as_i64()?, 0)
}

/// One week, in seconds. Named because it decides two different things —
/// the `7d` label and `UsageWindow::weekly` — and they must not drift apart.
const WEEK_SECONDS: i64 = 604_800;

/// Derived from the window's own length rather than from its slot name. The
/// slot is both plan- and state-dependent: `primary_window` was measured as 7d
/// on an idle paid account, 30d on free, and 5h on an active paid account.
/// Naming either slot for one capture would confidently mislabel the others.
fn label_for(seconds: i64) -> String {
    match seconds {
        18_000 => "5h".to_string(),
        86_400 => "1d".to_string(),
        WEEK_SECONDS => "7d".to_string(),
        2_592_000 => "30d".to_string(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s => format!("{}m", s / 60),
    }
}

fn window(
    rate_limit: &Value,
    slot: &str,
    id_prefix: Option<&str>,
    display_name: Option<&str>,
) -> Option<UsageWindow> {
    let w = rate_limit.get(slot)?;
    // Every field is required. A window missing any of them is dropped rather
    // than filled in: AGENTS.md forbids demoting a missing value, and a bar
    // drawn from a default is exactly that.
    let percent = w
        .get("used_percent")?
        .as_f64()
        .filter(|percent| percent.is_finite() && (0.0..=100.0).contains(percent))?;
    let seconds = w
        .get("limit_window_seconds")?
        .as_i64()
        .filter(|seconds| *seconds > 0)?;
    let resets_at = parse_reset(w.get("reset_at")?)?;
    let slot_id = slot.trim_end_matches("_window");
    let duration = label_for(seconds);
    Some(UsageWindow {
        window_id: id_prefix
            .map(|prefix| format!("additional:{prefix}:{slot_id}"))
            .unwrap_or_else(|| slot_id.to_string()),
        // Duration first: the widget's label track ellipsizes long names on
        // the right. Name-first labels can hide the only part that
        // distinguishes a bucket's primary and secondary windows.
        label: display_name
            .map(|name| format!("{duration} · {name}"))
            .unwrap_or(duration),
        percent,
        resets_at,
        scope: display_name.map(str::to_string),
        // The same reason `label_for` reads the duration rather than the slot
        // name: `secondary_window` is the weekly one on a paid account and is
        // something else on a free one, so a slot-name test would mark a free
        // account's window as weekly and let §8.6's auto sort order that
        // account by a seven-day reset it does not have.
        weekly: seconds == WEEK_SECONDS,
    })
}

fn windows_from_limit(
    rate_limit: &Value,
    id_prefix: Option<&str>,
    display_name: Option<&str>,
) -> impl Iterator<Item = UsageWindow> {
    [
        window(rate_limit, "primary_window", id_prefix, display_name),
        window(rate_limit, "secondary_window", id_prefix, display_name),
    ]
    .into_iter()
    .flatten()
}

/// The windows a recognizable Codex body reports. Identity is checked by
/// [`parse_usage_for_account`] before this parser is allowed onto a production
/// path.
///
/// Two distinct error cases say different things about the response:
///
/// - **`UnknownShape`** when neither `rate_limit` nor
///   `additional_rate_limits` is present — this body is not a recognized Codex
///   usage response at all.
/// - **`UnreadableSource`** when a recognized container is present but every
///   window inside it failed to parse — e.g. `{"rate_limit": {}}`, or a server that
///   renamed `used_percent`. Checking only that the `rate_limit` key exists is
///   not enough: `window()` already returns `None` per-slot on any
///   missing/unparseable field, so a `rate_limit` that exists but is empty or
///   reshaped would otherwise flow straight through `.flatten()` into
///   `Ok(vec![])` — a legitimate-looking empty success. `primary_window` was
///   present and populated in every account measured, on both plans
///   (docs/research/codex-usage-endpoint.md), so an empty result from a
///   present `rate_limit` has no known legitimate cause. This is the same
///   failure `anthropic::ParseError::UnreadableSource` exists to prevent, and
///   its doc comment carries the reasoning directly: disguising "present but
///   unparseable" as "no windows to report" would let the screen freeze
///   silently blank when the endpoint changes shape, with nobody noticing.
///
/// An empty list would render as an account with no limits, which is a claim
/// neither case supports.
fn parse_usage(raw: &Value) -> Result<Vec<UsageWindow>, ParseError> {
    if raw.get("rate_limit").is_none() && raw.get("additional_rate_limits").is_none() {
        return Err(ParseError::UnknownShape);
    }
    let mut windows = Vec::new();
    if let Some(rate_limit) = raw.get("rate_limit").filter(|value| !value.is_null()) {
        windows.extend(windows_from_limit(rate_limit, None, None));
    }
    let mut additional_windows = Vec::new();
    if let Some(additional) = raw.get("additional_rate_limits").and_then(Value::as_array) {
        for bucket in additional {
            let Some(feature) = bucket
                .get("metered_feature")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let display_name = bucket
                .get("limit_name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(feature);
            let Some(rate_limit) = bucket.get("rate_limit").filter(|value| !value.is_null())
            else {
                continue;
            };
            additional_windows.extend(windows_from_limit(
                rate_limit,
                Some(feature),
                Some(display_name),
            ));
        }
    }
    // `metered_feature` is the official stable identity. The response is an
    // array, but neither its order nor uniqueness is part of that identity.
    // Sorting makes presentation a function of content; deduplication prevents
    // duplicate Svelte keys if an upstream retry ever repeats a bucket. The
    // stable sort keeps the first server value when a malformed response gives
    // one feature/slot two different readings.
    additional_windows.sort_by(|a, b| a.window_id.cmp(&b.window_id));
    additional_windows.dedup_by(|a, b| a.window_id == b.window_id);
    windows.extend(additional_windows);
    if windows.is_empty() {
        return Err(ParseError::UnreadableSource);
    }
    Ok(windows)
}

fn response_identity_matches(
    raw: &Value,
    expected_user_id: &str,
    expected_workspace_id: Option<&str>,
) -> bool {
    if expected_user_id.trim().is_empty()
        || expected_workspace_id.is_some_and(|workspace| workspace.trim().is_empty())
    {
        return false;
    }
    if raw.get("user_id").and_then(Value::as_str) != Some(expected_user_id) {
        return false;
    }
    expected_workspace_id.is_none_or(|workspace| {
        raw.get("account_id").and_then(Value::as_str) == Some(workspace)
    })
}

/// Parse one response only when its identity matches the account context that
/// was requested.
///
/// `user_id` is always required and must match. When login supplied a
/// workspace, `account_id` is required and must match that too. When login did
/// not supply one, the response workspace is neither required nor copied from
/// the user id: those identifiers share values on some personal accounts but
/// name different things. A missing required or mismatched value is not an
/// invitation to guess, because that would attach a confident number to the
/// wrong row.
pub fn parse_usage_for_account(
    raw: &Value,
    expected_user_id: &str,
    expected_workspace_id: Option<&str>,
) -> Result<Vec<UsageWindow>, ParseError> {
    if !response_identity_matches(raw, expected_user_id, expected_workspace_id) {
        return Err(ParseError::UnverifiedIdentity);
    }
    parse_usage(raw)
}

/// `None` when the account holds none. **Zero is silence, not a line reading
/// "0"** — the same choice `anthropic::parse_credit` makes for an account with
/// no spending limit.
fn parse_reset_credits(raw: &Value) -> Option<ResetCredits> {
    let c = raw.get("rate_limit_reset_credits")?;
    let available = u32::try_from(c.get("available_count")?.as_i64()?).ok()?;
    if available == 0 {
        return None;
    }
    let applicable = c
        .get("applicable_available_count")
        .and_then(Value::as_i64)
        .and_then(|count| u32::try_from(count).ok())
        .filter(|count| *count <= available);
    Some(ResetCredits {
        available,
        applicable,
    })
}

/// Read reset credits behind the same user/workspace proof as usage windows.
/// A count from another workspace is no safer to display than its percentages.
pub fn parse_reset_credits_for_account(
    raw: &Value,
    expected_user_id: &str,
    expected_workspace_id: Option<&str>,
) -> Result<Option<ResetCredits>, ParseError> {
    if !response_identity_matches(raw, expected_user_id, expected_workspace_id) {
        return Err(ParseError::UnverifiedIdentity);
    }
    Ok(parse_reset_credits(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Measured against a real `plus` account, 2026-08-03.
    const PLUS_ZERO: &str = include_str!("fixtures/openai_plus_zero.json");
    /// Measured against a real `free` account, 2026-08-03. **Except for three
    /// `credits` booleans**: `has_credits`, `unlimited`, and
    /// `overage_limit_reached` were not transcribed before the raw capture was
    /// destroyed (docs/research/codex-usage-endpoint.md, "Measurement errors
    /// made and corrected", item 4) and are not recoverable. They are set to
    /// `false` here as a placeholder, not a measurement — this parser does not
    /// read any of the three, so the placeholder cannot affect a test result.
    const FREE_ZERO: &str = include_str!("fixtures/openai_free_zero.json");
    /// Sanitized from a live paid account capture on 2026-09-03. Unlike the
    /// earlier synthetic body, this establishes which duration occupies each
    /// slot while both are active.
    const PAID_ACTIVE: &str = include_str!("fixtures/openai_paid_active.json");

    fn v(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    #[test]
    fn reads_the_primary_window_of_a_plus_account() {
        let w = parse_usage(&v(PLUS_ZERO)).unwrap();
        assert_eq!(w.len(), 1, "secondary_window is null here, so one bar");
        assert_eq!(w[0].window_id, "primary");
        assert_eq!(w[0].label, "7d");
        assert_eq!(w[0].percent, 0.0);
        assert_eq!(w[0].resets_at.timestamp(), 1786345526);
        assert_eq!(w[0].scope, None);
        assert!(w[0].weekly, "a 7d window is weekly whichever slot it arrives in");
    }

    /// The window length is plan-dependent — 30 days on free, 7 on plus. A
    /// hardcoded "7d" label would mislabel every free account.
    #[test]
    fn labels_a_free_accounts_window_by_its_own_length() {
        let w = parse_usage(&v(FREE_ZERO)).unwrap();
        assert_eq!(w[0].label, "30d");
        assert!(!w[0].weekly, "thirty days is not a week");
    }

    /// The one fixture pair that proves the `weekly` flag cannot be recovered
    /// from `window_id`. Both of these accounts report a window in the
    /// **`primary`** slot, and only one of them is a week — so a downstream
    /// test for `window_id == "secondary"`, or for a label starting "7d",
    /// would rank a free account by a seven-day reset it does not have.
    /// docs/design.md §8.6 is what would then be confidently wrong.
    #[test]
    fn the_weekly_flag_follows_the_duration_not_the_slot_name() {
        let plus = parse_usage(&v(PLUS_ZERO)).unwrap();
        let free = parse_usage(&v(FREE_ZERO)).unwrap();
        assert_eq!(plus[0].window_id, free[0].window_id, "the same slot");
        assert!(plus[0].weekly);
        assert!(!free[0].weekly, "same slot, and not a week");
    }

    #[test]
    fn reads_both_windows_when_both_are_present() {
        let body = v(PAID_ACTIVE);
        assert_ne!(
            body["account_id"], body["user_id"],
            "the quota-bearing workspace is not the user key"
        );
        let w =
            parse_usage_for_account(&body, "user-paid", Some("workspace-paid")).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].window_id, "primary");
        assert_eq!(w[1].window_id, "secondary");
        assert_eq!(w[0].label, "5h", "the paid primary window is the short one");
        assert_eq!(w[0].percent, 31.0);
        assert!(!w[0].weekly);
        assert_eq!(w[1].label, "7d", "the paid secondary window is the weekly one");
        assert_eq!(w[1].percent, 6.0);
        assert!(w[1].weekly);
    }

    /// A valid-looking 200 for another user or workspace is not this row's
    /// usage. Accepting it would render the most dangerous state this product
    /// has: a confident number attached to the wrong account.
    #[test]
    fn response_identity_must_match_the_requested_user_and_workspace() {
        let body = v(PAID_ACTIVE);

        for (user, workspace) in [
            ("another-user", "workspace-paid"),
            ("user-paid", "another-workspace"),
        ] {
            assert!(
                matches!(
                    parse_usage_for_account(&body, user, Some(workspace)),
                    Err(ParseError::UnverifiedIdentity)
                ),
                "accepted response user/workspace {}/{}, for requested {user}/{workspace}",
                body["user_id"],
                body["account_id"]
            );
        }
        assert!(matches!(
            parse_usage_for_account(&body, "another-user", None),
            Err(ParseError::UnverifiedIdentity)
        ));
    }

    /// The user id is always required. Workspace is compared only when the
    /// issuer supplied one during login; a personal grant that omitted the
    /// claim must remain usable through its measured bearer-only request.
    #[test]
    fn missing_response_identity_is_an_error_not_an_unverified_value() {
        let mut no_user = v(PAID_ACTIVE);
        no_user.as_object_mut().unwrap().remove("user_id");
        assert!(matches!(
            parse_usage_for_account(&no_user, "user-paid", None),
            Err(ParseError::UnverifiedIdentity)
        ));

        let mut no_workspace = v(PAID_ACTIVE);
        no_workspace.as_object_mut().unwrap().remove("account_id");
        assert!(matches!(
            parse_usage_for_account(&no_workspace, "user-paid", Some("workspace-paid")),
            Err(ParseError::UnverifiedIdentity)
        ));
        assert!(parse_usage_for_account(&no_workspace, "user-paid", None).is_ok());
    }

    /// AGENTS.md: never demote a missing value to 0%. A body with no
    /// `rate_limit` at all is not an account at 0% — it is a body we do not
    /// understand.
    #[test]
    fn a_body_without_rate_limit_is_unknown_shape_not_zero() {
        let e = parse_usage(&v(r#"{"plan_type":"plus"}"#)).unwrap_err();
        assert!(matches!(e, ParseError::UnknownShape));
    }

    /// A `rate_limit` that is present but whose only window cannot be read
    /// (here, missing `used_percent`) must be an error, not an empty success —
    /// `primary_window` was populated in every account this endpoint has ever
    /// shown us, so a present `rate_limit` yielding zero windows has no known
    /// legitimate cause and must not be confused with "this account has no
    /// limits".
    ///
    /// **Replaces a version of this test that called `.unwrap_or_default()`**,
    /// which passes whether `parse_usage` returns `Ok(vec![])` or
    /// `Err(UnreadableSource)` — it could not tell the two outcomes apart, so
    /// it could not have caught the gap this test now pins.
    #[test]
    fn a_body_whose_only_window_is_unreadable_is_an_error_not_an_empty_success() {
        let body = v(r#"{"rate_limit":{"primary_window":
            {"limit_window_seconds":604800,"reset_at":1786345526}}}"#);
        match parse_usage(&body) {
            Err(ParseError::UnreadableSource) => {}
            other => panic!("expected UnreadableSource, got {other:?} — an empty success is wrong"),
        }
    }

    /// A negative percentage is malformed, not a reassuring empty limit. The
    /// webview clamps bar width below zero and colors negative values green, so
    /// accepting this would turn an upstream error into the healthiest-looking
    /// state the product can display.
    #[test]
    fn a_negative_percentage_is_unreadable_not_zero() {
        let body = v(r#"{"rate_limit":{"primary_window":
            {"used_percent":-1,"limit_window_seconds":604800,
             "reset_at":1786345526}}}"#);
        assert!(matches!(parse_usage(&body), Err(ParseError::UnreadableSource)));
    }

    /// `UsageWindow` promises a 0-100 percentage. `CreditSpend` deliberately
    /// permits overspend, but a Codex rate-limit bar does not: accepting 101
    /// would break the normalized model's contract instead of reporting the
    /// upstream value as unreadable.
    #[test]
    fn a_percentage_above_100_is_unreadable() {
        let body = v(r#"{"rate_limit":{"primary_window":
            {"used_percent":101,"limit_window_seconds":604800,
             "reset_at":1786345526}}}"#);
        assert!(matches!(parse_usage(&body), Err(ParseError::UnreadableSource)));
    }

    /// Zero and negative durations are not labels. Without validation they
    /// become `0d` and a negative duration, both confident UI claims derived
    /// from malformed input.
    #[test]
    fn a_nonpositive_window_duration_is_unreadable() {
        for seconds in [0, -60] {
            let body = serde_json::json!({
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 12,
                        "limit_window_seconds": seconds,
                        "reset_at": 1786345526
                    }
                }
            });
            assert!(
                matches!(parse_usage(&body), Err(ParseError::UnreadableSource)),
                "accepted {seconds}-second window"
            );
        }
    }

    /// The companion to the test above: this is what proves the emptiness
    /// check runs on the *collected* list of windows, not on each window
    /// individually. A fix that errored whenever any single window failed to
    /// parse — rather than only when the whole list came back empty — would
    /// pass every other test in this file but fail this one, by wrongly
    /// discarding the one window that did parse.
    #[test]
    fn one_readable_window_survives_an_unreadable_sibling() {
        let body = v(r#"{"rate_limit":{
            "primary_window": {"used_percent":12,"limit_window_seconds":604800,
                "reset_after_seconds":604800,"reset_at":1786345526},
            "secondary_window": {"limit_window_seconds":18000}
        }}"#);
        let w = parse_usage(&body).unwrap();
        assert_eq!(w.len(), 1, "the unreadable secondary_window must not sink the readable primary");
        assert_eq!(w[0].window_id, "primary");
        assert_eq!(w[0].percent, 12.0);
    }

    #[test]
    fn reads_reset_credits_and_keeps_the_two_counts_apart() {
        let r = parse_reset_credits_for_account(
            &v(PLUS_ZERO),
            "user-REDACTED",
            Some("user-REDACTED"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.available, 1);
        assert_eq!(r.applicable, Some(0));
    }

    /// The current official client accepts this summary shape. Absence of the
    /// older applicable count is unknown, not zero: zero would claim the user
    /// cannot apply a reset when the server did not answer that question.
    #[test]
    fn count_only_reset_credits_do_not_invent_an_applicable_count() {
        let r = parse_reset_credits_for_account(
            &v(r#"{
                "user_id":"user-one",
                "rate_limit_reset_credits":{"available_count":3}
            }"#),
            "user-one",
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.available, 3);
        assert_eq!(r.applicable, None);
    }

    /// Applicability is documented as a subset of available credits. Keep a
    /// valid available count when that optional detail is impossible, but do
    /// not forward the impossible value as a confident UI claim.
    #[test]
    fn an_impossible_applicable_count_becomes_unknown() {
        let r = parse_reset_credits_for_account(
            &v(r#"{
                "user_id":"user-one",
                "rate_limit_reset_credits":{
                    "available_count":3,
                    "applicable_available_count":4
                }
            }"#),
            "user-one",
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.available, 3);
        assert_eq!(r.applicable, None);
    }

    /// `additional_rate_limits` is the wire form behind the official
    /// multi-bucket view. Every readable bucket must survive normalization,
    /// with a stable id and a label that distinguishes it from ordinary Codex
    /// windows.
    #[test]
    fn reads_every_additional_rate_limit_bucket() {
        let body = v(
            r#"{
                "rate_limit": {
                    "primary_window": {
                        "used_percent": 11,
                        "limit_window_seconds": 18000,
                        "reset_at": 1788414820
                    }
                },
                "additional_rate_limits": [
                    {
                        "limit_name": "Codex Spark",
                        "metered_feature": "codex_spark",
                        "rate_limit": {
                            "primary_window": {
                                "used_percent": 42,
                                "limit_window_seconds": 3600,
                                "reset_at": 1788418420
                            },
                            "secondary_window": {
                                "used_percent": 7,
                                "limit_window_seconds": 86400,
                                "reset_at": 1788501220
                            }
                        }
                    },
                    {
                        "limit_name": "Codex Luna",
                        "metered_feature": "codex_luna",
                        "rate_limit": {
                            "primary_window": {
                                "used_percent": 9,
                                "limit_window_seconds": 900,
                                "reset_at": 1788415720
                            }
                        }
                    }
                ]
            }"#,
        );
        let windows = parse_usage(&body).unwrap();
        assert_eq!(windows.len(), 4);
        assert_eq!(windows[0].window_id, "primary");
        assert_eq!(windows[1].window_id, "additional:codex_luna:primary");
        assert_eq!(windows[1].label, "15m · Codex Luna");
        assert_eq!(windows[2].window_id, "additional:codex_spark:primary");
        assert_eq!(windows[2].label, "1h · Codex Spark");
        assert_eq!(windows[2].scope.as_deref(), Some("Codex Spark"));
        assert_eq!(windows[3].window_id, "additional:codex_spark:secondary");
        assert_eq!(windows[3].label, "1d · Codex Spark");
    }

    /// The default bucket is backwards-compatible, not a prerequisite. A
    /// response with only a readable named bucket still provided real usage.
    #[test]
    fn an_additional_only_response_is_still_readable() {
        let body = v(
            r#"{
                "additional_rate_limits": [{
                    "limit_name": "Codex Spark",
                    "metered_feature": "codex_spark",
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 21,
                            "limit_window_seconds": 3600,
                            "reset_at": 1788418420
                        }
                    }
                }]
            }"#,
        );
        let windows = parse_usage(&body).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].window_id, "additional:codex_spark:primary");
    }

    /// The webview keys bars by `window_id`. Reordering the server array must
    /// not reorder those bars, and a duplicate feature/slot must not emit two
    /// identical keys that make Svelte reject the whole row.
    #[test]
    fn additional_window_ids_are_unique_and_order_independent() {
        fn bucket(feature: &str, percent: u32) -> Value {
            serde_json::json!({
                "limit_name": feature,
                "metered_feature": feature,
                "rate_limit": {
                    "primary_window": {
                        "used_percent": percent,
                        "limit_window_seconds": 3600,
                        "reset_at": 1788418420
                    }
                }
            })
        }

        let first = serde_json::json!({
            "additional_rate_limits": [
                bucket("zeta", 9),
                bucket("alpha", 7),
                bucket("alpha", 99)
            ]
        });
        let second = serde_json::json!({
            "additional_rate_limits": [
                bucket("alpha", 7),
                bucket("zeta", 9)
            ]
        });

        let first = parse_usage(&first).unwrap();
        let second = parse_usage(&second).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.iter().map(|window| window.window_id.as_str()).collect::<Vec<_>>(),
            ["additional:alpha:primary", "additional:zeta:primary"]
        );
    }

    /// Unknown future entries are isolated. A malformed bucket must not erase
    /// a readable sibling just because both live in the same dynamic array.
    #[test]
    fn a_readable_additional_bucket_survives_malformed_siblings() {
        let body = serde_json::json!({
            "additional_rate_limits": [
                {
                    "limit_name": "missing stable identity",
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 90,
                            "limit_window_seconds": 3600,
                            "reset_at": 1788418420
                        }
                    }
                },
                {
                    "limit_name": "Codex Spark",
                    "metered_feature": "codex_spark",
                    "rate_limit": {
                        "primary_window": {
                            "used_percent": 21,
                            "limit_window_seconds": 3600,
                            "reset_at": 1788418420
                        }
                    }
                }
            ]
        });

        let windows = parse_usage(&body).unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].window_id, "additional:codex_spark:primary");
    }

    /// Zero credits is silence, not a line reading "0" — the same treatment
    /// `parse_credit` gives an account with no spending limit.
    #[test]
    fn zero_reset_credits_is_absent_rather_than_a_zero() {
        assert_eq!(
            parse_reset_credits_for_account(
                &v(FREE_ZERO),
                "user-REDACTED",
                Some("user-REDACTED"),
            )
                .unwrap(),
            None
        );
    }

    /// The two parsers must not accept each other's bodies. Anthropic's
    /// response has no `rate_limit` object, and Codex's has no `limits[]`.
    #[test]
    fn an_anthropic_body_does_not_parse_as_codex() {
        let anthropic = v(r#"{"five_hour":{"utilization":7.0,
            "resets_at":"2026-07-29T09:09:59.795962+00:00"},"limits":[]}"#);
        assert!(parse_usage(&anthropic).is_err());
    }

}
