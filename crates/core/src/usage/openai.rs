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

/// Derived from the window's own length rather than from its slot name,
/// because the length is plan-dependent: 604800 on `plus` and 2592000 on
/// `free` were both measured on `primary_window`. Naming the slot "weekly"
/// would mislabel every free account.
fn label_for(seconds: i64) -> String {
    match seconds {
        18_000 => "5h".to_string(),
        86_400 => "1d".to_string(),
        604_800 => "7d".to_string(),
        2_592_000 => "30d".to_string(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s => format!("{}m", s / 60),
    }
}

fn window(root: &Value, slot: &str) -> Option<UsageWindow> {
    let w = root.get("rate_limit")?.get(slot)?;
    // Every field is required. A window missing any of them is dropped rather
    // than filled in: CLAUDE.md forbids demoting a missing value, and a bar
    // drawn from a default is exactly that.
    let percent = w.get("used_percent")?.as_f64()?;
    let seconds = w.get("limit_window_seconds")?.as_i64()?;
    let resets_at = parse_reset(w.get("reset_at")?)?;
    Some(UsageWindow {
        window_id: slot.trim_end_matches("_window").to_string(),
        label: label_for(seconds),
        percent,
        resets_at,
        scope: None,
    })
}

/// The windows this account reports. **`Err` when the body is not a Codex usage
/// response at all** — an empty list would render as an account with no limits,
/// which is a claim the body does not support.
pub fn parse_usage(raw: &Value) -> Result<Vec<UsageWindow>, ParseError> {
    if raw.get("rate_limit").is_none() {
        return Err(ParseError::UnknownShape);
    }
    Ok([window(raw, "primary_window"), window(raw, "secondary_window")]
        .into_iter()
        .flatten()
        .collect())
}

/// `None` when the account holds none. **Zero is silence, not a line reading
/// "0"** — the same choice `anthropic::parse_credit` makes for an account with
/// no spending limit.
pub fn parse_reset_credits(raw: &Value) -> Option<ResetCredits> {
    let c = raw.get("rate_limit_reset_credits")?;
    let available = u32::try_from(c.get("available_count")?.as_i64()?).ok()?;
    if available == 0 {
        return None;
    }
    let applicable = u32::try_from(c.get("applicable_available_count")?.as_i64()?).ok()?;
    Some(ResetCredits { available, applicable })
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
    /// **Synthetic. No measurement backs this shape.** No account with usage in
    /// flight was ever observed (docs/research/codex-usage-endpoint.md, "Scope
    /// limits"), so `secondary_window` being populated, and the values in it,
    /// are this project's guess. A failure here means the guess was wrong, not
    /// that the server changed.
    const SYNTHETIC_POPULATED: &str = include_str!("fixtures/openai_synthetic_populated.json");

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
    }

    /// The window length is plan-dependent — 30 days on free, 7 on plus. A
    /// hardcoded "7d" label would mislabel every free account.
    #[test]
    fn labels_a_free_accounts_window_by_its_own_length() {
        let w = parse_usage(&v(FREE_ZERO)).unwrap();
        assert_eq!(w[0].label, "30d");
    }

    #[test]
    fn reads_both_windows_when_both_are_present() {
        let w = parse_usage(&v(SYNTHETIC_POPULATED)).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].window_id, "primary");
        assert_eq!(w[1].window_id, "secondary");
        assert_eq!(w[1].label, "5h");
        assert_eq!(w[1].percent, 62.0);
    }

    /// CLAUDE.md: never demote a missing value to 0%. A body with no
    /// `rate_limit` at all is not an account at 0% — it is a body we do not
    /// understand.
    #[test]
    fn a_body_without_rate_limit_is_unknown_shape_not_zero() {
        let e = parse_usage(&v(r#"{"plan_type":"plus"}"#)).unwrap_err();
        assert!(matches!(e, ParseError::UnknownShape));
    }

    /// A window missing its percentage is dropped, not defaulted. One
    /// unreadable window must not become a confident 0% bar.
    #[test]
    fn a_window_without_a_percentage_is_dropped_rather_than_zeroed() {
        let body = v(r#"{"rate_limit":{"primary_window":
            {"limit_window_seconds":604800,"reset_at":1786345526}}}"#);
        let w = parse_usage(&body).unwrap_or_default();
        assert!(w.is_empty(), "a percentage-less window became a bar: {w:?}");
    }

    #[test]
    fn reads_reset_credits_and_keeps_the_two_counts_apart() {
        let r = parse_reset_credits(&v(PLUS_ZERO)).unwrap();
        assert_eq!(r.available, 1);
        assert_eq!(r.applicable, 0);
    }

    /// Zero credits is silence, not a line reading "0" — the same treatment
    /// `parse_credit` gives an account with no spending limit.
    #[test]
    fn zero_reset_credits_is_absent_rather_than_a_zero() {
        assert_eq!(parse_reset_credits(&v(FREE_ZERO)), None);
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
