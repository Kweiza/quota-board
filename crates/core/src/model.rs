use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One normalized usage window. The 5-hour window, the flat 7-day window, and
/// per-model weekly windows are all represented by this single type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageWindow {
    /// Stable identifier. "five_hour" | "seven_day" | "weekly:<model>"
    pub window_id: String,
    /// Label displayed verbatim in the UI. "5h" | "7d" | "weekly (Opus)"
    pub label: String,
    /// Always 0-100. Whatever unit convention the response used, here it is a percentage.
    pub percent: f64,
    pub resets_at: DateTime<Utc>,
    /// Display name of the model for per-model weekly windows. None otherwise.
    pub scope: Option<String>,
}

/// The monthly credit spend, for an account that has a spending limit.
///
/// **Money stays in minor units.** The endpoint sends `{amount_minor, currency,
/// exponent}` and never a decimal, so widening to `f64` here would round a value
/// the UI then prints as an exact amount.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreditSpend {
    /// Spent this month, in minor units (cents at `exponent` 2).
    pub used_minor: i64,
    /// The monthly spend limit, same units. Always > 0 — see `parse_credit`.
    pub limit_minor: i64,
    /// ISO-4217 code, e.g. "USD". Both amounts are in this currency.
    pub currency: String,
    /// Minor-unit scale: 2 means `amount_minor` counts cents.
    pub exponent: u32,
    /// `used_minor / limit_minor` as a percentage. **Not the endpoint's own
    /// `spend.percent`**, and that is a deliberate divergence — see
    /// `usage::parse::parse_credit`, which carries the measurement.
    ///
    /// **May exceed 100.** Spending past the limit is exactly what this line
    /// exists to show, so no clamp happens here; the bar clamps when it draws.
    pub percent: f64,
}

/// Spec §7.1. All of these are user-visible states.
///
/// **The serialized form must match the `AccountState` union in
/// `src/lib/types.ts` exactly.** `tag = "kind"` plus snake_case is that
/// contract.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccountState {
    /// Right after the account is added, before the first fetch.
    Loading,
    /// `credit` is `None` for an account with no spending limit, which is the
    /// normal case — it is not a failure and renders as no credit line at all.
    /// Never a zero: see `usage::parse::parse_credit`.
    Ok {
        windows: Vec<UsageWindow>,
        credit: Option<CreditSpend>,
        fetched_at: DateTime<Utc>,
    },
    /// Automatic polling failed but the last known value is kept. **Never
    /// render without its age.**
    Stale {
        windows: Vec<UsageWindow>,
        credit: Option<CreditSpend>,
        fetched_at: DateTime<Utc>,
    },
    Throttled { until: DateTime<Utc> },
    /// Access token expired, refresh in progress.
    AuthExpired,
    /// invalid_grant. Only re-login fixes this.
    AuthDead,
    /// This account's Anthropic organization has OAuth turned off.
    ///
    /// Permanent like `AuthDead`, but **its remedy is different and that is why
    /// it is not `AuthDead`**: re-logging in cannot help, because the grant
    /// would be refused again. Offering the one affordance that cannot work is
    /// the confusing failure §7.1 exists to prevent. Only an administrator of
    /// that organization can clear it, which is an action this application
    /// cannot take and must not pretend to offer.
    OrgOauthDisabled,
    SecretsLocked,
    /// The response could not be parsed. **Not 0%.**
    UnknownShape,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Green,
    Cyan,
    Yellow,
    Red,
}

impl Severity {
    /// The same thresholds existing terminal statusline tools use. See docs/design.md §8.2.
    pub fn from_percent(percent: f64) -> Self {
        if percent >= 90.0 {
            Severity::Red
        } else if percent >= 70.0 {
            Severity::Yellow
        } else if percent >= 40.0 {
            Severity::Cyan
        } else {
            Severity::Green
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_boundaries_are_inclusive_at_the_lower_edge() {
        assert_eq!(Severity::from_percent(0.0), Severity::Green);
        assert_eq!(Severity::from_percent(39.9), Severity::Green);
        assert_eq!(Severity::from_percent(40.0), Severity::Cyan);
        assert_eq!(Severity::from_percent(69.9), Severity::Cyan);
        assert_eq!(Severity::from_percent(70.0), Severity::Yellow);
        assert_eq!(Severity::from_percent(89.9), Severity::Yellow);
        assert_eq!(Severity::from_percent(90.0), Severity::Red);
        assert_eq!(Severity::from_percent(100.0), Severity::Red);
    }
}
