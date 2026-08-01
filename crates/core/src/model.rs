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
    /// The server is refusing OAuth for this account **right now**.
    ///
    /// Distinct from `AuthExpired` because the token is fine: a refresh
    /// succeeds and the next poll is refused identically, so `AUTH_EXPIRED`'s
    /// "refreshing…" is a spinner that never resolves — the waiting-shaped
    /// permanent failure §7.1 exists to separate.
    ///
    /// Distinct from `AuthDead` because **it is not permanent**, which is the
    /// part an earlier revision of this enum got wrong. The wire code names an
    /// organization (`oauth_not_allowed_for_organization`), but the one case
    /// observed was a **lapsed subscription** on an ordinary personal account,
    /// and the server's own message says "currently". So the account recovers
    /// on its own when whatever caused it is resolved, and this state must be
    /// retried rather than quarantined — a quarantine would keep showing the
    /// error after the user had already fixed it, with removing and re-adding
    /// the account as the only way out.
    ///
    /// It still wins over a cached reading. A dimmed old percentage with an age
    /// implies "we could not reach the server just now"; this is the server
    /// telling us plainly that it will not serve this account, and last week's
    /// number is not a useful answer to that.
    OauthNotAllowed,
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
