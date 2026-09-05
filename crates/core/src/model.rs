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
    /// Whether this window covers **seven days**. Set by the parser that read
    /// the response, which is the only place the fact is actually known, and
    /// never re-derived from `window_id` or `label` downstream.
    ///
    /// Two things make the string tests it replaces wrong rather than merely
    /// ugly. On the Anthropic side `weekly:<model>` and `seven_day` are weekly
    /// by construction, but the label of the first is "weekly (Opus)", so a
    /// test for "7d" misses it. On the Codex side the weekly window is
    /// `secondary`, and `secondary` is **not** always seven days: the duration
    /// comes from `limit_window_seconds`, and
    /// `codex_free_plan_labels_the_secondary_window_from_its_own_duration`
    /// pins a free account whose secondary window is not a week. A name-based
    /// test would call that window weekly and sort the account by a reset it
    /// does not have — the confidently-wrong display AGENTS.md forbids.
    ///
    /// `#[serde(default)]` because `snapshots::CachedSnapshot` writes these to
    /// disk: without it, every cache written before this field existed fails
    /// to parse, and `snapshots::load` turns that into an empty cache without
    /// a word, so the first launch after an upgrade would lose every stale
    /// value the cache exists to keep. False on such a window is the honest
    /// reading — the fact was not recorded — and §8.6's auto sort already
    /// places a window it cannot date last rather than guessing at one.
    #[serde(default)]
    pub weekly: bool,
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
    /// `usage::anthropic::parse_credit`, which carries the measurement.
    ///
    /// **May exceed 100.** Spending past the limit is exactly what this line
    /// exists to show, so no clamp happens here; the bar clamps when it draws.
    pub percent: f64,
}

/// Codex's rate-limit reset credits.
///
/// **Not `CreditSpend`.** That type is money, with a limit and a percentage of
/// it consumed. This is a count of one-shot resets, and it has no limit and no
/// percentage — modelling it as money would put a meaningless denominator on
/// screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetCredits {
    /// Reset credits on the account.
    pub available: u32,
    /// The subset applicable to the limit currently in force, when the
    /// service reports it.
    ///
    /// **Measured 0 while `available` was 1** (Spike F), so the two are not
    /// interchangeable: an account can hold a credit that does nothing for the
    /// limit it is actually hitting.
    ///
    /// Current official responses may carry only `available_count`. `None`
    /// preserves that absence; it must never be rendered as a confident zero.
    pub applicable: Option<u32>,
}

/// The one optional line a row may carry under its bars.
///
/// An enum rather than two `Option` fields because the two are mutually
/// exclusive *per provider* — an Anthropic account has no reset credits and a
/// Codex account has no monthly spend. The enum makes that a fact the type
/// system holds rather than a convention a reader has to know.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtraLine {
    Credit(CreditSpend),
    ResetCredits(ResetCredits),
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
    /// `extra` is `None` for an account with nothing to show under its bars —
    /// an Anthropic account with no spending limit, or a Codex account with no
    /// reset credits. Both are the normal case and render as no line at all.
    /// Never a zero: see `usage::anthropic::parse_credit` and
    /// `usage::openai::parse_reset_credits`.
    Ok {
        windows: Vec<UsageWindow>,
        extra: Option<ExtraLine>,
        fetched_at: DateTime<Utc>,
    },
    /// Automatic polling failed but the last known value is kept. **Never
    /// render without its age.**
    Stale {
        windows: Vec<UsageWindow>,
        extra: Option<ExtraLine>,
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

/// The soonest seven-day reset this account has, or `None` when it has none.
///
/// `None` is a real answer, not a zero: an account that is `LOADING`, throttled
/// or unreadable has no seven-day reset to be ordered by, and neither does a
/// Codex account whose plan reports no weekly window at all (§5.3 says the
/// count is 0, 1 or N — never assumed). `by_weekly_reset` puts every such
/// account after the ones it can date instead of inventing a timestamp for it.
///
/// `Stale` counts. The reading is old, but the *reset instant* it carries is a
/// fact about the week, not about the fetch, so dropping a stale account to the
/// bottom would reorder the widget on every transient network failure.
pub fn weekly_reset(state: &AccountState) -> Option<DateTime<Utc>> {
    let windows = match state {
        AccountState::Ok { windows, .. } | AccountState::Stale { windows, .. } => windows.as_slice(),
        _ => &[],
    };
    // `min`, not `first`: an Anthropic account reports one weekly window per
    // model (§5.3), and the one that matters to "how long have I got" is
    // whichever comes back soonest.
    windows.iter().filter(|w| w.weekly).map(|w| w.resets_at).min()
}

/// docs/design.md §8.6's auto sort: soonest seven-day reset first, accounts
/// with no datable weekly window last.
///
/// **Stable, and that is the whole reason it is `sort_by_key` rather than a
/// comparison that ranks the undatable accounts among themselves.** Ties and
/// unknowns keep the order they arrived in, which is the user's own
/// `sort_order` — so turning the toggle off restores exactly the manual
/// arrangement, and the accounts this function cannot rank do not shuffle on
/// every poll.
///
/// The `is_none()` in the key is what puts them last: `Option`'s own ordering
/// sorts `None` *before* `Some`, which would bury the account the user most
/// needs to see under every account this function knows nothing about.
pub fn by_weekly_reset<T>(items: &mut [T], state: impl Fn(&T) -> &AccountState) {
    items.sort_by_key(|item| {
        let reset = weekly_reset(state(item));
        (reset.is_none(), reset)
    });
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

    /// The serialized form is a contract with `src/lib/types.ts`. `tag = "kind"`
    /// plus snake_case on the outside, and an internally tagged `extra` whose own
    /// tag the TypeScript union switches on.
    fn win(id: &str, weekly: bool, resets_at: &str) -> UsageWindow {
        UsageWindow {
            window_id: id.to_string(),
            label: id.to_string(),
            percent: 10.0,
            resets_at: resets_at.parse().unwrap(),
            scope: None,
            weekly,
        }
    }

    fn ok(windows: Vec<UsageWindow>) -> AccountState {
        AccountState::Ok {
            windows,
            extra: None,
            fetched_at: "2026-09-05T00:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn weekly_reset_ignores_windows_that_are_not_weekly() {
        // The 5h window resets far sooner. Reading it here is the whole defect
        // the `weekly` flag exists to prevent: every account would then sort by
        // a bar that turns over five times a day.
        let state = ok(vec![
            win("five_hour", false, "2026-09-05T01:00:00Z"),
            win("seven_day", true, "2026-09-09T00:00:00Z"),
        ]);
        assert_eq!(weekly_reset(&state), Some("2026-09-09T00:00:00Z".parse().unwrap()));
    }

    #[test]
    fn weekly_reset_takes_the_soonest_of_several_per_model_weeks() {
        let state = ok(vec![
            win("weekly:Opus", true, "2026-09-11T00:00:00Z"),
            win("weekly:Sonnet", true, "2026-09-07T00:00:00Z"),
            win("weekly:Fable", true, "2026-09-09T00:00:00Z"),
        ]);
        assert_eq!(weekly_reset(&state), Some("2026-09-07T00:00:00Z".parse().unwrap()));
    }

    #[test]
    fn weekly_reset_is_none_when_no_window_is_weekly() {
        // A Codex plan that reports only a short window. Not a zero, not the
        // 5h reset standing in for one: there is no weekly reset to report.
        assert_eq!(weekly_reset(&ok(vec![win("primary", false, "2026-09-05T01:00:00Z")])), None);
        assert_eq!(weekly_reset(&ok(vec![])), None);
    }

    #[test]
    fn weekly_reset_reads_a_stale_reading_but_not_a_stateless_one() {
        let windows = vec![win("seven_day", true, "2026-09-09T00:00:00Z")];
        let stale = AccountState::Stale {
            windows: windows.clone(),
            extra: None,
            fetched_at: "2026-09-01T00:00:00Z".parse().unwrap(),
        };
        assert_eq!(weekly_reset(&stale), Some("2026-09-09T00:00:00Z".parse().unwrap()));
        // Every state that carries no windows at all answers None rather than
        // being ranked by something borrowed from elsewhere.
        assert_eq!(weekly_reset(&AccountState::Loading), None);
        assert_eq!(weekly_reset(&AccountState::AuthDead), None);
        assert_eq!(
            weekly_reset(&AccountState::Throttled {
                until: "2026-09-05T02:00:00Z".parse().unwrap()
            }),
            None
        );
    }

    #[test]
    fn by_weekly_reset_orders_soonest_first_and_undatable_last() {
        let mut items = vec![
            ("far", ok(vec![win("seven_day", true, "2026-09-11T00:00:00Z")])),
            ("unknown-a", AccountState::Loading),
            ("near", ok(vec![win("seven_day", true, "2026-09-06T00:00:00Z")])),
            ("unknown-b", ok(vec![win("primary", false, "2026-09-05T01:00:00Z")])),
            ("mid", ok(vec![win("seven_day", true, "2026-09-08T00:00:00Z")])),
        ];
        by_weekly_reset(&mut items, |(_, state)| state);
        assert_eq!(
            items.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            // "unknown-a" precedes "unknown-b" because it did before the sort:
            // the two are unrankable, so the user's own order survives.
            vec!["near", "mid", "far", "unknown-a", "unknown-b"]
        );
    }

    /// **The shape of this input is what gives the test teeth, and both halves
    /// of it are load-bearing.** Two earlier versions passed against
    /// `sort_unstable_by_key`: three accounts, because Rust's unstable sort is
    /// insertion sort below about twenty elements and incidentally stable
    /// there; then forty accounts all sharing one reset, because pdqsort
    /// recognises an all-equal slice and leaves it alone. Only a long list with
    /// *several* groups actually partitions, and an unstable partition is what
    /// shuffles the accounts inside each group.
    #[test]
    fn by_weekly_reset_keeps_the_manual_order_of_accounts_that_tie() {
        let resets = ["2026-09-10T00:00:00Z", "2026-09-06T00:00:00Z", "2026-09-08T00:00:00Z"];
        let names: Vec<String> = (0..60).map(|i| format!("account-{i:02}")).collect();
        let mut items: Vec<(&str, AccountState)> = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                (name.as_str(), ok(vec![win("seven_day", true, resets[i % resets.len()])]))
            })
            .collect();
        by_weekly_reset(&mut items, |(_, state)| state);

        // Group by reset, soonest first, and inside each group the accounts
        // must still be in the order the user arranged them.
        let sorted: Vec<&str> = items.iter().map(|(name, _)| *name).collect();
        let expected: Vec<&str> = [1usize, 2, 0]
            .into_iter()
            .flat_map(|group| {
                names
                    .iter()
                    .enumerate()
                    .filter(move |(i, _)| i % resets.len() == group)
                    .map(|(_, name)| name.as_str())
            })
            .collect();
        assert_eq!(
            sorted, expected,
            "a stable sort is what lets the toggle be turned off without losing the manual order"
        );
    }

    #[test]
    fn extra_line_serializes_as_the_typescript_union_expects() {
        let credit = ExtraLine::Credit(CreditSpend {
            used_minor: 2231,
            limit_minor: 2000,
            currency: "USD".into(),
            exponent: 2,
            percent: 111.55,
        });
        let v = serde_json::to_value(&credit).unwrap();
        assert_eq!(v["kind"], "credit");
        assert_eq!(v["used_minor"], 2231);

        let resets = ExtraLine::ResetCredits(ResetCredits {
            available: 1,
            applicable: Some(0),
        });
        let v = serde_json::to_value(&resets).unwrap();
        assert_eq!(v["kind"], "reset_credits");
        assert_eq!(v["available"], 1);
        assert_eq!(v["applicable"], 0);

        let unknown = ExtraLine::ResetCredits(ResetCredits {
            available: 3,
            applicable: None,
        });
        let v = serde_json::to_value(&unknown).unwrap();
        assert!(v["applicable"].is_null());
    }
}
