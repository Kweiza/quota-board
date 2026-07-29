use crate::model::{AccountState, UsageWindow};
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The seam that lets tests fast-forward time.
pub trait Clock: Clone + Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Clone)]
pub struct TestClock(Arc<Mutex<DateTime<Utc>>>);

impl TestClock {
    pub fn new(iso: &str) -> Self {
        Self(Arc::new(Mutex::new(iso.parse().expect("valid ISO-8601"))))
    }
    pub fn advance_secs(&self, secs: i64) {
        let mut t = self.0.lock().unwrap();
        *t += TimeDelta::seconds(secs);
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FailureKind {
    Network,
    UnknownShape,
    AuthExpired,
    /// invalid_grant. Permanently dead.
    AuthDead,
    SecretsLocked,
}

#[derive(Debug, Clone)]
pub struct PollPolicy {
    pub interval: TimeDelta,
    /// Stagger between accounts. Prevents a simultaneous burst at startup.
    pub stagger: TimeDelta,
}

impl PollPolicy {
    /// Spec §6.1. This floor is set by the 429 throttle, not by cost.
    pub const MIN_INTERVAL_SECS: i64 = 180;
    /// How long to back off after a `Retry-After: 0` (budget exhausted).
    ///
    /// **This is a measured value.** On 2026-07-29, a 90-minute run at a 60s
    /// interval showed 26 consecutive successes before 429s began, after which
    /// 200s and 429s alternated perfectly. That means the token bucket refills
    /// about one token every 120 seconds. The draft's original value of 3600s
    /// (one full sliding-window rotation) was wrong — at that value, a single
    /// 429 would leave the widget showing a stale value for an hour. Set to
    /// 180s to leave margin over the measured recovery time.
    pub const SATURATED_BACKOFF_SECS: i64 = 180;

    pub fn with_interval_secs(secs: i64) -> Self {
        Self {
            interval: TimeDelta::seconds(secs.max(Self::MIN_INTERVAL_SECS)),
            stagger: TimeDelta::seconds(15),
        }
    }
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self::with_interval_secs(300)
    }
}

/// How long an in-flight claim survives without `end_poll`. Comfortably above
/// the worst legitimate case (a 30-second refresh followed by a 30-second usage
/// fetch) and comfortably below the 180-second polling floor, so a reclaim can
/// never race the next scheduled poll for the same account.
pub const IN_FLIGHT_RECLAIM_SECS: i64 = 90;

struct Entry {
    next_due_at: DateTime<Utc>,
    backoff_level: u32,
    last_windows: Option<Vec<UsageWindow>>,
    last_fetched_at: Option<DateTime<Utc>>,
    last_failure: Option<FailureKind>,
    throttled_until: Option<DateTime<Utc>>,
    quarantined: bool,
    /// Set while a poll is running for this account. An `Option<DateTime>`
    /// rather than a `bool` because the driver can skip `end_poll` on a panic
    /// or an early return, and without a reclaim the account would then never
    /// be polled again. Judged against the injected clock, so the reclaim is
    /// itself testable without waiting.
    in_flight_since: Option<DateTime<Utc>>,
}

impl Entry {
    fn is_in_flight(&self, now: DateTime<Utc>) -> bool {
        self.in_flight_since
            .is_some_and(|t| now < t + TimeDelta::seconds(IN_FLIGHT_RECLAIM_SECS))
    }
}

pub struct Scheduler<C: Clock> {
    policy: PollPolicy,
    clock: C,
    entries: HashMap<String, Entry>,
    order: Vec<String>,
    visible: bool,
}

impl<C: Clock> Scheduler<C> {
    pub fn new(policy: PollPolicy, clock: C) -> Self {
        Self { policy, clock, entries: HashMap::new(), order: Vec::new(), visible: true }
    }

    pub fn add(&mut self, uuid: &str) {
        if self.entries.contains_key(uuid) {
            return;
        }
        // Stagger: the nth account is first polled n * stagger later.
        let offset = self.policy.stagger * self.order.len() as i32;
        self.entries.insert(
            uuid.to_string(),
            Entry {
                next_due_at: self.clock.now() + offset,
                backoff_level: 0,
                last_windows: None,
                last_fetched_at: None,
                last_failure: None,
                throttled_until: None,
                quarantined: false,
                in_flight_since: None,
            },
        );
        self.order.push(uuid.to_string());
    }

    pub fn remove(&mut self, uuid: &str) {
        self.entries.remove(uuid);
        self.order.retain(|x| x != uuid);
    }

    /// Widget visibility. On the false→true transition, every account
    /// becomes immediately due.
    pub fn set_visible(&mut self, visible: bool) {
        let becoming_visible = visible && !self.visible;
        self.visible = visible;
        if becoming_visible {
            let now = self.clock.now();
            for e in self.entries.values_mut() {
                if !e.quarantined && e.throttled_until.is_none_or(|t| t <= now) {
                    e.next_due_at = now;
                }
            }
        }
    }

    /// Accounts that should be polled right now. **At most one** — global
    /// concurrency of 1.
    pub fn due(&self) -> Vec<String> {
        if !self.visible {
            return Vec::new();
        }
        let now = self.clock.now();
        self.order
            .iter()
            .filter(|id| {
                self.entries.get(*id).is_some_and(|e| {
                    !e.quarantined
                        && e.throttled_until.is_none_or(|t| t <= now)
                        && e.next_due_at <= now
                        && !e.is_in_flight(now)
                })
            })
            .take(1)
            .cloned()
            .collect()
    }

    /// Claims the in-flight slot for this account. Returns false when a poll is
    /// already running, which is the caller's signal to return the current
    /// state instead of starting a second request.
    ///
    /// docs/design.md §6.1 requires a global concurrency of 1. `due()` upholds
    /// it for the polling loop via `.take(1)`, but manual refresh never goes
    /// through `due()` — this is what covers that path. An unknown uuid is
    /// refused too: there is nothing to poll.
    pub fn begin_poll(&mut self, uuid: &str) -> bool {
        let now = self.clock.now();
        match self.entries.get_mut(uuid) {
            Some(e) if !e.is_in_flight(now) => {
                e.in_flight_since = Some(now);
                true
            }
            _ => false,
        }
    }

    pub fn end_poll(&mut self, uuid: &str) {
        if let Some(e) = self.entries.get_mut(uuid) {
            e.in_flight_since = None;
        }
    }

    pub fn next_wake(&self, uuid: &str) -> Option<DateTime<Utc>> {
        self.entries.get(uuid).map(|e| e.next_due_at)
    }

    pub fn record_success(&mut self, uuid: &str, windows: Vec<UsageWindow>) {
        let now = self.clock.now();
        let interval = self.policy.interval;
        if let Some(e) = self.entries.get_mut(uuid) {
            e.last_windows = Some(windows);
            e.last_fetched_at = Some(now);
            e.last_failure = None;
            e.throttled_until = None;
            e.backoff_level = 0;
            e.next_due_at = now + interval;
        }
    }

    pub fn record_failure(&mut self, uuid: &str, kind: FailureKind) {
        let now = self.clock.now();
        let interval = self.policy.interval;
        if let Some(e) = self.entries.get_mut(uuid) {
            e.last_failure = Some(kind);
            if kind == FailureKind::AuthDead {
                // One-strike quarantine. Never retried.
                e.quarantined = true;
                return;
            }
            e.backoff_level = (e.backoff_level + 1).min(6);
            let factor = 1i32 << e.backoff_level; // 2, 4, 8, ... up to 64x
            e.next_due_at = now + interval * factor;
        }
    }

    /// Spec §6.2. `retry_after_secs == 0` means budget exhausted — sit out an
    /// entire window. `u64`, not `i64`, to line up with `UsageError::Throttled`
    /// — Task 12 made that field `u64` so a negative `Retry-After` cannot parse
    /// at all. The non-negative contract therefore holds by construction and
    /// there is nothing to clamp here.
    pub fn record_throttle(&mut self, uuid: &str, retry_after_secs: u64) {
        let now = self.clock.now();
        let wait = if retry_after_secs > 0 {
            // `Retry-After: N > 0` is a real countdown and must be obeyed
            // exactly (§6.2). Measured 2026-07-30: 300, then 299 one second
            // later. An earlier measurement saw only zeroes and nearly got this
            // branch deleted; applying the 180 s budget-exhausted backoff to a
            // 300 s block would return while it is still in force.
            TimeDelta::seconds(retry_after_secs as i64)
        } else {
            TimeDelta::seconds(PollPolicy::SATURATED_BACKOFF_SECS)
        };
        if let Some(e) = self.entries.get_mut(uuid) {
            e.throttled_until = Some(now + wait);
            e.next_due_at = now + wait;
        }
    }

    pub fn state(&self, uuid: &str) -> Option<AccountState> {
        let e = self.entries.get(uuid)?;
        let now = self.clock.now();

        if e.quarantined {
            return Some(AccountState::AuthDead);
        }
        if let Some(until) = e.throttled_until.filter(|t| *t > now) {
            return Some(AccountState::Throttled { until });
        }

        match (&e.last_windows, e.last_fetched_at) {
            (Some(w), Some(at)) => {
                // Failed, or past the staleness boundary: Stale.
                let too_old = now - at > self.policy.interval * 2;
                if e.last_failure.is_some() || too_old {
                    Some(AccountState::Stale { windows: w.clone(), fetched_at: at })
                } else {
                    Some(AccountState::Ok { windows: w.clone(), fetched_at: at })
                }
            }
            // Never succeeded yet — show the failure itself.
            _ => Some(match e.last_failure {
                None => AccountState::Loading,
                Some(FailureKind::Network) => AccountState::Network,
                Some(FailureKind::UnknownShape) => AccountState::UnknownShape,
                Some(FailureKind::AuthExpired) => AccountState::AuthExpired,
                Some(FailureKind::SecretsLocked) => AccountState::SecretsLocked,
                Some(FailureKind::AuthDead) => AccountState::AuthDead,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::UsageWindow;

    fn win(pct: f64) -> Vec<UsageWindow> {
        vec![UsageWindow {
            window_id: "five_hour".into(),
            label: "5h".into(),
            percent: pct,
            resets_at: Utc::now() + TimeDelta::hours(1),
            scope: None,
        }]
    }

    fn sched() -> (Scheduler<TestClock>, TestClock) {
        let clock = TestClock::new("2026-07-29T12:00:00Z");
        let s = Scheduler::new(PollPolicy::default(), clock.clone());
        (s, clock)
    }

    #[test]
    fn interval_below_the_floor_is_clamped() {
        let p = PollPolicy::with_interval_secs(30);
        assert_eq!(p.interval.num_seconds(), PollPolicy::MIN_INTERVAL_SECS);
    }

    #[test]
    fn a_new_account_is_due_immediately_and_starts_loading() {
        let (mut s, _c) = sched();
        s.add("a");
        assert_eq!(s.state("a"), Some(AccountState::Loading));
        assert_eq!(s.due(), vec!["a"]);
    }

    #[test]
    fn success_schedules_the_next_poll_one_interval_later() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(20.0));
        assert!(s.due().is_empty(), "just fetched, so wait");
        c.advance_secs(299);
        assert!(s.due().is_empty());
        c.advance_secs(2);
        assert_eq!(s.due(), vec!["a"], "due again once the interval passes");
    }

    /// Spec §6.1: stagger accounts to avoid a startup burst.
    #[test]
    fn accounts_are_staggered_so_startup_never_bursts() {
        let (mut s, _c) = sched();
        s.add("a");
        s.add("b");
        s.add("c");
        assert_eq!(s.due(), vec!["a"], "only one on the first tick");
    }

    /// Spec §6.1: global concurrency of 1.
    #[test]
    fn due_returns_at_most_one_account() {
        let (mut s, c) = sched();
        for id in ["a", "b", "c"] {
            s.add(id);
            s.record_success(id, win(10.0));
        }
        c.advance_secs(3600);
        assert_eq!(s.due().len(), 1);
    }

    /// Spec §7.2: an automatic polling failure quietly keeps the last value.
    #[test]
    fn failure_keeps_the_last_good_value_as_stale() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(42.0));
        c.advance_secs(400);
        s.record_failure("a", FailureKind::Network);
        match s.state("a").unwrap() {
            AccountState::Stale { windows, .. } => assert_eq!(windows[0].percent, 42.0),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// A failure with no previous value is not Stale — it's the failure itself.
    #[test]
    fn failure_without_a_previous_value_is_not_stale() {
        let (mut s, _c) = sched();
        s.add("a");
        s.record_failure("a", FailureKind::Network);
        assert_eq!(s.state("a"), Some(AccountState::Network));
    }

    /// Spec §6.2: Retry-After: 0 = budget exhausted. Back off by
    /// SATURATED_BACKOFF_SECS, which leaves margin over the measured recovery
    /// time (~120s), and don't probe before then.
    #[test]
    fn retry_after_zero_backs_off_by_the_measured_recovery_time() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_throttle("a", 0);
        c.advance_secs(PollPolicy::SATURATED_BACKOFF_SECS - 1);
        assert!(s.due().is_empty(), "don't probe before the recovery time");
        c.advance_secs(2);
        assert_eq!(s.due(), vec!["a"], "resume once the recovery time passes");
    }

    /// An excessive backoff like 3600s would kill the widget for an hour on a
    /// single 429. Measurement overturned that value, so this guards against
    /// regressing it.
    #[test]
    // SATURATED_BACKOFF_SECS is a const, so clippy sees this as an assertion
    // on a constant and suggests folding it into a `const { .. }` block. Kept
    // as a normal runtime assert instead: this is a regression guard, and a
    // named failing test in `cargo test` output is more informative than a
    // compile error pointing at a `const` block.
    #[allow(clippy::assertions_on_constants)]
    fn saturated_backoff_is_not_an_hour() {
        assert!(
            PollPolicy::SATURATED_BACKOFF_SECS <= 300,
            "the measured recovery time is about 120s; anything much larger has no basis"
        );
    }

    /// Spec §6.2: Retry-After: N > 0 = exactly N seconds.
    #[test]
    fn retry_after_n_sleeps_exactly_n() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_throttle("a", 120);
        c.advance_secs(119);
        assert!(s.due().is_empty());
        c.advance_secs(2);
        assert_eq!(s.due(), vec!["a"]);
    }

    #[test]
    fn repeated_failures_back_off_exponentially_and_reset_on_success() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(1.0));
        let mut waits = vec![];
        for _ in 0..3 {
            c.advance_secs(10_000);
            s.due();
            s.record_failure("a", FailureKind::Network);
            waits.push(s.next_wake("a").unwrap() - c.now());
        }
        assert!(waits[1] > waits[0] && waits[2] > waits[1], "intervals must grow: {waits:?}");
        c.advance_secs(10_000);
        s.due();
        s.record_success("a", win(1.0));
        let after = s.next_wake("a").unwrap() - c.now();
        assert!(after <= PollPolicy::default().interval, "success resets the backoff");
    }

    /// Spec §6.3: no polling while not visible.
    #[test]
    fn hidden_widget_produces_no_work() {
        let (mut s, c) = sched();
        s.add("a");
        s.set_visible(false);
        c.advance_secs(10_000);
        assert!(s.due().is_empty());
    }

    /// Spec §6.3: becoming visible again refreshes everything immediately.
    #[test]
    fn becoming_visible_makes_everything_due_at_once() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(5.0));
        s.set_visible(false);
        c.advance_secs(60);
        s.set_visible(true);
        assert_eq!(s.due(), vec!["a"], "refresh immediately regardless of how long it was hidden");
    }

    /// Spec §7.2: invalid_grant is one-strike quarantine. Never polled again.
    #[test]
    fn auth_dead_is_quarantined_forever() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_failure("a", FailureKind::AuthDead);
        assert_eq!(s.state("a"), Some(AccountState::AuthDead));
        c.advance_secs(100_000);
        assert!(s.due().is_empty(), "a quarantined account is never polled again");
    }

    /// Spec §7: accounts are independent of each other.
    #[test]
    fn one_account_failing_does_not_affect_another() {
        let (mut s, c) = sched();
        s.add("a");
        s.add("b");
        s.record_failure("a", FailureKind::AuthDead);
        c.advance_secs(1000);
        assert_eq!(s.due(), vec!["b"]);
        assert!(matches!(s.state("b"), Some(AccountState::Loading)));
    }

    /// Spec §7.3: twice the polling interval is the staleness boundary.
    #[test]
    fn value_goes_stale_after_twice_the_interval() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(30.0));
        c.advance_secs(599);
        assert!(matches!(s.state("a"), Some(AccountState::Ok { .. })));
        c.advance_secs(2);
        assert!(matches!(s.state("a"), Some(AccountState::Stale { .. })));
    }

    #[test]
    fn removing_an_account_forgets_it_entirely() {
        let (mut s, _c) = sched();
        s.add("a");
        s.remove("a");
        assert_eq!(s.state("a"), None);
        assert!(s.due().is_empty());
    }

    /// Spec §6.1 "global concurrency of 1". `due()` only upholds that for the
    /// polling loop, and manual refresh bypasses `due()`, so the guarantee has
    /// to live above the entry point.
    #[test]
    fn a_second_poll_cannot_start_while_one_is_in_flight() {
        let (mut s, _c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"), "the first request must succeed");
        assert!(!s.begin_poll("a"), "the second request must be refused");
        assert!(s.due().is_empty(), "an in-flight account must not show up in due");
        s.end_poll("a");
        assert!(s.begin_poll("a"), "after end_poll it must be claimable again");
    }

    /// If the driver panics or returns early, `end_poll` never runs. Without a
    /// reclaim, that account would never be polled again.
    #[test]
    fn an_in_flight_slot_is_reclaimed_after_the_timeout() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        c.advance_secs(IN_FLIGHT_RECLAIM_SECS - 1);
        assert!(!s.begin_poll("a"), "still claimed just before the deadline");
        c.advance_secs(2);
        assert!(s.begin_poll("a"), "reclaimed once the deadline passes");
    }
}
