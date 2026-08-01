use crate::accounts::{Account, AccountError, AccountStore};
use crate::auth::stored::StoredTokenError;
use crate::auth::token::AuthError;
use crate::model::{AccountState, CreditSpend, UsageWindow};
use crate::secrets::SecretError;
use crate::snapshots::CachedSnapshot;
use crate::usage::http::UsageError;
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
    /// The organization disabled OAuth. Permanent, and unlike `AuthDead` a
    /// re-login does not fix it.
    OrgOauthDisabled,
}

/// The classification of the two error types a poll can produce lives here, in
/// one place, because docs/design.md §4.1 gives `scheduler` "failure
/// classification" and because the alternative is every caller re-deriving it.
/// The wiring that joins `auth::stored`, `usage::http` and this module is the
/// first such caller, and there is no reason for it to invent these semantics.
///
/// **Both matches are written exhaustively, arm by arm.** A `_ =>` catch-all
/// would give any error variant added later a silent, probably wrong
/// classification; as written, adding one is a compile error here first.
impl FailureKind {
    /// `None` means "this is not a `record_failure`". `Throttled` carries a
    /// wait, so it routes to `record_throttle` instead — folding it in here
    /// would discard the `Retry-After` that §6.2 makes the entire input to the
    /// throttle policy.
    pub fn from_usage_error(err: &UsageError) -> Option<Self> {
        match err {
            UsageError::Throttled { .. } => None,
            // The access token was rejected. §7.1's `AUTH_EXPIRED` — a refresh
            // is the remedy, and `auth::stored` performs it on the next poll.
            UsageError::Unauthorized => Some(FailureKind::AuthExpired),
            // Not `AuthExpired`: that state renders as "refreshing…" and waits
            // for a refresh to rescue it. The token here is fine, so the
            // refresh succeeds and the next poll gets the same 403 — a spinner
            // that never resolves, which is the display §7.1 calls out by name.
            UsageError::OrgOauthDisabled => Some(FailureKind::OrgOauthDisabled),
            UsageError::UnknownShape => Some(FailureKind::UnknownShape),
            UsageError::Transport(_) => Some(FailureKind::Network),
            // **A 5xx is not a network error, and calling it one is a
            // deliberate simplification, not an oversight.** §7.1 defines
            // `NETWORK` by how it renders — "treated the same as `STALE`" — and
            // keeping the last value with its age is the correct rendering for
            // any fetch that failed without telling us the credential is bad.
            // The honest alternative would be a sixth state whose display is
            // identical to two existing ones.
            UsageError::Status(_) => Some(FailureKind::Network),
        }
    }

    /// Total, unlike the usage mapping: every stored-token failure is a
    /// `record_failure`.
    pub fn from_stored_token_error(err: &StoredTokenError) -> Self {
        match err {
            // §9.2: `NOT_FOUND` means the account needs a re-login, not a
            // retry. `Corrupt` lands here too — an unreadable blob is not a
            // credential we can refresh our way out of, and routing either to
            // `AUTH_EXPIRED` renders a permanent spinner where §7.1 promises a
            // clickable "re-login required".
            StoredTokenError::Missing | StoredTokenError::Corrupt => FailureKind::AuthDead,
            StoredTokenError::Secrets(e) => match e {
                // §9.2 makes `LOCKED` first-class: the only remedy it carries
                // is the "unlock" affordance.
                SecretError::Locked(_) => FailureKind::SecretsLocked,
                // `NO_BACKEND` is handled by falling back to the encrypted file
                // store and is not supposed to reach an account state at all;
                // `Backend` is usually transient; `TooLong` is permanent but
                // has no state of its own. All three render as "the last value
                // with its age", which is `NETWORK`.
                SecretError::NoBackend(_) | SecretError::Backend(_) | SecretError::TooLong { .. } => {
                    FailureKind::Network
                }
            },
            StoredTokenError::Auth(e) => match e {
                // §10.5: one strike, then quarantine.
                AuthError::OAuth { .. } if e.is_dead_grant() => FailureKind::AuthDead,
                // A transport failure is not an auth failure. Classifying it as
                // one would eventually quarantine an account over a flaky link.
                AuthError::Transport(_) => FailureKind::Network,
                AuthError::OAuth { .. } | AuthError::StateMismatch | AuthError::Decode(_) => {
                    FailureKind::AuthExpired
                }
            },
        }
    }
}

/// Constructed only through [`PollPolicy::with_interval_secs`].
///
/// **The fields are private on purpose.** While they were public,
/// `PollPolicy { interval: TimeDelta::seconds(5), .. }` compiled, and the
/// 180-second floor — which is §5.2's throttle position expressed as a number,
/// not a tuning parameter — was advisory. A constructor that clamps is not a
/// floor if the struct can be built around it.
#[derive(Debug, Clone)]
pub struct PollPolicy {
    interval: TimeDelta,
    /// Stagger between accounts. Prevents a simultaneous burst at startup.
    stagger: TimeDelta,
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
    /// Upper bound on a server-supplied `Retry-After`. That header is
    /// externally controlled input reaching time arithmetic that panics on
    /// overflow, and past `i64::MAX` it wraps negative and defeats the throttle
    /// entirely — see `record_throttle`. An hour is far beyond any legitimate
    /// value; the largest ever observed is 300.
    pub const MAX_RETRY_AFTER_SECS: u64 = 3600;
    /// Upper bound on the polling interval. **Not a preference — two separate
    /// panics and one correctness rule.**
    ///
    /// (1) `TimeDelta::seconds` panics above `i64::MAX / 1000` and
    /// `with_interval_secs` calls it: measured on chrono 0.4.45,
    /// `PollPolicy::with_interval_secs(i64::MAX)` panics with "TimeDelta::
    /// seconds out of bounds" — inside `setup()`, before any window exists.
    /// (2) Even a value chrono accepts panics later: `Utc::now() +
    /// TimeDelta::seconds(i64::MAX / 1000)` panics, and `record_success` does
    /// exactly `now + interval` — on the task whose panic, per state.rs's own
    /// doc comment, "stops all polling for the life of the process".
    /// (3) One hour is the ceiling rather than one day because `state()` calls
    /// a value stale only past `interval * 2`: at a one-day interval a
    /// two-day-old percentage still renders as `Ok`, long after the 5-hour
    /// window it describes has rotated — the confidently-wrong-number failure
    /// CLAUDE.md names as the worst one. At one hour the staleness boundary is
    /// two hours, comfortably inside that window.
    ///
    /// Both bounds are reachable from a file a user can hand-edit, which is
    /// why they are structural rather than advisory — the same argument the
    /// struct doc above makes for the private fields.
    pub const MAX_INTERVAL_SECS: i64 = 3_600;

    /// The only way to set the interval, and it clamps to
    /// [`PollPolicy::MIN_INTERVAL_SECS`] ..= [`PollPolicy::MAX_INTERVAL_SECS`].
    pub fn with_interval_secs(secs: i64) -> Self {
        Self {
            interval: TimeDelta::seconds(
                secs.clamp(Self::MIN_INTERVAL_SECS, Self::MAX_INTERVAL_SECS),
            ),
            stagger: TimeDelta::seconds(15),
        }
    }

    pub fn interval(&self) -> TimeDelta {
        self.interval
    }

    pub fn stagger(&self) -> TimeDelta {
        self.stagger
    }
}

impl Default for PollPolicy {
    fn default() -> Self {
        Self::with_interval_secs(300)
    }
}

/// How long an in-flight claim survives without `end_poll`.
///
/// The worst legitimate poll is **150 seconds**, and every term comes from a
/// different module:
///
/// ```text
///   30s   one token request        (auth::token's 30-second timeout)
/// x  2    one invalid_scope retry  (auth::token::refresh, §10.5)
/// x  2    the CAS retry loop       (auth::stored::MAX_ATTEMPTS)
/// = 120s  worst-case refresh
/// + 30s   the usage fetch
/// = 150s
/// ```
///
/// An earlier value of 90 seconds was derived from "a 30-second refresh
/// followed by a 30-second usage fetch" — true of `auth::token::refresh` alone,
/// but wrong once `auth::stored` wraps it in a retry loop. **No review of any
/// single module could see that**, because no single module contains two of the
/// three multipliers; it is visible only with all of `auth::token`,
/// `auth::stored` and this file open at once. At 90 seconds the reclaim fires
/// while a first poll is still legitimately running and a second poll starts
/// for the same account, defeating §6.1's concurrency of 1 precisely when the
/// network is slow — the case the claim exists for.
///
/// 170 is above that 150-second worst case and still below the 180-second
/// polling floor, so a reclaim can never race the next scheduled poll.
pub const IN_FLIGHT_RECLAIM_SECS: i64 = 170;

/// Caps `record_failure`'s exponential backoff at 64x the polling interval.
/// Bounded rather than open-ended so the shift below stays inside `i32` and the
/// multiplication has a chance of being representable.
const MAX_BACKOFF_LEVEL: u32 = 6;

struct Entry {
    next_due_at: DateTime<Utc>,
    backoff_level: u32,
    last_windows: Option<Vec<UsageWindow>>,
    /// The credit spend from the last successful poll **of this process**.
    ///
    /// Deliberately absent from `CachedSnapshot`: a credit figure carries no
    /// reset date (measured — the endpoint has none, see
    /// `usage::parse::parse_credit`), so a snapshot restored across a month
    /// boundary would show last month's spend as this month's with no way to
    /// tell. Windows can be filtered on `resets_at`; this cannot, so it is not
    /// persisted at all and reappears on the first poll instead.
    last_credit: Option<CreditSpend>,
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
    /// When a poll was last *started* for this account, success or not. Read by
    /// `set_visible` and by `due()`, so that neither path can poll inside the
    /// §6.1 floor. `last_fetched_at` cannot serve here: it is set on success
    /// only, so an account that keeps failing would have no floor at all on the
    /// very paths most likely to be triggered repeatedly.
    last_attempt_at: Option<DateTime<Utc>>,
}

impl Entry {
    fn is_in_flight(&self, now: DateTime<Utc>) -> bool {
        self.in_flight_since
            .is_some_and(|t| now < t + TimeDelta::seconds(IN_FLIGHT_RECLAIM_SECS))
    }

    /// Moves this entry's next poll to the earliest moment §6.1 allows — or
    /// leaves it exactly where it is, when §7.2 or §6.2 says it must not be
    /// polled at all.
    ///
    /// Every pull-forward path goes through here: visibility (§6.3), the unlock
    /// remedy (§9.2) and a fresh registration (§10.3). The floor arithmetic
    /// below is the thing that must never be re-derived by a second caller, and
    /// there are now three of them.
    fn pull_forward(&mut self, now: DateTime<Utc>, floor: TimeDelta) {
        // §7.2's one strike and §6.2's server-ordered wait both outrank any
        // local reason to poll sooner.
        if self.quarantined || self.throttled_until.is_some_and(|t| t > now) {
            return;
        }
        // Pull the poll forward, but never inside §6.1's per-account floor.
        //
        // The floor is the whole reason this arithmetic is in one place. Three
        // callers reach it — §6.3's visibility flip, §9.2's unlock remedy and
        // §10.3's registration — and each of them is a plausible place for a
        // second author to write `next_due_at = now` instead.
        //
        // **The visibility caller is where that was measured.** Setting this to
        // `now` unconditionally let a widget that is hidden and shown every
        // five seconds poll every five seconds — the floor simply was not
        // enforced on this path — and it reset the failure backoff on every
        // flip. Focus changes and workspace switches are not rare deliberate
        // acts. `min` keeps §6.3's "refresh the moment it becomes visible"
        // intact for any realistic hidden duration, and the other two callers
        // inherit the same protection rather than restating it.
        let earliest = self.last_attempt_at.map_or(now, |t| t + floor);
        self.next_due_at = self.next_due_at.min(now.max(earliest));
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
                last_credit: None,
                last_fetched_at: None,
                last_failure: None,
                throttled_until: None,
                quarantined: false,
                in_flight_since: None,
                last_attempt_at: None,
            },
        );
        self.order.push(uuid.to_string());
    }

    pub fn remove(&mut self, uuid: &str) {
        self.entries.remove(uuid);
        self.order.retain(|x| x != uuid);
    }

    /// The policy the loop is **actually** running under. `get_settings` reads
    /// the interval back from here rather than from the settings file, so the
    /// window can never display a number the poll loop is not using — the same
    /// two-sources-disagree argument the `AccountView` doc comment in
    /// `src-tauri/src/commands.rs` already makes about `quarantined`.
    pub fn policy(&self) -> &PollPolicy {
        &self.policy
    }

    /// §6.1's "Configurable". Replaces the policy while the loop is running and
    /// re-anchors every account that has already been polled to the new
    /// interval.
    ///
    /// **The re-anchoring is the point, not a side effect.** `next_due_at` is
    /// written only by `record_success`, `record_failure` and `record_throttle`,
    /// so without it a user who lowers the interval from an hour to three
    /// minutes keeps waiting out the old hour — a setting that appears to do
    /// nothing, which is the two-sources-disagree hazard §7.1 exists to prevent.
    ///
    /// It recomputes exactly what `record_failure` would compute — the interval
    /// times the current backoff factor — so a settings change does not reset an
    /// exponential backoff earned against an unreachable network. Three
    /// exclusions, each pinned by a test: an account that has never been polled
    /// keeps `add()`'s startup stagger; a throttled account keeps the server's
    /// `Retry-After` (§6.2); a quarantined account has no schedule to move
    /// (§7.2).
    ///
    /// The floor cannot be crossed here: `with_interval_secs` is the only
    /// constructor and it clamps, and `due()` re-checks `last_attempt_at +
    /// MIN_INTERVAL_SECS` independently of the policy whatever is written here.
    pub fn set_policy(&mut self, policy: PollPolicy) {
        self.policy = policy;
        let now = self.clock.now();
        let interval = self.policy.interval;
        for e in self.entries.values_mut() {
            if e.quarantined || e.throttled_until.is_some_and(|t| t > now) {
                continue;
            }
            let Some(attempted) = e.last_attempt_at else { continue };
            let factor = 1i32 << e.backoff_level;
            e.next_due_at = interval
                .checked_mul(factor)
                .and_then(|wait| attempted.checked_add_signed(wait))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
        }
    }

    /// Widget visibility. On the false→true transition, every account
    /// becomes immediately due.
    pub fn set_visible(&mut self, visible: bool) {
        let becoming_visible = visible && !self.visible;
        self.visible = visible;
        if becoming_visible {
            self.pull_forward();
        }
    }

    /// Pulls every eligible account's next poll forward to the earliest moment
    /// §6.1 allows. Extracted from `set_visible` so the visibility path and the
    /// remedy path cannot drift; `Entry::pull_forward` holds the arithmetic and
    /// the two exclusions, so `make_due_now` cannot drift from either.
    fn pull_forward(&mut self) {
        let now = self.clock.now();
        let floor = TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS);
        for e in self.entries.values_mut() {
            e.pull_forward(now, floor);
        }
    }

    /// §9.2's unlock succeeded. Make every account due again as soon as §6.1
    /// allows.
    ///
    /// **Without this the remedy works and the display does not change.** A
    /// store answering `LOCKED` drives `record_failure(SecretsLocked)` on every
    /// tick, and that doubles `next_due_at` up to `MAX_BACKOFF_LEVEL` — 64x,
    /// over five hours at the 300-second default.
    ///
    /// **`backoff_level` and `last_failure` are deliberately left alone.**
    /// Clearing `last_failure` would promote a row that has not been re-fetched:
    /// measured, an account whose last success was ten seconds before a
    /// `SecretsLocked` failure jumps straight to `AccountState::Ok` with a stale
    /// `fetched_at`, un-dimming a row §7.1 requires to be dimmed. It buys
    /// nothing either — an account carrying any backoff last attempted at least
    /// one interval ago, so the pull-forward alone makes it due on the next
    /// 5-second tick. `record_success` clears both on the first poll that works.
    /// §7.2's quarantine is untouched: `pull_forward` skips `e.quarantined`.
    pub fn retry_all_now(&mut self) {
        self.pull_forward();
    }

    /// §10.3. One named account — the one the user just registered — becomes
    /// due as soon as §6.1 allows, instead of waiting out `add`'s startup
    /// stagger.
    ///
    /// **Single-account rather than a variant of `retry_all_now`, because the
    /// stagger has to survive.** §6.1 asks for the stagger at startup, and the
    /// jitter note under it explains why it also has to persist: each account
    /// is anchored to its own last fetch, so accounts that start staggered stay
    /// de-synchronised without a randomness source the injected clock could not
    /// model. Pulling every account forward here would flatten that. One
    /// deliberate registration is neither of those cases — after its first poll
    /// the new account anchors to its own fetch time and lands de-synchronised
    /// anyway — while `add`'s offset made it wait: measured, the third account
    /// added through the settings window sat on `Loading` for 30 seconds and
    /// the fourth for 45. A re-login is worse still: it is §7.2's remedy, the
    /// user is watching, and `remove` + `add` rebuilds the entry at the end of
    /// `order`, so it inherits the largest offset of all.
    ///
    /// **§6.1's floor is not loosened here.** `Entry::pull_forward` re-applies
    /// it and `due()` re-checks it independently. A freshly registered account
    /// is due immediately only because `add` builds the entry with
    /// `last_attempt_at: None` and it has therefore never been polled — that is
    /// pre-existing behaviour of `add`, not something this method relaxes.
    ///
    /// **A nudge, not a remedy.** `backoff_level`, `last_failure` and
    /// `throttled_until` are untouched, so a server-ordered `Retry-After` still
    /// wins (§6.2) and a row §7.1 requires to stay dimmed is not promoted — the
    /// same reasoning `retry_all_now` records. §7.2's quarantine is skipped for
    /// the same reason: on the only call path there is,
    /// `register_authenticated` has already cleared the quarantine before it
    /// gets here, so that exclusion is defence in depth against a future caller
    /// rather than a case this one can reach.
    pub fn make_due_now(&mut self, uuid: &str) {
        let now = self.clock.now();
        let floor = TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS);
        if let Some(e) = self.entries.get_mut(uuid) {
            e.pull_forward(now, floor);
        }
    }

    /// Accounts that should be polled right now. **At most one** — global
    /// concurrency of 1.
    pub fn due(&self) -> Vec<String> {
        if !self.visible {
            return Vec::new();
        }
        let now = self.clock.now();
        let floor = TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS);
        self.order
            .iter()
            .filter(|id| {
                self.entries.get(*id).is_some_and(|e| {
                    !e.quarantined
                        && e.throttled_until.is_none_or(|t| t <= now)
                        && e.next_due_at <= now
                        && !e.is_in_flight(now)
                        // §6.1's floor, made structural rather than a driver
                        // obligation. `next_due_at` only ever moves in
                        // `record_success`/`record_failure`/`record_throttle`,
                        // so a driver that calls `begin_poll`, hits an error and
                        // calls `end_poll` without recording an outcome leaves
                        // the account immediately due again — a continuous
                        // hammer on the usage endpoint at loop speed. That is
                        // an easy path for a caller to take, so the floor is
                        // enforced here instead of being asked for.
                        && e.last_attempt_at.is_none_or(|t| now >= t + floor)
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
                e.last_attempt_at = Some(now);
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

    /// `credit` is overwritten on every success, `None` included: an account
    /// whose spending limit was removed must lose its credit line, not keep the
    /// last figure it ever reported.
    pub fn record_success(
        &mut self,
        uuid: &str,
        windows: Vec<UsageWindow>,
        credit: Option<CreditSpend>,
    ) {
        let now = self.clock.now();
        let interval = self.policy.interval;
        if let Some(e) = self.entries.get_mut(uuid) {
            e.last_windows = Some(windows);
            e.last_credit = credit;
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
            // Both are permanent, so both quarantine on the first strike. They
            // differ only in what the user is told and offered.
            if kind == FailureKind::AuthDead || kind == FailureKind::OrgOauthDisabled {
                // One-strike quarantine. Never retried.
                e.quarantined = true;
                return;
            }
            e.backoff_level = (e.backoff_level + 1).min(MAX_BACKOFF_LEVEL);
            let factor = 1i32 << e.backoff_level; // 2, 4, 8, ... up to 64x
            // `TimeDelta`'s `Mul` and `DateTime`'s `Add` both **panic** on
            // overflow, and the interval is caller-supplied. Saturating is the
            // right answer rather than a cap chosen out of the air: a wait that
            // cannot be represented is already unreachably far away, and a
            // panic in the polling loop takes the whole widget down.
            e.next_due_at = interval
                .checked_mul(factor)
                .and_then(|wait| now.checked_add_signed(wait))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
        }
    }

    /// Restores a snapshot cached to disk **with the age it actually has**.
    ///
    /// docs/design.md §7.4 requires the cached snapshot to be shown as `STALE`
    /// after a restart, and §7.1 forbids rendering a stale value without its
    /// age. `record_success` cannot serve: it stamps `last_fetched_at` from the
    /// clock, so restoring through it would render a real value with a
    /// fabricated zero-second age — the confidently-wrong-number failure this
    /// project treats as its worst, applied to the age instead of the
    /// percentage. §4.1 assigns "snapshot retention" to this module, so the
    /// entry point belongs here rather than in the wiring.
    ///
    /// Deliberately does **not** touch `next_due_at`. Restoring a cache is not
    /// a poll and must neither delay the first one nor pull it forward.
    pub fn seed(&mut self, uuid: &str, windows: Vec<UsageWindow>, fetched_at: DateTime<Utc>) {
        if let Some(e) = self.entries.get_mut(uuid) {
            e.last_windows = Some(windows);
            // A restored snapshot carries no credit — see `Entry::last_credit`.
            // Cleared rather than left alone so a re-seed cannot strand a figure
            // from an earlier poll beside a much older `fetched_at`.
            e.last_credit = None;
            e.last_fetched_at = Some(fetched_at);
            // §7.4: a restored snapshot reads as STALE until the first poll of
            // this process confirms it, regardless of age. Without this a
            // restart inside 2x the interval renders the cached number as a
            // live value (measured: a 60-second-old seed returns `Ok`, because
            // `state()` only calls a value stale past `interval * 2` — its
            // `too_old` check). `next_due_at` and `backoff_level` are still
            // untouched: restoring a cache is not a poll.
            e.last_failure = Some(FailureKind::Network);
        }
    }

    /// §7.4 + §9.3. Restores a cached snapshot, or does nothing.
    ///
    /// Delegates to `seed` on purpose. A second entry point that also wrote
    /// `next_due_at = now` was measured to flatten the startup stagger `add()`
    /// installs: with three accounts the wake times went from 12:00:00 /
    /// 12:00:15 / 12:00:30 to all three at 12:00:00, and the shipped guard test
    /// `seeding_does_not_make_an_account_due_earlier_than_its_schedule` could
    /// not see it because it names the other function.
    pub fn seed_from_cache(&mut self, uuid: &str, snap: CachedSnapshot, current_fp: &str) {
        // §9.3: a fingerprint that does not match means "cannot verify", and an
        // unverified cache is not shown. This is ccstatusline #459 — stale
        // values surviving an account switch until the TTL.
        if snap.token_fingerprint != current_fp {
            return;
        }
        let now = self.clock.now();
        // User decision 3: never restore a window the data itself says has
        // rotated. `formatReset` prints the literal "now" for any `resets_at`
        // in the past (its `secs <= 0` early return in src/lib/format.ts) and
        // `Bar.svelte` renders the percentage beside it unconditionally, so a
        // weekend-old snapshot would show a rotated window's old percentage as
        // if it were current — the confidently-wrong-number failure CLAUDE.md
        // names as the worst one.
        let live: Vec<UsageWindow> =
            snap.windows.into_iter().filter(|w| w.resets_at > now).collect();
        // Nothing survived: leave the account `Loading` rather than restoring an
        // empty bar list, which would render as an account with no windows.
        if live.is_empty() {
            return;
        }
        self.seed(uuid, live, snap.fetched_at);
    }

    /// The value to persist for this account, stamped with the fingerprint of
    /// the token that produced it.
    ///
    /// The caller passes the fingerprint rather than this module deriving it,
    /// because the poll path already holds the access token it fetched with
    /// (`fresh.tokens.access_token`) and re-reading the store to hash it would
    /// pull a live credential — access **and** refresh token, in plaintext —
    /// into the persistence path for nothing.
    pub fn snapshot(&self, uuid: &str, token_fingerprint: &str) -> Option<CachedSnapshot> {
        let e = self.entries.get(uuid)?;
        Some(CachedSnapshot {
            windows: e.last_windows.clone()?,
            fetched_at: e.last_fetched_at?,
            token_fingerprint: token_fingerprint.to_string(),
        })
    }

    /// §6.4. The earliest instant a manual refresh may fire. `None` means "now".
    ///
    /// §6.1's 180-second floor is enforced inside `due()`'s `last_attempt_at`
    /// check and inside `set_visible`'s pull-forward, and deliberately **not**
    /// inside `begin_poll`: the shipped test
    /// `a_second_poll_cannot_start_while_one_is_in_flight` requires a re-claim
    /// immediately after `end_poll` with the clock unmoved. Manual refresh never
    /// goes through `due()` (`begin_poll`'s own doc says so), so it has to ask.
    /// Measured: begin_poll/end_poll/record_success can be cycled once per
    /// simulated second while `due()` allows zero.
    pub fn earliest_manual_refresh(&self, uuid: &str) -> Option<DateTime<Utc>> {
        let e = self.entries.get(uuid)?;
        let floor = TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS);
        e.last_attempt_at.map(|t| t + floor).filter(|t| *t > self.clock.now())
    }

    /// Spec §6.2. `retry_after_secs == 0` means budget exhausted — sit out an
    /// entire window. `u64`, not `i64`, to line up with `UsageError::Throttled`
    /// — Task 12 made that field `u64` so a negative `Retry-After` cannot parse
    /// at all.
    ///
    /// **That settles the sign, not the magnitude, and the magnitude is the
    /// dangerous half.** The header is parsed with no upper bound, so a server
    /// (or anything able to answer as one) can send a value that:
    ///   - overflows `TimeDelta::seconds`, which panics;
    ///   - or overflows `now + wait`, which also panics;
    ///   - or, past `i64::MAX`, wraps negative through `as i64` and lands
    ///     `throttled_until` in the **past** — so the client immediately
    ///     re-polls a server that just told it to back off, silently defeating
    ///     the one mechanism this module exists to provide.
    ///
    /// Cap it. An hour is far beyond any legitimate value.
    pub fn record_throttle(&mut self, uuid: &str, retry_after_secs: u64) {
        let now = self.clock.now();
        let retry_after_secs = retry_after_secs.min(PollPolicy::MAX_RETRY_AFTER_SECS);
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
            // Written arm by arm rather than with a `_` fallback: a third
            // quarantining kind added later must be given a display here
            // deliberately, not inherit `AuthDead`'s clickable "re-login
            // required" — the one affordance that is wrong for this state.
            return Some(match e.last_failure {
                Some(FailureKind::OrgOauthDisabled) => AccountState::OrgOauthDisabled,
                Some(FailureKind::AuthDead)
                | Some(FailureKind::Network)
                | Some(FailureKind::UnknownShape)
                | Some(FailureKind::AuthExpired)
                | Some(FailureKind::SecretsLocked)
                | None => AccountState::AuthDead,
            });
        }
        if let Some(until) = e.throttled_until.filter(|t| *t > now) {
            return Some(AccountState::Throttled { until });
        }
        // `SECRETS_LOCKED` wins over `STALE`, the way `THROTTLED` and
        // `AUTH_DEAD` above already do. Without this it became unreachable the
        // moment an account succeeded once: every later failure rendered
        // `Stale`, so a keychain locking while the app runs — a screen lock,
        // which is the normal case, not an edge one — showed a dimmed old value
        // forever and never offered §7.1's "unlock" affordance, the only remedy
        // that state carries.
        //
        // The three kinds that remain shadowed stay that way on purpose. §7.1
        // makes `NETWORK` explicitly equivalent to `STALE`; `UNKNOWN_SHAPE`
        // means this fetch was unreadable, which is exactly when the last
        // readable value is worth keeping; and `AUTH_EXPIRED` is transient and
        // resolves itself on the next refresh. `AUTH_DEAD` is not in that list
        // because it is not shadowed at all — it already wins above, through
        // `quarantined`.
        if e.last_failure == Some(FailureKind::SecretsLocked) {
            return Some(AccountState::SecretsLocked);
        }

        match (&e.last_windows, e.last_fetched_at) {
            (Some(w), Some(at)) => {
                // Failed, or past the staleness boundary: Stale.
                let too_old = now - at > self.policy.interval * 2;
                let credit = e.last_credit.clone();
                if e.last_failure.is_some() || too_old {
                    Some(AccountState::Stale { windows: w.clone(), credit, fetched_at: at })
                } else {
                    Some(AccountState::Ok { windows: w.clone(), credit, fetched_at: at })
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
                Some(FailureKind::OrgOauthDisabled) => AccountState::OrgOauthDisabled,
            }),
        }
    }
}

/// Registers every account at startup: §6.1's stagger, §7.4's cache restore,
/// and §7.2's quarantine restore — in that order.
///
/// `current_fingerprint` is a closure so this stays Tauri-free and testable;
/// the wiring passes one that reads the token store. It returns `None` when the
/// token cannot be read, and that **fails closed**: with no fingerprint there
/// is nothing to verify the cache against, and §9.3 does not allow showing an
/// unverified cache. On the fallback store at launch-at-login that means the
/// widget shows nothing until the passphrase is entered — a consequence of
/// §9.3 (and of design.md:600-601), not a bug to work around.
pub fn register_accounts<C: Clock>(
    sched: &mut Scheduler<C>,
    accounts: &[Account],
    cache: &mut std::collections::HashMap<String, CachedSnapshot>,
    current_fingerprint: &dyn Fn(&str) -> Option<String>,
) {
    for a in accounts {
        sched.add(&a.uuid);
        if let Some(snap) = cache.remove(&a.uuid) {
            if let Some(fp) = current_fingerprint(&a.uuid) {
                sched.seed_from_cache(&a.uuid, snap, &fp);
            }
        }
        if a.quarantined {
            // §7.2/§10.5: one strike survives a restart. Replaying the failure
            // is enough and needs no new API — `record_failure` is the only
            // writer of the in-memory flag and it returns before touching the
            // backoff (its `AuthDead` early return). Order against the seed
            // above does not matter: `state()` checks `quarantined` before
            // anything else.
            sched.record_failure(&a.uuid, FailureKind::AuthDead);
        }
    }
}

/// §7.2. Writes the one-strike quarantine through to the account file so it
/// survives a restart. `Ok(false)` means it was already recorded.
///
/// Without this, every launch re-polls an account the server has already
/// declared dead and burns one refresh that can only answer `invalid_grant` —
/// exactly what "do not retry" forbids. Must go through the single
/// `AccountStore` instance: accounts.rs:36-47 warns that two open instances
/// silently discard each other's writes.
pub fn persist_quarantine(
    accounts: &mut AccountStore,
    uuid: &str,
) -> Result<bool, AccountError> {
    let Some(mut a) = accounts.list().iter().find(|a| a.uuid == uuid).cloned() else {
        return Ok(false);
    };
    if a.quarantined {
        return Ok(false);
    }
    a.quarantined = true;
    // `upsert` preserves `sort_order` for an existing uuid (accounts.rs:71-83).
    accounts.upsert(a)?;
    Ok(true)
}

/// Records the time of a successful poll in the account metadata file.
/// `Ok(false)` means there was no such account and nothing was written.
///
/// docs/design.md:636 lists `last_ok_at` in that file, but nothing ever wrote
/// it: every path either set `None` or copied the previous value forward, so a
/// profile that had been polling successfully for weeks still read
/// `"last_ok_at": null` on every account — a stored claim that the account had
/// never once succeeded. Nothing reads the field yet, which is why this went
/// unnoticed; a value that is wrong only when someone finally looks is still
/// wrong.
///
/// Writes on every success rather than diffing first, because the value changes
/// every time. `AccountStore::flush` is temp-file-plus-rename, so the raised
/// write frequency cannot tear the file (accounts.rs:143-160).
pub fn persist_last_ok(
    accounts: &mut AccountStore,
    uuid: &str,
    at: DateTime<Utc>,
) -> Result<bool, AccountError> {
    let Some(mut a) = accounts.list().iter().find(|a| a.uuid == uuid).cloned() else {
        return Ok(false);
    };
    a.last_ok_at = Some(at);
    accounts.upsert(a)?;
    Ok(true)
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

    /// §6.1's floor is §5.2's throttle position written as a number, so it has
    /// to be unreachable rather than merely defaulted around. `PollPolicy`'s
    /// fields are private and `with_interval_secs` is the only way in; this
    /// pins that the only way in clamps.
    #[test]
    fn interval_below_the_floor_is_clamped() {
        let p = PollPolicy::with_interval_secs(30);
        assert_eq!(p.interval().num_seconds(), PollPolicy::MIN_INTERVAL_SECS);
        let p = PollPolicy::with_interval_secs(600);
        assert_eq!(p.interval().num_seconds(), 600, "a legitimate value must pass through unchanged");
    }

    /// The one exhaustive mapping from `usage`'s error type to a failure kind.
    /// Task 17 is its first caller; hand-derived copies of this table at every
    /// call site are what it exists to prevent.
    #[test]
    fn usage_errors_map_to_one_failure_kind_each() {
        fn kind(e: UsageError) -> Option<FailureKind> {
            FailureKind::from_usage_error(&e)
        }
        assert_eq!(
            kind(UsageError::Throttled { retry_after_secs: 42 }),
            None,
            "Throttled carries a wait and must route to record_throttle instead"
        );
        assert_eq!(kind(UsageError::Unauthorized), Some(FailureKind::AuthExpired));
        assert_eq!(kind(UsageError::UnknownShape), Some(FailureKind::UnknownShape));
        assert_eq!(kind(UsageError::Transport("boom".into())), Some(FailureKind::Network));
        // Not because a 5xx is a network error, but because §7.1 defines
        // NETWORK by its rendering and "last value with its age" is right here.
        assert_eq!(kind(UsageError::Status(503)), Some(FailureKind::Network));
    }

    /// The same, for `auth::stored`. `Missing`/`Corrupt` reaching `AUTH_DEAD`
    /// rather than `AUTH_EXPIRED` is the load-bearing row: §9.2 says re-login,
    /// and `AUTH_EXPIRED` would render a spinner that never resolves.
    #[test]
    fn stored_token_errors_map_to_one_failure_kind_each() {
        fn kind(e: StoredTokenError) -> FailureKind {
            FailureKind::from_stored_token_error(&e)
        }
        fn oauth(code: &str) -> AuthError {
            AuthError::OAuth { status: 400, code: Some(code.into()), description: None }
        }
        assert_eq!(kind(StoredTokenError::Missing), FailureKind::AuthDead);
        assert_eq!(kind(StoredTokenError::Corrupt), FailureKind::AuthDead);

        assert_eq!(
            kind(StoredTokenError::Secrets(SecretError::Locked("x".into()))),
            FailureKind::SecretsLocked
        );
        assert_eq!(
            kind(StoredTokenError::Secrets(SecretError::NoBackend("x".into()))),
            FailureKind::Network
        );
        assert_eq!(
            kind(StoredTokenError::Secrets(SecretError::Backend("x".into()))),
            FailureKind::Network
        );
        assert_eq!(
            kind(StoredTokenError::Secrets(SecretError::TooLong { limit: 2560 })),
            FailureKind::Network
        );

        assert!(oauth("invalid_grant").is_dead_grant(), "the guard below would be vacuous");
        assert_eq!(kind(StoredTokenError::Auth(oauth("invalid_grant"))), FailureKind::AuthDead);
        assert_eq!(
            kind(StoredTokenError::Auth(AuthError::Transport("boom".into()))),
            FailureKind::Network
        );
        assert_eq!(kind(StoredTokenError::Auth(oauth("invalid_scope"))), FailureKind::AuthExpired);
        assert_eq!(kind(StoredTokenError::Auth(AuthError::StateMismatch)), FailureKind::AuthExpired);
        assert_eq!(
            kind(StoredTokenError::Auth(AuthError::Decode("x".into()))),
            FailureKind::AuthExpired
        );
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
        s.record_success("a", win(20.0), None);
        assert!(s.due().is_empty(), "just fetched, so wait");
        c.advance_secs(299);
        assert!(s.due().is_empty());
        c.advance_secs(2);
        assert_eq!(s.due(), vec!["a"], "due again once the interval passes");
    }

    /// Spec §6.1: stagger accounts to avoid a startup burst.
    ///
    /// **`due()` cannot verify the stagger.** `due()` ends in `.take(1)`, so it
    /// returns only the first account even when stagger is zero — an earlier
    /// version written that way still passed with the offset in `add()`
    /// deleted entirely. The schedule itself has to be inspected.
    #[test]
    fn accounts_are_staggered_so_startup_never_bursts() {
        let (mut s, _c) = sched();
        s.add("a");
        s.add("b");
        s.add("c");

        let stagger = PollPolicy::default().stagger();
        assert!(stagger > TimeDelta::zero(), "a zero stagger would make this test catch nothing");

        let a = s.next_wake("a").unwrap();
        assert_eq!(s.next_wake("b").unwrap() - a, stagger, "the second account is one stagger behind");
        assert_eq!(s.next_wake("c").unwrap() - a, stagger * 2, "the third is two staggers behind");
    }

    /// Spec §6.1: global concurrency of 1.
    #[test]
    fn due_returns_at_most_one_account() {
        let (mut s, c) = sched();
        for id in ["a", "b", "c"] {
            s.add(id);
            s.record_success(id, win(10.0), None);
        }
        c.advance_secs(3600);
        assert_eq!(s.due().len(), 1);
    }

    /// Spec §7.2: an automatic polling failure quietly keeps the last value.
    #[test]
    fn failure_keeps_the_last_good_value_as_stale() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(42.0), None);
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

    /// Neither the clock nor `due()` appears between the iterations below, and
    /// that is deliberate. `record_failure` computes the next wake from the
    /// clock at the instant it is called, so advancing time changes nothing
    /// this asserts; and `due()` takes `&self` and mutates nothing, so calling
    /// it here only implied a state transition that does not exist. Both were
    /// present in an earlier version of this test.
    #[test]
    fn repeated_failures_back_off_exponentially_and_reset_on_success() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(1.0), None);
        let mut waits = vec![];
        for _ in 0..3 {
            s.record_failure("a", FailureKind::Network);
            waits.push(s.next_wake("a").unwrap() - c.now());
        }
        assert!(waits[1] > waits[0] && waits[2] > waits[1], "intervals must grow: {waits:?}");
        s.record_success("a", win(1.0), None);
        let after = s.next_wake("a").unwrap() - c.now();
        assert!(after <= PollPolicy::default().interval(), "success resets the backoff");
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
        s.record_success("a", win(5.0), None);
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

    /// A 403 naming the organization policy is permanent like `AuthDead`, and
    /// must **not** render as `AuthDead` — the two differ in the only thing
    /// §7.1 says a failure state is for, which is the remedy it offers. Telling
    /// a user to re-login when re-logging in is guaranteed to be refused is the
    /// confusing failure that section exists to prevent.
    #[test]
    fn an_org_oauth_denial_is_quarantined_but_is_not_auth_dead() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_failure("a", FailureKind::OrgOauthDisabled);

        assert_eq!(s.state("a"), Some(AccountState::OrgOauthDisabled));
        assert_ne!(
            s.state("a"),
            Some(AccountState::AuthDead),
            "re-login is the one affordance that cannot work here"
        );
        c.advance_secs(100_000);
        assert!(s.due().is_empty(), "permanent, so never polled again");
    }

    /// The quarantine branch runs before the cached-snapshot branch, so an
    /// account that worked yesterday and is denied today must show the denial
    /// rather than a dimmed old reading. Without this the state would be
    /// reachable only on an account that had never once succeeded.
    #[test]
    fn an_org_oauth_denial_beats_a_cached_snapshot() {
        let (mut s, c) = sched();
        s.add("a");
        s.begin_poll("a");
        s.record_success("a", win(42.0), None);
        assert!(matches!(s.state("a"), Some(AccountState::Ok { .. })));

        c.advance_secs(10);
        s.record_failure("a", FailureKind::OrgOauthDisabled);
        assert_eq!(
            s.state("a"),
            Some(AccountState::OrgOauthDisabled),
            "a stale reading with an age would imply this is transient"
        );
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
        s.record_success("a", win(30.0), None);
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

    /// The server-supplied `Retry-After` is external input with no upper
    /// bound. `u64::MAX` wraps negative through `as i64` and lands
    /// `throttled_until` in the **past** — immediately re-hitting a server
    /// that just told us to back off. Values below that panic in
    /// `TimeDelta::seconds` or in `now + wait`.
    #[test]
    fn an_absurd_retry_after_is_capped_and_never_lands_in_the_past() {
        let (mut s, c) = sched();
        s.add("a");
        let now = c.now();

        s.record_throttle("a", u64::MAX);
        let until = s.next_wake("a").unwrap();
        assert!(until > now, "throttled_until landed in the past — the throttle is defeated");
        assert_eq!(
            until - now,
            TimeDelta::seconds(PollPolicy::MAX_RETRY_AFTER_SECS as i64),
            "must be clamped to the cap"
        );
        assert!(s.due().is_empty(), "must not become due right after being capped");
    }

    /// Spec §7.4: after a restart the disk-cached snapshot is shown as `STALE`
    /// rather than an empty screen — and §7.1 forbids rendering a stale value
    /// without its age, so the age has to be the real one. Restoring through
    /// `record_success` would stamp the restart time and claim a value fetched
    /// an hour ago was fetched now.
    #[test]
    fn a_seeded_snapshot_renders_stale_with_the_age_it_really_has() {
        let (mut s, c) = sched();
        s.add("a");
        let cached_at = c.now() - TimeDelta::seconds(3600);
        s.seed("a", win(63.0), cached_at);

        match s.state("a").unwrap() {
            AccountState::Stale { windows, fetched_at, .. } => {
                assert_eq!(windows[0].percent, 63.0);
                assert_eq!(fetched_at, cached_at, "the cached snapshot was stamped with the restart time");
                assert_eq!(
                    c.now() - fetched_at,
                    TimeDelta::seconds(3600),
                    "a stale value rendered with a fabricated age is worse than no value"
                );
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// Restoring a cache is not a poll. It must not pull the schedule forward,
    /// or every restart would fire a request outside §6.1's floor.
    #[test]
    fn seeding_does_not_make_an_account_due_earlier_than_its_schedule() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(10.0), None);
        let scheduled = s.next_wake("a").unwrap();

        s.seed("a", win(63.0), c.now() - TimeDelta::seconds(3600));

        assert_eq!(s.next_wake("a").unwrap(), scheduled, "seed moved the schedule");
        assert!(s.due().is_empty(), "seed made the account due");
    }

    /// §6.1's floor must not depend on the driver remembering to record an
    /// outcome. A poll that begins, fails in a way the caller handles itself,
    /// and ends without any `record_*` call leaves `next_due_at` where it was —
    /// so without a floor of its own `due()` hands the same account back on the
    /// very next tick, hammering the usage endpoint at loop speed.
    #[test]
    fn a_poll_that_records_no_outcome_still_respects_the_floor() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");

        assert!(s.due().is_empty(), "immediately due again after a poll that recorded nothing");
        c.advance_secs(PollPolicy::MIN_INTERVAL_SECS - 1);
        assert!(s.due().is_empty(), "still inside the floor");
        c.advance_secs(2);
        assert_eq!(s.due(), vec!["a"], "due again once the floor has passed");
    }

    /// §7.1's `SECRETS_LOCKED` carries an "unlock" affordance, and that is the
    /// only remedy the state has. Letting `Stale` shadow it made it unreachable
    /// after the first success — so a keychain locking mid-session (a screen
    /// lock: the normal case) showed a dimmed old value forever with nothing to
    /// click.
    #[test]
    fn a_locked_store_wins_over_stale_even_after_a_success() {
        let (mut s, c) = sched();
        s.add("a");
        s.record_success("a", win(42.0), None);
        c.advance_secs(10);
        s.record_failure("a", FailureKind::SecretsLocked);
        assert_eq!(
            s.state("a"),
            Some(AccountState::SecretsLocked),
            "a locked store must offer the unlock affordance, not a dimmed value"
        );

        // The shadowing §7.1 does ask for is unchanged: NETWORK is defined as
        // "treated the same as STALE".
        s.record_success("a", win(42.0), None);
        s.record_failure("a", FailureKind::Network);
        assert!(
            matches!(s.state("a"), Some(AccountState::Stale { .. })),
            "NETWORK must stay equivalent to STALE"
        );
    }

    /// Spec §6.1's floor applies to the visibility path too. Repeatedly
    /// hiding and showing the widget must not bypass it — a focus change or a
    /// workspace switch alone can trigger that.
    #[test]
    fn becoming_visible_never_polls_inside_the_floor() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"), "poll once");
        s.end_poll("a");
        s.record_success("a", win(10.0), None);

        c.advance_secs(5);
        s.set_visible(false);
        s.set_visible(true);
        assert!(s.due().is_empty(), "hide/show cycling bypassed the floor");

        c.advance_secs(PollPolicy::MIN_INTERVAL_SECS);
        s.set_visible(false);
        s.set_visible(true);
        assert_eq!(s.due(), vec!["a"], "once the floor has passed, becoming visible must make it due");
    }

    /// A cached window built **from the injected clock**, never from
    /// `Utc::now()`.
    ///
    /// The fixture clock is pinned at 2026-07-29T12:00:00Z and the real clock
    /// is past it, so a snapshot stamped `Utc::now() - 20min` lands in the
    /// *future* relative to `c.now()`: `now - fetched_at` goes negative and
    /// `state()`'s `too_old` is unconditionally false. An earlier version of
    /// these tests did exactly that and never executed the age path at all.
    fn cached(c: &TestClock, pct: f64, resets_in_secs: i64, fp: &str) -> CachedSnapshot {
        CachedSnapshot {
            windows: vec![UsageWindow {
                window_id: "five_hour".into(),
                label: "5h".into(),
                percent: pct,
                resets_at: c.now() + TimeDelta::seconds(resets_in_secs),
                scope: None,
            }],
            fetched_at: c.now(),
            token_fingerprint: fp.to_string(),
        }
    }

    fn account(uuid: &str, quarantined: bool) -> Account {
        Account {
            uuid: uuid.into(),
            display_label: uuid.into(),
            email: format!("{uuid}@example.com"),
            created_at: Utc::now(),
            last_ok_at: None,
            quarantined,
            sort_order: 0,
        }
    }

    /// §9.3: a cache that cannot be verified against the current token is not
    /// shown. ccstatusline #459 is stale values surviving an account switch.
    #[test]
    fn a_cache_from_another_login_is_discarded() {
        let (mut s, c) = sched();
        s.add("a");
        s.seed_from_cache("a", cached(&c, 63.0, 3600, "fp-from-another-login"), "fp-current");
        assert_eq!(
            s.state("a"),
            Some(AccountState::Loading),
            "an unverifiable cache was shown anyway"
        );
    }

    #[test]
    fn a_cache_with_a_matching_fingerprint_is_restored_as_stale() {
        let (mut s, c) = sched();
        s.add("a");
        let at = c.now();
        s.seed_from_cache("a", cached(&c, 63.0, 3600, "fp"), "fp");
        match s.state("a").unwrap() {
            AccountState::Stale { windows, fetched_at, .. } => {
                assert_eq!(windows[0].percent, 63.0);
                assert_eq!(fetched_at, at, "the cached age must be the real one");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    /// §7.4: a restored snapshot is `STALE` until this process confirms it,
    /// **regardless of age**. `state()` only calls a value stale past
    /// `interval * 2`, so without `seed` recording a failure a restart inside
    /// ten minutes renders a cached number as a live one.
    #[test]
    fn a_cache_seeded_seconds_ago_is_still_stale_not_ok() {
        let (mut s, c) = sched();
        s.add("a");
        let mut snap = cached(&c, 63.0, 3600, "fp");
        snap.fetched_at = c.now() - TimeDelta::seconds(5);
        assert!(
            c.now() - snap.fetched_at < PollPolicy::default().interval() * 2,
            "a snapshot older than the staleness boundary would make this test vacuous"
        );
        s.seed_from_cache("a", snap, "fp");
        assert!(
            matches!(s.state("a"), Some(AccountState::Stale { .. })),
            "a five-second-old cache rendered as a confirmed live value, got {:?}",
            s.state("a")
        );
    }

    /// User decision 3. A window whose `resets_at` has passed has rotated; its
    /// old percentage is not the current one and `formatReset` would print the
    /// literal "now" beside it.
    #[test]
    fn a_window_that_has_already_reset_is_not_restored() {
        let (mut s, c) = sched();
        s.add("a");
        let mut snap = cached(&c, 63.0, 3600, "fp");
        snap.windows.push(UsageWindow {
            window_id: "seven_day".into(),
            label: "7d".into(),
            percent: 41.0,
            resets_at: c.now() - TimeDelta::seconds(1),
            scope: None,
        });
        s.seed_from_cache("a", snap, "fp");
        match s.state("a").unwrap() {
            AccountState::Stale { windows, .. } => {
                assert_eq!(windows.len(), 1, "the rotated window survived: {windows:?}");
                assert_eq!(windows[0].window_id, "five_hour", "the wrong window was dropped");
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn an_account_whose_windows_have_all_reset_is_not_restored() {
        let (mut s, c) = sched();
        s.add("a");
        s.seed_from_cache("a", cached(&c, 63.0, -1, "fp"), "fp");
        assert_eq!(
            s.state("a"),
            Some(AccountState::Loading),
            "an account with no live windows must stay Loading, not render an empty bar list"
        );
    }

    /// Restoring a cache is not a poll. A second entry point that also set
    /// `next_due_at = now` flattened §6.1's stagger, and the shipped guard test
    /// could not see it because it names `seed` rather than `seed_from_cache`.
    #[test]
    fn restoring_a_cache_does_not_erase_the_startup_stagger() {
        let (mut s, c) = sched();
        for id in ["a", "b", "c"] {
            s.add(id);
        }
        let stagger = PollPolicy::default().stagger();
        assert!(stagger > TimeDelta::zero(), "a zero stagger would make this test catch nothing");

        for id in ["a", "b", "c"] {
            s.seed_from_cache(id, cached(&c, 10.0, 3600, "fp"), "fp");
        }

        assert_eq!(s.next_wake("a").unwrap(), c.now());
        assert_eq!(s.next_wake("b").unwrap(), c.now() + stagger);
        assert_eq!(s.next_wake("c").unwrap(), c.now() + stagger * 2);
    }

    /// §7.2/§10.5: "do not retry". Without restoring the flag, every launch
    /// burns one refresh that can only answer `invalid_grant`.
    #[test]
    fn a_persisted_quarantine_is_restored_at_startup() {
        let (mut s, c) = sched();
        let mut cache = HashMap::new();
        register_accounts(&mut s, &[account("a", true), account("b", false)], &mut cache, &|_| None);

        assert_eq!(s.state("a"), Some(AccountState::AuthDead));
        c.advance_secs(100_000);
        assert_eq!(
            s.due(),
            vec!["b"],
            "the quarantined account was polled again after a restart"
        );
    }

    /// The disk value, not the in-memory one. `Scheduler`'s copy of the flag is
    /// lost at exit, so the account file is the only thing that carries it
    /// across a restart.
    #[test]
    fn an_auth_dead_poll_writes_the_quarantine_through_to_the_account_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("quota-quarantine-{}-{:016x}.json", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_file(&path);

        let mut store = AccountStore::load(&path);
        store.upsert(account("a", false)).unwrap();

        assert!(persist_quarantine(&mut store, "a").unwrap(), "the first call must record it");
        assert!(!persist_quarantine(&mut store, "a").unwrap(), "the second call is a no-op");
        assert!(!persist_quarantine(&mut store, "unknown").unwrap(), "an unknown uuid is a no-op");

        let reloaded = AccountStore::load(&path);
        assert!(
            reloaded.list()[0].quarantined,
            "the quarantine never reached the disk — it dies with the process"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Measured on a real profile: three accounts that had all polled
    /// successfully, and `accounts.json` read `"last_ok_at": null` for every
    /// one of them. docs/design.md:636 puts the field in that file, so a
    /// permanent null there is a stored statement that no poll has ever
    /// worked.
    #[test]
    fn a_successful_poll_writes_the_time_through_to_the_account_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("quota-lastok-{}-{:016x}.json", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_file(&path);

        let at: DateTime<Utc> = "2026-07-31T11:41:03.891055Z".parse().unwrap();
        let mut store = AccountStore::load(&path);
        let mut renamed = account("a", false);
        renamed.display_label = "work".into();
        store.upsert(renamed).unwrap();

        assert!(persist_last_ok(&mut store, "a", at).unwrap(), "the account exists, so it writes");
        assert!(
            !persist_last_ok(&mut store, "unknown", at).unwrap(),
            "an unknown uuid is a no-op"
        );

        let reloaded = AccountStore::load(&path);
        assert_eq!(
            reloaded.list()[0].last_ok_at,
            Some(at),
            "the successful poll never reached the disk"
        );
        // The same trap `persist_quarantine` has: this rewrites a whole account
        // record, so a field it does not mean to touch is one it can erase.
        assert_eq!(
            reloaded.list()[0].display_label, "work",
            "recording the poll time overwrote the user's rename"
        );
        assert!(
            !reloaded.list()[0].quarantined,
            "recording the poll time changed the quarantine flag"
        );
        std::fs::remove_file(&path).ok();
    }

    /// §6.4. The 180-second floor lives inside `due()`, and manual refresh
    /// never goes through `due()` — so the manual path has to ask. Measured:
    /// cycling begin_poll/end_poll/record_success once per simulated second
    /// sends ten requests in ten seconds while `due()` allows zero.
    #[test]
    fn a_manual_refresh_inside_the_floor_is_refused() {
        let (mut s, c) = sched();
        s.add("a");
        assert_eq!(s.earliest_manual_refresh("a"), None, "an account never polled may refresh now");

        assert!(s.begin_poll("a"));
        s.end_poll("a");
        s.record_success("a", win(10.0), None);

        let until = s.earliest_manual_refresh("a").expect("inside the floor, refresh must be refused");
        assert_eq!(until, c.now() + TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS));
    }

    #[test]
    fn a_manual_refresh_is_allowed_after_the_floor() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");

        c.advance_secs(PollPolicy::MIN_INTERVAL_SECS - 1);
        assert!(s.earliest_manual_refresh("a").is_some(), "still inside the floor");
        c.advance_secs(2);
        assert_eq!(s.earliest_manual_refresh("a"), None, "the floor has passed");
    }

    /// The ceiling exists because chrono panics: measured on 0.4.45,
    /// `PollPolicy::with_interval_secs(i64::MAX)` panicked with "TimeDelta::
    /// seconds out of bounds", and `Utc::now() + TimeDelta::seconds(i64::MAX /
    /// 1000)` panicked too — the second inside `record_success`, on the task
    /// whose panic ends all polling for the process.
    #[test]
    fn an_interval_above_the_ceiling_is_clamped_rather_than_panicking() {
        let p = PollPolicy::with_interval_secs(i64::MAX);
        assert_eq!(p.interval().num_seconds(), PollPolicy::MAX_INTERVAL_SECS);
        let (mut s, _c) = sched();
        s.add("a");
        s.set_policy(p);
        assert!(s.begin_poll("a"));
        s.record_success("a", win(10.0), None);
        let p = PollPolicy::with_interval_secs(600);
        assert_eq!(p.interval().num_seconds(), 600, "a legitimate value must still pass through");
    }

    #[test]
    fn lowering_the_interval_pulls_a_pending_poll_forward() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");
        s.record_success("a", win(10.0), None);
        let started = c.now();
        assert_eq!(s.next_wake("a").unwrap(), started + PollPolicy::default().interval());

        s.set_policy(PollPolicy::with_interval_secs(PollPolicy::MIN_INTERVAL_SECS));

        assert_eq!(
            s.next_wake("a").unwrap(),
            started + TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS),
            "the new interval never reached the schedule"
        );
        c.advance_secs(PollPolicy::MIN_INTERVAL_SECS - 1);
        assert!(s.due().is_empty(), "an interval change must not poll inside §6.1's floor");
        c.advance_secs(1);
        assert_eq!(s.due(), vec!["a"], "due once the new interval has passed");
    }

    #[test]
    fn raising_the_interval_takes_effect_at_once() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");
        s.record_success("a", win(10.0), None);
        let started = c.now();
        s.set_policy(PollPolicy::with_interval_secs(3600));
        assert_eq!(s.next_wake("a").unwrap(), started + TimeDelta::seconds(3600));
    }

    /// A settings change must not reset an exponential backoff earned against
    /// an unreachable network. Measured: an assignment of `now + interval`
    /// collapses a 19000-second wait to 180.
    #[test]
    fn changing_the_interval_does_not_reset_an_exponential_backoff() {
        let (mut s, c) = sched();
        s.add("a");
        for _ in 0..8 {
            assert!(s.begin_poll("a"));
            s.end_poll("a");
            s.record_failure("a", FailureKind::Network);
            c.advance_secs(200);
        }
        let attempted = c.now() - TimeDelta::seconds(200);
        s.set_policy(PollPolicy::with_interval_secs(PollPolicy::MIN_INTERVAL_SECS));
        assert_eq!(
            s.next_wake("a").unwrap(),
            attempted + TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS * 64),
            "the backoff level was silently discarded by a settings change"
        );
    }

    /// §6.2: the wait after a 429 is the server's, not a local preference.
    #[test]
    fn changing_the_interval_does_not_shorten_a_server_ordered_backoff() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");
        let started = c.now();
        s.record_throttle("a", 300);
        s.set_policy(PollPolicy::with_interval_secs(PollPolicy::MIN_INTERVAL_SECS));
        assert_eq!(
            s.next_wake("a").unwrap(),
            started + TimeDelta::seconds(300),
            "a settings change overrode the server's Retry-After"
        );
    }

    /// The same invariant `restoring_a_cache_does_not_erase_the_startup_stagger`
    /// pins for the cache path. Measured: `min(now + interval)` collapses
    /// accounts 13-16 of 16 onto one instant at the floor.
    #[test]
    fn changing_the_interval_does_not_erase_the_startup_stagger() {
        let (mut s, _c) = sched();
        for id in ["a", "b", "c"] {
            s.add(id);
        }
        let stagger = PollPolicy::default().stagger();
        assert!(stagger > TimeDelta::zero(), "a zero stagger would make this test catch nothing");
        let a = s.next_wake("a").unwrap();
        s.set_policy(PollPolicy::with_interval_secs(1800));
        assert_eq!(s.next_wake("a").unwrap(), a);
        assert_eq!(s.next_wake("b").unwrap() - a, stagger);
        assert_eq!(s.next_wake("c").unwrap() - a, stagger * 2);
    }

    #[test]
    fn set_policy_does_not_resurrect_a_quarantined_account() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");
        s.record_failure("a", FailureKind::AuthDead);
        let before = s.next_wake("a").unwrap();
        s.set_policy(PollPolicy::with_interval_secs(PollPolicy::MIN_INTERVAL_SECS));
        assert_eq!(s.next_wake("a").unwrap(), before);
        c.advance_secs(100_000);
        assert!(s.due().is_empty(), "a quarantined account was made due again");
    }

    #[test]
    fn a_remedy_makes_a_backed_off_account_due_again_without_breaking_the_floor() {
        let (mut s, c) = sched();
        s.add("a");
        for _ in 0..4 {
            assert!(s.begin_poll("a"));
            s.record_failure("a", FailureKind::SecretsLocked);
            s.end_poll("a");
            c.advance_secs(1);
        }
        assert!(s.due().is_empty(), "premise: the backoff has pushed the poll far out");
        let last_attempt = c.now() - TimeDelta::seconds(1);

        s.retry_all_now();
        // The floor half is asserted on `next_wake`, NOT on `due()`. `due()`
        // re-applies the same floor itself (its `last_attempt_at` predicate), so
        // it answers "empty" even when the pull-forward has dropped the floor
        // entirely — measured, and it is why the shipped
        // `becoming_visible_never_polls_inside_the_floor` also survives that
        // mutation.
        assert_eq!(
            s.next_wake("a"),
            Some(last_attempt + TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS)),
            "the remedy pulled the next poll inside §6.1's floor"
        );
        assert!(s.due().is_empty(), "and it is not due yet");

        c.advance_secs(PollPolicy::MIN_INTERVAL_SECS);
        assert_eq!(s.due(), vec!["a"], "the account never became due again after the remedy");
    }

    /// §10.3. `add`'s stagger is right for startup and wrong for the one path
    /// where the user is watching: measured on the device, the third account
    /// registered through the settings window showed `Loading` for 30 seconds
    /// and the fourth for 45.
    #[test]
    fn a_newly_registered_account_is_due_immediately_even_behind_other_accounts() {
        let (mut s, c) = sched();
        for id in ["a", "b", "c"] {
            s.add(id);
            assert!(s.begin_poll(id));
            s.end_poll(id);
            s.record_success(id, win(10.0), None);
        }
        assert!(s.due().is_empty(), "premise: no existing account is due, so due() below is about the new one");

        s.add("d");
        assert_eq!(
            s.next_wake("d").unwrap(),
            c.now() + PollPolicy::default().stagger() * 3,
            "premise: add() puts the fourth account three staggers out"
        );

        s.make_due_now("d");
        assert_eq!(s.next_wake("d").unwrap(), c.now(), "the new account still waits out the stagger");
        assert_eq!(s.due(), vec!["d"], "the account the user just added was not polled");

        // A re-login is the same defect on a worse path:
        // `register_authenticated` does `remove` + `add`, so the rebuilt entry
        // goes to the end of `order` and inherits the largest offset there is.
        s.remove("a");
        s.add("a");
        s.make_due_now("a");
        assert_eq!(
            s.next_wake("a").unwrap(),
            c.now(),
            "a re-login — §7.2's remedy, with the user watching — inherited the largest stagger"
        );
    }

    /// The other half of the same change: only the account named by
    /// `make_due_now` moves. §6.1's stagger is what buys the deliberate
    /// decision not to implement jitter (the note under §6.1), so the bulk
    /// startup path must keep every offset it installs.
    #[test]
    fn registering_accounts_at_startup_still_staggers_them() {
        let (mut s, c) = sched();
        let mut cache = HashMap::new();
        let accounts = [account("a", false), account("b", false), account("c", false)];
        register_accounts(&mut s, &accounts, &mut cache, &|_| None);

        let stagger = PollPolicy::default().stagger();
        assert!(stagger > TimeDelta::zero(), "a zero stagger would make this test catch nothing");
        assert_eq!(s.next_wake("a").unwrap(), c.now());
        assert_eq!(s.next_wake("b").unwrap(), c.now() + stagger, "the startup burst is back");
        assert_eq!(s.next_wake("c").unwrap(), c.now() + stagger * 2, "the startup burst is back");
    }

    /// §7.2 is one strike, and a nudge is not a remedy. On the only shipped
    /// call path `register_authenticated` has already cleared the quarantine,
    /// so this pins the exclusion for whatever calls it next.
    ///
    /// The assertion is on `next_wake`, **not** on `due()`: `due()` re-checks
    /// `quarantined` itself, so it answers "empty" even with the exclusion in
    /// `Entry::pull_forward` deleted — the same blind spot
    /// `a_remedy_makes_a_backed_off_account_due_again_without_breaking_the_floor`
    /// records. The backoff earned below is what makes the move visible at all:
    /// `record_failure(AuthDead)` returns before touching `next_due_at`, so
    /// without the preceding network failures the schedule is already at `now`
    /// and nothing could move.
    #[test]
    fn a_quarantined_account_is_not_made_due_by_the_registration_nudge() {
        let (mut s, c) = sched();
        s.add("a");
        for _ in 0..4 {
            assert!(s.begin_poll("a"));
            s.record_failure("a", FailureKind::Network);
            s.end_poll("a");
        }
        s.record_failure("a", FailureKind::AuthDead);
        let before = s.next_wake("a").unwrap();
        assert!(
            before > c.now() + TimeDelta::seconds(PollPolicy::MIN_INTERVAL_SECS),
            "premise: the backoff must sit beyond the floor, or the nudge could not move it"
        );

        s.make_due_now("a");

        assert_eq!(s.next_wake("a").unwrap(), before, "a quarantined account was rescheduled");
        c.advance_secs(100_000);
        assert!(s.due().is_empty(), "a quarantined account was polled again");
    }

    /// §6.2: the wait after a 429 is the server's, not a local preference. The
    /// nudge is a scheduling hint, so it loses — the same rule
    /// `changing_the_interval_does_not_shorten_a_server_ordered_backoff` pins
    /// for the settings path.
    #[test]
    fn a_server_ordered_throttle_outlasts_the_registration_nudge() {
        let (mut s, c) = sched();
        s.add("a");
        assert!(s.begin_poll("a"));
        s.end_poll("a");
        let started = c.now();
        s.record_throttle("a", 300);

        s.make_due_now("a");

        // Again on `next_wake`: `due()` re-checks `throttled_until` on its own,
        // so it cannot see this schedule being dragged inside the server's wait.
        assert_eq!(
            s.next_wake("a").unwrap(),
            started + TimeDelta::seconds(300),
            "the nudge overrode the server's Retry-After"
        );
        assert_eq!(
            s.state("a"),
            Some(AccountState::Throttled { until: started + TimeDelta::seconds(300) }),
            "the throttle itself must survive too"
        );
        c.advance_secs(301);
        assert_eq!(s.due(), vec!["a"], "and the account must come back once the wait expires");
    }
}