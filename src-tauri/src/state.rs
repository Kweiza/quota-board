use quoata_core::accounts::AccountStore;
use quoata_core::auth::pkce::AuthConfig;
use quoata_core::auth::stored::{ensure_fresh, RefreshLocks};
use quoata_core::auth::token::ReqwestHttp;
use quoata_core::scheduler::{persist_quarantine, FailureKind, Scheduler, SystemClock};
use quoata_core::secrets::{SecretError, SecretStore};
use quoata_core::snapshots::{fingerprint, save as save_snapshot};
use quoata_core::usage::http::{fetch_usage_at, UsageError};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;

/// **Lock order: `scheduler` before `accounts`, never the reverse, and never
/// hold either across `ensure_fresh` or `fetch_usage_at`.** Both are `tokio`
/// mutexes and neither is reentrant. Task 18 adds commands that touch the same
/// two stores; a command taking them in the other order deadlocks against the
/// polling loop. `crates/core/src/accounts.rs:36-47` carries the matching
/// warning for the store itself: two open `AccountStore` instances silently
/// discard each other's writes, so the one in this struct is the sole owner.
pub struct AppState {
    pub scheduler: Mutex<Scheduler<SystemClock>>,
    pub accounts: Mutex<AccountStore>,
    pub secrets: Arc<dyn SecretStore>,
    pub http: ReqwestHttp,
    pub cfg: AuthConfig,
    /// Per-account refresh locks (Task 10b). **Exactly one instance may exist
    /// in the whole application** — two copies serialize nothing, because each
    /// hands out its own mutex (auth/stored.rs:76-84).
    pub refresh_locks: RefreshLocks,
    /// §6.1's global concurrency of 1. `begin_poll` does **not** provide it:
    /// measured, `begin_poll("b")` succeeds while a is in flight, because it
    /// looks up one `Entry` by uuid and there is no process-wide counter
    /// anywhere in the scheduler. `due()` bounds only the polling loop, via
    /// `.take(1)`. This permit is what actually enforces the rule where the
    /// loop and the manual path meet.
    ///
    /// **`pub(crate)` only so `main.rs` can build the struct — never lock it
    /// directly.** `poll_one` and `try_poll_one` are the two entry points, and
    /// the difference between them (blocking versus `try_lock`) is the whole
    /// reason the permit exists. A third caller taking it by hand would
    /// reintroduce the case they exist to separate.
    pub(crate) poll_permit: Mutex<()>,
    /// §9.1's OS cache directory, resolved once in `setup()`. Resolving it per
    /// call would need an `AppHandle` the poll path does not have — which is
    /// why the earlier draft could only persist from the timer loop, so a
    /// snapshot obtained through `refresh_account` was never written.
    pub snapshots_path: PathBuf,
    /// §4.3's URL-injection seam, carried one layer up. Without it nothing in
    /// this path can ever be exercised against a mock, because `fetch_usage`
    /// hardcodes §5.1's production URL (usage/http.rs:6, :22-27). This is what
    /// makes Step 11 executable at all. **Do not add a trait to `usage`** —
    /// CLAUDE.md and design.md §4.3 forbid it; the URL is the seam.
    pub usage_url: String,
    /// §6.3. What the widget webview last reported. Defaults to `true` so a
    /// webview that never reports at all cannot freeze polling. Combined with
    /// the window's own state by the loop, which is the single writer of
    /// `Scheduler::set_visible`.
    ///
    /// **Only the webview can clear a `false` here — showing the window cannot.**
    /// The loop ANDs this with the window signals, so once this is `false` no
    /// amount of window state makes the account due again. That is why
    /// `src/main.ts` re-reports on a heartbeat rather than on edges alone: a
    /// single dropped or rejected `set_widget_visible(true)` would otherwise
    /// pin polling off permanently and silently, with the widget still showing
    /// its last values. The heartbeat bounds that failure to one interval.
    pub webview_visible: AtomicBool,
}

/// Stands in for the token store when §9.2's keychain probe fails and the
/// encrypted-file fallback cannot be opened (it needs a passphrase prompt no
/// task has built yet — see Step 9). Every account then renders
/// `SECRETS_LOCKED`, which is §7.1's state carrying the "unlock" affordance.
/// The alternatives were a panic and a blank widget; both are worse.
pub struct LockedStore;

impl SecretStore for LockedStore {
    fn put(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
        Err(SecretError::Locked("no token store is open".into()))
    }
    fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, SecretError> {
        Err(SecretError::Locked("no token store is open".into()))
    }
    fn delete(&self, _k: &str) -> Result<bool, SecretError> {
        Err(SecretError::Locked("no token store is open".into()))
    }
    fn describe(&self) -> String {
        "locked (no store opened)".to_string()
    }
}

impl AppState {
    /// The polling loop's entry point: waits for the global permit.
    pub async fn poll_one(&self, uuid: &str) {
        let _permit = self.poll_permit.lock().await;
        self.poll_guarded(uuid).await;
    }

    /// The manual path's entry point. `try_lock` rather than `lock`: blocking a
    /// UI command behind a poll that can legitimately run 150 seconds (the
    /// `IN_FLIGHT_RECLAIM_SECS` derivation, scheduler.rs:181-206) is the other
    /// failure mode. `false` means "did not run".
    pub async fn try_poll_one(&self, uuid: &str) -> bool {
        match self.poll_permit.try_lock() {
            Ok(_permit) => {
                self.poll_guarded(uuid).await;
                true
            }
            Err(_) => false,
        }
    }

    async fn poll_guarded(&self, uuid: &str) {
        // Per-account exclusion, and the reclaim that covers an early return.
        if !self.scheduler.lock().await.begin_poll(uuid) {
            return;
        }
        self.poll_claimed(uuid).await;
        self.scheduler.lock().await.end_poll(uuid);
    }

    /// **A panic here stops all polling for the life of the process.** This is
    /// awaited inside the single task spawned in `main.rs`, so a panic unwinds
    /// that task, its `JoinHandle` is dropped unexamined, and no account is ever
    /// polled again. `IN_FLIGHT_RECLAIM_SECS` does not rescue it: the reclaim
    /// frees this account's claim, but nothing is left running to take it.
    /// `scheduler.rs`'s `record_failure` says the same thing of its own
    /// arithmetic — "a panic in the polling loop takes the whole widget down".
    ///
    /// Nothing below may therefore panic on input it does not control, which is
    /// why the unclassifiable-error arm degrades instead of asserting.
    async fn poll_claimed(&self, uuid: &str) {
        // Task 10b owns read -> refresh -> write. Inlining it here would let
        // scheduler polls and manual refreshes invalidate each other's refresh
        // tokens (§10.5).
        let fresh = match ensure_fresh(
            &self.http,
            &self.cfg,
            self.secrets.as_ref(),
            &self.refresh_locks,
            uuid,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                // §7.1: "There is one mapping, in the core, and every caller
                // uses it rather than deriving its own." Not re-written here.
                let kind = FailureKind::from_stored_token_error(&e);
                self.record(uuid, kind).await;
                return;
            }
        };

        if let Err(e) = &fresh.persisted {
            // The rotation succeeded and the token is live. Do not degrade the
            // state — only the next process start will miss this value. The
            // error is printed verbatim because the three cases differ:
            // `Locked` recovers on unlock, `Backend` is usually transient, and
            // **`TooLong` is permanent** — that blob will never fit, so every
            // restart will demand a re-login until someone is told why (§9.3).
            eprintln!("{uuid}: the rotated token could not be persisted: {e}");
        }

        match fetch_usage_at(&self.http, &self.usage_url, &fresh.tokens.access_token).await {
            Ok(windows) => {
                // The fingerprint is taken from the token that produced *this*
                // fetch, not re-read from the store afterwards.
                let fp = fingerprint(&fresh.tokens.access_token);
                let snap = {
                    let mut sched = self.scheduler.lock().await;
                    sched.record_success(uuid, windows);
                    sched.snapshot(uuid, &fp)
                };
                // Lock released before touching the filesystem.
                if let Some(snap) = snap {
                    let path = self.snapshots_path.clone();
                    let id = uuid.to_string();
                    let written = tauri::async_runtime::spawn_blocking(move || {
                        save_snapshot(&path, &id, &snap)
                    })
                    .await;
                    // Not swallowed with `let _ =`: a cache that silently never
                    // writes is indistinguishable from one that works until the
                    // next restart.
                    if let Ok(Err(e)) = written {
                        eprintln!("{uuid}: the snapshot cache could not be written: {e}");
                    }
                }
            }
            // `Throttled` is the one variant `from_usage_error` returns `None`
            // for, by design: folding it into `record_failure` would discard the
            // `Retry-After` that §6.2 makes the entire input to the policy.
            Err(UsageError::Throttled { retry_after_secs }) => {
                self.scheduler.lock().await.record_throttle(uuid, retry_after_secs)
            }
            Err(e) => {
                // `Throttled` is the only `None` today, and it is handled
                // above — so this fallback is unreachable as the code stands.
                // It is a fallback rather than an `unreachable!` because that
                // invariant is hand-maintained across two crates: adding a
                // `UsageError` variant that also returns `None` is a one-line
                // change in `usage::http` that would turn this into a panic,
                // and a panic here silently ends polling for the whole process
                // (see this function's doc comment). Degrading to `Network`
                // keeps the last value with its age (§7.1) and retries with
                // backoff, which is the right answer for a fetch that failed
                // without telling us the credential is bad.
                let kind = FailureKind::from_usage_error(&e).unwrap_or_else(|| {
                    eprintln!(
                        "{uuid}: unclassifiable usage error, treating it as a network failure: {e}"
                    );
                    FailureKind::Network
                });
                self.record(uuid, kind).await;
            }
        }
    }

    async fn record(&self, uuid: &str, kind: FailureKind) {
        self.scheduler.lock().await.record_failure(uuid, kind);
        if kind == FailureKind::AuthDead {
            let mut accounts = self.accounts.lock().await;
            if let Err(e) = persist_quarantine(&mut accounts, uuid) {
                eprintln!("{uuid}: the quarantine could not be persisted: {e}");
            }
        }
    }
}

pub async fn poll_loop(handle: tauri::AppHandle) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    // The default is `Burst`: after a poll that legitimately ran 150 seconds,
    // ~30 accumulated ticks fire back to back. Harmless — §6.1's floor is
    // structural inside `due()` (scheduler.rs:334) — but pointless churn.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let state = handle.state::<AppState>();

        // §6.3. The two window signals below are **polled**, so a missed or
        // bogus window edge self-heals on the next tick. The webview signal
        // they are ANDed with is **pushed**, and does not: nothing here can
        // clear a stale `false`, so its self-healing has to come from the
        // webview end, where `src/main.ts` re-reports on a heartbeat.
        //
        // **`WindowEvent::Focused` is deliberately not used.** The widget is
        // declared `focus: false, alwaysOnTop, skipTaskbar` (tauri.conf.json:
        // 27-30) — being unfocused is its normal condition — and `due()`
        // returns an empty vec unconditionally while `!visible`
        // (scheduler.rs:311-314). Mapping focus loss to `set_visible(false)`
        // freezes polling the moment the user clicks anything else, which is
        // the exact inversion of §6.3's rationale.
        let shown = handle.get_webview_window("widget").is_none_or(|w| {
            w.is_visible().unwrap_or(true) && !w.is_minimized().unwrap_or(false)
        });
        let visible = shown && state.webview_visible.load(Ordering::Relaxed);
        state.scheduler.lock().await.set_visible(visible);

        let due: Vec<String> = state.scheduler.lock().await.due();
        for uuid in due {
            state.poll_one(&uuid).await;
            let _ = handle.emit("usage://updated", ());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quoata_core::accounts::Account;
    use quoata_core::model::AccountState;
    use quoata_core::scheduler::PollPolicy;
    use quoata_core::secrets::timeout::TimeoutStore;
    use std::time::{Duration, Instant};

    /// Every `SecretStore` read blocks for `nap`, the way the macOS keychain
    /// does while `securityd` waits on a SecurityAgent prompt nobody can answer.
    ///
    /// **Finite, not infinite.** Twenty seconds stands in for "indefinitely"
    /// while still letting the back-test of this test *fail* rather than hang —
    /// a hanging test proves nothing and cannot be reported.
    struct SleepingStore(Duration);

    impl SecretStore for SleepingStore {
        fn put(&self, _k: &str, _v: &[u8]) -> Result<(), SecretError> {
            std::thread::sleep(self.0);
            Ok(())
        }
        fn get(&self, _k: &str) -> Result<Option<Vec<u8>>, SecretError> {
            std::thread::sleep(self.0);
            Ok(None)
        }
        fn delete(&self, _k: &str) -> Result<bool, SecretError> {
            std::thread::sleep(self.0);
            Ok(false)
        }
        fn describe(&self) -> String {
            "sleeping (test only)".to_string()
        }
    }

    /// Unique per call. The harness runs tests as threads in one process, so a
    /// pid alone collides — the same trap `accounts.rs`'s test helper documents.
    /// A counter is used rather than `rand` so this needs no new dependency on
    /// `src-tauri` for a test.
    fn tmp(kind: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("quoata-state-{kind}-{}-{n}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn account(uuid: &str) -> Account {
        Account {
            uuid: uuid.into(),
            display_label: uuid.into(),
            email: format!("{uuid}@example.invalid"),
            created_at: chrono::Utc::now(),
            last_ok_at: None,
            quarantined: false,
            sort_order: 0,
        }
    }

    /// Builds an `AppState` around `secrets`, with accounts a and b registered.
    /// No Tauri window or `AppHandle` is involved — `AppState` is a plain
    /// struct, which is what makes the polling path testable at all.
    fn app_state(secrets: Arc<dyn SecretStore>) -> AppState {
        let accounts_path = tmp("accounts");
        let mut accounts = AccountStore::load(&accounts_path).unwrap();
        let mut scheduler = Scheduler::new(PollPolicy::with_interval_secs(300), SystemClock);
        for id in ["a", "b"] {
            accounts.upsert(account(id)).unwrap();
            scheduler.add(id);
        }
        AppState {
            scheduler: Mutex::new(scheduler),
            accounts: Mutex::new(accounts),
            secrets,
            http: quoata_core::auth::token::ReqwestHttp::new().unwrap(),
            // Unreachable in these tests: the store fails before any request.
            cfg: AuthConfig {
                token_url: "http://127.0.0.1:1/never".into(),
                ..AuthConfig::default()
            },
            refresh_locks: RefreshLocks::default(),
            poll_permit: Mutex::new(()),
            snapshots_path: tmp("snapshots"),
            usage_url: "http://127.0.0.1:1/never".into(),
            webview_visible: AtomicBool::new(true),
        }
    }

    /// **Critical regression guard.** A credential store that never answers
    /// must not wedge the polling loop.
    ///
    /// The failure this pins is not hypothetical: measured on macOS 15.6, an
    /// unbounded keychain read left the app blocked in
    /// `SecKeychainFindGenericPassword -> mach_msg` forever. Because that call
    /// is made from the single task driving `poll_loop`, `poll_one` held
    /// `poll_permit` for the life of the process — so no other account was ever
    /// polled and every manual refresh got `false` from `try_poll_one` and
    /// answered with an unchanged state, with no diagnostic anywhere.
    ///
    /// The assertion is therefore about **both** accounts and about elapsed
    /// time, not just about account a's own state.
    #[tokio::test]
    async fn the_poll_path_survives_a_store_that_never_answers() {
        let secrets: Arc<dyn SecretStore> = Arc::new(
            TimeoutStore::spawn(Duration::from_millis(200), || {
                Ok(Box::new(SleepingStore(Duration::from_secs(20))) as Box<dyn SecretStore>)
            })
            .expect("the store opens promptly"),
        );
        let state = app_state(secrets);

        let started = Instant::now();
        state.poll_one("a").await;
        // The second account is the real assertion: it only gets here if a
        // released `poll_permit`.
        state.poll_one("b").await;
        let waited = started.elapsed();

        assert!(
            waited < Duration::from_secs(5),
            "two polls took {waited:?} — the blocking store wedged the loop"
        );

        let sched = state.scheduler.lock().await;
        for id in ["a", "b"] {
            assert_eq!(
                sched.state(id),
                Some(AccountState::SecretsLocked),
                "{id} should have recorded a locked store and moved on"
            );
        }
        // And the loop can still claim work afterwards — the permit was
        // released, not merely bypassed.
        drop(sched);
        assert!(
            state.try_poll_one("a").await,
            "the global poll permit was never released"
        );
    }

    /// The bound must not cost anything when the store behaves.
    ///
    /// **The healthy store is wrapped, exactly as `main.rs` wraps it.** An
    /// earlier version passed the `MemoryStore` in bare, which meant no
    /// mutation of the wrapper could ever fail this test — it was verifying the
    /// poll path, not the isolation that now sits on it. A wrapper that failed
    /// closed would take every account down rather than degrade one, and that
    /// is the regression this pins.
    #[tokio::test]
    async fn a_healthy_store_still_reaches_the_credential_check_through_the_wrapper() {
        let secrets: Arc<dyn SecretStore> = Arc::new(
            TimeoutStore::spawn(Duration::from_secs(5), || {
                Ok(Box::new(quoata_core::secrets::MemoryStore::default()) as Box<dyn SecretStore>)
            })
            .expect("the store opens promptly"),
        );
        // No token is stored, so `ensure_fresh` reports `Missing` -> AUTH_DEAD
        // without ever blocking. What matters is that it is reached at all: a
        // timed-out store would read `SECRETS_LOCKED` instead.
        let state = app_state(secrets);
        state.poll_one("a").await;
        assert_eq!(
            state.scheduler.lock().await.state("a"),
            Some(AccountState::AuthDead),
            "a healthy store must reach the credential check, not report a locked store"
        );
    }
}
