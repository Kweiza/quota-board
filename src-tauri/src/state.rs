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
    /// webview that never reports cannot freeze polling — only an explicit
    /// "hidden" can, and the next report or window show undoes it within one
    /// tick. Combined with the window's own state by the loop, which is the
    /// single writer of `Scheduler::set_visible`.
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

    /// A panic here skips `end_poll`, but the scheduler reclaims the slot after
    /// `IN_FLIGHT_RECLAIM_SECS`.
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
                let Some(kind) = FailureKind::from_usage_error(&e) else {
                    unreachable!("Throttled is the only None and it is handled above")
                };
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

        // §6.3, recomputed every tick so a missed or bogus edge self-heals.
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
