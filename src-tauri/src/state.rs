use chrono::Utc;
use quota_core::accounts::{Account, AccountStore};
use quota_core::auth::pkce::PendingAuth;
use quota_core::auth::stored::{ensure_fresh, RefreshLocks};
use quota_core::auth::token::ReqwestHttp;
use quota_core::provider::{Provider, ProviderSpec};
use quota_core::scheduler::{
    persist_last_ok, persist_quarantine, FailureKind, Scheduler, SystemClock,
};
use quota_core::secrets::{SecretError, SecretStore};
use quota_core::settings::SettingsStore;
use quota_core::snapshots::{fingerprint, save as save_snapshot};
use quota_core::usage::http::{fetch_usage_captured_at, UsageError};
use quota_core::usage::raw::{RawLog, RawResponse};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;

/// **Lock order: `scheduler` before `accounts`, never the reverse, and never
/// hold either across `ensure_fresh` or `fetch_usage_captured_at`.** Both are `tokio`
/// mutexes and neither is reentrant. Task 18 adds commands that touch the same
/// two stores; a command taking them in the other order deadlocks against the
/// polling loop. `crates/core/src/accounts.rs:36-47` carries the matching
/// warning for the store itself: two open `AccountStore` instances silently
/// discard each other's writes, so the one in this struct is the sole owner.
///
/// The `secrets` lock added in Task 18 is deliberately **not** part of that
/// order. It is a leaf: taken alone, holding nothing else while held, released
/// before any other acquisition — and the `!Send` guard below is what makes
/// that mechanical rather than a convention. `settings` is not part of it
/// either: `set_poll_interval` takes it and releases it before touching
/// `scheduler`.
pub struct AppState {
    pub scheduler: Mutex<Scheduler<SystemClock>>,
    pub accounts: Mutex<AccountStore>,
    /// §9.1's settings file, and the only live instance of it.
    pub settings: Mutex<SettingsStore>,
    /// §9.2's token store, swappable at runtime.
    ///
    /// **`pub(crate)` and never locked directly — use `secrets()`,
    /// `install_store()`, `secrets_status()` and `store_kind()`.** The same
    /// convention as `poll_permit` below, and for a sharper reason: a read
    /// guard held across `ensure_fresh`'s awaits would make `unlock_secrets`
    /// block behind a poll that can legitimately run 150 seconds
    /// (`IN_FLIGHT_RECLAIM_SECS` in `scheduler`). The accessor hands out
    /// an `Arc` clone instead, so a poll finishes against the store it started
    /// with and an unlock never waits on one.
    ///
    /// A `std::sync` lock rather than a `tokio` one on purpose, and the
    /// compiler is what enforces it: `std::sync::RwLockReadGuard` is `!Send`,
    /// so a guard held across an `await` makes the future non-`Send` and
    /// `tauri::async_runtime::spawn` (`F: Future + Send`), which is how
    /// `poll_loop` is started in `main.rs`'s `setup`, refuses to compile it.
    /// Measured: "the trait `Send` is not implemented for
    /// `std::sync::RwLockReadGuard<'_, SecretsHandle>`". A `tokio::sync::RwLock`
    /// here would compile silently.
    pub(crate) secrets: RwLock<SecretsHandle>,
    /// §5.5's "retain the raw JSON so it can be inspected in a debug window",
    /// keyed by uuid, **already masked** (`usage::raw`).
    ///
    /// **In memory only.** It is deliberately not merged into
    /// `snapshots_path`: §9.1 puts that cache in a plain file on disk, and a
    /// whole response body carries fields this app does not read and therefore
    /// has not reasoned about. Losing the debug body on restart is the correct
    /// trade.
    ///
    /// **There is no entry cap.** The key set is a subset of the registered
    /// accounts — `record` is reached only from `poll_claimed` with a
    /// scheduler-owned uuid — and `forget_raw` drops an entry when the account
    /// is deleted. `crates/core/src/snapshots.rs:73-86` is a uuid-keyed map with
    /// the same `save`/`remove` shape and no cap, for the same reason.
    ///
    /// Same `std::sync` rule as `secrets`: taken and released inside one
    /// statement, never across an `await`.
    pub(crate) last_raw: std::sync::Mutex<RawLog>,
    /// §10.3's manual-paste login, waiting for the user to bring a code back.
    ///
    /// Its `redirect_uri` is always the manual one, so `complete_login` needs no
    /// branch: `exchange_code` replays whatever is in here.
    ///
    /// **Written on every `begin_login`, not only when the loopback fails.**
    /// Two of the four ways the loopback can fail are detected in the webview —
    /// a `Callback::bind` that never happened and an `openUrl` that threw — and
    /// the webview cannot reach this field. Storing it up front is what lets
    /// all four failures share one paste path.
    ///
    /// Holding a login here does **not** hold `LOGIN_IN_FLIGHT`. Nothing is
    /// waiting once the loopback is abandoned, and a flag with no task behind it
    /// is the state `LoginGuard`'s comment exists to prevent. A second
    /// `begin_login` therefore replaces this value, and a code pasted from the
    /// replaced login is refused on its `state` — which is the correct answer,
    /// not a bug.
    ///
    /// Same `std::sync` rule as `secrets`: taken and released inside one
    /// statement, never across an `await`.
    pub(crate) pending_manual: std::sync::Mutex<Option<PendingAuth>>,
    pub http: ReqwestHttp,
    pub cfg: ProviderSpec,
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
    /// directly.** `poll_one` is the sole entry point. There used to be a
    /// second, `try_poll_one`, which `try_lock`ed so a manual refresh would
    /// never wait behind a poll; §6.4 removed it, because "did not run" reached
    /// the user as a press that silently changed nothing. A caller taking this
    /// by hand would bring that case straight back.
    pub(crate) poll_permit: Mutex<()>,
    /// §9.1's OS cache directory, resolved once in `setup()`. Resolving it per
    /// call would need an `AppHandle` the poll path does not have — which is
    /// why the earlier draft could only persist from the timer loop, so a
    /// snapshot obtained through `refresh_account` was never written.
    pub snapshots_path: PathBuf,
    /// §4.3's URL-injection seam, carried one layer up. Without it nothing in
    /// this path can ever be exercised against a mock, because `fetch_usage`
    /// hardcodes §5.1's production URL (`USAGE_URL` in usage/http.rs). This is
    /// what makes Step 11 executable at all. **Do not add a trait to `usage`**
    /// — CLAUDE.md and design.md §4.3 forbid it; the URL is the seam.
    ///
    /// Anthropic's half of the pair. A single field here — before this task —
    /// sent every account through the same URL regardless of its provider, so
    /// a Codex account would have been queried against `api.anthropic.com`
    /// with an OpenAI access token. See `openai_usage_url` below.
    pub usage_url: String,
    /// Codex's half of the pair. Kept as its own field rather than a map:
    /// `Provider` is "a closed set of two" (provider.rs's own doc comment),
    /// and a `HashMap` would buy nothing over one field per variant while
    /// making a typo'd key a runtime `None` instead of a compile error.
    pub openai_usage_url: String,
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

/// The token store together with what kind of store it is.
///
/// One value behind one lock so the two can never disagree. A separate
/// `store_kind` field would have to be updated in lockstep with the store and
/// eventually would not be — and the settings window branches on `kind` to
/// choose which of docs/design.md §9.2's two remedies to offer, so a stale
/// value there is a *wrong* remedy, not a cosmetic one.
pub struct SecretsHandle {
    pub store: Arc<dyn SecretStore>,
    pub kind: StoreKind,
}

/// Which store is installed, and therefore which remedy §7.1's
/// `SECRETS_LOCKED` actually carries.
///
/// docs/design.md:587-588 requires exactly this: "`secrets` must distinguish
/// three states and surface each differently: `NO_BACKEND` / `LOCKED` /
/// `NOT_FOUND`." §9.2 keeps `NO_BACKEND` off the account-state axis entirely
/// (:592-594 — "Not surfaced as an account state"); this build nevertheless
/// renders both it and `LOCKED` as `SECRETS_LOCKED`, because the passphrase
/// prompt §9.2 asks for cannot be raised from `setup()`, where the store is
/// opened and no window exists yet. That deviation makes the distinction
/// *more* load-bearing, not less: the two states carry different remedies and
/// nothing else on the wire tells them apart, so a single "is it locked"
/// boolean collapses the one distinction the design document forbids
/// collapsing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    /// §9.2's first choice: the OS keychain opened and answered its canary.
    Keychain,
    /// §9.2's fallback: the encrypted file is open.
    EncryptedFile,
    /// §9.2's `NO_BACKEND`. No credential store is registered on this machine
    /// at all — the passphrase fallback is the remedy.
    NoBackend,
    /// §9.2's `LOCKED`. A keychain exists but did not answer. A passphrase is
    /// the *wrong* answer here: it would open a different, empty store.
    KeychainLocked,
}

impl StoreKind {
    /// Written exhaustively rather than with a `_` arm, matching
    /// `FailureKind`'s own rule: a `SecretError` variant added later must be a
    /// compile error here, not a silent guess. `Backend` and `TooLong` have no
    /// passphrase remedy either — a `Backend` from an open means "the store
    /// thread would not start or stopped" (secrets/timeout.rs:105, :117).
    pub fn from_open_error(e: &SecretError) -> Self {
        match e {
            SecretError::NoBackend(_) => StoreKind::NoBackend,
            SecretError::Locked(_) | SecretError::Backend(_) | SecretError::TooLong { .. } => {
                StoreKind::KeychainLocked
            }
        }
    }
}

/// Stands in for the token store when §9.2's keychain probe fails and no
/// fallback has been opened yet. Every account then renders `SECRETS_LOCKED`,
/// which is §7.1's state carrying the "unlock" affordance — and that click now
/// leads somewhere: the settings window's passphrase form calls
/// `unlock_secrets`, which opens §9.2's encrypted file and swaps it in through
/// `AppState::install_store`. It is only offered when `StoreKind` says
/// `NoBackend`: a keychain that merely did not answer arrives as
/// `KeychainLocked`, and a passphrase there would open a different, empty
/// store. The alternatives were a panic and a blank widget; both are worse.
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
    /// The token store in effect right now.
    ///
    /// A poisoned lock is recovered from rather than panicked on:
    /// `poll_claimed`'s doc comment says a panic on that path ends polling for
    /// the life of the process, and what this lock protects is two fields
    /// always written together — there is no torn state to refuse.
    pub fn secrets(&self) -> Arc<dyn SecretStore> {
        Arc::clone(&self.secrets.read().unwrap_or_else(|e| e.into_inner()).store)
    }

    /// Which store is installed right now.
    pub fn store_kind(&self) -> StoreKind {
        self.secrets.read().unwrap_or_else(|e| e.into_inner()).kind
    }

    /// Installs a store opened by `unlock_secrets` (§9.2) and returns the one
    /// it replaced, so the caller drops it after the write guard is released.
    ///
    /// Dropping the **last** handle to a replaced `TimeoutStore` closes its job
    /// channel, which is the only thing that lets a worker stranded inside a
    /// wedged keychain call retire (secrets/timeout.rs:97-98). A poll already in
    /// flight holds a clone until it finishes (`poll_claimed`'s `ensure_fresh`
    /// call in this file), so the thread retires then, not at the moment of the
    /// swap.
    ///
    /// The old store's `stuck` latch is never cleared in place and there is no
    /// API to do so. It is cleared only by that store's own worker completing a
    /// job (timeout.rs:100-102), which by definition cannot happen while the
    /// worker is stranded — the next job would queue behind the wedged one and
    /// time out again. Replacing the whole store is what recovers, and the new
    /// `TimeoutStore` starts with its own `stuck: false` (timeout.rs:76).
    pub fn install_store(
        &self,
        store: Arc<dyn SecretStore>,
        kind: StoreKind,
    ) -> Arc<dyn SecretStore> {
        let mut w = self.secrets.write().unwrap_or_else(|e| e.into_inner());
        w.kind = kind;
        std::mem::replace(&mut w.store, store)
    }

    /// `(description, kind)` for the settings window. `describe()` is the one
    /// `SecretStore` method safe to call from a UI command: `TimeoutStore`
    /// answers it from a string captured when the store opened
    /// (secrets/timeout.rs:173-177), unlike `get`/`delete`, which block a real
    /// thread.
    pub fn secrets_status(&self) -> (String, StoreKind) {
        let r = self.secrets.read().unwrap_or_else(|e| e.into_inner());
        (r.store.describe(), r.kind)
    }

    /// §5.5's capture. **Never `unwrap()`s the lock**: this runs on the polling
    /// path, and `poll_claimed`'s doc comment below records that a panic here
    /// ends polling for the life of the process. The body arrives already
    /// masked and already bounded — `RawResponse::capture` is the only
    /// constructor and it does both, so nothing here can forget either.
    fn record_raw(&self, uuid: &str, raw: RawResponse) {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).record(uuid, raw);
    }

    /// §5.5. `None` means this account has not been polled successfully since
    /// the process started — not "there was no body".
    pub fn last_raw_for(&self, uuid: &str) -> Option<RawResponse> {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).get(uuid).cloned()
    }

    /// Dropped together with the account. With no entry cap this is the only
    /// bound on the key set, so the call at `remove_account` is not optional.
    pub fn forget_raw(&self, uuid: &str) {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).remove(uuid);
    }

    /// §6.1 + §8.4. Applies a new polling interval to the **running** scheduler.
    ///
    /// **Persist first, then swap the live policy.** If the write fails the
    /// running interval is left alone, so the process can never poll at a
    /// cadence the settings file does not record.
    ///
    /// The two locks are taken sequentially, never nested, so this cannot take
    /// part in the deadlock this struct's doc comment warns about.
    ///
    /// The policy comes from the store that just accepted the value, never from
    /// a second `PollPolicy::with_interval_secs` call here: `poll_policy`'s own
    /// doc comment calls itself "the one derivation" of the running policy, and
    /// a copy of it on this side would be free to disagree the moment the
    /// policy grows a field the stored value feeds.
    pub async fn set_poll_interval(&self, secs: i64) -> Result<i64, String> {
        let (effective, policy) = {
            let mut settings = self.settings.lock().await;
            let effective = settings.set_poll_interval_secs(secs).map_err(|e| e.to_string())?;
            (effective, settings.poll_policy())
        };
        self.scheduler.lock().await.set_policy(policy);
        Ok(effective)
    }

    /// Registers a freshly authenticated account (§10.3's flow, completed).
    ///
    /// **This and `list_accounts` in `commands.rs` are the only two places
    /// in the application that hold both stores at once**, so the lock order
    /// documented on this struct is a two-party agreement and nothing else.
    /// It lives here rather than inside the command because a
    /// `#[tauri::command]` body needs an `AppHandle` no test can build — see
    /// `the_two_stores_are_always_taken_in_the_same_order`.
    ///
    /// A re-login must clear the quarantine **without clearing the user's
    /// rename.** `AccountStore::upsert` preserves only `sort_order`
    /// (accounts.rs:71-83): everything else in the record is overwritten
    /// wholesale. Writing `display_label: email` here would therefore silently
    /// undo `rename_account` — and undo the reason `email` is on the wire at
    /// all (`AccountView`'s doc comment in `commands.rs`) — at the exact moment
    /// the user is trying to recover a quarantined account.
    pub async fn register_authenticated(
        &self,
        uuid: &str,
        email: &str,
    ) -> Result<(), quota_core::accounts::AccountError> {
        // Lock order: scheduler before accounts. See this struct's doc comment.
        let mut sched = self.scheduler.lock().await;
        let mut accounts = self.accounts.lock().await;

        let existing = accounts.list().iter().find(|a| a.account_id == uuid).cloned();
        accounts.upsert(Account {
            account_id: uuid.to_string(),
            provider: Provider::Anthropic,
            display_label: existing
                .as_ref()
                .map(|a| a.display_label.clone())
                .unwrap_or_else(|| email.to_string()),
            email: email.to_string(),
            created_at: existing.as_ref().map(|a| a.created_at).unwrap_or_else(Utc::now),
            last_ok_at: existing.as_ref().and_then(|a| a.last_ok_at),
            // Clearing this is the point of a re-login (§7.2).
            quarantined: false,
            // Overwritten by `upsert` either way: preserved for a known uuid,
            // set to the list length for a new one (accounts.rs:71-83).
            sort_order: 0,
        })?;

        // `Scheduler::add` returns immediately for a uuid it already holds, so
        // it alone would leave a quarantined entry AUTH_DEAD forever — and
        // Task 17 persists `quarantined`, so that now survives every restart.
        // Drop the entry and rebuild it.
        //
        // `Provider::Anthropic`: this login flow is Anthropic's OAuth exchange
        // — there is no Codex login path yet for it to be anything else, the
        // same reason `finish_manual_login` in `commands.rs` hardcodes it for
        // `token_key`.
        sched.remove(Provider::Anthropic, uuid);
        sched.add(Provider::Anthropic, uuid);
        // ...which hands the rebuilt entry `add`'s startup stagger, and — since
        // it goes to the end of `order` — the largest offset of the lot.
        // Measured on the device: the third account added through the settings
        // window sat on `Loading` for 30 seconds, the fourth for 45, and a
        // re-login (§7.2's remedy, with the user watching) always draws the
        // worst case. §6.1's stagger is about startup and about staying
        // de-synchronised over time; one deliberate registration is neither, and
        // §6.1's floor is untouched — see `make_due_now`.
        sched.make_due_now(Provider::Anthropic, uuid);
        Ok(())
    }

    /// The polling loop's entry point: waits for the global permit.
    pub async fn poll_one(&self, provider: Provider, uuid: &str) {
        let _permit = self.poll_permit.lock().await;
        self.poll_guarded(provider, uuid).await;
    }

    async fn poll_guarded(&self, provider: Provider, uuid: &str) {
        // Per-account exclusion, and the reclaim that covers an early return.
        if !self.scheduler.lock().await.begin_poll(provider, uuid) {
            return;
        }
        self.poll_claimed(provider, uuid).await;
        self.scheduler.lock().await.end_poll(provider, uuid);
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
    async fn poll_claimed(&self, provider: Provider, uuid: &str) {
        // Task 10b owns read -> refresh -> write. Inlining it here would let
        // scheduler polls and manual refreshes invalidate each other's refresh
        // tokens (§10.5).
        // One `Arc` clone taken before the await, so no lock is held across
        // one. A store swapped in mid-poll therefore takes effect from the
        // next poll, and this one finishes against the store it started with.
        let store = self.secrets();
        let fresh = match ensure_fresh(
            &self.http,
            &self.cfg,
            store.as_ref(),
            &self.refresh_locks,
            provider,
            uuid,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                // §7.1: "There is one mapping, in the core, and every caller
                // uses it rather than deriving its own." Not re-written here.
                let kind = FailureKind::from_stored_token_error(&e);
                self.record(provider, uuid, kind).await;
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

        // §5.5: capture before classifying, so the body that failed to parse —
        // the one the debug window exists for — is retained too.
        let usage_url = match provider {
            Provider::Anthropic => &self.usage_url,
            Provider::Openai => &self.openai_usage_url,
        };
        let fetched =
            fetch_usage_captured_at(&self.http, provider, usage_url, &fresh.tokens.access_token)
                .await;
        if let Some(raw) = fetched.raw {
            self.record_raw(uuid, raw);
        }
        let extra = fetched.extra;
        match fetched.outcome {
            Ok(windows) => {
                // The fingerprint is taken from the token that produced *this*
                // fetch, not re-read from the store afterwards.
                let fp = fingerprint(&fresh.tokens.access_token);
                let snap = {
                    let mut sched = self.scheduler.lock().await;
                    sched.record_success(provider, uuid, windows, extra);
                    sched.snapshot(provider, uuid, &fp)
                };
                // Taken from the snapshot rather than read off the clock again,
                // so the file and the screen cannot disagree about when this
                // poll happened: `record_success` already stamped it.
                let polled_at = snap.as_ref().map(|s| s.fetched_at);
                // Lock released before touching the filesystem.
                if let Some(snap) = snap {
                    let path = self.snapshots_path.clone();
                    let id = uuid.to_string();
                    let written = tauri::async_runtime::spawn_blocking(move || {
                        save_snapshot(&path, provider, &id, &snap)
                    })
                    .await;
                    // Not swallowed with `let _ =`: a cache that silently never
                    // writes is indistinguishable from one that works until the
                    // next restart.
                    if let Ok(Err(e)) = written {
                        eprintln!("{uuid}: the snapshot cache could not be written: {e}");
                    }
                }
                // §9.1's metadata file. Taken *after* the scheduler lock is
                // released, in the scheduler-then-accounts order `record` uses:
                // the two are never held together, which is what the deadlock
                // test below pins.
                if let Some(at) = polled_at {
                    let mut accounts = self.accounts.lock().await;
                    if let Err(e) = persist_last_ok(&mut accounts, provider, uuid, at) {
                        eprintln!("{uuid}: the successful poll could not be recorded: {e}");
                    }
                }
            }
            // `Throttled` is the one variant `from_usage_error` returns `None`
            // for, by design: folding it into `record_failure` would discard the
            // `Retry-After` that §6.2 makes the entire input to the policy.
            Err(UsageError::Throttled { retry_after_secs }) => {
                self.scheduler.lock().await.record_throttle(provider, uuid, retry_after_secs)
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
                self.record(provider, uuid, kind).await;
            }
        }
    }

    async fn record(&self, provider: Provider, uuid: &str, kind: FailureKind) {
        self.scheduler.lock().await.record_failure(provider, uuid, kind);
        if kind == FailureKind::AuthDead {
            let mut accounts = self.accounts.lock().await;
            if let Err(e) = persist_quarantine(&mut accounts, provider, uuid) {
                eprintln!("{uuid}: the quarantine could not be persisted: {e}");
            }
        }
    }
}

pub async fn poll_loop(handle: tauri::AppHandle) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
    // The default is `Burst`: after a poll that legitimately ran 150 seconds,
    // ~30 accumulated ticks fire back to back. Harmless — §6.1's floor is
    // structural inside `due()`'s `last_attempt_at` check — but pointless
    // churn.
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
        // returns an empty vec unconditionally while `!visible` (its
        // `!self.visible` early return). Mapping focus loss to
        // `set_visible(false)` freezes polling the moment the user clicks
        // anything else, which is the exact inversion of §6.3's rationale.
        let shown = handle.get_webview_window("widget").is_none_or(|w| {
            w.is_visible().unwrap_or(true) && !w.is_minimized().unwrap_or(false)
        });
        let visible = shown && state.webview_visible.load(Ordering::Relaxed);
        state.scheduler.lock().await.set_visible(visible);

        let due: Vec<(Provider, String)> = state.scheduler.lock().await.due();
        for (provider, uuid) in due {
            state.poll_one(provider, &uuid).await;
            let _ = handle.emit("usage://updated", ());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use quota_core::accounts::Account;
    use quota_core::model::AccountState;
    use quota_core::scheduler::PollPolicy;
    use quota_core::secrets::timeout::TimeoutStore;
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
        p.push(format!("quota-state-{kind}-{}-{n}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn account(uuid: &str) -> Account {
        Account {
            account_id: uuid.into(),
            provider: Provider::Anthropic,
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
    ///
    /// The healthy default: a keychain-kind store and a throwaway settings
    /// file. Kept as its own function so the two polling tests that predate
    /// Task 18 read exactly as they did.
    pub(crate) fn app_state(secrets: Arc<dyn SecretStore>) -> AppState {
        app_state_with(secrets, StoreKind::Keychain, tmp("settings"))
    }

    /// The real builder, for the tests that need to say which kind of store is
    /// installed or where the settings file lives.
    pub(crate) fn app_state_with(
        secrets: Arc<dyn SecretStore>,
        kind: StoreKind,
        settings_path: PathBuf,
    ) -> AppState {
        let accounts_path = tmp("accounts");
        let mut accounts = AccountStore::load(&accounts_path);
        let mut scheduler = Scheduler::new(PollPolicy::with_interval_secs(300), SystemClock);
        for id in ["a", "b"] {
            accounts.upsert(account(id)).unwrap();
            scheduler.add(Provider::Anthropic, id);
        }
        AppState {
            scheduler: Mutex::new(scheduler),
            accounts: Mutex::new(accounts),
            settings: Mutex::new(SettingsStore::load(&settings_path)),
            secrets: RwLock::new(SecretsHandle { store: secrets, kind }),
            last_raw: std::sync::Mutex::new(RawLog::default()),
            pending_manual: std::sync::Mutex::new(None),
            http: quota_core::auth::token::ReqwestHttp::new().unwrap(),
            // Unreachable in these tests: the store fails before any request.
            cfg: ProviderSpec {
                token_url: "http://127.0.0.1:1/never".into(),
                ..Provider::Anthropic.spec()
            },
            refresh_locks: RefreshLocks::default(),
            poll_permit: Mutex::new(()),
            snapshots_path: tmp("snapshots"),
            usage_url: "http://127.0.0.1:1/never".into(),
            openai_usage_url: "http://127.0.0.1:1/never".into(),
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
    /// polled, and no manual refresh could produce a fresh number either: back
    /// then it gave up on the permit and answered with an unchanged state, and
    /// since §6.4 it waits on the permit instead, which here means forever.
    /// Neither shape left a diagnostic anywhere.
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
        state.poll_one(Provider::Anthropic, "a").await;
        // The second account is the real assertion: it only gets here if a
        // released `poll_permit`.
        state.poll_one(Provider::Anthropic, "b").await;
        let waited = started.elapsed();

        assert!(
            waited < Duration::from_secs(5),
            "two polls took {waited:?} — the blocking store wedged the loop"
        );

        let sched = state.scheduler.lock().await;
        for id in ["a", "b"] {
            assert_eq!(
                sched.state(Provider::Anthropic, id),
                Some(AccountState::SecretsLocked),
                "{id} should have recorded a locked store and moved on"
            );
        }
        // And the loop can still claim work afterwards — the permit was
        // released, not merely bypassed. Bounded rather than a bare `await`:
        // an unreleased permit would park this forever, and a test that hangs
        // reports nothing. This assertion has to be able to fail out loud.
        drop(sched);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), state.poll_one(Provider::Anthropic, "a"))
                .await
                .is_ok(),
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
                Ok(Box::new(quota_core::secrets::MemoryStore::default()) as Box<dyn SecretStore>)
            })
            .expect("the store opens promptly"),
        );
        // No token is stored, so `ensure_fresh` reports `Missing` -> AUTH_DEAD
        // without ever blocking. What matters is that it is reached at all: a
        // timed-out store would read `SECRETS_LOCKED` instead.
        let state = app_state(secrets);
        state.poll_one(Provider::Anthropic, "a").await;
        assert_eq!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::AuthDead),
            "a healthy store must reach the credential check, not report a locked store"
        );
    }

    /// **Critical regression guard, and it is measured.**
    ///
    /// `register_authenticated` and `list_accounts` (in `commands.rs`) are the
    /// only two places that hold both stores at once. If they disagree about
    /// the order, the pair wedges permanently and the polling loop freezes
    /// behind whichever one holds the scheduler — with **no diagnostic
    /// anywhere**, because the login half runs inside a
    /// `tauri::async_runtime::spawn` whose `JoinHandle` is dropped.
    ///
    /// The second task is a hand-written copy of `list_accounts`' order rather
    /// than the command itself, because a `#[tauri::command]` body needs a
    /// `State<'_, AppState>` no test can build. **If `list_accounts` ever
    /// changes its order, change it here too** — that is the whole agreement.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_two_stores_are_always_taken_in_the_same_order() {
        let state = Arc::new(app_state(Arc::new(quota_core::secrets::MemoryStore::default())));

        // **Which task starts first is load-bearing, and it is measured.**
        // `register_authenticated` has no await point between its two
        // acquisitions, so whenever it starts first it takes both and returns
        // before the other task is polled at all. Measured on this machine:
        // spawning the login task first and the listing task second, with the
        // two acquisitions in `register_authenticated` inverted, **passed 5
        // runs out of 5 in 0.28s** — a back-test that proves nothing. Parking
        // the listing task on `scheduler` and only then starting the login
        // task removes that race, because the login half is guaranteed to
        // reach its first acquisition while the listing half holds the
        // scheduler and is still asleep before its second one. With that
        // ordering the same inversion **failed 5 of 5 at the 3s timeout**, and
        // the restored code **passed 5 of 5 in 0.28s**.
        let listing = {
            let s = Arc::clone(&state);
            tokio::spawn(async move {
                // `list_accounts`' order: scheduler before accounts.
                let sched = s.scheduler.lock().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
                let accounts = s.accounts.lock().await;
                accounts.list().len() + usize::from(sched.state(Provider::Anthropic, "a").is_some())
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let login = {
            let s = Arc::clone(&state);
            tokio::spawn(async move { s.register_authenticated("a", "a@example.invalid").await })
        };

        let both = tokio::time::timeout(Duration::from_secs(3), async {
            let _ = login.await;
            let _ = listing.await;
        })
        .await;
        assert!(
            both.is_ok(),
            "the two paths deadlocked — they take `scheduler` and `accounts` in different orders"
        );
    }

    /// §7.2's quarantine must clear on a re-login **without** clearing the
    /// user's rename. `AccountStore::upsert` preserves only `sort_order`
    /// (accounts.rs:71-83), so every other field is whatever the caller wrote —
    /// and writing `display_label: email` there would undo `rename_account` at
    /// the exact moment the user is recovering a quarantined account.
    #[tokio::test]
    async fn a_re_login_clears_the_quarantine_but_keeps_the_users_rename() {
        let state = app_state(Arc::new(quota_core::secrets::MemoryStore::default()));
        let created = Utc::now() - chrono::TimeDelta::days(30);
        let last_ok = Utc::now() - chrono::TimeDelta::hours(2);
        {
            let mut accounts = state.accounts.lock().await;
            accounts
                .upsert(Account {
                    account_id: "a".into(),
                    provider: Provider::Anthropic,
                    display_label: "work".into(),
                    email: "old@example.invalid".into(),
                    created_at: created,
                    last_ok_at: Some(last_ok),
                    quarantined: true,
                    sort_order: 0,
                })
                .unwrap();
        }
        state.scheduler.lock().await.record_failure(Provider::Anthropic, "a", FailureKind::AuthDead);
        assert_eq!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::AuthDead),
            "premise: the account reads as quarantined before the re-login"
        );

        state.register_authenticated("a", "different@example.invalid").await.unwrap();

        {
            let accounts = state.accounts.lock().await;
            let a =
                accounts.list().iter().find(|x| x.account_id == "a").expect("the account is still there");
            assert_eq!(a.display_label, "work", "the re-login overwrote the user's rename");
            assert_eq!(
                a.email, "different@example.invalid",
                "the re-login did not record the newly authenticated email"
            );
            assert_eq!(a.created_at, created, "the re-login reset when the account was added");
            assert_eq!(
                a.last_ok_at,
                Some(last_ok),
                "the re-login discarded the last successful poll"
            );
            assert!(!a.quarantined, "the quarantine survived the re-login on disk");
        }
        assert_ne!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::AuthDead),
            "the scheduler entry still reads AUTH_DEAD after a successful re-login"
        );
    }

    /// **docs/design.md §9.2's fallback had never been exercised by the
    /// application.** `EncryptedFileStore` is well tested inside `crates/core`,
    /// but nothing in `src-tauri` had ever constructed one: it was reachable
    /// only through a passphrase prompt no task had built. This drives the whole
    /// unlock path — locked store, swap, poll again — against a real encrypted
    /// file on disk, with no keychain and no network.
    ///
    /// The final assertion is `Network`, not merely "not locked". "Not locked"
    /// would also pass if the swap had installed some other broken store;
    /// `Network` is reachable only by decrypting the token off disk, handing it
    /// to `ensure_fresh` without a refresh being due, and failing the usage
    /// fetch against 127.0.0.1:1.
    ///
    /// `EncryptedFileStore::open` runs Argon2 twice here, which is the bulk of
    /// this test's runtime. That is the intended cost, and it is why these
    /// three behaviours are one test rather than three.
    #[tokio::test]
    async fn unlocking_installs_the_encrypted_file_store_and_the_poll_path_uses_it() {
        use quota_core::auth::token::TokenSet;
        use quota_core::provider::token_key;
        use quota_core::secrets::encrypted_file::EncryptedFileStore;

        let path = tmp("tokens");
        // Not due for a refresh, so `ensure_fresh` answers straight from the
        // store and never touches the network (§10.5's five-minute skew).
        let tokens = TokenSet {
            access_token: "live-access".into(),
            refresh_token: "live-refresh".into(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            refresh_token_expires_at: Utc::now() + chrono::TimeDelta::days(30),
            scopes: vec![],
            client_id: "test".into(),
        };
        {
            let seed = EncryptedFileStore::open(&path, "correct horse").unwrap();
            seed.put(&token_key(Provider::Anthropic, "a"), &serde_json::to_vec(&tokens).unwrap())
                .unwrap();
        }

        let state = app_state_with(Arc::new(LockedStore), StoreKind::NoBackend, tmp("settings"));
        state.poll_one(Provider::Anthropic, "a").await;
        assert_eq!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::SecretsLocked),
            "premise: with no store open every account reads as locked (§7.1)"
        );

        let open_path = path.clone();
        let opened = TimeoutStore::spawn(Duration::from_secs(10), move || {
            EncryptedFileStore::open(&open_path, "correct horse")
                .map(|s| Box::new(s) as Box<dyn SecretStore>)
        })
        .expect("the encrypted-file fallback opens");
        drop(state.install_store(Arc::new(opened), StoreKind::EncryptedFile));
        assert_eq!(state.store_kind(), StoreKind::EncryptedFile);

        state.poll_one(Provider::Anthropic, "a").await;
        assert_eq!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::Network),
            "the fallback store was installed but the poll path did not read it"
        );

        std::fs::remove_file(&path).ok();
        let mut lock = path.clone().into_os_string();
        lock.push(".lock");
        std::fs::remove_file(PathBuf::from(lock)).ok();
    }

    /// The wiring, not the store. What is untested without this is whether a
    /// saved value ever reaches the object the polling loop actually reads.
    #[tokio::test]
    async fn a_new_interval_is_persisted_and_reaches_the_running_scheduler() {
        let settings_path = tmp("settings");
        let state =
            app_state_with(Arc::new(LockedStore), StoreKind::Keychain, settings_path.clone());
        assert_eq!(state.scheduler.lock().await.policy().interval().num_seconds(), 300);

        assert_eq!(state.set_poll_interval(600).await.unwrap(), 600);

        assert_eq!(
            state.scheduler.lock().await.policy().interval().num_seconds(),
            600,
            "the setting never reached the running scheduler"
        );
        assert_eq!(
            SettingsStore::load(&settings_path).poll_interval_secs(),
            600,
            "the setting never reached the disk"
        );

        // §6.1's floor is enforced here, not only by the control in the window.
        assert_eq!(state.set_poll_interval(5).await.unwrap(), 180);
        assert_eq!(state.scheduler.lock().await.policy().interval().num_seconds(), 180);

        std::fs::remove_file(&settings_path).ok();
    }

    /// Persist first, then apply. A cadence the settings file does not record
    /// is one the next process start silently abandons.
    #[tokio::test]
    async fn an_interval_that_cannot_be_saved_does_not_change_the_running_one() {
        let blocker = tmp("settings-blocker");
        std::fs::write(&blocker, b"a regular file, not a directory").unwrap();
        let state = app_state_with(
            Arc::new(LockedStore),
            StoreKind::Keychain,
            blocker.join("settings.json"),
        );

        assert!(state.set_poll_interval(600).await.is_err(), "the write cannot succeed here");
        assert_eq!(
            state.scheduler.lock().await.policy().interval().num_seconds(),
            300,
            "a setting that was never saved was applied to the running scheduler anyway"
        );
        std::fs::remove_file(&blocker).ok();
    }

    /// The wiring, not the scheduler. `Scheduler::make_due_now` being correct
    /// says nothing about whether the login path calls it, and this is the one
    /// path where the user is watching a spinner: `add` gives the new entry
    /// `order.len() * 15s`, so with a and b already registered the account just
    /// added waits 30 seconds, and a re-login — rebuilt at the end of `order` —
    /// waits the longest of all.
    #[tokio::test]
    async fn an_account_registered_through_the_login_flow_is_polled_at_once() {
        let state = app_state(Arc::new(LockedStore));
        let b_before = state.scheduler.lock().await.next_wake(Provider::Anthropic, "b").unwrap();

        state.register_authenticated("c", "c@example.invalid").await.unwrap();

        let sched = state.scheduler.lock().await;
        assert!(
            sched.next_wake(Provider::Anthropic, "c").unwrap() <= Utc::now(),
            "the account the user just added waits out the startup stagger"
        );
        // Single-account by design: §6.1's stagger is what buys the deliberate
        // decision not to implement jitter, so registering one account must not
        // flatten the schedule of the others.
        assert_eq!(
            sched.next_wake(Provider::Anthropic, "b").unwrap(),
            b_before,
            "registering one account moved another account's schedule"
        );
    }

    /// **The one behavioral change in this diff that would be silently wrong
    /// if the two match arms in `poll_claimed`'s `usage_url` routing were
    /// swapped.** Every other poll-path test points `usage_url` and
    /// `openai_usage_url` at the same dead address (`app_state_with`), so none
    /// of them can tell the two fields apart. This one binds them to two
    /// *different* mock servers and asserts both halves positively: the Codex
    /// account's poll reached its own mock, and Anthropic's received nothing
    /// at all — not merely "the fetch succeeded", which a swapped routing
    /// would also produce if the wrong mock happened to answer.
    #[tokio::test]
    async fn a_codex_account_is_polled_against_its_own_url_not_anthropics() {
        use quota_core::auth::token::TokenSet;
        use quota_core::provider::token_key;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"rate_limit":{"primary_window":{"used_percent":10,
                    "limit_window_seconds":604800,"reset_after_seconds":604800,
                    "reset_at":9999999999},"secondary_window":null}}"#,
            ))
            .mount(&openai_server)
            .await;
        // Deliberately no `Mock` mounted on `anthropic_server`. If the Codex
        // account's poll reached it anyway, wiremock would still answer with
        // its own default 404 — the point is caught by
        // `received_requests()` below, not by whether the fetch succeeded.

        let mut state = app_state(Arc::new(quota_core::secrets::MemoryStore::default()));
        state.usage_url = anthropic_server.uri();
        state.openai_usage_url = openai_server.uri();

        let tokens = TokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            refresh_token_expires_at: Utc::now() + chrono::TimeDelta::days(30),
            scopes: vec![],
            client_id: "test".into(),
        };
        state
            .secrets()
            .put(&token_key(Provider::Openai, "codex-a"), &serde_json::to_vec(&tokens).unwrap())
            .unwrap();
        state.scheduler.lock().await.add(Provider::Openai, "codex-a");

        state.poll_one(Provider::Openai, "codex-a").await;

        assert!(
            matches!(
                state.scheduler.lock().await.state(Provider::Openai, "codex-a"),
                Some(AccountState::Ok { .. })
            ),
            "the Codex account's poll did not read as a successful fetch"
        );
        assert!(
            !openai_server.received_requests().await.unwrap().is_empty(),
            "the Codex account's poll never reached its own URL"
        );
        assert!(
            anthropic_server.received_requests().await.unwrap().is_empty(),
            "the Codex account's poll reached Anthropic's URL instead of its own"
        );
    }
}
