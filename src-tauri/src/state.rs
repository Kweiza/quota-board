use chrono::Utc;
use quota_core::accounts::{Account, AccountStore};
use quota_core::auth::pkce::PendingAuth;
use quota_core::auth::stored::{
    delete_tokens, ensure_fresh, load_tokens, refresh_after_unauthorized, save_tokens, AuthConfigs,
    RefreshLocks, StoredTokenError, StoredTokens,
};
use quota_core::auth::token::ReqwestHttp;
use quota_core::provider::Provider;
use quota_core::scheduler::{
    persist_last_ok, persist_quarantine, FailureKind, Scheduler, SystemClock,
};
use quota_core::secrets::{SecretError, SecretStore};
use quota_core::settings::SettingsStore;
use quota_core::snapshots::{fingerprint, save as save_snapshot};
use quota_core::usage::http::{fetch_usage_captured_for_account_at, UsageError};
use quota_core::usage::raw::{RawLog, RawResponse};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tauri::{Emitter, Manager};
use tokio::sync::{oneshot, Mutex};

pub(crate) struct PendingManual {
    pub generation: u64,
    pub pending: PendingAuth,
    pub cancel: Option<oneshot::Sender<()>>,
}

/// **Lock order: `scheduler` before `accounts`, never the reverse, and never
/// hold either across `ensure_fresh` or the usage fetch.** Both are `tokio`
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
    /// `install_fallback_store()`, `secrets_status()` and `store_kind()`.** The same
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
    /// keyed by (provider, uuid) — the pair, not the bare id (§9.3), so two
    /// accounts sharing an id across providers do not share a slot — **already
    /// masked** (`usage::raw`).
    ///
    /// **In memory only.** It is deliberately not merged into
    /// `snapshots_path`: §9.1 puts that cache in a plain file on disk, and a
    /// whole response body carries fields this app does not read and therefore
    /// has not reasoned about. Losing the debug body on restart is the correct
    /// trade.
    ///
    /// **There is no entry cap.** The key set is a subset of the registered
    /// accounts — `record` is reached only from `poll_claimed` with a
    /// scheduler-owned (provider, uuid) pair — and `forget_raw` drops an entry
    /// when the account is deleted. `crates/core/src/snapshots.rs:73-86` is a
    /// pair-keyed map with the same `save`/`remove` shape and no cap, for the
    /// same reason.
    ///
    /// Same `std::sync` rule as `secrets`: taken and released inside one
    /// statement, never across an `await`.
    pub(crate) last_raw: std::sync::Mutex<RawLog>,
    /// §10.3's Claude manual-paste login, waiting for the user to bring a code
    /// back. Codex has no `code#state` route and never writes this field.
    ///
    /// Its `redirect_uri` is always the manual one, so the Anthropic exchange
    /// replays exactly the URI stored here.
    ///
    /// **Written on every Claude `begin_login`, not only when loopback fails.**
    /// Two of the four ways the loopback can fail are detected in the webview —
    /// a `Callback::bind` that never happened and an `openUrl` that threw — and
    /// the webview cannot reach this field. Storing it up front is what lets
    /// all four failures share one paste path.
    ///
    /// A manual-only attempt does not hold `LOGIN_IN_FLIGHT`; a loopback attempt
    /// does until its listener is cancelled or completes. The generation beside
    /// this value prevents a replaced or late callback from committing.
    ///
    /// Same `std::sync` rule as `secrets`: taken and released inside one
    /// statement, never across an `await`.
    pub(crate) pending_manual: std::sync::Mutex<Option<PendingManual>>,
    /// The generation allowed to commit a login result. A late callback from a
    /// replaced Claude attempt observes a different value and exits without a
    /// token request or event.
    pub(crate) active_login: std::sync::Mutex<Option<u64>>,
    /// Serializes the generation check with token/account persistence. It is
    /// separate from `LOGIN_IN_FLIGHT`: Claude's manual fallback can complete
    /// while its loopback task still owns that process-wide flag.
    pub(crate) login_commit: Mutex<()>,
    pub http: ReqwestHttp,
    /// Both protocols' refresh and revocation configuration. OpenAI is not a
    /// `ProviderSpec`: its root-issuer endpoints and wire bodies differ from
    /// Anthropic's at every step.
    pub auth_configs: AuthConfigs,
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
    /// — AGENTS.md and design.md §4.3 forbid it; the URL is the seam.
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

fn authenticated_account(
    existing: Option<&Account>,
    provider: Provider,
    account_id: &str,
    email: &str,
    workspace_id: Option<&str>,
    is_fedramp: bool,
) -> Account {
    Account {
        account_id: account_id.to_string(),
        provider,
        workspace_id: workspace_id.map(str::to_string),
        is_fedramp,
        display_label: existing
            .map(|account| account.display_label.clone())
            .unwrap_or_else(|| email.to_string()),
        email: email.to_string(),
        created_at: existing.map(|account| account.created_at).unwrap_or_else(Utc::now),
        last_ok_at: existing.and_then(|account| account.last_ok_at),
        // Clearing this is the point of a successful re-login (§7.2).
        quarantined: false,
        // `AccountStore::upsert` preserves the existing value or assigns the
        // next slot for a new row.
        sort_order: 0,
    }
}

async fn rollback_tokens(
    store: Arc<dyn SecretStore>,
    provider: Provider,
    account_id: String,
    previous: Option<StoredTokens>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || match previous {
        Some(previous) => save_tokens(store.as_ref(), provider, &account_id, &previous),
        None => delete_tokens(store.as_ref(), provider, &account_id).map(|_| ()),
    })
    .await
    .map_err(|e| format!("token rollback task failed: {e}"))?
    .map_err(|e| format!("token rollback failed: {e}"))
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

    /// Installs the fallback only while no backend is open. The check and swap
    /// share one write guard so two concurrent passphrase commands cannot leave
    /// the process with two independently cached encrypted-file stores.
    pub fn install_fallback_store(
        &self,
        store: Arc<dyn SecretStore>,
    ) -> Result<Arc<dyn SecretStore>, Arc<dyn SecretStore>> {
        let mut current = self.secrets.write().unwrap_or_else(|e| e.into_inner());
        if current.kind != StoreKind::NoBackend {
            return Err(store);
        }
        current.kind = StoreKind::EncryptedFile;
        Ok(std::mem::replace(&mut current.store, store))
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
    fn record_raw(&self, provider: Provider, uuid: &str, raw: RawResponse) {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).record(provider, uuid, raw);
    }

    /// §5.5. `None` means this account has not been polled successfully since
    /// the process started — not "there was no body".
    pub fn last_raw_for(&self, provider: Provider, uuid: &str) -> Option<RawResponse> {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).get(provider, uuid).cloned()
    }

    /// Dropped together with the account. With no entry cap this is the only
    /// bound on the key set, so the call at `remove_account` is not optional.
    pub fn forget_raw(&self, provider: Provider, uuid: &str) {
        self.last_raw.lock().unwrap_or_else(|e| e.into_inner()).remove(provider, uuid);
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

    /// Stores and registers a freshly authenticated account (§10.3).
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
        account_id: &str,
        email: &str,
        tokens: StoredTokens,
    ) -> Result<(), String> {
        let provider = tokens.provider();
        let workspace_id = tokens.workspace_id().map(str::to_string);
        let is_fedramp = tokens.is_fedramp();

        // Login and refresh share this lock. Without it, a refresh can finish
        // between the new credential write and the metadata write and replace
        // the grant that just authenticated successfully.
        let _account_lock = self.refresh_locks.lock_account(provider, account_id).await;

        // Refuse a known workspace conflict before touching the credential
        // store. The same validation runs again at commit time because account
        // metadata remains editable while the blocking store work runs.
        {
            let accounts = self.accounts.lock().await;
            let existing = accounts
                .list()
                .iter()
                .find(|a| a.provider == provider && a.account_id == account_id);
            let account = authenticated_account(
                existing,
                provider,
                account_id,
                email,
                workspace_id.as_deref(),
                is_fedramp,
            );
            accounts
                .validate_upsert(&account)
                .map_err(|e| format!("the account could not be saved: {e}"))?;
        }

        let store = self.secrets();
        let previous = {
            let store = Arc::clone(&store);
            let id = account_id.to_string();
            match tauri::async_runtime::spawn_blocking(move || {
                load_tokens(store.as_ref(), provider, &id)
            })
            .await
            .map_err(|e| format!("the token store task failed: {e}"))?
            {
                Ok(tokens) => Some(tokens),
                // Re-login is the remedy for both an absent credential and a
                // corrupt/partial one. Neither has a trustworthy value that
                // can be restored, so a later rollback removes the attempted
                // set completely.
                Err(StoredTokenError::Missing | StoredTokenError::Corrupt) => None,
                Err(e) => return Err(format!("the existing token could not be read: {e}")),
            }
        };

        let save_result = {
            let store = Arc::clone(&store);
            let id = account_id.to_string();
            let saved = tokens.clone();
            tauri::async_runtime::spawn_blocking(move || {
                save_tokens(store.as_ref(), provider, &id, &saved)
            })
            .await
            .map_err(|e| format!("the token store task failed: {e}"))?
        };
        if let Err(save_error) = save_result {
            let rollback = rollback_tokens(
                Arc::clone(&store),
                provider,
                account_id.to_string(),
                previous.clone(),
            )
            .await;
            return match rollback {
                Ok(()) => Err(format!("the token could not be stored: {save_error}")),
                Err(rollback_error) => Err(format!(
                    "the token could not be stored ({save_error}); {rollback_error}"
                )),
            };
        }

        // Lock order: scheduler before accounts. No credential-store operation
        // occurs while either is held.
        let metadata_error = {
            let mut sched = self.scheduler.lock().await;
            let mut accounts = self.accounts.lock().await;
            let existing = accounts
                .list()
                .iter()
                .find(|a| a.provider == provider && a.account_id == account_id)
                .cloned();
            let account = authenticated_account(
                existing.as_ref(),
                provider,
                account_id,
                email,
                workspace_id.as_deref(),
                is_fedramp,
            );

            match accounts.validate_upsert(&account) {
                Err(e) => Some(e),
                Ok(()) => match accounts.upsert(account) {
                    Ok(()) => {
                        // Rebuild to clear a persisted quarantine, then bypass
                        // the startup stagger while the user is watching.
                        sched.remove(provider, account_id);
                        sched.add(provider, account_id);
                        sched.make_due_now(provider, account_id);
                        None
                    }
                    Err(e) => {
                        // `AccountStore::upsert` mutates memory before flushing.
                        // Restore the in-memory view too; the second flush may
                        // fail for the same reason and is deliberately ignored.
                        match existing {
                            Some(previous) => {
                                let _ = accounts.upsert(previous);
                            }
                            None => {
                                let _ = accounts.remove(provider, account_id);
                            }
                        }
                        Some(e)
                    }
                },
            }
        };

        if let Some(error) = metadata_error {
            if let Err(rollback_error) = rollback_tokens(
                Arc::clone(&store),
                provider,
                account_id.to_string(),
                previous,
            )
            .await
            {
                return Err(format!(
                    "the account could not be saved ({error}); {rollback_error}"
                ));
            }
            return Err(format!("the account could not be saved: {error}"));
        }

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
        // `auth::stored` owns read -> refresh -> write. Inlining it here would let
        // scheduler polls and manual refreshes invalidate each other's refresh
        // tokens (§10.5).
        // One `Arc` clone taken before the await, so no lock is held across
        // one. A store swapped in mid-poll therefore takes effect from the
        // next poll, and this one finishes against the store it started with.
        let store = self.secrets();
        let fresh = match ensure_fresh(
            &self.http,
            &self.auth_configs,
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
        let mut fetched_access = fresh.tokens.access_token().to_string();
        let mut fetched_workspace = fresh.tokens.workspace_id().map(str::to_string);
        let mut fetched_is_fedramp = fresh.tokens.is_fedramp();
        let mut fetched = fetch_usage_captured_for_account_at(
            &self.http,
            provider,
            usage_url,
            &fetched_access,
            fetched_workspace.as_deref(),
            fetched_is_fedramp,
        )
        .await;

        // A 401 is the authoritative access-token rejection. Force one
        // rotation using the rejected token as the race witness, then retry the
        // usage request exactly once. A second 401 falls through to the normal
        // AuthExpired mapping; there is deliberately no retry loop.
        if matches!(&fetched.outcome, Err(UsageError::Unauthorized)) {
            match refresh_after_unauthorized(
                &self.http,
                &self.auth_configs,
                store.as_ref(),
                &self.refresh_locks,
                provider,
                uuid,
                &fetched_access,
            )
            .await
            {
                Ok(rotated) => {
                    if let Err(e) = &rotated.persisted {
                        eprintln!("{uuid}: the 401-triggered rotation could not be persisted: {e}");
                    }
                    fetched_access = rotated.tokens.access_token().to_string();
                    fetched_workspace = rotated.tokens.workspace_id().map(str::to_string);
                    fetched_is_fedramp = rotated.tokens.is_fedramp();
                    fetched = fetch_usage_captured_for_account_at(
                        &self.http,
                        provider,
                        usage_url,
                        &fetched_access,
                        fetched_workspace.as_deref(),
                        fetched_is_fedramp,
                    )
                    .await;
                }
                Err(e) => {
                    let kind = FailureKind::from_stored_token_error(&e);
                    self.record(provider, uuid, kind).await;
                    return;
                }
            }
        }
        if let Some(raw) = fetched.raw {
            self.record_raw(provider, uuid, raw);
        }
        let extra = fetched.extra;
        match fetched.outcome {
            Ok(windows) => {
                // The fingerprint is taken from the token that produced *this*
                // fetch, not re-read from the store afterwards.
                let fp = fingerprint(&fetched_access);
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
    use quota_core::auth::openai::{OpenAiAuthConfig, OpenAiTokenSet};
    use quota_core::auth::token::TokenSet;
    use quota_core::model::AccountState;
    use quota_core::provider::{
        openai_access_token_key, openai_refresh_token_key, openai_token_meta_key, token_key,
        ProviderSpec,
    };
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

    #[derive(Default)]
    struct FailOnePutStore {
        inner: quota_core::secrets::MemoryStore,
        fail_key: std::sync::Mutex<Option<String>>,
    }

    impl FailOnePutStore {
        fn fail_once_on(&self, key: String) {
            *self.fail_key.lock().unwrap() = Some(key);
        }
    }

    impl SecretStore for FailOnePutStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            let mut fail_key = self.fail_key.lock().unwrap();
            if fail_key.as_deref() == Some(key) {
                *fail_key = None;
                return Err(SecretError::Backend("injected put failure".into()));
            }
            drop(fail_key);
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<bool, SecretError> {
            self.inner.delete(key)
        }

        fn describe(&self) -> String {
            "fail-one-put (test only)".into()
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
            workspace_id: None,
            is_fedramp: false,
            display_label: uuid.into(),
            email: format!("{uuid}@example.invalid"),
            created_at: chrono::Utc::now(),
            last_ok_at: None,
            quarantined: false,
            sort_order: 0,
        }
    }

    fn anthropic_tokens(access_token: &str) -> StoredTokens {
        StoredTokens::Anthropic(TokenSet {
            access_token: access_token.into(),
            refresh_token: format!("{access_token}-refresh"),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            refresh_token_expires_at: Utc::now() + chrono::TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: "test".into(),
        })
    }

    fn openai_tokens(account_id: &str, workspace_id: &str, access_token: &str) -> StoredTokens {
        StoredTokens::Openai(OpenAiTokenSet {
            access_token: access_token.into(),
            refresh_token: format!("{access_token}-refresh"),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            client_id: "test".into(),
            account_id: account_id.into(),
            workspace_id: workspace_id.into(),
            is_fedramp: false,
        })
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
            active_login: std::sync::Mutex::new(None),
            login_commit: Mutex::new(()),
            http: quota_core::auth::token::ReqwestHttp::new().unwrap(),
            auth_configs: AuthConfigs {
                anthropic: ProviderSpec {
                    token_url: "http://127.0.0.1:1/never".into(),
                    ..Provider::Anthropic.spec()
                },
                openai: OpenAiAuthConfig {
                    issuer: "http://127.0.0.1:1/never".into(),
                    ..OpenAiAuthConfig::default()
                },
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
            tokio::spawn(async move {
                s.register_authenticated("a", "a@example.invalid", anthropic_tokens("new-a"))
                    .await
            })
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
                    workspace_id: None,
                    is_fedramp: false,
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

        state
            .register_authenticated(
                "a",
                "different@example.invalid",
                anthropic_tokens("new-a"),
            )
            .await
            .unwrap();

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

    /// docs/design.md §9.3: nothing stops two providers from issuing the same
    /// id string, and a Codex login sharing an id with an existing Anthropic
    /// account must not collide with it — the account this task adds carries
    /// its own `Provider`, and the two rows coexist untouched by each other.
    ///
    /// Back-tested: matching `existing` on `uuid` alone (as this lookup did
    /// before this task, when the function was Anthropic-only) makes this
    /// fail — the Codex account would inherit the Anthropic account's
    /// `display_label` and `created_at` instead of getting its own.
    #[tokio::test]
    async fn a_codex_login_does_not_collide_with_an_anthropic_account_sharing_the_same_id() {
        let state = app_state(Arc::new(quota_core::secrets::MemoryStore::default()));
        let anthropic_created = Utc::now() - chrono::TimeDelta::days(10);
        {
            let mut accounts = state.accounts.lock().await;
            accounts
                .upsert(Account {
                    account_id: "shared-id".into(),
                    provider: Provider::Anthropic,
                    workspace_id: None,
                    is_fedramp: false,
                    display_label: "claude work".into(),
                    email: "claude@example.invalid".into(),
                    created_at: anthropic_created,
                    last_ok_at: None,
                    quarantined: false,
                    sort_order: 0,
                })
                .unwrap();
        }

        state
            .register_authenticated(
                "shared-id",
                "codex@example.invalid",
                openai_tokens("shared-id", "workspace-codex", "codex-access"),
            )
            .await
            .unwrap();

        let accounts = state.accounts.lock().await;
        assert_eq!(
            accounts.list().iter().filter(|a| a.account_id == "shared-id").count(),
            2,
            "the two providers' accounts sharing this id collapsed into one"
        );

        let codex = accounts
            .list()
            .iter()
            .find(|a| a.account_id == "shared-id" && a.provider == Provider::Openai)
            .expect("the Codex account was not registered");
        assert_eq!(codex.email, "codex@example.invalid");
        // A fresh account, not the Anthropic one's metadata leaking across the
        // provider boundary.
        assert_eq!(codex.display_label, "codex@example.invalid");
        assert!(codex.created_at > anthropic_created);

        let claude = accounts
            .list()
            .iter()
            .find(|a| a.account_id == "shared-id" && a.provider == Provider::Anthropic)
            .expect("the Anthropic account was dropped");
        assert_eq!(claude.display_label, "claude work", "the Codex login mutated the Anthropic account");

        assert!(matches!(
            state.scheduler.lock().await.state(Provider::Openai, "shared-id"),
            Some(AccountState::Loading)
        ));
    }

    #[tokio::test]
    async fn every_partial_openai_save_failure_deletes_a_new_grant() {
        let account_id = "new-codex-user";
        let failing_keys = [
            openai_refresh_token_key(account_id),
            openai_access_token_key(account_id),
            openai_token_meta_key(account_id),
        ];

        for key in failing_keys {
            let store = Arc::new(FailOnePutStore::default());
            store.fail_once_on(key.clone());
            let state = app_state(store.clone());

            let error = state
                .register_authenticated(
                    account_id,
                    "new@example.invalid",
                    openai_tokens(account_id, "workspace-new", "new-access"),
                )
                .await
                .expect_err("the injected split-store failure was ignored");
            assert!(error.contains("could not be stored"), "{key}: {error}");
            assert!(
                matches!(
                    load_tokens(store.as_ref(), Provider::Openai, account_id),
                    Err(StoredTokenError::Missing)
                ),
                "{key}: a partial new credential survived rollback"
            );
            assert!(
                state
                    .accounts
                    .lock()
                    .await
                    .list()
                    .iter()
                    .all(|account| {
                        account.provider != Provider::Openai
                            || account.account_id != account_id
                    }),
                "{key}: a failed token save still registered an account"
            );
        }
    }

    #[tokio::test]
    async fn every_partial_openai_save_failure_restores_the_previous_grant() {
        let account_id = "existing-codex-user";
        let failing_keys = [
            openai_refresh_token_key(account_id),
            openai_access_token_key(account_id),
            openai_token_meta_key(account_id),
        ];

        for key in failing_keys {
            let store = Arc::new(FailOnePutStore::default());
            let state = app_state(store.clone());
            state
                .register_authenticated(
                    account_id,
                    "old@example.invalid",
                    openai_tokens(account_id, "workspace-one", "old-access"),
                )
                .await
                .unwrap();
            store.fail_once_on(key.clone());

            state
                .register_authenticated(
                    account_id,
                    "new@example.invalid",
                    openai_tokens(account_id, "workspace-one", "new-access"),
                )
                .await
                .expect_err("the injected split-store failure was ignored");

            let restored = load_tokens(store.as_ref(), Provider::Openai, account_id)
                .expect("the previous complete credential was not restored");
            assert_eq!(restored.access_token(), "old-access", "failed at {key}");
            assert_eq!(
                restored.refresh_token(),
                "old-access-refresh",
                "failed at {key}"
            );
            let account = state
                .accounts
                .lock()
                .await
                .list()
                .iter()
                .find(|account| {
                    account.provider == Provider::Openai && account.account_id == account_id
                })
                .cloned()
                .unwrap();
            assert_eq!(account.email, "old@example.invalid", "failed at {key}");
        }
    }

    #[tokio::test]
    async fn workspace_conflict_is_refused_before_the_existing_token_is_overwritten() {
        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        let state = app_state(store.clone());
        state
            .register_authenticated(
                "workspace-user",
                "old@example.invalid",
                openai_tokens("workspace-user", "workspace-one", "old-access"),
            )
            .await
            .unwrap();

        let error = state
            .register_authenticated(
                "workspace-user",
                "new@example.invalid",
                openai_tokens("workspace-user", "workspace-two", "new-access"),
            )
            .await
            .expect_err("a second workspace silently replaced the first");
        assert!(error.contains("different workspace"), "{error}");
        let stored = load_tokens(store.as_ref(), Provider::Openai, "workspace-user").unwrap();
        assert_eq!(stored.access_token(), "old-access");
        assert_eq!(stored.workspace_id(), Some("workspace-one"));
    }

    #[tokio::test]
    async fn a_metadata_failure_deletes_a_newly_saved_credential() {
        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        let path = tmp("unreadable-accounts");
        std::fs::write(&path, b"not valid account JSON").unwrap();
        let mut state = app_state(store.clone());
        state.accounts = Mutex::new(AccountStore::load(&path));

        let error = state
            .register_authenticated(
                "metadata-user",
                "metadata@example.invalid",
                openai_tokens("metadata-user", "workspace-one", "new-access"),
            )
            .await
            .expect_err("an unreadable account file accepted a registration");
        assert!(error.contains("account could not be saved"), "{error}");
        assert!(matches!(
            load_tokens(store.as_ref(), Provider::Openai, "metadata-user"),
            Err(StoredTokenError::Missing)
        ));
        assert!(state.accounts.lock().await.list().is_empty());
        std::fs::remove_file(path).ok();
    }

    #[tokio::test]
    async fn a_metadata_failure_restores_the_previous_credential_and_row() {
        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        let dir = tmp("account-directory");
        let moved = dir.with_extension("moved");
        std::fs::create_dir_all(&dir).unwrap();
        let accounts_path = dir.join("accounts.json");
        let mut accounts = AccountStore::load(&accounts_path);
        accounts
            .upsert(authenticated_account(
                None,
                Provider::Openai,
                "metadata-user",
                "old@example.invalid",
                Some("workspace-one"),
                false,
            ))
            .unwrap();
        save_tokens(
            store.as_ref(),
            Provider::Openai,
            "metadata-user",
            &openai_tokens("metadata-user", "workspace-one", "old-access"),
        )
        .unwrap();
        let mut state = app_state(store.clone());
        state.accounts = Mutex::new(accounts);

        std::fs::rename(&dir, &moved).unwrap();
        std::fs::write(&dir, b"blocks the account directory").unwrap();
        state
            .register_authenticated(
                "metadata-user",
                "new@example.invalid",
                openai_tokens("metadata-user", "workspace-one", "new-access"),
            )
            .await
            .expect_err("the blocked metadata path accepted a registration");

        let restored = load_tokens(store.as_ref(), Provider::Openai, "metadata-user").unwrap();
        assert_eq!(restored.access_token(), "old-access");
        let accounts = state.accounts.lock().await;
        let restored_account = accounts
            .list()
            .iter()
            .find(|account| {
                account.provider == Provider::Openai && account.account_id == "metadata-user"
            })
            .unwrap();
        assert_eq!(restored_account.email, "old@example.invalid");
        drop(accounts);

        std::fs::remove_file(&dir).ok();
        std::fs::rename(&moved, &dir).ok();
        std::fs::remove_file(accounts_path).ok();
        std::fs::remove_dir(dir).ok();
    }

    #[tokio::test]
    async fn corrupt_anthropic_credentials_can_be_repaired_by_re_login() {
        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        store
            .put(&token_key(Provider::Anthropic, "a"), b"not valid token JSON")
            .unwrap();
        let state = app_state(store.clone());
        {
            let mut accounts = state.accounts.lock().await;
            let mut saved = accounts
                .list()
                .iter()
                .find(|account| {
                    account.provider == Provider::Anthropic && account.account_id == "a"
                })
                .cloned()
                .unwrap();
            saved.quarantined = true;
            accounts.upsert(saved).unwrap();
        }
        state
            .scheduler
            .lock()
            .await
            .record_failure(Provider::Anthropic, "a", FailureKind::AuthDead);

        state
            .register_authenticated("a", "repaired@example.invalid", anthropic_tokens("repaired"))
            .await
            .unwrap();

        let repaired = load_tokens(store.as_ref(), Provider::Anthropic, "a").unwrap();
        assert_eq!(repaired.access_token(), "repaired");
        assert_ne!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::AuthDead)
        );
        assert!(
            !state
                .accounts
                .lock()
                .await
                .list()
                .iter()
                .find(|account| {
                    account.provider == Provider::Anthropic && account.account_id == "a"
                })
                .unwrap()
                .quarantined
        );
    }

    #[tokio::test]
    async fn partial_openai_credentials_can_be_repaired_by_re_login() {
        for present_entries in [1, 2] {
            let account_id = format!("partial-user-{present_entries}");
            let store = Arc::new(quota_core::secrets::MemoryStore::default());
            store
                .put(
                    &openai_refresh_token_key(&account_id),
                    b"orphaned-refresh",
                )
                .unwrap();
            if present_entries == 2 {
                store
                    .put(&openai_access_token_key(&account_id), b"orphaned-access")
                    .unwrap();
            }
            let state = app_state(store.clone());
            {
                let mut account = account(&account_id);
                account.provider = Provider::Openai;
                account.workspace_id = Some("workspace-one".into());
                account.quarantined = true;
                state.accounts.lock().await.upsert(account).unwrap();
                state.scheduler.lock().await.add(Provider::Openai, &account_id);
                state.scheduler.lock().await.record_failure(
                    Provider::Openai,
                    &account_id,
                    FailureKind::AuthDead,
                );
            }

            state
                .register_authenticated(
                    &account_id,
                    "repaired@example.invalid",
                    openai_tokens(&account_id, "workspace-one", "repaired-access"),
                )
                .await
                .unwrap();

            let repaired = load_tokens(store.as_ref(), Provider::Openai, &account_id).unwrap();
            assert_eq!(repaired.access_token(), "repaired-access");
            assert_ne!(
                state.scheduler.lock().await.state(Provider::Openai, &account_id),
                Some(AccountState::AuthDead),
                "{present_entries}-entry partial set stayed quarantined"
            );
            let accounts = state.accounts.lock().await;
            let repaired_account = accounts
                .list()
                .iter()
                .find(|account| {
                    account.provider == Provider::Openai && account.account_id == account_id
                })
                .unwrap();
            assert!(!repaired_account.quarantined);
        }
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
        let replaced = match state.install_fallback_store(Arc::new(opened)) {
            Ok(replaced) => replaced,
            Err(_) => panic!("the fallback store was refused from NoBackend"),
        };
        drop(replaced);
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
        let state = app_state(Arc::new(quota_core::secrets::MemoryStore::default()));
        let b_before = state.scheduler.lock().await.next_wake(Provider::Anthropic, "b").unwrap();

        state
            .register_authenticated("c", "c@example.invalid", anthropic_tokens("new-c"))
            .await
            .unwrap();

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
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("chatgpt-account-id", "workspace-a"))
            .and(header("x-openai-fedramp", "true"))
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

        let tokens = StoredTokens::Openai(OpenAiTokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            expires_at: Utc::now() + chrono::TimeDelta::hours(1),
            client_id: "test".into(),
            account_id: "codex-a".into(),
            workspace_id: "workspace-a".into(),
            is_fedramp: true,
        });
        save_tokens(state.secrets().as_ref(), Provider::Openai, "codex-a", &tokens).unwrap();
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

    /// The identical hazard as the test above, one step earlier in the same
    /// poll: `ensure_fresh`'s `cfg` argument, not its `provider` argument, is
    /// what reaches the network — `refresh` (auth/token.rs) posts
    /// `refresh_token` and `client_id` to `cfg.token_url`. An unconditional
    /// Anthropic's config in `poll_claimed` would send a live Codex refresh token to
    /// Anthropic's token endpoint on **every token rotation**, not once at
    /// removal like the revoke call this task already fixed — routinely,
    /// whenever a Codex access token expires.
    ///
    /// The token here is **expired** (`expires_at` in the past), unlike the
    /// sibling test above: `ensure_fresh` only calls `refresh` at all when
    /// `needs_refresh()` is true, so a live token — which the sibling test
    /// uses deliberately, to isolate the usage-URL routing from this one —
    /// would never reach this code path.
    #[tokio::test]
    async fn a_codex_account_is_refreshed_against_its_own_token_endpoint_not_anthropics() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "e30.eyJleHAiOjk5OTk5OTk5OTl9.signature",
                "refresh_token": "new-codex-refresh",
            })))
            .mount(&openai_server)
            .await;
        // Deliberately no `Mock` mounted on `anthropic_server` — same reasoning
        // as the sibling test above.

        let mut state = app_state(Arc::new(quota_core::secrets::MemoryStore::default()));
        state.auth_configs.anthropic.token_url =
            format!("{}/v1/oauth/token", anthropic_server.uri());
        state.auth_configs.openai.issuer = openai_server.uri();

        let tokens = StoredTokens::Openai(OpenAiTokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            expires_at: Utc::now() - chrono::TimeDelta::seconds(1),
            client_id: "test".into(),
            account_id: "codex-a".into(),
            workspace_id: "workspace-a".into(),
            is_fedramp: false,
        });
        save_tokens(state.secrets().as_ref(), Provider::Openai, "codex-a", &tokens).unwrap();
        state.scheduler.lock().await.add(Provider::Openai, "codex-a");

        state.poll_one(Provider::Openai, "codex-a").await;

        assert!(
            !openai_server.received_requests().await.unwrap().is_empty(),
            "the Codex account's refresh never reached its own token endpoint"
        );
        assert!(
            anthropic_server.received_requests().await.unwrap().is_empty(),
            "a Codex refresh token was sent to Anthropic's token endpoint"
        );
    }

    #[tokio::test]
    async fn a_usage_401_forces_one_refresh_and_retries_with_the_rotated_access_token() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let usage = MockServer::start().await;
        let auth = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer rejected-access"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&usage)
            .await;
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer rotated-access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "five_hour": {
                    "utilization": 23,
                    "resets_at": "2030-01-01T00:00:00Z"
                },
                "seven_day": null,
                "limits": []
            })))
            .expect(1)
            .mount(&usage)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "rotated-access",
                "refresh_token": "rotated-refresh",
                "expires_in": 27000,
                "scope": "user:profile"
            })))
            .expect(1)
            .mount(&auth)
            .await;

        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        save_tokens(
            store.as_ref(),
            Provider::Anthropic,
            "a",
            &anthropic_tokens("rejected-access"),
        )
        .unwrap();
        let mut state = app_state(store.clone());
        state.usage_url = usage.uri();
        state.auth_configs.anthropic.token_url = format!("{}/token", auth.uri());

        state.poll_one(Provider::Anthropic, "a").await;

        assert!(matches!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::Ok { .. })
        ));
        assert_eq!(
            load_tokens(store.as_ref(), Provider::Anthropic, "a")
                .unwrap()
                .access_token(),
            "rotated-access"
        );
    }

    #[tokio::test]
    async fn a_second_usage_401_is_not_refreshed_or_retried_again() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let usage = MockServer::start().await;
        let auth = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .expect(2)
            .mount(&usage)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "rotated-access",
                "refresh_token": "rotated-refresh",
                "expires_in": 27000,
                "scope": "user:profile"
            })))
            .expect(1)
            .mount(&auth)
            .await;

        let store = Arc::new(quota_core::secrets::MemoryStore::default());
        save_tokens(
            store.as_ref(),
            Provider::Anthropic,
            "a",
            &anthropic_tokens("rejected-access"),
        )
        .unwrap();
        let mut state = app_state(store);
        state.usage_url = usage.uri();
        state.auth_configs.anthropic.token_url = format!("{}/token", auth.uri());

        state.poll_one(Provider::Anthropic, "a").await;

        assert_eq!(
            state.scheduler.lock().await.state(Provider::Anthropic, "a"),
            Some(AccountState::AuthExpired)
        );
    }
}
