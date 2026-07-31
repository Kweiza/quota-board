use crate::state::{AppState, StoreKind};
use quota_core::auth::callback::Callback;
use quota_core::auth::pkce::{begin, success_redirect};
use quota_core::auth::stored::token_key;
use quota_core::auth::token::{exchange_code, revoke, TokenSet};
use quota_core::model::AccountState;
use quota_core::scheduler::PollPolicy;
use quota_core::secrets::{encrypted_file::EncryptedFileStore, timeout::TimeoutStore, SecretStore};
use quota_core::usage::raw::RawResponse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager, State};

/// Mirrors `AccountView` in `src/lib/types.ts`. The two must be changed
/// together — `crates/core/src/model.rs:19-23` carries the reciprocal note for
/// `AccountState`.
///
/// `email` is display-only and is **never** used as a key (§9.3). It is here
/// because `display_label` is user-editable, so after a rename Task 18's
/// settings list has nothing else to tell two accounts apart by. Adding it now
/// shakes the two-sided contract once instead of twice.
///
/// There is deliberately **no `quarantined` field**: `Scheduler::state` checks
/// `quarantined` before anything else and already returns `AuthDead` for a
/// quarantined account, so a second copy of that fact on the wire is exactly
/// the two-sources-disagree hazard §7.1 exists to prevent. Sort order needs no
/// field either — `AccountStore` sorts by `sort_order` on load (accounts.rs:62)
/// and `list()` returns that order, so the array order *is* the order.
#[derive(serde::Serialize)]
pub struct AccountView {
    pub uuid: String,
    pub label: String,
    pub email: String,
    pub state: AccountState,
}

#[tauri::command]
pub async fn list_accounts(state: State<'_, AppState>) -> Result<Vec<AccountView>, String> {
    // Lock order: scheduler before accounts. See the doc comment on `AppState`.
    let sched = state.scheduler.lock().await;
    let accounts = state.accounts.lock().await;
    Ok(accounts
        .list()
        .iter()
        .map(|a| AccountView {
            uuid: a.uuid.clone(),
            label: a.display_label.clone(),
            email: a.email.clone(),
            state: sched.state(&a.uuid).unwrap_or(AccountState::Loading),
        })
        .collect())
}

/// §6.3. Records what the widget webview reports; the polling loop combines it
/// with the window's own `is_visible()`/`is_minimized()` once per tick and is
/// the single writer of `Scheduler::set_visible`. Task 19's tray toggle calls
/// this too, so there is one entry point rather than two scheduler touches.
#[tauri::command]
pub async fn set_widget_visible(state: State<'_, AppState>, visible: bool) -> Result<(), String> {
    state.webview_visible.store(visible, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
pub async fn refresh_account(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    uuid: String,
) -> Result<AccountState, String> {
    {
        let sched = state.scheduler.lock().await;
        // Already throttled by the server (§6.2).
        if let Some(s @ AccountState::Throttled { .. }) = sched.state(&uuid) {
            return Ok(s);
        }
        // §6.4: with no budget, do **not** fire — report when it will be
        // available. `AccountRow.svelte`'s `throttled` branch renders this state
        // as "throttled, after HH:MM", which is exactly what §6.4 asks for, and
        // `AccountList.svelte` renders the refused press as "throttled,
        // available after HH:MM". Cited by name: both files move.
        //
        // **Both arms above answer with the same shape.** The first is §6.2's
        // server-ordered wait and this one is §6.1's local floor; on the wire
        // they are one `Throttled { until }`, so no consumer can tell them
        // apart, and none needs to — "come back after HH:MM" is the whole
        // answer either way.
        if let Some(until) = sched.earliest_manual_refresh(&uuid) {
            return Ok(AccountState::Throttled { until });
        }
    }
    // The braces above are load-bearing: a `MutexGuard` created in an `if let`
    // scrutinee lives to the end of that statement in edition 2021, so moving
    // the poll below inside them would deadlock against this very lock.

    // §7.1's AUTH_EXPIRED is "access token expired, **refresh in progress**".
    // Answer with it instead of blocking this UI command on the refresh mutex
    // for up to 30 seconds. `is_refreshing` is advisory by design
    // (auth/stored.rs:98-103) and drives a display state only.
    if state.refresh_locks.is_refreshing(&uuid) {
        return Ok(AccountState::AuthExpired);
    }

    // Returns false when the global permit is held by the polling loop; the
    // current state is then returned unchanged rather than queueing.
    if state.try_poll_one(&uuid).await {
        let _ = app.emit("usage://updated", ());
    }
    state
        .scheduler
        .lock()
        .await
        .state(&uuid)
        .ok_or_else(|| "unknown account".to_string())
}

/// One login at a time (§10.3). The second click is refused rather than
/// queued: each `begin_login` binds its own loopback port and holds it until
/// its callback arrives, so N concurrent attempts leak N ports and N tasks,
/// and only whichever callback lands first can win.
static LOGIN_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Releases the flag on **every** exit path, including an early `return` deep
/// inside the spawned task. A bare `store(false)` on the happy path would let
/// one failed login block every later one for the life of the process, with
/// the flag claiming a login is in progress and no task behind it.
struct LoginGuard;

impl Drop for LoginGuard {
    fn drop(&mut self) {
        LOGIN_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Starts a login. Returns the authorize URL; the callback is awaited in the
/// background. On completion an `accounts://changed` event is emitted, and on
/// any failure an `auth://failed` event carrying a message.
#[tauri::command]
pub async fn begin_login(app: tauri::AppHandle) -> Result<String, String> {
    if LOGIN_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("a login is already in progress".into());
    }
    let guard = LoginGuard;

    let cfg = app.state::<AppState>().cfg.clone();

    // Bind before building the authorize URL: `redirect_uri` must carry the
    // real port, and that exact string is replayed at token exchange
    // (auth/callback.rs:25-27, pkce.rs `PendingAuth::redirect_uri`).
    let cb = Callback::bind().await.map_err(|e| e.to_string())?;
    // `begin` returns a `Result` because `authorize_url` is user-overridable
    // (§10.2), so a bad config value surfaces here instead of crashing a login
    // in progress (pkce.rs:75-81).
    let (pending, url) = begin(&cfg, &cb.redirect_uri()).map_err(|e| e.to_string())?;

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // Moved in, so the single-flight flag is released whichever way this
        // task ends.
        let _guard = guard;
        let state = handle.state::<AppState>();

        // The whole wait is bounded. `wait_for_code`'s own timeout covers one
        // connection's header read and then continues (callback.rs:99-105);
        // nothing inside it bounds the overall wait, so an abandoned login
        // would hold its port for the life of the process.
        let waited = tokio::time::timeout(
            Duration::from_secs(300),
            // The second argument is the listener's own state guard, not a
            // duplicate of `exchange_code`'s check: the listener is
            // single-shot, so without it "a single stray or forged request
            // with the wrong state would consume the listener and strand the
            // real callback with nowhere to land" (callback.rs:59-61).
            cb.wait_for_code(success_redirect(), &pending.state),
        )
        .await;

        let params = match waited {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                let _ = handle.emit("auth://failed", e.to_string());
                return;
            }
            Err(_) => {
                let _ = handle.emit("auth://failed", "the login timed out");
                return;
            }
        };

        let (Some(code), Some(returned_state)) = (params.get("code"), params.get("state")) else {
            let _ = handle.emit("auth://failed", "the callback carried no code or no state");
            return;
        };

        match exchange_code(&state.http, &state.cfg, &pending, code, returned_state).await {
            Ok((tokens, Some(identity))) => {
                // Serialization failure fails loudly. Falling through to the
                // account write would register an account with no credential
                // behind it: `ensure_fresh` would report `Missing`, that
                // classifies to AUTH_DEAD, `record()` would persist the
                // quarantine, and the user would be looking at a dead account
                // produced by a login that appeared to succeed.
                let blob = match serde_json::to_vec(&tokens) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = handle
                            .emit("auth://failed", format!("the token could not be serialized: {e}"));
                        return;
                    }
                };
                // Synchronous and able to block a real thread (timeout.rs:144-156),
                // so it goes on a blocking thread rather than an async worker —
                // the same principle `refresh_account` applies when it answers
                // AUTH_EXPIRED instead of waiting on the refresh mutex.
                let store = state.secrets();
                let key = token_key(&identity.uuid);
                let put = tauri::async_runtime::spawn_blocking(move || store.put(&key, &blob)).await;
                match put {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        let _ = handle
                            .emit("auth://failed", format!("the token could not be stored: {e}"));
                        return;
                    }
                    Err(e) => {
                        let _ = handle
                            .emit("auth://failed", format!("the token store task failed: {e}"));
                        return;
                    }
                }

                if let Err(e) = state
                    .register_authenticated(&identity.uuid, &identity.email)
                    .await
                {
                    let _ =
                        handle.emit("auth://failed", format!("the account could not be saved: {e}"));
                    return;
                }
                let _ = handle.emit("accounts://changed", ());
            }
            Ok((_, None)) => {
                // Without `account.uuid` there is no key. Never substitute the
                // email (§9.3) — it is display-only and user-editable.
                let _ = handle.emit("auth://failed", "the token response carried no account block");
            }
            Err(e) => {
                let _ = handle.emit("auth://failed", e.to_string());
            }
        }
    });

    Ok(url)
}

#[tauri::command]
pub async fn remove_account(app: tauri::AppHandle, uuid: String) -> Result<(), String> {
    let state = app.state::<AppState>();
    let key = token_key(&uuid);
    let store = state.secrets();

    // Both store calls run on a blocking thread. `SecretStore` is synchronous
    // and `TimeoutStore` blocks a real thread on `recv_timeout`
    // (secrets/timeout.rs:144-156, bound at 10s), so on an async worker these
    // two would hold it for up to twenty seconds against a wedged keychain —
    // the same reason `refresh_account` answers AUTH_EXPIRED instead of waiting
    // on the refresh mutex.
    //
    // Server-side revocation is best-effort (§10.6) and already bounded at 5s
    // internally (auth/token.rs:24, :330-338) — it needs no timeout of its own.
    let raw = {
        let store = Arc::clone(&store);
        let key = key.clone();
        tauri::async_runtime::spawn_blocking(move || store.get(&key)).await
    };
    if let Ok(Ok(Some(raw))) = raw {
        if let Ok(t) = serde_json::from_slice::<TokenSet>(&raw) {
            revoke(&state.http, &state.cfg, &t.refresh_token).await;
        }
    }
    // **Not `let _ =`.** The comment above marks the server-side *revocation*
    // as best-effort per §10.6; it says nothing about the local deletion, and
    // the two are not equally harmless. This arm is reachable whenever the
    // store is `LockedStore` or a `TimeoutStore` that has gone stuck, and in
    // exactly that case the `store.get` above failed too, so the token is
    // neither revoked server-side nor deleted locally — while the account row
    // it belonged to disappears, leaving nothing that will ever retry it.
    // Reporting it is the floor: the cached-snapshot arm below already prints
    // its failure, and a surviving credential must not be quieter than a
    // surviving percentage.
    {
        let store = Arc::clone(&store);
        let key = key.clone();
        if let Ok(Err(e)) = tauri::async_runtime::spawn_blocking(move || store.delete(&key)).await {
            eprintln!(
                "{uuid}: the stored token could not be deleted ({e}); it may still be in the \
                 credential store"
            );
        }
    }

    // Lock order: scheduler before accounts.
    state.scheduler.lock().await.remove(&uuid);
    let removed = state
        .accounts
        .lock()
        .await
        .remove(&uuid)
        .map_err(|e| e.to_string())?;
    if !removed {
        // `AccountStore::remove` answers `Ok(false)` for an unknown uuid
        // (accounts.rs:85-96). Emitting `accounts://changed` for a removal
        // that removed nothing would tell every window to re-read for no
        // reason. Same shape as `rename_account`'s unknown-account arm.
        return Err("unknown account".into());
    }

    // Removing an account must remove its cached usage too, or the app keeps
    // percentages and reset times on disk for an account the user deleted.
    // `snapshots::remove` (snapshots.rs:80) exists for exactly this and had no
    // caller.
    let path = state.snapshots_path.clone();
    let id = uuid.clone();
    if let Ok(Err(e)) =
        tauri::async_runtime::spawn_blocking(move || quota_core::snapshots::remove(&path, &id))
            .await
    {
        eprintln!("{uuid}: the cached snapshot could not be removed: {e}");
    }
    state.forget_raw(&uuid);

    let _ = app.emit("accounts://changed", ());
    Ok(())
}

#[tauri::command]
pub async fn rename_account(
    app: tauri::AppHandle,
    uuid: String,
    label: String,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let mut accounts = state.accounts.lock().await;
    let Some(mut a) = accounts.list().iter().find(|a| a.uuid == uuid).cloned() else {
        return Err("unknown account".into());
    };
    a.display_label = label;
    accounts.upsert(a).map_err(|e| e.to_string())?;
    drop(accounts);
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

#[tauri::command]
pub async fn reorder_accounts(app: tauri::AppHandle, uuids: Vec<String>) -> Result<(), String> {
    let state = app.state::<AppState>();
    state
        .accounts
        .lock()
        .await
        .reorder(&uuids)
        .map_err(|e| e.to_string())?;
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

/// A user passphrase in transit.
///
/// **`Debug` is hand-written and prints `<redacted>`** — the same rule and the
/// same shape as `TokenSet` (crates/core/src/auth/token.rs:76-87), which CLAUDE.md
/// names as the pattern to copy. A derived `Debug` would put a live credential
/// into any `format!("{:?}")`. Separately, the store's own errors are safe to
/// stringify: `SecretError` carries only descriptions and a `limit: usize`
/// (secrets/mod.rs:17-29), and the wrong-passphrase message is a fixed literal
/// naming no input (encrypted_file.rs:190).
struct Passphrase(String);

impl Passphrase {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// Mirrors `StoreStatus` in `src/lib/types.ts`. The two must be changed
/// together — the same reciprocal contract `AccountView` carries above.
#[derive(serde::Serialize)]
pub struct StoreStatus {
    /// `SecretStore::describe()`. **Display only — never branch on it.** It is
    /// the one `SecretStore` method safe to call from a UI command:
    /// `TimeoutStore` answers it from a string captured when the store opened
    /// (secrets/timeout.rs:173-177), unlike `get`/`delete`, which block a real
    /// thread.
    pub description: String,
    /// Which of §9.2's states we are in. The settings window branches on this,
    /// because `no_backend` and `keychain_locked` reach the user as the same
    /// account state in this build — §9.2 keeps `NO_BACKEND` off the
    /// account-state axis (design.md:592-594), but the passphrase prompt it
    /// asks for instead cannot be raised from `setup()`, so both start as
    /// `SECRETS_LOCKED` — while carrying two different remedies. Nothing else
    /// on the wire tells them apart.
    pub kind: StoreKind,
    /// Whether §9.2's fallback file already exists. Wording only — the first
    /// passphrase *creates* the store, so a typo there is permanent.
    pub fallback_file_exists: bool,
}

fn store_status_now(state: &AppState) -> StoreStatus {
    let (description, kind) = state.secrets_status();
    StoreStatus {
        description,
        kind,
        fallback_file_exists: quota_core::paths::secrets_file().exists(),
    }
}

#[tauri::command]
pub async fn store_status(state: State<'_, AppState>) -> Result<StoreStatus, String> {
    Ok(store_status_now(&state))
}

/// docs/design.md §9.2's encrypted-file fallback, opened with a passphrase the
/// user typed, and installed as this process's token store.
#[tauri::command]
pub async fn unlock_secrets(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<StoreStatus, String> {
    // **The most expensive mistake this command can make is opening the wrong
    // store.** §9.2 folds two very different failures into `SECRETS_LOCKED`
    // (design.md:595-596) and a passphrase is the remedy for only one of them.
    // Opening the fallback while the tokens live in a keychain installs an
    // *empty* store: every `get` answers `Missing`,
    // `FailureKind::from_stored_token_error` classifies that `AuthDead`,
    // `AppState::record` writes the quarantine through to accounts.json, where
    // `record_failure`'s one-strike quarantine never retries it. Only
    // `NoBackend` — no credential store registered on this machine at all —
    // may reach the fallback.
    match state.store_kind() {
        StoreKind::Keychain => {
            return Err("the OS keychain is open — there is nothing to unlock".into())
        }
        StoreKind::KeychainLocked => {
            return Err("a keychain exists on this machine but did not answer; \
                        unlock it in the OS and restart quota-board. A passphrase \
                        here would open a different, empty store"
                .into())
        }
        StoreKind::NoBackend | StoreKind::EncryptedFile => {}
    }
    if passphrase.is_empty() {
        return Err("a passphrase is required".into());
    }

    let path = quota_core::paths::secrets_file();
    let pass = Passphrase(passphrase);

    // Opening derives an Argon2id key (64 MiB, t=3 — encrypted_file.rs:82) and
    // `TimeoutStore::spawn` itself waits on a channel, so both halves block a
    // real thread. **Measured in a debug build on this machine: one
    // `EncryptedFileStore::open` takes ~1.37 s** (missing file 1.372 s,
    // existing file 1.352 s, wrong passphrase 1.381 s), comfortably inside
    // `DEFAULT_TIMEOUT_SECS` = 10. Nowhere near cheap enough for an async
    // worker. `spawn_blocking`, exactly as `poll_claimed`'s `save_snapshot`
    // call in `state.rs` does.
    let opened = tauri::async_runtime::spawn_blocking(move || {
        TimeoutStore::spawn(
            Duration::from_secs(quota_core::secrets::timeout::DEFAULT_TIMEOUT_SECS),
            move || {
                EncryptedFileStore::open(&path, pass.expose())
                    .map(|s| Box::new(s) as Box<dyn SecretStore>)
            },
        )
    })
    .await
    .map_err(|e| format!("the unlock task failed: {e}"))?;

    let store: Arc<dyn SecretStore> = match opened {
        Ok(s) => Arc::new(s),
        // A wrong passphrase arrives as `SecretError::Locked` with the wording
        // set at encrypted_file.rs:190 — "passphrase does not match, or the
        // store file is corrupt or tampered". That distinction is not guessable
        // from outside, so it is passed through rather than replaced. Note this
        // check only exists once the file exists: on a missing file any
        // passphrase opens an empty store (encrypted_file.rs:288-297).
        Err(e) => return Err(format!("the token store could not be opened: {e}")),
    };

    // Dropped after the write guard is released — see `install_store`.
    drop(state.install_store(store, StoreKind::EncryptedFile));
    // Every account has been failing against a store that was not there, so
    // each carries an exponential backoff of up to 64x the interval. Without
    // this the user types the right passphrase and nothing visible happens for
    // hours.
    state.scheduler.lock().await.retry_all_now();
    // Reuses Task 18's own event: what changed is the account *states*, and
    // `onAccountsChanged` re-reads `list_accounts`. That path does not depend on
    // the visibility gate, which matters because the user has been typing in the
    // settings window.
    let _ = app.emit("accounts://changed", ());

    Ok(store_status_now(&state))
}

/// Mirrors `SettingsView` in `src/lib/types.ts`. The two must be changed
/// together — the same contract `AccountView` carries above.
#[derive(serde::Serialize)]
pub struct SettingsView {
    /// The interval the scheduler is **actually running at**, read back from
    /// the live policy rather than from the file, so this window can never show
    /// a number the polling loop is not using.
    pub poll_interval_secs: i64,
    /// §6.1's floor, sent rather than hardcoded in the view.
    pub min_interval_secs: i64,
    pub max_interval_secs: i64,
    /// Why the stored settings were not used, if they were not.
    pub warning: Option<String>,
    /// False when the settings file on disk carries a format version this build
    /// cannot interpret. `set_settings` refuses in that case rather than
    /// rewriting a newer build's file, so the window disables the control
    /// instead of offering a save that is guaranteed to fail — and `warning`
    /// already carries the reason to show beside it.
    pub writable: bool,
}

/// The two locks are taken sequentially, never nested — see
/// `AppState::set_poll_interval`. Each guard is a temporary in its own `let`,
/// so it is dropped at the end of that statement.
async fn settings_view(state: &AppState) -> SettingsView {
    let poll_interval_secs = state.scheduler.lock().await.policy().interval().num_seconds();
    let (warning, writable) = {
        let settings = state.settings.lock().await;
        (settings.warning().map(str::to_string), settings.is_writable())
    };
    SettingsView {
        poll_interval_secs,
        min_interval_secs: PollPolicy::MIN_INTERVAL_SECS,
        max_interval_secs: PollPolicy::MAX_INTERVAL_SECS,
        warning,
        writable,
    }
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<SettingsView, String> {
    Ok(settings_view(&state).await)
}

/// Returns the value **actually applied**, which may differ from the one passed
/// in: §6.1's floor is a throttle position, not a preference. The settings
/// window writes this answer back into its field, so the clamp is visible
/// rather than silent.
///
/// **A refusal is an `Err`, never a quietly unchanged `SettingsView`.** A
/// settings file from a format version this build does not understand is
/// read-only — `SettingsStore::set_poll_interval_secs` answers
/// `SettingsError::UnknownVersion` before clamping, because rewriting that file
/// would delete the newer build's settings. Returning the view as if nothing
/// had happened would show the user the old interval with no reason given,
/// which is the settings-window form of the confidently-wrong display CLAUDE.md
/// forbids. `writable` on the view is the same fact offered ahead of time.
#[tauri::command]
pub async fn set_settings(
    state: State<'_, AppState>,
    poll_interval_secs: i64,
) -> Result<SettingsView, String> {
    state.set_poll_interval(poll_interval_secs).await?;
    Ok(settings_view(&state).await)
}

/// docs/design.md §8.4's "Debug: view the last raw JSON response (§5.5)".
///
/// `Ok(None)` means this account has not been polled successfully since the
/// process started — **not** that the response was empty. The panel renders the
/// two differently; `unwrap_or_default` here would be exactly the
/// confidently-wrong display CLAUDE.md forbids.
///
/// The body was masked at capture, in `usage::raw` — nothing is masked here,
/// and there is no unmasked copy anywhere to forget about. Takes neither
/// `scheduler` nor `accounts`, so it sits outside the lock order `AppState`'s
/// doc comment governs.
#[tauri::command]
pub async fn last_response(
    state: State<'_, AppState>,
    uuid: String,
) -> Result<Option<RawResponse>, String> {
    Ok(state.last_raw_for(&uuid))
}
