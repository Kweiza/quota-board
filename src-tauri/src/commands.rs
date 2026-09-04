use crate::state::{AppState, StoreKind};
use quota_core::auth::callback::Callback;
use quota_core::auth::pkce::{
    authorize_url_for, begin, manual_redirect_uri, parse_manual_code, success_redirect, PendingAuth,
};
use quota_core::auth::stored::{delete_tokens, load_tokens, revoke_tokens, save_anthropic_tokens};
use quota_core::auth::token::exchange_code;
#[cfg(test)]
use quota_core::auth::token::TokenSet;
use quota_core::model::AccountState;
#[cfg(test)]
use quota_core::provider::token_key;
use quota_core::provider::{Provider, ProviderSpec};
use quota_core::scheduler::PollPolicy;
use quota_core::secrets::{encrypted_file::EncryptedFileStore, timeout::TimeoutStore, SecretStore};
use quota_core::usage::raw::RawResponse;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{Emitter, Manager, State};
use tauri_plugin_autostart::ManagerExt;

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
    pub account_id: String,
    /// Which service this row belongs to. The widget shows a badge from it and
    /// gates §5.3's "weekly not reported" note on it.
    pub provider: Provider,
    pub label: String,
    /// Display only. **Never used as a key** (§9.3) — the key is the pair.
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
            account_id: a.account_id.clone(),
            provider: a.provider,
            label: a.display_label.clone(),
            email: a.email.clone(),
            state: sched.state(a.provider, &a.account_id).unwrap_or(AccountState::Loading),
        })
        .collect())
}

/// §6.3. Records what the widget webview reports; the polling loop combines it
/// with the window's own `is_visible()`/`is_minimized()` once per tick and is
/// the single writer of `Scheduler::set_visible`.
///
/// **The webview is the only caller, and the tray toggle deliberately is not
/// one** — an earlier draft of this comment said it would be. The loop already
/// re-reads the window's own visibility every tick, so hiding from the tray
/// closes the gate without help; pushing a `false` in here as well would create
/// the stale value this half cannot clear on its own, leaving polling off after
/// the widget came back until the 30-second heartbeat fired. See
/// `tray::toggle_widget`.
#[tauri::command]
pub async fn set_widget_visible(state: State<'_, AppState>, visible: bool) -> Result<(), String> {
    state.webview_visible.store(visible, Ordering::Relaxed);
    Ok(())
}

/// §9.1's account file could not be read, so the list is empty for a reason.
///
/// A separate command rather than a field on `AccountView`: the answer is about
/// the whole file, and there is no view to hang it on precisely when it
/// applies — the list is empty. `None` on the ordinary first run, which must
/// not be dressed up as a problem.
#[tauri::command]
pub async fn accounts_warning(state: State<'_, AppState>) -> Result<Option<String>, String> {
    Ok(state.accounts.lock().await.warning())
}

#[tauri::command]
pub async fn refresh_account(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    uuid: String,
    provider: Provider,
) -> Result<AccountState, String> {
    let (result, polled) = refresh_account_for(&state, provider, &uuid).await;
    // Only when a poll actually ran — not on the two early-return paths below.
    // Emitting there too would cost nothing functionally (every listener just
    // re-reads the list), but it is not what the pre-Task-9 behavior did, and
    // this task changes only *which account* is reached, never *when* this
    // fires.
    if polled {
        let _ = app.emit("usage://updated", ());
    }
    result
}

/// The whole of `refresh_account` except the event, so it can be tested
/// without an `AppHandle` — the same split `remove_account_for` uses.
///
/// Returns whether a poll actually ran, alongside the answer: the two early
/// returns below (throttled, already refreshing) must not fire
/// `usage://updated`, only the path that actually touched the network should,
/// and that is a fact about which branch ran, not about whether the final
/// `Result` came back `Ok`.
pub(crate) async fn refresh_account_for(
    state: &AppState,
    provider: Provider,
    uuid: &str,
) -> (Result<AccountState, String>, bool) {
    {
        let sched = state.scheduler.lock().await;
        // Already throttled by the server (§6.2), and this is now the **only**
        // thing that refuses a press. §6.1's client-side floor used to refuse
        // one too; §6.4 dropped it, because the moment a user asks is the
        // moment the number matters and the server's own bucket is the real
        // limit. This arm is a different question and it stays: re-hitting a
        // server that has just sent `Retry-After` spends the request without
        // shortening the block by a second (§6.2, measured).
        //
        // `AccountRow.svelte`'s `throttled` branch renders this state as
        // "throttled, after HH:MM" and `AccountList.svelte` renders it as
        // "throttled, available after HH:MM". Cited by name: both files move.
        if let Some(s @ AccountState::Throttled { .. }) = sched.state(provider, uuid) {
            return (Ok(s), false);
        }
    }
    // The braces above are load-bearing: a `MutexGuard` created in an `if let`
    // scrutinee lives to the end of that statement in edition 2021, so moving
    // the poll below inside them would deadlock against this very lock.

    // §7.1's AUTH_EXPIRED is "access token expired, **refresh in progress**".
    // Answer with it instead of blocking this UI command on the refresh mutex
    // for up to 30 seconds. `is_refreshing` is advisory by design
    // (auth/stored.rs:98-103) and drives a display state only.
    if state.refresh_locks.is_refreshing(provider, uuid) {
        return (Ok(AccountState::AuthExpired), false);
    }

    // `poll_one`, not `try_poll_one`: §6.4 requires the press to load, and
    // `try_poll_one` gives up whenever the polling loop happens to hold §6.1's
    // global permit — a click that vanishes with nothing on screen to say so,
    // which is the whole defect this path exists to avoid. Waiting is bounded
    // by one poll (`IN_FLIGHT_RECLAIM_SECS`, derived in scheduler.rs), and this
    // is an async command, so the wait costs a task and not the UI thread.
    // `AccountRow.svelte` disables its button for the duration.
    state.poll_one(provider, uuid).await;
    let result = state
        .scheduler
        .lock()
        .await
        .state(provider, uuid)
        .ok_or_else(|| "unknown account".to_string());
    (result, true)
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

/// §10.3's overall wait for the loopback callback.
const LOGIN_TIMEOUT_SECS: u64 = 300;

/// The wait, with a **`debug_assertions`-only** override so Step 8's manual
/// verification does not cost five minutes per attempt.
///
/// Release builds ignore the environment entirely, the same rule `usage_url()`
/// and `token_url()` state in `main.rs`: a shipped binary whose login window
/// anything on the machine could collapse would push users onto the paste path
/// at will.
///
/// A zero or unparseable value falls back rather than being honoured — a
/// zero-second timeout would fail every login instantly, which is a worse
/// outcome than ignoring a typo in a debugging variable.
#[cfg(debug_assertions)]
fn login_timeout_secs() -> u64 {
    std::env::var("QUOTA_LOGIN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(LOGIN_TIMEOUT_SECS)
}

#[cfg(not(debug_assertions))]
fn login_timeout_secs() -> u64 {
    LOGIN_TIMEOUT_SECS
}

/// The two authorize URLs one login has (§10.3: "Always construct both URLs").
///
/// Mirrors `LoginUrls` in `src/lib/types.ts`. Change both together.
#[derive(serde::Serialize)]
pub struct LoginUrls {
    /// `None` when no loopback socket could be bound, which is not fatal: the
    /// manual redirect needs no local port, so the login continues with the
    /// paste path alone.
    pub loopback: Option<String>,
    pub manual: String,
}

/// Payload of `auth://manual-fallback`. Mirrors `ManualFallback` in
/// `src/lib/types.ts`. Change both together.
#[derive(Clone, serde::Serialize)]
pub struct ManualFallback {
    pub url: String,
    /// Why the loopback path is not going to finish. Shown verbatim, so it is
    /// written for the user, not for a log.
    pub reason: String,
}

/// Anthropic's browser-login configuration. OpenAI never reaches this helper;
/// its device protocol is `quota_core::auth::openai`.
fn login_cfg(state: &AppState) -> ProviderSpec {
    state.cfg.clone()
}

/// Starts a login. Returns both authorize URLs; the loopback callback, when
/// there is one, is awaited in the background.
///
/// Events: `accounts://changed` on success, `auth://failed` when a login
/// definitely cannot be recovered, and `auth://manual-fallback` when the
/// loopback path gave up but §10.3's paste path still can finish it.
#[tauri::command]
pub async fn begin_login(app: tauri::AppHandle, provider: Provider) -> Result<LoginUrls, String> {
    if provider == Provider::Openai {
        return Err(
            "Codex login now requires the device-code flow; this desktop screen has not adopted it yet"
                .into(),
        );
    }
    if LOGIN_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("a login is already in progress".into());
    }
    let guard = LoginGuard;

    let cfg = login_cfg(&app.state::<AppState>());

    // Bind before building the authorize URL: `redirect_uri` must carry the
    // real port, and that exact string is replayed at token exchange
    // (auth/callback.rs:25-27, pkce.rs `PendingAuth::redirect_uri`).
    //
    // **A bind failure is no longer fatal.** It used to end the login; §10.3's
    // manual redirect needs no socket of our own, so the only thing lost is the
    // automatic half.
    let cb = Callback::bind().await;
    // `begin` returns a `Result` because `authorize_url` is user-overridable
    // (§10.2), so a bad config value surfaces here instead of crashing a login
    // in progress (pkce.rs:75-81).
    let (pending, loopback) = match &cb {
        Ok(cb) => {
            let (p, u) = begin(&cfg, &cb.redirect_uri()).map_err(|e| e.to_string())?;
            (p, Some(u))
        }
        // The PKCE pair still has to exist for the paste path, and this one is
        // born with the manual redirect_uri because it will never be exchanged
        // against any other.
        Err(_) => (begin(&cfg, manual_redirect_uri()).map_err(|e| e.to_string())?.0, None),
    };

    let manual = authorize_url_for(&cfg, &pending, manual_redirect_uri()).map_err(|e| e.to_string())?;

    // Stored before either path runs — see `AppState::pending_manual`. Only the
    // redirect_uri differs from `pending`; sharing the verifier and state is
    // what lets a code issued for either URL be exchanged here. `provider`
    // travels alongside it so `finish_manual_login` knows which token endpoint
    // a pasted code belongs to.
    *app.state::<AppState>().pending_manual.lock().unwrap() = Some((
        provider,
        PendingAuth {
            verifier: pending.verifier.clone(),
            state: pending.state.clone(),
            redirect_uri: manual_redirect_uri().to_string(),
        },
    ));

    let Ok(cb) = cb else {
        // Nothing to wait on, so `guard` drops here and releases the
        // single-flight flag rather than stranding it behind a task that does
        // not exist. The webview sees `loopback: None` and goes straight to the
        // paste form.
        return Ok(LoginUrls { loopback: None, manual });
    };

    let fallback_url = manual.clone();
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
            Duration::from_secs(login_timeout_secs()),
            // The second argument is the listener's own state guard, not a
            // duplicate of `exchange_code`'s check: the listener is
            // single-shot, so without it "a single stray or forged request
            // with the wrong state would consume the listener and strand the
            // real callback with nowhere to land" (callback.rs:59-61).
            cb.wait_for_code(success_redirect(), &pending.state),
        )
        .await;

        // Everything up to holding a code is a *loopback* failure, and §10.3's
        // paste path can still finish the same login — the PKCE pair is shared
        // and already stored. So these three report `auth://manual-fallback`
        // rather than `auth://failed`, which would tell the user a login had
        // ended when the half that can still work has not been offered yet.
        //
        // Each reason is a different sentence on purpose: "no callback arrived"
        // and "the callback was unreadable" send the user to different places,
        // and the first is the ordinary outcome of authorising in a browser on
        // another machine, which is the case this whole path exists for.
        let fallback = |reason: &str| {
            let _ = handle.emit(
                "auth://manual-fallback",
                ManualFallback { url: fallback_url.clone(), reason: reason.to_string() },
            );
        };

        let params = match waited {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                fallback(&format!("the browser reached this app but the reply could not be read ({e})"));
                return;
            }
            Err(_) => {
                fallback(
                    "no reply arrived from the browser. If it opened on another machine, \
                     it could not have reached this one",
                );
                return;
            }
        };

        let (Some(code), Some(returned_state)) = (params.get("code"), params.get("state")) else {
            fallback("the browser replied without an authorization code");
            return;
        };

        // This path reports both outcomes as events, because nobody is waiting
        // on its return value — it runs in a detached task.
        match complete_login(&state, provider, &pending, code, returned_state).await {
            Ok(()) => {
                let _ = handle.emit("accounts://changed", ());
            }
            Err(e) => {
                let _ = handle.emit("auth://failed", e);
            }
        }
    });

    Ok(LoginUrls { loopback, manual })
}

/// Mirrors `AutostartView` in `src/lib/types.ts`. Change both together.
#[derive(serde::Serialize)]
pub struct AutostartView {
    pub enabled: bool,
    /// False in a development build. Same shape as `SettingsView::writable`,
    /// and for the same reason: the window disables the control and says why,
    /// rather than offering one that is guaranteed to fail.
    pub writable: bool,
}

/// docs/design.md §11.3.
///
/// **Reading is always allowed; only writing is refused in a debug build.**
/// Knowing the state is harmless, and a window that could not read it would
/// have to either guess or show nothing.
#[tauri::command]
pub fn get_autostart(app: tauri::AppHandle) -> Result<AutostartView, String> {
    Ok(AutostartView {
        enabled: app.autolaunch().is_enabled().map_err(|e| e.to_string())?,
        writable: !cfg!(debug_assertions),
    })
}

/// docs/design.md §11.3. Answers with the state the OS reports afterwards, not
/// with the state that was asked for — the two can disagree.
///
/// **Refused in a development build.** The plugin resolves its target with
/// `std::env::current_exe()` at the moment it is enabled, so doing this here
/// would write a LaunchAgent pointing at `target/debug/quota-board`: a path the
/// user never installed, that `cargo clean` deletes, and that would then fail
/// silently at every login. §11.3 names this as a pitfall and says not to
/// validate autostart with a development build; refusing is what makes that
/// advice enforceable rather than a note somebody has to remember.
#[tauri::command]
pub fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<AutostartView, String> {
    if cfg!(debug_assertions) {
        return Err("this is a development build, so start-at-login cannot be changed here — \
                    it would register the build directory rather than an installed app"
            .into());
    }
    let mgr = app.autolaunch();
    if enabled {
        mgr.enable().map_err(|e| e.to_string())?;
    } else {
        mgr.disable().map_err(|e| e.to_string())?;
    }
    get_autostart(app)
}

/// §10.3's paste path: finishes a login whose loopback half did not.
///
/// Every refusal is a different sentence. "There is no login waiting", "that is
/// not the right shape" and "that belongs to an older attempt" need three
/// different actions from the user, and one shared message would leave them
/// guessing which.
#[tauri::command]
pub async fn submit_manual_code(app: tauri::AppHandle, pasted: String) -> Result<(), String> {
    finish_manual_login(&app.state::<AppState>(), &pasted).await?;
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

/// The whole of `submit_manual_code` except the event, so that it can be
/// tested: `src-tauri` has no dev-dependency on tauri's `test` feature, and a
/// function holding an `AppHandle` cannot be called without one. Same split as
/// `complete_login`, for the same reason.
pub(crate) async fn finish_manual_login(state: &AppState, pasted: &str) -> Result<(), String> {
    let (code, returned_state) = parse_manual_code(pasted).ok_or(
        "that is not a code#state line. Copy the whole line from the page, \
         including the # and everything after it",
    )?;

    // Cloned out from under the lock rather than held across the exchange: this
    // is a `std::sync` guard and `complete_login` awaits. `provider` travels
    // with `pending` — see `AppState::pending_manual` — so a pasted Codex code
    // is exchanged against Codex's token endpoint, not Anthropic's.
    let (provider, pending) = state
        .pending_manual
        .lock()
        .unwrap()
        .clone()
        .ok_or("no login is waiting for a code. Press Add account to start one")?;

    // **Advisory, not the enforcement.** `exchange_code` performs this same
    // comparison before it touches the network (auth/token.rs:226-231) and is
    // the authority; if the two ever disagreed, that one still refuses. This
    // exists only because its message — "state mismatch, the callback cannot be
    // trusted" — is written for the loopback path and says nothing a user
    // holding a pasted line can act on.
    if returned_state != pending.state {
        return Err("that code belongs to an older login attempt. Press Add account \
                    and use the link it gives you"
            .into());
    }

    complete_login(state, provider, &pending, code, returned_state).await
}

/// Exchanges an authorization code, stores the token, and registers the
/// account.
///
/// **Shared by both of §10.3's paths** — the loopback callback and the manual
/// paste. They differ only in `pending.redirect_uri`, which `exchange_code`
/// replays exactly as given, so nothing in here branches on which one is
/// running. One copy is the point: every failure below is a case where doing
/// the obvious thing instead would register a broken account, and a second copy
/// would go stale on whichever path its author was not looking at.
///
/// **Reports neither outcome itself, and takes no `AppHandle`.** The two
/// callers need different things: the detached loopback task has no return
/// value anyone reads and must emit both outcomes, while `submit_manual_code`
/// is a command whose rejection belongs in its own `Result` so the paste form
/// can show it beside the field. Keeping `AppHandle` out is also what makes
/// this function reachable from a test — `src-tauri` has no dev-dependency on
/// `tauri`'s `test` feature, so anything holding a handle cannot be called
/// without one.
pub(crate) async fn complete_login(
    state: &AppState,
    provider: Provider,
    pending: &PendingAuth,
    code: &str,
    returned_state: &str,
) -> Result<(), String> {
    if provider == Provider::Openai {
        return Err(
            "Codex login uses device authorization; the browser-paste flow is Claude-only".into(),
        );
    }
    let cfg = login_cfg(state);
    let (tokens, identity) = exchange_code(&state.http, &cfg, pending, code, returned_state)
        .await
        .map_err(|e| e.to_string())?;
    // Without an identifier there is no key. Never substitute the email
    // (§9.3) — it is display-only and user-editable. Reachable only for
    // Anthropic: `exchange_code` never returns `Ok((_, None))` for OpenAI,
    // whose absence instead fails loudly through `AuthError::NoAccountIdentifier`
    // above (Step 3 of the Codex login task).
    let identity = identity.ok_or("the token response carried no account block")?;

    // Synchronous and able to block a real thread (timeout.rs:144-156), so it
    // goes on a blocking thread rather than an async worker — the same
    // principle `refresh_account` applies when it answers AUTH_EXPIRED instead
    // of waiting on the refresh mutex.
    let store = state.secrets();
    let id = identity.uuid.clone();
    tauri::async_runtime::spawn_blocking(move || {
        save_anthropic_tokens(store.as_ref(), &id, &tokens)
    })
        .await
        .map_err(|e| format!("the token store task failed: {e}"))?
        .map_err(|e| format!("the token could not be stored: {e}"))?;

    state
        .register_authenticated(provider, &identity.uuid, &identity.email, None)
        .await
        .map_err(|e| format!("the account could not be saved: {e}"))?;

    // The login is over, so §10.3's paste copy of it is a dead value. Left
    // behind, the next loopback failure would hand the user a form that refuses
    // every code as belonging to an older attempt. Cleared here rather than in
    // `submit_manual_code` so a login finished through the loopback clears it
    // too — both routes end here.
    *state.pending_manual.lock().unwrap() = None;

    Ok(())
}

#[tauri::command]
pub async fn remove_account(
    app: tauri::AppHandle,
    uuid: String,
    provider: Provider,
) -> Result<(), String> {
    remove_account_for(&app.state::<AppState>(), provider, &uuid).await?;
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

/// The whole of `remove_account` except the event, so it can be tested without
/// an `AppHandle` — the same split `finish_manual_login`/`complete_login` use.
///
/// Takes `provider` rather than assuming Anthropic: the primary key is the
/// pair (§9.3), and an id-only lookup would remove the wrong account, or
/// nothing at all, whenever a Codex account happens to share an id with a
/// Claude one.
pub(crate) async fn remove_account_for(
    state: &AppState,
    provider: Provider,
    uuid: &str,
) -> Result<(), String> {
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
    let loaded = {
        let store = Arc::clone(&store);
        let id = uuid.to_string();
        tauri::async_runtime::spawn_blocking(move || load_tokens(store.as_ref(), provider, &id))
            .await
    };
    if let Ok(Ok(tokens)) = loaded {
        revoke_tokens(&state.http, &state.auth_configs, &tokens).await;
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
        let id = uuid.to_string();
        if let Ok(Err(e)) = tauri::async_runtime::spawn_blocking(move || {
            delete_tokens(store.as_ref(), provider, &id)
        })
        .await
        {
            eprintln!(
                "{uuid}: the stored token could not be deleted ({e}); it may still be in the \
                 credential store"
            );
        }
    }

    // Lock order: scheduler before accounts.
    state.scheduler.lock().await.remove(provider, uuid);
    let removed =
        state.accounts.lock().await.remove(provider, uuid).map_err(|e| e.to_string())?;
    if !removed {
        // `AccountStore::remove` answers `Ok(false)` for an unknown (provider,
        // id) pair (accounts.rs:137-149). Emitting `accounts://changed` for a
        // removal that removed nothing would tell every window to re-read for
        // no reason. Same shape as `rename_account`'s unknown-account arm.
        return Err("unknown account".into());
    }

    // Removing an account must remove its cached usage too, or the app keeps
    // percentages and reset times on disk for an account the user deleted.
    // `snapshots::remove` (snapshots.rs:80) exists for exactly this and had no
    // caller.
    let path = state.snapshots_path.clone();
    let id = uuid.to_string();
    if let Ok(Err(e)) = tauri::async_runtime::spawn_blocking(move || {
        quota_core::snapshots::remove(&path, provider, &id)
    })
            .await
    {
        eprintln!("{uuid}: the cached snapshot could not be removed: {e}");
    }
    state.forget_raw(provider, uuid);

    Ok(())
}

/// One account's key, as a reorder needs it: the pair is the primary key
/// (§9.3), so a bare id would let two providers sharing an id collide.
#[derive(serde::Deserialize)]
pub struct AccountKey {
    pub account_id: String,
    pub provider: Provider,
}

#[tauri::command]
pub async fn rename_account(
    app: tauri::AppHandle,
    uuid: String,
    label: String,
    provider: Provider,
) -> Result<(), String> {
    rename_account_for(&app.state::<AppState>(), provider, &uuid, label).await?;
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

/// The whole of `rename_account` except the event, so it can be tested
/// without an `AppHandle` — the same split `remove_account_for` uses.
///
/// Looks the account up by (provider, id), not id alone: a bare-id lookup
/// would rename whichever of two same-id accounts across providers happened
/// to sort first, silently leaving the one actually asked for untouched.
pub(crate) async fn rename_account_for(
    state: &AppState,
    provider: Provider,
    uuid: &str,
    label: String,
) -> Result<(), String> {
    let mut accounts = state.accounts.lock().await;
    let Some(mut a) =
        accounts.list().iter().find(|a| a.account_id == uuid && a.provider == provider).cloned()
    else {
        return Err("unknown account".into());
    };
    a.display_label = label;
    accounts.upsert(a).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn reorder_accounts(app: tauri::AppHandle, keys: Vec<AccountKey>) -> Result<(), String> {
    let pairs: Vec<(Provider, String)> =
        keys.into_iter().map(|k| (k.provider, k.account_id)).collect();
    reorder_accounts_for(&app.state::<AppState>(), pairs).await?;
    let _ = app.emit("accounts://changed", ());
    Ok(())
}

/// The whole of `reorder_accounts` except the event, so it can be tested
/// without an `AppHandle` — the same split `remove_account_for` uses.
pub(crate) async fn reorder_accounts_for(
    state: &AppState,
    keys: Vec<(Provider, String)>,
) -> Result<(), String> {
    state.accounts.lock().await.reorder(&keys).map_err(|e| e.to_string())
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
                        unlock it in the OS and restart Quota Board. A passphrase \
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
    provider: Provider,
) -> Result<Option<RawResponse>, String> {
    Ok(state.last_raw_for(provider, &uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::app_state;
    use quota_core::auth::pkce::PendingAuth;
    use quota_core::secrets::MemoryStore;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The manual pending a `begin_login` would have left behind, for the
    /// given provider.
    fn armed_as(state: &AppState, provider: Provider) -> PendingAuth {
        let pending = PendingAuth {
            verifier: "v-verifier".into(),
            state: "s-state".into(),
            redirect_uri: manual_redirect_uri().to_string(),
        };
        *state.pending_manual.lock().unwrap() = Some((provider, pending.clone()));
        pending
    }

    /// `armed_as` fixed to `Provider::Anthropic`, which is what every test in
    /// this module needed before Codex had a login path of its own.
    fn armed(state: &AppState) -> PendingAuth {
        armed_as(state, Provider::Anthropic)
    }

    /// The browser helper is now Anthropic-only. This test keeps its debug URL
    /// seam real without implying that OpenAI shares the protocol.
    #[test]
    fn the_browser_login_cfg_carries_the_anthropic_override() {
        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.cfg.token_url = "http://127.0.0.1:1/overridden-anthropic".into();
        assert_eq!(login_cfg(&state).token_url, state.cfg.token_url);
    }

    fn token_body(account: Option<serde_json::Value>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "access_token": "at-1",
            "refresh_token": "rt-1",
            "expires_in": 3600,
            "refresh_token_expires_in": 86400,
            "scope": "user:profile",
        });
        if let Some(a) = account {
            body["account"] = a;
        }
        body
    }

    async fn state_against(server: &MockServer) -> AppState {
        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.cfg.token_url = format!("{}/v1/oauth/token", server.uri());
        state
    }

    #[tokio::test]
    async fn a_paste_with_no_login_waiting_is_refused_by_name() {
        let state = app_state(Arc::new(MemoryStore::default()));
        let e = finish_manual_login(&state, "code#s-state").await.unwrap_err();
        assert!(e.contains("no login is waiting"), "{e}");
    }

    /// The paste is refused **before** the pending is consulted, so a user who
    /// pasted the URL instead of the code is told which of the two they got
    /// wrong.
    #[tokio::test]
    async fn a_paste_that_is_not_code_hash_state_is_refused_by_name() {
        let state = app_state(Arc::new(MemoryStore::default()));
        armed(&state);
        for bad in ["justacode", "#s-state", "a#b#c", ""] {
            let e = finish_manual_login(&state, bad).await.unwrap_err();
            assert!(e.contains("code#state"), "{bad:?} produced the wrong message: {e}");
        }
    }

    /// A code from a login that has since been replaced. `exchange_code` would
    /// also refuse this, but with a sentence about a callback the user never
    /// saw — hence the advisory check ahead of it.
    #[tokio::test]
    async fn a_code_from_an_older_attempt_is_refused_by_name() {
        let state = app_state(Arc::new(MemoryStore::default()));
        armed(&state);
        let e = finish_manual_login(&state, "the-code#a-different-state").await.unwrap_err();
        assert!(e.contains("older login attempt"), "{e}");
    }

    /// The whole point of the task: a pasted code registers the account and
    /// stores its token. Nothing in this repository covered this path before.
    #[tokio::test]
    async fn a_good_paste_stores_the_token_and_registers_the_account() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(Some(
                serde_json::json!({ "uuid": "u-42", "email_address": "who@example.invalid" }),
            ))))
            .mount(&server)
            .await;

        let state = state_against(&server).await;
        armed(&state);

        finish_manual_login(&state, "  the-code#s-state \n").await.unwrap();

        let stored = state.secrets().get(&token_key(Provider::Anthropic, "u-42")).unwrap();
        assert!(stored.is_some(), "the token never reached the store");
        let tokens: TokenSet = serde_json::from_slice(&stored.unwrap()).unwrap();
        assert_eq!(tokens.access_token, "at-1");

        let accounts = state.accounts.lock().await;
        let a =
            accounts.list().iter().find(|a| a.account_id == "u-42").expect("account not registered");
        assert_eq!(a.email, "who@example.invalid");

        // The login is over; the paste form must not stay armed with a value
        // that would refuse every later code as belonging to an older attempt.
        assert!(
            state.pending_manual.lock().unwrap().is_none(),
            "the finished login was left armed"
        );
    }

    /// OpenAI device authorization has no pasteable `code#state` route. The
    /// old desktop path reused Anthropic's manual redirect and only failed
    /// after a real code had been spent. Refuse before the token endpoint and
    /// before either store changes; `auth::openai` owns the replacement flow.
    #[tokio::test]
    async fn a_codex_paste_is_refused_without_storing_or_registering_anything() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.auth_configs.openai.token_url = format!("{}/oauth/token", server.uri());
        armed_as(&state, Provider::Openai);

        let err = finish_manual_login(&state, "the-code#s-state")
            .await
            .unwrap_err();
        assert!(err.contains("device authorization"), "wrong refusal: {err}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "the code was sent anyway"
        );
        assert!(
            state
                .accounts
                .lock()
                .await
                .list()
                .iter()
                .all(|a| a.provider != Provider::Openai),
            "a refused paste registered an OpenAI account"
        );
        assert!(
            state
                .secrets()
                .get(&token_key(Provider::Openai, "codex-user-1"))
                .unwrap()
                .is_none(),
            "a refused paste stored a credential"
        );
    }

    /// §9.3: `account.uuid` is the primary key and the email is display-only,
    /// so a response with no account block has no key to store under. It must
    /// fail rather than substitute the email — and it must not leave a token
    /// behind under some other name.
    #[tokio::test]
    async fn a_response_without_an_account_block_is_refused_and_stores_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_body(None)))
            .mount(&server)
            .await;

        let state = state_against(&server).await;
        armed(&state);

        let e = finish_manual_login(&state, "the-code#s-state").await.unwrap_err();
        assert!(e.contains("no account block"), "{e}");
        assert!(
            state.accounts.lock().await.list().iter().all(|a| a.email != "who@example.invalid"),
            "an account was registered from a response that carried no uuid"
        );
        // Still armed: the user may paste again, and a refused attempt must not
        // cost them the URL.
        assert!(state.pending_manual.lock().unwrap().is_some(), "a refusal disarmed the form");
    }

    /// The fourth provider-blind command, missed by this task's own brief and
    /// found only once the other three were fixed: `refresh_account` is the
    /// per-row refresh button, so a bare-id lookup would let a press on a
    /// Codex row read (or wait on, or poll) whichever provider's account
    /// happens to share the pressed id.
    ///
    /// `app_state` already registers Anthropic "a" in the scheduler; this adds
    /// an Openai "a" beside it and throttles *only* the Anthropic one. A press
    /// for the Openai account must not read that throttle — reading it is
    /// exactly what `Provider::Anthropic` hardcoded into the lookup would do.
    #[tokio::test]
    async fn refresh_account_acts_on_the_matching_provider() {
        let state = app_state(Arc::new(MemoryStore::default()));
        state.scheduler.lock().await.add(Provider::Openai, "a");
        state.scheduler.lock().await.record_throttle(Provider::Anthropic, "a", 60);

        let (result, polled) = refresh_account_for(&state, Provider::Openai, "a").await;

        assert!(
            !matches!(result, Ok(AccountState::Throttled { .. })),
            "the press for the Openai account read the Anthropic account's throttle instead: {result:?}"
        );
        assert!(polled, "the Openai account's refresh press never polled");
    }

    /// Clones `app_state`'s Anthropic "a" into an Openai account sharing the
    /// same id — the exact collision (provider, id) exists to resolve. Reusing
    /// the seeded account rather than hand-building one keeps this test in the
    /// construction style the module already uses.
    async fn add_openai_twin_of_a(state: &AppState) {
        let mut accounts = state.accounts.lock().await;
        let mut twin = accounts.list().iter().find(|a| a.account_id == "a").unwrap().clone();
        twin.provider = Provider::Openai;
        twin.workspace_id = Some("workspace-a".into());
        accounts.upsert(twin).unwrap();
    }

    /// docs/design.md §9.3: the primary key is the pair, not the bare id.
    /// Mutating `remove_account_for`'s provider check to match on the id alone
    /// would delete the Anthropic account here instead of its Openai twin, or
    /// delete both — this is the test that catches it.
    #[tokio::test]
    async fn remove_account_only_removes_the_matching_provider() {
        let state = app_state(Arc::new(MemoryStore::default()));
        {
            let mut accounts = state.accounts.lock().await;
            // Only the colliding pair matters here; `app_state`'s incidental
            // second seeded account ("b") would otherwise survive the removal
            // too and blur the exact count this test is about.
            accounts.remove(Provider::Anthropic, "b").unwrap();
        }
        add_openai_twin_of_a(&state).await;

        remove_account_for(&state, Provider::Openai, "a").await.unwrap();

        let accounts = state.accounts.lock().await;
        assert_eq!(
            accounts.list().len(),
            1,
            "removing the Openai twin should leave exactly the Anthropic account behind"
        );
        assert_eq!(
            accounts.list()[0].provider,
            Provider::Anthropic,
            "the Anthropic account was removed instead of its Openai twin"
        );
    }

    /// Same premise, for `reorder_accounts_for`: it must move the pair asked
    /// for, not merely an account whose id half happens to match. Asked to
    /// move the Openai twin to the front, the Anthropic account sharing its id
    /// must stay at the position requested for it rather than being the one
    /// that moves.
    #[tokio::test]
    async fn reorder_accounts_moves_the_matching_provider() {
        let state = app_state(Arc::new(MemoryStore::default()));
        add_openai_twin_of_a(&state).await;

        reorder_accounts_for(
            &state,
            vec![
                (Provider::Openai, "a".to_string()),
                (Provider::Anthropic, "b".to_string()),
                (Provider::Anthropic, "a".to_string()),
            ],
        )
        .await
        .unwrap();

        let accounts = state.accounts.lock().await;
        let order: Vec<(Provider, String)> =
            accounts.list().iter().map(|a| (a.provider, a.account_id.clone())).collect();
        assert_eq!(
            order,
            vec![
                (Provider::Openai, "a".to_string()),
                (Provider::Anthropic, "b".to_string()),
                (Provider::Anthropic, "a".to_string()),
            ],
            "reorder did not produce the requested order"
        );
    }

    /// Same premise again, for `rename_account_for`: renaming the Openai twin
    /// must not touch the Anthropic account sharing its id.
    #[tokio::test]
    async fn rename_account_only_renames_the_matching_provider() {
        let state = app_state(Arc::new(MemoryStore::default()));
        add_openai_twin_of_a(&state).await;

        rename_account_for(&state, Provider::Openai, "a", "renamed".to_string()).await.unwrap();

        let accounts = state.accounts.lock().await;
        let anthropic_a = accounts
            .list()
            .iter()
            .find(|a| a.account_id == "a" && a.provider == Provider::Anthropic)
            .expect("the Anthropic account vanished");
        assert_eq!(
            anthropic_a.display_label, "a",
            "the Anthropic account's label changed even though only its Openai twin was renamed"
        );
        let openai_a = accounts
            .list()
            .iter()
            .find(|a| a.account_id == "a" && a.provider == Provider::Openai)
            .expect("the Openai twin vanished");
        assert_eq!(openai_a.display_label, "renamed");
    }

    /// The one call inside `remove_account_for` that did not get the provider:
    /// server-side revocation. Sending an OpenAI refresh token to Anthropic's
    /// revoke endpoint is not a silent no-op — it is a live credential
    /// reaching a vendor it does not belong to, which is exactly what
    /// CLAUDE.md's token rules exist to prevent.
    ///
    /// Two separate mock servers, no mock mounted on the Anthropic one: if
    /// the Codex removal reached it anyway, wiremock would still answer with
    /// its own default 404 and the call would swallow that outcome (§10.6) —
    /// the point is caught by `received_requests()` below, not by whether
    /// `remove_account_for` itself failed. Same shape as
    /// `a_codex_account_is_polled_against_its_own_url_not_anthropics` in
    /// `state.rs`.
    #[tokio::test]
    async fn removing_a_codex_account_revokes_against_the_openai_endpoint_not_anthropics() {
        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(200)).mount(&openai_server).await;
        // Deliberately no `Mock` mounted on `anthropic_server` — see the doc
        // comment above.

        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.cfg.revoke_url = format!("{}/v1/oauth/token/revoke", anthropic_server.uri());
        state.auth_configs.anthropic.revoke_url =
            format!("{}/v1/oauth/token/revoke", anthropic_server.uri());
        state.auth_configs.openai.revoke_url = format!("{}/oauth/revoke", openai_server.uri());
        add_openai_twin_of_a(&state).await;

        let tokens = quota_core::auth::openai::OpenAiTokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            client_id: "test".into(),
            user_id: "a".into(),
            workspace_id: Some("workspace-a".into()),
            is_fedramp: None,
        };
        quota_core::auth::stored::save_openai_tokens(state.secrets().as_ref(), "a", &tokens)
            .unwrap();

        remove_account_for(&state, Provider::Openai, "a").await.unwrap();

        assert!(
            !openai_server.received_requests().await.unwrap().is_empty(),
            "the Codex account's revoke never reached its own endpoint"
        );
        assert!(
            anthropic_server.received_requests().await.unwrap().is_empty(),
            "a Codex refresh token was sent to Anthropic's revoke endpoint"
        );
    }

    /// §9.3 again, one layer up from `usage::raw::RawLog`'s own pair-key test:
    /// `remove_account_for` must forget only the (provider, id) pair it was
    /// given. Mutating its `forget_raw` call back to a bare id — or to
    /// `Provider::Anthropic` — would delete the Anthropic account's debug
    /// capture when the Openai twin sharing its id is removed instead.
    #[tokio::test]
    async fn removing_a_codex_account_does_not_forget_the_anthropic_accounts_raw_capture() {
        let state = app_state(Arc::new(MemoryStore::default()));
        add_openai_twin_of_a(&state).await;

        let v = serde_json::json!({ "five_hour": null });
        {
            let mut log = state.last_raw.lock().unwrap();
            log.record(Provider::Anthropic, "a", RawResponse::capture(200, &v));
            log.record(Provider::Openai, "a", RawResponse::capture(200, &v));
        }

        remove_account_for(&state, Provider::Openai, "a").await.unwrap();

        assert!(
            state.last_raw_for(Provider::Anthropic, "a").is_some(),
            "removing the Openai twin erased the Anthropic account's raw capture"
        );
        assert!(
            state.last_raw_for(Provider::Openai, "a").is_none(),
            "the removed Openai account's raw capture was not forgotten"
        );
    }
}
