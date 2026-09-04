use crate::state::{AppState, PendingManual, StoreKind};
use quota_core::auth::callback::Callback;
use quota_core::auth::openai::{self, DeviceCode, OpenAiIdentity, OpenAiPendingAuth, OpenAiTokenSet};
use quota_core::auth::pkce::{
    authorize_url_for, begin, manual_redirect_uri, parse_manual_code, success_redirect, PendingAuth,
};
use quota_core::auth::stored::{
    delete_tokens, load_tokens, revoke_tokens, StoredTokens,
};
use quota_core::auth::token::{exchange_code as exchange_anthropic_code, AuthError};
use quota_core::model::AccountState;
use quota_core::provider::Provider;
use quota_core::scheduler::PollPolicy;
use quota_core::secrets::{encrypted_file::EncryptedFileStore, timeout::TimeoutStore, SecretStore};
use quota_core::usage::raw::RawResponse;
use std::sync::atomic::{AtomicU64, Ordering};
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
const NO_LOGIN: u64 = 0;
static LOGIN_IN_FLIGHT: AtomicU64 = AtomicU64::new(NO_LOGIN);
static NEXT_LOGIN_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Releases the flag on **every** exit path, including an early `return` deep
/// inside the spawned task. A bare `store(false)` on the happy path would let
/// one failed login block every later one for the life of the process, with
/// the flag claiming a login is in progress and no task behind it.
struct LoginGuard {
    generation: u64,
}

impl Drop for LoginGuard {
    fn drop(&mut self) {
        let _ = LOGIN_IN_FLIGHT.compare_exchange(
            self.generation,
            NO_LOGIN,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
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

/// The provider-specific login the settings window should present.
///
/// Internally tagged so the webview cannot mistake a Codex browser/device flow
/// for Claude's manual `code#state` path. Mirrors `LoginStart` in
/// `src/lib/types.ts`.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoginStart {
    ClaudeBrowser {
        /// `None` when no loopback socket could be bound. Claude's manual URL
        /// remains usable without one.
        loopback: Option<String>,
        manual: String,
    },
    CodexBrowser {
        authorize_url: String,
    },
    CodexDevice {
        verification_url: String,
        /// A short-lived credential intentionally shown to the user. This type
        /// does not derive `Debug`, so it cannot leak through incidental logs.
        user_code: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
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

enum LoginTask {
    ClaudeBrowser {
        generation: u64,
        callback: Callback,
        pending: PendingAuth,
        fallback_url: String,
        cancelled: tokio::sync::oneshot::Receiver<()>,
    },
    CodexBrowser {
        generation: u64,
        callback: Callback,
        pending: OpenAiPendingAuth,
    },
    CodexDevice {
        generation: u64,
        device: DeviceCode,
    },
}

struct PreparedLogin {
    start: LoginStart,
    task: Option<LoginTask>,
}

enum LoginTaskFailure {
    ClaudeFallback(ManualFallback),
    Terminal(String),
    Cancelled,
}

fn codex_device_start_error(error: AuthError) -> String {
    if matches!(error, AuthError::OAuth { status: 404, .. }) {
        return "Codex device sign-in is unavailable; enable it in ChatGPT security/workspace settings or free localhost ports 1455/1457 and try again".into();
    }
    error.to_string()
}

fn finish_login_generation(state: &AppState, generation: u64) {
    let mut active = state.active_login.lock().unwrap();
    if *active != Some(generation) {
        return;
    }
    *active = None;
    let mut pending = state.pending_manual.lock().unwrap();
    if pending.as_ref().is_some_and(|value| value.generation == generation) {
        if let Some(cancel) = pending.take().and_then(|value| value.cancel) {
            let _ = cancel.send(());
        }
    }
}

fn release_login_single_flight(generation: u64) {
    let _ = LOGIN_IN_FLIGHT.compare_exchange(
        generation,
        NO_LOGIN,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
}

fn login_generation_is_active(state: &AppState, generation: u64) -> bool {
    *state.active_login.lock().unwrap() == Some(generation)
}

async fn install_login_generation(
    state: &AppState,
    generation: u64,
    pending: Option<PendingManual>,
) {
    let _commit = state.login_commit.lock().await;
    let mut active = state.active_login.lock().unwrap();
    let mut slot = state.pending_manual.lock().unwrap();
    if let Some(cancel) = slot.take().and_then(|value| value.cancel) {
        let _ = cancel.send(());
    }
    *slot = pending;
    *active = Some(generation);
}

async fn prepare_claude_login(
    state: &AppState,
    generation: u64,
    callback: std::io::Result<Callback>,
) -> Result<PreparedLogin, String> {
    let cfg = &state.auth_configs.anthropic;
    let (pending, loopback, callback) = match callback {
        Ok(callback) => {
            let (pending, url) =
                begin(cfg, &callback.redirect_uri()).map_err(|e| e.to_string())?;
            (pending, Some(url), Some(callback))
        }
        Err(_) => (
            begin(cfg, manual_redirect_uri())
                .map_err(|e| e.to_string())?
                .0,
            None,
            None,
        ),
    };
    let manual = authorize_url_for(cfg, &pending, manual_redirect_uri())
        .map_err(|e| e.to_string())?;

    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let has_callback = callback.is_some();
    install_login_generation(
        state,
        generation,
        Some(PendingManual {
            generation,
            pending: PendingAuth {
                verifier: pending.verifier.clone(),
                state: pending.state.clone(),
                redirect_uri: manual_redirect_uri().to_string(),
            },
            cancel: has_callback.then_some(cancel),
        }),
    )
    .await;

    let task = callback.map(|callback| LoginTask::ClaudeBrowser {
        generation,
        callback,
        pending,
        fallback_url: manual.clone(),
        cancelled,
    });
    Ok(PreparedLogin {
        start: LoginStart::ClaudeBrowser { loopback, manual },
        task,
    })
}

async fn prepare_codex_login(
    state: &AppState,
    generation: u64,
    callback: std::io::Result<Callback>,
) -> Result<PreparedLogin, String> {
    match callback {
        Ok(callback) => {
            let (pending, authorize_url) =
                openai::begin_browser(&state.auth_configs.openai, &callback)
                    .map_err(|e| e.to_string())?;
            install_login_generation(state, generation, None).await;
            Ok(PreparedLogin {
                start: LoginStart::CodexBrowser { authorize_url },
                task: Some(LoginTask::CodexBrowser {
                    generation,
                    callback,
                    pending,
                }),
            })
        }
        Err(_) => {
            let device = openai::request_device_code(&state.http, &state.auth_configs.openai)
                .await
                .map_err(codex_device_start_error)?;
            let start = LoginStart::CodexDevice {
                verification_url: device.verification_url.clone(),
                user_code: device.user_code.clone(),
                expires_at: device.expires_at,
            };
            install_login_generation(state, generation, None).await;
            Ok(PreparedLogin {
                start,
                task: Some(LoginTask::CodexDevice { generation, device }),
            })
        }
    }
}

async fn register_openai_grant(
    state: &AppState,
    tokens: OpenAiTokenSet,
    identity: OpenAiIdentity,
) -> Result<(), String> {
    state
        .register_authenticated(
            &identity.account_id,
            &identity.email,
            StoredTokens::Openai(tokens),
        )
        .await
}

async fn complete_anthropic_login(
    state: &AppState,
    pending: &PendingAuth,
    code: &str,
    returned_state: &str,
) -> Result<(), String> {
    let (tokens, identity) = exchange_anthropic_code(
        &state.http,
        &state.auth_configs.anthropic,
        Provider::Anthropic,
        pending,
        code,
        returned_state,
    )
    .await
    .map_err(|e| e.to_string())?;
    let identity = identity.ok_or("the token response carried no account block")?;
    state
        .register_authenticated(
            &identity.uuid,
            &identity.email,
            StoredTokens::Anthropic(tokens),
        )
        .await?;
    Ok(())
}

async fn run_login_task(
    state: &AppState,
    task: LoginTask,
) -> Result<Provider, LoginTaskFailure> {
    match task {
        LoginTask::ClaudeBrowser {
            generation,
            callback,
            pending,
            fallback_url,
            mut cancelled,
        } => {
            let waited = tokio::select! {
                _ = &mut cancelled => return Err(LoginTaskFailure::Cancelled),
                waited = tokio::time::timeout(
                    Duration::from_secs(login_timeout_secs()),
                    callback.wait_for_code(success_redirect(), &pending.state),
                ) => waited,
            };
            let fallback = |reason: String| {
                LoginTaskFailure::ClaudeFallback(ManualFallback {
                    url: fallback_url.clone(),
                    reason,
                })
            };
            let params = match waited {
                Ok(Ok(params)) => params,
                Ok(Err(e)) => {
                    return Err(fallback(format!(
                        "the browser reached this app but the reply could not be read ({e})"
                    )))
                }
                Err(_) => {
                    return Err(fallback(
                        "no reply arrived from the browser. If it opened on another machine, it could not have reached this one"
                            .into(),
                    ))
                }
            };
            let (Some(code), Some(returned_state)) =
                (params.get("code"), params.get("state"))
            else {
                return Err(fallback(
                    "the browser replied without an authorization code".into(),
                ));
            };
            let _commit = state.login_commit.lock().await;
            if !login_generation_is_active(state, generation) {
                return Err(LoginTaskFailure::Cancelled);
            }
            if let Err(error) =
                complete_anthropic_login(state, &pending, code, returned_state).await
            {
                finish_login_generation(state, generation);
                return Err(LoginTaskFailure::Terminal(error));
            }
            finish_login_generation(state, generation);
            Ok(Provider::Anthropic)
        }
        LoginTask::CodexBrowser {
            generation,
            callback,
            pending,
        } => {
            let params = tokio::time::timeout(
                Duration::from_secs(login_timeout_secs()),
                callback.wait_for_code(&state.auth_configs.openai.issuer, pending.state()),
            )
            .await;
            let params = match params {
                Ok(Ok(params)) => params,
                Ok(Err(e)) => {
                    finish_login_generation(state, generation);
                    return Err(LoginTaskFailure::Terminal(format!(
                        "the browser callback could not be read ({e})"
                    )));
                }
                Err(_) => {
                    finish_login_generation(state, generation);
                    return Err(LoginTaskFailure::Terminal(
                        "no reply arrived from the browser".into(),
                    ));
                }
            };
            let (Some(code), Some(returned_state)) =
                (params.get("code"), params.get("state"))
            else {
                finish_login_generation(state, generation);
                return Err(LoginTaskFailure::Terminal(
                    "the browser replied without an authorization code".into(),
                ));
            };
            let _commit = state.login_commit.lock().await;
            if !login_generation_is_active(state, generation) {
                return Err(LoginTaskFailure::Cancelled);
            }
            let exchanged = openai::exchange_code(
                &state.http,
                &state.auth_configs.openai,
                &pending,
                code,
                returned_state,
            )
            .await;
            let (tokens, identity) = match exchanged {
                Ok(value) => value,
                Err(error) => {
                    finish_login_generation(state, generation);
                    return Err(LoginTaskFailure::Terminal(error.to_string()));
                }
            };
            if let Err(error) = register_openai_grant(state, tokens, identity).await {
                finish_login_generation(state, generation);
                return Err(LoginTaskFailure::Terminal(error));
            }
            finish_login_generation(state, generation);
            Ok(Provider::Openai)
        }
        LoginTask::CodexDevice { generation, device } => {
            let completed = openai::complete_device_code(
                &state.http,
                &state.auth_configs.openai,
                &device,
            )
            .await;
            let _commit = state.login_commit.lock().await;
            if !login_generation_is_active(state, generation) {
                return Err(LoginTaskFailure::Cancelled);
            }
            let (tokens, identity) = match completed {
                Ok(value) => value,
                Err(error) => {
                    finish_login_generation(state, generation);
                    return Err(LoginTaskFailure::Terminal(error.to_string()));
                }
            };
            if let Err(error) = register_openai_grant(state, tokens, identity).await {
                finish_login_generation(state, generation);
                return Err(LoginTaskFailure::Terminal(error));
            }
            finish_login_generation(state, generation);
            Ok(Provider::Openai)
        }
    }
}

/// Starts the selected provider's login and waits for its completion in the
/// background when there is a listener or device grant to wait on.
///
/// Events: `accounts://changed` on success, `auth://failed` when a login
/// definitely cannot be recovered, and `auth://manual-fallback` when the
/// loopback path gave up but §10.3's paste path still can finish it.
#[tauri::command]
pub async fn begin_login(app: tauri::AppHandle, provider: Provider) -> Result<LoginStart, String> {
    let generation = NEXT_LOGIN_GENERATION.fetch_add(1, Ordering::SeqCst);
    if LOGIN_IN_FLIGHT
        .compare_exchange(NO_LOGIN, generation, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("a login is already in progress".into());
    }
    let guard = LoginGuard { generation };

    let state = app.state::<AppState>();
    let prepared = match provider {
        Provider::Anthropic => {
            prepare_claude_login(&state, generation, Callback::bind().await).await?
        }
        Provider::Openai => {
            prepare_codex_login(&state, generation, Callback::bind_openai().await).await?
        }
    };
    let PreparedLogin { start, task } = prepared;

    let Some(task) = task else {
        // Claude's manual-only path has no background work. Do not leave the
        // single-flight flag claiming otherwise.
        drop(guard);
        return Ok(start);
    };

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let _guard = guard;
        let state = handle.state::<AppState>();
        match run_login_task(&state, task).await {
            Ok(provider) => {
                let _ = handle.emit("accounts://changed", ());
                let _ = handle.emit("auth://completed", provider);
            }
            Err(LoginTaskFailure::ClaudeFallback(fallback)) => {
                let _ = handle.emit("auth://manual-fallback", fallback);
            }
            Err(LoginTaskFailure::Terminal(error)) => {
                let _ = handle.emit("auth://failed", error);
            }
            Err(LoginTaskFailure::Cancelled) => {}
        }
    });

    Ok(start)
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
    let events = app.clone();
    finish_manual_login_with(&app.state::<AppState>(), &pasted, move || {
        let _ = events.emit("accounts://changed", ());
        let _ = events.emit("auth://completed", Provider::Anthropic);
    })
    .await
}

/// The whole of `submit_manual_code` except the event, so that it can be
/// tested: `src-tauri` has no dev-dependency on tauri's `test` feature, and a
/// function holding an `AppHandle` cannot be called without one. Same split as
/// `complete_login`, for the same reason.
async fn finish_manual_login_with<F>(
    state: &AppState,
    pasted: &str,
    on_success: F,
) -> Result<(), String>
where
    F: FnOnce() + Send,
{
    let (code, returned_state) = parse_manual_code(pasted).ok_or(
        "that is not a code#state line. Copy the whole line from the page, \
         including the # and everything after it",
    )?;

    // Serialize the generation check with the exchange and persistence. A new
    // begin_login can replace an abandoned manual-only attempt, but it cannot
    // replace one after its code has begun committing.
    let _commit = state.login_commit.lock().await;
    let (generation, pending) = {
        let waiting = state.pending_manual.lock().unwrap();
        let waiting = waiting
            .as_ref()
            .ok_or("no login is waiting for a code. Press Add account to start one")?;
        (waiting.generation, waiting.pending.clone())
    };
    if !login_generation_is_active(state, generation) {
        return Err("that login attempt is no longer active. Press Add account to start one".into());
    }

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

    complete_anthropic_login(state, &pending, code, returned_state).await?;
    // Emit completion while the generation is still current and the commit
    // mutex is held. Otherwise a new login can start between persistence and
    // this event and receive the previous attempt's completion signal.
    on_success();
    finish_login_generation(state, generation);
    // The loopback task may still be unwinding from its cancellation. Release
    // immediately for the manual path; its generation-aware guard cannot clear
    // a newer attempt when it eventually drops.
    release_login_single_flight(generation);
    Ok(())
}

#[cfg(test)]
pub(crate) async fn finish_manual_login(state: &AppState, pasted: &str) -> Result<(), String> {
    finish_manual_login_with(state, pasted, || {}).await
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
/// an `AppHandle` — the same split the login completion helpers use.
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
    let _account_lock = state.refresh_locks.lock_account(provider, uuid).await;

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
            .map_err(|e| format!("the token load task failed: {e}"))?
    };
    if let Ok(tokens) = loaded {
        revoke_tokens(&state.http, &state.auth_configs, &tokens).await;
    }
    // Local deletion is not best-effort. If it fails, retain the row and
    // scheduler entry so the user has a visible retry path to remove the still
    // stored credential.
    let _deleted = {
        let store = Arc::clone(&store);
        let id = uuid.to_string();
        tauri::async_runtime::spawn_blocking(move || {
            delete_tokens(store.as_ref(), provider, &id)
        })
        .await
        .map_err(|e| format!("the token deletion task failed: {e}"))?
        .map_err(|e| {
            format!(
                "the stored token could not be deleted ({e}); the account was kept so removal can be retried"
            )
        })?
    };

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
    if let Ok(Err(e)) =
        tauri::async_runtime::spawn_blocking(move || quota_core::snapshots::remove(&path, provider, &id))
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
/// same shape as `TokenSet` (crates/core/src/auth/token.rs:76-87), which AGENTS.md
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

fn ensure_unlock_allowed(state: &AppState) -> Result<(), String> {
    match state.store_kind() {
        StoreKind::Keychain => {
            Err("the OS keychain is open — there is nothing to unlock".into())
        }
        StoreKind::EncryptedFile => Err(
            "the encrypted token store is already open — close and restart Quota Board to change it"
                .into(),
        ),
        StoreKind::KeychainLocked => Err(
            "a keychain exists on this machine but did not answer; unlock it in the OS and restart Quota Board. A passphrase here would open a different, empty store"
                .into(),
        ),
        StoreKind::NoBackend => Ok(()),
    }
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
    ensure_unlock_allowed(&state)?;
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

    // A second command may have passed the first check while this one was
    // deriving its key. The conditional install performs the re-check and swap
    // under one write guard, so concurrent unlocks cannot install two
    // independently cached views of the same encrypted file.
    let replaced = match state.install_fallback_store(store) {
        Ok(replaced) => replaced,
        Err(unused) => {
            drop(unused);
            ensure_unlock_allowed(&state)?;
            return Err("another token store was opened while this one was unlocking".into());
        }
    };
    // Dropped after the write guard is released.
    drop(replaced);
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
/// which is the settings-window form of the confidently-wrong display AGENTS.md
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
/// confidently-wrong display AGENTS.md forbids.
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
    use crate::state::tests::{app_state, app_state_with};
    use quota_core::auth::pkce::PendingAuth;
    use quota_core::auth::stored::{load_tokens, save_tokens};
    use quota_core::auth::token::TokenSet;
    use quota_core::provider::token_key;
    use quota_core::secrets::{MemoryStore, SecretError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Default)]
    struct DeleteFailsOnceStore {
        inner: MemoryStore,
        fail: std::sync::atomic::AtomicBool,
    }

    impl DeleteFailsOnceStore {
        fn arm(&self) {
            self.fail.store(true, Ordering::SeqCst);
        }
    }

    impl SecretStore for DeleteFailsOnceStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<bool, SecretError> {
            if key.ends_with(":refresh") && self.fail.swap(false, Ordering::SeqCst) {
                return Err(SecretError::Backend("injected delete failure".into()));
            }
            self.inner.delete(key)
        }

        fn describe(&self) -> String {
            "delete-fails-once (test only)".into()
        }
    }

    async fn send_callback(port: u16, path: &str, state: &str) {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        socket
            .write_all(
                format!(
                    "GET {path}?code=loopback-code&state={state} HTTP/1.1\r\nHost: localhost\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
    }

    /// The Claude manual pending a `begin_login` would have left behind.
    fn armed(state: &AppState) -> PendingAuth {
        let pending = PendingAuth {
            verifier: "v-verifier".into(),
            state: "s-state".into(),
            redirect_uri: manual_redirect_uri().to_string(),
        };
        let generation = NEXT_LOGIN_GENERATION.fetch_add(1, Ordering::SeqCst);
        *state.active_login.lock().unwrap() = Some(generation);
        *state.pending_manual.lock().unwrap() = Some(PendingManual {
            generation,
            pending: pending.clone(),
            cancel: None,
        });
        pending
    }

    /// The two protocol configs stay distinct rather than guessing OpenAI's
    /// endpoints through Anthropic's `ProviderSpec` shape.
    #[test]
    fn auth_configs_keep_provider_overrides_separate() {
        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.auth_configs.anthropic.token_url =
            "http://127.0.0.1:1/overridden-anthropic".into();
        state.auth_configs.openai.issuer = "http://127.0.0.1:2/overridden-openai".into();

        assert_ne!(
            state.auth_configs.anthropic.token_url,
            state.auth_configs.openai.issuer,
            "the two providers' overrides must not collide"
        );
    }

    #[test]
    fn login_start_serializes_as_three_disjoint_provider_flows() {
        let claude = serde_json::to_value(LoginStart::ClaudeBrowser {
            loopback: Some("https://claude.example/loopback".into()),
            manual: "https://claude.example/manual".into(),
        })
        .unwrap();
        assert_eq!(claude["kind"], "claude_browser");
        assert!(claude.get("authorize_url").is_none());
        assert!(claude.get("user_code").is_none());

        let browser = serde_json::to_value(LoginStart::CodexBrowser {
            authorize_url: "https://openai.example/authorize".into(),
        })
        .unwrap();
        assert_eq!(browser["kind"], "codex_browser");
        assert!(browser.get("manual").is_none());

        let device = serde_json::to_value(LoginStart::CodexDevice {
            verification_url: "https://openai.example/device".into(),
            user_code: "ABCD-EFGH".into(),
            expires_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        })
        .unwrap();
        assert_eq!(device["kind"], "codex_device");
        assert_eq!(device["user_code"], "ABCD-EFGH");
        assert!(device.get("manual").is_none());
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
        state.auth_configs.anthropic.token_url = format!("{}/v1/oauth/token", server.uri());
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

    #[tokio::test]
    async fn manual_success_cancels_a_late_callback_before_a_second_exchange() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(150))
                    .set_body_json(token_body(Some(serde_json::json!({
                        "uuid": "u-race", "email_address": "race@example.invalid"
                    })))),
            )
            .expect(1)
            .mount(&server)
            .await;

        let state = state_against(&server).await;
        let callback = Callback::bind().await.unwrap();
        let port = callback.port();
        let generation = NEXT_LOGIN_GENERATION.fetch_add(1, Ordering::SeqCst);
        let prepared = prepare_claude_login(&state, generation, Ok(callback))
            .await
            .unwrap();
        let returned_state = state
            .pending_manual
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending
            .state
            .clone();
        let state = Arc::new(state);
        let background = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { run_login_task(&state, prepared.task.unwrap()).await })
        };
        let manual = {
            let state = Arc::clone(&state);
            let pasted = format!("manual-code#{returned_state}");
            tokio::spawn(async move {
                finish_manual_login(&state, &pasted).await
            })
        };

        for _ in 0..100 {
            if server.received_requests().await.unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        send_callback(port, "/callback", &returned_state).await;

        manual.await.unwrap().unwrap();
        assert!(matches!(
            background.await.unwrap(),
            Err(LoginTaskFailure::Cancelled)
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert!(state.pending_manual.lock().unwrap().is_none());
        assert!(state.active_login.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn terminal_claude_callback_failure_clears_the_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/oauth/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let state = Arc::new(state_against(&server).await);
        let callback = Callback::bind().await.unwrap();
        let port = callback.port();
        let generation = NEXT_LOGIN_GENERATION.fetch_add(1, Ordering::SeqCst);
        let prepared = prepare_claude_login(&state, generation, Ok(callback))
            .await
            .unwrap();
        let returned_state = state
            .pending_manual
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .pending
            .state
            .clone();
        LOGIN_IN_FLIGHT.store(generation, Ordering::SeqCst);
        let guard = LoginGuard { generation };
        let background = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { run_login_task(&state, prepared.task.unwrap()).await })
        };
        send_callback(port, "/callback", &returned_state).await;

        assert!(matches!(
            background.await.unwrap(),
            Err(LoginTaskFailure::Terminal(_))
        ));
        assert!(state.pending_manual.lock().unwrap().is_none());
        assert!(state.active_login.lock().unwrap().is_none());
        drop(guard);
        assert_eq!(LOGIN_IN_FLIGHT.load(Ordering::SeqCst), NO_LOGIN);
    }

    /// With both registered callback ports unavailable, the desktop requests a
    /// device code and completes the whole flow in Rust. Every endpoint here is
    /// loopback; no test consumes a real account's authorization or quota.
    #[tokio::test]
    async fn codex_device_fallback_stores_split_tokens_and_registers_context() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/usercode"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_auth_id": "device-secret",
                "user_code": "ABCD-EFGH",
                "interval": 1
            })))
            .mount(&server)
            .await;
        let verifier = "device-verifier";
        Mock::given(method("POST"))
            .and(path("/api/accounts/deviceauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_code": "device-code",
                "code_challenge": quota_core::auth::pkce::code_challenge_s256(verifier),
                "code_verifier": verifier
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": concat!(
                    "e30.",
                    "eyJlbWFpbCI6Indob0BleGFtcGxlLmludmFsaWQiLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF91c2VyX2lkIjoiY29kZXgtdXNlci0xIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoid29ya3NwYWNlLW9uZSIsImNoYXRncHRfcGxhbl90eXBlIjoicGx1cyIsImNoYXRncHRfYWNjb3VudF9pc19mZWRyYW1wIjp0cnVlfX0",
                    ".signature"
                ),
                "access_token": "e30.eyJleHAiOjk5OTk5OTk5OTl9.signature",
                "refresh_token": "codex-rt-1",
            })))
            .mount(&server)
            .await;

        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.auth_configs.openai.issuer = server.uri();
        // Proves a Codex start cannot leave Claude's code#state route armed.
        armed(&state);
        let prepared = prepare_codex_login(
            &state,
            7001,
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "both registered ports are occupied",
            )),
        )
        .await
        .unwrap();
        let start = serde_json::to_value(&prepared.start).unwrap();
        assert_eq!(start["kind"], "codex_device");
        assert_eq!(start["user_code"], "ABCD-EFGH");
        assert!(state.pending_manual.lock().unwrap().is_none());

        let provider = match run_login_task(&state, prepared.task.unwrap()).await {
            Ok(provider) => provider,
            Err(_) => panic!("the local device flow did not complete"),
        };
        assert_eq!(provider, Provider::Openai);

        let stored = load_tokens(state.secrets().as_ref(), Provider::Openai, "codex-user-1")
            .expect("the split Codex credential was not loadable");
        assert_eq!(stored.access_token(), "e30.eyJleHAiOjk5OTk5OTk5OTl9.signature");
        assert_eq!(stored.workspace_id(), Some("workspace-one"));
        assert!(stored.is_fedramp());

        let accounts = state.accounts.lock().await;
        let a = accounts
            .list()
            .iter()
            .find(|a| a.account_id == "codex-user-1")
            .expect("the Codex account was not registered");
        assert_eq!(a.workspace_id.as_deref(), Some("workspace-one"));
        assert!(a.is_fedramp);
    }

    #[tokio::test]
    async fn codex_browser_callback_exchanges_and_registers_without_a_manual_route() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": concat!(
                    "e30.",
                    "eyJlbWFpbCI6Indob0BleGFtcGxlLmludmFsaWQiLCJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF91c2VyX2lkIjoiY29kZXgtdXNlci0xIiwiY2hhdGdwdF9hY2NvdW50X2lkIjoid29ya3NwYWNlLW9uZSIsImNoYXRncHRfcGxhbl90eXBlIjoicGx1cyIsImNoYXRncHRfYWNjb3VudF9pc19mZWRyYW1wIjp0cnVlfX0",
                    ".signature"
                ),
                "access_token": "e30.eyJleHAiOjk5OTk5OTk5OTl9.signature",
                "refresh_token": "browser-refresh"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut state = app_state(Arc::new(MemoryStore::default()));
        state.auth_configs.openai.issuer = server.uri();
        let callback = Callback::bind_openai().await.unwrap();
        let port = callback.port();
        let prepared = prepare_codex_login(&state, 7002, Ok(callback))
            .await
            .unwrap();
        assert!(matches!(prepared.start, LoginStart::CodexBrowser { .. }));
        assert!(state.pending_manual.lock().unwrap().is_none());
        let returned_state = match prepared.task.as_ref().unwrap() {
            LoginTask::CodexBrowser { pending, .. } => pending.state().to_string(),
            _ => panic!("a browser callback prepared the wrong task"),
        };
        let state = Arc::new(state);
        let background = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { run_login_task(&state, prepared.task.unwrap()).await })
        };
        send_callback(port, "/auth/callback", &returned_state).await;
        assert!(matches!(background.await.unwrap(), Ok(Provider::Openai)));
        assert!(load_tokens(
            state.secrets().as_ref(),
            Provider::Openai,
            "codex-user-1"
        )
        .is_ok());
    }

    #[test]
    fn device_404_explains_both_available_remedies() {
        let message = codex_device_start_error(AuthError::OAuth {
            status: 404,
            code: None,
            description: None,
        });
        assert!(message.contains("enable it in ChatGPT"), "{message}");
        assert!(message.contains("1455/1457"), "{message}");
        assert!(!message.contains("OAuth error"), "{message}");
    }

    #[tokio::test]
    async fn an_open_encrypted_store_cannot_be_swapped_during_refresh() {
        let installed: Arc<dyn SecretStore> = Arc::new(MemoryStore::default());
        let state = app_state_with(
            Arc::clone(&installed),
            StoreKind::EncryptedFile,
            std::env::temp_dir().join("quota-repeat-unlock-settings.json"),
        );
        let _refresh = state
            .refresh_locks
            .lock_account(Provider::Anthropic, "a")
            .await;
        let before = state.secrets();

        let error = ensure_unlock_allowed(&state).unwrap_err();
        assert!(error.contains("already open"), "{error}");
        let candidate: Arc<dyn SecretStore> = Arc::new(MemoryStore::default());
        assert!(
            state.install_fallback_store(candidate).is_err(),
            "the atomic install bypassed the command's repeated-unlock check"
        );
        let after = state.secrets();
        assert!(
            Arc::ptr_eq(&before, &after) && Arc::ptr_eq(&installed, &after),
            "a repeated unlock swapped the live store"
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
    /// AGENTS.md's token rules exist to prevent.
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
        state.auth_configs.anthropic.revoke_url =
            format!("{}/v1/oauth/token/revoke", anthropic_server.uri());
        state.auth_configs.openai.issuer = openai_server.uri();
        add_openai_twin_of_a(&state).await;

        let tokens = StoredTokens::Openai(OpenAiTokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            expires_at: chrono::Utc::now() + chrono::TimeDelta::hours(1),
            client_id: "test".into(),
            account_id: "a".into(),
            workspace_id: "workspace-a".into(),
            is_fedramp: false,
        });
        save_tokens(state.secrets().as_ref(), Provider::Openai, "a", &tokens).unwrap();

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

    #[tokio::test]
    async fn a_failed_local_delete_keeps_the_row_until_removal_can_be_retried() {
        use quota_core::provider::{
            openai_access_token_key, openai_refresh_token_key, openai_token_meta_key,
        };

        let store = Arc::new(DeleteFailsOnceStore::default());
        let state = app_state(store.clone());
        add_openai_twin_of_a(&state).await;
        state.scheduler.lock().await.add(Provider::Openai, "a");
        let tokens = StoredTokens::Openai(OpenAiTokenSet {
            access_token: "codex-access".into(),
            refresh_token: "codex-refresh".into(),
            expires_at: chrono::Utc::now() + chrono::TimeDelta::hours(1),
            client_id: "test".into(),
            account_id: "a".into(),
            workspace_id: "workspace-a".into(),
            is_fedramp: false,
        });
        save_tokens(store.as_ref(), Provider::Openai, "a", &tokens).unwrap();
        store.arm();

        let first = remove_account_for(&state, Provider::Openai, "a").await;
        assert!(first.is_err(), "a partial local delete was reported as success");
        assert!(
            state
                .accounts
                .lock()
                .await
                .list()
                .iter()
                .any(|account| account.provider == Provider::Openai && account.account_id == "a"),
            "the only retry path disappeared with the row"
        );
        assert!(
            state.scheduler.lock().await.state(Provider::Openai, "a").is_some(),
            "the scheduler entry disappeared before local deletion completed"
        );

        remove_account_for(&state, Provider::Openai, "a")
            .await
            .expect("the second removal should repair the partial delete");
        for key in [
            openai_refresh_token_key("a"),
            openai_access_token_key("a"),
            openai_token_meta_key("a"),
        ] {
            assert!(store.get(&key).unwrap().is_none(), "split key survived: {key}");
        }
        assert!(
            state
                .accounts
                .lock()
                .await
                .list()
                .iter()
                .all(|account| account.provider != Provider::Openai || account.account_id != "a")
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
