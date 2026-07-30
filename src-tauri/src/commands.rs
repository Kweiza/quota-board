use crate::state::AppState;
use quoata_core::model::AccountState;
use std::sync::atomic::Ordering;
use tauri::{Emitter, State};

/// Mirrors `AccountView` in `src/lib/types.ts`. The two must be changed
/// together — `crates/core/src/model.rs:19-23` carries the reciprocal note for
/// `AccountState`.
///
/// `email` is display-only and is **never** used as a key (§9.3). It is here
/// because `display_label` is user-editable, so after a rename Task 18's
/// settings list has nothing else to tell two accounts apart by. Adding it now
/// shakes the two-sided contract once instead of twice.
///
/// There is deliberately **no `quarantined` field**: `Scheduler::state` already
/// returns `AuthDead` for a quarantined account (scheduler.rs:468), so a second
/// copy of that fact on the wire is exactly the two-sources-disagree hazard
/// §7.1 exists to prevent. Sort order needs no field either — `AccountStore`
/// sorts by `sort_order` on load (accounts.rs:62) and `list()` returns that
/// order, so the array order *is* the order.
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
        // available. `AccountRow.svelte:58-59` already renders this state as
        // "throttled, after HH:MM", which is exactly what §6.4 asks for.
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
