#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_window_state::StateFlags;

mod commands;
mod state;

use quoata_core::accounts::AccountStore;
use quoata_core::auth::pkce::AuthConfig;
use quoata_core::auth::stored::{token_key, RefreshLocks};
use quoata_core::auth::token::{ReqwestHttp, TokenSet};
use quoata_core::scheduler::{register_accounts, PollPolicy, Scheduler, SystemClock};
use quoata_core::secrets::{keychain::KeychainStore, SecretStore, SERVICE};
use quoata_core::snapshots::fingerprint;
use state::{poll_loop, AppState, LockedStore};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

fn main() {
    // Must be set before gtk::init(). .setup() is already too late — the
    // runtime, and therefore GTK, is created inside .build().
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("GDK_BACKEND", "x11");
    }

    tauri::Builder::default()
        .plugin(
            tauri_plugin_window_state::Builder::default()
                // The default is all(), which is harmful for the widget:
                // DECORATIONS would override decorations:false, and VISIBLE
                // would resurrect a window we deliberately start hidden.
                //
                // SIZE is off as well. docs/design.md §8.1 makes the height a
                // derived value — the view measures its content and calls
                // setSize (src/main.ts) — so a persisted size is not the
                // user's choice to restore. Left on, the plugin restores the
                // previous height on launch and the view immediately corrects
                // it, and the same restore would override any height set in
                // tauri.conf.json.
                .with_state_flags(StateFlags::POSITION)
                .skip_initial_state("settings")
                .build(),
        )
        .setup(|app| {
            // §9.1 + user decision 1: the same file `quoata-cli login` writes.
            // There is one derivation of this path and both binaries call it.
            let accounts = AccountStore::load(&quoata_core::paths::accounts_file())?;

            // §9.2's canary self-check. **Must run exactly once per process**:
            // keyring 4.1.5 flips an internal flag before registering the
            // store, so the error carrying the real cause is produced only on
            // the first call and every later one yields a context-free
            // `NoDefaultStore` (secrets/keychain.rs:13-21).
            let secrets: Arc<dyn SecretStore> = match KeychainStore::probe(SERVICE) {
                Ok(s) => {
                    eprintln!("token store: {}", s.describe());
                    Arc::new(s)
                }
                Err(e) => {
                    // §9.2 wants the encrypted-file fallback here. It needs a
                    // passphrase prompt, which **no task in this plan builds**
                    // (see Step 9). Until one does, keep running and render
                    // every account SECRETS_LOCKED rather than crashing.
                    eprintln!("no usable credential store ({e}) — every account will read as locked");
                    Arc::new(LockedStore)
                }
            };

            // §9.1: the snapshot cache goes in the OS cache directory.
            let snapshots_path = app
                .path()
                .app_cache_dir()
                .map(|d| d.join("snapshots.json"))
                .map_err(|e| format!("no cache directory: {e}"))?;
            let mut cache = quoata_core::snapshots::load(&snapshots_path);

            let mut scheduler = Scheduler::new(PollPolicy::with_interval_secs(300), SystemClock);
            let store = Arc::clone(&secrets);
            let current_fp = move |uuid: &str| -> Option<String> {
                let raw = store.get(&token_key(uuid)).ok().flatten()?;
                let tokens: TokenSet = serde_json::from_slice(&raw).ok()?;
                Some(fingerprint(&tokens.access_token))
            };
            register_accounts(&mut scheduler, accounts.list(), &mut cache, &current_fp);

            // Managed **before** the loop is spawned: `tokio::time::interval`
            // completes its first tick immediately, so `handle.state::<AppState>()`
            // would panic on that tick if the order were reversed.
            app.manage(AppState {
                scheduler: tokio::sync::Mutex::new(scheduler),
                accounts: tokio::sync::Mutex::new(accounts),
                secrets,
                http: ReqwestHttp::new()?,
                cfg: AuthConfig { token_url: token_url(), ..AuthConfig::default() },
                refresh_locks: RefreshLocks::default(),
                poll_permit: tokio::sync::Mutex::new(()),
                snapshots_path,
                usage_url: usage_url(),
                webview_visible: AtomicBool::new(true),
            });

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move { poll_loop(handle).await });

            // No restore_state() call here on purpose. "settings" is the only
            // label passed to skip_initial_state, so the plugin restores the
            // widget itself before setup() runs. Measured on macOS 15.6 with
            // plugin 2.4.1: widget moved to (300,700), quit, relaunched, and it
            // came back at (300,700) with no explicit restore in this closure.
            if let Some(widget) = app.get_webview_window("widget") {
                widget.show()?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the settings window hides it rather than quitting.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "settings" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_accounts,
            commands::refresh_account,
            commands::set_widget_visible
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application")
        // No manual save on exit either: plugin 2.4.1 already persists from
        // RunEvent::Exit. Measured — quitting wrote the moved position to
        // ~/Library/Application Support/com.quoata.board/.window-state.json.
        .run(|_app, _event| {
            // The two-argument run() form is kept because later tasks need the
            // run-loop closure (Task 19's tray, macOS Reopen).
        });
}

/// Endpoint overrides for the local-mock run (Step 11). **`debug_assertions`
/// only.** In a release build the environment cannot point this binary at
/// another host: the token endpoint receives a refresh token, so an
/// env-settable URL in a shipped binary would be a credential exfiltration
/// switch. Production values are §5.1's URL and `AuthConfig::default()`.
#[cfg(debug_assertions)]
fn usage_url() -> String {
    std::env::var("QUOATA_USAGE_URL")
        .unwrap_or_else(|_| quoata_core::usage::http::USAGE_URL.to_string())
}
#[cfg(not(debug_assertions))]
fn usage_url() -> String {
    quoata_core::usage::http::USAGE_URL.to_string()
}

#[cfg(debug_assertions)]
fn token_url() -> String {
    std::env::var("QUOATA_TOKEN_URL").unwrap_or_else(|_| AuthConfig::default().token_url)
}
#[cfg(not(debug_assertions))]
fn token_url() -> String {
    AuthConfig::default().token_url
}
