#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_window_state::StateFlags;

mod commands;
mod state;
mod tray;

use quota_core::accounts::AccountStore;
use quota_core::auth::pkce::AuthConfig;
use quota_core::auth::stored::{token_key, RefreshLocks};
use quota_core::auth::token::{ReqwestHttp, TokenSet};
use quota_core::scheduler::{register_accounts, Scheduler, SystemClock};
use quota_core::secrets::{keychain::KeychainStore, timeout::TimeoutStore, SecretStore, SERVICE};
/// Named only inside the `QUOTA_FORCE_FALLBACK` block below, which is itself
/// `debug_assertions`-only. Imported unconditionally it is an `unused_imports`
/// warning in every release build — invisible to `cargo clippy --all-targets`,
/// which builds the debug profile, and therefore only surfacing at the release
/// build the installer step runs.
#[cfg(debug_assertions)]
use quota_core::secrets::SecretError;
use quota_core::settings::SettingsStore;
use quota_core::snapshots::fingerprint;
use state::{poll_loop, AppState, LockedStore, SecretsHandle, StoreKind};
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// §3.3's global toggle. Built on demand rather than stored in a `static`:
/// `Shortcut::new` is cheap, and the handler and the registration have to agree
/// on one value — a second literal is how they would stop agreeing.
fn toggle_shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyQ)
}

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
        // Opening the authorize URL in the user's real browser is the whole
        // point of §10.3's flow — the consent screen must not run inside this
        // app's webview. **Without this line the permission in
        // capabilities/settings.json still resolves at build time and the
        // button silently does nothing at runtime**, which is exactly the
        // state `tauri-plugin-autostart` is in today (Task 20 owns that).
        .plugin(tauri_plugin_opener::init())
        // §11.3. **LaunchAgent, never AppleScript mode** — that one drives
        // System Events through osascript, which trips a TCC automation
        // consent prompt, needs `NSAppleEventsUsageDescription`, and registers
        // the raw Unix executable whenever `.app/` does not appear exactly once
        // in the canonical path. design.md calls it an explicit non-goal.
        //
        // **No launch arguments.** The plan called for `--minimized`, but
        // nothing in this binary reads an argument, so a `--minimized` sitting
        // in the user's LaunchAgent plist would promise a hidden start that
        // does not happen. §11.3 does not ask for one either — it mentions
        // those flags only when explaining what AppleScript mode is limited to.
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
        // §3.3's second recovery route. **`Builder`, not `init()`** — this
        // plugin has no `init`. The handler fires on both press and release, so
        // without the `Pressed` filter every hotkey toggles twice and looks
        // like it did nothing.
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(move |app, shortcut, event| {
                    if event.state == ShortcutState::Pressed && shortcut == &toggle_shortcut() {
                        tray::toggle_widget(app);
                    }
                })
                .build(),
        )
        .setup(|app| {
            // §9.1 + user decision 1: the same file `quota-cli login` writes.
            // There is one derivation of this path and both binaries call it.
            let accounts = AccountStore::load(&quota_core::paths::accounts_file())?;

            // §9.2's canary self-check. **Must run exactly once per process**:
            // keyring 4.1.5 flips an internal flag before registering the
            // store, so the error carrying the real cause is produced only on
            // the first call and every later one yields a context-free
            // `NoDefaultStore` (secrets/keychain.rs:13-21).
            //
            // **Wrapped in `TimeoutStore`, and the wrapper is what makes both
            // this line and the polling loop safe.** Every `SecretStore` method
            // is synchronous, and the keychain backend can block without bound
            // waiting on a SecurityAgent prompt that may never be answerable
            // (measured on macOS 15.6 — see `secrets/timeout.rs`). Unwrapped,
            // this call hangs `setup()` before `widget.show()` and the window
            // never appears; the same call inside `ensure_fresh` hangs the task
            // that drives the polling loop, and nothing is left running to
            // reclaim it.
            let opened = TimeoutStore::spawn(
                std::time::Duration::from_secs(quota_core::secrets::timeout::DEFAULT_TIMEOUT_SECS),
                || KeychainStore::probe(SERVICE).map(|s| Box::new(s) as Box<dyn SecretStore>),
            );
            // docs/design.md §9.2's real trigger — a Linux box with no Secret
            // Service (design.md:580-586) — cannot be reproduced on a macOS
            // development machine, and "the fallback has never been exercised
            // by the application" is a pre-release blocker. Debug builds only,
            // for the reason `usage_url()`'s doc comment below already gives
            // for the URL overrides. It cannot redirect writes: the path comes
            // from `paths::secrets_file()`, never from the environment.
            #[cfg(debug_assertions)]
            let opened = if std::env::var_os("QUOTA_FORCE_FALLBACK").is_some() {
                Err(SecretError::NoBackend(
                    "QUOTA_FORCE_FALLBACK is set: pretending this machine has no keychain".into(),
                ))
            } else {
                opened
            };

            let (secrets, store_kind): (Arc<dyn SecretStore>, StoreKind) = match opened {
                Ok(s) => {
                    eprintln!("token store: {}", s.describe());
                    (Arc::new(s), StoreKind::Keychain)
                }
                Err(e) => {
                    // §9.2's encrypted-file fallback needs a passphrase, and a
                    // passphrase cannot be asked for from `setup()` — there is
                    // no window yet. Start locked, render every account
                    // SECRETS_LOCKED (§7.1), and let the settings window's
                    // `unlock_secrets` swap a real store in. `store_kind` is
                    // what tells that window which of §9.2's two remedies to
                    // offer.
                    eprintln!("{e} — every account will read as locked until it is unlocked in Settings");
                    let kind = StoreKind::from_open_error(&e);
                    (Arc::new(LockedStore) as Arc<dyn SecretStore>, kind)
                }
            };

            // §9.1: the snapshot cache goes in the OS cache directory.
            let snapshots_path = app
                .path()
                .app_cache_dir()
                .map(|d| d.join("snapshots.json"))
                .map_err(|e| format!("no cache directory: {e}"))?;
            let mut cache = quota_core::snapshots::load(&snapshots_path);

            // §9.1: settings live beside accounts.json, through the one shared
            // `paths` derivation. Deleting the literal 300 is the guard that
            // keeps the file the only source of the running interval.
            let settings = SettingsStore::load(&quota_core::paths::settings_file());
            if let Some(w) = settings.warning() {
                eprintln!("settings: {w}");
            }
            let mut scheduler = Scheduler::new(settings.poll_policy(), SystemClock);
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
                settings: tokio::sync::Mutex::new(settings),
                secrets: std::sync::RwLock::new(SecretsHandle {
                    store: secrets,
                    kind: store_kind,
                }),
                last_raw: std::sync::Mutex::new(quota_core::usage::raw::RawLog::default()),
                pending_manual: std::sync::Mutex::new(None),
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

            tray::build_tray(app)?;

            // **Not fatal.** On Linux this needs X11 regardless of
            // `GDK_BACKEND`, because `global-hotkey` opens its own `$DISPLAY`
            // connection, so a pure Wayland session cannot register it at all —
            // and there the tray menu is the only way back to a hidden widget.
            // A failure here must therefore lose the shortcut, not the app.
            if let Err(e) = app.global_shortcut().register(toggle_shortcut()) {
                eprintln!("the global shortcut could not be registered ({e}) — use the tray menu");
            }

            // §3.3: this is a widget, not an application. Done **after** the
            // tray exists, and in the same commit as it, because it is the tray
            // menu that replaces everything this takes away: with no Dock icon
            // there is no Cmd+Q and no Cmd+Tab entry, so an app that hid its
            // icon before it had a tray would have no quit at all.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

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
            commands::set_widget_visible,
            commands::begin_login,
            commands::submit_manual_code,
            commands::get_autostart,
            commands::set_autostart,
            commands::remove_account,
            commands::rename_account,
            commands::reorder_accounts,
            commands::store_status,
            commands::unlock_secrets,
            commands::get_settings,
            commands::set_settings,
            commands::last_response
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application")
        // No manual save on exit either: plugin 2.4.1 already persists from
        // RunEvent::Exit. Measured — quitting wrote the moved position to
        // ~/Library/Application Support/com.quota.board/.window-state.json.
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
    std::env::var("QUOTA_USAGE_URL")
        .unwrap_or_else(|_| quota_core::usage::http::USAGE_URL.to_string())
}
#[cfg(not(debug_assertions))]
fn usage_url() -> String {
    quota_core::usage::http::USAGE_URL.to_string()
}

#[cfg(debug_assertions)]
fn token_url() -> String {
    std::env::var("QUOTA_TOKEN_URL").unwrap_or_else(|_| AuthConfig::default().token_url)
}
#[cfg(not(debug_assertions))]
fn token_url() -> String {
    AuthConfig::default().token_url
}
