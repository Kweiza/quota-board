#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_window_state::StateFlags;

mod commands;
mod state;
mod tray;
mod window_recovery;

use quota_core::accounts::AccountStore;
use quota_core::auth::openai::{OpenAiAuthConfig, OPENAI_ISSUER};
use quota_core::auth::stored::{load_tokens, AuthConfigs, RefreshLocks};
use quota_core::auth::token::{AnthropicAuthConfig, ReqwestHttp};
use quota_core::provider::Provider;
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

/// The locked state startup must install when an encrypted-file backend was
/// selected on an earlier run.
///
/// Kept as a named seam so both the choice and the skipped probe can be
/// regression-tested without opening either real backend.
fn select_startup_store<T, E>(
    path: &std::path::Path,
    probe_keychain: impl FnOnce() -> Result<T, E>,
) -> (Option<StoreKind>, Option<Result<T, E>>) {
    let fallback = match std::fs::metadata(path) {
        Ok(_) => Some(StoreKind::EncryptedFileLocked),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        // Fail closed. An unreadable path may still contain every account's
        // credential; probing and selecting an empty keychain would then turn a
        // transient filesystem error into a persisted AUTH_DEAD quarantine.
        Err(_) => Some(StoreKind::EncryptedFileLocked),
    };
    match fallback {
        Some(kind) => (Some(kind), None),
        None => (None, Some(probe_keychain())),
    }
}

/// §3.3's global toggle. Built on demand rather than stored in a `static`:
/// `Shortcut::new` is cheap, and the handler and the registration have to agree
/// on one value — a second literal is how they would stop agreeing.
fn toggle_shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyQ)
}

fn current_token_fingerprint(
    store: &dyn SecretStore,
    provider: Provider,
    account_id: &str,
) -> Option<String> {
    let tokens = load_tokens(store, provider, account_id).ok()?;
    Some(fingerprint(tokens.access_token()))
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
            // Infallible: a file that cannot be read yields an empty list and a
            // warning rather than ending the process. This used to be `?`, and a
            // truncated `accounts.json` aborted before any window existed —
            // measured, exit 134 — which on a transparent widget with no Dock
            // icon is indistinguishable from the app simply not launching.
            let accounts = AccountStore::load(&quota_core::paths::accounts_file());
            if let Some(w) = accounts.warning() {
                eprintln!("accounts: {w}");
            }

            // §9.2's keychain canary self-check. **When the keychain is the
            // selected backend, it must run exactly once per process**: keyring
            // 4.1.5 flips an internal flag before registering the store, so the
            // error carrying the real cause is produced only on the first call
            // and every later one yields a context-free `NoDefaultStore`
            // (secrets/keychain.rs:13-21). An existing encrypted backend skips
            // the keychain and therefore skips this probe entirely.
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
            // Once the encrypted fallback has been selected it remains the
            // credential source on later launches. A Secret Service daemon can
            // appear after those credentials were written; probing it first
            // would select an empty keychain, classify every fallback token as
            // missing and persist AUTH_DEAD for otherwise healthy accounts.
            let fallback_path = quota_core::paths::secrets_file();
            let (existing_fallback, opened) = select_startup_store(&fallback_path, || {
                TimeoutStore::spawn(
                    std::time::Duration::from_secs(
                        quota_core::secrets::timeout::DEFAULT_TIMEOUT_SECS,
                    ),
                    || KeychainStore::probe(SERVICE).map(|s| Box::new(s) as Box<dyn SecretStore>),
                )
            });
            // docs/design.md §9.2's real trigger — a Linux box with no Secret
            // Service (design.md:580-586) — cannot be reproduced on a macOS
            // development machine, and "the fallback has never been exercised
            // by the application" is a pre-release blocker. Debug builds only,
            // for the reason `usage_url()`'s doc comment below already gives
            // for the URL overrides. It cannot redirect writes: the path comes
            // from `paths::secrets_file()`, never from the environment.
            #[cfg(debug_assertions)]
            let opened = opened.map(|opened| {
                if std::env::var_os("QUOTA_FORCE_FALLBACK").is_some() {
                    Err(SecretError::NoBackend(
                        "QUOTA_FORCE_FALLBACK is set: pretending this machine has no keychain"
                            .into(),
                    ))
                } else {
                    opened
                }
            });

            let (secrets, store_kind): (Arc<dyn SecretStore>, StoreKind) = match opened {
                None => {
                    let kind = existing_fallback.unwrap_or(StoreKind::EncryptedFileLocked);
                    eprintln!(
                        "encrypted token store found — waiting for its passphrase before reading accounts"
                    );
                    (Arc::new(LockedStore) as Arc<dyn SecretStore>, kind)
                }
                Some(Ok(s)) => {
                    eprintln!("token store: {}", s.describe());
                    (Arc::new(s), StoreKind::Keychain)
                }
                Some(Err(e)) => {
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
            let current_fp = move |provider: Provider, uuid: &str| -> Option<String> {
                current_token_fingerprint(store.as_ref(), provider, uuid)
            };
            register_accounts(&mut scheduler, accounts.list(), &mut cache, &current_fp);

            let mut anthropic = AnthropicAuthConfig::production();
            anthropic.token_url = token_url();
            let auth_configs = AuthConfigs {
                anthropic,
                openai: OpenAiAuthConfig {
                    issuer: openai_issuer(),
                    ..OpenAiAuthConfig::default()
                },
            };

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
                active_login: std::sync::Mutex::new(None),
                login_commit: tokio::sync::Mutex::new(()),
                http: ReqwestHttp::new()?,
                auth_configs,
                refresh_locks: RefreshLocks::default(),
                poll_permit: tokio::sync::Mutex::new(()),
                snapshots_path,
                usage_url: usage_url(),
                openai_usage_url: openai_usage_url(),
                webview_visible: AtomicBool::new(true),
            });

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move { poll_loop(handle).await });

            // No restore_state() call here on purpose. "settings" is the only
            // label passed to skip_initial_state, so the plugin restores the
            // widget itself before setup() runs. `center: true` establishes a
            // primary-display fallback first; a valid saved position replaces
            // it, while an invalid one leaves the centered fallback intact.
            // Measured on macOS 15.6 with plugin 2.4.1: widget moved to
            // (300,700), quit, relaunched, and it came back at (300,700) with
            // no explicit restore in this closure.
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
            commands::accounts_warning,
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
            commands::set_auto_sort,
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
/// switch. Production values are §5.1's URL and
/// `AnthropicAuthConfig::production()`.
#[cfg(debug_assertions)]
fn usage_url() -> String {
    std::env::var("QUOTA_USAGE_URL")
        .unwrap_or_else(|_| quota_core::usage::http::USAGE_URL.to_string())
}
#[cfg(not(debug_assertions))]
fn usage_url() -> String {
    quota_core::usage::http::USAGE_URL.to_string()
}

/// Codex's half of the same override. Its own env var rather than reusing
/// `QUOTA_USAGE_URL` for both: the two providers are fetched from different
/// mock servers whenever a local run needs to exercise them side by side, the
/// same reason `AppState` carries two fields rather than one.
#[cfg(debug_assertions)]
fn openai_usage_url() -> String {
    std::env::var("QUOTA_OPENAI_USAGE_URL")
        .unwrap_or_else(|_| quota_core::usage::http::OPENAI_USAGE_URL.to_string())
}
#[cfg(not(debug_assertions))]
fn openai_usage_url() -> String {
    quota_core::usage::http::OPENAI_USAGE_URL.to_string()
}

#[cfg(debug_assertions)]
fn token_url() -> String {
    std::env::var("QUOTA_TOKEN_URL")
        .unwrap_or_else(|_| AnthropicAuthConfig::production().token_url)
}
#[cfg(not(debug_assertions))]
fn token_url() -> String {
    AnthropicAuthConfig::production().token_url
}

/// Debug-only issuer override for a local OpenAI mock. Every OpenAI endpoint is
/// derived from this root by `OpenAiAuthConfig`; individual endpoint overrides
/// would let tests exercise a topology production never uses.
#[cfg(debug_assertions)]
fn openai_issuer() -> String {
    std::env::var("QUOTA_OPENAI_ISSUER").unwrap_or_else(|_| OPENAI_ISSUER.to_string())
}
#[cfg(not(debug_assertions))]
fn openai_issuer() -> String {
    OPENAI_ISSUER.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use quota_core::accounts::Account;
    use quota_core::auth::openai::OpenAiTokenSet;
    use quota_core::auth::stored::{save_tokens, StoredTokens};
    use quota_core::model::{AccountState, UsageWindow};
    use quota_core::scheduler::PollPolicy;
    use quota_core::secrets::MemoryStore;
    use quota_core::snapshots::{self, CachedSnapshot};

    #[test]
    fn an_existing_encrypted_store_is_selected_before_an_empty_keychain_can_be_probed() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "quota-existing-fallback-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::write(&path, b"encrypted store marker").unwrap();

        let probed = std::sync::atomic::AtomicBool::new(false);
        let (kind, opened) = select_startup_store(&path, || -> Result<(), ()> {
            probed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(kind, Some(StoreKind::EncryptedFileLocked));
        assert!(opened.is_none());
        assert!(
            !probed.load(std::sync::atomic::Ordering::SeqCst),
            "startup would select a newly available but empty keychain and quarantine every fallback account"
        );

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_fresh_install_still_probes_the_os_keychain() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "quota-missing-fallback-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::remove_file(&path).ok();

        let probed = std::sync::atomic::AtomicBool::new(false);
        let (kind, opened) = select_startup_store(&path, || -> Result<(), ()> {
            probed.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(kind, None);
        assert!(matches!(opened, Some(Ok(()))));
        assert!(probed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn startup_restores_a_split_openai_credentials_snapshot() {
        let store = MemoryStore::default();
        let account_id = "startup-user";
        let access_token = "startup-access";
        let tokens = StoredTokens::Openai(OpenAiTokenSet {
            access_token: access_token.into(),
            refresh_token: "startup-refresh".into(),
            expires_at: chrono::Utc::now() + chrono::TimeDelta::hours(1),
            client_id: "test".into(),
            account_id: account_id.into(),
            workspace_id: Some("startup-workspace".into()),
            is_fedramp: Some(false),
        });
        save_tokens(&store, Provider::Openai, account_id, &tokens).unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!(
            "quota-startup-snapshot-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let snapshot = CachedSnapshot {
            windows: vec![UsageWindow {
                window_id: "primary".into(),
                label: "5h".into(),
                percent: 31.0,
                resets_at: chrono::Utc::now() + chrono::TimeDelta::hours(1),
                scope: None,
                weekly: false,
            }],
            fetched_at: chrono::Utc::now(),
            token_fingerprint: fingerprint(access_token),
        };
        snapshots::save(&path, Provider::Openai, account_id, &snapshot).unwrap();
        let mut cache = snapshots::load(&path);
        let account = Account {
            account_id: account_id.into(),
            provider: Provider::Openai,
            workspace_id: Some("startup-workspace".into()),
            is_fedramp: false,
            display_label: "Codex".into(),
            email: "startup@example.invalid".into(),
            created_at: chrono::Utc::now(),
            last_ok_at: Some(snapshot.fetched_at),
            quarantined: false,
            sort_order: 0,
        };
        let mut scheduler = Scheduler::new(PollPolicy::with_interval_secs(300), SystemClock);
        register_accounts(
            &mut scheduler,
            &[account],
            &mut cache,
            &|provider, id| current_token_fingerprint(&store, provider, id),
        );

        assert!(matches!(
            scheduler.state(Provider::Openai, account_id),
            Some(AccountState::Stale { .. })
        ));
        std::fs::remove_file(path).ok();
    }
}
