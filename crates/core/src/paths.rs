//! Where this application's files live. docs/design.md §9.1.
//!
//! There is one derivation and both binaries call it. The CLI used to hand-roll
//! `$XDG_CONFIG_HOME || $HOME/.config` (crates/cli/src/main.rs:16-25), which is
//! correct on Linux and wrong on macOS and Windows — and `quota-cli login` is
//! how accounts are added, so a second derivation means the GUI reads a file
//! nobody writes. Re-derived paths and keys are the ccstatusline #521 bug class
//! §9.3 cites.

use std::path::PathBuf;
use std::sync::OnceLock;

/// A base directory supplied by the host, for platforms where `dirs` cannot
/// find one. Write-once: see [`set_base_dir`].
static BASE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Where the base directory came from. Exposed so a diagnostics view can show
/// it, because the failure it distinguishes is otherwise invisible until a
/// write fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseDirSource {
    /// The host called [`set_base_dir`].
    Injected,
    /// `dirs` resolved one, which is the desktop case.
    Platform,
    /// Neither. Every path below is a guess relative to the working directory
    /// and writing to it will probably fail.
    Fallback,
}

/// Tell this crate where its files live, for hosts `dirs` cannot serve.
///
/// **Android needs this and does not merely prefer it.** `dirs 6.0` routes
/// Android to its Linux implementation, `dirs-sys` defines the fallback as
/// `None` there, and AOSP's `init.environ.rc` does not export `HOME` — so
/// `dirs::config_dir()` returns `None` and the derivation below lands on
/// `"./quota-board"`, which in an app process resolves against `/` and fails
/// with `Read-only file system` (measured in a zygote-forked app process on
/// Android 16, not through `adb shell`, which sets `HOME` for interactive
/// shells and reports a false pass). Pass `Context.getNoBackupFilesDir()`.
///
/// It also has a use on the desktop it was not written for: a test that needs
/// its own config directory can take one here instead of writing into the
/// developer's real one.
///
/// **Call it before deriving any path.** Returns `Err` with the rejected value
/// if a base directory was already established, rather than silently letting a
/// second caller win — two live derivations is the ccstatusline #521 bug class
/// this module exists to prevent.
pub fn set_base_dir(dir: PathBuf) -> Result<(), PathBuf> {
    BASE_DIR.set(dir)
}

/// Which of the three cases [`config_dir`] is currently in.
pub fn base_dir_source() -> BaseDirSource {
    if BASE_DIR.get().is_some() {
        BaseDirSource::Injected
    } else if dirs::config_dir().is_some() {
        BaseDirSource::Platform
    } else {
        BaseDirSource::Fallback
    }
}

/// The config directory for this application, per §9.1.
///
/// In precedence order: a base directory the host [`set_base_dir`]; then
/// whatever `dirs` resolves —
///
/// ```text
///   macOS    ~/Library/Application Support/quota-board
///   Linux    $XDG_CONFIG_HOME/quota-board, else ~/.config/quota-board
///   Windows  %APPDATA%\quota-board
/// ```
///
/// — and only then the current directory, which on a desktop means `$HOME` is
/// unset and on Android means nobody called [`set_base_dir`].
///
/// **The `quota-board` component is appended in all three cases**, including an
/// injected base. That is deliberate: one derivation, one layout, everywhere.
/// A host that injects an already-app-private directory gets one redundant
/// path component and, in exchange, the same structure the desktop has.
pub fn config_dir() -> PathBuf {
    BASE_DIR
        .get()
        .cloned()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("quota-board")
}

/// The account metadata file. Shared by the GUI and `quota-cli`.
pub fn accounts_file() -> PathBuf {
    config_dir().join("accounts.json")
}

/// User settings. §9.1 puts these beside `accounts.json` in the OS config
/// directory. Tokens never live here — `secrets` owns those.
pub fn settings_file() -> PathBuf {
    config_dir().join("settings.json")
}

/// §9.2's encrypted-file fallback. Only reached when no OS keychain is
/// usable; `unlock_secrets` is the one caller, because opening it needs a
/// passphrase the user types.
pub fn secrets_file() -> PathBuf {
    config_dir().join("secrets.enc")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test, not four, because `BASE_DIR` is a `OnceLock` and can only be
    /// set once per process — splitting this would make the assertions depend
    /// on test ordering, which is exactly the kind of test that passes for the
    /// wrong reason.
    ///
    /// Safe to set the lock here: nothing else in this crate's tests derives a
    /// path, so no parallel test can observe the injected value.
    #[test]
    fn an_injected_base_directory_wins_and_cannot_be_replaced() {
        // Before injection the source is whatever the host platform offers.
        // On a developer machine that is `Platform`; asserting on it would make
        // this test depend on the environment, so only the negative is checked.
        assert_ne!(base_dir_source(), BaseDirSource::Injected);

        let base = std::env::temp_dir().join("quota-board-paths-test");
        set_base_dir(base.clone()).expect("first set must succeed");

        assert_eq!(base_dir_source(), BaseDirSource::Injected);
        assert_eq!(config_dir(), base.join("quota-board"));

        // Every derived path must sit under the injected base — the point of
        // the module is that there is one derivation, not one per file.
        assert_eq!(accounts_file(), base.join("quota-board").join("accounts.json"));
        assert_eq!(settings_file(), base.join("quota-board").join("settings.json"));
        assert_eq!(secrets_file(), base.join("quota-board").join("secrets.enc"));

        // A second caller does not silently win. It gets its value back.
        let rejected = PathBuf::from("/somewhere/else");
        assert_eq!(set_base_dir(rejected.clone()), Err(rejected));
        assert_eq!(config_dir(), base.join("quota-board"), "the first base still stands");
    }
}
