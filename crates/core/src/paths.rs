//! Where this application's files live. docs/design.md §9.1.
//!
//! There is one derivation and both binaries call it. The CLI used to hand-roll
//! `$XDG_CONFIG_HOME || $HOME/.config` (crates/cli/src/main.rs:16-25), which is
//! correct on Linux and wrong on macOS and Windows — and `quoata-cli login` is
//! how accounts are added, so a second derivation means the GUI reads a file
//! nobody writes. Re-derived paths and keys are the ccstatusline #521 bug class
//! §9.3 cites.

use std::path::PathBuf;

/// The OS config directory for this application, per §9.1. `dirs` resolves it:
///
/// ```text
///   macOS    ~/Library/Application Support/quoata-board
///   Linux    $XDG_CONFIG_HOME/quoata-board, else ~/.config/quoata-board
///   Windows  %APPDATA%\quoata-board
/// ```
///
/// Falls back to the current directory only when the platform reports no config
/// directory at all, which on a desktop means `$HOME` is unset.
pub fn config_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("quoata-board")
}

/// The account metadata file. Shared by the GUI and `quoata-cli`.
pub fn accounts_file() -> PathBuf {
    config_dir().join("accounts.json")
}
