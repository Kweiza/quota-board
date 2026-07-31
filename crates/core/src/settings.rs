//! User settings. docs/design.md §9.1 puts these in the OS config directory
//! beside `accounts.json`, resolved by the one shared derivation in `paths` —
//! never by `tauri-plugin-store`, which resolves Tauri's `app_config_dir()`
//! (keyed by the bundle identifier, a different directory) and is unreachable
//! from this deliberately Tauri-unaware crate, so the degrade-to-default rule
//! below could not be tested headlessly.
//!
//! **The only setting today is the polling interval**, and it exists because
//! §6.1 says the interval is "Configurable, with a floor of 180 seconds".
//! Before this module the interval was a literal in `src-tauri/src/main.rs`,
//! so the floor had nothing to defend against.
//!
//! **A settings file that cannot be understood degrades to the documented
//! default, never to a nonsense value, and never silently.** That is CLAUDE.md's
//! "never demote a missing or unparseable value to 0%" applied to
//! configuration: a hand-edited `poll_interval_secs: 5` must not become a
//! five-second polling loop, and it must not vanish without the settings window
//! saying why.

use crate::scheduler::PollPolicy;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Bumped only when the meaning of an **existing** field changes. Adding a
/// field needs no bump — `#[serde(default)]` on the container already fills a
/// field an older file does not carry.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("settings file I/O error: {0}")]
    Io(String),
    /// Refusing to guess at a file has to mean refusing to overwrite it too.
    /// Reading a newer file already falls back to the defaults, and `extra`
    /// only preserves unknown keys for a version this build understands — so
    /// without this, the first interval change would rewrite a v2 file as v1
    /// and delete every setting the newer build had put there. That is the
    /// exact loss `extra` exists to prevent, arriving through the one door
    /// `extra` does not cover.
    #[error(
        "the settings file is format version {found} and this build understands \
         {understood}; it will not be overwritten"
    )]
    UnknownVersion { found: u32, understood: u32 },
}

/// `#[serde(default)]` on the container, not per field: a settings file written
/// by an older build is missing every field a newer build adds, and without it
/// the whole file fails to parse and every setting silently reverts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct SettingsFile {
    /// Defaults to [`FORMAT_VERSION`], so a file this build wrote (and a
    /// hand-written one without the key) is accepted, while a file from a
    /// future build that bumped the version is refused rather than misread.
    version: u32,
    poll_interval_secs: i64,
    /// Every key this build does not know, kept so that saving one setting
    /// does not delete another build's. Without it, an older build that only
    /// knows `poll_interval_secs` silently drops `launch_at_login` and
    /// `opacity` (design.md:535-536, deferred to Tasks 19-20) the first time
    /// the interval is changed.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl Default for SettingsFile {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            poll_interval_secs: default_poll_interval_secs(),
            extra: serde_json::Map::new(),
        }
    }
}

/// The default polling interval, read from [`PollPolicy::default`] rather than
/// repeated here, so §6.1's "5 minutes" has exactly one home.
pub fn default_poll_interval_secs() -> i64 {
    PollPolicy::default().interval().num_seconds()
}

/// §6.1's floor is expressed once, in `PollPolicy`, and is not copied here.
///
/// The ceiling is not cosmetic. `TimeDelta::seconds` panics above
/// `i64::MAX / 1000` and `now + interval` panics well below that — measured on
/// chrono 0.4.45: `PollPolicy::with_interval_secs(i64::MAX)` panics with
/// "TimeDelta::seconds out of bounds", and `Utc::now() + TimeDelta::seconds(
/// i64::MAX / 1000)` panics too. Both are reachable from a hand-edited file:
/// the first inside `setup()` before any window exists, the second inside
/// `record_success` on the polling task, where state.rs's own doc comment says
/// "a panic here stops all polling for the life of the process".
fn clamp_interval(secs: i64) -> i64 {
    secs.clamp(PollPolicy::MIN_INTERVAL_SECS, PollPolicy::MAX_INTERVAL_SECS)
}

/// Split out from `SettingsStore::load` so the decision table is a pure
/// function of the file's bytes and every branch is testable.
///
/// The third element is the version this build could not interpret, when there
/// is one. It travels separately from the warning because it is not a message —
/// it is what makes the file read-only for the rest of the process.
fn read(path: &Path) -> (SettingsFile, Option<String>, Option<u32>) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        // No file yet is the ordinary first run, not a problem to report.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (SettingsFile::default(), None, None)
        }
        Err(e) => {
            return (
                SettingsFile::default(),
                Some(format!("the settings file could not be read ({e}); the defaults are in use")),
                None,
            )
        }
    };
    let parsed: SettingsFile = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            return (
                SettingsFile::default(),
                Some(format!(
                    "the settings file could not be parsed ({e}); the defaults are in use"
                )),
                None,
            )
        }
    };
    if parsed.version != FORMAT_VERSION {
        return (
            SettingsFile::default(),
            Some(format!(
                "the settings file is format version {} and this build understands \
                 {FORMAT_VERSION}; the defaults are in use and it will not be \
                 overwritten",
                parsed.version
            )),
            Some(parsed.version),
        );
    }
    let clamped = clamp_interval(parsed.poll_interval_secs);
    let warning = (clamped != parsed.poll_interval_secs).then(|| {
        format!(
            "the stored polling interval of {}s is outside the allowed range and was \
             adjusted to {clamped}s",
            parsed.poll_interval_secs
        )
    });
    (SettingsFile { poll_interval_secs: clamped, ..parsed }, warning, None)
}

/// A single-owner handle to one settings file.
///
/// The ownership rule `AccountStore` carries (accounts.rs:36-47) applies here
/// too: `flush` rewrites the whole file and does not re-read and merge, so two
/// live instances pointed at the same path would discard each other's writes.
/// `AppState` holds the only one.
pub struct SettingsStore {
    path: PathBuf,
    file: SettingsFile,
    warning: Option<String>,
    /// Set when the file on disk carries a version this build cannot interpret.
    /// While it is set the store serves defaults and refuses to write, so a
    /// newer build's settings survive being read by an older one.
    unknown_version: Option<u32>,
}

impl SettingsStore {
    /// **Never fails.** A missing, unreadable, unparseable or unknown-version
    /// file yields the documented defaults plus a reason.
    pub fn load(path: &Path) -> Self {
        let (mut file, warning, unknown_version) = read(path);
        file.version = FORMAT_VERSION;
        Self { path: path.to_path_buf(), file, warning, unknown_version }
    }

    /// Whether this store will accept a write. False only for a file from a
    /// format version this build does not understand — the settings window
    /// disables its controls on this rather than letting a save fail.
    pub fn is_writable(&self) -> bool {
        self.unknown_version.is_none()
    }

    /// The effective interval: already inside `PollPolicy`'s allowed range,
    /// whatever the file said.
    pub fn poll_interval_secs(&self) -> i64 {
        self.file.poll_interval_secs
    }

    /// **The one derivation** of the running policy from the stored value.
    pub fn poll_policy(&self) -> PollPolicy {
        PollPolicy::with_interval_secs(self.file.poll_interval_secs)
    }

    /// Why the defaults are in use, if they are.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    /// Clamps, writes, and returns the value that actually took effect.
    ///
    /// On a write failure the in-memory value is rolled back, so this type
    /// never reports an interval the file does not carry.
    pub fn set_poll_interval_secs(&mut self, secs: i64) -> Result<i64, SettingsError> {
        // Before the clamp, not after: refusing to interpret the file has to
        // mean refusing to rewrite it. `flush` serialises the whole struct, and
        // for an unknown version that struct is the defaults with an empty
        // `extra` — so writing would delete the newer build's settings rather
        // than preserve them.
        if let Some(found) = self.unknown_version {
            return Err(SettingsError::UnknownVersion { found, understood: FORMAT_VERSION });
        }
        let clamped = clamp_interval(secs);
        let previous = self.file.poll_interval_secs;
        self.file.poll_interval_secs = clamped;
        match self.flush() {
            Ok(()) => {
                self.warning = None;
                Ok(clamped)
            }
            Err(e) => {
                self.file.poll_interval_secs = previous;
                Err(e)
            }
        }
    }

    fn flush(&self) -> Result<(), SettingsError> {
        let text = serde_json::to_string_pretty(&self.file)
            .map_err(|e| SettingsError::Io(e.to_string()))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| SettingsError::Io(e.to_string()))?;
        }
        let tmp = random_tmp_path(&self.path);
        let written = std::fs::File::create(&tmp)
            .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
            .map_err(|e| SettingsError::Io(e.to_string()));
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(SettingsError::Io(e.to_string()));
        }
        Ok(())
    }
}

/// Random per call, for the reason accounts.rs:116-120 spells out.
fn random_tmp_path(path: &Path) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut bytes = [0u8; 8];
    rand::fill(&mut bytes[..]);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".tmp.{}.{n}.{hex}", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut bytes = [0u8; 8];
        rand::fill(&mut bytes[..]);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut p = std::env::temp_dir();
        p.push(format!("quoata-settings-{}-{n}-{hex}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn a_missing_file_yields_the_documented_default() {
        let path = tmp();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), 300, "docs/design.md:281 says five minutes");
        assert_eq!(s.poll_interval_secs(), default_poll_interval_secs());
        assert!(s.warning().is_none(), "a first run is not a problem to report");
    }

    #[test]
    fn a_corrupt_file_degrades_to_the_default_and_says_so() {
        let path = tmp();
        std::fs::write(&path, b"{ this is not json").unwrap();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), default_poll_interval_secs());
        assert!(s.warning().is_some(), "a corrupt settings file must be reported");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_file_missing_a_field_keeps_the_default_for_it() {
        let path = tmp();
        std::fs::write(&path, b"{}").unwrap();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), default_poll_interval_secs());
        assert!(s.warning().is_none(), "an older build's file is not an error");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_file_from_an_unknown_format_version_is_not_guessed_at() {
        let path = tmp();
        std::fs::write(
            &path,
            format!(r#"{{"version": {}, "poll_interval_secs": 900}}"#, FORMAT_VERSION + 1),
        )
        .unwrap();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), default_poll_interval_secs());
        assert!(s.warning().is_some());
        std::fs::remove_file(&path).ok();
    }

    /// The other half of "not guessed at". Falling back to the defaults on
    /// *read* only preserves a newer build's settings if the *write* is refused
    /// too — `extra` cannot help here, because the struct that would be
    /// serialised is the default one, with `extra` empty. Without the refusal
    /// the first interval change deletes every key the newer build added, which
    /// is precisely the loss `extra` exists to prevent.
    #[test]
    fn a_file_from_an_unknown_format_version_is_never_overwritten() {
        let path = tmp();
        let original = format!(
            r#"{{"version": {}, "poll_interval_secs": 900, "opacity": 0.8}}"#,
            FORMAT_VERSION + 1
        );
        std::fs::write(&path, &original).unwrap();

        let mut s = SettingsStore::load(&path);
        assert!(!s.is_writable(), "a file this build cannot interpret must not be writable");

        let err = s.set_poll_interval_secs(600).unwrap_err();
        assert!(matches!(err, SettingsError::UnknownVersion { .. }), "wrong error: {err}");

        // The bytes are the assertion. A store that reported an error but wrote
        // anyway would pass every check above.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            original,
            "the newer build's settings file was modified"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_hand_edited_value_below_the_floor_is_raised_to_it() {
        let path = tmp();
        std::fs::write(&path, br#"{"poll_interval_secs": 5}"#).unwrap();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), PollPolicy::MIN_INTERVAL_SECS);
        assert_eq!(s.poll_policy().interval().num_seconds(), PollPolicy::MIN_INTERVAL_SECS);
        assert!(s.warning().is_some(), "an adjusted value must be reported");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_absurd_interval_cannot_panic_the_startup_or_the_poll_loop() {
        let path = tmp();
        std::fs::write(&path, format!(r#"{{"poll_interval_secs": {}}}"#, i64::MAX)).unwrap();
        let s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), PollPolicy::MAX_INTERVAL_SECS);
        assert_eq!(s.poll_policy().interval().num_seconds(), PollPolicy::MAX_INTERVAL_SECS);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_saved_interval_survives_a_reload_and_a_failed_save_changes_nothing() {
        let path = tmp();
        {
            let mut s = SettingsStore::load(&path);
            assert_eq!(s.set_poll_interval_secs(900).unwrap(), 900);
            assert_eq!(s.set_poll_interval_secs(5).unwrap(), PollPolicy::MIN_INTERVAL_SECS);
            assert_eq!(s.set_poll_interval_secs(900).unwrap(), 900);
        }
        assert_eq!(SettingsStore::load(&path).poll_interval_secs(), 900);

        let blocker = tmp();
        std::fs::write(&blocker, b"a regular file, not a directory").unwrap();
        let mut s = SettingsStore::load(&blocker.join("settings.json"));
        let before = s.poll_interval_secs();
        assert!(s.set_poll_interval_secs(1800).is_err(), "the write cannot succeed here");
        assert_eq!(s.poll_interval_secs(), before, "a failed write was reported as applied");

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&blocker).ok();
    }

    /// A build that does not know `opacity` must not delete it when the user
    /// changes the interval. Tasks 19-20 add exactly such fields.
    #[test]
    fn saving_one_setting_preserves_a_field_this_build_does_not_know() {
        let path = tmp();
        std::fs::write(&path, br#"{"poll_interval_secs": 600, "opacity": 0.8}"#).unwrap();
        let mut s = SettingsStore::load(&path);
        assert_eq!(s.poll_interval_secs(), 600);
        s.set_poll_interval_secs(900).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("opacity"), "an unknown setting was deleted: {text}");
        std::fs::remove_file(&path).ok();
    }

    /// The saved file carries the version this build writes, so a later build
    /// can tell what wrote it.
    #[test]
    fn the_saved_file_records_the_format_version() {
        let path = tmp();
        SettingsStore::load(&path).set_poll_interval_secs(600).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(r#""version": 1"#), "{text}");
        std::fs::remove_file(&path).ok();
    }
}
