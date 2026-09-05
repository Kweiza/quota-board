//! §7.4 + §9.3: the last successful snapshot per account, cached to disk so a
//! restart shows the previous value as `STALE` instead of an empty widget.
//!
//! **This lives in the core, not in `src-tauri`.** §4.1 assigns "snapshot
//! retention" to `scheduler`, and `src-tauri` has no test module, no test
//! harness, and cannot be reached by `cargo test -p quota-core` at all — so
//! the one part of this task that handles a credential-derived value and writes
//! a file would otherwise ship with zero coverage, in a repository whose
//! AGENTS.md records that the same redaction defect already shipped twice. The
//! only piece that genuinely needs Tauri is resolving the cache directory, and
//! that stays in the wiring.

use crate::model::UsageWindow;
use crate::provider::Provider;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One account's last successful snapshot, as written to disk.
///
/// Deriving `Debug` is safe here and is not an oversight: this struct holds
/// windows, a timestamp and a digest, never a credential. If it ever gains a
/// field that carries one, hand-write `Debug` following `TokenSet`
/// (auth/token.rs:76-88) — but do not pre-emptively redact a digest, which
/// would make the cache undebuggable for no gain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSnapshot {
    pub windows: Vec<UsageWindow>,
    pub fetched_at: DateTime<Utc>,
    /// Fingerprint of the access token this snapshot was fetched with.
    pub token_fingerprint: String,
}

/// A one-way fingerprint of a token. **The token itself never reaches disk.**
///
/// Two facts a future reader will otherwise re-litigate. (1) This value
/// **rotates on every refresh** — `auth::stored` re-saves a new `TokenSet`
/// (stored.rs:220) and §10.5 calls refresh routine, not exceptional — so a
/// mismatch means "this cache cannot be verified", not necessarily "a different
/// account". Discarding is still what §9.3 requires. (2) The thing that
/// actually prevents ccstatusline #521 is keying by `account.uuid`; the
/// fingerprint is the separate §9.3 requirement that closes #459.
pub fn fingerprint(access_token: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};
    let full = Sha256::digest(access_token.as_bytes());
    // Twelve bytes is enough to avoid collisions and leaves nothing to
    // reconstruct the token from. Measured: 16 base64url characters.
    URL_SAFE_NO_PAD.encode(&full[..12])
}

/// The whole cache. A missing or unreadable file is an empty cache, never an
/// error: no account state depends on this file.
pub fn load(path: &Path) -> HashMap<String, CachedSnapshot> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Symmetric, unlike `provider::token_key`, and for a measured difference in
/// cost: an orphaned cache entry is one cold start, while an orphaned keychain
/// entry is a forced re-login. Making the two agree is not itself a goal.
///
/// **`pub(crate)`, not private.** `scheduler::register_accounts` reads this
/// same map by key on startup (§7.4's restore) and must build the identical
/// string, or a bare-id lookup would hit nothing — or worse, hit a stale
/// pre-namespacing entry that this module's own `save`/`remove` can no longer
/// reach and that therefore never gets updated or cleaned up again. One shared
/// function rather than a second hand-built `format!` at the call site: a key
/// format stays a format only while exactly one piece of code writes it.
pub(crate) fn cache_key(provider: Provider, account_id: &str) -> String {
    format!("{}:{}", provider.as_str(), account_id)
}

/// Writes **one** account's entry, merging into whatever is already on disk.
///
/// Rebuilding the whole map on every call and writing it over the file deletes
/// every account that has not yet polled successfully in this process.
/// Reproduced twice: with accounts a and b registered and only a having
/// succeeded, the rebuilt map was `["a"]`; and against a store answering
/// `SecretError::Locked` — §9.2's ordinary screen-lock case, which
/// `Scheduler::state`'s `SecretsLocked` branch calls "the normal case, not an
/// edge one" — the file became literally `{}`. With more than one account, the
/// entire premise of this product, §7.4's restore would only ever work for
/// whichever account polled first. Removal happens only through `remove`.
pub fn save(
    path: &Path,
    provider: Provider,
    uuid: &str,
    snap: &CachedSnapshot,
) -> std::io::Result<()> {
    let mut map = load(path);
    map.insert(cache_key(provider, uuid), snap.clone());
    write_map(path, &map)
}

/// Drops one account's entry. Called when an account is deleted (Task 18).
pub fn remove(path: &Path, provider: Provider, uuid: &str) -> std::io::Result<()> {
    let mut map = load(path);
    if map.remove(&cache_key(provider, uuid)).is_none() {
        return Ok(());
    }
    write_map(path, &map)
}

fn write_map(path: &Path, map: &HashMap<String, CachedSnapshot>) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(map)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Same shape as `accounts::write_text_then_rename` (accounts.rs:150-163)
    // and `secrets::encrypted_file::write_bytes_then_rename`: random temp name,
    // write, fsync, rename, and remove the temp on every failure path.
    let tmp = tmp_path(path);
    let written = (|| -> std::io::Result<()> {
        let mut f = create_owner_only(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

fn tmp_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(format!(".tmp.{}.{:016x}", std::process::id(), rand::random::<u64>()));
    PathBuf::from(name)
}

/// Born `0600`, never chmodded afterwards — the invariant
/// `secrets::encrypted_file` is tested against (encrypted_file.rs:253, :279,
/// and the test at :563-587, whose comment records that an earlier
/// chmod-after-create version passed a weaker test and proved nothing).
/// Measured on this machine: a plain `std::fs::write` under umask 022 produces
/// mode 644. This file is derived from a credential — it carries account uuids
/// and a token digest — and §3.2 frames this machine as concentrating every
/// account's risk.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::TokenSet;
    use chrono::TimeDelta;

    /// Produce a unique path on every call. Same reasoning as
    /// `accounts::tests::tmp` (accounts.rs:173-183): the harness runs tests as
    /// threads in one process, so a pid alone collides.
    fn tmp() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        rand::fill(&mut rand_bytes[..]);
        let hex: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut p = std::env::temp_dir();
        p.push(format!("quota-snapshots-{}-{n}-{hex}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn snap(pct: f64, fp: &str) -> CachedSnapshot {
        CachedSnapshot {
            windows: vec![UsageWindow {
                window_id: "five_hour".into(),
                label: "5h".into(),
                percent: pct,
                resets_at: Utc::now() + TimeDelta::hours(1),
                scope: None,
                weekly: false,
            }],
            fetched_at: Utc::now(),
            token_fingerprint: fp.to_string(),
        }
    }

    #[test]
    fn a_missing_cache_file_is_an_empty_cache() {
        let path = tmp();
        assert!(!path.exists(), "the fixture must start with no file");
        assert!(load(&path).is_empty(), "a missing file must not be an error");
    }

    /// The whole premise of this product is more than one account. Rebuilding
    /// the map from the accounts that have polled successfully in *this*
    /// process and writing it over the file deletes everyone else, so §7.4's
    /// restore would only ever work for whichever account polled first.
    #[test]
    fn saving_one_account_does_not_delete_the_others() {
        let path = tmp();
        save(&path, Provider::Anthropic, "a", &snap(11.0, "fp-a")).unwrap();
        save(&path, Provider::Anthropic, "b", &snap(22.0, "fp-b")).unwrap();

        let map = load(&path);
        assert_eq!(map.len(), 2, "the second write dropped the first account: {:?}", map.keys());
        assert_eq!(map["anthropic:a"].windows[0].percent, 11.0);
        assert_eq!(map["anthropic:b"].windows[0].percent, 22.0);

        // `remove` is the only path that may drop an entry.
        remove(&path, Provider::Anthropic, "a").unwrap();
        let map = load(&path);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("anthropic:b"));
        std::fs::remove_file(&path).ok();
    }

    /// docs/design.md §9.3, applied to the cache rather than the token store:
    /// two providers issuing the same account id must land in two entries, not
    /// one overwriting the other. Unlike `provider::token_key`, this is not
    /// load-bearing for credential safety — an orphaned cache entry costs one
    /// cold start — but it must still hold, or a Codex account with the same id
    /// as an existing Anthropic account would silently steal its cached
    /// snapshot (or vice versa).
    #[test]
    fn two_providers_do_not_share_a_cache_entry() {
        let path = tmp();
        let f = fingerprint("tok");
        save(&path, Provider::Anthropic, "same", &snap(10.0, &f)).unwrap();
        save(&path, Provider::Openai, "same", &snap(90.0, &f)).unwrap();
        let map = load(&path);
        assert_eq!(map.len(), 2, "one provider overwrote the other: {:?}", map.keys());
        std::fs::remove_file(&path).ok();
    }

    /// Same shape as `encrypted_file.rs:563-587`: the mode is inspected the
    /// instant the file is created, **before any write**, because a
    /// chmod-after-create version also ends at 0600 and would pass a weaker
    /// check while leaving a world-readable window in between.
    #[cfg(unix)]
    #[test]
    fn the_cache_file_is_owner_only_from_the_start() {
        use std::os::unix::fs::PermissionsExt;

        let probe = tmp();
        let f = create_owner_only(&probe).unwrap();
        let mode_before_any_write = f.metadata().unwrap().permissions().mode() & 0o777;
        drop(f);
        std::fs::remove_file(&probe).ok();
        assert_eq!(
            mode_before_any_write, 0o600,
            "the temp file must be owner-only from the instant it is created, before any write"
        );

        // And the real path end to end, twice — the second write goes through
        // rename over an existing file, which is where a mode can be lost.
        let path = tmp();
        save(&path, Provider::Anthropic, "a", &snap(1.0, "fp")).unwrap();
        let after_first = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(after_first, 0o600, "the cache file did not end up owner-only");
        save(&path, Provider::Anthropic, "b", &snap(2.0, "fp")).unwrap();
        let after_second = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(after_second, 0o600, "the second write widened the mode");
        std::fs::remove_file(&path).ok();
    }

    /// The bytes that actually reach the disk carry no token material. Same
    /// shape as `accounts::tests::serialized_form_has_no_token_fields`
    /// (accounts.rs:300-311), but with one addition that shape does not have,
    /// and the addition is the whole point.
    ///
    /// **A named-substring sweep cannot catch a truncated leak.** Measured
    /// during this task's back-test: the mutation that makes `fingerprint`
    /// return the token's first 16 characters writes `sk-ant-oat01-SEN` to
    /// disk, which contains neither the sentinel nor `access_token` nor
    /// `Bearer` — every named assertion passed and the mutation **survived**.
    /// So the token is also swept against itself: any contiguous run of it
    /// reaching the file fails, whatever the leak was truncated to.
    #[test]
    fn the_cache_file_contains_no_token_material() {
        const SENTINEL: &str = "sk-ant-oat01-SENTINELVALUE";
        let tokens = TokenSet {
            access_token: SENTINEL.into(),
            refresh_token: "sk-ant-ort01-SENTINELREFRESH".into(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: crate::auth::token::AnthropicAuthConfig::production().client_id,
        };

        let path = tmp();
        save(&path, Provider::Anthropic, "uuid-a", &snap(42.0, &fingerprint(&tokens.access_token)))
            .unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for forbidden in
            ["access_token", "refresh_token", "Bearer", SENTINEL, "SENTINEL", &tokens.refresh_token]
        {
            assert!(!text.contains(forbidden), "the cache file contains {forbidden}: {text}");
        }

        // Eight characters is short enough to catch a prefix leak and long
        // enough that a collision against a base64url digest is not a real
        // risk. Both tokens are fixed constants here, so this is deterministic
        // rather than probabilistic.
        const RUN: usize = 8;
        for token in [&tokens.access_token, &tokens.refresh_token] {
            for window in token.as_bytes().windows(RUN) {
                let run = std::str::from_utf8(window).expect("the fixture tokens are ASCII");
                assert!(
                    !text.contains(run),
                    "the cache file contains a {RUN}-character run of a token ({run}): {text}"
                );
            }
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let a = fingerprint("sk-ant-oat01-aaaa");
        assert_eq!(a, fingerprint("sk-ant-oat01-aaaa"), "the same token must fingerprint the same");
        assert_ne!(a, fingerprint("sk-ant-oat01-aaab"), "one changed character must change it");
        assert!(!a.is_empty());
    }
}
