//! Many logical keys inside **one** physical store entry. docs/design.md §9.3.
//!
//! **This exists for one measured reason: on macOS the keychain grants access
//! per *entry*, and the grant is pinned to the exact binary that created it.**
//! Nine accounts occupy fifteen entries — Anthropic writes one per account,
//! Codex three (`:access`, `:refresh`, `:meta`) — so every new build of the app
//! is a stranger to fifteen separate access-control lists and the user is asked
//! to approve fifteen times, on every install.
//!
//! Two things were measured before this module was written, because both are
//! load-bearing and neither was obvious:
//!
//! 1. **A stable code-signing identity does not help.** The keychain's ACL
//!    stores a snapshot of the signed binary, not its designated requirement.
//!    Two binaries signed with the same self-signed certificate and the same
//!    identifier: the writer read its own entry (`status=0`), the rebuilt one
//!    was refused (`-25293 errSecAuthFailed`) with user interaction disabled.
//!    So the fix cannot come from signing, only from having fewer entries.
//! 2. **macOS accepts at least 1 MiB in a single generic-password item.**
//!    Measured at 1, 4, 16, 64, 256 and 1024 KiB — every one written and read
//!    back byte-for-byte. The 2560-byte cap this project applied everywhere is
//!    Windows Credential Manager's alone (`keychain::WINDOWS_BLOB_LIMIT`), which
//!    is why packing is a macOS-only arrangement rather than the default.
//!
//! Packing is therefore **not** a size optimization. It is how fifteen approval
//! prompts become one.
//!
//! The single-blob shape is not new to this codebase: `encrypted_file` has
//! always held every secret in one file. This type gives the keychain the same
//! shape without changing a single key that `provider::token_key` produces, so
//! `auth::stored`, the `(provider, account_id)` keying of §9.3, and every test
//! over them are untouched.

use super::{SecretError, SecretStore};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::HashMap;
use std::sync::Mutex;

/// The one entry every packed key lives inside.
///
/// It must never collide with a key `provider::token_key` can produce. Those
/// are `<uuid>:tokens` and `openai:<id>:tokens:<part>`; this name contains a
/// space and a capital letter and matches neither.
pub const PACKED_ENTRY: &str = "packed accounts";

/// A [`SecretStore`] that keeps every value in one entry of the store beneath
/// it.
///
/// **Reads fall back to the unpacked entry and migrate it.** An installation
/// that predates packing has its tokens in individual entries; a miss in the
/// map consults the inner store under the original key, folds what it finds
/// into the packed entry and removes the original. The migration is lazy on
/// purpose — a single eager pass would have to read all fifteen entries before
/// the first account could be shown, and each of those reads is the approval
/// prompt this module exists to avoid. Spreading them costs the same total once
/// and lets the app come up in between.
pub struct PackedStore<S: SecretStore> {
    inner: S,
    /// `None` until the packed entry has been read once. The load is what costs
    /// an approval prompt, so it happens at most once per process.
    cache: Mutex<Option<HashMap<String, Vec<u8>>>>,
}

/// **Hand-written, and printing `<redacted>` is the whole point.** The cache
/// holds live tokens. AGENTS.md names `auth::token::TokenSet` as the pattern to
/// copy and records that the same defect has shipped twice; a derived `Debug`
/// here would put every account's credentials into any `format!("{:?}")`.
impl<S: SecretStore> std::fmt::Debug for PackedStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackedStore")
            .field("inner", &self.inner.describe())
            .field("cache", &"<redacted>")
            .finish()
    }
}

impl<S: SecretStore> PackedStore<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, cache: Mutex::new(None) }
    }

    /// Runs `f` against the packed map with the cache lock **held for the whole
    /// read-modify-write**, and writes the result through if `f` changed it.
    ///
    /// **The lock spans load and flush on purpose.** Every write here rewrites
    /// the entire entry, so a load that released the lock before the flush
    /// would let two concurrent token refreshes each write a map missing the
    /// other's insert — one account silently losing its credentials. That is
    /// not hypothetical: the scheduler refreshes accounts concurrently, which
    /// is why `auth::stored` carries a compare-and-swap loop at all. Before
    /// packing each key was its own entry and the races could not touch each
    /// other.
    ///
    /// A packed entry that cannot be parsed is **not** treated as an empty map:
    /// that would silently orphan every token it holds and re-log-in every
    /// account. It is an error, which reaches the user as a store failure.
    fn with_map<T>(
        &self,
        f: impl FnOnce(&mut HashMap<String, Vec<u8>>, &S) -> Result<(T, bool), SecretError>,
    ) -> Result<T, SecretError> {
        let mut guard = self.cache.lock().expect("packed cache poisoned");
        if guard.is_none() {
            *guard = Some(match self.inner.get(PACKED_ENTRY)? {
                None => HashMap::new(),
                Some(raw) => decode(&raw)?,
            });
        }
        let map = guard.as_mut().expect("just populated");
        let mut working = map.clone();
        let (value, changed) = f(&mut working, &self.inner)?;
        if changed {
            // Write through before adopting it, so a failed write never leaves
            // this process believing in a value the store does not hold.
            self.inner.put(PACKED_ENTRY, &encode(&working))?;
            *map = working;
        }
        Ok(value)
    }
}

fn encode(map: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    // Base64 rather than a string: values are arbitrary bytes, and a token that
    // happened not to be valid UTF-8 must not become unstorable.
    let encoded: HashMap<&str, String> =
        map.iter().map(|(k, v)| (k.as_str(), STANDARD.encode(v))).collect();
    serde_json::to_vec(&encoded).expect("a map of strings always serializes")
}

fn decode(raw: &[u8]) -> Result<HashMap<String, Vec<u8>>, SecretError> {
    let encoded: HashMap<String, String> = serde_json::from_slice(raw)
        .map_err(|e| SecretError::Backend(format!("the packed entry is not readable ({e})")))?;
    encoded
        .into_iter()
        .map(|(k, v)| {
            STANDARD
                .decode(&v)
                .map(|bytes| (k, bytes))
                .map_err(|e| SecretError::Backend(format!("a packed value is not readable ({e})")))
        })
        .collect()
}

impl<S: SecretStore> SecretStore for PackedStore<S> {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        self.with_map(|map, _| {
            map.insert(key.to_string(), value.to_vec());
            Ok(((), true))
        })
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        // The migration runs inside the same critical section as an ordinary
        // read, so it cannot interleave with a concurrent write either.
        let (value, unpacked_to_drop) = self.with_map(|map, inner| {
            if let Some(value) = map.get(key) {
                return Ok(((Some(value.clone()), false), false));
            }
            // Not packed. An installation older than this module keeps it under
            // its own key.
            let Some(value) = inner.get(key)? else {
                return Ok(((None, false), false));
            };
            map.insert(key.to_string(), value.clone());
            Ok(((Some(value), true), true))
        })?;
        // Deleted only after the packed copy is safely written. A failure here
        // leaves the original where it is, which costs one more migration on
        // the next launch — far cheaper than losing the only copy.
        if unpacked_to_drop {
            let _ = self.inner.delete(key);
        }
        Ok(value)
    }

    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        let was_packed = self.with_map(|map, _| {
            let removed = map.remove(key).is_some();
            Ok((removed, removed))
        })?;
        // Always reach through as well: an entry that predates packing, or one
        // left behind by a flush that failed mid-migration, is still a stored
        // credential and `remove_account` promises it is gone.
        let was_unpacked = self.inner.delete(key)?;
        Ok(was_packed || was_unpacked)
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemoryStore;
    use std::sync::Arc;

    /// Counts what actually reaches the backend, which is the whole point: the
    /// number of physical entries is the number of approval prompts.
    #[derive(Default)]
    struct CountingStore {
        inner: MemoryStore,
        gets: Mutex<Vec<String>>,
    }

    impl SecretStore for CountingStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            self.inner.put(key, value)
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.gets.lock().unwrap().push(key.to_string());
            self.inner.get(key)
        }
        fn delete(&self, key: &str) -> Result<bool, SecretError> {
            self.inner.delete(key)
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
    }


    #[test]
    fn many_values_occupy_one_backend_entry() {
        // The reason this module exists. Fifteen logical keys, the shape nine
        // accounts actually produce, must leave exactly one entry behind — one
        // access-control list, one approval prompt.
        let packed = PackedStore::new(MemoryStore::default());
        for i in 0..6 {
            packed.put(&format!("uuid-{i}:tokens"), b"anthropic").unwrap();
        }
        for i in 0..3 {
            for part in ["access", "refresh", "meta"] {
                packed.put(&format!("openai:user-{i}:tokens:{part}"), b"codex").unwrap();
            }
        }
        assert_eq!(packed.inner.keys(), vec![PACKED_ENTRY.to_string()]);
        assert_eq!(packed.get("uuid-3:tokens").unwrap().as_deref(), Some(&b"anthropic"[..]));
        assert_eq!(
            packed.get("openai:user-2:tokens:refresh").unwrap().as_deref(),
            Some(&b"codex"[..])
        );
    }

    /// The measurement that matters, expressed as a test: reading every account
    /// costs **one** backend read, not one per account. On macOS each backend
    /// read of a differently-owned entry is an approval prompt.
    #[test]
    fn reading_every_key_costs_one_backend_read() {
        let backing = Arc::new(CountingStore::default());
        // A store already containing five packed values, as a later launch finds it.
        PackedStore::new(Arc::clone(&backing))
            .put("seed", b"v")
            .and_then(|()| {
                let p = PackedStore::new(Arc::clone(&backing));
                for i in 0..5 {
                    p.put(&format!("k{i}"), b"v")?;
                }
                Ok(())
            })
            .unwrap();
        backing.gets.lock().unwrap().clear();

        let fresh = PackedStore::new(Arc::clone(&backing));
        for i in 0..5 {
            assert!(fresh.get(&format!("k{i}")).unwrap().is_some());
        }
        let reads = backing.gets.lock().unwrap().clone();
        assert_eq!(reads, vec![PACKED_ENTRY.to_string()], "one entry read, and only that one");
    }

    #[test]
    fn a_value_survives_a_round_trip_through_a_fresh_store() {
        let backing = Arc::new(MemoryStore::default());
        PackedStore::new(Arc::clone(&backing)).put("k", b"\x00\xff not utf-8").unwrap();
        // A second process: no cache, reads what is on disk.
        let reopened = PackedStore::new(Arc::clone(&backing));
        assert_eq!(reopened.get("k").unwrap().as_deref(), Some(&b"\x00\xff not utf-8"[..]));
    }

    #[test]
    fn an_unpacked_entry_is_still_found_and_is_migrated() {
        // The upgrade path. Tokens written before this module existed sit under
        // their own keys; they must be readable, and reading one must fold it
        // in so the next launch does not pay for it again.
        let backing = Arc::new(MemoryStore::default());
        backing.put("uuid-1:tokens", b"legacy").unwrap();
        let packed = PackedStore::new(Arc::clone(&backing));

        assert_eq!(packed.get("uuid-1:tokens").unwrap().as_deref(), Some(&b"legacy"[..]));
        assert_eq!(
            backing.keys(),
            vec![PACKED_ENTRY.to_string()],
            "the original entry should be gone once its value is packed"
        );
        // And a fresh handle still sees it.
        assert_eq!(
            PackedStore::new(Arc::clone(&backing)).get("uuid-1:tokens").unwrap().as_deref(),
            Some(&b"legacy"[..])
        );
    }

    #[test]
    fn delete_removes_both_the_packed_and_the_unpacked_copy() {
        let backing = Arc::new(MemoryStore::default());
        backing.put("k", b"legacy").unwrap();
        let packed = PackedStore::new(Arc::clone(&backing));
        packed.put("k", b"packed").unwrap();
        assert!(packed.delete("k").unwrap());
        assert_eq!(packed.get("k").unwrap(), None);
        assert_eq!(backing.get("k").unwrap(), None, "the unpacked copy is a stored credential too");
    }

    #[test]
    fn deleting_something_absent_reports_false() {
        let packed = PackedStore::new(MemoryStore::default());
        assert!(!packed.delete("never-existed").unwrap());
    }

    /// **Not an empty map.** A packed entry this build cannot parse holds every
    /// account's tokens; reporting it as "nothing stored" classifies all of
    /// them as `AUTH_DEAD` and asks the user to log in again — destroying what
    /// is probably still there.
    #[test]
    fn an_unreadable_packed_entry_is_an_error_rather_than_an_empty_store() {
        let backing = Arc::new(MemoryStore::default());
        backing.put(PACKED_ENTRY, b"{ this is not json").unwrap();
        let packed = PackedStore::new(Arc::clone(&backing));
        assert!(matches!(packed.get("anything"), Err(SecretError::Backend(_))));
    }

    /// **Every write rewrites the whole entry, so two concurrent writes can lose
    /// one of them.** The scheduler refreshes accounts concurrently, and before
    /// packing each key was its own entry where that could not happen. The
    /// eight tests above all passed against a version that released the cache
    /// lock between loading the map and writing it back, so this is the only
    /// one that holds the critical section to its promise.
    ///
    /// `SlowStore` widens the window a real backend leaves open; without it the
    /// interleaving is possible but rare enough to pass by luck.
    #[test]
    fn concurrent_writes_do_not_lose_each_other() {
        use std::thread;
        use std::time::Duration;

        #[derive(Default)]
        struct SlowStore(MemoryStore);
        impl SecretStore for SlowStore {
            fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
                thread::sleep(Duration::from_millis(2));
                self.0.put(key, value)
            }
            fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
                thread::sleep(Duration::from_millis(2));
                self.0.get(key)
            }
            fn delete(&self, key: &str) -> Result<bool, SecretError> {
                self.0.delete(key)
            }
            fn describe(&self) -> String {
                self.0.describe()
            }
        }

        let packed = Arc::new(PackedStore::new(SlowStore::default()));
        let writers: Vec<_> = (0..8)
            .map(|i| {
                let packed = Arc::clone(&packed);
                thread::spawn(move || {
                    packed.put(&format!("account-{i}:tokens"), format!("token-{i}").as_bytes())
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap().unwrap();
        }

        for i in 0..8 {
            assert_eq!(
                packed.get(&format!("account-{i}:tokens")).unwrap().as_deref(),
                Some(format!("token-{i}").as_bytes()),
                "account {i} lost its credentials to a concurrent write"
            );
        }
    }

    #[test]
    fn debug_never_prints_a_token() {
        let packed = PackedStore::new(MemoryStore::default());
        packed.put("uuid:tokens", b"super-secret-refresh-token").unwrap();
        let rendered = format!("{packed:?}");
        assert!(!rendered.contains("super-secret"), "a credential reached Debug: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }
}
