// Both stores are optional; the `SecretStore` trait below is not. A host that
// implements the trait itself — which is how a mobile build reaches the iOS
// Keychain and the Android Keystore, neither of which `keyring` serves — needs
// neither module, and compiling them out is what keeps Argon2's 64 MiB
// allocation out of binaries that cannot survive it. See this crate's
// `[features]`.
#[cfg(feature = "encrypted-file")]
pub mod encrypted_file;
#[cfg(feature = "os-keychain")]
pub mod keychain;
// Unconditional for the same reason as `timeout`: it wraps any `SecretStore`
// and touches no backend of its own.
pub mod packed;
// Unconditional: it wraps any `SecretStore` in a timeout and touches no backend
// of its own. Its only mention of keyring is in a doc comment tracing a call
// path.
pub mod timeout;

use std::collections::HashMap;
use std::sync::Mutex;

/// The keychain service name. docs/design.md §9.3 keys entries "uniquely by
/// `account.uuid` under our own service name" — this is that name, and both
/// binaries must pass the same string or the GUI sees none of the CLI's tokens.
/// A mismatch is silent: `ensure_fresh` returns `StoredTokenError::Missing`,
/// which classifies to `AuthDead` (scheduler.rs:95) and quarantines every
/// account on the first tick.
pub const SERVICE: &str = "quota-board";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// No usable OS store is available. The signal to switch to the encrypted-file fallback.
    #[error("no usable credential store: {0}")]
    NoBackend(String),
    /// A store exists but is locked. The user must unlock it.
    #[error("credential store is locked: {0}")]
    Locked(String),
    /// The hard limit imposed by Windows Credential Manager.
    #[error("value too large (limit {limit} bytes)")]
    TooLong { limit: usize },
    #[error("store error: {0}")]
    Backend(String),
}

/// One byte string per key. Any backend satisfying this contract will do.
pub trait SecretStore: Send + Sync {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError>;
    /// `Ok(None)` when absent. Absence is not an error.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError>;
    /// `Ok(true)` if something was actually removed, `Ok(false)` if it was not there.
    fn delete(&self, key: &str) -> Result<bool, SecretError>;
    /// Backend name to show in the UI.
    fn describe(&self) -> String;
}

/// **The one way to open the OS keychain.** Both binaries must call this rather
/// than `KeychainStore::probe` directly.
///
/// docs/design.md §9.3 already warns that the GUI and the CLI must agree on
/// [`SERVICE`], and that a mismatch is silent — every account classifies to
/// `AUTH_DEAD` on the first tick. The storage *layout* is the same kind of
/// agreement: a build that packs and a build that does not would look at the
/// same keychain and see none of each other's tokens. Having one function
/// decide is what keeps them from drifting.
///
/// On macOS the store is wrapped in [`packed::PackedStore`], which is where the
/// reasoning for that lives. Elsewhere the keychain is returned as it is.
#[cfg(feature = "os-keychain")]
pub fn open_os_keychain(service: &str) -> Result<Box<dyn SecretStore>, SecretError> {
    let store = keychain::KeychainStore::probe(service)?;
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(packed::PackedStore::new(store)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(Box::new(store))
    }
}

/// Test-only. Never used on a production path.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for MemoryStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        self.inner.lock().unwrap().insert(key.to_string(), value.to_vec());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        Ok(self.inner.lock().unwrap().remove(key).is_some())
    }
    fn describe(&self) -> String {
        "memory (test only)".to_string()
    }
}

impl MemoryStore {
    /// Test-only. What actually reached the backend — `packed` asserts on this,
    /// because the number of physical entries *is* the number of macOS approval
    /// prompts.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.inner.lock().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }
}

/// So a wrapper can be handed a shared backend without owning it. `AppState`
/// already passes the store around as `Arc<dyn SecretStore>`; this makes that
/// shape usable wherever a `SecretStore` is expected rather than only where a
/// `&dyn` is.
impl<T: SecretStore + ?Sized> SecretStore for &T {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        (**self).put(key, value)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        (**self).get(key)
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        (**self).delete(key)
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
}

impl<T: SecretStore + ?Sized> SecretStore for std::sync::Arc<T> {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        (**self).put(key, value)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        (**self).get(key)
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        (**self).delete(key)
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(store: &dyn SecretStore) {
        assert_eq!(store.get("absent").unwrap(), None, "an absent key must yield None");
        store.put("k1", b"hello").unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some(&b"hello"[..]));
        store.put("k1", b"replaced").unwrap();
        assert_eq!(store.get("k1").unwrap().as_deref(), Some(&b"replaced"[..]));
        assert!(store.delete("k1").unwrap(), "deleting an existing key returns true");
        assert_eq!(store.get("k1").unwrap(), None);
        assert!(!store.delete("k1").unwrap(), "deleting an absent key returns false, not an error");
    }

    #[test]
    fn memory_store_satisfies_the_contract() {
        round_trip(&MemoryStore::default());
    }

    #[test]
    fn memory_store_keys_are_independent() {
        let s = MemoryStore::default();
        s.put("a", b"1").unwrap();
        s.put("b", b"2").unwrap();
        assert_eq!(s.get("a").unwrap().as_deref(), Some(&b"1"[..]));
        s.delete("a").unwrap();
        assert_eq!(s.get("b").unwrap().as_deref(), Some(&b"2"[..]), "b must survive");
    }

    /// docs/design.md §9.3: lookups must be exact-key lookups.
    /// Returning "the first entry sharing a prefix" reproduces ccstatusline #521
    /// once more than one account is present.
    #[test]
    fn lookup_is_exact_not_prefix() {
        let s = MemoryStore::default();
        s.put("uuid-1:access", b"one").unwrap();
        s.put("uuid-11:access", b"eleven").unwrap();
        assert_eq!(s.get("uuid-1:access").unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(s.get("uuid-11:access").unwrap().as_deref(), Some(&b"eleven"[..]));
    }
}
