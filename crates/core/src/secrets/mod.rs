pub mod encrypted_file;
pub mod keychain;
pub mod timeout;

use std::collections::HashMap;
use std::sync::Mutex;

/// The keychain service name. docs/design.md §9.3 keys entries "uniquely by
/// `account.uuid` under our own service name" — this is that name, and both
/// binaries must pass the same string or the GUI sees none of the CLI's tokens.
/// A mismatch is silent: `ensure_fresh` returns `StoredTokenError::Missing`,
/// which classifies to `AuthDead` (scheduler.rs:95) and quarantines every
/// account on the first tick.
pub const SERVICE: &str = "quoata-board";

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
