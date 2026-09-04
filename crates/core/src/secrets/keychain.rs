use super::{SecretError, SecretStore};

/// The hard limit imposed by Windows Credential Manager
/// (CRED_MAX_CREDENTIAL_BLOB_SIZE = 5*512). It is why per-account tokens are
/// stored as several entries rather than one large blob.
pub const WINDOWS_BLOB_LIMIT: usize = 2560;

pub struct KeychainStore {
    service: String,
    vendor: String,
}

impl KeychainStore {
    /// **Must be called at most once at application startup.** An application
    /// that has already selected another persistent backend need not call it.
    ///
    /// The v1 wrapper in keyring 4.1.5 has a confirmed bug: `Entry::new` flips
    /// an internal AtomicBool to true *before* attempting to register the store,
    /// and does not roll it back on failure. As a result **the error carrying
    /// the real cause is produced exactly once, on the first call.** Every call
    /// after that yields a context-free `NoDefaultStore`. This function catches
    /// and preserves that first error.
    pub fn probe(service: &str) -> Result<Self, SecretError> {
        let entry = keyring::Entry::new(service, "__quota_probe__").map_err(map_err)?;
        // Canary: only a real store can write, read, and delete successfully.
        entry.set_secret(b"canary").map_err(map_err)?;
        let read = entry.get_secret().map_err(map_err)?;
        let _ = entry.delete_credential();
        if read != b"canary" {
            return Err(SecretError::NoBackend(
                "canary value did not read back — the store does not actually persist".into(),
            ));
        }
        let vendor = keyring_core::get_default_store()
            .map(|s| s.vendor())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(Self { service: service.to_string(), vendor })
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, SecretError> {
        keyring::Entry::new(&self.service, key).map_err(map_err)
    }
}

/// Collapse keyring errors into our three categories.
///
/// `keyring_core::Error` is `#[non_exhaustive]`, so the `_` arm is mandatory.
fn map_err(e: keyring::Error) -> SecretError {
    use keyring::Error as E;
    match e {
        // No backend at all. The first failure arrives as PlatformFailure and
        // every later one as NoDefaultStore; both mean the same thing here.
        E::NoDefaultStore => SecretError::NoBackend("no credential store registered".into()),
        E::PlatformFailure(inner) => SecretError::NoBackend(inner.to_string()),
        // A store exists but access is blocked — usually a locked collection.
        E::NoStorageAccess(inner) => SecretError::Locked(inner.to_string()),
        E::TooLong(_, limit) => SecretError::TooLong { limit: limit as usize },
        other => SecretError::Backend(other.to_string()),
    }
}

impl SecretStore for KeychainStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        if value.len() > WINDOWS_BLOB_LIMIT {
            return Err(SecretError::TooLong { limit: WINDOWS_BLOB_LIMIT });
        }
        self.entry(key)?.set_secret(value).map_err(map_err)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        match self.entry(key)?.get_secret() {
            Ok(v) => Ok(Some(v)),
            // NoEntry means "absent", not an error. Treating it as one would
            // turn an ordinary cache miss into a hard failure.
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(map_err(e)),
        }
    }

    fn describe(&self) -> String {
        format!("OS keychain ({})", self.vendor)
    }
}
