//! Encrypted-file fallback token store, for headless environments and machines
//! with no keychain (docs/design.md §9.2). The file layout and locking strategy
//! are documented on the `EncryptedFileStore` type.
//!
//! ## Known limitation: no cross-process write serialization on Windows
//!
//! `acquire_lock` implements a cross-process exclusive lock over the store using
//! `flock(2)` on Unix, but is a no-op on Windows. As a result, on Windows two
//! different processes (for example, the app launched twice) calling `put` at
//! nearly the same time can each do a read-merge-write, and whichever finishes
//! its rename last silently erases the other's update — I5 ("two instances lose
//! each other's writes") still reproduces on Windows. The file itself is never
//! torn or corrupted (random temp names + `create_new` + atomic rename are safe
//! on every platform); only one side's most recent update is lost. A Windows
//! file lock (`LockFileEx` or similar) is not implemented yet and is left as a
//! known, tracked gap — the primary target here is the headless Linux fallback.

use super::{SecretError, SecretStore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// File magic bytes. Missing or different means this is not our format, or it
/// is badly corrupted.
const MAGIC: [u8; 4] = *b"QBE1";
/// File layout version. Raise this whenever the layout changes, and handle the
/// older versions too.
const FORMAT_VERSION: u8 = 1;
/// `[MAGIC(4)][FORMAT_VERSION(1)][m_cost(4)][t_cost(4)][p_cost(4)]` — all little endian.
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4;

/// Accepted range for the Argon2 parameters read from the header. Values
/// outside it are treated as corrupted or tampered with — not as "different but
/// legitimate parameters" — and rejected **before they reach the KDF**.
///
/// Without this check: `m_cost` is a `u32` in KiB with no upper bound, and
/// `hash_password_into` unconditionally allocates
/// `vec![Block::default(); block count derived from m_cost]` internally.
/// Planting `m_cost = u32::MAX` turns into a terabyte-scale allocation request,
/// and the process dies with SIGABRT rather than returning a `SecretError`
/// (measured: exit 134, "memory allocation ... failed"). Flipping a single bit
/// in the file's eighth byte is enough to take that path.
const MIN_ACCEPTED_M_COST: u32 = 8 * 1024; // below 8 MiB is meaningless as a KDF
const MAX_ACCEPTED_M_COST: u32 = 1024 * 1024; // 1 GiB — room to raise later, but bounded
const MIN_ACCEPTED_T_COST: u32 = 1;
const MAX_ACCEPTED_T_COST: u32 = 10;
const MIN_ACCEPTED_P_COST: u32 = 1;
const MAX_ACCEPTED_P_COST: u32 = 8;

/// File layout: `[header][16-byte salt][24-byte nonce][XChaCha20-Poly1305 ciphertext]`.
/// The plaintext is the JSON serialization of a `HashMap<String, Vec<u8>>`.
///
/// The header records the Argon2 parameters actually used, so that raising the
/// defaults later (increasing the memory cost, say) does not orphan existing
/// files — they keep deriving the same key from the values written in the file.
pub struct EncryptedFileStore {
    path: PathBuf,
    key: [u8; 32],
    salt: [u8; SALT_LEN],
    params: KdfParams,
    map: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    /// The current defaults, used when creating a new store.
    /// This file holds long-lived secrets such as refresh tokens in a location
    /// that also ends up in backups and snapshots, so the parameters are set
    /// above OWASP's "constrained server" minimum (m=19MiB, t=2).
    const CURRENT: KdfParams = KdfParams { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 };

    fn to_argon2_params(self) -> Result<argon2::Params, SecretError> {
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, None)
            .map_err(|e| SecretError::Backend(format!("invalid Argon2 parameters: {e}")))
    }
}

fn derive_key(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<[u8; 32], SecretError> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.to_argon2_params()?,
    );
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SecretError::Backend(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn encode_header(params: KdfParams) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&MAGIC);
    h[4] = FORMAT_VERSION;
    h[5..9].copy_from_slice(&params.m_cost.to_le_bytes());
    h[9..13].copy_from_slice(&params.t_cost.to_le_bytes());
    h[13..17].copy_from_slice(&params.p_cost.to_le_bytes());
    h
}

struct ParsedFile<'a> {
    /// The raw header bytes — passed to the AEAD as AAD so the header itself is
    /// authenticated against tampering.
    header: &'a [u8],
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

fn parse_file(bytes: &[u8]) -> Result<ParsedFile<'_>, SecretError> {
    if bytes.len() < HEADER_LEN + SALT_LEN + NONCE_LEN {
        return Err(SecretError::Backend("store file is corrupt (too short)".into()));
    }
    if bytes[0..4] != MAGIC {
        return Err(SecretError::Backend("not a store file (magic byte mismatch)".into()));
    }
    let version = bytes[4];
    if version != FORMAT_VERSION {
        return Err(SecretError::Backend(format!("unsupported store format version: {version}")));
    }
    let m_cost = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
    let t_cost = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
    let p_cost = u32::from_le_bytes(bytes[13..17].try_into().unwrap());

    // NB1: this filter is mandatory — if these values reach Argon2 unvalidated,
    // one corrupted or tampered file can abort the whole process (see the
    // constant documentation above).
    if !(MIN_ACCEPTED_M_COST..=MAX_ACCEPTED_M_COST).contains(&m_cost)
        || !(MIN_ACCEPTED_T_COST..=MAX_ACCEPTED_T_COST).contains(&t_cost)
        || !(MIN_ACCEPTED_P_COST..=MAX_ACCEPTED_P_COST).contains(&p_cost)
    {
        return Err(SecretError::Backend(
            "store file KDF parameters are out of the accepted range — corrupt or tampered".into(),
        ));
    }

    let header = &bytes[0..HEADER_LEN];
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[HEADER_LEN..HEADER_LEN + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[HEADER_LEN + SALT_LEN..HEADER_LEN + SALT_LEN + NONCE_LEN]);
    let ciphertext = &bytes[HEADER_LEN + SALT_LEN + NONCE_LEN..];

    Ok(ParsedFile { header, params: KdfParams { m_cost, t_cost, p_cost }, salt, nonce, ciphertext })
}

/// Encrypt with `aad` (the header bytes) bound in as AAD. The header is not
/// itself encrypted, but binding it this way means touching it breaks
/// authentication. Rather than relying on the side effect that m/t/p happen to
/// feed key derivation, this builds header tamper-detection explicitly into the
/// cryptographic construction.
fn encrypt_payload(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), SecretError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes[..]);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(nonce, Payload { msg: plain, aad })
        .map_err(|e| SecretError::Backend(format!("encryption failed: {e}")))?;
    Ok((nonce_bytes, ct))
}

/// A decryption/authentication failure means either a wrong passphrase or a
/// corrupted/tampered store file — an AEAD cannot distinguish the two, so the
/// message acknowledges both. Either way, proceeding with an empty map would
/// overwrite the tokens, so we never do that.
fn decrypt_payload(
    key: &[u8; 32],
    aad: &[u8],
    nonce_bytes: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SecretError> {
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| SecretError::Locked("passphrase does not match, or the store file is corrupt or tampered".into()))
}

fn build_record(params: KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&encode_header(params));
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

fn read_raw(path: &Path) -> Result<Option<Vec<u8>>, SecretError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SecretError::Backend(e.to_string())),
    }
}

/// Never put the original error (`{e}`) into a JSON parse failure message —
/// serde embeds the value that failed to parse in its error, so a decrypted
/// token could leak through the error message into logs or the UI. Use a static
/// message only.
fn parse_map(plain: &[u8]) -> Result<HashMap<String, Vec<u8>>, SecretError> {
    serde_json::from_slice(plain)
        .map_err(|_| SecretError::Backend("failed to parse the store (corrupt format or unsupported version)".into()))
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(unix)]
struct FileLock {
    // Never read, but dropping it closes the fd, which releases the flock —
    // an RAII guard.
    _file: std::fs::File,
}

/// Blockingly acquire an exclusive lock over the store. The lock is held until
/// the returned value goes out of scope and is dropped, at which point the OS
/// releases it automatically (closing the file descriptor releases the flock).
///
/// The lock is taken on a separate `<path>.lock` file rather than on the store
/// file itself because every write replaces the store file via rename: locking
/// the store file would not carry over, since the file opened after a rename is
/// a different inode. The dedicated lock file is never renamed, so its inode is
/// stable.
#[cfg(unix)]
fn acquire_lock(lock_path: &Path) -> Result<FileLock, SecretError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false) // Nothing is ever written here — it only exists to be flocked.
        .mode(0o600)
        .open(lock_path)
        .map_err(|e| SecretError::Backend(format!("failed to open the lock file: {e}")))?;
    // Exclusive blocking flock — wait until another process's read-modify-write finishes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(SecretError::Backend(format!("failed to acquire the lock: {}", std::io::Error::last_os_error())));
    }
    Ok(FileLock { _file: file })
}

#[cfg(not(unix))]
struct FileLock;

#[cfg(not(unix))]
fn acquire_lock(_lock_path: &Path) -> Result<FileLock, SecretError> {
    // Windows: within a single process the Mutex around `map` plus the
    // read-modify-write ordering give some protection, but there is no
    // cross-process serialization yet — the flock-based lock is implemented for
    // Unix only, since the headless Linux fallback (docs/design.md §9.2) is the
    // primary target.
    Ok(FileLock)
}

#[cfg(unix)]
fn create_restricted_file(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn create_restricted_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

impl EncryptedFileStore {
    pub fn open(path: &Path, passphrase: &str) -> Result<Self, SecretError> {
        match read_raw(path)? {
            None => {
                // A new store. Start with a fresh salt and the current default
                // KDF parameters. Nothing is written to disk yet — the file
                // appears on the first `put`.
                let mut salt = [0u8; SALT_LEN];
                rand::fill(&mut salt[..]);
                let params = KdfParams::CURRENT;
                let key = derive_key(passphrase, &salt, params)?;
                Ok(Self { path: path.to_path_buf(), key, salt, params, map: Mutex::new(HashMap::new()) })
            }
            Some(bytes) => {
                let parsed = parse_file(&bytes)?;
                // Derive using the parameters written in the file's header, so
                // existing files keep opening after the defaults change.
                let key = derive_key(passphrase, &parsed.salt, parsed.params)?;
                let plain = decrypt_payload(&key, parsed.header, &parsed.nonce, parsed.ciphertext)?;
                let map = parse_map(&plain)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    key,
                    salt: parsed.salt,
                    params: parsed.params,
                    map: Mutex::new(map),
                })
            }
        }
    }

    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Build a fresh random temp path on every write — sharing one fixed name
    /// lets concurrent writes fight over the same path, tearing the file or
    /// having renames displace one another.
    fn random_tmp_path(&self) -> PathBuf {
        let mut rand_bytes = [0u8; 8];
        rand::fill(&mut rand_bytes[..]);
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".tmp.{}.{}", std::process::id(), to_hex(&rand_bytes)));
        PathBuf::from(name)
    }

    /// Re-read the latest contents from disk while holding the lock, so that our
    /// possibly stale in-memory snapshot does not overwrite what another process
    /// wrote in the meantime.
    fn read_current(&self) -> Result<HashMap<String, Vec<u8>>, SecretError> {
        match read_raw(&self.path)? {
            None => Ok(HashMap::new()),
            Some(bytes) => {
                let parsed = parse_file(&bytes)?;
                if parsed.salt != self.salt {
                    // We collided with a store recreated under a different salt.
                    // There is no way to reconcile that with this passphrase, so
                    // fail loudly rather than overwrite.
                    return Err(SecretError::Backend(
                        "the store on disk was created with a different salt — conflict with another process".into(),
                    ));
                }
                let plain = decrypt_payload(&self.key, parsed.header, &parsed.nonce, parsed.ciphertext)?;
                parse_map(&plain)
            }
        }
    }

    fn encode_plain(&self, plain: &[u8]) -> Result<Vec<u8>, SecretError> {
        let header = encode_header(self.params);
        let (nonce_bytes, ciphertext) = encrypt_payload(&self.key, &header, plain)?;
        Ok(build_record(self.params, &self.salt, &nonce_bytes, &ciphertext))
    }

    /// Write to a temp file and rename — a crash partway through leaves the
    /// existing file intact. The temp name is random per call and created with
    /// `create_new`, so concurrent writes never fight over the same path.
    /// Creating it with `mode(0o600)` means there is no world-readable window at
    /// all — it is born with those permissions rather than chmodded afterwards.
    fn write_atomic(&self, map: &HashMap<String, Vec<u8>>) -> Result<(), SecretError> {
        let plain = serde_json::to_vec(map).map_err(|e| SecretError::Backend(e.to_string()))?;
        let bytes = self.encode_plain(&plain)?;

        const MAX_ATTEMPTS: u32 = 8;
        let mut last_err: Option<std::io::Error> = None;
        for _ in 0..MAX_ATTEMPTS {
            let tmp = self.random_tmp_path();
            match create_restricted_file(&tmp) {
                Ok(f) => return write_bytes_then_rename(f, &tmp, &bytes, &self.path),
                // Random name collision (all but impossible) — retry with fresh randomness.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(SecretError::Backend(format!("failed to create the temp file: {e}"))),
            }
        }
        Err(SecretError::Backend(format!(
            "failed to create the temp file (retries exhausted): {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}

/// If any of `write_all`, `sync_all`, or `rename` fails, remove the temp file
/// and return the error. Omitting this (NB2) would leave a failed write's 0600
/// file on disk holding a complete copy of the ciphertext — and because the temp
/// name is random in this design, no later write would ever reuse that name and
/// clean it up.
fn write_bytes_then_rename(
    mut tmp_file: std::fs::File,
    tmp_path: &Path,
    bytes: &[u8],
    dest: &Path,
) -> Result<(), SecretError> {
    let write_result = tmp_file
        .write_all(bytes)
        .and_then(|()| tmp_file.sync_all())
        .map_err(|e| SecretError::Backend(e.to_string()));
    drop(tmp_file);
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(tmp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(tmp_path, dest) {
        let _ = std::fs::remove_file(tmp_path);
        return Err(SecretError::Backend(e.to_string()));
    }
    Ok(())
}

impl SecretStore for EncryptedFileStore {
    fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
        let _lock = acquire_lock(&self.lock_path())?;
        let mut current = self.read_current()?;
        current.insert(key.to_string(), value.to_vec());
        self.write_atomic(&current)?;
        *self.map.lock().unwrap() = current;
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
        Ok(self.map.lock().unwrap().get(key).cloned())
    }
    fn delete(&self, key: &str) -> Result<bool, SecretError> {
        let _lock = acquire_lock(&self.lock_path())?;
        let mut current = self.read_current()?;
        let existed = current.remove(key).is_some();
        if existed {
            self.write_atomic(&current)?;
        }
        *self.map.lock().unwrap() = current;
        Ok(existed)
    }
    fn describe(&self) -> String {
        "encrypted file (passphrase)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::SecretStore;

    /// Produce a unique path on every call. A pid alone would collide across
    /// tests running in parallel — the source of a flake caught in review. A
    /// counter plus random bytes removes the collision.
    fn tmp() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        rand::fill(&mut rand_bytes[..]);
        let mut p = std::env::temp_dir();
        p.push(format!("quota-test-{}-{n}-{}.enc", std::process::id(), to_hex(&rand_bytes)));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        if haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn round_trips_through_disk() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "hunter2").unwrap();
            s.put("uuid-1:refresh", b"secret-token").unwrap();
        }
        // A fresh instance actually decrypts and reads from disk.
        let s = EncryptedFileStore::open(&path, "hunter2").unwrap();
        assert_eq!(s.get("uuid-1:refresh").unwrap().as_deref(), Some(&b"secret-token"[..]));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_passphrase_is_rejected_not_silently_empty() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "correct").unwrap();
            s.put("k", b"v").unwrap();
        }
        match EncryptedFileStore::open(&path, "wrong") {
            Err(SecretError::Locked(_)) => {}
            Ok(_) => panic!("a wrong passphrase was accepted — appearing as an empty store overwrites the tokens"),
            Err(e) => panic!("expected Locked, got {e}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_on_disk_does_not_contain_the_plaintext() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"SUPER-SECRET-TOKEN").unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(18).any(|w| w == b"SUPER-SECRET-TOKEN"),
            "the plaintext appears verbatim in the file"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_starts_empty() {
        let path = tmp();
        let s = EncryptedFileStore::open(&path, "pw").unwrap();
        assert_eq!(s.get("anything").unwrap(), None);
        std::fs::remove_file(&path).ok();
    }

    /// I7: `file_on_disk_does_not_contain_the_plaintext` above passes even with
    /// the encryption removed, because serde_json encodes `Vec<u8>` as an array
    /// of numbers — it proves nothing. This test instead computes the exact byte
    /// sequence that would appear in the file if there were no encryption, and
    /// checks it is absent. Replacing the encryption with the identity function
    /// makes this test fail.
    #[test]
    fn ciphertext_differs_from_the_serialized_plaintext() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"SUPER-SECRET-TOKEN").unwrap();
        }
        let on_disk = std::fs::read(&path).unwrap();

        let mut plain_map = HashMap::new();
        plain_map.insert("k".to_string(), b"SUPER-SECRET-TOKEN".to_vec());
        let plain_json = serde_json::to_vec(&plain_map).unwrap();

        assert!(
            !contains_subsequence(&on_disk, &plain_json),
            "the serialized plaintext JSON appears verbatim in the file — equivalent to no encryption"
        );
        std::fs::remove_file(&path).ok();
    }

    /// I3: `File::create` is born with `0o666 & ~umask` and the chmod only
    /// arrives after the write completes — leaving a window in which another
    /// local user could read the ciphertext.
    ///
    /// Round-2 note on this test: it originally inspected only the final mode
    /// *after* `put()` returned, which the old "create first, chmod later" code
    /// also passed (it did end at 0600), so it proved nothing. It now calls
    /// `create_restricted_file` — the function actually used for writes —
    /// directly and inspects the mode immediately after creation, before
    /// `write_all` is even called. Under the old code that moment would have
    /// been `0o666 & ~umask` (typically 0664), so this test really does catch
    /// that bug.
    #[cfg(unix)]
    #[test]
    fn store_file_is_created_owner_only_from_the_start() {
        use std::os::unix::fs::PermissionsExt;

        let probe_path = tmp();
        let f = create_restricted_file(&probe_path).unwrap();
        let mode_before_any_write = f.metadata().unwrap().permissions().mode() & 0o777;
        drop(f);
        std::fs::remove_file(&probe_path).ok();
        assert_eq!(
            mode_before_any_write, 0o600,
            "the temp file must be owner-only from the instant it is created, before any write — \
             chmodding after the write leaves a world-readable window in between"
        );

        // Also run the real store path end to end and re-check the final mode.
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"v").unwrap();
        }
        let final_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(final_mode, 0o600, "the store file did not end up owner-only");
        std::fs::remove_file(&path).ok();
    }

    /// I4: the header must carry the magic bytes and the KDF parameters actually
    /// used, so existing files keep opening after the defaults are raised.
    #[test]
    fn file_header_carries_magic_and_the_kdf_params_actually_used() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"v").unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[0..4], &MAGIC, "without magic bytes, future format changes are indistinguishable");
        assert_eq!(bytes[4], FORMAT_VERSION);
        let m_cost = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
        let t_cost = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
        assert_eq!(m_cost, KdfParams::CURRENT.m_cost, "the header must record the m_cost actually used");
        assert_eq!(t_cost, KdfParams::CURRENT.t_cost, "the header must record the t_cost actually used");
        std::fs::remove_file(&path).ok();
    }

    /// I4: an unknown format version must fail loudly rather than quietly
    /// degrading to an empty store.
    #[test]
    fn unsupported_format_version_is_rejected_not_silently_empty() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"v").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[4] = 0xFF; // a format version that does not exist
        std::fs::write(&path, &bytes).unwrap();

        match EncryptedFileStore::open(&path, "pw") {
            Err(_) => {}
            Ok(_) => panic!("an unknown format version was accepted — corruption goes undetected"),
        }
        std::fs::remove_file(&path).ok();
    }

    /// NB1: the header's `m_cost` is an unbounded `u32`, and passing it to Argon2
    /// unvalidated makes `hash_password_into` allocate memory blocks from that
    /// value directly — planting `u32::MAX` becomes a terabyte-scale allocation
    /// request and the process dies with SIGABRT instead of returning a
    /// `SecretError` (measured in review: "memory allocation of 4398046507008
    /// bytes failed", exit 134). The fact that this test survives to reach `Err`
    /// is itself the evidence that `parse_file` filtered it out without aborting
    /// the process.
    #[test]
    fn header_with_absurd_m_cost_is_rejected_without_aborting_the_process() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"v").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[5..9].copy_from_slice(&u32::MAX.to_le_bytes()); // plant it in the m_cost field
        std::fs::write(&path, &bytes).unwrap();

        match EncryptedFileStore::open(&path, "pw") {
            Err(_) => {} // reaching this point at all means we did not abort.
            Ok(_) => panic!("an absurd m_cost (u32::MAX) was accepted"),
        }
        std::fs::remove_file(&path).ok();
    }

    /// NB1: because the header bytes are bound in as AAD, touching the header
    /// must be rejected by AEAD authentication itself — independently of the
    /// incidental fact that it also changes the derived key — even when the
    /// values stay inside the accepted range.
    #[test]
    fn tampered_header_is_rejected_as_tampering_not_silently_opened() {
        let path = tmp();
        {
            let s = EncryptedFileStore::open(&path, "pw").unwrap();
            s.put("k", b"v").unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        // Flip the low byte of t_cost, choosing a value that stays inside the
        // accepted range (1..=10) so the range check alone would not catch it.
        assert_eq!(bytes[9], 3, "test premise: the default t_cost must be 3");
        bytes[9] = 4;
        std::fs::write(&path, &bytes).unwrap();

        match EncryptedFileStore::open(&path, "pw") {
            Err(_) => {}
            Ok(_) => panic!("a file with a tampered header opened under the correct passphrase"),
        }
        std::fs::remove_file(&path).ok();
    }

    /// I4: pin down that the Argon2 parameters really do exceed OWASP's
    /// "constrained server" minimum. This file protects long-lived refresh tokens
    /// that end up in backups, so the minimum is not enough. Comparing constants
    /// makes clippy report "assertion has a constant value", but this is an
    /// intentional regression guard — it catches anyone lowering
    /// `KdfParams::CURRENT` by mistake later.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn kdf_params_exceed_the_owasp_minimum_for_long_lived_tokens() {
        assert!(KdfParams::CURRENT.m_cost >= 64 * 1024, "an m_cost below 64MiB is weak against offline attack");
        assert!(KdfParams::CURRENT.t_cost >= 3, "a t_cost below 3 is weak against offline attack");
    }

    /// I6: when decrypted plaintext fails to parse as JSON, serde's default error
    /// message embeds the value that failed — and if that value is a token, it
    /// leaks through the error into logs or the UI. Verify it was replaced with a
    /// static message.
    #[test]
    fn parse_failure_does_not_leak_the_secret_value_into_the_error() {
        let path = tmp();
        // Nothing on disk yet — this only establishes the salt, key, and params.
        let store = EncryptedFileStore::open(&path, "pw").unwrap();

        // Plant plaintext that is validly encrypted but cannot deserialize into
        // `HashMap<String, Vec<u8>>` (the value is a string, not an array).
        let malformed = br#"{"k":"sk-ant-LEAKED-TOKEN"}"#;
        let bytes = store.encode_plain(malformed).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let err = match EncryptedFileStore::open(&path, "pw") {
            Err(e) => e,
            Ok(_) => panic!("malformed plaintext parsed successfully — the test premise is broken"),
        };
        let msg = err.to_string();
        assert!(!msg.contains("LEAKED-TOKEN"), "the parse error message exposed the secret value: {msg}");
        std::fs::remove_file(&path).ok();
    }

    /// I5: when A and B each open the same file and write different keys, the
    /// later writer must not erase the earlier one's change wholesale. It has to
    /// re-read the disk under the lock and merge.
    #[cfg(unix)]
    #[test]
    fn two_instances_do_not_lose_each_others_writes() {
        let path = tmp();
        {
            // The file must exist first so both instances share one salt
            // (avoiding a bootstrap race).
            let seed = EncryptedFileStore::open(&path, "pw").unwrap();
            seed.put("seed", b"x").unwrap();
        }
        let a = EncryptedFileStore::open(&path, "pw").unwrap();
        let b = EncryptedFileStore::open(&path, "pw").unwrap();
        a.put("from-a", b"a-value").unwrap();
        b.put("from-b", b"b-value").unwrap();

        let reopened = EncryptedFileStore::open(&path, "pw").unwrap();
        assert_eq!(
            reopened.get("from-a").unwrap().as_deref(),
            Some(&b"a-value"[..]),
            "A's write was overwritten and lost by B's"
        );
        assert_eq!(
            reopened.get("from-b").unwrap().as_deref(),
            Some(&b"b-value"[..]),
            "B's write was lost"
        );
        std::fs::remove_file(&path).ok();
    }

    /// C1: sharing one fixed temp file name across writes (without a lock) tears
    /// the file or has renames displace one another. Even with many threads
    /// hammering `put` on the same path, the file must end up uncorrupted with
    /// every key intact.
    #[cfg(unix)]
    #[test]
    fn concurrent_writes_across_threads_do_not_corrupt_the_file() {
        let path = tmp();
        {
            let seed = EncryptedFileStore::open(&path, "pw").unwrap();
            seed.put("seed", b"seed-value").unwrap();
        }

        const THREADS: usize = 8;
        const PER_THREAD: usize = 20;
        let mut handles = Vec::with_capacity(THREADS);
        for i in 0..THREADS {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let s = EncryptedFileStore::open(&path, "pw").unwrap();
                for j in 0..PER_THREAD {
                    s.put(&format!("k-{i}-{j}"), b"v").unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        // If the file had been torn, decryption itself would fail here.
        let s = EncryptedFileStore::open(&path, "pw").unwrap();
        assert_eq!(s.get("seed").unwrap().as_deref(), Some(&b"seed-value"[..]));
        for i in 0..THREADS {
            for j in 0..PER_THREAD {
                assert_eq!(
                    s.get(&format!("k-{i}-{j}")).unwrap().as_deref(),
                    Some(&b"v"[..]),
                    "a key was lost during concurrent writes — read-modify-write did not merge"
                );
            }
        }
        std::fs::remove_file(&path).ok();
    }
}
