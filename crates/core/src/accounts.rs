//! Account metadata store. Holds the labels, emails, and sort order needed to
//! display several Claude accounts side by side. **Tokens never live here** —
//! the `secrets` module owns those.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Account metadata. **Tokens never live here** — `secrets` owns those.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Primary key. `account.uuid` from the OAuth token response.
    pub uuid: String,
    /// User-editable display name.
    pub display_label: String,
    /// Display only. **Never used as a key.**
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub last_ok_at: Option<DateTime<Utc>>,
    /// Whether the account was quarantined by the one-strike invalid_grant rule.
    /// See docs/design.md §7.2.
    pub quarantined: bool,
    pub sort_order: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("account file I/O error: {0}")]
    Io(String),
    #[error("account file parse error: {0}")]
    Parse(String),
}

/// A single-owner handle to one account metadata file.
///
/// **Two simultaneously open instances are not safe.** `flush` rewrites the
/// whole in-memory list over the file via rename; it takes no lock and does not
/// re-read and merge before writing. If two `AccountStore` values pointing at
/// the same path write at nearly the same time (for example, the settings
/// window and the scheduler each holding their own instance), whichever
/// flushes last silently discards the other's changes wholesale. The file is
/// never torn — the temp path is random on every write, so that part is safe —
/// but one side's most recent update can vanish. This type does not decide the
/// locking or merge strategy: if several instances are needed, the caller must
/// either funnel access through a single owner or design that strategy
/// separately.
pub struct AccountStore {
    path: PathBuf,
    accounts: Vec<Account>,
}

impl AccountStore {
    pub fn load(path: &Path) -> Result<Self, AccountError> {
        let accounts = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| AccountError::Parse(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(AccountError::Io(e.to_string())),
        };
        let mut s = Self { path: path.to_path_buf(), accounts };
        s.accounts.sort_by_key(|a| a.sort_order);
        Ok(s)
    }

    pub fn list(&self) -> &[Account] {
        &self.accounts
    }

    /// Update by uuid, or append if it is new.
    pub fn upsert(&mut self, mut account: Account) -> Result<(), AccountError> {
        match self.accounts.iter().position(|a| a.uuid == account.uuid) {
            Some(i) => {
                account.sort_order = self.accounts[i].sort_order;
                self.accounts[i] = account;
            }
            None => {
                account.sort_order = self.accounts.len() as u32;
                self.accounts.push(account);
            }
        }
        self.flush()
    }

    pub fn remove(&mut self, uuid: &str) -> Result<bool, AccountError> {
        let before = self.accounts.len();
        self.accounts.retain(|a| a.uuid != uuid);
        let removed = self.accounts.len() != before;
        if removed {
            for (i, a) in self.accounts.iter_mut().enumerate() {
                a.sort_order = i as u32;
            }
            self.flush()?;
        }
        Ok(removed)
    }

    /// Reorder to match the given uuid sequence. Unknown uuids are ignored, and
    /// accounts missing from the argument are appended afterwards in their
    /// original order.
    pub fn reorder(&mut self, uuids: &[String]) -> Result<(), AccountError> {
        let mut ordered: Vec<Account> = Vec::with_capacity(self.accounts.len());
        for id in uuids {
            if let Some(i) = self.accounts.iter().position(|a| &a.uuid == id) {
                ordered.push(self.accounts.remove(i));
            }
        }
        ordered.append(&mut self.accounts);
        for (i, a) in ordered.iter_mut().enumerate() {
            a.sort_order = i as u32;
        }
        self.accounts = ordered;
        self.flush()
    }

    /// Build a fresh random temp path on every write. Sharing one fixed name
    /// (`.with_extension("tmp")`) lets two writers of the same file truncate and
    /// interleave into each other's temp file, and the torn result then lands on
    /// top of the original via the final rename. (Same pattern as
    /// `random_tmp_path` in `secrets::encrypted_file`.)
    fn random_tmp_path(&self) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        rand::fill(&mut rand_bytes[..]);
        let hex: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!(".tmp.{}.{n}.{hex}", std::process::id()));
        PathBuf::from(name)
    }

    fn flush(&mut self) -> Result<(), AccountError> {
        let text = serde_json::to_string_pretty(&self.accounts)
            .map_err(|e| AccountError::Parse(e.to_string()))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| AccountError::Io(e.to_string()))?;
        }
        let tmp = self.random_tmp_path();
        write_text_then_rename(&tmp, &text, &self.path)
    }
}

/// Write to a temp file, fsync it, then rename — so a crash partway through
/// leaves the existing file intact. Because the temp name is random per call
/// (`random_tmp_path`), no later write will ever reuse that name and clean up
/// after a failed one, unlike with a fixed name — so every failure path removes
/// it here explicitly. Otherwise orphaned temp files would pile up in exactly
/// the situation that produces repeated failures, such as a full disk. (Same
/// pattern as `secrets::encrypted_file::write_bytes_then_rename`.)
fn write_text_then_rename(tmp: &Path, text: &str, dest: &Path) -> Result<(), AccountError> {
    let write_result = std::fs::File::create(tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
        .map_err(|e| AccountError::Io(e.to_string()));
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(tmp, dest) {
        let _ = std::fs::remove_file(tmp);
        return Err(AccountError::Io(e.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a unique path on every call. A pid alone would collide across
    /// every test, since the harness runs them as threads in one process — the
    /// classic source of flaky filesystem tests. A counter plus random bytes
    /// removes the collision.
    fn tmp() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        rand::fill(&mut rand_bytes[..]);
        let hex: String = rand_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut p = std::env::temp_dir();
        p.push(format!("quota-accounts-{}-{n}-{hex}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn acc(uuid: &str, label: &str) -> Account {
        Account {
            uuid: uuid.into(),
            display_label: label.into(),
            email: format!("{label}@example.com"),
            created_at: Utc::now(),
            last_ok_at: None,
            quarantined: false,
            sort_order: 0,
        }
    }

    #[test]
    fn survives_a_reload_from_disk() {
        let path = tmp();
        {
            let mut s = AccountStore::load(&path).unwrap();
            s.upsert(acc("uuid-a", "work")).unwrap();
            s.upsert(acc("uuid-b", "personal")).unwrap();
        }
        let s = AccountStore::load(&path).unwrap();
        assert_eq!(s.list().len(), 2);
        std::fs::remove_file(&path).ok();
    }

    /// docs/design.md §9.3: the primary key is the uuid. Re-registering the same
    /// uuid is an update, not a duplicate.
    #[test]
    fn upsert_by_uuid_replaces_rather_than_duplicates() {
        let path = tmp();
        let mut s = AccountStore::load(&path).unwrap();
        s.upsert(acc("uuid-a", "work")).unwrap();
        let mut updated = acc("uuid-a", "work-renamed");
        updated.email = "changed@example.com".into();
        s.upsert(updated).unwrap();
        assert_eq!(s.list().len(), 1, "the same uuid must collapse to one entry");
        assert_eq!(s.list()[0].display_label, "work-renamed");
        std::fs::remove_file(&path).ok();
    }

    /// The same email with different uuids means two separate accounts.
    /// Keying by email would make one of them disappear here.
    #[test]
    fn same_email_different_uuid_stays_two_accounts() {
        let path = tmp();
        let mut s = AccountStore::load(&path).unwrap();
        let mut a = acc("uuid-a", "one");
        let mut b = acc("uuid-b", "two");
        a.email = "same@example.com".into();
        b.email = "same@example.com".into();
        s.upsert(a).unwrap();
        s.upsert(b).unwrap();
        assert_eq!(s.list().len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_is_ordered_by_sort_order() {
        let path = tmp();
        let mut s = AccountStore::load(&path).unwrap();
        s.upsert(acc("uuid-a", "a")).unwrap();
        s.upsert(acc("uuid-b", "b")).unwrap();
        s.upsert(acc("uuid-c", "c")).unwrap();
        s.reorder(&["uuid-c".into(), "uuid-a".into(), "uuid-b".into()]).unwrap();
        let ids: Vec<_> = s.list().iter().map(|a| a.uuid.clone()).collect();
        assert_eq!(ids, vec!["uuid-c", "uuid-a", "uuid-b"]);

        // Check that the order survives a round trip through disk.
        drop(s);
        let s = AccountStore::load(&path).unwrap();
        let ids: Vec<_> = s.list().iter().map(|a| a.uuid.clone()).collect();
        assert_eq!(ids, vec!["uuid-c", "uuid-a", "uuid-b"], "order must survive a restart");

        std::fs::remove_file(&path).ok();
    }

    /// Pin down that `load()` re-sorts by `sort_order` rather than trusting the
    /// array order. Files written through the store's own API are always
    /// already sorted, so they cannot distinguish the two behaviors — hence
    /// writing JSON directly whose array order disagrees with `sort_order`.
    #[test]
    fn load_sorts_by_sort_order_not_array_order() {
        let path = tmp();
        // Array order is [a, b, c] while sort_order is [2, 0, 1].
        let mut a = acc("uuid-a", "a");
        a.sort_order = 2;
        let mut b = acc("uuid-b", "b");
        b.sort_order = 0;
        let mut c = acc("uuid-c", "c");
        c.sort_order = 1;
        std::fs::write(&path, serde_json::to_string_pretty(&vec![a, b, c]).unwrap()).unwrap();

        let s = AccountStore::load(&path).unwrap();
        let ids: Vec<_> = s.list().iter().map(|x| x.uuid.clone()).collect();
        assert_eq!(ids, vec!["uuid-b", "uuid-c", "uuid-a"], "load() must sort by sort_order");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_returns_whether_it_existed() {
        let path = tmp();
        let mut s = AccountStore::load(&path).unwrap();
        s.upsert(acc("uuid-a", "a")).unwrap();
        assert!(s.remove("uuid-a").unwrap());
        assert!(!s.remove("uuid-a").unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_starts_empty() {
        let path = tmp();
        let s = AccountStore::load(&path).unwrap();
        assert!(s.list().is_empty());
    }

    /// No token may ever reach the metadata file. docs/design.md §9.3.
    #[test]
    fn serialized_form_has_no_token_fields() {
        let path = tmp();
        let mut s = AccountStore::load(&path).unwrap();
        s.upsert(acc("uuid-a", "a")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for forbidden in ["access_token", "refresh_token", "Bearer"] {
            assert!(!text.contains(forbidden), "metadata contains {forbidden}");
        }
        std::fs::remove_file(&path).ok();
    }
}
