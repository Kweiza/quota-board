//! Account metadata store. Holds the labels, emails, providers, and sort order
//! needed to display several Claude and Codex accounts side by side.
//! **Tokens never live here** — the `secrets` module owns those.

use crate::provider::Provider;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Account metadata. **Tokens never live here** — `secrets` owns those.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// The provider's own account identifier, and half of the primary key.
    ///
    /// **Serialized as `uuid`, which it is not.** Anthropic issues a UUID here;
    /// Codex issues `user-…` (measured, Spike F). The Rust name was corrected
    /// and the wire name deliberately was not: renaming the on-disk key would
    /// make a downgraded build fail to parse the file, and `AccountStore::load`
    /// answers an unparseable file by serving an empty list and refusing every
    /// write — the user is told their accounts could not be read.
    #[serde(rename = "uuid")]
    pub account_id: String,
    /// The other half of the primary key. Absent from files written before this
    /// field existed, which is exactly what `Provider`'s `Default` covers.
    #[serde(default)]
    pub provider: Provider,
    /// OpenAI's `chatgpt_account_id`: the workspace whose quota this login
    /// reads. It is request context, not the account key — two different users
    /// can hold seats in the same workspace.
    ///
    /// Absent for Anthropic and from every file written before Codex support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
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
    /// The file on disk could not be read, so this store is serving an empty
    /// list and **refuses to write**. Returned by every mutating call.
    #[error("the account file could not be read, so it is not being written: {0}")]
    Unreadable(String),
    /// The v1 key is `(provider, user_id)`, so it cannot store two workspace
    /// grants for one OpenAI user without silently overwriting one.
    #[error("this OpenAI user is already stored for a different workspace")]
    WorkspaceConflict,
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
    /// Set when the file exists but could not be read. While it is set the
    /// store serves an empty list and refuses to write, the same shape
    /// `SettingsStore` uses for a file it cannot interpret.
    unreadable: Option<String>,
}

impl AccountStore {
    /// **Infallible on purpose**, like `SettingsStore::load`. This used to
    /// return `Err` for an unparseable file, `main.rs`'s `setup()` propagated
    /// it, and the process aborted before any window existed — measured, exit
    /// 134 with `panic in a function that cannot unwind`. With a transparent
    /// undecorated widget and no Dock icon, one malformed byte in this file
    /// made the application launch into nothing, with no way for the user to
    /// learn why.
    ///
    /// A file that cannot be read yields an empty list **and** a warning, and
    /// the store then refuses every write. Serving the empty list without that
    /// refusal would be worse than the crash: `flush` rewrites the whole file,
    /// so the first successful poll calling `persist_last_ok` would replace the
    /// user's real accounts with the empty list this degraded to.
    pub fn load(path: &Path) -> Self {
        let (accounts, unreadable) = match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<Vec<Account>>(&text) {
                Ok(list) => (list, None),
                Err(e) => (Vec::new(), Some(format!("it is not valid account JSON ({e})"))),
            },
            // No file yet is the ordinary first run, not a problem to report.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), None),
            Err(e) => (Vec::new(), Some(format!("it could not be opened ({e})"))),
        };
        let mut s = Self { path: path.to_path_buf(), accounts, unreadable };
        s.accounts.sort_by_key(|a| a.sort_order);
        s
    }

    /// Why this store is empty, when it is empty for a reason. `None` on the
    /// ordinary first run — a fresh install must not be shown a problem.
    pub fn warning(&self) -> Option<String> {
        self.unreadable
            .as_ref()
            .map(|why| format!("your saved accounts could not be read, so {why}"))
    }

    pub fn list(&self) -> &[Account] {
        &self.accounts
    }

    /// Check whether `account` can be upserted without changing memory or
    /// disk. Login calls this before it stores a newly issued credential: a
    /// workspace conflict discovered after the keychain write would already
    /// have overwritten the existing workspace's only token, while writing
    /// metadata first would leave a row with no credential if the keychain then
    /// failed. One preflight, with the same rule `upsert` enforces, closes the
    /// only expected refusal before either write begins.
    pub fn validate_upsert(&self, account: &Account) -> Result<(), AccountError> {
        if let Some(existing) = self
            .accounts
            .iter()
            .find(|a| a.account_id == account.account_id && a.provider == account.provider)
        {
            if account.provider == Provider::Openai
                && existing.workspace_id != account.workspace_id
            {
                return Err(AccountError::WorkspaceConflict);
            }
        }
        Ok(())
    }

    /// Update by (provider, account_id), or append if it is new.
    pub fn upsert(&mut self, mut account: Account) -> Result<(), AccountError> {
        self.validate_upsert(&account)?;
        // The pair, not the id alone: two providers may issue the same string,
        // and collapsing them would make adding the second account silently
        // replace the first.
        let existing = self
            .accounts
            .iter()
            .position(|a| a.account_id == account.account_id && a.provider == account.provider);
        match existing {
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

    pub fn remove(&mut self, provider: Provider, account_id: &str) -> Result<bool, AccountError> {
        let before = self.accounts.len();
        self.accounts
            .retain(|a| !(a.account_id == account_id && a.provider == provider));
        let removed = self.accounts.len() != before;
        if removed {
            for (i, a) in self.accounts.iter_mut().enumerate() {
                a.sort_order = i as u32;
            }
            self.flush()?;
        }
        Ok(removed)
    }

    /// Reorder to match the given (provider, account_id) sequence. Unknown keys
    /// are ignored, and accounts missing from the argument are appended
    /// afterwards in their original order.
    pub fn reorder(&mut self, keys: &[(Provider, String)]) -> Result<(), AccountError> {
        let mut ordered: Vec<Account> = Vec::with_capacity(self.accounts.len());
        for (provider, id) in keys {
            if let Some(i) = self
                .accounts
                .iter()
                .position(|a| a.provider == *provider && &a.account_id == id)
            {
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
        // The refusal that makes the degrade in `load` safe rather than
        // destructive. Checked here, not in each caller, because this is the
        // one place that overwrites the file.
        if let Some(why) = &self.unreadable {
            return Err(AccountError::Unreadable(why.clone()));
        }
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
    use crate::provider::Provider;

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

    fn acc(account_id: &str, label: &str) -> Account {
        Account {
            account_id: account_id.into(),
            provider: Provider::Anthropic,
            workspace_id: None,
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
            let mut s = AccountStore::load(&path);
            s.upsert(acc("uuid-a", "work")).unwrap();
            s.upsert(acc("uuid-b", "personal")).unwrap();
        }
        let s = AccountStore::load(&path);
        assert_eq!(s.list().len(), 2);
        std::fs::remove_file(&path).ok();
    }

    /// docs/design.md §9.3: the primary key is the uuid. Re-registering the same
    /// uuid is an update, not a duplicate.
    #[test]
    fn upsert_by_uuid_replaces_rather_than_duplicates() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
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
        let mut s = AccountStore::load(&path);
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
        let mut s = AccountStore::load(&path);
        s.upsert(acc("uuid-a", "a")).unwrap();
        s.upsert(acc("uuid-b", "b")).unwrap();
        s.upsert(acc("uuid-c", "c")).unwrap();
        s.reorder(&[
            (Provider::Anthropic, "uuid-c".into()),
            (Provider::Anthropic, "uuid-a".into()),
            (Provider::Anthropic, "uuid-b".into()),
        ])
        .unwrap();
        let ids: Vec<_> = s.list().iter().map(|a| a.account_id.clone()).collect();
        assert_eq!(ids, vec!["uuid-c", "uuid-a", "uuid-b"]);

        // Check that the order survives a round trip through disk.
        drop(s);
        let s = AccountStore::load(&path);
        let ids: Vec<_> = s.list().iter().map(|a| a.account_id.clone()).collect();
        assert_eq!(ids, vec!["uuid-c", "uuid-a", "uuid-b"], "order must survive a restart");

        std::fs::remove_file(&path).ok();
    }

    /// **Reproduced before this was fixed**: a truncated `accounts.json` made
    /// `load` return `Err`, `main.rs`'s `setup()` propagated it, and the process
    /// aborted with exit 134 — `panic in a function that cannot unwind`. The
    /// widget is transparent and undecorated and the app has no Dock icon, so
    /// what the user saw was nothing at all: no window, no dialog, and stderr
    /// going nowhere. One bad byte in this file bricked the application.
    #[test]
    fn an_unreadable_file_degrades_instead_of_failing_to_load() {
        let path = tmp();
        std::fs::write(&path, br#"[{"uuid":"a","display_label":"x""#).unwrap();

        let s = AccountStore::load(&path);
        assert!(s.list().is_empty(), "a file that cannot be parsed is not a list of accounts");
        let w = s.warning().expect("the reason must be reported, not swallowed");
        assert!(w.contains("could not be read"), "unhelpful warning: {w}");
        std::fs::remove_file(&path).ok();
    }

    /// The half that makes the degrade safe. Serving an empty list is only
    /// tolerable while nothing writes it back: `flush` rewrites the whole file,
    /// so one successful poll calling `persist_last_ok` would replace a user's
    /// real accounts with the empty list this store degraded to.
    #[test]
    fn a_degraded_store_refuses_to_write_and_leaves_the_file_alone() {
        let path = tmp();
        let original = br#"[{"uuid":"a","display_label":"x""#;
        std::fs::write(&path, original).unwrap();

        let mut s = AccountStore::load(&path);
        let e = s.upsert(acc("b", "second")).expect_err("a degraded store must refuse to write");
        assert!(matches!(e, AccountError::Unreadable(_)), "wrong error: {e}");

        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "the refused write still changed the file on disk"
        );
        std::fs::remove_file(&path).ok();
    }

    /// A missing file is the ordinary first run, not a problem to report — the
    /// two must not collapse into one state, or every fresh install would show
    /// a scary warning.
    #[test]
    fn a_missing_file_is_not_a_warning() {
        let path = tmp();
        std::fs::remove_file(&path).ok();
        let s = AccountStore::load(&path);
        assert!(s.list().is_empty());
        assert_eq!(s.warning(), None, "a first run reported a problem");
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

        let s = AccountStore::load(&path);
        let ids: Vec<_> = s.list().iter().map(|x| x.account_id.clone()).collect();
        assert_eq!(ids, vec!["uuid-b", "uuid-c", "uuid-a"], "load() must sort by sort_order");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn remove_returns_whether_it_existed() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        s.upsert(acc("uuid-a", "a")).unwrap();
        assert!(s.remove(Provider::Anthropic, "uuid-a").unwrap());
        assert!(!s.remove(Provider::Anthropic, "uuid-a").unwrap());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_starts_empty() {
        let path = tmp();
        let s = AccountStore::load(&path);
        assert!(s.list().is_empty());
    }

    /// No token may ever reach the metadata file. docs/design.md §9.3.
    #[test]
    fn serialized_form_has_no_token_fields() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        s.upsert(acc("uuid-a", "a")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        for forbidden in ["access_token", "refresh_token", "Bearer"] {
            assert!(!text.contains(forbidden), "metadata contains {forbidden}");
        }
        std::fs::remove_file(&path).ok();
    }

    /// An accounts.json written by 0.2.1 has no `provider` field at all. It must
    /// keep loading, as Anthropic — the alternative is `AccountStore::load`
    /// degrading to an empty list and then refusing every write, which is how a
    /// user is told their saved accounts could not be read.
    #[test]
    fn a_file_without_provider_loads_as_anthropic() {
        let path = tmp();
        std::fs::write(
            &path,
            r#"[{"uuid":"acc-1","display_label":"work","email":"w@example.com",
                 "created_at":"2026-07-01T00:00:00Z","last_ok_at":null,
                 "quarantined":false,"sort_order":0}]"#,
        )
        .unwrap();

        let s = AccountStore::load(&path);
        assert_eq!(s.list().len(), 1, "a pre-provider file must still load");
        assert_eq!(s.list()[0].provider, Provider::Anthropic);
        assert_eq!(s.list()[0].account_id, "acc-1");
        std::fs::remove_file(&path).ok();
    }

    /// The on-disk name stays `uuid` even though the Rust field does not. A
    /// downgraded build must not meet a key it has never heard of.
    #[test]
    fn the_on_disk_key_is_still_named_uuid() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        s.upsert(acc("acc-1", "work")).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"uuid\""), "on-disk key changed: {text}");
        assert!(!text.contains("\"account_id\""), "wrote the Rust name: {text}");
        std::fs::remove_file(&path).ok();
    }

    /// The key is (provider, account_id). Two providers may issue the same string
    /// and they are still two accounts.
    #[test]
    fn the_same_id_under_two_providers_stays_two_accounts() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        let mut a = acc("same-id", "claude");
        let mut b = acc("same-id", "codex");
        a.provider = Provider::Anthropic;
        b.provider = Provider::Openai;
        b.workspace_id = Some("workspace-b".into());
        s.upsert(a).unwrap();
        s.upsert(b).unwrap();
        assert_eq!(s.list().len(), 2, "the provider is part of the key");
        std::fs::remove_file(&path).ok();
    }

    /// OpenAI calls the person `user_id` and the quota-bearing workspace
    /// `account_id`. The first is our key; the second is request context. If
    /// the workspace is discarded while loading metadata, a later usage GET
    /// cannot reproduce the account the grant was issued for.
    #[test]
    fn an_openai_workspace_survives_the_metadata_round_trip() {
        let path = tmp();
        std::fs::write(
            &path,
            r#"[{"uuid":"user-one","provider":"openai","workspace_id":"workspace-one",
                 "display_label":"work","email":"w@example.com",
                 "created_at":"2026-09-04T00:00:00Z","last_ok_at":null,
                 "quarantined":false,"sort_order":0}]"#,
        )
        .unwrap();

        let mut s = AccountStore::load(&path);
        assert_eq!(
            s.list().len(),
            1,
            "the workspace field made the file unreadable"
        );
        // Force a write through the real serializer rather than inspecting the
        // input bytes we just planted.
        let account = s.list()[0].clone();
        s.upsert(account).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written[0]["workspace_id"], "workspace-one");
        std::fs::remove_file(&path).ok();
    }

    /// One Codex user authenticated into two workspaces is not two users. The
    /// current store key cannot represent both, so silently accepting the
    /// second login would overwrite the first grant under the same key. Until
    /// the product supports a workspace dimension in its primary key, refuse
    /// the replacement and leave the first row intact.
    #[test]
    fn the_same_openai_user_in_a_different_workspace_is_refused() {
        let path = tmp();
        let first: Account = serde_json::from_value(serde_json::json!({
            "uuid": "user-one", "provider": "openai", "workspace_id": "workspace-one",
            "display_label": "one", "email": "one@example.com",
            "created_at": "2026-09-04T00:00:00Z", "last_ok_at": null,
            "quarantined": false, "sort_order": 0
        }))
        .unwrap();
        let second: Account = serde_json::from_value(serde_json::json!({
            "uuid": "user-one", "provider": "openai", "workspace_id": "workspace-two",
            "display_label": "two", "email": "two@example.com",
            "created_at": "2026-09-04T00:01:00Z", "last_ok_at": null,
            "quarantined": false, "sort_order": 0
        }))
        .unwrap();
        let mut s = AccountStore::load(&path);
        s.upsert(first).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            s.validate_upsert(&second).is_err(),
            "the preflight accepted a login that upsert must refuse"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "validation changed the account file"
        );
        assert!(
            s.upsert(second).is_err(),
            "the second workspace silently replaced the first"
        );
        assert_eq!(s.list().len(), 1);
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("workspace-one"),
            "the first workspace was lost: {written}"
        );
        assert!(
            !written.contains("workspace-two"),
            "the refused workspace reached disk: {written}"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Missing workspace context is not evidence that an existing workspace
    /// disappeared. Letting a re-login with no workspace id replace a
    /// workspace-scoped row would keep the same primary key while silently
    /// changing which quota the bearer reads.
    #[test]
    fn a_missing_workspace_cannot_replace_a_known_openai_workspace() {
        let path = tmp();
        let mut first = acc("user-one", "one");
        first.provider = Provider::Openai;
        first.workspace_id = Some("workspace-one".into());
        let mut incoming = first.clone();
        incoming.workspace_id = None;

        let mut store = AccountStore::load(&path);
        store.upsert(first).unwrap();
        assert!(matches!(
            store.validate_upsert(&incoming),
            Err(AccountError::WorkspaceConflict)
        ));
        assert!(matches!(
            store.upsert(incoming),
            Err(AccountError::WorkspaceConflict)
        ));
        assert_eq!(store.list()[0].workspace_id.as_deref(), Some("workspace-one"));
        std::fs::remove_file(&path).ok();
    }

    /// A workspace is not a user. Two seats in one team share the workspace id
    /// and must remain two rows, keyed by their different user ids.
    #[test]
    fn two_openai_users_in_one_workspace_remain_two_accounts() {
        let path = tmp();
        let make = |user: &str| -> Account {
            serde_json::from_value(serde_json::json!({
                "uuid": user, "provider": "openai", "workspace_id": "workspace-shared",
                "display_label": user, "email": format!("{user}@example.com"),
                "created_at": "2026-09-04T00:00:00Z", "last_ok_at": null,
                "quarantined": false, "sort_order": 0
            }))
            .unwrap()
        };
        let mut s = AccountStore::load(&path);
        s.upsert(make("user-one")).unwrap();
        s.upsert(make("user-two")).unwrap();
        assert_eq!(
            s.list().len(),
            2,
            "the workspace was mistaken for the account key"
        );
        std::fs::remove_file(&path).ok();
    }

    /// The key is (provider, account_id), not the id alone — `remove` must
    /// delete only the pair asked for. Mutating the `&&` in `remove`'s retain
    /// predicate to `||` would delete both accounts here, since the id half
    /// alone matches either one regardless of provider; this is the test that
    /// catches it.
    #[test]
    fn remove_only_deletes_the_matching_provider() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        let mut a = acc("same-id", "claude");
        let mut b = acc("same-id", "codex");
        a.provider = Provider::Anthropic;
        b.provider = Provider::Openai;
        b.workspace_id = Some("workspace-b".into());
        s.upsert(a).unwrap();
        s.upsert(b).unwrap();

        assert!(s.remove(Provider::Anthropic, "same-id").unwrap());
        assert_eq!(s.list().len(), 1, "only the Anthropic account should be gone");
        assert_eq!(
            s.list()[0].provider,
            Provider::Openai,
            "the other provider's account was removed too"
        );
        std::fs::remove_file(&path).ok();
    }

    /// Same premise as `remove_only_deletes_the_matching_provider`, for
    /// `reorder`: it must move the pair asked for, not merely an account whose
    /// id half happens to match. Mutating the `&&` in `reorder`'s `position`
    /// predicate to `||` would move the wrong entry here, because the id alone
    /// matches the first account in insertion order regardless of which
    /// provider was actually requested.
    #[test]
    fn reorder_targets_the_matching_provider_when_ids_collide() {
        let path = tmp();
        let mut s = AccountStore::load(&path);
        let mut a = acc("same-id", "claude");
        let mut b = acc("same-id", "codex");
        a.provider = Provider::Anthropic;
        b.provider = Provider::Openai;
        b.workspace_id = Some("workspace-b".into());
        s.upsert(a).unwrap();
        s.upsert(b).unwrap();

        // Ask for the Openai entry to move first; the Anthropic entry, which
        // shares the id string, must stay behind it rather than being the one
        // that moves.
        s.reorder(&[(Provider::Openai, "same-id".into())]).unwrap();

        let providers: Vec<_> = s.list().iter().map(|a| a.provider).collect();
        assert_eq!(
            providers,
            vec![Provider::Openai, Provider::Anthropic],
            "reorder moved the wrong provider's account"
        );
        std::fs::remove_file(&path).ok();
    }
}
