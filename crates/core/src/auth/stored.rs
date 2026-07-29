//! The stored token: its key, its serialization, and the order in which
//! refreshes happen. docs/design.md §10.5.
//!
//! `auth::token::refresh` is a pure network call that never touches a store,
//! so before this module nothing owned the read → refresh → write sequence and
//! there was nowhere to put the lock §10.5 requires.
//!
//! **Known limits, all accepted deliberately.**
//!
//! - Cross-process, the compare-and-swap is largely inert. Under §10.7's
//!   single-use rotating chain premise the loser's refresh already fails with
//!   `invalid_grant` before the re-read runs. The CAS's real job is the
//!   re-login-lands-mid-refresh case, which is in-process. §10.5 scopes itself
//!   to the single-process case for the same reason.
//! - In-process it is correct on both backends, including `EncryptedFileStore`,
//!   whose `put` updates the cached map that `get` serves.
//! - Cross-process on `EncryptedFileStore` the re-read is blind, because `get`
//!   serves that cached map rather than re-reading disk. A `SecretStore`-level
//!   `compare_and_swap` *would* be genuinely atomic there — `put` already
//!   flocks and re-reads from disk inside the critical section — but not on the
//!   keychain, which exposes no such primitive and is the primary backend. One
//!   uniform implementation above the trait was chosen over two divergent ones.
//! - A crash between the HTTP 200 and the store write loses the rotation
//!   permanently; the next launch sees `invalid_grant`. Neither the lock nor
//!   the compare-and-swap addresses this.
//! - The blocking `SecretStore` call runs while the async mutex is held. On the
//!   encrypted-file backend `put` takes an unbounded blocking `flock(LOCK_EX)`
//!   and an `fsync`. `tokio`'s `rt` feature is not enabled in this crate, so
//!   `spawn_blocking` is not available to move it off the runtime thread. At a
//!   180-second polling floor and a handful of accounts this is acceptable —
//!   but it is a decision, not an accident. (Reviewer trap: the dev-dependency
//!   enables `rt-multi-thread`, so an accidental `spawn_blocking` compiles
//!   under `cargo test` and `cargo clippy --all-targets` and fails only under a
//!   plain `cargo build`. Neither project gate catches it.)

use crate::auth::pkce::AuthConfig;
use crate::auth::token::{refresh, AuthError, TokenHttp, TokenSet};
use crate::secrets::{SecretError, SecretStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Attempt cap for the compare-and-swap loop. One pass writes our own value;
/// a second pass exists only to adopt a value stored underneath us and
/// re-evaluate it. More than that is not contention, it is a bug.
const MAX_ATTEMPTS: usize = 2;

/// docs/design.md §9.3: entries are keyed uniquely by `account.uuid` under our
/// own service name, and lookups are exact. This is the only place the key is
/// built — four independent re-derivations of this format is how ccstatusline
/// #521 happens.
pub fn token_key(uuid: &str) -> String {
    format!("{uuid}:tokens")
}

#[derive(Debug, thiserror::Error)]
pub enum StoredTokenError {
    /// No token for this uuid. docs/design.md §9.2: `NOT_FOUND` means the
    /// account is `AUTH_DEAD` and needs a re-login — not a transient failure.
    #[error("no token is stored for this account")]
    Missing,
    /// The blob is present but unreadable. The serde message is deliberately
    /// dropped: the blob is the token bundle verbatim.
    #[error("the stored token blob could not be parsed")]
    Corrupt,
    #[error(transparent)]
    Secrets(#[from] SecretError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

/// One async mutex per account. Entries are created on first use and never
/// evicted — the map is bounded by the account count, so eviction would be more
/// machinery than it saves.
#[derive(Default)]
pub struct RefreshLocks {
    inner: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl RefreshLocks {
    fn for_uuid(&self, uuid: &str) -> Arc<tokio::sync::Mutex<()>> {
        // The std guard is a temporary and is dropped at the end of this
        // expression, so it never crosses an await and
        // `clippy::await_holding_lock` does not fire.
        self.inner.lock().unwrap().entry(uuid.to_string()).or_default().clone()
    }

    /// Whether a refresh is in flight for this account. Lets a caller answer
    /// "refresh in progress" (docs/design.md §7.1 `AUTH_EXPIRED`) instead of
    /// blocking on the lock for the length of a 30-second token request.
    ///
    /// Advisory only: the answer can go stale the instant it is returned. It
    /// drives a display state, never a correctness decision — the lock itself
    /// is what orders writers.
    pub fn is_refreshing(&self, uuid: &str) -> bool {
        self.inner.lock().unwrap().get(uuid).is_some_and(|m| m.try_lock().is_err())
    }
}

/// `Debug` is derived, which is safe only because `TokenSet` hand-writes its
/// own redacting `Debug`. If that ever changes, this leaks both tokens.
#[derive(Debug)]
pub struct Fresh {
    pub tokens: TokenSet,
    /// False when the rotation succeeded over HTTP but the store write did not.
    /// The tokens are live and usable for this cycle; only the next process
    /// start will fail to see them.
    pub persisted: bool,
}

fn load(store: &dyn SecretStore, uuid: &str) -> Result<TokenSet, StoredTokenError> {
    let raw = store.get(&token_key(uuid))?.ok_or(StoredTokenError::Missing)?;
    serde_json::from_slice(&raw).map_err(|_| StoredTokenError::Corrupt)
}

fn save(store: &dyn SecretStore, uuid: &str, tokens: &TokenSet) -> Result<(), StoredTokenError> {
    let blob = serde_json::to_vec(tokens).map_err(|_| StoredTokenError::Corrupt)?;
    store.put(&token_key(uuid), &blob)?;
    Ok(())
}

/// Returns a token set that is fresh by §10.5's five-minute skew, refreshing
/// and persisting it if it is not. Refreshes are serialized per account.
///
/// **Takes a uuid, never a pre-loaded `TokenSet`.** Re-reading the store inside
/// the lock is the whole of this function's correctness: the caller that waited
/// on the lock must see what the winner wrote, or both refresh and one of the
/// two chains dies. Accepting an already-loaded value as a parameter — an
/// obvious-looking optimization, since callers have usually just read it —
/// reopens the race completely.
///
/// The caller must not hold any other lock across this call. It awaits a
/// network request of up to 30 seconds.
pub async fn ensure_fresh<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfig,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    uuid: &str,
) -> Result<Fresh, StoredTokenError> {
    let guard = locks.for_uuid(uuid);
    let _held = guard.lock().await;

    for _ in 0..MAX_ATTEMPTS {
        let current = load(store, uuid)?;
        if !current.needs_refresh() {
            // The double check. A caller that waited on the lock lands here and
            // returns what the winner stored, with no second request.
            return Ok(Fresh { tokens: current, persisted: true });
        }

        let witness = current.refresh_token.clone();
        let new = refresh(http, cfg, &current).await?;

        // Compare-and-swap (§10.5). Every arm is explicit on purpose: a
        // catch-all that falls through to the write is wrong in two distinct
        // ways, and both cost the user a permanently dead account.
        match load(store, uuid) {
            // Someone stored a different chain underneath us — realistically a
            // re-login landing mid-refresh. §10.5 says adopt it rather than
            // overwrite. `continue` re-reads and re-evaluates freshness, which
            // is what makes "adopt" literal: the token we just obtained is
            // dropped rather than written.
            Ok(stored) if stored.refresh_token != witness => continue,
            Ok(_) => {}
            // The key is gone: `remove_account` deleted it while we were on the
            // network, and it revoked this refresh token first (§10.6). Writing
            // here would resurrect a revoked credential for an account that no
            // longer exists, with no UI path left to delete it. Dropping the
            // rotated token is correct — it belongs to a deleted account.
            Err(StoredTokenError::Missing) => return Err(StoredTokenError::Missing),
            // A keychain that locked mid-refresh (§9.2 makes `LOCKED` a
            // first-class state). The comparison could not be performed at all,
            // and a compare-and-swap that cannot compare must not swap.
            Err(e) => return Err(e),
        }

        return Ok(match save(store, uuid, &new) {
            Ok(()) => Fresh { tokens: new, persisted: true },
            // The rotation already happened server-side, so the old refresh
            // token is dead and `new` is the only live credential. Returning
            // `Err` here would discard it, leave the dead one on disk, and
            // waste the poll cycle as well.
            Err(_) => Fresh { tokens: new, persisted: false },
        });
    }

    // Two adoptions in a row means some third writer keeps storing already
    // stale token sets. Hand back what is actually stored and let the next poll
    // cycle re-evaluate, rather than refreshing in a loop.
    Ok(Fresh { tokens: load(store, uuid)?, persisted: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::ReqwestHttp;
    use crate::secrets::MemoryStore;
    use chrono::{TimeDelta, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const UUID: &str = "acc-1";

    async fn cfg_for(server: &MockServer) -> AuthConfig {
        AuthConfig { token_url: format!("{}/v1/oauth/token", server.uri()), ..AuthConfig::default() }
    }

    fn expired_tokens(refresh_token: &str) -> TokenSet {
        TokenSet {
            access_token: "old-at".into(),
            refresh_token: refresh_token.into(),
            expires_at: Utc::now() - TimeDelta::seconds(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: AuthConfig::default().client_id,
        }
    }

    fn fresh_tokens(refresh_token: &str) -> TokenSet {
        TokenSet { expires_at: Utc::now() + TimeDelta::hours(2), ..expired_tokens(refresh_token) }
    }

    fn ok_body(rt: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": "new-at", "refresh_token": rt,
            "expires_in": 27000, "scope": "user:profile"
        })
    }

    fn stored_refresh_token(store: &dyn SecretStore) -> Option<String> {
        let raw = store.get(&token_key(UUID)).unwrap()?;
        Some(serde_json::from_slice::<TokenSet>(&raw).unwrap().refresh_token)
    }

    /// Counts writes and can be made to fail them, so "no write on the no-op
    /// path" and "a failed write still returns the live token" are assertions
    /// rather than claims. Seed it through `inner` so seeding is not counted.
    #[derive(Default)]
    struct CountingStore {
        inner: MemoryStore,
        puts: AtomicUsize,
        fail_puts: bool,
    }

    impl SecretStore for CountingStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            if self.fail_puts {
                return Err(SecretError::Locked("test".into()));
            }
            self.inner.put(key, value)
        }
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.inner.get(key)
        }
        fn delete(&self, key: &str) -> Result<bool, SecretError> {
            self.inner.delete(key)
        }
        fn describe(&self) -> String {
            "counting (test only)".to_string()
        }
    }

    /// docs/design.md §10.5 and §14: refreshes are serialized per account. Two
    /// callers race on one uuid and exactly one request must go out.
    ///
    /// The mock is delayed so the first caller actually yields inside the
    /// request. Without a real await point, `tokio::join!` on the default
    /// current-thread runtime runs the first future to completion before
    /// polling the second, and the test would pass with the lock removed —
    /// the "test that cannot fail" CLAUDE.md forbids. For the same reason the
    /// assertion is a request count, never a non-overlapping-interval check.
    /// A `Barrier(2)` rendezvous does not work either: when the lock does its
    /// job the second caller never reaches the barrier and the test deadlocks.
    #[tokio::test]
    async fn concurrent_refreshes_are_serialized_per_account() {
        let server = MockServer::start().await;
        let posts = Arc::new(AtomicUsize::new(0));
        let counter = posts.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(ok_body("rt-1"))
                    .set_delay(std::time::Duration::from_millis(50))
            })
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        store
            .put(&token_key(UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();
        let locks = RefreshLocks::default();
        let http = ReqwestHttp::new().unwrap();
        let cfg = cfg_for(&server).await;

        let (a, b) = tokio::join!(
            ensure_fresh(&http, &cfg, &store, &locks, UUID),
            ensure_fresh(&http, &cfg, &store, &locks, UUID),
        );

        assert_eq!(posts.load(Ordering::SeqCst), 1, "the refresh was not serialized");
        assert_eq!(a.unwrap().tokens.refresh_token, "rt-1");
        assert_eq!(b.unwrap().tokens.refresh_token, "rt-1", "the waiter re-read stale state");
    }

    /// docs/design.md §10.5: "if the value changed underneath us, adopt the new
    /// value rather than overwriting it." The responder simulates a re-login
    /// landing mid-refresh by storing a different chain before our request
    /// returns.
    #[tokio::test]
    async fn a_chain_stored_underneath_us_is_adopted_not_overwritten() {
        let server = MockServer::start().await;
        let store = Arc::new(MemoryStore::default());
        store
            .put(&token_key(UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let interloper = store.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                let fresh = fresh_tokens("rt-login");
                interloper
                    .put(&token_key(UUID), &serde_json::to_vec(&fresh).unwrap())
                    .unwrap();
                ResponseTemplate::new(200).set_body_json(ok_body("rt-ours"))
            })
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let out = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            store.as_ref(),
            &RefreshLocks::default(),
            UUID,
        )
        .await
        .unwrap();

        assert_eq!(
            out.tokens.refresh_token, "rt-login",
            "we overwrote the newer chain instead of adopting it"
        );
        assert_eq!(stored_refresh_token(store.as_ref()).as_deref(), Some("rt-login"));
    }

    /// A delete landing mid-refresh must not be undone. `remove_account`
    /// revokes the refresh token before deleting the key (docs/design.md
    /// §10.6), so writing our rotated token back would resurrect a revoked
    /// credential for an account that no longer exists — and leave no UI path
    /// to delete it again.
    #[tokio::test]
    async fn a_deleted_account_is_not_resurrected_by_an_in_flight_refresh() {
        let server = MockServer::start().await;
        let store = Arc::new(MemoryStore::default());
        store
            .put(&token_key(UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let deleter = store.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                deleter.delete(&token_key(UUID)).unwrap();
                ResponseTemplate::new(200).set_body_json(ok_body("rt-1"))
            })
            .mount(&server)
            .await;

        let http = ReqwestHttp::new().unwrap();
        let err = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            store.as_ref(),
            &RefreshLocks::default(),
            UUID,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, StoredTokenError::Missing), "expected Missing, got {err:?}");
        assert_eq!(
            stored_refresh_token(store.as_ref()),
            None,
            "the deleted token was written back"
        );
    }

    /// A token that is still fresh costs neither a request nor a store write.
    /// Re-writing on every poll would be an OS keychain write per tick.
    #[tokio::test]
    async fn a_fresh_token_costs_no_request_and_no_write() {
        // No mock is mounted, so any request gets wiremock's 404 and the
        // `unwrap()` below fails the test.
        let server = MockServer::start().await;
        let store = CountingStore::default();
        store
            .inner
            .put(&token_key(UUID), &serde_json::to_vec(&fresh_tokens("rt-0")).unwrap())
            .unwrap();

        let http = ReqwestHttp::new().unwrap();
        let out = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            UUID,
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.refresh_token, "rt-0");
        assert!(out.persisted);
        assert_eq!(store.puts.load(Ordering::SeqCst), 0, "a fresh token was re-written");
    }

    /// A store write that fails after a successful rotation must not discard
    /// the rotated token. The server has already moved on, so the old refresh
    /// token is dead and the new one is the only live credential; returning an
    /// error here would throw it away and waste the poll cycle too.
    #[tokio::test]
    async fn a_failed_write_after_rotation_still_returns_the_live_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body("rt-1")))
            .mount(&server)
            .await;

        let store = CountingStore { fail_puts: true, ..Default::default() };
        store
            .inner
            .put(&token_key(UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let http = ReqwestHttp::new().unwrap();
        let out = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            UUID,
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.refresh_token, "rt-1", "the live rotated token was discarded");
        assert!(!out.persisted, "a failed write must be reported to the caller");
    }

    /// `Fresh` carries a live credential, so it gets the same treatment as
    /// `TokenSet`: a derived `Debug` would print both tokens into any
    /// `tracing::debug!(?fresh)` or `assert_eq!` failure.
    #[test]
    fn fresh_debug_redacts_the_tokens() {
        let fresh = Fresh { tokens: expired_tokens("sk-ant-SENTINEL"), persisted: true };
        let printed = format!("{fresh:?}");
        assert!(!printed.contains("SENTINEL"), "Fresh leaked a token: {printed}");
        assert!(printed.contains("<redacted>"));
        // Redaction, not a black box — the durability flag must stay visible.
        assert!(printed.contains("persisted"));
    }

    /// The stored blob is the token bundle verbatim, so a parse failure must
    /// not fold it into the error. `secrets` shipped exactly this defect once
    /// (an error message that embedded the value it failed to read).
    #[tokio::test]
    async fn a_corrupt_blob_does_not_leak_its_contents() {
        let server = MockServer::start().await;
        let store = MemoryStore::default();
        store.put(&token_key(UUID), br#"{"access_token":"sk-ant-SENTINEL""#).unwrap();

        let http = ReqwestHttp::new().unwrap();
        let err = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            UUID,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, StoredTokenError::Corrupt), "expected Corrupt, got {err:?}");
        assert!(!format!("{err:?}").contains("SENTINEL"));
        assert!(!err.to_string().contains("SENTINEL"));
    }
}
