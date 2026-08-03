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
use crate::provider::{token_key, Provider};
use crate::secrets::{SecretError, SecretStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Attempt cap for the compare-and-swap loop. One pass writes our own value;
/// a second pass exists only to adopt a value stored underneath us and
/// re-evaluate it. More than that is not contention, it is a bug.
const MAX_ATTEMPTS: usize = 2;

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

/// One lock per account, identified by provider and id together — see
/// `RefreshLocks`'s doc comment for why the pair, not the id alone, is the key.
type AccountLock = Arc<tokio::sync::Mutex<()>>;

/// One async mutex per **(provider, account)** pair. Entries are created on
/// first use and never evicted — the map is bounded by the account count, so
/// eviction would be more machinery than it saves.
///
/// **Keyed by `(Provider, String)`, not by the id alone.** Two accounts that
/// share an id across providers (docs/design.md §9.3 — nothing stops Anthropic
/// and Codex from issuing the same string) must not share a lock: if they did,
/// one provider's refresh would serialize against a refresh that has nothing
/// to do with it, and `is_refreshing` would answer for the wrong account
/// entirely.
///
/// **A `RefreshLocks` serializes only against itself.** Two instances covering
/// the same account serialize nothing at all: each hands out its own mutex, and
/// two `ensure_fresh` calls holding different mutexes both proceed. The caller
/// must therefore hold exactly one instance for the process and pass it to
/// every call — one in the application state, not one per task, per command
/// handler, or per poll.
#[derive(Default)]
pub struct RefreshLocks {
    inner: Mutex<HashMap<(Provider, String), AccountLock>>,
}

impl RefreshLocks {
    fn for_account(&self, provider: Provider, uuid: &str) -> AccountLock {
        // The std guard is a temporary and is dropped at the end of this
        // expression, so it never crosses an await and
        // `clippy::await_holding_lock` does not fire.
        self.inner.lock().unwrap().entry((provider, uuid.to_string())).or_default().clone()
    }

    /// Whether a refresh is in flight for this account. Lets a caller answer
    /// "refresh in progress" (docs/design.md §7.1 `AUTH_EXPIRED`) instead of
    /// blocking on the lock for the length of a 30-second token request.
    ///
    /// Advisory only: the answer can go stale the instant it is returned. It
    /// drives a display state, never a correctness decision — the lock itself
    /// is what orders writers.
    pub fn is_refreshing(&self, provider: Provider, uuid: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(&(provider, uuid.to_string()))
            .is_some_and(|m| m.try_lock().is_err())
    }
}

/// `Debug` is derived, which is safe only because `TokenSet` hand-writes its
/// own redacting `Debug`. If that ever changes, this leaks both tokens.
#[derive(Debug)]
pub struct Fresh {
    pub tokens: TokenSet,
    /// `Err` when the rotation succeeded over HTTP but the store write did not.
    /// The tokens are live and usable for this cycle.
    ///
    /// **What the next process start sees is worse than "not these tokens".**
    /// The store still holds the pre-rotation token, and the server has already
    /// moved past it — so the next start loads a dead credential, its first
    /// refresh returns `invalid_grant`, and §10.5 quarantines the account on
    /// that one strike. The user-visible outcome is `AUTH_DEAD` and a forced
    /// re-login, not a missed rotation.
    ///
    /// The error is carried rather than reduced to a flag because §9.2 and §9.3
    /// make two of its cases first-class and they need different responses: a
    /// `Locked` keychain must ask the user to unlock, while a `TooLong` blob
    /// will never fit — every future rotation fails identically, and the
    /// account silently demands a re-login on every restart until someone is
    /// told why.
    pub persisted: Result<(), SecretError>,
}

fn load(
    store: &dyn SecretStore,
    provider: Provider,
    uuid: &str,
) -> Result<TokenSet, StoredTokenError> {
    let raw = store.get(&token_key(provider, uuid))?.ok_or(StoredTokenError::Missing)?;
    serde_json::from_slice(&raw).map_err(|_| StoredTokenError::Corrupt)
}

fn save(
    store: &dyn SecretStore,
    provider: Provider,
    uuid: &str,
    tokens: &TokenSet,
) -> Result<(), SecretError> {
    // `TokenSet` is plain data, so serializing it cannot fail in practice.
    // Report it as a store error rather than as `Corrupt`: nothing was parsed
    // and nothing was stored, and the caller's useful response is identical to
    // any other failed write — the value did not reach the store.
    let blob = serde_json::to_vec(tokens)
        .map_err(|_| SecretError::Backend("failed to serialize the token set".into()))?;
    store.put(&token_key(provider, uuid), &blob)
}

/// Refreshes the stored token set if §10.5's five-minute skew says it is due,
/// persists the result, and returns it. Refreshes are serialized per account.
///
/// **The returned token is not guaranteed fresh.** The `MAX_ATTEMPTS` loop
/// below falls through after two adoptions and hands back whatever the store
/// currently holds, which may still be expired. That is deliberate — the
/// alternative is refreshing in a loop against a third writer that keeps
/// storing stale sets — but it means the caller must be prepared for the usage
/// fetch to answer 401, and must treat that as `AUTH_EXPIRED` (a refresh is
/// still the remedy) rather than as a dead account.
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
///
/// **`provider` is part of the identity, not a filter.** Two accounts that
/// share a `uuid` string across providers are two different accounts
/// (docs/design.md §9.3), so it is threaded into every key and lock lookup
/// alongside `uuid` rather than assumed to be Anthropic.
pub async fn ensure_fresh<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfig,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    uuid: &str,
) -> Result<Fresh, StoredTokenError> {
    let guard = locks.for_account(provider, uuid);
    let _held = guard.lock().await;

    for _ in 0..MAX_ATTEMPTS {
        let current = load(store, provider, uuid)?;
        if !current.needs_refresh() {
            // The double check. A caller that waited on the lock lands here and
            // returns what the winner stored, with no second request. Nothing
            // was written on this path, so there is no write to have failed.
            return Ok(Fresh { tokens: current, persisted: Ok(()) });
        }

        let witness = current.refresh_token.clone();
        let new = refresh(http, cfg, &current).await?;

        // Compare-and-swap (§10.5). Every arm is explicit on purpose: a
        // catch-all that falls through to the write is wrong in two distinct
        // ways, and both cost the user a permanently dead account.
        match load(store, provider, uuid) {
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
            // The comparison could not be performed at all, and a
            // compare-and-swap that cannot compare must not swap. Two cases
            // reach here and both are covered by that rule: a keychain that
            // locked mid-refresh (§9.2 makes `LOCKED` first-class), and a
            // `Corrupt` blob. Refusing to overwrite an unparseable blob is
            // deliberate, not incidental — the likeliest way one appears is a
            // re-login writing a new bundle while we read, so it may well be a
            // half-written *newer* credential, and overwriting it would destroy
            // the chain the user just created.
            Err(e) => return Err(e),
        }

        // The rotation already happened server-side, so the old refresh token
        // is dead and `new` is the only live credential. A failed write is
        // reported, never propagated: returning `Err` here would discard the
        // live token and waste the poll cycle on top of the durability loss.
        let persisted = save(store, provider, uuid, &new);
        return Ok(Fresh { tokens: new, persisted });
    }

    // Two adoptions in a row means some third writer keeps storing already
    // stale token sets. Hand back what is actually stored and let the next poll
    // cycle re-evaluate, rather than refreshing in a loop.
    Ok(Fresh { tokens: load(store, provider, uuid)?, persisted: Ok(()) })
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
        let raw = store.get(&token_key(Provider::Anthropic, UUID)).unwrap()?;
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
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();
        let locks = RefreshLocks::default();
        let http = ReqwestHttp::new().unwrap();
        let cfg = cfg_for(&server).await;

        let (a, b) = tokio::join!(
            ensure_fresh(&http, &cfg, &store, &locks, Provider::Anthropic, UUID),
            ensure_fresh(&http, &cfg, &store, &locks, Provider::Anthropic, UUID),
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
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let interloper = store.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                let fresh = fresh_tokens("rt-login");
                interloper
                    .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&fresh).unwrap())
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
            Provider::Anthropic,
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
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let deleter = store.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                deleter.delete(&token_key(Provider::Anthropic, UUID)).unwrap();
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
            Provider::Anthropic,
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
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&fresh_tokens("rt-0")).unwrap())
            .unwrap();

        let http = ReqwestHttp::new().unwrap();
        let out = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.refresh_token, "rt-0");
        assert!(out.persisted.is_ok());
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
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let http = ReqwestHttp::new().unwrap();
        let out = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.refresh_token, "rt-1", "the live rotated token was discarded");
        // Pins the error itself, not just that one occurred: reducing this to a
        // boolean is what §9.2/§9.3 forbid, and asserting `is_err()` alone
        // would keep passing if it were.
        assert!(
            matches!(out.persisted, Err(SecretError::Locked(_))),
            "the store error must reach the caller, got {:?}",
            out.persisted
        );
    }

    /// `Fresh` carries a live credential. Its `Debug` is derived, and that is
    /// safe only because it delegates to `TokenSet`'s hand-written redacting
    /// `Debug` — this test is what holds that dependency in place.
    #[test]
    fn fresh_debug_redacts_the_tokens() {
        let fresh = Fresh { tokens: expired_tokens("sk-ant-SENTINEL"), persisted: Ok(()) };
        let printed = format!("{fresh:?}");
        assert!(!printed.contains("SENTINEL"), "Fresh leaked a token: {printed}");
        assert!(printed.contains("<redacted>"));
        // Redaction, not a black box — the durability flag must stay visible.
        assert!(printed.contains("persisted"));
    }

    /// docs/design.md §14 names the one-strike `invalid_grant` quarantine as a
    /// required `auth` test target, and `ensure_fresh` is the only path in the
    /// application that can reach it — nothing else calls `refresh`.
    ///
    /// `token.rs` already tests `is_dead_grant` on a bare `AuthError`. This
    /// tests the seam: that the flag survives the `StoredTokenError::Auth`
    /// wrapper, which is the form every caller actually receives. If that
    /// breaks, a permanently dead grant is silently retried on every poll and
    /// `AUTH_DEAD` never appears — the account shows a spinner or a dimmed
    /// stale value forever and the user is never told to sign in again.
    #[tokio::test]
    async fn a_dead_grant_is_still_recognisable_through_the_stored_wrapper() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .expect(1) // exactly once — §10.5 forbids retrying a dead grant
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        store
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let http = ReqwestHttp::new().unwrap();
        let err = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, StoredTokenError::Auth(ref e) if e.is_dead_grant()),
            "the dead-grant flag did not survive the wrapper, got {err:?}"
        );
    }

    /// The stored blob is the token bundle verbatim, so a parse failure must
    /// not fold it into the error. `secrets` shipped exactly this defect once
    /// (an error message that embedded the value it failed to read).
    #[tokio::test]
    async fn a_corrupt_blob_does_not_leak_its_contents() {
        let server = MockServer::start().await;
        let store = MemoryStore::default();
        store.put(&token_key(Provider::Anthropic, UUID), br#"{"access_token":"sk-ant-SENTINEL""#).unwrap();

        let http = ReqwestHttp::new().unwrap();
        let err = ensure_fresh(
            &http,
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, StoredTokenError::Corrupt), "expected Corrupt, got {err:?}");
        assert!(!format!("{err:?}").contains("SENTINEL"));
        assert!(!err.to_string().contains("SENTINEL"));
    }
}
