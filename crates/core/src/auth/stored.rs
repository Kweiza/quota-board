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

use crate::auth::openai::{self, OpenAiAuthConfig, OpenAiTokenSet};
use crate::auth::token::{refresh, AuthError, TokenHttp, TokenSet};
use crate::provider::{token_key, Provider, ProviderSpec};
use crate::secrets::{SecretError, SecretStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Attempt cap for the compare-and-swap loop. One pass writes our own value;
/// a second pass exists only to adopt a value stored underneath us and
/// re-evaluate it. More than that is not contention, it is a bug.
const MAX_ATTEMPTS: usize = 2;

/// The two auth protocols a polling process uses.
///
/// Kept as two typed values rather than one provider-generic endpoint record:
/// Anthropic refreshes with its measured JSON-plus-scopes request, while
/// OpenAI refreshes with a different JSON response whose token fields are all
/// optional. Sharing an HTTP client is sound; pretending those payloads are
/// one protocol is not.
#[derive(Debug, Clone)]
pub struct AuthConfigs {
    pub anthropic: ProviderSpec,
    pub openai: OpenAiAuthConfig,
}

impl Default for AuthConfigs {
    fn default() -> Self {
        Self {
            anthropic: ProviderSpec::anthropic(),
            openai: OpenAiAuthConfig::default(),
        }
    }
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
    #[error("{source}")]
    Auth {
        provider: Provider,
        #[source]
        source: AuthError,
    },
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

/// The provider-specific credential read from one provider-specific key.
///
/// This enum is deliberately **not** serialized. Existing Anthropic entries
/// contain an untagged `TokenSet` JSON object, and wrapping it in an enum would
/// orphan every mobile and desktop account on upgrade. The key tells `load`
/// which concrete type to deserialize; OpenAI uses a new namespaced key and can
/// therefore start with its own shape.
#[derive(Debug, Clone)]
pub enum StoredTokens {
    Anthropic(TokenSet),
    Openai(OpenAiTokenSet),
}

impl StoredTokens {
    pub fn provider(&self) -> Provider {
        match self {
            Self::Anthropic(_) => Provider::Anthropic,
            Self::Openai(_) => Provider::Openai,
        }
    }

    pub fn access_token(&self) -> &str {
        match self {
            Self::Anthropic(tokens) => &tokens.access_token,
            Self::Openai(tokens) => &tokens.access_token,
        }
    }

    pub fn refresh_token(&self) -> &str {
        match self {
            Self::Anthropic(tokens) => &tokens.refresh_token,
            Self::Openai(tokens) => &tokens.refresh_token,
        }
    }

    pub fn workspace_id(&self) -> Option<&str> {
        match self {
            Self::Anthropic(_) => None,
            Self::Openai(tokens) => tokens.workspace_id.as_deref(),
        }
    }

    pub fn is_fedramp(&self) -> Option<bool> {
        match self {
            Self::Anthropic(_) => None,
            Self::Openai(tokens) => tokens.is_fedramp,
        }
    }

    fn needs_refresh(&self) -> bool {
        match self {
            Self::Anthropic(tokens) => tokens.needs_refresh(),
            Self::Openai(tokens) => tokens.needs_refresh_at(chrono::Utc::now()),
        }
    }
}

/// `Debug` is derived, which is safe only because both stored token variants
/// hand-write their own redacting `Debug`.
#[derive(Debug)]
pub struct Fresh {
    pub tokens: StoredTokens,
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

pub fn load_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    uuid: &str,
) -> Result<StoredTokens, StoredTokenError> {
    let raw = store
        .get(&token_key(provider, uuid))?
        .ok_or(StoredTokenError::Missing)?;
    match provider {
        Provider::Anthropic => serde_json::from_slice(&raw)
            .map(StoredTokens::Anthropic)
            .map_err(|_| StoredTokenError::Corrupt),
        Provider::Openai => serde_json::from_slice(&raw)
            .map(StoredTokens::Openai)
            .map_err(|_| StoredTokenError::Corrupt),
    }
}

pub fn save_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    uuid: &str,
    tokens: &StoredTokens,
) -> Result<(), SecretError> {
    if tokens.provider() != provider {
        return Err(SecretError::Backend(
            "refusing to store a credential under another provider's key".into(),
        ));
    }
    // Both token structs are plain data, so serializing cannot fail in
    // practice. Match before serializing so Anthropic remains an untagged
    // `TokenSet` object byte-for-byte compatible with existing entries.
    let blob = match tokens {
        StoredTokens::Anthropic(tokens) => serde_json::to_vec(tokens),
        StoredTokens::Openai(tokens) => serde_json::to_vec(tokens),
    }
    .map_err(|_| SecretError::Backend("failed to serialize the token set".into()))?;
    store.put(&token_key(provider, uuid), &blob)
}

pub fn save_anthropic_tokens(
    store: &dyn SecretStore,
    account_id: &str,
    tokens: &TokenSet,
) -> Result<(), SecretError> {
    save_tokens(
        store,
        Provider::Anthropic,
        account_id,
        &StoredTokens::Anthropic(tokens.clone()),
    )
}

pub fn save_openai_tokens(
    store: &dyn SecretStore,
    account_id: &str,
    tokens: &OpenAiTokenSet,
) -> Result<(), SecretError> {
    save_tokens(
        store,
        Provider::Openai,
        account_id,
        &StoredTokens::Openai(tokens.clone()),
    )
}

async fn refresh_tokens<H: TokenHttp>(
    http: &H,
    configs: &AuthConfigs,
    current: &StoredTokens,
) -> Result<StoredTokens, AuthError> {
    match current {
        StoredTokens::Anthropic(tokens) => refresh(http, &configs.anthropic, tokens)
            .await
            .map(StoredTokens::Anthropic),
        StoredTokens::Openai(tokens) => openai::refresh(http, &configs.openai, tokens)
            .await
            .map(StoredTokens::Openai),
    }
}

/// Provider-aware best-effort server-side revocation.
pub async fn revoke_tokens<H: TokenHttp>(http: &H, configs: &AuthConfigs, tokens: &StoredTokens) {
    match tokens {
        StoredTokens::Anthropic(tokens) => {
            crate::auth::token::revoke(http, &configs.anthropic, &tokens.refresh_token).await
        }
        StoredTokens::Openai(tokens) => openai::revoke(http, &configs.openai, tokens).await,
    }
}

/// Delete the provider-specific local entry. Server revocation is a separate
/// best-effort step because local deletion must still proceed if the network is
/// unavailable.
pub fn delete_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    account_id: &str,
) -> Result<bool, SecretError> {
    store.delete(&token_key(provider, account_id))
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
    configs: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    uuid: &str,
) -> Result<Fresh, StoredTokenError> {
    ensure_fresh_inner(http, configs, store, locks, provider, uuid, None).await
}

/// Force one provider-aware refresh after a usage endpoint rejected the
/// access token. This is the recovery path for an OpenAI access token whose
/// `exp` claim is absent or unreadable: unknown expiry is not fabricated as
/// 1970, but a 401 must not produce an endless `AUTH_EXPIRED` loop either.
pub async fn refresh_after_unauthorized<H: TokenHttp>(
    http: &H,
    configs: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    uuid: &str,
    rejected_access_token: &str,
) -> Result<Fresh, StoredTokenError> {
    ensure_fresh_inner(
        http,
        configs,
        store,
        locks,
        provider,
        uuid,
        Some(rejected_access_token),
    )
    .await
}

async fn ensure_fresh_inner<H: TokenHttp>(
    http: &H,
    configs: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    uuid: &str,
    rejected_access_token: Option<&str>,
) -> Result<Fresh, StoredTokenError> {
    let guard = locks.for_account(provider, uuid);
    let _held = guard.lock().await;

    for _ in 0..MAX_ATTEMPTS {
        let current = load_tokens(store, provider, uuid)?;
        if rejected_access_token
            .is_some_and(|rejected| current.access_token() != rejected)
            || (rejected_access_token.is_none() && !current.needs_refresh())
        {
            // The double check. A caller that waited on the lock lands here and
            // returns what the winner stored, with no second request. Nothing
            // was written on this path, so there is no write to have failed.
            return Ok(Fresh { tokens: current, persisted: Ok(()) });
        }

        let witness = current.refresh_token().to_string();
        let new = refresh_tokens(http, configs, &current)
            .await
            .map_err(|source| StoredTokenError::Auth { provider, source })?;

        // Compare-and-swap (§10.5). Every arm is explicit on purpose: a
        // catch-all that falls through to the write is wrong in two distinct
        // ways, and both cost the user a permanently dead account.
        match load_tokens(store, provider, uuid) {
            // Someone stored a different chain underneath us — realistically a
            // re-login landing mid-refresh. §10.5 says adopt it rather than
            // overwrite. `continue` re-reads and re-evaluates freshness, which
            // is what makes "adopt" literal: the token we just obtained is
            // dropped rather than written.
            Ok(stored) if stored.refresh_token() != witness => continue,
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
        let persisted = save_tokens(store, provider, uuid, &new);
        return Ok(Fresh {
            tokens: new,
            persisted,
        });
    }

    // Two adoptions in a row means some third writer keeps storing already
    // stale token sets. Hand back what is actually stored and let the next poll
    // cycle re-evaluate, rather than refreshing in a loop.
    Ok(Fresh {
        tokens: load_tokens(store, provider, uuid)?,
        persisted: Ok(()),
    })
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

    async fn cfg_for(server: &MockServer) -> AuthConfigs {
        AuthConfigs {
            anthropic: ProviderSpec {
                token_url: format!("{}/v1/oauth/token", server.uri()),
                ..ProviderSpec::anthropic()
            },
            ..AuthConfigs::default()
        }
    }

    fn expired_tokens(refresh_token: &str) -> TokenSet {
        TokenSet {
            access_token: "old-at".into(),
            refresh_token: refresh_token.into(),
            expires_at: Utc::now() - TimeDelta::seconds(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: ProviderSpec::anthropic().client_id,
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
        Some(
            serde_json::from_slice::<TokenSet>(&raw)
                .unwrap()
                .refresh_token,
        )
    }

    fn openai_tokens(access_token: &str) -> OpenAiTokenSet {
        OpenAiTokenSet {
            access_token: access_token.into(),
            refresh_token: "openai-refresh-old".into(),
            client_id: openai::CLIENT_ID.into(),
            user_id: "user-one".into(),
            workspace_id: Some("workspace-one".into()),
            is_fedramp: None,
        }
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

        assert_eq!(
            posts.load(Ordering::SeqCst),
            1,
            "the refresh was not serialized"
        );
        assert_eq!(a.unwrap().tokens.refresh_token(), "rt-1");
        assert_eq!(
            b.unwrap().tokens.refresh_token(),
            "rt-1",
            "the waiter re-read stale state"
        );
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
            out.tokens.refresh_token(),
            "rt-login",
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

        assert_eq!(out.tokens.refresh_token(), "rt-0");
        assert!(out.persisted.is_ok());
        assert_eq!(
            store.puts.load(Ordering::SeqCst),
            0,
            "a fresh token was re-written"
        );
    }

    /// The enum is an in-memory dispatch only. If serde ever wraps the
    /// Anthropic value as `{"Anthropic": ...}`, every existing keychain entry
    /// becomes unreadable by the prior release and an upgrade forces all users
    /// to sign in again.
    #[test]
    fn saving_anthropic_tokens_writes_the_old_untagged_blob() {
        let store = MemoryStore::default();
        let tokens = fresh_tokens("rt-old-shape");
        save_anthropic_tokens(&store, UUID, &tokens).unwrap();
        let stored = store
            .get(&token_key(Provider::Anthropic, UUID))
            .unwrap()
            .unwrap();
        assert_eq!(stored, serde_json::to_vec(&tokens).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert!(
            value.get("Anthropic").is_none(),
            "an enum tag reached the old blob"
        );
    }

    #[test]
    fn openai_tokens_round_trip_only_under_the_namespaced_user_key() {
        let store = MemoryStore::default();
        let tokens = openai_tokens("opaque-access");
        save_openai_tokens(&store, "user-one", &tokens).unwrap();
        assert!(
            store.get("user-one:tokens").unwrap().is_none(),
            "the Claude key was reused"
        );
        let got = load_tokens(&store, Provider::Openai, "user-one").unwrap();
        assert_eq!(got.access_token(), "opaque-access");
        assert_eq!(got.workspace_id(), Some("workspace-one"));
    }

    /// Unknown expiry is not 1970 and therefore does not trigger a speculative
    /// rotation on every poll. But once the usage endpoint returns 401, the
    /// forced path must rotate exactly once even though the same opaque access
    /// token still has no readable `exp` claim.
    #[tokio::test]
    async fn a_401_forces_openai_refresh_when_access_expiry_is_unreadable() {
        let server = MockServer::start().await;
        let posts = Arc::new(AtomicUsize::new(0));
        let count = posts.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                count.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "still-opaque-but-new"
                }))
            })
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        save_openai_tokens(&store, "user-one", &openai_tokens("opaque-old")).unwrap();
        let configs = AuthConfigs {
            openai: OpenAiAuthConfig {
                token_url: format!("{}/oauth/token", server.uri()),
                ..OpenAiAuthConfig::default()
            },
            ..AuthConfigs::default()
        };
        let locks = RefreshLocks::default();
        let http = ReqwestHttp::new().unwrap();

        let before = ensure_fresh(
            &http,
            &configs,
            &store,
            &locks,
            Provider::Openai,
            "user-one",
        )
        .await
        .unwrap();
        assert_eq!(before.tokens.access_token(), "opaque-old");
        assert_eq!(
            posts.load(Ordering::SeqCst),
            0,
            "unknown expiry was guessed as expired"
        );

        let after = refresh_after_unauthorized(
            &http,
            &configs,
            &store,
            &locks,
            Provider::Openai,
            "user-one",
            "opaque-old",
        )
        .await
        .unwrap();
        assert_eq!(after.tokens.access_token(), "still-opaque-but-new");
        assert_eq!(
            posts.load(Ordering::SeqCst),
            1,
            "the 401 did not force exactly one refresh"
        );
    }

    /// Both callers observed the same rejected access token. The first rotates
    /// it while the second waits on the account lock; the waiter must adopt the
    /// already-rotated access token instead of consuming the single-use refresh
    /// chain a second time. The delayed response is what makes the waiter
    /// actually queue behind the first request.
    #[tokio::test]
    async fn concurrent_401_refreshes_use_the_rejected_access_token_as_a_witness() {
        let server = MockServer::start().await;
        let posts = Arc::new(AtomicUsize::new(0));
        let count = posts.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &Request| {
                count.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({
                        "access_token": "opaque-new"
                    }))
                    .set_delay(std::time::Duration::from_millis(50))
            })
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        save_openai_tokens(&store, "user-one", &openai_tokens("opaque-old")).unwrap();
        let configs = AuthConfigs {
            openai: OpenAiAuthConfig {
                token_url: format!("{}/oauth/token", server.uri()),
                ..OpenAiAuthConfig::default()
            },
            ..AuthConfigs::default()
        };
        let locks = RefreshLocks::default();
        let http = ReqwestHttp::new().unwrap();

        let (a, b) = tokio::join!(
            refresh_after_unauthorized(
                &http,
                &configs,
                &store,
                &locks,
                Provider::Openai,
                "user-one",
                "opaque-old",
            ),
            refresh_after_unauthorized(
                &http,
                &configs,
                &store,
                &locks,
                Provider::Openai,
                "user-one",
                "opaque-old",
            ),
        );

        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(a.unwrap().tokens.access_token(), "opaque-new");
        assert_eq!(b.unwrap().tokens.access_token(), "opaque-new");
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

        assert_eq!(
            out.tokens.refresh_token(),
            "rt-1",
            "the live rotated token was discarded"
        );
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
        let fresh = Fresh {
            tokens: StoredTokens::Anthropic(expired_tokens("sk-ant-SENTINEL")),
            persisted: Ok(()),
        };
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
            matches!(
                err,
                StoredTokenError::Auth { provider, ref source }
                    if source.is_dead_grant_for(provider)
            ),
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
