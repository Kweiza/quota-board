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
use crate::auth::token::{
    refresh as refresh_anthropic, revoke as revoke_anthropic, AuthError, TokenHttp, TokenSet,
};
use crate::provider::{
    openai_access_token_key, openai_refresh_token_key, openai_token_meta_key, token_key, Provider,
    ProviderSpec,
};
use crate::secrets::{SecretError, SecretStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Attempt cap for the compare-and-swap loop. One pass writes our own value;
/// a second pass exists only to adopt a value stored underneath us and
/// re-evaluate it. More than that is not contention, it is a bug.
const MAX_ATTEMPTS: usize = 2;

/// A safety margin below Windows Credential Manager's 2560-byte credential
/// limit. Each OpenAI value is checked before the first write, so discovering
/// that the last value is too large cannot leave the first two half-written.
const OPENAI_ENTRY_LIMIT: usize = 2300;

#[derive(Debug, thiserror::Error)]
pub enum StoredTokenError {
    /// No token for this account id. docs/design.md §9.2: `NOT_FOUND` means the
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

/// The credential shape belonging to one provider.
///
/// `Debug` is hand-written because both variants contain live credentials.
/// The inner types redact too, but deriving here would make that safety depend
/// silently on both of them continuing to do so.
#[derive(Clone)]
pub enum StoredTokens {
    Anthropic(TokenSet),
    Openai(OpenAiTokenSet),
}

impl std::fmt::Debug for StoredTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anthropic(tokens) => f.debug_tuple("Anthropic").field(tokens).finish(),
            Self::Openai(tokens) => f.debug_tuple("Openai").field(tokens).finish(),
        }
    }
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

    /// OpenAI workspace routing context. Anthropic has no counterpart.
    pub fn workspace_id(&self) -> Option<&str> {
        match self {
            Self::Anthropic(_) => None,
            Self::Openai(tokens) => Some(&tokens.workspace_id),
        }
    }

    /// Whether OpenAI requires the FedRAMP workspace header. Always false for
    /// Anthropic, where the concept does not exist.
    pub fn is_fedramp(&self) -> bool {
        match self {
            Self::Anthropic(_) => false,
            Self::Openai(tokens) => tokens.is_fedramp,
        }
    }

    fn needs_refresh(&self) -> bool {
        match self {
            Self::Anthropic(tokens) => tokens.needs_refresh(),
            Self::Openai(tokens) => tokens.needs_refresh(),
        }
    }
}

/// Both providers' refresh configuration, owned by application state. Keeping
/// the dispatch beside the token enum makes it impossible for a Codex refresh
/// token to be posted to Anthropic merely because a caller selected the wrong
/// standalone config.
#[derive(Debug, Clone)]
pub struct AuthConfigs {
    pub anthropic: ProviderSpec,
    pub openai: OpenAiAuthConfig,
}

impl Default for AuthConfigs {
    fn default() -> Self {
        Self {
            anthropic: Provider::Anthropic.spec(),
            openai: OpenAiAuthConfig::default(),
        }
    }
}

/// The non-secret portion of an OpenAI credential. Access and refresh tokens
/// are raw bytes in separate entries; serializing them together here would
/// recreate the Windows size failure the split exists to prevent.
#[derive(Serialize, Deserialize)]
struct OpenAiTokenMeta {
    expires_at: DateTime<Utc>,
    client_id: String,
    account_id: String,
    workspace_id: String,
    is_fedramp: bool,
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
    fn for_account(&self, provider: Provider, account_id: &str) -> AccountLock {
        // The std guard is a temporary and is dropped at the end of this
        // expression, so it never crosses an await and
        // `clippy::await_holding_lock` does not fire.
        self.inner.lock().unwrap().entry((provider, account_id.to_string())).or_default().clone()
    }

    /// Acquires the same per-account lock used by refresh. Login holds this
    /// across its blocking [`save_tokens`] call so a newly issued credential
    /// cannot interleave with refresh's post-network compare-and-swap.
    pub async fn lock_account(
        &self,
        provider: Provider,
        account_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.for_account(provider, account_id).lock_owned().await
    }

    /// Whether a refresh is in flight for this account. Lets a caller answer
    /// "refresh in progress" (docs/design.md §7.1 `AUTH_EXPIRED`) instead of
    /// blocking on the lock for the length of a 30-second token request.
    ///
    /// Advisory only: the answer can go stale the instant it is returned. It
    /// drives a display state, never a correctness decision — the lock itself
    /// is what orders writers.
    pub fn is_refreshing(&self, provider: Provider, account_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(&(provider, account_id.to_string()))
            .is_some_and(|m| m.try_lock().is_err())
    }
}

pub struct Fresh {
    pub tokens: StoredTokens,
    /// `Err` when the rotation succeeded over HTTP but the store write did not.
    /// The tokens are live and usable for this cycle.
    ///
    /// **The durability consequence depends on where the write failed.** A
    /// Claude failure, or an OpenAI failure before its first split-entry write,
    /// leaves the pre-rotation refresh token behind after the server has moved
    /// past it. The next start then loads a dead credential and can require a
    /// re-login. OpenAI writes refresh → access → metadata, however, so a later
    /// split-entry failure has already preserved the live refresh chain. The
    /// next load may combine it with the previous access token or expiry, but a
    /// forced or expiry-driven refresh can repair that recoverable prefix.
    ///
    /// The error is carried rather than reduced to a flag because §9.2 and §9.3
    /// make two of its cases first-class and they need different responses: a
    /// `Locked` keychain must ask the user to unlock, while a `TooLong` blob
    /// will never fit — every future rotation fails identically, and the
    /// account silently demands a re-login on every restart until someone is
    /// told why.
    pub persisted: Result<(), SecretError>,
}

impl std::fmt::Debug for Fresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fresh")
            .field("tokens", &self.tokens)
            .field("persisted", &self.persisted)
            .finish()
    }
}

fn valid_openai_tokens(tokens: &OpenAiTokenSet, account_id: &str) -> bool {
    !account_id.trim().is_empty()
        && !tokens.access_token.trim().is_empty()
        && !tokens.refresh_token.trim().is_empty()
        && !tokens.client_id.trim().is_empty()
        && !tokens.account_id.trim().is_empty()
        && tokens.account_id == account_id
        && !tokens.workspace_id.trim().is_empty()
}

fn load_openai(
    store: &dyn SecretStore,
    account_id: &str,
) -> Result<OpenAiTokenSet, StoredTokenError> {
    if account_id.trim().is_empty() {
        return Err(StoredTokenError::Corrupt);
    }

    let access = store.get(&openai_access_token_key(account_id))?;
    let refresh = store.get(&openai_refresh_token_key(account_id))?;
    let meta = store.get(&openai_token_meta_key(account_id))?;
    let (access, refresh, meta) = match (access, refresh, meta) {
        (None, None, None) => return Err(StoredTokenError::Missing),
        (Some(access), Some(refresh), Some(meta)) => (access, refresh, meta),
        // A partly written set is not the same as an absent login. Reporting
        // it as corrupt preserves that distinction without ever including the
        // bytes that may contain a credential.
        _ => return Err(StoredTokenError::Corrupt),
    };

    let access_token = String::from_utf8(access).map_err(|_| StoredTokenError::Corrupt)?;
    let refresh_token = String::from_utf8(refresh).map_err(|_| StoredTokenError::Corrupt)?;
    let meta: OpenAiTokenMeta =
        serde_json::from_slice(&meta).map_err(|_| StoredTokenError::Corrupt)?;
    let tokens = OpenAiTokenSet {
        access_token,
        refresh_token,
        expires_at: meta.expires_at,
        client_id: meta.client_id,
        account_id: meta.account_id,
        workspace_id: meta.workspace_id,
        is_fedramp: meta.is_fedramp,
    };
    if !valid_openai_tokens(&tokens, account_id) {
        return Err(StoredTokenError::Corrupt);
    }
    Ok(tokens)
}

/// Loads one provider's credential without ever probing the other provider's
/// keys. OpenAI metadata must name the requested account exactly; accepting a
/// different id would attach one user's credential to another user's row.
pub fn load_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    account_id: &str,
) -> Result<StoredTokens, StoredTokenError> {
    if account_id.trim().is_empty() {
        return Err(StoredTokenError::Corrupt);
    }
    match provider {
        Provider::Anthropic => {
            let raw = store
                .get(&token_key(provider, account_id))?
                .ok_or(StoredTokenError::Missing)?;
            serde_json::from_slice(&raw)
                .map(StoredTokens::Anthropic)
                .map_err(|_| StoredTokenError::Corrupt)
        }
        Provider::Openai => load_openai(store, account_id).map(StoredTokens::Openai),
    }
}

fn check_openai_entry(value: &[u8]) -> Result<(), SecretError> {
    if value.len() > OPENAI_ENTRY_LIMIT {
        return Err(SecretError::TooLong {
            limit: OPENAI_ENTRY_LIMIT,
        });
    }
    Ok(())
}

fn save_openai(
    store: &dyn SecretStore,
    account_id: &str,
    tokens: &OpenAiTokenSet,
) -> Result<(), SecretError> {
    if !valid_openai_tokens(tokens, account_id) {
        return Err(SecretError::Backend(
            "the OpenAI token set does not match the requested account".into(),
        ));
    }

    let meta = serde_json::to_vec(&OpenAiTokenMeta {
        expires_at: tokens.expires_at,
        client_id: tokens.client_id.clone(),
        account_id: tokens.account_id.clone(),
        workspace_id: tokens.workspace_id.clone(),
        is_fedramp: tokens.is_fedramp,
    })
    .map_err(|_| SecretError::Backend("failed to serialize OpenAI token metadata".into()))?;

    // Validate the whole prospective write before touching the store. The
    // metadata check deliberately comes before the refresh write even though
    // metadata is written last.
    check_openai_entry(tokens.refresh_token.as_bytes())?;
    check_openai_entry(tokens.access_token.as_bytes())?;
    check_openai_entry(&meta)?;

    // A refresh-token rotation invalidates the old chain server-side. Preserve
    // the new chain first, then its immediately usable access token, and leave
    // reconstructible metadata last. A failure is still returned, but every
    // successful prefix is the most recoverable prefix possible.
    store.put(
        &openai_refresh_token_key(account_id),
        tokens.refresh_token.as_bytes(),
    )?;
    store.put(
        &openai_access_token_key(account_id),
        tokens.access_token.as_bytes(),
    )?;
    store.put(&openai_token_meta_key(account_id), &meta)
}

/// Stores a credential only under the provider matching its concrete type.
/// Anthropic retains the exact legacy one-key JSON representation; OpenAI is
/// split before it ever reaches a [`SecretStore`].
pub fn save_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    account_id: &str,
    tokens: &StoredTokens,
) -> Result<(), SecretError> {
    if account_id.trim().is_empty() || tokens.provider() != provider {
        return Err(SecretError::Backend(
            "the token set does not match the requested provider or account".into(),
        ));
    }
    match tokens {
        StoredTokens::Anthropic(tokens) => {
            // This is intentionally the same serialization and unprefixed key
            // shipped before providers existed. Any migration here would turn
            // an upgrade into a forced Claude re-login.
            let blob = serde_json::to_vec(tokens)
                .map_err(|_| SecretError::Backend("failed to serialize the token set".into()))?;
            store.put(&token_key(provider, account_id), &blob)
        }
        StoredTokens::Openai(tokens) => save_openai(store, account_id, tokens),
    }
}

/// Deletes every credential entry owned by one `(provider, account_id)` pair.
/// OpenAI attempts all three deletes even if one backend call fails, then
/// reports the first error so the caller cannot mistake partial cleanup for
/// success.
pub fn delete_tokens(
    store: &dyn SecretStore,
    provider: Provider,
    account_id: &str,
) -> Result<bool, SecretError> {
    if account_id.trim().is_empty() {
        return Err(SecretError::Backend("the account id is empty".into()));
    }
    if provider == Provider::Anthropic {
        return store.delete(&token_key(provider, account_id));
    }

    let keys = [
        openai_refresh_token_key(account_id),
        openai_access_token_key(account_id),
        openai_token_meta_key(account_id),
    ];
    let mut removed = false;
    let mut first_error = None;
    for key in keys {
        match store.delete(&key) {
            Ok(found) => removed |= found,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(removed),
    }
}

/// Best-effort provider-aware server revocation. The enum, rather than a
/// caller-supplied URL, decides which vendor receives the live credential.
pub async fn revoke_tokens<H: TokenHttp>(http: &H, cfg: &AuthConfigs, tokens: &StoredTokens) {
    match tokens {
        StoredTokens::Anthropic(tokens) => {
            revoke_anthropic(http, &cfg.anthropic, &tokens.refresh_token).await;
        }
        StoredTokens::Openai(tokens) => openai::revoke(http, &cfg.openai, tokens).await,
    }
}

async fn refresh_tokens<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfigs,
    tokens: &StoredTokens,
) -> Result<StoredTokens, AuthError> {
    match tokens {
        StoredTokens::Anthropic(tokens) => refresh_anthropic(http, &cfg.anthropic, tokens)
            .await
            .map(StoredTokens::Anthropic),
        StoredTokens::Openai(tokens) => openai::refresh(http, &cfg.openai, tokens)
            .await
            .map(StoredTokens::Openai),
    }
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
/// **Takes an account id, never a pre-loaded token set.** Re-reading the store
/// inside the lock is the whole of this function's correctness: the caller that
/// waited on the lock must see what the winner wrote, or both refresh and one
/// of the two chains dies. Accepting an already-loaded value as a parameter — an
/// obvious-looking optimization, since callers have usually just read it —
/// reopens the race completely.
///
/// The caller must not hold any other lock across this call. It awaits a
/// network request of up to 30 seconds.
///
/// **`provider` is part of the identity, not a filter.** Two accounts that
/// share an account-id string across providers are two different accounts
/// (docs/design.md §9.3), so it is threaded into every key and lock lookup
/// alongside the id rather than assumed to be Anthropic.
pub async fn ensure_fresh<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    account_id: &str,
) -> Result<Fresh, StoredTokenError> {
    refresh_if_needed(http, cfg, store, locks, provider, account_id, None).await
}

/// Forces one refresh after a usage endpoint rejected an access token. The
/// rejected token itself is the witness: after taking the per-account lock, a
/// different stored access token means another caller already repaired the
/// failure, so that value is adopted without a second POST.
pub async fn refresh_after_unauthorized<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    account_id: &str,
    rejected_access_token: &str,
) -> Result<Fresh, StoredTokenError> {
    refresh_if_needed(
        http,
        cfg,
        store,
        locks,
        provider,
        account_id,
        Some(rejected_access_token),
    )
    .await
}

async fn refresh_if_needed<H: TokenHttp>(
    http: &H,
    cfg: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    provider: Provider,
    account_id: &str,
    rejected_access_token: Option<&str>,
) -> Result<Fresh, StoredTokenError> {
    let _held = locks.lock_account(provider, account_id).await;

    for _ in 0..MAX_ATTEMPTS {
        let current = load_tokens(store, provider, account_id)?;
        if rejected_access_token.is_some_and(|rejected| current.access_token() != rejected) {
            return Ok(Fresh {
                tokens: current,
                persisted: Ok(()),
            });
        }
        if rejected_access_token.is_none() && !current.needs_refresh() {
            // The double check. A caller that waited on the lock lands here and
            // returns what the winner stored, with no second request. Nothing
            // was written on this path, so there is no write to have failed.
            return Ok(Fresh {
                tokens: current,
                persisted: Ok(()),
            });
        }

        let refresh_witness = current.refresh_token().to_owned();
        let access_witness = current.access_token().to_owned();
        let new = refresh_tokens(http, cfg, &current).await?;

        // Compare-and-swap (§10.5). Every arm is explicit on purpose: a
        // catch-all that falls through to the write is wrong in two distinct
        // ways, and both cost the user a permanently dead account.
        match load_tokens(store, provider, account_id) {
            // Someone stored a different chain underneath us — realistically a
            // re-login landing mid-refresh. §10.5 says adopt it rather than
            // overwrite. `continue` re-reads and re-evaluates freshness, which
            // is what makes "adopt" literal: the token we just obtained is
            // dropped rather than written.
            Ok(stored)
                if stored.refresh_token() != refresh_witness
                    || stored.access_token() != access_witness =>
            {
                continue;
            }
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
        let persisted = save_tokens(store, provider, account_id, &new);
        return Ok(Fresh { tokens: new, persisted });
    }

    // Two adoptions in a row means some third writer keeps storing already
    // stale token sets. Hand back what is actually stored and let the next poll
    // cycle re-evaluate, rather than refreshing in a loop.
    Ok(Fresh {
        tokens: load_tokens(store, provider, account_id)?,
        persisted: Ok(()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::token::ReqwestHttp;
    use crate::secrets::MemoryStore;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use chrono::{TimeDelta, Utc};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const UUID: &str = "acc-1";

    async fn cfg_for(server: &MockServer) -> AuthConfigs {
        AuthConfigs {
            anthropic: ProviderSpec {
                token_url: format!("{}/v1/oauth/token", server.uri()),
                ..Provider::Anthropic.spec()
            },
            openai: OpenAiAuthConfig::default(),
        }
    }

    fn expired_tokens(refresh_token: &str) -> TokenSet {
        TokenSet {
            access_token: "old-at".into(),
            refresh_token: refresh_token.into(),
            expires_at: Utc::now() - TimeDelta::seconds(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: Provider::Anthropic.spec().client_id,
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

    /// Records ordering and can fail one selected operation exactly once. The
    /// in-memory store remains readable after that failure, which lets tests
    /// inspect the precise partial state a restart would encounter.
    #[derive(Default)]
    struct FaultStore {
        inner: MemoryStore,
        puts: Mutex<Vec<String>>,
        deletes: Mutex<Vec<String>>,
        fail_put: Mutex<Option<String>>,
        fail_delete: Mutex<Option<String>>,
    }

    impl FaultStore {
        fn fail_next_put(&self, key: String) {
            *self.fail_put.lock().unwrap() = Some(key);
        }

        fn fail_next_delete(&self, key: String) {
            *self.fail_delete.lock().unwrap() = Some(key);
        }

        fn clear_history(&self) {
            self.puts.lock().unwrap().clear();
            self.deletes.lock().unwrap().clear();
        }
    }

    impl SecretStore for FaultStore {
        fn put(&self, key: &str, value: &[u8]) -> Result<(), SecretError> {
            self.puts.lock().unwrap().push(key.to_string());
            let mut fail = self.fail_put.lock().unwrap();
            if fail.as_deref() == Some(key) {
                fail.take();
                return Err(SecretError::Locked("test".into()));
            }
            drop(fail);
            self.inner.put(key, value)
        }

        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, SecretError> {
            self.inner.get(key)
        }

        fn delete(&self, key: &str) -> Result<bool, SecretError> {
            self.deletes.lock().unwrap().push(key.to_string());
            let mut fail = self.fail_delete.lock().unwrap();
            if fail.as_deref() == Some(key) {
                fail.take();
                return Err(SecretError::Locked("test".into()));
            }
            drop(fail);
            self.inner.delete(key)
        }

        fn describe(&self) -> String {
            "fault-injecting (test only)".to_string()
        }
    }

    /// docs/design.md §10.5 and §14: refreshes are serialized per account. Two
    /// callers race on one uuid and exactly one request must go out.
    ///
    /// The mock is delayed so the first caller actually yields inside the
    /// request. Without a real await point, `tokio::join!` on the default
    /// current-thread runtime runs the first future to completion before
    /// polling the second, and the test would pass with the lock removed —
    /// the "test that cannot fail" AGENTS.md forbids. For the same reason the
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
        assert_eq!(a.unwrap().tokens.refresh_token(), "rt-1");
        assert_eq!(b.unwrap().tokens.refresh_token(), "rt-1", "the waiter re-read stale state");
    }

    #[tokio::test]
    async fn an_external_account_write_can_share_the_refresh_lock() {
        let locks = RefreshLocks::default();
        let held = locks.lock_account(Provider::Openai, UUID).await;

        assert!(locks.is_refreshing(Provider::Openai, UUID));
        assert!(
            !locks.is_refreshing(Provider::Anthropic, UUID),
            "the same id under another provider shared the write lock"
        );

        drop(held);
        assert!(!locks.is_refreshing(Provider::Openai, UUID));
    }

    /// A 401 forces a refresh even when the access token's clock says it is
    /// fresh. Both callers carry the same rejected token as a witness; after
    /// the first writes its replacement, the waiter must adopt it and avoid a
    /// second POST.
    #[tokio::test]
    async fn concurrent_forced_refreshes_send_exactly_one_request() {
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
            .put(
                &token_key(Provider::Anthropic, UUID),
                &serde_json::to_vec(&fresh_tokens("rt-0")).unwrap(),
            )
            .unwrap();
        let locks = RefreshLocks::default();
        let http = ReqwestHttp::new().unwrap();
        let cfg = cfg_for(&server).await;

        let (a, b) = tokio::join!(
            refresh_after_unauthorized(
                &http,
                &cfg,
                &store,
                &locks,
                Provider::Anthropic,
                UUID,
                "old-at",
            ),
            refresh_after_unauthorized(
                &http,
                &cfg,
                &store,
                &locks,
                Provider::Anthropic,
                UUID,
                "old-at",
            ),
        );

        assert_eq!(
            posts.load(Ordering::SeqCst),
            1,
            "the rejected witness was ignored"
        );
        assert_eq!(a.unwrap().tokens.access_token(), "new-at");
        assert_eq!(b.unwrap().tokens.access_token(), "new-at");
    }

    #[tokio::test]
    async fn a_changed_access_token_is_adopted_without_a_forced_request() {
        // No mock is mounted. A request would receive wiremock's 404 and make
        // the unwrap below fail.
        let server = MockServer::start().await;
        let store = CountingStore::default();
        let changed = TokenSet {
            access_token: "replacement-at".into(),
            ..fresh_tokens("rt-1")
        };
        store
            .inner
            .put(
                &token_key(Provider::Anthropic, UUID),
                &serde_json::to_vec(&changed).unwrap(),
            )
            .unwrap();

        let out = refresh_after_unauthorized(
            &ReqwestHttp::new().unwrap(),
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
            "rejected-at",
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.access_token(), "replacement-at");
        assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn concurrent_openai_401_recovery_rotates_once_and_adopts_the_winner() {
        let server = MockServer::start().await;
        let replacement = jwt_with_exp((Utc::now() + TimeDelta::hours(1)).timestamp());
        let posts = Arc::new(AtomicUsize::new(0));
        let counter = posts.clone();
        Mock::given(method("POST"))
            .respond_with({
                let replacement = replacement.clone();
                move |_: &Request| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({
                            "access_token": replacement,
                            "refresh_token": "new-openai-rt"
                        }))
                        .set_delay(std::time::Duration::from_millis(50))
                }
            })
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(openai_tokens("rejected-openai-at", "old-openai-rt")),
        )
        .unwrap();
        let locks = RefreshLocks::default();
        let cfg = openai_cfg_for(&server);
        let http = ReqwestHttp::new().unwrap();

        let (a, b) = tokio::join!(
            refresh_after_unauthorized(
                &http,
                &cfg,
                &store,
                &locks,
                Provider::Openai,
                UUID,
                "rejected-openai-at",
            ),
            refresh_after_unauthorized(
                &http,
                &cfg,
                &store,
                &locks,
                Provider::Openai,
                UUID,
                "rejected-openai-at",
            ),
        );

        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(a.unwrap().tokens.access_token(), replacement);
        assert_eq!(b.unwrap().tokens.access_token(), replacement);
        assert_eq!(
            load_tokens(&store, Provider::Openai, UUID)
                .unwrap()
                .refresh_token(),
            "new-openai-rt"
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

        assert_eq!(out.tokens.refresh_token(), "rt-1", "the live rotated token was discarded");
        // Pins the error itself, not just that one occurred: reducing this to a
        // boolean is what §9.2/§9.3 forbid, and asserting `is_err()` alone
        // would keep passing if it were.
        assert!(
            matches!(out.persisted, Err(SecretError::Locked(_))),
            "the store error must reach the caller, got {:?}",
            out.persisted
        );
    }

    #[tokio::test]
    async fn a_partial_openai_rotation_returns_live_tokens_and_the_durability_error() {
        let server = MockServer::start().await;
        let replacement = jwt_with_exp((Utc::now() + TimeDelta::hours(1)).timestamp());
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": replacement,
                "refresh_token": "new-openai-rt"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let store = FaultStore::default();
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(openai_tokens("rejected-at", "old-openai-rt")),
        )
        .unwrap();
        store.fail_next_put(openai_token_meta_key(UUID));

        let out = refresh_after_unauthorized(
            &ReqwestHttp::new().unwrap(),
            &openai_cfg_for(&server),
            &store,
            &RefreshLocks::default(),
            Provider::Openai,
            UUID,
            "rejected-at",
        )
        .await
        .unwrap();

        assert_eq!(out.tokens.access_token(), replacement);
        assert_eq!(out.tokens.refresh_token(), "new-openai-rt");
        assert!(matches!(out.persisted, Err(SecretError::Locked(_))));
        let partial = load_tokens(&store, Provider::Openai, UUID).unwrap();
        assert_eq!(partial.access_token(), replacement);
        assert_eq!(partial.refresh_token(), "new-openai-rt");
    }

    /// `Fresh` carries a live credential, so its hand-written `Debug` must keep
    /// delegating only to redacted token output.
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
            matches!(err, StoredTokenError::Auth(ref e) if e.is_dead_grant()),
            "the dead-grant flag did not survive the wrapper, got {err:?}"
        );
    }

    /// OpenAI has provider-specific terminal refresh responses. Recognising
    /// those must not turn a generic Anthropic 401 into `AUTH_DEAD`; only
    /// Anthropic's measured `invalid_grant` code is terminal.
    #[tokio::test]
    async fn an_arbitrary_anthropic_401_is_not_a_terminal_refresh_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "unauthorized"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let store = MemoryStore::default();
        store
            .put(&token_key(Provider::Anthropic, UUID), &serde_json::to_vec(&expired_tokens("rt-0")).unwrap())
            .unwrap();

        let err = ensure_fresh(
            &ReqwestHttp::new().unwrap(),
            &cfg_for(&server).await,
            &store,
            &RefreshLocks::default(),
            Provider::Anthropic,
            UUID,
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, StoredTokenError::Auth(ref e) if !e.is_dead_grant()),
            "a non-invalid_grant Anthropic response became terminal: {err:?}"
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

    fn openai_tokens(access: &str, refresh: &str) -> OpenAiTokenSet {
        OpenAiTokenSet {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_at: Utc::now() + TimeDelta::hours(2),
            client_id: "openai-client".into(),
            account_id: UUID.into(),
            workspace_id: "workspace-1".into(),
            is_fedramp: false,
        }
    }

    fn jwt_with_exp(exp: i64) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::json!({ "exp": exp }).to_string());
        format!("e30.{payload}.signature")
    }

    fn openai_cfg_for(server: &MockServer) -> AuthConfigs {
        AuthConfigs {
            anthropic: Provider::Anthropic.spec(),
            openai: OpenAiAuthConfig {
                issuer: server.uri(),
                client_id: "openai-client".into(),
            },
        }
    }

    /// The split is a storage property, not merely an implementation detail:
    /// neither token may be copied into JSON beside the other one, or the
    /// Windows credential-size failure returns.
    #[test]
    fn openai_tokens_are_stored_as_two_raw_entries_and_metadata() {
        let store = MemoryStore::default();
        let tokens = StoredTokens::Openai(openai_tokens("at-SENTINEL", "rt-SENTINEL"));

        save_tokens(&store, Provider::Openai, UUID, &tokens).unwrap();

        assert_eq!(
            store
                .get(&openai_access_token_key(UUID))
                .unwrap()
                .as_deref(),
            Some(&b"at-SENTINEL"[..])
        );
        assert_eq!(
            store
                .get(&openai_refresh_token_key(UUID))
                .unwrap()
                .as_deref(),
            Some(&b"rt-SENTINEL"[..])
        );
        let meta = store.get(&openai_token_meta_key(UUID)).unwrap().unwrap();
        assert!(!meta.windows(b"SENTINEL".len()).any(|w| w == b"SENTINEL"));

        let loaded = load_tokens(&store, Provider::Openai, UUID).unwrap();
        assert_eq!(loaded.access_token(), "at-SENTINEL");
        assert_eq!(loaded.refresh_token(), "rt-SENTINEL");
    }

    /// All three sizes are checked before any write. Checking lazily would
    /// rotate the refresh entry and only then discover oversized metadata,
    /// leaving the credential half-written.
    #[test]
    fn an_oversized_openai_entry_is_rejected_before_any_store_write() {
        let cases = [
            openai_tokens(&"a".repeat(OPENAI_ENTRY_LIMIT + 1), "rt"),
            openai_tokens("at", &"r".repeat(OPENAI_ENTRY_LIMIT + 1)),
            // Two bytes per character: the limit is bytes, not Rust `char`s.
            openai_tokens(&"é".repeat(OPENAI_ENTRY_LIMIT / 2 + 1), "rt"),
            {
                let mut tokens = openai_tokens("at", "rt");
                tokens.workspace_id = "w".repeat(OPENAI_ENTRY_LIMIT + 1);
                tokens
            },
        ];

        for tokens in cases {
            let store = CountingStore::default();
            let err = save_tokens(
                &store,
                Provider::Openai,
                UUID,
                &StoredTokens::Openai(tokens),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                SecretError::TooLong {
                    limit: OPENAI_ENTRY_LIMIT
                }
            ));
            assert_eq!(
                store.puts.load(Ordering::SeqCst),
                0,
                "validation ran after a write"
            );
        }

        let store = CountingStore::default();
        let tokens = openai_tokens(&"a".repeat(OPENAI_ENTRY_LIMIT), "rt");
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(tokens),
        )
        .unwrap();
        assert_eq!(
            store.puts.load(Ordering::SeqCst),
            3,
            "the inclusive limit was refused"
        );
    }

    #[test]
    fn saving_a_token_as_the_wrong_provider_is_refused_without_a_write() {
        let store = CountingStore::default();
        let err = save_tokens(
            &store,
            Provider::Anthropic,
            UUID,
            &StoredTokens::Openai(openai_tokens("at", "rt")),
        )
        .unwrap_err();

        assert!(matches!(err, SecretError::Backend(_)));
        assert_eq!(store.puts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn anthropic_keeps_its_legacy_key_and_blob_byte_for_byte() {
        let store = MemoryStore::default();
        let tokens = TokenSet {
            access_token: "legacy-at".into(),
            refresh_token: "legacy-rt".into(),
            expires_at: "2026-09-04T01:02:03Z".parse().unwrap(),
            refresh_token_expires_at: "2026-10-04T01:02:03Z".parse().unwrap(),
            scopes: vec!["user:profile".into()],
            client_id: "legacy-client".into(),
        };

        save_tokens(
            &store,
            Provider::Anthropic,
            UUID,
            &StoredTokens::Anthropic(tokens),
        )
        .unwrap();

        assert_eq!(
            store.get("acc-1:tokens").unwrap().as_deref(),
            Some(
                &br#"{"access_token":"legacy-at","refresh_token":"legacy-rt","expires_at":"2026-09-04T01:02:03Z","refresh_token_expires_at":"2026-10-04T01:02:03Z","scopes":["user:profile"],"client_id":"legacy-client"}"#[..]
            )
        );
    }

    #[test]
    fn openai_refresh_writes_the_most_recoverable_value_first() {
        let store = FaultStore::default();
        let tokens = StoredTokens::Openai(openai_tokens("at", "rt"));

        save_tokens(&store, Provider::Openai, UUID, &tokens).unwrap();

        assert_eq!(
            *store.puts.lock().unwrap(),
            [
                openai_refresh_token_key(UUID),
                openai_access_token_key(UUID),
                openai_token_meta_key(UUID),
            ]
        );
    }

    /// If the second write fails, the rotating refresh chain has still moved
    /// forward while the old access token and metadata remain readable. A
    /// later retry can therefore use the only refresh token the server still
    /// accepts instead of falling back to the dead one.
    #[test]
    fn a_partial_openai_write_preserves_the_new_refresh_chain_and_can_recover() {
        let store = FaultStore::default();
        let mut old = openai_tokens("old-at", "old-rt");
        old.expires_at = Utc::now() - TimeDelta::seconds(1);
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(old.clone()),
        )
        .unwrap();
        store.clear_history();

        let new = openai_tokens("new-at", "new-rt");
        store.fail_next_put(openai_access_token_key(UUID));
        let err = save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(new.clone()),
        )
        .unwrap_err();
        assert!(matches!(err, SecretError::Locked(_)));

        let mixed = load_tokens(&store, Provider::Openai, UUID).unwrap();
        assert_eq!(
            mixed.refresh_token(),
            "new-rt",
            "the live chain was not preserved"
        );
        assert_eq!(
            mixed.access_token(),
            "old-at",
            "a failed access write changed the value"
        );
        assert!(
            mixed.needs_refresh(),
            "old metadata no longer prompts recovery"
        );

        save_tokens(&store, Provider::Openai, UUID, &StoredTokens::Openai(new)).unwrap();
        let recovered = load_tokens(&store, Provider::Openai, UUID).unwrap();
        assert_eq!(recovered.access_token(), "new-at");
        assert_eq!(recovered.refresh_token(), "new-rt");
    }

    #[test]
    fn a_failed_metadata_write_keeps_both_new_tokens_with_recoverable_old_metadata() {
        let store = FaultStore::default();
        let mut old = openai_tokens("old-at", "old-rt");
        old.expires_at = Utc::now() - TimeDelta::seconds(1);
        save_tokens(&store, Provider::Openai, UUID, &StoredTokens::Openai(old)).unwrap();
        store.fail_next_put(openai_token_meta_key(UUID));

        let new = openai_tokens("new-at", "new-rt");
        let err =
            save_tokens(&store, Provider::Openai, UUID, &StoredTokens::Openai(new)).unwrap_err();

        assert!(matches!(err, SecretError::Locked(_)));
        let mixed = load_tokens(&store, Provider::Openai, UUID).unwrap();
        assert_eq!(mixed.access_token(), "new-at");
        assert_eq!(mixed.refresh_token(), "new-rt");
        assert!(
            mixed.needs_refresh(),
            "old metadata did not make the partial set recoverable"
        );
    }

    #[test]
    fn an_incomplete_openai_set_is_corrupt_not_absent() {
        let store = MemoryStore::default();
        store
            .put(&openai_refresh_token_key(UUID), b"rt-SENTINEL")
            .unwrap();

        let err = load_tokens(&store, Provider::Openai, UUID).unwrap_err();

        assert!(matches!(err, StoredTokenError::Corrupt));
        assert!(!format!("{err:?}").contains("SENTINEL"));
    }

    #[test]
    fn openai_load_rejects_an_empty_or_mismatched_identity_without_leaking_it() {
        let store = MemoryStore::default();
        store
            .put(&openai_access_token_key(UUID), b"at-SENTINEL")
            .unwrap();
        store
            .put(&openai_refresh_token_key(UUID), b"rt-SENTINEL")
            .unwrap();
        let meta = OpenAiTokenMeta {
            expires_at: Utc::now() + TimeDelta::hours(1),
            client_id: "client".into(),
            account_id: "different-SENTINEL".into(),
            workspace_id: "workspace".into(),
            is_fedramp: false,
        };
        store
            .put(
                &openai_token_meta_key(UUID),
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();

        let err = load_tokens(&store, Provider::Openai, UUID).unwrap_err();
        assert!(matches!(err, StoredTokenError::Corrupt));
        assert!(!format!("{err:?}").contains("SENTINEL"));
        assert!(!err.to_string().contains("SENTINEL"));

        let err = load_tokens(&store, Provider::Openai, "").unwrap_err();
        assert!(matches!(err, StoredTokenError::Corrupt));
    }

    #[test]
    fn openai_load_rejects_every_empty_stored_identifier() {
        for field in ["client_id", "account_id", "workspace_id"] {
            let store = MemoryStore::default();
            store.put(&openai_access_token_key(UUID), b"at").unwrap();
            store.put(&openai_refresh_token_key(UUID), b"rt").unwrap();
            let mut meta = OpenAiTokenMeta {
                expires_at: Utc::now() + TimeDelta::hours(1),
                client_id: "client".into(),
                account_id: UUID.into(),
                workspace_id: "workspace".into(),
                is_fedramp: false,
            };
            match field {
                "client_id" => meta.client_id = "  ".into(),
                "account_id" => meta.account_id = "  ".into(),
                "workspace_id" => meta.workspace_id = "  ".into(),
                _ => unreachable!(),
            }
            store
                .put(
                    &openai_token_meta_key(UUID),
                    &serde_json::to_vec(&meta).unwrap(),
                )
                .unwrap();

            assert!(
                matches!(
                    load_tokens(&store, Provider::Openai, UUID),
                    Err(StoredTokenError::Corrupt)
                ),
                "empty {field} was accepted"
            );
        }
    }

    #[test]
    fn openai_delete_attempts_every_split_entry_even_after_an_error() {
        let store = FaultStore::default();
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(openai_tokens("at", "rt")),
        )
        .unwrap();
        store.clear_history();
        store.fail_next_delete(openai_access_token_key(UUID));

        let err = delete_tokens(&store, Provider::Openai, UUID).unwrap_err();

        assert!(matches!(err, SecretError::Locked(_)));
        assert_eq!(
            *store.deletes.lock().unwrap(),
            [
                openai_refresh_token_key(UUID),
                openai_access_token_key(UUID),
                openai_token_meta_key(UUID),
            ]
        );
        assert_eq!(store.get(&openai_refresh_token_key(UUID)).unwrap(), None);
        assert_eq!(store.get(&openai_token_meta_key(UUID)).unwrap(), None);
        assert_eq!(
            store
                .get(&openai_access_token_key(UUID))
                .unwrap()
                .as_deref(),
            Some(&b"at"[..])
        );
    }

    #[test]
    fn deleting_openai_does_not_touch_anthropic_with_the_same_id() {
        let store = MemoryStore::default();
        let anthropic = expired_tokens("anthropic-rt");
        store
            .put(
                &token_key(Provider::Anthropic, UUID),
                &serde_json::to_vec(&anthropic).unwrap(),
            )
            .unwrap();
        save_tokens(
            &store,
            Provider::Openai,
            UUID,
            &StoredTokens::Openai(openai_tokens("openai-at", "openai-rt")),
        )
        .unwrap();

        assert!(delete_tokens(&store, Provider::Openai, UUID).unwrap());

        assert!(store
            .get(&token_key(Provider::Anthropic, UUID))
            .unwrap()
            .is_some());
        assert!(matches!(
            load_tokens(&store, Provider::Openai, UUID),
            Err(StoredTokenError::Missing)
        ));
    }

    #[tokio::test]
    async fn revocation_dispatches_each_token_only_to_its_own_provider() {
        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/anthropic/revoke"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&anthropic_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/revoke"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&openai_server)
            .await;
        let cfg = AuthConfigs {
            anthropic: ProviderSpec {
                revoke_url: format!("{}/anthropic/revoke", anthropic_server.uri()),
                ..Provider::Anthropic.spec()
            },
            openai: OpenAiAuthConfig {
                issuer: openai_server.uri(),
                client_id: "openai-client".into(),
            },
        };
        let http = ReqwestHttp::new().unwrap();

        revoke_tokens(
            &http,
            &cfg,
            &StoredTokens::Anthropic(expired_tokens("anthropic-rt")),
        )
        .await;
        revoke_tokens(
            &http,
            &cfg,
            &StoredTokens::Openai(openai_tokens("openai-at", "openai-rt")),
        )
        .await;
    }

    #[test]
    fn provider_wrappers_redact_both_openai_tokens() {
        let tokens = StoredTokens::Openai(openai_tokens("at-SENTINEL", "rt-SENTINEL"));
        assert_eq!(tokens.workspace_id(), Some("workspace-1"));
        assert!(!tokens.is_fedramp());
        let printed = format!("{tokens:?}");
        assert!(
            !printed.contains("SENTINEL"),
            "StoredTokens leaked a token: {printed}"
        );
        assert!(printed.contains("<redacted>"));

        let fresh = Fresh {
            tokens,
            persisted: Ok(()),
        };
        let printed = format!("{fresh:?}");
        assert!(
            !printed.contains("SENTINEL"),
            "Fresh leaked a token: {printed}"
        );
        assert!(printed.contains("persisted"));
    }
}
