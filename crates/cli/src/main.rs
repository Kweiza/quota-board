//! Headless smoke tool. Exercises login, query, and refresh for real, with no GUI.
//!
//! Usage:
//!   quota-cli login                         — add one Claude account via browser OAuth
//!   quota-cli show [<provider>:<account>]   — print usage, optionally for one exact pair
//!   quota-cli refresh <provider>:<account>  — force-refresh that account's token

use quota_core::accounts::{Account, AccountStore};
use quota_core::auth::callback::Callback;
use quota_core::auth::pkce::{begin, success_redirect};
use quota_core::auth::stored::{
    ensure_fresh, load_tokens, refresh_after_unauthorized, AuthConfigs, Fresh, RefreshLocks,
    StoredTokenError, StoredTokens,
};
use quota_core::auth::token::{exchange_code, ReqwestHttp};
use quota_core::paths::accounts_file;
use quota_core::provider::{token_key, Provider};
use quota_core::secrets::{keychain::KeychainStore, SecretStore, SERVICE};
use quota_core::usage::http::{
    fetch_usage_for_account_at, OPENAI_USAGE_URL, USAGE_URL,
};

fn open_store() -> Box<dyn SecretStore> {
    match KeychainStore::probe(SERVICE) {
        Ok(s) => {
            eprintln!("store: {}", s.describe());
            Box::new(s)
        }
        Err(e) => {
            eprintln!("keychain unavailable ({e}).");
            eprintln!("the CLI does not use the fallback store — EncryptedFileStore is for the GUI only.");
            std::process::exit(1);
        }
    }
}

async fn cmd_login() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Provider::Anthropic.spec();
    let cb = Callback::bind().await?;
    let (pending, url) = begin(&cfg, &cb.redirect_uri())?;

    println!("Open this URL in your browser:\n\n{url}\n");
    println!("(The consent screen will say 'Claude Code' — we reuse its public client_id.)");

    let params = cb.wait_for_code(success_redirect(), &pending.state).await?;
    let code = params.get("code").ok_or("the callback carried no code")?;
    let state = params.get("state").ok_or("the callback carried no state")?;

    let http = ReqwestHttp::new()?;
    // `Provider::Anthropic`: this CLI has no Codex login flow yet.
    let (tokens, identity) = exchange_code(&http, &cfg, Provider::Anthropic, &pending, code, state).await?;
    let identity = identity.ok_or("the token response carried no account block — there is no uuid to key by")?;

    // The token key format belongs to `provider::token_key` — not re-derived
    // here, that is the only place it is built. `Provider::Anthropic` because
    // this CLI has no Codex login flow yet.
    open_store()
        .put(&token_key(Provider::Anthropic, &identity.uuid), &serde_json::to_vec(&tokens)?)?;

    let mut accounts = AccountStore::load(&accounts_file());
    accounts.upsert(Account {
        account_id: identity.uuid.clone(),
        provider: Provider::Anthropic,
        workspace_id: None,
        is_fedramp: false,
        display_label: identity.email.clone(),
        email: identity.email,
        created_at: chrono::Utc::now(),
        last_ok_at: None,
        quarantined: false,
        sort_order: 0,
    })?;

    println!("added: {}", identity.uuid);
    println!("scopes: {}", tokens.scopes.join(" "));
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccountSelector {
    provider: Provider,
    account_id: String,
}

impl AccountSelector {
    fn matches(&self, account: &Account) -> bool {
        self.provider == account.provider && self.account_id == account.account_id
    }

    fn as_arg(&self) -> String {
        format!("{}:{}", self.provider.as_str(), self.account_id)
    }
}

fn parse_account_selector(raw: &str) -> Result<AccountSelector, String> {
    let (provider, account_id) = raw.split_once(':').ok_or_else(|| {
        "account selectors must be explicit: anthropic:<id> or openai:<id>".to_string()
    })?;
    let provider = match provider {
        "anthropic" => Provider::Anthropic,
        "openai" => Provider::Openai,
        _ => {
            return Err(
                "account selectors must be explicit: anthropic:<id> or openai:<id>".into(),
            );
        }
    };
    if account_id.trim().is_empty() {
        return Err("the account selector has an empty id".into());
    }
    Ok(AccountSelector { provider, account_id: account_id.to_string() })
}

#[derive(Clone, Copy)]
struct UsageEndpoints<'a> {
    anthropic: &'a str,
    openai: &'a str,
}

impl<'a> UsageEndpoints<'a> {
    fn for_provider(self, provider: Provider) -> &'a str {
        match provider {
            Provider::Anthropic => self.anthropic,
            Provider::Openai => self.openai,
        }
    }
}

#[derive(Default)]
struct ShowOutput {
    matched: usize,
    lines: Vec<String>,
    diagnostics: Vec<String>,
}

/// The network-bearing half of `show`, with both stores and URLs injected so
/// tests can keep every request on loopback.
async fn show_accounts_at(
    accounts: &[Account],
    only: Option<&AccountSelector>,
    store: &dyn SecretStore,
    http: &ReqwestHttp,
    cfg: &AuthConfigs,
    locks: &RefreshLocks,
    endpoints: UsageEndpoints<'_>,
) -> ShowOutput {
    let mut output = ShowOutput::default();
    for account in accounts {
        if only.is_some_and(|selector| !selector.matches(account)) {
            continue;
        }
        output.matched += 1;

        let fresh = match ensure_fresh(
            http,
            cfg,
            store,
            locks,
            account.provider,
            &account.account_id,
        )
        .await
        {
            Ok(fresh) => fresh,
            Err(error) => {
                output.lines.push(format!(
                    "{} [{}]: {error}",
                    account.display_label,
                    account.provider.as_str()
                ));
                continue;
            }
        };
        if let Err(error) = &fresh.persisted {
            output.diagnostics.push(format!(
                "{} [{}]: the token was rotated but could not be stored ({error}) — the next run may not see it",
                account.display_label,
                account.provider.as_str()
            ));
        }

        match fetch_usage_for_account_at(
            http,
            account.provider,
            endpoints.for_provider(account.provider),
            fresh.tokens.access_token(),
            fresh.tokens.workspace_id(),
            fresh.tokens.is_fedramp(),
        )
        .await
        {
            Ok(windows) => {
                output.lines.push(format!(
                    "{} [{}]:",
                    account.display_label,
                    account.provider.as_str()
                ));
                output.lines.extend(windows.into_iter().map(|window| {
                    format!(
                        "  {:<16} {:>5.1}%  resets {}",
                        window.label, window.percent, window.resets_at
                    )
                }));
            }
            Err(error) => output.lines.push(format!(
                "{} [{}]: {error}",
                account.display_label,
                account.provider.as_str()
            )),
        }
    }
    output
}

/// With `only` given, queries just that exact `(provider, account_id)` pair.
///
/// **That narrowing is why the flag exists**, not a convenience. Any question
/// about how the 429 budget is *scoped* needs asymmetric load: hitting every
/// account equally drains every account equally, so a per-account budget and a
/// per-IP budget produce the same observation. Saturating one account while
/// leaving the others untouched, then probing them, is the only shape that
/// separates the two — see docs/research/usage-endpoint.md, Spike D.
async fn cmd_show(only: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Parse before opening a credential store. A bare id is ambiguous by
    // definition and must fail before any provider's key can be touched.
    let selector = only.map(parse_account_selector).transpose()?;
    let store = open_store();
    let accounts = AccountStore::load(&accounts_file());
    let http = ReqwestHttp::new()?;
    let cfg = AuthConfigs::default();

    // Task 10b owns the read -> refresh -> write sequence. Reimplementing it
    // inline here would produce a second copy with neither the lock nor the CAS.
    let locks = RefreshLocks::default();

    let output = show_accounts_at(
        accounts.list(),
        selector.as_ref(),
        store.as_ref(),
        &http,
        &cfg,
        &locks,
        UsageEndpoints { anthropic: USAGE_URL, openai: OPENAI_USAGE_URL },
    )
    .await;
    if let Some(selector) = &selector {
        if output.matched == 0 {
            return Err(format!("no account matches {}", selector.as_arg()).into());
        }
    }
    for diagnostic in output.diagnostics {
        eprintln!("{diagnostic}");
    }
    for line in output.lines {
        println!("{line}");
    }
    Ok(())
}

/// Forces the selected provider's refresh protocol through the same lock and
/// compare-and-swap path as 401 recovery. The currently stored access token is
/// the rejection witness, so this rotates even when its expiry is still far
/// away; if another writer wins before the lock is acquired, that replacement
/// is adopted instead.
async fn force_refresh_account(
    http: &ReqwestHttp,
    cfg: &AuthConfigs,
    store: &dyn SecretStore,
    locks: &RefreshLocks,
    selector: &AccountSelector,
) -> Result<Fresh, StoredTokenError> {
    let current = load_tokens(store, selector.provider, &selector.account_id)?;
    let rejected_access_token = current.access_token().to_owned();
    refresh_after_unauthorized(
        http,
        cfg,
        store,
        locks,
        selector.provider,
        &selector.account_id,
        &rejected_access_token,
    )
    .await
}

async fn cmd_refresh(raw_selector: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Parse first for the same reason as `show`: a bare id must never select
    // whichever provider happens to be checked first.
    let selector = parse_account_selector(raw_selector)?;
    let store = open_store();
    let http = ReqwestHttp::new()?;
    let fresh = force_refresh_account(
        &http,
        &AuthConfigs::default(),
        store.as_ref(),
        &RefreshLocks::default(),
        &selector,
    )
    .await?;
    if let Err(error) = &fresh.persisted {
        return Err(format!(
            "{} was refreshed, but the live token could not be stored: {error}",
            selector.as_arg()
        )
        .into());
    }
    match &fresh.tokens {
        StoredTokens::Anthropic(tokens) => {
            println!("refreshed. new expiry: {}", tokens.expires_at);
            println!("scopes: {}", tokens.scopes.join(" "));
        }
        StoredTokens::Openai(tokens) => {
            println!("refreshed. new expiry: {}", tokens.expires_at);
            println!("workspace: {}", tokens.workspace_id);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") => cmd_login().await,
        Some("show") => cmd_show(args.get(2).map(String::as_str)).await,
        Some("refresh") => cmd_refresh(
            args.get(2)
                .ok_or("an explicit provider and account id are required")?,
        )
        .await,
        _ => {
            eprintln!("usage: quota-cli login | show [<provider>:<id>] | refresh <provider>:<id>");
            eprintln!("providers: anthropic, openai");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeDelta, Utc};
    use quota_core::auth::openai::{OpenAiAuthConfig, OpenAiTokenSet};
    use quota_core::auth::stored::{load_tokens, save_tokens, StoredTokens};
    use quota_core::auth::token::TokenSet;
    use quota_core::secrets::MemoryStore;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SAME_ID: &str = "same-id";
    const FUTURE_OPENAI_JWT: &str = "e30.eyJleHAiOjQxMDI0NDQ4MDB9.sig";

    fn account(provider: Provider) -> Account {
        Account {
            account_id: SAME_ID.into(),
            provider,
            // Intentionally differs from the stored token. Usage routing must
            // follow the credential that produced the bearer, not stale
            // account metadata left behind by an interrupted metadata write.
            workspace_id: (provider == Provider::Openai)
                .then(|| "stale-metadata-workspace".into()),
            is_fedramp: false,
            display_label: format!("{} account", provider.as_str()),
            email: format!("{}@example.invalid", provider.as_str()),
            created_at: Utc::now(),
            last_ok_at: None,
            quarantined: false,
            sort_order: 0,
        }
    }

    fn anthropic_tokens(access: &str, refresh: &str) -> TokenSet {
        TokenSet {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            refresh_token_expires_at: Utc::now() + TimeDelta::days(30),
            scopes: vec!["user:profile".into()],
            client_id: Provider::Anthropic.spec().client_id,
        }
    }

    fn openai_tokens(access: &str, refresh: &str) -> OpenAiTokenSet {
        OpenAiTokenSet {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_at: Utc::now() + TimeDelta::hours(1),
            client_id: "openai-client".into(),
            account_id: SAME_ID.into(),
            workspace_id: "workspace-openai".into(),
            is_fedramp: true,
        }
    }

    fn seed_same_id(store: &MemoryStore) {
        save_tokens(
            store,
            Provider::Anthropic,
            SAME_ID,
            &StoredTokens::Anthropic(anthropic_tokens("claude-at", "claude-rt")),
        )
        .unwrap();
        save_tokens(
            store,
            Provider::Openai,
            SAME_ID,
            &StoredTokens::Openai(openai_tokens("codex-at", "codex-rt")),
        )
        .unwrap();
    }

    fn anthropic_usage() -> serde_json::Value {
        serde_json::json!({
            "five_hour": { "utilization": 12, "resets_at": "2099-01-01T00:00:00Z" },
            "seven_day": null
        })
    }

    fn openai_usage() -> serde_json::Value {
        serde_json::json!({
            "rate_limit": {
                "primary_window": {
                    "used_percent": 34,
                    "limit_window_seconds": 18000,
                    "reset_at": 4070908800_i64
                }
            }
        })
    }

    #[test]
    fn selectors_require_the_full_provider_and_account_pair() {
        assert_eq!(
            parse_account_selector("anthropic:same-id").unwrap(),
            AccountSelector { provider: Provider::Anthropic, account_id: SAME_ID.into() }
        );
        assert_eq!(
            parse_account_selector("openai:same-id").unwrap(),
            AccountSelector { provider: Provider::Openai, account_id: SAME_ID.into() }
        );
        for invalid in ["same-id", "claude:same-id", "codex:same-id", "openai:", ":same-id"] {
            assert!(parse_account_selector(invalid).is_err(), "accepted ambiguous {invalid:?}");
        }
    }

    /// Two providers deliberately share the same id here. Passing this test
    /// requires all four dispatches to agree: account selection, credential
    /// key, usage URL, and OpenAI-only workspace headers.
    #[tokio::test]
    async fn show_keeps_same_id_accounts_on_their_own_endpoint_key_and_context() {
        let anthropic_server = MockServer::start().await;
        let openai_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/claude-usage"))
            .and(header("authorization", "Bearer claude-at"))
            .and(header("anthropic-beta", "oauth-2025-04-20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_usage()))
            .expect(1)
            .mount(&anthropic_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/codex-usage"))
            .and(header("authorization", "Bearer codex-at"))
            .and(header("chatgpt-account-id", "workspace-openai"))
            .and(header("x-openai-fedramp", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_usage()))
            .expect(1)
            .mount(&openai_server)
            .await;

        let store = MemoryStore::default();
        seed_same_id(&store);
        let accounts = [account(Provider::Anthropic), account(Provider::Openai)];
        let output = show_accounts_at(
            &accounts,
            None,
            &store,
            &ReqwestHttp::new().unwrap(),
            &AuthConfigs::default(),
            &RefreshLocks::default(),
            UsageEndpoints {
                anthropic: &format!("{}/claude-usage", anthropic_server.uri()),
                openai: &format!("{}/codex-usage", openai_server.uri()),
            },
        )
        .await;

        assert_eq!(output.matched, 2);
        assert!(output.lines.iter().any(|line| line.contains("anthropic account [anthropic]")));
        assert!(output.lines.iter().any(|line| line.contains("openai account [openai]")));
        assert!(store.get(&token_key(Provider::Anthropic, SAME_ID)).unwrap().is_some());
        assert!(store.get(&token_key(Provider::Openai, SAME_ID)).unwrap().is_none());

        let anthropic_request = &anthropic_server.received_requests().await.unwrap()[0];
        assert!(anthropic_request.headers.get("chatgpt-account-id").is_none());
        assert!(anthropic_request.headers.get("x-openai-fedramp").is_none());
        let openai_request = &openai_server.received_requests().await.unwrap()[0];
        assert!(openai_request.headers.get("anthropic-beta").is_none());
    }

    #[tokio::test]
    async fn show_selector_never_falls_through_to_the_same_id_at_another_provider() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/codex"))
            .respond_with(ResponseTemplate::new(200).set_body_json(openai_usage()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/claude"))
            .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_usage()))
            .expect(0)
            .mount(&server)
            .await;
        let store = MemoryStore::default();
        seed_same_id(&store);
        let accounts = [account(Provider::Anthropic), account(Provider::Openai)];
        let selector = parse_account_selector("openai:same-id").unwrap();

        let output = show_accounts_at(
            &accounts,
            Some(&selector),
            &store,
            &ReqwestHttp::new().unwrap(),
            &AuthConfigs::default(),
            &RefreshLocks::default(),
            UsageEndpoints {
                anthropic: &format!("{}/claude", server.uri()),
                openai: &format!("{}/codex", server.uri()),
            },
        )
        .await;

        assert_eq!(output.matched, 1);
        assert!(output.lines.iter().all(|line| !line.contains("anthropic account")));
    }

    #[tokio::test]
    async fn forced_refresh_uses_the_selected_providers_protocol_and_split_storage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/anthropic-token"))
            .and(body_json(serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": "claude-rt",
                "client_id": Provider::Anthropic.spec().client_id,
                "scope": "user:profile"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-claude-at",
                "refresh_token": "new-claude-rt",
                "expires_in": 27000,
                "scope": "user:profile"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_json(serde_json::json!({
                "client_id": "openai-client",
                "grant_type": "refresh_token",
                "refresh_token": "codex-rt"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": FUTURE_OPENAI_JWT,
                "refresh_token": "new-codex-rt"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let store = MemoryStore::default();
        seed_same_id(&store);
        let cfg = AuthConfigs {
            anthropic: quota_core::provider::ProviderSpec {
                token_url: format!("{}/anthropic-token", server.uri()),
                ..Provider::Anthropic.spec()
            },
            openai: OpenAiAuthConfig {
                issuer: server.uri(),
                client_id: "openai-client".into(),
            },
        };
        let http = ReqwestHttp::new().unwrap();
        let locks = RefreshLocks::default();

        force_refresh_account(
            &http,
            &cfg,
            &store,
            &locks,
            &parse_account_selector("openai:same-id").unwrap(),
        )
        .await
        .unwrap();
        force_refresh_account(
            &http,
            &cfg,
            &store,
            &locks,
            &parse_account_selector("anthropic:same-id").unwrap(),
        )
        .await
        .unwrap();

        let anthropic = load_tokens(&store, Provider::Anthropic, SAME_ID).unwrap();
        let openai = load_tokens(&store, Provider::Openai, SAME_ID).unwrap();
        assert_eq!(anthropic.access_token(), "new-claude-at");
        assert_eq!(anthropic.refresh_token(), "new-claude-rt");
        assert_eq!(openai.access_token(), FUTURE_OPENAI_JWT);
        assert_eq!(openai.refresh_token(), "new-codex-rt");
        assert_eq!(openai.workspace_id(), Some("workspace-openai"));
        assert!(openai.is_fedramp());
    }
}
