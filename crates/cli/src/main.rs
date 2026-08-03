//! Headless smoke tool. Exercises login, query, and refresh for real, with no GUI.
//!
//! Usage:
//!   quota-cli login          — add one account via browser OAuth
//!   quota-cli show [uuid]    — print usage. With a uuid, only that account
//!   quota-cli refresh <uuid> — force-refresh that account's token

use quota_core::accounts::{Account, AccountStore};
use quota_core::auth::callback::Callback;
use quota_core::auth::pkce::{begin, success_redirect, AuthConfig};
use quota_core::auth::stored::{ensure_fresh, token_key, RefreshLocks};
use quota_core::auth::token::{exchange_code, refresh, ReqwestHttp, TokenSet};
use quota_core::paths::accounts_file;
use quota_core::provider::Provider;
use quota_core::secrets::{keychain::KeychainStore, SecretStore, SERVICE};
use quota_core::usage::http::fetch_usage;

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
    let cfg = AuthConfig::default();
    let cb = Callback::bind().await?;
    let (pending, url) = begin(&cfg, &cb.redirect_uri())?;

    println!("Open this URL in your browser:\n\n{url}\n");
    println!("(The consent screen will say 'Claude Code' — we reuse its public client_id.)");

    let params = cb.wait_for_code(success_redirect(), &pending.state).await?;
    let code = params.get("code").ok_or("the callback carried no code")?;
    let state = params.get("state").ok_or("the callback carried no state")?;

    let http = ReqwestHttp::new()?;
    let (tokens, identity) = exchange_code(&http, &cfg, &pending, code, state).await?;
    let identity = identity.ok_or("the token response carried no account block — there is no uuid to key by")?;

    // The token key format belongs to Task 10b's `auth::stored` — not
    // re-derived here, `token_key` above is the only place it is built.
    open_store().put(&token_key(&identity.uuid), &serde_json::to_vec(&tokens)?)?;

    let mut accounts = AccountStore::load(&accounts_file());
    accounts.upsert(Account {
        account_id: identity.uuid.clone(),
        provider: Provider::Anthropic,
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

/// With `only` given, queries just that one uuid.
///
/// **That narrowing is why the flag exists**, not a convenience. Any question
/// about how the 429 budget is *scoped* needs asymmetric load: hitting every
/// account equally drains every account equally, so a per-account budget and a
/// per-IP budget produce the same observation. Saturating one account while
/// leaving the others untouched, then probing them, is the only shape that
/// separates the two — see docs/research/usage-endpoint.md, Spike D.
async fn cmd_show(only: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store();
    let accounts = AccountStore::load(&accounts_file());
    let http = ReqwestHttp::new()?;
    let cfg = AuthConfig::default();

    // Task 10b owns the read -> refresh -> write sequence. Reimplementing it
    // inline here would produce a second copy with neither the lock nor the CAS.
    let locks = RefreshLocks::default();

    for a in accounts.list() {
        if only.is_some_and(|u| u != a.account_id) {
            continue;
        }
        let fresh = match ensure_fresh(&http, &cfg, store.as_ref(), &locks, &a.account_id).await {
            Ok(f) => f,
            Err(e) => {
                println!("{}: {e}", a.display_label);
                continue;
            }
        };
        if let Err(e) = &fresh.persisted {
            eprintln!("{}: the token was rotated but could not be stored ({e}) — the next run will not see it", a.display_label);
        }

        match fetch_usage(&http, Provider::Anthropic, &fresh.tokens.access_token).await {
            Ok(windows) => {
                println!("{}:", a.display_label);
                for w in windows {
                    println!("  {:<16} {:>5.1}%  resets {}", w.label, w.percent, w.resets_at);
                }
            }
            Err(e) => println!("{}: {e}", a.display_label),
        }
    }
    Ok(())
}

/// **Deliberately does not use `ensure_fresh` here.** `ensure_fresh` returns
/// immediately without a request when the token is already fresh, and this
/// command exists to **force** a rotation: it is how refresh behaviour is
/// observed on a real account at all — what the server rotates, what expiry it
/// returns, and whether a chain elsewhere is disturbed. Only the key format is
/// borrowed from `auth::stored`. This is a one-shot smoke command, not a
/// concurrent path, so it needs no lock.
async fn cmd_refresh(uuid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store();
    let raw = store.get(&token_key(uuid))?.ok_or("no token is stored for that uuid")?;
    let tokens: TokenSet = serde_json::from_slice(&raw)?;
    let http = ReqwestHttp::new()?;
    let new = refresh(&http, &AuthConfig::default(), &tokens).await?;
    store.put(&token_key(uuid), &serde_json::to_vec(&new)?)?;
    println!("refreshed. new expiry: {}", new.expires_at);
    println!("scopes: {}", new.scopes.join(" "));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") => cmd_login().await,
        Some("show") => cmd_show(args.get(2).map(String::as_str)).await,
        Some("refresh") => cmd_refresh(args.get(2).ok_or("a uuid is required")?).await,
        _ => {
            eprintln!("usage: quota-cli [login|show|refresh <uuid>]");
            std::process::exit(2);
        }
    }
}
