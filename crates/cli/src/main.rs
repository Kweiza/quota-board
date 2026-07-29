//! Headless smoke tool. Exercises login, query, and refresh for real, with no GUI.
//!
//! Usage:
//!   quoata-cli login          — add one account via browser OAuth
//!   quoata-cli show [uuid]    — print usage. With a uuid, only that account (spike 6)
//!   quoata-cli refresh <uuid> — force-refresh that account's token (spike C)

use quoata_core::accounts::{Account, AccountStore};
use quoata_core::auth::callback::Callback;
use quoata_core::auth::pkce::{begin, success_redirect, AuthConfig};
use quoata_core::auth::stored::{ensure_fresh, token_key, RefreshLocks};
use quoata_core::auth::token::{exchange_code, refresh, ReqwestHttp, TokenSet};
use quoata_core::secrets::{keychain::KeychainStore, SecretStore};
use quoata_core::usage::http::fetch_usage;

fn config_dir() -> std::path::PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let mut p = std::path::PathBuf::from(std::env::var("HOME").unwrap());
            p.push(".config");
            p
        });
    base.join("quoata-board")
}

const SERVICE: &str = "quoata-board";

fn open_store() -> Box<dyn SecretStore> {
    match KeychainStore::probe(SERVICE) {
        Ok(s) => {
            eprintln!("저장소: {}", s.describe());
            Box::new(s)
        }
        Err(e) => {
            eprintln!("키체인 사용 불가 ({e}).");
            eprintln!("CLI에서는 폴백을 쓰지 않는다 — Task 6의 EncryptedFileStore는 GUI에서만 쓴다.");
            std::process::exit(1);
        }
    }
}

async fn cmd_login() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = AuthConfig::default();
    let cb = Callback::bind().await?;
    let (pending, url) = begin(&cfg, &cb.redirect_uri())?;

    println!("브라우저에서 아래 주소를 여세요:\n\n{url}\n");
    println!("(동의 화면에 'Claude Code'로 표시됩니다 — client_id를 재사용하기 때문입니다.)");

    let params = cb.wait_for_code(success_redirect(), &pending.state).await?;
    let code = params.get("code").ok_or("콜백에 code가 없음")?;
    let state = params.get("state").ok_or("콜백에 state가 없음")?;

    let http = ReqwestHttp::new()?;
    let (tokens, identity) = exchange_code(&http, &cfg, &pending, code, state).await?;
    let identity = identity.ok_or("토큰 응답에 account 블록이 없음 — uuid를 얻을 수 없다")?;

    // The token key format belongs to Task 10b's `auth::stored` — not
    // re-derived here, `token_key` above is the only place it is built.
    open_store().put(&token_key(&identity.uuid), &serde_json::to_vec(&tokens)?)?;

    let mut accounts = AccountStore::load(&config_dir().join("accounts.json"))?;
    accounts.upsert(Account {
        uuid: identity.uuid.clone(),
        display_label: identity.email.clone(),
        email: identity.email,
        created_at: chrono::Utc::now(),
        last_ok_at: None,
        quarantined: false,
        sort_order: 0,
    })?;

    println!("추가됨: {}", identity.uuid);
    println!("스코프: {}", tokens.scopes.join(" "));
    Ok(())
}

/// With `only` given, queries just that one uuid.
///
/// Telling spike 6 apart (is the 429 budget per-account or per-IP?) needs
/// **asymmetric load**. Hitting every account equally makes both hypotheses
/// produce **the same observation** — a per-account budget exhausts both at
/// once just as a per-IP one does. Only saturating one and then probing the
/// other distinguishes them.
async fn cmd_show(only: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store();
    let accounts = AccountStore::load(&config_dir().join("accounts.json"))?;
    let http = ReqwestHttp::new()?;
    let cfg = AuthConfig::default();

    // Task 10b owns the read -> refresh -> write sequence. Reimplementing it
    // inline here would produce a second copy with neither the lock nor the CAS.
    let locks = RefreshLocks::default();

    for a in accounts.list() {
        if only.is_some_and(|u| u != a.uuid) {
            continue;
        }
        let fresh = match ensure_fresh(&http, &cfg, store.as_ref(), &locks, &a.uuid).await {
            Ok(f) => f,
            Err(e) => {
                println!("{}: {e}", a.display_label);
                continue;
            }
        };
        if let Err(e) = &fresh.persisted {
            eprintln!("{}: 토큰은 갱신됐지만 저장에 실패했다 ({e}) — 다음 실행은 이 값을 못 본다", a.display_label);
        }

        match fetch_usage(&http, &fresh.tokens.access_token).await {
            Ok(windows) => {
                println!("{}:", a.display_label);
                for w in windows {
                    println!("  {:<16} {:>5.1}%  리셋 {}", w.label, w.percent, w.resets_at);
                }
            }
            Err(e) => println!("{}: {e}", a.display_label),
        }
    }
    Ok(())
}

/// **Deliberately does not use `ensure_fresh` here.** `ensure_fresh` returns
/// immediately without a request when the token is already fresh, but this
/// command's whole reason to exist is a **forced** refresh — spike 7 (does
/// our refresh kill a running Claude Code session?) is observed through this
/// command specifically. Only the key format is borrowed from Task 10b. This
/// is a one-shot smoke command, not a concurrent path, so it needs no lock.
async fn cmd_refresh(uuid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = open_store();
    let raw = store.get(&token_key(uuid))?.ok_or("해당 uuid의 토큰 없음")?;
    let tokens: TokenSet = serde_json::from_slice(&raw)?;
    let http = ReqwestHttp::new()?;
    let new = refresh(&http, &AuthConfig::default(), &tokens).await?;
    store.put(&token_key(uuid), &serde_json::to_vec(&new)?)?;
    println!("갱신됨. 새 만료: {}", new.expires_at);
    println!("스코프: {}", new.scopes.join(" "));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("login") => cmd_login().await,
        Some("show") => cmd_show(args.get(2).map(String::as_str)).await,
        Some("refresh") => cmd_refresh(args.get(2).ok_or("uuid 필요")?).await,
        _ => {
            eprintln!("사용법: quoata-cli [login|show|refresh <uuid>]");
            std::process::exit(2);
        }
    }
}
