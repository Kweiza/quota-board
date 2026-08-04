//! Which service an account belongs to, and the per-provider constants that
//! follow from it.
//!
//! A closed set of two. `dyn` dispatch would buy nothing here and would put a
//! trait object on a path that is a `match` in three places.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// The default so that an `accounts.json` written before this enum existed
    /// keeps loading. Every account in such a file is an Anthropic one.
    #[default]
    Anthropic,
    Openai,
}

impl Provider {
    /// Stable, lowercase, and used in storage keys. **Not for display** — the
    /// UI says "Claude" and "Codex", which are product names rather than
    /// vendor names.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Anthropic => "anthropic",
            Provider::Openai => "openai",
        }
    }

    /// The shortest interval this provider may be polled at, per account.
    pub fn min_interval_secs(self) -> u64 {
        match self {
            // docs/design.md §6.1. Spike B measured a 120-second floor under
            // saturation; this is that plus a 50% margin.
            Provider::Anthropic => 180,
            // Spike G drove one account at 60-second intervals for 89 minutes
            // and never saw a 429, so **no boundary was found**. That makes 60 s
            // a point known to be safe rather than a floor derived from a
            // measured limit — there is no Spike-B-style arithmetic to perform
            // on a run in which nothing failed.
            //
            // The number stays at three times that point to cover what the run
            // did not. Spike D established that Anthropic's 429 budget is per
            // account; nothing establishes the same for OpenAI, so N accounts
            // at the floor is N times a rate only ever measured at N=1. The
            // default interval is 300 s, so this binds only a user who
            // deliberately lowers it.
            Provider::Openai => 180,
        }
    }

    /// Everything the OAuth flow needs that differs between providers.
    /// docs/design.md §10.1-§10.4 for Anthropic; discovery plus the codex
    /// binary for OpenAI (docs/research/codex-usage-endpoint.md, "OAuth
    /// endpoints").
    pub fn spec(self) -> ProviderSpec {
        match self {
            Provider::Anthropic => ProviderSpec {
                authorize_url: "https://claude.com/cai/oauth/authorize".into(),
                token_url: "https://platform.claude.com/v1/oauth/token".into(),
                // Matches design.md §10.1's table. An explicit field rather than
                // `format!("{token_url}/revoke")`: OpenAI's revoke endpoint is a
                // sibling of its token endpoint, not a suffix of it (see the
                // Openai arm below), so deriving one from the other would be
                // correct for Anthropic and wrong for OpenAI.
                revoke_url: "https://platform.claude.com/v1/oauth/token/revoke".into(),
                // Anthropic runs no third-party OAuth client registration program,
                // so this reuses Claude Code's own public client. The visible
                // consequence is that the consent screen shows "Claude Code"
                // rather than this app's name. Must stay overridable via
                // configuration so we can switch the moment a real client_id
                // becomes available — docs/design.md §10.2.
                client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e".into(),
                // `user:inference` was dropped after measurement, not by guess: a
                // live spike showed the server accepts `user:profile` alone at
                // consent, issues a token scoped to it (does not silently re-add
                // `user:inference`), and that token's `/api/oauth/usage` calls —
                // both on the initial token and after a refresh — return 200.
                // Claude Code's insistence on requesting both scopes is therefore
                // a client-side gate, not a server requirement. A token that
                // cannot run inference is the point, not an optimisation: it is
                // the terms-of-service position this whole project is built
                // around — docs/design.md §10.4, §5.2.
                scopes: vec!["user:profile"],
                body_style: BodyStyle::JsonWithState,
            },
            Provider::Openai => ProviderSpec {
                authorize_url: "https://auth.openai.com/api/accounts/authorize".into(),
                token_url: "https://auth.openai.com/api/accounts/oauth/token".into(),
                // The CLI's request log shows it using https://auth.openai.com/oauth/token
                // rather than the endpoint discovery advertises. Both are recorded in
                // docs/research/codex-usage-endpoint.md; the advertised one is used here
                // because it is the documented contract, and this comment exists so the
                // other candidate is one grep away when a refresh starts failing.
                revoke_url: "https://auth.openai.com/api/accounts/oauth/revoke".into(),
                // The codex binary's public client. **Not verified** — no
                // authorization flow has been run against it (see the research
                // document's "OAuth endpoints" section).
                client_id: "app_EMoamEEZ73f0CkXaXp7hrann".into(),
                // Discovery's full advertised list. Unlike Anthropic there is no
                // `user:inference`-shaped scope to decline — see docs/design.md
                // §10.4's counterpart note and the research document.
                scopes: vec!["openid", "profile", "email", "offline_access"],
                // Discovery advertises a JSON token endpoint, but nothing here
                // confirms its request shape — no authorization flow has been
                // run against OpenAI (research document, "Scope limits"). RFC
                // 6749's own form encoding is assumed until measurement says
                // otherwise, which is the opposite default from Anthropic's
                // measured JsonWithState.
                body_style: BodyStyle::Form,
            },
        }
    }
}

/// Everything the OAuth flow needs that differs between providers.
///
/// A value, not a trait. The flow itself — PKCE S256, loopback redirect, manual
/// paste fallback — is identical, and only these fields change.
///
/// **`String`, not `&'static str`, for every field but `scopes`.** `token_url`
/// is the one field this application overrides at runtime: a debug-only
/// environment variable in `src-tauri/main.rs` points it at a local mock
/// server for manual verification, and every test in this module, in
/// `auth::token`, and in `auth::stored` does the same to reach `wiremock`. A
/// `&'static str` field would have forced every one of those call sites to
/// leak a string to get a `'static` lifetime out of a value that only exists
/// at runtime. `scopes` carries no such requirement — both providers' lists
/// are compile-time constants that nothing ever overrides — so it alone stays
/// `Vec<&'static str>`.
#[derive(Debug, Clone)]
pub struct ProviderSpec {
    pub authorize_url: String,
    pub token_url: String,
    pub revoke_url: String,
    pub client_id: String,
    pub scopes: Vec<&'static str>,
    /// Anthropic's token endpoint takes a JSON body carrying a non-standard
    /// `state`; the standard is form encoding. docs/design.md §10.3 records the
    /// first as measured.
    pub body_style: BodyStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyStyle {
    /// JSON, with `state` included. Measured against Anthropic (§10.3).
    JsonWithState,
    /// `application/x-www-form-urlencoded`, the RFC 6749 form.
    Form,
}

/// docs/design.md §9.3: entries are keyed uniquely under our own service name.
///
/// **Deliberately asymmetric.** Anthropic entries stay unprefixed not for lack
/// of taste but because changing the format orphans every existing keychain
/// entry: the lookup falls to `NOT_FOUND`, §9.2 maps that to `AUTH_DEAD`, and
/// the upgrade forces a re-login on every account the user already has. The
/// token store is the one place where a bug means credential loss, so this
/// carries no migration. New providers are namespaced from the start.
pub fn token_key(provider: Provider, account_id: &str) -> String {
    match provider {
        Provider::Anthropic => format!("{account_id}:tokens"),
        Provider::Openai => format!("openai:{account_id}:tokens"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// **The Anthropic form must not change.** Every existing keychain entry is
    /// stored under it; a new format orphans them all, lookups fall to
    /// NOT_FOUND, docs/design.md §9.2 maps that to AUTH_DEAD, and the upgrade
    /// demands a re-login on every account the user already has.
    #[test]
    fn the_anthropic_key_format_is_frozen() {
        assert_eq!(token_key(Provider::Anthropic, "uuid-1"), "uuid-1:tokens");
    }

    #[test]
    fn a_new_provider_is_namespaced_from_the_start() {
        assert_eq!(token_key(Provider::Openai, "user-1"), "openai:user-1:tokens");
    }

    /// Anthropic's floor is derived from a measurement (Spikes B and D: a
    /// 120-second observed floor plus 50%), so it is pinned.
    ///
    /// OpenAI's deliberately is not. Spike G found no boundary at all, so its
    /// 180 is a chosen margin over a known-safe point rather than a number the
    /// data produced — and a test asserting it would freeze a judgment call as
    /// though it were data. What must hold is the safety property, which the
    /// next test covers.
    #[test]
    fn the_anthropic_floor_is_the_measured_one() {
        assert_eq!(Provider::Anthropic.min_interval_secs(), 180);
    }

    #[test]
    fn every_provider_has_a_floor_above_zero() {
        for p in [Provider::Anthropic, Provider::Openai] {
            assert!(p.min_interval_secs() >= 60, "{p:?} would poll too fast");
        }
    }

    /// docs/design.md §9.3: lookups are exact. Two providers issuing the same
    /// id must not collide.
    #[test]
    fn the_same_id_under_two_providers_yields_two_keys() {
        assert_ne!(token_key(Provider::Anthropic, "x"), token_key(Provider::Openai, "x"));
    }

    /// Measured from auth.openai.com's discovery document, 2026-08-03.
    #[test]
    fn the_openai_spec_matches_the_measured_discovery_document() {
        let s = Provider::Openai.spec();
        assert_eq!(s.authorize_url, "https://auth.openai.com/api/accounts/authorize");
        assert_eq!(s.token_url, "https://auth.openai.com/api/accounts/oauth/token");
        assert_eq!(s.revoke_url, "https://auth.openai.com/api/accounts/oauth/revoke");
        assert!(s.scopes.contains(&"offline_access"), "no refresh without it");
    }

    /// docs/design.md §10.4 drops `user:inference` deliberately. OpenAI's
    /// advertised list contains no inference scope to drop, so the test pins
    /// what we do request rather than what we omit.
    #[test]
    fn the_anthropic_spec_still_requests_profile_alone() {
        assert_eq!(Provider::Anthropic.spec().scopes, vec!["user:profile"]);
    }

    /// The serialized form is a contract with `src/lib/types.ts:51`
    /// (`export type Provider = 'anthropic' | 'openai'`), the same kind
    /// `model.rs` pins for `ExtraLine`.
    ///
    /// **Nothing else notices if it breaks.** Drop the `rename_all` attribute
    /// and every Rust test and every vitest test still passes, because both
    /// suites work with values of their own side's spelling. At runtime
    /// `list_accounts` starts answering `"Openai"`, `AccountRow.svelte`'s
    /// `BADGE["Openai"]` is `undefined`, and `{badge.text}` throws while
    /// rendering — a blank widget, which is the failure mode this whole
    /// product is built to avoid.
    ///
    /// The deserialize half matters separately: `accounts.json` stores this
    /// value, so a rename would also make every saved Codex account
    /// unreadable.
    #[test]
    fn provider_serializes_as_the_typescript_union_spells_it() {
        assert_eq!(serde_json::to_value(Provider::Anthropic).unwrap(), json!("anthropic"));
        assert_eq!(serde_json::to_value(Provider::Openai).unwrap(), json!("openai"));
        let back = |s: &str| serde_json::from_value::<Provider>(json!(s)).unwrap();
        assert_eq!(back("anthropic"), Provider::Anthropic);
        assert_eq!(back("openai"), Provider::Openai);
    }

    /// `as_str` and the serde name are **two independent spellings of the same
    /// word**, and `src/lib/types.ts:98-109` says they mirror each other:
    /// `snapshots::cache_key` builds `"<as_str>:<id>"` in Rust, while
    /// `accountKey` builds `"<serialized>:<id>"` in the webview from the value
    /// that arrived over IPC. Let the two drift and the webview's key stops
    /// matching the core's for every keyed lookup — the `{#each}` block, the
    /// throttle notes, and the debug panel's selection all key off it.
    #[test]
    fn the_storage_spelling_and_the_wire_spelling_are_the_same_word() {
        for p in [Provider::Anthropic, Provider::Openai] {
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                json!(p.as_str()),
                "{p:?} serializes as one word and stores itself as another"
            );
        }
    }
}
