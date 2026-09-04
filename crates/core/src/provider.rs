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

/// The raw OpenAI access-token entry. Derived from [`token_key`] so the
/// provider namespace has exactly one implementation.
pub fn openai_access_token_key(account_id: &str) -> String {
    format!("{}:access", token_key(Provider::Openai, account_id))
}

/// The raw OpenAI refresh-token entry. Kept separate from the access token so
/// neither approaches Windows Credential Manager's per-entry limit.
pub fn openai_refresh_token_key(account_id: &str) -> String {
    format!("{}:refresh", token_key(Provider::Openai, account_id))
}

/// The non-secret OpenAI token metadata entry. It still lives in
/// [`SecretStore`](crate::secrets::SecretStore): splitting storage must never
/// turn into permission to put token-adjacent state in a plaintext store.
pub fn openai_token_meta_key(account_id: &str) -> String {
    format!("{}:meta", token_key(Provider::Openai, account_id))
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

    /// OpenAI's tokens are deliberately split across three credential entries
    /// to stay below Windows Credential Manager's per-entry byte limit. These
    /// names are storage ABI: changing any suffix silently loses that piece of
    /// every Codex login already on disk.
    #[test]
    fn the_openai_split_key_formats_are_frozen() {
        assert_eq!(
            openai_access_token_key("user-1"),
            "openai:user-1:tokens:access"
        );
        assert_eq!(
            openai_refresh_token_key("user-1"),
            "openai:user-1:tokens:refresh"
        );
        assert_eq!(openai_token_meta_key("user-1"), "openai:user-1:tokens:meta");
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
