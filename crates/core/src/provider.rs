//! Which service an account belongs to, and the per-provider constants that
//! follow from it.
//!
//! A closed set of two. `dyn` dispatch would buy nothing here and would put a
//! trait object on a path that is a `match` in three places.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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
}
