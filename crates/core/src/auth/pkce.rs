use crate::provider::ProviderSpec;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

/// State that must be held onto while a login is in flight.
/// **`verifier` and `state` are passed to the token exchange exactly as-is.**
#[derive(Clone)]
pub struct PendingAuth {
    pub verifier: String,
    pub state: String,
    pub redirect_uri: String,
}

/// Redacts `verifier`. A derived `Debug` printed it in full, and the PKCE
/// verifier is a live credential: with an authorization code it is exchanged
/// for tokens. §10.3's manual fallback keeps one of these in the application
/// state for the whole paste window, so the number of paths that could print it
/// is no longer small.
///
/// `state` and `redirect_uri` are deliberately **not** redacted. Neither is a
/// secret — `state` is a CSRF nonce that already travels in the authorize URL
/// and in the callback query, and the redirect_uri is the single most useful
/// value to see when a token exchange is rejected for replaying the wrong one
/// (§10.3 requires it to match byte for byte). Redacting them would leave a
/// `Debug` that cannot diagnose the failure it is most likely to be printed
/// for.
///
/// Hand-written, never derived — the same shape as `TokenSet` in
/// `auth/token.rs`. AGENTS.md names this because the defect has shipped twice.
impl std::fmt::Debug for PendingAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAuth")
            .field("verifier", &"<redacted>")
            .field("state", &self.state)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// `n_bytes` of randomness, encoded as base64url with no padding.
pub fn random_urlsafe(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::fill(&mut buf[..]);
    URL_SAFE_NO_PAD.encode(&buf)
}

/// code_challenge = BASE64URL-NO-PAD(SHA256(ASCII(verifier)))
pub fn code_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// redirect_uri for the manual copy-paste fallback path. docs/design.md §10.1.
pub fn manual_redirect_uri() -> &'static str {
    "https://platform.claude.com/oauth/code/callback"
}

/// Splits a pasted `<code>#<state>` into its two halves. docs/design.md §10.3.
///
/// The manual redirect renders a single line the user copies by hand, so the
/// input arrives with whatever the clipboard and the terminal added: leading
/// spaces, a trailing newline, sometimes both. Those are trimmed, from the
/// whole string and from each half.
///
/// **Both halves are required, and more than one `#` is refused.** A shape this
/// function does not recognise must not be guessed at: a mis-split code reaches
/// the server as a well-formed request and comes back "Invalid authorization
/// code", which sends the user looking at their account instead of at their
/// paste.
pub fn parse_manual_code(input: &str) -> Option<(&str, &str)> {
    let (code, state) = input.trim().split_once('#')?;
    // `split_once` takes the first `#` and leaves the rest in `state`, so this
    // is what makes a second one a refusal instead of a silent truncation.
    if state.contains('#') {
        return None;
    }
    let (code, state) = (code.trim(), state.trim());
    if code.is_empty() || state.is_empty() {
        return None;
    }
    Some((code, state))
}

/// Where the browser is sent once the login page has issued its code.
/// docs/design.md §10.1.
pub fn success_redirect() -> &'static str {
    "https://platform.claude.com/oauth/code/success?app=claude-code"
}

/// Assemble an authorize URL for an **existing** login, with a different
/// `redirect_uri`.
///
/// §10.3 requires both the loopback URL and the manual-paste URL to exist for
/// one login. They must share the PKCE pair and the `state`: the server binds
/// the issued code to the challenge, and the exchange replays the verifier, so
/// two independently generated pairs would be two separate logins and a code
/// from one could not be exchanged against the other's pending state.
///
/// Nothing new is stored — the challenge is re-derived from `pending.verifier`.
///
/// `redirect_uri` is a parameter rather than `pending.redirect_uri` precisely
/// because the point is to build a URL for a *different* one; the pending value
/// stays whatever the exchange will replay.
///
/// **The query order is defined here and nowhere else.** It is kept identical to
/// what Claude Code itself sends, and the leading non-standard `code=true` is
/// what makes the server render a pasteable `code#state` page — the switch the
/// whole manual fallback depends on. A second copy of this sequence is a copy
/// that drifts.
pub fn authorize_url_for(
    cfg: &ProviderSpec,
    pending: &PendingAuth,
    redirect_uri: &str,
) -> Result<String, url::ParseError> {
    let challenge = code_challenge_s256(&pending.verifier);
    let scope = cfg.scopes.join(" ");

    // `authorize_url` is user-overridable (docs/design.md §10.2), so a bad
    // config value or environment variable must surface as an error here
    // rather than crash a login flow in progress.
    let mut url = url::Url::parse(&cfg.authorize_url)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("code", "true");
        q.append_pair("client_id", &cfg.client_id);
        q.append_pair("response_type", "code");
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &scope);
        q.append_pair("code_challenge", &challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("state", &pending.state);
    }
    Ok(url.to_string())
}

/// Generate a fresh PKCE pair and state, and assemble the authorize URL.
///
/// Only the randomness lives here; the URL is [`authorize_url_for`]'s job, so
/// the query order has one definition. Call this once per login and then
/// [`authorize_url_for`] for any further redirect_uri the same login needs
/// (§10.3's manual fallback).
pub fn begin(
    cfg: &ProviderSpec,
    redirect_uri: &str,
) -> Result<(PendingAuth, String), url::ParseError> {
    let pending = PendingAuth {
        verifier: random_urlsafe(32),
        state: random_urlsafe(32),
        redirect_uri: redirect_uri.to_string(),
    };
    let url = authorize_url_for(cfg, &pending, redirect_uri)?;
    Ok((pending, url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;

    /// The official RFC 7636 Appendix B test vector.
    #[test]
    fn s256_matches_the_rfc_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge_s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn verifier_is_43_chars_and_url_safe() {
        let v = random_urlsafe(32);
        assert_eq!(v.len(), 43, "32 raw bytes as base64url-no-pad is 43 characters");
        assert!(v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn random_urlsafe_is_not_constant() {
        let a = random_urlsafe(32);
        let b = random_urlsafe(32);
        assert_ne!(a, b);
    }

    /// docs/design.md §10.3: query order matters, and so does the leading
    /// non-standard `code=true` — it is what makes the server render a
    /// pasteable code#state page.
    #[test]
    fn authorize_url_has_code_true_first_and_all_required_params() {
        let cfg = Provider::Anthropic.spec();
        let (_pending, url) = begin(&cfg, "http://localhost:54321/callback").unwrap();

        let query = url.split_once('?').unwrap().1;
        assert!(query.starts_with("code=true&"), "code=true must be first: {query}");

        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("client_id").unwrap(), &cfg.client_id);
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(q.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(q.get("redirect_uri").unwrap(), "http://localhost:54321/callback");
        assert_eq!(q.get("scope").unwrap(), "user:profile");
        assert!(q.contains_key("code_challenge"));
        assert!(q.contains_key("state"));
    }

    /// AGENTS.md: a live credential must never reach `Debug` output, and the
    /// PKCE verifier is one — combined with an authorization code it is
    /// exchanged for tokens. Task 23 keeps a `PendingAuth` in the application
    /// state for the whole manual-paste window, which widens every path that
    /// could print it. `TokenSet` in `auth/token.rs` is the pattern this
    /// copies; the same defect has shipped twice in this repository.
    #[test]
    fn debug_redacts_the_verifier_but_keeps_the_rest() {
        let (pending, _url) = begin(&Provider::Anthropic.spec(), "http://localhost:1/callback").unwrap();
        let text = format!("{pending:?}");
        assert!(
            !text.contains(&pending.verifier),
            "the code_verifier reached Debug output: {text}"
        );
        assert!(text.contains("<redacted>"), "nothing marks the redaction: {text}");
        // A `Debug` that prints nothing is not a diagnosis. Neither of these is
        // a credential: `state` is a CSRF nonce that already travels in the
        // authorize URL, and the redirect_uri is the thing most worth seeing
        // when a token exchange is rejected for replaying the wrong one.
        assert!(text.contains(&pending.state), "state was redacted needlessly: {text}");
        assert!(
            text.contains(&pending.redirect_uri),
            "redirect_uri was redacted needlessly: {text}"
        );
    }

    /// §10.3: "Always construct both URLs." They must differ in `redirect_uri`
    /// and in **nothing else** — same challenge, same state, same query order.
    /// Two independently generated PKCE pairs would be two separate logins, and
    /// a code issued for one could not be exchanged against the other's pending
    /// state, which is precisely the failure the fallback exists to avoid.
    #[test]
    fn the_manual_url_differs_from_the_loopback_url_only_in_redirect_uri() {
        let cfg = Provider::Anthropic.spec();
        let (pending, loopback) = begin(&cfg, "http://localhost:54321/callback").unwrap();
        let manual = authorize_url_for(&cfg, &pending, manual_redirect_uri()).unwrap();

        // Compares the whole query with `redirect_uri` removed, so it catches a
        // changed *order* as well as a changed value — the order is what makes
        // the server render the pasteable page.
        let without_redirect = |u: &str| {
            u.split('&').filter(|p| !p.starts_with("redirect_uri=")).collect::<Vec<_>>().join("&")
        };
        assert_eq!(
            without_redirect(&loopback),
            without_redirect(&manual),
            "the two URLs differ somewhere other than redirect_uri"
        );

        let parsed = url::Url::parse(&manual).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("redirect_uri").unwrap(), manual_redirect_uri());
        assert_eq!(q.get("state").unwrap(), &pending.state);
        assert_eq!(q.get("code_challenge").unwrap(), &code_challenge_s256(&pending.verifier));
        assert!(
            manual.split_once('?').unwrap().1.starts_with("code=true&"),
            "code=true must still lead: {manual}"
        );
    }

    #[test]
    fn authorize_url_challenge_matches_the_returned_verifier() {
        let cfg = Provider::Anthropic.spec();
        let (pending, url) = begin(&cfg, "http://localhost:1/callback").unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("code_challenge").unwrap(), &code_challenge_s256(&pending.verifier));
        assert_eq!(q.get("state").unwrap(), &pending.state);
        // `state` must be independent randomness, not derived from the
        // verifier — a state equal to the verifier would publish the
        // code_verifier in the authorize URL and in query logs, defeating PKCE.
        assert_ne!(pending.verifier, pending.state);
    }

    #[test]
    fn a_pasted_code_splits_on_the_hash() {
        assert_eq!(parse_manual_code("abc#def"), Some(("abc", "def")));
    }

    /// The user copies this line out of a web page by hand, so it arrives with
    /// whatever the clipboard and the terminal added.
    #[test]
    fn surrounding_whitespace_is_trimmed_from_both_halves() {
        assert_eq!(parse_manual_code("  abc#def \n"), Some(("abc", "def")));
        assert_eq!(parse_manual_code("abc # def"), Some(("abc", "def")));
    }

    /// §10.3 makes both halves required. Each of these is a paste that went
    /// wrong in a different way, and none of them may be guessed at: a
    /// mis-split code is accepted by the server's parser and rejected by its
    /// validator, so the user is told their authorization is invalid rather
    /// than that their paste was.
    #[test]
    fn an_incomplete_or_ambiguous_paste_is_refused() {
        for bad in ["abc", "#def", "abc#", "", "   ", "#", " # "] {
            assert_eq!(parse_manual_code(bad), None, "{bad:?} was accepted");
        }
    }

    /// More than one `#` means this is not the documented shape. Splitting on
    /// the first would silently hand the server a truncated state.
    #[test]
    fn more_than_one_hash_is_refused() {
        assert_eq!(parse_manual_code("a#b#c"), None);
    }

    /// docs/design.md §10.4: do not ask for scopes this app has no use for.
    #[test]
    fn default_scopes_exclude_everything_we_do_not_need() {
        let cfg = Provider::Anthropic.spec();
        for forbidden in [
            "org:create_api_key",
            "user:sessions:claude_code",
            "user:mcp_servers",
            "user:file_upload",
            // Dropped after measurement showed the server does not require it
            // for the read-only usage call — see the comment on
            // `Provider::Anthropic.spec()`. This is the line that stops a future
            // edit from quietly re-adding it.
            "user:inference",
        ] {
            assert!(!cfg.scopes.contains(&forbidden), "requesting {forbidden}");
        }
    }

    /// docs/design.md §10.1: authorize lives on claude.com/cai, not claude.ai.
    #[test]
    fn endpoints_are_the_verified_ones() {
        let cfg = Provider::Anthropic.spec();
        assert_eq!(cfg.authorize_url, "https://claude.com/cai/oauth/authorize");
        assert_eq!(cfg.token_url, "https://platform.claude.com/v1/oauth/token");
        assert_eq!(cfg.client_id, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
    }
}
