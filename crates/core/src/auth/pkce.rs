use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

/// docs/design.md §10.1, §10.2, §10.4.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub authorize_url: String,
    pub token_url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            authorize_url: "https://claude.com/cai/oauth/authorize".into(),
            token_url: "https://platform.claude.com/v1/oauth/token".into(),
            // Anthropic runs no third-party OAuth client registration program,
            // so this reuses Claude Code's own public client. The visible
            // consequence is that the consent screen shows "Claude Code"
            // rather than this app's name. Must stay overridable via
            // configuration so we can switch the moment a real client_id
            // becomes available — docs/design.md §10.2.
            client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e".into(),
            scopes: vec!["user:profile".into(), "user:inference".into()],
        }
    }
}

/// State that must be held onto while a login is in flight.
/// **`verifier` and `state` are passed to the token exchange exactly as-is.**
#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub verifier: String,
    pub state: String,
    pub redirect_uri: String,
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

/// Where the browser is sent once the login page has issued its code.
/// docs/design.md §10.1.
pub fn success_redirect() -> &'static str {
    "https://platform.claude.com/oauth/code/success?app=claude-code"
}

/// Generate a fresh PKCE pair and state, and assemble the authorize URL.
///
/// The query order is kept identical to what Claude Code itself sends. The
/// leading non-standard `code=true` is what makes the server render a
/// pasteable `code#state` page — the only switch that makes the manual
/// fallback possible, so it stays first.
pub fn begin(
    cfg: &AuthConfig,
    redirect_uri: &str,
) -> Result<(PendingAuth, String), url::ParseError> {
    let verifier = random_urlsafe(32);
    let state = random_urlsafe(32);
    let challenge = code_challenge_s256(&verifier);
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
        q.append_pair("state", &state);
    }

    let pending = PendingAuth {
        verifier,
        state,
        redirect_uri: redirect_uri.to_string(),
    };
    Ok((pending, url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cfg = AuthConfig::default();
        let (_pending, url) = begin(&cfg, "http://localhost:54321/callback").unwrap();

        let query = url.split_once('?').unwrap().1;
        assert!(query.starts_with("code=true&"), "code=true must be first: {query}");

        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q.get("client_id").unwrap(), &cfg.client_id);
        assert_eq!(q.get("response_type").unwrap(), "code");
        assert_eq!(q.get("code_challenge_method").unwrap(), "S256");
        assert_eq!(q.get("redirect_uri").unwrap(), "http://localhost:54321/callback");
        assert_eq!(q.get("scope").unwrap(), "user:profile user:inference");
        assert!(q.contains_key("code_challenge"));
        assert!(q.contains_key("state"));
    }

    #[test]
    fn authorize_url_challenge_matches_the_returned_verifier() {
        let cfg = AuthConfig::default();
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

    /// docs/design.md §10.4: do not ask for scopes this app has no use for.
    #[test]
    fn default_scopes_exclude_everything_we_do_not_need() {
        let cfg = AuthConfig::default();
        for forbidden in [
            "org:create_api_key",
            "user:sessions:claude_code",
            "user:mcp_servers",
            "user:file_upload",
        ] {
            assert!(!cfg.scopes.iter().any(|s| s == forbidden), "requesting {forbidden}");
        }
    }

    /// docs/design.md §10.1: authorize lives on claude.com/cai, not claude.ai.
    #[test]
    fn endpoints_are_the_verified_ones() {
        let cfg = AuthConfig::default();
        assert_eq!(cfg.authorize_url, "https://claude.com/cai/oauth/authorize");
        assert_eq!(cfg.token_url, "https://platform.claude.com/v1/oauth/token");
        assert_eq!(cfg.client_id, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
    }
}
