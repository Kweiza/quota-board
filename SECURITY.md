# Reporting a security problem

**Do not open a public issue for anything involving credentials.** This
application holds credentials for every Claude or Codex account you add to it,
so a bug that exposes one is worth reporting privately first.

Use GitHub's private vulnerability reporting on this repository
(*Security* → *Report a vulnerability*). If that is unavailable to you, open an
issue that says only that you have a security report and asks for a contact —
no details.

Things worth reporting privately rather than publicly:

- an access, refresh, or ID token; authorization code; PKCE verifier; Codex user
  code; or device-auth identifier appearing in a log, an error message, a panic,
  or the Settings window's debug panel
- the encrypted-file store accepting a wrong passphrase, or leaving plaintext
  anywhere on disk
- tokens surviving an account removal, or reachable by another local user
- anything that makes this application send a request it does not describe

## Reporting anything else

Open an ordinary issue, and include:

- the version, from the workspace `Cargo.toml` of the build you are running
- your operating system, and on Linux whether the session is X11 or Wayland
- for a wrong or missing number: the body from **Settings → Debug → Reload**.
  It is masked when it is captured, not when it is displayed — tokens, email
  addresses and monetary amounts are already removed from what you can copy
  there, which is what that panel is for.

Both usage endpoints are undocumented. Anthropic's has changed shape before,
and either provider may change again. `docs/design.md` §12 expects that, so
"the numbers went blank" or "a window disappeared" is a useful report, not a
nuisance one.
