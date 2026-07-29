# CLAUDE.md

Guidance for Claude Code (and any other agent) working in this repository.

## What this is

quoata-board is a desktop widget that shows the 5-hour and 7-day Claude usage
limits for several accounts at once. It is a single Tauri v2 application: a Rust
core owns accounts, tokens, polling, and networking, and a Svelte + TypeScript
webview renders state.

Read `docs/design.md` before making architectural decisions. Its section numbers
(§5, §7, §8, §9 in particular) are cited from code comments and must stay
stable.

## Hard constraints

These are not style preferences. Violating any of them is a defect.

- **Never impersonate `User-Agent: claude-code/<version>`.** Always send
  `quoata-board/<version>`. Misrepresenting identity to Anthropic's servers is
  the one unambiguous prohibition in their terms, and the whole project is built
  around not crossing it. This costs us the generous throttle bucket, and that
  cost is accepted deliberately — see `docs/design.md` §5.2.
- **Send only `anthropic-beta: oauth-2025-04-20`.** No other header that
  identifies Claude Code.
- **Never read or write `~/.claude/.credentials.json` from application code.**
  The manual research scripts in `scripts/` are the sole exception, and only
  when a human runs them.
- **Never call `POST /v1/messages`.** This app is not an inference client. That
  path would consume the very limits it reports.
- **Never store tokens in plaintext.** Not in `tauri-plugin-store`, not in the
  account metadata file. Tokens live in `secrets` only.
- **The account primary key is `account.uuid`.** Never key by email or by user
  label — emails are display-only and user-editable.
- **No test may consume real account limits or throttle budget.** All HTTP goes
  behind a trait and is mocked in tests.
- **Never demote a missing or unparseable value to 0%.** Degrade to "unknown".
  A confidently wrong number is the worst failure mode this product has.

## Language and publication

This repository is public.

- **Everything published is written in English** — code, comments, doc
  comments, error messages, documentation, and commit messages.
- **Private working material goes in `.local/`**, which is git-ignored:
  implementation plans, session handoffs, raw research logs, and internal design
  deliberation. Content there may be in any language.
- `.superpowers/` (agent workspace scratch) and `.claude/` are also git-ignored.

## Commit messages

- Format: `<type>: <description>` where type is one of `feat`, `fix`, `test`,
  `docs`, `chore`, `refactor`.
- English, imperative, describing what changed and why it matters.
- **Never add AI attribution trailers.** No `Co-Authored-By: Claude`, no
  "Generated with Claude Code", no 🤖 marker. The commit log stays clean.

## Layout

```
crates/core/          Headless library. Knows nothing about Tauri.
  src/model.rs        UsageWindow, Severity — the normalized domain types
  src/accounts.rs     Account metadata store (uuid-keyed, no tokens)
  src/secrets/        Token store: keychain first, encrypted file fallback
  src/usage/          Anthropic API response parsing
docs/design.md        Architecture, constraints, terms-of-service position
docs/research/        Measured behavior of the undocumented usage endpoint
scripts/              Manual research scripts (run by a human, never by the app)
```

`crates/core` is deliberately Tauri-unaware, so the entire core can be built and
tested headlessly — including on machines with no GTK or WebKit.

## Commands

```bash
cargo test -p quoata-core                      # full test suite
cargo test -p quoata-core accounts             # one module
cargo clippy --all-targets -- -D warnings      # lint gate; must be clean
cargo run -p quoata-core --example probe       # probe the OS keychain backend
```

Both the test suite and clippy must be clean before any commit.

## Working practices

- **Follow TDD where the task calls for it**: write the failing test, run it and
  confirm it fails for the reason you expect, then implement.
- **A test that cannot fail is not a test.** When adding a test to close a
  coverage gap, back-test it: break the behavior it names, confirm the test
  fails, then restore. Several tests in this repo exist specifically because an
  earlier version of them passed against broken code.
- **Match the surrounding style.** Comments here explain *why*, not *what*, and
  frequently cite the concrete failure the code prevents. Keep that.
- **Do not widen scope.** If you spot a real problem outside your task, report it
  rather than fixing it inline.
