# CLAUDE.md

Guidance for Claude Code (and any other agent) working in this repository.

## What this is

quota-board is a desktop widget that shows the usage limits of several Claude
and Codex accounts at once. It is a single Tauri v2 application: a Rust
core owns accounts, tokens, polling, and networking, and a Svelte + TypeScript
webview renders state.

Read `docs/design.md` before making architectural decisions. Its section numbers
(§5, §7, §8, §9 in particular) are cited from code comments and must stay
stable.

## Hard constraints

These are not style preferences. Violating any of them is a defect.

- **Never impersonate `User-Agent: claude-code/<version>`.** Always send
  `quota-board/<version>`. Misrepresenting identity to Anthropic's servers is
  the one unambiguous prohibition in their terms, and the whole project is built
  around not crossing it. This costs us the generous throttle bucket, and that
  cost is accepted deliberately — see `docs/design.md` §5.2.
- **Send only `anthropic-beta: oauth-2025-04-20`.** No other header that
  identifies Claude Code.
- **Never read or write `~/.claude/.credentials.json` from application code.**
  The manual research scripts in `scripts/` are the sole exception, and only
  when a human runs them.
- **Never call an inference endpoint for either provider** — `POST
  /v1/messages` for Anthropic, or any OpenAI completions/response endpoint for
  Codex. This app is not an inference client for either service. Either path
  would consume the very limits it reports.
- **Never store tokens in plaintext.** Not in `tauri-plugin-store`, not in the
  account metadata file. Tokens live in `secrets` only.
- **The account primary key is `account.uuid`.** Never key by email or by user
  label — emails are display-only and user-editable.
- **No test may consume real account limits or throttle budget.** Every test
  reaches a local mock, never the network. Two different seams achieve that, and
  the difference is deliberate: `secrets`' store access and `auth`'s HTTP both
  sit behind traits, while `usage` injects the endpoint URL instead — its path
  needs `Retry-After`, which `auth`'s HTTP trait discards. See `docs/design.md`
  §4.3 before adding a trait there.
- **Never let a token reach an error message, `Debug` output, or a panic.** Any
  type carrying a live credential hand-writes `Debug` and prints `"<redacted>"`
  for the sensitive fields — never derives it. `TokenSet` in
  `crates/core/src/auth/token.rs` is the pattern to copy. This exists because
  the same defect shipped twice in this repository.
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
  src/usage/          Anthropic and OpenAI usage response parsing
docs/design.md        Architecture, constraints, terms-of-service position
docs/research/        Measured behavior of the undocumented usage endpoints
scripts/              Manual research scripts (run by a human, never by the app)
```

`crates/core` is deliberately Tauri-unaware, so the entire core can be built and
tested headlessly — including on machines with no GTK or WebKit.

## Commands

```bash
cargo test -p quota-core                      # full test suite
cargo test -p quota-core accounts             # one module
cargo clippy --all-targets -- -D warnings      # lint gate; must be clean
cargo run -p quota-core --example probe       # probe the OS keychain backend
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
- **Never replace a shipped file with a snippet.** A plan or task description
  that shows "the contents" of a file describes it as of the day that text was
  written. If the file already exists, read the snippet as a diff and change
  only the lines it actually intends to change. Three separate defects here came
  from transcribing a whole-file snippet over a file later work had grown:
  a workspace member silently dropped, a component that mounted nothing, and a
  109-line entry point overwritten by seven lines.
