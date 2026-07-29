# quoata-board

A desktop widget showing the 5-hour and 7-day usage limits of several Claude
accounts at once.

> **Status: work in progress.** The headless core (account metadata, token
> storage, usage-response parsing) is implemented and tested. The OAuth flow,
> scheduler, and Tauri UI are not finished yet. There is no release to install.

## Why it exists

If you use more than one Claude subscription, there is no single place to see
how much of each one's limits you have left. `claude /usage` reports the
currently active account only.

The design turns on one observation: **the 5-hour and 7-day limits belong to the
account, not to the machine.** So even when an account is being used on several
remote machines, a single token held locally reports the same numbers. That
collapses what could have been a distributed system — remote agents, snapshot
sync, a central server — into one desktop app.

## How it reads usage

It calls `GET https://api.anthropic.com/api/oauth/usage`, the same endpoint
behind Claude Code's `/usage` command, which costs no inference. It never sends
an inference request, so it never consumes the limits it reports. The OAuth
token it holds backs that up structurally, not just by convention: it is
requested with the `user:profile` scope only, so it never carries
`user:inference`.

Full architecture and rationale: [`docs/design.md`](docs/design.md).
Measured behavior of that endpoint, including its throttling:
[`docs/research/usage-endpoint.md`](docs/research/usage-endpoint.md).

## Read this before you use it

**This tool queries Anthropic's API using your subscription's OAuth
credentials, which is a gray area. Installing it means accepting that
uncertainty.** The honest state of affairs:

- Read-only usage queries are not addressed by any Anthropic document.
  Consumer Terms §3(7), prohibiting "access through automated means such as bots
  or scripts," textually covers polling.
- Observed enforcement has been credential scoping at the API edge and billing
  reclassification — not account suspension. No account suspension over this has
  been documented.
- The one unambiguous prohibition is misrepresenting your identity to
  Anthropic's servers. **This tool does not do that.** It always sends
  `User-Agent: quoata-board/<version>` and never impersonates Claude Code, even
  though impersonation is the community's standard workaround for the rate
  limiting. The price is a much narrower throttle budget, which is why polling
  is floored at 3 minutes per account.

What this project will not do, as a matter of policy: no inference relaying, no
central or remote server, no credential sharing between users, no reading or
writing another tool's credentials, no User-Agent or header spoofing, no
rate-limit circumvention.

### The consent screen will say "Claude Code"

Anthropic has no third-party OAuth client registration program, so this app has
to reuse Claude Code's public client_id. **The OAuth consent screen therefore
displays "Claude Code" rather than this application's name.** The client_id is
overridable via configuration, so if third-party registration ever becomes
available it can be switched immediately.

### One machine will hold all your tokens

The app performs its own OAuth login per account and stores those tokens on the
machine it runs on — it never copies credentials from anywhere else, and it
neither reads nor writes Claude Code's credential file. The consequence is that
one machine ends up holding valid tokens for every account you add. If it is
compromised, all of them are exposed together.

Tokens go into the OS keychain when one is available, and into a file encrypted
with a passphrase you choose (Argon2id + XChaCha20-Poly1305) when it is not —
which is the common case on headless Linux, over SSH, and under minimal window
managers.

## Building

```bash
cargo test -p quoata-core                  # run the test suite
cargo clippy --all-targets -- -D warnings  # lint
```

The core library is Tauri-unaware and builds and tests headlessly, with no GTK
or WebKit needed. The desktop application will additionally require the Tauri
v2 system dependencies.

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or sponsored by Anthropic.
