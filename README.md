# quota-board

A desktop widget showing the 5-hour and 7-day usage limits of several Claude
accounts at once.

> **Status: complete but unreleased. Build it yourself — see [Installing](#installing).**
>
> The widget, the settings window, the tray, start-at-login and both login
> routes are implemented, and the whole thing has been run against real
> accounts. What is missing is distribution: nothing is code-signed and no
> version has been tagged, so there is no download.
>
> `crates/core` is deliberately Tauri-unaware, so the core builds and tests with
> no GTK or WebKit present.

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
  `User-Agent: quota-board/<version>` and never impersonates Claude Code, even
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
displays "Claude Code" rather than this application's name.** It is a single
constant in one file, so if third-party registration ever becomes available,
switching is a one-line change and a rebuild — there is no setting for it
today.

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

## Installing

There is no signed release yet, so building it is the only way to install it.
You need [Rust](https://rustup.rs) and Node 24; the pinned toolchain installs
itself from `rust-toolchain.toml`.

```bash
npm ci
npm run tauri build
```

The installers land in `target/release/bundle/` — `.dmg` on macOS, `.msi` on
Windows, `.deb`/`.rpm`/`.AppImage` on Linux. Prefer the `.deb` or `.rpm` on
Linux: they are a few megabytes, while the AppImage carries its own copy of
WebKitGTK and is an order of magnitude larger.

**Nothing is notarized and there is no Developer ID.** The macOS bundle is
ad-hoc signed, which is enough for the app to run but not enough for Gatekeeper
to admit it unaided.

- **macOS** — copy the app to `/Applications` first, then clear the quarantine
  flag: `xattr -dr com.apple.quarantine "/Applications/Quota Board.app"`.
  Finder's right-click → *Open* is **not** an alternative on macOS 15 and later;
  Apple removed that bypass. There the other route is to let the launch be
  blocked, then System Settings → *Privacy & Security* → *Open Anyway*.

  The message you should expect is **"Apple could not verify 'Quota Board.app'
  is free of malware…"** — measured on macOS 26. That one is the ordinary
  unnotarized-app refusal and both routes above clear it. If you instead see
  **"…is damaged and can't be opened"**, you have a 0.1.0 or 0.2.0 build; see
  the note below.
- **Windows** — SmartScreen will warn; the bypass is *More info* →
  *Run anyway*.

> **Releases 0.1.0 and 0.2.0 shipped without the ad-hoc signature.** macOS
> reports those two as *"damaged and can't be opened"*, and no click-through
> gets past it — the `xattr` command above is the only way to run them. Fixed in
> 0.2.1.

**On macOS the build's signing identity changes with every release**, and
keychain items are bound to that identity. After an update the system asks again
for permission to read your stored tokens, **once per account** — measured on
the 0.2.0 → 0.2.1 upgrade with three accounts, where all three were asked.
Approving each one restores every account. Dismissing instead is expected to
leave that account reading as locked until the next launch you do approve; that
branch has not been measured.

**Codex (ChatGPT) accounts read a subscription usage endpoint too.**
`GET https://chatgpt.com/backend-api/wham/usage` reports a Codex account's
limits the same way `/api/oauth/usage` does for Claude, and it is held to the
same rule: an honest `quota-board/<version>` User-Agent is sent, and nothing
here impersonates the Codex CLI. Its 180-second polling floor is **borrowed**,
not measured the way Claude's is — no run against this endpoint has ever
produced a 429, so there is no boundary to derive a floor from, only a point
(60-second polling for 89 minutes) known to be safe. See
[`docs/research/codex-usage-endpoint.md`](docs/research/codex-usage-endpoint.md).

### Linux

- **An X server is required — X11 or XWayland.** The app sets
  `GDK_BACKEND=x11` before GTK starts, so a Wayland session needs XWayland
  present; a session without it is untested and expected to fail at launch
  rather than to degrade. The price of forcing it is slight blurriness on HiDPI
  displays, taken deliberately: staying on top and remembering its position is
  what makes this a widget rather than a window, and Wayland supports neither.
- **The global shortcut needs a real X11 connection of its own** and does not
  follow `GDK_BACKEND`, so it can fail even where the rest of the app works.
  When it does, the tray menu is the only way to get a hidden widget back —
  which is why every action is in that menu rather than on the icon's click.
- **An appindicator library must be installed** or the tray icon silently never
  appears — and with no Dock icon and no menu bar, the tray is where Quit lives.
  Both packages now declare it (`libayatana-appindicator3-1` on Debian,
  `libappindicator-gtk3` on Fedora), but **the `.rpm` has never been
  install-tested**, so treat a failed install there as a name to correct rather
  than as a missing library.
- **A Secret Service provider** (GNOME Keyring, KWallet) holds your tokens if
  one is running. Without one — headless boxes, bare window managers — the app
  falls back to a passphrase-encrypted file that has to be unlocked once per
  boot, in Settings.
- **Do not expect a 30MB tray app.** That figure is quoted for Tauri often and
  is not true on Linux, where the webview is a separate WebKitGTK process tree.
  Published measurements of a *default* Tauri app on Ubuntu put it around 185MB
  PSS, comparable to Electron. This project has not measured its own footprint,
  so that is the neighbourhood rather than a number for this app.

## Using it

The widget is a small always-on-top card. It has no Dock icon and no menu bar of
its own; **everything that is not a usage row lives in two places.**

- **The gear on the widget** opens Settings — add and remove accounts, rename
  them, set the polling interval, unlock the encrypted token store, and inspect
  the last raw response.
- **The tray icon** shows or hides the widget and quits the app. `Ctrl+Alt+Q`
  toggles the widget too, where the OS allows it.

To add an account, press **Add account** in Settings and approve in the browser
that opens. If the browser cannot be opened, or is on another machine, the
window falls back to a link you can copy anywhere and a box to paste the
resulting code into.

## Uninstalling

Removing the application leaves three things behind, and none of them are
removed for you:

- **Your tokens**, in the OS keychain under the service name `quota-board`, one
  entry per account. Delete them in Keychain Access on macOS, `seahorse` or
  `secret-tool` on Linux, or Credential Manager on Windows. Removing an account
  in Settings first also revokes it server-side, which is the tidier route.
- **Account metadata and settings**, in `quota-board/` under your platform's
  config directory — no tokens are in there.
- **A login item**, if you enabled start-at-login: `Quota Board.plist` in
  `~/Library/LaunchAgents`, an XDG autostart entry, or an HKCU `Run` value.

## Building

```bash
cargo test --workspace                                        # Rust tests
cargo clippy --all-targets -- -D warnings                     # lint
cargo clippy --all-targets --features custom-protocol -- -D warnings
npm test -- --run                                             # front-end tests
npm run check                                                 # type gate
```

The second clippy run is not redundant: `custom-protocol` is off by default, and
it is the feature that makes a built app serve its own frontend instead of
fetching a dev server. Code behind it is not compiled otherwise.

`npm run tauri dev` runs the app against the Vite dev server. A plain
`cargo build -p quota-board` produces a binary that still expects that server,
so run it with `--features custom-protocol` if you want to launch it directly.

The version lives in the workspace `Cargo.toml` and nowhere else — the installer
version and the `User-Agent` this app sends are both derived from it.

## Reporting problems

Include the version, your platform, and — for a wrong or missing number — the
body from **Settings → Debug → Reload**, which is masked when it is captured.
For anything involving credentials, report it privately: see
[SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or sponsored by Anthropic.
