# quota-board

A desktop widget showing the subscription usage limits of several Claude and
Codex accounts at once.

> Installers are available from [GitHub Releases](https://github.com/Kweiza/quota-board/releases),
> or you can build the application yourself. The bundles are not notarized or
> signed by a trusted publisher; read [Installing](#installing) before running
> one.
>
> **Codex sign-in is experimental in 0.3.0.** Its protocol is audited against
> the official Codex 0.153.2 source and covered by local mock tests, but a full
> quota-board login → usage → refresh → usage → revoke run was not completed
> against a live account before this release.
>
> `crates/core` is deliberately Tauri-unaware, so the core builds and tests with
> no GTK or WebKit present.

## Why it exists

If you use more than one Claude or Codex subscription, there is no single place
to see how much of each account's limits you have left. Each first-party client
shows only its currently active account or workspace.

The design turns on one observation: **usage belongs to the authenticated
subscription context, not to the machine running the work.** A local,
read-only query can therefore monitor accounts used on several machines. That
collapses what could have been a distributed system — remote agents, snapshot
sync, a central server — into one desktop app.

## How it reads usage

Each provider has one read-only data source:

- **Claude** — `GET https://api.anthropic.com/api/oauth/usage`, the endpoint
  behind Claude Code's `/usage`. Its OAuth grant requests `user:profile` only,
  without `user:inference`.
- **Codex** — `GET https://chatgpt.com/backend-api/wham/usage`, carrying the
  ChatGPT workspace selected during sign-in. The first-party page states that
  Codex and ChatGPT Work share this allowance. OpenAI exposes no separate
  non-inference scope for the grant, so the token is not proven incapable of
  inference; quota-board enforces the boundary by never calling an inference
  endpoint.

Both calls send `User-Agent: quota-board/<version>`. The OpenAI request sends no
`originator` or other header claiming to be Codex CLI. Neither provider's CLI
credential file is read or written.

Full architecture and rationale: [`docs/design.md`](docs/design.md).
Measured behavior of the endpoints, including the different limits of the
throttling evidence: [`docs/research/usage-endpoint.md`](docs/research/usage-endpoint.md)
and [`docs/research/codex-usage-endpoint.md`](docs/research/codex-usage-endpoint.md).

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

The Codex usage endpoint is undocumented too. It has been observed to agree
with the account's own usage page, but OpenAI does not publish it as a stable
third-party API. It may change or disappear without notice.

### Provider sign-in

Anthropic has no third-party OAuth client registration program, so this app has
to reuse Claude Code's public client_id. **The OAuth consent screen therefore
displays "Claude Code" rather than this application's name.** It is a single
constant in one file, so if third-party registration ever becomes available,
it can be replaced in one place.

Codex sign-in is experimental in 0.3.0 and follows OpenAI's public-client flow.
The normal desktop path opens `auth.openai.com` and returns to a loopback
callback on this machine. If neither registered callback port is available,
quota-board offers OpenAI's device-code flow instead. Device-code sign-in is a
beta OpenAI feature and may need to be enabled in ChatGPT security or workspace
settings. The source-audited wire contract and local mock coverage are complete;
the missing evidence is one full live quota-board lifecycle, not an inference
request or imported CLI credential.

### One machine will hold all your tokens

The app performs its own login per account and stores those tokens on the
machine it runs on. It never copies credentials from anywhere else, and it
neither reads nor writes Claude Code's `~/.claude/.credentials.json` or Codex
CLI's `~/.codex/auth.json`. The consequence is that one machine ends up holding
valid tokens for every account you add. If it is compromised, all of them are
exposed together.

On first setup, tokens go into the OS keychain when one is available, and into
a file encrypted with a passphrase you choose (Argon2id +
XChaCha20-Poly1305) when it is not — which is the common case on headless Linux,
over SSH, and under minimal window managers. Once that encrypted store exists,
the app keeps using it on later launches rather than silently switching to an
empty keychain; unlock it once per boot in Settings.

## Installing

Download the bundle for your platform from
[GitHub Releases](https://github.com/Kweiza/quota-board/releases), or build it
locally. A source build needs [Rust](https://rustup.rs) and Node 24; the pinned
toolchain installs itself from `rust-toolchain.toml`.

```bash
npm ci
npm run tauri build
```

The installers land in `target/release/bundle/` — `.dmg` on macOS, `.msi` on
Windows, `.deb`/`.rpm`/`.AppImage` on Linux. Prefer the `.deb` or `.rpm` on
Linux: they are a few megabytes, while the AppImage carries its own copy of
WebKitGTK and is an order of magnitude larger.

**The published macOS `.dmg` is Apple Silicon (`aarch64`) only.** Intel Mac
users need to build from source; the current release workflow does not produce
an `x86_64` macOS artifact.

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

  If the widget briefly paints and then becomes completely transparent while
  its invisible area is still draggable, check CoreAudio before deleting app
  data or credentials:

  ```bash
  /usr/sbin/system_profiler -timeout 5 -detailLevel mini SPAudioDataType
  ```

  No Audio output from that bounded probe means macOS device enumeration is
  wedged. Save any recording or call first, quit audio/video apps, and restart
  the Mac. The narrower recovery is `sudo killall coreaudiod`; launchd starts it
  again, but all current audio streams are interrupted. If it recurs, disconnect
  external audio/display devices and disable aggregate or multi-output devices
  before troubleshooting third-party HAL drivers in Audio MIDI Setup. This is
  a system-wide WKWebView failure: reinstalling Quota Board or deleting its
  accounts does not repair it. See Apple's
  [Audio MIDI Setup troubleshooting](https://support.apple.com/guide/audio-midi-setup/if-your-audio-apps-stop-working-amsfa3961363/mac).
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

Codex uses the same conservative 180-second polling floor as Claude, but for a
different evidentiary reason. One Codex account returned 90 successful reads at
roughly 60-second intervals over 89 minutes without a 429. That establishes a
safe point, not a throttle boundary, a multi-account budget, or a daily cap.

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
- **A Secret Service provider** (GNOME Keyring, KWallet) holds tokens when it
  is available at the first backend selection. Without one — headless boxes,
  bare window managers — the app selects a passphrase-encrypted file that has
  to be unlocked once per boot in Settings. Once that file exists it stays the
  selected backend, even if a Secret Service provider appears later.
- **Do not expect a 30MB tray app.** That figure is quoted for Tauri often and
  is not true on Linux, where the webview is a separate WebKitGTK process tree.
  Published measurements of a *default* Tauri app on Ubuntu put it around 185MB
  PSS, comparable to Electron. This project has not measured its own footprint,
  so that is the neighbourhood rather than a number for this app.

## Using it

The widget is a small always-on-top card. It has no Dock icon and no menu bar of
its own; **everything that is not a usage row lives in two places.**

- **The gear on the widget** opens Settings — add and remove accounts, rename
  them, reorder them, set the polling interval, unlock the encrypted token
  store, and inspect the last raw response.
- **The tray icon** shows or hides the widget, moves it back to the primary
  display if a monitor change strands it, and quits the app. `Ctrl+Alt+Q`
  toggles the widget too, where the OS allows it.

**Accounts are grouped into one column per service, Claude on the left and
Codex on the right**, so the two never interleave and the card stays about half
as tall as one list of the same accounts. The widget is about 280px wide with a
single service and about 520px with both; a column appears only when it has an
account in it.

**Ordering is yours.** Drag the handle at the left of a row in Settings to
arrange the accounts within its column, or hold `Alt` and press the up or down
arrow. Turning on **Sort accounts by soonest weekly reset** orders both windows
by whichever 7-day window turns over first, with accounts that report no 7-day
window last; your own arrangement is kept while it is on and comes back
untouched when you turn it off.

To add an account, choose the equally weighted **Claude** or **Codex** card in
Settings. Claude opens its browser flow and retains a copy/paste fallback.
Codex normally returns through a local browser callback and offers a device code
when the registered callback ports are unavailable. The full provider name is
always shown — as the heading of each account column, and inside the name of
every control and Debug entry.

## Uninstalling

Removing the application leaves three things behind, and none of them are
removed for you:

- **Your tokens**, in the OS keychain under the service name `quota-board`.
  Delete them in Keychain Access on macOS, `seahorse` or
  `secret-tool` on Linux, or Credential Manager on Windows. Removing an account
  in Settings first attempts best-effort server-side revocation, then removes
  the local credential even when revocation is unavailable.
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

This project is not affiliated with, endorsed by, or sponsored by Anthropic or
OpenAI.
