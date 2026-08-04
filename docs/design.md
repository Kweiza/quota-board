# quota-board — Design

> Status: settled. Section numbers in §5, §7, §8, and §9 are cited from code
> comments and are kept stable.

## 1. Scope

quota-board is a desktop widget that shows the usage limits of several Claude
and Codex accounts at once. This document records the architecture, the
constraints that shape it, and the terms-of-service position the project takes.

Two observations determine almost everything else in the design; they are §2.
The constraints that follow from them are §3. Everything after that is detail.

## 2. The two facts that determined the architecture

### 2.1 Limits are per-account

**The 5-hour and 7-day limits belong to the account (the subscription) and are
independent of the machine.**

An earlier draft of this project assumed that because actual usage happens on
remote machines, usage had to be collected from those remote machines. But
because limits belong to the account, even if an account is running on three
remote servers, holding a single token for that account on one monitoring
machine yields **the same numbers**.

As a consequence, all of the following disappear from the design:

- SSH access to remote machines
- Hook or agent scripts deployed to remote machines
- Snapshot file synchronization or a central collection server

The entire system shrinks to **a single desktop application**.

### 2.2 A free query endpoint exists

`GET https://api.anthropic.com/api/oauth/usage` returns usage at **zero
inference cost**. It is the endpoint behind Claude Code's `/usage` command.
Three independent open-source tools (Claude-Code-Usage-Monitor, ccstatusline,
claude-swap) use the same call, which cross-confirms that it works from a
process outside Claude Code.

The alternative path to the same numbers — the `anthropic-ratelimit-unified-*`
response headers — can only be obtained by actually sending a
`POST /v1/messages` inference request, which consumes the very limit being
measured. **We do not adopt that path.** See §12.6.

## 3. The constraints that follow

### 3.1 Cost is not the constraint; throttling is

Free does not mean unlimited. This endpoint is subject to 429 throttling, and
**the budget is allocated per access token and per User-Agent tier.**

Sending `User-Agent: claude-code/<version>` places a client in the generous
first-party bucket. **We do not do this** (§5.2). We therefore remain in the
narrow bucket. Measurement puts the sustainable rate at roughly one request per
120 seconds per token; see docs/research/usage-endpoint.md and §6.2.1.

**Consequence: the polling floor is 3 minutes per account.** That value is set
by throttling, not by cost. The default interval is 5 minutes.

### 3.2 The app holds its own tokens, and that concentrates risk

The app performs its own OAuth login per account and stores the issued tokens
on the machine it runs on. It does not copy tokens from anywhere else, and it
neither reads nor writes Claude Code's credential file (§9.3).

The consequence is that **one machine ends up holding valid tokens for every
account you add**. If that machine is compromised, all of those accounts are
exposed together. This is a deliberately accepted trade-off, and anyone
installing this tool is accepting it too.

### 3.3 Terms-of-service position

Calling the Anthropic API with subscription (Pro/Max) OAuth credentials is a
gray area. The precise state of affairs:

- Read-only usage queries are **not addressed by any Anthropic document.**
  Consumer Terms §3(7), prohibiting "access through automated means such as
  bots or scripts," textually covers polling. The prohibitions in the Claude
  Code legal notice (providing claude.ai logins; routing requests on behalf of
  others using Pro/Max credentials) are narrower and do not textually cover
  querying your own account locally.
- Observed enforcement has consisted of credential scoping at the API edge
  (HTTP 400 "This credential is only authorized for use with Claude Code"), a
  legal request to OpenCode, and billing reclassification. **No account
  suspension has been documented**, and an Anthropic spokesperson has stated
  they would not terminate accounts.
- **One prohibition is unambiguous: misrepresenting your identity.**
  Anthropic's help documentation (2026-05-19) names it explicitly —
  *"Misrepresenting your identity to Anthropic's servers, routing third-party
  traffic onto subscription limits, or otherwise using third-party tools that
  violate the terms is prohibited and may be subject to enforcement."*

This project's response to that last point is §5.2 and §16.1. Because this
ships as open source, the risk transfers to third parties who install it, so it
is disclosed in the README as well as here.

## 4. Architecture

A single Tauri v2 application. No remote machines, no central server, no agents
to deploy.

A Rust core owns accounts, tokens, polling, and networking; a Svelte +
TypeScript webview receives state and renders it. The two communicate in both
directions via Tauri commands (webview → core requests) and events (core →
webview pushes).

### 4.1 Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `accounts` | Account metadata CRUD. JSON file. **Contains no tokens** | filesystem |
| `secrets` | Token store abstraction. Keychain first, encrypted file as fallback | `keyring`, filesystem |
| `auth` | PKCE OAuth flow, token refresh and revocation | `secrets`, HTTP |
| `usage` | One valid token → a list of usage windows. **The only module that knows the Anthropic API** | `auth` (for its HTTP client), HTTP |
| `scheduler` | Polling, manual refresh, visibility gating, throttle management, snapshot retention, failure classification | the four above |
| webview | Widget rendering, settings forms | Tauri IPC |

### 4.2 Data flow

```
scheduler ──token request──▶ auth ──▶ secrets
    │                         │ ▲
    │◀────────token───────────┘ │
    │                           │ HTTP client (§4.3)
    └──token──▶ usage ──────────┘
                 │
                 └──window list──▶ scheduler ──event──▶ webview
```

The flow of *state* is one-directional. The webview receives state and draws
it; user actions (manual refresh, adding an account) are requests to the core
via commands.

The one edge that is not part of that flow is `usage → auth`: `usage` borrows
`auth`'s configured HTTP client rather than building a second one, so that the
User-Agent and header policy of §5.2 has exactly one implementation. §4.3
records why that edge exists in place of an HTTP trait.

### 4.3 Intent behind the module boundaries

**`usage` is the only module that knows the Anthropic API.** The most unstable
part of this design — the response schema of an undocumented endpoint — is
confined to this one module. When the schema changes (and per §12.4 it already
changed once), only this module is touched.

`secrets`' store access sits behind a trait, so tests substitute an in-memory
implementation.

**`usage`'s HTTP access does not. Its seam is URL injection.** `fetch_usage_at`
takes the endpoint URL, and tests point it at a wiremock server on loopback;
the production entry point is the same function with §5.1's URL. `usage`
therefore takes `auth`'s concrete HTTP client — the dependency edge in §4.1 and
§4.2 — rather than a trait of its own.

The reason is `Retry-After`. `auth`'s HTTP trait (`TokenHttp::get_json`) returns
only a deserialized body and discards the response headers, so it cannot carry
that header at all — and §6.2 makes `Retry-After` the input to the entire
throttle policy. A second HTTP trait, shaped to carry headers and used by
exactly one caller, would buy nothing that injecting the URL does not.

**The property the trait was there for is unchanged**: every `usage` test runs
against a loopback mock, and no test touches the network or consumes throttle
budget (§14).

## 5. Usage retrieval (the `usage` module)

### 5.1 Data source

**The following call is the only data source for a Claude account.** §5.6 is
Codex's counterpart.

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <access_token for the account>
anthropic-beta: oauth-2025-04-20
Content-Type: application/json
User-Agent: quota-board/<version>
```

The following two paths are **explicitly out of scope**:

- **The response-header path** (`anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`)
  — obtainable only by sending a real inference request. It consumes the very
  limit being measured and turns the app from a "reader" into an "inference
  client," which is precisely the behavior every Anthropic prohibition targets.
  It is not even an emergency fallback — see §12.6.
- **Claude Code statusline JSON** — can report only the single currently active
  account, making it unsuitable for a multi-account monitor, and it requires
  Claude Code to be installed and running.

**Losing this endpoint ends the product.** Not degraded performance —
termination.

> This claim, and its restatement at §12.6, predate Codex existing as an
> independent second data source (§5.6). Whether losing this one endpoint still
> ends *the product* — as opposed to ending its Claude side while Codex
> accounts keep working — is unresolved and is not decided here.

### 5.2 User-Agent policy (a non-goal)

**We send an honest `quota-board/<version>`. We never impersonate
`claude-code/<version>`.**

The community's standard workaround for the 429 problem is User-Agent
impersonation, but that falls squarely inside the one unambiguous prohibition
quoted in §3.3. There is precedent: in March 2026 OpenCode received a legal
request and removed the `claude-code-20250219` beta header and its Anthropic
auth plugin.

For `anthropic-beta` we send only `oauth-2025-04-20`. We send no other header
that identifies Claude Code.

**The price is stated explicitly: we chose to remain in the narrow throttle
bucket, and that is why the polling floor is 3 minutes rather than seconds.**

### 5.3 The order in which the 7-day window is read (normative)

`seven_day` is **independently optional and may be null.** Weekly figures have
been observed arriving only inside `limits[]`, broken out per model:

```json
{ "kind": "weekly_scoped", "group": "weekly", "percent": 31,
  "resets_at": "...", "scope": { "model": { "display_name": "Fable" } } }
```

**Normative read order:**

1. Read `limits[]` **first**. From entries where `kind == "weekly_scoped"` or
   `group == "weekly"`, take `percent`, `resets_at`, and
   `scope.model.display_name` for use as the bar label.
2. If absent, fall back to the flat `seven_day` object (legacy).
3. If neither is present, explicitly render a **"weekly not reported"** state.

Note that step 2 applies only when `limits[]` contains no weekly element at
all. Weekly elements that were present but failed to parse must **not** trigger
the fallback — silently substituting the legacy number for one that failed to
read is how a confidently wrong figure reaches the screen.

**The number of bars per account may be 1, 2, or N (one per model for weekly).
A layout that assumes exactly 2 is forbidden.**

### 5.4 Unit normalization

Three conventions coexist, so normalize once at the module boundary.

| Source | Utilization | Reset time |
|---|---|---|
| `/api/oauth/usage` | `utilization`, 0–100 | `resets_at`, ISO-8601 string |
| `wham/usage` (Codex) | `used_percent`, 0–100 | `reset_at`, **Unix epoch seconds** |
| Response headers (unused) | `-utilization`, **0..1 fraction** | `-reset`, **Unix epoch seconds** |
| statusline JSON (unused) | `used_percentage`, 0–100 | `resets_at`, epoch seconds |

Canonical internal representation:

```rust
struct UsageWindow {
    window_id: String,
    label: String,
    percent: f64,              // always 0-100
    resets_at: DateTime<Utc>,
    scope: Option<String>,     // model name for per-model weekly windows
    source: Source,
    fetched_at: DateTime<Utc>,
}
```

### 5.5 Schema tolerance

The real response body carries more than the documented fields (additional
fields observed: `seven_day_cowork`, `seven_day_omelette`, `spend{}`,
`extra_usage{}`, `five_hour.limit_dollars/used_dollars/remaining_dollars`,
`limits[].severity/is_active`).

- Parse with serde, **ignoring unknown fields**.
- Retain the raw JSON so it can be inspected in a debug window.
- Treat unrecognizable shapes as an `UNKNOWN_SHAPE` state.
- **Never demote a missing or unparseable window to 0%.** Displaying a
  confidently wrong number is the worst failure mode.

### 5.6 The Codex data source

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <access_token for the account>
User-Agent: quota-board/<version>
Accept: application/json
```

**`/backend-api/codex/usage` is not this endpoint.** It answers a Cloudflare
challenge — an HTML body, `server-timing: chlray`, no `x-oai-request-id` — while
`wham/usage` answers 200 and agrees field for field with the account's own
usage page. Both were measured; §5.2's problem does not arise here either: the
honest `quota-board/<version>` User-Agent above is served on the first attempt,
with no header that identifies Codex CLI. Full method and data:
**docs/research/codex-usage-endpoint.md** (Spike F for the endpoint itself,
Spike G for what was and was not found about its throttling —
`Provider::min_interval_secs`'s doc comment carries the conclusion: a 180-second
floor chosen as a margin, not derived from a measured boundary, because none was
found).

`rate_limit_reset_credits` arrives in the same response, so the widget's
reset-credit line needs no second request to populate.

**Every account measured read 0% throughout.** `secondary_window`,
`additional_rate_limits`, and `code_review_rate_limit` were `null` in every
capture, so the shape a populated window takes is not measured — §5.5's schema
tolerance and the never-demote-to-0% rule carry the design across that gap, but
the gap itself stays open until an account with usage in flight is observed.

## 6. Polling policy

### 6.1 Numbers

- Default interval **5 minutes**. Configurable, with a **floor of 180 seconds**
  (per account).
- **Stagger** accounts so no burst occurs at startup.
- Global **concurrency of 1**.

> **On jitter.** An earlier draft of this list called for jitter on each
> account's schedule. It is deliberately not implemented, for two reasons that
> hold only while the two bullets above do. Global concurrency of 1 makes a
> burst impossible inside the app — `due()` yields at most one account per tick
> — and each account's next poll is anchored to its own last fetch, so accounts
> that start staggered stay de-synchronised without help. Adding jitter would
> mean injecting a source of randomness beside the injected clock, and the
> scheduler's testability rests on it being a pure function of that clock.
>
> **Revisit if global concurrency ever rises above 1**, or if scheduling stops
> being anchored per account. Either change lets accounts re-synchronise, and
> jitter starts earning its cost.

### 6.2 Interpreting Retry-After (two meanings)

| Value | Meaning | Response |
|---|---|---|
| `Retry-After: 0` | Budget exhausted | Back off roughly 180 seconds (per §6.2.1) |
| `Retry-After: N > 0` | Burst-rule hard block | Wait exactly N seconds. Probing does not extend it |

**Both branches are bounded above at one hour.** "Wait exactly N seconds" means
exactly N up to that bound and no further. `Retry-After` is externally supplied
input that reaches time arithmetic which *panics* on overflow, and past
`i64::MAX` a cast wraps it negative — landing the "throttled until" instant in
the **past**, so the client immediately re-hits a server that had just told it
to back off, silently defeating the one mechanism this section exists to
provide. An hour is far beyond any legitimate value; the largest ever observed
is 300 (§6.2.1). The bound is a safety limit on hostile or malformed input, not
a policy about how long to wait.

**Repeated 429s do not escalate the wait, and that is deliberate.** An earlier
draft of this line called for exponential backoff on repeated 429s. The
measurement in §6.2.1 landed afterwards: the sustainable rate after saturation
is roughly one request per 120 seconds, in a near-perfect alternating pattern.
The 180-second wait is therefore already above the rate the server will sustain,
and escalating past it buys no measured headroom while making the widget staler
the longer a throttle persists. The `N > 0` branch could not escalate in any
case — §6.2 requires obeying `N` exactly.

This is the same correction §6.2.1 applies to the "back off one full sliding
window" draft: a plausible policy chosen before measurement, replaced by the
measurement.

### 6.2.1 Measured behavior

Full method and data: **docs/research/usage-endpoint.md**. Summary, from 90
minutes of 60-second polling on a single account with an honest User-Agent:

- 26 consecutive successes, then the first 429; after six consecutive 429s, a
  near-perfect alternating pattern.
- All 34 `Retry-After` values observed **in that run** were `0`. See the
  correction immediately below — this is no longer the whole picture.
- Sustainable rate after saturation: roughly **1 request per 120 seconds**.

> **Correction (2026-07-30). `N > 0` has now been observed.** A later run at
> 10-second intervals produced `Retry-After: 300` on the first 429, and `299` on
> a probe one second later. Both branches of §6.2's table are therefore live,
> and the earlier "the header gives no usable wait hint" no longer holds: when
> `N > 0` arrives it is a real countdown and must be obeyed exactly.
>
> That same pair of observations also confirms the table's previously untested
> claim that **probing does not extend the block** — the deadline moved by
> exactly the one second that elapsed, not by the probe.
>
> The saturation count in that run (9 requests) is **not** a clean measurement
> of bucket depth; that account had carried other traffic earlier in the
> session. Only the throttle-scope conclusion (§12.8) is graded from it.

Two mechanisms (a continuous token bucket refilling every ~120s, and an hourly
quota of ~30) fit the data equally well and the measurement cannot separate
them. The practical conclusion is identical under both.

**Impact on the design:**

- An earlier draft's "on `Retry-After: 0`, back off one full sliding window
  (3600 seconds)" is **wrong.** Measured recovery is about 120 seconds; sleeping
  an hour means one 429 leaves the widget stale for that hour.
- **The 180-second floor in §6.1 is safe by measurement** (comfortably above the
  120-second minimum).
- The `N > 0` branch was retained despite not appearing in the first
  measurement, on the reasoning that the server might adopt that form at any
  time and that handling it cost nothing. **It has since appeared** (see the
  correction above). Deleting an unobserved-but-cheap branch would have left the
  client applying a 180-second backoff to a 300-second block.

### 6.3 Visibility gating

**Stop polling while the widget is not visible, and refresh once the moment it
becomes visible again.** Burning budget while nobody is looking means taking a
429 exactly when the user does look.

### 6.4 Manual refresh

**Manual refresh fires immediately. It is not rate-limited client-side, and it
waits for the global permit rather than giving up on it.** Every account row —
in the widget and in the settings window — carries its own refresh control.

The one thing that still refuses a press is §6.2's server-ordered wait. When a
429's `Retry-After` has not run out, do not fire; display **"throttled,
available after HH:MM"** instead.

> **This reverses an earlier draft, which applied §6.1's 180-second floor to the
> manual path as well.** Three things were wrong with it.
>
> The floor exists to bound *unattended* traffic. §6.1 sets the polling interval
> at 5 minutes and §6.2.1 measures the sustainable rate at roughly one request
> per 120 seconds, so the automatic schedule already runs well under budget; a
> press is one extra request against that headroom, at the one moment the user
> has said the number matters. The floor was buying protection the schedule had
> already bought.
>
> It also refused the button for 180 of every 300 seconds — the majority of the
> time, for the ordinary case of pressing after a poll. A control that usually
> declines is a control the user stops trusting, and the shipped bug report was
> exactly that: *"Refresh now does not work. I press it and the capture time
> never changes."*
>
> Third, the manual path used to give up whenever the polling loop held §6.1's
> global concurrency permit, returning the current state unchanged. That is a
> click that vanishes with nothing on screen to explain it. It now waits for the
> permit; the wait is bounded by one poll, and the row disables its button for
> the duration so the press is visibly in progress.
>
> **What is *not* relaxed:** the server's `Retry-After` (§6.2), the automatic
> schedule's floor (§6.1, enforced structurally inside `Scheduler::due`), and
> global concurrency of 1. Re-hitting a server that has just sent `Retry-After`
> spends a request without shortening the block by a second (§6.2, measured),
> so that refusal is the one worth keeping.

## 7. Failure states

Failure states are independent per account. One account's failure does not
affect another account's display.

### 7.1 State enumeration (all visible to the user)

| State | Meaning | Display |
|---|---|---|
| `OK` | Normal | value |
| `STALE(last_good, age)` | Automatic poll failed, last value retained | value + "n minutes ago", dimmed |
| `THROTTLED(retry_after)` | 429 | "throttled, after HH:MM" |
| `AUTH_EXPIRED` | Access token expired, refresh in progress | loading |
| `AUTH_DEAD` | `invalid_grant`, refresh chain permanently dead | "re-login required" (click starts OAuth) |
| `SECRETS_LOCKED` | Token store locked — OS keychain locked, or fallback passphrase not entered | "unlock" (click prompts for input) |
| `UNKNOWN_SHAPE` | Response parsing failed | "unknown" (not 0%) |
| `NETWORK` | Network error | treated the same as `STALE` |

**A stale value is never rendered without its age.**

**Which failure produces which state.** There is one mapping, in the core, and
every caller uses it rather than deriving its own — hand-derived copies at each
call site are how two paths come to disagree about what an error means. The
rows that are decisions rather than mechanics:

- A token missing from the store, or a stored blob that will not parse →
  `AUTH_DEAD`. §9.2 says `NOT_FOUND` means the account needs a re-login;
  routing either to `AUTH_EXPIRED` renders a spinner that never resolves where
  the user needs a clickable re-login.
- A locked store → `SECRETS_LOCKED` (§9.2), and **that state wins over
  `STALE`.** Left to shadow, it becomes unreachable the moment an account
  succeeds once: a keychain that locks while the app runs — a screen lock, the
  ordinary case — would show a dimmed old value forever and never offer the
  unlock affordance, which is the only remedy the state carries.
- Any other store failure → `NETWORK`. `NO_BACKEND` is answered by falling back
  to the encrypted file (§9.2) and is not meant to reach an account state at
  all; a backend failure is usually transient; `TooLong` is permanent but has no
  state of its own. All three render as the last value with its age.
- `invalid_grant` → `AUTH_DEAD` on one strike (§10.5).
- A transport failure while refreshing → `NETWORK`. A failed connection is not
  an auth failure, and treating it as one eventually quarantines an account
  over a flaky link.
- Any other OAuth failure, and a usage query the server answers 401/403 →
  `AUTH_EXPIRED`. A refresh is the remedy in both cases, and the next poll
  performs one.
- A non-2xx usage response → `NETWORK`. **A 5xx is not a network error**; the
  mapping is by *rendering*. This table defines `NETWORK` as "treated the same
  as `STALE`", and keeping the last value with its age is the right display for
  a fetch that failed without implicating the credential. The honest
  alternative is a ninth state whose display is identical to two existing ones.
- An edge refusal of a Codex usage request — one that never reached the API at
  all, distinguished from an API answer by the absence of `x-oai-request-id`
  (§5.6) — → `NETWORK`. No new state was added for it: this table's states
  exist to carry remedies, and an edge refusal has the same remedy as `NETWORK`
  already does — none. Reading it as `AUTH_DEAD` would mark a healthy account
  dead and send the user through a re-login that would be refused identically,
  since the account was never what was asked about.
- A 429 is **not** one of these at all. It carries a wait, so it drives §6.2's
  throttle path instead; folding it in here would discard the `Retry-After`.
- A rotation that succeeded over HTTP but failed to persist changes **no**
  state — the token is live for this cycle. It is warned about, carrying the
  store error rather than a flag, because the cases differ: a locked store
  recovers on unlock, a backend failure is usually transient, and `TooLong` is
  permanent — that blob will never fit, so every restart will silently demand a
  re-login until someone is told why (§9.3).

No error type on any of these paths carries a credential, and that is a rule
rather than an observation: **any type holding a live credential hand-writes its
`Debug` and prints `"<redacted>"` for the sensitive fields — it is never
derived.** `TokenSet` is the shape to copy. A derived `Debug` reaches a log line,
an `assert_eq!` failure, or a panic message, and this repository has shipped that
defect twice.

### 7.2 How loud failures are

| Situation | Behavior |
|---|---|
| Automatic poll failure | Silently `STALE`. No banner, no popup |
| Manual refresh failure | A clear error with its reason on that account's row |
| `invalid_grant` | **One-strike quarantine.** Do not retry — each retry only burns a fresh 401/429 |

### 7.3 Freshness indication

Only two levels. Within twice the polling interval, show the value alone;
beyond that, append "n minutes ago" and dim the row. Three or more levels is
information users will not distinguish.

### 7.4 Application restart

Cache the last snapshot to disk so that, until the first poll completes, the
cached value is shown as `STALE` rather than an empty screen.

## 8. UI

### 8.1 Widget window

Undecorated (`decorations: false`), always on top, hidden from the taskbar, not
resizable, starting with `visible: false` and shown after the position is
restored (to avoid placement flicker). Fixed width of about 280px; height
follows content.

```
┌──────────────────────────────┐
│                            ⚙ │
│  work@example.com          ↻ │
│  5h  ███████░░░  72%   1h23m │   ← yellow
│  7d  ████░░░░░░  41%   4d12h │   ← teal
│                              │
│  personal@example.com      ↻ │
│  5h  ██░░░░░░░░  18%   2h05m │   ← green
│  weekly (Opus) █████████░ 91%│   ← per-model weekly window
│  weekly (Sonnet) ███░░░░░ 27%│
│                              │
│  side@example.com   12m ago ↻│
│  5h  ████░░░░░░  38%   0h47m │   ← entire row dimmed
│  weekly not reported         │
└──────────────────────────────┘
```

**The fact that the number of bars can differ per account is the central
constraint of this layout** (§5.3).

**Every account row carries its own `↻`, on every state** — including the ones
with no numbers to show, which are the rows most worth retrying. It fires
immediately (§6.4). It stays at full strength on a dimmed stale row: staleness
is when the user most wants to press it, so dimming the one remedy the row
offers would point the affordance the wrong way.

### 8.2 Color warning steps

The same thresholds as existing terminal statusline tools, for consistency.

| Utilization | Color |
|---|---|
| 0–39% | green |
| 40–69% | teal |
| 70–89% | yellow |
| 90%+ | red |

### 8.3 Window dragging

**Use manual `startDragging()`. `data-tauri-drag-region` is forbidden.**

Rationale: (a) in v2 the attribute applies only to the element it is attached
to, so it would have to be added to every child individually. (b) It has
double-click-to-maximize built in with no way to disable it, and
`maximizable: false` does not work on Linux, so the widget can be maximized by
a double click. (c) It is known to break under the isolation pattern.

Implementation: `onmousedown` → `if (e.buttons === 1) appWindow.startDragging()`.
Requires the `core:window:allow-start-dragging` capability.

> macOS caveat: the tao documentation notes that `drag_window` can suppress
> button-release events, and there are reports that an unfocused window's first
> click only grants focus, requiring a second drag. This applies directly to an
> always-on-top widget that normally does not hold focus.

### 8.4 Settings window

A separate, ordinary (decorated) window, entered via the widget's gear icon.

- **Account list**: add / remove / edit display name / reorder
- **Add account**: browser OAuth → added automatically on completion. No limit
  on account count
- **Polling interval** (floor 180 seconds) plus a "roughly N queries per day"
  readout
- **Launch at login** toggle
- **Opacity**
- **Store status**: whether the current tokens live in the OS keychain or in
  the encrypted file (§9.2)
- **Debug**: view the last raw JSON response (§5.5)

### 8.5 Tray icon and global hotkey

For recovery and quit only. The menu has two items: "show / hide widget" and
"quit". Settings are deliberately not included.

**Every action must live in the tray *menu*.** Tauri documents that icon click
events (`TrayIconEvent`) do not fire on Linux, so a "left-click to toggle the
widget" design does nothing there. `show_menu_on_left_click` is likewise
unsupported on Linux.

For the tray to appear on Linux, `libayatana-appindicator3-1` must be
installed. Without it the icon **silently** fails to appear, so it is declared
as a package dependency.

The global hotkey is bound to toggling widget visibility and is reconfigurable
in settings. Per §11.1, however, registration fails under pure Wayland.

## 9. Storage

### 9.1 Locations

| Data | Location |
|---|---|
| Account metadata, settings | OS config directory (the `dirs` crate) |
| Window position and size | `tauri-plugin-window-state` → `app_config_dir()/.window-state.json` |
| OAuth tokens | §9.2 |
| Snapshot cache | OS cache directory |

Platform-specific paths are resolved by `dirs`. **No path, hostname, or
username is hardcoded anywhere.**

### 9.2 Token store (the `secrets` module)

**OS keychain first, encrypted file as fallback.**

When a keychain is available, use it — it unlocks automatically at login, which
suits launch-at-login. Otherwise fall back to a file encrypted with a user
passphrase.

The need for this fallback is not hypothetical. **The Linux Secret Service
requires *both* a D-Bus session bus and a daemon owning
`org.freedesktop.secrets` (gnome-keyring, KWallet, KeePassXC)**; a session bus
alone is not enough. It fails under SSH, tty, and headless environments, under
minimal WMs that auto-start nothing (i3/sway/dwm), and whenever the login
collection is locked.

`secrets` must distinguish three states and surface each differently:
`NO_BACKEND` / `LOCKED` / `NOT_FOUND`.

How those map onto account states (§7.1):

- `NO_BACKEND` → switch to the fallback store. Not surfaced as an account
  state. Prompt once to set a passphrase, then prompt for it on every
  subsequent run.
- `LOCKED` (keychain locked) or fallback passphrase not entered →
  `SECRETS_LOCKED`.
- `NOT_FOUND` → treat that account as `AUTH_DEAD` (re-login required).

While the fallback store is in use, the benefit of launch-at-login is reduced —
the widget cannot populate values until the passphrase is entered after boot.
This is stated explicitly in the settings screen.

**On the `keyring` crate version.** keyring 3.x **silently degrades to an
in-memory mock store if platform features are not specified** — refresh tokens
are then stored nowhere and vanish when the process exits, leaving no trace in
the logs. keyring 4.1.5 fixed that default (`default = ["v1"]`).

**Decision: keyring 4.1.5 with default features**, plus a canary
write/read/delete self-check at startup that hard-fails if the store does not
actually persist. The risk of silent data loss outweighs the risk of a young
version, and the canary is included either way.

**`tauri-plugin-store` is forbidden for token storage** — it is plaintext JSON.
`linux-keyutils` is also forbidden — the kernel keyring is in-memory and
vanishes on reboot.

### 9.3 Key structure and isolation

- **The account primary key is `account.uuid` from the OAuth token response.**
  Email is for display and is user-editable. Neither email nor a user label is
  ever used as a key.
- Store entries are keyed **uniquely by `account.uuid` under our own service
  name**. Lookups must be exact-key lookups, never "the first entry whose
  service matches."
- **The key format is deliberately asymmetric between providers**, not for lack
  of taste. Anthropic entries stay unprefixed (`<uuid>:tokens`) because changing
  that format orphans every existing keychain entry — the lookup falls to
  `NOT_FOUND`, §9.2 maps that to `AUTH_DEAD`, and the upgrade forces a
  re-login on every account already added. New providers are namespaced from
  the start (`openai:<id>:tokens`): the token store is the one place a bug
  means credential loss, so it carries no migration to get wrong. See
  `provider::token_key`.
- Per-entry JSON blob:
  `{ access_token, refresh_token, expires_at, refresh_token_expires_at, scopes[], client_id }`

  > **Windows Credential Manager has a hard 2560-byte limit per credential
  > blob** (`CRED_MAX_CREDENTIAL_BLOB_SIZE`). Packing the access token and
  > refresh token into one blob approaches that limit. Treat `TooLong` as a
  > first-class error path, and if measurement shows the limit is exceeded,
  > split entries per token. The string API (`set_password`) encodes to UTF-16
  > before checking, giving an effective limit of about 1280 ASCII characters —
  > **use the byte API (`set_secret`).**
- Metadata file:
  `{ uuid, display_label, email, created_at, last_ok_at, quarantined }` —
  **no tokens**
- **Every cache is fingerprinted with a one-way hash of the current access
  token.** Re-logging in invalidates the cache immediately.

> All three of these rules come from real bugs in prior art. ccstatusline #521
> (OPEN): when the macOS login keychain holds multiple `Claude Code-credentials`
> entries for different accounts, **every** widget displays `[No credentials]`.
> #459: caches were not invalidated on account switch, so stale values persisted
> until the TTL. #486: a prefetch lock was never released, producing spurious
> `[Timeout]` after an account switch.

- **`~/.claude/.credentials.json` is neither read nor written.** This app does
  not depend on, interoperate with, or interfere with another tool's credential
  storage.

## 10. OAuth (the `auth` module)

authorization_code + PKCE (S256), public client, no client_secret. No
device-code alternative exists.

### 10.1 Endpoints

| Purpose | URL |
|---|---|
| authorize (subscription) | `https://claude.com/cai/oauth/authorize` |
| token | `POST https://platform.claude.com/v1/oauth/token` |
| revoke | `POST https://platform.claude.com/v1/oauth/token/revoke` |
| manual-paste redirect | `https://platform.claude.com/oauth/code/callback` |
| success redirect | `https://platform.claude.com/oauth/code/success?app=claude-code` |
| API base | `https://api.anthropic.com` |

Note that authorize is **not** `claude.ai/oauth/authorize`. Many older
integration clients still use that address. `claude.ai` itself is not used for
token or usage traffic at all.

**OpenAI (Codex)**, from `auth.openai.com`'s discovery document
(`/.well-known/openid-configuration`) and cross-checked against the codex
binary's own request log — docs/research/codex-usage-endpoint.md, "OAuth
endpoints":

| Purpose | URL |
|---|---|
| authorize | `https://auth.openai.com/api/accounts/authorize` |
| token (discovery-advertised) | `https://auth.openai.com/api/accounts/oauth/token` |
| token (CLI-observed) | `https://auth.openai.com/oauth/token` |
| revoke | `https://auth.openai.com/api/accounts/oauth/revoke` |

**The CLI does not use the token endpoint its own issuer advertises** — its
request log records the second URL above instead. `Provider::spec` uses the
discovery-advertised one, because it is the documented contract; the
CLI-observed one is recorded rather than adopted, so it is one grep away
(`crates/core/src/provider.rs`) the day a refresh starts failing against it.
**No OAuth flow has ever been run against either** — every row in this table
comes from discovery or from reading the binary, not from a completed
authorize/token exchange.

### 10.2 client_id

```
9d1c250a-e61b-44d9-88ed-5944d1962f5e
```

This is Claude Code's public client. **Anthropic has no third-party client
registration program, so reusing it is unavoidable.**

**Visible consequence: the OAuth consent screen displays "Claude Code" rather
than this application's name.** This is stated in the README.

It is **overridable** via settings or an environment variable, so that if
Anthropic ever issues third-party client_ids we can switch immediately.

### 10.3 Flow

**PKCE**: verifier = base64url(32 random bytes), with `+`→`-`, `/`→`_`, and `=`
stripped. challenge = base64url(sha256(verifier)). `state` is an independent
base64url(32 random bytes).

**authorize query** (in this exact order): `code=true`, `client_id`,
`response_type=code`, `redirect_uri`, `scope` (space-joined), `code_challenge`,
`code_challenge_method=S256`, `state`.

The leading non-standard `code=true` makes the server render a pasteable
`code#state` page — it is what makes the manual fallback possible, so it is
retained.

**Redirect**: bind an HTTP server to an OS-assigned port (port 0) on
`127.0.0.1` with the path `/callback`. **The redirect_uri string is literally
`http://localhost:<port>/callback` even though the socket binds to 127.0.0.1.**
Validate `state` before accepting the code (on mismatch, 400 "Invalid state
parameter"). Then 302-redirect the browser to the success URL.

**Always construct both URLs.** Open the browser with the loopback URL and
display the manual URL as a fallback. The manual-paste format is
`<code>#<state>`, split on `#`, with both parts required.

**Token exchange**: POST, `Content-Type: application/json`, with a **JSON body,
not form-encoded**:

```json
{ "grant_type": "authorization_code", "code": "...", "redirect_uri": "...",
  "client_id": "...", "code_verifier": "...", "state": "..." }
```

Including `state` in the token body is non-standard, but it is the shape this
server expects. Timeout 30 seconds; 401 means "Invalid authorization code".

**Token response**: `access_token`, `refresh_token`, `expires_in`,
`refresh_token_expires_in` (non-standard), `scope` (space-separated string),
and optionally `account:{uuid, email_address}` and `organization:{uuid}`.

### 10.4 Scopes

**Request: `user:profile` alone. `user:inference` is deliberately not
requested.**

Claude Code gates its own `/api/oauth/usage` call on both `user:profile` and
`user:inference`, but that is a **client-side** gate. A live spike against a
real account measured the server side directly and established the full
lifecycle works with `user:profile` alone: the consent screen accepted the
narrowed scope (the authorize URL carried `scope=user%3Aprofile`), the token
response came back scoped to `user:profile` with no silent widening, an
initial `GET /api/oauth/usage` returned 200 with a complete response, a
refresh with the narrowed stored scope succeeded and kept `user:profile`
rather than the server re-adding `user:inference`, and a usage query after
that refresh also returned 200. Claude Code's requirement of both scopes is
therefore confirmed to be a client-side gate only, not a server one (§13).

A token that cannot run inference is not an optimisation — it is the
terms-of-service position this whole project is built around (§5.2). What we
did **not** verify, and will not: that the resulting token is actually
incapable of inference. Confirming that would mean calling
`POST /v1/messages`, which this project forbids outright. What is recorded
here is narrower and honest about that limit: we requested a narrower scope,
and the server issued it.

We do not request `org:create_api_key`, `user:sessions:claude_code`,
`user:mcp_servers`, or `user:file_upload` — they are not needed.

**OpenAI's counterpart.** Discovery's advertised scope list for OpenAI
(`openid`, `profile`, `email`, `offline_access` — §10.1) contains nothing
resembling `user:inference`, so there is no inference scope to decline the way
Anthropic's is declined above. **That is not evidence the resulting token
cannot run inference** — access there is likely account-based rather than
scope-gated. Establishing otherwise would mean sending an inference request,
which this project forbids outright, so it stays unmeasured and is stated that
way (docs/research/codex-usage-endpoint.md, "OAuth endpoints").

### 10.5 Expiry and refresh

Store `expires_at = now + expires_in * 1000` (absolute epoch ms). Treat as
expired when `now + 300_000 >= expires_at` (a 5-minute skew).

Compute `refresh_token_expires_at` from `refresh_token_expires_in` when it is
numeric. Fall back to now+30 days **only on the initial exchange**; on refresh,
keep the previous value with no fallback.

> Observed access-token lifetime is on the order of hours. **Refresh is
> routine, not exceptional.**

**Refresh request**: POST to the same token URL, JSON
`{ grant_type: "refresh_token", refresh_token, client_id, scope: "<space-joined>" }`,
timeout 30 seconds, anything other than 200 is a failure.

**Important — send the stored scopes back verbatim.** Falling back to a
hardcoded scope list **silently narrows the scopes on every refresh**, which is
an observable phenomenon, not a theoretical one.

**One retry on `invalid_scope`**: if the first refresh returns HTTP 400 with
`code === "invalid_scope"`, retry **exactly once** using the stored scopes
verbatim.

**Concurrency**: serialize refreshes per account. Even in a single process, a
scheduler poll and a user's manual refresh can overlap. Take a lock, and
compare-and-swap against the stored refresh token before writing (if the value
changed underneath us, adopt the new value rather than overwriting it).

**`invalid_grant`**: means the refresh chain is permanently dead and cannot
recover on its own. Only re-login helps. **Quarantine the account on one
strike** and surface `AUTH_DEAD`. Do not retry.

**What the lock and the compare-and-swap do not cover.** They are worth having
and they are narrower than they look; both facts are recorded here so neither
is rediscovered as a surprise.

- **Across processes the compare-and-swap is largely inert.** Under §10.7's
  single-use rotating chain, the loser's refresh has already failed with
  `invalid_grant` before its re-read runs. The swap's real job is the
  re-login-landing-mid-refresh case, which is in-process — which is why the
  paragraph above scopes itself to a single process.
- **In one process it is correct on both stores**, including the encrypted file
  store, whose write updates the cached map that its read serves. **Across
  processes on that store the re-read is blind**, because the read serves that
  cached map rather than the disk. A store-level compare-and-swap *would* be
  genuinely atomic there — its write already takes an exclusive lock and
  re-reads from disk inside the critical section — but not on the keychain,
  which exposes no such primitive and is the primary store (§9.2). One uniform
  implementation above the store abstraction was chosen over two divergent ones.
- **A crash between the token endpoint's 200 and the store write loses the
  rotation permanently.** The store keeps the pre-rotation token, the server has
  moved past it, and the next launch gets `invalid_grant` — so the visible
  outcome is `AUTH_DEAD` and a forced re-login. Neither the lock nor the
  compare-and-swap addresses this.
- **Nothing structurally prevents a future caller from refreshing directly**
  and bypassing the lock. The compare-and-swap narrows that window; it does not
  close it.

### 10.6 Revocation

On account deletion, POST
`{ token, token_type_hint: "refresh_token", client_id }` to
`<TOKEN_URL>/revoke`. Timeout 5 seconds, best-effort — swallow failures and
proceed with local deletion.

### 10.7 Refresh-chain isolation — the benefit and the measured risk

The practical benefit of our own OAuth: because we obtain our own grant per
account, we hold **independent refresh chains** and do not compete with Claude
Code's single-use chain. The race that consumes most of clauth's and
claude-swap's complexity — where whoever refreshes first invalidates the other
— simply does not arise for us.

**The risk this section was written for has been measured, and it does not
materialise.** It was not known whether the server binds refresh chains per
grant or per `(account, client_id)`; under the latter, reusing Claude Code's
client_id would have meant our refresh invalidating a Claude Code session on the
same account, with the damage landing outside this app on the user's primary
tool.

**Measured: chains are bound per grant.** One account signed in to Claude Code
on several machines holds one grant per machine under the same
`(account, client_id)` pair, and those machines run in parallel for days without
either being asked to re-authenticate. Access tokens last eight hours (§13), so
each machine has refreshed successfully many times *after* the others obtained
their grants — which a per-`(account, client_id)` binding would have made
impossible. Our own grant is obtained through the same authorization_code + PKCE
flow, under the same client_id, requesting a subset of Claude Code's scopes; the
server has no basis on which to treat it differently.

What remains untested is narrow: no experiment has driven our grant and a Claude
Code grant against each other directly. Doing so requires deliberately risking a
working session, and the evidence above — one class of grant observed against
itself at scale, over days — is the strongest available without that. It is
recorded as measured rather than proven.

Had it gone the other way, the fallbacks were long-lived tokens via
`claude setup-token` (an official feature, designed not to compete with rotating
chains), or documenting a "one session per account" constraint. Neither is
needed.

## 11. Platform

### 11.1 Linux display server policy

**Force `GDK_BACKEND=x11` at startup.**

Under Wayland, all of the following are **silently ignored** — no error, no
log, no exception:

| Feature | Wayland behavior |
|---|---|
| `alwaysOnTop` | Unsupported. Even on X11 it is only a hint to the WM |
| `skipTaskbar` | Unsupported. The widget appears in the taskbar/overview |
| `set_position` / `outer_position` | Unsupported. Wayland has no global coordinate system |
| `shadow` | Unsupported |
| `maximizable` / `minimizable` | Unsupported |

tauri#14913 is open about this silence. **Design for the silence, not for an
exception.**

The only geometry operation that works under Wayland is drag-to-move, because
tao implements it via `gtk_window_begin_move_drag` rather than absolute
positioning.

The price of forcing XWayland is slight blurriness on HiDPI displays. Staying
on top and remembering its position is the definition of a widget, so that
takes priority over sharpness.

**In environments where XWayland is unavailable** (pure Wayland compositors,
XWayland not installed), start under Wayland but inform the user in-app that
the features above are inactive, and gray out those items in settings. Do not
let them fail silently.

**Global hotkeys do not work in that environment either.** On Linux,
`global-hotkey` opens an x11rb connection directly based on `$DISPLAY` and has
no Wayland backend. This is independent of `GDK_BACKEND=x11` — that variable
affects only GDK's window creation. Therefore **under pure Wayland the tray
icon is the only way to recover the widget.** Do not treat global-hotkey
registration failure as fatal; inform the user and continue running.

### 11.2 Window state persistence

`tauri-plugin-window-state`. StateFlags: SIZE=1, POSITION=2, MAXIMIZED=4,
VISIBLE=8, DECORATIONS=16, FULLSCREEN=32.

Two of its behaviors fit a widget exactly: it restores position only when the
saved rectangle intersects a currently available monitor (otherwise deferring
to the OS — the correct behavior for docking/undocking), and it tracks
prev_x/prev_y.

Apply `.skip_initial_state("settings")` to the settings window so it does not
fight the widget's placement.

Use `tauri-plugin-positioner` only as a named-placement fallback for when
absolute coordinates are unavailable. **It too goes through `set_position`
internally, so it is not a Wayland solution.**

### 11.3 Launch at login

`tauri-plugin-autostart`, which uses `auto-launch` 0.5 internally (not 0.6 —
the caret on a 0.x version pins it below 0.6).

| OS | Mechanism |
|---|---|
| Linux | `~/.config/autostart/<app_name>.desktop` (XDG) |
| Windows | `HKCU\SOFTWARE\...\Run` string value. Not HKLM → no elevation required, per-user |
| macOS | **LaunchAgent mode** (`~/Library/LaunchAgents/<app_name>.plist`) |

**macOS AppleScript mode is an explicit non-goal.** It invokes System Events
via osascript, which triggers a TCC automation consent prompt, requires
`NSAppleEventsUsageDescription`, survives only the `--hidden`/`--minimized`
arguments, and substitutes the bundle path only when `.app/` appears exactly
once in the canonical path (otherwise it silently registers the raw Unix
executable, which shows up as "Unix Executable" in Login Items).

**Pitfall**: the plugin resolves its target with `std::env::current_exe()` at
setup time, so enabling autostart under `cargo tauri dev` registers
`target/debug/...`. **Do not validate autostart with a development build.** On
Linux, AppImage builds prefer the APPIMAGE environment variable path, so `.deb`
and AppImage take different code paths and **must be tested separately.**

### 11.4 Memory

**The commonly cited 30–60MB is not true on Linux.** Measurements of a default
Tauri app on Ubuntu 22.04 (tauri#5889): USS Electron 118MB vs Tauri 125MB; PSS
Electron 207MB vs Tauri 185MB — comparable, not 4× better.

**This widget's expected idle footprint is 120–200MB PSS.** Tauri is
multi-process on Linux (GTK main + WebKitWebProcess + WebKitNetworkProcess), so
measure PSS from `/proc/*/smaps_rollup`, not RSS.

**WebKitGTK has a documented monotonically increasing memory leak in long-lived
processes** — reports describe RSS growing without being returned, eventually
invoking the OOM killer. A polling widget that stays resident for 24 hours
**needs a periodic webview reload or a memory watchdog. Treat this as a
functional requirement, not an optimization.**

> **On the watchdog.** It is deliberately not implemented. A design for one was
> written, reviewed before any code, and dropped — the reasons are worth keeping
> because they are the reasons anyone would write the same design again.
>
> **It would apply to one platform of three.** The leak above is WebKitGTK's,
> which is the Linux webview. macOS runs WKWebView and Windows runs WebView2;
> neither shares that engine or that report. Two thirds of the shipped bundles
> would carry a component that can never act.
>
> **It has never been measured against this app.** The footprint figures above
> come from a default Tauri app (tauri#5889); the leak itself is cited from
> third-party reports, not from an observation of this binary. `docs/research/`
> holds no memory measurement, and §12 does not list memory as a risk. The
> workload here is also unlike the reports': a few rows of text and block glyphs,
> rewritten once per polling interval.
>
> **The obvious design does not work, and the review found it before it was
> built.** Reading `/proc/self/smaps_rollup` measures the GTK main process —
> `smaps_rollup` is strictly one process's own rollup, and the leaking heap is in
> WebKitWebProcess, a different pid. That is why the sentence above says
> `/proc/*/smaps_rollup` with a glob: the number has to be summed across the
> process tree, including the intermediate parent WebKitGTK's sandbox inserts.
> A watchdog on `self` cannot fire, and one that cannot fire is worse than none —
> it reads as a mitigation while providing nothing.
>
> **And the remedy is unproven.** `location.reload()` returns objects to the same
> allocator this section says does not return memory. Whether it reclaims
> anything has never been measured before and after a forced reload.
>
> **Revive it when there is a measurement**: run on Linux long enough to see PSS
> summed across the process tree grow materially above the 120–200MB idle band,
> then force one reload and record PSS on both sides of it. That number decides
> both whether the feature is needed and whether a reload is the right lever —
> if it is not, the remedy is a different one (recreating the webview window, or
> a supervised restart) and belongs in a different design.

## 12. Risks

### 12.1 The 7-day number may not exist in the shape the UI assumes

See §5.3. "Two bars per account" is not a safe assumption; measurement found an
account where the weekly figure existed only as a per-model `weekly_scoped`
entry.

### 12.2 429 throttling is an ecosystem killer

A sustained 429 regression in March 2026 broke every statusline tool.
anthropics/claude-code#30930 is **still open** with no policy response from
Anthropic, and duplicate issues were closed as NOT_PLANNED.

**If an honest User-Agent is ever throttled to effectively zero, the entire
architecture collapses, and no fallback exists that does not consume
inference.**

### 12.3 Identity misrepresentation is the one unambiguous prohibition, and this project brushes against it twice

(a) User-Agent impersonation — **we do not do it.** That decision forces the
3-minute polling floor.
(b) Reusing Claude Code's public client_id — **unavoidable.** There is no
third-party registration program. The consent screen displays "Claude Code".

Precedent: in March 2026 OpenCode merged an "anthropic legal requests" PR
removing the `claude-code-20250219` beta header and the Anthropic auth plugin.

### 12.4 Schema drift in an undocumented endpoint

`/api/oauth/usage` **has already changed shape once.** Around July 2026,
per-model weekly usage moved from the flat `seven_day_sonnet`/`seven_day_opus`
keys into weekly_scoped entries in `limits[]`, and the flat keys began
returning null for models that had actual usage (ccstatusline #503).

Expect it to change again. **The failure mode to avoid is rendering a
confidently wrong number. Degrade to "unknown."**

### 12.5 Refresh-chain collision — measured, does not occur

See §10.7. This was second in severity only to the 7-day problem, because the
damage would have landed on the user's primary tool. Chains are bound per grant,
so it does not arise. Retained here rather than deleted: the reasoning is what
justifies reusing Claude Code's client_id at all, and a future change to the
server's binding would revive it.

### 12.6 The header fallback is not a fallback

If `/api/oauth/usage` disappears, the only other confirmed source of the 5-hour
and 7-day numbers is the response headers, and those require a real inference
request per account. That consumes the very limit being measured, and it turns
the app from a reader into an inference client.

**Losing `/api/oauth/usage` is a product-termination event, not a
degradation.**

### 12.7 Multi-account credential and cache bugs are a recurring bug class

See §9.3. Keying on anything other than `account.uuid`, or failing to
fingerprint caches with the token, reproduces these bugs by default.

### 12.8 The per-account assumption — measured for N=3

The design rests on "limits are per-account, so one session per account
suffices." The open part was whether N accounts polling from one process and IP
receive N independent 429 budgets or are collapsed into per-IP throttling.

**Measured: the budgets are independent per account.** Three accounts were
signed in from one machine. One was driven to a 429; in the same second, the
other two returned 200, and a re-probe of the throttled account confirmed it was
still blocked rather than momentarily unlucky. Under per-IP throttling all three
would have failed together.

The polling constants in §6.1 therefore do **not** need to scale with account
count. A per-IP result would have forced the interval to be multiplied by the
number of accounts, and the 180-second floor with it.

Scope limit: three accounts on one machine, one run. Nothing here bounds how
many accounts a single IP can poll before some other limit appears; the
conclusion is that the *429 budget* is not the shared thing.

## 13. Verification status

What has been measured, and how, is recorded in
**docs/research/usage-endpoint.md** — one section per run, Spikes A through E.
In summary:

| Item | Status |
|---|---|
| `/api/oauth/usage` returns 200 with an honest User-Agent | **confirmed** |
| The response's top-level key set and schema | **confirmed** |
| `seven_day` null with weekly data only in `limits[]` | **confirmed** |
| The 429 boundary and `Retry-After: 0` semantics | **confirmed** |
| `Retry-After: N > 0` also occurs, and is a real countdown a probe does not extend | **confirmed** (§6.2.1) |
| Access-token lifetime: **8 hours** (28,799 s, twice) | **confirmed** |
| Refresh rotates both tokens on every call | **confirmed** |
| The refresh chain's expiry is absolute and is **not** extended by refreshing | **confirmed** |
| Different accounts report **different window sets** | **confirmed** |
| Whether our refresh disturbs a Claude Code session (§10.7) | **observational** — chains are per grant; it does not. Not an experiment; see below |
| Whether `user:profile` alone passes server-side (§10.4) | **confirmed** — it does; `user:inference` dropped |
| Whether 429 budgets are independent per account (§12.8) | **confirmed** — independent, for N=3 on one IP |
| An unsigned bundle reads as *"damaged"*, an ad-hoc signed one as *"could not verify"* (§15) | **confirmed** — both seen on macOS 26, one evening apart |
| Upgrading re-prompts for keychain access **once per account** | **confirmed** — N=3, on the 0.2.0 → 0.2.1 upgrade that also changed the bundle identifier |
| Dismissing that prompt leaves every account reading as `SECRETS_LOCKED` | **not measured** — every prompt was approved |

**One row is graded differently, and the difference is the point.** Every other
row above was measured on the wire, in a run written down with its method in the
research document. The §10.7 row was not. It rests on long-standing everyday use
of one class of grant observed against itself, which §10.7 itself records as
"measured rather than proven" and the research document as "observational, not a
controlled experiment". Bolding it as **confirmed** alongside the wire-measured
rows erased a distinction that the prose keeps in both places, and this table is
where a reader looks precisely when they do not want to read the prose.

**What would upgrade it**: a run that drives one of this project's grants and a
Claude Code grant on the same account directly against each other — refresh
ours, then confirm the Claude Code session still refreshes rather than being
sent to re-authenticate. That requires deliberately risking a working session on
the user's primary tool, so it has not been done, and the evidence above is the
strongest available short of it.

## 14. Test strategy

| Target | Method |
|---|---|
| `usage` | Inject the endpoint URL and point it at a wiremock server on loopback (§4.3); verify parsing against stored response fixtures. **No real network calls.** Fixtures must include: both 5h and 7d present; `seven_day: null` with weekly_scoped; weekly entirely absent; many unknown fields; a completely alien shape (`UNKNOWN_SHAPE`) |
| `scheduler` | Inject the clock to verify polling interval, stagger, freshness transitions, visibility gating, both meanings of `Retry-After`, and exponential backoff without real waiting. **Not jitter** — §6.1 records that it is deliberately not implemented |
| `auth` | A local mock OAuth server for the PKCE flow, state-mismatch rejection, the manual-paste path, scope-preserving refresh, the one `invalid_scope` retry, one-strike `invalid_grant` quarantine, and serialized concurrent refresh |
| `secrets` | Contract tests against an in-memory implementation. Distinguish the three states `NO_BACKEND`/`LOCKED`/`NOT_FOUND`. **Must test that the canary self-check detects a mock store** |
| `accounts` | CRUD round-trip in a temporary directory. uuid keying, cache invalidation by token fingerprint |
| webview | Extract color-step selection, "n minutes ago" formatting, bar width computation, and **variable bar-count rendering (1/2/N/0)** as pure functions and unit-test them |

**No test may consume real account limits or throttle budget.**

## 15. Distribution

- **License**: MIT
- **Build**: GitHub Actions 3-OS matrix
- **Linux primary**: `.deb` / `.rpm` (4–8MB, linked against the system
  `libwebkit2gtk-4.1`)
- **AppImage**: optional. **75–110MB for the same app**, because it bundles the
  entire WebKitGTK dependency closure
- **Windows**: `.msi`, about 3.5MB / **macOS**: `.dmg`, about 9MB
- **Flatpak/Snap: out of scope for v1.** Under sandboxing, Secret Service goes
  through the XDG portal rather than the session bus, and `~/.config/autostart`
  entries are isolated from the host, so both the keychain and the autostart
  designs would need separate validation
- **macOS App Store: not a goal.** Transparent windows require
  `macOSPrivateApi`, which forfeits App Store distribution eligibility
- **Code signing**: no Developer ID and no notarization. The macOS bundle **is**
  ad-hoc signed (`bundle.macOS.signingIdentity: "-"`), and that is not a
  cosmetic difference from signing nothing at all. Tauri only runs `codesign`
  when an identity is configured; with none, the bundle ships carrying only the
  linker's ad-hoc Mach-O signature and **no `_CodeSignature/CodeResources`** —
  and macOS then reports the app as **"damaged and can't be opened"**, which
  neither right-click → *Open* nor the *Open Anyway* button will bypass.

  **Measured on 0.1.0 and 0.2.0, which both shipped that way.**
  `codesign --verify` failed with *"code has no resources but signature
  indicates they must be present"*, and `syspolicy_check distribution` graded it
  a **Fatal** codesign error. Ad-hoc signing clears exactly that error; the only
  Fatal left is the missing notarization ticket, which is the ordinary state of
  an unnotarized app and is what the README's instructions address. JSON takes
  no comments, so this is the only place the reason is written down.

  **The two states are told apart by the message, and both were measured on
  macOS 26.** Unsigned bundle → *"…is damaged and can't be opened. You should
  move it to the Trash."*, which no click-through clears. Ad-hoc signed bundle →
  *"Apple could not verify 'Quota Board.app' is free of malware…"*, which both
  `xattr` and *Open Anyway* clear. A bug report quoting the first sentence is
  reporting a build problem; one quoting the second is reporting the documented
  install step.
- **`spctl -a` cannot tell those two apart** — it answers `rejected` for both.
  Use `syspolicy_check distribution <app>`, which grades each finding, and read
  it against a known-good bundle rather than alone
- **Right-click → *Open* is no longer a bypass on macOS 15 and later.** Apple
  removed it; the flow is now blocked launch → System Settings → *Privacy &
  Security* → *Open Anyway*. `xattr -dr com.apple.quarantine` still works and is
  the instruction to lead with

## 16. Non-goals

- Claude.ai web subscription limits; Anthropic Console (API credit/billing)
  usage
- Installing and logging into Claude Code on remote machines
- Automatic re-login on token expiry
- Usage history graphs, notifications, threshold alerts
- Showing "which machine is using this account" — meaningless, since limits are
  per-account
- Entering settings from the tray menu
- macOS AppleScript autostart mode (§11.3)

### 16.1 Non-goals as a terms-of-service position

This project does **not** do the following. This list is its terms-of-service
position.

- No inference relaying of any kind
- No central or remote server
- No credential sharing between users
- No reading or writing of another tool's credentials
- No spoofing of User-Agent or headers
- No attempts to circumvent rate limits

And the following is stated in the README: read-only usage polling is an area
Anthropic's published terms do not address. There is room to read Consumer
Terms §3(7) as covering it textually. Observed enforcement has been credential
scoping and billing reclassification, not account suspension. Using this tool
is a choice made in awareness of that uncertainty.
