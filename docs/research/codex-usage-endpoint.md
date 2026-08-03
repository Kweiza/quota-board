# Spike F — measuring the Codex usage endpoint

Run date: 2026-08-03
User-Agent: `quota-board/0.2.1-spike`
Script: `scripts/spike-codex-usage.sh`
Accounts: two ChatGPT accounts on one machine — one on the `free` plan, one on
`plus`. Identifiers are not reproduced.

Spikes A–E (`usage-endpoint.md`) measured the Anthropic side. This one asks
whether the same product can show Codex usage beside it.

## Verdict

**GO, qualified.**

`GET https://chatgpt.com/backend-api/wham/usage` returns Codex usage limits to
an honest `quota-board/<version>` User-Agent, with no header that identifies
Codex CLI and no Cloudflare challenge. §2.2's premise — a free query endpoint
exists — holds for Codex.

The qualification is that **no window with usage in it was ever observed.** Both
accounts read 0% throughout, so the shape a populated window takes, and what
`reset_after_seconds` does once a window is in use, are not measured. §5.5's
schema tolerance and the never-demote-to-0% rule carry the design across that
gap, but the gap is real and is not closed by this run.

## The endpoint

```
GET https://chatgpt.com/backend-api/wham/usage
Authorization: Bearer <access_token for the account>
User-Agent: quota-board/<version>
Accept: application/json
```

Nothing else is required. Measured:

| Header | Effect |
|---|---|
| `Authorization: Bearer` | required |
| `User-Agent: quota-board/…` | **accepted**. 200 on the first attempt |
| `ChatGPT-Account-Id: <id>` | **not required** — 200 with and without it |
| `originator: codex_cli_rs` | never sent; not needed |

**The §5.2 problem does not arise here.** On the Anthropic side an honest
User-Agent costs the generous throttle bucket, and that price is paid
deliberately. Here it costs nothing measurable: the honest request is served.
The script carries impersonating control variants behind
`CODEX_SPIKE_IMPERSONATE=1` for the case where an honest request is refused;
they were never run, because it never was.

## Path selection, and what the 403s mean

Four paths were probed. Three families appear in the codex binary as siblings —
`/api/codex/X` and `/wham/X` exist as a pair for both `usage` and
`rate-limit-reset-credits`.

| URL | Status | Answered by |
|---|---|---|
| `…/backend-api/wham/usage` | **200** | backend (`x-oai-request-id`) |
| `…/backend-api/wham/usage?client_version=…` | **200** | backend |
| `…/backend-api/codex/usage` | 403 | edge (HTML, `server-timing: chlray`) |
| `…/backend-api/api/codex/usage` | 403 | edge (HTML, `server-timing: chlray`) |
| `…/backend-api/codex/models` | 400 | backend (`x-oai-request-id`) |

**The status code does not say who refused; the headers do.** A Cloudflare
challenge carries an HTML body and `server-timing: chlray` and no
`x-oai-request-id`. A backend answer carries `x-oai-request-id` and
`x-openai-proxy-wasm` whatever its status.

The `/codex/models` control is what settles it. It is a path this machine's CLI
is observed to call successfully, and it answered:

```json
{"error": {"message": "[{'type': 'missing', 'loc': ('query', 'client_version'),
 'msg': 'Field required', 'input': None}]", "type": "invalid_request_error"}}
```

A JSON 400 from the backend, over an honest User-Agent. So the `/codex/*` family
is **not** blocked at the edge for this client, and the 403s above are about
those two specific routes rather than about who is asking. Any conclusion of the
form "OpenAI blocks non-CLI clients" is contradicted by this row.

`client_version` is a required query parameter on `/codex/models`. **`wham/usage`
ignores it**: probed with and without in the same run, both returned 200, and
the two bodies are identical apart from `reset_at` advancing with the clock. The
parameter belongs to the `/codex/*` family rather than to this endpoint, and a
client reading usage does not need to send it — which also means it cannot be
used to make the two 403s above behave differently.

## Response schema

Twelve top-level keys, identical on both plans:

```
account_id  additional_rate_limits  code_review_rate_limit  credits
email       plan_type               promo                   rate_limit
rate_limit_reached_type  rate_limit_reset_credits  spend_control  user_id
```

`email`, `user_id`, and `account_id` are in the body. On the account measured,
`account_id` and `user_id` were the same `user-…` string — a personal account
with no workspace. **This body carries identifiers, so raw captures belong in
`.local/`, never in this repository.**

### `rate_limit`

```json
{ "allowed": true, "limit_reached": false,
  "primary_window": { "used_percent": 0, "limit_window_seconds": 604800,
                      "reset_after_seconds": 604800, "reset_at": 1786343558 },
  "secondary_window": null }
```

`limit_window_seconds` is plan-dependent: **2592000 (30 days) on `free`,
604800 (7 days) on `plus`.**

`reset_at` is **Unix epoch seconds**, not the ISO-8601 string
`/api/oauth/usage` sends. §5.4's normalisation table needs a row for it. While a
window is closed the server reports `reset_at` as `now + reset_after_seconds`,
so it advances one second per second of wall clock — a comparison that includes
it will always report movement.

`secondary_window`, `additional_rate_limits`, and `code_review_rate_limit` were
`null` on both accounts. **Their populated shape is unmeasured.** The ChatGPT
usage page shows no 5-hour window for this plan either, so the two-window
5h + weekly shape assumed before this run may simply not exist here.

### `rate_limit_reset_credits`

```json
{ "available_count": 1, "applicable_available_count": 0 }   // plus
{ "available_count": 0, "applicable_available_count": 0 }   // free
```

Present in the usage response itself, so the widget's reset-credit line needs
**no second request**. The sibling path `…/rate-limit-reset-credits/consume`
spends a credit and is never called by the script.

### `credits` and `spend_control`

```json
"credits": { "has_credits": false, "unlimited": false,
             "overage_limit_reached": false, "balance": "0",
             "approx_local_messages": [0, 0], "approx_cloud_messages": [0, 0] },
"spend_control": { "reached": false, "individual_limit": null }
```

Two parsing traps: `balance` is a **string**, not a number, and
`approx_*_messages` are **two-element arrays**, not scalars. On the `free`
account `balance` and both arrays were `null` instead.

## Cross-check against the official page

The decisive check, and it cost no quota. `https://chatgpt.com/codex/settings/usage`
was read in a browser on the same `plus` account within minutes of the API read:

| | Web page | `wham/usage` |
|---|---|---|
| Weekly limit | 100% remaining (= 0% used) | `used_percent: 0` |
| 5-hour window | not shown at all | `secondary_window: null` |
| Credits remaining | 0 | `credits.balance: "0"` |

The page also reports "Codex and Work share the same usage limit", and its
breakdown recorded **1 turn** against model `gpt-5.5` — the deliberate turn run
for this spike.

**This is what identifies `wham/usage` as the Codex source.** The two agree
field for field, including on the absence of a 5-hour window.

## Does reading cost anything?

No movement was observed, but the run cannot carry the weight that sounds like.

- 12 consecutive reads changed no field.
- One real Codex turn (2,911 tokens) changed no field either. It was read back
  three times, spanning roughly 25 minutes after the turn; `used_percent` and
  `reset_after_seconds` were identical in all three.

The second row is the important one: **the endpoint did not move for a real
turn**, and the official page agreed, recording the turn while still showing 0%
used. So `used_percent`'s resolution is coarser than one turn, and the
consumption test's "nothing moved" is consistent with reads being free *and*
with the instrument being too blunt to detect anything at this scale.

An earlier reading of this run inferred a mechanism — that a closed window
reports `reset_after_seconds` pinned at `limit_window_seconds` and that the
first billed request would anchor it. **That is a hypothesis, not a
measurement.** Nothing here established how the field behaves once a window is
in use.

What can be said: a `GET` with no request body, on an endpoint whose numbers
match the account's own usage page, did not alter those numbers across 12 reads.
That is the same shape of evidence Spike A rests on, and it is weaker here
because the baseline was zero.

## OAuth endpoints

Discovery at `https://auth.openai.com/.well-known/openid-configuration`
(unauthenticated):

| Purpose | URL |
|---|---|
| authorize | `https://auth.openai.com/api/accounts/authorize` |
| token | `https://auth.openai.com/api/accounts/oauth/token` |
| revoke | `https://auth.openai.com/api/accounts/oauth/revoke` |

`code_challenge_methods_supported: ["S256"]`. Scopes advertised: `openid`,
`profile`, `email`, `offline_access`.

**The CLI does not use the token endpoint its own issuer advertises.** Its
request log records `https://auth.openai.com/oauth/token`, and
`https://auth.openai.com/deviceauth/callback` for device login. Both are
recorded here because a design that picks one on the strength of discovery alone
would be picking the one nothing has been observed to use.

The codex binary carries the public client `app_EMoamEEZ73f0CkXaXp7hrann`.
**Not verified**: no authorization flow was run against it in this spike.

Note for §10.4's counterpart: the advertised scope list contains nothing
resembling `user:inference`, so there is no inference scope to decline. That is
not evidence the resulting token cannot run inference — access here is likely
account-based rather than scope-gated. Establishing otherwise would mean sending
an inference request, which this project forbids, so it stays unmeasured and is
stated that way.

## Measurement errors made and corrected

Recorded because three of them produced a confident wrong answer that survived
until something contradicted it, and the same shapes will recur.

1. **A test that could not fail.** The first response reader looked for
   `rate_limits` and `rate_limits_by_limit_id` — struct names read out of the
   binary. The endpoint answers with a singular `rate_limit` holding
   `primary_window`. The reader matched nothing and returned `[]`, and the
   consumption test then compared `[]` against `[]` and printed **GO**. The
   fix is not a better guess at the shape: a reader that finds nothing now says
   so loudly and marks every step below it vacuous.
2. **A URL nothing serves, read as an absence.** `/api/codex/usage` was built by
   pasting a bare binary string onto the base URL. Its 403 was briefly read as
   "Codex exposes no usage endpoint." The CLI's own request log shows the real
   family is `/backend-api/codex/…` with no `api` segment.
3. **A backend answer read as a block.** The control probe was graded with
   `= 200`, so its 400 printed "the family refuses this client" — the opposite
   of what a JSON body naming a missing query parameter shows. Grading now keys
   on `x-oai-request-id`, which says *who answered* rather than how well.
4. **Research data destroyed by a line break.** The `CODEX_SPIKE_DIR` override
   was typed on its own line, which sets a shell variable without exporting it,
   so the paid run silently wrote over the free-plan run's raw bodies. They are
   not recoverable; the `free` figures in this document were transcribed before
   the overwrite. The script now refuses to write into a directory that already
   holds a run.

---

# Spike G — the 429 boundary, not found

Run date: 2026-08-03
User-Agent: `quota-board/0.2.1-spike`
Script: `scripts/spike-codex-throttle.sh`
Account: one, `plus`, with no usage in flight.
Raw log: `.local/research/codex-throttle-log.tsv`, not committed.

Method mirrors `spike-throttle.sh` so the two are comparable: 90 iterations at
60-second intervals against `wham/usage`, one account, honest User-Agent.
Measured inter-request intervals were 59 s once, 60 s forty times and 61 s
forty-eight times — the loop's `sleep 60` plus round-trip time, the same drift
Spike B saw.

## Result

| | |
|---|---|
| HTTP 200 | **90 of 90** |
| HTTP 429 | **0** |
| Answered by the backend (`x-oai-request-id`) | 90 of 90 |
| `Retry-After` seen | never |
| Elapsed | 89 minutes |

**No throttle boundary was found.** Spike B drove Anthropic's endpoint the same
way and saw 26 consecutive successes before the first 429, then a sustained
alternating rhythm. This run found nothing to alternate with.

## What that does and does not establish

**Measured:** one account polled every 60 seconds for 89 minutes is not
throttled, and every response came from the API rather than from the edge.

**Not measured, and the list matters more than the result:**

- **Any interval below 60 seconds.** No boundary was located, so the shortest
  safe interval is unknown — 60 s is a point known to be safe, not a floor
  derived from a measured limit. Spike B's 180 s came from halving a measured
  120 s floor and adding margin; there is no equivalent arithmetic to do here,
  because nothing failed.
- **More than one account.** Spike D established that Anthropic's 429 budget is
  per account. Nothing here tests whether that holds for OpenAI, so the request
  rate of N accounts polling at this interval is unbounded by this measurement.
- **Anything past 89 minutes.** A daily or weekly request cap would not appear
  in this window.
- **Whether a 429 exists on this endpoint at all**, and therefore whether
  `Retry-After` is ever sent or what it would carry. "Never seen" here is the
  absence of an event, not a property of the server — the same shape of claim
  Spike B made about `Retry-After: 0` and Spike D refuted.

## The consumption question, at 90 reads

`used_percent` held at 0 and `reset_after_seconds` at 604800 across all 90
requests. That is a far larger sample than Spike F's twelve, and it is still
the same weak direction of evidence: the account had no usage in flight, so 0
is a floor the value cannot fall below. It remains consistent with reads being
free and with the instrument being too blunt at this scale.

## Scope limits

- **Two accounts, one machine, one day, and neither had usage in flight.**
  Every schema statement above describes a zero-usage account.
- **`secondary_window`, `additional_rate_limits`, and `code_review_rate_limit`
  are unmeasured.** They were `null` in every capture. A run in which a field
  stays null measures nothing about that field.
- **No throttle boundary was measured.** Spike B and D did that work for
  Anthropic; nothing equivalent exists here. The 429 behaviour of this endpoint,
  whether it sends `Retry-After`, and whether its budget is per account or per
  IP are all unknown. A poll interval for Codex accounts cannot be derived from
  this document.
- **No OAuth flow was run.** The endpoints and client_id above come from
  discovery and from the binary; nothing here confirms an authorization request
  against them succeeds, or what the consent screen displays.
- **The read-cost question is answered only in the weak direction.** Reads did
  not move the numbers, at a scale where one real turn did not move them either.
