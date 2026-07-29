# Spike A — measuring /api/oauth/usage

Run date: 2026-07-29
User-Agent: `quoata-board/0.1.0-spike`

## Verdict

**GO**

The request to `https://api.anthropic.com/api/oauth/usage` was made with an honest User-Agent (`quoata-board/0.1.0-spike`, not impersonating Claude Code) and returned HTTP 200 on the first attempt. The architecture's central premise — that the usage endpoint can be read without impersonating Claude Code — holds.

## HTTP status

`200` (response time 0.38s)

Response headers worth noting:

- `content-type: application/json`
- `anthropic-organization-id: <masked>`
- `server: cloudflare`
- `content-security-policy: default-src 'none'; frame-ancestors 'none'`

## Top-level key set

```
amber_ladder
cinder_cove
extra_usage
five_hour
iguana_necktie
limits
member_dashboard_available
nimbus_quill
omelette_promotional
seven_day
seven_day_cowork
seven_day_oauth_apps
seven_day_omelette
seven_day_opus
seven_day_sonnet
spend
tangelo
```

## seven_day

`null`. On this account, `seven_day`, `seven_day_oauth_apps`, `seven_day_opus`, `seven_day_sonnet`, `seven_day_cowork`, and `seven_day_omelette` were all `null`. Weekly data was instead expressed as a `weekly_scoped` entry (`group: "weekly"`) inside `limits[]`.

## limits[]

`limits[]` **does** contain a `weekly_scoped` entry. The `scope.model.display_name` value was `"Fable"`.

The full observed `limits[]`:

```json
[
  {
    "kind": "session",
    "group": "session",
    "percent": 7,
    "severity": "normal",
    "resets_at": "2026-07-29T09:09:59.795962+00:00",
    "scope": null,
    "is_active": false
  },
  {
    "kind": "weekly_scoped",
    "group": "weekly",
    "percent": 39,
    "severity": "normal",
    "resets_at": "2026-08-01T10:00:00.796179+00:00",
    "scope": {
      "model": { "id": null, "display_name": "Fable" },
      "surface": null
    },
    "is_active": true
  }
]
```

## Full response body (identifiers masked)

The response body itself contained no email address, organization UUID, or account UUID. (The organization UUID appeared only in the `anthropic-organization-id` response header, masked above.) No token was included or recorded anywhere.

```json
{
  "five_hour": {
    "utilization": 7.0,
    "resets_at": "2026-07-29T09:09:59.795962+00:00",
    "limit_dollars": null,
    "used_dollars": null,
    "remaining_dollars": null
  },
  "seven_day": null,
  "seven_day_oauth_apps": null,
  "seven_day_opus": null,
  "seven_day_sonnet": null,
  "seven_day_cowork": null,
  "seven_day_omelette": null,
  "tangelo": null,
  "iguana_necktie": null,
  "omelette_promotional": null,
  "nimbus_quill": null,
  "cinder_cove": null,
  "amber_ladder": null,
  "extra_usage": {
    "is_enabled": false,
    "monthly_limit": null,
    "used_credits": null,
    "utilization": null,
    "currency": null,
    "decimal_places": null,
    "disabled_reason": null,
    "user_disabled": false,
    "spend_limit_reached": false,
    "credits_ever_enabled": false,
    "daily": null,
    "weekly": null
  },
  "limits": [
    {
      "kind": "session",
      "group": "session",
      "percent": 7,
      "severity": "normal",
      "resets_at": "2026-07-29T09:09:59.795962+00:00",
      "scope": null,
      "is_active": false
    },
    {
      "kind": "weekly_scoped",
      "group": "weekly",
      "percent": 39,
      "severity": "normal",
      "resets_at": "2026-08-01T10:00:00.796179+00:00",
      "scope": {
        "model": { "id": null, "display_name": "Fable" },
        "surface": null
      },
      "is_active": true
    }
  ],
  "spend": {
    "used": { "amount_minor": 0, "currency": "USD", "exponent": 2 },
    "limit": null,
    "percent": 0,
    "severity": "normal",
    "enabled": false,
    "disabled_reason": null,
    "cap": null,
    "balance": null,
    "auto_reload": null,
    "disclaimer": "Usage credits cover you when you hit your plan limits. [Learn more](https://support.claude.com/articles/12429409)",
    "can_purchase_credits": false,
    "can_toggle": false
  },
  "member_dashboard_available": false
}
```

## Surprising observations

- Of the top-level keys, `amber_ladder`, `cinder_cove`, `iguana_necktie`, `nimbus_quill`, `omelette_promotional`, `seven_day_cowork`, `seven_day_omelette`, and `tangelo` were all `null` on this account. The irregular naming suggests server-side codenames for A/B tests or internal experiments. They are inactive on this account tier and may carry values on other plans or accounts. Parser fixtures should treat these fields as "present but usually null."
- Contrary to expectation, weekly (7-day) usage was expressed not through `seven_day` but as a `kind: "weekly_scoped"` entry inside `limits[]`. The UI must iterate `limits[]` and branch on `group`/`kind` rather than reading the top-level `seven_day` field.
- `limits[].scope.model.display_name` carried the value `"Fable"`. This is a real public model name (Claude Fable 5), not an internal codename — no display-name mapping table is needed; use `display_name` directly as the label.
- `spend` and `extra_usage` blocks sit alongside the limit data at the top level, so credit and billing information arrives from the same endpoint as pure limit information. This account has `enabled: false`, so the first UI version can ignore them, but other accounts (on credit-enabled plans) may carry values.
- The response headers included `anthropic-organization-id` — usable for account identification, so it is masked in this document.
- No retry or header adjustment was needed to authenticate; the very first request returned 200.

## Implications for the parser fixtures

- Use the 17-key top-level set above verbatim as a fixed fixture. The `seven_day*` family was entirely `null` on this account — fixtures need both an "all null" case and a "populated" case (the latter requires re-measurement on a different account or plan).
- Fixture `limits[]` as an array with at least two elements (`session`, `weekly_scoped`). The nested `scope.model` object structure must be reproduced exactly. `scope.model.id` may be `null` — treat only `display_name` as reliable.
- Each `limits[]` element carries `kind`, `group`, `percent`, `severity`, `resets_at`, `scope`, and `is_active` — more fields than the `{kind, group, percent, resets_at, scope}` the original script summarized (`severity` and `is_active` are additional). The UI can use `is_active` to highlight the limit currently affecting the user.
- `resets_at` was an ISO 8601 string including a timezone offset (`+00:00`) — fixtures and the parser should treat that format as canonical.
- `extra_usage`, `spend`, and `member_dashboard_available` must also be included in fixtures (all inactive or zero on the current account).

---

## Throttle boundary (Spike B)

Measurement conditions: 1 account, `scripts/spike-throttle.sh` targeting 90 iterations at 60-second intervals (about 90 minutes), User-Agent `quoata-board/0.1.0-spike`. The raw log lives at `.local/research/throttle-log.tsv` and is not committed.

### Summary

- Status code distribution: 56 × `200`, 34 × `429` (90 rows total)
- `ERR_TOKEN` / `ERR_TMPFILE` sentinels: **0**. The failure modes the script guards against (token extraction failure, temp file creation failure) never occurred during this run; all 90 rows are valid samples with a real HTTP response.
- Consecutive successes before the first 429: **26** (seq 1–26 all `200`, first `429` at seq 27)

### Shape after saturation (one character per iteration, in groups of ten)

```text
..........  [10]
..........  [20]
......XXXX  [30]
XX.X.X.X.X  [40]
.X.X.X.X..  [50]
X.X.X.X.X.  [60]
X.X.X.X.X.  [70]
X.X.X.X.X.  [80]
X.X.X.X.X.  [90]
```

(`.` = 200, `X` = 429, seq ascending)

From seq 27 through 32 there are **six consecutive 429s** (the initial burst being exhausted), after which, from seq 33 onward, `200` and `429` settle into a nearly perfect **alternating** rhythm. So this endpoint does not recover "gradually" or "all at once in a burst" — it recovers **at a steady rhythm**. Exactly which mechanism produces that rhythm cannot be determined from this visualization alone; both models discussed under "Deriving the sustainable request rate" below explain it equally well.

The single exception is seq 49–50, the only place where two `200`s occur back to back (the alternating rhythm's phase slips by one). This exception admits two readings: (a) it is merely timing jitter, because the refill/reset instant does not line up exactly with our 60-second polling period — evidence that the alternating pattern itself is intact; or (b) it is evidence that the refill is not on a perfectly fixed period, and a slot can occasionally open earlier than expected. A single log cannot settle which, so both readings are recorded.

### Deriving the sustainable request rate

Taking every interval (epoch difference) between successful (`200`) requests after seq 33 (i.e. after entering saturation):

- 28 of the 29 intervals are **120 or 121 seconds** (14 × 120s, 14 × 121s — given that the real loop period was 60–61 seconds due to the 60-second sleep plus curl round-trip time, this is effectively "exactly twice the period")
- 1 exception: **61 seconds** between seq 49 and 50 (the same phase slip seen in the visualization above)
- Mean interval excluding the exception: (14 × 120 + 14 × 121) / 28 = **120.5 seconds**

This data fits at least two different models. This log alone cannot determine which is correct.

1. **Continuous token bucket refill**: each account accrues roughly one success slot every 120 seconds. Because we polled at 60-second intervals, every second request caught exactly one success slot.
2. **Hourly (on-the-hour reset) quota**: a fixed number per hour (around 30) is allowed, replenished at the top of the hour.

The log does contain a clue that bears on this. The wall-clock time of the seq 32→33 transition — where the 429 burst ends and the alternating rhythm begins — is seq32 = 04:59:56 UTC and seq33 = 05:00:56 UTC. The transition point therefore **coincides almost exactly with the hour boundary (05:00 UTC)**, about 31–32 minutes into the measurement. That is too clean to be coincidence and supports the hourly-quota model.

However, this run ended at 05:58:11 UTC (about 89 minutes in) and **never crossed the next hour boundary (06:00 UTC).** So this log observed the alternating rhythm within a single hourly window only, and observed nothing about whether the rhythm continues across the hour boundary (token bucket) or resets and produces another run of consecutive successes (hourly quota). **The one observation that could actually separate the two models — a run spanning two or more hour boundaries — is absent from this measurement.**

**Conclusion (model-independent): the observed sustainable request rate for this single account is roughly one request per 120 seconds (≈29.9/hour, 30 rounded), and this value holds identically under either model.**

This figure matches almost exactly the "28–30 per hour" estimate carried in the design document (marked low-to-moderate confidence). But this measurement covers one account and one run and did not cross two hour boundaries, so it does not separate the two models — it is too early to raise confidence to high. **Keep the number (28–30/hour) and set confidence to moderate.** Rationale: the value itself is confirmed by measurement, but the mechanism producing it is undetermined and the sample is a single run.

### Observed Retry-After values

- Values observed: **`0` only** (all 34 of the 429s)
- Any value greater than 0: **no**, not once
- Meaning: on this endpoint the `Retry-After` header gives no usable wait-time hint at all. A client cannot use it for backoff computation and must rely on its own fixed-interval policy.

### Values for the poll policy

- Safe sustained interval per account: **180 seconds**
- Rationale: the measured floor (the minimum success interval observed under saturation) is 120 seconds, plus a **50% margin** (120 × 1.5 = 180). Timing jitter exists — the real loop period wandered between 60 and 61 seconds — so polling exactly at the theoretical floor would drift back into the 429 boundary on jitter alone.
- **Safe under both models:** regardless of which of the two models above is correct, 180 seconds is safe. Under a token bucket it is the measured 120-second floor plus a 50% margin; under an hourly quota (about 30/hour) the mean permitted interval is likewise about 120 seconds (3600/30), so the same margin applies. This recommendation does not depend on the model uncertainty left unresolved above.

### Implications for the design (including contradictions)

- **The design document's "28–30 per hour" figure matches this measurement.** But it is too early to raise confidence to high — for the reasons under "Scope limits" below (one account, one run, model undetermined), confidence stays at moderate. Whether the mechanism is a token bucket or an hourly quota is undetermined.
- **The cause (mechanism) of the recovery shape is undetermined.** The alternating rhythm beginning at seq 33 is explained equally well by continuous token-bucket refill and by an hourly quota resetting on the hour — this measurement never crossed an hour boundary and so cannot distinguish them. If a later task needs that distinction (for example, logic that depends on the reset instant, such as resuming polling in anticipation of the top of the hour), a re-measurement spanning two or more hour boundaries is required.
- **The 60-second interval that the measurement script itself used as a default is directly refuted as unsustainable by this measurement.** Polling at 60-second intervals starts producing 429s after 26 iterations (about 26 minutes), after which half of all requests are always 429. The implicit assumption that "60 seconds should be safe" must be discarded — the poll policy default must be the measured floor (120s) plus a margin (180s), and that value is safe under either model.
- **The initial 26 consecutive successes are not the steady-state sustainable rate**; they appear to be the draining of an initial allowance already accumulated in the bucket or quota. Steady state is only observed from seq 33 onward. The design should anticipate the user-visible behavior that "polling works rapidly right after launch, then suddenly starts mixing in 429s about half the time."
- **The fact that `Retry-After` is always 0 explicitly rules out a design that follows the server's stated value.** The client must rely on its own fixed backoff with no server hint.

### Scope limits

- **One account, one process only.** This measurement used a single account in a single process. Whether this throttle is independent per account, or a shared budget per IP/process/application, when several accounts are polled concurrently from one process is **entirely unknown from this measurement.** It remains an open question for a separate task.
- **Aliasing cannot be ruled out, because the polling period and the derived period stand in an exact 2:1 relationship.** This measurement polled at 60-second intervals, and the period derived above is exactly twice that, 120 seconds. A near-perfect 200/429 alternation is also the classic aliasing pattern produced by exactly such an integer relationship — measuring at a different interval (40 or 90 seconds, say) might have produced a different apparent pattern (one failure in three, or a more complex rhythm). The true minimum period should therefore be read as **bounded** near that value rather than pinned to exactly 120 seconds. The 61-second interval at seq 49–50 (see "Shape after saturation") can be read alongside this as weak evidence in the same direction — that the bound may not be perfectly fixed.

---

# Spike C — refresh behaviour and per-account window sets

Run date: 2026-07-30
User-Agent: `quoata-board/0.1.0`
Accounts: three, referred to below as A, B and C. Identifiers are not reproduced.

## Method

Three accounts were signed in through this project's own OAuth (authorization_code +
PKCE, loopback redirect, Claude Code's public client_id). The machine is headless, so the
consent redirects were received over an SSH tunnel to the loopback listener.

For the refresh measurements, `quoata-cli refresh` was temporarily instrumented to print a
truncated, non-reversible SHA-256 of each credential before and after the call, alongside
the stored expiry timestamps. The instrument was reverted before commit; no credential was
ever printed, only a hash prefix.

## Refresh rotates both tokens

Two forced refreshes of account A, 36 seconds apart. On **both** calls the refresh-token
fingerprint and the access-token fingerprint changed. The server rotates both credentials
on every refresh.

This matters beyond bookkeeping: §10.5 and the `auth::stored` compare-and-swap are written
around a "single-use rotating chain" premise, and until this run that premise was an
assumption with nothing measuring it. The rotating half is now measured. The single-use
half — whether the superseded refresh token is actually rejected — is **not** measured
here, because the CLI keeps no copy of a rotated-away token.

## Access-token lifetime: 8 hours

`expires_in` was 28,799 s on both calls — eight hours less one second. §10.5's
five-minute skew is therefore about 1% of the lifetime, which is comfortable.

Note for anyone reading older internal notes: a figure of 7.6 hours appears in earlier
private working material. The measured value is 8 hours.

## The refresh chain's expiry is absolute, and refreshing does not extend it

Across all three samples the stored `refresh_token_expires_at` resolved to the same
absolute instant, drifting only by the sub-second gap between the two calls:

```
before refresh #1   2026-08-26 08:03:28.027
after  refresh #1   2026-08-26 08:03:28.304
after  refresh #2   2026-08-26 08:03:28.450
```

The client computes this field as `now + refresh_token_expires_in` whenever the server
sends it, and preserves the previous value byte-for-byte when it does not. The sub-second
drift proves the server **did** send it, and the stable absolute result proves the value is
*remaining seconds to a fixed deadline* rather than a fresh duration.

**Consequence: a refresh chain cannot be kept alive indefinitely by refreshing it.** It
expires at a fixed instant roughly a month after the grant, and the user must sign in
again. A widget left running will reach `AUTH_DEAD` on that date with no warning unless
the UI anticipates it. What the deadline is anchored to is undetermined — it is not
exactly 28 days after our grant.

## Window sets differ per account, and an absent window is not zero

Queried within one minute of each other:

| Account | `5h` | `7d` | `weekly (Fable)` |
|---|---|---|---|
| A | absent | 100.0% | 75.0% |
| B | 26.0% | absent | 59.0% |
| C | 0.0% | 96.0% | 100.0% |

Three accounts, three different shapes; no account returned every window. This is §12.1's
risk observed directly, and it is why the renderer must handle a variable bar count rather
than assume a fixed pair.

**C's `5h 0.0%` is not a true zero.** A deliberate one-token prompt was run on C shortly
before the query, so the value is a small non-zero utilisation rounded to one decimal. It
is therefore consistent with — not evidence against — the reading that windows with no
usage are omitted entirely.

**Why an absent window must still degrade to "unknown" rather than 0%.** B reports `5h` at
26% but no `7d` at all. Five-hour usage is a subset of seven-day usage, so B's missing
`7d` cannot be an omitted zero; something other than "no usage" removes it. A is the
opposite case, and looks like an omitted zero. The same absence therefore carries two
different meanings, and the response gives no way to tell them apart. Rendering either as
"0% used" would state a fact the data does not support — for B, it would claim a
seven-day limit that may not exist.

Three candidate explanations for B's missing `7d` were considered and **none is
established**: the account's plan may not carry that limit; the window may be omitted for
zero usage; or the account was created and subscribed the same day and has no seven-day
history. The third is weakened by B carrying a `weekly (Fable)` window, which is also
week-scoped. Re-measuring B after several days would separate them.

## Chain binding is per grant (resolves §10.7)

Not measured by an experiment run here, but by long-standing everyday use: one account
signed in to Claude Code on several machines holds one grant per machine under the same
`(account, client_id)` pair, and those machines run in parallel for days with neither
being asked to re-authenticate. Access tokens last eight hours, so every machine has
refreshed successfully many times after the others obtained their grants — impossible
under a per-`(account, client_id)` binding.

## Scope limits

- **Three accounts, one machine, one run.** The window-set observations are three samples
  taken within a minute; nothing here establishes how window sets vary over time.
- **The per-grant binding evidence is observational, not a controlled experiment.** No run
  drove one of this project's grants and a Claude Code grant against each other directly;
  doing so requires deliberately risking a working session. One class of grant was
  observed against itself, at scale and over days, which is the strongest evidence
  available short of that.
- **The single-use half of the rotation premise is untested.** Rotation is measured;
  rejection of a superseded token is not.
- **The refresh-expiry anchor is undetermined.** It is fixed and is not extended by
  refreshing, but what instant it is measured from was not established.
