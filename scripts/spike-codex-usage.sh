#!/usr/bin/env bash
# Spike F — measuring the Codex usage endpoint before any Codex support exists.
# (A–E are in docs/research/usage-endpoint.md and cover the Anthropic side.)
#
# docs/design.md §2.2 makes "a free query endpoint exists" the premise the whole
# architecture rests on. Nothing establishes that premise for Codex yet, so this
# script measures it. Its output decides whether a Codex provider is written at
# all; see the GO/NO-GO summary it prints last.
#
# Manual research script only. The application never reads ~/.codex/auth.json;
# only this script does, and only when a human runs it. That is the same
# exemption AGENTS.md grants scripts/ for ~/.claude/.credentials.json, and it
# does not widen: nothing here writes the file, and no application code may copy
# this access.
#
# This script only ever issues GET requests against usage/limit endpoints. It
# never calls an inference endpoint, and it never calls
# /rate-limit-reset-credits/consume — that one spends a reset credit, which is a
# real, non-refundable resource on the user's account.
set -euo pipefail

# --- knobs -------------------------------------------------------------------

AUTH="${CODEX_AUTH:-$HOME/.codex/auth.json}"
BASE="${CODEX_BASE:-https://chatgpt.com/backend-api}"
# How many extra reads the consumption test issues between its two samples.
# Small on purpose: if reads turn out *not* to be free, this is the quota it
# costs to discover that.
READS="${CODEX_SPIKE_READS:-10}"
OUT="${CODEX_SPIKE_DIR:-.local/research/codex-spike}"

# Derived rather than hardcoded: commit 38c03ac made Cargo.toml the only place
# the version is written, and a spike that reports a stale version in its
# User-Agent would put a wrong number into the research record. Falls back to a
# literal when the script is run from outside the repo.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT:-.}/Cargo.toml" 2>/dev/null | head -1)
UA="quota-board/${VERSION:-unknown}-spike"

# --- preconditions -----------------------------------------------------------

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

if [ ! -f "$AUTH" ]; then
  echo "credential file not found: $AUTH" >&2
  echo "Run 'codex login' on this machine first." >&2
  exit 1
fi

MODE=$(jq -r '.auth_mode // empty' "$AUTH")
if [ "$MODE" != "chatgpt" ]; then
  # An API-key install has no subscription rate limits to report, so every
  # measurement below would describe a different product than the one we are
  # deciding about.
  echo "auth_mode is '${MODE:-<absent>}', not 'chatgpt'." >&2
  echo "This spike measures ChatGPT-subscription rate limits and does not apply." >&2
  exit 1
fi

# stderr is suppressed on every jq call that touches this file: jq echoes input
# fragments on failure, and those fragments can carry the token. The token value
# is never printed, logged, or written to the output directory.
TOKEN=$(jq -r '.tokens.access_token // empty' "$AUTH" 2>/dev/null || true)
ACCOUNT=$(jq -r '.tokens.account_id // empty' "$AUTH" 2>/dev/null || true)
if [ -z "$TOKEN" ]; then
  echo "could not find .tokens.access_token. Key structure of the file:" >&2
  jq -r 'paths(scalars) | join(".")' "$AUTH" 2>/dev/null >&2 || true
  exit 1
fi

# Refuse to write into a directory that already holds a run. On 2026-08-03 the
# paid-plan run landed on top of the free-plan run and destroyed it: the
# override was typed as a `VAR=value` line of its own, which sets a shell
# variable but does not export it, so this script never saw it and silently used
# the default path. A measurement that cost a real request must not be
# overwritable by a line break.
if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  if [ "${CODEX_SPIKE_FORCE:-0}" != "1" ]; then
    echo "output directory already holds a run: $OUT" >&2
    echo >&2
    echo "Pass a different one on the SAME line as the command:" >&2
    echo "  CODEX_SPIKE_DIR=.local/research/codex-spike-2 $0" >&2
    echo >&2
    echo "or set CODEX_SPIKE_FORCE=1 to overwrite that run deliberately." >&2
    exit 1
  fi
  echo "overwriting the previous run in $OUT (CODEX_SPIKE_FORCE=1)"
fi
mkdir -p "$OUT"
# Bodies land under .local/ rather than /tmp because they carry account
# identifiers and plan details, and AGENTS.md designates .local/ for raw
# research logs. It is git-ignored, so nothing here can reach the public repo by
# accident.
echo "output directory: $OUT"
echo "User-Agent:       $UA"
echo "account id:       ${ACCOUNT:0:8}… (masked; ${#ACCOUNT} chars)"
echo

# --- helpers -----------------------------------------------------------------

# Measured 2026-08-03 against `wham/usage`. Windows sit under `rate_limit` as
# two named slots, with two optional siblings beside it. There is no
# `rate_limits` array and no `rate_limits_by_limit_id` — which is exactly what
# the first draft of this filter looked for, on the strength of struct names
# read out of the codex binary. It matched nothing, returned [], and the
# consumption test then compared an empty list against an empty list and printed
# a pass. A reader that finds nothing must say so loudly; returning [] makes
# every step after it vacuous while still looking like a measurement.
#
# Two shapes, because two different APIs answer here and only one of them is
# Codex's. The binary's `GetAccountRateLimitsResponse` carries `rate_limits`
# plus `rate_limits_by_limit_id`; `wham/usage` answers with a singular
# `rate_limit` holding `primary_window`/`secondary_window`. An earlier draft
# read only the first pair, met the second, matched nothing, and returned [] —
# after which the consumption test compared [] against [] and printed a pass.
# Both are read here, and the fields are normalised so the steps below never
# have to know which one they got.
JQ_LIMITS='
def windows:
  ( ( if   (.rate_limits? | type) == "array"  then .rate_limits
      elif (.rate_limits? | type) == "object" then (.rate_limits | to_entries | map(.value))
      elif (.rate_limits_by_limit_id? | type) == "object"
                                              then (.rate_limits_by_limit_id | to_entries | map(.value))
      elif (.rate_limits_by_limit_id? | type) == "array"
                                              then .rate_limits_by_limit_id
      else [] end
      | map({name: (.limit_id // .limit_name // "limit"), w: .}) )
    +
    ( [ {name: "primary",     w: (.rate_limit.primary_window?)},
        {name: "secondary",   w: (.rate_limit.secondary_window?)},
        {name: "code_review", w: (.code_review_rate_limit?)} ]
      + ((.additional_rate_limits // []) | to_entries
         | map({name: ("additional[" + (.key|tostring) + "]"), w: .value})) ) )
  | map(select(.w != null))
  | map({ name: .name,
          used: (.w.used_percent // .w.percent),
          win:  (.w.limit_window_seconds
                 // (if (.w.window_minutes? | type) == "number"
                     then .w.window_minutes * 60 else null end)),
          left: (.w.reset_after_seconds // .w.resets_in_seconds),
          raw:  .w });
'

# request <name> <url> <header-set>
# Writes headers and body to $OUT/<name>.{headers,json} and prints one status
# line. Never fails the script: a non-2xx is a measurement, not an error.
request() {
  local name="$1" url="$2" set="$3"
  local -a h=(-H "Authorization: Bearer $TOKEN" -H "Accept: application/json")

  case "$set" in
    honest)
      h+=(-H "User-Agent: $UA" -H "ChatGPT-Account-Id: $ACCOUNT") ;;
    honest-no-account)
      h+=(-H "User-Agent: $UA") ;;
    # The three below assert an identity this application does not have. They
    # are opt-in (see CODEX_SPIKE_IMPERSONATE) and exist only to answer "is the
    # honest request refused *because* it is honest?" — a question that cannot
    # be answered by absence. A GO decision may never rest on these rows.
    originator)
      h+=(-H "User-Agent: $UA" -H "ChatGPT-Account-Id: $ACCOUNT"
          -H "originator: codex_cli_rs") ;;
    codex-ua)
      h+=(-H "User-Agent: codex_cli_rs/0.146.0" -H "ChatGPT-Account-Id: $ACCOUNT") ;;
    codex-full)
      h+=(-H "User-Agent: codex_cli_rs/0.146.0" -H "ChatGPT-Account-Id: $ACCOUNT"
          -H "originator: codex_cli_rs") ;;
    *) echo "unknown header set: $set" >&2; return 1 ;;
  esac

  local code
  code=$(curl -sS -X GET "$url" "${h[@]}" \
    -D "$OUT/$name.headers" -o "$OUT/$name.json" \
    -w '%{http_code}' --max-time 30 || echo "000")
  printf '  %-22s %-16s HTTP %s' "$set" "$name" "$code"

  local ra
  ra=$(grep -i '^retry-after:' "$OUT/$name.headers" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
  [ -n "$ra" ] && printf '  retry-after=%s' "$ra"
  printf '\n'
  echo "$code"  > "$OUT/$name.status"
}

status_of() { cat "$OUT/$1.status" 2>/dev/null || echo "000"; }

# --- 1. OAuth endpoint discovery ---------------------------------------------

# Unauthenticated and free. §10.1 records Anthropic's authorize/token URLs as
# measured facts; this is the equivalent for OpenAI, so the design does not have
# to guess them. The client_id below was read out of the codex binary, not
# guessed — but nothing has confirmed it is accepted, which is why it is printed
# as an input to a later step rather than as a finding.
echo "=== 1. OAuth discovery (auth.openai.com) ==="
if curl -sS --max-time 20 https://auth.openai.com/.well-known/openid-configuration \
     -o "$OUT/oidc.json" -H "User-Agent: $UA"; then
  jq -r '{issuer, authorization_endpoint, token_endpoint, revocation_endpoint,
          scopes_supported, code_challenge_methods_supported}' "$OUT/oidc.json" 2>/dev/null \
    || { echo "  not JSON; raw body:"; head -c 400 "$OUT/oidc.json"; echo; }
else
  echo "  discovery request failed (recorded as unknown, not as absent)"
fi
echo "  codex-cli public client_id seen in the binary: app_EMoamEEZ73f0CkXaXp7hrann"
# The CLI does not use the endpoint its own issuer advertises. Its request log
# (~/.codex/logs_2.sqlite) records token traffic against
# https://auth.openai.com/oauth/token, not the /api/accounts/oauth/token above.
# Both are recorded because a design that picks one on the strength of discovery
# alone would be picking the one nothing has been observed to use.
echo "  token endpoint the CLI is observed to use: https://auth.openai.com/oauth/token"
echo

# --- 2. which usage path answers ---------------------------------------------

# Two candidates, both taken from the binary: it carries `/api/codex/usage` and
# `/wham/usage` as sibling strings, and nothing says which one this account's
# server routes. Probing both and reporting each status is cheaper than reading
# a 404 as "the endpoint does not exist" — this repository has twice misdiagnosed
# a defect by treating absence as proof.
echo "=== 2. usage path probe (honest headers) ==="
# Order matters: the first 200 wins, so the list is ranked by what the evidence
# supports rather than by what answers.
#
# `codex/usage` leads because every Codex call the CLI is observed to make sits
# under /backend-api/codex/… with no `api` segment — read out of the CLI's own
# request log, which recorded https://chatgpt.com/backend-api/codex/models.
#
# `api/codex/usage` is the composition an earlier draft of this script guessed
# by pasting a bare `/api/codex/usage` string from the binary onto $BASE. It
# 403s, and that 403 was briefly read as "Codex exposes no usage endpoint". It
# says nothing of the kind; it says this script built a URL nothing serves.
#
# `wham/usage` is last despite answering 200. A real Codex turn measured on
# 2026-08-03 did not move its window, so a 200 there is not evidence of the
# right data source. Ranking it any higher would let the wrong numbers win
# silently — which is how a confidently wrong figure reaches a widget.
# `client_version` is not decoration. `/codex/models` answered 400 with
# `{'loc': ('query','client_version'), 'msg': 'Field required'}` — a JSON error
# carrying `x-oai-request-id`, so that path reaches the backend and rejects the
# request on its own terms. Probing without the parameter cannot distinguish
# "this route does not exist" from "this route wanted an argument".
CV="${CODEX_CLIENT_VERSION:-0.146.0}"
CANDIDATES="codex-usage:$BASE/codex/usage?client_version=$CV
api-codex-usage:$BASE/api/codex/usage?client_version=$CV
wham-usage:$BASE/wham/usage?client_version=$CV
wham-usage-bare:$BASE/wham/usage"

USAGE_URL=""; USAGE_NAME=""
while IFS=: read -r cname curl_; do
  [ -z "$cname" ] && continue
  request "$cname" "$curl_" honest
  if [ -z "$USAGE_URL" ] && [ "$(status_of "$cname")" = "200" ]; then
    USAGE_URL="$curl_"; USAGE_NAME="$cname"
  fi
done <<EOF
$CANDIDATES
EOF

# Control. `/codex/models` is a path this machine's CLI is observed to call
# successfully (recorded in ~/.codex/logs_2.sqlite), so it isolates what a 403
# on `/codex/usage` actually means:
#
# What separates the cases is not the status code but who answered. An
# `x-oai-request-id` header means the request reached OpenAI's backend; a
# Cloudflare challenge (HTML body, `server-timing: chlray`) means it did not.
# An earlier version of this block tested `= 200` and reported the measured 400
# as "the family refuses this client" — the opposite of what a JSON 400 saying
# `client_version: Field required` actually shows, which is that the backend
# read the request and answered it.
request "control-models" "$BASE/codex/models" honest
if grep -qi '^x-oai-request-id:' "$OUT/control-models.headers" 2>/dev/null; then
  echo "  → control reached the backend (x-oai-request-id present, HTTP $(status_of control-models))."
  echo "    /codex/* is not blocked at the edge for this client, so a 403 above is"
  echo "    about that specific route, not about who is asking."
else
  echo "  → control did NOT reach the backend (no x-oai-request-id, HTTP $(status_of control-models))."
  echo "    The edge is answering for the whole /codex/* family. Nothing below can"
  echo "    tell you whether a usage endpoint exists behind it."
fi
echo

if [ -z "$USAGE_URL" ]; then
  echo
  echo "No candidate returned 200 with honest headers."
  echo "Bodies are in $OUT/. A 401 usually means the stored access token has"
  echo "expired — run any codex command to refresh it, then re-run this script."
  echo "Stopping before the remaining steps, which all need a working read."
  exit 2
fi
echo "  → using $USAGE_URL"
echo

# --- 3. which headers are actually required ----------------------------------

echo "=== 3. header requirement (A/B) ==="
request "hdr-no-account" "$USAGE_URL" honest-no-account

if [ "${CODEX_SPIKE_IMPERSONATE:-0}" = "1" ]; then
  echo
  echo "  CODEX_SPIKE_IMPERSONATE=1 — sending requests that claim to be codex_cli_rs."
  echo "  These exist only as a control for a *refused* honest request. If the"
  echo "  honest request above returned 200, these rows answer nothing and the"
  echo "  §5.2 policy question is already settled in favour of staying honest."
  request "hdr-originator" "$USAGE_URL" originator
  request "hdr-codex-ua"   "$USAGE_URL" codex-ua
  request "hdr-codex-full" "$USAGE_URL" codex-full
else
  echo "  (impersonating control variants skipped; set CODEX_SPIKE_IMPERSONATE=1 to run them)"
fi
echo

# --- 4. schema ---------------------------------------------------------------

echo "=== 4. response schema ==="
echo "top-level keys:"
jq -r 'keys[] | "  " + .' "$OUT/$USAGE_NAME.json" 2>/dev/null || {
  echo "  body is not a JSON object; first 400 bytes:"; head -c 400 "$OUT/$USAGE_NAME.json"; echo; }

echo
echo "plan_type: $(jq -r '.plan_type // "<absent>"' "$OUT/$USAGE_NAME.json" 2>/dev/null)"
echo "  Every schema line below is conditional on this. A plan whose windows are"
echo "  all null teaches nothing about the shape a populated window takes."

echo
echo "windows found:"
WCOUNT=$(jq -r "$JQ_LIMITS"' windows | length' "$OUT/$USAGE_NAME.json" 2>/dev/null || echo 0)
if [ "${WCOUNT:-0}" = "0" ]; then
  SHAPE_OK=no
  echo "  NONE — the reader matched no window."
  echo "  Do NOT read this as 'this account has no limits'. It means the response"
  echo "  shape has moved away from what JQ_LIMITS knows, and every step below is"
  echo "  vacuous. Compare the top-level keys above against the filter and fix it"
  echo "  before trusting the summary."
else
  SHAPE_OK=yes
  jq -r "$JQ_LIMITS"' windows[] | "  " + .name + ": " + (.raw|tostring)' \
    "$OUT/$USAGE_NAME.json" 2>/dev/null || true
  echo
  echo "field names on each window (as sent, before normalisation):"
  jq -r "$JQ_LIMITS"' [windows[].raw | keys[]] | unique[] | "  " + .' \
    "$OUT/$USAGE_NAME.json" 2>/dev/null || true
fi

echo
echo "reset credits (the row content chosen for the widget):"
# Prefer the field embedded in this response; only probe the dedicated endpoint
# when it is absent, so the common case costs no extra request. The /consume
# sibling of this path is never called — it spends a credit.
if jq -e 'has("rate_limit_reset_credits")' "$OUT/$USAGE_NAME.json" >/dev/null 2>&1; then
  jq -r '.rate_limit_reset_credits | "  in usage response: " + tostring' "$OUT/$USAGE_NAME.json" 2>/dev/null
else
  echo "  absent from the usage response; probing the dedicated path"
  request "credits" "$BASE/api/codex/rate-limit-reset-credits" honest
  jq -r '"  " + tostring' "$OUT/credits.json" 2>/dev/null || true
fi
echo

# --- 5. does reading cost anything? (the go/no-go) ---------------------------

# The premise under test. §12.6 already rejected the response-header path for
# Anthropic precisely because obtaining it consumes the limit being measured; a
# Codex reader that did the same would be the same defect with a different
# vendor's name on it.
echo "=== 5. consumption test — $READS extra reads ==="
echo "  Do not use Codex while this runs, or the comparison is confounded."

# `reset_at` is deliberately absent from the comparison. While a window is
# closed the server reports it as now + reset_after_seconds, so it advances once
# per wall-clock second and would make every pair of samples differ — turning
# the test into a guaranteed "moved" the same way the missing reader turned it
# into a guaranteed "unchanged". `reset_after_seconds` carries the same fact
# without the clock in it, and it is the more sensitive signal of the two: a
# closed window reports it pinned at `limit_window_seconds`, and the first
# billed request anchors the window and starts it counting down.
sample() {
  jq -c "$JQ_LIMITS"' [windows[] | {n: .name, used, win, left}]' \
    "$OUT/$1.json" 2>/dev/null || echo 'null'
}

# Whether any window is currently open. A run in which every window stayed shut
# can only show that reads do not *open* one; it cannot speak to what a read
# does to a window already ticking.
any_open() {
  jq -r "$JQ_LIMITS"' [windows[] | select(.left != null and .win != null and .left < .win)]
                      | length > 0' "$OUT/$1.json" 2>/dev/null || echo "false"
}

if [ "$SHAPE_OK" != "yes" ]; then
  VERDICT="INCONCLUSIVE — the reader found no window to watch, so there is"
  VERDICT="$VERDICT nothing this test could have detected."
  MOVED="unmeasured"
  OPEN="unknown"
else
  request "consume-before" "$USAGE_URL" honest >/dev/null
  BEFORE=$(sample consume-before)
  OPEN=$(any_open consume-before)
  echo "  before: $BEFORE"

  for i in $(seq 1 "$READS"); do
    request "consume-$i" "$USAGE_URL" honest >/dev/null
    sleep 1
  done

  request "consume-after" "$USAGE_URL" honest >/dev/null
  AFTER=$(sample consume-after)
  echo "  after:  $AFTER"
  echo

  if [ "$BEFORE" = "$AFTER" ]; then MOVED="no"; else MOVED="yes"; fi

  if [ "$MOVED" = "yes" ]; then
    VERDICT="NO-GO candidate — a window moved across reads alone."
  elif [ "$OPEN" = "true" ]; then
    VERDICT="GO — an already-open window did not move across $READS reads."
  else
    VERDICT="GO, qualified — no window was open, so this run shows only that"
    VERDICT="$VERDICT reads do not open one. Re-run on an account with usage in"
    VERDICT="$VERDICT flight to test the other half."
  fi
fi

# --- summary -----------------------------------------------------------------

echo "=== summary ==="
echo "usage endpoint:        $USAGE_URL"
echo "honest headers:        HTTP $(status_of "$USAGE_NAME")"
echo "without account id:    HTTP $(status_of hdr-no-account)"
if [ "${CODEX_SPIKE_IMPERSONATE:-0}" = "1" ]; then
  echo "originator only:       HTTP $(status_of hdr-originator)"
  echo "codex UA only:         HTTP $(status_of hdr-codex-ua)"
  echo "codex UA + originator: HTTP $(status_of hdr-codex-full)"
fi
echo "plan_type:             $(jq -r '.plan_type // "<absent>"' "$OUT/$USAGE_NAME.json" 2>/dev/null)"
echo "reader matched shape:  $SHAPE_OK"
echo "a window was open:     $OPEN"
echo "windows moved:         $MOVED (over $READS reads)"
echo
echo "$VERDICT"
echo
if [ "$MOVED" = "yes" ]; then
  echo "Before recording that, rule out the cheaper explanation: a Codex session"
  echo "running concurrently moves these numbers for reasons that have nothing to"
  echo "do with this script. Repeat the run with Codex idle."
fi
echo
echo "Whatever this run says, it describes one plan on one account. The schema of"
echo "a window that is null here is not measured by a run in which it stayed null."
echo
echo "Full bodies and headers: $OUT/"
