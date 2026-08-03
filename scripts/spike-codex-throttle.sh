#!/usr/bin/env bash
# Spike G — the 429 boundary of the Codex usage endpoint.
#
# Spike F (docs/research/codex-usage-endpoint.md) established that the endpoint
# can be read honestly, and explicitly did not measure how often. §6.1's
# 180-second floor was derived from Spikes B and D against Anthropic; nothing
# equivalent exists here, so a Codex poll interval currently has no basis. This
# run is that basis. The method mirrors spike-throttle.sh so the two are
# comparable: 60-second intervals for 90 iterations, one account.
#
# It doubles as the larger consumption sample Spike F lacked. That run compared
# 12 reads against a window that was already at 0% and could not move down; this
# one logs `used_percent` and `reset_after_seconds` on every row, so 90 reads
# over 90 minutes either move them or do not. **Do not use Codex while this
# runs**, or that second measurement is confounded.
#
# Manual research script only. The application never reads ~/.codex/auth.json;
# only this script does, and only when a human runs it.
set -euo pipefail

AUTH="${CODEX_AUTH:-$HOME/.codex/auth.json}"
URL="${CODEX_USAGE_URL:-https://chatgpt.com/backend-api/wham/usage}"
LOG="${CODEX_THROTTLE_LOG:-.local/research/codex-throttle-log.tsv}"
ITERATIONS="${ITERATIONS:-90}"
INTERVAL="${INTERVAL:-60}"

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "${ROOT:-.}/Cargo.toml" 2>/dev/null | head -1)
UA="quota-board/${VERSION:-unknown}-spike"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

if [ -e "$LOG" ]; then
  # Same refusal as spike-codex-usage.sh, for the same reason: a run that took
  # 90 minutes must not be destroyed by starting another one.
  echo "log already exists: $LOG" >&2
  echo "Move it aside, or pass CODEX_THROTTLE_LOG=<path> on the same line." >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG")"
printf 'seq\tepoch\thttp\tretry_after\twho\tused_percent\treset_after\n' > "$LOG"

echo "endpoint:   $URL"
echo "User-Agent: $UA"
echo "log:        $LOG"
echo "plan:       $ITERATIONS iterations at ${INTERVAL}s (~$((ITERATIONS * INTERVAL / 60)) minutes)"
echo "Do not use Codex while this runs."
echo

for i in $(seq 1 "$ITERATIONS"); do
  CODE=""; RA=""; WHO=""; USED=""; LEFT=""

  # The token is re-read every iteration rather than captured once, because it
  # can rotate mid-run — and the file briefly disappears while Codex rewrites
  # it. That was observed on 2026-08-03: a read at 15:24 failed with ENOENT and
  # the file was back, with a different size, at 15:25. Guarding inside the `if`
  # keeps a jq failure from killing the loop under `set -e`. stderr is always
  # suppressed because jq echoes input fragments on failure and those fragments
  # can carry the token; no token value is ever printed or recorded.
  if TOKEN=$(jq -r '.tokens.access_token // empty' "$AUTH" 2>/dev/null) \
      && [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    if HDRS=$(mktemp) && BODY=$(mktemp); then
      CODE=$(curl -sS -D "$HDRS" -o "$BODY" -w '%{http_code}' --max-time 30 "$URL" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Accept: application/json" \
        -H "User-Agent: $UA" || echo "000")

      # `|| true` on every grep: no match exits 1, which would end the run under
      # `set -e` with pipefail on the first response that simply lacks a header.
      RA=$(grep -i '^retry-after:' "$HDRS" | tr -d '\r' | awk '{print $2}' || true)

      # Which side answered. Spike F showed the status code alone cannot say:
      # a Cloudflare challenge and a backend rejection both arrive as 4xx, and
      # only the backend sets x-oai-request-id. A throttle and a bot-block are
      # different findings and must not be averaged into one column.
      if grep -qi '^x-oai-request-id:' "$HDRS"; then WHO="backend"; else WHO="edge"; fi

      # The consumption half. Absent on a non-200, which records as "-".
      USED=$(jq -r '.rate_limit.primary_window.used_percent // empty' "$BODY" 2>/dev/null || true)
      LEFT=$(jq -r '.rate_limit.primary_window.reset_after_seconds // empty' "$BODY" 2>/dev/null || true)

      rm -f "$HDRS" "$BODY"
    else
      CODE="ERR_TMPFILE"
    fi
  else
    CODE="ERR_TOKEN"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$i" "$(date +%s)" "${CODE:-ERR_UNKNOWN}" "${RA:--}" "${WHO:--}" "${USED:--}" "${LEFT:--}" \
    | tee -a "$LOG" || echo "warning: failed to record row seq=$i (tee)" >&2

  [ "$i" -lt "$ITERATIONS" ] && sleep "$INTERVAL"
done

echo
echo "=== status distribution ==="
awk -F'\t' 'NR>1 {n[$3]++} END {for (k in n) printf "  %-14s %d\n", k, n[k]}' "$LOG"
echo "=== who answered ==="
awk -F'\t' 'NR>1 {n[$5]++} END {for (k in n) printf "  %-14s %d\n", k, n[k]}' "$LOG"
echo "=== Retry-After values seen ==="
awk -F'\t' 'NR>1 && $4 != "-" {n[$4]++} END {for (k in n) printf "  %-14s %d\n", k, n[k]}' "$LOG"
echo "=== used_percent range (the consumption half) ==="
awk -F'\t' 'NR>1 && $6 != "-" {if (min=="") {min=$6; max=$6} if ($6<min) min=$6; if ($6>max) max=$6}
            END {if (min=="") print "  no 200 carried a window"; else printf "  min %s  max %s\n", min, max}' "$LOG"
echo
echo "A flat used_percent here is a much larger sample than Spike F's twelve"
echo "reads, but it is still only evidence that reads are free at this rate --"
echo "not proof, and not a statement about an account with usage in flight."
