#!/usr/bin/env bash
# Observe the 429 boundary and the meaning of Retry-After by polling for 90
# minutes at 60-second intervals.
#
# Manual research script only. The application never reads the credential file;
# only this script does, and only when a human runs it.
set -euo pipefail

CREDS="${CLAUDE_CREDS:-$HOME/.claude/.credentials.json}"
UA="quota-board/0.1.0-spike"
LOG="${THROTTLE_LOG:-.local/research/throttle-log.tsv}"
ITERATIONS="${ITERATIONS:-90}"

mkdir -p "$(dirname "$LOG")"
printf 'seq\tepoch\thttp\tretry_after\n' > "$LOG"

for i in $(seq 1 "$ITERATIONS"); do
  CODE=""
  RA=""

  # Token extraction: guard the failure inside the `if` condition so that a jq
  # failure (for example, the file being momentarily incomplete during a token
  # refresh) does not kill the script under `set -e`. stderr is always
  # suppressed because it can carry fragments of the credential file — the token
  # value is never printed or recorded under any circumstances.
  if TOKEN=$(jq -r '.claudeAiOauth.accessToken // .accessToken' "$CREDS" 2>/dev/null) \
      && [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    # Guard temp-header-file creation failure (for example, /tmp being full) the
    # same way.
    if HDRS=$(mktemp); then
      CODE=$(curl -sS -D "$HDRS" -o /dev/null -w '%{http_code}' \
        https://api.anthropic.com/api/oauth/usage \
        -H "Authorization: Bearer $TOKEN" \
        -H "anthropic-beta: oauth-2025-04-20" \
        -H "Content-Type: application/json" \
        -H "User-Agent: $UA" || echo "000")
      # On responses without a Retry-After header (a 200, say) grep exits 1 for
      # no match; `|| true` keeps that from terminating the script early under
      # `set -e` with pipefail.
      RA=$(grep -i '^retry-after:' "$HDRS" | tr -d '\r' | awk '{print $2}' || true)
      rm -f "$HDRS"
    else
      CODE="ERR_TMPFILE"
    fi
  else
    CODE="ERR_TOKEN"
  fi

  # Guard the row write itself (tee) so a failure — a disk error, say — does not
  # kill the loop but moves on to the next iteration. In that case the row
  # cannot be recorded in the TSV, so warn on stderr only.
  printf '%s\t%s\t%s\t%s\n' "$i" "$(date +%s)" "${CODE:-ERR_UNKNOWN}" "${RA:--}" \
    | tee -a "$LOG" || echo "warning: failed to record row seq=$i (tee)" >&2

  [ "$i" -lt "$ITERATIONS" ] && sleep 60
done
