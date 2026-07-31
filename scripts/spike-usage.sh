#!/usr/bin/env bash
# Manual research script only. The application never reads this file; only this
# script does, and only when a human runs it.
set -euo pipefail

CREDS="${CLAUDE_CREDS:-$HOME/.claude/.credentials.json}"
UA="quota-board/0.1.0-spike"

if [ ! -f "$CREDS" ]; then
  echo "credential file not found: $CREDS" >&2
  echo "Run 'claude auth login' on this machine first." >&2
  exit 1
fi

TOKEN=$(jq -r '.claudeAiOauth.accessToken // .accessToken // empty' "$CREDS")
if [ -z "$TOKEN" ]; then
  echo "could not find accessToken. Check the file's key structure:" >&2
  jq -r 'paths(scalars) | join(".")' "$CREDS" >&2
  exit 1
fi

echo "=== request User-Agent: $UA ==="
curl -sS -D /tmp/quota-spike-headers.txt \
  -o /tmp/quota-spike-body.json \
  -w 'HTTP %{http_code}  %{time_total}s\n' \
  https://api.anthropic.com/api/oauth/usage \
  -H "Authorization: Bearer $TOKEN" \
  -H "anthropic-beta: oauth-2025-04-20" \
  -H "Content-Type: application/json" \
  -H "User-Agent: $UA"

echo; echo "=== response headers ==="
cat /tmp/quota-spike-headers.txt

echo; echo "=== top-level keys ==="
jq -r 'keys[]' /tmp/quota-spike-body.json 2>/dev/null || cat /tmp/quota-spike-body.json

echo; echo "=== is seven_day present? ==="
jq '.seven_day' /tmp/quota-spike-body.json 2>/dev/null || true

echo; echo "=== limits[] summary ==="
jq -c '.limits // [] | .[] | {kind, group, percent, resets_at, scope}' \
  /tmp/quota-spike-body.json 2>/dev/null || true
