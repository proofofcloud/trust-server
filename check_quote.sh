#!/usr/bin/env bash
set -euo pipefail

# ---- Args ----
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <quote_file_path> [server_url]" >&2
  echo "       server_url defaults to http://localhost:8080" >&2
  exit 2
fi

QUOTE_PATH="$1"
SERVER_URL="${2:-http://localhost:8080}"

# ---- Dependency check ----
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need_cmd curl
need_cmd jq

# ---- Validate quote file ----
if [[ ! -f "$QUOTE_PATH" ]]; then
  echo "Error: quote file not found: $QUOTE_PATH" >&2
  exit 2
fi

QUOTE="$(cat "$QUOTE_PATH")"

if [[ -z "$QUOTE" ]]; then
  echo "Error: quote file is empty: $QUOTE_PATH" >&2
  exit 2
fi

# ---- Build request body and POST ----
URL="${SERVER_URL%/}/check_quote"
BODY="$(jq -cn --arg q "$QUOTE" '{quote: $q}')"

RESP_FILE="$(mktemp -t check_quote_resp.XXXXXX 2>/dev/null || mktemp)"
trap 'rm -f "$RESP_FILE"' EXIT

HTTP_STATUS=0
RESPONSE="$(
  curl -sS -o "$RESP_FILE" -w "%{http_code}" \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d "$BODY"
)" || HTTP_STATUS=$?

if (( HTTP_STATUS != 0 )); then
  echo "Error: curl failed to reach $URL" >&2
  exit 1
fi

HTTP_CODE="$RESPONSE"
BODY_OUT="$(cat "$RESP_FILE")"

echo "HTTP $HTTP_CODE"
if echo "$BODY_OUT" | jq . >/dev/null 2>&1; then
  echo "$BODY_OUT" | jq .
else
  echo "$BODY_OUT"
fi

if (( HTTP_CODE < 200 || HTTP_CODE >= 300 )); then
  exit 1
fi
