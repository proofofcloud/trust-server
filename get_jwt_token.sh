#!/usr/bin/env bash
set -euo pipefail

# ---- Hardcoded config ----
M=3
COSIGNERS=(
  "http://localhost:8081/get_jwt"
  "http://localhost:8082/get_jwt"
  "http://localhost:8083/get_jwt"
  "http://localhost:8084/get_jwt"
)

# ---- Args ----
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/my_quote.txt" >&2
  exit 2
fi

QUOTE_PATH="$1"
if [[ ! -f "$QUOTE_PATH" ]]; then
  echo "Error: quote file not found: $QUOTE_PATH" >&2
  exit 2
fi

QUOTE="$(cat "$QUOTE_PATH")"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required command: $1" >&2; exit 2; }; }
need_cmd curl
need_cmd jq

# ---- Helpers ----
post_json() {
  local url="$1"
  local payload="$2"
  curl -sS --fail \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

# Builds {"quote":"..."} safely with jq (handles quotes/newlines)
payload_stage1() {
  jq -cn --arg quote "$QUOTE" '{quote:$quote}'
}

# Builds {"quote":"...","nonces":{...},"partial_sigs":{...}} with jq
payload_stage2() {
  local nonces_json="$1"       # JSON object
  local partial_sigs_json="$2" # JSON object
  jq -cn --arg quote "$QUOTE" \
        --argjson nonces "$nonces_json" \
        --argjson partial_sigs "$partial_sigs_json" \
        '{quote:$quote, nonces:$nonces, partial_sigs:$partial_sigs}'
}

# Like stage2 but without partial_sigs (first signer in chain)
payload_stage2_first() {
  local nonces_json="$1"
  jq -cn --arg quote "$QUOTE" \
        --argjson nonces "$nonces_json" \
        '{quote:$quote, nonces:$nonces}'
}

# ---- Stage 1: collect moniker+nonce until quorum ----
declare -A URL_BY_MONIKER=()
declare -A NONCE_BY_MONIKER=()

echo "Stage 1: collecting nonces (need M=$M)..."

for url in "${COSIGNERS[@]}"; do
  payload="$(payload_stage1)"
  echo "  -> $url"
  if ! resp="$(post_json "$url" "$payload" 2>/dev/null)"; then
    echo "     (skip: request failed)"
    continue
  fi

  moniker="$(jq -r '.moniker // empty' <<<"$resp")"
  nonce="$(jq -r '.nonce // empty' <<<"$resp")"

  if [[ -z "$moniker" || -z "$nonce" ]]; then
    echo "     (skip: missing moniker/nonce)"
    continue
  fi

  # If duplicate moniker appears, keep first (or overwrite—your choice)
  if [[ -n "${NONCE_BY_MONIKER[$moniker]+x}" ]]; then
    echo "     (warn: duplicate moniker '$moniker', ignoring this one)"
    continue
  fi

  URL_BY_MONIKER["$moniker"]="$url"
  NONCE_BY_MONIKER["$moniker"]="$nonce"
  echo "     accepted: moniker=$moniker"

  if (( ${#NONCE_BY_MONIKER[@]} >= M )); then
    break
  fi
done

if (( ${#NONCE_BY_MONIKER[@]} < M )); then
  echo "Error: only got ${#NONCE_BY_MONIKER[@]} approvals, need $M" >&2
  exit 1
fi

# Choose exactly M monikers deterministically (sorted)
mapfile -t CHOSEN_MONIKERS < <(printf "%s\n" "${!NONCE_BY_MONIKER[@]}" | sort | head -n "$M")

echo "Chosen quorum:"
printf "  - %s\n" "${CHOSEN_MONIKERS[@]}"

# Build nonces JSON object: {"alice":"...","bob":"..."}
nonces_json="$(jq -cn 'reduce inputs as $i ({}; . * $i)' \
  < <(
    for m in "${CHOSEN_MONIKERS[@]}"; do
      jq -cn --arg k "$m" --arg v "${NONCE_BY_MONIKER[$m]}" '{($k):$v}'
    done
  )
)"

# ---- Stage 2: chain partial signatures ----
partial_sigs_json='{}'

echo "Stage 2: chaining signatures..."
for i in "${!CHOSEN_MONIKERS[@]}"; do
  moniker="${CHOSEN_MONIKERS[$i]}"
  url="${URL_BY_MONIKER[$moniker]}"

  if [[ "$partial_sigs_json" == "{}" ]]; then
    payload="$(payload_stage2_first "$nonces_json")"
  else
    payload="$(payload_stage2 "$nonces_json" "$partial_sigs_json")"
  fi

  echo "  -> $url (as $moniker)"
  if ! resp="$(post_json "$url" "$payload" 2>/dev/null)"; then
    echo "Error: signing step failed at $url (moniker=$moniker)" >&2
    exit 1
  fi

  # If final JWT present, output and finish
  jwt="$(jq -r '.jwt // empty' <<<"$resp")"
  if [[ -n "$jwt" ]]; then
    echo "Final result received:"
    echo "$resp" | jq .
    exit 0
  fi

  # Otherwise expect a map like {"alice":"sig..."} or {"alice":"...","bob":"..."}
  if ! jq -e 'type=="object" and (has("jwt")|not)' >/dev/null <<<"$resp"; then
    echo "Error: unexpected response from $url: $resp" >&2
    exit 1
  fi

  # Merge returned partial sigs into accumulated map
  partial_sigs_json="$(jq -cn --argjson a "$partial_sigs_json" --argjson b "$resp" '$a * $b')"

  echo "     partial_sigs now has $(jq 'length' <<<"$partial_sigs_json") entries"
done

echo "Error: chain finished but no final jwt was returned." >&2
echo "Last partial_sigs: $partial_sigs_json" >&2
exit 1

