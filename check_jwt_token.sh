#!/usr/bin/env bash
set -euo pipefail

# ---- Args ----
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 jwt_token quote_hex" >&2
  exit 2
fi

JWT="$1"
QUOTE_HEX="$2"

# Basic validation of quote hex
if ! [[ "$QUOTE_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "Error: quote_hex is not valid hex" >&2
  exit 2
fi


if (( ${#QUOTE_HEX} % 2 != 0 )); then
  echo "Error: quote_hex must contain an even number of hex digits" >&2
  exit 2
fi

# ---- Compute sha256(quote binary), where quote is provided as hex ----
QUOTE_HASH_ACTUAL="$(
  printf '%s' "$QUOTE_HEX" | xxd -r -p | sha256sum | awk '{print $1}'
)"

#PUBKEY_HEX='5c8b1d8541733c5cf9593a5f6b608105a1315514a584dde8496471a2e90c88aa'
PUBKEY_HEX=$(curl -s https://raw.githubusercontent.com/proofofcloud/trust-server/refs/heads/main/public_info/public_key.txt)

if ! [[ "$PUBKEY_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "Error: fetched public key is not a valid 32-byte hex string" >&2
  exit 1
fi

echo 'Shared pubkey: ' $PUBKEY_HEX

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

IFS='.' read -r HDR PAY SIG <<< "$JWT"

if [ -z "${HDR:-}" ] || [ -z "${PAY:-}" ] || [ -z "${SIG:-}" ]; then
  echo "Invalid JWT format" >&2
  exit 1
fi

# Build Ed25519 SPKI public key PEM from raw 32-byte hex key
python3 - "$PUBKEY_HEX" > "$tmpdir/pubkey.pem" <<'PY'
import sys, base64, textwrap

pk_hex = sys.argv[1]
pk = bytes.fromhex(pk_hex)
if len(pk) != 32:
    raise SystemExit(f"Public key must be 32 bytes, got {len(pk)}")

# ASN.1 DER SubjectPublicKeyInfo prefix for Ed25519:
# 30 2a
#   30 05
#     06 03 2b 65 70
#   03 21 00
der = bytes.fromhex("302a300506032b6570032100") + pk

b64 = base64.b64encode(der).decode()
print("-----BEGIN PUBLIC KEY-----")
for i in range(0, len(b64), 64):
    print(b64[i:i+64])
print("-----END PUBLIC KEY-----")
PY

# Exact signed data is "<base64url(header)>.<base64url(payload)>"
printf '%s.%s' "$HDR" "$PAY" > "$tmpdir/msg.bin"

# Decode JWT signature from base64url
python3 - "$SIG" > "$tmpdir/sig.bin" <<'PY'
import sys, base64
s = sys.argv[1]
s += "=" * ((4 - len(s) % 4) % 4)
sys.stdout.buffer.write(base64.urlsafe_b64decode(s))
PY

# Optional: check alg field
ALG="$(python3 - "$HDR" <<'PY'
import sys, base64, json
s = sys.argv[1]
s += "=" * ((4 - len(s) % 4) % 4)
obj = json.loads(base64.urlsafe_b64decode(s))
print(obj.get("alg", ""))
PY
)"

if [ "$ALG" != "EdDSA" ]; then
  echo "Unexpected JWT alg: $ALG" >&2
  exit 1
fi

# Verify signature
if ! OUT=$(openssl pkeyutl \
    -verify \
    -pubin \
    -inkey "$tmpdir/pubkey.pem" \
    -rawin \
    -in "$tmpdir/msg.bin" \
    -sigfile "$tmpdir/sig.bin" \
    2>&1); then
    echo "$OUT"
    exit 1
fi

echo "Signature: OK"

# Extract quote_hash
QUOTE_HASH_FROM_JWT="$(python3 - "$PAY" <<'PY'
import sys, base64, json
s = sys.argv[1]
s += "=" * ((4 - len(s) % 4) % 4)
obj = json.loads(base64.urlsafe_b64decode(s))
print(obj["quote_hash"])
PY
)"

if [[ "$QUOTE_HASH_ACTUAL" != "$QUOTE_HASH_FROM_JWT" ]]; then
  echo "Error: quote hash mismatch" >&2
  exit 1
fi

echo "Quote hash verified OK"
