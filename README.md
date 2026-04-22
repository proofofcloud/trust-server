# Confidential VM Quote Processing Server

A Node.js web service for processing Intel SGX/TDX and AMD SEV-SNP quotes. It validates remote attestation reports, extracts platform identifiers, and issues signed JWT tokens for verified confidential VMs.

## Overview

This service acts as a trust anchor for Confidential Computing workflows. It accepts raw hardware quotes (hex encoded), validates them using the appropriate internal tool (attester for Intel or amd-verifier for AMD), extracts a unique hardware identifier (Chip ID or PPID), and checks it against a whitelist of verified providers and a revocation list of blocked machines. Verified non-revoked quotes receive a signed JWT; callers that only need a yes/no answer can use the dedicated `/check_quote` endpoint.

## Features

* **Multi-Architecture Support**:
    * **Intel SGX & TDX**: Validates DCAP quotes via Intel's QVL.
    * **AMD SEV-SNP**: Validates attestation reports via amd-verifier.
* **Automatic Detection**: Automatically determines the architecture based on the quote structure and length.
* **Hardware Identity Extraction**:
    * Extracts PPID (Platform Provisioning ID) for Intel quotes.
    * Extracts Chip ID for AMD SEV-SNP reports.
* **Whitelist Verification**: Checks hardware IDs against a strict whitelist of approved machines (sourced from the Proof of Cloud database).
* **Revocation List**: Deny-list of revoked hardware IDs with revocation timestamps. Takes precedence over the whitelist; also sourced from the Proof of Cloud database and baked into the image at build time.
* **JWT Generation**: Issues RS256-signed JWT tokens containing the machine ID, label, quote hash, timestamp, and a curated TEE measurement snapshot. Revoked machines are denied with an HTTP 403 and a revocation-specific error message.
* **Lightweight Check Endpoint**: `POST /check_quote` answers "is this machine on our whitelist?" without issuing a JWT — useful for monitoring, gating, and ops tooling.

## API Endpoints

### `POST /get_jwt`

Processes an SGX, TDX, or SEV-SNP quote and returns a signed JWT containing the machine identity and a curated snapshot of the TEE measurement fields.

**Request Body:**
```json
{
  "quote": "hex_encoded_quote",
  "timestamp": 1234567890, // Optional: Unix seconds. Server accepts ±5 min skew.
  "nonces": ["..."],       // Optional: Required if MULTISIG_MODE is true
  "partial_sigs": ["..."]  // Optional: Required if MULTISIG_MODE is true
}
```

**Response:**
```json
{
  "machineId": "hex_machine_id",
  "label": "machine label",
  "jwt": "rs256_or_eddsa_signed_jwt_token"
}
```

The JWT payload contains:

```json
{
  "quote_hash": "sha256_of_quote_bytes",
  "machine_id": "hex_machine_id",
  "label": "machine label",
  "timestamp": 1234567890,
  "tee": {
    "type": "tdx" | "sgx" | "sev-snp",
    ...architecture-specific fields (see below)
  }
}
```  

**`tee` fields by architecture:**

Intel TDX (`tee.type = "tdx"`):
| Field | Hex length |
|---|---|
| `mr_td` | 96 |
| `mr_seam` | 96 |
| `mr_signer_seam` | 96 |
| `td_attributes` | 16 |
| `xfam` | 16 |
| `tcb_svn` | 32 |
| `rtmr0`, `rtmr1`, `rtmr2`, `rtmr3` | 96 each |
| `report_data` | 128 |

Intel SGX v3 (`tee.type = "sgx"`):
| Field | Hex length / type |
|---|---|
| `mr_enclave` | 64 hex |
| `mr_signer` | 64 hex |
| `report_data` | 128 hex |
| `attributes` | 32 hex |
| `cpu_svn` | 32 hex |
| `isv_prod_id`, `isv_svn`, `config_svn` | JSON number |

AMD SEV-SNP (`tee.type = "sev-snp"`):
| Field | Hex length |
|---|---|
| `measurement` | 96 |
| `host_data` | 64 |
| `report_data` | 128 |
| `policy` | 16 |
| `reported_tcb` | 16 |
| `id_key_digest` | 96 |

All hex values are lowercase.

**Trust semantics:** The `tee` fields in the JWT attest that this server observed a successfully-verified quote containing these measurement values. They do not constitute an authorization decision — consumers must apply their own policy (e.g., allowed `mr_enclave` values, required `td_attributes` bits). In particular, `report_data` is caller-controlled (typically a challenge nonce) and must be matched against the challenge the consumer issued; it provides no authentication on its own.

**Error responses:**
- `403 { "error": "Machine is not whitelisted." }` — hardware ID is unknown.
- `403 { "error": "Machine <id> was revoked on <iso8601_timestamp>" }` — hardware ID has been revoked.
- `500` — verifier failure, malformed input, or other server error.

### `POST /check_quote`

Verifies an attestation quote and returns whether the underlying machine is on the whitelist. Does **not** issue a JWT; does **not** require multisig coordination. Intended for lightweight "is this machine approved?" checks.

**Request Body:**
```json
{
  "quote": "hex_encoded_sgx_or_tdx_quote"
}
```

**Response (whitelisted):**
```json
{
  "whitelisted": true,
  "machine_id": "hex_machine_id"
}
```

**Response (not whitelisted, not revoked):**
```json
{
  "whitelisted": false,
  "machine_id": "hex_machine_id"
}
```

**Response (revoked — whether or not also whitelisted):**
```json
{
  "whitelisted": false,
  "machine_id": "hex_machine_id",
  "revoked": true,
  "revoked_at": "2026-04-16T12:00:00Z"
}
```

Revocation takes precedence over whitelisting: a machine in both lists is reported as `revoked`.

### `POST /verify_token`

Verifies JWT token generated for the provided quote.

**Request Body:**
```json
{
  "quote": "hex_encoded_sgx_or_tdx_quote",
  "jwt": "hex_encoded_sgx_or_tdx_quote"
}
```

**Response:**
```json
{
  "valid": true,
  "keyId": "key id of the signer",
  "label": "machine label",
  "tee": { "type": "tdx|sgx|sev-snp", "...": "see /get_jwt response" }
}
```

The `tee` field mirrors the TEE object from the JWT payload. For JWTs issued before the `tee` field was introduced, this field is `null`.

### `GET /`

Health check endpoint that returns service status.

## How to run

### Standard (Single Sig, HTTP)

```
sudo docker run \
    -d \
    --rm \
    -p 8080:8080 \
    ghcr.io/proofofcloud/trust-server:sha-<sha_hash>
```

### Secure Mode (Single Sig, HTTPS)

To run in production with HTTPS, you must mount your certificates into the container and set the environment variables.

1. **Prepare Certificates**: Ensure you have your `privkey.pem` and `fullchain.pem`.
2. **Run Container**:

```
sudo docker run \
    -d \
    --rm \
    -p 443:8080 \
    -e HTTPS_ENABLED=true \
    -e HTTPS_KEY_PATH=/certs/privkey.pem \
    -e HTTPS_CERT_PATH=/certs/fullchain.pem \
    -v /path/to/your/certs:/certs:ro \
    ghcr.io/proofofcloud/trust-server:sha-<sha_hash>
```

### Multisig Mode

To run in Multisig mode (with or without HTTPS), add the `MULTISIG_MODE` environment variable.

```
sudo docker run \
    -d \
    --rm \
    -p 8080:8080 \
    -e MULTISIG_MODE=true \
    ghcr.io/proofofcloud/trust-server:sha-<sha_hash>
```
