# Confidential VM Quote Processing Server

A Node.js web service for processing Intel SGX/TDX and AMD SEV-SNP quotes. It validates remote attestation reports, extracts platform identifiers, and issues signed JWT tokens for verified confidential VMs.

## Overview

This service acts as a trust anchor for Confidential Computing workflows. It accepts raw hardware quotes (hex encoded), validates them using the appropriate internal tool (attester for Intel or amd-verifier for AMD), extracts a unique hardware identifier (Chip ID or PPID), checks it against a whitelist of verified providers, and returns a signed JWT.

## Features

* **Multi-Architecture Support**:
    * **Intel SGX & TDX**: Validates DCAP quotes via Intel's QVL.
    * **AMD SEV-SNP**: Validates attestation reports via amd-verifier.
* **Automatic Detection**: Automatically determines the architecture based on the quote structure and length.
* **Hardware Identity Extraction**:
    * Extracts PPID (Platform Provisioning ID) for Intel quotes.
    * Extracts Chip ID for AMD SEV-SNP reports.
* **Whitelist Verification**: Checks hardware IDs against a strict whitelist of approved machines (sourced from the Proof of Cloud database).
* **JWT Generation**: Issues RS256-signed JWT tokens containing the machine ID, label, and quote hash.

## API Endpoints

### `POST /get_jwt`

Processes an SGX or TDX quote and returns verification results.

**Request Body:**
```json
{
  "quote": "hex_encoded_sgx_or_tdx_quote"
}
```

**Response:**
```json
{
  "machineId": "truncated_sha256_of_ppid", 
  "label": "machine label",
  "jwt": "rs256_signed_jwt_token"
}
```

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
  "valid": "true|false", 
  "keyId": "key id of the signer", 
  "label": "machine label",
}
```

### `GET /`

Health check endpoint that returns service status.

## How to run

```
sudo docker run \
    -d \
    --rm \
    -p 8080:8080 \
    ghcr.io/proofofcloud/trust-server:sha-<sha_hash>
```

The service will run on `http://localhost:8080`
