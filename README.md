# Confidential VM Quote Processing Server

A Node.js web service for processing Intel SGX and TDX DCAP quotes, extracting platform identifiers, and generating JWT tokens for verified enclaves.

## Overview

This service validates SGX and TDX quotes, extracts the PPID (Platform Provisioning ID), checks against a whitelist, and returns a JWT token for authenticated enclaves. It's designed for Intel SGX and TDX attestation workflows.

## Features

- **Quote Processing**: Validates SGX and TDX DCAP quotes in hexadecimal format
- **PPID Extraction**: Extracts Platform Provisioning ID from quote data
- **Machine ID Generation**: Creates unique machine identifiers from PPID
- **Whitelist Verification**: Checks machine IDs against a whitelist taken from proofofcloud database of verified machines
- **JWT Generation**: Issues RS256-signed JWT tokens for verified quotes

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
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v ./keys.json:/app/keys.json \
    ghcr.io/proofofcloud/trust-server:sha-1e44ad0e83daefc6137f2ec95ac952394735ab34
```

The service will run on `http://localhost:8080`
