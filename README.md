# Hive Typed Signer

Real **ML-DSA-65** (NIST FIPS 204) typed-fragment signing and verification.

No mock signatures. No Ed25519. Every receipt is signed with a real post-quantum
ML-DSA-65 signature that verifies under the published demo public key — by this
service or by any independent third party.

Backend for the public "try it yourself" demo at
[thehiveryiq.com/typed-signer/](https://thehiveryiq.com/typed-signer/).

## What it does

A visitor pastes text. The service decomposes it into typed fragments
(reasoning, tool_call, final, decomposition, ...), signs the selected set with
**one** ML-DSA-65 signature over an aggregate root, and the same service — or
anyone holding the published public key — verifies it live. Tampering with any
signed fragment causes verification to fail.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | Service info |
| GET | `/health` | Health check |
| GET | `/pubkey` | Published ML-DSA-65 public key (independent verify) |
| POST | `/sign` | `{ text }` or `{ fragments: [...] }` → typed receipt |
| POST | `/verify` | `{ envelope, fragments }` → `{ valid, reasons, verify_us }` |

### Carnac digest signing contract

`/sign` and `/verify` also accept a narrow, backwards-compatible digest mode for
Carnac. Supply a precomputed SHA-256 digest and the same real ML-DSA-65 engine
binds + signs exactly that digest (no mock, no fallback, `ml-dsa-65` /
`ML-DSA-65` casing accepted, any other algorithm rejected):

```
POST /sign    { payload_sha256: <64 hex>, algo: "ML-DSA-65" }
           -> { signature: <b64>, public_key: <b64>, algo: "ML-DSA-65" }

POST /verify  { payload_sha256, signature, public_key, algo }
           -> { valid: <bool>, algo }
```

If `HIVE_INTERNAL_TOKEN` is set, digest signing requires an
`X-Hive-Internal-Token` header matching it; verification stays public and is
rate limited (`CARNAC_VERIFY_RATE_MAX`, default 240/min/IP). When the token is
unset, existing behavior is unchanged. The private key is never returned or
logged, and raw payloads are never logged.

## Run locally

```bash
npm install
DEMO_SIGNER_SEED_HEX=<64-hex-chars> node server.js
# -> http://localhost:3000
```

If `DEMO_SIGNER_SEED_HEX` is not set, a seed is generated and persisted to
`data/demo_signer_seed.hex` so the published key stays stable across restarts.
The demo key is isolated from any production key.

## Deploy (Render)

`render.yaml` defines a Node web service. Set `DEMO_SIGNER_SEED_HEX` in the
Render dashboard so the published public key is reproducible across deploys.

---

Patent Pending HC-2026-001.
