# Verification API — `/receipts/verify` and `/v1/keys`

A third party must be able to verify a receipt with two HTTP responses and the
receipt bytes. No SDK, no account, and no call back to the issuer.

## Mounting

```
agentid evidence export --demo --out evidence-bundle.json
agentid serve --bundle evidence-bundle.json --addr 127.0.0.1:8080
```

`agentid serve` mounts the handlers on **caller-owned infrastructure**. We do
not host a public verifier (see D28): doing so would reintroduce the trusted
third party the anchoring decisions reject.

## Endpoints

`GET /v1/keys` →
`{"keys":[{"kid":"…","alg":"ES256","material":"-----BEGIN PUBLIC KEY…","format":"pem"},{"kid":"…","alg":"ML-DSA-65","material":"<base64url>","format":"raw-b64url"}]}`

Key `alg`/`format` are inferred from material: PEM ⇒ ES256, >1000 raw
base64url characters ⇒ ML-DSA-65. Callers with unusual key shapes should serve
their own registry; the inference is a convenience, not a normative registry.

`POST /receipts/verify` (or `GET /receipts/verify?receipt=<json>`) takes one
receipt JSON object and returns:

```
{"verified":true,
 "checks":[{"name":"body_hash","ok":true}, …],
 "reason":""}
```

Checks performed, using only the receipt bytes and published keys:

1. body hash matches the receipt id prefix;
2. `profile_digest` and `envelope_digest` are present and SHA-256-shaped;
3. primary ES256 signature verifies;
4. **every additional signature** (ML-DSA-65 by default) verifies — a missing
   PQ `kid` in the key set is a failure, not a skip;
5. HTTP 200 = verified, 422 = failed verification, 400 = malformed receipt.

The endpoint does not check the receipt against a ledger — that is the
evidence-bundle verifier's job. It answers the narrower question "are these
bytes a properly signed receipt from a published key?"

## Falsifier

A third party cannot verify with only these two responses, or a PQ signature
is silently skipped when its key is absent — `httpapi_test.go` attacks both.
