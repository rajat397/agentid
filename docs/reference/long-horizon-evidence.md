# Long-horizon evidence — RFC 3161 anchoring

**Status:** Implemented, tested offline (11 tests, `tests/test_anchor.py`). One honest limitation below.

## Why this exists

Agent receipts are meant to outlive the algorithms that sign them. NISTIR 8587 §5.3.1.2 notes short-lived tokens bound to reauthentication limit a compromised credential's window — but the *evidence* an auditor wants is the opposite: it must survive for years. The anchor resolves that split:

- **Live enforcement** uses short-lived ES256 artifacts.
- **Existence and integrity over time** rest on an independent RFC 3161 TSA and the hash chain — not on any one signature algorithm.

The chain head commits to every earlier receipt (`Ledger.verify_chain`), so stamping the head stamps the whole history.

## What ships

| Piece | File |
|---|---|
| Anchor library | `src/agentid/anchor.py` — DER TimeStampReq by hand (no new dependencies), response parsing, binding check |
| CLI | `agentid anchor --ledger <receipts.jsonl> [--tsa URL] [--out anchors.jsonl]` |
| Offline verify | `agentid verify-anchor --file anchors.jsonl --ledger anchors.jsonl.ledger.jsonl` |
| Fixture | `tests/fixtures/demo-anchor.jsonl*` — a real FreeTSA response captured 2026-11-17 (serial 169877646), so tests never touch the network |

## What is verified

- The anchor binds the exact chain head of the ledger it was taken against.
- The TSTInfo inside the TSA response names the same digest.
- The stored request matches the recorded head hash.
- Any of the above diverging — head flip, imprint tamper, request mismatch, ledger tamper, empty ledger — fails verification (each has a test).

## Honest limitation

`verify_anchor` checks the **binding**, not the TSA's certificate chain. Full trust means validating the TSA's signature and its root (e.g., `openssl ts -verify -reply resp.tsr -queryfile req.tsq -CAfile tsa-ca.pem`, or pinning FreeTSA's CA). Chain-of-trust verification is deliberately not claimed here; supply your own `--ca` verification before relying on this in an audit. The binding check alone still detects all tampering of stored evidence, which is what the receipt ledger claims.

## Rules for operators

- Anchor on a cadence (e.g., every N receipts or M minutes), not once — recent receipts are never worse than the last anchor.
- Store anchors with the archived receipts; they are useless apart from the ledger.
- Treat a failed verification as an incident, not a warning.
