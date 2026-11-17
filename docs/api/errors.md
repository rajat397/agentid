# API Errors

**Status:** Draft v0.1 (steering document)

---

## 1. Error envelope

Every non-2xx response uses the same envelope:

```json
{
  "error": {
    "type": "insufficient_authority",
    "code": "delegation_constraint_violated",
    "message": "Requested amount 4500 USD exceeds delegation cap 2000 USD.",
    "param": "amount",
    "request_id": "req_01J8X4R7M2N9P",
    "docs_url": "https://docs.agentid.example/errors/delegation_constraint_violated",
    "details": {
      "constraint": "max_amount",
      "bound": {"value": 2000, "currency": "USD"},
      "observed": {"value": 4500, "currency": "USD"},
      "delegation_id": "dlg_01J8X2K9Q4T7W"
    }
  }
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `type` | string | yes | Broad category. Stable. Switch on this. |
| `code` | string | yes | Specific error. Stable. Switch on this when you need to. |
| `message` | string | yes | Human-readable. **Not stable — do not parse.** |
| `param` | string | no | Field path that caused the error, where applicable |
| `request_id` | string | yes | **Quote this when contacting support.** Correlates with our logs. |
| `docs_url` | string | no | Link to the code's documentation |
| `details` | object | no | Structured, machine-readable context |

---

## 2. Error types

| `type` | HTTP | Meaning |
|---|---|---|
| `invalid_request` | 400 | Malformed or semantically invalid request |
| `authentication_required` | 401 | Missing or invalid credentials |
| `permission_denied` | 403 | Valid credentials, insufficient permission for the operation |
| `insufficient_authority` | 403 | The *agent's delegation* does not permit this action |
| `not_found` | 404 | Resource does not exist |
| `conflict` | 409 | State conflict — duplicate, already revoked, race |
| `precondition_failed` | 412 | Conditional request failed |
| `constraint_violated` | 422 | Semantically valid but violates a declared constraint |
| `rate_limited` | 429 | Too many requests |
| `internal_error` | 500 | Our fault |
| `unavailable` | 503 | Temporarily unavailable; retry with backoff |
| `policy_violation` | 403 | Rejected by policy evaluation |

**`insufficient_authority` vs `permission_denied`** — the distinction matters for debugging. `permission_denied` means *your API client* may not do this (wrong scope, wrong role). `insufficient_authority` means *the agent* may not do this (delegation constraints). Agents see `insufficient_authority`; the human sees both.

---

## 3. Catalogue

### 3.1 `invalid_request` (400)

| Code | Meaning | Common cause |
|---|---|---|
| `malformed_json` | Body is not valid JSON | Trailing comma, single quotes |
| `missing_required_field` | Required field absent | Check `param` |
| `invalid_field_type` | Wrong type | `param` names the field |
| `constraints_required` | Delegation created with no constraints | Deliberate rejection — unbounded grants are not allowed |
| `invalid_money_amount` | Negative, zero, or wrong currency | Minor units must be positive integers |
| `invalid_timestamp` | Not RFC 3339, or not UTC | Use `Z` suffix |
| `invalid_spid` | Malformed SPIFFE ID | Must be `spiffe://domain/path` |
| `chain_depth_exceeded` | Delegation chain deeper than the configured maximum | V1 limit: 3 hops |

### 3.2 `authentication_required` (401)

| Code | Meaning | Common cause |
|---|---|---|
| `missing_token` | No Authorization header | |
| `invalid_token` | Token failed validation | Expired, bad signature, wrong issuer |
| `token_audience_mismatch` | Token audience is not this API | Token minted for a different resource server (RFC 9700 §2.3: the RS MUST refuse on mismatch) |
| `token_expired` | `exp` in the past | Clock skew; see `clock_skew` detail |
| `proof_of_possession_failed` | `cnf` binding not satisfied | mTLS client cert missing or wrong key; `cnf.x5t#S256` (mTLS) or `cnf.jkt` (DPoP) per RFC 7800 |
| `token_replayed` | `jti` already seen | Token replay attempt |
| `svid_revoked` | The presented SVID was revoked | Agent revoked; check `POST /agents/{id}/revocation` |

### 3.3 `insufficient_authority` (403)

| Code | Meaning | `details` |
|---|---|---|
| `no_active_delegation` | Agent has no active delegation for this action | `agent_id` |
| `delegation_expired` | Delegation expired | `delegation_id`, `expired_at` |
| `delegation_revoked` | Delegation revoked | `delegation_id` |
| `delegation_constraint_violated` | A constraint was exceeded | `constraint`, `bound`, `observed` |
| `action_not_permitted` | Action not in the delegation's allowlist | `action`, `permitted_actions` |
| `system_not_permitted` | Target system not in the delegation's allowlist | `system`, `permitted_systems` |
| `approval_required` | Amount exceeded the approval threshold; approval not obtained | `threshold`, `observed`, `approval_endpoint` |
| `approval_lacks_authority` | The approving human could not satisfy the constraint | `approver_id`, `required_role` |
| `outside_time_window` | Action outside the delegation's allowed hours | `window`, `timezone` |
| `agent_revoked` | Agent revoked | `agent_id`, `revoked_at` |
| `chain_depth_exceeded` | Delegation chain too deep | `chain_depth`, `max_depth` |

### 3.4 `not_found` (404)

`agent_not_found` · `delegation_not_found` · `receipt_not_found` · `approval_not_found` · `policy_not_found` · `fleet_not_found` · `erasure_request_not_found`

**Note:** for resources a caller is not authorized to see, we return `404`, not `403`. Returning `403` would confirm the resource exists — an enumeration oracle. This is a deliberate trade: it costs debuggability, buys resistance to enumeration.

### 3.5 `conflict` (409)

| Code | Meaning |
|---|---|
| `agent_already_registered` | An agent with the same attestation selector exists |
| `agent_already_revoked` | Revocation is terminal |
| `delegation_already_revoked` | Revocation is terminal |
| `approval_already_decided` | A decision was already recorded |
| `idempotency_key_reuse` | Same key, different request body — reject rather than guess |
| `attestation_in_progress` | Attestation is running; retry shortly |

### 3.6 `constraint_violated` (422)

| Code | Meaning |
|---|---|
| `immutable_field_modification` | Attempt to change an immutable field (e.g. `human_owner` after activation) |
| `invalid_state_transition` | e.g. reactivating a revoked agent |
| `duplicate_target_system` | Same system listed twice |
| `delegation_exceeds_parent` | Requested constraints exceed the parent delegation — **rejected at creation, not at use** |
| `approval_expired` | Approval request passed its expiry |

### 3.7 `rate_limited` (429)

```json
{
  "error": {
    "type": "rate_limited",
    "code": "rate_limit_exceeded",
    "message": "Write rate limit exceeded for this tenant.",
    "request_id": "req_01J8X4R7M2N9P",
    "details": {
      "limit": 600,
      "window": "1m",
      "retry_after_seconds": 23
    }
  }
}
```

Honor `Retry-After`. We use exponential backoff with jitter on our side, so client retries should also include jitter to avoid synchronizing.

### 3.8 `unavailable` (503)

Raised when the PDP or SPIRE is unreachable, and fail-closed applies. **This is a control working as designed, not a bug.**

```json
{
  "error": {
    "type": "unavailable",
    "code": "policy_decision_unavailable",
    "message": "Authorization could not be evaluated. Action denied (fail-closed).",
    "request_id": "req_01J8X4R7M2N9P",
    "details": {
      "fail_mode": "closed",
      "component": "pdp",
      "retry_after_seconds": 5,
      "break_glass_available": false
    }
  }
}
```

**Client guidance:** on `policy_decision_unavailable`, retry with exponential backoff. Do not fall back to an unauthorized call. If the action is configured as read-only and fail-open, you will get a `200` with `x-agentid-fail-open: true` instead — treat that as degraded operation and alert on it.

---

## 4. Error handling guidance

### 4.1 Retry policy

| Error type | Retry? | Strategy |
|---|---|---|
| `invalid_request` | No | Fix the request |
| `authentication_required` | No | Refresh credentials |
| `insufficient_authority` | No | **This is the control working.** Escalate to a human or request a broader delegation |
| `not_found` | No | Check the ID |
| `conflict` | No | Read current state before retrying |
| `constraint_violated` | No | Fix the request or the policy |
| `rate_limited` | Yes | Honor `Retry-After`, add jitter |
| `unavailable` | Yes | Backoff. Never fall back to unauthorized |
| `internal_error` | Yes | Backoff, max 3 attempts, then escalate with `request_id` |

### 4.2 The one that matters most

**A `403 insufficient_authority` from the PEP is a security event, not a bug to retry.**

When an agent hits a constraint, that is a detection opportunity — possibly prompt injection. The PEP records a receipt with `result: "denied"` for exactly this reason. Retry logic that loops on `403` turns one injection attempt into a hundred.

```python
# Wrong
while True:
    resp = post(action, payload)
    if resp.status == 403:
        continue   # ← amplification of a blocked attack

# Right
resp = post(action, payload)
if resp.status == 403:
    # Already recorded by the PEP as a denied receipt.
    # Surface it; do not retry.
    raise AuthorizationDenied(resp.json()["error"])
```

### 4.3 Distinguishing a real outage from a control

`503 policy_decision_unavailable` with `fail_mode: "closed"` means the control plane is down and actions are being blocked. This is safe but not available. `503` with `fail_mode: "open"` means we degraded deliberately for read-only traffic. Alert on both, but treat the first as an availability incident and the second as a security-posture degradation.

---

## 5. Support diagnostics

Every error includes `request_id`. When escalating:

```
request_id: req_01J8X4R7M2N9P
time:       2026-11-15T04:41:07Z
operation:  POST /receipts
agent:      spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c
delegation: dlg_01J8X2K9Q4T7W
```

The `request_id` alone is sufficient for us to find the request in our logs, including the PDP decision, the constraint evaluation, and the receipt if one was written.

---

*Next: [`core-api.md`](core-api.md). Webhooks and erasure-request endpoints are designed but not published yet — see the roadmap section of the README.*
