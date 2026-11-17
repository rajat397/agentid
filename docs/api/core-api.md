# API Reference — Agent Identity & Authorization Control Plane

**Status:** Draft v0.1 (steering document)
**Base URL:** `https://api.{tenant}.agentid.example/v1`
**Content type:** `application/json`
**Auth:** OAuth 2.1 (`draft-ietf-oauth-v2-1-17` — an Internet-Draft, not a
standard) — `client_credentials` for machine callers, `authorization_code` +
PKCE for human-facing surfaces.

- `client_credentials` is restricted to **confidential clients** (OAuth 2.1 §4.2).
  It cannot express delegation; that is what RFC 8693 token exchange is for.
- PKCE is REQUIRED for the authorization-code grant, with one narrow exception
  (OAuth 2.1 §7.5.1.1: confidential client **and** reasonable assurance of
  proper OIDC nonce handling). The RFC 7636 `plain` method is prohibited.

---

## 1. Conventions

**Resource naming.** Singular nouns, hyphenated IDs with a type prefix. Prefixes are stable and part of the public contract:
`agt_` agent · `dlg_` delegation · `rcp_` receipt · `apr_` approval · `pol_` policy · `flr_` fleet · `ev_` event · `req_` erasure request · `blk_` approval block.

**Timestamps.** RFC 3339, UTC, with `Z`. Never local time. Never unix epoch.

**Money.** Integer minor units plus ISO 4217 currency. Never floats.

**Pagination.** Cursor-based. `limit` (default 50, max 500) + `after` cursor. Cursors are opaque; do not parse them. Response envelope:

```json
{
  "data": [ ... ],
  "has_more": true,
  "next_cursor": "eyJvIjoxNzE2NDQyMzAxLCJpZCI6InJjcF8wMUo4WDRSN0wyTjlQIn0"
}
```

**Errors.** Uniform envelope. Full model in [`errors.md`](errors.md).

```json
{
  "error": {
    "type": "insufficient_authority",
    "code": "delegation_constraint_violated",
    "message": "Requested amount 4500 USD exceeds delegation cap 2000 USD.",
    "param": "amount",
    "request_id": "req_01J8X4R7M2N9P",
    "docs_url": "https://docs.agentid.example/errors/delegation_constraint_violated"
  }
}
```

**Idempotency.** `POST` endpoints that create resources accept `Idempotency-Key`. Replaying a key returns the original response and `Idempotency-Replayed: true`. Keys are scoped per-tenant, retained 24 hours. Required on `POST /delegations`, `POST /approvals`, `POST /erasure-requests`.

**Access token types.** Two categories, per OAuth 2.1 §5.2: **reference
tokens** (validated by querying the authorization server or a token database)
and **self-encoded tokens** (authorization information in an encrypted and/or
signed string). The JWT profile for access tokens, `at+jwt`, is defined by
**RFC 9068** — not by OAuth 2.1 itself. We issue **self-encoded** tokens with
`at+jwt` for PEP-local validation, and support reference tokens for
revocation-sensitive deployments.

**Audience binding.** Access tokens are audience-restricted to the intended
resource server via the `aud` claim (RFC 9068) and the `resource` parameter
(RFC 8707). On audience mismatch the resource server **MUST refuse** the
request (RFC 9700 §2.3). Note the spec permits restricting to "a small set of
resource servers", so "exact single-audience matching" is our policy, not the
spec's wording.

**Scope enforcement.** The resource server **MUST** check that the token was
issued with the appropriate scope (OAuth 2.1 §5.2), in addition to expiry,
resource authorization, and its own policy requirements.

**Versioning.** URL-path version. Additive changes ship within `v1`. Breaking changes ship as `v2` with a documented migration. Field-level breaking changes are avoided by only ever adding fields.

---

## 2. Agents

### 2.1 Register an agent

```
POST /agents
```

Registers an agent. The agent has no usable identity until attestation succeeds.

```json
{
  "name": "marketing-agent",
  "fleet": "flr_marketing",
  "human_owner": "oidc|acme-retail|usr_8842",
  "purpose": "Manages paid social campaigns and ad credit spend.",
  "attestation": {
    "type": "spiffe_workload",
    "selector": {
      "k8s_service_account": "system:serviceaccount:agents:marketing-agent",
      "container_image_digest": "sha256:3f9a...c1"
    }
  },
  "target_systems": ["meta-ads", "linkedin-ads"],
  "metadata": {"tier": "prod", "owner_team": "growth"}
}
```

**Response `201`**
```json
{
  "id": "agt_01J8X2K9Q4T7W",
  "name": "marketing-agent",
  "fleet": "flr_marketing",
  "human_owner": "oidc|acme-retail|usr_8842",
  "status": "pending_attestation",
  "spiffe_id": null,
  "attestation": {
    "type": "spiffe_workload",
    "selector": {"k8s_service_account": "system:serviceaccount:agents:marketing-agent"}
  },
  "target_systems": ["meta-ads", "linkedin-ads"],
  "created_at": "2026-11-15T04:10:00Z"
}
```

**Notes**
- `spiffe_id` is `null` until attestation matches. This is deliberate — issuing an identity before attestation would defeat C3.
- `human_owner` is required and immutable after first activation. It is the root of every delegation chain for this agent.
- Duplicate registration with the same `attestation.selector` returns `409 agent_already_registered`.

### 2.2 Get an agent

```
GET /agents/{agent_id}
```

### 2.3 List agents

```
GET /agents?fleet={fleet_id}&status={status}&limit=50&after={cursor}
```

`status` ∈ `pending_attestation` · `active` · `suspended` · `revoked`

### 2.4 Revoke an agent

```
POST /agents/{agent_id}/revocation
```

Revocation is immediate and irreversible from the control plane's perspective. It:
1. Marks the agent `revoked`
2. Invalidates the agent's SVID in SPIRE (bounded by propagation — see Architecture §4.8)
3. Invalidates all outstanding access tokens bearing that SVID
4. Invalidates all active delegations where this agent is the actor
5. Emits `agt.revoked` event and a ledger receipt

```json
{
  "reason": "credential_exposure",
  "detail": "SVID key id kgv-3f9a appeared in a public repository scan.",
  "revoke_delegations": true
}
```

**Response `200`**
```json
{
  "id": "agt_01J8X2K9Q4T7W",
  "status": "revoked",
  "revoked_at": "2026-11-15T04:44:19Z",
  "revoked_by": "oidc|acme-retail|usr_9011",
  "invalidated": {
    "svid": true,
    "active_delegations": 3,
    "outstanding_tokens": 5
  }
}
```

**Errors:** `404 agent_not_found` · `409 agent_already_revoked`

### 2.5 Agent status transitions

```
pending_attestation ──attestation matched──▶ active
pending_attestation ──attestation timeout (24h)──▶ expired
active ──suspend──▶ suspended ──reactivate──▶ active
active ──revoke──▶ revoked  (terminal)
```

---

## 3. Delegations

### 3.1 Create a delegation

```
POST /delegations
```

Grants an agent the authority to act for a human principal, under explicit constraints. This is the object that makes "acting for whom" and "under whose approval" answerable.

```json
{
  "subject": {
    "type": "human",
    "id": "oidc|acme-retail|usr_8842"
  },
  "actor": {
    "type": "agent",
    "agent_id": "agt_01J8X2K9Q4T7W"
  },
  "parent_delegation_id": null,
  "constraints": {
    "permissions": [
      {"action": "ad.credit.purchase", "system": "meta-ads"},
      {"action": "social.post.publish", "system": "meta-ads"},
      {"action": "social.post.publish", "system": "linkedin-ads"}
    ],
    "max_amount": {"value": 2000, "currency": "USD"},
    "requires_human_approval_above": {"value": 500, "currency": "USD"},
    "allowed_hours": {"start": "06:00", "end": "23:00", "timezone": "America/New_York"}
  },
  "expires_at": "2026-11-15T16:22:10Z",
  "approval": {
    "method": "oidc_consent",
    "acr": "urn:mace:incommon:iap:silver"
  }
}
```

**Response `201`**
```json
{
  "id": "dlg_01J8X2K9Q4T7W",
  "status": "active",
  "subject": {"type": "human", "id": "oidc|acme-retail|usr_8842"},
  "actor": {"type": "agent", "agent_id": "agt_01J8X2K9Q4T7W", "spiffe_id": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c"},
  "parent_delegation_id": null,
  "chain_depth": 1,
  "constraints": {
    "permissions": [
      {"action": "ad.credit.purchase", "system": "meta-ads"},
      {"action": "social.post.publish", "system": "meta-ads"},
      {"action": "social.post.publish", "system": "linkedin-ads"}
    ],
    "max_amount": {"value": 2000, "currency": "USD"},
    "requires_human_approval_above": {"value": 500, "currency": "USD"}
  },
  "approval": {
    "method": "oidc_consent",
    "approved_by": "oidc|acme-retail|usr_8842",
    "approved_at": "2026-11-15T04:22:10Z",
    "acr": "urn:mace:incommon:iap:silver",
    "auth_time": "2026-11-15T04:21:58Z",
    "context": {"ip": "203.0.113.9", "session_id": "sess_7c1e"}
  },
  "expires_at": "2026-11-15T16:22:10Z",
  "signature": {"alg": "ES256", "kid": "dlg-key-2026-04", "value": "MEUCIQ..."}
}
```

**Notes**
- `chain_depth` is capped at 3 (see Architecture Q6). Exceeding returns `409 delegation_depth_exceeded`. **This cap is our extension** — RFC 8693 specifies no depth limit.
- Constraints are mandatory. A delegation with no constraints is rejected — `400 constraints_required`. An unbounded grant is the exact anti-pattern NIST's least-privilege question targets (concept paper, p.4, Authorization sub-question 4).
- `permissions` is a list of explicit **(action, system) pairs**, not two independent lists. RFC 8693 §2.1.1: "the requested access rights of the token are the Cartesian product of all the scopes at all the target services." Two independent lists would silently grant `ad.credit.purchase` on `linkedin-ads`, which the operator never approved. Pairs make the grant exactly what it says.
- The signature is over the canonical JSON of the delegation body excluding the `signature` field itself. Canonicalization: RFC 8785 (JCS).
- The issued access token carries **identity only** — the subject (`sub`), the current actor (`act`), and a `delegation_id` reference. It does **not** carry the constraint set: RFC 8693 §4.1 states that non-identity claims are "not meaningful" inside `act`, and the policy engine MUST resolve constraints from this delegation record, never from a nested `act` history.

### 3.1.1 Token exchange (RFC 8693)

The Delegation Service exposes RFC 8693 token exchange so existing OAuth
infrastructure can interoperate.

```
POST /oauth2/token
```

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<human id token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&actor_token=<agent SVID-derived token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://meta-ads.internal
```

**Notes**
- `actor_token_type` is REQUIRED when `actor_token` is present and **MUST NOT** be included otherwise (RFC 8693 §2.1).
- `resource` is an absolute URI and MUST NOT include a fragment component (RFC 8693 §2.1, RFC 8707).
- The issued token must not outlive the delegation record's `expires_at`. Token exchange does not create a tight linkage between input and output tokens, so this is enforced by us, not inherited (RFC 8693 §2.1).
- Pre-authorization may be expressed with the `may_act` claim on the subject token. The AS uses it to decide whether the requested delegation is permitted. `may_act` carries **identity only** — it says *who* may act, never *under what constraints*.
- Client authentication is **required**. RFC 8693 §2.1: omitting it "allows for a compromised token to be leveraged via an STS into other tokens by anyone possessing the compromised token." Agents authenticate with an SVID-derived `private_key_jwt`.

### 3.2 Revoke a delegation

```
POST /delegations/{delegation_id}/revocation
```
```json
{"reason": "human_request", "revoke_children": true}
```

### 3.3 List delegations

```
GET /delegations?actor={agent_id}&subject={human_id}&status={status}&limit=50&after={cursor}
```

### 3.4 Inspect a delegation chain

```
GET /delegations/{delegation_id}/chain
```
Returns the full ancestor chain, root-first:
```json
{
  "data": [
    {"hop": 1, "from": "oidc|acme-retail|usr_8842", "to": "agt_01J8X2K9Q4T7W", "delegation_id": "dlg_01J8X2K9Q4T7W"},
    {"hop": 2, "from": "agt_01J8X2K9Q4T7W", "to": "agt_01J8X2K9Q4T7W2", "delegation_id": "dlg_01J8X2K9Q4T8X"}
  ]
}
```

---

## 4. Receipts (audit trail)

### 4.1 Write a receipt

```
POST /receipts
```

Normally called by the PEP, not by agents. Agent-facing callers are permitted only for receipts in `action_type: "self_reported"`, which are marked as such and cannot satisfy non-repudiation requirements.

```json
{
  "fleet": "flr_marketing",
  "actor": {"spiffe_id": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c"},
  "delegation_id": "dlg_01J8X2K9Q4T7W",
  "action": "ad.credit.purchase",
  "resource": {
    "type": "ad_credit_account",
    "id": "acme_retail_meta",
    "attributes": {"amount": 2000, "currency": "USD", "personal_data_refs": ["cust_4471"]}
  },
  "decision": {
    "result": "allowed",
    "constraints_evaluated": [
      {"constraint": "amount_cap", "bound": 2000, "observed": 2000, "satisfied": true},
      {"constraint": "requires_human_approval_above", "bound": 500, "observed": 2000, "satisfied": false, "resolution": "approval_obtained", "approval_ref": "apr_01J8X3Q1"}
    ]
  },
  "outcome": {"status": "succeeded", "external_ref": "meta_ad_order_993812"},
  "action_type": "observed"
}
```

**Response `201`** returns the receipt with `id`, `issued_at`, `prev_hash`, `hash`.

### 4.2 List receipts — the investigation query

```
GET /receipts
  ?fleet={fleet_id}
  &actor={spiffe_id}
  &action={action}
  &resource_type={type}&resource_id={id}
  &delegation_id={delegation_id}
  &since={rfc3339}&until={rfc3339}
  &result={allowed|denied}
  &personal_data_ref={ref}
  &limit=50&after={cursor}
```

This is the endpoint that answers the post-incident question set. `personal_data_ref` is the erasure-workflow key.

### 4.3 Get a receipt

```
GET /receipts/{receipt_id}
```

### 4.4 Verify chain integrity

```
GET /receipts/verify?fleet={fleet_id}&from={receipt_id}&to={receipt_id}
```
```json
{
  "valid": true,
  "checked_receipts": 1884,
  "chain_head": "sha256:9df2...",
  "anchor": {"type": "transparency_log", "ref": "log_8812", "anchored_at": "2026-11-15T05:00:00Z"},
  "verified_at": "2026-11-15T05:12:44Z"
}
```

Anyone can run this against a downloaded export. This is C7 made concrete.

---

## 5. Approvals

### 5.1 Request approval

```
POST /approvals
```
Called by the PEP when a constraint requires human approval.

```json
{
  "delegation_id": "dlg_01J8X2K9Q4T7W",
  "action": "ad.credit.purchase",
  "resource": {"type": "ad_credit_account", "id": "acme_retail_meta", "attributes": {"amount": 4500, "currency": "USD"}},
  "constraint": "requires_human_approval_above",
  "reason": "Requested amount 4500 USD exceeds configured approval threshold of 500 USD.",
  "expires_at": "2026-11-15T04:59:00Z",
  "notify": {"channels": ["slack:#ads-approvals"], "fallback": "api_poll"}
}
```

**Response `201`** returns the approval with `status: "pending"`.

### 5.2 Approve or reject

```
POST /approvals/{approval_id}/decision
```
```json
{"decision": "approved", "comment": "Q4 campaign — approved."}
```
```json
{"decision": "rejected", "comment": "Over budget. Re-scope to $2000."}
```

**Notes**
- Approvals expire. An expired approval is `status: "expired"`, not `rejected` — the distinction matters in audit.
- The approving human must have authority to satisfy the constraint. If they do not, the response is `403 approver_lacks_authority`.
- A human may approve a delegation that was itself granted by an agent, subject to that agent's own constraints.

### 5.3 List approvals

```
GET /approvals?status={pending|approved|rejected|expired}&delegation_id={id}&since={t}&until={t}
```

---

## 6. Erasure requests (GDPR Art. 17)

### 6.1 Create an erasure request

```
POST /erasure-requests
```
```json
{
  "subject": {"type": "customer", "id": "cust_4471"},
  "jurisdiction": "EU",
  "requested_by": "oidc|acme-retail|usr_9011",
  "deadline": "2026-12-15T00:00:00Z",
  "scope": {"include_derived_artifacts": true, "include_backups": false}
}
```

**Response `201`**
```json
{
  "id": "req_01J8X9T2W6K4M",
  "status": "planning",
  "subject": {"type": "customer", "id": "cust_4471"},
  "deadline": "2026-12-15T00:00:00Z",
  "days_remaining": 30,
  "plan": {
    "total_receipts": 214,
    "total_delegations": 12,
    "fleets_affected": ["flr_marketing", "flr_support"],
    "downstream_systems": [
      {"system": "meta-ads", "records": 88, "deletion_method": "customer_connector"},
      {"system": "internal_crm", "records": 31, "deletion_method": "customer_connector"}
    ],
    "derived_artifacts": [
      {"artifact": "campaign_performance_model", "owner": "growth-analytics", "action_required": "customer_action"}
    ]
  },
  "created_at": "2026-11-15T06:00:00Z"
}
```

### 6.2 Confirm execution

```
POST /erasure-requests/{id}/confirmation
```
```json
{
  "confirmations": [
    {"system": "meta-ads", "records_deleted": 88, "confirmed_by": "oidc|acme-retail|usr_9011"},
    {"system": "internal_crm", "records_deleted": 31, "confirmed_by": "oidc|acme-retail|usr_9011"}
  ],
  "derived_artifacts": [
    {"artifact": "campaign_performance_model", "disposition": "retrained_without_subject_data", "confirmed_by": "oidc|acme-retail|usr_7702"}
  ]
}
```

### 6.3 Export the evidence bundle

```
GET /erasure-requests/{id}/evidence-bundle
```
Returns a signed PDF + JSON manifest covering: receipts matched, delegations, downstream confirmations, derived-artifact dispositions, timeline, and chain-integrity verification. This is the artifact a DPO hands to a regulator.

---

## 7. Policies

### 7.1 Create a policy

```
POST /policies
```
```json
{
  "name": "marketing-ad-spend",
  "fleet": "flr_marketing",
  "effect": "allow",
  "match": {
    "actors": ["fleet:flr_marketing"],
    "actions": ["ad.credit.purchase"],
    "resources": [{"type": "ad_credit_account", "id_prefix": "acme_retail_"}]
  },
  "conditions": [
    {"type": "amount_within", "field": "resource.amount", "max": {"value": 2000, "currency": "USD"}},
    {"type": "require_approval_above", "field": "resource.amount", "threshold": {"value": 500, "currency": "USD"}},
    {"type": "time_window", "field": "context.timestamp", "start": "06:00", "end": "23:00", "timezone": "America/New_York"}
  ],
  "description": "Allow the marketing fleet to purchase ad credit up to $2000; anything above $500 needs explicit human approval."
}
```

### 7.2 Test a policy (dry run)

```
POST /policies/{policy_id}/evaluate
```
```json
{
  "actor": {"spiffe_id": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c"},
  "action": "ad.credit.purchase",
  "resource": {"type": "ad_credit_account", "id": "acme_retail_meta", "attributes": {"amount": 4500, "currency": "USD"}},
  "context": {"timestamp": "2026-11-15T14:00:00Z"}
}
```
```json
{
  "result": "allow_with_approval",
  "matched_policy": "pol_01J8XA3M5K8Q",
  "constraints": [
    {"type": "amount_within", "satisfied": false, "bound": 2000, "observed": 4500},
    {"type": "require_approval_above", "satisfied": false, "bound": 500, "observed": 4500, "resolution": "approval_required"},
    {"type": "time_window", "satisfied": true}
  ],
  "explanation": "Amount 4500 USD exceeds the 2000 USD cap; approval required above 500 USD."
}
```

**This endpoint is deliberately free and unlimited.** Policy debugging is the highest-frequency need during rollout and must not require an approval loop or a paid tier.

---

## 8. Fleets

```
GET    /fleets
GET    /fleets/{fleet_id}
POST   /fleets
PATCH  /fleets/{fleet_id}
```

A fleet is the organizational unit for policy scoping, chain depth limits, and receipt partitioning.

---

## 9. Events

### 9.1 List events

```
GET /events?type={event_type}&since={t}&until={t}&limit=100&after={cursor}
```

### 9.2 Event types

| Type | Emitted when |
|---|---|
| `agt.registered` | An agent is registered |
| `agt.attested` | Attestation succeeds; SVID bound |
| `agt.revoked` | An agent is revoked |
| `dlg.granted` | A delegation is created |
| `dlg.revoked` | A delegation is revoked |
| `apr.requested` | An approval is requested |
| `apr.decided` | An approval is decided |
| `rcp.written` | A receipt is written |
| `req.erasure_created` | An erasure request is created |
| `req.erasure_completed` | An erasure request is completed |

### 9.3 Webhook delivery

Webhooks and the attestation endpoints are designed and specified in the architecture document but not yet published — this is a reference implementation, not a stable API.

---

## 10. Error codes

Full catalogue in [`errors.md`](errors.md).

---

## 11. Rate limits

| Endpoint class | Limit | Burst |
|---|---|---|
| Write endpoints (POST/PATCH/DELETE) | 600 req/min per tenant | 1200 |
| `POST /receipts` | 6000 req/min per tenant | 12000 |
| Read endpoints | 3000 req/min per tenant | 6000 |
| `POST /policies/{id}/evaluate` | Unlimited | — |
| `GET /receipts/verify` | 60 req/min per tenant | 120 |

Exceeding returns `429` with `Retry-After`. Receipt write limits are separate because they scale with agent action volume, not human request volume.

---

## 12. Versioning and stability

- `v1` is stable. We will not make breaking changes within `v1`.
- Additive fields may appear in responses without notice. **Clients must ignore unknown fields.**
- Enum values may be added. **Clients must handle unknown enum values gracefully.**
- Deprecations are announced at least 180 days ahead via `Deprecation` and `Sunset` headers and an email to the tenant's technical contact.
- A machine-readable changelog is published at `/v1/changelog`.

---

## 13. Authentication of the control plane itself

The control plane authenticates callers via OAuth 2.1. Agents additionally present SVIDs, which are exchanged for scoped access tokens (RFC 8693). The control plane's own credentials (signing keys, SPIRE server cert, database) are held in a KMS/HSM and never exposed to tenants.

**Signing keys.** Delegation records and receipts are signed with ES256 keys. The public key set is published at `GET /v1/keys` (JWKS-like) and rotated at most annually with a published overlap window. Verification is possible offline against a cached key set — an auditor does not need our service to prove an audit record was genuine.

---

*Next: [`../security/threat-model.md`](../security/threat-model.md) · [`errors.md`](errors.md).*
