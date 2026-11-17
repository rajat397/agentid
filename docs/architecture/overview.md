# Architecture — Agent Identity & Authorization Control Plane

**Status:** Draft v0.1 (steering document)
**Product form:** Standards-based control plane (Okta-style), SaaS-delivered
**Standards implemented:** MCP · OAuth 2.1 (+ extensions) · OIDC · SPIFFE/SPIRE · SCIM · NGAC
**Primary source:** NIST NCCoE concept paper, "Accelerating the Adoption of Software and AI Agent Identity and Authorization" (DRAFT, February 2026)

---

## 1. Why this architecture exists

NIST's concept paper does not describe a product. It poses questions:

> "How can we ensure that agents log their actions and intent in a tamper-proof and verifiable manner? How do we ensure non-repudiation for agent actions and binding back to human authorization?"
> — NCCoE concept paper, p.5 (Auditing and non-repudiation)

> "What are the mechanisms for an agent to prove its authority to perform a specific action? How might an agent convey the intent of its actions? How do we handle delegation of authority for 'on behalf of' scenarios? How do we bind agent identity with human identity to support 'human-in-the-loop' authorizations?"
> — NCCoE concept paper, p.5 (Authorization)

The paper then names six standards it "is currently considering" (p.7–8): MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC. It says it "will also apply relevant guidelines from SP 800-207 Zero Trust Architecture, SP 800-63-4 Digital Identity Guidelines, NISTIR 8587 Protecting Tokens and Assertions from Forgery, Theft, and Misuse" (p.8).

**This control plane's architectural thesis: the four questions a post-incident investigation asks map one-to-one onto four standards NIST named. We implement the standards, and the questions answer themselves.**

| Investigation question | Standard that answers it | Control-plane component |
|---|---|---|
| *Which agent acted?* | SPIFFE / SPIRE — workload attestation, cryptographic identity | Agent Registry |
| *Acting for whom?* | OAuth 2.1 + token exchange (RFC 8693) — delegation chains | Delegation Service |
| *With which credential?* | SPIFFE key lifecycle + SCIM provisioning/deprovisioning | Credential Service + Provisioning |
| *Under whose approval?* | OIDC human binding + signed authorization records | Authorization Binding + Audit Ledger |

---

## 2. Design constraints

These are non-negotiable. Every architectural decision traces to one of them.

### C1 — Standards-native, not standards-inspired
NIST names the standards; we implement them. We do not invent a proprietary identity model that later has to be reconciled with MCP's OAuth dependency or SPIFFE's SVID issuance. *Rationale: NIST p.7–8 explicitly notes MCP "relies on existing identity standards such as Open Authorization (OAuth) and Open ID Connect (OIDC) for rights delegation and authentication." A proprietary model would be dead on arrival with enterprise buyers and with the NCCoE.*

### C2 — Enterprise-controlled agents only
NIST scopes the initial effort to "enterprise use-cases where greater control and visibility can be maintained over agents and the systems they access" (p.8) and explicitly excludes "external agents from untrusted sources" (p.8). Our V1 refuses to issue identities to agents the enterprise cannot attest. *Rationale: mirrors NIST scope; keeps the trust model closed; avoids the hardest unsolved problem (attesting agents you don't control) out of V1.*

### C3 — Attestation before identity
An agent does not get an identity because it asked. It gets an identity because a workload attestation proved what it is. *Rationale: SPIFFE/SPIRE's attestation model is the only one of the six named standards that answers "who is this, really" without trusting the network or the application layer.*

### C4 — Delegation is explicit, multi-hop, and linkable
Authority flows as a signed chain. Every hop is inspectable, and the chain terminates at a human principal. *Rationale: NIST p.5 asks "How do we handle delegation of authority for 'on behalf of' scenarios?" — a chain is the only structure that makes the answer reconstructable after the fact.*

### C5 — Every consequential action produces a receipt
Not every action is logged — every action **with an external effect** produces a signed, verifiable receipt that binds the actor, the authority, and the outcome. *Rationale: NIST p.7 "Logging and Transparency: Link specific AI agent and software systems actions to the identity of the non-human entity."*

### C6 — The audit ledger is independent of the agents it audits
Agents must not be able to write their own audit trail, suppress it, or edit it. *Rationale: NIST p.5 asks for logs that are "tamper-proof and verifiable." An agent-writable log is not that.*

### C7 — Open by default
Every API, every event, every schema is documented and stable. The control plane is not a black box. *Rationale: this product's entire value proposition is verifiability. A vendor that cannot show its work has forfeited the right to be trusted with audit evidence.*

---

## 3. Component architecture

```
                            ┌──────────────────────────────────────────┐
                            │          HUMAN PRINCIPALS                │
                            │   (OIDC IdP — enterprise identity)        │
                            └──────────────────┬───────────────────────┘
                                               │ OIDC authorization grant
                                               │ (human → agent delegation)
                                               ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE (our service)                          │
│                                                                              │
│  ┌────────────────┐   ┌──────────────────┐   ┌───────────────────────────┐  │
│  │ Agent Registry │◄──┤ Delegation       │◄──┤ Policy Decision Point     │  │
│  │                │   │ Service          │   │ (NGAC / Zanzibar-style   │  │
│  │ SPIFFE ID      │   │                  │   │  relation tuples)        │  │
│  │ issuance,      │   │ OAuth 2.1 token  │   │                           │  │
│  │ attestation    │   │ exchange         │   │ least privilege,          │  │
│  │ verification   │   │ (RFC 8693)       │   │ delegation chains,       │  │
│  │ lifecycle      │   │ actor/subject    │   │ context-sensitive policy  │  │
│  └───────┬────────┘   └────────┬─────────┘   └────────────┬──────────────┘  │
│          │                     │                            │                 │
│          │            ┌────────▼─────────┐                  │                 │
│          │            │ Authorization    │                  │                 │
│          │            │ Binding Service  │                  │                 │
│          │            │ (human ↔ agent)  │                  │                 │
│          │            └────────┬─────────┘                  │                 │
│          │                     │                            │                 │
│  ┌───────▼─────────────────────▼────────────────────────────▼─────────────┐  │
│  │                    Audit Ledger (append-only, hash-chained)           │  │
│  │   receipts · delegation records · authorization grants · revocations  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌────────────────────┐              ┌──────────────────────────────────┐   │
│  │ Provisioning (SCIM)│              │ Credential Service (SPIFFE keys)│   │
│  └────────────────────┘              └──────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │ attestation                       │ PEP calls
         │                                    ▼
┌────────────────────────┐   ┌──────────────────────────────────────────────┐
│  AGENT RUNTIME         │   │  POLICY ENFORCEMENT POINT (sidecar/gateway) │
│  (enterprise-deployed) │──►│  sits in front of target systems             │
│  LangGraph, CrewAI,    │   │  verifies token → calls PDP → executes       │
│  MCP client, custom    │   │  → emits receipt to ledger                   │
└────────────────────────┘   └──────────────────────┬───────────────────────┘
                                                    │
                                                    ▼
                              ┌──────────────────────────────────────┐
                              │  TARGET SYSTEMS (downstream)         │
                              │  ad platform · CRM · DB · ticket    │
                              │  · deploy pipeline · internal API    │
                              └──────────────────────────────────────┘
```

---

## 4. Component specifications

### 4.1 Agent Registry — "Which agent?"

**Responsibility:** Issue, verify, and revoke cryptographic identities for enterprise agents.

**Standard:** SPIFFE / SPIRE. An agent's identity is a SPIFFE ID of the form:

```
spiffe://{enterprise-trust-domain}/agent/{fleet}/{agent-name}/{instance-id}
```

Example: `spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c`

**Why SPIFFE and not an API key:**
- The identity is *cryptographically attested* by a workload that proves what it is (SPIRE node + workload attestation), not asserted by the caller.
- It is short-lived and rotated automatically by the SPIRE agent, which structurally eliminates the "credential left unrevoked" failure mode (NIST p.3, Authentication question).
- It binds naturally to the MCP ecosystem: MCP already relies on OAuth/OIDC for rights delegation, and SPIFFE SVIDs can be exchanged for OAuth tokens at the boundary.

**Registry responsibilities:**
1. Register agent metadata (fleet, purpose, human owner, target systems it may touch)
2. Attest workload identity → mint SVID
3. Map SVID → agent record → human owner (the "acting for whom" root)
4. Revoke on lifecycle events (decommission, human departure, anomaly)

**Key design decision:** the registry stores an explicit `human_owner` binding at registration time. Every later receipt inherits it. This means the "under whose approval" question has a default answer even for background agents, because the authority chain roots in a registered human.

### 4.2 Delegation Service — "Acting for whom?"

**Responsibility:** Represent and enforce authority chains from human principal → agent → (optionally) sub-agent.

**Standard:** OAuth 2.1 (`draft-ietf-oauth-v2-1-17`, 31 October 2026 — an
Internet-Draft, **not** a standard) for the protocol; **RFC 8707** (Resource
Indicators) to bind the intended resource server; **RFC 8693** (Token Exchange)
for `actor_token`/`subject_token`; **RFC 9700** (OAuth 2.0 Security BCP) for the
normative security requirements; plus an extension for delegation constraints.

**Delegation vs impersonation.** RFC 8693 §1.1 draws the distinction and we
deliberately use delegation semantics: under delegation, "principal A still has
its own identity separate from B, and it is explicitly understood that while B
may have delegated some of its rights to A, any actions taken are being taken
by A representing B." Under impersonation, "A is B" and the distinction is
lost — which is exactly the failure mode the retailer scenario exhibited. Our
receipts always keep the actor and the subject distinct.

**The three RFC 8693 claims we use:**

| Claim | Role | Carries constraints? |
|---|---|---|
| `sub` + `act` | The subject (human) and the current actor (agent) | No |
| nested `act` | The delegation **history** — outermost is the current actor, least recent is most deeply nested | No |
| `may_act` | "This party is authorized to become the actor and act on behalf of another party" — the pre-authorization check | No |

RFC 8693 §4.1 is explicit that `exp`, `nbf` and `aud` are "not meaningful when
used within an 'act' claim and are therefore not used." **Constraints therefore
cannot live in the token.** They live in the delegation record on the control
plane, and the token carries only a `delegation_id` reference to it.

**The MUST NOT that constrains our policy engine.** RFC 8693 §4.1: "For the
purpose of applying access control policy, the consumer of a token MUST only
consider the token's top-level claims and the party identified as the current
actor by the 'act' claim. **Prior actors identified by any nested 'act' claims
are informational only and are not to be considered in access control
decisions.**" Our PDP therefore resolves constraints from the delegation
record, never from the token's chain history. This is an implementation
constraint on the policy engine, not a citation.

**Protocol properties actually mandated by the source** (verified against
`../reference/verification-log.md` §V7.1):

| Property | Source | Strength |
|---|---|---|
| PKCE for the authorization-code grant | OAuth 2.1 §4.1.1 | MUST, with a narrow exception (§7.5.1.1): confidential client **and** reasonable assurance of proper OIDC nonce handling. Still RECOMMENDED in that case. The RFC 7636 `plain` method is explicitly prohibited. |
| Implicit grant removed | OAuth 2.1 §4 | Grant types are authorization_code, client_credentials, refresh_token, extension grants |
| `client_credentials` | OAuth 2.1 §4.2 | **Confidential clients only.** Cannot express delegation — the AS arranges cross-owner access by a method "beyond the scope of this specification", which is the gap RFC 8693 fills |
| Audience restriction | **RFC 9700 §2.3** | Access tokens **SHOULD** be audience-restricted to a specific resource server "or... a small set of resource servers". On mismatch, the resource server **MUST refuse**. Mechanisms: `aud` claim (RFC 9068), `resource` parameter (RFC 8707) |
| Sender-constrained tokens | OAuth 2.1 §1.4.3, RFC 9700 §2.1.1 | **SHOULD** — DPoP (RFC 9449) or mTLS (RFC 8705). Requiring it for write scopes is **our policy, stricter than the spec** |
| Refresh-token replay handling | **RFC 9700 §2.2.2, §4.14.2** | Required for **public clients** only: sender-constrained **or** rotation. OAuth 2.1 §4.3.3 makes rotation a **MAY**. Our agents are confidential clients, so neither is mandated — our use of rotation is a policy choice, and OAuth 2.1 §4.3.3 documents rotation's delivery-loss failure mode, which is why sender-constrained refresh tokens are the better fit for unattended fleet agents |
| Access-token validation | OAuth 2.1 §5.2 | RS **MUST** check: not expired, authorized for the requested resource, issued with the appropriate scope, and meets other RS policy requirements |
| Token types | OAuth 2.1 §5.2 | Two categories: **reference tokens** (AS lookup) and **self-encoded tokens** (encrypted and/or signed). `at+jwt` is defined by RFC 9068, not OAuth 2.1 |
| Custom scope values | OAuth 2.1 §1.4.1 | Allowed, but "avoid defining custom scopes that conflict with scopes from known extensions" — our scope names do not collide with OIDC standard scopes |

**The delegation record.** The core object. Immutable once signed:

```json
{
  "delegation_id": "dlg_01J8X2K9Q4T7W",
  "subject": {
    "type": "human",
    "id": "oidc|acme-retail|usr_8842",
    "roles": ["marketing_manager"]
  },
  "actor": {
    "type": "agent",
    "spiffe_id": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c"
  },
  "chain": [
    {
      "hop": 1,
      "from": "oidc|acme-retail|usr_8842",
      "to": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c",
      "granted_at": "2026-11-15T04:22:10Z",
      "expires_at": "2026-11-15T16:22:10Z",
      "constraints": {
        "permissions": [
          {"action": "ad.credit.purchase", "system": "meta-ads"},
          {"action": "social.post.publish", "system": "meta-ads"},
          {"action": "social.post.publish", "system": "linkedin-ads"}
        ],
        "max_amount": {"value": 2000, "currency": "USD"},
        "requires_human_approval_above": {"value": 500, "currency": "USD"}
      }
    }
  ],
  "approval": {
    "method": "oidc_implicit",
    "approved_by": "oidc|acme-retail|usr_8842",
    "approved_at": "2026-11-15T04:22:10Z",
    "acr": "urn:mace:incommon:iap:silver",
    "context": {"ip": "203.0.113.9", "user_agent": "...", "session": "..."}
  },
  "signature": {"alg": "ES256", "kid": "dlg-key-2026-04", "value": "..."}
}
```

**The four questions answered by one record:**

| Question | Field |
|---|---|
| Which agent? | `actor.spiffe_id` |
| Acting for whom? | `subject.id` + `chain[].from` |
| With which credential? | The SVID that presented the token (bound at PEP, recorded in the receipt) |
| Under whose approval? | `approval.approved_by`, `approval.approved_at`, `approval.method` |

**Delegation chaining.** If agent A delegates to agent B, the chain grows. B's
token is issued via RFC 8693 exchange of A's token, and the issued token carries
a **nested `act` claim** — outermost is the current actor, least recent actor
most deeply nested (RFC 8693 §4.1). The chain depth is bounded (V1: max 3 hops)
because unbounded chains make the reconstruction question unanswerable in
practice and the blast radius unbounded.

> **Our extension, ahead of the standard.** RFC 8693 specifies **no** chain
> depth limit, **no** constraint inheritance or intersection across hops, and
> **no** mid-chain revocation model — its security considerations are a single
> paragraph covering scope restriction and token lifetime. The depth cap and
> **constraint intersection on every hop** are ours. Constraint intersection is
> what stops a $2,000 approval becoming $6,000 across three hops: a child
> delegation's permissions must be a subset of its parent's, and its amount cap
> must be no greater. Both are candidates for the NIST feedback submission —
> a standards body with an open question, and a working answer.

**Revocation does not propagate through exchange.** RFC 8693 §2.1: the exchange
"does not create a tight linkage between the input and output tokens", and
propagating revocation events "is not a general property of the STS protocol."
So revoking a delegation does **not** kill tokens already derived from it.
Two consequences, both design rules:

1. The exchanged token must never outlive the delegation record's `expires_at`.
2. The **maximum token age** rule (Architecture §4.8) is the *primary*
   containment for delegation revocation, not a backstop for SPIRE propagation
   lag. Those are different problems; this one is larger.

**Why not just OAuth scopes?** Because scopes answer "may this token do X?" but not "under whose authority, with what constraint, approved by whom, when." NIST p.5 explicitly asks how to "convey the intent of its actions" — scopes cannot carry intent. Our delegation record carries constraints, approval context, and the chain.

### 4.3 Policy Decision Point (PDP) — "May it?"

**Standards:** **NGAC** — the Next Generation Access Control functional
architecture, ANSI/INCITS 499-2013 (NGAC–FA). NGAC is named in the NIST concept
paper (p.8). Its normative spec is paywalled and **has not been read** — our
NGAC usage is cited, not verified. **SP 800-162** (the ABAC guide, 2014)
supplies the ABAC model and the reference architecture (PDP/PEP/PAP/PIP) this
component implements, and is the document that **includes agents as subjects**:
"A subject is a human user or NPE, such as a device that issues access requests
to perform operations on objects" — with the blind spot stated in its own text,
"assume that subject and user are synonymous." That assumption is the gap.

**Model:** attribute-based access control with explicit delegation relations — Zanzibar-style tuples, because multi-hop agent delegation is inherently a relation graph.

```
<subject, relation, object, condition>

actor:spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c
  --delegated_by-->  human:oidc|acme-retail|usr_8842
  --member_of-->    fleet:marketing
  --has_role-->     role:ad_purchaser

resource:ad_credit_account:acme_retail_meta
  --owned_by-->     org:acme-retail
  --limit-->        {"max_amount": 2000, "currency": "USD"}

grant:delegation:dlg_01J8X2K9Q4T7W
  --constrains-->   action:ad.credit.purchase
  --scope-->        resource:ad_credit_account:acme_retail_meta
  --amount_cap-->   2000 USD
```

**Decision output** is a decision *plus* the constraint set that was evaluated, so the receipt can record not just "allowed" but "allowed under these constraints, which were satisfied."

**Context-sensitive policy.** NIST p.5 asks "Can authorization policies be dynamically updated when an agent context changes?" V1 supports: time-of-day, amount thresholds, system list, and `requires_human_approval_above`. Deferred: full data-sensitivity aggregation, which NIST flags as a harder open question (p.5, Authorization sub-question 2).

### 4.4 Policy Enforcement Point (PEP) — sidecar / gateway

**Placement options (pick per deployment):**

| Option | Where it runs | Best for |
|---|---|---|
| **Sidecar** | Next to the agent runtime | Custom agents (Mode 3); agent makes all outbound calls through it |
| **Gateway** | In front of target systems | Enterprise-wide policy across many agents (Mode 5/6) |
| **MCP server wrapper** | Wraps a tool server | Mode 5 — the natural choke point NIST's own MCP dependency implies |

**Execution flow (per consequential call):**

1. Agent presents SVID-derived OAuth access token
2. PEP validates token (issuer, audience, expiry, signature) — **local, no network round-trip**
3. PEP calls PDP with (subject, actor, action, resource, context) — **only if policy requires context**
4. PDP returns decision + evaluated constraints
5. PEP executes the call against the target system
6. PEP emits a **receipt** to the Audit Ledger (signed, hash-chained)
7. If the constraint set required human approval above a threshold and was exceeded → PEP **blocks** and requests approval (human-in-the-loop binding)

**Design decision — fail-closed.** If the PDP is unreachable, the PEP denies. Rationale: this is an audit and authorization control plane; a control that fails open is not a control. We do provide a documented, explicitly-configured fail-open escape hatch for read-only actions, because blocking all reads during a PDP outage is operationally unacceptable. This distinction must be recorded per-action-type.

### 4.5 Audit Ledger — the receipts

**Responsibility:** Append-only, tamper-evident record of agent actions, delegation grants, and revocations.

**Properties:**

| Property | Mechanism |
|---|---|
| **Tamper-evident** | Each receipt contains `prev_hash`; the record forms a hash chain per fleet. Recomputation detects any mutation or deletion. |
| **Independently written** | Receipts are written by the PEP to the control plane, never by the agent. C6. |
| **Verifiable offline** | Anyone holding the chain head + receipts can verify integrity without the vendor. |
| **Anchored** | Periodically anchor the chain head to an external, independently-controlled anchor (e.g. a transparency log, or customer-controlled storage). Prevents a compromised control plane from rewriting history undetectably. |

**Receipt shape:**

```json
{
  "receipt_id": "rcp_01J8X4R7M2N9P",
  "issued_at": "2026-11-15T04:41:07Z",
  "fleet": "marketing",
  "actor": {
    "spiffe_id": "spiffe://acme-retail.example/agent/marketing/marketing-agent/7f3a2b1c"
  },
  "delegation_id": "dlg_01J8X2K9Q4T7W",
  "action": "ad.credit.purchase",
  "resource": {
    "type": "ad_credit_account",
    "id": "acme_retail_meta",
    "attributes": {"amount": 2000, "currency": "USD"}
  },
  "decision": {
    "result": "allowed",
    "constraints_evaluated": [
      {"constraint": "amount_cap", "bound": 2000, "observed": 2000, "satisfied": true},
      {"constraint": "requires_human_approval_above", "bound": 500, "observed": 2000, "satisfied": false, "resolution": "approval_obtained", "approval_ref": "apr_01J8X3Q1"}
    ]
  },
  "outcome": {"status": "succeeded", "external_ref": "meta_ad_order_993812"}
  ,
  "prev_hash": "sha256:b41c...",
  "hash": "sha256:9df2..."
}
```

**The three questions this record answers that the old log did not:**

Old agent log: `{"task": "promote campaign", "status": "completed"}`

Our receipt: *which agent* (spiffe_id), *acting for whom* (via delegation_id → subject), *with which credential* (SVID kid recorded in the delegation binding), *under whose approval* (constraint resolution → `approval_ref` → approval record), *what it touched* (resource + external_ref + outcome).

### 4.6 Authorization Binding Service — "Under whose approval?"

**Responsibility:** Capture and preserve the evidence of human approval, and bind it to agent actions that exceed a threshold or match a flagged policy.

**Sources of approval evidence (V1):**
- OIDC authorization grant (user authenticated and consented) — ACR, auth_time, session id
- Explicit approval endpoint (PEP requests approval; human approves via an approval surface; approval is signed)
- Policy-mediated approval (a second agent authorized to approve, within its own constraints)

**Binding mechanics:** the approval reference is embedded in the receipt's constraint resolution, and the approval record itself carries the delegation it was granted under. When the constraint was exceeded, the receipt shows both: the constraint, and the approval that satisfied it. This is what makes "under whose approval" answerable rather than merely asserted.

**Explicit non-goal for V1:** building an approval UI. V1 integrates with the enterprise's existing IdP and, where a separate approval surface is needed, exposes a minimal approval API and expects the customer's own workflow tool (Slack, Jira, ServiceNow) to call it. Building a workflow product is a different company.

### 4.7 Provisioning — SCIM

**Responsibility:** Agent identity lifecycle across the enterprise's systems — provisioning, deprovisioning, and revocation.

**Standard:** SCIM 2.0 (RFC 7643/7644).

**Why SCIM:** NIST p.8 notes SCIM "does not provide authentication or authorization, it does provide a potential way to create, update and revoke agent identities across systems." It is the lifecycle plane, not the decision plane.

**V1 scope:** create / deactivate / delete agent records; group agents into fleets; propagate to connected target systems that support SCIM (Okta, Entra, Google Workspace).

**The lifecycle rule that matters:** when an agent is revoked, the Credential Service must invalidate its SVID within one rotation interval, and the PEP must reject any in-flight token bearing that SVID. This is the direct answer to NIST p.3's "issuance, update, and revocation" question — and to our failure mode #4.

### 4.8 Credential Service — SPIFFE/SPIRE

**Responsibility:** mint, rotate, and revoke SVIDs; maintain the attestation chain.

**SPIRE topology:** SPIRE Server (control plane) + SPIRE Agent (node agent, runs beside the workload). Workload attestation via node + workload selectors (e.g. k8s service account, unix uid, container image digest).

**Rotation:** SVID TTL is short (V1 default: 15 minutes, agent workload selector permitting). Revocation is via the SPIRE Server's revocation list, which the PEP consults via the token validation path.

**The honest limitation (documented, not hidden):** SPIRE revocation lists require either a push (server → agent) or a pull (agent → server). In a partitioned network, revocation can lag by up to the propagation interval. Our PEP therefore enforces a **maximum token age** independent of the credential TTL, so a revoked agent's already-issued access token dies on a bounded clock. This is a deliberate design choice to bound the revocation-lag exposure, and it is documented here rather than claimed away.

---

## 5. End-to-end flows

### 5.1 Provisioning an agent (Mode 3/5/6 fleet onboarding)

```
Admin (human)
  │  SCIM: POST /Users {userName: "marketing-agent", externalId: "agent-042"}
  ▼
Provisioning ──creates──▶ Agent Registry record (status=pending, human_owner=usr_8842)
  │
  │  workload starts, calls SPIRE Agent ──attestation──▶ SPIRE Server
  │  SPIRE Server mints SVID ──▶ workload
  ▼
Agent Registry: attestation matches registered selector ──▶ status=active, SVID bound
  │
  ▼
Admin grants delegation in control plane UI/API:
  POST /delegations {subject, actor, constraints, requires_human_approval_above}
  │
  ▼
Authorization Binding captures OIDC consent (ACR, auth_time) ──▶ delegation record signed
```

### 5.2 Agent takes a consequential action

```
Agent needs to call ad platform
  │  RFC 8693 token exchange:
  │  subject_token = SVID, actor_token = current delegation token
  ▼
Delegation Service issues constrained access token
  │  (audience = ad platform, scopes = ad.credit.purchase,
  │   includes delegation_id + constraint digest)
  ▼
Agent calls ad platform through PEP (sidecar)
  │
  ▼
PEP validates token locally (iss, aud, exp, sig, delegation_id known)
  │
  ▼
PEP → PDP: evaluate(subject, actor, action, resource, context)
  │
  ├─ decision=deny ──▶ PEP returns 403, writes receipt(result=denied), done
  │
  └─ decision=allow + constraints
       │
       ├─ all constraints satisfied ──▶ execute, write receipt(result=allowed)
       │
       └─ constraint requires approval, threshold exceeded
            │  PEP → Authorization Binding → approval request
            │  human approves (OIDC / approval API)
            │  approval_ref returned
            ▼
         execute, write receipt(result=allowed, constraint resolution=approval_obtained)
```

### 5.3 Post-incident investigation — the four questions

**Question 1: "Which agent made the purchase?"**
```
GET /receipts?resource=ad_credit_account:acme_retail_meta&action=ad.credit.purchase&since=...
→ receipt.actor.spiffe_id
→ Agent Registry lookup → fleet, version, human owner
```

**Question 2: "Acting for whom?"**
```
GET /delegations/{delegation_id}
→ subject.id (human principal), chain[] (full delegation path)
```

**Question 3: "With which credential?"**
```
Receipt records the SVID key identifier that presented the token
→ Credential Service: was this SVID valid at issued_at? was it revoked before?
→ Provisioning: was this agent's record active at the time?
```

**Question 4: "Under whose approval?"**
```
Receipt.decision.constraints_evaluated[]
  → constraint=requires_human_approval_above, satisfied=false, resolution=approval_obtained
  → approval_ref → GET /approvals/{approval_ref}
      → approved_by (human), approved_at, method, context
```

**And the fifth question the old log could not answer: "What else did it touch during that window?"**
```
GET /receipts?fleet=marketing&since=<t-19h>&until=<t>
→ every action by that fleet in the window, correlated by delegation_id
```

That last capability is the one that turns an investigation from "hours of lost time and a stalled sign-off" into a single query. It is the operational payoff of the whole design.

### 5.4 Right to be forgotten — agent-collected personal data

This is the flow that connects the identity plane to the compliance plane. It is the hardest flow in the system and the one we will build first as a pilot, because it is where the business value is most legible (a legal deadline, not a fuzzy risk metric).

```
Data subject request (GDPR Art.17) arrives
  │
  ▼
Compliance API: POST /erasure-requests {subject: "customer_4471"}
  │
  ▼
Control plane enumerates:
  1. Which agents touched this subject's data?
     → Ledger index: receipts where resource.attributes.personal_data contains subject
  2. Which delegations authorized those actions?
     → receipt.delegation_id → delegation record → subject human principal
  3. What derived data exists?
     → customer-supplied data-source registry (what downstream systems hold this data)
  │
  ▼
Erasure plan generated:
  {receipts: [...], delegations: [...], downstream_systems: [...], derived_artifacts: [...]}
  │
  ▼
Execution:
  - Delete/re-anchor in customer systems (via customer's own connectors)
  - Delete derived artifacts per customer's retention policy mapping
  - Record erasure completion as a receipt (an action by the control plane, itself audited)
  │
  ▼
Deadline tracking: GDPR Art.12 requires response within one month
  → control plane tracks, escalates, and produces an evidence bundle
```

**Key design decision:** the control plane does not itself hold customer data. It holds **indexes and references**. The customer's systems remain the system of record. This keeps us out of the data-protection liability class entirely while still letting us answer "which agents touched this data, under whose authority, and what must be deleted."

---

## 6. What V1 deliberately does not do

Stated plainly, because a north-star document that hides its edges is not a north star.

| Deferred | Reason |
|---|---|
| External / untrusted agents | NIST explicitly excludes them from the initial effort (p.8). Different trust model, different threat model. |
| RAG / LLM-only architectures | NIST explicitly excludes them (p.6). |
| Cross-org agent-to-agent delegation | Requires federation we cannot yet attest. V1 is single-trust-domain. |
| Full data-sensitivity aggregation policy | NIST flags it as an open question with open sub-questions (p.5). We ship thresholds, not inference. |
| Browser / computer-use agents (Mode 4) | Action trails are screenshots and clicks; reconstructing structured receipts requires a different instrumentation strategy. NIST p.5's logging question applies, but the solution is not the same. |
| Approval UI / workflow product | Deliberately out of scope. Integrate with the customer's existing workflow tooling. |
| In-house PKI | We consume SPIFFE/SPIRE rather than reimplementing attestation. |

---

## 7. Open architectural questions

These are unresolved and need answers before V1 scope is locked.

| # | Question | Why it matters | How we resolve it |
|---|---|---|---|
| Q1 | Is the PDP a single service or per-fleet? | Latency on every action vs. isolation between fleets | Benchmark; likely single service with per-fleet policy isolation |
| Q2 | What is the receipt retention model? | GDPR minimization vs. audit defensibility | Default 13 months, customer-configurable; receipts themselves contain pseudonymous references, not personal data, by default |
| Q3 | How do we anchor the hash chain without becoming a trusted third party? | Anchoring to ourselves defeats the purpose | Customer-selectable anchor (transparency log, customer bucket); document the trust assumptions either way |
| Q4 | Does a human approval need to be synchronous? | Synchronous blocks the agent; asynchronous creates a TOCTOU window between approval and action | V1: synchronous for amounts over threshold. Revisit with pilot data. |
| Q5 | What happens when the control plane is down? | Fail-closed blocks all agent activity; fail-open defeats the control | Fail-closed by default; explicitly-configured fail-open for read-only action types only |
| Q6 | Multi-hop delegation depth limit | Deeper chains = larger blast radius and harder reconstruction | V1: 3 hops max; pilot data to revisit |
| Q7 | How are agent versions distinguished? | "Which agent" is insufficient if the agent changed between grant and action | Include build/version digest in SVID selector; receipts reference the version |
| Q8 | What is the PDP's combining algorithm? | With multiple policies per fleet and an explicit deny, resolution order is undefined. ABAC treats rule- and policy-combining algorithms as a core element (SP 800-162 §3). **Default should be deny-overrides**, which also matches the fail-closed posture — but it is not yet specified, and an unspecified PDP is an implementation waiting to diverge | **Must be specified before V1 freeze.** Newly surfaced by V7.6 |
| Q9 | Should we adopt a token status list instead of max-token-age containment? | NISTIR 8587 §5.3.1.2 points at the IETF Token Status List and the Global Token Revocation drafts for faster revocation. Our max-token-age rule is the fallback NIST prescribes for stateless implementations. Both are Internet-Drafts in development | V1.1 decision; track both drafts |

---

## 8. Citation index

The standards-to-NIST mapping is in [`../reference/standards-matrix.md`](../reference/standards-matrix.md).

| Claim in this document | Source |
|---|---|
| Agentic architecture definition; RAG and LLM-only out of scope | NCCoE concept paper, p.6 |
| Authentication open questions (strong auth, key management, issuance/update/revocation) | NCCoE concept paper, p.3 |
| Authorization open questions (zero-trust, dynamic policy, least privilege, proving authority, conveying intent, delegation, human binding) | NCCoE concept paper, p.4 |
| Auditing and non-repudiation open questions | NCCoE concept paper, p.5 |
| Prompt injection open questions | NCCoE concept paper, p.5 |
| Enterprise focus; external untrusted agents excluded | NCCoE concept paper, p.8 |
| Areas of interest: identification, authorization, access delegation, logging and transparency, data-flow tracking | NCCoE concept paper, p.7 |
| Standards considered: MCP, OAuth 2.0/2.1, OIDC, SPIFFE/SPIRE, SCIM, NGAC | NCCoE concept paper, p.7–8 |
| SP 800-207, SP 800-63-4, NISTIR 8587 referenced | NCCoE concept paper, p.8 |
| Comment deadline April 2, 2026; possible draft project description and call for collaborators | NCCoE concept paper, p.1, p.9 |
