# Standards Matrix — NIST NCCoE Concept Paper → Our Implementation

**Status:** Draft v0.1 (steering document)
**Source:** NCCoE, "Accelerating the Adoption of Software and AI Agent Identity and Authorization," DRAFT, February 2026.

This document is the credibility anchor for the project. It demonstrates, line by line, that every architectural decision traces to something NIST actually wrote — and it exposes, honestly, where we are *not* yet aligned.

---

## 1. How to read this matrix

Each row is a direct statement from the concept paper, with its page reference, followed by our implementation decision and its status.

**Status values:**
- **Implemented** — built and verified by a mutant condition
- **Partially implemented** — mechanism exists but does not cover the full NIST question
- **Planned** — scoped, not built
- **Deferred** — deliberately out of V1, with reason
- **Open** — NIST question we have not solved; tracked as a research item

---

## 2. The four open-question categories (p.3–5)

NIST poses six numbered question groups. These are the open problems.

### 2.1 Identification (p.3)

| # | NIST question | Our implementation | Status |
|---|---|---|---|
| I.1 | "How might we identify AI and software agents?" (Areas of Interest, p.7) | SPIFFE ID per agent instance: `spiffe://{domain}/agent/{fleet}/{name}/{instance}`. Issued only after SPIRE workload attestation matches a registered selector. Registry maps SVID → agent record → fleet → human owner. | **Implemented** |
| I.2 | "How do we ensure that access management systems can distinguish between agent and human identities?" (p.7) | Distinct token types and distinct subject types: `human` (OIDC subject) vs `agent` (SPIFFE ID). PEP and PDP reject the wrong type for the operation. Authorization records carry `subject.type` and `actor.type` explicitly. | **Implemented** |
| I.3 | Agent identity versioning — *our addition, not NIST's* | Agent build/version digest is part of the attestation selector; receipts reference the version, not just the agent name. "Which agent" is not sufficient if the agent changed between grant and action. | **Implemented** |

### 2.2 Authentication (p.3)

| # | NIST question | Our implementation | Status |
|---|---|---|---|
| A.1 | "What constitutes a strong authentication for an AI agent?" | Workload attestation (SPIFFE/SPIRE) — identity is proven cryptographically by the workload, not asserted by a bearer token. Proof-of-possession (mTLS-bound `cnf` claim) required for write scopes. | **Implemented** |
| A.2 | "How do we handle key management for agents?" | Central Credential Service. Keys are non-exportable, held in KMS/HSM, rotated automatically. Agents never hold long-lived secrets. | **Implemented** |
| A.3 | "Issuance, update, and revocation?" | Issuance: attestation-matched SVID mint. Update: automatic rotation on a ≤15-minute interval. Revocation: `POST /agents/{id}/revocation` invalidates SVID, outstanding tokens, and all active delegations in one call. SCIM propagates to connected customer systems. | **Implemented** |
| A.4 | Revocation propagation lag — *our addition* | SPIRE revocation lists propagate (push or pull) and may lag. Mitigation: PEP enforces a maximum token age independent of SVID TTL, bounding exposure to a known interval. Documented in Architecture §4.8 rather than claimed away. | **Implemented** |

### 2.3 Authorization (p.4)

NIST's seven authorization sub-questions, mapped one-to-one. This is the densest alignment in the project.

| # | NIST question (p.4) | Our implementation | Status |
|---|---|---|---|
| Z.1 | "How can zero-trust principles be applied to agent authorization?" | SP 800-207 is explicitly cited by NIST (p.8). Tenet-by-tenet mapping in §4a below. Summary: no implicit trust from network location (tenet 2); per-session grant with least privilege and no cross-resource leakage (tenet 3); dynamic policy over observable identity and context (tenet 4); no asset inherently trusted, posture evaluated per request (tenet 5); dynamic, strictly enforced, cryptographically strong authorization with event-driven re-evaluation (tenet 6). **Our evaluation is per-action, which is stricter than the tenet's per-session baseline** — a deliberate choice, recorded so an auditor checking against the tenet finds a documented difference rather than a discrepancy. | **Implemented, stricter than the source requires** |
| Z.2 | "Can authorization policies be dynamically updated when an agent context changes?" | NGAC supports event-driven policy updates (p.8) and we use that: policy changes take effect on the next action without re-issuing delegations. V1 context dimensions: time window, amount threshold, resource, approval threshold. Matching is against explicit (action, system) permission pairs, not against independent action and system lists (see V7.2 — RFC 8693 §2.1.1 makes the independent-list form a Cartesian product). | **Partially implemented** |
| Z.3 | "How do we determine sensitivity levels of data when aggregated by an agent, and whether users are authorized to access the aggregated response?" | **Not solved.** Requires inference over aggregate content, which we cannot evaluate at the authorization layer. We expose `personal_data_refs` so aggregation can be detected post-hoc, but do not gate on it pre-emptively. | **Open** |
| Z.4 | "How do we establish 'least privilege' for an agent, especially when its required actions might not be fully predictable when deployed?" | Constraints are mandatory on every delegation — an unbounded grant is rejected at the API (`400 constraints_required`). For unpredictable actions, the requester must specify an action allowlist and a numeric cap; anything exceeding the cap requires fresh human approval. This converts "least privilege under uncertainty" into "least privilege with a hard ceiling and a human at the boundary." | **Implemented** |
| Z.5 | "What are the mechanisms for an agent to prove its authority to perform a specific action?" | Delegation record: signed, chained, constraint-bearing. Presented as an OAuth 2.1 access token via RFC 8693 exchange, bound to the actor's SVID. PEP validates authority locally; PDP confirms against live policy. Receipts record the delegation ID that authorized each action. | **Implemented** |
| Z.6 | "How might an agent convey the intent of its actions?" | Constraint sets carry intent (allowed actions, systems, amounts, time windows). The action name itself (`ad.credit.purchase`) is part of the signed record. V1 carries **structured intent**; natural-language intent declaration is not implemented. | **Partially implemented** |
| Z.7 | "How do we handle delegation of authority for 'on behalf of' scenarios?" | RFC 8693 token exchange with explicit `subject_token` (human) + `actor_token` (agent). Delegation semantics, not impersonation (RFC 8693 §1.1). Chain carried as **nested `act` claims** (RFC 8693 §4.1); pre-authorization via `may_act` (§4.4); constraints resolve from the control-plane delegation record, never from token chain history (§4.1 MUST NOT). Depth capped at 3 and **constraint intersection on every hop** — **both our extensions; RFC 8693 specifies neither** (its security considerations are one paragraph). | **Implemented, ahead of the standard on chain constraints** |
| Z.8 | "How do we bind agent identity with human identity to support 'human-in-the-loop' authorizations?" | OIDC-mediated consent at delegation creation captures approver identity, ACR, auth_time, session context. Over-threshold actions require a fresh approval bound to a specific delegation + amount + nonce. `approval_ref` appears in the receipt's constraint resolution. | **Implemented** |

### 2.4 Auditing and non-repudiation (p.5)

| # | NIST question | Our implementation | Status |
|---|---|---|---|
| L.1 | "How can we ensure that agents log their actions and intent in a tamper-proof and verifiable manner?" | Append-only, hash-chained ledger per fleet. Agents never write it — the PEP does. Chain head externally anchorable. `GET /receipts/verify` recomputes and reports; offline verification supported against a published key set. | **Implemented** |
| L.2 | "How do we ensure non-repudiation for agent actions and binding back to human authorization?" | Every receipt references a `delegation_id`; every delegation references an `approval` record; every approval records who approved, when, method, and context. The chain is hash-linked so no link can be silently broken. | **Implemented** |
| L.3 | Tamper-evidence vs. tamper-proofing — *our honest framing* | We deliver **tamper-evidence with external anchoring**, not tamper-proofing in the absolute sense. A fully compromised control plane could rewrite unanchored history; anchoring prevents that from being undetectable. This distinction is stated in every customer-facing artifact. | **Implemented** |
| L.4 | Log intent, not just action | Receipts carry the action type, resource attributes, constraint evaluations, and outcome. The delegation carries the authorized intent. Both are retained. | **Implemented** |

### 2.5 Prompt injection prevention and mitigation (p.6)

| # | NIST question | Our implementation | Status |
|---|---|---|---|
| P.1 | "What controls help prevent both direct and indirect prompt injections?" | **Not our layer.** Injection prevention belongs to model and prompt-layer defenses. We do not claim to prevent it. | **Deferred** |
| P.2 | "After prompt injection occurs, what controls/practices can minimize the impact of the injection?" | This is the load-bearing NIST question for us. Impact minimization is achieved by: hard numeric caps, mandatory human approval above threshold, action and system allowlists, delegation expiry, and detection via receipt analysis (flagging actions whose initiating input traces to untrusted content). | **Implemented** |
| P.3 | Injection-aware detection — *our extension* | Receipts record the action's initiating context. Where the customer's systems tag inputs as untrusted (e.g. support tickets), the control plane can flag receipts whose authority was exercised on untrusted-origin data without approval. | **Planned** |

---

## 3. The four Areas of Interest (p.7)

| Area of Interest (NIST p.7, quoted) | Our implementation | Status |
|---|---|---|
| **"Identification of AI and Software Systems."** "Explore available means to identify software and AI agents such that access management systems can distinguish between agent and human identities and effectively manage the range of actions an agent may take from controlled human-in-the-loop approval to autonomous action in response to an input." | SPIFFE identification; distinct agent/human subject types; the full action range from human-in-the-loop to autonomous-response is supported by the same delegation model — the difference is whether `approval.approved_at` precedes the action or a threshold-triggered approval is inserted mid-flight. | **Implemented** |
| **"Authorization of AI Systems."** "Leveraging standards such as OAuth 2.0 and its extensions and policy-based access control mechanisms, to manage how rights and entitlements are granted to software and AI agents and to enforce access decisions based on the identity of the AI agent." | OAuth 2.1 + RFC 8693 for rights; NGAC for policy-based access control; PEP enforces decisions keyed on agent identity. | **Implemented** |
| **"Access Delegation."** "Link specific user identities to AI agents or software systems to support effective delegation controls and maintain accountability for the actions of automated systems." | The delegation record is literally this: a signed link from a specific user identity to a specific agent, carrying effective delegation controls, and maintained in a ledger that holds the agent accountable for its actions. | **Implemented** |
| **"Logging and Transparency."** "Link specific AI agent and software systems actions to the identity of the non-human entity and enable effective visibility into the actions taken, data generated, and outcomes of automated activities within a given system, platform, or network." | Receipts link action → non-human identity → delegation → human → approval → outcome, plus a `POST /receipts` query surface for the "visibility into actions taken, data generated, and outcomes" requirement. | **Implemented** |
| **"Tracking Data Flows of an AI System."** "Track and maintain provenance of user prompts and data input sources to support risk determinations and policy decisions regarding actions to be taken by an AI Agent." | `personal_data_refs` on resources, plus the customer's data-source registry, give provenance from data subject → agent action → downstream system. This is the mechanism behind the erasure workflow. | **Implemented** |

---

## 4. The standards NIST names (p.7–8)

NIST lists six standards it "is currently considering." We implement all six. This table is the direct answer to "what did you actually build?"

| NIST-named standard | NIST's stated role (p.7–8) | Our use | Status |
|---|---|---|---|
| **Model Context Protocol (MCP)** | "A protocol that enables AI models and agentic systems to discover, access, and interact with external tools, data sources, and services in a consistent and structured manner. The MCP protocol relies on existing identity standards such as OAuth and OIDC for rights delegation and authentication." | Our primary integration surface. PEP wraps MCP tool servers so every tool call is authorized and receipted. We rely on MCP's existing OAuth dependency rather than layering a parallel auth path. | **Planned** (V1.1) — the PEP-as-MCP-wrapper is the highest-value integration |
| **OAuth 2.0/2.1 + extensions** | "An authorization standard that can be used to support access control objectives... At this time, OAuth is integrated into the MCP as the primary method for authorizing agentic access. The specification follows the draft OAuth 2.1 standard." | The access-token plane. Verified against `draft-ietf-oauth-v2-1-17` (31 Oct 2026 — an Internet-Draft, **not a standard**) and RFC 9700: PKCE REQUIRED for the authorization-code grant with one narrow exception (§7.5.1.1); implicit grant removed; `client_credentials` restricted to confidential clients and unable to express delegation (hence RFC 8693); token types are *reference* and *self-encoded* (§5.2) with `at+jwt` defined by RFC 9068; audience restriction is a SHOULD with a MUST-refuse on mismatch (RFC 9700 §2.3); sender-constraining is a SHOULD, required-for-write-scopes is our stricter policy; refresh-token replay handling is required for public clients only. See `verification-log.md` §V7.1. | **Implemented** |
| **OpenID Connect (OIDC)** | "An interoperable authentication protocol... provides a consistent way for expressing authentication, consent, and authorization information through identity tokens that can support access outcomes related to Agents or users when interacting with Agents." | The human-identity plane. OIDC is how we (a) authenticate the human who grants a delegation, (b) capture consent evidence, (c) bind agent identity to human identity, and (d) implement human-in-the-loop approval. | **Implemented** |
| **ANSI/INCITS 499-2013 (NGAC–FA)** | **Not named by NIST's concept paper by designation**, but "NGAC" is named at p.8 and SP 800-162 cites NGAC's normative spec as [ANSI499]. **NGAC–FA is paywalled and has NOT been read.** Our NGAC usage is therefore *cited, not verified* | Cited, **not verified** (paywalled) |
| **NIST SP 800-162** (ABAC guide) | Not named by the concept paper, but supplies the ABAC model and reference architecture our policy plane is built on. Provides PDP/PEP/PAP/PIP naming, and includes NPEs as ABAC subjects | Implemented; **combining algorithm gap — open question Q8** |
| **SPIFFE / SPIRE** | "A framework for issuing and managing cryptographic identities to workloads and SPIRE Runtime Environment (SPIRE) is an implementation of SPIFFE that provides APIs for workload attestation. Together they represent one way in which agent workloads could be identified and authenticated." | The workload-identity plane. SPIFFE ID = agent identity. SPIRE = attestation, rotation, revocation. | **Implemented** |
| **SCIM** | "A standard that defines RESTful APIs and JSON schemas for automating the provisioning, deprovisioning, and lifecycle management of identities across systems. While SCIM does not provide authentication or authorization, it does provide a potential way to create, update and revoke agent identities across systems." | The lifecycle plane. Agent create / deactivate / delete; fleet grouping; propagation of revocation to connected customer systems. | **Implemented** |
| **NGAC** | "An attribute-based access control standard that represents access control policies in a unified graph of users, objects, attributes, and policy classes... NGAC also supports event driven policy updates, native delegation and least privilege making it suitable for agentic systems." | The policy plane. Zanzibar-style relation tuples, explicit delegation relations, event-driven policy updates. NGAC's "native delegation" is exactly what multi-hop agent authority needs. **Attribution note: NGAC's normative spec is ANSI/INCITS 499-2013 (NGAC–FA), not SP 800-162 — see the row above. Our NGAC usage is cited, not verified.** | **Implemented on an unverified base; combining algorithm undefined (Q8)** |

### Also referenced by NIST (p.8)

| NIST reference | Our alignment |
|---|---|
| **NIST SP 800-207 Zero Trust Architecture** | Architecture principles (§2.1 tenets, mapped in §4a) **and the primary grounding for our threat model** (§5.7, which names the attacker-coerces-an-agent and agent-impersonation threats explicitly). Note: the tenet's grant baseline is per-session with event-driven re-evaluation; our implementation evaluates per action, which is stricter — recorded rather than implied. |
| **NIST SP 800-63-4 Digital Identity Guidelines** | **Human identity plane only.** §1.1: "For this publication, 'person' refers only to natural persons" and these guidelines "do not explicitly address some subjects... including, but not limited to, machine-to-machine authentication, interconnected devices (e.g., IoT devices), or **access to Application Programming Interfaces (APIs) on behalf of subjects**." Our agent identity plane is therefore **outside this guideline's scope by its own terms** — which is precisely why the 2026 concept paper exists. We use it for the customer's IdP integration: federation is **FAL**-governed (§3.3.2.3; FAL2 covers assertion-injection attacks, relevant to our approval binding), the human's authentication is **AAL**-governed, and `acr` is the OpenID Connect Core carrier for that assurance level (SP 800-63-4 does not define ACR). |
| **NISTIR 8587 Protecting Tokens and Assertions from Forgery, Theft, and Misuse** | **§5.3.1.6 Workload Protections** — "Workload identities — including non-person entities, automated services, and machine-to-machine processes — MUST use tightly scoped, short-lived tokens... and SHOULD use sender-constrained mechanisms (e.g., mTLS, DPoP) whenever feasible. **Incorporating SPIFFE-based workload identities strengthens this model** by eliminating long-lived static credentials altogether." This is our workload-identity plane, specified by NIST. **§5.3.1.5 Token Protection** — "All tokens MUST be strictly protected from exposure in system logs, CI/CD pipelines... Any detected exposure of tokens should be treated as a security incident" (grounding for Mutant M1). **§5.2.1.1 Assertion and Token Contents** — seven mandatory contents: issuer identifier, subject/client identifier, audience identifier, issuance time, validity time window, assertion or token identifier or nonce (replay prevention), authentication time. **§5.3.1.2 Token Revocation** — "when short-lived access tokens are coupled with refresh tokens or reauthentication requirements, CSPs and agencies can substantially limit the time for which a compromised token is valid" (grounding for max token age as primary containment). **Note: §1.1.1 excludes AI agent access risks from scope** — "NIST and CISA recognize this gap". |

### 4a. SP 800-207 tenet-by-tenet mapping

NIST cites SP 800-207 as a guideline it "will also apply" (concept paper, p.8).
We map each tenet to our implementation, with the honest gap where we are
stricter or narrower than the source.

| Tenet (SP 800-207 §2.1) | Source language | Our implementation | Status |
|---|---|---|---|
| **1** — All data sources and computing services are resources | "an enterprise may decide to classify personally owned devices as resources if they can access enterprise-owned resources" | Every agent, agent fleet, credential, and policy is a registered resource | Implemented |
| **2** — All communication secured regardless of network location | "Network location alone does not imply trust... trust should not be automatically granted based on the device being on enterprise network infrastructure" | No implicit trust from network position. An agent inside the enterprise network gets the same evaluation as one outside it | Implemented |
| **3** — Access granted on a **per-session** basis, least privilege | "This could mean only 'sometime recently'... and may not occur directly before initiating a session or performing a transaction with a resource." "authentication and authorization to one resource will not automatically grant access to a different resource" | We grant per **delegation record**, with an expiry, and evaluate per **action** — stricter than per-session. Cross-resource isolation is enforced by audience restriction and by explicit (action, system) permission pairs | Implemented, **stricter than the source** |
| **4** — Access determined by dynamic policy over observable state | "client identity can include the user account (or service identity) and any associated attributes assigned by the enterprise to that account or artifacts to authenticate automated tasks" | Delegation constraints + request context (time, amount, system) drive the decision. The SPIFFE SVID is the "artifact to authenticate automated tasks" | Implemented |
| **5** — No asset is inherently trusted; posture evaluated per request | "The enterprise evaluates the security posture of the asset when evaluating a resource request" | Architecture constraint C3: attestation before identity. An agent that has not attested has no identity to act under | Implemented |
| **6** — Authentication/authorization dynamic, strictly enforced, cryptographically strong | Re-authentication triggers: "time-based, new resource requested, **resource modification**, anomalous subject activity detected" | Cryptographically strong (ES256, RFC 9068 `at+jwt`, mTLS/DPoP). `requires_human_approval_above` **is an instance of the source's "resource modification" trigger**. We evaluate on every action rather than only on trigger events | Implemented, **stricter than the source** |
| **7** — Collect information about current state to improve posture | "This data can also be used to provide context for access requests from subjects" | Receipt ledger is the state collection; anomaly detection over receipt patterns is our open item (threat model S6) | Partial |
| **Scope limit** | "These tenets apply to work done within an organization... and not to anonymous public or consumer-facing business processes" | Enterprise-controlled agents only. Consistent with the concept paper's own scope | Implemented |

### Dependencies NIST did not name, but we track

OAuth 2.1 inherits most of its normative *security* requirements from RFC 9700
(the OAuth 2.0 Security Best Current Practice), which NIST's concept paper does
not name. Three of our earlier citations attributed RFC 9700's requirements to
OAuth 2.1 itself. Corrected in `verification-log.md` §V7.1.

| Standard | Why we track it | Status |
|---|---|---|
| **RFC 9700** — OAuth 2.0 Security BCP | Source of the audience-restriction, sender-constraining, refresh-token-replay and privilege-restriction requirements that OAuth 2.1 inherits | Implemented |
| **RFC 8707** — Resource Indicators | Mechanism for telling the AS the intended resource server (`resource` parameter) | Implemented |
| **RFC 9068** — JWT Profile for Access Tokens | Defines `at+jwt` and the `aud` claim | Implemented |
| **RFC 7800** — Proof of Possession (`cnf` claim) | Defines `cnf.x5t#S256` (mTLS) and `cnf.jkt` (DPoP) | Implemented |
| **RFC 9449 / RFC 8705** — DPoP / mTLS | Sender-constraining mechanisms | Implemented |
| **RAG and LLM-only architectures out of scope (p.6)** | We explicitly refuse to issue identities to RAG-only or LLM-only architectures in V1. |
| **External untrusted agents out of scope (p.8)** | We do not attest agents outside the customer trust domain. |

---

## 5. The three NIST use cases (p.8)

| NIST use case (p.8) | Our coverage | Notes |
|---|---|---|
| **Enterprise AI agents to improve workforce efficiency and decision making** — "agents and software will need delegated and managed access to multiple data sources to take actions based on user prompts or inputs" | Full | This is the primary V1 target: agents with delegated, managed access to multiple data sources. The delegation + constraint + receipt model is designed for exactly this. |
| **Enterprise AI agents for security** — "analyze security information and either take or recommend security actions... with an elevated risk due to the sensitivity of security data" | Full | Same primitives, stricter policies. This use case drives the `requires_human_approval_above` default for privileged actions. |
| **Enterprise AI agents for software development and deployment** — "how entitlements and authorization are supported in automated deployment pipelines that use AI Agents" | Partial | Agent-driven deployment is supported by the same model. The gap: deployment pipelines need **pipeline-stage** semantics (this agent may deploy to staging but not production) which we express as system allowlists rather than as first-class pipeline stages. Planned. |

---

## 6. Desired outcomes (p.8) and how we participate

NIST's stated desired outcomes (p.8, lines 183–193):

| NIST desired outcome | Our participation |
|---|---|
| "Provide a better understanding of how agents can be deployed in line with identity and authorization standards and best practices to help agencies and enterprise maximize value and minimize risk" | We publish a reference implementation and pilot findings. |
| "Create relationships and mechanisms to provide feedback to standards development entities as they advance and evolve standards in the agentic ecosystem" | We submit implementation-derived feedback to AI-Identity@nist.gov. Our open-question answers (Z.3, P.1, S2) are the specific items we can contribute evidence on. |
| "Identify and communicate risks and opportunities associated with real-world deployments of Agentic AI solutions" | Pilot findings, published, including negative results. |
| "Provide detailed implementation resources that can enable more rapid adoption of agentic technology" | Our documentation set *is* the implementation resource. |

NIST's final deliverable (p.8, line 182): "the ultimate deliverable will be a practice guide detailing example implementation details built in the NCCoE laboratories using commercially available technologies."

**Our position:** we intend to be a candidate source of implementation detail for that practice guide, and to submit the pilot evidence that informs it. NIST states community input "will inform subsequent project planning activities, which could include development of a draft project description and a call for collaborators" (p.1).

**Unverified status:** as of this writing we have not confirmed whether a draft project description or call for collaborators has been published following the April 2, 2026 comment deadline. **This must be checked before any customer-facing or investor-facing claim about NIST engagement.** Tracked in the reviewer is expected to have read the NIST materials cited in the Verification Log as an open checklist item.

---

## 7. Where we are behind NIST

Honest accounting. These are the places where NIST's question is broader than our V1 answer.

| NIST question | Our gap | Why | Plan |
|---|---|---|---|
| Z.3 — data sensitivity in aggregated agent responses | We cannot evaluate sensitivity of content an agent aggregated | Requires inference over content, not attributes | Open research item; contribute findings to NIST |
| P.1 — preventing prompt injection | Out of layer | Model/prompt concern | Not our product; we state the boundary explicitly |
| Z.6 — conveying intent | Structured intent only, no natural-language intent | NL intent requires an interpretation layer we have not built | V2 candidate |
| Z.2 — dynamic policy on context change | Partial — fixed dimensions only | Open-ended context needs a semantic layer | V2 candidate; pilot data to size it |
| Use case 3 — deployment pipelines | System allowlists, not pipeline stages | Requires a domain model we have not validated | Validate with a deployment-focused pilot |
| Tamper-*proofing* | Tamper-*evidence* with anchoring | Absolute tamper-proofing is not achievable in a software system | Stated explicitly; never overclaim |
| Multi-org federation | Single trust domain | Federation requires attesting agents we cannot control | Out of V1 by NIST's own scope exclusion |

---

## 8. Citation discipline

Every row in this document cites a page in the concept paper. Where we have made an assertion NIST does not make, it is marked *"(our addition)"*. No statistic appears in this document that is not either (a) a direct quotation from the concept paper, (b) a standard named by the concept paper, or (c) explicitly labeled as our own derived reasoning.

Secondary market figures (Gartner, Databricks, Deloitte, survey percentages) are deliberately absent. See the Verification Log (`docs/reference/verification-log.md`).

---

*Next: [`verification-log.md`](verification-log.md) · [`../architecture/overview.md`](../architecture/overview.md) · [`../security/threat-model.md`](../security/threat-model.md)*
