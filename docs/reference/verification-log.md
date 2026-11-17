# Verification Log — V7 Standards Conformance

**Status:** v1.0
**Purpose:** Evidence artifact for V7. Records what each normative text actually
says, checked line by line against the claims in `docs/`, and what changed as a
result.

**Rule:** a claim marked CORRECT here means it matches the normative source.
A claim marked WRONG means it was in our docs and did not. Every WRONG entry
names the file that carried it.

---

## V7.1 — OAuth 2.1 (and the Security BCP it inherits from)

**Sources read:**
- `draft-ietf-oauth-v2-1-17`, "The OAuth 2.1 Authorization Framework", 31 October 2026 (expires 4 May 2027) — `references/oauth-2.1-draft.txt`
- RFC 9700, "Best Current Practice for OAuth 2.0 Security", January 2025 — `references/rfc9700-oauth-security-bcp.txt`
- RFC 8707, "Resource Indicators for OAuth 2.0" — `references/rfc8707-resource-indicators.txt`

**Why RFC 9700 matters:** OAuth 2.1 names RFC 9700 only twice, but the *normative
security requirements* — audience restriction, refresh-token replay handling,
sender-constraining, scope privilege restriction — live in RFC 9700, not in
OAuth 2.1 itself. Any doc that attributes a security property to "OAuth 2.1"
when it actually comes from RFC 9700 is mis-citing it. Three of ours did.

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "PKCE mandatory" | **PARTLY WRONG** | "Clients MUST use code_challenge and code_verifier, and authorization servers MUST enforce their use **except under the conditions described in Section 7.5.1**." The exception requires **both**: the client is confidential, **and** there is reasonable assurance the client implements the OIDC nonce mechanism properly. PKCE is still RECOMMENDED in that case. Separately: the RFC 7636 `plain` transformation method is **removed and explicitly prohibited**. | OAuth 2.1 §4.1.1, §7.5.1.1, §7.5.2 |
| 2 | "implicit flow not offered" | **CORRECT** | Grant types are authorization_code (§4.1), client_credentials (§4.2), refresh_token (§4.3), extension grants (§4.4). Implicit is not among them. | OAuth 2.1 §4 |
| 3 | "refresh token rotation" as an OAuth 2.1 property | **WRONG** | OAuth 2.1: "The authorization server **MAY** revoke the old refresh token after issuing a new refresh token to the client." Rotation is **optional**. RFC 9700 §2.2.2: "Refresh tokens for **public clients** MUST be sender-constrained **or** use refresh token rotation" — an either/or, and only for public clients. RFC 9700 §4.14.2 requires AS to detect replay "for public clients" by one of those two methods. **Our agents are confidential clients, so neither is mandated for us.** | OAuth 2.1 §4.3.3; RFC 9700 §2.2.2, §4.14.2 |
| 4 | "exact audience matching" | **WRONG STRENGTH** | RFC 9700 §2.3: "access tokens **SHOULD** be audience-restricted to a specific resource server or, if that is not feasible, to a small set of resource servers... every resource server is obliged to verify, for every request, whether the access token... was meant to be used for that particular resource server. **If it was not, the resource server MUST refuse to serve the respective request.**" So: audience restriction is SHOULD; the *refusal* on mismatch is MUST. The `aud` claim (RFC 9068) and the `resource` parameter (RFC 8707) are the mechanisms. **"Exact" and "no wildcard" are not the source's language** — the source allows "a small set". | RFC 9700 §2.3, §4.10.2 |
| 5 | "`at+jwt` or opaque" presented as OAuth 2.1 token types | **WRONG CITATION** | OAuth 2.1 §5.2 uses two terms: **"reference tokens"** (validated by querying the AS or a token database) and **"self-encoded tokens"** (authorization info in an encrypted and/or signed string). `at+jwt` is defined by **RFC 9068** (JWT Profile for Access Tokens), which OAuth 2.1 merely cross-references. "opaque" is not the spec's word. | OAuth 2.1 §5.2; RFC 9068 |
| 6 | "Proof-of-possession (mTLS-bound `cnf` claim) required for write scopes" | **CORRECT AS OUR POLICY, mis-cited strength** | OAuth 2.1 §1.4.3: "Authorization and resource servers **SHOULD** use mechanisms for sender-constraining access tokens, such as OAuth 2.0 Demonstrating Proof of Possession (DPoP) [RFC9449] or Mutual TLS for OAuth 2.0 [RFC8705]." RFC 9700 §2.1.1: same SHOULD. Our "required for write scopes" is **stricter than the spec** — legitimate as policy, but must be labeled as our policy, not as a spec requirement. Also: `cnf` is defined by RFC 7800 and carries `x5t#S256` for mTLS or `jkt` for DPoP; we specified only the mTLS variant. | OAuth 2.1 §1.4.3; RFC 9700 §2.1.1; RFC 7800 |
| 7 | "client_credentials for machine callers" | **CORRECT, with a constraint we omitted** | "The client credentials grant type **MUST only be used by confidential clients**." It also cannot express delegation: the AS may issue for resources "of another resource owner that have been previously arranged with the authorization server (**the method of which is beyond the scope of this specification**)" — which is exactly the gap RFC 8693 fills. | OAuth 2.1 §4.2 |
| 8 | Access-token validation requirements | **INCOMPLETE IN OUR DOCS** | "the resource server **MUST** check that the access token has not expired, **is authorized to access the requested resource**, **was issued with the appropriate scope**, and meets other policy requirements of the resource server to access the protected resource." Our docs stated only expiry + audience + revocation. Scope enforcement was missing. | OAuth 2.1 §5.2 |
| 9 | Custom scope names (`ad.credit.purchase`, `agents:write`) | **NEW CONSTRAINT, NOT VIOLATED** | "OAuth does not define any scope values; instead, scopes are defined by the authorization server or by extensions or profiles of OAuth... it is recommended to avoid defining custom scopes that **conflict with scopes from known extensions**." Our scope names do not collide with OIDC standard scopes. | OAuth 2.1 §1.4.1 |
| 10 | Redirect URI handling | **CORRECT** | Redirect URIs "must be compared using exact string matching". | OAuth 2.1 §2.3 |

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/architecture/overview.md` §4.2 | "OAuth 2.1 (draft) semantics: PKCE mandatory, implicit flow not offered, refresh token rotation, exact audience matching" | Corrected per findings 1–4; citation split between OAuth 2.1 and RFC 9700 |
| `docs/api/core-api.md` §13 | "OAuth 2.1, `at+jwt` or opaque" | "reference tokens or self-encoded tokens (OAuth 2.1 §5.2); `at+jwt` per RFC 9068" |
| `docs/api/core-api.md` §1 | — | Added: client_credentials is confidential-clients-only (OAuth 2.1 §4.2) |
| `docs/api/errors.md` §3.2 | "`at+jwt` for PEP-local verification; opaque for revocation sensitivity" | Terminology corrected to reference/self-encoded; note that self-encoded trades instant revocation for local validation |
| `docs/security/threat-model.md` §5 | "OAuth 2.1, `at+jwt` or opaque"; "Refresh token rotation is on by default" | Split by source; rotation relabeled as our policy, not a spec requirement |
| `docs/security/threat-model.md` §5 | "Proof-of-possession \| mTLS-bound `cnf` claim \| Required for write scopes" | Spec strength noted (SHOULD); DPoP alternative added; RFC 7800 added |
| `docs/security/threat-model.md` T9 | audience restriction as hard control | Strength corrected to SHOULD + MUST-refuse; RFC 9700 §2.3 cited |
| `docs/security/threat-model.md` §5 | "Audience restriction" as a MUST-derivation | Rewritten to match RFC 9700 §2.3 wording |
| `docs/guides/getting-started.md` §11.3 | "Refresh token rotation is on by default" | Relabeled as our policy; the OAuth 2.1 delivery-loss failure mode noted |
| `docs/reference/standards-matrix.md` §4 | "OAuth 2.0/2.1 + extensions" row | Source split: OAuth 2.1 for protocol, RFC 9700 for the security requirements |
| `docs/reference/citations.md` §3 | OAuth 2.1 + RFC 8693 | Added RFC 9700, RFC 8707, RFC 9068, RFC 7800, RFC 7636, RFC 9449, RFC 8705 |
| `docs/api/core-api.md` §5.2 | validation list | Added scope enforcement per OAuth 2.1 §5.2 |

### Design consequences (not just wording)

1. **Refresh-token rotation may be the wrong default.** OAuth 2.1 §4.3.3
   documents the failure mode directly: "a failure to deliver the refresh token
   response (e.g., due to a network error) can leave the client holding only an
   invalidated refresh token, forcing a new authorization flow. Authorization
   servers that wish to avoid this failure mode **can use sender-constrained
   refresh tokens instead of rotation**." For agents running unattended in a
   fleet, a forced new authorization flow on a network blip is an availability
   event. We already require sender-constraining for write scopes, so
   sender-constrained refresh tokens are the consistent choice. **This is now a
   live design question, not a settled default.**
2. **Client authentication for agents.** RFC 9700 §2.2.2 notes that for
   confidential clients, refresh tokens "can only be used by the client for
   which they were issued" — RFC 6749 already requires this. Our SVID-based
   client authentication is `private_key_jwt`-shaped and aligns with that.
3. **RFC 9700 is a seventh normative source** that must be tracked alongside
   the six NIST-named standards (concept paper, p.7-8). Three of our citations attributed its
   requirements to OAuth 2.1.

### Falsifier for this verification

If a later draft of OAuth 2.1 changes §4.3.3 to mandate rotation, or if the
IETF publishes OAuth 2.1 as an RFC with different normative text, these
findings need re-checking. The draft is version 17 of an Internet-Draft with
an expiry of 4 May 2027 — **it is not a standard yet**, and our docs say so
wherever they cite it.

### Unknown

The exact `aud` claim handling in our chosen JWT profile (RFC 9068) has not
been read. We cite RFC 9068 for `at+jwt` but have not verified its `aud`
requirements, which is where the "exact vs. small set" question is actually
decided. Not blocking; flagged.

---

---

## V7.2 — RFC 8693 (OAuth 2.0 Token Exchange)

**Source read:** RFC 8693, "OAuth 2.0 Token Exchange", April 2020 —
`references/rfc8693-token-exchange.txt`

This RFC carries the delegation model, which is the load-bearing piece of our
architecture. It is also the standard where our docs were **most confident and
most wrong**.

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "RFC 8693 token exchange with explicit `subject_token` (human) + `actor_token` (agent)" | **CORRECT — and directly validated** | "`subject_token` represents the identity of the party **on behalf of whom** the token is being requested while the `actor_token` represents the identity of the party **to whom the access rights of the issued token are being delegated**." §1.1 further distinguishes **delegation** semantics ("principal A still has its own identity separate from B... any actions taken are being taken by A representing B") from **impersonation** semantics ("A is B within the context of the rights authorized by the token"). Our design uses delegation. | RFC 8693 §1.1, §2.1 |
| 2 | Chain represented as a flat `chain[]` array in the delegation record | **WRONG for the token; correct for the control plane** | "A chain of delegation can be expressed by **nesting one 'act' claim within another**. The outermost 'act' claim represents the current actor while nested 'act' claims represent prior actors. The least recent actor is the most deeply nested." A flat array is not the standard token representation. | RFC 8693 §4.1 |
| 3 | (implicit) The PEP/PDP can evaluate constraints from the token's delegation chain | **WRONG — MUST NOT** | "For the purpose of applying access control policy, the consumer of a token **MUST only consider the token's top-level claims and the party identified as the current actor** by the 'act' claim. **Prior actors identified by any nested 'act' claims are informational only and are not to be considered in access control decisions.**" | RFC 8693 §4.1 |
| 4 | Constraints as two independent lists: `actions: [...]` and `systems: [...]` | **WRONG — over-grants** | "the requested access rights of the token are the **Cartesian product** of all the scopes at all the target services... clients should exercise discretion in the breadth of the access requested, **particularly the number of target services**." Our two-list model implies `ad.credit.purchase × linkedin-ads`, which the operator never granted. | RFC 8693 §2.1.1 |
| 5 | (absent) A standard mechanism for pre-authorized delegation | **MISSING FROM OUR DOCS** | The `may_act` claim "makes a statement that one party is authorized to become the actor and act on behalf of another party" — the AS uses it "to determine whether the client (or party identified in the 'actor_token') is authorized to engage in the requested delegation." It carries **identity only**; `exp`, `nbf`, `aud` are "not meaningful... and are therefore not used" inside it. | RFC 8693 §4.4 |
| 6 | (absent) Revocation propagation as a protocol property | **WRONG — it is not** | "the act of performing a token exchange has no impact on the validity of the subject token or actor token... the exchange is a one-time event and does not create a tight linkage between the input and output tokens... **It may still be appropriate or desirable to propagate token-revocation events. However, doing so is not a general property of the STS protocol** and would be specific to a particular implementation, token type, or deployment." | RFC 8693 §2.1 |
| 7 | Client authentication for agents | **CORRECT — and the RFC names the risk** | "omitting client authentication allows for a compromised token to be leveraged via an STS into other tokens by anyone possessing the compromised token. Thus, client authentication allows for additional authorization checks by the STS as to which entities are permitted to impersonate or receive delegations from other entities." | RFC 8693 §2.1 |
| 8 | Depth cap of 3 hops; constraint intersection on every hop | **OUR EXTENSION — not in the standard** | RFC 8693 specifies **no** chain depth limit, **no** constraint inheritance or intersection semantics across hops, and **no** mid-chain revocation model. Our security considerations (§5) are one paragraph and cover only scope restriction and token lifetime. | RFC 8693 §5 (absence) |
| 9 | Minimal data in tokens, pseudonymous references | **CORRECT** | "Deployments SHOULD determine the minimally necessary amount of data and only include such information in issued tokens. In some cases, data minimization may include representing only an anonymous or pseudonymous user." | RFC 8693 §6 |
| 10 | (absent) Exact token type URNs | **NEW — now used in the API** | `urn:ietf:params:oauth:token-type:access_token`, `...:refresh_token`, `...:id_token`, `...:saml1`, `...:saml2`. `actor_token_type` is REQUIRED when `actor_token` is present and MUST NOT be included otherwise. | RFC 8693 §3, §2.1 |

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/architecture/overview.md` §4.2 | flat `chain[]` array; two-list constraints | Nested `act` claims for the token; `permissions` as explicit (action, system) **pairs**; `may_act` added; revocation non-propagation documented |
| `docs/architecture/overview.md` §4.2 | "constraint intersection on every hop" stated as if standard | Relabeled **our extension**, ahead of RFC 8693, with the standard's silence noted |
| `docs/architecture/overview.md` §4.3 | constraints as attribute tuples | Constraint evaluation notes the RFC 8693 §4.1 MUST NOT — the PDP resolves constraints from the delegation record, never from the token's nested `act` history |
| `docs/api/core-api.md` §3.1 | `constraints.actions` + `constraints.systems` | `constraints.permissions[]` of explicit `{action, system}` pairs |
| `docs/api/core-api.md` §3.1 | delegation request shape | RFC 8693 token-exchange parameters and token type URNs added |
| `docs/security/threat-model.md` T2 | "Revocation propagation" as a control | Relabelled implementation-specific; **max token age is now the primary containment**, not a backstop |
| `docs/security/threat-model.md` §5 | — | RFC 8693 §2.1 revocation non-propagation added to the crypto posture table |
| `docs/reference/standards-matrix.md` Z.7 | "Implemented" | Corrected, and the two areas where we are **ahead of the standard** are named |

### Design consequences (not just wording)

1. **The constraint model was over-granting.** Two independent lists imply a
   Cartesian product. `actions: [purchase, publish]` × `systems: [meta-ads,
   linkedin-ads]` grants `ad.credit.purchase` on LinkedIn Ads, which no operator
   asked for. Constraints are now **explicit (action, system) pairs**. This is
   the single most consequential finding of V7.2 — it was a real over-grant
   reachable through the normal API path.
2. **Max token age is now a primary control, not a backstop.** Because token
   exchange does not propagate revocation (§2.1), revoking a delegation does not
   kill tokens already derived from it. Our existing "maximum token age
   independent of SVID TTL" rule is what actually bounds that exposure, and it
   was previously framed as a mitigation for SPIRE revocation lag — a different
   and smaller problem. The exchanged token must also never outlive the
   delegation record's `expires_at`.
3. **The PDP cannot read the chain from the token.** RFC 8693 §4.1's MUST NOT
   is now an explicit implementation constraint on the policy engine, not just a
   citation. The delegation record stays control-plane-side and the receipt
   references it by `delegation_id`.
4. **Two things we invented that the standard does not have.** Depth cap and
   constraint intersection. Both are reasonable; neither is standard. They are
   candidates for the NIST feedback submission — an area where a standards body
   has an open question and we have a working answer.

### Falsifier

If a later revision of RFC 8693 (or an OAuth extension such as an
"Authorization Server Metadata for Delegation" profile) specifies chain depth
limits or constraint inheritance, our extensions become redundant rather than
wrong — and would need to be reconciled. RFC 8693 is Informational, not a
Standard, so this is more likely than for the OAuth 2.x track.

### Unknown

Whether `may_act` composes correctly with nested `act` claims in a multi-hop
exchange — the RFC treats them in separate sections and does not show a
combined example. Not blocking, but it is the exact case our multi-hop design
depends on, so it needs a hands-on test against a real STS before the design
is frozen.

---

---

## V7.3 — NIST SP 800-207 (Zero Trust Architecture)

**Source read:** NIST SP 800-207, *Zero Trust Architecture*, August 2020 —
`references/nist-sp-800-207.pdf`

**This is the most consequential verification so far.** SP 800-207 is cited by
the NIST concept paper (p.8) only as a guideline it "will also apply". Our docs
cited it for exactly one thing — "architecture principle Z.1" — and missed the
rest of it. In particular we missed the fact that SP 800-207 **already names
our threat, in our terms, six years before the concept paper**.

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "no implicit trust from network location" | **CORRECT** | Tenet 2: "Network location alone does not imply trust... trust should not be automatically granted based on the device being on enterprise network infrastructure." | §2.1 tenet 2 |
| 2 | "per-request verification" | **WRONG — the source says per-session** | Tenet 3: "Access to individual enterprise resources is granted on a **per-session** basis. Trust in the requester is evaluated before the access is granted... This could mean only 'sometime recently' for this particular transaction and **may not occur directly before initiating a session or performing a transaction with a resource.**" Re-evaluation is event-driven: tenet 6 lists the triggers as "time-based, new resource requested, resource modification, anomalous subject activity detected". **Our per-action evaluation is stricter than SP 800-207 requires.** §2.1 also notes "not all tenets may be fully implemented in their purest form" — so stricter is permitted, but our citation was wrong. | §2.1 tenets 3, 6 |
| 3 | "continuous evaluation" | **CORRECT but needs precision** | Tenet 6: "This is a constant cycle of obtaining access, scanning and assessing threats, adapting, and continually reevaluating trust in ongoing communication." Continuous re-evaluation is triggered by policy-defined events, not by every request. | §2.1 tenet 6 |
| 4 | (implicit) our `requires_human_approval_above` is an invention | **CORRECT — and directly named by the source** | Tenet 6's re-authentication triggers include "time-based, new resource requested, **resource modification**, anomalous subject activity detected". Our approval-threshold control is an instance of SP 800-207's named "resource modification" trigger. | §2.1 tenet 6 |
| 5 | (not claimed by us) SP 800-207 says nothing about our threat | **WRONG — it says a great deal** | §5.7 *Use of Non-person Entities (NPE) in ZTA Administration*: "The associated risk is that an attacker will be able to **induce or coerce an NPE to perform some task that the attacker is not privileged to perform**. The software agent may have a lower bar for authentication (e.g., API key versus MFA) to perform administrative or security-related tasks compared with a human user. **If an attacker can interact with the agent, they could theoretically trick the agent into allowing the attacker greater access or into performing some task on behalf of the attacker.** There is also a risk that an attacker could gain access to a software agent's credentials and **impersonate the agent** when performing tasks." | §5.7 |
| 6 | "PEP" naming | **CORRECT — the source's own vocabulary** | §2.2 assumption 3: "Every asset must have its security posture evaluated **via a PEP** before a request is granted to an enterprise-owned resource." §3.3: "the policy engine can be thought of as the brain and the PE's trust algorithm as its primary thought process." Our PDP/PEP naming maps onto the standard's policy engine / policy enforcement point. | §2.2, §3.3 |
| 7 | (absent) human + agent duality | **CORRECT and validated** | §7.3.1: "Subjects could encompass both human and possible NPEs, such as service accounts that interact with resources." | §7.3.1 |
| 8 | (absent) attestation-before-identity | **CORRECT and validated** | Tenet 5: "**No asset is inherently trusted.** The enterprise evaluates the security posture of the asset when evaluating a resource request." Tenet 4: "client identity can include the user account (or service identity) and any associated attributes assigned by the enterprise to that account or **artifacts to authenticate automated tasks**." | §2.1 tenets 4, 5 |
| 9 | (absent) one-resource authorization isolation | **CORRECT — cross-validates V7.2** | Tenet 3: "**authentication and authorization to one resource will not automatically grant access to a different resource.**" This independently supports both the audience restriction and the explicit (action, system) pair model found in V7.2. | §2.1 tenet 3 |
| 10 | (absent) scope limit on the tenets | **CONSISTENT** | "These tenets apply to work done within an organization or in collaboration with one or more partner organizations and **not to anonymous public or consumer-facing business processes**." Matches our enterprise-controlled-only scope. | §2.1 |
| 11 | (absent) audit logs as a compensating control | **CORRECT and validated** | §7.3.1: legacy architectures give privileged accounts "blanket permission to access all enterprise resources. ZTA should allow developers and administrators to have sufficient flexibility to satisfy their business requirements **while using logs and audit actions to identify access behavior patterns**." | §7.3.1 |

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/reference/standards-matrix.md` Z.1 | "SP 800-207 is explicitly cited by NIST (p.8) and we follow it: no implicit trust from network location; per-request verification; continuous evaluation; no standing trust." | Full tenet-by-tenet mapping. "Per-request verification" corrected to per-session with event-driven re-evaluation, and our per-action evaluation labelled as **stricter than the source requires**. |
| `docs/reference/standards-matrix.md` §4 | SP 800-207 listed only under "Also referenced by NIST" | Promoted to a mapped row with per-tenet status, and §5.7 added as the grounding for the threat model |
| `docs/security/threat-model.md` §1 | Trust zones described with no source | §5.7 of SP 800-207 named as the primary source for T1, T2 and the retailer scenario, with the source text quoted |
| `docs/security/threat-model.md` T1 | "Category: Elevation of privilege / Tampering. Source: NIST p.5" | Source now includes SP 800-207 §5.7, quoted verbatim — the attack is NIST's own, named in 2020 |
| `docs/security/compliance-mapping.md` | SP 800-207 row: one line | Per-tenet mapping |
| `docs/reference/citations.md` §3 | SP 800-207: "Architecture principle (NIST-cited)" | "Threat model grounding (§5.7) + architecture principles (§2.1 tenets) — NIST-cited" |

### Design consequences

1. **Our problem statement is six years older than we thought.** SP 800-207
   §5.7 describes, in NIST's own words, the exact incident in our scenario and
   the exact two threats in our model: an attacker coercing an agent into a
   privileged action, and an attacker impersonating an agent. The 2026 concept
   paper turns that identified threat into a **standards gap**. Our framing
   "recognized problem, not only our hypothesis" is therefore stronger than we
   claimed — it is recognized in a *peer-reviewed federal architecture
   guideline*, and separately in a 2026 standards concept paper.
2. **"Per-request" was wrong and we are stricter than the standard.** We
   evaluate per action; SP 800-207 requires per-session plus event-driven
   re-evaluation. That is a legitimate design choice and it costs latency
   (PDP on every action). Recording the gap matters because an auditor reading
   "we implement SP 800-207" would check against per-session and find us
   stricter, which is fine — but only if we say so rather than implying the
   standard mandates it.
3. **Our approval-threshold control is a named SP 800-207 re-evaluation
   trigger.** Tenet 6's "resource modification" trigger is exactly what
   `requires_human_approval_above` implements. That is a materially stronger
   grounding than "we invented it".
4. **V7.2's pair model now has two independent NIST sources.** RFC 8693 §2.1.1
   (Cartesian product) and SP 800-207 tenet 3 ("authentication and
   authorization to one resource will not automatically grant access to a
   different resource") both point the same way.

### Falsifier

If SP 800-207 is revised in a way that changes the tenets or §5.7, the
mapping must be re-checked. This is a 2020 publication; SP 800-207 Rev. 1 or a
successor would change the reference. More importantly: our per-action
evaluation is *stricter* than the tenets, and if fleet-scale latency makes it
impractical we will be tempted to relax to per-session — at which point this
mapping must be revisited rather than quietly dropped.

### Unknown

SP 800-207's §3.3 Trust Algorithm defines the inputs a policy engine may use
(subject database, subject attributes and roles, historical behaviour patterns,
threat intelligence, current resource, asset posture). Our PDP uses a much
narrower input set — delegation record, attestation state, request context.
Whether "historical behaviour patterns" is a normative expectation for our
PDP, or an optional enrichment, is not settled by the source. It maps to our
open threat-model question S6 (detecting a subverted-but-compliant agent).

---

---

## V7.4 — NIST SP 800-63-4 (Digital Identity Guidelines)

**Source read:** NIST SP 800-63-4, *Digital Identity Guidelines*, **July 2025** —
`references/nist-sp-800-63-4.pdf`

**This produced the strongest positioning finding of the entire verification
exercise.**

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "Human identity via OIDC; ACR-based assurance levels on approvals; we capture `acr` and `auth_time`" | **MIS-CITED** | **ACR does not appear in SP 800-63-4 at all.** ACR (`authentication_context_class_reference`) is an **OpenID Connect Core** construct. SP 800-63-4 defines a unified **xAL** notation: **IAL** (identity proofing robustness), **AAL** (authentication-process robustness and authenticator-to-individual binding), **FAL** (federation-process robustness when an RP is connected to a CSP/IdP "through a federated protocol"). The right citation for `acr` is OIDC Core; the right SP 800-63-4 concepts are AAL and FAL. | §3.3.2, §1.1 |
| 2 | (implicit) SP 800-63-4 is applicable to our agent identity plane | **WRONG — it explicitly excludes our case** | §1.1: "For this publication, **'person' refers only to natural persons**." And: "these guidelines **do not explicitly address some subjects**... including, but not limited to, **machine-to-machine authentication**, interconnected devices (e.g., Internet of Things [IoT] devices), or **access to Application Programming Interfaces (APIs) on behalf of subjects**." | §1.1 |
| 3 | (absent) the gap between NIST's own documents | **NEW — the project's strongest finding** | SP 800-207 (2020) **names** the agent threat in §5.7 but prescribes no standard for it. SP 800-63-4 (2025) **explicitly excludes** agents from scope. The 2026 NCCoE concept paper proposes to close the gap between them. The problem statement can therefore be stated precisely: **NIST's own digital identity guidelines exclude agent identity from their scope; NIST's zero trust guidelines identify the agent threat; the gap between those two documents is what the concept paper proposes to close.** | Cross-document |
| 4 | (absent) FAL for the IdP integration | **NEW** | "Federation Assurance Level (FAL) refers to federation functions when the relying party (RP) is connected to a credential service provider (CSP) or an identity provider (IdP) through a federated protocol." FAL2 adds "protection against... attempts to inject assertions into a federated transaction" — which is directly relevant to our approval-binding design. | §3.3.2.3 |
| 5 | (absent) the xAL levels | **NEW** | IAL1–3, AAL1–3, FAL1–3. AAL2 requires multi-factor; AAL3 requires phishing-resistant cryptographic authentication with a non-exportable key. "organizations are required to select an assurance level for each of the following functions." | §3.3.2 |
| 6 | (absent) augmentation, not replacement | **NEW** | "The controls and requirements encompassed by the identity, authentication, and federation assurance levels under these guidelines **augment but do not replace or alter** the information and information system controls determined under FISMA and the RMF." | §1.2 |
| 7 | (absent) version currency | **CONFIRMED** | SP 800-63-4 is dated **July 2025** — the current revision, superseding SP 800-63-3. | Title page |

### Provenance finding

**The same NIST authors are behind all three documents that matter to us.**

| Document | Authors include |
|---|---|
| NCCoE concept paper (Feb 2026) | Harold Booth, Bill Fisher, **Ryan Galluzzo**, Joshua Roberts |
| NISTIR 8587 (2026) | **Ryan Galluzzo**, Andrew Regenscheid, Stephanie Nelson, Christine Lazcano |
| SP 800-63-4 (July 2025) | David Temoshok, Diana Proud-Madruga, Yee-Yin Choong, **Ryan Galluzzo**, Sarbari Gupta, Connie LaSalle, Naomi Lefkovitz, **Andrew Regenscheid** |

Ryan Galluzzo appears on all three. This is not a citation to make in a marketing
artifact, but it is relevant to a NIST submission: the same people who wrote the
guidelines we rely on, the report on token protection, and the concept paper we
are responding to.

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/reference/standards-matrix.md` §4 | "NIST SP 800-63-4 ... Human identity via OIDC; ACR-based assurance levels on approvals; `acr` and `auth_time` captured on every approval. \| Implemented" | Corrected: ACR is an OIDC Core construct, not SP 800-63-4; the guideline's concepts are IAL/AAL/FAL. Explicit scope exclusion recorded |
| `docs/reference/standards-matrix.md` §4 | SP 800-63-4 listed as covering "Human assurance" | Re-scoped to the **human identity plane only**, with the machine-to-machine and API-on-behalf-of-subjects exclusion quoted |
| `docs/evidence/formal-problem-statement.md` | "NIST has framed it as a standards gap" | Strengthened with the cross-document gap statement (finding 3) |
| `docs/security/compliance-mapping.md` | "SP 800-63-4 \| Human identity via OIDC; ACR recorded on approvals; `auth_time` captured \| Implemented" | Corrected to IAL/AAL/FAL framing, with the scope boundary stated |
| `docs/reference/citations.md` §3 | SP 800-63-4: "Human assurance (NIST-cited)" | "Human identity plane ONLY — excludes machine-to-machine and API-on-behalf-of-subjects (§1.1) — NIST-cited" |

### Design consequences

1. **The problem statement can be made much more precise.** "NIST has framed
   this as a standards gap" is true but weak. The precise statement is: NIST's
   own digital identity guidelines **exclude** agents from scope, NIST's zero
   trust guidelines **name** the agent threat, and the 2026 concept paper
   proposes to close the gap between the two. That is a specific, verifiable,
   primary-sourced claim — and it is a much harder argument to dismiss.
2. **SP 800-63-4 governs our human plane and nothing else.** We use it for the
   customer's IdP integration: the federation is **FAL**-governed, the human's
   authentication is **AAL**-governed. FAL2's protection against assertion
   injection is directly relevant to approval-binding. We must not let a reader
   infer that SP 800-63-4 covers the agent identity work — it does not, by its
   own words.
3. **`acr` needs a second citation.** It is an OIDC Core claim. Our compliance
   mapping should cite OIDC Core for `acr` and SP 800-63-4 for the assurance-level
   concept it carries.

### Falsifier

If SP 800-63-5 is published and broadens the scope to non-person entities, or
if NISTIR 8587 (which we have not yet read, V7.5) turns out to define agent
identity assurance levels, the scope boundary changes and the positioning in
finding 3 must be re-stated. NISTIR 8587 is by the same author group, so this
is a live possibility — V7.5 should be read with this in mind.

### Unknown

Whether SP 800-63-4's companion volumes (63A enrollment, 63B authentication,
63C federation) contain requirements that bear on our approval-binding design
in a way the umbrella volume does not. We have read only 63-4. A/B/C are
normative; the umbrella volume says so explicitly.

---

---

## V7.5 — NISTIR 8587 (Protecting Tokens and Assertions from Forgery, Theft, and Misuse)

**Source read:** NIST IR 8587, **September 2026** (final; initial public draft
22 December 2025, comments closed 30 January 2026, obsoleted 15 September 2026)
— `references/nistir-8587.pdf`

This document **validates the architecture almost line for line** — and
simultaneously contains the third instance of the exclusion pattern.

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "Token handling: short lifetime, audience binding, proof-of-possession, issuer/salt validation, `jti` replay detection" | **MOSTLY CORRECT — one element WRONG** | §5.2.1.1 requires seven minimum contents: **issuer identifier; subject or client identifier; audience identifier; issuance time; validity time window; assertion or token identifier or nonce ("used to prevent attackers from replaying prior assertions"); authentication time.** All of our claims map except **salt** — the word does not appear, and there is no client-authentication or RFC 9101 content. §1.1 places "schemes based on symmetric cryptography, API keys" **out of scope**. Salt is a symmetric-client-secret concept, irrelevant to our `private_key_jwt` agents. | §5.2.1.1, §1.1 |
| 2 | (absent) our architecture as a whole | **DIRECTLY VALIDATED** | §5.3.1.6 *Workload Protections*: "Workload identities — including non-person entities, automated services, and machine-to-machine processes — **MUST use tightly scoped, short-lived tokens**... and **SHOULD use sender-constrained mechanisms (e.g., mTLS, DPoP) whenever feasible**. **Incorporating SPIFFE-based workload identities strengthens this model** by eliminating long-lived static credentials altogether. Instead, workloads obtain SPIFFE Verifiable Identity Documents (SVIDs) (e.g., SVID JWTs) dynamically from a trusted control plane... promotes tokens and workload credentials that are **automatically rotated, cryptographically verifiable, and bound to the specific workload, reducing the risk of impersonation or stolen tokens being replayed.**" Every one of our design choices — tightly scoped, short-lived, sender-constrained, SPIFFE SVID, attestation-gated issuance — is named here. | §5.3.1.6 |
| 3 | (absent) Mutant M1's required behaviour | **INDEPENDENTLY SPECIFIED** | §5.3.1.5 *Token Protection*: "All tokens MUST be strictly protected from exposure in system logs, CI/CD pipelines, and related build or deployment artifacts and stored exclusively in approved secure storage mechanisms... Pipelines MUST only retrieve secrets through secret management systems, inject them ephemerally at runtime, and ensure that they are never written to logs, console outputs, cache directories, or artifact stores. **Any detected exposure of tokens should be treated as a security incident** and remediated according to enterprise incident response procedures." | §5.3.1.5 |
| 4 | (absent) max token age as primary containment | **VALIDATED — this was our V7.1 conclusion** | §5.3.1.2 *Token Revocation*: "Immediate and global token revocation is not always possible in stateless token implementations before the expiration of token validity periods. However, **when short-lived access tokens are coupled with refresh tokens or reauthentication requirements, CSPs and agencies can substantially limit the time for which a compromised token is valid.**" | §5.3.1.2 |
| 5 | (absent) refresh-token replay handling | **CORRECT** | "Authorization servers must protect refresh tokens from being replayed (e.g., through sender-constraining or rotation)." Same either/or as RFC 9700 — our preference for sender-constrained over rotation (V7.1) is consistent with this. | §5.3.1.1 |
| 6 | (absent) proof-of-possession | **CORRECT** | "Proof-of-possession schemes... implement additional means (e.g., device-specific public-private key pairs, Demonstrated Proof of Possession [DPoP], mutual TLS binding) to verify the identity of an endpoint or user in a transaction before granting access. If strong sender binding is not achievable, IdPs and token services can consider channel-binding techniques that use TLS properties to constrain token usage." | §5.3.1.4 |
| 7 | (implicit) NISTIR 8587 might define agent identity assurance | **NO — it excludes agent access risks** | §1.1.1: "This document is not a comprehensive guide to addressing AI and agent access risks. **Those risks create additional IAM challenges that require further guidelines and, in some cases, new or expanded standards and protocols. This document excludes those topics from scope. NIST and CISA recognize this gap** and continue to develop practical guidelines as AI and agentic AI systems gain traction." **This resolves the V7.4 falsifier: NISTIR 8587 does not close the agent gap, it names the gap again.** | §1.1.1 |
| 8 | (absent) our scope is in scope for the document | **CORRECT** | §1.1: the controls cover IAM systems relying on "digitally signed assertions and tokens based on asymmetric cryptography... This often includes SSO, federation, application programming interface (API), and **workload access** scenarios." Our SPIFFE + ES256 design is squarely in scope. | §1.1 |
| 9 | (absent) revocation standards to watch | **NEW** | "the IETF Token Status List specification (an active Internet-Draft adopted by the OAuth Working Group) and the Global Token Revocation specification (an individual Internet-Draft in development) provide additional capabilities for the more rapid revocation of access tokens and the propagation of current token statuses to connected RPs. **CSPs and consumers should track these evolving standards.**" | §5.3.1.2 |
| 10 | (absent) publication timeline | **VERIFIED** | Initial Public Draft published **22 December 2025**, comments closed **30 January 2026**, obsoleted by the final on **15 September 2026**. The NCCoE concept paper (5 February 2026) therefore cited the **draft** — its citation is accurate, not anachronistic. The concept paper published one week after the token-protection draft's comment window closed. | NIST publication record |

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/reference/standards-matrix.md` §4 | "issuer/**salt** validation" | "issuer validation" — salt is not in the source and symmetric client-secret schemes are out of its scope |
| `docs/reference/standards-matrix.md` §4 | NISTIR 8587 mapped as token handling only | Mapped to the three sections that actually validate our design: §5.3.1.6 (workload protections), §5.3.1.5 (token protection), §5.2.1.1 (token contents) |
| `docs/security/threat-model.md` §5 | NISTIR 8587 listed as token handling | §5.3.1.6 quoted as the primary grounding for the workload-identity plane; §5.3.1.5's "Any detected exposure of tokens should be treated as a security incident" quoted as the grounding for Mutant M1 |
| `docs/security/threat-model.md` M1 | No NISTIR grounding | M1's exit condition now cites NISTIR 8587 §5.3.1.5 as an independent source for its "treat exposure as a security incident" behaviour |
| `docs/reference/citations.md` §3 | NISTIR 8587 "Token handling (NIST-cited)" | "Workload protections §5.3.1.6 (names SPIFFE SVIDs), token protection §5.3.1.5, token contents §5.2.1.1 — NIST-cited. **§1.1.1 excludes agent access risks from scope**" |
| `docs/evidence/formal-problem-statement.md` | Two-document gap statement | Extended to three documents — NISTIR 8587 §1.1.1 names the gap again, one week after the concept paper's citation of it as a draft |

### Design consequences

1. **The architecture is now independently specified by NIST.** §5.3.1.6 names
   non-person entities, machine-to-machine processes, short-lived tightly scoped
   tokens, sender-constraining, and **SPIFFE SVIDs** — in a sentence. We did not
   derive our workload identity plane from NIST; NIST specifies it. That is a
   materially stronger position than "aligned with" and it should be said
   plainly in any external artifact.
2. **Mutant M1 has a second, independent source.** §5.3.1.5's requirement that
   "any detected exposure of tokens should be treated as a security incident"
   is precisely M1's exit condition. Our M1 was designed from first
   principles; NIST specifies the same behaviour.
3. **The V7.1 conclusion is confirmed by NIST.** Our independent conclusion —
   that max token age is the primary containment because token exchange does
   not propagate revocation — is exactly §5.3.1.2's guidance for stateless
   implementations. We reached it by reasoning from RFC 8693; NIST states it.
4. **The gap is now named in three NIST documents**, not two:
   SP 800-207 §5.7 (threat, no fix), SP 800-63-4 §1.1 (excluded from scope),
   NISTIR 8587 §1.1.1 (excluded from scope, "NIST and CISA recognize this
   gap"). The concept paper is the proposed remedy.

### Falsifier

If a subsequent NIST publication defines agent identity assurance levels, or
if the NCCoE project description (if published since 2 April 2026) reframes the
gap, the positioning must be re-stated. We also have not read SP 800-63C, which
NISTIR 8587 names as the source of its own mandatory token contents.

### Unknown

Whether NISTIR 8587's recommended revocation approach (Token Status List,
Global Token Revocation) is compatible with our "max token age as primary
containment" design, or whether adopting a status list would be better. Both are
in development as Internet-Drafts. This is a live design question for V1.1.

---

---

## V7.6 — NIST SP 800-162 (Guide to Attribute Based Access Control) and NGAC

**Sources:**
- NIST SP 800-162, *Guide to Attribute Based Access Control (ABAC) Definition and Considerations*, **August 2014** — `references/nist-sp-800-162.pdf`
- NGAC's normative specification: **ANSI/INCITS 499-2013**, *Information technology — Next Generation Access Control — Functional Architecture (NGAC–FA)*. **Not freely available** — the ANSI webstore returns 403. We cite it but **cannot verify against it in this exercise.**

### Findings

| # | Our claim | Verdict | What the source says | Source |
|---|---|---|---|---|
| 1 | "NGAC (Next Generation Access Control), following NIST's named standard" — cited as **NIST SP 800-162** | **WRONG CITATION** | SP 800-162 mentions NGAC exactly **twice**: once as an example of an ABAC-consistent framework ("Another example of the Next Generation Access Control standard [ANSI499]"), and once in the reference list. **NGAC's normative functional architecture is ANSI/INCITS 499-2013 (NGAC–FA)**, not SP 800-162. | SP 800-162 §3 (example list), reference [ANSI499] |
| 2 | Our description of SP 800-162's title | **WRONG TITLE** | We wrote *"Guide to Attribute Based Access Control (ABAC) **for Access Control Systems**"*. The actual title is *"Guide to Attribute Based Access Control (ABAC) **Definition and Considerations**"*. | Title page |
| 3 | "NGAC's originating publication is NIST SP 800-162" (our own footnote in citations.md) | **WRONG — our own confident assumption** | Same as finding 1. SP 800-162 post-dates NGAC-FA (2013) by a year and uses it as an example, not as its source. This was a claim we asserted about a document we had not read. | — |
| 4 | "policy classes" as NGAC terminology | **CORRECT about NGAC, unsupported by SP 800-162** | The string "policy class" appears **zero** times in SP 800-162. It is NGAC-FA terminology, carried into the concept paper's p.8 description of NGAC. SP 800-162's own vocabulary is different: **Natural Language Policies (NLP)**, **Digital Policy (DP)**, **Metapolicy (MP)**. | SP 800-162 §4 |
| 5 | (absent) our PDP/PEP/PAP/PIP component naming | **CORRECT — the source's own reference architecture** | SP 800-162 describes the ABAC reference architecture as containing "Policy Decision Points (PDPs), Policy Enforcement Points (PEPs), Policy Administration Points (PAPs), and Policy Information Points (PIPs)". Our component names are the standard's. | SP 800-162 §3 |
| 6 | (absent) our attribute-based policy model | **CORRECT** | "Attribute Based Access Control (ABAC): An access control method where subject requests to perform operations on objects are granted or denied based on assigned attributes of the subject, assigned attributes of the object, environment conditions, and a set of policies that are specified in terms of those attributes and conditions." | SP 800-162 §3 |
| 7 | (absent) agents in scope for the policy model | **VALIDATED — and the counterpoint to the exclusion pattern** | "**A subject is a human user or NPE**, such as a device that issues access requests to perform operations on objects. Subjects are assigned one or more attributes. **For the purpose of this document, assume that subject and user are synonymous.**" SP 800-162 is the **first of our four NIST documents to include agents rather than exclude them** — and it does so in 2014. Note the last sentence: the document *assumes* subject and user are synonymous. That assumption is exactly where the attribution gap opens: ABAC can model an agent as a subject, but cannot attribute it to a human without the identity chain we are building. | SP 800-162 §3 |
| 8 | (absent) delegation in ABAC | **ABSENT — as expected** | SP 800-162 contains **no** delegation content. Our delegation model comes from RFC 8693, and the policy plane consumes it. Consistent with the V7.2 split. | — |
| 9 | (absent) a combining algorithm for our PDP | **GAP FOUND** | SP 800-162 treats "rule- and policy-combining algorithms" as a core ABAC element (via XACML). **Our PDP specification has no documented combining algorithm.** With multiple policies per fleet and an explicit deny, the resolution order is undefined. This is a real specification gap, newly surfaced by reading the source. | SP 800-162 §3 |

### Corrections applied

| File | Was | Now |
|---|---|---|
| `docs/reference/standards-matrix.md` §4 | "NGAC \| NIST SP 800-162 \| Policy plane \| Implemented" | Split into two rows: **NGAC** → ANSI/INCITS 499-2013 (NGAC–FA), paywalled, **cited but not verified**; **SP 800-162** → the ABAC guide supplying the reference architecture, the ABAC model, and the NPE-as-subject basis |
| `docs/reference/citations.md` §3 | "NGAC \| NIST SP 800-162 \| Policy plane" | NGAC → ANSI/INCITS 499-2013 (not verified — paywalled); SP 800-162 → ABAC guide, reference architecture + ABAC model + NPE as subject |
| `docs/reference/citations.md` §3 | "**Note on SP 800-162 (NGAC):** ... NGAC's originating publication is NIST SP 800-162, *Guide to Attribute Based Access Control (ABAC) for Access Control Systems*." | Corrected: NGAC's originating publication is ANSI/INCITS 499-2013; SP 800-162 is the ABAC guide that uses it as an example. Title corrected. |
| `docs/architecture/overview.md` §4.3 | "**Standard:** NGAC (Next Generation Access Control), following NIST's named standard." | Attribution corrected; the ABAC-model basis and the combining-algorithm gap added |
| `docs/architecture/overview.md` §7 | Open architectural questions | Added Q8 — combining algorithm undefined |

### Design consequences

1. **A combining algorithm is now a required addition to the PDP spec.** Without
   one, two policies with opposing effects on the same action have no defined
   outcome. The obvious default is deny-overrides (an explicit deny anywhere
   wins), which also matches the safety posture of fail-closed. **This was a
   genuine gap in our specification that only reading the source exposed.**
2. **SP 800-162 is the fourth document in the picture, and it points the other
   way.** It does not exclude agents — it puts NPEs in scope as subjects, in
   2014. Its blind spot is stated in its own text: "assume that subject and
   user are synonymous." **That assumption is precisely the attribution gap.**
   ABAC can model the agent; it cannot say which human the agent was acting
   for. Our delegation chain is the piece that breaks the synonym assumption.
3. **NGAC is now cited to a document we have not read.** ANSI/INCITS 499-2013 is
   paywalled. We cite it because the concept paper names NGAC, but our
   verification status must say "not verified" rather than implying otherwise.

### The four-document picture, complete

| Document | Date | What it says about agents |
|---|---|---|
| **SP 800-162** (ABAC guide) | 2014 | **Includes** them — "a subject is a human user or NPE" — but assumes subject and user are synonymous, which is exactly the gap |
| **SP 800-207** (Zero Trust) | 2020 | **Names the threat** (§5.7) — attacker coerces or impersonates an NPE — prescribes no fix |
| **SP 800-63-4** (Digital Identity) | 2025 | **Excludes** them — "person refers only to natural persons"; machine-to-machine and API-on-behalf-of-subjects out of scope |
| **NISTIR 8587** (Token Protection) | 2026 | **Excludes** agent access risks (§1.1.1); specifies the workload-identity controls that *do* apply (§5.3.1.6, naming SPIFFE SVIDs); "NIST and CISA recognize this gap" |
| **NCCoE concept paper** | 2026 | **Proposes to close it** |

### Falsifier

If the ANSI/INCITS 499-2013 text contradicts our reading of NGAC — in particular
if its delegation semantics differ from the Zanzibar-style relation tuples we
assume — the policy plane needs rework. We have not been able to read it, so
this is an unverified dependency, not a resolved question.

### Unknown

Whether NGAC-FA's "native delegation" (the phrase the concept paper uses at
p.8) provides the constraint-intersection semantics we invented, or something
different. Our depth cap and constraint intersection were derived independently
from RFC 8693's silence; NGAC-FA may already specify an answer.

---


---

## D8 — Positioning: conformant implementer + specification contributor

**Decided:** 2026-11-15. **Option B** — implement the emerging IETF agent-delegation
model, own the assurance/evidence layer, and contribute back to the gaps the
current drafts leave. Gated on having a working implementation and a pilot
first; contribution is downstream of both.

**Basis.** `draft-hulea-wimse-agent-mandate-01` §1 states four things the
standardization effort explicitly does **not** do: determine whether an action
reflects the principal's present intent; define a trust framework, assurance
levels, or the legal effect of a mandate; define how a delegator is shown a
mandate or consents to it; and replace the relying party's authorization policy.
All four exclusions are components already built here. `draft-liu-oauth-delegation-chaining-00`
confirms from the other side: it "leaves the validation of the actor_token, the
related policy evaluation, and the act claim of the issued ID-JAG open for
future profiles." Meanwhile `draft-liu-oauth-delegation-chaining-00` specifies
our architecture almost term for term — subject_token = the human's assertion,
actor_token = the agent's SPIFFE JWT-SVID, pre-authorization via `may_act`, the
chain in nested `act` claims, and "monotonic scope attenuation" (what we called
constraint intersection).

**Falsifier.** If a vendor ships a complete assurance layer — enforcement plus
evidence plus erasure — for the emerging drafts within 12 months, the layer is a
feature rather than a moat. Okta and Ping Identity are already the mandate
draft's authors and both have the IdP installed at the customers we would sell
to.

**Unknown.** Whether enterprise buyers treat "conformant to an Internet-Draft"
as a buying criterion or as noise. A draft is not a standard, and this should
be learned in a pilot conversation rather than assumed.

**Cost.** We now track seven moving drafts instead of one stable document.
The "we are first" claim is dropped — it is now factually false, and a security
buyer can discover it in ten minutes from a vendor's own linked documents.

---


---

## D9 — Root-authority evaluation: strict by default, indeterminate resolves to explicit human approval

**Decided:** 2026-11-15. Two-tier, but **strict by default**: root authority is
evaluated rather than silently inherited. Where it cannot be evaluated, the
*action* requires an explicit human approval rather than being denied outright.

**The rule this implements:**

| Root authority | Outcome | Action path |
|---|---|---|
| Evaluable, delegator had the power | valid | normal — no extra approval |
| Evaluable, delegator lacked the power | invalid | **denied** (draft: "MUST NOT allow an action when the outcome is `invalid`") |
| **Not evaluable** (no delegation-of-authority policy) | indeterminate | **explicit human approval required for the action** |

**Basis — and it is conformant, not a deviation.** `draft-hulea-wimse-agent-mandate-01`
§10.1: the RP "MUST treat indeterminate as a denial, **unless its policy
explicitly permits it for that type of action**." §5.3.1.2 of the same draft
uses the identical pattern: "treat the outcome as indeterminate and apply its
policy for that outcome." Our policy explicitly permits indeterminate **for
that action type**, conditioned on explicit human approval. That is the
escape hatch the draft provides, used as written.

**Mechanism.** Root authority is not a second authorization system — it is one
more relation in the ABAC/NGAC graph the PDP already evaluates:
`may_delegate(power, delegator)`. The delegator's `delegable_powers` attribute
comes from the customer's own delegation-of-authority policy. Evaluated at
delegation-creation time, so an invalid root never becomes a live delegation.

**Falsifier.** If compliance officers in pilot conversations say the delegator's
own approval is sufficient and they have no interest in modelling delegable
powers, then root-authority evaluation is a compliance-mapping footnote rather
than a product feature. The pilot question is concrete: *"if a manager delegates
an agent to spend money, who checks that the manager was allowed to spend that
much?"*

**Known consequence — approval load scales with action volume.** Under this
rule, a customer with no delegation-of-authority policy needs explicit approval
per consequential action. That is the strict reading, and it is intended. It
also means Mode 6 (background/event-driven agents, no human in the loop) cannot
run until such a policy exists. This is a deliberate narrowing, not an
oversight; it is the trade that makes the default safe.

**Unknown.** How the customer's delegation-of-authority policy is ingested, and
who maintains it. Not decided. The candidate mechanisms differ in cost by an
order of magnitude, and this is the next open question.

---


---

## D10 — Delegation-of-authority ingestion: SCIM-first, own policy API for limits

**Decided:** 2026-11-15. Two mechanisms, in this order:

1. **SCIM roles/groups as the default source.** "Managers may delegate ad-spend
   to their reports" becomes group membership plus one relation. Near-zero
   integration cost for the customer; covers the common case.
2. **Our own policy API for explicit limits.** Where a customer needs authority
   limits a role hierarchy cannot express — "may delegate up to $500", "may
   delegate ad-spend but not publish" — they author explicit tuples against
   our API.

**Not for V1:** consuming an Authority Assertion. The draft's design is the
destination, but it requires a customer-run issuer we would have to build, with
no standard to conform to yet.

**Basis.** Root authority is one more relation in the ABAC/NGAC graph the PDP
already evaluates (`may_delegate(power, delegator)`), so the engine does not
change — only ingestion does. SCIM is already in the design as the lifecycle
plane, so mechanism 1 reuses existing work. Mechanism 2 exists because role
hierarchies cannot carry authority limits, and because the resulting policy is
the artefact a CISO is asked to produce in an audit.

**Falsifier.** If enterprises cannot articulate who may delegate what — likely
for most mid-size companies — then asking them to formalise it stalls D9's
strict default and adoption. The pilot question: *"do you have a written policy
for who can delegate what on behalf of the company?"* If the answer is "no, but
we know it informally," then informal knowledge is the only available source,
and the honest product answer is to capture a coarse rule rather than demand
formalisation.

**Unknown.** How much of the delegation-of-authority matrix is load-bearing for
buyers versus table-stakes we could infer. No evidence either way; the pilot
is the only source.

---


---

## D11 — Adopt the IETF draft's constraint and obligation model wholesale

**Decided:** 2026-11-15. Replace our two bespoke constraint mechanisms with
`draft-hulea-wimse-agent-mandate-01`'s: `sum_max` (cumulative budgets keyed to
the root mandate), `cosign_above` (co-signature obligations), and monotonic
attenuation across the chain.

**Our mechanisms being replaced:**
- "constraint intersection on every hop" -> the draft's monotonic attenuation,
  whose soundness argument is stated at §4: "the sum over the parent's period is
  at most the sum over the longer child period, which the child's constraint
  keeps at or below a value no greater than the parent's."
- `requires_human_approval_above` -> `cosign_above`, which "produces an
  Obligation if resolved decimal exceeds value" and requires that "a second
  party designated by the RP's policy MUST approve the specific action."

**What we gain that we did not have.** `sum_max` carries a `root` member — "an
Artifact Reference to the root mandate, equal to the first element of chain" —
plus `budget`, `period`, `value`. The §9.5 obligation: "The sum of the
contributions recorded under the same root and budget with a recording time t
such that A minus period < t <= A, plus amount, MUST NOT exceed value." This
is a **cumulative budget shared across the whole chain, keyed to the root**.
Three consequences:
1. Blast radius is bounded **quantitatively** (a hard total), not structurally
   (a list of allowed actions) — strictly stronger than approval reuse.
2. Mode 6 (background agents) becomes viable: a human grants a budget once; the
   agent runs unattended; the budget is enforced at the PEP. This is also the
   delegation shape enterprises already use.
3. It solves chain compounding properly. Our depth cap of 3 was a workaround;
   a root-keyed budget makes three hops of $2,000 still draw on one $2,000 pot.

**Cost — accepted.** Our money model changes. The draft mandates decimal
strings for amounts: "compared as exact decimal numbers. JSON numbers MUST NOT
be used for amounts." Our `{"value": 2000, "currency": "USD"}` is not
conformant. Under this decision the constraint value becomes a decimal string
and the currency moves to the requested-authorization detail.

**Falsifier.** If budgets turn out to be hard to explain to a compliance officer
— "the agent may spend up to $2,000 but you have to think of it as a budget,
not a limit" — then the mechanism that survives contact with a buyer is the
per-action co-signature, and Mode 6 stays out of V1. Test in a pilot: describe
both, ask which a compliance officer would rather sign off on.

**Unknown.** Whether budget accounting survives real usage. "The same root and
budget" means two delegations naming different budgets do not share, while two
naming the same budget do. Whether enterprises use one budget per root or
fragment them and accidentally multiply exposure is a usage question the draft
leaves to the issuer. This is the most likely way the mechanism gets misused,
and it is a candidate contribution: budgets keyed to root with an explicit
non-fragmentation rule.

---


---

## D12 — Post-quantum posture: algorithm-agile, PQ-signed anchor, plus a re-signing service

**Decided:** 2026-11-15. Three commitments:

1. **Algorithm agility now.** The signing algorithm is configuration, not a
   hardcoded constant, so a future PQ migration is a configuration change rather
   than a refactor across the system.
2. **Classical signatures on the hot path, PQ-signed anchor on the archive.**
   Receipts and delegation records stay classically signed — short-lived
   artifacts do not justify a ~34x signature-size increase (FIPS 204 Table 2:
   ML-DSA-44 signature 2,420 bytes vs ECDSA P-256 72 bytes DER; public key
   1,312 vs 65) against the latency budget we have not yet measured. What
   changes is the **anchor**: a periodic **PQ-signed timestamp** over the chain
   head, RFC 3161-style, so archived evidence remains independently verifiable
   after the classical algorithm weakens.
3. **A re-signing / notary service.** Built alongside the anchor capability, so
   archived receipt batches can be counter-signed on a schedule by an
   independent signer.

**Basis — and why this is the agent-specific problem.** Our receipts *are* the
product and are retained for years, because their value is answering "what
happened, and can you prove it?" A 2026 TLS session is worthless in 2035;
nobody cares. A 2026 receipt presented as non-repudiation evidence in a 2035
audit is worth a great deal to someone who wants to falsify it. If classic
signatures are harvested today, a future quantum adversary can forge them for
that audit. **No ordinary web application has this problem.** It exists because
we are the evidence layer. RFC 3161 timestamping answers it without
re-signing receipts: the TSA can be PQ-signed later, so the timestamp — not the
receipt signature — is the evidence of existence, and the chain is the evidence
of integrity.

**Falsifier.** If customers never retain receipts beyond the
classical-cryptography horizon — deleting within ~18 months and re-deriving
anything they must keep — then the whole PQ thread reduces to commitment 1
alone. This depends on customers' retention obligations, which we do not know.
Pilot question: *"how long do you have to be able to prove what an agent
did?"*

**Unknown.** Whether customers accept a PQ-signed timestamp from a vendor we
introduce into their evidence chain as a new trust dependency. The reply is that
they already trust us for the ledger, and an *independent* anchor is strictly
more trustworthy than a self-asserted one — which is exactly why it survives the
algorithm change.

**Incidental find.** The mandate draft references HTTP Message Signatures
(RFC 9421). Our receipts do not have to be JWTs; HTTP Message Signatures would
make them considerably smaller and cheaper to verify. Relevant to the
latency budget (open question G14) and worth evaluating before the receipt
format is fixed.

---


---

## D13 — Split the PDP; the Validation Profile is a first-class, per-customer, archived artifact

**Decided:** 2026-11-15. Adopt the draft's two-stage split. Our PDP becomes:

1. **Validator** — deterministic and profile-driven. Evidence in;
   `valid` / `invalid` / `indeterminate` plus **Obligations** out. No business
   policy.
2. **RP policy step** — applies the customer's own policy to the Validation
   Result: grant, deny, discharge obligations (obtain the co-signature, check
   the budget).

The **Validation Profile** becomes a first-class product artifact: issued by the
**customer** (the RP), content-addressed by the base64url-encoded SHA-256 digest
of its bytes, versioned, distributed to the PEPs, pinned, and **archived
alongside every receipt**.

**Basis.** `draft-hulea-wimse-agent-mandate-01` §1.1: "Validation separate from
authorization. Given the same inputs, including the same validation profile,
two conforming Validators produce the same Validation Result. The relying party
then applies its own policy." §8: the profile is "a JSON document fixing every
rule that influences the Validation Result and is not fixed by this
specification. It is identified by a URI and by the base64url-encoded SHA-256
digest of its bytes."

**Our scattered tunables become profile parameters.** This closes open question
Q6 outright:

| Ours | Becomes |
|---|---|
| Q6 — depth cap, "V1: 3 hops max; pilot data to revisit" | **`max_chain_length`** — and the customer's, so the customer sets it |
| max token age (primary containment for delegation revocation, per V7.2) | **`max_token_lifetime`** |
| status-evidence freshness bound | **`max_status_age`** |
| supported constraint predicates | **`predicates`** |
| — (we had none) | **`max_clock_skew`**, `max_pop_window` |

**The gain that justifies the cost.** A receipt stops saying "allowed" and starts
saying "allowed under profile X, digest Y." An auditor holding profile Y and the
same inputs reaches the same result — the draft's determinism goal, and a
property no ordinary audit system has. Today's receipts rely on the customer's
trust in us; these are independently re-derivable.

**The problem the draft does not solve — ours.** The profile is issued by the
RP, so profiles differ per customer, get versioned, distributed, pinned, and
drift from what was in force at time T. Critically: **to re-validate a 2026
receipt in 2035 you need the profile as it was in 2026.** If the profile bytes
are not archived with the receipt, historical validation is impossible — and
historical validation is the entire point of the evidence product. The draft is
silent on this. **Candidate contribution: the profile is part of the evidence,
not part of the deployment.**

**Cost, honestly.** Two components with a defined interface instead of one, plus
profile lifecycle management: versioning, distribution, pinning, drift detection,
archival. And the product becomes "one control plane, many profiles" rather than
"one control plane, many fleets" — arguably better for enterprise (a regulated
business unit can hold a different profile from a marketing one), worse for
simplicity.

**Falsifier.** If customers will not operate a profile artifact — if they want
*our* opinion of their depth limits and token lifetimes rather than their own —
then the profile should be ours, centrally versioned, and the split collapses
back toward one PDP. Test: ask a security lead whether they want to tune
`max_chain_length` themselves or have us set it per deployment. The draft
assumes they want to; that assumption is worth a real sum of money in product
scope and should be verified early.

**Unknown.** Whether the determinism property is worth enforcing. Any
non-deterministic input — a clock, a random source, map iteration order, a
floating-point comparison — breaks byte-identical results. We have never tested
for it because we never had a requirement to. Content-addressing makes it
checkable: same profile digest + same inputs must yield the same result, or the
profile is not doing its job.

---


---

## D14 — Product shape: open-source SDK + hosted evidence/enforcement tier

**Decided:** 2026-11-16. **Option A.** The Stripe model: a free, embedded,
zero-config primitive that any agent framework adopts in a line or two, with a
hosted tier for evidence, enforcement and PKI.

**Scope of the primitive.** It is *not* compliance. The product is agent
identity, guardrails, reliability and traceability; compliance is the layer on
top. This corrects the earlier certifier narrowing, which treated the primitive
as someone else's and was too narrow.

**Basis.** OTel's GenAI semantic conventions define agent spans but sit at
*Development* status with three named identity gaps, and #350 — the proposal
that adds `gen_ai.agent.identity.id` — scopes itself explicitly: *"Observability
only: these are identifiers for correlation and audit, **not credentials or
access-control inputs**."* The authority layer is carved out of the telemetry
standard by the standard body itself. The integration surface already exists:
OpenAI Agents exposes `needs_approval` + `RunState.reject()`, the Claude Agent
SDK exposes `can_use_tool`, and the Microsoft Agent Framework exposes approval
requests — so attaching is a few lines each, not a restructure.

**The hosted tier is the part that cannot be skipped.** A free SDK with no
hosted value is a commodity: Braintree open-sourced and lost to Stripe, because
the SDK cannot do fraud, treasury, tax or disputes. Our hosted edge is the
evidence layer (tamper-evident, reproducible under a Validation Profile,
PQ-anchored, erasable) plus the enforcement and PKI plane. **Design the hosted
edge first even if it ships second.**

**Falsifier.** If OTel ratifies an identity model that already includes
authority/attribution within a year, the differentiator shrinks to a features
argument against a funded competitor with 150 integrations. Separately, if we
ship an SDK with no hosted edge, we have built a commodity. Both are checkable:
the first by watching the repo, the second by whether anyone pays.

**Unknown.** Whether the OTel community will accept an authority dimension in a
telemetry standard at all. R48 partially answers it — #350 explicitly excludes
access-control inputs — but the argument is still live in open issues #350, #535,
#320, #462, #243 and #370.

