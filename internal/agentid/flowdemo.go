package agentid

import (
	"net/http"

	"github.com/rajat397/agentid/attest"
	"net/http/httptest"
	"strings"
	"time"
)

type flowArtifact struct {
	Label string `json:"label"`
	Value any    `json:"value"`
}

type flowStep struct {
	ID        string         `json:"id"`
	Actor     string         `json:"actor"`
	Node      string         `json:"node"`
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	Artifacts []flowArtifact `json:"artifacts"`
}

type flowBranch struct {
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	Artifacts []flowArtifact `json:"artifacts"`
}

type flowTrace struct {
	Mode    string     `json:"mode"`
	Outcome string     `json:"outcome"`
	Steps   []flowStep `json:"steps"`
	Branch  flowBranch `json:"branch"`
}

// FlowDemoTrace produces a real guided journey from the Go components. Each
// step carries the actual artifact contents, not a hand-written illustration.
func FlowDemoTrace(mode string) (flowTrace, error) {
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return flowTrace{}, err
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "flow_demo_key")
	if err != nil {
		return flowTrace{}, err
	}
	subject := map[string]any{"type": "human", "id": "oidc|acme-retail|usr_8842"}
	idx := 0
	delegation, err := CreateDelegation(nil, subject, "marketing-agent", map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
		"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
		"aud":                           "rp_acme",
	}, "2030-01-01T00:00:00Z", DelegationOptions{
		Signer: signer, StatusIdx: &idx,
		Attestor: attestDev("spiffe://example.trust/agent/marketing-agent", publicPEM),
	})
	if err != nil {
		return flowTrace{}, err
	}
	now := int(time.Now().Unix())
	token, err := BuildStatusToken("https://example.invalid/status", []int{0x00},
		signer, now, now+600, 300)
	if err != nil {
		return flowTrace{}, err
	}
	statusPayload, err := VerifyStatusTokenAtIssuedTime(token, signer.PublicKeys(), 300)
	if err != nil {
		return flowTrace{}, err
	}
	amount := "1000.00"
	if mode == "deny" {
		amount = "1500.00"
	}
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": amount, "currency": "USD",
		"resource_type": "ad_credit_account", "resource_id": "acme_retail_meta",
		"region": "eu", "stage": StageSideEffect, "provenance": ProvenanceTrusted,
		"sensitivity_tier": TierConfidential, "aud": "rp_acme",
	}
	envelope, err := BuildEnvelope(action)
	if err != nil {
		return flowTrace{}, err
	}
	envelopeDigest, err := EnvelopeDigest(action)
	if err != nil {
		return flowTrace{}, err
	}
	trace, err := NewTraceContext()
	if err != nil {
		return flowTrace{}, err
	}
	statusLookup := func(uri string, i int) (int, error) {
		return CheckStatusLive(token, i, signer.PublicKeys(), 60)
	}
	var approval map[string]any
	if mode == "allow" {
		reviewerPEM, reviewerPub, err := GenerateKeyPair()
		if err != nil {
			return flowTrace{}, err
		}
		reviewer, err := NewDevSigner(reviewerPEM, reviewerPub, "flow_reviewer")
		if err != nil {
			return flowTrace{}, err
		}
		approval, err = SignApproval(map[string]any{
			"id": "apr_flow", "delegation_id": delegation.ID,
			"action": "ad.credit.purchase", "amount": amount,
			"approver": "human@rp", "nonce": "flow-nonce",
		}, reviewer)
		if err != nil {
			return flowTrace{}, err
		}
	}
	ledger := &Ledger{}
	receipt, result, err := Act(ledger, []Delegation{delegation}, action,
		ExampleProfile(), publicPEM, ActOptions{
			Signer: signer, Approval: approval, StatusLookup: statusLookup,
			Trace: &trace,
		})
	if err != nil {
		return flowTrace{}, err
	}
	receiptHash, _ := receipt.Hash()
	delegationDigest := DigestSHA256(mustCanonical(delegation.UnsignedBody()))
	profileDigest, _ := ExampleProfile().Digest()

	downstreamText := "not called — no allowed receipt"
	if result.Outcome == "valid" {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodDelete,
			"/subjects/acme_retail_meta", nil)
		request.Header.Set("Authorization", "Bearer reference-credential")
		MockMetaAdsHandler("reference-credential").ServeHTTP(recorder, request)
		downstreamText = strings.TrimSpace(recorder.Body.String())
	}
	spans := BuildEvidenceSpans(receipt, delegation, trace, false)
	spanKinds := []string{}
	for _, span := range spans {
		spanKinds = append(spanKinds, stringField(span, "kind"))
	}
	head, _ := ChainHead(ledger)
	stamp, err := NewBucketStamp(head, 0, signer)
	if err != nil {
		return flowTrace{}, err
	}
	bundle, err := BuildEvidenceBundle("rp_acme", ledger, []Delegation{delegation},
		ExampleProfile(), []map[string]any{map[string]any{
			"flavor": "bucket", "head_hash": head, "head_seq": 0,
			"gen_time": stamp.GenTime, "signer_kid": stamp.SignerKid,
			"alg": stamp.Alg, "signature": stamp.Signature,
			"signer_public": signer.PublicKeys()[stamp.SignerKid],
		}}, []string{token}, signer.PublicKeys())
	if err != nil {
		return flowTrace{}, err
	}

	outcome := "ALLOWED"
	if result.Outcome != "valid" {
		outcome = "BLOCKED"
	}
	steps := []flowStep{
		{
			ID: "principal", Actor: "Principal", Node: "principal",
			Title:  "A human initiates the journey",
			Detail: "The principal asks an agent to purchase ad credit. Authority is not implied by the prompt — it must be issued as a signed, narrow credential.",
			Artifacts: []flowArtifact{
				{Label: "Request (natural language)", Value: map[string]any{
					"principal":   "oidc|acme-retail|usr_8842",
					"instruction": "Purchase ad credit on meta-ads, up to $2,000, EU only, human co-sign above $500.",
					"agent":       "marketing-agent",
				}},
			},
		},
		{
			ID: "credential", Actor: "Issuer", Node: "issuer",
			Title:  "A delegation certificate is issued",
			Detail: "The issuer signs a certificate naming the actor, audience, exact permissions, typed attribute bounds, expiry, attestation and both classical and post-quantum signatures.",
			Artifacts: []flowArtifact{
				{Label: "Delegation certificate", Value: map[string]any{
					"id": delegation.ID, "body": delegation.UnsignedBody(),
					"signature":             delegation.Signature.toMap(),
					"additional_signatures": signaturesAsMaps(delegation.Signatures),
					"sha256":                delegationDigest,
				}},
				{Label: "Workload attestation", Value: delegation.Attestation},
			},
		},
		{
			ID: "agent", Actor: "Agent", Node: "agent",
			Title:  "The agent receives authority — not secrets",
			Detail: "The agent holds a signed credential and its key id. It cannot obtain the downstream credential; that stays inside the enforcement point.",
			Artifacts: []flowArtifact{
				{Label: "Agent identity", Value: map[string]any{
					"spiffe_id":             "spiffe://example.trust/agent/marketing-agent",
					"credential_kid":        delegation.Signature.Kid,
					"downstream_credential": "NOT HELD BY AGENT",
					"delegation_digest":     delegationDigest,
				}},
			},
		},
		{
			ID: "envelope", Actor: "PEP wrapper", Node: "pep",
			Title:  "Tool call becomes an action envelope",
			Detail: "The wrapper maps the JSON-RPC tool call into a canonical envelope. Operator-owned fields override anything the agent tried to supply.",
			Artifacts: []flowArtifact{
				{Label: "tools/call", Value: map[string]any{
					"method": "tools/call", "tool": "purchase_ad_credit",
					"arguments": map[string]any{"amount": amount, "currency": "USD"},
				}},
				{Label: "Canonical envelope", Value: map[string]any{
					"envelope": envelope.ToMap(), "digest": envelopeDigest,
				}},
			},
		},
		{
			ID: "validate", Actor: "Validator", Node: "validator",
			Title:  "The decision is derived locally",
			Detail: "Signature chain, attenuation, audience, revocation status, typed predicates, stage and provenance are checked against a signed policy bundle. No call to our infrastructure.",
			Artifacts: []flowArtifact{
				{Label: "Decision", Value: map[string]any{
					"outcome": result.Outcome, "reason": result.Reason,
					"envelope_digest": envelopeDigest, "profile_digest": profileDigest,
					"trace_id": trace.TraceID, "receipt_id": receipt.ID,
				}},
				{Label: "Status token", Value: map[string]any{
					"token": token, "decoded": statusPayload,
				}},
				{Label: "Validation Profile", Value: map[string]any{
					"digest": profileDigest, "document": ExampleProfile().Document(),
				}},
			},
		},
		{
			ID: "downstream", Actor: "Reference tool", Node: "downstream",
			Title:  "Downstream executes only on allow",
			Detail: "The PEP makes the call with the credential it holds. A denial produces no downstream traffic and still writes a receipt.",
			Artifacts: []flowArtifact{
				{Label: "Downstream result", Value: map[string]any{
					"system": "meta-ads (reference mock)", "status": "executed",
					"response": downstreamText, "credential_location": "PEP wrapper",
				}},
			},
		},
		{
			ID: "receipt", Actor: "Evidence plane", Node: "receipt",
			Title:  "A signed receipt certificate is minted",
			Detail: "The receipt binds the decision, the envelope digest, the profile digest and the chain head. ES256 and ML-DSA-65 signatures make authorship checkable.",
			Artifacts: []flowArtifact{
				{Label: "Receipt certificate", Value: map[string]any{
					"id": receipt.ID, "body": receipt.Body(), "hash": receiptHash,
					"primary_signature":     receipt.Signature.toMap(),
					"additional_signatures": signaturesAsMaps(receipt.Signatures),
				}},
				{Label: "Five spans", Value: map[string]any{
					"kinds": spanKinds, "trace_id": trace.TraceID,
					"receipt_id": receipt.ID, "pii": "pseudonymous by default",
				}},
			},
		},
		{
			ID: "audit", Actor: "Auditor", Node: "audit",
			Title:  "An offline bundle closes the loop",
			Detail: "The bundle carries receipts, profiles, signer keys, status tokens and customer-chosen anchor stamps. Verification never contacts our service.",
			Artifacts: []flowArtifact{
				{Label: "Evidence bundle manifest", Value: bundle.Manifest},
				{Label: "Bucket anchor stamp", Value: stamp},
			},
		},
	}

	branchAction := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": "1500.00", "currency": "USD",
		"resource_type": "ad_credit_account", "resource_id": "acme_retail_meta",
		"region": "eu", "stage": StageSideEffect, "provenance": ProvenanceTrusted,
		"sensitivity_tier": TierConfidential, "aud": "rp_acme",
	}
	branchLedger := &Ledger{}
	branchReceipt, branchResult, err := Act(branchLedger, []Delegation{delegation},
		branchAction, ExampleProfile(), publicPEM, ActOptions{
			Signer: signer, StatusLookup: statusLookup,
		})
	if err != nil {
		return flowTrace{}, err
	}
	workflow := NewApprovalWorkflow()
	branchDigest, _ := EnvelopeDigest(branchAction)
	request, requestErr := workflow.Request("ad.credit.purchase", "meta-ads",
		delegation.ID, branchDigest, firstObligationType(branchResult.Obligations),
		branchResult.Reason)
	branchRequest := map[string]any{"error": "no approval obligation"}
	if requestErr == nil {
		branchRequest = request.ToMap()
	}
	return flowTrace{
		Mode: mode, Outcome: outcome, Steps: steps,
		Branch: flowBranch{
			Title:  "The blocked branch",
			Detail: "At validation, the same agent asking for $1,500 with no human co-sign is held. No downstream call happens; an approval request is created for a reviewer.",
			Artifacts: []flowArtifact{
				{Label: "Blocked decision", Value: map[string]any{
					"outcome": branchResult.Outcome, "reason": branchResult.Reason,
					"receipt_id": branchReceipt.ID, "obligations": branchResult.Obligations,
				}},
				{Label: "Approval request", Value: branchRequest},
			},
		},
	}, nil
}

func signaturesAsMaps(signatures []Signature) []any {
	out := []any{}
	for _, signature := range signatures {
		out = append(out, map[string]any{
			"alg": signature.Alg, "kid": signature.Kid, "value": signature.Value,
		})
	}
	return out
}

func attestDev(id string, publicPEM []byte) attest.Attestor {
	return attest.DevAttestor{SPIFFEID: id, PublicKey: publicPEM}
}

func mustCanonical(value any) []byte {
	data, _ := CanonicalJSON(value)
	return data
}
