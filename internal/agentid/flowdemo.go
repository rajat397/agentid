package agentid

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

type flowStep struct {
	ID       string `json:"id"`
	Actor    string `json:"actor"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Artifact string `json:"artifact"`
}

type flowTrace struct {
	Mode    string     `json:"mode"`
	Outcome string     `json:"outcome"`
	Steps   []flowStep `json:"steps"`
}

func compactJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return err.Error()
	}
	return string(data)
}

// FlowDemoTrace produces a real allow/deny trace from the same components the
// PEP uses, including a local reference downstream tool. It powers the page.
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
	}, "2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, StatusIdx: &idx})
	if err != nil {
		return flowTrace{}, err
	}
	now := int(time.Now().Unix())
	token, err := BuildStatusToken("https://example.invalid/status", []int{0x00},
		signer, now, now+600, 300)
	if err != nil {
		return flowTrace{}, err
	}
	amount := "1000.00"
	if mode == "deny" {
		amount = "5000.00"
	}
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": amount, "currency": "USD",
		"resource_type": "ad_credit_account", "resource_id": "acme_retail_meta",
		"region": "eu", "stage": StageSideEffect, "provenance": ProvenanceTrusted,
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
			"action": "ad.credit.purchase", "amount": "1000.00",
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
	workflow := NewApprovalWorkflow()
	requestID := ""
	obligation := firstObligationType(result.Obligations)
	if result.Outcome != "valid" && obligation != "" {
		req, err := workflow.Request("ad.credit.purchase", "meta-ads", delegation.ID,
			envelopeDigest, obligation, result.Reason)
		if err != nil {
			return flowTrace{}, err
		}
		requestID = req.ID
	}
	downstreamText := "not called — no allowed receipt"
	if result.Outcome == "valid" {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodDelete,
			"/subjects/acme_retail_meta", nil)
		request.Header.Set("Authorization", "Bearer reference-credential")
		MockMetaAdsHandler("reference-credential").ServeHTTP(recorder, request)
		downstreamText = fmt.Sprintf("HTTP %d — %s",
			recorder.Code, strings.TrimSpace(recorder.Body.String()))
	}
	spans := BuildEvidenceSpans(receipt, delegation, trace, false)
	spanKinds := []string{}
	for _, span := range spans {
		spanKinds = append(spanKinds, stringField(span, "kind"))
	}
	outcome := "ALLOWED"
	if result.Outcome != "valid" {
		outcome = "BLOCKED"
	}
	return flowTrace{Mode: mode, Outcome: outcome, Steps: []flowStep{
		{ID: "call", Actor: "Agent", Title: "tools/call",
			Detail: "An agent asks for a consequential action. It has no downstream credential.",
			Artifact: compactJSON(map[string]any{
				"method": "tools/call", "tool": "purchase_ad_credit",
				"arguments": map[string]any{"amount": amount, "currency": "USD"},
			})},
		{ID: "envelope", Actor: "PEP wrapper", Title: "Canonical action envelope",
			Detail: "The wrapper — not the agent — supplies system, stage, provenance and sensitivity. Digest is the unit of approval.",
			Artifact: compactJSON(map[string]any{
				"digest": envelopeDigest, "envelope": envelope.ToMap(),
			})},
		{ID: "decision", Actor: "Validator", Title: "Deterministic decision",
			Detail: "Signed delegation, typed predicates, status list and signed policy are checked locally. Failed calls still mint receipts.",
			Artifact: compactJSON(map[string]any{
				"outcome": result.Outcome, "reason": result.Reason,
				"receipt_id": receipt.ID, "trace_id": trace.TraceID,
				"profile_digest": stringField(receipt.Decision, "profile_digest"),
			})},
		{ID: "downstream", Actor: "Reference tool", Title: "meta-ads (mock)",
			Detail: downstreamText,
			Artifact: compactJSON(map[string]any{
				"credential_location": "PEP wrapper (env)",
				"response":            downstreamText,
			})},
		{ID: "evidence", Actor: "Evidence plane", Title: "Receipt + spans + approval",
			Detail: "Signed receipt, five mutually-bound spans, status token and evidence bundle are verifiable offline.",
			Artifact: compactJSON(map[string]any{
				"receipt_id": receipt.ID, "span_kinds": spanKinds,
				"approval_request_id": requestID,
				"obligations":         result.Obligations,
			})},
	}}, nil
}
