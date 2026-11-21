package agentid

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Five moments of one consequential action. No proprietary SDK is required:
// these are plain span shapes an OTel SDK can export unchanged.
const (
	SpanDelegationIssued = "delegation.issue"
	SpanValidation       = "validation"
	SpanObligation       = "obligation"
	SpanDownstreamCall   = "downstream.call"
	SpanReceiptPersisted = "receipt.persisted"
)

var evidenceSpanKinds = []string{
	SpanDelegationIssued, SpanValidation, SpanObligation,
	SpanDownstreamCall, SpanReceiptPersisted,
}

// TraceContext carries W3C trace context plus an authority hash in tracestate.
type TraceContext struct {
	TraceID       string
	SpanID        string
	AuthorityHash string
}

// NewTraceContext generates a fresh W3C context.
func NewTraceContext() (TraceContext, error) {
	traceID := make([]byte, 16)
	spanID := make([]byte, 8)
	if _, err := rand.Read(traceID); err != nil {
		return TraceContext{}, err
	}
	if _, err := rand.Read(spanID); err != nil {
		return TraceContext{}, err
	}
	return TraceContext{
		TraceID: hex.EncodeToString(traceID),
		SpanID:  hex.EncodeToString(spanID),
	}, nil
}

// Traceparent renders the W3C traceparent header.
func (t TraceContext) Traceparent() string {
	return "00-" + t.TraceID + "-" + t.SpanID + "-01"
}

// Tracestate publishes the authority binding as an agentid list member.
func (t TraceContext) Tracestate() string {
	hash := t.AuthorityHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return "agentid=" + hash
}

// ParseTraceparent validates and extracts a W3C traceparent header.
func ParseTraceparent(header string) (TraceContext, error) {
	parts := strings.Split(header, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 ||
		len(parts[2]) != 16 || len(parts[3]) != 2 {
		return TraceContext{}, errors.New("invalid traceparent")
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return TraceContext{}, err
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return TraceContext{}, err
	}
	return TraceContext{TraceID: parts[1], SpanID: parts[2]}, nil
}

// AuthorityHash binds the action envelope, delegation and receipt to the trace.
func AuthorityHash(action, delegationID, receiptID string) string {
	data, _ := CanonicalJSON([]any{action, delegationID, receiptID})
	return DigestSHA256(data)[:16]
}

// BuildEvidenceSpans emits the five mutually-bound spans for one action.
// Subject references are pseudonymous unless rawPII is explicitly enabled.
func BuildEvidenceSpans(receipt *Receipt, delegation Delegation,
	trace TraceContext, rawPII bool) []map[string]any {
	subject := stringField(delegation.Subject, "id")
	if subject != "" && !rawPII {
		subject = PseudonymousID(subject)
	}
	if trace.AuthorityHash == "" {
		trace.AuthorityHash = AuthorityHash(receipt.Action,
			receipt.DelegationID, receipt.ID)
	}
	common := map[string]any{
		"trace_id": trace.TraceID, "receipt_id": receipt.ID,
		"gen_ai.operation.name":         receipt.Action,
		"gen_ai.agent.id":               stringField(receipt.Actor, "agent_id"),
		"gen_ai.agent.identity.id":      stringField(receipt.Actor, "spiffe_id"),
		"agent.authority.delegation_id": receipt.DelegationID,
		"agent.authority.decision":      stringField(receipt.Decision, "result"),
		"agent.authority.trace_state":   trace.Tracestate(),
		"subject_ref":                   subject,
	}
	if version := AsMap(receipt.Actor["version"]); version != nil {
		common["gen_ai.agent.version"] = version
	}
	spans := []map[string]any{}
	for i, kind := range evidenceSpanKinds {
		attributes := map[string]any{}
		for key, value := range common {
			attributes[key] = value
		}
		attributes["span.kind"] = kind
		attributes["span_id"] = spanIDFor(trace.SpanID, i)
		if i > 0 {
			attributes["parent_span_id"] = spanIDFor(trace.SpanID, 0)
		}
		switch kind {
		case SpanDelegationIssued:
			attributes["delegation.expires_at"] = delegation.ExpiresAt
		case SpanValidation:
			attributes["decision.outcome"] = stringField(receipt.Decision, "outcome")
			attributes["decision.reason"] = stringField(receipt.Decision, "reason")
		case SpanObligation:
			obligations, _ := json.Marshal(receipt.Decision["obligations"])
			attributes["obligations"] = string(obligations)
		case SpanDownstreamCall:
			attributes["action.system"] = stringValue(AsMap(receipt.Resource)["currency"])
			attributes["action.name"] = receipt.Action
		case SpanReceiptPersisted:
			hash, _ := receipt.Hash()
			attributes["receipt.hash"] = hash
			attributes["receipt.prev_hash"] = receipt.PrevHash
		}
		spans = append(spans, map[string]any{
			"name": kind, "kind": kind, "trace_id": trace.TraceID,
			"span_id":    attributes["span_id"],
			"receipt_id": receipt.ID, "decision": stringField(receipt.Decision, "result"),
			"attributes": attributes, "status": "DEVELOPMENT",
		})
	}
	return spans
}

func spanIDFor(base string, index int) string {
	if len(base) < 15 {
		return fmt.Sprintf("%016x", index)
	}
	prefix := base[:14]
	return fmt.Sprintf("%s%02x", prefix, index)
}

// Mismatch is a divergence between telemetry and the receipt evidence.
type Mismatch struct {
	Type      string `json:"type"`
	ReceiptID string `json:"receipt_id,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// ReconcileEvidenceSpans compares spans to receipts using two independent
// sources. Any divergence is a `agentid.mismatch` signal, never a silent pass.
func ReconcileEvidenceSpans(spans []map[string]any, ledger *Ledger) []Mismatch {
	mismatches := []Mismatch{}
	byReceipt := map[string][]map[string]any{}
	for _, span := range spans {
		id := stringField(span, "receipt_id")
		if id == "" {
			mismatches = append(mismatches, Mismatch{Type: "span_without_receipt_id"})
			continue
		}
		byReceipt[id] = append(byReceipt[id], span)
	}
	ledgerReceipts := map[string]*Receipt{}
	for _, receipt := range ledger.Receipts {
		ledgerReceipts[receipt.ID] = receipt
	}
	for id, group := range byReceipt {
		receipt, ok := ledgerReceipts[id]
		if !ok {
			mismatches = append(mismatches,
				Mismatch{Type: "span_without_receipt", ReceiptID: id})
			continue
		}
		kinds := map[string]bool{}
		for _, span := range group {
			kind := stringField(span, "kind")
			kinds[kind] = true
			if decision := stringField(span, "decision"); decision != "" &&
				decision != stringField(receipt.Decision, "result") {
				mismatches = append(mismatches, Mismatch{
					Type: "decision_mismatch", ReceiptID: id, Detail: decision,
				})
			}
		}
		for _, expected := range evidenceSpanKinds {
			if !kinds[expected] {
				mismatches = append(mismatches, Mismatch{
					Type: "missing_span", ReceiptID: id, Detail: expected,
				})
			}
		}
	}
	for _, receipt := range ledger.Receipts {
		traceID := stringField(receipt.Decision, "trace_id")
		if traceID == "" {
			continue
		}
		found := false
		for _, span := range byReceipt[receipt.ID] {
			if stringField(span, "trace_id") == traceID {
				found = true
				break
			}
		}
		if !found {
			mismatches = append(mismatches, Mismatch{
				Type: "receipt_without_span", ReceiptID: receipt.ID,
			})
		}
	}
	return mismatches
}

// Collector is a caller-owned OTLP ingest point that reconciles spans against
// the ledger and exposes `agentid.mismatch` as a metric.
type Collector struct {
	mu         sync.Mutex
	ledger     *Ledger
	mismatches []Mismatch
	lastSpans  []map[string]any
}

func NewCollector(ledger *Ledger) *Collector { return &Collector{ledger: ledger} }

func (c *Collector) Ingest(spans []map[string]any) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSpans = spans
	c.mismatches = ReconcileEvidenceSpans(spans, c.ledger)
	types := []string{}
	for _, mismatch := range c.mismatches {
		types = append(types, mismatch.Type)
	}
	sort.Strings(types)
	return map[string]any{
		"metric": "agentid.mismatch", "count": len(c.mismatches),
		"types": types, "mismatches": c.mismatches,
	}
}

func (c *Collector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Spans []map[string]any `json:"spans"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, c.Ingest(payload.Spans))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, c.Ingest(c.lastSpans))
	})
	return mux
}

// SpanDeletionHints lists span identifiers tied to a subject for erasure.
func SpanDeletionHints(spans []map[string]any, subjectRef string) []map[string]any {
	hints := []map[string]any{}
	needle := PseudonymousID(subjectRef)
	for _, span := range spans {
		attributes := AsMap(span["attributes"])
		if stringField(attributes, "subject_ref") != needle {
			continue
		}
		hints = append(hints, map[string]any{
			"trace_id": span["trace_id"], "span_id": span["span_id"],
			"receipt_id": span["receipt_id"],
		})
	}
	return hints
}
