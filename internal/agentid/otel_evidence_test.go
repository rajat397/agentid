package agentid

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestW3CTraceContextRoundTrip(t *testing.T) {
	trace, err := NewTraceContext()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTraceparent(trace.Traceparent())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TraceID != trace.TraceID || parsed.SpanID != trace.SpanID {
		t.Fatal("W3C traceparent did not round-trip")
	}
	if !strings.HasPrefix(trace.Tracestate(), "agentid=") {
		t.Fatal("tracestate lacks authority member")
	}
	if _, err := ParseTraceparent("bad"); err == nil {
		t.Fatal("invalid traceparent accepted")
	}
}

func TestCollectorMetricAndPIIDefaults(t *testing.T) {
	signer, pub := newSigner(t, "otel_signer")
	trace, _ := NewTraceContext()
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "alice@example.com"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	action := testAction()
	action["personal_data_refs"] = []any{"cust_4471"}
	receipt, _, err := Act(ledger, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{Trace: &trace})
	if err != nil {
		t.Fatal(err)
	}
	spans := BuildEvidenceSpans(receipt, delegation, trace, false)
	data, _ := CanonicalJSON(spans)
	if strings.Contains(string(data), "alice@example.com") || strings.Contains(string(data), "cust_4471") {
		t.Fatal("raw PII leaked into default spans")
	}
	raw := BuildEvidenceSpans(receipt, delegation, trace, true)
	rawData, _ := CanonicalJSON(raw)
	if !strings.Contains(string(rawData), "alice@example.com") {
		t.Fatal("opt-in raw mode did not include the subject")
	}
	hints := SpanDeletionHints(spans, "alice@example.com")
	if len(hints) != len(spans) {
		t.Fatalf("erasure hints missing spans: %d/%d", len(hints), len(spans))
	}

	collector := NewCollector(ledger)
	result := collector.Ingest(spans)
	if intValue(result["count"]) != 0 {
		t.Fatalf("clean spans produced mismatches: %v", result)
	}
	spans[0]["decision"] = "denied"
	result = collector.Ingest(spans)
	if intValue(result["count"]) == 0 {
		t.Fatal("tampered span did not raise agentid.mismatch")
	}

	server := httptest.NewServer(collector.Handler())
	defer server.Close()
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/metrics", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("collector metrics status %d", response.StatusCode)
	}
}
