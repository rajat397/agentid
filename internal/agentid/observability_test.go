package agentid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsRenderIncludesOperatorSignals(t *testing.T) {
	m := NewMetrics()
	m.RecordDecision("allow")
	m.RecordDecision("deny")
	m.RecordVerificationFailure()
	m.SetStatusAge(12.5)
	m.SetAnchorGaps(2)
	m.SetAdapterHealth("mcp", true)
	m.RecordLatency(3 * time.Millisecond)

	rendered := string(m.Render())
	for _, want := range []string{
		`agentid_decisions_total{outcome="allow"} 1`,
		`agentid_decisions_total{outcome="deny"} 1`,
		"agentid_verification_failures_total 1",
		"agentid_status_age_seconds 12.5",
		"agentid_anchor_gaps 2",
		`agentid_adapter_healthy{adapter="mcp"} 1`,
		"agentid_pep_latency_seconds_count 1",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in metrics:\n%s", want, rendered)
		}
	}
}

func TestMCPWrapperRecordsDecisionAndLatencyMetrics(t *testing.T) {
	metrics := NewMetrics()
	wrapper := proxyTestWrapper(t, false)
	wrapper.metrics = metrics
	proxy := NewMCPProxy(wrapper)

	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "100.00"))
	if !forward || response != nil {
		t.Fatalf("allowed call failed: %s", response)
	}
	forward, response = proxy.ProcessClient(context.Background(), proxyCall(t, "5000.00"))
	if forward || response == nil {
		t.Fatal("denied call was forwarded")
	}

	rendered := string(metrics.Render())
	if !strings.Contains(rendered, `agentid_decisions_total{outcome="allow"} 1`) {
		t.Fatalf("allow not recorded:\n%s", rendered)
	}
	if !strings.Contains(rendered, `agentid_decisions_total{outcome="deny"} 1`) {
		t.Fatalf("deny not recorded:\n%s", rendered)
	}
	if !strings.Contains(rendered, "agentid_pep_latency_seconds_count 2") {
		t.Fatalf("latency not recorded:\n%s", rendered)
	}
}

func TestVerificationHandlerServesMetrics(t *testing.T) {
	metrics := NewMetrics()
	metrics.RecordDecision("allow")
	handler := NewVerificationHandler(map[string]string{}, metrics)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "agentid_decisions_total") {
		t.Fatalf("metrics endpoint missing decision counter: %s", recorder.Body.String())
	}
}
