package agentid

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Metrics is a small, dependency-free observability surface for a self-hosted PEP.
type Metrics struct {
	mu                   sync.Mutex
	decisions            map[string]int64
	verificationFailures int64
	statusAgeSeconds     float64
	anchorGaps           int64
	adapterHealth        map[string]bool
	latencySumSeconds    float64
	latencyCount         int64
}

func (w *MCPWrapper) recordVerificationFailure() {
	if w != nil && w.metrics != nil {
		w.metrics.RecordVerificationFailure()
	}
}

func NewMetrics() *Metrics {
	return &Metrics{
		decisions:     map[string]int64{},
		adapterHealth: map[string]bool{},
	}
}

func (m *Metrics) RecordDecision(outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[outcome]++
}

func (m *Metrics) RecordVerificationFailure() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verificationFailures++
}

func (m *Metrics) SetStatusAge(seconds float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusAgeSeconds = seconds
}

func (m *Metrics) SetAnchorGaps(count int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anchorGaps = count
}

func (m *Metrics) SetAdapterHealth(name string, healthy bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adapterHealth[name] = healthy
}

func (m *Metrics) RecordLatency(duration time.Duration) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencySumSeconds += duration.Seconds()
	m.latencyCount++
}

func (m *Metrics) Render() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out bytes.Buffer
	outcomes := make([]string, 0, len(m.decisions))
	for outcome := range m.decisions {
		outcomes = append(outcomes, outcome)
	}
	sort.Strings(outcomes)
	for _, outcome := range outcomes {
		fmt.Fprintf(&out, "agentid_decisions_total{outcome=%q} %d\n", outcome, m.decisions[outcome])
	}
	fmt.Fprintf(&out, "agentid_verification_failures_total %d\n", m.verificationFailures)
	fmt.Fprintf(&out, "agentid_status_age_seconds %g\n", m.statusAgeSeconds)
	fmt.Fprintf(&out, "agentid_anchor_gaps %d\n", m.anchorGaps)

	adapters := make([]string, 0, len(m.adapterHealth))
	for adapter := range m.adapterHealth {
		adapters = append(adapters, adapter)
	}
	sort.Strings(adapters)
	for _, adapter := range adapters {
		value := 0
		if m.adapterHealth[adapter] {
			value = 1
		}
		fmt.Fprintf(&out, "agentid_adapter_healthy{adapter=%q} %d\n", adapter, value)
	}
	fmt.Fprintf(&out, "agentid_pep_latency_seconds_sum %g\n", m.latencySumSeconds)
	fmt.Fprintf(&out, "agentid_pep_latency_seconds_count %d\n", m.latencyCount)
	return out.Bytes()
}
