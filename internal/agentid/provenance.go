package agentid

// Provenance values form a two-point taint lattice: untrusted ⊑ trusted is
// false — any untrusted input taints the action. Missing provenance is
// untrusted, so integrations must opt in explicitly.
const (
	ProvenanceTrusted   = "trusted"
	ProvenanceUntrusted = "untrusted"
)

// JoinProvenance returns the conservative join of all observed sources.
func JoinProvenance(values ...string) string {
	result := ProvenanceTrusted
	if len(values) == 0 {
		return ProvenanceUntrusted
	}
	for _, value := range values {
		if value != ProvenanceTrusted {
			return ProvenanceUntrusted
		}
	}
	return result
}

// ProvenanceTracker accumulates taint across tool results and inputs.
type ProvenanceTracker struct {
	current  string
	observed bool
}

// NewProvenanceTracker starts untrusted (fail closed).
func NewProvenanceTracker() *ProvenanceTracker {
	return &ProvenanceTracker{current: ProvenanceUntrusted}
}

// Observe joins a new source's provenance into the running taint state.
func (p *ProvenanceTracker) Observe(source string) {
	if !p.observed {
		p.current = source
		p.observed = true
		return
	}
	p.current = JoinProvenance(p.current, source)
}

// Value returns the current taint state.
func (p *ProvenanceTracker) Value() string { return p.current }
