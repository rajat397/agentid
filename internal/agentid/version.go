package agentid

// AgentVersion identifies the build, runtime engine and (optionally) model
// that produced a delegation hop. It is signed into actor.version.
type AgentVersion struct {
	Build  string `json:"build"`
	Engine string `json:"engine"`
	Model  string `json:"model,omitempty"`
}

func (v AgentVersion) toMap() map[string]any {
	out := map[string]any{"build": v.Build, "engine": v.Engine}
	if v.Model != "" {
		out["model"] = v.Model
	}
	return out
}

func versionFromMap(value any) *AgentVersion {
	raw := AsMap(value)
	if raw == nil {
		return nil
	}
	return &AgentVersion{
		Build: stringField(raw, "build"), Engine: stringField(raw, "engine"),
		Model: stringField(raw, "model"),
	}
}

func versionEqual(a, b *AgentVersion) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Build == b.Build && a.Engine == b.Engine && a.Model == b.Model
}
