package agentid

// Pipeline stages form a capability ceiling: side_effect ⊒ write ⊒ read ⊒ plan.
// A grant scoped at "read" permits plan and read, but never write or a side
// effect. Stages are part of the action envelope, not inferred from names.
const (
	StagePlan       = "plan"
	StageRead       = "read"
	StageWrite      = "write"
	StageSideEffect = "side_effect"
)

var stageRank = map[string]int{
	StagePlan: 0, StageRead: 1, StageWrite: 2, StageSideEffect: 3,
}

// StageIsValid reports whether a stage label is known.
func StageIsValid(stage string) bool {
	_, ok := stageRank[stage]
	return ok
}

// StageWithin reports whether `observed` is at or below the `ceiling` stage.
// An empty ceiling imposes no restriction.
func StageWithin(ceiling, observed string) bool {
	if ceiling == "" {
		return true
	}
	ceilingRank, ok := stageRank[ceiling]
	if !ok {
		return false
	}
	observedRank, ok := stageRank[observed]
	return ok && observedRank <= ceilingRank
}
