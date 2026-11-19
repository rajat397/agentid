package agentid

import (
	"sort"
	"time"
)

// ErasurePlan enumerates every agent action touching a personal-data subject.
type ErasurePlan struct {
	SubjectID         string
	CreatedAt         string
	Deadline          string
	DaysRemaining     int
	Receipts          []any
	Delegations       []string
	DownstreamSystems []any
	DerivedArtifacts  []any
	TotalReceipts     int
}

// ToMap produces the export form of the plan.
func (p ErasurePlan) ToMap() map[string]any {
	return map[string]any{
		"subject_id": p.SubjectID, "created_at": p.CreatedAt,
		"deadline": p.Deadline, "days_remaining": p.DaysRemaining,
		"total_receipts": p.TotalReceipts, "delegations": p.Delegations,
		"downstream_systems": p.DownstreamSystems,
		"derived_artifacts":  p.DerivedArtifacts,
	}
}

// BuildErasurePlan enumerates receipts, delegations and downstream systems.
// The registry is customer-supplied; the plan is only as good as that input.
func BuildErasurePlan(ledger *Ledger, subjectID string,
	registry map[string][]any, artifacts []any, jurisdiction string) ErasurePlan {
	now := time.Now().UTC()
	created := now.Format(timeLayout)
	deadline := now.AddDate(0, 0, 30).Format(timeLayout)

	var hits []*Receipt
	for _, receipt := range ledger.Receipts {
		for _, ref := range receipt.PersonalDataRefs() {
			if ref == subjectID {
				hits = append(hits, receipt)
				break
			}
		}
	}
	delegationSet := map[string]bool{}
	downstream := map[string]map[string]any{}
	receiptsDesc := []any{}
	for _, receipt := range hits {
		delegationSet[receipt.DelegationID] = true
		for _, ref := range receipt.PersonalDataRefs() {
			for _, raw := range registry[ref] {
				entry := AsMap(raw)
				system := stringField(entry, "system")
				if system == "" {
					continue
				}
				record, ok := downstream[system]
				if !ok {
					record = map[string]any{
						"system": system, "records": 0,
						"deletion_method": stringField(entry, "method"),
					}
					if record["deletion_method"] == "" {
						record["deletion_method"] = "customer_connector"
					}
					downstream[system] = record
				}
				record["records"] = intValue(record["records"]) + intValue(entry["records"])
			}
		}
		receiptsDesc = append(receiptsDesc, map[string]any{
			"receipt_id": receipt.ID, "action": receipt.Action,
			"fleet": receipt.Fleet, "issued_at": receipt.IssuedAt,
			"refs":   receipt.PersonalDataRefs(),
			"result": stringField(receipt.Decision, "result"),
		})
	}
	delegations := make([]string, 0, len(delegationSet))
	for id := range delegationSet {
		delegations = append(delegations, id)
	}
	sort.Strings(delegations)
	systems := make([]any, 0, len(downstream))
	names := make([]string, 0, len(downstream))
	for name := range downstream {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		systems = append(systems, downstream[name])
	}
	if artifacts == nil {
		artifacts = []any{}
	}
	return ErasurePlan{
		SubjectID: subjectID, CreatedAt: created, Deadline: deadline,
		DaysRemaining: 30, Receipts: receiptsDesc, Delegations: delegations,
		DownstreamSystems: systems, DerivedArtifacts: artifacts,
		TotalReceipts: len(hits),
	}
}
