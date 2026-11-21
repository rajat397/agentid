package agentid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultRetentionMonths is the customer-facing minimization window (Q2).
const DefaultRetentionMonths = 13

// RetentionPolicy controls archive-before-prune behavior. Archived receipts are
// never mutated in place; anchors remain permanent.
type RetentionPolicy struct {
	WindowMonths int
	ArchiveDir   string
}

func (p RetentionPolicy) window() int {
	if p.WindowMonths <= 0 {
		return DefaultRetentionMonths
	}
	return p.WindowMonths
}

// ExportArchive writes eligible receipts to customer-controlled storage and
// appends an ARCHIVE receipt to the same hash chain.
func ExportArchive(ledger *Ledger, policy RetentionPolicy,
	at time.Time) (string, *Receipt, error) {
	cutoff := at.AddDate(0, -policy.window(), 0)
	eligible := []*Receipt{}
	for _, receipt := range ledger.Receipts {
		if receipt.ActionType == "archive" || receipt.ActionType == "tombstone" {
			continue
		}
		if receipt.IssuedAt == "" || receipt.IssuedAt >= cutoff.Format(timeLayout) {
			continue
		}
		eligible = append(eligible, receipt)
	}
	if len(eligible) == 0 {
		return "", nil, errors.New("no receipts eligible for archival")
	}
	if policy.ArchiveDir == "" {
		return "", nil, errors.New("archive directory is required")
	}
	if err := os.MkdirAll(policy.ArchiveDir, 0o700); err != nil {
		return "", nil, err
	}
	path := filepath.Join(policy.ArchiveDir,
		"archive-"+cutoff.Format("2006-01-02")+".jsonl")
	data := []byte{}
	for _, receipt := range eligible {
		entry, err := CanonicalJSON(receipt.ToMap())
		if err != nil {
			return "", nil, err
		}
		data = append(data, append(entry, '\n')...)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", nil, err
	}
	digest := DigestSHA256(data)
	attributes := map[string]any{
		"window_start": "0001-01-01T00:00:00Z",
		"window_end":   cutoff.Format(timeLayout),
		"count":        len(eligible),
		"archive_uri":  path,
		"digest":       digest,
	}
	previous := stringsRepeatedZero
	if len(ledger.Receipts) > 0 {
		hash, err := ledger.Receipts[len(ledger.Receipts)-1].Hash()
		if err != nil {
			return "", nil, err
		}
		previous = hash
	}
	archiveReceipt := &Receipt{
		IssuedAt: at.Format(timeLayout), Fleet: "retention",
		Actor:        map[string]any{"system": "agentid", "operation": "retention.export"},
		DelegationID: "system", Action: "retention.archive",
		Resource: map[string]any{"type": "archive", "id": digest[:16],
			"attributes": attributes},
		Decision: map[string]any{"result": "allowed", "outcome": "valid",
			"reason": "archive-before-prune completed",
			"archive": map[string]any{
				"count": len(eligible), "digest": digest, "archive_uri": path,
			}},
		Outcome:    map[string]any{"status": "succeeded", "blocked": false},
		ActionType: "archive", PrevHash: previous, SignatureAlg: "ES256",
	}
	if err := ledger.Append(archiveReceipt); err != nil {
		return "", nil, err
	}
	return path, archiveReceipt, nil
}

// VerifyArchive re-reads the exported file and checks its binding to the
// ARCHIVE receipt. No issuer service is involved.
func VerifyArchive(path string, receipt *Receipt) []string {
	problems := []string{}
	attributes := AsMap(AsMap(receipt.Resource)["attributes"])
	data, err := os.ReadFile(path)
	if err != nil {
		return append(problems, "archive unreadable: "+err.Error())
	}
	if got := DigestSHA256(data); got != stringField(attributes, "digest") {
		problems = append(problems, "archive digest mismatch")
	}
	lines := 0
	for _, line := range splitLines(string(data)) {
		if line != "" {
			lines++
		}
	}
	if lines != intValue(attributes["count"]) {
		problems = append(problems,
			fmt.Sprintf("archive count %d does not match receipt count %v",
				lines, attributes["count"]))
	}
	if receipt.ActionType != "archive" {
		problems = append(problems, "receipt is not an ARCHIVE receipt")
	}
	return problems
}

// Tombstone records an erasure decision over opaque subject references.
// Original receipts stay immutable so the hash chain and anchors remain valid.
func Tombstone(ledger *Ledger, subjectRef string, at time.Time) (*Receipt, error) {
	targets := []string{}
	for _, receipt := range ledger.Receipts {
		for _, ref := range receipt.PersonalDataRefs() {
			if ref == subjectRef {
				targets = append(targets, receipt.ID)
				break
			}
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no receipts reference subject " + subjectRef)
	}
	sort.Strings(targets)
	previous := stringsRepeatedZero
	if len(ledger.Receipts) > 0 {
		hash, err := ledger.Receipts[len(ledger.Receipts)-1].Hash()
		if err != nil {
			return nil, err
		}
		previous = hash
	}
	receipt := &Receipt{
		IssuedAt: at.Format(timeLayout), Fleet: "erasure",
		Actor:        map[string]any{"system": "agentid", "operation": "erasure.tombstone"},
		DelegationID: "system", Action: "erasure.tombstone",
		Resource: map[string]any{"type": "tombstone", "id": subjectRef,
			"attributes": map[string]any{
				"subject_ref": subjectRef, "targets": stringsToAny(targets),
			}},
		Decision: map[string]any{"result": "allowed", "outcome": "valid",
			"reason": "opaque references tombstoned; chain unchanged"},
		Outcome:    map[string]any{"status": "succeeded", "blocked": false},
		ActionType: "tombstone", PrevHash: previous, SignatureAlg: "ES256",
	}
	if err := ledger.Append(receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

// IsTombstoned reports whether a subject ref has an erasure tombstone.
func IsTombstoned(ledger *Ledger, subjectRef string) bool {
	for _, receipt := range ledger.Receipts {
		if receipt.ActionType != "tombstone" {
			continue
		}
		attributes := AsMap(AsMap(receipt.Resource)["attributes"])
		if stringField(attributes, "subject_ref") == subjectRef {
			return true
		}
	}
	return false
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func splitLines(text string) []string {
	out := []string{}
	current := []byte{}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			out = append(out, string(current))
			current = current[:0]
		} else {
			current = append(current, text[i])
		}
	}
	return append(out, string(current))
}
