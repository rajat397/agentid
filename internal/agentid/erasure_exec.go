package agentid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Connector outcomes are explicit: a connector never silently succeeds.
const (
	OutcomeDeleted     = "deleted"
	OutcomeNotFound    = "not_found"
	OutcomeUnreachable = "unreachable"
	OutcomeForbidden   = "forbidden"
)

// DeletionRecord is the connector's report for one subject.
type DeletionRecord struct {
	System      string
	SubjectRef  string
	Outcome     string
	ExternalRef string
}

// DownstreamConnector is the erasure boundary for one customer system.
type DownstreamConnector interface {
	System() string
	DeleteSubject(ctx context.Context, subjectRef string) (DeletionRecord, error)
	VerifyAbsent(ctx context.Context, subjectRef string) (bool, error)
}

// HTTPConnector speaks a minimal REST subject API. Credentials are injected
// from the deployment (inline or via environment), never stored in receipts.
type HTTPConnector struct {
	SystemName    string
	BaseURL       string
	Credential    string
	CredentialEnv string
	Client        *http.Client
}

func (c HTTPConnector) System() string { return c.SystemName }

func (c HTTPConnector) credential() string {
	if c.CredentialEnv != "" {
		return os.Getenv(c.CredentialEnv)
	}
	return c.Credential
}

func (c HTTPConnector) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c HTTPConnector) subjectURL(ref string) string {
	return strings.TrimRight(c.BaseURL, "/") + "/subjects/" + url.PathEscape(ref)
}

func (c HTTPConnector) request(ctx context.Context, method, ref string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.subjectURL(ref), nil)
	if err != nil {
		return nil, err
	}
	if credential := c.credential(); credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	return c.client().Do(request)
}

// DeleteSubject deletes a subject; not_found is a successful idempotent replay.
func (c HTTPConnector) DeleteSubject(ctx context.Context,
	subjectRef string) (DeletionRecord, error) {
	record := DeletionRecord{System: c.SystemName, SubjectRef: subjectRef}
	response, err := c.request(ctx, http.MethodDelete, subjectRef)
	if err != nil {
		record.Outcome = OutcomeUnreachable
		return record, err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	switch {
	case response.StatusCode == http.StatusOK || response.StatusCode == http.StatusNoContent:
		record.Outcome = OutcomeDeleted
	case response.StatusCode == http.StatusNotFound:
		record.Outcome = OutcomeNotFound
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		record.Outcome = OutcomeForbidden
		return record, errors.New(c.SystemName + ": connector forbidden")
	default:
		record.Outcome = OutcomeUnreachable
		return record, fmt.Errorf("%s: HTTP %d", c.SystemName, response.StatusCode)
	}
	return record, nil
}

// VerifyAbsent re-queries the system to prove the subject is gone.
func (c HTTPConnector) VerifyAbsent(ctx context.Context, subjectRef string) (bool, error) {
	response, err := c.request(ctx, http.MethodGet, subjectRef)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return false, err
	}
	if response.StatusCode == http.StatusNotFound {
		return true, nil
	}
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%s: HTTP %d", c.SystemName, response.StatusCode)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, err
	}
	return payload["found"] == false, nil
}

// ExecuteErasure runs all connectors, minting a chained deletion receipt per
// successful action. Any failure halts the run with ERASURE_INCOMPLETE: no
// partial success is reported as completion.
func ExecuteErasure(ledger *Ledger, requestID, subjectRef string,
	connectors []DownstreamConnector, at time.Time) ([]*Receipt, error) {
	receipts := []*Receipt{}
	deadline := at.AddDate(0, 0, 30).Format(timeLayout)
	for _, connector := range connectors {
		record, err := connector.DeleteSubject(context.Background(), subjectRef)
		if err != nil || (record.Outcome != OutcomeDeleted && record.Outcome != OutcomeNotFound) {
			return receipts, fmt.Errorf("ERASURE_INCOMPLETE: %s: %v",
				connector.System(), err)
		}
		previous := stringsRepeatedZero
		if len(ledger.Receipts) > 0 {
			hash, hashErr := ledger.Receipts[len(ledger.Receipts)-1].Hash()
			if hashErr != nil {
				return receipts, hashErr
			}
			previous = hash
		}
		receipt := &Receipt{
			IssuedAt: at.Format(timeLayout), Fleet: "erasure",
			Actor:        map[string]any{"system": "agentid", "operation": "erasure.delete"},
			DelegationID: "system", Action: "erasure.delete",
			Resource: map[string]any{
				"type": "deletion", "id": connector.System(),
				"attributes": map[string]any{
					"erasure_request_id": requestID, "subject_ref": subjectRef,
					"system": connector.System(), "outcome": record.Outcome,
					"external_ref": record.ExternalRef, "deadline": deadline,
				},
			},
			Decision: map[string]any{"result": "allowed", "outcome": "valid",
				"reason": "downstream deletion executed",
				"deletion": map[string]any{
					"system": connector.System(), "outcome": record.Outcome,
					"erasure_request_id": requestID,
				}},
			Outcome:    map[string]any{"status": "succeeded", "blocked": false},
			ActionType: "deletion", PrevHash: previous, SignatureAlg: "ES256",
		}
		if err := ledger.Append(receipt); err != nil {
			return receipts, err
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

// VerifyErasure proves absence across all connectors, or reports residue.
func VerifyErasure(connectors []DownstreamConnector, subjectRef string) []string {
	problems := []string{}
	for _, connector := range connectors {
		absent, err := connector.VerifyAbsent(context.Background(), subjectRef)
		if err != nil {
			problems = append(problems, "VERIFY_FAILED: "+connector.System()+": "+err.Error())
			continue
		}
		if !absent {
			problems = append(problems, "RESIDUE_FOUND: "+connector.System())
		}
	}
	return problems
}
