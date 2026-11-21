package agentid

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ApprovalRequest is a reviewable obligation raised by the PEP.
type ApprovalRequest struct {
	ID             string         `json:"id"`
	Action         string         `json:"action"`
	System         string         `json:"system"`
	DelegationID   string         `json:"delegation_id"`
	EnvelopeDigest string         `json:"envelope_digest"`
	Obligation     string         `json:"obligation"`
	Reason         string         `json:"reason"`
	Status         string         `json:"status"`
	CreatedAt      string         `json:"created_at"`
	ExpiresAt      string         `json:"expires_at"`
	Approval       map[string]any `json:"approval,omitempty"`
}

func (r ApprovalRequest) ToMap() map[string]any {
	return map[string]any{
		"id": r.ID, "action": r.Action, "system": r.System,
		"delegation_id": r.DelegationID, "envelope_digest": r.EnvelopeDigest,
		"obligation": r.Obligation, "reason": r.Reason, "status": r.Status,
		"created_at": r.CreatedAt, "expires_at": r.ExpiresAt,
	}
}

// ApprovalWorkflow is the caller-owned review queue for obligations the PEP
// already enforces. It never relaxes policy; it only issues signed evidence.
type ApprovalWorkflow struct {
	mu       sync.Mutex
	requests map[string]*ApprovalRequest
	counter  int
}

func NewApprovalWorkflow() *ApprovalWorkflow {
	return &ApprovalWorkflow{requests: map[string]*ApprovalRequest{}}
}

// Request creates a pending review item for an indeterminate decision.
func (w *ApprovalWorkflow) Request(action, system, delegationID, envelopeDigest,
	obligation, reason string) (*ApprovalRequest, error) {
	if envelopeDigest == "" {
		return nil, errors.New("approval request needs an action envelope digest")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.counter++
	now := dateTimeNow()
	id := fmt.Sprintf("apr_req_%08d", w.counter)
	request := &ApprovalRequest{
		ID: id, Action: action, System: system, DelegationID: delegationID,
		EnvelopeDigest: envelopeDigest, Obligation: obligation, Reason: reason,
		Status: "pending", CreatedAt: now.Format(timeLayout),
		ExpiresAt: now.Add(15 * time.Minute).Format(timeLayout),
	}
	w.requests[id] = request
	return request, nil
}

// Get returns one request by id.
func (w *ApprovalWorkflow) Get(id string) (*ApprovalRequest, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	request, ok := w.requests[id]
	if !ok {
		return nil, errors.New("unknown approval request: " + id)
	}
	copy := *request
	return &copy, nil
}

// List returns requests with a given status (or all when empty).
func (w *ApprovalWorkflow) List(status string) []ApprovalRequest {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []ApprovalRequest{}
	for _, request := range w.requests {
		if status == "" || request.Status == status {
			out = append(out, *request)
		}
	}
	return out
}

// Review approves or rejects a pending request. Approval produces a signed
// artifact bound to the request and the action envelope digest.
func (w *ApprovalWorkflow) Review(id string, approve bool,
	reviewer Signer, notes string) (*ApprovalRequest, error) {
	if approve && reviewer == nil {
		return nil, errors.New("approval requires a reviewer signer")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	request, ok := w.requests[id]
	if !ok {
		return nil, errors.New("unknown approval request: " + id)
	}
	if request.Status != "pending" {
		return nil, errors.New("approval request is not pending")
	}
	if !approve {
		request.Status = "rejected"
		return request, nil
	}
	approval := map[string]any{
		"id": "apr_" + request.ID, "delegation_id": request.DelegationID,
		"action": request.Action, "envelope_digest": request.EnvelopeDigest,
		"approver": reviewer.Kid(), "nonce": request.ID,
		"approves_request_id": request.ID, "expires_at": request.ExpiresAt,
	}
	if request.Obligation == "cosign_untrusted" {
		approval["acknowledges_untrusted"] = true
	}
	signed, err := SignApproval(approval, reviewer)
	if err != nil {
		return nil, err
	}
	request.Approval = signed
	request.Status = "approved"
	_ = notes
	return request, nil
}
