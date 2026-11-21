package agentid

import (
	"errors"
	"fmt"
	"regexp"
)

// IntentCompilation is a proposed delegation, never live authority. Only a
// human review signature over Digest can activate it.
type IntentCompilation struct {
	Text      string
	Plan      map[string]any
	Draft     Delegation
	Unmatched []string
	Digest    string
}

var (
	intentActor   = regexp.MustCompile(`(?i)agent\s+([a-z0-9._-]+)\s+may`)
	intentAction  = regexp.MustCompile(`(?i)purchase\s+ad\s+credit\s+on\s+([a-z0-9._-]+)`)
	intentAmount  = regexp.MustCompile(`(?i)up\s+to\s+([0-9]+(?:\.[0-9]+)?)\s*USD`)
	intentUntil   = regexp.MustCompile(`until\s+(\d{4}-\d{2}-\d{2})`)
	intentApprove = regexp.MustCompile(`(?i)require\s+approval\s+above\s+([0-9]+(?:\.[0-9]+)?)`)
	intentRegion  = regexp.MustCompile(`(?i)only\s+EU\s+region`)
)

// CompileIntent maps a bounded natural-language pattern set into a draft plan.
// Unknown clauses are returned as unmatched; nothing is guessed or invented.
func CompileIntent(text string) IntentCompilation {
	plan := map[string]any{}
	unmatched := []string{}

	if match := intentActor.FindStringSubmatch(text); match != nil {
		plan["actor_id"] = match[1]
	} else {
		unmatched = append(unmatched, "actor")
	}
	if match := intentAction.FindStringSubmatch(text); match != nil {
		plan["action"] = "ad.credit.purchase"
		plan["system"] = match[1]
	} else {
		unmatched = append(unmatched, "action/system")
	}
	if match := intentAmount.FindStringSubmatch(text); match != nil {
		plan["max_amount"] = match[1]
		plan["currency"] = "USD"
	}
	if match := intentUntil.FindStringSubmatch(text); match != nil {
		plan["expires_at"] = match[1] + "T23:59:59Z"
	} else {
		unmatched = append(unmatched, "expiry")
	}
	predicates := []any{}
	if match := intentApprove.FindStringSubmatch(text); match != nil {
		predicates = append(predicates, map[string]any{
			"type": "cosign_above", "path": "/attributes/amount", "value": match[1],
		})
	}
	if intentRegion.MatchString(text) {
		predicates = append(predicates, map[string]any{
			"type": "eq", "path": "/attributes/region", "value": "eu",
		})
	}
	if len(predicates) > 0 {
		plan["predicates"] = predicates
	}
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": stringValue(plan["action"]), "system": stringValue(plan["system"]),
		}},
	}
	if cap, ok := plan["max_amount"]; ok {
		constraints["max_amount"] = map[string]any{
			"value": cap, "currency": "USD",
		}
	}
	if predicates, ok := plan["predicates"]; ok {
		constraints["predicates"] = predicates
	}
	expires := stringValue(plan["expires_at"])
	if expires == "" {
		expires = "1970-01-01T00:00:00Z"
	}
	actorID := stringValue(plan["actor_id"])
	draft := Delegation{
		ID:      "draft_pending_review",
		Subject: map[string]any{"type": "human", "id": "pending_review"},
		Actor: map[string]any{
			"type": "agent", "id": actorID,
			"spiffe_id": "spiffe://example.trust/agent/" + actorID,
		},
		ChainDepth: 1, Constraints: constraints, ExpiresAt: expires,
		Draft: true,
	}
	body, _ := CanonicalJSON(map[string]any{
		"text": text, "plan": plan, "draft": draft.UnsignedBody(),
	})
	return IntentCompilation{
		Text: text, Plan: plan, Draft: draft, Unmatched: unmatched,
		Digest: DigestSHA256(body),
	}
}

// ToMap is the export form of a compilation candidate.
func (c IntentCompilation) ToMap() map[string]any {
	return map[string]any{
		"text": c.Text, "plan": c.Plan, "draft": c.Draft.ToMap(),
		"unmatched": stringsToAny(c.Unmatched), "digest": c.Digest,
	}
}

// ActivateIntent requires a human-signed approval of this exact compilation
// digest and returns a properly signed, live delegation.
func ActivateIntent(compilation IntentCompilation, approval map[string]any,
	signer Signer) (Delegation, error) {
	if len(compilation.Unmatched) > 0 {
		return Delegation{}, errors.New("cannot activate intent with unmatched clauses")
	}
	if err := VerifyApprovalSignature(approval); err != nil {
		return Delegation{}, err
	}
	if stringField(approval, "approves_compilation_digest") != compilation.Digest {
		return Delegation{}, errors.New("approval does not bind this compilation digest")
	}
	body := compilation.Draft.UnsignedBody()
	delete(body, "draft")
	body["issued_at"] = dateTimeNow().Format(timeLayout)
	signature, err := signer.Sign(body)
	if err != nil {
		return Delegation{}, fmt.Errorf("sign activation: %w", err)
	}
	draft := compilation.Draft
	draft.Draft = false
	draft.IssuedAt = stringValue(body["issued_at"])
	draft.Signature = signature
	draft.SignerKeys = map[string]string{
		signature.Kid: signer.PublicKeys()[signature.Kid],
	}
	return draft, nil
}
