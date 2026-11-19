// Command crosstest emits Go-produced signed artifacts for Python verification.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/rajat397/agentid/internal/agentid"
)

func main() {
	privatePEM, publicPEM, err := agentid.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	signer, err := agentid.NewDevSigner(privatePEM, publicPEM, "cross_key")
	if err != nil {
		panic(err)
	}
	delegation, err := agentid.CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr_1"}, "agent",
		map[string]any{"permissions": []any{map[string]any{
			"action": "support.ticket.resolve", "system": "zendesk"}}},
		"2030-01-01T00:00:00Z", agentid.DelegationOptions{Signer: signer})
	if err != nil {
		panic(err)
	}
	ledger := &agentid.Ledger{}
	receipt, result, err := agentid.Act(ledger, []agentid.Delegation{delegation}, map[string]any{
		"action": "support.ticket.resolve", "system": "zendesk",
		"resource_type": "ticket", "resource_id": "t1", "count": "1",
	}, agentid.ExampleProfile(), publicPEM, agentid.ActOptions{Signer: signer})
	if err != nil {
		panic(err)
	}
	token, err := agentid.BuildStatusToken("https://example.invalid/status",
		[]int{0x00, 0x01, 0x02}, signer, 1800000000, 1800000600, 300)
	if err != nil {
		panic(err)
	}
	output := map[string]any{
		"public_pem":         string(publicPEM),
		"delegation_body":    delegation.UnsignedBody(),
		"delegation_sig":     delegation.Signature.Value,
		"receipt_body":       receipt.Body(),
		"receipt_sig":        receipt.Signature.Value,
		"decision":           result.Outcome,
		"status_token":       token,
		"status_public_keys": signer.PublicKeys(),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(output); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "cross-test artifacts emitted")
}
