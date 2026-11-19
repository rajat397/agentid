package agentid

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Run dispatches the agentid CLI. It returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: agentid <version|demo|profile|erasure|anchor|verify-anchor>")
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "agentid 0.2.0 (go)")
		return 0
	case "profile":
		return cmdProfile(stdout)
	case "demo":
		return cmdDemo(stdout, stderr)
	case "erasure":
		return cmdErasure(args[1:], stdout)
	case "anchor":
		return cmdAnchor(args[1:], stdout, stderr)
	case "verify-anchor":
		return cmdVerifyAnchor(args[1:], stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func cmdProfile(stdout io.Writer) int {
	profile := ExampleProfile()
	data, err := CanonicalJSON(profile.document())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	digest, _ := profile.Digest()
	fmt.Fprintf(stdout, "%s\ndigest=%s\n", data, digest)
	return 0
}

func cmdDemo(stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "DevSigner uses a local private key — NOT FOR PRODUCTION; use ExternalSigner with a KMS/HSM adapter.")
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "demo_signer")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	subject := map[string]any{"type": "human", "id": "oidc|acme-retail|usr_8842"}
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
		"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
	}
	delegation, err := CreateDelegation(nil, subject, "marketing-agent", constraints,
		dateTimeNow().Add(30*time.Minute).Format(timeLayout), DelegationOptions{Signer: signer})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ledger := &Ledger{}
	denial, denialResult, err := Act(ledger, []Delegation{delegation}, map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads", "amount": "4500.00",
		"currency": "USD", "resource_type": "ad_credit_account",
		"resource_id": "acme_retail_meta", "external_ref": "meta_ad_order_993812",
		"personal_data_refs": []any{"cust_4471"},
	}, ExampleProfile(), publicPEM, ActOptions{Signer: signer})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	approval := map[string]any{
		"id": "apr_01DEMO", "delegation_id": delegation.ID,
		"action": "ad.credit.purchase", "amount": "2000.00",
		"approver": "oidc|acme-retail|usr_8842", "nonce": "nonce-demo",
	}
	allowed, allowedResult, err := Act(ledger, []Delegation{delegation}, map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
		"currency": "USD", "resource_type": "ad_credit_account",
		"resource_id": "acme_retail_meta", "external_ref": "meta_ad_order_993813",
		"personal_data_refs": []any{"cust_4471"},
	}, ExampleProfile(), publicPEM, ActOptions{Signer: signer, Approval: approval})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "agentid — the full lifecycle, running against real Go code")
	fmt.Fprintf(stdout, "\n1. Human grants authority: %s (kid %s)\n", delegation.ID, delegation.Signature.Kid)
	fmt.Fprintf(stdout, "2. Over-cap action: %s — %s (receipt %s)\n",
		denialResult.Outcome, denialResult.Reason, denial.ID)
	fmt.Fprintf(stdout, "3. Within authority: %s (receipt %s)\n", allowedResult.Outcome, allowed.ID)
	fmt.Fprintf(stdout, "4. Four questions: agent=%s, subject=%s, credential=%s, approval=%s\n",
		stringField(allowed.Actor, "spiffe_id"), stringField(delegation.Subject, "id"),
		stringField(allowed.Actor, "credential_kid"), stringField(approval, "id"))
	ledger.Receipts[0].Action = "social.post.publish"
	problems := ledger.VerifyChain(signer.PublicKeys())
	fmt.Fprintf(stdout, "5. Tampered receipt: signatures + hash chain verify: %t (%s)\n",
		len(problems) == 0, firstProblem(problems))
	return 0
}

func firstProblem(problems []string) string {
	if len(problems) == 0 {
		return "none"
	}
	return problems[0]
}

func cmdErasure(args []string, stdout io.Writer) int {
	subject := "cust_4471"
	ledgerPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		case "--demo":
		default:
			subject = args[i]
		}
	}
	ledger := &Ledger{}
	if ledgerPath == "" {
		privatePEM, publicPEM, err := GenerateKeyPair()
		if err != nil {
			return 1
		}
		signer, _ := NewDevSigner(privatePEM, publicPEM, "erasure_demo_signer")
		delegation, err := CreateDelegation(nil,
			map[string]any{"type": "human", "id": "usr"}, "support-agent",
			map[string]any{"permissions": []any{map[string]any{
				"action": "support.reply", "system": "zendesk"}}},
			"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
		if err != nil {
			return 1
		}
		for i := 0; i < 2; i++ {
			Act(ledger, []Delegation{delegation}, map[string]any{
				"action": "support.reply", "system": "zendesk",
				"personal_data_refs": []any{subject},
			}, ExampleProfile(), publicPEM, ActOptions{Signer: signer})
		}
	} else {
		data, err := os.ReadFile(ledgerPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			value, err := DecodeJSON([]byte(line))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			receipt := ReceiptFromMap(AsMap(value))
			if err := ledger.Append(&receipt); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
		}
	}
	registry := map[string][]any{}
	plan := BuildErasurePlan(ledger, subject, registry, nil, "EU")
	data, _ := json.MarshalIndent(plan.ToMap(), "", "  ")
	fmt.Fprintln(stdout, string(data))
	return 0
}

func cmdAnchor(args []string, stdout, stderr io.Writer) int {
	tsaURL := DefaultTSA
	ledgerPath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--tsa" && i+1 < len(args) {
			i++
			tsaURL = args[i]
		}
		if args[i] == "--ledger" && i+1 < len(args) {
			i++
			ledgerPath = args[i]
		}
	}
	ledger := &Ledger{}
	if ledgerPath != "" {
		data, err := os.ReadFile(ledgerPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			value, err := DecodeJSON([]byte(line))
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			receipt := ReceiptFromMap(AsMap(value))
			if err := ledger.Append(&receipt); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
		}
	} else {
		fmt.Fprintln(stderr, "anchor requires --ledger <receipts.jsonl>")
		return 2
	}
	record, err := AnchorLedger(ledger, tsaURL, 15*time.Second)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, _ := json.Marshal(record)
	fmt.Fprintln(stdout, string(data))
	return 0
}

func cmdVerifyAnchor(args []string, stdout io.Writer) int {
	anchorPath, ledgerPath := "", ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--file" && i+1 < len(args) {
			i++
			anchorPath = args[i]
		}
		if args[i] == "--ledger" && i+1 < len(args) {
			i++
			ledgerPath = args[i]
		}
	}
	if anchorPath == "" || ledgerPath == "" {
		fmt.Fprintln(os.Stderr, "verify-anchor requires --file and --ledger")
		return 2
	}
	anchors, err := LoadAnchors(anchorPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ledger := &Ledger{}
	for _, line := range strings.Split(string(ledgerData), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		value, err := DecodeJSON([]byte(line))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		receipt := ReceiptFromMap(AsMap(value))
		if err := ledger.Append(&receipt); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	ok := 0
	for _, anchor := range anchors {
		problems := VerifyAnchor(anchor, ledger)
		if len(problems) == 0 {
			ok++
			fmt.Fprintf(stdout, "anchor[%d] VERIFIED head=%s\n", ok, shortHash(stringField(anchor, "head_hash")))
		} else {
			fmt.Fprintf(stdout, "anchor[%d] FAILED: %s\n", ok+1, firstProblem(problems))
		}
	}
	if ok != len(anchors) {
		return 1
	}
	return 0
}
