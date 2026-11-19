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
	case "evidence":
		return cmdEvidence(args[1:], stdout, stderr)
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

type demoBundle struct {
	ledger        *Ledger
	delegation    Delegation
	approval      map[string]any
	signer        Signer
	denial        *Receipt
	allowed       *Receipt
	denialResult  ValidationResult
	allowedResult ValidationResult
}

func buildDemoLedger() (*demoBundle, error) {
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "demo_signer")
	if err != nil {
		return nil, err
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
		return nil, err
	}
	ledger := &Ledger{}
	denial, denialResult, err := Act(ledger, []Delegation{delegation}, map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads", "amount": "4500.00",
		"currency": "USD", "resource_type": "ad_credit_account",
		"resource_id": "acme_retail_meta", "external_ref": "meta_ad_order_993812",
		"personal_data_refs": []any{"cust_4471"},
	}, ExampleProfile(), publicPEM, ActOptions{Signer: signer})
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return &demoBundle{ledger: ledger, delegation: delegation, approval: approval,
		signer: signer, denial: denial, allowed: allowed,
		denialResult: denialResult, allowedResult: allowedResult}, nil
}

func cmdDemo(stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "DevSigner uses a local private key — NOT FOR PRODUCTION; use ExternalSigner with a KMS/HSM adapter.")
	bundle, err := buildDemoLedger()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "agentid — the full lifecycle, running against real Go code")
	fmt.Fprintf(stdout, "\n1. Human grants authority: %s (kid %s)\n",
		bundle.delegation.ID, bundle.delegation.Signature.Kid)
	fmt.Fprintf(stdout, "2. Over-cap action: %s — %s (receipt %s)\n",
		bundle.denialResult.Outcome, bundle.denialResult.Reason, bundle.denial.ID)
	fmt.Fprintf(stdout, "3. Within authority: %s (receipt %s)\n",
		bundle.allowedResult.Outcome, bundle.allowed.ID)
	fmt.Fprintf(stdout, "4. Four questions: agent=%s, subject=%s, credential=%s, approval=%s\n",
		stringField(bundle.allowed.Actor, "spiffe_id"),
		stringField(bundle.delegation.Subject, "id"),
		stringField(bundle.allowed.Actor, "credential_kid"),
		stringField(bundle.approval, "id"))
	bundle.ledger.Receipts[0].Action = "social.post.publish"
	problems := bundle.ledger.VerifyChain(bundle.ledger.SignerKeys)
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
	outPath := "anchors.jsonl"
	ledgerPath := ""
	demo := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--demo":
			demo = true
		case "--tsa":
			if i+1 < len(args) {
				i++
				tsaURL = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				outPath = args[i]
			}
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		}
	}
	var ledger *Ledger
	if demo {
		bundle, err := buildDemoLedger()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		ledger = bundle.ledger
	} else if ledgerPath != "" {
		loaded, err := loadLedgerFile(ledgerPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		ledger = loaded
	} else {
		fmt.Fprintln(stderr, "anchor requires --demo or --ledger <receipts.jsonl>")
		return 2
	}
	head, err := ChainHead(ledger)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stderr, "anchoring chain head %s… via %s\n", shortHash(head), tsaURL)
	record, err := AnchorLedger(ledger, tsaURL, 15*time.Second)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if outPath != "" {
		receiptsPath := outPath + ".ledger.jsonl"
		if err := writeReceipts(receiptsPath, ledger); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := appendAnchor(outPath, record); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "ledger receipts written to %s\nanchor record appended to %s\n",
			receiptsPath, outPath)
	}
	data, _ := json.MarshalIndent(record, "", "  ")
	fmt.Fprintln(stdout, string(data))
	return 0
}

func loadLedgerFile(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ledger := &Ledger{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		value, err := DecodeJSON([]byte(line))
		if err != nil {
			return nil, err
		}
		receipt := ReceiptFromMap(AsMap(value))
		if err := ledger.Append(&receipt); err != nil {
			return nil, err
		}
	}
	return ledger, nil
}

func writeReceipts(path string, ledger *Ledger) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	for _, receipt := range ledger.Receipts {
		if err := encoder.Encode(receipt.ToMap()); err != nil {
			return err
		}
	}
	return nil
}

func appendAnchor(path string, record map[string]any) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := CanonicalJSON(record)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
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
	ledger, err := loadLedgerFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
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
	fmt.Fprintf(stdout, "%d/%d anchors verify\n", ok, len(anchors))
	if ok != len(anchors) {
		return 1
	}
	return 0
}

func cmdEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: agentid evidence <export|verify>")
		return 2
	}
	switch args[0] {
	case "export":
		outPath := "evidence-bundle.json"
		demo := false
		ledgerPath, delegationsPath, profilePath := "", "", ""
		anchorsPath := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--demo":
				demo = true
			case "--out":
				if i+1 < len(args) {
					i++
					outPath = args[i]
				}
			case "--ledger":
				if i+1 < len(args) {
					i++
					ledgerPath = args[i]
				}
			case "--delegations":
				if i+1 < len(args) {
					i++
					delegationsPath = args[i]
				}
			case "--profile":
				if i+1 < len(args) {
					i++
					profilePath = args[i]
				}
			case "--anchors":
				if i+1 < len(args) {
					i++
					anchorsPath = args[i]
				}
			}
		}
		profile := ExampleProfile()
		var ledger *Ledger
		var delegations []Delegation
		var statusTokens []string
		extraKeys := map[string]string{}
		if demo {
			bundle, err := buildDemoLedger()
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			ledger = bundle.ledger
			delegations = []Delegation{bundle.delegation}
			token, err := BuildStatusToken("https://example.invalid/status",
				[]int{0x00, 0x01}, bundle.signer,
				int(dateTimeNow().Unix()), int(dateTimeNow().Unix())+600, 300)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			statusTokens = append(statusTokens, token)
		} else if ledgerPath != "" {
			loaded, err := loadLedgerFile(ledgerPath)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			ledger = loaded
			if profilePath != "" {
				data, err := os.ReadFile(profilePath)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				value, err := DecodeJSON(data)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				profile, err = ProfileFromMap(AsMap(value))
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
			}
			if delegationsPath != "" {
				data, err := os.ReadFile(delegationsPath)
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
					delegation, err := DelegationFromMap(AsMap(value))
					if err != nil {
						fmt.Fprintln(stderr, err)
						return 1
					}
					delegations = append(delegations, delegation)
					for kid, material := range delegation.SignerKeys {
						extraKeys[kid] = material
					}
				}
			}
		} else {
			fmt.Fprintln(stderr, "evidence export requires --demo or --ledger")
			return 2
		}
		var anchors []map[string]any
		if anchorsPath != "" {
			loaded, err := LoadAnchors(anchorsPath)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			anchors = loaded
		}
		bundle, err := BuildEvidenceBundle("default", ledger, delegations, profile,
			anchors, statusTokens, extraKeys)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := WriteBundle(outPath, bundle); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "wrote %s (digest %v, %d receipts)\n",
			outPath, bundle.Manifest["digest"], len(bundle.Receipts))
		return 0
	case "verify":
		path := ""
		for i := 1; i < len(args); i++ {
			if args[i] == "--file" && i+1 < len(args) {
				i++
				path = args[i]
			}
		}
		if path == "" {
			fmt.Fprintln(stderr, "evidence verify requires --file")
			return 2
		}
		bundle, err := LoadEvidenceBundle(path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		problems := VerifyEvidenceBundle(bundle)
		if len(problems) > 0 {
			for _, problem := range problems {
				fmt.Fprintf(stdout, "FAILED: %s\n", problem)
			}
			return 1
		}
		fmt.Fprintf(stdout, "evidence bundle VERIFIED (%d receipts, %d delegations, %d anchors, %d status tokens)\n",
			len(bundle.Receipts), len(bundle.Delegations), len(bundle.Anchors), len(bundle.StatusTokens))
		return 0
	default:
		fmt.Fprintf(stderr, "unknown evidence command %q\n", args[0])
		return 2
	}
}
