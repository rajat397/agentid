package agentid

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rajat397/agentid/attest"
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
	case "serve":
		return cmdServe(args[1:], stdout, stderr)
	case "mcp-serve":
		return cmdMCPServe(args[1:], stdout, stderr)
	case "mock-ads":
		return cmdMockAds(args[1:], stdout, stderr)
	case "anchor-watch":
		return cmdAnchorWatch(args[1:], stdout, stderr)
	case "retention":
		return cmdRetention(args[1:], stdout, stderr)
	case "erasure-exec":
		return cmdErasureExec(args[1:], stdout, stderr)
	case "otel-serve":
		return cmdOTelServe(args[1:], stdout, stderr)
	case "otel-demo":
		return cmdOTelDemo(args[1:], stdout, stderr)
	case "verify-signed":
		return cmdVerifySigned(args[1:], stdout, stderr)
	case "flow-demo":
		return cmdFlowDemo(args[1:], stdout, stderr)
	case "wrap":
		return cmdWrap(args[1:], stdout, stderr)
	case "claude-hook":
		return cmdClaudeHook(args[1:], stdout, stderr)
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
		dateTimeNow().Add(30*time.Minute).Format(timeLayout), DelegationOptions{
			Signer: signer,
			Attestor: attest.DevAttestor{
				SPIFFEID:  "spiffe://example.trust/agent/marketing-agent",
				PublicKey: publicPEM,
			},
		})
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
	reviewerPEM, reviewerPub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	reviewer, err := NewDevSigner(reviewerPEM, reviewerPub, "demo_reviewer")
	if err != nil {
		return nil, err
	}
	approval, err := SignApproval(map[string]any{
		"id": "apr_01DEMO", "delegation_id": delegation.ID,
		"action": "ad.credit.purchase", "amount": "2000.00",
		"approver": "oidc|acme-retail|usr_8842", "nonce": "nonce-demo",
	}, reviewer)
	if err != nil {
		return nil, err
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
	registry := map[string][]any{}
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
		registry[subject] = []any{
			map[string]any{"system": "zendesk", "records": 2, "method": "customer_connector"},
			map[string]any{"system": "internal_crm", "records": 31, "method": "customer_connector"},
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

func cmdServe(args []string, stdout, stderr io.Writer) int {
	bundlePath, addr := "", "127.0.0.1:8080"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bundle":
			if i+1 < len(args) {
				i++
				bundlePath = args[i]
			}
		case "--addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		}
	}
	if bundlePath == "" {
		fmt.Fprintln(stderr, "serve requires --bundle <evidence-bundle.json>")
		return 2
	}
	bundle, err := LoadEvidenceBundle(bundlePath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "mounting /receipts/verify and /v1/keys on %s (caller-owned infrastructure)\n", addr)
	return serveError(http.ListenAndServe(addr, NewVerificationHandler(bundle.SignerKeys)))
}

func serveError(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(os.Stderr, err)
	return 1
}

func cmdMCPServe(args []string, stdout, stderr io.Writer) int {
	configPath, addr, authEnv := "", "127.0.0.1:8090", ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			}
		case "--addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		case "--auth-token-env":
			if i+1 < len(args) {
				i++
				authEnv = args[i]
			}
		}
	}
	if configPath == "" || authEnv == "" {
		fmt.Fprintln(stderr, "mcp-serve requires --config <file> and --auth-token-env <NAME>")
		return 2
	}
	authToken := os.Getenv(authEnv)
	if authToken == "" {
		fmt.Fprintf(stderr, "environment variable %s is not set\n", authEnv)
		return 2
	}
	wrapper, err := LoadMCPWrapper(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	wrapper.SetAuthToken(authToken)
	fmt.Fprintf(stdout, "MCP wrapper mounted on %s (authenticated; credentials held by wrapper)\n", addr)
	return serveError(http.ListenAndServe(addr, NewMCPHandler(wrapper)))
}

func cmdMockAds(args []string, stdout, stderr io.Writer) int {
	envName, addr := "MOCK_ADS_TOKEN", "127.0.0.1:8091"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--credential-env":
			if i+1 < len(args) {
				i++
				envName = args[i]
			}
		case "--addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		}
	}
	credential := os.Getenv(envName)
	if credential == "" {
		fmt.Fprintf(stderr, "environment variable %s is not set\n", envName)
		return 2
	}
	fmt.Fprintf(stdout, "mock meta-ads mounted on %s\n", addr)
	return serveError(http.ListenAndServe(addr, MockMetaAdsHandler(credential)))
}

func cmdAnchorWatch(args []string, stdout, stderr io.Writer) int {
	ledgerPath, tsaURL, outPath := "", "", "anchors.jsonl"
	flavor, bucketDir, signerKeyPath := "rfc3161", "", ""
	every := 1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		case "--tsa":
			if i+1 < len(args) {
				i++
				tsaURL = args[i]
			}
		case "--every":
			if i+1 < len(args) {
				i++
				every = intValue(args[i])
			}
		case "--out":
			if i+1 < len(args) {
				i++
				outPath = args[i]
			}
		case "--flavor":
			if i+1 < len(args) {
				i++
				flavor = args[i]
			}
		case "--bucket-dir":
			if i+1 < len(args) {
				i++
				bucketDir = args[i]
			}
		case "--signer-key":
			if i+1 < len(args) {
				i++
				signerKeyPath = args[i]
			}
		}
	}
	if ledgerPath == "" {
		fmt.Fprintln(stderr, "anchor-watch requires --ledger <receipts.jsonl>")
		return 2
	}
	ledger, err := loadLedgerFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if every <= 0 {
		every = 1
	}
	config := AnchorConfig{
		Flavor: flavor, BucketDir: bucketDir,
		TSAURL: tsaURL, StrictCA: true,
		Cadence: AnchorCadence{MaxReceipts: every},
	}
	if flavor == "bucket" {
		keyData, err := os.ReadFile(signerKeyPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		key, err := ParsePrivatePEM(keyData)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		publicPEM, err := PublicPEMFromPrivate(key)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		config.BucketSigner, err = NewDevSigner(keyData, publicPEM, "bucket_signer")
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	manager, err := NewAnchorManager(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	anchors, err := manager.Observe(ledger, "")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	file, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer file.Close()
	for _, anchor := range anchors {
		data, err := CanonicalJSON(anchor)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := file.Write(append(data, '\n')); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "%d anchors written to %s; %d pending retry\n",
		len(anchors), outPath, len(manager.Pending()))
	return 0
}

func cmdRetention(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "usage: agentid retention export --ledger <file> --archive-dir <dir> [--at ISO]")
		return 2
	}
	ledgerPath, archiveDir, atValue := "", "", ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		case "--archive-dir":
			if i+1 < len(args) {
				i++
				archiveDir = args[i]
			}
		case "--at":
			if i+1 < len(args) {
				i++
				atValue = args[i]
			}
		}
	}
	if ledgerPath == "" || archiveDir == "" {
		fmt.Fprintln(stderr, "retention export requires --ledger and --archive-dir")
		return 2
	}
	ledger, err := loadLedgerFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	at := time.Now()
	if atValue != "" {
		if parsed, err := time.Parse(timeLayout, atValue); err == nil {
			at = parsed
		}
	}
	path, receipt, err := ExportArchive(ledger, RetentionPolicy{
		WindowMonths: DefaultRetentionMonths, ArchiveDir: archiveDir,
	}, at)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "archived to %s (receipt %s)\n", path, receipt.ID)
	return 0
}

type erasureConnectorConfig struct {
	System        string `json:"system"`
	URL           string `json:"url"`
	CredentialEnv string `json:"credential_env"`
}

func cmdErasureExec(args []string, stdout, stderr io.Writer) int {
	subject, ledgerPath, configPath, requestID := "", "", "", "erasure_request"
	verify := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--subject":
			if i+1 < len(args) {
				i++
				subject = args[i]
			}
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		case "--config":
			if i+1 < len(args) {
				i++
				configPath = args[i]
			}
		case "--request":
			if i+1 < len(args) {
				i++
				requestID = args[i]
			}
		case "--verify":
			verify = true
		}
	}
	if subject == "" || ledgerPath == "" || configPath == "" {
		fmt.Fprintln(stderr, "erasure-exec requires --subject, --ledger and --config")
		return 2
	}
	ledger, err := loadLedgerFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var configs []erasureConnectorConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	connectors := []DownstreamConnector{}
	for _, config := range configs {
		connectors = append(connectors, HTTPConnector{
			SystemName: config.System, BaseURL: config.URL,
			CredentialEnv: config.CredentialEnv,
		})
	}
	receipts, err := ExecuteErasure(ledger, requestID, subject, connectors, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%d deletion receipts minted\n", len(receipts))
	if verify {
		problems := VerifyErasure(connectors, subject)
		for _, problem := range problems {
			fmt.Fprintf(stdout, "%s\n", problem)
		}
		if len(problems) > 0 {
			return 1
		}
		fmt.Fprintln(stdout, "all systems verified absent")
	}
	return 0
}

func cmdOTelServe(args []string, stdout, stderr io.Writer) int {
	ledgerPath, addr := "", "127.0.0.1:4318"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ledger":
			if i+1 < len(args) {
				i++
				ledgerPath = args[i]
			}
		case "--addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		}
	}
	if ledgerPath == "" {
		fmt.Fprintln(stderr, "otel-serve requires --ledger <receipts.jsonl>")
		return 2
	}
	ledger, err := loadLedgerFile(ledgerPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "reconciling collector on %s (/v1/traces, /metrics)\n", addr)
	return serveError(http.ListenAndServe(addr, NewCollector(ledger).Handler()))
}

func cmdOTelDemo(args []string, stdout, stderr io.Writer) int {
	summary := false
	for _, arg := range args {
		if arg == "--summary" {
			summary = true
		}
	}
	bundle, err := buildDemoLedger()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	receipt := bundle.ledger.Receipts[1]
	trace := TraceContext{
		TraceID: stringField(receipt.Decision, "trace_id"),
		SpanID:  stringField(receipt.Decision, "span_id"),
	}
	spans := BuildEvidenceSpans(receipt, bundle.delegation, trace, false)
	result := NewCollector(bundle.ledger).Ingest(spans)
	if summary {
		kinds := []string{}
		for _, span := range spans {
			kinds = append(kinds, stringField(span, "kind"))
		}
		fmt.Fprintf(stdout, "five spans: %s\n", strings.Join(kinds, ", "))
		fmt.Fprintf(stdout, "reconciliation: agentid.mismatch = %v\n", result["count"])
		fmt.Fprintln(stdout, "propagation: W3C traceparent + agentid authority tracestate")
		fmt.Fprintln(stdout, "PII: subject refs pseudonymous by default")
		return 0
	}
	data, _ := CanonicalJSON(map[string]any{
		"spans": spans, "reconciliation": result,
	})
	fmt.Fprintln(stdout, string(data))
	return 0
}

func cmdVerifySigned(args []string, stdout, stderr io.Writer) int {
	path := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--artifact" && i+1 < len(args) {
			i++
			path = args[i]
		}
	}
	if path == "" {
		fmt.Fprintln(stderr, "verify-signed requires --artifact <file>")
		return 2
	}
	algorithms, err := VerifySignedArtifact(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "FULLY VERIFIED: %v\n", algorithms)
	return 0
}

func cmdFlowDemo(args []string, stdout, stderr io.Writer) int {
	mode := "allow"
	for i := 0; i < len(args); i++ {
		if args[i] == "--mode" && i+1 < len(args) {
			i++
			mode = args[i]
		}
	}
	if mode != "allow" && mode != "deny" {
		fmt.Fprintln(stderr, "flow-demo --mode must be allow or deny")
		return 2
	}
	trace, err := FlowDemoTrace(mode)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, _ := json.Marshal(trace)
	fmt.Fprintln(stdout, string(data))
	return 0
}

func cmdWrap(args []string, stdout, stderr io.Writer) int {
	configPath := ""
	separator := -1
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			i++
			configPath = args[i]
		}
		if arg == "--" {
			separator = i
			break
		}
	}
	if configPath == "" || separator < 0 || separator+1 >= len(args) {
		fmt.Fprintln(stderr, "usage: agentid wrap --config <file> -- <mcp-server-command> [args...]")
		return 2
	}
	wrapper, err := LoadMCPWrapper(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	proxy := NewMCPProxy(wrapper)
	command := exec.Command(args[separator+1], args[separator+2:]...)
	command.Stderr = stderr
	childIn, err := command.StdinPipe()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	childOut, err := command.StdoutPipe()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := command.Start(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var outMu sync.Mutex
	writeOut := func(data []byte) {
		outMu.Lock()
		defer outMu.Unlock()
		fmt.Fprintln(stdout, string(data))
	}
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			forward, response := proxy.ProcessClient(context.Background(), scanner.Bytes())
			if response != nil {
				writeOut(response)
				continue
			}
			if forward {
				childIn.Write(append(scanner.Bytes(), '\n'))
			}
		}
		childIn.Close()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		scanner := bufio.NewScanner(childOut)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		for scanner.Scan() {
			response, err := proxy.ProcessServerResponse(scanner.Bytes())
			if err != nil {
				continue
			}
			writeOut(response)
		}
	}()

	<-done
	<-done
	if err := command.Wait(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func cmdClaudeHook(args []string, stdout, stderr io.Writer) int {
	configPath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			i++
			configPath = args[i]
		}
	}
	if configPath == "" {
		fmt.Fprintln(stderr, "claude-hook requires --config <file>")
		return 2
	}
	wrapper, err := LoadMCPWrapper(configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	output, err := NewClaudeHookAdapter(wrapper).ProcessHook(context.Background(), input)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(output) > 0 {
		fmt.Fprintln(stdout, string(output))
	}
	return 0
}
