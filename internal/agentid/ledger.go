package agentid

import (
	"fmt"
	"math/big"
)

// Ledger is an append-only, hash-chained receipt trail.
type Ledger struct{ Receipts []*Receipt }

// Append links a receipt to the current chain head and assigns its id.
func (l *Ledger) Append(receipt *Receipt) error {
	expected := stringsRepeatedZero
	if len(l.Receipts) > 0 {
		hash, err := l.Receipts[len(l.Receipts)-1].Hash()
		if err != nil {
			return err
		}
		expected = hash
	}
	if receipt.PrevHash != expected {
		return fmt.Errorf("prev_hash does not match the current chain head")
	}
	if receipt.ID == "" {
		data, err := CanonicalJSON(receipt.Body())
		if err != nil {
			return err
		}
		receipt.ID = "rcp_" + DigestSHA256(data)[:16]
	}
	l.Receipts = append(l.Receipts, receipt)
	return nil
}

const stringsRepeatedZero = "0000000000000000000000000000000000000000000000000000000000000000"

// VerifyChain checks hash links and, when keys are supplied, ES256 signatures.
func (l *Ledger) VerifyChain(publicKeys map[string]string) []string {
	problems := []string{}
	expected := stringsRepeatedZero
	for i, receipt := range l.Receipts {
		if receipt.PrevHash != expected {
			problems = append(problems, fmt.Sprintf(
				"receipt[%d] prev_hash broken: expected %s… got %s…",
				i, expected[:12], receipt.PrevHash[:min(12, len(receipt.PrevHash))]))
			break
		}
		if receipt.Signature != nil {
			if publicKeys == nil {
				problems = append(problems, fmt.Sprintf(
					"receipt[%d] signature not verified: no public keys supplied", i))
			} else {
				pem, ok := publicKeys[receipt.Signature.Kid]
				key, parseErr := ParsePublicPEM([]byte(pem))
				if !ok || parseErr != nil || !Verify(key, receipt.Body(), receipt.Signature.Value) {
					problems = append(problems, fmt.Sprintf(
						"receipt[%d] signature invalid or kid unknown", i))
				}
			}
		}
		hash, err := receipt.Hash()
		if err != nil {
			problems = append(problems, fmt.Sprintf("receipt[%d] hash failed: %v", i, err))
			break
		}
		expected = hash
	}
	if len(l.Receipts) == 0 {
		problems = append(problems, "ledger is empty")
	}
	return problems
}

// TotalFor sums one numeric attribute path for a root key within a period.
func (l *Ledger) TotalFor(path, key, periodStart string, currency *string) (string, error) {
	total := new(big.Rat)
	for _, receipt := range l.Receipts {
		if stringField(receipt.Decision, "result") != "allowed" {
			continue
		}
		attributes := AsMap(AsMap(receipt.Resource)["attributes"])
		if stringValue(attributes["budget_key"]) != key {
			continue
		}
		if currency != nil && stringValue(attributes["currency"]) != *currency {
			continue
		}
		if receipt.IssuedAt < periodStart {
			continue
		}
		observed, err := Resolve(map[string]any{"attributes": attributes}, path)
		if err != nil {
			continue
		}
		value, err := toDecimal(observed)
		if err != nil {
			continue
		}
		total.Add(total, value)
	}
	return total.FloatString(2), nil
}

// TotalSpend is the legacy money-shaped wrapper over TotalFor.
func (l *Ledger) TotalSpend(rootBudget, periodStart, currency string) (string, error) {
	return l.TotalFor("/attributes/amount", rootBudget, periodStart, &currency)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
