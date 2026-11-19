package agentid

import (
	"fmt"
	"math/big"
)

// Ledger is an append-only, hash-chained receipt trail.
type Ledger struct {
	Receipts   []*Receipt
	SignerKeys map[string]string
}

// RegisterKeys records public key material used to sign receipts in this ledger.
func (l *Ledger) RegisterKeys(keys map[string]string) {
	if l.SignerKeys == nil {
		l.SignerKeys = map[string]string{}
	}
	for kid, material := range keys {
		l.SignerKeys[kid] = material
	}
}

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

// VerifyHashes checks hash-chain links without requiring signature keys.
func (l *Ledger) VerifyHashes() []string {
	problems := []string{}
	expected := stringsRepeatedZero
	for i, receipt := range l.Receipts {
		if receipt.PrevHash != expected {
			problems = append(problems, fmt.Sprintf(
				"receipt[%d] prev_hash broken: expected %s… got %s…",
				i, expected[:12], receipt.PrevHash[:min(12, len(receipt.PrevHash))]))
			break
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

// VerifyChain checks hash links and all available signatures by algorithm.
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
		keys := publicKeys
		if keys == nil {
			keys = l.SignerKeys
		}
		if receipt.Signature != nil {
			material, ok := keys[receipt.Signature.Kid]
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"receipt[%d] signature not verified: no public keys supplied", i))
			} else if !VerifySignature(receipt.Signature.Alg, material,
				receipt.Body(), receipt.Signature.Value) {
				problems = append(problems, fmt.Sprintf(
					"receipt[%d] signature invalid or kid unknown", i))
			}
		}
		for j, signature := range receipt.Signatures {
			material, ok := keys[signature.Kid]
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"receipt[%d] additional signature[%d] not verified: key unknown", i, j))
			} else if !VerifySignature(signature.Alg, material,
				receipt.Body(), signature.Value) {
				problems = append(problems, fmt.Sprintf(
					"receipt[%d] additional signature[%d] invalid", i, j))
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
func (l *Ledger) TotalFor(path, key, periodStart string, currency *string,
	audience ...string) (string, error) {
	aud := ""
	if len(audience) > 0 {
		aud = audience[0]
	}
	total := new(big.Rat)
	for _, receipt := range l.Receipts {
		if stringField(receipt.Decision, "result") != "allowed" {
			continue
		}
		attributes := AsMap(AsMap(receipt.Resource)["attributes"])
		if stringValue(attributes["budget_key"]) != key {
			continue
		}
		if stringValue(attributes["aud"]) != aud {
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
