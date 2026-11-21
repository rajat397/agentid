package agentid

import (
	"fmt"
	"math/big"
	"time"

	"github.com/rajat397/agentid/attest"
)

const timeLayout = "2006-01-02T15:04:05Z"

// ValidationOptions carries optional evidence into validation.
type ValidationOptions struct {
	Ledger       *Ledger
	Approval     map[string]any
	At           string
	Revoked      map[string]bool
	PublicKeys   map[string]string
	StatusLookup func(uri string, idx int) (int, error)
}

// Validate is the deterministic validator split from RP policy evaluation.
func Validate(chain []Delegation, action map[string]any, profile Profile,
	publicPEM []byte, opts ValidationOptions) ValidationResult {
	if err := NormalizeSensitivity(action); err != nil {
		return ValidationResult{Outcome: "invalid", Reason: err.Error()}
	}
	now := time.Now().UTC()
	if opts.At != "" {
		if parsed, err := time.Parse(timeLayout, opts.At); err == nil {
			now = parsed
		}
	}
	nowISO := now.Format(timeLayout)
	fail := func(reason string) ValidationResult {
		return ValidationResult{Outcome: "invalid", Reason: reason}
	}

	if len(chain) == 0 {
		return fail("empty delegation chain")
	}
	if opts.Revoked[chain[len(chain)-1].ID] {
		return fail("leaf delegation has been revoked")
	}
	if len(chain) > profile.MaxChainLength {
		return fail(fmt.Sprintf("chain depth %d exceeds profile max_chain_length %d",
			len(chain), profile.MaxChainLength))
	}

	// 1. Signatures — hop 1 uses the caller's root key, later hops the key
	// pinned in their parent's signed body (offline chain of custody).
	versionDrift := []any{}
	var leafKeyPEM []byte
	for i, delegation := range chain {
		alg := delegation.Signature.Alg
		if !profile.AllowsAlgorithm(alg) {
			return fail(fmt.Sprintf("signature algorithm '%s' not in profile allowlist", alg))
		}
		keyPEM := publicPEM
		if i == 0 {
			if opts.PublicKeys != nil {
				if published, ok := opts.PublicKeys[delegation.Signature.Kid]; ok {
					keyPEM = []byte(published)
				}
			}
		} else {
			parent := chain[i-1]
			pinned := stringField(parent.Actor, "verification_key")
			if pinned == "" {
				if delegation.Issuer != nil {
					return fail(fmt.Sprintf("chain hop %d has an issuer but no parent key pin", i+1))
				}
				keyPEM = publicPEM
			} else {
				if delegation.Issuer == nil ||
					stringField(delegation.Issuer, "id") != stringField(parent.Actor, "id") {
					return fail(fmt.Sprintf("chain hop %d issuer does not match parent actor", i+1))
				}
				if stringField(delegation.Issuer, "kid") != KeyFingerprint([]byte(pinned)) {
					return fail(fmt.Sprintf(
						"chain hop %d issuer key id does not match parent pin", i+1))
				}
				keyPEM = []byte(pinned)
			}
		}
		if i == len(chain)-1 {
			leafKeyPEM = keyPEM
		}
		key, err := ParsePublicPEM(keyPEM)
		if err != nil || !Verify(key, delegation.UnsignedBody(), delegation.Signature.Value) {
			return fail(fmt.Sprintf("invalid signature at chain hop %d", i+1))
		}
		if len(delegation.Signatures) > 0 {
			keys := opts.PublicKeys
			if len(keys) == 0 {
				keys = delegation.SignerKeys
			}
			for j, signature := range delegation.Signatures {
				material, ok := keys[signature.Kid]
				if ok && !VerifySignature(signature.Alg, material,
					delegation.UnsignedBody(), signature.Value) {
					return fail(fmt.Sprintf(
						"invalid additional signature[%d] at chain hop %d", j, i+1))
				}
			}
		}
	}

	// 2. Attenuation and expiry across hops.
	for i := 0; i+1 < len(chain); i++ {
		parent, child := chain[i], chain[i+1]
		parentVersion := versionFromMap(parent.Actor["version"])
		childVersion := versionFromMap(child.Actor["version"])
		if !versionEqual(parentVersion, childVersion) {
			from, to := map[string]any{}, map[string]any{}
			if parentVersion != nil {
				from = parentVersion.toMap()
			}
			if childVersion != nil {
				to = childVersion.toMap()
			}
			versionDrift = append(versionDrift, map[string]any{
				"type": "agent_version_drift", "from": from, "to": to,
				"status": "noted",
			})
		}
		if violation := AttenuationViolation(child.Constraints, parent.Constraints); violation != "" {
			return fail(violation)
		}
		parentExpiry, err1 := time.Parse(timeLayout, parent.ExpiresAt)
		childExpiry, err2 := time.Parse(timeLayout, child.ExpiresAt)
		if err1 == nil && err2 == nil && childExpiry.After(parentExpiry) {
			return fail("attenuation violated: child expiry exceeds parent")
		}
	}

	// 3. Leaf time and revocation status.
	leaf := chain[len(chain)-1]
	leafExpiry, err := time.Parse(timeLayout, leaf.ExpiresAt)
	if err != nil || leafExpiry.Before(now) {
		return fail("delegation expired")
	}
	if att := leaf.Attestation; att != nil {
		if stringField(leaf.Actor, "spiffe_id") != att.SPIFFEID {
			return fail("attestation does not bind the actor identity")
		}
		validUntil, err := time.Parse(timeLayout, att.ValidUntil)
		if err != nil || validUntil.Before(now) {
			return fail("attestation expired")
		}
		actorKey := stringField(leaf.Actor, "verification_key")
		if actorKey == "" {
			actorKey = string(leafKeyPEM)
		}
		if att.CredentialDigest != "" &&
			att.CredentialDigest != attest.CredentialDigest([]byte(actorKey)) {
			return fail("attestation credential digest mismatch")
		}
	}
	evaluated := []any{}
	if leaf.StatusList != nil {
		if opts.StatusLookup == nil {
			return fail("status list required but no lookup configured (fail closed)")
		}
		idx := intValue(leaf.StatusList["idx"])
		status, err := opts.StatusLookup(stringField(leaf.StatusList, "uri"), idx)
		if err != nil {
			return fail(fmt.Sprintf("status lookup failed: %v", err))
		}
		if status != 0x00 {
			name := map[int]string{0x01: "revoked", 0x02: "suspended"}[status]
			if name == "" {
				name = "unknown"
			}
			return fail(fmt.Sprintf("delegation %s (status 0x%02x)", name, status))
		}
		evaluated = append(evaluated, map[string]any{
			"constraint": "status", "uri": stringField(leaf.StatusList, "uri"),
			"idx": idx, "value": status, "satisfied": true,
		})
	}

	permissions, atoms, err := Normalize(leaf.Constraints)
	if err != nil {
		return fail("malformed constraints: " + err.Error())
	}
	want := Permission{Action: stringField(action, "action"), System: stringField(action, "system")}
	permitted := false
	for _, permission := range permissions {
		if permission == want {
			permitted = true
			break
		}
	}
	evaluated = append(evaluated, map[string]any{
		"constraint": "permission", "pair": []any{want.Action, want.System},
		"satisfied": permitted,
	})
	if !permitted {
		return ValidationResult{Outcome: "invalid", Reason: "action/system not permitted by delegation",
			ConstraintsEvaluated: evaluated}
	}
	for _, atom := range atoms {
		if !profile.AllowsPredicate(atom.Type) {
			return ValidationResult{Outcome: "invalid",
				Reason:               fmt.Sprintf("predicate '%s' not in profile %s", atom.Type, profile.URI),
				ConstraintsEvaluated: evaluated}
		}
	}

	envelope, err := BuildEnvelope(action)
	if err != nil {
		return fail(err.Error())
	}
	obligations := []any{}
	pinnedAudience := stringField(leaf.Constraints, "aud")
	actionAudience := stringValue(envelope.Attributes["aud"])
	if pinnedAudience != "" && actionAudience != pinnedAudience {
		return ValidationResult{Outcome: "invalid",
			Reason: "aud pinning: action audience " + actionAudience +
				" differs from grant audience " + pinnedAudience,
			ConstraintsEvaluated: evaluated}
	}
	if pinnedAudience != "" {
		evaluated = append(evaluated, map[string]any{
			"constraint": "aud", "aud": pinnedAudience, "satisfied": true,
		})
	}
	spendAudience := pinnedAudience
	if spendAudience == "" {
		spendAudience = actionAudience
	}
	ceiling := stringField(leaf.Constraints, "stage")
	if ceiling != "" || len(profile.StageAllowlist) > 0 {
		if !StageIsValid(envelope.Stage) {
			return ValidationResult{
				Outcome: "invalid", Reason: "action stage is missing or unknown",
				ConstraintsEvaluated: evaluated,
			}
		}
		if ceiling != "" && !StageWithin(ceiling, envelope.Stage) {
			return ValidationResult{
				Outcome:              "invalid",
				Reason:               "action stage " + envelope.Stage + " exceeds delegation ceiling " + ceiling,
				ConstraintsEvaluated: evaluated,
			}
		}
		if len(profile.StageAllowlist) > 0 {
			allowed := false
			for _, stage := range profile.StageAllowlist {
				if stage == envelope.Stage {
					allowed = true
					break
				}
			}
			if !allowed {
				return ValidationResult{
					Outcome:              "invalid",
					Reason:               "action stage " + envelope.Stage + " not in profile allowlist",
					ConstraintsEvaluated: evaluated,
				}
			}
		}
		evaluated = append(evaluated, map[string]any{
			"constraint": "stage", "stage": envelope.Stage, "ceiling": ceiling,
			"satisfied": true,
		})
	}
	if profile.RequireTrustedProvenance {
		provenance := stringValue(envelope.Attributes["provenance"])
		if provenance != ProvenanceTrusted {
			ok, why := checkUntrustedApproval(opts.Approval, leaf, action, now,
				profile.RequireSignedApprovals)
			evaluated = append(evaluated, map[string]any{
				"constraint": "provenance", "path": "/attributes/provenance",
				"observed": provenance, "satisfied": ok,
			})
			if !ok {
				if opts.Approval == nil {
					return ValidationResult{
						Outcome: "indeterminate",
						Reason:  "action derived from untrusted provenance; no acknowledgement supplied",
						Obligations: []any{map[string]any{
							"type": "cosign_untrusted", "observed": provenance,
							"status": "required",
						}},
						ConstraintsEvaluated: evaluated,
					}
				}
				return ValidationResult{
					Outcome:              "invalid",
					Reason:               "untrusted provenance acknowledgement failed: " + why,
					ConstraintsEvaluated: evaluated,
				}
			}
			obligations = append(obligations, map[string]any{
				"type": "cosign_untrusted", "observed": provenance,
				"status": "discharged", "approval_id": stringField(opts.Approval, "id"),
			})
		}
	}
	view := map[string]any{
		"action":     envelope.Action,
		"system":     envelope.System,
		"resource":   envelope.Resource,
		"attributes": envelope.Attributes,
		"nonce":      envelope.Nonce,
		"time":       nowISO,
	}
	typeProfile, err := TypeProfileFromMap(profile.TypeProfile)
	if err != nil {
		return ValidationResult{Outcome: "invalid", Reason: "type profile invalid: " + err.Error(),
			ConstraintsEvaluated: evaluated}
	}
	for _, atom := range atoms {
		observedValue, resolveErr := Resolve(view, atom.Path)
		if resolveErr == nil {
			if typeErr := typeProfile.Validate(atom.Path, observedValue, atom.Type); typeErr != nil {
				return ValidationResult{Outcome: "invalid", Reason: typeErr.Error(),
					ConstraintsEvaluated: evaluated}
			}
		}
		switch atom.Type {
		case "sum_max":
			observed, err := toDecimalValue(Resolve(view, atom.Path))
			if err != nil {
				return ValidationResult{Outcome: "invalid", Reason: "attribute " + atom.Path + " is missing",
					ConstraintsEvaluated: evaluated}
			}
			cap, err := toDecimal(atom.Max)
			if err != nil {
				return fail("malformed sum_max cap")
			}
			key := atom.Key
			if key == "" {
				key = stringField(action, "budget_key")
			}
			if key == "" {
				key = "budget"
			}
			periodStart := stringField(action, "period_start")
			if periodStart == "" {
				periodStart = "1970-01-01T00:00:00Z"
			}
			if atom.PeriodSeconds > 0 {
				periodStart = now.Add(-time.Duration(atom.PeriodSeconds) * time.Second).Format(timeLayout)
			}
			var currency *string
			if atom.Path == "/attributes/amount" {
				value := stringValue(envelope.Attributes["currency"])
				if value == "" {
					value = "USD"
				}
				currency = &value
			}
			spentString := "0.00"
			if opts.Ledger != nil {
				spentString, err = opts.Ledger.TotalFor(
					atom.Path, key, periodStart, currency, spendAudience)
				if err != nil {
					return fail("ledger sum failed: " + err.Error())
				}
			}
			spent, _ := toDecimal(spentString)
			remaining := new(big.Rat).Sub(cap, spent)
			satisfied := observed.Cmp(remaining) <= 0
			evaluated = append(evaluated, map[string]any{
				"constraint": "sum_max", "path": atom.Path, "budget": key,
				"cap": atom.Max, "spent": spentString, "satisfied": satisfied,
			})
			if !satisfied {
				total := new(big.Rat).Add(spent, observed)
				return ValidationResult{Outcome: "invalid",
					Reason: fmt.Sprintf("budget exhausted: %s exceeds cap %s for %s",
						total.FloatString(2), cap.FloatString(2), key),
					ConstraintsEvaluated: evaluated}
			}
			continue

		case "cosign_above":
			observed, err := toDecimalValue(Resolve(view, atom.Path))
			if err != nil {
				return ValidationResult{Outcome: "invalid", Reason: "attribute " + atom.Path + " is missing",
					ConstraintsEvaluated: evaluated}
			}
			threshold, err := toDecimal(atom.Value)
			if err != nil {
				return fail("malformed cosign threshold")
			}
			needed := observed.Cmp(threshold) > 0
			evaluated = append(evaluated, map[string]any{
				"constraint": "cosign_above", "path": atom.Path, "bound": atom.Value,
				"observed": observed.FloatString(2), "satisfied": !needed,
			})
			if !needed {
				continue
			}
			ok, why := checkApproval(opts.Approval, leaf, action, atom, observed, now,
				profile.RequireSignedApprovals)
			approvalID := ""
			if opts.Approval != nil {
				approvalID = stringField(opts.Approval, "id")
			}
			evaluated = append(evaluated, map[string]any{
				"constraint": "approval", "approval_id": approvalID,
				"satisfied": ok, "reason": why,
			})
			if !ok {
				if opts.Approval == nil {
					return ValidationResult{Outcome: "indeterminate",
						Reason: fmt.Sprintf("%s %s exceeds approval threshold %s; no approval supplied",
							atom.Path, observed.FloatString(2), threshold.FloatString(2)),
						Obligations: []any{map[string]any{
							"type": "cosign_above", "path": atom.Path, "value": atom.Value,
							"observed": observed.FloatString(2), "status": "required"}},
						ConstraintsEvaluated: evaluated}
				}
				return ValidationResult{Outcome: "invalid",
					Reason: fmt.Sprintf(
						"approval does not satisfy the cosign_above obligation (%s)", why),
					ConstraintsEvaluated: evaluated}
			}
			obligations = append(obligations, map[string]any{
				"type": "cosign_above", "path": atom.Path, "value": atom.Value,
				"observed": observed.FloatString(2), "status": "discharged",
				"approval_id": approvalID,
			})
			continue
		}

		satisfied, observed, _ := Evaluate(atom, view)
		bound := any(atom.Value)
		if atom.Type == "in" {
			bound = atom.Values
		} else if atom.Type == "window" {
			bound = atom.Start
		}
		evaluated = append(evaluated, map[string]any{
			"constraint": atom.Type, "path": atom.Path, "bound": bound,
			"observed": observed, "satisfied": satisfied,
		})
		if !satisfied {
			return ValidationResult{Outcome: "invalid",
				Reason: fmt.Sprintf("%s %s predicate violated (observed %v)",
					atom.Path, atom.Type, observed), ConstraintsEvaluated: evaluated}
		}
	}

	obligations = append(obligations, versionDrift...)
	return ValidationResult{Outcome: "valid", Reason: "within constraints",
		Obligations: CanonicalObligations(obligations), ConstraintsEvaluated: evaluated}
}

func toDecimalValue(value any, err error) (*big.Rat, error) {
	if err != nil {
		return nil, err
	}
	return toDecimal(value)
}

func checkApproval(approval map[string]any, leaf Delegation, action map[string]any,
	atom Atom, observed *big.Rat, now time.Time, requireSigned bool) (bool, string) {
	if approval == nil {
		return false, "no approval supplied"
	}
	if err := VerifyApprovalSignature(approval); err != nil {
		if AsMap(approval["signature"]) != nil || requireSigned {
			return false, err.Error()
		}
	}
	if stringField(approval, "delegation_id") != leaf.ID {
		return false, "approval names a different delegation"
	}
	if stringField(approval, "action") != stringField(action, "action") {
		return false, "approval names a different action"
	}
	if stringField(approval, "approver") == "" {
		return false, "approval has no approver identity"
	}
	if stringField(approval, "nonce") == "" {
		return false, "approval has no nonce"
	}
	if expiry := stringField(approval, "expires_at"); expiry != "" {
		if parsed, err := time.Parse(timeLayout, expiry); err == nil && parsed.Before(now) {
			return false, "approval expired"
		}
	}
	if digest := stringField(approval, "envelope_digest"); digest != "" {
		want, err := EnvelopeDigest(action)
		if err != nil || digest != want {
			return false, "approval digest does not bind this action envelope"
		}
		return true, "envelope-bound approval"
	}
	if atom.Path == "/attributes/amount" {
		value, err := toDecimal(approval["amount"])
		if err == nil && value.Cmp(observed) >= 0 {
			return true, "legacy amount approval"
		}
		return false, "approval amount is below the action"
	}
	return false, "approval does not bind an action envelope"
}

func checkUntrustedApproval(approval map[string]any, leaf Delegation,
	action map[string]any, now time.Time, requireSigned bool) (bool, string) {
	if approval == nil {
		return false, "no approval supplied"
	}
	if err := VerifyApprovalSignature(approval); err != nil {
		if AsMap(approval["signature"]) != nil || requireSigned {
			return false, err.Error()
		}
	}
	if stringField(approval, "delegation_id") != leaf.ID ||
		stringField(approval, "action") != stringField(action, "action") {
		return false, "approval names a different delegation or action"
	}
	if stringField(approval, "approver") == "" || stringField(approval, "nonce") == "" {
		return false, "approval lacks approver or nonce"
	}
	if approval["acknowledges_untrusted"] != true {
		return false, "approval does not acknowledge untrusted provenance"
	}
	digest := stringField(approval, "envelope_digest")
	if digest == "" {
		return false, "approval does not bind the action envelope"
	}
	want, err := EnvelopeDigest(action)
	if err != nil || digest != want {
		return false, "approval digest does not bind this action envelope"
	}
	if expiry := stringField(approval, "expires_at"); expiry != "" {
		if parsed, err := time.Parse(timeLayout, expiry); err == nil && parsed.Before(now) {
			return false, "approval expired"
		}
	}
	return true, "envelope-bound acknowledgement"
}
