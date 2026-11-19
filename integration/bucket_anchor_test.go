package integration

import (
	"sync/atomic"
	"testing"
)

// Scenario: an air-gapped customer cannot use a public TSA. They anchor the
// chain head into their own bucket with their own key; an auditor verifies the
// stamp offline with only the stamp and the published public key.
func TestScenarioCustomerBucketAnchor(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))
	beforeTSA := atomic.LoadInt64(w.tsaCalls)
	w.ObserveBucketAnchors()
	if len(w.bucketStamps) == 0 {
		t.Fatal("customer bucket received no signed head-stamp")
	}
	if atomic.LoadInt64(w.tsaCalls) != beforeTSA {
		t.Fatal("bucket anchoring called the TSA path")
	}

	stamp := w.bucketStamps[0]
	if problems := w.VerifyBucketStamp(stamp); len(problems) > 0 {
		t.Fatalf("bucket stamp did not verify offline: %v", problems)
	}

	tampered := map[string]any{}
	for key, value := range stamp {
		tampered[key] = value
	}
	tampered["head_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
	if problems := w.VerifyBucketStamp(tampered); len(problems) == 0 {
		t.Fatal("tampered bucket stamp verified")
	}
}
