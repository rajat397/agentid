package integration

import (
	"testing"
	"time"

	"github.com/rajat397/agentid/internal/agentid"
)

// Scenario: a validly signed but year-old status token must not be accepted by
// a running PEP. Archived verification may use issued time; live enforcement
// must use the wall clock and max_status_age.
func TestScenarioReplayedStatusTokenRejected(t *testing.T) {
	w := NewWorld(t)

	old, err := agentid.BuildStatusToken("https://example.invalid/status",
		[]int{0x00}, w.signer, 1800000000, 1800000600, 300)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrapper.RefreshStatus(old, w.statusKeys, w.profile.MaxStatusAge); err == nil {
		t.Fatal("stale status token was accepted by the live PEP")
	}

	fresh, err := agentid.BuildStatusToken("https://example.invalid/status",
		[]int{0x00}, w.signer,
		int(time.Now().Unix()), int(time.Now().Add(time.Hour).Unix()), 300)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrapper.RefreshStatus(fresh, w.statusKeys, w.profile.MaxStatusAge); err != nil {
		t.Fatalf("fresh status token rejected: %v", err)
	}
}
