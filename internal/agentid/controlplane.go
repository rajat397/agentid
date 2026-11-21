package agentid

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// PolicyBundle is a signed, content-addressed profile snapshot published by
// the one control plane. Relying parties verify it with the published key.
type PolicyBundle struct {
	Profile   map[string]any `json:"profile"`
	Digest    string         `json:"digest"`
	IssuedAt  string         `json:"issued_at"`
	Signature Signature      `json:"signature"`
}

func (b PolicyBundle) body() map[string]any {
	return map[string]any{
		"profile": b.Profile, "digest": b.Digest, "issued_at": b.IssuedAt,
	}
}

// ControlPlane owns policy, revocation publication and anchor orchestration.
// It never sits on the per-action hot path.
type ControlPlane struct {
	mu       sync.RWMutex
	signer   Signer
	profiles map[string]Profile
	active   Profile
	registry Registry
	status   StatusPublisher
	anchors  *AnchorManager
}

// NewControlPlane assembles the single control plane from existing components.
func NewControlPlane(signer Signer, registry Registry, status StatusPublisher,
	anchors *AnchorManager) (*ControlPlane, error) {
	if signer == nil {
		return nil, errors.New("control plane needs a signer")
	}
	return &ControlPlane{
		signer: signer, profiles: map[string]Profile{},
		registry: registry, status: status, anchors: anchors,
	}, nil
}

// PublishPolicy stores and activates a profile, returning its digest.
func (c *ControlPlane) PublishPolicy(profile Profile) (string, error) {
	digest, err := profile.Digest()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profiles[digest] = profile
	c.active = profile
	return digest, nil
}

// PolicyBundle signs the currently active profile snapshot.
func (c *ControlPlane) PolicyBundle() (PolicyBundle, error) {
	c.mu.RLock()
	profile := c.active
	c.mu.RUnlock()
	if profile.Iss == "" {
		return PolicyBundle{}, errors.New("no policy published")
	}
	digest, err := profile.Digest()
	if err != nil {
		return PolicyBundle{}, err
	}
	bundle := PolicyBundle{
		Profile: profile.Document(), Digest: digest,
		IssuedAt: dateTimeNow().Format(timeLayout),
	}
	bundle.Signature, err = c.signer.Sign(bundle.body())
	return bundle, err
}

// PublishStatus renders the current registry state into a signed status token.
func (c *ControlPlane) PublishStatus() (string, error) {
	return c.status.Publish()
}

// ObserveAnchors delegates cadence and retry orchestration to the anchor manager.
func (c *ControlPlane) ObserveAnchors(ledger *Ledger) ([]map[string]any, error) {
	if c.anchors == nil {
		return nil, errors.New("no anchor manager configured")
	}
	return c.anchors.Observe(ledger, "")
}

// Snapshot describes control-plane state for operators.
func (c *ControlPlane) Snapshot() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	digest, _ := c.active.Digest()
	entries, _ := c.registry.Entries()
	return map[string]any{
		"active_policy_digest": digest,
		"published_policies":   len(c.profiles),
		"registry_entries":     len(entries),
	}
}

// PolicyCache holds the last verified policy bundle in a PEP. A stale or
// unverifiable cache fails closed rather than enforcing old authority.
type PolicyCache struct {
	mu        sync.RWMutex
	keys      map[string]string
	maxAge    time.Duration
	profile   Profile
	fetchedAt time.Time
	digest    string
}

// NewPolicyCache creates a cache with a freshness bound.
func NewPolicyCache(keys map[string]string, maxAge time.Duration) *PolicyCache {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	return &PolicyCache{keys: keys, maxAge: maxAge}
}

// Refresh verifies a bundle's signature and digest before installing it.
func (c *PolicyCache) Refresh(bundle PolicyBundle) error {
	material, ok := c.keys[bundle.Signature.Kid]
	if !ok || !VerifySignature(bundle.Signature.Alg, material,
		bundle.body(), bundle.Signature.Value) {
		return errors.New("policy bundle signature invalid or key unknown")
	}
	profile, err := ProfileFromMap(bundle.Profile)
	if err != nil {
		return err
	}
	digest, err := profile.Digest()
	if err != nil || digest != bundle.Digest {
		return errors.New("policy bundle digest mismatch")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profile, c.digest, c.fetchedAt = profile, digest, time.Now()
	return nil
}

// Profile returns the cached profile, failing closed beyond the freshness bound.
func (c *PolicyCache) Profile() (Profile, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fetchedAt.IsZero() || time.Since(c.fetchedAt) > c.maxAge {
		return Profile{}, fmt.Errorf(
			"policy cache stale beyond %s: fail closed", c.maxAge)
	}
	return c.profile, nil
}

// Expire simulates an unavailable control plane for tests and incident drills.
func (c *PolicyCache) Expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetchedAt = time.Time{}
}
