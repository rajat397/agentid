package agentid

import (
	"github.com/rajat397/agentid/registry"
)

type RegistryEntry = registry.RegistryEntry
type Registry = registry.Registry
type FileRegistry = registry.FileRegistry

var OpenFileRegistry = registry.OpenFileRegistry

// StatusPublisher renders registry state into a signed Token Status List.
// StatusPublisher renders registry state into a signed Token Status List.
type StatusPublisher struct {
	Registry Registry
	Signer   Signer
	URI      string
	TTL      int
	MaxAge   int
}

// Publish builds a fresh statuslist+jwt from the registry snapshot.
func (p StatusPublisher) Publish() (string, error) {
	entries, err := p.Registry.Entries()
	if err != nil {
		return "", err
	}
	size := 0
	for _, entry := range entries {
		if entry.StatusIdx >= size {
			size = entry.StatusIdx + 1
		}
	}
	statuses := make([]int, size)
	for _, entry := range entries {
		if entry.StatusIdx >= 0 && entry.StatusIdx < size && entry.Revoked {
			statuses[entry.StatusIdx] = StatusRevoked
		}
	}
	ttl := p.TTL
	if ttl <= 0 {
		ttl = 300
	}
	now := int(dateTimeNow().Unix())
	return BuildStatusToken(p.URI, statuses, p.Signer, now, now+ttl*2, ttl)
}
