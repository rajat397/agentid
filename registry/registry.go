package registry

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// RegistryEntry is one subject's revocation state in the single-writer registry.
type RegistryEntry struct {
	SubjectID    string `json:"subject_id"`
	DelegationID string `json:"delegation_id"`
	StatusIdx    int    `json:"status_idx"`
	Revoked      bool   `json:"revoked"`
	UpdatedAt    string `json:"updated_at"`
}

// Registry is the authority ledger for revocation. Only the operator-side
// control plane writes; relying parties read published status tokens.
type Registry interface {
	Register(subjectID, delegationID string, idx int) error
	Revoke(subjectID string) error
	Entries() ([]RegistryEntry, error)
}

// FileRegistry is a stdlib, append-only, single-writer implementation. Each
// mutation is one JSON line; a process-local mutex serializes writers.
type FileRegistry struct {
	mu      sync.RWMutex
	path    string
	entries map[string]RegistryEntry
}

// OpenFileRegistry opens or creates a file-backed registry.
func OpenFileRegistry(path string) (*FileRegistry, error) {
	registry := &FileRegistry{path: path, entries: map[string]RegistryEntry{}}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry RegistryEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, err
		}
		registry.entries[entry.SubjectID] = entry
	}
	return registry, scanner.Err()
}

func (r *FileRegistry) append(entry RegistryEntry) error {
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

// Register pins a subject to a delegation and a status-list index.
func (r *FileRegistry) Register(subjectID, delegationID string, idx int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := RegistryEntry{
		SubjectID: subjectID, DelegationID: delegationID,
		StatusIdx: idx, Revoked: false, UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if err := r.append(entry); err != nil {
		return err
	}
	r.entries[subjectID] = entry
	return nil
}

// Revoke marks a subject revoked; unknown subjects are a failure, not a no-op.
func (r *FileRegistry) Revoke(subjectID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[subjectID]
	if !ok {
		return errors.New("cannot revoke unknown subject: " + subjectID)
	}
	entry.Revoked = true
	entry.UpdatedAt = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	if err := r.append(entry); err != nil {
		return err
	}
	r.entries[subjectID] = entry
	return nil
}

// Entries returns a snapshot of current registry state.
func (r *FileRegistry) Entries() ([]RegistryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RegistryEntry, 0, len(r.entries))
	for _, entry := range r.entries {
		out = append(out, entry)
	}
	return out, nil
}
