// Package sqliteadapter provides a single-writer SQLite registry for agent
// revocation state. It is an optional module: the core stays stdlib-only.
package sqliteadapter

import (
	"database/sql"
	"errors"
	"time"

	"github.com/rajat397/agentid/registry"
	_ "modernc.org/sqlite"
)

// Registry stores revocation state in a caller-owned SQLite file.
type Registry struct {
	db *sql.DB
}

// Open opens or creates the registry database.
func Open(path string) (*Registry, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS entries (
		subject_id TEXT PRIMARY KEY,
		delegation_id TEXT NOT NULL,
		status_idx INTEGER NOT NULL,
		revoked INTEGER NOT NULL,
		updated_at TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Registry{db: db}, nil
}

// Close releases the database handle.
func (r *Registry) Close() error { return r.db.Close() }

func nowISO() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// Register pins a subject to a delegation and status index.
func (r *Registry) Register(subjectID, delegationID string, idx int) error {
	_, err := r.db.Exec(`INSERT INTO entries
		(subject_id, delegation_id, status_idx, revoked, updated_at)
		VALUES (?, ?, ?, 0, ?)
		ON CONFLICT(subject_id) DO UPDATE SET
		delegation_id=excluded.delegation_id, status_idx=excluded.status_idx,
		revoked=0, updated_at=excluded.updated_at`,
		subjectID, delegationID, idx, nowISO())
	return err
}

// Revoke marks a subject revoked; unknown subjects fail.
func (r *Registry) Revoke(subjectID string) error {
	result, err := r.db.Exec(`UPDATE entries SET revoked=1, updated_at=? WHERE subject_id=?`,
		nowISO(), subjectID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("cannot revoke unknown subject: " + subjectID)
	}
	return nil
}

// Entries returns the current registry snapshot.
func (r *Registry) Entries() ([]registry.RegistryEntry, error) {
	rows, err := r.db.Query(`SELECT subject_id, delegation_id, status_idx, revoked, updated_at FROM entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []registry.RegistryEntry{}
	for rows.Next() {
		var entry registry.RegistryEntry
		var revoked int
		if err := rows.Scan(&entry.SubjectID, &entry.DelegationID, &entry.StatusIdx,
			&revoked, &entry.UpdatedAt); err != nil {
			return nil, err
		}
		entry.Revoked = revoked != 0
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

var _ registry.Registry = (*Registry)(nil)
