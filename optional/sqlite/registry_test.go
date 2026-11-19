package sqliteadapter

import (
	"path/filepath"
	"testing"
)

func TestSQLiteRegistryLifecycle(t *testing.T) {
	registry, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Register("usr_1", "dlg_1", 3); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke("usr_1"); err != nil {
		t.Fatal(err)
	}
	entries, err := registry.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].StatusIdx != 3 || !entries[0].Revoked {
		t.Fatalf("unexpected registry state: %+v", entries)
	}
	if err := registry.Revoke("unknown"); err == nil {
		t.Fatal("revoking unknown subject succeeded")
	}
}
