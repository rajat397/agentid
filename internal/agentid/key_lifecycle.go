package agentid

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type localKeyMeta struct {
	Kid       string `json:"kid"`
	Algorithm string `json:"algorithm"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

type publishedLocalKey struct {
	Kid       string `json:"kid"`
	State     string `json:"state"`
	PublicKey string `json:"public_key"`
}

func GenerateLocalKey(dir, kid string) (string, error) {
	if kid == "" {
		return "", errors.New("kid is required")
	}
	keyDir := filepath.Join(dir, kid)
	if _, err := os.Stat(keyDir); err == nil {
		return "", errors.New("key already exists: " + kid)
	}
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", err
	}
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return "", err
	}
	if err := writeMode(filepath.Join(keyDir, "private.pem"), privatePEM, 0600); err != nil {
		return "", err
	}
	if err := writeMode(filepath.Join(keyDir, "public.pem"), publicPEM, 0644); err != nil {
		return "", err
	}
	meta := localKeyMeta{
		Kid:       kid,
		Algorithm: "ES256",
		State:     "active",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeLocalKeyMeta(keyDir, meta); err != nil {
		return "", err
	}
	return keyDir, nil
}

func RotateLocalKey(dir, kid string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		keyDir := filepath.Join(dir, entry.Name())
		meta, err := readLocalKeyMeta(keyDir)
		if err != nil || meta.State != "active" {
			continue
		}
		meta.State = "previous"
		if err := writeLocalKeyMeta(keyDir, meta); err != nil {
			return "", err
		}
	}
	return GenerateLocalKey(dir, kid)
}

func PublishLocalKeys(dir, out string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	keys := []publishedLocalKey{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		keyDir := filepath.Join(dir, entry.Name())
		meta, err := readLocalKeyMeta(keyDir)
		if err != nil {
			return err
		}
		publicPEM, err := os.ReadFile(filepath.Join(keyDir, "public.pem"))
		if err != nil {
			return err
		}
		keys = append(keys, publishedLocalKey{
			Kid:       meta.Kid,
			State:     meta.State,
			PublicKey: string(publicPEM),
		})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Kid < keys[j].Kid })
	data, err := CanonicalJSON(map[string]any{"version": "v1", "keys": keys})
	if err != nil {
		return err
	}
	return writeMode(out, data, 0644)
}

func writeLocalKeyMeta(dir string, meta localKeyMeta) error {
	data, err := CanonicalJSON(meta)
	if err != nil {
		return err
	}
	return writeMode(filepath.Join(dir, "meta.json"), data, 0644)
}

func readLocalKeyMeta(dir string) (localKeyMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return localKeyMeta{}, err
	}
	var meta localKeyMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return localKeyMeta{}, err
	}
	if meta.Kid == "" || meta.State == "" {
		return localKeyMeta{}, errors.New("invalid key metadata")
	}
	return meta, nil
}

func writeMode(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
