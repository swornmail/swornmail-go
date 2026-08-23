package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultSelectorIsPublishable(t *testing.T) {
	got := defaultSelector(time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC))
	if got != "2026a" {
		t.Errorf("defaultSelector = %q, want 2026a", got)
	}
}

func TestWritePrivateKeyPermsAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "2026a.key")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, priv, false); err != nil {
		t.Fatalf("first write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != keyFilePerm {
		t.Errorf("key file mode = %#o, want %#o", perm, keyFilePerm)
	}

	// A second keygen must not silently destroy the signing key.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, other, false); err == nil {
		t.Fatal("overwrote an existing key file without --force")
	}
	reread, err := loadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reread.Equal(priv) {
		t.Error("refused write still changed the key on disk")
	}

	if err := writePrivateKey(path, other, true); err != nil {
		t.Fatalf("--force write: %v", err)
	}
	reread, err = loadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reread.Equal(other) {
		t.Error("--force did not replace the key")
	}
}

// --force reuses the existing file, whose mode O_CREATE would leave alone.
func TestWritePrivateKeyForceRetightensPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose.key")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, priv, true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != keyFilePerm {
		t.Errorf("key file mode = %#o, want %#o", perm, keyFilePerm)
	}
}

func TestLoadPublicKeyAcceptedForms(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "k.key")
	if err := writePrivateKey(privPath, priv, false); err != nil {
		t.Fatal(err)
	}
	b64Path := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(b64Path, []byte(encodePublicKey(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, spec := range map[string]string{
		"private key file": privPath,
		"base64 file":      b64Path,
		"inline base64":    encodePublicKey(pub),
	} {
		got, err := loadPublicKey(spec)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !got.Equal(pub) {
			t.Errorf("%s: wrong key", name)
		}
	}

	for name, spec := range map[string]string{
		"garbage":      "not-a-key",
		"short key":    "AAAA",
		"missing file": filepath.Join(dir, "absent"),
	} {
		if _, err := loadPublicKey(spec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
