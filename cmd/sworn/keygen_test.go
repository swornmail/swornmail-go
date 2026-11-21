package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// --force replaces the file whatever its mode was: the key never inherits a
// loose mode from the file it displaces.
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

// leftovers lists what is in dir besides the named files.
func leftovers(t *testing.T, dir string, expected ...string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var extra []string
next:
	for _, e := range entries {
		for _, want := range expected {
			if e.Name() == want {
				continue next
			}
		}
		extra = append(extra, e.Name())
	}
	return extra
}

// A --force write that fails part-way (a full disk, say) must leave the old
// key exactly as it was. Truncating the key file in place lost both: the old
// key was gone the moment the file was opened, and the new one never arrived.
func TestForcedWriteFailureKeepsTheOldKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "2026a.key")
	_, old, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, old, false); err != nil {
		t.Fatal(err)
	}

	diskFull := errors.New("no space left on device")
	encodeKeyPEM = func(w io.Writer, _ *pem.Block) error {
		_, _ = w.Write([]byte("-----BEGIN PRIV")) // some of it reaches the disk
		return diskFull
	}
	t.Cleanup(func() { encodeKeyPEM = pem.Encode })

	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, replacement, true); !errors.Is(err, diskFull) {
		t.Fatalf("writePrivateKey = %v, want the write error", err)
	}
	reread, err := loadPrivateKey(path)
	if err != nil {
		t.Fatalf("the old key is no longer readable: %v", err)
	}
	if !reread.Equal(old) {
		t.Error("a failed --force write changed the key on disk")
	}
	if extra := leftovers(t, dir, "2026a.key"); len(extra) != 0 {
		t.Errorf("a failed write left files behind: %v", extra)
	}
}

// Without --force a failed write must not leave a truncated key file either:
// the next keygen would refuse to overwrite it, and sign would fail on it.
func TestFailedFirstWriteLeavesNoKeyFile(t *testing.T) {
	dir := t.TempDir()
	diskFull := errors.New("no space left on device")
	encodeKeyPEM = func(w io.Writer, _ *pem.Block) error {
		_, _ = w.Write([]byte("-----BEGIN PRIV"))
		return diskFull
	}
	t.Cleanup(func() { encodeKeyPEM = pem.Encode })

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(filepath.Join(dir, "2026a.key"), priv, false); !errors.Is(err, diskFull) {
		t.Fatalf("writePrivateKey = %v, want the write error", err)
	}
	if extra := leftovers(t, dir); len(extra) != 0 {
		t.Errorf("a failed write left files behind: %v", extra)
	}
}

// Symlink attack: whoever can write to the key directory plants a link at the
// key's path, pointing at a file of their choosing. Opening the path to
// overwrite it follows the link, so the private key is written into their
// file, with the contents that were there destroyed. --force must replace the
// link itself and leave its target alone.
func TestForcedWriteReplacesASymlinkInsteadOfFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "2026a.key")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, priv, true); err != nil {
		t.Fatal(err)
	}

	if got, err := os.ReadFile(target); err != nil || string(got) != "not a key" {
		t.Errorf("the link target was written through: %q, %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("key path is %v, want a regular file in place of the link", info.Mode())
	}
	if perm := info.Mode().Perm(); perm != keyFilePerm {
		t.Errorf("key file mode = %#o, want %#o", perm, keyFilePerm)
	}
	if reread, err := loadPrivateKey(path); err != nil || !reread.Equal(priv) {
		t.Errorf("the new key is not at the key path: %v", err)
	}
	if extra := leftovers(t, dir, "2026a.key"); len(extra) != 0 {
		t.Errorf("the write left files behind: %v", extra)
	}
}

// Without --force a link at the path is an existing file like any other, even
// one that points nowhere: exclusive creation does not follow it.
func TestUnforcedWriteRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "absent")
	path := filepath.Join(dir, "2026a.key")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, priv, false); err == nil {
		t.Fatal("wrote a key through a dangling link")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link target was created: %v", err)
	}
}

// A key given outside DNS is held to the rule a published pk= value is: the
// offline path must not accept what no receiver would accept from the record.
func TestOfflineKeyIsHeldToTheRecordRule(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := encodePublicKey(pub)
	if got, err := decodeKey(good); err != nil || !got.Equal(pub) {
		t.Fatalf("decodeKey(canonical) = %x, %v", got, err)
	}

	// 43 characters carry 258 bits; the last two are padding and must be
	// zero. Setting one gives a second spelling of the same 32 octets.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, good[42])
	sloppy := good[:42] + string(alphabet[last|1]) + "="
	if last&1 == 1 {
		sloppy = good[:42] + string(alphabet[last|2]) + "="
	}
	if sloppy == good {
		t.Fatal("test bug: the second spelling is the canonical one")
	}

	for name, in := range map[string]string{
		"non-zero padding bits":  sloppy,
		"unpadded":               strings.TrimSuffix(good, "="),
		"base64url alphabet":     strings.NewReplacer("+", "-", "/", "_").Replace(good) + "-",
		"not a curve point":      "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // y = 2
		"31 octets":              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"33 octets":              good[:43] + "AAA=",
		"leading space":          " " + good,
		"trailing newline":       good + "\n",
		"line break inside":      good[:20] + "\n" + good[20:],
		"second tag smuggled in": good + "; x=y",
		"second pk smuggled in":  good + "; pk=" + good,
		"empty":                  "",
	} {
		if got, err := decodeKey(in); err == nil {
			t.Errorf("%s: decodeKey(%q) accepted as %x", name, in, got)
		}
	}
}

// Without --force the key is written beside its destination and then given
// the name with link(2), which cannot replace anything. Creating the file
// under its real name first, and removing it when the write failed, could
// remove a key that another run had put in place in the meantime.
func TestUnforcedWriteNeverTouchesAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "2026a.key")
	_, first, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePrivateKey(path, first, false); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _ := ed25519.GenerateKey(nil)
	if err := writePrivateKey(path, second, false); err == nil {
		t.Fatal("second unforced write succeeded over an existing key")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("existing key changed or vanished: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %d entries in the directory", len(entries))
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != keyFilePerm {
		t.Fatalf("mode = %v, want %o", info.Mode().Perm(), keyFilePerm)
	}
}
