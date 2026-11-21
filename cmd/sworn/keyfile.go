package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Signing keys are stored as PKCS#8 PEM — the form openssl and every
// mainstream key tool already reads — so an operator can inspect, back up,
// or move a SwornMail key without this CLI.
const (
	pemTypePrivate = "PRIVATE KEY"
	pemTypePublic  = "PUBLIC KEY"
	keyFilePerm    = 0o600
)

// writePrivateKey writes priv to path with owner-only permissions. Without
// force an existing file is never touched: silently destroying a signing key
// would revoke every token the operator has issued under that selector.
//
// With force the new key is written to a temporary file beside path and
// renamed over it, so the old key is replaced in one step or not at all.
// Opening path itself to truncate it did two things an operator would not
// expect of a key tool. A write that failed part-way (a full disk is enough)
// left neither key. And a symbolic link at path was followed, so the private
// key landed in whatever file the link named, which someone else with write
// access to the directory could have chosen. rename(2) replaces the link.
func writePrivateKey(path string, priv ed25519.PrivateKey, force bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: pemTypePrivate, Bytes: der}
	if !force {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFilePerm)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return fmt.Errorf("%s already exists; refusing to overwrite a signing key (pass --force to replace it)", path)
			}
			return err
		}
		if err := writeKeyFile(f, block); err != nil {
			// O_EXCL means this run created the file, so a truncated key
			// is ours to take away again.
			_ = os.Remove(path)
			return err
		}
		return nil
	}
	// os.CreateTemp opens with O_EXCL and mode 0600, in the destination's
	// own directory so the rename never crosses a filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if err := writeKeyFile(tmp, block); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return nil
}

// encodeKeyPEM is pem.Encode, held in a variable so a test can make the
// write fail part-way.
var encodeKeyPEM = pem.Encode

// writeKeyFile writes block to f, flushes it to stable storage and closes f.
// The mode is set explicitly rather than left to the creating call: a umask
// can only narrow it, but nothing here should depend on that.
func writeKeyFile(f *os.File, block *pem.Block) error {
	err := f.Chmod(keyFilePerm)
	if err == nil {
		err = encodeKeyPEM(f, block)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// loadPrivateKey reads an Ed25519 signing key written by keygen.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM; expected a PKCS#8 %q block as written by `sworn keygen`", path, pemTypePrivate)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 private key", path)
	}
	return priv, nil
}

// loadPublicKey resolves a --key argument that may be a key file (private or
// public, PEM or bare base64) or a base64 public key given inline.
func loadPublicKey(spec string) (ed25519.PublicKey, error) {
	if raw, err := os.ReadFile(spec); err == nil {
		return publicKeyFromFile(raw, spec)
	}
	pub, err := decodeKey(strings.TrimSpace(spec))
	if err != nil {
		return nil, fmt.Errorf("%q is neither a readable key file nor a base64 Ed25519 public key", spec)
	}
	return pub, nil
}

func publicKeyFromFile(raw []byte, path string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		// A file holding just the printed base64 public key.
		pub, err := decodeKey(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("%s: not a PEM key file and not a base64 Ed25519 public key", path)
		}
		return pub, nil
	}
	switch block.Type {
	case pemTypePrivate:
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an Ed25519 private key", path)
		}
		return priv.Public().(ed25519.PublicKey), nil
	case pemTypePublic:
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		pub, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an Ed25519 public key", path)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%s: unexpected PEM block %q", path, block.Type)
	}
}

// encodePublicKey renders a public key in the base64 form the pk= record tag
// uses (RFC 4648 §4, padded).
func encodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
