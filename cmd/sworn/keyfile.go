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
func writePrivateKey(path string, priv ed25519.PrivateKey, force bool) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, keyFilePerm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite a signing key (pass --force to replace it)", path)
		}
		return err
	}
	// O_CREATE leaves the mode of an existing file alone, so --force must
	// re-tighten permissions itself.
	err = f.Chmod(keyFilePerm)
	if err == nil {
		err = pem.Encode(f, &pem.Block{Type: pemTypePrivate, Bytes: der})
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
