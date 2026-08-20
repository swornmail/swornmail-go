package sworn

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Record is a parsed _sworn TXT key/policy record, e.g.:
//
//	v=SWORN1; k=ed25519; s=2026a; pk=<base64>; u=64; l=https://log.example/...
type Record struct {
	Version   string
	Algorithm string
	Selector  string
	PublicKey ed25519.PublicKey
	Unit      uint8
	LogURL    string
}

var (
	ErrRecordSyntax      = errors.New("sworn: record syntax error")
	ErrRecordVersion     = errors.New("sworn: unsupported record version")
	ErrRecordAlgorithm   = errors.New("sworn: unsupported algorithm")
	ErrRecordKey         = errors.New("sworn: invalid public key")
	ErrRecordUnitInvalid = errors.New("sworn: invalid unit value")
)

// ParseRecord parses a _sworn TXT record. The v= tag MUST be first
// (SPF/DKIM convention); unknown tags are ignored for forward compatibility.
func ParseRecord(txt string) (Record, error) {
	rec := Record{Unit: DefaultUnitPrefixLen}
	parts := strings.Split(txt, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return Record{}, ErrRecordSyntax
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if i == 0 && k != "v" {
			return Record{}, ErrRecordSyntax
		}
		switch k {
		case "v":
			if v != Version {
				return Record{}, ErrRecordVersion
			}
			rec.Version = v
		case "k":
			// Registry currently: ed25519. Unknown algorithms are a hard
			// error so verifiers fail closed to "no usable record", which
			// the protocol treats as fail-open neutral overall.
			if v != "ed25519" {
				return Record{}, ErrRecordAlgorithm
			}
			rec.Algorithm = v
		case "s":
			rec.Selector = v
		case "pk":
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return Record{}, ErrRecordKey
			}
			rec.PublicKey = ed25519.PublicKey(raw)
		case "u":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 128 {
				return Record{}, ErrRecordUnitInvalid
			}
			rec.Unit = uint8(n)
		case "l":
			rec.LogURL = v
		}
	}
	if rec.Version == "" || rec.Algorithm == "" || rec.PublicKey == nil {
		return Record{}, ErrRecordSyntax
	}
	return rec, nil
}
