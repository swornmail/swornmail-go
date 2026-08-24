package sworn

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Record is a parsed <selector>._sworn key record, per I-D -01:
//
//	v=SWORN1; k=ed25519; pk=<base64>
//
// The selector lives in the QNAME, not the record body; operator policy
// (unit, testing, reports) lives in the separate _prefixes policy record.
type Record struct {
	Version   string
	Algorithm string
	PublicKey ed25519.PublicKey
}

// PolicyRecord is a parsed _prefixes._sworn policy record, per I-D -01:
//
//	v=SWORN1; p=2001:db8:f00::/48,...; u=64; t=y; rua=mailto:...
//
// It carries prefix enumeration (Mode 1 and audit) and operator-wide policy
// tags applying to both modes.
type PolicyRecord struct {
	Version  string
	Prefixes []netip.Prefix
	Unit     uint8
	Testing  bool
	RUA      string
}

// MaxPolicyPrefixes caps enumeration per I-D -01 §Policy Record.
const MaxPolicyPrefixes = 64

var (
	ErrRecordSyntax      = errors.New("sworn: record syntax error")
	ErrRecordVersion     = errors.New("sworn: unsupported record version")
	ErrRecordAlgorithm   = errors.New("sworn: unsupported algorithm")
	ErrRecordKey         = errors.New("sworn: invalid public key")
	ErrRecordUnitInvalid = errors.New("sworn: invalid unit value")
	ErrRecordDupTag      = errors.New("sworn: duplicate record tag")
	ErrRecordPrefix      = errors.New("sworn: invalid or out-of-range prefix")
	ErrRecordRUA         = errors.New("sworn: rua must be a non-empty mailto: address")
)

// splitTags splits a record into (key, value) pairs, enforcing the shared
// -01 §Record Tag Parsing rules: v= first, no duplicate tag, no whitespace
// inside a value. Unknown tags are returned for the caller to ignore.
func splitTags(txt string) ([][2]string, error) {
	var pairs [][2]string
	seen := map[string]bool{}
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, ErrRecordSyntax
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		// v= must be the first tag present. Counting position among the
		// emitted tags rather than among the raw segments is what makes a
		// leading ";" or an empty segment unable to smuggle a tag ahead of it.
		if len(pairs) == 0 && k != "v" {
			return nil, ErrRecordSyntax
		}
		if strings.ContainsAny(v, " \t") {
			return nil, ErrRecordSyntax
		}
		if seen[k] {
			return nil, ErrRecordDupTag
		}
		seen[k] = true
		pairs = append(pairs, [2]string{k, v})
	}
	return pairs, nil
}

// ParseRecord parses a <selector>._sworn key record. Unknown tags (including
// the -00 s= selector tag) are ignored for forward compatibility.
func ParseRecord(txt string) (Record, error) {
	pairs, err := splitTags(txt)
	if err != nil {
		return Record{}, err
	}
	var rec Record
	for _, kv := range pairs {
		k, v := kv[0], kv[1]
		switch k {
		case "v":
			if v != Version {
				return Record{}, ErrRecordVersion
			}
			rec.Version = v
		case "k":
			// Registry currently: ed25519. Unknown algorithms are a hard
			// error so verifiers fail closed to "no usable record"; the
			// caller maps that to sworn=none (never fail), fail-open overall.
			if v != "ed25519" {
				return Record{}, ErrRecordAlgorithm
			}
			rec.Algorithm = v
		case "pk":
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(raw) != ed25519.PublicKeySize {
				return Record{}, ErrRecordKey
			}
			rec.PublicKey = ed25519.PublicKey(raw)
		}
	}
	if rec.Version == "" || rec.Algorithm == "" || rec.PublicKey == nil {
		return Record{}, ErrRecordSyntax
	}
	return rec, nil
}

// ParsePointerRecord parses a reverse-tree pointer record
// (`_sworn.<nibbles>.ip6.arpa`), per I-D -01 §Discovery step 1:
//
//	v=SWORN1; d=<operator domain>
//
// It returns the operator domain, which MUST satisfy the operator-domain
// syntax of {{token}}. The named domain is still subject to step-3
// confirmation by the caller.
func ParsePointerRecord(txt string) (string, error) {
	pairs, err := splitTags(txt)
	if err != nil {
		return "", err
	}
	var version, domain string
	for _, kv := range pairs {
		switch kv[0] {
		case "v":
			if kv[1] != Version {
				return "", ErrRecordVersion
			}
			version = kv[1]
		case "d":
			domain = kv[1]
		}
	}
	if version == "" || domain == "" || !ValidDomain(domain) {
		return "", ErrRecordSyntax
	}
	return domain, nil
}

// ParsePolicyRecord parses a _prefixes._sworn policy record.
func ParsePolicyRecord(txt string) (PolicyRecord, error) {
	pairs, err := splitTags(txt)
	if err != nil {
		return PolicyRecord{}, err
	}
	rec := PolicyRecord{Unit: DefaultUnitPrefixLen}
	for _, kv := range pairs {
		k, v := kv[0], kv[1]
		switch k {
		case "v":
			if v != Version {
				return PolicyRecord{}, ErrRecordVersion
			}
			rec.Version = v
		case "p":
			for _, ps := range strings.Split(v, ",") {
				if ps == "" {
					continue
				}
				if len(rec.Prefixes) >= MaxPolicyPrefixes {
					break // ignore beyond the 64th
				}
				pfx, err := netip.ParsePrefix(ps)
				if err != nil || validatePrefix(pfx) != nil {
					return PolicyRecord{}, ErrRecordPrefix
				}
				rec.Prefixes = append(rec.Prefixes, pfx)
			}
		case "u":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > MaxUnitPrefixLen {
				return PolicyRecord{}, ErrRecordUnitInvalid
			}
			rec.Unit = uint8(n)
		case "t":
			for _, flag := range strings.Split(v, ":") {
				if flag == "y" {
					rec.Testing = true
				}
			}
		case "rua":
			// Only the mailto: scheme is defined. rua names a destination
			// receivers send aggregate reports to, so anything else is
			// rejected here rather than left for a report sender to
			// interpret — a parser that accepts an arbitrary URI hands its
			// consumers an attacker-chosen target.
			addr, ok := strings.CutPrefix(v, "mailto:")
			if !ok || addr == "" {
				return PolicyRecord{}, ErrRecordRUA
			}
			rec.RUA = v
		}
	}
	if rec.Version == "" {
		return PolicyRecord{}, ErrRecordSyntax
	}
	return rec, nil
}
