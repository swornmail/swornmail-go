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

// Authorizes reports whether the policy explicitly covers a signed token
// prefix. A broader policy prefix may authorize a more specific token prefix,
// but never the reverse. Both prefixes must already meet the protocol's
// canonical address constraints.
func (r PolicyRecord) Authorizes(tokenPrefix netip.Prefix) bool {
	if r.Version != Version || validatePrefix(tokenPrefix) != nil {
		return false
	}
	for _, allowed := range r.Prefixes {
		if validatePrefix(allowed) == nil &&
			tokenPrefix.Bits() >= allowed.Bits() &&
			allowed.Contains(tokenPrefix.Addr()) {
			return true
		}
	}
	return false
}

// MaxPolicyPrefixes caps enumeration per I-D -01 §Policy Record.
const MaxPolicyPrefixes = 64

var (
	ErrRecordSyntax      = errors.New("sworn: record syntax error")
	ErrRecordVersion     = errors.New("sworn: unsupported record version")
	ErrRecordAlgorithm   = errors.New("sworn: unsupported algorithm")
	ErrRecordKey         = errors.New("sworn: invalid public key")
	ErrRecordUnitInvalid = errors.New("sworn: unit must cover no more space than every policy prefix and be at most 64")
	ErrRecordDupTag      = errors.New("sworn: duplicate record tag")
	ErrRecordPrefix      = errors.New("sworn: invalid or out-of-range prefix")
	ErrRecordRUA         = errors.New("sworn: rua must be a non-empty mailto: address")
)

// splitTags splits a record into (key, value) pairs, enforcing the shared
// -01 §Record Tag Parsing rules: v= first, no duplicate tag, no whitespace
// inside a value. Unknown tags are returned for the caller to ignore.
func splitTags(txt string) ([][2]string, error) {
	// A SwornMail record is printable ASCII by construction: domains are LDH,
	// prefixes and units are digits and punctuation, rua is a dot-atom. So the
	// rule is the simplest one three implementations can agree on exactly —
	// reject every byte outside 0x20..0x7E, plus HTAB.
	//
	// This is not pedantry. "Whitespace" is where parsers silently disagree:
	// Go's unicode.IsSpace covers U+00A0 and U+3000, Lua's %s is byte-wise,
	// and Rust's is_ascii_whitespace excludes VT. The same record then parses
	// differently in three places, and a value one verifier rejects another
	// trims into something that looks safe. Restricting the record to an
	// explicit octet set removes the disagreement at its source, and takes CR,
	// LF, NUL, DEL and every other C0 control with it.
	//
	// HTAB is admitted because a hand-edited zone file legitimately contains
	// one between tags, and all three implementations already strip it there
	// and reject it inside a value — so it is a byte operators use and nothing
	// disagrees about. Every other control is not.
	for i := 0; i < len(txt); i++ {
		if c := txt[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return nil, ErrRecordSyntax
		}
	}
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
		// Only SP and HTAB survive the octet gate above, and those are
		// exactly what "whitespace" means here.
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
	return strings.ToLower(domain), nil
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
			if !validRUAMailto(v) {
				return PolicyRecord{}, ErrRecordRUA
			}
			rec.RUA = v
		}
	}
	if rec.Version == "" {
		return PolicyRecord{}, ErrRecordSyntax
	}
	for _, prefix := range rec.Prefixes {
		if int(rec.Unit) < prefix.Bits() {
			return PolicyRecord{}, ErrRecordUnitInvalid
		}
	}
	return rec, nil
}

// validRUAMailto accepts one conservative RFC 5322 dot-atom mailbox. SwornMail
// aggregate reports do not need quoted local parts, URI parameters, or
// recipient lists; rejecting them removes parser differentials and prevents a
// report destination from becoming a header or command injection surface.
func validRUAMailto(value string) bool {
	address, ok := strings.CutPrefix(value, "mailto:")
	if !ok || strings.Count(address, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(address, "@")
	if local == "" || !ValidDomain(domain) {
		return false
	}
	for _, atom := range strings.Split(local, ".") {
		if atom == "" {
			return false
		}
		for _, c := range []byte(atom) {
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", rune(c)):
			default:
				return false
			}
		}
	}
	return true
}
