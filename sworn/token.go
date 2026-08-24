// Package sworn implements the SwornMail protocol core:
// Mode-2 connection tokens (tagged COSE_Sign1 over a CBOR payload) and
// operator record parsing, per draft-kafedzhy-swornmail-01.
package sworn

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Protocol constants (must match the I-D and the published Rust crate).
const (
	Version              = "SWORN1"
	DNSLabel             = "_sworn"
	DefaultUnitPrefixLen = 64
	MaxUnitPrefixLen     = 64 // -01: unit finer than /64 cannot aggregate under SLAAC
	MinPrefixLen         = 32 // -01: attested prefix length floor
	MaxPrefixLen         = 64 // -01: attested prefix length ceiling
	MaxTokenLifetime     = 24 * time.Hour
	SkewTolerance        = 300 * time.Second // -01: fixed clock-skew tolerance
	// ContentType is the COSE protected content-type header value that
	// domain-separates SwornMail tokens from any other COSE use of a key.
	ContentType = "application/sworn-token+cbor"
)

// CBOR map keys of the token payload, per I-D §Mode-2.
const (
	keyOperator = 1
	keyPrefix   = 2
	keyUnit     = 3
	keyIssuedAt = 4
	keyExpires  = 5
	keyRole     = 6
)

var validRoles = map[string]bool{"mta": true, "esp-tenant": true, "forwarder": true}

// globalUnicast is the 2000::/3 block; attested prefixes MUST lie within it.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// ineligibleSourceRanges are source-address ranges that MUST NOT be treated
// as within any attested prefix (embedded-IPv4 and transition mechanisms).
// Signers also MUST NOT attest a prefix overlapping the two that fall inside
// 2000::/3 (Teredo, 6to4).
var (
	ineligibleSourceRanges = mustPrefixes(
		"::ffff:0:0/96",  // IPv4-mapped
		"::/96",          // IPv4-compatible
		"64:ff9b::/96",   // NAT64 well-known
		"64:ff9b:1::/48", // NAT64 local
		"2001::/32",      // Teredo
		"2002::/16",      // 6to4
	)
	unicastForbiddenRanges = mustPrefixes("2001::/32", "2002::/16")
)

func mustPrefixes(ss ...string) []netip.Prefix {
	ps := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		ps[i] = netip.MustParsePrefix(s)
	}
	return ps
}

// Verification failure reasons. Distinct sentinel errors so callers can map
// them to the Authentication-Results reason-code taxonomy.
var (
	ErrMalformed       = errors.New("sworn: malformed token")
	ErrBadSignature    = errors.New("sworn: signature verification failed")
	ErrExpired         = errors.New("sworn: token expired")
	ErrNotYetValid     = errors.New("sworn: token not yet valid")
	ErrLifetimeTooLong = errors.New("sworn: token lifetime exceeds 24h")
	ErrOffPrefix       = errors.New("sworn: source address outside attested prefix")
	ErrIneligibleSrc   = errors.New("sworn: source address is not eligible global-unicast IPv6")
	ErrBadUnit         = errors.New("sworn: unit shorter than attested prefix or greater than 64")
	ErrBadPrefix       = errors.New("sworn: attested prefix non-canonical or out of range")
	ErrContentType     = errors.New("sworn: missing or wrong content-type header")
	ErrNoSelector      = errors.New("sworn: missing kid (selector) header")
	ErrHeaderConfusion = errors.New("sworn: protected/unprotected header conflict or crit present")
	ErrBadRole         = errors.New("sworn: missing or unregistered role")
	ErrBadValidity     = errors.New("sworn: exp not greater than iat")
)

// Payload is the signed claim: "connections from Prefix are operated by
// Operator; aggregate reputation at Unit granularity".
type Payload struct {
	Operator string
	Prefix   netip.Prefix
	Unit     uint8
	IssuedAt time.Time
	Expires  time.Time
	Role     string // "mta" | "esp-tenant" | "forwarder"
}

// Result of a successful verification.
type Result struct {
	Operator string
	// Unit is the reputation key: the source address masked to the
	// payload's unit length. Receivers key reputation on (Operator, Unit).
	Unit netip.Prefix
	// Selector is the token's kid header; the caller must have fetched the
	// verification key from <Selector>._sworn.<Operator>.
	Selector string
}

// prefix wire form: 16-byte address followed by one prefix-length byte.
func encodePrefix(p netip.Prefix) []byte {
	a16 := p.Addr().As16()
	return append(a16[:], byte(p.Bits()))
}

func decodePrefix(b []byte) (netip.Prefix, error) {
	if len(b) != 17 {
		return netip.Prefix{}, ErrMalformed
	}
	var a16 [16]byte
	copy(a16[:], b[:16])
	p := netip.PrefixFrom(netip.AddrFrom16(a16), int(b[16]))
	if err := validatePrefix(p); err != nil {
		return netip.Prefix{}, err
	}
	return p, nil
}

// validatePrefix enforces the -01 §Address and Prefix Constraints: valid,
// masked-canonical, within 2000::/3, length 32..64, and not overlapping a
// forbidden transition range.
func validatePrefix(p netip.Prefix) error {
	if !p.IsValid() || p.Addr().Is4() {
		return ErrBadPrefix
	}
	if p != p.Masked() {
		return ErrBadPrefix
	}
	if p.Bits() < MinPrefixLen || p.Bits() > MaxPrefixLen {
		return ErrBadPrefix
	}
	if !globalUnicast.Contains(p.Addr()) {
		return ErrBadPrefix
	}
	for _, r := range unicastForbiddenRanges {
		if p.Overlaps(r) {
			return ErrBadPrefix
		}
	}
	return nil
}

// eligibleSource reports whether a connecting address may be matched against
// an attested prefix at all (-01 §Address and Prefix Constraints): an
// ordinary global-unicast IPv6 address, excluding the embedded-IPv4 and
// transition ranges. The 2000::/3 gate also excludes link-local, ULA, and
// multicast sources.
func eligibleSource(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() {
		return false
	}
	if !globalUnicast.Contains(a) {
		return false
	}
	for _, r := range ineligibleSourceRanges {
		if r.Contains(a) {
			return false
		}
	}
	return true
}

// ValidDomain enforces the -01 operator-domain syntax: A-label form, total
// length <= 253, each label 1..63 octets of LDH not beginning/ending with
// '-'. This rejects empty labels, NUL, CR/LF (Authentication-Results header
// injection), wildcards, and U-labels before any value reaches a resolver or
// a log line. Exported for Mode-1 discovery, which applies the same rule to a
// reverse-tree pointer's d= value.
func ValidDomain(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

var (
	detEnc cbor.EncMode
	detDec cbor.DecMode
)

func init() {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	detEnc = m
	// Reject duplicate map keys — two payloads in one signature otherwise.
	// Non-deterministic-but-well-formed encodings (indefinite length,
	// non-minimal ints, unsorted keys) are accepted: the signature binds the
	// exact octets, so this is an interop nicety, not a security check, and
	// the reference implementations stay lenient together (see -01 §Token).
	d, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	if err != nil {
		panic(err)
	}
	detDec = d
}

func encodePayload(p Payload) ([]byte, error) {
	if p.Operator == "" {
		return nil, ErrMalformed
	}
	if err := validatePrefix(p.Prefix); err != nil {
		return nil, err
	}
	return detEnc.Marshal(map[int]any{
		keyOperator: p.Operator,
		keyPrefix:   encodePrefix(p.Prefix),
		keyUnit:     p.Unit,
		keyIssuedAt: p.IssuedAt.Unix(),
		keyExpires:  p.Expires.Unix(),
		keyRole:     p.Role,
	})
}

func decodePayload(b []byte) (Payload, error) {
	var raw map[int]cbor.RawMessage
	if err := detDec.Unmarshal(b, &raw); err != nil {
		return Payload{}, ErrMalformed
	}
	var (
		p   Payload
		pfx []byte
		iat int64
		exp int64
	)
	// REQUIRED keys.
	required := []struct {
		key int
		dst any
	}{
		{keyOperator, &p.Operator}, {keyPrefix, &pfx},
		{keyIssuedAt, &iat}, {keyExpires, &exp}, {keyRole, &p.Role},
	}
	for _, f := range required {
		rm, ok := raw[f.key]
		if !ok {
			return Payload{}, ErrMalformed
		}
		if err := cbor.Unmarshal(rm, f.dst); err != nil {
			return Payload{}, ErrMalformed
		}
	}
	if !ValidDomain(p.Operator) {
		return Payload{}, ErrMalformed
	}
	if iat < 0 || exp < 0 {
		return Payload{}, ErrMalformed
	}
	// OPTIONAL unit; absent means default.
	p.Unit = DefaultUnitPrefixLen
	if rm, ok := raw[keyUnit]; ok {
		if err := cbor.Unmarshal(rm, &p.Unit); err != nil {
			return Payload{}, ErrMalformed
		}
	}
	if !validRoles[p.Role] {
		return Payload{}, ErrBadRole
	}
	prefix, err := decodePrefix(pfx)
	if err != nil {
		return Payload{}, err
	}
	p.Prefix = prefix
	p.IssuedAt, p.Expires = time.Unix(iat, 0).UTC(), time.Unix(exp, 0).UTC()
	return p, nil
}

// Sign produces a Mode-2 token: tagged COSE_Sign1(EdDSA) over the CBOR
// payload, with the selector in the protected kid header and the protocol
// content-type binding (I-D -01 wire format). Ed25519 signing is
// deterministic (RFC 8032), so tokens are reproducible for fixed inputs —
// required for the published test vectors.
func Sign(p Payload, selector string, priv ed25519.PrivateKey) ([]byte, error) {
	if selector == "" {
		return nil, ErrNoSelector
	}
	if !p.Expires.After(p.IssuedAt) {
		return nil, ErrBadValidity
	}
	if p.Expires.Sub(p.IssuedAt) > MaxTokenLifetime {
		return nil, ErrLifetimeTooLong
	}
	if !validRoles[p.Role] {
		return nil, ErrBadRole
	}
	if err := validatePrefix(p.Prefix); err != nil {
		return nil, err
	}
	if int(p.Unit) < p.Prefix.Bits() || p.Unit > MaxUnitPrefixLen {
		return nil, ErrBadUnit
	}
	if p.Role == "esp-tenant" && int(p.Unit) != p.Prefix.Bits() {
		return nil, ErrBadUnit
	}
	payload, err := encodePayload(p)
	if err != nil {
		return nil, err
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, err
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
	msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte(selector)
	msg.Headers.Protected[cose.HeaderLabelContentType] = ContentType
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

// protectedHeaders enforces the -01 protected-header requirements: content
// type and kid present in the protected bucket, no header confusion with the
// unprotected bucket, and no crit header. Returns the selector from kid.
func protectedHeaders(msg *cose.Sign1Message) (string, error) {
	// crit forbidden.
	if _, ok := msg.Headers.Protected[cose.HeaderLabelCritical]; ok {
		return "", ErrHeaderConfusion
	}
	// No label may appear in both buckets, and 1/3/4 in particular MUST NOT
	// appear unprotected (they are sourced only from the signed bucket).
	for label := range msg.Headers.Unprotected {
		if _, dup := msg.Headers.Protected[label]; dup {
			return "", ErrHeaderConfusion
		}
	}
	for _, label := range []any{
		cose.HeaderLabelAlgorithm, cose.HeaderLabelContentType, cose.HeaderLabelKeyID,
	} {
		if _, ok := msg.Headers.Unprotected[label]; ok {
			return "", ErrHeaderConfusion
		}
	}
	// The signed alg MUST be the one the protocol verifies (EdDSA for the sole
	// registered k=ed25519); a differing alg is a header fault (permerror),
	// not a signature failure.
	if alg, ok := msg.Headers.Protected[cose.HeaderLabelAlgorithm]; !ok || alg != cose.AlgorithmEdDSA {
		return "", ErrHeaderConfusion
	}
	ct, ok := msg.Headers.Protected[cose.HeaderLabelContentType]
	if !ok {
		return "", ErrContentType
	}
	if s, isStr := ct.(string); !isStr || s != ContentType {
		return "", ErrContentType
	}
	kid, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]
	if !ok {
		return "", ErrNoSelector
	}
	b, isBytes := kid.([]byte)
	if !isBytes || !validSelector(b) {
		return "", ErrNoSelector
	}
	return string(b), nil
}

// ValidSelector reports whether s is a usable selector under the -01 kid
// syntax. Exported so sender-side tooling rejects an unpublishable selector
// at generation time using the same rule the verifier applies to kid.
func ValidSelector(s string) bool { return validSelector([]byte(s)) }

// EligibleSource reports whether a connecting address may be matched against
// an attested prefix at all. Exported so other implementations can be checked
// against this rule rather than against a restatement of it.
func EligibleSource(a netip.Addr) bool { return eligibleSource(a) }

// ValidatePrefix reports whether p is attestable under -01 §canon:
// masked-canonical, within 2000::/3, length 32..64, not overlapping Teredo
// or 6to4. Exported so record generators reject a prefix before it is
// published, using the verifier's own rule rather than a restatement of it.
// Returns ErrBadPrefix on any violation.
func ValidatePrefix(p netip.Prefix) error { return validatePrefix(p) }

// validSelector enforces the -01 kid syntax: a single DNS label, 1..63
// octets of LDH, not beginning or ending with '-'.
func validSelector(b []byte) bool {
	if len(b) < 1 || len(b) > 63 {
		return false
	}
	if b[0] == '-' || b[len(b)-1] == '-' {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// ParseUnverified runs the header and payload syntax checks — including the
// kid and operator-domain constraints — WITHOUT the signature, so a caller
// can learn (selector, operator) safely before fetching the key from
// <selector>._sworn.<operator>. It performs no DNS and no cryptography. This
// is the step the -01 §Verification check-3 ordering requires before any DNS
// query; callers MUST NOT resolve a name derived from an invalid token.
func ParseUnverified(token []byte) (selector, operator string, err error) {
	var msg cose.Sign1Message
	if err = msg.UnmarshalCBOR(token); err != nil {
		return "", "", ErrMalformed
	}
	selector, err = protectedHeaders(&msg)
	if err != nil {
		return "", "", err
	}
	p, err := decodePayload(msg.Payload)
	if err != nil {
		return "", "", err
	}
	return selector, p.Operator, nil
}

// Verify performs the -01 §Verification checks in a DoS-hardened order
// (cheap local checks before the caller's key is used). `now` is injected
// for testability; `source` is the connecting address; `pub` is the key the
// caller fetched from <selector>._sworn.<operator>.
func Verify(token []byte, pub ed25519.PublicKey, source netip.Addr, now time.Time) (Result, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		return Result{}, ErrMalformed
	}
	selector, err := protectedHeaders(&msg)
	if err != nil {
		return Result{}, err
	}
	p, err := decodePayload(msg.Payload)
	if err != nil {
		return Result{}, err
	}
	// Validity bounds on raw values (check 2), before signature/key use.
	if !p.Expires.After(p.IssuedAt) {
		return Result{}, ErrBadValidity
	}
	if p.Expires.Sub(p.IssuedAt) > MaxTokenLifetime {
		return Result{}, ErrLifetimeTooLong
	}
	if int(p.Unit) < p.Prefix.Bits() || p.Unit > MaxUnitPrefixLen {
		return Result{}, ErrBadUnit
	}
	if p.Role == "esp-tenant" && int(p.Unit) != p.Prefix.Bits() {
		return Result{}, ErrBadUnit
	}
	// Source eligibility and membership (cheap, no network).
	if !eligibleSource(source) {
		return Result{}, ErrIneligibleSrc
	}
	if !p.Prefix.Contains(source) {
		return Result{}, ErrOffPrefix
	}
	// Validity window with fixed skew (check 5).
	if now.Before(p.IssuedAt.Add(-SkewTolerance)) {
		return Result{}, ErrNotYetValid
	}
	if now.After(p.Expires.Add(SkewTolerance)) {
		return Result{}, ErrExpired
	}
	// Signature (check 4) — the only step needing the fetched key.
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return Result{}, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return Result{}, ErrBadSignature
	}
	unit, err := source.Prefix(int(p.Unit))
	if err != nil {
		return Result{}, fmt.Errorf("sworn: unit derivation: %w", err)
	}
	return Result{Operator: p.Operator, Unit: unit, Selector: selector}, nil
}
