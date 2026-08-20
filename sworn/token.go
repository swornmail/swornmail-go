// Package sworn implements the SwornMail protocol core:
// Mode-2 connection tokens (COSE_Sign1 over a CBOR payload) and
// operator record parsing, per draft-swornmail-protocol-00.
package sworn

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Protocol constants (must match the I-D and the published Rust crate).
const (
	Version              = "SWORN1"
	DNSLabel             = "_sworn"
	DefaultUnitPrefixLen = 64
	MaxTokenLifetime     = 24 * time.Hour
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

// Verification failure reasons. Distinct sentinel errors so callers can map
// them to the Authentication-Results reason-code taxonomy.
var (
	ErrMalformed       = errors.New("sworn: malformed token")
	ErrBadSignature    = errors.New("sworn: signature verification failed")
	ErrExpired         = errors.New("sworn: token expired")
	ErrNotYetValid     = errors.New("sworn: token not yet valid")
	ErrLifetimeTooLong = errors.New("sworn: token lifetime exceeds 24h")
	ErrOffPrefix       = errors.New("sworn: source address outside attested prefix")
	ErrBadUnit         = errors.New("sworn: unit shorter than attested prefix or >128")
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
	if !p.IsValid() {
		return netip.Prefix{}, ErrMalformed
	}
	return p, nil
}

var detEnc cbor.EncMode

func init() {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	detEnc = m
}

func encodePayload(p Payload) ([]byte, error) {
	if p.Operator == "" || !p.Prefix.IsValid() {
		return nil, ErrMalformed
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
	if err := cbor.Unmarshal(b, &raw); err != nil {
		return Payload{}, ErrMalformed
	}
	var (
		p    Payload
		pfx  []byte
		iat  int64
		exp  int64
		unit uint8
	)
	fields := []struct {
		key int
		dst any
	}{
		{keyOperator, &p.Operator}, {keyPrefix, &pfx}, {keyUnit, &unit},
		{keyIssuedAt, &iat}, {keyExpires, &exp}, {keyRole, &p.Role},
	}
	for _, f := range fields {
		rm, ok := raw[f.key]
		if !ok {
			return Payload{}, ErrMalformed
		}
		if err := cbor.Unmarshal(rm, f.dst); err != nil {
			return Payload{}, ErrMalformed
		}
	}
	prefix, err := decodePrefix(pfx)
	if err != nil {
		return Payload{}, err
	}
	p.Prefix, p.Unit = prefix, unit
	p.IssuedAt, p.Expires = time.Unix(iat, 0).UTC(), time.Unix(exp, 0).UTC()
	return p, nil
}

// Sign produces a Mode-2 token: COSE_Sign1(EdDSA) over the CBOR payload.
// Ed25519 signing is deterministic (RFC 8032), so tokens are reproducible
// for fixed inputs — required for the published test vectors.
func Sign(p Payload, priv ed25519.PrivateKey) ([]byte, error) {
	if p.Expires.Sub(p.IssuedAt) > MaxTokenLifetime {
		return nil, ErrLifetimeTooLong
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
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, err
	}
	return msg.MarshalCBOR()
}

// Verify performs the five verification steps from I-D §Mode-2, in order:
// parse, key lookup (caller-supplied), signature, time window, prefix
// membership. `now` is injected for testability; `source` is the connecting
// address.
func Verify(token []byte, pub ed25519.PublicKey, source netip.Addr, now time.Time) (Result, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		return Result{}, ErrMalformed
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return Result{}, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return Result{}, ErrBadSignature
	}
	p, err := decodePayload(msg.Payload)
	if err != nil {
		return Result{}, err
	}
	if p.Expires.Sub(p.IssuedAt) > MaxTokenLifetime {
		return Result{}, ErrLifetimeTooLong
	}
	if now.Before(p.IssuedAt) {
		return Result{}, ErrNotYetValid
	}
	if now.After(p.Expires) {
		return Result{}, ErrExpired
	}
	if int(p.Unit) < p.Prefix.Bits() || p.Unit > 128 {
		return Result{}, ErrBadUnit
	}
	if !p.Prefix.Contains(source) {
		return Result{}, ErrOffPrefix
	}
	unit, err := source.Prefix(int(p.Unit))
	if err != nil {
		return Result{}, fmt.Errorf("sworn: unit derivation: %w", err)
	}
	return Result{Operator: p.Operator, Unit: unit}, nil
}
