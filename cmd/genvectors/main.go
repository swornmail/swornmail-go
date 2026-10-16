// Command genvectors emits the deterministic SwornMail test vectors
// consumed by the spec repo and by other implementations (Rust crate,
// plugins) for cross-implementation conformance, per draft-kafedzhy-swornmail-01.
//
// Expectations are authored from the DRAFT, not derived from the reference
// implementation. Generation self-checks every case against
// sworn.VerifySignatureOnly and
// FAILS if the implementation disagrees with the authored expectation — so a
// verifier that is more lenient than the spec makes generation fail rather
// than silently shrinking the suite. Cases whose reason-code the draft leaves
// unordered carry `expect_any` (a set), not a single `expect`.
//
// Determinism: fixed Ed25519 seed, fixed timestamps, deterministic CBOR
// encoding, RFC 8032 deterministic signatures. Tokens are published in
// base64url-unpadded (the wire encoding), base64-standard, and hex.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"github.com/fxamacker/cbor/v2"
	"github.com/swornmail/swornmail-go/sworn"
	cose "github.com/veraison/go-cose"
)

const selector = "2026a"

var (
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	detEnc cbor.EncMode
	t0     = int64(1786291200) // iat
	expU   = t0 + 3600         // exp: 1h lifetime models the -01 SHOULD
)

// tc is an authored case: raw token bytes plus the expectation written from
// the draft. Exactly one of expect / expectAny is set.
type tc struct {
	name, section  string
	token          []byte
	source         string
	now            int64
	expect         string
	expectAny      []string
	operator, unit string // asserted on pass
	pubHex         string // this case's own operator key; empty means the file's key
}

type vectorCase struct {
	Name      string   `json:"name"`
	Section   string   `json:"spec_section"`
	TokenB64  string   `json:"token_b64url"` // wire encoding: base64url, no padding
	TokenStd  string   `json:"token_b64std"`
	TokenHex  string   `json:"token_hex"`
	Source    string   `json:"source_ip"`
	Now       int64    `json:"now_unix"`
	Expect    string   `json:"expect,omitempty"`
	ExpectAny []string `json:"expect_any,omitempty"`
	Operator  string   `json:"operator,omitempty"`
	Unit      string   `json:"unit,omitempty"`
	// PubHex overrides the file-level key for this case only. It is last and
	// omitted when empty, so cases without it encode exactly as before.
	PubHex string `json:"public_key_hex,omitempty"`
}

// authorizationCase exercises draft §Verification check 3 and the observed
// unit of §Receiver Reputation Semantics: the part of the protocol that has no
// coverage in the token vectors, because those verify a signature against a key
// with no policy in sight.
type authorizationCase struct {
	Name     string `json:"name"`
	TokenB64 string `json:"token_b64url"`
	TokenStd string `json:"token_b64std"`
	TokenHex string `json:"token_hex"`
	Policy   string `json:"policy_record"`
	Source   string `json:"source_ip"`
	Now      int64  `json:"now_unix"`
	// AuthResult is the Authentication-Results value and is the load-bearing
	// assertion: it is the one output both implementations must agree on.
	AuthResult string `json:"auth_result"`
	Expect     string `json:"expect,omitempty"` // reason token, rejections only
	Testing    bool   `json:"testing,omitempty"`
	Operator   string `json:"operator,omitempty"`
	Unit       string `json:"unit,omitempty"`          // the operator's claim
	Observed   string `json:"observed_unit,omitempty"` // what the connection proved
}

type recordCase struct {
	Name   string `json:"name"`
	TXT    string `json:"txt"`
	Kind   string `json:"kind"` // "key" or "policy"
	Expect string `json:"expect"`
}

type vectors struct {
	Spec          string              `json:"spec"`
	Note          string              `json:"note"`
	SeedHex       string              `json:"ed25519_seed_hex"`
	PubHex        string              `json:"ed25519_public_hex"`
	Selector      string              `json:"selector"`
	ContentType   string              `json:"content_type"`
	KeyQName      string              `json:"key_record_qname"`
	KeyRecord     string              `json:"key_record"`
	PolicyQName   string              `json:"policy_record_qname"`
	PolicyRec     string              `json:"policy_record"`
	Cases         []vectorCase        `json:"cases"`
	Records       []recordCase        `json:"records"`
	Authorization []authorizationCase `json:"authorization"`
}

// --- CBOR / COSE builders for malformed cases ---

type kv struct {
	k any
	v any
}

func buildMap(entries ...kv) []byte {
	if len(entries) > 23 {
		panic("map too large for single-byte header")
	}
	body := []byte{0xa0 | byte(len(entries))}
	for _, e := range entries {
		kb, _ := detEnc.Marshal(e.k)
		vb, _ := detEnc.Marshal(e.v)
		body = append(body, kb...)
		body = append(body, vb...)
	}
	return body
}

func prefixWire(s string, bits int) []byte {
	a := netip.MustParseAddr(s).As16()
	return append(a[:], byte(bits))
}

// payload with all six required keys valid; override via extra/replace helpers.
func goodEntries() []kv {
	return []kv{
		{1, "mailer.example.com"},
		{2, prefixWire("2001:db8:f00::", 48)},
		{3, uint64(64)},
		{4, uint64(t0)},
		{5, uint64(expU)},
		{6, "mta"},
	}
}

func signWith(payload []byte, prot cose.ProtectedHeader, unprot cose.UnprotectedHeader) []byte {
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		panic(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	if prot == nil {
		prot = cose.ProtectedHeader{}
	}
	if _, ok := prot[cose.HeaderLabelAlgorithm]; !ok {
		prot[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
	}
	msg.Headers.Protected = prot
	if unprot != nil {
		msg.Headers.Unprotected = unprot
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		panic(err)
	}
	b, err := msg.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	return b
}

// algEd25519 is the fully-specified COSE identifier for Ed25519, taken from
// RFC 9864 §2.2 and the IANA COSE Algorithms registry, not from the library.
const algEd25519 cose.Algorithm = -19

// labelledSigner produces a plain RFC 8032 Ed25519 signature under whatever
// COSE alg label a case names. go-cose's own signer refuses a header alg that
// differs from its -8, and these cases need -19 or a deliberately wrong label
// over a signature that is itself valid.
type labelledSigner struct{ alg cose.Algorithm }

func (s labelledSigner) Algorithm() cose.Algorithm { return s.alg }

func (labelledSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	return ed25519.Sign(priv, content), nil
}

// signWithAlg signs the valid payload and protected header under alg.
func signWithAlg(alg cose.Algorithm) []byte {
	msg := cose.NewSign1Message()
	msg.Payload = buildMap(goodEntries()...)
	msg.Headers.Protected = goodProt()
	msg.Headers.Protected[cose.HeaderLabelAlgorithm] = alg
	if err := msg.Sign(nil, nil, labelledSigner{alg}); err != nil {
		panic(err)
	}
	b, err := msg.MarshalCBOR()
	if err != nil {
		panic(err)
	}
	return b
}

// identityRSigner signs as the key holder would, but with nonce 0: R is the
// identity and S = k*a, which satisfies the cofactorless equation under the
// real key. Only a check on R rejects it.
type identityRSigner struct{}

func (identityRSigner) Algorithm() cose.Algorithm { return cose.AlgorithmEdDSA }

func (identityRSigner) Sign(_ io.Reader, content []byte) ([]byte, error) {
	h := sha512.Sum512(priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, err
	}
	r := edwards25519.NewIdentityPoint().Bytes()
	kh := sha512.New()
	kh.Write(r)
	kh.Write(pub)
	kh.Write(content)
	k, err := edwards25519.NewScalar().SetUniformBytes(kh.Sum(nil))
	if err != nil {
		return nil, err
	}
	return append(r, edwards25519.NewScalar().Multiply(k, a).Bytes()...), nil
}

// strayBits sets a stray bit in the last character of a base64 string with
// one "=" of padding: the decoded bytes are the same, the spelling is not
// canonical.
func strayBits(b64 string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := []byte(b64)
	last := len(out) - 2
	out[last] = alphabet[strings.IndexByte(alphabet, out[last])^1]
	return string(out)
}

// paddedToken signs the valid payload plus an unknown key 99 whose byte
// string is sized so the whole token is exactly n octets. Verifiers ignore
// the unknown key, so length is the only thing that differs.
func paddedToken(n int) []byte {
	for pad := 0; pad < n; pad++ {
		tok := signRaw(append(goodEntries(), kv{99, make([]byte, pad)})...)
		if len(tok) == n {
			return tok
		}
		if len(tok) > n {
			break
		}
	}
	panic(fmt.Sprintf("no padding gives a %d-octet token", n))
}

// bigEndian is the minimal big-endian byte string of n, the content of a
// CBOR bignum (tag 2).
func bigEndian(n uint64) []byte {
	var b []byte
	for ; n > 0; n >>= 8 {
		b = append([]byte{byte(n)}, b...)
	}
	return b
}

func goodProt() cose.ProtectedHeader {
	return cose.ProtectedHeader{
		cose.HeaderLabelContentType: sworn.ContentType,
		cose.HeaderLabelKeyID:       []byte(selector),
	}
}

// signRaw signs an arbitrary payload with the valid protected header.
func signRaw(entries ...kv) []byte {
	return signWith(buildMap(entries...), goodProt(), nil)
}

func main() {
	out := flag.String("o", "test-vectors-v1.json", "output path")
	flag.Parse()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	detEnc = m

	// Well-formed tokens signed through the guarded Sign path.
	sign := func(p sworn.Payload) []byte {
		tok, err := sworn.Sign(p, selector, priv)
		if err != nil {
			panic(fmt.Sprintf("sign %+v: %v", p, err))
		}
		return tok
	}
	base := sworn.Payload{
		Operator: "mailer.example.com",
		Prefix:   netip.MustParsePrefix("2001:db8:f00::/48"),
		Unit:     64,
		IssuedAt: time.Unix(t0, 0).UTC(),
		Expires:  time.Unix(expU, 0).UTC(),
		Role:     "mta",
	}
	good := sign(base)
	maxlife := sign(func() sworn.Payload { p := base; p.Expires = time.Unix(t0+86400, 0).UTC(); return p }())
	espP := base
	espP.Prefix = netip.MustParsePrefix("2001:db8:f00::/64")
	espP.Unit = 64
	espP.Role = "esp-tenant"
	espTok := sign(espP)

	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	fullySpecified := signWithAlg(algEd25519)
	// The universal forgery: R = identity, S = 0. Under a small-order key it
	// satisfies the cofactorless equation for any message.
	identityHex := "01" + strings.Repeat("00", 31)
	smallOrderR := func() []byte {
		msg := cose.NewSign1Message()
		msg.Payload = buildMap(goodEntries()...)
		msg.Headers.Protected = goodProt()
		msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
		if err := msg.Sign(nil, nil, identityRSigner{}); err != nil {
			panic(err)
		}
		b, err := msg.MarshalCBOR()
		if err != nil {
			panic(err)
		}
		return b
	}()
	// Under the identity key, R = B and S = 1 verify for any message.
	ordinaryRUnderIdentityKey := func() []byte {
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(good); err != nil {
			panic(err)
		}
		one := make([]byte, 32)
		one[0] = 1
		msg.Signature = append(edwards25519.NewGeneratorPoint().Bytes(), one...)
		b, err := msg.MarshalCBOR()
		if err != nil {
			panic(err)
		}
		return b
	}()
	universalForgery := func() []byte {
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(good); err != nil {
			panic(err)
		}
		id, _ := hex.DecodeString(identityHex)
		msg.Signature = append(id, make([]byte, 32)...)
		b, err := msg.MarshalCBOR()
		if err != nil {
			panic(err)
		}
		return b
	}()
	fullySpecifiedTampered := append([]byte(nil), fullySpecified...)
	fullySpecifiedTampered[len(fullySpecifiedTampered)-1] ^= 0xff
	untagged := good
	if len(good) > 0 && good[0] == 0xd2 {
		untagged = good[1:]
	}

	cases := []tc{
		// --- positive & boundary ---
		{name: "valid_in_prefix", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},
		{name: "prefix_first_address", section: "verification", token: good,
			source: "2001:db8:f00::", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00::/64"},
		{name: "prefix_last_address", section: "verification", token: good,
			source: "2001:db8:f00:ffff:ffff:ffff:ffff:ffff", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:ffff::/64"},
		{name: "iat_exact", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: t0, expect: "pass"},
		{name: "exp_exact", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: expU, expect: "pass"},
		{name: "skew_iat_minus_300", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: t0 - 300, expect: "pass"},
		{name: "skew_iat_minus_301", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: t0 - 301, expect: "not_yet_valid"},
		{name: "skew_exp_plus_300", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: expU + 300, expect: "pass"},
		{name: "skew_exp_plus_301", section: "verification", token: good,
			source: "2001:db8:f00:1234::a:1", now: expU + 301, expect: "expired"},
		{name: "lifetime_exact_86400", section: "token", token: maxlife,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass"},
		{name: "esp_tenant_valid", section: "token", token: espTok,
			source: "2001:db8:f00::abcd", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00::/64"},
		{name: "unknown_int_key_ignored", section: "token",
			token:  signRaw(append(goodEntries(), kv{99, "future"})...),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},
		{name: "unit_absent_defaults_64", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},

		// --- membership / signature / ordering (advisory) ---
		{name: "off_prefix_adjacent", section: "verification", token: good,
			source: "2001:db8:f01::a:1", now: t0 + 1800, expect: "off_prefix"},
		{name: "expired_and_off_prefix", section: "verification", token: good,
			source: "2001:db8:f01::a:1", now: t0 + 7200, expectAny: []string{"off_prefix", "expired"}},
		{name: "tampered_signature", section: "token", token: tampered,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_signature"},

		// --- source eligibility (all six ineligible families + non-global) ---
		{name: "src_v4mapped", section: "canon", token: good,
			source: "::ffff:203.0.113.5", now: t0 + 1800, expect: "ineligible_source"},
		{name: "src_v4compat", section: "canon", token: good,
			source: "::203.0.113.5", now: t0 + 1800, expect: "ineligible_source"},
		{name: "src_nat64_wellknown", section: "canon", token: good,
			source: "64:ff9b::203.0.113.5", now: t0 + 1800, expect: "ineligible_source"},
		{name: "src_nat64_local", section: "canon", token: good,
			source: "64:ff9b:1::1", now: t0 + 1800, expect: "ineligible_source"},
		{name: "src_teredo", section: "canon", token: good,
			source: "2001::1", now: t0 + 1800, expectAny: []string{"ineligible_source", "off_prefix"}},
		{name: "src_6to4", section: "canon", token: good,
			source: "2002:c000:0204::1", now: t0 + 1800, expectAny: []string{"ineligible_source", "off_prefix"}},
		{name: "src_link_local", section: "canon", token: good,
			source: "fe80::1", now: t0 + 1800, expect: "ineligible_source"},

		// --- COSE header cases ---
		{name: "untagged_cose", section: "token", token: untagged,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "wrong_content_type", section: "token",
			token: signWith(buildMap(goodEntries()...), cose.ProtectedHeader{
				cose.HeaderLabelContentType: "application/evil",
				cose.HeaderLabelKeyID:       []byte(selector),
			}, nil),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_content_type"},
		{name: "missing_content_type", section: "token",
			token: signWith(buildMap(goodEntries()...), cose.ProtectedHeader{
				cose.HeaderLabelKeyID: []byte(selector),
			}, nil),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_content_type"},
		{name: "missing_kid", section: "token",
			token: signWith(buildMap(goodEntries()...), cose.ProtectedHeader{
				cose.HeaderLabelContentType: sworn.ContentType,
			}, nil),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_kid"},
		{name: "empty_kid", section: "token",
			token: signWith(buildMap(goodEntries()...), cose.ProtectedHeader{
				cose.HeaderLabelContentType: sworn.ContentType,
				cose.HeaderLabelKeyID:       []byte{},
			}, nil),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_kid"},
		{name: "kid_in_unprotected_only", section: "token",
			token: signWith(buildMap(goodEntries()...),
				cose.ProtectedHeader{cose.HeaderLabelContentType: sworn.ContentType},
				cose.UnprotectedHeader{cose.HeaderLabelKeyID: []byte(selector)}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800,
			expectAny: []string{"header_confusion", "bad_kid"}},
		{name: "shared_label_both_buckets", section: "token",
			token: signWith(buildMap(goodEntries()...),
				cose.ProtectedHeader{
					cose.HeaderLabelContentType: sworn.ContentType,
					cose.HeaderLabelKeyID:       []byte(selector),
					int64(99):                   "protected",
				},
				cose.UnprotectedHeader{int64(99): "attacker"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "header_confusion"},
		{name: "crit_present", section: "token",
			token: signWith(buildMap(goodEntries()...), cose.ProtectedHeader{
				cose.HeaderLabelContentType: sworn.ContentType,
				cose.HeaderLabelKeyID:       []byte(selector),
				cose.HeaderLabelCritical:    []any{int64(99)},
				int64(99):                   "x",
			}, nil),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "header_confusion"},

		// --- prefix constraints ---
		{name: "non_canonical_prefix", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00:dead::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_prefix"},
		{name: "prefix_too_short", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8::", 16)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_prefix"},
		{name: "prefix_and_unit_too_long", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 65)},
				kv{3, uint64(65)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800,
			expectAny: []string{"bad_prefix", "bad_unit"}},
		{name: "prefix_not_global_unicast", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("fc00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_prefix"},
		{name: "attested_prefix_teredo", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_prefix"},
		{name: "attested_prefix_6to4", section: "canon",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2002::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_prefix"},

		// --- unit / validity / role / domain ---
		{name: "unit_lt_prefix", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(40)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_unit"},
		{name: "unit_over_64", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(96)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_unit"},
		{name: "esp_tenant_unit_ne_prefix", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "esp-tenant"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_unit"},
		{name: "exp_before_iat", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(expU)}, kv{5, uint64(t0)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800,
			expectAny: []string{"bad_validity", "not_yet_valid", "expired"}},
		{name: "lifetime_over_cap", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(t0 + 86401)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "lifetime_too_long"},
		{name: "unknown_role", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "pirate"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_role"},
		{name: "missing_role", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "operator_domain_crlf", section: "verification",
			token: signRaw(kv{1, "x.example.com\r\nQUIT"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "operator_domain_empty_label", section: "verification",
			token: signRaw(kv{1, "evil.example.com.."}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "tstr_payload_key", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"},
				kv{"future", "value"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "duplicate_map_key", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{2, prefixWire("2001:db8:f01::", 48)},
				kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},

		// --- COSE algorithm identifier (appended; earlier cases unchanged) ---
		//
		// §token: the verifier takes the algorithm from k= and rejects a token
		// whose alg "does not correspond to it". RFC 9864 deprecated the
		// polymorphic EdDSA (-8) for the fully-specified Ed25519 (-19); both
		// correspond to k=ed25519, so both verify.
		{name: "alg_ed25519_fully_specified", section: "token", token: fullySpecified,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},
		// A verifier that accepted the -19 label without checking the
		// signature would pass forgeries carrying it.
		{name: "alg_ed25519_fully_specified_tampered", section: "token", token: fullySpecifiedTampered,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_signature"},
		// Algorithm substitution: the token may not choose its algorithm, so a
		// valid Ed25519 signature labelled ES256 is a header fault.
		{name: "alg_es256_substituted", section: "token", token: signWithAlg(cose.AlgorithmES256),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "header_confusion"},

		// --- strict Ed25519 (appended; earlier cases unchanged) ---
		//
		// §token: verification is strict, so a small-order public key is a
		// signature failure. Under the identity key, R = identity and S = 0
		// verify for every message with the cofactorless equation; a verifier
		// that doesn't check passes a token nobody signed. This case carries
		// its own key in public_key_hex.
		{name: "small_order_public_key", section: "token", token: universalForgery,
			pubHex: identityHex, source: "2001:db8:f00:1234::a:1", now: t0 + 1800,
			expect: "bad_signature"},
		// The same rule, with each check on its own. Under the identity key with
		// an ordinary R (B) and S = 1, only the key check rejects; a key holder
		// signing with R = identity under the real key, only the R check does.
		{name: "small_order_public_key_ordinary_r", section: "token", token: ordinaryRUnderIdentityKey,
			pubHex: identityHex, source: "2001:db8:f00:1234::a:1", now: t0 + 1800,
			expect: "bad_signature"},
		{name: "small_order_r_component", section: "token", token: smallOrderR,
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "bad_signature"},

		// --- token size bound (appended) ---
		//
		// §token: a token longer than 3072 octets is malformed before it is
		// decoded. Both tokens are validly signed; only the length differs.
		{name: "token_at_size_cap", section: "token", token: paddedToken(sworn.MaxTokenSize),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},
		{name: "token_over_size_cap", section: "token", token: paddedToken(sworn.MaxTokenSize + 1),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},

		// --- payload value types (appended) ---
		//
		// §token CDDL: operator is tstr and iat/exp are uint. A tagged value
		// is not a tstr or uint, and a bignum is CDDL's biguint, a different
		// type. Only key 99, typed `any`, may carry a tag.
		{name: "operator_tagged", section: "token",
			token: signRaw(kv{1, cbor.Tag{Number: 32, Content: "mailer.example.com"}}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "iat_tagged_epoch", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, cbor.Tag{Number: 1, Content: uint64(t0)}}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "iat_bignum", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, cbor.Tag{Number: 2, Content: bigEndian(uint64(t0))}}, kv{5, uint64(expU)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "malformed"},
		{name: "unknown_key_tagged_ignored", section: "token",
			token:  signRaw(append(goodEntries(), kv{99, cbor.Tag{Number: 2, Content: []byte{1}}})...),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "pass",
			operator: "mailer.example.com", unit: "2001:db8:f00:1234::/64"},
		// uint runs to 2^64-1. A time past 2^63 is far in the future, so the
		// token is not yet valid; an implementation that stores seconds in a
		// signed 64-bit integer must not turn that into a malformed token.
		{name: "iat_beyond_int64", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(1<<63 + 100)}, kv{5, uint64(1<<63 + 3700)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "not_yet_valid"},
		{name: "validity_straddles_int64", section: "token",
			token: signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
				kv{3, uint64(64)}, kv{4, uint64(1<<63 - 1800)}, kv{5, uint64(1<<63 + 1800)}, kv{6, "mta"}),
			source: "2001:db8:f00:1234::a:1", now: t0 + 1800, expect: "not_yet_valid"},
	}

	// Self-check against the reference implementation; authored expectations
	// are the oracle, not the other way round.
	var failures []string
	for _, c := range cases {
		src, err := netip.ParseAddr(c.source)
		if err != nil {
			failures = append(failures, c.name+": bad source addr")
			continue
		}
		key := pub
		if c.pubHex != "" {
			b, err := hex.DecodeString(c.pubHex)
			if err != nil {
				failures = append(failures, c.name+": bad public_key_hex")
				continue
			}
			key = ed25519.PublicKey(b)
		}
		res, verr := sworn.VerifySignatureOnly(c.token, key, src, time.Unix(c.now, 0).UTC())
		got := sworn.Reason(verr)
		ok := got == c.expect
		for _, e := range c.expectAny {
			if got == e {
				ok = true
			}
		}
		if !ok {
			want := c.expect
			if len(c.expectAny) > 0 {
				want = fmt.Sprintf("%v", c.expectAny)
			}
			failures = append(failures, fmt.Sprintf("%s: expected %s got %q", c.name, want, got))
			continue
		}
		if c.expect == "pass" {
			if c.operator != "" && res.Operator != c.operator {
				failures = append(failures, fmt.Sprintf("%s: operator %q != %q", c.name, res.Operator, c.operator))
			}
			if c.unit != "" && res.Unit.String() != c.unit {
				failures = append(failures, fmt.Sprintf("%s: unit %v != %s", c.name, res.Unit, c.unit))
			}
		}
	}

	// --- policy authorization, authored from the draft ---
	//
	// Expectations come from §Verification check 3 ("the token prefix MUST be
	// the same as or a subnet of at least one of the first 64 policy prefixes,
	// and the token unit MUST equal the policy u value"), §Testing Mode, and
	// the observed-unit rule in §Receiver Reputation Semantics. As with the
	// token cases, the reference implementation is checked against these, not
	// the other way round.
	authTok := func(prefix string, bits int, unit uint8) []byte {
		tok, err := sworn.Sign(sworn.Payload{
			Operator: "mailer.example.com",
			Prefix:   netip.PrefixFrom(netip.MustParseAddr(prefix), bits),
			Unit:     unit,
			IssuedAt: time.Unix(t0, 0).UTC(),
			Expires:  time.Unix(expU, 0).UTC(),
			Role:     "mta",
		}, selector, priv)
		if err != nil {
			panic(fmt.Sprintf("authorization token %s/%d u=%d: %v", prefix, bits, unit, err))
		}
		return tok
	}
	tok48 := authTok("2001:db8:f00::", 48, 64)
	tok32 := authTok("2001:db8::", 32, 32)
	const inSrc = "2001:db8:f00:1234::a:1"

	auths := []authorizationCase{
		{Name: "policy_authorizes_exact_prefix", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00::/48; u=64", Source: inSrc, Now: t0 + 1800,
			AuthResult: "pass", Operator: "mailer.example.com",
			Unit: "2001:db8:f00:1234::/64", Observed: "2001:db8:f00:1234::/64"},
		// A broader policy prefix authorizes a more specific token prefix.
		{Name: "policy_authorizes_broader_prefix", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8::/32; u=64", Source: inSrc, Now: t0 + 1800,
			AuthResult: "pass", Operator: "mailer.example.com",
			Unit: "2001:db8:f00:1234::/64", Observed: "2001:db8:f00:1234::/64"},
		// ...but never the reverse: a narrow enumeration cannot authorize its parent.
		{Name: "policy_narrower_than_token_prefix", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00:1200::/56; u=64", Source: inSrc, Now: t0 + 1800,
			AuthResult: "permerror", Expect: "unauthorized_prefix"},
		{Name: "policy_unrelated_prefix", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:bad::/48; u=64", Source: inSrc, Now: t0 + 1800,
			AuthResult: "permerror", Expect: "unauthorized_prefix"},
		// "A policy with no p value authorizes no Mode-2 token."
		{Name: "policy_without_prefixes_authorizes_nothing", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; u=64", Source: inSrc, Now: t0 + 1800,
			AuthResult: "permerror", Expect: "unauthorized_prefix"},
		{Name: "policy_unit_mismatch", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00::/48; u=56", Source: inSrc, Now: t0 + 1800,
			AuthResult: "permerror", Expect: "policy_unit_mismatch"},
		// The unit rule applies to the default too: absent u= means 64.
		{Name: "policy_default_unit_matches_token", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00::/48", Source: inSrc, Now: t0 + 1800,
			AuthResult: "pass", Operator: "mailer.example.com",
			Unit: "2001:db8:f00:1234::/64", Observed: "2001:db8:f00:1234::/64"},
		// t=y is never a pass, for credit or blame.
		{Name: "testing_policy_is_none_not_pass", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00::/48; u=64; t=y", Source: inSrc, Now: t0 + 1800,
			AuthResult: "none", Testing: true, Operator: "mailer.example.com",
			Unit: "2001:db8:f00:1234::/64", Observed: "2001:db8:f00:1234::/64"},
		// A claimant declaring a shared aggregate: the declared unit is the
		// claim, the observed unit is the /64 the connection corroborated.
		{Name: "coarse_declared_unit_does_not_widen_observed", TokenHex: hex.EncodeToString(tok32),
			Policy: "v=SWORN1; p=2001:db8::/32; u=32", Source: "2001:db8:aaaa:bbbb::5", Now: t0 + 1800,
			AuthResult: "pass", Operator: "mailer.example.com",
			Unit: "2001:db8::/32", Observed: "2001:db8:aaaa:bbbb::/64"},
		// A local check fails before policy is consulted, so the outcome is the
		// local failure and no DNS was owed.
		{Name: "local_failure_precedes_authorization", TokenHex: hex.EncodeToString(tok48),
			Policy: "v=SWORN1; p=2001:db8:f00::/48; u=64", Source: "2001:db8:bad::1", Now: t0 + 1800,
			AuthResult: "fail", Expect: "off_prefix"},
	}
	for i := range auths {
		tok, err := hex.DecodeString(auths[i].TokenHex)
		if err != nil {
			panic(err)
		}
		auths[i].TokenB64 = base64.RawURLEncoding.EncodeToString(tok)
		auths[i].TokenStd = base64.StdEncoding.EncodeToString(tok)

		src, err := netip.ParseAddr(auths[i].Source)
		if err != nil {
			failures = append(failures, "authorization "+auths[i].Name+": bad source")
			continue
		}
		policy, perr := sworn.ParsePolicyRecord(auths[i].Policy)
		if perr != nil {
			failures = append(failures, fmt.Sprintf("authorization %s: policy does not parse: %v", auths[i].Name, perr))
			continue
		}
		res, verr := sworn.Verify(tok, pub, policy, src, time.Unix(auths[i].Now, 0).UTC())
		if got := sworn.AuthResult(verr); got != auths[i].AuthResult {
			failures = append(failures, fmt.Sprintf("authorization %s: auth_result %s != %s", auths[i].Name, got, auths[i].AuthResult))
			continue
		}
		if auths[i].Expect != "" {
			if got := sworn.Reason(verr); got != auths[i].Expect {
				failures = append(failures, fmt.Sprintf("authorization %s: reason %s != %s", auths[i].Name, got, auths[i].Expect))
			}
		}
		if auths[i].Operator != "" {
			if res.Operator != auths[i].Operator {
				failures = append(failures, fmt.Sprintf("authorization %s: operator %q != %q", auths[i].Name, res.Operator, auths[i].Operator))
			}
			if res.Unit.String() != auths[i].Unit {
				failures = append(failures, fmt.Sprintf("authorization %s: unit %s != %s", auths[i].Name, res.Unit, auths[i].Unit))
			}
			if res.ObservedUnit.String() != auths[i].Observed {
				failures = append(failures, fmt.Sprintf("authorization %s: observed %s != %s", auths[i].Name, res.ObservedUnit, auths[i].Observed))
			}
			if res.Testing != auths[i].Testing {
				failures = append(failures, fmt.Sprintf("authorization %s: testing %v != %v", auths[i].Name, res.Testing, auths[i].Testing))
			}
		}
	}

	records := []recordCase{
		{"key_record", "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "ok"},
		{"key_legacy_selector_ignored", "v=SWORN1; k=ed25519; s=2026a; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "ok"},
		{"key_v_not_first", "k=ed25519; v=SWORN1; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "error"},
		{"key_unknown_version", "v=SWORN9; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "error"},
		{"key_unknown_algorithm", "v=SWORN1; k=rsa; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "error"},
		{"key_garbage_key", "v=SWORN1; k=ed25519; pk=notbase64!!", "key", "error"},
		{"key_duplicate_tag", "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub) + "; pk=" + base64.StdEncoding.EncodeToString(pub), "key", "error"},
		{"key_missing_key", "v=SWORN1; k=ed25519", "key", "error"},
		{"policy_full", "v=SWORN1; p=2001:db8:f00::/48; u=64; t=y; rua=mailto:a@b.example", "policy", "ok"},
		{"policy_multi_prefix", "v=SWORN1; p=2001:db8:f00::/48,2620:12a:8000::/48", "policy", "ok"},
		{"policy_unit_over_64", "v=SWORN1; p=2001:db8:f00::/48; u=128", "policy", "error"},
		{"policy_duplicate_tag", "v=SWORN1; u=64; u=48", "policy", "error"},
		{"policy_prefix_out_of_range", "v=SWORN1; p=2001:db8::/16", "policy", "error"},
		{"policy_v_not_first", "u=64; v=SWORN1", "policy", "error"},
		// A record is printable ASCII, 0x20..0x7E. These are the bytes three
		// runtimes classify differently as "whitespace"; stating the rule as an
		// octet range is what makes them agree. Pinned here because the Go/Lua
		// record differential cannot see the Rust verifier.
		{"policy_vertical_tab", "v=SWORN1; p=2001:db8:f00::/48; x=a\x0bb", "policy", "error"},
		{"policy_form_feed", "v=SWORN1; p=2001:db8:f00::/48; x=a\x0cb", "policy", "error"},
		{"policy_escape_byte", "v=SWORN1; p=2001:db8:f00::/48; x=a\x1bb", "policy", "error"},
		{"policy_no_break_space", "v=SWORN1; p=2001:db8:f00::/48; x=a\u00a0b", "policy", "error"},
		{"policy_ideographic_space", "v=SWORN1; p=2001:db8:f00::/48; x=a\u3000b", "policy", "error"},
		{"policy_trailing_no_break_space", "v=SWORN1; p=2001:db8:f00::/48; u=64\u00a0", "policy", "error"},
		{"policy_space_in_value", "v=SWORN1; p=2001:db8:f00::/48; x=a b", "policy", "error"},
		{"policy_tab_in_value", "v=SWORN1; p=2001:db8:f00::/48; x=a\tb", "policy", "error"},
		// HTAB between tags is what a hand-edited zone file produces, and is
		// stripped, not rejected. Pinned so the octet gate cannot quietly
		// start rejecting records operators actually write.
		{"policy_tab_between_tags", "v=SWORN1;\tp=2001:db8:f00::/48", "policy", "ok"},
		{"policy_tab_around_value", "v=SWORN1; p=\t2001:db8:f00::/48\t", "policy", "ok"},
		// Empty p= elements are skipped, not rejected: sloppy, not hostile.
		// This decides how many prefixes authorize, so all three must agree.
		{"policy_trailing_comma", "v=SWORN1; p=2001:db8:f00::/48,", "policy", "ok"},
		{"policy_leading_comma", "v=SWORN1; p=,2001:db8:f00::/48", "policy", "ok"},
		{"policy_double_comma", "v=SWORN1; p=2001:db8:f00::/48,,2001:db8:f01::/48", "policy", "ok"},
		// Appended: a pk of the right length that is not a curve point (y = 2)
		// makes the record malformed. Go used to accept it and fail every
		// signature, while Rust rejected the record.
		{"key_not_a_curve_point", "v=SWORN1; k=ed25519; pk=AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "key", "error"},
		// Both implementations accept the two non-canonical encodings RFC 8032
		// 5.1.3 rejects, and the draft says so. Pinned, so an implementation
		// that rejects them shows up as a divergence rather than in the field:
		// y = p + 3 (an ordinary point), and x = 0 with the sign bit set.
		{"key_noncanonical_y_accepted", "v=SWORN1; k=ed25519; pk=8P///////////////////////////////////////38=", "key", "ok"},
		{"key_x0_sign_bit_accepted", "v=SWORN1; k=ed25519; pk=AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA=", "key", "ok"},
		// Appended with the record ABNF: numbers are digits only, with no
		// sign and no leading zero; a tag has a name; an embedded IPv4
		// address only ends an IPv6 address. Each of these split the three
		// parsers before. The last two pin spellings that stay valid.
		{"policy_unit_plus_sign", "v=SWORN1; p=2001:db8:f00::/48; u=+64", "policy", "error"},
		{"policy_unit_leading_zero", "v=SWORN1; p=2001:db8:f00::/48; u=064", "policy", "error"},
		{"policy_prefix_len_leading_zero", "v=SWORN1; p=2001:db8:f00::/048", "policy", "error"},
		{"policy_prefix_len_plus_sign", "v=SWORN1; p=2001:db8:f00::/+48", "policy", "error"},
		{"policy_empty_tag_name", "v=SWORN1; p=2001:db8:f00::/48; =x", "policy", "error"},
		{"policy_dotted_quad_before_gap", "v=SWORN1; p=32.1.13.184::/32", "policy", "error"},
		{"policy_uppercase_hex_prefix", "v=SWORN1; p=2001:DB8:F00::/48", "policy", "ok"},
		{"policy_uncompressed_prefix", "v=SWORN1; p=2001:db8:f00:0:0:0:0:0/48", "policy", "ok"},
		// Appended: the file's own key, spelled with a stray bit in the last
		// base64 character. RFC 4648 3.5 leaves those bits zero; Go's lenient
		// decoder dropped them and accepted the record, Rust rejected it.
		{"key_pk_noncanonical_base64", "v=SWORN1; k=ed25519; pk=" + strayBits(base64.StdEncoding.EncodeToString(pub)), "key", "error"},
	}
	for _, r := range records {
		var perr error
		switch r.Kind {
		case "key":
			_, perr = sworn.ParseRecord(r.TXT)
		case "policy":
			_, perr = sworn.ParsePolicyRecord(r.TXT)
		default:
			failures = append(failures, "record "+r.Name+": unknown kind")
			continue
		}
		got := "ok"
		if perr != nil {
			got = "error"
		}
		if got != r.Expect {
			failures = append(failures, fmt.Sprintf("record %s: expected %s got %s (%v)", r.Name, r.Expect, got, perr))
		}
	}

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr, "SELF-CHECK FAILED (implementation disagrees with authored expectations):")
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, "  -", f)
		}
		os.Exit(1)
	}

	// Convert to output form with all three token encodings.
	outCases := make([]vectorCase, len(cases))
	for i, c := range cases {
		outCases[i] = vectorCase{
			Name: c.name, Section: c.section,
			TokenB64: base64.RawURLEncoding.EncodeToString(c.token),
			TokenStd: base64.StdEncoding.EncodeToString(c.token),
			TokenHex: hex.EncodeToString(c.token),
			Source:   c.source, Now: c.now,
			Expect: c.expect, ExpectAny: c.expectAny,
			Operator: c.operator, Unit: c.unit,
			PubHex: c.pubHex,
		}
	}

	v := vectors{
		Spec:          "draft-kafedzhy-swornmail-01",
		Note:          "expect = single reason; expect_any = draft leaves reason-code order unspecified, any listed value conforms. token_b64url is the wire encoding.",
		SeedHex:       hex.EncodeToString(seed),
		PubHex:        hex.EncodeToString(pub),
		Selector:      selector,
		ContentType:   sworn.ContentType,
		KeyQName:      selector + "._sworn.mailer.example.com",
		KeyRecord:     "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub),
		PolicyQName:   "_prefixes._sworn.mailer.example.com",
		PolicyRec:     "v=SWORN1; p=2001:db8:f00::/48; u=64",
		Cases:         outCases,
		Records:       records,
		Authorization: auths,
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d cases, %d records, %d authorization, base token=%d bytes)\n",
		*out, len(v.Cases), len(v.Records), len(v.Authorization), len(good))
}
