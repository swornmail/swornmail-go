// Command genvectors emits the deterministic SwornMail test vectors
// consumed by the spec repo and by other implementations (Rust crate,
// plugins) for cross-implementation conformance, per draft-kafedzhy-swornmail-01.
//
// Expectations are authored from the DRAFT, not derived from the reference
// implementation. Generation self-checks every case against sworn.Verify and
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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

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
}

type recordCase struct {
	Name   string `json:"name"`
	TXT    string `json:"txt"`
	Kind   string `json:"kind"` // "key" or "policy"
	Expect string `json:"expect"`
}

type vectors struct {
	Spec        string       `json:"spec"`
	Note        string       `json:"note"`
	SeedHex     string       `json:"ed25519_seed_hex"`
	PubHex      string       `json:"ed25519_public_hex"`
	Selector    string       `json:"selector"`
	ContentType string       `json:"content_type"`
	KeyQName    string       `json:"key_record_qname"`
	KeyRecord   string       `json:"key_record"`
	PolicyQName string       `json:"policy_record_qname"`
	PolicyRec   string       `json:"policy_record"`
	Cases       []vectorCase `json:"cases"`
	Records     []recordCase `json:"records"`
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
		res, verr := sworn.Verify(c.token, pub, src, time.Unix(c.now, 0).UTC())
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
		}
	}

	v := vectors{
		Spec:        "draft-kafedzhy-swornmail-01",
		Note:        "expect = single reason; expect_any = draft leaves reason-code order unspecified, any listed value conforms. token_b64url is the wire encoding.",
		SeedHex:     hex.EncodeToString(seed),
		PubHex:      hex.EncodeToString(pub),
		Selector:    selector,
		ContentType: sworn.ContentType,
		KeyQName:    selector + "._sworn.mailer.example.com",
		KeyRecord:   "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub),
		PolicyQName: "_prefixes._sworn.mailer.example.com",
		PolicyRec:   "v=SWORN1; p=2001:db8:f00::/48; u=64",
		Cases:       outCases,
		Records:     records,
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
	fmt.Printf("wrote %s (%d cases, %d records, base token=%d bytes)\n",
		*out, len(v.Cases), len(v.Records), len(good))
}
