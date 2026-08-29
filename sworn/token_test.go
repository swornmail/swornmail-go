package sworn

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Deterministic key for reproducible tests and vectors.
var testSeed = func() []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}()

var (
	testPriv = ed25519.NewKeyFromSeed(testSeed)
	testPub  = testPriv.Public().(ed25519.PublicKey)

	attested = netip.MustParsePrefix("2001:db8:f00::/48")
	inside   = netip.MustParseAddr("2001:db8:f00:1234::a:1")
	outside  = netip.MustParseAddr("2001:db8:f01::a:1") // adjacent /48
	iat      = time.Unix(1786291200, 0).UTC()
	exp      = iat.Add(12 * time.Hour)
	now      = iat.Add(time.Hour)
)

func basePayload() Payload {
	return Payload{
		Operator: "mailer.example.com",
		Prefix:   attested,
		Unit:     64,
		IssuedAt: iat,
		Expires:  exp,
		Role:     "mta",
	}
}

const testSelector = "2026a"

func mustSign(t *testing.T, p Payload) []byte {
	t.Helper()
	tok, err := Sign(p, testSelector, testPriv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

func TestRoundTrip(t *testing.T) {
	tok := mustSign(t, basePayload())
	res, err := VerifySignatureOnly(tok, testPub, inside, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Operator != "mailer.example.com" {
		t.Errorf("operator = %q", res.Operator)
	}
	wantUnit := netip.MustParsePrefix("2001:db8:f00:1234::/64")
	if res.Unit != wantUnit {
		t.Errorf("unit = %v, want %v", res.Unit, wantUnit)
	}
	if res.Selector != testSelector {
		t.Errorf("selector = %q, want %q", res.Selector, testSelector)
	}
}

func TestSignRequiresSelector(t *testing.T) {
	if _, err := Sign(basePayload(), "", testPriv); !errors.Is(err, ErrNoSelector) {
		t.Errorf("err = %v, want ErrNoSelector", err)
	}
}

func TestOffPrefix(t *testing.T) {
	tok := mustSign(t, basePayload())
	if _, err := VerifySignatureOnly(tok, testPub, outside, now); !errors.Is(err, ErrOffPrefix) {
		t.Errorf("err = %v, want ErrOffPrefix", err)
	}
}

func TestPrefixBoundaries(t *testing.T) {
	tok := mustSign(t, basePayload())
	first := netip.MustParseAddr("2001:db8:f00::")
	last := netip.MustParseAddr("2001:db8:f00:ffff:ffff:ffff:ffff:ffff")
	for _, a := range []netip.Addr{first, last} {
		if _, err := VerifySignatureOnly(tok, testPub, a, now); err != nil {
			t.Errorf("boundary %v rejected: %v", a, err)
		}
	}
}

func TestExpiredAndNotYetValid(t *testing.T) {
	tok := mustSign(t, basePayload())
	// Past the 300s skew tolerance on each side.
	if _, err := VerifySignatureOnly(tok, testPub, inside, exp.Add(SkewTolerance+time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := VerifySignatureOnly(tok, testPub, inside, iat.Add(-SkewTolerance-time.Second)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}
}

func TestSkewToleranceBoundary(t *testing.T) {
	tok := mustSign(t, basePayload())
	// Exactly at the skew edge on each side is still valid.
	if _, err := VerifySignatureOnly(tok, testPub, inside, iat.Add(-SkewTolerance)); err != nil {
		t.Errorf("iat-skew edge rejected: %v", err)
	}
	if _, err := VerifySignatureOnly(tok, testPub, inside, exp.Add(SkewTolerance)); err != nil {
		t.Errorf("exp+skew edge rejected: %v", err)
	}
}

func TestLifetimeCap(t *testing.T) {
	p := basePayload()
	p.Expires = p.IssuedAt.Add(25 * time.Hour)
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrLifetimeTooLong) {
		t.Errorf("Sign err = %v, want ErrLifetimeTooLong", err)
	}
}

func TestTamperedToken(t *testing.T) {
	tok := mustSign(t, basePayload())
	tok[len(tok)-1] ^= 0xff
	if _, err := VerifySignatureOnly(tok, testPub, inside, now); err == nil {
		t.Error("tampered token verified")
	}
}

func TestWrongKey(t *testing.T) {
	tok := mustSign(t, basePayload())
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifySignatureOnly(tok, otherPub, inside, now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestBadUnitRejectedAtSign(t *testing.T) {
	p := basePayload()
	p.Unit = 40 // shorter than the /48 attested prefix
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrBadUnit) {
		t.Errorf("err = %v, want ErrBadUnit", err)
	}
	p.Unit = 65 // finer than /64
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrBadUnit) {
		t.Errorf("err = %v, want ErrBadUnit", err)
	}
}

func TestIneligibleSource(t *testing.T) {
	tok := mustSign(t, basePayload())
	for _, s := range []string{
		"::ffff:203.0.113.5", // IPv4-mapped
		"2001::1",            // Teredo
		"2002:c000:0204::1",  // 6to4
		"fe80::1",            // link-local
		"fc00::1",            // ULA
		"ff02::1",            // multicast
	} {
		a := netip.MustParseAddr(s)
		if _, err := VerifySignatureOnly(tok, testPub, a, now); !errors.Is(err, ErrIneligibleSrc) {
			t.Errorf("source %s: err = %v, want ErrIneligibleSrc", s, err)
		}
	}
}

func TestParseUnverified(t *testing.T) {
	tok := mustSign(t, basePayload())
	sel, op, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if sel != testSelector || op != "mailer.example.com" {
		t.Errorf("got selector %q operator %q", sel, op)
	}
}

func mustPolicy(t *testing.T, text string) PolicyRecord {
	t.Helper()
	policy, err := ParsePolicyRecord(text)
	if err != nil {
		t.Fatalf("ParsePolicyRecord: %v", err)
	}
	return policy
}

func TestPreparedAuthorizationFlow(t *testing.T) {
	tok := mustSign(t, basePayload())
	pending, err := PrepareVerification(tok, inside, now)
	if err != nil {
		t.Fatalf("PrepareVerification: %v", err)
	}
	if pending.Operator() != "mailer.example.com" || pending.Selector() != testSelector || pending.Prefix() != attested {
		t.Fatalf("unexpected pending identity: op=%q selector=%q prefix=%s", pending.Operator(), pending.Selector(), pending.Prefix())
	}

	policy := mustPolicy(t, "v=SWORN1; p=2001:db8:f00::/48; u=64; t=y; rua=mailto:a@b.example")
	authorized, err := pending.Authorize(policy)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// t=y returns ErrTestingMode WITH the result: a caller that only checks
	// `err == nil` must not be able to report this as a pass.
	result, err := authorized.VerifySignature(testPub)
	if !errors.Is(err, ErrTestingMode) {
		t.Fatalf("VerifySignature err = %v, want ErrTestingMode", err)
	}
	if result.Prefix != attested || !result.Testing || result.RUA != "mailto:a@b.example" {
		t.Errorf("authorized result lost policy data: %+v", result)
	}
	if AuthResult(err) != "none" || Reason(err) != "testing_mode" {
		t.Errorf("testing mode reported as %s/%s, want none/testing_mode", AuthResult(err), Reason(err))
	}
}

// The declared unit is a claim; the observed unit is what this connection
// actually corroborated. A shared-hosting tenant that enumerates its
// provider's aggregate must not thereby move where reputation attaches.
func TestObservedUnitIgnoresACoarseDeclaredUnit(t *testing.T) {
	p := basePayload()
	p.Prefix = netip.MustParsePrefix("2001:db8::/32")
	p.Unit = 32
	tok := mustSign(t, p)
	policy := mustPolicy(t, "v=SWORN1; p=2001:db8::/32; u=32")
	src := netip.MustParseAddr("2001:db8:aaaa:bbbb::5")

	res, err := Verify(tok, testPub, policy, src, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := res.Unit.String(); got != "2001:db8::/32" {
		t.Errorf("declared unit = %s, want the operator's claim 2001:db8::/32", got)
	}
	if got := res.ObservedUnit.String(); got != "2001:db8:aaaa:bbbb::/64" {
		t.Errorf("observed unit = %s, want the source /64", got)
	}
	if res.ObservedUnit.Bits() != ObservedUnitLen {
		t.Errorf("observed unit is /%d, want /%d regardless of the declared unit",
			res.ObservedUnit.Bits(), ObservedUnitLen)
	}
}

// When the operator declares the finest permitted unit there is nothing to
// clamp, and the two values agree.
func TestObservedUnitMatchesUnitAtDefaultGranularity(t *testing.T) {
	tok := mustSign(t, basePayload())
	policy := mustPolicy(t, "v=SWORN1; p=2001:db8:f00::/48; u=64")
	res, err := Verify(tok, testPub, policy, inside, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Unit != res.ObservedUnit {
		t.Errorf("unit %s != observed %s at u=64", res.Unit, res.ObservedUnit)
	}
}

func TestPolicyRejectsUnrelatedOrNarrowerAuthorization(t *testing.T) {
	tok := mustSign(t, basePayload())
	pending, err := PrepareVerification(tok, inside, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"unrelated": "v=SWORN1; p=2001:db8:bad::/48; u=64",
		"narrower":  "v=SWORN1; p=2001:db8:f00:1200::/56; u=64",
	} {
		if _, err := pending.Authorize(mustPolicy(t, text)); !errors.Is(err, ErrUnauthorizedPrefix) {
			t.Errorf("%s: err = %v, want ErrUnauthorizedPrefix", name, err)
		}
	}
}

func TestPolicyUnitMustMatchToken(t *testing.T) {
	tok := mustSign(t, basePayload())
	pending, err := PrepareVerification(tok, inside, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := mustPolicy(t, "v=SWORN1; p=2001:db8:f00::/48; u=56")
	if _, err := pending.Authorize(policy); !errors.Is(err, ErrPolicyUnitMismatch) {
		t.Errorf("err = %v, want ErrPolicyUnitMismatch", err)
	}
}

func TestBroaderPolicyAuthorizesSpecificTokenPrefix(t *testing.T) {
	payload := basePayload()
	payload.Prefix = netip.MustParsePrefix("2001:db8:f00:1200::/56")
	tok := mustSign(t, payload)
	policy := mustPolicy(t, "v=SWORN1; p=2001:db8:f00::/48; u=64")
	if _, err := Verify(tok, testPub, policy, inside, now); err != nil {
		t.Fatalf("broader policy rejected a covered token prefix: %v", err)
	}
}

func TestSignerCanonicalizesDNSIdentityCase(t *testing.T) {
	payload := basePayload()
	payload.Operator = "Mailer.Example.COM"
	tok, err := Sign(payload, "2026A", testPriv)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := PrepareVerification(tok, inside, now)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Operator() != "mailer.example.com" || pending.Selector() != "2026a" {
		t.Errorf("identity was not canonicalized: op=%q selector=%q", pending.Operator(), pending.Selector())
	}
}

func TestNonCanonicalPrefixRejectedAtSign(t *testing.T) {
	p := basePayload()
	p.Prefix = netip.PrefixFrom(netip.MustParseAddr("2001:db8:f00:dead::"), 48)
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrBadPrefix) {
		t.Errorf("err = %v, want ErrBadPrefix", err)
	}
}

func TestRoleValidation(t *testing.T) {
	p := basePayload()
	p.Role = "pirate"
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrBadRole) {
		t.Errorf("err = %v, want ErrBadRole", err)
	}
}

func TestEspTenantUnitMustEqualPrefix(t *testing.T) {
	p := basePayload()
	p.Role = "esp-tenant" // prefix /48 but unit 64 → invalid for this role
	if _, err := Sign(p, testSelector, testPriv); !errors.Is(err, ErrBadUnit) {
		t.Errorf("err = %v, want ErrBadUnit", err)
	}
	p.Prefix = netip.MustParsePrefix("2001:db8:f00::/64")
	p.Unit = 64 // now unit == prefix length
	if _, err := Sign(p, testSelector, testPriv); err != nil {
		t.Errorf("valid esp-tenant rejected: %v", err)
	}
}

func TestTokenSizeBudget(t *testing.T) {
	tok := mustSign(t, basePayload())
	if len(tok) > 512 {
		t.Errorf("classical token = %d bytes, exceeds 512-byte SHOULD", len(tok))
	}
	t.Logf("token size: %d bytes", len(tok))
}

func TestRecordRoundTrip(t *testing.T) {
	txt := "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(testPub)
	rec, err := ParseRecord(txt)
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if rec.Algorithm != "ed25519" || !rec.PublicKey.Equal(testPub) {
		t.Errorf("parsed record mismatch: %+v", rec)
	}
}

func TestRecordIgnoresLegacySelectorTag(t *testing.T) {
	// -00 records carried s=; -01 moved the selector to the QNAME. The
	// tag now falls under unknown-tag forward compatibility.
	txt := "v=SWORN1; k=ed25519; s=2026a; pk=" +
		base64.StdEncoding.EncodeToString(testPub)
	if _, err := ParseRecord(txt); err != nil {
		t.Errorf("legacy s= tag rejected: %v", err)
	}
}

func TestRecordRejectsDuplicateTag(t *testing.T) {
	pk := base64.StdEncoding.EncodeToString(testPub)
	txt := "v=SWORN1; k=ed25519; pk=" + pk + "; pk=" + pk
	if _, err := ParseRecord(txt); !errors.Is(err, ErrRecordDupTag) {
		t.Errorf("err = %v, want ErrRecordDupTag", err)
	}
}

func TestPolicyRecordRoundTrip(t *testing.T) {
	txt := "v=SWORN1; p=2001:db8:f00::/48,2620:12a:8000::/48; u=64; t=y; rua=mailto:a@b.example"
	rec, err := ParsePolicyRecord(txt)
	if err != nil {
		t.Fatalf("ParsePolicyRecord: %v", err)
	}
	if len(rec.Prefixes) != 2 || rec.Unit != 64 || !rec.Testing || rec.RUA != "mailto:a@b.example" {
		t.Errorf("parsed policy mismatch: %+v", rec)
	}
}

func TestPolicyRecordRejects(t *testing.T) {
	bad := map[string]string{
		"unit over 64":     "v=SWORN1; p=2001:db8:f00::/48; u=128",
		"duplicate tag":    "v=SWORN1; u=64; u=48",
		"prefix too short": "v=SWORN1; p=2001:db8::/16",
		"v not first":      "u=64; v=SWORN1",
		// An empty leading segment must not let a tag precede v=.
		"v not first behind a leading semicolon": ";u=64; v=SWORN1",
		"v not first behind several":             ";;; p=2001:db8:f00::/48; v=SWORN1",
		// rua names where receivers send reports: only mailto: is defined, so
		// another scheme must not survive parsing.
		"rua with a non-mail scheme": "v=SWORN1; rua=https://evil.example/collect",
		"rua empty":                  "v=SWORN1; rua=",
		"rua scheme only":            "v=SWORN1; rua=mailto:",
		"rua CRLF injection":         "v=SWORN1; rua=mailto:a@b.example\r\nBcc:victim@example.net",
		"rua recipient list":         "v=SWORN1; rua=mailto:a@b.example,c@d.example",
		"unit broader than prefix":   "v=SWORN1; p=2001:db8:f00:1200::/56; u=48",
	}
	for name, txt := range bad {
		if _, err := ParsePolicyRecord(txt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A leading empty segment is not itself an error — v= is still the first tag.
func TestPolicyRecordAllowsLeadingSemicolon(t *testing.T) {
	rec, err := ParsePolicyRecord(";v=SWORN1; p=2001:db8:f00::/48")
	if err != nil {
		t.Fatalf("ParsePolicyRecord: %v", err)
	}
	if len(rec.Prefixes) != 1 {
		t.Errorf("parsed %d prefixes, want 1", len(rec.Prefixes))
	}
}

func TestRecordRejects(t *testing.T) {
	pk := base64.StdEncoding.EncodeToString(testPub)
	bad := map[string]string{
		"version not first": "k=ed25519; v=SWORN1; pk=" + pk,
		"unknown version":   "v=SWORN9; k=ed25519; pk=" + pk,
		"unknown algorithm": "v=SWORN1; k=rsa; pk=" + pk,
		"garbage key":       "v=SWORN1; k=ed25519; pk=notbase64!!",
		"missing key":       "v=SWORN1; k=ed25519",
	}
	for name, txt := range bad {
		if _, err := ParseRecord(txt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A CBOR simple value encodes as the same small integer an unsigned key would,
// and the library coerces it, so `simple(1)` arrives as key 1. A payload whose
// ONLY key 1 was `simple(1)` therefore decoded cleanly and took the operator
// from it, while the Rust verifier rejected the same signed payload outright:
// one token, two operator domains.
//
// Presenting both `1` and `simple(1)` is caught by the decoder's duplicate-key
// check, in either order, so the collision is not the hole — the lone simple
// value supplying a required field is. Payload keys must be integers, per the
// payload CDDL, and nothing else.
func TestPayloadRejectsNonIntegerMapKeys(t *testing.T) {
	prefix := func() []byte {
		a := netip.MustParseAddr("2001:db8:f00::").As16()
		return append(a[:], 48)
	}()
	for name, payload := range map[string][]byte{
		// THE exploitable shape: simple(1) is the only key 1 in the map, so
		// nothing collides and the old code took the operator from it.
		"simple value supplies the operator": buildTestMap(
			testKV{cbor.SimpleValue(1), "evil.example.com"},
			testKV{uint64(2), prefix}, testKV{uint64(4), uint64(iat.Unix())},
			testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"}),
		// simple(2) supplying the prefix: same shape, different required field.
		"simple value supplies the prefix": buildTestMap(
			testKV{uint64(1), "mailer.example.com"},
			testKV{cbor.SimpleValue(2), prefix}, testKV{uint64(4), uint64(iat.Unix())},
			testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"}),
		// Caught by the duplicate-key check even before this fix; kept so a
		// later change cannot quietly stop catching it.
		"simple value collides with the operator key": buildTestMap(
			testKV{uint64(1), "mailer.example.com"},
			testKV{cbor.SimpleValue(1), "evil.example.com"},
			testKV{uint64(2), prefix}, testKV{uint64(4), uint64(iat.Unix())},
			testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"}),
		// simple(19) where the unit key belongs.
		"simple value as an unknown key": buildTestMap(
			testKV{uint64(1), "mailer.example.com"}, testKV{uint64(2), prefix},
			testKV{cbor.SimpleValue(19), uint64(64)}, testKV{uint64(4), uint64(iat.Unix())},
			testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"}),
		"boolean as a key": buildTestMap(
			testKV{uint64(1), "mailer.example.com"}, testKV{uint64(2), prefix},
			testKV{true, uint64(64)}, testKV{uint64(4), uint64(iat.Unix())},
			testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"}),
	} {
		if _, err := decodePayload(payload); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// The payload CDDL says `* int => any`, and CDDL `int` covers negatives. A
// negative key is a legal unknown key and must be ignored, not rejected —
// rejecting it would make this implementation stricter than the draft and
// disagree with the Rust verifier on a token both should accept.
func TestPayloadIgnoresNegativeIntegerKeys(t *testing.T) {
	prefix := func() []byte {
		a := netip.MustParseAddr("2001:db8:f00::").As16()
		return append(a[:], 48)
	}()
	payload := buildTestMap(
		testKV{uint64(1), "mailer.example.com"}, testKV{uint64(2), prefix},
		testKV{int64(-16), "private use"}, testKV{uint64(4), uint64(iat.Unix())},
		testKV{uint64(5), uint64(exp.Unix())}, testKV{uint64(6), "mta"})
	p, err := decodePayload(payload)
	if err != nil {
		t.Fatalf("negative key rejected: %v", err)
	}
	if p.Operator != "mailer.example.com" || p.Unit != DefaultUnitPrefixLen {
		t.Errorf("unexpected payload %+v", p)
	}
}

type testKV struct{ k, v any }

// buildTestMap emits a definite-length CBOR map with arbitrary key types, which
// the guarded encoder deliberately cannot produce.
func buildTestMap(entries ...testKV) []byte {
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	body := []byte{0xa0 | byte(len(entries))}
	for _, e := range entries {
		kb, err := enc.Marshal(e.k)
		if err != nil {
			panic(err)
		}
		vb, err := enc.Marshal(e.v)
		if err != nil {
			panic(err)
		}
		body = append(append(body, kb...), vb...)
	}
	return body
}
