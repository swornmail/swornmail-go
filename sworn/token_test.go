package sworn

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"
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
	res, err := Verify(tok, testPub, inside, now)
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
	if _, err := Verify(tok, testPub, outside, now); !errors.Is(err, ErrOffPrefix) {
		t.Errorf("err = %v, want ErrOffPrefix", err)
	}
}

func TestPrefixBoundaries(t *testing.T) {
	tok := mustSign(t, basePayload())
	first := netip.MustParseAddr("2001:db8:f00::")
	last := netip.MustParseAddr("2001:db8:f00:ffff:ffff:ffff:ffff:ffff")
	for _, a := range []netip.Addr{first, last} {
		if _, err := Verify(tok, testPub, a, now); err != nil {
			t.Errorf("boundary %v rejected: %v", a, err)
		}
	}
}

func TestExpiredAndNotYetValid(t *testing.T) {
	tok := mustSign(t, basePayload())
	// Past the 300s skew tolerance on each side.
	if _, err := Verify(tok, testPub, inside, exp.Add(SkewTolerance+time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := Verify(tok, testPub, inside, iat.Add(-SkewTolerance-time.Second)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}
}

func TestSkewToleranceBoundary(t *testing.T) {
	tok := mustSign(t, basePayload())
	// Exactly at the skew edge on each side is still valid.
	if _, err := Verify(tok, testPub, inside, iat.Add(-SkewTolerance)); err != nil {
		t.Errorf("iat-skew edge rejected: %v", err)
	}
	if _, err := Verify(tok, testPub, inside, exp.Add(SkewTolerance)); err != nil {
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
	if _, err := Verify(tok, testPub, inside, now); err == nil {
		t.Error("tampered token verified")
	}
}

func TestWrongKey(t *testing.T) {
	tok := mustSign(t, basePayload())
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(tok, otherPub, inside, now); !errors.Is(err, ErrBadSignature) {
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
		if _, err := Verify(tok, testPub, a, now); !errors.Is(err, ErrIneligibleSrc) {
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
	}
	for name, txt := range bad {
		if _, err := ParsePolicyRecord(txt); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
