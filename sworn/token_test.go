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

func mustSign(t *testing.T, p Payload) []byte {
	t.Helper()
	tok, err := Sign(p, testPriv)
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
	if _, err := Verify(tok, testPub, inside, exp.Add(time.Second)); !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if _, err := Verify(tok, testPub, inside, iat.Add(-time.Second)); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}
}

func TestLifetimeCap(t *testing.T) {
	p := basePayload()
	p.Expires = p.IssuedAt.Add(25 * time.Hour)
	if _, err := Sign(p, testPriv); !errors.Is(err, ErrLifetimeTooLong) {
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

func TestBadUnit(t *testing.T) {
	p := basePayload()
	p.Unit = 40 // shorter than the /48 attested prefix
	tok := mustSign(t, p)
	if _, err := Verify(tok, testPub, inside, now); !errors.Is(err, ErrBadUnit) {
		t.Errorf("err = %v, want ErrBadUnit", err)
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
	txt := "v=SWORN1; k=ed25519; s=2026a; pk=" +
		base64.StdEncoding.EncodeToString(testPub) + "; u=64; l=https://log.example/op"
	rec, err := ParseRecord(txt)
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if rec.Selector != "2026a" || rec.Unit != 64 || !rec.PublicKey.Equal(testPub) {
		t.Errorf("parsed record mismatch: %+v", rec)
	}
}

func TestRecordRejects(t *testing.T) {
	pk := base64.StdEncoding.EncodeToString(testPub)
	bad := map[string]string{
		"version not first": "k=ed25519; v=SWORN1; pk=" + pk,
		"unknown version":   "v=SWORN9; k=ed25519; pk=" + pk,
		"unknown algorithm": "v=SWORN1; k=rsa; pk=" + pk,
		"garbage key":       "v=SWORN1; k=ed25519; pk=notbase64!!",
		"unit out of range": "v=SWORN1; k=ed25519; pk=" + pk + "; u=129",
		"missing key":       "v=SWORN1; k=ed25519",
	}
	for name, txt := range bad {
		if _, err := ParseRecord(txt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
