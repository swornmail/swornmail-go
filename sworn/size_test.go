package sworn

import (
	"errors"
	"testing"

	cose "github.com/veraison/go-cose"
)

// tokenOfLength signs a valid token padded to exactly n octets with an
// unknown payload key, which verifiers ignore, so only the length differs.
func tokenOfLength(t *testing.T, n int) []byte {
	t.Helper()
	for pad := 0; pad < n; pad++ {
		entries := []testKV{
			{uint64(1), "mailer.example.com"}, {uint64(2), prefixWire()},
			{uint64(3), uint64(64)}, {uint64(4), uint64(iat.Unix())},
			{uint64(5), uint64(exp.Unix())}, {uint64(6), "mta"},
			{uint64(99), make([]byte, pad)},
		}
		msg := cose.NewSign1Message()
		msg.Payload = buildTestMap(entries...)
		msg.Headers.Protected[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
		msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte(testSelector)
		msg.Headers.Protected[cose.HeaderLabelContentType] = ContentType
		signer, err := cose.NewSigner(cose.AlgorithmEdDSA, testPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := msg.Sign(nil, nil, signer); err != nil {
			t.Fatal(err)
		}
		tok, err := msg.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) == n {
			return tok
		}
		if len(tok) > n {
			break
		}
	}
	t.Fatalf("no padding gives a %d-octet token", n)
	return nil
}

func prefixWire() []byte {
	a := attested.Addr().As16()
	return append(a[:], byte(attested.Bits()))
}

// The longest SWORN line carries at most 3066 octets of token. Anything over
// the cap is rejected before CBOR decoding, so an oversized input from a
// library caller or a non-SMTP integration costs nothing to refuse.
func TestTokenSizeCap(t *testing.T) {
	if _, err := VerifySignatureOnly(tokenOfLength(t, MaxTokenSize), testPub, inside, now); err != nil {
		t.Fatalf("token at the cap: %v", err)
	}
	over := tokenOfLength(t, MaxTokenSize+1)
	if _, err := VerifySignatureOnly(over, testPub, inside, now); !errors.Is(err, ErrMalformed) {
		t.Fatalf("token one octet over the cap: err = %v, want ErrMalformed", err)
	}
	if _, _, err := ParseUnverified(over); !errors.Is(err, ErrMalformed) {
		t.Fatalf("ParseUnverified over the cap: err = %v, want ErrMalformed", err)
	}
}
