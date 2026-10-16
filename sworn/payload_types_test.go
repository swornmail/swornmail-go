package sworn

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// payloadWith returns the six valid payload entries with some values
// replaced, plus any extra entries.
func payloadWith(override map[uint64]any, extra ...testKV) []testKV {
	entries := []testKV{
		{uint64(1), "mailer.example.com"}, {uint64(2), prefixWire()},
		{uint64(3), uint64(64)}, {uint64(4), uint64(iat.Unix())},
		{uint64(5), uint64(exp.Unix())}, {uint64(6), "mta"},
	}
	for i := range entries {
		if v, ok := override[entries[i].k.(uint64)]; ok {
			entries[i].v = v
		}
	}
	return append(entries, extra...)
}

// The CDDL types the defined payload keys tstr, bstr and uint. The decoder
// would otherwise strip a tag, or fold a bignum into an integer, and accept
// a token another conforming verifier rejects: two verifiers disagreeing on
// one token is exactly what an attacker probes for.
func TestPayloadValueTypes(t *testing.T) {
	type o = map[uint64]any
	cases := []struct {
		name    string
		entries []testKV
		want    error
	}{
		{"operator tagged as text", payloadWith(o{1: cbor.Tag{Number: 32, Content: "mailer.example.com"}}), ErrMalformed},
		{"prefix tagged as embedded CBOR", payloadWith(o{2: cbor.Tag{Number: 24, Content: prefixWire()}}), ErrMalformed},
		{"unit as a bignum", payloadWith(o{3: cbor.Tag{Number: 2, Content: []byte{64}}}), ErrMalformed},
		{"iat tagged as epoch time", payloadWith(o{4: cbor.Tag{Number: 1, Content: uint64(iat.Unix())}}), ErrMalformed},
		{"exp as a bignum", payloadWith(o{5: cbor.Tag{Number: 2, Content: bigEndianTest(uint64(exp.Unix()))}}), ErrMalformed},
		{"role tagged as text", payloadWith(o{6: cbor.Tag{Number: 32, Content: "mta"}}), ErrMalformed},
		{"negative iat", payloadWith(o{4: int64(-1)}), ErrMalformed},
		{"unknown key may be tagged", payloadWith(nil, testKV{uint64(99), cbor.Tag{Number: 2, Content: []byte{1}}}), nil},
		// CDDL uint runs to 2^64-1. Past 2^63 the token is valid in shape and
		// merely far in the future; the bounds still apply to the raw values.
		{"iat past 2^63", payloadWith(o{4: uint64(1<<63 + 100), 5: uint64(1<<63 + 3700)}), nil},
		{"lifetime over cap across 2^63", payloadWith(o{4: uint64(1<<63 - 1), 5: uint64(1<<63 + 86400)}), ErrLifetimeTooLong},
		{"exp before iat past 2^63", payloadWith(o{4: uint64(1<<63 + 10), 5: uint64(1<<63 + 5)}), ErrBadValidity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := decodePayload(buildTestMap(c.entries...))
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// A token issued near or past 2^63 seconds is not yet valid, a fail, and
// never a malformed or expired token (time.Unix overflowed below 2^63 too): the verdict must not depend on how wide an
// implementation's integers are.
func TestTimesPastInt64AreNotYetValid(t *testing.T) {
	for _, times := range [][2]uint64{{1<<63 + 100, 1<<63 + 3700}, {1<<63 - 1800, 1<<63 + 1800}, {1<<63 - 3601, 1<<63 - 1}, {1<<64 - 3601, 1<<64 - 1}} {
		entries := payloadWith(map[uint64]any{4: times[0], 5: times[1]})
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
		if _, err := VerifySignatureOnly(tok, testPub, inside, now); !errors.Is(err, ErrNotYetValid) {
			t.Errorf("iat=%d exp=%d: err = %v, want ErrNotYetValid", times[0], times[1], err)
		}
	}
}

func bigEndianTest(n uint64) []byte {
	var b []byte
	for ; n > 0; n >>= 8 {
		b = append([]byte{byte(n)}, b...)
	}
	return b
}
