package sworn

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var (
	cborNull      = cbor.RawMessage{0xf6}
	cborUndefined = cbor.RawMessage{0xf7}
	selfDescribed = func(v any) cbor.Tag { return cbor.Tag{Number: 55799, Content: v} }
	bignum        = func(b ...byte) cbor.Tag { return cbor.Tag{Number: 2, Content: b} }
	minNint       = cbor.RawMessage{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

// A lenient CBOR decoder reads null as "leave the default", simple(n) as the
// integer n, and an array of small integers as a byte string. Each is a
// payload this verifier accepted and a strict one rejects, so a signer could
// mint one token that two receivers judge differently. The CDDL types these
// values tstr, bstr and uint, and nothing else.
func TestPayloadValueMajorTypes(t *testing.T) {
	type o = map[uint64]any
	prefixArray := make([]uint64, 0, 17)
	for _, b := range prefixWire() {
		prefixArray = append(prefixArray, uint64(b))
	}
	for name, override := range map[string]o{
		"operator null":                {1: cborNull},
		"operator as a byte string":    {1: []byte("mailer.example.com")},
		"operator self-described":      {1: selfDescribed("mailer.example.com")},
		"prefix null":                  {2: cborNull},
		"prefix as a text string":      {2: string(prefixWire())},
		"prefix as an integer array":   {2: prefixArray},
		"prefix self-described":        {2: selfDescribed(prefixWire())},
		"unit null reads as default":   {3: cborNull},
		"unit undefined":               {3: cborUndefined},
		"unit simple(64) reads as 64":  {3: cbor.RawMessage{0xf8, 64}},
		"unit true":                    {3: true},
		"unit float":                   {3: float64(64)},
		"unit self-described":          {3: selfDescribed(uint64(64))},
		"iat null reads as zero":       {4: cborNull},
		"iat float":                    {4: float64(iat.Unix())},
		"iat self-described":           {4: selfDescribed(uint64(iat.Unix()))},
		"exp null":                     {5: cborNull},
		"exp undefined":                {5: cborUndefined},
		"role null":                    {6: cborNull},
		"role as a byte string":        {6: []byte("mta")},
		"role self-described":          {6: selfDescribed("mta")},
		"negative unit":                {3: int64(-64)},
		"negative exp":                 {5: int64(-1)},
		"iat as a text string of digs": {4: "1786291200"},
	} {
		if _, err := decodePayload(buildTestMap(payloadWith(override)...)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// An unknown key's value is `any`: none of the above applies to it.
func TestUnknownKeyValueIsAnyType(t *testing.T) {
	for name, v := range map[string]any{
		"null":           cborNull,
		"undefined":      cborUndefined,
		"simple value":   cbor.RawMessage{0xf8, 64},
		"float":          1.5,
		"array":          []uint64{1, 2},
		"self-described": selfDescribed("x"),
		"text-keyed map": map[string]uint64{"a": 1},
	} {
		if _, err := decodePayload(buildTestMap(payloadWith(nil, testKV{uint64(99), v})...)); err != nil {
			t.Errorf("%s under key 99: %v", name, err)
		}
	}
}

// `* int => any`. A self-described tag around key 1 used to be stripped, so
// the operator was read from under a key that is not an integer; a bignum is
// CDDL's bigint, also not `int`. Neither may stand in for a defined key or
// ride along as an unknown one.
func TestPayloadKeysMustBeIntegers(t *testing.T) {
	rekey := func(i int, k any) []testKV {
		entries := payloadWith(nil)
		entries[i-1].k = k
		return entries
	}
	for name, entries := range map[string][]testKV{
		"self-described operator key": rekey(1, selfDescribed(uint64(1))),
		"bignum operator key":         rekey(1, bignum(1)),
		"self-described unit key":     rekey(3, selfDescribed(uint64(3))),
		"float unit key":              rekey(3, float64(3)),
		"self-described unknown key":  payloadWith(nil, testKV{selfDescribed(uint64(99)), "x"}),
		"bignum unknown key":          payloadWith(nil, testKV{bignum(99), "x"}),
		"negative bignum unknown key": payloadWith(nil, testKV{cbor.Tag{Number: 3, Content: []byte{99}}, "x"}),
		"null key":                    payloadWith(nil, testKV{cborNull, "x"}),
	} {
		if _, err := decodePayload(buildTestMap(entries...)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// CDDL `int` is every CBOR integer. An unknown key past what a machine word
// holds is still an unknown key, and rejecting it would make the verdict
// depend on the word size of the verifier.
func TestWideUnknownIntegerKeysAreIgnored(t *testing.T) {
	for name, k := range map[string]any{
		"2^31":                uint64(1 << 31),
		"2^63":                uint64(1 << 63),
		"2^64-1":              uint64(1<<64 - 1),
		"-2^64":               minNint,
		"just below int64":    cbor.RawMessage{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0},
		"non-minimal key 99":  cbor.RawMessage{0x19, 0x00, 99},
		"non-minimal key -16": cbor.RawMessage{0x38, 15},
	} {
		if _, err := decodePayload(buildTestMap(payloadWith(nil, testKV{k, "x"})...)); err != nil {
			t.Errorf("unknown key %s: %v", name, err)
		}
	}
}

// Two entries under one key are two payloads in one signature, whichever of
// them a verifier happens to read. Width and sign do not hide a repeat.
func TestDuplicateKeysAcrossEncodings(t *testing.T) {
	for name, extra := range map[string][]testKV{
		"operator again, non-minimal": {{cbor.RawMessage{0x18, 1}, "evil.example.com"}},
		"unknown key twice":           {{uint64(99), "x"}, {uint64(99), "y"}},
		"unknown key, two widths":     {{uint64(99), "x"}, {cbor.RawMessage{0x18, 99}, "y"}},
		"2^63 twice":                  {{uint64(1 << 63), "x"}, {uint64(1 << 63), "y"}},
		"-2^64 twice":                 {{minNint, "x"}, {minNint, "y"}},
		"negative key twice":          {{int64(-16), "x"}, {cbor.RawMessage{0x38, 15}, "y"}},
	} {
		if _, err := decodePayload(buildTestMap(payloadWith(nil, extra...)...)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	// 99 and -100 share an argument and differ in major type: not a repeat.
	distinct := payloadWith(nil, testKV{uint64(99), "x"}, testKV{int64(-100), "y"})
	if _, err := decodePayload(buildTestMap(distinct...)); err != nil {
		t.Errorf("keys 99 and -100: %v", err)
	}
}

// The payload is a map. A tagged map is a tag, trailing octets are a second
// item, and neither is what was signed for.
func TestPayloadMustBeExactlyOneMap(t *testing.T) {
	good := buildTestMap(payloadWith(nil)...)
	indefinite := append(append([]byte{0xbf}, good[1:]...), 0xff)
	if _, err := decodePayload(indefinite); err != nil {
		t.Errorf("indefinite-length map: %v", err)
	}
	for name, payload := range map[string][]byte{
		"empty":                     {},
		"self-described map":        append([]byte{0xd9, 0xd9, 0xf7}, good...),
		"map in tag 24":             append([]byte{0xd8, 24}, good...),
		"array":                     {0x80},
		"trailing octet":            append(append([]byte(nil), good...), 0x00),
		"count larger than content": append([]byte{0xa7}, good[1:]...),
		"indefinite without break":  indefinite[:len(indefinite)-1],
		"break then trailing octet": append(append([]byte(nil), indefinite...), 0x00),
		"key without a value":       append(append([]byte{0xa7}, good[1:]...), 0x18, 99),
		"truncated count":           {0xbb, 0xff, 0xff},
		"count of 2^64-1":           {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := decodePayload(payload); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// rawToken assembles a tagged COSE_Sign1 around already-encoded buckets and
// signs it as the key holder would, for header shapes go-cose will not emit.
func rawToken(protected, unprotected, payload []byte) []byte {
	enc := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			panic(err)
		}
		return b
	}
	sig := ed25519.Sign(testPriv, enc([]any{"Signature1", protected, []byte{}, payload}))
	tok := []byte{0xd2, 0x84}
	for _, item := range [][]byte{enc(protected), unprotected, enc(payload), enc(sig)} {
		tok = append(tok, item...)
	}
	return tok
}

// The COSE library decodes header buckets through a decoder that drops a
// self-described tag, so `55799(4): kid` was read as the kid label and
// `1: 55799(-8)` as alg -8. Both tokens carry a valid signature; a verifier
// that keeps the tag rejects them. A label is int / tstr (RFC 9052 §3), and
// alg, content type and kid are an int, a tstr and a bstr.
func TestHeaderMajorTypes(t *testing.T) {
	alg := testKV{uint64(1), int64(-8)}
	cty := testKV{uint64(3), ContentType}
	kid := testKV{uint64(4), []byte(testSelector)}
	payload := buildTestMap(payloadWith(nil)...)
	empty := []byte{0xa0}

	if _, err := VerifySignatureOnly(rawToken(buildTestMap(alg, cty, kid), empty, payload), testPub, inside, now); err != nil {
		t.Fatalf("hand-built token with ordinary headers: %v", err)
	}
	// A text label and a negative label are legal and unknown.
	extra := buildTestMap(alg, cty, kid, testKV{"future", 1}, testKV{int64(-70000), 1})
	if _, err := VerifySignatureOnly(rawToken(extra, buildTestMap(testKV{"note", "x"}), payload), testPub, inside, now); err != nil {
		t.Fatalf("unknown text and negative labels: %v", err)
	}

	cases := []struct {
		name        string
		protected   []byte
		unprotected []byte
		want        error
	}{
		{"kid under a self-described label", buildTestMap(alg, cty, testKV{selfDescribed(uint64(4)), []byte(testSelector)}), empty, ErrMalformed},
		{"alg under a self-described label", buildTestMap(testKV{selfDescribed(uint64(1)), int64(-8)}, cty, kid), empty, ErrMalformed},
		{"kid under a bignum label", buildTestMap(alg, cty, testKV{bignum(4), []byte(testSelector)}), empty, ErrMalformed},
		{"unknown self-described label", buildTestMap(alg, cty, kid, testKV{selfDescribed(uint64(99)), 1}), empty, ErrMalformed},
		{"self-described alg", buildTestMap(testKV{uint64(1), selfDescribed(int64(-8))}, cty, kid), empty, ErrHeaderConfusion},
		{"self-described content type", buildTestMap(alg, testKV{uint64(3), selfDescribed(ContentType)}, kid), empty, ErrContentType},
		{"self-described kid", buildTestMap(alg, cty, testKV{uint64(4), selfDescribed([]byte(testSelector))}), empty, ErrNoSelector},
		{"self-described protected map", append([]byte{0xd9, 0xd9, 0xf7}, buildTestMap(alg, cty, kid)...), empty, ErrMalformed},
		{"unprotected self-described label", buildTestMap(alg, cty, kid), buildTestMap(testKV{selfDescribed(uint64(99)), 1}), ErrMalformed},
		{"unprotected bignum label", buildTestMap(alg, cty, kid), buildTestMap(testKV{bignum(99), 1}), ErrMalformed},
		{"unprotected self-described map", buildTestMap(alg, cty, kid), []byte{0xd9, 0xd9, 0xf7, 0xa0}, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := VerifySignatureOnly(rawToken(c.protected, c.unprotected, payload), testPub, inside, now)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}
