package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/swornmail/swornmail-go/sworn"
	cose "github.com/veraison/go-cose"
)

const insideSrc = "2001:db8:f00:1234::a:1" // inside 2001:db8:f00::/48

// generate builds the differential corpus.
func generate(fuzzN int) []caseT {
	var cases []caseT
	// add evaluates signature-only, matching the frozen token vectors.
	add := func(name string, tok []byte, src string, now int64) {
		cases = append(cases, caseT{name: name, token: tok, source: src, now: now})
	}
	// addPolicy runs the complete path: local checks, then policy
	// authorization, then the signature.
	addPolicy := func(name string, tok []byte, src string, now int64, policy string) {
		cases = append(cases, caseT{name: name, token: tok, source: src, now: now, policy: policy})
	}

	// --- valid parameter space: both must agree pass / off_prefix ---
	valids := []struct {
		prefix string
		bits   int
		unit   uint64
		role   string
	}{
		{"2001:db8:f00::", 48, 64, "mta"},
		{"2001:db8::", 32, 64, "mta"},
		{"2001:db8:f00:1234::", 64, 64, "mta"},
		{"2606:4700::", 32, 64, "mta"},
		{"2a00:1450:4001::", 48, 48, "mta"},
		{"2001:db8:f00::", 48, 56, "mta"},
		{"2001:db8:f00::", 48, 64, "forwarder"},
		{"2001:db8:f00:1234::", 64, 64, "esp-tenant"},
	}
	for i, v := range valids {
		p := netip.PrefixFrom(netip.MustParseAddr(v.prefix), v.bits)
		tok, err := sworn.Sign(sworn.Payload{
			Operator: "mailer.example.com", Prefix: p, Unit: uint8(v.unit),
			IssuedAt: time.Unix(t0, 0).UTC(), Expires: time.Unix(expU, 0).UTC(), Role: v.role,
		}, selector, priv)
		if err != nil {
			panic(fmt.Sprintf("valid %d: %v", i, err))
		}
		add(fmt.Sprintf("valid_%d_inside", i), tok, insideAddr(p, 0xabcd).String(), t0+1800)
		add(fmt.Sprintf("valid_%d_network", i), tok, p.Masked().Addr().String(), t0+1800)
		add(fmt.Sprintf("valid_%d_outside", i), tok, outsideAddr(p).String(), t0+1800)
	}

	// --- time boundaries on a valid /48 token ---
	base, _ := sworn.Sign(sworn.Payload{
		Operator: "mailer.example.com", Prefix: netip.MustParsePrefix("2001:db8:f00::/48"),
		Unit: 64, IssuedAt: time.Unix(t0, 0).UTC(), Expires: time.Unix(expU, 0).UTC(), Role: "mta",
	}, selector, priv)
	for _, tb := range []struct {
		name string
		now  int64
	}{
		{"iat_minus_300", t0 - 300}, {"iat_minus_301", t0 - 301}, {"iat_exact", t0},
		{"exp_plus_300", expU + 300}, {"exp_plus_301", expU + 301}, {"exp_exact", expU},
	} {
		add("time_"+tb.name, base, insideSrc, tb.now)
	}

	// --- should-PASS edges (validate lenient/ignore alignment) ---
	add("unknown_int_payload_key", signRaw(append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, "future"})...), insideSrc, t0+1800)
	add("unknown_protected_int_label", signWith(
		buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...),
		cose.ProtectedHeader{cose.HeaderLabelContentType: sworn.ContentType, cose.HeaderLabelKeyID: []byte(selector), int64(99): "x"},
		nil), insideSrc, t0+1800)
	add("descending_map_keys", signWith(buildMap(
		kv{6, "mta"}, kv{5, uint64(expU)}, kv{4, uint64(t0)}, kv{3, uint64(64)},
		kv{2, prefixWire("2001:db8:f00::", 48)}, kv{1, "mailer.example.com"},
	), goodProt(), nil), insideSrc, t0+1800)
	add("indefinite_length_map", signWith(buildIndefMap(
		kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)}, kv{3, uint64(64)},
		kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"},
	), goodProt(), nil), insideSrc, t0+1800)

	// --- structural / header adversarial: both must REJECT ---
	untagged := append([]byte(nil), base...)
	if len(untagged) > 0 && untagged[0] == 0xd2 {
		untagged = untagged[1:]
	}
	add("untagged", untagged, insideSrc, t0+1800)
	add("wrong_content_type", signWith(buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...),
		cose.ProtectedHeader{cose.HeaderLabelContentType: "application/evil", cose.HeaderLabelKeyID: []byte(selector)}, nil), insideSrc, t0+1800)
	add("missing_kid", signWith(buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...),
		cose.ProtectedHeader{cose.HeaderLabelContentType: sworn.ContentType}, nil), insideSrc, t0+1800)
	add("kid_in_unprotected", signWith(buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...),
		cose.ProtectedHeader{cose.HeaderLabelContentType: sworn.ContentType},
		cose.UnprotectedHeader{cose.HeaderLabelKeyID: []byte(selector)}), insideSrc, t0+1800)
	add("non_canonical_prefix", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00:dead::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("prefix_len_byte_200", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 200)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("teredo_prefix", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("unit_128", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(128)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("exp_before_iat", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(expU)}, kv{5, uint64(t0)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("unknown_role", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "pirate"}), insideSrc, t0+1800)
	add("tstr_payload_key", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}, kv{"future", "v"}), insideSrc, t0+1800)

	// --- policy authorization: the contract added by the Mode-2 repair ---
	//
	// Every case here runs the complete verifier, so Go and Rust must agree on
	// containment direction, the unit-equality rule, testing-mode suppression,
	// and the observed unit. Without these the authorization logic lives in
	// two implementations with nothing comparing them.
	authTok := func(prefix string, bits int, unit uint64) []byte {
		tok, err := sworn.Sign(sworn.Payload{
			Operator: "mailer.example.com",
			Prefix:   netip.PrefixFrom(netip.MustParseAddr(prefix), bits),
			Unit:     uint8(unit),
			IssuedAt: time.Unix(t0, 0).UTC(), Expires: time.Unix(expU, 0).UTC(), Role: "mta",
		}, selector, priv)
		if err != nil {
			panic(fmt.Sprintf("auth token %s/%d u=%d: %v", prefix, bits, unit, err))
		}
		return tok
	}
	tok48 := authTok("2001:db8:f00::", 48, 64)
	tok32 := authTok("2001:db8::", 32, 32)

	for _, ac := range []struct {
		name, policy, src string
		token             []byte
	}{
		// Exact and broader policy prefixes authorize; narrower and unrelated
		// ones do not. Containment runs one way only.
		{"auth_exact_prefix", "v=SWORN1; p=2001:db8:f00::/48; u=64", insideSrc, tok48},
		{"auth_broader_policy", "v=SWORN1; p=2001:db8::/32; u=64", insideSrc, tok48},
		{"auth_narrower_policy", "v=SWORN1; p=2001:db8:f00:1200::/56; u=64", insideSrc, tok48},
		{"auth_unrelated_policy", "v=SWORN1; p=2001:db8:bad::/48; u=64", insideSrc, tok48},
		// "A policy with no p value authorizes no Mode-2 token."
		{"auth_empty_policy", "v=SWORN1; u=64", insideSrc, tok48},
		// The token unit must equal the policy unit, default included.
		{"auth_unit_mismatch", "v=SWORN1; p=2001:db8:f00::/48; u=56", insideSrc, tok48},
		{"auth_unit_default", "v=SWORN1; p=2001:db8:f00::/48", insideSrc, tok48},
		// t=y must never read as a pass on either side.
		{"auth_testing_policy", "v=SWORN1; p=2001:db8:f00::/48; u=64; t=y", insideSrc, tok48},
		// A claimant declaring a shared aggregate: both must still report the
		// source /64 as the observed unit.
		{"auth_coarse_unit", "v=SWORN1; p=2001:db8::/32; u=32", "2001:db8:aaaa:bbbb::5", tok32},
		// A local failure must beat authorization even when the policy covers
		// the prefix, so the reported outcome cannot depend on ordering.
		{"auth_local_failure_first", "v=SWORN1; p=2001:db8:f00::/48; u=64", "2001:db8:bad::1", tok48},
		// A policy that does not parse is a permerror, not a silent pass.
		// u=32 under a /48 is malformed (a unit may not extend outside an
		// attested prefix); u=48 would have parsed fine and quietly tested
		// the unit-mismatch branch instead.
		{"auth_malformed_policy", "v=SWORN1; p=2001:db8:f00::/48; u=32", insideSrc, tok48},
	} {
		addPolicy(ac.name, ac.token, ac.src, t0+1800, ac.policy)
	}

	// --- COSE alg identifier: both identifiers for Ed25519 pass, and the
	// signature behind -19 is really checked; anything else is substitution.
	byAlg := func(alg cose.Algorithm) []byte {
		return signWithAlg(alg, buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...))
	}
	fullySpecified := byAlg(algEd25519)
	fullySpecifiedTampered := append([]byte(nil), fullySpecified...)
	fullySpecifiedTampered[len(fullySpecifiedTampered)-1] ^= 0xff
	add("alg_ed25519_fully_specified", fullySpecified, insideSrc, t0+1800)
	addPolicy("alg_ed25519_fully_specified_authorized", fullySpecified, insideSrc, t0+1800,
		"v=SWORN1; p=2001:db8:f00::/48; u=64")
	add("alg_ed25519_fully_specified_tampered", fullySpecifiedTampered, insideSrc, t0+1800)
	add("alg_es256_substituted", byAlg(cose.AlgorithmES256), insideSrc, t0+1800)
	add("alg_ed448_fully_specified", byAlg(cose.Algorithm(-53)), insideSrc, t0+1800)
	add("alg_reserved_zero", byAlg(cose.Algorithm(0)), insideSrc, t0+1800)

	// --- size bound: exactly at the cap, one over, and far over ---
	for _, n := range []int{sworn.MaxTokenSize, sworn.MaxTokenSize + 1, 4096} {
		found := false
		for pad := 0; pad < n && !found; pad++ {
			tok := signRaw(append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, make([]byte, pad)})...)
			if len(tok) > n {
				break
			}
			if len(tok) == n {
				add(fmt.Sprintf("size_%d", n), tok, insideSrc, t0+1800)
				found = true
			}
		}
		// A missing size case would silently drop the edge this block exists to test.
		if !found {
			panic(fmt.Sprintf("no padding gives a %d-octet token", n))
		}
	}

	// --- payload value types: tags, bignums, times past 2^63 ---
	timed := func(iat, exp any) []kv {
		return []kv{{1, "mailer.example.com"}, {2, prefixWire("2001:db8:f00::", 48)},
			{3, uint64(64)}, {4, iat}, {5, exp}, {6, "mta"}}
	}
	add("type_operator_tag32", signRaw(kv{1, cbor.Tag{Number: 32, Content: "mailer.example.com"}},
		kv{2, prefixWire("2001:db8:f00::", 48)}, kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("type_prefix_tag24", signRaw(kv{1, "mailer.example.com"}, kv{2, cbor.Tag{Number: 24, Content: prefixWire("2001:db8:f00::", 48)}},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("type_unit_bignum", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, cbor.Tag{Number: 2, Content: []byte{64}}}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("type_iat_tag1", signRaw(timed(cbor.Tag{Number: 1, Content: uint64(t0)}, uint64(expU))...), insideSrc, t0+1800)
	add("type_exp_bignum", signRaw(timed(uint64(t0), cbor.Tag{Number: 2, Content: []byte{byte(expU >> 24), byte(expU >> 16), byte(expU >> 8), byte(expU)}})...), insideSrc, t0+1800)
	add("type_role_tag32", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, cbor.Tag{Number: 32, Content: "mta"}}), insideSrc, t0+1800)
	add("type_unknown_key_bignum", signRaw(append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, cbor.Tag{Number: 3, Content: []byte{9}}})...), insideSrc, t0+1800)
	add("time_iat_2p63", signRaw(timed(uint64(1<<63+100), uint64(1<<63+3700))...), insideSrc, t0+1800)
	add("time_straddle_2p63", signRaw(timed(uint64(1<<63-1800), uint64(1<<63+1800))...), insideSrc, t0+1800)
	add("time_max_uint64", signRaw(timed(uint64(1<<64-3601), uint64(1<<64-1))...), insideSrc, t0+1800)
	add("time_lifetime_over_cap_2p63", signRaw(timed(uint64(1<<63-1), uint64(1<<63+86400))...), insideSrc, t0+1800)

	// --- payload major types: the shapes a lenient decoder coerces ---
	//
	// with replaces one value in a valid payload; keyed replaces one key.
	with := func(key int, v any) []kv {
		es := goodEntries("2001:db8:f00::", 48, 64, "mta")
		es[key-1].v = v
		return es
	}
	keyed := func(key int, k any) []kv {
		es := goodEntries("2001:db8:f00::", 48, 64, "mta")
		es[key-1].k = k
		return es
	}
	null, undefined := cbor.RawMessage{0xf6}, cbor.RawMessage{0xf7}
	prefixArray := make([]uint64, 17)
	for i, b := range prefixWire("2001:db8:f00::", 48) {
		prefixArray[i] = uint64(b)
	}
	for _, c := range []struct {
		name    string
		entries []kv
	}{
		{"major_operator_null", with(1, null)},
		{"major_operator_bstr", with(1, []byte("mailer.example.com"))},
		{"major_prefix_null", with(2, null)},
		{"major_prefix_tstr", with(2, string(prefixWire("2400:cb00::", 48)))},
		{"major_prefix_int_array", with(2, prefixArray)},
		{"major_unit_null", with(3, null)},
		{"major_unit_undefined", with(3, undefined)},
		{"major_unit_simple64", with(3, cbor.RawMessage{0xf8, 64})},
		{"major_unit_simple16", with(3, cbor.RawMessage{0xf0})},
		{"major_unit_true", with(3, true)},
		{"major_unit_float", with(3, float64(64))},
		{"major_unit_tstr", with(3, "64")},
		{"major_iat_null", with(4, null)},
		{"major_iat_float", with(4, float64(t0))},
		{"major_exp_null", with(5, null)},
		{"major_exp_undefined", with(5, undefined)},
		{"major_role_null", with(6, null)},
		{"major_role_bstr", with(6, []byte("mta"))},
		{"major_operator_self_described", with(1, cbor.Tag{Number: 55799, Content: "mailer.example.com"})},
		{"major_prefix_self_described", with(2, cbor.Tag{Number: 55799, Content: prefixWire("2001:db8:f00::", 48)})},
		{"major_unit_self_described", with(3, cbor.Tag{Number: 55799, Content: uint64(64)})},
		{"major_iat_self_described", with(4, cbor.Tag{Number: 55799, Content: uint64(t0)})},
		{"major_unknown_self_described", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, cbor.Tag{Number: 55799, Content: "x"}})},
		// An unknown key's value is `any`: nothing about it is held to a type.
		{"any_unknown_null", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, null})},
		{"any_unknown_undefined", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, undefined})},
		{"any_unknown_float", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, float64(1.5)})},
		{"any_unknown_array", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, []uint64{1, 2}})},
		{"any_unknown_map_duplicate_keys", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, cbor.RawMessage{0xa2, 0x01, 0x01, 0x01, 0x02}})},
		{"any_unknown_map_text_key", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{99, map[string]uint64{"a": 1}})},
		// Keys: `* int => any`. A tag, a bignum or a float is not an int.
		{"key_operator_self_described", keyed(1, cbor.Tag{Number: 55799, Content: uint64(1)})},
		{"key_operator_bignum", keyed(1, cbor.Tag{Number: 2, Content: []byte{1}})},
		{"key_unit_self_described", keyed(3, cbor.Tag{Number: 55799, Content: uint64(3)})},
		{"key_unit_bignum", keyed(3, cbor.Tag{Number: 2, Content: []byte{3}})},
		{"key_unit_float", keyed(3, float64(3))},
		{"key_unknown_self_described", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{cbor.Tag{Number: 55799, Content: uint64(99)}, "x"})},
		{"key_unknown_bignum", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{cbor.Tag{Number: 2, Content: []byte{99}}, "x"})},
		{"key_unknown_negative_bignum", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{cbor.Tag{Number: 3, Content: []byte{99}}, "x"})},
		// Every CBOR integer is a CDDL int, however wide: unknown, ignored.
		{"key_unknown_2p31", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{uint64(1 << 31), "x"})},
		{"key_unknown_2p63", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{uint64(1 << 63), "x"})},
		{"key_unknown_max_uint64", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{uint64(1<<64 - 1), "x"})},
		{"key_unknown_min_nint", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{cbor.RawMessage{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "x"})},
		{"key_unknown_nint_below_int64", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{cbor.RawMessage{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0}, "x"})},
		{"key_duplicate_2p63", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{uint64(1 << 63), "x"}, kv{uint64(1 << 63), "y"})},
		{"key_duplicate_min_nint", append(goodEntries("2001:db8:f00::", 48, 64, "mta"),
			kv{cbor.RawMessage{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "x"},
			kv{cbor.RawMessage{0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "y"})},
		{"key_duplicate_non_minimal", append(goodEntries("2001:db8:f00::", 48, 64, "mta"), kv{uint64(99), "x"}, kv{cbor.RawMessage{0x18, 99}, "y"})},
		{"key_operator_non_minimal", keyed(1, cbor.RawMessage{0x18, 1})},
	} {
		add(c.name, signRaw(c.entries...), insideSrc, t0+1800)
	}
	good := buildMap(goodEntries("2001:db8:f00::", 48, 64, "mta")...)
	add("payload_self_described", signWith(append([]byte{0xd9, 0xd9, 0xf7}, good...), goodProt(), nil), insideSrc, t0+1800)
	add("payload_tag24", signWith(append([]byte{0xd8, 24}, good...), goodProt(), nil), insideSrc, t0+1800)
	add("payload_trailing_octet", signWith(append(append([]byte(nil), good...), 0x00), goodProt(), nil), insideSrc, t0+1800)
	add("payload_array", signWith([]byte{0x80}, goodProt(), nil), insideSrc, t0+1800)

	// --- envelope and header types: the same coercions one layer up ---
	enc := func(v any) []byte { b, _ := detEnc.Marshal(v); return b }
	selfDescribed := func(b []byte) []byte { return append([]byte{0xd9, 0xd9, 0xf7}, b...) }
	prot := func(alg, cty, kid kv) []byte { return buildMap(alg, cty, kid) }
	algKV, ctyKV, kidKV := kv{1, int64(-8)}, kv{3, sworn.ContentType}, kv{4, []byte(selector)}
	bignum := func(n byte) cbor.Tag { return cbor.Tag{Number: 2, Content: []byte{n}} }
	goodProtRaw := prot(algKV, ctyKV, kidKV)
	add("envelope_hand_built", envelope(goodProtRaw, good, nil), insideSrc, t0+1800)
	for _, c := range []struct {
		name string
		prot []byte
	}{
		{"header_label_alg_bignum", prot(kv{bignum(1), int64(-8)}, ctyKV, kidKV)},
		{"header_label_cty_bignum", prot(algKV, kv{bignum(3), sworn.ContentType}, kidKV)},
		{"header_label_kid_bignum", prot(algKV, ctyKV, kv{bignum(4), []byte(selector)})},
		{"header_label_kid_self_described", prot(algKV, ctyKV, kv{cbor.Tag{Number: 55799, Content: uint64(4)}, []byte(selector)})},
		{"header_label_unknown_bignum", buildMap(algKV, ctyKV, kidKV, kv{bignum(99), "x"})},
		{"header_alg_negative_bignum", prot(kv{1, cbor.Tag{Number: 3, Content: []byte{7}}}, ctyKV, kidKV)},
		{"header_alg_self_described", prot(kv{1, cbor.Tag{Number: 55799, Content: int64(-8)}}, ctyKV, kidKV)},
		{"header_cty_self_described", prot(algKV, kv{3, cbor.Tag{Number: 55799, Content: sworn.ContentType}}, kidKV)},
		{"header_kid_self_described", prot(algKV, ctyKV, kv{4, cbor.Tag{Number: 55799, Content: []byte(selector)}})},
		{"header_kid_null", prot(algKV, ctyKV, kv{4, null})},
		{"header_cty_null", prot(algKV, kv{3, null}, kidKV)},
		{"header_alg_null", prot(kv{1, null}, ctyKV, kidKV)},
		{"header_alg_simple", prot(kv{1, cbor.RawMessage{0xf8, 0x27}}, ctyKV, kidKV)},
		{"header_kid_int_array", prot(algKV, ctyKV, kv{4, []uint64{'2', '0', '2', '6', 'a'}})},
		{"header_protected_self_described", selfDescribed(goodProtRaw)},
	} {
		add(c.name, envelope(c.prot, good, nil), insideSrc, t0+1800)
	}
	for _, c := range []struct {
		name   string
		mutate func(items [][]byte)
	}{
		{"envelope_protected_self_described", func(items [][]byte) { items[0] = selfDescribed(items[0]) }},
		{"envelope_unprotected_self_described", func(items [][]byte) { items[1] = selfDescribed(items[1]) }},
		{"envelope_payload_self_described", func(items [][]byte) { items[2] = selfDescribed(items[2]) }},
		{"envelope_signature_self_described", func(items [][]byte) { items[3] = selfDescribed(items[3]) }},
		{"envelope_unprotected_null", func(items [][]byte) { items[1] = null }},
		{"envelope_protected_int_array", func(items [][]byte) {
			arr := make([]uint64, len(goodProtRaw))
			for i, b := range goodProtRaw {
				arr[i] = uint64(b)
			}
			items[0] = enc(arr)
		}},
		{"envelope_unprotected_label_bignum", func(items [][]byte) { items[1] = buildMap(kv{bignum(99), "x"}) }},
		{"envelope_unprotected_kid_bignum_label", func(items [][]byte) { items[1] = buildMap(kv{bignum(4), []byte(selector)}) }},
		{"envelope_unprotected_label_self_described", func(items [][]byte) {
			items[1] = buildMap(kv{cbor.Tag{Number: 55799, Content: uint64(99)}, "x"})
		}},
	} {
		add(c.name, envelope(goodProtRaw, good, c.mutate), insideSrc, t0+1800)
	}
	add("envelope_outer_self_described", selfDescribed(envelope(goodProtRaw, good, nil)), insideSrc, t0+1800)

	// --- unvectored judgment calls (Rust report flagged these) ---
	add("operator_trailing_dot", signRaw(kv{1, "mailer.example.com."}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("operator_empty_label", signRaw(kv{1, "mailer..example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, uint64(t0)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)
	add("negative_iat", signRaw(kv{1, "mailer.example.com"}, kv{2, prefixWire("2001:db8:f00::", 48)},
		kv{3, uint64(64)}, kv{4, int64(-100)}, kv{5, uint64(expU)}, kv{6, "mta"}), insideSrc, t0+1800)

	// --- deterministic byte-fuzz over the base token ---
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < fuzzN; i++ {
		m := append([]byte(nil), base...)
		switch rng.Intn(3) {
		case 0: // flip 1-3 bytes
			for f := 0; f < 1+rng.Intn(3); f++ {
				pos := rng.Intn(len(m))
				m[pos] ^= byte(1 + rng.Intn(255))
			}
		case 1: // truncate
			m = m[:rng.Intn(len(m))]
		case 2: // append junk
			m = append(m, byte(rng.Intn(256)), byte(rng.Intn(256)))
		}
		name := fmt.Sprintf("fuzz_%04d", i)
		if dumpFuzz != "" && name == dumpFuzz {
			fmt.Fprintf(os.Stderr, "DUMP %s %s\n", name, hex.EncodeToString(m))
		}
		add(name, m, insideSrc, t0+1800)
	}

	return cases
}

// buildIndefMap encodes the entries as an indefinite-length CBOR map
// (0xbf ... 0xff) — well-formed but non-deterministic; verifiers are lenient.
func buildIndefMap(entries ...kv) []byte {
	out := []byte{0xbf}
	for _, e := range entries {
		kb, _ := detEnc.Marshal(e.k)
		vb, _ := detEnc.Marshal(e.v)
		out = append(append(out, kb...), vb...)
	}
	return append(out, 0xff)
}

func insideAddr(p netip.Prefix, low uint16) netip.Addr {
	a := p.Masked().Addr().As16()
	a[14], a[15] = byte(low>>8), byte(low)
	return netip.AddrFrom16(a)
}

func outsideAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As16()
	a[(p.Bits()-1)/8] ^= 0x01
	return netip.AddrFrom16(a)
}
