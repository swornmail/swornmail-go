package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"time"

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
