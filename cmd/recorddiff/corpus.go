package main

import (
	"fmt"
	"strings"
)

// generate builds the adversarial corpus. The cases target the places a
// re-implementation is most likely to drift: tag syntax, prefix canonical
// form and range, the enumeration cap, unit derivation, address formatting,
// and the boundaries of every range the rules name.
func generate() ([]policyCase, map[string]string) {
	var policies []policyCase
	add := func(name, record, source string) {
		policies = append(policies, policyCase{name: name, record: record, source: source})
	}

	// Well-formed records against sources inside, outside, and on the edges.
	const src = "2001:db8:f00:1234::a:1"
	base := "v=SWORN1; p=2001:db8:f00::/48; u=64"
	add("plain-inside", base, src)
	add("plain-outside", base, "2001:db8:f01::1")
	add("first-address", base, "2001:db8:f00::")
	add("last-address", base, "2001:db8:f00:ffff:ffff:ffff:ffff:ffff")
	add("just-below", base, "2001:db8:eff:ffff:ffff:ffff:ffff:ffff")
	add("just-above", base, "2001:db8:f01::")

	// Every legal unit, so unit derivation and formatting are compared across
	// byte boundaries and inside bytes.
	for unit := 1; unit <= 64; unit++ {
		add(fmt.Sprintf("unit-%d", unit),
			fmt.Sprintf("v=SWORN1; p=2001:db8:f00::/48; u=%d", unit), src)
	}

	// Every legal prefix length.
	for bits := 32; bits <= 64; bits++ {
		add(fmt.Sprintf("prefixlen-%d", bits),
			fmt.Sprintf("v=SWORN1; p=%s/%d", maskedText(bits), bits), src)
	}

	// Longest-match precedence among overlapping prefixes.
	add("longest-match", "v=SWORN1; p=2001:db8::/32,2001:db8:f00::/48,2001:db8:f00:1234::/64; u=64", src)
	add("longest-match-reversed", "v=SWORN1; p=2001:db8:f00:1234::/64,2001:db8:f00::/48,2001:db8::/32; u=64", src)
	add("longest-match-unit-coarser", "v=SWORN1; p=2001:db8::/32,2001:db8:f00::/48; u=40", src)

	// Tag syntax.
	for name, record := range map[string]string{
		"no-version":         "p=2001:db8:f00::/48",
		"version-not-first":  "u=64; v=SWORN1; p=2001:db8:f00::/48",
		"leading-semicolon":  ";v=SWORN1; p=2001:db8:f00::/48",
		"leading-semicolons": ";;;v=SWORN1; p=2001:db8:f00::/48",
		"tag-before-version": ";u=64; v=SWORN1; p=2001:db8:f00::/48",
		"trailing-semicolon": "v=SWORN1; p=2001:db8:f00::/48;",
		"duplicate-tag":      "v=SWORN1; p=2001:db8:f00::/48; u=64; u=48",
		"duplicate-p":        "v=SWORN1; p=2001:db8:f00::/48; p=2001:db8:f01::/48",
		"wrong-version":      "v=SWORN9; p=2001:db8:f00::/48",
		"empty-version":      "v=; p=2001:db8:f00::/48",
		"no-equals":          "v=SWORN1; justatag",
		"internal-space":     "v=SWORN1; p=2001:db8:f00::/48 extra",
		"internal-tab":       "v=SWORN1; p=2001:db8:f00::/48\textra",
		"spaces-around-tags": "v=SWORN1 ;  p=2001:db8:f00::/48  ; u=64",
		"unknown-tag":        "v=SWORN1; p=2001:db8:f00::/48; zz=future",
		"unknown-tag-first":  "zz=future; v=SWORN1; p=2001:db8:f00::/48",
		"empty-record":       "",
		"only-semicolons":    ";;;",
		"crlf-in-value":      "v=SWORN1; p=2001:db8:f00::/48\r\nInjected: yes",
		"empty-p":            "v=SWORN1; p=",
		"empty-p-element":    "v=SWORN1; p=2001:db8:f00::/48,,2001:db8:f01::/48",
		"trailing-comma":     "v=SWORN1; p=2001:db8:f00::/48,",
		"leading-comma":      "v=SWORN1; p=,2001:db8:f00::/48",
	} {
		add("syntax-"+name, record, src)
	}

	// The rua grammar and the control-character rule, both tightened when
	// Mode-2 authorization landed. A report destination is where a receiver
	// sends mail, so a parser differential here is a differential in who gets
	// mailed — the reason these are compared rather than trusted per side.
	for name, record := range map[string]string{
		"rua-plain":            "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b.example",
		"rua-dot-atom":         "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a.b+tag@b.example",
		"rua-specials":         "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:!#$%&'*+-/=?^_`{|}~@b.example",
		"rua-no-scheme":        "v=SWORN1; p=2001:db8:f00::/48; rua=a@b.example",
		"rua-wrong-scheme":     "v=SWORN1; p=2001:db8:f00::/48; rua=https://evil.example/collect",
		"rua-scheme-only":      "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:",
		"rua-empty":            "v=SWORN1; p=2001:db8:f00::/48; rua=",
		"rua-no-at":            "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:nobody",
		"rua-two-at":           "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b@c.example",
		"rua-empty-local":      "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:@b.example",
		"rua-leading-dot":      "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:.a@b.example",
		"rua-trailing-dot":     "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a.@b.example",
		"rua-double-dot":       "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a..b@b.example",
		"rua-recipient-list":   "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b.example,c@d.example",
		"rua-uri-parameter":    "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b.example?subject=x",
		"rua-quoted-local":     "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:\"a b\"@b.example",
		"rua-bad-domain":       "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@-bad.example",
		"rua-empty-label":      "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b..example",
		"rua-crlf-injection":   "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b.example\r\nBcc:victim@example.net",
		"rua-header-injection": "v=SWORN1; p=2001:db8:f00::/48; rua=mailto:a@b.example%0aBcc:victim@example.net",
		"ctl-nul":              "v=SWORN1; p=2001:db8:f00::/48\x00; u=64",
		"ctl-cr":               "v=SWORN1;\r p=2001:db8:f00::/48",
		"ctl-lf":               "v=SWORN1;\n p=2001:db8:f00::/48",
		"ctl-del":              "v=SWORN1; p=2001:db8:f00::/48\x7f",
		"ctl-nul-leading":      "\x00v=SWORN1; p=2001:db8:f00::/48",
		// The bytes three runtimes classify differently. Go's unicode.IsSpace
		// covers NBSP and U+3000, Lua's %s is byte-wise, Rust's
		// is_ascii_whitespace excludes VT and includes FF. Under the printable
		// -ASCII rule every one of these is rejected by every implementation,
		// which is the point of stating the rule as an octet range.
		"ws-vt":             "v=SWORN1; p=2001:db8:f00::/48; x=a\x0bb",
		"ws-ff":             "v=SWORN1; p=2001:db8:f00::/48; x=a\x0cb",
		"ws-nbsp":           "v=SWORN1; p=2001:db8:f00::/48; x=a\u00a0b",
		"ws-ideographic":    "v=SWORN1; p=2001:db8:f00::/48; x=a\u3000b",
		"ws-nel":            "v=SWORN1; p=2001:db8:f00::/48; x=a\u0085b",
		"ws-nbsp-trailing":  "v=SWORN1; p=2001:db8:f00::/48; u=64\u00a0",
		"ws-nbsp-in-prefix": "v=SWORN1; p=2001:db8:f00::/48\u00a0",
		"ws-tab-in-value":   "v=SWORN1; p=2001:db8:f00::/48; x=a\tb",
		// HTAB between tags is what a hand-edited zone file produces: stripped,
		// not rejected. All three must agree, or an operator's record parses
		// on one verifier and not another.
		"ws-tab-between-tags": "v=SWORN1;\tp=2001:db8:f00::/48",
		"ws-tab-around-value": "v=SWORN1; p=\t2001:db8:f00::/48\t",
		"ws-space-in-value":   "v=SWORN1; p=2001:db8:f00::/48; x=a b",
		"high-bit-byte":       "v=SWORN1; p=2001:db8:f00::/48; x=\u00ff",
		"esc-in-value":        "v=SWORN1; p=2001:db8:f00::/48; x=a\x1bb",
		// Empty p= elements: skipped, not counted, not rejected. All three
		// must agree, because this decides how many prefixes authorize.
		"p-trailing-comma": "v=SWORN1; p=2001:db8:f00::/48,",
		"p-leading-comma":  "v=SWORN1; p=,2001:db8:f00::/48",
		"p-double-comma":   "v=SWORN1; p=2001:db8:f00::/48,,2001:db8:f01::/48",
		"p-only-commas":    "v=SWORN1; p=,,,",
	} {
		add("guard-"+name, record, src)
	}

	// Unit values, including the ones a lenient numeric parser would accept.
	for name, unit := range map[string]string{
		"zero": "0", "over": "65", "negative": "-1", "plus": "+5",
		"leading-zeros": "0064", "huge": "99999999999999999999",
		"empty": "", "text": "abc", "hex": "0x40", "float": "64.0",
		"space-inside": "6 4",
	} {
		add("unit-syntax-"+name, "v=SWORN1; p=2001:db8:f00::/48; u="+unit, src)
	}

	// Prefixes that must be rejected, and near-misses that must not be.
	for name, prefix := range map[string]string{
		"unmasked":         "2001:db8:f00::1/48",
		"unmasked-deep":    "2001:db8:f00:0:0:0:0:8000/49",
		"too-short":        "2001:db8::/31",
		"too-long":         "2001:db8:f00:1234::/65",
		"length-128":       "2001:db8:f00:1234::a:1/128",
		"length-zero":      "::/0",
		"over-128":         "2001:db8:f00::/129",
		"ula":              "fd00::/48",
		"link-local":       "fe80::/48",
		"multicast":        "ff00::/48",
		"unspecified-low":  "::/32",
		"ipv4-mapped":      "::ffff:0:0/96",
		"teredo":           "2001::/32",
		"teredo-inside":    "2001:0:1::/48",
		"6to4":             "2002::/16",
		"6to4-inside":      "2002:db8::/48",
		"just-below-2000":  "1fff::/32",
		"just-above-3fff":  "4000::/32",
		"top-of-range":     "3fff:ffff::/32",
		"no-slash":         "2001:db8:f00::",
		"empty-length":     "2001:db8:f00::/",
		"length-leading-0": "2001:db8:f00::/048",
		"not-an-address":   "nonsense/48",
		"ipv4":             "192.0.2.0/24",
		"double-colon-x2":  "2001::db8::1/48",
		"trailing-colon":   "2001:db8:f00:/48",
		"embedded-ipv4":    "2001:db8:f00::192.0.2.1/48",
		"uppercase":        "2001:DB8:F00::/48",
		"leading-zeros":    "2001:0db8:0f00::/48",
	} {
		add("prefix-"+name, "v=SWORN1; p="+prefix, src)
	}

	// The enumeration cap: at the limit, one past it, and one past it with an
	// invalid entry that must not change the verdict.
	var many []string
	for i := 0; i < 64; i++ {
		many = append(many, fmt.Sprintf("2001:db8:%x::/48", i))
	}
	add("cap-exactly-64", "v=SWORN1; p="+strings.Join(many, ","), "2001:db8:3f::1")
	add("cap-65th-ignored", "v=SWORN1; p="+strings.Join(append(many, "2001:db8:ff::/48"), ","), "2001:db8:ff::1")
	add("cap-65th-invalid", "v=SWORN1; p="+strings.Join(append(many, "not-a-prefix"), ","), "2001:db8:3f::1")
	add("cap-64th-matches", "v=SWORN1; p="+strings.Join(many, ","), "2001:db8:3f:ffff::1")

	// Testing and rua tags travel alongside; they must not change matching,
	// but a rejected rua must reject the record.
	for name, tail := range map[string]string{
		"testing":         "; t=y",
		"testing-list":    "; t=x:y:z",
		"testing-unknown": "; t=x",
		"testing-empty":   "; t=",
		"rua-mailto":      "; rua=mailto:reports@example.net",
		"rua-https":       "; rua=https://example.net/collect",
		"rua-empty":       "; rua=",
		"rua-scheme-only": "; rua=mailto:",
		"rua-uppercase":   "; rua=MAILTO:a@example.net",
	} {
		add("tags-"+name, base+tail, src)
	}

	// Address forms on the source side: the same address written differently
	// must produce the same unit text.
	for name, source := range map[string]string{
		"compressed":    "2001:db8:f00:1234::a:1",
		"expanded":      "2001:0db8:0f00:1234:0000:0000:000a:0001",
		"uppercase":     "2001:DB8:F00:1234::A:1",
		"zero-run-mid":  "2001:db8:f00:1234:0:0:0:1",
		"trailing-zero": "2001:db8:f00:1234::",
	} {
		add("source-"+name, base, source)
	}

	// Sources that are not addresses at all, or not IPv6.
	for name, source := range map[string]string{
		"ipv4":       "192.0.2.1",
		"garbage":    "not-an-address",
		"empty":      "",
		"bracketed":  "[2001:db8:f00::1]",
		"with-zone":  "2001:db8:f00::1%eth0",
		"with-port":  "2001:db8:f00::1/64",
		"ipv4-in-v6": "::ffff:192.0.2.1",
	} {
		add("badsource-"+name, base, source)
	}

	// Eligibility, including every boundary the rule names.
	eligibility := map[string]string{
		"global-unicast":   "2001:db8:f00::1",
		"range-first":      "2000::",
		"range-last":       "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"just-below-range": "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"just-above-range": "4000::",
		"teredo-first":     "2001::",
		"teredo-last":      "2001:0:ffff:ffff:ffff:ffff:ffff:ffff",
		"teredo-adjacent":  "2001:1::1",
		"6to4-first":       "2002::",
		"6to4-last":        "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"6to4-adjacent":    "2003::1",
		"loopback":         "::1",
		"unspecified":      "::",
		"ula":              "fd00::1",
		"link-local":       "fe80::1",
		"multicast":        "ff02::1",
		"ipv4-mapped":      "::ffff:192.0.2.1",
		"ipv4-compatible":  "::192.0.2.1",
		"nat64":            "64:ff9b::1",
		"nat64-local":      "64:ff9b:1::1",
		"documentation":    "2001:db8::1",
		"ipv4":             "192.0.2.1",
		"garbage":          "nonsense",
	}
	return policies, eligibility
}

// maskedText returns a canonical prefix address of the given length inside
// documentation space, used to exercise every legal prefix length.
func maskedText(bits int) string {
	full := []int{0x2001, 0x0db8, 0xf00f, 0x1234, 0, 0, 0, 0}
	groups := make([]int, 8)
	for i := 0; i < 8; i++ {
		remaining := bits - i*16
		switch {
		case remaining >= 16:
			groups[i] = full[i]
		case remaining <= 0:
			groups[i] = 0
		default:
			groups[i] = full[i] &^ ((1 << (16 - remaining)) - 1)
		}
	}
	parts := make([]string, 8)
	for i, g := range groups {
		parts[i] = fmt.Sprintf("%x", g)
	}
	return strings.Join(parts, ":")
}
