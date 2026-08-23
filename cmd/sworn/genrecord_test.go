package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/swornmail/swornmail-go/sworn"
)

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// baseOptions is a valid generation request; tests mutate one field at a time.
func baseOptions(pub ed25519.PublicKey) genOptions {
	return genOptions{
		Domain:   "mailer.example.com",
		Selector: "2026a",
		PubKey:   pub,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:f00::/48")},
		Unit:     64,
		Testing:  true,
	}
}

func TestBuildRecordsEmitsBothRecords(t *testing.T) {
	pub := testKey(t)
	rs, err := buildRecords(baseOptions(pub))
	if err != nil {
		t.Fatal(err)
	}
	if rs.Key.QName != "2026a._sworn.mailer.example.com" {
		t.Errorf("key qname = %q", rs.Key.QName)
	}
	if want := "v=SWORN1; k=ed25519; pk=" + encodePublicKey(pub); rs.Key.Value != want {
		t.Errorf("key value = %q, want %q", rs.Key.Value, want)
	}
	if rs.Policy.QName != "_prefixes._sworn.mailer.example.com" {
		t.Errorf("policy qname = %q", rs.Policy.QName)
	}
	if want := "v=SWORN1; p=2001:db8:f00::/48; u=64; t=y"; rs.Policy.Value != want {
		t.Errorf("policy value = %q, want %q", rs.Policy.Value, want)
	}
}

// Liability staking is opt-in: t=y unless the operator turns it off.
func TestBuildRecordsTestingFlag(t *testing.T) {
	pub := testKey(t)
	rs, err := buildRecords(baseOptions(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rs.Policy.Value, "; t=y") {
		t.Errorf("testing default missing from %q", rs.Policy.Value)
	}
	o := baseOptions(pub)
	o.Testing = false
	rs, err = buildRecords(o)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rs.Policy.Value, "t=") {
		t.Errorf("--testing=false still emitted a t tag: %q", rs.Policy.Value)
	}
}

// Whatever is emitted must parse back to what was asked for; the protocol's
// own parsers are the gate.
func TestBuildRecordsRoundTrips(t *testing.T) {
	pub := testKey(t)
	o := baseOptions(pub)
	o.Prefixes = append(o.Prefixes, netip.MustParsePrefix("2620:12a:8000::/48"))
	o.Unit = 56
	o.RUA = "mailto:sworn@mailer.example.com"
	rs, err := buildRecords(o)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sworn.ParseRecord(rs.Key.Value)
	if err != nil {
		t.Fatalf("key record does not parse: %v", err)
	}
	if !key.PublicKey.Equal(pub) {
		t.Error("key record round-trips to a different key")
	}
	policy, err := sworn.ParsePolicyRecord(rs.Policy.Value)
	if err != nil {
		t.Fatalf("policy record does not parse: %v", err)
	}
	if len(policy.Prefixes) != 2 || policy.Prefixes[1] != o.Prefixes[1] {
		t.Errorf("prefixes round-trip to %v", policy.Prefixes)
	}
	if policy.Unit != 56 || !policy.Testing || policy.RUA != o.RUA {
		t.Errorf("policy tags round-trip to u=%d t=%t rua=%q", policy.Unit, policy.Testing, policy.RUA)
	}
}

func TestBuildRecordsRejections(t *testing.T) {
	pub := testKey(t)
	many := make([]netip.Prefix, 0, sworn.MaxPolicyPrefixes+1)
	for i := 0; i <= sworn.MaxPolicyPrefixes; i++ {
		many = append(many, netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i)}), 48))
	}
	for name, mutate := range map[string]func(*genOptions){
		"empty domain":       func(o *genOptions) { o.Domain = "" },
		"domain with CRLF":   func(o *genOptions) { o.Domain = "mailer.example.com\r\n" },
		"domain empty label": func(o *genOptions) { o.Domain = "mailer..example.com" },
		"selector too long":  func(o *genOptions) { o.Selector = strings.Repeat("a", 64) },
		"selector dotted":    func(o *genOptions) { o.Selector = "2026.a" },
		"selector hyphen":    func(o *genOptions) { o.Selector = "-2026a" },
		"short key":          func(o *genOptions) { o.PubKey = ed25519.PublicKey{1, 2, 3} },
		"no prefix":          func(o *genOptions) { o.Prefixes = nil },
		"too many prefixes":  func(o *genOptions) { o.Prefixes = many },
		"duplicate prefix":   func(o *genOptions) { o.Prefixes = append(o.Prefixes, o.Prefixes[0]) },
		"unmasked prefix":    func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("2001:db8:f00::1/48") },
		"prefix too short":   func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("2000::/24") },
		"prefix too long":    func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("2001:db8:f00::/96") },
		"prefix ULA":         func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("fd00::/48") },
		"prefix Teredo":      func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("2001:0:1::/48") },
		"prefix 6to4":        func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("2002:db8::/48") },
		"prefix IPv4":        func(o *genOptions) { o.Prefixes[0] = netip.MustParsePrefix("192.0.2.0/24") },
		"unit zero":          func(o *genOptions) { o.Unit = 0 },
		"unit over 64":       func(o *genOptions) { o.Unit = 65 },
		"rua not mailto":     func(o *genOptions) { o.RUA = "https://example.net/reports" },
		"rua no mailbox":     func(o *genOptions) { o.RUA = "mailto:@example.net" },
		"rua bad domain":     func(o *genOptions) { o.RUA = "mailto:reports@exa mple.net" },
		"rua with semicolon": func(o *genOptions) { o.RUA = "mailto:a@example.net;x=1" },
	} {
		o := baseOptions(pub)
		mutate(&o)
		if _, err := buildRecords(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Pointer records are only useful at the two lengths discovery queries.
func TestPointerRecordsOnlyAtQueriedLengths(t *testing.T) {
	pub := testKey(t)
	o := baseOptions(pub)
	o.Prefixes = []netip.Prefix{
		netip.MustParsePrefix("2001:db8:f00::/48"),
		netip.MustParsePrefix("2001:db8:f00:1234::/64"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	rs, err := buildRecords(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Pointers) != 2 {
		t.Fatalf("got %d pointer records, want 2", len(rs.Pointers))
	}
	want := map[string]bool{
		"_sworn.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa":         true,
		"_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa": true,
	}
	for _, p := range rs.Pointers {
		if !want[p.QName] {
			t.Errorf("unexpected pointer qname %q", p.QName)
		}
		if _, err := sworn.ParsePointerRecord(p.Value); err != nil {
			t.Errorf("pointer %q does not parse: %v", p.Value, err)
		}
	}
}

func TestZoneLineSplitsOverlongValue(t *testing.T) {
	long := "v=SWORN1; " + strings.Repeat("x", 600)
	line := zoneLine(dnsRecord{QName: "_prefixes._sworn.example.com", Value: long})
	if got := strings.Count(line, `"`); got != 6 {
		t.Errorf("expected 3 quoted character-strings, got %d quotes: %s", got, line)
	}
	var joined string
	for _, part := range strings.Split(line, `"`) {
		if !strings.HasPrefix(part, "_prefixes") && part != " " {
			joined += part
		}
	}
	if joined != long {
		t.Error("chunked zone line does not reassemble to the record value")
	}
	for _, c := range txtChunks(long) {
		if len(c) > txtStringMax {
			t.Errorf("chunk of %d octets exceeds %d", len(c), txtStringMax)
		}
	}
}

func TestRelativeName(t *testing.T) {
	if got := relativeName("2026a._sworn.example.com", "example.com"); got != "2026a._sworn" {
		t.Errorf("relativeName = %q", got)
	}
	if got := relativeName("_sworn.0.8.b.d.0.1.0.0.2.ip6.arpa", "example.com"); got != "_sworn.0.8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Errorf("out-of-zone name = %q", got)
	}
}

func TestNotesWarnOnCoarseUnitAndShortPrefix(t *testing.T) {
	pub := testKey(t)
	o := baseOptions(pub)
	o.Prefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	o.Unit = 24
	rs, err := buildRecords(o)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rs.Notes, "\n")
	for _, want := range []string{"coarser than", "shorter than /48", "observe-only"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes missing %q:\n%s", want, all)
		}
	}
}

func TestParsePrefixesSplitsCommas(t *testing.T) {
	got, err := parsePrefixes([]string{"2001:db8:f00::/48, 2620:12a:8000::/48", "2001:db8:1::/64"})
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v, err %v", got, err)
	}
	if _, err := parsePrefixes([]string{"nonsense"}); err == nil {
		t.Error("nonsense prefix accepted")
	}
}
