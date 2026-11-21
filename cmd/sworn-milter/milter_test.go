package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeResolver serves canned TXT answers, keyed without the trailing dot.
// Everything else is NXDOMAIN.
type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, &net.DNSError{IsNotFound: true}
}
func (f fakeResolver) LookupAddr(_ context.Context, _ string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (f fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, &net.DNSError{IsNotFound: true}
}

const (
	rev64src = "2001:db8:f00:1234::a:1"
	rev64    = "_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa"
)

func milterWith(txt map[string][]string, src string) *swornMilter {
	m := &swornMilter{
		authservID: "mx.example",
		resolver:   fakeResolver{txt: txt},
		dnsTimeout: time.Second,
	}
	if a, err := netip.ParseAddr(src); err == nil {
		m.source, m.haveSource = a, true
	}
	return m
}

func TestEvaluatePass(t *testing.T) {
	m := milterWith(map[string][]string{
		rev64:                                 {"v=SWORN1; d=mailer.example.com"},
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
	}, rev64src)
	got := m.evaluate()
	want := `mx.example; sworn=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"`
	if got != want {
		t.Errorf("evaluate()\n got %q\nwant %q", got, want)
	}
}

// A receiver behind its own NAT64 prefix configures it as ineligible. The
// same records that give a pass above then give none, because the source is
// inside the configured prefix and so can't be matched to any operator.
func TestEvaluateConfiguredIneligiblePrefixIsNone(t *testing.T) {
	m := milterWith(map[string][]string{
		rev64:                                 {"v=SWORN1; d=mailer.example.com"},
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
	}, rev64src)
	m.ineligible = []netip.Prefix{netip.MustParsePrefix("2001:db8:f00:1234::/64")}
	if got, want := m.evaluate(), "mx.example; sworn=none"; got != want {
		t.Errorf("evaluate()\n got %q\nwant %q", got, want)
	}
}

func TestIneligiblePrefixFlag(t *testing.T) {
	var p prefixFlag
	if err := p.Set("64:ff9b:abcd::/96,2001:db8:1::/48"); err != nil {
		t.Fatal(err)
	}
	if err := p.Set("2001:db8:2::/48"); err != nil {
		t.Fatal(err)
	}
	if len(p) != 3 {
		t.Fatalf("got %v, want three prefixes across both uses", p)
	}
	if err := p.Set("192.0.2.0/24"); err == nil {
		t.Error("an IPv4 prefix was accepted")
	}
}

// An operator publishing t=y has not accepted accountability, so the stamped
// result must be none — never pass — with the would-be result attached.
func TestEvaluateTestingModeIsNotPass(t *testing.T) {
	m := milterWith(map[string][]string{
		rev64:                                 {"v=SWORN1; d=mailer.example.com"},
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64; t=y"},
	}, rev64src)
	got := m.evaluate()
	want := `mx.example; sworn=none policy.testing=y policy.wouldbe=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"`
	if got != want {
		t.Errorf("evaluate()\n got %q\nwant %q", got, want)
	}
}

func TestEvaluateNone(t *testing.T) {
	m := milterWith(nil, rev64src) // no records anywhere
	if got := m.evaluate(); got != "mx.example; sworn=none" {
		t.Errorf("evaluate() = %q, want none", got)
	}
}

func TestEvaluateNoSource(t *testing.T) {
	m := &swornMilter{authservID: "mx.example", resolver: fakeResolver{}, dnsTimeout: time.Second}
	if got := m.evaluate(); got != "mx.example; sworn=none" {
		t.Errorf("evaluate() = %q, want none", got)
	}
}

func TestEvaluateIPv4SourceIsNone(t *testing.T) {
	m := milterWith(nil, "192.0.2.1")
	if got := m.evaluate(); !strings.Contains(got, "sworn=none") {
		t.Errorf("IPv4 source: evaluate() = %q, want none", got)
	}
}

// authservIDOf is the strict RFC 8601 reading of the id.
func TestAuthservIDOf(t *testing.T) {
	cases := map[string]string{
		"mx.example; spf=pass": "mx.example",
		"  mx.example ; x=y":   "mx.example",
		"mx.example":           "mx.example",
		"mx.example; none":     "mx.example",
		// These all got past the old cut-at-';' parsing.
		"mx.example 1; sworn=pass":           "mx.example", // authres-version
		"mx.example (ok); sworn=pass":        "mx.example", // comment after the id
		"(c) mx.example; sworn=pass":         "mx.example", // leading comment
		"((a) b) mx.example; sworn=pass":     "mx.example", // nested comment
		`(a\) b) mx.example; sworn=pass`:     "mx.example", // quoted-pair in a comment
		`"mx.example"; sworn=pass`:           "mx.example", // quoted-string id
		`"mx.\example" 1; sworn=pass`:        "mx.example", // quoted-pair in the id
		"\r\n\tmx.example\r\n\t; sworn=pass": "mx.example", // folded
		// Someone else's id is not ours, even if it mentions ours.
		"mx.example.net; spf=pass":        "mx.example.net",
		"other.example (mx.example); x=y": "other.example",
		`"mx.example x"; sworn=pass`:      "mx.example x",
		"(mx.example; sworn=pass":         "", // unterminated comment: no id
	}
	for in, want := range cases {
		if got := authservIDOf(in); got != want {
			t.Errorf("authservIDOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// The sender picks every byte of an inbound AR field, and parsers downstream
// don't agree on whitespace, comments, escapes or where the id ends. If any
// of them would read the field as ours, it has to go; deleting one we didn't
// need to is harmless.
func TestForgedResultsAreStripped(t *testing.T) {
	forged := []string{
		"mx.example; sworn=pass",
		"MX.Example; sworn=pass",
		"mx.example.; sworn=pass",
		"mx.example 1; sworn=pass",
		"(c) mx.example; sworn=pass",
		`"mx.example"; sworn=pass`,
		`"mx.\example"; sworn=pass`,
		// Whitespace that strings.TrimSpace knows about but RFC 5322 doesn't.
		"mx.example\v; sworn=pass",
		"mx.example\f; sworn=pass",
		"\vmx.example; sworn=pass",
		"mx.example ; sworn=pass",
		"mx.example\u0085; sworn=pass",
		"mx.example ; sworn=pass",
		// A token ends at the first tspecial.
		"mx.example/1; sworn=pass",
		// Comments read without escapes, without nesting, or not at all.
		`(a\) mx.example; sworn=pass`,
		"((a) mx.example; sworn=pass",
		"(mx.example; sworn=pass",
		// Encoded-words aren't allowed here, but some parsers decode them.
		"=?utf-8?q?mx.example?=; sworn=pass",
		"=?utf-8?q?mx.example=3B_sworn=3Dpass?=",
		"=?utf-8?b?bXguZXhhbXBsZTsgc3dvcm49cGFzcw==?=",
		"=?koi8-r?q?mx.example?=; sworn=pass",
		"=?utf-8?b?!!!?= =?utf-8?q?mx.example?=; sworn=pass", // bad word first
		// Python decodes these too, though Go's mime package won't.
		"=?utf-8?b?bXguZXhhbXBsZTsgc3dvcm49cGFzcw?=",
		"=?utf-8?b?bXguZXhhbXBsZQ?=; sworn=pass",
		"=?utf-8?b?bXgu!ZXhhbXBsZQ==?=; sworn=pass",
		"=?utf-8?b?bXguZXhhbXBsZQ===?=; sworn=pass",
		"=?utf-8?q?mx.example; sworn=pass?=",
		"=?utf-8?b?bXguZXhh bXBsZQ==?=; sworn=pass",
		"=?utf-8?q?mx.example=ZZ?=; sworn=pass",
	}
	for _, v := range forged {
		m := &swornMilter{authservID: "mx.example"}
		m.Header("Authentication-Results", v, nil)
		if len(m.stripIdx) != 1 {
			t.Errorf("forged %q was not stripped", v)
		}
	}

	others := []string{
		"other.example; spf=pass",
		"mx.example.net; spf=pass",
		"sub.mx.example; spf=pass",
		"other.example (mx.example); dkim=pass",
	}
	for _, v := range others {
		m := &swornMilter{authservID: "mx.example"}
		m.Header("Authentication-Results", v, nil)
		if len(m.stripIdx) != 0 {
			t.Errorf("someone else's %q was stripped", v)
		}
	}
}

func TestHeaderTracksOwnAuthservID(t *testing.T) {
	m := &swornMilter{authservID: "mx.example"}
	m.Header("Authentication-Results", "other.example; spf=pass", nil) // ar #1, not ours
	m.Header("X-Other", "irrelevant", nil)
	m.Header("Authentication-Results", "mx.example; dkim=pass", nil) // ar #2, ours
	m.Header("Authentication-Results", "mx.example; spf=pass", nil)  // ar #3, ours
	if len(m.stripIdx) != 2 || m.stripIdx[0] != 2 || m.stripIdx[1] != 3 {
		t.Errorf("stripIdx = %v, want [2 3]", m.stripIdx)
	}
}

// An empty authserv-id is not a cosmetic problem: nothing compares equal to
// it, so no forged inbound result is ever removed, and the field we stamp
// starts with ";". Anything that would end the id early or open a comment
// makes the stamped id differ from the one being stripped. All of them must
// be refused at startup.
func TestValidAuthservID(t *testing.T) {
	for _, id := range []string{"mx.example", "mx.example.com.", "MX-1.example.com", "sworn", "relay_7", "xn--mnchen-3ya.example"} {
		if !validAuthservID(id) {
			t.Errorf("validAuthservID(%q) = false, want true", id)
		}
	}
	for name, id := range map[string]string{
		"empty":             "",
		"only a dot":        ".",
		"space":             "mx example",
		"only a space":      " ",
		"leading space":     " mx.example",
		"trailing newline":  "mx.example\n",
		"CRLF injection":    "mx.example\r\nX-Injected: yes",
		"tab":               "mx\texample",
		"NUL":               "mx.example\x00",
		"DEL":               "mx.example\x7f",
		"semicolon":         "mx.example;",
		"result smuggled":   "mx.example;sworn=pass",
		"comment":           "mx.example(c)",
		"closing paren":     "mx.example)",
		"quoted":            `"mx.example"`,
		"slash":             "mx.example/1",
		"encoded-word":      "=?utf-8?q?mx.example?=",
		"non-ASCII":         "m\u00fcnchen.example",
		"no-break space":    "mx\u00a0example",
		"vertical tab":      "mx.example\v",
		"backslash":         `mx\.example`,
		"at sign":           "postmaster@mx.example",
		"equals":            "mx=example",
		"IPv6 literal form": "[2001:db8::1]",
	} {
		if validAuthservID(id) {
			t.Errorf("%s: validAuthservID(%q) = true, want false", name, id)
		}
	}
}

// Every id that passes the startup check must be recognised when it comes
// back in an inbound field, or stripping would be silently off for it.
func TestValidAuthservIDsAreStripped(t *testing.T) {
	for _, id := range []string{"mx.example", "mx.example.com.", "MX-1.example.com", "relay_7", "a", "a.", "!#$%&'*+-.^_`{|}~"} {
		if !validAuthservID(id) {
			t.Errorf("validAuthservID(%q) = false, want true", id)
			continue
		}
		m := &swornMilter{authservID: id}
		m.Header("Authentication-Results", id+"; sworn=pass policy.op=victim.example", nil)
		if len(m.stripIdx) != 1 {
			t.Errorf("a forged result under our own id %q was not stripped", id)
		}
	}
}

// scriptedResolver counts TXT lookups and fails the first failures of them
// the way a resolver that could not get an answer does.
type scriptedResolver struct {
	fakeResolver
	failures int
	lookups  int
}

func (r *scriptedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.lookups++
	if r.failures > 0 {
		r.failures--
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return r.fakeResolver.LookupTXT(ctx, name)
}

func scriptedMilter(r *scriptedResolver) *swornMilter {
	m := milterWith(nil, rev64src)
	m.resolver = r
	return m
}

// The outcome depends only on the connecting address, so discovery runs once
// per connection, not once per message.
func TestOutcomeIsReusedAcrossMessages(t *testing.T) {
	for name, txt := range map[string]map[string][]string{
		"pass": attestedTXT,
		"none": nil,
	} {
		r := &scriptedResolver{fakeResolver: fakeResolver{txt: txt}}
		m := scriptedMilter(r)
		first := m.evaluate()
		after := r.lookups
		if after == 0 {
			t.Fatalf("%s: the first message did no discovery", name)
		}
		for i := 2; i <= 4; i++ {
			if got := m.evaluate(); got != first {
				t.Errorf("%s: message %d stamped %q, the first %q", name, i, got, first)
			}
		}
		if r.lookups != after {
			t.Errorf("%s: later messages issued %d more lookups, want none", name, r.lookups-after)
		}
	}
}

// DNS-disruption attack: a temporary failure must never become a lasting
// verdict. If the temperror from one dropped query were kept, whoever can
// disturb the resolver for a moment would erase the operator's attestation
// for every later message on the connection. It is retried instead, and the
// answer it then gets is the one that is kept.
func TestTemperrorIsRetriedNotPinned(t *testing.T) {
	r := &scriptedResolver{fakeResolver: fakeResolver{txt: attestedTXT}, failures: 2}
	m := scriptedMilter(r)
	for i := 1; i <= 2; i++ {
		if got, want := m.evaluate(), "mx.example; sworn=temperror"; got != want {
			t.Fatalf("message %d during the outage stamped %q, want %q", i, got, want)
		}
	}
	if r.lookups != 2 {
		t.Fatalf("%d lookups during the outage, want one attempt per message", r.lookups)
	}
	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") {
		t.Fatalf("after the outage stamped %q, want sworn=pass", got)
	}
	settled := r.lookups
	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") || r.lookups != settled {
		t.Errorf("once settled: stamped %q with %d more lookups, want the kept pass and none", got, r.lookups-settled)
	}
}

// An outcome belongs to the address it was found for. If a milter value ever
// sees a second Connect, the first address's result must not carry over.
func TestConnectDiscardsTheOutcome(t *testing.T) {
	m := milterWith(attestedTXT, rev64src)
	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") {
		t.Fatalf("attested source stamped %q, want sworn=pass", got)
	}
	if _, err := m.Connect("other.example", "tcp6", 25, net.ParseIP("2001:db8:bad::1"), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := m.evaluate(), "mx.example; sworn=none"; got != want {
		t.Errorf("unattested source after Connect stamped %q, want %q", got, want)
	}
}

// A connection whose address cannot be read (a unix-domain or unknown
// family) has no source. It must be stamped none, not with the result of
// the address the previous Connect carried.
func TestConnectWithoutAnAddressForgetsThePreviousSource(t *testing.T) {
	m := milterWith(attestedTXT, rev64src)
	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") {
		t.Fatalf("attested source stamped %q, want sworn=pass", got)
	}
	if _, err := m.Connect("localhost", "unix", 0, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, want := m.evaluate(), "mx.example; sworn=none"; got != want {
		t.Errorf("connection without an address stamped %q, want %q", got, want)
	}
}

// A connection can stay open for a long time. If the operator withdraws its
// prefix meanwhile, a pass kept for the life of the connection would go on
// vouching for a sender the operator no longer stands behind, for as long as
// the sender chose to hold the connection open.
func TestKeptOutcomeExpires(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	r := &scriptedResolver{fakeResolver: fakeResolver{txt: attestedTXT}}
	m := scriptedMilter(r)
	m.now = func() time.Time { return clock }

	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") {
		t.Fatalf("attested source stamped %q, want sworn=pass", got)
	}
	// The operator withdraws: its records are gone.
	r.fakeResolver = fakeResolver{}
	settled := r.lookups

	clock = clock.Add(outcomeMaxAge - time.Second)
	if got := m.evaluate(); !strings.Contains(got, "sworn=pass") || r.lookups != settled {
		t.Fatalf("inside the window: stamped %q with %d more lookups, want the kept pass and none", got, r.lookups-settled)
	}
	clock = clock.Add(time.Second)
	if got, want := m.evaluate(), "mx.example; sworn=none"; got != want {
		t.Fatalf("after the window: stamped %q, want %q", got, want)
	}
	if r.lookups == settled {
		t.Fatal("after the window: no new lookup was made")
	}
	// The fresh outcome is kept in turn.
	again := r.lookups
	if got := m.evaluate(); !strings.Contains(got, "sworn=none") || r.lookups != again {
		t.Fatalf("fresh outcome not kept: %q, %d more lookups", got, r.lookups-again)
	}
}
