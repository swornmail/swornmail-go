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
