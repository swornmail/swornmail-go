package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeResolver serves canned TXT answers; everything else is NXDOMAIN.
type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
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
	want := `mx.example; sworn=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64"`
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

func TestAuthservIDOf(t *testing.T) {
	cases := map[string]string{
		"mx.example; spf=pass": "mx.example",
		"  mx.example ; x=y":   "mx.example",
		"mx.example":           "mx.example",
	}
	for in, want := range cases {
		if got := authservIDOf(in); got != want {
			t.Errorf("authservIDOf(%q) = %q, want %q", in, got, want)
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
