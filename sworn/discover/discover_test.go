package discover

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// fakeResolver serves canned answers so discovery tests need no network.
type fakeResolver struct {
	txt   map[string][]string
	ptr   map[string][]string
	ip    map[string][]netip.Addr
	fail  map[string]bool // name -> temporary failure
	calls int
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.calls++
	if f.fail[name] {
		return nil, &net.DNSError{Err: "timeout", IsTimeout: true}
	}
	v, ok := f.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "nxdomain", IsNotFound: true}
	}
	return v, nil
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls++
	v, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "nxdomain", IsNotFound: true}
	}
	return v, nil
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls++
	v, ok := f.ip[host]
	if !ok {
		return nil, &net.DNSError{Err: "nxdomain", IsNotFound: true}
	}
	return v, nil
}

var (
	src       = netip.MustParseAddr("2001:db8:f00:1234::a:1")
	rev64     = "_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa"
	rev48     = "_sworn.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa"
	wantUnit  = netip.MustParsePrefix("2001:db8:f00:1234::/64")
	policyTXT = "v=SWORN1; p=2001:db8:f00::/48; u=64"
)

func TestReverseNibbleName(t *testing.T) {
	got64, ok := reverseNibbleName(src, 64)
	if !ok || got64 != rev64 {
		t.Errorf("/64 name = %q, want %q", got64, rev64)
	}
	got48, ok := reverseNibbleName(src, 48)
	if !ok || got48 != rev48 {
		t.Errorf("/48 name = %q, want %q", got48, rev48)
	}
}

func discover(t *testing.T, f *fakeResolver) (Result, error) {
	t.Helper()
	return Discover(context.Background(), f, src, Options{})
}

func TestReverseTreeHit(t *testing.T) {
	f := &fakeResolver{
		txt: map[string][]string{
			rev64:                                 {"v=SWORN1; d=mailer.example.com"},
			"_prefixes._sworn.mailer.example.com": {policyTXT},
		},
	}
	res, err := discover(t, f)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Operator != "mailer.example.com" || res.Mode != "dns" || res.Unit != wantUnit {
		t.Errorf("result = %+v", res)
	}
	// The attested prefix is reported alongside the unit: they differ, and a
	// caller recording accountability needs the prefix the operator staked.
	if res.Prefix.String() != "2001:db8:f00::/48" {
		t.Errorf("attested prefix = %s, want 2001:db8:f00::/48", res.Prefix)
	}
}

// Where several enumerated prefixes cover the source, the reported prefix is
// the longest match — the same precedence receivers apply.
func TestLongestMatchingPrefixIsReported(t *testing.T) {
	f := &fakeResolver{
		txt: map[string][]string{
			rev64: {"v=SWORN1; d=mailer.example.com"},
			"_prefixes._sworn.mailer.example.com": {
				"v=SWORN1; p=2001:db8::/32,2001:db8:f00::/48,2001:db8:f00:1234::/64; u=64",
			},
		},
	}
	res, err := discover(t, f)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Prefix.String() != "2001:db8:f00:1234::/64" {
		t.Errorf("attested prefix = %s, want the longest match", res.Prefix)
	}
}

// t=y must survive discovery so the caller can report it; the walk itself is
// unaffected — a testing operator still confirms.
func TestTestingFlagPropagates(t *testing.T) {
	for name, tc := range map[string]struct {
		policy string
		want   bool
	}{
		"testing":         {"v=SWORN1; p=2001:db8:f00::/48; u=64; t=y", true},
		"not testing":     {policyTXT, false},
		"unknown flag":    {"v=SWORN1; p=2001:db8:f00::/48; u=64; t=x", false},
		"flag list has y": {"v=SWORN1; p=2001:db8:f00::/48; u=64; t=x:y", true},
	} {
		f := &fakeResolver{
			txt: map[string][]string{
				rev64:                                 {"v=SWORN1; d=mailer.example.com"},
				"_prefixes._sworn.mailer.example.com": {tc.policy},
			},
		}
		res, err := discover(t, f)
		if err != nil {
			t.Fatalf("%s: Discover: %v", name, err)
		}
		if res.Testing != tc.want {
			t.Errorf("%s: Testing = %t, want %t", name, res.Testing, tc.want)
		}
	}
}

func TestReverseTreeLongestFirst(t *testing.T) {
	// Both /64 and /48 pointers exist; the more specific /64 must win.
	f := &fakeResolver{
		txt: map[string][]string{
			rev64:                                   {"v=SWORN1; d=specific.example.com"},
			rev48:                                   {"v=SWORN1; d=broad.example.com"},
			"_prefixes._sworn.specific.example.com": {policyTXT},
			"_prefixes._sworn.broad.example.com":    {policyTXT},
		},
	}
	res, err := discover(t, f)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Operator != "specific.example.com" {
		t.Errorf("operator = %q, want specific.example.com", res.Operator)
	}
}

func TestReverseTreeUnconfirmedFallsToPTR(t *testing.T) {
	// Pointer names a domain that does NOT cover the source; discovery must
	// fall through to the PTR path, which confirms a different operator.
	f := &fakeResolver{
		txt: map[string][]string{
			rev64:                                 {"v=SWORN1; d=liar.example.com"},
			"_prefixes._sworn.liar.example.com":   {"v=SWORN1; p=2001:db8:999::/48"},
			"_prefixes._sworn.mailer.example.com": {policyTXT},
		},
		ptr: map[string][]string{src.String(): {"mx.mailer.example.com."}},
		ip:  map[string][]netip.Addr{"mx.mailer.example.com": {src}},
	}
	res, err := discover(t, f)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Operator != "mailer.example.com" {
		t.Errorf("operator = %q, want mailer.example.com", res.Operator)
	}
}

func TestPTRCandidateWalk(t *testing.T) {
	// Host is deep; confirmation is at the 3rd candidate (mailer.example.com).
	f := &fakeResolver{
		ptr: map[string][]string{src.String(): {"mx.eu.mailer.example.com."}},
		ip:  map[string][]netip.Addr{"mx.eu.mailer.example.com": {src}},
		txt: map[string][]string{"_prefixes._sworn.mailer.example.com": {policyTXT}},
	}
	res, err := discover(t, f)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Operator != "mailer.example.com" {
		t.Errorf("operator = %q", res.Operator)
	}
}

func TestFCrDNSFailureIsNone(t *testing.T) {
	// PTR hostname does not forward-confirm to the source: not usable.
	f := &fakeResolver{
		ptr: map[string][]string{src.String(): {"mx.mailer.example.com."}},
		ip:  map[string][]netip.Addr{"mx.mailer.example.com": {netip.MustParseAddr("2001:db8:f00::9")}},
		txt: map[string][]string{"_prefixes._sworn.mailer.example.com": {policyTXT}},
	}
	if _, err := discover(t, f); !errors.Is(err, ErrNone) {
		t.Errorf("err = %v, want ErrNone", err)
	}
}

func TestNoAttestationIsNone(t *testing.T) {
	f := &fakeResolver{} // everything NXDOMAIN
	if _, err := discover(t, f); !errors.Is(err, ErrNone) {
		t.Errorf("err = %v, want ErrNone", err)
	}
}

func TestTemporaryFailure(t *testing.T) {
	f := &fakeResolver{fail: map[string]bool{rev64: true}}
	if _, err := discover(t, f); !errors.Is(err, ErrTemp) {
		t.Errorf("err = %v, want ErrTemp", err)
	}
}

func TestIneligibleSourceIsNone(t *testing.T) {
	v4mapped := netip.MustParseAddr("::ffff:203.0.113.5")
	if _, err := Discover(context.Background(), &fakeResolver{}, v4mapped, Options{}); !errors.Is(err, ErrNone) {
		t.Errorf("err = %v, want ErrNone", err)
	}
}

func TestQueryBudgetNotExceeded(t *testing.T) {
	// Worst case: both reverse-tree misses, PTR hit, forward confirm, full
	// 5-candidate walk with no confirmation. Must stay within MaxQueries.
	f := &fakeResolver{
		ptr: map[string][]string{src.String(): {"a.b.c.d.e.example.com."}},
		ip:  map[string][]netip.Addr{"a.b.c.d.e.example.com": {src}},
	}
	if _, err := discover(t, f); !errors.Is(err, ErrNone) {
		t.Fatalf("err = %v, want ErrNone", err)
	}
	if f.calls > MaxQueries {
		t.Errorf("made %d queries, exceeds budget %d", f.calls, MaxQueries)
	}
}

func TestCandidateDomains(t *testing.T) {
	got := candidateDomains("mx.eu.mailer.example.com", nil)
	want := []string{"mx.eu.mailer.example.com", "eu.mailer.example.com", "mailer.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("candidate[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// Two-label host: no PSL means fewer than 3 labels is not evaluated.
	if c := candidateDomains("example.com", nil); len(c) != 0 {
		t.Errorf("two-label host yielded %v, want none", c)
	}
	// Deep host caps at 5 candidates.
	if c := candidateDomains("a.b.c.d.e.f.g.example.com", nil); len(c) != 5 {
		t.Errorf("deep host yielded %d candidates, want 5", len(c))
	}
}
