package discover

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestAuthResults(t *testing.T) {
	pass := Result{
		Operator:     "mailer.example.com",
		Unit:         netip.MustParsePrefix("2001:db8:f00:1234::/64"),
		ObservedUnit: netip.MustParsePrefix("2001:db8:f00:1234::/64"),
		Mode:         "dns",
	}
	// A publisher declaring a coarse unit over a shared aggregate: the header
	// must still show the /64 the connection actually corroborated, so a
	// consumer reading only this line cannot widen where reputation lands.
	coarse := Result{
		Operator:     "tenant.example",
		Unit:         netip.MustParsePrefix("2001:db8::/32"),
		ObservedUnit: netip.MustParsePrefix("2001:db8:f00:1234::/64"),
		Mode:         "dns",
	}
	observing := pass
	observing.Testing = true

	for name, tc := range map[string]struct {
		res  Result
		err  error
		want string
	}{
		"pass": {pass, nil,
			`mx.example.net; sworn=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"`},
		"coarse declared unit still reports the observed /64": {coarse, nil,
			`mx.example.net; sworn=pass policy.mode=dns policy.op=tenant.example policy.unit="2001:db8::/32" policy.observed="2001:db8:f00:1234::/64"`},
		// t=y is a MUST: report none, carry the would-be result, stake nothing.
		"testing mode": {observing, nil,
			`mx.example.net; sworn=none policy.testing=y policy.wouldbe=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1234::/64" policy.observed="2001:db8:f00:1234::/64"`},
		"temperror": {Result{}, ErrTemp, "mx.example.net; sworn=temperror"},
		"none":      {Result{}, ErrNone, "mx.example.net; sworn=none"},
		"wrapped temp": {Result{}, errors.Join(errors.New("resolver died"), ErrTemp),
			"mx.example.net; sworn=temperror"},
	} {
		if got := AuthResults("mx.example.net", tc.res, tc.err); got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", name, got, tc.want)
		}
	}
}

// A testing-mode operator must never be reported as passing: consumers keying
// on sworn=pass would stake reputation the operator has not accepted.
func TestAuthResultsTestingIsNeverPass(t *testing.T) {
	got := AuthResults("mx.example.net", Result{
		Operator: "mailer.example.com",
		Unit:     netip.MustParsePrefix("2001:db8:f00::/64"),
		Mode:     "dns",
		Testing:  true,
	}, nil)
	if strings.Contains(got, "sworn=pass") {
		t.Errorf("testing-mode operator reported as pass: %s", got)
	}
	if !strings.Contains(got, "policy.testing=y") || !strings.Contains(got, "policy.wouldbe=pass") {
		t.Errorf("testing result missing required properties: %s", got)
	}
}

// RFC 8601 requires a pvalue containing ':' or '/' to be a quoted-string.
func TestAuthResultsQuotesUnit(t *testing.T) {
	got := AuthResults("mx", Result{Operator: "d.example", Unit: netip.MustParsePrefix("2001:db8::/48"), Mode: "dns"}, nil)
	if !strings.Contains(got, `policy.unit="2001:db8::/48"`) {
		t.Errorf("unit not quoted: %s", got)
	}
}
