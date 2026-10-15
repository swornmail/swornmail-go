package discover

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAuthResults(t *testing.T) {
	// A declared unit coarser than the observed /64, so the test shows the
	// claim and the corroborated boundary are reported separately.
	confirmed := Result{
		Operator:     "mailer.example.com",
		Unit:         netip.MustParsePrefix("2001:db8:f00:1200::/56"),
		ObservedUnit: netip.MustParsePrefix("2001:db8:f00:1234::/64"),
		Mode:         "dns",
	}
	trial := confirmed
	trial.Testing = true

	cases := []struct {
		name string
		res  Result
		err  error
		want string
	}{
		{"pass", confirmed, nil,
			`mx.example; sworn=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1200::/56" policy.observed="2001:db8:f00:1234::/64"`},
		{"testing operator is never pass", trial, nil,
			`mx.example; sworn=none policy.testing=y policy.wouldbe=pass policy.mode=dns policy.op=mailer.example.com policy.unit="2001:db8:f00:1200::/56" policy.observed="2001:db8:f00:1234::/64"`},
		{"no confirming operator", Result{}, ErrNone, "mx.example; sworn=none"},
		{"temporary DNS failure", Result{}, ErrTemp, "mx.example; sworn=temperror"},
		{"unknown error names no operator", confirmed, errors.New("boom"), "mx.example; sworn=none"},
	}
	for _, c := range cases {
		if got := AuthResults("mx.example", c.res, c.err); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
