package sworn

import (
	"errors"
	"net/netip"
	"testing"
)

// A receiver that reaches IPv4 clients through its own NAT64 prefix sees all
// of them at addresses inside that one prefix. Without a local ineligible
// list, a token covering it would pass for every IPv4 client.
func TestConfiguredIneligiblePrefixRejectsSource(t *testing.T) {
	tok := mustSign(t, basePayload())
	opts := VerifyOptions{IneligiblePrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:f00:1234::/64")}}

	if _, err := PrepareVerificationWith(tok, inside, now, opts); !errors.Is(err, ErrIneligibleSrc) {
		t.Fatalf("source inside a configured prefix: err = %v, want ErrIneligibleSrc", err)
	}
	// The same token from another /64 of the attested prefix still verifies.
	other := netip.MustParseAddr("2001:db8:f00:abcd::1")
	if _, err := PrepareVerificationWith(tok, other, now, opts); err != nil {
		t.Fatalf("source outside the configured prefix: %v", err)
	}
	// And the zero options change nothing.
	if _, err := PrepareVerificationWith(tok, inside, now, VerifyOptions{}); err != nil {
		t.Fatalf("zero options: %v", err)
	}
}

func TestParseIneligiblePrefixes(t *testing.T) {
	got, err := ParseIneligiblePrefixes("64:ff9b:abcd::/96, 2001:db8:1::5/48")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("64:ff9b:abcd::/96"), netip.MustParsePrefix("2001:db8:1::/48")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v (masked)", got, want)
	}
	for _, bad := range []string{"192.0.2.0/24", "not-a-prefix", "2001:db8::", "2001:db8::/48,", ""} {
		if _, err := ParseIneligiblePrefixes(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}
