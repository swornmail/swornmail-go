package sworn

import (
	"fmt"
	"net/netip"
	"strings"
)

// VerifyOptions carries a receiver's local verification settings. The zero
// value applies the protocol's rules and nothing more.
type VerifyOptions struct {
	// IneligiblePrefixes are source ranges this receiver treats as
	// ineligible on top of the protocol's own list: its NAT64 or SIIT
	// translation prefixes, and any of its own infrastructure that relays
	// external traffic. Behind such a prefix many unrelated clients share
	// one address range, so a token or policy covering it would vouch for
	// all of them. The draft requires receivers that translate to list
	// these.
	IneligiblePrefixes []netip.Prefix
}

// Eligible reports whether a may be matched against an attested prefix: the
// protocol's eligibility rules, and outside every configured prefix.
func (o VerifyOptions) Eligible(a netip.Addr) bool {
	if !eligibleSource(a) {
		return false
	}
	for _, p := range o.IneligiblePrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ParseIneligiblePrefixes reads a comma-separated list of IPv6 prefixes, as a
// receiver's configuration supplies them. Each is masked to its length. An
// empty item, an IPv4 prefix, or anything unparseable is an error, so a typo
// in the configuration stops the receiver instead of silently letting
// translated traffic through.
func ParseIneligiblePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		p, err := netip.ParsePrefix(item)
		if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
			return nil, fmt.Errorf("sworn: %q is not an IPv6 prefix", item)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
