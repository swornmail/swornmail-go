// Package discover implements SwornMail Mode-1 (DNS-only) attestation
// discovery, per draft-kafedzhy-swornmail-01 §Mode 1. Given a connecting
// source address it finds the accountable operator domain — via the
// reverse-tree pointer where present, otherwise via forward-confirmed PTR
// candidates — bounded by a total DNS-query budget. No per-connection
// cryptography; the result is a prefix-to-operator binding weaker than a
// Mode-2 token.
package discover

import (
	"context"
	"net/netip"
	"strings"
)

// Resolver is the DNS surface discovery needs. *net.Resolver satisfies it
// directly; tests inject a fake so no network is required. Implementations
// are expected to enforce their own CNAME chain-length limits.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// MaxQueries bounds total DNS work for one discovery (I-D -01 §Discovery):
// reverse-tree queries, PTR + forward confirmation, and candidate lookups
// combined. Exhaustion yields a temporary error.
const MaxQueries = 10

const hexDigits = "0123456789abcdef"

// reverseNibbleName builds the reverse-tree query name for the enclosing
// prefix of length prefixLen (a multiple of 4, i.e. /48 or /64), with the
// `_sworn` label leftmost so the name falls inside the operator's reverse
// delegation, e.g. for 2001:db8:f00:1234::a:1 at /64:
// `_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa`.
func reverseNibbleName(a netip.Addr, prefixLen int) (string, bool) {
	if !a.Is6() || a.Is4In6() || prefixLen%4 != 0 || prefixLen < 4 || prefixLen > 128 {
		return "", false
	}
	b := a.As16()
	nibbles := make([]byte, 32)
	for i, x := range b {
		nibbles[2*i] = hexDigits[x>>4]
		nibbles[2*i+1] = hexDigits[x&0x0f]
	}
	n := prefixLen / 4
	var sb strings.Builder
	sb.WriteString("_sworn")
	for i := n - 1; i >= 0; i-- {
		sb.WriteByte('.')
		sb.WriteByte(nibbles[i])
	}
	sb.WriteString(".ip6.arpa")
	return sb.String(), true
}

// candidateDomains yields the ordered operator-domain candidates derived from
// a forward-confirmed PTR hostname (I-D -01 §Discovery step 2): the hostname
// itself, then successive parents by stripping one leading label, at most 5.
// Without a public-suffix list, candidates with fewer than 3 labels are not
// evaluated; if isPublicSuffix is non-nil, a public suffix or its ancestor
// stops the walk instead.
func candidateDomains(host string, isPublicSuffix func(string) bool) []string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	var out []string
	for cur := host; cur != "" && len(out) < 5; {
		labels := strings.Split(cur, ".")
		if isPublicSuffix != nil {
			if isPublicSuffix(cur) {
				break
			}
		} else if len(labels) < 3 {
			break
		}
		out = append(out, cur)
		if len(labels) < 2 {
			break
		}
		cur = strings.Join(labels[1:], ".")
	}
	return out
}
