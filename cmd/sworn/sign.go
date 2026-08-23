package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

// recommendedLifetime is the -01 SHOULD for token lifetimes. Longer is legal
// up to the 24h hard cap, but it widens the replay window an attacker gets
// from temporary control of routing for the attested prefix.
const recommendedLifetime = time.Hour

func cmdSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "private key file from `sworn keygen` (required)")
	selector := fs.String("selector", "", "selector naming the published key record (required)")
	domain := fs.String("domain", "", "operator domain (required)")
	prefixArg := fs.String("prefix", "", "attested IPv6 prefix (required)")
	unit := fs.Int("unit", 0, "reputation unit prefix length (default 64, or the prefix length for esp-tenant)")
	role := fs.String("role", "mta", "mta | esp-tenant | forwarder")
	lifetime := fs.Duration("lifetime", recommendedLifetime, "token validity")
	nowUnix := fs.Int64("now", 0, "issue as of this Unix time (0 = wall clock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || *selector == "" || *domain == "" || *prefixArg == "" {
		fmt.Fprintln(os.Stderr, "usage: sworn sign --key <file> --selector <sel> --domain <d> --prefix <p>")
		fmt.Fprintln(os.Stderr, "       [--unit N] [--role mta|esp-tenant|forwarder] [--lifetime 1h]")
		return 2
	}
	if !sworn.ValidSelector(*selector) {
		fmt.Fprintf(os.Stderr, "sworn: invalid --selector %q: %s\n", *selector, selectorRule)
		return 2
	}
	if !sworn.ValidDomain(*domain) {
		fmt.Fprintf(os.Stderr, "sworn: invalid --domain %q: %s\n", *domain, domainRule)
		return 2
	}
	prefix, err := netip.ParsePrefix(*prefixArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sworn: invalid --prefix %q: expected CIDR form, e.g. 2001:db8:f00::/48\n", *prefixArg)
		return 2
	}
	if err := sworn.ValidatePrefix(prefix); err != nil {
		fmt.Fprintf(os.Stderr, "sworn: invalid --prefix %s: %s\n", prefix, explainPrefix(prefix))
		return 2
	}
	if *unit != 0 && (*unit < 1 || *unit > sworn.MaxUnitPrefixLen) {
		fmt.Fprintf(os.Stderr, "sworn: invalid --unit %d: must be 1-64\n", *unit)
		return 2
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn: --key:", err)
		return 2
	}
	if *lifetime > recommendedLifetime {
		fmt.Fprintf(os.Stderr, "sworn: warning: --lifetime %v exceeds the recommended %v\n", *lifetime, recommendedLifetime)
	}

	now := time.Now().UTC()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}
	token, err := sworn.Sign(sworn.Payload{
		Operator: *domain,
		Prefix:   prefix,
		Unit:     unitFor(*unit, *role, prefix),
		IssuedAt: now,
		Expires:  now.Add(*lifetime),
		Role:     *role,
	}, *selector, priv)
	if err != nil {
		// sworn errors already carry the "sworn:" prefix.
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, sworn.ErrBadRole) {
			fmt.Fprintln(os.Stderr, "sworn: --role must be mta, esp-tenant, or forwarder")
		}
		return 2
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(token))
	return 0
}

// unitFor applies the default the operator did not state: 64, except for
// esp-tenant, where -01 requires unit == prefix length so a tenant's
// reputation unit is never finer than the prefix it is accountable for.
func unitFor(unit int, role string, prefix netip.Prefix) uint8 {
	if unit != 0 {
		return uint8(unit)
	}
	if role == "esp-tenant" {
		return uint8(prefix.Bits())
	}
	return sworn.DefaultUnitPrefixLen
}
