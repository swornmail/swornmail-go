package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/swornmail/swornmail-go/sworn"
	"github.com/swornmail/swornmail-go/sworn/discover"
)

// genOptions is the validated input to record generation.
type genOptions struct {
	Domain   string
	Selector string
	PubKey   ed25519.PublicKey
	Prefixes []netip.Prefix
	Unit     int
	Testing  bool
	RUA      string
}

// dnsRecord is one TXT record to publish.
type dnsRecord struct {
	QName string
	Value string
}

// recordSet is everything genrecord emits. It is built and round-tripped
// through the protocol's own parsers before any of it is printed.
type recordSet struct {
	Domain   string
	Key      dnsRecord
	Policy   dnsRecord
	Pointers []dnsRecord // optional reverse-tree pointers (/48 and /64 only)
	Notes    []string
}

func cmdGenrecord(args []string) int {
	fs := flag.NewFlagSet("genrecord", flag.ContinueOnError)
	domain := fs.String("domain", "", "operator domain (required)")
	selector := fs.String("selector", "", "selector of the key record (required)")
	key := fs.String("key", "", "key file from `sworn keygen`, or a base64 public key (required)")
	unit := fs.Int("unit", sworn.DefaultUnitPrefixLen, "reputation unit prefix length, 1-64")
	testing := fs.Bool("testing", true, "publish t=y, observe-only; --testing=false stakes reputation")
	rua := fs.String("rua", "", "aggregate report destination, mailto:<mailbox>@<domain>")
	asJSON := fs.Bool("json", false, "JSON output, for driving a DNS provider's API")
	var prefixArgs stringList
	fs.Var(&prefixArgs, "prefix", "attested IPv6 prefix (repeat the flag, or comma-separate)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *domain == "" || *selector == "" || *key == "" || len(prefixArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sworn genrecord --domain <d> --selector <sel> --key <file|b64> --prefix <p> [--prefix <p>...]")
		fmt.Fprintln(os.Stderr, "       [--unit N] [--testing=false] [--rua mailto:<addr>] [--json]")
		return 2
	}

	pub, err := loadPublicKey(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn: --key:", err)
		return 2
	}
	prefixes, err := parsePrefixes(prefixArgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}
	rs, err := buildRecords(genOptions{
		Domain: *domain, Selector: *selector, PubKey: pub,
		Prefixes: prefixes, Unit: *unit, Testing: *testing, RUA: *rua,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}
	if *asJSON {
		return printRecordSetJSON(os.Stdout, rs)
	}
	printRecordSet(os.Stdout, rs)
	return 0
}

// parsePrefixes turns the raw --prefix arguments into prefixes, naming the
// syntax problem rather than echoing netip's parser error alone.
func parsePrefixes(args []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, arg := range args {
		for _, s := range strings.Split(arg, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid --prefix %q: expected CIDR form, e.g. 2001:db8:f00::/48", s)
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// buildRecords validates every -01 constraint an operator can violate, then
// assembles the records. Validation failures name the rule they broke: this
// command is a linter as much as a generator.
func buildRecords(o genOptions) (recordSet, error) {
	if !sworn.ValidDomain(o.Domain) {
		return recordSet{}, fmt.Errorf("invalid --domain %q: %s", o.Domain, domainRule)
	}
	if !sworn.ValidSelector(o.Selector) {
		return recordSet{}, fmt.Errorf("invalid --selector %q: %s", o.Selector, selectorRule)
	}
	if len(o.PubKey) != ed25519.PublicKeySize {
		return recordSet{}, fmt.Errorf("public key is %d bytes, expected %d", len(o.PubKey), ed25519.PublicKeySize)
	}
	if len(o.Prefixes) == 0 {
		return recordSet{}, fmt.Errorf("at least one --prefix is required")
	}
	if len(o.Prefixes) > sworn.MaxPolicyPrefixes {
		return recordSet{}, fmt.Errorf("%d prefixes: a policy record carries at most %d, and verifiers ignore the rest",
			len(o.Prefixes), sworn.MaxPolicyPrefixes)
	}
	if o.Unit < 1 || o.Unit > sworn.MaxUnitPrefixLen {
		return recordSet{}, fmt.Errorf("invalid --unit %d: must be 1-64; a value outside that range makes the record malformed rather than being clamped", o.Unit)
	}
	seen := make(map[netip.Prefix]bool, len(o.Prefixes))
	shortest := 128
	for _, p := range o.Prefixes {
		if err := sworn.ValidatePrefix(p); err != nil {
			return recordSet{}, fmt.Errorf("invalid --prefix %s: %s", p, explainPrefix(p))
		}
		if seen[p] {
			return recordSet{}, fmt.Errorf("--prefix %s listed twice", p)
		}
		seen[p] = true
		if p.Bits() < shortest {
			shortest = p.Bits()
		}
	}
	if err := validateRUA(o.RUA); err != nil {
		return recordSet{}, err
	}

	rs := recordSet{
		Domain: o.Domain,
		Key: dnsRecord{
			QName: o.Selector + "." + sworn.DNSLabel + "." + o.Domain,
			Value: fmt.Sprintf("v=%s; k=ed25519; pk=%s", sworn.Version, encodePublicKey(o.PubKey)),
		},
		Policy: dnsRecord{
			QName: "_prefixes." + sworn.DNSLabel + "." + o.Domain,
			Value: policyValue(o),
		},
	}
	if err := roundTrip(rs, o); err != nil {
		return recordSet{}, err
	}
	pointers, err := pointerRecords(o)
	if err != nil {
		return recordSet{}, err
	}
	rs.Pointers = pointers
	rs.Notes = notes(o, shortest, len(rs.Policy.Value))
	return rs, nil
}

func policyValue(o genOptions) string {
	ps := make([]string, len(o.Prefixes))
	for i, p := range o.Prefixes {
		ps[i] = p.String()
	}
	v := fmt.Sprintf("v=%s; p=%s; u=%d", sworn.Version, strings.Join(ps, ","), o.Unit)
	if o.Testing {
		v += "; t=y"
	}
	if o.RUA != "" {
		v += "; rua=" + o.RUA
	}
	return v
}

// pointerRecords emits a reverse-tree pointer for each prefix whose length is
// one discovery actually queries (the enclosing /64 and /48, -01 §Discovery
// step 1). Publishing it is optional and needs control of the reverse zone.
func pointerRecords(o genOptions) ([]dnsRecord, error) {
	var out []dnsRecord
	for _, p := range o.Prefixes {
		if p.Bits() != 48 && p.Bits() != 64 {
			continue
		}
		name, ok := discover.ReverseName(p.Addr(), p.Bits())
		if !ok {
			continue
		}
		rec := dnsRecord{QName: name, Value: fmt.Sprintf("v=%s; d=%s", sworn.Version, o.Domain)}
		if _, err := sworn.ParsePointerRecord(rec.Value); err != nil {
			return nil, fmt.Errorf("generated pointer record does not parse: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// roundTrip re-reads the generated records with the protocol's own parsers and
// compares the result to the input, so the tool can never emit a record its
// own verifier would reject or read differently.
func roundTrip(rs recordSet, o genOptions) error {
	key, err := sworn.ParseRecord(rs.Key.Value)
	if err != nil {
		return fmt.Errorf("generated key record does not parse: %w", err)
	}
	if !key.PublicKey.Equal(o.PubKey) {
		return fmt.Errorf("generated key record round-trips to a different key")
	}
	policy, err := sworn.ParsePolicyRecord(rs.Policy.Value)
	if err != nil {
		return fmt.Errorf("generated policy record does not parse: %w", err)
	}
	if len(policy.Prefixes) != len(o.Prefixes) {
		return fmt.Errorf("generated policy record round-trips to %d prefixes, not %d", len(policy.Prefixes), len(o.Prefixes))
	}
	for i, p := range policy.Prefixes {
		if p != o.Prefixes[i] {
			return fmt.Errorf("generated policy record round-trips prefix %s as %s", o.Prefixes[i], p)
		}
	}
	if int(policy.Unit) != o.Unit || policy.Testing != o.Testing || policy.RUA != o.RUA {
		return fmt.Errorf("generated policy record round-trips to different policy tags")
	}
	return nil
}

// validateRUA enforces -01 §Aggregate Feedback Reports (mailto: only) plus the
// tag-value syntax the record parser requires.
func validateRUA(rua string) error {
	if rua == "" {
		return nil
	}
	if strings.ContainsAny(rua, " \t;,\"\\") {
		return fmt.Errorf("invalid --rua %q: a tag value may not contain whitespace, ';', ',', or quoting characters", rua)
	}
	addr, ok := strings.CutPrefix(rua, "mailto:")
	if !ok {
		return fmt.Errorf("invalid --rua %q: only the mailto: scheme is defined", rua)
	}
	mailbox, domain, ok := strings.Cut(addr, "@")
	if !ok || mailbox == "" || !sworn.ValidDomain(domain) {
		return fmt.Errorf("invalid --rua %q: expected mailto:<mailbox>@<domain>", rua)
	}
	return nil
}

// domainRule states the -01 operator-domain syntax in operator terms.
const domainRule = "must be a domain in A-label form, at most 253 octets, each label 1-63 letters, digits or '-' not starting or ending with '-'"

// Diagnostic ranges. sworn.ValidatePrefix decides accept or reject; these only
// let the CLI name which rule a rejected prefix broke.
var (
	globalUnicast = netip.MustParsePrefix("2000::/3")
	teredo        = netip.MustParsePrefix("2001::/32")
	sixToFour     = netip.MustParsePrefix("2002::/16")
)

func explainPrefix(p netip.Prefix) string {
	switch {
	case !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6():
		return "must be an IPv6 prefix"
	// Length is reported ahead of canonical form: an out-of-range length is
	// the problem masking cannot fix.
	case p.Bits() < sworn.MinPrefixLen:
		return fmt.Sprintf("/%d is shorter than the /%d floor, which keeps one attestation from covering unrelated networks",
			p.Bits(), sworn.MinPrefixLen)
	case p.Bits() > sworn.MaxPrefixLen:
		return fmt.Sprintf("/%d is longer than /%d, the finest prefix SLAAC lets receivers aggregate on",
			p.Bits(), sworn.MaxPrefixLen)
	case p != p.Masked():
		return fmt.Sprintf("is not in masked canonical form; publish %s", p.Masked())
	case !globalUnicast.Contains(p.Addr()):
		return "is outside global unicast 2000::/3"
	case p.Overlaps(teredo):
		return "overlaps Teredo 2001::/32, which is not attestable"
	case p.Overlaps(sixToFour):
		return "overlaps 6to4 2002::/16, which is not attestable"
	default:
		return "is not attestable"
	}
}

// stringList collects a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }
