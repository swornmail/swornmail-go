package discover

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/swornmail/swornmail-go/sworn"
)

// Result of a successful Mode-1 discovery.
type Result struct {
	Operator string       // confirmed accountable operator domain
	Unit     netip.Prefix // source masked to the operator's declared unit
	Mode     string       // always "dns" for Mode 1
	// Testing reports the operator's t=y flag. Discovery itself is
	// unaffected; reporting is not. Callers MUST NOT stake reputation on a
	// testing operator, for credit or blame — see AuthResults.
	Testing bool
}

// Outcome sentinels. ErrNone maps to sworn=none (no confirming operator),
// ErrTemp to sworn=temperror (DNS failure or query-budget exhaustion).
var (
	ErrNone = errors.New("sworn/discover: no confirming operator")
	ErrTemp = errors.New("sworn/discover: temporary DNS failure")
)

// Options tunes discovery. The zero value is valid.
type Options struct {
	// IsPublicSuffix, if set, decides the candidate-walk stop instead of the
	// default "fewer than 3 labels" rule (I-D -01 §Discovery step 2).
	IsPublicSuffix func(string) bool
}

type discovery struct {
	ctx    context.Context
	r      Resolver
	budget int
	opt    Options
}

// Discover runs Mode-1 discovery for a connecting source address. It returns a
// Result on confirmation, ErrNone when no operator confirms, or ErrTemp on a
// temporary DNS failure or budget exhaustion. Ineligible sources (not ordinary
// global-unicast IPv6) yield ErrNone: Mode 1 attests IPv6 space only.
func Discover(ctx context.Context, r Resolver, source netip.Addr, opt Options) (Result, error) {
	if !source.Is6() || source.Is4In6() {
		return Result{}, ErrNone
	}
	d := &discovery{ctx: ctx, r: r, budget: MaxQueries, opt: opt}

	// Step 1: reverse-tree pointer, longest (more specific) prefix first.
	for _, prefixLen := range []int{64, 48} {
		name, ok := reverseNibbleName(source, prefixLen)
		if !ok {
			continue
		}
		txts, err := d.lookupTXT(name)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return Result{}, ErrTemp
		}
		domain, ok := d.pointerDomain(txts)
		if !ok {
			continue
		}
		res, confirmed, err := d.confirm(domain, source)
		if err != nil {
			return Result{}, err
		}
		if confirmed {
			return res, nil
		}
		// d= named a domain that does not confirm: fall through to step 2.
	}

	// Step 2: forward-confirmed PTR candidates (at most one PTR name).
	ptrs, err := d.lookupAddr(source)
	if err != nil {
		if isNotFound(err) {
			return Result{}, ErrNone
		}
		return Result{}, ErrTemp
	}
	if len(ptrs) == 0 {
		return Result{}, ErrNone
	}
	host := strings.TrimSuffix(ptrs[0], ".")
	confirmedHost, err := d.forwardConfirm(host, source)
	if err != nil {
		return Result{}, ErrTemp
	}
	if !confirmedHost {
		return Result{}, ErrNone
	}
	for _, candidate := range candidateDomains(host, d.opt.IsPublicSuffix) {
		res, confirmed, err := d.confirm(candidate, source)
		if err != nil {
			return Result{}, err
		}
		if confirmed {
			return res, nil
		}
	}
	return Result{}, ErrNone
}

// pointerDomain extracts the operator domain from a reverse-tree pointer TXT
// set, requiring exactly one v=SWORN1 record.
func (d *discovery) pointerDomain(txts []string) (string, bool) {
	rec, ok := singleSwornRecord(txts)
	if !ok {
		return "", false
	}
	domain, err := sworn.ParsePointerRecord(rec)
	if err != nil {
		return "", false
	}
	return domain, true
}

// confirm checks whether source falls within a prefix enumerated in the
// candidate's policy record; on success it returns the Mode-1 Result keyed on
// the policy record's declared unit.
func (d *discovery) confirm(domain string, source netip.Addr) (Result, bool, error) {
	txts, err := d.lookupTXT("_prefixes._sworn." + domain)
	if err != nil {
		if isNotFound(err) {
			return Result{}, false, nil
		}
		return Result{}, false, ErrTemp
	}
	rec, ok := singleSwornRecord(txts)
	if !ok {
		return Result{}, false, nil
	}
	policy, err := sworn.ParsePolicyRecord(rec)
	if err != nil {
		return Result{}, false, nil // malformed policy: no confirmation (none)
	}
	best := netip.Prefix{}
	for _, p := range policy.Prefixes {
		if p.Contains(source) && (!best.IsValid() || p.Bits() > best.Bits()) {
			best = p
		}
	}
	if !best.IsValid() {
		return Result{}, false, nil
	}
	unit, err := source.Prefix(int(policy.Unit))
	if err != nil {
		return Result{}, false, nil
	}
	return Result{Operator: domain, Unit: unit, Mode: "dns", Testing: policy.Testing}, true, nil
}

// forwardConfirm implements FCrDNS (iprev): the PTR hostname must resolve back
// to the source address.
func (d *discovery) forwardConfirm(host string, source netip.Addr) (bool, error) {
	addrs, err := d.lookupNetIP(host)
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, ErrTemp
	}
	for _, a := range addrs {
		if a.Unmap() == source {
			return true, nil
		}
	}
	return false, nil
}

// singleSwornRecord returns the one v=SWORN1 record among a TXT RRset;
// zero or more than one is not a usable record.
func singleSwornRecord(txts []string) (string, bool) {
	var found string
	n := 0
	for _, t := range txts {
		if strings.HasPrefix(t, "v="+sworn.Version) {
			found = t
			n++
		}
	}
	if n != 1 {
		return "", false
	}
	return found, true
}

// --- budgeted resolver wrappers ---

func (d *discovery) spend() error {
	if d.budget <= 0 {
		return ErrTemp
	}
	d.budget--
	return nil
}

func (d *discovery) lookupTXT(name string) ([]string, error) {
	if err := d.spend(); err != nil {
		return nil, err
	}
	return d.r.LookupTXT(d.ctx, name)
}

func (d *discovery) lookupAddr(source netip.Addr) ([]string, error) {
	if err := d.spend(); err != nil {
		return nil, err
	}
	return d.r.LookupAddr(d.ctx, source.String())
}

func (d *discovery) lookupNetIP(host string) ([]netip.Addr, error) {
	if err := d.spend(); err != nil {
		return nil, err
	}
	return d.r.LookupNetIP(d.ctx, "ip6", host)
}

// isNotFound distinguishes NXDOMAIN / no-such-host (a definite negative that
// lets discovery continue) from temporary failures and budget exhaustion
// (which abort with temperror).
func isNotFound(err error) bool {
	if errors.Is(err, ErrTemp) {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}
