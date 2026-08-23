package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/swornmail/swornmail-go/sworn"
)

// recordTTL is the TTL printed in zone-file form: short enough that a key
// rotation or prefix change propagates within an hour.
const recordTTL = 3600

// txtStringMax is the DNS character-string limit (RFC 1035 §3.3.14). A longer
// value is legal in a TXT RR only when split into several character-strings,
// which -01 §Record Tag Parsing concatenates without separators.
const txtStringMax = 255

func printRecordSet(w io.Writer, rs recordSet) {
	fmt.Fprintf(w, "Publish these records for %s.\n\n", rs.Domain)

	fmt.Fprintln(w, "1. key record — the signing key receivers fetch")
	printRecord(w, rs.Key, rs.Domain)
	fmt.Fprintln(w, "2. policy record — the prefixes you stand behind")
	printRecord(w, rs.Policy, rs.Domain)

	if len(rs.Pointers) > 0 {
		fmt.Fprintln(w, "3. reverse-tree pointer (optional) — publish in your reverse zone if you")
		fmt.Fprintln(w, "   control it; otherwise discovery uses your MTA's forward-confirmed PTR")
		for _, p := range rs.Pointers {
			fmt.Fprintf(w, "     %s\n", zoneLine(p))
		}
		fmt.Fprintln(w)
	}

	if len(rs.Notes) > 0 {
		fmt.Fprintln(w, "notes:")
		for _, n := range rs.Notes {
			fmt.Fprintf(w, "  - %s\n", wrapNote(n))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "then check them from a machine that can resolve DNS:")
	fmt.Fprintf(w, "  sworn record %s --selector %s\n", rs.Domain, selectorOf(rs.Key.QName))
	fmt.Fprintln(w, "  sworn discover --ip <one of your MTA's IPv6 addresses>")
}

func printRecord(w io.Writer, rec dnsRecord, domain string) {
	fmt.Fprintln(w, "   zone file:")
	fmt.Fprintf(w, "     %s\n", zoneLine(rec))
	fmt.Fprintln(w, "   DNS panel:")
	fmt.Fprintln(w, "     type  TXT")
	fmt.Fprintf(w, "     name  %s\n", relativeName(rec.QName, domain))
	fmt.Fprintf(w, "     value %s\n\n", rec.Value)
}

// zoneLine renders a record in zone-file syntax, splitting an over-long value
// into character-strings so the zone loads.
func zoneLine(rec dnsRecord) string {
	chunks := txtChunks(rec.Value)
	for i, c := range chunks {
		chunks[i] = `"` + c + `"`
	}
	return fmt.Sprintf("%s. %d IN TXT %s", rec.QName, recordTTL, strings.Join(chunks, " "))
}

func txtChunks(v string) []string {
	var out []string
	for len(v) > txtStringMax {
		out = append(out, v[:txtStringMax])
		v = v[txtStringMax:]
	}
	return append(out, v)
}

// relativeName is the host field a DNS panel expects: the QName with the
// zone's own name removed.
func relativeName(qname, domain string) string {
	if rel, ok := strings.CutSuffix(qname, "."+domain); ok {
		return rel
	}
	return qname + "."
}

// selectorOf recovers the selector from a key-record QName for the closing
// check-it-yourself hint.
func selectorOf(qname string) string {
	sel, _, _ := strings.Cut(qname, ".")
	return sel
}

// wrapNote indents continuation lines under the note's bullet.
func wrapNote(n string) string {
	return strings.ReplaceAll(n, "\n", "\n    ")
}

// notes explains what the operator has just committed to, and the conditions
// that make a published record less effective than it looks.
func notes(o genOptions, shortestPrefix, policyLen int) []string {
	var out []string
	if o.Testing {
		out = append(out, "t=y is set, so this is observe-only: receivers report sworn=none policy.testing=y\n"+
			"and stake no reputation on you, for credit or blame. Watch your traffic, then\n"+
			"re-run with --testing=false to accept accountability.")
	} else {
		out = append(out, "t=y is NOT set: publishing this accepts accountability for every address in\n"+
			"the listed prefixes, including sub-allocations whose PTRs you do not control.")
	}
	if o.Unit < shortestPrefix {
		out = append(out, fmt.Sprintf("u=%d is coarser than your shortest attested prefix (/%d), so the reputation\n"+
			"unit spans addresses you have not attested; Mode-2 tokens require unit >= prefix length.",
			o.Unit, shortestPrefix))
	}
	if d := ruaDomain(o.RUA); d != "" && d != o.Domain && !strings.HasSuffix(d, "."+o.Domain) {
		out = append(out, fmt.Sprintf("the rua mailbox is outside %s, so receivers must confirm consent before\n"+
			"sending anything: %s has to publish\n"+
			"  %s._report.%s.%s. IN TXT \"v=%s\"",
			o.Domain, d, o.Domain, sworn.DNSLabel, d, sworn.Version))
	}
	if shortestPrefix < 48 {
		out = append(out, "Mode-1 discovery queries the reverse tree only at the enclosing /48 and /64,\n"+
			"so a prefix shorter than /48 is found through the forward-confirmed PTR path\n"+
			"or through Mode 2.")
	}
	if policyLen > txtStringMax {
		out = append(out, fmt.Sprintf("the policy value is %d octets; the zone form above is already split into\n"+
			"%d character-strings, but some DNS panels refuse values over %d.",
			policyLen, (policyLen+txtStringMax-1)/txtStringMax, txtStringMax))
	}
	return out
}

func ruaDomain(rua string) string {
	_, domain, _ := strings.Cut(rua, "@")
	return domain
}
