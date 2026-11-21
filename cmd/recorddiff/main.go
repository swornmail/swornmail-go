// Command recorddiff is a differential harness for the record-parsing and
// prefix-matching surface, driving an external implementation against this
// one. The rspamd module implements those rules a third time in Lua, and a
// third implementation that quietly disagrees is exactly what the shared
// vectors exist to prevent.
//
// The external arm reads cases on stdin and writes verdicts on stdout:
//
//	policy\t<name>\t<hex record>\t<source address>  ->  <name>\t<verdict>
//	elig\t<name>\t<source address>                  ->  <name>\t<verdict>
//
// Policy verdicts are "err" (record rejected), "nomatch" (no enumerated
// prefix contains the source), or "match:<unit prefix>". Eligibility
// verdicts are "yes" or "no". Any disagreement exits non-zero.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/swornmail/swornmail-go/sworn"
)

type policyCase struct {
	name   string
	record string
	source string
}

func main() {
	arm := flag.String("arm", "", "command running the external implementation (required)")
	reportPath := flag.String("report", "", "write a markdown report to this path")
	flag.Parse()
	if *arm == "" {
		fmt.Fprintln(os.Stderr, "recorddiff: --arm <command> is required")
		os.Exit(2)
	}

	policies, eligibility := generate()
	// Verdicts come back keyed by name alone, so a name must be unique across
	// both kinds of case: two cases under one name would be compared as one,
	// and the other would pass unexamined.
	names := make([]string, 0, len(policies)+len(eligibility))
	for _, c := range policies {
		names = append(names, c.name)
	}
	for name := range eligibility {
		names = append(names, name)
	}
	if dups := repeated(names); len(dups) > 0 {
		fatal("corpus has duplicate case names: " + strings.Join(dups, ", "))
	}

	ourPolicy := make(map[string]string, len(policies))
	for _, c := range policies {
		ourPolicy[c.name] = evalPolicy(c.record, c.source)
	}
	ourElig := make(map[string]string, len(eligibility))
	for name, addr := range eligibility {
		ourElig[name] = evalEligibility(addr)
	}

	var in bytes.Buffer
	for _, c := range policies {
		fmt.Fprintf(&in, "policy\t%s\t%s\t%s\n", c.name, hex.EncodeToString([]byte(c.record)), c.source)
	}
	for name, addr := range eligibility {
		fmt.Fprintf(&in, "elig\t%s\t%s\n", name, addr)
	}

	fields := strings.Fields(*arm)
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Stdin = &in
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "recorddiff: arm failed:", err)
		os.Exit(1)
	}

	theirs := map[string]string{}
	var answered []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		name, verdict, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			theirs[name] = verdict
			answered = append(answered, name)
		}
	}
	// The arm's output is evidence, and a run that lost part of it has
	// compared nothing for the part it lost. A missing verdict is reported
	// per case below; a read error or a second verdict for one name is not
	// something the comparison can see, so it ends the run here.
	if err := sc.Err(); err != nil {
		fatal("reading the arm's output: " + err.Error())
	}
	if dups := repeated(answered); len(dups) > 0 {
		sort.Strings(dups)
		fatal("arm returned more than one verdict for: " + strings.Join(dups, ", "))
	}

	var divergences []string
	compare := func(kind string, ours map[string]string, describe func(string) string) {
		names := make([]string, 0, len(ours))
		for n := range ours {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			got, present := theirs[n]
			if !present {
				divergences = append(divergences, fmt.Sprintf("%s %s: arm returned no verdict (%s)", kind, n, describe(n)))
				continue
			}
			if got != ours[n] {
				divergences = append(divergences, fmt.Sprintf("%s %s: go=%q arm=%q (%s)", kind, n, ours[n], got, describe(n)))
			}
		}
	}
	byName := map[string]policyCase{}
	for _, c := range policies {
		byName[c.name] = c
	}
	compare("policy", ourPolicy, func(n string) string {
		return fmt.Sprintf("record=%q source=%s", byName[n].record, byName[n].source)
	})
	compare("elig", ourElig, func(n string) string { return eligibility[n] })

	total := len(ourPolicy) + len(ourElig)
	summary := fmt.Sprintf("%d cases (%d policy, %d eligibility), %d divergences",
		total, len(ourPolicy), len(ourElig), len(divergences))
	fmt.Println("recorddiff:", summary)
	for _, d := range divergences {
		fmt.Println("  DIVERGENCE", d)
	}
	if *reportPath != "" {
		// A report that was asked for and not written is a failed run: the
		// caller is about to read a stale file, or none, as this result.
		if err := writeReport(*reportPath, summary, divergences); err != nil {
			fatal("writing report: " + err.Error())
		}
	}
	if len(divergences) > 0 {
		os.Exit(1)
	}
}

// fatal ends a run that cannot vouch for its own comparison.
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "recorddiff:", msg)
	os.Exit(1)
}

// repeated returns each name that occurs more than once, in first-seen order.
func repeated(names []string) []string {
	count := make(map[string]int, len(names))
	var dups []string
	for _, n := range names {
		if count[n]++; count[n] == 2 {
			dups = append(dups, n)
		}
	}
	return dups
}

// evalPolicy is the reference answer: parse the record, then find the longest
// enumerated prefix containing the source and derive the reputation unit.
func evalPolicy(record, source string) string {
	policy, err := sworn.ParsePolicyRecord(record)
	if err != nil {
		return "err"
	}
	src, err := netip.ParseAddr(source)
	if err != nil {
		return "nomatch"
	}
	best := netip.Prefix{}
	for _, p := range policy.Prefixes {
		if p.Contains(src) && (!best.IsValid() || p.Bits() > best.Bits()) {
			best = p
		}
	}
	if !best.IsValid() {
		return "nomatch"
	}
	unit, err := src.Prefix(int(policy.Unit))
	if err != nil {
		return "nomatch"
	}
	return "match:" + unit.String()
}

func evalEligibility(source string) string {
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return "no"
	}
	if sworn.EligibleSource(addr) {
		return "yes"
	}
	return "no"
}

func writeReport(path, summary string, divergences []string) error {
	var b strings.Builder
	b.WriteString("# Record and prefix differential — Go vs external arm\n\n")
	b.WriteString(summary + "\n\n")
	if len(divergences) == 0 {
		b.WriteString("No divergences: every case produced an identical verdict.\n")
	} else {
		b.WriteString("## Divergences\n\n")
		for _, d := range divergences {
			b.WriteString("- " + d + "\n")
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
