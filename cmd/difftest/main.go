// Command difftest is the SwornMail gate-B differential: it generates an
// adversarial token corpus, evaluates each case with the Go reference
// pipes the same corpus to the Rust verifier via its difftest binary, and
// reports any DISAGREEMENT. The load-bearing invariant is agreement on the
// Authentication-Results value, plus operator/unit/observed-unit agreement on
// a pass; the draft calls reason-code order advisory, so a differing reason
// among rejections is tallied, not failed.
//
// Cases carrying a policy record exercise the complete path — local checks,
// policy authorization, then the signature — so the authorization contract is
// differentially tested rather than only unit-tested on each side. Cases
// without one exercise the signature-only primitive the frozen token vectors
// use.
//
// Usage: difftest --rust <path-to-rust-difftest-binary> [--fuzz N] [--report FILE]
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/swornmail/swornmail-go/sworn"
	cose "github.com/veraison/go-cose"
)

const selector = "2026a"

// dumpFuzz, when set via --dump, prints one fuzz case's bytes for triage.
var dumpFuzz string

var (
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	detEnc cbor.EncMode
	t0     = int64(1786291200)
	expU   = t0 + 3600
)

// --- CBOR/COSE builders (mirror cmd/genvectors; kept local to avoid an
// exported test-only package). ---

type kv struct{ k, v any }

func buildMap(entries ...kv) []byte {
	body := []byte{0xa0 | byte(len(entries))}
	for _, e := range entries {
		kb, _ := detEnc.Marshal(e.k)
		vb, _ := detEnc.Marshal(e.v)
		body = append(append(body, kb...), vb...)
	}
	return body
}

func prefixWire(s string, bits int) []byte {
	a := netip.MustParseAddr(s).As16()
	return append(a[:], byte(bits))
}

func signWith(payload []byte, prot cose.ProtectedHeader, unprot cose.UnprotectedHeader) []byte {
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		panic(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	if prot == nil {
		prot = cose.ProtectedHeader{}
	}
	if _, ok := prot[cose.HeaderLabelAlgorithm]; !ok {
		prot[cose.HeaderLabelAlgorithm] = cose.AlgorithmEdDSA
	}
	msg.Headers.Protected = prot
	if unprot != nil {
		msg.Headers.Unprotected = unprot
	}
	if err := msg.Sign(nil, nil, signer); err != nil {
		// nil rand => deterministic Ed25519 (RFC 8032).
		panic(err)
	}
	b, _ := msg.MarshalCBOR()
	return b
}

func goodProt() cose.ProtectedHeader {
	return cose.ProtectedHeader{
		cose.HeaderLabelContentType: sworn.ContentType,
		cose.HeaderLabelKeyID:       []byte(selector),
	}
}

func signRaw(entries ...kv) []byte { return signWith(buildMap(entries...), goodProt(), nil) }

func goodEntries(prefix string, bits int, unit uint64, role string) []kv {
	return []kv{
		{1, "mailer.example.com"}, {2, prefixWire(prefix, bits)}, {3, unit},
		{4, uint64(t0)}, {5, uint64(expU)}, {6, role},
	}
}

type caseT struct {
	name   string
	token  []byte
	source string
	now    int64
	// policy is the _prefixes._sworn TXT to authorize against. Empty means
	// signature-only evaluation, matching the frozen token vectors.
	policy string
}

func main() {
	rustBin := flag.String("rust", "", "path to the rust difftest binary (required)")
	fuzzN := flag.Int("fuzz", 3000, "number of byte-level fuzz cases")
	reportPath := flag.String("report", "", "write a markdown report to this path")
	dump := flag.String("dump", "", "print the bytes of this fuzz case to stderr, for triage")
	flag.Parse()
	dumpFuzz = *dump
	if *rustBin == "" {
		fmt.Fprintln(os.Stderr, "difftest: --rust <binary> is required")
		os.Exit(2)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)
	detEnc, _ = cbor.CoreDetEncOptions().EncMode()

	cases := generate(*fuzzN)

	// Go evaluation.
	type result struct{ authres, reason, op, unit, observed string }
	goRes := make(map[string]result, len(cases))
	for _, c := range cases {
		src, err := netip.ParseAddr(c.source)
		if err != nil {
			goRes[c.name] = result{authres: "permerror", reason: "bad_source"}
			continue
		}
		now := time.Unix(c.now, 0).UTC()
		var res sworn.Result
		var verr error
		if c.policy == "" {
			res, verr = sworn.VerifySignatureOnly(c.token, pub, src, now)
		} else {
			policy, perr := sworn.ParsePolicyRecord(c.policy)
			if perr != nil {
				goRes[c.name] = result{authres: "permerror", reason: "policy_record_invalid"}
				continue
			}
			res, verr = sworn.Verify(c.token, pub, policy, src, now)
		}
		r := result{authres: sworn.AuthResult(verr), reason: sworn.Reason(verr)}
		// A testing outcome still names the operator (it is a real
		// verification), which is why it carries the properties too.
		if verr == nil || errors.Is(verr, sworn.ErrTestingMode) {
			r.op, r.unit, r.observed = res.Operator, res.Unit.String(), res.ObservedUnit.String()
		}
		goRes[c.name] = r
	}

	// Rust evaluation via the difftest binary.
	var in bytes.Buffer
	fmt.Fprintf(&in, "%s\n", hex.EncodeToString(pub))
	for _, c := range cases {
		fmt.Fprintf(&in, "%s\t%s\t%s\t%d\t%s\n",
			c.name, hex.EncodeToString(c.token), c.source, c.now, c.policy)
	}
	cmd := exec.Command(*rustBin)
	cmd.Stdin = &in
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "difftest: rust binary failed:", err)
		os.Exit(1)
	}
	rustRes := make(map[string]result, len(cases))
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), "\t", 6)
		if len(f) < 3 {
			continue
		}
		r := result{authres: f[1], reason: f[2]}
		if len(f) >= 6 {
			r.op, r.unit, r.observed = f[3], f[4], f[5]
		}
		rustRes[f[0]] = r
	}

	// Compare.
	var divergences, advisory []string
	reasonExact := 0
	for _, c := range cases {
		g, r := goRes[c.name], rustRes[c.name]
		gPass, rPass := g.authres == "pass", r.authres == "pass"
		switch {
		case g.authres != r.authres:
			divergences = append(divergences, fmt.Sprintf(
				"AUTHRESULT     %-32s go=%s rust=%s", c.name, g.authres, r.authres))
		case g.op != r.op || g.unit != r.unit || g.observed != r.observed:
			divergences = append(divergences, fmt.Sprintf(
				"PROPERTIES     %-32s go=(%s,%s,%s) rust=(%s,%s,%s)",
				c.name, g.op, g.unit, g.observed, r.op, r.unit, r.observed))
		}
		if g.reason == r.reason {
			reasonExact++
		} else if !gPass && !rPass {
			advisory = append(advisory, fmt.Sprintf("%s: go=%s rust=%s", c.name, g.reason, r.reason))
		}
	}

	authorized := 0
	for _, c := range cases {
		if c.policy != "" {
			authorized++
		}
	}
	summary := fmt.Sprintf(
		"cases=%d (%d policy-authorized)  authresult+property divergences=%d  exact-reason-agreement=%d/%d (%.1f%%)",
		len(cases), authorized, len(divergences), reasonExact, len(cases),
		100*float64(reasonExact)/float64(len(cases)))
	fmt.Println(summary)
	for _, d := range divergences {
		fmt.Println("  ", d)
	}

	if *reportPath != "" {
		writeReport(*reportPath, summary, cases, divergences, advisory, reasonExact)
	}
	if len(divergences) > 0 {
		os.Exit(1)
	}
}

func writeReport(path, summary string, cases []caseT, divergences, advisory []string, reasonExact int) {
	var b strings.Builder
	b.WriteString("# Gate B — Go/Rust differential report\n\n")
	b.WriteString("Mechanical differential: every case verified by both `swornmail-go` and the independent Rust verifier. Cases carrying a policy record run the complete path (local checks, policy authorization, signature); the rest run the signature-only primitive the frozen token vectors use. A disagreement on the Authentication-Results value, or on operator/unit/observed-unit, is a finding. Reason-string differences among rejections are advisory (draft leaves reason-code order unspecified) and are tallied, not failed.\n\n")
	fmt.Fprintf(&b, "**Result:** %s\n\n", summary)
	if len(divergences) == 0 {
		b.WriteString("**No accept/reject or result divergences.** The two implementations agree on the pass/reject decision and on operator/unit for every case in the corpus.\n\n")
	} else {
		b.WriteString("## Divergences\n\n")
		for _, d := range divergences {
			fmt.Fprintf(&b, "- `%s`\n", d)
		}
		b.WriteString("\n")
	}
	if len(advisory) > 0 {
		b.WriteString("## Advisory reason differences (both reject; not findings)\n\n")
		b.WriteString("The draft calls reason-code order advisory; these cases reject in both implementations but report a different reason token — exactly the ambiguity `expect_any` encodes in the vectors.\n\n")
		for _, a := range advisory {
			fmt.Fprintf(&b, "- `%s`\n", a)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "Corpus: %d cases (valid parameter space, structural/header adversarial, unvectored judgment calls, and deterministic byte-fuzz). Exact-reason agreement %d/%d.\n", len(cases), reasonExact, len(cases))
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}
