package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	ip := fs.String("ip", "", "connecting source IPv6 address (required)")
	keyB64 := fs.String("key", "", "operator public key, base64 (offline; skips key DNS)")
	policyTXT := fs.String("policy", "", "operator policy TXT content (offline; skips policy DNS)")
	nowUnix := fs.Int64("now", 0, "verify as of this Unix time (0 = wall clock)")
	asJSON := fs.Bool("json", false, "JSON output")
	tokenArg, rest := leadingPositional(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if tokenArg == "" && fs.NArg() == 1 {
		tokenArg = fs.Arg(0)
	}
	if tokenArg == "" || *ip == "" {
		fmt.Fprintln(os.Stderr, "usage: sworn verify <token-b64url> --ip <addr> [--key <b64>] [--policy <txt>] [--json]")
		return 2
	}
	token, err := decodeToken(tokenArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}
	src, err := netip.ParseAddr(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn: invalid --ip:", err)
		return 2
	}

	now := time.Now()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}
	prepared, perr := sworn.PrepareVerification(token, src, now)
	if perr != nil {
		return report(*asJSON, verifyOutput{Result: sworn.AuthResult(perr), Reason: sworn.Reason(perr)})
	}

	var policy sworn.PolicyRecord
	if *policyTXT != "" {
		policy, err = sworn.ParsePolicyRecord(*policyTXT)
		if err != nil {
			err = lookupError("permerror", "policy_record_invalid", "malformed offline policy record", err)
		}
	} else {
		policy, err = fetchPolicy(prepared.Operator())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sworn: policy lookup _prefixes._sworn.%s: %v\n", prepared.Operator(), err)
		return reportLookup(*asJSON, err)
	}
	authorized, aerr := prepared.Authorize(policy)
	if aerr != nil {
		return report(*asJSON, verifyOutput{Result: sworn.AuthResult(aerr), Reason: sworn.Reason(aerr)})
	}

	var pub ed25519.PublicKey
	if *keyB64 != "" {
		pub, err = decodeKey(*keyB64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sworn: invalid --key:", err)
			return 2
		}
	} else {
		pub, err = fetchKey(prepared.Selector(), prepared.Operator())
		if err != nil {
			fmt.Fprintf(os.Stderr, "sworn: key lookup %s._sworn.%s: %v\n", prepared.Selector(), prepared.Operator(), err)
			return reportLookup(*asJSON, err)
		}
	}

	res, verr := authorized.VerifySignature(pub)
	out := verifyOutput{Result: sworn.AuthResult(verr), Reason: sworn.Reason(verr)}
	// ErrTestingMode is the one error that still carries a usable Result: the
	// signature verified, so the operator and units are attributable, but the
	// outcome is none. Every other error identifies no accountable party and
	// must not name one.
	if verr == nil || errors.Is(verr, sworn.ErrTestingMode) {
		out.Operator, out.Selector = res.Operator, res.Selector
		out.Unit, out.Observed, out.Prefix = res.Unit.String(), res.ObservedUnit.String(), res.Prefix.String()
	}
	if errors.Is(verr, sworn.ErrTestingMode) {
		out.Testing, out.WouldBe = true, "pass"
	}
	return report(*asJSON, out)
}

type verifyOutput struct {
	Result   string `json:"result"`
	Reason   string `json:"reason"`
	Operator string `json:"operator,omitempty"`
	Unit     string `json:"unit,omitempty"`
	Observed string `json:"observed,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Selector string `json:"selector,omitempty"`
	Testing  bool   `json:"testing,omitempty"`
	WouldBe  string `json:"would_be,omitempty"`
}

func report(asJSON bool, o verifyOutput) int {
	if asJSON {
		b, _ := json.Marshal(o)
		fmt.Println(string(b))
	} else if o.Testing {
		fmt.Printf("sworn=none policy.testing=y policy.wouldbe=%s op=%s unit=%s observed=%s\n",
			o.WouldBe, o.Operator, o.Unit, o.Observed)
	} else if o.Result == "pass" {
		// observed= is the boundary to key reputation on; unit= is what the
		// operator asked for and is only usable with control evidence.
		fmt.Printf("sworn=pass op=%s unit=%s observed=%s\n", o.Operator, o.Unit, o.Observed)
	} else {
		fmt.Printf("sworn=%s reason=%s\n", o.Result, o.Reason)
	}
	return resultExit(o.Result)
}

func reportLookup(asJSON bool, err error) int {
	var lookup *recordLookupError
	if errors.As(err, &lookup) {
		return report(asJSON, verifyOutput{Result: lookup.result, Reason: lookup.reason})
	}
	return report(asJSON, verifyOutput{Result: "temperror", Reason: "dns_lookup_failed"})
}

// decodeToken accepts the wire encoding (base64url, no padding) and tolerates
// base64-standard for convenience.
func decodeToken(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("token is not valid base64url")
}

func decodeKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d-byte base64 Ed25519 key", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

type recordLookupError struct {
	result string
	reason string
	err    error
}

func (e *recordLookupError) Error() string { return e.err.Error() }
func (e *recordLookupError) Unwrap() error { return e.err }

func lookupError(result, reason, message string, err error) error {
	if err != nil {
		return &recordLookupError{result: result, reason: reason, err: fmt.Errorf("%s: %w", message, err)}
	}
	return &recordLookupError{result: result, reason: reason, err: errors.New(message)}
}

// fetchPolicy resolves the operator policy before any key lookup.
func fetchPolicy(operator string) (sworn.PolicyRecord, error) {
	txt, err := fetchSingleRecord("_prefixes._sworn."+operator, "policy")
	if err != nil {
		return sworn.PolicyRecord{}, err
	}
	policy, err := sworn.ParsePolicyRecord(txt)
	if err != nil {
		return sworn.PolicyRecord{}, lookupError("permerror", "policy_record_invalid", "malformed policy record", err)
	}
	return policy, nil
}

// fetchKey resolves and parses the operator key record only after policy
// authorization has succeeded.
func fetchKey(selector, operator string) (ed25519.PublicKey, error) {
	txt, err := fetchSingleRecord(selector+"._sworn."+operator, "key")
	if err != nil {
		return nil, err
	}
	parsed, err := sworn.ParseRecord(txt)
	if errors.Is(err, sworn.ErrRecordAlgorithm) {
		return nil, lookupError("none", "unsupported_algorithm", "unimplemented key algorithm", err)
	}
	if err != nil {
		return nil, lookupError("permerror", "key_record_invalid", "malformed key record", err)
	}
	return parsed.PublicKey, nil
}

func fetchSingleRecord(qname, kind string) (string, error) {
	ctx, cancel := dnsContext()
	defer cancel()
	txts, err := defaultResolver.LookupTXT(ctx, qname)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", lookupError("none", kind+"_not_found", "no "+kind+" record", err)
		}
		return "", lookupError("temperror", kind+"_lookup_failed", kind+" DNS lookup failed", err)
	}
	var record string
	count := 0
	for _, txt := range txts {
		if len(txt) >= len("v="+sworn.Version) && txt[:len("v="+sworn.Version)] == "v="+sworn.Version {
			record, count = txt, count+1
		}
	}
	switch count {
	case 0:
		return "", lookupError("none", kind+"_not_found", "no v=SWORN1 "+kind+" record", nil)
	case 1:
		return record, nil
	default:
		return "", lookupError("permerror", kind+"_record_ambiguous", "multiple v=SWORN1 "+kind+" records", nil)
	}
}
