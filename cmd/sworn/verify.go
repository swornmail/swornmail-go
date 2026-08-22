package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	ip := fs.String("ip", "", "connecting source IPv6 address (required)")
	keyB64 := fs.String("key", "", "operator public key, base64 (offline; skips DNS)")
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
		fmt.Fprintln(os.Stderr, "usage: sworn verify <token-b64url> --ip <addr> [--key <b64>] [--json]")
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

	var pub ed25519.PublicKey
	if *keyB64 != "" {
		pub, err = decodeKey(*keyB64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sworn: invalid --key:", err)
			return 2
		}
	} else {
		// Validate the token's kid/operator BEFORE any DNS query, then fetch.
		selector, operator, perr := sworn.ParseUnverified(token)
		if perr != nil {
			return report(*asJSON, verifyOutput{Result: sworn.AuthResult(perr), Reason: sworn.Reason(perr)})
		}
		pub, err = fetchKey(selector, operator)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sworn: key lookup %s._sworn.%s: %v\n", selector, operator, err)
			return report(*asJSON, verifyOutput{Result: "temperror", Reason: "key_lookup_failed"})
		}
	}

	now := time.Now()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}
	res, verr := sworn.Verify(token, pub, src, now)
	out := verifyOutput{Result: sworn.AuthResult(verr), Reason: sworn.Reason(verr)}
	if verr == nil {
		out.Operator, out.Unit, out.Selector = res.Operator, res.Unit.String(), res.Selector
	}
	return report(*asJSON, out)
}

type verifyOutput struct {
	Result   string `json:"result"`
	Reason   string `json:"reason"`
	Operator string `json:"operator,omitempty"`
	Unit     string `json:"unit,omitempty"`
	Selector string `json:"selector,omitempty"`
}

func report(asJSON bool, o verifyOutput) int {
	if asJSON {
		b, _ := json.Marshal(o)
		fmt.Println(string(b))
	} else if o.Result == "pass" {
		fmt.Printf("sworn=pass op=%s unit=%s\n", o.Operator, o.Unit)
	} else {
		fmt.Printf("sworn=%s reason=%s\n", o.Result, o.Reason)
	}
	return resultExit(o.Result)
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

// fetchKey resolves and parses the operator key record at
// <selector>._sworn.<operator>.
func fetchKey(selector, operator string) (ed25519.PublicKey, error) {
	ctx, cancel := dnsContext()
	defer cancel()
	txts, err := defaultResolver.LookupTXT(ctx, selector+"._sworn."+operator)
	if err != nil {
		return nil, err
	}
	rec, ok := oneSwornRecord(txts)
	if !ok {
		return nil, fmt.Errorf("no single v=SWORN1 key record")
	}
	parsed, err := sworn.ParseRecord(rec)
	if err != nil {
		return nil, err
	}
	return parsed.PublicKey, nil
}
