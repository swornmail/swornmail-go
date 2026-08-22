package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/swornmail/swornmail-go/sworn"
)

func cmdRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	selector := fs.String("selector", "", "also fetch and lint this key record's selector")
	asJSON := fs.Bool("json", false, "JSON output")
	domainArg, rest := leadingPositional(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if domainArg == "" && fs.NArg() == 1 {
		domainArg = fs.Arg(0)
	}
	if domainArg == "" {
		fmt.Fprintln(os.Stderr, "usage: sworn record <domain> [--selector <sel>] [--json]")
		return 2
	}
	domain := domainArg
	out := recordOutput{Domain: domain}

	if *selector != "" {
		out.Key = lintKey(*selector, domain)
	}
	out.Policy = lintPolicy(domain)

	if *asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		printRecordText(out)
	}
	if (out.Key != nil && out.Key.Error != "") || (out.Policy != nil && out.Policy.Error != "") {
		return 2
	}
	return 0
}

type recordOutput struct {
	Domain string      `json:"domain"`
	Key    *keyLint    `json:"key_record,omitempty"`
	Policy *policyLint `json:"policy_record,omitempty"`
}

type keyLint struct {
	QName     string `json:"qname"`
	Algorithm string `json:"algorithm,omitempty"`
	PublicKey string `json:"public_key_b64,omitempty"`
	Error     string `json:"error,omitempty"`
}

type policyLint struct {
	QName    string   `json:"qname"`
	Prefixes []string `json:"prefixes,omitempty"`
	Unit     uint8    `json:"unit,omitempty"`
	Testing  bool     `json:"testing,omitempty"`
	RUA      string   `json:"rua,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func lintKey(selector, domain string) *keyLint {
	qname := selector + "._sworn." + domain
	out := &keyLint{QName: qname}
	ctx, cancel := dnsContext()
	defer cancel()
	txts, err := defaultResolver.LookupTXT(ctx, qname)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	rec, ok := oneSwornRecord(txts)
	if !ok {
		out.Error = "no single v=SWORN1 key record"
		return out
	}
	parsed, err := sworn.ParseRecord(rec)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Algorithm = parsed.Algorithm
	out.PublicKey = fmt.Sprintf("%x", []byte(parsed.PublicKey))
	return out
}

func lintPolicy(domain string) *policyLint {
	qname := "_prefixes._sworn." + domain
	out := &policyLint{QName: qname}
	ctx, cancel := dnsContext()
	defer cancel()
	txts, err := defaultResolver.LookupTXT(ctx, qname)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	rec, ok := oneSwornRecord(txts)
	if !ok {
		out.Error = "no single v=SWORN1 policy record"
		return out
	}
	parsed, err := sworn.ParsePolicyRecord(rec)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, p := range parsed.Prefixes {
		out.Prefixes = append(out.Prefixes, p.String())
	}
	out.Unit, out.Testing, out.RUA = parsed.Unit, parsed.Testing, parsed.RUA
	return out
}

func printRecordText(out recordOutput) {
	if out.Key != nil {
		if out.Key.Error != "" {
			fmt.Printf("key    %s: ERROR %s\n", out.Key.QName, out.Key.Error)
		} else {
			fmt.Printf("key    %s: ok k=%s\n", out.Key.QName, out.Key.Algorithm)
		}
	}
	if out.Policy != nil {
		if out.Policy.Error != "" {
			fmt.Printf("policy %s: ERROR %s\n", out.Policy.QName, out.Policy.Error)
		} else {
			fmt.Printf("policy %s: ok prefixes=%v unit=%d testing=%t\n",
				out.Policy.QName, out.Policy.Prefixes, out.Policy.Unit, out.Policy.Testing)
		}
	}
}
