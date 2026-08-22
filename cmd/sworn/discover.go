package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"

	"github.com/swornmail/swornmail-go/sworn/discover"
)

func cmdDiscover(args []string) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	ip := fs.String("ip", "", "connecting source IPv6 address (required)")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "usage: sworn discover --ip <addr> [--json]")
		return 2
	}
	src, err := netip.ParseAddr(*ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn: invalid --ip:", err)
		return 2
	}

	ctx, cancel := dnsContext()
	defer cancel()
	res, derr := discover.Discover(ctx, defaultResolver, src, discover.Options{})

	var out discoverOutput
	switch {
	case derr == nil:
		out = discoverOutput{Result: "pass", Mode: res.Mode, Operator: res.Operator, Unit: res.Unit.String()}
	case errors.Is(derr, discover.ErrTemp):
		out = discoverOutput{Result: "temperror"}
	default: // ErrNone
		out = discoverOutput{Result: "none"}
	}

	if *asJSON {
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	} else if out.Result == "pass" {
		fmt.Printf("sworn=pass mode=%s op=%s unit=%s\n", out.Mode, out.Operator, out.Unit)
	} else {
		fmt.Printf("sworn=%s\n", out.Result)
	}
	return resultExit(out.Result)
}

type discoverOutput struct {
	Result   string `json:"result"`
	Mode     string `json:"mode,omitempty"`
	Operator string `json:"operator,omitempty"`
	Unit     string `json:"unit,omitempty"`
}
