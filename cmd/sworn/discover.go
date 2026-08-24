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
	case derr == nil && res.Testing:
		// The operator publishes t=y: the outcome is reported as none with
		// the would-be result attached, and no reputation is staked.
		out = discoverOutput{
			Result: "none", Testing: true, WouldBe: "pass",
			Mode: res.Mode, Operator: res.Operator, Unit: res.Unit.String(),
		}
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
	} else {
		fmt.Println(textLine(out))
	}
	return resultExit(out.Result)
}

// textLine renders a discovery outcome for a terminal, mirroring the
// Authentication-Results vocabulary so what an operator sees while testing is
// what a receiver will report.
func textLine(out discoverOutput) string {
	switch {
	case out.Testing:
		return fmt.Sprintf("sworn=none testing=y wouldbe=%s mode=%s op=%s unit=%s (observe-only: no reputation staked)",
			out.WouldBe, out.Mode, out.Operator, out.Unit)
	case out.Result == "pass":
		return fmt.Sprintf("sworn=pass mode=%s op=%s unit=%s", out.Mode, out.Operator, out.Unit)
	default:
		return "sworn=" + out.Result
	}
}

type discoverOutput struct {
	Result   string `json:"result"`
	Testing  bool   `json:"testing,omitempty"`
	WouldBe  string `json:"wouldbe,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Operator string `json:"operator,omitempty"`
	Unit     string `json:"unit,omitempty"`
}
