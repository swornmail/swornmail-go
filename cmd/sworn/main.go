// Command sworn is a command-line tool for the SwornMail protocol
// (draft-kafedzhy-swornmail-01): verify Mode-2 connection tokens, lint
// operator DNS records, and run Mode-1 (DNS-only) discovery.
//
// Exit codes mirror the Authentication-Results result:
//
//	0 pass · 1 fail · 2 permerror/usage · 3 temperror · 4 none
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

const dnsTimeout = 5 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "record":
		os.Exit(cmdRecord(os.Args[2:]))
	case "discover":
		os.Exit(cmdDiscover(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "sworn: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sworn — SwornMail protocol CLI

usage:
  sworn verify <token-b64url> --ip <addr> [--key <b64>] [--json]
      Verify a Mode-2 token against a connecting source address. Without
      --key, the operator key is fetched from DNS using the token's kid and
      operator domain.
  sworn record <domain> [--selector <sel>] [--json]
      Fetch and lint a domain's SwornMail records: the policy record, and
      (with --selector) a key record.
  sworn discover --ip <addr> [--json]
      Run Mode-1 DNS-only discovery for a source address.

exit: 0 pass · 1 fail · 2 permerror/usage · 3 temperror · 4 none
`)
}

// resultExit maps an Authentication-Results value to the CLI exit code.
func resultExit(result string) int {
	switch result {
	case "pass":
		return 0
	case "fail":
		return 1
	case "temperror":
		return 3
	case "none":
		return 4
	default: // permerror
		return 2
	}
}

func dnsContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), dnsTimeout)
}

// oneSwornRecord returns the single v=SWORN1 record from a TXT RRset.
func oneSwornRecord(txts []string) (string, bool) {
	var found string
	n := 0
	for _, t := range txts {
		if strings.HasPrefix(t, "v="+sworn.Version) {
			found, n = t, n+1
		}
	}
	return found, n == 1
}

// defaultResolver is the live resolver used by record/discover/verify.
var defaultResolver = net.DefaultResolver

// leadingPositional pulls a leading non-flag argument (the token or domain)
// off the front so the remaining flags parse regardless of order — Go's flag
// package otherwise stops at the first positional.
func leadingPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}
