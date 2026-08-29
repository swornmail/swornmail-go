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
	"net/netip"
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
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "genrecord":
		os.Exit(cmdGenrecord(os.Args[2:]))
	case "sign":
		os.Exit(cmdSign(os.Args[2:]))
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

sender (set up a domain):
  sworn keygen [--selector <sel>] [--out <dir>] [--force]
      Generate an Ed25519 signing key. Writes <selector>.key with owner-only
      permissions and prints the public key.
  sworn genrecord --domain <d> --selector <sel> --key <file|b64> --prefix <p>
                  [--prefix <p>...] [--unit N] [--testing=false] [--rua mailto:<addr>] [--json]
      Emit the key and policy TXT records, in zone-file and DNS-panel form
      (--json for feeding a DNS provider's API).
      Validates every -01 constraint first; publishes t=y (observe-only)
      unless --testing=false.
  sworn sign --key <file> --selector <sel> --domain <d> --prefix <p>
             [--unit N] [--role mta|esp-tenant|forwarder] [--lifetime 1h]
      Sign a Mode-2 token — for proving a key works, and for demos.

receiver (check a sender):
  sworn verify <token-b64url> --ip <addr> [--key <b64>] [--policy <txt>] [--json]
      Verify a Mode-2 token against a connecting source address. Without
      --key/--policy, the policy is fetched and authorized before the key
      lookup. Supply both flags for a fully offline verification.
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

// resolver is the DNS surface shared by record, discovery, and verification.
// Keeping it as an interface lets tests prove that local failures and
// unauthorized policies issue no attacker-directed key query.
type resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupAddr(context.Context, string) ([]string, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// defaultResolver is the live resolver used by record/discover/verify.
var defaultResolver resolver = net.DefaultResolver

// leadingPositional pulls a leading non-flag argument (the token or domain)
// off the front so the remaining flags parse regardless of order — Go's flag
// package otherwise stops at the first positional.
func leadingPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}
