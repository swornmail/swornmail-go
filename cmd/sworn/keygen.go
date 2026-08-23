package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	selector := fs.String("selector", defaultSelector(time.Now()), "selector label; the key is published at <selector>._sworn.<domain>")
	outDir := fs.String("out", ".", "directory to write the private key into")
	force := fs.Bool("force", false, "replace an existing key file (revokes every token signed with it)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !sworn.ValidSelector(*selector) {
		fmt.Fprintf(os.Stderr, "sworn: invalid --selector %q: %s\n", *selector, selectorRule)
		return 2
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}
	path := filepath.Join(*outDir, *selector+".key")
	if err := writePrivateKey(path, priv, *force); err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}

	fmt.Printf("selector    %s\n", *selector)
	fmt.Printf("private key %s (mode %#o — keep it secret, back it up)\n", path, keyFilePerm)
	fmt.Printf("public key  %s\n", encodePublicKey(pub))
	fmt.Printf("\nnext:\n  sworn genrecord --domain <your.domain> --selector %s --key %s --prefix <your IPv6 prefix>\n",
		*selector, path)
	return 0
}

// selectorRule states the -01 kid syntax in operator terms, for error output.
const selectorRule = "must be a single DNS label: 1-63 letters, digits or '-', not starting or ending with '-'"

// defaultSelector proposes a rotatable, date-ish label ("2026a"): DKIM
// practice, and it keeps the operator's first rotation obvious ("2026b").
func defaultSelector(now time.Time) string {
	return strconv.Itoa(now.UTC().Year()) + "a"
}
