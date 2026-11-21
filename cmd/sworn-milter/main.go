// Command sworn-milter is a Postfix/Sendmail milter that runs SwornMail
// Mode-1 (DNS-only) discovery on each connection and stamps an
// Authentication-Results `sworn=` result on the message, removing inbound
// results that claim its authserv-id. It is strictly fail-open and never
// rejects mail.
//
// Postfix setup (main.cf, Postfix 3.0 or later):
//
//	smtpd_milters = { inet:127.0.0.1:10025, default_action=accept }
//
// then run sworn-milter, which listens there by default. Content filters
// such as amavis often take port 10025 too; if it's in use, pick another with
// --listen and use the same port in smtpd_milters. Keep
// default_action=accept inside the braces: it makes this milter fail open
// without touching the others, where the global milter_default_action would
// make every milter fail open. See https://swornmail.dev/milter/.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	milter "github.com/emersion/go-milter"
	"github.com/swornmail/swornmail-go/sworn"
)

func main() {
	listen := flag.String("listen", "tcp:127.0.0.1:10025", "listen address: tcp:host:port or unix:/path")
	authservID := flag.String("authserv-id", defaultAuthservID(), "authserv-id to stamp and to strip inbound results for")
	dnsTimeout := flag.Duration("dns-timeout", 5*time.Second, "per-connection DNS discovery timeout")
	var ineligible prefixFlag
	flag.Var(&ineligible, "ineligible-prefix", "IPv6 prefixes to treat as ineligible sources, comma-separated or repeated: your NAT64/SIIT translation prefixes, and any of your own relays")
	flag.Parse()

	network, address, ok := strings.Cut(*listen, ":")
	if !ok || (network != "tcp" && network != "unix") {
		fmt.Fprintln(os.Stderr, "sworn-milter: --listen must be tcp:host:port or unix:/path")
		os.Exit(2)
	}
	// Checked before anything listens: with an unusable id the milter would
	// run, look healthy, and protect nothing.
	if !validAuthservID(*authservID) {
		fmt.Fprintf(os.Stderr, "sworn-milter: --authserv-id %q is not usable: %s\n", *authservID, authservIDRule)
		os.Exit(2)
	}
	ln, release, err := listenOn(network, address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn-milter: listen:", err)
		os.Exit(1)
	}

	// The pure-Go resolver, not whatever the platform's libc offers. Discovery
	// turns on telling NXDOMAIN (no record: none) from SERVFAIL or a timeout
	// (temperror), and a temporary failure must never read as "no
	// attestation". Through getaddrinfo and friends that distinction depends
	// on the libc, its NSS modules and any caching daemon behind them, which
	// can hand back a failed lookup as "not found". PreferGo keeps the
	// classification the same on every host this runs on.
	resolver := &net.Resolver{PreferGo: true}
	server := newServer(*authservID, resolver, *dnsTimeout, []netip.Prefix(ineligible))

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		// The socket goes first: Serve returns as soon as the server
		// closes, and main may exit before anything after Close runs.
		release()
		_ = server.Close()
	}()

	fmt.Fprintf(os.Stderr, "sworn-milter: listening on %s (authserv-id %s)\n", *listen, *authservID)
	if err := server.Serve(ln); err != nil && err != milter.ErrServerClosed {
		release()
		fmt.Fprintln(os.Stderr, "sworn-milter: serve:", err)
		os.Exit(1)
	}
}

// prefixFlag collects --ineligible-prefix values. A bad prefix stops the
// milter at startup: running without the list it was given would let
// translated traffic be attributed as if it came from one sender.
type prefixFlag []netip.Prefix

func (p *prefixFlag) String() string { return fmt.Sprint([]netip.Prefix(*p)) }

func (p *prefixFlag) Set(v string) error {
	ps, err := sworn.ParseIneligiblePrefixes(v)
	if err != nil {
		return err
	}
	*p = append(*p, ps...)
	return nil
}

func defaultAuthservID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sworn"
}
