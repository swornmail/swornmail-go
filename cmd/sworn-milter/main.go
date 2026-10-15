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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	milter "github.com/emersion/go-milter"
)

func main() {
	listen := flag.String("listen", "tcp:127.0.0.1:10025", "listen address: tcp:host:port or unix:/path")
	authservID := flag.String("authserv-id", defaultAuthservID(), "authserv-id to stamp and to strip inbound results for")
	dnsTimeout := flag.Duration("dns-timeout", 5*time.Second, "per-connection DNS discovery timeout")
	flag.Parse()

	network, address, ok := strings.Cut(*listen, ":")
	if !ok || (network != "tcp" && network != "unix") {
		fmt.Fprintln(os.Stderr, "sworn-milter: --listen must be tcp:host:port or unix:/path")
		os.Exit(2)
	}
	if network == "unix" {
		_ = os.Remove(address) // clear a stale socket
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn-milter: listen:", err)
		os.Exit(1)
	}

	server := newServer(*authservID, net.DefaultResolver, *dnsTimeout)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		_ = server.Close()
		if network == "unix" {
			_ = os.Remove(address)
		}
	}()

	fmt.Fprintf(os.Stderr, "sworn-milter: listening on %s (authserv-id %s)\n", *listen, *authservID)
	if err := server.Serve(ln); err != nil && err != milter.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "sworn-milter: serve:", err)
		os.Exit(1)
	}
}

func defaultAuthservID() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sworn"
}
