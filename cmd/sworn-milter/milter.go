package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	milter "github.com/emersion/go-milter"
	"github.com/swornmail/swornmail-go/sworn/discover"
)

// swornMilter runs Mode-1 discovery for each connection and stamps an
// Authentication-Results `sworn=` result. It is strictly fail-open: any error
// yields a `none`/`temperror` result and the message is always accepted —
// SwornMail never rejects mail by itself.
type swornMilter struct {
	milter.NoOpMilter
	authservID string
	resolver   discover.Resolver
	dnsTimeout time.Duration
	ineligible []netip.Prefix

	source     netip.Addr
	haveSource bool
	// stripIdx holds the per-name (1-based) positions of inbound
	// Authentication-Results fields that claim our authserv-id and must be
	// removed at the trust boundary (RFC 8601 §5). Both are per message and
	// reset in MailFrom.
	stripIdx []int
	arSeen   int
}

// newServer builds the milter server. main and the session tests share it, so
// the tests run against the protocol options Postfix actually negotiates.
func newServer(authservID string, r discover.Resolver, dnsTimeout time.Duration, ineligible []netip.Prefix) *milter.Server {
	return &milter.Server{
		NewMilter: func() milter.Milter {
			return &swornMilter{authservID: authservID, resolver: r, dnsTimeout: dnsTimeout, ineligible: ineligible}
		},
		Actions:  milter.OptAddHeader | milter.OptChangeHeader,
		Protocol: milter.OptNoBody, // skip body chunks; we act on headers + end of message
	}
}

func (s *swornMilter) Connect(host, family string, port uint16, addr net.IP, _ *milter.Modifier) (milter.Response, error) {
	if a, ok := netip.AddrFromSlice(addr); ok {
		s.source, s.haveSource = a.Unmap(), true
	}
	return milter.RespContinue, nil
}

// MailFrom starts a new message. Header positions are counted per message;
// a count left over from an aborted message would point the delete at the
// wrong header and let a forged result through.
func (s *swornMilter) MailFrom(string, *milter.Modifier) (milter.Response, error) {
	s.stripIdx, s.arSeen = nil, 0
	return milter.RespContinue, nil
}

func (s *swornMilter) Header(name, value string, _ *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "Authentication-Results") {
		s.arSeen++
		if claimsID(value, s.authservID) {
			s.stripIdx = append(s.stripIdx, s.arSeen)
		}
	}
	return milter.RespContinue, nil
}

func (s *swornMilter) Body(m *milter.Modifier) (milter.Response, error) {
	// Trust-boundary stripping: delete inbound AR fields claiming our
	// authserv-id, highest index first so earlier positions stay valid.
	for i := len(s.stripIdx) - 1; i >= 0; i-- {
		_ = m.ChangeHeader(s.stripIdx[i], "Authentication-Results", "")
	}
	// Prepend our result. Errors here must not fail the message (fail-open).
	_ = m.InsertHeader(0, "Authentication-Results", s.evaluate())
	// Return continue, not accept. The MTA treats them the same at end of
	// message, but go-milter throws the milter away after anything other than
	// continue, and the new one never sees Connect, so every later message on
	// the connection would be stamped none.
	return milter.RespContinue, nil
}

// evaluate runs discovery for the captured source and formats the AR value.
func (s *swornMilter) evaluate() string {
	if !s.haveSource {
		return discover.AuthResults(s.authservID, discover.Result{}, discover.ErrNone)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	defer cancel()
	res, err := discover.Discover(ctx, s.resolver, s.source, discover.Options{IneligiblePrefixes: s.ineligible})
	return discover.AuthResults(s.authservID, res, err)
}
