package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	milter "github.com/emersion/go-milter"
	"github.com/swornmail/swornmail-go/sworn/discover"
)

// swornMilter runs Mode-1 discovery once for each connection and stamps an
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
	// outcome is the connection's Authentication-Results value once discovery
	// has settled on one; empty until then. See evaluate.
	outcome string
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
	// An outcome belongs to the address it was discovered for, and so does
	// the address itself: a connection whose address cannot be read must not
	// inherit the previous one's.
	s.outcome = ""
	s.haveSource = false
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

// evaluate returns the Authentication-Results value for the connection. The
// outcome depends only on the connecting address, so discovery runs at the
// first message and every later message on the connection is stamped with
// what it found: a sender pushing a thousand messages down one connection
// would otherwise cost up to ten thousand lookups for one answer.
//
// A temperror is the exception and is never kept. It says discovery could
// not finish, not what the answer is, and a temporary DNS failure must not
// become a lasting verdict: pinned, one dropped query would stand in for the
// operator's attestation on every later message of a long-lived connection.
// The next message tries again.
func (s *swornMilter) evaluate() string {
	if s.outcome != "" {
		return s.outcome
	}
	res, err := s.discover()
	value := discover.AuthResults(s.authservID, res, err)
	if !errors.Is(err, discover.ErrTemp) {
		s.outcome = value
	}
	return value
}

// discover runs discovery for the captured source.
func (s *swornMilter) discover() (discover.Result, error) {
	if !s.haveSource {
		return discover.Result{}, discover.ErrNone
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	defer cancel()
	return discover.Discover(ctx, s.resolver, s.source, discover.Options{IneligiblePrefixes: s.ineligible})
}
