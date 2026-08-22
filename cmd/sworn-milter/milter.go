package main

import (
	"context"
	"errors"
	"fmt"
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

	source     netip.Addr
	haveSource bool
	// stripIdx holds the per-name (1-based) positions of inbound
	// Authentication-Results fields that claim our authserv-id and must be
	// removed at the trust boundary (RFC 8601 §5).
	stripIdx []int
	arSeen   int
}

func (s *swornMilter) Connect(host, family string, port uint16, addr net.IP, _ *milter.Modifier) (milter.Response, error) {
	if a, ok := netip.AddrFromSlice(addr); ok {
		s.source, s.haveSource = a.Unmap(), true
	}
	return milter.RespContinue, nil
}

func (s *swornMilter) Header(name, value string, _ *milter.Modifier) (milter.Response, error) {
	if strings.EqualFold(name, "Authentication-Results") {
		s.arSeen++
		if strings.EqualFold(authservIDOf(value), s.authservID) {
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
	return milter.RespAccept, nil
}

// evaluate runs discovery for the captured source and formats the AR value.
func (s *swornMilter) evaluate() string {
	if !s.haveSource {
		return s.authservID + "; sworn=none"
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dnsTimeout)
	defer cancel()
	res, err := discover.Discover(ctx, s.resolver, s.source, discover.Options{})
	return arValue(s.authservID, res, err)
}

// arValue formats an Authentication-Results value from a discovery outcome.
// A pvalue containing ':' or '/' (the unit prefix) is quoted per RFC 8601.
func arValue(authservID string, res discover.Result, err error) string {
	switch {
	case err == nil:
		return fmt.Sprintf("%s; sworn=pass policy.mode=%s policy.op=%s policy.unit=%q",
			authservID, res.Mode, res.Operator, res.Unit.String())
	case errors.Is(err, discover.ErrTemp):
		return authservID + "; sworn=temperror"
	default: // ErrNone: no attestation, ineligible source, or IPv4
		return authservID + "; sworn=none"
	}
}

// authservIDOf returns the authserv-id (the token before the first ';') of an
// Authentication-Results field value.
func authservIDOf(value string) string {
	id, _, _ := strings.Cut(value, ";")
	return strings.TrimSpace(id)
}
