package main

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	milter "github.com/emersion/go-milter"
	"github.com/swornmail/swornmail-go/sworn/discover"
)

// These tests talk to the real server over a socket using go-milter's client.
// Like Postfix, they keep one milter session per SMTP connection and send
// every message on that connection through it.

var attestedTXT = map[string][]string{
	rev64:                                 {"v=SWORN1; d=mailer.example.com"},
	"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
}

func startSession(t *testing.T, txt map[string][]string) *milter.ClientSession {
	t.Helper()
	return startSessionWith(t, fakeResolver{txt: txt})
}

func startSessionWith(t *testing.T, r discover.Resolver) *milter.ClientSession {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("mx.example", r, time.Second, nil)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client := milter.NewClientWithOptions("tcp", ln.Addr().String(), milter.ClientOptions{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		ActionMask:   milter.OptAddHeader | milter.OptChangeHeader,
	})
	s, err := client.Session()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Conn("client.example", milter.FamilyInet6, 25, rev64src); err != nil {
		t.Fatal(err)
	}
	return s
}

// sendHeaders opens a transaction and sends its header fields.
func sendHeaders(t *testing.T, s *milter.ClientSession, fields ...[2]string) {
	t.Helper()
	if _, err := s.Mail("<a@mailer.example.com>", nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range fields {
		if _, err := s.HeaderField(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.HeaderEnd(); err != nil {
		t.Fatal(err)
	}
}

// endMessage finishes the message and returns the milter's modifications. The
// milter never rejects, so the final action must let the message through.
func endMessage(t *testing.T, s *milter.ClientSession) []milter.ModifyAction {
	t.Helper()
	mods, act, err := s.End()
	if err != nil {
		t.Fatal(err)
	}
	if act.Code != milter.ActAccept && act.Code != milter.ActContinue {
		t.Fatalf("end of message action = %c, want accept or continue", act.Code)
	}
	return mods
}

func stamped(t *testing.T, mods []milter.ModifyAction) string {
	t.Helper()
	for _, m := range mods {
		if m.Code == milter.ActInsertHeader && m.HeaderName == "Authentication-Results" {
			return m.HeaderValue
		}
	}
	t.Fatalf("no Authentication-Results inserted: %+v", mods)
	return ""
}

// Senders like ESPs push many messages through one connection. They all come
// from the same attested address, so each one should pass, not just the first.
func TestEveryMessageInAConnectionIsEvaluated(t *testing.T) {
	s := startSession(t, attestedTXT)
	for i := 1; i <= 3; i++ {
		sendHeaders(t, s, [2]string{"Subject", "hello"})
		if got := stamped(t, endMessage(t, s)); !strings.Contains(got, "sworn=pass") {
			t.Errorf("message %d in the connection stamped %q, want sworn=pass", i, got)
		}
	}
}

// Header positions are per message. If the count from an aborted message
// carried over, we would delete a header that isn't there and the forged
// result in the next message would survive.
func TestAbortDoesNotShiftStripPositions(t *testing.T) {
	s := startSession(t, attestedTXT)
	sendHeaders(t, s,
		[2]string{"Authentication-Results", "other.example; spf=pass"},
		[2]string{"Authentication-Results", "other.example; dkim=pass"},
	)
	if err := s.Abort(); err != nil {
		t.Fatal(err)
	}

	sendHeaders(t, s, [2]string{"Authentication-Results", "mx.example; sworn=pass policy.op=victim.example"})
	var deleted []uint32
	for _, m := range endMessage(t, s) {
		if m.Code == milter.ActChangeHeader && m.HeaderValue == "" {
			deleted = append(deleted, m.HeaderIndex)
		}
	}
	if len(deleted) != 1 || deleted[0] != 1 {
		t.Errorf("deleted Authentication-Results positions %v, want [1]", deleted)
	}
}

// outageResolver is safe to share with the server's goroutines. It counts TXT
// lookups and answers the first failures of them as a resolver that could
// not get an answer does.
type outageResolver struct {
	fakeResolver
	failures atomic.Int32
	lookups  atomic.Int32
}

func (r *outageResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.lookups.Add(1)
	if r.failures.Add(-1) >= 0 {
		return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
	}
	return r.fakeResolver.LookupTXT(ctx, name)
}

// Over the wire, as Postfix drives it: discovery runs for the first message
// of a connection and the later ones reuse the outcome, each still stamped.
func TestConnectionIsDiscoveredOnce(t *testing.T) {
	r := &outageResolver{fakeResolver: fakeResolver{txt: attestedTXT}}
	s := startSessionWith(t, r)
	var perConnection int32
	for i := 1; i <= 4; i++ {
		sendHeaders(t, s, [2]string{"Subject", "hello"})
		if got := stamped(t, endMessage(t, s)); !strings.Contains(got, "sworn=pass") {
			t.Errorf("message %d stamped %q, want sworn=pass", i, got)
		}
		if i == 1 {
			perConnection = r.lookups.Load()
		}
	}
	if perConnection == 0 {
		t.Fatal("the first message did no discovery")
	}
	if got := r.lookups.Load(); got != perConnection {
		t.Errorf("%d TXT lookups over four messages, want the first message's %d", got, perConnection)
	}
}

// DNS-disruption attack, over the wire: the message that meets a temporary
// DNS failure is stamped temperror, and the next message on the same
// connection is evaluated afresh rather than inheriting it.
func TestTemperrorDoesNotOutliveTheOutage(t *testing.T) {
	r := &outageResolver{fakeResolver: fakeResolver{txt: attestedTXT}}
	r.failures.Store(1)
	s := startSessionWith(t, r)

	sendHeaders(t, s, [2]string{"Subject", "during"})
	if got, want := stamped(t, endMessage(t, s)), "mx.example; sworn=temperror"; got != want {
		t.Fatalf("message during the outage stamped %q, want %q", got, want)
	}
	for i := 2; i <= 3; i++ {
		sendHeaders(t, s, [2]string{"Subject", "after"})
		if got := stamped(t, endMessage(t, s)); !strings.Contains(got, "sworn=pass") {
			t.Errorf("message %d, after the outage, stamped %q, want sworn=pass", i, got)
		}
	}
}

// Reusing the outcome must not reuse the header positions: stripping stays
// per message, so a forged result in a later message is still removed.
func TestStrippingStaysPerMessageWhenTheOutcomeIsReused(t *testing.T) {
	s := startSession(t, attestedTXT)
	sendHeaders(t, s, [2]string{"Subject", "clean"})
	for _, m := range endMessage(t, s) {
		if m.Code == milter.ActChangeHeader {
			t.Errorf("the clean first message had a header changed: %+v", m)
		}
	}

	sendHeaders(t, s,
		[2]string{"Authentication-Results", "other.example; spf=pass"},
		[2]string{"Authentication-Results", "mx.example; sworn=pass policy.op=victim.example"},
	)
	mods := endMessage(t, s)
	var deleted []uint32
	for _, m := range mods {
		if m.Code == milter.ActChangeHeader && m.HeaderValue == "" {
			deleted = append(deleted, m.HeaderIndex)
		}
	}
	if len(deleted) != 1 || deleted[0] != 2 {
		t.Errorf("deleted Authentication-Results positions %v, want [2]", deleted)
	}
	if got := stamped(t, mods); !strings.Contains(got, "policy.op=mailer.example.com") {
		t.Errorf("second message stamped %q, want our own pass", got)
	}
}
