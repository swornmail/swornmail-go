package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
	"github.com/swornmail/swornmail-go/sworn/discover"
)

func TestUnitForDefaults(t *testing.T) {
	p48 := netip.MustParsePrefix("2001:db8:f00::/48")
	for name, tc := range map[string]struct {
		unit int
		role string
		want uint8
	}{
		"explicit wins":      {56, "mta", 56},
		"mta default":        {0, "mta", 64},
		"forwarder default":  {0, "forwarder", 64},
		"esp-tenant default": {0, "esp-tenant", 48},
	} {
		if got := unitFor(tc.unit, tc.role, p48); got != tc.want {
			t.Errorf("%s: unitFor = %d, want %d", name, got, tc.want)
		}
	}
}

// The signing path must produce a token the verifier accepts using only the
// public key published in the generated key record.
func TestSignedTokenVerifiesAgainstGeneratedRecord(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "2026a.key")
	if err := writePrivateKey(keyPath, priv, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := buildRecords(baseOptions(pub))
	if err != nil {
		t.Fatal(err)
	}
	published, err := sworn.ParseRecord(rs.Key.Value)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	prefix := netip.MustParsePrefix("2001:db8:f00::/48")
	token, err := sworn.Sign(sworn.Payload{
		Operator: "mailer.example.com",
		Prefix:   prefix,
		Unit:     unitFor(0, "mta", prefix),
		IssuedAt: now,
		Expires:  now.Add(recommendedLifetime),
		Role:     "mta",
	}, "2026a", loaded)
	if err != nil {
		t.Fatal(err)
	}
	res, err := sworn.Verify(token, published.PublicKey, netip.MustParseAddr("2001:db8:f00:1234::25"), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("token from sign does not verify: %v", err)
	}
	if res.Operator != "mailer.example.com" || res.Unit.String() != "2001:db8:f00:1234::/64" || res.Selector != "2026a" {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestSignRejectsOverlongLifetime(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	_, err = sworn.Sign(sworn.Payload{
		Operator: "mailer.example.com",
		Prefix:   netip.MustParsePrefix("2001:db8:f00::/48"),
		Unit:     64,
		IssuedAt: now,
		Expires:  now.Add(sworn.MaxTokenLifetime + time.Second),
		Role:     "mta",
	}, "2026a", priv)
	if err == nil {
		t.Error("lifetime beyond the 24h cap was signed")
	}
}

// stubResolver serves exactly the records genrecord printed, so discovery is
// exercised end to end without a network.
type stubResolver struct {
	txt map[string][]string
	ptr map[string][]string
	ip  map[string][]netip.Addr
}

func (s *stubResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return answer(s.txt, name)
}

func (s *stubResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return answer(s.ptr, addr)
}

func (s *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return answer(s.ip, host)
}

func answer[T any](m map[string][]T, key string) ([]T, error) {
	v, ok := m[key]
	if !ok {
		return nil, &net.DNSError{Err: "nxdomain", IsNotFound: true}
	}
	return v, nil
}

// The deploy flow the outreach ask describes: generate records, publish them,
// and Mode-1 discovery finds the operator — with or without a reverse-zone
// pointer.
func TestGeneratedRecordsSatisfyDiscovery(t *testing.T) {
	pub := testKey(t)
	rs, err := buildRecords(baseOptions(pub))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Pointers) != 1 {
		t.Fatalf("expected one pointer record, got %d", len(rs.Pointers))
	}
	source := netip.MustParseAddr("2001:db8:f00:1234::25")
	policy := map[string][]string{rs.Policy.QName: {rs.Policy.Value}}

	t.Run("reverse-tree pointer", func(t *testing.T) {
		r := &stubResolver{txt: map[string][]string{
			rs.Pointers[0].QName: {rs.Pointers[0].Value},
			rs.Policy.QName:      {rs.Policy.Value},
		}}
		assertDiscovers(t, r, source)
	})

	// Two records only: the operator's MTA already has a forward-confirmed
	// PTR under the operator domain.
	t.Run("forward-confirmed PTR", func(t *testing.T) {
		r := &stubResolver{
			txt: policy,
			ptr: map[string][]string{source.String(): {"mx1.mailer.example.com."}},
			ip:  map[string][]netip.Addr{"mx1.mailer.example.com": {source}},
		}
		assertDiscovers(t, r, source)
	})
}

func assertDiscovers(t *testing.T, r discover.Resolver, source netip.Addr) {
	t.Helper()
	res, err := discover.Discover(context.Background(), r, source, discover.Options{})
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if res.Operator != "mailer.example.com" {
		t.Errorf("operator = %q", res.Operator)
	}
	if res.Unit.String() != "2001:db8:f00:1234::/64" {
		t.Errorf("unit = %s", res.Unit)
	}
}
