package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

type verificationResolver struct {
	txt     map[string][]string
	queries []string
}

func (r *verificationResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.queries = append(r.queries, name)
	return r.txt[name], nil
}

func (r *verificationResolver) LookupAddr(context.Context, string) ([]string, error) {
	panic("unexpected PTR lookup during token verification")
}

func (r *verificationResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	panic("unexpected address lookup during token verification")
}

func verificationFixture(t *testing.T) (string, ed25519.PublicKey, int64) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	iat := time.Unix(1786291200, 0).UTC()
	token, err := sworn.Sign(sworn.Payload{
		Operator: "mailer.example.com",
		Prefix:   netip.MustParsePrefix("2001:db8:f00::/48"),
		Unit:     64,
		IssuedAt: iat,
		Expires:  iat.Add(time.Hour),
		Role:     "mta",
	}, "2026a", priv)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(token), pub, iat.Add(time.Minute).Unix()
}

func withVerificationResolver(t *testing.T, r resolver) {
	t.Helper()
	previous := defaultResolver
	defaultResolver = r
	t.Cleanup(func() { defaultResolver = previous })
}

func TestVerifyRunsLocalChecksBeforeDNS(t *testing.T) {
	token, _, _ := verificationFixture(t)
	r := &verificationResolver{}
	withVerificationResolver(t, r)

	code := cmdVerify([]string{token, "--ip", "2001:db8:bad::1", "--now", "1786291260"})
	if code != 1 {
		t.Fatalf("off-prefix result exit = %d, want fail", code)
	}
	if len(r.queries) != 0 {
		t.Fatalf("local failure issued DNS queries: %v", r.queries)
	}
}

func TestVerifyAuthorizesPolicyBeforeKeyLookup(t *testing.T) {
	token, pub, _ := verificationFixture(t)
	key := "v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub)
	r := &verificationResolver{txt: map[string][]string{
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
		"2026a._sworn.mailer.example.com":     {key},
	}}
	withVerificationResolver(t, r)

	code := cmdVerify([]string{token, "--ip", "2001:db8:f00:1234::1", "--now", "1786291260"})
	if code != 0 {
		t.Fatalf("valid verification exit = %d", code)
	}
	want := []string{"_prefixes._sworn.mailer.example.com", "2026a._sworn.mailer.example.com"}
	if len(r.queries) != len(want) || r.queries[0] != want[0] || r.queries[1] != want[1] {
		t.Fatalf("query order = %v, want %v", r.queries, want)
	}
}

func TestVerifyUnauthorizedPolicySuppressesKeyQuery(t *testing.T) {
	token, _, _ := verificationFixture(t)
	r := &verificationResolver{txt: map[string][]string{
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:bad::/48; u=64"},
	}}
	withVerificationResolver(t, r)

	code := cmdVerify([]string{token, "--ip", "2001:db8:f00:1234::1", "--now", "1786291260"})
	if code != 2 {
		t.Fatalf("unauthorized policy exit = %d, want permerror", code)
	}
	if len(r.queries) != 1 || r.queries[0] != "_prefixes._sworn.mailer.example.com" {
		t.Fatalf("unauthorized token queried beyond policy: %v", r.queries)
	}
}

func TestVerifyTestingPolicyNeverPasses(t *testing.T) {
	token, pub, _ := verificationFixture(t)
	r := &verificationResolver{txt: map[string][]string{
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64; t=y"},
		"2026a._sworn.mailer.example.com":     {"v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub)},
	}}
	withVerificationResolver(t, r)

	if code := cmdVerify([]string{token, "--ip", "2001:db8:f00:1234::1", "--now", "1786291260"}); code != 4 {
		t.Fatalf("testing verification exit = %d, want none", code)
	}
}

// An offline key must not buy a shortcut past authorization: --key skips only
// the key lookup, never the policy fetch that decides whether the signed
// prefix was authorized at all.
func TestVerifyOfflineKeyStillRequiresPolicy(t *testing.T) {
	token, pub, _ := verificationFixture(t)
	r := &verificationResolver{txt: map[string][]string{
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:bad::/48; u=64"},
	}}
	withVerificationResolver(t, r)

	key := base64.StdEncoding.EncodeToString(pub)
	code := cmdVerify([]string{token, "--ip", "2001:db8:f00:1234::1", "--key", key, "--now", "1786291260"})
	if code != 2 {
		t.Fatalf("offline key with unauthorized policy exit = %d, want permerror", code)
	}
	if len(r.queries) != 1 || r.queries[0] != "_prefixes._sworn.mailer.example.com" {
		t.Fatalf("policy query not issued exactly once: %v", r.queries)
	}
}
