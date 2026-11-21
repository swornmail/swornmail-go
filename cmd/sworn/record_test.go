package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// sworn record should query names with a trailing dot but still print them
// the way the operator publishes them.
func TestRecordLintQueriesFullyQualifiedNames(t *testing.T) {
	_, pub, _ := verificationFixture(t)
	r := &verificationResolver{txt: map[string][]string{
		"2026a._sworn.mailer.example.com":     {"v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub)},
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
	}}
	withVerificationResolver(t, r)

	key, policy := lintKey("2026a", "mailer.example.com"), lintPolicy("mailer.example.com")
	if key.Error != "" || policy.Error != "" {
		t.Fatalf("lint errors: key %q, policy %q", key.Error, policy.Error)
	}
	want := []string{"2026a._sworn.mailer.example.com.", "_prefixes._sworn.mailer.example.com."}
	if len(r.queries) != len(want) || r.queries[0] != want[0] || r.queries[1] != want[1] {
		t.Errorf("queried %v, want %v", r.queries, want)
	}
	if key.QName != "2026a._sworn.mailer.example.com" || policy.QName != "_prefixes._sworn.mailer.example.com" {
		t.Errorf("reported names %q, %q, want them as published", key.QName, policy.QName)
	}
}

// The domain and selector become DNS query names. Anything that is not a
// domain or a selector is a usage error, reported before a single query: a
// newline or a space must never reach the resolver, and a pasted URL should
// be called that, not looked up and reported as a missing record.
func TestRecordRejectsUnusableNamesBeforeDNS(t *testing.T) {
	for name, args := range map[string][]string{
		"domain with a space":      {"mailer.example.com evil.example"},
		"domain with a newline":    {"mailer.example.com\nevil.example"},
		"domain with a NUL":        {"mailer.example.com\x00"},
		"URL":                      {"https://mailer.example.com/"},
		"empty label":              {"mailer..example.com"},
		"trailing dot":             {"mailer.example.com."},
		"underscore label":         {"_prefixes._sworn.mailer.example.com"},
		"U-label":                  {"m\u00fcnchen.example"},
		"label over 63 octets":     {strings.Repeat("a", 64) + ".example.com"},
		"selector with a dot":      {"mailer.example.com", "--selector", "2026a.evil"},
		"selector with a newline":  {"mailer.example.com", "--selector", "2026a\n"},
		"selector leading hyphen":  {"mailer.example.com", "--selector=-2026a"},
		"selector over 63 octets":  {"mailer.example.com", "--selector", strings.Repeat("a", 64)},
		"selector with underscore": {"mailer.example.com", "--selector", "_dmarc"},
	} {
		r := &verificationResolver{}
		withVerificationResolver(t, r)
		if code := cmdRecord(args); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
		if len(r.queries) != 0 {
			t.Errorf("%s: issued DNS queries: %v", name, r.queries)
		}
	}
}

// Names are queried in lower case, as the verifier canonicalises them.
func TestRecordLowercasesNames(t *testing.T) {
	_, pub, _ := verificationFixture(t)
	r := &verificationResolver{txt: map[string][]string{
		"2026a._sworn.mailer.example.com":     {"v=SWORN1; k=ed25519; pk=" + base64.StdEncoding.EncodeToString(pub)},
		"_prefixes._sworn.mailer.example.com": {"v=SWORN1; p=2001:db8:f00::/48; u=64"},
	}}
	withVerificationResolver(t, r)

	if code := cmdRecord([]string{"Mailer.EXAMPLE.com", "--selector", "2026A"}); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	want := []string{"2026a._sworn.mailer.example.com.", "_prefixes._sworn.mailer.example.com."}
	if len(r.queries) != len(want) || r.queries[0] != want[0] || r.queries[1] != want[1] {
		t.Errorf("queried %v, want %v", r.queries, want)
	}
}
