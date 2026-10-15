package main

import (
	"encoding/base64"
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
