package sworn

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Sign checks the validity window on the whole seconds it serialises. Checked
// on the time.Time values instead, a sub-second lifetime and a pre-1970
// IssuedAt both passed and produced a signed token no verifier accepts.
func TestSignValidatesSerialisedSeconds(t *testing.T) {
	cases := []struct {
		name     string
		issuedAt time.Time
		expires  time.Time
		want     error
	}{
		{"one second", iat, iat.Add(time.Second), nil},
		{"sub-second parts on both ends", iat.Add(900 * time.Millisecond), iat.Add(time.Second + 100*time.Millisecond), nil},
		{"exactly the cap", iat, iat.Add(MaxTokenLifetime), nil},
		// 24h and 0.6s as a duration, 86400 once both ends are truncated.
		{"cap plus a fraction that truncates away", iat.Add(200 * time.Millisecond), iat.Add(MaxTokenLifetime + 800*time.Millisecond), nil},
		{"issued at the epoch", time.Unix(0, 0), time.Unix(3600, 0), nil},

		{"500 ms lifetime truncates to exp == iat", iat, iat.Add(500 * time.Millisecond), ErrBadValidity},
		{"lifetime within one second", iat.Add(100 * time.Millisecond), iat.Add(900 * time.Millisecond), ErrBadValidity},
		{"exp == iat", iat, iat, ErrBadValidity},
		{"exp before iat", iat, iat.Add(-time.Second), ErrBadValidity},
		{"one second over the cap", iat, iat.Add(MaxTokenLifetime + time.Second), ErrLifetimeTooLong},
		// 0.1s over the cap as a duration, a whole second over once truncated.
		{"a fraction over the cap that truncates to a second", iat.Add(900 * time.Millisecond), iat.Add(MaxTokenLifetime + time.Second), ErrLifetimeTooLong},
		{"issued before 1970", time.Unix(-1, 0), time.Unix(3600, 0), ErrMalformed},
		{"zero IssuedAt", time.Time{}, iat, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := basePayload()
			p.IssuedAt, p.Expires = c.issuedAt, c.expires
			tok, err := Sign(p, testSelector, testPriv)
			if !errors.Is(err, c.want) {
				t.Fatalf("Sign = %v, want %v", err, c.want)
			}
			if c.want != nil {
				if tok != nil {
					t.Error("a token was returned alongside the error")
				}
				return
			}
			// Whatever Sign agrees to sign, the verifier accepts.
			at := time.Unix(c.issuedAt.Unix(), 0)
			if _, err := VerifySignatureOnly(tok, testPub, inside, at); err != nil {
				t.Errorf("Sign produced a token the verifier rejects: %v", err)
			}
		})
	}
}

// The seconds check must not move a single octet of a token that was already
// valid: sub-second precision never reached the wire.
func TestSignIgnoresSubSecondPrecision(t *testing.T) {
	whole := mustSign(t, basePayload())
	p := basePayload()
	p.IssuedAt, p.Expires = p.IssuedAt.Add(999*time.Millisecond), p.Expires.Add(time.Nanosecond)
	if got := mustSign(t, p); !bytes.Equal(got, whole) {
		t.Error("sub-second precision changed the token bytes")
	}
}
