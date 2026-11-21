package sworn

import (
	"errors"
	"testing"
)

// An unimplemented k= must read as "no usable record" (sworn=none) wherever
// it stands in the record. Validating pk as an Ed25519 key before k had been
// seen made the verdict depend on tag order: the same future-algorithm record
// was none with k first and a malformed record (permerror) with pk first, so
// an operator publishing a new algorithm's selector was penalized by this
// verifier and not by the Rust one.
func TestUnknownAlgorithmWinsWhateverTheTagOrder(t *testing.T) {
	const futureKey = "not-an-ed25519-key"
	for _, rec := range []string{
		"v=SWORN1; k=future; pk=" + futureKey,
		"v=SWORN1; pk=" + futureKey + "; k=future",
		"v=SWORN1; pk=; k=future",
		"v=SWORN1; k=future",
	} {
		if _, err := ParseRecord(rec); !errors.Is(err, ErrRecordAlgorithm) {
			t.Errorf("%q: err = %v, want ErrRecordAlgorithm", rec, err)
		}
	}
}

// With k=ed25519 the key is held to the same rules in either order, and a
// record that never names an algorithm is still a syntax error, bad key or
// not.
func TestKeyRulesDoNotDependOnTagOrder(t *testing.T) {
	good := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	cases := []struct {
		rec  string
		want error
	}{
		{"v=SWORN1; k=ed25519; pk=" + good, nil},
		{"v=SWORN1; pk=" + good + "; k=ed25519", nil},
		{"v=SWORN1; k=ed25519; pk=short", ErrRecordKey},
		{"v=SWORN1; pk=short; k=ed25519", ErrRecordKey},
		{"v=SWORN1; pk=" + good, ErrRecordSyntax},
		{"v=SWORN1; pk=short", ErrRecordSyntax},
		{"v=SWORN1; k=ed25519", ErrRecordSyntax},
	}
	for _, c := range cases {
		_, err := ParseRecord(c.rec)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%q: err = %v, want %v", c.rec, err, c.want)
		}
	}
}
