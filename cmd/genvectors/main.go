// Command genvectors emits the deterministic SwornMail test vectors
// consumed by the spec repo and by other implementations (Rust crate,
// plugins) for cross-implementation conformance.
//
// Determinism: fixed Ed25519 seed, fixed timestamps, deterministic CBOR
// encoding, and RFC 8032 deterministic signatures — output is stable
// across runs and platforms.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/swornmail/swornmail-go/sworn"
)

type vectorCase struct {
	Name     string `json:"name"`
	TokenB64 string `json:"token_b64"`
	Source   string `json:"source_ip"`
	Now      int64  `json:"now_unix"`
	Expect   string `json:"expect"` // "pass" or the expected error reason
	Operator string `json:"operator,omitempty"`
	Unit     string `json:"unit,omitempty"` // expected reputation unit on pass
}

type vectors struct {
	Spec    string       `json:"spec"`
	SeedHex string       `json:"ed25519_seed_hex"`
	PubHex  string       `json:"ed25519_public_hex"`
	Record  string       `json:"sworn_record"`
	Cases   []vectorCase `json:"cases"`
}

func main() {
	out := flag.String("o", "test-vectors-v0.json", "output path")
	flag.Parse()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	iat := time.Unix(1786291200, 0).UTC()
	payload := sworn.Payload{
		Operator: "mailer.example.com",
		Prefix:   netip.MustParsePrefix("2001:db8:f00::/48"),
		Unit:     64,
		IssuedAt: iat,
		Expires:  iat.Add(12 * time.Hour),
		Role:     "mta",
	}
	token, err := sworn.Sign(payload, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
	tampered := append([]byte(nil), token...)
	tampered[len(tampered)-1] ^= 0xff

	tokB64 := base64.StdEncoding.EncodeToString(token)
	inNow := iat.Add(time.Hour).Unix()
	v := vectors{
		Spec:    "draft-kafedzhy-swornmail-00",
		SeedHex: hex.EncodeToString(seed),
		PubHex:  hex.EncodeToString(pub),
		Record: "v=SWORN1; k=ed25519; s=2026a; pk=" +
			base64.StdEncoding.EncodeToString(pub) + "; u=64",
		Cases: []vectorCase{
			{
				Name: "valid_in_prefix", TokenB64: tokB64,
				Source: "2001:db8:f00:1234::a:1", Now: inNow, Expect: "pass",
				Operator: "mailer.example.com", Unit: "2001:db8:f00:1234::/64",
			},
			{
				Name: "prefix_first_address", TokenB64: tokB64,
				Source: "2001:db8:f00::", Now: inNow, Expect: "pass",
				Operator: "mailer.example.com", Unit: "2001:db8:f00::/64",
			},
			{
				Name: "off_prefix_adjacent", TokenB64: tokB64,
				Source: "2001:db8:f01::a:1", Now: inNow, Expect: "off_prefix",
			},
			{
				Name: "expired", TokenB64: tokB64,
				Source: "2001:db8:f00:1234::a:1",
				Now:    iat.Add(13 * time.Hour).Unix(), Expect: "expired",
			},
			{
				Name: "not_yet_valid", TokenB64: tokB64,
				Source: "2001:db8:f00:1234::a:1",
				Now:    iat.Add(-time.Hour).Unix(), Expect: "not_yet_valid",
			},
			{
				Name:     "tampered_signature",
				TokenB64: base64.StdEncoding.EncodeToString(tampered),
				Source:   "2001:db8:f00:1234::a:1", Now: inNow, Expect: "bad_signature",
			},
		},
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d cases, token=%d bytes)\n", *out, len(v.Cases), len(token))
}
