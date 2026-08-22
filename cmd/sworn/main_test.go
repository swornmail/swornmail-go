package main

import (
	"encoding/base64"
	"testing"
)

func TestLeadingPositional(t *testing.T) {
	pos, rest := leadingPositional([]string{"tok", "--ip", "::1"})
	if pos != "tok" || len(rest) != 2 {
		t.Errorf("token-first: pos=%q rest=%v", pos, rest)
	}
	pos, rest = leadingPositional([]string{"--ip", "::1", "tok"})
	if pos != "" || len(rest) != 3 {
		t.Errorf("flags-first: pos=%q rest=%v", pos, rest)
	}
	pos, _ = leadingPositional(nil)
	if pos != "" {
		t.Errorf("empty: pos=%q", pos)
	}
}

func TestResultExit(t *testing.T) {
	for result, code := range map[string]int{
		"pass": 0, "fail": 1, "permerror": 2, "temperror": 3, "none": 4, "weird": 2,
	} {
		if got := resultExit(result); got != code {
			t.Errorf("resultExit(%q) = %d, want %d", result, got, code)
		}
	}
}

func TestDecodeTokenAcceptsBothBase64(t *testing.T) {
	raw := []byte{0xd2, 0x84, 0x01, 0x02, 0x03}
	for name, enc := range map[string]string{
		"base64url": base64.RawURLEncoding.EncodeToString(raw),
		"base64std": base64.StdEncoding.EncodeToString(raw),
	} {
		got, err := decodeToken(enc)
		if err != nil || string(got) != string(raw) {
			t.Errorf("%s: got %x err %v", name, got, err)
		}
	}
	if _, err := decodeToken("not valid !!"); err == nil {
		t.Error("garbage decoded without error")
	}
}

func TestOneSwornRecord(t *testing.T) {
	if _, ok := oneSwornRecord([]string{"v=SWORN1; k=ed25519", "unrelated"}); !ok {
		t.Error("single v=SWORN1 record not selected")
	}
	if _, ok := oneSwornRecord([]string{"v=SWORN1; a", "v=SWORN1; b"}); ok {
		t.Error("two v=SWORN1 records wrongly accepted")
	}
	if _, ok := oneSwornRecord([]string{"other"}); ok {
		t.Error("no v=SWORN1 record wrongly accepted")
	}
}
