package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// jsonRecord carries the fields a DNS provider's API asks for. Strings is the
// value already split into character-strings, which providers that reject a
// value over 255 octets (Route 53 among them) require.
type jsonRecord struct {
	Role     string   `json:"role"` // key | policy | pointer
	QName    string   `json:"qname"`
	Name     string   `json:"name"` // relative to the zone, for panel/API fields
	Type     string   `json:"type"`
	TTL      int      `json:"ttl"`
	Value    string   `json:"value"`
	Strings  []string `json:"strings"`
	Required bool     `json:"required"`
}

type recordSetJSON struct {
	Domain  string       `json:"domain"`
	Records []jsonRecord `json:"records"`
	Notes   []string     `json:"notes,omitempty"`
}

func printRecordSetJSON(w io.Writer, rs recordSet) int {
	out := recordSetJSON{
		Domain: rs.Domain,
		Records: []jsonRecord{
			jsonRecordOf("key", rs.Key, rs.Domain, true),
			jsonRecordOf("policy", rs.Policy, rs.Domain, true),
		},
	}
	for _, p := range rs.Pointers {
		out.Records = append(out.Records, jsonRecordOf("pointer", p, rs.Domain, false))
	}
	// Notes are wrapped for a terminal; JSON consumers want one line each.
	for _, n := range rs.Notes {
		out.Notes = append(out.Notes, strings.ReplaceAll(n, "\n", " "))
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sworn:", err)
		return 2
	}
	fmt.Fprintln(w, string(b))
	return 0
}

func jsonRecordOf(role string, rec dnsRecord, domain string, required bool) jsonRecord {
	return jsonRecord{
		Role:     role,
		QName:    rec.QName,
		Name:     relativeName(rec.QName, domain),
		Type:     "TXT",
		TTL:      recordTTL,
		Value:    rec.Value,
		Strings:  txtChunks(rec.Value),
		Required: required,
	}
}
