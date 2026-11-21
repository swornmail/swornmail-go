package main

import (
	"reflect"
	"testing"
)

func TestRepeated(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  []string
	}{
		{"none", nil, nil},
		{"all distinct", []string{"a", "b", "c"}, nil},
		{"one pair", []string{"a", "b", "a"}, []string{"a"}},
		{"reported once however often it repeats", []string{"a", "a", "a", "a"}, []string{"a"}},
		{"first-seen order", []string{"b", "a", "a", "b"}, []string{"a", "b"}},
	}
	for _, c := range cases {
		if got := repeated(c.names); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: repeated(%v) = %v, want %v", c.name, c.names, got, c.want)
		}
	}
}

// Verdicts come back keyed by name alone, so the corpus the harness runs must
// not reuse a name within or across the policy and eligibility cases.
func TestCorpusNamesAreUnique(t *testing.T) {
	policies, eligibility := generate()
	names := make([]string, 0, len(policies)+len(eligibility))
	for _, c := range policies {
		names = append(names, c.name)
	}
	for name := range eligibility {
		names = append(names, name)
	}
	if dups := repeated(names); len(dups) > 0 {
		t.Errorf("corpus has duplicate case names: %v", dups)
	}
}
