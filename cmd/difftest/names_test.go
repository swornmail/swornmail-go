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
		// Names are compared as written: the harness keys results by exact name.
		{"case differs", []string{"a", "A"}, nil},
	}
	for _, c := range cases {
		if got := repeated(c.names); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: repeated(%v) = %v, want %v", c.name, c.names, got, c.want)
		}
	}
}

// The corpus the harness actually runs must itself be free of duplicates, or
// every run would stop before comparing anything.
func TestCorpusNamesAreUnique(t *testing.T) {
	setup()
	if dups := repeated(caseNames(generate(200))); len(dups) > 0 {
		t.Errorf("corpus has duplicate case names: %v", dups)
	}
}

func TestSummarize(t *testing.T) {
	if got, want := summarize([]string{"a", "b"}), "a, b"; got != want {
		t.Errorf("summarize = %q, want %q", got, want)
	}
	many := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"}
	if got, want := summarize(many), "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, and 2 more"; got != want {
		t.Errorf("summarize = %q, want %q", got, want)
	}
}
