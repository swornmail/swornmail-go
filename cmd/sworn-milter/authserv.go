package main

import (
	"regexp"
	"strings"
)

// claimsID reports whether an inbound Authentication-Results value could be
// read as carrying our authserv-id. The sender picks every byte, and parsers
// downstream don't agree on whitespace, comments, escapes or where the id
// ends, so this fails closed: the field counts as ours if the strict RFC 8601
// reading or any of the looser ones gives our id. Deleting a field we didn't
// need to is harmless; leaving a forged one in place is not.
func claimsID(value, id string) bool {
	return encodedWordStart.MatchString(value) || readsAsID(value, id)
}

// encodedWordStart matches the start of an RFC 2047 encoded-word. They aren't
// allowed in this field, but some parsers decode them anyway, and loosely:
// Python's email package accepts bad base64, bad escapes and spaces inside a
// word. Rather than chase every decoder, any field containing one counts as
// ours. A well-formed field has no reason to contain one, so at worst we drop
// someone else's malformed result.
var encodedWordStart = regexp.MustCompile(`(?i)=\?[^?]*\?[bq]\?`)

func readsAsID(value, id string) bool {
	if sameID(authservIDOf(value), id) {
		return true
	}
	for _, mode := range commentModes {
		if sameID(leadingToken(value, mode), id) {
			return true
		}
	}
	return false
}

// sameID compares ids the way a consumer might: case-insensitively, and with
// or without a trailing dot.
func sameID(got, id string) bool {
	got, id = strings.TrimSuffix(got, "."), strings.TrimSuffix(id, ".")
	return got != "" && strings.EqualFold(got, id)
}

// commentMode is one way a parser might treat parentheses.
type commentMode struct {
	comments bool // "(" opens a comment; otherwise it's just punctuation
	nesting  bool // comments nest
	escapes  bool // a backslash in a comment escapes the next byte
}

var commentModes = []commentMode{
	{comments: true, nesting: true, escapes: true}, // RFC 5322
	{comments: true, nesting: true},
	{comments: true, escapes: true},
	{comments: true},
	{},
}

// leadingToken is the loose reading: skip everything up to the first byte
// that can appear in an RFC 2045 token, treating parentheses as mode says,
// and return the run of token bytes that starts there. Control characters,
// non-ASCII whitespace and quotes are all skipped or end the token.
func leadingToken(value string, mode commentMode) string {
	depth := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case depth > 0 && mode.escapes && c == '\\':
			i++
		case mode.comments && c == '(' && (depth == 0 || mode.nesting):
			depth++
		case depth > 0 && c == ')':
			depth--
		case depth == 0 && isTokenByte(c):
			end := i
			for end < len(value) && isTokenByte(value[end]) {
				end++
			}
			return value[i:end]
		}
	}
	return ""
}

// isTokenByte reports whether c can appear in an RFC 2045 token.
func isTokenByte(c byte) bool {
	return c > ' ' && c < 0x7f && !strings.ContainsRune(`()<>@,;:\"/[]?=`, rune(c))
}

// authservIDOf returns the authserv-id from an Authentication-Results value
// the way RFC 8601 §2.2 defines it: skip leading whitespace and comments, then
// take the token or quoted string. Whatever follows it (a version, a comment,
// the ';') is ignored, and a comment or quoted string that never closes means
// there is no id.
func authservIDOf(value string) string {
	s := skipCFWS(value)
	if !strings.HasPrefix(s, `"`) {
		if end := strings.IndexAny(s, " \t\r\n(;"); end >= 0 {
			return s[:end]
		}
		return s
	}
	var id strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i++; i < len(s) {
				id.WriteByte(s[i])
			}
		case '"':
			return id.String()
		default:
			id.WriteByte(s[i])
		}
	}
	return ""
}

// skipCFWS skips leading whitespace and comments. Comments can nest and
// contain backslash escapes (RFC 5322 §3.2.2); an unclosed one eats the rest.
func skipCFWS(value string) string {
	depth := 0
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case depth > 0 && c == '\\':
			i++
		case c == '(':
			depth++
		case depth > 0 && c == ')':
			depth--
		case depth == 0 && c != ' ' && c != '\t' && c != '\r' && c != '\n':
			return value[i:]
		}
	}
	return ""
}
