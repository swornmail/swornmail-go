package discover

import (
	"errors"
	"fmt"
	"strings"
)

// AuthResults formats a Mode-1 outcome as an Authentication-Results field
// value (RFC 8601), per draft-01 §Result Reporting. It is the single place
// the result vocabulary is produced, so every receiver-side integration —
// milter, CLI, and any third-party port — reports identically.
//
// Testing mode (t=y) is the subtle case the spec makes a MUST: a confirmed
// operator that is still observing is reported as `none`, carrying the
// would-be result in policy.wouldbe. Reporting it as `pass` would stake
// reputation the operator explicitly has not accepted — the whole purpose of
// the observe-only on-ramp — and would mislead consumers that key on
// `sworn=pass` into treating a trial deployment as a committed one.
func AuthResults(authservID string, res Result, err error) string {
	switch {
	case err == nil && res.Testing:
		return join(authservID, "sworn=none policy.testing=y policy.wouldbe=pass", properties(res))
	case err == nil:
		return join(authservID, "sworn=pass", properties(res))
	case errors.Is(err, ErrTemp):
		// DNS failure or query-budget exhaustion: no accountable party was
		// identified, and per §Receiver Reputation Semantics this MUST NOT be
		// treated as worse than none.
		return join(authservID, "sworn=temperror", "")
	default: // ErrNone
		return join(authservID, "sworn=none", "")
	}
}

// properties renders the diagnostic properties shared by pass and testing
// results. Prefixes are quoted: they contain ':' and '/', which RFC 8601
// requires be emitted as a quoted-string.
//
// Both units are emitted because they mean different things and a consumer
// reading only the header has no other way to tell them apart. policy.unit is
// the aggregation the operator asked for — a claim. policy.observed is the
// source /64 actually corroborated by this connection, and is what reputation
// attaches to unless the receiver holds independent evidence that the operator
// controls the whole attested prefix.
func properties(res Result) string {
	return fmt.Sprintf("policy.mode=%s policy.op=%s policy.unit=%q policy.observed=%q",
		res.Mode, res.Operator, res.Unit.String(), res.ObservedUnit.String())
}

func join(authservID, result, props string) string {
	var b strings.Builder
	b.WriteString(authservID)
	b.WriteString("; ")
	b.WriteString(result)
	if props != "" {
		b.WriteString(" ")
		b.WriteString(props)
	}
	return b.String()
}
