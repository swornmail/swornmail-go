package discover

import (
	"errors"
	"strings"
)

// AuthResults formats a Mode-1 outcome as an Authentication-Results field
// value (RFC 8601) using the `sworn` method. It is the one place that value
// is rendered, so the milter and any third-party port that matches it report
// the same outcome the same way.
//
// A pass carries the confirmed operator, the unit the operator asked for
// (policy.unit, a claim) and the observed unit (policy.observed, the source
// /64 this connection corroborated). An operator publishing t=y is reported as
// none with policy.testing=y and policy.wouldbe=pass, never as pass: it has
// not accepted accountability, and a consumer keying on sworn=pass must not
// stake reputation on it. ErrTemp is temperror; any other error is none.
// Prefix values contain ':' and '/', RFC 2045 tspecials, so they are quoted.
func AuthResults(authservID string, res Result, err error) string {
	var b strings.Builder
	b.WriteString(authservID)
	b.WriteString("; sworn=")
	switch {
	case err == nil && res.Testing:
		b.WriteString("none policy.testing=y policy.wouldbe=pass")
	case err == nil:
		b.WriteString("pass")
	case errors.Is(err, ErrTemp):
		b.WriteString("temperror")
		return b.String()
	default:
		b.WriteString("none")
		return b.String()
	}
	b.WriteString(" policy.mode=" + res.Mode)
	b.WriteString(" policy.op=" + res.Operator)
	b.WriteString(` policy.unit="` + res.Unit.String() + `"`)
	b.WriteString(` policy.observed="` + res.ObservedUnit.String() + `"`)
	return b.String()
}
