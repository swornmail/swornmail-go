package sworn

import "errors"

// Reason maps a verification error to its draft-01 reason token — an advisory
// diagnostic, not a canonical ordering. A nil error is "pass". This is the
// single source of the reason vocabulary shared by the CLI and the test-vector
// generator.
func Reason(err error) string {
	switch {
	case err == nil:
		return "pass"
	case errors.Is(err, ErrIneligibleSrc):
		return "ineligible_source"
	case errors.Is(err, ErrOffPrefix):
		return "off_prefix"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrLifetimeTooLong):
		return "lifetime_too_long"
	case errors.Is(err, ErrBadUnit):
		return "bad_unit"
	case errors.Is(err, ErrBadPrefix):
		return "bad_prefix"
	case errors.Is(err, ErrBadValidity):
		return "bad_validity"
	case errors.Is(err, ErrTestingMode):
		return "testing_mode"
	case errors.Is(err, ErrUnauthorizedPrefix):
		return "unauthorized_prefix"
	case errors.Is(err, ErrPolicyUnitMismatch):
		return "policy_unit_mismatch"
	case errors.Is(err, ErrContentType):
		return "bad_content_type"
	case errors.Is(err, ErrNoSelector):
		return "bad_kid"
	case errors.Is(err, ErrHeaderConfusion):
		return "header_confusion"
	case errors.Is(err, ErrBadRole):
		return "bad_role"
	case errors.Is(err, ErrMalformed):
		return "malformed"
	default:
		return "error"
	}
}

// AuthResult maps a verification error to its draft-01 Authentication-Results
// result value (§Result Reporting). A nil error is "pass"; signature failure,
// off-prefix, expired, and not-yet-valid are "fail"; every other verification
// error is "permerror". DNS-layer none/temperror are decided by the caller
// (they are not verification errors).
func AuthResult(err error) string {
	switch {
	case err == nil:
		return "pass"
	case errors.Is(err, ErrTestingMode):
		// A testing operator has not accepted accountability, so a complete
		// cryptographic success is still reported as none — never pass.
		return "none"
	case errors.Is(err, ErrBadSignature),
		errors.Is(err, ErrOffPrefix),
		errors.Is(err, ErrExpired),
		errors.Is(err, ErrNotYetValid):
		return "fail"
	default:
		return "permerror"
	}
}
