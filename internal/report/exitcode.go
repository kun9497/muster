package report

import "github.com/kun9497/muster/internal/check"

// ExitOptions selects what counts as a finding (spec §7.2, D11).
type ExitOptions struct {
	AllowError bool
	FailOn     string // fail | warn | manual | none; "" means fail
}

// ExitCode applies the contract 2 > 1 > 0. Errors outrank findings unless
// the caller explicitly allows them; WAIVED and NOT_APPLICABLE never count.
func ExitCode(results []check.Result, o ExitOptions) int {
	failOn := o.FailOn
	if failOn == "" {
		failOn = "fail"
	}
	var hasError, hasFail, hasWarn, hasManual bool
	for _, r := range results {
		switch r.Status {
		case check.ERROR:
			hasError = true
		case check.FAIL:
			hasFail = true
		case check.WARN:
			hasWarn = true
		case check.MANUAL:
			hasManual = true
		}
	}
	if hasError && !o.AllowError {
		return 2
	}
	switch failOn {
	case "none":
		return 0
	case "manual":
		if hasFail || hasWarn || hasManual {
			return 1
		}
	case "warn":
		if hasFail || hasWarn {
			return 1
		}
	default:
		if hasFail {
			return 1
		}
	}
	return 0
}
