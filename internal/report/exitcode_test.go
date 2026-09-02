package report

import (
	"testing"

	"github.com/kun9497/muster/internal/check"
)

func rs(statuses ...check.Status) []check.Result {
	out := make([]check.Result, len(statuses))
	for i, s := range statuses {
		out[i] = check.Result{ID: "x", Status: s}
	}
	return out
}

func TestExitCodePrecedence(t *testing.T) {
	cases := []struct {
		name string
		res  []check.Result
		opts ExitOptions
		want int
	}{
		{"clean", rs(check.PASS, check.NotApplicable, check.WAIVED), ExitOptions{}, 0},
		{"fail", rs(check.PASS, check.FAIL), ExitOptions{}, 1},
		{"error outranks fail", rs(check.FAIL, check.ERROR), ExitOptions{}, 2},
		{"allow-error drops to fail", rs(check.FAIL, check.ERROR), ExitOptions{AllowError: true}, 1},
		{"allow-error clean", rs(check.PASS, check.ERROR), ExitOptions{AllowError: true}, 0},
		{"warn default 0", rs(check.WARN), ExitOptions{}, 0},
		{"warn with fail-on warn", rs(check.WARN), ExitOptions{FailOn: "warn"}, 1},
		{"manual default 0", rs(check.MANUAL), ExitOptions{}, 0},
		{"manual with fail-on manual", rs(check.MANUAL), ExitOptions{FailOn: "manual"}, 1},
		{"fail-on manual includes warn", rs(check.WARN), ExitOptions{FailOn: "manual"}, 1},
		{"fail-on none ignores fail", rs(check.FAIL), ExitOptions{FailOn: "none"}, 0},
		{"fail-on none keeps error", rs(check.FAIL, check.ERROR), ExitOptions{FailOn: "none"}, 2},
		{"waived never counts", rs(check.WAIVED), ExitOptions{FailOn: "manual"}, 0},
	}
	for _, c := range cases {
		if got := ExitCode(c.res, c.opts); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}
