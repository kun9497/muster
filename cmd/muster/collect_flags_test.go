package main

import (
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
)

// R58: one parser serves both builds, so an unknown flag is rejected the
// same way on a workstation as on the host it will run on.
func TestParseCollectFlagsAcceptsEveryFlag(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	got, err := parseCollectFlags([]string{"--out", p, "--force", "--deep",
		"--walk-budget", "4m", "--walk-max-entries", "1000",
		"--walk-exclude", "/data", "--walk-include", "/var/snap",
		"--timeout", "30m", "--require-root", "--require-complete"})
	if err != nil {
		t.Fatal(err)
	}
	// collectOpts carries slices now, so the comparison is DeepEqual rather
	// than != — it still fails on any field this list forgot.
	want := collectOpts{out: p, force: true, deep: true,
		walkBudget: 4 * time.Minute, walkMaxEntries: 1000,
		walkExclude: []string{"/data"}, walkInclude: []string{"/var/snap"},
		timeout: 30 * time.Minute, timeoutGiven: true,
		requireRoot: true, requireComplete: true, format: "table"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestParseCollectFlagsDefaults(t *testing.T) {
	got, err := parseCollectFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The budget and the entry cap carry their defaults whether or not
	// --deep was given; --timeout stays zero, which is the collect default.
	want := collectOpts{format: "table", walkBudget: 10 * time.Minute, walkMaxEntries: 2_000_000}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("defaults %+v want %+v", got, want)
	}
}

func TestParseCollectFlagsListActions(t *testing.T) {
	got, err := parseCollectFlags([]string{"--list-actions", "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.listActions || got.format != "json" {
		t.Errorf("got %+v", got)
	}
}

// W-12: a walk with a 10m budget under the 5m global default could only
// ever end as a deadline, so --deep raises the default --timeout to the
// budget plus the five minutes the rest of the run has today.
func TestDeepRaisesTheDefaultTimeout(t *testing.T) {
	got, err := parseCollectFlags([]string{"--deep"})
	if err != nil {
		t.Fatal(err)
	}
	want := collectOpts{deep: true, walkBudget: 10 * time.Minute, walkMaxEntries: 2_000_000,
		timeout: 15 * time.Minute, format: "table"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
	// The raised deadline is a consequence of --deep alone: without it the
	// field stays zero and collect applies its own default.
	plain, err := parseCollectFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.timeout != 0 || plain.timeoutGiven {
		t.Errorf("without --deep the deadline is untouched: %+v", plain)
	}
}

// W-12: an explicit --timeout wins over budget + 5m, and a budget that
// cannot fit inside the effective deadline is refused naming both — a walk
// that is guaranteed to be killed leaves a half-seen filesystem, which is
// ERROR(walk_incomplete) for every walk-based control.
func TestWalkBudgetMustFitTheTimeout(t *testing.T) {
	got, err := parseCollectFlags([]string{"--deep", "--walk-budget", "1m", "--timeout", "3m"})
	if err != nil {
		t.Fatal(err)
	}
	if got.timeout != 3*time.Minute || !got.timeoutGiven || got.walkBudget != time.Minute {
		t.Errorf("an explicit --timeout wins over --walk-budget + 5m: %+v", got)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"explicit budget", []string{"--deep", "--walk-budget", "4m", "--timeout", "3m"}},
		// The default budget is a budget: --deep --timeout 3m asks for a
		// 10m walk inside a 3m deadline and is refused the same way.
		{"default budget", []string{"--deep", "--timeout", "3m"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCollectFlags(tc.args)
			if err == nil {
				t.Fatal("a budget above the effective deadline must be refused")
			}
			for _, want := range []string{"--walk-budget", "--timeout", "3m"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err %q does not name %q", err, want)
				}
			}
		})
	}
}

// A budget of zero is a walk that is over before it starts, and a negative
// one drags the derived deadline below zero, where collect.Run would
// silently put its own 5m default back — a walk running on a deadline the
// operator never asked for. Both are refused naming the flag, exit 2.
func TestWalkBudgetMustBePositive(t *testing.T) {
	for _, v := range []string{"0s", "-10m"} {
		t.Run(v, func(t *testing.T) {
			_, err := parseCollectFlags([]string{"--deep", "--walk-budget", v})
			if err == nil || !strings.Contains(err.Error(), "--walk-budget must be greater than 0") {
				t.Fatalf("err=%v, want one naming --walk-budget", err)
			}
			var out, errb strings.Builder
			if code := runCollect([]string{"--deep", "--walk-budget", v}, &out, &errb); code != exitError {
				t.Errorf("code %d, want %d", code, exitError)
			}
			if !strings.Contains(errb.String(), "--walk-budget must be greater than 0") {
				t.Errorf("stderr %q", errb.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout must stay empty on error, got %q", out.String())
			}
		})
	}
	// The spec refuses a budget ABOVE the deadline, so an equal pair stands.
	got, err := parseCollectFlags([]string{"--deep", "--walk-budget", "3m", "--timeout", "3m"})
	if err != nil {
		t.Fatalf("a budget equal to the deadline is accepted: %v", err)
	}
	if got.walkBudget != got.timeout {
		t.Errorf("got %+v", got)
	}
}

// W-12: a walk flag without --deep tunes a walk that will not run. Ignoring
// it silently is how an operator ends up trusting an exclusion that never
// applied, so it is an error naming the flag, and exit 2 through runCollect.
func TestWalkFlagsNeedDeep(t *testing.T) {
	for _, args := range [][]string{
		{"--walk-budget", "1m"},
		{"--walk-max-entries", "10"},
		{"--walk-exclude", "/data"},
		{"--walk-include", "/var/snap"},
		// A value the walk would also refuse is still reported as the flag
		// that needs --deep: without a walk there is no budget to judge.
		{"--walk-budget", "0s"},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, err := parseCollectFlags(args)
			if want := args[0] + " needs --deep"; err == nil || err.Error() != want {
				t.Fatalf("err=%v, want %q", err, want)
			}
		})
	}
	var out, errb strings.Builder
	if code := runCollect([]string{"--walk-budget", "1m"}, &out, &errb); code != exitError {
		t.Errorf("code %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "--walk-budget needs --deep") {
		t.Errorf("stderr %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on error, got %q", out.String())
	}
}

// L-9/W-2: --walk-exclude adds any root, --walk-include only takes an entry
// off the fixed container-storage set, so it can never become a general
// override that walks /proc or a remote mount.
func TestWalkIncludeOnlyRemovesAFixedRoot(t *testing.T) {
	got, err := parseCollectFlags([]string{"--deep",
		"--walk-exclude", "/data", "--walk-exclude", "/srv/backup",
		"--walk-include", "/var/lib/docker", "--walk-include", "/var/snap"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/data", "/srv/backup"}; !reflect.DeepEqual(got.walkExclude, want) {
		t.Errorf("exclude %v want %v", got.walkExclude, want)
	}
	if want := []string{"/var/lib/docker", "/var/snap"}; !reflect.DeepEqual(got.walkInclude, want) {
		t.Errorf("include %v want %v", got.walkInclude, want)
	}
	roots := collect.ContainerStorageRoots()
	if len(roots) != 15 || !sort.StringsAreSorted(roots) {
		t.Errorf("the fixed set is fifteen sorted paths, got %d: %v", len(roots), roots)
	}
	if !slices.Contains(roots, "/var/lib/containerd") || !slices.Contains(roots, "/var/cache/pbuilder") {
		t.Errorf("fixed set %v", roots)
	}
	for _, r := range roots {
		if _, err := parseCollectFlags([]string{"--deep", "--walk-include", r}); err != nil {
			t.Errorf("--walk-include %s: %v", r, err)
		}
	}
	for _, tc := range []struct{ args, want []string }{
		{[]string{"--deep", "--walk-include", "/proc"}, []string{"--walk-include: /proc is not a container-storage root"}},
		{[]string{"--deep", "--walk-include", "/var/lib/docker/"}, []string{"--walk-include", "/var/lib/docker/"}},
		{[]string{"--deep", "--walk-exclude", "data"}, []string{"--walk-exclude", "data"}},
		// "/" is an absolute, clean path and would still exclude every
		// filesystem under the walk's "equal or under" rule.
		{[]string{"--deep", "--walk-exclude", "/"}, []string{"--walk-exclude: / would exclude every filesystem"}},
		{[]string{"--deep", "--walk-exclude", "/data/../etc"}, []string{"--walk-exclude", "/data/../etc"}},
	} {
		_, err := parseCollectFlags(tc.args)
		if err == nil {
			t.Fatalf("%v was accepted", tc.args)
		}
		for _, want := range tc.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%v: err %q lacks %q", tc.args, err, want)
			}
		}
	}
}

func TestParseCollectFlagsRejections(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"unknown flag", "--bogus", []string{"--bogus"}},
		{"missing value", "needs a value", []string{"--out"}},
		{"bad duration", "--timeout", []string{"--timeout", "soon"}},
		{"bad format", "--format", []string{"--format", "yaml"}},
		{"format without list-actions", "only meaningful with --list-actions", []string{"--format", "json"}},
		{"bad walk budget", "--walk-budget", []string{"--deep", "--walk-budget", "soon"}},
		{"walk budget without a value", "needs a value", []string{"--deep", "--walk-budget"}},
		{"bad walk entry cap", "--walk-max-entries", []string{"--deep", "--walk-max-entries", "lots"}},
		{"walk entry cap of zero", "greater than 0", []string{"--deep", "--walk-max-entries", "0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCollectFlags(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want one naming %q", err, tc.want)
			}
		})
	}
}
