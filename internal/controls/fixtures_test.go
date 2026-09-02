package controls_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

const fixtureRoot = "../../controls/testdata"

var prefixStatus = map[string]check.Status{
	"pass": check.PASS, "fail": check.FAIL, "warn": check.WARN, "manual": check.MANUAL,
	"na": check.NotApplicable, "error": check.ERROR,
}

type expect struct {
	ReasonCode string `json:"reason_code"`
	ExitCode   *int   `json:"exit_code"`
}

func loadFixture(t *testing.T, path string) (*facts.Snapshot, expect) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Expect expect `json:"_expect"`
	}
	json.Unmarshal(raw, &meta)
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	delete(tree, "_expect")
	cleaned, _ := json.Marshal(tree)
	s, err := facts.Load(strings.NewReader(string(cleaned)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s, meta.Expect
}

// Every control has pass and fail fixtures, every fixture produces the status
// its name promises, and every result honours the invariants of spec §11.
func TestEveryControlHasFixturesThatBehave(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range set.Controls {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, c.ID)
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			sort.Strings(files)
			seen := map[string]bool{}
			for _, f := range files {
				name := filepath.Base(f)
				prefix := strings.SplitN(name, "-", 2)[0]
				want, ok := prefixStatus[prefix]
				if !ok {
					t.Fatalf("%s: unknown fixture prefix %q", name, prefix)
				}
				if prefix == "fail" && c.Automation == "partial" {
					want = check.WARN
				}
				seen[prefix] = true
				snap, exp := loadFixture(t, f)
				one := &controls.Set{Version: set.Version, Digest: set.Digest, Controls: []controls.Control{c}}
				res := check.Evaluate(snap, one, reg, check.Options{})
				r := res[0]
				if r.Status != want {
					t.Errorf("%s: status %s (%s: %s), want %s", name, r.Status, r.ReasonCode, r.Reason, want)
				}
				if exp.ReasonCode != "" && string(r.ReasonCode) != exp.ReasonCode {
					t.Errorf("%s: reason_code %q want %q", name, r.ReasonCode, exp.ReasonCode)
				}
				if exp.ExitCode != nil {
					if got := report.ExitCode(res, report.ExitOptions{}); got != *exp.ExitCode {
						t.Errorf("%s: exit code %d want %d", name, got, *exp.ExitCode)
					}
				}
				checkInvariants(t, name, r)
			}
			if c.Automation == "auto" || c.Automation == "partial" {
				for _, p := range []string{"pass", "fail"} {
					if !seen[p] {
						t.Errorf("control %s has no %s-*.json fixture under %s", c.ID, p, dir)
					}
				}
			}
		})
	}
}

func checkInvariants(t *testing.T, name string, r check.Result) {
	t.Helper()
	switch r.Status {
	case check.FAIL, check.WARN:
		if r.Reason == "" {
			t.Errorf("%s: %s without reason", name, r.Status)
		}
		if len(r.Evidence) == 0 && len(r.Observations) == 0 {
			t.Errorf("%s: %s without evidence or observations", name, r.Status)
		}
	case check.ERROR:
		if r.ReasonCode == "" || r.Reason == "" {
			t.Errorf("%s: ERROR without reason code and text: %+v", name, r)
		}
		// R25: every ERROR must carry evidence for the fact(s) it errored on,
		// except missing_fact when the fact is not in the snapshot at all —
		// there is nothing on disk to show.
		if r.ReasonCode != check.MissingFact && len(r.Evidence) == 0 {
			t.Errorf("%s: ERROR without evidence: %+v", name, r)
		}
	case check.MANUAL:
		if r.Reason == "" {
			t.Errorf("%s: MANUAL without reason", name)
		}
	case check.NotApplicable:
		if r.Reason == "" {
			t.Errorf("%s: NOT_APPLICABLE without reason", name)
		}
		if r.ReasonCode != check.MissingFact && len(r.Evidence) == 0 {
			t.Errorf("%s: NOT_APPLICABLE without evidence: %+v", name, r)
		}
	}
}

func TestLintOfEmbeddedSetIsClean(t *testing.T) {
	set, _ := controls.LoadDefault()
	reg, _ := facts.LoadRegistry()
	problems := controls.Lint(set, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs(), FixtureDir: fixtureRoot})
	for _, p := range problems {
		t.Error(p)
	}
}
