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
		Expect    expect `json:"_expect"`
		Synthetic *bool  `json:"synthetic"`
	}
	json.Unmarshal(raw, &meta)
	// Spec §11 and CLAUDE.md: a fixture is captured from a public image with
	// a provenance header, or it is synthetic and says so. Every fixture in
	// this repository is synthetic (D02).
	if meta.Synthetic == nil || !*meta.Synthetic {
		t.Errorf(`%s: fixture must carry a top-level "synthetic": true marker`, path)
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	delete(tree, "_expect")
	// "synthetic" is deliberately left in: facts.Load must ignore a top-level
	// key it does not know, the same way a real snapshot may gain one.
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
		// Spec §11: "MANUAL carries evidence" — a human asked to decide must
		// be shown the facts the engine could read.
		if len(r.Evidence) == 0 && len(r.Observations) == 0 {
			t.Errorf("%s: MANUAL without evidence or observations: %+v", name, r)
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

// M-8/M-25: a control muster declines to judge names the facts the reviewer
// needs in front of them, so its manual-*.json fixture must carry every one
// of those leaves. A leaf the fixture omits reads back "missing", which
// shows the reviewer nothing exactly where the control promised evidence.
// (The walk gate's own missing walk.complete on
// muster.file.world_writable/manual-no-walk.json is by design — R16 — and is
// not an evidence-list key, so it is out of this test's scope.)
func TestManualFixturesCarryEveryEvidenceLeaf(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range set.Controls {
		if c.Automation != "manual" || len(c.Evidence) == 0 {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(fixtureRoot, c.ID, "manual-*.json"))
		sort.Strings(files)
		if len(files) == 0 {
			t.Errorf("%s declares evidence but has no manual-*.json fixture to show it on", c.ID)
		}
		for _, f := range files {
			snap, _ := loadFixture(t, f)
			one := &controls.Set{Version: set.Version, Digest: set.Digest, Controls: []controls.Control{c}}
			r := check.Evaluate(snap, one, reg, check.Options{})[0]
			if r.Status != check.MANUAL {
				t.Errorf("%s: status %s (%s), want MANUAL", f, r.Status, r.Reason)
				continue
			}
			status := map[string]facts.Status{}
			for _, ev := range r.Evidence {
				status[ev.Fact] = ev.Status
			}
			for _, k := range c.Evidence {
				st, ok := status[k]
				if !ok {
					t.Errorf("%s: the result carries no evidence for %s", f, k)
					continue
				}
				if st == facts.StatusMissing {
					t.Errorf("%s: evidence %s is missing from the fixture; a MANUAL result must show every leaf its control names", f, k)
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no manual control with an evidence list was checked; M-8's evidence lists are gone")
	}
}

func TestLintOfEmbeddedSetIsClean(t *testing.T) {
	set, _ := controls.LoadDefault()
	reg, _ := facts.LoadRegistry()
	idx, err := controls.LoadReferenceIndex("../../docs/reference")
	if err != nil {
		t.Fatal(err)
	}
	problems := controls.Lint(set, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs(), FixtureDir: fixtureRoot, References: idx})
	for _, p := range problems {
		t.Error(p)
	}
}
