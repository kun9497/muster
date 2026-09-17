package controls_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// outcome is what the kill oracle compares: the pair a fixture's result
// shows an operator. F-1 compares against the ORIGINAL's observed outcome,
// never against the fixture's expected prefix, so a fixture that reaches its
// status for a reason unrelated to the mutated clause cannot count as a kill.
type outcome struct {
	Status check.Status
	Reason check.ReasonCode
}

// exclusion is one row of controls/testdata/_mutants.yaml (F-3): a mutant no
// fixture can tell apart, with the reason why.
type exclusion struct {
	Control string `yaml:"control"`
	Mutant  string `yaml:"mutant"`
	Reason  string `yaml:"reason"`
}

// decodeExclusions decodes the exclusion list strictly, like every other YAML
// muster reads, and refuses a row that does not carry all three of F-3's
// fields -- an exclusion without a reason is the thing F-3 exists to prevent.
func decodeExclusions(raw []byte) ([]exclusion, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var out []exclusion
	if err := dec.Decode(&out); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for i, e := range out {
		if e.Control == "" || e.Mutant == "" || strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("entry %d needs control, mutant and reason: %+v", i, e)
		}
	}
	return out, nil
}

// loadExclusions reads controls/testdata/_mutants.yaml. An absent file is an
// empty list: a repository whose fixtures kill every mutant needs no file.
func loadExclusions(t *testing.T, path string) []exclusion {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeExclusions(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// indexExclusion returns the position of the entry covering one mutant of one
// control, or -1. F-3: exclusions are per control and per signature, never
// wildcards.
func indexExclusion(excl []exclusion, id, signature string) int {
	for i := range excl {
		if excl[i].Control == id && excl[i].Mutant == signature {
			return i
		}
	}
	return -1
}

// findExclusion returns the entry covering one mutant of one control, or nil.
func findExclusion(excl []exclusion, id, signature string) *exclusion {
	if i := indexExclusion(excl, id, signature); i >= 0 {
		return &excl[i]
	}
	return nil
}

// compareOutcomes is the kill oracle of F-1. diff says at least one fixture
// answered differently; onlyInternal says every fixture that did so moved to
// ERROR(internal_error), which the evaluator produces by recovering a panic
// and which therefore proves nothing about the judgment; firstDiff is the
// index of the first fixture that differs, or -1.
func compareOutcomes(base, got []outcome) (diff, onlyInternal bool, firstDiff int) {
	firstDiff = -1
	if len(base) != len(got) {
		panic(fmt.Sprintf("outcome count changed: %d then %d", len(base), len(got)))
	}
	onlyInternal = true
	for i := range base {
		if base[i] == got[i] {
			continue
		}
		diff = true
		if firstDiff < 0 {
			firstDiff = i
		}
		if got[i].Reason != check.InternalError {
			onlyInternal = false
		}
	}
	if !diff {
		onlyInternal = false
	}
	return diff, onlyInternal, firstDiff
}

// loadSnapshots reads a control's fixtures once (G-13). Every mutant of that
// control is then evaluated against the same decoded snapshots, so the cost
// of the whole test is the evaluations, not the JSON.
func loadSnapshots(t *testing.T, files []string) []*facts.Snapshot {
	t.Helper()
	out := make([]*facts.Snapshot, 0, len(files))
	for _, f := range files {
		snap, _ := loadFixture(t, f)
		out = append(out, snap)
	}
	return out
}

// evaluateFixtures runs one control against already-loaded snapshots through
// the same one-control set the fixture harness builds, and returns one
// outcome per snapshot in the same order.
func evaluateFixtures(t *testing.T, c controls.Control, set *controls.Set, reg *facts.Registry, snaps []*facts.Snapshot) []outcome {
	t.Helper()
	one := &controls.Set{Version: set.Version, Digest: set.Digest, Controls: []controls.Control{c}}
	out := make([]outcome, 0, len(snaps))
	for _, snap := range snaps {
		r := check.Evaluate(snap, one, reg, check.Options{})[0]
		out = append(out, outcome{Status: r.Status, Reason: r.ReasonCode})
	}
	return out
}

// TestEveryMutantIsKilled is F-1: for every control of the embedded set,
// every mutant F-2 generates is evaluated against the control's own fixtures
// and must change at least one fixture's (status, reason_code). It runs in
// REPORT MODE -- every survivor is logged and the test passes -- until
// MUSTER_MUTANTS_STRICT=1 turns the survivors into a failure. The exclusion
// list (F-3) is honoured either way, and an exclusion that no longer holds --
// killed, or naming a mutant nobody generates -- fails the test whatever the
// mode, because a rotten exclusion is a bug in the list, not a survivor.
func TestEveryMutantIsKilled(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	strict := os.Getenv("MUSTER_MUTANTS_STRICT") == "1"
	excl := loadExclusions(t, filepath.Join(fixtureRoot, "_mutants.yaml"))
	generatedBy := make([]bool, len(excl))

	var generated, invalid, killed, surviving, excluded int
	var report []string
	for _, c := range set.Controls {
		// A control muster declines to judge has nothing to mutate.
		if c.Automation == "manual" && len(c.Checks)+len(c.Mechanisms) == 0 {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(fixtureRoot, c.ID, "*.json"))
		sort.Strings(files)
		if len(files) == 0 {
			t.Errorf("%s has no fixture; every mutant of it would survive unexamined", c.ID)
			continue
		}
		snaps := loadSnapshots(t, files)
		base := evaluateFixtures(t, c, set, reg, snaps)
		for _, m := range mutantsOf(c) {
			generated++
			// F-3: an exclusion that names no generated mutant has rotted.
			// The mark is set before the validity check, because a mutant
			// the lint rejects was still generated -- reporting it as
			// "not generated" would send a reviewer looking for a typo.
			if i := indexExclusion(excl, c.ID, m.Signature); i >= 0 {
				generatedBy[i] = true
			}
			if !lintValid(m.Control, reg) {
				invalid++
				continue
			}
			got := evaluateFixtures(t, m.Control, set, reg, snaps)
			diff, onlyInternal, firstDiff := compareOutcomes(base, got)
			switch {
			case diff && onlyInternal:
				// A recovered panic is not a judgment a fixture saw.
				invalid++
			case diff:
				killed++
				if ex := findExclusion(excl, c.ID, m.Signature); ex != nil {
					t.Errorf("excluded mutant %s %s is now killed by %s; drop the exclusion", c.ID, m.Signature, files[firstDiff])
				}
			case findExclusion(excl, c.ID, m.Signature) != nil:
				excluded++
			default:
				surviving++
				report = append(report, fmt.Sprintf("%s %s: %d fixtures unchanged", c.ID, m.Signature, len(files)))
			}
		}
	}
	for i, e := range excl {
		if !generatedBy[i] {
			t.Errorf("exclusion %s %q names no mutant the generator produces", e.Control, e.Mutant)
		}
	}
	t.Logf("mutants: generated %d, invalid %d, killed %d, surviving %d, excluded %d", generated, invalid, killed, surviving, excluded)
	if surviving > 0 {
		msg := strings.Join(report, "\n")
		if strict {
			t.Errorf("surviving mutants:\n%s", msg)
		} else {
			t.Logf("surviving mutants (report mode; set MUSTER_MUTANTS_STRICT=1 to fail):\n%s", msg)
		}
	}
}

func TestCompareOutcomes(t *testing.T) {
	ok := outcome{check.PASS, ""}
	bad := outcome{check.FAIL, ""}
	boom := outcome{check.ERROR, check.InternalError}
	missing := outcome{check.ERROR, check.MissingFact}
	cases := []struct {
		name             string
		base, got        []outcome
		diff, onlyIntern bool
		first            int
	}{
		{"identical", []outcome{ok, bad}, []outcome{ok, bad}, false, false, -1},
		{"status differs", []outcome{ok, bad}, []outcome{bad, bad}, true, false, 0},
		{"reason code alone differs", []outcome{missing}, []outcome{{check.ERROR, check.ParseError}}, true, false, 0},
		{"only a recovered panic", []outcome{ok, bad}, []outcome{ok, boom}, true, true, 1},
		{"a panic and a real change", []outcome{ok, bad, ok}, []outcome{boom, bad, bad}, true, false, 0},
		{"empty", nil, nil, false, false, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diff, onlyIntern, first := compareOutcomes(tc.base, tc.got)
			if diff != tc.diff || onlyIntern != tc.onlyIntern || first != tc.first {
				t.Errorf("= (%v, %v, %d), want (%v, %v, %d)", diff, onlyIntern, first, tc.diff, tc.onlyIntern, tc.first)
			}
		})
	}
}

func TestFindExclusionMatchesControlAndSignature(t *testing.T) {
	excl := []exclusion{
		{Control: "muster.a.one", Mutant: "checks[0] op eq->ne", Reason: "equivalent"},
		{Control: "muster.a.two", Mutant: "checks[0] op eq->ne", Reason: "equivalent"},
	}
	if got := findExclusion(excl, "muster.a.two", "checks[0] op eq->ne"); got == nil || got.Control != "muster.a.two" {
		t.Errorf("the second row was not matched: %+v", got)
	}
	if got := findExclusion(excl, "muster.a.one", "checks[1] op eq->ne"); got != nil {
		t.Errorf("a different signature matched: %+v", got)
	}
	if got := findExclusion(excl, "muster.a.three", "checks[0] op eq->ne"); got != nil {
		t.Errorf("a different control matched: %+v", got)
	}
	if got := findExclusion(nil, "muster.a.one", "checks[0] op eq->ne"); got != nil {
		t.Errorf("an empty list matched: %+v", got)
	}
}

func TestLoadExclusions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "_mutants.yaml")
	// G-2: Task 2 writes the file; until it exists the list is empty and the
	// loop still runs.
	if got := loadExclusions(t, path); got != nil {
		t.Errorf("an absent file is not an empty list: %+v", got)
	}
	body := "- {control: muster.a.one, mutant: \"checks[0] op lte->gt\", reason: equivalent to lt 4}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []exclusion{{Control: "muster.a.one", Mutant: "checks[0] op lte->gt", Reason: "equivalent to lt 4"}}
	if got := loadExclusions(t, path); !reflect.DeepEqual(got, want) {
		t.Errorf("= %+v, want %+v", got, want)
	}
}

func TestDecodeExclusionsRefusesBadRows(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		// CLAUDE.md: every YAML muster reads is decoded strictly.
		{"unknown key", "- {control: muster.a.one, mutant: m, reason: r, note: x}\n"},
		{"no reason", "- {control: muster.a.one, mutant: m}\n"},
		{"blank reason", "- {control: muster.a.one, mutant: m, reason: \"  \"}\n"},
		{"no mutant", "- {control: muster.a.one, reason: r}\n"},
		{"no control", "- {mutant: m, reason: r}\n"},
		{"not a list", "control: muster.a.one\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := decodeExclusions([]byte(tc.body)); err == nil {
				t.Errorf("accepted %q as %+v", tc.body, got)
			}
		})
	}
	if got, err := decodeExclusions(nil); err != nil || got != nil {
		t.Errorf("an empty file = (%+v, %v), want (nil, nil)", got, err)
	}
}
