package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var repoFixtures = filepath.Join("..", "..", "controls", "testdata")
var repoReferences = filepath.Join("..", "..", "docs", "reference")
var repoKisa = filepath.Join("..", "..", "docs", "reference", "kisa")

// R35: run from anywhere but the repository root, lint used to skip the
// fixture-pair rule and print "ok" -- a green light it had not earned.
func TestControlsLintRefusesToRunWithoutTheFixtureDirectory(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint"}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when it could not check fixtures: %q", out.String())
	}
	if !strings.Contains(errb.String(), "controls/testdata") || !strings.Contains(errb.String(), "--fixtures") {
		t.Errorf("stderr must name the missing directory and the flag: %q", errb.String())
	}
}

func TestControlsLintFixturesFlagAndUnusedKeysNote(t *testing.T) {
	var out, errb bytes.Buffer
	// R97: the real embedded set is linted against the real reference index
	// too, so a control that later gains a stig/nist_800_53 reference is
	// checked for existence here, not just shape.
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}
	// Spec §5.5: registered keys no control uses are reported, without failing.
	if !strings.Contains(out.String(), "sockets.listening") || !strings.Contains(out.String(), "used by no control") {
		t.Errorf("stdout %q lacks the unused-keys note", out.String())
	}
}

// R98: without --references, a missing stig/*.json under the given
// directory is an I/O failure named on stderr, exit 2 -- the same class as a
// missing fixture directory (R35). The fixtures check runs first, so this
// case must point at --fixtures repoFixtures to reach the references check.
func TestControlsLintReferencesFlagRejectsAMissingIndex(t *testing.T) {
	empty := t.TempDir()
	var out, errb bytes.Buffer
	code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", empty, "--kisa", repoKisa}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), empty) {
		t.Errorf("stderr %q must name the directory %q", errb.String(), empty)
	}
	if !strings.Contains(errb.String(), "refindex") {
		t.Errorf("stderr %q must name the regenerate command", errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when the reference index could not load: %q", out.String())
	}
}

// R98: without the flag at all, lint accepts any well-formed STIG/NIST
// reference and only checks it for shape -- it must not try to read
// docs/reference on its own and must not fail for that reason.
func TestControlsLintWithoutReferencesFlagChecksShapeOnly(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}
}

func TestControlsLintRejectsAnUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--bogus"}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "--bogus") {
		t.Errorf("stderr %q lacks the flag", errb.String())
	}
	var out2, errb2 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures"}, &out2, &errb2); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb2.String(), "needs a value") {
		t.Errorf("stderr %q lacks the missing-value message", errb2.String())
	}
}

// M-4/M-26: without --references the stig and nist_800_53 ids are checked
// for shape only, and lint says so on stdout instead of leaving the reader
// to believe the ids were verified. --kisa points at the item inventory the
// cross-check needs, and a missing directory is an error the way a missing
// fixture directory is (R35), never a silently skipped rule.
func TestControlsLintNotesAndKisaFlag(t *testing.T) {
	const shapeOnlyNote = "note: stig and nist_800_53 references checked for shape only; pass --references docs/reference to check them against the index"

	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), shapeOnlyNote) {
		t.Errorf("stdout %q lacks the shape-only note", out.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}

	var out2, errb2 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa}, &out2, &errb2); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb2.String())
	}
	if strings.Contains(out2.String(), shapeOnlyNote) {
		t.Errorf("with --references the shape-only note must be gone: %q", out2.String())
	}

	missing := filepath.Join(t.TempDir(), "no-inventory-here")
	var out3, errb3 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", missing}, &out3, &errb3); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out3.String(), errb3.String())
	}
	if !strings.Contains(errb3.String(), missing) || !strings.Contains(errb3.String(), "--kisa") {
		t.Errorf("stderr %q must name the missing directory and the flag", errb3.String())
	}
	if strings.Contains(out3.String(), "ok:") {
		t.Errorf("lint must not report ok when it could not cross-check the inventory: %q", out3.String())
	}

	var out4, errb4 bytes.Buffer
	if code := runControls([]string{"lint", "--kisa"}, &out4, &errb4); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb4.String(), "needs a value") {
		t.Errorf("stderr %q lacks the missing-value message", errb4.String())
	}
}

// M-2: the flag has to reach the lint, not merely be parsed. Pointed at an
// inventory holding an item no control claims and no deferral excuses, lint
// must fail with the set-level rule -- which is exactly what would go
// unnoticed if the CLI parsed --kisa and then handed Lint a nil inventory.
func TestControlsLintCrossChecksAgainstTheInventoryItWasGiven(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"kisa_items_latest.json", "kisa_items_2021.json", "kisa_deferred.json"} {
		data, err := os.ReadFile(filepath.Join(repoKisa, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "kisa_items_latest.json" {
			// One more item than the set enrols, so the coverage rule must
			// fire. The row is synthetic: an id and placeholder fields, no
			// guide text (ATTRIBUTION.md).
			var items []map[string]any
			if err := json.Unmarshal(data, &items); err != nil {
				t.Fatal(err)
			}
			items = append(items, map[string]any{"id": "U-98", "name_ko": "synthetic", "category": "synthetic", "importance": "하", "page": 1})
			if data, err = json.Marshal(items); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", dir}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "controls: kisa_coverage:") || !strings.Contains(errb.String(), "U-98") {
		t.Errorf("stderr %q must carry the set-level coverage problem naming U-98", errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when the cross-check failed: %q", out.String())
	}
}
