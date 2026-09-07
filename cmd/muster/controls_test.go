package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

var repoFixtures = filepath.Join("..", "..", "controls", "testdata")
var repoReferences = filepath.Join("..", "..", "docs", "reference")

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
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 18 controls") {
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
	code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", empty}, &out, &errb)
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
	if code := runControls([]string{"lint", "--fixtures", repoFixtures}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 18 controls") {
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
