package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

var repoFixtures = filepath.Join("..", "..", "controls", "testdata")

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
	if code := runControls([]string{"lint", "--fixtures", repoFixtures}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 8 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}
	// Spec §5.5: registered keys no control uses are reported, without failing.
	if !strings.Contains(out.String(), "sockets.listening") || !strings.Contains(out.String(), "used by no control") {
		t.Errorf("stdout %q lacks the unused-keys note", out.String())
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
