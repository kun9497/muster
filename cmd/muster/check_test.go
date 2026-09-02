package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRequiresFacts(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--facts") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCheckRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "x.json", "--bogus"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--bogus") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCheckSchemaMismatchIsExit2WithEmptyStdout(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.json")
	os.WriteFile(p, []byte(`{"schema_version": 99, "run": {}, "facts": {}}`), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", p}, &out, &errb); code != exitError || out.Len() != 0 || !strings.Contains(errb.String(), "schema_mismatch") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

func TestCheckBadWaiverFileIsExit2(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "s.json")
	os.WriteFile(snap, []byte(`{"schema_version": 1, "run": {}, "facts": {}}`), 0o644)
	w := filepath.Join(dir, "w.yaml")
	os.WriteFile(w, []byte("waivers:\n  - control: muster.a.b\n    reason: ''\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", snap, "--waivers", w}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "reason") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
