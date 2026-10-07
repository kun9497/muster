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

// Z-8: a profile file the strict decoder refuses is exit 2, named, and
// nothing reaches stdout.
func TestCheckBadProfileFileIsExit2(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "s.json")
	os.WriteFile(snap, []byte(`{"schema_version": 1, "run": {}, "facts": {}}`), 0o644)
	p := filepath.Join(dir, "p.yaml")
	os.WriteFile(p, []byte("profile: site\nextends: default\nbogus: 1\n"), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", snap, "--profile", p}, &out, &errb); code != exitError || out.Len() != 0 ||
		!strings.Contains(errb.String(), "muster: invalid profile: "+p+": ") || !strings.Contains(errb.String(), "bogus") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// Z-8: a tuning value of the wrong shape is exit 2, the file named.
func TestCheckBadTuningFileIsExit2(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "s.json")
	os.WriteFile(snap, []byte(`{"schema_version": 1, "run": {}, "facts": {}}`), 0o644)
	tn := filepath.Join(dir, "t.yaml")
	os.WriteFile(tn, []byte("params:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: 22\n"), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", snap, "--tuning", tn}, &out, &errb); code != exitError || out.Len() != 0 ||
		!strings.Contains(errb.String(), "muster: invalid tuning file: "+tn+": ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// Fix wave item 5: the usage names the profile default as the built-in one,
// never as "default default".
func TestCheckUsageNamesTheBuiltinDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check"}, &out, &errb); code != exitError {
		t.Fatalf("check without --facts: exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "or a profile file (default: the built-in default)\n") || strings.Contains(errb.String(), "(default default)") {
		t.Errorf("usage %q", errb.String())
	}
}

// Z-21: a repeated --profile or --tuning keeps the last value, as every other
// value flag of check does.
func TestParseCheckArgsRepeatedProfileAndTuningKeepTheLast(t *testing.T) {
	f, err := parseCheckArgs([]string{"--facts", "s", "--profile", "a", "--profile", "b", "--tuning", "t1", "--tuning", "t2"})
	if err != nil {
		t.Fatal(err)
	}
	if f.profile != "b" || f.tuning != "t2" || !f.tuningGiven {
		t.Errorf("profile %q tuning %q, want b and t2", f.profile, f.tuning)
	}
	if f, err = parseCheckArgs([]string{"--facts", "s"}); err != nil || f.profile != "default" || f.tuning != "" || f.tuningGiven {
		t.Errorf("defaults: profile %q tuning %q err %v, want default and none", f.profile, f.tuning, err)
	}
	// Fix wave item 1: an empty value is given, not absent.
	if f, err = parseCheckArgs([]string{"--facts", "s", "--tuning", ""}); err != nil || f.tuning != "" || !f.tuningGiven {
		t.Errorf("--tuning \"\": tuning %q given %v err %v, want an empty value that was given", f.tuning, f.tuningGiven, err)
	}
}
