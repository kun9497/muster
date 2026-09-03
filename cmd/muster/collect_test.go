package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCollectRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--bogus"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--bogus") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on error, got %q", out.String())
	}
}

func TestCollectOffLinuxSaysSo(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--out", "-"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "requires Linux") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// R58: --list-actions is unsupported off Linux too, and the answer is
	// the same sentence rather than a half-answered action list.
	out.Reset()
	errb.Reset()
	if code := run([]string{"collect", "--list-actions"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "requires Linux") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty off Linux, got %q", out.String())
	}
}

// The whole command end to end against the real host: it writes a 0600
// snapshot where it was told to, says so on stderr, keeps stdout empty and
// returns 0 (complete, as root) or 1 (partial, as anyone else). Nothing
// about what was collected is asserted — that is the host's business, not
// this repository's (D02).
func TestCollectWritesASnapshotOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	p := filepath.Join(t.TempDir(), "s.json")
	var out, errb bytes.Buffer
	code := run([]string{"collect", "--out", p}, &out, &errb)
	if code != exitOK && code != exitFindings {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "muster: wrote ") {
		t.Errorf("stderr %q lacks the wrote line", errb.String())
	}
	if os.Geteuid() != 0 && !strings.Contains(errb.String(), "not running as root") {
		t.Errorf("a non-root run must warn: %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout carries only a snapshot asked for with --out -, got %q", out.String())
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
}

// I2 (R83): an --out path that is a symbolic link is refused before
// anything is written, with --force exactly as without it, and the command
// reports it the way it reports the writer's other refusals — exit 2 and a
// "muster:" line that names the path and what it is, not a generic
// "collect failed".
func TestCollectRefusesASymlinkedOutPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "s.json")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"collect", "--out", link},
		{"collect", "--out", link, "--force"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != exitError {
			t.Errorf("%v: code %d, want %d (stderr %q)", args, code, exitError, errb.String())
		}
		if want := "muster: " + link + ": output path is a symbolic link"; !strings.Contains(errb.String(), want) {
			t.Errorf("%v: stderr %q lacks %q", args, errb.String(), want)
		}
		if got, _ := os.ReadFile(target); string(got) != "original" {
			t.Errorf("%v: the link's target was written: %q", args, got)
		}
	}
}

func TestCollectListActionsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--list-actions", "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	// R60: /proc/self/status is read by the "muster" pseudo-collector, so
	// the action list names it like any other declared read.
	for _, want := range []string{`"kind": "read"`, `"kind": "command"`, `"kind": "write"`, "/usr/sbin/sshd -T", "/proc/self/status"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	if errb.Len() != 0 {
		t.Errorf("stderr must stay empty, got %q", errb.String())
	}
}
