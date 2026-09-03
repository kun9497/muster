package main

import (
	"bytes"
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
