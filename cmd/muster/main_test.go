package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionPrintsThreeFields(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stderr=%q", code, exitOK, errb.String())
	}
	for _, want := range []string{"muster ", "commit ", "built "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("version output %q lacks %q", out.String(), want)
		}
	}
}

func TestRunUnknownCommandIsExit2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"bogus"}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on error, got %q", out.String())
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("stderr %q lacks 'unknown command'", errb.String())
	}
}

func TestRunNoArgsPrintsHelpAndExits2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "usage:") {
		t.Errorf("stderr %q lacks usage", errb.String())
	}
}

func TestRunRecoversFromPanicWithExit2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"__panic_for_test"}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "internal error") {
		t.Errorf("stderr %q lacks 'internal error'", errb.String())
	}
}
