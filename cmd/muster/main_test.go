package main

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func TestRunVersionPrintsFiveLines(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"muster " + version, "commit " + commit, "built " + date,
		"controls " + set.Version, "schema " + strconv.Itoa(facts.SchemaVersion),
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr %q", errb.String())
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
