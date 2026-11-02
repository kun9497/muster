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
