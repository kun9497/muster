package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R58: one parser serves both builds, so an unknown flag is rejected the
// same way on a workstation as on the host it will run on.
func TestParseCollectFlagsAcceptsEveryFlag(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	got, err := parseCollectFlags([]string{"--out", p, "--force", "--deep", "--timeout", "90s", "--require-root", "--require-complete"})
	if err != nil {
		t.Fatal(err)
	}
	want := collectOpts{out: p, force: true, deep: true, timeout: 90 * time.Second, requireRoot: true, requireComplete: true, format: "table"}
	if got != want {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestParseCollectFlagsDefaults(t *testing.T) {
	got, err := parseCollectFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != (collectOpts{format: "table"}) {
		t.Errorf("defaults %+v", got)
	}
}

func TestParseCollectFlagsListActions(t *testing.T) {
	got, err := parseCollectFlags([]string{"--list-actions", "--format", "json"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.listActions || got.format != "json" {
		t.Errorf("got %+v", got)
	}
}

func TestParseCollectFlagsRejections(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"unknown flag", "--bogus", []string{"--bogus"}},
		{"missing value", "needs a value", []string{"--out"}},
		{"bad duration", "--timeout", []string{"--timeout", "soon"}},
		{"bad format", "--format", []string{"--format", "yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCollectFlags(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want one naming %q", err, tc.want)
			}
		})
	}
}
