package main

import (
	"bytes"
	"strings"
	"testing"
)

// The ls synopsis is in the snapshot usage and the top-level usage names the
// listing (RL-16).
func TestSnapshotLsUsageListed(t *testing.T) {
	if !strings.Contains(snapshotUsage, "muster snapshot ls [--dir <d>] [--format table|json]") {
		t.Errorf("snapshot usage lacks the ls synopsis:\n%s", snapshotUsage)
	}
	if !strings.Contains(usage, "list, remove or prune the snapshots muster keeps") {
		t.Errorf("usage does not name the snapshot listing:\n%s", usage)
	}
}

// Flag refusals are the same on every platform: exit 2, the reason and the
// usage on stderr, nothing on stdout.
func TestSnapshotLsFlagRefusals(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--format", "xml"}, "--format must be table or json"},
		{[]string{"--dir", ""}, "flag --dir needs a non-empty value"},
		{[]string{"--format", ""}, "flag --format needs a non-empty value"},
		{[]string{"--dir"}, "flag --dir needs a value"},
		{[]string{"--keep", "1"}, "unknown flag --keep"},
	} {
		var out, errb bytes.Buffer
		code := run(append([]string{"snapshot", "ls"}, tc.args...), &out, &errb)
		if code != exitError || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q; want 2 and empty", tc.args, code, out.String())
		}
		if !strings.Contains(errb.String(), "muster: "+tc.want+"\n") || !strings.Contains(errb.String(), snapshotUsage) {
			t.Errorf("%v: stderr %q lacks %q and the usage", tc.args, errb.String(), tc.want)
		}
	}
}

func TestParseLsArgsDefaults(t *testing.T) {
	f, err := parseLsArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f != (lsFlags{dir: "/var/lib/muster/snapshots", format: "table"}) {
		t.Errorf("defaults = %+v", f)
	}
	f, err = parseLsArgs([]string{"--format", "json", "--dir", "/srv/snaps"})
	if err != nil || f != (lsFlags{dir: "/srv/snaps", format: "json"}) {
		t.Errorf("parsed = %+v, %v", f, err)
	}
}
