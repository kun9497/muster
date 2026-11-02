package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/snapshots"
)

func TestRmParsesArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want rmFlags
	}{
		{[]string{"a.json"}, rmFlags{dir: snapshots.DefaultDir, names: []string{"a.json"}}},
		{[]string{"--dir", "/srv/s", "--dry-run", "a.json", "b.json"}, rmFlags{dir: "/srv/s", dryRun: true, names: []string{"a.json", "b.json"}}},
		{[]string{"/srv/s/a.json", "/srv/s/b.json"}, rmFlags{dir: "/srv/s", names: []string{"a.json", "b.json"}}},
		{[]string{"--", "-x.json"}, rmFlags{dir: snapshots.DefaultDir, names: []string{"-x.json"}}},
		{[]string{"/d/x.json"}, rmFlags{dir: "/d", names: []string{"x.json"}}},
	} {
		got, err := parseRmArgs(tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: %+v, %v; want %+v", tc.args, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "rm needs at least one name"},
		{[]string{"--dry-run"}, "rm needs at least one name"},
		{[]string{"--dir"}, "flag --dir needs a value"},
		{[]string{"--dir", "", "a.json"}, "flag --dir needs a non-empty value"},
		{[]string{"--keep", "1", "a.json"}, "unknown flag --keep"},
		{[]string{"rel/a.json"}, "rel/a.json is not an absolute path"},
		{[]string{"--dir", "/srv/s", "/srv/s/a.json"}, "not both"},
		{[]string{"/srv/s/a.json", "b.json"}, "not both"},
		{[]string{"/srv/s/a.json", "/srv/t/b.json"}, "not both"},
		{[]string{"/d/x/"}, "/d/x/ is not a clean absolute path"},
		{[]string{"/d//x.json"}, "/d//x.json is not a clean absolute path"},
		{[]string{"/d/a/../b.json"}, "/d/a/../b.json is not a clean absolute path"},
		{[]string{"--dir", "/a", "--dir", "/b", "x.json"}, "flag --dir given twice"},
		{[]string{"--dry-run", "--dry-run", "x.json"}, "flag --dry-run given twice"},
	} {
		if _, err := parseRmArgs(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestPruneParsesArgs(t *testing.T) {
	got, err := parsePruneArgs([]string{"--keep", "3", "--keep-days", "0", "--dir", "/srv/s", "--dry-run"})
	want := pruneFlags{dir: "/srv/s", dryRun: true, b: snapshots.Bounds{Keep: 3, HasKeep: true, HasKeepDays: true}}
	if err != nil || got != want {
		t.Errorf("got %+v, %v; want %+v", got, err, want)
	}
	if got, err := parsePruneArgs([]string{"--keep-days", "7"}); err != nil || got.dir != snapshots.DefaultDir || got.b != (snapshots.Bounds{KeepDays: 7, HasKeepDays: true}) {
		t.Errorf("--keep-days 7: %+v, %v", got, err)
	}
	if got, err := parsePruneArgs([]string{"--keep-days", "36500"}); err != nil || got.b != (snapshots.Bounds{KeepDays: 36500, HasKeepDays: true}) {
		t.Errorf("--keep-days 36500: %+v, %v", got, err)
	}
	if _, err := parsePruneArgs(nil); !errors.Is(err, snapshots.ErrNoBounds) {
		t.Errorf("no bound: err = %v, want ErrNoBounds", err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--keep", "-1"}, "flag --keep needs a non-negative integer"},
		{[]string{"--keep-days", "-2"}, "flag --keep-days needs a non-negative integer"},
		{[]string{"--keep-days", "36501"}, "flag --keep-days must be at most 36500"},
		{[]string{"--keep", "x"}, "flag --keep needs a non-negative integer"},
		{[]string{"--keep", "1", "--keep", "2"}, "flag --keep given twice"},
		{[]string{"--keep-days", "1", "--keep-days", "2"}, "flag --keep-days given twice"},
		{[]string{"--keep"}, "flag --keep needs a value"},
		{[]string{"--keep", "1", "a.json"}, "unknown flag a.json"},
		{[]string{"--keep", "1", "--dir", "/a", "--dir", "/b"}, "flag --dir given twice"},
		{[]string{"--keep", "1", "--dry-run", "--dry-run"}, "flag --dry-run given twice"},
	} {
		if _, err := parsePruneArgs(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestValidRmName(t *testing.T) {
	for _, name := range []string{"a.json", "notes.txt", "-x", ".hidden"} {
		if !validRmName(name) {
			t.Errorf("validRmName(%q) = false", name)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", "../x", "a\nb", "a\x7fb", "a\tb"} {
		if validRmName(name) {
			t.Errorf("validRmName(%q) = true", name)
		}
	}
}

// Flag refusals print the reason and the usage, exit 2, stdout empty.
func TestRmAndPruneFlagRefusals(t *testing.T) {
	for _, args := range [][]string{{"rm"}, {"prune"}, {"prune", "--keep", "-1"}} {
		var out, errb strings.Builder
		code := run(append([]string{"snapshot"}, args...), &out, &errb)
		if code != exitError || out.Len() != 0 || !strings.Contains(errb.String(), snapshotUsage) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out.String(), errb.String())
		}
	}
}
