//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
)

// The rm and prune directory: ok rows a (40 days before rmNow), b (10 days)
// and c (1 hour), a newer row n collected after c, an unreadable row u, a
// non-pattern file, a subdirectory and latest -> c.
const (
	rmA = "web01-2026-08-22T070000Z-aaaaaaaaaaa1.json"
	rmB = "web01-2026-09-21T070000Z-bbbbbbbbbbb1.json"
	rmC = "web01-2026-10-01T060000Z-ccccccccccc1.json"
	rmN = "web01-2026-10-02T060000Z-ddddddddddd1.json"
	rmU = "web01-2026-08-01T060000Z-eeeeeeeeeee1.json"
	rmZ = "web01-2026-08-22T070000Z-fffffffffff1.json"
)

var rmNow = time.Date(2026, 10, 1, 7, 0, 0, 0, time.UTC) // c.collected_at + 1h

const rmWarnN = "muster: warning: " + rmN + " (newer) is newer than the newest readable snapshot "

func seedRmDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, filepath.Join(dir, rmA), snapBody(1, "2026-08-22T07:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, rmB), snapBody(1, "2026-09-21T07:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, rmC), snapBody(1, "2026-10-01T06:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, rmN), snapBody(99, "2026-10-02T06:00:00Z", "web01", seedMusterNext, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, rmU), "{")
	writeSnapshot(t, filepath.Join(dir, "notes.txt"), "notes")
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rmC, filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runSnap(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"snapshot"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// dirNames is the directory's listing, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}

func latestOf(t *testing.T, dir string) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(dir, "latest"))
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	return target
}

func TestRmRemovesByNameAndRepointsLatest(t *testing.T) {
	dir := seedRmDir(t)
	code, out, stderr := runSnap(t, "rm", "--dir", dir, rmC)
	if code != exitOK || out != "" {
		t.Fatalf("rm c: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if exists(t, filepath.Join(dir, rmC)) {
		t.Errorf("c still there")
	}
	if got := latestOf(t, dir); got != rmB {
		t.Errorf("latest -> %s, want b", got)
	}
	if want := rmWarnN + rmB + "\nmuster: latest -> " + rmB + "\n"; stderr != want {
		t.Errorf("stderr = %q\nwant     %q", stderr, want)
	}

	if code, out, stderr := runSnap(t, "rm", "--dir", dir, rmN, rmU, "notes.txt"); code != exitOK || out != "" || stderr != "" {
		t.Errorf("rm n u notes.txt: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	for _, name := range []string{rmN, rmU, "notes.txt"} {
		if exists(t, filepath.Join(dir, name)) {
			t.Errorf("%s still there", name)
		}
	}

	before := dirNames(t, dir)
	if code, _, stderr := runSnap(t, "rm", "--dir", dir, "d"); code != exitError || !strings.Contains(stderr, "d is a directory") {
		t.Errorf("rm d: exit %d, stderr %q", code, stderr)
	}
	if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("rm d changed the directory: %v -> %v", before, after)
	}

	// RA-3: the pre-pass refuses before anything is removed.
	if code, _, stderr := runSnap(t, "rm", "--dir", dir, rmB, "d"); code != exitError || !strings.Contains(stderr, "d is a directory") {
		t.Errorf("rm b d: exit %d, stderr %q", code, stderr)
	}
	if !exists(t, filepath.Join(dir, rmB)) {
		t.Errorf("rm b d removed b before refusing d")
	}

	// RA-8: latest is refused by name, a link or not.
	const latestMsg = "muster: latest is a link; name the snapshot it points at\n"
	if code, _, stderr := runSnap(t, "rm", "--dir", dir, "latest"); code != exitError || stderr != latestMsg {
		t.Errorf("rm latest (a link): exit %d, stderr %q", code, stderr)
	}
	if err := os.Remove(filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, filepath.Join(dir, "latest"), rmB)
	if code, _, stderr := runSnap(t, "rm", "--dir", dir, "latest"); code != exitError || stderr != latestMsg {
		t.Errorf("rm latest (a file): exit %d, stderr %q", code, stderr)
	}
	if !exists(t, filepath.Join(dir, "latest")) {
		t.Errorf("a regular latest was removed")
	}

	// Review Focus 1: no path components, no control bytes. A name with a
	// '/' is a path, and a relative one is refused before the directory is
	// opened.
	for _, tc := range []struct{ name, want string }{
		{"../x", "../x is not an absolute path"},
		{"a\nb", "is not a file name"},
		{".", "is not a file name"},
		{"..", "is not a file name"},
	} {
		before := dirNames(t, dir)
		if code, _, stderr := runSnap(t, "rm", "--dir", dir, tc.name); code != exitError || !strings.Contains(stderr, tc.want) {
			t.Errorf("rm %q: exit %d, stderr %q", tc.name, code, stderr)
		}
		if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
			t.Errorf("rm %q changed the directory", tc.name)
		}
	}

	// A full path names its own directory.
	if code, out, stderr := runSnap(t, "rm", filepath.Join(dir, rmB)); code != exitOK || out != "" || stderr != "" {
		t.Errorf("rm <full path of b>: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if exists(t, filepath.Join(dir, rmB)) {
		t.Errorf("b still there after rm by full path")
	}

	// RA-11: never both, never two directories.
	other := seedRmDir(t)
	const notBoth = "rm takes bare names under --dir or full paths of one directory, not both"
	for _, args := range [][]string{
		{"rm", "--dir", dir, filepath.Join(dir, rmA)},
		{"rm", filepath.Join(dir, rmA), filepath.Join(other, rmB)},
		{"rm", filepath.Join(dir, rmA), rmB},
	} {
		if code, _, stderr := runSnap(t, args...); code != exitError || !strings.Contains(stderr, notBoth) {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if !exists(t, filepath.Join(dir, rmA)) || !exists(t, filepath.Join(other, rmB)) {
		t.Errorf("a refused rm removed a file")
	}
}

// With no ok snapshot left, the latest link is removed, not re-pointed.
func TestRmRemovesLatestWhenNoOKSnapshotIsLeft(t *testing.T) {
	dir := seedRmDir(t)
	for _, name := range []string{rmA, rmB} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	code, out, stderr := runSnap(t, "rm", "--dir", dir, rmC)
	if code != exitOK || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if exists(t, filepath.Join(dir, "latest")) {
		t.Errorf("latest still there")
	}
	if !strings.HasSuffix(stderr, "muster: latest link removed\n") {
		t.Errorf("stderr = %q, want it to end with the link removal", stderr)
	}
}

func TestRmDryRunRemovesNothing(t *testing.T) {
	dir := seedRmDir(t)
	before := dirNames(t, dir)
	code, out, stderr := runSnap(t, "rm", "--dir", dir, "--dry-run", rmC, "notes.txt")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "would remove " + rmC + "\nwould remove notes.txt\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("dry run changed the directory: %v -> %v", before, after)
	}
	if got := latestOf(t, dir); got != rmC {
		t.Errorf("latest -> %s, want c", got)
	}
}

func TestPruneKeepsTheNewestAndSkipsNewerAndUnreadable(t *testing.T) {
	pinNow(t, rmNow)
	for _, tc := range []struct {
		bounds  []string
		removed []string
	}{
		{[]string{"--keep-days", "7"}, []string{rmA, rmB}},
		{[]string{"--keep", "1"}, []string{rmA, rmB}},
		{[]string{"--keep", "2", "--keep-days", "7"}, []string{rmA}},
	} {
		dir := seedRmDir(t)
		code, out, stderr := runSnap(t, append([]string{"prune", "--dir", dir}, tc.bounds...)...)
		if code != exitOK || out != "" {
			t.Fatalf("%v: exit %d, stdout %q, stderr %q", tc.bounds, code, out, stderr)
		}
		if want := rmWarnN + rmC + "\n"; stderr != want {
			t.Errorf("%v: stderr = %q\nwant %q", tc.bounds, stderr, want)
		}
		for _, name := range []string{rmA, rmB, rmC, rmN, rmU, "notes.txt", "d"} {
			gone := !exists(t, filepath.Join(dir, name))
			want := false
			for _, r := range tc.removed {
				want = want || r == name
			}
			if gone != want {
				t.Errorf("%v: %s gone = %v, want %v", tc.bounds, name, gone, want)
			}
		}
		if got := latestOf(t, dir); got != rmC {
			t.Errorf("%v: latest -> %s, want c", tc.bounds, got)
		}
	}

	dir := seedRmDir(t)
	before := dirNames(t, dir)
	if code, _, stderr := runSnap(t, "prune", "--dir", dir); code != exitError || !strings.Contains(stderr, "needs --keep or --keep-days") {
		t.Errorf("prune without a bound: exit %d, stderr %q", code, stderr)
	}
	if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("prune without a bound changed the directory")
	}

	for _, name := range []string{rmA, rmB} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	before = dirNames(t, dir)
	if code, out, _ := runSnap(t, "prune", "--dir", dir, "--keep-days", "0"); code != exitOK || out != "" {
		t.Errorf("prune --keep-days 0 over one ok row: exit %d, stdout %q", code, out)
	}
	if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("prune removed the only ok snapshot: %v -> %v", before, after)
	}
}

func TestPruneRepointsLatestWhenItsTargetGoes(t *testing.T) {
	pinNow(t, rmNow)
	dir := seedRmDir(t)
	if err := os.Remove(filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rmA, filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runSnap(t, "prune", "--dir", dir, "--keep", "1")
	if code != exitOK || out != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if got := latestOf(t, dir); got != rmC {
		t.Errorf("latest -> %s, want c", got)
	}
	if !strings.HasSuffix(stderr, "muster: latest -> "+rmC+"\n") {
		t.Errorf("stderr = %q, want it to end with the re-point", stderr)
	}
}

// RA-7: one clock reading, after the listing. A snapshot that appears when
// the clock is read was not in the listing and is not pruned.
func TestPruneReadsTheClockOnceAfterTheListing(t *testing.T) {
	dir := seedRmDir(t)
	calls := 0
	old := now
	now = func() time.Time {
		calls++
		if calls == 1 {
			writeSnapshot(t, filepath.Join(dir, rmZ), snapBody(1, rmNow.Add(-40*24*time.Hour).Format("2006-01-02T15:04:05Z"), "web01", seedMusterV, seedControlsV))
		}
		return rmNow
	}
	t.Cleanup(func() { now = old })
	code, out, stderr := runSnap(t, "prune", "--dir", dir, "--keep-days", "7", "--dry-run")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if want := "would remove " + rmB + "\nwould remove " + rmA + "\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	if calls != 1 {
		t.Errorf("now called %d times, want 1", calls)
	}
}

func TestRmAndPruneRefuseALockedDirectory(t *testing.T) {
	dir := seedRmDir(t)
	l, err := collect.AcquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	before := dirNames(t, dir)
	for _, args := range [][]string{
		{"prune", "--dir", dir, "--keep", "1"},
		{"rm", "--dir", dir, rmA},
	} {
		if code, _, stderr := runSnap(t, args...); code != exitError || stderr != "muster: another muster holds the lock: "+dir+"\n" {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if after := dirNames(t, dir); !reflect.DeepEqual(before, after) {
		t.Errorf("a locked directory changed: %v -> %v", before, after)
	}
}

func TestPruneRefusesADirectoryRootDoesNotOwn(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown needs root; the CI root job and the lab run this as root")
	}
	dir := seedRmDir(t)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runSnap(t, "prune", "--dir", dir, "--keep", "1"); code != exitError || !strings.Contains(stderr, "not owned by uid 0") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if !exists(t, filepath.Join(dir, rmA)) {
		t.Errorf("a refused prune removed a")
	}
}

func TestPruneRefusesAGroupWritableDirectory(t *testing.T) {
	dir := seedRmDir(t)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runSnap(t, "prune", "--dir", dir, "--keep", "1"); code != exitError || !strings.Contains(stderr, "group- or world-writable") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if !exists(t, filepath.Join(dir, rmA)) {
		t.Errorf("a refused prune removed a")
	}
}
