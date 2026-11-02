//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/snapshots"
)

// snapBody is the smallest snapshot the header reader accepts.
func snapBody(schema int, collectedAt, host, musterVersion, controlsVersion string) string {
	return fmt.Sprintf(`{"schema_version":%d,"run":{"muster_version":%q,"controls_version":%q,"collected_at":%q,"host":{"hostname":%q}},"facts":{}}`,
		schema, musterVersion, controlsVersion, collectedAt, host)
}

// Names of the seeded directory, in the writer's pattern.
const (
	seedOKNew      = "web01-2026-09-02T060000Z-0123456789ab.json"
	seedOKOld      = "db02-2026-09-01T060000Z-aaaaaaaaaaaa.json"
	seedNewer      = "web01-2026-09-03T060000Z-bbbbbbbbbbbb.json"
	seedBrace      = "web01-2026-08-30T060000Z-cccccccccccc.json"
	seedEmpty      = "web01-2026-08-31T060000Z-dddddddddddd.json"
	seedControlsV  = "2026.09.09"
	seedMusterV    = "0.0.1"
	seedMusterNext = "9.9.9"
)

// seedSnapshotDir builds a 0700 directory holding two ok snapshots, a newer
// one, two unreadable pattern-matching files, three other names and a latest
// link to the newest ok one.
func seedSnapshotDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, filepath.Join(dir, seedOKNew), snapBody(1, "2026-09-02T06:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, seedOKOld), snapBody(1, "2026-09-01T06:00:00Z", "db02", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, seedNewer), snapBody(99, "2026-09-03T06:00:00Z", "web01", seedMusterNext, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, seedBrace), "{")
	writeSnapshot(t, filepath.Join(dir, seedEmpty), "")
	writeSnapshot(t, filepath.Join(dir, ".x.tmp-1"), "{}")
	writeSnapshot(t, filepath.Join(dir, "notes.txt"), "notes")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(seedOKNew, filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openTestDir(t *testing.T, dir string) *snapshotDir {
	t.Helper()
	d, err := openSnapshotDir(dir)
	if err != nil {
		t.Fatalf("openSnapshotDir(%s): %v", dir, err)
	}
	t.Cleanup(d.close)
	return d
}

// RL-18: the directory is opened without following a symlink, and one that
// is group- or world-writable is refused.
func TestOpenSnapshotDirRefusesSymlinkAndWritable(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := openSnapshotDir(real)
	if err != nil {
		t.Fatalf("a plain 0700 directory: %v", err)
	}
	d.close()

	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openSnapshotDir(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("a symlink to a directory: err = %v, want it to mention symlink", err)
	}

	if err := os.Chmod(real, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := openSnapshotDir(real); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("a 0770 directory: err = %v, want group- or world-writable", err)
	}
}

// RL-16, RA-6: pattern-matching regular files are rows of three classes,
// every other name but the latest link is counted and never opened.
func TestListClassifiesAndCountsOthers(t *testing.T) {
	d := openTestDir(t, seedSnapshotDir(t))
	entries, other, latest, err := d.list()
	if err != nil {
		t.Fatal(err)
	}
	snapshots.Sort(entries)
	type row struct {
		name  string
		class snapshots.Class
	}
	var got []row
	for _, e := range entries {
		got = append(got, row{e.Name, e.Class})
	}
	want := []row{
		{seedNewer, snapshots.ClassNewer},
		{seedOKNew, snapshots.ClassOK},
		{seedOKOld, snapshots.ClassOK},
		{seedEmpty, snapshots.ClassUnreadable},
		{seedBrace, snapshots.ClassUnreadable},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries = %v\nwant      %v", got, want)
	}
	if other != 3 {
		t.Errorf("other = %d, want 3 (.x.tmp-1, notes.txt, sub)", other)
	}
	if want := (latestLink{present: true, target: seedOKNew, state: "ok"}); latest != want {
		t.Errorf("latest = %+v, want %+v", latest, want)
	}
	if entries[1].Hostname != "web01" || entries[1].CollectedAt != "2026-09-02T06:00:00Z" || entries[1].ControlsVersion != seedControlsV || entries[1].Size == 0 {
		t.Errorf("ok row lost its header: %+v", entries[1])
	}
	if entries[0].MusterVersion != seedMusterNext {
		t.Errorf("newer row lost its header: %+v", entries[0])
	}
}

// Review Focus 2: a latest that names no entry, or a path outside the
// directory, is reported verbatim and never followed.
func TestListLatestDanglingAndOutside(t *testing.T) {
	for _, tc := range []struct{ target, state string }{
		{"gone.json", "dangling"},
		{"../x/y.json", "outside"},
	} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeSnapshot(t, filepath.Join(dir, seedOKNew), snapBody(1, "2026-09-02T06:00:00Z", "web01", seedMusterV, seedControlsV))
		if err := os.Symlink(tc.target, filepath.Join(dir, "latest")); err != nil {
			t.Fatal(err)
		}
		d := openTestDir(t, dir)
		entries, other, latest, err := d.list()
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if len(entries) != 1 || other != 0 {
			t.Errorf("%s: %d entries, %d other; want 1, 0", tc.target, len(entries), other)
		}
		if want := (latestLink{present: true, target: tc.target, state: tc.state}); latest != want {
			t.Errorf("latest = %+v, want %+v", latest, want)
		}
	}
}

// RA-6: a latest that is not a symlink is an other file, not a link.
func TestListCountsARegularLatest(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, filepath.Join(dir, seedOKNew), snapBody(1, "2026-09-02T06:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, "latest"), seedOKNew)
	entries, other, latest, err := openTestDir(t, dir).list()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || other != 1 || latest != (latestLink{}) {
		t.Errorf("%d entries, other %d, latest %+v; want 1, 1, not present", len(entries), other, latest)
	}
}

// The file opened must be the one the listing stat-ed: another inode, or a
// symlink in its place (ELOOP under O_NOFOLLOW), is an other file, never a
// row.
func TestReadEntryRefusesSwappedAndLinkedEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSnapshot(t, filepath.Join(dir, seedOKNew), snapBody(1, "2026-09-02T06:00:00Z", "web01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, seedOKOld), snapBody(1, "2026-09-01T06:00:00Z", "db02", seedMusterV, seedControlsV))
	if err := os.Symlink(seedOKNew, filepath.Join(dir, seedEmpty)); err != nil {
		t.Fatal(err)
	}
	d := openTestDir(t, dir)
	var stA unix.Stat_t
	if err := unix.Fstatat(d.fd, seedOKNew, &stA, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if _, out, err := d.readEntry(seedOKNew, stA); err != nil || out != entryRow {
		t.Fatalf("the stat-ed file itself: outcome %d, err %v; want a row", out, err)
	}
	if _, out, err := d.readEntry(seedOKOld, stA); err != nil || out != entryOther {
		t.Errorf("another inode: outcome %d, err %v; want other", out, err)
	}
	if _, out, err := d.readEntry(seedEmpty, stA); err != nil || out != entryOther {
		t.Errorf("a symlink in the entry's place: outcome %d, err %v; want other", out, err)
	}
}

// remove unlinks a regular file through the directory fd and refuses
// anything else, which stays where it is.
func TestRemoveUnlinksOnlyRegularFiles(t *testing.T) {
	dir := seedSnapshotDir(t)
	d := openTestDir(t, dir)
	if err := d.remove(seedOKOld); err != nil {
		t.Fatalf("remove a regular file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, seedOKOld)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s still there after remove: %v", seedOKOld, err)
	}
	for _, name := range []string{"sub", "latest"} {
		if err := d.remove(name); !errors.Is(err, errNotRegular) {
			t.Errorf("remove(%s): err = %v, want errNotRegular", name, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s gone after a refused remove: %v", name, err)
		}
	}
}

// latest is written as a relative bare name through a temporary link and a
// rename; an empty target removes a link and leaves a regular latest alone.
func TestRepointLatestWritesARelativeLinkAtomically(t *testing.T) {
	dir := seedSnapshotDir(t)
	d := openTestDir(t, dir)
	if err := d.repointLatest("b.json"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.Readlink(filepath.Join(dir, "latest")); err != nil || got != "b.json" {
		t.Errorf("latest -> %q (%v), want b.json", got, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".latest.tmp-*")); len(left) != 0 {
		t.Errorf("temporary links left: %v", left)
	}
	if err := d.repointLatest(""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "latest")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("latest link still there after repointLatest(\"\"): %v", err)
	}
	writeSnapshot(t, filepath.Join(dir, "latest"), "not a link")
	if err := d.repointLatest(""); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(filepath.Join(dir, "latest")); err != nil || string(body) != "not a link" {
		t.Errorf("a regular latest changed: %q, %v", body, err)
	}
	// A non-empty target is refused over a regular latest, never renamed over it.
	if err := d.repointLatest("b.json"); err == nil || !strings.Contains(err.Error(), "is not a symlink, left as is") {
		t.Errorf("repointLatest over a regular latest: err = %v, want a refusal", err)
	}
	fi, err := os.Lstat(filepath.Join(dir, "latest"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Errorf("latest after the refusal: %v, %v; want a regular file", fi, err)
	}
	if body, err := os.ReadFile(filepath.Join(dir, "latest")); err != nil || string(body) != "not a link" {
		t.Errorf("a regular latest changed by the refusal: %q, %v", body, err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".latest.tmp-*")); len(left) != 0 {
		t.Errorf("temporary links left after the refusal: %v", left)
	}
}

// A second lock on the same directory is refused while the first is held.
func TestLockRefusesASecondHolder(t *testing.T) {
	d := openTestDir(t, seedSnapshotDir(t))
	l, err := d.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if l2, err := d.lock(); !errors.Is(err, collect.ErrLocked) {
		if l2 != nil {
			l2.Release()
		}
		t.Fatalf("second lock: err = %v, want collect.ErrLocked", err)
	}
}
