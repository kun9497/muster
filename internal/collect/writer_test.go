//go:build linux

package collect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSnapshotNameIsSanitisedAndStable(t *testing.T) {
	n := SnapshotName("web 01/prod", "2026-09-02T06:00:00Z", "sha256:0123456789abcdef0123")
	if n != "web_01_prod-2026-09-02T060000Z-0123456789ab.json" {
		t.Fatalf("%q", n)
	}
}

func TestWriteSnapshotCreatesDirAtomicallyWithLatest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots")
	p, err := WriteSnapshot([]byte(`{"a":1}`), WriteOptions{Dir: dir, Hostname: "host1", CollectedAt: "2026-09-02T06:00:00Z"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", dst.Mode().Perm())
	}
	if target, err := os.Readlink(filepath.Join(dir, "latest")); err != nil || target != filepath.Base(p) {
		t.Errorf("latest → %q err=%v", target, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestWriteSnapshotGeneratedNameUsesSuppliedHostnameAndTime is R54's check
// that WriteSnapshot never reads os.Hostname() or time.Now() itself: with
// Out empty, the generated file name must be built purely from
// WriteOptions.Hostname/CollectedAt (and the digest of data), so passing
// values that can never match the real host/clock still produces the exact
// expected name.
func TestWriteSnapshotGeneratedNameUsesSuppliedHostnameAndTime(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"a":1}`)
	p, err := WriteSnapshot(data, WriteOptions{Dir: dir, Hostname: "not-a-real-host", CollectedAt: "1999-01-01T00:00:00Z"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, SnapshotName("not-a-real-host", "1999-01-01T00:00:00Z", digestOf(data)))
	if p != want {
		t.Errorf("path = %q, want %q", p, want)
	}
}

// TestWriteSnapshotReportsFailedLatestUpdateWithoutLosingSnapshot is
// fix-round-1 item 1 (R74): when updating the `latest` convenience symlink
// fails, WriteSnapshot must still return the path of the (successfully
// written) snapshot, wrap the failure as ErrLatestNotUpdated, and not leave
// its own temp link behind. Pre-creating "latest" as a non-empty directory
// makes the final os.Rename(latestTmp, ".../latest") fail (a symlink can't
// be renamed onto an existing directory) without touching the snapshot
// write path at all.
func TestWriteSnapshotReportsFailedLatestUpdateWithoutLosingSnapshot(t *testing.T) {
	dir := t.TempDir()
	latest := filepath.Join(dir, "latest")
	if err := os.Mkdir(latest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(latest, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := WriteSnapshot([]byte(`{"a":1}`), WriteOptions{Dir: dir, Hostname: "h", CollectedAt: "2026-09-02T06:00:00Z"}, nil)
	if !errors.Is(err, ErrLatestNotUpdated) {
		t.Fatalf("err = %v, want ErrLatestNotUpdated", err)
	}
	if p == "" {
		t.Fatal("path is empty, want the written snapshot's path")
	}
	if _, statErr := os.Stat(p); statErr != nil {
		t.Errorf("snapshot not present at returned path %q: %v", p, statErr)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".latest.tmp-") {
			t.Errorf("temp latest link left behind: %s", e.Name())
		}
	}
}

// TestWriteSnapshotFailsClosedWhenStatfsErrors is fix-round-1 item 2: a
// Statfs failure must fail closed (WriteSnapshot returns the error) rather
// than silently skip the free-space check.
func TestWriteSnapshotFailsClosedWhenStatfsErrors(t *testing.T) {
	orig := statfs
	boom := errors.New("statfs boom")
	statfs = func(path string, buf *unix.Statfs_t) error { return boom }
	t.Cleanup(func() { statfs = orig })

	dir := t.TempDir()
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Dir: dir, Hostname: "h", CollectedAt: "2026-09-02T06:00:00Z"}, nil); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

func TestWriteSnapshotRefusesExistingWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "s.json")
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: out}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: out}, nil); !errors.Is(err, ErrExists) {
		t.Errorf("err=%v", err)
	}
	if _, err := WriteSnapshot([]byte(`{"v":2}`), WriteOptions{Out: out, Force: true}, nil); err != nil {
		t.Errorf("force: %v", err)
	}
}

func TestWriteSnapshotRefusesWorldWritableOrSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	ww := filepath.Join(base, "ww")
	os.Mkdir(ww, 0o777)
	os.Chmod(ww, 0o777)
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: filepath.Join(ww, "s.json")}, nil); !errors.Is(err, ErrUntrustedDir) {
		t.Errorf("world-writable: err=%v", err)
	}
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	os.Symlink(real, link)
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: filepath.Join(link, "s.json")}, nil); !errors.Is(err, ErrUntrustedDir) {
		t.Errorf("symlinked parent: err=%v", err)
	}
}

func TestWriteSnapshotToStdout(t *testing.T) {
	var buf bytes.Buffer
	p, err := WriteSnapshot([]byte("{}\n"), WriteOptions{Out: "-"}, &buf)
	if err != nil || p != "-" || buf.String() != "{}\n" {
		t.Errorf("%q %v %q", p, err, buf.String())
	}
}

func TestLockIsExclusiveAndNamesTheHolder(t *testing.T) {
	lp := filepath.Join(t.TempDir(), "d", ".lock")
	l1, err := AcquireLock(lp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(lp); !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), "pid") {
		t.Errorf("second lock: err=%v", err)
	}
	l1.Release()
	if l2, err := AcquireLock(lp); err != nil {
		t.Errorf("after release: %v", err)
	} else {
		l2.Release()
	}
}

// TestAcquireDirLock is R73's requirement: two AcquireDirLock calls on the
// same directory conflict, and Release frees it for the next caller — the
// same contract AcquireLock gives for a lock file, but taken on the
// directory's own inode instead of a file inside it.
func TestAcquireDirLock(t *testing.T) {
	dir := t.TempDir()
	l1, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireDirLock(dir); !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), dir) {
		t.Errorf("second dir lock: err=%v", err)
	}
	l1.Release()
	if l2, err := AcquireDirLock(dir); err != nil {
		t.Errorf("after release: %v", err)
	} else {
		l2.Release()
	}
}

// TestFinalizeRenameFallsBackWhenRenameNoReplaceUnsupported is fix-round-1
// item 3: when renameNoReplace reports EINVAL (as a filesystem or kernel
// without RENAME_NOREPLACE support would), finalizeRename must fall back to
// Lstat-then-Rename — writing when the destination is absent, and returning
// ErrExists without touching the destination when it's already there.
func TestFinalizeRenameFallsBackWhenRenameNoReplaceUnsupported(t *testing.T) {
	orig := renameNoReplace
	renameNoReplace = func(tmp, dst string) error { return unix.EINVAL }
	t.Cleanup(func() { renameNoReplace = orig })

	t.Run("writes when destination absent", func(t *testing.T) {
		dir := t.TempDir()
		tmp := filepath.Join(dir, ".s.json.tmp-1")
		if err := os.WriteFile(tmp, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		final := filepath.Join(dir, "s.json")
		if err := finalizeRename(tmp, final, false); err != nil {
			t.Fatalf("finalizeRename: %v", err)
		}
		got, err := os.ReadFile(final)
		if err != nil || string(got) != "data" {
			t.Errorf("final content = %q, err=%v", got, err)
		}
		if _, err := os.Lstat(tmp); !os.IsNotExist(err) {
			t.Errorf("tmp still present after successful rename: err=%v", err)
		}
	})

	t.Run("ErrExists when destination present", func(t *testing.T) {
		dir := t.TempDir()
		tmp := filepath.Join(dir, ".s.json.tmp-2")
		if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		final := filepath.Join(dir, "s.json")
		if err := os.WriteFile(final, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := finalizeRename(tmp, final, false); !errors.Is(err, ErrExists) {
			t.Errorf("err = %v, want ErrExists", err)
		}
		got, err := os.ReadFile(final)
		if err != nil || string(got) != "old" {
			t.Errorf("final was overwritten: %q err=%v", got, err)
		}
	})
}

// TestWriteSnapshotRefusesASymlinkedOutputPath is I2 (R83). Spec §7.1
// refuses an output path that is a symbolic link and writes nothing — and
// says so with no exception for --force, which only licenses replacing a
// snapshot muster itself wrote. Without the check the rename swaps the link
// for the new file and leaves the operator's intended target untouched.
func TestWriteSnapshotRefusesASymlinkedOutputPath(t *testing.T) {
	for _, force := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, "s.json")
		if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := WriteSnapshot([]byte(`{"a":1}`), WriteOptions{Out: link, Force: force}, nil); !errors.Is(err, ErrOutputSymlink) {
			t.Errorf("force=%v: err = %v, want ErrOutputSymlink", force, err)
		}
		if got, _ := os.ReadFile(target); string(got) != "original" {
			t.Errorf("force=%v: the link's target was written: %q", force, got)
		}
		fi, err := os.Lstat(link)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("force=%v: the output path is no longer a symbolic link: %v %v", force, fi, err)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 2 {
			t.Errorf("force=%v: %d entries, want only the target and the link", force, len(entries))
		}
	}
}

// TestLockHolderTextIsStrippedToPrintableASCII is M9. The holder line comes
// out of a file some other process wrote, and the message it lands in goes
// to a terminal, so everything outside printable ASCII is stripped first.
func TestLockHolderTextIsStrippedToPrintableASCII(t *testing.T) {
	lp := filepath.Join(t.TempDir(), "d", ".lock")
	l1, err := AcquireLock(lp)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()
	// flock is advisory: holding it does not stop another writer from
	// putting whatever it likes in the file the holder text is read from.
	if err := os.WriteFile(lp, []byte("31337 \x1b[31m\x00\x07evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = AcquireLock(lp)
	switch {
	case !errors.Is(err, ErrLocked):
		t.Fatalf("err = %v, want ErrLocked", err)
	case strings.ContainsAny(err.Error(), "\x00\x07\x1b"):
		t.Errorf("holder text keeps control bytes: %q", err.Error())
	case !strings.Contains(err.Error(), "31337"):
		t.Errorf("holder text lost its printable part: %q", err.Error())
	}
}

// TestAcquireLockRefusesAnUntrustedDirectory is M9's second half: the lock
// file's parent is held to the same rule as the snapshot directory, so a
// world-writable one is refused rather than locked.
func TestAcquireLockRefusesAnUntrustedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ww")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(filepath.Join(dir, ".lock")); !errors.Is(err, ErrUntrustedDir) {
		t.Errorf("err = %v, want ErrUntrustedDir", err)
	}
}

// TestSnapshotNameCapsTheHostname is M11: the hostname is read off the host
// and lands in a file name, so its sanitised form is capped.
func TestSnapshotNameCapsTheHostname(t *testing.T) {
	n := SnapshotName(strings.Repeat("h", 200), "2026-09-02T06:00:00Z", "sha256:0123456789abcdef")
	host, _, _ := strings.Cut(n, "-")
	if len(host) != 64 {
		t.Errorf("host part is %d bytes, want 64: %q", len(host), n)
	}
}
