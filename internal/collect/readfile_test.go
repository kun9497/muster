//go:build linux

package collect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func mkfile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func timeAfter(sec int) <-chan time.Time { return time.After(time.Duration(sec) * time.Second) }

func TestReadFileHappyPathRecordsMeta(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	mkfile(t, p, "PermitRootLogin no\n", 0o600)
	data, meta, err := ReadFile(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PermitRootLogin no\n" || meta.Truncated || meta.Binary || meta.Size != 19 {
		t.Errorf("%q %+v", data, meta)
	}
	if meta.Tier != "openat2" && meta.Tier != "componentwise" {
		t.Errorf("tier %q", meta.Tier)
	}
}

func TestReadFileRefusesSymlinkInAnyComponent(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "shadow")
	mkfile(t, secret, "root:$6$notreally$hash::0:99999:7:::\n", 0o600)
	// final component is a link
	link := filepath.Join(dir, "passwd")
	os.Symlink(secret, link)
	if _, _, err := ReadFile(link, 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("final-component symlink: err=%v", err)
	}
	// intermediate component is a link
	realDir := filepath.Join(dir, "real")
	os.Mkdir(realDir, 0o755)
	mkfile(t, filepath.Join(realDir, "f"), "x", 0o644)
	os.Symlink(realDir, filepath.Join(dir, "linkdir"))
	if _, _, err := ReadFile(filepath.Join(dir, "linkdir", "f"), 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("intermediate symlink: err=%v", err)
	}
	// symlink loop
	os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a"))
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	if _, _, err := ReadFile(filepath.Join(dir, "a"), 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("loop: err=%v", err)
	}
}

func TestReadFileRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := ReadFile(fifo, 1<<20); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("err=%v want ErrNotRegular", err)
		}
	case <-timeAfter(2):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

func TestReadFileTruncatesAndFlagsBinary(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	mkfile(t, big, strings.Repeat("a", 1000), 0o644)
	data, meta, err := ReadFile(big, 100)
	if err != nil || len(data) != 100 || !meta.Truncated {
		t.Errorf("len=%d meta=%+v err=%v", len(data), meta, err)
	}
	bin := filepath.Join(dir, "bin")
	mkfile(t, bin, "abc\x00def", 0o644)
	data, meta, err = ReadFile(bin, 100)
	if err != nil || len(data) != 0 || !meta.Binary {
		t.Errorf("binary: len=%d meta=%+v err=%v", len(data), meta, err)
	}
}

func TestReadFileNamesWithNewlines(t *testing.T) {
	dir := t.TempDir()
	odd := filepath.Join(dir, "weird\nname")
	mkfile(t, odd, "ok", 0o644)
	if data, _, err := ReadFile(odd, 10); err != nil || string(data) != "ok" {
		t.Errorf("%q %v", data, err)
	}
}

func TestReadFileRequiresAbsolutePath(t *testing.T) {
	if _, _, err := ReadFile("etc/passwd", 10); err == nil {
		t.Error("relative path must be refused")
	}
}

func TestStatReportsSymlinkAndParentTrust(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	p := filepath.Join(dir, "f")
	mkfile(t, p, "x", 0o644)
	meta, err := Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.ParentUntrusted {
		t.Error("world-writable parent must set ParentUntrusted")
	}
	os.Symlink(p, filepath.Join(dir, "l"))
	if _, err := Stat(filepath.Join(dir, "l")); !errors.Is(err, ErrSymlink) {
		t.Errorf("err=%v", err)
	}
}

// TestReadFileComponentwiseGivesSameGuarantees is R49: tier 2 must give the
// same no-symlink guarantee as tier 1. Force the component-wise walk (skip
// openat2) and rerun the symlink cases plus the happy path, asserting the
// tier actually used was componentwise.
func TestReadFileComponentwiseGivesSameGuarantees(t *testing.T) {
	old := forceComponentwise
	forceComponentwise = true
	defer func() { forceComponentwise = old }()

	dir := t.TempDir()

	p := filepath.Join(dir, "sshd_config")
	mkfile(t, p, "PermitRootLogin no\n", 0o600)
	data, meta, err := ReadFile(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PermitRootLogin no\n" || meta.Truncated || meta.Binary || meta.Size != 19 {
		t.Errorf("happy path: %q %+v", data, meta)
	}
	if meta.Tier != "componentwise" {
		t.Errorf("happy path tier %q, want componentwise", meta.Tier)
	}

	secret := filepath.Join(dir, "shadow")
	mkfile(t, secret, "root:$6$notreally$hash::0:99999:7:::\n", 0o600)
	link := filepath.Join(dir, "passwd")
	os.Symlink(secret, link)
	if _, meta, err := ReadFile(link, 1<<20); !errors.Is(err, ErrSymlink) || meta.Tier != "componentwise" {
		t.Errorf("final-component symlink: err=%v tier=%q", err, meta.Tier)
	}

	realDir := filepath.Join(dir, "real")
	os.Mkdir(realDir, 0o755)
	mkfile(t, filepath.Join(realDir, "f"), "x", 0o644)
	os.Symlink(realDir, filepath.Join(dir, "linkdir"))
	if _, meta, err := ReadFile(filepath.Join(dir, "linkdir", "f"), 1<<20); !errors.Is(err, ErrSymlink) || meta.Tier != "componentwise" {
		t.Errorf("intermediate symlink: err=%v tier=%q", err, meta.Tier)
	}

	os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a"))
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	if _, meta, err := ReadFile(filepath.Join(dir, "a"), 1<<20); !errors.Is(err, ErrSymlink) || meta.Tier != "componentwise" {
		t.Errorf("loop: err=%v tier=%q", err, meta.Tier)
	}
}

// TestParentUntrustedFalseForRootOwnedNonWritableParent is R68: a root-owned,
// non-group/world-writable parent must report ParentUntrusted=false for both
// Stat and ReadFile, once the parent is resolved through the no-follow
// primitive instead of a second, racy unix.Lstat. The world-writable ->
// true case is already covered by TestStatReportsSymlinkAndParentTrust.
func TestParentUntrustedFalseForRootOwnedNonWritableParent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to guarantee a root-owned parent; the lab host runs as root")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "f")
	mkfile(t, p, "x", 0o644)

	meta, err := Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ParentUntrusted {
		t.Error("Stat: root-owned 0755 parent must not be untrusted")
	}

	_, rmeta, err := ReadFile(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rmeta.ParentUntrusted {
		t.Error("ReadFile: root-owned 0755 parent must not be untrusted")
	}
}

// TestReadFileRecordsRawModeBits is R69: ReadMeta.Mode carries the raw POSIX
// bits including setuid/setgid/sticky, which os.FileMode cannot represent.
// The chmod below goes through unix.Chmod, not os.Chmod: os.Chmod interprets
// its argument as an os.FileMode, whose special bits (os.ModeSetuid = 1<<23,
// ...) live at entirely different positions than the raw 0o4000/0o2000/
// 0o1000 — os.Chmod(p, 0o4755) would silently keep only Perm() (0o755) and
// drop the setuid request.
func TestReadFileRecordsRawModeBits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "setuid")
	mkfile(t, p, "x", 0o755)
	if err := unix.Chmod(p, 0o4755); err != nil {
		t.Fatal(err)
	}
	_, meta, err := ReadFile(p, 10)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Mode != 0o4755 {
		t.Errorf("meta.Mode = %o, want 4755", meta.Mode)
	}
}

func TestReadFileRejectsNegativeLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	mkfile(t, p, "x", 0o644)
	if _, _, err := ReadFile(p, -1); err == nil {
		t.Error("negative limit must be refused")
	}
}

// TestReadFileRootPathIsNotRegular covers "/" under tier 1 (openat2).
func TestReadFileRootPathIsNotRegular(t *testing.T) {
	if _, _, err := ReadFile("/", 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("err=%v want ErrNotRegular", err)
	}
}

// TestReadFileRootPathIsNotRegularComponentwise is item 4: tier 2's normal
// component split turns "/" into a single empty component, which openat
// rejects with ENOENT rather than the ErrNotRegular tier 1 gives; "/" is
// special-cased so both tiers agree.
func TestReadFileRootPathIsNotRegularComponentwise(t *testing.T) {
	old := forceComponentwise
	forceComponentwise = true
	defer func() { forceComponentwise = old }()
	if _, meta, err := ReadFile("/", 10); !errors.Is(err, ErrNotRegular) || meta.Tier != "componentwise" {
		t.Errorf("err=%v tier=%q want ErrNotRegular/componentwise", err, meta.Tier)
	}
}

func TestDeniedReasonClassifiesPermissionErrors(t *testing.T) {
	if _, ok := DeniedReason(fmt.Errorf("wrap: %w", unix.EACCES)); !ok {
		t.Error("wrapped EACCES must be denied")
	}
	if _, ok := DeniedReason(os.ErrPermission); !ok {
		t.Error("os.ErrPermission must be denied")
	}
	if _, ok := DeniedReason(errors.New("boom")); ok {
		t.Error("unrelated error must not be denied")
	}
}

func TestReadFileRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := ReadFile(dir, 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("err=%v want ErrNotRegular", err)
	}
}

func TestReadFileRejectsDotDotAndTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	mkfile(t, p, "x", 0o644)
	if _, _, err := ReadFile(dir+"/sub/../f", 10); err == nil {
		t.Error("path with .. must be refused")
	}
	if _, _, err := ReadFile(dir+"/", 10); err == nil {
		t.Error("trailing slash must be refused")
	}
}

// TestReadFileTruncatedSizeIsFullFileSize: Size comes from fstat before the
// read and must reflect the whole file, not the (possibly truncated) number
// of bytes ReadFile actually returns.
func TestReadFileTruncatedSizeIsFullFileSize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big")
	mkfile(t, p, strings.Repeat("a", 1000), 0o644)
	data, meta, err := ReadFile(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 100 || !meta.Truncated {
		t.Fatalf("len=%d meta=%+v", len(data), meta)
	}
	if meta.Size != 1000 {
		t.Errorf("meta.Size = %d, want 1000 (full file size, not the truncated read length)", meta.Size)
	}
}
