//go:build linux

package collect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// walkTree builds the one tree every ReadDir test below lists: a directory
// "a" holding a regular file, a setuid file, a symlink to that regular
// file, a subdirectory and a fifo. It returns the tmp root and "a".
func walkTree(t *testing.T) (root, a string) {
	t.Helper()
	root = t.TempDir()
	a = filepath.Join(root, "a")
	if err := os.Mkdir(a, 0o755); err != nil {
		t.Fatal(err)
	}
	// Every mode is pinned with an explicit Chmod: os.WriteFile and os.Mkdir
	// apply the process umask to theirs, and os.WriteFile cannot set setuid
	// at all, so the bits the listing must report are set here.
	mkfile(t, filepath.Join(a, "f"), "hello\n", 0o644)
	chmod(t, filepath.Join(a, "f"), 0o644)
	mkfile(t, filepath.Join(a, "s"), "suid\n", 0o644)
	chmod(t, filepath.Join(a, "s"), 0o4755)
	if err := os.Symlink("f", filepath.Join(a, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(a, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	chmod(t, filepath.Join(a, "d"), 0o700)
	if err := syscall.Mkfifo(filepath.Join(a, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
	chmod(t, filepath.Join(a, "p"), 0o600)
	return root, a
}

// chmod sets the raw 0o7777 bits. unix.Chmod, not os.Chmod: an os.FileMode
// carries setuid/setgid/sticky in high bits of its own and silently drops a
// raw 0o4000 written into a FileMode literal, so os.Chmod(p, 0o4755) leaves
// a plain 0755 behind.
func chmod(t *testing.T, p string, mode uint32) {
	t.Helper()
	if err := unix.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func entryByName(l Listing, name string) (DirEntry, bool) {
	for _, e := range l.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return DirEntry{}, false
}

func TestReadDirListsEveryKindSorted(t *testing.T) {
	_, a := walkTree(t)
	l, err := hostAccess{}.ReadDir(a, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if l.Self.Name != "" {
		t.Errorf("Self.Name = %q, want empty", l.Self.Name)
	}
	var names []string
	for _, e := range l.Entries {
		names = append(names, e.Name)
	}
	want := []string{"d", "f", "l", "p", "s"}
	if len(names) != len(want) {
		t.Fatalf("entries = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("entries = %v, want %v (sorted, no . or ..)", names, want)
		}
	}
	kinds := map[string]string{"d": "dir", "f": "regular", "l": "symlink", "p": "fifo", "s": "regular"}
	modes := map[string]uint32{"d": 0o700, "f": 0o644, "p": 0o600, "s": 0o4755}
	for _, e := range l.Entries {
		if e.Kind != kinds[e.Name] {
			t.Errorf("%s: kind = %q, want %q", e.Name, e.Kind, kinds[e.Name])
		}
		if want, ok := modes[e.Name]; ok && e.Mode != want {
			t.Errorf("%s: mode = %#o, want %#o", e.Name, e.Mode, want)
		}
		if e.Ino == 0 {
			t.Errorf("%s: Ino = 0", e.Name)
		}
		if e.UID != uint32(os.Getuid()) || e.GID != uint32(os.Getgid()) {
			t.Errorf("%s: uid/gid = %d/%d, want %d/%d", e.Name, e.UID, e.GID, os.Getuid(), os.Getgid())
		}
	}
	if f, ok := entryByName(l, "f"); !ok || f.Size != 6 {
		t.Errorf("f: size = %d, want 6 (ok=%v)", f.Size, ok)
	}
	var st unix.Stat_t
	if err := unix.Lstat(a, &st); err != nil {
		t.Fatal(err)
	}
	if l.Self.Ino != st.Ino {
		t.Errorf("Self.Ino = %d, want %d", l.Self.Ino, st.Ino)
	}
	if l.Self.Kind != "dir" {
		t.Errorf("Self.Kind = %q, want %q", l.Self.Kind, "dir")
	}
}

func TestReadDirDoesNotFollowSymlinks(t *testing.T) {
	_, a := walkTree(t)
	l, err := hostAccess{}.ReadDir(a, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	link, ok := entryByName(l, "l")
	if !ok {
		t.Fatal("no entry for the symlink")
	}
	target, ok := entryByName(l, "f")
	if !ok {
		t.Fatal("no entry for the link's target")
	}
	if link.Kind != "symlink" {
		t.Errorf("l: kind = %q, want %q", link.Kind, "symlink")
	}
	if link.Ino == target.Ino {
		t.Errorf("l stat'd the target (ino %d) rather than the link itself", link.Ino)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(a, "l"), &st); err != nil {
		t.Fatal(err)
	}
	if link.Ino != st.Ino {
		t.Errorf("l: ino = %d, want the link's own %d", link.Ino, st.Ino)
	}
}

func TestReadDirRefusesASymlinkedPath(t *testing.T) {
	root, a := walkTree(t)
	link := filepath.Join(root, "link-to-dir")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if l, err := (hostAccess{}).ReadDir(link, Identity{}); !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink (listing %+v)", err, l)
	} else if len(l.Entries) != 0 {
		t.Errorf("a refused listing must be empty, got %+v", l.Entries)
	}
	// An intermediate symlink is refused the same way.
	if _, err := (hostAccess{}).ReadDir(filepath.Join(link, "d"), Identity{}); !errors.Is(err, ErrSymlink) {
		t.Errorf("intermediate symlink: err = %v, want ErrSymlink", err)
	}
}

func TestReadDirIdentityMismatchIsVanished(t *testing.T) {
	_, a := walkTree(t)
	other := filepath.Join(a, "d")
	l, err := hostAccess{}.ReadDir(other, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	expect := Identity{Dev: l.Self.Dev, Ino: l.Self.Ino}
	got, err := hostAccess{}.ReadDir(a, expect)
	if !errors.Is(err, ErrVanished) {
		t.Fatalf("err = %v, want ErrVanished", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("a vanished listing must be empty, got %+v", got.Entries)
	}
	// The matching identity is accepted, so the check is not simply always
	// failing on a non-zero expect.
	self, err := hostAccess{}.ReadDir(a, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (hostAccess{}).ReadDir(a, Identity{Dev: self.Self.Dev, Ino: self.Self.Ino}); err != nil {
		t.Errorf("matching identity: err = %v", err)
	}
}

func TestReadDirCarriesTheMountID(t *testing.T) {
	_, a := walkTree(t)
	l, err := hostAccess{}.ReadDir(a, Identity{})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Self.MntIDKnown {
		t.Fatalf("Self.MntIDKnown false: STATX_MNT_ID needs Linux >= 5.8, which the lab host and CI have")
	}
	if l.Self.MntID == 0 {
		t.Errorf("Self.MntID = 0 while MntIDKnown")
	}
	for _, e := range l.Entries {
		if !e.MntIDKnown {
			t.Errorf("%s: MntIDKnown false", e.Name)
			continue
		}
		if e.MntID != l.Self.MntID {
			t.Errorf("%s: MntID = %d, want the directory's %d (same mount)", e.Name, e.MntID, l.Self.MntID)
		}
		if e.Dev != l.Self.Dev {
			t.Errorf("%s: Dev = %d, want %d", e.Name, e.Dev, l.Self.Dev)
		}
	}
}

func TestReadlinkReadsOnlyTheFinalLink(t *testing.T) {
	root, a := walkTree(t)
	got, err := hostAccess{}.Readlink(filepath.Join(a, "l"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "f" {
		t.Errorf("Readlink = %q, want %q", got, "f")
	}
	if _, err := (hostAccess{}).Readlink(filepath.Join(a, "f")); !errors.Is(err, unix.EINVAL) {
		t.Errorf("Readlink of a regular file: err = %v, want EINVAL", err)
	}
	link := filepath.Join(root, "link-to-dir")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (hostAccess{}).Readlink(filepath.Join(link, "l")); !errors.Is(err, ErrSymlink) {
		t.Errorf("Readlink through a symlinked parent: err = %v, want ErrSymlink", err)
	}
	if _, err := (hostAccess{}).Readlink("a/relative/path"); err == nil {
		t.Error("a relative path must be refused")
	}
}

// A directory with no permission bits at all: root lists it (DAC_OVERRIDE /
// DAC_READ_SEARCH), anyone else is denied — and the denial is an ordinary
// permission error, so a caller classifies it with DeniedReason like any
// other refused read rather than learning a new error shape. Both halves are
// asserted; which one runs is decided by the uid the suite happens to have
// (root on the lab host, an unprivileged user on the CI runner).
func TestReadDirOnAnUnreadableDirectory(t *testing.T) {
	_, a := walkTree(t)
	shut := filepath.Join(a, "d")
	chmod(t, shut, 0o000)
	l, err := hostAccess{}.ReadDir(shut, Identity{})
	if os.Getuid() == 0 {
		if err != nil {
			t.Fatalf("root must be able to list a 0o000 directory: %v", err)
		}
		if l.Self.Mode != 0 {
			t.Errorf("Self.Mode = %#o, want 0", l.Self.Mode)
		}
		return
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want a permission error", err)
	}
	if _, ok := DeniedReason(err); !ok {
		t.Errorf("DeniedReason did not recognise %v", err)
	}
	if len(l.Entries) != 0 {
		t.Errorf("a denied listing must be empty, got %+v", l.Entries)
	}
}
