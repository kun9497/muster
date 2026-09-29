//go:build linux

package collectors

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// aclBlob builds a system.posix_acl_access value: version 2 header, then
// 8-byte entries {tag uint16, perm uint16, id uint32}, little-endian.
func aclBlob(entries ...[3]uint32) []byte {
	b := make([]byte, 4, 4+8*len(entries))
	binary.LittleEndian.PutUint32(b, 2)
	for _, e := range entries {
		var rec [8]byte
		binary.LittleEndian.PutUint16(rec[0:], uint16(e[0]))
		binary.LittleEndian.PutUint16(rec[2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(rec[4:], e[2])
		b = append(b, rec[:]...)
	}
	return b
}

const undefinedID = 0xFFFFFFFF

func fiveEntryACL() []byte {
	return aclBlob(
		[3]uint32{0x01, 6, undefinedID}, // user::rw-
		[3]uint32{0x02, 6, 1000},        // user:1000:rw-
		[3]uint32{0x04, 4, undefinedID}, // group::r--
		[3]uint32{0x10, 6, undefinedID}, // mask::rw-
		[3]uint32{0x20, 4, undefinedID}, // other::r--
	)
}

func TestDecodeACLRendersEveryTag(t *testing.T) {
	blob := aclBlob(
		[3]uint32{0x01, 6, undefinedID},
		[3]uint32{0x02, 6, 1000},
		[3]uint32{0x04, 4, undefinedID},
		[3]uint32{0x08, 5, 27},
		[3]uint32{0x10, 6, undefinedID},
		[3]uint32{0x20, 4, undefinedID},
	)
	got, err := decodeACL(blob)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user::rw-", "user:1000:rw-", "group::r--", "group:27:r-x", "mask::rw-", "other::r--"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDecodeACLRejectsGarbage(t *testing.T) {
	for name, blob := range map[string][]byte{
		"short":       {1, 2, 3},
		"bad version": append([]byte{9, 0, 0, 0}, aclBlob([3]uint32{0x01, 6, undefinedID})[4:]...),
		"ragged":      append(aclBlob([3]uint32{0x01, 6, undefinedID}), 1, 2, 3),
		"unknown tag": aclBlob([3]uint32{0x40, 6, undefinedID}),
	} {
		if _, err := decodeACL(blob); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestACLEntriesOnTheRealHost sets an ACL through the raw xattr on a file
// in t.TempDir() and reads it back through the production Access, so
// Getxattr is exercised end to end under the guard.
func TestACLEntriesOnTheRealHost(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/f"
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(p, "system.posix_acl_access", fiveEntryACL(), 0); err != nil {
		t.Skipf("filesystem without ACL xattr support: %v", err)
	}
	c := collect.Collector{Name: "t", Declare: collect.Declaration{Reads: []string{p}, Needs: "none"}, Run: func(context.Context, collect.Access, *collect.Builder) error { return nil }}
	g := collect.Guard(collect.Host(), c)
	entries, present, err := aclEntries(g, p)
	if err != nil || !present {
		t.Fatalf("entries=%v present=%v err=%v", entries, present, err)
	}
	if len(entries) != 5 || entries[1] != "user:1000:rw-" {
		t.Errorf("entries = %v", entries)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Errorf("declared read must not be a violation: %v", v)
	}
	plain := dir + "/plain"
	if err := os.WriteFile(plain, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := collect.Collector{Name: "t2", Declare: collect.Declaration{Reads: []string{plain}, Needs: "none"}, Run: c.Run}
	if entries, present, err := aclEntries(collect.Guard(collect.Host(), c2), plain); err != nil || present || entries != nil {
		t.Errorf("no ACL: entries=%v present=%v err=%v", entries, present, err)
	}
}

// The walk hands decodeACL what the host's ReadDir read under Xattrs: an
// extended access ACL the test set on its own 0755 file (an owner may, no
// root needed) comes back byte for byte and renders as its five entries.
// A minimal three-entry ACL would not do — the kernel folds one that only
// restates the mode bits into the mode and stores no attribute.
func TestHostReadDirACLDecodes(t *testing.T) {
	d := t.TempDir()
	x := filepath.Join(d, "x")
	if err := os.WriteFile(x, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(x, 0o755); err != nil {
		t.Fatal(err)
	}
	const undefined = 0xffffffff
	blob := aclBlob(
		[3]uint32{aclUserObj, 7, undefined}, [3]uint32{aclUser, 5, 4242}, [3]uint32{aclGroupObj, 5, undefined},
		[3]uint32{aclMask, 5, undefined}, [3]uint32{aclOther, 5, undefined},
	)
	if err := unix.Setxattr(x, aclXattrName, blob, 0); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) {
			t.Skipf("the temp dir's filesystem cannot hold an access ACL: %v", err)
		}
		t.Fatal(err)
	}
	l, err := collect.Host().ReadDir(d, collect.Identity{}, collect.ReadDirOptions{Xattrs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 1 || l.Entries[0].Name != "x" {
		t.Fatalf("entries = %+v, want x alone", l.Entries)
	}
	e := l.Entries[0]
	if e.XattrErr != nil || !bytes.Equal(e.ACL, blob) {
		t.Fatalf("x: ACL=%x XattrErr=%v, want %x", e.ACL, e.XattrErr, blob)
	}
	got, err := decodeACL(e.ACL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user::rwx", "user:4242:r-x", "group::r-x", "mask::r-x", "other::r-x"}
	if !slices.Equal(got, want) {
		t.Errorf("decodeACL = %v, want %v", got, want)
	}
}
