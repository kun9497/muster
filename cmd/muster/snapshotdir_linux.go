//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/snapshots"
)

// errUntrustedSnapshotDir is a snapshot directory RL-18 refuses: not owned by
// the caller, or group- or world-writable.
var errUntrustedSnapshotDir = errors.New("untrusted snapshot directory")

// dirError carries a message naming the path and the sentinel it is.
type dirError struct {
	msg string
	err error
}

func (e *dirError) Error() string { return e.msg }
func (e *dirError) Unwrap() error { return e.err }

// snapshotDir is the snapshot directory, opened once: every listing and
// every change goes through fd, never through a path that could be
// re-pointed in between (RL-18).
type snapshotDir struct {
	fd   int
	path string
}

// latestLink is what the latest symlink says. state is ok (target names an
// entry of the listing), dangling (no such entry) or outside (the target
// holds a '/'); a latest that is not a symlink is not present.
type latestLink struct {
	present bool
	target  string
	state   string
}

// dirKind is what one name in the directory is, without following it.
type dirKind int

const (
	kindAbsent dirKind = iota
	kindRegular
	kindDir
	kindSymlink
	kindOther
)

// openSnapshotDir opens path as a directory without following a symlink and
// applies RL-18: the directory is owned by the caller and neither group- nor
// world-writable. The components above it are not walked, as the writer's
// trustedDir does not walk them.
func openSnapshotDir(path string) (*snapshotDir, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			if st, lerr := os.Lstat(path); lerr == nil && st.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%s is a symlink", path)
			}
			return nil, fmt.Errorf("%s is not a directory", path)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	euid := os.Geteuid()
	if st.Uid != uint32(euid) || st.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0 {
		unix.Close(fd)
		return nil, &dirError{
			msg: fmt.Sprintf("%s is not owned by uid %d, or is group- or world-writable", path, euid),
			err: errUntrustedSnapshotDir,
		}
	}
	return &snapshotDir{fd: fd, path: path}, nil
}

func (d *snapshotDir) close() { unix.Close(d.fd) }

// readDirNames returns the entry names of an open directory fd, "." and ".."
// dropped, from the start of the directory (internal/collect's readNames
// loop).
func readDirNames(fd int) ([]string, error) {
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10)
	var names []string
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
	}
}

// list reads the directory once. A regular file whose name is the writer's
// pattern is opened relative to the fd without following a symlink, checked
// to be the file the stat saw, and classified from its header; a symlink
// named latest is read, not counted; every other name is counted in other
// and never opened (RA-6). A name that vanished since the listing is
// dropped.
func (d *snapshotDir) list() (entries []snapshots.Entry, other int, latest latestLink, err error) {
	names, err := readDirNames(d.fd)
	if err != nil {
		return nil, 0, latestLink{}, fmt.Errorf("read %s: %w", d.path, err)
	}
	for _, name := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, 0, latestLink{}, fmt.Errorf("stat %s/%s: %w", d.path, report.Escape(name), err)
		}
		typ := st.Mode & unix.S_IFMT
		if name == "latest" && typ == unix.S_IFLNK {
			target, err := readLinkAt(d.fd, name)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return nil, 0, latestLink{}, fmt.Errorf("read %s/latest: %w", d.path, err)
			}
			latest = latestLink{present: true, target: target}
			continue
		}
		if _, _, ok := snapshots.ParseName(name); !ok || typ != unix.S_IFREG {
			other++
			continue
		}
		e, counted, err := d.readEntry(name, st)
		if err != nil {
			return nil, 0, latestLink{}, err
		}
		switch counted {
		case entryRow:
			entries = append(entries, e)
		case entryOther:
			other++
		}
	}
	if latest.present {
		latest.state = "dangling"
		if strings.Contains(latest.target, "/") {
			latest.state = "outside"
		} else {
			for _, e := range entries {
				if e.Name == latest.target {
					latest.state = "ok"
					break
				}
			}
		}
	}
	return entries, other, latest, nil
}

type entryOutcome int

const (
	entryRow entryOutcome = iota
	entryOther
	entryGone
)

// readEntry opens one pattern-matching regular file and classifies it. A
// file that vanished is dropped; one replaced by something else between the
// stat and the open (a symlink, another inode) is counted as other; one that
// cannot be opened or read is an unreadable row, so the operator sees what
// is taking space.
func (d *snapshotDir) readEntry(name string, st unix.Stat_t) (snapshots.Entry, entryOutcome, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return snapshots.Entry{}, entryGone, nil
	case errors.Is(err, unix.ELOOP):
		return snapshots.Entry{}, entryOther, nil
	case err != nil:
		return snapshots.Classify(name, st.Size, facts.Header{}, err), entryRow, nil
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil {
		return snapshots.Entry{}, entryRow, fmt.Errorf("stat %s/%s: %w", d.path, report.Escape(name), err)
	}
	if fst.Mode&unix.S_IFMT != unix.S_IFREG || fst.Dev != st.Dev || fst.Ino != st.Ino {
		return snapshots.Entry{}, entryOther, nil
	}
	h, herr := facts.LoadHeader(io.LimitReader(f, facts.MaxSnapshotBytes+1))
	return snapshots.Classify(name, fst.Size, h, herr), entryRow, nil
}

// readLinkAt reads a symlink's text relative to dirfd, growing the buffer
// while the text fills it.
func readLinkAt(dirfd int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// stat is what name is in the directory, without following it (RA-3).
func (d *snapshotDir) stat(name string) (dirKind, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return kindAbsent, nil
		}
		return kindAbsent, err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return kindRegular, nil
	case unix.S_IFDIR:
		return kindDir, nil
	case unix.S_IFLNK:
		return kindSymlink, nil
	default:
		return kindOther, nil
	}
}
