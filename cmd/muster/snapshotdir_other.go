//go:build !linux

package main

import (
	"errors"

	"github.com/kun9497/muster/internal/snapshots"
)

// errSnapshotDirLinux is what every snapshot directory command answers off
// Linux, after its flags parsed (the collect_other.go precedent).
var errSnapshotDirLinux = errors.New("snapshot ls, rm and prune require Linux")

// snapshotDir, latestLink and dirKind mirror snapshotdir_linux.go so the
// untagged commands compile everywhere.
type snapshotDir struct {
	fd   int
	path string
}

type latestLink struct {
	present bool
	target  string
	state   string
}

type dirKind int

const (
	kindAbsent dirKind = iota
	kindRegular
	kindDir
	kindSymlink
	kindOther
)

func openSnapshotDir(string) (*snapshotDir, error) { return nil, errSnapshotDirLinux }

func (d *snapshotDir) list() ([]snapshots.Entry, int, latestLink, error) {
	return nil, 0, latestLink{}, errSnapshotDirLinux
}

func (d *snapshotDir) stat(string) (dirKind, error) { return kindAbsent, errSnapshotDirLinux }

func (d *snapshotDir) close() {}
