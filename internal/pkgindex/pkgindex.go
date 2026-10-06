//go:build linux

package pkgindex

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// Options bounds one Build. USRMerged is the merged-/usr table (alias ->
// target, e.g. "/bin" -> "/usr/bin") every dpkg path is canonicalised
// through; nil canonicalises nothing. RPMTimeout and RPMMaxOutput override
// RPMCommand's 120 s and 256 MiB when non-zero.
type Options struct {
	USRMerged    map[string]string
	RPMTimeout   time.Duration
	RPMMaxOutput int64
}

// Build detects the host's package database and indexes the candidates in
// it. It returns the index, whether a table was read only in part (the rows
// held are real, a missing row means nothing) and, when the index cannot
// answer, the envelope every fact derived from it carries: absent "no
// package database" on a host with neither, or the failing read's status
// with the path in the reason. On a failure the index still says which
// family it is and what it cites.
func Build(ctx context.Context, a collect.Access, cands map[string]bool, opts Options) (Index, bool, *facts.Envelope) {
	switch DetectFamily(a) {
	case FamilyRPM:
		return buildRPM(ctx, a, cands, opts)
	case FamilyDpkg:
		return buildDpkg(a, cands, opts)
	default:
		// Not an error: a host built without a package manager (or a
		// minimal image) simply cannot answer, and absent_means: manual
		// turns that into MANUAL rather than into a false PASS.
		e := collect.Absent(NoPackageDBReason)
		return Index{Family: FamilyNone}, false, &e
	}
}

// DetectFamily names the package database by the same two artefacts the
// patch collector uses and in the same order, so one host can never be an
// apt host to one collector and an rpm host to another. A path that refuses
// to be stat-ed for any reason other than "not found" is still occupied for
// /var/lib/rpm: it is a directory, sometimes a symlink.
func DetectFamily(a collect.Access) Family {
	if _, err := a.Stat(DpkgStatusPath); err == nil {
		return FamilyDpkg
	}
	if _, err := a.Stat(RPMDBDir); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return FamilyRPM
	}
	return FamilyNone
}
