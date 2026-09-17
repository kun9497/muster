//go:build linux

package collectors

import (
	"context"

	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The package join (W-6, W-7) answers, for every candidate the traversal
// found, "does a package say this file is meant to look like this?". It runs
// ONCE, after the walk, over the candidates alone: a host's package database
// names every packaged file, and an index of all of them would cost more
// memory than the whole rest of the run.
//
// It never verifies a package (W-8): rpm -V and dpkg --verify take a package
// list computed at run time, which the command whitelist cannot express
// today, and both exit non-zero when a file merely differs. Plan 3C designs
// that; 3A reports declarations.
//
// The join fills fields on the rows the traversal already wrote, in place,
// and then splits the setuid/setgid candidates: what it could decide either
// way stays in walk.suid_sgid (which a control judges), what it could not
// moves to walk.suid_sgid_unverified (which only warns). Nothing here writes
// a fact — the collector does, from joinOutcome.
const (
	// reference names the source that decided a row. The vocabulary is
	// closed: a control's description quotes it, and a value invented here
	// would be a value nothing can be written against.
	refRPMDB           = "rpmdb"        // the rpm file table, which carries modes
	refDpkgDB          = "dpkgdb"       // a dpkg .list, which carries ownership only
	refStatOverride    = "statoverride" // dpkg-statoverride, which the administrator set
	refList            = "list"         // the release's reference list (W-7)
	refUnpackaged      = "unpackaged"   // no source owns the path
	refUnlisted        = "unlisted"     // packaged, but the list covers no such package
	refVersionMismatch = "version_mismatch"
	refPostinst        = "postinst" // the package sets the mode at install time
	refNone            = "none"     // there is no reference list for this release

	noPackageDBReason = "no package database"
)

// loadReferenceList is suid.Load behind a variable so a test can serve a
// fixture list; nothing else reassigns it.
var loadReferenceList = suid.Load

// joinOutcome is what the join has to say about itself. failed, when set, is
// the envelope EVERY joined list carries — the join is one operation, and a
// table nobody could read leaves walk.suid_sgid as unanswerable as
// walk.hidden. truncated says the tables were read only in part, so the rows
// that were joined are real but the absence of a row means nothing; source
// is the evidence the joined lists cite.
type joinOutcome struct {
	family    string
	failed    *facts.Envelope
	truncated bool
	source    *facts.Source
}

// joinCandidates joins every candidate of walk.suid_sgid, walk.world_writable
// and walk.hidden to the host's package database and, on dpkg, to the
// release's reference list. It mutates r.
func joinCandidates(ctx context.Context, a collect.Access, hdr *facts.Run, plan mountPlan, r *walkResult) joinOutcome {
	cands := candidateSet(r)
	family := detectFamily(a)
	var out joinOutcome
	switch family {
	case "rpm":
		out = joinRPM(ctx, a, cands, r)
	case "dpkg":
		out = joinDpkg(a, hdr, plan, cands, r)
	default:
		// Not an error: a host built without a package manager (or a
		// minimal image) simply cannot answer, and absent_means: manual
		// turns that into MANUAL rather than into a false PASS.
		e := collect.Absent(noPackageDBReason)
		out.failed = &e
	}
	out.family = family
	splitUnverified(r)
	r.lists.sort()
	return out
}

// detectFamily names the package database, by the same two artefacts
// patch.go uses (W-6) and in the same order, so one host can never be an apt
// host to the patch collector and an rpm host to the walk. pathPresent, not
// exists, for /var/lib/rpm: it is a directory, sometimes a symlink, and a
// path that refuses to be stat-ed for any reason other than "not found" is
// still occupied.
func detectFamily(a collect.Access) string {
	if exists(a, dpkgStatusPath) {
		return "dpkg"
	}
	if pathPresent(a, rpmDBDir) {
		return "rpm"
	}
	return "none"
}

// candidateSet is every path the join will look up. The three lists are the
// only ones with package fields: sticky_missing and unowned are judged by
// what they are, not by what a package says, and skipped is provenance.
func candidateSet(r *walkResult) map[string]bool {
	out := make(map[string]bool, len(r.lists.suid)+len(r.lists.worldWritable)+len(r.lists.hidden))
	for _, rows := range [][]map[string]any{r.lists.suid, r.lists.worldWritable, r.lists.hidden} {
		for _, row := range rows {
			out[rowField(row, "path")] = true
		}
	}
	return out
}

// candidateBits are the special bits one setuid/setgid candidate carries.
// package_declared asks whether a source declares EVERY bit the file has, so
// a file that is both setuid and setgid is not declared by a source that
// only ships it setgid.
func candidateBits(row map[string]any) int {
	bits := 0
	if b, _ := row["setuid"].(bool); b {
		bits |= 0o4000
	}
	if b, _ := row["setgid"].(bool); b {
		bits |= 0o2000
	}
	return bits
}

// splitUnverified moves the candidates the join could not decide out of
// walk.suid_sgid (W-7). The grammar cannot say "this element is FAIL and
// that one WARN", so the split is what keeps an undecidable row from being
// read as a finding — and keeps a decided one from being softened into a
// warning.
func splitUnverified(r *walkResult) {
	kept := r.lists.suid[:0]
	for _, row := range r.lists.suid {
		switch rowField(row, "reference") {
		case refUnlisted, refVersionMismatch, refPostinst, refNone:
			r.lists.suidUnverified = append(r.lists.suidUnverified, row)
		default:
			kept = append(kept, row)
		}
	}
	r.lists.suid = kept
}
