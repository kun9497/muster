//go:build linux

package collectors

import (
	"context"

	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgindex"
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

	noPackageDBReason = pkgindex.NoPackageDBReason
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

// joinCandidates joins every candidate of walk.suid_sgid, walk.world_writable,
// walk.hidden and walk.capabilities to the host's package database and, on
// dpkg, to the release's reference list and the packages' postinst
// scripts. It mutates r.
func joinCandidates(ctx context.Context, a collect.Access, hdr *facts.Run, plan mountPlan, r *walkResult) joinOutcome {
	cands := candidateSet(r)
	// The index is read by pkgindex, shared with the process collector; a
	// host with neither database comes back FamilyNone with the absent
	// envelope, which absent_means: manual turns into MANUAL rather than
	// into a false PASS.
	ix, truncated, failed := pkgindex.Build(ctx, a, cands, pkgindex.Options{USRMerged: plan.usrMerged})
	out := joinOutcome{family: string(ix.Family), failed: failed, truncated: truncated, source: ix.Source}
	switch ix.Family {
	case pkgindex.FamilyRPM:
		// The rpm database carries modes, so there is nothing it cannot
		// decide: a path it holds is declared (or not) by the mode rpm
		// recorded, and a path it does not hold is unpackaged. The
		// reference list is never consulted — on this family it is
		// cross-check evidence for the maintainer, not an input (W-7).
		if failed == nil {
			applyRPM(r, ix.RPM)
		}
	case pkgindex.FamilyDpkg:
		joinDpkg(a, hdr, plan, ix.Dpkg, &out, r)
	}
	splitUnverified(r)
	r.lists.sort()
	return out
}

// detectFamily is pkgindex.DetectFamily as the string the walk's tests and
// joinOutcome compare: one detection for every collector, so one host can
// never be an apt host to the patch collector and an rpm host to the walk.
func detectFamily(a collect.Access) string { return string(pkgindex.DetectFamily(a)) }

// candidateSet is every path the join will look up. The four lists are the
// only ones with package fields: sticky_missing and unowned are judged by
// what they are, not by what a package says, acl_grants carries no package
// field (an ACL is the administrator's, never a package's), and skipped is
// provenance.
func candidateSet(r *walkResult) map[string]bool {
	out := make(map[string]bool, len(r.lists.suid)+len(r.lists.worldWritable)+len(r.lists.hidden)+len(r.lists.capabilities))
	for _, rows := range [][]map[string]any{r.lists.suid, r.lists.worldWritable, r.lists.hidden, r.lists.capabilities} {
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
