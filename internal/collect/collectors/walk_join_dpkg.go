//go:build linux

package collectors

import (
	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgindex"
)

// The dpkg database says which package owns a path and nothing whatever
// about its permissions, so the join takes the index pkgindex builds from
// dpkg's four files (the .list files, diversions, statoverride and status)
// and then asks the release's reference list (W-7) what the distribution
// ships. The index is the reading; what follows here is the verdict.
const (
	dpkgInfoDir          = pkgindex.DpkgInfoDir
	dpkgInfoGlob         = pkgindex.DpkgInfoGlob
	dpkgDiversionsPath   = pkgindex.DpkgDiversionsPath
	dpkgStatOverridePath = pkgindex.DpkgStatOverridePath

	// dpkgJoinReadLimit is the index's per-file cap, which the postinst
	// reads of the capability join share.
	dpkgJoinReadLimit = pkgindex.DpkgReadLimit
)

// dpkgJoin is the verdict half of one join: the access the postinst reads
// go through, the merged-usr table a postinst path is canonicalised
// through, the index pkgindex built and the outcome the failures are
// recorded in.
type dpkgJoin struct {
	a      collect.Access
	merged map[string]string
	idx    *pkgindex.DpkgIndex
	out    *joinOutcome
}

// joinDpkg consults the reference list and decides every candidate from the
// index. A failure of the index's own reads is already in out; a reference
// list that will not decode is recorded only when there was none.
func joinDpkg(a collect.Access, hdr *facts.Run, plan mountPlan, idx *pkgindex.DpkgIndex, out *joinOutcome, r *walkResult) {
	j := &dpkgJoin{a: a, merged: plan.usrMerged, idx: idx, out: out}
	applyDpkg(r, j.idx, j.referenceList(hdr))
	if j.out.failed == nil {
		// A failed join publishes no row, so there is no script to read.
		j.applyDpkgCaps(r)
	}
}

// referenceList is the list for the host's release, chosen from the run
// header alone (the walk never reads /etc/os-release, which is a symlink on
// the RHEL family). A release with no list is an ordinary answer — every
// packaged candidate then reads `none` and warns. A list that will not
// decode is a defect in muster's own data and is loud.
func (j *dpkgJoin) referenceList(hdr *facts.Run) *suid.List {
	var id, versionID string
	if hdr != nil {
		id, versionID = hdr.Host.OSRelease.ID, hdr.Host.OSRelease.VersionID
	}
	list, ok, err := loadReferenceList(id, versionID)
	if err != nil {
		j.fail(collect.ErrorEnv("reference list: " + err.Error()))
		return nil
	}
	if !ok {
		return nil
	}
	return list
}

// fail records the join's first failure. Every joined list carries it, so a
// second one would only hide the first.
func (j *dpkgJoin) fail(e facts.Envelope) {
	if j.out.failed == nil {
		j.out.failed = &e
	}
}

// decideBit answers, for one candidate and one special bit, whether a source
// declares it — W-7's table, in order:
//
//	statoverride entry            -> statoverride, declared by its mode
//	no package owns the path      -> unpackaged, declared false
//	no reference list             -> none
//	package not covered           -> unlisted
//	listed WITH the bit           -> list, declared, whatever the version
//	package sets the mode itself  -> postinst
//	version equal, not listed so  -> list, declared FALSE (the finding)
//	version differs, not listed so-> version_mismatch
//
// The bit a listed file HAS is a declaration whatever the installed version:
// treating every patched host as unverified would make the list useless on
// the day after an upgrade. The list is a floor, not a ceiling, and the
// control's description says so.
//
// Ruling A-33: the listed bit is also checked BEFORE postinst_sets_mode. For
// a package the image itself installs, the list is the INSTALLED state, so a
// bit a maintainer script set is in the list; a flag that pushed such a file
// to unverified anyway would turn a perfectly ordinary /usr/bin/atq into a
// permanent WARN. postinst_sets_mode answers only for the files the list
// does not show carrying the bit.
func decideBit(cand map[string]any, bit int, idx *pkgindex.DpkgIndex, list *suid.List) (declared bool, reference string, declaredMode any, declaredPath string) {
	p := rowField(cand, "path")
	declaredPath = idx.DeclaredPath[p]
	if ov, ok := idx.Overrides[p]; ok {
		// An override on a path no package owns still counts: dpkg enforces
		// it on every upgrade regardless.
		return ov.Mode&bit == bit, refStatOverride, ov.Mode, declaredPath
	}
	pkg, owned := idx.Owner[p]
	if !owned {
		return false, refUnpackaged, nil, ""
	}
	if list == nil {
		return false, refNone, nil, declaredPath
	}
	rec, covered := list.Package(pkg)
	if !covered {
		return false, refUnlisted, nil, declaredPath
	}
	e, found := listEntryFor(p, pkg, idx, list)
	if found {
		declaredMode = e.Mode
	}
	switch {
	case found && e.Mode&bit == bit:
		return true, refList, declaredMode, declaredPath
	case rec.PostinstSetsMode:
		return false, refPostinst, declaredMode, declaredPath
	case idx.Versions[pkg] == rec.Version:
		return false, refList, declaredMode, declaredPath
	default:
		return false, refVersionMismatch, declaredMode, declaredPath
	}
}

// listEntryFor is the reference list's entry for one candidate, and only
// when it belongs to the package that owns the candidate ON THIS HOST.
//
// The list is keyed by path, but a path can be named by two packages: one
// that Replaces another, or a diversion, whose `from` is listed by the
// package that shipped it AND owned at run time by the package that
// displaced it. Honouring the other package's bit would let package B vouch
// for a file package A installed — the entry would declare a setuid bit the
// host's owner never ships. A path the list holds under a different package
// is therefore absent from the list as far as this candidate is concerned,
// which sends it down the version rule like any other unlisted path.
func listEntryFor(p, pkg string, idx *pkgindex.DpkgIndex, list *suid.List) (suid.Entry, bool) {
	e, ok := list.Entry(dpkgListKey(p, idx))
	if !ok || e.Package != pkg {
		return suid.Entry{}, false
	}
	return e, true
}

// dpkgListKey is the path the reference list holds a candidate under: the
// name the package shipped, which differs from the candidate only where a
// diversion moved the file.
func dpkgListKey(p string, idx *pkgindex.DpkgIndex) string {
	if lp, ok := idx.ListPath[p]; ok {
		return lp
	}
	return p
}

// declaredIdentity is the owner and group the deciding source names. Only
// the two sources that carry an identity have one — dpkg's own database
// records neither — and a source that did not decide declares nothing.
func declaredIdentity(p, reference string, idx *pkgindex.DpkgIndex, list *suid.List) (owner, group string) {
	switch reference {
	case refStatOverride:
		ov := idx.Overrides[p]
		return ov.User, ov.Group
	case refList:
		if list == nil {
			return "", ""
		}
		if e, ok := listEntryFor(p, idx.Owner[p], idx, list); ok {
			return e.Owner, e.Group
		}
	}
	return "", ""
}

// applyDpkg writes the decision onto every candidate row.
func applyDpkg(r *walkResult, idx *pkgindex.DpkgIndex, list *suid.List) {
	for _, row := range r.lists.suid {
		p := rowField(row, "path")
		declared, reference, mode, declaredPath := decideBit(row, candidateBits(row), idx, list)
		owner, group := declaredIdentity(p, reference, idx, list)
		row["package"] = idx.Owner[p]
		row["package_declared"] = declared
		row["reference"] = reference
		row["declared_mode"] = mode
		row["declared_path"] = declaredPath
		row["declared_owner"], row["declared_group"] = owner, group
	}
	for _, row := range r.lists.worldWritable {
		p := rowField(row, "path")
		declared, reference, _, _ := decideBit(row, 0o002, idx, list)
		row["package"] = idx.Owner[p]
		row["package_declared"] = declared
		row["reference"] = reference
	}
	for _, row := range r.lists.hidden {
		// A hidden entry carries no bit, so ownership is the whole answer
		// and neither the list nor an override is consulted.
		pkg, owned := idx.Owner[rowField(row, "path")]
		if !owned {
			continue
		}
		row["package"] = pkg
		row["package_declared"] = true
		row["reference"] = refDpkgDB
	}
}
