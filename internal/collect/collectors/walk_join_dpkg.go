//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// The dpkg database says which package owns a path and nothing whatever
// about its permissions, so the join reads four things and then asks the
// release's reference list (W-7) what the distribution ships:
//
//   - /var/lib/dpkg/info/*.list — path -> package, in the PRE-MERGE spelling
//     (/bin/su) that a merged-usr host no longer has;
//   - /var/lib/dpkg/diversions — three-line groups (from, to, package): the
//     file a package shipped as `from` is on disk as `to`, and the package's
//     own .list still says `from`;
//   - /var/lib/dpkg/statoverride — `user group mode path`, what the
//     administrator told dpkg to enforce on every upgrade;
//   - /var/lib/dpkg/status — the installed version per package, read with
//     patch.go's parser so both collectors read one file one way.
const (
	dpkgInfoDir          = "/var/lib/dpkg/info"
	dpkgInfoGlob         = "/var/lib/dpkg/info/*.list"
	dpkgDiversionsPath   = "/var/lib/dpkg/diversions"
	dpkgStatOverridePath = "/var/lib/dpkg/statoverride"

	// TeX Live's file list is over a megabyte, so the per-file cap is
	// generous; a read that hits it truncates the join exactly as a capped
	// rpm capture does.
	dpkgJoinReadLimit = 16 << 20
)

// statOverride is one dpkg-statoverride entry.
type statOverride struct {
	user, group string
	mode        int
}

// dpkgIndex is everything the four files say about the CANDIDATES, and about
// nothing else. Every map is keyed by the candidate's own path, as the walk
// reports it, so a lookup is one map hit and no path arithmetic:
//
//   - owner: the package that ships the file (through a diversion where one
//     applies);
//   - declaredPath: the spelling the source used when it differs from the
//     candidate — the pre-merge /bin/su, or the diverted-from name — which
//     the record carries as declared_path;
//   - listPath: the path the reference list would hold the file under, set
//     only for a diverted candidate (the list holds what the package
//     shipped, not where dpkg put it);
//   - overrides, versions: the statoverride entry and the installed version.
type dpkgIndex struct {
	owner        map[string]string
	declaredPath map[string]string
	listPath     map[string]string
	overrides    map[string]statOverride
	versions     map[string]string
}

func newDpkgIndex() dpkgIndex {
	return dpkgIndex{
		owner:        map[string]string{},
		declaredPath: map[string]string{},
		listPath:     map[string]string{},
		overrides:    map[string]statOverride{},
		versions:     map[string]string{},
	}
}

// dpkgJoin is one join's state: the access, the merged-usr table every path
// out of the database is canonicalised through, the index being built and
// the outcome the failures are recorded in.
type dpkgJoin struct {
	a      collect.Access
	merged map[string]string
	idx    dpkgIndex
	out    joinOutcome
}

// joinDpkg builds the index, consults the reference list and decides every
// candidate. The source it cites is the info directory: the .list files are
// where ownership came from, and naming one of them would cite the last file
// read rather than the table.
func joinDpkg(a collect.Access, hdr *facts.Run, plan mountPlan, cands map[string]bool, r *walkResult) joinOutcome {
	j := &dpkgJoin{
		a:      a,
		merged: plan.usrMerged,
		idx:    newDpkgIndex(),
		out:    joinOutcome{source: &facts.Source{Kind: "file", Path: dpkgInfoDir}},
	}
	// The diversions are read first: they decide which name each candidate
	// is looked up under.
	divert := j.readDiversions(cands)
	j.readLists(cands, divert)
	j.readOverrides(cands)
	j.readVersions()
	applyDpkg(r, j.idx, j.referenceList(hdr))
	return j.out
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

// read reads one database file at the join's cap. A file that is not there
// is an ordinary absence for the two optional ones (a host with no diversion
// and no override has neither file); every other failure is the join's
// answer, with the path in the reason (C3). A capped read is not a failure —
// what was read is real — but it sets truncated, so the absence of a row
// means nothing.
func (j *dpkgJoin) read(p string, optional bool) ([]byte, bool) {
	data, meta, err := j.a.ReadFile(p, dpkgJoinReadLimit)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		e := collect.FromReadError(err, meta)
		e.Reason = p + ": " + e.Reason
		j.fail(e)
		return nil, false
	}
	if meta.Truncated {
		j.out.truncated = true
	}
	return data, true
}

// readDiversions returns, for each candidate that is a diversion's TARGET,
// the name the package that ships it still uses. A diverted file sits under
// its diverted-to name while the shipping package's .list says the original,
// so without this the file would read unpackaged.
func (j *dpkgJoin) readDiversions(cands map[string]bool) map[string]string {
	data, ok := j.read(dpkgDiversionsPath, true)
	if !ok {
		return nil
	}
	lines := splitLines(data)
	out := map[string]string{}
	for i := 0; i+2 < len(lines); i += 3 {
		from := pkgfiles.CanonicalUsr(strings.TrimSpace(lines[i]), j.merged)
		to := pkgfiles.CanonicalUsr(strings.TrimSpace(lines[i+1]), j.merged)
		if from == "" || to == "" || from == to {
			continue
		}
		if cands[to] {
			out[to] = from
		}
	}
	return out
}

// readLists streams every package's file list and keeps the candidate lines
// alone. The package name is the FILE's name — dpkg has no other record of
// it — with the architecture qualifier of a multi-arch package removed.
func (j *dpkgJoin) readLists(cands map[string]bool, divert map[string]string) {
	files, err := j.a.Glob(dpkgInfoGlob)
	if err != nil {
		e := collect.FromReadError(err, collect.ReadMeta{})
		e.Reason = dpkgInfoDir + ": " + e.Reason
		j.fail(e)
		return
	}
	// wanted maps the name a package uses to the candidates that name
	// reaches: a list, because a diverted-from path can itself be a
	// candidate, and deciding which of the two wins by map order would make
	// two runs of one host differ.
	wanted := make(map[string][]string, len(cands))
	for p := range cands {
		key := p
		if d, ok := divert[p]; ok {
			key = d
		}
		wanted[key] = append(wanted[key], p)
	}
	for _, f := range files {
		data, ok := j.read(f, false)
		if !ok {
			continue
		}
		pkg := dpkgListPackage(f)
		for _, line := range splitLines(data) {
			raw := strings.TrimSpace(line)
			if raw == "" {
				continue
			}
			canon := pkgfiles.CanonicalUsr(raw, j.merged)
			for _, cand := range wanted[canon] {
				j.idx.owner[cand] = pkg
				if raw != cand {
					j.idx.declaredPath[cand] = raw
				}
				if canon != cand {
					j.idx.listPath[cand] = canon
				}
			}
		}
	}
}

// dpkgListPackage is the package name a .list file belongs to:
// "/var/lib/dpkg/info/util-linux:amd64.list" -> "util-linux".
func dpkgListPackage(file string) string {
	name := strings.TrimSuffix(path.Base(file), ".list")
	if arch := strings.IndexByte(name, ':'); arch >= 0 {
		name = name[:arch]
	}
	return name
}

// readOverrides keeps the statoverride entries for candidate paths. An
// override outranks everything else the join reads: it is what dpkg enforces
// on every upgrade, whatever the archive or the reference list says.
func (j *dpkgJoin) readOverrides(cands map[string]bool) {
	data, ok := j.read(dpkgStatOverridePath, true)
	if !ok {
		return
	}
	for _, line := range splitLines(data) {
		user, rest, ok := cutField(line)
		if !ok {
			continue
		}
		group, rest, ok := cutField(rest)
		if !ok {
			continue
		}
		modeText, rest, ok := cutField(rest)
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(modeText, 8, 32)
		if err != nil {
			continue
		}
		p := pkgfiles.CanonicalUsr(strings.TrimLeft(rest, " \t"), j.merged)
		if !cands[p] {
			continue
		}
		j.idx.overrides[p] = statOverride{user: user, group: group, mode: int(mode) & 0o7777}
	}
}

// cutField splits off one whitespace-separated field and returns the rest
// untouched, so the path at the end of a statoverride line keeps whatever
// spaces it contains.
func cutField(s string) (field, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i:], true
}

// readVersions records the installed version of every package, which is what
// the reference list's version rule compares against.
func (j *dpkgJoin) readVersions() {
	data, ok := j.read(dpkgStatusPath, false)
	if !ok {
		return
	}
	for _, v := range parseDpkgStatus(data) {
		rec, ok := v.(map[string]any)
		if !ok {
			continue
		}
		name, _ := rec["name"].(string)
		version, _ := rec["version"].(string)
		if name != "" {
			j.idx.versions[name] = version
		}
	}
}

// decideBit answers, for one candidate and one special bit, whether a source
// declares it — W-7's table, in order:
//
//	statoverride entry            -> statoverride, declared by its mode
//	no package owns the path      -> unpackaged, declared false
//	no reference list             -> none
//	package not covered           -> unlisted
//	package sets the mode itself  -> postinst
//	listed WITH the bit           -> list, declared, whatever the version
//	version equal, not listed so  -> list, declared FALSE (the finding)
//	version differs, not listed so-> version_mismatch
//
// The bit a listed file HAS is a declaration whatever the installed version:
// treating every patched host as unverified would make the list useless on
// the day after an upgrade. The list is a floor, not a ceiling, and the
// control's description says so.
func decideBit(cand map[string]any, bit int, idx dpkgIndex, list *suid.List) (declared bool, reference string, declaredMode any, declaredPath string) {
	p := rowField(cand, "path")
	declaredPath = idx.declaredPath[p]
	if ov, ok := idx.overrides[p]; ok {
		// An override on a path no package owns still counts: dpkg enforces
		// it on every upgrade regardless.
		return ov.mode&bit == bit, refStatOverride, ov.mode, declaredPath
	}
	pkg, owned := idx.owner[p]
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
	if rec.PostinstSetsMode {
		return false, refPostinst, nil, declaredPath
	}
	e, found := list.Entry(dpkgListKey(p, idx))
	if found {
		declaredMode = e.Mode
	}
	switch {
	case found && e.Mode&bit == bit:
		return true, refList, declaredMode, declaredPath
	case idx.versions[pkg] == rec.Version:
		return false, refList, declaredMode, declaredPath
	default:
		return false, refVersionMismatch, declaredMode, declaredPath
	}
}

// dpkgListKey is the path the reference list holds a candidate under: the
// name the package shipped, which differs from the candidate only where a
// diversion moved the file.
func dpkgListKey(p string, idx dpkgIndex) string {
	if lp, ok := idx.listPath[p]; ok {
		return lp
	}
	return p
}

// declaredIdentity is the owner and group the deciding source names. Only
// the two sources that carry an identity have one — dpkg's own database
// records neither — and a source that did not decide declares nothing.
func declaredIdentity(p, reference string, idx dpkgIndex, list *suid.List) (owner, group string) {
	switch reference {
	case refStatOverride:
		ov := idx.overrides[p]
		return ov.user, ov.group
	case refList:
		if list == nil {
			return "", ""
		}
		if e, ok := list.Entry(dpkgListKey(p, idx)); ok {
			return e.Owner, e.Group
		}
	}
	return "", ""
}

// applyDpkg writes the decision onto every candidate row.
func applyDpkg(r *walkResult, idx dpkgIndex, list *suid.List) {
	for _, row := range r.lists.suid {
		p := rowField(row, "path")
		declared, reference, mode, declaredPath := decideBit(row, candidateBits(row), idx, list)
		owner, group := declaredIdentity(p, reference, idx, list)
		row["package"] = idx.owner[p]
		row["package_declared"] = declared
		row["reference"] = reference
		row["declared_mode"] = mode
		row["declared_path"] = declaredPath
		row["declared_owner"], row["declared_group"] = owner, group
	}
	for _, row := range r.lists.worldWritable {
		p := rowField(row, "path")
		declared, reference, _, _ := decideBit(row, 0o002, idx, list)
		row["package"] = idx.owner[p]
		row["package_declared"] = declared
		row["reference"] = reference
	}
	for _, row := range r.lists.hidden {
		// A hidden entry carries no bit, so ownership is the whole answer
		// and neither the list nor an override is consulted.
		pkg, owned := idx.owner[rowField(row, "path")]
		if !owned {
			continue
		}
		row["package"] = pkg
		row["package_declared"] = true
		row["reference"] = refDpkgDB
	}
}
