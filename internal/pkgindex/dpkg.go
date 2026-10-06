//go:build linux

package pkgindex

import (
	"errors"
	"io/fs"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// The dpkg database says which package owns a path and nothing whatever
// about its permissions. The reader reads four things:
//
//   - /var/lib/dpkg/info/*.list — path -> package, in the PRE-MERGE spelling
//     (/bin/su) that a merged-usr host no longer has;
//   - /var/lib/dpkg/diversions — three-line groups (from, to, package): the
//     file a package shipped as `from` is on disk as `to`, and the package's
//     own .list still says `from`;
//   - /var/lib/dpkg/statoverride — `user group mode path`, what the
//     administrator told dpkg to enforce on every upgrade;
//   - /var/lib/dpkg/status — the installed version per package.

// dpkgReader is one build's state: the access, the merged-usr table every
// path out of the database is canonicalised through, the index being built
// and the first failure and the truncation the reads recorded.
type dpkgReader struct {
	a         collect.Access
	merged    map[string]string
	idx       *DpkgIndex
	failed    *facts.Envelope
	truncated bool
}

// buildDpkg reads the four files for the candidates. The source it cites is
// the info directory: the .list files are where ownership came from, and
// naming one of them would cite the last file read rather than the table.
// A failure does not stop the build — what was read is kept — but the first
// one is returned, and a caller treats the index as unanswerable.
func buildDpkg(a collect.Access, cands map[string]bool, opts Options) (Index, bool, *facts.Envelope) {
	r := &dpkgReader{a: a, merged: opts.USRMerged, idx: NewDpkgIndex()}
	// The diversions are read first: they decide which name each candidate
	// is looked up under, and which package may claim it.
	r.readLists(cands, r.readDiversions(cands))
	r.readOverrides(cands)
	r.readVersions()
	ix := Index{Family: FamilyDpkg, Dpkg: r.idx, Source: &facts.Source{Kind: "file", Path: DpkgInfoDir}}
	return ix, r.truncated, r.failed
}

// fail records the first failure; a second one would only hide the first.
func (r *dpkgReader) fail(e facts.Envelope) {
	if r.failed == nil {
		r.failed = &e
	}
}

// read reads one database file at the cap. A file that is not there is an
// ordinary absence for the two optional ones (a host with no diversion and no
// override has neither file); every other failure is the build's answer,
// with the path in the reason (C3). A capped read is not a failure — what
// was read is real — but it sets truncated, so the absence of a row means
// nothing, and the cut last line is dropped.
func (r *dpkgReader) read(p string, optional bool) ([]byte, bool) {
	data, meta, err := r.a.ReadFile(p, DpkgReadLimit)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		e := collect.FromReadError(err, meta)
		e.Reason = p + ": " + e.Reason
		r.fail(e)
		return nil, false
	}
	if meta.Truncated {
		r.truncated = true
		data = dropCutLine(data)
	}
	return data, true
}

// readDiversions returns the diversion groups that touch a candidate, in
// file order. A diverted file sits under its diverted-to name while the
// shipping package's .list still says the original, so without this the
// file would read unpackaged.
func (r *dpkgReader) readDiversions(cands map[string]bool) []diversion {
	data, ok := r.read(DpkgDiversionsPath, true)
	if !ok {
		return nil
	}
	var out []diversion
	for _, d := range parseDiversions(data, r.merged) {
		if cands[d.to] || cands[d.from] {
			out = append(out, d)
		}
	}
	return out
}

// listLookup is one claim a .list line can satisfy: the candidate it decides
// and, where a diversion applies, which package may make the claim. A
// diverted path is named by two packages, so one of the two rows requires
// the diverting package and the other refuses it.
type listLookup struct {
	cand                   string
	requirePkg, excludePkg string
}

// readLists streams every package's file list and keeps the candidate lines
// alone. The package name is the FILE's name — dpkg has no other record of
// it — with the architecture qualifier of a multi-arch package removed.
func (r *dpkgReader) readLists(cands map[string]bool, divs []diversion) {
	files, err := r.a.Glob(DpkgInfoGlob)
	if err != nil {
		e := collect.FromReadError(err, collect.ReadMeta{})
		e.Reason = DpkgInfoDir + ": " + e.Reason
		r.fail(e)
		return
	}
	wanted := wantedPaths(cands, divs)
	for _, f := range files {
		data, ok := r.read(f, false)
		if !ok {
			continue
		}
		pkg := DpkgListPackage(f)
		for _, raw := range dpkgListPaths(data) {
			canon := pkgfiles.CanonicalUsr(raw, r.merged)
			for _, w := range wanted[canon] {
				if w.requirePkg != "" && pkg != w.requirePkg {
					continue
				}
				if w.excludePkg != "" && pkg == w.excludePkg {
					continue
				}
				if _, claimed := r.idx.Owner[w.cand]; claimed {
					// Two packages listing one path is a broken database;
					// the first in Glob's sorted order keeps it, so the
					// answer cannot depend on directory order.
					continue
				}
				r.idx.Owner[w.cand] = pkg
				r.idx.ListFile[w.cand] = f
				if raw != w.cand {
					r.idx.DeclaredPath[w.cand] = raw
				}
				if canon != w.cand {
					r.idx.ListPath[w.cand] = canon
				}
			}
		}
	}
}

// wantedPaths maps the name a package uses to the candidates that name
// reaches. A candidate a diversion touches is looked up under `from` — under
// its own name it would find the other package's line, or nothing.
func wantedPaths(cands map[string]bool, divs []diversion) map[string][]listLookup {
	wanted := make(map[string][]listLookup, len(cands))
	diverted := make(map[string]bool, 2*len(divs))
	for _, d := range divs {
		if cands[d.to] {
			wanted[d.from] = append(wanted[d.from], listLookup{cand: d.to, excludePkg: d.by})
			diverted[d.to] = true
		}
		if cands[d.from] {
			wanted[d.from] = append(wanted[d.from], listLookup{cand: d.from, requirePkg: d.by})
			diverted[d.from] = true
		}
	}
	for p := range cands {
		if diverted[p] {
			continue
		}
		wanted[p] = append(wanted[p], listLookup{cand: p})
	}
	return wanted
}

// readOverrides keeps the statoverride entries for candidate paths. An
// override outranks everything else a caller reads: it is what dpkg enforces
// on every upgrade, whatever the archive or a reference list says.
func (r *dpkgReader) readOverrides(cands map[string]bool) {
	data, ok := r.read(DpkgStatOverridePath, true)
	if !ok {
		return
	}
	for _, l := range parseStatOverrides(data, r.merged) {
		if cands[l.path] {
			r.idx.Overrides[l.path] = l.ov
		}
	}
}

// readVersions records the installed version of every package, in the
// (name, arch) order ParseDpkgStatus returns, so a package installed for two
// architectures records the version of the later one as it always has.
func (r *dpkgReader) readVersions() {
	data, ok := r.read(DpkgStatusPath, false)
	if !ok {
		return
	}
	for _, p := range ParseDpkgStatus(data) {
		r.idx.Versions[p.Name] = p.Version
	}
}
