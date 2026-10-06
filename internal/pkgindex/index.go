// Package pkgindex answers "which package owns this path, and what does the
// package database say about it?" for a set of candidate paths, on a dpkg or
// an rpm host. It is the index the walk's package join builds, lifted out of
// the collectors package so a second collector (the process collector) reads
// the same database the same way: one host can never be an rpm host to one
// collector and a dpkg host to another, and a path can never be packaged to
// one and unpackaged to the other.
//
// The index is built for exactly the candidates a caller names and for
// nothing else. A host's package database names every packaged file, and an
// index of all of them would cost more memory than the whole rest of a run;
// the readers stream the database and keep the candidate rows alone.
//
// The verdicts — whether a package DECLARES a mode, what the release's
// reference list says, what a maintainer script sets — are the caller's. This
// package reads; it decides nothing.
//
// This file and parse.go carry no build tag, so the types and the byte
// parsers build and are tested on any host; the readers that touch the host
// through collect.Access are Linux-only, as collect is.
package pkgindex

import "github.com/kun9497/muster/internal/facts"

// Family names the package database a host has.
type Family string

const (
	FamilyDpkg Family = "dpkg"
	FamilyRPM  Family = "rpm"
	FamilyNone Family = "none"
)

// The paths the readers open. A caller that builds an index declares them
// (DpkgReads, RPMReads) so its guard licenses every read Build makes.
const (
	DpkgStatusPath       = "/var/lib/dpkg/status"
	DpkgInfoDir          = "/var/lib/dpkg/info"
	DpkgInfoGlob         = "/var/lib/dpkg/info/*.list"
	DpkgDiversionsPath   = "/var/lib/dpkg/diversions"
	DpkgStatOverridePath = "/var/lib/dpkg/statoverride"
	RPMDBDir             = "/var/lib/rpm"

	// DpkgReadLimit is the per-file cap of every dpkg database read. TeX
	// Live's file list is over a megabyte, so the cap is generous; a read
	// that hits it truncates the index exactly as a capped rpm capture does.
	DpkgReadLimit = 16 << 20

	// NoPackageDBReason is the reason of the absent envelope a host with
	// neither database gets.
	NoPackageDBReason = "no package database"
)

// DpkgReads is every path the dpkg reader opens; RPMReads is the one path
// DetectFamily stats on an rpm host (the rpm reader runs RPMCommand).
var (
	DpkgReads = []string{DpkgInfoGlob, DpkgStatOverridePath, DpkgDiversionsPath, DpkgStatusPath}
	RPMReads  = []string{RPMDBDir}
)

// StatOverride is one dpkg-statoverride entry.
type StatOverride struct {
	User, Group string
	Mode        int
}

// DpkgIndex is everything the four dpkg files say about the CANDIDATES, and
// about nothing else. Every map is keyed by the candidate's own path, as the
// caller names it, so a lookup is one map hit and no path arithmetic:
//
//   - Owner: the package that ships the file (through a diversion where one
//     applies);
//   - DeclaredPath: the spelling the source used when it differs from the
//     candidate — the pre-merge /bin/su, or the diverted-from name;
//   - ListPath: the path a reference list would hold the file under, set
//     only for a diverted candidate (a list holds what the package shipped,
//     not where dpkg put it);
//   - ListFile: the .list file that gave the owner (the multi-arch name is
//     the file's own), whose postinst a caller may read;
//   - Overrides, Versions: the statoverride entry and the installed version
//     of every package.
type DpkgIndex struct {
	Owner        map[string]string
	DeclaredPath map[string]string
	ListPath     map[string]string
	ListFile     map[string]string
	Overrides    map[string]StatOverride
	Versions     map[string]string
}

// NewDpkgIndex is an empty index with every map allocated.
func NewDpkgIndex() *DpkgIndex {
	return &DpkgIndex{
		Owner:        map[string]string{},
		DeclaredPath: map[string]string{},
		ListPath:     map[string]string{},
		ListFile:     map[string]string{},
		Overrides:    map[string]StatOverride{},
		Versions:     map[string]string{},
	}
}

// RPMFile is one row of the rpm file table, for a candidate path only.
type RPMFile struct {
	Pkg, Owner, Group, Caps string
	Mode                    int
}

// Index is the answer Build gives: the family, the table that family has
// (Dpkg on dpkg, RPM on rpm, neither on none) and the evidence the table
// cites — the dpkg info directory, or the rpm command with its exit code.
type Index struct {
	Family Family
	Dpkg   *DpkgIndex
	RPM    map[string]RPMFile
	Source *facts.Source
}

// Owner is the package that owns path on this host, if the index holds it.
// It is the one lookup a caller that only needs ownership makes; a path that
// was not a candidate is never held.
func (ix Index) Owner(path string) (pkg string, ok bool) {
	switch ix.Family {
	case FamilyDpkg:
		if ix.Dpkg == nil {
			return "", false
		}
		pkg, ok = ix.Dpkg.Owner[path]
		return pkg, ok
	case FamilyRPM:
		f, ok := ix.RPM[path]
		return f.Pkg, ok
	}
	return "", false
}
