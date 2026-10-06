package pkgindex

import (
	"bufio"
	"bytes"
	"cmp"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/pkgfiles"
)

// The byte parsers of the index. They carry no build tag so their tests and
// fuzz targets run on any host; the readers in dpkg.go and rpm.go hand them
// what Access read.

// rpmMaxLine bounds one line of the rpm file table. PATH_MAX is 4 KiB, so
// 64 KiB is far more than any real line needs: a line that overruns it is a
// stream that is not the table muster asked for, and the reader says so
// rather than stopping silently and reporting the rest of the host as
// unpackaged.
const rpmMaxLine = 64 << 10

// RPMFileTable streams RPMCommand's output and keeps the candidate lines
// alone, so the memory the index costs is bounded by the number of
// candidates and not by the number of files on the host.
//
// A capture that hit the output cap ends mid-line, and the last line of a
// capped capture is dropped rather than parsed: the path is the last field,
// so a cut one is a PREFIX of the real path and could spell some other
// candidate exactly (a cut /var/lib/x/spool-archive reads as
// /var/lib/x/spool). Deciding a candidate from another file's mode is worse
// than not deciding it.
func RPMFileTable(stdout []byte, cands map[string]bool, truncated bool) (map[string]RPMFile, error) {
	if truncated {
		stdout = dropCutLine(stdout)
	}
	table := make(map[string]RPMFile, len(cands))
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), rpmMaxLine)
	for sc.Scan() {
		pkg, mode, owner, group, caps, p, ok := pkgfiles.ParseRPMFileLine(sc.Text())
		if !ok || !cands[p] {
			continue
		}
		table[p] = RPMFile{Pkg: pkg, Owner: owner, Group: group, Caps: caps, Mode: mode}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return table, nil
}

// dropCutLine removes everything after the last newline of a capped read:
// the cut tail is not a path but the PREFIX of one, so "/usr/bin/sudoedit"
// cut short spells "/usr/bin/su" and would hand a candidate to the wrong
// package.
func dropCutLine(data []byte) []byte {
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return data[:i+1]
	}
	return nil
}

// DpkgPackage is one installed package of /var/lib/dpkg/status.
type DpkgPackage struct {
	Name, Version, Arch string
}

// ParseDpkgStatus reads /var/lib/dpkg/status and returns the packages whose
// Status is "install ok installed", ordered by (name, arch). It is the one
// reader of the file: the patch collector publishes its rows and the index
// takes the installed versions from them, so the two can never read one file
// two ways.
func ParseDpkgStatus(data []byte) []DpkgPackage {
	var out []DpkgPackage
	var name, version, arch, status string
	flush := func() {
		if name != "" && status == "install ok installed" {
			out = append(out, DpkgPackage{Name: name, Version: version, Arch: arch})
		}
		name, version, arch, status = "", "", "", ""
	}
	for _, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // a folded continuation of the previous field
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			name = v
		case "Version":
			version = v
		case "Architecture":
			arch = v
		case "Status":
			status = v
		}
	}
	flush()
	slices.SortStableFunc(out, func(a, b DpkgPackage) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Arch, b.Arch))
	})
	return out
}

// DpkgListPackage is the package name a .list file belongs to:
// "/var/lib/dpkg/info/util-linux:amd64.list" -> "util-linux".
func DpkgListPackage(file string) string {
	name := strings.TrimSuffix(path.Base(file), ".list")
	if arch := strings.IndexByte(name, ':'); arch >= 0 {
		name = name[:arch]
	}
	return name
}

// dpkgListPaths is every path a .list file names, as the package spelled it
// (surrounding whitespace removed, blank lines skipped).
func dpkgListPaths(data []byte) []string {
	lines := splitLines(data)
	out := lines[:0]
	for _, line := range lines {
		if raw := strings.TrimSpace(line); raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// diversion is one three-line group of /var/lib/dpkg/diversions: the path a
// package ships (from), where dpkg actually puts that package's copy (to),
// and the package that asked for the diversion (by). BOTH packages list
// `from` — the one that shipped the file and the one that displaced it — so
// the third line is what tells the two candidates apart:
//
//	a candidate at `to`   is the DIVERTED package's file: the owner is the
//	                      package listing `from` that is NOT `by`;
//	a candidate at `from` is the DIVERTING package's own file: the owner is
//	                      `by`, and only `by`.
//
// Without the package name both rows would be decided by whichever .list
// Glob happened to hand over last.
type diversion struct{ from, to, by string }

// parseDiversions reads every complete group of the diversions file, both
// paths canonicalised through the merged-usr table, in file order. A group
// with an empty path, or one that diverts a path to itself, is dropped.
func parseDiversions(data []byte, merged map[string]string) []diversion {
	lines := splitLines(data)
	var out []diversion
	for i := 0; i+2 < len(lines); i += 3 {
		d := diversion{
			from: pkgfiles.CanonicalUsr(strings.TrimSpace(lines[i]), merged),
			to:   pkgfiles.CanonicalUsr(strings.TrimSpace(lines[i+1]), merged),
			by:   strings.TrimSpace(lines[i+2]),
		}
		if d.from == "" || d.to == "" || d.from == d.to {
			continue
		}
		out = append(out, d)
	}
	return out
}

// statOverrideLine is one parsed statoverride line: the canonical path and
// the entry.
type statOverrideLine struct {
	path string
	ov   StatOverride
}

// parseStatOverrides reads `user group mode path` lines, the mode octal and
// masked to 0o7777, the path canonicalised through the merged-usr table and
// kept whole (it may contain spaces). A line that does not read in full is
// skipped.
func parseStatOverrides(data []byte, merged map[string]string) []statOverrideLine {
	var out []statOverrideLine
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
		p := pkgfiles.CanonicalUsr(strings.TrimLeft(rest, " \t"), merged)
		out = append(out, statOverrideLine{path: p, ov: StatOverride{User: user, Group: group, Mode: int(mode) & 0o7777}})
	}
	return out
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

// splitLines splits on \n and drops a trailing \r from every line, as the
// collectors' own splitLines does.
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}
