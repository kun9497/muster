package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// The script run inside the image prints one flat, line-oriented document,
// because the only thing every one of the five images is guaranteed to have
// is a POSIX shell and the distribution's own package tool. The document is
// a sequence of sections, each introduced by a `== ` header:
//
//	== osrelease           the image's own ID and VERSION_ID, one per line
//	== arch                the image's own `uname -m`
//	== usrmerge            `<alias> <readlink target>` for each merged-usr link
//	== versions            `<package> <version>` for every package covered
//	== files <package>     `stat -c '%a %U %G %n'` for every file it installs
//	== modes <package>     the mode-setting lines of its maintainer scripts
//	== deb <package> <sha> `tar -tv` over the archive's filesystem tarball
//
// Nothing here talks to a container runtime: assembleList is a pure function
// of the document, so the shape of a real image's answer is a committed
// fixture (testdata/image-output.sample) and every rule the reference list
// depends on is tested on a host with no docker at all.
//
// The covered packages are a SEED unioned with a discovery: sources.json
// names the ones a maintainer cares about, and the script adds the owner of
// every setuid and setgid file the image carries, so a list covers packages
// sources.json never mentions (mount, libpam-modules-bin, usermode). A seed
// the image does not install is dropped with a warning — the script installs
// nothing, because a list has to be reproducible from the pinned digest.
//
// The lines are parsed by internal/pkgfiles — the same parsers the collector
// reads a host's package database with (Task 6). That is the point of the
// shared package: a line the tool and the join read differently would
// produce a list that never matches the host it describes.

const (
	sectionOSRelease = "osrelease"
	sectionArch      = "arch"
	sectionUsrMerge  = "usrmerge"
	sectionVersions  = "versions"
	sectionFiles     = "files"
	sectionModes     = "modes"
	sectionDeb       = "deb"
)

// usrAliases are the six top-level directories a merged-usr distribution
// turns into symlinks, in the order internal/collect/collectors names them.
var usrAliases = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// section is one `== ` block: its kind, the header's remaining words and the
// lines that followed it.
type section struct {
	kind  string
	args  []string
	lines []string
}

// document is the parsed script output.
type document struct {
	sections []section
}

// parseScriptOutput splits the document into sections. A line before the
// first header, or a header naming a section this tool does not know, is an
// error: the script and this parser are written together, so a surprise
// means the script did not run the way the tool believes it did.
func parseScriptOutput(out []byte) (*document, error) {
	var doc document
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if rest, ok := strings.CutPrefix(line, "== "); ok {
			f := strings.Fields(rest)
			if len(f) == 0 {
				return nil, fmt.Errorf("a section header with no name: %q", line)
			}
			switch f[0] {
			case sectionOSRelease, sectionArch, sectionUsrMerge, sectionVersions, sectionFiles, sectionModes, sectionDeb:
			default:
				return nil, fmt.Errorf("unknown section %q", f[0])
			}
			doc.sections = append(doc.sections, section{kind: f[0], args: f[1:]})
			continue
		}
		if len(doc.sections) == 0 {
			if strings.TrimSpace(line) == "" {
				continue
			}
			return nil, fmt.Errorf("output does not start with == osrelease: %q", line)
		}
		doc.sections[len(doc.sections)-1].lines = append(doc.sections[len(doc.sections)-1].lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(doc.sections) == 0 || doc.sections[0].kind != sectionOSRelease {
		return nil, fmt.Errorf("output does not start with == osrelease")
	}
	return &doc, nil
}

// assembleList turns one run's document into the release's committed list.
// generated is stamped into the list and is the run's UTC date; arch is the
// Go architecture name the image was pulled for, which the image's own
// `uname -m` has to agree with.
//
// The second result is the warnings the run produced — the maintainer-script
// line behind every postinst_sets_mode flag, a path two packages both
// install, and a package sources.json names that the image does not have.
// They are not failures: the list is still correct, but each is a judgement
// a person should be able to check without unpacking an archive again.
func assembleList(rel suid.Release, generated, arch string, out []byte) (suid.List, []string, error) {
	doc, err := parseScriptOutput(out)
	if err != nil {
		return suid.List{}, nil, err
	}
	var warnings []string

	id, versionID, err := doc.osRelease()
	if err != nil {
		return suid.List{}, nil, err
	}
	if id != rel.ID {
		return suid.List{}, nil, fmt.Errorf("the image reports ID=%q, but sources.json says %q", id, rel.ID)
	}
	if versionID != rel.VersionID && majorOf(versionID) != rel.VersionID {
		return suid.List{}, nil, fmt.Errorf("the image reports VERSION_ID=%q, which is not %q nor a point release of it", versionID, rel.VersionID)
	}
	if err := doc.checkArch(arch); err != nil {
		return suid.List{}, nil, err
	}

	merged, err := doc.usrMerged()
	if err != nil {
		return suid.List{}, nil, err
	}
	entries, covered, dups, err := doc.entries(merged)
	if err != nil {
		return suid.List{}, nil, err
	}
	warnings = append(warnings, dups...)
	if len(entries) == 0 {
		return suid.List{}, nil, fmt.Errorf("the run produced no entries at all")
	}

	// What each package ships, in the canonical form the list holds it in.
	// postinstSetsMode needs it: a chmod naming a literal path decides
	// nothing unless that path is a file this package actually installs.
	shipped := make(map[string]map[string]bool, len(covered))
	for _, e := range entries {
		if shipped[e.Package] == nil {
			shipped[e.Package] = map[string]bool{}
		}
		shipped[e.Package][e.Path] = true
	}

	versions := doc.versions()
	packages := make([]suid.Package, 0, len(covered))
	for _, name := range covered {
		v, ok := versions[name]
		if !ok || v == "" {
			return suid.List{}, nil, fmt.Errorf("package %s ships files but the run reported no version for it", name)
		}
		p := suid.Package{Name: name, Version: v}
		if line, ok := postinstSetsMode(doc.linesOf(sectionModes, name), shipped[name], merged); ok {
			p.PostinstSetsMode = true
			warnings = append(warnings, fmt.Sprintf("%s: postinst sets a mode: %s", name, line))
		}
		packages = append(packages, p)
	}

	coveredSet := make(map[string]bool, len(covered))
	for _, name := range covered {
		coveredSet[name] = true
	}
	for i, sp := range rel.Packages {
		switch {
		case sp.URL != "":
			sec, ok := doc.section(sectionDeb, sp.Name)
			if !ok {
				return suid.List{}, nil, fmt.Errorf("package %s is downloaded from %s but the run reported no archive for it", sp.Name, sp.URL)
			}
			if len(sec.args) < 2 {
				return suid.List{}, nil, fmt.Errorf("package %s: the archive section carries no sha256", sp.Name)
			}
			if sec.args[1] != sp.SHA256 {
				return suid.List{}, nil, fmt.Errorf("package %s: the archive in the image has sha256 %s, pinned %s", sp.Name, sec.args[1], sp.SHA256)
			}
			// sources.json may force the flag for a package whose script
			// this tool's textual scan cannot read.
			if rel.Packages[i].PostinstSetsMode && setPostinst(packages, sp.Name) {
				warnings = append(warnings, fmt.Sprintf("%s: postinst sets a mode: sources.json says so", sp.Name))
			}
		case !coveredSet[sp.Name]:
			warnings = append(warnings, fmt.Sprintf("%s: sources.json names %s, but the image does not install it; the list does not cover it", rel.ID+"-"+versionID, sp.Name))
		}
	}

	return suid.List{
		Distro:      id,
		Release:     versionID,
		Arch:        arch,
		ImageDigest: rel.Digest,
		Generated:   generated,
		Packages:    packages,
		Entries:     entries,
	}, warnings, nil
}

// setPostinst raises the flag and reports whether it was not already up, so
// a forced flag that only repeats what the scan found says nothing.
func setPostinst(pkgs []suid.Package, name string) bool {
	for i := range pkgs {
		if pkgs[i].Name == name && !pkgs[i].PostinstSetsMode {
			pkgs[i].PostinstSetsMode = true
			return true
		}
	}
	return false
}

// machineArch maps the kernel's name for a machine to Go's. An image's
// `uname -m` is the only thing that can contradict the platform the tool
// asked the runtime for, which is why it is read at all: a runtime that
// quietly served an emulated image of another architecture would otherwise
// produce a list labelled amd64 out of arm64 binaries.
var machineArch = map[string]string{
	"x86_64": "amd64", "amd64": "amd64",
	"aarch64": "arm64", "arm64": "arm64",
	"ppc64le": "ppc64le", "s390x": "s390x", "riscv64": "riscv64",
}

func (d *document) checkArch(want string) error {
	s, ok := d.section(sectionArch, "")
	if !ok {
		return fmt.Errorf("the run reported no == arch section")
	}
	machine := ""
	for _, line := range s.lines {
		if t := strings.TrimSpace(line); t != "" {
			machine = t
			break
		}
	}
	if machine == "" {
		return fmt.Errorf("== arch reported nothing")
	}
	if got := machineArch[machine]; got != want {
		return fmt.Errorf("the image reports uname -m %q, but the run pinned %s", machine, want)
	}
	return nil
}

// majorOf is the part of a VERSION_ID before the first dot: the RHEL family
// reports 9.8 for what sources.json pins as 9 (ruling A-36).
func majorOf(versionID string) string {
	major, _, _ := strings.Cut(versionID, ".")
	return major
}

func (d *document) section(kind, arg string) (section, bool) {
	for _, s := range d.sections {
		if s.kind != kind {
			continue
		}
		if arg == "" || (len(s.args) > 0 && s.args[0] == arg) {
			return s, true
		}
	}
	return section{}, false
}

func (d *document) linesOf(kind, arg string) []string {
	s, ok := d.section(kind, arg)
	if !ok {
		return nil
	}
	return s.lines
}

// osRelease is the image's own identity, which is what the list is named
// from: an image whose VERSION_ID is a point release (rocky 9.8) is
// committed under that version and Load falls back to the major (A-36).
func (d *document) osRelease() (id, versionID string, err error) {
	s, ok := d.section(sectionOSRelease, "")
	if !ok {
		return "", "", fmt.Errorf("output does not start with == osrelease")
	}
	var f []string
	for _, line := range s.lines {
		if t := strings.TrimSpace(line); t != "" {
			f = append(f, t)
		}
	}
	if len(f) != 2 {
		return "", "", fmt.Errorf("== osrelease reported %d values, want ID and VERSION_ID", len(f))
	}
	return f[0], f[1], nil
}

// usrMerged is the image's merged-usr table, built the way
// mountPlan.readUsrMerged builds a host's: an alias is kept only when it is
// a symlink INTO /usr, so a distribution that points /libx32 somewhere else
// entirely leaves those paths alone.
func (d *document) usrMerged() (map[string]string, error) {
	out := map[string]string{}
	alias := map[string]bool{}
	for _, a := range usrAliases {
		alias[a] = true
	}
	for _, line := range d.linesOf(sectionUsrMerge, "") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, target, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !alias[name] {
			return nil, fmt.Errorf("== usrmerge: unreadable line %q", line)
		}
		// readlink prints the link's own text, which is relative on every
		// merged-usr distribution ("usr/bin"); the link sits at the root, so
		// the resolution is a single leading slash.
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		if target != "/usr" && !strings.HasPrefix(target, "/usr/") {
			continue
		}
		out[name] = target
	}
	return out, nil
}

// versions maps every package the run reported to its version.
func (d *document) versions() map[string]string {
	out := map[string]string{}
	for _, s := range d.sections {
		if s.kind != sectionVersions {
			continue
		}
		for _, line := range s.lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			name, v, ok := strings.Cut(strings.TrimSpace(line), " ")
			if ok && name != "" {
				out[name] = v
			}
		}
	}
	return out
}

// entries reads every `== files` and `== deb` section into the list's
// entries, canonicalised through the image's merged-usr table and sorted by
// path. A path two packages both install keeps the one whose package sorts
// first, so the answer cannot depend on the order the script walked; the
// other is returned as a warning.
//
// The second result is the packages that produced a section, in sorted
// order — the list's `packages`, which is what the join's "is this package
// covered at all?" question reads.
func (d *document) entries(merged map[string]string) (entries []suid.Entry, covered []string, warnings []string, err error) {
	seen := map[string]bool{}
	for _, s := range d.sections {
		var pkg string
		if len(s.args) > 0 {
			pkg = s.args[0]
		}
		switch s.kind {
		case sectionFiles:
			if pkg == "" {
				return nil, nil, nil, fmt.Errorf("== files with no package name")
			}
			for _, line := range s.lines {
				if strings.TrimSpace(line) == "" {
					continue
				}
				mode, owner, group, p, ok := pkgfiles.ParseStatLine(line)
				if !ok {
					return nil, nil, nil, fmt.Errorf("== files %s: unreadable stat line %q", pkg, line)
				}
				entries = append(entries, suid.Entry{
					Path: pkgfiles.CanonicalUsr(p, merged), Mode: mode,
					Owner: owner, Group: group, Package: pkg,
				})
			}
		case sectionDeb:
			if pkg == "" {
				return nil, nil, nil, fmt.Errorf("== deb with no package name")
			}
			for _, line := range s.lines {
				if strings.TrimSpace(line) == "" {
					continue
				}
				// Only a regular file carries a mode that says anything
				// about a file: a directory's mode is not a declaration the
				// walk could ever join, and a symlink's is meaningless.
				if line[0] != '-' {
					continue
				}
				mode, owner, group, p, ok := pkgfiles.ParseTarTV(line)
				if !ok {
					return nil, nil, nil, fmt.Errorf("== deb %s: unreadable archive line %q", pkg, line)
				}
				entries = append(entries, suid.Entry{
					Path: pkgfiles.CanonicalUsr(p, merged), Mode: mode,
					Owner: owner, Group: group, Package: pkg,
				})
			}
		default:
			continue
		}
		if !seen[pkg] {
			seen[pkg] = true
			covered = append(covered, pkg)
		}
	}
	sort.Strings(covered)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Package < entries[j].Package
	})
	kept := entries[:0]
	// The message names the entry that WAS kept, not the previous element of
	// the input: with three packages claiming one path, "both B and C" would
	// name a row that is not in the list either.
	var last suid.Entry
	for i, e := range entries {
		if i > 0 && last.Path == e.Path {
			warnings = append(warnings, fmt.Sprintf("%s is installed by both %s and %s; the list keeps %s", e.Path, last.Package, e.Package, last.Package))
			continue
		}
		last = e
		kept = append(kept, e)
	}
	return kept, covered, warnings, nil
}

// setModeCall matches a chmod: its mode operand and the operand after it,
// with any option flags skipped. The scan is textual and deliberately
// generous about a mode or a target the script COMPUTES — a line this tool
// misreads as setting a special bit costs a WARN on that package's files,
// while one it MISSES lets the join read an ordinary /usr/bin/pkexec as "the
// distribution does not ship this setuid", which is a finding against a
// perfectly stock host.
var setModeCall = regexp.MustCompile(`(?:^|[;&|(]|\s)chmod\s+(?:-[A-Za-z-]+\s+)*(\S+)\s+(\S+)`)

// statOverrideAdd matches a maintainer script that hands the mode to dpkg
// rather than setting it itself. `dpkg-statoverride --add` has exactly the
// effect a chmod would, and policy asks Debian packages to prefer it — dbus
// and postfix both do — so a scan that only knew chmod would miss the
// commonest case of all.
var statOverrideAdd = regexp.MustCompile(`dpkg-statoverride\s.*--add(\s|$)`)

// postinstSetsMode reports whether an archive's maintainer scripts give a
// shipped FILE a setuid or setgid bit, and returns the line it read that
// off. Such a package's archive is not the truth about an installed host —
// the file is unpacked without the bit and the script adds it — so the join
// routes its files to walk.suid_sgid_unverified instead of reading the
// archive's mode as a declaration (W-7).
//
// Two things are required of a line, and the second is what keeps the flag
// from being raised by everything:
//
//   - the MODE has to carry setuid or setgid, or be one the script computes
//     (chmod $MODE $FILE, as policykit-1 and postfix do), which the archive
//     gives no way to resolve;
//   - the TARGET, when it is a literal absolute path, has to be a file this
//     package ships. The walk only ever makes a REGULAR FILE a setuid
//     candidate, so a chmod on a directory (`chmod -R g+s /var/spool/mail`)
//     or on a path the archive does not contain can never decide anything
//     the join will ask about — and raising the flag for it would soften
//     every one of that package's real files to a WARN for nothing. A
//     computed target keeps the generous answer.
//
// shipped holds the package's own paths in the canonical form the list uses,
// and merged is the image's usr table: fuse3's script says /bin/fusermount3
// while the list says /usr/bin/fusermount3, and a lookup that did not
// canonicalise would drop the one package whose flag is least in doubt.
func postinstSetsMode(lines []string, shipped map[string]bool, merged map[string]string) (string, bool) {
	ships := func(target string) bool {
		if strings.ContainsAny(target, "$`*?") || !strings.HasPrefix(target, "/") {
			// Computed, or relative to a directory the script chose: the
			// archive cannot say what it names.
			return true
		}
		return shipped[pkgfiles.CanonicalUsr(strings.TrimRight(target, "/"), merged)]
	}
	for _, line := range lines {
		if statOverrideAdd.MatchString(line) {
			if mode, target, ok := statOverrideTarget(line); ok && mode&0o6000 != 0 && ships(target) {
				return strings.TrimSpace(line), true
			}
			continue
		}
		for _, m := range setModeCall.FindAllStringSubmatch(line, -1) {
			if setsSpecialBit(m[1]) && ships(unquote(m[2])) {
				return strings.TrimSpace(line), true
			}
		}
	}
	return "", false
}

// setsSpecialBit classifies one chmod mode operand.
func setsSpecialBit(mode string) bool {
	if strings.Contains(mode, "$") {
		// A computed mode. It may or may not carry a special bit and the
		// archive gives no way to know, so the package is unverifiable.
		return true
	}
	if v, err := strconv.ParseUint(mode, 8, 32); err == nil {
		return v&0o6000 != 0
	}
	for _, sep := range []string{"+", "="} {
		if _, perms, ok := strings.Cut(mode, sep); ok && strings.Contains(perms, "s") {
			return true
		}
	}
	return false
}

// statOverrideTarget reads the mode and the path out of a statoverride call.
// The arguments are `<user> <group> <mode> <path>` after the options, but the
// options differ between `--add` and `--update --add`, so the mode is found
// by what it looks like — an octal word — and the path is the word after it.
func statOverrideTarget(line string) (mode int, target string, ok bool) {
	words := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" \t", r) })
	for i, w := range words {
		u := unquote(w)
		if len(u) < 3 || len(u) > 5 {
			continue
		}
		v, err := strconv.ParseUint(u, 8, 32)
		if err != nil || i+1 >= len(words) {
			continue
		}
		return int(v), unquote(words[i+1]), true
	}
	return 0, "", false
}

// unquote strips the shell quoting a maintainer script puts round a word.
// "$LAUNCHER" has to keep its dollar sign — that is what makes it computed —
// so only the surrounding quotes go.
func unquote(w string) string {
	return strings.Trim(w, `"'`)
}

// renderList encodes a list the one way the committed files are encoded:
// two-space indentation and a trailing newline, as tools/refindex writes the
// STIG index. -check compares the bytes, so the encoding is part of the
// contract.
func renderList(l suid.List) ([]byte, error) {
	if l.Packages == nil {
		l.Packages = []suid.Package{}
	}
	if l.Entries == nil {
		l.Entries = []suid.Entry{}
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// diffKind is what -check found. A date-only difference is separated from
// real drift because `generated` moves on every run by construction: a
// -check that failed on it would only be usable on the day the lists were
// made, and a maintainer verifying a months-old tree would learn nothing.
type diffKind int

const (
	diffNone diffKind = iota
	diffDateOnly
	diffReal
)

// describeDifference reports the FIRST thing that moved between the
// committed list and the one this run produced. A byte comparison alone
// would send the maintainer to a diff of tens of thousands of lines; the
// answer they need is "which file, and what about it".
//
// `generated` is compared LAST and on its own: everything else is compared
// with the two dates masked to the same value, so a date that moved
// alongside real drift is still reported as the drift.
func describeDifference(committed, generated []byte) (string, diffKind) {
	if bytes.Equal(committed, generated) {
		return "", diffNone
	}
	var have, got suid.List
	if err := json.Unmarshal(committed, &have); err != nil {
		return fmt.Sprintf("the committed file does not decode: %v", err), diffReal
	}
	if err := json.Unmarshal(generated, &got); err != nil {
		return fmt.Sprintf("the generated list does not decode: %v", err), diffReal
	}
	for _, f := range []struct{ name, a, b string }{
		{"distro", have.Distro, got.Distro},
		{"release", have.Release, got.Release},
		{"arch", have.Arch, got.Arch},
		{"image_digest", have.ImageDigest, got.ImageDigest},
	} {
		if f.a != f.b {
			return fmt.Sprintf("%s is %q, the run produced %q", f.name, f.a, f.b), diffReal
		}
	}
	if msg, differs := firstPackageDifference(have.Packages, got.Packages); differs {
		return msg, diffReal
	}
	if msg, differs := firstEntryDifference(have.Entries, got.Entries); differs {
		return msg, diffReal
	}
	if have.Generated != got.Generated {
		return fmt.Sprintf("generated is %q and this run would stamp %q; nothing else moved", have.Generated, got.Generated), diffDateOnly
	}
	return "the two encode the same list but not the same bytes; regenerate to normalise the file", diffReal
}

func firstPackageDifference(have, got []suid.Package) (string, bool) {
	i, j := 0, 0
	for i < len(have) || j < len(got) {
		switch {
		case j == len(got) || (i < len(have) && have[i].Name < got[j].Name):
			return fmt.Sprintf("package %s is committed but the run no longer covers it", have[i].Name), true
		case i == len(have) || got[j].Name < have[i].Name:
			return fmt.Sprintf("package %s is new in this run", got[j].Name), true
		case have[i] != got[j]:
			return fmt.Sprintf("package %s: committed %+v, the run produced %+v", have[i].Name, have[i], got[j]), true
		}
		i++
		j++
	}
	return "", false
}

func firstEntryDifference(have, got []suid.Entry) (string, bool) {
	i, j := 0, 0
	for i < len(have) || j < len(got) {
		switch {
		case j == len(got) || (i < len(have) && have[i].Path < got[j].Path):
			return fmt.Sprintf("%s is committed but the run no longer lists it", have[i].Path), true
		case i == len(have) || got[j].Path < have[i].Path:
			return fmt.Sprintf("%s is new in this run", got[j].Path), true
		case have[i] != got[j]:
			return fmt.Sprintf("%s: committed mode %o %s:%s (%s), the run produced %o %s:%s (%s)",
				have[i].Path, have[i].Mode, have[i].Owner, have[i].Group, have[i].Package,
				got[j].Mode, got[j].Owner, got[j].Group, got[j].Package), true
		}
		i++
		j++
	}
	return "", false
}
