// Package pkgfiles parses the three package-file listings muster reads and
// canonicalises a merged-usr path. It is shared, deliberately, by the walk's
// package join (internal/collect/collectors) and by the maintainer tool that
// generates the reference lists (tools/suidindex): the tool writes the list
// the join later reads, so a line the two read differently would produce a
// list that never matches the host it describes. There is one parser per
// producing command and no second copy of any of them.
//
// Every parser takes ONE line with its terminator already removed — callers
// scan with bufio.Scanner, whose ScanLines drops a trailing \r as well — and
// returns ok false for a line it cannot read in full, never a partly filled
// result. A mode is the numeric POSIX mode masked to 0o7777 (permissions
// plus setuid, setgid and sticky), the form internal/facts stores.
//
// The package has no build tag: it must build and be tested on any host.
package pkgfiles

import (
	"path"
	"strconv"
	"strings"
)

// ParseRPMFileLine reads one line of
// `rpm -qa --qf '[%{=NAME}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILENAMES}\n]'`:
//
//	bash<TAB>0100755<TAB>root<TAB>root<TAB>/usr/bin/bash
//
// The path is last and the line is split on the FIRST four tabs, so a path
// containing a space — or a tab — survives whole; rpm records the owner and
// group as NAMES, never as ids, and they are reported as it recorded them.
// The mode field is the full st_mode in octal (0104755 for a setuid file),
// masked here to 0o7777: the file-TYPE bits are discarded deliberately, so a
// symlink or a directory row reads as a mode-only row like any other. The
// join never needs the type — the traversal decides what a candidate is from
// its own stat, and it never makes a symlink a mode candidate — and a caller
// that needed it would be asking this parser a question rpm's own format
// string was not asked.
func ParseRPMFileLine(line string) (pkg string, mode int, owner, group string, p string, ok bool) {
	f := strings.SplitN(line, "\t", 5)
	if len(f) < 5 || f[0] == "" || !strings.HasPrefix(f[4], "/") {
		return "", 0, "", "", "", false
	}
	m, err := strconv.ParseUint(f[1], 8, 32)
	if err != nil {
		return "", 0, "", "", "", false
	}
	return f[0], int(m) & 0o7777, f[2], f[3], f[4], true
}

// ParseTarTV reads one line of `tar -tv` over a .deb's filesystem tarball:
//
//	-rwsr-xr-x root/root  72712 2024-01-01 00:00 ./usr/bin/at
//
// The name is the sixth field and everything after it, so spaces in a path
// survive; a leading "./" is dropped and the result is an absolute clean
// path. A symlink ('l') and a hard link ('h') are refused: their mode says
// nothing about the file they name, and their name field carries the target
// as well, which would be read as part of the path.
func ParseTarTV(line string) (mode int, owner, group, p string, ok bool) {
	f, name, ok := fields(line, 5)
	if !ok {
		return 0, "", "", "", false
	}
	bits := f[0]
	if len(bits) < 10 || bits[0] == 'l' || bits[0] == 'h' {
		return 0, "", "", "", false
	}
	mode, ok = modeFromBits(bits)
	if !ok {
		return 0, "", "", "", false
	}
	owner, group, ok = strings.Cut(f[1], "/")
	if !ok || owner == "" || group == "" {
		return 0, "", "", "", false
	}
	return mode, owner, group, absClean(name), true
}

// ParseStatLine reads one line of `stat -c '%a %U %G %n'`:
//
//	4755 root root /usr/bin/su
//
// %a prints the mode in octal with no leading zero, and the name is the
// fourth field and everything after it.
func ParseStatLine(line string) (mode int, owner, group, p string, ok bool) {
	f, name, ok := fields(line, 3)
	if !ok {
		return 0, "", "", "", false
	}
	m, err := strconv.ParseUint(f[0], 8, 32)
	if err != nil || !strings.HasPrefix(name, "/") {
		return 0, "", "", "", false
	}
	return int(m) & 0o7777, f[1], f[2], name, true
}

// CanonicalUsr rewrites a path recorded under a merged-usr alias into the
// form the walk sees. usrMerged maps an alias that is a symlink into /usr to
// its target ("/bin" -> "/usr/bin"); a package's file list still says
// /bin/su on a merged host while the no-follow walk can only ever report
// /usr/bin/su, and the two would otherwise never join.
//
// The match is on whole path components, so /binx and /lib64 are untouched
// by a "/bin" or "/lib" alias; the longest matching alias wins, so the
// result cannot depend on map iteration order.
func CanonicalUsr(p string, usrMerged map[string]string) string {
	best, target := "", ""
	for alias, t := range usrMerged {
		if p != alias && !strings.HasPrefix(p, alias+"/") {
			continue
		}
		if len(alias) > len(best) {
			best, target = alias, t
		}
	}
	if best == "" {
		return p
	}
	return target + p[len(best):]
}

// fields splits off the first n whitespace-separated fields and returns the
// rest of the line with its leading whitespace removed and nothing else
// touched — that rest is a name, and a name may contain spaces. A line with
// fewer than n fields, or with nothing after them, is refused.
func fields(line string, n int) ([]string, string, bool) {
	out := make([]string, 0, n)
	rest := line
	for i := 0; i < n; i++ {
		rest = strings.TrimLeft(rest, " \t")
		j := strings.IndexAny(rest, " \t")
		if j <= 0 {
			return nil, "", false
		}
		out = append(out, rest[:j])
		rest = rest[j:]
	}
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return nil, "", false
	}
	return out, rest, true
}

// modeFromBits reads the ten-character mode string ls and tar print. Each
// column may only hold its own letter or '-'; the execute columns also carry
// the special bits, in their lower case with the execute bit and in their
// upper case without it (rwS is setuid without execute). Anything else is
// refused rather than guessed at.
func modeFromBits(s string) (int, bool) {
	mode := 0
	for _, c := range []struct {
		idx  int
		want byte
		bit  int
	}{{1, 'r', 0o400}, {2, 'w', 0o200}, {4, 'r', 0o040}, {5, 'w', 0o020}, {7, 'r', 0o004}, {8, 'w', 0o002}} {
		switch s[c.idx] {
		case '-':
		case c.want:
			mode |= c.bit
		default:
			return 0, false
		}
	}
	for _, c := range []struct {
		idx               int
		exec, special     int
		withExec, withOut byte
	}{{3, 0o100, 0o4000, 's', 'S'}, {6, 0o010, 0o2000, 's', 'S'}, {9, 0o001, 0o1000, 't', 'T'}} {
		switch s[c.idx] {
		case '-':
		case 'x':
			mode |= c.exec
		case c.withExec:
			mode |= c.exec | c.special
		case c.withOut:
			mode |= c.special
		default:
			return 0, false
		}
	}
	return mode, true
}

// absClean turns an archive member name into the absolute path the walk
// would report for it: "./usr/bin/at" -> "/usr/bin/at", "./tmp/" -> "/tmp".
func absClean(name string) string {
	name = strings.TrimPrefix(name, ".")
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	return path.Clean(name)
}
