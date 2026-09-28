//go:build linux

package collectors

import (
	"bytes"
	"regexp"
	"strings"
)

// verifyLineRE is the one grammar of both tools' lines (J-4). rpm prints the
// nine columns, two spaces, the type letter and a space (`%s  %c %s`, rpm
// lib/verify.c); dpkg prints them, one space, the letter and a space
// (`%.9s %c %s`, dpkg src/verify.c). Both spell a file they could not lstat
// as `missing` padded to nine, and both may append ` (strerror)`; rpm also
// appends a non-normal file state (` (replaced)`, ` (not installed)`).
var verifyLineRE = regexp.MustCompile(`^([S.?M5DLUGTP]{9}|missing  )\s{1,3}([a-z ])\s(/.*?)(?: \(([^)]*)\))?$`)

// verifyColumns are rpm(8)'s nine columns in its order: the letter a column
// prints when that attribute differs, and the attribute's name.
var verifyColumns = [9]struct {
	letter byte
	name   string
}{
	{'S', "size"}, {'M', "mode"}, {'5', "digest"}, {'D', "device"}, {'L', "link"},
	{'U', "user"}, {'G', "group"}, {'T', "mtime"}, {'P', "caps"},
}

// verifyFileTypes names rpm's file attribute letters. A letter outside this
// table (rpm's rarely printed `s`, `m`, `n`) is kept as the letter itself, and
// a row is never dropped for carrying one.
var verifyFileTypes = map[byte]string{
	'c': "config", 'd': "doc", 'g': "ghost", 'l': "license", 'r': "readme", 'a': "artifact",
}

// verifyRow is one parsed line.
type verifyRow struct {
	path     string
	attrs    []string // the columns that differ, in the tool's order; ["missing"] for a missing line
	untested int      // the columns the tool printed as `?`
	letter   byte     // the raw type letter, ' ' for none
	note     string   // the parenthesised trailer, without the parentheses
}

// fileType is the row's type letter as a word, or "" for none.
func (r verifyRow) fileType() string {
	if r.letter == ' ' {
		return ""
	}
	if w, ok := verifyFileTypes[r.letter]; ok {
		return w
	}
	return string(r.letter)
}

// verifyParse is what one verify output holds.
type verifyParse struct {
	rows     []verifyRow
	lines    int      // every non-empty line, parsed or not
	unparsed []string // the first verifyHeadLines lines the grammar did not match
}

// verifyHeadLines is how many unparsed stdout (or stderr) lines the stats
// keep.
const verifyHeadLines = 3

// parseVerifyOutput reads rpm -Va or dpkg --verify output. cut says the
// capture stopped early (the output cap or a kill): its last line is then
// dropped rather than parsed, because the path is the last field and a cut
// one is a prefix of the real path — another file's name, or a shorter
// spelling of it.
func parseVerifyOutput(data []byte, cut bool) verifyParse {
	if cut {
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else {
			data = nil
		}
	}
	var p verifyParse
	for _, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p.lines++
		if row, ok := parseVerifyLine(line); ok {
			p.rows = append(p.rows, row)
			continue
		}
		if len(p.unparsed) < verifyHeadLines {
			p.unparsed = append(p.unparsed, sourceRaw(line))
		}
	}
	return p
}

// parseVerifyLine parses one line. A column holding anything but `.`, `?` or
// its own letter is not the tool's output, and the line is not a row.
func parseVerifyLine(line string) (verifyRow, bool) {
	m := verifyLineRE.FindStringSubmatch(line)
	if m == nil {
		return verifyRow{}, false
	}
	row := verifyRow{path: m[3], letter: m[2][0], note: m[4], attrs: []string{}}
	if m[1] == "missing  " {
		row.attrs = append(row.attrs, "missing")
		return row, true
	}
	for i, col := range verifyColumns {
		switch m[1][i] {
		case '.':
		case '?':
			row.untested++
		case col.letter:
			row.attrs = append(row.attrs, col.name)
		default:
			return verifyRow{}, false
		}
	}
	return row, true
}

// dpkgPathFilter is one path-exclude or path-include option of dpkg's
// configuration, in the order dpkg reads them.
type dpkgPathFilter struct {
	include bool
	glob    string
}

// directive renders the filter the way the configuration spells it, which is
// what stats.dpkg_path_excludes records.
func (f dpkgPathFilter) directive() string {
	if f.include {
		return "path-include=" + f.glob
	}
	return "path-exclude=" + f.glob
}

// parseDpkgPathExcludes reads the path filters of one dpkg configuration
// file with dpkg's own line grammar (lib/dpkg/options.c): a `#` in the first
// column is a comment; the option name is the leading run of letters, digits
// and `-`; one separator after it is consumed, then an optional `=` and any
// blanks; a value wholly in matching quotes loses them, and an unbalanced
// quote makes dpkg refuse the line, so it is skipped here. Every other option
// is dpkg's business and is ignored.
func parseDpkgPathExcludes(data []byte) []dpkgPathFilter {
	var out []dpkgPathFilter
	for _, line := range splitLines(data) {
		if line == "" || line[0] == '#' {
			continue
		}
		i := 0
		for i < len(line) && (isASCIIAlnum(line[i]) || line[i] == '-') {
			i++
		}
		name := line[:i]
		if name != "path-exclude" && name != "path-include" || i == len(line) {
			continue
		}
		v := line[i+1:]
		v = strings.TrimPrefix(v, "=")
		v = strings.TrimLeft(v, " \t\n\v\f\r")
		v, ok := stripDpkgQuotes(v)
		if !ok || v == "" {
			continue
		}
		out = append(out, dpkgPathFilter{include: name == "path-include", glob: v})
	}
	return out
}

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// stripDpkgQuotes is dpkg's str_strip_quotes: a value that opens with a quote
// must close with the same one as its last byte.
func stripDpkgQuotes(v string) (string, bool) {
	if v == "" || v[0] != '"' && v[0] != '\'' {
		return v, true
	}
	if len(v) < 2 || v[len(v)-1] != v[0] {
		return "", false
	}
	return v[1 : len(v)-1], true
}

// dpkgGlobRegexp translates a path filter glob into the regexp dpkg's
// fnmatch(pattern, path, 0) decides by. The flags are 0, so there is no
// FNM_PATHNAME and `*` and `?` cross `/`, which is exactly what path.Match
// does NOT do; a backslash quotes the next byte; a bracket expression is kept,
// with its leading `!` spelled `^`. A bracket that never closes is a literal
// `[`, as fnmatch treats it. The result is anchored at both ends.
func dpkgGlobRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			b.WriteString(`(?s:.*)`)
		case '?':
			b.WriteString(`(?s:.)`)
		case '\\':
			if i+1 < len(glob) {
				i++
				b.WriteString(regexp.QuoteMeta(glob[i : i+1]))
			} else {
				b.WriteString(`\\`)
			}
		case '[':
			if class, n, ok := globBracket(glob[i:]); ok {
				b.WriteString(class)
				i += n - 1
			} else {
				b.WriteString(`\[`)
			}
		default:
			b.WriteString(regexp.QuoteMeta(glob[i : i+1]))
		}
	}
	b.WriteString(`$`)
	return regexp.Compile(b.String())
}

// globBracket translates the bracket expression at the start of s and says
// how many bytes of s it took. A `]` straight after the opening (or after its
// `!`/`^`) is a member, not the close, as POSIX has it.
func globBracket(s string) (string, int, bool) {
	var b strings.Builder
	b.WriteByte('[')
	i := 1
	if i < len(s) && (s[i] == '!' || s[i] == '^') {
		b.WriteByte('^')
		i++
	}
	first := true
	for i < len(s) {
		c := s[i]
		switch {
		case c == ']' && !first:
			b.WriteByte(']')
			return b.String(), i + 1, true
		case c == '[' && i+1 < len(s) && s[i+1] == ':':
			// A POSIX class such as [:alpha:], which the regexp syntax shares.
			end := strings.Index(s[i+2:], ":]")
			if end < 0 {
				return "", 0, false
			}
			b.WriteString(s[i : i+2+end+2])
			i += 2 + end + 2
		case c == '\\' && i+1 < len(s):
			// Without FNM_NOESCAPE a backslash quotes the next byte here too.
			b.WriteString(classByte(s[i+1]))
			i += 2
		case c == '\\' || c == '[' || c == '^' || c == ']':
			b.WriteString(classByte(c))
			i++
		default:
			b.WriteByte(c)
			i++
		}
		first = false
	}
	return "", 0, false
}

// verifyFilter is the noise filter's input beyond the rows: dpkg's compiled
// path filters, nil when the rule is not applied.
type verifyFilter struct {
	pathFilters []compiledPathFilter
}

type compiledPathFilter struct {
	include bool
	re      *regexp.Regexp
}

// excluded is dpkg's filter_should_skip: every filter is tried in order and
// the last one that matches decides.
func (f verifyFilter) excluded(p string) bool {
	skip := false
	for _, pf := range f.pathFilters {
		if pf.re.MatchString(p) {
			skip = !pf.include
		}
	}
	return skip
}

// verifyFilterNames are the noise filter's rules in the order they are
// tried; packages.verify.filter records them and filtered_counts counts each.
var verifyFilterNames = []string{"config", "doc", "dpkg_excluded", "ghost", "mtime_only", "unverifiable", "unchanged"}

// verifyDocPrefixes are the documentation trees the doc rule drops whatever
// the type letter: dpkg has no documentation letter, and a minimised install
// never writes them.
var verifyDocPrefixes = []string{"/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/locale/"}

// filterVerifyRows applies the rules of verifyFilterNames in order, the first
// that claims a row deciding it: config moves the row to the configuration
// list; every later rule drops it and counts it; a row no rule claims is a
// modification.
func filterVerifyRows(rows []verifyRow, f verifyFilter) (modified, config []verifyRow, counts map[string]int) {
	counts = make(map[string]int, len(verifyFilterNames))
	for _, n := range verifyFilterNames {
		counts[n] = 0
	}
	for _, r := range rows {
		rule := verifyRule(r, f)
		switch rule {
		case "":
			modified = append(modified, r)
			continue
		case "config":
			config = append(config, r)
		}
		counts[rule]++
	}
	return modified, config, counts
}

// verifyRule names the first rule that claims r, or "" for none.
func verifyRule(r verifyRow, f verifyFilter) string {
	switch {
	case r.letter == 'c':
		return "config"
	case r.letter == 'd' || r.letter == 'l' || r.letter == 'r' || hasDocPrefix(r.path):
		return "doc"
	case f.excluded(r.path):
		return "dpkg_excluded"
	case r.letter == 'g':
		return "ghost"
	case len(r.attrs) == 1 && r.attrs[0] == "mtime":
		return "mtime_only"
	case len(r.attrs) == 0 && r.untested > 0:
		return "unverifiable"
	case len(r.attrs) == 0:
		// All nine columns `.`: rpm printed the row only to carry a file
		// state such as `(not installed)` or `(replaced)`. Nothing differs.
		return "unchanged"
	}
	return ""
}

func hasDocPrefix(p string) bool {
	for _, pre := range verifyDocPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// classByte spells one literal byte inside a regexp character class: ASCII
// punctuation is escaped, anything else is written as it is.
func classByte(c byte) string {
	if c < 0x80 && !isASCIIAlnum(c) {
		return `\` + string(rune(c))
	}
	return string([]byte{c})
}
