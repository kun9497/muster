//go:build linux

package collectors

import (
	"path"
	"slices"
	"strconv"
	"strings"
)

// auditRule is one non-comment line of a persisted rules file, in the order
// the file carries it.
type auditRule struct {
	file string
	line int
	kind string // watch | syscall | control | other
	key  string
	text string
}

// auditControlFlags are the auditctl options that configure the kernel's
// audit subsystem rather than add a rule (auditctl(8)): delete all, the
// backlog, the failure mode, enable, the rate, the backlog wait time, the
// loginuid lock, and the two "carry on past an error" switches.
var auditControlFlags = map[string]bool{
	"-D": true, "-b": true, "-f": true, "-e": true, "-r": true,
	"--backlog_wait_time": true, "--loginuid-immutable": true,
	"-c": true, "-i": true,
}

// auditFlag is the option a rules line starts with, as getopt reads it: a
// long option up to its "=", a short option as its first two bytes, so
// "-b8192" and "--backlog_wait_time=60000" name the same options as their
// spaced spellings.
func auditFlag(tok string) string {
	if strings.HasPrefix(tok, "--") {
		name, _, _ := strings.Cut(tok, "=")
		return name
	}
	if len(tok) >= 2 && tok[0] == '-' {
		return tok[:2]
	}
	return tok
}

func auditKind(flag string) string {
	switch {
	case flag == "-w":
		return "watch"
	case flag == "-a" || flag == "-A":
		return "syscall"
	case auditControlFlags[flag]:
		return "control"
	}
	return "other"
}

// auditRuleKey is the rule's filter key: the argument of -k, or the value of
// a key= field (the form auditctl -l prints and -F key= accepts). The first
// one wins; a rule may carry several and the first names it.
func auditRuleKey(fields []string) string {
	for i, f := range fields {
		switch {
		case f == "-k":
			if i+1 < len(fields) {
				return fields[i+1]
			}
		case strings.HasPrefix(f, "-k"):
			return f[2:]
		case strings.HasPrefix(f, "key="):
			return f[len("key="):]
		case strings.HasPrefix(f, "-Fkey="):
			return f[len("-Fkey="):]
		}
	}
	return ""
}

// parseAuditRules reads one rules file the way augenrules reads it: blank
// lines and lines whose first non-blank character is "#" carry nothing, and
// every other line is one row, whatever it says (augenrules has no inline
// comment either). The row keeps its line number, so a finding can point at
// the line.
func parseAuditRules(data []byte, file string) []auditRule {
	var out []auditRule
	for i, l := range splitLines(data) {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.Fields(t)
		out = append(out, auditRule{
			file: file,
			line: i + 1,
			kind: auditKind(auditFlag(fields[0])),
			key:  sourceRaw(auditRuleKey(fields)),
			text: sourceRaw(t),
		})
	}
	return out
}

// lastEnableValue is the value of the LAST -e line in load order. augenrules
// keeps only that one (its awk overwrites minus_e on every -e line and prints
// it last), and auditctl(8) locks the configuration at -e 2, so a later -e
// line could never take effect anyway: the last one written is the intent.
// An -e whose argument is not an integer is found with value -1, which no
// reader mistakes for the lock.
func lastEnableValue(rules []auditRule) (value int, file string, found bool) {
	r, found := lastEnableRule(rules)
	if !found {
		return 0, "", false
	}
	fields := strings.Fields(r.text)
	arg := strings.TrimPrefix(fields[0], "-e")
	if arg == "" && len(fields) > 1 {
		arg = fields[1]
	}
	n, err := strconv.Atoi(arg)
	if err != nil {
		n = -1
	}
	return n, r.file, true
}

// lastEnableRule is the row lastEnableValue decides on: the last control
// line whose option is -e. The persisted envelope and the setting's winner
// cite it.
func lastEnableRule(rules []auditRule) (auditRule, bool) {
	var last auditRule
	found := false
	for _, r := range rules {
		if r.kind == "control" && auditFlag(strings.Fields(r.text)[0]) == "-e" {
			last, found = r, true
		}
	}
	return last, found
}

// augenrulesOrder is the order augenrules loads the rules.d files in: it
// lists the directory with `/bin/ls -1v`, so the *.rules names are in GNU
// version order — 9-lock.rules before 10-site.rules — and the dot-files ls
// never names are dropped.
func augenrulesOrder(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if !strings.HasPrefix(path.Base(p), ".") {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y string) int { return versionCompare(path.Base(x), path.Base(y)) })
	return out
}

// versionCompare is ls -v's comparison (gnulib filevercmp) for the names a
// *.rules glob can return: the ".rules" suffix is set aside and the prefixes
// compared first, then the whole names, and a final tie falls back to
// strings.Compare, as ls breaks a version tie with strcmp. filevercmp's
// fuller suffix rule (any trailing run of ".alpha" parts) only matters for
// names with more than one such part, which augenrules' own files do not use.
func versionCompare(x, y string) int {
	px, py := strings.TrimSuffix(x, ".rules"), strings.TrimSuffix(y, ".rules")
	if c := verrevcmp(px, py); c != 0 {
		return c
	}
	if c := verrevcmp(x, y); c != 0 {
		return c
	}
	return strings.Compare(x, y)
}

// verrevcmp is filevercmp's core, the Debian version comparison: a run of
// non-digits compares character by character with letters before other
// bytes and the end of a run before either, then a run of digits compares by
// numeric value, leading zeros ignored.
func verrevcmp(s1, s2 string) int {
	i, j := 0, 0
	for i < len(s1) || j < len(s2) {
		for (i < len(s1) && !isDigit(s1[i])) || (j < len(s2) && !isDigit(s2[j])) {
			c1, c2 := verOrder(s1, i), verOrder(s2, j)
			if c1 != c2 {
				return c1 - c2
			}
			i++
			j++
		}
		for i < len(s1) && s1[i] == '0' {
			i++
		}
		for j < len(s2) && s2[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(s1) && j < len(s2) && isDigit(s1[i]) && isDigit(s2[j]) {
			if firstDiff == 0 {
				firstDiff = int(s1[i]) - int(s2[j])
			}
			i++
			j++
		}
		if i < len(s1) && isDigit(s1[i]) {
			return 1
		}
		if j < len(s2) && isDigit(s2[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

// verOrder is filevercmp's character weight: the end of the string lowest,
// then a digit, then letters by value, then every other byte above them.
func verOrder(s string, i int) int {
	if i >= len(s) {
		return -1
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseAuditdConf reads auditd.conf's "keyword = value" lines. A line whose
// first non-blank character is "#" is a comment (the shipped file's
// "##name = mydomain" is one), a line without "=" sets nothing, and a later
// line for the same keyword replaces an earlier one. Keywords are
// lower-cased, as the daemon matches them case-insensitively; so are the
// action values, which auditd.conf(5) reads case-insensitively. log_file is
// a path and log_group a group name — the daemon passes both to the kernel
// and getgrnam as written — so those two keep their case.
func parseAuditdConf(data []byte) map[string]string {
	out := map[string]string{}
	for _, l := range splitLines(data) {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if k != "log_file" && k != "log_group" {
			v = strings.ToLower(v)
		}
		out[k] = sourceRaw(v)
	}
	return out
}

// parseAuditctlStatus reads auditctl -s: one "<name> <integer>" line per
// field, and the loginuid_immutable line's third word ("unlocked") after its
// integer. Each name takes the first integer after it; the first line for a
// name wins. ok is whether an enabled line parsed — without it the kernel
// gave no status, whatever else was printed.
func parseAuditctlStatus(data []byte) (fields map[string]int, ok bool) {
	fields = map[string]int{}
	for _, l := range splitLines(data) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		if _, dup := fields[f[0]]; dup {
			continue
		}
		for _, w := range f[1:] {
			if n, err := strconv.Atoi(w); err == nil {
				fields[f[0]] = n
				break
			}
		}
	}
	_, ok = fields["enabled"]
	return fields, ok
}

// auditctlRuleLines are the rule lines of auditctl -l: every non-blank line
// but the "No rules" it prints when the kernel holds none.
func auditctlRuleLines(data []byte) []string {
	var out []string
	for _, l := range splitLines(data) {
		t := strings.TrimSpace(l)
		if t == "" || t == "No rules" {
			continue
		}
		out = append(out, t)
	}
	return out
}
