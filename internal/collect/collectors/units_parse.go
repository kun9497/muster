package collectors

import (
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The unit-file grammar the units collector reads (P-4, V-4). This file has
// no build tag: it reads bytes, touches nothing, and is tested on every
// platform. The collector (units.go) finds the files and hands each one to
// parseUnitFile, then merges them in systemd's order with mergeUnitFiles.

// execDirectives are the [Service] command lines of systemd.service(5), in
// the order a unit's exec rows are written: the order systemd runs them in.
var execDirectives = []string{
	"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost",
}

// unitFile is what one unit file or drop-in says about the two things the
// collector judges: the user the service runs as, and its command lines.
//
// User is nil when the file does not assign User=, and points at the value
// (possibly "") when it does. Exec holds, per directive, the command lines
// the file assigns in order; an empty assignment resets the list, and a
// file that reset it carries "" as its first element so mergeUnitFiles can
// discard what earlier files said. No other element is ever "".
type unitFile struct {
	User *string
	Exec map[string][]string
}

// parseUnitFile reads a unit file or drop-in per systemd.syntax(7): lines
// starting with # or ; are comments, a line ending in a backslash continues
// on the next (the backslash becoming a space, comment lines inside the
// continuation skipped), whitespace around = is ignored. Only the [Service]
// section is read.
func parseUnitFile(data []byte) unitFile {
	u := unitFile{Exec: map[string][]string{}}
	section := ""
	for _, line := range unitLogicalLines(data) {
		if strings.HasPrefix(line, "[") {
			if end := strings.IndexByte(line, ']'); end > 0 {
				section = line[1:end]
			}
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "User":
			v := value
			u.User = &v
		case isExecDirective(key):
			if value == "" {
				u.Exec[key] = []string{""}
				continue
			}
			u.Exec[key] = append(u.Exec[key], value)
		}
	}
	return u
}

func isExecDirective(key string) bool {
	for _, d := range execDirectives {
		if d == key {
			return true
		}
	}
	return false
}

// unitLogicalLines joins continued lines and drops blank and comment lines.
func unitLogicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	continuing := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			// A comment inside a continuation is skipped and the
			// continuation joins what follows it.
			continue
		}
		if !continuing && line == "" {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continuing = true
			continue
		}
		cur.WriteString(line)
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
		continuing = false
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// mergeUnitFiles applies files in the order given — the unit file, then its
// drop-ins in the order the collector chose — the way systemd loads them: a
// later User= wins, a later command line is appended to its directive's
// list, and a file that reset a directive discards everything earlier files
// assigned to it.
func mergeUnitFiles(files []unitFile) unitFile {
	out := unitFile{Exec: map[string][]string{}}
	for _, f := range files {
		if f.User != nil {
			v := *f.User
			out.User = &v
		}
		for _, d := range execDirectives {
			lines, ok := f.Exec[d]
			if !ok {
				continue
			}
			if len(lines) > 0 && lines[0] == "" {
				out.Exec[d] = append([]string{}, lines[1:]...)
				continue
			}
			out.Exec[d] = append(out.Exec[d], lines...)
		}
	}
	for d, lines := range out.Exec {
		if len(lines) == 0 {
			delete(out.Exec, d)
		}
	}
	return out
}

// execPrefixes are the special executable prefixes of systemd.service(5)
// "Command lines" (V-4): @ - : + ! and, from systemd 258, | ; "!!" is two
// "!" and is stripped the same way.
const execPrefixes = "@-:+!|"

// execCommands splits an Exec*= value into its commands: a word that is a
// lone, unquoted ";" separates two commands (systemd's config_parse_exec;
// "\;" is a literal argument). Each command is returned as written.
func execCommands(line string) []string {
	var out []string
	start := 0
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		wordStart := i
		quote := byte(0)
		for i < len(line) {
			c := line[i]
			if quote != 0 {
				switch c {
				case quote:
					quote = 0
				case '\\':
					i++
				}
				i++
				continue
			}
			if c == ' ' || c == '\t' {
				break
			}
			switch c {
			case '"', '\'':
				quote = c
			case '\\':
				i++
			}
			i++
		}
		if i > len(line) {
			i = len(line)
		}
		if line[wordStart:i] == ";" {
			if s := strings.TrimSpace(line[start:wordStart]); s != "" {
				out = append(out, s)
			}
			start = i
		}
	}
	if s := strings.TrimSpace(line[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

// execFirstToken is the executable a command line runs: the first item is
// unquoted per systemd.syntax(7) and then the prefixes are stripped, in
// systemd's order. resolved is true only for an absolute, clean path with no
// % specifier — a bare name (searched in systemd's built-in PATH since
// v239), a variable, a specifier such as a template's %i or %I, or a
// malformed quote is not a path muster can stat.
func execFirstToken(line string) (string, bool) {
	tok, ok := unquoteFirstItem(strings.TrimLeft(line, " \t"))
	tok = strings.TrimLeft(tok, execPrefixes)
	if !ok || tok == "" {
		return tok, false
	}
	resolved := strings.HasPrefix(tok, "/") && !strings.Contains(tok, "%") && path.Clean(tok) == tok
	return tok, resolved
}

// unquoteFirstItem reads the first whitespace-separated item of s the way
// systemd's extract_first_word does with EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE:
// a quote opens anywhere in the word and must be closed, and C escapes are
// undone inside and outside quotes. ok is false for a malformed item.
func unquoteFirstItem(s string) (string, bool) {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
			i++
			continue
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
			i++
			continue
		case quote == 0 && (c == ' ' || c == '\t'):
			return b.String(), true
		case c == '\\':
			r, n, ok := unitEscape(s[i+1:])
			if !ok {
				return b.String(), false
			}
			b.WriteRune(r)
			i += 1 + n
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), quote == 0
}

// unitEscape decodes one C escape of systemd.syntax(7) after its backslash,
// returning the rune and how many bytes it consumed.
func unitEscape(s string) (rune, int, bool) {
	if s == "" {
		return 0, 0, false
	}
	switch s[0] {
	case 'a':
		return '\a', 1, true
	case 'b':
		return '\b', 1, true
	case 'f':
		return '\f', 1, true
	case 'n':
		return '\n', 1, true
	case 'r':
		return '\r', 1, true
	case 't':
		return '\t', 1, true
	case 'v':
		return '\v', 1, true
	case 's':
		return ' ', 1, true
	case '\\', '"', '\'':
		return rune(s[0]), 1, true
	case 'x':
		return unitNumEscape(s, 1, 2, 16)
	case 'u':
		return unitNumEscape(s, 1, 4, 16)
	case 'U':
		return unitNumEscape(s, 1, 8, 16)
	}
	if s[0] >= '0' && s[0] <= '7' {
		return unitNumEscape(s, 0, 3, 8)
	}
	return 0, 0, false
}

func unitNumEscape(s string, skip, digits, base int) (rune, int, bool) {
	if len(s) < skip+digits {
		return 0, 0, false
	}
	n, err := strconv.ParseUint(s[skip:skip+digits], base, 32)
	if err != nil || n == 0 || n > utf8.MaxRune {
		return 0, 0, false
	}
	return rune(n), skip + digits, true
}

// parseListUnits is the unit column of `systemctl list-units --plain
// --no-legend`: rows are UNIT LOAD ACTIVE SUB [JOB] DESCRIPTION and only the
// first field is read (V-4). A leading status bullet, which --plain omits, is
// skipped all the same.
func parseListUnits(data []byte) []string {
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		f := strings.Fields(raw)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:]
		}
		if len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

// templateOf names the template an instance is loaded from:
// foo@bar.service → foo@.service, true. A plain unit, and a template
// itself, is not an instance.
func templateOf(unit string) (string, bool) {
	at := strings.IndexByte(unit, '@')
	dot := strings.LastIndexByte(unit, '.')
	if at < 0 || dot < at+2 {
		return unit, false
	}
	return unit[:at+1] + unit[dot:], true
}
