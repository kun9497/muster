//go:build linux

package collectors

import (
	"path"
	"slices"
	"strings"
)

// aideConf is what the fim collector reads from an AIDE configuration file:
// the database it checks against, and the macros that path names but the
// file never defines.
type aideConf struct {
	database   string   // the file: value, macros substituted
	found      bool     // a database_in= or database= line was there
	unresolved []string // @@{NAME} references with no @@define, in order
}

// parseAideConf reads an aide.conf (spec I-4, J-5). Every @@define is
// collected first, wherever it stands, and substituted into the @@{NAME}
// references of the database path; database_in= (aide 0.17 and later) wins
// over database= (older), and the first line of each counts, as the Debian
// cron script's `grep | head -n 1` reads it. Every other @@ directive —
// @@include (EL9), @@x_include and @@x_include_setenv (Ubuntu) — is ignored:
// none of them can set the database path this key reports.
func parseAideConf(data []byte) aideConf {
	defines := map[string]string{}
	var in, old string
	var haveIn, haveOld bool
	for _, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' {
			continue
		}
		if strings.HasPrefix(l, "@@") {
			if f := strings.Fields(l); f[0] == "@@define" && len(f) >= 2 {
				defines[f[1]] = strings.Join(f[2:], " ")
			}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "database_in":
			if !haveIn {
				in, haveIn = v, true
			}
		case "database":
			if !haveOld {
				old, haveOld = v, true
			}
		}
	}
	var c aideConf
	switch {
	case haveIn:
		c.database, c.found = in, true
	case haveOld:
		c.database, c.found = old, true
	default:
		return c
	}
	c.database = strings.TrimPrefix(c.database, "file:")
	c.database, c.unresolved = expandAideMacros(c.database, defines)
	return c
}

// expandAideMacros substitutes @@{NAME} references. A define may itself name
// another macro, so the expansion repeats a bounded number of times; a
// reference no define answers is left as written and returned by name.
func expandAideMacros(s string, defines map[string]string) (string, []string) {
	for range 8 {
		next, changed := expandAideOnce(s, defines)
		s = next
		if !changed {
			break
		}
	}
	var unresolved []string
	for rest := s; ; {
		i := strings.Index(rest, "@@{")
		if i < 0 {
			break
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			break
		}
		if name := rest[i+3 : i+j]; !slices.Contains(unresolved, name) {
			unresolved = append(unresolved, name)
		}
		rest = rest[i+j+1:]
	}
	return s, unresolved
}

func expandAideOnce(s string, defines map[string]string) (string, bool) {
	var out strings.Builder
	changed := false
	for {
		i := strings.Index(s, "@@{")
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			break
		}
		name := s[i+3 : i+j]
		v, ok := defines[name]
		if !ok {
			out.WriteString(s[:i+j+1])
			s = s[i+j+1:]
			continue
		}
		out.WriteString(s[:i])
		out.WriteString(v)
		s = s[i+j+1:]
		changed = true
	}
	out.WriteString(s)
	return out.String(), changed
}

// listedTimer is one row of `systemctl list-timers --all --no-legend`.
type listedTimer struct {
	unit  string
	armed bool // the row shows a next elapse time
}

// parseListTimers reads the --no-legend layout, NEXT LEFT LAST PASSED UNIT
// ACTIVATES, whose time columns hold a variable number of words. The unit is
// the first field ending in .timer; a row whose NEXT is n/a (systemd 249 and
// 252) or - (255) will not elapse, so it is not armed.
func parseListTimers(data []byte) []listedTimer {
	var out []listedTimer
	for _, line := range splitLines(data) {
		f := strings.Fields(line)
		i := slices.IndexFunc(f, func(s string) bool { return strings.HasSuffix(s, ".timer") })
		if i < 0 {
			continue
		}
		out = append(out, listedTimer{unit: f[i], armed: i > 0 && f[0] != "n/a" && f[0] != "-"})
	}
	return out
}

// cronDailyRun is the last CRON_DAILY_RUN assignment of /etc/default/aide,
// quotes removed, and whether there was one. The file is sourced by a shell,
// so a commented line is no assignment, and the value ends at unquoted
// whitespace.
func cronDailyRun(data []byte) (string, bool) {
	value, set := "", false
	for _, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		l = strings.TrimSpace(strings.TrimPrefix(l, "export "))
		v, ok := strings.CutPrefix(l, "CRON_DAILY_RUN=")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'"):
			q := v[:1]
			if j := strings.Index(v[1:], q); j >= 0 {
				v = v[1 : j+1]
			} else {
				v = v[1:]
			}
		default:
			if j := strings.IndexAny(v, " \t;#"); j >= 0 {
				v = v[:j]
			}
		}
		value, set = v, true
	}
	return value, set
}

// aideCommands are the basenames that run an AIDE check: the binary, the
// Debian wrapper and init script, EL's check unit's script name and Ubuntu
// 24.04's daily check.
var aideCommands = []string{"aide", "aide.wrapper", "aideinit", "aide-check", "dailyaidecheck"}

// aideBinDirs are the directories a path token may run an AIDE command from.
var aideBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

// runsAide reports whether one command-field token runs AIDE: its basename is
// one of aideCommands and it is either bare (found on PATH) or a path in one
// of aideBinDirs. So `nice -n 19 /usr/bin/aide --check` counts, while
// `find /var/log/aide …` or `cp /etc/aide/aide.conf …` does not.
func runsAide(tok string) bool {
	tok = strings.Trim(tok, `;&|()'"`+"`")
	if !slices.Contains(aideCommands, path.Base(tok)) {
		return false
	}
	return !strings.Contains(tok, "/") || slices.Contains(aideBinDirs, path.Dir(tok))
}

// namesAide reports whether a system crontab (/etc/crontab, /etc/cron.d/*)
// has a line whose COMMAND runs aide (runsAide on any of its tokens). The
// user field is not the command, so a user called adelaide does not count; a
// commented line, the usual way a check is switched off, is no line at all;
// an environment assignment is not a job.
func namesAide(data []byte) bool {
	for _, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		var cmd []string
		switch {
		case strings.HasPrefix(f[0], "@"):
			if len(f) >= 3 {
				cmd = f[2:]
			}
		case strings.Contains(f[0], "="):
			continue
		case len(f) >= 7:
			cmd = f[6:]
		}
		if slices.ContainsFunc(cmd, runsAide) {
			return true
		}
	}
	return false
}
