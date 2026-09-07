//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	sshdConfigPath  = "/etc/ssh/sshd_config"
	sshdConfigDir   = "/etc/ssh/sshd_config.d/*.conf"
	permitRootLogin = "permitrootlogin"
	maxIncludeDepth = 8

	// maxTokenValue caps a single keyword value muster stores (M16). A
	// keyword's value is a word — "yes", "prohibit-password" — and the read
	// and output limits above it are megabytes, so without this cap one
	// pathological line of a file or of a command's output would be copied
	// whole into the snapshot. A longer token is not a value that was
	// misread; it is not a value at all, so none of it is stored.
	maxTokenValue = 4 << 10
)

// R168: the conventional banner paths live here (T1 lands before the banners
// collector), so the sshd guard can allow the Banner-file stat. T3's
// banners.go reuses these two constants and defines only motdPath/motdDGlob;
// it must NOT redeclare issuePath/issueNetPath (one package, one definition).
const (
	issuePath    = "/etc/issue"
	issueNetPath = "/etc/issue.net"
)

var (
	sshdG        = collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-G"}}
	sshdT        = collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}
	sshdV        = collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-V"}}
	sshdCRoot    = personaCmd("root")
	sshdCUser    = personaCmd("nobody")
	sshdCInvalid = personaCmd("muster-nx-user")
)

// personaCmd builds `sshd -T -C user=<u>,host=localhost,addr=127.0.0.1,lport=22`.
// The full tuple is given because some OpenSSH versions refuse a connection
// spec that names only a user; the lab's 8.9 accepts either, and the extra
// fields never change a Match that keys on the user.
func personaCmd(user string) collect.Command {
	return collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-T", "-C",
		"user=" + user + ",host=localhost,addr=127.0.0.1,lport=22"}}
}

// personaOrder is the fixed order personas are queried and recorded in, so a
// snapshot is byte-stable. The names are the clause vocabulary (spec §6.6).
var personaOrder = []struct {
	name string
	cmd  collect.Command
}{
	{"root", sshdCRoot},
	{"user", sshdCUser},
	{"invalid", sshdCInvalid},
}

var sshdCollector = collect.Collector{
	Name: "sshd",
	Declare: collect.Declaration{
		// R168: /etc/issue and /etc/issue.net are declared so the guard's
		// Allowed lets writeBannerFile stat the file a stock Banner names;
		// any other Banner path is refused and recorded (see writeBannerFile).
		Reads:    []string{sshdConfigPath, sshdConfigDir, issueNetPath, issuePath},
		Commands: []collect.Command{sshdG, sshdT, sshdV, sshdCRoot, sshdCUser, sshdCInvalid},
		Needs:    "root",
	},
	Run: runSshd,
}

// sshdOption names one option muster stores and how its parsed value is
// folded. `numeric` marks an int-typed setting; the rest are folded strings
// (a multistate value case-insensitively, a path or command line verbatim).
type sshdOption struct {
	keyword string // lower-case sshd keyword
	key     string // registry key under sshd.options
	numeric bool
}

var sshdOptions = []sshdOption{
	{permitRootLogin, "sshd.options.permit_root_login", false},
	{"maxauthtries", "sshd.options.max_auth_tries", true},
	{"clientaliveinterval", "sshd.options.client_alive_interval", true},
	{"clientalivecountmax", "sshd.options.client_alive_count_max", true},
	{"banner", "sshd.options.banner", false},
}

// runSshd fills sshd.* (spec §10.2) by the method ladder: sshd -G, then
// sshd -T, then parsing the files. When the daemon answered, three -T -C
// persona queries record per-persona (Match) overrides, and the file
// sshd's Banner names is stat'd (C1).
func runSshd(ctx context.Context, a collect.Access, b *collect.Builder) error {
	// 1. The daemon side, by the method ladder: -G, then -T. Each returns a
	//    parsed map of keyword -> value and the command's source, or nil when
	//    that rung did not answer.
	daemon, method, dsrc, dtrunc := sshdDaemon(ctx, a)
	b.Set("sshd.version", sshdVersion(ctx, a))

	// 2. The parsed side and the include sources, always (they are the
	//    persisted side and they answer when the daemon does not).
	parsed := map[string]facts.Envelope{}
	for _, o := range sshdOptions {
		if env, found := parseSshdConfig(a, sshdConfigPath, o.keyword, 0); found {
			parsed[o.keyword] = env
		}
	}
	b.Set("sshd.include_sources", collectIncludeSources(a, sshdConfigPath))

	// 3. Personas: only when the daemon answered (a parse cannot re-evaluate
	//    Match). All three must succeed, or the flag stays false.
	personas, personasOK := sshdPersonas(ctx, a, method)
	b.Set("sshd.personas_collected", collect.OK(personasOK, dsrc))
	b.Set("sshd.collect_method", withTruncation(collect.OK(method, methodSource(method, dsrc)), dtrunc))

	// 4. Assemble each option as a setting with its per-persona overrides.
	for _, o := range sshdOptions {
		s := sshdSetting(o, daemon, dsrc, dtrunc, method, parsed[o.keyword])
		if personasOK {
			for _, p := range personaOrder {
				if pv, ok := personas[p.name][o.keyword]; ok && daemon != nil {
					if global, gok := daemon[o.keyword]; !gok || pv != global {
						if s.Personas == nil {
							s.Personas = map[string]*facts.Envelope{}
						}
						e := optionEnvelope(o, pv, personaSource(p.cmd))
						s.Personas[p.name] = &e
					}
				}
			}
		}
		b.SetSetting(o.key, s)
	}

	// 5. The Banner file: a discovered path, stat'd by the daemon's own
	//    collector (C1). "none" is the default and means no pre-auth banner.
	//    R172 (C3): when the daemon did not answer and the config that would
	//    set Banner could not be read (denied/error/timeout), that read's
	//    status — not a definite "no banner" — is the answer for both
	//    banner_file leaves; a false here would hide the read failure and
	//    publish the module's default as if it were the host's state.
	if daemon == nil {
		if e, ok := parsed["banner"]; ok {
			switch e.Status {
			case facts.StatusDenied, facts.StatusError, facts.StatusTimeout:
				b.Set("sshd.banner_file.exists", e)
				b.Set("sshd.banner_file.nonempty", e)
				return nil
			}
		}
	}
	writeBannerFile(a, b, bannerPath(daemon, parsed))
	return nil
}

// sshdDaemon runs the method ladder. It returns the daemon's option map
// (keyword -> raw value), the method ("G", "T" or "parse"), the source of
// the command that answered — or, on a fall to parse, the last command that
// actually ran and failed, and nil when no command ever started (so the
// method cites the failing exit that forced the fallback, matching the
// stage-1 rule) — and whether that command's capture was truncated.
func sshdDaemon(ctx context.Context, a collect.Access) (map[string]string, string, *facts.Source, bool) {
	var lastSrc *facts.Source
	for _, rung := range []struct {
		method string
		cmd    collect.Command
	}{{"G", sshdG}, {"T", sshdT}} {
		out := a.Run(ctx, rung.cmd)
		src := out.Source(rung.cmd)
		if out.Err == nil {
			// The command started (a non-zero exit sets ExitCode, not Err),
			// so it can be cited as the reason a later "parse" was chosen.
			lastSrc = src
		}
		switch {
		case out.Err != nil:
			continue // the binary or that option is not there; try the next rung
		case out.TimedOut:
			continue
		case out.ExitCode != 0:
			// R84/R88/R169: a privilege failure or a socket-activated -T that
			// cannot reach /run/sshd is not a value; drop to the next rung
			// (and finally to parse), where the files answer.
			continue
		default:
			m := parseDaemonDump(out.Stdout)
			if len(m) == 0 {
				continue
			}
			return m, rung.method, src, out.Truncated
		}
	}
	return nil, "parse", lastSrc, false
}

// parseDaemonDump reads the `keyword value` lines -G and -T print (lower-case
// keywords, one directive per line) into a map, keeping only the options
// muster stores. The first line for a keyword wins, matching sshd's dump.
func parseDaemonDump(stdout []byte) map[string]string {
	want := map[string]bool{}
	for _, o := range sshdOptions {
		want[o.keyword] = true
	}
	m := map[string]string{}
	for _, line := range splitLines(stdout) {
		f := configTokens(line)
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if want[k] {
			if _, seen := m[k]; !seen {
				m[k] = f[1]
			}
		}
	}
	return m
}

// sshdVersion parses OpenSSH_<major>.<minor> from `sshd -V`. Every OpenSSH
// prints its banner for -V — newer to stdout with exit 0, 8.9 to stderr as
// part of the "unknown option" message — so both streams are searched and
// the exit code is ignored.
func sshdVersion(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, sshdV)
	src := out.Source(sshdV)
	if out.Err != nil {
		return withSource(collect.Absent("sshd -V could not be run: "+runErr(out)), src)
	}
	m := versionRe.FindSubmatch(append(append([]byte{}, out.Stdout...), out.Stderr...))
	if m == nil {
		return withSource(collect.Absent("no OpenSSH version in sshd -V output"), src)
	}
	return withTruncation(collect.OK(string(m[1]), src), out.Truncated)
}

var versionRe = regexp.MustCompile(`OpenSSH_(\d+\.\d+)`)

// sshdPersonas runs the three -T -C queries when the daemon answered. It
// returns a persona-name -> (keyword -> value) map and whether ALL three
// succeeded; a single failure returns ok=false so the flag stays false
// (a half-collected set would hide a Match block — spec §6.5 step 13).
func sshdPersonas(ctx context.Context, a collect.Access, method string) (map[string]map[string]string, bool) {
	if method == "parse" {
		return nil, false
	}
	out := map[string]map[string]string{}
	for _, p := range personaOrder {
		r := a.Run(ctx, p.cmd)
		if r.Err != nil || r.TimedOut || r.ExitCode != 0 {
			return out, false
		}
		m := parseDaemonDump(r.Stdout)
		if len(m) == 0 {
			return out, false
		}
		out[p.name] = m
	}
	return out, true
}

// sshdSetting builds one option's setting from the daemon map and the parsed
// envelope, following the effective-side rule (spec §5.3, R59): effective is
// the daemon value when the daemon answered, else the parsed value marked so
// the parse-fallback degradation fires, else absent.
func sshdSetting(o sshdOption, daemon map[string]string, dsrc *facts.Source, dtrunc bool, method string, parsed facts.Envelope) facts.Setting {
	var s facts.Setting
	if daemon != nil {
		if v, ok := daemon[o.keyword]; ok {
			e := optionEnvelope(o, v, dsrc)
			e = withTruncation(e, dtrunc)
			s.Runtime = &e
		} else {
			e := collect.Absent(o.keyword + " not in sshd -" + method + " output")
			e.Source = dsrc
			s.Runtime = &e
		}
	}
	if parsed.Status != "" {
		p := parsed
		// R165: parseSshdConfig returns a string for every non-multistate
		// keyword. A numeric option's persisted (and, on fallback, effective)
		// side must be an int envelope, or compare()->toInt gives
		// ERROR(internal_error). Re-wrap through the int branch, keeping the
		// file source; an unparseable file value becomes an error side.
		if o.numeric && p.Status == facts.StatusOK {
			if str, ok := p.Value.(string); ok {
				// R174: optionEnvelope rewraps through collect.OK, which drops
				// the Truncated flag the parsed OKRead carried. Carry it across
				// so a truncated numeric config read is never judged as a clean
				// value.
				p = withTruncation(optionEnvelope(o, str, p.Source), parsed.Truncated)
			}
		}
		s.Persisted = &p
	}
	switch {
	case s.Runtime != nil && s.Runtime.Status == facts.StatusOK:
		eff := *s.Runtime
		s.Effective = &eff
	case s.Persisted != nil:
		eff := *s.Persisted
		if eff.Status == facts.StatusOK {
			eff.Reason = "parsed files; sshd -" + methodLabel(method) + " unavailable"
		}
		s.Effective = &eff
	case s.Runtime != nil:
		eff := *s.Runtime
		s.Effective = &eff
	default:
		eff := collect.Absent("no sshd daemon output and no readable sshd_config for " + o.keyword)
		s.Effective = &eff
	}
	return s
}

// optionEnvelope wraps a raw value as the right typed envelope: an int for a
// numeric option (an unparseable number is an error, never a stored blob), a
// folded string otherwise. oversized values are refused (M16).
func optionEnvelope(o sshdOption, raw string, src *facts.Source) facts.Envelope {
	if oversized(raw) {
		return withSource(collect.ErrorEnv(oversizedReason), src)
	}
	if o.numeric {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return withSource(collect.ErrorEnv(o.keyword+": not an integer: "+raw), src)
		}
		return collect.OK(n, src)
	}
	return collect.OK(keywordValue(o.keyword, raw), src)
}

// bannerPath resolves the effective Banner value from the daemon map, then
// the parsed file. "" means unknown; "none" is sshd's default (no banner).
func bannerPath(daemon map[string]string, parsed map[string]facts.Envelope) string {
	if daemon != nil {
		if v, ok := daemon["banner"]; ok {
			return v
		}
	}
	if e, ok := parsed["banner"]; ok && e.Status == facts.StatusOK {
		if v, isStr := e.Value.(string); isStr {
			return v
		}
	}
	return ""
}

// writeBannerFile stats the file Banner names. "none" or "" means the daemon
// serves no pre-auth banner, so exists/nonempty are a definite false, not an
// error. A path that cannot be stat'd carries the read error.
func writeBannerFile(a collect.Access, b *collect.Builder, p string) {
	if p == "" || strings.EqualFold(p, "none") {
		src := &facts.Source{Kind: "derived"}
		b.Set("sshd.banner_file.exists", collect.OK(false, src))
		b.Set("sshd.banner_file.nonempty", collect.OK(false, src))
		return
	}
	src := &facts.Source{Kind: "file", Path: p}
	// R168: the Banner file is a discovered path. Reading a path outside the
	// declaration is recorded, never requested (the same precedent the
	// Include expansion sets); a stock Banner (/etc/issue.net, /etc/issue)
	// is declared and read normally.
	if !declared(a, p) {
		e := collect.ErrorEnv("Banner " + p + " is outside the collector's declaration")
		e.Source = src
		b.Set("sshd.banner_file.exists", e)
		b.Set("sshd.banner_file.nonempty", e)
		return
	}
	data, meta, err := a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			b.Set("sshd.banner_file.exists", collect.OK(false, src))
			b.Set("sshd.banner_file.nonempty", collect.OK(false, src))
			return
		}
		e := collect.FromReadError(err, meta)
		b.Set("sshd.banner_file.exists", e)
		b.Set("sshd.banner_file.nonempty", e)
		return
	}
	b.Set("sshd.banner_file.exists", collect.OKRead(true, src, meta))
	b.Set("sshd.banner_file.nonempty", collect.OKRead(len(strings.TrimSpace(string(data))) > 0, src, meta))
}

// collectIncludeSources records every Include the parse followed, in
// expansion order, as {path, line, depth} records. It walks the same way
// parseSshdConfig does but gathers Include directives rather than a keyword,
// and stops at the same depth bound. It never fails the collector: an
// unreadable drop-in simply ends that branch (the option settings already
// carry that read's error on their persisted side).
func collectIncludeSources(a collect.Access, file string) facts.Envelope {
	var out []any
	var walk func(file string, depth int)
	walk = func(file string, depth int) {
		if depth > maxIncludeDepth {
			return
		}
		data, _, err := a.ReadFile(file, readLimit)
		if err != nil {
			return
		}
		for i, raw := range splitLines(data) {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := configTokens(line)
			key := strings.ToLower(f[0])
			if key == "match" {
				break
			}
			if key == "include" && len(f) >= 2 {
				for _, pattern := range f[1:] {
					if !declared(a, pattern) {
						continue
					}
					matches, err := a.Glob(pattern)
					if err != nil {
						continue
					}
					slices.Sort(matches)
					for _, m := range matches {
						out = append(out, map[string]any{
							"path": path.Clean(m), "line": i + 1, "depth": depth + 1,
						})
						walk(path.Clean(m), depth+1)
					}
				}
			}
		}
	}
	walk(file, 0)
	if out == nil {
		out = []any{} // R50: an empty result is [], never null
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: file})
}

func withSource(e facts.Envelope, src *facts.Source) facts.Envelope { e.Source = src; return e }

// methodSource cites the command that decided the method; a "parse" reached
// because no command started has none, matching the stage-1 rule.
func methodSource(method string, dsrc *facts.Source) *facts.Source {
	if method == "parse" && dsrc == nil {
		return nil
	}
	return dsrc
}

func personaSource(c collect.Command) *facts.Source { return collect.Output{}.Source(c) }

func methodLabel(method string) string {
	if method == "G" {
		return "G"
	}
	return "T"
}

func runErr(out collect.Output) string {
	if out.Err != nil {
		return out.Err.Error()
	}
	return "exit " + strconv.Itoa(out.ExitCode)
}

// parseSshdConfig resolves keyword the way sshd itself does: an Include is
// read where the directive appears, its matches in sorted order, and the
// FIRST occurrence of a keyword anywhere in that walk wins. depth guards
// against an Include loop.
//
// The bool result distinguishes "this file answered" from "keep looking".
// Only a file that is NOT THERE may be skipped, and only below the top
// level: a drop-in that exists but could not be read — a symlink the
// primitive refuses, a non-regular file, EACCES — may have carried a
// higher-priority PermitRootLogin, so falling through to the main file and
// publishing its value as ok would be a PASS on evidence never seen. That
// read failure becomes the answer instead (the same rule services.go
// applies to an unreadable xinetd fragment).
func parseSshdConfig(a collect.Access, file, keyword string, depth int) (facts.Envelope, bool) {
	if depth > maxIncludeDepth {
		return collect.ErrorEnv("Include nesting deeper than " + strconv.Itoa(maxIncludeDepth) + " levels"), true
	}
	data, meta, err := a.ReadFile(file, readLimit)
	if err != nil {
		if depth == 0 || !errors.Is(err, fs.ErrNotExist) {
			return collect.FromReadError(err, meta), true
		}
		return facts.Envelope{}, false
	}
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := configTokens(line)
		key := strings.ToLower(f[0])
		if key == "match" {
			break // global values only; per-persona Match values come from sshd -T -C
		}
		if key == "include" && len(f) >= 2 {
			for _, pattern := range f[1:] {
				// R55/R75: an Include outside the declaration is recorded
				// and expansion stops. It is never requested, so it raises
				// no guard violation and the collector still succeeds.
				if !declared(a, pattern) {
					return collect.ErrorEnv("Include " + pattern + " is outside the collector's declaration"), true
				}
				matches, err := a.Glob(pattern)
				if err != nil {
					// A Glob that failed is not an Include that matched
					// nothing: each drop-in it would have named could have
					// carried a higher-priority value, so expanding to
					// nothing and publishing the main file's value as ok
					// would be a PASS on evidence never seen — the same rule
					// an unreadable drop-in gets just below.
					return collect.ErrorEnv("Include " + pattern + ": " + err.Error()), true
				}
				slices.Sort(matches)
				for _, m := range matches {
					if env, ok := parseSshdConfig(a, path.Clean(m), keyword, depth+1); ok {
						return env, true
					}
				}
			}
			continue
		}
		if key == keyword && len(f) >= 2 {
			if oversized(f[1]) {
				return collect.ErrorEnv(oversizedReason), true
			}
			return collect.OKRead(keywordValue(key, f[1]), &facts.Source{
				Kind: "file", Path: file, Line: i + 1, Raw: sourceRaw(raw),
			}, meta), true
		}
	}
	return facts.Envelope{}, false
}

// oversizedReason is the reason an over-long value carries. It names the
// limit rather than the value, because the value is exactly what must not
// be stored (M16).
const oversizedReason = "value exceeds 4 KiB"

// oversized reports whether a single parsed value is too long to be one —
// the same rule for a value read out of a file and one printed by a
// command, so the two sides of a setting cannot disagree about it.
func oversized(v string) bool { return len(v) > maxTokenValue }

// configTokens splits an sshd_config line into its keyword and arguments.
//
// R85: sshd's own tokenizer (strdelim) counts "=" as a separator alongside
// whitespace for the first separator on a line, so all four of
//
//	Keyword value    Keyword=value    Keyword = value
//	Keyword =value   Keyword= value
//
// are one directive. Every spelling muster does not recognise reads as "the
// keyword is not configured", which is a PASS on a directive that is right
// there in the file — so the first "=" after the keyword is folded away
// here, wherever the spaces around it fall. A later "=" is left alone: it
// belongs to the value (an AuthorizedKeysCommand argument, say), not to the
// keyword.
func configTokens(line string) []string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return f
	}
	if k, v, ok := strings.Cut(f[0], "="); ok {
		// "Keyword=value" and "Keyword= value": the keyword carries the
		// separator, and the value may be empty (it is then the next field,
		// or the directive has no value at all).
		out := []string{k}
		if v != "" {
			out = append(out, v)
		}
		return append(out, f[1:]...)
	}
	if len(f) > 1 {
		if f[1] == "=" { // "Keyword = value"
			return append(f[:1], f[2:]...)
		}
		if v, ok := strings.CutPrefix(f[1], "="); ok { // "Keyword =value"
			f[1] = v
		}
	}
	return f
}

// multistate names the keywords whose value is one of a fixed set of words
// rather than free text. sshd matches those case-insensitively, so
// "PermitRootLogin No" and "permitrootlogin no" are one answer; the value
// is folded here so a control never has to match both spellings and two
// hosts that are configured identically cannot produce different facts.
// Paths, ciphers and command lines are NOT folded — their case is theirs.
var multistate = map[string]bool{permitRootLogin: true}

// keywordValue is the value stored for one parsed keyword.
func keywordValue(keyword, value string) string {
	if multistate[strings.ToLower(keyword)] {
		return strings.ToLower(value)
	}
	return value
}

// declared asks the guard whether pattern is inside the collector's
// declaration without the question itself counting as a violation (R55). A
// test double that does not offer Allowed counts everything as declared.
func declared(a collect.Access, pattern string) bool {
	al, ok := a.(interface{ Allowed(string) bool })
	return !ok || al.Allowed(pattern)
}
