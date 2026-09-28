//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	sudoersPath   = "/etc/sudoers"
	sudoersDDir   = "/etc/sudoers.d"
	sudoersDGlob  = "/etc/sudoers.d/*"
	varLogDir     = "/var/log"
	varLogGlob1   = "/var/log/*"
	varLogGlob2   = "/var/log/*/*"
	logMaxEntries = 4096
	// sudoersReadLimit caps the /etc/sudoers content read (for the @includedir
	// and secure_path parse); /etc/sudoers is small, so 256 KiB is ample and
	// well under the 1 MiB readLimit used for larger files.
	sudoersReadLimit = 256 * 1024
)

var securePathRe = regexp.MustCompile(`secure_path\s*=\s*(.*)`)

// sudoersFacts writes the sudoers permission facts (stat only), the drop-in
// entries, and the sudo.* derived keys parsed from /etc/sudoers content.
func sudoersFacts(b *collect.Builder, a collect.Access, groups map[int]string) {
	// Permission facts of /etc/sudoers (stat; works without reading it).
	if meta, err := a.Stat(sudoersPath); err == nil {
		b.Set("files.etc_sudoers.mode", collect.OK(int(meta.Mode), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.uid", collect.OK(int(meta.UID), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.gid", collect.OK(int(meta.GID), permSrc(sudoersPath)))
		// acl_present follows writeRootHome/writePermFacts: the ACL probe's
		// error is the answer for the leaf (denied on a non-root run, since the
		// xattr read needs the file open O_RDONLY), never a quiet false.
		_, present, aerr := aclEntries(a, sudoersPath)
		if aerr != nil {
			b.Set("files.etc_sudoers.acl_present", collect.FromReadError(aerr, meta))
		} else {
			b.Set("files.etc_sudoers.acl_present", collect.OK(present, permSrc(sudoersPath)))
		}
	} else {
		e := statAbsentOrError(sudoersPath, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers."+k, e)
		}
	}
	// The drop-in directory and its entries.
	if meta, err := a.Stat(sudoersDDir); err == nil {
		b.Set("files.etc_sudoers_d.mode", collect.OK(int(meta.Mode), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.uid", collect.OK(int(meta.UID), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.gid", collect.OK(int(meta.GID), permSrc(sudoersDDir)))
		_, present, aerr := aclEntries(a, sudoersDDir)
		if aerr != nil {
			b.Set("files.etc_sudoers_d.acl_present", collect.FromReadError(aerr, meta))
		} else {
			b.Set("files.etc_sudoers_d.acl_present", collect.OK(present, permSrc(sudoersDDir)))
		}
	} else {
		e := statAbsentOrError(sudoersDDir, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers_d."+k, e)
		}
	}
	b.Set("files.sudoers_d_entries", sudoersDropIns(a, groups))
	// sudo.* derived from reading /etc/sudoers (root-only). A non-root run
	// gets a denied read → every sudo.* key it could set carries that status.
	// One read serves both writers.
	var main sudoersRead
	main.data, main.meta, main.err = a.ReadFile(sudoersPath, sudoersReadLimit)
	writeSudoDerived(b, main)
	sudoLogFacts(b, a, main)
}

// sudoersDropIns lists /etc/sudoers.d entries. sudo ignores a name ending in
// ~ or containing a "." (a backup or dotted file), recorded as ignored:true
// so the control skips it.
func sudoersDropIns(a collect.Access, groups map[int]string) facts.Envelope {
	matches, err := a.Glob(sudoersDGlob)
	if err != nil {
		return collect.FromReadError(err, collect.ReadMeta{})
	}
	sort.Strings(matches)
	rows := []any{}
	for _, p := range matches {
		row, ok := permRow(a, p, groups)
		if !ok {
			continue
		}
		base := path.Base(p)
		row["ignored"] = strings.HasSuffix(base, "~") || strings.Contains(base, ".")
		rows = append(rows, row)
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: sudoersDDir})
}

// sudoersRead is the one read of /etc/sudoers both sudo.* writers share.
type sudoersRead struct {
	data []byte
	meta collect.ReadMeta
	err  error
}

// writeSudoDerived parses /etc/sudoers for the @includedir directory and the
// Defaults secure_path. installed is whether /etc/sudoers exists at all.
func writeSudoDerived(b *collect.Builder, main sudoersRead) {
	data, err := main.data, main.err
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			src := &facts.Source{Kind: "derived"}
			b.Set("sudo.installed", collect.OK(false, src))
			b.Set("sudo.includedir", collect.OK("", src))
			b.Set("sudo.secure_path", collect.OK("", src))
			return
		}
		e := readErrorEnv(sudoersPath, err)                             // path-prefixed (C3)
		b.Set("sudo.installed", collect.OK(true, permSrc(sudoersPath))) // the file exists; we just cannot read it
		b.Set("sudo.includedir", e)
		b.Set("sudo.secure_path", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: sudoersPath}
	includedir, securePath := "", ""
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "@includedir") || strings.HasPrefix(line, "#includedir") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				includedir = f[1]
			}
		}
		if strings.HasPrefix(line, "Defaults") && strings.Contains(line, "secure_path") {
			// secure_path may carry spaces around the "=" (Rocky ships
			// `Defaults    secure_path = /sbin:...`), so match with a regex.
			if m := securePathRe.FindStringSubmatch(line); m != nil {
				securePath = strings.Trim(strings.TrimSpace(m[1]), `"`)
			}
		}
	}
	b.Set("sudo.installed", collect.OK(true, src))
	b.Set("sudo.includedir", collect.OK(includedir, src))
	b.Set("sudo.secure_path", collect.OK(securePath, src))
}

// logTree records /var/log itself as a log_dirs row, then walks it one and two
// levels deep (bounded), recording each entry's group name and the
// group/other-writable flags. U-67 owns the allowed-group policy, so no
// "unexpected" flag is precomputed here (D09).
//
// gmeta and gerr are what groupNames returned. Unlike the cron rows, U-67
// JUDGES the group field (`each where group_writable require group in
// allowed`), so a group name built from an unreadable/truncated /etc/group
// would be fabricated evidence: on gerr both keys carry that read error
// (path-prefixed, C3/R70, mirroring writePermFacts), and a truncated read
// marks the two envelopes so a name the cap may have dropped is honest.
func logTree(a collect.Access, groups map[int]string, gmeta collect.ReadMeta, gerr error) (facts.Envelope, facts.Envelope) {
	if gerr != nil {
		// /etc/group could not be read; every log row's group name would be a
		// silent "" that U-67 would then judge on. Surface the read error on
		// both log keys instead (path-prefixed, since /etc/group is not the
		// path these facts are about).
		e := readErrorEnv(groupPath, gerr)
		return e, e
	}
	var paths []string
	for _, g := range []string{varLogGlob1, varLogGlob2} {
		m, err := a.Glob(g)
		if err != nil {
			e := collect.FromReadError(err, collect.ReadMeta{})
			return e, e
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	truncated := false
	if len(paths) > logMaxEntries {
		paths = paths[:logMaxEntries]
		truncated = true
	}
	dirs, files := []any{}, []any{}
	// /var/log itself is a log_dirs row (its own perms matter to U-67/SI-11).
	if meta, err := a.Stat(varLogDir); err == nil {
		dirs = append(dirs, map[string]any{
			"path": varLogDir, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group":          groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		})
	}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if errors.Is(err, collect.ErrSymlink) {
			// A symlinked log entry is not itself a finding (its target is
			// judged where it lives): is_symlink:true and no reason, so the
			// reason-guard leaves it alone.
			files = append(files, map[string]any{
				"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
				"group_writable": false, "other_writable": false, "is_symlink": true,
			})
			continue
		}
		if err != nil {
			// an unreadable entry: record it as a finding row (carrying a
			// reason) so a denied log path is visible, never silently dropped.
			row := map[string]any{"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
				"group_writable": false, "other_writable": false, "reason": readReason(p, err)}
			files = append(files, row)
			continue
		}
		row := map[string]any{
			"path": p, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group":          groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		}
		if meta.Kind == "dir" {
			dirs = append(dirs, row)
		} else {
			files = append(files, row)
		}
	}
	src := &facts.Source{Kind: "file", Path: varLogDir}
	// A truncated /etc/group read (gmeta.Truncated) marks the two envelopes too:
	// the walk carries the group name it looked up, which the read cap may have
	// missed (R70), just like the row-cap truncation of the walk itself.
	de := withTruncation(collect.OK(dirs, src), truncated || gmeta.Truncated)
	fe := withTruncation(collect.OK(files, src), truncated || gmeta.Truncated)
	return de, fe
}

// --- sudo's logging defaults (spec I-6) ---------------------------------

// sudoLogKeys degrade together: C3 makes a sudoers file that cannot be read
// the answer for every value it could set.
var sudoLogKeys = []string{"sudo.log.syslog", "sudo.log.logfile", "sudo.defaults.scoped_count"}

// sudoMaxDepth bounds the include recursion, so two files including each
// other through different spellings cannot loop.
const sudoMaxDepth = 8

// sudoLogFacts writes sudo.log.syslog, sudo.log.logfile and
// sudo.defaults.scoped_count from /etc/sudoers (the read writeSudoDerived
// made) and the files it includes, in sudoers(5)'s order, later lines
// winning. Only unscoped Defaults are interpreted; scoped ones are counted.
func sudoLogFacts(b *collect.Builder, a collect.Access, main sudoersRead) {
	if main.err != nil {
		if errors.Is(main.err, fs.ErrNotExist) {
			// No sudoers file: sudo's compiled-in defaults, a fact.
			b.Set("sudo.log.syslog", collect.OK(true, &facts.Source{Kind: "derived"}))
			b.Set("sudo.log.logfile", collect.OK("", &facts.Source{Kind: "derived"}))
			b.Set("sudo.defaults.scoped_count", collect.OK(0, &facts.Source{Kind: "derived"}))
			return
		}
		e := readErrorEnv(sudoersPath, main.err)
		for _, k := range sudoLogKeys {
			b.Set(k, e)
		}
		return
	}
	s := &sudoLogScan{a: a, syslog: true, seen: map[string]bool{sudoersPath: true}}
	s.file(sudoersPath, main.data, main.meta, 0)
	if s.failure != nil {
		for _, k := range sudoLogKeys {
			b.Set(k, *s.failure)
		}
		return
	}
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(s.inputs)} }
	b.Set("sudo.log.syslog", withTruncation(collect.OK(s.syslog, src()), s.truncated))
	b.Set("sudo.log.logfile", withTruncation(collect.OK(s.logfile, src()), s.truncated))
	b.Set("sudo.defaults.scoped_count", withTruncation(collect.OK(s.scoped, src()), s.truncated))
}

// sudoLogScan applies the sudoers files in the order sudo reads them.
type sudoLogScan struct {
	a         collect.Access
	syslog    bool
	logfile   string
	scoped    int
	inputs    []facts.Source
	truncated bool
	seen      map[string]bool
	failure   *facts.Envelope
}

func (s *sudoLogScan) fail(e facts.Envelope) {
	if s.failure == nil {
		s.failure = &e
	}
}

func (s *sudoLogScan) file(p string, data []byte, meta collect.ReadMeta, depth int) {
	s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: p})
	s.truncated = s.truncated || meta.Truncated
	for _, e := range parseSudoersDefaults(data) {
		if s.failure != nil {
			return
		}
		switch e.kind {
		case sudoScoped:
			s.scoped++
		case sudoDefaults:
			for _, o := range e.options {
				switch o.name {
				case "syslog":
					// syslog=facility keeps logging on; only !syslog stops it.
					s.syslog = !o.negated
				case "logfile":
					if o.negated {
						s.logfile = ""
					} else {
						s.logfile = o.value
					}
				}
			}
		case sudoIncludeDir:
			s.includeDir(e.arg, depth)
		case sudoInclude:
			s.include(e.arg, depth)
		}
	}
}

// includeDir reads every file of an includedir in lexical order, skipping a
// name that contains a "." or ends in "~" as sudo does. The directory is
// declared as /etc/sudoers.d alone; any other is a path the model declines
// to read (C4).
func (s *sudoLogScan) includeDir(dir string, depth int) {
	dir = strings.TrimSuffix(dir, "/")
	if dir != sudoersDDir {
		s.fail(collect.Absent("includedir " + dir + " is outside the collector's declaration"))
		return
	}
	if s.seen[dir] || depth >= sudoMaxDepth {
		return
	}
	s.seen[dir] = true
	matches, err := s.a.Glob(sudoersDGlob)
	if err != nil {
		s.fail(globReadError(sudoersDGlob, err, collect.ErrorEnv(sudoersDGlob+": "+err.Error())))
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		base := path.Base(m)
		if strings.Contains(base, ".") || strings.HasSuffix(base, "~") {
			continue
		}
		if meta, err := s.a.Stat(m); err == nil && meta.Kind == "dir" {
			continue
		}
		s.read(m, depth)
		if s.failure != nil {
			return
		}
	}
}

// include reads one file an @include/#include names.
func (s *sudoLogScan) include(p string, depth int) {
	if s.seen[p] || depth >= sudoMaxDepth {
		return
	}
	s.seen[p] = true
	if !path.IsAbs(p) || !declared(s.a, p) {
		s.fail(collect.Absent("include " + p + " is outside the collector's declaration"))
		return
	}
	s.read(p, depth)
}

func (s *sudoLogScan) read(p string, depth int) {
	data, meta, err := s.a.ReadFile(p, sudoersReadLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		s.fail(readErrorEnv(p, err))
		return
	}
	s.file(p, data, meta, depth+1)
}

// The kinds of sudoers line the logging leaves care about.
const (
	sudoDefaults   = "defaults"
	sudoScoped     = "scoped"
	sudoIncludeDir = "includedir"
	sudoInclude    = "include"
)

// sudoersEntry is one sudoers line that matters to sudo.log.*: an unscoped
// Defaults line and its options, a scoped Defaults line (counted only), or
// an include directive and its argument.
type sudoersEntry struct {
	kind    string
	options []sudoOption
	arg     string
}

// sudoOption is one Defaults option: its name, whether it was negated with
// "!", and its value with quotes removed ("" when it has none).
type sudoOption struct {
	name    string
	negated bool
	value   string
}

// parseSudoersDefaults reads a sudoers file for its Defaults lines and
// include directives, in file order. Backslash continuations are joined
// first (a comment ends at its newline). sudo's lexer reads Defaults[:@>!]?
// as ONE word, so a line is scoped exactly when the character right after
// "Defaults" is one of those four — Defaults:root, Defaults!/usr/bin/x —
// while "Defaults !syslog" and "Defaults<TAB>env_reset" are unscoped. The
// option list is comma-separated with quoted values, whitespace around an
// operator allowed and += / -= part of the option. #include and #includedir
// are directives, not comments.
func parseSudoersDefaults(data []byte) []sudoersEntry {
	var logical []string
	cur, joining := "", false
	for _, raw := range splitLines(data) {
		t := strings.TrimRight(raw, " \t")
		if !joining && strings.HasPrefix(strings.TrimSpace(t), "#") {
			logical = append(logical, strings.TrimSpace(t))
			continue
		}
		if strings.HasSuffix(t, `\`) {
			cur += strings.TrimSuffix(t, `\`) + " "
			joining = true
			continue
		}
		logical = append(logical, strings.TrimSpace(cur+t))
		cur, joining = "", false
	}
	if joining {
		logical = append(logical, strings.TrimSpace(cur))
	}
	var out []sudoersEntry
	for _, l := range logical {
		if kind, arg, ok := sudoDirective(l); ok {
			out = append(out, sudoersEntry{kind: kind, arg: arg})
			continue
		}
		rest, ok := strings.CutPrefix(l, "Defaults")
		if !ok || rest == "" {
			continue
		}
		switch c := rest[0]; {
		case strings.IndexByte(":@>!", c) >= 0:
			out = append(out, sudoersEntry{kind: sudoScoped})
		case c == ' ' || c == '\t':
			out = append(out, sudoersEntry{kind: sudoDefaults, options: sudoOptions(rest)})
		}
	}
	return out
}

// sudoDirective recognises @include, @includedir and their # spellings.
func sudoDirective(s string) (kind, arg string, ok bool) {
	f := strings.Fields(s)
	if len(f) < 2 {
		return "", "", false
	}
	switch f[0] {
	case "@includedir", "#includedir":
		return sudoIncludeDir, strings.Trim(f[1], `"`), true
	case "@include", "#include":
		return sudoInclude, strings.Trim(f[1], `"`), true
	}
	return "", "", false
}

// sudoOptions splits a Defaults option list on the commas outside double
// quotes, stops at an unquoted comment, and reads each option.
func sudoOptions(s string) []sudoOption {
	var parts []string
	var b strings.Builder
	quoted, escaped := false, false
scan:
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			parts = append(parts, b.String())
			b.Reset()
			continue
		case r == '#' && !quoted:
			break scan
		}
		b.WriteRune(r)
	}
	parts = append(parts, b.String())
	var out []sudoOption
	for _, p := range parts {
		p = strings.TrimSpace(p)
		neg := false
		for strings.HasPrefix(p, "!") {
			neg = !neg
			p = strings.TrimSpace(p[1:])
		}
		name, rest := p, ""
		if end := strings.IndexAny(p, "=+- \t"); end >= 0 {
			name, rest = p[:end], strings.TrimSpace(p[end:])
		}
		if name == "" {
			continue
		}
		value := ""
		for _, op := range []string{"+=", "-=", "="} {
			if v, ok := strings.CutPrefix(rest, op); ok {
				value = strings.TrimSpace(v)
				break
			}
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		out = append(out, sudoOption{name: name, negated: neg, value: value})
	}
	return out
}
