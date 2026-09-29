//go:build linux

package collectors

import (
	"context"
	"errors"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The units collector (P-4, V-4): the system services that run with root's
// power — enabled or active, with no User= other than root — and whether a
// non-root user could rewrite what they execute. The unit files are found
// and merged here as systemd does; the parsers are in units_parse.go.

// unitSearchPath is the system unit search path of systemd.unit(5), highest
// precedence first (V-4).
var unitSearchPath = []string{
	"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
	"/run/systemd/generator.early", "/etc/systemd/system", "/run/systemd/system", "/run/systemd/generator",
	"/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late",
}

// listUnitsCmd is the active-service inventory, a read-only D-Bus query
// (V-17, V-36).
var listUnitsCmd = collect.Command{
	Path:      systemctlPath,
	Args:      []string{"list-units", "--type=service", "--state=active", "--plain", "--no-legend"},
	Timeout:   30 * time.Second,
	MaxOutput: 4 << 20,
}

// unitExecReads are the executables the collector may stat (V-20). A path a
// command line names outside them is not read (C4).
var unitExecReads = []string{
	"/usr/bin/*", "/usr/sbin/*", "/bin/*", "/sbin/*", "/usr/local/bin/*", "/usr/local/sbin/*",
	"/usr/lib/*", "/usr/lib/*/*", "/usr/lib/*/*/*", "/usr/libexec/*", "/usr/libexec/*/*",
	"/lib/*", "/lib/*/*", "/opt/*/*", "/opt/*/bin/*", "/snap/bin/*", "/etc/init.d/*",
	// V-44: stock Ubuntu's unattended-upgrades.service runs a script under /usr/share.
	"/usr/share/*/*", "/usr/share/*/*/*",
}

// unitAliasDirs are the merged-/usr aliases a command line spells a path
// through (/bin/kill, /lib/systemd/systemd-logind). The read primitive
// refuses a symlinked component, so the collector reads the alias itself and,
// when it is the link into /usr of the same name, stats the /usr spelling.
var unitAliasDirs = []string{"/bin", "/sbin", "/lib"}

// unitRowCap bounds units.root_services (V-12).
const unitRowCap = 500

func unitsReads() []string {
	var reads []string
	for _, d := range unitSearchPath {
		reads = append(reads, d, d+"/*.service", d+"/*.service.d", d+"/*.service.d/*.conf",
			d+"/*.wants", d+"/*.wants/*", d+"/*.requires", d+"/*.requires/*")
	}
	reads = append(reads, systemdMarker)
	reads = append(reads, unitAliasDirs...)
	return append(reads, unitExecReads...)
}

var unitsCollector = collect.Collector{
	Name: "units",
	Declare: collect.Declaration{
		Reads:    unitsReads(),
		Commands: []collect.Command{listUnitsCmd},
		Needs:    "none",
	},
	Run: runUnits,
}

const (
	unitsRootServices = "units.root_services"
	unitsExecWritable = "units.exec_writable"
	unitsUnresolved   = "units.exec_unresolved"
)

func setUnitsAll(b *collect.Builder, e facts.Envelope) {
	b.Set(unitsRootServices, e)
	b.Set(unitsExecWritable, e)
	b.Set(unitsUnresolved, e)
}

// unitsRun is one pass: what was read, and the first reason the writable
// answer is unknown.
type unitsRun struct {
	a        collect.Access
	inputs   []facts.Source
	cited    map[string]bool
	writable []any
	seen     map[string]bool
	unknown  string // the first reason units.exec_writable is absent
	aliases  map[string]bool
	cut      bool
	probe    bool // the unit being read is past the cap: it flags nothing
}

func runUnits(ctx context.Context, a collect.Access, b *collect.Builder) error {
	if _, err := a.Stat(systemdMarker); err != nil {
		setUnitsAll(b, collect.Unsupported("no systemd on this host or inside this container"))
		return nil
	}
	out := a.Run(ctx, listUnitsCmd)
	if e := listUnitsFailure(out); e != nil {
		setUnitsAll(b, *e)
		return nil
	}
	r := &unitsRun{a: a, cited: map[string]bool{}, seen: map[string]bool{}, aliases: map[string]bool{}, cut: out.Truncated}
	r.inputs = append(r.inputs, *out.Source(listUnitsCmd))

	active := map[string]bool{}
	for _, u := range parseListUnits(out.Stdout) {
		if strings.HasSuffix(u, ".service") {
			active[u] = true
		}
	}
	enabled := map[string]bool{}
	for _, d := range unitSearchPath {
		for _, pattern := range []string{d + "/*.wants/*", d + "/*.requires/*"} {
			matches, err := a.Glob(pattern)
			if err != nil {
				e := globReadError(pattern, err, collect.ErrorEnv(pattern+": "+err.Error()))
				e.Source = r.src()
				setUnitsAll(b, e)
				return nil
			}
			for _, m := range matches {
				if u := path.Base(m); strings.HasSuffix(u, ".service") {
					enabled[u] = true
				}
			}
		}
	}
	var units []string
	for u := range active {
		units = append(units, u)
	}
	for u := range enabled {
		if !active[u] {
			units = append(units, u)
		}
	}
	slices.Sort(units)

	// Once the cap is reached the pass only asks whether one more unit is in
	// scope — that is what says the list was cut — and a unit past the cap
	// contributes nothing to the other two leaves.
	var rows []any
	unresolved := 0
	cut := false
	for _, u := range units {
		r.probe = len(rows) == unitRowCap
		row, n, ok := r.unit(u, enabled[u], active[u])
		if !ok {
			continue
		}
		if r.probe {
			cut = true
			break
		}
		rows = append(rows, row)
		unresolved += n
	}
	cut = cut || r.cut
	src := r.src()
	b.Set(unitsRootServices, withTruncation(collect.OK(rows, src), cut))
	b.Set(unitsUnresolved, withTruncation(collect.OK(unresolved, src), cut))
	if r.unknown != "" {
		e := collect.Absent(r.unknown)
		e.Source = src
		b.Set(unitsExecWritable, withTruncation(e, cut))
		return nil
	}
	w := r.writable
	if w == nil {
		w = []any{}
	}
	slices.SortFunc(w, func(x, y any) int {
		mx, my := x.(map[string]any), y.(map[string]any)
		for _, k := range []string{"unit", "path", "why"} {
			if c := strings.Compare(mx[k].(string), my[k].(string)); c != 0 {
				return c
			}
		}
		return 0
	})
	b.Set(unitsExecWritable, withTruncation(collect.OK(w, src), cut))
	return nil
}

// listUnitsFailure classifies a systemctl list-units run that gave no
// inventory, or returns nil when it gave one (listTimersFailure's shape).
func listUnitsFailure(out collect.Output) *facts.Envelope {
	line := commandLine(listUnitsCmd)
	stderr := firstLine(out.Stderr)
	var e facts.Envelope
	switch {
	case out.TimedOut:
		e = collect.TimeoutEnv(line + " timed out")
	case out.Err != nil:
		e = collect.Unsupported("systemd unit inventory unavailable: " + line + ": " + out.Err.Error())
	case out.ExitCode == 0:
		return nil
	case strings.Contains(string(out.Stderr), "System has not been booted with systemd"):
		e = collect.Unsupported("systemd unit inventory unavailable: " + stderr)
	default:
		reason := line + " exited " + strconv.Itoa(out.ExitCode)
		if stderr != "" {
			reason += ": " + stderr
		}
		e = collect.ErrorEnv(reason)
	}
	return &e
}

func (r *unitsRun) src() *facts.Source {
	return &facts.Source{Kind: "derived", Inputs: slices.Clone(r.inputs)}
}

func (r *unitsRun) cite(p string) {
	if !r.cited[p] {
		r.cited[p] = true
		r.inputs = append(r.inputs, facts.Source{Kind: "file", Path: p})
	}
}

// markUnknown records the first reason the writable answer is unknown.
func (r *unitsRun) markUnknown(reason string) {
	if r.unknown == "" && !r.probe {
		r.unknown = reason
	}
}

func (r *unitsRun) flag(unit, p, why string) {
	if r.probe {
		return
	}
	k := unit + "\x00" + p + "\x00" + why
	if r.seen[k] {
		return
	}
	r.seen[k] = true
	r.writable = append(r.writable, map[string]any{"unit": unit, "path": p, "why": why})
}

// judge flags what a non-root user could rewrite: a file owned by
// another uid, or one its group or everyone may write. A symlink is judged
// by its owner only — its mode bits mean nothing.
func (r *unitsRun) judge(unit, p, prefix string, meta collect.ReadMeta, symlink bool) {
	if meta.UID != 0 {
		r.flag(unit, p, prefix+"owner")
	}
	if symlink {
		return
	}
	if meta.Mode&0o020 != 0 {
		r.flag(unit, p, prefix+"group_writable")
	}
	if meta.Mode&0o002 != 0 {
		r.flag(unit, p, prefix+"other_writable")
	}
}

// unitLookup is where a unit's file was found.
type unitLookup struct {
	kind   string // file | symlink | missing | masked | error
	path   string
	name   string // the name the file carries (an alias target, or a template)
	meta   collect.ReadMeta
	errEnv facts.Envelope
}

// find looks a unit up through the search path, an instance falling back to
// its template; a symlink into the same directory is an alias, followed by
// name once.
func (r *unitsRun) find(unit string) unitLookup {
	names := []string{unit}
	if tpl, inst := templateOf(unit); inst {
		names = append(names, tpl)
	}
	followed := false
names:
	for i := 0; i < len(names); i++ {
		name := names[i]
		for _, d := range unitSearchPath {
			p := d + "/" + name
			meta, err := r.a.Stat(p)
			switch {
			case err == nil:
				return unitLookup{kind: "file", path: p, name: name, meta: meta}
			case errors.Is(err, collect.ErrSymlink):
				target, ok := linkTarget(r.a, p)
				if ok && target == "/dev/null" {
					return unitLookup{kind: "masked", path: p, name: name}
				}
				if ok && !followed && path.Dir(target) == d && strings.HasSuffix(target, path.Ext(name)) {
					followed = true
					// An alias: the name it points at is looked up afresh,
					// before the template of the name asked for.
					names = slices.Insert(names, i+1, path.Base(target))
					continue names
				}
				return unitLookup{kind: "symlink", path: p, name: name}
			case notPresent(err):
				continue
			default:
				return unitLookup{kind: "error", path: p, name: name, errEnv: readErrorEnv(p, err)}
			}
		}
	}
	return unitLookup{kind: "missing"}
}

// notPresent is ENOENT or ENOTDIR: nothing at that path.
func notPresent(err error) bool {
	e := collect.FromReadError(err, collect.ReadMeta{})
	return e.Status == facts.StatusAbsent
}

// dropinsFor returns the drop-ins that apply to a unit, in the order they
// apply: for each .conf name the copy in the highest tree wins, within a
// tree the instance's directory before the template's (V-34); a /dev/null
// link masks the name; survivors sort by name.
func (r *unitsRun) dropinsFor(names []string) ([]string, map[string]collect.ReadMeta, *facts.Envelope) {
	chosen := map[string]string{}
	metas := map[string]collect.ReadMeta{}
	masked := map[string]bool{}
	var order []string
	for _, d := range unitSearchPath {
		for _, n := range names {
			pattern := d + "/" + globEscape(n) + ".d/*.conf"
			matches, err := r.a.Glob(pattern)
			if err != nil {
				e := globReadError(pattern, err, collect.ErrorEnv(pattern+": "+err.Error()))
				return nil, metas, &e
			}
			for _, m := range matches {
				base := path.Base(m)
				if _, done := chosen[base]; done || masked[base] {
					continue
				}
				meta, err := r.a.Stat(m)
				switch {
				case err == nil:
					chosen[base] = m
					metas[m] = meta
					order = append(order, base)
				case errors.Is(err, collect.ErrSymlink):
					if t, ok := linkTarget(r.a, m); ok && t == "/dev/null" {
						masked[base] = true
						continue
					}
					e := collect.ErrorEnv(m + ": a symbolic link, not followed")
					return nil, metas, &e
				case notPresent(err):
					continue
				default:
					e := readErrorEnv(m, err)
					return nil, metas, &e
				}
			}
		}
	}
	slices.Sort(order)
	out := make([]string, 0, len(order))
	for _, base := range order {
		out = append(out, chosen[base])
	}
	return out, metas, nil
}

// unit builds one unit's row. ok is false when the unit is out of scope:
// masked, or running as a user other than root. n is what the unit adds to
// units.exec_unresolved.
func (r *unitsRun) unit(unit string, enabled, active bool) (map[string]any, int, bool) {
	row := map[string]any{
		"unit": unit, "enabled": enabled, "active": active, "user": "",
		"unit_file": "missing", "files": []any{}, "exec": []any{},
		"read_status": "ok", "reason": "",
	}
	fail := func(status, reason string) {
		row["read_status"], row["reason"] = status, reason
		r.markUnknown("unit file could not be read: " + unit + " " + reason)
	}
	l := r.find(unit)
	switch l.kind {
	case "masked":
		return nil, 0, false
	case "missing":
		// V-47: an active unit muster found no file for runs something
		// unknown as root; a dangling .wants link that is only enabled runs
		// nothing.
		if active {
			r.markUnknown("unit file not found: " + unit + " (unit_file missing)")
		}
		return row, 1, true
	case "symlink":
		// V-47: a linked unit file — the file that decides is not read.
		row["unit_file"] = "symlink"
		r.markUnknown("unit file not followed: " + unit + " " + l.path + " (unit_file symlink)")
		return row, 1, true
	case "error":
		row["unit_file"] = "file"
		fail(string(l.errEnv.Status), l.errEnv.Reason)
		return row, 0, true
	}
	row["unit_file"] = "file"

	names := []string{unit}
	if l.name != unit {
		names = append(names, l.name)
	}
	if tpl, inst := templateOf(unit); inst && !slices.Contains(names, tpl) {
		names = append(names, tpl)
	}
	dropins, metas, dropErr := r.dropinsFor(names)
	if dropErr != nil {
		fail(string(dropErr.Status), dropErr.Reason)
	}
	metas[l.path] = l.meta

	var files []any
	var parsed []unitFile
	for _, p := range append([]string{l.path}, dropins...) {
		meta := metas[p]
		files = append(files, map[string]any{"path": p, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID)})
		data, rmeta, err := r.a.ReadFile(p, readLimit)
		r.cite(p)
		switch {
		case err != nil:
			e := readErrorEnv(p, err)
			fail(string(e.Status), e.Reason)
			continue
		case rmeta.Binary:
			fail("error", p+": binary content")
			continue
		}
		if p == l.path && len(data) == 0 && !rmeta.Truncated {
			// systemd.unit(5): an empty unit file is a mask, like a
			// /dev/null link.
			return nil, 0, false
		}
		r.cut = r.cut || rmeta.Truncated
		parsed = append(parsed, parseUnitFile(data))
	}
	row["files"] = files
	merged := mergeUnitFiles(parsed)
	user := ""
	if merged.User != nil {
		user = *merged.User
	}
	if _, inst := templateOf(unit); inst {
		// User=%i (user@.service): the instance is the user.
		instance := unit[strings.IndexByte(unit, '@')+1 : strings.LastIndexByte(unit, '.')]
		user = strings.NewReplacer("%i", instance, "%I", instance).Replace(user)
	}
	row["user"] = user
	// A User= still carrying a specifier cannot be named, so it stays in scope.
	if row["read_status"] == "ok" && user != "" && user != "root" && user != "0" && !strings.Contains(user, "%") {
		// Its executables run without root's power. An unreadable file could
		// set User= back, so a unit with one stays in scope.
		return nil, 0, false
	}
	for _, p := range append([]string{l.path}, dropins...) {
		r.judge(unit, p, "unit_file:", metas[p], false)
	}

	var execs []any
	n := 0
	for _, d := range execDirectives {
		for _, cmdline := range merged.Exec[d] {
			for _, command := range execCommands(cmdline) {
				er := r.execRow(unit, d, command)
				if er["resolved"] == false {
					n++
				}
				execs = append(execs, er)
			}
		}
	}
	if execs != nil {
		row["exec"] = execs
	}
	return row, n, true
}

// execRow is one command's executable, every field present (V-9).
func (r *unitsRun) execRow(unit, directive, command string) map[string]any {
	p, resolved := execFirstToken(command)
	row := map[string]any{
		"directive": directive, "path": p, "resolved": resolved, "stat_path": "",
		"exists": false, "kind": "", "mode": -1, "uid": -1, "gid": -1,
		"group_writable": false, "other_writable": false, "stat_status": "unresolved",
	}
	if !resolved {
		return row
	}
	if !declared(r.a, p) {
		row["stat_status"] = "undeclared"
		r.markUnknown("executable outside the collector's declaration: " + unit + " " + p)
		return row
	}
	statPath, meta, ok, err := r.statExec(p)
	flagPath := p
	if ok && errors.Is(err, collect.ErrSymlink) && meta.Kind == "symlink" {
		// A symlinked executable: its owner is judged, and one hop to its
		// target, which is judged in its place (a deploy's
		// /usr/local/bin/app → /opt/app/current/app).
		row["exists"], row["kind"] = true, "symlink"
		r.judge(unit, p, "", meta, true)
		target, isLink := linkTarget(r.a, statPath)
		if !isLink || !declared(r.a, target) {
			row["stat_status"] = "link_undeclared"
			row["stat_path"] = target
			r.markUnknown("executable is a symbolic link to a path outside the collector's declaration: " + unit + " " + p + " -> " + target)
			return row
		}
		statPath, meta, ok, err = r.statExec(target)
		flagPath = statPath
		if ok && errors.Is(err, collect.ErrSymlink) && meta.Kind == "symlink" {
			row["stat_status"] = "link_chain"
			row["stat_path"] = statPath
			r.markUnknown("executable is a chain of symbolic links muster follows one hop of: " + unit + " " + p + " -> " + statPath)
			return row
		}
	}
	row["stat_path"] = statPath
	switch {
	case !ok || errors.Is(err, collect.ErrSymlink):
		// A symlinked directory above the executable that is not a
		// merged-/usr alias: not followed.
		row["stat_status"] = "symlink_in_path"
		r.markUnknown("executable path runs through a symbolic link muster does not follow: " + unit + " " + statPath)
		return row
	case err == nil:
	case notPresent(err):
		row["stat_status"] = "missing"
		return row
	default:
		e := readErrorEnv(statPath, err)
		row["stat_status"] = string(e.Status)
		r.markUnknown("executable could not be read: " + unit + " " + e.Reason)
		return row
	}
	kind := meta.Kind
	if kind == "" {
		kind = "regular"
	}
	row["stat_status"] = "ok"
	if row["kind"] == "" {
		row["kind"] = kind
	}
	row["exists"] = true
	row["mode"], row["uid"], row["gid"] = int(meta.Mode), int(meta.UID), int(meta.GID)
	row["group_writable"] = meta.Mode&0o020 != 0
	row["other_writable"] = meta.Mode&0o002 != 0
	r.judge(unit, flagPath, "", meta, false)
	if meta.ParentUntrusted {
		// V-46: whoever may write the directory may replace the file.
		r.flag(unit, flagPath, "parent_writable")
	}
	return row
}

// statExec stats an executable, reading a merged-/usr alias through its
// /usr spelling. ok is false for a symlinked directory above p that is not
// such an alias; the path returned is the one stat-ed.
func (r *unitsRun) statExec(p string) (string, collect.ReadMeta, bool, error) {
	meta, err := r.a.Stat(p)
	if !errors.Is(err, collect.ErrSymlink) || meta.Kind == "symlink" {
		return p, meta, true, err
	}
	alt, ok := r.usrSpelling(p)
	if !ok {
		return p, meta, false, err
	}
	meta, err = r.a.Stat(alt)
	return alt, meta, true, err
}

// globEscape quotes the glob metacharacters of a unit name — systemd's
// \x2d escapes in an instance name among them — so its drop-in directory
// pattern matches the name literally.
func globEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '\\', '*', '?', '[':
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// usrSpelling is the /usr path of p when p's first directory is a
// merged-/usr alias the collector has read: /bin → usr/bin.
func (r *unitsRun) usrSpelling(p string) (string, bool) {
	for _, d := range unitAliasDirs {
		if !strings.HasPrefix(p, d+"/") {
			continue
		}
		ok, done := r.aliases[d]
		if !done {
			t, isLink := linkTarget(r.a, d)
			ok = isLink && t == "/usr"+d
			r.aliases[d] = ok
		}
		alt := "/usr" + p
		if !ok || !declared(r.a, alt) {
			return "", false
		}
		return alt, true
	}
	return "", false
}
