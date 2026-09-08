//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The syslog configuration this collector knows how to find. Which daemon is
// RUNNING is services.syslog.*; these are the persisted view.
const (
	rsyslogConf  = "/etc/rsyslog.conf"
	rsyslogDGlob = "/etc/rsyslog.d/*.conf"
	syslogNgConf = "/etc/syslog-ng/syslog-ng.conf"

	// Ruling I-10: the log directory is declared as two flat globs, never a
	// "**"-ish pattern — guardedAccess matches with path.Match, which has no
	// recursive wildcard. The second also covers /var/log/journal for the
	// journald leaves Task 3 adds.
	varLogGlob    = "/var/log/*"
	varLogSubGlob = "/var/log/*/*"
)

// The journald configuration chain (Ruling I-23). It is declared here, with
// the rest of this collector's reads, because the journald leaves live in the
// same collector; nothing in this file reads it yet.
var (
	journaldMains = []string{"/etc/systemd/journald.conf", "/usr/lib/systemd/journald.conf"}
	// Descending precedence, the order mergeDropins wants.
	journaldDropinDirs = []string{
		"/etc/systemd/journald.conf.d",
		"/run/systemd/journald.conf.d",
		"/usr/local/lib/systemd/journald.conf.d",
		"/usr/lib/systemd/journald.conf.d",
	}
)

func loggingReads() []string {
	reads := []string{rsyslogConf, rsyslogDGlob, syslogNgConf, systemdMarker, varLogGlob, varLogSubGlob}
	reads = append(reads, journaldMains...)
	for _, d := range journaldDropinDirs {
		reads = append(reads, path.Join(d, "*.conf"))
	}
	return reads
}

var loggingCollector = collect.Collector{
	Name: "logging",
	Declare: collect.Declaration{
		Reads: loggingReads(),
		// Needs: "none" — every read here is world-readable on a stock host,
		// and a file that is not is reported denied through C3 rather than
		// wrapped as a privilege failure.
		Needs: "none",
	},
	Run: runLogging,
}

// rsyslogLeafKeys are every leaf derived from the rsyslog configuration. They
// degrade together: C3 says a file that exists but cannot be read is the
// answer for every value it could set, and a host that does not run rsyslog
// has no rsyslog answers at all.
var rsyslogLeafKeys = []string{
	"logging.rsyslog.rules",
	"logging.rsyslog.parse_complete",
	"logging.rsyslog.unmodelled",
	"logging.rsyslog.property_filters",
	"logging.rsyslog.coverage",
	"logging.log_targets",
}

func runLogging(_ context.Context, a collect.Access, b *collect.Builder) error {
	impl, data, truncated, readErr := syslogImplementation(a)
	b.Set("logging.syslog.implementation", collect.OK(impl, implementationSource(impl)))

	if readErr != nil {
		for _, k := range rsyslogLeafKeys {
			b.Set(k, *readErr)
		}
		return nil
	}
	if impl != "rsyslog" {
		deg := collect.Absent(noRsyslogReason(impl))
		for _, k := range rsyslogLeafKeys {
			b.Set(k, deg)
		}
		return nil
	}

	s := &rsyslogScan{a: a, truncated: truncated, seen: map[string]bool{rsyslogConf: true}}
	s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: rsyslogConf})
	s.file(data)

	// R147: a fresh Source pointer per envelope, never one shared.
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(s.inputs)} }
	set := func(key string, value any) {
		b.Set(key, withTruncation(collect.OK(value, src()), s.truncated))
	}
	set("logging.rsyslog.rules", s.ruleRecords())
	set("logging.rsyslog.parse_complete", len(s.incomplete) == 0)
	set("logging.rsyslog.unmodelled", s.unmodelled)
	set("logging.rsyslog.property_filters", s.properties)
	if reason := s.coverageBlocked(); reason != "" {
		// Under-claiming is the safe direction: the control's
		// absent_means: manual turns this into MANUAL rather than a
		// confidently wrong PASS or FAIL.
		b.Set("logging.rsyslog.coverage", collect.Absent(reason))
	} else {
		set("logging.rsyslog.coverage", rsyslogCoverage(s.rules))
	}
	set("logging.log_targets", s.logTargets(a, collectedAt(b)))
	return nil
}

// syslogImplementation names the syslog implementation this host is
// configured with, and returns the main rsyslog configuration when there is
// one. An /etc/rsyslog.conf that exists but cannot be read still means
// "rsyslog"; the read error it returns then becomes every rsyslog leaf (C3),
// because the module's defaults are never the answer for a file this process
// was refused.
func syslogImplementation(a collect.Access) (impl string, data []byte, truncated bool, readErr *facts.Envelope) {
	data, meta, err := a.ReadFile(rsyslogConf, readLimit)
	switch {
	case err == nil:
		return "rsyslog", data, meta.Truncated, nil
	case !errors.Is(err, fs.ErrNotExist):
		e := readErrorEnv(rsyslogConf, err)
		return "rsyslog", nil, false, &e
	}
	switch {
	case pathPresent(a, syslogNgConf):
		return "syslog-ng", nil, false, nil
	case pathPresent(a, systemdMarker):
		return "journald-only", nil, false, nil
	}
	return "none", nil, false, nil
}

// pathPresent reports whether a path is there. A stat that fails for any
// reason other than "not found" — a denied parent, a symlink — still means
// something occupies the path.
func pathPresent(a collect.Access, p string) bool {
	_, err := a.Stat(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

func implementationSource(impl string) *facts.Source {
	switch impl {
	case "rsyslog":
		return &facts.Source{Kind: "file", Path: rsyslogConf}
	case "syslog-ng":
		return &facts.Source{Kind: "file", Path: syslogNgConf}
	case "journald-only":
		return &facts.Source{Kind: "file", Path: systemdMarker}
	}
	return &facts.Source{Kind: "derived"}
}

func noRsyslogReason(impl string) string {
	if impl == "syslog-ng" {
		return "this host is configured with syslog-ng, whose dialect this version does not parse; check " + syslogNgConf + " by hand"
	}
	return "no rsyslog configuration on this host (" + rsyslogConf + " is not present)"
}

// --- the rsyslog configuration ------------------------------------------

// maxRsyslogIncludes caps how many distinct include arguments are followed,
// so a configuration that includes itself through two different spellings
// cannot loop.
const maxRsyslogIncludes = 64

// rsyslogRule is one routing decision the configuration makes for ONE
// facility: the compound selectors, comma lists and "*" of a selector line
// are expanded here, so nothing downstream has to re-parse syslog syntax.
type rsyslogRule struct {
	facility string
	priority string // the floor this line selects for this facility
	target   string
	kind     string // file | remote | user | pipe | module | discard
	line     string // the source line, evidence for a coverage reason
}

// rsyslogSelector is one parsed selector list: which facilities it selects
// and, per facility, the priority floor.
type rsyslogSelector struct {
	facilities []string // sorted, so rule emission is deterministic
	priority   map[string]string
}

// rsyslogFilter is the filter of the line just parsed, which a leading "&"
// continuation line re-uses with a new action.
type rsyslogFilter struct {
	sel      *rsyslogSelector
	property bool // the previous line was a property-based filter (Ruling I-12)
}

type rsyslogScan struct {
	a collect.Access

	inputs    []facts.Source
	truncated bool

	rules      []rsyslogRule
	unmodelled int      // constructs v1 does not model (Ruling I-12: exactly four)
	properties int      // property-based filter lines, evidence only
	incomplete []string // why the parse is not complete (Ruling I-10)

	seen map[string]bool // include arguments already followed
	skip int             // open brace depth of an unmodelled block being skipped
}

// file parses one configuration file, following its includes IN PLACE — the
// order rsyslog itself applies them, which Ruling I-13's ordered coverage
// derivation depends on.
func (s *rsyslogScan) file(data []byte) {
	var prev rsyslogFilter
	for _, line := range rsyslogLogicalLines(data) {
		if s.skip > 0 {
			// Inside an `if … then { … }` block the collector already counted
			// as unmodelled; the actions in it are conditional and must not
			// be read as unconditional routing.
			s.skip += rsyslogBraceDelta(line)
			if s.skip < 0 {
				s.skip = 0
			}
			continue
		}
		prev = s.line(line, prev)
	}
}

// line classifies one logical line and returns the filter a following "&"
// continuation would re-use.
func (s *rsyslogScan) line(l string, prev rsyslogFilter) rsyslogFilter {
	low := strings.ToLower(l)
	fields := strings.Fields(l)
	switch {
	case l == "":
		return prev

	// Legacy "$Directive" lines are globals, not rules — except
	// $IncludeConfig, which brings more rules in (Ruling I-12).
	case strings.HasPrefix(l, "$"):
		if len(fields) >= 2 && strings.EqualFold(fields[0], "$IncludeConfig") {
			s.include(strings.Join(fields[1:], " "))
		}
		return prev

	case strings.HasPrefix(low, "include("):
		s.includeCall(l)
		return prev

	// Statements that configure the daemon rather than route a message. A
	// template changes the FORMAT of a message, never where it goes, so it
	// is not unmodelled either.
	case hasAnyPrefix(low, "module(", "global(", "input(", "main_queue(", "template(", "parser(", "timezone(", "lookup_table("):
		return prev

	// Ruling I-12: exactly four things are unmodelled. Two of them are
	// whole statements.
	case strings.HasPrefix(low, "if ") || strings.HasPrefix(low, "if("):
		s.unmodelled++
		s.skip = max(rsyslogBraceDelta(l), 0)
		return rsyslogFilter{}
	case strings.HasPrefix(low, "ruleset(") || (len(fields) >= 2 && strings.EqualFold(fields[0], "call")):
		s.unmodelled++
		return rsyslogFilter{}

	// A leading "&" re-uses the previous line's filter with a new action.
	case strings.HasPrefix(l, "&"):
		s.continuation(strings.TrimSpace(l[1:]), prev)
		return prev

	// A property-based filter routes a tagged SUBSET of messages to an extra
	// destination; it can never un-log a facility, so it is coverage-neutral
	// evidence and not unmodelled (Ruling I-12).
	case isPropertyFilter(l):
		s.properties++
		return rsyslogFilter{property: true}

	// A bare RainerScript action with no filter applies to every message.
	case strings.HasPrefix(low, "action("):
		sel := allFacilitiesSelector()
		s.emit(sel, l, l)
		return rsyslogFilter{sel: sel}
	}

	// A classic "selector<whitespace>action" line.
	i := strings.IndexAny(l, " \t")
	if i <= 0 {
		return rsyslogFilter{}
	}
	act := strings.TrimSpace(l[i:])
	if act == "" {
		return rsyslogFilter{}
	}
	parsed := parseRsyslogSelector(l[:i])
	if parsed == nil {
		// Not a selector line at all. It is deliberately NOT counted as
		// unmodelled: Ruling I-12 fixes that net at four constructs, and
		// widening it here would turn a stock host MANUAL on any surprise.
		return rsyslogFilter{}
	}
	s.emit(parsed, act, l)
	return rsyslogFilter{sel: parsed}
}

// continuation applies a new action to the previous line's filter.
func (s *rsyslogScan) continuation(act string, prev rsyslogFilter) {
	if prev.property || prev.sel == nil {
		// Ruling I-12: "& stop" / "& ~" after a property filter discards that
		// tagged subset only, never a facility; a further destination after
		// one is likewise additive.
		return
	}
	s.emit(prev.sel, act, "& "+act)
}

// emit turns one selector and one action into a rule per selected facility.
func (s *rsyslogScan) emit(sel *rsyslogSelector, act, line string) {
	a := parseRsyslogAction(act)
	if a.unmodelled {
		s.unmodelled++
		return
	}
	if a.kind == "" {
		return
	}
	raw := sourceRaw(line)
	for _, f := range sel.facilities {
		s.rules = append(s.rules, rsyslogRule{
			facility: f, priority: sel.priority[f],
			target: a.target, kind: a.kind, line: raw,
		})
	}
}

// includeCall follows a RainerScript include(). Extra attributes — the
// mode="optional" every RHEL rsyslog.conf carries — are tolerated.
func (s *rsyslogScan) includeCall(l string) {
	f := rainerAttrs(l)["file"]
	if f == "" {
		// An include this version cannot resolve may name rules that were
		// never seen, so the parse is not complete.
		s.incomplete = append(s.incomplete, "unresolved include "+sourceRaw(l))
		return
	}
	s.include(f)
}

// include follows one include argument, which is either a plain path or a
// glob. Ruling I-10: an argument outside the collector's declaration is
// RECORDED and never globbed or read — reaching for it would be a guard
// violation, which makes the whole run incomplete.
func (s *rsyslogScan) include(arg string) {
	arg = strings.Trim(strings.TrimSpace(arg), `"'`)
	if arg == "" {
		return
	}
	if strings.HasSuffix(arg, "/") {
		arg += "*" // rsyslog reads every file in a directory named this way
	}
	if s.seen[arg] {
		return
	}
	s.seen[arg] = true
	if len(s.seen) > maxRsyslogIncludes {
		s.incomplete = append(s.incomplete, "too many include directives to follow")
		return
	}
	if !declared(s.a, arg) {
		s.incomplete = append(s.incomplete, arg+" is outside the collector's declaration")
		return
	}
	if !strings.ContainsAny(arg, "*?[") {
		s.read(arg)
		return
	}
	matches, err := s.a.Glob(arg)
	if err != nil {
		s.incomplete = append(s.incomplete, arg+": "+readReason(arg, err))
		return
	}
	slices.Sort(matches)
	for _, m := range matches {
		s.read(m)
	}
}

// read parses one included file. A file that is simply not there is not a
// failure — every distribution ships an include of a directory that may be
// empty — but one that exists and cannot be read is (R148).
func (s *rsyslogScan) read(p string) {
	data, meta, err := s.a.ReadFile(p, readLimit)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.incomplete = append(s.incomplete, readErrorEnv(p, err).Reason)
		}
		return
	}
	s.truncated = s.truncated || meta.Truncated
	s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: p})
	s.file(data)
}

func (s *rsyslogScan) ruleRecords() []any {
	out := make([]any, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, map[string]any{
			"facility":    r.facility,
			"priority":    r.priority,
			"target":      r.target,
			"target_kind": r.kind,
		})
	}
	return out
}

// coverageBlocked is why the per-facility derivation must not be published,
// or "" when it may be. Either condition means the rule set on this host is
// not the rule set that was read.
func (s *rsyslogScan) coverageBlocked() string {
	switch {
	case len(s.incomplete) > 0:
		return "per-facility routing cannot be derived; " + strings.Join(s.incomplete, "; ")
	case s.unmodelled > 0:
		return "per-facility routing cannot be derived; the configuration carries " +
			strconv.Itoa(s.unmodelled) + " construct(s) this version does not model"
	}
	return ""
}

// logTargets stats every distinct local file target the rules name.
// exists and mtime_age_s are EVIDENCE (Ruling I-15): omfile creates its file
// on first write, so a target that is not there yet says nothing about
// whether the facility is persistently logged.
func (s *rsyslogScan) logTargets(a collect.Access, now time.Time) []any {
	seen := map[string]bool{}
	var paths []string
	for _, r := range s.rules {
		if r.kind != "file" || r.target == "" || seen[r.target] {
			continue
		}
		seen[r.target] = true
		paths = append(paths, r.target)
	}
	sort.Strings(paths)
	out := make([]any, 0, len(paths))
	for _, p := range paths {
		// R176: every field a control could read is initialised before the
		// branch, so no row is missing one.
		rec := map[string]any{"path": p, "exists": false, "persistent": true}
		if !declared(a, p) {
			// Ruling I-10: recorded, never stat-ed.
			rec["stat_status"] = "undeclared"
			out = append(out, rec)
			continue
		}
		meta, err := a.Stat(p)
		switch {
		case err == nil:
			rec["stat_status"] = "ok"
			rec["exists"] = true
			if age, ok := mtimeAge(now, meta.ModTime); ok {
				rec["mtime_age_s"] = age
			}
		case errors.Is(err, fs.ErrNotExist):
			rec["stat_status"] = "absent"
		default:
			rec["stat_status"] = "denied"
			rec["reason"] = readReason(p, err)
		}
		out = append(out, rec)
	}
	return out
}

// collectedAt is the one clock a collector may read: the timestamp the run
// header took once (R54). Ruling I-27 — never time.Now() here, or the same
// snapshot would render different bytes on two runs.
func collectedAt(b *collect.Builder) time.Time {
	t, err := time.Parse(time.RFC3339, b.Header().CollectedAt)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// mtimeAge is the whole seconds between a file's modification time and the
// run's collected_at. An unknown time on either side, or a file modified
// after the run started, yields no age at all rather than a fabricated one.
func mtimeAge(now, mod time.Time) (int, bool) {
	if now.IsZero() || mod.IsZero() {
		return 0, false
	}
	d := now.Sub(mod)
	if d < 0 {
		return 0, false
	}
	return int(d / time.Second), true
}

// --- per-facility coverage (Ruling I-13) --------------------------------

// syslogFacilities are the facility names a selector can name. "*" expands to
// exactly this list; rsyslog's internal "mark" is not one of them.
var syslogFacilities = []string{
	"auth", "authpriv", "cron", "daemon", "ftp", "kern", "lpr", "mail",
	"news", "syslog", "user", "uucp",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

// syslogPriorities maps every accepted spelling to its severity; a LARGER
// number is a less severe message, so the widest floor is the largest one.
var syslogPriorities = map[string]int{
	"emerg": 0, "panic": 0,
	"alert": 1, "crit": 2,
	"err": 3, "error": 3,
	"warning": 4, "warn": 4,
	"notice": 5, "info": 6, "debug": 7,
}

var canonicalPriority = map[string]string{"panic": "emerg", "error": "err", "warn": "warning"}

func prioritySeverity(name string) int { return syslogPriorities[name] }

// rsyslogCoverage derives, per facility, whether it is routed anywhere and
// whether that destination is persistent — walking the rules IN FILE ORDER,
// because a discard ahead of a covering rule means the facility never
// reaches it (Ruling I-13).
func rsyslogCoverage(rules []rsyslogRule) []any {
	out := make([]any, 0, len(syslogFacilities))
	for _, f := range syslogFacilities {
		logged, persistent := false, false
		var target, remote, floor, reason string
		for _, r := range rules {
			if r.facility != f {
				continue
			}
			if r.kind == "discard" {
				reason = "rule processing stops at " + r.line
				break
			}
			if r.kind != "file" && r.kind != "remote" {
				continue
			}
			logged = true
			if floor == "" || prioritySeverity(r.priority) > prioritySeverity(floor) {
				floor = r.priority
			}
			if r.kind == "file" {
				// Ruling I-15: persistent is a property of the TARGET KIND,
				// not of whether the file exists yet.
				if !persistent {
					persistent, target = true, r.target
				}
				continue
			}
			if remote == "" {
				remote = r.target
			}
		}
		if !persistent {
			target = remote
		}
		out = append(out, map[string]any{
			"facility":       f,
			"logged":         logged,
			"persistent":     persistent,
			"priority_floor": floor,
			"target":         target,
			"reason":         reason,
		})
	}
	return out
}

// --- syslog syntax ------------------------------------------------------

// rsyslogLogicalLines joins what rsyslog reads as one statement: a
// backslash-continued legacy line, and a RainerScript call whose parentheses
// span lines — which every RHEL rsyslog.conf's module() blocks do. Comments
// are stripped first, so a "#" inside one can neither open a parenthesis nor
// continue a line; a "#" inside a quoted string is kept.
func rsyslogLogicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	depth := 0
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for _, raw := range splitLines(data) {
		line := strings.TrimRight(stripRsyslogComment(raw), " \t")
		cont := strings.HasSuffix(line, "\\")
		line = strings.TrimSuffix(line, "\\")
		if cur.Len() == 0 {
			// The leading indentation goes, but an inner tab does not: it is
			// what separates a selector from its action.
			line = strings.TrimLeft(line, " \t")
			if line == "" && !cont {
				continue
			}
		} else {
			cur.WriteString(" ")
			line = strings.TrimSpace(line)
		}
		cur.WriteString(line)
		if depth += rsyslogParenDelta(line); depth < 0 {
			depth = 0
		}
		if depth > 0 || cont {
			continue
		}
		flush()
	}
	flush()
	return out
}

// stripRsyslogComment cuts a "#" comment that is not inside a quoted string.
func stripRsyslogComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

func rsyslogParenDelta(line string) int { return rsyslogDelta(line, '(', ')') }
func rsyslogBraceDelta(line string) int { return rsyslogDelta(line, '{', '}') }

func rsyslogDelta(line string, opener, closer byte) int {
	d, inQuote := 0, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == opener:
			d++
		case c == closer:
			d--
		}
	}
	return d
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isPropertyFilter recognises `:property, compare-op, "value" action`. The
// comma after the property name is what tells it from an action written in
// the `:module:argument` form, which a selector line ends with.
func isPropertyFilter(l string) bool {
	if !strings.HasPrefix(l, ":") {
		return false
	}
	rest := l[1:]
	i := strings.IndexAny(rest, ",: \t")
	return i > 0 && rest[i] == ','
}

func allFacilitiesSelector() *rsyslogSelector {
	pri := make(map[string]string, len(syslogFacilities))
	for _, f := range syslogFacilities {
		pri[f] = "debug"
	}
	return &rsyslogSelector{facilities: slices.Clone(syslogFacilities), priority: pri}
}

// parseRsyslogSelector parses one selector list, or returns nil when the text
// is not one. The ";"-joined parts are applied in order: a ".none" part
// REMOVES the facilities it names — from THIS line only, never from the
// target path, which is what lets the Ubuntu default log auth to
// /var/log/auth.log on one line and exclude it from /var/log/syslog on the
// next (Ruling I-14).
func parseRsyslogSelector(sel string) *rsyslogSelector {
	pri := map[string]string{}
	parsedAny := false
	for _, part := range strings.Split(sel, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		dot := strings.LastIndex(part, ".")
		if dot <= 0 || dot == len(part)-1 {
			return nil
		}
		facs, ok := rsyslogFacilityList(part[:dot])
		if !ok {
			return nil
		}
		parsedAny = true
		spec := strings.TrimSpace(part[dot+1:])
		if strings.EqualFold(spec, "none") {
			for _, f := range facs {
				delete(pri, f)
			}
			continue
		}
		floor, ok := rsyslogPriorityFloor(spec)
		if !ok {
			return nil
		}
		for _, f := range facs {
			if cur, seen := pri[f]; !seen || prioritySeverity(floor) > prioritySeverity(cur) {
				pri[f] = floor
			}
		}
	}
	if !parsedAny {
		return nil
	}
	facs := make([]string, 0, len(pri))
	for f := range pri {
		facs = append(facs, f)
	}
	sort.Strings(facs)
	return &rsyslogSelector{facilities: facs, priority: pri}
}

// rsyslogFacilityList expands the comma list (or "*") before a selector's
// dot. A name this version does not know selects nothing — it is not a parse
// failure, since a plugin may define its own.
func rsyslogFacilityList(s string) ([]string, bool) {
	if strings.TrimSpace(s) == "" {
		return nil, false
	}
	var out []string
	for _, name := range strings.Split(s, ",") {
		switch name = strings.ToLower(strings.TrimSpace(name)); {
		case name == "":
			return nil, false
		case name == "*":
			out = append(out, syslogFacilities...)
		case name == "security": // the obsolete alias for auth
			out = append(out, "auth")
		case slices.Contains(syslogFacilities, name):
			out = append(out, name)
		}
	}
	return out, true
}

// rsyslogPriorityFloor names the least severe priority a spec selects, which
// is the floor at which the facility starts being logged. "=info" selects
// exactly that priority and is recorded as its own floor; a negated "!err"
// routes everything BELOW that priority, so the facility is logged and the
// floor is the widest one — the exclusion of the severe end shows only in the
// rule's source line.
func rsyslogPriorityFloor(spec string) (string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "*" {
		return "debug", true
	}
	negated := strings.HasPrefix(spec, "!")
	spec = strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(spec, "!"), "="))
	if c, ok := canonicalPriority[spec]; ok {
		spec = c
	}
	if _, ok := syslogPriorities[spec]; !ok {
		return "", false
	}
	if negated {
		return "debug", true
	}
	return spec, true
}

// rsyslogAction is one parsed action. unmodelled marks the two action-shaped
// members of Ruling I-12's fixed list: a "?TemplateName" dynamic file, and an
// omfile/omfwd whose argument cannot be parsed.
type rsyslogAction struct {
	kind       string // file | remote | user | pipe | module | discard
	target     string
	unmodelled bool
}

func parseRsyslogAction(act string) rsyslogAction {
	act = strings.TrimSpace(act)
	if act == "" {
		return rsyslogAction{}
	}
	if act == "~" || strings.EqualFold(act, "stop") {
		return rsyslogAction{kind: "discard"}
	}
	if strings.HasPrefix(strings.ToLower(act), "action(") {
		return parseRsyslogActionCall(act)
	}
	// A leading "-" only ever marks an asynchronous file write, and a ";"
	// only ever introduces the template a legacy action formats with.
	if strings.HasPrefix(act, "-/") || strings.HasPrefix(act, "-?") {
		act = act[1:]
	}
	if i := strings.Index(act, ";"); i >= 0 {
		act = strings.TrimSpace(act[:i])
	}
	low := strings.ToLower(act)
	switch {
	case act == "":
		return rsyslogAction{}
	case strings.HasPrefix(act, "?"):
		// The file name resolves through a template this version does not
		// expand, so which file it writes is unknown.
		return rsyslogAction{unmodelled: true}
	case strings.HasPrefix(act, "@"):
		return rsyslogAction{kind: "remote", target: act}
	case strings.HasPrefix(act, "|"):
		return rsyslogAction{kind: "pipe", target: strings.TrimSpace(act[1:])}
	case strings.HasPrefix(act, "/"):
		return rsyslogAction{kind: "file", target: act}
	case strings.HasPrefix(low, ":omusrmsg:"):
		return rsyslogAction{kind: "user", target: act[len(":omusrmsg:"):]}
	case strings.HasPrefix(low, ":omfile:"):
		if p := strings.TrimSpace(act[len(":omfile:"):]); strings.HasPrefix(p, "/") {
			return rsyslogAction{kind: "file", target: p}
		}
		return rsyslogAction{unmodelled: true}
	case strings.HasPrefix(low, ":omfwd:"):
		if p := strings.TrimSpace(act[len(":omfwd:"):]); p != "" {
			return rsyslogAction{kind: "remote", target: p}
		}
		return rsyslogAction{unmodelled: true}
	case strings.HasPrefix(act, ":"):
		return rsyslogAction{kind: "module", target: act}
	}
	// What is left is a user list ("*" is every logged-in user).
	return rsyslogAction{kind: "user", target: act}
}

func parseRsyslogActionCall(act string) rsyslogAction {
	attrs := rainerAttrs(act)
	switch strings.ToLower(attrs["type"]) {
	case "omfile":
		if attrs["dynafile"] != "" {
			return rsyslogAction{unmodelled: true}
		}
		if f := attrs["file"]; strings.HasPrefix(f, "/") {
			return rsyslogAction{kind: "file", target: f}
		}
		return rsyslogAction{unmodelled: true}
	case "omfwd":
		t := attrs["target"]
		if t == "" {
			return rsyslogAction{unmodelled: true}
		}
		if p := attrs["port"]; p != "" {
			t += ":" + p
		}
		return rsyslogAction{kind: "remote", target: t}
	case "omusrmsg":
		return rsyslogAction{kind: "user", target: attrs["users"]}
	case "":
		return rsyslogAction{unmodelled: true}
	default:
		return rsyslogAction{kind: "module", target: strings.ToLower(attrs["type"])}
	}
}

// rainerAttrs reads the key="value" attributes of a RainerScript call. Keys
// are folded to lower case, since rsyslog accepts File= and file= alike.
func rainerAttrs(s string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(s); {
		q := strings.IndexByte(s[i:], '"')
		if q < 0 {
			break
		}
		q += i
		end := strings.IndexByte(s[q+1:], '"')
		if end < 0 {
			break
		}
		end += q + 1
		key := strings.TrimSuffix(strings.TrimSpace(s[i:q]), "=")
		if j := strings.LastIndexAny(key, " \t(,"); j >= 0 {
			key = key[j+1:]
		}
		if key = strings.TrimSpace(key); key != "" {
			out[strings.ToLower(key)] = s[q+1 : end]
		}
		i = end + 1
	}
	return out
}
