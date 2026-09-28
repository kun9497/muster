//go:build linux

package collectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The fim collector (spec I-4, J-5): which file-integrity tool the host
// has, and for AIDE — the one tool muster models — where its configuration
// and database are and whether anything will actually run it. The other
// tools are evidence only.
const (
	aideConfDebian   = "/etc/aide/aide.conf"
	aideConfEL       = "/etc/aide.conf"
	aideDefaults     = "/etc/default/aide"
	aideDBGlob       = "/var/lib/aide/*"
	fimCronDailyGlob = "/etc/cron.daily/*"
	fimCronDGlob     = "/etc/cron.d/*"
	fimRowCap        = 64 // J-16, fim.aide.schedules and fim.other_tools

	// nobleShimMarker is the test the Ubuntu 24.04 cron.daily shim makes
	// before exiting in favour of dailyaidecheck.timer (J-5).
	nobleShimMarker = "/run/systemd/system"
)

var (
	aideBins = []string{"/usr/bin/aide", "/usr/sbin/aide"}
	// otherFimBins are the tools muster names but does not model.
	otherFimBins = []string{
		"/usr/sbin/tripwire", "/usr/sbin/samhain", "/usr/bin/osqueryd", "/opt/osquery/bin/osqueryd",
		"/usr/sbin/integrit", "/var/ossec/bin/wazuh-agentd", "/var/ossec/bin/ossec-agentd",
	}
	aideConfs = []string{aideConfDebian, aideConfEL}

	// listTimersCmd carries each timer's next elapse time. The unit-file
	// inventory the cron collector reads says whether a timer is enabled,
	// not whether it is armed, and a static timer a target pulls in is
	// armed without being enabled.
	listTimersCmd = collect.Command{Path: systemctlPath, Args: []string{"list-timers", "--all", "--no-legend", "--no-pager"}}
)

func fimReads() []string {
	reads := slices.Concat(aideBins, otherFimBins, aideConfs)
	return append(reads, aideDefaults, fimCronDailyGlob, fimCronDGlob, etcCrontab, aideDBGlob, systemdMarker)
}

var fimCollector = collect.Collector{
	Name: "fim",
	Declare: collect.Declaration{
		Reads:    fimReads(),
		Commands: []collect.Command{listTimersCmd},
		// Every read is world-readable on the Debian family; EL9's 0600
		// aide.conf and 24.04's 0700 /var/lib/aide are reported denied (C3)
		// rather than wrapped as a privilege failure.
		Needs: "none",
	},
	Run: runFim,
}

func runFim(ctx context.Context, a collect.Access, b *collect.Builder) error {
	aide := ""
	for _, p := range aideBins {
		if pathPresent(a, p) {
			aide = p
			break
		}
	}
	var others []any
	var named []string
	for _, p := range slices.Sorted(slices.Values(otherFimBins)) {
		if pathPresent(a, p) {
			others = append(others, map[string]any{"name": path.Base(p), "path": p})
			named = append(named, path.Base(p)+" ("+p+")")
		}
	}

	switch {
	case aide != "":
		b.Set("fim.tool", collect.OK("aide", permSrc(aide)))
		b.Set("fim.aide.installed", collect.OK(true, permSrc(aide)))
	case len(others) == 0:
		b.Set("fim.tool", collect.OK("none", &facts.Source{Kind: "derived"}))
		b.Set("fim.aide.installed", collect.OK(false, &facts.Source{Kind: "derived"}))
	default:
		// The key means "the tool muster models on this host": there is
		// none, though there is a tool, so the control reads MANUAL with
		// the evidence attached (spec §4).
		b.Set("fim.tool", collect.Absent("aide is not installed; other tools present: "+strings.Join(named, ", ")))
		b.Set("fim.aide.installed", collect.OK(false, &facts.Source{Kind: "derived"}))
	}
	rows, cut := capRows(append([]any{}, others...), fimRowCap)
	b.Set("fim.other_tools", withTruncation(collect.OK(rows, &facts.Source{Kind: "derived"}), cut))

	aideDatabase(a, b, aide != "")
	list, scheduled := aideSchedules(ctx, a)
	b.Set("fim.aide.schedules", list)
	b.Set("fim.aide.scheduled", scheduled)
	return nil
}

// aideDatabase writes the configuration path and the three database leaves.
// With AIDE installed, a configuration that names no database — no file at
// either candidate path, or no database line — is a known answer: there is
// no database AIDE would check against, so database_present is ok false.
func aideDatabase(a collect.Access, b *collect.Builder, installed bool) {
	conf := ""
	for _, p := range aideConfs {
		if pathPresent(a, p) {
			conf = p
			break
		}
	}
	setDB := func(e facts.Envelope) {
		b.Set("fim.aide.database_path", e)
		b.Set("fim.aide.database_present", e)
		b.Set("fim.aide.database_modified", e)
	}
	noDatabase := func(reason string, inputs ...string) {
		setDB(collect.Absent(reason))
		if installed {
			src := &facts.Source{Kind: "derived"}
			for _, p := range inputs {
				src.Inputs = append(src.Inputs, facts.Source{Kind: "file", Path: p})
			}
			e := collect.OK(false, src)
			e.Reason = reason
			b.Set("fim.aide.database_present", e)
		}
	}
	if conf == "" {
		b.Set("fim.aide.config_path", collect.Absent("neither "+aideConfDebian+" nor "+aideConfEL+" exists"))
		noDatabase("no AIDE configuration file names a database: neither "+aideConfDebian+" nor "+aideConfEL+" exists", aideConfDebian, aideConfEL)
		return
	}
	b.Set("fim.aide.config_path", collect.OK(conf, permSrc(conf)))
	data, meta, err := a.ReadFile(conf, readLimit)
	if err != nil {
		// C3: the file is there and could not be read, so its answer is
		// that read's status — never a guessed default path.
		setDB(readErrorEnv(conf, err))
		return
	}
	c := parseAideConf(data)
	if !c.found {
		noDatabase("no database_in= or database= line in "+conf, conf)
		return
	}
	dp := collect.OKRead(c.database, permSrc(conf), meta)
	if len(c.unresolved) > 0 {
		refs := make([]string, 0, len(c.unresolved))
		for _, n := range c.unresolved {
			refs = append(refs, "@@{"+n+"}")
		}
		dp.Reason = "left as written: " + conf + " never defines " + strings.Join(refs, ", ")
	}
	b.Set("fim.aide.database_path", dp)

	p := c.database
	if ok, _ := path.Match(aideDBGlob, p); !ok || path.Clean(p) != p {
		// C4: a path the model declines to stat is absent, naming it.
		e := collect.Absent(p + " is outside the collector's declaration (" + aideDBGlob + ")")
		b.Set("fim.aide.database_present", e)
		b.Set("fim.aide.database_modified", e)
		return
	}
	st, err := a.Stat(p)
	switch {
	case err == nil && st.Kind == "regular":
		b.Set("fim.aide.database_present", collect.OK(true, permSrc(p)))
		if st.ModTime.IsZero() {
			b.Set("fim.aide.database_modified", collect.Absent("the modification time of "+p+" is not known"))
		} else {
			b.Set("fim.aide.database_modified", collect.OK(st.ModTime.UTC().Format(time.RFC3339), permSrc(p)))
		}
	case err == nil || errors.Is(err, fs.ErrNotExist):
		b.Set("fim.aide.database_present", collect.OK(false, permSrc(p)))
		b.Set("fim.aide.database_modified", collect.Absent("no database at "+p))
	default:
		e := readErrorEnv(p, err)
		b.Set("fim.aide.database_present", e)
		b.Set("fim.aide.database_modified", e)
	}
}

// fimSchedules gathers the schedule rows and the first failure that makes
// the list incomplete.
type fimSchedules struct {
	a       collect.Access
	rows    []any
	inputs  []facts.Source
	failure *facts.Envelope
	cut     bool
}

func (s *fimSchedules) fail(e facts.Envelope) {
	if s.failure == nil {
		s.failure = &e
	}
}

func (s *fimSchedules) row(kind, p string, armed bool, detail string) {
	s.rows = append(s.rows, map[string]any{"kind": kind, "path": p, "armed": armed, "detail": detail})
}

// aideSchedules answers fim.aide.schedules and fim.aide.scheduled (J-5).
func aideSchedules(ctx context.Context, a collect.Access) (facts.Envelope, facts.Envelope) {
	s := &fimSchedules{a: a}
	systemd := pathPresent(a, systemdMarker)

	// The CRON_DAILY_RUN gate: both scripts default it to yes, and the
	// 24.04 service reads the same file.
	// An empty value is unset: the scripts read ${CRON_DAILY_RUN:-yes}. A file
	// that is there and cannot be read leaves the gate unknown (C3): every row
	// it controls is disarmed with that read as the detail, and scheduled is
	// that read's status unless a row the gate does not control is armed.
	gate := ""
	var gateErr *facts.Envelope
	switch data, _, err := a.ReadFile(aideDefaults, readLimit); {
	case err == nil:
		s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: aideDefaults})
		if v, set := cronDailyRun(data); set && v != "yes" && v != "" {
			gate = aideDefaults + " sets CRON_DAILY_RUN=" + v
		}
	case !errors.Is(err, fs.ErrNotExist):
		e := readErrorEnv(aideDefaults, err)
		gate, gateErr = e.Reason, &e
	}

	s.cronDaily(systemd, gate)
	s.crontabs()

	var timerFailure *facts.Envelope
	if systemd {
		timerFailure = s.timers(ctx, gate)
	}

	slices.SortStableFunc(s.rows, func(x, y any) int {
		return strings.Compare(x.(map[string]any)["path"].(string), y.(map[string]any)["path"].(string))
	})
	armed := slices.ContainsFunc(s.rows, func(r any) bool { return r.(map[string]any)["armed"] == true })
	blocked := s.failure
	if blocked == nil {
		blocked = timerFailure
	}
	if blocked != nil {
		// An incomplete inventory is that failure's answer for the list;
		// scheduled is still true when a row that WAS read is armed.
		if armed {
			return *blocked, collect.OK(true, s.src())
		}
		return *blocked, *blocked
	}
	scheduled := collect.OK(armed, s.src())
	if !armed && gateErr != nil {
		scheduled = *gateErr
	}
	rows, cut := capRows(append([]any{}, s.rows...), fimRowCap)
	return withTruncation(collect.OK(rows, s.src()), cut || s.cut), scheduled
}

func (s *fimSchedules) src() *facts.Source {
	return &facts.Source{Kind: "derived", Inputs: slices.Clone(s.inputs)}
}

// cronDaily reads the run-parts scripts whose name contains aide.
func (s *fimSchedules) cronDaily(systemd bool, gate string) {
	matches, err := s.a.Glob(fimCronDailyGlob)
	if err != nil {
		s.fail(globReadError(fimCronDailyGlob, err, collect.ErrorEnv(fimCronDailyGlob+": "+err.Error())))
		return
	}
	slices.Sort(matches)
	for _, m := range matches {
		base := path.Base(m)
		if !strings.Contains(base, "aide") {
			continue
		}
		if !runPartsName(base) {
			s.row("cron_daily", m, false, "run-parts skips this name")
			continue
		}
		meta, err := s.a.Stat(m)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, collect.ErrSymlink):
			// muster never follows a link; a row, never an error.
			s.row("cron_daily", m, false, "not a regular file")
			continue
		case err != nil:
			s.fail(readErrorEnv(m, err))
			continue
		case meta.Kind != "regular":
			s.row("cron_daily", m, false, "not a regular file")
			continue
		case meta.Mode&0o111 == 0:
			s.row("cron_daily", m, false, "not executable (mode "+fmt.Sprintf("%04o", meta.Mode)+"); run-parts skips it")
			continue
		}
		data, _, err := s.a.ReadFile(m, readLimit)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				s.fail(readErrorEnv(m, err))
			}
			continue
		}
		s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: m})
		switch {
		case systemd && bytes.Contains(data, []byte(nobleShimMarker)):
			s.row("cron_daily", m, false, "runs only without systemd")
		case gate != "":
			s.row("cron_daily", m, false, gate)
		default:
			s.row("cron_daily", m, true, "")
		}
	}
}

// crontabs reads the system crontabs for a job that runs aide.
func (s *fimSchedules) crontabs() {
	matches, err := s.a.Glob(fimCronDGlob)
	if err != nil {
		s.fail(globReadError(fimCronDGlob, err, collect.ErrorEnv(fimCronDGlob+": "+err.Error())))
	}
	slices.Sort(matches)
	files := append(slices.Clone(matches), etcCrontab)
	for _, m := range files {
		data, _, err := s.a.ReadFile(m, readLimit)
		switch {
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, collect.ErrNotRegular), errors.Is(err, collect.ErrSymlink):
			// Not a crontab cron reads as a regular file; a directory or a
			// link carries no job this model can see.
			continue
		case err != nil:
			s.fail(readErrorEnv(m, err))
			continue
		}
		s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: m})
		if namesAide(data) {
			kind := "cron_d"
			if m == etcCrontab {
				kind = "crontab"
			}
			s.row(kind, m, true, "")
		}
	}
}

// timers reads the timer inventory and returns the answer for both leaves
// when it cannot be read: a kill is a timeout; a systemctl that could not
// start, or a host not booted with systemd, is the environment's limitation
// (R220, unsupported); any other non-zero exit is an error naming it.
func (s *fimSchedules) timers(ctx context.Context, gate string) *facts.Envelope {
	out := s.a.Run(ctx, listTimersCmd)
	if e := listTimersFailure(out); e != nil {
		return e
	}
	s.inputs = append(s.inputs, *out.Source(listTimersCmd))
	s.cut = s.cut || out.Truncated
	for _, t := range parseListTimers(out.Stdout) {
		if !strings.Contains(t.unit, "aide") {
			continue
		}
		switch {
		case !t.armed:
			s.row("timer", t.unit, false, "no next elapse time in systemctl list-timers")
		case gate != "":
			s.row("timer", t.unit, false, gate)
		default:
			s.row("timer", t.unit, true, "")
		}
	}
	return nil
}

// runPartsName is the name rule Debian's run-parts applies (and the
// narrowest of the families'): letters, digits, underscore and hyphen only,
// so aide.dpkg-old or aide~ never runs.
func runPartsName(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return name != ""
}

// listTimersFailure classifies a systemctl list-timers run that gave no
// inventory, or returns nil when it gave one.
func listTimersFailure(out collect.Output) *facts.Envelope {
	line := commandLine(listTimersCmd)
	stderr := firstLine(out.Stderr)
	var e facts.Envelope
	switch {
	case out.TimedOut:
		e = collect.TimeoutEnv(line + " timed out")
	case out.Err != nil:
		e = collect.Unsupported("systemd timer inventory unavailable: " + line + ": " + out.Err.Error())
	case out.ExitCode == 0:
		return nil
	case strings.Contains(string(out.Stderr), "System has not been booted with systemd"):
		e = collect.Unsupported("systemd timer inventory unavailable: " + stderr)
	default:
		reason := line + " exited " + strconv.Itoa(out.ExitCode)
		if stderr != "" {
			reason += ": " + stderr
		}
		e = collect.ErrorEnv(reason)
	}
	return &e
}
