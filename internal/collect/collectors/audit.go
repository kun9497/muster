//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The audit collector (spec I-3): the audit daemon's rules and immutable
// flag as two-home settings, the four auditctl -s fields, the seven
// auditd.conf leaves a control judges, and the permission facts of the log
// file auditd.conf names and of its directory (C1: a path a daemon's
// configuration names belongs to that daemon's collector).
const (
	auditdConfPath   = "/etc/audit/auditd.conf"
	auditRulesPath   = "/etc/audit/audit.rules"
	auditRulesDDir   = "/etc/audit/rules.d"
	auditRulesDGlob  = "/etc/audit/rules.d/*.rules"
	auditDefaultLog  = "/var/log/audit/audit.log"
	auditRulesRowCap = 2000 // J-16

	auditRulesDMissing = "rules.d is missing: augenrules loads nothing at boot"
)

// The two commands, fixed arguments, the primitive's 5 s and 1 MiB. On EL9
// /sbin is a link to usr/sbin, so one path serves both families.
var (
	auditctlListCmd   = collect.Command{Path: "/usr/sbin/auditctl", Args: []string{"-l"}}
	auditctlStatusCmd = collect.Command{Path: "/usr/sbin/auditctl", Args: []string{"-s"}}
)

// auditConfKeys are the auditd.conf keywords published under audit.conf.*,
// in registry order.
var auditConfKeys = []string{
	"log_file", "log_group", "max_log_file_action", "space_left_action",
	"admin_space_left_action", "disk_full_action", "disk_error_action",
}

// auditStatusFields are the auditctl -s fields published under
// audit.status.*.
var auditStatusFields = []string{"enabled", "failure", "lost", "backlog_limit"}

var auditCollector = collect.Collector{
	Name: "audit",
	Declare: collect.Declaration{
		Reads: []string{
			auditdConfPath, auditRulesPath, auditRulesDDir, auditRulesDGlob,
			systemdMarker, groupPath,
			"/var/log", "/var/log/*", "/var/log/audit", "/var/log/audit/*",
		},
		Commands: []collect.Command{auditctlListCmd, auditctlStatusCmd},
		// J-7: documentation only. run.go never reads Needs, so a non-root
		// run still runs this collector, and every leaf it cannot read is
		// denied, never error: auditctl's exit 4, the 0750 /etc/audit, the
		// 0700 or 0750 /var/log/audit.
		Needs: "root",
	},
	Run: runAudit,
}

func runAudit(ctx context.Context, a collect.Access, b *collect.Builder) error {
	listOut := a.Run(ctx, auditctlListCmd)
	listEnv, listOK := auditctlEnvelope(listOut, auditctlListCmd)
	statusOut := a.Run(ctx, auditctlStatusCmd)
	statusEnv, statusOK := auditctlEnvelope(statusOut, auditctlStatusCmd)

	// Runtime: the rule lines auditctl -l printed.
	rulesRuntime, loadedCount := copyEnvelope(listEnv), copyEnvelope(listEnv)
	if listOK {
		n := len(auditctlRuleLines(listOut.Stdout))
		rulesRuntime.Value, loadedCount.Value = n > 0, n
	}

	// Runtime: the status fields, and the lock read off enabled.
	var fields map[string]int
	if statusOK {
		fields, _ = parseAuditctlStatus(statusOut.Stdout)
	}
	statusLeaf := func(name string) facts.Envelope {
		e := copyEnvelope(statusEnv)
		if !statusOK {
			return e
		}
		n, ok := fields[name]
		if !ok {
			return withTruncation(collect.Absent(commandLine(auditctlStatusCmd)+" printed no "+name), statusEnv.Truncated)
		}
		e.Value = n
		return e
	}
	immutableRuntime := statusLeaf("enabled")
	if immutableRuntime.Status == facts.StatusOK {
		immutableRuntime.Value = immutableRuntime.Value.(int) == 2
	}

	p := auditPersisted(a)
	b.SetSetting("audit.rules.present", auditSetting(rulesRuntime, p.present(), nil))
	b.SetSetting("audit.immutable", auditSetting(immutableRuntime, p.immutable(), p.immutableWinner()))
	b.Set("audit.rules.loaded_count", loadedCount)
	b.Set("audit.rules.persisted_count", p.count())
	b.Set("audit.rules.persisted", p.rows())
	for _, name := range auditStatusFields {
		b.Set("audit.status."+name, statusLeaf(name))
	}

	writeAuditConf(a, b)
	return nil
}

// auditSetting builds one two-home leaf the way sysctlSetting does (K-3):
// effective is a COPY of runtime, and the winner a copy of runtime's source
// when runtime answered. When it did not, the winner is the persisted line
// that decided the persisted side, if one did (spec I-3: audit.immutable's
// winner names the file that carried the deciding line).
func auditSetting(runtime, persisted facts.Envelope, persistedWinner *facts.Source) facts.Setting {
	effective := copyEnvelope(runtime)
	s := facts.Setting{Runtime: &runtime, Persisted: &persisted, Effective: &effective}
	switch {
	case runtime.Status == facts.StatusOK && runtime.Source != nil:
		w := *runtime.Source
		s.Winner = &w
	case persistedWinner != nil:
		w := *persistedWinner
		s.Winner = &w
	}
	return s
}

// auditctlEnvelope classifies one auditctl run (J-1) in this order: a kill,
// a binary that is not there, exit 4 (the CAP_AUDIT_CONTROL gate), exit 255
// with EPERM (a pid namespace the kernel will not answer), the two texts of a
// kernel without audit, an exit 0 that carried no answer, any other code. On
// success the envelope is ok with no value and the command as its source,
// and the bool says the caller may parse stdout. A status nobody parsed is
// never a value.
func auditctlEnvelope(out collect.Output, cmd collect.Command) (facts.Envelope, bool) {
	line := commandLine(cmd)
	stderr := string(out.Stderr)
	var e facts.Envelope
	ok := false
	switch {
	case out.TimedOut:
		e = collect.TimeoutEnv(line + " timed out after " + patchTimeout(cmd).String())
	case out.Err != nil:
		// The kernel may hold rules nobody can list; the controls that need
		// the runtime side gate on the daemon being installed anyway.
		return collect.Absent("auditctl is not installed"), false
	case out.ExitCode == 4:
		if euid() != 0 {
			e = collect.Denied(line + " needs CAP_AUDIT_CONTROL, which a non-root run does not have: " + auditctlReason(out))
		} else {
			e = collect.Unsupported(line + ": no CAP_AUDIT_CONTROL: an unprivileged container")
		}
	case out.ExitCode == 255 && strings.Contains(stderr, "Operation not permitted"):
		e = collect.Unsupported(line + ": kernel audit is not reachable from this pid namespace")
	case strings.Contains(stderr, "audit support not in kernel"), strings.Contains(stderr, "Cannot open netlink audit socket"):
		e = collect.Unsupported(line + ": " + firstLine(out.Stderr))
	case out.ExitCode == 0 && auditctlGaveNothing(out, cmd):
		e = collect.Unsupported(line + ": the kernel gave no audit status")
	case out.ExitCode == 0:
		e = collect.OK(nil, nil)
		ok = true
	default:
		e = collect.ErrorEnv(line + " exited " + strconv.Itoa(out.ExitCode) + ": " + auditctlReason(out))
	}
	e.Source = out.Source(cmd)
	return withTruncation(e, out.Truncated), ok
}

// auditctlGaveNothing is J-1's exit 0 with no answer: a non-init user
// namespace gets ECONNREFUSED, which auditctl swallows ("The audit system is
// disabled", exit 0). -s answered only if an enabled line parsed; -l always
// prints a rule or "No rules", so an empty -l answered nothing either.
func auditctlGaveNothing(out collect.Output, cmd collect.Command) bool {
	if strings.Contains(string(out.Stderr)+string(out.Stdout), "The audit system is disabled") {
		return true
	}
	if cmd.Args[0] == "-s" {
		_, ok := parseAuditctlStatus(out.Stdout)
		return !ok
	}
	return strings.TrimSpace(string(out.Stdout)) == ""
}

func auditctlReason(out collect.Output) string {
	if s := firstLine(out.Stderr); s != "" {
		return s
	}
	return "no message"
}

// auditPersist is the persisted side: the rules read, in load order, with the
// source of the answer — or the one envelope every persisted leaf carries
// instead (a missing rules.d, a read that failed — C3).
type auditPersist struct {
	fail      *facts.Envelope
	rules     []auditRule
	src       *facts.Source
	truncated bool
}

// auditPersisted models augenrules(8), the only loader on a systemd host
// (ExecStartPost on both families; the daemon never reads audit.rules
// itself): the *.rules files of rules.d. rules.d is probed first (J-23),
// because Glob cannot tell a missing directory from an empty one: missing is
// absent — a hand-written audit.rules beside it is dead at the next boot —
// and empty is "no rules". /etc/audit/audit.rules is the source only on a
// host without systemd.
func auditPersisted(a collect.Access) auditPersist {
	if !pathPresent(a, systemdMarker) {
		data, meta, err := a.ReadFile(auditRulesPath, readLimit)
		if err != nil {
			e := readErrorEnv(auditRulesPath, err)
			return auditPersist{fail: &e}
		}
		return auditPersist{
			rules:     parseAuditRules(data, auditRulesPath),
			src:       &facts.Source{Kind: "file", Path: auditRulesPath},
			truncated: meta.Truncated,
		}
	}
	if _, err := a.Stat(auditRulesDDir); err != nil {
		var e facts.Envelope
		if errors.Is(err, fs.ErrNotExist) {
			e = collect.Absent(auditRulesDMissing)
		} else {
			e = readErrorEnv(auditRulesDDir, err)
		}
		return auditPersist{fail: &e}
	}
	matches, err := a.Glob(auditRulesDGlob)
	if err != nil {
		e := globReadError(auditRulesDGlob, err, collect.ErrorEnv(auditRulesDGlob+": "+err.Error()))
		return auditPersist{fail: &e}
	}
	// chainScan's rule: a /dev/null link is a mask (K-21), a name that
	// vanished is not part of the chain, and the first real read failure is
	// the answer for every value the chain could set (C3).
	var s chainScan
	for _, m := range augenrulesOrder(matches) {
		s.read(a, m)
	}
	if s.readErr != nil {
		return auditPersist{fail: s.readErr}
	}
	p := auditPersist{truncated: s.truncated, src: filesSource(pathsOf(s.files))}
	for _, f := range s.files {
		p.rules = append(p.rules, parseAuditRules(f.data, f.path)...)
	}
	if p.src == nil {
		p.src = &facts.Source{Kind: "file", Path: auditRulesDDir}
	}
	return p
}

// ok builds a persisted envelope with a source of its own, so no two leaves
// share storage (R147).
func (p auditPersist) ok(v any) facts.Envelope {
	return withTruncation(copyEnvelope(collect.OK(v, p.src)), p.truncated)
}

// ruleCount is the watch and syscall lines: control lines configure the
// kernel and are not rules.
func (p auditPersist) ruleCount() int {
	n := 0
	for _, r := range p.rules {
		if r.kind == "watch" || r.kind == "syscall" {
			n++
		}
	}
	return n
}

func (p auditPersist) present() facts.Envelope {
	if p.fail != nil {
		return copyEnvelope(*p.fail)
	}
	return p.ok(p.ruleCount() > 0)
}

func (p auditPersist) count() facts.Envelope {
	if p.fail != nil {
		return copyEnvelope(*p.fail)
	}
	return p.ok(p.ruleCount())
}

// rows are the persisted rules in load order — the files in augenrules'
// order, each top to bottom — which is the list's sort (J-16's cap applies).
func (p auditPersist) rows() facts.Envelope {
	if p.fail != nil {
		return copyEnvelope(*p.fail)
	}
	rows := make([]any, 0, len(p.rules))
	for _, r := range p.rules {
		rows = append(rows, map[string]any{
			"file": r.file, "line": r.line, "kind": r.kind, "key": r.key, "text": r.text,
		})
	}
	rows, cut := capRows(rows, auditRulesRowCap)
	return withTruncation(p.ok(rows), cut)
}

// immutable is the persisted lock: the last -e line is -e 2. Its source is
// that line when there is one.
func (p auditPersist) immutable() facts.Envelope {
	if p.fail != nil {
		return copyEnvelope(*p.fail)
	}
	v, _, found := lastEnableValue(p.rules)
	e := p.ok(found && v == 2)
	if w := p.immutableWinner(); w != nil {
		e.Source = w
	}
	return e
}

// immutableWinner is the -e line that decided the persisted lock, or nil.
func (p auditPersist) immutableWinner() *facts.Source {
	if p.fail != nil {
		return nil
	}
	r, found := lastEnableRule(p.rules)
	if !found {
		return nil
	}
	return &facts.Source{Kind: "file", Path: r.file, Line: r.line, Raw: r.text}
}

// writeAuditConf publishes the seven auditd.conf leaves and the permission
// facts of the log file and its directory. An auditd.conf that cannot be read
// is the answer for every leaf (C3) — the permission facts too, since the
// path they are about is the one the file would have named.
func writeAuditConf(a collect.Access, b *collect.Builder) {
	data, meta, err := a.ReadFile(auditdConfPath, readLimit)
	if err != nil {
		e := readErrorEnv(auditdConfPath, err)
		for _, k := range auditConfKeys {
			b.Set("audit.conf."+k, e)
		}
		for _, prefix := range []string{"audit.log_file", "audit.log_dir"} {
			for _, l := range permLeaves {
				b.Set(prefix+"."+l, e)
			}
		}
		return
	}
	conf := parseAuditdConf(data)
	src := &facts.Source{Kind: "file", Path: auditdConfPath}
	for _, k := range auditConfKeys {
		v, ok := conf[k]
		switch {
		case ok:
			b.Set("audit.conf."+k, collect.OKRead(v, src, meta))
		case k == "log_file":
			// The one documented default muster looks at: there is no
			// verdict on the path string, only on the file it names, whose
			// own existence is the proof.
			derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: auditdConfPath}}}
			b.Set("audit.conf.log_file", collect.OKRead(auditDefaultLog, derived, meta))
		default:
			// A daemon's compiled default is not a decision anybody made.
			b.Set("audit.conf."+k, withTruncation(collect.Absent("auditd.conf sets no "+k), meta.Truncated))
		}
	}

	logFile := auditDefaultLog
	if v, ok := conf["log_file"]; ok {
		logFile = path.Clean(v)
	}
	var groups map[int]string
	var gmeta collect.ReadMeta
	var gerr error
	loaded := false
	perm := func(prefix, p string) {
		// C4: a path outside the declaration is one muster declined to
		// read — absent with the path, never an error, and never a stat
		// the guard would refuse.
		if !path.IsAbs(p) || !declared(a, p) {
			e := collect.Absent(p + ": outside the paths muster reads")
			for _, l := range permLeaves {
				b.Set(prefix+"."+l, e)
			}
			return
		}
		if !loaded {
			groups, gmeta, gerr = groupNames(a)
			loaded = true
		}
		writePermFacts(b, a, prefix, p, groups, gmeta, gerr, false)
	}
	perm("audit.log_file", logFile)
	perm("audit.log_dir", path.Dir(logFile))
}
