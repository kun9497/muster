//go:build linux

package collectors

import (
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// stockStatus is auditctl -s on a stock EL9 host whose daemon runs with the
// shipped rules: enabled, printk on failure, no lock.
const stockStatus = "enabled 1\nfailure 1\npid 812\nlost 0\nbacklog_limit 8192\n"

// auditAccess is a stock EL9 host: systemd, rules.d holding the shipped
// audit.rules (10-base-config: control lines only), the upstream auditd.conf,
// auditctl answering "No rules", and the log directory 0700 root with the log
// 0600 root.
func auditAccess() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			auditdConfPath:                   "auditd.conf.sample",
			"/etc/audit/rules.d/audit.rules": "audit.rules.sample",
			groupPath:                        "group",
		},
		dirs: map[string]bool{systemdMarker: true, auditRulesDDir: true},
		stats: map[string]statResult{
			"/var/log/audit":           {mode: 0o700, kind: "dir"},
			"/var/log/audit/audit.log": {mode: 0o600, kind: "regular"},
		},
		cmds: map[string]cmdResult{
			cmdKey(auditctlListCmd):   {file: "auditctl_l.norules"},
			cmdKey(auditctlStatusCmd): {stdout: []byte(stockStatus)},
		},
	}
}

func auditInt(t *testing.T, b *collect.Builder, key string) int {
	t.Helper()
	e := env(t, b, key)
	n, ok := e.Value.(int)
	if e.Status != facts.StatusOK || !ok {
		t.Fatalf("%s = %+v, want an ok int", key, e)
	}
	return n
}

func sideIs(t *testing.T, what string, e *facts.Envelope, want any) {
	t.Helper()
	if e == nil || e.Status != facts.StatusOK || e.Value != want {
		t.Errorf("%s = %+v, want ok %v", what, e, want)
	}
}

func statusIs(t *testing.T, what string, e *facts.Envelope, want facts.Status, reason string) {
	t.Helper()
	if e == nil || e.Status != want || !strings.Contains(e.Reason, reason) {
		t.Errorf("%s = %+v, want %s naming %q", what, e, want, reason)
	}
}

func TestAuditStockEL9(t *testing.T) {
	b := build(t, "audit", auditAccess())

	present := setting(t, b, "audit.rules.present")
	sideIs(t, "rules.present runtime", present.Runtime, false)
	sideIs(t, "rules.present persisted", present.Persisted, false)
	sideIs(t, "rules.present effective", present.Effective, false)
	if present.Effective == present.Runtime || present.Effective.Source == present.Runtime.Source {
		t.Error("effective must be a copy of runtime, not the same storage (R147)")
	}
	if present.Winner == nil || present.Winner.Kind != "command" || present.Winner.Cmd != cmdKey(auditctlListCmd) {
		t.Errorf("winner = %+v, want the auditctl -l source", present.Winner)
	}
	if src := present.Persisted.Source; src == nil || src.Path != "/etc/audit/rules.d/audit.rules" {
		t.Errorf("persisted source = %+v, want the one rules.d file read", src)
	}
	if n := auditInt(t, b, "audit.rules.persisted_count"); n != 0 {
		t.Errorf("persisted_count = %d, want 0: 10-base-config has control lines only", n)
	}
	if n := auditInt(t, b, "audit.rules.loaded_count"); n != 0 {
		t.Errorf("loaded_count = %d, want 0 from No rules", n)
	}
	rows := okList(t, b, "audit.rules.persisted")
	var kinds []string
	for _, r := range rows {
		kinds = append(kinds, r.(map[string]any)["kind"].(string))
	}
	if !slices.Equal(kinds, []string{"control", "control", "control", "control"}) {
		t.Errorf("persisted kinds = %v, want the four control lines of 10-base-config", kinds)
	}

	imm := setting(t, b, "audit.immutable")
	sideIs(t, "immutable runtime", imm.Runtime, false)
	sideIs(t, "immutable persisted", imm.Persisted, false)
	sideIs(t, "immutable effective", imm.Effective, false)
	if imm.Winner == nil || imm.Winner.Cmd != cmdKey(auditctlStatusCmd) {
		t.Errorf("immutable winner = %+v, want the auditctl -s source while runtime answered", imm.Winner)
	}

	for k, want := range map[string]int{"enabled": 1, "failure": 1, "lost": 0, "backlog_limit": 8192} {
		if n := auditInt(t, b, "audit.status."+k); n != want {
			t.Errorf("audit.status.%s = %d, want %d", k, n, want)
		}
	}

	var confSources []*facts.Source
	for k, want := range map[string]string{
		"log_file":                "/var/log/audit/audit.log",
		"log_group":               "root",
		"max_log_file_action":     "rotate",
		"space_left_action":       "syslog",
		"admin_space_left_action": "suspend",
		"disk_full_action":        "suspend",
		"disk_error_action":       "suspend",
	} {
		e := env(t, b, "audit.conf."+k)
		if e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("audit.conf.%s = %+v, want %q", k, e, want)
		}
		if e.Source == nil || e.Source.Kind != "file" || e.Source.Path != auditdConfPath {
			t.Errorf("audit.conf.%s source = %+v, want the file", k, e.Source)
		}
		for _, seen := range confSources {
			if seen == e.Source {
				t.Errorf("audit.conf.%s shares its source with another leaf (R147)", k)
			}
		}
		confSources = append(confSources, e.Source)
	}

	for prefix, want := range map[string]int{"audit.log_file": 0o600, "audit.log_dir": 0o700} {
		if m := auditInt(t, b, prefix+".mode"); m != want {
			t.Errorf("%s.mode = %o, want %o", prefix, m, want)
		}
		for _, l := range permLeaves {
			if e := env(t, b, prefix+"."+l); e.Status != facts.StatusOK {
				t.Errorf("%s.%s = %+v, want ok", prefix, l, e)
			}
		}
		if g := env(t, b, prefix+".group"); g.Value != "root" {
			t.Errorf("%s.group = %+v, want root", prefix, g)
		}
	}
	if e := env(t, b, "audit.log_dir.mode"); e.Source == nil || e.Source.Path != "/var/log/audit" {
		t.Errorf("log_dir source = %+v, want /var/log/audit", e.Source)
	}
	if w := b.Worst("audit"); w != facts.StatusOK {
		t.Errorf(`Worst("audit") = %s, want ok`, w)
	}
}

func TestAuditRulesDAndLastEnable(t *testing.T) {
	a := auditAccess()
	delete(a.cmds, cmdKey(auditctlListCmd))
	delete(a.cmds, cmdKey(auditctlStatusCmd))
	a.files["/etc/audit/rules.d/10-base.rules"] = "audit.rules.sample"
	a.files["/etc/audit/rules.d/99-finalize.rules"] = "audit.rules.d-99-finalize.rules"
	a.files["/etc/audit/rules.d/50-watch.rules"] = "audit.rules.d-50-watch.rules"
	delete(a.files, "/etc/audit/rules.d/audit.rules")
	// K-21: a /dev/null link masks a name and is never the chain's error.
	seedLink(a, "/etc/audit/rules.d/60-masked.rules", devNull)
	b := build(t, "audit", a)

	present := setting(t, b, "audit.rules.present")
	sideIs(t, "rules.present persisted", present.Persisted, true)
	statusIs(t, "rules.present runtime", present.Runtime, facts.StatusAbsent, "auditctl is not installed")
	if n := auditInt(t, b, "audit.rules.persisted_count"); n != 2 {
		t.Errorf("persisted_count = %d, want 2 (one watch, one syscall)", n)
	}
	src := present.Persisted.Source
	if src == nil || src.Kind != "derived" || len(src.Inputs) != 3 {
		t.Fatalf("persisted source = %+v, want derived from the three files read", src)
	}

	var got []string
	for _, r := range okList(t, b, "audit.rules.persisted") {
		m := r.(map[string]any)
		got = append(got, fmt.Sprintf("%s:%d %s %s", m["file"], m["line"], m["kind"], m["key"]))
	}
	want := []string{
		"/etc/audit/rules.d/10-base.rules:2 control ",
		"/etc/audit/rules.d/10-base.rules:6 control ",
		"/etc/audit/rules.d/10-base.rules:9 control ",
		"/etc/audit/rules.d/10-base.rules:12 control ",
		"/etc/audit/rules.d/50-watch.rules:2 watch identity",
		"/etc/audit/rules.d/50-watch.rules:4 syscall exec",
		"/etc/audit/rules.d/99-finalize.rules:2 control ",
	}
	if !slices.Equal(got, want) {
		t.Errorf("persisted rows\n got %q\nwant %q", got, want)
	}

	imm := setting(t, b, "audit.immutable")
	sideIs(t, "immutable persisted", imm.Persisted, true)
	if imm.Winner == nil || imm.Winner.Path != "/etc/audit/rules.d/99-finalize.rules" || imm.Winner.Line != 2 {
		t.Errorf("immutable winner = %+v, want 99-finalize.rules line 2", imm.Winner)
	}

	// A later -e 1 is the last one written, so the intent is not the lock.
	a.contents = map[string][]byte{"/etc/audit/rules.d/99-zz.rules": []byte("-e 1\n")}
	b = build(t, "audit", a)
	imm = setting(t, b, "audit.immutable")
	sideIs(t, "immutable persisted after -e 1", imm.Persisted, false)
	if imm.Winner == nil || imm.Winner.Path != "/etc/audit/rules.d/99-zz.rules" {
		t.Errorf("immutable winner = %+v, want 99-zz.rules", imm.Winner)
	}
}

// augenrules without rules.d prints "No rules directory" and loads
// /etc/audit/audit.rules as it stands, so that file is the persisted source;
// with neither there is nothing to load.
func TestAuditRulesDMissingFallsBackToAuditRules(t *testing.T) {
	a := auditAccess()
	delete(a.dirs, auditRulesDDir)
	delete(a.files, "/etc/audit/rules.d/audit.rules")
	a.files[auditRulesPath] = "audit.rules.d-50-watch.rules"
	b := build(t, "audit", a)

	present := setting(t, b, "audit.rules.present")
	sideIs(t, "rules.present persisted", present.Persisted, true)
	if src := present.Persisted.Source; src == nil || src.Kind != "file" || src.Path != auditRulesPath {
		t.Errorf("persisted source = %+v, want the plain file %s", src, auditRulesPath)
	}
	if present.Persisted.Reason != auditRulesDFallback {
		t.Errorf("persisted reason = %q, want the fallback named", present.Persisted.Reason)
	}
	if n := auditInt(t, b, "audit.rules.persisted_count"); n != 2 {
		t.Errorf("persisted_count = %d, want 2 from audit.rules", n)
	}
	if !slices.Contains(a.reads, auditRulesPath) {
		t.Errorf("reads %v: audit.rules is what augenrules loads without rules.d", a.reads)
	}

	// Neither rules.d nor audit.rules: nothing to load at boot.
	delete(a.files, auditRulesPath)
	b = build(t, "audit", a)
	statusIs(t, "rules.present persisted", setting(t, b, "audit.rules.present").Persisted, facts.StatusAbsent, auditNothingToLoad)
	statusIs(t, "immutable persisted", setting(t, b, "audit.immutable").Persisted, facts.StatusAbsent, auditNothingToLoad)
	for _, k := range []string{"audit.rules.persisted", "audit.rules.persisted_count"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent || e.Reason != auditNothingToLoad {
			t.Errorf("%s = %+v, want absent %q", k, e, auditNothingToLoad)
		}
	}

	// A present rules.d wins even beside audit.rules, and an EMPTY one is an
	// answer: augenrules regenerates an empty audit.rules from it, so there
	// are no rules and nothing is locked.
	a.files[auditRulesPath] = "audit.rules.d-50-watch.rules"
	a.dirs[auditRulesDDir] = true
	a.reads = nil
	b = build(t, "audit", a)
	present = setting(t, b, "audit.rules.present")
	sideIs(t, "rules.present persisted (empty rules.d)", present.Persisted, false)
	if src := present.Persisted.Source; src == nil || src.Path != auditRulesDDir {
		t.Errorf("empty rules.d source = %+v, want the directory", src)
	}
	sideIs(t, "immutable persisted (empty rules.d)", setting(t, b, "audit.immutable").Persisted, false)
	if rows := okList(t, b, "audit.rules.persisted"); len(rows) != 0 {
		t.Errorf("rows = %v, want none", rows)
	}
	if slices.Contains(a.reads, auditRulesPath) {
		t.Errorf("reads %v: with rules.d present augenrules regenerates audit.rules, so it is not read", a.reads)
	}
}

// augenrules lists rules.d with `ls -1v`: version order, so 9- loads before
// 10- and 99- before 100-, and the last -e in that order decides.
func TestAuditRulesDVersionOrder(t *testing.T) {
	a := auditAccess()
	delete(a.cmds, cmdKey(auditctlStatusCmd))
	delete(a.files, "/etc/audit/rules.d/audit.rules")
	a.contents = map[string][]byte{
		"/etc/audit/rules.d/10-site.rules":     []byte("-e 1\n"),
		"/etc/audit/rules.d/9-lock.rules":      []byte("-e 2\n"),
		"/etc/audit/rules.d/100-local.rules":   []byte("-w /etc/shadow -p wa -k shadow\n"),
		"/etc/audit/rules.d/99-finalize.rules": []byte("-w /etc/group -p wa -k group\n"),
	}
	b := build(t, "audit", a)
	var files []string
	for _, r := range okList(t, b, "audit.rules.persisted") {
		files = append(files, r.(map[string]any)["file"].(string))
	}
	want := []string{
		"/etc/audit/rules.d/9-lock.rules",
		"/etc/audit/rules.d/10-site.rules",
		"/etc/audit/rules.d/99-finalize.rules",
		"/etc/audit/rules.d/100-local.rules",
	}
	if !slices.Equal(files, want) {
		t.Errorf("load order %v, want %v", files, want)
	}
	imm := setting(t, b, "audit.immutable")
	sideIs(t, "immutable persisted", imm.Persisted, false)
	if imm.Winner == nil || imm.Winner.Path != "/etc/audit/rules.d/10-site.rules" {
		t.Errorf("immutable winner = %+v, want 10-site.rules, whose -e 1 is loaded last", imm.Winner)
	}
}

func TestVersionCompare(t *testing.T) {
	for _, tc := range []struct {
		x, y string
		want int
	}{
		{"9-lock.rules", "10-site.rules", -1},
		{"99-finalize.rules", "100-local.rules", -1},
		{"10-a.rules", "10-b.rules", -1},
		{"a.rules", "a1.rules", -1},
		{"007-x.rules", "7-x.rules", -1}, // equal value: strcmp breaks the tie
		{"x", "x", 0},
	} {
		if got := sign(versionCompare(tc.x, tc.y)); got != tc.want {
			t.Errorf("versionCompare(%q, %q) = %d, want %d", tc.x, tc.y, got, tc.want)
		}
		if got := sign(versionCompare(tc.y, tc.x)); got != -tc.want {
			t.Errorf("versionCompare(%q, %q) = %d, want %d", tc.y, tc.x, got, -tc.want)
		}
	}
}

func TestAuditNoSystemdReadsAuditRules(t *testing.T) {
	a := auditAccess()
	delete(a.dirs, systemdMarker)
	a.files[auditRulesPath] = "audit.rules.d-50-watch.rules"
	b := build(t, "audit", a)

	present := setting(t, b, "audit.rules.present")
	sideIs(t, "rules.present persisted", present.Persisted, true)
	if src := present.Persisted.Source; src == nil || src.Path != auditRulesPath {
		t.Errorf("persisted source = %+v, want %s", src, auditRulesPath)
	}
	if n := auditInt(t, b, "audit.rules.persisted_count"); n != 2 {
		t.Errorf("persisted_count = %d, want 2", n)
	}
	if slices.Contains(a.reads, "/etc/audit/rules.d/audit.rules") {
		t.Errorf("reads %v: rules.d is augenrules' and augenrules does not run without systemd", a.reads)
	}

	// Without systemd a missing audit.rules is absent with its path.
	delete(a.files, auditRulesPath)
	b = build(t, "audit", a)
	statusIs(t, "persisted (no audit.rules)", setting(t, b, "audit.rules.present").Persisted, facts.StatusAbsent, auditRulesPath)
}

func TestAuditctlClassification(t *testing.T) {
	cases := []struct {
		name       string
		uid        int
		list, stat cmdResult
		absentCmd  bool
		want       facts.Status
		reason     string // both commands, unless one of the two below is set
		listReason string
		statReason string
	}{
		{name: "exit 4 not root", uid: 1000,
			list: cmdResult{exitCode: 4, stderr: "You must be root to run this program.\n"},
			stat: cmdResult{exitCode: 4, stderr: "You must be root to run this program.\n"},
			want: facts.StatusDenied, reason: "CAP_AUDIT_CONTROL"},
		{name: "exit 4 as root", uid: 0,
			list: cmdResult{exitCode: 4, stderr: "You must be root to run this program.\n"},
			stat: cmdResult{exitCode: 4, stderr: "You must be root to run this program.\n"},
			want: facts.StatusUnsupported, reason: "no CAP_AUDIT_CONTROL: an unprivileged container"},
		{name: "container as root: -l 255, -s 4", uid: 0,
			list:       cmdResult{exitCode: 255, stderr: "Error sending rule list data request (Operation not permitted)\n"},
			stat:       cmdResult{exitCode: 4, stderr: "You must be root to run this program.\n"},
			want:       facts.StatusUnsupported,
			listReason: "-l: kernel audit is not reachable from this pid namespace",
			statReason: "-s: no CAP_AUDIT_CONTROL: an unprivileged container"},
		{name: "exit 255 EPERM", uid: 0,
			list: cmdResult{exitCode: 255, stderr: "Error sending rule list data request (Operation not permitted)\n"},
			stat: cmdResult{exitCode: 255, stderr: "Error sending status request (Operation not permitted)\n"},
			want: facts.StatusUnsupported, reason: "kernel audit is not reachable from this pid namespace"},
		{name: "kernel without audit", uid: 0,
			list:       cmdResult{exitCode: 255, stderr: "Error - audit support not in kernel\nCannot open netlink audit socket\n"},
			stat:       cmdResult{exitCode: 1, stderr: "Cannot open netlink audit socket\n"},
			want:       facts.StatusUnsupported,
			listReason: "-l: Error - audit support not in kernel",
			statReason: "-s: Cannot open netlink audit socket"},
		{name: "exit 0 empty stdout", uid: 0,
			list: cmdResult{}, stat: cmdResult{},
			want: facts.StatusUnsupported, reason: "gave no audit status"},
		{name: "user namespace: disabled", uid: 0,
			list: cmdResult{stderr: "The audit system is disabled\n"},
			stat: cmdResult{stderr: "The audit system is disabled\n"},
			want: facts.StatusUnsupported, reason: "gave no audit status"},
		{name: "not installed", uid: 0, absentCmd: true,
			want: facts.StatusAbsent, reason: "auditctl is not installed"},
		// W-9: a binary that is there and could not be started is an error
		// naming the command, never "not installed".
		{name: "could not start", uid: 0,
			list: cmdResult{exitCode: -1, err: fs.ErrPermission}, stat: cmdResult{exitCode: -1, err: fs.ErrPermission},
			want: facts.StatusError, listReason: "/usr/sbin/auditctl -l: permission denied", statReason: "/usr/sbin/auditctl -s: permission denied"},
		{name: "other code", uid: 0,
			list: cmdResult{exitCode: 3, stderr: "boom\n"}, stat: cmdResult{exitCode: 3, stderr: "boom\n"},
			want: facts.StatusError, reason: "exited 3: boom"},
		{name: "timeout", uid: 0,
			list: cmdResult{timedOut: true, exitCode: -1}, stat: cmdResult{timedOut: true, exitCode: -1},
			want: facts.StatusTimeout, reason: "timed out after 5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withEUID(t, tc.uid)
			a := auditAccess()
			if tc.absentCmd {
				a.cmds = nil
			} else {
				a.cmds = map[string]cmdResult{cmdKey(auditctlListCmd): tc.list, cmdKey(auditctlStatusCmd): tc.stat}
			}
			listReason, statReason := tc.reason, tc.reason
			if tc.listReason != "" {
				listReason = tc.listReason
			}
			if tc.statReason != "" {
				statReason = tc.statReason
			}
			b := build(t, "audit", a)
			present := setting(t, b, "audit.rules.present")
			imm := setting(t, b, "audit.immutable")
			statusIs(t, "rules.present runtime", present.Runtime, tc.want, listReason)
			statusIs(t, "rules.present effective", present.Effective, tc.want, listReason)
			loaded := env(t, b, "audit.rules.loaded_count")
			statusIs(t, "loaded_count", &loaded, tc.want, listReason)
			statusIs(t, "immutable runtime", imm.Runtime, tc.want, statReason)
			statusIs(t, "immutable effective", imm.Effective, tc.want, statReason)
			for _, k := range prefixed("audit.status.", auditStatusFields) {
				e := env(t, b, k)
				statusIs(t, k, &e, tc.want, statReason)
			}
			if present.Winner != nil {
				t.Errorf("rules.present winner = %+v, want none while runtime did not answer", present.Winner)
			}
			// The persisted side is the files, whatever auditctl said.
			sideIs(t, "rules.present persisted", present.Persisted, false)
		})
	}
}

// Rules and status as auditctl prints them on a host with rules loaded and
// the lock set.
func TestAuditRuntimeRulesAndLock(t *testing.T) {
	a := auditAccess()
	a.cmds[cmdKey(auditctlListCmd)] = cmdResult{file: "auditctl_l.sample"}
	a.cmds[cmdKey(auditctlStatusCmd)] = cmdResult{stdout: []byte("enabled 2\nfailure 1\npid 812\nlost 3\nbacklog_limit 8192\nloginuid_immutable 0 unlocked\n")}
	b := build(t, "audit", a)
	sideIs(t, "rules.present runtime", setting(t, b, "audit.rules.present").Runtime, true)
	if n := auditInt(t, b, "audit.rules.loaded_count"); n != 3 {
		t.Errorf("loaded_count = %d, want 3", n)
	}
	imm := setting(t, b, "audit.immutable")
	sideIs(t, "immutable runtime", imm.Runtime, true)
	sideIs(t, "immutable effective", imm.Effective, true)
	sideIs(t, "immutable persisted", imm.Persisted, false)
	if n := auditInt(t, b, "audit.status.lost"); n != 3 {
		t.Errorf("lost = %d, want 3", n)
	}

	// A status that printed enabled but not lost is absent for lost alone.
	a.cmds[cmdKey(auditctlStatusCmd)] = cmdResult{stdout: []byte("enabled 1\n")}
	b = build(t, "audit", a)
	if e := env(t, b, "audit.status.lost"); e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "printed no lost") {
		t.Errorf("lost = %+v, want absent naming the field", e)
	}
	if e := env(t, b, "audit.status.lost"); e.Source == nil || e.Source.Cmd != cmdKey(auditctlStatusCmd) {
		t.Errorf("lost source = %+v, want the auditctl -s it was derived from (C4)", e.Source)
	}
}

func TestAuditdConfAbsentKeysAndDefaultLogFile(t *testing.T) {
	a := auditAccess()
	a.contents = map[string][]byte{auditdConfPath: []byte("# local\nLog_Group = Adm\nmax_log_file_action=Keep_Logs\n")}
	delete(a.files, auditdConfPath)
	b := build(t, "audit", a)

	e := env(t, b, "audit.conf.space_left_action")
	if e.Status != facts.StatusAbsent || e.Reason != "auditd.conf sets no space_left_action" {
		t.Errorf("space_left_action = %+v, want absent naming the key", e)
	}
	if e := env(t, b, "audit.conf.max_log_file_action"); e.Value != "keep_logs" {
		t.Errorf("max_log_file_action = %+v, want lower-cased keep_logs", e)
	}
	if e := env(t, b, "audit.conf.log_group"); e.Value != "Adm" {
		t.Errorf("log_group = %+v, want Adm as written: a group name is case-sensitive", e)
	}
	lf := env(t, b, "audit.conf.log_file")
	if lf.Status != facts.StatusOK || lf.Value != auditDefaultLog {
		t.Fatalf("log_file = %+v, want the default path", lf)
	}
	if lf.Source == nil || lf.Source.Kind != "derived" || len(lf.Source.Inputs) != 1 || lf.Source.Inputs[0].Path != auditdConfPath {
		t.Errorf("log_file source = %+v, want derived from auditd.conf", lf.Source)
	}
	if m := auditInt(t, b, "audit.log_file.mode"); m != 0o600 {
		t.Errorf("the default log file was not the one stat'ed: mode %o", m)
	}
}

// C3: auditd.conf that exists and cannot be read is every conf leaf's answer
// and the permission facts' too, since it would have named their path.
func TestAuditdConfUnreadableReachesEveryConfLeaf(t *testing.T) {
	a := auditAccess()
	a.fails = map[string]error{auditdConfPath: unix.EACCES}
	b := build(t, "audit", a)
	keys := prefixed("audit.conf.", auditConfKeys)
	keys = append(keys, prefixed("audit.log_file.", permLeaves)...)
	keys = append(keys, prefixed("audit.log_dir.", permLeaves)...)
	for _, k := range keys {
		e := env(t, b, k)
		statusIs(t, k, &e, facts.StatusDenied, auditdConfPath)
	}
}

func TestAuditLogFileOutsideDeclarationIsC4(t *testing.T) {
	a := auditAccess()
	a.contents = map[string][]byte{auditdConfPath: []byte("log_file = /srv/audit/a.log\n")}
	delete(a.files, auditdConfPath)
	a.stats["/srv/audit/a.log"] = statResult{mode: 0o600, kind: "regular"}
	a.stats["/srv/audit"] = statResult{mode: 0o700, kind: "dir"}
	b := build(t, "audit", a) // build runs under the guard: a stat here would be a violation
	for _, l := range permLeaves {
		e := env(t, b, "audit.log_file."+l)
		statusIs(t, "log_file."+l, &e, facts.StatusAbsent, "/srv/audit/a.log: outside the paths muster reads")
		e = env(t, b, "audit.log_dir."+l)
		statusIs(t, "log_dir."+l, &e, facts.StatusAbsent, "/srv/audit: outside the paths muster reads")
	}
	if e := env(t, b, "audit.conf.log_file"); e.Value != "/srv/audit/a.log" {
		t.Errorf("log_file = %+v, want the path as written", e)
	}

	// A log file directly under /var/log is inside the declaration, and so
	// is its directory.
	a.contents[auditdConfPath] = []byte("log_file = /var/log/audit.log\n")
	a.stats["/var/log/audit.log"] = statResult{mode: 0o640, kind: "regular"}
	a.stats["/var/log"] = statResult{mode: 0o755, kind: "dir"}
	b = build(t, "audit", a)
	if m := auditInt(t, b, "audit.log_file.mode"); m != 0o640 {
		t.Errorf("log_file.mode = %o, want 0640", m)
	}
	if m := auditInt(t, b, "audit.log_dir.mode"); m != 0o755 {
		t.Errorf("log_dir.mode = %o, want 0755", m)
	}
}

// /etc/audit is 0750 root on both families, so a run outside it reads every
// persisted and conf leaf denied — at whichever step the denial arrives —
// and the runtime side is untouched.
func TestAuditDeniedReachesEveryPersistedLeaf(t *testing.T) {
	cases := map[string]func(a *fsAccess){
		"rules.d stat": func(a *fsAccess) {
			a.fails[auditRulesDDir] = unix.EACCES
			delete(a.dirs, auditRulesDDir)
		},
		"rules.d glob": func(a *fsAccess) { a.deniedDirs = map[string]bool{auditRulesDDir: true} },
		"rules file":   func(a *fsAccess) { a.fails["/etc/audit/rules.d/audit.rules"] = unix.EACCES },
	}
	for name, deny := range cases {
		t.Run(name, func(t *testing.T) {
			a := auditAccess()
			a.fails = map[string]error{auditdConfPath: unix.EACCES}
			deny(a)
			b := build(t, "audit", a)
			for _, k := range []string{"audit.rules.present", "audit.immutable"} {
				s := setting(t, b, k)
				statusIs(t, k+" persisted", s.Persisted, facts.StatusDenied, "/etc/audit/rules.d")
				if s.Runtime == nil || s.Runtime.Status != facts.StatusOK {
					t.Errorf("%s runtime = %+v, want ok: the denial is the files'", k, s.Runtime)
				}
			}
			for _, k := range []string{"audit.rules.persisted", "audit.rules.persisted_count"} {
				e := env(t, b, k)
				statusIs(t, k, &e, facts.StatusDenied, "/etc/audit/rules.d")
			}
			for _, k := range prefixed("audit.conf.", auditConfKeys) {
				e := env(t, b, k)
				statusIs(t, k, &e, facts.StatusDenied, auditdConfPath)
			}
		})
	}
}

// J-16: the persisted list is capped at 2000 rows and says so; the counts
// are of every rule read.
func TestAuditPersistedRowsAreCapped(t *testing.T) {
	a := auditAccess()
	var sb strings.Builder
	for i := 0; i < auditRulesRowCap+5; i++ {
		fmt.Fprintf(&sb, "-w /etc/f%d -p wa -k k%d\n", i, i)
	}
	a.contents = map[string][]byte{"/etc/audit/rules.d/50-many.rules": []byte(sb.String())}
	b := build(t, "audit", a)
	e := env(t, b, "audit.rules.persisted")
	if rows, _ := e.Value.([]any); len(rows) != auditRulesRowCap || !e.Truncated {
		t.Errorf("rows = %d truncated %v, want %d and truncated", len(rows), e.Truncated, auditRulesRowCap)
	}
	if n := auditInt(t, b, "audit.rules.persisted_count"); n != auditRulesRowCap+5 {
		t.Errorf("persisted_count = %d, want every rule read", n)
	}
	if env(t, b, "audit.rules.persisted_count").Truncated {
		t.Error("the count saw every line; only the list was cut")
	}
}

// Every registered audit key is written on every shape the collector can
// meet, so none reaches a control as missing -> ERROR(missing_fact).
func TestAuditPublishesEveryRegisteredKey(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range reg.Keys {
		if k.Collector == "audit" {
			keys = append(keys, k.Key)
		}
	}
	if len(keys) != 34 {
		t.Fatalf("the registry declares %d audit keys, want 34", len(keys))
	}
	shapes := map[string]func() *fsAccess{
		"no auditd": func() *fsAccess { return &fsAccess{dirs: map[string]bool{systemdMarker: true}} },
		"empty":     func() *fsAccess { return &fsAccess{} },
		"stock":     auditAccess,
		"denied": func() *fsAccess {
			a := auditAccess()
			a.fails = map[string]error{auditdConfPath: unix.EACCES, auditRulesDDir: unix.EACCES}
			delete(a.dirs, auditRulesDDir)
			return a
		},
		"conf outside": func() *fsAccess {
			a := auditAccess()
			a.contents = map[string][]byte{auditdConfPath: []byte("log_file = /srv/a.log\n")}
			delete(a.files, auditdConfPath)
			return a
		},
	}
	for name, mk := range shapes {
		t.Run(name, func(t *testing.T) {
			b := buildBegun(t, "audit", mk())
			for _, k := range keys {
				switch v := leaf(t, b, k).(type) {
				case facts.Envelope:
				case facts.Setting:
					if v.Runtime == nil || v.Persisted == nil || v.Effective == nil {
						t.Errorf("%s = %+v, want all three sides", k, v)
					}
				default:
					t.Errorf("%s was not written (%T)", k, v)
				}
			}
			if got := b.Keys("audit"); !slices.Equal(got, sortedCopy(keys)) {
				t.Errorf("Keys(audit) = %v, want every registered key %v", got, keys)
			}
		})
	}

	// The lab's shape: systemd, no auditd anywhere.
	b := build(t, "audit", shapes["no auditd"]())
	statusIs(t, "rules.present runtime", setting(t, b, "audit.rules.present").Runtime, facts.StatusAbsent, "auditctl is not installed")
	statusIs(t, "rules.present persisted", setting(t, b, "audit.rules.present").Persisted, facts.StatusAbsent, auditNothingToLoad)
	e := env(t, b, "audit.conf.log_file")
	statusIs(t, "conf.log_file", &e, facts.StatusAbsent, "not present")
	e = env(t, b, "audit.log_file.mode")
	statusIs(t, "log_file.mode", &e, facts.StatusAbsent, "not present")
	if w := b.Worst("audit"); w != facts.StatusOK {
		t.Errorf(`Worst("audit") = %s, want ok on a host without auditd`, w)
	}
}

// A symlink administrators placed at auditd.conf is C4's error by design:
// muster reads without following links.
func TestAuditdConfSymlinkIsError(t *testing.T) {
	a := auditAccess()
	delete(a.files, auditdConfPath)
	seedLink(a, auditdConfPath, "/srv/auditd.conf")
	b := build(t, "audit", a)
	if e := env(t, b, "audit.conf.disk_full_action"); e.Status != facts.StatusError {
		t.Errorf("disk_full_action = %+v, want error", e)
	}
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// An empty or relative log_file names no file muster could stat: every
// permission leaf says so, and nothing is stat'ed at "." or a relative path.
func TestAuditLogFileNotAbsolute(t *testing.T) {
	for _, v := range []string{"", "audit.log"} {
		a := auditAccess()
		delete(a.files, auditdConfPath)
		a.contents = map[string][]byte{auditdConfPath: []byte("log_file = " + v + "\n")}
		b := build(t, "audit", a)
		want := "auditd.conf sets log_file to " + strconv.Quote(v) + ", which is not an absolute path"
		for _, k := range append(prefixed("audit.log_file.", permLeaves), prefixed("audit.log_dir.", permLeaves)...) {
			if e := env(t, b, k); e.Status != facts.StatusAbsent || e.Reason != want {
				t.Errorf("log_file %q: %s = %+v, want absent %q", v, k, e, want)
			}
		}
		if e := env(t, b, "audit.conf.log_file"); e.Status != facts.StatusOK || e.Value != v {
			t.Errorf("conf.log_file = %+v, want %q as written", e, v)
		}
	}
}

// The order GNU ls -1v printed on the lab for these names — augenrules' own
// listing — including the upstream sample rules' names.
func TestAugenrulesOrderMatchesLsV(t *testing.T) {
	lsV := []string{
		"007-x.rules", "7-x.rules", "9-lock.rules", "10-a.rules", "10-b.rules", "10-site.rules",
		"30-ospp-v42.rules", "30-pci-dss-v31.rules", "30-stig.rules", "43-module-load.rules",
		"99-finalize.rules", "100-local.rules", "a.rules", "a1.rules",
	}
	in := make([]string, 0, len(lsV)+1)
	for i := len(lsV) - 1; i >= 0; i-- {
		in = append(in, auditRulesDDir+"/"+lsV[i])
	}
	in = append(in, auditRulesDDir+"/.hidden.rules")
	var got []string
	for _, p := range augenrulesOrder(in) {
		got = append(got, strings.TrimPrefix(p, auditRulesDDir+"/"))
	}
	if !slices.Equal(got, lsV) {
		t.Errorf("augenrulesOrder\n got %v\nwant %v (ls -1v, dot-files unlisted)", got, lsV)
	}
}
