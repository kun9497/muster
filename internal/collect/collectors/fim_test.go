//go:build linux

package collectors

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// fimAccess is the double for the fim collector with every map initialised,
// so a test can add a stat, a failure or a command without a nil-map panic.
// It is a host WITHOUT systemd; withSystemd adds the marker.
func fimAccess() *fsAccess {
	return &fsAccess{
		files:    map[string]string{},
		contents: map[string][]byte{},
		dirs:     map[string]bool{},
		cmds:     map[string]cmdResult{},
		fails:    map[string]error{},
		stats:    map[string]statResult{},
	}
}

func withSystemd(a *fsAccess) *fsAccess {
	a.dirs[systemdMarker] = true
	a.stats[systemdMarker] = statResult{mode: 0o755, kind: "dir"}
	return a
}

// fimJammy is a stock Ubuntu 22.04 host with aide installed (J-5): the
// binary, the Debian configuration, /etc/default/aide as shipped and the
// executable cron.daily script. /etc/cron.daily/logrotate is there to be
// ignored.
func fimJammy() *fsAccess {
	a := fimAccess()
	a.stats["/usr/bin/aide"] = statResult{mode: 0o755, kind: "regular"}
	a.files["/etc/aide/aide.conf"] = "aide.conf.debian"
	a.files["/etc/default/aide"] = "default_aide.sample"
	a.files["/etc/cron.daily/aide"] = "cron.daily-aide.sample"
	a.stats["/etc/cron.daily/aide"] = statResult{mode: 0o755, kind: "regular"}
	a.files["/etc/cron.daily/logrotate"] = "cron_d_entry"
	a.stats["/etc/cron.daily/logrotate"] = statResult{mode: 0o755, kind: "regular"}
	return a
}

// fimNoble is Ubuntu 24.04: the cron.daily shim beside dailyaidecheck.timer
// on a systemd host.
func fimNoble() *fsAccess {
	a := withSystemd(fimAccess())
	a.stats["/usr/bin/aide"] = statResult{mode: 0o755, kind: "regular"}
	a.files["/etc/aide/aide.conf"] = "aide.conf.debian"
	a.files["/etc/default/aide"] = "default_aide.sample"
	a.files["/etc/cron.daily/dailyaidecheck"] = "cron.daily-dailyaidecheck.sample"
	a.stats["/etc/cron.daily/dailyaidecheck"] = statResult{mode: 0o755, kind: "regular"}
	a.cmds[cmdKey(listTimersCmd)] = cmdResult{file: "list_timers.sample"}
	return a
}

// fimEL9 is a stock EL9 host: /usr/sbin/aide, /etc/aide.conf with its
// @@define macros, and aide-check.timer shipped but not armed.
func fimEL9() *fsAccess {
	a := withSystemd(fimAccess())
	a.stats["/usr/sbin/aide"] = statResult{mode: 0o755, kind: "regular"}
	a.files["/etc/aide.conf"] = "aide.conf.el9"
	a.modes = map[string]uint32{"/etc/aide.conf": 0o600}
	a.cmds[cmdKey(listTimersCmd)] = cmdResult{stdout: []byte(
		"n/a                         n/a       n/a                         n/a      aide-check.timer            aide-check.service\n")}
	return a
}

// schedule returns the one schedules row with this path.
func schedule(t *testing.T, rows []any, p string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if m := r.(map[string]any); m["path"] == p {
			return m
		}
	}
	t.Fatalf("no schedules row for %s in %v", p, rows)
	return nil
}

func okValue(t *testing.T, e facts.Envelope, want any, what string) {
	t.Helper()
	if e.Status != facts.StatusOK || e.Value != want {
		t.Errorf("%s = %+v, want ok %v", what, e, want)
	}
}

func TestFimNoTool(t *testing.T) {
	b := build(t, "fim", fimAccess())
	okValue(t, env(t, b, "fim.tool"), "none", "fim.tool")
	if s := env(t, b, "fim.tool").Source; s == nil || s.Kind != "derived" {
		t.Errorf("fim.tool source %+v, want derived", s)
	}
	okValue(t, env(t, b, "fim.aide.installed"), false, "installed")
	for _, k := range []string{"fim.aide.config_path", "fim.aide.database_path", "fim.aide.database_present", "fim.aide.database_modified"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent", k, e)
		}
	}
	if rows := okList(t, b, "fim.aide.schedules"); len(rows) != 0 {
		t.Errorf("schedules %v, want none", rows)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")
	if rows := okList(t, b, "fim.other_tools"); len(rows) != 0 {
		t.Errorf("other_tools %v, want none", rows)
	}
}

// Spec I-4: a host with another tool but no AIDE has no tool muster models,
// so fim.tool is absent and names what is there.
func TestFimOtherToolOnlyIsAbsent(t *testing.T) {
	a := fimAccess()
	a.stats["/usr/bin/osqueryd"] = statResult{mode: 0o755, kind: "regular"}
	b := build(t, "fim", a)
	absentBecause(t, b, "fim.tool", "aide is not installed", "osqueryd (/usr/bin/osqueryd)")
	rows := okList(t, b, "fim.other_tools")
	if len(rows) != 1 {
		t.Fatalf("other_tools %v, want one row", rows)
	}
	if r := rows[0].(map[string]any); r["name"] != "osqueryd" || r["path"] != "/usr/bin/osqueryd" {
		t.Errorf("other_tools row %v", r)
	}
	okValue(t, env(t, b, "fim.aide.installed"), false, "installed")
	for _, k := range []string{"fim.aide.config_path", "fim.aide.database_path", "fim.aide.database_present", "fim.aide.database_modified"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent", k, e)
		}
	}
}

func TestFimDebianCronDaily(t *testing.T) {
	b := build(t, "fim", fimJammy())
	okValue(t, env(t, b, "fim.tool"), "aide", "fim.tool")
	okValue(t, env(t, b, "fim.aide.installed"), true, "installed")
	okValue(t, env(t, b, "fim.aide.config_path"), "/etc/aide/aide.conf", "config_path")
	okValue(t, env(t, b, "fim.aide.database_path"), "/var/lib/aide/aide.db", "database_path")
	// No database after a stock install (J-5).
	okValue(t, env(t, b, "fim.aide.database_present"), false, "database_present")
	if e := env(t, b, "fim.aide.database_modified"); e.Status != facts.StatusAbsent {
		t.Errorf("database_modified %+v, want absent", e)
	}
	rows := okList(t, b, "fim.aide.schedules")
	want := []any{map[string]any{"kind": "cron_daily", "path": "/etc/cron.daily/aide", "armed": true, "detail": ""}}
	if fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("schedules %v, want %v", rows, want)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), true, "scheduled")
}

func TestFimCronDailyRunNo(t *testing.T) {
	a := fimJammy()
	delete(a.files, "/etc/default/aide")
	a.contents["/etc/default/aide"] = []byte("# local\nCRON_DAILY_RUN=\"no\"\n")
	b := build(t, "fim", a)
	r := schedule(t, okList(t, b, "fim.aide.schedules"), "/etc/cron.daily/aide")
	if r["armed"] != false || !strings.Contains(r["detail"].(string), "/etc/default/aide") {
		t.Errorf("row %v, want disarmed naming /etc/default/aide", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")

	// yes, spelled out, keeps the gate open.
	a = fimJammy()
	delete(a.files, "/etc/default/aide")
	a.contents["/etc/default/aide"] = []byte("CRON_DAILY_RUN=no\nCRON_DAILY_RUN=yes\n")
	okValue(t, env(t, build(t, "fim", a), "fim.aide.scheduled"), true, "scheduled with CRON_DAILY_RUN=yes last")

	// run-parts skips a script without the execute bit.
	a = fimJammy()
	a.stats["/etc/cron.daily/aide"] = statResult{mode: 0o644, kind: "regular"}
	b = build(t, "fim", a)
	r = schedule(t, okList(t, b, "fim.aide.schedules"), "/etc/cron.daily/aide")
	if r["armed"] != false || !strings.Contains(r["detail"].(string), "not executable") {
		t.Errorf("row %v, want disarmed as not executable", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")
}

func TestFimNobleTimer(t *testing.T) {
	b := build(t, "fim", fimNoble())
	rows := okList(t, b, "fim.aide.schedules")
	shim := schedule(t, rows, "/etc/cron.daily/dailyaidecheck")
	if shim["kind"] != "cron_daily" || shim["armed"] != false || shim["detail"] != "runs only without systemd" {
		t.Errorf("shim row %v", shim)
	}
	timer := schedule(t, rows, "dailyaidecheck.timer")
	if timer["kind"] != "timer" || timer["armed"] != true || timer["detail"] != "" {
		t.Errorf("timer row %v", timer)
	}
	if other := schedule(t, rows, "aide-check.timer"); other["armed"] != false {
		t.Errorf("a timer with no next elapse is not armed: %v", other)
	}
	for _, r := range rows {
		if p := r.(map[string]any)["path"]; p == "logrotate.timer" || p == "apt-daily-upgrade.timer" {
			t.Errorf("a timer not naming aide is listed: %v", r)
		}
	}
	if !slices.IsSortedFunc(rows, func(x, y any) int {
		return strings.Compare(x.(map[string]any)["path"].(string), y.(map[string]any)["path"].(string))
	}) {
		t.Errorf("schedules not sorted by path: %v", rows)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), true, "scheduled")

	// No next elapse: the timer is not armed and nothing else is.
	a := fimNoble()
	a.cmds[cmdKey(listTimersCmd)] = cmdResult{stdout: []byte(
		"n/a n/a Tue 2026-09-23 02:41:17 UTC 21h ago dailyaidecheck.timer dailyaidecheck.service\n")}
	b = build(t, "fim", a)
	if r := schedule(t, okList(t, b, "fim.aide.schedules"), "dailyaidecheck.timer"); r["armed"] != false {
		t.Errorf("n/a timer row %v, want disarmed", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")

	// systemd 255 prints "-" for no next elapse.
	a = fimNoble()
	a.cmds[cmdKey(listTimersCmd)] = cmdResult{stdout: []byte("- - - - dailyaidecheck.timer dailyaidecheck.service\n")}
	okValue(t, env(t, build(t, "fim", a), "fim.aide.scheduled"), false, "scheduled with a '-' next elapse")

	// The 24.04 service reads the same CRON_DAILY_RUN gate.
	a = fimNoble()
	delete(a.files, "/etc/default/aide")
	a.contents["/etc/default/aide"] = []byte("CRON_DAILY_RUN=no\n")
	b = build(t, "fim", a)
	if r := schedule(t, okList(t, b, "fim.aide.schedules"), "dailyaidecheck.timer"); r["armed"] != false ||
		!strings.Contains(r["detail"].(string), "CRON_DAILY_RUN") {
		t.Errorf("gated timer row %v", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")
}

func TestFimEL9Macros(t *testing.T) {
	a := fimEL9()
	b := build(t, "fim", a)
	okValue(t, env(t, b, "fim.tool"), "aide", "fim.tool")
	okValue(t, env(t, b, "fim.aide.config_path"), "/etc/aide.conf", "config_path")
	dp := env(t, b, "fim.aide.database_path")
	okValue(t, dp, "/var/lib/aide/aide.db.gz", "database_path")
	if dp.Reason != "" {
		t.Errorf("a resolved path carries no reason: %q", dp.Reason)
	}
	okValue(t, env(t, b, "fim.aide.database_present"), false, "database_present")
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")
	if r := schedule(t, okList(t, b, "fim.aide.schedules"), "aide-check.timer"); r["armed"] != false {
		t.Errorf("preset-disabled timer %v", r)
	}

	a = fimEL9()
	a.stats["/var/lib/aide/aide.db.gz"] = statResult{mode: 0o600, kind: "regular", mtime: time.Date(2026, 9, 20, 3, 4, 5, 0, time.FixedZone("KST", 9*3600))}
	b = build(t, "fim", a)
	okValue(t, env(t, b, "fim.aide.database_present"), true, "database_present")
	okValue(t, env(t, b, "fim.aide.database_modified"), "2026-09-19T18:04:05Z", "database_modified")
}

func TestFimUnresolvedMacro(t *testing.T) {
	a := fimEL9()
	delete(a.files, "/etc/aide.conf")
	a.contents["/etc/aide.conf"] = []byte("@@define DBDIR /var/lib/aide\ndatabase_in=file:@@{NOPE}/aide.db.gz\n")
	b := build(t, "fim", a)
	e := env(t, b, "fim.aide.database_path")
	okValue(t, e, "@@{NOPE}/aide.db.gz", "database_path")
	if !strings.Contains(e.Reason, "@@{NOPE}") {
		t.Errorf("reason %q must name the unresolved macro", e.Reason)
	}
	absentBecause(t, b, "fim.aide.database_present", "@@{NOPE}/aide.db.gz")
}

func TestParseAideConf(t *testing.T) {
	for _, c := range []struct {
		name, in, want string
		unresolved     []string
		found          bool
	}{
		{"literal", "database_in=file:/var/lib/aide/aide.db\n", "/var/lib/aide/aide.db", nil, true},
		{"older database=", "database=file:/var/lib/aide/aide.db\n", "/var/lib/aide/aide.db", nil, true},
		{"database_in wins over database", "database_in=file:/a/in.db\ndatabase=file:/a/old.db\n", "/a/in.db", nil, true},
		{"spaces around =", "database_in = file:/a/b.db\n", "/a/b.db", nil, true},
		{"define after use", "database_in=file:@@{D}/x.db\n@@define D /v\n", "/v/x.db", nil, true},
		{"comment ignored", "#database_in=file:/nope\n", "", nil, false},
		{"other @@ ignored", "@@include /etc/aide.d x\n@@x_include /etc/aide/aide.conf.d y\ndatabase_in=file:/d\n", "/d", nil, true},
		{"unknown macro", "database_in=file:@@{A}/@@{B}\n@@define A /a\n", "/a/@@{B}", []string{"B"}, true},
		{"none", "gzip_dbout=yes\n", "", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := parseAideConf([]byte(c.in))
			if got.database != c.want || got.found != c.found || !slices.Equal(got.unresolved, c.unresolved) {
				t.Errorf("parseAideConf(%q) = %+v, want %q found %v unresolved %v", c.in, got, c.want, c.found, c.unresolved)
			}
		})
	}
}

// Without systemd the timer inventory is never asked for: the command is
// unscripted, so running it would have made both leaves unsupported.
func TestFimNoSystemdCronOnly(t *testing.T) {
	a := fimJammy()
	a.contents["/etc/cron.d/aide"] = []byte("# m h dom mon dow user command\n30 3 * * * root /usr/bin/aide --check\n")
	a.contents["/etc/cron.d/raider"] = []byte("0 1 * * * adelaide /usr/local/bin/raider --run\n")
	a.contents["/etc/crontab"] = []byte("#0 4 * * * root /usr/bin/aide --check\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
	b := build(t, "fim", a)
	rows := okList(t, b, "fim.aide.schedules")
	var paths []string
	for _, r := range rows {
		m := r.(map[string]any)
		paths = append(paths, m["path"].(string))
		if m["kind"] == "timer" {
			t.Errorf("a timer row on a host without systemd: %v", m)
		}
	}
	if !slices.Equal(paths, []string{"/etc/cron.d/aide", "/etc/cron.daily/aide"}) {
		t.Errorf("schedule paths %v", paths)
	}
	if r := schedule(t, rows, "/etc/cron.d/aide"); r["kind"] != "cron_d" || r["armed"] != true {
		t.Errorf("cron.d row %v", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), true, "scheduled")
}

func TestFimCrontabLine(t *testing.T) {
	a := fimAccess()
	a.contents["/etc/crontab"] = []byte("SHELL=/bin/sh\n@daily root aide --check\n")
	rows := okList(t, build(t, "fim", a), "fim.aide.schedules")
	if len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	if r := rows[0].(map[string]any); r["kind"] != "crontab" || r["path"] != "/etc/crontab" || r["armed"] != true {
		t.Errorf("crontab row %v", r)
	}
}

// W-4: a list-timers run that gave no inventory is classified — a kill is a
// timeout, a systemctl that could not start or a host not booted with systemd
// is unsupported, any other non-zero exit is an error naming the command and
// its code — on both leaves.
func TestFimTimerInventoryFailure(t *testing.T) {
	for _, c := range []struct {
		name   string
		res    cmdResult
		status facts.Status
		reason string
	}{
		{"timed out", cmdResult{timedOut: true, exitCode: -1}, facts.StatusTimeout,
			"/usr/bin/systemctl list-timers --all --no-legend --no-pager timed out"},
		{"could not start", cmdResult{exitCode: -1, err: fs.ErrNotExist}, facts.StatusUnsupported,
			"systemd timer inventory unavailable: /usr/bin/systemctl list-timers --all --no-legend --no-pager: file does not exist"},
		{"not booted with systemd", cmdResult{exitCode: 1, stderr: "System has not been booted with systemd as init system (PID 1). Can't operate.\nFailed to connect to bus: Host is down\n"}, facts.StatusUnsupported,
			"systemd timer inventory unavailable: System has not been booted with systemd as init system (PID 1). Can't operate."},
		{"other exit", cmdResult{exitCode: 1, stderr: "Failed to connect to bus: No such file or directory\n"}, facts.StatusError,
			"/usr/bin/systemctl list-timers --all --no-legend --no-pager exited 1: Failed to connect to bus: No such file or directory"},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := fimNoble()
			// No cron.daily row, so scheduled carries the failure too.
			delete(a.files, "/etc/cron.daily/dailyaidecheck")
			delete(a.stats, "/etc/cron.daily/dailyaidecheck")
			a.cmds[cmdKey(listTimersCmd)] = c.res
			b := buildBegun(t, "fim", a)
			for _, k := range []string{"fim.aide.schedules", "fim.aide.scheduled"} {
				if e := env(t, b, k); e.Status != c.status || e.Reason != c.reason {
					t.Errorf("%s = %+v, want %s %q", k, e, c.status, c.reason)
				}
			}
		})
	}
}

// X-3: with AIDE installed, a configuration that names no database is a
// known answer — there is no database — so database_present is ok false with
// the reason; database_path stays absent.
func TestFimInstalledWithoutADatabaseLine(t *testing.T) {
	a := fimJammy()
	delete(a.files, "/etc/aide/aide.conf")
	b := build(t, "fim", a)
	e := env(t, b, "fim.aide.database_present")
	okValue(t, e, false, "database_present without a configuration")
	if !strings.Contains(e.Reason, "neither /etc/aide/aide.conf nor /etc/aide.conf exists") {
		t.Errorf("reason %q must say neither configuration exists", e.Reason)
	}
	if e.Source == nil || e.Source.Kind != "derived" || len(e.Source.Inputs) != 2 ||
		e.Source.Inputs[0].Path != "/etc/aide/aide.conf" || e.Source.Inputs[1].Path != "/etc/aide.conf" {
		t.Errorf("source %+v, want derived from the two candidate paths", e.Source)
	}
	absentBecause(t, b, "fim.aide.database_path", "names a database")

	a = fimJammy()
	delete(a.files, "/etc/aide/aide.conf")
	a.contents["/etc/aide/aide.conf"] = []byte("gzip_dbout=yes\n")
	b = build(t, "fim", a)
	e = env(t, b, "fim.aide.database_present")
	okValue(t, e, false, "database_present without a database line")
	if e.Reason != "no database_in= or database= line in /etc/aide/aide.conf" {
		t.Errorf("reason %q", e.Reason)
	}
	if e.Source == nil || e.Source.Kind != "derived" || len(e.Source.Inputs) != 1 || e.Source.Inputs[0].Path != "/etc/aide/aide.conf" {
		t.Errorf("source %+v, want derived from the configuration", e.Source)
	}
	absentBecause(t, b, "fim.aide.database_path", "no database_in= or database= line")
}

// X-5 / W-6: a cron line arms only when a command token runs an AIDE command
// — bare, or from a bin/sbin directory — never when aide is a path argument.
func TestNamesAideCommandToken(t *testing.T) {
	for _, c := range []struct {
		line string
		want bool
	}{
		{"0 5 * * * root find /var/log/aide -mtime +30 -delete\n", false},
		{"0 5 * * * root cp /etc/aide/aide.conf /root/aide.conf.bak\n", false},
		{"0 5 * * * root nice -n 19 /usr/bin/aide --check\n", true},
		{"0 5 * * * root aide --check\n", true},
		{"@daily root /usr/sbin/aide.wrapper --check\n", true},
		{"0 5 * * * root /opt/tools/aide --check\n", false},
		{"0 5 * * * root cd / && dailyaidecheck;\n", true},
	} {
		if got := namesAide([]byte(c.line)); got != c.want {
			t.Errorf("namesAide(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// C3: the configuration exists and cannot be read, so every value it sets is
// that read's status, path-prefixed — never a default database path.
func TestFimDeniedConf(t *testing.T) {
	a := fimEL9()
	a.fails["/etc/aide.conf"] = unix.EACCES
	a.stats["/etc/aide.conf"] = statResult{mode: 0o600, kind: "regular"}
	b := build(t, "fim", a)
	okValue(t, env(t, b, "fim.aide.config_path"), "/etc/aide.conf", "config_path")
	for _, k := range []string{"fim.aide.database_path", "fim.aide.database_present", "fim.aide.database_modified"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/aide.conf: ") {
			t.Errorf("%s = %+v, want denied naming /etc/aide.conf", k, e)
		}
	}
}

// A cron.d file that cannot be read may be the one that schedules aide: the
// list is that read's status, and scheduled is too unless another row is
// already armed.
func TestFimUnreadableCronFile(t *testing.T) {
	a := fimAccess()
	a.files["/etc/cron.d/secret"] = "cron_d_entry"
	a.fails["/etc/cron.d/secret"] = unix.EACCES
	b := build(t, "fim", a)
	for _, k := range []string{"fim.aide.schedules", "fim.aide.scheduled"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/cron.d/secret: ") {
			t.Errorf("%s = %+v, want denied naming the file", k, e)
		}
	}
	a = fimJammy()
	a.files["/etc/cron.d/secret"] = "cron_d_entry"
	a.fails["/etc/cron.d/secret"] = unix.EACCES
	okValue(t, env(t, build(t, "fim", a), "fim.aide.scheduled"), true, "scheduled with an armed row")
}

// J-16: a list longer than the cap is cut and marked, never an error.
func TestFimSchedulesAreCapped(t *testing.T) {
	a := fimAccess()
	for i := range 70 {
		a.contents[fmt.Sprintf("/etc/cron.d/aide-%02d", i)] = []byte("0 1 * * * root aide --check\n")
	}
	b := build(t, "fim", a)
	e := env(t, b, "fim.aide.schedules")
	if rows := okList(t, b, "fim.aide.schedules"); len(rows) != 64 || !e.Truncated {
		t.Errorf("schedules %d rows truncated %v, want 64 and truncated", len(rows), e.Truncated)
	}
}

func TestParseListTimers(t *testing.T) {
	got := parseListTimers([]byte("Wed 2026-09-24 01:50:00 UTC 3h left Tue 2026-09-23 02:41:17 UTC 21h ago dailyaidecheck.timer dailyaidecheck.service\n" +
		"n/a n/a n/a n/a aide-check.timer aide-check.service\n" +
		"- - - - x.timer x.service\n\n  garbage line\n"))
	want := []listedTimer{{unit: "dailyaidecheck.timer", armed: true}, {unit: "aide-check.timer"}, {unit: "x.timer"}}
	if !slices.Equal(got, want) {
		t.Errorf("parseListTimers = %+v, want %+v", got, want)
	}
}

// Every registered fim key is written on every shape the collector meets, so
// none reaches a control as missing -> ERROR(missing_fact).
func TestFimPublishesEveryRegisteredKey(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range reg.Keys {
		if k.Collector == "fim" {
			keys = append(keys, k.Key)
		}
	}
	if len(keys) != 9 {
		t.Fatalf("the registry declares %d fim keys, want 9", len(keys))
	}
	shapes := map[string]func() *fsAccess{
		"empty": fimAccess,
		"jammy": fimJammy,
		"noble": fimNoble,
		"el9":   fimEL9,
		"other tool": func() *fsAccess {
			a := fimAccess()
			a.stats["/var/ossec/bin/wazuh-agentd"] = statResult{kind: "regular"}
			return a
		},
		"denied conf": func() *fsAccess { a := fimEL9(); a.fails["/etc/aide.conf"] = unix.EACCES; return a },
		"timers fail": func() *fsAccess { a := fimNoble(); a.cmds[cmdKey(listTimersCmd)] = cmdResult{exitCode: 1}; return a },
		"denied cron": func() *fsAccess { a := fimAccess(); a.deniedDirs = map[string]bool{"/etc/cron.d": true}; return a },
		"conf no path": func() *fsAccess {
			a := fimJammy()
			delete(a.files, "/etc/aide/aide.conf")
			a.contents["/etc/aide/aide.conf"] = []byte("gzip_dbout=yes\n")
			return a
		},
	}
	for name, mk := range shapes {
		t.Run(name, func(t *testing.T) {
			b := buildBegun(t, "fim", mk())
			for _, k := range keys {
				if _, ok := leaf(t, b, k).(facts.Envelope); !ok {
					t.Errorf("%s was not written", k)
				}
			}
			if got := b.Keys("fim"); !slices.Equal(got, sortedCopy(keys)) {
				t.Errorf("Keys(fim) = %v, want every registered key %v", got, keys)
			}
		})
	}
}

// C3 on the gate (review fix 1): an /etc/default/aide this run may not read
// may hold CRON_DAILY_RUN=no, so every row it controls is disarmed with that
// read as the detail, and scheduled is the read's status unless a row the
// gate does not control is armed.
func TestFimUnreadableDefaultsDisarmsTheGatedRows(t *testing.T) {
	a := fimJammy()
	a.fails["/etc/default/aide"] = unix.EACCES
	b := build(t, "fim", a)
	r := schedule(t, okList(t, b, "fim.aide.schedules"), "/etc/cron.daily/aide")
	if r["armed"] != false || !strings.HasPrefix(r["detail"].(string), "/etc/default/aide: ") {
		t.Errorf("gated cron.daily row %v, want disarmed naming the unread file", r)
	}
	if e := env(t, b, "fim.aide.scheduled"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/default/aide: ") {
		t.Errorf("scheduled = %+v, want denied naming /etc/default/aide", e)
	}

	a = fimJammy()
	a.fails["/etc/default/aide"] = unix.EACCES
	a.contents["/etc/cron.d/aide-check"] = []byte("0 5 * * * root /usr/bin/aide --check\n")
	okValue(t, env(t, build(t, "fim", a), "fim.aide.scheduled"), true, "scheduled with an ungated cron.d row")

	a = fimNoble()
	a.fails["/etc/default/aide"] = unix.EACCES
	b = build(t, "fim", a)
	if r := schedule(t, okList(t, b, "fim.aide.schedules"), "dailyaidecheck.timer"); r["armed"] != false ||
		!strings.HasPrefix(r["detail"].(string), "/etc/default/aide: ") {
		t.Errorf("gated timer row %v", r)
	}
	if e := env(t, b, "fim.aide.scheduled"); e.Status != facts.StatusDenied {
		t.Errorf("noble scheduled = %+v, want denied", e)
	}
}

// Review fix 4: an empty CRON_DAILY_RUN= is unset (${CRON_DAILY_RUN:-yes}).
func TestFimEmptyCronDailyRunIsYes(t *testing.T) {
	a := fimJammy()
	delete(a.files, "/etc/default/aide")
	a.contents["/etc/default/aide"] = []byte("CRON_DAILY_RUN=\n")
	okValue(t, env(t, build(t, "fim", a), "fim.aide.scheduled"), true, "scheduled with an empty CRON_DAILY_RUN")
}

// Review fix 3: run-parts runs only names of letters, digits, _ and -.
func TestFimRunPartsSkipsTheName(t *testing.T) {
	a := fimJammy()
	a.files["/etc/cron.daily/aide.dpkg-old"] = "cron.daily-aide.sample"
	a.stats["/etc/cron.daily/aide.dpkg-old"] = statResult{mode: 0o755, kind: "regular"}
	b := build(t, "fim", a)
	rows := okList(t, b, "fim.aide.schedules")
	if r := schedule(t, rows, "/etc/cron.daily/aide.dpkg-old"); r["armed"] != false || r["detail"] != "run-parts skips this name" {
		t.Errorf("dotted row %v", r)
	}
	if r := schedule(t, rows, "/etc/cron.daily/aide"); r["armed"] != true {
		t.Errorf("the real script %v", r)
	}
}

// Review fix 5: a link among the cron.daily candidates is a row, never an
// error; a stat that fails is the list's answer (C3).
func TestFimCronDailyNonRegularAndStatFailure(t *testing.T) {
	a := fimAccess()
	a.files["/etc/cron.daily/aide"] = "cron.daily-aide.sample"
	a.links = map[string]string{"/etc/cron.daily/aide": "/usr/share/aide/bin/aide"}
	b := buildBegun(t, "fim", a)
	if r := schedule(t, okList(t, b, "fim.aide.schedules"), "/etc/cron.daily/aide"); r["armed"] != false || r["detail"] != "not a regular file" {
		t.Errorf("symlink row %v", r)
	}
	okValue(t, env(t, b, "fim.aide.scheduled"), false, "scheduled")
	if w := b.Worst("fim"); w != facts.StatusOK {
		t.Errorf(`Worst("fim") = %s, want ok`, w)
	}

	a = fimAccess()
	a.files["/etc/cron.daily/aide"] = "cron.daily-aide.sample"
	a.fails["/etc/cron.daily/aide"] = unix.EACCES
	b = build(t, "fim", a)
	for _, k := range []string{"fim.aide.schedules", "fim.aide.scheduled"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/cron.daily/aide: ") {
			t.Errorf("%s = %+v, want denied naming the script", k, e)
		}
	}
}
