//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The two timedatectl command lines, byte-identical to the Command
// declarations and to what the collector runs (Ruling I-16/I-20: the guard
// matches Path+Args exactly and the test double keys its canned outcomes on
// the same rendering, so any drift shows up as an unmapped command).
const (
	timedatectlShowKey         = "/usr/bin/timedatectl show -p NTP -p NTPSynchronized"
	timedatectlShowTimesyncKey = "/usr/bin/timedatectl show-timesync --all"
)

// timesyncFake is fsAccess plus a record of the commands that were actually
// run, so a test can assert that an oracle the collector must NOT consult on
// this branch was never invoked (Ruling I-16).
type timesyncFake struct {
	*fsAccess
	ran map[string]bool
}

func (a *timesyncFake) Run(ctx context.Context, c collect.Command) collect.Output {
	a.ran[strings.TrimSpace(c.Path+" "+strings.Join(c.Args, " "))] = true
	return a.fsAccess.Run(ctx, c)
}

// timesyncAccess builds the double. Ruling I-20: every map fsAccess offers is
// initialised here — a later `a.fails[…] = …` on a nil map panics — and
// /run/systemd/system is seeded, since a timesyncd host is a systemd host.
func timesyncAccess(files map[string]string, cmds map[string]cmdResult) *timesyncFake {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &timesyncFake{
		fsAccess: &fsAccess{
			files: files,
			cmds:  cmds,
			fails: map[string]error{},
			dirs:  map[string]bool{"/run/systemd/system": true},
			stats: map[string]statResult{"/run/systemd/system": {mode: 0o755, kind: "dir"}},
		},
		ran: map[string]bool{},
	}
}

// The new rows exist and degrade with the table: on a no-systemd host every
// services.ntp.*/services.syslog.* key is unsupported and Worst stays ok.
func TestServicesNtpAndSyslogRowsDegradeWithTheTable(t *testing.T) {
	b := buildBegun(t, "services", &fsAccess{}) // no /run/systemd/system
	for _, k := range []string{"services.ntp.installed", "services.ntp.active", "services.syslog.installed", "services.syslog.enabled"} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s = %s, want unsupported", k, e.Status)
		}
	}
	if got := b.Worst("services"); got != facts.StatusOK {
		t.Errorf(`Worst("services") = %s, want ok`, got)
	}
}

// chrony: servers come from the files; timedatectl is not consulted for the list.
func TestTimesyncChronyServersFromFiles(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.pool"}, nil)
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "chrony" {
		t.Errorf("provider: %+v", e)
	}
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value != 2 {
		t.Errorf("server_count: %+v", e)
	}
}

// timesyncd with a fully commented config: the list comes from timedatectl show-timesync.
func TestTimesyncTimesyncdServersFromTimedatectl(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/systemd/timesyncd.conf": "timesyncd.conf.commented"},
		map[string]cmdResult{timedatectlShowTimesyncKey: {file: "timedatectl.show-timesync"}, timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "timesyncd" {
		t.Errorf("provider: %+v", e)
	}
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value == 0 {
		t.Errorf("server_count from timedatectl: %+v", e)
	}
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusOK {
		t.Errorf("synchronized: %+v", e)
	}
}

// Ruling I-19/I-24: the timesyncd branch reads the merged drop-in chain — a
// drop-in NTP= REPLACES the main file's, and the merged value joins the
// timedatectl list.
func TestTimesyncTimesyncdDropinOverridesTheMainFile(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/systemd/timesyncd.conf":                   "timesyncd.conf.ntp",
		"/etc/systemd/timesyncd.conf.d/10-ntp.conf":     "timesyncd.d.10-ntp",
		"/usr/lib/systemd/timesyncd.conf.d/10-ntp.conf": "timesyncd.conf.ntp", // shadowed by /etc
	}, map[string]cmdResult{timedatectlShowTimesyncKey: {file: "timedatectl.show-timesync"}, timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	got := okList(t, b, "time_sync.servers")
	var names []string
	for _, v := range got {
		names = append(names, v.(string))
	}
	if !contains(names, "ntp-dropin.example.net") {
		t.Errorf("the drop-in NTP= must be in the list: %v", names)
	}
	if contains(names, "ntp-main.example.net") {
		t.Errorf("the main file's NTP= is replaced by the drop-in, not merged with it: %v", names)
	}
	// Ruling I-24: the networkd/DHCP lists timedatectl reports merge in too.
	if !contains(names, "ntp2.example.net") {
		t.Errorf("SystemNTPServers from show-timesync must be in the list: %v", names)
	}
	// Deterministic: de-duplicated and sorted.
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("servers must be sorted and de-duplicated: %v", names)
			break
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// timesyncd + timedatectl unavailable (systemd-less container): the list is ABSENT
// (→ MANUAL), synchronized is unsupported, and the run stays complete (R220).
func TestTimesyncTimedatectlUnavailableIsAbsentNotError(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/systemd/timesyncd.conf": "timesyncd.conf.commented"}, nil) // commands unmapped → Err
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusAbsent {
		t.Errorf("servers must be absent: %+v", e)
	}
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusAbsent {
		t.Errorf("server_count must be absent: %+v", e)
	}
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusUnsupported {
		t.Errorf("synchronized: %+v", e)
	}
	if got := b.Worst("timesync"); got != facts.StatusOK {
		t.Errorf(`Worst("timesync") = %s, want ok`, got)
	}
}

// Ruling I-16: show-timesync is a timesyncd-only oracle and is not even run on a
// chrony host; `synchronized` follows `show` alone and stays ok there.
func TestTimesyncChronyKeepsSynchronizedWithoutShowTimesync(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.pool"},
		map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}}) // show-timesync unmapped → would fail
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusOK {
		t.Errorf("synchronized: %+v", e)
	}
	if a.ran[timedatectlShowTimesyncKey] {
		t.Error("show-timesync must not run on the chrony branch")
	}
}

// Ruling I-17: refclock lines and a declared sourcedir count as sources.
func TestTimesyncChronyRefclockAndSourcedirCount(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/chrony/chrony.conf":       "chrony.conf.sourcedir", // refclock PHC … + sourcedir /run/chrony-dhcp
		"/run/chrony-dhcp/eth0.sources": "chrony.sources.dhcp",
	}, map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value.(int) < 2 {
		t.Errorf("server_count: %+v", e)
	}
	names := okList(t, b, "time_sync.servers")
	var found bool
	for _, v := range names {
		if v.(string) == "refclock:PHC:/dev/ptp0" {
			found = true
		}
	}
	if !found {
		t.Errorf("a refclock is a source, recorded as refclock:<driver>:<arg>: %v", names)
	}
}

// Rulings I-10 + I-17: a sourcedir outside the declaration is RECORDED, never read;
// servers/server_count go absent (→ MANUAL) and the path never reaches a.reads.
func TestTimesyncUndeclaredSourcedirIsRecordedNotRead(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.sourcedir-odd"}, nil) // sourcedir /opt/ntp
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusAbsent {
		t.Errorf("servers: %+v", e)
	}
	if e := env(t, b, "time_sync.servers"); !strings.Contains(e.Reason, "/opt/ntp") {
		t.Errorf("the reason must name the path a reader has to check by hand: %+v", e)
	}
	for _, p := range a.reads {
		if strings.HasPrefix(p, "/opt/ntp") {
			t.Fatalf("read an undeclared path: %s", p)
		}
	}
}

// Ruling I-18: no provider config at all — the judged leaf is ok:0, never unset
// (an unset registered key is missing → ERROR(missing_fact), not FAIL).
func TestTimesyncNoProviderIsZeroNotMissing(t *testing.T) {
	a := timesyncAccess(nil, map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "none" {
		t.Errorf("provider: %+v", e)
	}
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value.(int) != 0 {
		t.Errorf("server_count: %+v", e)
	}
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusOK {
		t.Errorf("servers: %+v", e)
	}
}

// The ntpd branch reads server/pool lines out of ntp.conf.
func TestTimesyncNtpdServersFromFiles(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/ntp.conf": "ntp.conf.servers"},
		map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "ntpd" {
		t.Errorf("provider: %+v", e)
	}
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value.(int) != 2 {
		t.Errorf("server_count: %+v", e)
	}
}

// C3: a provider configuration that exists but cannot be read is the answer for
// every value it could set — never a silent "no servers configured".
func TestTimesyncUnreadableConfigPoisonsTheDerivedValues(t *testing.T) {
	a := timesyncAccess(nil, map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	a.fails["/etc/chrony/chrony.conf"] = os.ErrPermission
	b := buildBegun(t, "timesync", a)
	for _, k := range []string{"time_sync.provider", "time_sync.servers", "time_sync.server_count"} {
		e := env(t, b, k)
		if e.Status == facts.StatusOK {
			t.Errorf("%s must carry the read failure, not a default: %+v", k, e)
		}
		if !strings.Contains(e.Reason, "/etc/chrony/chrony.conf") {
			t.Errorf("%s: the reason must name the file: %+v", k, e)
		}
	}
}
