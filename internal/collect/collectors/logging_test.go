//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// loggingAccess builds the double for the logging collector. Ruling I-20:
// EVERY map fsAccess offers is initialised here — a later `a.fails[…] = …`
// or `a.stats[…] = …` on a nil map panics — and /run/systemd/system is
// seeded, since implementation detection asks whether this is a systemd
// host. Directory-ness is judged by ReadMeta.Kind, which fsAccess.Stat only
// reports from `stats`, so a directory needs a stats entry, not just a dirs
// one.
//
// targets are the log files that already exist on this fake host; each is
// stat-able with no modification time, which is exactly the "the age is not
// known" case Ruling I-27 forbids inventing an answer for.
func loggingAccess(files map[string]string, targets []string) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	stats := map[string]statResult{"/run/systemd/system": {mode: 0o755, kind: "dir"}}
	// IR-7: a configuration file names the implementation only when the
	// daemon's binary is installed too, so a fixture that seeds one seeds the
	// other. A test about a REMOVED package deletes the binary again.
	if _, ok := files["/etc/rsyslog.conf"]; ok {
		stats["/usr/sbin/rsyslogd"] = statResult{mode: 0o755, kind: "regular"}
	}
	if _, ok := files["/etc/syslog-ng/syslog-ng.conf"]; ok {
		stats["/usr/sbin/syslog-ng"] = statResult{mode: 0o755, kind: "regular"}
	}
	for _, p := range targets {
		stats[p] = statResult{mode: 0o640, kind: "regular"}
	}
	return &fsAccess{
		files: files,
		cmds:  map[string]cmdResult{},
		fails: map[string]error{},
		dirs:  map[string]bool{"/run/systemd/system": true},
		stats: stats,
	}
}

// buildBegunAt is buildBegun with the run header's collected_at filled in
// BEFORE the collector runs. Ruling I-27: a collector never reads the clock
// itself, so an age is only derivable when the header already carries the
// one timestamp R54 reads once per run.
func buildBegunAt(t *testing.T, name string, a collect.Access, collectedAt string) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	b.Header().CollectedAt = collectedAt
	c := collectorNamed(t, name)
	b.Begin(name)
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("%s touched undeclared targets: %v", name, v)
	}
	return b
}

// findFacility returns the coverage record for one facility.
func findFacility(t *testing.T, list []any, facility string) map[string]any {
	t.Helper()
	for _, v := range list {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("coverage row is %#v, not a record", v)
		}
		if rec["facility"] == facility {
			return rec
		}
	}
	t.Fatalf("no coverage row for facility %q in %v", facility, list)
	return nil
}

// findPath returns the log_targets record for one path.
func findPath(t *testing.T, list []any, path string) map[string]any {
	t.Helper()
	for _, v := range list {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("log_targets row is %#v, not a record", v)
		}
		if rec["path"] == path {
			return rec
		}
	}
	t.Fatalf("no log_targets row for %q in %v", path, list)
	return nil
}

// Ruling I-14: ".none" is scoped to ITS selector line, not to the target path.
// The Ubuntu default logs auth/authpriv to /var/log/auth.log on one line; the
// separate "*.*;auth,authpriv.none -/var/log/syslog" line excludes them ON
// THAT LINE ONLY, and kern/daemon/cron ride the same catch-all. Judged by
// facility, never by path.
//
// Ruling I-12: the stock 20-ufw.conf / 21-cloudinit.conf property filters,
// the "& stop" continuation and postfix.conf's legacy $Directive must NOT
// make coverage absent — they are additive routing and globals, counted as
// evidence.
func TestLoggingUbuntuDefaultCoversFacilitiesByFacilityNotPath(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/rsyslog.conf":                "rsyslog.conf.ubuntu",
		"/etc/rsyslog.d/50-default.conf":   "rsyslog.d/50-default.conf",
		"/etc/rsyslog.d/20-ufw.conf":       "rsyslog.d/20-ufw.conf",
		"/etc/rsyslog.d/21-cloudinit.conf": "rsyslog.d/21-cloudinit.conf",
		"/etc/rsyslog.d/postfix.conf":      "rsyslog.d/postfix.conf",
	}, []string{"/var/log/syslog", "/var/log/auth.log"})
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.syslog.implementation"); e.Value != "rsyslog" {
		t.Fatalf("impl: %+v", e)
	}
	if e := env(t, b, "logging.rsyslog.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("parse_complete: %+v", e)
	}
	cov := okList(t, b, "logging.rsyslog.coverage")
	for _, f := range []string{"auth", "authpriv", "kern", "daemon", "cron"} {
		rec := findFacility(t, cov, f)
		if rec["logged"] != true || rec["persistent"] != true {
			t.Errorf("%s: %+v", f, rec)
		}
	}
	// auth is logged by its OWN line, not by the catch-all that excludes it.
	if got := findFacility(t, cov, "auth")["target"]; got != "/var/log/auth.log" {
		t.Errorf("auth target %v, want /var/log/auth.log", got)
	}
	if got := findFacility(t, cov, "cron")["target"]; got != "/var/log/syslog" {
		t.Errorf("cron target %v, want the catch-all /var/log/syslog", got)
	}
	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value.(int) != 0 {
		t.Errorf("stock Ubuntu must be fully modelled: %+v", e)
	}
	if e := env(t, b, "logging.rsyslog.property_filters"); e.Status != facts.StatusOK || e.Value.(int) != 2 {
		t.Errorf("property_filters (evidence, coverage-neutral): %+v", e)
	}
	if got := b.Worst("logging"); got != facts.StatusOK {
		t.Errorf(`Worst("logging") = %s, want ok`, got)
	}
}

// The RHEL default reaches the same facilities through different paths:
// "*.info;mail.none;authpriv.none;cron.none /var/log/messages" covers
// auth/daemon/kern at floor info, and authpriv/cron get their own files.
// The multi-line module() blocks must not be mistaken for rules.
func TestLoggingRhelDefaultCoversFacilities(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.rhel"},
		[]string{"/var/log/messages", "/var/log/secure", "/var/log/cron"})
	b := buildBegun(t, "logging", a)

	cov := okList(t, b, "logging.rsyslog.coverage")
	for _, f := range []string{"auth", "authpriv", "kern", "daemon", "cron"} {
		rec := findFacility(t, cov, f)
		if rec["logged"] != true || rec["persistent"] != true {
			t.Errorf("%s: %+v", f, rec)
		}
	}
	if got := findFacility(t, cov, "authpriv")["target"]; got != "/var/log/secure" {
		t.Errorf("authpriv target %v, want /var/log/secure", got)
	}
	if got := findFacility(t, cov, "auth")["priority_floor"]; got != "info" {
		t.Errorf("auth priority_floor %v, want info", got)
	}
	// mail is excluded from the *.info line and has its own; the "-" async
	// marker is not part of the path.
	if got := findFacility(t, cov, "mail")["target"]; got != "/var/log/maillog" {
		t.Errorf("mail target %v, want /var/log/maillog (async marker stripped)", got)
	}
	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Value.(int) != 0 {
		t.Errorf("the RHEL default must be fully modelled: %+v", e)
	}
}

// An include the collector cannot read → parse_complete false → coverage
// ABSENT (→ MANUAL). The rules that WERE read are still reported: they are
// evidence, and only the derived judgement is withheld.
func TestLoggingUnreadableIncludeMakesCoverageAbsent(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.include-missing"}, nil)
	a.fails["/etc/rsyslog.d/10-custom.conf"] = os.ErrPermission
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete: %+v", e)
	}
	e := env(t, b, "logging.rsyslog.coverage")
	if e.Status != facts.StatusAbsent {
		t.Errorf("coverage must be absent: %+v", e)
	}
	if !strings.Contains(e.Reason, "/etc/rsyslog.d/10-custom.conf") {
		t.Errorf("the reason must name the file a reader has to check by hand: %+v", e)
	}
	if l := okList(t, b, "logging.rsyslog.rules"); len(l) == 0 {
		t.Error("the rules that were read are still evidence")
	}
}

// An unmodelled RainerScript construct → unmodelled > 0 → coverage ABSENT
// (under-claim, never a guess about what the conditional routes).
func TestLoggingUnmodelledRainerScriptMakesCoverageAbsent(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.rainerscript-if"},
		[]string{"/var/log/messages"})
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value.(int) == 0 {
		t.Errorf("an `if … then` is unmodelled: %+v", e)
	}
	if e := env(t, b, "logging.rsyslog.parse_complete"); e.Value != true {
		t.Errorf("every file was read, so the parse is complete: %+v", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
		t.Errorf("coverage must be absent: %+v", e)
	}
}

// No rsyslog or syslog-ng configuration on a systemd host → journald-only,
// and the rsyslog leaves are absent (never a fabricated "no rules").
func TestLoggingJournaldOnlyImplementation(t *testing.T) {
	b := buildBegun(t, "logging", loggingAccess(nil, nil))
	if e := env(t, b, "logging.syslog.implementation"); e.Status != facts.StatusOK || e.Value != "journald-only" {
		t.Fatalf("impl: %+v", e)
	}
	// IR-18: the six leaves degrade together, so the list itself is iterated —
	// a hand-picked subset would let a new leaf slip through as a default.
	for _, k := range rsyslogLeafKeys {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent on a host with no rsyslog", k, e)
		}
	}
	if got := b.Worst("logging"); got != facts.StatusOK {
		t.Errorf(`Worst("logging") = %s, want ok (absent ranks ok)`, got)
	}
}

// Neither a syslog daemon configuration nor systemd → "none".
func TestLoggingNoImplementationAtAll(t *testing.T) {
	a := &fsAccess{files: map[string]string{}, cmds: map[string]cmdResult{}, fails: map[string]error{},
		dirs: map[string]bool{}, stats: map[string]statResult{}}
	b := buildBegun(t, "logging", a)
	if e := env(t, b, "logging.syslog.implementation"); e.Value != "none" {
		t.Errorf("impl: %+v", e)
	}
}

// syslog-ng is detected but its dialect is not parsed in v1, so coverage is
// absent (→ MANUAL) rather than a confidently wrong verdict.
func TestLoggingSyslogNgIsDetectedButNotParsed(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/syslog-ng/syslog-ng.conf": "syslog-ng.conf"}, nil)
	b := buildBegun(t, "logging", a)
	if e := env(t, b, "logging.syslog.implementation"); e.Value != "syslog-ng" {
		t.Fatalf("impl: %+v", e)
	}
	e := env(t, b, "logging.rsyslog.coverage")
	if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "syslog-ng") {
		t.Errorf("coverage must be absent naming syslog-ng: %+v", e)
	}
	// IR-18: every rsyslog leaf, not a hand-picked subset.
	for _, k := range rsyslogLeafKeys {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent on a syslog-ng host", k, e)
		}
	}
}

// Ruling I-15: persistent = the target is a LOCAL FILE target kind, never
// "the file exists". A file target that does not exist yet (a fresh host;
// omfile creates it on first write) is persistent:true with
// log_targets.exists false as the evidence.
func TestLoggingPersistenceIsTargetKindNotExistence(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.rhel"}, nil) // nothing exists yet
	b := buildBegun(t, "logging", a)

	rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "authpriv")
	if rec["logged"] != true || rec["persistent"] != true {
		t.Errorf("a fresh host must not FAIL: %+v", rec)
	}
	tgt := findPath(t, okList(t, b, "logging.log_targets"), "/var/log/secure")
	if tgt["exists"] != false || tgt["stat_status"] != "absent" {
		t.Errorf("existence is evidence, not the judgement: %+v", tgt)
	}
	if _, ok := tgt["mtime_age_s"]; ok {
		t.Errorf("a file that is not there has no age: %+v", tgt)
	}
}

// A forward-only host: every facility is logged, none persistently.
func TestLoggingRemoteOnlyIsLoggedButNotPersistent(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.remote-only"}, nil)
	b := buildBegun(t, "logging", a)
	rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "auth")
	if rec["logged"] != true || rec["persistent"] != false {
		t.Errorf("remote-only coverage is logged but not persistent: %+v", rec)
	}
	if l := okList(t, b, "logging.log_targets"); len(l) != 0 {
		t.Errorf("a remote target is not a file target: %v", l)
	}
}

// Ruling I-13: rules are ordered. "auth.* stop" (and the legacy
// "authpriv.* ~") BEFORE the catch-all mean neither facility ever reaches
// the file — coverage must not read them as logged.
func TestLoggingSelectorDiscardBeforeCoveringRuleRemovesFacility(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.stop-before"}, []string{"/var/log/syslog"})
	b := buildBegun(t, "logging", a)
	cov := okList(t, b, "logging.rsyslog.coverage")

	for _, f := range []string{"auth", "authpriv"} {
		rec := findFacility(t, cov, f)
		if rec["logged"] != false || rec["persistent"] != false {
			t.Errorf("a discard ahead of the covering rule must remove %s: %+v", f, rec)
		}
		if r, _ := rec["reason"].(string); !strings.Contains(r, "stop") && !strings.Contains(r, "~") {
			t.Errorf("%s: the reason must cite the discarding line: %+v", f, rec)
		}
	}
	// Everything else still rides the catch-all that follows the discards.
	if rec := findFacility(t, cov, "daemon"); rec["logged"] != true || rec["persistent"] != true {
		t.Errorf("daemon: %+v", rec)
	}
}

// Ruling I-10, modelled on TestSshdBannerOutsideDeclarationIsRecordedNotRead:
// a rule target outside Declare.Reads is RECORDED, never stat-ed — a guard
// violation would make the collector error and the whole run incomplete.
func TestLoggingUndeclaredTargetIsRecordedNotStatted(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.undeclared-target"}, nil)
	b := buildBegun(t, "logging", a)

	tgt := okList(t, b, "logging.log_targets")
	rec := findPath(t, tgt, "/opt/logs/app.log")
	if rec["stat_status"] != "undeclared" {
		t.Errorf("targets: %+v", tgt)
	}
	if _, ok := rec["mtime_age_s"]; ok {
		t.Errorf("a path that was never stat-ed has no age: %+v", rec)
	}
	for _, p := range a.reads {
		if strings.HasPrefix(p, "/opt/logs") {
			t.Fatalf("touched an undeclared path: %s", p)
		}
	}
}

// Ruling I-27: "now" is the run header's collected_at, never time.Now(), so
// the same snapshot always renders the same bytes. A seeded modification
// time yields the expected age; a stat with no modification time does not
// get one invented for it.
func TestLoggingTargetAgeComesFromTheRunHeader(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.two-targets"},
		[]string{"/var/log/auth.log"}) // seeded WITHOUT a modification time
	a.stats["/var/log/syslog"] = statResult{
		mode: 0o640, kind: "regular",
		mtime: time.Date(2026, 9, 8, 5, 58, 30, 0, time.UTC),
	}
	b := buildBegunAt(t, "logging", a, "2026-09-08T06:00:00Z")

	tgt := okList(t, b, "logging.log_targets")
	if got := findPath(t, tgt, "/var/log/syslog")["mtime_age_s"]; got != 90 {
		t.Errorf("mtime_age_s = %v (%T), want 90", got, got)
	}
	if rec := findPath(t, tgt, "/var/log/auth.log"); func() bool { _, ok := rec["mtime_age_s"]; return ok }() {
		t.Errorf("an unseeded modification time must not produce an age: %+v", rec)
	}
}

// Without a collected_at in the header there is no clock at all, and no age
// is invented from one.
func TestLoggingNoCollectedAtInventsNoAge(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.two-targets"}, nil)
	a.stats["/var/log/syslog"] = statResult{mode: 0o640, kind: "regular", mtime: time.Date(2026, 9, 8, 5, 58, 30, 0, time.UTC)}
	b := buildBegun(t, "logging", a) // header left empty
	if rec := findPath(t, okList(t, b, "logging.log_targets"), "/var/log/syslog"); func() bool {
		_, ok := rec["mtime_age_s"]
		return ok
	}() {
		t.Errorf("no clock, no age: %+v", rec)
	}
}

// C3: /etc/rsyslog.conf exists but cannot be read — that read's status is the
// answer for every value the file could set, path-prefixed, never a default.
func TestLoggingUnreadableMainConfigPoisonsTheRsyslogLeaves(t *testing.T) {
	a := loggingAccess(nil, nil)
	a.fails["/etc/rsyslog.conf"] = os.ErrPermission
	// IR-7: the daemon is installed — only its configuration is unreadable.
	a.stats["/usr/sbin/rsyslogd"] = statResult{mode: 0o755, kind: "regular"}
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.syslog.implementation"); e.Status != facts.StatusOK || e.Value != "rsyslog" {
		t.Errorf("a file that cannot be read is still a file that is there: %+v", e)
	}
	for _, k := range []string{
		"logging.rsyslog.rules", "logging.rsyslog.parse_complete", "logging.rsyslog.unmodelled",
		"logging.rsyslog.property_filters", "logging.rsyslog.coverage", "logging.log_targets",
	} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s must carry the read failure, not a default: %+v", k, e)
		}
		if !strings.Contains(e.Reason, "/etc/rsyslog.conf") {
			t.Errorf("%s: the reason must name the file: %+v", k, e)
		}
	}
}

// An include that names a path outside the declaration is RECORDED, never
// globbed or read: parse_complete goes false with the path in the reason.
func TestLoggingUndeclaredIncludeIsRecordedNotRead(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.undeclared-include"}, nil)
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.parse_complete"); e.Value != false {
		t.Errorf("parse_complete: %+v", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "/opt/rsyslog") {
		t.Errorf("the reason must name the path a reader has to check by hand: %+v", e)
	}
	for _, p := range a.reads {
		if strings.HasPrefix(p, "/opt/rsyslog") {
			t.Fatalf("read an undeclared path: %s", p)
		}
	}
}

// The rules list is evidence in FILE ORDER — the order Ruling I-13's
// derivation depends on — and every record carries the four fields.
func TestLoggingRulesAreRecordedInFileOrder(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.stop-before"}, nil)
	rules := okList(t, buildBegun(t, "logging", a), "logging.rsyslog.rules")
	if len(rules) < 3 {
		t.Fatalf("rules: %v", rules)
	}
	first := rules[0].(map[string]any)
	for _, f := range []string{"facility", "priority", "target", "target_kind"} {
		if _, ok := first[f]; !ok {
			t.Errorf("rule record lacks %q: %+v", f, first)
		}
	}
	if first["facility"] != "auth" || first["target_kind"] != "discard" {
		t.Errorf("the discard must come first, as it does in the file: %+v", first)
	}
}

// --- journald (Rulings I-8 / I-23) --------------------------------------

// journalDirSeed makes /var/log/journal a DIRECTORY on the fake host. Ruling
// I-20: fsAccess.Stat reports a Kind only from stats, so a dirs entry alone
// would leave Kind empty and the directory would read as "not a directory".
func journalDirSeed(a *fsAccess) {
	a.stats["/var/log/journal"] = statResult{mode: 0o2755, uid: 0, gid: 4, kind: "dir"}
	a.dirs["/var/log/journal"] = true
}

// Ruling I-8: the journal is persistent when Storage=persistent, or when
// Storage is auto (journald's default) AND /var/log/journal is there — the
// directory is what journald consults at boot. The two sides of
// logging.journald.storage are ALWAYS both set (H-18): persisted is what the
// chain configures, runtime is what the directory says the journal is doing
// now, and the two disagreeing is the interesting case, not an error.
func TestJournaldPersistentDerivation(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		journalDir bool
		want       bool
		persisted  string
		runtime    string
	}{{
		name:       "auto with the journal directory present",
		files:      map[string]string{"/etc/systemd/journald.conf": "journald.conf.main"},
		journalDir: true, want: true, persisted: "auto", runtime: "persistent",
	}, {
		name:  "auto without it",
		files: map[string]string{"/etc/systemd/journald.conf": "journald.conf.main"},
		want:  false, persisted: "auto", runtime: "volatile",
	}, {
		// journald creates the directory itself on the next boot, so its
		// absence is not what decides an explicit Storage=persistent.
		name: "Storage=persistent before the directory exists",
		files: map[string]string{
			"/etc/systemd/journald.conf":                  "journald.conf.main",
			"/etc/systemd/journald.conf.d/10-vendor.conf": "journald.d.10-vendor-etc",
		},
		want: true, persisted: "persistent", runtime: "volatile",
	}, {
		// The configuration wins over a leftover directory: journald with
		// Storage=volatile writes nothing into it.
		name: "Storage=volatile with the directory still on disk",
		files: map[string]string{
			"/etc/systemd/journald.conf":                  "journald.conf.main",
			"/etc/systemd/journald.conf.d/10-vendor.conf": "journald.d.10-vendor",
		},
		journalDir: true, want: false, persisted: "volatile", runtime: "persistent",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := loggingAccess(tc.files, nil)
			if tc.journalDir {
				journalDirSeed(a)
			}
			b := buildBegun(t, "logging", a)

			if e := env(t, b, "logging.journald.persistent"); e.Status != facts.StatusOK || e.Value != tc.want {
				t.Errorf("persistent = %+v, want ok:%v", e, tc.want)
			}
			s := setting(t, b, "logging.journald.storage")
			if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || s.Persisted.Value != tc.persisted {
				t.Errorf("storage persisted = %+v, want ok:%q", s.Persisted, tc.persisted)
			}
			if s.Runtime == nil || s.Runtime.Status != facts.StatusOK || s.Runtime.Value != tc.runtime {
				t.Errorf("storage runtime = %+v, want ok:%q", s.Runtime, tc.runtime)
			}
			// No fixture here sets ForwardToSyslog, and journald's default is no.
			if e := env(t, b, "logging.journald.forward_to_syslog"); e.Status != facts.StatusOK || e.Value != false {
				t.Errorf("forward_to_syslog = %+v, want ok:false", e)
			}
			if got := b.Worst("logging"); got != facts.StatusOK {
				t.Errorf("Worst(logging) = %s, want ok", got)
			}
		})
	}
}

// C3/R148: a drop-in that EXISTS and cannot be read is the answer for every
// value the chain could set — including the runtime side, which must not be
// published as a confident "volatile" beside a persisted side nobody could
// read. Never a default.
func TestJournaldUnreadableDropinIsNotADefault(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/systemd/journald.conf":             "journald.conf.main",
		"/etc/systemd/journald.conf.d/10-x.conf": "journald.d.10-vendor-etc",
	}, nil)
	a.fails["/etc/systemd/journald.conf.d/10-x.conf"] = os.ErrPermission
	journalDirSeed(a) // the stat that would otherwise have said "persistent"
	b := buildBegun(t, "logging", a)

	s := setting(t, b, "logging.journald.storage")
	for _, side := range []struct {
		name string
		e    *facts.Envelope
	}{{"runtime", s.Runtime}, {"persisted", s.Persisted}} {
		if side.e == nil || side.e.Status != facts.StatusDenied {
			t.Errorf("storage %s = %+v, want denied", side.name, side.e)
			continue
		}
		if !strings.Contains(side.e.Reason, "/etc/systemd/journald.conf.d/10-x.conf") {
			t.Errorf("storage %s: the reason must name the file: %+v", side.name, side.e)
		}
	}
	for _, k := range []string{"logging.journald.forward_to_syslog", "logging.journald.persistent"} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s must carry the read failure, not a default: %+v", k, e)
		}
		if !strings.Contains(e.Reason, "/etc/systemd/journald.conf.d/10-x.conf") {
			t.Errorf("%s: the reason must name the file: %+v", k, e)
		}
	}
	if got := b.Worst("logging"); got != facts.StatusDenied {
		t.Errorf("Worst(logging) = %s, want denied", got)
	}
}

// Ruling I-11: with no systemd there is no journal to judge. ok:false would
// claim to have judged one that does not exist; unsupported ranks as ok in
// Worst (R71), so such a host's run stays complete.
func TestJournaldOnANonSystemdHostIsUnsupported(t *testing.T) {
	a := &fsAccess{files: map[string]string{}, cmds: map[string]cmdResult{}, fails: map[string]error{},
		dirs: map[string]bool{}, stats: map[string]statResult{}}
	journalDirSeed(a) // even a leftover directory does not make a journal
	b := buildBegun(t, "logging", a)

	s := setting(t, b, "logging.journald.storage")
	for _, side := range []struct {
		name string
		e    *facts.Envelope
	}{{"runtime", s.Runtime}, {"persisted", s.Persisted}} {
		if side.e == nil || side.e.Status != facts.StatusUnsupported {
			t.Errorf("storage %s = %+v, want unsupported", side.name, side.e)
		}
	}
	for _, k := range []string{"logging.journald.forward_to_syslog", "logging.journald.persistent"} {
		e := env(t, b, k)
		if e.Status != facts.StatusUnsupported {
			t.Errorf("%s = %+v, want unsupported", k, e)
		}
		if !strings.Contains(e.Reason, "journald") {
			t.Errorf("%s: the reason must say what this host has not got: %+v", k, e)
		}
	}
	if got := b.Worst("logging"); got != facts.StatusOK {
		t.Errorf("Worst(logging) = %s, want ok (unsupported ranks ok)", got)
	}
}

// Ruling I-23: systemd >= 254 may ship only /usr/lib/systemd/journald.conf.
// With no /etc copy the vendor file IS this host's main file, and its values
// are the answer — never journald's compiled-in defaults.
func TestJournaldMainFileFallsBackToTheVendorCopy(t *testing.T) {
	a := loggingAccess(map[string]string{"/usr/lib/systemd/journald.conf": "journald.conf.vendor"}, nil)
	b := buildBegun(t, "logging", a)

	s := setting(t, b, "logging.journald.storage")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || s.Persisted.Value != "persistent" {
		t.Errorf("storage persisted = %+v, want ok:persistent from the vendor copy", s.Persisted)
	}
	if e := env(t, b, "logging.journald.forward_to_syslog"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("forward_to_syslog = %+v, want ok:true from the vendor copy", e)
	}
	if e := env(t, b, "logging.journald.persistent"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("persistent = %+v, want ok:true", e)
	}
	if src := s.Persisted.Source; src == nil || len(src.Inputs) != 1 ||
		src.Inputs[0].Path != "/usr/lib/systemd/journald.conf" {
		t.Errorf("the persisted side must cite the file it was read from: %+v", src)
	}
}

// Ruling I-5/I-23 for the journald LEAVES: the /etc drop-in shadows the
// same-named vendor one — which is never opened — while a drop-in with
// another basename still applies, whichever directory it came from.
func TestJournaldEtcDropinShadowsTheVendorDropin(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/systemd/journald.conf":                      "journald.conf.main",       // Storage=auto
		"/usr/lib/systemd/journald.conf.d/10-vendor.conf": "journald.d.10-vendor",     // Storage=volatile (shadowed)
		"/etc/systemd/journald.conf.d/10-vendor.conf":     "journald.d.10-vendor-etc", // Storage=persistent
		"/run/systemd/journald.conf.d/20-runtime.conf":    "journald.d.20-runtime",    // ForwardToSyslog=yes
	}, nil)
	b := buildBegun(t, "logging", a)

	if s := setting(t, b, "logging.journald.storage"); s.Persisted == nil || s.Persisted.Value != "persistent" {
		t.Errorf("storage persisted = %+v, want the /etc drop-in's persistent", s.Persisted)
	}
	if e := env(t, b, "logging.journald.persistent"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("persistent = %+v, want ok:true (no journal directory needed)", e)
	}
	if e := env(t, b, "logging.journald.forward_to_syslog"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("forward_to_syslog = %+v, want ok:true from the /run drop-in", e)
	}
	for _, p := range a.reads {
		if strings.HasPrefix(p, "/usr/lib/systemd/journald.conf.d/") {
			t.Errorf("a shadowed drop-in must not be read: %s", p)
		}
	}
}

// C3 for the OTHER oracle: the configuration chain reads cleanly, but the
// stat of /var/log/journal is refused. That stat is the whole runtime side
// and, under Storage=auto, the whole judgement — so both carry the read's
// status. "The directory could not be stat-ed, therefore the journal is
// volatile" would be a fabricated FAIL.
func TestJournaldDeniedJournalDirIsNotVolatile(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/systemd/journald.conf": "journald.conf.main"}, nil)
	a.fails["/var/log/journal"] = os.ErrPermission // no stats entry: fsAccess.Stat then fails
	b := buildBegun(t, "logging", a)

	s := setting(t, b, "logging.journald.storage")
	if s.Runtime == nil || s.Runtime.Status != facts.StatusDenied ||
		!strings.Contains(s.Runtime.Reason, "/var/log/journal") {
		t.Errorf("storage runtime = %+v, want denied naming /var/log/journal", s.Runtime)
	}
	// The file that WAS readable still answers its own side.
	if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || s.Persisted.Value != "auto" {
		t.Errorf("storage persisted = %+v, want ok:auto", s.Persisted)
	}
	e := env(t, b, "logging.journald.persistent")
	if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/var/log/journal") {
		t.Errorf("persistent = %+v, want denied naming /var/log/journal (never ok:false, never error)", e)
	}
	if got := b.Worst("logging"); got != facts.StatusDenied {
		t.Errorf("Worst(logging) = %s, want denied", got)
	}
}

// --- the whole-branch fix wave (IR-2, IR-4, IR-7, IR-9 … IR-17) ----------

// IR-7: Debian and Ubuntu keep /etc/rsyslog.conf as a conffile after
// `apt remove rsyslog`, and `apt install syslog-ng` removes rsyslog through
// the conflict. Judging such a host by the DEAD rsyslog rules is a
// confidently wrong verdict either way, so the configuration file only names
// the implementation when the daemon's binary is there too.
func TestLoggingConffileWithoutItsBinaryIsNotRsyslog(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.ubuntu"}, nil)
	delete(a.stats, "/usr/sbin/rsyslogd") // the package went; the conffile stayed
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.syslog.implementation"); e.Status != facts.StatusOK || e.Value != "journald-only" {
		t.Fatalf("impl = %+v, want journald-only", e)
	}
	// IR-18: every rsyslog leaf degrades together, so the list itself is
	// iterated rather than a hand-picked subset of it.
	for _, k := range rsyslogLeafKeys {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent on a host with no rsyslogd", k, e)
		}
		if !strings.Contains(e.Reason, "/etc/rsyslog.conf") {
			t.Errorf("%s: the reason must name the leftover file: %+v", k, e)
		}
	}
	if got := b.Worst("logging"); got != facts.StatusOK {
		t.Errorf(`Worst("logging") = %s, want ok (absent ranks ok)`, got)
	}
}

// IR-7: the same rule the other way round — a syslog-ng host that still
// carries the rsyslog conffile the conflict left behind is judged as
// syslog-ng, whose dialect this version does not parse.
func TestLoggingSyslogNgNeedsItsBinaryToo(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/rsyslog.conf":             "rsyslog.conf.ubuntu", // left behind by the conflict
		"/etc/syslog-ng/syslog-ng.conf": "syslog-ng.conf",
	}, nil)
	delete(a.stats, "/usr/sbin/rsyslogd")
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.syslog.implementation"); e.Value != "syslog-ng" {
		t.Fatalf("impl = %+v, want syslog-ng", e)
	}
	for _, k := range rsyslogLeafKeys {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent", k, e)
		}
	}
}

// IR-2: /dev/console is a device — the message is shown on a terminal and
// nothing is kept — so the facility is logged but not persistent, and the
// device is not a log target to stat.
func TestLoggingDeviceTargetIsNotPersistent(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.dev-console"},
		[]string{"/var/log/messages"})
	b := buildBegun(t, "logging", a)

	rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "kern")
	if rec["logged"] != true || rec["persistent"] != false || rec["target"] != "/dev/console" {
		t.Errorf("kern = %+v, want logged, not persistent, on /dev/console", rec)
	}
	for _, v := range okList(t, b, "logging.log_targets") {
		if p, _ := v.(map[string]any)["path"].(string); strings.HasPrefix(p, "/dev/") {
			t.Errorf("a device is not a log file to stat: %v", v)
		}
	}
	// The facility that DOES reach a file is unaffected.
	if rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "daemon"); rec["persistent"] != true {
		t.Errorf("daemon = %+v, want persistent", rec)
	}
}

// IR-4: Debian's default block splits one selector over four backslash-
// continued lines, each fragment ending on a ";". Joining them with a space
// would make the parser read "auth,authpriv.none" as the ACTION of the first
// fragment — a user-message rule — and /var/log/messages would vanish.
func TestLoggingBackslashContinuationKeepsTheSelectorWhole(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.debian-continuation"},
		[]string{"/var/log/messages"})
	b := buildBegun(t, "logging", a)

	files := 0
	for _, v := range okList(t, b, "logging.rsyslog.rules") {
		rec := v.(map[string]any)
		if rec["target_kind"] == "user" {
			t.Errorf("a selector fragment must not be read as a user action: %+v", rec)
		}
		if rec["target_kind"] == "file" && rec["target"] == "/var/log/messages" {
			files++
		}
	}
	if files == 0 {
		t.Error("the block routes to /var/log/messages")
	}
	if rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "kern"); rec["persistent"] != true {
		t.Errorf("kern = %+v, want persistent on /var/log/messages", rec)
	}
	if rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "mail"); rec["logged"] != false {
		t.Errorf("mail = %+v: the block excludes it with .none", rec)
	}
}

// IR-9: stat_status names the status the read primitive actually reported. A
// target that is a symlink is an error, not a refusal — "denied" would send a
// reader looking for a privilege that has nothing to do with it.
func TestLoggingTargetStatStatusNamesTheRealStatus(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.two-targets"}, nil)
	a.fails["/var/log/syslog"] = collect.ErrSymlink
	b := buildBegun(t, "logging", a)

	rec := findPath(t, okList(t, b, "logging.log_targets"), "/var/log/syslog")
	if rec["stat_status"] != "error" {
		t.Errorf("stat_status = %v, want error: %+v", rec["stat_status"], rec)
	}
	if r, _ := rec["reason"].(string); !strings.Contains(r, "symbolic link") {
		t.Errorf("the reason must say what the stat hit: %+v", rec)
	}
}

// IR-10: a bare `stop` line is not a global — it is `*.* stop`, and every
// rule below it in the ruleset is unreachable. Reading it as a no-op made the
// catch-all below it look like coverage for every facility.
func TestLoggingBareStopDiscardsEverythingBelowIt(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.bare-stop"},
		[]string{"/var/log/auth.log"})
	b := buildBegun(t, "logging", a)
	cov := okList(t, b, "logging.rsyslog.coverage")

	rec := findFacility(t, cov, "kern")
	if rec["logged"] != false || rec["persistent"] != false {
		t.Errorf("kern = %+v: the catch-all below a bare stop is unreachable", rec)
	}
	if r, _ := rec["reason"].(string); !strings.Contains(r, "stop") {
		t.Errorf("kern: the reason must cite the discarding line: %+v", rec)
	}
	// The rule ABOVE the stop still applies.
	if rec := findFacility(t, cov, "auth"); rec["logged"] != true || rec["persistent"] != true {
		t.Errorf("auth = %+v, want logged persistently by the line above the stop", rec)
	}
}

// IR-11 (BLOCKING): the actions under $ActionExecOnlyWhenPreviousIsSuspended
// run only when the one before them failed. Reading a failover buffer as
// unconditional routing turns "the primary collector is unreachable" into
// "this facility is logged locally" — the honest answer is MANUAL.
func TestLoggingConditionalActionsAreUnmodelled(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		want    int
	}{
		{"legacy $ActionExecOnly directive", "rsyslog.conf.failover", 2},
		{"RainerScript action.execOnly attribute", "rsyslog.conf.action-conditional", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := loggingAccess(map[string]string{"/etc/rsyslog.conf": tc.fixture}, nil)
			b := buildBegun(t, "logging", a)

			if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value != tc.want {
				t.Errorf("unmodelled = %+v, want ok:%d", e, tc.want)
			}
			if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
				t.Errorf("coverage = %+v, want absent", e)
			}
			for _, v := range okList(t, b, "logging.rsyslog.rules") {
				if rec := v.(map[string]any); rec["target"] == "/var/log/localbuffer" {
					t.Errorf("a conditional action must not be recorded as routing: %+v", rec)
				}
			}
		})
	}
}

// IR-12: $RuleSet and $DefaultRuleset are the legacy spelling of
// ruleset()/call, which Ruling I-12 already counts — the rules below them
// belong to a ruleset that may never be called.
func TestLoggingLegacyRulesetIsUnmodelled(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.legacy-ruleset"}, nil)
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value.(int) == 0 {
		t.Errorf("unmodelled = %+v, want > 0", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
		t.Errorf("coverage = %+v, want absent", e)
	}
}

// IR-13: omdiscard is the RainerScript spelling of "~".
func TestLoggingOmdiscardIsADiscard(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.omdiscard"},
		[]string{"/var/log/syslog"})
	b := buildBegun(t, "logging", a)
	cov := okList(t, b, "logging.rsyslog.coverage")

	if rec := findFacility(t, cov, "kern"); rec["logged"] != false {
		t.Errorf("kern = %+v: omdiscard drops it before the catch-all", rec)
	}
	if rec := findFacility(t, cov, "daemon"); rec["logged"] != true || rec["persistent"] != true {
		t.Errorf("daemon = %+v, want logged persistently", rec)
	}
}

// IR-14: a property filter on the FACILITY or SEVERITY property can take a
// whole facility out of everything below it, unlike the msg/syslogtag filters
// Ruling I-12 counts as coverage-neutral evidence.
func TestLoggingFacilityPropertyFilterIsUnmodelled(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.facility-filter"}, nil)
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("unmodelled = %+v, want ok:1", e)
	}
	if e := env(t, b, "logging.rsyslog.property_filters"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("property_filters = %+v: a facility filter is not neutral evidence", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
		t.Errorf("coverage = %+v, want absent", e)
	}
}

// IR-15: a discard restricted to one severity silences part of a facility —
// possibly exactly the serious part — so it is neither a discard of the whole
// facility nor something to ignore. A full discard still discards.
func TestLoggingPriorityRestrictedDiscardIsUnmodelled(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.partial-discard"}, nil)
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("unmodelled = %+v, want ok:1", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
		t.Errorf("coverage = %+v, want absent (never kern logged:false)", e)
	}
	for _, v := range okList(t, b, "logging.rsyslog.rules") {
		if rec := v.(map[string]any); rec["target_kind"] == "discard" {
			t.Errorf("a partial discard is not recorded as a discard: %+v", rec)
		}
	}
	// A full discard is unchanged.
	full := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.stop-before"},
		[]string{"/var/log/syslog"})
	fb := buildBegun(t, "logging", full)
	if e := env(t, fb, "logging.rsyslog.unmodelled"); e.Value != 0 {
		t.Errorf("a full discard stays modelled: %+v", e)
	}
	if rec := findFacility(t, okList(t, fb, "logging.rsyslog.coverage"), "auth"); rec["logged"] != false {
		t.Errorf("auth = %+v, want logged:false", rec)
	}
}

// IR-16: "^program" hands the message to a program; it is not a user list,
// and it is not persistent local storage either.
func TestLoggingProgramActionIsRecordedAsItsOwnKind(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.program-action"},
		[]string{"/var/log/syslog"})
	b := buildBegun(t, "logging", a)

	var found bool
	for _, v := range okList(t, b, "logging.rsyslog.rules") {
		rec := v.(map[string]any)
		if rec["facility"] != "kern" || rec["target_kind"] != "program" {
			continue
		}
		found = true
		if rec["target"] != "/usr/local/bin/alerter" {
			t.Errorf("the caret is not part of the program: %+v", rec)
		}
	}
	if !found {
		t.Errorf("no program rule in %v", okList(t, b, "logging.rsyslog.rules"))
	}
	for _, v := range okList(t, b, "logging.log_targets") {
		if p, _ := v.(map[string]any)["path"].(string); strings.Contains(p, "alerter") {
			t.Errorf("a program is not a log file to stat: %v", v)
		}
	}
}

// IR-17: rsyslog accepts numeric facility and priority codes. This version
// does not map them, so such a line is counted rather than silently dropped —
// "4.* ~" discards auth on a real host.
func TestLoggingNumericSelectorIsUnmodelled(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.numeric-selector"}, nil)
	b := buildBegun(t, "logging", a)

	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("unmodelled = %+v, want ok:1", e)
	}
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent {
		t.Errorf("coverage = %+v, want absent", e)
	}
}
