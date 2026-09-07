package check

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func snap(t *testing.T, factsJSON string) *facts.Snapshot {
	t.Helper()
	s, err := facts.Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":` + factsJSON + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func one(c controls.Control) *controls.Set {
	c.Path = "test/" + c.ID + ".yaml"
	return &controls.Set{Version: "t", Digest: "sha256:0", Controls: []controls.Control{c}}
}

var reg = func() *facts.Registry { r, _ := facts.LoadRegistry(); return r }()

func telnetControl(automation, absentMeans string) controls.Control {
	return controls.Control{
		ID: "muster.service.telnet_disabled", Importance: "중", Category: "service", Automation: automation, AbsentMeans: absentMeans,
		RequiresFacts: ">=1",
		Checks:        []controls.Clause{{Fact: "services.telnet.reachable", Op: "eq", Expected: false}},
		Remediation:   &controls.Remediation{Risk: "none"},
	}
}

// permitRootLoginControl checks the sshd.options.permit_root_login setting
// on its effective side explicitly (default_on is also "effective", but
// spelling it out keeps these cases readable next to the "both" cases
// below).
func permitRootLoginControl(automation, absentMeans string) controls.Control {
	return controls.Control{
		ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: automation, AbsentMeans: absentMeans,
		Checks:      []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}},
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
	}
}

// passMaxDaysControl checks accounts.login_defs.pass_max_days without an
// explicit `on`, so it screens/evaluates on the registry's default_on
// ("both").
func passMaxDaysControl(automation string) controls.Control {
	return controls.Control{
		ID: "muster.account.pass_max_days", Importance: "중", Category: "account", Automation: automation, AbsentMeans: "not_applicable",
		Checks:      []controls.Clause{{Fact: "accounts.login_defs.pass_max_days", Op: "lte", Expected: 90}},
		Remediation: &controls.Remediation{Risk: "none"},
	}
}

// nopassControl reads an accounts.* list fact, which is what makes the
// step-13 remote-NSS degradation (spec §7.3) apply to it.
func nopassControl() controls.Control {
	return controls.Control{
		ID: "muster.account.shadow_passwords", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "fail",
		Checks:      []controls.Clause{{Fact: "accounts.users", Op: "none", Subject: "name", Where: &controls.Clause{Field: "password_status", Op: "eq", Expected: "nopass"}}},
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
	}
}

// passwordPolicyControl checks two `both` settings at once, which is what
// makes cross-clause degradation shadowing (C2) visible: one clause can fail
// on both sides while another carries a side mismatch.
func passwordPolicyControl() controls.Control {
	return controls.Control{
		ID: "muster.account.password_policy", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "fail",
		RequiresFacts: ">=1",
		Checks: []controls.Clause{
			{Fact: "accounts.login_defs.pass_max_days", Op: "lte", Expected: 90},
			{Fact: "accounts.login_defs.pass_min_days", Op: "gte", Expected: 1},
		},
		Remediation: &controls.Remediation{Risk: "none"},
	}
}

// evidenceHasFact returns a verify func asserting r.Evidence names fact with
// status (R25: the hard/unsupported ERROR and NOT_APPLICABLE paths must
// carry evidence for the fact that actually screened, not just whatever
// applies_when evidence happened to accumulate earlier).
func evidenceHasFact(fact string, status facts.Status) func(t *testing.T, r Result) {
	return func(t *testing.T, r Result) {
		for _, ev := range r.Evidence {
			if ev.Fact == fact && ev.Status == status {
				return
			}
		}
		t.Errorf("want evidence for %s (%s), got %+v", fact, status, r.Evidence)
	}
}

func TestDerivationTable(t *testing.T) {
	cases := []struct {
		name   string
		facts  string
		ctl    controls.Control
		status Status
		code   ReasonCode
		verify func(t *testing.T, r Result) // optional extra assertion beyond status/code
	}{
		{"14 pass", `{"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`, telnetControl("auto", "pass"), PASS, "", nil},
		{"12 fail", `{"services":{"telnet":{"reachable":{"status":"ok","value":true}}}}`, telnetControl("auto", "pass"), FAIL, "", nil},
		{"11 partial warn", `{"services":{"telnet":{"reachable":{"status":"ok","value":true}}}}`, telnetControl("partial", "pass"), WARN, "", nil},
		{"8 absent means pass", `{"services":{"telnet":{"reachable":{"status":"absent"}}}}`, telnetControl("auto", "pass"), PASS, "", nil},
		{"8 absent means na", `{"services":{"telnet":{"reachable":{"status":"absent"}}}}`, telnetControl("auto", "not_applicable"), NotApplicable, "", nil},
		{"7 unsupported", `{"services":{"telnet":{"reachable":{"status":"unsupported","reason":"container"}}}}`, telnetControl("auto", "pass"), NotApplicable, UnsupportedEnv,
			evidenceHasFact("services.telnet.reachable", facts.StatusUnsupported)}, // R25
		{"6 denied", `{"services":{"telnet":{"reachable":{"status":"denied","reason":"needs root"}}}}`, telnetControl("auto", "pass"), ERROR, PermissionDenied,
			evidenceHasFact("services.telnet.reachable", facts.StatusDenied)}, // R25
		{"6 truncated", `{"services":{"telnet":{"reachable":{"status":"ok","value":false,"truncated":true}}}}`, telnetControl("auto", "pass"), ERROR, Truncated, nil},
		{"6 missing key never absent_means", `{}`, telnetControl("auto", "pass"), ERROR, MissingFact, nil},
		{"1 requires_facts unmet", `{"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`, func() controls.Control { c := telnetControl("auto", "pass"); c.RequiresFacts = ">=2"; return c }(), ERROR, MissingFact, nil},
		{"4 manual", `{}`, controls.Control{ID: "muster.log.review", Importance: "하", Category: "log", Automation: "manual", ManualReason: "interview"}, MANUAL, "", nil},
		{"3 applies_when false", `{"services":{"ssh":{"installed":{"status":"ok","value":false}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), NotApplicable, "", nil},
		{"2 applies_when denied", `{"services":{"ssh":{"installed":{"status":"denied","reason":"root"}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), ERROR, PermissionDenied, evidenceHasFact("services.ssh.installed", facts.StatusDenied)}, // R25
		// spec §6.5 rows 2-4 (amended 2026-09-03): a manual control's
		// applies_when is screened and evaluated before the automation
		// class is looked at, so MANUAL is reached only when applies_when
		// holds (or is absent).
		{"2 manual control whose applies_when fact is denied is ERROR",
			`{"services":{"ssh":{"installed":{"status":"denied","reason":"needs root"}}}}`,
			controls.Control{ID: "muster.service.mail_version", Importance: "하", Category: "service", Automation: "manual",
				ManualReason:  "needs the MTA configuration parser",
				AppliesWhen:   controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
				RequiresFacts: ">=1"},
			ERROR, PermissionDenied, nil},
		{"3 manual control whose applies_when is false is NOT_APPLICABLE, not MANUAL",
			`{"services":{"ssh":{"installed":{"status":"ok","value":false}}}}`,
			controls.Control{ID: "muster.service.mail_version", Importance: "하", Category: "service", Automation: "manual",
				ManualReason:  "needs the MTA configuration parser",
				AppliesWhen:   controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
				RequiresFacts: ">=1"},
			NotApplicable, "", func(t *testing.T, r Result) {
				if !strings.Contains(r.Reason, "applies_when does not hold") {
					t.Errorf("reason must say applies_when does not hold: %q", r.Reason)
				}
			}},
		{"4 manual control whose applies_when holds is MANUAL with evidence",
			`{"services":{"ssh":{"installed":{"status":"ok","value":true}}}}`,
			controls.Control{ID: "muster.service.mail_version", Importance: "하", Category: "service", Automation: "manual",
				ManualReason:  "needs the MTA configuration parser",
				AppliesWhen:   controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
				RequiresFacts: ">=1"},
			MANUAL, "", evidenceHasFact("services.ssh.installed", facts.StatusOK)},
		{"R25 mechanism-selection hard error carries evidence for the denied fact, not only applies_when's",
			`{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"denied","reason":"sshd -T needs root"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "manual", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				AppliesWhen: controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
				}},
			ERROR, PermissionDenied, evidenceHasFact("sshd.options.permit_root_login", facts.StatusDenied)},
		{"9 walk not run", `{"walk":{"world_writable":{"status":"ok","value":[]}}}`,
			controls.Control{ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "pass", Remediation: &controls.Remediation{Risk: "none"},
				Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path", Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}}},
			MANUAL, "", func(t *testing.T, r Result) {
				if len(r.Evidence) == 0 {
					t.Errorf("walk-gate MANUAL must carry evidence for walk.complete, got none: %+v", r)
				}
			}},
		{"10 walk incomplete", `{"walk":{"world_writable":{"status":"ok","value":[]},"complete":{"status":"ok","value":false}}}`,
			controls.Control{ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "pass", Remediation: &controls.Remediation{Risk: "none"},
				Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path", Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}}},
			ERROR, WalkIncomplete, nil},
		{"13 degraded warn", `{"sshd":{"personas_collected":{"status":"ok","value":false},"options":{"permit_root_login":{"effective":{"status":"ok","value":"no"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Persona: "root", Op: "eq", Expected: "no"}}},
			WARN, "", nil},
		{"5 mechanisms fallback", `{"files":{"etc_securetty":{"status":"ok","value":{}},"etc_securetty_lines":{"status":"ok","value":["console"]}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty_lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			PASS, "", func(t *testing.T, r Result) {
				if r.Mechanism != 2 {
					t.Errorf("want mechanism 2 chosen, got %d", r.Mechanism)
				}
				// M10: the `when` clause that selected this mechanism is part
				// of the decision, so its evidence must be kept.
				evidenceHasFact("files.etc_securetty", facts.StatusOK)(t, r)
			}},
		{"5 no mechanism applies", `{"files":{"etc_securetty":{"status":"absent"}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty_lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			NotApplicable, "", nil},
		// R15/R16 fix-round cases.
		{"8 absent means fail plain fact carries evidence", `{"services":{"telnet":{"reachable":{"status":"absent"}}}}`, telnetControl("auto", "fail"), FAIL, "",
			func(t *testing.T, r Result) {
				if len(r.Evidence) == 0 {
					t.Errorf("absent_means: fail must carry evidence, got none: %+v", r)
				}
			}},
		{"8 absent means fail setting effective side carries evidence", `{"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			permitRootLoginControl("auto", "fail"), FAIL, "",
			func(t *testing.T, r Result) {
				for _, ev := range r.Evidence {
					if ev.Side == "effective" {
						return
					}
				}
				t.Errorf("want evidence with Side==effective, got %+v", r.Evidence)
			}},
		{"R15 setting one side ok one side absent on selected side is not screened away", `{"sshd":{"options":{"permit_root_login":{"effective":{"status":"ok","value":"yes"},"persisted":{"status":"absent"}}}}}`,
			permitRootLoginControl("auto", "not_applicable"), FAIL, "", nil},
		{"both sides ok mismatched degrades not applied", `{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":99999},"persisted":{"status":"ok","value":90}}}}}`,
			passMaxDaysControl("auto"), WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != "not applied" {
					t.Errorf("want Degraded=%q, got %q (%+v)", "not applied", r.Degraded, r)
				}
			}},
		{"persisted side missing degrades reverts on reboot", `{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90}}}}}`,
			passMaxDaysControl("auto"), WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != "reverts on reboot" {
					t.Errorf("want Degraded=%q, got %q (%+v)", "reverts on reboot", r.Degraded, r)
				}
			}},
		// C2: a clause failing on BOTH sides is a hard failure; another
		// clause's side mismatch must not soften it into WARN (step 12).
		{"12 hard failure is not shadowed by another clause's side mismatch",
			`{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":99999},"persisted":{"status":"ok","value":99999}},` +
				`"pass_min_days":{"runtime":{"status":"ok","value":1},"persisted":{"status":"ok","value":0}}}}}`,
			passwordPolicyControl(), FAIL, "",
			func(t *testing.T, r Result) {
				if !strings.Contains(r.Reason, "pass_max_days") {
					t.Errorf("reason must name the clause that failed outright: %q", r.Reason)
				}
				if !strings.Contains(r.Reason, "reverts on reboot") {
					t.Errorf("reason must keep the degradation as secondary: %q", r.Reason)
				}
				if r.Degraded != "reverts on reboot" {
					t.Errorf("want Degraded=%q, got %q", "reverts on reboot", r.Degraded)
				}
			}},
		{"12 side mismatch alone still warns when every failing clause is a mismatch",
			`{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90},"persisted":{"status":"ok","value":90}},` +
				`"pass_min_days":{"runtime":{"status":"ok","value":1},"persisted":{"status":"ok","value":0}}}}}`,
			passwordPolicyControl(), WARN, "", nil},
		// M11: the key is present; the side the clause selected is not.
		{"6 selected side absent from the snapshot names the side",
			`{"sshd":{"options":{"permit_root_login":{"effective":{"status":"ok","value":"no"}}}}}`,
			func() controls.Control {
				c := permitRootLoginControl("auto", "fail")
				c.Checks = []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "runtime", Op: "eq", Expected: "no"}}
				return c
			}(), ERROR, MissingFact,
			func(t *testing.T, r Result) {
				if !strings.Contains(r.Reason, "side runtime of sshd.options.permit_root_login is not present in this snapshot") {
					t.Errorf("reason must name the missing side: %q", r.Reason)
				}
			}},
		// M12: walk.complete carrying something that is not a bool is a type
		// error, not "the walk did not finish".
		{"10 non-bool walk.complete is a type error",
			`{"walk":{"world_writable":{"status":"ok","value":[]},"complete":{"status":"ok","value":"yes"}}}`,
			controls.Control{ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "pass", Remediation: &controls.Remediation{Risk: "none"},
				Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path", Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}}},
			ERROR, InternalError,
			func(t *testing.T, r Result) {
				if !strings.Contains(r.Reason, "walk.complete") {
					t.Errorf("reason must name the key: %q", r.Reason)
				}
			}},
		// M12: a reason is user text; Go's %#v syntax must never appear in it.
		{"6 type mismatch reason carries no Go syntax",
			`{"services":{"telnet":{"reachable":{"status":"ok","value":{"a":1}}}}}`,
			telnetControl("auto", "pass"), ERROR, InternalError,
			func(t *testing.T, r Result) {
				if strings.Contains(r.Reason, "interface {}") || strings.Contains(r.Reason, "map[string]") {
					t.Errorf("reason must not leak Go syntax: %q", r.Reason)
				}
			}},
		// S1/R34: step 13's parse fallback for a daemon-reported setting.
		{"13 sshd parse fallback degrades a holding result to WARN",
			`{"sshd":{"collect_method":{"status":"ok","value":"parse"},"personas_collected":{"status":"ok","value":true},` +
				`"options":{"permit_root_login":{"effective":{"status":"ok","value":"no"}}}}}`,
			permitRootLoginControl("auto", "fail"), WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != degradedParseFallback {
					t.Errorf("want Degraded=%q, got %q", degradedParseFallback, r.Degraded)
				}
				if !strings.Contains(r.Reason, "sshd -T unavailable") {
					t.Errorf("reason must name the fallback: %q", r.Reason)
				}
			}},
		{"13 sshd parse fallback leaves a failing result at FAIL",
			`{"sshd":{"collect_method":{"status":"ok","value":"parse"},"personas_collected":{"status":"ok","value":true},` +
				`"options":{"permit_root_login":{"effective":{"status":"ok","value":"yes"}}}}}`,
			permitRootLoginControl("auto", "fail"), FAIL, "", nil},
		// Spec §7.3: an account control judged while NSS names a remote
		// source is a degraded judgment — local files are only part of it.
		{"13 remote NSS source degrades a holding account control to WARN",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"users":{"status":"ok","value":[{"name":"root","password_status":"hashed"}]}}}`,
			nopassControl(), WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != degradedRemoteNSS {
					t.Errorf("want Degraded=%q, got %q", degradedRemoteNSS, r.Degraded)
				}
				if !strings.Contains(r.Reason, "remote NSS") {
					t.Errorf("reason must name the degradation: %q", r.Reason)
				}
			}},
		{"13 remote NSS source leaves a failing account control at FAIL",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"users":{"status":"ok","value":[{"name":"bob","password_status":"nopass"}]}}}`,
			nopassControl(), FAIL, "", nil},
		{"13 remote NSS source does not touch a non-account control",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}}},"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`,
			telnetControl("auto", "pass"), PASS, "", nil},
		{"13 an unreadable nsswitch is not a remote source",
			`{"accounts":{"nss":{"remote":{"status":"denied","reason":"/etc/nsswitch.conf: permission denied"}},"users":{"status":"ok","value":[{"name":"root","password_status":"hashed"}]}}}`,
			nopassControl(), PASS, "", nil},
		// R128: a login.defs control (no user/group subject_kind, and not
		// accounts.shadow_in_use) is never degraded by a remote NSS source.
		{"13 remote NSS source does not degrade a login.defs control",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90},"persisted":{"status":"ok","value":90}}}}}`,
			passMaxDaysControl("auto"), PASS, "", nil},
		// R127: remoteNSS treats accounts.shadow_in_use as a remote-source
		// clause explicitly (it has no registry SubjectKind), so a control
		// that reads only that fact is degraded too, not just the
		// user/group-subject ones above.
		{"13 remote NSS source degrades a control that reads only shadow_in_use",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"shadow_in_use":{"status":"ok","value":true}}}`,
			controls.Control{ID: "muster.account.shadow_only_probe", Importance: "중", Category: "account", Automation: "auto", AbsentMeans: "fail",
				Checks:      []controls.Clause{{Fact: "accounts.shadow_in_use", Op: "eq", Expected: true}},
				Remediation: &controls.Remediation{Risk: "none"},
			},
			WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != degradedRemoteNSS {
					t.Errorf("want Degraded=%q, got %q", degradedRemoteNSS, r.Degraded)
				}
			}},
		// M10: applies_when evidence must survive absent_means, and a
		// mechanism's `when` evidence must not be discarded.
		{"5 no mechanism applies keeps applies_when evidence",
			`{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"files":{"etc_securetty":{"status":"absent"}},` +
				`"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "manual", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				AppliesWhen: controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty_lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			MANUAL, "", evidenceHasFact("services.ssh.installed", facts.StatusOK)},
		// I4: a snapshot that forges the reader-only "missing" on one side of
		// a `both` setting must not read as absent and fall to absent_means.
		{"6 forged status on a both side is an error, never absent_means",
			`{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90},"persisted":{"status":"missing"}}}}}`,
			passMaxDaysControl("auto"), ERROR, ParseError, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Evaluate(snap(t, c.facts), one(c.ctl), reg, Options{})
			if len(res) != 1 {
				t.Fatalf("%d results", len(res))
			}
			r := res[0]
			if r.Status != c.status || r.ReasonCode != c.code {
				t.Fatalf("status=%s code=%q reason=%q, want %s %q", r.Status, r.ReasonCode, r.Reason, c.status, c.code)
			}
			if r.Status != MANUAL && r.Status != PASS && r.Reason == "" && r.Status != NotApplicable {
				t.Errorf("non-pass result must carry a reason: %+v", r)
			}
			if (r.Status == FAIL || r.Status == WARN) && len(r.Evidence) == 0 && len(r.Observations) == 0 {
				t.Errorf("FAIL/WARN must carry evidence: %+v", r)
			}
			if c.verify != nil {
				c.verify(t, r)
			}
		})
	}
}

// R27: a reason string must name the substituted parameter value, not the
// literal "${name}" token.
func TestReasonRendersSubstitutedParamsNotTheToken(t *testing.T) {
	c := controls.Control{
		ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "manual",
		Params:      map[string]controls.Param{"allowed": {Type: "list<string>", Default: []any{"no", "prohibit-password"}}},
		Checks:      []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "in", Expected: "${allowed}"}},
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
	}
	res := Evaluate(snap(t, `{"sshd":{"options":{"permit_root_login":{"effective":{"status":"ok","value":"yes"}}}}}`), one(c), reg, Options{})
	r := res[0]
	if r.Status != FAIL {
		t.Fatalf("status=%s, want FAIL: %+v", r.Status, r)
	}
	if strings.Contains(r.Reason, "${") {
		t.Errorf("reason must not contain a literal param token: %q", r.Reason)
	}
	if !strings.Contains(r.Reason, "no") || !strings.Contains(r.Reason, "prohibit-password") {
		t.Errorf("reason must name the substituted list: %q", r.Reason)
	}
}

// R27: an each/none reason must name the operative where/require sub-clause,
// never Go's zero-value rendering of a nil pointer ("<nil>").
func TestReasonForEachAndNoneNamesTheSubClauseNotNil(t *testing.T) {
	eachCtl := controls.Control{
		ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "manual",
		Remediation: &controls.Remediation{Risk: "none"},
		Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path",
			Where:   &controls.Clause{Field: "sticky", Op: "eq", Expected: false},
			Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}},
	}
	eachFacts := `{"walk":{"world_writable":{"status":"ok","value":[{"path":"/opt/x","sticky":false,"package_declared":false}]},"complete":{"status":"ok","value":true}}}`
	res := Evaluate(snap(t, eachFacts), one(eachCtl), reg, Options{})
	r := res[0]
	if r.Reason == "" || strings.Contains(r.Reason, "<nil>") {
		t.Fatalf("each reason must be non-empty and free of <nil>: %q (%+v)", r.Reason, r)
	}
	if !strings.Contains(r.Reason, "require") || !strings.Contains(r.Reason, "package_declared") {
		t.Errorf("each reason must name the require sub-clause: %q", r.Reason)
	}

	noneCtl := controls.Control{
		ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "manual",
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
		Checks:      []controls.Clause{{Fact: "files.etc_securetty_lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}},
	}
	noneFacts := `{"files":{"etc_securetty":{"status":"ok","value":{}},"etc_securetty_lines":{"status":"ok","value":["pts/0"]}}}`
	res2 := Evaluate(snap(t, noneFacts), one(noneCtl), reg, Options{})
	r2 := res2[0]
	if r2.Reason == "" || strings.Contains(r2.Reason, "<nil>") {
		t.Fatalf("none reason must be non-empty and free of <nil>: %q (%+v)", r2.Reason, r2)
	}
	if !strings.Contains(r2.Reason, "where") || !strings.Contains(r2.Reason, "^pts/") {
		t.Errorf("none reason must name the where sub-clause: %q", r2.Reason)
	}
}

// M10 follow-on: keeping a mechanism's `when` evidence must not print the
// same fact reading twice, because a `when` clause and the checks it selects
// usually read the same key.
func TestEvidenceDoesNotRepeatTheSameReading(t *testing.T) {
	c := controls.Control{
		ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "manual",
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
		AppliesWhen: controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}},
		Mechanisms: []controls.Mechanism{
			{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}},
				Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
		}}
	res := Evaluate(snap(t, `{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"ok","value":"yes"}}}}}`),
		one(c), reg, Options{})
	r := res[0]
	if r.Status != FAIL {
		t.Fatalf("status=%s, want FAIL: %+v", r.Status, r)
	}
	seen := map[string]int{}
	for _, ev := range r.Evidence {
		seen[ev.Fact+"@"+ev.Side]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("evidence repeats %s %d times: %+v", k, n, r.Evidence)
		}
	}
	// The `when` evidence is still what keeps the fact in the record.
	evidenceHasFact("sshd.options.permit_root_login", facts.StatusOK)(t, r)
	evidenceHasFact("services.ssh.installed", facts.StatusOK)(t, r)
}

func TestEvaluateIsolatesPanics(t *testing.T) {
	customs["__panic"] = func(e *env, c *controls.Control) clauseOutcome { panic("boom") }
	defer delete(customs, "__panic")
	c := controls.Control{ID: "muster.beyond.panic", Importance: "하", Category: "beyond", Automation: "auto", AbsentMeans: "fail", Custom: "__panic", Remediation: &controls.Remediation{Risk: "none"}}
	res := Evaluate(snap(t, `{}`), one(c), reg, Options{})
	if res[0].Status != ERROR || res[0].ReasonCode != InternalError {
		t.Fatalf("%+v", res[0])
	}
}
