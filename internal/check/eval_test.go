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
		{"7 unsupported", `{"services":{"telnet":{"reachable":{"status":"unsupported","reason":"container"}}}}`, telnetControl("auto", "pass"), NotApplicable, UnsupportedEnv, nil},
		{"6 denied", `{"services":{"telnet":{"reachable":{"status":"denied","reason":"needs root"}}}}`, telnetControl("auto", "pass"), ERROR, PermissionDenied, nil},
		{"6 truncated", `{"services":{"telnet":{"reachable":{"status":"ok","value":false,"truncated":true}}}}`, telnetControl("auto", "pass"), ERROR, Truncated, nil},
		{"6 missing key never absent_means", `{}`, telnetControl("auto", "pass"), ERROR, MissingFact, nil},
		{"1 requires_facts unmet", `{"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`, func() controls.Control { c := telnetControl("auto", "pass"); c.RequiresFacts = ">=2"; return c }(), ERROR, MissingFact, nil},
		{"2 manual", `{}`, controls.Control{ID: "muster.log.review", Importance: "하", Category: "log", Automation: "manual", ManualReason: "interview"}, MANUAL, "", nil},
		{"4 applies_when false", `{"services":{"ssh":{"installed":{"status":"ok","value":false}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), NotApplicable, "", nil},
		{"3 applies_when denied", `{"services":{"ssh":{"installed":{"status":"denied","reason":"root"}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), ERROR, PermissionDenied, nil},
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
		{"5 mechanisms fallback", `{"files":{"etc_securetty":{"status":"ok","value":{},"lines":{"status":"ok","value":["console"]}}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty.lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			PASS, "", func(t *testing.T, r Result) {
				if r.Mechanism != 2 {
					t.Errorf("want mechanism 2 chosen, got %d", r.Mechanism)
				}
			}},
		{"5 no mechanism applies", `{"files":{"etc_securetty":{"status":"absent"}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty.lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
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

func TestEvaluateIsolatesPanics(t *testing.T) {
	customs["__panic"] = func(e *env, c *controls.Control) clauseOutcome { panic("boom") }
	defer delete(customs, "__panic")
	c := controls.Control{ID: "muster.beyond.panic", Importance: "하", Category: "beyond", Automation: "auto", AbsentMeans: "fail", Custom: "__panic", Remediation: &controls.Remediation{Risk: "none"}}
	res := Evaluate(snap(t, `{}`), one(c), reg, Options{})
	if res[0].Status != ERROR || res[0].ReasonCode != InternalError {
		t.Fatalf("%+v", res[0])
	}
}
