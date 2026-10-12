package remedy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

func build(t *testing.T, rep *report.Report, opts Options) *Plan {
	t.Helper()
	p, err := Build(rep, testSet(t), opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return p
}

func itemByID(t *testing.T, p *Plan, id string) Item {
	t.Helper()
	for _, it := range p.Items {
		if it.ID == id {
			return it
		}
	}
	t.Fatalf("no item %s in %+v", id, p.Items)
	return Item{}
}

func TestPlanOrdersByRiskSeverityID(t *testing.T) {
	rep := testReport(
		row("muster.test.c_lockout", "FAIL", "r", "", "high"),
		row("muster.test.a_none", "FAIL", "r", "", "low"),
		row("muster.test.f_partial", "WARN", "observations need human review", "", "high"),
		row("muster.test.e_param", "FAIL", "r", "", "high"),
		row("muster.test.b_restart", "FAIL", "r", "", "medium"),
	)
	p := build(t, rep, Options{})
	type key struct{ id, risk, severity string }
	want := []key{
		{"muster.test.e_param", "none", "high"},
		{"muster.test.f_partial", "none", "high"},
		{"muster.test.a_none", "none", "low"},
		{"muster.test.b_restart", "restart_service", "medium"},
		{"muster.test.c_lockout", "lockout_risk", "high"},
	}
	var got []key
	for _, it := range p.Items {
		got = append(got, key{it.ID, it.Risk, it.Severity})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order:\n got %v\nwant %v", got, want)
	}
}

func TestPlanClassifiesEveryRow(t *testing.T) {
	errRow := row("x1", "ERROR", "fact missing", "", "high")
	errRow.ReasonCode = check.MissingFact
	rep := testReport(
		row("p1", "PASS", "", "", "high"),
		row("n1", "NOT_APPLICABLE", "gated", "", "low"),
		row("w1", "WAIVED", "waived", "", "medium"),
		errRow,
		row("m1", "MANUAL", "review", "", "medium"),
		row("muster.test.a_none", "WARN", check.ReasonDegradedPrefix+"not applied", "not applied", "high"),
		row("muster.test.b_restart", "FAIL", "value is 1; "+check.ReasonDegradedPrefix+"x", "x", "high"),
		row("muster.test.c_lockout", "FAIL", check.ReasonAbsentFailPrefix+"no file", "", "high"),
		row("muster.test.e_param", "FAIL", "mode 777", "", "high"),
		row("muster.test.d_reboot", "FAIL", "bad", "", "high"),
	)
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "tuning"}}
	p := build(t, rep, Options{})

	wantNP := []NotPlanned{
		{ID: "m1", Status: "manual", Reason: "review"},
		{ID: "muster.test.a_none", Status: "warn_degraded", Reason: check.ReasonDegradedPrefix + "not applied"},
		{ID: "x1", Status: "error", Reason: "[missing_fact] fact missing"},
	}
	if !reflect.DeepEqual(p.NotPlanned, wantNP) {
		t.Fatalf("not_planned:\n got %+v\nwant %+v", p.NotPlanned, wantNP)
	}
	type cls struct {
		id, status, textOnly string
		script               bool
	}
	want := map[string]cls{
		"muster.test.b_restart": {"muster.test.b_restart", "fail", "", true},
		"muster.test.c_lockout": {"muster.test.c_lockout", "fail", "absent", false},
		"muster.test.e_param":   {"muster.test.e_param", "fail", "params_tuned", false},
		"muster.test.d_reboot":  {"muster.test.d_reboot", "fail", "no_script", false},
	}
	if len(p.Items) != len(want) {
		t.Fatalf("items: got %d, want %d: %+v", len(p.Items), len(want), p.Items)
	}
	for id, w := range want {
		it := itemByID(t, p, id)
		got := cls{it.ID, it.Status, it.TextOnlyReason, it.Script}
		if got != w {
			t.Errorf("%s: got %+v, want %+v", id, got, w)
		}
	}
	if b := itemByID(t, p, "muster.test.b_restart"); b.Reason != "value is 1; "+check.ReasonDegradedPrefix+"x" || b.SourceStatus != check.FAIL {
		t.Errorf("b_restart reason/source status: %q %q", b.Reason, b.SourceStatus)
	}
	s := p.Summary
	wantS := Summary{
		Planned: 4, WithScript: 1, TextOnly: 3, Waived: 1, Clean: 2,
		NotPlanned: NotPlannedCounts{Error: 1, Manual: 1, WarnDegraded: 1},
		ByRisk:     RiskCounts{None: 1, RestartService: 1, RebootRequired: 1, LockoutRisk: 1},
	}
	if s != wantS {
		t.Fatalf("summary:\n got %+v\nwant %+v", s, wantS)
	}
	if n := len(p.Items) + len(p.NotPlanned) + s.Waived + s.Clean; n != len(rep.Results) {
		t.Fatalf("partition sums to %d, want %d", n, len(rep.Results))
	}
}

func TestPlanMarksItemsAboveMaxRisk(t *testing.T) {
	rep := testReport(
		row("muster.test.c_lockout", "FAIL", "r", "", "high"),
		row("muster.test.a_none", "FAIL", "r", "", "high"),
		row("muster.test.b_restart", "FAIL", "r", "", "high"),
	)
	p := build(t, rep, Options{MaxRisk: "restart_service"})
	if p.Fix.MaxRisk != "restart_service" {
		t.Errorf("max_risk %q", p.Fix.MaxRisk)
	}
	c := itemByID(t, p, "muster.test.c_lockout")
	if c.Planned || c.Status != "fail" || !c.Script {
		t.Errorf("lockout item: planned %v status %q script %v", c.Planned, c.Status, c.Script)
	}
	for _, id := range []string{"muster.test.a_none", "muster.test.b_restart"} {
		if !itemByID(t, p, id).Planned {
			t.Errorf("%s not planned", id)
		}
	}
	wantS := Summary{Planned: 2, AboveMaxRisk: 1, WithScript: 2,
		ByRisk: RiskCounts{None: 1, RestartService: 1, LockoutRisk: 1}}
	if p.Summary != wantS {
		t.Fatalf("summary:\n got %+v\nwant %+v", p.Summary, wantS)
	}
	if d := build(t, rep, Options{}); d.Fix.MaxRisk != "lockout_risk" || d.Summary.AboveMaxRisk != 0 || d.Summary.Planned != 3 {
		t.Errorf("default max risk: %q above %d planned %d", d.Fix.MaxRisk, d.Summary.AboveMaxRisk, d.Summary.Planned)
	}
}

func TestPlanRollbackVocabulary(t *testing.T) {
	rep := testReport(
		row("muster.test.a_none", "FAIL", "r", "", "high"),
		row("muster.test.b_restart", "FAIL", "r", "", "high"),
		row("muster.test.c_lockout", "FAIL", "r", "", "high"),
		row("muster.test.d_reboot", "FAIL", "r", "", "high"),
		row("muster.test.e_param", "FAIL", "r", "", "high"),
	)
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "default"}}
	p := build(t, rep, Options{})
	type rb struct {
		rollback string
		backup   []string
		script   bool
		validate bool
	}
	want := map[string]rb{
		"muster.test.a_none":    {"restore_backup", []string{"/etc/hosts"}, true, false},
		"muster.test.b_restart": {"declared", []string{}, true, false},
		"muster.test.c_lockout": {"both", []string{"/etc/ssh/sshd_config"}, true, true},
		"muster.test.d_reboot":  {"none", []string{}, false, false},
		"muster.test.e_param":   {"restore_backup", []string{"/etc/group"}, true, false},
	}
	for id, w := range want {
		it := itemByID(t, p, id)
		got := rb{it.Rollback, it.Backup, it.Script, it.Validate}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s: got %+v, want %+v", id, got, w)
		}
		if it.Backup == nil {
			t.Errorf("%s: backup is nil", id)
		}
	}
	c := itemByID(t, p, "muster.test.c_lockout")
	if c.ScriptBody != "sed -i s/a/b/ /etc/ssh/sshd_config" || c.ValidateCmd != "sshd -t" || c.RollbackBody != "systemctl reload ssh" {
		t.Errorf("c_lockout bodies: %q %q %q", c.ScriptBody, c.ValidateCmd, c.RollbackBody)
	}
	if c.TextEn != "fix c" || c.TextKo != "조치 c" || !c.Idempotent {
		t.Errorf("c_lockout texts: %q %q %v", c.TextEn, c.TextKo, c.Idempotent)
	}
	d := itemByID(t, p, "muster.test.d_reboot")
	if d.ScriptBody != "" || d.RollbackBody != "" || d.ValidateCmd != "" || d.Risk != "reboot_required" {
		t.Errorf("d_reboot: %+v", d)
	}
}

func TestPlanRejectsUnknownMaxRisk(t *testing.T) {
	p, err := Build(testReport(), testSet(t), Options{MaxRisk: "high"})
	if err == nil || p != nil {
		t.Fatalf("got plan %v err %v", p, err)
	}
	for _, w := range []string{"none", "restart_service", "reboot_required", "lockout_risk", `"high"`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not name %s", err, w)
		}
	}
}

// Z-26: an id outside the control-id grammar would reach the script's
// command lines; Build refuses it, naming the id, for FAIL and WARN alike.
func TestPlanRefusesAnUnexpectedID(t *testing.T) {
	for _, bad := range []string{"muster.test.x\nPWN #", "muster.test.$(id)", "x1", "Muster.test.a"} {
		for _, status := range []string{"FAIL", "WARN"} {
			p, err := Build(testReport(row(bad, status, "r", "", "high")), testSet(t), Options{})
			if err == nil || p != nil {
				t.Fatalf("%q (%s): got plan %v err %v", bad, status, p, err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", bad)) {
				t.Errorf("error %q does not name %q", err, bad)
			}
		}
	}
	// Rows the plan does not act on are not items: their ids never reach a
	// command line, so they are not refused.
	if _, err := Build(testReport(row("x1", "MANUAL", "r", "", "high"), row("p2", "PASS", "", "", "low")), testSet(t), Options{}); err != nil {
		t.Fatalf("a non-item row was refused: %v", err)
	}
}

func TestPlanEmpty(t *testing.T) {
	p := build(t, testReport(row("muster.test.a_none", "PASS", "", "", "high"), row("p2", "PASS", "", "", "low")), Options{})
	if p.Items == nil || len(p.Items) != 0 {
		t.Errorf("items %#v", p.Items)
	}
	if p.NotPlanned == nil || len(p.NotPlanned) != 0 {
		t.Errorf("not_planned %#v", p.NotPlanned)
	}
	if want := (Summary{Clean: 2}); p.Summary != want {
		t.Errorf("summary %+v", p.Summary)
	}
}

func TestPlanHasNoMap(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(t2 reflect.Type, path string)
	walk = func(t2 reflect.Type, path string) {
		if seen[t2] {
			return
		}
		seen[t2] = true
		switch t2.Kind() {
		case reflect.Map:
			t.Errorf("%s is a map (%s)", path, t2)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t2.Elem(), path+"[]")
		case reflect.Struct:
			for i := 0; i < t2.NumField(); i++ {
				f := t2.Field(i)
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(reflect.TypeOf(Plan{}), "Plan")
	if !seen[reflect.TypeOf(facts.Run{})] || !seen[reflect.TypeOf(Item{})] {
		t.Fatal("walk did not reach Run and Item")
	}
}

func TestPlanCopiesProvenance(t *testing.T) {
	rep := testReport(row("p1", "PASS", "", "", "high"))
	rep.Run = facts.Run{MusterVersion: "snap-v", Commit: "snapc", Host: facts.Host{Hostname: "h1"}, CollectedAt: "2026-10-08T00:00:00Z"}
	rep.Check = report.CheckBlock{
		MusterVersion: "mv", Commit: "abc", ControlsVersion: "cv", ControlsDigest: "sha256:cd",
		SnapshotDigest: "sha256:sd", GuideEdition: "2026",
		Profile: report.ProfileBlock{Name: "default", Source: "built-in", Digest: "sha256:pd", Extends: []string{}, Selected: 3, Excluded: 1, ExcludedIDs: []string{"z"}},
		Tuning:  &report.TuningBlock{Path: "/etc/t.yaml", Digest: "sha256:td"},
		Waivers: report.WaiversBlock{Path: "/w.yaml", Digest: "sha256:wd", Applied: 2, NotApplied: 1},
	}
	p := build(t, rep, Options{MaxRisk: "none"})
	want := FixBlock{
		MusterVersion: "mv", Commit: "abc", ControlsVersion: "cv", ControlsDigest: "sha256:cd",
		SnapshotDigest: "sha256:sd", GuideEdition: "2026", Profile: rep.Check.Profile,
		Tuning: rep.Check.Tuning, Waivers: rep.Check.Waivers, MaxRisk: "none",
	}
	if !reflect.DeepEqual(p.Fix, want) {
		t.Fatalf("fix block:\n got %+v\nwant %+v", p.Fix, want)
	}
	if !reflect.DeepEqual(p.Run, rep.Run) {
		t.Fatalf("run: got %+v", p.Run)
	}
	if p.SchemaVersion != PlanSchemaVersion || PlanSchemaVersion != 1 {
		t.Fatalf("schema version %d", p.SchemaVersion)
	}
}

// A parameter in force from a profile is tuned as much as one from a tuning
// file: the declared script assumes the defaults (review I-1).
func TestPlanTunedByProfile(t *testing.T) {
	rep := testReport(row("muster.test.e_param", "FAIL", "mode 777", "", "high"))
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "profile"}}
	it := itemByID(t, build(t, rep, Options{}), "muster.test.e_param")
	if it.TextOnlyReason != "params_tuned" || it.Script || it.ScriptBody != "" {
		t.Fatalf("profile-tuned item: text_only_reason %q script %v body %q", it.TextOnlyReason, it.Script, it.ScriptBody)
	}
}

// absent is judged before params_tuned (review M-1).
func TestPlanAbsentBeforeTuned(t *testing.T) {
	rep := testReport(row("muster.test.e_param", "FAIL", check.ReasonAbsentFailPrefix+"no file", "", "high"))
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "tuning"}}
	if it := itemByID(t, build(t, rep, Options{}), "muster.test.e_param"); it.TextOnlyReason != "absent" {
		t.Fatalf("text_only_reason %q, want absent", it.TextOnlyReason)
	}
}

// Only a WARN whose Degraded is set and whose whole reason is the degraded
// prefix plus it is a degraded pass; either half missing keeps the item
// (review M-2).
func TestPlanDegradedGuardNeedsBothHalves(t *testing.T) {
	rep := testReport(
		row("muster.test.a_none", "WARN", check.ReasonDegradedPrefix, "", "high"),
		row("muster.test.b_restart", "FAIL", check.ReasonDegradedPrefix+"x", "x", "high"),
	)
	p := build(t, rep, Options{})
	if len(p.NotPlanned) != 0 || p.Summary.NotPlanned != (NotPlannedCounts{}) {
		t.Fatalf("not_planned %+v counts %+v", p.NotPlanned, p.Summary.NotPlanned)
	}
	if a := itemByID(t, p, "muster.test.a_none"); a.Status != "warn" {
		t.Errorf("a_none status %q", a.Status)
	}
	if b := itemByID(t, p, "muster.test.b_restart"); b.Status != "fail" {
		t.Errorf("b_restart status %q", b.Status)
	}
}

// The absent test reads the bare reason (Z-6), while the item's reason is
// the reason line, code included (review M-3).
func TestPlanAbsentWithReasonCode(t *testing.T) {
	r := row("muster.test.c_lockout", "FAIL", check.ReasonAbsentFailPrefix+"no file", "", "high")
	r.ReasonCode = check.Truncated
	it := itemByID(t, build(t, testReport(r), Options{}), "muster.test.c_lockout")
	if it.TextOnlyReason != "absent" || it.Script {
		t.Errorf("text_only_reason %q script %v, want absent and no script", it.TextOnlyReason, it.Script)
	}
	if want := "[truncated] absent counts as fail: no file"; it.Reason != want || it.Reason != report.ReasonLine(r) {
		t.Errorf("reason %q, want %q", it.Reason, want)
	}
}

// Every field of a scripted item, the script-only ones included (review M-4).
func TestPlanItemCopiesEveryField(t *testing.T) {
	r := row("muster.test.c_lockout", "FAIL", "PermitRootLogin yes", "", "low")
	r.SeveritySource = "profile"
	it := itemByID(t, build(t, testReport(r), Options{}), "muster.test.c_lockout")
	want := Item{
		ID: "muster.test.c_lockout", TitleEn: "muster.test.c_lockout en", TitleKo: "muster.test.c_lockout ko",
		Status: "fail", Severity: "low", SeveritySource: "profile", Risk: "lockout_risk", Idempotent: true,
		Automation: "auto", Reason: "PermitRootLogin yes", TextEn: "fix c", TextKo: "조치 c", Script: true,
		TextOnlyReason: "", Rollback: "both", Backup: []string{"/etc/ssh/sshd_config"}, Validate: true, Planned: true,
		SourceStatus: check.FAIL, ScriptBody: "sed -i s/a/b/ /etc/ssh/sshd_config", ValidateCmd: "sshd -t",
		RollbackBody: "systemctl reload ssh",
	}
	if !reflect.DeepEqual(it, want) {
		t.Fatalf("item:\n got %+v\nwant %+v", it, want)
	}
}

// A row whose control the set does not carry is a text-only item of risk
// none, so it is planned under every cap; a text-only item whose risk is
// above the cap is not (review M-5).
func TestPlanItemWithoutRemediationIsPlanned(t *testing.T) {
	rep := testReport(
		row("muster.test.zz_unknown", "FAIL", "r", "", "high"),
		row("muster.test.d_reboot", "FAIL", "r", "", "high"),
	)
	for _, maxRisk := range []string{"none", ""} {
		p := build(t, rep, Options{MaxRisk: maxRisk})
		z := itemByID(t, p, "muster.test.zz_unknown")
		if z.Risk != "none" || z.TextOnlyReason != "no_script" || !z.Planned || z.Rollback != "none" || z.Script {
			t.Errorf("max-risk %q: unknown item %+v", maxRisk, z)
		}
		d := itemByID(t, p, "muster.test.d_reboot")
		if wantPlanned := maxRisk == ""; d.Planned != wantPlanned || d.TextOnlyReason != "no_script" {
			t.Errorf("max-risk %q: d_reboot planned %v (want %v) text_only_reason %q", maxRisk, d.Planned, wantPlanned, d.TextOnlyReason)
		}
	}
}

// The plan's JSON carries no script body field, and a text-only item's
// backup and the empty lists are [] (review N-2).
func TestPlanJSONShape(t *testing.T) {
	rep := testReport(
		row("muster.test.c_lockout", "FAIL", "r", "", "high"),
		row("muster.test.d_reboot", "FAIL", "r", "", "high"),
	)
	data, err := json.Marshal(build(t, rep, Options{}))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Items      []map[string]json.RawMessage `json:"items"`
		NotPlanned json.RawMessage              `json:"not_planned"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.NotPlanned) != "[]" {
		t.Errorf("not_planned %s, want []", got.NotPlanned)
	}
	if len(got.Items) != 2 {
		t.Fatalf("items: %d", len(got.Items))
	}
	for _, it := range got.Items {
		for _, k := range []string{"SourceStatus", "ScriptBody", "ValidateCmd", "RollbackBody", "source_status", "script_body", "validate_cmd", "rollback_body"} {
			if _, ok := it[k]; ok {
				t.Errorf("item %s carries %s", it["id"], k)
			}
		}
	}
	// reboot_required sorts before lockout_risk.
	if id := string(got.Items[0]["id"]); id != `"muster.test.d_reboot"` {
		t.Fatalf("first item %s", id)
	}
	if b := string(got.Items[0]["backup"]); b != "[]" {
		t.Errorf("text-only backup %s, want []", b)
	}
	empty, err := json.Marshal(build(t, testReport(row("p1", "PASS", "", "", "high")), Options{}))
	if err != nil {
		t.Fatal(err)
	}
	var e struct {
		Items      json.RawMessage `json:"items"`
		NotPlanned json.RawMessage `json:"not_planned"`
	}
	if err := json.Unmarshal(empty, &e); err != nil {
		t.Fatal(err)
	}
	if string(e.Items) != "[]" || string(e.NotPlanned) != "[]" {
		t.Errorf("empty plan items %s not_planned %s", e.Items, e.NotPlanned)
	}
}
