package remedy

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

const callStatusLine = `[ "$?" -eq 0 ] || failed=$((failed+1))`

// scriptReport is a report with fixed provenance, so the goldens move only
// when the template, a plan shape or a shipped body moves.
func scriptReport(rows ...report.Row) *report.Report {
	rep := testReport(rows...)
	rep.Run = facts.Run{Host: facts.Host{Hostname: "host-a"}, CollectedAt: "2026-10-08T00:00:00Z"}
	rep.Check = report.CheckBlock{
		ControlsVersion: "test+1", ControlsDigest: "sha256:c0",
		Profile: report.ProfileBlock{Name: "default", Digest: "sha256:p0"},
	}
	return rep
}

func mustBuild(t *testing.T, rep *report.Report, set *controls.Set, opts Options) *Plan {
	t.Helper()
	p, err := Build(rep, set, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return p
}

// fullPlan has every shape at the default cap: restore_backup, declared,
// both with validate (lockout), the text-only reasons no_script and
// params_tuned, and the three not-planned kinds.
func fullPlan(t *testing.T) *Plan {
	errRow := row("x.error", "ERROR", "fact missing", "", "high")
	errRow.ReasonCode = check.MissingFact
	rep := scriptReport(
		row("muster.test.a_none", "FAIL", "clause does not hold: files.etc_hosts.mode in [0 420]", "", "low"),
		row("muster.test.b_restart", "FAIL", "clause does not hold", "", "medium"),
		row("muster.test.c_lockout", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.d_reboot", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.e_param", "FAIL", "mode 777", "", "high"),
		row("muster.test.f_partial", "WARN", "observations need human review", "", "high"),
		errRow,
		row("x.manual", "MANUAL", "review", "", "medium"),
		row("x.degraded", "WARN", check.ReasonDegradedPrefix+"not applied", "not applied", "low"),
		row("x.pass", "PASS", "", "", "high"),
	)
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "tuning"}}
	return mustBuild(t, rep, testSet(t), Options{})
}

// cappedPlan caps at none: one scripted item and one absent item run; the
// restart, reboot and lockout items are commented out.
func cappedPlan(t *testing.T) *Plan {
	rep := scriptReport(
		row("muster.test.a_none", "FAIL", "clause does not hold", "", "low"),
		row("muster.test.b_restart", "FAIL", "clause does not hold", "", "medium"),
		row("muster.test.c_lockout", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.d_reboot", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.e_param", "FAIL", check.ReasonAbsentFailPrefix+"no /etc/group", "", "high"),
	)
	return mustBuild(t, rep, testSet(t), Options{MaxRisk: "none"})
}

func emptyPlan(t *testing.T) *Plan {
	return mustBuild(t, scriptReport(row("x.pass", "PASS", "", "", "high")), testSet(t), Options{})
}

const poison = "\x1b[31m\n# $(id) `id`"

// poisonControls carry ESC, BEL, a newline, '#' and command substitutions
// in both texts (YAML's "\e" is ESC, "\a" BEL).
var poisonControls = map[string]string{
	"muster.test.p_script": `automation: auto
remediation:
  text_en: "do \e[31m\n# $(id) ` + "`id`" + `"
  text_ko: "조치 \e[31m\n# $(id)"
  risk: lockout_risk
  idempotent: true
  script: chmod 644 /etc/hosts
  rollback: systemctl reload ssh
  backup: [/etc/hosts]
  validate: stat -c '%a' /etc/hosts
`,
	"muster.test.p_text": `automation: auto
remediation:
  text_en: "text \e]0;x\a\n$(id)"
  text_ko: "글 \n# $(id)"
  risk: none
  idempotent: true
`,
}

func setFrom(t *testing.T, ctl map[string]string) *controls.Set {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("test+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for id, body := range ctl {
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte("id: "+id+"\n"+controlHead+body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := controls.LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}
	return set
}

func poisonPlan(t *testing.T) *Plan {
	var rows []report.Row
	for _, id := range []string{"muster.test.p_script", "muster.test.p_text"} {
		r := row(id, "FAIL", "value "+poison, "", "high")
		r.TitleEn, r.TitleKo = "title "+poison, "제목 "+poison
		rows = append(rows, r)
	}
	rep := scriptReport(rows...)
	rep.Run.Host.Hostname = "host" + poison
	rep.Run.CollectedAt = "2026" + poison
	rep.Check.ControlsVersion, rep.Check.ControlsDigest = "v"+poison, "d"+poison
	rep.Check.Profile.Name, rep.Check.Profile.Digest = "p"+poison, "pd"+poison
	p := mustBuild(t, rep, setFrom(t, poisonControls), Options{})
	if len(p.Items) != 2 || !strings.ContainsRune(p.Items[0].TextEn+p.Items[1].TextEn, 0x1b) {
		t.Fatal("poison controls carry no ESC: the fixture is not poisoned")
	}
	return p
}

var importanceSeverity = map[string]string{"상": "high", "중": "medium", "하": "low"}

// allScriptedPlan is one FAIL row per shipped control that declares a
// script: the golden CI shellchecks.
func allScriptedPlan(t *testing.T) *Plan {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var rows []report.Row
	for _, c := range set.Controls {
		if c.Remediation == nil || strings.TrimSpace(c.Remediation.Script) == "" {
			continue
		}
		rows = append(rows, row(c.ID, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance]))
	}
	return mustBuild(t, scriptReport(rows...), set, Options{})
}

func lines(b []byte) []string { return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") }

func fnName(id string) string { return "fix_" + strings.ReplaceAll(id, ".", "_") }

func TestScriptGolden(t *testing.T) {
	for _, g := range []struct {
		name string
		mk   func(*testing.T) *Plan
	}{{"full", fullPlan}, {"empty", emptyPlan}, {"capped", cappedPlan}, {"poison", poisonPlan}, {"all-scripted", allScriptedPlan}} {
		t.Run(g.name, func(t *testing.T) {
			got := Script(g.mk(t))
			path := filepath.Join("testdata", g.name+".sh")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s differs from the golden; run go test ./internal/remedy -run TestScriptGolden -update and review the diff\n%s", path, got)
			}
		})
	}
}

func TestScriptBlocksAreIndependent(t *testing.T) {
	p := fullPlan(t)
	ls := lines(Script(p))
	scripted := 0
	for _, it := range p.Items {
		if !it.Planned || !it.Script {
			continue
		}
		scripted++
		fn := fnName(it.ID)
		defs, calls := 0, 0
		for i, l := range ls {
			if l == fn+"() {" {
				defs++
			}
			if l == fn {
				calls++
				if i+1 >= len(ls) || ls[i+1] != callStatusLine {
					t.Errorf("%s: the line after the call is not %q", fn, callStatusLine)
				}
			}
		}
		if defs != 1 || calls != 1 {
			t.Errorf("%s: %d definitions, %d bare calls; want 1 and 1", fn, defs, calls)
		}
	}
	if scripted != 3 {
		t.Fatalf("full plan has %d planned scripted items, want 3", scripted)
	}
	for _, l := range ls {
		if strings.HasPrefix(l, "fix_") {
			for _, bad := range []string{"||", "&&", "if ", "!"} {
				if strings.Contains(l, bad) {
					t.Errorf("call or definition line %q carries %q", l, bad)
				}
			}
		}
	}

	cl := lines(Script(cappedPlan(t)))
	headers := 0
	for i, l := range cl {
		if !strings.Contains(l, "-- above max-risk") {
			continue
		}
		headers++
		for j := i; j < len(cl) && cl[j] != ""; j++ {
			if !strings.HasPrefix(cl[j], "#") {
				t.Errorf("capped.sh line %d of a block above max-risk is not a comment: %q", j+1, cl[j])
			}
		}
	}
	if headers != 3 {
		t.Fatalf("capped plan has %d blocks above max-risk, want 3", headers)
	}
}

func TestScriptFailurePathRollbackThenRestore(t *testing.T) {
	p := fullPlan(t)
	if it := itemByID(t, p, "muster.test.c_lockout"); it.Rollback != "both" || !it.Validate {
		t.Fatalf("c_lockout is not a both+validate item: %+v", it)
	}
	ls := lines(Script(p))
	start := -1
	for i, l := range ls {
		if l == fnName("muster.test.c_lockout")+"() {" {
			start = i
		}
	}
	if start < 0 {
		t.Fatal("no c_lockout block")
	}
	branches := 0
	for i := start; i < len(ls) && ls[i] != "}"; i++ {
		if ls[i] != `  if [ "$rc" -ne 0 ]; then` {
			continue
		}
		branches++
		rb, rs := -1, -1
		for j := i + 1; j < len(ls) && ls[j] != "    return 1"; j++ {
			if ls[j] == "    ( set -e" && rb < 0 {
				rb = j
			}
			if strings.HasPrefix(ls[j], "    restore ") {
				rs = j
			}
		}
		if rb < 0 || rs < 0 || rb > rs {
			t.Errorf("failure branch at line %d: rollback subshell at %d, restore at %d; want both, rollback first", i+1, rb, rs)
		}
	}
	if branches != 2 {
		t.Fatalf("c_lockout has %d failure branches, want 2 (script and validate)", branches)
	}
}

// templateLines is every non-comment line the generator may write for p:
// the fixed prologue and epilogue, the structural lines of each item, and
// the item's declared bodies at the indent the template gives them.
func templateLines(p *Plan) map[string]bool {
	ok := map[string]bool{"": true}
	for _, l := range strings.Split(prologue+epilogue, "\n") {
		ok[l] = true
	}
	for _, it := range p.Items {
		id, fn, bk := it.ID, fnName(it.ID), strings.Join(it.Backup, " ")
		for _, l := range []string{
			fn + "() {", fn, callStatusLine, "}",
			"  backup " + bk + ` || { log "` + id + `: backup failed, nothing changed"; return 1; }`,
			"  ( set -e", "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`, "    return 1", "  fi",
			`    log "` + id + `: script failed (rc $rc), rolling back"`,
			`    log "` + id + `: validate failed, rolling back"`,
			"    ( set -e", "    ); rrc=$?",
			`    [ "$rrc" -eq 0 ] || log "` + id + `: rollback failed (rc $rrc)"`,
			"    restore " + bk + ` || log "` + id + `: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`,
			`  log "` + id + `: done"`,
			"    " + it.ValidateCmd,
		} {
			ok[l] = true
		}
		for _, l := range strings.Split(it.ScriptBody, "\n") {
			ok["    "+l] = true
		}
		for _, l := range strings.Split(it.RollbackBody, "\n") {
			ok["      "+l] = true
		}
	}
	return ok
}

func TestScriptEveryLineIsTemplateBodyOrComment(t *testing.T) {
	for _, g := range []struct {
		name string
		mk   func(*testing.T) *Plan
	}{{"poison", poisonPlan}, {"full", fullPlan}, {"capped", cappedPlan}} {
		p := g.mk(t)
		out := Script(p)
		if bytes.IndexByte(out, 0x1b) >= 0 || bytes.IndexByte(out, '\a') >= 0 || bytes.IndexByte(out, '\r') >= 0 {
			t.Errorf("%s: a raw control byte reached the script", g.name)
		}
		ok := templateLines(p)
		for i, l := range lines(out) {
			if strings.HasPrefix(l, "#") {
				continue
			}
			if !ok[l] {
				t.Errorf("%s line %d is neither template, body nor comment: %q", g.name, i+1, l)
			}
			if strings.Contains(l, "$(id)") || strings.Contains(l, "`id`") {
				t.Errorf("%s line %d carries a derived command outside a comment: %q", g.name, i+1, l)
			}
		}
	}
}

func TestScriptIsDeterministic(t *testing.T) {
	a, b := Script(fullPlan(t)), Script(fullPlan(t))
	if !bytes.Equal(a, b) {
		t.Fatal("two renders of the same plan differ")
	}
}

func TestScriptAllScriptedCoversTheShippedSet(t *testing.T) {
	p := allScriptedPlan(t)
	if len(p.Items) != 16 || p.Summary.WithScript != 16 {
		t.Fatalf("all-scripted plan: %d items, %d with script; want 16 and 16", len(p.Items), p.Summary.WithScript)
	}
	defs := 0
	for _, l := range lines(Script(p)) {
		if strings.HasPrefix(l, "fix_") && strings.HasSuffix(l, "() {") {
			defs++
		}
	}
	if defs != 16 {
		t.Fatalf("all-scripted.sh defines %d functions, want 16", defs)
	}
}

// runScript writes the script for p, minus the root check, and runs sh on
// it with MUSTER_BACKUP set; it returns stdout+stderr and the exit code.
func runScript(t *testing.T, p *Plan, dir, backupDir string) (string, int) {
	t.Helper()
	src := string(Script(p))
	// The test's one transformation: drop the root check so sh runs it as
	// any user; the bodies act only inside t.TempDir().
	trimmed := strings.Replace(src, rootCheckLine+"\n", "", 1)
	if trimmed == src {
		t.Fatal("the script carries no root-check line")
	}
	path := filepath.Join(dir, "fix.sh")
	if err := os.WriteFile(path, []byte(trimmed), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", path)
	cmd.Env = append(os.Environ(), "MUSTER_BACKUP="+backupDir)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		t.Fatalf("sh: %v", err)
		return "", -1
	}
}

func needSh(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("runs the script with sh: Linux only")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScriptBodyFailureReachesTheFailurePath(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	f := filepath.Join(tmp, "f")
	if err := os.WriteFile(f, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.body_failure", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "both", Backup: []string{f},
		ScriptBody:   "printf changed > " + f + "\nfalse\nprintf ran > " + filepath.Join(tmp, "after"),
		RollbackBody: "printf rb > " + filepath.Join(tmp, "rb"),
	}}}
	out, code := runScript(t, p, tmp, filepath.Join(tmp, "bk"))
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(tmp, "after")); !os.IsNotExist(err) {
		t.Errorf("the body ran past its failing command (after: %v)\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(tmp, "rb")); err != nil {
		t.Errorf("the declared rollback did not run: %v\n%s", err, out)
	}
	if got := readFile(t, f); got != "original" {
		t.Errorf("f is %q after restore, want the original\n%s", got, out)
	}
}

func TestScriptReusedBackupKeepsTheFirstCopy(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	f := filepath.Join(tmp, "f")
	if err := os.WriteFile(f, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.reused", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "restore_backup", Backup: []string{f},
		ScriptBody: "printf two > " + f, Validate: true, ValidateCmd: "false",
	}}}
	bk := filepath.Join(tmp, "bk")
	out, code := runScript(t, p, tmp, bk)
	if got := readFile(t, f); code != 1 || got != "original" {
		t.Fatalf("first run: exit %d, f %q; want 1 and the original\n%s", code, got, out)
	}
	if err := os.WriteFile(f, []byte("edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code = runScript(t, p, tmp, bk)
	if code != 1 {
		t.Fatalf("second run: exit %d, want 1\n%s", code, out)
	}
	if got := readFile(t, f); got != "original" {
		t.Errorf("second run restored %q, want the first copy (the original)\n%s", got, out)
	}
	if !strings.Contains(out, "backup exists, keeping the first") {
		t.Errorf("second run did not say it kept the first copy:\n%s", out)
	}
}
