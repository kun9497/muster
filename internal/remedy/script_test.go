package remedy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
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
		// report.Build turns nil profile lists into [] (report.go); the
		// fixture carries the shape the command emits.
		Profile: report.ProfileBlock{Name: "default", Digest: "sha256:p0", Extends: []string{}, ExcludedIDs: []string{}},
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
	partial := row("muster.test.f_partial", "WARN", "observations need human review", "", "high")
	partial.Automation = "partial" // as its control declares
	rep := scriptReport(
		row("muster.test.a_none", "FAIL", "clause does not hold: files.etc_hosts.mode in [0 420]", "", "low"),
		row("muster.test.b_restart", "FAIL", "clause does not hold", "", "medium"),
		row("muster.test.c_lockout", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.g_units", "FAIL", "clause does not hold", "", "medium"),
		row("muster.test.d_reboot", "FAIL", "clause does not hold", "", "high"),
		row("muster.test.e_param", "FAIL", "mode 777", "", "high"),
		partial,
		errRow,
		row("x.manual", "MANUAL", "review", "", "medium"),
		row("x.degraded", "WARN", check.ReasonDegradedPrefix+"not applied", "not applied", "low"),
		row("x.pass", "PASS", "", "", "high"),
	)
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.e_param": {"mode": "tuning"}}
	sum := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	rep.Run.Host.MachineIDHash = hex.EncodeToString(sum[:]) // T-8: the guard-on prologue
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

// poisonHash is 64 characters but not 64 hex: Build must leave the guard off.
var poisonHash = "'; id; '" + strings.Repeat("a", 56)

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
	// Not-planned rows carry snapshot text too: an ERROR and a degraded WARN.
	errRow := row("muster.test.p_error", "ERROR", "value "+poison, "", "high")
	errRow.ReasonCode = check.MissingFact
	rows = append(rows, errRow,
		row("muster.test.p_degraded", "WARN", check.ReasonDegradedPrefix+poison, poison, "low"))
	rep := scriptReport(rows...)
	rep.Run.Host.Hostname = "host" + poison
	rep.Run.CollectedAt = "2026" + poison
	rep.Check.ControlsVersion, rep.Check.ControlsDigest = "v"+poison, "d"+poison
	rep.Check.Profile.Name, rep.Check.Profile.Digest = "p"+poison, "pd"+poison
	rep.Run.Host.MachineIDHash = poisonHash
	p := mustBuild(t, rep, setFrom(t, poisonControls), Options{})
	if p.Fix.HostGuard != "off" {
		t.Fatalf("a malformed machine-id hash set the guard %q, want off", p.Fix.HostGuard)
	}
	if len(p.Items) != 2 || !strings.ContainsRune(p.Items[0].TextEn+p.Items[1].TextEn, 0x1b) {
		t.Fatal("poison controls carry no ESC: the fixture is not poisoned")
	}
	if len(p.NotPlanned) != 2 {
		t.Fatalf("poison not-planned rows = %d, want 2 (error, warn_degraded)", len(p.NotPlanned))
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
	if scripted != 4 {
		t.Fatalf("full plan has %d planned scripted items, want 4", scripted)
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
	for _, l := range strings.Split(prologue(p)+epilogue, "\n") {
		ok[l] = true
	}
	for _, it := range p.Items {
		id, fn, bk := it.ID, fnName(it.ID), strings.Join(it.Backup, " ")
		if len(it.Units) > 0 {
			us := strings.Join(it.Units, " ")
			ok["  save_units "+us+` || { log "`+id+`: backup failed, nothing changed"; return 1; }`] = true
			ok["    UNITS='"+us+"'"] = true
			ok["    restore_units "+us+` || log "`+id+`: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`] = true
		}
		if it.Validate {
			ok["  # validate"] = true
		}
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
			// D34 amended: the one snapshot value on a command line is the
			// machine-id hash, as 64 hex on the MUSTER_SNAPSHOT_HOST= line.
			if hex64.MatchString(l) && (p.Fix.MachineIDHash == "" || l != "MUSTER_SNAPSHOT_HOST="+p.Fix.MachineIDHash) {
				t.Errorf("%s line %d carries a 64-hex run off the MUSTER_SNAPSHOT_HOST= line: %q", g.name, i+1, l)
			}
			if strings.Contains(l, poisonHash) {
				t.Errorf("%s line %d carries the malformed hash: %q", g.name, i+1, l)
			}
		}
	}
	if !strings.Contains(string(Script(fullPlan(t))), "\nMUSTER_SNAPSHOT_HOST="+fullPlan(t).Fix.MachineIDHash+"\n") {
		t.Error("full: no MUSTER_SNAPSHOT_HOST= line carrying the plan's hash")
	}
}

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

// M-2: above the cap a blank body line is "#" alone (no trailing space), so
// the commented block has no empty line and nothing after it runs; planned,
// the same blank line stays empty.
func TestScriptBlankBodyLineAboveTheCapIsAHash(t *testing.T) {
	it := Item{ID: "muster.test.blank", Status: "fail", Severity: "high", Risk: "lockout_risk",
		Reason: "r", TextEn: "e", TextKo: "k", Script: true, Rollback: "declared", ScriptBody: "true\n\nfalse", RollbackBody: "true\n\ntrue"}
	p := &Plan{Fix: FixBlock{MaxRisk: "none"}, Items: []Item{it}}
	ls := lines(Script(p))
	start := -1
	for i, l := range ls {
		if strings.HasPrefix(l, "# ---- 1/1 muster.test.blank") {
			start = i
		}
	}
	if start < 0 || !strings.HasSuffix(ls[start], "-- above max-risk none, NOT RUN") {
		t.Fatalf("no above-cap header for the blank-line item")
	}
	hashes, reachedEnd := 0, false
	for i := start; i < len(ls) && ls[i] != ""; i++ {
		if ls[i] == "#" {
			hashes++
		}
		if !strings.HasPrefix(ls[i], "#") || strings.HasSuffix(ls[i], " ") {
			t.Errorf("line %d of the commented block: %q", i+1, ls[i])
		}
		reachedEnd = reachedEnd || ls[i] == "# "+callStatusLine
	}
	if hashes != 2 || !reachedEnd {
		t.Fatalf("commented block: %d blank-body \"#\" lines, reached its last line %v; want 2 and true", hashes, reachedEnd)
	}

	p.Items[0].Planned = true
	p.Fix.MaxRisk = "lockout_risk"
	planned := string(Script(p))
	if !strings.Contains(planned, "    true\n\n    false\n") || strings.Contains(planned, "\n#\n") {
		t.Errorf("a planned blank body line is not left empty:\n%s", planned)
	}
}

// N-1: the block header escapes the id. Build refuses such an id, so the plan
// is built by hand; the header line carries the escaped spelling and no raw
// newline or ESC byte.
func TestScriptHeaderEscapesTheID(t *testing.T) {
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.a\nb\x1bc", Status: "fail", Severity: "high", Risk: "none",
		Planned: true, TextOnlyReason: "no_script",
	}}}
	const want = `# ---- 1/1 muster.test.a\nb\x1bc [risk none] [fail, high]`
	var header string
	for _, l := range lines(Script(p)) {
		if strings.HasPrefix(l, "# ---- 1/1 ") {
			header = l
		}
	}
	if header != want {
		t.Errorf("header line %q, want %q", header, want)
	}
	if strings.ContainsAny(header, "\n\x1b") {
		t.Errorf("header line carries a raw byte: %q", header)
	}
}

func TestScriptIsDeterministic(t *testing.T) {
	a, b := Script(fullPlan(t)), Script(fullPlan(t))
	if !bytes.Equal(a, b) {
		t.Fatal("two renders of the same plan differ")
	}
}

func TestScriptGuardOffWithoutAHash(t *testing.T) {
	s := string(Script(emptyPlan(t)))
	if !strings.Contains(s, "\n# host guard: off (the snapshot has no machine id)\n") || strings.Contains(s, "muster_machine_id_hash") || strings.Contains(s, "MUSTER_SNAPSHOT_HOST") {
		t.Fatalf("guard-off prologue wrong:\n%s", s)
	}
}

func TestScriptPrologueOrder(t *testing.T) {
	s := string(Script(fullPlan(t)))
	order := []string{"set -u\n", "umask 077\n", "log() {", "muster_machine_id_hash() {", rootCheckLine, "MUSTER_SNAPSHOT_HOST=", `MUSTER_BACKUP="${MUSTER_BACKUP:-`, `mkdir -p "$MUSTER_BACKUP" || exit 2`, backupOwnerLine, "backup() {", "restore() {", "save_units() {", "restore_units() {", "failed=0\n"}
	at := 0
	for _, o := range order {
		i := strings.Index(s[at:], o)
		if i < 0 {
			t.Fatalf("prologue: %q missing or out of order", o)
		}
		at += i + len(o)
	}
}

func TestScriptUnitsBlockOrder(t *testing.T) {
	ls := lines(Script(fullPlan(t)))
	fn := fnName("muster.test.g_units")
	in, saw := false, map[string]int{}
	for i, l := range ls {
		if l == fn+"() {" {
			in = true
		}
		if !in {
			continue
		}
		switch {
		case strings.HasPrefix(l, "  save_units g.socket g.service || "):
			saw["save"] = i
		case l == "    UNITS='g.socket g.service'":
			if ls[i-1] != "  ( set -e" {
				t.Errorf("UNITS= not the first body line: after %q", ls[i-1])
			}
			saw["units"] = i
		case strings.HasPrefix(l, "    restore_units g.socket g.service || log "):
			saw["restore"]++
		case l == "  # validate":
			if ls[i+1] != "  ( set -e" {
				t.Errorf("# validate not before the validate subshell")
			}
			saw["marker"] = i
		case l == "}":
			in = false
		}
	}
	if saw["save"] == 0 || saw["units"] <= saw["save"] || saw["restore"] != 2 || saw["marker"] == 0 {
		t.Fatalf("units block shape: %v", saw)
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
	out, _, code := runScriptStreams(t, p, dir, backupDir)
	return out, code
}

// runScriptStreams is runScript with stderr also returned on its own. The
// working directory is dir, so a relative MUSTER_BACKUP stays inside it.
func runScriptStreams(t *testing.T, p *Plan, dir, backupDir string) (string, string, int) {
	t.Helper()
	return runScriptWith(t, p, dir, backupDir, runOpts{})
}

// runOpts are runScriptWith's extra transformations (T-7).
type runOpts struct {
	replace    [][2]string // applied to the rendered script, each must change it
	pathPrefix string      // prepended to PATH
	env        []string
}

// runScriptWith is runScriptStreams with the script's text rewritten, a
// directory put first on PATH and variables added to the environment. The
// inherited environment never carries MUSTER_ANY_HOST.
func runScriptWith(t *testing.T, p *Plan, dir, backupDir string, o runOpts) (all, stderr string, code int) {
	t.Helper()
	src := string(Script(p))
	for _, r := range o.replace {
		next := strings.Replace(src, r[0], r[1], 1)
		if next == src {
			t.Fatalf("the script carries no %q to replace", r[0])
		}
		src = next
	}
	// The test's transformations: drop the root check so sh runs it as any
	// user (the bodies act only inside t.TempDir()), and, unless the test
	// runs as root, the backup-owner check, which a non-root user's temp dir
	// never passes.
	trimmed := strings.Replace(src, rootCheckLine+"\n", "", 1)
	if trimmed == src {
		t.Fatal("the script carries no root-check line")
	}
	if !strings.Contains(trimmed, "\n"+backupOwnerLine+"\n") {
		t.Fatal("the script carries no backup-owner line")
	}
	if os.Geteuid() != 0 {
		trimmed = strings.Replace(trimmed, backupOwnerLine+"\n", "", 1)
	}
	path := filepath.Join(dir, "fix.sh")
	if err := os.WriteFile(path, []byte(trimmed), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", path)
	cmd.Dir = dir
	var env []string
	for _, e := range os.Environ() {
		switch {
		case strings.HasPrefix(e, "MUSTER_ANY_HOST="):
		case o.pathPrefix != "" && strings.HasPrefix(e, "PATH="):
			env = append(env, "PATH="+o.pathPrefix+string(os.PathListSeparator)+strings.TrimPrefix(e, "PATH="))
		default:
			env = append(env, e)
		}
	}
	cmd.Env = append(append(env, "MUSTER_BACKUP="+backupDir), o.env...)
	// os/exec copies stdout and stderr from two goroutines; both write all.
	var both syncBuf
	var errb bytes.Buffer
	cmd.Stdout = &both
	cmd.Stderr = io.MultiWriter(&both, &errb)
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return both.String(), errb.String(), 0
	case errors.As(err, &ee):
		return both.String(), errb.String(), ee.ExitCode()
	default:
		t.Fatalf("sh: %v", err)
		return "", "", -1
	}
}

// syncBuf is a bytes.Buffer safe for the two writers os/exec runs.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// I-1(a): a backup that cannot be made stops the block before its body. The
// first declared path cannot be copied (its backup directory is a regular
// file); the second can, so a backup() that went on past the first failure
// would return 0 and the body would run.
func TestScriptBackupFailureStopsTheBlock(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(tmp, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fa, fb := filepath.Join(tmp, "a", "f"), filepath.Join(tmp, "b", "g")
	for _, f := range []string{fa, fb} {
		if err := os.WriteFile(f, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bk := filepath.Join(tmp, "bk")
	if err := os.MkdirAll(bk+tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bk+filepath.Join(tmp, "a"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tmp, "ran")
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.backup_fails", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "restore_backup", Backup: []string{fa, fb},
		ScriptBody: "printf ran > " + marker,
	}}}
	out, code := runScript(t, p, tmp, bk)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if exists(marker) {
		t.Errorf("the body ran although the backup failed\n%s", out)
	}
	if !strings.Contains(out, "muster.test.backup_fails: backup failed, nothing changed") {
		t.Errorf("no backup-failed line\n%s", out)
	}
	if !strings.Contains(out, "1 block(s) failed") {
		t.Errorf("the epilogue did not count the failed block\n%s", out)
	}
}

// I-1(b): existence is -e || -L, so a dangling symlink with a relative
// target is backed up and restored as the same link.
func TestScriptDanglingRelativeSymlinkIsRestoredAsALink(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	link := filepath.Join(tmp, "link")
	if err := os.Symlink("nowhere", link); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.symlink", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "restore_backup", Backup: []string{link},
		ScriptBody: "rm -f " + link + "\nprintf file > " + link + "\nfalse",
	}}}
	out, code := runScript(t, p, tmp, filepath.Join(tmp, "bk"))
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	target, err := os.Readlink(link)
	if err != nil || target != "nowhere" {
		t.Errorf("after restore %s reads as link %q (%v); want the link to nowhere\n%s", link, target, err, out)
	}
}

// Z-25: restore never writes through a destination symlink. The body swaps
// the backed-up file for a link to another file and fails; restore removes
// the link and puts the original file back, leaving the link's target alone.
func TestScriptRestoreNeverWritesThroughASymlink(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	f, victim := filepath.Join(tmp, "f"), filepath.Join(tmp, "victim")
	if err := os.WriteFile(f, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.through_link", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "restore_backup", Backup: []string{f},
		ScriptBody: "rm -f " + f + "\nln -s " + victim + " " + f + "\nfalse",
	}}}
	out, code := runScript(t, p, tmp, filepath.Join(tmp, "bk"))
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if got := readFile(t, victim); got != "victim" {
		t.Errorf("restore wrote through the link: victim is %q\n%s", got, out)
	}
	fi, err := os.Lstat(f)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("%s is %v after restore, want a regular file\n%s", f, fi.Mode().Type(), out)
	}
	if got := readFile(t, f); got != "original" {
		t.Errorf("%s is %q after restore, want the original\n%s", f, got, out)
	}
}

// I-1(c): a MUSTER_BACKUP that is not a clean absolute path exits 2 with the
// refusal on stderr, before any directory is made or any block runs. Every
// value but "/" lies under the test's own directory, so a regression creates
// nothing outside it.
func TestScriptRefusesAnUncleanBackupPath(t *testing.T) {
	needSh(t)
	for _, v := range []struct{ name, val string }{
		{"root", "/"},
		{"double slash", "/"},
		{"dot component", "/a/./b"},
		{"dotdot component", "/a/../b"},
		{"trailing dot", "/a/."},
		{"trailing dotdot", "/a/.."},
		{"relative", "rel"},
	} {
		t.Run(v.name, func(t *testing.T) {
			tmp := t.TempDir()
			val := v.val
			switch v.name {
			case "double slash":
				val = "/" + tmp + "/x"
			case "root", "relative":
			default:
				val = tmp + val
			}
			marker := filepath.Join(tmp, "ran")
			p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
				ID: "muster.test.refused", Status: "fail", Severity: "high", Risk: "none",
				Script: true, Planned: true, Rollback: "declared",
				ScriptBody: "printf ran > " + marker, RollbackBody: "true",
			}}}
			out, stderr, code := runScriptStreams(t, p, tmp, val)
			if code != 2 {
				t.Fatalf("MUSTER_BACKUP=%q: exit %d, want 2\n%s", val, code, out)
			}
			if !strings.Contains(stderr, "muster-fix: MUSTER_BACKUP must be a clean absolute path") {
				t.Errorf("MUSTER_BACKUP=%q: no refusal on stderr: %q", val, stderr)
			}
			if exists(marker) {
				t.Errorf("MUSTER_BACKUP=%q: a block ran", val)
			}
			for _, d := range []string{"a", "rel", "x"} {
				if exists(filepath.Join(tmp, d)) {
					t.Errorf("MUSTER_BACKUP=%q: %s was created", val, d)
				}
			}
		})
	}
}

// Z-28: a pre-created MUSTER_BACKUP that group can write is refused with exit
// 2 before any block runs or any backup is copied. The check reads uid 0, so
// the test runs only as root (the lab): CI's test job is not root, its temp
// dirs are never root-owned, and runScriptStreams drops the check there.
func TestScriptRefusesABackupDirOnlyRootMustWrite(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("the backup-directory check needs a root-owned directory: run as root")
	}
	tmp := t.TempDir()
	f, bk := filepath.Join(tmp, "f"), filepath.Join(tmp, "bk")
	if err := os.WriteFile(f, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bk, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bk, 0o770); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(tmp, "ran")
	p := &Plan{Fix: FixBlock{MaxRisk: "lockout_risk"}, Items: []Item{{
		ID: "muster.test.backup_dir", Status: "fail", Severity: "high", Risk: "none",
		Script: true, Planned: true, Rollback: "restore_backup", Backup: []string{f},
		ScriptBody: "printf ran > " + marker,
	}}}
	out, stderr, code := runScriptStreams(t, p, tmp, bk)
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s", code, out)
	}
	if !strings.Contains(stderr, "muster-fix: MUSTER_BACKUP must be a root-owned directory that only root can write\n") {
		t.Errorf("no refusal on stderr: %q", stderr)
	}
	if exists(marker) {
		t.Error("a block ran")
	}
	if ents, err := os.ReadDir(bk); err != nil || len(ents) != 0 {
		t.Errorf("the backup directory holds %v (%v), want it empty", ents, err)
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
