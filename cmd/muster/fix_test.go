package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/remedy"
)

const fullFail = "testdata/full-fail.json"

// failWriter is a stdout whose every write fails, as a closed pipe does.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func runFixArgs(t *testing.T, args ...string) (code int, stdout, stderr []byte) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(append([]string{"fix"}, args...), &out, &errb)
	return code, out.Bytes(), errb.Bytes()
}

func decodePlan(t *testing.T, b []byte) remedy.Plan {
	t.Helper()
	var p remedy.Plan
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("the JSON plan does not decode into remedy.Plan: %v\n%s", err, b)
	}
	return p
}

func planJSON(t *testing.T, args ...string) remedy.Plan {
	t.Helper()
	code, out, errb := runFixArgs(t, append([]string{"--dry-run", "--format", "json"}, args...)...)
	if code != exitOK {
		t.Fatalf("fix %v: exit %d, want 0; stderr %q", args, code, errb)
	}
	return decodePlan(t, out)
}

// hostsCopy is full-fail.json with /etc/hosts at 0644, which makes
// muster.file.hosts_permissions FAIL: the file-permission shape (risk none,
// a script, a backup to restore).
func hostsCopy(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fullFail)
	if err != nil {
		t.Fatal(err)
	}
	old := `"etc_hosts":{"mode":{"status":"ok","value":384,`
	if bytes.Count(b, []byte(old)) != 1 {
		t.Fatalf("full-fail.json no longer carries %s once", old)
	}
	b = bytes.Replace(b, []byte(old), []byte(`"etc_hosts":{"mode":{"status":"ok","value":420,`), 1)
	p := filepath.Join(t.TempDir(), "hosts-0644.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// X-1, Z-12: without --dry-run, or with any positional word, fix refuses
// before any other flag error, and stdout stays empty.
func TestFixRefusesWithoutDryRun(t *testing.T) {
	for _, args := range [][]string{
		{"--facts", fullFail},
		{"apply", "--dry-run", "--facts", fullFail},
		{"--dry-run", "apply", "--facts", fullFail},
		{"--bogus", "apply", "--dry-run", "--facts", fullFail},
		{"--facts", "--dry-run"},
	} {
		code, out, errb := runFixArgs(t, args...)
		if code != exitError {
			t.Errorf("fix %v: exit %d, want %d", args, code, exitError)
		}
		if len(out) != 0 {
			t.Errorf("fix %v: stdout %q, want empty", args, out)
		}
		if want := "muster: fix never applies a remediation (D24); run fix --dry-run\n"; !strings.HasPrefix(string(errb), want) {
			t.Errorf("fix %v: stderr %q, want it to start %q", args, errb, want)
		}
	}
}

// The pre-pass skips a value flag's value without swallowing a later
// --dry-run.
func TestFixDryRunAfterTheFactsValue(t *testing.T) {
	code, out, errb := runFixArgs(t, "--facts", fullFail, "--dry-run")
	if code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb)
	}
	if !bytes.Contains(out, []byte("fix --dry-run · ")) || !bytes.Contains(out, []byte("muster.account.root_remote_login")) {
		t.Errorf("stdout is not the plan table:\n%s", out)
	}
}

func TestFixUnknownFlag(t *testing.T) {
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--bogus")
	if code != exitError || len(out) != 0 {
		t.Fatalf("exit %d stdout %q, want 2 and empty", code, out)
	}
	if !strings.HasPrefix(string(errb), "muster: unknown flag --bogus\n") || !strings.Contains(string(errb), "usage: muster fix --dry-run") {
		t.Errorf("stderr %q", errb)
	}
}

func TestFixMaxRiskOutsideTheList(t *testing.T) {
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--max-risk", "high")
	if code != exitError || len(out) != 0 {
		t.Fatalf("exit %d stdout %q, want 2 and empty", code, out)
	}
	for _, w := range []string{`"high"`, "none", "restart_service", "reboot_required", "lockout_risk"} {
		if !strings.Contains(string(errb), w) {
			t.Errorf("stderr %q does not name %s", errb, w)
		}
	}
}

func TestFixThreeFormats(t *testing.T) {
	for _, format := range []string{"table", "json", "script"} {
		code1, out1, err1 := runFixArgs(t, "--dry-run", "--facts", fullFail, "--format", format, "--color", "never")
		code2, out2, _ := runFixArgs(t, "--dry-run", "--facts", fullFail, "--format", format, "--color", "never")
		if code1 != exitOK || code2 != exitOK {
			t.Fatalf("--format %s: exit %d/%d, want 0; stderr %q", format, code1, code2, err1)
		}
		if !bytes.Equal(out1, out2) {
			t.Errorf("--format %s: two runs differ", format)
		}
		switch format {
		case "table":
			if !bytes.Contains(out1, []byte("fix --dry-run · ")) || bytes.Contains(out1, []byte("\x1b")) {
				t.Errorf("not a colourless plan table:\n%s", out1)
			}
		case "script":
			if !bytes.HasPrefix(out1, []byte("#!/bin/sh\n")) {
				t.Errorf("script starts %q", out1[:min(len(out1), 40)])
			}
		case "json":
			p := decodePlan(t, out1)
			if len(p.Items) != 10 {
				t.Fatalf("%d items, want 10", len(p.Items))
			}
			if last := p.Items[len(p.Items)-1]; last.ID != "muster.account.root_remote_login" || last.Risk != "lockout_risk" {
				t.Errorf("last item %s (%s), want the lockout item root_remote_login", last.ID, last.Risk)
			}
		}
	}
}

// Every FAIL/WARN row of check is an item or a not-planned warn_degraded
// row of fix, and fix plans nothing else.
func TestFixAgreesWithCheck(t *testing.T) {
	for _, facts := range []string{fullFail, hostsCopy(t)} {
		var out, errb bytes.Buffer
		if code := run([]string{"check", "--facts", facts, "--format", "json"}, &out, &errb); code != exitFindings {
			t.Fatalf("check %s: exit %d; stderr %q", facts, code, errb.String())
		}
		var rep struct {
			Results []struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"results"`
		}
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, r := range rep.Results {
			if r.Status == "FAIL" || r.Status == "WARN" {
				want = append(want, r.ID)
			}
		}
		p := planJSON(t, "--facts", facts)
		var got []string
		for _, it := range p.Items {
			got = append(got, it.ID)
		}
		for _, n := range p.NotPlanned {
			if n.Status == "warn_degraded" {
				got = append(got, n.ID)
			}
		}
		sort.Strings(want)
		sort.Strings(got)
		if len(want) == 0 || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: fix plans %v, check's FAIL/WARN rows are %v", facts, got, want)
		}
	}
}

func TestFixFilePermissionShape(t *testing.T) {
	p := planJSON(t, "--facts", hostsCopy(t))
	if len(p.Items) == 0 {
		t.Fatal("no items")
	}
	it := p.Items[0]
	if it.ID != "muster.file.hosts_permissions" || it.Risk != "none" || !it.Script || it.Rollback != "restore_backup" {
		t.Errorf("item 1 is %s risk %s script %v rollback %s, want hosts_permissions, none, true, restore_backup",
			it.ID, it.Risk, it.Script, it.Rollback)
	}
}

func TestFixMaxRiskMarksTheLockoutItem(t *testing.T) {
	p := planJSON(t, "--facts", fullFail, "--max-risk", "restart_service")
	found := false
	for _, it := range p.Items {
		if it.ID == "muster.account.root_remote_login" {
			found = true
			if it.Planned {
				t.Error("root_remote_login is planned above max-risk restart_service")
			}
		} else if !it.Planned {
			t.Errorf("%s (%s) is not planned at max-risk restart_service", it.ID, it.Risk)
		}
	}
	if !found || p.Summary.AboveMaxRisk != 1 {
		t.Errorf("found %v, summary.above_max_risk %d, want the item and 1", found, p.Summary.AboveMaxRisk)
	}
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--max-risk", "restart_service", "--format", "script")
	if code != exitOK {
		t.Fatalf("exit %d; stderr %q", code, errb)
	}
	_, after, ok := strings.Cut(string(out), "\n# ---- 10/10 muster.account.root_remote_login ")
	if !ok {
		t.Fatalf("the script has no block header for root_remote_login:\n%s", out)
	}
	blockText, _, _ := strings.Cut(after, "\n\n")
	lines := strings.Split(blockText, "\n")
	if len(lines) < 5 {
		t.Fatalf("the block is %d lines", len(lines))
	}
	for _, l := range lines[1:] { // lines[0] is the rest of the header line
		if !strings.HasPrefix(l, "#") {
			t.Errorf("a line of the block above max-risk is not a comment: %q", l)
		}
	}
	if !strings.Contains(blockText, "\n# fix_muster_account_root_remote_login\n") {
		t.Error("the commented block lost its function call")
	}
}

func TestFixProfileAndWaivers(t *testing.T) {
	dir := t.TempDir()
	prof := filepath.Join(dir, "no-rrl.yaml")
	if err := os.WriteFile(prof, []byte("profile: no-rrl\nextends: default\nexclude: [muster.account.root_remote_login]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := planJSON(t, "--facts", fullFail, "--profile", prof)
	for _, it := range p.Items {
		if it.ID == "muster.account.root_remote_login" {
			t.Error("an excluded control is an item")
		}
	}
	if len(p.Items) != 9 || p.Fix.Profile.Name != "no-rrl" {
		t.Errorf("%d items, profile %q; want 9 and no-rrl", len(p.Items), p.Fix.Profile.Name)
	}

	w := filepath.Join(dir, "waivers.yaml")
	body := "waivers:\n  - control: muster.account.root_remote_login\n    reason: synthetic waiver for the fix end-to-end test\n    expires: 2099-12-31\n"
	if err := os.WriteFile(w, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p = planJSON(t, "--facts", fullFail, "--waivers", w)
	if p.Summary.Waived != 1 || len(p.Items) != 9 {
		t.Errorf("summary.waived %d, %d items; want 1 and 9", p.Summary.Waived, len(p.Items))
	}
}

func TestFixNothingToFix(t *testing.T) {
	const pass = "testdata/full-pass.json"
	code, table, errb := runFixArgs(t, "--dry-run", "--facts", pass)
	if code != exitOK || !bytes.Contains(table, []byte("nothing to fix\n")) {
		t.Errorf("table: exit %d, stderr %q:\n%s", code, errb, table)
	}
	code, js, _ := runFixArgs(t, "--dry-run", "--facts", pass, "--format", "json")
	if code != exitOK || !bytes.Contains(js, []byte(`"items": []`)) {
		t.Errorf("json: exit %d:\n%s", code, js)
	}
	code, sh, _ := runFixArgs(t, "--dry-run", "--facts", pass, "--format", "script")
	if code != exitOK || !bytes.Contains(sh, []byte("\n# nothing to fix\n")) {
		t.Errorf("script: exit %d:\n%s", code, sh)
	}
}

func TestFixScriptPassesShN(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sh -n runs on Linux")
	}
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--format", "script")
	if code != exitOK {
		t.Fatalf("exit %d; stderr %q", code, errb)
	}
	p := filepath.Join(t.TempDir(), "fix.sh")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("sh", "-n", p).CombinedOutput(); err != nil {
		t.Errorf("sh -n: %v\n%s", err, b)
	}
}

func TestFixFailingStdoutIsExit2(t *testing.T) {
	var errb bytes.Buffer
	if code := run([]string{"fix", "--dry-run", "--facts", fullFail}, failWriter{}, &errb); code != exitError {
		t.Errorf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "muster: write: closed\n") {
		t.Errorf("stderr %q", errb.String())
	}
}

// --tuning has check's semantics: the plan carries the tuning block, and an
// item whose parameters the site tuned is text only (the declared script
// assumes the defaults).
func TestFixTuningMakesTheItemTextOnly(t *testing.T) {
	tun := filepath.Join(t.TempDir(), "tuning.yaml")
	body := "params:\n  muster.file.hosts_permissions:\n    allowed_modes: [0, 256, 384]\n"
	if err := os.WriteFile(tun, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p := planJSON(t, "--facts", hostsCopy(t), "--tuning", tun)
	if p.Fix.Tuning == nil || p.Fix.Tuning.Path != tun || !strings.HasPrefix(p.Fix.Tuning.Digest, "sha256:") {
		t.Fatalf("tuning block %+v, want path %s and a digest", p.Fix.Tuning, tun)
	}
	var found bool
	for _, it := range p.Items {
		if it.ID != "muster.file.hosts_permissions" {
			continue
		}
		found = true
		if it.Script || it.TextOnlyReason != "params_tuned" {
			t.Errorf("hosts_permissions: script %v, text_only_reason %q; want false and params_tuned", it.Script, it.TextOnlyReason)
		}
	}
	if !found {
		t.Error("hosts_permissions (0644, not in the tuned modes) is not an item")
	}
	if untuned := planJSON(t, "--facts", hostsCopy(t)); untuned.Fix.Tuning != nil {
		t.Errorf("a plan without --tuning carries a tuning block %+v", untuned.Fix.Tuning)
	}
}

// --tuning "" is refused, as check refuses it, with the same words.
func TestFixEmptyTuningIsRefusedAsCheckRefusesIt(t *testing.T) {
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--tuning", "")
	if code != exitError || len(out) != 0 {
		t.Fatalf("exit %d stdout %q, want 2 and empty", code, out)
	}
	var cout, cerr bytes.Buffer
	if c := run([]string{"check", "--facts", fullFail, "--tuning", ""}, &cout, &cerr); c != exitError {
		t.Fatalf("check --tuning \"\": exit %d", c)
	}
	if string(errb) != cerr.String() || !strings.HasPrefix(string(errb), "muster: ") {
		t.Errorf("fix stderr %q, check stderr %q; want the same refusal", errb, cerr.String())
	}
}

// --no-color after --color always means never; --color always alone paints.
func TestFixColorFlags(t *testing.T) {
	_, painted, _ := runFixArgs(t, "--dry-run", "--facts", fullFail, "--color", "always")
	if !bytes.Contains(painted, []byte("\x1b[")) {
		t.Error("--color always did not paint the table")
	}
	code, plain, errb := runFixArgs(t, "--dry-run", "--facts", fullFail, "--color", "always", "--no-color")
	if code != exitOK || bytes.Contains(plain, []byte("\x1b")) {
		t.Errorf("--color always --no-color: exit %d, stderr %q, escape in table %v", code, errb, bytes.Contains(plain, []byte("\x1b")))
	}
}

func TestStdoutIsTTY(t *testing.T) {
	if stdoutIsTTY(&bytes.Buffer{}) {
		t.Error("a bytes.Buffer is a tty")
	}
	fh, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if stdoutIsTTY(fh) {
		t.Error("a regular file is a tty")
	}
}

// The root warning is pinned where the test runs as root (the lab, CI's
// root job); elsewhere it cannot be produced.
func TestFixWarnsAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	code, _, errb := runFixArgs(t, "--dry-run", "--facts", fullFail)
	if code != exitOK || !strings.Contains(string(errb), "muster: warning: fix does not need root\n") {
		t.Errorf("exit %d, stderr %q", code, errb)
	}
}

func TestFixUsageListed(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"help"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "\n  fix ") {
		t.Errorf("usage does not list fix:\n%s", out.String())
	}
}
