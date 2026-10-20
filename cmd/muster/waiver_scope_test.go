package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sudoNopasswdAll = "muster.beyond.sudo_nopasswd_all"

// sudoSnapshot writes the control's fail-cloud-init fixture with
// sudo.authenticate_disabled set to authDisabled, and returns its path.
func sudoSnapshot(t *testing.T, authDisabled bool) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "controls", "testdata", sudoNopasswdAll, "fail-cloud-init.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	if err := json.Unmarshal(b, &snap); err != nil {
		t.Fatal(err)
	}
	sudo := snap["facts"].(map[string]any)["sudo"].(map[string]any)
	sudo["authenticate_disabled"].(map[string]any)["value"] = authDisabled
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "snap.json")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

type scopeRow struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
	Observations []struct {
		Subject string `json:"subject"`
		Verdict string `json:"verdict"`
	} `json:"observations"`
	Waiver *struct {
		Applied bool   `json:"applied"`
		Subject string `json:"subject"`
	} `json:"waiver"`
}

// runSudoCheck runs check on snap with the one control selected and the
// waiver entry given, and returns the exit code, the control's row and stderr.
func runSudoCheck(t *testing.T, snap, waiverEntry string) (int, scopeRow, string) {
	t.Helper()
	dir := t.TempDir()
	prof := filepath.Join(dir, "sudo-only.yaml")
	if err := os.WriteFile(prof, []byte("profile: sudo-only\ninclude: ["+sudoNopasswdAll+"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wf := filepath.Join(dir, "waivers.yaml")
	if err := os.WriteFile(wf, []byte("waivers:\n"+waiverEntry), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"check", "--facts", snap, "--profile", prof, "--waivers", wf, "--format", "json"}, &out, &errb)
	var rep struct {
		Results []scopeRow `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v\nstderr %s", err, errb.String())
	}
	if len(rep.Results) != 1 || rep.Results[0].ID != sudoNopasswdAll {
		t.Fatalf("results %+v, want the one control", rep.Results)
	}
	return code, rep.Results[0], errb.String()
}

const (
	subjectWaiver = "  - control: " + sudoNopasswdAll + "\n    subject: user:ubuntu\n    reason: the image's default user, recorded on purpose\n    expires: 2099-12-31\n"
	controlWaiver = "  - control: " + sudoNopasswdAll + "\n    reason: the whole control, recorded on purpose\n    expires: 2099-12-31\n"
)

// f2: a subject waiver covers its observation and nothing else (spec §6.4).
// A host-wide Defaults !authenticate is a scalar clause no observation
// carries, so waiving user:ubuntu's NOPASSWD line must leave the row FAIL
// (exit 1) and say so on stderr — never turn it into WAIVED (exit 0).
func TestCheckSubjectWaiverDoesNotWaiveAScalarClause(t *testing.T) {
	code, row, stderr := runSudoCheck(t, sudoSnapshot(t, true), subjectWaiver)
	if code != exitFindings || row.Status != "FAIL" {
		t.Errorf("exit %d status %s, want %d FAIL", code, row.Status, exitFindings)
	}
	if len(row.Observations) != 1 || row.Observations[0].Subject != "user:ubuntu" || row.Observations[0].Verdict != "waived" {
		t.Errorf("observations %+v, want user:ubuntu waived", row.Observations)
	}
	if row.Waiver == nil || !row.Waiver.Applied || row.Waiver.Subject != "user:ubuntu" {
		t.Errorf("waiver %+v, want applied to user:ubuntu", row.Waiver)
	}
	// The reason names the clause the row still fails on, not the waived one.
	const reason = "clause does not hold: sudo.authenticate_disabled eq false"
	if row.Reason != reason {
		t.Errorf("reason %q, want %q", row.Reason, reason)
	}
	want := "waiver for " + sudoNopasswdAll + "#user:ubuntu applied; " + sudoNopasswdAll + " stays FAIL on a clause no subject waiver covers (" + reason + ")"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr %q, want %q", stderr, want)
	}
}

// A control-level waiver still waives the whole row, scalar clause included.
func TestCheckControlWaiverWaivesTheScalarClauseToo(t *testing.T) {
	code, row, _ := runSudoCheck(t, sudoSnapshot(t, true), controlWaiver)
	if code != exitOK || row.Status != "WAIVED" {
		t.Errorf("exit %d status %s, want %d WAIVED", code, row.Status, exitOK)
	}
}

// With the scalar clause holding, the subject waiver waives the row as before.
func TestCheckSubjectWaiverWaivesWhenOnlyItsObservationFails(t *testing.T) {
	code, row, stderr := runSudoCheck(t, sudoSnapshot(t, false), subjectWaiver)
	if code != exitOK || row.Status != "WAIVED" {
		t.Errorf("exit %d status %s, want %d WAIVED", code, row.Status, exitOK)
	}
	if strings.Contains(stderr, "no subject waiver covers") {
		t.Errorf("stderr %q warns about a scalar clause that holds", stderr)
	}
}

// fix --dry-run reads the same waived report: a row a subject waiver leaves
// FAIL on an unobserved clause stays in the plan; a control-level waiver
// takes it out.
func TestFixPlansARowASubjectWaiverLeavesFailing(t *testing.T) {
	snap := sudoSnapshot(t, true)
	for _, c := range []struct {
		name, entry string
		planned     bool
	}{
		{"subject", subjectWaiver, true},
		{"control", controlWaiver, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			prof := filepath.Join(dir, "sudo-only.yaml")
			wf := filepath.Join(dir, "waivers.yaml")
			if err := os.WriteFile(prof, []byte("profile: sudo-only\ninclude: ["+sudoNopasswdAll+"]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(wf, []byte("waivers:\n"+c.entry), 0o644); err != nil {
				t.Fatal(err)
			}
			code, out, errb := runFixArgs(t, "--dry-run", "--facts", snap, "--profile", prof, "--waivers", wf, "--format", "json")
			if code != exitOK {
				t.Fatalf("exit %d, stderr %s", code, errb)
			}
			p := decodePlan(t, out)
			planned := false
			for _, it := range p.Items {
				if it.ID == sudoNopasswdAll {
					planned = true
				}
			}
			if planned != c.planned {
				t.Errorf("planned %v, want %v (items %+v)", planned, c.planned, p.Items)
			}
		})
	}
}
