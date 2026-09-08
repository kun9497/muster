package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// M15/spec §11: every snapshot in this repository is synthetic and says so,
// so nobody has to guess whether a fixture came off somebody's host (D02).
func TestEndToEndFixturesAreMarkedSynthetic(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var meta struct {
			Synthetic *bool `json:"synthetic"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if meta.Synthetic == nil || !*meta.Synthetic {
			t.Errorf(`%s: fixture must carry a top-level "synthetic": true marker`, f)
		}
	}
}

// M16: waivers end to end — the exit code drops from 1 to 0, the result
// counts the waiver, the table shows a WAIVED row, and every warning is on
// stderr (spec §6.7, §7.4).
func TestCheckEndToEndWaiversTurnFailIntoWaived(t *testing.T) {
	// Copy waiver file to temp dir so the trust gate passes when running as root
	// (spec D12: trustedFile refuses files not owned by root when euid=0).
	tmpDir := t.TempDir()
	waiverSrc, err := os.ReadFile("testdata/waivers.yaml")
	if err != nil {
		t.Fatalf("read source waiver: %v", err)
	}
	tmpWaiver := filepath.Join(tmpDir, "waivers.yaml")
	if err := os.WriteFile(tmpWaiver, waiverSrc, 0o600); err != nil {
		t.Fatalf("write temp waiver: %v", err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"check", "--facts", "testdata/full-fail.json", "--waivers", tmpWaiver, "--format", "json"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d, want 0 once the only FAIL is waived; stderr %q", code, errb.String())
	}
	assertStatuses(t, out.Bytes(), map[string]string{
		"muster.account.root_remote_login": "WAIVED",
		"muster.account.password_policy":   "PASS",
	})
	var rep struct {
		Check struct {
			Waivers struct {
				Path    string `json:"path"`
				Digest  string `json:"digest"`
				Applied int    `json:"applied"`
				Unknown int    `json:"unknown"`
			} `json:"waivers"`
		} `json:"check"`
		Summary struct {
			Undecidable struct {
				Waived int `json:"waived"`
			} `json:"undecidable"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Check.Waivers.Applied != 1 || rep.Check.Waivers.Unknown != 1 {
		t.Errorf("waiver tally applied=%d unknown=%d, want 1 and 1", rep.Check.Waivers.Applied, rep.Check.Waivers.Unknown)
	}
	if rep.Check.Waivers.Path == "" || !strings.HasPrefix(rep.Check.Waivers.Digest, "sha256:") {
		t.Errorf("the result must name the waiver file and its digest: %+v", rep.Check.Waivers)
	}
	if rep.Summary.Undecidable.Waived != 1 {
		t.Errorf("summary must count the waived control: %d", rep.Summary.Undecidable.Waived)
	}
	// The unknown-control warning is on stderr, never on stdout (spec §7.4).
	if !strings.Contains(errb.String(), "unknown control") {
		t.Errorf("stderr %q lacks the unknown-control warning", errb.String())
	}
	// A generic substring check on "warning" would false-positive on
	// muster.service.login_banner's title, which legitimately contains that
	// English word; assert on the actual warning content instead.
	if strings.Contains(out.String(), "unknown control") {
		t.Errorf("stdout must carry the report only: %s", out.String())
	}

	var table, tableErr bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--waivers", tmpWaiver, "--color", "never"}, &table, &tableErr); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, tableErr.String())
	}
	if !strings.Contains(table.String(), "WAIVED") || !strings.Contains(table.String(), "migration to key-only access") {
		t.Errorf("table must show the WAIVED row and its reason:\n%s", table.String())
	}
}

// assertStatuses parses a --format json report and checks each named
// control's status (R26).
func assertStatuses(t *testing.T, jsonBytes []byte, want map[string]string) {
	t.Helper()
	var rep struct {
		Results []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatalf("parse results: %v", err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.ID] = r.Status
	}
	for id, status := range want {
		if got[id] != status {
			t.Errorf("%s: status=%q, want %q (all: %v)", id, got[id], status, got)
		}
	}
}

func TestCheckEndToEndJSONAndTable(t *testing.T) {
	var out1, out2, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out1, &errb); code != exitOK {
		t.Fatalf("exit %d stderr %q", code, errb.String())
	}
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out2, &errb); code != exitOK {
		t.Fatal(code)
	}
	if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
		t.Fatal("JSON output is not deterministic")
	}
	var rep map[string]any
	if err := json.Unmarshal(out1.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if rep["schema_version"].(float64) != 1 || rep["check"].(map[string]any)["guide_edition"] != "kisa-unix-2026" {
		t.Errorf("report header: %v", rep["check"])
	}
	// I5/R30: the result records the parameter values in force (spec §6.6,
	// §9), so a reader can tell which threshold produced the verdict.
	params, ok := rep["check"].(map[string]any)["params"].(map[string]any)
	if !ok {
		t.Fatalf("check.params is missing: %v", rep["check"])
	}
	rrl, ok := params["muster.account.root_remote_login"].(map[string]any)
	if !ok {
		t.Fatalf("check.params lacks muster.account.root_remote_login: %v", params)
	}
	allowed, ok := rrl["allowed"].([]any)
	if !ok || len(allowed) != 2 || allowed[0] != "no" || allowed[1] != "prohibit-password" {
		t.Errorf("check.params[...].allowed = %v, want the control's declared default", rrl["allowed"])
	}
	if _, declared := params["muster.service.telnet_disabled"]; declared {
		t.Errorf("only controls that declare params belong in check.params: %v", params)
	}
	// R26: full-pass.json must produce exactly the thirty-five embedded
	// controls' documented statuses, not merely "some PASS rows appear
	// somewhere in the output".
	assertStatuses(t, out1.Bytes(), map[string]string{
		"muster.account.root_remote_login":       "PASS",
		"muster.account.password_policy":         "PASS",
		"muster.file.passwd_permissions":         "PASS",
		"muster.file.hosts_permissions":          "PASS",
		"muster.file.services_permissions":       "PASS",
		"muster.file.hosts_lpd_permissions":      "PASS",
		"muster.service.telnet_disabled":         "PASS",
		"muster.file.world_writable":             "MANUAL",
		"muster.account.shadow_passwords":        "PASS",
		"muster.account.root_only_uid_zero":      "PASS",
		"muster.account.primary_group_exists":    "PASS",
		"muster.account.unique_uids":             "PASS",
		"muster.account.system_account_shells":   "PASS",
		"muster.account.unnecessary_accounts":    "PASS",
		"muster.account.admin_group_minimal":     "PASS",
		"muster.account.password_hash_algorithm": "PASS",
		"muster.file.shadow_permissions":         "PASS",
		"muster.service.ftp_account_shell":       "PASS",
		"muster.account.lockout_threshold":       "PASS",
		"muster.account.su_restricted":           "PASS",
		"muster.account.session_timeout":         "PASS",
		"muster.service.login_banner":            "PASS",
		"muster.account.root_home_and_path":      "PASS",
		"muster.account.umask_policy":            "PASS",
		"muster.file.env_file_permissions":       "PASS",
		"muster.file.dev_no_stale_files":         "PASS",
		"muster.file.rhosts_forbidden":           "PASS",
		"muster.file.home_dir_permissions":       "PASS",
		"muster.file.home_dir_exists":            "PASS",
		"muster.file.startup_script_permissions": "PASS",
		"muster.file.syslog_conf_permissions":    "PASS",
		"muster.file.inetd_conf_permissions":     "PASS",
		"muster.account.cron_permissions":        "PASS",
		"muster.account.sudoers_permissions":     "PASS",
		"muster.file.log_dir_permissions":        "PASS",
	})

	var table bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--color", "never"}, &table, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	if !bytes.Contains(table.Bytes(), []byte("muster.account.root_remote_login")) || bytes.Contains(table.Bytes(), []byte("\x1b")) {
		t.Errorf("table output:\n%s", table.String())
	}

	// R26: full-fail.json flips only root_remote_login to FAIL; the other
	// thirty-four controls are unchanged from full-pass.json.
	var failJSON bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--format", "json"}, &failJSON, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	assertStatuses(t, failJSON.Bytes(), map[string]string{
		"muster.account.root_remote_login":       "FAIL",
		"muster.account.password_policy":         "PASS",
		"muster.file.passwd_permissions":         "PASS",
		"muster.file.hosts_permissions":          "PASS",
		"muster.file.services_permissions":       "PASS",
		"muster.file.hosts_lpd_permissions":      "PASS",
		"muster.service.telnet_disabled":         "PASS",
		"muster.file.world_writable":             "MANUAL",
		"muster.account.shadow_passwords":        "PASS",
		"muster.account.root_only_uid_zero":      "PASS",
		"muster.account.primary_group_exists":    "PASS",
		"muster.account.unique_uids":             "PASS",
		"muster.account.system_account_shells":   "PASS",
		"muster.account.unnecessary_accounts":    "PASS",
		"muster.account.admin_group_minimal":     "PASS",
		"muster.account.password_hash_algorithm": "PASS",
		"muster.file.shadow_permissions":         "PASS",
		"muster.service.ftp_account_shell":       "PASS",
		"muster.account.lockout_threshold":       "PASS",
		"muster.account.su_restricted":           "PASS",
		"muster.account.session_timeout":         "PASS",
		"muster.service.login_banner":            "PASS",
		"muster.account.root_home_and_path":      "PASS",
		"muster.account.umask_policy":            "PASS",
		"muster.file.env_file_permissions":       "PASS",
		"muster.file.dev_no_stale_files":         "PASS",
		"muster.file.rhosts_forbidden":           "PASS",
		"muster.file.home_dir_permissions":       "PASS",
		"muster.file.home_dir_exists":            "PASS",
		"muster.file.startup_script_permissions": "PASS",
		"muster.file.syslog_conf_permissions":    "PASS",
		"muster.file.inetd_conf_permissions":     "PASS",
		"muster.account.cron_permissions":        "PASS",
		"muster.account.sudoers_permissions":     "PASS",
		"muster.file.log_dir_permissions":        "PASS",
	})

	// R26: every run() call's exit code is asserted, including --quiet's,
	// and --quiet must hide PASS rows while still showing the FAIL row.
	var quiet bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--quiet", "--fail-on", "none"}, &quiet, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0 with --fail-on none; stderr %q", code, errb.String())
	}
	if bytes.Contains(quiet.Bytes(), []byte("muster.service.telnet_disabled")) {
		t.Error("--quiet must hide PASS rows")
	}
	if !bytes.Contains(quiet.Bytes(), []byte("muster.account.root_remote_login")) {
		t.Error("--quiet must still show the FAIL row")
	}
}
