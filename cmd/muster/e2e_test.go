package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

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
	// R26: full-pass.json must produce exactly the five stage-1 controls'
	// documented statuses (spec §10.2's five-controls list), not merely
	// "some PASS rows appear somewhere in the output".
	assertStatuses(t, out1.Bytes(), map[string]string{
		"muster.account.root_remote_login": "PASS",
		"muster.account.password_policy":   "PASS",
		"muster.file.passwd_permissions":   "PASS",
		"muster.service.telnet_disabled":   "PASS",
		"muster.file.world_writable":       "MANUAL",
	})

	var table bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--color", "never"}, &table, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	if !bytes.Contains(table.Bytes(), []byte("muster.account.root_remote_login")) || bytes.Contains(table.Bytes(), []byte("\x1b")) {
		t.Errorf("table output:\n%s", table.String())
	}

	// R26: full-fail.json flips only root_remote_login to FAIL; the other
	// four controls are unchanged from full-pass.json.
	var failJSON bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--format", "json"}, &failJSON, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	assertStatuses(t, failJSON.Bytes(), map[string]string{
		"muster.account.root_remote_login": "FAIL",
		"muster.account.password_policy":   "PASS",
		"muster.file.passwd_permissions":   "PASS",
		"muster.service.telnet_disabled":   "PASS",
		"muster.file.world_writable":       "MANUAL",
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
