package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
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
	// testdata/full-fail.json now also fails the nine 2G service controls
	// (R230/R240: the fail fixture is the only proof of their positive path
	// in CI, since no such daemon runs on the CI images). Waive them here too
	// so this test keeps exercising only what it is named for: one FAIL
	// (root_remote_login) turning into WAIVED, not a pile of unrelated ones.
	extraWaivers := "\n"
	for _, id := range []string{
		"muster.service.finger_disabled",
		"muster.service.rservices_disabled",
		"muster.service.dos_services_disabled",
		"muster.service.nfs_server_disabled",
		"muster.service.automount_disabled",
		"muster.service.rpcbind_disabled",
		"muster.service.nis_disabled",
		"muster.service.tftp_talk_disabled",
		"muster.service.snmp_disabled",
	} {
		extraWaivers += "  - control: " + id + "\n" +
			"    reason: synthetic 2G service fixture waived so this test isolates the root_remote_login waiver path\n" +
			"    expires: 2099-12-31\n"
	}
	tmpWaiver := filepath.Join(tmpDir, "waivers.yaml")
	if err := os.WriteFile(tmpWaiver, append(waiverSrc, extraWaivers...), 0o600); err != nil {
		t.Fatalf("write temp waiver: %v", err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"check", "--facts", "testdata/full-fail.json", "--waivers", tmpWaiver, "--format", "json"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d, want 0 once every FAIL is waived; stderr %q", code, errb.String())
	}
	// M-28: exhaustive like the other two calls - the ten waived controls
	// (root_remote_login and the nine 2G services waived above) as WAIVED,
	// every other id exactly as the full-fail run reads it.
	assertStatuses(t, out.Bytes(), map[string]string{
		"muster.account.root_remote_login":       "WAIVED",
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
		"muster.service.finger_disabled":         "WAIVED",
		"muster.service.rservices_disabled":      "WAIVED",
		"muster.service.dos_services_disabled":   "WAIVED",
		"muster.service.nfs_server_disabled":     "WAIVED",
		"muster.service.automount_disabled":      "WAIVED",
		"muster.service.rpcbind_disabled":        "WAIVED",
		"muster.service.nis_disabled":            "WAIVED",
		"muster.service.tftp_talk_disabled":      "WAIVED",
		"muster.service.snmp_disabled":           "WAIVED",
		"muster.file.ip_port_restriction":        "PASS",
		"muster.log.time_sync":                   "PASS",
		"muster.log.syslog_policy":               "PASS",
		"muster.service.nfs_export_access":       "PASS",
		"muster.service.snmp_version":            "PASS",
		"muster.service.snmp_community_strength": "PASS",
		"muster.service.snmp_access_control":     "PASS",
		"muster.patch.security_updates":          "PASS",
		"muster.service.ftp_anonymous":           "PASS",
		"muster.service.ftp_banner":              "PASS",
		"muster.service.ftp_unencrypted":         "PASS",
		"muster.service.ftpusers_permissions":    "PASS",
		"muster.service.ftpusers_root":           "PASS",
		"muster.service.mail_expn_vrfy":          "PASS",
		"muster.service.mail_user_execution":     "MANUAL",
		"muster.service.mail_relay":              "MANUAL",
		"muster.service.mail_version":            "MANUAL",
		"muster.service.dns_zone_transfer":       "PASS",
		"muster.service.dns_dynamic_update":      "PASS",
		"muster.service.dns_version":             "MANUAL",
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
	if rep.Check.Waivers.Applied != 10 || rep.Check.Waivers.Unknown != 1 {
		t.Errorf("waiver tally applied=%d unknown=%d, want 10 and 1", rep.Check.Waivers.Applied, rep.Check.Waivers.Unknown)
	}
	if rep.Check.Waivers.Path == "" || !strings.HasPrefix(rep.Check.Waivers.Digest, "sha256:") {
		t.Errorf("the result must name the waiver file and its digest: %+v", rep.Check.Waivers)
	}
	if rep.Summary.Undecidable.Waived != 10 {
		t.Errorf("summary must count the waived controls: %d", rep.Summary.Undecidable.Waived)
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
// control's status (R26). M-17: the map must be exhaustive, so the check is
// done by checkStatuses and this wrapper only reports what it found.
func assertStatuses(t *testing.T, jsonBytes []byte, want map[string]string) {
	t.Helper()
	if err := checkStatuses(jsonBytes, want); err != nil {
		t.Error(err)
	}
}

// checkStatuses is assertStatuses without a *testing.T, so the two ways it
// can reject an incomplete map are drivable from a test of their own
// (TestAssertStatusesIsExhaustive). Beyond the per-id status comparison it
// enforces M-17 in both directions: an id the report carries that `want`
// does not name, and an id the embedded control set loads that `want` does
// not name, are both failures — otherwise a control added to the set slips
// into the end-to-end runs with nobody looking at its status.
func checkStatuses(jsonBytes []byte, want map[string]string) error {
	var rep struct {
		Results []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		return fmt.Errorf("parse results: %v", err)
	}
	got := map[string]string{}
	seen := map[string]int{}
	for _, r := range rep.Results {
		got[r.ID] = r.Status
		seen[r.ID]++
	}
	var problems []string
	for _, id := range sortedIDs(want) {
		switch g, carried := got[id]; {
		case !carried:
			problems = append(problems, fmt.Sprintf("%s: want %q, but the report carries no such control", id, want[id]))
		case g != want[id]:
			problems = append(problems, fmt.Sprintf("%s: status=%q, want %q", id, g, want[id]))
		}
	}
	for _, id := range sortedIDs(got) {
		// A duplicate would otherwise collapse last-write-wins and the two
		// loops below would never see it. The loader rejects a duplicate
		// control id today, so this guards the helper, not the set.
		if seen[id] > 1 {
			problems = append(problems, fmt.Sprintf("%s: the report carries this control %d times", id, seen[id]))
		}
		if _, named := want[id]; !named {
			problems = append(problems, fmt.Sprintf("%s: the report carries this control (status %q) and want does not name it", id, got[id]))
		}
	}
	set, err := controls.LoadDefault()
	if err != nil {
		return fmt.Errorf("load the embedded control set: %v", err)
	}
	for _, c := range set.Controls {
		if _, named := want[c.ID]; !named {
			problems = append(problems, fmt.Sprintf("%s: the embedded control set loads this control and want does not name it", c.ID))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

func sortedIDs(m map[string]string) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// M-17: the exhaustiveness of assertStatuses is the only thing standing
// between a newly enrolled control and an end-to-end run that never looks
// at it, so drive both of its rejections directly rather than trusting the
// three call sites to stay complete on their own.
func TestAssertStatusesIsExhaustive(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d stderr %q", code, errb.String())
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
	complete := map[string]string{}
	for _, r := range rep.Results {
		complete[r.ID] = r.Status
	}
	if len(complete) == 0 {
		t.Fatal("the report carried no results, so this test proves nothing")
	}
	if err := checkStatuses(out.Bytes(), complete); err != nil {
		t.Fatalf("a map naming every result must satisfy the helper: %v", err)
	}

	dropped := sortedIDs(complete)[0]
	short := map[string]string{}
	for id, status := range complete {
		if id != dropped {
			short[id] = status
		}
	}
	err := checkStatuses(out.Bytes(), short)
	if err == nil {
		t.Fatalf("a map missing %s must be rejected", dropped)
	}
	if !strings.Contains(err.Error(), dropped) {
		t.Errorf("the rejection must name the unasserted control %s: %v", dropped, err)
	}

	extra := map[string]string{"muster.account.no_such_control": "PASS"}
	for id, status := range complete {
		extra[id] = status
	}
	err = checkStatuses(out.Bytes(), extra)
	if err == nil {
		t.Fatal("a map naming a control the report does not carry must be rejected")
	}
	if !strings.Contains(err.Error(), "muster.account.no_such_control") {
		t.Errorf("the rejection must name the phantom control: %v", err)
	}

	// The two exhaustiveness loops, driven apart. The `dropped` case above
	// is rejected by either one of them, so on its own it would stay green
	// with either deleted; these two cases each leave exactly one loop with
	// anything to say. A synthesised report is what makes that possible: a
	// report that came out of run() always agrees with the embedded set.
	//
	// The set-loops's own case: the report carries the same sixty-three the
	// map names, so nothing is unnamed and nothing mismatches - only the
	// control the set loads and the map skips is left.
	if err := checkStatuses(reportBytes(t, rowsOf(short)), short); err == nil {
		t.Errorf("a control the set loads but neither the report nor want names must be rejected")
	} else if !strings.Contains(err.Error(), dropped) {
		t.Errorf("the rejection must name the control the set loads, %s: %v", dropped, err)
	}

	// The got-loop's own case: want names every loaded control, so the set
	// loop has nothing to say; the report carries one id beyond them.
	const phantom = "muster.account.not_in_the_set"
	withPhantom := append(rowsOf(complete), reportRow{ID: phantom, Status: "PASS"})
	if err := checkStatuses(reportBytes(t, withPhantom), complete); err == nil {
		t.Errorf("a control the report carries that want does not name must be rejected")
	} else if !strings.Contains(err.Error(), phantom) {
		t.Errorf("the rejection must name the unasserted control %s: %v", phantom, err)
	}

	// A duplicated result id must not collapse into one reading.
	doubled := append(rowsOf(complete), reportRow{ID: dropped, Status: complete[dropped]})
	if err := checkStatuses(reportBytes(t, doubled), complete); err == nil {
		t.Errorf("a report carrying %s twice must be rejected", dropped)
	} else if !strings.Contains(err.Error(), dropped) {
		t.Errorf("the rejection must name the duplicated control %s: %v", dropped, err)
	}
}

// reportRow is one row of the minimum report checkStatuses reads.
type reportRow struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// reportBytes renders rows as a --format json report. Synthesising one is the
// only way to hand checkStatuses a report that disagrees with the embedded
// control set, which is what pinning its two loops apart needs.
func reportBytes(t *testing.T, rows []reportRow) []byte {
	t.Helper()
	b, err := json.Marshal(struct {
		Results []reportRow `json:"results"`
	}{rows})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rowsOf renders a want map as report rows, in id order.
func rowsOf(m map[string]string) []reportRow {
	rows := make([]reportRow, 0, len(m))
	for _, id := range sortedIDs(m) {
		rows = append(rows, reportRow{ID: id, Status: m[id]})
	}
	return rows
}

// M-8: a MANUAL row is the worksheet the reviewer answers the item from, so
// every fact the control names in its `evidence:` list has to be readable in
// the snapshot. A `missing` leaf there hands the reviewer a fact name and no
// reading, which is worse than not naming it at all.
//
// The check is scoped to `automation: manual` controls, which are the only
// ones that may carry an `evidence:` list. An auto control that reaches
// MANUAL through the walk gate is a different contract: R16 attaches
// walk.complete as evidence precisely so a reader sees that the key is
// missing, which is the honest answer on a snapshot collected without
// --deep.
func assertManualEvidenceIsPresent(t *testing.T, jsonBytes []byte) {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	// Keyed on the automation class alone: lint permits a manual control with
	// no evidence list, and such a control must still be counted below, or the
	// "every manual control produced a MANUAL row" guard would balance while
	// covering less than it claims.
	declared := map[string][]string{}
	for _, c := range set.Controls {
		if c.Automation == "manual" {
			declared[c.ID] = c.Evidence
		}
	}
	if len(declared) == 0 {
		t.Fatal("the set loads no manual control, so this assertion proves nothing")
	}
	lists := 0
	for _, keys := range declared {
		if len(keys) > 0 {
			lists++
		}
	}
	if lists == 0 {
		t.Fatal("no manual control declares an evidence list, so this assertion proves nothing")
	}
	var rep struct {
		Results []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			Evidence []struct {
				Fact   string `json:"fact"`
				Status string `json:"status"`
			} `json:"evidence"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatalf("parse results: %v", err)
	}
	checked := 0
	for _, r := range rep.Results {
		keys, isManual := declared[r.ID]
		if !isManual || r.Status != "MANUAL" {
			continue
		}
		checked++
		// T-6/EV-5 (LOW-5, as internal/controls' fixture gate does it): a
		// setting key emits one entry PER SIDE, so every side is kept rather
		// than the last one overwriting the rest. No manual control names a
		// setting today and the lint rule does not forbid one, which is
		// exactly when a gate keyed by fact alone would quietly stop checking.
		read := map[string][]string{}
		for _, ev := range r.Evidence {
			read[ev.Fact] = append(read[ev.Fact], ev.Status)
		}
		for _, k := range keys {
			sides := read[k]
			if len(sides) == 0 {
				t.Errorf("%s: the MANUAL row does not carry its declared evidence %s", r.ID, k)
				continue
			}
			for _, status := range sides {
				if status == "missing" {
					t.Errorf("%s: MANUAL evidence %s is missing from the snapshot; the row names a fact it cannot show", r.ID, k)
				}
			}
		}
	}
	if checked != len(declared) {
		t.Errorf("%d of the %d manual controls produced a MANUAL row on this snapshot; every one of them must, or this assertion covers less than it claims", checked, len(declared))
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
	// R26: full-pass.json must produce exactly the sixty-four embedded
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
		"muster.service.finger_disabled":         "PASS",
		"muster.service.rservices_disabled":      "PASS",
		"muster.service.dos_services_disabled":   "PASS",
		"muster.service.nfs_server_disabled":     "PASS",
		"muster.service.automount_disabled":      "PASS",
		"muster.service.rpcbind_disabled":        "PASS",
		"muster.service.nis_disabled":            "PASS",
		"muster.service.tftp_talk_disabled":      "PASS",
		"muster.service.snmp_disabled":           "PASS",
		"muster.file.ip_port_restriction":        "PASS",
		"muster.log.time_sync":                   "PASS",
		"muster.log.syslog_policy":               "PASS",
		"muster.service.nfs_export_access":       "PASS",
		"muster.service.snmp_version":            "PASS",
		"muster.service.snmp_community_strength": "PASS",
		"muster.service.snmp_access_control":     "PASS",
		"muster.patch.security_updates":          "PASS",
		"muster.service.ftp_anonymous":           "PASS",
		"muster.service.ftp_banner":              "PASS",
		"muster.service.ftp_unencrypted":         "PASS",
		"muster.service.ftpusers_permissions":    "PASS",
		"muster.service.ftpusers_root":           "PASS",
		"muster.service.mail_expn_vrfy":          "PASS",
		"muster.service.mail_user_execution":     "MANUAL",
		"muster.service.mail_relay":              "MANUAL",
		"muster.service.mail_version":            "MANUAL",
		"muster.service.dns_zone_transfer":       "PASS",
		"muster.service.dns_dynamic_update":      "PASS",
		"muster.service.dns_version":             "MANUAL",
	})
	assertManualEvidenceIsPresent(t, out1.Bytes())

	var table bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--color", "never"}, &table, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	if !bytes.Contains(table.Bytes(), []byte("muster.account.root_remote_login")) || bytes.Contains(table.Bytes(), []byte("\x1b")) {
		t.Errorf("table output:\n%s", table.String())
	}

	// R26: full-fail.json flips only root_remote_login to FAIL; the other
	// sixty-three controls are unchanged from full-pass.json.
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
		"muster.service.finger_disabled":         "FAIL",
		"muster.service.rservices_disabled":      "FAIL",
		"muster.service.dos_services_disabled":   "FAIL",
		"muster.service.nfs_server_disabled":     "FAIL",
		"muster.service.automount_disabled":      "FAIL",
		"muster.service.rpcbind_disabled":        "FAIL",
		"muster.service.nis_disabled":            "FAIL",
		"muster.service.tftp_talk_disabled":      "FAIL",
		"muster.service.snmp_disabled":           "FAIL",
		"muster.file.ip_port_restriction":        "PASS",
		"muster.log.time_sync":                   "PASS",
		"muster.log.syslog_policy":               "PASS",
		"muster.service.nfs_export_access":       "PASS",
		"muster.service.snmp_version":            "PASS",
		"muster.service.snmp_community_strength": "PASS",
		"muster.service.snmp_access_control":     "PASS",
		"muster.patch.security_updates":          "PASS",
		"muster.service.ftp_anonymous":           "PASS",
		"muster.service.ftp_banner":              "PASS",
		"muster.service.ftp_unencrypted":         "PASS",
		"muster.service.ftpusers_permissions":    "PASS",
		"muster.service.ftpusers_root":           "PASS",
		"muster.service.mail_expn_vrfy":          "PASS",
		"muster.service.mail_user_execution":     "MANUAL",
		"muster.service.mail_relay":              "MANUAL",
		"muster.service.mail_version":            "MANUAL",
		"muster.service.dns_zone_transfer":       "PASS",
		"muster.service.dns_dynamic_update":      "PASS",
		"muster.service.dns_version":             "MANUAL",
	})
	assertManualEvidenceIsPresent(t, failJSON.Bytes())

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
