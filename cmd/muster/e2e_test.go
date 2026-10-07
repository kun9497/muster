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
		"muster.beyond.kernel_pointer_exposure":             "PASS",
		"muster.beyond.ptrace_restriction":                  "PASS",
		"muster.beyond.unprivileged_bpf_restricted":         "PASS",
		"muster.beyond.aslr_and_link_protection":            "PASS",
		"muster.beyond.sysrq_restricted":                    "PASS",
		"muster.beyond.core_dump_policy":                    "PASS",
		"muster.beyond.suid_dumpable_disabled":              "PASS",
		"muster.beyond.bootloader_config_permissions":       "PASS",
		"muster.beyond.bootloader_password":                 "PASS",
		"muster.beyond.secure_boot_enabled":                 "PASS",
		"muster.beyond.separate_partitions":                 "PASS",
		"muster.beyond.tmp_mount_options":                   "PASS",
		"muster.beyond.var_tmp_mount_options":               "PASS",
		"muster.beyond.dev_shm_mount_options":               "PASS",
		"muster.beyond.home_mount_options":                  "PASS",
		"muster.beyond.swap_encrypted":                      "PASS",
		"muster.beyond.uncommon_filesystems_disabled":       "PASS",
		"muster.beyond.usb_storage_disabled":                "PASS",
		"muster.beyond.uncommon_network_protocols_disabled": "PASS",
		"muster.beyond.auditd_active":                       "PASS",
		"muster.beyond.audit_rules_loaded":                  "PASS",
		"muster.beyond.audit_immutable":                     "PASS",
		"muster.beyond.audit_disk_actions":                  "PASS",
		"muster.beyond.audit_log_permissions":               "PASS",
		"muster.beyond.remote_log_forwarding":               "PASS",
		"muster.beyond.sudo_logging":                        "PASS",
		"muster.beyond.file_integrity_tool":                 "PASS",
		"muster.beyond.package_files_unmodified":            "MANUAL",
		"muster.beyond.account_inactivity_lock":             "PASS",
		"muster.beyond.sudo_nopasswd_all":                   "PASS",
		"muster.beyond.file_capabilities_declared":          "MANUAL",
		"muster.beyond.root_unit_exec_writable":             "PASS",
		"muster.beyond.ld_so_preload_empty":                 "PASS",
		"muster.beyond.container_runtime_access":            "PASS",
		"muster.beyond.root_authorized_keys":                "PASS",
		"muster.beyond.ssh_key_quality":                     "PASS",
		"muster.beyond.exposed_listeners_allowed":           "PASS",
		"muster.beyond.listeners_packaged":                  "PASS",
		"muster.beyond.no_deleted_executables":              "PASS",
		"muster.beyond.ip_forwarding_disabled":              "PASS",
		"muster.beyond.ipv6_forwarding_disabled":            "PASS",
		"muster.beyond.icmp_redirects_ignored":              "PASS",
		"muster.beyond.ipv6_redirects_ignored":              "PASS",
		"muster.beyond.source_routing_rejected":             "PASS",
		"muster.beyond.ipv6_source_routing_rejected":        "PASS",
		"muster.beyond.reverse_path_filtering":              "PASS",
		"muster.beyond.icmp_broadcast_and_bogus_ignored":    "PASS",
		"muster.beyond.syn_cookies_enabled":                 "PASS",
		"muster.beyond.ipv6_router_advertisements_ignored":  "PASS",
		"muster.account.root_remote_login":                  "WAIVED",
		"muster.account.password_policy":                    "PASS",
		"muster.file.passwd_permissions":                    "PASS",
		"muster.file.hosts_permissions":                     "PASS",
		"muster.file.services_permissions":                  "PASS",
		"muster.file.hosts_lpd_permissions":                 "PASS",
		"muster.service.telnet_disabled":                    "PASS",
		"muster.file.world_writable":                        "MANUAL",
		"muster.file.unowned_files":                         "MANUAL",
		"muster.file.suid_sgid":                             "MANUAL",
		"muster.file.suid_sgid_unverified":                  "MANUAL",
		"muster.file.hidden_entries":                        "MANUAL",
		"muster.account.shadow_passwords":                   "PASS",
		"muster.account.root_only_uid_zero":                 "PASS",
		"muster.account.primary_group_exists":               "PASS",
		"muster.account.unique_uids":                        "PASS",
		"muster.account.system_account_shells":              "PASS",
		"muster.account.unnecessary_accounts":               "PASS",
		"muster.account.admin_group_minimal":                "PASS",
		"muster.account.password_hash_algorithm":            "PASS",
		"muster.file.shadow_permissions":                    "PASS",
		"muster.service.ftp_account_shell":                  "PASS",
		"muster.account.lockout_threshold":                  "PASS",
		"muster.account.su_restricted":                      "PASS",
		"muster.account.session_timeout":                    "PASS",
		"muster.service.login_banner":                       "PASS",
		"muster.account.root_home_and_path":                 "PASS",
		"muster.account.umask_policy":                       "PASS",
		"muster.file.env_file_permissions":                  "PASS",
		"muster.file.dev_no_stale_files":                    "PASS",
		"muster.file.rhosts_forbidden":                      "PASS",
		"muster.file.home_dir_permissions":                  "PASS",
		"muster.file.home_dir_exists":                       "PASS",
		"muster.file.startup_script_permissions":            "PASS",
		"muster.file.syslog_conf_permissions":               "PASS",
		"muster.file.inetd_conf_permissions":                "PASS",
		"muster.account.cron_permissions":                   "PASS",
		"muster.account.sudoers_permissions":                "PASS",
		"muster.file.log_dir_permissions":                   "PASS",
		"muster.service.finger_disabled":                    "WAIVED",
		"muster.service.rservices_disabled":                 "WAIVED",
		"muster.service.dos_services_disabled":              "WAIVED",
		"muster.service.nfs_server_disabled":                "WAIVED",
		"muster.service.automount_disabled":                 "WAIVED",
		"muster.service.rpcbind_disabled":                   "WAIVED",
		"muster.service.nis_disabled":                       "WAIVED",
		"muster.service.tftp_talk_disabled":                 "WAIVED",
		"muster.service.snmp_disabled":                      "WAIVED",
		"muster.file.ip_port_restriction":                   "PASS",
		"muster.log.time_sync":                              "PASS",
		"muster.log.syslog_policy":                          "PASS",
		"muster.service.nfs_export_access":                  "PASS",
		"muster.service.snmp_version":                       "PASS",
		"muster.service.snmp_community_strength":            "PASS",
		"muster.service.snmp_access_control":                "PASS",
		"muster.patch.security_updates":                     "PASS",
		"muster.service.ftp_anonymous":                      "PASS",
		"muster.service.ftp_banner":                         "PASS",
		"muster.service.ftp_unencrypted":                    "PASS",
		"muster.service.ftpusers_permissions":               "PASS",
		"muster.service.ftpusers_root":                      "PASS",
		"muster.service.mail_expn_vrfy":                     "PASS",
		"muster.service.mail_user_execution":                "MANUAL",
		"muster.service.mail_relay":                         "MANUAL",
		"muster.service.mail_version":                       "MANUAL",
		"muster.service.dns_zone_transfer":                  "PASS",
		"muster.service.dns_dynamic_update":                 "PASS",
		"muster.service.dns_version":                        "MANUAL",
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
	// R26: full-pass.json must produce exactly the one hundred and seventeen embedded
	// controls' documented statuses, not merely "some PASS rows appear
	// somewhere in the output".
	assertStatuses(t, out1.Bytes(), fullPassWant())
	assertManualEvidenceIsPresent(t, out1.Bytes())

	var table bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--color", "never"}, &table, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	if !bytes.Contains(table.Bytes(), []byte("muster.account.root_remote_login")) || bytes.Contains(table.Bytes(), []byte("\x1b")) {
		t.Errorf("table output:\n%s", table.String())
	}

	// R26: full-fail.json flips root_remote_login and the nine 2G
	// *_disabled services to FAIL, and its PermitRootLogin yes opens
	// root_authorized_keys' gate (NOT_APPLICABLE on full-pass.json, PASS
	// here); the other one hundred and six controls are unchanged from
	// full-pass.json.
	var failJSON bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--format", "json"}, &failJSON, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	assertStatuses(t, failJSON.Bytes(), fullFailWant())
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

// fullPassWant is every embedded control's status on testdata/full-pass.json
// (R26), one source for the full-set test and the profile tests that filter it
// (Z-26).
func fullPassWant() map[string]string {
	return map[string]string{
		"muster.beyond.kernel_pointer_exposure":             "PASS",
		"muster.beyond.ptrace_restriction":                  "PASS",
		"muster.beyond.unprivileged_bpf_restricted":         "PASS",
		"muster.beyond.aslr_and_link_protection":            "PASS",
		"muster.beyond.sysrq_restricted":                    "PASS",
		"muster.beyond.core_dump_policy":                    "PASS",
		"muster.beyond.suid_dumpable_disabled":              "PASS",
		"muster.beyond.bootloader_config_permissions":       "PASS",
		"muster.beyond.bootloader_password":                 "PASS",
		"muster.beyond.secure_boot_enabled":                 "PASS",
		"muster.beyond.separate_partitions":                 "PASS",
		"muster.beyond.tmp_mount_options":                   "PASS",
		"muster.beyond.var_tmp_mount_options":               "PASS",
		"muster.beyond.dev_shm_mount_options":               "PASS",
		"muster.beyond.home_mount_options":                  "PASS",
		"muster.beyond.swap_encrypted":                      "PASS",
		"muster.beyond.uncommon_filesystems_disabled":       "PASS",
		"muster.beyond.usb_storage_disabled":                "PASS",
		"muster.beyond.uncommon_network_protocols_disabled": "PASS",
		"muster.beyond.auditd_active":                       "PASS",
		"muster.beyond.audit_rules_loaded":                  "PASS",
		"muster.beyond.audit_immutable":                     "PASS",
		"muster.beyond.audit_disk_actions":                  "PASS",
		"muster.beyond.audit_log_permissions":               "PASS",
		"muster.beyond.remote_log_forwarding":               "PASS",
		"muster.beyond.sudo_logging":                        "PASS",
		"muster.beyond.file_integrity_tool":                 "PASS",
		"muster.beyond.package_files_unmodified":            "MANUAL",
		"muster.beyond.account_inactivity_lock":             "PASS",
		"muster.beyond.sudo_nopasswd_all":                   "PASS",
		"muster.beyond.file_capabilities_declared":          "MANUAL",
		"muster.beyond.root_unit_exec_writable":             "PASS",
		"muster.beyond.ld_so_preload_empty":                 "PASS",
		"muster.beyond.container_runtime_access":            "PASS",
		"muster.beyond.root_authorized_keys":                "NOT_APPLICABLE",
		"muster.beyond.ssh_key_quality":                     "PASS",
		"muster.beyond.exposed_listeners_allowed":           "PASS",
		"muster.beyond.listeners_packaged":                  "PASS",
		"muster.beyond.no_deleted_executables":              "PASS",
		"muster.beyond.ip_forwarding_disabled":              "PASS",
		"muster.beyond.ipv6_forwarding_disabled":            "PASS",
		"muster.beyond.icmp_redirects_ignored":              "PASS",
		"muster.beyond.ipv6_redirects_ignored":              "PASS",
		"muster.beyond.source_routing_rejected":             "PASS",
		"muster.beyond.ipv6_source_routing_rejected":        "PASS",
		"muster.beyond.reverse_path_filtering":              "PASS",
		"muster.beyond.icmp_broadcast_and_bogus_ignored":    "PASS",
		"muster.beyond.syn_cookies_enabled":                 "PASS",
		"muster.beyond.ipv6_router_advertisements_ignored":  "PASS",
		"muster.account.root_remote_login":                  "PASS",
		"muster.account.password_policy":                    "PASS",
		"muster.file.passwd_permissions":                    "PASS",
		"muster.file.hosts_permissions":                     "PASS",
		"muster.file.services_permissions":                  "PASS",
		"muster.file.hosts_lpd_permissions":                 "PASS",
		"muster.service.telnet_disabled":                    "PASS",
		"muster.file.world_writable":                        "MANUAL",
		"muster.file.unowned_files":                         "MANUAL",
		"muster.file.suid_sgid":                             "MANUAL",
		"muster.file.suid_sgid_unverified":                  "MANUAL",
		"muster.file.hidden_entries":                        "MANUAL",
		"muster.account.shadow_passwords":                   "PASS",
		"muster.account.root_only_uid_zero":                 "PASS",
		"muster.account.primary_group_exists":               "PASS",
		"muster.account.unique_uids":                        "PASS",
		"muster.account.system_account_shells":              "PASS",
		"muster.account.unnecessary_accounts":               "PASS",
		"muster.account.admin_group_minimal":                "PASS",
		"muster.account.password_hash_algorithm":            "PASS",
		"muster.file.shadow_permissions":                    "PASS",
		"muster.service.ftp_account_shell":                  "PASS",
		"muster.account.lockout_threshold":                  "PASS",
		"muster.account.su_restricted":                      "PASS",
		"muster.account.session_timeout":                    "PASS",
		"muster.service.login_banner":                       "PASS",
		"muster.account.root_home_and_path":                 "PASS",
		"muster.account.umask_policy":                       "PASS",
		"muster.file.env_file_permissions":                  "PASS",
		"muster.file.dev_no_stale_files":                    "PASS",
		"muster.file.rhosts_forbidden":                      "PASS",
		"muster.file.home_dir_permissions":                  "PASS",
		"muster.file.home_dir_exists":                       "PASS",
		"muster.file.startup_script_permissions":            "PASS",
		"muster.file.syslog_conf_permissions":               "PASS",
		"muster.file.inetd_conf_permissions":                "PASS",
		"muster.account.cron_permissions":                   "PASS",
		"muster.account.sudoers_permissions":                "PASS",
		"muster.file.log_dir_permissions":                   "PASS",
		"muster.service.finger_disabled":                    "PASS",
		"muster.service.rservices_disabled":                 "PASS",
		"muster.service.dos_services_disabled":              "PASS",
		"muster.service.nfs_server_disabled":                "PASS",
		"muster.service.automount_disabled":                 "PASS",
		"muster.service.rpcbind_disabled":                   "PASS",
		"muster.service.nis_disabled":                       "PASS",
		"muster.service.tftp_talk_disabled":                 "PASS",
		"muster.service.snmp_disabled":                      "PASS",
		"muster.file.ip_port_restriction":                   "PASS",
		"muster.log.time_sync":                              "PASS",
		"muster.log.syslog_policy":                          "PASS",
		"muster.service.nfs_export_access":                  "PASS",
		"muster.service.snmp_version":                       "PASS",
		"muster.service.snmp_community_strength":            "PASS",
		"muster.service.snmp_access_control":                "PASS",
		"muster.patch.security_updates":                     "PASS",
		"muster.service.ftp_anonymous":                      "PASS",
		"muster.service.ftp_banner":                         "PASS",
		"muster.service.ftp_unencrypted":                    "PASS",
		"muster.service.ftpusers_permissions":               "PASS",
		"muster.service.ftpusers_root":                      "PASS",
		"muster.service.mail_expn_vrfy":                     "PASS",
		"muster.service.mail_user_execution":                "MANUAL",
		"muster.service.mail_relay":                         "MANUAL",
		"muster.service.mail_version":                       "MANUAL",
		"muster.service.dns_zone_transfer":                  "PASS",
		"muster.service.dns_dynamic_update":                 "PASS",
		"muster.service.dns_version":                        "MANUAL",
	}
}

// fullFailWant is every embedded control's status on testdata/full-fail.json
// (R26), one source for the full-set test and the profile tests that filter it
// (Z-26).
func fullFailWant() map[string]string {
	return map[string]string{
		"muster.beyond.kernel_pointer_exposure":             "PASS",
		"muster.beyond.ptrace_restriction":                  "PASS",
		"muster.beyond.unprivileged_bpf_restricted":         "PASS",
		"muster.beyond.aslr_and_link_protection":            "PASS",
		"muster.beyond.sysrq_restricted":                    "PASS",
		"muster.beyond.core_dump_policy":                    "PASS",
		"muster.beyond.suid_dumpable_disabled":              "PASS",
		"muster.beyond.bootloader_config_permissions":       "PASS",
		"muster.beyond.bootloader_password":                 "PASS",
		"muster.beyond.secure_boot_enabled":                 "PASS",
		"muster.beyond.separate_partitions":                 "PASS",
		"muster.beyond.tmp_mount_options":                   "PASS",
		"muster.beyond.var_tmp_mount_options":               "PASS",
		"muster.beyond.dev_shm_mount_options":               "PASS",
		"muster.beyond.home_mount_options":                  "PASS",
		"muster.beyond.swap_encrypted":                      "PASS",
		"muster.beyond.uncommon_filesystems_disabled":       "PASS",
		"muster.beyond.usb_storage_disabled":                "PASS",
		"muster.beyond.uncommon_network_protocols_disabled": "PASS",
		"muster.beyond.auditd_active":                       "PASS",
		"muster.beyond.audit_rules_loaded":                  "PASS",
		"muster.beyond.audit_immutable":                     "PASS",
		"muster.beyond.audit_disk_actions":                  "PASS",
		"muster.beyond.audit_log_permissions":               "PASS",
		"muster.beyond.remote_log_forwarding":               "PASS",
		"muster.beyond.sudo_logging":                        "PASS",
		"muster.beyond.file_integrity_tool":                 "PASS",
		"muster.beyond.package_files_unmodified":            "MANUAL",
		"muster.beyond.account_inactivity_lock":             "PASS",
		"muster.beyond.sudo_nopasswd_all":                   "PASS",
		"muster.beyond.file_capabilities_declared":          "MANUAL",
		"muster.beyond.root_unit_exec_writable":             "PASS",
		"muster.beyond.ld_so_preload_empty":                 "PASS",
		"muster.beyond.container_runtime_access":            "PASS",
		"muster.beyond.root_authorized_keys":                "PASS",
		"muster.beyond.ssh_key_quality":                     "PASS",
		"muster.beyond.exposed_listeners_allowed":           "PASS",
		"muster.beyond.listeners_packaged":                  "PASS",
		"muster.beyond.no_deleted_executables":              "PASS",
		"muster.beyond.ip_forwarding_disabled":              "PASS",
		"muster.beyond.ipv6_forwarding_disabled":            "PASS",
		"muster.beyond.icmp_redirects_ignored":              "PASS",
		"muster.beyond.ipv6_redirects_ignored":              "PASS",
		"muster.beyond.source_routing_rejected":             "PASS",
		"muster.beyond.ipv6_source_routing_rejected":        "PASS",
		"muster.beyond.reverse_path_filtering":              "PASS",
		"muster.beyond.icmp_broadcast_and_bogus_ignored":    "PASS",
		"muster.beyond.syn_cookies_enabled":                 "PASS",
		"muster.beyond.ipv6_router_advertisements_ignored":  "PASS",
		"muster.account.root_remote_login":                  "FAIL",
		"muster.account.password_policy":                    "PASS",
		"muster.file.passwd_permissions":                    "PASS",
		"muster.file.hosts_permissions":                     "PASS",
		"muster.file.services_permissions":                  "PASS",
		"muster.file.hosts_lpd_permissions":                 "PASS",
		"muster.service.telnet_disabled":                    "PASS",
		"muster.file.world_writable":                        "MANUAL",
		"muster.file.unowned_files":                         "MANUAL",
		"muster.file.suid_sgid":                             "MANUAL",
		"muster.file.suid_sgid_unverified":                  "MANUAL",
		"muster.file.hidden_entries":                        "MANUAL",
		"muster.account.shadow_passwords":                   "PASS",
		"muster.account.root_only_uid_zero":                 "PASS",
		"muster.account.primary_group_exists":               "PASS",
		"muster.account.unique_uids":                        "PASS",
		"muster.account.system_account_shells":              "PASS",
		"muster.account.unnecessary_accounts":               "PASS",
		"muster.account.admin_group_minimal":                "PASS",
		"muster.account.password_hash_algorithm":            "PASS",
		"muster.file.shadow_permissions":                    "PASS",
		"muster.service.ftp_account_shell":                  "PASS",
		"muster.account.lockout_threshold":                  "PASS",
		"muster.account.su_restricted":                      "PASS",
		"muster.account.session_timeout":                    "PASS",
		"muster.service.login_banner":                       "PASS",
		"muster.account.root_home_and_path":                 "PASS",
		"muster.account.umask_policy":                       "PASS",
		"muster.file.env_file_permissions":                  "PASS",
		"muster.file.dev_no_stale_files":                    "PASS",
		"muster.file.rhosts_forbidden":                      "PASS",
		"muster.file.home_dir_permissions":                  "PASS",
		"muster.file.home_dir_exists":                       "PASS",
		"muster.file.startup_script_permissions":            "PASS",
		"muster.file.syslog_conf_permissions":               "PASS",
		"muster.file.inetd_conf_permissions":                "PASS",
		"muster.account.cron_permissions":                   "PASS",
		"muster.account.sudoers_permissions":                "PASS",
		"muster.file.log_dir_permissions":                   "PASS",
		"muster.service.finger_disabled":                    "FAIL",
		"muster.service.rservices_disabled":                 "FAIL",
		"muster.service.dos_services_disabled":              "FAIL",
		"muster.service.nfs_server_disabled":                "FAIL",
		"muster.service.automount_disabled":                 "FAIL",
		"muster.service.rpcbind_disabled":                   "FAIL",
		"muster.service.nis_disabled":                       "FAIL",
		"muster.service.tftp_talk_disabled":                 "FAIL",
		"muster.service.snmp_disabled":                      "FAIL",
		"muster.file.ip_port_restriction":                   "PASS",
		"muster.log.time_sync":                              "PASS",
		"muster.log.syslog_policy":                          "PASS",
		"muster.service.nfs_export_access":                  "PASS",
		"muster.service.snmp_version":                       "PASS",
		"muster.service.snmp_community_strength":            "PASS",
		"muster.service.snmp_access_control":                "PASS",
		"muster.patch.security_updates":                     "PASS",
		"muster.service.ftp_anonymous":                      "PASS",
		"muster.service.ftp_banner":                         "PASS",
		"muster.service.ftp_unencrypted":                    "PASS",
		"muster.service.ftpusers_permissions":               "PASS",
		"muster.service.ftpusers_root":                      "PASS",
		"muster.service.mail_expn_vrfy":                     "PASS",
		"muster.service.mail_user_execution":                "MANUAL",
		"muster.service.mail_relay":                         "MANUAL",
		"muster.service.mail_version":                       "MANUAL",
		"muster.service.dns_zone_transfer":                  "PASS",
		"muster.service.dns_dynamic_update":                 "PASS",
		"muster.service.dns_version":                        "MANUAL",
	}
}

// stageFiles copies testdata files into a temp dir with their relative
// layout (the waiver precedent: the CI root job runs this package as root
// and trustedFile refuses files it did not own).
func stageFiles(t *testing.T, rel ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, r := range rel {
		b, err := os.ReadFile(filepath.Join("testdata", r))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, r)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// assertSelection keeps M-17's exhaustiveness for a profile run: the
// evaluated ids are exactly want's keys with those statuses, the excluded
// ids are exactly excluded, and together they are the embedded set.
func assertSelection(t *testing.T, jsonBytes []byte, want map[string]string, excluded []string) {
	t.Helper()
	var rep struct {
		Check struct {
			Profile struct {
				Selected    int      `json:"selected"`
				Excluded    int      `json:"excluded"`
				ExcludedIDs []string `json:"excluded_ids"`
			} `json:"profile"`
		} `json:"check"`
		Results []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.ID] = r.Status
	}
	for id, st := range want {
		if got[id] != st {
			t.Errorf("%s: status %q, want %q", id, got[id], st)
		}
	}
	for id := range got {
		if _, named := want[id]; !named {
			t.Errorf("%s evaluated but not named by want", id)
		}
	}
	if strings.Join(rep.Check.Profile.ExcludedIDs, ",") != strings.Join(excluded, ",") {
		t.Errorf("excluded_ids %v, want %v", rep.Check.Profile.ExcludedIDs, excluded)
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if len(want)+len(excluded) != len(set.Controls) || rep.Check.Profile.Selected+rep.Check.Profile.Excluded != len(set.Controls) {
		t.Errorf("%d evaluated + %d excluded != %d loaded", len(want), len(excluded), len(set.Controls))
	}
}

// guideOnly splits a full-set status map into the guide's statuses and the
// sorted beyond ids, so the exclude-beyond expectations come from the one
// source the full-set test asserts (Z-26).
func guideOnly(full map[string]string) (map[string]string, []string) {
	guide := map[string]string{}
	var beyond []string
	for id, st := range full {
		if strings.HasPrefix(id, "muster.beyond.") {
			beyond = append(beyond, id)
			continue
		}
		guide[id] = st
	}
	sort.Strings(beyond)
	return guide, beyond
}

// profileReport is the slice of the report the profile tests read.
type profileReport struct {
	Check struct {
		Profile struct {
			Name        string   `json:"name"`
			Source      string   `json:"source"`
			Digest      string   `json:"digest"`
			Extends     []string `json:"extends"`
			Selected    int      `json:"selected"`
			Excluded    int      `json:"excluded"`
			ExcludedIDs []string `json:"excluded_ids"`
		} `json:"profile"`
		Tuning *struct {
			Path   string `json:"path"`
			Digest string `json:"digest"`
		} `json:"tuning"`
		Waivers struct {
			NotApplied int `json:"not_applied"`
			Unknown    int `json:"unknown"`
		} `json:"waivers"`
		Params       map[string]map[string]any    `json:"params"`
		ParamSources map[string]map[string]string `json:"param_sources"`
	} `json:"check"`
	Results []struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		Severity       string `json:"severity"`
		SeveritySource string `json:"severity_source"`
	} `json:"results"`
}

func decodeProfileReport(t *testing.T, b []byte) profileReport {
	t.Helper()
	var rep profileReport
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("stdout is not a report: %v\n%s", err, b)
	}
	return rep
}

// Spec §6: a profile that excludes every beyond control evaluates the 68
// guide controls alone, names the 49 it left out, and records the file and
// the chain it came from.
func TestCheckProfileExcludeBeyondEvaluatesTheGuideOnly(t *testing.T) {
	dir := stageFiles(t, "profiles/exclude-beyond.yaml")
	prof := filepath.Join(dir, "profiles", "exclude-beyond.yaml")
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--profile", prof, "--format", "json"}, &out, &errb); code != exitFindings {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitFindings, errb.String())
	}
	guide, beyond := guideOnly(fullFailWant())
	if len(guide) != 68 || len(beyond) != 49 {
		t.Fatalf("%d guide + %d beyond, want 68 + 49", len(guide), len(beyond))
	}
	assertSelection(t, out.Bytes(), guide, beyond)
	rep := decodeProfileReport(t, out.Bytes())
	p := rep.Check.Profile
	if p.Name != "exclude-beyond" || p.Source != "file:"+prof {
		t.Errorf("profile %q source %q, want exclude-beyond file:%s", p.Name, p.Source, prof)
	}
	if want := []string{"builtin:default", "file:" + prof}; strings.Join(p.Extends, "|") != strings.Join(want, "|") {
		t.Errorf("extends %v, want %v", p.Extends, want)
	}
	if !strings.HasPrefix(p.Digest, "sha256:") {
		t.Errorf("digest %q", p.Digest)
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--profile", prof, "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("full-pass: exit %d, want 0; stderr %q", code, errb.String())
	}
	guide, beyond = guideOnly(fullPassWant())
	assertSelection(t, out.Bytes(), guide, beyond)
}

// Spec §3/§5: a chain of two files records the child as given and the parent
// by the cleaned path it was opened at; the parent's severity entry rates
// every selected beyond row, and a guide row keeps its importance.
func TestCheckProfileChainOfTwoRecordsTheOpenedPaths(t *testing.T) {
	dir := stageFiles(t, "profiles/chain-child.yaml", "profiles/chain-base.yaml")
	child := filepath.Join(dir, "profiles", "chain-child.yaml")
	base := filepath.Clean(filepath.Join(dir, "profiles", "chain-base.yaml"))
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--profile", child, "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb.String())
	}
	rep := decodeProfileReport(t, out.Bytes())
	p := rep.Check.Profile
	if want := []string{"builtin:default", "file:" + base, "file:" + child}; strings.Join(p.Extends, "|") != strings.Join(want, "|") {
		t.Errorf("extends %v, want %v", p.Extends, want)
	}
	want := fullPassWant()
	delete(want, "muster.beyond.no_deleted_executables")
	assertSelection(t, out.Bytes(), want, []string{"muster.beyond.no_deleted_executables"})
	beyondRows, guideRows := 0, 0
	for _, r := range rep.Results {
		if strings.HasPrefix(r.ID, "muster.beyond.") {
			beyondRows++
			if r.SeveritySource != "profile" || r.Severity != "low" {
				t.Errorf("%s: severity %q from %q, want low from profile", r.ID, r.Severity, r.SeveritySource)
			}
		} else {
			guideRows++
			if r.SeveritySource != "importance" {
				t.Errorf("%s: severity_source %q, want importance", r.ID, r.SeveritySource)
			}
		}
	}
	if beyondRows != 48 || guideRows != 68 {
		t.Errorf("%d beyond rows + %d guide rows, want 48 + 68", beyondRows, guideRows)
	}
}

// Spec §4: a tuning file's value is the one in force -- tcp/80 declared turns
// the folded-http FAIL into a PASS, and the result says where the value came
// from.
func TestCheckProfileOneControlWithTuningFlipsTheVerdict(t *testing.T) {
	const id = "muster.beyond.exposed_listeners_allowed"
	snap := filepath.Join("..", "..", "controls", "testdata", id, "fail-ufw-folded-http.json")
	dir := stageFiles(t, "profiles/one-control.yaml", "tuning/ports.yaml")
	prof := filepath.Join(dir, "profiles", "one-control.yaml")
	tun := filepath.Join(dir, "tuning", "ports.yaml")
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", snap, "--profile", prof, "--tuning", tun, "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb.String())
	}
	rep := decodeProfileReport(t, out.Bytes())
	if len(rep.Results) != 1 || rep.Results[0].ID != id || rep.Results[0].Status != "PASS" {
		t.Fatalf("results %+v, want one PASS row for %s", rep.Results, id)
	}
	if rep.Check.ParamSources[id]["allowed_ports"] != "tuning" {
		t.Errorf("param_sources %v, want %s.allowed_ports from tuning", rep.Check.ParamSources, id)
	}
	if ports, ok := rep.Check.Params[id]["allowed_ports"].([]any); !ok || len(ports) != 4 {
		t.Errorf("params[%s].allowed_ports = %v, want the four tuned entries", id, rep.Check.Params[id]["allowed_ports"])
	}
	if rep.Check.Tuning == nil || rep.Check.Tuning.Path != tun || !strings.HasPrefix(rep.Check.Tuning.Digest, "sha256:") {
		t.Errorf("tuning block %+v, want path %s and a digest", rep.Check.Tuning, tun)
	}

	out.Reset()
	errb.Reset()
	if code := run([]string{"check", "--facts", snap, "--profile", prof, "--format", "json"}, &out, &errb); code != exitFindings {
		t.Fatalf("without --tuning: exit %d, want %d; stderr %q", code, exitFindings, errb.String())
	}
	rep = decodeProfileReport(t, out.Bytes())
	if len(rep.Results) != 1 || rep.Results[0].Status != "FAIL" {
		t.Errorf("without --tuning: results %+v, want one FAIL row", rep.Results)
	}
	if rep.Check.Tuning != nil || rep.Check.ParamSources[id]["allowed_ports"] != "default" {
		t.Errorf("without --tuning: tuning %+v, param_sources %v", rep.Check.Tuning, rep.Check.ParamSources)
	}
}

// Review focus 1: a tuning value for a control the profile excludes is
// warned about and dropped, never an error.
func TestCheckProfileTuningForExcludedControlWarns(t *testing.T) {
	const id = "muster.beyond.exposed_listeners_allowed"
	dir := stageFiles(t, "profiles/exclude-beyond.yaml", "tuning/excluded.yaml")
	prof := filepath.Join(dir, "profiles", "exclude-beyond.yaml")
	tun := filepath.Join(dir, "tuning", "excluded.yaml")
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--profile", prof, "--tuning", tun, "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb.String())
	}
	if want := "muster: warning: tuning parameter " + id + ".allowed_ports ignored: excluded by profile\n"; !strings.Contains(errb.String(), want) {
		t.Errorf("stderr %q lacks %q", errb.String(), want)
	}
	rep := decodeProfileReport(t, out.Bytes())
	if _, ok := rep.Check.Params[id]; ok {
		t.Errorf("check.params carries an excluded control: %v", rep.Check.Params[id])
	}
	if _, ok := rep.Check.ParamSources[id]; ok {
		t.Errorf("check.param_sources carries an excluded control: %v", rep.Check.ParamSources[id])
	}
	if rep.Check.Tuning == nil || rep.Check.Tuning.Path != tun {
		t.Errorf("tuning block %+v, want path %s", rep.Check.Tuning, tun)
	}
}

// Review focus 4: a waiver on a control the profile excludes is counted
// not_applied and warned, never unknown; the guide's FAILs still exit 1.
func TestCheckProfileWaiverOnExcludedControlIsNotApplied(t *testing.T) {
	dir := stageFiles(t, "profiles/exclude-beyond.yaml")
	prof := filepath.Join(dir, "profiles", "exclude-beyond.yaml")
	w := filepath.Join(dir, "waivers.yaml")
	body := "waivers:\n  - control: muster.beyond.no_deleted_executables\n    reason: synthetic waiver on a control the profile excludes\n    expires: 2099-12-31\n"
	if err := os.WriteFile(w, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--profile", prof, "--waivers", w, "--format", "json"}, &out, &errb); code != exitFindings {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitFindings, errb.String())
	}
	rep := decodeProfileReport(t, out.Bytes())
	if rep.Check.Waivers.NotApplied != 1 || rep.Check.Waivers.Unknown != 0 {
		t.Errorf("waivers %+v, want not_applied 1 and unknown 0", rep.Check.Waivers)
	}
	if want := "muster: warning: waiver for muster.beyond.no_deleted_executables not applied: excluded by profile\n"; !strings.Contains(errb.String(), want) {
		t.Errorf("stderr %q lacks %q", errb.String(), want)
	}
}

// Review focus 3: a name that is no built-in is refused naming the built-ins,
// never opened as a file.
func TestCheckProfileUnknownNameNamesTheBuiltins(t *testing.T) {
	for _, name := range []string{"Default", "site"} {
		var out, errb bytes.Buffer
		if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--profile", name}, &out, &errb); code != exitError {
			t.Errorf("--profile %s: exit %d, want %d", name, code, exitError)
		}
		if out.Len() != 0 {
			t.Errorf("--profile %s: stdout %q, want empty", name, out.String())
		}
		if !strings.Contains(errb.String(), "default, kisa-unix-2026") || !strings.Contains(errb.String(), `"`+name+`"`) {
			t.Errorf("--profile %s: stderr %q does not name it and the built-ins", name, errb.String())
		}
	}
}

// Spec §5: every check carries a profile block, the built-in default when no
// flag names one, and no tuning block without --tuning.
func TestCheckProfileDefaultBlock(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb.String())
	}
	var doc struct {
		Check map[string]json.RawMessage `json:"check"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Check["tuning"]; ok {
		t.Errorf("check.tuning present without --tuning: %s", doc.Check["tuning"])
	}
	p := decodeProfileReport(t, out.Bytes()).Check.Profile
	if p.Name != "default" || p.Source != "builtin" || strings.Join(p.Extends, "|") != "builtin:default" ||
		p.Selected != 117 || p.Excluded != 0 || p.ExcludedIDs == nil || len(p.ExcludedIDs) != 0 || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Errorf("profile block %+v, want default/builtin/[builtin:default]/117/0/[]", p)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc.Check["profile"], &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["excluded_ids"]) != "[]" {
		t.Errorf("excluded_ids must render as [] not null: %s", raw["excluded_ids"])
	}
}

// Review focus 5: run as root, check refuses a group-writable profile, chain
// file or tuning file, naming that path, before anything reaches stdout.
func TestCheckRootRefusesWritableProfileFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the trusted-file rule applies only to a root run; the CI root job and the lab run this as root")
	}
	dir := stageFiles(t, "profiles/chain-child.yaml", "profiles/chain-base.yaml", "tuning/ports.yaml")
	child := filepath.Join(dir, "profiles", "chain-child.yaml")
	base := filepath.Join(dir, "profiles", "chain-base.yaml")
	tun := filepath.Join(dir, "tuning", "ports.yaml")
	args := []string{"check", "--facts", "testdata/full-pass.json", "--profile", child, "--tuning", tun, "--format", "json"}
	var out, errb bytes.Buffer
	if code := run(args, &out, &errb); code != exitOK {
		t.Fatalf("all files 0600: exit %d, want 0; stderr %q", code, errb.String())
	}
	for _, p := range []string{child, base, tun} {
		if err := os.Chmod(p, 0o664); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		errb.Reset()
		code := run(args, &out, &errb)
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if code != exitError || out.Len() != 0 || !strings.Contains(errb.String(), p+" is group- or world-writable") {
			t.Errorf("%s 0664: exit %d, stdout %d bytes, stderr %q; want exit 2, empty stdout, the path named", p, code, out.Len(), errb.String())
		}
	}
}

// Spec §5: lint resolves a profile against the set it has just linted and
// says what it selects; list prints the profile's subset in its four columns.
func TestControlsLintProfileAndListProfile(t *testing.T) {
	lint := func(profileArg string) []string {
		return []string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa, "--profile", profileArg}
	}
	var out, errb bytes.Buffer
	if code := runControls(lint("default"), &out, &errb); code != exitOK {
		t.Fatalf("--profile default: exit %d; stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 117 controls") || !strings.Contains(out.String(), "ok: profile default selects 117 of 117 controls, 0 excluded\n") {
		t.Errorf("--profile default: stdout %q", out.String())
	}
	dir := stageFiles(t, "profiles/exclude-beyond.yaml")
	prof := filepath.Join(dir, "profiles", "exclude-beyond.yaml")
	out.Reset()
	errb.Reset()
	if code := runControls(lint(prof), &out, &errb); code != exitOK {
		t.Fatalf("--profile exclude-beyond: exit %d; stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "ok: profile exclude-beyond selects 68 of 117 controls, 49 excluded\n") {
		t.Errorf("--profile exclude-beyond: stdout %q", out.String())
	}
	typo := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(typo, []byte("profile: typo\ninclude: [\"muster.nothing.*\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := runControls(lint(typo), &out, &errb); code != exitError {
		t.Errorf("typo profile: exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), `"muster.nothing.*"`) || strings.Contains(out.String(), "ok: profile") {
		t.Errorf("typo profile: stdout %q stderr %q; want the pattern named and no ok: profile line", out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	if code := runControls([]string{"list", "--profile", prof}, &out, &errb); code != exitOK {
		t.Fatalf("list --profile: exit %d; stderr %q", code, errb.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 68 {
		t.Errorf("list --profile: %d lines, want 68", len(lines))
	}
	for _, l := range lines {
		if len(strings.Split(l, "\t")) != 4 || strings.HasPrefix(l, "muster.beyond.") {
			t.Errorf("list --profile: line %q", l)
		}
	}
}

// Z-21: a profile whose severity entry matches only controls it excludes is
// warned about, never refused -- lint still exits 0 and prints its line.
func TestControlsLintProfileWarningExitsZero(t *testing.T) {
	prof := filepath.Join(t.TempDir(), "sev-excluded.yaml")
	body := "profile: sev-excluded\nextends: default\nexclude: [muster.beyond.no_deleted_executables]\nseverity:\n  - { controls: muster.beyond.no_deleted_executables, level: low }\n"
	if err := os.WriteFile(prof, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa, "--profile", prof}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want 0; stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "ok: profile sev-excluded selects 116 of 117 controls, 1 excluded\n") {
		t.Errorf("stdout %q", out.String())
	}
	if want := "muster: warning: severity entry muster.beyond.no_deleted_executables matches only excluded controls\n"; !strings.Contains(errb.String(), want) {
		t.Errorf("stderr %q lacks %q", errb.String(), want)
	}
}
