package controls_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// hostRoot holds the whole-host snapshots, one file per environment. They sit
// beside the per-control fixtures but outside every fixture glob, which is
// keyed on a control id (`testdata/<id>/*.json`), so the fixture harness, the
// mutation test and `controls lint` never see them.
const hostRoot = fixtureRoot + "/_hosts"

// stockUbuntu2204 is the verdict table of spec §5 (B-10) and of the 3C-1
// spec §4: what a stock Ubuntu 22.04 host — BIOS, a plain swap file, no
// separate /tmp or /var, sysrq 176, suid_dumpable 2, apport's core pattern,
// the distribution's blacklists only, no auditd, no AIDE, rsyslog writing
// locally, sudo's compiled-in syslog, and `--deep` finding only the two
// conffiles the installer rewrites — reads for the controls beyond the
// guide. The snapshot beside it carries that host's facts; a verdict that
// moves is a defect in the control or in the collector shape the snapshot
// copies, and this table is what decides which.
var stockUbuntu2204 = map[string]check.Status{
	"muster.beyond.kernel_pointer_exposure":             check.PASS,          // 1: kptr 1, dmesg 1
	"muster.beyond.ptrace_restriction":                  check.PASS,          // 2: yama 1, perf 4
	"muster.beyond.unprivileged_bpf_restricted":         check.FAIL,          // 3: bpf_jit_harden 0
	"muster.beyond.aslr_and_link_protection":            check.PASS,          // 4: 2/1/1/1/2
	"muster.beyond.sysrq_restricted":                    check.FAIL,          // 5: 176
	"muster.beyond.core_dump_policy":                    check.WARN,          // 6: apport's pipe, partial
	"muster.beyond.suid_dumpable_disabled":              check.FAIL,          // 7: 2
	"muster.beyond.bootloader_config_permissions":       check.FAIL,          // 8: 0644
	"muster.beyond.bootloader_password":                 check.FAIL,          // 9: no pbkdf2 hash
	"muster.beyond.secure_boot_enabled":                 check.NotApplicable, // 10: BIOS
	"muster.beyond.separate_partitions":                 check.WARN,          // 11: none of the six, partial
	"muster.beyond.tmp_mount_options":                   check.NotApplicable, // 12: /tmp is not separate
	"muster.beyond.var_tmp_mount_options":               check.NotApplicable, // 13: /var/tmp is not separate
	"muster.beyond.dev_shm_mount_options":               check.FAIL,          // 14: nosuid,nodev, no noexec
	"muster.beyond.home_mount_options":                  check.NotApplicable, // 15: /home is not separate
	"muster.beyond.swap_encrypted":                      check.FAIL,          // 16: a plain swap file
	"muster.beyond.uncommon_filesystems_disabled":       check.FAIL,          // 17: six modules loadable
	"muster.beyond.usb_storage_disabled":                check.FAIL,          // 18: loadable
	"muster.beyond.uncommon_network_protocols_disabled": check.FAIL,          // 19: four modules loadable
	"muster.beyond.auditd_active":                       check.FAIL,          // 3C-1: no auditd
	"muster.beyond.audit_rules_loaded":                  check.NotApplicable, // 3C-1: gate, auditd not installed
	"muster.beyond.audit_immutable":                     check.NotApplicable, // 3C-1: gate
	"muster.beyond.audit_disk_actions":                  check.NotApplicable, // 3C-1: gate
	"muster.beyond.audit_log_permissions":               check.NotApplicable, // 3C-1: gate
	"muster.beyond.remote_log_forwarding":               check.FAIL,          // 3C-1: nothing leaves the host
	"muster.beyond.sudo_logging":                        check.PASS,          // 3C-1: sudo's default syslog
	"muster.beyond.file_integrity_tool":                 check.FAIL,          // 3C-1: no tool
	"muster.beyond.package_files_unmodified":            check.PASS,          // 3C-1: --deep, only conffiles differ
}

// stockEL9 is the 3C-1 spec's EL9 reading (§4): a stock Rocky 9 install —
// auditd installed, enabled and running with the shipped rules.d/audit.rules,
// which carries control lines only (auditctl -l says "No rules"), no -e 2,
// upstream auditd.conf (syslog at space_left, suspend at admin_space_left,
// disk_full and disk_error), the 0700 log directory and 0600 log, no AIDE,
// rsyslog writing locally, sudo's default syslog, and rpm -Va finding only
// the installer's chrony.conf among the files rpm tracks. The snapshot
// carries env, the header and the 3C-1 facts only, so the table names the
// nine 3C-1 controls and nothing else.
var stockEL9 = map[string]check.Status{
	"muster.beyond.auditd_active":            check.PASS, // installed, active, enabled
	"muster.beyond.audit_rules_loaded":       check.FAIL, // No rules; rules.d has control lines only
	"muster.beyond.audit_immutable":          check.FAIL, // enabled 1, no -e 2
	"muster.beyond.audit_disk_actions":       check.FAIL, // upstream suspend ×3
	"muster.beyond.audit_log_permissions":    check.PASS, // 0600 root in 0700 root
	"muster.beyond.remote_log_forwarding":    check.FAIL, // nothing leaves the host
	"muster.beyond.sudo_logging":             check.PASS, // sudo's default syslog
	"muster.beyond.file_integrity_tool":      check.FAIL, // no AIDE on a stock install
	"muster.beyond.package_files_unmodified": check.PASS, // --deep, only a conffile differs
}

// B-11 and I-10: one synthetic snapshot per stock host pins its verdicts
// at once. A per-control fixture proves a clause; only a whole-host snapshot
// proves that the controls together say what the spec predicts a real stock
// host says, which is what the lab run is compared against.
//
// SCOPE: the Ubuntu snapshot carries the facts of the collectors the beyond
// controls read and env.container, and nothing else; the EL9 snapshot
// carries only the 3C-1 facts. The whole embedded set is evaluated against
// each — Evaluate takes the whole set, and running only the tabled controls
// would not prove that the beyond scope is reached at all — but the other
// controls' results are ERROR(missing_fact) for the keys a snapshot omits
// and are deliberately not asserted: the guide controls on both snapshots,
// and on the EL9 one the 3B controls as well. What is asserted is that the
// Ubuntu table names every control beyond the guide, and that no tabled
// control reads ERROR.
func TestStockHostsPinTheBeyondVerdicts(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}

	// Every beyond control of the set is in the Ubuntu table and every table
	// row is a control of the set: a new control beyond the guide has to
	// state what this host reads for it rather than slip past unasserted.
	var beyond []string
	for _, c := range set.Controls {
		if c.Category == "beyond" {
			beyond = append(beyond, c.ID)
		}
	}
	sort.Strings(beyond)
	if len(beyond) != len(stockUbuntu2204) {
		t.Errorf("the set has %d controls beyond the guide, the stock Ubuntu table names %d: %s",
			len(beyond), len(stockUbuntu2204), strings.Join(beyond, " "))
	}
	for _, id := range beyond {
		if _, ok := stockUbuntu2204[id]; !ok {
			t.Errorf("%s is beyond the guide and the stock Ubuntu table does not say what this host reads for it", id)
		}
	}
	if len(stockEL9) != 9 {
		t.Errorf("the stock EL9 table names %d controls, want the nine of 3C-1", len(stockEL9))
	}

	for _, host := range []struct {
		file  string
		table map[string]check.Status
	}{
		{"ubuntu-22.04-stock.json", stockUbuntu2204},
		{"el9-stock.json", stockEL9},
	} {
		t.Run(host.file, func(t *testing.T) {
			snap, _ := loadFixture(t, filepath.Join(hostRoot, host.file))
			results := check.Evaluate(snap, set, reg, check.Options{})
			got := make(map[string]check.Result, len(results))
			for _, r := range results {
				got[r.ID] = r
			}
			for _, id := range sortedKeys(host.table) {
				want := host.table[id]
				r, ok := got[id]
				if !ok {
					t.Errorf("%s: the set has no such control", id)
					continue
				}
				if r.Status != want {
					t.Errorf("%s: %s (%s: %s), want %s", id, r.Status, r.ReasonCode, r.Reason, want)
				}
				// B-10 again, as its own assertion: a tabled control that
				// cannot be decided on a host whose facts are all ok is a
				// collector or control defect, and reading the table alone
				// would hide it behind the status it happened to expect.
				if r.Status == check.ERROR {
					t.Errorf("%s: ERROR (%s: %s) on a stock host every fact of which was collected", id, r.ReasonCode, r.Reason)
				}
			}
		})
	}
}

func sortedKeys(m map[string]check.Status) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
