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

// stockUbuntu2204 is the verdict table of spec §5 (B-10): what a stock Ubuntu
// 22.04 host — BIOS, a plain swap file, no separate /tmp or /var, sysrq 176,
// suid_dumpable 2, apport's core pattern, the distribution's blacklists only —
// reads for the nineteen controls beyond the guide. The snapshot beside it
// carries that host's facts; a verdict that moves is a defect in the control
// or in the collector shape the snapshot copies, and this table is what
// decides which.
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
}

// B-11: one synthetic snapshot of the stock host pins all nineteen verdicts at
// once. A per-control fixture proves a clause; only a whole-host snapshot
// proves that the nineteen together say what the spec predicts a real stock
// host says, which is what the lab run is compared against.
//
// SCOPE: the snapshot carries the facts of the six collectors of plan 3B and
// env.container, and nothing else. The other 68 controls are evaluated with it
// — Evaluate takes the whole embedded set, and running only nineteen of them
// would not prove that the beyond scope is reached at all — but their results
// are ERROR(missing_fact) for the keys the snapshot omits and are deliberately
// not asserted. The one thing asserted about them is that they are not in the
// beyond scope, by the count check below.
func TestStockUbuntu2204PinsTheNineteenBeyondVerdicts(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := loadFixture(t, filepath.Join(hostRoot, "ubuntu-22.04-stock.json"))

	results := check.Evaluate(snap, set, reg, check.Options{})
	got := make(map[string]check.Result, len(results))
	for _, r := range results {
		got[r.ID] = r
	}

	// Every beyond control of the set is in the table and every table row is a
	// control of the set: a twentieth control beyond the guide has to state
	// what this host reads for it rather than slip past unasserted.
	var beyond []string
	for _, c := range set.Controls {
		if c.Category == "beyond" {
			beyond = append(beyond, c.ID)
		}
	}
	sort.Strings(beyond)
	if len(beyond) != len(stockUbuntu2204) {
		t.Errorf("the set has %d controls beyond the guide, the stock table names %d: %s",
			len(beyond), len(stockUbuntu2204), strings.Join(beyond, " "))
	}
	for _, id := range beyond {
		if _, ok := stockUbuntu2204[id]; !ok {
			t.Errorf("%s is beyond the guide and the stock table does not say what this host reads for it", id)
		}
	}

	for _, id := range sortedKeys(stockUbuntu2204) {
		want := stockUbuntu2204[id]
		r, ok := got[id]
		if !ok {
			t.Errorf("%s: the set has no such control", id)
			continue
		}
		if r.Status != want {
			t.Errorf("%s: %s (%s: %s), want %s", id, r.Status, r.ReasonCode, r.Reason, want)
		}
		// B-10 again, as its own assertion: a beyond control that cannot be
		// decided on a host whose facts are all ok is a collector or control
		// defect, and reading the table alone would hide it behind the status
		// it happened to expect.
		if r.Status == check.ERROR {
			t.Errorf("%s: ERROR (%s: %s) on a stock host every fact of which was collected", id, r.ReasonCode, r.Reason)
		}
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
