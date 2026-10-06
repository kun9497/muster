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
// locally, sudo's compiled-in syslog, `--deep` finding only the two
// conffiles the installer rewrites, INACTIVE commented out in
// /etc/default/useradd, `%sudo` with a password, the four file capabilities
// their postinst declares, no /etc/ld.so.preload, no container runtime
// socket (so no runtime group with a member), sshd's compiled-in
// prohibit-password (sshd -T prints without-password), no key in root's
// authorized_keys, and no DSA or short RSA key — and, for 3C-2b (spec §5;
// Task 7 measured the lab, which is not stock, and pinned what a stock host
// shares with it), ufw installed and inactive so sshd and the
// DHCP client are exposed through the open policy, every listener packaged,
// no deleted executable, and the kernel's network defaults with systemd's
// and procps' rp_filter and source-route lines on top — reads for the
// controls beyond the guide. The snapshot beside it carries that host's facts; a verdict that
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
	"muster.beyond.account_inactivity_lock":             check.FAIL,          // 3C-2a: INACTIVE commented out, root and the user unset
	"muster.beyond.sudo_nopasswd_all":                   check.PASS,          // 3C-2a: root, %admin, %sudo, all with a password
	"muster.beyond.file_capabilities_declared":          check.PASS,          // 3C-2a: the four files postinst declares
	"muster.beyond.root_unit_exec_writable":             check.PASS,          // 3C-2a: nothing a non-root user can write
	"muster.beyond.ld_so_preload_empty":                 check.PASS,          // 3C-2a: no /etc/ld.so.preload
	"muster.beyond.container_runtime_access":            check.PASS,          // 3C-2a: no runtime socket
	"muster.beyond.root_authorized_keys":                check.PASS,          // 3C-2a: prohibit-password lets keys through, root has none
	"muster.beyond.ssh_key_quality":                     check.PASS,          // 3C-2a: the user's one ed25519 key
	"muster.beyond.exposed_listeners_allowed":           check.PASS,          // 3C-2b: ufw inactive (X-9), tcp/22 and udp/68 via open_policy, both allowed
	"muster.beyond.listeners_packaged":                  check.PASS,          // 3C-2b: every listener dpkg-owned
	"muster.beyond.no_deleted_executables":              check.PASS,          // 3C-2b: a rebooted host
	"muster.beyond.ip_forwarding_disabled":              check.PASS,          // 3C-2b: 0 (1 on a docker host)
	"muster.beyond.ipv6_forwarding_disabled":            check.PASS,          // 3C-2b: 0/0
	"muster.beyond.icmp_redirects_ignored":              check.FAIL,          // 3C-2b: accept, secure and send 1/1
	"muster.beyond.ipv6_redirects_ignored":              check.FAIL,          // 3C-2b: accept_redirects 1/1
	"muster.beyond.source_routing_rejected":             check.PASS,          // 3C-2b: 0/0
	"muster.beyond.ipv6_source_routing_rejected":        check.PASS,          // 3C-2b: 0/0
	"muster.beyond.reverse_path_filtering":              check.FAIL,          // 3C-2b: rp_filter 2/2, log_martians 0/0
	"muster.beyond.icmp_broadcast_and_bogus_ignored":    check.PASS,          // 3C-2b: 1, 1
	"muster.beyond.syn_cookies_enabled":                 check.PASS,          // 3C-2b: 1
	"muster.beyond.ipv6_router_advertisements_ignored":  check.FAIL,          // 3C-2b: accept_ra 1/1
}

// stockEL9 is the 3C-1 spec's EL9 reading (§4): a stock Rocky 9 install —
// auditd installed, enabled and running with the shipped rules.d/audit.rules,
// which carries control lines only (auditctl -l says "No rules"), no -e 2,
// upstream auditd.conf (syslog at space_left, suspend at admin_space_left,
// disk_full and disk_error), the 0700 log directory and 0600 log, no AIDE,
// rsyslog writing locally, sudo's default syslog, and rpm -Va finding only
// the installer's chrony.conf among the files rpm tracks — and the 3C-2a
// reading measured in the Rocky 9 init image (V-18, V-23): INACTIVE=-1 in
// /etc/default/useradd and root unset, `%wheel` with a password, the four
// file capabilities rpm's FILECAPS declares (iputils' arping and clockdiff,
// shadow-utils' newgidmap and newuidmap; ping carries none), no root service
// a non-root user can rewrite, no /etc/ld.so.preload, no runtime socket,
// sshd's compiled-in prohibit-password and no key at all — and the 3C-2b
// reading Task 7 measured in the same image with firewalld started:
// firewalld reads partial so the exposure verdict is MANUAL, every listener
// rpm-owned, no deleted executable, and the network sysctls as
// 50-default.conf and 50-redhat.conf persist them over the kernel's
// defaults (the runtime side is a hypothesis until an EL VM). The
// snapshot carries env, the header, the 3C-1, 3C-2a and 3C-2b facts, so the
// table names those thirty controls and nothing else.
var stockEL9 = map[string]check.Status{
	"muster.beyond.auditd_active":                      check.PASS,   // installed, active, enabled
	"muster.beyond.audit_rules_loaded":                 check.FAIL,   // No rules; rules.d has control lines only
	"muster.beyond.audit_immutable":                    check.FAIL,   // enabled 1, no -e 2
	"muster.beyond.audit_disk_actions":                 check.FAIL,   // upstream suspend ×3
	"muster.beyond.audit_log_permissions":              check.PASS,   // 0600 root in 0700 root
	"muster.beyond.remote_log_forwarding":              check.FAIL,   // nothing leaves the host
	"muster.beyond.sudo_logging":                       check.PASS,   // sudo's default syslog
	"muster.beyond.file_integrity_tool":                check.FAIL,   // no AIDE on a stock install
	"muster.beyond.package_files_unmodified":           check.PASS,   // --deep, only a conffile differs
	"muster.beyond.account_inactivity_lock":            check.FAIL,   // 3C-2a: INACTIVE=-1, root unset
	"muster.beyond.sudo_nopasswd_all":                  check.PASS,   // 3C-2a: root and %wheel, both with a password
	"muster.beyond.file_capabilities_declared":         check.PASS,   // 3C-2a: the four files FILECAPS declares
	"muster.beyond.root_unit_exec_writable":            check.PASS,   // 3C-2a: nothing a non-root user can write
	"muster.beyond.ld_so_preload_empty":                check.PASS,   // 3C-2a: no /etc/ld.so.preload
	"muster.beyond.container_runtime_access":           check.PASS,   // 3C-2a: no runtime socket
	"muster.beyond.root_authorized_keys":               check.PASS,   // 3C-2a: prohibit-password lets keys through, root has none
	"muster.beyond.ssh_key_quality":                    check.PASS,   // 3C-2a: no key at all
	"muster.beyond.exposed_listeners_allowed":          check.MANUAL, // 3C-2b: firewalld reads partial, sshd listening
	"muster.beyond.listeners_packaged":                 check.PASS,   // 3C-2b: every listener rpm-owned
	"muster.beyond.no_deleted_executables":             check.PASS,   // 3C-2b: nothing runs a deleted executable
	"muster.beyond.ip_forwarding_disabled":             check.PASS,   // 3C-2b: 0
	"muster.beyond.ipv6_forwarding_disabled":           check.PASS,   // 3C-2b: 0/0
	"muster.beyond.icmp_redirects_ignored":             check.FAIL,   // 3C-2b: accept, secure and send 1/1
	"muster.beyond.ipv6_redirects_ignored":             check.FAIL,   // 3C-2b: accept_redirects 1/1
	"muster.beyond.source_routing_rejected":            check.PASS,   // 3C-2b: 0/0
	"muster.beyond.ipv6_source_routing_rejected":       check.PASS,   // 3C-2b: 0/0
	"muster.beyond.reverse_path_filtering":             check.FAIL,   // 3C-2b: rp_filter 0/1, log_martians 0/0 (persisted hypothesis)
	"muster.beyond.icmp_broadcast_and_bogus_ignored":   check.PASS,   // 3C-2b: 1, 1
	"muster.beyond.syn_cookies_enabled":                check.PASS,   // 3C-2b: 1
	"muster.beyond.ipv6_router_advertisements_ignored": check.FAIL,   // 3C-2b: accept_ra 1/1
}

// B-11 and I-10: one synthetic snapshot per stock host pins its verdicts
// at once. A per-control fixture proves a clause; only a whole-host snapshot
// proves that the controls together say what the spec predicts a real stock
// host says, which is what the lab run is compared against.
//
// SCOPE: the Ubuntu snapshot carries the facts of the collectors the beyond
// controls read and env.container, and nothing else; the EL9 snapshot
// carries the 3C-1, the 3C-2a and the 3C-2b facts only. The whole embedded set is evaluated against
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
	if len(stockEL9) != 30 {
		t.Errorf("the stock EL9 table names %d controls, want the nine of 3C-1, the eight of 3C-2a and the thirteen of 3C-2b", len(stockEL9))
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
