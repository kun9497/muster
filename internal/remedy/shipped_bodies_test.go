//go:build linux

package remedy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/controls"
)

func shippedControl(t *testing.T, id string) *controls.Control {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := set.ByID(id)
	if !ok || c.Remediation == nil {
		t.Fatalf("no shipped remediation for %s", id)
	}
	return c
}

// pEnv is the P_ assignments a block would carry at the defaults, as
// environment entries for runBody.
func pEnv(t *testing.T, c *controls.Control) []string {
	t.Helper()
	var env []string
	for _, n := range c.Remediation.ScriptParams {
		v, ok := controls.ScriptParamValue(c.Params[n].Type, c.Params[n].Default)
		if !ok {
			t.Fatalf("%s: default of %s cannot be carried", c.ID, n)
		}
		env = append(env, "P_"+n+"="+v)
	}
	return env
}

// sysctlKeys: per key, a value its control FAILs on and a different value
// it accepts (the stricter or other accepted member). perf_event_paranoid
// fails at 1 and passes at 10: the gte arms are globs, and [1-9][0-9]* alone
// would match 1 (S-21), [2-9] alone would miss 10.
var sysctlKeys = map[string][2]string{
	"kernel.randomize_va_space": {"0", "2"}, "fs.protected_symlinks": {"0", "1"}, "fs.protected_hardlinks": {"0", "1"},
	"fs.protected_fifos": {"0", "2"}, "fs.protected_regular": {"0", "1"},
	"net.ipv4.icmp_echo_ignore_broadcasts": {"0", "1"}, "net.ipv4.icmp_ignore_bogus_error_responses": {"0", "1"},
	"net.ipv4.conf.all.accept_redirects": {"1", "0"}, "net.ipv4.conf.default.accept_redirects": {"1", "0"},
	"net.ipv4.conf.all.secure_redirects": {"1", "0"}, "net.ipv4.conf.default.secure_redirects": {"1", "0"},
	"net.ipv4.conf.all.send_redirects": {"1", "0"}, "net.ipv4.conf.default.send_redirects": {"1", "0"},
	"net.ipv4.ip_forward": {"1", "0"}, "net.ipv6.conf.all.forwarding": {"1", "0"}, "net.ipv6.conf.default.forwarding": {"1", "0"},
	"net.ipv6.conf.all.accept_redirects": {"1", "0"}, "net.ipv6.conf.default.accept_redirects": {"1", "0"},
	"net.ipv6.conf.all.accept_ra": {"1", "0"}, "net.ipv6.conf.default.accept_ra": {"1", "0"},
	"net.ipv6.conf.all.accept_source_route": {"1", "0"}, "net.ipv6.conf.default.accept_source_route": {"1", "0"},
	"kernel.kptr_restrict": {"0", "2"}, "kernel.dmesg_restrict": {"0", "1"},
	"kernel.yama.ptrace_scope": {"0", "2"}, "kernel.perf_event_paranoid": {"1", "10"},
	"net.ipv4.conf.all.rp_filter": {"0", "2"}, "net.ipv4.conf.default.rp_filter": {"0", "2"},
	"net.ipv4.conf.all.log_martians": {"0", "1"}, "net.ipv4.conf.default.log_martians": {"0", "1"},
	"net.ipv4.conf.all.accept_source_route": {"1", "0"}, "net.ipv4.conf.default.accept_source_route": {"1", "0"},
	"fs.suid_dumpable": {"2", "0"}, "net.ipv4.tcp_syncookies": {"0", "1"}, "kernel.sysrq": {"176", "0"},
	"kernel.unprivileged_bpf_disabled": {"0", "1"}, "net.core.bpf_jit_harden": {"0", "1"},
}

// companion keys are recorded and put back, never judged by their control.
var companion = map[string]string{"muster.beyond.ip_forwarding_disabled": "net.ipv4.conf.all.accept_redirects"}

// coupled keys are set by the write to an earlier key of the same list (the
// stub copies all.forwarding into default.forwarding, as the kernel does,
// S-46), so on a host failing both the body writes the first alone (E-8).
var coupled = map[string]bool{"net.ipv6.conf.default.forwarding": true}

func sysctlControls(t *testing.T) []*controls.Control {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var out []*controls.Control
	for i := range set.Controls {
		if r := set.Controls[i].Remediation; r != nil && len(r.Sysctl) > 0 {
			out = append(out, &set.Controls[i])
		}
	}
	if len(out) != 16 {
		t.Fatalf("%d controls declare sysctl, want 16", len(out))
	}
	return out
}

// seedSysctl writes the stub's state: one file per key, and a .oneway file
// for a key whose value the stub then refuses to change.
func seedSysctl(t *testing.T, st string, state, oneway map[string]string) {
	t.Helper()
	for k, v := range state {
		if err := os.WriteFile(filepath.Join(st, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range oneway {
		if err := os.WriteFile(filepath.Join(st, k+".oneway"), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sysctlValue(t *testing.T, st, k string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(st, k))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func sysctlCalls(st string) []string {
	b, err := os.ReadFile(filepath.Join(st, "calls"))
	if err != nil {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(string(b), "w ", ""))
}

// rebaseSysctlD moves a body's /etc/sysctl.d/ paths under dir.
func rebaseSysctlD(s, dir string) string { return strings.ReplaceAll(s, "/etc/sysctl.d/", dir+"/") }

// runSysctlBody seeds the stub with state, runs the body and then the
// validate with the file under a temp sysctl.d, and returns the stub's write
// calls, the file's lines and the two exit codes.
func runSysctlBody(t *testing.T, c *controls.Control, state map[string]string, oneway map[string]string) (calls, file []string, body, validate int) {
	t.Helper()
	bin, st, dir := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "sysctl", sysctlStub)
	seedSysctl(t, st, state, oneway)
	r := c.Remediation
	env := append(pEnv(t, c), "SYSCTL_STATE="+st)
	// the script runs every body under umask 077; the drop-in must still be
	// 0644, or a non-root collect reads it as an error (C3)
	if out, code := runBody(t, dir, bin, "umask 077\n"+rebaseSysctlD(r.Script, dir), env...); code != 0 {
		body = code
		t.Logf("%s body: %s", c.ID, out)
	}
	_, validate = runBody(t, dir, bin, rebaseSysctlD(r.Validate, dir), env...)
	calls = sysctlCalls(st)
	if b, err := os.ReadFile(rebaseSysctlD(r.Backup[0], dir)); err == nil {
		file = strings.Split(strings.TrimSpace(string(b)), "\n")
		if m := mode(t, rebaseSysctlD(r.Backup[0], dir)); m != "644" {
			t.Errorf("%s: the drop-in is mode %s, want 644", c.ID, m)
		}
	}
	return calls, file, body, validate
}

func TestSysctlBodiesWriteOnlyOutsideTheSet(t *testing.T) {
	needSh(t)
	for _, c := range sysctlControls(t) {
		t.Run(c.ID, func(t *testing.T) {
			judged := []string{}
			for _, k := range c.Remediation.Sysctl {
				if k != companion[c.ID] && !coupled[k] {
					judged = append(judged, k)
				}
			}
			failing, passing := map[string]string{}, map[string]string{}
			for _, k := range c.Remediation.Sysctl {
				v, ok := sysctlKeys[k]
				if !ok {
					t.Fatalf("no test values for %s", k)
				}
				failing[k], passing[k] = v[0], v[1]
			}
			if k := companion[c.ID]; k != "" {
				failing[k] = "0" // the companion is not judged: it keeps its value
			}
			calls, file, body, val := runSysctlBody(t, c, failing, nil)
			if body != 0 || val != 0 {
				t.Fatalf("failing host: body %d, validate %d", body, val)
			}
			if len(calls) < len(judged) || len(file) < len(judged) {
				t.Fatalf("failing host: %d writes %v, %d file lines %v; want one per judged, uncoupled key (%d)", len(calls), calls, len(file), file, len(judged))
			}
			calls, file, body, val = runSysctlBody(t, c, passing, nil)
			if body != 0 || val != 0 || len(calls) != 0 || len(file) != 0 {
				t.Fatalf("passing host: body %d, validate %d, writes %v, file %v; want no write and no file", body, val, calls, file)
			}
		})
	}
}

// E-8 keeps the one-way values safe: the body never writes a key that
// passes, so a host locked at 1 (or 3) is repaired on its other key.
func TestSysctlBodiesLeaveOneWayValues(t *testing.T) {
	needSh(t)
	for _, c := range []struct{ id, locked, lockedAt, other, otherFail string }{
		{"muster.beyond.unprivileged_bpf_restricted", "kernel.unprivileged_bpf_disabled", "1", "net.core.bpf_jit_harden", "0"},
		{"muster.beyond.ptrace_restriction", "kernel.yama.ptrace_scope", "3", "kernel.perf_event_paranoid", "1"},
	} {
		ctl := shippedControl(t, c.id)
		calls, _, body, val := runSysctlBody(t, ctl, map[string]string{c.locked: c.lockedAt, c.other: c.otherFail}, map[string]string{c.locked: c.lockedAt})
		if body != 0 || val != 0 {
			t.Errorf("%s: body %d, validate %d", c.id, body, val)
		}
		for _, w := range calls {
			if strings.HasPrefix(w, c.locked+"=") {
				t.Errorf("%s: wrote the locked key: %v", c.id, calls)
			}
		}
	}
}

// E-13: the forwarding body reads the companion before it writes ip_forward
// (the stub flips it on that write, as the kernel does) and writes it back
// after, at runtime and, when it read 0, as the next line of its file (S-43).
func TestIPForwardBodyPutsTheCompanionBack(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.beyond.ip_forwarding_disabled")
	calls, file, body, val := runSysctlBody(t, c, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.accept_redirects": "0"}, nil)
	if body != 0 || val != 0 {
		t.Fatalf("body %d, validate %d", body, val)
	}
	if strings.Join(calls, " ") != "net.ipv4.ip_forward=0 net.ipv4.conf.all.accept_redirects=0" {
		t.Errorf("writes %v", calls)
	}
	if strings.Join(file, "|") != "net.ipv4.ip_forward = 0|net.ipv4.conf.all.accept_redirects = 0" {
		t.Errorf("file %v", file)
	}
}

// S-43: a companion that read 1 is not persisted — a 1 in this later-sorting
// drop-in would override icmp_redirects_ignored's file at boot — and the
// kernel's flip already left it at 1, so nothing writes it.
func TestIPForwardBodyPersistsOnlyAZeroCompanion(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.beyond.ip_forwarding_disabled")
	calls, file, body, val := runSysctlBody(t, c, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.accept_redirects": "1"}, nil)
	if body != 0 || val != 0 {
		t.Fatalf("body %d, validate %d", body, val)
	}
	if strings.Join(file, "|") != "net.ipv4.ip_forward = 0" {
		t.Errorf("file %v, want the ip_forward line alone", file)
	}
	if strings.Join(calls, " ") != "net.ipv4.ip_forward=0" {
		t.Errorf("writes %v", calls)
	}
}

// sysctlBlock is the shipped control's planned block with its drop-in moved
// under dir, and validate forced to fail when failValidate is set.
func sysctlBlock(t *testing.T, id, dir string, failValidate bool) *Plan {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := set.ByID(id)
	p := mustBuild(t, scriptReport(row(id, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
	if len(p.Items) != 1 || !p.Items[0].Script || !p.Items[0].Planned {
		t.Fatalf("%s: plan %+v, want one planned scripted item", id, p.Items)
	}
	it := &p.Items[0]
	for i := range it.Backup {
		it.Backup[i] = rebaseSysctlD(it.Backup[i], dir)
	}
	it.ScriptBody = rebaseSysctlD(it.ScriptBody, dir)
	it.ValidateCmd = rebaseSysctlD(it.ValidateCmd, dir)
	if failValidate {
		it.ValidateCmd = "false"
	}
	return p
}

// S-46: writing all.forwarding copies the value into default.forwarding (the
// stub does it, as the kernel does), so the way back must put all back
// before default. A host at all=1, default=0 whose validate fails ends at
// all=1, default=0, with the drop-in gone.
func TestIPv6ForwardRestoreKeepsAllBeforeDefault(t *testing.T) {
	needSh(t)
	tmp := t.TempDir()
	bin, st, dir := filepath.Join(tmp, "bin"), filepath.Join(tmp, "st"), filepath.Join(tmp, "sysctl.d")
	for _, d := range []string{bin, st, dir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeStub(t, bin, "sysctl", sysctlStub)
	seedSysctl(t, st, map[string]string{"net.ipv6.conf.all.forwarding": "1", "net.ipv6.conf.default.forwarding": "0"}, nil)
	p := sysctlBlock(t, "muster.beyond.ipv6_forwarding_disabled", dir, true)
	out, _, code := runScriptWith(t, p, tmp, filepath.Join(tmp, "bk"), runOpts{pathPrefix: bin, env: []string{"SYSCTL_STATE=" + st}})
	if code != 1 || !strings.Contains(out, "validate failed") {
		t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
	}
	if strings.Contains(out, "ROLLBACK INCOMPLETE") {
		t.Errorf("the way back was incomplete\n%s", out)
	}
	if a, d := sysctlValue(t, st, "net.ipv6.conf.all.forwarding"), sysctlValue(t, st, "net.ipv6.conf.default.forwarding"); a != "1" || d != "0" {
		t.Errorf("after the way back all=%s default=%s, want all=1 default=0 (writes %v)\n%s", a, d, sysctlCalls(st), out)
	}
	if exists(filepath.Join(dir, "99-muster-ipv6-forwarding-disabled.conf")) {
		t.Errorf("the drop-in survived the way back\n%s", out)
	}
}

// S-27: a drop-in that is a symlink (an operator's /dev/null mask) fails the
// block before any write; the link, its target's mode and its content are
// unchanged after the whole block, way back included.
func TestSysctlBodiesLeaveASymlinkedDropIn(t *testing.T) {
	needSh(t)
	for _, c := range sysctlControls(t) {
		t.Run(c.ID, func(t *testing.T) {
			tmp := t.TempDir()
			bin, st, dir := filepath.Join(tmp, "bin"), filepath.Join(tmp, "st"), filepath.Join(tmp, "sysctl.d")
			for _, d := range []string{bin, st, dir} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			writeStub(t, bin, "sysctl", sysctlStub)
			failing := map[string]string{}
			for _, k := range c.Remediation.Sysctl {
				failing[k] = sysctlKeys[k][0]
			}
			if k := companion[c.ID]; k != "" {
				failing[k] = "0"
			}
			seedSysctl(t, st, failing, nil)
			victim := filepath.Join(tmp, "victim")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0o666); err != nil {
				t.Fatal(err)
			}
			p := sysctlBlock(t, c.ID, dir, false)
			link := p.Items[0].Backup[0]
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}
			out, _, code := runScriptWith(t, p, tmp, filepath.Join(tmp, "bk"), runOpts{pathPrefix: bin, env: []string{"SYSCTL_STATE=" + st}})
			if code == 0 {
				t.Fatalf("the block over a symlinked drop-in exited 0\n%s", out)
			}
			if !strings.Contains(out, c.ID+": "+link+" is a symlink (a mask), left as is") {
				t.Errorf("no symlink refusal in the log\n%s", out)
			}
			if got, err := os.Readlink(link); err != nil || got != victim {
				t.Errorf("the drop-in is %q (%v) after the block, want the link to %s", got, err, victim)
			}
			if m := mode(t, victim); m != "666" {
				t.Errorf("the link's target is mode %s, want 666", m)
			}
			if got := readFile(t, victim); got != "victim\n" {
				t.Errorf("the link's target holds %q", got)
			}
			for _, w := range sysctlCalls(st) {
				k, v, _ := strings.Cut(w, "=")
				if failing[k] != v {
					t.Errorf("wrote %s although the drop-in is a mask", w)
				}
			}
		})
	}
}

// moduleIDs are the three controls that declare modules.
var moduleIDs = []string{"muster.beyond.usb_storage_disabled", "muster.beyond.uncommon_filesystems_disabled", "muster.beyond.uncommon_network_protocols_disabled"}

// moduleRebase moves /etc/modprobe.d/ under st/conf (where the stub's
// --showconfig reads) and /proc/modules to st/modules (the stub's loaded set).
func moduleRebase(st string) func(string) string {
	return func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "/etc/modprobe.d/", filepath.Join(st, "conf")+"/"), "/proc/modules", filepath.Join(st, "modules"))
	}
}

// moduleState makes the stub's state directory: an empty conf/ and every
// module of the control loaded.
func moduleState(t *testing.T, r *controls.Remediation) (bin, st, loaded string) {
	t.Helper()
	bin, st = t.TempDir(), t.TempDir()
	writeStub(t, bin, "modprobe", modprobeStub)
	if err := os.Mkdir(filepath.Join(st, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, m := range r.Modules {
		fmt.Fprintf(&b, "%s 16384 0 - Live 0x0\n", strings.ReplaceAll(m, "-", "_"))
	}
	if err := os.WriteFile(filepath.Join(st, "modules"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return bin, st, b.String()
}

func TestModuleBodiesWriteFoldedLinesAndUnload(t *testing.T) {
	needSh(t)
	for _, id := range moduleIDs {
		t.Run(id, func(t *testing.T) {
			r := shippedControl(t, id).Remediation
			bin, st, loaded := moduleState(t, r)
			rebase := moduleRebase(st)
			procModules := rebase("/proc/modules")
			env := "MODPROBE_STATE=" + st
			for run := 1; run <= 2; run++ { // the second run changes nothing
				// under the script's umask 077, so the 644 below is the body's chmod
				if out, code := runBody(t, st, bin, "umask 077\n"+rebase(r.Script), env); code != 0 {
					t.Fatalf("run %d: body %d %s", run, code, out)
				}
				if out, code := runBody(t, st, bin, rebase(r.Validate), env); code != 0 {
					t.Fatalf("run %d: validate %d %s", run, code, out)
				}
			}
			conf, _ := os.ReadFile(rebase(r.Backup[0]))
			for _, m := range r.Modules {
				line := "install " + strings.ReplaceAll(m, "-", "_") + " /bin/false\n"
				if strings.Count(string(conf), line) != 1 {
					t.Errorf("conf carries %q %d times:\n%s", line, strings.Count(string(conf), line), conf)
				}
			}
			if m := mode(t, rebase(r.Backup[0])); m != "644" {
				t.Errorf("the drop-in is mode %s, want 644", m)
			}
			if left, _ := os.ReadFile(procModules); len(strings.TrimSpace(string(left))) != 0 {
				t.Errorf("modules still loaded: %s", left)
			}
			// a module in use fails the body, so the block rolls back
			if err := os.WriteFile(procModules, []byte(loaded), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(st, "busy"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, code := runBody(t, st, bin, rebase(r.Script), env); code == 0 {
				t.Error("a module in use did not fail the body")
			}
		})
	}
}

// S-25: an earlier vendor file that already disables a module with any of
// the collector's no-op commands is the effective install line; the body adds
// no line of its own for that module and the validate accepts it. A vendor
// line that loads the module wins over muster's file, and the validate fails.
func TestModuleBodiesKeepAVendorInstallLine(t *testing.T) {
	needSh(t)
	r := shippedControl(t, "muster.beyond.uncommon_filesystems_disabled").Remediation
	for _, tc := range []struct {
		vendor string
		ok     bool
	}{
		{"install cramfs /bin/true\n", true},
		{"install cramfs false\n", true},
		{"install cramfs /sbin/modprobe --ignore-install cramfs\n", false},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			bin, st, _ := moduleState(t, r)
			rebase := moduleRebase(st)
			if err := os.WriteFile(filepath.Join(st, "conf", "00-vendor.conf"), []byte(tc.vendor), 0o644); err != nil {
				t.Fatal(err)
			}
			env := "MODPROBE_STATE=" + st
			if out, code := runBody(t, st, bin, rebase(r.Script), env); code != 0 {
				t.Fatalf("body %d %s", code, out)
			}
			_, code := runBody(t, st, bin, rebase(r.Validate), env)
			if (code == 0) != tc.ok {
				t.Errorf("validate exit %d, want success %v", code, tc.ok)
			}
			conf := readFile(t, rebase(r.Backup[0]))
			if tc.ok == strings.Contains(conf, "install cramfs ") {
				t.Errorf("muster's drop-in, with the vendor line %q:\n%s", tc.vendor, conf)
			}
			if !strings.Contains(conf, "install udf /bin/false\n") {
				t.Errorf("the drop-in lacks the other modules:\n%s", conf)
			}
		})
	}
}

// S-27: a drop-in that is a symlink (an operator's mask) fails the whole
// block before any write; the link, its target's mode and content stay, and
// no module is unloaded.
func TestModuleBodiesLeaveASymlinkedDropIn(t *testing.T) {
	needSh(t)
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range moduleIDs {
		t.Run(id, func(t *testing.T) {
			c, _ := set.ByID(id)
			tmp := t.TempDir()
			bin, st, loaded := moduleState(t, c.Remediation)
			rebase := moduleRebase(st)
			p := mustBuild(t, scriptReport(row(id, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
			if len(p.Items) != 1 || !p.Items[0].Script || !p.Items[0].Planned {
				t.Fatalf("plan %+v, want one planned scripted item", p.Items)
			}
			it := &p.Items[0]
			for i := range it.Backup {
				it.Backup[i] = rebase(it.Backup[i])
			}
			it.ScriptBody, it.ValidateCmd = rebase(it.ScriptBody), rebase(it.ValidateCmd)
			victim := filepath.Join(tmp, "victim")
			if err := os.WriteFile(victim, []byte("victim\n"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(victim, 0o666); err != nil {
				t.Fatal(err)
			}
			link := it.Backup[0]
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}
			out, _, code := runScriptWith(t, p, tmp, filepath.Join(tmp, "bk"), runOpts{
				pathPrefix: bin, env: []string{"MODPROBE_STATE=" + st},
				replace: [][2]string{{"/proc/modules", rebase("/proc/modules")}},
			})
			if code == 0 {
				t.Fatalf("the block over a symlinked drop-in exited 0\n%s", out)
			}
			if !strings.Contains(out, id+": "+link+" is a symlink (a mask), left as is") {
				t.Errorf("no symlink refusal in the log\n%s", out)
			}
			if got, err := os.Readlink(link); err != nil || got != victim {
				t.Errorf("the drop-in is %q (%v) after the block, want the link to %s", got, err, victim)
			}
			if m := mode(t, victim); m != "666" {
				t.Errorf("the link's target is mode %s, want 666", m)
			}
			if got := readFile(t, victim); got != "victim\n" {
				t.Errorf("the link's target holds %q", got)
			}
			// restore_modules may load a recorded module again (the stub then
			// lists it twice); every module must still be in the loaded set
			got := readFile(t, rebase("/proc/modules"))
			for _, l := range strings.SplitAfter(loaded, "\n") {
				if !strings.Contains(got, l) {
					t.Errorf("%q left the loaded set: %q", l, got)
				}
			}
			if calls, _ := os.ReadFile(filepath.Join(st, "calls")); strings.Contains(string(calls), "-r ") {
				t.Errorf("modprobe -r ran although the drop-in is a mask:\n%s", calls)
			}
		})
	}
}

// rebaseRoot moves every absolute path a file body names under root.
func rebaseRoot(s, root string) string {
	for _, pre := range []string{"/etc/", "/var/", "/boot/"} {
		s = strings.ReplaceAll(s, " "+pre, " "+root+pre)
		s = strings.ReplaceAll(s, "\n"+pre, "\n"+root+pre)
		s = strings.ReplaceAll(s, "("+pre, "("+root+pre)
		s = strings.ReplaceAll(s, "'"+pre, "'"+root+pre)
		s = strings.ReplaceAll(s, "|"+pre, "|"+root+pre) // a case arm's second pattern
	}
	return s
}

type treeFile struct {
	path string
	mode os.FileMode
	dir  bool
}

// TestFileBodiesRepairATempTree runs the nine file bodies of 3D-2c over a
// tree under a root-owned directory made in / (root only, to chown; the
// prologue's modes_trusted refuses anything under the other-writable /tmp):
// the validate fails on the loosened modes, the body passes it, a mode the
// body must keep is kept, and no symlink — beside the set or at a single path
// the body names (S-45) — is followed to its 0666 target. A directory not
// root's (S-47) is left with its files as they are and named in the log.
func TestFileBodiesRepairATempTree(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown under the temp tree")
	}
	cases := []struct {
		id       string
		loosened []treeFile // modes the control FAILs on
		kept     []treeFile // modes the body must not change
		after    []treeFile // modes the body must leave (S-40)
		links    []string   // single paths the body names, planted as symlinks to the victim (S-45)
		foreign  []string   // directories chowned to uid 65534: the body leaves what they hold (S-47)
		refused  []treeFile // crontab or sudoers files chowned to uid 65534: never adopted, the validate fails (S-49)
	}{
		{id: "muster.account.sudoers_permissions", loosened: []treeFile{{"/etc/sudoers", 0o644, false}, {"/etc/sudoers.d/a", 0o664, false}}, kept: []treeFile{{"/etc/sudoers.d/README.txt", 0o666, false}}},
		{id: "muster.service.nfs_export_access", loosened: []treeFile{{"/etc/exports", 0o666, false}}},
		{id: "muster.service.nfs_export_access", links: []string{"/etc/exports"}},
		{id: "muster.beyond.bootloader_config_permissions", loosened: []treeFile{{"/boot/grub/grub.cfg", 0o644, false}}, links: []string{"/boot/grub2/grub.cfg"}},
		{id: "muster.file.inetd_conf_permissions", loosened: []treeFile{{"/etc/inetd.conf", 0o644, false}, {"/etc/xinetd.d/x", 0o666, false}}, links: []string{"/etc/xinetd.conf"}},
		{id: "muster.beyond.audit_log_permissions", loosened: []treeFile{{"/var/log/audit", 0o755, true}, {"/var/log/audit/audit.log", 0o644, false}}},
		{id: "muster.file.syslog_conf_permissions", loosened: []treeFile{{"/etc/rsyslog.conf", 0o644, false}, {"/etc/rsyslog.d/50.conf", 0o644, false}}, kept: []treeFile{{"/etc/rsyslog.d/notes.txt", 0o644, false}}, links: []string{"/etc/systemd/journald.conf"}},
		{id: "muster.account.cron_permissions",
			loosened: []treeFile{{"/etc/crontab", 0o644, false}, {"/etc/cron.allow", 0o644, false}, {"/etc/cron.d/x", 0o644, false}, {"/etc/cron.daily/y", 0o757, false}, {"/var/spool/cron/crontabs/u", 0o644, false}, {"/var/spool/cron/atjobs/a0002", 0o4700, false}},
			kept:     []treeFile{{"/var/spool/cron/atjobs/a0001", 0o700, false}, {"/var/spool/cron/crontabs", 0o1730, true}},
			after:    []treeFile{{"/etc/cron.allow", 0o640, false}, {"/var/spool/cron/atjobs/a0002", 0o700, false}}},
		{id: "muster.account.cron_permissions", links: []string{"/etc/cron.allow"}},
		{id: "muster.file.log_dir_permissions", loosened: []treeFile{{"/var/log", 0o757, true}, {"/var/log/x.log", 0o666, false}, {"/var/log/sub/y.log", 0o646, false}}, kept: []treeFile{{"/var/log/grp.log", 0o664, false}}, after: []treeFile{{"/var/log", 0o755, true}, {"/var/log/x.log", 0o664, false}}},
		{id: "muster.file.log_dir_permissions", loosened: []treeFile{{"/var/log/ok/a.log", 0o666, false}}, kept: []treeFile{{"/var/log/svc/b.log", 0o666, false}}, foreign: []string{"/var/log/svc"}},
		{id: "muster.account.cron_permissions", kept: []treeFile{{"/var/spool/cron/atjobs/a0003", 0o4700, false}}, foreign: []string{"/var/spool/cron/atjobs"}},
		{id: "muster.service.ftpusers_permissions", loosened: []treeFile{{"/etc/ftpusers", 0o644, false}}, links: []string{"/etc/vsftpd/user_list"}},
		// S-49: a crontab or sudoers file not owned by root is left as it is
		{id: "muster.account.cron_permissions", loosened: []treeFile{{"/etc/cron.d/x", 0o644, false}}, refused: []treeFile{{"/etc/cron.d/u", 0o644, false}}},
		{id: "muster.account.cron_permissions", refused: []treeFile{{"/etc/crontab", 0o644, false}}},
		{id: "muster.account.sudoers_permissions", loosened: []treeFile{{"/etc/sudoers", 0o644, false}}, refused: []treeFile{{"/etc/sudoers.d/b", 0o664, false}}},
		{id: "muster.account.sudoers_permissions", refused: []treeFile{{"/etc/sudoers", 0o644, false}}},
		// S-50: the directory is fixed first, and its files only when it is
		// root's; an other-writable parent holds a planted symlink
		{id: "muster.account.cron_permissions", loosened: []treeFile{{"/etc/cron.d", 0o757, true}, {"/etc/cron.d/x", 0o644, false}}, after: []treeFile{{"/etc/cron.d", 0o755, true}, {"/etc/cron.d/x", 0o640, false}}},
		{id: "muster.account.cron_permissions", kept: []treeFile{{"/etc/cron.d/z", 0o646, false}, {"/etc/cron.daily/y", 0o757, false}}, foreign: []string{"/etc/cron.d", "/etc/cron.daily"}},
		{id: "muster.beyond.audit_log_permissions", loosened: []treeFile{{"/var/log/audit", 0o777, true}}, links: []string{"/var/log/audit/audit.log"}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			r := shippedControl(t, c.id).Remediation
			root, err := os.MkdirTemp("/", "muster-tree-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(root) })
			// The NFS body asks systemctl whether the server runs and may
			// re-export (O-45): systemctl answers inactive and exportfs only
			// logs, so no run reaches the host's own; MB is the run's record
			// directory.
			bin, stub := t.TempDir(), t.TempDir()
			writeStub(t, bin, "systemctl", `printf '%s\n' "$*" >> "$STUB/systemctl"
case "$1" in is-active) exit 3;; esac
exit 99
`)
			writeStub(t, bin, "exportfs", `printf '%s\n' "$*" >> "$STUB/exportfs"
`)
			env := []string{"MB=" + t.TempDir(), "STUB=" + stub}
			mk := func(f treeFile) string {
				p := filepath.Join(root, f.path)
				if f.dir {
					if err := os.MkdirAll(p, 0o755); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if out, err := exec.Command("chmod", strconv.FormatUint(uint64(f.mode), 8), p).CombinedOutput(); err != nil {
					t.Fatalf("chmod %s: %v %s", p, err, out) // chmod(1), so the setgid and sticky bits land too
				}
				return p
			}
			for _, f := range append(append([]treeFile{}, c.loosened...), c.kept...) {
				mk(f)
			}
			// a symlink beside the set is never followed
			victim := mk(treeFile{"/victim", 0o666, false})
			for _, l := range append([]string{"/var/log/link", "/etc/cron.d/link", "/etc/sudoers.d/link"}, c.links...) {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l)), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(victim, filepath.Join(root, l)); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range c.foreign {
				if err := os.Chown(filepath.Join(root, d), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range c.refused {
				if err := os.Chown(mk(f), 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			// the block runs with the prologue's log and modes_trusted defined
			helpers := "log() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + stateHelpers + "\n"
			body, val := helpers+rebaseRoot(" "+r.Script, root), helpers+rebaseRoot(" "+r.Validate, root)
			if _, code := runBody(t, root, bin, val, env...); code == 0 && len(c.loosened) > 0 {
				t.Error("validate passed on the loosened tree")
			}
			out, code := runBody(t, root, bin, body, env...)
			if code != 0 {
				t.Fatalf("body %d: %s", code, out)
			}
			if exists(filepath.Join(stub, "exportfs")) {
				t.Errorf("the body re-exported a tree that holds no no_root_squash: %s", readFile(t, filepath.Join(stub, "exportfs")))
			}
			for _, d := range c.foreign {
				if want := c.id + ": " + filepath.Join(root, d) + " is not root's, left as is"; !strings.Contains(out, want) {
					t.Errorf("the log does not name the skipped directory %q:\n%s", want, out)
				}
			}
			if out, code := runBody(t, root, bin, val, env...); len(c.refused) == 0 && code != 0 {
				t.Fatalf("validate after the body %d: %s", code, out)
			} else if len(c.refused) > 0 && code == 0 {
				t.Errorf("validate passed although a file not root's was left as is: the block would not roll back")
			}
			for _, f := range c.refused {
				p := filepath.Join(root, f.path)
				if want := c.id + ": " + p + " is owned by uid 65534; review it before chown root, left as is"; !strings.Contains(out, want) {
					t.Errorf("the log does not name the refused file %q:\n%s", want, out)
				}
				if got, err := exec.Command("stat", "-c", "%u %a", p).Output(); err != nil || strings.TrimSpace(string(got)) != "65534 "+strconv.FormatUint(uint64(f.mode&0o7777), 8) {
					t.Errorf("%s is %q (%v) after the body, want it untouched", f.path, strings.TrimSpace(string(got)), err)
				}
			}
			for _, f := range c.kept {
				if got := mode(t, filepath.Join(root, f.path)); got != strconv.FormatUint(uint64(f.mode&0o7777), 8) {
					t.Errorf("%s changed to %s", f.path, got)
				}
			}
			for _, f := range c.after {
				if got := mode(t, filepath.Join(root, f.path)); got != strconv.FormatUint(uint64(f.mode&0o7777), 8) {
					t.Errorf("%s is %s after the body, want %o", f.path, got, f.mode)
				}
			}
			if got := mode(t, victim); got != "666" {
				t.Errorf("a body followed a symlink: the victim is %s", got)
			}
			for _, l := range c.links {
				if got, err := os.Readlink(filepath.Join(root, l)); err != nil || got != victim {
					t.Errorf("%s is %q (%v) after the body, want the link to the victim", l, got, err)
				}
			}
			// S-26: a root-group cron access file is given group crontab where
			// the host has one (Debian and Ubuntu)
			if c.id == "muster.account.cron_permissions" && exists(filepath.Join(root, "/etc/cron.allow")) && len(c.links) == 0 {
				if err := exec.Command("getent", "group", "crontab").Run(); err != nil {
					t.Log("no crontab group on this host: the access-file group was not checked")
				} else if out, err := exec.Command("stat", "-c", "%G", filepath.Join(root, "/etc/cron.allow")).Output(); err != nil || strings.TrimSpace(string(out)) != "crontab" {
					t.Errorf("/etc/cron.allow is in group %q (%v), want crontab", strings.TrimSpace(string(out)), err)
				}
			}
		})
	}
}

// accountTree stubs chage, sshd and systemctl for the account bodies: chage
// logs its argv; sshd -T answers from the muster drop-in when it exists (it
// sorts first, and the first value wins) and from $STUB/sshd_T otherwise;
// sshd -t succeeds; systemctl logs its argv, reports ssh.service active when
// $STUB/ssh_active exists and nothing else active, and a reload logs the
// drop-in as the daemon would read it, and "(00-muster.conf is a link)" when
// root_remote_login's drop-in is a symlink. Each reload also appends RELOAD and
// root_remote_login's drop-in (or "(absent)") to $STUB/muster_reloads; with
// $STUB/sshd_t_fail_first present the first sshd -t fails.
func accountTree(t *testing.T) (root, bin, stub string) {
	root, bin, stub = t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "chage", `printf '%s\n' "$*" >> "$STUB/chage"`+"\n")
	writeStub(t, bin, "systemctl", `printf '%s\n' "$*" >> "$STUB/systemctl"
case "$*" in
  "is-active --quiet ssh.service") [ -e "$STUB/ssh_active" ]; exit;;
  is-active*) exit 1;;
  reload*) cat "$ROOT/etc/ssh/sshd_config.d/00-muster-session.conf" >> "$STUB/systemctl" 2>/dev/null || echo "(no drop-in)" >> "$STUB/systemctl"
    { echo RELOAD; cat "$ROOT/etc/ssh/sshd_config.d/00-muster.conf" 2>/dev/null || echo "(absent)"; } >> "$STUB/muster_reloads"
    if [ -L "$ROOT/etc/ssh/sshd_config.d/00-muster.conf" ]; then echo "(00-muster.conf is a link)" >> "$STUB/systemctl"; fi;;
esac
exit 0
`)
	writeStub(t, bin, "sshd", `case "$1" in
  -t) if [ -e "$STUB/sshd_t_fail_first" ] && [ ! -e "$STUB/sshd_t_seen" ]; then : > "$STUB/sshd_t_seen"; exit 1; fi; exit 0;;
  -T) d="$ROOT/etc/ssh/sshd_config.d/00-muster-session.conf"
      if [ -f "$d" ]; then tr 'A-Z' 'a-z' < "$d"; else cat "$STUB/sshd_T"; fi;;
esac
`)
	return root, bin, stub
}

func rebaseAccounts(s, root string) string {
	for _, p := range []string{"/etc/login.defs", "/etc/security/", "/etc/shadow", "/etc/passwd", "/etc/ssh/", "/run/sshd", "/etc/securetty", "/etc/pam.d/"} {
		s = strings.ReplaceAll(s, p, root+p)
	}
	return s
}

// writeUnder writes s at root+p, making its directories.
func writeUnder(t *testing.T, root, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// S-10, S-42, S-48: login.defs and pwquality are tightened only where looser;
// the ageing reaches every hashed account /etc/passwd holds, except root (uid
// 0: an expired root password stops root's cron and at jobs) and one whose
// password is already past the maximum; the record replays on rollback.
func TestPasswordPolicyBodyTightensOnly(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.account.password_policy")
	r := c.Remediation
	root, bin, stub := accountTree(t)
	today := int(time.Now().Unix() / 86400)
	writeUnder(t, root, "/etc/login.defs", "#PASS_MAX_DAYS 1\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS 2\nPASS_MAX_DAYS 99999\n")
	writeUnder(t, root, "/etc/security/pwquality.conf", "minlen = 14\n")
	writeUnder(t, root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\nfresh:x:1000:1000::/home/fresh:/bin/sh\nold:x:1001:1001::/home/old:/bin/sh\nstrict:x:1002:1002::/home/strict:/bin/sh\nlegacy:x:1003:1003::/home/legacy:/bin/sh\nedge:x:1004:1004::/home/edge:/bin/sh\n")
	// edge changed its password exactly max_days ago: shadow's isexpired()
	// counts now >= lastchg + max as expired, so it is skipped too (E-10)
	writeUnder(t, root, "/etc/shadow", fmt.Sprintf("root:$6$x:%d:0:99999:7:::\nfresh:$6$x:%d::99999:7:::\nold:$6$x:%d:0:99999:7:::\nstrict:$6$x:%d:5:30:7:::\nlegacy:abcDEF:%d:::7:::\nghost:$6$x:%d::99999:7:::\nedge:$6$x:%d::99999:7:::\n#c:$6$x:1:0:1:::\n", today, today, today-400, today, today, today, today-90))
	mb := t.TempDir()
	env := append(pEnv(t, c), "MB="+mb, "STUB="+stub, "ROOT="+root)
	body := "log() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(r.Script, root)
	out, code := runBody(t, root, bin, body, env...)
	if code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	ld := readFile(t, filepath.Join(root, "/etc/login.defs"))
	if !strings.Contains(ld, "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 2\nPASS_MAX_DAYS 90\n") || !strings.Contains(ld, "PASS_MIN_LEN 8\n") || !strings.Contains(ld, "#PASS_MAX_DAYS 1\n") {
		t.Errorf("login.defs:\n%s", ld)
	}
	if pw := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")); pw != "minclass = 3\n" {
		t.Errorf("drop-in %q: minlen 14 is stricter and stays; minclass is written", pw)
	}
	got := readFile(t, filepath.Join(stub, "chage"))
	for _, w := range []string{"-M 90 -- fresh\n", "-m 1 -- fresh\n", "-M 90 -- legacy\n", "-m 1 -- legacy\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("chage lacks %q:\n%s", w, got)
		}
	}
	for _, never := range []string{"-- root\n", "-- old\n", "-M 90 -- strict\n", "-m 1 -- strict\n", "#c", "-- ghost\n", "-- edge\n"} {
		if strings.Contains(got, never) {
			t.Errorf("chage carries %q:\n%s", never, got)
		}
	}
	for _, n := range []string{"old", "edge"} {
		if !strings.Contains(out, "password_policy: "+n+": password at least 90 days old, change it first") {
			t.Errorf("no skip log for %s: %s", n, out)
		}
	}
	if !strings.Contains(out, "password_policy: root: root's password ageing is left to the operator: an expired root password stops root's cron and at jobs") {
		t.Errorf("no skip log for the hashed root: %s", out)
	}
	if !strings.Contains(out, "password_policy: ghost: not in "+root+"/etc/passwd, left as is") { // the log names the rebased path
		t.Errorf("no skip log for ghost: %s", out)
	}
	rec := readFile(t, filepath.Join(mb, "ageing.list"))
	if !strings.Contains(rec, "legacy:-1:-1\n") || !strings.Contains(rec, "fresh:-1:99999\n") || strings.Contains(rec, "ghost") || strings.Contains(rec, "old:") || strings.Contains(rec, "root:") {
		t.Errorf("ageing.list:\n%s", rec)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(r.Validate, root), env...); code != 0 {
		t.Errorf("validate %d: %s", code, out)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(r.Rollback, root), env...); code != 0 {
		t.Errorf("rollback %d: %s", code, out)
	}
	if calls := readFile(t, filepath.Join(stub, "chage")); !strings.Contains(calls, "-m -1 -M 99999 -- fresh\n") || !strings.Contains(calls, "-m -1 -M -1 -- legacy\n") {
		t.Errorf("rollback replay:\n%s", calls)
	}
}

// E-8: a login.defs and a pwquality chain already stricter than the
// parameters stay byte for byte; nothing is written and the validate holds.
func TestPasswordPolicyBodyKeepsAStricterHost(t *testing.T) {
	needSh(t)
	for _, pwq := range []string{"minlen = 12\ndcredit = -1\nucredit = -1\nlcredit = -1\n", "MINLEN = 14\nMinClass = 3\n", "minlen 12 # site\nminclass\t3\n"} {
		keepsAStricterHost(t, pwq)
	}
}

func keepsAStricterHost(t *testing.T, pwq string) {
	c := shippedControl(t, "muster.account.password_policy")
	root, bin, stub := accountTree(t)
	const defs = "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n"
	writeUnder(t, root, "/etc/login.defs", defs)
	writeUnder(t, root, "/etc/security/pwquality.conf", pwq)
	writeUnder(t, root, "/etc/passwd", "")
	writeUnder(t, root, "/etc/shadow", "")
	env := append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
	body := "log() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(c.Remediation.Script, root)
	if out, code := runBody(t, root, bin, body, env...); code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	if got := readFile(t, filepath.Join(root, "/etc/login.defs")); got != defs {
		t.Errorf("login.defs changed to %q", got)
	}
	if exists(filepath.Join(root, "/etc/security/pwquality.conf.d")) {
		t.Errorf("%q: a pwquality drop-in was written although the chain is stricter", pwq)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code != 0 {
		t.Errorf("%q: validate %d: %s", pwq, code, out)
	}
}

// The drop-in's own looser line is rewritten in place whatever its key's
// case (the collector lower-cases keys), never left beside a second one.
func TestPasswordPolicyBodyRewritesItsOwnLine(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.account.password_policy")
	root, bin, stub := accountTree(t)
	writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
	writeUnder(t, root, "/etc/security/pwquality.conf.d/99-muster.conf", "# site\nMinClass = 1\nMINLEN = 6\n")
	writeUnder(t, root, "/etc/passwd", "")
	writeUnder(t, root, "/etc/shadow", "")
	env := append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(c.Remediation.Script, root)
	if out, code := runBody(t, root, bin, body, env...); code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	f := filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")
	if got := readFile(t, f); got != "# site\nminclass = 3\nminlen = 8\n" {
		t.Errorf("drop-in %q", got)
	}
	if m := mode(t, f); m != "644" {
		t.Errorf("drop-in mode %s, want 644", m)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code != 0 {
		t.Errorf("validate %d: %s", code, out)
	}
}

// pwPolicyBody runs password_policy's body over a tree whose login.defs
// already passes, with pwquality.conf and the given drop-ins, and returns the
// tree's root and the environment the validate needs.
func pwPolicyBody(t *testing.T, main string, dropins map[string]string) (root string, env []string) {
	t.Helper()
	c := shippedControl(t, "muster.account.password_policy")
	root, bin, stub := accountTree(t)
	writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
	if main != "" {
		writeUnder(t, root, "/etc/security/pwquality.conf", main)
	}
	for n, s := range dropins {
		writeUnder(t, root, "/etc/security/pwquality.conf.d/"+n, s)
	}
	writeUnder(t, root, "/etc/passwd", "")
	writeUnder(t, root, "/etc/shadow", "")
	env = append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(c.Remediation.Script, root)
	if out, code := runBody(t, root, bin, body, env...); code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code != 0 {
		t.Errorf("validate %d after the body: %s", code, out)
	}
	return root, env
}

// f3: libpwquality reads pwquality.conf.d/*.conf first and pwquality.conf
// LAST, so a key the main file sets is rewritten there — every uncommented
// line that sets it, its key matched case-blind as the collector reads it —
// and a key it does not set goes to 99-muster.conf. A drop-in muster wrote
// would lose to the main file's value; the validate reads the same order.
func TestPasswordPolicyBodyRewritesTheMainFile(t *testing.T) {
	needSh(t)
	// main 6 alone: the main file is rewritten, minclass (unset there) goes to
	// the drop-in.
	const main = "# site\n# minlen = 4\nMinLen = 6\nminlen=7\ndictcheck = 1\n"
	root, _ := pwPolicyBody(t, main, nil)
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf")); got != "# site\n# minlen = 4\nminlen = 8\nminlen = 8\ndictcheck = 1\n" {
		t.Errorf("pwquality.conf %q", got)
	}
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")); got != "minclass = 3\n" {
		t.Errorf("99-muster.conf %q, want only the minclass the main file does not set", got)
	}
	// main 6 over an earlier run's drop-in at 14: libpwquality enforces 6, so
	// the main file is rewritten and the old drop-in left as it was.
	root, _ = pwPolicyBody(t, "minlen = 6\nminclass = 3\n", map[string]string{"99-muster.conf": "minlen = 14\n"})
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf")); got != "minlen = 8\nminclass = 3\n" {
		t.Errorf("pwquality.conf %q, want the main file's minlen rewritten", got)
	}
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")); got != "minlen = 14\n" {
		t.Errorf("99-muster.conf %q, want it unchanged", got)
	}
}

// f3: the validate fails when only a drop-in holds the value the main file
// overrides — the shape the old order certified as repaired.
func TestPasswordPolicyValidateReadsTheMainFileLast(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.account.password_policy")
	root, bin, stub := accountTree(t)
	writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
	writeUnder(t, root, "/etc/security/pwquality.conf", "minlen = 6\n")
	writeUnder(t, root, "/etc/security/pwquality.conf.d/99-muster.conf", "minlen = 14\nminclass = 3\n")
	env := append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
	if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code == 0 {
		t.Errorf("validate passed over a main file's minlen 6 that libpwquality reads last: %s", out)
	}
	// The same values with the main file stricter pass.
	writeUnder(t, root, "/etc/security/pwquality.conf", "minlen = 14\n")
	writeUnder(t, root, "/etc/security/pwquality.conf.d/99-muster.conf", "minlen = 6\nminclass = 3\n")
	if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code != 0 {
		t.Errorf("validate %d over a main file's minlen 14: %s", code, out)
	}
}

// f4: enforcing = 0 makes pam_pwquality warn and accept a weak password. The
// body sets 1 through the same writer — in pwquality.conf when it sets the
// key, else in 99-muster.conf — and the validate requires it non-zero in the
// files. It reads only the files (H-1): an enforcing=0 argument on the
// pam_pwquality.so line is the operator's to remove, and failing the validate
// on it would roll back the body's correct writes; the check keeps failing on
// it instead.
func TestPasswordPolicyBodyRepairsEnforcing(t *testing.T) {
	needSh(t)
	root, _ := pwPolicyBody(t, "", map[string]string{"50-rollout.conf": "enforcing = 0\n"})
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")); got != "minclass = 3\nenforcing = 1\n" {
		t.Errorf("99-muster.conf %q, want enforcing = 1 after the rollout drop-in", got)
	}
	root, _ = pwPolicyBody(t, "minclass = 3\nEnforcing=0\n", nil)
	if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf")); got != "minclass = 3\nenforcing = 1\n" {
		t.Errorf("pwquality.conf %q, want its enforcing rewritten", got)
	}
	if exists(filepath.Join(root, "/etc/security/pwquality.conf.d")) {
		t.Error("a drop-in was written although the main file sets every key the body changed")
	}

	c := shippedControl(t, "muster.account.password_policy")
	root, bin, stub := accountTree(t)
	writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
	writeUnder(t, root, "/etc/security/pwquality.conf", "minclass = 3\nenforcing = 0\n")
	env := append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
	validate := func() int {
		_, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...)
		return code
	}
	if validate() == 0 {
		t.Error("validate passed over enforcing = 0 left in pwquality.conf")
	}
	writeUnder(t, root, "/etc/security/pwquality.conf", "minclass = 3\nenforcing = 1\n")
	if code := validate(); code != 0 {
		t.Errorf("validate %d over enforcing = 1", code)
	}
	writeUnder(t, root, "/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3 enforcing=0\n")
	if code := validate(); code != 0 {
		t.Errorf("validate %d with an enforcing=0 argument on the PAM line: it must read only the files", code)
	}
}

// f3: pwquality.conf is in the block's backup, so a failed validate puts it
// back byte for byte after the body rewrote it in place.
func TestPasswordPolicyRollbackRestoresTheMainFile(t *testing.T) {
	needSh(t)
	root, bin, stub := accountTree(t)
	const main = "# site\nMinLen = 6\n\tminclass=1  \n"
	writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
	writeUnder(t, root, "/etc/security/pwquality.conf", main)
	writeUnder(t, root, "/etc/passwd", "")
	writeUnder(t, root, "/etc/shadow", "")
	pc := filepath.Join(root, "/etc/security/pwquality.conf")
	if err := os.Chmod(pc, 0o640); err != nil {
		t.Fatal(err)
	}
	p := accountBlock(t, "muster.account.password_policy", root, true)
	out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 1 || !strings.Contains(out, "validate failed") {
		t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
	}
	if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
		t.Errorf("the way back was incomplete\n%s", out)
	}
	if got := readFile(t, pc); got != main {
		t.Errorf("pwquality.conf is %q after the block, want %q", got, main)
	}
	if m := mode(t, pc); m != "640" {
		t.Errorf("pwquality.conf mode %s after the block, want 640", m)
	}
}

func TestLineBodiesTightenOnly(t *testing.T) {
	needSh(t)
	for _, c := range []struct {
		id, file, before, after string
		absent, created         bool     // the file is missing before; the body creates it
		mode                    string   // the file's mode after the body, when set
		env                     []string // overrides of the defaults
	}{
		{id: "muster.account.umask_policy", file: "/etc/login.defs", before: "UMASK 002\n", after: "UMASK 027\n"},
		{id: "muster.account.umask_policy", file: "/etc/login.defs", before: "UMASK 077\n", after: "UMASK 077\n"},
		{id: "muster.account.umask_policy", file: "/etc/login.defs", before: "# none\n", after: "# none\nUMASK 027\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 3\ndeny = 99\n", after: "deny = 5\ndeny = 5\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "# deny = 3\n", after: "# deny = 3\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 0\n", after: "deny = 5\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 2\n", after: "deny = 2\n"},
		// H-6: pam_faillock's set_conf_opt matches names case-sensitively, so
		// DENY and Deny are ignored (deny stays 3, in range) and left alone
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "DENY = 99\n", after: "DENY = 99\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "  Deny=2\n", after: "  Deny=2\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 2\nDENY = 99\n", after: "deny = 2\nDENY = 99\n"},
		// "#" cuts wherever it is, the "=" is optional, and sscanf reads the
		// leading digits (a value with none leaves deny unchanged)
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 10 # x\n", after: "deny = 5\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny 9\n", after: "deny = 5\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 0abc\n", after: "deny = 5\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 4abc\n", after: "deny = 4abc\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = abc\n", after: "deny = abc\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 4\ndeny = abc\n", after: "deny = 4\ndeny = abc\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 99\ndeny = abc\n", after: "deny = 5\ndeny = 5\n"},
		// "%hu" keeps the low 16 bits: 65541 locks after 5
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = 65541\n", after: "deny = 65541\n"},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "deny = -1\n", after: "deny = 5\n"},
		// S-41: a missing faillock.conf is deny 3 on both sides
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", absent: true},
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", absent: true, created: true, after: "deny = 2\n", mode: "644", env: []string{"P_max_attempts=2"}},
		// an existing file keeps its mode
		{id: "muster.account.lockout_threshold", file: "/etc/security/faillock.conf", before: "# none\n", after: "# none\ndeny = 2\n", mode: "600", env: []string{"P_max_attempts=2"}},
	} {
		ctl := shippedControl(t, c.id)
		root, bin, stub := accountTree(t)
		p := filepath.Join(root, c.file)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if !c.absent {
			perm := os.FileMode(0o644)
			if c.mode == "600" {
				perm = 0o600
			}
			if err := os.WriteFile(p, []byte(c.before), perm); err != nil {
				t.Fatal(err)
			}
		}
		env := append(append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root), c.env...)
		// the script runs every body under umask 077
		if out, code := runBody(t, root, bin, "umask 077\n"+rebaseAccounts(ctl.Remediation.Script, root), env...); code != 0 {
			t.Fatalf("%s %q: body %d %s", c.id, c.before, code, out)
		}
		if c.mode != "" {
			if m := mode(t, p); m != c.mode {
				t.Errorf("%s %q: mode %s, want %s", c.id, c.before, m, c.mode)
			}
		}
		if c.absent && !c.created {
			if exists(p) {
				t.Errorf("%s: the body created %s although the default is in range", c.id, c.file)
			}
		} else if b, _ := os.ReadFile(p); string(b) != c.after {
			t.Errorf("%s %q: file %q, want %q", c.id, c.before, b, c.after)
		}
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Validate, root), env...); code != 0 {
			t.Errorf("%s %q: validate %d %s", c.id, c.before, code, out)
		}
	}
}

func TestSessionTimeoutKeepsAValueInRange(t *testing.T) {
	needSh(t)
	ctl := shippedControl(t, "muster.account.session_timeout")
	for _, c := range []struct{ answer, want string }{
		{"clientaliveinterval 900\nclientalivecountmax 3\n", "ClientAliveInterval 300\nClientAliveCountMax 3\n"},
		{"clientaliveinterval 120\nclientalivecountmax 9\n", "ClientAliveInterval 120\nClientAliveCountMax 3\n"},
		{"clientaliveinterval 0\nclientalivecountmax 3\n", "ClientAliveInterval 300\nClientAliveCountMax 3\n"},
	} {
		root, bin, stub := accountTree(t)
		_ = os.MkdirAll(filepath.Join(root, "/etc/ssh/sshd_config.d"), 0o755)
		if err := os.WriteFile(filepath.Join(stub, "sshd_T"), []byte(c.answer), 0o644); err != nil {
			t.Fatal(err)
		}
		env := append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root)
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Script, root), env...); code != 0 {
			t.Fatalf("%q: body %d %s", c.answer, code, out)
		}
		if b, _ := os.ReadFile(filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster-session.conf")); string(b) != c.want {
			t.Errorf("%q: drop-in %q, want %q", c.answer, b, c.want)
		}
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Validate, root), env...); code != 0 {
			t.Errorf("%q: validate %d %s", c.answer, code, out)
		}
		if calls := readFile(t, filepath.Join(stub, "systemctl")); strings.Contains(calls, "reload") {
			t.Errorf("%q: reloaded a unit that is not active:\n%s", c.answer, calls)
		}
	}
}

// S-11, S-44: a host without sshd ends done with nothing written (the next
// check still FAILs, naming the TMOUT mechanism).
func TestSessionTimeoutWithoutSshdChangesNothing(t *testing.T) {
	needSh(t)
	if p, err := exec.LookPath("sshd"); err == nil {
		t.Skipf("this host has its own sshd (%s); the case needs a PATH without one", p)
	}
	ctl := shippedControl(t, "muster.account.session_timeout")
	root, bin, stub := accountTree(t)
	if err := os.Remove(filepath.Join(bin, "sshd")); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(root, "/etc/ssh/sshd_config.d"), 0o755)
	env := append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root)
	for _, b := range []struct{ name, v string }{{"script", ctl.Remediation.Script}, {"validate", ctl.Remediation.Validate}} {
		if out, code := runBody(t, root, bin, rebaseAccounts(b.v, root), env...); code != 0 {
			t.Errorf("%s %d without sshd: %s", b.name, code, out)
		}
	}
	if exists(filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster-session.conf")) {
		t.Error("a drop-in was written on a host without sshd")
	}
	if exists(filepath.Join(root, "/run/sshd")) {
		t.Error("/run/sshd was made on a host without sshd")
	}
}

// Z-30's pattern: only the active unit is reloaded, after the drop-in is
// written.
func TestSessionTimeoutReloadsTheActiveSshService(t *testing.T) {
	needSh(t)
	ctl := shippedControl(t, "muster.account.session_timeout")
	root, bin, stub := accountTree(t)
	_ = os.MkdirAll(filepath.Join(root, "/etc/ssh/sshd_config.d"), 0o755)
	writeUnder(t, stub, "/sshd_T", "clientaliveinterval 0\nclientalivecountmax 3\n")
	writeUnder(t, stub, "/ssh_active", "")
	env := append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root)
	if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Script, root), env...); code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	calls := readFile(t, filepath.Join(stub, "systemctl"))
	if !strings.Contains(calls, "reload ssh.service\nClientAliveInterval 300\n") {
		t.Errorf("no reload of ssh.service over the new drop-in:\n%s", calls)
	}
	if strings.Contains(calls, "reload sshd.service") {
		t.Errorf("reloaded the inactive sshd.service:\n%s", calls)
	}
}

// accountBlock is the shipped control's planned block with its paths moved
// under root, and validate forced to fail when failValidate is set.
func accountBlock(t *testing.T, id, root string, failValidate bool) *Plan {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := set.ByID(id)
	p := mustBuild(t, scriptReport(row(id, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
	if len(p.Items) != 1 || !p.Items[0].Script || !p.Items[0].Planned {
		t.Fatalf("%s: plan %+v, want one planned scripted item", id, p.Items)
	}
	it := &p.Items[0]
	for i := range it.Backup {
		it.Backup[i] = rebaseAccounts(it.Backup[i], root)
	}
	it.ScriptBody = rebaseAccounts(it.ScriptBody, root)
	it.ValidateCmd = rebaseAccounts(it.ValidateCmd, root)
	it.RollbackBody = rebaseAccounts(it.RollbackBody, root)
	if failValidate {
		it.ValidateCmd = "false"
	}
	return p
}

// S-27: a muster drop-in that is a symlink (an operator's mask) fails the
// block before any write; the link, its target's mode and content are
// unchanged after the whole block, and no account is touched. A symlinked
// /etc/login.defs is refused the same way (K2).
func TestAccountBodiesLeaveASymlinkedDropIn(t *testing.T) {
	needSh(t)
	for _, c := range []struct{ id, dropIn, what string }{
		{"muster.account.password_policy", "/etc/security/pwquality.conf.d/99-muster.conf", "is a symlink (a mask), left as is"},
		{"muster.account.session_timeout", "/etc/ssh/sshd_config.d/00-muster-session.conf", "is a symlink (a mask), left as is"},
		// K2: login.defs is written only when it is no symlink
		{"muster.account.password_policy", "/etc/login.defs", "is a symlink, left as is"},
		// f3: pwquality.conf is rewritten in place when it sets a key, so a
		// symlinked one is refused like login.defs (K2)
		{"muster.account.password_policy", "/etc/security/pwquality.conf", "is a symlink, left as is"},
		{"muster.account.umask_policy", "/etc/login.defs", "is a symlink, left as is"},
		// O-11: faillock.conf and securetty are vendor files (K2); 00-muster.conf
		// is muster's own drop-in (S-27)
		{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "is a symlink, left as is"},
		{"muster.account.root_remote_login", "/etc/securetty", "is a symlink, left as is"},
		{"muster.account.root_remote_login", "/etc/ssh/sshd_config.d/00-muster.conf", "is a symlink (a mask), left as is"},
	} {
		t.Run(c.id+c.dropIn, func(t *testing.T) {
			root, bin, stub := accountTree(t)
			const defs = "PASS_MAX_DAYS 99999\n"
			if c.dropIn != "/etc/login.defs" {
				writeUnder(t, root, "/etc/login.defs", defs)
			}
			writeUnder(t, root, "/etc/passwd", "fresh:x:1000:1000::/home/fresh:/bin/sh\n")
			writeUnder(t, root, "/etc/shadow", fmt.Sprintf("fresh:$6$x:%d::99999:7:::\n", time.Now().Unix()/86400))
			writeUnder(t, stub, "/sshd_T", "clientaliveinterval 0\nclientalivecountmax 3\n")
			victim := filepath.Join(root, "victim")
			writeUnder(t, root, "/victim", "victim\n")
			if err := os.Chmod(victim, 0o666); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, c.dropIn)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}
			p := accountBlock(t, c.id, root, false)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code == 0 {
				t.Fatalf("the block over a symlinked %s exited 0\n%s", c.dropIn, out)
			}
			if !strings.Contains(out, c.id+": "+link+" "+c.what) {
				t.Errorf("no symlink refusal in the log\n%s", out)
			}
			if got, err := os.Readlink(link); err != nil || got != victim {
				t.Errorf("%s is %q (%v) after the block, want the link to %s", c.dropIn, got, err, victim)
			}
			if m := mode(t, victim); m != "666" {
				t.Errorf("the link's target is mode %s, want 666", m)
			}
			if got := readFile(t, victim); got != "victim\n" {
				t.Errorf("the link's target holds %q", got)
			}
			if c.dropIn != "/etc/login.defs" {
				if got := readFile(t, filepath.Join(root, "/etc/login.defs")); got != defs {
					t.Errorf("login.defs is %q after the block", got)
				}
			}
			if exists(filepath.Join(stub, "chage")) {
				t.Errorf("chage ran although the block stopped:\n%s", readFile(t, filepath.Join(stub, "chage")))
			}
		})
	}
}

// O-11, O-45: root_remote_login's rollback never removes a symlinked
// 00-muster.conf. In a whole block the body's guard refuses the link before any
// write and the rollback then runs with the link in place; restore would put a
// removed link back afterwards, so only the rollback alone shows whether it
// was removed: the reload it sends must still see the link.
func TestRootLoginRollbackSkipsASymlinkedDropIn(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.account.root_remote_login")
	root, bin, stub := accountTree(t)
	const target = "PermitRootLogin yes\n"
	victim := filepath.Join(root, "victim")
	writeUnder(t, root, "/victim", target)
	link := filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster.conf")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	writeUnder(t, stub, "/ssh_active", "")
	body := "log() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(r.Rollback, root)
	out, code := runBody(t, root, bin, body, "STUB="+stub, "ROOT="+root)
	if code != 0 {
		t.Fatalf("rollback %d: %s", code, out)
	}
	if got, err := os.Readlink(link); err != nil || got != victim {
		t.Errorf("00-muster.conf is %q (%v) after the rollback, want the link to %s", got, err, victim)
	}
	if got := readFile(t, victim); got != target {
		t.Errorf("the link's target holds %q", got)
	}
	calls := readFile(t, filepath.Join(stub, "systemctl"))
	if !strings.Contains(calls, "reload ssh.service\n") || !strings.HasSuffix(calls, "(00-muster.conf is a link)\n") {
		t.Errorf("want a reload of ssh.service that sees the link; calls:\n%s", calls)
	}
}

// E-11, the root_remote_login counterpart of S-35: the rollback puts the
// recorded 00-muster.conf back (or removes it, when the run created it) before
// sshd -t and the reload, so the daemon never runs a configuration its files do
// not hold. A drop-in an earlier run left must come back, not be deleted.
func TestRootLoginRollbackRestoresBeforeTheReload(t *testing.T) {
	needSh(t)
	const before = "PermitRootLogin no\nAllowGroups wheel\n"
	for _, c := range []struct {
		name         string
		existing     bool
		failValidate bool
		failSshdT    bool
	}{
		{"validate fails, drop-in existed", true, true, false},
		{"validate fails, no drop-in", false, true, false},
		{"body fails, drop-in existed", true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := accountTree(t)
			dropIn := filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster.conf")
			if c.existing {
				writeUnder(t, root, "/etc/ssh/sshd_config.d/00-muster.conf", before)
			}
			writeUnder(t, stub, "/ssh_active", "")
			if c.failSshdT {
				writeUnder(t, stub, "/sshd_t_fail_first", "")
			}
			p := accountBlock(t, "muster.account.root_remote_login", root, c.failValidate)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 {
				t.Fatalf("exit %d, want 1 after a failed block\n%s", code, out)
			}
			if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
				t.Errorf("the way back was incomplete\n%s", out)
			}
			want := "(absent)\n"
			if c.existing {
				want = before
			}
			reloads := strings.Split(readFile(t, filepath.Join(stub, "muster_reloads")), "RELOAD\n")
			if last := reloads[len(reloads)-1]; last != want {
				t.Errorf("the last reload read %q, want %q (all: %q)", last, want, reloads)
			}
			got, err := os.ReadFile(dropIn)
			if c.existing {
				if err != nil || string(got) != before {
					t.Errorf("the drop-in is %q (%v) after the block, want %q", got, err, before)
				}
			} else if err == nil {
				t.Errorf("the drop-in exists after the block: %q", got)
			}
		})
	}
}

// S-35: on a failed validate the rollback puts the recorded drop-in back
// itself before it reloads, so the daemon never runs a configuration its
// files do not hold, also when an earlier run's drop-in existed.
func TestSessionTimeoutRollbackRestoresBeforeTheReload(t *testing.T) {
	needSh(t)
	root, bin, stub := accountTree(t)
	const before = "ClientAliveInterval 300\nClientAliveCountMax 9\n"
	writeUnder(t, root, "/etc/ssh/sshd_config.d/00-muster-session.conf", before)
	writeUnder(t, stub, "/ssh_active", "")
	p := accountBlock(t, "muster.account.session_timeout", root, true)
	out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 1 || !strings.Contains(out, "validate failed") {
		t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
	}
	if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
		t.Errorf("the way back was incomplete\n%s", out)
	}
	if got := readFile(t, filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster-session.conf")); got != before {
		t.Errorf("the drop-in is %q after the block, want %q", got, before)
	}
	calls := readFile(t, filepath.Join(stub, "systemctl"))
	if !strings.Contains(calls, "reload ssh.service\nClientAliveInterval 300\nClientAliveCountMax 3\n") {
		t.Errorf("the body did not reload over its own drop-in:\n%s", calls)
	}
	if !strings.HasSuffix(calls, "reload ssh.service\n"+before) {
		t.Errorf("the last reload did not read the restored drop-in:\n%s", calls)
	}
}

// H-7: a line libpwquality refuses (an unknown name, or an integer
// set_name_value rejects) stops it, and what it enforces then depends on what
// was applied before the stop. The body names the line and fails before ANY
// write - login.defs and the ageing included - so the block rolls back and the
// check keeps failing on the line; the validate refuses the same chain.
func TestPasswordPolicyBodyStopsOnARefusedLine(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.account.password_policy")
	for _, row := range []struct {
		name, main string
		dropins    map[string]string
		at, key    string
	}{
		{"a drop-in's bad integer", "minlen = 6\n", map[string]string{"50-site.conf": "# site\nminlen = 14chars\n"}, "/etc/security/pwquality.conf.d/50-site.conf:2", "minlen"},
		{"a drop-in's unknown name", "minlen = 6\n", map[string]string{"50-site.conf": "minlen = 14\nunknownkey = 1\n"}, "/etc/security/pwquality.conf.d/50-site.conf:2", "unknownkey"},
		{"an integer muster does not judge", "", map[string]string{"10-a.conf": "difok = x\n"}, "/etc/security/pwquality.conf.d/10-a.conf:1", "difok"},
		{"the main file after a good line", "minlen = 12\nBogus = 1\n", nil, "/etc/security/pwquality.conf:2", "Bogus"},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, bin, stub := accountTree(t)
			const defs = "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_MIN_LEN 5\n"
			writeUnder(t, root, "/etc/login.defs", defs)
			if row.main != "" {
				writeUnder(t, root, "/etc/security/pwquality.conf", row.main)
			}
			for n, b := range row.dropins {
				writeUnder(t, root, "/etc/security/pwquality.conf.d/"+n, b)
			}
			writeUnder(t, root, "/etc/passwd", "fresh:x:1000:1000::/home/fresh:/bin/sh\n")
			writeUnder(t, root, "/etc/shadow", fmt.Sprintf("fresh:$6$x:%d::99999:7:::\n", time.Now().Unix()/86400))
			env := append(pEnv(t, c), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
			body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(c.Remediation.Script, root)
			out, code := runBody(t, root, bin, body, env...)
			if code != 1 {
				t.Fatalf("body exit %d, want 1: %s", code, out)
			}
			if want := "muster-fix: muster.account.password_policy: " + root + row.at + " stops libpwquality (" + row.key + "), left as is\n"; !strings.Contains(out, want) {
				t.Errorf("no %q in:\n%s", want, out)
			}
			if got := readFile(t, filepath.Join(root, "/etc/login.defs")); got != defs {
				t.Errorf("login.defs written before the stop was found: %q", got)
			}
			if row.main != "" {
				if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf")); got != row.main {
					t.Errorf("pwquality.conf written: %q", got)
				}
			}
			if exists(filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf")) {
				t.Error("99-muster.conf written")
			}
			if exists(filepath.Join(stub, "chage")) {
				t.Errorf("chage ran: %s", readFile(t, filepath.Join(stub, "chage")))
			}
			// The validate refuses the same chain even where every value it
			// could read passes.
			writeUnder(t, root, "/etc/login.defs", "PASS_MAX_DAYS 60\nPASS_MIN_DAYS 2\nPASS_MIN_LEN 12\n")
			if out, code := runBody(t, root, bin, rebaseAccounts(c.Remediation.Validate, root), env...); code == 0 {
				t.Errorf("validate passed over a chain libpwquality stops: %s", out)
			}
		})
	}
}

// H-7: pput rewrites the main file's line for a key however libpwquality
// reads it - without "=", in any case, with a trailing comment - as
// "<key> = <value>", the comment not kept.
func TestPasswordPolicyBodyRewritesASpelledKey(t *testing.T) {
	needSh(t)
	for _, main := range []string{"minlen 6\n", "MinLen=6\n", "minlen = 6 # site\n", "  MINLEN\t6\r\n"} {
		root, _ := pwPolicyBody(t, main+"minclass 3\n", nil)
		if got := readFile(t, filepath.Join(root, "/etc/security/pwquality.conf")); got != "minlen = 8\nminclass 3\n" {
			t.Errorf("%q: pwquality.conf %q, want the line rewritten in place", main, got)
		}
		if exists(filepath.Join(root, "/etc/security/pwquality.conf.d")) {
			t.Errorf("%q: a drop-in was written although the main file sets the key", main)
		}
	}
}
