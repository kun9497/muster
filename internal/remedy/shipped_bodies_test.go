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
	if out, code := runBody(t, dir, bin, rebaseSysctlD(r.Script, dir), env...); code != 0 {
		body = code
		t.Logf("%s body: %s", c.ID, out)
	}
	_, validate = runBody(t, dir, bin, rebaseSysctlD(r.Validate, dir), env...)
	calls = sysctlCalls(st)
	if b, err := os.ReadFile(rebaseSysctlD(r.Backup[0], dir)); err == nil {
		file = strings.Split(strings.TrimSpace(string(b)), "\n")
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
				if out, code := runBody(t, st, bin, rebase(r.Script), env); code != 0 {
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
// tree under t.TempDir() (root only, to chown): the validate fails on the
// loosened modes, the body passes it, a mode the body must keep is kept, and
// no symlink — beside the set or at a single path the body names (S-45) — is
// followed to its 0666 target.
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
		{id: "muster.file.log_dir_permissions", loosened: []treeFile{{"/var/log/x.log", 0o666, false}, {"/var/log/sub/y.log", 0o646, false}}, kept: []treeFile{{"/var/log/grp.log", 0o664, false}}},
		{id: "muster.service.ftpusers_permissions", loosened: []treeFile{{"/etc/ftpusers", 0o644, false}}, links: []string{"/etc/vsftpd/user_list"}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			r := shippedControl(t, c.id).Remediation
			root, bin := t.TempDir(), t.TempDir()
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
			body, val := rebaseRoot(" "+r.Script, root), rebaseRoot(" "+r.Validate, root)
			if _, code := runBody(t, root, bin, val); code == 0 && len(c.loosened) > 0 {
				t.Error("validate passed on the loosened tree")
			}
			if out, code := runBody(t, root, bin, body); code != 0 {
				t.Fatalf("body %d: %s", code, out)
			}
			if out, code := runBody(t, root, bin, val); code != 0 {
				t.Fatalf("validate after the body %d: %s", code, out)
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
			if c.id == "muster.account.cron_permissions" && len(c.links) == 0 {
				if err := exec.Command("getent", "group", "crontab").Run(); err != nil {
					t.Log("no crontab group on this host: the access-file group was not checked")
				} else if out, err := exec.Command("stat", "-c", "%G", filepath.Join(root, "/etc/cron.allow")).Output(); err != nil || strings.TrimSpace(string(out)) != "crontab" {
					t.Errorf("/etc/cron.allow is in group %q (%v), want crontab", strings.TrimSpace(string(out)), err)
				}
			}
		})
	}
}
