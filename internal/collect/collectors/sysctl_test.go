//go:build linux

package collectors

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// procSysSeeds is the twelve /proc/sys files the sysctl collector reads, all
// answering "1", so a test can override exactly the ones it is about and
// every other leaf still has a value.
func procSysSeeds() map[string]string {
	return map[string]string{
		"/proc/sys/kernel/kptr_restrict":             "proc_sys.1",
		"/proc/sys/kernel/dmesg_restrict":            "proc_sys.1",
		"/proc/sys/kernel/yama/ptrace_scope":         "proc_sys.1",
		"/proc/sys/kernel/randomize_va_space":        "proc_sys.2",
		"/proc/sys/kernel/unprivileged_bpf_disabled": "proc_sys.2",
		"/proc/sys/net/core/bpf_jit_harden":          "proc_sys.0",
		"/proc/sys/kernel/perf_event_paranoid":       "proc_sys.2",
		"/proc/sys/kernel/sysrq":                     "proc_sys.176",
		"/proc/sys/fs/protected_symlinks":            "proc_sys.1",
		"/proc/sys/fs/protected_hardlinks":           "proc_sys.1",
		"/proc/sys/fs/protected_fifos":               "proc_sys.1",
		"/proc/sys/fs/protected_regular":             "proc_sys.2",
	}
}

// seedLink expresses one symlink the way fsAccess does. Three maps are
// involved because the double answers three different questions about the
// same entry: Glob must see the NAME (dirs), Stat must call it a symlink
// (links), and a read must fail the way the no-follow primitive fails
// (fails). A collector that models a link asks the first two; one that does
// not falls through to the third.
func seedLink(a *fsAccess, p, target string) {
	if a.dirs == nil {
		a.dirs = map[string]bool{}
	}
	if a.links == nil {
		a.links = map[string]string{}
	}
	if a.fails == nil {
		a.fails = map[string]error{}
	}
	a.dirs[p] = true
	a.links[p] = target
	a.fails[p] = fmt.Errorf("%s: %w", p, collect.ErrSymlink)
}

// The runtime side is the /proc/sys read and nothing else: a value, the file
// that answered as a "proc" source, and — for the three ways a read can fail
// — absent, denied and error, never a guess. Effective is a copy of runtime
// and the winner is the runtime source (B-3, K-3).
func TestSysctlRuntimeEnvelopes(t *testing.T) {
	files := procSysSeeds()
	files["/proc/sys/kernel/randomize_va_space"] = "proc_sys.not-an-integer"
	delete(files, "/proc/sys/kernel/yama/ptrace_scope") // Yama not built in
	a := &fsAccess{
		files: files,
		fails: map[string]error{"/proc/sys/fs/protected_symlinks": unix.EACCES},
	}
	b := build(t, "sysctl", a)

	sysrq := setting(t, b, "kernel.sysctl.sysrq")
	if sysrq.Runtime == nil || sysrq.Runtime.Status != facts.StatusOK || sysrq.Runtime.Value != 176 {
		t.Fatalf("sysrq runtime %+v, want ok 176", sysrq.Runtime)
	}
	want := facts.Source{Kind: "proc", Path: "/proc/sys/kernel/sysrq"}
	if !sameSource(sysrq.Runtime.Source, &want) {
		t.Errorf("sysrq runtime source %+v, want %+v", sysrq.Runtime.Source, want)
	}
	if sysrq.Effective == nil || !reflect.DeepEqual(*sysrq.Effective, *sysrq.Runtime) {
		t.Errorf("effective %+v is not a copy of runtime %+v", sysrq.Effective, sysrq.Runtime)
	}
	// A copy, not the same envelope or the same Source: nothing downstream
	// may change one side by writing to the other (R147).
	if sysrq.Effective == sysrq.Runtime || sysrq.Effective.Source == sysrq.Runtime.Source {
		t.Error("effective shares storage with runtime")
	}
	if !sameSource(sysrq.Winner, &want) {
		t.Errorf("winner %+v, want the runtime source %+v", sysrq.Winner, want)
	}
	if sysrq.Winner == sysrq.Runtime.Source {
		t.Error("winner shares the runtime envelope's Source pointer")
	}

	yama := setting(t, b, "kernel.sysctl.yama_ptrace_scope")
	if yama.Runtime.Status != facts.StatusAbsent ||
		!strings.Contains(yama.Runtime.Reason, "/proc/sys/kernel/yama/ptrace_scope") ||
		!strings.Contains(yama.Runtime.Reason, "does not exist") {
		t.Errorf("a kernel without Yama: %+v, want absent naming the path", yama.Runtime)
	}
	if yama.Effective.Status != facts.StatusAbsent {
		t.Errorf("effective %+v, want the runtime's absent", yama.Effective)
	}
	if yama.Winner != nil {
		t.Errorf("winner %+v, want none: the runtime read produced no source", yama.Winner)
	}

	den := setting(t, b, "kernel.sysctl.protected_symlinks")
	if den.Runtime.Status != facts.StatusDenied {
		t.Errorf("a 0600 /proc/sys file read without root: %+v, want denied", den.Runtime)
	}
	if !strings.Contains(den.Runtime.Reason, "/proc/sys/fs/protected_symlinks") {
		t.Errorf("denied reason %q does not name the file", den.Runtime.Reason)
	}
	if den.Effective.Status != facts.StatusDenied {
		t.Errorf("effective %+v, want the runtime's denied", den.Effective)
	}

	bad := setting(t, b, "kernel.sysctl.randomize_va_space")
	if bad.Runtime.Status != facts.StatusError ||
		!strings.Contains(bad.Runtime.Reason, "/proc/sys/kernel/randomize_va_space") ||
		!strings.Contains(bad.Runtime.Reason, "abc") {
		t.Errorf("a non-integer value: %+v, want error naming the path and the bytes", bad.Runtime)
	}
}

// The persisted side is the sysctl.d chain systemd-sysctl itself resolves:
// every *.conf of the four directories, a name in an earlier directory
// masking the same name later, the survivors applied in basename order with
// the last assignment winning, and /etc/sysctl.conf last.
func TestSysctlPersistedMerge(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/usr/lib/sysctl.d/50-default.conf":       "sysctl.d-50-default.conf",
		"/usr/lib/sysctl.d/99-protect-links.conf": "sysctl.d-99-protect-links.conf",
		"/etc/sysctl.d/99-protect-links.conf":     "sysctl.d-99-protect-links.etc.conf",
		"/etc/sysctl.d/10-magic-sysrq.conf":       "sysctl.d-10-magic-sysrq.conf",
		"/etc/sysctl.d/60-hardening.conf":         "sysctl.d-60-hardening.conf",
		"/etc/sysctl.conf":                        "sysctl.conf.sample",
	}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	b := build(t, "sysctl", a)

	// sysctl.d(5): "the entry in the file with the lexicographically latest
	// name will take precedence", whichever directory each file came from.
	// 10-magic-sysrq.conf sets 176, 50-default.conf sets 16 and
	// 60-hardening.conf sets 0, so the administrator's own file wins — and it
	// wins on its NAME, not because it is under /etc.
	if got := persistedOK(t, b, "kernel.sysctl.sysrq"); got.Value != 0 {
		t.Errorf("sysrq persisted %+v, want 0 from the lexicographically last file", got)
	} else if got.Source.Path != "/etc/sysctl.d/60-hardening.conf" {
		t.Errorf("sysrq persisted cites %q, want /etc/sysctl.d/60-hardening.conf", got.Source.Path)
	}

	// Masking: /etc/sysctl.d/99-protect-links.conf owns that base name, so
	// the vendor file of the same name is never opened at all.
	if got := persistedOK(t, b, "kernel.sysctl.protected_regular"); got.Value != 0 {
		t.Errorf("protected_regular persisted %+v, want 0 from the masking /etc file", got)
	} else if got.Source.Path != "/etc/sysctl.d/99-protect-links.conf" {
		t.Errorf("protected_regular cites %q, want the /etc copy", got.Source.Path)
	}
	if slices.Contains(a.reads, "/usr/lib/sysctl.d/99-protect-links.conf") {
		t.Error("the masked vendor file was read; a masked name is never opened")
	}
	// The masked file's OTHER assignment is masked with it: the /etc copy
	// replaces the whole file, it does not merge into it.
	if got := persisted(t, b, "kernel.sysctl.protected_fifos"); got.Status != facts.StatusAbsent {
		t.Errorf("protected_fifos persisted %+v, want absent: only the masked file set it", got)
	}

	// The slash spelling of a key and the ignore-if-missing "-" prefix are
	// both assignments (sysctl.d(5)).
	if got := persistedOK(t, b, "kernel.sysctl.yama_ptrace_scope"); got.Value != 1 {
		t.Errorf("kernel/yama/ptrace_scope persisted %+v, want 1 under the dotted key", got)
	}
	if got := persistedOK(t, b, "kernel.sysctl.unprivileged_bpf_disabled"); got.Value != 2 {
		t.Errorf("-kernel.unprivileged_bpf_disabled persisted %+v, want 2", got)
	}

	// The last assignment wins WITHIN one file too, not only across files:
	// 60-hardening.conf sets perf_event_paranoid to 3 on line 7 and to 1 on
	// line 11, and the source must cite the line that won.
	if got := persistedOK(t, b, "kernel.sysctl.perf_event_paranoid"); got.Value != 1 {
		t.Errorf("perf_event_paranoid persisted %+v, want 1: the file assigns it twice", got)
	} else if got.Source.Line != 11 {
		t.Errorf("perf_event_paranoid cites line %d, want 11, the second assignment", got.Source.Line)
	}

	// A CRLF-terminated line parses as its value, not as the value plus a
	// carriage return, and the evidence line carries none either.
	if got := persistedOK(t, b, "kernel.sysctl.randomize_va_space"); got.Value != 2 {
		t.Errorf("randomize_va_space persisted %+v, want 2 from the CRLF line", got)
	} else if strings.ContainsRune(got.Source.Raw, '\r') {
		t.Errorf("the evidence line %q kept its carriage return", got.Source.Raw)
	}

	// /etc/sysctl.conf is applied last of all.
	if got := persistedOK(t, b, "kernel.sysctl.kptr_restrict"); got.Value != 2 {
		t.Errorf("kptr_restrict persisted %+v, want 2 from /etc/sysctl.conf", got)
	} else if got.Source.Path != "/etc/sysctl.conf" {
		t.Errorf("kptr_restrict cites %q, want /etc/sysctl.conf", got.Source.Path)
	}

	// A key no file sets is absent with the key named, never the kernel's
	// compiled-in default.
	got := persisted(t, b, "kernel.sysctl.bpf_jit_harden")
	if got.Status != facts.StatusAbsent || !strings.Contains(got.Reason, "net.core.bpf_jit_harden") {
		t.Errorf("bpf_jit_harden persisted %+v, want absent naming the sysctl", got)
	}

	// The persisted side never decides the effective one (B-3).
	if s := setting(t, b, "kernel.sysctl.sysrq"); s.Effective.Value != 176 {
		t.Errorf("effective %+v, want the runtime 176 even though the files say 0", s.Effective)
	}
}

// The one symlink modelled: a distribution's /etc/sysctl.d/99-sysctl.conf
// points at ../sysctl.conf, so /etc/sysctl.conf is read at that position and
// the winner cites the real file rather than the link (C4, spec B-2).
func TestSysctlModelsTheStockSysctlConfLink(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/usr/lib/sysctl.d/50-default.conf": "sysctl.d-50-default.conf",
		"/etc/sysctl.conf":                  "sysctl.conf.sample",
	}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	seedLink(a, "/etc/sysctl.d/99-sysctl.conf", "../sysctl.conf")
	b := build(t, "sysctl", a)

	got := persistedOK(t, b, "kernel.sysctl.kptr_restrict")
	if got.Value != 2 || got.Source.Path != "/etc/sysctl.conf" {
		t.Errorf("kptr_restrict persisted %+v, want 2 citing /etc/sysctl.conf", got)
	}
	// Read once, at the link's position — not once there and once again as
	// the trailing main file.
	n := 0
	for _, p := range a.reads {
		if p == "/etc/sysctl.conf" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("/etc/sysctl.conf was read %d times, want exactly 1", n)
	}
	if e := persisted(t, b, "kernel.sysctl.dmesg_restrict"); e.Status != facts.StatusOK {
		t.Errorf("the linked file's other assignment: %+v, want ok", e)
	}
}

// Every other symlink in a sysctl.d is that file's error: muster reads
// without following links, and only the one a distribution ships is modelled
// (C4).
func TestSysctlOtherSymlinkIsAnError(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/sysctl.conf": "sysctl.conf.sample"}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	seedLink(a, "/etc/sysctl.d/70-managed.conf", "/opt/config/sysctl.conf")
	b := build(t, "sysctl", a)

	got := persisted(t, b, "kernel.sysctl.kptr_restrict")
	if got.Status != facts.StatusError || !strings.Contains(got.Reason, "/etc/sysctl.d/70-managed.conf") {
		t.Errorf("persisted %+v, want error naming the symlinked fragment", got)
	}
	// C3: the unreadable fragment is the answer for every value it could
	// have set, and the runtime side is untouched by it.
	if s := setting(t, b, "kernel.sysctl.sysrq"); s.Runtime.Status != facts.StatusOK || s.Effective.Value != 176 {
		t.Errorf("runtime %+v / effective %+v, want the /proc/sys answer", s.Runtime, s.Effective)
	}
}

// K-21: a link to /dev/null is sysctl.d(5)'s mask idiom, not a fragment
// muster failed to read. The base name is disabled — the vendor file below it
// is never opened — and nothing about it is an error.
func TestSysctlDevNullMasksABaseName(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/usr/lib/sysctl.d/99-protect-links.conf": "sysctl.d-99-protect-links.conf",
		"/etc/sysctl.d/10-magic-sysrq.conf":       "sysctl.d-10-magic-sysrq.conf",
	}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	seedLink(a, "/etc/sysctl.d/99-protect-links.conf", "/dev/null")
	b := build(t, "sysctl", a)

	// Not an error anywhere: the masked key simply has no persisted value.
	for _, key := range []string{"kernel.sysctl.protected_regular", "kernel.sysctl.protected_fifos"} {
		if got := persisted(t, b, key); got.Status != facts.StatusAbsent {
			t.Errorf("%s persisted %+v, want absent: the base name is masked to /dev/null", key, got)
		}
	}
	if slices.Contains(a.reads, "/usr/lib/sysctl.d/99-protect-links.conf") {
		t.Error("the masked vendor file was read; /dev/null still owns that base name")
	}
	// Every other key is untouched by the mask.
	if got := persistedOK(t, b, "kernel.sysctl.sysrq"); got.Value != 176 {
		t.Errorf("sysrq persisted %+v, want 176 from the file the mask says nothing about", got)
	}
}

// A sysctl.d directory this run may not list is that directory's denied on
// every persisted side (C3); the runtime side does not change.
func TestSysctlDeniedDirectoryReachesEveryPersistedSide(t *testing.T) {
	a := &fsAccess{
		files:      procSysSeeds(),
		deniedDirs: map[string]bool{"/etc/sysctl.d": true},
	}
	b := build(t, "sysctl", a)
	for _, key := range []string{"kernel.sysctl.sysrq", "kernel.sysctl.kptr_restrict", "kernel.sysctl.protected_regular"} {
		if got := persisted(t, b, key); got.Status != facts.StatusDenied {
			t.Errorf("%s persisted %+v, want denied", key, got)
		}
	}
	if s := setting(t, b, "kernel.sysctl.sysrq"); s.Runtime.Status != facts.StatusOK {
		t.Errorf("runtime %+v, want ok: a denied directory says nothing about /proc/sys", s.Runtime)
	}
}

// A persisted value that is not an integer is an error naming the file and
// the bytes, the same rule the runtime side follows.
func TestSysctlPersistedNonIntegerIsAnError(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/sysctl.d/10-bad.conf": "sysctl.d-bad-value.conf",
	}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	got := persisted(t, build(t, "sysctl", a), "kernel.sysctl.perf_event_paranoid")
	if got.Status != facts.StatusError ||
		!strings.Contains(got.Reason, "/etc/sysctl.d/10-bad.conf") ||
		!strings.Contains(got.Reason, "high") {
		t.Errorf("persisted %+v, want error naming the file and the bytes", got)
	}
}

// The twelve keys of B-2 and the twenty-seven of P-4 and no others, each
// written once, and a declaration that covers every path the collector
// reaches for (K-4).
func TestSysctlDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "sysctl")
	if c.Declare.Needs != "none" {
		t.Errorf("Needs %q, want none: nothing here requires root", c.Declare.Needs)
	}
	if len(c.Declare.Commands) != 0 {
		t.Errorf("declares %d commands, want none: /proc/sys is read directly (B-3)", len(c.Declare.Commands))
	}
	if c.Declare.Walk {
		t.Error("declares the walk licence, which this collector has no use for")
	}

	// The declaration, written out by hand: a typo in the table under test
	// must not be able to rewrite what this expects.
	want := []string{
		"/etc/sysctl.conf",
		"/etc/sysctl.d/*.conf",
		"/proc/sys/fs/protected_fifos",
		"/proc/sys/fs/protected_hardlinks",
		"/proc/sys/fs/protected_regular",
		"/proc/sys/fs/protected_symlinks",
		"/proc/sys/kernel/dmesg_restrict",
		"/proc/sys/kernel/kptr_restrict",
		"/proc/sys/kernel/perf_event_paranoid",
		"/proc/sys/kernel/randomize_va_space",
		"/proc/sys/kernel/sysrq",
		"/proc/sys/kernel/unprivileged_bpf_disabled",
		"/proc/sys/kernel/yama/ptrace_scope",
		"/proc/sys/net/core/bpf_jit_harden",
		"/proc/sys/net/ipv4/conf/all/accept_redirects",
		"/proc/sys/net/ipv4/conf/all/accept_source_route",
		"/proc/sys/net/ipv4/conf/all/log_martians",
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/all/secure_redirects",
		"/proc/sys/net/ipv4/conf/all/send_redirects",
		"/proc/sys/net/ipv4/conf/default/accept_redirects",
		"/proc/sys/net/ipv4/conf/default/accept_source_route",
		"/proc/sys/net/ipv4/conf/default/log_martians",
		"/proc/sys/net/ipv4/conf/default/rp_filter",
		"/proc/sys/net/ipv4/conf/default/secure_redirects",
		"/proc/sys/net/ipv4/conf/default/send_redirects",
		"/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
		"/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/tcp_syncookies",
		"/proc/sys/net/ipv6/bindv6only",
		"/proc/sys/net/ipv6/conf/*/disable_ipv6",
		"/proc/sys/net/ipv6/conf/all/accept_ra",
		"/proc/sys/net/ipv6/conf/all/accept_redirects",
		"/proc/sys/net/ipv6/conf/all/accept_source_route",
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/default/accept_ra",
		"/proc/sys/net/ipv6/conf/default/accept_redirects",
		"/proc/sys/net/ipv6/conf/default/accept_source_route",
		"/proc/sys/net/ipv6/conf/default/disable_ipv6",
		"/proc/sys/net/ipv6/conf/default/forwarding",
		"/run/sysctl.d/*.conf",
		"/usr/lib/sysctl.d/*.conf",
		"/usr/local/lib/sysctl.d/*.conf",
	}
	got := slices.Clone(c.Declare.Reads)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Reads =\n%v\nwant\n%v", got, want)
	}

	// Each leaf's /proc/sys path is licensed by one of those entries, under
	// the guard's own matching rule.
	for _, l := range sysctlLeaves {
		if !slices.ContainsFunc(c.Declare.Reads, func(r string) bool {
			ok, _ := path.Match(r, l.path)
			return ok
		}) {
			t.Errorf("%s reads %s, which no declared pattern covers", l.leaf, l.path)
		}
	}

	a := &fsAccess{files: procSysSeeds()}
	b := buildBegun(t, "sysctl", a)
	keys := b.Keys("sysctl")
	if len(keys) != 40 {
		t.Errorf("wrote %d keys, want the twelve of B-2, the twenty-seven of P-4 and the derived ipv6_disabled (W-79): %v", len(keys), keys)
	}
	for _, k := range []string{"net.sysctl.ipv6_bindv6only", "net.sysctl.ipv6_disabled"} {
		if !slices.Contains(keys, k) {
			t.Errorf("%s was not written", k)
		}
	}
	net, ok := leaf(t, b, "net.sysctl").(map[string]any)
	if !ok || len(net) != 28 {
		t.Errorf("net.sysctl carries %d leaves (%T), want 28", len(net), leaf(t, b, "net.sysctl"))
	}
	tree, ok := leaf(t, b, "kernel.sysctl").(map[string]any)
	if !ok {
		t.Fatalf("kernel.sysctl is %T, want a tree of leaves", leaf(t, b, "kernel.sysctl"))
	}
	if len(tree) != 12 {
		t.Errorf("kernel.sysctl carries %d leaves, want 12", len(tree))
	}
	for _, l := range sysctlLeaves {
		if !slices.Contains(keys, l.leaf) {
			t.Errorf("%s was not written", l.leaf)
		}
		if l.path != "/proc/sys/"+strings.ReplaceAll(l.key, ".", "/") {
			t.Errorf("%s: path %s is not the /proc/sys form of %s", l.leaf, l.path, l.key)
		}
	}
}

func TestParseSysctlD(t *testing.T) {
	got := parseSysctlD([]byte("" +
		"# a comment\n" +
		"; another\n" +
		"\n" +
		"-kernel.foo = 1\n" +
		"kernel/yama/ptrace_scope = 2\n" +
		"net/ipv4/conf/eth0.1/rp_filter = 1\n" +
		"   kernel.sysrq\t=\t176   \n" +
		"no equals\n" +
		"= 3\n" +
		"net.ipv4.conf.*.rp_filter = 2\n" +
		"-net.ipv4.conf.all.rp_filter\n" +
		"-net/ipv4/conf/all/accept_source_route\n" +
		"-\n"))
	want := []sysctlAssign{
		{key: "kernel.foo", value: "1", ignoreMissing: true, line: 4, raw: "-kernel.foo = 1"},
		{key: "kernel.yama.ptrace_scope", value: "2", line: 5, raw: "kernel/yama/ptrace_scope = 2"},
		{key: "net.ipv4.conf.eth0.1.rp_filter", value: "1", line: 6, raw: "net/ipv4/conf/eth0.1/rp_filter = 1"},
		{key: "kernel.sysrq", value: "176", line: 7, raw: "   kernel.sysrq\t=\t176   "},
		{key: "net.ipv4.conf.*.rp_filter", value: "2", glob: true, line: 10, raw: "net.ipv4.conf.*.rp_filter = 2"},
		{key: "net.ipv4.conf.all.rp_filter", ignoreMissing: true, exclude: true, line: 11, raw: "-net.ipv4.conf.all.rp_filter"},
		{key: "net.ipv4.conf.all.accept_source_route", ignoreMissing: true, exclude: true, line: 12, raw: "-net/ipv4/conf/all/accept_source_route"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSysctlD =\n%+v\nwant\n%+v", got, want)
	}
}

// normalizeSysctlName follows sysctl.d(5): the slash spelling is recognised
// by the FIRST separator, so a dotted key that contains a slash later keeps
// its dots and an interface name with a dot in it survives the slash form.
func TestNormalizeSysctlName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"kernel.sysrq", "kernel.sysrq"},
		{"kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope"},
		{"net.ipv4.conf.eth0.1.rp_filter", "net.ipv4.conf.eth0.1.rp_filter"},
		{"net/ipv4/conf/eth0.1/rp_filter", "net.ipv4.conf.eth0.1.rp_filter"},
		{"", ""},
	} {
		if got := normalizeSysctlName(tc.in); got != tc.want {
			t.Errorf("normalizeSysctlName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --- helpers ------------------------------------------------------------

// sameSource compares two sources by value. facts.Source carries a slice of
// its own inputs, so it is not comparable with ==.
func sameSource(got, want *facts.Source) bool {
	return got != nil && want != nil && reflect.DeepEqual(*got, *want)
}

func persisted(t *testing.T, b *collect.Builder, key string) facts.Envelope {
	t.Helper()
	s := setting(t, b, key)
	if s.Persisted == nil {
		t.Fatalf("%s has no persisted side", key)
	}
	return *s.Persisted
}

func persistedOK(t *testing.T, b *collect.Builder, key string) facts.Envelope {
	t.Helper()
	e := persisted(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s persisted %+v, want ok", key, e)
	}
	if e.Source == nil {
		t.Fatalf("%s persisted ok with no source", key)
	}
	return e
}

// The kernel's own proc_get_long takes the base from the text, so an
// administrator's `0x10` is the sixteen the host would apply. Reading it as
// "not an integer" would turn a working configuration into an ERROR, and
// reading it as ten would be worse.
func TestSysctlPersistedAcceptsTheBasesTheKernelDoes(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       any
	}{
		{"hex", "kernel.sysrq = 0x10\n", 16},
		{"octal", "kernel.sysrq = 0177\n", 127},
		{"decimal", "kernel.sysrq = 16\n", 16},
	} {
		a := &fsAccess{files: map[string]string{}, contents: map[string][]byte{
			"/etc/sysctl.d/10-base.conf": []byte(tc.text),
		}}
		for k, v := range procSysSeeds() {
			a.files[k] = v
		}
		b := build(t, "sysctl", a)
		if got := persistedOK(t, b, "kernel.sysctl.sysrq"); got.Value != tc.want {
			t.Errorf("%s: persisted %#v, want %#v", tc.name, got.Value, tc.want)
		}
	}
}

// Truncation has to reach the ABSENT branch too. "No sysctl.d line sets this"
// is a conclusion about bytes that were all read; when a file of the chain was
// cut at the read cap, the line that did set it may be past the cut, and an
// unmarked absent would let a control read that guess as the host's answer.
func TestSysctlAbsentPersistedCarriesTheChainsTruncation(t *testing.T) {
	const cut = "/etc/sysctl.d/10-magic-sysrq.conf"
	a := &fsAccess{
		files:     map[string]string{cut: "sysctl.d-10-magic-sysrq.conf"},
		truncated: map[string]bool{cut: true},
	}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	b := build(t, "sysctl", a)

	got := persisted(t, b, "kernel.sysctl.bpf_jit_harden")
	if got.Status != facts.StatusAbsent {
		t.Fatalf("persisted %+v, want absent: no file of the chain sets it", got)
	}
	if !got.Truncated {
		t.Errorf("persisted %+v, want truncated: %s was cut at the read cap", got, cut)
	}
}

// netSysValues gives each of the twenty-seven P-4 files a distinct value, so
// a leaf wired to the wrong file reads the wrong number.
func netSysValues() map[string]int {
	out := map[string]int{}
	for i, l := range sysctlLeaves {
		if strings.HasPrefix(l.leaf, "net.sysctl.") {
			out[l.path] = 100 + i
		}
	}
	out[sysctlBindV6OnlyPath] = 1
	return out
}

func netSysAccess(drop func(string) bool) *fsAccess {
	a := &fsAccess{files: procSysSeeds(), contents: map[string][]byte{}}
	for p, v := range netSysValues() {
		if drop != nil && drop(p) {
			continue
		}
		a.contents[p] = []byte(fmt.Sprintf("%d\n", v))
	}
	return a
}

// Every P-4 file is read into its own key: twenty-six settings whose runtime
// (and so effective) side is the /proc/sys number, and bindv6only as a plain
// int envelope.
func TestSysctlNetLeavesAreRead(t *testing.T) {
	vals := netSysValues()
	b := build(t, "sysctl", netSysAccess(nil))
	n := 0
	for _, l := range sysctlLeaves {
		if !strings.HasPrefix(l.leaf, "net.sysctl.") {
			continue
		}
		n++
		s := setting(t, b, l.leaf)
		if s.Runtime == nil || s.Runtime.Status != facts.StatusOK || s.Runtime.Value != vals[l.path] {
			t.Errorf("%s runtime %+v, want ok %d from %s", l.leaf, s.Runtime, vals[l.path], l.path)
		}
		if s.Effective == nil || s.Effective.Value != vals[l.path] {
			t.Errorf("%s effective %+v, want the runtime %d", l.leaf, s.Effective, vals[l.path])
		}
	}
	if n != 26 {
		t.Errorf("%d net.sysctl settings in sysctlLeaves, want 26", n)
	}
	e, ok := leaf(t, b, "net.sysctl.ipv6_bindv6only").(facts.Envelope)
	if !ok {
		t.Fatalf("net.sysctl.ipv6_bindv6only is %T, want a plain envelope", leaf(t, b, "net.sysctl.ipv6_bindv6only"))
	}
	if e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("bindv6only %+v, want ok 1", e)
	}
	want := facts.Source{Kind: "proc", Path: sysctlBindV6OnlyPath}
	if !sameSource(e.Source, &want) {
		t.Errorf("bindv6only source %+v, want %+v", e.Source, want)
	}
}

// A kernel booted with ipv6.disable=1 has no /proc/sys/net/ipv6 at all: every
// ipv6 key is absent saying so, and the IPv4 keys are untouched (spec P-4).
func TestSysctlIPv6AbsentReadsNotBuilt(t *testing.T) {
	b := build(t, "sysctl", netSysAccess(func(p string) bool { return strings.HasPrefix(p, "/proc/sys/net/ipv6/") }))
	check := func(key string, e facts.Envelope) {
		t.Helper()
		if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "IPv6 is not built or is disabled") {
			t.Errorf("%s %+v, want absent: IPv6 is not built or is disabled", key, e)
		}
	}
	v6 := 0
	for _, l := range sysctlLeaves {
		s := setting(t, b, l.leaf)
		switch {
		case strings.HasPrefix(l.leaf, "net.sysctl.ipv6_"):
			v6++
			check(l.leaf, *s.Runtime)
			check(l.leaf, *s.Effective)
		case strings.HasPrefix(l.leaf, "net.sysctl.ipv4_"):
			if s.Runtime.Status != facts.StatusOK {
				t.Errorf("%s runtime %+v, want ok: only IPv6 is gone", l.leaf, s.Runtime)
			}
		}
	}
	if v6 != 10 {
		t.Errorf("%d ipv6 settings, want 10", v6)
	}
	check("net.sysctl.ipv6_bindv6only", leaf(t, b, "net.sysctl.ipv6_bindv6only").(facts.Envelope))

	// The reason is IPv6's own: a missing knob elsewhere keeps the plain one.
	a := netSysAccess(nil)
	delete(a.files, "/proc/sys/kernel/yama/ptrace_scope")
	y := setting(t, build(t, "sysctl", a), "kernel.sysctl.yama_ptrace_scope")
	if y.Runtime.Status != facts.StatusAbsent || strings.Contains(y.Runtime.Reason, "IPv6") {
		t.Errorf("a missing Yama knob: %+v, want absent without the IPv6 reason", y.Runtime)
	}
}

// systemd's own 50-default.conf, verbatim from ubuntu:22.04's systemd
// package: a concrete default line, a glob for every interface, and a "-key"
// exclusion for "all". Ubuntu comments out the rp_filter exclusion and keeps
// the accept_source_route one, so the same file shows both outcomes.
func TestParseSysctlDGlobAndExclusion(t *testing.T) {
	a := netSysAccess(nil)
	a.files["/usr/lib/sysctl.d/50-default.conf"] = "sysctl.d-50-default.ubuntu2204.conf"
	b := build(t, "sysctl", a)

	// The concrete line, not the glob below it.
	if got := persistedOK(t, b, "net.sysctl.ipv4_default_rp_filter"); got.Value != 2 || got.Source.Line != 25 {
		t.Errorf("default.rp_filter persisted %+v, want 2 from line 25", got)
	}
	// No line names all.rp_filter and the exclusion is commented out, so the
	// glob reaches it.
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Value != 2 || got.Source.Line != 26 ||
		got.Source.Raw != "net.ipv4.conf.*.rp_filter = 2" {
		t.Errorf("all.rp_filter persisted %+v, want 2 from the glob on line 26", got)
	}
	if got := persistedOK(t, b, "net.sysctl.ipv4_default_accept_source_route"); got.Value != 0 || got.Source.Line != 30 {
		t.Errorf("default.accept_source_route persisted %+v, want 0 from line 30", got)
	}
	// -net.ipv4.conf.all.accept_source_route keeps the glob off that key.
	got := persisted(t, b, "net.sysctl.ipv4_all_accept_source_route")
	if got.Status != facts.StatusAbsent || !strings.Contains(got.Reason, "no sysctl.d line sets net.ipv4.conf.all.accept_source_route") {
		t.Errorf("all.accept_source_route persisted %+v, want absent: the glob excludes it", got)
	}
	// A key no line and no glob names.
	got = persisted(t, b, "net.sysctl.ipv4_ip_forward")
	if got.Status != facts.StatusAbsent || !strings.Contains(got.Reason, "no sysctl.d line sets net.ipv4.ip_forward") {
		t.Errorf("ip_forward persisted %+v, want absent", got)
	}
	// "conf.*" is one component: the glob does not reach the ipv6 tree.
	if got := persisted(t, b, "net.sysctl.ipv6_all_accept_source_route"); got.Status != facts.StatusAbsent {
		t.Errorf("ipv6 all.accept_source_route persisted %+v, want absent", got)
	}
}

// systemd-sysctl skips a glob for every key the chain names explicitly, so a
// concrete line wins even when the glob comes from a LATER file (W-46).
func TestSysctlConcreteBeatsGlob(t *testing.T) {
	a := netSysAccess(nil)
	a.contents["/etc/sysctl.d/10-concrete.conf"] = []byte("net.ipv4.conf.all.send_redirects = 0\n")
	a.contents["/etc/sysctl.d/90-glob.conf"] = []byte("" +
		"net.ipv4.conf.*.send_redirects = 1\n" +
		"net.ipv4.conf.*.log_martians = 1\n" +
		"net.ipv4.conf.*.log_martians = 0\n")
	b := build(t, "sysctl", a)

	got := persistedOK(t, b, "net.sysctl.ipv4_all_send_redirects")
	if got.Value != 0 || got.Source.Path != "/etc/sysctl.d/10-concrete.conf" {
		t.Errorf("all.send_redirects persisted %+v, want 0 from the concrete line in the earlier file", got)
	}
	// The glob still sets the key no line names.
	got = persistedOK(t, b, "net.sysctl.ipv4_default_send_redirects")
	if got.Value != 1 || got.Source.Path != "/etc/sysctl.d/90-glob.conf" {
		t.Errorf("default.send_redirects persisted %+v, want 1 from the glob", got)
	}
	// The last of two globs wins.
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_log_martians"); got.Value != 0 || got.Source.Line != 3 {
		t.Errorf("all.log_martians persisted %+v, want 0 from line 3", got)
	}
}

// A "-key" line after a concrete line replaces it, as systemd's table does: the
// key is then set by nothing, neither the earlier line nor a glob.
func TestSysctlExclusionAfterConcreteLeavesTheKeyUnset(t *testing.T) {
	a := netSysAccess(nil)
	a.contents["/etc/sysctl.d/10-a.conf"] = []byte("net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.*.rp_filter = 2\n")
	a.contents["/etc/sysctl.d/20-b.conf"] = []byte("-net.ipv4.conf.all.rp_filter\n")
	b := build(t, "sysctl", a)
	if got := persisted(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Status != facts.StatusAbsent {
		t.Errorf("all.rp_filter persisted %+v, want absent", got)
	}
	if got := persistedOK(t, b, "net.sysctl.ipv4_default_rp_filter"); got.Value != 2 {
		t.Errorf("default.rp_filter persisted %+v, want 2 from the glob", got)
	}
}

func TestSysctlGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, key string
		want         bool
	}{
		{"net.ipv4.conf.*.rp_filter", "net.ipv4.conf.all.rp_filter", true},
		{"net.ipv4.conf.*.rp_filter", "net.ipv4.conf.default.rp_filter", true},
		{"net.ipv4.conf.*.rp_filter", "net.ipv4.conf.eth0.1.rp_filter", false},
		{"net.ipv4.*", "net.ipv4.conf.all.rp_filter", false},
		{"net.ipv?.conf.all.rp_filter", "net.ipv6.conf.all.rp_filter", true},
		{"net.ipv4.conf.[ad]*.rp_filter", "net.ipv4.conf.all.rp_filter", true},
		{"net.ipv4.conf.[.rp_filter", "net.ipv4.conf.[.rp_filter", false},
		// glob(3)'s "[!...]" negation, which path.Match spells "[^...]".
		{"net.ipv4.conf.[!d]*.rp_filter", "net.ipv4.conf.all.rp_filter", true},
		{"net.ipv4.conf.[!d]*.rp_filter", "net.ipv4.conf.default.rp_filter", false},
		{"net.ipv4.conf.[^d]*.rp_filter", "net.ipv4.conf.all.rp_filter", true},
		{"net.ipv4.conf.[a!]*.rp_filter", "net.ipv4.conf.all.rp_filter", true},
	} {
		if got := sysctlGlobMatch(tc.pattern, tc.key); got != tc.want {
			t.Errorf("sysctlGlobMatch(%q, %q) = %v, want %v", tc.pattern, tc.key, got, tc.want)
		}
	}
}

// glob(3)'s negated class reaches the merge: "[!d]*" sets all, not default.
func TestSysctlGlobNegationSetsTheOtherKey(t *testing.T) {
	a := netSysAccess(nil)
	a.contents["/etc/sysctl.d/10-a.conf"] = []byte("net.ipv4.conf.[!d]*.rp_filter = 1\n")
	b := build(t, "sysctl", a)
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Value != 1 {
		t.Errorf("all.rp_filter persisted %+v, want 1 from the negated class", got)
	}
	if got := persisted(t, b, "net.sysctl.ipv4_default_rp_filter"); got.Status != facts.StatusAbsent {
		t.Errorf("default.rp_filter persisted %+v, want absent: [!d] excludes it", got)
	}
}

// systemd's parse_file keeps an existing glob entry IN PLACE when a later
// line repeats its pattern with the same value, so the repeat does not move
// it past a narrower glob in between: all.rp_filter ends up 1 from 20-b.
func TestSysctlRepeatedEqualGlobKeepsItsPlace(t *testing.T) {
	a := netSysAccess(nil)
	a.contents["/etc/sysctl.d/10-a.conf"] = []byte("net.ipv4.conf.*.rp_filter = 2\n")
	a.contents["/etc/sysctl.d/20-b.conf"] = []byte("net.ipv4.conf.a*.rp_filter = 1\n")
	a.contents["/etc/sysctl.d/30-c.conf"] = []byte("net.ipv4.conf.*.rp_filter = 2\n")
	b := build(t, "sysctl", a)
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Value != 1 || got.Source.Path != "/etc/sysctl.d/20-b.conf" {
		t.Errorf("all.rp_filter persisted %+v, want 1 from 20-b.conf", got)
	}
	// The kept entry cites its own, earlier line.
	if got := persistedOK(t, b, "net.sysctl.ipv4_default_rp_filter"); got.Value != 2 || got.Source.Path != "/etc/sysctl.d/10-a.conf" {
		t.Errorf("default.rp_filter persisted %+v, want 2 citing 10-a.conf", got)
	}

	// A DIFFERENT value replaces the entry and moves it to the end.
	a.contents["/etc/sysctl.d/30-c.conf"] = []byte("net.ipv4.conf.*.rp_filter = 0\n")
	b = build(t, "sysctl", a)
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Value != 0 || got.Source.Path != "/etc/sysctl.d/30-c.conf" {
		t.Errorf("all.rp_filter persisted %+v, want 0 from 30-c.conf", got)
	}
}

// An exclusion is not sticky: a later concrete line for the same key
// replaces it, as any later line does.
func TestSysctlConcreteAfterExclusionSetsTheKey(t *testing.T) {
	a := netSysAccess(nil)
	a.contents["/etc/sysctl.d/20-b.conf"] = []byte("-net.ipv4.conf.all.rp_filter\n")
	a.contents["/etc/sysctl.d/30-c.conf"] = []byte("net.ipv4.conf.all.rp_filter = 1\n")
	b := build(t, "sysctl", a)
	if got := persistedOK(t, b, "net.sysctl.ipv4_all_rp_filter"); got.Value != 1 || got.Source.Path != "/etc/sysctl.d/30-c.conf" {
		t.Errorf("all.rp_filter persisted %+v, want 1 from 30-c.conf", got)
	}
}

// W-79: net.sysctl.ipv6_disabled is 1 only when disable_ipv6 is 1 on all AND
// on default; one leaf alone leaves IPv6 live on the present interfaces. A
// kernel without IPv6 reads absent with the fixed reason, never 0.
func TestSysctlIPv6DisabledDerived(t *testing.T) {
	const allP = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	const defP = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
	for _, c := range []struct {
		all, def, want int
	}{{0, 0, 0}, {1, 0, 0}, {0, 1, 0}, {1, 1, 1}} {
		a := netSysAccess(nil)
		a.contents[allP] = []byte(fmt.Sprintf("%d\n", c.all))
		a.contents[defP] = []byte(fmt.Sprintf("%d\n", c.def))
		b := build(t, "sysctl", a)
		e, ok := leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope)
		if !ok {
			t.Fatalf("net.sysctl.ipv6_disabled is %T, want a plain envelope", leaf(t, b, "net.sysctl.ipv6_disabled"))
		}
		if e.Status != facts.StatusOK || e.Value != c.want {
			t.Errorf("all=%d default=%d: %+v, want ok %d", c.all, c.def, e, c.want)
		}
		if e.Source == nil || len(e.Source.Inputs) != 2 || e.Source.Inputs[0].Path != allP || e.Source.Inputs[1].Path != defP {
			t.Errorf("all=%d default=%d: source %+v, want the two disable_ipv6 paths", c.all, c.def, e.Source)
		}
	}
	// W-86: every present interface but lo has its own flag, and the
	// kernel's drop test is that flag — one interface re-enabled after
	// all=1 speaks IPv6. lo is never read into the predicate.
	const eth0 = "/proc/sys/net/ipv6/conf/eth0/disable_ipv6"
	const eth1 = "/proc/sys/net/ipv6/conf/eth1/disable_ipv6"
	const loP = "/proc/sys/net/ipv6/conf/lo/disable_ipv6"
	for _, c := range []struct {
		name   string
		ifaces map[string]string
		want   int
		inputs []string
	}{
		{"eth0=1", map[string]string{eth0: "1\n", loP: "0\n"}, 1, []string{allP, defP, eth0}},
		{"eth1=0", map[string]string{eth0: "1\n", eth1: "0\n", loP: "1\n"}, 0, []string{allP, defP, eth0, eth1}},
	} {
		a := netSysAccess(nil)
		a.contents[allP] = []byte("1\n")
		a.contents[defP] = []byte("1\n")
		for p, v := range c.ifaces {
			a.contents[p] = []byte(v)
		}
		b := build(t, "sysctl", a)
		e := leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope)
		if e.Status != facts.StatusOK || e.Value != c.want {
			t.Errorf("all=1 default=1 %s: %+v, want ok %d", c.name, e, c.want)
		}
		var got []string
		if e.Source != nil {
			for _, in := range e.Source.Inputs {
				got = append(got, in.Path)
			}
		}
		if !slices.Equal(got, c.inputs) {
			t.Errorf("all=1 default=1 %s: source inputs %v, want %v", c.name, got, c.inputs)
		}
	}
	// An interface file that exists and cannot be read is the answer (C3),
	// and it stays in the source.
	a := netSysAccess(nil)
	a.contents[allP] = []byte("1\n")
	a.contents[defP] = []byte("1\n")
	a.contents[eth0] = []byte("1\n")
	a.fails = map[string]error{eth0: fs.ErrPermission}
	b := build(t, "sysctl", a)
	e := leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope)
	if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, eth0) {
		t.Errorf("an unreadable eth0: %+v, want denied naming %s", e, eth0)
	}
	if e.Source == nil || len(e.Source.Inputs) != 3 || e.Source.Inputs[2].Path != eth0 {
		t.Errorf("an unreadable eth0: source %+v, want all, default and eth0", e.Source)
	}
	// A conf directory this run may not list is the answer too.
	a = netSysAccess(nil)
	a.contents[allP] = []byte("1\n")
	a.contents[defP] = []byte("1\n")
	a.deniedDirs = map[string]bool{"/proc/sys/net/ipv6/conf": true}
	b = build(t, "sysctl", a)
	if e := leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/proc/sys/net/ipv6/conf") {
		t.Errorf("an unlistable conf directory: %+v, want denied naming it", e)
	}

	b = build(t, "sysctl", netSysAccess(func(p string) bool { return p == defP }))
	e = leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope)
	if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "IPv6 is not built or is disabled") {
		t.Errorf("a missing default/disable_ipv6: %+v, want absent: IPv6 is not built or is disabled", e)
	}
	if e.Source == nil || len(e.Source.Inputs) != 2 || e.Source.Inputs[0].Path != allP || e.Source.Inputs[1].Path != defP {
		t.Errorf("a missing default/disable_ipv6: source %+v, want the two disable_ipv6 paths", e.Source)
	}
}

// The worse of the two reads is the derived leaf's status, whichever side
// it is on: a refused or failed read outweighs one that found nothing, and
// a failure never reads ok 0.
func TestSysctlIPv6DisabledTakesTheWorseRead(t *testing.T) {
	const allP = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	const defP = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
	ioErr := errors.New("input/output error")
	for _, c := range []struct {
		name     string
		drop     string           // the path whose file is missing
		fails    map[string]error // the paths whose read fails
		want     facts.Status
		wantPath string // the path the reason names
	}{
		{"all absent, default error", allP, map[string]error{defP: ioErr}, facts.StatusError, defP},
		{"all error, default absent", defP, map[string]error{allP: ioErr}, facts.StatusError, allP},
		{"all denied, default absent", defP, map[string]error{allP: fs.ErrPermission}, facts.StatusDenied, allP},
		{"all ok, default error", "", map[string]error{defP: ioErr}, facts.StatusError, defP},
		{"all denied, default error", "", map[string]error{allP: fs.ErrPermission, defP: ioErr}, facts.StatusError, defP},
	} {
		a := netSysAccess(func(p string) bool { return p == c.drop })
		if c.drop != allP {
			a.contents[allP] = []byte("1\n")
		}
		a.fails = c.fails
		b := build(t, "sysctl", a)
		e := leaf(t, b, "net.sysctl.ipv6_disabled").(facts.Envelope)
		if e.Status != c.want || !strings.Contains(e.Reason, c.wantPath) {
			t.Errorf("%s: %+v, want %s naming %s", c.name, e, c.want, c.wantPath)
		}
	}
}
