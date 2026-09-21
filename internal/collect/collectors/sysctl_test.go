//go:build linux

package collectors

import (
	"fmt"
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

// The twelve keys of B-2 and no others, each written once, and a declaration
// that covers every path the collector reaches for (K-4).
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
	if len(keys) != 12 {
		t.Errorf("wrote %d keys, want the twelve of B-2: %v", len(keys), keys)
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
		"= 3\n"))
	want := []sysctlAssign{
		{key: "kernel.foo", value: "1", ignoreMissing: true, line: 4, raw: "-kernel.foo = 1"},
		{key: "kernel.yama.ptrace_scope", value: "2", line: 5, raw: "kernel/yama/ptrace_scope = 2"},
		{key: "net.ipv4.conf.eth0.1.rp_filter", value: "1", line: 6, raw: "net/ipv4/conf/eth0.1/rp_filter = 1"},
		{key: "kernel.sysrq", value: "176", line: 7, raw: "   kernel.sysrq\t=\t176   "},
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
