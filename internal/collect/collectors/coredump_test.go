//go:build linux

package collectors

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// coredumpSeeds is the two /proc/sys files the coredump collector reads.
func coredumpSeeds() map[string]string {
	return map[string]string{
		"/proc/sys/kernel/core_pattern": "proc_sys.core_pattern.apport",
		"/proc/sys/fs/suid_dumpable":    "proc_sys.0",
	}
}

// core_pattern is a string leaf — the pattern is evidence a control matches
// against — while suid_dumpable is a two-home setting like the twelve
// kernel.sysctl.* ones.
func TestCoredumpCorePatternAndSuidDumpable(t *testing.T) {
	a := &fsAccess{files: coredumpSeeds()}
	a.files["/etc/sysctl.conf"] = "sysctl.conf.sample" // sets fs.suid_dumpable = 0
	b := build(t, "coredump", a)

	pat := env(t, b, "coredump.core_pattern")
	if pat.Status != facts.StatusOK || !strings.HasPrefix(pat.Value.(string), "|/usr/share/apport/apport ") {
		t.Fatalf("core_pattern %+v, want the apport pipe verbatim", pat)
	}
	if strings.ContainsAny(pat.Value.(string), "\n") {
		t.Errorf("core_pattern %q carries a newline; the trailing one is trimmed", pat.Value)
	}
	want := facts.Source{Kind: "proc", Path: "/proc/sys/kernel/core_pattern"}
	if !sameSource(pat.Source, &want) {
		t.Errorf("core_pattern source %+v, want %+v", pat.Source, want)
	}

	s := setting(t, b, "coredump.suid_dumpable")
	if s.Runtime == nil || s.Runtime.Value != 0 || s.Runtime.Source.Path != "/proc/sys/fs/suid_dumpable" {
		t.Errorf("suid_dumpable runtime %+v, want ok 0 from /proc/sys", s.Runtime)
	}
	if s.Effective == nil || !reflect.DeepEqual(*s.Effective, *s.Runtime) {
		t.Errorf("effective %+v is not a copy of runtime %+v", s.Effective, s.Runtime)
	}
	if s.Persisted == nil || s.Persisted.Value != 0 || s.Persisted.Source.Path != "/etc/sysctl.conf" {
		t.Errorf("suid_dumpable persisted %+v, want 0 citing /etc/sysctl.conf", s.Persisted)
	}
	if !sameSource(s.Winner, s.Runtime.Source) {
		t.Errorf("winner %+v, want the runtime source", s.Winner)
	}

	// A kernel that does not publish the file, and one that refuses it.
	missing := &fsAccess{files: map[string]string{"/proc/sys/fs/suid_dumpable": "proc_sys.0"}}
	e := env(t, build(t, "coredump", missing), "coredump.core_pattern")
	if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "/proc/sys/kernel/core_pattern") {
		t.Errorf("core_pattern %+v, want absent naming the path", e)
	}
	denied := &fsAccess{
		files: coredumpSeeds(),
		fails: map[string]error{"/proc/sys/kernel/core_pattern": unix.EACCES},
	}
	if e := env(t, build(t, "coredump", denied), "coredump.core_pattern"); e.Status != facts.StatusDenied {
		t.Errorf("core_pattern %+v, want denied", e)
	}
}

// The coredump.conf chain is systemd's own: one main file, four drop-in
// directories, /etc masking a base name, applied in base-name order with the
// last assignment winning.
func TestCoredumpSystemdConfMerge(t *testing.T) {
	a := &fsAccess{files: coredumpSeeds()}
	a.files["/etc/systemd/coredump.conf"] = "coredump.conf.sample"
	a.files["/etc/systemd/coredump.conf.d/10-size.conf"] = "coredump.conf.d-10-size.conf"
	a.files["/usr/lib/systemd/coredump.conf.d/10-size.conf"] = "coredump.conf.d-other-section.conf"
	a.files["/usr/lib/systemd/coredump.conf.d/90-disable.conf"] = "coredump.conf.d-90-disable.conf"
	b := build(t, "coredump", a)

	st := env(t, b, "coredump.systemd.storage")
	if st.Status != facts.StatusOK || st.Value != "none" {
		t.Fatalf("storage %+v, want ok none", st)
	}
	if st.Source == nil || st.Source.Path != "/usr/lib/systemd/coredump.conf.d/90-disable.conf" {
		t.Errorf("storage cites %+v, want the 90- drop-in that set it last", st.Source)
	}
	sz := env(t, b, "coredump.systemd.process_size_max")
	if sz.Status != facts.StatusOK || sz.Value != 0 {
		t.Errorf("process_size_max %+v, want ok 0", sz)
	}
	if slices.Contains(a.reads, "/usr/lib/systemd/coredump.conf.d/10-size.conf") {
		t.Error("the masked vendor drop-in was read; /etc owns that base name")
	}

	// The main file is /etc's when it is there, and /usr/lib's only when it
	// is not (systemd >= 254 ships it there).
	if !slices.Contains(a.reads, "/etc/systemd/coredump.conf") {
		t.Error("the /etc main file was not read")
	}
	if slices.Contains(a.reads, "/usr/lib/systemd/coredump.conf") {
		t.Error("/usr/lib's main file was consulted although /etc has one")
	}

	usr := &fsAccess{files: coredumpSeeds()}
	usr.files["/usr/lib/systemd/coredump.conf"] = "coredump.conf.d-90-disable.conf"
	ub := build(t, "coredump", usr)
	if e := env(t, ub, "coredump.systemd.storage"); e.Value != "none" || e.Source.Path != "/usr/lib/systemd/coredump.conf" {
		t.Errorf("storage %+v, want none citing the /usr/lib main file", e)
	}

	// No coredump.conf anywhere: absent. systemd's own default is external,
	// and it is systemd's to have, never muster's to publish.
	none := build(t, "coredump", &fsAccess{files: coredumpSeeds()})
	for _, key := range []string{"coredump.systemd.storage", "coredump.systemd.process_size_max"} {
		if e := env(t, none, key); e.Status != facts.StatusAbsent {
			t.Errorf("%s %+v, want absent on a host with no coredump.conf", key, e)
		}
	}

	// A file that exists and cannot be read is the answer for every value it
	// could have set (C3).
	bad := &fsAccess{files: coredumpSeeds()}
	bad.files["/etc/systemd/coredump.conf"] = "coredump.conf.sample"
	bad.fails = map[string]error{"/etc/systemd/coredump.conf.d/50-local.conf": unix.EACCES}
	bad.dirs = map[string]bool{"/etc/systemd/coredump.conf.d/50-local.conf": true}
	bb := build(t, "coredump", bad)
	for _, key := range []string{"coredump.systemd.storage", "coredump.systemd.process_size_max"} {
		e := env(t, bb, key)
		if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "50-local.conf") {
			t.Errorf("%s %+v, want denied naming the unreadable drop-in", key, e)
		}
	}
}

// The hard core limit is the last `* hard core` or `* - core` line of
// limits.conf and limits.d, with unlimited recorded as -1; sources lists the
// files that were read whether or not one of them set it.
func TestCoredumpLimitsCore(t *testing.T) {
	a := &fsAccess{files: coredumpSeeds()}
	a.files["/etc/security/limits.conf"] = "limits.conf.sample"
	b := build(t, "coredump", a)
	hc := env(t, b, "coredump.limits.hard_core")
	if hc.Status != facts.StatusOK || hc.Value != 0 {
		t.Fatalf("hard_core %+v, want ok 0 from the `* hard core 0` line", hc)
	}
	if hc.Source == nil || hc.Source.Path != "/etc/security/limits.conf" || hc.Source.Line != 3 {
		t.Errorf("hard_core cites %+v, want limits.conf line 3", hc.Source)
	}

	// limits.d is applied after limits.conf, in base-name order, last wins;
	// `-` sets the hard limit too, and unlimited is -1.
	a2 := &fsAccess{files: coredumpSeeds()}
	a2.files["/etc/security/limits.conf"] = "limits.conf.sample"
	a2.files["/etc/security/limits.d/10-nofile.conf"] = "limits.d-10-nofile.conf"
	a2.files["/etc/security/limits.d/90-core.conf"] = "limits.d-90-core.conf"
	b2 := build(t, "coredump", a2)
	if got := env(t, b2, "coredump.limits.hard_core"); got.Value != -1 {
		t.Errorf("hard_core %+v, want -1: the last file sets it to unlimited", got)
	}
	src := okList(t, b2, "coredump.limits.sources")
	want := []any{
		"/etc/security/limits.conf",
		"/etc/security/limits.d/10-nofile.conf",
		"/etc/security/limits.d/90-core.conf",
	}
	if !reflect.DeepEqual(src, want) {
		t.Errorf("sources = %v, want the files read in order %v", src, want)
	}

	// A `@group` domain is not `*` and sets nothing here, so a file with only
	// that line leaves the leaf absent while still being a source.
	a3 := &fsAccess{files: coredumpSeeds()}
	a3.files["/etc/security/limits.d/10-nofile.conf"] = "limits.d-10-nofile.conf"
	b3 := build(t, "coredump", a3)
	if got := env(t, b3, "coredump.limits.hard_core"); got.Status != facts.StatusAbsent {
		t.Errorf("hard_core %+v, want absent: no line sets a hard core limit for *", got)
	}
	if got := okList(t, b3, "coredump.limits.sources"); !reflect.DeepEqual(got, []any{"/etc/security/limits.d/10-nofile.conf"}) {
		t.Errorf("sources = %v, want the one file that exists", got)
	}

	// No limits file at all.
	b4 := build(t, "coredump", &fsAccess{files: coredumpSeeds()})
	if got := env(t, b4, "coredump.limits.hard_core"); got.Status != facts.StatusAbsent {
		t.Errorf("hard_core %+v, want absent", got)
	}
	if got := okList(t, b4, "coredump.limits.sources"); len(got) != 0 {
		t.Errorf("sources = %v, want the empty list", got)
	}

	// C3 again: an unreadable limits file is the answer for both leaves.
	a5 := &fsAccess{
		files: coredumpSeeds(),
		fails: map[string]error{"/etc/security/limits.conf": unix.EACCES},
	}
	b5 := build(t, "coredump", a5)
	for _, key := range []string{"coredump.limits.hard_core", "coredump.limits.sources"} {
		e := env(t, b5, key)
		if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/etc/security/limits.conf") {
			t.Errorf("%s %+v, want denied naming the file", key, e)
		}
	}
}

// The six keys of B-2 and a declaration that covers every path (K-4).
func TestCoredumpDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "coredump")
	if c.Declare.Needs != "none" || len(c.Declare.Commands) != 0 || c.Declare.Walk {
		t.Errorf("declaration %+v, want Needs none with no command and no walk licence", c.Declare)
	}
	want := []string{
		"/etc/security/limits.conf",
		"/etc/security/limits.d/*.conf",
		"/etc/sysctl.conf",
		"/etc/sysctl.d/*.conf",
		"/etc/systemd/coredump.conf",
		"/etc/systemd/coredump.conf.d/*.conf",
		"/proc/sys/fs/suid_dumpable",
		"/proc/sys/kernel/core_pattern",
		"/run/sysctl.d/*.conf",
		"/run/systemd/coredump.conf.d/*.conf",
		"/usr/lib/sysctl.d/*.conf",
		"/usr/lib/systemd/coredump.conf",
		"/usr/lib/systemd/coredump.conf.d/*.conf",
		"/usr/local/lib/sysctl.d/*.conf",
		"/usr/local/lib/systemd/coredump.conf.d/*.conf",
	}
	got := slices.Clone(c.Declare.Reads)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Reads =\n%v\nwant\n%v", got, want)
	}

	keys := buildBegun(t, "coredump", &fsAccess{files: coredumpSeeds()}).Keys("coredump")
	wantKeys := []string{
		"coredump.core_pattern",
		"coredump.limits.hard_core",
		"coredump.limits.sources",
		"coredump.suid_dumpable",
		"coredump.systemd.process_size_max",
		"coredump.systemd.storage",
	}
	if !slices.Equal(keys, wantKeys) {
		t.Errorf("keys =\n%v\nwant\n%v", keys, wantKeys)
	}
}

func TestParseCoredumpConf(t *testing.T) {
	got := parseCoredumpConf([]byte("" +
		"# comment\n" +
		"Storage=outside-a-section\n" +
		"[Journal]\n" +
		"Storage=persistent\n" +
		"[Coredump]\n" +
		"Storage=journal\n" +
		"ProcessSizeMax=2G\n" +
		"Storage=none\n" +
		"Compress=yes\n"))
	if !got.storage.set || got.storage.value != "none" || got.storage.line != 8 {
		t.Errorf("storage %+v, want the last [Coredump] assignment, none, at line 8", got.storage)
	}
	if !got.sizeMax.set || got.sizeMax.value != "2G" || got.sizeMax.line != 7 {
		t.Errorf("sizeMax %+v, want 2G at line 7", got.sizeMax)
	}

	empty := parseCoredumpConf([]byte("[Coredump]\n#Storage=external\n"))
	if empty.storage.set || empty.sizeMax.set {
		t.Errorf("a fully commented file set %+v / %+v", empty.storage, empty.sizeMax)
	}
}

func TestParseSizeValue(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0", 0, true},
		{"2G", 2 << 30, true},
		{"10m", 10 << 20, true},
		{"1K", 1024, true},
		{"", 0, false},
		{"-1", 0, false},
		{"2GB", 0, false},
		{"high", 0, false},
		{"9223372036854775807E", 0, false}, // overflow, not a silent wrap
	} {
		got, ok := parseSizeValue(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("parseSizeValue(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseLimitsCore(t *testing.T) {
	got := parseLimitsCore([]byte("" +
		"# a comment\n" +
		"*    hard   core   0\n" +
		"@dev hard   core   unlimited\n" +
		"*    soft   core   unlimited\n" +
		"*    HARD   CORE   17\n" +
		"*    -      core   -1\n" +
		"*    hard   nofile 1024\n" +
		"*    hard   core   notanumber\n" +
		"*    hard\n"))
	want := []limitLine{
		{value: 0, line: 2, raw: "*    hard   core   0"},
		{value: 17, line: 5, raw: "*    HARD   CORE   17"},
		{value: -1, line: 6, raw: "*    -      core   -1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseLimitsCore =\n%+v\nwant\n%+v", got, want)
	}
}
