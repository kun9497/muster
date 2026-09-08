//go:build linux

package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// cmdResult is one canned command outcome for fsAccess.
type cmdResult struct {
	file      string // testdata file served as stdout
	stderr    string
	exitCode  int
	timedOut  bool
	truncated bool  // the capture hit the output cap
	err       error // set only when the command could not be started at all
}

// fsAccess serves declared paths from testdata and commands from canned
// outcomes. It implements all seven Access methods (R46/R60), so a collector
// under test can never reach the real host.
type fsAccess struct {
	files       map[string]string            // host path -> testdata file name
	dirs        map[string]bool              // host path -> exists, but is not a readable file
	cmds        map[string]cmdResult         // command line -> canned outcome
	fails       map[string]error             // host path -> error returned instead of content
	truncated   map[string]bool              // host path -> ReadFile reports the read hit the cap (R70)
	modes       map[string]uint32            // host path -> raw 0o7777 bits (fallback consulted when stats has no entry)
	stats       map[string]statResult        // host path -> full Stat() shape (R93; Task 5 relies on this)
	xattrs      map[string][]string          // host path -> extended attribute names
	xattrValues map[string]map[string][]byte // host path -> attribute name -> value, served by Getxattr
	writable    map[string]bool              // host path -> Writable answer
	globErr     error                        // when set, every Glob fails with it

	// reads records every path ReadFile was asked for, so a test can assert
	// that a collector did NOT go looking for something it did not need.
	reads []string
}

// statResult is the one shape fsAccess.Stat renders into a collect.ReadMeta
// when a path has an entry in stats: mode, ownership and file kind, the
// fields collectors that need more than "does this path exist" (e.g. the
// ACL decoder in Task 5) inspect. A path without a stats entry falls back to
// today's files/dirs/modes-derived behaviour, so every existing literal
// keeps compiling unchanged.
type statResult struct {
	mode     uint32
	uid, gid uint32
	kind     string
}

func (a *fsAccess) read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", name))
}

func (a *fsAccess) mode(p string, def uint32) uint32 {
	if m, ok := a.modes[p]; ok {
		return m
	}
	return def
}

func (a *fsAccess) ReadFile(p string, _ int64) ([]byte, collect.ReadMeta, error) {
	a.reads = append(a.reads, p)
	if err, ok := a.fails[p]; ok {
		return nil, collect.ReadMeta{}, err
	}
	name, ok := a.files[p]
	if !ok {
		return nil, collect.ReadMeta{}, os.ErrNotExist
	}
	b, err := a.read(name)
	return b, collect.ReadMeta{Tier: "openat2", Size: int64(len(b)), Mode: a.mode(p, 0o644), Truncated: a.truncated[p]}, err
}

func (a *fsAccess) Stat(p string) (collect.ReadMeta, error) {
	// An explicit stat shape wins over a fails entry for the same path: a file
	// can be stat-able (its parent directory is searchable) yet unreadable (the
	// content read is denied) — exactly a 0440 root-owned file seen by a
	// non-root run. A path present only in fails still fails its Stat.
	if s, ok := a.stats[p]; ok {
		return collect.ReadMeta{Tier: "openat2", Mode: s.mode, UID: s.uid, GID: s.gid, Kind: s.kind}, nil
	}
	if err, ok := a.fails[p]; ok {
		return collect.ReadMeta{}, err
	}
	if _, ok := a.files[p]; ok {
		return collect.ReadMeta{Tier: "openat2", Mode: a.mode(p, 0o644)}, nil
	}
	if a.dirs[p] {
		return collect.ReadMeta{Tier: "openat2", Mode: a.mode(p, 0o755)}, nil
	}
	return collect.ReadMeta{}, os.ErrNotExist
}

// Glob matches the pattern against the fixture map with path.Match and
// returns the matches sorted, so a collector that depends on Glob order —
// sshd's Include expansion — is exercised deterministically.
func (a *fsAccess) Glob(pattern string) ([]string, error) {
	if a.globErr != nil {
		return nil, a.globErr
	}
	var out []string
	for p := range a.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	for p := range a.dirs {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Llistxattr lists the union of a.xattrs[p] (names with no set value) and
// the keys of a.xattrValues[p] (names Getxattr can actually answer), sorted
// so the result is deterministic regardless of which map a test populated.
func (a *fsAccess) Llistxattr(p string) ([]string, error) {
	if err, ok := a.fails[p]; ok {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range a.xattrs[p] {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for n := range a.xattrValues[p] {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Getxattr answers from xattrValues; a name not present there — whether or
// not it appears in xattrs — is ENODATA, matching hostAccess.Getxattr's
// propagation of the raw errno.
func (a *fsAccess) Getxattr(p, name string) ([]byte, error) {
	if err, ok := a.fails[p]; ok {
		return nil, err
	}
	if v, ok := a.xattrValues[p][name]; ok {
		return v, nil
	}
	return nil, unix.ENODATA
}

func (a *fsAccess) Writable(p string) bool { return a.writable[p] }

func (a *fsAccess) Run(_ context.Context, c collect.Command) collect.Output {
	line := strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " "))
	r, ok := a.cmds[line]
	if !ok {
		// RunCommand reports a command that never started as ExitCode -1
		// with Err set; the double has to say the same thing.
		return collect.Output{ExitCode: -1, Err: os.ErrNotExist}
	}
	var stdout []byte
	if r.file != "" {
		b, err := a.read(r.file)
		if err != nil {
			return collect.Output{ExitCode: -1, Err: err}
		}
		stdout = b
	}
	return collect.Output{
		Stdout:    stdout,
		Stderr:    []byte(r.stderr),
		ExitCode:  r.exitCode,
		TimedOut:  r.timedOut,
		Truncated: r.truncated,
		Err:       r.err,
	}
}

func collectorNamed(t *testing.T, name string) collect.Collector {
	t.Helper()
	for _, c := range collect.All() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("collector %s is not registered", name)
	return collect.Collector{}
}

// build runs one collector under the guard and fails the test if it touched
// anything it did not declare (spec §11).
func build(t *testing.T, name string, a collect.Access) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	c := collectorNamed(t, name)
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("%s touched undeclared targets: %v", name, v)
	}
	return b
}

func leaf(t *testing.T, b *collect.Builder, key string) any {
	t.Helper()
	cur := any(b.Tree())
	for _, s := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: not present", key)
		}
		cur = m[s]
	}
	return cur
}

func env(t *testing.T, b *collect.Builder, key string) facts.Envelope {
	t.Helper()
	e, ok := leaf(t, b, key).(facts.Envelope)
	if !ok {
		t.Fatalf("%s: not an envelope", key)
	}
	return e
}

// okList fetches an ok list-valued fact, reporting the envelope rather than
// panicking on a type assertion when the collector did not produce one.
func okList(t *testing.T, b *collect.Builder, key string) []any {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v", key, e)
	}
	list, ok := e.Value.([]any)
	if !ok {
		t.Fatalf("%s: value is %#v, not a list", key, e.Value)
	}
	return list
}

func setting(t *testing.T, b *collect.Builder, key string) facts.Setting {
	t.Helper()
	s, ok := leaf(t, b, key).(facts.Setting)
	if !ok {
		t.Fatalf("%s: not a setting", key)
	}
	return s
}

// --- sshd ---------------------------------------------------------------

// -G is the preferred method: it prints the daemon's configuration without
// loading host keys or the privilege-separation directory, so a socket-
// activated sshd that makes -T fail still answers. When -G answers, the
// method is "G" and -T is never consulted.
func TestSshdPrefersGOverT(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -G": {file: "sshd_G.txt"},
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13\n", exitCode: 1},
		},
	}
	b := build(t, "sshd", a)
	if m := env(t, b, "sshd.collect_method"); m.Value != "G" {
		t.Fatalf("method %+v, want G", m)
	}
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Value != "no" {
		t.Errorf("runtime from -G %+v", s.Runtime)
	}
	if v := env(t, b, "sshd.version"); v.Value != "9.6" {
		t.Errorf("version %+v, want 9.6", v)
	}
}

// 8.9 and 8.7 have no -G: the ladder drops to -T and the method is "T".
func TestSshdFallsFromGToT(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -G": {exitCode: 1, stderr: "unknown option -- G\n"},
			"/usr/sbin/sshd -T": {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.17\n", exitCode: 1},
			"/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1,lport=22":           {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -T -C user=nobody,host=localhost,addr=127.0.0.1,lport=22":         {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -T -C user=muster-nx-user,host=localhost,addr=127.0.0.1,lport=22": {file: "sshd_T_full.txt"},
		},
	}
	b := build(t, "sshd", a)
	if m := env(t, b, "sshd.collect_method"); m.Value != "T" {
		t.Fatalf("method %+v, want T", m)
	}
	if env(t, b, "sshd.personas_collected").Value != true {
		t.Error("all three persona queries succeeded; flag must be true")
	}
	if s := setting(t, b, "sshd.options.client_alive_interval"); s.Effective.Value != 300 {
		t.Errorf("client_alive_interval effective %+v, want int 300", s.Effective)
	}
	if s := setting(t, b, "sshd.options.max_auth_tries"); s.Effective.Value != 4 {
		t.Errorf("max_auth_tries effective %+v, want int 4", s.Effective)
	}
}

// A persona whose value differs from the global is recorded as an override;
// personas that match the global are not stored (byte stability).
func TestSshdRecordsAPersonaOverride(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -G": {exitCode: 1, stderr: "unknown option\n"},
			"/usr/sbin/sshd -T": {file: "sshd_T_full.txt"}, // permitrootlogin no
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_8.9p1\n", exitCode: 1},
			"/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1,lport=22":           {file: "sshd_T_C_root.txt"}, // permitrootlogin yes
			"/usr/sbin/sshd -T -C user=nobody,host=localhost,addr=127.0.0.1,lport=22":         {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -T -C user=muster-nx-user,host=localhost,addr=127.0.0.1,lport=22": {file: "sshd_T_full.txt"},
		},
	}
	s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
	if s.Effective.Value != "no" {
		t.Fatalf("global effective %+v, want no", s.Effective)
	}
	if s.Personas == nil || s.Personas["root"] == nil || s.Personas["root"].Value != "yes" {
		t.Fatalf("root persona override must be recorded as yes: %+v", s.Personas)
	}
	if _, ok := s.Personas["user"]; ok {
		t.Error("a persona equal to the global must not be stored")
	}
}

// One failed persona query leaves the flag false — a half-collected set is
// worse than none.
func TestSshdOnePersonaFailureLeavesFlagFalse(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -T": {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_8.9p1\n", exitCode: 1},
			"/usr/sbin/sshd -T -C user=root,host=localhost,addr=127.0.0.1,lport=22":   {file: "sshd_T_full.txt"},
			"/usr/sbin/sshd -T -C user=nobody,host=localhost,addr=127.0.0.1,lport=22": {exitCode: 255, stderr: "bad\n"},
		},
	}
	b := build(t, "sshd", a)
	if env(t, b, "sshd.personas_collected").Value != false {
		t.Error("a failed persona query must leave the flag false")
	}
	if s := setting(t, b, "sshd.options.permit_root_login"); s.Personas != nil {
		t.Error("no overrides recorded when personas are not fully collected")
	}
}

// Parse fallback: no daemon output at all. Options come from the files, the
// method is "parse", personas are not collected, version is absent.
func TestSshdParseFallbackFillsEveryOption(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_banners"}}
	b := build(t, "sshd", a)
	if env(t, b, "sshd.collect_method").Value != "parse" {
		t.Fatal("method must be parse")
	}
	if env(t, b, "sshd.personas_collected").Value != false {
		t.Error("no daemon, no personas")
	}
	if s := setting(t, b, "sshd.options.banner"); s.Effective.Value != "/etc/issue.net" {
		t.Errorf("banner from parse %+v", s.Effective)
	}
	// R165: a numeric option parsed from the files must be an int on the
	// effective side, never the string parseSshdConfig returns, or a clause
	// on it ERRORs. This is the assertion that catches the setting<int>
	// parsed-side bug the daemon path (int already) hides.
	ci := setting(t, b, "sshd.options.client_alive_interval")
	if n, ok := ci.Effective.Value.(int); !ok || n != 300 {
		t.Errorf("client_alive_interval effective %#v, want int 300", ci.Effective.Value)
	}
	if v := env(t, b, "sshd.version"); v.Status != facts.StatusAbsent {
		t.Errorf("version %+v, want absent", v)
	}
}

// The Banner file is stat'd, and "none" is a definite false, not an error.
func TestSshdBannerFileStat(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/ssh/sshd_config": "sshd_config_banners", // Banner /etc/issue.net
			"/etc/issue.net":       "issue_for_sshd",
		},
	}
	b := build(t, "sshd", a)
	if e := env(t, b, "sshd.banner_file.exists"); e.Value != true {
		t.Errorf("exists %+v", e)
	}
	if e := env(t, b, "sshd.banner_file.nonempty"); e.Value != true {
		t.Errorf("nonempty %+v", e)
	}

	none := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}} // no Banner -> none
	nb := build(t, "sshd", none)
	if e := env(t, nb, "sshd.banner_file.exists"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("Banner none must be a definite false: %+v", e)
	}
}

// Include sources are recorded in expansion order with depth.
func TestSshdIncludeSourcesRecorded(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/ssh/sshd_config":                      "sshd_config", // Include .../*.conf
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf",
	}}
	list := okList(t, build(t, "sshd", a), "sshd.include_sources")
	if len(list) != 1 {
		t.Fatalf("include_sources %v, want one entry", list)
	}
	rec := list[0].(map[string]any)
	if rec["path"] != "/etc/ssh/sshd_config.d/50-cloud-init.conf" || rec["depth"].(int) != 1 {
		t.Errorf("record %v", rec)
	}
}

// Two drop-ins match one Include glob: the records appear in sorted-Glob
// expansion order, each at depth 1, so the order across entries is pinned
// (not just a single match).
func TestSshdIncludeSourcesRecordedInExpansionOrder(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/ssh/sshd_config":                      "sshd_config", // Include .../*.conf
		"/etc/ssh/sshd_config.d/60-extra.conf":      "sshd_config.d_60-extra.conf",
		"/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf",
	}}
	list := okList(t, build(t, "sshd", a), "sshd.include_sources")
	if len(list) != 2 {
		t.Fatalf("include_sources %v, want two entries", list)
	}
	want := []string{
		"/etc/ssh/sshd_config.d/50-cloud-init.conf",
		"/etc/ssh/sshd_config.d/60-extra.conf",
	}
	for i, w := range want {
		rec := list[i].(map[string]any)
		if rec["path"] != w {
			t.Errorf("entry %d path %v, want %s (records must be in sorted expansion order)", i, rec["path"], w)
		}
		if rec["depth"].(int) != 1 {
			t.Errorf("entry %d depth %v, want 1", i, rec["depth"])
		}
	}
}

// R168: a Banner path outside Declare.Reads must be refused by the guard's
// Allowed and recorded as an error, never read. build() wraps the access in
// collect.Guard, so Allowed is live here (mirrors
// TestSshdIncludeOutsideDeclarationIsRecordedNotViolated).
func TestSshdBannerOutsideDeclarationIsRecordedNotRead(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/ssh/sshd_config": "sshd_config_banner_outside", // Banner /root/secret
	}}
	b := build(t, "sshd", a) // build fails the test on any guard violation
	for _, key := range []string{"sshd.banner_file.exists", "sshd.banner_file.nonempty"} {
		e := env(t, b, key)
		if e.Status != facts.StatusError {
			t.Errorf("%s %+v, want error", key, e)
		}
		if !strings.Contains(e.Reason, "/root/secret") || !strings.Contains(e.Reason, "outside the collector's declaration") {
			t.Errorf("%s reason %q", key, e.Reason)
		}
	}
	if slices.Contains(a.reads, "/root/secret") {
		t.Errorf("an undeclared Banner path must never be read: reads = %v", a.reads)
	}
}

// R165 negative branch: a numeric option whose parsed file value is not an
// integer is an error on the persisted (and, on parse fallback, effective)
// side, never a stored non-int.
func TestSshdNumericOptionWithANonIntegerFileValueIsAnError(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_bad_int"}}
	s := setting(t, build(t, "sshd", a), "sshd.options.max_auth_tries")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusError {
		t.Fatalf("persisted %+v, want error", s.Persisted)
	}
	if !strings.Contains(s.Persisted.Reason, "not an integer") {
		t.Errorf("reason %q, want it to name the non-integer value", s.Persisted.Reason)
	}
	if s.Effective.Status != facts.StatusError {
		t.Errorf("effective %+v, want error copied from the persisted side", s.Effective)
	}
}

// sshdVersion's no-version-found branch: sshd -V output that ran but carries
// no OpenSSH_x.y string yields an absent version, not a bogus value.
func TestSshdVersionAbsentWhenOutputHasNoVersion(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds:  map[string]cmdResult{"/usr/sbin/sshd -V": {stderr: "usage: sshd [options]\n", exitCode: 1}},
	}
	v := env(t, build(t, "sshd", a), "sshd.version")
	if v.Status != facts.StatusAbsent {
		t.Errorf("version %+v, want absent", v)
	}
	if !strings.Contains(v.Reason, "no OpenSSH version") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestSshdRuntimeAndPersistedWithInclude(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/ssh/sshd_config":                      "sshd_config",
			"/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf",
		},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {file: "sshd_T.txt"}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Value != "prohibit-password" || s.Effective.Value != "prohibit-password" {
		t.Errorf("runtime/effective %+v %+v", s.Runtime, s.Effective)
	}
	if s.Persisted.Value != "no" || s.Persisted.Source.Path != "/etc/ssh/sshd_config.d/50-cloud-init.conf" || s.Persisted.Source.Line != 2 {
		t.Errorf("persisted must come from the Include (first occurrence wins): %+v", s.Persisted)
	}
	if env(t, b, "sshd.collect_method").Value != "T" || env(t, b, "sshd.personas_collected").Value != false {
		t.Error("method/personas")
	}
}

func TestSshdFallsBackToParseWhenTUnavailable(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime != nil || s.Effective.Value != "yes" || !strings.Contains(s.Effective.Reason, "sshd -T unavailable") {
		t.Errorf("%+v", s)
	}
	if env(t, b, "sshd.collect_method").Value != "parse" {
		t.Error("method must be parse")
	}
}

// R169 (spec §6.5 step 13): a non-zero sshd -T exit (after a -G that also
// did not answer) is a parse-fallback degradation, not a failed collector —
// a readable config answering is better for non-root collection than a
// denied runtime side. The daemon rungs fall through, so there is no runtime
// side at all; the method is "parse", cited to the command that ran and
// failed; the effective side is the parsed ok value; and the collector's own
// status stays ok, so a run built on this outcome is complete.
func TestSshdNonZeroExitIsAnAbsentRuntimeSide(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -G": {exitCode: 1, stderr: "unknown option -- G\n"},
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_8.9p1\n", exitCode: 1},
			"/usr/sbin/sshd -T": {
				exitCode: 255,
				stderr:   "Missing privilege separation directory: /run/sshd\nsecond line\n",
			},
		},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime != nil {
		t.Fatalf("a daemon that did not answer leaves no runtime side: %+v", s.Runtime)
	}
	if m := env(t, b, "sshd.collect_method"); m.Value != "parse" || m.Source == nil || m.Source.Cmd != "/usr/sbin/sshd -T" {
		t.Errorf("method must be parse, cited to the command that ran and failed: %+v", m)
	}
	if s.Effective.Status != facts.StatusOK || s.Effective.Value != "yes" || !strings.Contains(s.Effective.Reason, "sshd -T unavailable") {
		t.Errorf("effective must fall back to the ok persisted value: %+v", s.Effective)
	}
	// Absent ranks as ok in Builder.Worst (R71), so this fallback must not
	// make the sshd collector itself worse than ok — which is what keeps a
	// run built on this outcome complete.
	if worst := b.Worst("sshd"); worst != facts.StatusOK {
		t.Errorf("Worst(sshd) = %s, want ok", worst)
	}
}

// R169: to still prove the denied path now that a -T exit drops to parse,
// both the -T exit AND the config read fail. The daemon rungs fall through,
// so the parsed side is denied, and effective copies that denied side
// unchanged with its reason (R59) — the explanation of why there is no value
// survives.
func TestSshdPermissionDeniedIsDeniedAndCopiedToEffective(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/ssh/sshd_config": os.ErrPermission},
		cmds: map[string]cmdResult{
			"/usr/sbin/sshd -G": {exitCode: 1, stderr: "unknown option -- G\n"},
			"/usr/sbin/sshd -V": {stderr: "OpenSSH_8.9p1\n", exitCode: 1},
			"/usr/sbin/sshd -T": {
				exitCode: 1,
				stderr:   "/etc/ssh/sshd_config: Permission denied\n",
			},
		},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if env(t, b, "sshd.collect_method").Value != "parse" {
		t.Fatalf("method must be parse")
	}
	if s.Runtime != nil {
		t.Fatalf("a daemon that did not answer leaves no runtime side: %+v", s.Runtime)
	}
	// R59: a non-ok persisted side is copied to effective unchanged, so the
	// reason still says why there is no value.
	if s.Persisted == nil || s.Persisted.Status != facts.StatusDenied {
		t.Fatalf("persisted %+v, want denied", s.Persisted)
	}
	if s.Effective.Status != facts.StatusDenied || s.Effective.Reason != s.Persisted.Reason {
		t.Errorf("effective %+v must copy the denied persisted side %+v unchanged", s.Effective, s.Persisted)
	}
}

// R55/R75: an Include pointing outside the declaration is recorded on the
// persisted side and expansion stops; it is not a guard violation.
func TestSshdIncludeOutsideDeclarationIsRecordedNotViolated(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_outside_include"}}
	b := build(t, "sshd", a) // build fails the test on any violation
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusError {
		t.Fatalf("persisted %+v", s.Persisted)
	}
	if !strings.Contains(s.Persisted.Reason, "/etc/ssh/other/*.conf") ||
		!strings.Contains(s.Persisted.Reason, "outside the collector's declaration") {
		t.Errorf("reason %q", s.Persisted.Reason)
	}
}

// Fix 1 (Critical). An Include'd drop-in that cannot be READ — a symlink the
// primitive refuses, a non-regular file, EACCES — must never be skipped: the
// main file's lower-priority value would then be published as ok, a PASS on
// evidence that was never seen. Only a drop-in that is not there may be
// skipped.
func TestSshdUnreadableDropInIsNeverSkipped(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want facts.Status
	}{
		{"symlink", collect.ErrSymlink, facts.StatusError},
		{"denied", os.ErrPermission, facts.StatusDenied},
		{"not regular", collect.ErrNotRegular, facts.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &fsAccess{
				files: map[string]string{
					"/etc/ssh/sshd_config":                      "sshd_config",
					"/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf",
				},
				fails: map[string]error{"/etc/ssh/sshd_config.d/50-cloud-init.conf": tc.err},
			}
			b := build(t, "sshd", a)
			s := setting(t, b, "sshd.options.permit_root_login")
			if s.Persisted == nil || s.Persisted.Status == facts.StatusOK {
				t.Fatalf("an unreadable drop-in must not leave the main file's value ok: %+v", s.Persisted)
			}
			if s.Persisted.Status != tc.want {
				t.Errorf("persisted status %s, want %s (%+v)", s.Persisted.Status, tc.want, s.Persisted)
			}
			// R59: effective copies a non-ok persisted side unchanged.
			if s.Effective.Status != s.Persisted.Status || s.Effective.Reason != s.Persisted.Reason {
				t.Errorf("effective %+v must copy persisted %+v unchanged", s.Effective, s.Persisted)
			}
		})
	}
}

// A drop-in that is simply absent is still skipped, so the main file answers.
func TestSshdMissingDropInStillFallsThroughToTheMainFile(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Persisted.Status != facts.StatusOK || s.Persisted.Value != "yes" {
		t.Errorf("%+v", s.Persisted)
	}
}

// Fix 3. sshd accepts "Keyword=value" as well as "Keyword value".
func TestSshdParsesTheEqualsForm(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_equals"}}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Persisted == nil || s.Persisted.Value != "yes" {
		t.Errorf("PermitRootLogin=yes must parse: %+v", s.Persisted)
	}
	if s.Persisted.Source.Line != 2 {
		t.Errorf("line %d, want 2", s.Persisted.Source.Line)
	}
}

// M4 (R85). sshd's own tokenizer (strdelim) treats "=" as a separator like
// whitespace, so all four spellings below are one directive, and it
// compares a multistate value case-insensitively, so "No" is "no". A
// spelling muster does not recognise reads as "the keyword is not
// configured" — a PASS on a directive that is right there in the file.
func TestSshdParsesEverySeparatorSpellingAndFoldsTheValue(t *testing.T) {
	for _, tc := range []struct {
		file, want string
	}{
		{"sshd_config_equals", "yes"},          // PermitRootLogin=yes
		{"sshd_config_equals_spaced", "yes"},   // PermitRootLogin = yes
		{"sshd_config_equals_leading", "yes"},  // PermitRootLogin =yes
		{"sshd_config_equals_trailing", "yes"}, // PermitRootLogin= yes
		{"sshd_config_mixed_case", "no"},       // PermitRootLogin No
	} {
		t.Run(tc.file, func(t *testing.T) {
			a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": tc.file}}
			s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
			if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || s.Persisted.Value != tc.want {
				t.Fatalf("persisted %+v, want ok %q", s.Persisted, tc.want)
			}
			if s.Persisted.Source.Line != 2 {
				t.Errorf("line %d, want 2", s.Persisted.Source.Line)
			}
		})
	}
}

// The same fold on the runtime side, so the two sides of the setting can
// never disagree about the spelling of one answer.
func TestSshdFoldsTheRuntimeValue(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds:  map[string]cmdResult{"/usr/sbin/sshd -T": {file: "sshd_T_mixed_case.txt"}},
	}
	s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Value != "no" || s.Effective.Value != "no" {
		t.Errorf("runtime %+v effective %+v, want \"no\"", s.Runtime, s.Effective)
	}
}

// M5. A Glob that fails is not an Include that matched nothing: the
// drop-ins it would have named may each carry a higher-priority value, so
// the failure is the answer rather than a silent expansion to nothing.
func TestSshdIncludeGlobFailureIsRecorded(t *testing.T) {
	a := &fsAccess{
		files:   map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		globErr: errors.New("glob boom"),
	}
	s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusError {
		t.Fatalf("persisted %+v, want error", s.Persisted)
	}
	if want := "Include /etc/ssh/sshd_config.d/*.conf: glob boom"; s.Persisted.Reason != want {
		t.Errorf("reason %q, want %q", s.Persisted.Reason, want)
	}
}

// Fix 4. A value parsed out of a capped capture is not the whole answer.
func TestSshdMarksTruncatedCommandOutput(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds:  map[string]cmdResult{"/usr/sbin/sshd -T": {file: "sshd_T.txt", truncated: true}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || !s.Runtime.Truncated {
		t.Errorf("runtime must carry truncated: %+v", s.Runtime)
	}
	if !env(t, b, "sshd.collect_method").Truncated {
		t.Errorf("collect_method must carry truncated: %+v", env(t, b, "sshd.collect_method"))
	}
}

// Fix 7. "parse" chosen because the binary never started cites no command:
// there is no exit code to point at.
func TestSshdCollectMethodHasNoSourceWhenTheBinaryNeverStarted(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}}
	b := build(t, "sshd", a)
	m := env(t, b, "sshd.collect_method")
	if m.Value != "parse" || m.Source != nil {
		t.Errorf("collect_method %+v source %+v", m, m.Source)
	}
}

// ...but a -T that ran and failed is cited, because its exit code is the
// reason "parse" was chosen.
func TestSshdCollectMethodCitesACommandThatRanAndFailed(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds:  map[string]cmdResult{"/usr/sbin/sshd -T": {exitCode: 255, stderr: "boom\n"}},
	}
	b := build(t, "sshd", a)
	m := env(t, b, "sshd.collect_method")
	if m.Value != "parse" || m.Source == nil || m.Source.Cmd != "/usr/sbin/sshd -T" {
		t.Errorf("collect_method %+v source %+v", m, m.Source)
	}
}

// withEUID installs a fake effective uid for one test (R84). The seam is
// the only way to exercise the privilege rule from a suite that runs as
// whichever account happens to have started it.
func withEUID(t *testing.T, id int) {
	t.Helper()
	orig := euid
	euid = func() int { return id }
	t.Cleanup(func() { euid = orig })
}

// R169: the sshd collector no longer routes a failed sshd -T through
// commandFailure — a non-zero/denied daemon exit drops to the parse
// fallback (see TestSshdNonZeroExitIsAnAbsentRuntimeSide and
// TestSshdPermissionDeniedIsDeniedAndCopiedToEffective), so the old
// root-only-command test that exercised commandFailure through sshd no
// longer has a subject and has been removed. commandFailure and its euid
// privilege rule are unchanged; the non-root case below still pins them
// through the services collector.

// R170 (R84/D25): commandFailure's needsRoot branch is kept for later
// root-command collectors even though no collector currently reaches it, so
// it is pinned directly here. A root-only command that failed while this
// process is not root is denied with the privilege named, whatever it
// printed; the same failure as root is an error carrying the stderr message.
func TestCommandFailureNeedsRootBranch(t *testing.T) {
	out := collect.Output{Stderr: []byte("no hostkeys available -- exiting.\n"), ExitCode: 255}
	src := out.Source(collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}})

	withEUID(t, 1000)
	e := commandFailure("sshd -T", out, src, true)
	if e.Status != facts.StatusDenied {
		t.Fatalf("non-root %+v, want denied", e)
	}
	if !strings.Contains(e.Reason, "requires root") || !strings.Contains(e.Reason, "no hostkeys available -- exiting.") {
		t.Errorf("denied reason %q must name the privilege and carry the stderr line", e.Reason)
	}

	withEUID(t, 0)
	e = commandFailure("sshd -T", out, src, true)
	if e.Status != facts.StatusError {
		t.Fatalf("root %+v, want error", e)
	}
	if e.Reason != "no hostkeys available -- exiting." {
		t.Errorf("root reason %q, want the stderr message", e.Reason)
	}
}

// A collector that does NOT need root keeps commandFailure's rule whatever
// this process's euid is: systemctl failing for a normal user is an error,
// because nothing about that command required a privilege it lacked.
func TestNonRootCollectorCommandFailureStaysAnError(t *testing.T) {
	withEUID(t, 1000)
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{exitCode: 1, stderr: "Failed to connect to bus\n"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	if e := env(t, build(t, "services", a), "services.ssh.installed"); e.Status != facts.StatusError {
		t.Errorf("%+v, want error: services declares Needs: none", e)
	}
}

// M16. A single-token value is a word like "yes" or "prohibit-password". A
// token past 4 KiB is a file's contents arriving through a value slot, and
// the snapshot is evidence for a finding, not a copy of the host — so it is
// reported as an error and none of it is stored, on either side.
func TestSshdOversizedValueIsAnErrorNotAStoredBlob(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_long_value"},
		cmds:  map[string]cmdResult{"/usr/sbin/sshd -T": {file: "sshd_T_long_value.txt"}},
	}
	s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
	for _, side := range []struct {
		name string
		e    *facts.Envelope
	}{{"runtime", s.Runtime}, {"persisted", s.Persisted}} {
		if side.e == nil || side.e.Status != facts.StatusError || side.e.Reason != "value exceeds 4 KiB" {
			t.Errorf("%s %+v, want error \"value exceeds 4 KiB\"", side.name, side.e)
			continue
		}
		if v, _ := side.e.Value.(string); v != "" {
			t.Errorf("%s stored %d bytes of the oversized value", side.name, len(v))
		}
	}
}

// R172 (C3): when the daemon does not answer and the sshd_config that would
// name Banner cannot be read, the banner_file leaves must carry that read's
// status — not a definite false, which would publish the module's default
// "no banner" as if it were the host's state and hide the read failure.
func TestSshdBannerFileUnreadableConfigCarriesTheReadError(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/etc/ssh/sshd_config": os.ErrPermission}}
	b := build(t, "sshd", a)
	for _, k := range []string{"sshd.banner_file.exists", "sshd.banner_file.nonempty"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s must be denied, not a quiet false: %+v", k, e)
		}
	}
}

// R174: a numeric option parsed from a truncated config read must stay marked
// truncated after the R165 int rewrap; a value that arrived truncated cannot
// be judged as a clean number.
func TestSshdParsedNumericCarriesTruncation(t *testing.T) {
	a := &fsAccess{
		files:     map[string]string{"/etc/ssh/sshd_config": "sshd_config_banners"},
		truncated: map[string]bool{"/etc/ssh/sshd_config": true},
	}
	s := setting(t, build(t, "sshd", a), "sshd.options.client_alive_interval")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || !s.Persisted.Truncated {
		t.Errorf("persisted %+v, want ok and truncated", s.Persisted)
	}
	if s.Effective == nil || !s.Effective.Truncated {
		t.Errorf("effective %+v, want truncated (copied from persisted)", s.Effective)
	}
}

// --- banners --------------------------------------------------------------

func TestBannersContentAndEscapes(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/issue":     "issue_os_escapes", // "Ubuntu 22.04 \n \l"
			"/etc/issue.net": "issue_net",        // a plain warning, no escapes
			"/etc/motd":      "motd_static",
		},
		modes: map[string]uint32{
			"/etc/issue": 0o644, "/etc/issue.net": 0o644, "/etc/motd": 0o644,
		},
	}
	b := build(t, "banners", a)
	if e := env(t, b, "banners.issue.nonempty"); e.Value != true {
		t.Errorf("issue.nonempty %+v", e)
	}
	if e := env(t, b, "banners.issue.os_escapes"); e.Value != true {
		t.Errorf("issue with \\l/version must set os_escapes: %+v", e)
	}
	if e := env(t, b, "banners.issue_net.os_escapes"); e.Value != false {
		t.Errorf("plain issue.net must not set os_escapes: %+v", e)
	}
	if e := env(t, b, "banners.issue.mode"); e.Value != 0o644 {
		t.Errorf("issue.mode %+v, want 420", e)
	}
}

// A missing file is a definite empty state, not an error.
func TestBannersMissingFileIsDefiniteEmpty(t *testing.T) {
	a := &fsAccess{files: map[string]string{}}
	b := build(t, "banners", a)
	for _, k := range []string{"banners.issue.nonempty", "banners.issue_net.nonempty", "banners.motd.nonempty"} {
		if e := env(t, b, k); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("%s must be a definite false: %+v", k, e)
		}
	}
	if e := env(t, b, "banners.issue.mode"); e.Value != 0 {
		t.Errorf("absent issue mode %+v, want 0", e)
	}
}

// An unreadable banner carries the read error, never a quiet empty — on every
// leaf that read would have set, not only nonempty (they all come from the one
// read).
func TestBannersUnreadableIsNotEmpty(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/etc/issue.net": os.ErrPermission}}
	b := build(t, "banners", a)
	for _, k := range []string{"banners.issue_net.nonempty", "banners.issue_net.mode", "banners.issue_net.os_escapes"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s: denied read must be denied, not empty: %+v", k, e)
		}
	}
}

// A Glob that fails is not an empty update-motd.d: motd_d and dynamic_motd
// carry that error rather than reporting no scripts (spec §7.3 honesty).
func TestBannersMotdGlobErrorCarriesTheError(t *testing.T) {
	a := &fsAccess{globErr: errors.New("glob boom")}
	b := build(t, "banners", a)
	for _, k := range []string{"banners.motd_d", "banners.dynamic_motd"} {
		if e := env(t, b, k); e.Status != facts.StatusError {
			t.Errorf("%s: a failed Glob must carry the error, not an empty inventory: %+v", k, e)
		}
	}
}

// update-motd.d with an executable script sets dynamic_motd and lists the
// script; a non-executable entry does not make it dynamic.
func TestBannersMotdInventory(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/update-motd.d/00-header": "motd_static",
			"/etc/update-motd.d/99-readme": "motd_static",
		},
		modes: map[string]uint32{
			"/etc/update-motd.d/00-header": 0o755,
			"/etc/update-motd.d/99-readme": 0o644,
		},
	}
	b := build(t, "banners", a)
	if e := env(t, b, "banners.dynamic_motd"); e.Value != true {
		t.Errorf("an executable script must set dynamic_motd: %+v", e)
	}
	list := okList(t, b, "banners.motd_d")
	if len(list) != 2 {
		t.Fatalf("motd_d %v, want two entries sorted by name", list)
	}
	first := list[0].(map[string]any)
	if first["name"] != "00-header" || first["executable"] != true {
		t.Errorf("first entry %v", first)
	}
	second := list[1].(map[string]any)
	if second["executable"] != false {
		t.Errorf("non-executable entry must be executable:false: %v", second)
	}
}

// No update-motd.d at all: dynamic_motd false, motd_d an empty list.
func TestBannersNoMotdD(t *testing.T) {
	a := &fsAccess{files: map[string]string{}}
	b := build(t, "banners", a)
	if e := env(t, b, "banners.dynamic_motd"); e.Value != false {
		t.Errorf("dynamic_motd %+v, want false", e)
	}
	if list := okList(t, b, "banners.motd_d"); len(list) != 0 {
		t.Errorf("motd_d %v, want empty list", list)
	}
}

// --- accounts -----------------------------------------------------------

func TestAccountsDerivesRuntimeAgeingWithoutStoringHashes(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs",
		"/etc/shadow":     "shadow",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	mx := setting(t, b, "accounts.login_defs.pass_max_days")
	if mx.Persisted.Value != 90 || mx.Persisted.Source.Line != 2 || mx.Runtime.Value != 99999 || mx.Runtime.Source.Kind != "derived" {
		t.Errorf("%+v %+v", mx.Persisted, mx.Runtime)
	}
	mn := setting(t, b, "accounts.login_defs.pass_min_days")
	if mn.Persisted.Value != 1 || mn.Runtime.Value != 0 {
		t.Errorf("%+v %+v", mn.Persisted, mn.Runtime)
	}
	if e := env(t, b, "accounts.login_defs.pass_min_len"); e.Value != 8 {
		t.Errorf("pass_min_len %+v", e)
	}
	users := okList(t, b, "accounts.users")
	if len(users) != 3 {
		t.Fatalf("users %+v", users)
	}
	for _, u := range users {
		for k, v := range u.(map[string]any) {
			if s, ok := v.(string); ok && strings.Contains(s, "hashhash") {
				t.Fatalf("hash leaked into %s=%q", k, s)
			}
		}
	}
	root := users[0].(map[string]any)
	if root["hash_algo"] != "$6$" || root["password_status"] != "hashed" {
		t.Errorf("%v", root)
	}
	if users[1].(map[string]any)["password_status"] != "locked" {
		t.Errorf("%v", users[1])
	}
	if users[2].(map[string]any)["hash_algo"] != "$y$" {
		t.Errorf("%v", users[2])
	}
}

func TestAccountsShadowDeniedIsDeniedNotAbsent(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd"},
		fails: map[string]error{"/etc/shadow": os.ErrPermission},
	}
	b := build(t, "accounts", a)
	if e := setting(t, b, "accounts.login_defs.pass_max_days").Runtime; e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	if e := setting(t, b, "accounts.login_defs.pass_min_days").Runtime; e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	users := okList(t, b, "accounts.users")
	if len(users) != 3 {
		t.Fatalf("users %v", users)
	}
	if _, present := users[0].(map[string]any)["password_status"]; present {
		t.Errorf("a shadow field appeared without shadow: %v", users[0])
	}
}

// Fix 5. Only a plausible crypt id is kept. A 200-byte "id" is not an
// algorithm name, it is hash material, and none of it may be stored.
func TestAccountsRejectsAnImplausibleHashId(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs",
		"/etc/shadow":     "shadow_longid",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	users := okList(t, b, "accounts.users")
	root := users[0].(map[string]any)
	if root["hash_algo"] != "" {
		t.Errorf("hash_algo %q must be empty for an implausible id", root["hash_algo"])
	}
	for _, u := range users {
		for k, v := range u.(map[string]any) {
			if str, ok := v.(string); ok && (strings.Contains(str, "hashhash") || len(str) > 32) {
				t.Fatalf("hash material leaked into %s=%q", k, str)
			}
		}
	}
	// The well-formed row beside it still yields its id.
	if users[1].(map[string]any)["hash_algo"] != "$6$" {
		t.Errorf("%v", users[1])
	}
}

// --- cron ---------------------------------------------------------------

// cron.files lists every cron/at config file that exists, with a precomputed
// owner_ok (root-owned, or the spool owner for a per-user spool file) and the
// group/other-writable flags. A world-writable /etc/crontab is owner_ok true
// but group/other-writable true, which U-37 will fail.
func TestCronConfigFiles(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/crontab":                   "crontab",
			"/etc/cron.d/muster":             "cron_d_entry",
			"/etc/cron.allow":                "cron_allow",
			"/var/spool/cron/crontabs/alice": "spool_user",
			"/etc/group":                     "group",
		},
		stats: map[string]statResult{
			"/etc/crontab":                   {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/etc/cron.d/muster":             {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/etc/cron.allow":                {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/var/spool/cron/crontabs/alice": {mode: 0o600, uid: 1000, gid: 1000, kind: "regular"},
		},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	byPath := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	if byPath["/etc/crontab"]["owner_ok"] != true || byPath["/etc/crontab"]["scope"] != "system" {
		t.Errorf("crontab %v", byPath["/etc/crontab"])
	}
	if byPath["/var/spool/cron/crontabs/alice"]["owner_ok"] != true || byPath["/var/spool/cron/crontabs/alice"]["user"] != "alice" {
		t.Errorf("a per-user spool file owned by that user is owner_ok: %v", byPath["/var/spool/cron/crontabs/alice"])
	}
	if byPath["/etc/cron.allow"]["scope"] != "access" {
		t.Errorf("cron.allow is scope access: %v", byPath["/etc/cron.allow"])
	}
}

// A spool directory caught by a spool glob (/var/spool/cron/crontabs matched by
// /var/spool/cron/*) is not a cron.files row — directories are covered by
// cron.dirs, and cronRow skips a non-regular Kind.
func TestCronSpoolDirIsNotAFileRow(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		dirs:  map[string]bool{"/var/spool/cron/crontabs": true},
		stats: map[string]statResult{
			"/etc/crontab":             {mode: 0o644, uid: 0, kind: "regular"},
			"/var/spool/cron/crontabs": {mode: 0o1730, uid: 0, gid: 0, kind: "dir"},
		},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	for _, r := range rows {
		if r.(map[string]any)["path"] == "/var/spool/cron/crontabs" {
			t.Errorf("a spool directory must not be a cron.files row: %v", r)
		}
	}
}

// The systemd timer inventory parses the systemctl table; a systemctl failure
// is the command's error, not an empty list.
func TestCronTimersInventoryAndFailure(t *testing.T) {
	ok := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o644, kind: "regular"}},
		cmds:  map[string]cmdResult{"/usr/bin/systemctl list-unit-files --type=timer --no-legend --no-pager": {file: "systemctl_list_timers.txt"}},
	}
	rows := okList(t, build(t, "cron", ok), "cron.timers")
	if len(rows) == 0 || rows[0].(map[string]any)["name"] == "" {
		t.Fatalf("timers %v", rows)
	}
	bad := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o644, kind: "regular"}},
		cmds:  map[string]cmdResult{"/usr/bin/systemctl list-unit-files --type=timer --no-legend --no-pager": {exitCode: 1, stderr: "fail\n"}},
	}
	if e := env(t, build(t, "cron", bad), "cron.timers"); e.Status == facts.StatusOK {
		t.Errorf("a failed systemctl must not be an ok empty list: %+v", e)
	}
}

// A world-writable /etc/crontab is recorded group/other-writable so U-37 fails.
func TestCronWorldWritableCrontab(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o646, uid: 0, kind: "regular"}},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	if rows[0].(map[string]any)["other_writable"] != true {
		t.Errorf("0646 crontab is other-writable: %v", rows[0])
	}
}

// R202: a denied stat is a finding, not a silent skip — the row carries a
// reason and owner_ok:false. A symlinked path is NOT a finding: is_symlink is
// set, owner_ok is true, and no reason key is present, so the reason-guard
// leaves it alone.
func TestCronStatFailureBranches(t *testing.T) {
	denied := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		fails: map[string]error{"/etc/crontab": fs.ErrPermission},
	}
	rows := okList(t, build(t, "cron", denied), "cron.files")
	var row map[string]any
	for _, r := range rows {
		if m := r.(map[string]any); m["path"] == "/etc/crontab" {
			row = m
		}
	}
	if row == nil {
		t.Fatalf("a denied stat must still yield a row: %v", rows)
	}
	if _, ok := row["reason"]; !ok {
		t.Errorf("a denied cron file must carry a reason: %v", row)
	}
	if row["owner_ok"] != false {
		t.Errorf("a denied cron file is owner_ok false: %v", row)
	}

	sym := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		fails: map[string]error{"/etc/crontab": collect.ErrSymlink},
	}
	srows := okList(t, build(t, "cron", sym), "cron.files")
	var srow map[string]any
	for _, r := range srows {
		if m := r.(map[string]any); m["path"] == "/etc/crontab" {
			srow = m
		}
	}
	if srow == nil {
		t.Fatalf("a symlinked path must still yield a row: %v", srows)
	}
	if srow["is_symlink"] != true || srow["owner_ok"] != true {
		t.Errorf("a symlinked cron file is is_symlink true and owner_ok true: %v", srow)
	}
	if _, ok := srow["reason"]; ok {
		t.Errorf("a symlinked cron file must carry no reason: %v", srow)
	}
}

// R212: owner_ok is false when the owner is neither root nor a real (>=1000)
// user. A system-scope file owned by a non-root system account, and a per-user
// spool file owned by a system account (uid 500), are both the anomaly U-37
// catches.
func TestCronOwnerOkFalseForSystemAccount(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/crontab":                 "crontab",
			"/var/spool/cron/crontabs/svc": "spool_user",
			"/etc/group":                   "group",
		},
		stats: map[string]statResult{
			"/etc/crontab":                 {mode: 0o644, uid: 500, gid: 0, kind: "regular"},
			"/var/spool/cron/crontabs/svc": {mode: 0o600, uid: 500, gid: 500, kind: "regular"},
		},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	byPath := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	if byPath["/etc/crontab"]["owner_ok"] != false {
		t.Errorf("a system-scope file owned by uid 500 is owner_ok false: %v", byPath["/etc/crontab"])
	}
	if byPath["/var/spool/cron/crontabs/svc"]["owner_ok"] != false {
		t.Errorf("a spool file owned by a system account is owner_ok false: %v", byPath["/var/spool/cron/crontabs/svc"])
	}
}

// --- sockets ------------------------------------------------------------

func TestSocketsParsesListeningAndLoopback(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}}
	b := build(t, "sockets", a)
	list := okList(t, b, "sockets.listening")
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	first := list[0].(map[string]any)
	if first["port"] != 22 || first["loopback"] != false || first["proto"] != "tcp" ||
		first["addr"] != "0.0.0.0" || first["inode"] != 12345 {
		t.Errorf("%v", first)
	}
	if list[1].(map[string]any)["loopback"] != true {
		t.Errorf("%v", list[1])
	}
}

func TestSocketsParsesIPv6Loopback(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/proc/self/net/tcp":  "proc_net_tcp_empty",
		"/proc/self/net/tcp6": "proc_net_tcp6_loopback",
	}}
	b := build(t, "sockets", a)
	list := okList(t, b, "sockets.listening")
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	if list[0].(map[string]any)["addr"] != "::1" || list[0].(map[string]any)["loopback"] != true {
		t.Errorf("%v", list[0])
	}
	if list[1].(map[string]any)["addr"] != "::" || list[1].(map[string]any)["loopback"] != false {
		t.Errorf("%v", list[1])
	}
}

// R50: an empty table serialises as [], never null.
func TestSocketsEmptyTableIsAnEmptyList(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/proc/self/net/tcp": "proc_net_tcp_empty"}}
	b := build(t, "sockets", a)
	e := env(t, b, "sockets.listening")
	if e.Status != facts.StatusOK {
		t.Fatalf("%+v", e)
	}
	list, ok := e.Value.([]any)
	if !ok || list == nil || len(list) != 0 {
		t.Errorf("want an empty non-nil list, got %#v", e.Value)
	}
}

func TestSocketsUnreadableTableIsNotAnEmptyList(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/proc/self/net/tcp": os.ErrPermission}}
	b := build(t, "sockets", a)
	if e := env(t, b, "sockets.listening"); e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
}

// I1 (R82). A mandatory /proc/self/net/tcp that is not there at all —
// procfs masked, or never mounted (ENOENT), or /proc/self/net turning out
// not to be a directory (ENOTDIR) — is an environment without a socket
// table, which spec §7.1 files as unsupported. As "absent" it would resolve
// through U-52's absent_means: pass to a PASS on a table nobody ever saw
// (D07), so both facts that rest on the table say unsupported instead.
func TestMaskedProcfsIsUnsupportedNotAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"enoent", os.ErrNotExist},
		{"enotdir", unix.ENOTDIR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := env(t, build(t, "sockets", &fsAccess{
				fails: map[string]error{"/proc/self/net/tcp": tc.err},
			}), "sockets.listening")
			if e.Status != facts.StatusUnsupported {
				t.Errorf("sockets.listening %+v, want unsupported", e)
			}
			if !strings.Contains(e.Reason, "/proc/self/net/tcp") {
				t.Errorf("reason %q must name the table that was not there", e.Reason)
			}
			svc := servicesAccess(nil, allUnitsNotFound())
			svc.fails = map[string]error{"/proc/self/net/tcp": tc.err}
			r := env(t, build(t, "services", svc), "services.telnet.reachable")
			if r.Status != facts.StatusUnsupported {
				t.Errorf("services.telnet.reachable %+v, want unsupported", r)
			}
			if !strings.Contains(r.Reason, "/proc/self/net/tcp") {
				t.Errorf("reason %q must name the table that was not there", r.Reason)
			}
		})
	}
}

// --- files --------------------------------------------------------------

// startup_scripts lists SysV init scripts and systemd unit files with mode
// and is_symlink. An enabled-unit symlink (Stat returns ErrSymlink) is
// is_symlink:true so U-17 can filter it with `where is_symlink eq false`; a
// world-writable regular init script is other_writable:true so U-17 fails it.
func TestFilesStartupScripts(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/init.d/muster": "initd_script", "/etc/systemd/system/muster.service": "systemd_unit", "/etc/group": "group"},
		stats: map[string]statResult{
			"/etc/init.d/muster":                 {mode: 0o755, uid: 0, gid: 0, kind: "regular"},
			"/etc/systemd/system/muster.service": {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
		},
		fails: map[string]error{"/etc/systemd/system/multi-user.target.wants/muster.service": collect.ErrSymlink},
		// The .wants directory itself is matched by /etc/systemd/system/* and must
		// be skipped by globRows (Kind=="dir"), not stat-errored into a row.
		dirs: map[string]bool{"/etc/systemd/system/multi-user.target.wants": true},
	}
	a.stats["/etc/systemd/system/multi-user.target.wants"] = statResult{mode: 0o755, uid: 0, gid: 0, kind: "dir"}
	// the wants-symlink is discoverable via Glob of /etc/systemd/system/*/*
	a.files["/etc/systemd/system/multi-user.target.wants/muster.service"] = "" // present for Glob
	rows := okList(t, build(t, "files", a), "files.startup_scripts")
	byPath := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	if byPath["/etc/init.d/muster"]["other_writable"] != false || byPath["/etc/init.d/muster"]["is_symlink"] != false {
		t.Errorf("regular init script %v", byPath["/etc/init.d/muster"])
	}
	if byPath["/etc/systemd/system/multi-user.target.wants/muster.service"]["is_symlink"] != true {
		t.Errorf("an enabled-unit symlink must be is_symlink:true: %v", byPath["/etc/systemd/system/multi-user.target.wants/muster.service"])
	}
	// The .wants directory is a directory, not a startup file: globRows skips it.
	if _, ok := byPath["/etc/systemd/system/multi-user.target.wants"]; ok {
		t.Errorf("a directory matched by the glob must not be a startup_scripts row: %v", byPath["/etc/systemd/system/multi-user.target.wants"])
	}
}

// syslog config rows are recorded; a world-writable rsyslog.conf is flagged.
func TestFilesSyslogConfigs(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/rsyslog.conf": "rsyslog_conf", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/rsyslog.conf": {mode: 0o646, uid: 0, kind: "regular"}},
	}
	rows := okList(t, build(t, "files", a), "files.syslog_configs")
	if len(rows) != 1 || rows[0].(map[string]any)["other_writable"] != true {
		t.Fatalf("syslog rows %v", rows)
	}
}

// inetd/xinetd are absent on a stock host: the fixed leaves are absent, the
// fragment list an ok empty list.
func TestFilesInetdAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	b := build(t, "files", a)
	if e := env(t, b, "files.etc_inetd_conf.mode"); e.Status != facts.StatusAbsent {
		t.Errorf("absent inetd.conf → absent leaf: %+v", e)
	}
	if l := okList(t, b, "files.xinetd_d"); len(l) != 0 {
		t.Errorf("no xinetd.d fragments → ok empty list, got %v", l)
	}
}

func TestFilesPasswdPermissionFacts(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/passwd": "passwd"}}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.mode").Value != 420 || env(t, b, "files.etc_passwd.uid").Value != 0 {
		t.Error("mode/uid")
	}
	if env(t, b, "files.etc_passwd.gid").Value != 0 {
		t.Error("gid")
	}
	if env(t, b, "files.etc_passwd.acl_present").Value != false {
		t.Error("acl_present")
	}
	if env(t, b, "files.etc_securetty").Status != facts.StatusAbsent {
		t.Error("securetty is absent on this fixture")
	}
	if env(t, b, "files.etc_securetty_lines").Status != facts.StatusAbsent {
		t.Error("securetty lines are absent on this fixture")
	}
}

// R51/R69: the raw 0o7777 bits are reported, so a setgid bit survives —
// FileMode.Perm() would have dropped it and reported a clean 0644.
func TestFilesPasswdModeKeepsTheHighBits(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd"},
		modes: map[string]uint32{"/etc/passwd": 0o2644},
	}
	b := build(t, "files", a)
	if got := env(t, b, "files.etc_passwd.mode").Value; got != 0o2644 {
		t.Errorf("mode %v, want %v", got, 0o2644)
	}
}

// R111: xattrs pins the Llistxattr union path — the ACL name arrives among
// other attributes — while xattrValues gives Getxattr something to answer
// with, since a listed name whose value reads back ENODATA is "no ACL".
func TestFilesAclPresentFromXattr(t *testing.T) {
	a := &fsAccess{
		files:       map[string]string{"/etc/passwd": "passwd"},
		xattrs:      map[string][]string{"/etc/passwd": {"security.selinux", "system.posix_acl_access"}},
		xattrValues: map[string]map[string][]byte{"/etc/passwd": {"system.posix_acl_access": fiveEntryACL()}},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.acl_present").Value != true {
		t.Error("acl_present must be true")
	}
}

func TestFilesNonAclXattrIsNotAnAcl(t *testing.T) {
	a := &fsAccess{
		files:  map[string]string{"/etc/passwd": "passwd"},
		xattrs: map[string][]string{"/etc/passwd": {"security.selinux"}},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.acl_present").Value != false {
		t.Error("a selinux label is not an ACL")
	}
}

func TestFilesSecurettyLinesSkipBlanksAndComments(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/passwd": "passwd", "/etc/securetty": "securetty"}}
	b := build(t, "files", a)
	lines, ok := env(t, b, "files.etc_securetty_lines").Value.([]any)
	if !ok || len(lines) != 2 || lines[0] != "console" || lines[1] != "tty1" {
		t.Errorf("%#v", env(t, b, "files.etc_securetty_lines").Value)
	}
	rec, ok := env(t, b, "files.etc_securetty").Value.(map[string]any)
	if !ok || rec["mode"] != 0o644 {
		t.Errorf("%#v", env(t, b, "files.etc_securetty").Value)
	}
}

// sudoers permission facts come from stat (works non-root); sudo.includedir
// and secure_path are parsed from /etc/sudoers content (root-only read). A
// drop-in ending in ~ or containing . is ignored:true (sudo skips it).
func TestFilesSudoers(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/sudoers": "sudoers", "/etc/sudoers.d/muster": "sudoers_d_entry", "/etc/group": "group"},
		stats: map[string]statResult{
			"/etc/sudoers":          {mode: 0o440, uid: 0, gid: 0, kind: "regular"},
			"/etc/sudoers.d":        {mode: 0o750, uid: 0, gid: 0, kind: "dir"},
			"/etc/sudoers.d/muster": {mode: 0o440, uid: 0, gid: 0, kind: "regular"},
		},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_sudoers.mode").Value != 0o440 || env(t, b, "files.etc_sudoers.uid").Value != 0 {
		t.Errorf("sudoers perms %+v", env(t, b, "files.etc_sudoers.mode"))
	}
	if env(t, b, "sudo.installed").Value != true {
		t.Error("sudo.installed")
	}
	if env(t, b, "sudo.secure_path").Value != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("secure_path %+v", env(t, b, "sudo.secure_path"))
	}
	rows := okList(t, b, "files.sudoers_d_entries")
	if len(rows) != 1 || rows[0].(map[string]any)["ignored"] != false {
		t.Fatalf("drop-in rows %v", rows)
	}
}

// A non-root run cannot read /etc/sudoers: sudo.secure_path is denied, but the
// stat-based perm facts (mode/uid) and sudo.installed still succeed. acl_present
// is legitimately denied on a non-root run (the ACL probe needs the file open),
// so this test does NOT assert acl_present is ok.
func TestFilesSudoersDeniedRead(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/sudoers": os.ErrPermission},
		stats: map[string]statResult{"/etc/sudoers": {mode: 0o440, uid: 0, kind: "regular"}},
		files: map[string]string{"/etc/group": "group"},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_sudoers.mode").Value != 0o440 {
		t.Errorf("stat still works: %+v", env(t, b, "files.etc_sudoers.mode"))
	}
	if env(t, b, "files.etc_sudoers.uid").Value != 0 {
		t.Errorf("uid stat still works: %+v", env(t, b, "files.etc_sudoers.uid"))
	}
	if e := env(t, b, "sudo.secure_path"); e.Status != facts.StatusDenied {
		t.Errorf("a denied read → denied secure_path: %+v", e)
	}
}

// A Defaults line with spaces around the "=" (Rocky's shape,
// `Defaults    secure_path = /usr/sbin:/usr/bin`) is parsed by the L2 regex.
func TestFilesSudoSecurePathSpacedEquals(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/sudoers": "sudoers_spaced_securepath", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/sudoers": {mode: 0o440, uid: 0, gid: 0, kind: "regular"}},
	}
	b := build(t, "files", a)
	if e := env(t, b, "sudo.secure_path"); e.Value != "/usr/sbin:/usr/bin" {
		t.Errorf("secure_path with spaces around = must parse to the trimmed value: %+v", e)
	}
}

// /var/log rows carry the group name and writable flags, and /var/log itself is
// a log_dirs row.
func TestFilesLogTree(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		dirs:  map[string]bool{"/var/log": true, "/var/log/journal": true},
		stats: map[string]statResult{
			"/var/log":         {mode: 0o755, uid: 0, gid: 0, kind: "dir"},
			"/var/log/journal": {mode: 0o2755, uid: 0, gid: 4, kind: "dir"},        // gid 4 = adm in the group fixture
			"/var/log/syslog":  {mode: 0o640, uid: 104, gid: 104, kind: "regular"}, // gid 104 = syslog
		},
	}
	a.files["/var/log/syslog"] = "" // present for Glob
	b := build(t, "files", a)
	ld := okList(t, b, "files.log_dirs")
	if len(ld) < 1 {
		t.Fatalf("log_dirs %v", ld)
	}
	// /var/log itself is a row.
	var haveVarLog bool
	for _, r := range ld {
		if r.(map[string]any)["path"] == "/var/log" {
			haveVarLog = true
		}
	}
	if !haveVarLog {
		t.Errorf("/var/log itself must be a log_dirs row: %v", ld)
	}
	// The syslog file row carries the group name (U-67 judges this leaf) and the
	// group-writable flag: gid 104 = syslog, mode 0640 is not group-writable.
	lf := okList(t, b, "files.log_files")
	var syslogRow map[string]any
	for _, r := range lf {
		if m := r.(map[string]any); m["path"] == "/var/log/syslog" {
			syslogRow = m
		}
	}
	if syslogRow == nil {
		t.Fatalf("the syslog file must be a log_files row: %v", lf)
	}
	if syslogRow["group"] != "syslog" {
		t.Errorf("syslog row group name (evidence U-67 judges) = %v, want syslog", syslogRow["group"])
	}
	if syslogRow["group_writable"] != false {
		t.Errorf("0640 syslog row must not be group_writable: %v", syslogRow)
	}
}

// When /etc/group cannot be read, U-67 judges the log rows' group field, so a
// silent group:"" would be fabricated evidence. Both log keys must carry the
// read error (path-prefixed with /etc/group), never a clean list.
func TestFilesLogTreeDeniedGroupIsError(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{},
		fails: map[string]error{"/etc/group": os.ErrPermission},
		dirs:  map[string]bool{"/var/log": true},
		stats: map[string]statResult{
			"/var/log":        {mode: 0o755, uid: 0, gid: 0, kind: "dir"},
			"/var/log/syslog": {mode: 0o640, uid: 104, gid: 104, kind: "regular"},
		},
	}
	a.files["/var/log/syslog"] = "" // present for Glob
	b := build(t, "files", a)
	for _, k := range []string{"files.log_dirs", "files.log_files"} {
		e := env(t, b, k)
		if e.Status == facts.StatusOK {
			t.Errorf("%s: a denied /etc/group must not yield a clean list: %+v", k, e)
		}
		if !strings.Contains(e.Reason, groupPath) {
			t.Errorf("%s: reason must name /etc/group: %+v", k, e)
		}
	}
}

// --- services -----------------------------------------------------------

func showLine(unit string) string {
	return "/usr/bin/systemctl show -p LoadState,ActiveState,UnitFileState,SubState " + unit
}

// allUnitsNotFound cans a systemd that answers, and says every unit this
// collector asks about is unknown to it.
func allUnitsNotFound() map[string]cmdResult {
	out := map[string]cmdResult{}
	for _, u := range []string{
		"ssh.service", "sshd.service", "ssh.socket",
		"telnet.socket", "telnet.service", "telnetd.service",
		"inetd.service", "xinetd.service",
	} {
		out[showLine(u)] = cmdResult{file: "systemctl.notfound"}
	}
	return out
}

func servicesAccess(files map[string]string, cmds map[string]cmdResult) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &fsAccess{
		files: files,
		dirs:  map[string]bool{"/run/systemd/system": true},
		cmds:  cmds,
	}
}

func TestServicesUnsupportedWithoutSystemd(t *testing.T) {
	b := build(t, "services", &fsAccess{})
	for _, k := range []string{
		"services.ssh.installed", "services.ssh.active",
		"services.telnet.installed", "services.telnet.reachable",
	} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s: %+v", k, e)
		}
	}
}

func TestServicesSshInstalledAndActive(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.active"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != true || env(t, b, "services.ssh.active").Value != true {
		t.Errorf("ssh %+v %+v", env(t, b, "services.ssh.installed"), env(t, b, "services.ssh.active"))
	}
	if env(t, b, "services.telnet.installed").Value != false {
		t.Errorf("telnet installed %+v", env(t, b, "services.telnet.installed"))
	}
	// The only port-23 listener in that fixture is bound to 127.0.0.1.
	if env(t, b, "services.telnet.reachable").Value != false {
		t.Errorf("telnet reachable %+v", env(t, b, "services.telnet.reachable"))
	}
}

func TestServicesSshInstalledButInactive(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.inactive"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != true || env(t, b, "services.ssh.active").Value != false {
		t.Errorf("ssh %+v %+v", env(t, b, "services.ssh.installed"), env(t, b, "services.ssh.active"))
	}
}

func TestServicesSshActiveIsAbsentWhenNoUnitIsLoaded(t *testing.T) {
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != false {
		t.Errorf("installed %+v", env(t, b, "services.ssh.installed"))
	}
	if env(t, b, "services.ssh.active").Status != facts.StatusAbsent {
		t.Errorf("active %+v", env(t, b, "services.ssh.active"))
	}
}

// R63: a live xinetd telnet block counts as installed, and a non-loopback
// port-23 listener makes it reachable.
func TestServicesTelnetInstalledFromXinetdAndReachable(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp":   "proc_net_tcp_telnet",
		"/etc/xinetd.d/telnet": "xinetd.telnet",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.telnet.installed").Value != true {
		t.Errorf("installed %+v", env(t, b, "services.telnet.installed"))
	}
	if env(t, b, "services.telnet.reachable").Value != true {
		t.Errorf("reachable %+v", env(t, b, "services.telnet.reachable"))
	}
}

func TestServicesTelnetInstalledFromInetdConf(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.telnet",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	e := env(t, b, "services.telnet.installed")
	if e.Value != true || e.Source == nil || e.Source.Path != "/etc/inetd.conf" || e.Source.Line != 2 {
		t.Errorf("installed %+v %+v", e, e.Source)
	}
}

// M14. An inetd line declares telnet by its FIRST field — the service name
// — or by a server program that ends in "telnetd". The word appearing
// anywhere on the line is not evidence: an unrelated service whose
// arguments or trailing comment mention telnet would otherwise be reported
// as a telnet daemon that is not installed at all.
func TestServicesInetdTelnetIsNotASubstringMatch(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.ftp_mentions_telnet",
	}, allUnitsNotFound())
	e := env(t, build(t, "services", a), "services.telnet.installed")
	if e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v: an ftp line that merely mentions telnet must not count", e)
	}
}

// ...and the server field still counts, whatever the service is called.
func TestServicesInetdTelnetFromTheServerField(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.server_telnetd",
	}, allUnitsNotFound())
	e := env(t, build(t, "services", a), "services.telnet.installed")
	if e.Value != true || e.Source == nil || e.Source.Line != 2 {
		t.Errorf("installed %+v %+v", e, e.Source)
	}
}

// R63: a comment line never counts, in either legacy file.
func TestServicesCommentedTelnetEntriesAreNotInstalled(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp":   "proc_net_tcp",
		"/etc/inetd.conf":      "inetd.conf.commented",
		"/etc/xinetd.d/telnet": "xinetd.telnet.commented",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.telnet.installed").Value != false {
		t.Errorf("a commented entry must not count: %+v", env(t, b, "services.telnet.installed"))
	}
}

// R41: with the socket table unreadable, reachable carries that read's
// envelope. A silent false would be a PASS on no evidence.
func TestServicesTelnetReachableCarriesTheSocketReadError(t *testing.T) {
	a := servicesAccess(nil, allUnitsNotFound())
	a.fails = map[string]error{"/proc/self/net/tcp": os.ErrPermission}
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.reachable"); e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	// installed stays independent of the socket read.
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("installed %+v", e)
	}
}

// A systemd host whose systemctl cannot be run has no unit evidence at all;
// reporting "not installed" there would be a PASS on nothing.
func TestServicesUnitQueryFailureIsNotASilentFalse(t *testing.T) {
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, nil)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusError {
		t.Errorf("ssh installed %+v", e)
	}
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusError {
		t.Errorf("telnet installed %+v", e)
	}
	// reachable is still answerable from the socket table alone.
	if e := env(t, b, "services.telnet.reachable"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("reachable %+v", e)
	}
}

// Fix 2 (Important). One unit that never answered means the sweep never
// covered it, so "not installed" would rest on evidence that does not exist.
func TestServicesOneUnitTimingOutIsNotOkFalse(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{timedOut: true, exitCode: -1}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusTimeout {
		t.Errorf("installed %+v, want timeout", e)
	}
	if e := env(t, b, "services.ssh.active"); e.Status != facts.StatusTimeout {
		t.Errorf("active %+v, want timeout", e)
	}
}

// The same for telnet, and the failing unit's own envelope is the one kept.
func TestServicesTelnetOneUnitDeniedIsNotOkFalse(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("telnet.socket")] = cmdResult{exitCode: 1, stderr: "Permission denied\n"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusDenied {
		t.Errorf("installed %+v, want denied", e)
	}
	// ssh answered completely, so it is unaffected.
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusOK {
		t.Errorf("ssh installed %+v", e)
	}
}

// Fix 4, command side: a capped systemctl capture marks the value.
func TestServicesMarksTruncatedCommandOutput(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.active", truncated: true}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); !e.Truncated {
		t.Errorf("%+v", e)
	}
}

// R80. Positive evidence stands on its own: a sibling unit that never
// answered cannot make a loaded, running unit unloaded or inactive.
func TestServicesPositiveEvidenceSurvivesAnIncompleteSweep(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.active"}
	cmds[showLine("sshd.service")] = cmdResult{timedOut: true, exitCode: -1}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("installed %+v, want ok:true", e)
	}
	if e := env(t, b, "services.ssh.active"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("active %+v, want ok:true", e)
	}
}

// ...but a negative still needs the whole sweep: nothing proved anything,
// and the unit that never answered is exactly the one that might have.
func TestServicesNegativeStillNeedsTheWholeSweep(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("sshd.service")] = cmdResult{timedOut: true, exitCode: -1}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusTimeout {
		t.Errorf("installed %+v, want timeout", e)
	}
}

// Telnet the same way: a loaded unit proves it even though a sibling failed,
// and the legacy files are not consulted at all.
func TestServicesTelnetPositiveEvidenceSurvivesAnIncompleteSweep(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("telnet.socket")] = cmdResult{file: "systemctl.loaded.active"}
	cmds[showLine("telnet.service")] = cmdResult{timedOut: true, exitCode: -1}
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.telnet",
	}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("installed %+v, want ok:true", e)
	}
	if slices.Contains(a.reads, "/etc/inetd.conf") {
		t.Errorf("systemd already proved it; /etc/inetd.conf must not be read: %v", a.reads)
	}
}

// Fix 10. Once systemd has proved telnet is installed, the legacy files
// cannot change the answer, so they are not read at all.
func TestServicesSkipsLegacyFilesWhenSystemdProvesTelnet(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("telnet.socket")] = cmdResult{file: "systemctl.loaded.active"}
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.telnet",
	}, cmds)
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.installed"); e.Value != true {
		t.Errorf("%+v", e)
	}
	if slices.Contains(a.reads, "/etc/inetd.conf") {
		t.Errorf("systemd already proved it; /etc/inetd.conf must not be read: %v", a.reads)
	}
}

// ...and it IS read when systemd did not prove it.
func TestServicesReadsLegacyFilesWhenSystemdDidNotProveTelnet(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.telnet",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.installed"); e.Value != true {
		t.Errorf("%+v", e)
	}
	if !slices.Contains(a.reads, "/etc/inetd.conf") {
		t.Errorf("/etc/inetd.conf should have been read: %v", a.reads)
	}
}

// --- os -----------------------------------------------------------------

func osAccess() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			"/etc/os-release":                          "os-release",
			"/etc/hostname":                            "hostname",
			"/etc/machine-id":                          "machine-id",
			"/proc/sys/kernel/osrelease":               "kernel-osrelease",
			"/proc/sys/kernel/random/boot_id":          "boot-id",
			"/proc/uptime":                             "uptime",
			"/proc/version":                            "proc-version",
			"/proc/1/cgroup":                           "proc-1-cgroup",
			"/proc/1/comm":                             "proc-1-comm",
			"/sys/devices/virtual/dmi/id/product_name": "dmi-product-name",
		},
		dirs:     map[string]bool{"/run/systemd/system": true, "/var/lib/cloud": true},
		writable: map[string]bool{"/proc/sys/net": true},
	}
}

func osDoubleWithDockerAndSystemd(t *testing.T) *fsAccess {
	a := osAccess()
	a.dirs["/.dockerenv"] = true
	return a
}

func TestOSFillsTheRunHeader(t *testing.T) {
	b := build(t, "os", osAccess())
	tree := b.Tree()
	if len(tree) != 1 {
		t.Errorf("os writes exactly env.container and env.has_systemd under env, got %v top-level keys: %v", len(tree), tree)
	}
	envMap, ok := tree["env"].(map[string]any)
	if !ok || len(envMap) != 2 {
		t.Errorf("env should have exactly 2 keys (container, has_systemd), got %v", envMap)
	}
	if v := env(t, b, "env.container"); v.Status != facts.StatusOK || v.Value != "none" {
		t.Errorf("env.container = %+v", v)
	}
	if v := env(t, b, "env.has_systemd"); v.Status != facts.StatusOK || v.Value != true {
		t.Errorf("env.has_systemd = %+v", v)
	}
	h := b.Header().Host
	if h.Hostname != "fixture-host" || h.Kernel != "6.8.0-31-generic" || h.UptimeS != 12345 {
		t.Errorf("%+v", h)
	}
	if h.OSRelease.ID != "ubuntu" || h.OSRelease.VersionID != "24.04" || h.OSRelease.Family != "debian" {
		t.Errorf("%+v", h.OSRelease)
	}
	sum := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	if h.MachineIDHash != hex.EncodeToString(sum[:]) {
		t.Errorf("machine id hash %q", h.MachineIDHash)
	}
	if strings.Contains(h.MachineIDHash, "0123456789abcdef0123456789abcdef") {
		t.Error("the machine id itself must never be stored")
	}
	e := b.Header().Env
	if e.Container != "none" || e.Virt != "kvm" || e.WSL || !e.HasSystemd || !e.SysctlWritable || !e.CloudInit {
		t.Errorf("%+v", e)
	}
}

// R40: /etc/os-release is a symlink on Ubuntu 22.04/24.04 and Rocky/Alma 9,
// which the read primitive refuses; the canonical file is the fallback.
func TestOSFallsBackToUsrLibOSRelease(t *testing.T) {
	a := osAccess()
	delete(a.files, "/etc/os-release")
	a.fails = map[string]error{"/etc/os-release": collect.ErrSymlink}
	a.files["/usr/lib/os-release"] = "os-release"
	b := build(t, "os", a)
	if b.Header().Host.OSRelease.ID != "ubuntu" {
		t.Errorf("%+v", b.Header().Host.OSRelease)
	}
}

func TestOSDetectsDockerAndWSL(t *testing.T) {
	a := osDoubleWithDockerAndSystemd(t)
	a.files["/proc/version"] = "proc-version-wsl"
	b := build(t, "os", a)
	if b.Header().Env.Container != "docker" {
		t.Errorf("container %q", b.Header().Env.Container)
	}
	if !b.Header().Env.WSL {
		t.Error("wsl")
	}
}

func TestOSVirtIsUnknownWhenDMIIsUnreadable(t *testing.T) {
	a := osAccess()
	delete(a.files, "/sys/devices/virtual/dmi/id/product_name")
	b := build(t, "os", a)
	if b.Header().Env.Virt != "unknown" {
		t.Errorf("virt %q", b.Header().Env.Virt)
	}
}

func TestOSWritesEnvContainerAndSystemdAsFacts(t *testing.T) {
	a := osDoubleWithDockerAndSystemd(t)
	b := build(t, "os", a)
	if v := env(t, b, "env.container"); v.Status != facts.StatusOK || v.Value != "docker" {
		t.Errorf("env.container = %+v", v)
	}
	if v := env(t, b, "env.has_systemd"); v.Status != facts.StatusOK || v.Value != true {
		t.Errorf("env.has_systemd = %+v", v)
	}
	if h := b.Header(); h.Env.Container != "docker" || !h.Env.HasSystemd {
		t.Errorf("header must agree with the facts: %+v", h.Env)
	}
}

// --- walk ---------------------------------------------------------------

// R47/R76: stage 1 registers walk with nothing declared and it writes no
// keys, so U-25 stays MANUAL on a real stage-1 snapshot.
func TestWalkDeclaresAndWritesNothing(t *testing.T) {
	c := collectorNamed(t, "walk")
	if len(c.Declare.Reads) != 0 || len(c.Declare.Commands) != 0 {
		t.Errorf("walk must declare nothing in stage 1: %+v", c.Declare)
	}
	b := build(t, "walk", &fsAccess{})
	if len(b.Tree()) != 0 {
		t.Errorf("walk must write no keys: %v", b.Tree())
	}
}

// --- the declaration contract ------------------------------------------

func TestEveryCollectorStaysInsideItsDeclaration(t *testing.T) {
	a := &fsAccess{}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	for _, c := range collect.All() {
		g := collect.Guard(a, c)
		b := collect.NewBuilder(reg)
		if err := c.Run(context.Background(), g, b); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		if v := g.Violations(); len(v) != 0 {
			t.Errorf("%s touched undeclared targets: %v", c.Name, v)
		}
	}
}

func TestEveryDeclaredTargetIsAbsolute(t *testing.T) {
	for _, c := range collect.All() {
		for _, cmd := range c.Declare.Commands {
			if !strings.HasPrefix(cmd.Path, "/") {
				t.Errorf("%s: command path %q is not absolute", c.Name, cmd.Path)
			}
		}
		for _, r := range c.Declare.Reads {
			if !strings.HasPrefix(r, "/") {
				t.Errorf("%s: read %q is not absolute", c.Name, r)
			}
		}
	}
}

// R40: no collector may declare a path the read primitive is guaranteed to
// refuse — /proc/net/* and /sys/class/dmi/* are symlinks on every supported
// distribution.
func TestNoCollectorDeclaresAKnownSymlink(t *testing.T) {
	for _, c := range collect.All() {
		for _, r := range c.Declare.Reads {
			if strings.HasPrefix(r, "/proc/net/") || strings.HasPrefix(r, "/sys/class/dmi/") {
				t.Errorf("%s declares %q, which is a symlink the read primitive refuses", c.Name, r)
			}
		}
	}
}

// --- the real host ------------------------------------------------------

// TestSmokeOnTheRealHost runs three collectors against the production
// Access — collect.Host(), the same one the collect command will use — with
// the real filesystem underneath and the guard on top. It asserts shapes
// only: no host value is printed, logged or stored anywhere.
func TestSmokeOnTheRealHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the smoke test collects as root")
	}
	if _, err := os.Stat("/proc/self/net/tcp"); err != nil {
		t.Skip("no /proc/self/net/tcp on this machine")
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	for _, name := range []string{"sockets", "os", "files"} {
		c := collectorNamed(t, name)
		g := collect.Guard(collect.Host(), c)
		if err := c.Run(context.Background(), g, b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := g.Violations(); len(v) != 0 {
			t.Fatalf("%s touched undeclared targets: %v", name, v)
		}
	}
	listening := env(t, b, "sockets.listening")
	if listening.Status != facts.StatusOK {
		t.Fatalf("sockets.listening status %s (%s)", listening.Status, listening.Reason)
	}
	if list, ok := listening.Value.([]any); !ok || list == nil {
		t.Fatal("sockets.listening must carry a non-nil list")
	}
	mode := env(t, b, "files.etc_passwd.mode")
	if mode.Status != facts.StatusOK {
		t.Fatalf("files.etc_passwd.mode status %s (%s)", mode.Status, mode.Reason)
	}
	if m, ok := mode.Value.(int); !ok || m < 0 || m > 0o7777 {
		t.Fatal("files.etc_passwd.mode must be permission bits in 0..0o7777")
	}
	// The same shape through writePermFacts on a second fixed path, so the
	// template is exercised against the real filesystem and not only the
	// double.
	hostsMode := env(t, b, "files.etc_hosts.mode")
	if hostsMode.Status != facts.StatusOK {
		t.Fatalf("files.etc_hosts.mode status %s (%s)", hostsMode.Status, hostsMode.Reason)
	}
	if m, ok := hostsMode.Value.(int); !ok || m < 0 || m > 0o7777 {
		t.Fatal("files.etc_hosts.mode must be permission bits in 0..0o7777")
	}
	if b.Header().Host.OSRelease.ID == "" {
		t.Fatal("run.host.os_release.id must not be empty")
	}
	t.Log("smoke: sockets, os and files collected under the guard with no violations")
}

// --- env ----------------------------------------------------------------

// The winning TMOUT is the last unconditional assignment across the profile
// files read in order; its exported/readonly flags come from that line (or a
// later export/readonly of the same name). A value set only inside an `if`
// block is recorded with conditional=true and does not win.
func TestEnvEffectiveTMOUT(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/profile":               "profile",               // TMOUT=600; export TMOUT
			"/etc/profile.d/99-tmout.sh": "profile.d_99-tmout.sh", // readonly TMOUT (no value)
		},
	}
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600", e)
	}
	if env(t, b, "env.shell.tmout_exported").Value != true {
		t.Error("TMOUT is exported")
	}
	if env(t, b, "env.shell.tmout_readonly").Value != true {
		t.Error("TMOUT is readonly")
	}
	settings := okList(t, b, "env.shell.tmout_settings")
	if len(settings) < 1 {
		t.Fatalf("tmout_settings %v", settings)
	}
}

// A conditional umask does not win and is flagged; a system-scope and a
// root-scope umask are both recorded with the right scope.
func TestEnvUmaskSettings(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/profile":                "profile",                // umask 022 (system, unconditional)
		"/etc/profile.d/10-muster.sh": "profile.d_10-muster.sh", // umask 002 inside an if (conditional)
		"/root/.bashrc":               "root_bashrc",
	}}
	rows := okList(t, build(t, "env", a), "env.shell.umask_settings")
	var sawConditional, sawSystem bool
	for _, r := range rows {
		m := r.(map[string]any)
		if m["value"] == "002" && m["conditional"] == true {
			sawConditional = true
		}
		if m["value"] == "022" && m["scope"] == "system" && m["conditional"] == false {
			sawSystem = true
		}
	}
	if !sawConditional || !sawSystem {
		t.Errorf("umask rows %v", rows)
	}
}

// Root PATH is split into positioned entries. An empty element is is_dot; a
// declared world-writable directory carries world_writable=true; an element
// outside the declared PATH-dir set is not stat'd but marked
// unresolved+undeclared (R175); a $/~ element is variable+unresolved (R180).
func TestEnvRootPathEntries(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/root/.bashrc": "root_bashrc_badpath"}, // PATH=/usr/bin::/usr/local/games:/opt/x:$HOME/bin
		stats: map[string]statResult{
			"/usr/bin":         {mode: 0o755, kind: "dir"},
			"/usr/local/games": {mode: 0o777, kind: "dir"}, // declared and world-writable
		},
	}
	entries := okList(t, build(t, "env", a), "env.shell.root_path_entries")
	if len(entries) != 5 {
		t.Fatalf("entries %v, want 5 (/usr/bin, empty, /usr/local/games, /opt/x, $HOME/bin)", entries)
	}
	if entries[1].(map[string]any)["is_dot"] != true {
		t.Error("the empty element between :: must be is_dot")
	}
	if entries[2].(map[string]any)["world_writable"] != true {
		t.Error("/usr/local/games is world-writable")
	}
	if entries[3].(map[string]any)["undeclared"] != true || entries[3].(map[string]any)["unresolved"] != true {
		t.Errorf("/opt/x is outside the declared PATH-dir set: unresolved+undeclared, never stat'd: %v", entries[3])
	}
	if entries[4].(map[string]any)["variable"] != true || entries[4].(map[string]any)["is_dot"] == true {
		t.Errorf("$HOME/bin is an unexpanded variable, not is_dot: %v", entries[4])
	}
}

// A profile file that cannot be read (denied — not ENOENT) is the answer for
// every value it could set: all seven env.shell.* keys carry the path-prefixed
// read error (C3, R183), never a value salvaged from the other files.
func TestEnvDeniedProfileIsAnError(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/profile": "profile"},
		fails: map[string]error{"/etc/bash.bashrc": os.ErrPermission},
	}
	b := build(t, "env", a)
	// All seven leaves the collector could set must carry the read's status —
	// none may salvage a value from /etc/profile (C3, R183).
	keys := []string{
		"env.shell.tmout", "env.shell.tmout_exported", "env.shell.tmout_readonly",
		"env.shell.tmout_settings", "env.shell.umask_settings",
		"env.shell.root_path_raw", "env.shell.root_path_entries",
	}
	for _, k := range keys {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("a denied profile file must make %s denied, got %+v", k, e)
		}
	}
	// The read's status must be path-prefixed so the report names the file that
	// could not be read (C3), matching readErrorEnv's shape.
	if e := env(t, b, "env.shell.tmout"); !strings.HasPrefix(e.Reason, "/etc/bash.bashrc:") {
		t.Errorf("reason %q must be prefixed with the unreadable path", e.Reason)
	}
}

// A line may hold several statements separated by an unquoted `;`, and a
// declaration keyword (declare/typeset/export/readonly) with -x/-r/-xr flags
// assigns TMOUT just as a bare assignment does (R184).
func TestEnvTMOUTDeclarationForms(t *testing.T) {
	b := build(t, "env", &fsAccess{files: map[string]string{"/etc/profile": "profile_tmout_oneline"}})
	if e := env(t, b, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600 from `TMOUT=600; export TMOUT`", e)
	}
	if env(t, b, "env.shell.tmout_exported").Value != true {
		t.Error("the trailing `export TMOUT` marks it exported")
	}

	b2 := build(t, "env", &fsAccess{files: map[string]string{"/etc/profile": "profile_tmout_declare"}})
	if e := env(t, b2, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600 from `declare -xr TMOUT=600`", e)
	}
	if env(t, b2, "env.shell.tmout_readonly").Value != true {
		t.Error("`declare -xr` makes TMOUT readonly")
	}
}

// R196: a later `PATH=$PATH:…` must SPLICE in the PATH accumulated from the
// earlier unconditional assignments, not mask them. Here /etc/profile.d/10-x.sh
// sets `PATH=/usr/bin:.` (a "." is_dot element) and /root/.bash_profile then
// sets `PATH=$PATH:$HOME/bin`; the spliced entry list must still carry the "."
// so U-14 would FAIL, while root_path_raw stays the verbatim last winning line.
func TestEnvRootPathSplicesSelfReference(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/profile.d/10-x.sh": "profile.d_10-path.sh",     // PATH=/usr/bin:.
			"/root/.bash_profile":    "root_bash_profile_splice", // PATH=$PATH:$HOME/bin
		},
		stats: map[string]statResult{"/usr/bin": {mode: 0o755, kind: "dir"}},
	}
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.root_path_raw"); e.Value != "$PATH:$HOME/bin" {
		t.Errorf("root_path_raw %+v, want the verbatim last winning line \"$PATH:$HOME/bin\"", e)
	}
	entries := okList(t, b, "env.shell.root_path_entries")
	var sawDot bool
	for _, r := range entries {
		if r.(map[string]any)["is_dot"] == true {
			sawDot = true
		}
	}
	if !sawDot {
		t.Errorf("the spliced PATH must still carry the \".\" from the earlier file (an is_dot row so U-14 FAILs): %v", entries)
	}
}

// R197: env.shell.tmout is a system-scope fact. A TMOUT set ONLY in root's
// dotfiles must not decide the host-wide value — otherwise a root-only TMOUT
// would yield a host-wide U-12 PASS. With no system-scope TMOUT, the value is 0.
func TestEnvTMOUTIsSystemScopeOnly(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/root/.bashrc": "root_bashrc_tmout"}} // TMOUT=600 in root scope only
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.tmout"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("tmout %+v, want 0 — a root-scope TMOUT must not set the system value", e)
	}
	// The row is still recorded as evidence, marked root scope.
	var sawRoot bool
	for _, r := range okList(t, b, "env.shell.tmout_settings") {
		m := r.(map[string]any)
		if m["value"] == "600" && m["scope"] == "root" {
			sawRoot = true
		}
	}
	if !sawRoot {
		t.Errorf("the root-scope TMOUT row must still be recorded with scope \"root\": %v", okList(t, b, "env.shell.tmout_settings"))
	}
}

// --- files: home directories, environment files and .rhosts --------------

// home_dirs has one row per passwd home. A service account (nologin shell,
// /nonexistent home) is interactive=false and its absent home is NOT a
// finding. root and an interactive user are interactive=true; an unreadable
// home (parent EACCES) is stat_status=denied, never absent.
func TestFilesHomeDirsInteractiveAndTriState(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo"},
		dirs:  map[string]bool{"/root": true, "/home/alice": true},
		stats: map[string]statResult{
			"/root":       {mode: 0o700, uid: 0, gid: 0, kind: "dir"},
			"/home/alice": {mode: 0o755, uid: 1000, gid: 1000, kind: "dir"},
		},
		fails: map[string]error{"/home/bob": os.ErrPermission}, // interactive, but parent denies stat
	}
	rows := okList(t, build(t, "files", a), "files.home_dirs")
	byUser := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byUser[m["user"].(string)] = m
	}
	if byUser["svc"]["interactive"] != false {
		t.Error("a nologin service account must be interactive=false")
	}
	if byUser["alice"]["stat_status"] != "ok" || byUser["alice"]["owner_matches"] != true {
		t.Errorf("alice %v", byUser["alice"])
	}
	if byUser["bob"]["stat_status"] != "denied" {
		t.Errorf("bob's unreadable home must be denied, not absent: %v", byUser["bob"])
	}
	// R176: every field the U-31/U-32 `each … require` clauses read must be
	// present and defaulted on a denied row, or the clause compares an absent
	// field and ERRORs instead of the intended FAIL. Lock the pre-fill so a
	// refactor that moved the defaults into only the ok branch is caught.
	if byUser["bob"]["owner_matches"] != false || byUser["bob"]["group_writable"] != false || byUser["bob"]["mode"] != -1 {
		t.Errorf("bob's denied row must keep the pre-filled defaults (owner_matches:false, group_writable:false, mode:-1): %v", byUser["bob"])
	}
}

// A denied /etc/passwd makes the three enumerations the read error, never an
// empty list.
func TestFilesHomeEnumDeniedPasswdIsError(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/etc/passwd": os.ErrPermission},
		files: map[string]string{"/etc/shells": "shells_home"}}
	b := build(t, "files", a)
	for _, k := range []string{"files.home_dirs", "files.env_files", "files.user_rhosts"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s must be denied, not an empty list: %+v", k, e)
		}
	}
}

// S3: a denied /etc/shells cannot be trusted for the interactive-home
// classification (the libc fallback omits /bin/bash, so every bash account
// would read as non-interactive and U-24/U-27/U-31/U-32 would pass vacuously).
// The three home enumerations must carry that read's status, never a clean
// empty list.
func TestFilesUntrustedShellsMakesEnumerationsDenied(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/proc/self/mountinfo": "mountinfo"},
		fails: map[string]error{"/etc/shells": os.ErrPermission}, // passwd is fine; only /etc/shells is denied
	}
	b := build(t, "files", a)
	for _, k := range []string{"files.home_dirs", "files.env_files", "files.user_rhosts"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("a denied /etc/shells must make %s denied, not a vacuous enumeration: %+v", k, e)
		}
	}
}

// S4: an unreadable /proc/self/mountinfo makes the /dev stray-file detection
// unreliable, so dev_entries and dev_nondevice must carry the read error, not a
// clean empty list (which would be a vacuous PASS for U-26).
func TestFilesDevUnreadableMountinfoIsNotACleanEmpty(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home"},
		fails: map[string]error{"/proc/self/mountinfo": os.ErrPermission},
	}
	b := build(t, "files", a)
	for _, k := range []string{"files.dev_nondevice", "files.dev_entries"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("an unreadable mountinfo must make %s denied, not an empty list: %+v", k, e)
		}
	}
}

// A .rhosts with a bare "+" is recorded has_plus=true with entry_count, body
// never stored; env_files marks a non-owner file owner_ok=false.
func TestFilesRhostsAndEnvFiles(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo",
			"/home/alice/.rhosts": "home_alice_rhosts", // contains "+"
			"/home/alice/.bashrc": "home_alice_bashrc",
		},
		stats: map[string]statResult{
			"/home/alice/.rhosts": {mode: 0o644, uid: 1000, kind: "regular"},
			"/home/alice/.bashrc": {mode: 0o644, uid: 0, kind: "regular"}, // root-owned in alice's home
		},
	}
	b := build(t, "files", a)
	rh := okList(t, b, "files.user_rhosts")
	if len(rh) != 1 || rh[0].(map[string]any)["has_plus"] != true {
		t.Fatalf("user_rhosts %v", rh)
	}
	ef := okList(t, b, "files.env_files")
	var alicebashrc map[string]any
	for _, r := range ef {
		m := r.(map[string]any)
		if m["path"] == "/home/alice/.bashrc" {
			alicebashrc = m
		}
	}
	if alicebashrc == nil || alicebashrc["owner_ok"] != true { // root-owned is ok
		t.Errorf(".bashrc row %v", alicebashrc)
	}
}

// R182: Stat returns collect.ErrSymlink for a final-component symlink, so a
// symlinked environment file never reaches the nil-error branch; it must still
// surface as a row, marked is_symlink=true and owner_ok=false, so U-24's
// `none where` clauses see it rather than the file silently vanishing.
func TestFilesEnvFilesSymlinkRow(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo"},
		fails: map[string]error{"/home/alice/.bashrc": collect.ErrSymlink},
	}
	ef := okList(t, build(t, "files", a), "files.env_files")
	var row map[string]any
	for _, r := range ef {
		m := r.(map[string]any)
		if m["path"] == "/home/alice/.bashrc" {
			row = m
		}
	}
	if row == nil {
		t.Fatalf("a symlinked ~/.bashrc must still appear in env_files: %v", ef)
	}
	if row["is_symlink"] != true || row["owner_ok"] != false {
		t.Errorf("symlink row must be is_symlink:true, owner_ok:false: %v", row)
	}
}

// A genuinely missing home is stat_status "absent" (ENOENT), distinct from a
// denied one; root and an interactive user are interactive=true (the filter's
// positive half); a home on an nfs mount carries on_remote_fs=true (R191).
func TestFilesHomeDirsAbsentAndRemoteFS(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo_nfs"},
		dirs:  map[string]bool{"/root": true, "/home/alice": true},
		stats: map[string]statResult{
			"/root":       {mode: 0o700, uid: 0, gid: 0, kind: "dir"},
			"/home/alice": {mode: 0o755, uid: 1000, gid: 1000, kind: "dir"}, // on the nfs /home
		},
		// /home/bob is declared but present nowhere -> Stat returns ENOENT -> absent
	}
	rows := okList(t, build(t, "files", a), "files.home_dirs")
	byUser := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byUser[m["user"].(string)] = m
	}
	if byUser["root"]["interactive"] != true || byUser["alice"]["interactive"] != true {
		t.Error("root and alice have real login shells -> interactive=true")
	}
	if byUser["bob"]["stat_status"] != "absent" {
		t.Errorf("bob's missing home must be absent (ENOENT), not denied: %v", byUser["bob"])
	}
	if byUser["alice"]["on_remote_fs"] != true {
		t.Errorf("alice's home on nfs must be on_remote_fs=true: %v", byUser["alice"])
	}
}

// --- files: /root, /etc/hosts.equiv and the /dev walk (Task 3) ------------

// /dev holds device nodes; a regular file living on devtmpfs (or tmpfs at
// /dev) is a stale/planted file U-26 flags. A character/block device is not.
func TestFilesDevNonDevice(t *testing.T) {
	a := &fsAccess{
		// fsAccess.Glob scans the files+dirs maps (not stats), so the /dev
		// nodes must be present there for the walk to enumerate them (R188);
		// stats supplies each node's kind.
		files: map[string]string{
			"/proc/self/mountinfo": "mountinfo_dev", // /dev -> devtmpfs
			"/dev/null":            "",              // present so Glob("/dev/*") sees it
			"/dev/planted":         "",
		},
		dirs: map[string]bool{"/dev": true},
		stats: map[string]statResult{
			"/dev/null":    {mode: 0o666, kind: "chardev"},
			"/dev/planted": {mode: 0o644, kind: "regular"},
		},
	}
	b := build(t, "files", a)
	nd := okList(t, b, "files.dev_nondevice")
	if len(nd) != 1 || nd[0].(map[string]any)["name"] != "planted" {
		t.Fatalf("dev_nondevice %v, want just the regular file", nd)
	}
	all := okList(t, b, "files.dev_entries")
	if len(all) < 2 {
		t.Errorf("dev_entries should list every /dev node: %v", all)
	}
}

// R181: a regular file under a DEEPER mount than /dev (a POSIX-shm file on the
// /dev/shm tmpfs) is NOT dev_nondevice — that mount is a legitimate tmpfs, and
// flagging its files would false-fail U-26. It still appears in dev_entries.
func TestFilesDevExcludesDeeperMounts(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/proc/self/mountinfo": "mountinfo_dev", // /dev devtmpfs, /dev/shm tmpfs
			"/dev/planted":         "",              // regular file directly on /dev
			"/dev/shm/sem.thing":   "",              // regular file on the /dev/shm tmpfs
		},
		dirs: map[string]bool{"/dev": true, "/dev/shm": true},
		stats: map[string]statResult{
			"/dev/planted":       {mode: 0o644, kind: "regular"},
			"/dev/shm":           {mode: 0o1777, kind: "dir"},
			"/dev/shm/sem.thing": {mode: 0o644, kind: "regular"},
		},
	}
	b := build(t, "files", a)
	nd := okList(t, b, "files.dev_nondevice")
	if len(nd) != 1 || nd[0].(map[string]any)["path"] != "/dev/planted" {
		t.Fatalf("dev_nondevice %v, want only the file served exactly by /dev", nd)
	}
	// The /dev/shm file is still enumerated, just not flagged as a stray.
	var sawShm bool
	for _, e := range okList(t, b, "files.dev_entries") {
		if e.(map[string]any)["path"] == "/dev/shm/sem.thing" {
			sawShm = true
		}
	}
	if !sawShm {
		t.Error("dev_entries must still list the /dev/shm file (it is excluded only from dev_nondevice)")
	}
}

// /root permission facts come from stat only; a stat failure reaches all six
// leaves.
func TestFilesRootHome(t *testing.T) {
	a := &fsAccess{stats: map[string]statResult{"/root": {mode: 0o700, uid: 0, gid: 0, kind: "dir"}},
		files: map[string]string{"/proc/self/mountinfo": "mountinfo"}}
	b := build(t, "files", a)
	if env(t, b, "files.root_home.mode").Value != 0o700 {
		t.Errorf("root_home.mode %+v", env(t, b, "files.root_home.mode"))
	}
	if env(t, b, "files.root_home.other_writable").Value != false {
		t.Error("0700 /root is not other-writable")
	}
}

// A stat failure on /root reaches all six root_home leaves with the same
// envelope, so U-14 never compares a partial set (R176).
func TestFilesRootHomeDeniedReachesEveryLeaf(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/root": os.ErrPermission},
		files: map[string]string{"/proc/self/mountinfo": "mountinfo"},
	}
	b := build(t, "files", a)
	for _, k := range []string{"mode", "uid", "gid", "group_writable", "other_writable", "acl_present"} {
		if e := env(t, b, "files.root_home."+k); e.Status != facts.StatusDenied {
			t.Errorf("files.root_home.%s must be denied, not a quiet value: %+v", k, e)
		}
	}
}

// /etc/hosts.equiv non-comment lines are recorded; a file that does not exist
// (ENOENT) yields an OK empty line list — NOT absent (R177) — so U-27 passes
// vacuously rather than screening to absent_means.
func TestFilesHostsEquiv(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/hosts.equiv": "hosts_equiv", "/proc/self/mountinfo": "mountinfo"},
		stats: map[string]statResult{"/etc/hosts.equiv": {mode: 0o644, uid: 0, kind: "regular"}}}
	lines := okList(t, build(t, "files", a), "files.etc_hosts_equiv_lines")
	if len(lines) == 0 {
		t.Error("hosts.equiv non-comment lines must be recorded")
	}

	// No /etc/hosts.equiv at all: the lines key is an OK empty list, not absent.
	none := &fsAccess{files: map[string]string{"/proc/self/mountinfo": "mountinfo"}}
	nb := build(t, "files", none)
	e := env(t, nb, "files.etc_hosts_equiv_lines")
	if e.Status != facts.StatusOK {
		t.Fatalf("a missing hosts.equiv must leave etc_hosts_equiv_lines OK, got %+v", e)
	}
	if l, _ := e.Value.([]any); len(l) != 0 {
		t.Errorf("a missing hosts.equiv must yield [], got %v", e.Value)
	}
	// ...while the two perm leaves are absent in that case.
	if m := env(t, nb, "files.etc_hosts_equiv.mode"); m.Status != facts.StatusAbsent {
		t.Errorf("a missing hosts.equiv must leave mode absent, got %+v", m)
	}
}
