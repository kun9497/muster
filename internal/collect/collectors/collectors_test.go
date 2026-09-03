//go:build linux

package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	if err, ok := a.fails[p]; ok {
		return collect.ReadMeta{}, err
	}
	if s, ok := a.stats[p]; ok {
		return collect.ReadMeta{Tier: "openat2", Mode: s.mode, UID: s.uid, GID: s.gid, Kind: s.kind}, nil
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

// R88 (spec §6.5 step 13): a non-zero sshd -T exit that is not a privilege
// failure is a parse-fallback degradation, not a failed collector — the
// runtime side is absent (not error), naming the command as its source and
// carrying the first stderr line in its reason; the method is "parse"
// because -T did not answer, cited to the command that ran and failed; and
// the collector's own status stays ok, so a run built on this outcome is
// complete.
func TestSshdNonZeroExitIsAnAbsentRuntimeSide(t *testing.T) {
	// R84: this test's expectation (absent, not denied) is the root-side
	// outcome of commandFailure's privilege rule, so the seam must be
	// pinned to root rather than left to whichever account runs the suite.
	withEUID(t, 0)
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {
			exitCode: 255,
			stderr:   "Missing privilege separation directory: /run/sshd\nsecond line\n",
		}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Status != facts.StatusAbsent {
		t.Fatalf("runtime %+v", s.Runtime)
	}
	if !strings.HasPrefix(s.Runtime.Reason, "sshd -T unavailable: ") ||
		!strings.Contains(s.Runtime.Reason, "Missing privilege separation directory: /run/sshd") {
		t.Errorf("reason must name the degradation and carry the first stderr line: %q", s.Runtime.Reason)
	}
	if s.Runtime.Source == nil || s.Runtime.Source.Cmd != "/usr/sbin/sshd -T" {
		t.Errorf("source %+v", s.Runtime.Source)
	}
	if m := env(t, b, "sshd.collect_method"); m.Value != "parse" || m.Source == nil || m.Source.Cmd != "/usr/sbin/sshd -T" {
		t.Errorf("method must be parse, cited to the command that ran and failed: %+v", m)
	}
	if s.Effective.Status != facts.StatusOK || s.Effective.Value != "yes" || !strings.Contains(s.Effective.Reason, "sshd -T unavailable") {
		t.Errorf("effective must fall back to the ok persisted value: %+v", s.Effective)
	}
	// Absent ranks as ok in Builder.Worst (R71), so this failure must not
	// make the sshd collector itself worse than ok — which is what keeps a
	// run built on this outcome complete (see TestRunAbsentSshdTKeepsTheRunComplete).
	if worst := b.Worst("sshd"); worst != facts.StatusOK {
		t.Errorf("Worst(sshd) = %s, want ok", worst)
	}
}

func TestSshdPermissionDeniedIsDeniedAndCopiedToEffective(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/ssh/sshd_config": os.ErrPermission},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {
			exitCode: 1,
			stderr:   "/etc/ssh/sshd_config: Permission denied\n",
		}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Status != facts.StatusDenied {
		t.Fatalf("runtime %+v", s.Runtime)
	}
	// R59: a non-ok persisted side is copied to effective unchanged, so the
	// reason still says why there is no value.
	if s.Persisted.Status != facts.StatusDenied || s.Effective.Status != facts.StatusDenied || s.Effective.Reason != s.Persisted.Reason {
		t.Errorf("persisted %+v effective %+v", s.Persisted, s.Effective)
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

// I3 (R84). sshd -T run by a non-root process fails with "Could not load
// host key" or "no hostkeys available" — never "Permission denied" — so the
// substring rule on its own files a privilege problem as an error, and the
// run header then says "facts with status error" where spec §7.1/D25 wants
// denied with the privilege named. A root-only collector's failed command
// is denied whenever this process is not root; as root the same failure is
// R88's parse-fallback degradation instead (absent, not error) — commandFailure
// itself is unchanged, sshd.go only turns its error outcome into absent.
func TestRootOnlyCommandFailureIsDeniedForANonRootProcess(t *testing.T) {
	for _, tc := range []struct {
		name string
		euid int
		want facts.Status
	}{
		{"non-root", 1000, facts.StatusDenied},
		{"root", 0, facts.StatusAbsent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withEUID(t, tc.euid)
			a := &fsAccess{
				files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
				cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {
					exitCode: 255,
					stderr:   "sshd: no hostkeys available -- exiting.\n",
				}},
			}
			s := setting(t, build(t, "sshd", a), "sshd.options.permit_root_login")
			if s.Runtime == nil || s.Runtime.Status != tc.want {
				t.Fatalf("runtime %+v, want %s", s.Runtime, tc.want)
			}
			switch tc.want {
			case facts.StatusDenied:
				if want := "sshd -T requires root: sshd: no hostkeys available -- exiting."; s.Runtime.Reason != want {
					t.Errorf("reason %q, want %q", s.Runtime.Reason, want)
				}
			case facts.StatusAbsent:
				if want := "sshd -T unavailable: sshd: no hostkeys available -- exiting."; s.Runtime.Reason != want {
					t.Errorf("reason %q, want %q", s.Runtime.Reason, want)
				}
			}
			if s.Runtime.Source == nil || s.Runtime.Source.Cmd != "/usr/sbin/sshd -T" {
				t.Errorf("source %+v", s.Runtime.Source)
			}
		})
	}
}

// ...and a collector that does NOT need root keeps the old rule whatever
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

func TestOSFillsTheRunHeader(t *testing.T) {
	b := build(t, "os", osAccess())
	if len(b.Tree()) != 0 {
		t.Errorf("os writes no fact keys, got %v", b.Tree())
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
	a := osAccess()
	a.dirs["/.dockerenv"] = true
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
