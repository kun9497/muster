//go:build linux

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// noopRun is a placeholder Collector.Run for tests that only exercise
// registration/declaration behaviour and never actually run the collector.
func noopRun(context.Context, Access, *Builder) error { return nil }

// fakeAccess implements all six Access methods (R46/R60); ReadFile, Stat,
// Llistxattr and Writable each record the path they were asked about so
// tests can assert on what actually reached the host.
type fakeAccess struct{ reads []string }

func (f *fakeAccess) ReadFile(p string, _ int64) ([]byte, ReadMeta, error) {
	f.reads = append(f.reads, p)
	return []byte("x"), ReadMeta{}, nil
}
func (f *fakeAccess) Stat(p string) (ReadMeta, error) {
	f.reads = append(f.reads, p)
	return ReadMeta{}, nil
}
func (f *fakeAccess) Glob(p string) ([]string, error) { return []string{p}, nil }
func (f *fakeAccess) Llistxattr(p string) ([]string, error) {
	f.reads = append(f.reads, p)
	return nil, nil
}
func (f *fakeAccess) Writable(p string) bool {
	f.reads = append(f.reads, p)
	return true
}
func (f *fakeAccess) Run(_ context.Context, c Command) Output { return Output{ExitCode: 0} }

func TestGuardRejectsUndeclaredAccess(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/login.defs", "/etc/ssh/sshd_config.d/*.conf"}, Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}}}}
	g := Guard(&fakeAccess{}, c)
	if _, _, err := g.ReadFile("/etc/login.defs", 10); err != nil {
		t.Error("declared read must pass")
	}
	if _, _, err := g.ReadFile("/etc/ssh/sshd_config.d/50-cloud-init.conf", 10); err != nil {
		t.Error("glob-declared read must pass")
	}
	if _, _, err := g.ReadFile("/etc/shadow", 10); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared read: err=%v", err)
	}
	if o := g.Run(context.Background(), Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}); o.Err != nil {
		t.Error("declared command must pass")
	}
	if o := g.Run(context.Background(), Command{Path: "/bin/sh", Args: []string{"-c", "id"}}); !errors.Is(o.Err, ErrUndeclared) {
		t.Errorf("undeclared command: %+v", o)
	}
	if len(g.violations) != 2 {
		t.Errorf("violations %v", g.violations)
	}
}

// R46/R60: Stat, Llistxattr and Writable are guarded exactly like ReadFile
// — matched against the declared Reads entries, and a refusal is recorded
// in Violations the same way.
func TestGuardTreatsStatLlistxattrWritableAsReads(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/login.defs"}}}
	g := Guard(&fakeAccess{}, c)

	if _, err := g.Stat("/etc/login.defs"); err != nil {
		t.Errorf("declared stat must pass: %v", err)
	}
	if _, err := g.Stat("/etc/shadow"); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared stat: err=%v", err)
	}
	if _, err := g.Llistxattr("/etc/login.defs"); err != nil {
		t.Errorf("declared llistxattr must pass: %v", err)
	}
	if _, err := g.Llistxattr("/etc/shadow"); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared llistxattr: err=%v", err)
	}
	if !g.Writable("/etc/login.defs") {
		t.Error("declared writable must pass")
	}
	if g.Writable("/etc/shadow") {
		t.Error("undeclared writable must be refused")
	}
	if len(g.Violations()) != 3 {
		t.Errorf("violations %v", g.Violations())
	}
}

// R55: Allowed answers the same declared-reads question as the guarded
// methods but never records a violation.
func TestAllowedDoesNotRecordViolation(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/login.defs"}}}
	g := Guard(&fakeAccess{}, c)
	if !g.Allowed("/etc/login.defs") {
		t.Error("declared path should be Allowed")
	}
	if g.Allowed("/etc/shadow") {
		t.Error("undeclared path should not be Allowed")
	}
	if len(g.Violations()) != 0 {
		t.Errorf("Allowed must not record violations: %v", g.Violations())
	}
}

// R65: allowedCommand requires the args to match exactly, not as a prefix.
func TestGuardCommandRequiresExactArgsNotPrefix(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}}}}
	g := Guard(&fakeAccess{}, c)
	if o := g.Run(context.Background(), Command{Path: "/usr/sbin/sshd", Args: []string{"-T", "-f", "x"}}); !errors.Is(o.Err, ErrUndeclared) {
		t.Errorf("sshd -T -f x must be refused when only \"sshd -T\" is declared: %+v", o)
	}
	if o := g.Run(context.Background(), Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}); o.Err != nil {
		t.Errorf("exact match must pass: %+v", o)
	}
}

// R72(a): allowedPath matches an unclean path against the declaration on
// its cleaned form, but every read-like guard method must go on to hand
// THAT cleaned form to inner, never the original string — otherwise a
// declaration for "/etc/login.defs" would authorise a request for
// "/etc/ssh/../login.defs" while handing the unclean original to inner,
// which (for hostAccess.Writable pre-fix, or any future Access
// implementation that isn't as careful as the read primitive) could
// resolve through whatever "/etc/ssh" happens to be instead of the
// declared file itself.
func TestGuardPassesCleanedPathToInnerForAllReadLikeMethods(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/login.defs"}}}
	const unclean = "/etc/ssh/../login.defs"
	const want = "/etc/login.defs"

	fa := &fakeAccess{}
	g := Guard(fa, c)
	if _, _, err := g.ReadFile(unclean, 10); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := g.Stat(unclean); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if _, err := g.Llistxattr(unclean); err != nil {
		t.Fatalf("Llistxattr: %v", err)
	}
	if !g.Writable(unclean) {
		t.Fatal("Writable must pass for the cleaned form")
	}
	if len(fa.reads) != 4 {
		t.Fatalf("inner saw %d calls, want 4: %v", len(fa.reads), fa.reads)
	}
	for _, got := range fa.reads {
		if got != want {
			t.Errorf("inner received %q, want the cleaned path %q", got, want)
		}
	}
}

// R72: Register rejects a Needs outside {root, none} and a nil Run, both
// programming errors caught at registration time.
func TestRegisterPanicsOnInvalidNeeds(t *testing.T) {
	Reset()
	defer Reset()
	defer func() {
		if recover() == nil {
			t.Error("expected panic for Needs outside {root, none}")
		}
	}()
	Register(Collector{Name: "x", Declare: Declaration{Needs: "sometimes"}, Run: noopRun})
}

func TestRegisterPanicsOnNilRun(t *testing.T) {
	Reset()
	defer Reset()
	defer func() {
		if recover() == nil {
			t.Error("expected panic for a nil Run")
		}
	}()
	Register(Collector{Name: "x", Declare: Declaration{Needs: "none"}})
}

func TestBuilderSetsEnvelopesAndSettingsByRegistryKey(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	b.Set("services.ssh.installed", OK(true, nil))
	b.SetSetting("sshd.options.permit_root_login", facts.Setting{Effective: &facts.Envelope{Status: facts.StatusOK, Value: "no"}})
	tree := b.Tree()
	svc := tree["services"].(map[string]any)["ssh"].(map[string]any)["installed"].(facts.Envelope)
	if svc.Value != true {
		t.Errorf("%+v", tree)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("unregistered key must panic")
			}
		}()
		b.Set("nope.key", OK(1, nil))
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("plain envelope on a setting key must panic")
			}
		}()
		b.Set("sshd.options.permit_root_login", OK("no", nil))
	}()
}

// R50: a nil []any or []string Value must serialise as "[]", not "null".
func TestBuilderNormalizesNilListsToEmptyArray(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	b.Set("files.etc_securetty_lines", OK([]string(nil), nil)) // list<string>
	b.Set("sockets.listening", OK([]any(nil), nil))            // list<record>

	raw, err := json.Marshal(b.Tree())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	lines := decoded["files"].(map[string]any)["etc_securetty_lines"].(map[string]any)
	if v, ok := lines["value"].([]any); !ok || len(v) != 0 {
		t.Errorf("etc_securetty_lines value = %#v (json %s), want []", lines["value"], raw)
	}
	listening := decoded["sockets"].(map[string]any)["listening"].(map[string]any)
	if v, ok := listening["value"].([]any); !ok || len(v) != 0 {
		t.Errorf("sockets.listening value = %#v (json %s), want []", listening["value"], raw)
	}
}

// injectSyntheticKeys pokes synthetic entries directly into reg's private
// index. There is no public constructor for a Registry with custom keys —
// facts.LoadRegistry only ever parses the embedded registry.yaml, and
// facts.Registry.byKey is unexported — so this reaches it via reflection,
// entirely within this test file, rather than adding a test-only
// constructor to internal/facts (out of Task 3's file list). It exists
// solely to test Builder.place's key-prefix-collision guard (item 8) with a
// pair of keys the real registry.yaml doesn't happen to contain: checked
// internal/facts/registry.go — LoadRegistry only rejects an exact duplicate
// key string, it never forbids one key's path being a dotted prefix of
// another's, so Builder.place is the only layer that can catch this.
func injectSyntheticKeys(t *testing.T, reg *facts.Registry, entries ...facts.Entry) {
	t.Helper()
	rv := reflect.ValueOf(reg).Elem().FieldByName("byKey")
	rv = reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem()
	m, ok := rv.Interface().(map[string]facts.Entry)
	if !ok {
		t.Fatalf("facts.Registry.byKey has unexpected type %v", rv.Type())
	}
	for _, e := range entries {
		m[e.Key] = e
	}
}

// item 8: setting a leaf then a key that descends past it must panic
// instead of silently replacing the leaf with an empty map.
func TestBuilderPlacePanicsOnLeafThenChildCollision(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	injectSyntheticKeys(t, reg,
		facts.Entry{Key: "synthetic.leaf", Type: "bool", Since: 1, Sensitivity: "public"},
		facts.Entry{Key: "synthetic.leaf.child", Type: "bool", Since: 1, Sensitivity: "public"},
	)
	b := NewBuilder(reg)
	b.Set("synthetic.leaf", OK(true, nil))
	defer func() {
		if recover() == nil {
			t.Error("expected panic: synthetic.leaf.child collides with the leaf already set at synthetic.leaf")
		}
	}()
	b.Set("synthetic.leaf.child", OK(true, nil))
}

// item 8, reverse direction: setting keys beneath a prefix and then setting
// the prefix itself as a leaf must also panic, not silently overwrite the
// map of children with a leaf.
func TestBuilderPlacePanicsOnChildThenLeafCollision(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	injectSyntheticKeys(t, reg,
		facts.Entry{Key: "synthetic2.leaf", Type: "bool", Since: 1, Sensitivity: "public"},
		facts.Entry{Key: "synthetic2.leaf.child", Type: "bool", Since: 1, Sensitivity: "public"},
	)
	b := NewBuilder(reg)
	b.Set("synthetic2.leaf.child", OK(true, nil))
	defer func() {
		if recover() == nil {
			t.Error("expected panic: synthetic2.leaf collides with keys already set beneath it")
		}
	}()
	b.Set("synthetic2.leaf", OK(true, nil))
}

// R71: Begin/Keys/Worst give a collector its own bookkeeping.
func TestBuilderPerCollectorBookkeeping(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)

	b.Begin("services")
	b.Set("services.ssh.installed", OK(true, nil))
	b.Set("services.ssh.active", Denied("requires root"))

	b.Begin("sshd")
	b.SetSetting("sshd.options.permit_root_login", facts.Setting{
		Runtime:   &facts.Envelope{Status: facts.StatusOK, Value: "no"},
		Persisted: &facts.Envelope{Status: facts.StatusError, Reason: "parse failed"},
	})

	if keys := b.Keys("services"); len(keys) != 2 || keys[0] != "services.ssh.active" || keys[1] != "services.ssh.installed" {
		t.Errorf("Keys(services) = %v", keys)
	}
	if got := b.Worst("services"); got != facts.StatusDenied {
		t.Errorf("Worst(services) = %v, want denied", got)
	}
	// The setting's persisted side errored even though runtime is ok: worst
	// counts each present side on its own.
	if got := b.Worst("sshd"); got != facts.StatusError {
		t.Errorf("Worst(sshd) = %v, want error", got)
	}
	if got := b.Worst("never-began"); got != facts.StatusOK {
		t.Errorf("Worst(no keys) = %v, want ok", got)
	}
}

// item 4: Keys deduplicates as well as sorts — a key set twice (e.g.
// corrected by a second Set call) appears once.
func TestBuilderKeysDeduplicates(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	b.Begin("services")
	b.Set("services.ssh.installed", OK(true, nil))
	b.Set("services.ssh.installed", OK(false, nil))
	if keys := b.Keys("services"); len(keys) != 1 || keys[0] != "services.ssh.installed" {
		t.Errorf("Keys(services) = %v, want exactly one entry", keys)
	}
}

// R71: absent and unsupported rank as ok, never worse.
func TestBuilderWorstRanksAbsentAndUnsupportedAsOK(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	b.Begin("files")
	b.Set("files.etc_securetty_lines", Absent("not present"))
	b.Set("files.etc_passwd.mode", Unsupported("no such mechanism"))
	if got := b.Worst("files"); got != facts.StatusOK {
		t.Errorf("Worst(files) = %v, want ok", got)
	}
}

// Self-consistency: Header returns the run header being assembled, created
// empty by NewBuilder.
func TestBuilderHeaderStartsEmpty(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	if b.Header() == nil {
		t.Fatal("Header() must not be nil")
	}
	if h := b.Header(); h.MusterVersion != "" || h.Commit != "" || len(h.Collectors) != 0 {
		t.Errorf("Header() should start empty, got %+v", h)
	}
}

func TestListActionsIncludesEveryDeclarationAndTheWrite(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "a", Declare: Declaration{Reads: []string{"/etc/passwd"}, Needs: "none"}, Run: noopRun})
	Register(Collector{Name: "b", Declare: Declaration{Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}}, Needs: "root"}, Run: noopRun})
	acts := ListActions()
	var kinds []string
	for _, a := range acts {
		kinds = append(kinds, a.Collector+":"+a.Kind+":"+a.Target)
	}
	joined := strings.Join(kinds, "\n")
	for _, want := range []string{"a:read:/etc/passwd", "b:command:/usr/sbin/sshd -T", "muster:write:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	var buf bytes.Buffer
	if err := WriteActions(&buf, acts, "json"); err != nil || !strings.Contains(buf.String(), `"kind": "command"`) {
		t.Errorf("json: %v %s", err, buf.String())
	}
}

// item 5: ListActions sorts by (collector, kind, target), independent of
// the order collectors were registered in or declared their reads/commands
// in.
func TestListActionsSortsByCollectorKindTarget(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "zzz", Declare: Declaration{Reads: []string{"/etc/z", "/etc/a"}, Needs: "none"}, Run: noopRun})
	Register(Collector{Name: "aaa", Declare: Declaration{Commands: []Command{{Path: "/usr/bin/y"}, {Path: "/usr/bin/b"}}, Needs: "none"}, Run: noopRun})

	acts := ListActions()
	for i := 1; i < len(acts); i++ {
		prev, cur := acts[i-1], acts[i]
		outOfOrder := prev.Collector > cur.Collector ||
			(prev.Collector == cur.Collector && prev.Kind > cur.Kind) ||
			(prev.Collector == cur.Collector && prev.Kind == cur.Kind && prev.Target > cur.Target)
		if outOfOrder {
			t.Fatalf("not sorted at index %d: %+v then %+v (full: %+v)", i, prev, cur, acts)
		}
	}
	if acts[0].Collector != "aaa" || acts[len(acts)-1].Collector != "zzz" {
		t.Errorf("unexpected boundary collectors: first=%q last=%q", acts[0].Collector, acts[len(acts)-1].Collector)
	}
}

// R40: the table lists the declared "/proc/self/..." form and appends the
// legend line only when it appears.
func TestWriteActionsAddsProcSelfLegendWhenDeclared(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "netstat", Declare: Declaration{Reads: []string{"/proc/self/net/tcp"}, Needs: "none"}, Run: noopRun})
	acts := ListActions()
	var buf bytes.Buffer
	if err := WriteActions(&buf, acts, "table"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "/proc/self/net/tcp") {
		t.Errorf("declared form missing: %s", out)
	}
	if !strings.Contains(out, "self = the collector's own pid") {
		t.Errorf("missing legend: %s", out)
	}
}

func TestWriteActionsOmitsLegendWithoutProcSelf(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "a", Declare: Declaration{Reads: []string{"/etc/passwd"}, Needs: "none"}, Run: noopRun})
	acts := ListActions()
	var buf bytes.Buffer
	if err := WriteActions(&buf, acts, "table"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "self =") {
		t.Errorf("unexpected legend: %s", buf.String())
	}
}

// item 7: an unknown format is rejected rather than silently falling back
// to the table renderer.
func TestWriteActionsRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteActions(&buf, nil, "yaml"); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func errNoEnt() error  { return unix.ENOENT }
func errAccess() error { return unix.EACCES }

// os/fs-sentinel-wrapped equivalents: R42 requires both a raw syscall.Errno
// and an os/fs sentinel to classify.
func errNoEntOS() error  { return fmt.Errorf("stat /etc/x: %w", os.ErrNotExist) }
func errAccessOS() error { return fmt.Errorf("open /etc/x: %w", os.ErrPermission) }
func errNotDirErrno() error {
	return fmt.Errorf("%s: %w", "/etc/passwd/x", unix.ENOTDIR)
}

func TestFromReadErrorMapsStatuses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want facts.Status
	}{
		{"ENOENT errno", errNoEnt(), facts.StatusAbsent},
		{"fs.ErrNotExist sentinel", errNoEntOS(), facts.StatusAbsent},
		{"ENOTDIR errno", errNotDirErrno(), facts.StatusAbsent},
		{"EACCES errno", errAccess(), facts.StatusDenied},
		{"fs.ErrPermission sentinel", errAccessOS(), facts.StatusDenied},
		{"ErrSymlink", ErrSymlink, facts.StatusError},
		{"ErrNotRegular", ErrNotRegular, facts.StatusError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := FromReadError(c.err, ReadMeta{})
			if e.Status != c.want {
				t.Errorf("FromReadError(%v) status = %v, want %v", c.err, e.Status, c.want)
			}
			if c.want == facts.StatusDenied && e.Reason == "" {
				t.Errorf("denied envelope missing reason")
			}
		})
	}
}

// R70: OKRead carries the truncation flag; FromReadError no longer does.
func TestOKReadSetsTruncated(t *testing.T) {
	e := OKRead("partial content", nil, ReadMeta{Truncated: true})
	if e.Status != facts.StatusOK || !e.Truncated || e.Value != "partial content" {
		t.Errorf("%+v", e)
	}
	e2 := OKRead("full content", nil, ReadMeta{Truncated: false})
	if e2.Status != facts.StatusOK || e2.Truncated {
		t.Errorf("%+v", e2)
	}
}

// Real-host test (run on the lab host, not in t.TempDir): /proc/self is a
// magic link the read primitive refuses outright, so hostAccess must
// rewrite it to the real pid before calling the primitive (R40). The
// collector declares and requests the "/proc/self/..." form; the guard
// matches that declared form and records no violation.
func TestHostAccessResolvesProcSelf(t *testing.T) {
	c := Collector{Name: "self", Declare: Declaration{Reads: []string{"/proc/self/status"}}}
	g := Guard(hostAccess{}, c)
	data, _, err := g.ReadFile("/proc/self/status", 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Pid:") {
		t.Errorf("expected Pid: in %q", data)
	}
	if len(g.Violations()) != 0 {
		t.Errorf("violations: %v", g.Violations())
	}
}

// Real-host test: Llistxattr must refuse a symlink the same way ReadFile
// does, never resolving it via unix.Llistxattr on the path.
func TestHostAccessLlistxattrDoesNotFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	mkfile(t, target, "x", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	c := Collector{Name: "x", Declare: Declaration{Reads: []string{link}}}
	g := Guard(hostAccess{}, c)
	if _, err := g.Llistxattr(link); !errors.Is(err, ErrSymlink) {
		t.Errorf("expected ErrSymlink, got %v", err)
	}
}

// R72(b): a non-absolute or unclean path is refused outright, with no probe
// against the host at all — proven here by using a path that, if the
// unclean/relative check were skipped and the file were probed instead,
// would come back writable (root, existing, mode 0644 file): the unclean
// form must still report false.
func TestHostAccessWritableRejectsUncleanOrRelativePath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	mkfile(t, target, "x", 0o644)
	cases := []string{
		dir + "/./f",    // unclean: contains a "." component
		"relative/path", // not absolute
	}
	for _, p := range cases {
		if (hostAccess{}).Writable(p) {
			t.Errorf("Writable(%q) = true, want false (unclean/relative, no probe)", p)
		}
	}
}

// R72(b): a plain writable file reports true, as root.
func TestHostAccessWritableTrueForWritableFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	mkfile(t, target, "x", 0o644)
	if !(hostAccess{}).Writable(target) {
		t.Errorf("expected Writable(%q) = true", target)
	}
}

// R72(b): a symlink target is refused, never resolved — hostAccess.Writable
// goes through the same no-follow primitive ReadFile/Stat use
// (openNoFollow), not unix.Access, which would happily follow it.
func TestHostAccessWritableRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	mkfile(t, target, "x", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if (hostAccess{}).Writable(link) {
		t.Error("Writable on a symlink must be refused, not resolved")
	}
}
