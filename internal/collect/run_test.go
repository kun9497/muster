//go:build linux

package collect

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// quietAccess answers "nothing here" to every access, so a Run test
// exercises the orchestration and never the host.
type quietAccess struct{}

func (quietAccess) ReadFile(string, int64) ([]byte, ReadMeta, error) {
	return nil, ReadMeta{}, os.ErrNotExist
}
func (quietAccess) Stat(string) (ReadMeta, error)       { return ReadMeta{}, os.ErrNotExist }
func (quietAccess) Glob(string) ([]string, error)       { return nil, nil }
func (quietAccess) Llistxattr(string) ([]string, error) { return nil, nil }
func (quietAccess) Getxattr(string, string) ([]byte, error) {
	return nil, unix.ENODATA
}
func (quietAccess) Writable(string) bool { return false }
func (quietAccess) Run(context.Context, Command) Output {
	return Output{ExitCode: 127, Err: os.ErrNotExist}
}

// capAccess serves one canned /proc/self/status and nothing else.
type capAccess struct {
	quietAccess
	status string
}

func (a capAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	if p == procSelfStatus {
		return []byte(a.status), ReadMeta{}, nil
	}
	return a.quietAccess.ReadFile(p, limit)
}

func TestRunWritesSnapshotWithHeaderAndCollectorLog(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "good", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("services.ssh.installed", OK(true, nil))
		return nil
	}})
	Register(Collector{Name: "bad", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		return errors.New("boom")
	}})
	Register(Collector{Name: "skip", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error { return ErrSkipped }})
	Register(Collector{Name: "panics", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error { panic("x") }})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{},
		Version: "0.1.0", Commit: "abc", ControlsVersion: "cv", ControlsDigest: "sha256:cd",
		Now: func() time.Time { return time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC) }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete {
		t.Error("a failing collector must make the run partial")
	}
	if strings.Join(out.Partial, ",") != "bad,panics" {
		t.Errorf("partial %v", out.Partial)
	}
	f, _ := os.Open(out.Path)
	defer f.Close()
	snap, err := facts.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != facts.SchemaVersion || snap.Run.CollectedAt != "2026-09-02T06:00:00Z" || snap.Run.GuideEdition != "kisa-unix-2026" || snap.Run.ControlsDigest != "sha256:cd" {
		t.Errorf("header %+v", snap.Run)
	}
	if snap.Run.MusterVersion != "0.1.0" || snap.Run.Commit != "abc" || snap.Run.ControlsVersion != "cv" {
		t.Errorf("versions %+v", snap.Run)
	}
	// R52: stage 1 stores no original secret, so the profile is always
	// "default" and include_secrets always false. R47/R76: --deep is
	// accepted by the command but the walk is stage 3, so deep stays false.
	if r := snap.Run.Redaction; r.Profile != "default" || r.IncludeSecrets || len(r.RedactedFields) != 0 || snap.Run.Deep {
		t.Errorf("redaction %+v deep %v", r, snap.Run.Deep)
	}
	statuses := map[string]string{}
	for _, c := range snap.Run.Collectors {
		statuses[c.Name] = c.Status
	}
	if statuses["good"] != "ok" || statuses["bad"] != "error" || statuses["skip"] != "skipped" || statuses["panics"] != "error" {
		t.Errorf("collector log %v", statuses)
	}
	reg, _ := facts.LoadRegistry()
	if r, _ := reg.Resolve(snap, "services.ssh.installed"); r.Envelope.Value != true {
		t.Errorf("fact lost: %+v", r)
	}
}

// R66: a collector that declares a command records it in the run header, so
// a reader of the snapshot sees which invocation produced the facts.
func TestRunRecordsTheDeclaredCommand(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "withcmd", Declare: Declaration{
		Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}},
		Needs:    "none",
	}, Run: func(ctx context.Context, a Access, b *Builder) error { return nil }})
	Register(Collector{Name: "nocmd", Declare: Declaration{Needs: "none"},
		Run: func(ctx context.Context, a Access, b *Builder) error { return nil }})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmds := map[string]string{}
	for _, c := range out.Header.Collectors {
		cmds[c.Name] = c.Cmd
	}
	if cmds["withcmd"] != "/usr/sbin/sshd -T" || cmds["nocmd"] != "" {
		t.Errorf("cmd %v", cmds)
	}
}

// collectorRun finds one collector's entry in the run header. The registry
// always carries the built-in "muster" collector (R60), so a test that
// registered one collector still sees more than one entry.
func collectorRun(t *testing.T, out Outcome, name string) facts.CollectorRun {
	t.Helper()
	for _, c := range out.Header.Collectors {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("collector %s is missing from the run header: %+v", name, out.Header.Collectors)
	return facts.CollectorRun{}
}

func TestRunDeniedFactMakesPartial(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "one", Declare: Declaration{Needs: "root"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("files.etc_passwd.mode", Denied("requires root"))
		b.Set("files.etc_passwd.uid", OK(0, nil))
		return nil
	}})
	Register(Collector{Name: "two", Declare: Declaration{Needs: "root"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("files.etc_passwd.gid", Denied("requires root"))
		b.Set("services.ssh.installed", Denied("requires root"))
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil || out.Complete {
		t.Fatalf("%+v %v", out, err)
	}
	// R56/R71: the collector returned nil, so its status is the worst
	// status among the facts it wrote — denied, not ok. Spec §7.1 wants a
	// reason with it, and "denied" alone does not say which fact was.
	one := collectorRun(t, out, "one")
	if one.Status != "denied" || one.Reason != "facts with status denied: files.etc_passwd.mode" {
		t.Errorf("collector log %+v", one)
	}
	// The ok fact must not be counted, and the second denial of the
	// collector that has two must be.
	two := collectorRun(t, out, "two")
	if two.Status != "denied" || two.Reason != "facts with status denied: files.etc_passwd.gid (+1 more)" {
		t.Errorf("collector log %+v", two)
	}
	if strings.Join(out.Partial, ",") != "one,two" {
		t.Errorf("partial %v", out.Partial)
	}
	if ExitCodeFor(out, nil, false) != 1 || ExitCodeFor(out, nil, true) != 2 || ExitCodeFor(out, errors.New("x"), false) != 2 {
		t.Error("exit code mapping")
	}
}

// A collector that runs past the global deadline is a timeout, its own
// error text is kept, and the snapshot is still written with everything
// that did succeed.
func TestRunGlobalDeadlineMakesTimeout(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "slow", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		<-ctx.Done()
		return ctx.Err()
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Timeout: 50 * time.Millisecond, Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	slow := collectorRun(t, out, "slow")
	if slow.Status != "timeout" || !strings.Contains(slow.Reason, "global deadline exceeded") || !strings.Contains(slow.Reason, "collector reported: context deadline exceeded") {
		t.Errorf("collector log %+v", slow)
	}
	if out.Complete || strings.Join(out.Partial, ",") != "slow" {
		t.Errorf("%+v", out)
	}
	if _, statErr := os.Stat(out.Path); statErr != nil {
		t.Errorf("the snapshot must still be written: %v", statErr)
	}
}

// Once the deadline has passed, the collectors that never started say so
// rather than being run to completion and labelled as if they had hung —
// reads and commands are not all ctx-aware.
func TestRunSkipsCollectorsAfterTheDeadline(t *testing.T) {
	Reset()
	defer Reset()
	ran := 0
	Register(Collector{Name: "a_eats_the_budget", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		<-ctx.Done()
		return nil
	}})
	Register(Collector{Name: "b_never_starts", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		ran++
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Timeout: 50 * time.Millisecond, Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ran != 0 {
		t.Errorf("the collector after the deadline ran %d times", ran)
	}
	never := collectorRun(t, out, "b_never_starts")
	if never.Status != "timeout" || never.Reason != "deadline expired before this collector started" || never.Ms != 0 {
		t.Errorf("collector log %+v", never)
	}
}

func TestRunCompleteRunExitsZero(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "ok", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("services.ssh.installed", OK(true, nil))
		return nil
	}})
	Register(Collector{Name: "skip", Declare: Declaration{Needs: "none"},
		Run: func(ctx context.Context, a Access, b *Builder) error { return ErrSkipped }})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A skipped collector is not a failure: complete stays true.
	if !out.Complete || len(out.Partial) != 0 {
		t.Errorf("%+v", out)
	}
	if ExitCodeFor(out, nil, true) != 0 {
		t.Error("a complete run must exit 0 even with --require-complete")
	}
}

// R88: sshd -T being unavailable for a reason other than privilege (a fresh
// or socket-activated sshd that has never created /run/sshd, say) is a
// parse-fallback degradation, not a failed collector — the setting's
// runtime side is absent while its persisted/effective sides stay ok. This
// reproduces that outcome's shape with a synthetic collector (the existing
// quietAccess double; no host access needed) and proves that a run built on
// it is complete, the way the real sshd collector's now is.
func TestRunAbsentSshdTKeepsTheRunComplete(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "sshd", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		runtime := Absent("sshd -T unavailable: Missing privilege separation directory: /run/sshd")
		persisted := OK("yes", nil)
		effective := OK("yes", nil)
		effective.Reason = "parsed files; sshd -T unavailable"
		b.SetSetting("sshd.options.permit_root_login", facts.Setting{
			Runtime: &runtime, Persisted: &persisted, Effective: &effective,
		})
		b.Set("sshd.collect_method", OK("parse", nil))
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sshd := collectorRun(t, out, "sshd")
	if sshd.Status != "ok" {
		t.Errorf("collector log %+v, want ok: an absent runtime side must not fail the collector", sshd)
	}
	if !out.Complete || len(out.Partial) != 0 {
		t.Errorf("%+v, want a complete run built on this sshd outcome", out)
	}
	if ExitCodeFor(out, nil, true) != 0 {
		t.Error("--require-complete must exit 0 on this outcome")
	}
}

func TestRunRequireRootRefusesWithoutWriting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	Reset()
	defer Reset()
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	_, err := Run(context.Background(), Options{Out: p, RequireRoot: true, Access: quietAccess{}}, nil)
	if !errors.Is(err, ErrNotRoot) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("nothing may be written when --require-root fails")
	}
}

func TestRunGuardViolationIsRecorded(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "sneaky", Declare: Declaration{Reads: []string{"/etc/hostname"}, Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		a.ReadFile("/etc/shadow", 10)
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil || out.Complete || strings.Join(out.Partial, ",") != "sneaky" {
		t.Fatalf("%+v %v", out, err)
	}
	// The violation is reported as an error whose reason names the access,
	// so the snapshot says what the collector reached for.
	c := collectorRun(t, out, "sneaky")
	if c.Status != "error" || !strings.Contains(c.Reason, "/etc/shadow") {
		t.Errorf("collector log %+v", c)
	}
}

// A collector that panics AND reaches outside its declaration reports both:
// the panic is why it stopped, the violation is what it tried.
func TestRunKeepsPanicTextBesideAViolation(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "both", Declare: Declaration{Reads: []string{"/etc/hostname"}, Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		a.ReadFile("/etc/shadow", 10)
		panic("x")
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := collectorRun(t, out, "both")
	if c.Status != "error" || !strings.Contains(c.Reason, "panic: x") || !strings.Contains(c.Reason, "/etc/shadow") {
		t.Errorf("collector log %+v", c)
	}
}

// R60: Reset is for tests, but the built-in pseudo-collector belongs to
// every run — a registry without it silently drops the header's privilege
// block, so Reset puts it back.
func TestResetKeepsTheBuiltInCollector(t *testing.T) {
	Reset()
	defer Reset()
	var names []string
	for _, c := range All() {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "muster" {
		t.Errorf("registry after Reset: %v", names)
	}
}

// R44/R73: an explicit --out path locks the destination DIRECTORY, so a
// second collect writing beside the first is refused and writes nothing.
func TestRunOutPathLocksItsDirectory(t *testing.T) {
	Reset()
	defer Reset()
	dir := t.TempDir()
	held, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	p := filepath.Join(dir, "s.json")
	_, err = Run(context.Background(), Options{Out: p, Access: quietAccess{}}, nil)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("nothing may be written when the destination is locked")
	}
}

// R44: --out - writes to a pipe, so there is no destination to guard and no
// lock is taken — a held lock file does not stop it.
func TestRunToStdoutTakesNoLock(t *testing.T) {
	Reset()
	defer Reset()
	var buf bytes.Buffer
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".lock")
	held, err := AcquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	out, err := Run(context.Background(), Options{Out: "-", LockPath: lockPath, Access: quietAccess{}}, &buf)
	if err != nil || out.Path != "-" || !strings.HasPrefix(buf.String(), "{") {
		t.Fatalf("%+v %v %q", out, err, buf.String())
	}
	if !strings.HasSuffix(buf.String(), "}\n") {
		t.Error("the snapshot written to stdout must end with a newline")
	}
}

// R44/R73: the default destination is the shared snapshot directory, so
// that run takes the lock file, and a second one is refused.
func TestRunDefaultDestinationTakesTheLockFile(t *testing.T) {
	Reset()
	defer Reset()
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".lock")
	held, err := AcquireLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	// Out is empty: the default lifecycle, which is what LockPath guards.
	// The lock is refused before anything is collected or written, so this
	// never reaches the default snapshot directory.
	_, err = Run(context.Background(), Options{LockPath: lockPath, Access: quietAccess{}}, nil)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err=%v", err)
	}
}

// M12. When no collector filled the header's hostname, the fallback comes
// from uname(2) — a plain syscall — rather than os.Hostname(), which reads
// /proc/sys/kernel/hostname: a path no collector declares, that the guard
// never sees and the no-follow read primitive never opened. Reset leaves
// only the muster pseudo-collector, which fills no host block, so this run
// takes the fallback.
func TestRunFallbackHostnameComesFromUname(t *testing.T) {
	Reset()
	defer Reset()
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}
	want := string(bytes.TrimRight(u.Nodename[:], "\x00"))
	if want == "" {
		t.Skip("this kernel reports no nodename")
	}
	if got := unameNodename(); got != want {
		t.Errorf("unameNodename() = %q, want %q", got, want)
	}
	out, err := Run(context.Background(), Options{Out: filepath.Join(t.TempDir(), "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Header.Host.Hostname != want {
		t.Errorf("hostname %q, want the uname nodename %q", out.Header.Host.Hostname, want)
	}
}

// R53/R60: capabilities come from a fixed, sorted table plus the raw mask,
// and are never nil — the header field has no omitempty and "null" would be
// a third meaning next to "none" and "some".
func TestCapabilitiesDecodeInTableOrder(t *testing.T) {
	// 0x200004 = CAP_DAC_READ_SEARCH (bit 2) | CAP_SYS_ADMIN (bit 21).
	got := capabilities(capAccess{status: "Name:\tmuster\nCapEff:\t0000000000200004\n"})
	if strings.Join(got, ",") != "CAP_DAC_READ_SEARCH,CAP_SYS_ADMIN,raw:0000000000200004" {
		t.Errorf("capabilities %v", got)
	}
	if got := capabilities(quietAccess{}); got == nil || len(got) != 0 {
		t.Errorf("an unreadable status file must give an empty list, got %#v", got)
	}
	if got := capabilities(capAccess{status: "Name:\tmuster\n"}); got == nil || len(got) != 0 {
		t.Errorf("a status file without CapEff must give an empty list, got %#v", got)
	}
	if got := capabilities(capAccess{status: "CapEff:\tnothex\n"}); strings.Join(got, ",") != "raw:nothex" {
		t.Errorf("an undecodable mask must still be recorded raw, got %v", got)
	}
}

// R60: the read of /proc/self/status is a registered collector like any
// other — declared, guarded and listed by --list-actions. Its Run is
// exercised directly rather than through the registry because the registry
// tests reset it and the suite runs shuffled.
func TestMusterCollectorFillsEUIDAndCapabilities(t *testing.T) {
	if reads := musterCollector.Declare.Reads; len(reads) != 1 || reads[0] != procSelfStatus {
		t.Fatalf("declaration %+v", musterCollector.Declare)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := NewBuilder(reg)
	g := Guard(capAccess{status: "CapEff:\t0000000000000004\n"}, musterCollector)
	if err := musterCollector.Run(context.Background(), g, b); err != nil {
		t.Fatal(err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Errorf("the pseudo-collector must stay inside its declaration: %v", v)
	}
	if strings.Join(b.Header().Capabilities, ",") != "CAP_DAC_READ_SEARCH,raw:0000000000000004" {
		t.Errorf("capabilities %v", b.Header().Capabilities)
	}
	if b.Header().EUID != os.Geteuid() {
		t.Errorf("euid %d, want %d", b.Header().EUID, os.Geteuid())
	}
}

// M-15 (J-7): run.redaction.redacted_fields names the registered secret keys
// this run actually stored — in reduced form, since nothing stores an
// original secret (R52). A secret key the run did not fill with a value
// (here snmp.v3_users, absent because no snmpd configuration was found) is
// not listed: the field is the set of values that were reduced, not the set
// of keys that could carry one. The no-secret case is pinned in
// TestRunWritesSnapshotWithHeaderAndCollectorLog, where the list is empty and
// omitempty keeps the field out of the JSON entirely.
func TestRunRecordsRedactedFields(t *testing.T) {
	Reset()
	defer Reset()
	Register(Collector{Name: "snmp", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("snmp.communities", OK([]any{map[string]any{"ref": "c1", "length": 6}}, nil))
		b.Set("snmp.v3_users", Absent("no snmpd configuration was found"))
		// A public key a collector set is never redaction evidence.
		b.Set("snmp.parse_complete", OK(true, nil))
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), Access: quietAccess{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := out.Header.Redaction
	if len(r.RedactedFields) != 1 || r.RedactedFields[0] != "snmp.communities" {
		t.Errorf("redacted_fields %v, want just the secret key that was stored", r.RedactedFields)
	}
	// R52: the profile and the flag are unchanged by any of this.
	if r.Profile != "default" || r.IncludeSecrets {
		t.Errorf("redaction %+v", r)
	}
	// T-4: the header D13 promises is the one in the FILE. The in-memory
	// value above is set before the snapshot is marshalled, so it alone would
	// stay green if the field were filled after the encode, or if its JSON
	// name or omitempty ever changed.
	f, err := os.Open(out.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	snap, err := facts.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"snmp.communities"}; !reflect.DeepEqual(snap.Run.Redaction.RedactedFields, want) {
		t.Errorf("the written snapshot says redacted_fields %v, wanted %v", snap.Run.Redaction.RedactedFields, want)
	}
}
