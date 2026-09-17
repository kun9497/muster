//go:build linux

package collectors

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
)

// This file holds one fuzz target per parser entry point (spec §3, F-5). A
// target asserts three properties and nothing about meaning:
//
//   - no panic — the fuzzer's own rule;
//   - determinism — the parser is called twice on the same bytes and the two
//     results must be identical (fuzzBody);
//   - bounded output — no list the parser returns is longer than the input
//     plus a small constant, and no evidence line it stores is longer than
//     the cap the collector promised (fuzzBody again).
//
// The seed corpus is the fixtures the ordinary unit tests already read, named
// by glob; `go test` runs every seed as a unit test, which is the
// pull-request regression. The nightly workflow does the fuzzing (F-7).
//
// TestEveryParserHasAFuzzTarget in fuzz_inventory_test.go fails when a parser
// in this package has neither a target here nor a row of its coveredThrough
// table, so a new parser cannot arrive unfuzzed.

// ---------------------------------------------------------------------------
// memAccess — the in-memory Access the sshd_config target parses through
// ---------------------------------------------------------------------------

// memAccess serves a fixed map of path to content and nothing else: it is the
// smallest Access parseSshdConfig can recurse through, so an Include that
// names the file serving it exercises the include loop without any host read.
// It has no Allowed method, so `declared` licenses every pattern — what is
// under test here is the parser, not the guard.
type memAccess struct {
	// NoWalkAccess answers ReadDir/Readlink with ErrNoWalk: nothing that
	// parses through this double walks a tree.
	collect.NoWalkAccess

	files map[string][]byte
}

// errNoCommand is what memAccess answers Run with: a parser that reached for
// a command through this double is doing something a fuzz target cannot
// model, and the error says so rather than pretending the command ran.
var errNoCommand = errors.New("memAccess runs no command")

func memMeta(data []byte) collect.ReadMeta {
	return collect.ReadMeta{Tier: "componentwise", Size: int64(len(data)), Kind: "regular", Mode: 0o644}
}

// ReadFile honours limit the way the host primitive does: the read stops
// there and the meta says it was cut, while Size stays the file's real size.
// Without that, the truncated branch every caller has — parseSshdConfig
// stores meta on the envelope it returns — would be unreachable through this
// double whatever the fuzzer produced.
func (m *memAccess) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	data, ok := m.files[p]
	if !ok {
		return nil, collect.ReadMeta{}, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	meta := memMeta(data)
	if limit > 0 && int64(len(data)) > limit {
		data = data[:limit]
		meta.Truncated = true
	}
	return data, meta, nil
}

func (m *memAccess) Stat(p string) (collect.ReadMeta, error) {
	data, ok := m.files[p]
	if !ok {
		return collect.ReadMeta{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
	}
	return memMeta(data), nil
}

// Glob matches the map's keys with path.Match, the same shell semantics the
// host primitive has: a "*" never crosses a "/". The result is sorted, so a
// caller that expands an Include sees the same order every run.
func (m *memAccess) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range m.files {
		ok, err := path.Match(pattern, p)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (m *memAccess) Llistxattr(string) ([]string, error) { return nil, nil }

func (m *memAccess) Getxattr(string, string) ([]byte, error) {
	return nil, errors.New("memAccess has no extended attributes")
}

func (m *memAccess) Run(context.Context, collect.Command) collect.Output {
	return collect.Output{ExitCode: -1, Err: errNoCommand}
}

func (m *memAccess) Writable(string) bool { return false }

func TestMemAccess(t *testing.T) {
	a := &memAccess{files: map[string][]byte{
		"/etc/ssh/sshd_config":                 []byte("PermitRootLogin no\n"),
		"/etc/ssh/sshd_config.d/00-fuzz.conf":  []byte("Banner /etc/issue.net\n"),
		"/etc/ssh/sshd_config.d/10-other.conf": []byte("MaxAuthTries 3\n"),
	}}

	data, meta, err := a.ReadFile("/etc/ssh/sshd_config", readLimit)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "PermitRootLogin no\n" {
		t.Errorf("ReadFile returned %q", data)
	}
	if meta.Kind != "regular" || meta.Size != int64(len(data)) {
		t.Errorf("ReadFile meta = %+v, want a regular file of %d bytes", meta, len(data))
	}

	if _, err := a.Stat("/etc/ssh/sshd_config.d/00-fuzz.conf"); err != nil {
		t.Errorf("Stat of a served path: %v", err)
	}

	// A limit below the file's size cuts the read and says so, while Size
	// stays the size the file really has.
	short, meta, err := a.ReadFile("/etc/ssh/sshd_config", 4)
	if err != nil {
		t.Fatalf("ReadFile with a limit: %v", err)
	}
	if string(short) != "Perm" {
		t.Errorf("ReadFile with limit 4 returned %q, want the first four bytes", short)
	}
	if !meta.Truncated {
		t.Error("ReadFile with a limit below the size did not report Truncated")
	}
	if meta.Size != int64(len(data)) {
		t.Errorf("a truncated read reported Size %d, want the file's %d", meta.Size, len(data))
	}
	if _, _, err := a.ReadFile("/etc/shadow", readLimit); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of an unserved path = %v, want fs.ErrNotExist", err)
	}
	if _, err := a.Stat("/etc/shadow"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat of an unserved path = %v, want fs.ErrNotExist", err)
	}

	got, err := a.Glob("/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	want := []string{"/etc/ssh/sshd_config.d/00-fuzz.conf", "/etc/ssh/sshd_config.d/10-other.conf"}
	if !slices.Equal(got, want) {
		t.Errorf("Glob = %v, want %v", got, want)
	}
	// A "*" does not cross a "/": the drop-ins are not matched by a pattern
	// that names only /etc/ssh.
	if got, err := a.Glob("/etc/ssh/*"); err != nil || !slices.Equal(got, []string{"/etc/ssh/sshd_config"}) {
		t.Errorf("Glob(/etc/ssh/*) = %v, %v; want just the main file", got, err)
	}
	if _, err := a.Glob("/etc/ssh/["); err == nil {
		t.Error("Glob of a malformed pattern returned no error")
	}
}

// ---------------------------------------------------------------------------
// seeds — the committed corpus, named by glob
// ---------------------------------------------------------------------------

// seedFiles reads every file the globs name, in glob order and then in the
// sorted order Glob returns, skipping directories (testdata/pam/ holds two).
// A glob that names no file is fatal (G-5): a seed list that silently expands
// to nothing would leave a target fuzzing from the empty input alone and the
// loss would never be noticed. fatalf is a parameter rather than a testing.TB
// method so TestSeedsRefuseAnEmptyGlob can observe the refusal instead of
// dying of it.
func seedFiles(fatalf func(string, ...any), globs ...string) [][]byte {
	var out [][]byte
	for _, g := range globs {
		matches, err := filepath.Glob(g)
		if err != nil {
			fatalf("seed glob %q: %v", g, err)
			return nil
		}
		found := 0
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				fatalf("seed %q: %v", m, err)
				return nil
			}
			if info.IsDir() {
				continue
			}
			data, err := os.ReadFile(m)
			if err != nil {
				fatalf("seed %q: %v", m, err)
				return nil
			}
			out = append(out, data)
			found++
		}
		if found == 0 {
			fatalf("seed glob %q matched no file; every glob must name at least one seed", g)
			return nil
		}
	}
	return out
}

// seeds registers one target's corpus.
func seeds(f *testing.F, globs ...string) {
	f.Helper()
	for _, data := range seedFiles(f.Fatalf, globs...) {
		f.Add(data)
	}
}

func TestSeedsRefuseAnEmptyGlob(t *testing.T) {
	var msgs []string
	record := func(format string, args ...any) { msgs = append(msgs, fmt.Sprintf(format, args...)) }

	if got := seedFiles(record, "testdata/passwd*"); len(got) == 0 {
		t.Error("a glob that names files returned no seed")
	}
	if len(msgs) != 0 {
		t.Errorf("a glob that names files complained: %v", msgs)
	}

	const empty = "testdata/no-such-fixture-*"
	msgs = nil
	if got := seedFiles(record, empty); got != nil {
		t.Errorf("a glob that names nothing returned %d seeds", len(got))
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0], empty) {
		t.Errorf("a glob that names nothing reported %v, want one message naming %q", msgs, empty)
	}

	// The refusal stops the whole list: a later glob is not read, so a
	// target cannot end up with a partial corpus it never asked for.
	msgs = nil
	if got := seedFiles(record, empty, "testdata/passwd*"); got != nil {
		t.Errorf("a list whose first glob names nothing returned %d seeds", len(got))
	}
	if len(msgs) != 1 {
		t.Errorf("a list whose first glob names nothing reported %v, want exactly one message", msgs)
	}

	// A directory is not a seed: testdata/pam holds two of them beside its
	// files, and only the files may reach f.Add.
	msgs = nil
	got := seedFiles(record, "testdata/pam/*")
	if len(msgs) != 0 {
		t.Fatalf("testdata/pam/* complained: %v", msgs)
	}
	if len(got) == 0 {
		t.Error("testdata/pam/* returned no seed")
	}
}

// ---------------------------------------------------------------------------
// fuzzBody — determinism and the output bounds (G-6)
// ---------------------------------------------------------------------------

// listSlack is how many elements a result may hold beyond the input's byte
// count. A parser that turns one byte into one row is fine; a parser that
// fabricates rows out of nothing is the bug this bound catches. The slack
// covers the fixed-size wrapper a target returns its results in.
const listSlack = 64

// rawEllipsis is the marker sourceRaw appends when it cut a line at rawCap.
const rawEllipsis = "…"

// rawWithinCap is the contract exactly: at most rawCap bytes of the file's
// own line, plus the marker when — and only when — the line was cut. Bounding
// the whole string at rawCap+len(rawEllipsis) would let an uncut line run
// three bytes over the cap unnoticed.
func rawWithinCap(s string) bool {
	if strings.HasSuffix(s, rawEllipsis) {
		return len(s)-len(rawEllipsis) <= rawCap
	}
	return len(s) <= rawCap
}

// modulePath is muster's import path. The bound walk descends into muster's
// own types only: a time.Time or an *fs.PathError a parser hands back is
// standard-library state, not parser output, and its internals are not this
// test's business.
const modulePath = "github.com/kun9497/muster"

// rawFields are the struct field names that hold a line of the file a fact
// came from — the strings sourceRaw caps.
var rawFields = map[string]bool{"raw": true, "line": true, "source": true}

// fuzzBody runs one parser twice through run and asserts the two properties a
// parser must have whatever it is fed. name is the parser's own name, so a
// failure names the function rather than the target; inputLen is the number
// of bytes the fuzzer produced.
func fuzzBody(t *testing.T, name string, run func() any, inputLen int) {
	t.Helper()
	first := run()
	second := run()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("%s is not deterministic: two calls on the same input differ at %s",
			name, firstDiff(reflect.ValueOf(first), reflect.ValueOf(second), name, 0))
	}
	w := &boundWalk{t: t, parser: name, inputLen: inputLen, budget: 1 << 16}
	w.walk(reflect.ValueOf(first), name, 0)
}

type boundWalk struct {
	t        *testing.T
	parser   string
	inputLen int
	budget   int
}

// walk descends the parser's result. Every value is navigated with reflect
// alone and never through Interface(), so an unexported field of one of this
// package's row types can be inspected without panicking.
func (w *boundWalk) walk(v reflect.Value, at string, depth int) {
	if !v.IsValid() || depth > 32 || w.budget <= 0 {
		return
	}
	w.budget--
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return
		}
		w.walk(v.Elem(), at, depth+1)
	case reflect.Slice:
		if n := v.Len(); n > w.inputLen+listSlack {
			w.t.Fatalf("%s returned %d elements at %s from %d input bytes (bound %d)",
				w.parser, n, at, w.inputLen, w.inputLen+listSlack)
		}
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), fmt.Sprintf("%s[%d]", at, i), depth+1)
		}
	case reflect.Map:
		if n := v.Len(); n > w.inputLen+listSlack {
			w.t.Fatalf("%s returned a map of %d entries at %s from %d input bytes (bound %d)",
				w.parser, n, at, w.inputLen, w.inputLen+listSlack)
		}
		iter := v.MapRange()
		for iter.Next() {
			w.walk(iter.Value(), at+"[key]", depth+1)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			w.walk(v.Index(i), fmt.Sprintf("%s[%d]", at, i), depth+1)
		}
	case reflect.Struct:
		if p := v.Type().PkgPath(); p != "" && !strings.HasPrefix(p, modulePath) {
			return
		}
		tp := v.Type()
		for i := 0; i < tp.NumField(); i++ {
			f := tp.Field(i)
			fv := v.Field(i)
			// Today the only field that reaches this branch is
			// facts.Source.Raw, through FuzzParseSshdConfig — it is the one
			// target whose parser returns an Envelope. The check is written
			// for the field name rather than for that type so a parser that
			// starts storing evidence is bounded the day it does.
			if fv.Kind() == reflect.String && rawFields[strings.ToLower(f.Name)] {
				if s := fv.String(); !rawWithinCap(s) {
					w.t.Fatalf("%s stored a %d-byte %s at %s.%s (cap %d, plus %q only when it cut)",
						w.parser, len(s), f.Name, at, f.Name, rawCap, rawEllipsis)
				}
			}
			w.walk(fv, at+"."+f.Name, depth+1)
		}
	}
}

// firstDiff names where two results of the same parser stopped agreeing. It
// is reporting only — reflect.DeepEqual has already decided they differ — so
// a descent that cannot pinpoint the difference falls back to the path it
// reached.
func firstDiff(a, b reflect.Value, at string, depth int) string {
	if depth > 32 || !a.IsValid() || !b.IsValid() || a.Type() != b.Type() {
		return at
	}
	switch a.Kind() {
	case reflect.Interface, reflect.Pointer:
		if a.IsNil() != b.IsNil() {
			return at + " (one call returned nil there)"
		}
		if a.IsNil() {
			return at
		}
		return firstDiff(a.Elem(), b.Elem(), at, depth+1)
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return fmt.Sprintf("%s (len %d vs %d)", at, a.Len(), b.Len())
		}
		for i := 0; i < a.Len(); i++ {
			if d, ok := diffAt(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", at, i), depth+1); ok {
				return d
			}
		}
		return at
	case reflect.Map:
		if a.Len() != b.Len() {
			return fmt.Sprintf("%s (len %d vs %d)", at, a.Len(), b.Len())
		}
		iter := a.MapRange()
		for iter.Next() {
			bv := b.MapIndex(iter.Key())
			if !bv.IsValid() {
				return at + " (a key of one call is missing from the other)"
			}
			if d, ok := diffAt(iter.Value(), bv, at+"[key]", depth+1); ok {
				return d
			}
		}
		return at
	case reflect.Struct:
		tp := a.Type()
		for i := 0; i < tp.NumField(); i++ {
			if d, ok := diffAt(a.Field(i), b.Field(i), at+"."+tp.Field(i).Name, depth+1); ok {
				return d
			}
		}
		return at
	default:
		return at
	}
}

// diffAt reports whether two values differ and, when they do, where.
func diffAt(a, b reflect.Value, at string, depth int) (string, bool) {
	if same(a, b, depth) {
		return "", false
	}
	return firstDiff(a, b, at, depth), true
}

// same compares two values of one type without Interface(), so it works on
// the unexported fields of this package's own row types.
func same(a, b reflect.Value, depth int) bool {
	if depth > 32 {
		return true
	}
	if !a.IsValid() || !b.IsValid() {
		return a.IsValid() == b.IsValid()
	}
	if a.Type() != b.Type() {
		return false
	}
	switch a.Kind() {
	case reflect.Interface, reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() && b.IsNil()
		}
		return same(a.Elem(), b.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return false
		}
		for i := 0; i < a.Len(); i++ {
			if !same(a.Index(i), b.Index(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Map:
		if a.Len() != b.Len() {
			return false
		}
		iter := a.MapRange()
		for iter.Next() {
			bv := b.MapIndex(iter.Key())
			if !bv.IsValid() || !same(iter.Value(), bv, depth+1) {
				return false
			}
		}
		return true
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if !same(a.Field(i), b.Field(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.String:
		return a.String() == b.String()
	case reflect.Bool:
		return a.Bool() == b.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return a.Int() == b.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return a.Uint() == b.Uint()
	case reflect.Float32, reflect.Float64:
		return a.Float() == b.Float()
	default:
		return true
	}
}

// ---------------------------------------------------------------------------
// The targets — accounts and ids
// ---------------------------------------------------------------------------

func FuzzParsePasswd(f *testing.F) {
	seeds(f, "testdata/passwd*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePasswd", func() any {
			rows, failures := parsePasswd(data)
			return []any{rows, failures}
		}, len(data))
	})
}

func FuzzParseGroup(f *testing.F) {
	seeds(f, "testdata/group*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseGroup", func() any {
			rows, failures := parseGroup(data)
			return []any{rows, failures}
		}, len(data))
	})
}

func FuzzParseShadow(f *testing.F) {
	seeds(f, "testdata/shadow*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseShadow", func() any { return parseShadow(data) }, len(data))
	})
}

func FuzzParseSubIDs(f *testing.F) {
	seeds(f, "testdata/subuid*", "testdata/subgid*")
	f.Fuzz(func(t *testing.T, data []byte) {
		known := func(n string) bool { return n == "alice" }
		fuzzBody(t, "parseSubIDs", func() any { return parseSubIDs(data, known) }, len(data))
	})
}

func FuzzNSSSources(f *testing.F) {
	seeds(f, "testdata/nsswitch*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "nssSources", func() any {
			var out []any
			for _, db := range []string{"passwd", "group"} {
				sources, line, found := nssSources(data, db)
				out = append(out, sources, line, found)
			}
			return out
		}, len(data))
	})
}

func FuzzDecodeACL(f *testing.F) {
	seeds(f, "testdata/acl.access*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "decodeACL", func() any {
			entries, err := decodeACL(data)
			return []any{entries, err != nil}
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// Mounts, sockets and the walk's id tables
// ---------------------------------------------------------------------------

func FuzzParseMountinfo(f *testing.F) {
	seeds(f, "testdata/mountinfo*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseMountinfo", func() any {
			rows, err := parseMountinfo(data)
			return []any{rows, err != nil}
		}, len(data))
	})
}

func FuzzParseProcNet(f *testing.F) {
	seeds(f, "testdata/proc_net_*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseProcNet", func() any {
			return []any{parseProcNet(data, "tcp"), parseProcNet(data, "tcp6")}
		}, len(data))
	})
}

func FuzzRPMFileTable(f *testing.F) {
	seeds(f, "testdata/rpm.qa-files.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "rpmFileTable", func() any {
			whole, errWhole := rpmFileTable(data, map[string]bool{"/usr/bin/su": true, "/usr/bin/at": true}, false)
			cut, errCut := rpmFileTable(data, map[string]bool{"/usr/bin/su": true, "/usr/bin/at": true}, true)
			return []any{whole, errWhole != nil, cut, errCut != nil}
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// The package databases
// ---------------------------------------------------------------------------

func FuzzParseDpkgStatus(f *testing.F) {
	seeds(f, "testdata/dpkg.status*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseDpkgStatus", func() any { return parseDpkgStatus(data) }, len(data))
	})
}

func FuzzParseAptSimulation(f *testing.F) {
	seeds(f, "testdata/apt-get*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseAptSimulation", func() any { return parseAptSimulation(data) }, len(data))
	})
}

func FuzzCountAptSecurity(f *testing.F) {
	seeds(f, "testdata/apt-get*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "countAptSecurity", func() any { return countAptSecurity(data) }, len(data))
	})
}

func FuzzAptPeriodicUnattended(f *testing.F) {
	seeds(f, "testdata/apt.20auto-upgrades*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "aptPeriodicUnattended", func() any {
			on, found := aptPeriodicUnattended(data)
			return []any{on, found}
		}, len(data))
	})
}

func FuzzNewestDpkgInstall(f *testing.F) {
	seeds(f, "testdata/dpkg.log.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "newestDpkgInstall", func() any {
			when, found := newestDpkgInstall(data)
			return []any{when, found}
		}, len(data))
	})
}

func FuzzParseDnfCheckUpdate(f *testing.F) {
	seeds(f, "testdata/dnf.check-update*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseDnfCheckUpdate", func() any { return parseDnfCheckUpdate(data) }, len(data))
	})
}

func FuzzCountDnfAdvisories(f *testing.F) {
	seeds(f, "testdata/dnf.updateinfo.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "countDnfAdvisories", func() any { return countDnfAdvisories(data) }, len(data))
	})
}

func FuzzDnfAutomaticApply(f *testing.F) {
	seeds(f, "testdata/dnf.automatic.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "dnfAutomaticApply", func() any {
			apply, found := dnfAutomaticApply(data)
			return []any{apply, found}
		}, len(data))
	})
}

func FuzzParseRpmQa(f *testing.F) {
	seeds(f, "testdata/rpm.qa.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseRpmQa", func() any { return parseRpmQa(data) }, len(data))
	})
}

// ---------------------------------------------------------------------------
// sshd
// ---------------------------------------------------------------------------

func FuzzParseDaemonDump(f *testing.F) {
	seeds(f, "testdata/sshd_T*.txt", "testdata/sshd_G.txt")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseDaemonDump", func() any { return parseDaemonDump(data) }, len(data))
	})
}

// FuzzParseSshdConfig serves the input as the main file AND as the one
// drop-in, so an Include the input carries expands to files that carry the
// same Include: the recursion, its depth limit and the drop-in precedence are
// all exercised by one input.
func FuzzParseSshdConfig(f *testing.F) {
	seeds(f, "testdata/sshd_config*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseSshdConfig", func() any {
			out := make([]any, 0, 2*len(sshdOptions))
			for _, o := range sshdOptions {
				a := &memAccess{files: map[string][]byte{
					"/etc/ssh/sshd_config":                data,
					"/etc/ssh/sshd_config.d/00-fuzz.conf": data,
				}}
				env, found := parseSshdConfig(a, "/etc/ssh/sshd_config", o.keyword, 0)
				out = append(out, env, found)
			}
			return out
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// PAM, key-value files and drop-ins
// ---------------------------------------------------------------------------

func FuzzParsePAMFile(f *testing.F) {
	seeds(f, "testdata/pam/*", "testdata/pam/ubuntu/common-*", "testdata/pam/rocky/authselect-*", "testdata/pam.d.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePAMFile", func() any {
			return parsePAMFile(data, "sshd", "/etc/pam.d/sshd")
		}, len(data))
	})
}

func FuzzParseKV(f *testing.F) {
	seeds(f, "testdata/pam/*/pwquality.conf", "testdata/pam/rocky/faillock.conf",
		"testdata/pam/rocky/dropin-*.conf", "testdata/pam/ubuntu/pwhistory.conf")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseKV", func() any { return parseKV(data) }, len(data))
	})
}

func FuzzParseDropin(f *testing.F) {
	seeds(f, "testdata/timesyncd*", "testdata/journald.d.*", "testdata/journald.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseDropin", func() any {
			values := map[string]string{}
			parseDropin(data, values)
			return values
		}, len(data))
	})
}

func FuzzParsePamListfiles(f *testing.F) {
	seeds(f, "testdata/pam.d.vsftpd.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePamListfiles", func() any { return parsePamListfiles(data) }, len(data))
	})
}

// ---------------------------------------------------------------------------
// Shell environment files and banners
// ---------------------------------------------------------------------------

func FuzzParseShellFile(f *testing.F) {
	seeds(f, "testdata/profile*", "testdata/*bashrc*", "testdata/root_bash_profile_splice")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseShellFile", func() any {
			return parseShellFile(data, "/etc/profile")
		}, len(data))
	})
}

func FuzzOSEscapes(f *testing.F) {
	seeds(f, "testdata/issue*", "testdata/motd*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "osEscapes", func() any { return osEscapes(data) }, len(data))
	})
}

// ---------------------------------------------------------------------------
// Firewalls
// ---------------------------------------------------------------------------

func FuzzParseNftRuleset(f *testing.F) {
	seeds(f, "testdata/nft.ruleset.*", "testdata/nftables.conf")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseNftRuleset", func() any {
			chains, records := parseNftRuleset(string(data))
			return []any{chains, records}
		}, len(data))
	})
}

func FuzzParseIptablesSave(f *testing.F) {
	seeds(f, "testdata/iptables-save.*", "testdata/ip6tables-save.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseIptablesSave", func() any {
			v4chains, v4records := parseIptablesSave("v4", string(data))
			v6chains, v6records := parseIptablesSave("v6", string(data))
			return []any{v4chains, v4records, v6chains, v6records}
		}, len(data))
	})
}

func FuzzUFWEnabledLine(f *testing.F) {
	seeds(f, "testdata/ufw.conf")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "ufwEnabledLine", func() any { return ufwEnabledLine(data) }, len(data))
	})
}

// ---------------------------------------------------------------------------
// FTP
// ---------------------------------------------------------------------------

func FuzzParseVsftpdInto(f *testing.F) {
	seeds(f, "testdata/vsftpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseVsftpdInto", func() any {
			dst := map[string]string{}
			parseVsftpdInto(dst, data)
			return dst
		}, len(data))
	})
}

func FuzzParsePureFtpdInto(f *testing.F) {
	seeds(f, "testdata/pure-ftpd.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePureFtpdInto", func() any {
			dst := map[string]string{}
			parsePureFtpdInto(dst, data)
			return dst
		}, len(data))
	})
}

func FuzzFirstSettingLine(f *testing.F) {
	seeds(f, "testdata/vsftpd.conf.*", "testdata/proftpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "firstSettingLine", func() any { return firstSettingLine(data) }, len(data))
	})
}

// FuzzParseProftpd drives the proftpd file walk itself (ruling G-25): the
// section stack, the Include handling and the depth attribution, not just the
// line helpers under it. A fresh ftpParse per call keeps the two runs
// fuzzBody compares independent, and memAccess serves the input at BOTH
// proftpd main paths, so an Include the input carries expands to a file
// carrying the same Include and the recursion guard is exercised.
func FuzzParseProftpd(f *testing.F) {
	seeds(f, "testdata/proftpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseProftpd", func() any {
			p := &ftpParse{
				a: &memAccess{files: map[string][]byte{
					proftpdDebianConf: data,
					proftpdRhelConf:   data,
				}},
				impl:     "proftpd",
				mainFile: proftpdDebianConf,
				seen:     map[string]bool{},
				vsftpd:   map[string]string{},
				pro:      map[string]string{},
				pure:     map[string]string{},
			}
			p.parseProftpd(proftpdDebianConf, data, 0, nil)
			return []any{p.pro, p.proAno, p.files, p.truncated, p.unmodelled, p.readFailure}
		}, len(data))
	})
}

func FuzzProftpdClosingName(f *testing.F) {
	seeds(f, "testdata/proftpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "proftpdClosingName", func() any { return proftpdClosingName(string(data)) }, len(data))
	})
}

func FuzzListsRoot(f *testing.F) {
	seeds(f, "testdata/ftpusers.*", "testdata/user_list.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "listsRoot", func() any { return listsRoot(data) }, len(data))
	})
}

// ---------------------------------------------------------------------------
// Mail
// ---------------------------------------------------------------------------

func FuzzParsePostfixInto(f *testing.F) {
	seeds(f, "testdata/main.cf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePostfixInto", func() any {
			dst := map[string]string{}
			parsePostfixInto(dst, data)
			return dst
		}, len(data))
	})
}

func FuzzParseSendmailPrivacy(f *testing.F) {
	seeds(f, "testdata/sendmail.cf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseSendmailPrivacy", func() any {
			flags, found, bad := parseSendmailPrivacy(data)
			return []any{flags, found, bad}
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// FuzzParseRsyslogSelector splits the input the way the collector does and
// then runs every one of its logical lines through the three action and
// selector parsers, so one input exercises the whole rsyslog line grammar.
func FuzzParseRsyslogSelector(f *testing.F) {
	seeds(f, "testdata/rsyslog.conf.*", "testdata/rsyslog_conf", "testdata/rsyslog.d/*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseRsyslogSelector", func() any {
			lines := rsyslogLogicalLines(data)
			// Parallel slices, not one flat list: each is exactly as long
			// as the logical-line list, so the bound stays proportional to
			// the input however many lines it holds.
			sels := make([]*rsyslogSelector, 0, len(lines))
			acts := make([]rsyslogAction, 0, len(lines))
			calls := make([]rsyslogAction, 0, len(lines))
			braces := make([]int, 0, len(lines))
			numeric := make([]bool, 0, len(lines))
			for _, l := range lines {
				sels = append(sels, parseRsyslogSelector(l))
				acts = append(acts, parseRsyslogAction(l))
				calls = append(calls, parseRsyslogActionCall(l))
				braces = append(braces, rsyslogBraceDelta(l))
				numeric = append(numeric, rsyslogNumericSelector(l))
			}
			return []any{lines, sels, acts, calls, braces, numeric}
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// NFS, SNMP, DNS and time sync
// ---------------------------------------------------------------------------

func FuzzParseExportsContent(f *testing.F) {
	seeds(f, "testdata/exports.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseExportsContent", func() any { return parseExportsContent(data) }, len(data))
	})
}

func FuzzSNMPStripComment(f *testing.F) {
	seeds(f, "testdata/snmpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "snmpStripComment", func() any { return snmpStripComment(string(data)) }, len(data))
	})
}

func FuzzSNMPTokens(f *testing.F) {
	seeds(f, "testdata/snmpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "snmpTokens", func() any { return snmpTokens(string(data)) }, len(data))
	})
}

// FuzzSNMPParse drives the directive walk, which the two line helpers below
// it do not reach: the com2sec/group/access bookkeeping, the v3 user table
// and the include handling all live there. memAccess serves the input at the
// main path so an include naming it exercises the depth guard.
func FuzzSNMPParse(f *testing.F) {
	seeds(f, "testdata/snmpd.conf.*", "testdata/var-lib-snmpd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parse", func() any {
			p := &snmpParse{
				a:            &memAccess{files: map[string][]byte{snmpdConfPath: data}},
				seen:         map[string]bool{},
				users:        map[string]*snmpUser{},
				accessWrites: map[string][]string{},
				com2secNames: map[string]bool{},
				communities:  []any{},
				rules:        []any{},
				agents:       []any{},
				curFile:      snmpdConfPath,
			}
			p.parse(data, 0)
			return []any{p.communities, p.rules, p.agents, p.userNames, p.groups, p.undeclared, p.truncated}
		}, len(data))
	})
}

func FuzzDNSTokenize(f *testing.F) {
	seeds(f, "testdata/named.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "dnsTokenize", func() any { return dnsTokenize(data) }, len(data))
	})
}

func FuzzCryptoPolicyName(f *testing.F) {
	seeds(f, "testdata/crypto-policies.state.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "cryptoPolicyName", func() any { return cryptoPolicyName(data) }, len(data))
	})
}

// FuzzNTPFile drives the ntpd/ntpsec configuration walk: the server and pool
// directives and the includefile chain it returns, which parseChronySources
// (a different file grammar) never sees.
func FuzzNTPFile(f *testing.F) {
	seeds(f, "testdata/ntp.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "ntpFile", func() any {
			s := &timesyncScan{a: &memAccess{files: map[string][]byte{}}}
			includes := s.ntpFile(data, 0)
			return []any{includes, s.servers}
		}, len(data))
	})
}

func FuzzParseChronySources(f *testing.F) {
	seeds(f, "testdata/chrony.conf.*", "testdata/ntp.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseChronySources", func() any {
			servers, dirs := parseChronySources(data)
			return []any{servers, dirs}
		}, len(data))
	})
}

// ---------------------------------------------------------------------------
// Services, super-servers and command output
// ---------------------------------------------------------------------------

func FuzzShowValues(f *testing.F) {
	seeds(f, "testdata/systemctl.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "showValues", func() any {
			load, active, unitFile := showValues(data)
			return []any{load, active, unitFile}
		}, len(data))
	})
}

func FuzzAttrValue(f *testing.F) {
	seeds(f, "testdata/xinetd*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "attrValue", func() any {
			v, ok := attrValue(string(data))
			return []any{v, ok}
		}, len(data))
	})
}

// FuzzParseXinetd drives the fragment walk (ruling G-25): the block flushing
// at `service`, at a closing brace and at end of file, which attrValue alone
// never reaches.
func FuzzParseXinetd(f *testing.F) {
	seeds(f, "testdata/xinetd*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parseXinetd", func() any {
			s := &superServers{}
			s.parseXinetd("/etc/xinetd.d/fuzz", data, false)
			return []any{s.entries, s.readErr}
		}, len(data))
	})
}

// FuzzReadInetd is the one target named for a function the inventory grammar
// does not catch: readInetd takes a collect.Access and does its own read, so
// the bytes reach it through memAccess rather than through a parameter
// (ruling G-25). Widening the grammar to every Access-taking function would
// inventory each of this package's collectors, so the target is listed by
// hand instead.
func FuzzReadInetd(f *testing.F) {
	seeds(f, "testdata/inetd.conf.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "readInetd", func() any {
			s := &superServers{}
			s.readInetd(&memAccess{files: map[string][]byte{inetdConf: data}})
			return []any{s.entries, s.readErr}
		}, len(data))
	})
}

func FuzzFirstLine(f *testing.F) {
	seeds(f, "testdata/stderr.*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "firstLine", func() any { return firstLine(data) }, len(data))
	})
}
