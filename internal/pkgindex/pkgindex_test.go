//go:build linux

package pkgindex

import (
	"context"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// fakeAccess is the smallest collect.Access the readers need: files by path,
// errors by path, directories that stat, and one command answer. It records
// every command so a test can say what Build ran.
type fakeAccess struct {
	files map[string]string
	errs  map[string]error
	dirs  map[string]bool
	out   collect.Output
	ran   []collect.Command
}

func (a *fakeAccess) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	if err := a.errs[p]; err != nil {
		return nil, collect.ReadMeta{}, err
	}
	s, ok := a.files[p]
	if !ok {
		return nil, collect.ReadMeta{}, fs.ErrNotExist
	}
	if int64(len(s)) > limit {
		return []byte(s[:limit]), collect.ReadMeta{Truncated: true}, nil
	}
	return []byte(s), collect.ReadMeta{}, nil
}

func (a *fakeAccess) ReadFileBinary(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	return a.ReadFile(p, limit)
}

func (a *fakeAccess) Stat(p string) (collect.ReadMeta, error) {
	if err := a.errs[p]; err != nil {
		return collect.ReadMeta{}, err
	}
	if _, ok := a.files[p]; ok || a.dirs[p] {
		return collect.ReadMeta{}, nil
	}
	return collect.ReadMeta{}, fs.ErrNotExist
}

func (a *fakeAccess) Glob(pattern string) ([]string, error) {
	if err := a.errs[pattern]; err != nil {
		return nil, err
	}
	var out []string
	for p := range a.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (a *fakeAccess) Llistxattr(string) ([]string, error)     { return nil, fs.ErrNotExist }
func (a *fakeAccess) Getxattr(string, string) ([]byte, error) { return nil, fs.ErrNotExist }
func (a *fakeAccess) Readlink(string) (string, error)         { return "", fs.ErrNotExist }
func (a *fakeAccess) Writable(string) bool                    { return false }
func (a *fakeAccess) ReadDir(string, collect.Identity, collect.ReadDirOptions) (collect.Listing, error) {
	return collect.Listing{}, fs.ErrNotExist
}

func (a *fakeAccess) Run(_ context.Context, c collect.Command) collect.Output {
	a.ran = append(a.ran, c)
	return a.out
}

var merged = map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib"}

const status = "Package: util-linux\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.37.2-4ubuntu3\n\n" +
	"Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n\n" +
	"Package: systemd\nStatus: install ok installed\nArchitecture: amd64\nVersion: 249.11-0ubuntu3\n"

func dpkgHost() *fakeAccess {
	return &fakeAccess{files: map[string]string{
		DpkgStatusPath:                         status,
		DpkgInfoDir + "/util-linux:amd64.list": "/.\n/bin\n/bin/su\n/usr/bin/mount\n",
		DpkgInfoDir + "/systemd.list":          "/lib/systemd/systemd-resolved\n  \n/usr/bin/systemctl\n",
		DpkgStatOverridePath:                   "root crontab 2755 /usr/bin/crontab\nbad line\n",
	}}
}

// The index holds the candidates and nothing else, each under the
// candidate's own (merged) spelling, with the pre-merge spelling the .list
// used as DeclaredPath and the .list itself as ListFile.
func TestBuildDpkgIndexesTheCandidatesThroughTheMergedAliases(t *testing.T) {
	a := dpkgHost()
	cands := map[string]bool{"/usr/bin/su": true, "/usr/lib/systemd/systemd-resolved": true, "/usr/bin/crontab": true, "/opt/x": true}
	ix, truncated, failed := Build(context.Background(), a, cands, Options{USRMerged: merged})
	if failed != nil || truncated {
		t.Fatalf("Build failed=%+v truncated=%v", failed, truncated)
	}
	if ix.Family != FamilyDpkg || ix.Dpkg == nil || ix.RPM != nil {
		t.Fatalf("index = %+v, want a dpkg index", ix)
	}
	if want := (&facts.Source{Kind: "file", Path: DpkgInfoDir}); !reflect.DeepEqual(ix.Source, want) {
		t.Errorf("source = %+v, want %+v", ix.Source, want)
	}
	want := &DpkgIndex{
		Owner:        map[string]string{"/usr/bin/su": "util-linux", "/usr/lib/systemd/systemd-resolved": "systemd"},
		DeclaredPath: map[string]string{"/usr/bin/su": "/bin/su", "/usr/lib/systemd/systemd-resolved": "/lib/systemd/systemd-resolved"},
		ListPath:     map[string]string{},
		ListFile: map[string]string{
			"/usr/bin/su":                       DpkgInfoDir + "/util-linux:amd64.list",
			"/usr/lib/systemd/systemd-resolved": DpkgInfoDir + "/systemd.list",
		},
		Overrides: map[string]StatOverride{"/usr/bin/crontab": {User: "root", Group: "crontab", Mode: 0o2755}},
		Versions:  map[string]string{"util-linux": "2.37.2-4ubuntu3", "systemd": "249.11-0ubuntu3"},
	}
	if !reflect.DeepEqual(ix.Dpkg, want) {
		t.Errorf("index\n got %+v\nwant %+v", ix.Dpkg, want)
	}
	if pkg, ok := ix.Owner("/usr/lib/systemd/systemd-resolved"); !ok || pkg != "systemd" {
		t.Errorf("Owner(resolved) = %q %v", pkg, ok)
	}
	if _, ok := ix.Owner("/usr/bin/mount"); ok {
		t.Error("a path that was not a candidate must not be held")
	}
	if _, ok := ix.Owner("/opt/x"); ok {
		t.Error("an unpackaged candidate must not be owned")
	}
}

// Without the alias table the pre-merge spelling never meets the candidate:
// the Options are what make a pre-merge .list match a merged path (W-35).
func TestBuildDpkgWithoutTheAliasesMissesThePreMergeSpelling(t *testing.T) {
	ix, _, failed := Build(context.Background(), dpkgHost(), map[string]bool{"/usr/bin/su": true}, Options{})
	if failed != nil {
		t.Fatalf("failed = %+v", failed)
	}
	if _, ok := ix.Owner("/usr/bin/su"); ok {
		t.Error("/bin/su matched /usr/bin/su with no alias table")
	}
}

// A diverted candidate is owned by the package the diversion displaced, the
// diverting package owns its own file, and the reference-list key of the
// diverted one is the name it shipped.
func TestBuildDpkgFollowsADiversion(t *testing.T) {
	a := &fakeAccess{files: map[string]string{
		DpkgStatusPath:                    status,
		DpkgDiversionsPath:                "/usr/bin/foo\n/usr/bin/foo.distrib\nfoo-wrapper\n",
		DpkgInfoDir + "/foo-tools.list":   "/usr/bin/foo\n",
		DpkgInfoDir + "/foo-wrapper.list": "/usr/bin/foo\n",
	}}
	cands := map[string]bool{"/usr/bin/foo.distrib": true, "/usr/bin/foo": true}
	ix, _, failed := Build(context.Background(), a, cands, Options{})
	if failed != nil {
		t.Fatalf("failed = %+v", failed)
	}
	if got := ix.Dpkg.Owner; !reflect.DeepEqual(got, map[string]string{"/usr/bin/foo.distrib": "foo-tools", "/usr/bin/foo": "foo-wrapper"}) {
		t.Errorf("owners = %v", got)
	}
	if got := ix.Dpkg.ListPath["/usr/bin/foo.distrib"]; got != "/usr/bin/foo" {
		t.Errorf("list path = %q, want the shipped name", got)
	}
}

// A database file that exists and cannot be read is the index's answer, with
// the path in the reason (C3).
func TestBuildDpkgReadFailureIsPathPrefixed(t *testing.T) {
	a := dpkgHost()
	a.errs = map[string]error{DpkgInfoDir + "/systemd.list": fs.ErrPermission}
	_, _, failed := Build(context.Background(), a, map[string]bool{"/usr/bin/su": true}, Options{USRMerged: merged})
	if failed == nil || failed.Status != facts.StatusDenied || !strings.HasPrefix(failed.Reason, DpkgInfoDir+"/systemd.list: ") {
		t.Fatalf("failed = %+v, want denied naming the .list", failed)
	}
}

// A missing optional file (diversions, statoverride) is no failure; a
// missing status file is.
func TestBuildDpkgMissingFiles(t *testing.T) {
	a := dpkgHost()
	delete(a.files, DpkgStatOverridePath)
	if _, _, failed := Build(context.Background(), a, map[string]bool{"/usr/bin/su": true}, Options{}); failed != nil {
		t.Errorf("no statoverride: failed = %+v", failed)
	}
	// The status file must stat for the host to be dpkg at all; make the
	// stat succeed and the read fail.
	b := &statOnly{fakeAccess: dpkgHost()}
	_, _, failed := Build(context.Background(), b, map[string]bool{"/usr/bin/su": true}, Options{})
	if failed == nil || failed.Status != facts.StatusAbsent || !strings.HasPrefix(failed.Reason, DpkgStatusPath+": ") {
		t.Errorf("unreadable status: failed = %+v, want absent naming the file", failed)
	}
}

// statOnly makes the status file stat but vanish before it is read.
type statOnly struct{ *fakeAccess }

func (s *statOnly) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	if p == DpkgStatusPath {
		return nil, collect.ReadMeta{}, fs.ErrNotExist
	}
	return s.fakeAccess.ReadFile(p, limit)
}

// A capped read truncates the index and drops the cut last line, which would
// otherwise be the prefix of some other path.
func TestBuildDpkgCappedReadTruncates(t *testing.T) {
	a := dpkgHost()
	pad := strings.Repeat("/x\n", DpkgReadLimit/3)
	a.files[DpkgInfoDir+"/big.list"] = "/usr/bin/sudo\n" + pad + "/usr/bin/sudoedit\n"
	cands := map[string]bool{"/usr/bin/sudo": true, "/usr/bin/su": true}
	ix, truncated, failed := Build(context.Background(), a, cands, Options{})
	if failed != nil || !truncated {
		t.Fatalf("failed = %+v truncated = %v, want a truncated answer", failed, truncated)
	}
	if pkg, _ := ix.Owner("/usr/bin/sudo"); pkg != "big" {
		t.Errorf("Owner(sudo) = %q, the rows before the cap are real", pkg)
	}
	if pkg, ok := ix.Owner("/usr/bin/su"); ok && pkg == "big" {
		t.Error("the cut tail /usr/bin/su… claimed a candidate")
	}
}

func TestBuildWithNoDatabaseIsAbsent(t *testing.T) {
	ix, truncated, failed := Build(context.Background(), &fakeAccess{}, map[string]bool{"/usr/bin/su": true}, Options{})
	if ix.Family != FamilyNone || truncated || failed == nil || failed.Status != facts.StatusAbsent || failed.Reason != NoPackageDBReason {
		t.Fatalf("Build = %+v %v %+v, want none + absent %q", ix, truncated, failed, NoPackageDBReason)
	}
	if _, ok := ix.Owner("/usr/bin/su"); ok {
		t.Error("a host with no database owns nothing")
	}
}

// The dpkg status file wins over /var/lib/rpm, in the patch collector's
// order; a /var/lib/rpm that refuses a stat is still an rpm host.
func TestDetectFamily(t *testing.T) {
	both := &fakeAccess{files: map[string]string{DpkgStatusPath: ""}, dirs: map[string]bool{RPMDBDir: true}}
	denied := &fakeAccess{errs: map[string]error{RPMDBDir: fs.ErrPermission}}
	for name, c := range map[string]struct {
		a    *fakeAccess
		want Family
	}{"both": {both, FamilyDpkg}, "rpm-denied": {denied, FamilyRPM}, "none": {&fakeAccess{}, FamilyNone}} {
		if got := DetectFamily(c.a); got != c.want {
			t.Errorf("%s: DetectFamily = %q, want %q", name, got, c.want)
		}
	}
}

func rpmHost(out collect.Output) *fakeAccess {
	return &fakeAccess{dirs: map[string]bool{RPMDBDir: true}, out: out}
}

// The rpm reader runs RPMCommand with the caller's bounds and the same Path
// and Args — the guard compares those — and keeps the candidate rows.
func TestBuildRPMRunsTheQueryUnderTheCallersBounds(t *testing.T) {
	a := rpmHost(collect.Output{Stdout: []byte("util-linux\t0104755\troot\troot\t\t/usr/bin/su\nbash\t0100755\troot\troot\t\t/usr/bin/bash\n")})
	ix, truncated, failed := Build(context.Background(), a, map[string]bool{"/usr/bin/su": true}, Options{RPMTimeout: 5 * time.Second, RPMMaxOutput: 1 << 20})
	if failed != nil || truncated {
		t.Fatalf("failed = %+v truncated = %v", failed, truncated)
	}
	if len(a.ran) != 1 {
		t.Fatalf("ran %d commands", len(a.ran))
	}
	got := a.ran[0]
	if got.Path != RPMCommand.Path || !slices.Equal(got.Args, RPMCommand.Args) || got.Timeout != 5*time.Second || got.MaxOutput != 1<<20 {
		t.Errorf("ran %+v, want RPMCommand's path and args under the caller's bounds", got)
	}
	if want := map[string]RPMFile{"/usr/bin/su": {Pkg: "util-linux", Owner: "root", Group: "root", Mode: 0o4755}}; !reflect.DeepEqual(ix.RPM, want) {
		t.Errorf("table = %+v, want %+v", ix.RPM, want)
	}
	if pkg, ok := ix.Owner("/usr/bin/su"); !ok || pkg != "util-linux" {
		t.Errorf("Owner(su) = %q %v", pkg, ok)
	}
	if ix.Source == nil || ix.Source.Kind != "command" || ix.Source.ExitCode == nil || *ix.Source.ExitCode != 0 {
		t.Errorf("source = %+v, want the command with exit 0", ix.Source)
	}
}

// Zero options are the walk's 120 s and 256 MiB; a capped capture is an
// answer marked truncated.
func TestBuildRPMDefaultsToTheWalksBounds(t *testing.T) {
	a := rpmHost(collect.Output{Truncated: true, Stdout: []byte("util-linux\t0104755\troot\troot\t\t/usr/bin/su\n")})
	ix, truncated, failed := Build(context.Background(), a, map[string]bool{"/usr/bin/su": true}, Options{})
	if len(a.ran) != 1 || a.ran[0].Timeout != 120*time.Second || a.ran[0].MaxOutput != 256<<20 {
		t.Errorf("ran %+v, want the default bounds", a.ran)
	}
	if failed != nil || !truncated || len(ix.RPM) != 1 {
		t.Errorf("Build = %+v %v %+v, want the row and truncated", ix, truncated, failed)
	}
}

func TestBuildRPMFailures(t *testing.T) {
	for name, c := range map[string]struct {
		out    collect.Output
		status facts.Status
		reason string
		trunc  bool
	}{
		"timeout":  {collect.Output{TimedOut: true, Truncated: true}, facts.StatusTimeout, "rpm -qa timed out", true},
		"exit":     {collect.Output{ExitCode: 1, Stderr: []byte("\nerror: rpmdb open failed\n")}, facts.StatusError, "rpm -qa exited 1: error: rpmdb open failed", false},
		"overlong": {collect.Output{Stdout: []byte("p\t0100644\tr\tr\t\t/" + strings.Repeat("x", 70<<10) + "\n")}, facts.StatusError, "rpm -qa: bufio.Scanner: token too long", false},
	} {
		ix, truncated, failed := Build(context.Background(), rpmHost(c.out), map[string]bool{"/usr/bin/su": true}, Options{})
		if failed == nil || failed.Status != c.status || failed.Reason != c.reason || failed.Truncated != c.trunc {
			t.Errorf("%s: failed = %+v, want %s %q truncated %v", name, failed, c.status, c.reason, c.trunc)
			continue
		}
		if truncated || ix.RPM != nil {
			t.Errorf("%s: a failure carries its truncation on the envelope and holds no table", name)
		}
		if failed.Source == nil || failed.Source.Kind != "command" || !reflect.DeepEqual(failed.Source, ix.Source) {
			t.Errorf("%s: failure source = %+v, index source %+v", name, failed.Source, ix.Source)
		}
	}
}

// A caller that declares DpkgReads, RPMReads and RPMCommand licenses every
// access Build makes, on either family: run under collect.Guard with exactly
// that declaration, Build records no violation (Task 1 review, item b).
func TestBuildStaysInsideTheDeclaredReads(t *testing.T) {
	decl := collect.Declaration{
		Reads:    append(slices.Clone(DpkgReads), RPMReads...),
		Commands: []collect.Command{RPMCommand},
		Needs:    "none",
	}
	rpmHost := &fakeAccess{dirs: map[string]bool{RPMDBDir: true},
		out: collect.Output{Stdout: []byte("openssh-server\t0100755\troot\troot\t\t/usr/sbin/sshd\n")}}
	diverted := dpkgHost()
	diverted.files[DpkgDiversionsPath] = "/usr/bin/foo\n/usr/bin/foo.distrib\nfoo-wrapper\n"
	for name, a := range map[string]collect.Access{"dpkg": diverted, "rpm": rpmHost} {
		g := collect.Guard(a, collect.Collector{Name: "caller", Declare: decl})
		ix, _, failed := Build(context.Background(), g, map[string]bool{"/usr/bin/su": true, "/usr/sbin/sshd": true}, Options{USRMerged: merged, RPMTimeout: time.Second})
		if v := g.Violations(); len(v) != 0 {
			t.Errorf("%s: Build touched undeclared targets: %v", name, v)
		}
		if failed != nil || string(ix.Family) != name {
			t.Errorf("%s: family %s failed %+v", name, ix.Family, failed)
		}
	}
	if pkg, ok := func() (string, bool) {
		ix, _, _ := Build(context.Background(), collect.Guard(rpmHost, collect.Collector{Name: "caller", Declare: decl}), map[string]bool{"/usr/sbin/sshd": true}, Options{})
		return ix.Owner("/usr/sbin/sshd")
	}(); !ok || pkg != "openssh-server" {
		t.Errorf("rpm Owner(sshd) = %q %v", pkg, ok)
	}
}

// FuzzFirstLine (here, beside the linux-tagged rpm.go it reaches, not in the
// untagged fuzz_test.go): the first non-blank line of a command's stderr, the reason
// a failed rpm query carries. It is a line of the input, trimmed, so never
// longer than the input.
func FuzzFirstLine(f *testing.F) {
	seeds(f, "stderr.*")
	f.Add([]byte("\n\n  rpmdb: open failed \r\nsecond\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "firstLine", func() (any, int) {
			s := firstLine(data)
			if len(s) > len(data) {
				t.Fatalf("firstLine returned %d bytes from %d", len(s), len(data))
			}
			return s, 0
		}, len(data))
	})
}
