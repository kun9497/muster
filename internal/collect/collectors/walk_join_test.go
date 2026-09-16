//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/docs/reference/suid"
	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The tree below is synthetic: real distribution paths, invented packages
// and versions, no host anywhere. It is walked by the REAL traversal rather
// than hand-built into rows, so the join is tested against the records the
// collector will actually hand it — a field the traversal stops writing
// fails here rather than being quietly re-invented by a fixture.
var joinTreeSpec = map[string][]collect.DirEntry{
	"/":    {treeDir("usr", 0o755), treeDir("opt", 0o755), treeDir("srv", 0o755), treeDir("var", 0o755)},
	"/usr": {treeDir("bin", 0o755), treeDir("sbin", 0o755)},
	"/usr/bin": {
		treeFile("at", 0o4755), treeFile("foo", 0o4755), treeFile("passwd", 0o4755),
		treeFile("python3", 0o4755), treeFile("su", 0o4755), treeFile("x.distrib", 0o4755),
	},
	"/usr/sbin":        {treeFile(".h", 0o600)},
	"/opt":             {treeDir("x", 0o755)},
	"/opt/x":           {treeFile("tool", 0o4755), treeFile(".hidden", 0o600)},
	"/var":             {treeDir("lib", 0o755)},
	"/var/lib":         {treeDir("x", 0o755)},
	"/var/lib/x":       {treeDir("spool", 0o1777)},
	"/var/lib/x/spool": {},
	"/srv":             {treeDir("share", 0o777)},
	"/srv/share":       {},
}

// joinWalk runs the traversal over the tree and returns its result together
// with the plan, whose merged-usr table is read from the access double's own
// symlinks — the wiring a dpkg host depends on.
func joinWalk(t *testing.T, a *fsAccess) (*walkResult, mountPlan) {
	t.Helper()
	a.tree = buildTree(joinTreeSpec, map[string]uint64{"/": 1})
	plan := planSpec{enter: map[int]string{1: "/"}}.build()
	plan.usrMerged = map[string]string{}
	plan.readUsrMerged(a)
	r := runWalk(a, plan)
	return &r, plan
}

// ubuntuHeader is the run header the os collector fills in before the walk
// runs; the join chooses the reference list from it and from nothing else.
func ubuntuHeader() *facts.Run {
	return &facts.Run{Host: facts.Host{OSRelease: facts.OSRelease{ID: "ubuntu", VersionID: "22.04"}}}
}

// mergedUsrLinks is what a Debian-family host has at the top level.
func mergedUsrLinks() map[string]string {
	return map[string]string{"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib"}
}

// dpkgFiles maps the database files this suite serves. The package name of a
// list comes from the FILE name, so util-linux is served under its
// architecture-qualified name and python3.11 under its own.
func dpkgFiles() map[string]string {
	return map[string]string{
		"/var/lib/dpkg/status":                     "dpkg.status.walk",
		"/var/lib/dpkg/info/util-linux:amd64.list": "dpkg.info/util-linux.list",
		"/var/lib/dpkg/info/passwd.list":           "dpkg.info/passwd.list",
		"/var/lib/dpkg/info/python3.11.list":       "dpkg.info/python3.list",
		"/var/lib/dpkg/info/at.list":               "dpkg.info/at.list",
		"/var/lib/dpkg/info/foo-tools.list":        "dpkg.info/foo-tools.list",
		"/var/lib/dpkg/info/pkg-a.list":            "dpkg.info/pkg-a.list",
		"/var/lib/dpkg/info/sysstat.list":          "dpkg.info/sysstat.list",
		"/var/lib/dpkg/diversions":                 "dpkg.diversions.sample",
	}
}

func dpkgAccess() *fsAccess {
	return &fsAccess{files: dpkgFiles(), links: mergedUsrLinks()}
}

// useReferenceList swaps the embedded loader for one serving the fixture
// list, and only for the release it names — a join that ignored the run
// header would read the list of a release the host is not.
func useReferenceList(t *testing.T, id, versionID string) {
	t.Helper()
	fixture := readFixtureList(t)
	orig := loadReferenceList
	t.Cleanup(func() { loadReferenceList = orig })
	loadReferenceList = func(gotID, gotVersion string) (*suid.List, bool, error) {
		if gotID != id || gotVersion != versionID {
			return nil, false, nil
		}
		return fixture, true, nil
	}
}

func readFixtureList(t *testing.T) *suid.List {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "suid.reference.ubuntu-22.04.json"))
	if err != nil {
		t.Fatalf("fixture list: %v", err)
	}
	var l suid.List
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("fixture list: %v", err)
	}
	return &l
}

// checkRow asserts the named fields of one row and says which row failed.
func checkRow(t *testing.T, rows []map[string]any, p string, want map[string]any) {
	t.Helper()
	row := rowFor(t, rows, p)
	for _, k := range sortedKeys(want) {
		if got := row[k]; !reflect.DeepEqual(got, want[k]) {
			t.Errorf("%s: %s = %#v, want %#v", p, k, got, want[k])
		}
	}
}

// listOf names the list a suid candidate ended in, which is the whole point
// of W-7: walk.suid_sgid is judged, walk.suid_sgid_unverified only warns.
func listOf(r *walkResult, p string) string {
	if slices.Contains(rowPaths(r.lists.suid), p) {
		return "suid_sgid"
	}
	if slices.Contains(rowPaths(r.lists.suidUnverified), p) {
		return "suid_sgid_unverified"
	}
	return "neither"
}

func checkList(t *testing.T, r *walkResult, p, want string) {
	t.Helper()
	if got := listOf(r, p); got != want {
		t.Errorf("%s is in %s, want %s", p, got, want)
	}
}

func checkSorted(t *testing.T, r *walkResult) {
	t.Helper()
	for name, rows := range map[string][]map[string]any{
		"suid_sgid": r.lists.suid, "suid_sgid_unverified": r.lists.suidUnverified,
	} {
		paths := rowPaths(rows)
		if !slices.IsSorted(paths) {
			t.Errorf("%s is not sorted after the split: %v", name, paths)
		}
	}
}

// --- rpm ----------------------------------------------------------------

// On an rpm host the file table decides every candidate: a path it carries
// is declared by the mode rpm recorded, a path it does not carry is
// unpackaged. Nothing is ever unverifiable, so walk.suid_sgid_unverified
// stays empty.
func TestJoinRPMDecidesEveryCandidate(t *testing.T) {
	a := &fsAccess{
		dirs: map[string]bool{"/var/lib/rpm": true},
		cmds: map[string]cmdResult{cmdKey(rpmCommand): {file: "rpm.qa-files.sample"}},
	}
	r, plan := joinWalk(t, a)
	out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)

	if out.family != "rpm" || out.failed != nil || out.truncated {
		t.Fatalf("outcome = %+v, want the rpm family and no failure", out)
	}
	if out.source == nil || out.source.Kind != "command" || out.source.Cmd != cmdKey(rpmCommand) {
		t.Errorf("source = %+v, want the rpm command", out.source)
	}

	checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{
		"package": "util-linux", "package_declared": true, "reference": "rpmdb",
		"declared_mode": 0o4755, "declared_owner": "root", "declared_group": "root", "declared_path": "",
	})
	// The table says 0755: the bit on disk is not one rpm declared.
	checkRow(t, r.lists.suid, "/usr/bin/python3", map[string]any{
		"package": "python3", "package_declared": false, "reference": "rpmdb", "declared_mode": 0o755,
	})
	checkRow(t, r.lists.suid, "/opt/x/tool", map[string]any{
		"package": "", "package_declared": false, "reference": "unpackaged",
		"declared_mode": nil, "declared_owner": "", "declared_group": "",
	})
	if n := len(r.lists.suidUnverified); n != 0 {
		t.Errorf("suid_sgid_unverified has %d rows (%v); the rpm database decides every candidate", n, rowPaths(r.lists.suidUnverified))
	}

	// world_writable is judged on the other-write bit of the same table.
	checkRow(t, r.lists.worldWritable, "/var/lib/x/spool", map[string]any{
		"package": "spooler", "package_declared": true, "reference": "rpmdb",
	})
	checkRow(t, r.lists.worldWritable, "/srv/share", map[string]any{
		"package": "web-assets", "package_declared": false, "reference": "rpmdb",
	})
	// A hidden entry carries no bit to compare: being owned is the answer.
	checkRow(t, r.lists.hidden, "/usr/sbin/.h", map[string]any{
		"package": "sysstat", "package_declared": true, "reference": "rpmdb",
	})
	checkRow(t, r.lists.hidden, "/opt/x/.hidden", map[string]any{
		"package": "", "package_declared": false, "reference": "unpackaged",
	})

	// The join fills fields; it never invents one. These are the thirteen
	// walk.suid_sgid names the registry describes and the three of
	// walk.world_writable's that the join owns.
	wantKeys := []string{
		"declared_group", "declared_mode", "declared_owner", "declared_path", "gid", "mode",
		"package", "package_declared", "path", "reference", "setgid", "setuid", "uid",
	}
	if got := sortedKeys(rowFor(t, r.lists.suid, "/usr/bin/su")); !slices.Equal(got, wantKeys) {
		t.Errorf("suid row fields = %v, want %v", got, wantKeys)
	}
	wantWW := []string{"gid", "kind", "package", "package_declared", "path", "reference", "sticky", "uid"}
	if got := sortedKeys(rowFor(t, r.lists.worldWritable, "/srv/share")); !slices.Equal(got, wantWW) {
		t.Errorf("world_writable row fields = %v, want %v", got, wantWW)
	}
	checkSorted(t, r)
}

// A join that did not finish must say so: main §6.5 row 6 turns the
// envelope into ERROR, which is the truth about a table nobody could read.
// A capped capture is different — what was parsed is real — so it is ok with
// truncated set.
func TestJoinRPMFailureShapes(t *testing.T) {
	cases := []struct {
		name       string
		result     cmdResult
		wantStatus facts.Status
		truncated  bool
	}{
		{"exit 1", cmdResult{file: "rpm.qa-files.sample", exitCode: 1, stderr: "rpm: database is locked\n"}, facts.StatusError, false},
		{"never started", cmdResult{err: os.ErrNotExist, exitCode: -1}, facts.StatusError, false},
		{"timed out", cmdResult{timedOut: true, exitCode: -1}, facts.StatusTimeout, false},
		{"capped output", cmdResult{file: "rpm.qa-files.sample", truncated: true}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &fsAccess{
				dirs: map[string]bool{"/var/lib/rpm": true},
				cmds: map[string]cmdResult{cmdKey(rpmCommand): c.result},
			}
			r, plan := joinWalk(t, a)
			out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
			if out.truncated != c.truncated {
				t.Errorf("truncated = %v, want %v", out.truncated, c.truncated)
			}
			if c.wantStatus == "" {
				if out.failed != nil {
					t.Fatalf("failed = %+v, want nil: a capped capture is still an answer", out.failed)
				}
				// and what the capture did carry was still joined
				checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{"package": "util-linux", "reference": "rpmdb"})
				return
			}
			if out.failed == nil {
				t.Fatalf("failed = nil, want a %s envelope", c.wantStatus)
			}
			if out.failed.Status != c.wantStatus {
				t.Errorf("status = %s, want %s", out.failed.Status, c.wantStatus)
			}
			if !strings.Contains(out.failed.Reason, "rpm -qa") {
				t.Errorf("reason %q does not name the command", out.failed.Reason)
			}
			if out.failed.Source == nil || out.failed.Source.Cmd != cmdKey(rpmCommand) {
				t.Errorf("source = %+v, want the rpm command", out.failed.Source)
			}
			// A failed join leaves the rows as the traversal wrote them.
			checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{"package": "", "reference": "unpackaged"})
		})
	}
}

// The join's memory is bounded by the candidates, never by the host's file
// count: a table with a thousand lines leaves exactly the candidate rows.
func TestJoinIsBoundedByCandidates(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "filler-%d\t0100644\troot\troot\t/usr/share/filler/%d\n", i, i)
	}
	b.WriteString("util-linux\t0104755\troot\troot\t/usr/bin/su\n")
	b.WriteString("python3\t0100755\troot\troot\t/usr/bin/python3\n")
	b.WriteString("sysstat\t0100600\troot\troot\t/usr/sbin/.h\n")
	cands := map[string]bool{"/usr/bin/su": true, "/usr/bin/python3": true, "/usr/sbin/.h": true}

	table, err := rpmFileTable([]byte(b.String()), cands)
	if err != nil {
		t.Fatalf("rpmFileTable: %v", err)
	}
	if len(table) != 3 {
		t.Errorf("table holds %d rows (%v), want the 3 candidates", len(table), sortedKeys(table))
	}
}

// A line longer than the scanner's buffer stops the stream; the join says so
// rather than reporting the rest of the table as unpackaged.
func TestJoinRPMOverlongLineIsAnError(t *testing.T) {
	line := "pkg\t0100644\troot\troot\t/usr/share/" + strings.Repeat("x", 70<<10) + "\n"
	if _, err := rpmFileTable([]byte(line), map[string]bool{"/usr/bin/su": true}); err == nil {
		t.Fatal("rpmFileTable accepted a line over the buffer")
	}
}

// --- dpkg ---------------------------------------------------------------

// Every row of W-7's table, on one host each, with the reference list the
// release has.
func TestJoinDpkgDecisionTable(t *testing.T) {
	t.Run("versions equal", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		r, plan := joinWalk(t, a)
		if !reflect.DeepEqual(plan.usrMerged, map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib"}) {
			t.Fatalf("usrMerged = %+v", plan.usrMerged)
		}
		out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
		if out.family != "dpkg" || out.failed != nil || out.truncated {
			t.Fatalf("outcome = %+v, want the dpkg family and no failure", out)
		}
		if out.source == nil || out.source.Kind != "file" || out.source.Path != "/var/lib/dpkg/info" {
			t.Errorf("source = %+v, want the dpkg info directory", out.source)
		}

		// in packages, listed WITH the bit -> declared, whatever the
		// version; the .list spells the path pre-merge and says so.
		checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{
			"package": "util-linux", "package_declared": true, "reference": "list",
			"declared_mode": 0o4755, "declared_owner": "root", "declared_group": "root",
			"declared_path": "/bin/su",
		})
		checkList(t, r, "/usr/bin/su", "suid_sgid")
		checkRow(t, r.lists.suid, "/usr/bin/passwd", map[string]any{
			"package": "passwd", "package_declared": true, "reference": "list",
			"declared_owner": "root", "declared_group": "shadow", "declared_path": "",
		})
		// in packages, version equal, listed WITHOUT the bit -> the bit is
		// a finding, and the row is judged.
		checkRow(t, r.lists.suid, "/usr/bin/python3", map[string]any{
			"package": "python3.11", "package_declared": false, "reference": "list", "declared_mode": 0o755,
		})
		checkList(t, r, "/usr/bin/python3", "suid_sgid")
		// the package sets the mode from its maintainer script
		checkRow(t, r.lists.suidUnverified, "/usr/bin/at", map[string]any{
			"package": "at", "package_declared": false, "reference": "postinst", "declared_mode": nil,
		})
		// packaged, but the list covers no such package
		checkRow(t, r.lists.suidUnverified, "/usr/bin/foo", map[string]any{
			"package": "foo-tools", "package_declared": false, "reference": "unlisted",
		})
		// no package owns it
		checkRow(t, r.lists.suid, "/opt/x/tool", map[string]any{
			"package": "", "package_declared": false, "reference": "unpackaged",
		})
		checkList(t, r, "/opt/x/tool", "suid_sgid")

		// world_writable is decided the same way, on the other-write bit:
		// sysstat is covered and the list holds no such entry, so the
		// directory's mode is nobody's declaration.
		checkRow(t, r.lists.worldWritable, "/var/lib/x/spool", map[string]any{
			"package": "sysstat", "package_declared": false, "reference": "list",
		})
		checkRow(t, r.lists.worldWritable, "/srv/share", map[string]any{
			"package": "", "package_declared": false, "reference": "unpackaged",
		})
		checkSorted(t, r)
	})

	t.Run("installed version differs", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		a.files["/var/lib/dpkg/status"] = "dpkg.status.walk-newer"
		r, plan := joinWalk(t, a)
		joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)

		// a bit the list SAW is still a declaration on an upgraded host
		checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{
			"package_declared": true, "reference": "list",
		})
		checkList(t, r, "/usr/bin/su", "suid_sgid")
		// a bit the list did not see, on a version it never read, cannot be
		// judged either way
		checkRow(t, r.lists.suidUnverified, "/usr/bin/python3", map[string]any{
			"package": "python3.11", "package_declared": false, "reference": "version_mismatch",
		})
		checkList(t, r, "/usr/bin/python3", "suid_sgid_unverified")
		checkSorted(t, r)
	})

	t.Run("no list for the release", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		r, plan := joinWalk(t, a)
		hdr := &facts.Run{Host: facts.Host{OSRelease: facts.OSRelease{ID: "debian", VersionID: "12"}}}
		out := joinCandidates(context.Background(), a, hdr, plan, r)
		if out.failed != nil {
			t.Fatalf("failed = %+v; a release with no list is not a failure", out.failed)
		}
		for _, p := range []string{"/usr/bin/su", "/usr/bin/passwd", "/usr/bin/python3", "/usr/bin/x.distrib"} {
			checkRow(t, r.lists.suidUnverified, p, map[string]any{"package_declared": false, "reference": "none"})
			checkList(t, r, p, "suid_sgid_unverified")
		}
		// An unpackaged path needs no list to be decided.
		checkRow(t, r.lists.suid, "/opt/x/tool", map[string]any{"reference": "unpackaged"})
		checkList(t, r, "/opt/x/tool", "suid_sgid")
	})
}

// dpkg-statoverride is what the administrator told dpkg to enforce on every
// upgrade, so it outranks the reference list — and it declares a path no
// package owns.
func TestJoinDpkgStatoverrideWinsFirst(t *testing.T) {
	useReferenceList(t, "ubuntu", "22.04")
	a := dpkgAccess()
	a.files["/var/lib/dpkg/statoverride"] = "dpkg.statoverride.sample"
	r, plan := joinWalk(t, a)
	joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)

	// The override is written in the pre-merge spelling and still matches.
	checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{
		"package": "util-linux", "package_declared": true, "reference": "statoverride",
		"declared_mode": 0o4755, "declared_owner": "root", "declared_group": "root",
	})
	checkRow(t, r.lists.suid, "/opt/x/tool", map[string]any{
		"package": "", "package_declared": true, "reference": "statoverride",
		"declared_mode": 0o4755, "declared_owner": "root", "declared_group": "root",
	})
	checkList(t, r, "/opt/x/tool", "suid_sgid")
}

// A diverted file sits under its diverted-to name while the package that
// ships it still lists the original, so the join looks the candidate up
// under the name the package used.
func TestJoinDpkgDiversions(t *testing.T) {
	useReferenceList(t, "ubuntu", "22.04")
	a := dpkgAccess()
	r, plan := joinWalk(t, a)
	joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)

	checkRow(t, r.lists.suid, "/usr/bin/x.distrib", map[string]any{
		"package": "pkg-a", "package_declared": true, "reference": "list",
		"declared_mode": 0o4755, "declared_path": "/usr/bin/x",
	})
	checkList(t, r, "/usr/bin/x.distrib", "suid_sgid")

	// Without the diversions file the same candidate is nobody's.
	a2 := dpkgAccess()
	delete(a2.files, "/var/lib/dpkg/diversions")
	r2, plan2 := joinWalk(t, a2)
	out := joinCandidates(context.Background(), a2, ubuntuHeader(), plan2, r2)
	if out.failed != nil {
		t.Fatalf("failed = %+v; a host with no diversions file is ordinary", out.failed)
	}
	checkRow(t, r2.lists.suid, "/usr/bin/x.distrib", map[string]any{
		"package": "", "reference": "unpackaged", "declared_path": "",
	})
}

// A hidden entry carries no bit, so ownership alone answers and neither the
// reference list nor an override is consulted.
func TestJoinDpkgHidden(t *testing.T) {
	useReferenceList(t, "ubuntu", "22.04")
	a := dpkgAccess()
	r, plan := joinWalk(t, a)
	joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)

	checkRow(t, r.lists.hidden, "/usr/sbin/.h", map[string]any{
		"package": "sysstat", "package_declared": true, "reference": "dpkgdb",
	})
	checkRow(t, r.lists.hidden, "/opt/x/.hidden", map[string]any{
		"package": "", "package_declared": false, "reference": "unpackaged",
	})
}

// A database file that cannot be read makes the join's answer the read's own
// status, with the path in the reason (C3); a file that was only truncated
// still answered, so far as it went.
func TestJoinDpkgFailureShapes(t *testing.T) {
	t.Run("statoverride denied", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		a.files["/var/lib/dpkg/statoverride"] = "dpkg.statoverride.sample"
		a.fails = map[string]error{"/var/lib/dpkg/statoverride": fmt.Errorf("open: %w", unix.EACCES)}
		r, plan := joinWalk(t, a)
		out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
		if out.failed == nil || out.failed.Status != facts.StatusDenied {
			t.Fatalf("failed = %+v, want denied", out.failed)
		}
		if !strings.Contains(out.failed.Reason, "/var/lib/dpkg/statoverride") {
			t.Errorf("reason %q does not name the file", out.failed.Reason)
		}
	})

	t.Run("a list read that was capped", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		a.truncated = map[string]bool{"/var/lib/dpkg/info/util-linux:amd64.list": true}
		r, plan := joinWalk(t, a)
		out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
		if out.failed != nil {
			t.Fatalf("failed = %+v, want nil: a capped read is still an answer", out.failed)
		}
		if !out.truncated {
			t.Error("truncated = false, want true")
		}
		// what the partial read did carry was still joined
		checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{"package": "util-linux"})
	})

	t.Run("the info directory cannot be listed", func(t *testing.T) {
		useReferenceList(t, "ubuntu", "22.04")
		a := dpkgAccess()
		a.deniedDirs = map[string]bool{"/var/lib/dpkg/info": true}
		r, plan := joinWalk(t, a)
		out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
		if out.failed == nil || out.failed.Status != facts.StatusDenied {
			t.Fatalf("failed = %+v, want denied", out.failed)
		}
		if !strings.Contains(out.failed.Reason, "/var/lib/dpkg/info") {
			t.Errorf("reason %q does not name the directory", out.failed.Reason)
		}
	})

	t.Run("a reference list that will not decode", func(t *testing.T) {
		orig := loadReferenceList
		t.Cleanup(func() { loadReferenceList = orig })
		loadReferenceList = func(string, string) (*suid.List, bool, error) {
			return nil, false, fmt.Errorf("ubuntu-22.04.json: unexpected end of JSON input")
		}
		a := dpkgAccess()
		r, plan := joinWalk(t, a)
		out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
		if out.failed == nil || out.failed.Status != facts.StatusError {
			t.Fatalf("failed = %+v, want an error", out.failed)
		}
		if !strings.Contains(out.failed.Reason, "ubuntu-22.04.json") {
			t.Errorf("reason %q does not name the list", out.failed.Reason)
		}
	})
}

// --- neither family ------------------------------------------------------

// A host with no package database cannot be joined at all; absent is what
// absent_means: manual turns into MANUAL, which is the honest verdict.
func TestJoinNoDatabase(t *testing.T) {
	a := &fsAccess{}
	r, plan := joinWalk(t, a)
	out := joinCandidates(context.Background(), a, ubuntuHeader(), plan, r)
	if out.family != "none" {
		t.Errorf("family = %q, want none", out.family)
	}
	if out.failed == nil || out.failed.Status != facts.StatusAbsent || out.failed.Reason != "no package database" {
		t.Fatalf("failed = %+v, want absent with the fixed reason", out.failed)
	}
	if out.source != nil {
		t.Errorf("source = %+v, want none", out.source)
	}
	// Nothing was decided, and nothing was invented either.
	checkRow(t, r.lists.suid, "/usr/bin/su", map[string]any{
		"package": "", "package_declared": false, "reference": "unpackaged",
	})
}

// detectFamily reads the two artefacts patch.go reads, and the dpkg database
// wins on a host that has both (a converted host keeps an rpm directory).
func TestDetectFamily(t *testing.T) {
	cases := []struct {
		name string
		a    *fsAccess
		want string
	}{
		{"dpkg", &fsAccess{files: map[string]string{"/var/lib/dpkg/status": "dpkg.status.walk"}}, "dpkg"},
		{"rpm", &fsAccess{dirs: map[string]bool{"/var/lib/rpm": true}}, "rpm"},
		{"both", &fsAccess{files: map[string]string{"/var/lib/dpkg/status": "dpkg.status.walk"}, dirs: map[string]bool{"/var/lib/rpm": true}}, "dpkg"},
		{"neither", &fsAccess{}, "none"},
		// A directory this process may not stat still occupies the path.
		{"rpm denied", &fsAccess{fails: map[string]error{"/var/lib/rpm": fmt.Errorf("stat: %w", unix.EACCES)}}, "rpm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := detectFamily(c.a); got != c.want {
				t.Errorf("detectFamily = %q, want %q", got, c.want)
			}
		})
	}
}
