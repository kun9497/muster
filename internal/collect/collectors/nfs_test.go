//go:build linux

package collectors

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// The host paths the nfs collector reads, spelled here as literals so a test
// asserts against the real path rather than against whatever the collector
// happens to have named its constant.
const (
	testExportsPath     = "/etc/exports"
	testExportsFragment = "/etc/exports.d/10-x.exports"
)

// nfsAccess seeds every map fsAccess exposes (files, cmds, fails, dirs,
// stats, truncated) so a test may assign into any of them after construction
// without tripping a nil-map panic (the R226/I-20 lesson).
func nfsAccess(files map[string]string, cmds map[string]cmdResult) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &fsAccess{
		files:     files,
		cmds:      cmds,
		fails:     map[string]error{},
		dirs:      map[string]bool{},
		stats:     map[string]statResult{},
		truncated: map[string]bool{},
	}
}

// A path with no client spec exports to the world; no_root_squash is
// derived from the options the other client spec carries. Records sort by
// (path, client), so "/srv/data" (d < s) comes before "/srv/share".
func TestNfsExportsWorldAndRootSquash(t *testing.T) {
	a := nfsAccess(map[string]string{"/etc/exports": "exports.world"}, nil)
	b := buildBegun(t, "nfs", a)
	recs := okList(t, b, "nfs.exports")
	if len(recs) != 2 {
		t.Fatalf("exports %v, want 2 records", recs)
	}
	restricted := recs[0].(map[string]any)
	if restricted["path"] != "/srv/data" || restricted["client"] != "192.0.2.0/24" ||
		restricted["wildcard"] != false || restricted["root_squash"] != false {
		t.Errorf("restricted export %v", restricted)
	}
	world := recs[1].(map[string]any)
	if world["path"] != "/srv/share" || world["client"] != "*" ||
		world["wildcard"] != true || world["root_squash"] != true {
		t.Errorf("world export %v", world)
	}
	if list := okList(t, b, "nfs.exports_source"); len(list) != 1 || list[0] != "/etc/exports" {
		t.Errorf("exports_source %v, want [/etc/exports]", list)
	}
	// Ruling JR-10: one file read is cited as that file.
	if src := env(t, b, "nfs.exports").Source; src == nil || src.Kind != "file" || src.Path != testExportsPath {
		t.Errorf("nfs.exports source %+v, want the one file that was read", src)
	}
	if got := b.Worst("nfs"); got != facts.StatusOK {
		t.Errorf(`Worst("nfs") = %s, want ok`, got)
	}
}

// exports.d fragments are read in sorted order; a missing /etc/exports with
// fragments present still parses (the main file's absence is not a
// finding).
func TestNfsExportsDFragments(t *testing.T) {
	a := nfsAccess(map[string]string{
		"/etc/exports.d/10-extra.exports": "exports.d_10-extra.exports",
		"/etc/exports.d/05-first.exports": "exports.d_05-first.exports",
	}, nil)
	b := buildBegun(t, "nfs", a)

	srcList := okList(t, b, "nfs.exports_source")
	want := []string{"/etc/exports.d/05-first.exports", "/etc/exports.d/10-extra.exports"}
	if len(srcList) != len(want) {
		t.Fatalf("exports_source %v, want %v", srcList, want)
	}
	for i, w := range want {
		if srcList[i] != w {
			t.Errorf("exports_source[%d] = %v, want %s (fragments must be read in sorted order)", i, srcList[i], w)
		}
	}

	recs := okList(t, b, "nfs.exports")
	if len(recs) != 2 {
		t.Fatalf("exports %v, want 2 records", recs)
	}
	first := recs[0].(map[string]any)
	if first["path"] != "/srv/extra" {
		t.Errorf("first record %v, want path /srv/extra (sorted before /srv/first)", first)
	}
	second := recs[1].(map[string]any)
	if second["path"] != "/srv/first" {
		t.Errorf("second record %v, want path /srv/first", second)
	}

	// Ruling JR-10: the Source names the files ACTUALLY read. This host has
	// no /etc/exports at all, so citing it would send a reader — and a
	// remediation — to a file the collector never opened; several files read
	// take the repository's derived shape, in read order.
	src := env(t, b, "nfs.exports").Source
	if src == nil {
		t.Fatalf("nfs.exports carries no source")
	}
	if src.Path == testExportsPath {
		t.Errorf("nfs.exports cites %s, which is not present on this host", testExportsPath)
	}
	if src.Kind != "derived" || len(src.Inputs) != len(want) {
		t.Fatalf("nfs.exports source %+v, want the derived shape over both fragments", src)
	}
	for i, w := range want {
		if src.Inputs[i].Kind != "file" || src.Inputs[i].Path != w {
			t.Errorf("nfs.exports source input[%d] = %+v, want the file %s", i, src.Inputs[i], w)
		}
	}
	if ssrc := env(t, b, "nfs.exports_source").Source; ssrc == nil || ssrc.Kind != "derived" {
		t.Errorf("nfs.exports_source source %+v, want the same derived shape", ssrc)
	}
}

// exportfs -v unavailable (an unmapped command, as when it is absent or a
// non-root run fails) leaves exports_runtime_collected a plain ok:false,
// never an error/denied envelope, and never worsens Worst("nfs").
func TestNfsExportfsUnavailableIsNotAnError(t *testing.T) {
	a := nfsAccess(map[string]string{"/etc/exports": "exports.world"}, nil)
	b := buildBegun(t, "nfs", a)
	e := env(t, b, "nfs.exports_runtime_collected")
	if e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("exports_runtime_collected %+v, want ok false (exportfs unmapped)", e)
	}
	if got := b.Worst("nfs"); got != facts.StatusOK {
		t.Errorf(`Worst("nfs") = %s, want ok`, got)
	}
}

// An existing-but-unreadable /etc/exports is denied on nfs.exports and
// nfs.exports_source (C3), never a silent empty list.
func TestNfsUnreadableExportsIsDenied(t *testing.T) {
	a := nfsAccess(nil, nil)
	a.fails["/etc/exports"] = os.ErrPermission
	b := buildBegun(t, "nfs", a)
	if e := env(t, b, "nfs.exports"); e.Status != facts.StatusDenied {
		t.Errorf("nfs.exports %+v, want denied", e)
	}
	if e := env(t, b, "nfs.exports_source"); e.Status != facts.StatusDenied {
		t.Errorf("nfs.exports_source %+v, want denied", e)
	}
	// The corroboration side is unaffected by a denied read.
	if e := env(t, b, "nfs.exports_runtime_collected"); e.Status != facts.StatusOK {
		t.Errorf("exports_runtime_collected %+v, want ok (unaffected by a denied read)", e)
	}
}

// No exports files at all (no /etc/exports, no exports.d fragments) is a
// definite "nothing exported" — ok:[], never missing.
func TestNfsNoExportsIsEmptyNotMissing(t *testing.T) {
	a := nfsAccess(nil, nil)
	b := buildBegun(t, "nfs", a)
	if recs := okList(t, b, "nfs.exports"); len(recs) != 0 {
		t.Errorf("exports %v, want empty", recs)
	}
	if list := okList(t, b, "nfs.exports_source"); len(list) != 0 {
		t.Errorf("exports_source %v, want empty", list)
	}
	// Ruling JR-10: with nothing read there is nothing to cite.
	if src := env(t, b, "nfs.exports").Source; src != nil {
		t.Errorf("nfs.exports source %+v, want none when no export file was read", src)
	}
}

// exports(5): '#' introduces a comment anywhere on a line, not only at its
// start, and a BSD-style "-options" defaults line (no client, options
// prefixed with "-") is not valid Linux exports(5) syntax. Round-1 review
// finding 1 (BLOCKING) + finding 3 (LOW).
func TestNfsTrailingCommentIsNotAClient(t *testing.T) {
	a := nfsAccess(map[string]string{"/etc/exports": "exports.trailing_comment"}, nil)
	b := buildBegun(t, "nfs", a)
	recs := okList(t, b, "nfs.exports")
	if len(recs) != 1 {
		t.Fatalf("exports %v, want exactly 1 record (a trailing comment must not mint phantom clients, and the BSD-style \"-rw\" line must not mint a bogus one)", recs)
	}
	rec := recs[0].(map[string]any)
	if rec["path"] != "/srv5" || rec["client"] != "gss/krb5" || rec["options"] != "rw" ||
		rec["wildcard"] != false || rec["root_squash"] != true {
		t.Errorf("record %v", rec)
	}
}

// exportfs's classic space-before-'(' trap: "client (options)" (a SPACE
// before the parenthesis) is two separate client specs — the bare host with
// default options, and a second, world-exporting "(options)" entry — never
// one "client(options)" pair. Round-1 review finding 2 (BLOCKING).
func TestNfsSpaceBeforeOptionsExportsToTheWorld(t *testing.T) {
	a := nfsAccess(map[string]string{"/etc/exports": "exports.space_before_options"}, nil)
	b := buildBegun(t, "nfs", a)
	recs := okList(t, b, "nfs.exports")
	if len(recs) != 2 {
		t.Fatalf("exports %v, want 2 records (space before '(' is a second, world, client spec)", recs)
	}
	// Sorted by (path, client): "*" < "192.0.2.5" lexically.
	world := recs[0].(map[string]any)
	if world["client"] != "*" || world["wildcard"] != true || world["root_squash"] != true || world["options"] != "rw" {
		t.Errorf("world export %v, want client \"*\", wildcard true, root_squash true, options \"rw\"", world)
	}
	host := recs[1].(map[string]any)
	if host["client"] != "192.0.2.5" || host["wildcard"] != false || host["root_squash"] != true {
		t.Errorf("host export %v, want the bare host with default options", host)
	}
}

// files.etc_exports.* — the nine writePermFacts leaves for /etc/exports,
// written by the FILES collector (C1: a fixed path's permission facts
// belong there, even though this file's nfs collector owns the export
// CONTENT). This is the caller test for the writePermFacts("/etc/exports")
// call site added to files.go's runFiles.
func TestFilesEtcExportsPermissionFacts(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/exports": "exports.world"}}
	b := build(t, "files", a)
	if e := env(t, b, "files.etc_exports.mode"); e.Status != facts.StatusOK || e.Value != 420 {
		t.Errorf("files.etc_exports.mode %+v, want ok 420 (0644)", e)
	}
	if e := env(t, b, "files.etc_exports.uid"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("files.etc_exports.uid %+v, want ok 0", e)
	}
	if e := env(t, b, "files.etc_exports.acl_present"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("files.etc_exports.acl_present %+v, want ok false", e)
	}
}

// A missing /etc/exports leaves every files.etc_exports.* leaf absent, the
// established 2A template shape (a Stat failure reaches every leaf).
func TestFilesEtcExportsAbsentWhenMissing(t *testing.T) {
	a := &fsAccess{}
	b := build(t, "files", a)
	for _, k := range []string{"files.etc_exports.mode", "files.etc_exports.uid", "files.etc_exports.acl_present"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s %+v, want absent", k, e)
		}
	}
}

// Ruling JR-2 (R70). The read primitive answers a file past the 1 MiB cap
// with data[:limit], Truncated true and NO error, so a parse of that prefix
// is a partial answer wearing a complete answer's clothes: a wildcard export
// written past the cap is invisible and nfs.exports would PASS the control
// on it. Both judged leaves go ABSENT naming the file that was cut — the
// snmp judged-list shape, and the exact reason
// controls/testdata/muster.service.nfs_export_access/manual-parse-incomplete.json
// models — while the corroboration leaf is still recorded and the run stays
// complete.
func TestNfsTruncatedReadIsAbsent(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		cut   string
	}{
		{"main file", map[string]string{testExportsPath: "exports.world"}, testExportsPath},
		{"fragment", map[string]string{
			testExportsPath:     "exports.world",
			testExportsFragment: "exports.d_10-extra.exports",
		}, testExportsFragment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := nfsAccess(tc.files, nil)
			a.truncated[tc.cut] = true
			b := buildBegun(t, "nfs", a)
			for _, k := range []string{"nfs.exports", "nfs.exports_source"} {
				e := env(t, b, k)
				if e.Status != facts.StatusAbsent {
					t.Errorf("%s %+v, want absent: a read cut at the cap is never published as the whole answer", k, e)
				}
				if !strings.Contains(e.Reason, tc.cut) {
					t.Errorf("%s reason %q, want the cut file %s named", k, e.Reason, tc.cut)
				}
			}
			if e := env(t, b, "nfs.exports_runtime_collected"); e.Status != facts.StatusOK {
				t.Errorf("exports_runtime_collected %+v, want ok (the corroboration is still recorded)", e)
			}
			if got := b.Worst("nfs"); got != facts.StatusOK {
				t.Errorf(`Worst("nfs") = %s, want ok (a cap is not an environment failure)`, got)
			}
		})
	}
}

// Ruling JR-1. The sshd Include precedent: a fragment that EXISTS but cannot
// be read is the answer for every value it could set (C3) — publishing the
// other files' exports as complete would hide whatever this one adds. A
// `continue` in that branch is silent and this is the test that catches it.
func TestNfsUnreadableFragmentIsDenied(t *testing.T) {
	a := nfsAccess(map[string]string{
		testExportsPath:     "exports.world",
		testExportsFragment: "exports.d_10-extra.exports",
	}, nil)
	a.fails[testExportsFragment] = os.ErrPermission
	b := buildBegun(t, "nfs", a)
	for _, k := range []string{"nfs.exports", "nfs.exports_source"} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s %+v, want denied: an unreadable fragment is never silently skipped", k, e)
		}
		if !strings.Contains(e.Reason, testExportsFragment) {
			t.Errorf("%s reason %q, want the fragment path named (C3: path-prefixed)", k, e.Reason)
		}
	}
	if got := b.Worst("nfs"); got != facts.StatusDenied {
		t.Errorf(`Worst("nfs") = %s, want denied`, got)
	}
}

// Ruling JR-6. This collector declares Needs "none", so a Glob that fails is
// an environment limitation, never an error — one error envelope ranks worst
// in Builder.Worst, flips run.complete and breaks the collect-contract leg.
// patch's identical branch already says unsupported; this mirrors it.
func TestNfsGlobFailureIsUnsupportedNotError(t *testing.T) {
	a := nfsAccess(map[string]string{testExportsPath: "exports.world"}, nil)
	a.globErr = errors.New("glob boom")
	b := buildBegun(t, "nfs", a)
	for _, k := range []string{"nfs.exports", "nfs.exports_source"} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s %+v, want unsupported", k, e)
		}
	}
	if e := env(t, b, "nfs.exports_runtime_collected"); e.Status != facts.StatusOK {
		t.Errorf("exports_runtime_collected %+v, want ok (still recorded)", e)
	}
	if got := b.Worst("nfs"); got != facts.StatusOK {
		t.Errorf(`Worst("nfs") = %s, want ok`, got)
	}
}

// Ruling JR-8. exportfs is corroboration, never the judged source, so both
// of its outcomes are a plain ok boolean citing the declared command — the
// success branch had no test at all before this one, which left the true
// value unobserved on every shape.
func TestNfsExportfsCorroborationIsRecorded(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		want     bool
	}{
		{"exportfs answers", 0, true},
		{"exportfs refuses", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := nfsAccess(map[string]string{testExportsPath: "exports.world"},
				map[string]cmdResult{cmdKey(exportfsCmd): {exitCode: tc.exitCode}})
			b := buildBegun(t, "nfs", a)
			e := env(t, b, "nfs.exports_runtime_collected")
			if e.Status != facts.StatusOK || e.Value != tc.want {
				t.Errorf("exports_runtime_collected %+v, want ok %v", e, tc.want)
			}
			if e.Source == nil || e.Source.Cmd != cmdKey(exportfsCmd) {
				t.Errorf("exports_runtime_collected source %+v, want the declared %q", e.Source, cmdKey(exportfsCmd))
			}
			if got := b.Worst("nfs"); got != facts.StatusOK {
				t.Errorf(`Worst("nfs") = %s, want ok (exportfs never worsens the run)`, got)
			}
		})
	}
}

// M-49 (extending M-10): Ruling JR-6 chose unsupported for a failed Glob
// because filepath.Glob could then only fail with ErrBadPattern — an
// environment limitation, never a privilege one. A directory the run may not
// search IS a privilege one, and unsupported ranks as ok in Builder.Worst,
// so it would quietly mislabel a denial as "this environment has no such
// mechanism" and let U-24 read the exports it could see as the whole set.
func TestNfsDeniedExportsDIsDeniedNotUnsupported(t *testing.T) {
	a := nfsAccess(nil, nil)
	a.deniedDirs = map[string]bool{"/etc/exports.d": true}
	b := buildBegun(t, "nfs", a)

	for _, k := range []string{"nfs.exports", "nfs.exports_source"} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s %+v, want denied (never unsupported, never error)", k, e)
		}
		if !strings.Contains(e.Reason, exportsDGlob) {
			t.Errorf("%s reason %q must name %s", k, e.Reason, exportsDGlob)
		}
	}
	if got := b.Worst("nfs"); got != facts.StatusDenied {
		t.Errorf(`Worst("nfs") = %s, want denied`, got)
	}
}
