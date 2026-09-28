//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// verifyTimeout is the --verify-timeout every armed test passes, so a reason
// that names the timeout can be told from the declared default.
const verifyTimeout = 7 * time.Minute

// pkgverifyRun runs the collector the way collect.Run does — Begin first, so
// Keys and Worst can be asked about what it wrote, and under the guard. arm
// is --deep without --no-verify.
func pkgverifyRun(t *testing.T, a collect.Access, arm bool) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	if arm {
		b.SetVerify(collect.VerifyOptions{Timeout: verifyTimeout})
	}
	b.Begin("pkgverify")
	c := collectorNamed(t, "pkgverify")
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("pkgverify: %v", err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("pkgverify touched undeclared targets: %v", v)
	}
	return b
}

// pkgverifyKeys is every registry key the pkgverify collector owns.
func pkgverifyKeys(t *testing.T) []string {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	var keys []string
	for _, e := range reg.Keys {
		if e.Collector == "pkgverify" {
			keys = append(keys, e.Key)
		}
	}
	slices.Sort(keys)
	if len(keys) != 7 {
		t.Fatalf("the registry names %d pkgverify keys, want 7: %v", len(keys), keys)
	}
	return keys
}

// dpkgVerifyHost is a dpkg host whose verify prints dpkg_verify.sample: two
// .list files and one .md5sums (one package without digests), a dpkg.cfg.d
// fragment excluding /usr/share/man/*, and a fragment whose NAME dpkg skips
// (it would exclude every /usr/lib row were it read).
func dpkgVerifyHost() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			dpkgStatusPath:                            "dpkg.status.sample",
			"/etc/dpkg/dpkg.cfg.d/excludes":           "dpkg.cfg.d-excludes",
			"/etc/dpkg/dpkg.cfg.d/excludes.dpkg-old":  "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/zz-other.conf":      "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/99_trailing-dot.":   "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/.hidden":            "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/UPPER_lower-09":     "dpkg.cfg.d-excludes",
			"/etc/dpkg/dpkg.cfg.d/bak~":               "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/space name":         "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/a.b":                "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/excludes.ucf-dist":  "dpkg.cfg.d-ignored",
			"/etc/dpkg/dpkg.cfg.d/excludes.dpkg-dist": "dpkg.cfg.d-ignored",
		},
		contents: map[string][]byte{
			"/var/lib/dpkg/info/a:amd64.list":    {},
			"/var/lib/dpkg/info/a:amd64.md5sums": {},
			"/var/lib/dpkg/info/b.list":          {},
		},
		cmds: map[string]cmdResult{cmdKey(dpkgVerifyCmd): {file: "dpkg_verify.sample"}},
	}
}

// rpmVerifyHost is an rpm host whose rpm -Va exits code with stdout file.
func rpmVerifyHost(r cmdResult) *fsAccess {
	return &fsAccess{
		dirs: map[string]bool{rpmDBDir: true},
		cmds: map[string]cmdResult{cmdKey(rpmVerifyCmd): r},
	}
}

func verifyRows(t *testing.T, b *collect.Builder, key string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	var order []string
	for _, v := range okList(t, b, key) {
		row, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: row %#v is not a record", key, v)
		}
		p, _ := row["path"].(string)
		out[p] = row
		order = append(order, p)
	}
	if !slices.IsSorted(order) {
		t.Errorf("%s is not sorted by path: %v", key, order)
	}
	return out
}

func verifyRecord(t *testing.T, b *collect.Builder, key string) map[string]any {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v", key, e)
	}
	m, ok := e.Value.(map[string]any)
	if !ok {
		t.Fatalf("%s: value %#v is not a record", key, e.Value)
	}
	return m
}

func attrsOf(row map[string]any) []string {
	var out []string
	for _, a := range row["attributes"].([]any) {
		out = append(out, a.(string))
	}
	return out
}

func strList(v any) []string {
	out := []string{}
	for _, s := range v.([]any) {
		out = append(out, s.(string))
	}
	return out
}

func wantCounts(t *testing.T, b *collect.Builder, want map[string]int) {
	t.Helper()
	got := verifyRecord(t, b, "packages.verify.filtered_counts")
	if len(got) != len(verifyFilterNames) {
		t.Errorf("filtered_counts has %d fields, want the %d filter names: %v", len(got), len(verifyFilterNames), got)
	}
	for _, name := range verifyFilterNames {
		if got[name] != want[name] {
			t.Errorf("filtered_counts[%s] = %v, want %d (all: %v)", name, got[name], want[name], got)
		}
	}
}

func wantFilter(t *testing.T, b *collect.Builder) {
	t.Helper()
	got := strList(env(t, b, "packages.verify.filter").Value)
	want := []string{"config", "doc", "dpkg_excluded", "ghost", "mtime_only", "unverifiable", "unchanged"}
	if !slices.Equal(got, want) {
		t.Errorf("filter %v, want %v", got, want)
	}
}

// --- the gate -------------------------------------------------------------

// Without --deep (or with --no-verify) Builder.Verify is false and nothing is
// written — even as root on a host whose verify would answer.
func TestPkgverifyWritesNothingWithoutDeep(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, dpkgVerifyHost(), false)
	if k := b.Keys("pkgverify"); len(k) != 0 {
		t.Fatalf("wrote %v without --deep", k)
	}
	if _, ok := b.Tree()["packages"]; ok {
		t.Errorf("a packages.* key reached the tree without --deep: %v", b.Tree()["packages"])
	}
	if w := b.Worst("pkgverify"); w != facts.StatusOK {
		t.Errorf("Worst %s, want ok", w)
	}
}

// Without root, complete is denied and nothing else is written (J-7).
func TestPkgverifyDeniedWithoutRoot(t *testing.T) {
	withEUID(t, 1000)
	b := pkgverifyRun(t, dpkgVerifyHost(), true)
	if k := b.Keys("pkgverify"); !slices.Equal(k, []string{"packages.verify.complete"}) {
		t.Fatalf("keys %v, want packages.verify.complete alone", k)
	}
	e := env(t, b, "packages.verify.complete")
	if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "root") {
		t.Errorf("complete %+v, want denied naming root", e)
	}
	if w := b.Worst("pkgverify"); w != facts.StatusDenied {
		t.Errorf("Worst %s, want denied", w)
	}
}

// --- dpkg -----------------------------------------------------------------

func TestPkgverifyDpkgShape(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, dpkgVerifyHost(), true)

	c := env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusOK || c.Value != true {
		t.Fatalf("complete %+v, want ok true", c)
	}
	if c.Source == nil || c.Source.Kind != "command" || c.Source.Cmd != "/usr/bin/dpkg --verify" {
		t.Errorf("complete source %+v, want the dpkg command", c.Source)
	}
	if e := env(t, b, "packages.verify.tool"); e.Value != "dpkg" {
		t.Errorf("tool %+v, want dpkg", e)
	}

	mod := verifyRows(t, b, "packages.verify.modified")
	paths := slices.Sorted(mapKeys(mod))
	if want := []string{"/usr/bin/tool", "/usr/lib/x/thing", "/usr/lib/y/secret"}; !slices.Equal(paths, want) {
		t.Fatalf("modified %v, want %v", paths, want)
	}
	if got := attrsOf(mod["/usr/bin/tool"]); !slices.Equal(got, []string{"digest"}) {
		t.Errorf("digest row attributes %v", got)
	}
	if mod["/usr/bin/tool"]["untested"] != 8 {
		t.Errorf("dpkg tests one column of nine: untested %v, want 8", mod["/usr/bin/tool"]["untested"])
	}
	if got := attrsOf(mod["/usr/lib/x/thing"]); !slices.Equal(got, []string{"mode"}) {
		t.Errorf("M row attributes %v", got)
	}
	secret := mod["/usr/lib/y/secret"]
	if got := attrsOf(secret); !slices.Equal(got, []string{"missing"}) || secret["note"] != "Permission denied" {
		t.Errorf("denied missing row %v, want attributes [missing] and the note kept", secret)
	}
	for p, row := range mod {
		if row["file_type"] != "" {
			t.Errorf("%s: file_type %q, want empty", p, row["file_type"])
		}
	}

	cfg := verifyRows(t, b, "packages.verify.modified_config")
	if len(cfg) != 1 || cfg["/etc/tool.conf"] == nil {
		t.Fatalf("modified_config %v, want the conffile alone", cfg)
	}
	if r := cfg["/etc/tool.conf"]; r["file_type"] != "config" || !slices.Equal(attrsOf(r), []string{"digest"}) {
		t.Errorf("conffile row %v", r)
	}

	wantFilter(t, b)
	wantCounts(t, b, map[string]int{"config": 1, "doc": 2})

	st := verifyRecord(t, b, "packages.verify.stats")
	if st["packages_without_digests"] != 1 {
		t.Errorf("packages_without_digests %v, want 1 (two .list, one .md5sums)", st["packages_without_digests"])
	}
	// Two fragments pass loadcfgdir's name rule — excludes and UPPER_lower-09
	// — and both carry the one glob; the eight skipped names never apply.
	if got := strList(st["dpkg_path_excludes"]); !slices.Equal(got, []string{"path-exclude=/usr/share/man/*", "path-exclude=/usr/share/man/*"}) {
		t.Errorf("dpkg_path_excludes %v", got)
	}
	if st["exit_code"] != 0 || st["lines"] != 6 || st["truncated"] != false {
		t.Errorf("stats %v", st)
	}
	if got := strList(st["unparsed_head"]); len(got) != 0 {
		t.Errorf("unparsed_head %v, want empty", got)
	}
	for _, k := range []string{"packages.verify.modified", "packages.verify.modified_config"} {
		if e := env(t, b, k); e.Source == nil || e.Source.Kind != "command" || e.Truncated {
			t.Errorf("%s envelope %+v", k, e)
		}
	}
	if w := b.Worst("pkgverify"); w != facts.StatusOK {
		t.Errorf("Worst %s, want ok", w)
	}
}

// dpkg's path-exclude is fnmatch WITHOUT FNM_PATHNAME: `*` crosses `/`, and a
// later path-include puts a path back (the last matching filter decides).
func TestPkgverifyDpkgExcludeGlobCrossesSlash(t *testing.T) {
	withEUID(t, 0)
	a := &fsAccess{
		files: map[string]string{
			dpkgStatusPath:                 "dpkg.status.sample",
			"/etc/dpkg/dpkg.cfg":           "dpkg.cfg.d-globs",
			"/etc/dpkg/dpkg.cfg.d/00-none": "dpkg.cfg.d-excludes",
		},
		cmds: map[string]cmdResult{cmdKey(dpkgVerifyCmd): {stdout: []byte(
			"missing     /opt/vendor/a/b/c.bak\n" +
				"missing     /opt/vendor/keep/x.bak\n" +
				"missing     /opt/vendor/c.bak.1\n" +
				"??5??????   /srv/cache/q/tmp7\n" +
				"??5??????   /srv/cache/qq/tmp7\n")}},
	}
	b := pkgverifyRun(t, a, true)
	mod := verifyRows(t, b, "packages.verify.modified")
	for _, p := range []string{"/opt/vendor/keep/x.bak", "/opt/vendor/c.bak.1", "/srv/cache/qq/tmp7"} {
		if mod[p] == nil {
			t.Errorf("%s was filtered; dpkg would have installed it", p)
		}
	}
	for _, p := range []string{"/opt/vendor/a/b/c.bak", "/srv/cache/q/tmp7"} {
		if mod[p] != nil {
			t.Errorf("%s survived; a path-exclude glob matches it", p)
		}
	}
	wantCounts(t, b, map[string]int{"dpkg_excluded": 2})
	st := verifyRecord(t, b, "packages.verify.stats")
	// dpkg loads dpkg.cfg.d first and dpkg.cfg after it (options.c
	// dpkg_options_load), so the fragment's glob comes first.
	want := []string{"path-exclude=/usr/share/man/*", "path-exclude=/opt/vendor/*.bak", "path-exclude=/srv/cache/?/tmp[0-9]", "path-include=/opt/vendor/keep/*"}
	if got := strList(st["dpkg_path_excludes"]); !slices.Equal(got, want) {
		t.Errorf("dpkg_path_excludes %v, want %v", got, want)
	}
}

// A dpkg.cfg fragment that exists and cannot be read drops the dpkg_excluded
// rule — a partial set of globs is not dpkg's set — and says why in stats.
// It is a filter input, not the verify, so complete stays true.
func TestPkgverifyUnreadableExcludesDropTheRule(t *testing.T) {
	withEUID(t, 0)
	a := &fsAccess{
		files: map[string]string{
			dpkgStatusPath:                "dpkg.status.sample",
			"/etc/dpkg/dpkg.cfg":          "dpkg.cfg.d-globs",
			"/etc/dpkg/dpkg.cfg.d/locked": "dpkg.cfg.d-excludes",
		},
		fails: map[string]error{"/etc/dpkg/dpkg.cfg.d/locked": os.ErrPermission},
		cmds: map[string]cmdResult{cmdKey(dpkgVerifyCmd): {stdout: []byte(
			"missing     /opt/vendor/a/b/c.bak\n")}},
	}
	b := pkgverifyRun(t, a, true)
	if e := env(t, b, "packages.verify.complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("complete %+v, want ok true", e)
	}
	if mod := verifyRows(t, b, "packages.verify.modified"); mod["/opt/vendor/a/b/c.bak"] == nil {
		t.Errorf("the rule was applied from a partial set of globs: %v", mod)
	}
	wantCounts(t, b, map[string]int{})
	got := strList(verifyRecord(t, b, "packages.verify.stats")["dpkg_path_excludes"])
	if len(got) != 1 || !strings.HasPrefix(got[0], "/etc/dpkg/dpkg.cfg.d/locked: ") {
		t.Errorf("dpkg_path_excludes %v, want the one failure path-prefixed", got)
	}
}

// --- rpm ------------------------------------------------------------------

func TestPkgverifyRpmFilterAndCounts(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{file: "rpm_Va.sample", exitCode: 1}), true)

	c := env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusOK || c.Value != true {
		t.Fatalf("complete %+v, want ok true (exit 1 with rows is an answer)", c)
	}
	if c.Source == nil || c.Source.Cmd != "/usr/bin/rpm -Va" || c.Source.ExitCode == nil || *c.Source.ExitCode != 1 {
		t.Errorf("complete source %+v", c.Source)
	}
	if e := env(t, b, "packages.verify.tool"); e.Value != "rpm" {
		t.Errorf("tool %+v, want rpm", e)
	}

	mod := verifyRows(t, b, "packages.verify.modified")
	if len(mod) != 4 {
		t.Errorf("modified has %d rows, want 4: %v", len(mod), mod)
	}
	x := mod["/usr/bin/x"]
	if x == nil {
		t.Fatalf("modified lacks /usr/bin/x: %v", mod)
	}
	all := []string{"size", "mode", "digest", "device", "link", "user", "group", "mtime", "caps"}
	if got := attrsOf(x); !slices.Equal(got, all) || x["untested"] != 0 {
		t.Errorf("/usr/bin/x %v, want all nine attributes and nothing untested", x)
	}
	if r := mod["/usr/lib/.build-id/ab/cdef"]; r == nil || r["file_type"] != "artifact" {
		t.Errorf("artifact row %v", r)
	}
	if r := mod["/usr/lib/odd"]; r == nil || r["file_type"] != "s" || !slices.Equal(attrsOf(r), []string{"size", "digest"}) {
		t.Errorf("an unknown type letter must be kept as the letter, never dropped: %v", r)
	}
	if r := mod["/usr/lib/gone"]; r == nil || r["note"] != "not installed" || !slices.Equal(attrsOf(r), []string{"missing"}) {
		t.Errorf("note row %v", r)
	}

	cfg := verifyRows(t, b, "packages.verify.modified_config")
	if r := cfg["/etc/ssh/sshd_config"]; len(cfg) != 1 || r == nil || !slices.Equal(attrsOf(r), []string{"size", "digest", "mtime"}) || r["file_type"] != "config" {
		t.Errorf("modified_config %v", cfg)
	}

	wantFilter(t, b)
	wantCounts(t, b, map[string]int{"config": 1, "doc": 1, "ghost": 1, "mtime_only": 1, "unverifiable": 1})

	st := verifyRecord(t, b, "packages.verify.stats")
	if got := strList(st["unparsed_head"]); len(got) != 1 || !strings.HasPrefix(got[0], "warning: %post") {
		t.Errorf("unparsed_head %v, want the warning line", got)
	}
	if st["lines"] != 10 || st["exit_code"] != 1 || st["packages_without_digests"] != 0 {
		t.Errorf("stats %v", st)
	}
	if got := strList(st["dpkg_path_excludes"]); len(got) != 0 {
		t.Errorf("an rpm host has no dpkg excludes: %v", got)
	}
}

// rpm -Va on a database it cannot open prints its complaint to stderr, exits
// 1 and prints no row: that is an error, never an unmodified host — and every
// other key is still written so none reads as missing.
func TestPkgverifyUnreadableDatabaseIsError(t *testing.T) {
	withEUID(t, 0)
	const complaint = "error: cannot open Packages database in /var/lib/rpm"
	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{stderr: complaint + "\nerror: cannot open Packages index using db5\n", exitCode: 1}), true)

	c := env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusError || !strings.Contains(c.Reason, complaint) {
		t.Fatalf("complete %+v, want error carrying the stderr line", c)
	}
	if e := env(t, b, "packages.verify.tool"); e.Value != "rpm" {
		t.Errorf("tool %+v", e)
	}
	for _, k := range []string{"packages.verify.modified", "packages.verify.modified_config"} {
		if l := okList(t, b, k); len(l) != 0 {
			t.Errorf("%s %v, want empty", k, l)
		}
	}
	wantFilter(t, b)
	wantCounts(t, b, map[string]int{})
	st := verifyRecord(t, b, "packages.verify.stats")
	if st["exit_code"] != 1 {
		t.Errorf("stats exit_code %v", st["exit_code"])
	}
	if got := strList(st["stderr_head"]); len(got) != 2 || got[0] != complaint {
		t.Errorf("stderr_head %v", got)
	}
	if w := b.Worst("pkgverify"); w != facts.StatusError {
		t.Errorf("Worst %s, want error", w)
	}
}

// Any exit code other than 0 and 1 is an error naming the code, rows or not.
func TestPkgverifyOtherExitIsError(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{file: "rpm_Va.sample", exitCode: 2}), true)
	if c := env(t, b, "packages.verify.complete"); c.Status != facts.StatusError || !strings.Contains(c.Reason, "exited 2") {
		t.Errorf("complete %+v, want error naming exit 2", c)
	}
	b = pkgverifyRun(t, rpmVerifyHost(cmdResult{exitCode: -1, err: os.ErrNotExist}), true)
	if c := env(t, b, "packages.verify.complete"); c.Status != facts.StatusError || !strings.Contains(c.Reason, "/usr/bin/rpm -Va") {
		t.Errorf("complete %+v, want error naming the command that could not start", c)
	}
}

// A killed command is timeout naming the command and the --verify-timeout it
// ran under; a capped capture is ok false, truncated, with a reason naming
// the cap. Either way the lists carry what was parsed before the cut, and the
// cut line is dropped rather than read as a shorter path.
func TestPkgverifyTimeoutAndCap(t *testing.T) {
	withEUID(t, 0)
	partial := []string{"/usr/bin/first", "/usr/bin/second"}

	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{file: "rpm_Va.cut.sample", exitCode: -1, timedOut: true}), true)
	c := env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusTimeout || !strings.Contains(c.Reason, "/usr/bin/rpm -Va") || !strings.Contains(c.Reason, verifyTimeout.String()) {
		t.Errorf("complete %+v, want timeout naming the command and %s", c, verifyTimeout)
	}
	if got := slices.Sorted(mapKeys(verifyRows(t, b, "packages.verify.modified"))); !slices.Equal(got, partial) {
		t.Errorf("timed-out modified %v, want %v", got, partial)
	}

	b = pkgverifyRun(t, rpmVerifyHost(cmdResult{file: "rpm_Va.cut.sample", exitCode: 1, truncated: true}), true)
	c = env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusOK || c.Value != false || !c.Truncated || !strings.Contains(c.Reason, "64 MiB") {
		t.Errorf("complete %+v, want ok false, truncated, naming the 64 MiB cap", c)
	}
	if got := slices.Sorted(mapKeys(verifyRows(t, b, "packages.verify.modified"))); !slices.Equal(got, partial) {
		t.Errorf("capped modified %v, want %v (the cut line dropped)", got, partial)
	}
	if e := env(t, b, "packages.verify.modified"); !e.Truncated {
		t.Errorf("a list parsed from a capped capture must say so: %+v", e)
	}
	if st := verifyRecord(t, b, "packages.verify.stats"); st["truncated"] != true || st["lines"] != 2 {
		t.Errorf("stats %v", st)
	}
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// Neither dpkg nor rpm: unsupported, and every other key written empty so no
// key reads as missing.
func TestPkgverifyUnknownFamily(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, &fsAccess{}, true)
	c := env(t, b, "packages.verify.complete")
	if c.Status != facts.StatusUnsupported || c.Reason != "no supported package manager" {
		t.Fatalf("complete %+v", c)
	}
	if e := env(t, b, "packages.verify.tool"); e.Status != facts.StatusOK || e.Value != "" {
		t.Errorf("tool %+v, want ok \"\"", e)
	}
	for _, k := range []string{"packages.verify.modified", "packages.verify.modified_config"} {
		if l := okList(t, b, k); len(l) != 0 {
			t.Errorf("%s %v, want empty", k, l)
		}
		if e := env(t, b, k); e.Source == nil || e.Source.Kind != "derived" {
			t.Errorf("%s source %+v, want derived", k, e.Source)
		}
	}
	wantFilter(t, b)
	wantCounts(t, b, map[string]int{})
	verifyRecord(t, b, "packages.verify.stats")
	if w := b.Worst("pkgverify"); w != facts.StatusOK {
		t.Errorf("Worst %s, want ok", w)
	}
}

// Every shape above writes all seven keys: a registered key the snapshot
// lacks is ERROR(missing_fact).
func TestPkgverifyPublishesEveryRegisteredKey(t *testing.T) {
	withEUID(t, 0)
	want := pkgverifyKeys(t)
	shapes := map[string]*fsAccess{
		"dpkg":       dpkgVerifyHost(),
		"rpm":        rpmVerifyHost(cmdResult{file: "rpm_Va.sample", exitCode: 1}),
		"unreadable": rpmVerifyHost(cmdResult{stderr: "error: cannot open Packages database\n", exitCode: 1}),
		"exit 2":     rpmVerifyHost(cmdResult{exitCode: 2}),
		"no start":   rpmVerifyHost(cmdResult{exitCode: -1, err: os.ErrNotExist}),
		"timeout":    rpmVerifyHost(cmdResult{file: "rpm_Va.cut.sample", exitCode: -1, timedOut: true}),
		"cap":        rpmVerifyHost(cmdResult{file: "rpm_Va.cut.sample", truncated: true}),
		"unknown":    {},
	}
	for name, a := range shapes {
		if got := pkgverifyRun(t, a, true).Keys("pkgverify"); !slices.Equal(got, want) {
			t.Errorf("%s: wrote %v, want %v", name, got, want)
		}
	}
}

// --- the list cap ---------------------------------------------------------

func TestCapRowsCuts(t *testing.T) {
	rows := make([]any, 5001)
	for i := range rows {
		rows[i] = i
	}
	got, cut := capRows(rows, 5000)
	if len(got) != 5000 || !cut || got[4999] != 4999 {
		t.Errorf("capRows(5001, 5000) = %d rows, cut %v", len(got), cut)
	}
	if got, cut := capRows(rows[:5000], 5000); len(got) != 5000 || cut {
		t.Errorf("capRows(5000, 5000) = %d rows, cut %v; a full list is not a cut one", len(got), cut)
	}

	// Through the collector: 5001 modified rows publish 5000, Truncated on
	// the envelope, and the collector carries on to write every other key.
	withEUID(t, 0)
	var out strings.Builder
	for i := range 5001 {
		fmt.Fprintf(&out, "S.5......    /usr/lib/many/f%05d\n", i)
	}
	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{stdout: []byte(out.String()), exitCode: 1}), true)
	e := env(t, b, "packages.verify.modified")
	if l := okList(t, b, "packages.verify.modified"); len(l) != 5000 || !e.Truncated {
		t.Errorf("modified: %d rows, truncated %v; want 5000 and true", len(l), e.Truncated)
	}
	if c := env(t, b, "packages.verify.complete"); c.Status != facts.StatusOK || c.Value != true {
		t.Errorf("a full list never stops the collector or fails the verify: %+v", c)
	}
	if e := env(t, b, "packages.verify.modified_config"); e.Truncated {
		t.Errorf("modified_config was not cut: %+v", e)
	}
	if got := len(pkgverifyRun(t, rpmVerifyHost(cmdResult{stdout: []byte(out.String()), exitCode: 1}), true).Keys("pkgverify")); got != 7 {
		t.Errorf("a capped run wrote %d keys, want 7", got)
	}
}

// rpm prints a row whose nine columns are all `.` only to carry a file state
// (`(not installed)`, `(replaced)`): nothing differs, so it is not a
// modification and the unchanged rule drops it. A `?`-only row is still
// unverifiable — the order of the two rules is what tells them apart.
func TestPkgverifyUnchangedRowIsDropped(t *testing.T) {
	withEUID(t, 0)
	b := pkgverifyRun(t, rpmVerifyHost(cmdResult{exitCode: 1, stdout: []byte(
		// rpm prints `%s  %c %s`: with no type letter that is four blanks.
		".........    /usr/bin/x (not installed)\n" +
			"..?......    /usr/sbin/unreadable\n" +
			"S.5......    /usr/bin/changed\n")}), true)
	mod := verifyRows(t, b, "packages.verify.modified")
	if len(mod) != 1 || mod["/usr/bin/changed"] == nil {
		t.Errorf("modified %v, want /usr/bin/changed alone", mod)
	}
	wantCounts(t, b, map[string]int{"unchanged": 1, "unverifiable": 1})
	wantFilter(t, b)
}

// A dpkg.cfg fragment read only in part (the read cap) or refused as binary
// (a NUL byte: the primitive returns no data and no error) is as unreadable
// as a denied one: its filters are not known, so the rule is dropped and the
// reason recorded.
func TestPkgverifyPartialExcludesDropTheRule(t *testing.T) {
	withEUID(t, 0)
	for _, tc := range []struct {
		name, reason string
		host         func(a *fsAccess)
	}{
		{"truncated", "truncated", func(a *fsAccess) {
			a.files["/etc/dpkg/dpkg.cfg.d/cut"] = "dpkg.cfg.d-globs"
			a.truncated = map[string]bool{"/etc/dpkg/dpkg.cfg.d/cut": true}
		}},
		{"binary", "binary", func(a *fsAccess) {
			a.contents = map[string][]byte{"/etc/dpkg/dpkg.cfg.d/cut": []byte("path-exclude=/opt/vendor/*\x00\n")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &fsAccess{
				files: map[string]string{dpkgStatusPath: "dpkg.status.sample", "/etc/dpkg/dpkg.cfg": "dpkg.cfg.d-globs"},
				cmds:  map[string]cmdResult{cmdKey(dpkgVerifyCmd): {stdout: []byte("missing     /opt/vendor/a/b/c.bak\n")}},
			}
			tc.host(a)
			b := pkgverifyRun(t, a, true)
			if mod := verifyRows(t, b, "packages.verify.modified"); mod["/opt/vendor/a/b/c.bak"] == nil {
				t.Errorf("the rule was applied from a partial set of globs: %v", mod)
			}
			wantCounts(t, b, map[string]int{})
			got := strList(verifyRecord(t, b, "packages.verify.stats")["dpkg_path_excludes"])
			if want := []string{"/etc/dpkg/dpkg.cfg.d/cut: " + tc.reason}; !slices.Equal(got, want) {
				t.Errorf("dpkg_path_excludes %v, want %v", got, want)
			}
		})
	}
}
