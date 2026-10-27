package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/cisindex"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/profile"
)

var repoCIS = filepath.Join("..", "..", "docs", "reference", "cis")

var cisBuiltins = []string{"cis-rhel9-l1", "cis-ubuntu2204-l1", "cis-ubuntu2404-l1"}

const allBuiltins = "default, cis-rhel9-l1, cis-ubuntu2204-l1, cis-ubuntu2404-l1, kisa-unix-2026"

// cisTree is the committed CIS reference tree: the per-product indexes, the
// map and the review list.
type cisTree struct {
	indexes map[string]*cisindex.Index // by product
	mapRows []cisindex.MapRow
	review  []cisindex.ReviewRow
}

func readCISTree(t *testing.T, dir string) cisTree {
	t.Helper()
	tree := cisTree{indexes: map[string]*cisindex.Index{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no CIS index under %s: %v", dir, err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		ix, err := cisindex.DecodeIndex(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		tree.indexes[ix.Product] = ix
	}
	b, err := os.ReadFile(filepath.Join(dir, "map.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tree.mapRows, err = cisindex.DecodeMap(b); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "review.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if tree.review, err = cisindex.DecodeReview(b); err != nil {
		t.Fatal(err)
	}
	return tree
}

// expectedInclude is a CIS built-in's include list as CB-7 defines it: the
// index's candidates minus the profile's review rows.
func expectedInclude(t *testing.T, tree cisTree, name string) []string {
	t.Helper()
	c, ok := profile.CISBenchmark(name)
	if !ok {
		t.Fatalf("%s is not a CIS built-in", name)
	}
	ix := tree.indexes[c.Benchmark]
	if ix == nil {
		t.Fatalf("%s: no index for %s", name, c.Benchmark)
	}
	out := []string{}
	for _, id := range cisindex.Candidates(ix) {
		if !slices.ContainsFunc(tree.review, func(r cisindex.ReviewRow) bool { return r.Profile == name && r.ID == id }) {
			out = append(out, id)
		}
	}
	return out
}

// CB-7: each generated profile is the index's candidates minus its review
// rows, so a hand edit of the profile or a stale regeneration fails here.
func TestCISProfilesMatchTheIndex(t *testing.T) {
	tree := readCISTree(t, repoCIS)
	for _, name := range cisBuiltins {
		f, ok := profile.Builtin(name)
		if !ok {
			t.Fatalf("no built-in %s", name)
		}
		got := append([]string(nil), f.Include...)
		sort.Strings(got)
		if want := expectedInclude(t, tree, name); !slices.Equal(got, want) {
			t.Errorf("%s includes %v\nthe index minus review.yaml gives %v\nrun go run ./tools/cisindex", name, got, want)
		}
	}
}

// cisDrift holds map.yaml and review.yaml together with the committed index
// and the generated profiles (CB-7's offline half); one line per problem.
func cisDrift(tree cisTree, builtin func(string) (*profile.File, bool)) []string {
	var out []string
	mapped := map[string]bool{}
	for _, r := range tree.mapRows {
		mapped[r.ID] = true
	}
	indexed := map[string]bool{}
	products := make([]string, 0, len(tree.indexes))
	for p := range tree.indexes {
		products = append(products, p)
	}
	sort.Strings(products)
	for _, p := range products {
		for _, row := range tree.indexes[p].Recs {
			for _, id := range row.Controls {
				indexed[id] = true
				if !mapped[id] {
					out = append(out, fmt.Sprintf("%s %s names %s, which map.yaml has no row for", p, row.Rec, id))
				}
			}
		}
	}
	for _, r := range tree.mapRows {
		if !indexed[r.ID] {
			out = append(out, fmt.Sprintf("map.yaml row %s is on no index row", r.ID))
		}
		recProducts := make([]string, 0, len(r.Recs))
		for p := range r.Recs {
			recProducts = append(recProducts, p)
		}
		sort.Strings(recProducts)
		for _, p := range recProducts {
			ix := tree.indexes[p]
			for _, rr := range r.Recs[p] {
				found := false
				if ix != nil {
					for _, row := range ix.Recs {
						if row.Rec == rr.Rec && slices.Contains(row.Controls, r.ID) {
							found = true
						}
					}
				}
				if !found {
					out = append(out, fmt.Sprintf("map.yaml %s recs %s %s is no index row naming the control", r.ID, p, rr.Rec))
				}
			}
		}
	}
	for _, rv := range tree.review {
		c, ok := profile.CISBenchmark(rv.Profile)
		if !ok {
			out = append(out, fmt.Sprintf("review.yaml %s names %s, which is no CIS built-in", rv.ID, rv.Profile))
			continue
		}
		ix := tree.indexes[c.Benchmark]
		if ix == nil || !slices.Contains(cisindex.Candidates(ix), rv.ID) {
			out = append(out, fmt.Sprintf("review.yaml %s %s is no candidate of %s", rv.Profile, rv.ID, c.Benchmark))
		}
		if f, ok := builtin(rv.Profile); ok && slices.Contains(f.Include, rv.ID) {
			out = append(out, fmt.Sprintf("review.yaml %s %s is reviewed out, yet the profile includes it", rv.Profile, rv.ID))
		}
	}
	for _, name := range cisBuiltins {
		f, ok := builtin(name)
		if !ok {
			out = append(out, "no built-in "+name)
			continue
		}
		ids := make([]string, 0, len(f.Params))
		for id := range f.Params {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !slices.Contains(f.Include, id) {
				out = append(out, fmt.Sprintf("%s sets params for %s, which it does not select", name, id))
			}
		}
	}
	return out
}

func TestCISMapAndReviewMatchTheIndex(t *testing.T) {
	tree := readCISTree(t, repoCIS)
	if problems := cisDrift(tree, profile.Builtin); len(problems) > 0 {
		t.Errorf("the committed CIS tree is out of step:\n%s", strings.Join(problems, "\n"))
	}
	// Review focus 5: a map.yaml with a row taken out fails naming the
	// control, read from a doctored copy of the committed tree.
	dir := t.TempDir()
	for _, name := range []string{"map.yaml", "review.yaml", "rhel9-2.0.0.json", "ubuntu2204-2.0.0.json", "ubuntu2404-1.0.0.json"} {
		b, err := os.ReadFile(filepath.Join(repoCIS, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "map.yaml" {
			const row = "- id: muster.account.primary_group_exists\n  rules: [gid_passwd_group_same]\n"
			if bytes.Count(b, []byte(row)) != 1 {
				t.Fatalf("map.yaml no longer carries %q once", row)
			}
			b = bytes.Replace(b, []byte(row), nil, 1)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	problems := cisDrift(readCISTree(t, dir), profile.Builtin)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "names muster.account.primary_group_exists, which map.yaml has no row for") {
		t.Errorf("a removed map.yaml row was not caught: %v", problems)
	}
	// A review row the profile still includes is caught as well.
	doctored := tree
	doctored.review = append(append([]cisindex.ReviewRow(nil), tree.review...), cisindex.ReviewRow{Profile: "cis-rhel9-l1", ID: "muster.account.primary_group_exists", Reason: "x"})
	if problems := cisDrift(doctored, profile.Builtin); !strings.Contains(strings.Join(problems, "\n"), "cis-rhel9-l1 muster.account.primary_group_exists is reviewed out, yet the profile includes it") {
		t.Errorf("a review row on an included control was not caught: %v", problems)
	}
}

func lintWithProfile(t *testing.T, refs bool, prof string) (int, string, string) {
	t.Helper()
	args := []string{"lint", "--fixtures", repoFixtures, "--kisa", repoKisa, "--profile", prof}
	if refs {
		args = append(args, "--references", repoReferences)
	}
	var out, errb bytes.Buffer
	code := runControls(args, &out, &errb)
	return code, out.String(), errb.String()
}

// CB-10 / Y-1: every control a CIS profile selects carries a reference on
// the profile's benchmark at Level 1 – Server; a file extending one is held
// to the same rule.
func TestControlsLintCISProfiles(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	idx, err := controls.LoadReferenceIndex(repoReferences)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range cisBuiltins {
		for _, refs := range []bool{true, false} {
			code, out, errb := lintWithProfile(t, refs, name)
			if code != exitOK || !strings.Contains(out, "ok: profile "+name+" selects ") {
				t.Errorf("lint --profile %s (references %v): exit %d\nstdout %s\nstderr %s", name, refs, code, out, errb)
			}
		}
	}
	// A control with no rhel9 entry at all, included by a file extending
	// cis-rhel9-l1, fails with and without --references.
	var bare, offLevel string
	for _, c := range set.Controls {
		has, l1 := false, false
		for _, r := range c.References.CIS {
			if r.Benchmark != "rhel9" {
				continue
			}
			has = true
			if lv, ok := idx.CISLevels("rhel9", r.Version, r.Rec); ok && slices.Contains(lv, "l1_server") {
				l1 = true
			}
		}
		if !has && bare == "" {
			bare = c.ID
		}
		if has && !l1 && offLevel == "" {
			offLevel = c.ID
		}
	}
	if bare == "" {
		t.Fatal("every control carries a rhel9 reference; the test needs one that does not")
	}
	dir := t.TempDir()
	site := filepath.Join(dir, "site.yaml")
	if err := os.WriteFile(site, []byte("profile: site\nextends: cis-rhel9-l1\ninclude: ["+bare+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, refs := range []bool{true, false} {
		want := "profile site selects " + bare + ", which carries no rhel9 CIS reference"
		if refs {
			want += " at Level 1 – Server"
		}
		code, out, errb := lintWithProfile(t, refs, site)
		if code != exitError {
			t.Errorf("references %v: exit %d, want %d", refs, code, exitError)
		}
		if lines := strings.Split(strings.TrimSpace(errb), "\n"); !slices.Equal(lines, []string{want, "muster: 1 lint problem(s)"}) {
			t.Errorf("references %v: stderr %q, want %q", refs, errb, want)
		}
		if strings.Contains(out, "ok: profile") {
			t.Errorf("references %v: a failing profile printed its ok line: %s", refs, out)
		}
		if !refs && !strings.Contains(out, shapeOnlyNote) {
			t.Errorf("without --references the shape-only note is missing: %s", out)
		}
	}
	// A control whose rhel9 entries all sit off Level 1 – Server passes the
	// shape-only rule and fails the indexed one.
	if offLevel == "" {
		t.Log("no control carries a rhel9 reference off Level 1 – Server; the level case is not exercised")
		return
	}
	if err := os.WriteFile(site, []byte("profile: site\nextends: cis-rhel9-l1\ninclude: ["+offLevel+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := lintWithProfile(t, false, site); code != exitOK {
		t.Errorf("shape-only, %s: exit %d, stderr %s", offLevel, code, errb)
	}
	if code, _, errb := lintWithProfile(t, true, site); code != exitError || !strings.Contains(errb, "profile site selects "+offLevel+", which carries no rhel9 CIS reference at Level 1 – Server\n") {
		t.Errorf("indexed, %s: exit %d, stderr %s", offLevel, code, errb)
	}
}

// osCopy is full-pass.json with its os-release replaced.
func osCopy(t *testing.T, id, versionID, family string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/full-pass.json")
	if err != nil {
		t.Fatal(err)
	}
	old := `"os_release":{"id":"ubuntu","version_id":"22.04","family":"debian"}`
	if bytes.Count(b, []byte(old)) != 1 {
		t.Fatalf("full-pass.json no longer carries %s once", old)
	}
	b = bytes.Replace(b, []byte(old), []byte(fmt.Sprintf(`"os_release":{"id":%q,"version_id":%q,"family":%q}`, id, versionID, family)), 1)
	p := filepath.Join(t.TempDir(), "os.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hostLines are the CB-11 lines of a stderr.
func hostLines(stderr string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.Contains(l, " is built for ") {
			out = append(out, l)
		}
	}
	return out
}

// runQuiet is the same run with the CB-11 warning switched off: the bytes
// and the exit code a run without the warning gives.
func runQuiet(args []string) (int, []byte) {
	saved := hostWarning
	hostWarning = func([]string, facts.OSRelease, func(string)) {}
	defer func() { hostWarning = saved }()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.Bytes()
}

func hostWarningCases(t *testing.T, cmd []string) {
	t.Helper()
	rocky := osCopy(t, "rocky", "9.3", "rhel")
	ubuntu := osCopy(t, "ubuntu", "22.04", "debian")
	empty := osCopy(t, "", "", "unknown")
	dir := t.TempDir()
	site := filepath.Join(dir, "site.yaml")
	if err := os.WriteFile(site, []byte("profile: site\nextends: cis-rhel9-l1\nexclude: [muster.account.primary_group_exists]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		facts, prof string
		want        []string
	}{
		{rocky, "cis-ubuntu2204-l1", []string{"muster: warning: profile cis-ubuntu2204-l1 is built for ubuntu2204; the snapshot is rocky 9.3"}},
		{ubuntu, "cis-ubuntu2204-l1", nil},
		{rocky, "cis-rhel9-l1", nil},
		{empty, "cis-ubuntu2404-l1", []string{"muster: warning: profile cis-ubuntu2404-l1 is built for ubuntu2404; the snapshot's os release is unknown"}},
		{ubuntu, site, []string{"muster: warning: profile cis-rhel9-l1 is built for rhel9, alma9, rocky9; the snapshot is ubuntu 22.04"}},
		{rocky, "default", nil},
	}
	for _, c := range cases {
		args := append(append([]string(nil), cmd...), "--facts", c.facts, "--profile", c.prof)
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if got := hostLines(errb.String()); !slices.Equal(got, c.want) {
			t.Errorf("%v: host lines %q, want %q", args, got, c.want)
		}
		qcode, qout := runQuiet(args)
		if code != qcode || !bytes.Equal(out.Bytes(), qout) {
			t.Errorf("%v: exit %d stdout %d bytes; without the warning exit %d stdout %d bytes", args, code, out.Len(), qcode, len(qout))
		}
	}
}

func TestCheckWarnsOnAnotherHost(t *testing.T) {
	hostWarningCases(t, []string{"check", "--format", "json"})
}

func TestFixWarnsOnAnotherHost(t *testing.T) {
	hostWarningCases(t, []string{"fix", "--dry-run", "--format", "json"})
}

func TestUnknownProfileListsBuiltins(t *testing.T) {
	for _, cmd := range [][]string{{"check"}, {"fix", "--dry-run"}} {
		var out, errb bytes.Buffer
		args := append(append([]string(nil), cmd...), "--facts", "testdata/full-pass.json", "--profile", "nope")
		if code := run(args, &out, &errb); code != exitError {
			t.Errorf("%v: exit %d", args, code)
		}
		if want := `unknown profile "nope"; the built-ins are ` + allBuiltins + "\n"; !strings.HasSuffix(errb.String(), want) {
			t.Errorf("%v: stderr %q, want it to end %q", args, errb.String(), want)
		}
	}
	if got := strings.Join(profile.Builtins(), ", "); got != allBuiltins {
		t.Errorf("Builtins() joined %q", got)
	}
	// The usage texts name the same built-ins in the same order; check's
	// carries the CB-13 sentence in one line of its own.
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for name, usage := range map[string]string{"check": checkUsage, "fix": fixUsage} {
		if !strings.Contains(flat(usage), "("+allBuiltins+")") {
			t.Errorf("%s usage does not list (%s):\n%s", name, allBuiltins, usage)
		}
	}
	const cb13 = "The `cis-<distro>-l1` profiles select muster's own controls that carry a CIS Benchmark recommendation number at Level 1 – Server; their results are muster's verdicts on muster's controls, not a CIS assessment, and muster is an independent publication not authorized, sponsored or otherwise approved by the Center for Internet Security."
	if !strings.Contains(checkUsage, "\n\n"+cb13+"\n") {
		t.Errorf("check usage lacks the CB-13 paragraph:\n%s", checkUsage)
	}
}
