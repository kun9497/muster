package suid

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// TestReferenceListsAreWellFormed checks every list committed here. Until
// tools/suidindex has generated them there are none, and that is a PASS, not
// a skip: the rules below are what a generated list must satisfy, and they
// are exercised against a crafted bad list in the same run so that an empty
// directory can never make the checker itself look healthy.
func TestReferenceListsAreWellFormed(t *testing.T) {
	lists, err := All()
	if err != nil {
		t.Fatalf("All(): %v", err)
	}
	for _, l := range lists {
		name := l.Distro + "-" + l.Release + ".json"
		if problems := listProblems(l); len(problems) != 0 {
			t.Errorf("%s: %s", name, strings.Join(problems, "; "))
		}
		got, ok, err := Load(l.Distro, l.Release)
		if err != nil || !ok {
			t.Errorf("Load(%q, %q) = (%v, %v, %v), want the committed list", l.Distro, l.Release, got, ok, err)
			continue
		}
		if got.Distro != l.Distro || got.Release != l.Release || len(got.Entries) != len(l.Entries) {
			t.Errorf("Load(%q, %q) returned a different list than All()", l.Distro, l.Release)
		}
	}

	// The checker is not vacuous: a list that breaks each rule reports each
	// rule, by name.
	bad := List{
		Distro: "", Release: "22.04", ImageDigest: "", Generated: "",
		Packages: []Package{{Name: "util-linux", Version: "1"}},
		Entries: []Entry{
			{Path: "/usr/bin/su", Mode: 0o4755, Owner: "root", Group: "root", Package: "util-linux"},
			{Path: "/bin/mount", Mode: 0o4755, Owner: "root", Group: "root", Package: "util-linux"},
			{Path: "relative", Mode: 0o755, Owner: "root", Group: "root", Package: "util-linux"},
			{Path: "/usr/bin/su", Mode: 0o4755, Owner: "root", Group: "root", Package: "nowhere"},
		},
	}
	want := []string{"distro", "image_digest", "generated", "sorted", "/bin/mount", "relative", "duplicate", "nowhere"}
	got := strings.Join(listProblems(bad), "; ")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("listProblems does not report %q; it said: %s", w, got)
		}
	}
	if len(listProblems(goodList())) != 0 {
		t.Errorf("a well-formed list reported %v", listProblems(goodList()))
	}
}

// Load names the file from the release and answers "no list" rather than an
// error when the release has none; All skips sources.json by name, because
// it is the generator's input and not a list.
func TestLoadAndAllOverAFixtureTree(t *testing.T) {
	good, err := json.Marshal(goodList())
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"ubuntu-22.04.json": {Data: good},
		"sources.json":      {Data: []byte(`{"releases": [{"id": "ubuntu"}]}`)},
	}
	l, ok, err := loadFrom(fsys, "ubuntu", "22.04")
	if err != nil || !ok {
		t.Fatalf("loadFrom(ubuntu, 22.04) = (%v, %v, %v)", l, ok, err)
	}
	if l.Distro != "ubuntu" || len(l.Entries) == 0 {
		t.Errorf("loaded %+v", l)
	}
	if l2, ok, err := loadFrom(fsys, "ubuntu", "24.04"); ok || err != nil || l2 != nil {
		t.Errorf("a release with no list = (%v, %v, %v), want (nil, false, nil)", l2, ok, err)
	}
	all, err := allFrom(fsys)
	if err != nil {
		t.Fatalf("allFrom: %v", err)
	}
	if len(all) != 1 || all[0].Distro != "ubuntu" {
		t.Errorf("allFrom returned %d lists (%+v), want the one list and not sources.json", len(all), all)
	}
}

// A committed file that will not decode is an error naming the file — never
// a silently empty list, which would turn every packaged candidate on that
// release into an unverified WARN with no explanation.
func TestMalformedListIsAnErrorNamingTheFile(t *testing.T) {
	fsys := fstest.MapFS{"ubuntu-22.04.json": {Data: []byte("{not json")}}
	if _, _, err := loadFrom(fsys, "ubuntu", "22.04"); err == nil || !strings.Contains(err.Error(), "ubuntu-22.04.json") {
		t.Errorf("loadFrom err = %v, want one naming ubuntu-22.04.json", err)
	}
	if _, err := allFrom(fsys); err == nil || !strings.Contains(err.Error(), "ubuntu-22.04.json") {
		t.Errorf("allFrom err = %v, want one naming ubuntu-22.04.json", err)
	}
}

// The two lookups the join makes on every candidate.
func TestPackageAndEntryLookups(t *testing.T) {
	l := goodList()
	if p, ok := l.Package("util-linux"); !ok || p.Version != "2.37.2-4ubuntu3" {
		t.Errorf("Package(util-linux) = (%+v, %v)", p, ok)
	}
	if p, ok := l.Package("at"); !ok || !p.PostinstSetsMode {
		t.Errorf("Package(at) = (%+v, %v), want postinst_sets_mode", p, ok)
	}
	if _, ok := l.Package("not-installed"); ok {
		t.Error("Package(not-installed) reported a package")
	}
	if e, ok := l.Entry("/usr/bin/su"); !ok || e.Mode != 0o4755 || e.Package != "util-linux" {
		t.Errorf("Entry(/usr/bin/su) = (%+v, %v)", e, ok)
	}
	if e, ok := l.Entry("/usr/bin/python3"); !ok || e.Mode&0o6000 != 0 {
		t.Errorf("Entry(/usr/bin/python3) = (%+v, %v), want the listed mode without a special bit", e, ok)
	}
	if _, ok := l.Entry("/usr/bin/nothing-here"); ok {
		t.Error("Entry(/usr/bin/nothing-here) reported an entry")
	}
}

// sources.json is the generator's input and is committed before any list
// exists. Its shape is checked now; Task 9 fills the digests and the URLs,
// and a release whose list IS committed may no longer carry a placeholder.
func TestSourcesJSONShape(t *testing.T) {
	s, err := LoadSources()
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	want := [][2]string{{"ubuntu", "22.04"}, {"ubuntu", "24.04"}, {"debian", "12"}, {"rocky", "9"}, {"almalinux", "9"}}
	var got [][2]string
	for _, r := range s.Releases {
		got = append(got, [2]string{r.ID, r.VersionID})
	}
	if !slices.Equal(got, want) {
		t.Errorf("releases = %v, want %v", got, want)
	}
	for _, r := range s.Releases {
		name := r.ID + "-" + r.VersionID
		if r.Image == "" || len(r.Packages) == 0 {
			t.Errorf("%s: image %q, %d packages", name, r.Image, len(r.Packages))
		}
		_, hasList, err := Load(r.ID, r.VersionID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hasList && r.Digest == "" {
			t.Errorf("%s: a list is committed but the image digest is still a placeholder", name)
		}
		seen := map[string]bool{}
		for _, p := range r.Packages {
			switch {
			case p.Name == "":
				t.Errorf("%s: a package with no name", name)
			case seen[p.Name]:
				t.Errorf("%s: %s is listed twice", name, p.Name)
			case p.Reason == "":
				t.Errorf("%s: %s has no reason", name, p.Name)
			case (p.URL == "") != (p.SHA256 == ""):
				// An image package is read inside the image and needs
				// neither; an extended package is downloaded and pins both.
				t.Errorf("%s: %s has url %q and sha256 %q; an extended package pins both", name, p.Name, p.URL, p.SHA256)
			}
			seen[p.Name] = true
		}
	}
}

// goodList is a synthetic, well-formed list: real distribution paths,
// invented versions, no host anywhere.
func goodList() List {
	return List{
		Distro: "ubuntu", Release: "22.04",
		ImageDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Generated:   "2026-01-01",
		Packages: []Package{
			{Name: "at", Version: "3.2.5-1ubuntu1", PostinstSetsMode: true},
			{Name: "python3.11", Version: "3.11.0-1"},
			{Name: "util-linux", Version: "2.37.2-4ubuntu3"},
		},
		Entries: []Entry{
			{Path: "/usr/bin/at", Mode: 0o4755, Owner: "root", Group: "root", Package: "at"},
			{Path: "/usr/bin/python3", Mode: 0o755, Owner: "root", Group: "root", Package: "python3.11"},
			{Path: "/usr/bin/su", Mode: 0o4755, Owner: "root", Group: "root", Package: "util-linux"},
		},
	}
}

// listProblems names every rule a list breaks. The rules are what the join
// depends on: the header identifies the release, the entries are sorted by
// path (Entry binary-searches them) and unique, every entry names a package
// the header covers, and every path is the absolute, merged-usr form the
// walk will report — a list that still said /bin/su could never join.
func listProblems(l List) []string {
	var out []string
	if l.Distro == "" {
		out = append(out, "distro is empty")
	}
	if l.Release == "" {
		out = append(out, "release is empty")
	}
	if l.ImageDigest == "" {
		out = append(out, "image_digest is empty")
	}
	if l.Generated == "" {
		out = append(out, "generated is empty")
	}
	pkgs := map[string]bool{}
	for _, p := range l.Packages {
		if p.Name == "" {
			out = append(out, "a package with no name")
		}
		if p.Version == "" {
			out = append(out, fmt.Sprintf("package %s has no version", p.Name))
		}
		pkgs[p.Name] = true
	}
	seen := map[string]bool{}
	for i, e := range l.Entries {
		if i > 0 && l.Entries[i-1].Path >= e.Path {
			out = append(out, fmt.Sprintf("entries are not sorted by path at %s", e.Path))
		}
		if seen[e.Path] {
			out = append(out, fmt.Sprintf("duplicate entry %s", e.Path))
		}
		seen[e.Path] = true
		if !strings.HasPrefix(e.Path, "/") {
			out = append(out, fmt.Sprintf("entry %s is not absolute", e.Path))
		}
		for _, alias := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
			if strings.HasPrefix(e.Path, alias) {
				out = append(out, fmt.Sprintf("entry %s is not canonicalised into /usr", e.Path))
			}
		}
		if !pkgs[e.Package] {
			out = append(out, fmt.Sprintf("entry %s names package %s, which the list does not cover", e.Path, e.Package))
		}
	}
	return out
}

// Ruling A-36. The RHEL family's images report a POINT release (rocky 9.8)
// where sources.json — and the maintainer — pin the major, so a list is
// committed under the version the image reported and Load falls back from
// the host's own version to `<id>-<major>.json`. Without the fallback a
// rocky 9.5 host and a rocky 9.8 list could never meet, and every packaged
// candidate on that host would read reference "none".
func TestLoadFallsBackToTheMajorVersion(t *testing.T) {
	major := goodList()
	major.Distro, major.Release = "rocky", "9"
	exact := goodList()
	exact.Distro, exact.Release = "rocky", "9.8"
	exact.Entries = append(exact.Entries, Entry{Path: "/usr/bin/zz", Mode: 0o755, Owner: "root", Group: "root", Package: "util-linux"})
	majorJSON, err := json.Marshal(major)
	if err != nil {
		t.Fatal(err)
	}
	exactJSON, err := json.Marshal(exact)
	if err != nil {
		t.Fatal(err)
	}

	onlyMajor := fstest.MapFS{"rocky-9.json": {Data: majorJSON}}
	l, ok, err := loadFrom(onlyMajor, "rocky", "9.8")
	if err != nil || !ok {
		t.Fatalf("loadFrom(rocky, 9.8) with only rocky-9.json = (%v, %v, %v)", l, ok, err)
	}
	if l.Release != "9" {
		t.Errorf("the fallback loaded %q, want the major list", l.Release)
	}

	// The exact file wins whenever it exists: the fallback must never
	// shadow the list generated for this very version.
	both := fstest.MapFS{"rocky-9.json": {Data: majorJSON}, "rocky-9.8.json": {Data: exactJSON}}
	l, ok, err = loadFrom(both, "rocky", "9.8")
	if err != nil || !ok {
		t.Fatalf("loadFrom(rocky, 9.8) with both = (%v, %v, %v)", l, ok, err)
	}
	if l.Release != "9.8" || len(l.Entries) != len(exact.Entries) {
		t.Errorf("the fallback shadowed the exact list: loaded %q with %d entries", l.Release, len(l.Entries))
	}

	// A version with no dot has no major to fall back to, and a release
	// neither name reaches is still the ordinary "no list" answer.
	if l, ok, err := loadFrom(onlyMajor, "rocky", "10"); ok || err != nil || l != nil {
		t.Errorf("loadFrom(rocky, 10) = (%v, %v, %v), want (nil, false, nil)", l, ok, err)
	}
	if l, ok, err := loadFrom(onlyMajor, "almalinux", "9.8"); ok || err != nil || l != nil {
		t.Errorf("loadFrom(almalinux, 9.8) = (%v, %v, %v), want (nil, false, nil)", l, ok, err)
	}
	// A malformed fallback file is still an error naming it, not a silent
	// "no list".
	broken := fstest.MapFS{"rocky-9.json": {Data: []byte("{not json")}}
	if _, _, err := loadFrom(broken, "rocky", "9.8"); err == nil || !strings.Contains(err.Error(), "rocky-9.json") {
		t.Errorf("loadFrom over a broken fallback = %v, want an error naming rocky-9.json", err)
	}
}
