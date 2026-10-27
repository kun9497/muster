package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/cisindex"
)

const control = "muster.account.lockout_threshold"

func controlsFile(version string, entries ...string) string {
	return "version: " + version + "\ncontrols:\n" + strings.Join(entries, "")
}

const (
	e1  = "  - id: \"5.1\"\n    levels: [l1_server, l1_workstation]\n    rules: [r_deny, \"var_deny=4\"]\n"
	e2  = "  - id: \"5.2\"\n    levels: [l2_server]\n    rules: [r_other]\n"
	e2a = "  - id: \"5.2\"\n    levels: [l2_server]\n    rules: [r_other_alma, r_extra]\n"
	e2l = "  - id: \"5.2\"\n    levels: [l1_server]\n    rules: [r_other]\n"
)

// fixtureDir is a t.TempDir holding every input of run, the download hook
// replaced so that a network call fails the test.
type fixtureDir struct {
	dir   string
	files map[string]string // path in sources → content
}

func newFixture(t *testing.T, alma string) *fixtureDir {
	t.Helper()
	orig := download
	t.Cleanup(func() { download = orig })
	download = func(url string) ([]byte, error) {
		t.Fatalf("network call to %s", url)
		return nil, nil
	}
	f := &fixtureDir{dir: t.TempDir(), files: map[string]string{
		"controls/cis_ubuntu2204.yml":           controlsFile("2.0.0", e1, e2),
		"controls/cis_ubuntu2404.yml":           controlsFile("1.0.0", e1, e2),
		"products/rhel9/controls/cis_rhel9.yml": controlsFile("2.0.0", e1, e2),
		"controls/cis_almalinux9.yml":           alma,
	}}
	return f
}

func (f *fixtureDir) path(p ...string) string { return filepath.Join(append([]string{f.dir}, p...)...) }

// write lays out the cache, sources.json, map.yaml and review.yaml.
func (f *fixtureDir) write(t *testing.T, mapYAML, reviewYAML string) {
	t.Helper()
	pin := func(path string) map[string]any {
		return map[string]any{"repo": "o/r", "tag": "v1", "commit": strings.Repeat("a", 40), "path": path,
			"sha256": digest([]byte(f.files[path]))}
	}
	with := func(m map[string]any, kv map[string]any) map[string]any {
		for k, v := range kv {
			m[k] = v
		}
		return m
	}
	srcs := []any{
		with(pin("controls/cis_ubuntu2204.yml"), map[string]any{"product": "ubuntu2204", "benchmark": "Synthetic A", "version": "2.0.0", "profile": "cis-ubuntu2204-l1", "applies_to": []string{}}),
		with(pin("controls/cis_ubuntu2404.yml"), map[string]any{"product": "ubuntu2404", "benchmark": "Synthetic B", "version": "1.0.0", "profile": "cis-ubuntu2404-l1", "applies_to": []string{}}),
		with(pin("products/rhel9/controls/cis_rhel9.yml"), map[string]any{"product": "rhel9", "benchmark": "Synthetic C", "version": "2.0.0", "profile": "cis-rhel9-l1", "applies_to": []string{"alma9", "rocky9"}}),
		with(pin("controls/cis_almalinux9.yml"), map[string]any{"equal_to": "rhel9"}),
	}
	raw, err := json.Marshal(srcs)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(f.path("cache"), 0o755))
	for _, c := range f.files {
		must(os.WriteFile(f.path("cache", digest([]byte(c))), []byte(c), 0o644))
	}
	must(os.WriteFile(f.path("sources.json"), raw, 0o644))
	must(os.WriteFile(f.path("map.yaml"), []byte(mapYAML), 0o644))
	must(os.WriteFile(f.path("review.yaml"), []byte(reviewYAML), 0o644))
}

func (f *fixtureDir) args(extra ...string) []string {
	return append([]string{"-sources", f.path("sources.json"), "-cache", f.path("cache"), "-ref-dir", f.path("ref"),
		"-profile-dir", f.path("prof"), "-map", f.path("map.yaml"), "-review", f.path("review.yaml")}, extra...)
}

func (f *fixtureDir) run(extra ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(f.args(extra...), &out, &errb)
	return code, out.String(), errb.String()
}

const goodMap = "- id: " + control + "\n  rules: [r_deny]\n  vars:\n    - { var: var_deny, param: max_attempts, as: int }\n"

var outputs = []string{
	"ref/ubuntu2204-2.0.0.json", "ref/ubuntu2404-1.0.0.json", "ref/rhel9-2.0.0.json",
	"prof/cis-ubuntu2204-l1.yaml", "prof/cis-ubuntu2404-l1.yaml", "prof/cis-rhel9-l1.yaml",
}

func TestGenerateWritesIndexAndProfiles(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.write(t, goodMap, "[]\n")
	if code, _, errs := f.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	first := map[string][]byte{}
	for _, o := range outputs {
		b, err := os.ReadFile(f.path(o))
		if err != nil {
			t.Fatalf("%s not written: %v", o, err)
		}
		first[o] = b
	}
	ix, err := cisindex.DecodeIndex(first["ref/rhel9-2.0.0.json"])
	if err != nil {
		t.Fatal(err)
	}
	if ix.EqualTo == nil || ix.EqualTo.Path != "controls/cis_almalinux9.yml" || ix.EqualTo.Compared != "ids and levels" ||
		ix.EqualTo.SHA256 != digest([]byte(f.files["controls/cis_almalinux9.yml"])) {
		t.Errorf("rhel9 equal_to = %+v", ix.EqualTo)
	}
	if got := strings.Join(ix.AppliesTo, ","); got != "alma9,rocky9" {
		t.Errorf("applies_to %q", got)
	}
	if len(ix.Recs) != 1 || ix.Recs[0].Rec != "5.1" || ix.Recs[0].Rules != "all" || ix.Counts.L1Server != 1 {
		t.Errorf("rows %+v counts %+v", ix.Recs, ix.Counts)
	}
	if ix2, _ := cisindex.DecodeIndex(first["ref/ubuntu2204-2.0.0.json"]); ix2.EqualTo != nil {
		t.Errorf("ubuntu2204 carries equal_to %+v", ix2.EqualTo)
	}
	prof := string(first["prof/cis-rhel9-l1.yaml"])
	for _, want := range []string{"profile: cis-rhel9-l1", "- " + control, "max_attempts: 4"} {
		if !strings.Contains(prof, want) {
			t.Errorf("profile lacks %q:\n%s", want, prof)
		}
	}
	if code, _, errs := f.run(); code != 0 {
		t.Fatalf("second run exit %d: %s", code, errs)
	}
	for _, o := range outputs {
		b, _ := os.ReadFile(f.path(o))
		if !bytes.Equal(b, first[o]) {
			t.Errorf("%s differs on a second run", o)
		}
	}
}

func TestCheckDetectsDrift(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.write(t, goodMap, "[]\n")
	if code, _, errs := f.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if code, _, errs := f.run("-check"); code != 0 {
		t.Fatalf("clean -check exit %d: %s", code, errs)
	}
	target := f.path("prof/cis-ubuntu2404-l1.yaml")
	if err := os.WriteFile(target, []byte("edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errs := f.run("-check")
	if code != 1 || !strings.Contains(errs, "cis-ubuntu2404-l1.yaml") {
		t.Fatalf("edited file: exit %d, stderr %q", code, errs)
	}
	if b, _ := os.ReadFile(target); string(b) != "edited\n" {
		t.Error("-check wrote a file")
	}
	if err := os.Remove(f.path("ref/rhel9-2.0.0.json")); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := f.run("-check"); code != 1 || !strings.Contains(errs, "rhel9-2.0.0.json") {
		t.Fatalf("missing file: exit %d, stderr %q", code, errs)
	}
}

func TestAlmaDifferenceInLevelsFails(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2l))
	f.write(t, goodMap, "[]\n")
	code, _, errs := f.run()
	if code != 2 || !strings.Contains(errs, "5.2") || !strings.Contains(errs, "levels") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(f.path("ref")); err == nil {
		t.Error("an output directory was created")
	}
}

func TestAlmaDifferenceInRulesIsLoggedOnly(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2a))
	// r_extra is only in the AlmaLinux file: the union excludes it.
	f.write(t, "- id: "+control+"\n  rules: [r_extra]\n", "[]\n")
	code, _, errs := f.run()
	if code != 2 || !strings.Contains(errs, "r_extra is in no source file") {
		t.Fatalf("a rule only AlmaLinux names was accepted: exit %d, %q", code, errs)
	}
	f.write(t, goodMap, "[]\n")
	code, _, errs = f.run()
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := "cisindex: alma9 rules differ from rhel9 on 1 entries (logged, not read)\n"
	if errs != want {
		t.Errorf("stderr %q, want %q", errs, want)
	}
}

func TestPinMismatchRefused(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.write(t, goodMap, "[]\n")
	// The cached copy is corrupt, so the file is downloaded; the download is
	// not what the pin names.
	pinned := digest([]byte(f.files["controls/cis_ubuntu2204.yml"]))
	if err := os.WriteFile(f.path("cache", pinned), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := 0
	download = func(url string) ([]byte, error) {
		calls++
		if !strings.HasSuffix(url, "/"+strings.Repeat("a", 40)+"/controls/cis_ubuntu2204.yml") {
			t.Errorf("url %s", url)
		}
		return []byte("something else"), nil
	}
	code, _, errs := f.run()
	if code != 2 || calls != 1 || !strings.Contains(errs, "refusing") || !strings.Contains(errs, pinned) {
		t.Fatalf("exit %d, %d downloads, stderr %q", code, calls, errs)
	}
	if b, _ := os.ReadFile(f.path("cache", pinned)); string(b) != "tampered" {
		t.Error("the cache was overwritten by a refused download")
	}
	// A download that matches the pin repairs the cache.
	good := []byte(f.files["controls/cis_ubuntu2204.yml"])
	download = func(string) ([]byte, error) { return good, nil }
	if code, _, errs := f.run(); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if b, _ := os.ReadFile(f.path("cache", pinned)); !bytes.Equal(b, good) {
		t.Error("the verified download was not cached")
	}
}

func TestRecsKeyThatIsNoProductIsRefused(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.write(t, goodMap+"  recs:\n    ubuntu2205: [{ rec: \"5.2\", reason: r }]\n", "[]\n")
	code, _, errs := f.run()
	if code != 2 || !strings.Contains(errs, control) || !strings.Contains(errs, `"ubuntu2205"`) {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestReviewNamingNoGeneratedProfileIsRefused(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.write(t, goodMap, "- { profile: cis-nothing-l1, id: "+control+", reason: r }\n")
	code, _, errs := f.run()
	if code != 2 || !strings.Contains(errs, "cis-nothing-l1") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestSourceVersionMustMatchTheFile(t *testing.T) {
	f := newFixture(t, controlsFile("2.0.0", e1, e2))
	f.files["controls/cis_ubuntu2404.yml"] = controlsFile("1.0.1", e1, e2)
	f.write(t, goodMap, "[]\n")
	code, _, errs := f.run()
	if code != 2 || !strings.Contains(errs, "version 1.0.1") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}
