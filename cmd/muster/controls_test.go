package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

var repoFixtures = filepath.Join("..", "..", "controls", "testdata")
var repoReferences = filepath.Join("..", "..", "docs", "reference")
var repoKisa = filepath.Join("..", "..", "docs", "reference", "kisa")

// R35: run from anywhere but the repository root, lint used to skip the
// fixture-pair rule and print "ok" -- a green light it had not earned.
func TestControlsLintRefusesToRunWithoutTheFixtureDirectory(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint"}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when it could not check fixtures: %q", out.String())
	}
	if !strings.Contains(errb.String(), "controls/testdata") || !strings.Contains(errb.String(), "--fixtures") {
		t.Errorf("stderr must name the missing directory and the flag: %q", errb.String())
	}
}

func TestControlsLintFixturesFlagAndUnusedKeysNote(t *testing.T) {
	var out, errb bytes.Buffer
	// R97: the real embedded set is linted against the real reference index
	// too, so a control that later gains a stig/nist_800_53 reference is
	// checked for existence here, not just shape.
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}
	// Spec §5.5 / M-27: registered keys no control uses are reported by the
	// usage note, without failing.
	if !strings.Contains(out.String(), "sockets.listening") ||
		!strings.Contains(out.String(), "registered fact keys are used by a control") ||
		!strings.Contains(out.String(), "unused:") {
		t.Errorf("stdout %q lacks the fact-usage note", out.String())
	}
}

// M-3 (spec §11): the note reports facts used, not merely facts collected --
// how many registered keys a control reads, how many the engine reads on its
// own, and which are read by nobody. The three account for every registered
// key, so the note is checked as an arithmetic statement rather than as a
// string.
func TestControlsLintPrintsTheUsageNote(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	re := regexp.MustCompile(`note: (\d+) of (\d+) registered fact keys are used by a control \((\d+) read by the engine\)(; unused: (.*))?\n`)
	m := re.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("stdout %q does not carry the usage note", out.String())
	}
	used, registered, engine := atoi(t, m[1]), atoi(t, m[2]), atoi(t, m[3])
	var unused []string
	if m[5] != "" {
		unused = strings.Split(m[5], ", ")
	}
	if used+engine+len(unused) != registered {
		t.Errorf("%d used + %d engine + %d unused != %d registered: %q", used, engine, len(unused), registered, m[0])
	}
	if used == 0 || registered == 0 {
		t.Errorf("the note reports nothing used: %q", m[0])
	}
	found := false
	for _, k := range unused {
		if k == "sockets.listening" {
			found = true
		}
	}
	if !found {
		t.Errorf("sockets.listening is referenced by no control and must be named in the note: %q", m[0])
	}
	// M-40/M-42: the note does not build its own list. It prints
	// controls.UnusedKeys, which answers in registry order -- a list the
	// note derived itself from the per-collector report would carry the
	// same keys in a different order.
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if want := controls.UnusedKeys(set, reg); !reflect.DeepEqual(unused, want) {
		t.Errorf("the note's unused list is not controls.UnusedKeys:\ngot  %v\nwant %v", unused, want)
	}
}

// The label belongs to the list: a set that reads every key it collects has
// no "unused:" to print, and an empty label would read as a defect in the
// note rather than as good news. The embedded set always has unused keys, so
// this shape can only be reached directly.
func TestUsageNoteOmitsTheListWhenNothingIsUnused(t *testing.T) {
	usage := []controls.CollectorUsage{
		{Collector: "a", Registered: 2, Used: 2},
		{Collector: "b", Registered: 1, Engine: 1},
	}
	const want = "note: 2 of 3 registered fact keys are used by a control (1 read by the engine)"
	if got := usageNote(usage, nil); got != want {
		t.Errorf("usageNote = %q, want %q", got, want)
	}
	// The list it prints is the one it is given, in that order.
	if got, want := usageNote(usage, []string{"b.k", "a.k"}), want+"; unused: b.k, a.k"; got != want {
		t.Errorf("usageNote = %q, want %q", got, want)
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return n
}

// R98: without --references, a missing stig/*.json under the given
// directory is an I/O failure named on stderr, exit 2 -- the same class as a
// missing fixture directory (R35). The fixtures check runs first, so this
// case must point at --fixtures repoFixtures to reach the references check.
func TestControlsLintReferencesFlagRejectsAMissingIndex(t *testing.T) {
	empty := t.TempDir()
	var out, errb bytes.Buffer
	code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", empty, "--kisa", repoKisa}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), empty) {
		t.Errorf("stderr %q must name the directory %q", errb.String(), empty)
	}
	if !strings.Contains(errb.String(), "refindex") {
		t.Errorf("stderr %q must name the regenerate command", errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when the reference index could not load: %q", out.String())
	}
}

// R98: without the flag at all, lint accepts any well-formed STIG/NIST
// reference and only checks it for shape -- it must not try to read
// docs/reference on its own and must not fail for that reason.
func TestControlsLintWithoutReferencesFlagChecksShapeOnly(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}
}

func TestControlsLintRejectsAnUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--bogus"}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "--bogus") {
		t.Errorf("stderr %q lacks the flag", errb.String())
	}
	var out2, errb2 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures"}, &out2, &errb2); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb2.String(), "needs a value") {
		t.Errorf("stderr %q lacks the missing-value message", errb2.String())
	}
}

// M-4/M-26: without --references the stig and nist_800_53 ids are checked
// for shape only, and lint says so on stdout instead of leaving the reader
// to believe the ids were verified. --kisa points at the item inventory the
// cross-check needs, and a missing directory is an error the way a missing
// fixture directory is (R35), never a silently skipped rule.
func TestControlsLintNotesAndKisaFlag(t *testing.T) {
	const shapeOnlyNote = "note: stig and nist_800_53 references checked for shape only; pass --references docs/reference to check them against the index"

	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", repoKisa}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb.String())
	}
	if !strings.Contains(out.String(), shapeOnlyNote) {
		t.Errorf("stdout %q lacks the shape-only note", out.String())
	}
	if !strings.Contains(out.String(), "ok: 64 controls") {
		t.Errorf("stdout %q lacks the ok line", out.String())
	}

	var out2, errb2 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--references", repoReferences, "--kisa", repoKisa}, &out2, &errb2); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, errb2.String())
	}
	if strings.Contains(out2.String(), shapeOnlyNote) {
		t.Errorf("with --references the shape-only note must be gone: %q", out2.String())
	}

	missing := filepath.Join(t.TempDir(), "no-inventory-here")
	var out3, errb3 bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", missing}, &out3, &errb3); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out3.String(), errb3.String())
	}
	if !strings.Contains(errb3.String(), missing) || !strings.Contains(errb3.String(), "--kisa") {
		t.Errorf("stderr %q must name the missing directory and the flag", errb3.String())
	}
	if strings.Contains(out3.String(), "ok:") {
		t.Errorf("lint must not report ok when it could not cross-check the inventory: %q", out3.String())
	}
	// LOW 10: a run that fails on --kisa must not first hand out advice
	// about a different flag. The note belongs after every directory check.
	if strings.Contains(out3.String(), shapeOnlyNote) {
		t.Errorf("a failed run must not print the shape-only note: %q", out3.String())
	}

	var out4, errb4 bytes.Buffer
	if code := runControls([]string{"lint", "--kisa"}, &out4, &errb4); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb4.String(), "needs a value") {
		t.Errorf("stderr %q lacks the missing-value message", errb4.String())
	}
}

// M-2: the flag has to reach the lint, not merely be parsed. Pointed at an
// inventory holding an item no control claims and no deferral excuses, lint
// must fail with the set-level rule -- which is exactly what would go
// unnoticed if the CLI parsed --kisa and then handed Lint a nil inventory.
func TestControlsLintCrossChecksAgainstTheInventoryItWasGiven(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"kisa_items_latest.json", "kisa_items_2021.json", "kisa_deferred.json"} {
		data, err := os.ReadFile(filepath.Join(repoKisa, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "kisa_items_latest.json" {
			// One more item than the set enrols, so the coverage rule must
			// fire. The row is synthetic: an id and placeholder fields, no
			// guide text (ATTRIBUTION.md).
			var items []map[string]any
			if err := json.Unmarshal(data, &items); err != nil {
				t.Fatal(err)
			}
			items = append(items, map[string]any{"id": "U-98", "name_ko": "synthetic", "category": "synthetic", "importance": "하", "page": 1})
			if data, err = json.Marshal(items); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	if code := runControls([]string{"lint", "--fixtures", repoFixtures, "--kisa", dir}, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitError, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "controls: kisa_coverage:") || !strings.Contains(errb.String(), "U-98") {
		t.Errorf("stderr %q must carry the set-level coverage problem naming U-98", errb.String())
	}
	if strings.Contains(out.String(), "ok:") {
		t.Errorf("lint must not report ok when the cross-check failed: %q", out.String())
	}
}

// kisaFrom2021 reads the 2021 ancestors of a 2026 item out of the mapping
// file, so the test asserts against the same source controls new reads
// rather than against a hard-coded list.
func kisaFrom2021(t *testing.T, dir, id string) []string {
	t.Helper()
	for _, row := range kisaMappingRows(t, dir) {
		if row.LatestID == id {
			if row.From2021 == nil {
				return []string{}
			}
			return row.From2021
		}
	}
	t.Fatalf("kisa_mapping.json carries no row for %s", id)
	return nil
}

type kisaMappingRow struct {
	LatestID string   `json:"latest_id"`
	From2021 []string `json:"from_2021"`
}

func kisaMappingRows(t *testing.T, dir string) []kisaMappingRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "kisa_mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Mapping []kisaMappingRow `json:"mapping"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Mapping
}

// M-16: controls new writes one control skeleton and its fixture stubs, the
// skeleton loads strictly and lints clean on shape, and a second run touches
// nothing.
func TestControlsNewWritesASkeletonAndRefusesToOverwrite(t *testing.T) {
	inv, err := controls.LoadKISA(repoKisa)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	const kisaID = "U-01"
	item, ok := inv.Item(controls.LatestKISAEdition, kisaID)
	if !ok || inv.IsDeferred(kisaID) {
		t.Fatalf("%s is not an implementable item of the %s inventory", kisaID, controls.LatestKISAEdition)
	}

	tmp := t.TempDir()
	out := filepath.Join(tmp, "controls")
	fixtures := filepath.Join(tmp, "testdata")
	var stdout, stderr bytes.Buffer
	code := runControls([]string{"new", "muster.file.example", "--kisa-id", kisaID, "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitOK, stdout.String(), stderr.String())
	}
	yamlPath := filepath.Join(out, "file", "example.yaml")
	written, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("controls new wrote no %s: %v", yamlPath, err)
	}
	if !strings.Contains(stdout.String(), yamlPath) {
		t.Errorf("stdout %q must name the file it wrote", stdout.String())
	}

	// The loader's own view of the skeleton: VERSION plus the one file,
	// every key known, decoded strictly (spec 6.8).
	if err := os.WriteFile(filepath.Join(out, "VERSION"), []byte("scaffold-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := controls.LoadFS(os.DirFS(out))
	if err != nil {
		t.Fatalf("the skeleton does not decode strictly: %v\n%s", err, written)
	}
	if len(set.Controls) != 1 {
		t.Fatalf("loaded %d controls, want 1", len(set.Controls))
	}
	c := set.Controls[0]
	if c.ID != "muster.file.example" {
		t.Errorf("id %q, want muster.file.example", c.ID)
	}
	if c.Category != "file" {
		t.Errorf("category %q, want the id's area, file", c.Category)
	}
	if c.Importance != item.Importance {
		t.Errorf("importance %q, want the inventory's %q", c.Importance, item.Importance)
	}
	if !strings.Contains(c.TitleKo, item.NameKo) {
		t.Errorf("title_ko %q must carry the inventory's item name as its placeholder", c.TitleKo)
	}
	if !strings.Contains(c.TitleEn, kisaID) {
		t.Errorf("title_en %q must name the item it scaffolds", c.TitleEn)
	}
	if c.Automation != "auto" {
		t.Errorf("automation %q, want auto by default", c.Automation)
	}
	if c.RequiresFacts != ">=1" {
		t.Errorf("requires_facts %q, want >=1", c.RequiresFacts)
	}
	if c.AbsentMeans != "manual" {
		t.Errorf("absent_means %q, want manual", c.AbsentMeans)
	}
	if len(c.Checks) != 1 || c.Remediation == nil {
		t.Errorf("an auto skeleton needs one checks clause and a remediation block; got %d clauses, remediation %v", len(c.Checks), c.Remediation)
	}
	for _, cl := range c.Checks {
		if _, ok := reg.Lookup(cl.Fact); !ok {
			t.Errorf("the placeholder clause names %q, which is not a registered fact key", cl.Fact)
		}
	}
	wantKISA := map[string][]string{"2026": {kisaID}, "2021": kisaFrom2021(t, repoKisa, kisaID)}
	if !reflect.DeepEqual(c.References.KISA, wantKISA) {
		t.Errorf("references.kisa %v, want %v", c.References.KISA, wantKISA)
	}
	if problems := controls.Lint(set, reg, controls.LintOptions{}); len(problems) != 0 {
		for _, p := range problems {
			t.Errorf("the skeleton is not lint-clean: %s", p)
		}
	}

	for _, name := range []string{"pass-example.json", "fail-example.json"} {
		checkFixtureStub(t, filepath.Join(fixtures, "muster.file.example", name))
	}

	// A 2026 item with no 2021 ancestor writes an empty list, not null: the
	// schema is a map of edition to ids, and "no ancestor" is a statement.
	var emptyID string
	for _, row := range kisaMappingRows(t, repoKisa) {
		if _, known := inv.Item(controls.LatestKISAEdition, row.LatestID); known && !inv.IsDeferred(row.LatestID) && len(row.From2021) == 0 {
			emptyID = row.LatestID
			break
		}
	}
	if emptyID == "" {
		t.Fatal("no 2026 item without a 2021 ancestor; this case cannot be exercised")
	}
	fresh := t.TempDir()
	var out2, err2 bytes.Buffer
	if code := runControls([]string{"new", "muster.account.example", "--kisa-id", emptyID, "--kisa-dir", repoKisa, "--out", filepath.Join(fresh, "controls"), "--fixtures", filepath.Join(fresh, "testdata")}, &out2, &err2); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, err2.String())
	}
	body, err := os.ReadFile(filepath.Join(fresh, "controls", "account", "example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"2021": []`) {
		t.Errorf("a 2026 item with no 2021 ancestor must write an empty list:\n%s", body)
	}

	// A second run refuses, names the file, and changes nothing.
	var out3, err3 bytes.Buffer
	if code := runControls([]string{"new", "muster.file.example", "--kisa-id", kisaID, "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures}, &out3, &err3); code != exitRefused {
		t.Fatalf("second run exit %d, want %d; stderr %q", code, exitRefused, err3.String())
	}
	if !strings.Contains(err3.String(), yamlPath) {
		t.Errorf("stderr %q must name the file it refused to overwrite", err3.String())
	}
	after, err := os.ReadFile(yamlPath)
	if err != nil || !bytes.Equal(written, after) {
		t.Errorf("the refused run rewrote %s", yamlPath)
	}

	// The fixture directory is refused on its own: the YAML is gone, the
	// stubs are not, and overwriting them would throw away real fixtures.
	if err := os.Remove(yamlPath); err != nil {
		t.Fatal(err)
	}
	var out4, err4 bytes.Buffer
	if code := runControls([]string{"new", "muster.file.example", "--kisa-id", kisaID, "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures}, &out4, &err4); code != exitRefused {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitRefused, err4.String())
	}
	if !strings.Contains(err4.String(), filepath.Join(fixtures, "muster.file.example")) {
		t.Errorf("stderr %q must name the fixture directory it refused to touch", err4.String())
	}
	if _, err := os.Stat(yamlPath); err == nil {
		t.Errorf("the refused run wrote %s anyway", yamlPath)
	}
}

// The refusals that keep a broken control out of the set in the first place.
func TestControlsNewRefusesWhatTheSetCannotHold(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "controls")
	fixtures := filepath.Join(dir, "testdata")
	scaffold := func(args ...string) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := runControls(append([]string{"new"}, args...), &stdout, &stderr)
		if stdout.Len() != 0 && code != exitOK {
			t.Errorf("a failed run wrote to stdout: %q", stdout.String())
		}
		return code, stderr.String()
	}

	// A bad id, named with the rule it broke.
	code, stderr := scaffold("muster.File.Example", "--kisa-id", "U-01", "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, "muster.<area>.<name>") {
		t.Errorf("bad id: exit %d stderr %q", code, stderr)
	}
	// An area that is not a control category has no directory to live in.
	code, stderr = scaffold("muster.nowhere.example", "--kisa-id", "U-01", "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, "nowhere") {
		t.Errorf("bad area: exit %d stderr %q", code, stderr)
	}
	// An id the inventory does not list.
	code, stderr = scaffold("muster.file.example", "--kisa-id", "U-99", "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, "U-99") {
		t.Errorf("unknown item: exit %d stderr %q", code, stderr)
	}
	// An id muster has deferred: a control for it would fail the set-level
	// coverage rule the moment it is committed.
	inv, err := controls.LoadKISA(repoKisa)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Deferred) == 0 {
		t.Fatal("no deferred item; this case cannot be exercised")
	}
	deferred := inv.Deferred[0].ID
	code, stderr = scaffold("muster.file.example", "--kisa-id", deferred, "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, deferred) || !strings.Contains(stderr, "kisa_deferred.json") {
		t.Errorf("deferred item: exit %d stderr %q", code, stderr)
	}
	// No inventory to read at all.
	code, stderr = scaffold("muster.file.example", "--kisa-id", "U-01", "--kisa-dir", filepath.Join(dir, "nothing"), "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, "nothing") {
		t.Errorf("missing inventory: exit %d stderr %q", code, stderr)
	}
	// An inventory without the mapping file: the 2021 ids cannot be derived
	// and controls new does not guess them.
	partial := filepath.Join(dir, "partial-kisa")
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kisa_items_latest.json", "kisa_items_2021.json", "kisa_deferred.json"} {
		data, err := os.ReadFile(filepath.Join(repoKisa, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(partial, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, stderr = scaffold("muster.file.example", "--kisa-id", "U-01", "--kisa-dir", partial, "--out", out, "--fixtures", fixtures)
	if code != exitRefused || !strings.Contains(stderr, "kisa_mapping.json") {
		t.Errorf("missing mapping: exit %d stderr %q", code, stderr)
	}
	// Nothing was written by any of them.
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		t.Errorf("a refused run wrote %v under %s", entries, out)
	}

	// Flag errors are the other kind: could not run, rather than refused to.
	var o, e bytes.Buffer
	if code := runControls([]string{"new", "muster.file.example", "--kisa-dir", repoKisa}, &o, &e); code != exitError || !strings.Contains(e.String(), "--kisa-id") {
		t.Errorf("missing --kisa-id: exit %d stderr %q", code, e.String())
	}
	o.Reset()
	e.Reset()
	if code := runControls([]string{"new", "muster.file.example", "--kisa-id", "U-01", "--bogus"}, &o, &e); code != exitError || !strings.Contains(e.String(), "--bogus") {
		t.Errorf("unknown flag: exit %d stderr %q", code, e.String())
	}
	o.Reset()
	e.Reset()
	if code := runControls([]string{"new", "--kisa-id", "U-01"}, &o, &e); code != exitError || !strings.Contains(e.String(), "control id") {
		t.Errorf("no id: exit %d stderr %q", code, e.String())
	}
	o.Reset()
	e.Reset()
	if code := runControls([]string{"new", "muster.file.example", "--kisa-id", "U-01", "--automation", "sometimes"}, &o, &e); code != exitError || !strings.Contains(e.String(), "sometimes") {
		t.Errorf("bad automation: exit %d stderr %q", code, e.String())
	}
}

// M-8/M-16: a manual skeleton judges nothing. It states why muster declines
// and names the facts the reviewer needs in hand instead.
func TestControlsNewManualShape(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	out := filepath.Join(tmp, "controls")
	fixtures := filepath.Join(tmp, "testdata")
	var stdout, stderr bytes.Buffer
	code := runControls([]string{"new", "muster.service.example", "--kisa-id", "U-45", "--automation", "manual", "--kisa-dir", repoKisa, "--out", out, "--fixtures", fixtures}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(out, "VERSION"), []byte("scaffold-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := controls.LoadFS(os.DirFS(out))
	if err != nil {
		t.Fatalf("the manual skeleton does not decode strictly: %v", err)
	}
	c := set.Controls[0]
	if c.Automation != "manual" {
		t.Fatalf("automation %q, want manual", c.Automation)
	}
	if strings.TrimSpace(c.ManualReason) == "" {
		t.Errorf("a manual skeleton must carry a manual_reason placeholder")
	}
	if len(c.Evidence) == 0 {
		t.Errorf("a manual skeleton must carry an evidence placeholder")
	}
	for _, k := range c.Evidence {
		if _, ok := reg.Lookup(k); !ok {
			t.Errorf("evidence placeholder %q is not a registered fact key", k)
		}
	}
	if len(c.Checks) != 0 || len(c.Mechanisms) != 0 || c.Custom != "" {
		t.Errorf("a manual skeleton carries no judgment; got %d checks, %d mechanisms, custom %q", len(c.Checks), len(c.Mechanisms), c.Custom)
	}
	if c.Remediation != nil {
		t.Errorf("a manual skeleton carries no remediation: %v", c.Remediation)
	}
	if problems := controls.Lint(set, reg, controls.LintOptions{}); len(problems) != 0 {
		for _, p := range problems {
			t.Errorf("the manual skeleton is not lint-clean: %s", p)
		}
	}
	// The fixture prefixes are the statuses a manual control can produce.
	for _, name := range []string{"manual-example.json", "na-example.json"} {
		checkFixtureStub(t, filepath.Join(fixtures, "muster.service.example", name))
	}
	for _, name := range []string{"pass-example.json", "fail-example.json"} {
		if _, err := os.Stat(filepath.Join(fixtures, "muster.service.example", name)); err == nil {
			t.Errorf("a manual control can never produce %s", name)
		}
	}
}

// checkFixtureStub holds a scaffolded stub to what the fixture test demands
// of every fixture: the synthetic marker (D02), a schema version, and the
// three empty blocks the author fills in.
func checkFixtureStub(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("controls new wrote no %s: %v", path, err)
	}
	var stub map[string]any
	if err := json.Unmarshal(data, &stub); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if stub["synthetic"] != true {
		t.Errorf(`%s: must carry a top-level "synthetic": true marker`, path)
	}
	if stub["schema_version"] != float64(1) {
		t.Errorf("%s: schema_version %v, want 1", path, stub["schema_version"])
	}
	for _, k := range []string{"run", "facts", "_expect"} {
		m, ok := stub[k].(map[string]any)
		if !ok || len(m) != 0 {
			t.Errorf("%s: %s = %v, want an empty object", path, k, stub[k])
		}
	}
	if len(stub) != 5 {
		t.Errorf("%s: %d top-level keys, want 5: %v", path, len(stub), stub)
	}
}
