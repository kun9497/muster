package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

// examplesDir is the repository's examples/ directory seen from cmd/muster.
// It holds the snapshots collected by .github/workflows/examples.yml and the
// reports check produced from them (spec §5, F-11).
const examplesDir = "../../examples"

// maskedCheckKeys name the four provenance fields of the report's check block
// that legitimately differ between the release binary that wrote a committed
// report and the `go test` binary that reproduces it here: the test binary
// has no -ldflags, so muster_version and commit read "dev"/"none", and an
// example collected against an older control set keeps that set's version and
// digest in its report (F-12 does not gate staleness). Everything else --
// the run block, the summary, every result -- must match byte for byte.
var maskedCheckKeys = []string{"commit", "controls_digest", "controls_version", "muster_version"}

// reportsFor renders both reports of one snapshot the way `muster check`
// does, through the check block the command itself uses (G-14).
func reportsFor(t *testing.T, snap *facts.Snapshot, set *controls.Set) (jsonReport, tableReport []byte) {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	// A snapshot collected against an older control set warns, and that is
	// not a failure here: F-12 keeps an example valid as long as it loads
	// and evaluates.
	results, cb := newCheckBlock(set, snap, reg, nil, func(msg string) { t.Logf("check warning: %s", msg) })
	rep := report.Build(snap, results, cb)
	var j, tb bytes.Buffer
	if err := report.WriteJSON(&j, rep); err != nil {
		t.Fatalf("write json: %v", err)
	}
	// Width 100 and colour off are what the command produces when its stdout
	// is a file, which is how the workflow captures the committed table.
	if err := report.WriteTable(&tb, rep, report.TableOptions{Width: 100}); err != nil {
		t.Fatalf("write table: %v", err)
	}
	return j.Bytes(), tb.Bytes()
}

// maskReportBytes drops maskedCheckKeys from a JSON report and re-marshals
// it. encoding/json sorts map keys, so two masked reports of the same content
// are the same bytes whatever order the originals were written in.
func maskReportBytes(data []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("report is not JSON: %w", err)
	}
	cb, ok := doc["check"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("report has no check block: %v", doc["check"])
	}
	for _, k := range maskedCheckKeys {
		delete(cb, k)
	}
	return json.Marshal(doc)
}

// maskReport is maskReportBytes for a caller that has a *testing.T and for
// which a malformed report is simply the end of the test.
func maskReport(t *testing.T, data []byte) []byte {
	t.Helper()
	out, err := maskReportBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reportControlsDigest returns a report's check.controls_digest, or "" when
// the bytes are not a report or carry no digest. "" never equals a real
// digest, so an unreadable committed report is treated as one this build
// cannot reproduce rather than compared against it.
func reportControlsDigest(data []byte) string {
	var doc struct {
		Check struct {
			ControlsDigest string `json:"controls_digest"`
		} `json:"check"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ""
	}
	return doc.Check.ControlsDigest
}

// checkExampleReports is the comparison half of the F-12 gate on one example:
// the committed reports against what this build just produced. It returns the
// problems to report and, instead of them, the note to log when the example
// was collected against a DIFFERENT control set.
//
// Ruling G-24: a snapshot collected before a control was added, retitled or
// re-parameterised carries that older set's verdicts in its committed report,
// and this build cannot reproduce them -- the byte comparison would fail on
// every example from the moment controls/ changed until somebody re-ran the
// workflow, which is a staleness alarm wired to the wrong bell. The report's
// own check.controls_digest says which set wrote it, so the comparison runs
// only when that is this build's set. Everything else about the example --
// that it loads, that it evaluates, that no control ends in
// ERROR(internal_error) -- is checked either way by the caller: those are
// properties of the SNAPSHOT, and no control-set change excuses them.
func checkExampleReports(name string, gotJSON, wantJSON, gotTable, wantTable []byte, buildDigest string) (problems []string, note string) {
	if committed := reportControlsDigest(wantJSON); committed != buildDigest {
		return nil, fmt.Sprintf("examples/%s: collected against control set %s, this build is %s; byte comparison skipped",
			name, committed, buildDigest)
	}
	maskedGot, err := maskReportBytes(gotJSON)
	if err != nil {
		return []string{fmt.Sprintf("%s: the report this build produced %v", name, err)}, ""
	}
	maskedWant, err := maskReportBytes(wantJSON)
	if err != nil {
		return []string{fmt.Sprintf("%s: the committed report %v", name, err)}, ""
	}
	if !bytes.Equal(maskedGot, maskedWant) {
		problems = append(problems, fmt.Sprintf(
			"%s-report.json is not what this binary produces from %s; refresh the examples (see examples/README.md)",
			strings.TrimSuffix(name, ".json"), name))
	}
	if !bytes.Equal(tableBody(gotTable), tableBody(wantTable)) {
		problems = append(problems, fmt.Sprintf(
			"%s-report.txt is not what this binary produces from %s; refresh the examples (see examples/README.md)",
			strings.TrimSuffix(name, ".json"), name))
	}
	return problems, ""
}

// tableBody drops the table's first line, which carries the binary version,
// the control set version, the hostname and the collection time.
func tableBody(txt []byte) []byte {
	_, rest, ok := bytes.Cut(txt, []byte("\n"))
	if !ok {
		return nil
	}
	return rest
}

// TestExampleReportHelpers proves the comparison the example test rests on,
// on a synthetic snapshot, so that the helpers are tested whether or not an
// example is committed yet: rendering twice gives the same bytes, masking
// removes exactly the four provenance fields and nothing else, and a report
// with different content survives the mask as different bytes.
func TestExampleReportHelpers(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}
	pass, _, err := openFacts(filepath.Join("testdata", "full-pass.json"))
	if err != nil {
		t.Fatalf("load full-pass: %v", err)
	}

	firstJSON, firstTable := reportsFor(t, pass, set)
	secondJSON, secondTable := reportsFor(t, pass, set)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Error("the JSON report of one snapshot is not the same bytes twice")
	}
	if !bytes.Equal(firstTable, secondTable) {
		t.Error("the table report of one snapshot is not the same bytes twice")
	}

	// The mask removes the four provenance fields and leaves the rest of the
	// report -- run block, summary, results, and the check block's remaining
	// fields -- exactly as it found them.
	var orig, masked map[string]any
	if err := json.Unmarshal(firstJSON, &orig); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if err := json.Unmarshal(maskReport(t, firstJSON), &masked); err != nil {
		t.Fatalf("unmarshal masked report: %v", err)
	}
	origCheck, _ := orig["check"].(map[string]any)
	maskedCheck, _ := masked["check"].(map[string]any)
	if origCheck == nil || maskedCheck == nil {
		t.Fatalf("check block: orig %T masked %T", orig["check"], masked["check"])
	}
	var removed []string
	for k := range origCheck {
		if _, kept := maskedCheck[k]; !kept {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	if !reflect.DeepEqual(removed, maskedCheckKeys) {
		t.Errorf("maskReport removed %v, want exactly %v", removed, maskedCheckKeys)
	}
	for _, k := range maskedCheckKeys {
		if _, present := origCheck[k]; !present {
			t.Errorf("the report has no check.%s to mask", k)
		}
	}
	if !reflect.DeepEqual(origCheck["snapshot_digest"], maskedCheck["snapshot_digest"]) ||
		!reflect.DeepEqual(origCheck["guide_edition"], maskedCheck["guide_edition"]) ||
		!reflect.DeepEqual(origCheck["waivers"], maskedCheck["waivers"]) {
		t.Error("maskReport changed a check field it was not asked to mask")
	}
	delete(orig, "check")
	delete(masked, "check")
	if !reflect.DeepEqual(orig, masked) {
		t.Error("maskReport changed the report outside its check block")
	}

	// tableBody drops the header line and keeps everything after it.
	header, rest, ok := bytes.Cut(firstTable, []byte("\n"))
	if !ok || !bytes.HasPrefix(header, []byte("muster ")) {
		t.Fatalf("the table's first line is not the header: %q", header)
	}
	if !bytes.Equal(tableBody(firstTable), rest) {
		t.Error("tableBody did not drop exactly the first line")
	}
	if !bytes.Contains(tableBody(firstTable), []byte("muster.file.passwd_permissions")) {
		t.Error("tableBody dropped the result rows")
	}
	if bytes.Contains(tableBody(firstTable), []byte("fixture-host")) {
		t.Error("the hostname belongs to the masked header line, not the body")
	}

	// A snapshot that evaluates differently is different masked bytes: the
	// mask hides provenance, never a verdict or an observation.
	fail, _, err := openFacts(filepath.Join("testdata", "full-fail.json"))
	if err != nil {
		t.Fatalf("load full-fail: %v", err)
	}
	failJSON, failTable := reportsFor(t, fail, set)
	if !bytes.Contains(failJSON, []byte(`"observations"`)) {
		t.Fatal("full-fail.json was expected to produce observations")
	}
	if bytes.Equal(maskReport(t, failJSON), maskReport(t, firstJSON)) {
		t.Error("two different snapshots produced the same masked JSON report")
	}
	if bytes.Equal(tableBody(failTable), tableBody(firstTable)) {
		t.Error("two different snapshots produced the same table body")
	}
}

// TestExampleStalenessGate is ruling G-24, driven the way the example gate
// drives it: real reports of a real snapshot, compared through
// checkExampleReports. The committed report is then damaged in two different
// ways -- the verdicts changed while the control-set digest still says this
// build's set, and the same damage with a digest that says another set -- and
// only the first may be reported.
func TestExampleStalenessGate(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}
	pass, _, err := openFacts(filepath.Join("testdata", "full-pass.json"))
	if err != nil {
		t.Fatalf("load full-pass: %v", err)
	}
	gotJSON, gotTable := reportsFor(t, pass, set)

	// The report this build just produced carries this build's digest, which
	// is what makes the gate open at all.
	if got := reportControlsDigest(gotJSON); got != set.Digest {
		t.Fatalf("this build's own report carries controls_digest %q, want %q", got, set.Digest)
	}

	// 1. A current, matching pair: compared, and nothing to report.
	problems, note := checkExampleReports("x.json", gotJSON, gotJSON, gotTable, gotTable, set.Digest)
	if len(problems) != 0 || note != "" {
		t.Errorf("a current example reported %v / %q", problems, note)
	}

	// 2. A current pair whose committed reports do NOT match: both
	//    comparisons fire. This is the branch the gate must not swallow.
	fail, _, err := openFacts(filepath.Join("testdata", "full-fail.json"))
	if err != nil {
		t.Fatalf("load full-fail: %v", err)
	}
	otherJSON, otherTable := reportsFor(t, fail, set)
	problems, note = checkExampleReports("x.json", gotJSON, otherJSON, gotTable, otherTable, set.Digest)
	if note != "" {
		t.Errorf("a committed report of this build's own control set was called stale: %q", note)
	}
	if len(problems) != 2 {
		t.Errorf("a mismatching example reported %d problems, want one per report: %v", len(problems), problems)
	}

	// 3. The same mismatch, but the committed report names another control
	//    set: nothing is reported and the note names both digests.
	stale := retagControlsDigest(t, otherJSON, "sha256:0000000000000000")
	problems, note = checkExampleReports("x.json", gotJSON, stale, gotTable, otherTable, set.Digest)
	if len(problems) != 0 {
		t.Errorf("an example of another control set was compared anyway: %v", problems)
	}
	for _, want := range []string{"x.json", "sha256:0000000000000000", set.Digest, "skipped"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q does not name %q", note, want)
		}
	}

	// 4. A committed report that is not a report at all reads as no digest,
	//    which is nobody's control set, so it is skipped rather than compared
	//    against bytes it cannot be compared with.
	if got := reportControlsDigest([]byte("not json")); got != "" {
		t.Errorf("reportControlsDigest of a non-report = %q", got)
	}
}

// retagControlsDigest returns report with a different check.controls_digest,
// which is how a report collected against an older control set differs from
// one this build could reproduce.
func retagControlsDigest(t *testing.T, report []byte, digest string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(report, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	cb, ok := doc["check"].(map[string]any)
	if !ok {
		t.Fatalf("report has no check block")
	}
	cb["controls_digest"] = digest
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

// TestExamplesLoadAndCheck is the F-12 gate on the committed examples: each
// snapshot still loads, still evaluates without the evaluator recovering a
// panic, and still produces the reports beside it -- the same-input-same-bytes
// contract measured on a real snapshot rather than a fixture.
func TestExamplesLoadAndCheck(t *testing.T) {
	all, err := filepath.Glob(filepath.Join(examplesDir, "*.json"))
	if err != nil {
		t.Fatalf("glob %s: %v", examplesDir, err)
	}
	var snapshots []string
	for _, f := range all {
		if strings.HasSuffix(filepath.Base(f), "-report.json") {
			continue
		}
		snapshots = append(snapshots, f)
	}
	if len(snapshots) == 0 {
		t.Skip("no example snapshot committed under examples/ yet")
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}
	for _, f := range snapshots {
		t.Run(filepath.Base(f), func(t *testing.T) {
			snap, _, err := openFacts(f)
			if err != nil {
				t.Fatalf("%s does not load: %v", f, err)
			}
			gotJSON, gotTable := reportsFor(t, snap, set)

			// ERROR(internal_error) is the status the evaluator gives a
			// control whose evaluation it had to recover from a panic; a real
			// snapshot must not produce one.
			var parsed struct {
				Results []struct {
					ID         string `json:"id"`
					Status     string `json:"status"`
					ReasonCode string `json:"reason_code"`
				} `json:"results"`
			}
			if err := json.Unmarshal(gotJSON, &parsed); err != nil {
				t.Fatalf("report is not JSON: %v", err)
			}
			if len(parsed.Results) == 0 {
				t.Fatal("the report has no results")
			}
			for _, r := range parsed.Results {
				if r.Status == "ERROR" && r.ReasonCode == "internal_error" {
					t.Errorf("%s: %s is ERROR(internal_error)", filepath.Base(f), r.ID)
				}
			}

			base := strings.TrimSuffix(f, ".json")
			wantJSON, err := os.ReadFile(base + "-report.json")
			if err != nil {
				t.Fatalf("every example snapshot needs its JSON report beside it: %v", err)
			}
			wantTable, err := os.ReadFile(base + "-report.txt")
			if err != nil {
				t.Fatalf("every example snapshot needs its table report beside it: %v", err)
			}
			problems, note := checkExampleReports(filepath.Base(f), gotJSON, wantJSON, gotTable, wantTable, set.Digest)
			if note != "" {
				t.Log(note)
			}
			for _, p := range problems {
				t.Error(p)
			}
		})
	}
}
