package main

import (
	"bytes"
	"encoding/json"
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

// maskReport drops maskedCheckKeys from a JSON report and re-marshals it.
// encoding/json sorts map keys, so two masked reports of the same content are
// the same bytes whatever order the originals were written in.
func maskReport(t *testing.T, data []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	cb, ok := doc["check"].(map[string]any)
	if !ok {
		t.Fatalf("report has no check block: %v", doc["check"])
	}
	for _, k := range maskedCheckKeys {
		delete(cb, k)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
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
			if !bytes.Equal(maskReport(t, gotJSON), maskReport(t, wantJSON)) {
				t.Errorf("%s-report.json is not what this binary produces from %s; refresh the examples (see examples/README.md)", filepath.Base(base), filepath.Base(f))
			}
			wantTable, err := os.ReadFile(base + "-report.txt")
			if err != nil {
				t.Fatalf("every example snapshot needs its table report beside it: %v", err)
			}
			if !bytes.Equal(tableBody(gotTable), tableBody(wantTable)) {
				t.Errorf("%s-report.txt is not what this binary produces from %s; refresh the examples (see examples/README.md)", filepath.Base(base), filepath.Base(f))
			}
		})
	}
}
