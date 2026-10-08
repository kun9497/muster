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
	"github.com/kun9497/muster/internal/remedy"
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
	return renderReports(t, checkReportFor(t, snap, set))
}

// checkReportFor evaluates one snapshot the way `muster check` and `muster
// fix` both do, under the built-in default profile and no waivers.
func checkReportFor(t *testing.T, snap *facts.Snapshot, set *controls.Set) *report.Report {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	// A snapshot collected against an older control set warns, and that is
	// not a failure here: F-12 keeps an example valid as long as it loads
	// and evaluates.
	sel, err := resolveSelection("default", nil, set, func(msg string) { t.Logf("check warning: %s", msg) })
	if err != nil {
		t.Fatalf("resolve default profile: %v", err)
	}
	results, cb := newCheckBlock(sel, snap, reg, nil, func(msg string) { t.Logf("check warning: %s", msg) })
	return report.Build(snap, results, cb, sel.SeverityByID)
}

// renderReports renders check's JSON and table reports of rep.
func renderReports(t *testing.T, rep *report.Report) (jsonReport, tableReport []byte) {
	t.Helper()
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

// fixReportsFor renders the three outputs of `muster fix --dry-run` from the
// report check produced, at the default max-risk (Z-14).
func fixReportsFor(t *testing.T, rep *report.Report, set *controls.Set) (jsonPlan, tablePlan, script []byte) {
	t.Helper()
	p, err := remedy.Build(rep, set, remedy.Options{MaxRisk: "lockout_risk"})
	if err != nil {
		t.Fatal(err)
	}
	return remedy.JSON(p), remedy.Table(p, false), remedy.Script(p)
}

// maskReportBytes drops maskedCheckKeys from the named provenance block
// ("check" for a check report, "fix" for a fix plan; the two blocks carry the
// same four fields) and re-marshals it. encoding/json sorts map keys, so two
// masked reports of the same content are the same bytes whatever order the
// originals were written in.
func maskReportBytes(data []byte, block string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("report is not JSON: %w", err)
	}
	cb, ok := doc[block].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("report has no %s block: %v", block, doc[block])
	}
	for _, k := range maskedCheckKeys {
		delete(cb, k)
	}
	return json.Marshal(doc)
}

// maskReport is maskReportBytes for a caller that has a *testing.T and for
// which a malformed report is simply the end of the test.
func maskReport(t *testing.T, data []byte, block string) []byte {
	t.Helper()
	out, err := maskReportBytes(data, block)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// reportControlsDigest returns a report's <block>.controls_digest, or the
// error that says the bytes are not JSON at all. A report that parses but
// carries no digest reads as "", which never equals a real digest, so it is
// treated as a set this build cannot reproduce; bytes that do not parse are a
// damaged file, not another control set, and the caller must say so rather
// than skip them.
func reportControlsDigest(data []byte, block string) (string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", err
	}
	var b struct {
		ControlsDigest string `json:"controls_digest"`
	}
	if raw, ok := doc[block]; ok {
		if err := json.Unmarshal(raw, &b); err != nil {
			return "", err
		}
	}
	return b.ControlsDigest, nil
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
	// A committed report that does not parse has no digest to compare, but it
	// is a damaged file rather than another control set: skipping it would
	// hide a truncated or half-written report behind the staleness note.
	committed, err := reportControlsDigest(wantJSON, "check")
	if err != nil {
		return []string{fmt.Sprintf("%s-report.json does not parse as JSON: %v; refresh the examples (see examples/README.md)",
			strings.TrimSuffix(name, ".json"), err)}, ""
	}
	if committed != buildDigest {
		return nil, fmt.Sprintf("examples/%s: collected against control set %s, this build is %s; byte comparison skipped",
			name, committed, buildDigest)
	}
	maskedGot, err := maskReportBytes(gotJSON, "check")
	if err != nil {
		return []string{fmt.Sprintf("%s: the report this build produced %v", name, err)}, ""
	}
	maskedWant, err := maskReportBytes(wantJSON, "check")
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

// checkFixReports is checkExampleReports for the three fix outputs of one
// example: the plan JSON masked under its "fix" block, the table without its
// header line, and the review script byte for byte (Z-22: it carries no
// muster version or commit, and the comparison runs only when the committed
// plan's fix.controls_digest is this build's set, G-24).
func checkFixReports(name string, gotJSON, wantJSON, gotTable, wantTable, gotScript, wantScript []byte, buildDigest string) (problems []string, note string) {
	base := strings.TrimSuffix(name, ".json")
	committed, err := reportControlsDigest(wantJSON, "fix")
	if err != nil {
		return []string{fmt.Sprintf("%s-fix-report.json does not parse as JSON: %v; refresh the examples (see examples/README.md)", base, err)}, ""
	}
	if committed != buildDigest {
		return nil, fmt.Sprintf("examples/%s: fix reports collected against control set %s, this build is %s; byte comparison skipped",
			name, committed, buildDigest)
	}
	maskedGot, err := maskReportBytes(gotJSON, "fix")
	if err != nil {
		return []string{fmt.Sprintf("%s: the plan this build produced %v", name, err)}, ""
	}
	maskedWant, err := maskReportBytes(wantJSON, "fix")
	if err != nil {
		return []string{fmt.Sprintf("%s: the committed plan %v", name, err)}, ""
	}
	stale := func(ext string) string {
		return fmt.Sprintf("%s-fix-report.%s is not what this binary produces from %s; refresh the examples (see examples/README.md)", base, ext, name)
	}
	if !bytes.Equal(maskedGot, maskedWant) {
		problems = append(problems, stale("json"))
	}
	if !bytes.Equal(tableBody(gotTable), tableBody(wantTable)) {
		problems = append(problems, stale("txt"))
	}
	if !bytes.Equal(gotScript, wantScript) {
		problems = append(problems, stale("sh"))
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
	if err := json.Unmarshal(maskReport(t, firstJSON, "check"), &masked); err != nil {
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
	if bytes.Equal(maskReport(t, failJSON, "check"), maskReport(t, firstJSON, "check")) {
		t.Error("two different snapshots produced the same masked JSON report")
	}
	if bytes.Equal(tableBody(failTable), tableBody(firstTable)) {
		t.Error("two different snapshots produced the same table body")
	}

	// The fix outputs (Z-14): the same bytes twice, the mask under the "fix"
	// block removes the same four fields and nothing else, and a different
	// snapshot is a different plan in all three formats.
	passRep := checkReportFor(t, pass, set)
	fixJSON, fixTable, fixScript := fixReportsFor(t, passRep, set)
	j2, t2, s2 := fixReportsFor(t, checkReportFor(t, pass, set), set)
	if !bytes.Equal(fixJSON, j2) || !bytes.Equal(fixTable, t2) || !bytes.Equal(fixScript, s2) {
		t.Error("the fix outputs of one snapshot are not the same bytes twice")
	}
	if _, err := maskReportBytes(fixJSON, "check"); err == nil {
		t.Error("a fix plan masked under the check block did not fail")
	}
	var origFix, maskedFix map[string]any
	if err := json.Unmarshal(fixJSON, &origFix); err != nil {
		t.Fatalf("unmarshal plan: %v", err)
	}
	if err := json.Unmarshal(maskReport(t, fixJSON, "fix"), &maskedFix); err != nil {
		t.Fatalf("unmarshal masked plan: %v", err)
	}
	of, _ := origFix["fix"].(map[string]any)
	mf, _ := maskedFix["fix"].(map[string]any)
	if of == nil || mf == nil {
		t.Fatalf("fix block: orig %T masked %T", origFix["fix"], maskedFix["fix"])
	}
	removed = nil
	for k := range of {
		if _, kept := mf[k]; !kept {
			removed = append(removed, k)
		}
	}
	sort.Strings(removed)
	if !reflect.DeepEqual(removed, maskedCheckKeys) {
		t.Errorf("maskReport(fix) removed %v, want exactly %v", removed, maskedCheckKeys)
	}
	for _, k := range []string{"snapshot_digest", "guide_edition", "profile", "waivers", "max_risk"} {
		if !reflect.DeepEqual(of[k], mf[k]) {
			t.Errorf("maskReport(fix) changed fix.%s", k)
		}
	}
	delete(origFix, "fix")
	delete(maskedFix, "fix")
	if !reflect.DeepEqual(origFix, maskedFix) {
		t.Error("maskReport(fix) changed the plan outside its fix block")
	}
	if d, err := reportControlsDigest(fixJSON, "fix"); err != nil || d != set.Digest {
		t.Errorf("the plan's fix.controls_digest is %q (err %v), want %q", d, err, set.Digest)
	}
	if d, err := reportControlsDigest(fixJSON, "check"); err != nil || d != "" {
		t.Errorf("a plan read as a check report carries digest %q (err %v), want none", d, err)
	}
	if h, _, _ := bytes.Cut(fixTable, []byte("\n")); !bytes.HasPrefix(h, []byte("muster ")) ||
		!bytes.Contains(tableBody(fixTable), []byte("nothing to fix")) {
		t.Errorf("the fix table is not a header line then the plan:\n%s", fixTable)
	}
	failFixJSON, failFixTable, failFixScript := fixReportsFor(t, checkReportFor(t, fail, set), set)
	if bytes.Equal(maskReport(t, failFixJSON, "fix"), maskReport(t, fixJSON, "fix")) ||
		bytes.Equal(tableBody(failFixTable), tableBody(fixTable)) || bytes.Equal(failFixScript, fixScript) {
		t.Error("two different snapshots produced the same fix output")
	}

	// The gates compare the tables without their header line: a committed
	// table whose first line names another binary, host or time is not a
	// problem, for check's table and for fix's, while the same body after an
	// extra line is.
	otherHeader := func(tbl []byte) []byte { return append([]byte("muster other · host elsewhere\n"), tableBody(tbl)...) }
	if bytes.Equal(otherHeader(firstTable), firstTable) || bytes.Equal(otherHeader(fixTable), fixTable) {
		t.Fatal("the re-headed tables are the same bytes; the check below would prove nothing")
	}
	if problems, note := checkExampleReports("x.json", firstJSON, firstJSON, firstTable, otherHeader(firstTable), set.Digest); len(problems) != 0 || note != "" {
		t.Errorf("check's gate reported a header-only difference: %v / %q", problems, note)
	}
	if problems, note := checkFixReports("x.json", fixJSON, fixJSON, fixTable, otherHeader(fixTable), fixScript, fixScript, set.Digest); len(problems) != 0 || note != "" {
		t.Errorf("fix's gate reported a header-only difference: %v / %q", problems, note)
	}
	shifted := append([]byte("muster x\n"), otherHeader(fixTable)...)
	if problems, _ := checkFixReports("x.json", fixJSON, fixJSON, fixTable, shifted, fixScript, fixScript, set.Digest); len(problems) != 1 || !strings.HasPrefix(problems[0], "x-fix-report.txt ") {
		t.Errorf("fix's gate missed a body difference: %v", problems)
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
	if got, err := reportControlsDigest(gotJSON, "check"); err != nil || got != set.Digest {
		t.Fatalf("this build's own report carries controls_digest %q (err %v), want %q", got, err, set.Digest)
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
	stale := retagControlsDigest(t, otherJSON, "check", "sha256:0000000000000000")
	problems, note = checkExampleReports("x.json", gotJSON, stale, gotTable, otherTable, set.Digest)
	if len(problems) != 0 {
		t.Errorf("an example of another control set was compared anyway: %v", problems)
	}
	for _, want := range []string{"x.json", "sha256:0000000000000000", set.Digest, "skipped"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note %q does not name %q", note, want)
		}
	}

	// 4. A committed report that is not JSON at all is a damaged file, not
	//    another control set: it is reported, naming the file, and never
	//    swallowed by the staleness note.
	problems, note = checkExampleReports("x.json", gotJSON, []byte("not json"), gotTable, otherTable, set.Digest)
	if note != "" {
		t.Errorf("a corrupt committed report was called stale: %q", note)
	}
	if len(problems) != 1 {
		t.Fatalf("a corrupt committed report reported %d problems, want 1: %v", len(problems), problems)
	}
	if !strings.Contains(problems[0], "x-report.json") {
		t.Errorf("the problem %q does not name the committed report file", problems[0])
	}

	// A report that parses but names another control set still takes the
	// skip, so the new branch reports damage only.
	if _, err := reportControlsDigest(stale, "check"); err != nil {
		t.Errorf("a well-formed report of another control set does not parse: %v", err)
	}

	// The same four cases for the fix outputs, gated on fix.controls_digest
	// (Z-14, Z-22).
	gotFJ, gotFT, gotFS := fixReportsFor(t, checkReportFor(t, pass, set), set)
	otherFJ, otherFT, otherFS := fixReportsFor(t, checkReportFor(t, fail, set), set)
	problems, note = checkFixReports("x.json", gotFJ, gotFJ, gotFT, gotFT, gotFS, gotFS, set.Digest)
	if len(problems) != 0 || note != "" {
		t.Errorf("current fix reports reported %v / %q", problems, note)
	}
	problems, note = checkFixReports("x.json", gotFJ, otherFJ, gotFT, otherFT, gotFS, otherFS, set.Digest)
	if note != "" || len(problems) != 3 {
		t.Errorf("mismatching fix reports: note %q, %d problems, want one per file: %v", note, len(problems), problems)
	}
	for i, ext := range []string{"json", "txt", "sh"} {
		if i < len(problems) && !strings.HasPrefix(problems[i], "x-fix-report."+ext+" is not what this binary produces from x.json") {
			t.Errorf("problem %d %q does not name x-fix-report.%s", i, problems[i], ext)
		}
	}
	// Only the script differs: the byte comparison of the script catches it.
	problems, _ = checkFixReports("x.json", gotFJ, gotFJ, gotFT, gotFT, gotFS, append(append([]byte{}, gotFS...), '#'), set.Digest)
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "x-fix-report.sh ") {
		t.Errorf("a changed script reported %v, want the .sh only", problems)
	}
	staleFix := retagControlsDigest(t, otherFJ, "fix", "sha256:0000000000000000")
	problems, note = checkFixReports("x.json", gotFJ, staleFix, gotFT, otherFT, gotFS, otherFS, set.Digest)
	if len(problems) != 0 {
		t.Errorf("fix reports of another control set were compared anyway: %v", problems)
	}
	for _, want := range []string{"x.json", "sha256:0000000000000000", set.Digest, "skipped"} {
		if !strings.Contains(note, want) {
			t.Errorf("the fix note %q does not name %q", note, want)
		}
	}
	problems, note = checkFixReports("x.json", gotFJ, []byte("not json"), gotFT, otherFT, gotFS, otherFS, set.Digest)
	if note != "" || len(problems) != 1 || !strings.Contains(problems[0], "x-fix-report.json") {
		t.Errorf("a corrupt committed plan: note %q, problems %v", note, problems)
	}
	// A check report's digest says nothing about the fix block.
	problems, note = checkFixReports("x.json", gotFJ, gotJSON, gotFT, gotFT, gotFS, gotFS, set.Digest)
	if len(problems) != 0 || note == "" {
		t.Errorf("a check report in place of a plan: problems %v, note %q, want the skip", problems, note)
	}
}

// readExample reads a committed example file; a missing one is a failure
// that names the file and the refresh (Z-14), never a skip.
func readExample(path, what string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("every example snapshot needs its %s beside it: %v; refresh the examples (see examples/README.md)", what, err)
	}
	return b, nil
}

// W3/W5: a missing committed report or fix file fails naming the refresh.
func TestReadExampleNamesTheRefresh(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "x-fix-report.json")
	if _, err := readExample(missing, "fix reports"); err == nil {
		t.Fatal("a missing example file read without an error")
	} else {
		msg := err.Error()
		if !strings.HasPrefix(msg, "every example snapshot needs its fix reports beside it: ") ||
			!strings.HasSuffix(msg, "; refresh the examples (see examples/README.md)") || !strings.Contains(msg, missing) {
			t.Errorf("the failure %q does not name the file and the refresh", msg)
		}
	}
	if err := os.WriteFile(missing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readExample(missing, "fix reports"); err != nil || string(b) != "x" {
		t.Errorf("readExample of a present file: %q, %v", b, err)
	}
}

// retagControlsDigest returns report with a different <block>.controls_digest,
// which is how a report collected against an older control set differs from
// one this build could reproduce.
func retagControlsDigest(t *testing.T, report []byte, block, digest string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(report, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	cb, ok := doc[block].(map[string]any)
	if !ok {
		t.Fatalf("report has no %s block", block)
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
			rep := checkReportFor(t, snap, set)
			gotJSON, gotTable := renderReports(t, rep)

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
			wantJSON, err := readExample(base+"-report.json", "JSON report")
			if err != nil {
				t.Fatal(err)
			}
			wantTable, err := readExample(base+"-report.txt", "table report")
			if err != nil {
				t.Fatal(err)
			}
			problems, note := checkExampleReports(filepath.Base(f), gotJSON, wantJSON, gotTable, wantTable, set.Digest)
			if note != "" {
				t.Log(note)
			}
			for _, p := range problems {
				t.Error(p)
			}

			// The fix outputs of the same report (Z-14): a missing file is
			// a hard failure that ends "; refresh the examples (see
			// examples/README.md)", never a skip.
			gotFJ, gotFT, gotFS := fixReportsFor(t, rep, set)
			var want [3][]byte
			for i, ext := range []string{"json", "txt", "sh"} {
				if want[i], err = readExample(base+"-fix-report."+ext, "fix reports"); err != nil {
					t.Fatal(err)
				}
			}
			problems, note = checkFixReports(filepath.Base(f), gotFJ, want[0], gotFT, want[1], gotFS, want[2], set.Digest)
			if note != "" {
				t.Log(note)
			}
			for _, p := range problems {
				t.Error(p)
			}
		})
	}
}
