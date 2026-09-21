package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sampleReport(t *testing.T) *Report {
	t.Helper()
	snap, err := facts.Load(strings.NewReader(`{"schema_version":1,"run":{"muster_version":"0.1.0","collected_at":"2026-09-02T06:00:00Z",
	  "host":{"hostname":"web-01"},"collectors":[{"name":"sshd","status":"ok","ms":41},{"name":"walk","status":"skipped","ms":0}],
	  "complete":true,"partial_failures":[]},"facts":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	results := []check.Result{
		{ID: "muster.file.world_writable", Importance: "상", Automation: "partial", Status: check.WARN, Reason: "observations need human review",
			Observations: []check.Observation{{Subject: "file:/var/tmp/x", Expected: true, Actual: false, Verdict: "fail"}}},
		{ID: "muster.service.telnet_disabled", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.account.root_remote_login", Importance: "상", Automation: "auto", Status: check.FAIL, Reason: "clause does not hold",
			Evidence: []check.Evidence{{Fact: "sshd.options.permit_root_login", Status: facts.StatusOK, Value: "yes", Side: "effective",
				Source: &facts.Source{Kind: "file", Path: "/etc/ssh/sshd_config", Line: 40, Raw: "PermitRootLogin yes"}}}},
		{ID: "muster.file.passwd_permissions", Importance: "상", Automation: "auto", Status: check.ERROR, ReasonCode: check.PermissionDenied, Reason: "needs root"},
		{ID: "muster.account.password_policy", Importance: "상", Automation: "auto", Status: check.WAIVED, Waiver: &check.WaiverNote{Applied: true, Reason: "r", Expires: "2026-09-20"}},
		{ID: "muster.log.review", Importance: "하", Automation: "manual", Status: check.MANUAL, Reason: "interview"},
	}
	cb := CheckBlock{MusterVersion: "0.1.0", Commit: "abc1234", ControlsVersion: "kisa-unix-2026+2026.09.09", ControlsDigest: "sha256:c", SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026",
		Waivers: WaiversBlock{Path: "w.yaml", Digest: "sha256:w", Applied: 1, ExpiringSoon: 1}}
	return Build(snap, results, cb)
}

func TestBuildSortsAndSummarises(t *testing.T) {
	r := sampleReport(t)
	ids := []string{}
	for _, row := range r.Results {
		ids = append(ids, row.ID)
	}
	want := "muster.account.password_policy,muster.account.root_remote_login,muster.file.passwd_permissions,muster.file.world_writable,muster.service.telnet_disabled,muster.log.review"
	if strings.Join(ids, ",") != want {
		t.Fatalf("order %v", ids)
	}
	s := r.Summary
	if s.Automatic.High.Fail != 1 || s.Automatic.Medium.Pass != 1 || s.Automatic.High.Warn != 0 {
		t.Errorf("automatic %+v", s.Automatic)
	}
	if s.ManualReview != 2 { // MANUAL + partial WARN
		t.Errorf("manual review %d", s.ManualReview)
	}
	if s.Undecidable.Error != 1 || s.Undecidable.Waived != 1 || s.FactsFailed != 1 || s.WaiversExpiringSoon != 1 {
		t.Errorf("undecidable %+v facts_failed %d expiring %d", s.Undecidable, s.FactsFailed, s.WaiversExpiringSoon)
	}
	if r.Results[0].Severity != "high" || r.Results[5].Severity != "low" {
		t.Errorf("severity %+v", r.Results)
	}
}

func TestJSONIsDeterministicAndMatchesGolden(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteJSON(&a, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two renders of the same input differ")
	}
	if !bytes.HasSuffix(a.Bytes(), []byte("\n")) {
		t.Error("output must end with a newline")
	}
	golden := filepath.Join("testdata", "basic.json.golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(golden, a.Bytes(), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(a.Bytes(), want) {
		t.Fatalf("JSON differs from golden; if intended run: go test ./internal/report -run TestJSON -update\n%s", a.String())
	}
}

func TestSeverityMapping(t *testing.T) {
	for in, want := range map[string]string{"상": "high", "중": "medium", "하": "low", "": "low"} {
		if got := Severity(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}

// scopedResults is one result of every status the counting loop can reach,
// split across the two scopes of B-9, so a bucket the scope loop forgot
// cannot hide behind a bucket it got right.
func scopedResults() []check.Result {
	return []check.Result{
		{ID: "muster.account.root_remote_login", Category: "account", Importance: "상", Automation: "auto", Status: check.FAIL},
		{ID: "muster.service.telnet_disabled", Category: "service", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.file.passwd_permissions", Category: "file", Importance: "상", Automation: "auto", Status: check.ERROR},
		{ID: "muster.log.review", Category: "log", Importance: "하", Automation: "manual", Status: check.MANUAL},
		{ID: "muster.beyond.aslr_and_link_protection", Category: "beyond", Importance: "상", Automation: "auto", Status: check.FAIL},
		{ID: "muster.beyond.sysrq_restricted", Category: "beyond", Importance: "중", Automation: "auto", Status: check.WARN},
		{ID: "muster.beyond.separate_partitions", Category: "beyond", Importance: "중", Automation: "partial", Status: check.WARN},
		{ID: "muster.beyond.swap_encrypted", Category: "beyond", Importance: "하", Automation: "auto", Status: check.PASS},
		{ID: "muster.beyond.secure_boot_enabled", Category: "beyond", Importance: "중", Automation: "auto", Status: check.NotApplicable},
		{ID: "muster.beyond.bootloader_password", Category: "beyond", Importance: "상", Automation: "auto", Status: check.WAIVED},
	}
}

// buildWith builds a report over a minimal snapshot from arbitrary results,
// so a test can choose the categories the counting loop and the sort see.
func buildWith(t *testing.T, results []check.Result) *Report {
	t.Helper()
	snap, err := facts.Load(strings.NewReader(`{"schema_version":1,"run":{"muster_version":"0.1.0","collected_at":"2026-09-02T06:00:00Z",
	  "host":{"hostname":"web-01"},"collectors":[{"name":"sshd","status":"ok","ms":1}],
	  "complete":true,"partial_failures":[]},"facts":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	return Build(snap, results, CheckBlock{MusterVersion: "0.1.0", GuideEdition: "kisa-unix-2026"})
}

// addScopes folds two scopes into one, which is what B-9 promises the split
// is: a partition of the very same rows. The three parts are added field by
// field, so a field added to ScopeCounts and not here fails to compile.
func addScopes(a, b ScopeCounts) ScopeCounts {
	add := func(x, y StatusCounts) StatusCounts {
		return StatusCounts{Pass: x.Pass + y.Pass, Fail: x.Fail + y.Fail, Warn: x.Warn + y.Warn}
	}
	return ScopeCounts{
		Controls: a.Controls + b.Controls,
		Automatic: SeverityCounts{
			High:   add(a.Automatic.High, b.Automatic.High),
			Medium: add(a.Automatic.Medium, b.Automatic.Medium),
			Low:    add(a.Automatic.Low, b.Automatic.Low),
		},
		ManualReview: a.ManualReview + b.ManualReview,
		Undecidable: UndecidableCounts{
			Error:         a.Undecidable.Error + b.Undecidable.Error,
			NotApplicable: a.Undecidable.NotApplicable + b.Undecidable.NotApplicable,
			Waived:        a.Undecidable.Waived + b.Undecidable.Waived,
		},
	}
}

// B-9: summary keeps every existing field with its existing meaning -- totals
// over every control -- and gains a scopes object whose two halves sum to it.
func TestSummaryScopesSumToTheTotal(t *testing.T) {
	two := buildWith(t, []check.Result{
		{ID: "muster.account.root_remote_login", Category: "account", Importance: "상", Automation: "auto", Status: check.FAIL},
		{ID: "muster.beyond.aslr_and_link_protection", Category: "beyond", Importance: "상", Automation: "auto", Status: check.FAIL},
	}).Summary
	if two.Scopes.Guide.Controls != 1 || two.Scopes.Beyond.Controls != 1 {
		t.Errorf("one control in each scope: guide %d beyond %d", two.Scopes.Guide.Controls, two.Scopes.Beyond.Controls)
	}

	s := buildWith(t, scopedResults()).Summary
	if s.Scopes.Guide.Controls != 4 || s.Scopes.Beyond.Controls != 6 {
		t.Errorf("controls per scope: guide %d beyond %d", s.Scopes.Guide.Controls, s.Scopes.Beyond.Controls)
	}
	// Each scope is the split of its own rows, not a copy of the total.
	if s.Scopes.Guide.Undecidable.Error != 1 || s.Scopes.Beyond.Undecidable.Error != 0 {
		t.Errorf("an error belongs to the scope that produced it: %+v", s.Scopes)
	}
	if s.Scopes.Guide.ManualReview != 1 || s.Scopes.Beyond.ManualReview != 1 {
		t.Errorf("manual review per scope: guide %d beyond %d", s.Scopes.Guide.ManualReview, s.Scopes.Beyond.ManualReview)
	}
	if s.Scopes.Beyond.Automatic.Medium.Warn != 1 || s.Scopes.Guide.Automatic.Medium.Warn != 0 {
		t.Errorf("an auto WARN belongs to its own scope's severity bucket: %+v", s.Scopes)
	}
	sum := addScopes(s.Scopes.Guide, s.Scopes.Beyond)
	if !reflect.DeepEqual(sum.Automatic, s.Automatic) {
		t.Errorf("automatic: guide+beyond %+v, top level %+v", sum.Automatic, s.Automatic)
	}
	if sum.ManualReview != s.ManualReview {
		t.Errorf("manual_review: guide+beyond %d, top level %d", sum.ManualReview, s.ManualReview)
	}
	if !reflect.DeepEqual(sum.Undecidable, s.Undecidable) {
		t.Errorf("undecidable: guide+beyond %+v, top level %+v", sum.Undecidable, s.Undecidable)
	}
	if sum.Controls != len(scopedResults()) {
		t.Errorf("every row falls in exactly one scope: %d of %d", sum.Controls, len(scopedResults()))
	}
}

// oldOrderIDs sorts by the comparator Build used before the scope split --
// severity, then id -- over rows in their input order. K-1: a report with no
// beyond row must still come out in exactly this order.
func oldOrderIDs(results []check.Result) []string {
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		rows = append(rows, Row{Result: r, Severity: Severity(r.Importance)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if severityRank[rows[i].Severity] != severityRank[rows[j].Severity] {
			return severityRank[rows[i].Severity] < severityRank[rows[j].Severity]
		}
		return rows[i].ID < rows[j].ID
	})
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids
}

func rowIDs(r *Report) []string {
	ids := make([]string, 0, len(r.Results))
	for _, row := range r.Results {
		ids = append(ids, row.ID)
	}
	return ids
}

// B-9: rows sort by (scope, severity, id). A high beyond row therefore prints
// after a low guide row, which is the point of the split.
func TestRowsSortGuideBeforeBeyond(t *testing.T) {
	mixed := []check.Result{
		{ID: "muster.beyond.aslr", Category: "beyond", Importance: "상", Automation: "auto", Status: check.FAIL},
		{ID: "muster.log.review", Category: "log", Importance: "하", Automation: "manual", Status: check.MANUAL},
		{ID: "muster.account.b", Category: "account", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.account.a", Category: "account", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.beyond.sysrq", Category: "beyond", Importance: "하", Automation: "auto", Status: check.PASS},
	}
	want := []string{"muster.account.a", "muster.account.b", "muster.log.review", "muster.beyond.aslr", "muster.beyond.sysrq"}
	if got := rowIDs(buildWith(t, mixed)); !reflect.DeepEqual(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}

	// K-1: with no beyond row the order is the old one, row for row.
	guideOnly := []check.Result{
		{ID: "muster.file.world_writable", Category: "file", Importance: "상", Automation: "partial", Status: check.WARN},
		{ID: "muster.service.telnet_disabled", Category: "service", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.account.root_remote_login", Category: "account", Importance: "상", Automation: "auto", Status: check.FAIL},
		{ID: "muster.log.review", Category: "log", Importance: "하", Automation: "manual", Status: check.MANUAL},
		{ID: "muster.account.password_policy", Category: "account", Importance: "상", Automation: "auto", Status: check.WAIVED},
	}
	if got, old := rowIDs(buildWith(t, guideOnly)), oldOrderIDs(guideOnly); !reflect.DeepEqual(got, old) {
		t.Errorf("a report with no beyond row must sort as before: %v, want %v", got, old)
	}
}
