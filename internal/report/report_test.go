package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
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
	cb := CheckBlock{MusterVersion: "0.1.0", Commit: "abc1234", ControlsVersion: "kisa-unix-2026+2026.09.02", ControlsDigest: "sha256:c", SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026",
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
