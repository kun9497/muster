package waiver

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/check"
)

var now = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

func TestLoadRefusesReasonlessUnknownKeyAndBadDate(t *testing.T) {
	bad := []string{
		"waivers:\n  - control: muster.a.b\n    reason: ''\n",
		"waivers:\n  - control: muster.a.b\n    reason: ok\n    expries: 2026-12-31\n",
		"waivers:\n  - control: muster.a.b\n    reason: ok\n    expires: 12/31/2026\n",
		"waivers:\n  - reason: ok\n",
	}
	for _, in := range bad {
		if _, err := Load(strings.NewReader(in), "w.yaml"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: err=%v want ErrInvalid", in, err)
		}
	}
}

func TestLoadGoodFileHasDigest(t *testing.T) {
	f, err := Load(strings.NewReader("waivers:\n  - control: muster.a.b\n    reason: because\n    expires: 2026-12-31\n"), "w.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != "w.yaml" || !strings.HasPrefix(f.Digest, "sha256:") || len(f.Waivers) != 1 {
		t.Fatalf("%+v", f)
	}
}

func results() []check.Result {
	return []check.Result{
		{ID: "muster.a.fail", Status: check.FAIL, Reason: "x"},
		{ID: "muster.a.err", Status: check.ERROR, ReasonCode: check.PermissionDenied},
		{ID: "muster.a.obs", Status: check.WARN, Observations: []check.Observation{
			{Subject: "file:/a", Verdict: "fail"}, {Subject: "file:/b", Verdict: "fail"}}},
	}
}

func TestApplyWaivesFailNeverError(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.fail\n    reason: r\n  - control: muster.a.err\n    reason: r\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[0].Status != check.WAIVED || rs[0].Waiver == nil || !rs[0].Waiver.Applied {
		t.Errorf("FAIL must be waived: %+v", rs[0])
	}
	if rs[1].Status != check.ERROR || rs[1].Waiver == nil || rs[1].Waiver.Applied || !strings.Contains(rs[1].Waiver.NotAppliedBecause, "ERROR") {
		t.Errorf("ERROR must never be waived: %+v", rs[1])
	}
	if a.Applied != 1 || a.NotApplied != 1 || len(warnings) != 0 {
		t.Errorf("%+v %v", a, warnings)
	}
}

func TestApplySubjectLevelAndExpiry(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r\n    expires: 2026-09-10\n  - control: muster.a.fail\n    reason: r\n    expires: 2026-01-01\n  - control: muster.zzz\n    reason: r\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[2].Status != check.WARN || rs[2].Observations[0].Verdict != "waived" || rs[2].Observations[1].Verdict != "fail" {
		t.Errorf("subject waiver must waive one observation and keep the result: %+v", rs[2])
	}
	if rs[0].Status != check.FAIL {
		t.Errorf("expired waiver must not apply: %+v", rs[0])
	}
	if a.Expired != 1 || a.Unknown != 1 || a.ExpiringSoon != 1 {
		t.Errorf("%+v", a)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "expired") || !strings.Contains(joined, "unknown control") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestApplyWaivesResultWhenAllObservationsWaived(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r\n  - control: muster.a.obs\n    subject: file:/b\n    reason: r\n"), "w.yaml")
	rs := results()
	f.Apply(rs, map[string]bool{"muster.a.obs": true}, now, func(string) {})
	if rs[2].Status != check.WAIVED {
		t.Errorf("%+v", rs[2])
	}
}

func TestApplyTwoSubjectWaivers(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r1\n    expires: 2026-09-20\n  - control: muster.a.obs\n    subject: file:/b\n    reason: r2\n    expires: 2026-09-20\n"), "w.yaml")
	rs := results()
	a := f.Apply(rs, map[string]bool{"muster.a.obs": true}, now, func(string) {})
	if rs[2].Status != check.WAIVED || rs[2].Waiver == nil || rs[2].Waiver.Subject != "file:/a, file:/b" {
		t.Errorf("two subject waivers: %+v", rs[2])
	}
	if a.Applied != 2 || a.ExpiringSoon != 2 {
		t.Errorf("applied=%d expiring=%d", a.Applied, a.ExpiringSoon)
	}
}

func TestApplyControlAndSubjectWaivers(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.fail\n    reason: r1\n  - control: muster.a.fail\n    subject: file:/a\n    reason: r2\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[0].Status != check.WAIVED {
		t.Errorf("should be waived: %+v", rs[0])
	}
	if a.Applied != 1 || a.NotApplied != 1 {
		t.Errorf("applied=%d notapplied=%d", a.Applied, a.NotApplied)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "shadowed") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestApplyNoMatchingObservation(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/zzz\n    reason: r\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[2].Status != check.WARN {
		t.Errorf("status should still be WARN: %+v", rs[2])
	}
	if a.NotApplied != 1 {
		t.Errorf("notapplied=%d", a.NotApplied)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "matched no failing observation") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestApplyExpiringSoonBoundary(t *testing.T) {
	// Expires exactly 30 days from now should count as expiring soon
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.fail\n    reason: r\n    expires: 2026-10-02\n"), "w.yaml")
	rs := results()
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(string) {})
	if a.ExpiringSoon != 1 {
		t.Errorf("entry expiring exactly 30 days should count as expiring soon: %d", a.ExpiringSoon)
	}
}
