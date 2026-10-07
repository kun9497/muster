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

// Fix wave item 4: one YAML document per file. A second document used to be
// ignored, so its waivers silently never applied while the digest changed.
func TestLoadRefusesASecondDocument(t *testing.T) {
	two := "waivers:\n  - control: muster.a.b\n    reason: r\n---\nwaivers: []\n"
	f, err := Load(strings.NewReader(two), "w.yaml")
	if f != nil || !errors.Is(err, ErrInvalid) || err.Error() != "invalid waiver file: w.yaml: more than one YAML document" {
		t.Errorf("Load: %+v %v, want the path and the second document named", f, err)
	}
	for _, one := range []string{"", "---\n", "# only a comment\n", "---\nwaivers: []\n"} {
		if _, err := Load(strings.NewReader(one), "w.yaml"); err != nil {
			t.Errorf("Load(%q): %v, want one document accepted", one, err)
		}
	}
}

// I8/R33: two entries for the same (control, subject) meant the second was
// silently dropped, which D12 forbids -- a waiver is counted and reasoned,
// never silent. Load refuses the file instead.
func TestLoadRefusesDuplicateControlAndSubjectPairs(t *testing.T) {
	dup := []string{
		"waivers:\n  - control: muster.a.b\n    reason: one\n  - control: muster.a.b\n    reason: two\n",
		"waivers:\n  - control: muster.a.b\n    subject: file:/a\n    reason: one\n  - control: muster.a.b\n    subject: file:/a\n    reason: two\n",
	}
	for _, in := range dup {
		_, err := Load(strings.NewReader(in), "w.yaml")
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: err=%v want ErrInvalid", in, err)
			continue
		}
		if !strings.Contains(err.Error(), "muster.a.b") {
			t.Errorf("error must name the control: %v", err)
		}
	}
	// A control-level entry next to subject entries, and two different
	// subjects, are all distinct pairs and stay legal.
	ok := "waivers:\n  - control: muster.a.b\n    reason: whole\n" +
		"  - control: muster.a.b\n    subject: file:/a\n    reason: one\n" +
		"  - control: muster.a.b\n    subject: file:/b\n    reason: two\n" +
		"  - control: muster.c.d\n    reason: other\n"
	if _, err := Load(strings.NewReader(ok), "w.yaml"); err != nil {
		t.Errorf("distinct pairs must load: %v", err)
	}
}

// M16: expiry is inclusive of the named day (spec §6.7), so a waiver that
// expires today still applies today.
func TestWaiverExpiringTodayStillApplies(t *testing.T) {
	f, err := Load(strings.NewReader("waivers:\n  - control: muster.a.fail\n    reason: r\n    expires: 2026-09-02\n"), "w.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true}, nil, now, func(s string) { warnings = append(warnings, s) })
	if rs[0].Status != check.WAIVED {
		t.Errorf("a waiver expiring today still applies: %+v (warnings %v)", rs[0], warnings)
	}
	if a.Applied != 1 || a.Expired != 0 {
		t.Errorf("applied=%d expired=%d, want 1 and 0", a.Applied, a.Expired)
	}
	// One day later it has expired.
	rs = results()
	a = f.Apply(rs, map[string]bool{"muster.a.fail": true}, nil, now.AddDate(0, 0, 1), func(string) {})
	if rs[0].Status != check.FAIL || a.Expired != 1 {
		t.Errorf("the day after expiry it must stop waiving: %+v tally=%+v", rs[0], a)
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
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, nil, now, func(s string) { warnings = append(warnings, s) })
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
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, nil, now, func(s string) { warnings = append(warnings, s) })
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
	f.Apply(rs, map[string]bool{"muster.a.obs": true}, nil, now, func(string) {})
	if rs[2].Status != check.WAIVED {
		t.Errorf("%+v", rs[2])
	}
}

func TestApplyTwoSubjectWaivers(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r1\n    expires: 2026-09-20\n  - control: muster.a.obs\n    subject: file:/b\n    reason: r2\n    expires: 2026-09-20\n"), "w.yaml")
	rs := results()
	a := f.Apply(rs, map[string]bool{"muster.a.obs": true}, nil, now, func(string) {})
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
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, nil, now, func(s string) { warnings = append(warnings, s) })
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
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, nil, now, func(s string) { warnings = append(warnings, s) })
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
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, nil, now, func(string) {})
	if a.ExpiringSoon != 1 {
		t.Errorf("entry expiring exactly 30 days should count as expiring soon: %d", a.ExpiringSoon)
	}
}

// A waiver naming a control the profile excludes is counted not_applied and
// warned -- never unknown, never silently dropped -- whatever its expiry, and
// with its subject named when it has one (spec 3D-1 §2, §5).
func TestApplyCountsAnExcludedWaiverAsNotApplied(t *testing.T) {
	f := &File{Waivers: []Waiver{
		{Control: "muster.beyond.x", Reason: "r"},
		{Control: "muster.beyond.x", Subject: "file:/a", Reason: "r"},
		{Control: "muster.beyond.y", Reason: "r", Expires: "2000-01-01"}, // excluded AND expired
		{Control: "muster.nope", Reason: "r"},
	}}
	rs := results()
	known := map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}
	excluded := map[string]bool{"muster.beyond.x": true, "muster.beyond.y": true}
	var warnings []string
	tally := f.Apply(rs, known, excluded, now, func(m string) { warnings = append(warnings, m) })
	if tally.NotApplied != 3 || tally.Unknown != 1 || tally.Expired != 0 || tally.Applied != 0 {
		t.Errorf("tally %+v: want not_applied 3 (one expired, one with a subject), unknown 1, expired 0", tally)
	}
	want := []string{
		"waiver for muster.beyond.x not applied: excluded by profile",
		"waiver for muster.beyond.x not applied: excluded by profile (subject file:/a)",
		"waiver for muster.beyond.y not applied: excluded by profile",
		"waiver names unknown control muster.nope",
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(warnings, "\n"), strings.Join(want, "\n"))
	}
	for _, r := range rs {
		if r.Waiver != nil {
			t.Errorf("%s: no row carries an excluded waiver: %+v", r.ID, r.Waiver)
		}
	}
}
