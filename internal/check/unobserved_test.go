package check

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// fixtureSnap loads a control's fixture, letting edit change it first.
func fixtureSnap(t *testing.T, id, name string, edit func(map[string]any)) *facts.Snapshot {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "controls", "testdata", id, name))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		if b, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	s, err := facts.Load(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// UnobservedFail is set exactly when a clause that does not hold carried no
// failing observation — a scalar clause, which a subject waiver cannot name
// (spec §6.4) — on the checks path, the mechanism path and for a WARN, and
// never for a failing collection clause alone or a holding row.
func TestUnobservedFailMarksOnlyAFailingScalarClause(t *testing.T) {
	const sudo = "muster.beyond.sudo_nopasswd_all"
	authOn := func(m map[string]any) {
		m["facts"].(map[string]any)["sudo"].(map[string]any)["authenticate_disabled"].(map[string]any)["value"] = true
	}
	ctrl := embedded(t, sudo)
	mech := controls.Control{
		ID: "muster.account.mech", Importance: "중", Category: "account", Automation: "auto", AbsentMeans: "not_applicable",
		Mechanisms: []controls.Mechanism{{
			When:   controls.ClauseList{{Fact: "services.telnet.reachable", Op: "eq", Expected: true}},
			Checks: []controls.Clause{{Fact: "accounts.login_defs.pass_max_days", Op: "lte", Expected: 90}},
		}},
		Remediation: &controls.Remediation{Risk: "none"},
	}
	for _, c := range []struct {
		name       string
		r          func() Result
		wantStatus Status
		want       bool
	}{
		{"collection clause alone fails", func() Result {
			return Evaluate(fixtureSnap(t, sudo, "fail-cloud-init.json", nil), one(ctrl), reg, Options{})[0]
		}, FAIL, false},
		{"scalar clause alone fails", func() Result {
			return Evaluate(fixtureSnap(t, sudo, "fail-authenticate-disabled.json", nil), one(ctrl), reg, Options{})[0]
		}, FAIL, true},
		{"collection and scalar clauses fail", func() Result {
			return Evaluate(fixtureSnap(t, sudo, "fail-cloud-init.json", authOn), one(ctrl), reg, Options{})[0]
		}, FAIL, true},
		{"holds", func() Result {
			return Evaluate(fixtureSnap(t, sudo, "pass-stock-ubuntu.json", nil), one(ctrl), reg, Options{})[0]
		}, PASS, false},
		{"none clause fails", func() Result {
			return evalSingle(t, `{"accounts":{"users":{"status":"ok","value":[{"name":"x","password_status":"nopass"}]}}}`, nopassControl())
		}, FAIL, false},
		{"scalar side mismatch is WARN", func() Result { return sideOnlyResult(t) }, WARN, true},
		{"mechanism scalar clause fails", func() Result {
			return evalSingle(t, `{"services":{"telnet":{"reachable":{"status":"ok","value":true}}},`+
				`"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":99999},"persisted":{"status":"ok","value":99999}}}}}`, mech)
		}, FAIL, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := c.r()
			if r.Status != c.wantStatus || r.UnobservedFail != c.want {
				t.Errorf("status %s UnobservedFail %v, want %s %v (%s: %s)", r.Status, r.UnobservedFail, c.wantStatus, c.want, r.ReasonCode, r.Reason)
			}
		})
	}
}
