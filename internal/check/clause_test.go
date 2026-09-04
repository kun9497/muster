package check

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func newEnv(t *testing.T, snapshotJSON string) *env {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.Load(strings.NewReader(snapshotJSON))
	if err != nil {
		t.Fatal(err)
	}
	return &env{snap: s, reg: reg, params: map[string]any{}, personas: personasCollected(s, reg)}
}

const sshdSnap = `{"schema_version":1,"run":{},"facts":{
  "sshd": {"personas_collected": {"status":"ok","value":false},
           "options": {"permit_root_login": {
              "runtime":   {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}},
              "persisted": {"status":"ok","value":"yes","source":{"kind":"file","path":"/etc/ssh/sshd_config","line":40,"raw":"PermitRootLogin yes"}},
              "effective": {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}}}}},
  "accounts": {"login_defs": {"pass_max_days": {
              "runtime":   {"status":"ok","value":99999},
              "persisted": {"status":"ok","value":90,"source":{"kind":"file","path":"/etc/login.defs","line":160}}}}},
  "services": {"ssh": {"installed": {"status":"ok","value":true}}}
}}`

func TestEvalClauseEffectiveSideWithPersonaDegradation(t *testing.T) {
	e := newEnv(t, sshdSnap)
	out := e.evalClause(controls.Clause{Fact: "sshd.options.permit_root_login", On: "effective", Persona: "root", Op: "in", Expected: []any{"no", "prohibit-password"}})
	if out.Err != nil || !out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
	if out.Degraded != "personas not collected" {
		t.Errorf("degraded=%q", out.Degraded)
	}
	if len(out.Evidence) != 1 || out.Evidence[0].Side != "effective" || out.Evidence[0].Value != "no" {
		t.Errorf("evidence %+v", out.Evidence)
	}
}

func TestEvalClauseBothSidesMismatchIsDegradedNotHolding(t *testing.T) {
	e := newEnv(t, sshdSnap)
	out := e.evalClause(controls.Clause{Fact: "accounts.login_defs.pass_max_days", Op: "lte", Expected: 90}) // default_on both
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if out.Holds {
		t.Fatal("runtime 99999 > 90 must not hold")
	}
	if out.Degraded != "not applied" {
		t.Errorf("degraded=%q, want 'not applied' (persisted holds, runtime fails)", out.Degraded)
	}
	if len(out.Evidence) != 2 {
		t.Errorf("both sides must be evidence: %+v", out.Evidence)
	}
}

func TestEvalClauseScalarAndParam(t *testing.T) {
	e := newEnv(t, sshdSnap)
	e.params["want"] = true
	out := e.evalClause(controls.Clause{Fact: "services.ssh.installed", Op: "eq", Expected: "${want}"})
	if out.Err != nil || !out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
}

func TestEvalClauseRefusesNonOKEnvelope(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"denied","reason":"root"}}}}}`)
	out := e.evalClause(controls.Clause{Fact: "services.ssh.installed", Op: "eq", Expected: true})
	if out.Err == nil {
		t.Fatal("a non-ok envelope must never reach comparison")
	}
}

const walkSnap = `{"schema_version":1,"run":{},"facts":{"walk":{
  "world_writable": {"status":"ok","value":[
     {"path":"/var/tmp/legacy.sock","sticky":false,"package_declared":false},
     {"path":"/tmp","sticky":true,"package_declared":true},
     {"path":"/usr/lib/x","sticky":false,"package_declared":true}]},
  "complete": {"status":"ok","value":true}}}}`

func TestEvalCollectionEachProducesObservations(t *testing.T) {
	e := newEnv(t, walkSnap)
	cl := controls.Clause{Fact: "walk.world_writable", Op: "each", Subject: "path",
		Where:   &controls.Clause{Field: "sticky", Op: "eq", Expected: false},
		Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if out.Holds {
		t.Fatal("legacy.sock is not package-declared; clause must not hold")
	}
	if len(out.Observations) != 2 {
		t.Fatalf("two non-sticky elements → two observations, got %+v", out.Observations)
	}
	if out.Observations[0].Subject != "file:/var/tmp/legacy.sock" || out.Observations[0].Verdict != "fail" {
		t.Errorf("%+v", out.Observations[0])
	}
	if out.Observations[1].Subject != "file:/usr/lib/x" || out.Observations[1].Verdict != "pass" {
		t.Errorf("%+v", out.Observations[1])
	}
}

func TestEvalCollectionNoneOnScalarList(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"files":{"etc_securetty":{"status":"ok","value":{}},"etc_securetty_lines":{"status":"ok","value":["console","tty1","pts/0"]}}}}`)
	cl := controls.Clause{Fact: "files.etc_securetty_lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}
	out := e.evalClause(cl)
	if out.Err != nil || out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
	if len(out.Observations) != 1 || out.Observations[0].Actual != "pts/0" {
		t.Errorf("%+v", out.Observations)
	}
}

func TestFieldClauseSubstitutesRequireExpectedParam(t *testing.T) {
	e := newEnv(t, walkSnap)
	e.params["want"] = true
	cl := controls.Clause{Fact: "walk.world_writable", Op: "each", Subject: "path",
		Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: "${want}"}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if len(out.Observations) != 3 {
		t.Fatalf("all three elements observed, got %+v", out.Observations)
	}
	for _, obs := range out.Observations {
		wantVerdict := "fail"
		if obs.Actual == true {
			wantVerdict = "pass"
		}
		if obs.Verdict != wantVerdict {
			t.Errorf("subject %s: verdict=%s, want %s (${want} must substitute to true, not compare against the literal string)", obs.Subject, obs.Verdict, wantVerdict)
		}
	}
}

// R129: Observation.Expected must carry the substituted value, never the
// raw "${param}" token — the same rule describe() already enforces for a
// plain clause's reason text (R27), now applied to each/none observations
// too.
func TestEvalCollectionObservationExpectedIsSubstituted(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"accounts":{"users":{"status":"ok","value":[{"name":"lp"}]}}}}`)
	e.params["names"] = []any{"lp"}

	t.Run("none", func(t *testing.T) {
		cl := controls.Clause{Fact: "accounts.users", Op: "none", Where: &controls.Clause{Field: "name", Op: "in", Expected: "${names}"}}
		out := e.evalClause(cl)
		if out.Err != nil {
			t.Fatal(out.Err)
		}
		if len(out.Observations) != 1 {
			t.Fatalf("%+v", out.Observations)
		}
		got := fmt.Sprint(out.Observations[0].Expected)
		if !strings.Contains(got, "lp") || strings.Contains(got, "${") {
			t.Errorf("Expected = %q, want the substituted value and no raw token", got)
		}
	})

	t.Run("each", func(t *testing.T) {
		cl := controls.Clause{Fact: "accounts.users", Op: "each", Require: &controls.Clause{Field: "name", Op: "in", Expected: "${names}"}}
		out := e.evalClause(cl)
		if out.Err != nil {
			t.Fatal(out.Err)
		}
		if len(out.Observations) != 1 {
			t.Fatalf("%+v", out.Observations)
		}
		got := fmt.Sprint(out.Observations[0].Expected)
		if !strings.Contains(got, "lp") || strings.Contains(got, "${") {
			t.Errorf("Expected = %q, want the substituted value and no raw token", got)
		}
	})
}

func TestEvalCollectionScalarSubjectUsesElementValue(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"files":{"etc_securetty":{"status":"ok","value":{}},"etc_securetty_lines":{"status":"ok","value":["console","tty1"]}}}}`)
	cl := controls.Clause{Fact: "files.etc_securetty_lines", Op: "each", Subject: "line",
		Require: &controls.Clause{Op: "eq", Expected: "console"}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if len(out.Observations) != 2 {
		t.Fatalf("two elements → two observations, got %+v", out.Observations)
	}
	if out.Observations[0].Subject != "item:console" {
		t.Errorf("subject=%q, want item:console (etc_securetty_lines has no subject_kind, so kind is item)", out.Observations[0].Subject)
	}
	if out.Observations[1].Subject != "item:tty1" {
		t.Errorf("subject=%q, want item:tty1", out.Observations[1].Subject)
	}
}
