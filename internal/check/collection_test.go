package check

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// The snapshots below drive the M-5/M-6/M-7 cases. accounts.users carries
// subject_kind "user" in the registry, so its subjects read "user:<name>";
// logging.rsyslog.rules carries none, so its subjects read "item:<...>" and
// its vacuous-selection subject is "item:*" (M-33).
const usersMissingRequireField = `{"schema_version":1,"run":{},"facts":{"accounts":{"users":{"status":"ok","value":[
  {"name":"alice","system":false,"shell_valid":true},
  {"name":"bob","system":false}]}}}}`

// rsyslogRulesFacts is a three-rule routing table whose facilities are none
// of the ones the vacuous-selection cases filter for; eval_test.go drives the
// control-level half of M-6 from the same rows.
const rsyslogRulesFacts = `{"logging":{"rsyslog":{"rules":{"status":"ok","value":[
  {"facility":"cron","priority":"info","target":"/var/log/cron","target_kind":"file"},
  {"facility":"mail","priority":"info","target":"/var/log/maillog","target_kind":"file"},
  {"facility":"daemon","priority":"info","target":"/var/log/messages","target_kind":"file"}]}}}}`

// M-5 (spec §5.7, line 206): a clause that names a field an older snapshot
// lacks fails that clause with a reason naming the field, never PASS and
// never ERROR(internal_error) — which named neither the element nor the
// field and read as a bug in muster rather than a gap in the snapshot.
func TestEachMissingRequireFieldFailsTheClauseNamingTheField(t *testing.T) {
	e := newEnv(t, usersMissingRequireField)
	cl := controls.Clause{Fact: "accounts.users", Op: "each", Subject: "name",
		Require: &controls.Clause{Field: "shell_valid", Op: "eq", Expected: true}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatalf("a field the snapshot lacks is a failing clause, never an evaluator error: %v", out.Err)
	}
	if out.Holds {
		t.Fatal("an element the clause could not judge must not let the clause hold")
	}
	if want := `element user:bob has no field "shell_valid"`; out.Reason != want {
		t.Errorf("Reason = %q, want %q", out.Reason, want)
	}
	if len(out.Observations) != 2 {
		t.Fatalf("both elements are examined, got %+v", out.Observations)
	}
	if bob := out.Observations[1]; bob.Subject != "user:bob" || bob.Verdict != "fail" || bob.Actual != nil {
		t.Errorf("observation %+v, want user:bob fail with a nil actual", bob)
	}
	if alice := out.Observations[0]; alice.Subject != "user:alice" || alice.Verdict != "pass" {
		t.Errorf("the judgeable element is still judged: %+v", alice)
	}

	// The control ends FAIL with no reason code: this is a finding about the
	// snapshot, not an internal error.
	c := controls.Control{ID: "muster.account.system_account_shells", Importance: "중", Category: "account",
		Automation: "auto", AbsentMeans: "fail", Checks: []controls.Clause{cl},
		Remediation: &controls.Remediation{Risk: "none"}}
	r := Evaluate(e.snap, one(c), reg, Options{})[0]
	if r.Status != FAIL || r.ReasonCode != "" {
		t.Fatalf("status=%s code=%q reason=%q, want FAIL with no reason code", r.Status, r.ReasonCode, r.Reason)
	}
	if want := `clause does not hold: element user:bob has no field "shell_valid"`; r.Reason != want {
		t.Errorf("reason = %q, want %q", r.Reason, want)
	}
	c.Automation = "partial"
	if pr := Evaluate(e.snap, one(c), reg, Options{})[0]; pr.Status != WARN {
		t.Errorf("a partial control reads WARN, got %s (%s)", pr.Status, pr.Reason)
	}
}

// M-5: the same rule on the `where` side. A missing where field must not
// silently deselect the element — that would be exactly the vacuous PASS
// spec §5.7 forbids.
func TestEachMissingWhereFieldFailsNotDeselects(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"accounts":{"users":{"status":"ok","value":[
	  {"name":"alice","system":true,"shell_valid":false},
	  {"name":"bob","shell_valid":false}]}}}}`)
	cl := controls.Clause{Fact: "accounts.users", Op: "each", Subject: "name",
		Where:   &controls.Clause{Field: "system", Op: "eq", Expected: true},
		Require: &controls.Clause{Field: "shell_valid", Op: "eq", Expected: false}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatalf("a field the snapshot lacks is a failing clause, never an evaluator error: %v", out.Err)
	}
	if out.Holds {
		t.Fatal("an element that could not be tested for selection must not let the clause hold")
	}
	if want := `element user:bob has no field "system"`; out.Reason != want {
		t.Errorf("Reason = %q, want %q", out.Reason, want)
	}
	if len(out.Observations) != 2 {
		t.Fatalf("the unselectable element is observed, not skipped: %+v", out.Observations)
	}
	if bob := out.Observations[1]; bob.Subject != "user:bob" || bob.Verdict != "fail" {
		t.Errorf("observation %+v, want user:bob fail", bob)
	}
}

// M-5 on `none`, where the two ops that are ABOUT a field's presence keep
// their meaning: present is false and absent is true for an element that
// lacks the field, exactly as before.
func TestNoneMissingFieldFailsExceptPresentAbsent(t *testing.T) {
	const usersJSON = `{"schema_version":1,"run":{},"facts":{"accounts":{"users":{"status":"ok","value":[
	  {"name":"root","password_status":"hashed"},
	  {"name":"bob"}]}}}}`

	t.Run("eq", func(t *testing.T) {
		e := newEnv(t, usersJSON)
		out := e.evalClause(controls.Clause{Fact: "accounts.users", Op: "none", Subject: "name",
			Where: &controls.Clause{Field: "password_status", Op: "eq", Expected: "nopass"}})
		if out.Err != nil {
			t.Fatalf("a field the snapshot lacks is a failing clause, never an evaluator error: %v", out.Err)
		}
		if out.Holds {
			t.Fatal("an element the where clause could not test must not let none hold")
		}
		if want := `element user:bob has no field "password_status"`; out.Reason != want {
			t.Errorf("Reason = %q, want %q", out.Reason, want)
		}
		if len(out.Observations) != 1 || out.Observations[0].Subject != "user:bob" || out.Observations[0].Actual != nil {
			t.Errorf("observations %+v, want one failing user:bob with a nil actual", out.Observations)
		}
	})

	t.Run("present", func(t *testing.T) {
		e := newEnv(t, usersJSON)
		out := e.evalClause(controls.Clause{Fact: "accounts.users", Op: "none", Subject: "name",
			Where: &controls.Clause{Field: "password_status", Op: "present"}})
		if out.Err != nil || out.Holds {
			t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
		}
		if out.Reason != "" {
			t.Errorf("present on a missing field is a decided false, not a missing-field failure: %q", out.Reason)
		}
		if len(out.Observations) != 1 || out.Observations[0].Subject != "user:root" {
			t.Errorf("only root has the field, so only root matches: %+v", out.Observations)
		}
	})

	t.Run("absent", func(t *testing.T) {
		e := newEnv(t, usersJSON)
		out := e.evalClause(controls.Clause{Fact: "accounts.users", Op: "none", Subject: "name",
			Where: &controls.Clause{Field: "password_status", Op: "absent"}})
		if out.Err != nil || out.Holds {
			t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
		}
		if out.Reason != "" {
			t.Errorf("absent on a missing field is a decided true, not a missing-field failure: %q", out.Reason)
		}
		if len(out.Observations) != 1 || out.Observations[0].Subject != "user:bob" {
			t.Errorf("only bob lacks the field, so only bob matches: %+v", out.Observations)
		}
	})
}

// M-6: an `each` whose `where` selects nothing out of a non-empty list is
// recorded rather than reported as a silent PASS. With a literal `where` the
// control chose that filter itself, so the observation is the whole story
// and the verdict stays PASS.
func TestVacuousLiteralSelectionIsObservedNotFailed(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":`+rsyslogRulesFacts+`}`)
	cl := controls.Clause{Fact: "logging.rsyslog.rules", Op: "each", Subject: "facility",
		Where:   &controls.Clause{Field: "facility", Op: "eq", Expected: "authpriv"},
		Require: &controls.Clause{Field: "target_kind", Op: "eq", Expected: "file"}}
	out := e.evalClause(cl)
	if out.Err != nil || !out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
	if out.Count != 3 {
		t.Errorf("Count = %d, want the list length 3", out.Count)
	}
	if out.Vacuous != "" {
		t.Errorf("a literal where is the control's own filter, not a parameter: %q", out.Vacuous)
	}
	if len(out.Observations) != 1 {
		t.Fatalf("observations %+v, want the one synthetic selection record", out.Observations)
	}
	ob := out.Observations[0]
	if ob.Subject != "item:*" || ob.Verdict != "pass" || ob.Actual != "0 of 3 elements selected" {
		t.Errorf("observation %+v, want item:* / pass / 0 of 3 elements selected", ob)
	}
	if got := fmt.Sprint(ob.Expected); !strings.Contains(got, "facility") || !strings.Contains(got, "authpriv") {
		t.Errorf("Expected = %q, want the where clause described", got)
	}

	c := controls.Control{ID: "muster.log.syslog_policy", Importance: "중", Category: "log",
		Automation: "auto", AbsentMeans: "manual", Checks: []controls.Clause{cl},
		Remediation: &controls.Remediation{Risk: "none"}}
	if r := Evaluate(e.snap, one(c), reg, Options{})[0]; r.Status != PASS {
		t.Errorf("status=%s reason=%q, want PASS", r.Status, r.Reason)
	}
}

// M-7: the evidence of a collection clause names what it judged, so a reader
// of the JSON sees the subjects without walking every observation.
func TestCollectionEvidenceNamesTheSubjects(t *testing.T) {
	users := func(rows string) string {
		return `{"schema_version":1,"run":{},"facts":{"accounts":{"users":{"status":"ok","value":[` + rows + `]}}}}`
	}
	walk := func(rows string) string {
		return `{"schema_version":1,"run":{},"facts":{"walk":{"complete":{"status":"ok","value":true},` +
			`"world_writable":{"status":"ok","value":[` + rows + `]}}}}`
	}
	cases := []struct {
		name  string
		snap  string
		cl    controls.Clause
		value string
	}{
		{"each with where names the failing subjects",
			users(`{"name":"alice","system":true,"shell_valid":false},{"name":"bob","system":true,"shell_valid":true},{"name":"carol","system":false,"shell_valid":true}`),
			controls.Clause{Fact: "accounts.users", Op: "each", Subject: "name",
				Where:   &controls.Clause{Field: "system", Op: "eq", Expected: true},
				Require: &controls.Clause{Field: "shell_valid", Op: "eq", Expected: false}},
			"3 elements; 2 selected; failing: user:bob"},
		{"each without where and without a failure names only the count",
			users(`{"name":"alice","shell_valid":true},{"name":"bob","shell_valid":true},{"name":"carol","shell_valid":true}`),
			controls.Clause{Fact: "accounts.users", Op: "each", Subject: "name",
				Require: &controls.Clause{Field: "shell_valid", Op: "eq", Expected: true}},
			"3 elements"},
		{"more than five failing subjects are capped",
			users(`{"name":"u1","shell_valid":true},{"name":"u2","shell_valid":true},{"name":"u3","shell_valid":true},{"name":"u4","shell_valid":true},{"name":"u5","shell_valid":true},{"name":"u6","shell_valid":true}`),
			controls.Clause{Fact: "accounts.users", Op: "each", Subject: "name",
				Require: &controls.Clause{Field: "shell_valid", Op: "eq", Expected: false}},
			"6 elements; failing: user:u1, user:u2, user:u3, user:u4, user:u5, +1 more"},
		{"none names the matching subjects",
			walk(`{"path":"/a","sticky":false},{"path":"/b","sticky":false},{"path":"/c","sticky":true}`),
			controls.Clause{Fact: "walk.world_writable", Op: "none", Subject: "path",
				Where: &controls.Clause{Field: "sticky", Op: "eq", Expected: false}},
			"3 elements; matching: file:/a, file:/b"},
		{"none with no match says so",
			walk(`{"path":"/a","sticky":true},{"path":"/b","sticky":true},{"path":"/c","sticky":true}`),
			controls.Clause{Fact: "walk.world_writable", Op: "none", Subject: "path",
				Where: &controls.Clause{Field: "sticky", Op: "eq", Expected: false}},
			"3 elements; none matching"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.snap)
			out := e.evalClause(tc.cl)
			if out.Err != nil {
				t.Fatal(out.Err)
			}
			if len(out.Evidence) != 1 {
				t.Fatalf("one evidence entry for the collection fact, got %+v", out.Evidence)
			}
			if got := out.Evidence[0].Value; got != tc.value {
				t.Errorf("evidence value = %q, want %q", got, tc.value)
			}
		})
	}
}
