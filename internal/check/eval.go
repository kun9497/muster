package check

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// Options carries per-control parameter overrides (stage 3 tuning).
type Options struct {
	Params map[string]map[string]any
}

// Evaluate is the pure function of spec §4.2: one Result per control, in
// set order, never panicking (a panic inside one control is that control's
// ERROR(internal_error), spec §7.2).
func Evaluate(snap *facts.Snapshot, set *controls.Set, reg *facts.Registry, opts Options) []Result {
	out := make([]Result, 0, len(set.Controls))
	personas := personasCollected(snap, reg)
	for i := range set.Controls {
		c := &set.Controls[i]
		e := &env{snap: snap, reg: reg, params: ParamValues(c, opts.Params[c.ID]), personas: personas}
		out = append(out, evalOne(e, c))
	}
	return out
}

func evalOne(e *env, c *controls.Control) (r Result) {
	r = Result{ID: c.ID, TitleEn: c.TitleEn, TitleKo: c.TitleKo, Category: c.Category, Importance: c.Importance, Automation: c.Automation}
	defer func() {
		if p := recover(); p != nil {
			r.Status, r.ReasonCode, r.Reason = ERROR, InternalError, fmt.Sprintf("panic while evaluating: %v", p)
			r.Evidence, r.Observations = nil, nil
		}
	}()
	// Step 1.
	if need, ok := requiredVersion(c.RequiresFacts); ok && e.snap.SchemaVersion < need {
		return fail(r, ERROR, MissingFact, fmt.Sprintf("control requires facts schema >=%d; snapshot is %d", need, e.snap.SchemaVersion))
	}
	// Step 2.
	if c.Automation == "manual" || c.Automation == "not_applicable" {
		r.Evidence = e.evidenceFor(clauseFacts(c.AppliesWhen))
		if c.Automation == "manual" {
			r.Status, r.Reason = MANUAL, c.ManualReason
		} else {
			r.Status, r.Reason = NotApplicable, c.ManualReason
		}
		return r
	}
	// Steps 3-4.
	if len(c.AppliesWhen) > 0 {
		if res, done := e.screen(clauseFacts(c.AppliesWhen), &r, screenApplies); done {
			return res
		}
		for _, cl := range c.AppliesWhen {
			out := e.evalClause(cl)
			if out.Err != nil {
				return fail(r, ERROR, InternalError, out.Err.Error())
			}
			r.Evidence = append(r.Evidence, out.Evidence...)
			if !out.Holds {
				return fail(r, NotApplicable, "", "applies_when does not hold: "+describe(cl))
			}
		}
	}
	// Step 5: choose the judgment.
	checks := c.Checks
	if len(c.Mechanisms) > 0 {
		chosen := -1
		for mi, m := range c.Mechanisms {
			keys := clauseFacts(m.When)
			st := e.worstStatus(keys)
			if st.hard {
				return fail(r, ERROR, st.code, st.reason)
			}
			if st.status == facts.StatusAbsent || st.status == facts.StatusUnsupported {
				continue
			}
			holds := true
			for _, cl := range m.When {
				out := e.evalClause(cl)
				if out.Err != nil {
					return fail(r, ERROR, InternalError, out.Err.Error())
				}
				if !out.Holds {
					holds = false
					break
				}
			}
			if holds {
				chosen = mi
				break
			}
		}
		if chosen < 0 {
			// R1: no mechanism could be chosen; absentMeans must still carry
			// evidence, so pass the union of every mechanism's `when` fact
			// keys (the facts the decision was actually based on).
			var allWhen []controls.Clause
			for _, m := range c.Mechanisms {
				allWhen = append(allWhen, m.When...)
			}
			return e.absentMeans(r, c, clauseFacts(allWhen), "no mechanism applies to this host")
		}
		checks = c.Mechanisms[chosen].Checks
		r.Mechanism = chosen + 1
	}
	if c.Custom != "" {
		fn, ok := customs[c.Custom]
		if !ok {
			return fail(r, ERROR, InternalError, "custom function "+c.Custom+" is not registered")
		}
		return finish(r, c, fn(e, c))
	}
	keys := clauseFacts(checks)
	// Steps 9-10 (R2): the walk gate runs before the fact-status screening
	// below. When the deep walk was never run, a walk-based list fact reads
	// back "absent" or "missing" — screening it first would let step 8's
	// absent_means resolve to PASS/FAIL and hide that the walk didn't run,
	// contradicting step 9's MANUAL "run collect --deep".
	if walkBased(keys) {
		wc, _ := e.reg.Resolve(e.snap, "walk.complete")
		switch {
		case wc.Envelope == nil || wc.Envelope.Status == facts.StatusMissing || wc.Envelope.Status == facts.StatusAbsent:
			return fail(r, MANUAL, "", "the deep walk was not run; run collect --deep")
		case wc.Envelope.Status == facts.StatusOK:
			if done, _ := wc.Envelope.Value.(bool); !done {
				return fail(r, ERROR, WalkIncomplete, "the deep walk did not finish within its budget")
			}
		default:
			return fail(r, ERROR, codeFor(wc.Envelope), "walk.complete: "+wc.Envelope.Reason)
		}
	}
	// Steps 6-8.
	if st := e.worstStatus(keys); st.hard {
		return fail(r, ERROR, st.code, st.reason)
	} else if st.status == facts.StatusUnsupported {
		return fail(r, NotApplicable, UnsupportedEnv, st.reason)
	} else if st.status == facts.StatusAbsent {
		return e.absentMeans(r, c, keys, st.reason)
	}
	// Steps 11-14.
	all := clauseOutcome{Holds: true}
	for _, cl := range checks {
		out := e.evalClause(cl)
		if out.Err != nil {
			return fail(r, ERROR, InternalError, out.Err.Error())
		}
		all.Evidence = append(all.Evidence, out.Evidence...)
		all.Observations = append(all.Observations, out.Observations...)
		if !out.Holds {
			all.Holds = false
			if all.Degraded == "" {
				all.Degraded = out.Degraded
			}
			all.Err = nil
			if r.Reason == "" {
				r.Reason = "clause does not hold: " + describe(cl)
			}
		}
		if out.Degraded != "" && all.Degraded == "" {
			all.Degraded = out.Degraded
		}
	}
	return finish(r, c, all)
}

// finish applies steps 11-14 to the combined clause outcome.
func finish(r Result, c *controls.Control, all clauseOutcome) Result {
	r.Evidence = append(r.Evidence, all.Evidence...)
	r.Observations = all.Observations
	if all.Err != nil {
		return fail(r, ERROR, InternalError, all.Err.Error())
	}
	if !all.Holds {
		if all.Degraded != "" {
			r.Degraded = all.Degraded
			if all.Degraded == "reverts on reboot" || all.Degraded == "not applied" {
				r.Status = WARN
				r.Reason = "setting holds on one side only: " + all.Degraded
				return r
			}
		}
		if c.Automation == "partial" {
			r.Status = WARN
			if r.Reason == "" {
				r.Reason = "observations need human review"
			}
			return r
		}
		r.Status = FAIL
		if r.Reason == "" {
			r.Reason = "a clause does not hold"
		}
		return r
	}
	if all.Degraded != "" {
		r.Status, r.Degraded, r.Reason = WARN, all.Degraded, "collection was degraded: "+all.Degraded
		return r
	}
	r.Status = PASS
	return r
}

type screening struct {
	hard   bool
	status facts.Status
	code   ReasonCode
	reason string
}

// worstStatus screens the facts a step references (spec §6.5 steps 3 and 6):
// hard failures first, then unsupported, then absent.
func (e *env) worstStatus(keys []string) screening {
	var soft screening
	for _, k := range keys {
		res, err := e.reg.Resolve(e.snap, k)
		if err != nil {
			return screening{hard: true, code: InternalError, reason: err.Error()}
		}
		envs := []*facts.Envelope{}
		if res.Setting != nil {
			for _, side := range []*facts.Envelope{res.Setting.Runtime, res.Setting.Persisted, res.Setting.Effective} {
				if side != nil {
					envs = append(envs, side)
				}
			}
			if len(envs) == 0 {
				envs = append(envs, facts.Missing(k))
			}
		} else {
			envs = append(envs, res.Envelope)
		}
		for _, env := range envs {
			switch env.Status {
			case facts.StatusMissing, facts.StatusDenied, facts.StatusTimeout, facts.StatusError:
				return screening{hard: true, status: env.Status, code: codeFor(env), reason: k + ": " + env.Reason}
			case facts.StatusOK:
				if env.Truncated {
					return screening{hard: true, status: env.Status, code: Truncated, reason: k + " was truncated at the read limit"}
				}
			case facts.StatusUnsupported:
				if soft.status != facts.StatusUnsupported {
					soft = screening{status: facts.StatusUnsupported, reason: k + ": " + env.Reason}
				}
			case facts.StatusAbsent:
				if soft.status == "" {
					soft = screening{status: facts.StatusAbsent, reason: k + " is absent on this host"}
				}
			}
		}
	}
	return soft
}

func screenApplies(st screening) (Status, ReasonCode) {
	if st.hard {
		return ERROR, st.code
	}
	return NotApplicable, ""
}

// screen applies worstStatus to applies_when facts (steps 3-4).
func (e *env) screen(keys []string, r *Result, _ func(screening) (Status, ReasonCode)) (Result, bool) {
	st := e.worstStatus(keys)
	if st.hard {
		return fail(*r, ERROR, st.code, st.reason), true
	}
	if st.status == facts.StatusAbsent || st.status == facts.StatusUnsupported {
		return fail(*r, NotApplicable, "", "applies_when: "+st.reason), true
	}
	return *r, false
}

// absentMeans applies the absent_means mapping (spec §6.5). R1: every
// FAIL/WARN a control can end in must carry evidence, so the caller's keys
// (the facts the decision was based on) are attached before the switch.
func (e *env) absentMeans(r Result, c *controls.Control, keys []string, why string) Result {
	r.Evidence = e.evidenceFor(keys)
	switch c.AbsentMeans {
	case "pass":
		r.Status, r.Reason = PASS, "absent counts as pass: "+why
	case "fail":
		r.Status, r.Reason = FAIL, "absent counts as fail: "+why
	case "manual":
		r.Status, r.Reason = MANUAL, "absent needs review: "+why
	default:
		r.Status, r.Reason = NotApplicable, why
	}
	return r
}

func codeFor(env *facts.Envelope) ReasonCode {
	switch env.Status {
	case facts.StatusMissing:
		return MissingFact
	case facts.StatusDenied:
		return PermissionDenied
	case facts.StatusTimeout:
		return Timeout
	case facts.StatusError:
		return ParseError
	}
	if env.Truncated {
		return Truncated
	}
	return InternalError
}

func fail(r Result, s Status, code ReasonCode, reason string) Result {
	r.Status, r.ReasonCode, r.Reason = s, code, reason
	return r
}

func (e *env) evidenceFor(keys []string) []Evidence {
	var out []Evidence
	for _, k := range keys {
		res, err := e.reg.Resolve(e.snap, k)
		if err != nil {
			continue
		}
		if res.Envelope != nil {
			out = append(out, Evidence{Fact: k, Status: res.Envelope.Status, Value: res.Envelope.Value, Source: res.Envelope.Source})
		}
	}
	return out
}

func clauseFacts(cls []controls.Clause) []string {
	seen := map[string]bool{}
	var out []string
	for _, cl := range cls {
		if cl.Fact != "" && !seen[cl.Fact] {
			seen[cl.Fact] = true
			out = append(out, cl.Fact)
		}
	}
	return out
}

func walkBased(keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, "walk.") {
			return true
		}
	}
	return false
}

func requiredVersion(s string) (int, bool) {
	if !strings.HasPrefix(s, ">=") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, ">="))
	return n, err == nil
}

func describe(cl controls.Clause) string {
	return fmt.Sprintf("%s %s %v", cl.Fact, cl.Op, cl.Expected)
}
