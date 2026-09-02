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
		if res, done := e.screen(c.AppliesWhen, &r, screenApplies); done {
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
			st := e.worstStatus(m.When)
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
		// R16: every branch below carries evidence for walk.complete itself.
		ev := walkCompleteEvidence(wc)
		switch {
		case wc.Envelope == nil || wc.Envelope.Status == facts.StatusMissing || wc.Envelope.Status == facts.StatusAbsent:
			res := fail(r, MANUAL, "", "the deep walk was not run; run collect --deep")
			res.Evidence = append(res.Evidence, ev)
			return res
		case wc.Envelope.Status == facts.StatusOK:
			if done, _ := wc.Envelope.Value.(bool); !done {
				res := fail(r, ERROR, WalkIncomplete, "the deep walk did not finish within its budget")
				res.Evidence = append(res.Evidence, ev)
				return res
			}
		default:
			res := fail(r, ERROR, codeFor(wc.Envelope), "walk.complete: "+wc.Envelope.Reason)
			res.Evidence = append(res.Evidence, ev)
			return res
		}
	}
	// Steps 6-8.
	if st := e.worstStatus(checks); st.hard {
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

// worstStatus screens the facts cls reference (spec §6.5 steps 3-4 and
// 6-8), one clause at a time so a two-home setting is screened by the
// side(s) its own clause actually selects (R15): a plain fact (or a key the
// snapshot doesn't carry at all — Resolve synthesises "missing" before it
// ever looks at whether the entry is a setting) is screened by its single
// envelope, same as before; a setting is screened by `on` (defaulting to
// the registry's default_on) — runtime/persisted/effective pick that one
// side, both considers the pair. This means a setting with one absent side
// and one ok side is left to reach the clause instead of being folded into
// absent_means, because the clause (not this screening pass) is what
// decides a mixed-sides judgment.
func (e *env) worstStatus(cls []controls.Clause) screening {
	var soft screening
	for _, cl := range cls {
		res, err := e.reg.Resolve(e.snap, cl.Fact)
		if err != nil {
			return screening{hard: true, code: InternalError, reason: err.Error()}
		}
		if res.Setting == nil {
			if s, hard := screenEnvelope(cl.Fact, res.Envelope); hard {
				return s
			} else if s.status != "" {
				soft = mergeSoft(soft, s)
			}
			continue
		}
		on := cl.On
		if on == "" {
			on = res.Entry.DefaultOn
		}
		if on != "both" {
			side := selectSide(res.Setting, on)
			if side == nil {
				side = facts.Missing(cl.Fact)
			}
			if s, hard := screenEnvelope(cl.Fact, side); hard {
				return s
			} else if s.status != "" {
				soft = mergeSoft(soft, s)
			}
			continue
		}
		// on == "both": a nil or explicitly absent side does not, on its
		// own, screen the clause away — only when NEITHER side is usable
		// does the pair count as absent/unsupported. A genuinely hard
		// status (denied/timeout/error, or ok-but-truncated) on either
		// side still screens immediately.
		var anyOK, anyUnsupported bool
		for _, side := range []*facts.Envelope{res.Setting.Runtime, res.Setting.Persisted} {
			if side == nil || side.Status == facts.StatusAbsent {
				continue
			}
			switch side.Status {
			case facts.StatusDenied, facts.StatusTimeout, facts.StatusError:
				return screening{hard: true, status: side.Status, code: codeFor(side), reason: cl.Fact + ": " + side.Reason}
			case facts.StatusOK:
				if side.Truncated {
					return screening{hard: true, status: side.Status, code: Truncated, reason: cl.Fact + " was truncated at the read limit"}
				}
				anyOK = true
			case facts.StatusUnsupported:
				anyUnsupported = true
			}
		}
		if anyOK {
			continue // at least one side is usable; let the clause decide
		}
		if anyUnsupported {
			soft = mergeSoft(soft, screening{status: facts.StatusUnsupported, reason: cl.Fact + ": setting is unsupported on every selected side"})
		} else {
			soft = mergeSoft(soft, screening{status: facts.StatusAbsent, reason: cl.Fact + " is absent on this host"})
		}
	}
	return soft
}

// screenEnvelope classifies one envelope as hard, soft (absent/unsupported)
// or fine (zero-value screening, status ""). It never inspects more than
// the one side the caller selected.
func screenEnvelope(fact string, env *facts.Envelope) (screening, bool) {
	switch env.Status {
	case facts.StatusMissing, facts.StatusDenied, facts.StatusTimeout, facts.StatusError:
		return screening{hard: true, status: env.Status, code: codeFor(env), reason: fact + ": " + env.Reason}, true
	case facts.StatusOK:
		if env.Truncated {
			return screening{hard: true, status: env.Status, code: Truncated, reason: fact + " was truncated at the read limit"}, true
		}
	case facts.StatusUnsupported:
		return screening{status: facts.StatusUnsupported, reason: fact + ": " + env.Reason}, false
	case facts.StatusAbsent:
		return screening{status: facts.StatusAbsent, reason: fact + " is absent on this host"}, false
	}
	return screening{}, false
}

// mergeSoft keeps the first soft status found, except unsupported always
// wins over absent (spec §6.5).
func mergeSoft(have, found screening) screening {
	if have.status == facts.StatusUnsupported {
		return have
	}
	if found.status == facts.StatusUnsupported || have.status == "" {
		return found
	}
	return have
}

// selectSide picks the envelope a clause's `on` names; "both" is handled by
// the caller since it needs both sides at once.
func selectSide(s *facts.Setting, on string) *facts.Envelope {
	switch on {
	case "runtime":
		return s.Runtime
	case "persisted":
		return s.Persisted
	case "effective":
		return s.Effective
	}
	return nil
}

func screenApplies(st screening) (Status, ReasonCode) {
	if st.hard {
		return ERROR, st.code
	}
	return NotApplicable, ""
}

// screen applies worstStatus to applies_when facts (steps 3-4). R16: the
// NOT_APPLICABLE it can return must carry evidence for the facts it judged.
func (e *env) screen(cls []controls.Clause, r *Result, _ func(screening) (Status, ReasonCode)) (Result, bool) {
	st := e.worstStatus(cls)
	if st.hard {
		return fail(*r, ERROR, st.code, st.reason), true
	}
	if st.status == facts.StatusAbsent || st.status == facts.StatusUnsupported {
		res := fail(*r, NotApplicable, "", "applies_when: "+st.reason)
		res.Evidence = e.evidenceFor(clauseFacts(cls))
		return res, true
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

// evidenceFor resolves keys for display, not judgment: a plain fact gets
// one Evidence entry, a setting gets one per side actually present in the
// snapshot (R16) — regardless of which side any particular clause selects,
// since this is the transparency record, not the screening pass.
func (e *env) evidenceFor(keys []string) []Evidence {
	var out []Evidence
	for _, k := range keys {
		res, err := e.reg.Resolve(e.snap, k)
		if err != nil {
			continue
		}
		if res.Setting != nil {
			for _, sd := range []struct {
				name string
				env  *facts.Envelope
			}{{"runtime", res.Setting.Runtime}, {"persisted", res.Setting.Persisted}, {"effective", res.Setting.Effective}} {
				if sd.env == nil {
					continue
				}
				out = append(out, Evidence{Fact: k, Status: sd.env.Status, Value: sd.env.Value, Source: sd.env.Source, Side: sd.name})
			}
			continue
		}
		if res.Envelope != nil {
			out = append(out, Evidence{Fact: k, Status: res.Envelope.Status, Value: res.Envelope.Value, Source: res.Envelope.Source})
		}
	}
	return out
}

// walkCompleteEvidence builds the Evidence entry the walk gate attaches for
// walk.complete (R16); a key the snapshot doesn't carry reads as "missing".
func walkCompleteEvidence(wc facts.Resolved) Evidence {
	if wc.Envelope == nil {
		return Evidence{Fact: "walk.complete", Status: facts.StatusMissing}
	}
	return Evidence{Fact: "walk.complete", Status: wc.Envelope.Status, Value: wc.Envelope.Value, Source: wc.Envelope.Source}
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
