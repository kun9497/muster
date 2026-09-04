package check

import (
	"fmt"
	"math"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// evalCollection implements each and none (spec §6.3, §6.4). Every element
// examined becomes an observation keyed <kind>:<subject value>.
func (e *env) evalCollection(cl controls.Clause, entry facts.Entry, list []any, src *facts.Source) clauseOutcome {
	out := clauseOutcome{Holds: true, Evidence: []Evidence{{Fact: cl.Fact, Status: facts.StatusOK, Value: fmt.Sprintf("%d elements", len(list)), Source: src}}}
	kind := entry.SubjectKind
	if kind == "" {
		kind = "item"
	}
	for i, elem := range list {
		subject := fmt.Sprintf("%s:%s", kind, subjectValue(cl.Subject, elem, i))
		switch cl.Op {
		case "each":
			if cl.Where != nil {
				sel, err := fieldClause(cl.Where, elem, e.params)
				if err != nil {
					return clauseOutcome{Err: err}
				}
				if !sel {
					continue
				}
			}
			ok, err := fieldClause(cl.Require, elem, e.params)
			if err != nil {
				return clauseOutcome{Err: err}
			}
			// R129: Expected must show the resolved value, never a raw
			// "${param}" token (spec §6.3, R27).
			expected, err := substitute(cl.Require.Expected, e.params)
			if err != nil {
				return clauseOutcome{Err: err}
			}
			obs := Observation{Subject: subject, Expected: expected, Actual: fieldValue(cl.Require.Field, elem), Verdict: "pass"}
			if !ok {
				obs.Verdict = "fail"
				out.Holds = false
			}
			out.Observations = append(out.Observations, obs)
		case "none":
			hit, err := fieldClause(cl.Where, elem, e.params)
			if err != nil {
				return clauseOutcome{Err: err}
			}
			if hit {
				expected, err := substitute(cl.Where.Expected, e.params)
				if err != nil {
					return clauseOutcome{Err: err}
				}
				out.Holds = false
				out.Observations = append(out.Observations, Observation{Subject: subject, Expected: fmt.Sprintf("not %s %v", cl.Where.Op, expected), Actual: fieldValue(cl.Where.Field, elem), Verdict: "fail"})
			}
		}
	}
	return out
}

// subjectValue picks the element field named by `subject` for a record
// element, or the element itself for a scalar (string) element regardless of
// `subject`; the index is the fallback so subjects stay unique.
func subjectValue(field string, elem any, i int) string {
	if s, ok := elem.(string); ok {
		return s
	}
	if m, ok := elem.(map[string]any); ok {
		if v, ok := m[field]; ok {
			return fmt.Sprint(v)
		}
	}
	return fmt.Sprint(i)
}

func fieldValue(field string, elem any) any {
	if field == "" {
		return elem
	}
	if m, ok := elem.(map[string]any); ok {
		return m[field]
	}
	return nil
}

// fieldClause evaluates a where/require sub-clause against one element. The
// field's type is inferred from the decoded JSON value. params resolves any
// `${name}` in sub.Expected (spec §6.3); an unknown parameter is an error.
func fieldClause(sub *controls.Clause, elem any, params map[string]any) (bool, error) {
	if sub == nil {
		return false, fmt.Errorf("sub-clause is nil")
	}
	v := fieldValue(sub.Field, elem)
	if v == nil {
		if sub.Op == "absent" {
			return true, nil
		}
		if sub.Op == "present" {
			return false, nil
		}
		return false, fmt.Errorf("element has no field %q", sub.Field)
	}
	expected, err := substitute(sub.Expected, params)
	if err != nil {
		return false, err
	}
	typ := "string"
	switch x := v.(type) {
	case bool:
		typ = "bool"
	case float64:
		if x == math.Trunc(x) {
			typ = "int"
		}
	case []any:
		typ = "list<string>"
	}
	return compare(sub.Op, v, expected, typ)
}
