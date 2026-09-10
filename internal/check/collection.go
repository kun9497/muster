package check

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// evalCollection implements each and none (spec §6.3, §6.4). Every element
// examined becomes an observation keyed <kind>:<subject value>.
func (e *env) evalCollection(cl controls.Clause, entry facts.Entry, list []any, src *facts.Source) clauseOutcome {
	out := clauseOutcome{Holds: true, Count: len(list)}
	kind := entry.SubjectKind
	if kind == "" {
		kind = "item"
	}
	// R129 (fix round 1): the sub-clause's Expected is the same for every
	// element a clause examines, so it is substituted once per clause here
	// rather than once per element inside the loop below.
	var requireExpected, whereExpected any
	switch cl.Op {
	case "each":
		var err error
		requireExpected, err = substitute(cl.Require.Expected, e.params)
		if err != nil {
			return clauseOutcome{Err: err}
		}
		if cl.Where != nil {
			whereExpected, err = substitute(cl.Where.Expected, e.params)
			if err != nil {
				return clauseOutcome{Err: err}
			}
		}
	case "none":
		var err error
		whereExpected, err = substitute(cl.Where.Expected, e.params)
		if err != nil {
			return clauseOutcome{Err: err}
		}
	}
	// M-5: an element whose judged field the snapshot does not carry fails
	// the clause and says which field, and the loop goes on so the report
	// still lists every element that was examined.
	missing := func(subject string, mf missingFieldError, expected any) {
		out.Observations = append(out.Observations, Observation{Subject: subject, Expected: expected, Actual: nil, Verdict: "fail"})
		out.Holds = false
		if out.Reason == "" {
			out.Reason = fmt.Sprintf("element %s has no field %q", subject, mf.Field)
		}
	}
	selected := 0
	for i, elem := range list {
		subject := fmt.Sprintf("%s:%s", kind, subjectValue(cl.Subject, elem, i))
		switch cl.Op {
		case "each":
			if cl.Where != nil {
				sel, err := fieldClause(cl.Where, elem, e.params)
				if err != nil {
					var mf missingFieldError
					if !errors.As(err, &mf) {
						return clauseOutcome{Err: err}
					}
					// Never a silent deselection: an element that could not
					// be tested for selection is the vacuous PASS §5.7 forbids.
					missing(subject, mf, whereExpected)
					continue
				}
				if !sel {
					continue
				}
			}
			selected++
			ok, err := fieldClause(cl.Require, elem, e.params)
			if err != nil {
				var mf missingFieldError
				if !errors.As(err, &mf) {
					return clauseOutcome{Err: err}
				}
				missing(subject, mf, requireExpected)
				continue
			}
			obs := Observation{Subject: subject, Expected: requireExpected, Actual: fieldValue(cl.Require.Field, elem), Verdict: "pass"}
			if !ok {
				obs.Verdict = "fail"
				out.Holds = false
			}
			out.Observations = append(out.Observations, obs)
		case "none":
			hit, err := fieldClause(cl.Where, elem, e.params)
			if err != nil {
				var mf missingFieldError
				if !errors.As(err, &mf) {
					return clauseOutcome{Err: err}
				}
				missing(subject, mf, whereExpected)
				continue
			}
			if hit {
				out.Holds = false
				out.Observations = append(out.Observations, Observation{Subject: subject, Expected: fmt.Sprintf("not %s %v", cl.Where.Op, whereExpected), Actual: fieldValue(cl.Where.Field, elem), Verdict: "fail"})
			}
		}
	}
	// M-6: an `each` whose `where` selected nothing out of a non-empty list
	// judged none of the host's elements. The observation makes that visible
	// in every report; when the filter was a ${param} rather than the
	// control's own literal, the caller turns it into MANUAL as well —
	// but only while the clause is otherwise holding, since a missing field
	// (M-5) is a failure no vacuous selection may override (M-33).
	if cl.Op == "each" && cl.Where != nil && len(list) > 0 && selected == 0 {
		out.Observations = append(out.Observations, Observation{
			Subject:  kind + ":*",
			Expected: describeField(cl.Where, e.params),
			Actual:   fmt.Sprintf("0 of %d elements selected", len(list)),
			Verdict:  "pass",
		})
		if out.Holds {
			if name, ok := paramName(cl.Where.Expected); ok {
				out.Vacuous = name
			}
		}
	}
	out.Evidence = []Evidence{{Fact: cl.Fact, Status: facts.StatusOK, Value: collectionValue(cl, len(list), selected, out.Observations), Source: src}}
	return out
}

// maxNamedSubjects caps how many subjects an evidence value spells out; the
// observations stay the complete record (M-7).
const maxNamedSubjects = 5

// collectionValue is the evidence value of an each/none clause: what it
// judged, not only how much of it (M-7). Subjects appear in observation
// order — the snapshot's own list order, so the same input renders the same
// bytes.
func collectionValue(cl controls.Clause, n, selected int, obs []Observation) string {
	var failed []string
	for _, ob := range obs {
		if ob.Verdict == "fail" {
			failed = append(failed, ob.Subject)
		}
	}
	value := fmt.Sprintf("%d elements", n)
	switch cl.Op {
	case "each":
		if cl.Where != nil {
			value += fmt.Sprintf("; %d selected", selected)
		}
		if len(failed) > 0 {
			value += "; failing: " + namedSubjects(failed)
		}
	case "none":
		if len(failed) > 0 {
			value += "; matching: " + namedSubjects(failed)
		} else {
			value += "; none matching"
		}
	}
	return value
}

func namedSubjects(subjects []string) string {
	if len(subjects) <= maxNamedSubjects {
		return strings.Join(subjects, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(subjects[:maxNamedSubjects], ", "), len(subjects)-maxNamedSubjects)
}

// missingFieldError is fieldClause's answer for an element that has no value
// under the field the sub-clause names. Spec §5.7 (line 206): a clause that
// names a field an older snapshot lacks fails that clause with a reason
// naming the field — so this is a typed error the collection loop turns into
// a failing observation, never an ERROR(internal_error).
type missingFieldError struct{ Field string }

func (e missingFieldError) Error() string { return fmt.Sprintf("element has no field %q", e.Field) }

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
		// Every other op judges the field's VALUE, which this element does
		// not have; M-5 fails the clause naming the field.
		return false, missingFieldError{Field: sub.Field}
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
