package controls_test

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// mutant is one control that differs from the original in exactly one place,
// carrying the signature of spec §2 F-2 -- `<path> <operator>` -- that names
// that place and that change. The signature is what an exclusion in
// controls/testdata/_mutants.yaml quotes (F-3), so it is part of the
// contract: renaming one invalidates the list.
type mutant struct {
	Signature string
	Control   controls.Control
}

// cloneControl deep-copies a control the way F-2 requires: by re-encoding it
// to YAML and decoding it again through a strict decoder, so a mutant is
// exactly what the loader would have accepted from a file. Path carries
// `yaml:"-"` and is restored by hand.
func cloneControl(c controls.Control) controls.Control {
	data, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var out controls.Control
	if err := dec.Decode(&out); err != nil {
		panic(err)
	}
	out.Path = c.Path
	return out
}

// flips is the operator-flip family of the F-2 table: every scalar operator
// paired with the one that inverts it. `each` is absent because its flip is
// conditional (it needs a where) and `none` because the reverse is never
// valid -- an each needs a require a none never has.
var flips = map[string]string{
	"eq": "ne", "ne": "eq",
	"in": "not_in", "not_in": "in",
	"lt": "gte", "lte": "gt", "gt": "lte", "gte": "lt",
	"matches": "not_matches", "not_matches": "matches",
	"contains": "not_contains", "not_contains": "contains",
	"present": "absent", "absent": "present",
}

// paramRefRe mirrors the loader's own ${name} reference syntax. A clause
// whose expected is such a reference is not mutated in place: F-2 mutates it
// once through the parameter's default instead, however many clauses cite it.
var paramRefRe = regexp.MustCompile(`^\$\{[a-z][a-z0-9_]*\}$`)

func isParamRef(v any) bool {
	s, ok := v.(string)
	return ok && paramRefRe.MatchString(s)
}

// addMutant appends one mutant built by applying edit to a fresh deep copy,
// so neither the original control nor any earlier mutant can be disturbed.
func addMutant(out *[]mutant, c controls.Control, sig string, edit func(*controls.Control)) {
	m := cloneControl(c)
	edit(&m)
	*out = append(*out, mutant{Signature: sig, Control: m})
}

// mutantsOf generates every mutant of c in the fixed order F-2 states:
// applies_when (clause then removal), absent_means, params, checks,
// mechanisms. It never touches c.
func mutantsOf(c controls.Control) []mutant {
	var out []mutant
	add := func(sig string, edit func(*controls.Control)) { addMutant(&out, c, sig, edit) }

	for k := range c.AppliesWhen {
		path := fmt.Sprintf("applies_when[%d]", k)
		clauseMutants(&out, c, path, func(m *controls.Control) *controls.Clause { return &m.AppliesWhen[k] })
		add(path+" remove", func(m *controls.Control) { m.AppliesWhen = slices.Delete(m.AppliesWhen, k, k+1) })
	}
	if c.AbsentMeans != "" {
		for _, v := range []string{"pass", "fail", "not_applicable", "manual"} {
			if v == c.AbsentMeans {
				continue
			}
			add("absent_means ->"+v, func(m *controls.Control) { m.AbsentMeans = v })
		}
	}
	for _, name := range c.SortedParamNames() {
		expectedMutants(&out, c, "params."+name+".default", c.Params[name].Default,
			func(m *controls.Control, v any) {
				p := m.Params[name]
				p.Default = v
				m.Params[name] = p
			})
	}
	for i := range c.Checks {
		path := fmt.Sprintf("checks[%d]", i)
		clauseMutants(&out, c, path, func(m *controls.Control) *controls.Clause { return &m.Checks[i] })
		if len(c.Checks) > 1 {
			add(path+" remove", func(m *controls.Control) { m.Checks = slices.Delete(m.Checks, i, i+1) })
		}
	}
	for j := range c.Mechanisms {
		mp := fmt.Sprintf("mechanisms[%d]", j)
		for k := range c.Mechanisms[j].When {
			path := fmt.Sprintf("%s.when[%d]", mp, k)
			clauseMutants(&out, c, path, func(m *controls.Control) *controls.Clause { return &m.Mechanisms[j].When[k] })
			add(path+" remove", func(m *controls.Control) {
				m.Mechanisms[j].When = slices.Delete(m.Mechanisms[j].When, k, k+1)
			})
		}
		for i := range c.Mechanisms[j].Checks {
			path := fmt.Sprintf("%s.checks[%d]", mp, i)
			clauseMutants(&out, c, path, func(m *controls.Control) *controls.Clause { return &m.Mechanisms[j].Checks[i] })
			if len(c.Mechanisms[j].Checks) > 1 {
				add(path+" remove", func(m *controls.Control) {
					m.Mechanisms[j].Checks = slices.Delete(m.Mechanisms[j].Checks, i, i+1)
				})
			}
		}
		if len(c.Mechanisms) > 1 {
			add(mp+" remove", func(m *controls.Control) { m.Mechanisms = slices.Delete(m.Mechanisms, j, j+1) })
		}
	}
	return out
}

// clauseMutants generates the F-2 rows that apply to one clause: the
// operator flip, `each->none` where the each has a where (the none keeps that
// where and drops the require), the expected substitutions, and then the same
// again for the where and require sub-clauses under the paths `.where` and
// `.require`. ref locates the clause inside a copy of the control, so one
// function serves checks, applies_when and every mechanism list.
func clauseMutants(out *[]mutant, c controls.Control, path string, ref func(*controls.Control) *controls.Clause) {
	cl := *ref(&c) // read-only: c's slices are shared with the caller's control
	if to, ok := flips[cl.Op]; ok {
		addMutant(out, c, fmt.Sprintf("%s op %s->%s", path, cl.Op, to), func(m *controls.Control) { ref(m).Op = to })
	}
	if cl.Op == "each" && cl.Where != nil {
		addMutant(out, c, path+" op each->none", func(m *controls.Control) {
			t := ref(m)
			t.Op = "none"
			t.Require = nil
		})
	}
	if !isParamRef(cl.Expected) {
		expectedMutants(out, c, path, cl.Expected, func(m *controls.Control, v any) { ref(m).Expected = v })
	}
	subs := []struct {
		suffix string
		pick   func(*controls.Clause) *controls.Clause
	}{
		{".where", func(t *controls.Clause) *controls.Clause { return t.Where }},
		{".require", func(t *controls.Clause) *controls.Clause { return t.Require }},
	}
	for _, sub := range subs {
		if sub.pick(&cl) == nil {
			continue
		}
		clauseMutants(out, c, path+sub.suffix, func(m *controls.Control) *controls.Clause { return sub.pick(ref(m)) })
	}
}

// expectedMutants generates the expected-substitution rows of F-2 for one
// value: `expected not` for a bool, `+1` and `-1` for an int (yaml.v3 decodes
// a YAML integer into int, so the arithmetic keeps the type a param
// declaration demands), `"__mutant__"` for a string, and one `drop[i]` per
// element plus `[]` for a list. A nil expected -- present, absent, each,
// none -- yields nothing.
func expectedMutants(out *[]mutant, c controls.Control, path string, v any, set func(*controls.Control, any)) {
	switch x := v.(type) {
	case bool:
		addMutant(out, c, path+" expected not", func(m *controls.Control) { set(m, !x) })
	case int:
		addMutant(out, c, path+" expected +1", func(m *controls.Control) { set(m, x+1) })
		addMutant(out, c, path+" expected -1", func(m *controls.Control) { set(m, x-1) })
	case string:
		addMutant(out, c, path+` expected "__mutant__"`, func(m *controls.Control) { set(m, "__mutant__") })
	case []any:
		for i := range x {
			addMutant(out, c, fmt.Sprintf("%s expected drop[%d]", path, i), func(m *controls.Control) {
				set(m, slices.Delete(slices.Clone(x), i, i+1))
			})
		}
		addMutant(out, c, path+" expected []", func(m *controls.Control) { set(m, []any{}) })
	}
}

// lintValid reports whether a mutant is a control the loader and the lint
// would have accepted (G-3). A mutant the lint rejects -- not_matches on a
// list fact, a param default of the wrong type -- is not a judgment change
// any fixture could have seen, so the kill loop counts it invalid and skips
// it. Only the rules a control carries in itself are applied: no fixture
// directory, no reference index and no KISA inventory, because a mutant has
// the original's ids and files and would otherwise be judged on them.
func lintValid(c controls.Control, reg *facts.Registry) bool {
	problems := controls.Lint(&controls.Set{Controls: []controls.Control{c}}, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs()})
	return len(problems) == 0
}
