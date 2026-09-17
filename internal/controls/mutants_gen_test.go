package controls_test

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// mustControl decodes one control through the same strict decoder the loader
// uses, so a fixture in this file is exactly what a file under controls/
// would have produced.
func mustControl(t *testing.T, text string) controls.Control {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	var c controls.Control
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode control: %v", err)
	}
	return c
}

func signatures(ms []mutant) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Signature)
	}
	return out
}

func findMutant(t *testing.T, ms []mutant, sig string) mutant {
	t.Helper()
	for _, m := range ms {
		if m.Signature == sig {
			return m
		}
	}
	t.Fatalf("no mutant with signature %q; got %v", sig, signatures(ms))
	return mutant{}
}

// leaves flattens a control to one entry per YAML scalar, keyed by the same
// locator grammar F-2 uses for a signature's path, so a test can say which
// part of the control a mutant touched.
func leaves(t *testing.T, c controls.Control) map[string]string {
	t.Helper()
	data, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, sub := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, sub)
			}
		case []any:
			if len(x) == 0 {
				out[prefix] = "[]"
				return
			}
			for i, sub := range x {
				walk(fmt.Sprintf("%s[%d]", prefix, i), sub)
			}
		default:
			out[prefix] = fmt.Sprintf("%v", v)
		}
	}
	walk("", tree)
	return out
}

func differingLeaves(t *testing.T, a, b controls.Control) []string {
	t.Helper()
	la, lb := leaves(t, a), leaves(t, b)
	var out []string
	for k, v := range la {
		if w, ok := lb[k]; !ok || w != v {
			out = append(out, k)
		}
	}
	for k := range lb {
		if _, ok := la[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// A control carrying one clause of every shape F-2 names: an applies_when
// screen, absent_means, a list parameter, a bool eq, an `in` over a list
// literal, an each with where and require, and a none with a where.
const sigFixtureYAML = `
id: muster.test.signatures
title_en: Signature fixture
title_ko: signature fixture
description_en: Exercises every mutation operator of F-2.
description_ko: F-2 operators.
category: file
importance: 중
automation: auto
references: {}
requires_facts: ">=1"
applies_when:
  - { fact: os.family, op: eq, expected: debian }
absent_means: manual
params:
  allowed: { type: list<string>, default: ["a", "b"], description: allowed values }
checks:
  - { fact: a.flag, op: eq, expected: true }
  - { fact: a.mode, op: in, expected: ["644", "640"] }
  - { fact: a.rows, op: each, subject: name, where: { field: kind, op: eq, expected: file }, require: { field: mode, op: eq, expected: "600" } }
  - { fact: a.rows, op: none, subject: name, where: { field: owner, op: ne, expected: root } }
remediation:
  text_en: Fix it.
  text_ko: Fix it.
  risk: none
  idempotent: true
`

// F-2: the signature grammar is `<path> <operator>`, the generation order is
// applies_when, absent_means, params, checks, mechanisms, and inside a clause
// it is the op flip, the expected substitutions, then the where and the
// require sub-clauses.
func TestMutantsOfSignaturesAndOrder(t *testing.T) {
	c := mustControl(t, sigFixtureYAML)
	want := []string{
		"applies_when[0] op eq->ne",
		`applies_when[0] expected "__mutant__"`,
		"applies_when[0] remove",
		"absent_means ->pass",
		"absent_means ->fail",
		"absent_means ->not_applicable",
		"params.allowed.default expected drop[0]",
		"params.allowed.default expected drop[1]",
		"params.allowed.default expected []",
		"checks[0] op eq->ne",
		"checks[0] expected not",
		"checks[0] remove",
		"checks[1] op in->not_in",
		"checks[1] expected drop[0]",
		"checks[1] expected drop[1]",
		"checks[1] expected []",
		"checks[1] remove",
		"checks[2] op each->none",
		"checks[2].where op eq->ne",
		`checks[2].where expected "__mutant__"`,
		"checks[2].require op eq->ne",
		`checks[2].require expected "__mutant__"`,
		"checks[2] remove",
		"checks[3].where op ne->eq",
		`checks[3].where expected "__mutant__"`,
		"checks[3] remove",
	}
	ms := mutantsOf(c)
	if got := signatures(ms); !reflect.DeepEqual(got, want) {
		t.Errorf("signatures mismatch\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	seen := map[string]bool{}
	for _, m := range ms {
		if seen[m.Signature] {
			t.Errorf("duplicate signature %q: two mutants would name the same site and change", m.Signature)
		}
		seen[m.Signature] = true
		diff := differingLeaves(t, c, m.Control)
		if len(diff) == 0 {
			t.Errorf("%s: mutant is identical to the original", m.Signature)
			continue
		}
		if strings.HasSuffix(m.Signature, " remove") {
			continue // a removal renumbers the rest of the list by design
		}
		path := strings.SplitN(m.Signature, " ", 2)[0]
		for _, k := range diff {
			if !strings.HasPrefix(k, path) {
				t.Errorf("%s: changed %s, which is outside the signature's path", m.Signature, k)
			}
		}
	}
}

// A two-mechanism control: the second half of F-2's generation order, which
// sigFixtureYAML (no mechanisms) cannot exercise -- per mechanism the `when`
// clauses then their removals, the checks then their removals, and the whole
// mechanism last, because the control has more than one.
const sigMechFixtureYAML = `
id: muster.test.mechanisms
title_en: Mechanism signature fixture
title_ko: mechanism signature fixture
description_en: Exercises the mechanism half of F-2's generation order.
description_ko: F-2 mechanisms.
category: file
importance: 중
automation: auto
references: {}
requires_facts: ">=1"
absent_means: manual
mechanisms:
  - when:
      - { fact: a.one, op: present }
    checks:
      - { fact: a.two, op: eq, expected: true }
      - { fact: a.three, op: gte, expected: 2 }
  - when:
      - { fact: b.one, op: eq, expected: true }
      - { fact: b.two, op: present }
    checks:
      - { fact: b.three, op: eq, expected: false }
remediation:
  text_en: Fix it.
  text_ko: Fix it.
  risk: none
  idempotent: true
`

func TestMutantsOfMechanismSignaturesAndOrder(t *testing.T) {
	c := mustControl(t, sigMechFixtureYAML)
	want := []string{
		"absent_means ->pass",
		"absent_means ->fail",
		"absent_means ->not_applicable",
		"mechanisms[0].when[0] op present->absent",
		"mechanisms[0].when[0] remove",
		"mechanisms[0].checks[0] op eq->ne",
		"mechanisms[0].checks[0] expected not",
		"mechanisms[0].checks[0] remove",
		"mechanisms[0].checks[1] op gte->lt",
		"mechanisms[0].checks[1] expected +1",
		"mechanisms[0].checks[1] expected -1",
		"mechanisms[0].checks[1] remove",
		"mechanisms[0] remove",
		"mechanisms[1].when[0] op eq->ne",
		"mechanisms[1].when[0] expected not",
		"mechanisms[1].when[0] remove",
		"mechanisms[1].when[1] op present->absent",
		"mechanisms[1].when[1] remove",
		"mechanisms[1].checks[0] op eq->ne",
		"mechanisms[1].checks[0] expected not",
		"mechanisms[1] remove",
	}
	ms := mutantsOf(c)
	if got := signatures(ms); !reflect.DeepEqual(got, want) {
		t.Errorf("signatures mismatch\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
	// A mechanism's mutant must change that mechanism and leave the other one
	// exactly as it was: the closures in mutantsOf capture j and k, and one
	// that captured the wrong index would still produce the right signature.
	for _, m := range ms {
		if !strings.HasPrefix(m.Signature, "mechanisms[1]") || strings.HasSuffix(m.Signature, " remove") {
			continue
		}
		if !reflect.DeepEqual(m.Control.Mechanisms[0], c.Mechanisms[0]) {
			t.Errorf("%s: also changed mechanisms[0]: %+v", m.Signature, m.Control.Mechanisms[0])
		}
	}
	rm := findMutant(t, ms, "mechanisms[0] remove")
	if len(rm.Control.Mechanisms) != 1 || !reflect.DeepEqual(rm.Control.Mechanisms[0], c.Mechanisms[1]) {
		t.Errorf("mechanisms[0] remove left %+v, want only the original mechanisms[1]", rm.Control.Mechanisms)
	}
}

const opsHead = "id: muster.test.ops\ntitle_en: T\ntitle_ko: T\ncategory: file\nimportance: 중\nautomation: auto\nreferences: {}\nrequires_facts: \">=1\"\nabsent_means: fail\n"

// F-2's operator table, row by row.
func TestMutantsOfOperatorTable(t *testing.T) {
	t.Run("each_to_none_keeps_where_drops_require", func(t *testing.T) {
		c := mustControl(t, opsHead+"checks:\n  - { fact: a.rows, op: each, subject: name, where: { field: kind, op: eq, expected: file }, require: { field: mode, op: eq, expected: \"600\" } }\n")
		m := findMutant(t, mutantsOf(c), "checks[0] op each->none")
		got := m.Control.Checks[0]
		if got.Op != "none" {
			t.Errorf("op = %q, want none", got.Op)
		}
		if got.Require != nil {
			t.Errorf("require survived the flip: %+v", got.Require)
		}
		if !reflect.DeepEqual(got.Where, c.Checks[0].Where) {
			t.Errorf("where = %+v, want %+v", got.Where, c.Checks[0].Where)
		}
		if got.Subject != "name" {
			t.Errorf("subject = %q, want name", got.Subject)
		}
	})

	t.Run("none_yields_no_reverse_flip", func(t *testing.T) {
		c := mustControl(t, opsHead+"checks:\n  - { fact: a.rows, op: none, subject: name, where: { field: kind, op: eq, expected: file } }\n")
		for _, s := range signatures(mutantsOf(c)) {
			if strings.HasPrefix(s, "checks[0] op none->") {
				t.Errorf("generated %q; an each needs a require a none never has", s)
			}
		}
	})

	t.Run("expected_by_type", func(t *testing.T) {
		cases := []struct {
			name     string
			expected string
			want     []string
			values   []any
		}{
			{"bool", "true", []string{"checks[0] expected not"}, []any{false}},
			{"int", "7", []string{"checks[0] expected +1", "checks[0] expected -1"}, []any{8, 6}},
			{"string", "root", []string{`checks[0] expected "__mutant__"`}, []any{"__mutant__"}},
			{"list", `["x", "y", "z"]`, []string{
				"checks[0] expected drop[0]", "checks[0] expected drop[1]",
				"checks[0] expected drop[2]", "checks[0] expected []",
			}, []any{
				[]any{"y", "z"}, []any{"x", "z"}, []any{"x", "y"}, []any{},
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := mustControl(t, opsHead+"checks:\n  - { fact: a.k, op: eq, expected: "+tc.expected+" }\n")
				ms := mutantsOf(c)
				var got []string
				for _, m := range ms {
					if strings.HasPrefix(m.Signature, "checks[0] expected") {
						got = append(got, m.Signature)
					}
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("expected mutants = %v, want %v", got, tc.want)
				}
				for i, sig := range tc.want {
					if v := findMutant(t, ms, sig).Control.Checks[0].Expected; !reflect.DeepEqual(v, tc.values[i]) {
						t.Errorf("%s: expected = %#v, want %#v", sig, v, tc.values[i])
					}
				}
			})
		}
	})

	t.Run("param_reference_mutated_once_per_parameter", func(t *testing.T) {
		c := mustControl(t, opsHead+"params:\n  allowed: { type: list<string>, default: [\"a\", \"b\"], description: d }\nchecks:\n  - { fact: a.one, op: in, expected: \"${allowed}\" }\n  - { fact: a.two, op: in, expected: \"${allowed}\" }\n")
		var params, clause []string
		for _, s := range signatures(mutantsOf(c)) {
			switch {
			case strings.HasPrefix(s, "params."):
				params = append(params, s)
			case strings.Contains(s, "expected"):
				clause = append(clause, s)
			}
		}
		want := []string{"params.allowed.default expected drop[0]", "params.allowed.default expected drop[1]", "params.allowed.default expected []"}
		if !reflect.DeepEqual(params, want) {
			t.Errorf("param mutants = %v, want %v", params, want)
		}
		if len(clause) != 0 {
			t.Errorf("a ${param} reference was mutated in place: %v", clause)
		}
	})
}

// F-2's two removal families: a clause list is thinned only when it has more
// than one clause, a mechanism only when the control has more than one, and
// absent_means takes its three other values.
func TestMutantsOfRemovalRules(t *testing.T) {
	head := "id: muster.test.rm\ntitle_en: T\ntitle_ko: T\ncategory: file\nimportance: 중\nautomation: auto\nreferences: {}\nrequires_facts: \">=1\"\n"
	one := "  - { fact: a.k, op: present }\n"
	mone := "      - { fact: a.k, op: present }\n" // one check nested under a mechanism

	has := func(sigs []string, sig string) bool {
		for _, s := range sigs {
			if s == sig {
				return true
			}
		}
		return false
	}
	t.Run("single_check_is_not_removed", func(t *testing.T) {
		sigs := signatures(mutantsOf(mustControl(t, head+"absent_means: fail\nchecks:\n"+one)))
		if has(sigs, "checks[0] remove") {
			t.Errorf("removed the only check, which leaves no judgment: %v", sigs)
		}
	})
	t.Run("two_checks_are_both_removed", func(t *testing.T) {
		sigs := signatures(mutantsOf(mustControl(t, head+"absent_means: fail\nchecks:\n"+one+"  - { fact: a.j, op: present }\n")))
		for _, want := range []string{"checks[0] remove", "checks[1] remove"} {
			if !has(sigs, want) {
				t.Errorf("no %q in %v", want, sigs)
			}
		}
	})
	t.Run("single_mechanism_is_not_removed", func(t *testing.T) {
		sigs := signatures(mutantsOf(mustControl(t, head+"absent_means: fail\nmechanisms:\n  - when: { fact: a.w, op: present }\n    checks:\n"+mone)))
		if has(sigs, "mechanisms[0] remove") {
			t.Errorf("removed the only mechanism: %v", sigs)
		}
		for _, want := range []string{"mechanisms[0].when[0] op present->absent", "mechanisms[0].when[0] remove", "mechanisms[0].checks[0] op present->absent"} {
			if !has(sigs, want) {
				t.Errorf("no %q in %v", want, sigs)
			}
		}
	})
	t.Run("two_mechanisms_are_both_removed", func(t *testing.T) {
		two := head + "absent_means: fail\nmechanisms:\n  - when: { fact: a.w, op: present }\n    checks:\n" + mone + "  - when: { fact: a.x, op: present }\n    checks:\n" + mone
		sigs := signatures(mutantsOf(mustControl(t, two)))
		for _, want := range []string{"mechanisms[0] remove", "mechanisms[1] remove"} {
			if !has(sigs, want) {
				t.Errorf("no %q in %v", want, sigs)
			}
		}
	})
	t.Run("absent_means_takes_the_three_others", func(t *testing.T) {
		sigs := signatures(mutantsOf(mustControl(t, head+"absent_means: manual\nchecks:\n"+one)))
		var got []string
		for _, s := range sigs {
			if strings.HasPrefix(s, "absent_means ") {
				got = append(got, s)
			}
		}
		want := []string{"absent_means ->pass", "absent_means ->fail", "absent_means ->not_applicable"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("absent_means mutants = %v, want %v", got, want)
		}
	})
}

// F-1: mutants are built on a deep copy, so generating them cannot disturb
// the set the kill loop is still evaluating, and two runs name the same
// mutants in the same order.
func TestMutantsOfIsPureAndDeterministic(t *testing.T) {
	c := mustControl(t, sigFixtureYAML)
	untouched := mustControl(t, sigFixtureYAML)
	first := mutantsOf(c)
	if !reflect.DeepEqual(c, untouched) {
		t.Errorf("mutantsOf mutated its input:\n got: %+v\nwant: %+v", c, untouched)
	}
	second := mutantsOf(c)
	if !reflect.DeepEqual(signatures(first), signatures(second)) {
		t.Errorf("two calls disagree:\n%v\n%v", signatures(first), signatures(second))
	}
	for i := range first {
		if !reflect.DeepEqual(first[i].Control, second[i].Control) {
			t.Errorf("%s: two calls built different controls", first[i].Signature)
		}
	}
}

// G-3: validity is the real lint with the registry and the custom-function
// set, not a hand-written list of what the generator believes is legal.
func TestLintValidUsesTheRealLint(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	head := "id: muster.test.valid\ntitle_en: T\ntitle_ko: T\ncategory: file\nimportance: 중\nautomation: auto\nreferences: {}\nrequires_facts: \">=1\"\nabsent_means: fail\nremediation: { text_en: x, text_ko: x, risk: none, idempotent: true }\n"
	cases := []struct {
		name string
		yaml string
		sig  string
		want bool
	}{
		{
			"not_matches_on_a_list_fact_is_rejected",
			head + "checks:\n  - { fact: files.etc_securetty_lines, op: matches, expected: \"^root$\" }\n",
			"checks[0] op matches->not_matches", false,
		},
		{
			"an_int_param_default_stays_an_int",
			head + "params:\n  max: { type: int, default: 10, description: d }\nchecks:\n  - { fact: banners.issue.mode, op: lte, expected: \"${max}\" }\n",
			"params.max.default expected +1", true,
		},
		{
			"present_flipped_to_absent_is_legal",
			head + "checks:\n  - { fact: services.ssh.installed, op: present }\n",
			"checks[0] op present->absent", true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mustControl(t, tc.yaml)
			if !lintValid(c, reg) {
				t.Fatalf("the original control does not lint clean; the case proves nothing")
			}
			m := findMutant(t, mutantsOf(c), tc.sig)
			if got := lintValid(m.Control, reg); got != tc.want {
				t.Errorf("lintValid(%s) = %v, want %v", tc.sig, got, tc.want)
			}
		})
	}
}
