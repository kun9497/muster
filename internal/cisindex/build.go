package cisindex

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// TableKey is the grammar of a vars: table key: a selection whose own
// spelling states its value (CB-8).
var TableKey = regexp.MustCompile(`^([0-9]+|0?[0-7]{3}|[0-9]+_(min|minutes|seconds))$`)

// asIntRE is `as: int`'s input: decimal digits, no leading zero.
var asIntRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// levelL1Server is the literal level a CIS Level 1 profile counts (CB-4, CB-7).
const levelL1Server = "l1_server"

// Benchmark is one pinned benchmark file and muster's own names for it.
type Benchmark struct {
	Product   string // the index key, e.g. ubuntu2204
	Display   string // the benchmark's display name
	Profile   string // the generated profile's name, e.g. cis-ubuntu2204-l1
	AppliesTo []string
	Pin       Pin
	EqualTo   *EqualTo
	Src       *Source
}

// Env is what Build needs from the control set: its ids, each parameter's
// declared type and the parameter value check (controls.CheckParamValue).
type Env struct {
	IDs       map[string]bool
	ParamType func(control, param string) (string, bool)
	Check     func(typ string, v any) error
}

// ProfileOut is a generated profile: exact control ids and parameter values.
type ProfileOut struct {
	Name    string
	Include []string
	Params  map[string]map[string]any
}

// Build joins one benchmark file with map.yaml and review.yaml into the
// benchmark's index and its generated profile (CB-5..CB-8). Every failure is
// reported, joined, each prefixed with the product.
func Build(b Benchmark, union map[string]bool, rows []MapRow, review []ReviewRow, env Env) (*Index, *ProfileOut, error) {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", b.Product, fmt.Sprintf(format, args...)))
	}
	if b.Src == nil {
		fail("no source file")
		return nil, nil, errors.Join(errs...)
	}
	if env.Check == nil {
		fail("env.Check is nil")
	}
	if env.ParamType == nil {
		fail("env.ParamType is nil")
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	entries := map[string]*Entry{}
	for i := range b.Src.Entries {
		entries[b.Src.Entries[i].ID] = &b.Src.Entries[i]
	}

	// Validate the rows.
	for _, r := range rows {
		if !env.IDs[r.ID] {
			fail("map: %s is not a control of the set", r.ID)
		}
		for _, rule := range r.Rules {
			switch {
			case !ValidRuleID(rule):
				fail("map: %s: rule id %q is outside the rule-id grammar", r.ID, rule)
			case !union[rule]:
				fail("map: %s: rule id %s is in no source file", r.ID, rule)
			}
		}
		for _, v := range r.Vars {
			if err := checkVarRow(v); err != nil {
				fail("map: %s: %v", r.ID, err)
				continue
			}
			if v.Param == "none" {
				continue
			}
			typ, ok := "", false
			if env.ParamType != nil {
				typ, ok = env.ParamType(r.ID, v.Param)
			}
			if !ok {
				fail("map: %s: vars: %s: the control declares no parameter %s", r.ID, v.Var, v.Param)
				continue
			}
			if tbl, isTable := v.As.(map[string]any); isTable {
				for _, k := range sortedKeys(tbl) {
					if !TableKey.MatchString(k) {
						fail("map: %s: vars: %s: table key %q does not state its value", r.ID, v.Var, k)
						continue
					}
					if err := env.Check(typ, tbl[k]); err != nil {
						fail("map: %s: vars: %s: table value for %q: %s.%s: %v", r.ID, v.Var, k, r.ID, v.Param, err)
					}
				}
			}
		}
		for _, rr := range r.Recs[b.Product] {
			if !ValidRec(rr.Rec) {
				fail("map: %s: recs: %q is not a recommendation number", r.ID, rr.Rec)
				continue
			}
			e, ok := entries[rr.Rec]
			if !ok {
				fail("map: %s: recs: %s is not in %s", r.ID, rr.Rec, b.Pin.Path)
				continue
			}
			if len(e.Rules) > 0 {
				fail("map: %s: recs: %s lists rule ids (%s); map them under rules:", r.ID, rr.Rec, strings.Join(e.Rules, ", "))
			}
		}
	}

	// Reach: an entry with rule ids is reached by rule ids alone, an entry
	// without by recs: alone (CB-5); the word is computed (CB-6).
	ruleSets := make([]map[string]bool, len(rows))
	for i, r := range rows {
		ruleSets[i] = setOf(r.Rules)
	}
	ix := &Index{
		Product: b.Product, Benchmark: b.Display, Version: b.Src.Version,
		AppliesTo: b.AppliesTo, Source: b.Pin, EqualTo: b.EqualTo,
	}
	reached := make([][]*Entry, len(rows)) // per row: the l1_server entries its rule ids reach
	for ei := range b.Src.Entries {
		e := &b.Src.Entries[ei]
		if HasLevel(*e, levelL1Server) {
			ix.Counts.L1Server++
		}
		controls := map[string]bool{}
		if len(e.Rules) > 0 {
			covered := map[string]bool{}
			for i, r := range rows {
				hit := false
				for _, rule := range e.Rules {
					if ruleSets[i][rule] {
						covered[rule], hit = true, true
					}
				}
				if hit {
					controls[r.ID] = true
					if HasLevel(*e, levelL1Server) {
						reached[i] = append(reached[i], e)
					}
				}
			}
			if len(controls) == 0 {
				continue
			}
			word := "some"
			if len(covered) == len(setOf(e.Rules)) {
				word = "all"
			}
			ix.Recs = append(ix.Recs, Row{Rec: e.ID, Levels: e.Levels, Controls: sortedKeys(controls), Rules: word})
			continue
		}
		for _, r := range rows {
			for _, rr := range r.Recs[b.Product] {
				if rr.Rec == e.ID {
					controls[r.ID] = true
				}
			}
		}
		if len(controls) > 0 {
			ix.Recs = append(ix.Recs, Row{Rec: e.ID, Levels: e.Levels, Controls: sortedKeys(controls), Rules: "none"})
		}
	}
	sort.SliceStable(ix.Recs, func(i, j int) bool { return CompareRec(ix.Recs[i].Rec, ix.Recs[j].Rec) < 0 })

	// Candidates minus the review list (CB-7).
	candidates := setOf(Candidates(ix))
	reviewed := map[string]bool{}
	for _, rv := range review {
		if rv.Profile != b.Profile {
			continue
		}
		if !candidates[rv.ID] {
			fail("review: %s on %s is not a candidate of %s", rv.ID, rv.Profile, b.Product)
			continue
		}
		reviewed[rv.ID] = true
	}
	p := &ProfileOut{Name: b.Profile, Include: []string{}}
	for _, id := range sortedKeys(candidates) {
		if !reviewed[id] {
			p.Include = append(p.Include, id)
		}
	}
	included := setOf(p.Include)

	// Variables (CB-8): the worklist over every mapped control, the
	// conversion over the controls the profile keeps.
	for i, r := range rows {
		named := map[string]bool{}
		for _, v := range r.Vars {
			named[v.Var] = true
		}
		values := map[string]map[string]bool{} // var → selected texts
		for _, e := range reached[i] {
			for _, s := range e.Selections {
				if !named[s.Var] {
					fail("map: %s: variable %s selected on %s has no vars: row", r.ID, s.Var, e.ID)
					named[s.Var] = true // once per variable
				}
				if values[s.Var] == nil {
					values[s.Var] = map[string]bool{}
				}
				values[s.Var][s.Value] = true
			}
		}
		if !included[r.ID] {
			continue
		}
		setBy := map[string]string{} // param → var
		for _, v := range r.Vars {
			if v.Param == "none" || values[v.Var] == nil || checkVarRow(v) != nil {
				continue
			}
			typ, ok := "", false
			if env.ParamType != nil {
				typ, ok = env.ParamType(r.ID, v.Param)
			}
			if !ok {
				continue // reported above
			}
			texts := sortedKeys(values[v.Var])
			if len(texts) > 1 {
				fail("map: %s: variable %s is selected as %s on one benchmark", r.ID, v.Var, strings.Join(texts, " and "))
				continue
			}
			val, err := convert(v, texts[0])
			if err != nil {
				fail("map: %s: vars: %s: %v", r.ID, v.Var, err)
				continue
			}
			if err := env.Check(typ, val); err != nil {
				fail("map: %s: vars: %s: %s.%s: %v", r.ID, v.Var, r.ID, v.Param, err)
				continue
			}
			if other, dup := setBy[v.Param]; dup {
				fail("map: %s: parameter %s is set by both %s and %s", r.ID, v.Param, other, v.Var)
				continue
			}
			setBy[v.Param] = v.Var
			if p.Params == nil {
				p.Params = map[string]map[string]any{}
			}
			if p.Params[r.ID] == nil {
				p.Params[r.ID] = map[string]any{}
			}
			p.Params[r.ID][v.Param] = val
		}
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return ix, p, nil
}

// convert reads a selected text through a vars: row's conversion.
func convert(v VarRow, text string) (any, error) {
	switch as := v.As.(type) {
	case string: // "int", checkVarRow
		if !asIntRE.MatchString(text) {
			return nil, fmt.Errorf("selection %q is not a decimal number", text)
		}
		n, err := strconv.Atoi(text)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %v", text, err)
		}
		return n, nil
	case map[string]any:
		val, ok := as[text]
		if !ok {
			return nil, fmt.Errorf("selection %q has no table entry", text)
		}
		return val, nil
	}
	return nil, fmt.Errorf("no conversion")
}

// Candidates are the controls on index rows whose levels hold l1_server,
// sorted (CB-7).
func Candidates(ix *Index) []string {
	set := map[string]bool{}
	for _, r := range ix.Recs {
		if HasLevel(Entry{Levels: r.Levels}, levelL1Server) {
			for _, c := range r.Controls {
				set[c] = true
			}
		}
	}
	return sortedKeys(set)
}

// profileHeader is the first line of every generated profile.
const profileHeader = "# Generated by tools/cisindex from docs/reference/cis; do not edit.\n"

// RenderProfile is a generated profile's bytes: the header, then profile,
// include and params (map keys sorted by yaml.v3).
func RenderProfile(p *ProfileOut) ([]byte, error) {
	doc := struct {
		Profile string                    `yaml:"profile"`
		Include []string                  `yaml:"include"`
		Params  map[string]map[string]any `yaml:"params,omitempty"`
	}{p.Name, p.Include, p.Params}
	if doc.Include == nil {
		doc.Include = []string{}
	}
	var buf bytes.Buffer
	buf.WriteString(profileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func setOf(xs []string) map[string]bool {
	s := make(map[string]bool, len(xs))
	for _, x := range xs {
		s[x] = true
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
