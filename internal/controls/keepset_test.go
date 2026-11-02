package controls_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/profile"
)

// The keep-set and mount-target pins (3D-3 AX-5, AX-6) live here, in an
// external test package, so that internal/anonymize never imports the
// control set: its closed lists are held to what the controls compare.

// litValueOps compare a clause's value with its expected; present and
// absent read presence only, and each and none read a list through their
// where and require clauses.
var litValueOps = map[string]bool{
	"eq": true, "ne": true, "in": true, "not_in": true, "matches": true, "not_matches": true,
	"contains": true, "not_contains": true, "gt": true, "gte": true, "lt": true, "lte": true,
}

var litCollectionOps = map[string]bool{"each": true, "none": true}

var litParamRef = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

// litRead is one comparison a clause makes: the table row of the value it
// reads, the op, and every string it compares that value with (a literal,
// or a ${param}'s default and each built-in profile's value for it).
type litRead struct {
	row, op, by string
	values      []string
}

// strs is every string of an expected value: a string, or the strings of a
// list. Anything else (a number, a boolean) names no account or path.
func strs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, strs(e)...)
		}
		return out
	case []string:
		return append([]string(nil), x...)
	}
	return nil
}

// controlReads walks every clause of the control set — checks,
// applies_when, each mechanism's when and checks, and the where and require
// of a collection op — and resolves each expected value: a literal as
// written, a ${param} as its default and as each built-in profile's value.
func controlReads(t *testing.T) []litRead {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var files []*profile.File
	for _, n := range profile.Builtins() {
		f, ok := profile.Builtin(n)
		if !ok {
			t.Fatalf("built-in %q does not load", n)
		}
		files = append(files, f)
	}
	var out []litRead
	for i := range set.Controls {
		c := &set.Controls[i]
		resolve := func(expected any) []string {
			s, ok := expected.(string)
			if !ok {
				return strs(expected)
			}
			m := litParamRef.FindStringSubmatch(s)
			if m == nil {
				return []string{s}
			}
			p, ok := c.Params[m[1]]
			if !ok {
				t.Fatalf("%s: ${%s} is not declared", c.ID, m[1])
			}
			vals := strs(p.Default)
			for _, f := range files {
				if v, ok := f.Params[c.ID][m[1]]; ok {
					vals = append(vals, strs(v)...)
				}
			}
			return vals
		}
		read := func(row, op string, expected any) {
			out = append(out, litRead{row: row, op: op, by: c.ID, values: resolve(expected)})
		}
		var clause func(cl controls.Clause, base string)
		clause = func(cl controls.Clause, base string) {
			p := base
			if cl.Fact != "" {
				p = cl.Fact
			}
			if cl.Field != "" {
				if p != "" {
					p += "."
				}
				p += cl.Field
			}
			if p == "" {
				return
			}
			switch {
			case litCollectionOps[cl.Op]:
				for _, sub := range []*controls.Clause{cl.Where, cl.Require} {
					if sub != nil {
						clause(*sub, p+"[]")
					}
				}
			case litValueOps[cl.Op]:
				read(p, cl.Op, cl.Expected)
			}
		}
		all := append(append([]controls.Clause(nil), c.AppliesWhen...), c.Checks...)
		for _, m := range c.Mechanisms {
			all = append(append(all, m.When...), m.Checks...)
		}
		for _, cl := range all {
			clause(cl, "")
		}
	}
	if len(out) < 100 {
		t.Fatalf("only %d comparisons found; the clause walk is broken", len(out))
	}
	return out
}

// ruleOf is the table row a read resolves to: the row itself, or a list's
// element row when the op reads a list field's elements (contains, in).
func ruleOf(row string) []anonymize.FieldRule {
	var rs []anonymize.FieldRule
	if r, ok := anonymize.Default[row]; ok {
		rs = append(rs, r)
	}
	if r, ok := anonymize.Default[row+"[]"]; ok {
		rs = append(rs, r)
	}
	return rs
}

// accountCore strips the sigils the account rule keeps (%group, +netgroup,
// -name, @netgroup, #name); "" for a uid (#<digits>) or an empty name.
func accountCore(s string) string {
	for s != "" {
		switch s[0] {
		case '%', '+', '-', '@':
			s = s[1:]
			continue
		case '#':
			rest := s[1:]
			if strings.Trim(rest, "0123456789") == "" {
				return ""
			}
			s = rest
			continue
		}
		return s
	}
	return ""
}

// accountNames is every account-class name a read compares: a whole
// expected string on an account row, an @netgroup or "*" on a
// host-or-netgroup row, and each whitespace token at an account position of
// a grammar row (an equality or membership read; a regular expression names
// no account). A regular expression against an account row is reported, not
// guessed at.
func accountNames(t *testing.T, rd litRead, r anonymize.FieldRule) []string {
	regex := rd.op == "matches" || rd.op == "not_matches"
	switch r.Class {
	case anonymize.ClassAccount:
		if regex {
			t.Errorf("%s: %s compares account row %s with a regular expression %q; pin its names by hand", rd.by, rd.op, rd.row, rd.values)
			return nil
		}
		var out []string
		for _, v := range rd.values {
			if c := accountCore(v); c != "" {
				out = append(out, c)
			}
		}
		return out
	case anonymize.ClassHostOrNetgroup:
		if regex {
			return nil
		}
		var out []string
		for _, v := range rd.values {
			if strings.HasPrefix(v, "@") || v == "*" {
				if c := accountCore(v); c != "" {
					out = append(out, c)
				} else {
					out = append(out, v)
				}
			}
		}
		return out
	case anonymize.ClassGrammar:
		if regex {
			return nil
		}
		g := r.Grammar
		at := func(i int) anonymize.Class {
			if i < len(g.Tokens) {
				return g.Tokens[i]
			}
			return g.Rest
		}
		var out []string
		for _, v := range rd.values {
			for i, tok := range strings.Fields(v) {
				if k, val, ok := strings.Cut(tok, "="); ok && g.Values[k] == anonymize.ClassAccount {
					if c := accountCore(val); c != "" {
						out = append(out, c)
					}
					continue
				}
				if at(i) == anonymize.ClassAccount && tok != "+" && tok != "-" {
					if c := accountCore(tok); c != "" {
						out = append(out, c)
					}
				}
			}
		}
		return out
	}
	return nil
}

// Every name a control compares against an account-class value — a scalar
// fact, a list element or a record field, as a literal or as a parameter's
// default or a built-in profile's value — is in the closed keep set, so
// anonymising a snapshot never changes the verdict that name decides
// (AX-5). A new literal fails here, not in a shared report.
func TestKeepSetCoversControlLiterals(t *testing.T) {
	found := map[string][]string{} // name -> controls that compare it
	for _, rd := range controlReads(t) {
		for _, r := range ruleOf(rd.row) {
			for _, n := range accountNames(t, rd, r) {
				found[n] = append(found[n], rd.by+" ("+rd.row+")")
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("no account-class literal found; the walk or the table lookup is broken")
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		by := uniq(found[n])
		t.Logf("account literal %q compared by %s", n, strings.Join(by, ", "))
		if !anonymize.Kept(n) {
			t.Errorf("%q is compared against an account-class value by %s but is not in anonymize's keep set (%s)",
				n, strings.Join(by, ", "), anonymize.KeepSetVersion)
		}
	}
	for _, must := range []string{"root", "ftp"} {
		if _, ok := found[must]; !ok {
			t.Errorf("%q is not among the found literals; the walk misses a known comparison", must)
		}
	}
}

// Every mount target a control compares — a literal or a parameter's
// default or built-in profile value compared with mounts.points[].target —
// is in anonymize.MountTargets, so a home equal to one is never rewritten
// and the comparison still finds it (AX-6).
func TestMountTargetsCoverControls(t *testing.T) {
	inList := map[string]bool{}
	for _, m := range anonymize.MountTargets {
		inList[m] = true
	}
	found := map[string][]string{}
	for _, rd := range controlReads(t) {
		if rd.row != "mounts.points[].target" {
			continue
		}
		if rd.op == "matches" || rd.op == "not_matches" {
			t.Errorf("%s compares mounts.points[].target with a regular expression; pin its targets by hand", rd.by)
			continue
		}
		for _, v := range rd.values {
			found[v] = append(found[v], rd.by)
		}
	}
	if len(found) == 0 {
		t.Fatal("no mount target found; the walk is broken")
	}
	targets := make([]string, 0, len(found))
	for v := range found {
		targets = append(targets, v)
	}
	sort.Strings(targets)
	for _, v := range targets {
		by := strings.Join(uniq(found[v]), ", ")
		t.Logf("mount target %q compared by %s", v, by)
		if !inList[v] {
			t.Errorf("mount target %q is compared by %s but is not in anonymize.MountTargets", v, by)
		}
	}
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
