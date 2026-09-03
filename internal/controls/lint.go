package controls

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/facts"
)

// Problem is one lint finding. Rule is a stable name CI can match on.
type Problem struct {
	ControlID string
	Path      string
	Rule      string
	Message   string
}

func (p Problem) String() string { return fmt.Sprintf("%s: %s: %s", p.Path, p.Rule, p.Message) }

// LintOptions carries what lint cannot know on its own: the registered
// custom functions (owned by check), where fixtures live, and the generated
// STIG/NIST reference index (nil means references are checked for shape
// only, never for existence).
type LintOptions struct {
	CustomFuncs map[string]bool
	FixtureDir  string
	References  *ReferenceIndex
}

var (
	idRe            = regexp.MustCompile(`^muster\.[a-z]+\.[a-z0-9_]+$`)
	requiresFactsRe = regexp.MustCompile(`^>=[1-9][0-9]*$`)
	kisaYearRe      = regexp.MustCompile(`^[0-9]{4}$`)
	kisaItemRe      = regexp.MustCompile(`^U-[0-9]{2}$`)
	paramRefRe      = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

	validCategory    = set("account", "file", "service", "patch", "log", "beyond")
	validImportance  = set("상", "중", "하")
	validAutomation  = set("auto", "partial", "manual", "not_applicable")
	validAbsentMeans = set("pass", "fail", "not_applicable", "manual")
	validRisk        = set("none", "restart_service", "reboot_required", "lockout_risk")
	validOn          = set("runtime", "persisted", "effective", "both")
	validPersona     = set("root", "user", "invalid")
	validParamType   = set("string", "int", "bool", "list<string>", "list<int>")
	scalarOps        = set("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "matches", "not_matches", "contains", "present", "absent")
	orderedOps       = set("lt", "lte", "gt", "gte")
	collectionOps    = set("each", "none")
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Lint applies every rule of spec §6.8 to set and returns the problems sorted
// by path then rule. An empty result means the set is clean.
func Lint(s *Set, reg *facts.Registry, opts LintOptions) []Problem {
	var out []Problem
	for i := range s.Controls {
		c := &s.Controls[i]
		add := func(rule, format string, args ...any) {
			out = append(out, Problem{ControlID: c.ID, Path: c.Path, Rule: rule, Message: fmt.Sprintf(format, args...)})
		}
		if !idRe.MatchString(c.ID) {
			add("id_format", "id %q must look like muster.<area>.<name>", c.ID)
		}
		if c.TitleEn == "" || c.TitleKo == "" {
			add("titles", "title_en and title_ko are required")
		}
		if !validCategory[c.Category] {
			add("category", "unknown category %q", c.Category)
		}
		if !validImportance[c.Importance] {
			add("importance", "importance must be 상, 중 or 하; got %q", c.Importance)
		}
		if !validAutomation[c.Automation] {
			add("automation", "unknown automation %q", c.Automation)
		}
		if c.Automation == "manual" && strings.TrimSpace(c.ManualReason) == "" {
			add("manual_reason", "manual controls must state manual_reason")
		}
		if (c.Automation == "auto" || c.Automation == "partial") && c.Remediation == nil {
			add("remediation", "%s controls must carry remediation", c.Automation)
		}
		if c.Remediation != nil && !validRisk[c.Remediation.Risk] {
			add("remediation", "unknown remediation risk %q", c.Remediation.Risk)
		}
		judgments := 0
		if len(c.Checks) > 0 {
			judgments++
		}
		if len(c.Mechanisms) > 0 {
			judgments++
		}
		if c.Custom != "" {
			judgments++
		}
		hasJudgment := c.Automation == "auto" || c.Automation == "partial"
		if hasJudgment && judgments != 1 {
			add("judgment", "exactly one of checks, mechanisms or custom is required; found %d", judgments)
		}
		if !hasJudgment && judgments != 0 {
			add("judgment", "%s controls carry no judgment", c.Automation)
		}
		if hasJudgment && !validAbsentMeans[c.AbsentMeans] {
			add("absent_means", "absent_means must be pass, fail, not_applicable or manual; got %q", c.AbsentMeans)
		}
		if c.RequiresFacts == "" {
			add("requires_facts", "requires_facts is required; use >=1")
		} else if !requiresFactsRe.MatchString(c.RequiresFacts) {
			add("requires_facts", "requires_facts must be >=N; got %q", c.RequiresFacts)
		}
		if c.Custom != "" && !opts.CustomFuncs[c.Custom] {
			add("custom_func", "unknown custom function %q", c.Custom)
		}
		for name, p := range c.Params {
			if !validParamType[p.Type] {
				add("param", "param %q has unknown type %q", name, p.Type)
			} else if !paramDefaultMatches(p) {
				add("param", "param %q default %v does not match type %s", name, p.Default, p.Type)
			}
		}
		for year, items := range c.References.KISA {
			if !kisaYearRe.MatchString(year) {
				add("references_kisa", "kisa reference key %q must be a four-digit edition year", year)
			}
			for _, it := range items {
				if !kisaItemRe.MatchString(it) {
					add("references_kisa", "kisa reference %q must look like U-01", it)
				}
			}
		}
		for _, r := range c.References.CIS {
			if r.Benchmark == "" || r.Version == "" || r.Rec == "" {
				add("references_cis", "cis references need benchmark, version and rec")
			}
		}
		for _, r := range c.References.STIG {
			switch {
			case r.Benchmark == "" || r.Version == "" || r.ID == "":
				add("references_stig", "stig references need benchmark, version and id")
			case opts.References == nil:
				add("references_stig", "no reference index loaded; %s@%s %s cannot be verified", r.Benchmark, r.Version, r.ID)
			case !opts.References.HasSTIG(r.Benchmark, r.Version, r.ID):
				add("references_stig", "stig reference %s@%s %s is not in docs/reference/stig", r.Benchmark, r.Version, r.ID)
			}
		}
		for _, n := range c.References.NIST80053 {
			if !ValidNISTID(n) {
				add("references_nist", "nist_800_53 reference %q must look like AC-6 or AC-6(10)", n)
				continue
			}
			if opts.References != nil && !opts.References.HasNIST(n) {
				add("references_nist", "nist_800_53 reference %q appears in no indexed STIG rule", n)
			}
		}
		for _, cl := range c.AppliesWhen {
			lintClause(c, cl, reg, add, "applies_when")
		}
		for _, cl := range c.Checks {
			lintClause(c, cl, reg, add, "checks")
		}
		for mi, m := range c.Mechanisms {
			for _, cl := range m.When {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].when", mi))
			}
			for _, cl := range m.Checks {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].checks", mi))
			}
		}
		if opts.FixtureDir != "" && hasJudgment {
			for _, prefix := range []string{"pass-", "fail-"} {
				matches, _ := filepath.Glob(filepath.Join(opts.FixtureDir, c.ID, prefix+"*.json"))
				if len(matches) == 0 {
					add("fixtures", "no %s*.json fixture under %s", prefix, filepath.Join(opts.FixtureDir, c.ID))
				}
			}
		}
	}
	// M13: several rules range over a map (params, references.kisa), whose
	// iteration order Go randomises, so the message has to be part of the
	// sort key or two problems of the same rule swap places between runs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Message < out[j].Message
	})
	if out == nil {
		out = []Problem{}
	}
	return out
}

func paramDefaultMatches(p Param) bool {
	switch p.Type {
	case "string":
		_, ok := p.Default.(string)
		return ok
	case "int":
		_, ok := p.Default.(int)
		return ok
	case "bool":
		_, ok := p.Default.(bool)
		return ok
	case "list<string>":
		xs, ok := p.Default.([]any)
		if !ok {
			return false
		}
		for _, x := range xs {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	case "list<int>":
		xs, ok := p.Default.([]any)
		if !ok {
			return false
		}
		for _, x := range xs {
			if _, ok := x.(int); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// lintClause checks one top-level clause and, for collections, its
// sub-clauses, against the grammar of spec §6.3.
func lintClause(c *Control, cl Clause, reg *facts.Registry, add func(string, string, ...any), where string) {
	if cl.Fact == "" {
		add("clause_grammar", "%s: clause needs fact", where)
		return
	}
	if cl.Field != "" {
		add("clause_grammar", "%s: field is only valid inside where/require", where)
	}
	entry, ok := reg.Lookup(cl.Fact)
	if !ok {
		add("fact_key", "%s: fact %q is not registered", where, cl.Fact)
		return
	}
	isSetting := reg.IsSetting(entry)
	isList := strings.HasPrefix(entry.Type, "list<")
	switch {
	case scalarOps[cl.Op]:
		lintScalarOp(cl, entry, add, where)
		if cl.Where != nil || cl.Require != nil || cl.Subject != "" {
			add("clause_grammar", "%s: where/require/subject are only valid with each or none", where)
		}
	case collectionOps[cl.Op]:
		if !isList {
			add("clause_grammar", "%s: %s needs a list-typed fact; %s is %s", where, cl.Op, cl.Fact, entry.Type)
		}
		if cl.Expected != nil || cl.On != "" || cl.Persona != "" {
			add("clause_grammar", "%s: %s takes no expected/on/persona", where, cl.Op)
		}
		if cl.Op == "each" && (cl.Subject == "" || cl.Require == nil) {
			add("clause_grammar", "%s: each needs subject and require", where)
		}
		if cl.Op == "none" && cl.Where == nil {
			add("clause_grammar", "%s: none needs where", where)
		}
		for _, sub := range []*Clause{cl.Where, cl.Require} {
			if sub == nil {
				continue
			}
			if sub.Fact != "" || sub.Where != nil || sub.Require != nil || sub.On != "" || sub.Persona != "" {
				add("clause_grammar", "%s: sub-clauses use field, op and expected only", where)
			}
			if !scalarOps[sub.Op] {
				add("clause_grammar", "%s: sub-clause op %q is not a scalar operator", where, sub.Op)
			}
			if entry.Type == "list<record>" && sub.Field == "" {
				add("clause_grammar", "%s: sub-clause needs field for a record element", where)
			}
			if entry.Type == "list<string>" && sub.Field != "" {
				add("clause_grammar", "%s: scalar elements have no fields", where)
			}
			lintExpected(*sub, add, where)
			checkParamRef(c, sub.Expected, add, where)
		}
	default:
		add("clause_grammar", "%s: unknown op %q", where, cl.Op)
	}
	if cl.On != "" && (!isSetting || !validOn[cl.On]) {
		add("clause_grammar", "%s: on=%q is only valid on a setting-typed fact", where, cl.On)
	}
	if cl.Persona != "" && (!validPersona[cl.Persona] || !strings.HasPrefix(cl.Fact, "sshd.options.")) {
		add("clause_grammar", "%s: persona=%q is only valid on sshd.options.* facts", where, cl.Persona)
	}
	if orderedOps[cl.Op] && entry.Type != "int" && entry.Type != "setting<int>" {
		add("clause_grammar", "%s: %s needs an int fact", where, cl.Op)
	}
	if cl.Op == "not_matches" && isList {
		add("clause_grammar", "%s: not_matches is scalar-only; use none with a where clause", where)
	}
	checkParamRef(c, cl.Expected, add, where)
}

// checkParamRef reports an undeclared ${name} reference in expected, whether
// it comes from a top-level clause or a where/require sub-clause (Ruling R7).
func checkParamRef(c *Control, expected any, add func(string, string, ...any), where string) {
	if s, ok := expected.(string); ok {
		if m := paramRefRe.FindStringSubmatch(s); m != nil {
			if _, declared := c.Params[m[1]]; !declared {
				add("param", "%s: parameter %q is not declared", where, m[1])
			}
		}
	}
}

func lintScalarOp(cl Clause, entry facts.Entry, add func(string, string, ...any), where string) {
	lintExpected(cl, add, where)
}

func lintExpected(cl Clause, add func(string, string, ...any), where string) {
	switch cl.Op {
	case "present", "absent":
		if cl.Expected != nil {
			add("clause_grammar", "%s: %s takes no expected", where, cl.Op)
		}
	case "matches", "not_matches":
		s, ok := cl.Expected.(string)
		if !ok {
			add("clause_grammar", "%s: %s needs a string pattern", where, cl.Op)
			return
		}
		if _, err := regexp.Compile(s); err != nil {
			add("clause_grammar", "%s: pattern %q does not compile: %v", where, s, err)
		}
	default:
		if cl.Expected == nil && scalarOps[cl.Op] {
			add("clause_grammar", "%s: %s needs expected", where, cl.Op)
		}
	}
}

// FixtureDirExists reports whether dir is a directory the CLI can lint
// fixtures against. A missing directory is an error there (R35), never a
// silently skipped rule.
func FixtureDirExists(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// UnusedKeys returns the registered fact keys no control in s references, in
// registry order (spec §5.5). It is a note rather than a lint failure: some
// keys are read by the evaluator itself (walk.complete gates the walk,
// sshd.collect_method and sshd.personas_collected decide degradation) and
// others are collected for stage 2 controls that do not exist yet.
func UnusedKeys(s *Set, reg *facts.Registry) []string {
	used := map[string]bool{}
	mark := func(cls []Clause) {
		for _, cl := range cls {
			if cl.Fact != "" {
				used[cl.Fact] = true
			}
		}
	}
	for i := range s.Controls {
		c := &s.Controls[i]
		mark(c.AppliesWhen)
		mark(c.Checks)
		for _, m := range c.Mechanisms {
			mark(m.When)
			mark(m.Checks)
		}
	}
	var out []string
	for _, e := range reg.Keys {
		if !used[e.Key] {
			out = append(out, e.Key)
		}
	}
	return out
}
