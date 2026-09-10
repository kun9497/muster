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

// String renders a problem for the CLI. A set-level problem belongs to no
// file, so it names the set instead of an empty path. M-2 marks such a
// problem by both an empty control id and an empty path: a Set built in code
// rather than loaded from disk has controls with no path, and their problems
// must not masquerade as set-level.
func (p Problem) String() string {
	if p.ControlID == "" && p.Path == "" {
		return fmt.Sprintf("controls: %s: %s", p.Rule, p.Message)
	}
	return fmt.Sprintf("%s: %s: %s", p.Path, p.Rule, p.Message)
}

// LintOptions carries what lint cannot know on its own: the registered
// custom functions (owned by check), where fixtures live, the generated
// STIG/NIST reference index (nil means references are checked for shape
// only, never for existence) and the KISA item inventory (nil means
// references.kisa is checked for shape only, and the set-level coverage rule
// does not run at all).
type LintOptions struct {
	CustomFuncs map[string]bool
	FixtureDir  string
	References  *ReferenceIndex
	KISA        *KISAInventory
}

var (
	idRe            = regexp.MustCompile(`^muster\.[a-z]+\.[a-z0-9_]+$`)
	requiresFactsRe = regexp.MustCompile(`^>=[1-9][0-9]*$`)
	kisaYearRe      = regexp.MustCompile(`^[0-9]{4}$`)
	kisaItemRe      = regexp.MustCompile(`^U-[0-9]{2}$`)
	paramRefRe      = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

	categories       = []string{"account", "file", "service", "patch", "log", "beyond"}
	validCategory    = set(categories...)
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

// ValidControlID reports whether id is a well-formed control id --
// muster.<area>.<name>, lowercase (spec §6.2). It is the same rule the
// id_format lint applies, exported so controls new can refuse a bad id
// before it writes a file the lint would then reject.
func ValidControlID(id string) bool { return idRe.MatchString(id) }

// Categories returns the categories a control may declare (spec §6.2) in a
// fixed order. controls new derives the category from the id's area, so it
// needs the list both to check that area and to name the choices when it
// refuses.
func Categories() []string { return append([]string(nil), categories...) }

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
			wellFormedYear := kisaYearRe.MatchString(year)
			if !wellFormedYear {
				add("references_kisa", "kisa reference key %q must be a four-digit edition year", year)
			}
			// M-2: with an inventory, every cited id must be a real item of
			// the edition it is filed under, and an edition muster holds no
			// inventory for cannot be checked at all -- which is an error,
			// not a licence to cite anything.
			known := wellFormedYear && opts.KISA != nil && opts.KISA.HasEdition(year)
			if wellFormedYear && opts.KISA != nil && !known {
				add("references_kisa", "no inventory for edition %s; kisa references must name an edition with an inventory file", year)
			}
			// M-39: an id repeated inside one list is a mistake in this
			// control, and a different one from two controls claiming the
			// same item -- which is what the set-level rule reports.
			seen := map[string]bool{}
			for _, it := range items {
				if seen[it] {
					add("references_kisa", "kisa reference %s is listed twice under %s", it, year)
					continue
				}
				seen[it] = true
				if !kisaItemRe.MatchString(it) {
					add("references_kisa", "kisa reference %q must look like U-01", it)
					continue
				}
				if !known {
					continue
				}
				item, ok := opts.KISA.Item(year, it)
				if !ok {
					add("references_kisa", "%s is not in the %s inventory", it, year)
					continue
				}
				// R117 automated: a control that claims an item must agree
				// with the guide about how important that item is.
				if year == LatestKISAEdition && item.Importance != c.Importance {
					add("kisa_importance", "importance %q does not match the %s inventory, which lists %s as %q", c.Importance, year, it, item.Importance)
				}
			}
		}
		// M-8: evidence names the facts a reviewer needs in front of them.
		// It is only meaningful where muster declines to judge.
		if len(c.Evidence) > 0 && c.Automation != "manual" {
			add("evidence", "evidence is only valid on manual controls; this one is %s", c.Automation)
		}
		for _, k := range c.Evidence {
			if _, ok := reg.Lookup(k); !ok {
				add("evidence", "evidence key %q is not registered", k)
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
			case !ValidSTIGID(r.ID):
				add("references_stig", "stig reference id %q must look like RHEL-09-211010", r.ID)
			case opts.References != nil && !opts.References.HasSTIG(r.Benchmark, r.Version, r.ID):
				add("references_stig", "stig reference %s@%s %s is not in %s", r.Benchmark, r.Version, r.ID, filepath.Join(opts.References.Dir, "stig"))
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
		// The last argument says whether the list is a SCREEN (applies_when,
		// a mechanism's when) rather than a judgement: the evaluator reads
		// only Holds there, so a collection op must not appear (EV-4).
		for _, cl := range c.AppliesWhen {
			lintClause(c, cl, reg, add, "applies_when", true)
		}
		for _, cl := range c.Checks {
			lintClause(c, cl, reg, add, "checks", false)
		}
		for mi, m := range c.Mechanisms {
			for _, cl := range m.When {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].when", mi), true)
			}
			for _, cl := range m.Checks {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].checks", mi), false)
			}
		}
		lintShellValidScreen(c.AppliesWhen, add, "applies_when")
		lintShellValidScreen(c.Checks, add, "checks")
		for mi, m := range c.Mechanisms {
			lintShellValidScreen(m.When, add, fmt.Sprintf("mechanisms[%d].when", mi))
			lintShellValidScreen(m.Checks, add, fmt.Sprintf("mechanisms[%d].checks", mi))
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
	out = append(out, lintKISACoverage(s, opts.KISA)...)
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

// lintKISACoverage is the set-level half of M-2: coverage is a property of
// the whole set, not of any one file, so its problems carry no control id and
// no path. Every item of the current edition is implemented by exactly one
// control or listed in kisa_deferred.json -- an item cited twice, an item
// cited by nobody and not deferred, and a deferral a control has since
// implemented are each an error naming the ids. Only the current edition is
// judged: a 2021 item may legitimately be cited by two controls, because the
// 2021 list was split and renumbered into 2026 (M-26).
func lintKISACoverage(s *Set, x *KISAInventory) []Problem {
	if x == nil {
		return nil // shape-only linting: no inventory was offered
	}
	// G-3: the index Item and HasEdition answer from is filled by LoadKISA
	// alone, so a hand-built value reports no edition. A caller that passed an
	// inventory asked for the cross-check, and a cross-check that cannot run
	// is a problem rather than a silent pass -- which is what turning the
	// set-level gate off without a word would be.
	if !x.HasEdition(LatestKISAEdition) {
		return []Problem{{Rule: "kisa_coverage", Message: fmt.Sprintf("inventory holds no %s edition; the coverage rule cannot run", LatestKISAEdition)}}
	}
	citedBy := map[string][]string{}
	for i := range s.Controls {
		c := &s.Controls[i]
		// M-39: count each control once however many times its own list
		// repeats an id, so "cited by N controls" is true by construction.
		// The repeat itself is a per-control references_kisa problem.
		seen := map[string]bool{}
		for _, id := range c.References.KISA[LatestKISAEdition] {
			if seen[id] {
				continue
			}
			seen[id] = true
			citedBy[id] = append(citedBy[id], c.ID)
		}
	}
	var out []Problem
	add := func(format string, args ...any) {
		out = append(out, Problem{Rule: "kisa_coverage", Message: fmt.Sprintf(format, args...)})
	}
	var duplicated, stale, uncited []string
	for _, it := range x.Items[LatestKISAEdition] {
		n, deferred := len(citedBy[it.ID]), x.IsDeferred(it.ID)
		switch {
		case n == 0 && !deferred:
			uncited = append(uncited, it.ID)
		case n > 1:
			duplicated = append(duplicated, it.ID)
		}
		if n > 0 && deferred {
			stale = append(stale, it.ID)
		}
	}
	sort.Strings(duplicated)
	sort.Strings(stale)
	sort.Strings(uncited)
	for _, id := range duplicated {
		cs := append([]string(nil), citedBy[id]...)
		sort.Strings(cs)
		add("%s is cited by %d controls: %s", id, len(cs), strings.Join(cs, ", "))
	}
	for _, id := range stale {
		cs := append([]string(nil), citedBy[id]...)
		sort.Strings(cs)
		add("deferred item %s is cited by %s; drop it from %s", id, strings.Join(cs, ", "), kisaDeferredFile)
	}
	if len(uncited) > 0 {
		// G-9: a set one item short read "1 2026 items are cited by no
		// control". The message names ids, so it agrees in number with them.
		noun, verb, them := "items", "are", "them"
		if len(uncited) == 1 {
			noun, verb, them = "item", "is", "it"
		}
		add("%d %s %s %s cited by no control and %s not deferred: %s (enrol %s or list %s in %s)",
			len(uncited), LatestKISAEdition, noun, verb, verb, strings.Join(uncited, ", "), them, them, kisaDeferredFile)
	}
	// M-37: the loop above is over items, so it structurally cannot see a
	// deferral for something that is not an item -- a typo, or an id from
	// another edition. Such an entry excuses nothing and would sit in the
	// file forever, so it gets its own pass. Deferred is file-ordered and
	// file order is not a promise, hence the sort.
	var strays []string
	for _, d := range x.Deferred {
		if _, ok := x.Item(LatestKISAEdition, d.ID); !ok {
			strays = append(strays, d.ID)
		}
	}
	sort.Strings(strays)
	for _, id := range strays {
		add("deferred id %s is not a %s item", id, LatestKISAEdition)
	}
	return out
}

// lintShellValidScreen is R126 as a rule (M-4). accounts.users[].shell_valid
// is false for a shell /etc/shells does not list, so a host where /etc/shells
// could not be read reports every account as invalid -- or, with the judgment
// inverted, as fine. The clause that judges shell_valid must be preceded, in
// the same list, by a { fact: accounts.shells, op: present } screen, which
// turns an unreadable /etc/shells into ERROR before any row is examined
// (system_account_shells.yaml is the shape).
//
// It runs over every clause list a control has -- applies_when, checks, and
// each mechanism's when and checks (M-38) -- because the hazard is the same
// in all of them: in applies_when an unreadable /etc/shells would make the
// control a silent NOT_APPLICABLE instead of the ERROR R126 wanted. The
// finding is a property of the list, so a list is reported once however many
// unscreened clauses it holds.
func lintShellValidScreen(cls []Clause, add func(string, string, ...any), where string) {
	for _, cl := range cls {
		if cl.Fact == "accounts.shells" && cl.Op == "present" {
			return
		}
		for _, sub := range []*Clause{cl.Where, cl.Require} {
			if sub != nil && sub.Field == "shell_valid" {
				add("shell_valid_screen", "%s: a clause on shell_valid needs an earlier { fact: accounts.shells, op: present } clause in the same list, or an unreadable /etc/shells is judged instead of reported", where)
				return
			}
		}
	}
}

// lintClause checks one top-level clause and, for collections, its
// sub-clauses, against the grammar of spec §6.3. screen says the clause sits
// in a list the evaluator reads for Holds alone -- applies_when or a
// mechanism's when.
func lintClause(c *Control, cl Clause, reg *facts.Registry, add func(string, string, ...any), where string, screen bool) {
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
		// EV-4: a screen's outcome is read for Holds alone (eval.go), so a
		// selection that matched nothing would silently apply the control or
		// choose the mechanism, and an M-5 missing field would silently skip
		// it -- neither with the reason a judged clause would carry.
		if screen {
			add("clause_grammar", "%s: each/none are only valid under checks — a screen cannot carry a vacuous or missing-field outcome", where)
		}
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

// DirExists reports whether dir is a directory the CLI can lint against --
// the fixtures, and the KISA inventory the cross-check needs. A missing
// directory is an error there (R35), never a silently skipped rule.
func DirExists(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}

// The fact-key report -- CollectorUsage, FactUsage and the UnusedKeys
// wrapper over it, with the engineReadKeys list they all rest on -- lives in
// usage.go.
