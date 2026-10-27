package controls

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/cisindex"
	"github.com/kun9497/muster/internal/facts"
)

// cisBenchmarkRE is the shape of a CIS benchmark name in references.cis.
var cisBenchmarkRE = regexp.MustCompile(`^[a-z0-9]+$`)

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
	backupPathRe    = regexp.MustCompile(`^/[A-Za-z0-9._@:+/-]+$`)
	unitRe          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*(@[A-Za-z0-9._:-]+)?\.(service|socket)$`)
	modesEntryRe    = regexp.MustCompile(`^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`)
	sysctlKeyRe     = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`)
	moduleNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	paramNameRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	pVarRe          = regexp.MustCompile(`\$\{?P_([A-Za-z0-9_]+)`)

	categories       = []string{"account", "file", "service", "patch", "log", "beyond"}
	validCategory    = set(categories...)
	validImportance  = set("상", "중", "하")
	validAutomation  = set("auto", "partial", "manual", "not_applicable")
	validAbsentMeans = set("pass", "fail", "not_applicable", "manual")
	validRisk        = set("none", "restart_service", "reboot_required", "lockout_risk")
	validOn          = set("runtime", "persisted", "effective", "both")
	validPersona     = set("root", "user", "invalid")
	validParamType   = set("string", "int", "bool", "list<string>", "list<int>")
	scalarOps        = set("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "matches", "not_matches", "contains", "not_contains", "present", "absent")
	orderedOps       = set("lt", "lte", "gt", "gte")
	collectionOps    = set("each", "none")
)

// ValidControlID reports whether id is a well-formed control id --
// muster.<area>.<name>, lowercase (spec §6.2). It is the same rule the
// id_format lint applies, exported so controls new can refuse a bad id
// before it writes a file the lint would then reject.
func ValidControlID(id string) bool { return idRe.MatchString(id) }

// ValidUnitName reports whether u is a unit name a remediation may declare
// (3D-2b §3): it starts with a letter or digit, carries a non-empty instance
// if it is a template, and ends .service or .socket. The review script puts
// it on a command line, so remedy.Build checks it again.
func ValidUnitName(u string) bool { return unitRe.MatchString(u) }

// ValidParamName reports whether n can name a P_<n> block variable (3D-2c S-1).
func ValidParamName(n string) bool { return paramNameRe.MatchString(n) }

// ValidBackupPath reports whether p is an absolute clean path in the charset
// the review script carries (the backup lint's rule; remedy.Build re-checks it).
func ValidBackupPath(p string) bool { return backupPathRe.MatchString(p) && path.Clean(p) == p }

// modesBase splits a modes entry into its base path and its number of /*
// segments.
func modesBase(e string) (string, int) {
	k := 0
	for k < 2 && strings.HasSuffix(e, "/*") {
		e, k = strings.TrimSuffix(e, "/*"), k+1
	}
	return e, k
}

// ValidModesEntry reports whether e is an absolute clean path followed by at
// most two /* segments (3D-2c E-3, S-7).
func ValidModesEntry(e string) bool {
	if !modesEntryRe.MatchString(e) {
		return false
	}
	base, _ := modesBase(e)
	return base != "/" && path.Clean(base) == base
}

// ValidSysctlKey reports whether k is a dotted kernel key (3D-2c E-3).
func ValidSysctlKey(k string) bool { return sysctlKeyRe.MatchString(k) }

// ValidModuleName reports whether m is a module name the helpers carry.
func ValidModuleName(m string) bool { return moduleNameRe.MatchString(m) }

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

func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// oneLine trims one trailing newline (a YAML block scalar's) and reports
// whether a line break is left.
func oneLine(s string) bool { return !strings.ContainsAny(strings.TrimSuffix(s, "\n"), "\r\n") }

func lintRemediation(c *Control, add func(rule, format string, args ...any)) {
	r := c.Remediation
	if !validRisk[r.Risk] {
		add("remediation", "unknown remediation risk %q", r.Risk)
	}
	for _, tx := range []struct{ name, v string }{{"text_en", r.TextEn}, {"text_ko", r.TextKo}} {
		switch {
		case strings.TrimSpace(tx.v) == "":
			add("remediation", "%s is blank", tx.name)
		case hasControlRune(tx.v):
			add("remediation", "%s carries a line break or control character", tx.name)
		case utf8.RuneCountInString(tx.v) > 1000:
			add("remediation", "%s is longer than 1000 runes", tx.name)
		}
	}
	for _, body := range []struct{ name, v string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
		if body.v == "" {
			continue // empty reads as absent
		}
		if strings.TrimSpace(body.v) == "" {
			add("remediation", "%s is blank", body.name)
		}
		if strings.Contains(body.v, "<<") {
			add("remediation", "%s carries a here-document", body.name)
		}
	}
	hasScript := strings.TrimSpace(r.Script) != ""
	hasState := len(r.Modes) > 0 || len(r.Sysctl) > 0 || len(r.Modules) > 0
	if hasScript && !r.Idempotent {
		add("remediation", "script requires idempotent: true")
	}
	if hasScript && strings.TrimSpace(r.Rollback) == "" && len(r.Backup) == 0 && len(r.Units) == 0 && !hasState {
		add("remediation", "script without rollback, backup, units, modes, sysctl or modules")
	}
	if hasScript && r.Validate == "" {
		add("script_needs_validate", "script without validate")
	}
	if len(r.Units) > 0 && !hasScript {
		add("units_needs_script", "units without script")
	}
	if hasState && !hasScript {
		add("state_needs_script", "modes, sysctl or modules without script")
	}
	if len(r.ScriptParams) > 0 && !hasScript {
		add("script_params_needs_script", "script_params without script")
	}
	if r.ScriptOnAbsent && !hasScript {
		add("script_on_absent_needs_script", "script_on_absent without script")
	}
	if len(r.Units) > 0 {
		for _, x := range []struct {
			name string
			has  bool
		}{{"rollback", strings.TrimSpace(r.Rollback) != ""}, {"backup", len(r.Backup) > 0}, {"modes", len(r.Modes) > 0}, {"sysctl", len(r.Sysctl) > 0}, {"modules", len(r.Modules) > 0}} {
			if x.has {
				add("units_exclusive", "units excludes %s: the unit state is the way back", x.name)
			}
		}
	}
	usesUnits := func(s string) bool { return strings.Contains(s, "$UNITS") || strings.Contains(s, "${UNITS") }
	if usesUnits(r.Script) && len(r.Units) == 0 {
		add("units_variable", "script uses $UNITS without units")
	}
	if usesUnits(r.Validate) {
		add("units_variable", "validate uses $UNITS, which only the script subshell sets")
	}
	if usesUnits(r.Rollback) {
		add("units_variable", "rollback uses $UNITS, which only the script subshell sets")
	}
	seenUnit, pos := map[string]bool{}, map[string]int{}
	for i, u := range r.Units {
		if !unitRe.MatchString(u) {
			add("units_charset", "unit %q is not a unit name a script can carry", u)
		}
		if seenUnit[u] {
			add("units_charset", "unit %q is repeated", u)
		}
		seenUnit[u] = true
		pos[u] = i
	}
	for _, u := range r.Units {
		if stem, ok := strings.CutSuffix(u, ".service"); ok {
			if j, has := pos[stem+".socket"]; has && j > pos[u] {
				add("units_order", "%s.socket must precede %s", stem, u)
			}
		}
	}
	if !hasScript && len(r.Backup) > 0 {
		add("remediation", "backup without script")
	}
	if !hasScript && r.Validate != "" {
		add("remediation", "validate without script")
	}
	if r.Validate != "" && !oneLine(r.Validate) {
		add("remediation", "validate must be one line")
	}
	lintScriptParams(c, add)
	lintStateEntries(r, add)
	seen := map[string]bool{}
	for _, p := range r.Backup {
		switch {
		case !strings.HasPrefix(p, "/"):
			add("remediation", "backup path %q is not absolute", p)
		case path.Clean(p) != p:
			add("remediation", "backup path %q is not clean", p)
		case !backupPathRe.MatchString(p):
			add("remediation", "backup path %q carries a character the script cannot carry", p)
		}
		if seen[p] {
			add("remediation", "backup path %q is repeated", p)
		}
		seen[p] = true
	}
}

// lintScriptParams holds script_params to the control's declared params and
// to the bodies that read them (3D-2c E-1).
func lintScriptParams(c *Control, add func(rule, format string, args ...any)) {
	r := c.Remediation
	declared := map[string]bool{}
	for _, n := range r.ScriptParams {
		switch {
		case !ValidParamName(n):
			add("script_params_declared", "script param %q is not a parameter name", n)
			continue
		case declared[n]:
			add("script_params_declared", "script param %q is repeated", n)
			continue
		}
		declared[n] = true
		p, ok := c.Params[n]
		if !ok {
			add("script_params_declared", "script param %q is not a declared parameter", n)
			continue
		}
		if _, safe := ScriptParamValue(p.Type, p.Default); !safe {
			add("script_params_default_safe", "script param %q default %v cannot be carried by a script", n, p.Default)
		}
	}
	usedInScript := map[string]bool{}
	for _, b := range []struct{ name, v string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
		for _, m := range pVarRe.FindAllStringSubmatch(b.v, -1) {
			if b.name == "script" {
				usedInScript[m[1]] = true
			}
			if !declared[m[1]] {
				add("script_params_used", "%s uses $P_%s, which script_params does not declare", b.name, m[1])
			}
		}
	}
	for _, n := range r.ScriptParams {
		if declared[n] && !usedInScript[n] {
			add("script_params_used", "script param %q is not used in script", n)
		}
	}
}

// lintStateEntries checks the modes, sysctl and modules lists (3D-2c E-3).
func lintStateEntries(r *Remediation, add func(rule, format string, args ...any)) {
	seen := map[string]bool{}
	for _, e := range r.Modes {
		if !ValidModesEntry(e) {
			add("modes_charset", "modes entry %q is not an absolute clean path with at most two /* segments", e)
		}
		if seen[e] {
			add("modes_charset", "modes entry %q is repeated", e)
		}
		seen[e] = true
		base, k := modesBase(e)
		for _, b := range r.Backup {
			rest, under := strings.CutPrefix(b, base+"/")
			if (k == 0 && b == base) || (k > 0 && under && strings.Count(rest, "/") == k-1) {
				add("modes_backup_overlap", "backup path %q is also covered by modes entry %q", b, e)
			}
		}
	}
	for _, x := range []struct {
		rule, kind string
		list       []string
		valid      func(string) bool
	}{{"sysctl_charset", "sysctl key", r.Sysctl, ValidSysctlKey}, {"modules_charset", "module", r.Modules, ValidModuleName}} {
		seen := map[string]bool{}
		for _, v := range x.list {
			if !x.valid(v) {
				add(x.rule, "%s %q is not one a script can carry", x.kind, v)
			}
			if seen[v] {
				add(x.rule, "%s %q is repeated", x.kind, v)
			}
			seen[v] = true
		}
	}
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
		for _, tt := range []struct{ name, v string }{{"title_en", c.TitleEn}, {"title_ko", c.TitleKo}} {
			if hasControlRune(tt.v) {
				add("titles", "%s carries a line break or control character", tt.name)
			}
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
		if c.Remediation != nil {
			lintRemediation(c, add)
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
		// B-9/K-10, the half that needs no inventory: a control filed beyond
		// the guide that also claims a KISA item contradicts itself on its
		// own evidence, and the report's two scopes would then overlap. The
		// converse -- a guide control that claims nothing -- is a statement
		// about coverage and lives in lintKISACoverage, which runs only where
		// a caller offered an inventory.
		if c.Category == "beyond" && citesKISA(c) {
			add("beyond_scope", "category beyond means this control implements no KISA item, but it cites %s; drop references.kisa or give it the category of the item", strings.Join(citedKISA(c), ", "))
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
		seenCIS := map[string]bool{}
		for _, r := range c.References.CIS {
			switch {
			case r.Benchmark == "" || r.Version == "" || r.Rec == "":
				add("references_cis", "cis references need benchmark, version and rec")
			case !cisBenchmarkRE.MatchString(r.Benchmark):
				add("references_cis", "cis reference benchmark %q must look like ubuntu2204", r.Benchmark)
			case !cisindex.ValidRec(r.Rec):
				add("references_cis", "cis reference rec %q must look like 5.1.20", r.Rec)
			case opts.References != nil:
				product, alias, ok := opts.References.CISProduct(r.Benchmark)
				switch {
				case !ok:
					add("references_cis", "cis benchmark %q is not in %s", r.Benchmark, filepath.Join(opts.References.Dir, "cis"))
				case alias:
					add("references_cis", "cis benchmark %s is an alias of %s; write %s", r.Benchmark, product, product)
				case !opts.References.HasCIS(product, r.Version, r.Rec):
					add("references_cis", "cis reference %s@%s %s is not in %s", r.Benchmark, r.Version, r.Rec, filepath.Join(opts.References.Dir, "cis"))
				}
			}
			if r.Benchmark != "" && r.Version != "" && r.Rec != "" {
				k := r.Benchmark + "|" + r.Version + "|" + r.Rec
				if seenCIS[k] {
					add("references_cis", "cis reference %s@%s %s is listed twice", r.Benchmark, r.Version, r.Rec)
				}
				seenCIS[k] = true
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

// citedKISA returns every KISA item c cites, across every edition, sorted and
// deduplicated so the beyond_scope message is the same bytes on every run
// (references.kisa is a map, whose iteration order Go randomises).
func citedKISA(c *Control) []string {
	seen := map[string]bool{}
	for _, items := range c.References.KISA {
		for _, it := range items {
			seen[it] = true
		}
	}
	out := make([]string, 0, len(seen))
	for it := range seen {
		out = append(out, it)
	}
	sort.Strings(out)
	return out
}

// citesKISA reports whether c claims any KISA item at all. An empty list
// under an edition key claims nothing, so it counts as no reference: the
// scope predicate must agree with the report's, which asks what the control
// implements, not which keys its YAML happens to carry.
func citesKISA(c *Control) bool { return len(citedKISA(c)) > 0 }

func paramDefaultMatches(p Param) bool { return CheckParamValue(p.Type, p.Default) == nil }

// lintKISACoverage is the set-level half of M-2: coverage is a property of
// the whole set, not of any one file, so its problems carry no control id and
// no path. Every item of the current edition is implemented by at least one
// control or listed in kisa_deferred.json -- an item cited by nobody and not
// deferred, and a deferral a control has since implemented, are each an error
// naming the ids. W-10: more than one control per item is allowed, because an
// item such as U-23 covers setuid, setgid and sticky, whose remediations and
// waivers have nothing to do with each other. One control listing an id twice
// is still a per-control references_kisa problem (M-39). Only the current
// edition is judged (M-26).
//
// It also carries the converse half of beyond_scope (B-9, K-10), for the
// reason stated at that loop: it is an offence only where an inventory was
// offered.
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
	var out []Problem
	// B-9/K-10, the converse half: a control that is not beyond the guide
	// must implement an item of it. It lives here rather than with the
	// per-control rules because "claims nothing" is only an offence where
	// somebody offered the guide to compare against -- a set linted for shape
	// alone, which is what the mutation test and most unit tests do, carries
	// no references at all and is not wrong for it. The problem still names
	// the control and its file: it is that file that has to change.
	for i := range s.Controls {
		c := &s.Controls[i]
		if c.Category != "beyond" && !citesKISA(c) {
			out = append(out, Problem{ControlID: c.ID, Path: c.Path, Rule: "beyond_scope",
				Message: fmt.Sprintf("category %q means this control implements a KISA item, but it cites none; add references.kisa or give it category beyond", c.Category)})
		}
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
	add := func(format string, args ...any) {
		out = append(out, Problem{Rule: "kisa_coverage", Message: fmt.Sprintf(format, args...)})
	}
	var stale, uncited []string
	for _, it := range x.Items[LatestKISAEdition] {
		n, deferred := len(citedBy[it.ID]), x.IsDeferred(it.ID)
		if n == 0 && !deferred {
			uncited = append(uncited, it.ID)
		}
		if n > 0 && deferred {
			stale = append(stale, it.ID)
		}
	}
	sort.Strings(stale)
	sort.Strings(uncited)
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
		// Spec §5: a record element has no name of its own, so without subject
		// every observation and every waiver falls back to the element's index
		// in a list whose order is the collector's, not the host's. A scalar
		// element IS its name, so the rule is record-lists only.
		//
		// What the rule requires is a DELIBERATE choice of naming field, not a
		// non-positional one: where a record carries no stable identifier, a
		// positional field is the right subject. env.shell.root_path_entries
		// is the case -- a PATH element's value is empty for the "." entry the
		// control exists to catch and may repeat, so `subject: position` names
		// it, and the order is root's PATH rather than the collector's.
		if cl.Op == "none" && entry.Type == "list<record>" && cl.Subject == "" {
			add("none_subject", "%s: none on %s (list<record>) needs subject so observations and waivers can name the element", where, cl.Fact)
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
