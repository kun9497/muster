package controls

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

func lintOne(t *testing.T, yamlText string, opts LintOptions) []Problem {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("t+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "account"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account", "c.yaml"), []byte(yamlText), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return Lint(set, reg, opts)
}

func rules(ps []Problem) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.Rule] = true
	}
	return m
}

const goodControl = `id: muster.account.good
title_en: Good
title_ko: 좋음
description_en: d
description_ko: 설명
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-01"] }
  cis: [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]
requires_facts: ">=1"
absent_means: not_applicable
params:
  allowed: { type: list<string>, default: ["no"], description: d }
checks:
  - { fact: sshd.options.permit_root_login, on: effective, persona: root, op: in, expected: "${allowed}" }
remediation: { text_en: t, text_ko: 조치, risk: lockout_risk, idempotent: true }
`

func TestLintCleanControlHasNoProblems(t *testing.T) {
	if ps := lintOne(t, goodControl, LintOptions{}); len(ps) != 0 {
		t.Fatalf("unexpected problems: %v", ps)
	}
}

func TestLintRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		rule string
	}{
		{"bad id", `id: U-01
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
`, "id_format"},
		{"manual without reason", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
`, "manual_reason"},
		{"auto without remediation", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
`, "remediation"},
		{"unregistered fact", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: nope.key, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "fact_key"},
		{"present with expected", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: present, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"bad regex", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: files.etc_securetty_lines, op: none, where: { op: matches, expected: "(" } }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"on without setting", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, on: runtime, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"undeclared param", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: "${nope}" }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "param"},
		{"kisa ref format", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
references: { kisa: { "2026": ["U-1"] } }
`, "references_kisa"},
		{"missing absent_means", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "absent_means"},
		{"two judgments", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
custom: Whatever
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "judgment"},
		{"sub-clause param not declared", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
requires_facts: ">=1"
checks: [{ fact: walk.world_writable, op: each, subject: path, require: { field: package_declared, op: eq, expected: "${nope}" } }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "param"},
		{"record element sub-clause needs field", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
requires_facts: ">=1"
checks: [{ fact: walk.world_writable, op: each, subject: path, require: { op: eq, expected: true } }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"scalar element sub-clause has no field", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
requires_facts: ">=1"
checks: [{ fact: files.etc_securetty_lines, op: none, where: { field: something, op: matches, expected: "^pts/" } }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"missing title_ko", `id: muster.account.x
title_en: t
category: account
importance: 상
automation: manual
manual_reason: r
requires_facts: ">=1"
`, "titles"},
		{"bad category", `id: muster.account.x
title_en: t
title_ko: 제목
category: bogus
importance: 상
automation: manual
manual_reason: r
requires_facts: ">=1"
`, "category"},
		{"bad importance", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: high
automation: manual
manual_reason: r
requires_facts: ">=1"
`, "importance"},
		{"bad automation", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: maybe
requires_facts: ">=1"
`, "automation"},
		{"missing requires_facts", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
`, "requires_facts"},
		{"cis missing rec", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
requires_facts: ">=1"
references: { cis: [{ benchmark: ubuntu-22.04, version: "2.0.0" }] }
`, "references_cis"},
		{"unknown custom func", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
requires_facts: ">=1"
custom: NotRegistered
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "custom_func"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rules(lintOne(t, c.yaml, LintOptions{CustomFuncs: map[string]bool{}}))
			if !got[c.rule] {
				t.Fatalf("want rule %q among %v", c.rule, got)
			}
		})
	}
}

// R114: list<int> params default-check every element as an integer, the
// same way the int case checks a scalar default.
func TestLintListIntParamDefaultMustBeAllIntegers(t *testing.T) {
	bad := `id: muster.file.list_int_test
title_en: t
title_ko: t
description_en: d
description_ko: d
category: file
importance: 상
automation: auto
references: { kisa: { "2026": ["U-19"] } }
requires_facts: ">=1"
absent_means: fail
params:
  allowed_modes: { type: list<int>, default: [0, "128"], description: d }
checks:
  - { fact: files.etc_hosts.mode, op: in, expected: "${allowed_modes}" }
remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }
`
	if r := rules(lintOne(t, bad, LintOptions{})); !r["param"] {
		t.Errorf("list<int> default with a non-integer element must be a param problem: %v", r)
	}
	good := strings.Replace(bad, `default: [0, "128"]`, `default: [0, 128]`, 1)
	if ps := lintOne(t, good, LintOptions{}); len(ps) != 0 {
		t.Fatalf("all-integer list<int> default must lint clean: %v", ps)
	}
}

func TestLintAcceptsNotMatchesWithAPatternAndRejectsItOnLists(t *testing.T) {
	ok := `
id: muster.file.banner_test
title_en: t
title_ko: t
description_en: d
description_ko: d
category: file
importance: 하
automation: auto
references: { kisa: { "2026": ["U-53"] } }
requires_facts: ">=1"
absent_means: pass
checks:
  - { fact: sshd.collect_method, op: not_matches, expected: "(?i)parse" }
remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }
`
	if r := rules(lintOne(t, ok, LintOptions{})); len(r) != 0 {
		t.Fatalf("not_matches with a pattern must lint clean: %v", r)
	}
	bad := strings.Replace(ok, `expected: "(?i)parse"`, `expected: 3`, 1)
	if r := rules(lintOne(t, bad, LintOptions{})); !r["clause_grammar"] {
		t.Errorf("not_matches without a string pattern must be a clause_grammar problem: %v", r)
	}
	onList := strings.Replace(ok, "fact: sshd.collect_method", "fact: files.etc_securetty_lines", 1)
	if r := rules(lintOne(t, onList, LintOptions{})); !r["clause_grammar"] {
		t.Errorf("not_matches on a list fact must be a clause_grammar problem: %v", r)
	}
}

// M13: lint ranges over c.Params and References.KISA, whose iteration order
// Go randomises, and sorted only on (path, rule) -- so two problems sharing a
// rule came out in a different order on every run.
func TestLintProblemOrderIsDeterministic(t *testing.T) {
	const twoOfEachRule = `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
requires_facts: ">=1"
references:
  kisa: { "2026": ["U-1"], "2021": ["U-2"] }
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("t+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "account"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account", "c.yaml"), []byte(twoOfEachRule), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		var b strings.Builder
		for _, p := range Lint(set, reg, LintOptions{}) {
			b.WriteString(p.String())
			b.WriteString("\n")
		}
		return b.String()
	}
	want := render()
	if strings.Count(want, "references_kisa") != 2 {
		t.Fatalf("the fixture must produce two problems of one rule:\n%s", want)
	}
	for i := 0; i < 200; i++ {
		if got := render(); got != want {
			t.Fatalf("lint output differs between runs:\n--- want ---\n%s--- got ---\n%s", want, got)
		}
	}
}

// R35: spec §5.5 -- lint reports registered keys no control uses. It is a
// note, not a failure: some keys are read by the evaluator itself.
func TestUnusedKeysNamesRegisteredKeysNoControlReferences(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range UnusedKeys(set, reg) {
		got[k] = true
	}
	for _, k := range []string{"sockets.listening", "accounts.groups", "services.ssh.active"} {
		if !got[k] {
			t.Errorf("%s is referenced by no control and must be reported", k)
		}
	}
	for _, k := range []string{"services.telnet.reachable", "files.etc_securetty_lines", "walk.world_writable", "accounts.users", "accounts.shadow_in_use", "accounts.orphan_gids", "accounts.shells"} {
		if got[k] {
			t.Errorf("%s is referenced by a control and must not be reported", k)
		}
	}
}

func TestLintValidatesSTIGAndNISTReferencesAgainstTheIndex(t *testing.T) {
	x, err := LoadReferenceIndex("testdata/refs")
	if err != nil {
		t.Fatal(err)
	}
	base := `
id: muster.file.ref_test
title_en: t
title_ko: t
description_en: d
description_ko: d
category: file
importance: 하
automation: auto
references:
  kisa: { "2026": ["U-19"] }
  stig: [{ benchmark: mini, version: V1R1, id: MINI-00-000010 }]
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: files.etc_hosts.uid, op: eq, expected: 0 }
remediation: { text_en: t, text_ko: t, risk: none, idempotent: true }
`
	if probs := lintOne(t, base, LintOptions{References: x}); len(probs) != 0 {
		t.Fatalf("valid references must lint clean: %v", probs)
	}
	cases := map[string]string{
		"unknown benchmark": strings.Replace(base, "benchmark: mini", "benchmark: nope", 1),
		"wrong version":     strings.Replace(base, "version: V1R1", "version: V9R9", 1),
		"unknown id":        strings.Replace(base, "MINI-00-000010", "MINI-00-777777", 1),
		"nist not indexed":  strings.Replace(base, `["CM-6"]`, `["AC-99"]`, 1),
		"nist bad format":   strings.Replace(base, `["CM-6"]`, `["cm6"]`, 1),
	}
	for name, y := range cases {
		got := rules(lintOne(t, y, LintOptions{References: x}))
		if !got["references_stig"] && !got["references_nist"] {
			t.Errorf("%s: want a references problem, got %v", name, got)
		}
	}
	if probs := lintOne(t, base, LintOptions{References: nil}); len(probs) != 0 {
		t.Errorf("without an index a well-formed reference must lint clean, got %v", probs)
	}
	malformed := strings.Replace(base, "MINI-00-000010", "RHEL 9 bad", 1)
	if got := rules(lintOne(t, malformed, LintOptions{References: nil})); !got["references_stig"] {
		t.Errorf("without an index a malformed stig id must still be a problem, got %v", got)
	}
}

func TestLintFixturePairRule(t *testing.T) {
	fx := t.TempDir()
	os.MkdirAll(filepath.Join(fx, "muster.account.good"), 0o755)
	os.WriteFile(filepath.Join(fx, "muster.account.good", "pass-one.json"), []byte("{}"), 0o644)
	ps := lintOne(t, goodControl, LintOptions{FixtureDir: fx})
	if !rules(ps)["fixtures"] {
		t.Fatalf("missing fail fixture must be reported: %v", ps)
	}
	os.WriteFile(filepath.Join(fx, "muster.account.good", "fail-one.json"), []byte("{}"), 0o644)
	if ps := lintOne(t, goodControl, LintOptions{FixtureDir: fx}); len(ps) != 0 {
		t.Fatalf("unexpected: %v", ps)
	}
}

// lintSet lints a set built from several control files, which is what the
// set-level rules (kisa_coverage) need.
func lintSet(t *testing.T, opts LintOptions, yamlTexts ...string) []Problem {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("t+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "account"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, y := range yamlTexts {
		name := fmt.Sprintf("c%d.yaml", i)
		if err := os.WriteFile(filepath.Join(dir, "account", name), []byte(y), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return Lint(set, reg, opts)
}

// messagesOf returns the messages of every problem carrying rule.
func messagesOf(ps []Problem, rule string) []string {
	var out []string
	for _, p := range ps {
		if p.Rule == rule {
			out = append(out, p.Message)
		}
	}
	return out
}

// hasMessage reports whether any message of rule contains every fragment.
func hasMessage(ps []Problem, rule string, fragments ...string) bool {
	for _, m := range messagesOf(ps, rule) {
		all := true
		for _, f := range fragments {
			if !strings.Contains(m, f) {
				all = false
			}
		}
		if all {
			return true
		}
	}
	return false
}

// M-2: every id under references.kisa["<year>"] must exist in that edition's
// inventory, and an edition muster has no inventory file for is an error
// rather than an unchecked citation.
func TestLintKISAReferenceMustExistInTheEdition(t *testing.T) {
	inv := mustLoadKISA(t)

	unknownID := strings.Replace(goodControl, `"2026": ["U-01"]`, `"2026": ["U-99"]`, 1)
	ps := lintOne(t, unknownID, LintOptions{KISA: inv})
	if !hasMessage(ps, "references_kisa", "U-99", "2026") {
		t.Errorf("an id absent from the edition must be a references_kisa problem naming it and the edition: %v", messagesOf(ps, "references_kisa"))
	}

	unknownYear := strings.Replace(goodControl, `"2026": ["U-01"]`, `"1999": ["U-01"]`, 1)
	ps = lintOne(t, unknownYear, LintOptions{KISA: inv})
	if !hasMessage(ps, "references_kisa", "1999") {
		t.Errorf("an edition with no inventory must be a references_kisa problem naming it: %v", messagesOf(ps, "references_kisa"))
	}

	if ps := lintOne(t, goodControl, LintOptions{KISA: inv}); len(messagesOf(ps, "references_kisa")) != 0 {
		t.Errorf("a cited id that is in the edition must lint clean: %v", messagesOf(ps, "references_kisa"))
	}
}

// M-2: the R117 class of bug -- a control whose importance disagrees with the
// KISA item it claims to implement -- is caught by the lint, not by a reader.
func TestLintKISAImportanceMustMatchTheInventory(t *testing.T) {
	inv := mustLoadKISA(t)

	if ps := lintOne(t, goodControl, LintOptions{KISA: inv}); len(messagesOf(ps, "kisa_importance")) != 0 {
		t.Errorf("importance 상 on a control citing U-01 (상) must lint clean: %v", messagesOf(ps, "kisa_importance"))
	}

	mismatched := strings.Replace(goodControl, "importance: 상", "importance: 하", 1)
	ps := lintOne(t, mismatched, LintOptions{KISA: inv})
	if !hasMessage(ps, "kisa_importance", "하", "상", "U-01") {
		t.Errorf("a mismatch must name the control's importance, the inventory's and the id: %v", messagesOf(ps, "kisa_importance"))
	}
}

// M-2: coverage is a property of the whole set, so the problem carries no
// control id and no path, and String() says so.
func TestLintKISACoverageIsSetLevel(t *testing.T) {
	inv := mustLoadKISA(t)
	second := strings.Replace(goodControl, "id: muster.account.good", "id: muster.account.good_twin", 1)

	ps := lintSet(t, LintOptions{KISA: inv}, goodControl, second)
	if !hasMessage(ps, "kisa_coverage", "U-01 is cited by 2 controls") {
		t.Errorf("an item cited twice must be reported: %v", messagesOf(ps, "kisa_coverage"))
	}
	found := false
	for _, p := range ps {
		if p.Rule != "kisa_coverage" {
			continue
		}
		found = true
		if p.ControlID != "" || p.Path != "" {
			t.Errorf("a set-level problem must carry no control id and no path: %+v", p)
		}
		if got, want := p.String(), "controls: kisa_coverage: "+p.Message; got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
	if !found {
		t.Fatal("no kisa_coverage problem at all")
	}

	ps = lintSet(t, LintOptions{KISA: inv}, goodControl)
	if !hasMessage(ps, "kisa_coverage", "U-02", "U-67") {
		t.Errorf("items no control cites must be listed: %v", messagesOf(ps, "kisa_coverage"))
	}
	for _, m := range messagesOf(ps, "kisa_coverage") {
		if strings.Contains(m, "U-15") {
			t.Errorf("a deferred item must not be reported as uncited: %q", m)
		}
	}

	deferredCited := strings.Replace(goodControl, `"2026": ["U-01"]`, `"2026": ["U-15"]`, 1)
	ps = lintSet(t, LintOptions{KISA: inv}, deferredCited)
	if !hasMessage(ps, "kisa_coverage", "U-15", "muster.account.good") {
		t.Errorf("a stale deferral must name the item and the control citing it: %v", messagesOf(ps, "kisa_coverage"))
	}
}

// G-3: LoadKISA is what fills the index Item and HasEdition answer from, so a
// hand-built KISAInventory answers "no 2026 edition" -- and the coverage rule
// used to return silently, turning the whole set-level gate off with nothing
// said. A caller that passes an inventory is asking for the cross-check; if it
// cannot run, that is a problem, not a pass. A nil KISA still means shape-only.
func TestLintReportsAnInventoryWithoutTheCurrentEdition(t *testing.T) {
	handBuilt := &KISAInventory{Items: map[string][]KISAItem{LatestKISAEdition: {{ID: "U-01"}}}}
	ps := lintSet(t, LintOptions{KISA: handBuilt}, goodControl)
	if !hasMessage(ps, "kisa_coverage", "no "+LatestKISAEdition+" edition") {
		t.Errorf("an inventory the coverage rule cannot run on must say so: %v", messagesOf(ps, "kisa_coverage"))
	}
	if got := len(messagesOf(ps, "kisa_coverage")); got != 1 {
		t.Errorf("want exactly one kisa_coverage problem, got %d: %v", got, messagesOf(ps, "kisa_coverage"))
	}
	// Shape-only linting (no inventory at all) is unchanged.
	for _, m := range messagesOf(lintSet(t, LintOptions{}, goodControl), "kisa_coverage") {
		t.Errorf("a nil inventory must run no coverage rule: %q", m)
	}
}

// G-9: the uncited-items message names ids, so it must agree in number with
// them -- a set one item short read "1 2026 items are cited by no control".
// A two-item inventory built through LoadKISA (the only thing that fills the
// edition index) gives exactly one uncited item; the real inventory gives the
// plural in TestLintKISACoverageIsSetLevel above.
func TestLintUncitedMessageAgreesInNumber(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("kisa_items_latest.json", `[{"id":"U-01","name_ko":"a","category":"account","importance":"상","page":1},
	  {"id":"U-02","name_ko":"b","category":"account","importance":"상","page":2}]`)
	write("kisa_items_2021.json", `[{"id":"U-01","name_ko":"a","category":"account","importance":"상","page":1}]`)
	write(kisaDeferredFile, `[]`)
	inv, err := LoadKISA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ms := messagesOf(lintSet(t, LintOptions{KISA: inv}, goodControl), "kisa_coverage")
	if len(ms) != 1 {
		t.Fatalf("want one kisa_coverage problem for the one uncited item, got %v", ms)
	}
	if !strings.Contains(ms[0], "1 2026 item is cited by no control") {
		t.Errorf("message %q must agree in number with the one id it names", ms[0])
	}
	if strings.Contains(ms[0], "items are") {
		t.Errorf("message %q still uses the plural", ms[0])
	}
}

// The gate: the embedded set must satisfy the cross-check against the
// committed inventory. Every 2026 item is enrolled exactly once or deferred.
func TestLintEmbeddedSetPassesTheKISACrossCheck(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range Lint(set, reg, LintOptions{KISA: mustLoadKISA(t)}) {
		t.Errorf("embedded set: %s", p)
	}
}

// A nil inventory keeps today's behaviour: references.kisa is checked for
// shape only, so the unit tests that build a one-control set stay clean.
func TestLintWithoutInventoryIsShapeOnly(t *testing.T) {
	unknownID := strings.Replace(goodControl, `"2026": ["U-01"]`, `"2026": ["U-99"]`, 1)
	if ps := lintOne(t, unknownID, LintOptions{}); len(ps) != 0 {
		t.Errorf("without an inventory a well-formed id must lint clean: %v", ps)
	}
	mismatched := strings.Replace(goodControl, "importance: 상", "importance: 하", 1)
	if ps := lintOne(t, mismatched, LintOptions{}); len(ps) != 0 {
		t.Errorf("without an inventory importance is not cross-checked: %v", ps)
	}
	if ps := lintSet(t, LintOptions{}, goodControl); len(ps) != 0 {
		t.Errorf("without an inventory there is no set-level coverage rule: %v", ps)
	}
}

const manualEvidenceControl = `id: muster.patch.evidence_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: patch
importance: 상
automation: manual
manual_reason: r
requires_facts: ">=1"
evidence: [patch.pending_security_count, patch.metadata_age_s]
`

// M-8: evidence: names the facts a reviewer needs in front of them for a
// manual call. It is only meaningful where muster declines to judge, and
// every key must be one the registry knows.
func TestLintEvidenceOnlyOnManualControlsAndRegistered(t *testing.T) {
	if ps := lintOne(t, manualEvidenceControl, LintOptions{}); len(ps) != 0 {
		t.Fatalf("registered evidence keys on a manual control must lint clean: %v", ps)
	}

	onAuto := `id: muster.patch.evidence_auto_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: patch
importance: 상
automation: auto
requires_facts: ">=1"
absent_means: fail
evidence: [patch.pending_security_count]
checks: [{ fact: patch.reboot_required, op: eq, expected: false }]
remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }
`
	ps := lintOne(t, onAuto, LintOptions{})
	if !hasMessage(ps, "evidence", "manual") {
		t.Errorf("evidence on an auto control must be a problem saying so: %v", messagesOf(ps, "evidence"))
	}

	unregistered := strings.Replace(manualEvidenceControl, "patch.metadata_age_s", "nope.key", 1)
	ps = lintOne(t, unregistered, LintOptions{})
	if !hasMessage(ps, "evidence", `"nope.key"`, "registered") {
		t.Errorf("an unregistered evidence key must be named: %v", messagesOf(ps, "evidence"))
	}
}

// M-4 (R126 as a rule): shell_valid is false for a shell /etc/shells does not
// list, so a denied /etc/shells would quietly turn every row into a pass. The
// screen clause must come first in the same list.
func TestLintShellValidNeedsTheShellsScreen(t *testing.T) {
	const screen = "  - { fact: accounts.shells, op: present }\n"
	const judge = "  - { fact: accounts.users, op: each, subject: name, where: { field: system, op: eq, expected: true }, require: { field: shell_valid, op: eq, expected: false } }\n"
	head := `id: muster.account.shell_screen_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: account
importance: 하
automation: auto
requires_facts: ">=1"
absent_means: fail
checks:
`
	tail := "remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }\n"

	if ps := lintOne(t, head+screen+judge+tail, LintOptions{}); len(ps) != 0 {
		t.Fatalf("the screened shape (system_account_shells.yaml) must lint clean: %v", ps)
	}
	ps := lintOne(t, head+judge+tail, LintOptions{})
	if !hasMessage(ps, "shell_valid_screen", "accounts.shells") {
		t.Errorf("an unscreened shell_valid clause must be a problem naming the screen fact: %v", messagesOf(ps, "shell_valid_screen"))
	}
	// The screen has to precede the judgment, not merely appear in the list.
	ps = lintOne(t, head+judge+screen+tail, LintOptions{})
	if !hasMessage(ps, "shell_valid_screen", "accounts.shells") {
		t.Errorf("a screen after the judgment must still be a problem: %v", messagesOf(ps, "shell_valid_screen"))
	}
	// where, not just require, names the field.
	whereForm := head + "  - { fact: accounts.users, op: none, where: { field: shell_valid, op: eq, expected: true } }\n" + tail
	if !hasMessage(lintOne(t, whereForm, LintOptions{}), "shell_valid_screen", "accounts.shells") {
		t.Error("a where clause on shell_valid must be screened too")
	}
	// A mechanism's checks list is its own list.
	indent := func(s string) string { return "    " + s }
	mech := `id: muster.account.shell_screen_mech_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: account
importance: 하
automation: auto
requires_facts: ">=1"
absent_means: fail
mechanisms:
  - when: [{ fact: services.ssh.installed, op: eq, expected: true }]
    checks:
` + indent(judge) + tail
	if !hasMessage(lintOne(t, mech, LintOptions{}), "shell_valid_screen", "accounts.shells") {
		t.Error("an unscreened shell_valid clause inside a mechanism must be a problem")
	}
	mechOK := strings.Replace(mech, "    checks:\n", "    checks:\n"+indent(screen), 1)
	if ps := lintOne(t, mechOK, LintOptions{}); len(ps) != 0 {
		t.Errorf("a screened mechanism must lint clean: %v", ps)
	}
}

// M-4: the message must name the index directory lint was actually given, so
// a run against a custom index does not send the reader to docs/reference.
func TestLintUnindexedMessageNamesTheIndexDir(t *testing.T) {
	x, err := LoadReferenceIndex(filepath.Join("testdata", "refs"))
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(goodControl, "requires_facts:", "  stig: [{ benchmark: mini, version: V1R1, id: MINI-00-777777 }]\nrequires_facts:", 1)
	ps := lintOne(t, bad, LintOptions{References: x})
	want := filepath.Join("testdata", "refs", "stig")
	if !hasMessage(ps, "references_stig", want) {
		t.Errorf("message must name %q: %v", want, messagesOf(ps, "references_stig"))
	}
	if hasMessage(ps, "references_stig", filepath.Join("docs", "reference", "stig")) {
		t.Errorf("message must not name the default index directory: %v", messagesOf(ps, "references_stig"))
	}
}

// M-37: a deferral naming something that is not a 2026 item excuses nothing
// and would sit in the file forever. It is reported per id, beside the other
// coverage offences, so the set-level rule stays one contract.
func TestLintKISACoverageNamesADeferralThatIsNotAnItem(t *testing.T) {
	dir := writeKISADir(t, map[string]string{"kisa_deferred.json": `[
	  {"id": "U-15", "stage": "3", "reason": "r"},
	  {"id": "U-98", "stage": "3", "reason": "r"},
	  {"id": "U-97", "stage": "3", "reason": "r"}
	]`})
	inv, err := LoadKISA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps := lintSet(t, LintOptions{KISA: inv}, goodControl)
	got := 0
	for _, m := range messagesOf(ps, "kisa_coverage") {
		if strings.Contains(m, "is not a 2026 item") {
			got++
		}
	}
	if got != 2 {
		t.Errorf("want one problem per stray deferral, got %d: %v", got, messagesOf(ps, "kisa_coverage"))
	}
	for _, want := range []string{"deferred id U-97 is not a 2026 item", "deferred id U-98 is not a 2026 item"} {
		if !hasMessage(ps, "kisa_coverage", want) {
			t.Errorf("want %q among %v", want, messagesOf(ps, "kisa_coverage"))
		}
	}
	// The committed list is clean, so the real inventory must not produce one.
	clean := lintSet(t, LintOptions{KISA: mustLoadKISA(t)}, goodControl)
	for _, m := range messagesOf(clean, "kisa_coverage") {
		if strings.Contains(m, "is not a 2026 item") {
			t.Errorf("the committed deferral list must be clean: %q", m)
		}
	}
}

// M-39: one control listing an id twice is a mistake in that control, not two
// controls claiming one item -- the coverage message used to say "cited by 2
// controls" and then name the same control twice.
func TestLintKISARepeatedReferenceIsNamedPerControl(t *testing.T) {
	inv := mustLoadKISA(t)
	twice := strings.Replace(goodControl, `"2026": ["U-01"]`, `"2026": ["U-01", "U-01"]`, 1)
	ps := lintSet(t, LintOptions{KISA: inv}, twice)
	if !hasMessage(ps, "references_kisa", "U-01 is listed twice under 2026") {
		t.Errorf("a repeated id must be a per-control problem: %v", messagesOf(ps, "references_kisa"))
	}
	for _, p := range ps {
		if p.Rule == "references_kisa" && strings.Contains(p.Message, "listed twice") && (p.ControlID == "" || p.Path == "") {
			t.Errorf("the repeat belongs to a control, not to the set: %+v", p)
		}
	}
	for _, m := range messagesOf(ps, "kisa_coverage") {
		if strings.Contains(m, "is cited by") {
			t.Errorf("one control citing an id twice is not two controls: %q", m)
		}
	}
	// Two controls really claiming one item is still reported.
	second := strings.Replace(goodControl, "id: muster.account.good", "id: muster.account.good_twin", 1)
	both := lintSet(t, LintOptions{KISA: inv}, goodControl, second)
	if !hasMessage(both, "kisa_coverage", "U-01 is cited by 2 controls") {
		t.Errorf("two controls claiming one item must still be reported: %v", messagesOf(both, "kisa_coverage"))
	}
}

// M-38: the hazard is identical wherever a clause judges shell_valid -- in
// applies_when an unreadable /etc/shells turns the whole control into a
// silent NOT_APPLICABLE instead of the ERROR R126 wanted.
func TestLintShellValidScreenCoversEveryClauseList(t *testing.T) {
	const judge = "  - { fact: accounts.users, op: none, where: { field: shell_valid, op: eq, expected: true } }\n"
	const screen = "  - { fact: accounts.shells, op: present }\n"
	head := `id: muster.account.shell_screen_lists_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: account
importance: 하
automation: auto
requires_facts: ">=1"
absent_means: fail
`
	body := `checks:
  - { fact: accounts.shells, op: present }
  - { fact: services.ssh.installed, op: eq, expected: true }
remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }
`
	// applies_when is its own list: a screen in checks does not cover it.
	appliesWhen := head + "applies_when:\n" + judge + body
	if !hasMessage(lintOne(t, appliesWhen, LintOptions{}), "shell_valid_screen", "applies_when") {
		t.Error("an unscreened shell_valid clause in applies_when must be a problem")
	}
	// EV-4 refuses a collection op in a screen whatever it selects on, so this
	// construct now also carries a clause_grammar problem; what is asserted
	// here is the shell_valid rule alone, satisfied by a screen in its OWN list.
	screened := head + "applies_when:\n" + screen + judge + body
	if ps := messagesOf(lintOne(t, screened, LintOptions{}), "shell_valid_screen"); len(ps) != 0 {
		t.Errorf("a screen in the same list must satisfy the shell_valid rule: %v", ps)
	}

	// A mechanism's when list is its own list too.
	mechWhen := head + `mechanisms:
  - when:
      - { fact: accounts.users, op: none, where: { field: shell_valid, op: eq, expected: true } }
    checks:
      - { fact: services.ssh.installed, op: eq, expected: true }
remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }
`
	if !hasMessage(lintOne(t, mechWhen, LintOptions{}), "shell_valid_screen", "mechanisms[0].when") {
		t.Error("an unscreened shell_valid clause in a mechanism's when must be a problem")
	}
}

// EV-4: each/none may only be judged, never screened. evalOne reads a screen
// clause's Holds alone (eval.go), so under applies_when or a mechanism's when
// a selection that matched nothing would silently apply the control or choose
// the mechanism, and an M-5 missing field would silently skip it -- with no
// field-naming reason anywhere. No embedded control does this today; the rule
// is what keeps it that way.
func TestLintRefusesACollectionOpInAScreen(t *testing.T) {
	head := `id: muster.account.screen_grammar_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: account
importance: 하
automation: auto
requires_facts: ">=1"
absent_means: fail
`
	const judged = "  - { fact: files.home_dirs, op: none, where: { field: other_writable, op: eq, expected: true } }\n"
	const screenOK = "  - { fact: accounts.shells, op: present }\n"
	const remediation = "remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }\n"

	// applies_when
	y := head + "applies_when:\n" + judged + "checks:\n" + screenOK + remediation
	if !hasMessage(lintOne(t, y, LintOptions{}), "clause_grammar", "applies_when", "only valid under checks") {
		t.Errorf("an each/none clause in applies_when must be a clause_grammar problem: %v", lintOne(t, y, LintOptions{}))
	}
	// a mechanism's when
	mech := head + `mechanisms:
  - when:
      - { fact: files.home_dirs, op: none, where: { field: other_writable, op: eq, expected: true } }
    checks:
      - { fact: accounts.shells, op: present }
` + remediation
	if !hasMessage(lintOne(t, mech, LintOptions{}), "clause_grammar", "mechanisms[0].when", "only valid under checks") {
		t.Errorf("an each/none clause in a mechanism's when must be a clause_grammar problem: %v", lintOne(t, mech, LintOptions{}))
	}
	// The same clause under checks is the ordinary case and must stay clean of
	// this rule -- in both the plain and the mechanism list.
	for _, ok := range []string{
		head + "checks:\n" + screenOK + judged + remediation,
		head + `mechanisms:
  - checks:
      - { fact: accounts.shells, op: present }
      - { fact: files.home_dirs, op: none, where: { field: other_writable, op: eq, expected: true } }
` + remediation,
	} {
		for _, m := range messagesOf(lintOne(t, ok, LintOptions{}), "clause_grammar") {
			if strings.Contains(m, "only valid under checks") {
				t.Errorf("a judged each/none must lint clean: %s", m)
			}
		}
	}
}

// LOW 4: the message is about the list, so a second unscreened clause in the
// same list adds a byte-identical line and inflates the problem count.
func TestLintShellValidScreenReportsAListOnce(t *testing.T) {
	const judge = "  - { fact: accounts.users, op: none, where: { field: shell_valid, op: eq, expected: true } }\n"
	y := `id: muster.account.shell_screen_once_test
title_en: t
title_ko: 제목
description_en: d
description_ko: d
category: account
importance: 하
automation: auto
requires_facts: ">=1"
absent_means: fail
checks:
` + judge + judge + "remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true }\n"
	if got := len(messagesOf(lintOne(t, y, LintOptions{}), "shell_valid_screen")); got != 1 {
		t.Errorf("want one problem for the list, got %d", got)
	}
}

// LOW 7: an empty Path alone does not make a problem set-level; M-2 says a
// set-level problem carries neither a control id nor a path. A Set built in
// code has controls with empty paths, and their problems must not sort in
// among the set-level ones or claim to be them.
func TestProblemStringMarksOnlySetLevelProblems(t *testing.T) {
	setLevel := Problem{Rule: "kisa_coverage", Message: "m"}
	if got, want := setLevel.String(), "controls: kisa_coverage: m"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	pathless := Problem{ControlID: "muster.account.x", Rule: "titles", Message: "m"}
	if strings.HasPrefix(pathless.String(), "controls: ") {
		t.Errorf("a control problem must not masquerade as set-level: %q", pathless.String())
	}
}
