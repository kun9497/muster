package controls

import (
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
	for _, k := range []string{"sockets.listening", "accounts.users", "services.ssh.active"} {
		if !got[k] {
			t.Errorf("%s is referenced by no control and must be reported", k)
		}
	}
	for _, k := range []string{"services.telnet.reachable", "files.etc_securetty_lines", "walk.world_writable"} {
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
