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
