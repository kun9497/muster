# Stage 3D-2 — `fix --dry-run` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `muster fix --dry-run` turns the failures of a `check` run into a risk-ordered remediation plan (table, JSON) and a POSIX `sh` review script that muster never runs.

**Architecture:** `cmd/muster` runs check's own pipeline (`openFacts` → load set and registry → `resolveSelection` → `loadWaivers` → `newCheckBlock` → `report.Build`) and hands the `*report.Report` to the new pure package `internal/remedy`, which builds a `Plan` and renders it three ways. `internal/report` exports the helpers the fix renderers share; `internal/check` exports three reason prefixes; `internal/controls` gains two remediation fields and their lint rules; the sixteen scripted controls are rewritten to the template's discipline.

**Tech Stack:** Go 1.25.5, standard library, `gopkg.in/yaml.v3` (existing), POSIX `sh`, shellcheck in CI.

**Spec:** `docs/superpowers/specs/2026-10-07-stage3d2-fix-dry-run-design.md` (EN canonical, `.ko.md` pair) at `d5ce4ad`, rulings X-1..X-10. Code map with exact current line numbers: `.superpowers/sdd/2026-10-07-stage3d2-fix-dry-run/code-map.md` (git-ignored; the controller hands its sections to each task).

## Global Constraints

- muster never executes a remediation: `internal/remedy` imports no `os`, `os/exec`, `net`, `syscall` or `time` (a test enforces it); nothing in `cmd/muster` runs the script.
- `fix` requires `--dry-run`; the refusal text is exactly `fix never applies a remediation (D24); run fix --dry-run`.
- `fix` exit codes: `0` a plan was produced (with or without items), `2` it could not be. Never `1`. `check`/`collect` exit codes unchanged.
- Same input, same bytes, in all three formats; no `map` in `remedy.Plan`; the generator reads no clock.
- Result output is stdout and nothing else; warnings are stderr lines `muster: warning: …`.
- Control YAML is decoded strictly; new fields carry `omitempty` (the mutation test round-trips controls through `yaml.Marshal`).
- No snapshot- or control-derived text outside a `#` comment line of the script, except template text, declared bodies, the control id (safe by `idRe`) and declared backup paths (safe by the lint charset).
- The block function call is a bare line followed by `[ "$?" -eq 0 ] || failed=$((failed+1))`; never `fix_x || …`, `&&`, `if`, `!`.
- `controls/VERSION` becomes `kisa-unix-2026+2026.10.08`; no control judgment changes.
- Documents: English canonical, `.ko.md` pair in the same commit; identifiers stay English.
- Commits: personal identity (pinned), trailers `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01LjfwtnJHSH7afTYL99Pmom`; never push; never amend/rebase/stash.
- The examples gate (`TestExamplesLoadAndCheck`) is red from Task 7 until the examples refresh (merge step); locally run `go test ./... -skip TestExamplesLoadAndCheck` from Task 7 on, and quote its failure once.
- On Windows `internal/collect/...` tests do not build (Linux-only); the lab run and CI cover them.

## Rulings carried from the code map (the spec as built)

- **Z-1** `report.StatusColor` is a function `StatusColor(s check.Status) string`, not the exported map (a mutable global).
- **Z-2** `report.Title` is `Title(ko, en string) string` (`ko`, falling back to `en`), because `remedy.Item` is not a `Row`; `WriteTable` calls `Title(row.TitleKo, row.TitleEn)`.
- **Z-3** `report.HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition string) string` returns the line without `\n`; the versions come from the CheckBlock (check) or FixBlock (fix), never from `run`.
- **Z-4** `report.ProfileLine(p ProfileBlock, t *TuningBlock) string` replaces `profileLine(cb CheckBlock)`; its one caller changes.
- **Z-5** The width helpers stay unexported: the fix table's padded columns are all ASCII (`fmt` `%-*s`), and its last column (the title) is never padded or width-cut — only `EscapeNoCut`.
- **Z-6** The absent-means-fail test reads `row.Reason`, never `ReasonLine(row)`.
- **Z-7** `eval.go:343`'s mid-string degraded suffix becomes `"; " + ReasonDegradedPrefix + all.Degraded` (byte-identical).
- **Z-8** A partial control's `WARN` ("observations need human review") is an item (X-2: FAIL/WARN); check's summary books it as manual review, so the two summaries differ there by design. No partial control carries a script, so such items are text-only.
- **Z-9** `fix`'s write failure is detected by `cmd/muster` on `stdout.Write(body)` (the renderers return `[]byte`); `report.WriteTable` is untouched.
- **Z-10** `remedy` tests build their own fixtures (report's test helpers are package-private).
- **Z-11** `remedy` keeps its own severity rank (`report.severityRank` is unexported).
- **Z-12** X-1 pre-pass: the value flags are exactly `--facts --format --waivers --profile --tuning --max-risk --color`; an unknown `-…` argument takes no value in the pre-pass; any argument not starting with `-` that is not a value-flag's value is the X-1 refusal; so `--bogus apply` → X-1, `--facts --dry-run` → X-1 (the `--dry-run` is the value of `--facts`).
- **Z-13** `loadWaivers("")` returns `nil, nil` (`--waivers ""` means no waiver file, as in check today); its refusal text keeps today's bytes (`muster: refusing waiver file: <why>`).
- **Z-14** `examples_test.go` helpers take the block name (`"check"` or `"fix"`); `examples/README.md` gains the three fix files per snapshot (twelve files).
- **Z-15** The `lintOne` table gets a `msg` field asserted with `hasMessage`; existing cases leave it empty (no assertion).
- **Z-16** `stdoutIsTTY(w io.Writer) bool` is lifted from `runCheck` and shared.
- **Z-17** The `shellcheck` CI step and Make target guard each glob with `[ -e "$f" ] || continue`, so a missing `examples/*-fix-report.sh` before the refresh is skipped there (the examples gate is what goes red).
- **Z-19** The spec's `remedy.Plan(rep, set, opts)` function is `remedy.Build(rep, set, opts) (*Plan, error)`: Go cannot name a type and a function `Plan` in one package.
- **Z-18** Design §7's document list gains the gaps the map found: §4.2 package table row for `internal/remedy`, §4.4/§8 "Data files" naming `fix`, README status line and the stale "Applying fixes … later" bullet, CLAUDE.md Build/Layout/Tests lines, CHANGELOG `### Tooling`, THREAT_MODEL's stale data-file sentence.

## Review Focus

1. A snapshot whose host, reason or a control's text carries ESC, `\n`, `#` or `$(…)` → the script has every such byte inside a `#` comment; nothing executes. (Task 5: `TestScriptEveryLineIsTemplateBodyOrComment`.)
2. The operator runs the script twice with the same `MUSTER_BACKUP` → the first, original copy is kept; a body failing on the second run restores the original. (Task 5: `TestScriptReusedBackupKeepsTheFirstCopy`, Linux.)
3. A host with nothing to fix (`full-pass.json`) → table `nothing to fix`, JSON `items: []`, script with `# nothing to fix` that exits 0, `fix` exit 0. (Tasks 5, 6, 7.)
4. `--max-risk none` with a lockout item → the whole block is commented, `sh -n` passes, the table marks `(above max-risk)`. (Tasks 5, 7.)
5. `fix --facts snap.json` (no `--dry-run`), `fix apply …`, `fix --dry-run apply`, `--bogus apply` → exit 2 with the X-1 text and nothing on stdout. (Task 7.)

---

### Task 1: Exported report helpers and evaluator reason constants (no output change)

**Files:**
- Modify: `internal/check/results.go` (constants beside the degradation strings, ~line 34-50)
- Modify: `internal/check/eval.go:326-349, 527-531`
- Test: `internal/check/eval_test.go` (new `TestWarnReasonShapes`; tighten the two degraded-pass cases' `verify` at ~372-400)
- Modify: `internal/report/table.go` (rename/export `escape`, `maxCell`, `paint`, `reasonLine`, `profileLine`; add `EscapeNoCut`, `StatusColor`, `Title`, `HeaderLine`)
- Test: `internal/report/table_test.go` (rename call sites; new `TestHeaderLineIsCheckLineOne`, `TestProfileLineForms`, `TestEscapeNoCutKeepsLength`)

**Interfaces:**
- Produces (check): `const ReasonDegradedPrefix = "collection was degraded: "`, `const ReasonSideOnlyPrefix = "setting holds on one side only: "`, `const ReasonAbsentFailPrefix = "absent counts as fail: "`.
- Produces (report): `const MaxCell = 200`; `func Escape(s string) string`; `func EscapeNoCut(s string) string`; `func Paint(on bool, code, s string) string`; `func StatusColor(s check.Status) string`; `func ReasonLine(row Row) string`; `func Title(ko, en string) string`; `func ProfileLine(p ProfileBlock, t *TuningBlock) string`; `func HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition string) string`.

- [ ] **Step 1: Write the failing tests**

`internal/check/eval_test.go` (reuse the file's `snap`, `one`, `reg` harness; build the degraded-pass row from the existing "13 sshd parse fallback" case's facts and control):

```go
func TestWarnReasonShapes(t *testing.T) {
	// The degraded pass: every clause held, collection degraded.
	r := degradedPassResult(t) // copy the facts/control of the "13 sshd parse fallback degrades a holding result to WARN" case
	if r.Status != WARN || r.Reason != ReasonDegradedPrefix+r.Degraded || r.Degraded == "" {
		t.Fatalf("degraded pass: status %s reason %q degraded %q", r.Status, r.Reason, r.Degraded)
	}
	// A hard FAIL with a secondary degradation is never the exact shape.
	f := hardFailWithDegradation(t) // the facts/control of the existing "reverts on reboot" FAIL case (~line 318)
	if f.Status != FAIL || f.Reason == ReasonDegradedPrefix+f.Degraded {
		t.Fatalf("hard fail must not match the degraded-pass shape: %s %q", f.Status, f.Reason)
	}
	if !strings.Contains(f.Reason, "; "+ReasonDegradedPrefix) {
		t.Fatalf("hard fail keeps the secondary degraded text: %q", f.Reason)
	}
	// Side-only WARN.
	s := sideOnlyResult(t) // the "not applied" side-mismatch case (~line 302)
	if s.Status != WARN || !strings.HasPrefix(s.Reason, ReasonSideOnlyPrefix) {
		t.Fatalf("side only: %s %q", s.Status, s.Reason)
	}
	// Absent means fail.
	a := absentFailResult(t) // the "8 absent means fail plain fact carries evidence" case (~line 284)
	if a.Status != FAIL || !strings.HasPrefix(a.Reason, ReasonAbsentFailPrefix) {
		t.Fatalf("absent fail: %s %q", a.Status, a.Reason)
	}
}
```

Write the four small helpers in the test file by lifting each named case's `facts` and `ctl` out of `TestDerivationTable` and calling `Evaluate` through the file's `one(c)`; keep the table cases as they are.

`internal/report/table_test.go`:

```go
func TestHeaderLineIsCheckLineOne(t *testing.T) {
	r := sampleReportWithTitles()
	var b bytes.Buffer
	if err := WriteTable(&b, r, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	first := strings.SplitN(b.String(), "\n", 2)[0]
	got := HeaderLine(r.Run, r.Check.MusterVersion, r.Check.ControlsVersion, r.Check.GuideEdition)
	if got != first {
		t.Fatalf("HeaderLine %q != table line 1 %q", got, first)
	}
}

func TestProfileLineForms(t *testing.T) {
	esc := "\x1b[31m"
	cases := []struct {
		p    ProfileBlock
		t    *TuningBlock
		want string
	}{
		{ProfileBlock{Name: "site" + esc, Selected: 4, Excluded: 2}, &TuningBlock{Path: "t.yaml"}, `profile site\x1b[31m (4 of 6, 2 excluded; tuning t.yaml)`},
		{ProfileBlock{Name: "all" + esc, Selected: 6}, &TuningBlock{Path: "t" + esc + ".yaml"}, `profile all\x1b[31m (6 controls; tuning t\x1b[31m.yaml)`},
		{ProfileBlock{Name: "default", Selected: 6}, nil, `profile default (6 controls)`},
	}
	for _, c := range cases {
		if got := ProfileLine(c.p, c.t); got != c.want {
			t.Errorf("ProfileLine = %q, want %q", got, c.want)
		}
	}
}

func TestEscapeNoCutKeepsLength(t *testing.T) {
	long := strings.Repeat("가", 300) + "\n\x1b"
	got := EscapeNoCut(long)
	if strings.Contains(got, "…") || !strings.HasSuffix(got, `\n\x1b`) || len([]rune(got)) != 300+4 {
		t.Fatalf("EscapeNoCut cut or mis-escaped: %d runes, tail %q", len([]rune(got)), got[len(got)-8:])
	}
	if Escape(long) == got {
		t.Fatal("Escape must still cut at MaxCell")
	}
}
```

- [ ] **Step 2: Run them; they fail to compile** (`undefined: ReasonDegradedPrefix`, `undefined: HeaderLine`, …).

Run: `go test ./internal/check ./internal/report -count=1`

- [ ] **Step 3: Implement**

`internal/check/results.go`, beside the unexported degradation strings:

```go
// The three reason shapes the evaluator writes and fix --dry-run reads
// (stage 3D-2 X-2): exported so a consumer never parses prose.
const (
	ReasonDegradedPrefix   = "collection was degraded: "
	ReasonSideOnlyPrefix   = "setting holds on one side only: "
	ReasonAbsentFailPrefix = "absent counts as fail: "
)
```

`internal/check/eval.go`: line 328 `r.Reason = ReasonSideOnlyPrefix + all.Degraded`; line 343 `r.Reason += "; " + ReasonDegradedPrefix + all.Degraded`; line 348 `r.Status, r.Degraded, r.Reason = WARN, all.Degraded, ReasonDegradedPrefix+all.Degraded`; line 529 `r.Status, r.Reason = FAIL, ReasonAbsentFailPrefix+why`.

`internal/report/table.go`:

```go
const MaxCell = 200

func escapeRune(b *strings.Builder, r rune) {
	switch {
	case r == '\t':
		b.WriteRune(r)
	case r == '\r':
		b.WriteString(`\r`)
	case r == '\n':
		b.WriteString(`\n`)
	case r == 0x1b:
		b.WriteString(`\x1b`)
	case r < 0x20 || (r >= 0x7f && r <= 0x9f):
		fmt.Fprintf(b, `\u%04x`, r)
	default:
		b.WriteRune(r)
	}
}

// Escape neutralises anything a hostile snapshot could use to repaint the
// terminal (spec §7.4) and cuts at MaxCell runes.
func Escape(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= MaxCell {
			b.WriteString("…")
			break
		}
		n++
		escapeRune(&b, r)
	}
	return b.String()
}

// EscapeNoCut is Escape without the cut: for control text, which is the
// plan's payload and is kept to one line by lint (stage 3D-2).
func EscapeNoCut(s string) string {
	var b strings.Builder
	for _, r := range s {
		escapeRune(&b, r)
	}
	return b.String()
}

func Paint(on bool, code, s string) string { /* body of today's paint */ }

var statusColor = map[check.Status]string{ /* unchanged */ }

// StatusColor is the ANSI code check's table paints a status with.
func StatusColor(s check.Status) string { return statusColor[s] }

func ReasonLine(row Row) string { /* body of today's reasonLine */ }

// Title is the table's title rule: Korean first, English when empty.
func Title(ko, en string) string {
	if ko == "" {
		return en
	}
	return ko
}

func ProfileLine(p ProfileBlock, t *TuningBlock) string { /* today's profileLine body over p and t */ }

// HeaderLine is the first line of check's table and of fix's (stage 3D-2).
func HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition string) string {
	return fmt.Sprintf("muster %s · controls %s · guide %s · host %s · collected %s",
		Escape(musterVersion), Escape(controlsVersion), Escape(guideEdition),
		Escape(run.Host.Hostname), Escape(run.CollectedAt))
}
```

In `WriteTable`: line 1 becomes `fmt.Fprintln(w, HeaderLine(r.Run, r.Check.MusterVersion, r.Check.ControlsVersion, r.Check.GuideEdition))`; line 2 `fmt.Fprintln(w, ProfileLine(r.Check.Profile, r.Check.Tuning))`; the title becomes `Title(row.TitleKo, row.TitleEn)`; `statusColor[row.Status]` becomes `StatusColor(row.Status)`; every `escape(`/`paint(`/`reasonLine(`/`maxCell` becomes the exported name. Update `table_test.go`'s call sites (`escape` at :27, :35, :41, :48) to `Escape`.

- [ ] **Step 4: Run** `go test ./internal/check ./internal/report ./cmd/muster -count=1` — PASS, and `git diff --stat -- internal/report/testdata examples` is empty (no golden or example changed). `TestExamplesLoadAndCheck` still passes (it compares the committed examples byte for byte).

- [ ] **Step 5: Remove the call to `ReasonDegradedPrefix` at eval.go:348 once (write the literal `"collection was degraded"` without the colon), run `TestWarnReasonShapes` and confirm it goes red; restore.**

- [ ] **Step 6: Commit** — `git add internal/check internal/report` then commit "Export the table helpers fix will share and the evaluator's three reason prefixes" with a body naming Z-1..Z-4, Z-7 and "no golden or example changed".

---

### Task 2: Remediation `backup`/`validate` fields and their lint rules

**Files:**
- Modify: `internal/controls/schema.go:104-111`
- Modify: `internal/controls/lint.go` (imports add `path`, `unicode/utf8`; titles rule at ~100-102; remediation rules at ~115-120 → `lintRemediation`)
- Test: `internal/controls/lint_test.go` (`TestLintRules` gets a `msg` field, Z-15)

**Interfaces:**
- Produces: `Remediation.Backup []string \`yaml:"backup,omitempty"\``, `Remediation.Validate string \`yaml:"validate,omitempty"\``.

- [ ] **Step 1: Write the failing tests.** Add `msg string` to the `TestLintRules` case struct; after the existing `got[c.rule]` assertion add `if c.msg != "" && !hasMessage(ps, c.rule, c.msg) { t.Errorf("%s: no %q message in %v", c.name, c.msg, ps) }`. Add one case per rule, each built from `goodControl`'s shape with only the `remediation:` block changed:

| name | remediation block (YAML flow or block) | rule | msg |
|---|---|---|---|
| `text_en blank` | `{ text_en: " ", text_ko: 조치, risk: none, idempotent: true }` | remediation | `text_en is blank` |
| `text_ko line break` | `text_ko: "a\nb"` | remediation | `text_ko carries a line break or control character` |
| `text_en too long` | `text_en:` 1001 × `a` | remediation | `text_en is longer than 1000 runes` |
| `title control char` | top-level `title_en: "t\u0007"` | titles | `title_en carries a line break or control character` |
| `script not idempotent` | `idempotent: false, script: "true", rollback: "true"` | remediation | `script requires idempotent: true` |
| `script without way back` | `script: "true"` | remediation | `script without rollback or backup` |
| `backup without script` | `backup: [/etc/hosts]` | remediation | `backup without script` |
| `validate without script` | `validate: "true"` | remediation | `validate without script` |
| `backup relative` | `script: "true", backup: [etc/hosts]` | remediation | `backup path "etc/hosts" is not absolute` |
| `backup unclean` | `backup: [/etc//hosts]` | remediation | `backup path "/etc//hosts" is not clean` |
| `backup trailing slash` | `backup: [/etc/]` | remediation | `backup path "/etc/" is not clean` |
| `backup charset` | `backup: ["/etc/my file"]` | remediation | `backup path "/etc/my file" carries a character the script cannot carry` |
| `backup glob` | `backup: ["/etc/*.conf"]` | remediation | `carries a character the script cannot carry` |
| `backup repeated` | `backup: [/etc/hosts, /etc/hosts]` | remediation | `backup path "/etc/hosts" is repeated` |
| `validate two lines` | `script: "true", rollback: "true", validate: "a\nb"` | remediation | `validate must be one line` |
| `script blank` | `script: " ", rollback: "true"` | remediation | `script is blank` |
| `rollback here-document` | `script: "true", rollback: "cat <<EOF\nx\nEOF"` | remediation | `rollback carries a here-document` |

And two accept cases (rule absent): a block scalar `validate: |` with one line plus its trailing newline; `script: ""` (empty reads as absent) with no `rollback`.

- [ ] **Step 2: Run** `go test ./internal/controls -run TestLintRules -count=1` — FAIL (unknown field `backup`, missing messages).

- [ ] **Step 3: Implement.** Schema fields as in Interfaces. In `lint.go` var block: `backupPathRe = regexp.MustCompile(\`^/[A-Za-z0-9._@:+/-]+$\`)`. Beside the titles rule:

```go
for _, tt := range []struct{ name, v string }{{"title_en", c.TitleEn}, {"title_ko", c.TitleKo}} {
	if hasControlRune(tt.v) {
		add("titles", "%s carries a line break or control character", tt.name)
	}
}
```

Replace the risk rule with `if c.Remediation != nil { lintRemediation(c.Remediation, add) }` and:

```go
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

func lintRemediation(r *Remediation, add func(rule, format string, args ...any)) {
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
	if hasScript && !r.Idempotent {
		add("remediation", "script requires idempotent: true")
	}
	if hasScript && strings.TrimSpace(r.Rollback) == "" && len(r.Backup) == 0 {
		add("remediation", "script without rollback or backup")
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
```

(`*?[` are outside the charset, so the glob case is the charset message.)

- [ ] **Step 4: Run** `go test ./internal/controls -count=1` (including `TestEveryMutantIsKilled`) and `go run ./cmd/muster controls lint --references docs/reference` — PASS / `ok:`; the shipped set is clean (no shipped control uses the new fields yet).

- [ ] **Step 5: Comment out the `script without rollback or backup` rule, run, see the case red; restore.**

- [ ] **Step 6: Commit** "Lint the remediation block: backup and validate, one-line texts, a way back for every script".

---

### Task 3: The sixteen scripted controls rewritten, and the unit-list pin

**Files:**
- Modify: the sixteen controls (`grep -rl '^  script:' controls`): `controls/file/{hosts,services,hosts_lpd,passwd,shadow}_permissions.yaml`, `controls/service/{telnet,finger,rservices,dos_services,nfs_server,automount,rpcbind,nis,tftp_talk,snmp}_disabled.yaml`, `controls/account/root_remote_login.yaml`
- Modify: `controls/VERSION` → `kisa-unix-2026+2026.10.08`
- Create: `internal/collect/collectors/remediation_units_test.go` (`//go:build linux`, package `collectors`)

**Interfaces:**
- Consumes: Task 2's fields and lint.
- Produces: the shipped bodies Task 5's `all-scripted.sh` golden renders.

The literal remediation blocks. Keep each control's existing `text_en`/`text_ko` except where a sentence is appended (shown). YAML: block scalars `|` for multi-line bodies, single- or double-quoted one-line validates exactly as written.

**File permissions** (hosts shown; services uses `/etc/services` and `644`, hosts_lpd uses `/etc/hosts.lpd` and `600`):

```yaml
remediation:
  text_en: chown root:root /etc/hosts; chmod 600 /etc/hosts
  text_ko: chown root:root /etc/hosts; chmod 600 /etc/hosts
  risk: none
  idempotent: true
  backup: [/etc/hosts]
  script: |
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod 600 /etc/hosts
  validate: "stat -c '%u %g %a' /etc/hosts | grep -qx '0 0 600'"
```

passwd:

```yaml
  backup: [/etc/passwd]
  script: |
    [ -f /etc/passwd ]
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi
  validate: "stat -c '%u %g %a' /etc/passwd | grep -qx '0 0 644'"
```

shadow (owner and mode only; the group is the distribution's):

```yaml
  backup: [/etc/shadow]
  script: |
    [ -f /etc/shadow ]
    chown root /etc/shadow
    chmod 400 /etc/shadow
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/shadow; fi
  validate: "stat -c '%u %a' /etc/shadow | grep -qx '0 400'"
```

**Services.** For a control with units `U1 … Un` (the `provesInstall: true` units of its row in `internal/collect/collectors/services.go`):

```yaml
  script: |
    for u in U1 … Un; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u"
    done
  validate: '! systemctl is-active --quiet U1 && case "$(systemctl is-enabled U1 2>/dev/null)" in enabled|enabled-runtime) false;; esac && … (the same pair for every unit, joined by " && ")'
  rollback: |
    for u in U1 … Un; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl unmask "$u"
      systemctl enable --now "$u"
    done
```

Units per control (sockets before their services):

| control | units |
|---|---|
| telnet_disabled | `telnet.socket telnet.service telnetd.service` |
| finger_disabled | `finger.socket fingerd.service` |
| rservices_disabled | `rsh.socket rlogin.socket rexec.socket` |
| dos_services_disabled | `echo.socket discard.socket daytime.socket chargen.socket` |
| nfs_server_disabled | `nfs-server.service nfs-kernel-server.service` |
| automount_disabled | `autofs.service` |
| rpcbind_disabled | `rpcbind.socket rpcbind.service` |
| nis_disabled | `ypserv.service ypbind.service ypxfrd.service yppasswdd.service` |
| tftp_talk_disabled | `tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket` |
| snmp_disabled | `snmpd.service` |

`telnet_disabled` appends to `text_en`: ` A telnet started by inetd or xinetd is not stopped by the script; remove its entry there.` and to `text_ko`: ` inetd나 xinetd가 띄우는 telnet은 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.` The same sentence (with the service's name) goes to `finger`, `rservices`, `dos_services` and `tftp_talk` (the rows with `inetdNames`).

**root_remote_login:**

```yaml
  backup: [/etc/ssh/sshd_config.d/00-muster.conf, /etc/securetty]
  script: |
    if command -v sshd >/dev/null 2>&1; then
      [ -d /run/sshd ] || mkdir -p /run/sshd
      printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/00-muster.conf
      chmod 644 /etc/ssh/sshd_config.d/00-muster.conf
      sshd -t
    fi
    if [ -f /etc/securetty ]; then
      sed -i '/^pts\//d' /etc/securetty
    fi
  validate: "if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'; fi"
  rollback: |
    rm -f /etc/ssh/sshd_config.d/00-muster.conf
    if command -v sshd >/dev/null 2>&1; then sshd -t; fi
```

Its `text_en`/`text_ko` change `90-muster.conf` to `00-muster.conf` and append: ` sshd keeps the first value it reads: a drop-in that sorts before 00-muster.conf, or a PermitRootLogin line before the Include in sshd_config, still wins.` / ` sshd는 처음 읽은 값을 지키므로 00-muster.conf보다 먼저 정렬되는 드롭인이나 sshd_config의 Include 앞 PermitRootLogin 줄이 여전히 이깁니다.`

- [ ] **Step 1: Write the failing pin test** `internal/collect/collectors/remediation_units_test.go`:

```go
//go:build linux

package collectors

import (
	"regexp"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestServiceScriptsNameTheCollectorsUnits pins stage 3D-2 §3: a service
// control's script, validate and rollback name exactly the provesInstall
// units of its logical service's row, never a super-server unit.
func TestServiceScriptsNameTheCollectorsUnits(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{
		"muster.service.telnet_disabled":       {"telnet"},
		"muster.service.finger_disabled":       {"finger"},
		"muster.service.rservices_disabled":    {"rservices"},
		"muster.service.dos_services_disabled": {"dos_services"},
		"muster.service.nfs_server_disabled":   {"nfs_server"},
		"muster.service.automount_disabled":    {"automount"},
		"muster.service.rpcbind_disabled":      {"rpcbind"},
		"muster.service.nis_disabled":          {"nis"},
		"muster.service.tftp_talk_disabled":    {"tftp", "talk"},
		"muster.service.snmp_disabled":         {"snmp"},
	}
	byName := map[string]logicalService{}
	for _, s := range services {
		byName[s.name] = s
	}
	word := func(u string) *regexp.Regexp { return regexp.MustCompile(`(^|[\s"'])` + regexp.QuoteMeta(u) + `($|[\s"';])`) }
	for id, names := range rows {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil {
			t.Fatalf("%s: no remediation", id)
		}
		r := c.Remediation
		for _, n := range names {
			svc, ok := byName[n]
			if !ok {
				t.Fatalf("%s: no logical service %q", id, n)
			}
			for _, u := range svc.units {
				for _, body := range []struct{ name, text string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
					has := word(u.name).MatchString(body.text)
					if u.provesInstall && !has {
						t.Errorf("%s: %s does not name %s", id, body.name, u.name)
					}
					if !u.provesInstall && has {
						t.Errorf("%s: %s names %s, a host of the service", id, body.name, u.name)
					}
				}
			}
		}
		for _, u := range append(append([]string{}, superServerExtraHostUnits...), "inetd.service", "xinetd.service") {
			if word(u).MatchString(r.Script) {
				t.Errorf("%s: script names super-server unit %s", id, u)
			}
		}
	}
}
```

(If `superServerExtraHostUnits` has a different type, adapt the range to its element's unit name.)

- [ ] **Step 2: Run on the lab** (Linux): `go test ./internal/collect/collectors -run TestServiceScriptsNameTheCollectorsUnits -count=1` — FAIL (the current bodies miss units). On Windows the test does not build; say so in the report.

- [ ] **Step 3: Rewrite the sixteen remediation blocks** exactly as above; set `controls/VERSION` to `kisa-unix-2026+2026.10.08`.

- [ ] **Step 4: Run** `go run ./cmd/muster controls lint --references docs/reference` → `ok:`; `go test ./internal/controls ./internal/check ./cmd/muster -count=1` (the examples gate now reports the G-24 digest skip note, not a failure); `go run ./tools/coverage -check`; on the lab the pin test passes. Render each body once through `sh -n` on the lab (write each body to `/tmp/muster-dev-3d2/<id>.sh`, 0700 dir) and run `shellcheck -s sh` if the lab has it (else note it: CI runs it in Task 8).

- [ ] **Step 5: Commit** "Rewrite the sixteen remediation scripts for the review script: guarded per-unit loops, one-line validates, declared backups" with body naming the VERSION bump and "no judgment changed".

---

### Task 4: `internal/remedy` — the plan model

**Files:**
- Create: `internal/remedy/plan.go`
- Create: `internal/remedy/plan_test.go`, `internal/remedy/imports_test.go`, `internal/remedy/fixture_test.go` (shared test fixtures, Z-10)

**Interfaces:**
- Consumes: `report.Report`, `report.Row`, `report.CheckBlock`, `report.ProfileBlock`, `report.TuningBlock`, `report.WaiversBlock`, `check.ReasonDegradedPrefix`, `check.ReasonAbsentFailPrefix`, `controls.Set.ByID`, `Remediation.{Script,Validate,Rollback,Backup,Risk,Idempotent,TextEn,TextKo}`.
- Produces (used by Tasks 5–7):

```go
package remedy

const PlanSchemaVersion = 1

type Options struct{ MaxRisk string } // "" means lockout_risk

type FixBlock struct {
	MusterVersion   string              `json:"muster_version"`
	Commit          string              `json:"commit"`
	ControlsVersion string              `json:"controls_version"`
	ControlsDigest  string              `json:"controls_digest"`
	SnapshotDigest  string              `json:"snapshot_digest"`
	GuideEdition    string              `json:"guide_edition"`
	Profile         report.ProfileBlock `json:"profile"`
	Tuning          *report.TuningBlock `json:"tuning,omitempty"`
	Waivers         report.WaiversBlock `json:"waivers"`
	MaxRisk         string              `json:"max_risk"`
}

type Item struct {
	ID             string   `json:"id"`
	TitleEn        string   `json:"title_en"`
	TitleKo        string   `json:"title_ko"`
	Status         string   `json:"status"` // fail | warn
	Severity       string   `json:"severity"`
	SeveritySource string   `json:"severity_source"`
	Risk           string   `json:"risk"`
	Idempotent     bool     `json:"idempotent"`
	Automation     string   `json:"automation"`
	Reason         string   `json:"reason"` // report.ReasonLine(row)
	TextEn         string   `json:"text_en"`
	TextKo         string   `json:"text_ko"`
	Script         bool     `json:"script"`
	TextOnlyReason string   `json:"text_only_reason"` // "" | no_script | absent | params_tuned
	Rollback       string   `json:"rollback"`         // none | declared | restore_backup | both
	Backup         []string `json:"backup"`
	Validate       bool     `json:"validate"`
	Planned        bool     `json:"planned"`

	SourceStatus check.Status `json:"-"` // for the table's status colour
	ScriptBody   string       `json:"-"`
	ValidateCmd  string       `json:"-"`
	RollbackBody string       `json:"-"`
}

type NotPlanned struct {
	ID     string `json:"id"`
	Status string `json:"status"` // error | manual | warn_degraded
	Reason string `json:"reason"` // report.ReasonLine(row)
}

type NotPlannedCounts struct {
	Error        int `json:"error"`
	Manual       int `json:"manual"`
	WarnDegraded int `json:"warn_degraded"`
}

type RiskCounts struct {
	None           int `json:"none"`
	RestartService int `json:"restart_service"`
	RebootRequired int `json:"reboot_required"`
	LockoutRisk    int `json:"lockout_risk"`
}

type Summary struct {
	Planned      int              `json:"planned"`
	AboveMaxRisk int              `json:"above_max_risk"`
	WithScript   int              `json:"with_script"`
	TextOnly     int              `json:"text_only"`
	Waived       int              `json:"waived"`
	Clean        int              `json:"clean"`
	NotPlanned   NotPlannedCounts `json:"not_planned"`
	ByRisk       RiskCounts       `json:"by_risk"`
}

type Plan struct {
	SchemaVersion int          `json:"schema_version"`
	Run           facts.Run    `json:"run"`
	Fix           FixBlock     `json:"fix"`
	Items         []Item       `json:"items"`
	NotPlanned    []NotPlanned `json:"not_planned"`
	Summary       Summary      `json:"summary"`
}

func Plan(rep *report.Report, set *controls.Set, opts Options) (*Plan, error)
```

(Ruling Z-19: the function is `Build`.)

- [ ] **Step 1: Write the fixtures and failing tests.** `fixture_test.go`: a `row(id, status, reason, degraded, severity string) report.Row` builder; a `testSet(t)` that writes control YAML to `t.TempDir()` and loads it with `controls.LoadFS(os.DirFS(dir))` (a VERSION file plus one YAML per control) covering: a scripted `none` control with `backup`; a scripted `restart_service` control with `rollback`; a scripted `lockout_risk` control with both; a `reboot_required` control without script; a scripted control with a param; a partial control without script. `plan_test.go`:

```go
func TestPlanOrdersByRiskSeverityID(t *testing.T)       // lockout high, none low, none high, restart medium → none/high, none/low, restart/medium, lockout/high; ties by id
func TestPlanClassifiesEveryRow(t *testing.T)           // PASS, NOT_APPLICABLE→clean; WAIVED→waived; ERROR→not_planned/error; MANUAL→manual;
                                                        // WARN with Reason==check.ReasonDegradedPrefix+Degraded→warn_degraded; FAIL with "; collection was degraded: x"→item;
                                                        // FAIL with check.ReasonAbsentFailPrefix→item text_only absent; tuned param (ParamSources[id][p]="tuning")→params_tuned;
                                                        // len(items)+len(not_planned)+waived+clean == len(rep.Results)
func TestPlanMarksItemsAboveMaxRisk(t *testing.T)       // MaxRisk restart_service: lockout item Planned=false, AboveMaxRisk 1, ByRisk counts it, Status kept
func TestPlanRollbackVocabulary(t *testing.T)           // backup only→restore_backup; rollback only→declared; both→both; text-only→none, Backup []
func TestPlanRejectsUnknownMaxRisk(t *testing.T)        // Options{MaxRisk:"high"} → error naming the four words
func TestPlanEmpty(t *testing.T)                        // all PASS → Items []Item{} (not nil), NotPlanned []NotPlanned{}
func TestPlanHasNoMap(t *testing.T)                     // reflect walk over reflect.TypeOf(Plan{}) (fields, slices, pointers, struct facts.Run): any reflect.Map kind fails
func TestPlanCopiesProvenance(t *testing.T)             // FixBlock fields equal rep.Check's; Run equals rep.Run
```

Write each test body with explicit `want` values (ids, statuses, counts); assert structurally (field by field), not by substring.

`imports_test.go`: copy `internal/profile/imports_test.go`'s `go list -f '{{join .Imports "\n"}}'` test for `github.com/kun9497/muster/internal/remedy`, refusing `os`, `os/exec`, `net`, `syscall`, `time` (it may import `os` only in `_test.go` files, which `.Imports` excludes).

- [ ] **Step 2: Run** `go test ./internal/remedy -count=1` — FAIL (package does not exist).

- [ ] **Step 3: Implement `plan.go`:**

```go
var riskRank = map[string]int{"none": 0, "restart_service": 1, "reboot_required": 2, "lockout_risk": 3}
var severityRank = map[string]int{"high": 0, "medium": 1, "low": 2}

func Build(rep *report.Report, set *controls.Set, opts Options) (*Plan, error) {
	max := opts.MaxRisk
	if max == "" {
		max = "lockout_risk"
	}
	maxRank, ok := riskRank[max]
	if !ok {
		return nil, fmt.Errorf("--max-risk must be none, restart_service, reboot_required or lockout_risk, got %q", opts.MaxRisk)
	}
	cb := rep.Check
	p := &Plan{
		SchemaVersion: PlanSchemaVersion,
		Run:           rep.Run,
		Fix: FixBlock{MusterVersion: cb.MusterVersion, Commit: cb.Commit, ControlsVersion: cb.ControlsVersion,
			ControlsDigest: cb.ControlsDigest, SnapshotDigest: cb.SnapshotDigest, GuideEdition: cb.GuideEdition,
			Profile: cb.Profile, Tuning: cb.Tuning, Waivers: cb.Waivers, MaxRisk: max},
		Items:      []Item{},
		NotPlanned: []NotPlanned{},
	}
	notPlanned := func(row report.Row, status string) {
		p.NotPlanned = append(p.NotPlanned, NotPlanned{ID: row.ID, Status: status, Reason: report.ReasonLine(row)})
	}
	for _, row := range rep.Results {
		switch row.Status {
		case check.PASS, check.NotApplicable:
			p.Summary.Clean++
		case check.WAIVED:
			p.Summary.Waived++
		case check.ERROR:
			notPlanned(row, "error")
			p.Summary.NotPlanned.Error++
		case check.MANUAL:
			notPlanned(row, "manual")
			p.Summary.NotPlanned.Manual++
		case check.WARN, check.FAIL:
			if row.Status == check.WARN && row.Degraded != "" && row.Reason == check.ReasonDegradedPrefix+row.Degraded {
				notPlanned(row, "warn_degraded")
				p.Summary.NotPlanned.WarnDegraded++
				continue
			}
			p.Items = append(p.Items, item(row, set, cb, maxRank))
		}
	}
	sort.SliceStable(p.Items, func(i, j int) bool {
		a, b := p.Items[i], p.Items[j]
		if riskRank[a.Risk] != riskRank[b.Risk] {
			return riskRank[a.Risk] < riskRank[b.Risk]
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		return a.ID < b.ID
	})
	sort.SliceStable(p.NotPlanned, func(i, j int) bool { return p.NotPlanned[i].ID < p.NotPlanned[j].ID })
	for _, it := range p.Items {
		switch it.Risk {
		case "none":
			p.Summary.ByRisk.None++
		case "restart_service":
			p.Summary.ByRisk.RestartService++
		case "reboot_required":
			p.Summary.ByRisk.RebootRequired++
		case "lockout_risk":
			p.Summary.ByRisk.LockoutRisk++
		}
		if !it.Planned {
			p.Summary.AboveMaxRisk++
			continue
		}
		p.Summary.Planned++
		if it.Script {
			p.Summary.WithScript++
		} else {
			p.Summary.TextOnly++
		}
	}
	return p, nil
}

func item(row report.Row, set *controls.Set, cb report.CheckBlock, maxRank int) Item {
	it := Item{ID: row.ID, TitleEn: row.TitleEn, TitleKo: row.TitleKo, Status: strings.ToLower(string(row.Status)),
		Severity: row.Severity, SeveritySource: row.SeveritySource, Automation: row.Automation,
		Reason: report.ReasonLine(row), Risk: "none", Rollback: "none", Backup: []string{}, SourceStatus: row.Status}
	c, ok := set.ByID(row.ID)
	if !ok || c.Remediation == nil {
		it.TextOnlyReason = "no_script"
		it.Planned = riskRank[it.Risk] <= maxRank
		return it
	}
	r := c.Remediation
	it.Risk, it.Idempotent, it.TextEn, it.TextKo = r.Risk, r.Idempotent, r.TextEn, r.TextKo
	it.Planned = riskRank[it.Risk] <= maxRank
	switch {
	case strings.TrimSpace(r.Script) == "":
		it.TextOnlyReason = "no_script"
	case strings.HasPrefix(row.Reason, check.ReasonAbsentFailPrefix): // Z-6: the bare reason
		it.TextOnlyReason = "absent"
	case tuned(cb.ParamSources[row.ID]):
		it.TextOnlyReason = "params_tuned"
	default:
		it.Script = true
		it.ScriptBody, it.ValidateCmd, it.RollbackBody = r.Script, strings.TrimSuffix(r.Validate, "\n"), r.Rollback
		it.Backup = append([]string{}, r.Backup...)
		it.Validate = r.Validate != ""
		hasRB, hasBK := strings.TrimSpace(r.Rollback) != "", len(r.Backup) > 0
		switch {
		case hasRB && hasBK:
			it.Rollback = "both"
		case hasRB:
			it.Rollback = "declared"
		default:
			it.Rollback = "restore_backup"
		}
	}
	return it
}

func tuned(sources map[string]string) bool {
	for _, s := range sources {
		if s != "default" {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run** `go test ./internal/remedy -count=1` — PASS; `go vet ./internal/remedy`.

- [ ] **Step 5: Delete the degraded-pass `continue` branch, run `TestPlanClassifiesEveryRow`, see red; restore. Same for the `absent` case.**

- [ ] **Step 6: Commit** "Plan the remediation of a check report: risk-ordered items, not-planned rows and a partition that sums to the selection".

---

### Task 5: `remedy.Script` — the review script

**Files:**
- Create: `internal/remedy/script.go`
- Create: `internal/remedy/script_test.go`, goldens `internal/remedy/testdata/{full,empty,capped,poison,all-scripted}.sh`

**Interfaces:**
- Consumes: Task 4's `Plan`/`Item`; `report.Escape`, `report.EscapeNoCut`.
- Produces: `func Script(p *Plan) []byte`.

- [ ] **Step 1: Write the failing tests** (`var update = flag.Bool("update", false, "rewrite golden files")` in `script_test.go`):

```go
func TestScriptGolden(t *testing.T)                          // five plans → five goldens; -update rewrites
func TestScriptBlocksAreIndependent(t *testing.T)           // for full.sh: each planned scripted item has one "fix_<fn>() {" line, one bare "fix_<fn>" line,
                                                             // and the next line is exactly `[ "$?" -eq 0 ] || failed=$((failed+1))`; no line starting with "fix_" contains "||", "&&", "if " or "!";
                                                             // capped.sh: every line between an "-- above max-risk" header and the next "# ---- " header starts with "#"
func TestScriptFailurePathRollbackThenRestore(t *testing.T) // the "both" block: inside each failure branch the rollback subshell line precedes the "restore " line
func TestScriptEveryLineIsTemplateBodyOrComment(t *testing.T) // poison plan (ESC, "\n", "#", "$(id)" in host, reason, titles, texts): every output line is a template line,
                                                             // a body line (from the plan's declared bodies), or starts with "#"; and no line outside comments contains "$(id)" or "\x1b"
func TestScriptIsDeterministic(t *testing.T)                // two renders byte-equal
func TestScriptAllScriptedCoversTheShippedSet(t *testing.T) // all-scripted plan from controls.LoadDefault(): one planned FAIL item per control with a script → 16 function definitions
func TestScriptBodyFailureReachesTheFailurePath(t *testing.T) // Linux only (runtime.GOOS check + exec.LookPath("sh")); see below
func TestScriptReusedBackupKeepsTheFirstCopy(t *testing.T)    // Linux only; see below
```

The two Linux tests render a synthetic plan whose bodies act only inside `t.TempDir()`, remove the root-check line (`strings.Replace(script, rootCheckLine+"\n", "", 1)` — the test's one transformation, named in a comment), set `MUSTER_BACKUP` to a temp dir, and run `sh` on the file:
- body-failure: item with `backup: [<tmp>/f]`, `ScriptBody: "false\nprintf ran > <tmp>/after"`, `RollbackBody: "printf rb > <tmp>/rb"`; after `sh`, exit code 1, `<tmp>/after` absent, `<tmp>/rb` present, `<tmp>/f` restored to its original bytes.
- reused backup: item with `backup: [<tmp>/f]`, body `printf two > <tmp>/f`, validate `false`; run once (f becomes original again by restore); change f to `edited`; run again with the same `MUSTER_BACKUP`; f is the original (the first copy), and stdout contains `backup exists, keeping the first`.

- [ ] **Step 2: Run** — FAIL (undefined `Script`).

- [ ] **Step 3: Implement `script.go`:**

```go
const rootCheckLine = `[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }`

const prologue = `set -u
umask 077
` + rootCheckLine + `
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
log() { printf 'muster-fix: %s\n' "$*"; }
backup() {
  for p in "$@"; do
    { [ -e "$p" ] || [ -L "$p" ]; } || continue
    if [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  rc=0
  for p in "$@"; do
    { [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; rc=1; continue; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0
`

const epilogue = `
if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
`

var textOnlyPhrase = map[string]string{
	"no_script":    "no script declared",
	"absent":       "the finding is an absent file",
	"params_tuned": "params tuned, see muster check --format json: check.param_sources",
}

func Script(p *Plan) []byte {
	var b strings.Builder
	s := p.Summary
	b.WriteString("#!/bin/sh\n# muster fix --dry-run: review before running. muster never runs this file.\n")
	fmt.Fprintf(&b, "# snapshot: host %s, collected %s; controls %s %s\n",
		report.Escape(p.Run.Host.Hostname), report.Escape(p.Run.CollectedAt), report.Escape(p.Fix.ControlsVersion), report.Escape(p.Fix.ControlsDigest))
	fmt.Fprintf(&b, "# profile %s (%s); max-risk %s\n", report.Escape(p.Fix.Profile.Name), report.Escape(p.Fix.Profile.Digest), p.Fix.MaxRisk)
	fmt.Fprintf(&b, "# planned %d (script %d, text only %d); above max-risk %d; not planned: error %d, manual %d, warn_degraded %d\n",
		s.Planned, s.WithScript, s.TextOnly, s.AboveMaxRisk, s.NotPlanned.Error, s.NotPlanned.Manual, s.NotPlanned.WarnDegraded)
	b.WriteString(prologue)
	if len(p.Items) == 0 {
		b.WriteString("\n# nothing to fix\n")
	}
	for i, it := range p.Items {
		b.WriteString("\n")
		for _, l := range block(i+1, len(p.Items), it, p.Fix.MaxRisk) {
			b.WriteString(l + "\n")
		}
	}
	b.WriteString(epilogue)
	return []byte(b.String())
}

func indent(body, pfx string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		out = append(out, pfx+l)
	}
	return out
}

func failurePath(it Item, pfx string) []string {
	var out []string
	if strings.TrimSpace(it.RollbackBody) != "" {
		out = append(out, pfx+"( set -e")
		out = append(out, indent(it.RollbackBody, pfx+"  ")...)
		out = append(out, pfx+"); rrc=$?",
			fmt.Sprintf(`%s[ "$rrc" -eq 0 ] || log "%s: rollback failed (rc $rrc)"`, pfx, it.ID))
	}
	if len(it.Backup) > 0 {
		out = append(out, fmt.Sprintf(`%srestore %s || log "%s: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`, pfx, strings.Join(it.Backup, " "), it.ID))
	}
	return out
}

func block(n, total int, it Item, maxRisk string) []string {
	header := fmt.Sprintf("# ---- %d/%d %s [risk %s] [%s, %s]", n, total, it.ID, it.Risk, it.Status, it.Severity)
	if !it.Planned {
		header += fmt.Sprintf(" -- above max-risk %s, NOT RUN", maxRisk)
	}
	lines := []string{}
	if it.Risk == "lockout_risk" {
		lines = append(lines, "# keep a second session open; a lockout here needs console access")
	}
	lines = append(lines,
		"# why: "+report.Escape(it.Reason),
		"# do:  "+report.EscapeNoCut(it.TextEn),
		"# ko:  "+report.EscapeNoCut(it.TextKo))
	if !it.Script {
		lines = append(lines, "# text only: "+textOnlyPhrase[it.TextOnlyReason])
	} else {
		fn := "fix_" + strings.ReplaceAll(it.ID, ".", "_")
		lines = append(lines, fn+"() {")
		if len(it.Backup) > 0 {
			lines = append(lines, fmt.Sprintf(`  backup %s || { log "%s: backup failed, nothing changed"; return 1; }`, strings.Join(it.Backup, " "), it.ID))
		}
		lines = append(lines, "  ( set -e")
		lines = append(lines, indent(it.ScriptBody, "    ")...)
		lines = append(lines, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
			fmt.Sprintf(`    log "%s: script failed (rc $rc), rolling back"`, it.ID))
		lines = append(lines, failurePath(it, "    ")...)
		lines = append(lines, "    return 1", "  fi")
		if it.Validate {
			lines = append(lines, "  ( set -e", "    "+it.ValidateCmd, "  ); rc=$?", `  if [ "$rc" -ne 0 ]; then`,
				fmt.Sprintf(`    log "%s: validate failed, rolling back"`, it.ID))
			lines = append(lines, failurePath(it, "    ")...)
			lines = append(lines, "    return 1", "  fi")
		}
		lines = append(lines, fmt.Sprintf(`  log "%s: done"`, it.ID), "}", fn, `[ "$?" -eq 0 ] || failed=$((failed+1))`)
	}
	out := []string{header}
	for _, l := range lines {
		switch {
		case it.Planned || strings.HasPrefix(l, "#"):
			out = append(out, l)
		case l == "":
			out = append(out, "#")
		default:
			out = append(out, "# "+l)
		}
	}
	return out
}
```

- [ ] **Step 4: Run** `go test ./internal/remedy -count=1 -update` once, read every golden line by line (in the report: what each golden shows), then without `-update`. On the lab: `go test ./internal/remedy -count=1` (the two Linux tests run), `sh -n` and `shellcheck -s sh` over `internal/remedy/testdata/*.sh` if shellcheck is present.

- [ ] **Step 5: Change the call line to `fn+" || failed=$((failed+1))"`, run on the lab, see `TestScriptBlocksAreIndependent` and `TestScriptBodyFailureReachesTheFailurePath` red; restore.**

- [ ] **Step 6: Commit** "Render the plan as a review script: one independent block per control, backup first, rollback then restore on failure".

---

### Task 6: `remedy.Table` and `remedy.JSON`

**Files:**
- Create: `internal/remedy/render.go`, `internal/remedy/render_test.go`, goldens `internal/remedy/testdata/{full,empty,poison}.table`, `full.json`, `empty.json`

**Interfaces:**
- Consumes: Task 4's `Plan`; `report.HeaderLine`, `report.ProfileLine`, `report.Escape`, `report.EscapeNoCut`, `report.Paint`, `report.StatusColor`, `report.Title`.
- Produces: `func Table(p *Plan, color bool) []byte`, `func JSON(p *Plan) []byte`.

- [ ] **Step 1: Failing tests:** `TestTableGolden`, `TestJSONGolden` (`-update`), `TestTablePoisoned` (poison plan, `color=false`: no `\x1b` byte in the output), `TestTableColorPaintsRiskAndStatus` (`color=true`: the lockout row's risk cell is `\x1b[31m` + padded word + `\x1b[0m`; a `none` risk cell carries no escape), `TestJSONEmptyListsAreArrays` (empty plan: `"items": []`, `"not_planned": []`, `"backup": []` for a text-only item), `TestTableEmptyPlan` (four header lines, blank, `nothing to fix`, nothing else), `TestTableNotPlannedOnlyWhenNonEmpty`.

- [ ] **Step 2: Run** — FAIL.

- [ ] **Step 3: Implement `render.go`:**

```go
var riskColor = map[string]string{"lockout_risk": "31", "reboot_required": "35", "restart_service": "33"}

func Table(p *Plan, color bool) []byte {
	var b strings.Builder
	s := p.Summary
	b.WriteString(report.HeaderLine(p.Run, p.Fix.MusterVersion, p.Fix.ControlsVersion, p.Fix.GuideEdition) + "\n")
	fmt.Fprintf(&b, "fix --dry-run · %s · max-risk %s\n", report.ProfileLine(p.Fix.Profile, p.Fix.Tuning), p.Fix.MaxRisk)
	fmt.Fprintf(&b, "planned %d (script %d, text only %d) · above max-risk %d · waived %d · clean %d · not planned: error %d, manual %d, warn_degraded %d\n",
		s.Planned, s.WithScript, s.TextOnly, s.AboveMaxRisk, s.Waived, s.Clean, s.NotPlanned.Error, s.NotPlanned.Manual, s.NotPlanned.WarnDegraded)
	fmt.Fprintf(&b, "by risk: none %d · restart_service %d · reboot_required %d · lockout_risk %d\n\n",
		s.ByRisk.None, s.ByRisk.RestartService, s.ByRisk.RebootRequired, s.ByRisk.LockoutRisk)
	if len(p.Items) == 0 {
		b.WriteString("nothing to fix\n")
	} else {
		numW, idW := len(strconv.Itoa(len(p.Items))), 2
		for _, it := range p.Items {
			if len(it.ID) > idW {
				idW = len(it.ID)
			}
		}
		fmt.Fprintf(&b, "%-*s  %-15s  %-*s  %-6s  %-6s  %-6s  %-14s  %s\n", numW, "#", "risk", idW, "id", "status", "sev", "script", "rollback", "title")
		for i, it := range p.Items {
			script, rb := "no", it.Rollback
			if it.Script {
				script = "yes"
			}
			if rb == "none" {
				rb = "-"
			}
			title := report.EscapeNoCut(report.Title(it.TitleKo, it.TitleEn))
			if !it.Planned {
				title += " (above max-risk)"
			}
			fmt.Fprintf(&b, "%-*d  %s  %-*s  %s  %-6s  %-6s  %-14s  %s\n", numW, i+1,
				report.Paint(color, riskColor[it.Risk], fmt.Sprintf("%-15s", it.Risk)),
				idW, it.ID,
				report.Paint(color, report.StatusColor(it.SourceStatus), fmt.Sprintf("%-6s", it.Status)),
				it.Severity, script, rb, title)
			fmt.Fprintf(&b, "   why: %s\n", report.Escape(it.Reason))
			do := report.EscapeNoCut(report.Title(it.TextKo, it.TextEn))
			if !it.Script {
				do += " (text only: " + it.TextOnlyReason + ")"
			}
			fmt.Fprintf(&b, "   do:  %s\n", do)
		}
	}
	if len(p.NotPlanned) > 0 {
		idW := 2
		for _, n := range p.NotPlanned {
			if len(n.ID) > idW {
				idW = len(n.ID)
			}
		}
		b.WriteString("\nnot planned:\n")
		for _, n := range p.NotPlanned {
			fmt.Fprintf(&b, "  %-*s  %-13s  %s\n", idW, n.ID, n.Status, report.Escape(n.Reason))
		}
	}
	return []byte(b.String())
}

func JSON(p *Plan) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(p); err != nil {
		panic(err) // a Plan always encodes: no channels, funcs or maps
	}
	return b.Bytes()
}
```

(`report.Title(it.TextKo, it.TextEn)` is the same Korean-first rule applied to the `do:` text.)

- [ ] **Step 4: Run with `-update`, read the goldens line by line, run again without.** `go vet ./internal/remedy`.

- [ ] **Step 5: Drop `report.Escape` from the reason line, see `TestTablePoisoned` red; restore.**

- [ ] **Step 6: Commit** "Render the plan as a table and as JSON".

---

### Task 7: `muster fix --dry-run`

**Files:**
- Create: `cmd/muster/fix.go`, `cmd/muster/fix_test.go`
- Modify: `cmd/muster/main.go` (usage line after `check`; `case "fix": return runFix(args[1:], stdout, stderr)`)
- Modify: `cmd/muster/check.go` (lift `loadWaivers` (Z-13) and `stdoutIsTTY` (Z-16); `runCheck` calls both; bytes of check's output unchanged)
- Modify: `cmd/muster/examples_test.go` (Z-14: block-name parameter for `maskReportBytes`, `reportControlsDigest`, `retagControlsDigest`; `fixReportsFor`; compare `<snap>-fix-report.{json,txt,sh}`)

**Interfaces:**
- Consumes: `remedy.Build`, `remedy.Table`, `remedy.JSON`, `remedy.Script`, `resolveSelection`, `newCheckBlock`, `report.Build`, `openFacts`, `warnTo`, `trustedFile`.
- Produces: `func runFix(args []string, stdout, stderr io.Writer) int`; `func loadWaivers(path string) (*waiver.File, error)`; `func stdoutIsTTY(w io.Writer) bool`.

`fix.go`:

```go
const fixUsage = `usage: muster fix --dry-run --facts <snapshot.json|-> [flags]

flags:
  --format table|json|script   output format (default table)
  --waivers <file>             waiver file, as check
  --profile <name|path>        the profile in force, as check (default: the built-in default)
  --tuning <file>              site parameter values, as check
  --max-risk none|restart_service|reboot_required|lockout_risk
                               the highest risk the script will run (default lockout_risk: everything)
  --color auto|always|never    colour (default auto); --no-color = never
`

const x1Refusal = "fix never applies a remediation (D24); run fix --dry-run"

var fixValueFlags = map[string]bool{"--facts": true, "--format": true, "--waivers": true, "--profile": true, "--tuning": true, "--max-risk": true, "--color": true}

type fixFlags struct {
	facts, format, waivers, color, profile, tuning, maxRisk string
	tuningGiven                                             bool
}

func parseFixArgs(args []string) (fixFlags, error) {
	dry := false
	for i := 0; i < len(args); i++ { // Z-12 pre-pass
		a := args[i]
		switch {
		case a == "--dry-run":
			dry = true
		case fixValueFlags[a]:
			i++ // its value, whatever it is
		case !strings.HasPrefix(a, "-"):
			return fixFlags{}, errors.New(x1Refusal)
		}
	}
	if !dry {
		return fixFlags{}, errors.New(x1Refusal)
	}
	f := fixFlags{format: "table", color: "auto", profile: "default", maxRisk: "lockout_risk"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--dry-run":
		case "--facts":
			f.facts, err = next()
		case "--format":
			f.format, err = next()
		case "--waivers":
			f.waivers, err = next()
		case "--profile":
			f.profile, err = next()
		case "--tuning":
			f.tuning, err = next()
			f.tuningGiven = true
		case "--max-risk":
			f.maxRisk, err = next()
		case "--color":
			f.color, err = next()
		case "--no-color":
			f.color = "never"
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	switch {
	case f.facts == "":
		return f, errors.New("--facts is required")
	case f.format != "table" && f.format != "json" && f.format != "script":
		return f, fmt.Errorf("--format must be table, json or script, got %q", f.format)
	case f.color != "auto" && f.color != "always" && f.color != "never":
		return f, fmt.Errorf("--color must be auto, always or never, got %q", f.color)
	}
	switch f.maxRisk {
	case "none", "restart_service", "reboot_required", "lockout_risk":
	default:
		return f, fmt.Errorf("--max-risk must be none, restart_service, reboot_required or lockout_risk, got %q", f.maxRisk)
	}
	return f, nil
}

func runFix(args []string, stdout, stderr io.Writer) int {
	f, err := parseFixArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, fixUsage)
		return exitError
	}
	snap, _, err := openFacts(f.facts)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	warn := warnTo(stderr)
	var tuningPath *string
	if f.tuningGiven {
		tuningPath = &f.tuning
	}
	sel, err := resolveSelection(f.profile, tuningPath, set, warn)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	wf, err := loadWaivers(f.waivers)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "muster: warning: fix does not need root")
	}
	results, cb := newCheckBlock(sel, snap, reg, wf, warn)
	rep := report.Build(snap, results, cb, sel.SeverityByID)
	p, err := remedy.Build(rep, set, remedy.Options{MaxRisk: f.maxRisk})
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	var body []byte
	switch f.format {
	case "json":
		body = remedy.JSON(p)
	case "script":
		body = remedy.Script(p)
	default:
		body = remedy.Table(p, report.ColorEnabled(f.color, os.Getenv("NO_COLOR"), os.Getenv("TERM"), stdoutIsTTY(stdout)))
	}
	if _, err := stdout.Write(body); err != nil {
		fmt.Fprintf(stderr, "muster: write: %v\n", err)
		return exitError
	}
	return exitOK
}
```

`check.go` additions: `func loadWaivers(path string) (*waiver.File, error)` — `""` → `nil, nil`; `trustedFile` refusal → `fmt.Errorf("refusing waiver file: %s", why)`; open/`waiver.Load` errors as today; `runCheck` replaces its inline block with it, printing `muster: %v`. `func stdoutIsTTY(w io.Writer) bool` lifts the `*os.File`/`Stat`/`ModeCharDevice` test; `runCheck` calls it.

`examples_test.go` (Z-14): `maskReportBytes(data []byte, block string)`, `reportControlsDigest(data []byte, block string)`, `retagControlsDigest(t, report []byte, block, digest string)`; existing callers pass `"check"`. Add:

```go
func fixReportsFor(t *testing.T, rep *report.Report, set *controls.Set) (jsonPlan, tablePlan, script []byte) {
	p, err := remedy.Build(rep, set, remedy.Options{MaxRisk: "lockout_risk"})
	if err != nil {
		t.Fatal(err)
	}
	return remedy.JSON(p), remedy.Table(p, false), remedy.Script(p)
}
```

`reportsFor` returns `rep` too (or a sibling builds it once). In `TestExamplesLoadAndCheck`, per snapshot after the check comparison: read `<b>-fix-report.json/.txt/.sh` (missing → `t.Fatalf("every example snapshot needs its fix reports beside it: %v", err)`); if the committed `fix.controls_digest` differs from `set.Digest` → note and skip (G-24); else compare masked JSON (block `"fix"`), `tableBody` of the table, and the script with its `# snapshot:` line removed — problems name `%s-fix-report.%s is not what this binary produces from %s; refresh the examples (see examples/README.md)`. Extend `TestExampleReportHelpers`/`TestExampleStalenessGate` for the `"fix"` block name.

- [ ] **Step 1: Write the failing e2e tests** in `fix_test.go` (`run([]string{"fix", …}, &out, &errb)` as the existing tests do; `type failWriter struct{}` whose `Write` returns `errors.New("closed")`):

```go
func TestFixRefusesWithoutDryRun(t *testing.T)          // ["fix","--facts",ff]; ["fix","apply","--dry-run","--facts",ff]; ["fix","--dry-run","apply","--facts",ff];
                                                        // ["fix","--bogus","apply","--dry-run","--facts",ff]; ["fix","--facts","--dry-run"] → exit 2, stderr starts "muster: fix never applies a remediation (D24); run fix --dry-run\n", stdout empty
func TestFixUnknownFlag(t *testing.T)                   // ["fix","--dry-run","--facts",ff,"--bogus"] → 2, "muster: unknown flag --bogus"
func TestFixMaxRiskOutsideTheList(t *testing.T)         // --max-risk high → 2, names the four words
func TestFixThreeFormats(t *testing.T)                  // full-fail.json: table/json/script exit 0; JSON decodes into remedy.Plan; 10 items; the lockout item last; two runs byte-equal per format
func TestFixAgreesWithCheck(t *testing.T)               // ids of check --format json FAIL/WARN rows == plan items ∪ not_planned warn_degraded, nothing else (full-fail.json and the hosts-0644 copy)
func TestFixFilePermissionShape(t *testing.T)           // TempDir copy of full-fail.json with etc_hosts.mode 384→420: muster.file.hosts_permissions is item 1, risk none, script true, rollback restore_backup
func TestFixMaxRiskMarksTheLockoutItem(t *testing.T)    // --max-risk restart_service: root_remote_login Planned=false, summary.above_max_risk 1; script: its block lines all start with "#"
func TestFixProfileAndWaivers(t *testing.T)             // --profile excluding root_remote_login (TempDir profile): not an item; --waivers turning it WAIVED: summary.waived 1
func TestFixNothingToFix(t *testing.T)                  // full-pass.json: exit 0; table contains "nothing to fix"; JSON items []; script contains "# nothing to fix"
func TestFixScriptPassesShN(t *testing.T)               // Linux only: write the full-fail script to TempDir, `sh -n` exits 0
func TestFixFailingStdoutIsExit2(t *testing.T)          // failWriter → 2, stderr "muster: write: closed"
func TestFixUsageListed(t *testing.T)                   // run(["help"]) output contains "  fix "
```

- [ ] **Step 2: Run** `go test ./cmd/muster -run 'Fix' -count=1` — FAIL.

- [ ] **Step 3: Implement** as above. Also add the `fix` line to `main.go`'s usage: `  fix        plan the remediation of a snapshot's failures (--dry-run only)`.

- [ ] **Step 4: Run** `go test ./... -count=1 -skip TestExamplesLoadAndCheck` (Windows) — PASS; run `go test ./cmd/muster -run TestExamplesLoadAndCheck -count=1` and quote its failure (the fix example files are missing — red until the refresh). On the lab: the full suite as root with `-race`, staticcheck, and `TestFixScriptPassesShN`.

- [ ] **Step 5: Remove the pre-pass's positional check, see `TestFixRefusesWithoutDryRun` red; restore. Replace `stdout.Write` error handling with `_, _ =`, see `TestFixFailingStdoutIsExit2` red; restore.**

- [ ] **Step 6: Commit** "Add muster fix --dry-run: check's pipeline, then the plan as a table, JSON or review script" (body: Z-12, Z-13, Z-14, Z-16; the examples gate red until the refresh).

---

### Task 8: CI — shellcheck, the round trip, the examples workflow

**Files:**
- Modify: `.github/workflows/ci.yml` (a `sh -n + shellcheck` step in `test` after `test`; a new `fix-roundtrip` job)
- Modify: `.github/workflows/examples.yml` (three `fix` lines in the report loop)
- Modify: `Makefile` (`shellcheck` target, `.PHONY`)
- Modify: `examples/README.md` (twelve files, the fix commands)

- [ ] **Step 1: `test` job step** (after `- name: test`):

```yaml
      - name: review scripts parse and pass shellcheck
        run: |
          command -v shellcheck || sudo apt-get install -y -qq shellcheck
          for f in internal/remedy/testdata/*.sh examples/*-fix-report.sh; do
            [ -e "$f" ] || continue
            sh -n "$f"
            shellcheck -s sh "$f"
          done
```

- [ ] **Step 2: Makefile:**

```make
shellcheck:
	@for f in internal/remedy/testdata/*.sh examples/*-fix-report.sh; do [ -e "$$f" ] || continue; sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; done
```

and add `shellcheck` to `.PHONY`.

- [ ] **Step 3: `fix-roundtrip` job** (copy `collect-containers`' build step and init start/wait/trap verbatim, code-map §ci-docs):

```yaml
  fix-roundtrip:
    runs-on: ubuntu-24.04
    needs: test
    strategy:
      fail-fast: false
      matrix:
        include:
          - image: rockylinux/rockylinux:9-ubi-init
            init: "true"
            seeded: "muster.service.rpcbind_disabled muster.account.root_remote_login muster.file.hosts_permissions"
          - image: almalinux/9-init
            init: "true"
            seeded: "muster.service.rpcbind_disabled muster.account.root_remote_login muster.file.hosts_permissions"
          - image: ubuntu:22.04
            init: "false"
            seeded: "muster.file.hosts_permissions muster.file.shadow_permissions"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
      - name: build muster
        run: CGO_ENABLED=0 go build -trimpath -o bin/muster ./cmd/muster
      - name: seed, plan, run the script, check again
        run: |
          set -eu
          d="$RUNNER_TEMP/rt"; mkdir -m 700 "$d"
          if [ "${{ matrix.init }}" = "true" ]; then
            cid=$(docker run -d --privileged --cgroupns=host -v "$PWD/bin:/m:ro" -v "$d:/out" ${{ matrix.image }} /sbin/init)
            for i in $(seq 1 30); do
              state=$(docker exec "$cid" systemctl is-system-running --wait 2>/dev/null || true)
              case "$state" in running|degraded) break ;; esac
              sleep 1
            done
          else
            cid=$(docker run -d -v "$PWD/bin:/m:ro" -v "$d:/out" ${{ matrix.image }} sleep infinity)
          fi
          trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
          if [ "${{ matrix.init }}" = "true" ]; then
            docker exec "$cid" dnf install -y -q rpcbind openssh-server acl
            docker exec "$cid" ssh-keygen -A
            docker exec "$cid" systemctl enable --now rpcbind.socket sshd
            docker exec "$cid" sh -c "printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/99-ci.conf"
          else
            docker exec "$cid" sh -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acl'
          fi
          docker exec "$cid" chmod 644 /etc/hosts
          docker exec "$cid" /m/muster collect --out /out/before.json || true
          sudo chown "$(id -u)" "$d/before.json"
          ./bin/muster fix --dry-run --facts "$d/before.json" --format json > "$d/plan.json"
          ./bin/muster fix --dry-run --facts "$d/before.json" --format script > "$d/fix.sh"
          for id in ${{ matrix.seeded }}; do
            jq -e --arg id "$id" '[.items[] | select(.id == $id and .planned and .script)] | length == 1' "$d/plan.json" > /dev/null \
              || { echo "seeded $id is not a planned scripted item"; jq '.items[] | {id, planned, script, text_only_reason}' "$d/plan.json"; exit 1; }
          done
          docker exec "$cid" sh /out/fix.sh
          docker exec "$cid" /m/muster collect --out /out/after.json || true
          sudo chown "$(id -u)" "$d/after.json"
          set +e
          ./bin/muster check --facts "$d/after.json" --format json > "$d/after-report.json"
          set -e
          for id in ${{ matrix.seeded }}; do
            jq -e --arg id "$id" '[.results[] | select(.id == $id and (.status == "PASS" or .status == "NOT_APPLICABLE"))] | length == 1' "$d/after-report.json" > /dev/null \
              || { echo "$id did not pass after the script"; jq --arg id "$id" '.results[] | select(.id == $id)' "$d/after-report.json"; exit 1; }
          done
```

- [ ] **Step 4: `examples.yml`** report loop, after the two `check` lines (same `set +e … set -e` region):

```sh
  NO_COLOR=1 "$GITHUB_WORKSPACE/bin/muster" fix --dry-run --facts "$f" --max-risk lockout_risk --format json > "$b-fix-report.json"
  NO_COLOR=1 "$GITHUB_WORKSPACE/bin/muster" fix --dry-run --facts "$f" --max-risk lockout_risk --format table > "$b-fix-report.txt"
  NO_COLOR=1 "$GITHUB_WORKSPACE/bin/muster" fix --dry-run --facts "$f" --max-risk lockout_risk --format script > "$b-fix-report.sh"
  test -s "$b-fix-report.json"; test -s "$b-fix-report.txt"; test -s "$b-fix-report.sh"
```

(examples.yml's jq programs are single-quoted: no apostrophes in any comment added there.)

- [ ] **Step 5: `examples/README.md`:** the file table gains the three fix files per snapshot; "the six files" → "the twelve files"; the commands block gains the three `fix` lines.

- [ ] **Step 6: Validate:** `go run github.com/rhysd/actionlint/cmd/actionlint@latest` if reachable, else a YAML parse (`python -X utf8 -c "import yaml,sys; [yaml.safe_load(open(p)) for p in sys.argv[1:]]" .github/workflows/ci.yml .github/workflows/examples.yml`); `make shellcheck` on the lab if shellcheck is there.

- [ ] **Step 7: Commit** "Check the review scripts with shellcheck, prove the seeded scripts in throwaway containers, and add the fix examples".

---

### Task 9 (controller): documents

**Files:** main design EN/KO, `CLAUDE.md`, `README.md`/`README.ko.md`, `CHANGELOG.md`, `CONTRIBUTING.md`/`.ko.md`, `THREAT_MODEL.md`. Anchors with line numbers: code-map §ci-docs 4–9.

- [ ] Main design (both files, same commit): §4.1 Subcommands sentence moves `fix --dry-run` into the list (leave `later … explain`) and the example block gains `muster fix --dry-run --facts host.json --format script > fix.sh`; §4.2 package table gains `internal/remedy` (plan and renderers; must not import `os`, `os/exec`, `net`, `syscall`, `time` or run anything); §4.3 figure gains `results ──fix --dry-run──▶ plan ──▶ table / JSON / review script (exit 0)`; §4.4 names `check` and `fix` as the readers of data files and under the root trusted-file rule; §6.2 example becomes the rewritten root_remote_login block (`00-muster.conf`, `backup`, `validate`) and the Fields sentence names `backup`/`validate` and the lint rules; new `### 7.5 \`fix --dry-run\`` (inputs, three formats, exit codes 0/2 and "exits 0 with findings", the template contract, `validate` proves the step); §8 Writes and Data files name `fix`; §10.2 "3D-2 (merged): … — `2026-10-07-stage3d2-fix-dry-run-design.md`"; D34 between D33 and D28 (spec §7 text).
- [ ] `CLAUDE.md`: Build and test gains `make shellcheck`; Layout gains `internal/remedy`; new `## Fix (stage 3D-2)` after Profiles (X rulings, the body discipline, the call-line rule, the examples-refresh rule); Tests gains the remedy goldens `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden|TestJSONGolden' -update`; decision range D01–D34.
- [ ] README pair: status → 3D-2 merged; usage line; "Applying fixes" bullet loses "later" and names `fix --dry-run`; roadmap 3D-2 (merged) entry and "then" sentence; Example output sentence naming the fix files.
- [ ] `CHANGELOG.md`: Added (`fix --dry-run`, three formats, `--max-risk`, the plan JSON schema 1); Changed (lint rules; `check`'s output unchanged); Controls (new top paragraph: `kisa-unix-2026+2026.10.08` (was `+2026.10.02`), the sixteen rewritten, no verdict changes); Tooling (shellcheck step, `make shellcheck`, `fix-roundtrip` job).
- [ ] CONTRIBUTING pair: `### Remediation bodies` subsection before Adding a fact (the spec §3 body discipline); Tests goldens + CI bullets.
- [ ] THREAT_MODEL: a Trust-boundary bullet for `fix --dry-run`; fix the stale "refuses waiver and control files" sentence to include profile and tuning files.
- [ ] Host/employer grep 0; gitleaks over the branch; commit "Record stage 3D-2 in the documents: D34, section 7.5, the fix command and the remediation body rules".

---

## Merge (the user's word)

Whole-branch review workflow → one fix wave + scoped re-review → Execution notes → final gates (Windows suite with `-skip TestExamplesLoadAndCheck`, lab root `-race`, staticcheck, oracles, the Linux remedy tests, `make shellcheck`) → push → `examples.yml` on the branch → `make examples-fetch RUN=<id>` into a backup directory outside the repository, copy into `examples/` (now twelve files plus README) → commit "Refresh the example snapshots and add the fix examples from the branch's examples run" → `TestExamplesLoadAndCheck` green → PR → CI (incl. the first `fix-roundtrip` run: record each image's planned set in the Execution notes) → merge → cleanup → memory.

## Execution notes

### Rulings settled during execution (Z-20 …)

### What the reviews found

### Deviations from the spec, as shipped

### Numbers

### Parked
