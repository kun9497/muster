# Stage 3F — Test Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the four test subsystems of spec 3F — a mutation test over the control YAML whose kill oracle is the fixture set, one native fuzz target per parser entry point with a committed corpus run nightly, daemon-oracle tests run in the CI jobs that have the daemons, and committed example snapshots from public images — without changing what any collector reads or any control judges.

**Architecture:** Everything is `go test`: the mutant generator and its kill loop live in the `internal/controls` external test package and reuse the fixture harness's loader and `check.Evaluate`; the fuzz targets live beside the parsers with an in-memory `Access` for the one parser that reads through `Access`; the oracle test is a Linux test that is off unless `MUSTER_ORACLE=1` and is run by the existing root job and, as a static test binary, inside the init containers. Two new workflows (`fuzz.yml` nightly, `examples.yml` on demand) and small additions to `ci.yml` and the Makefile carry the rest.

**Tech Stack:** Go 1.25 native fuzzing (`testing.F`, `go test -fuzz`), `gopkg.in/yaml.v3` (already a dependency), `go/ast` for the parser inventory, `os/exec` in the oracle test only, GitHub Actions. No new Go dependency (D28).

**Spec:** `docs/superpowers/specs/2026-09-17-stage3f-hardening-design.md` (F-1…F-12; §2 mutants, §3 fuzzing, §4 oracles, §5 examples, §6 changes elsewhere, §7 errors, §8 success criteria), committed at `ec9d6e8` with the main design's §11 stage-3 amendment.

## Global Constraints

- **Branch base:** `stage3f-hardening` at `ec9d6e8` over main `0fe31c8`. Task 6 confirms `git merge-base HEAD main` is main's tip before the final gates.
- **Ruling G-1 (nothing judged changes):** no collector read, registry key, cap, budget, control clause or verdict changes in this plan. A fuzzer-found parser bug is fixed in its own commit with the crashing input committed as a seed; a control a mutant proves wrong is fixed in its own commit with a CHANGELOG line and a `controls/VERSION` bump; otherwise `controls/VERSION` stays `kisa-unix-2026+2026.09.16`.
- **Ruling G-2 (the mutation test lands in two steps):** Task 1 lands the generator and `TestEveryMutantIsKilled` in *report mode* — it logs every surviving mutant and passes unless `MUSTER_MUTANTS_STRICT=1` — so the branch stays green while Task 2 examines the survivors; Task 2 kills them with fixtures, writes `controls/testdata/_mutants.yaml` for the equivalent ones, and removes the gate so the test is unconditional from then on. No placeholder reason ever reaches `_mutants.yaml`.
- **Ruling G-3 (mutant validity):** every mutant is re-linted with `controls.Lint(&controls.Set{Controls: []controls.Control{m}}, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs()})` (no `FixtureDir`, no references, no KISA — shape only); any problem makes it invalid. A mutant whose only differing fixtures moved to `ERROR(internal_error)` is invalid, not killed.
- **Ruling G-4 (signatures):** `<path> <operator>` exactly as the spec's F-2 table spells them; paths use `checks[i]`, `checks[i].where`, `checks[i].require`, `mechanisms[j].when[k]`, `mechanisms[j].checks[i]` (+ `.where`/`.require`), `mechanisms[j]`, `applies_when[k]`, `params.<name>.default`, `absent_means`; operators `op A->B`, `expected not`, `expected +1`, `expected -1`, `expected "__mutant__"`, `expected drop[i]`, `expected []`, `remove`, `absent_means -><value>`. Generation order: control fields in the order `applies_when`, `absent_means`, `params`, `checks`, `mechanisms`; within a list by index; within a clause `op` then `expected` then `where` then `require`; `remove` after the clause's own mutants.
- **Ruling G-5 (seeds):** each fuzz target registers seeds from an explicit glob list in the fuzz file (`testdata/<prefix>*`), never from a directory scan of everything; a target whose glob list matches no file fails at seed time.
- **Ruling G-6 (fuzz body):** exactly the spec's three properties — no panic, determinism (`reflect.DeepEqual` of two calls; maps compared as maps), bounded output (fields filled through `sourceRaw` ≤ `rawCap`, every returned list ≤ `len(input) + 64` elements — the slack covers legitimate expansions such as `parseRsyslogSelector("*.*")` producing the whole facility table from three bytes, while a parser that fabricates rows per byte is still caught) — nothing about meaning.
- **Ruling G-7 (oracle test):** skips unless `MUSTER_ORACLE=1`; reads the host through `collect.Guard(collect.Host(), <collector>)`; runs oracle commands with `exec.Command` and absolute paths (`/usr/sbin/sshd`, `/usr/bin/getent`, `/usr/bin/findmnt`, `/usr/bin/systemctl`, falling back to `/bin/…`); a missing binary skips that pair naming it; every mismatch names pair, key, parser value and oracle value.
- **Ruling G-8 (examples):** both examples come from the `examples.yml` run on the pull request (Task 6, controller) — a container example made on the lab would carry the lab kernel's raw `boot_id`, `kernel` and `uptime_s`. The F-11 rewrite therefore also blanks `run.host.boot_id`, `run.host.kernel` and `run.host.uptime_s` (`boot_id` is the raw UUID today, not a hash — the spec's F-11 sentence is corrected in this commit). Task 5 lands the workflow and the test with its comparison logic proven on a synthetic snapshot; with no example file committed the example test skips with a named reason, and Task 6 turns it live.
- **Ruling G-9 (lab and gates):** the LAB TOKEN is 3F's from Task 3. Linux-only tests run on the lab through the session's read-only `lab-sync.sh <worktree>` / `lab-run.sh '<cmd>'`; subagents build and run only under `/root/muster-dev`, `/tmp` and, for docker, the public images only. Windows gates before every commit: `gofmt -l .`, `go vet ./...`, `GOOS=linux GOARCH=amd64 go vet ./...`, `go test ./... -count=1`, `go run ./cmd/muster controls lint --references docs/reference` → `ok: 68 controls`, `go run ./tools/coverage -check`; staticcheck (`go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...`) on the lab before every push. The controller's host-string grep → 0 on every commit; `gitleaks git --no-banner` before the merge menu. Never push, never `git stash`, never commit anything captured from the lab host.
- **Ruling G-10 (work split):** implementers write code, tests, fixtures, workflows, Makefile targets and `examples/README.md`; the controller writes CONTRIBUTING/CLAUDE/README/CHANGELOG prose and the Execution notes (Task 6). Commit trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01LjfwtnJHSH7afTYL99Pmom` on every commit. No hostname, IP address, SSH alias or organisation name in any file; synthetic fixtures only.
- **Ruling G-11 (the fuzz inventory is transitive):** the spec's F-5 table is a floor, not the list. `TestEveryParserHasAFuzzTarget` builds the package's call graph with `go/ast` (top-level function → the top-level functions its body calls, transitively) and a parser is covered when some `Fuzz*` body reaches it; `coveredThrough` is not a free-text table but is *derived* from that graph and printed for the reader. Functions the inventory rule matches that are not parsers (`splitLines`, `firstLine`, `sourceRaw`, `showValues` and the like) are listed in `notParsers` with a one-line reason each; every other match without a reaching target fails the test. Known uncovered parsers to give targets of their own (or reach through an existing target): `nssSources`, `decodeACL`, `dnsTokenize`, `rpmFileTable`, `rsyslogLogicalLines`, `sendmailLogicalLines`, `snmpTokens`, `osEscapes`, `cryptoPolicyName`, `ufwEnabledLine`, `firstSettingLine`, `listsRoot`, `aptPeriodicUnattended`, `newestDpkgInstall`, `countAptSecurity`, `countDnfAdvisories`, `dnfAutomaticApply`.
- **Ruling G-12 (all-absent fixtures):** an `absent_means` fixture keeps every screen fact (`applies_when`, mechanism `when`) `ok` and makes only the judged facts `absent`; otherwise the control answers NOT_APPLICABLE before `absent_means` and the mutant survives for the wrong reason.
- **Ruling G-13 (cache the fixtures):** the kill loop loads each control's fixtures once (snapshots are immutable and `check.Evaluate` is pure) and evaluates every mutant against the cached snapshots; the package must stay under 30 s on Windows.
- **Ruling G-14 (report block):** `runCheck`'s construction of `report.CheckBlock` (the six header fields plus the `Params` map `check.ParamValues` fills for every control with params) is extracted into `newCheckBlock(set *controls.Set, snap *facts.Snapshot, wf *waiver.File) report.CheckBlock` in `cmd/muster/check.go` and reused by the example test, so the in-process report and the binary's report are built by one function.

## File Structure

- Create `internal/controls/mutants_test.go` — the generator (`mutantsOf`, `mutant`, signature paths, the operator table, `cloneControl`) and its unit tests (`mutants_gen_test.go`).
- Create `internal/controls/mutation_test.go` — `TestEveryMutantIsKilled`, the kill loop, the exclusion file loader.
- Create `controls/testdata/_mutants.yaml` (Task 2) and new fixtures under `controls/testdata/<id>/`.
- Create `internal/collect/collectors/fuzz_test.go` (targets, `memAccess`, seed globs), `fuzz_inventory_test.go` (`TestEveryParserHasAFuzzTarget`, `coveredThrough`); `internal/pkgfiles/fuzz_test.go`.
- Create `internal/collect/collectors/oracle_test.go`.
- Create `.github/workflows/fuzz.yml`, `.github/workflows/examples.yml`; modify `.github/workflows/ci.yml` (root job oracle + seed steps; init-container test-binary step), `Makefile` (`fuzz`, `examples-fetch`).
- Create `cmd/muster/examples_test.go`, `examples/README.md` (Task 5); modify `cmd/muster/check.go` (`newCheckBlock`); the six example files land in Task 6 from the workflow run.
- Controller (Task 6): `CONTRIBUTING.md`/`.ko.md`, `CLAUDE.md`, `README.md`/`.ko.md`, `CHANGELOG.md`.

## Interfaces (produced by this plan)

```go
// internal/controls/mutants_test.go (package controls_test)
type mutant struct {
	Signature string            // "<path> <operator>", G-4
	Control   controls.Control  // a deep copy with one change applied
}
func cloneControl(c controls.Control) controls.Control          // yaml.Marshal + strict decode (KnownFields), the loader's own round trip
func mutantsOf(c controls.Control) []mutant                       // deterministic order, G-4; never mutates c
func lintValid(m controls.Control, reg *facts.Registry) bool     // G-3
// internal/controls/mutation_test.go
type outcome struct{ Status check.Status; Reason check.ReasonCode } // per fixture
func loadSnapshots(t *testing.T, files []string) []*facts.Snapshot                       // loadFixture once per file (G-13)
func evaluateFixtures(t *testing.T, c controls.Control, set *controls.Set, reg *facts.Registry, snaps []*facts.Snapshot) []outcome
type exclusion struct { Control string `yaml:"control"`; Mutant string `yaml:"mutant"`; Reason string `yaml:"reason"` }
func loadExclusions(t *testing.T, path string) []exclusion       // strict YAML; absent file → empty (Task 1) / required (Task 2)

// internal/collect/collectors/fuzz_test.go
type memAccess struct { collect.NoWalkAccess; files map[string][]byte } // ReadFile/Stat/Glob over the map; Llistxattr/Getxattr → ENODATA; Writable false; Run → exit -1
func seeds(f *testing.F, globs ...string)                         // f.Add for every match; f.Fatalf when a glob matches nothing (G-5)
func fuzzBody(t *testing.T, name string, run func() any, inputLen int) // calls run twice, DeepEqual, bound check via reflect over the result (G-6)
var coveredThrough = map[string]string{ "parseNftRule": "FuzzParseNftRuleset", … } // fuzz_inventory_test.go

// internal/collect/collectors/oracle_test.go
func oracleEnabled(t *testing.T)                                   // t.Skip unless MUSTER_ORACLE=1
func oracleCommand(t *testing.T, pair string, names ...string) string // first existing absolute path or t.Skipf("%s: no %s", pair, names)
```

---

### Task 1: the mutant generator and the kill loop in report mode (F-1, F-2, F-4; G-2, G-3, G-4)

**Files:** create `internal/controls/mutants_test.go`, `mutants_gen_test.go`, `mutation_test.go`.

**Interfaces:** consumes `controls.LoadDefault`, `controls.Lint`, `check.Evaluate`, `check.CustomFuncs`, `facts.LoadRegistry`, the fixture harness's `loadFixture`/`fixtureRoot`/`prefixStatus` (same package `controls_test`); produces `mutant`, `mutantsOf`, `cloneControl`, `lintValid`, `outcome`, `evaluateFixtures`, `TestEveryMutantIsKilled` (report mode).

- [ ] **Step 1: Failing generator tests** (`mutants_gen_test.go`)
```go
// A control with checks [eq bool, in list<string>, each/where/require, none/where] and applies_when [eq] and absent_means manual, params {allowed: list<string>}:
// mutantsOf yields exactly these signatures in this order (the test lists them literally — ~30 lines) and every mutant differs from the original in exactly one YAML-marshalled field.
func TestMutantsOfSignaturesAndOrder(t *testing.T) {}
// each->none keeps the where and drops the require; a `none` clause yields no none->each mutant; a bool expected yields `expected not` only; an int yields +1 and -1; a string yields "__mutant__"; a 3-element list yields drop[0..2] and []; a ${allowed} reference yields params.allowed.default … rows once even when two clauses reference it.
func TestMutantsOfOperatorTable(t *testing.T) {}
// checks with one clause → no `remove`; with two → `checks[0] remove`, `checks[1] remove`; one mechanism → no `mechanisms[0] remove`; two → both; absent_means manual → three `absent_means ->pass|fail|not_applicable`.
func TestMutantsOfRemovalRules(t *testing.T) {}
// mutantsOf never mutates its input (DeepEqual before/after) and two calls yield identical signatures.
func TestMutantsOfIsPureAndDeterministic(t *testing.T) {}
// lintValid: `matches->not_matches` on a list<string> fact → false (lint rejects not_matches on lists); an int default +1 → true; a present clause flipped to absent → true.
func TestLintValidUsesTheRealLint(t *testing.T) {}
```
- [ ] **Step 2: Run red.** `go test ./internal/controls/ -run 'MutantsOf|LintValid' -count=1`.
- [ ] **Step 3: Implement `mutants_test.go`.**
```go
func cloneControl(c controls.Control) controls.Control {
	data, err := yaml.Marshal(c)            // Path has yaml:"-" and is restored below
	if err != nil { panic(err) }
	dec := yaml.NewDecoder(bytes.NewReader(data)); dec.KnownFields(true)
	var out controls.Control
	if err := dec.Decode(&out); err != nil { panic(err) }
	out.Path = c.Path
	return out
}
var flips = map[string]string{"eq": "ne", "ne": "eq", "in": "not_in", "not_in": "in", "lt": "gte", "lte": "gt", "gt": "lte", "gte": "lt", "matches": "not_matches", "not_matches": "matches", "contains": "not_contains", "not_contains": "contains", "present": "absent", "absent": "present"}
func mutantsOf(c controls.Control) []mutant {
	var out []mutant
	add := func(sig string, edit func(m *controls.Control)) { m := cloneControl(c); edit(&m); out = append(out, mutant{sig, m}) }
	for k := range c.AppliesWhen { clauseMutants(&out, c, fmt.Sprintf("applies_when[%d]", k), func(m *controls.Control) *controls.Clause { return &m.AppliesWhen[k] }) ; add(fmt.Sprintf("applies_when[%d] remove", k), func(m *controls.Control){ m.AppliesWhen = slices.Delete(m.AppliesWhen, k, k+1) }) }
	if c.AbsentMeans != "" { for _, v := range []string{"pass","fail","not_applicable","manual"} { if v != c.AbsentMeans { add("absent_means ->"+v, func(m *controls.Control){ m.AbsentMeans = v }) } } }
	for _, name := range sortedKeys(c.Params) { expectedMutants(&out, c, "params."+name+".default", c.Params[name].Default, func(m *controls.Control, v any){ p := m.Params[name]; p.Default = v; m.Params[name] = p }) }
	for i := range c.Checks { clauseMutants(&out, c, fmt.Sprintf("checks[%d]", i), func(m *controls.Control) *controls.Clause { return &m.Checks[i] }); if len(c.Checks) > 1 { add(fmt.Sprintf("checks[%d] remove", i), func(m *controls.Control){ m.Checks = slices.Delete(m.Checks, i, i+1) }) } }
	for j := range c.Mechanisms {
		mp := fmt.Sprintf("mechanisms[%d]", j)
		for k := range c.Mechanisms[j].When {
			clauseMutants(&out, c, fmt.Sprintf("%s.when[%d]", mp, k), func(m *controls.Control) *controls.Clause { return &m.Mechanisms[j].When[k] })
			add(fmt.Sprintf("%s.when[%d] remove", mp, k), func(m *controls.Control) { m.Mechanisms[j].When = slices.Delete(m.Mechanisms[j].When, k, k+1) })
		}
		for i := range c.Mechanisms[j].Checks {
			clauseMutants(&out, c, fmt.Sprintf("%s.checks[%d]", mp, i), func(m *controls.Control) *controls.Clause { return &m.Mechanisms[j].Checks[i] })
			if len(c.Mechanisms[j].Checks) > 1 { add(fmt.Sprintf("%s.checks[%d] remove", mp, i), func(m *controls.Control) { m.Mechanisms[j].Checks = slices.Delete(m.Mechanisms[j].Checks, i, i+1) }) }
		}
		if len(c.Mechanisms) > 1 { add(mp+" remove", func(m *controls.Control) { m.Mechanisms = slices.Delete(m.Mechanisms, j, j+1) }) }
	}
	return out
}
// clauseMutants: op flip (flips[cl.Op]; each->none only when cl.Where != nil, dropping Require), expected mutants when Expected is a literal (a "${…}" string is skipped here — its param row covers it), then the same for cl.Where / cl.Require with path suffix ".where"/".require".
// expectedMutants(out, c, path, v, set): bool → "expected not"; int (yaml decodes to int) → "+1", "-1"; string → `expected "__mutant__"`; []any → drop[i] for each i and "expected []".
```
`lintValid` runs G-3's `controls.Lint` and returns `len(problems) == 0`. Keep the file under 300 lines; helpers get doc comments that name the spec row they implement.
- [ ] **Step 4: The kill loop** (`mutation_test.go`)
```go
func TestEveryMutantIsKilled(t *testing.T) {
	set, _ := controls.LoadDefault(); reg, _ := facts.LoadRegistry()
	strict := os.Getenv("MUSTER_MUTANTS_STRICT") == "1"
	excl := loadExclusions(t, filepath.Join(fixtureRoot, "_mutants.yaml")) // absent → nil in Task 1
	var generated, invalid, killed, surviving, excluded int
	var report []string
	for _, c := range set.Controls {
		if c.Automation == "manual" && len(c.Checks)+len(c.Mechanisms) == 0 { continue } // nothing to judge
		files, _ := filepath.Glob(filepath.Join(fixtureRoot, c.ID, "*.json")); sort.Strings(files)
		snaps := loadSnapshots(t, files) // G-13: once per control; evaluateFixtures takes the loaded snapshots
		base := evaluateFixtures(t, c, set, reg, snaps)
		for _, m := range mutantsOf(c) {
			generated++
			if !lintValid(m.Control, reg) { invalid++; continue }
			got := evaluateFixtures(t, m.Control, set, reg, snaps)
			diff, onlyInternal, firstDiff := compareOutcomes(base, got) // diff: any index differs; onlyInternal: every differing got[i].Reason == check.InternalError; firstDiff: the first differing index (-1 when none)
			switch {
			case diff && onlyInternal: invalid++
			case diff: killed++; if ex := findExclusion(excl, c.ID, m.Signature); ex != nil { t.Errorf("excluded mutant %s %s is now killed by %s", c.ID, m.Signature, files[firstDiff]) }
			case findExclusion(excl, c.ID, m.Signature) != nil: excluded++
			default: surviving++; report = append(report, fmt.Sprintf("%s %s: %d fixtures unchanged", c.ID, m.Signature, len(files)))
			}
		}
	}
	// every exclusion must name a generated signature of its control (checked while iterating: unknown ones are t.Errorf'd)
	t.Logf("mutants: generated %d, invalid %d, killed %d, surviving %d, excluded %d", generated, invalid, killed, surviving, excluded)
	if surviving > 0 { msg := strings.Join(report, "\n"); if strict { t.Errorf("surviving mutants:\n%s", msg) } else { t.Logf("surviving mutants (report mode; set MUSTER_MUTANTS_STRICT=1 to fail):\n%s", msg) } }
}
```
`loadSnapshots` calls `loadFixture` once per file; `evaluateFixtures(t, c, set, reg, snaps []*facts.Snapshot)` builds a one-control `Set{Version, Digest, Controls: []Control{c}}` and returns one `outcome{r.Status, r.ReasonCode}` per snapshot (G-13). Unit-test `compareOutcomes` and `findExclusion` on literals.
- [ ] **Step 5: Run green** and record the first report: `go test ./internal/controls/ -run 'EveryMutantIsKilled' -count=1 -v` — paste the totals line and every surviving signature into the task report the controller receives (Task 2's input). The whole package must stay under 30 s on Windows.
- [ ] **Step 6: Gates, commit.** `Add the control-YAML mutant generator and the kill loop in report mode`.

### Task 2: kill the survivors — fixtures and the exclusion list (F-3, F-4; G-1, G-2)

**Files:** create `controls/testdata/_mutants.yaml`; create fixtures under `controls/testdata/<id>/`; modify `internal/controls/mutation_test.go` (remove the `MUSTER_MUTANTS_STRICT` gate; `_mutants.yaml` becomes required); possibly `controls/*.yaml` + `controls/VERSION` + `CHANGELOG.md` when a mutant proves a control wrong (G-1, own commit).

**Interfaces:** consumes Task 1's report and test; produces the exclusion file and the fixtures.

- [ ] **Step 1: Read the survivor report** (Task 1's report file) and sort survivors into three bins with one line each in the task report: (a) *fixture missing* — a fixture that would kill it is realisable from the collector's real record shapes (the registry descriptions name the fields; the walk rows are in `internal/collect/collectors/walk_traverse.go`); (b) *equivalent* — no fixture can tell the mutant apart (write the reason); (c) *control defect* — the mutant survives because the clause never judged anything (report to the controller before changing the control; G-1).
- [ ] **Step 2: Fixtures for bin (a).** Naming: `<prefix>-mutant-<short>.json` (e.g. `fail-mutant-ne-flip.json`), `synthetic: true`, the minimum facts the control's clauses read, `_expect.reason_code` where the kill is by reason. For `absent_means` mutants: one all-absent fixture per judgment control that lacks one, prefix by the control's `absent_means` (`manual-all-absent.json`, `na-all-absent.json`, `pass-all-absent.json`); every screen fact stays `ok` and only the judged facts are `absent` (G-12); walk-based controls use `walk.complete` ok true with the judged list absent. Bound: at most 64 such fixtures plus the report's survivors; anything that needs a control change stops and reports (G-1). Run the fixture harness after each batch: `go test ./internal/controls/ -run 'EveryControlHasFixturesThatBehave|ManualFixtures' -count=1`.
- [ ] **Step 3: `_mutants.yaml` for bin (b)**
```yaml
# Surviving mutants no fixture can distinguish, one row each; the mutation test
# fails when a row's mutant is killed or is not generated (spec 3F, F-3).
- control: muster.account.password_policy
  mutant: "checks[2].expected +1"
  reason: "lte 90 vs lte 91: every fixture value is 90 or 365; a 91-day fixture would judge the same guide threshold from the other side, which the pass/fail pair already does — equivalent by value spacing"
```
Every reason is specific to that mutant — it names the fixture value spacing or the unreachable shape; a reason that could be pasted onto another row is not a reason.
- [ ] **Step 4: Make the test strict.** Remove the env gate; `loadExclusions` fails when the file is absent; `t.Errorf` on any survivor. `go test ./internal/controls/ -count=1` green; print the final totals line in the report (target: surviving 0; excluded ≤ 40).
- [ ] **Step 5: Gates, commit** (`Kill the surviving mutants with fixtures and record the equivalent ones`; a separate commit per control change, if any, with its CHANGELOG line and VERSION bump).

### Task 3: fuzz targets, seeds, the parser inventory and the nightly workflow (F-5, F-6, F-7; G-5, G-6)

**Files:** create `internal/collect/collectors/fuzz_test.go`, `fuzz_inventory_test.go`, `internal/pkgfiles/fuzz_test.go`, `.github/workflows/fuzz.yml`; modify `Makefile`.

**Interfaces:** produces `memAccess`, `seeds`, `fuzzBody`, the 26 + 4 targets, `coveredThrough`, `TestEveryParserHasAFuzzTarget`, `make fuzz`.

- [ ] **Step 1: Failing tests**
```go
// fuzz_inventory_test.go (G-11): parse every non-test .go file of the package with go/parser; build calls[f] = top-level functions f's body calls; the inventory = top-level funcs whose first param type is []byte, or string named content/line/sel/act; reachable = the transitive closure of calls from every Fuzz* body in fuzz_test.go; every inventory function must be reachable or in notParsers (with a reason). coveredThrough is derived (inventory function → the first Fuzz* that reaches it) and logged. A literal list of the Fuzz* names (30 at least) pins deletions.
func TestEveryParserHasAFuzzTarget(t *testing.T) {}
// seeds: a glob that matches nothing → f.Fatalf (tested through a helper on testing.T that mirrors the check).
func TestSeedsRefuseAnEmptyGlob(t *testing.T) {}
// memAccess: ReadFile returns the bytes, Stat a regular-file meta, Glob matches keys by path.Match; a missing path is os.ErrNotExist.
func TestMemAccess(t *testing.T) {}
```
- [ ] **Step 2: Run red** (compile on Windows with `GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o NUL`; run on the lab).
- [ ] **Step 3: Implement the targets.** Every target has the shape:
```go
func FuzzParsePasswd(f *testing.F) {
	seeds(f, "testdata/passwd*")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "parsePasswd", func() any { rows, n := parsePasswd(data); return []any{rows, n} }, len(data))
	})
}
```
`fuzzBody(t, name, run, inputLen)` calls `run` twice, `reflect.DeepEqual`s the results (fails naming `name` and the first differing path), then walks the result with `reflect` to assert every `[]…` has `Len() <= inputLen+64` (G-6) and every string field named `raw` or filled through `sourceRaw` (the walk names the struct fields the parsers use: `raw`, `line`, `source`) has `len <= rawCap`. Adapters per the spec's F-5 table: `parseSubIDs(data, func(n string) bool { return n == "alice" })`; `parseProcNet(data, "tcp")` and `"tcp6"`; `parseSshdConfig(&memAccess{files: map[string][]byte{"/etc/ssh/sshd_config": data, "/etc/ssh/sshd_config.d/00-fuzz.conf": data}}, "/etc/ssh/sshd_config", o.keyword, 0)` for every `o` in `sshdOptions` (a struct `{keyword, key string; numeric bool}`); `parseIptablesSave("v4", string(data))` and `"v6"`; `parseRsyslogSelector(string(data))`, `parseRsyslogAction(string(data))`, `parseRsyslogActionCall(string(data))`; maps fresh per call for the `*Into` parsers and `parseDropin`. Seed globs from the testdata names as they are (run `ls internal/collect/collectors/testdata` first — a glob matching nothing fails at seed time, G-5): `passwd*`, `group*`, `shadow*`, `subuid*`/`subgid*`, `mountinfo*`, `dpkg.status*`, `apt-get*`, `dnf*`, `rpm*`, `proc_net_*`, `sshd_config*`, `pam/*`, `login*`, `profile*`, `nft*`, `iptables-save*`/`ip6tables-save*`, `vsftpd*`, `pure-ftpd*`, `ftpusers*`/`user_list*`, `main*`, `sendmail*`, `rsyslog*`, `exports*`, `chrony*`; targets added under G-11 seed from the files their parsers' unit tests read; a parser with no testdata file gets one small synthetic seed committed under `testdata/`. `pkgfiles` targets seed from literal lines in the file.
- [ ] **Step 4: Run every target as seeds and one 10-second fuzz each on the lab:** `go test ./internal/collect/collectors/ -run 'Fuzz|EveryParserHasAFuzzTarget|MemAccess|Seeds' -count=1`, then `for t in $(go test -list '^Fuzz' ./internal/collect/collectors/ | grep ^Fuzz); do go test -run '^$' -fuzz "^$t\$" -fuzztime 10s ./internal/collect/collectors/ || echo "FAILED $t"; done` and the same for `./internal/pkgfiles/`. A crash is recorded in the report with the input (Go writes it under `testdata/fuzz/`) and reported to the controller before any parser is changed (G-1).
- [ ] **Step 5: `fuzz.yml` and the Makefile.**
```yaml
name: fuzz
on:
  schedule: [{cron: "17 3 * * *"}]
  workflow_dispatch:
permissions: {contents: read}
jobs:
  fuzz:
    runs-on: ubuntu-24.04
    strategy: {fail-fast: false, matrix: {shard: [0, 1, 2, 3]}}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: "1.25.5", check-latest: false}
      - name: fuzz my share of the targets for 60 s each
        run: |
          set -o pipefail
          targets=$( { go test -list '^Fuzz' ./internal/collect/collectors/ | sed 's#^Fuzz#./internal/collect/collectors/ Fuzz#'; go test -list '^Fuzz' ./internal/pkgfiles/ | sed 's#^Fuzz#./internal/pkgfiles/ Fuzz#'; } | grep ' Fuzz' | sort )
          i=0; failed=0
          while read -r pkg name; do
            if [ $((i % 4)) -eq ${{ matrix.shard }} ]; then
              echo "== $name"
              go test -run '^$' -fuzz "^${name}\$" -fuzztime 60s "$pkg" || failed=1
            fi
            i=$((i+1))
          done <<< "$targets"
          exit $failed
      - name: upload new corpus entries
        if: failure()
        uses: actions/upload-artifact@v4
        with: {name: "fuzz-corpus-shard-${{ matrix.shard }}", path: "internal/**/testdata/fuzz/**", if-no-files-found: ignore}
```
Makefile: `fuzz:` → `go test -run '^$$' -fuzz "^$(TARGET)$$" -fuzztime $(TIME) $(FUZZPKG)` with `TIME ?= 60s`, `FUZZPKG ?= ./internal/collect/collectors/` and a guard that `TARGET` is set; `.PHONY` updated. Validate the YAML (`python -c "import yaml…"`).
- [ ] **Step 6: Gates, commit.** `Add a fuzz target for every parser entry point, the seed corpus and the nightly workflow`.

### Task 4: the daemon oracles in CI (F-8, F-9, F-10; G-7)

**Files:** create `internal/collect/collectors/oracle_test.go`; modify `.github/workflows/ci.yml` (root job: oracle step + seed artifact; container matrix: static test binary run for `init == 'true'` + seed artifact).

**Interfaces:** consumes `parseSshdConfig`, `sshdOptions`, `parsePasswd`, `parseGroup`, `parseMountinfo`, `services`, `enabledFromUnitFile`, `collect.Guard/Host`; produces the four `TestOracle*` pairs and the CI steps.

- [ ] **Step 1: The tests** (all Linux, all begin with `oracleEnabled(t)`)
```go
// sshd: for each kw in sshdOptions, parseSshdConfig(guarded host, "/etc/ssh/sshd_config", kw.keyword, 0); when it returned an ok envelope, find the same keyword in `sshd -T` output (lower-cased first token), map the parser's value through aliases (without-password→prohibit-password; banner "" or unset→"none") and compare case-folded; a keyword the file did not set (envelope absent) is not compared. Mismatch → t.Errorf("sshd: %s: parser %q, sshd -T %q", kw, v, want).
func TestOracleSshdConfig(t *testing.T) {}
// accounts: parsePasswd(/etc/passwd) rows ⊆ getent passwd rows on (name, uid, gid, home, shell); getent-only rows must have uid in [61184, 65519]; same for parseGroup vs getent group on (name, gid, members after trim+dedupe).
func TestOracleAccounts(t *testing.T) {}
// mountinfo: parseMountinfo(/proc/self/mountinfo) → set of (id, fstype, target) equals `findmnt -A -J -o ID,FSTYPE,TARGET` flattened over "children" (keys are lowercase; `id` is a JSON number on util-linux 2.39 — decode as json.Number/float and compare as int).
func TestOracleMountinfo(t *testing.T) {}
// services: run the services collector under its guard on the host; for each row of `services`, enabled must equal OR over row.units of enabledFromUnitFile(UnitFileState, ActiveState=="active") from `systemctl show -p LoadState,ActiveState,UnitFileState,SubState <unit>` (LoadState not-found ⇒ the unit contributes false); active compared only when len(row.ports)==0 && len(row.inetdNames)==0.
func TestOracleServices(t *testing.T) {}
```
Each test ends with `t.Logf("oracle %s: compared %d", pair, n)`; `TestOracleSummary` is not needed — the CI step counts `SKIP` lines.
- [ ] **Step 2: Lab proof:** `lab-run.sh 'cd /root/muster-dev && MUSTER_ORACLE=1 go test ./internal/collect/collectors/ -run Oracle -count=1 -v 2>&1 | grep -E "^(=== RUN|--- |\s+oracle_test.go)" '` — all four pairs run (the lab has sshd, getent, findmnt, systemctl); a mismatch is reported to the controller with both values before any parser or test rule changes.
- [ ] **Step 3: `ci.yml`.** In `collect-root`, after the sudo-run tests step:
```yaml
      - name: the parsers agree with the daemons (oracle)
        run: |
          set -o pipefail
          sudo env PATH="$PATH" GOFLAGS="$GOFLAGS" MUSTER_ORACLE=1 go test ./internal/collect/collectors/ -run Oracle -count=1 -v 2>&1 | tee "$RUNNER_TEMP/oracle.log"
          ! grep -q -- '--- SKIP' "$RUNNER_TEMP/oracle.log"
      - name: seed files from the runner (artifact)
        run: |
          mkdir -p "$RUNNER_TEMP/seeds/sshd" && sudo cp /etc/ssh/sshd_config "$RUNNER_TEMP/seeds/sshd/" && sudo cp -r /etc/ssh/sshd_config.d "$RUNNER_TEMP/seeds/sshd/" 2>/dev/null || true
          cp /etc/passwd /etc/group "$RUNNER_TEMP/seeds/" && cp /proc/self/mountinfo "$RUNNER_TEMP/seeds/mountinfo"
          sudo chown -R "$(id -u)" "$RUNNER_TEMP/seeds"
      - uses: actions/upload-artifact@v4
        with: {name: seeds-runner, path: "${{ runner.temp }}/seeds"}
```
In the build step of `collect-containers` add `CGO_ENABLED=0 go test -c ./internal/collect/collectors/ -o bin/collectors.test`. The container id `cid` is a shell variable local to the "collect inside" `run:` block, which ends with `docker rm -f "$cid"` — so the oracle run goes INSIDE that block, in its `init == "true"` branch, before the removal: `set -o pipefail; docker exec "$cid" env MUSTER_ORACLE=1 /m/collectors.test -test.run Oracle -test.v 2>&1 | tee "$RUNNER_TEMP/muster/containers/oracle.log"` (a mismatch fails the job; a skip for a missing binary is allowed there and counted with `grep -c -- '--- SKIP'` into the log), and the seed copy `docker exec "$cid" sh -c 'cat /etc/passwd' > …` for the four files into `$RUNNER_TEMP/muster/containers/seeds/`, uploaded after the block as `seeds-<image with / and : replaced by ->`.
- [ ] **Step 4: Gates, commit.** `Compare the sshd, account, mountinfo and service parsers with their daemons in CI`.

### Task 5: the example snapshots — workflow, test, the container example (F-11, F-12; G-8)

**Files:** create `.github/workflows/examples.yml`, `cmd/muster/examples_test.go`, `examples/README.md`; modify `cmd/muster/check.go` (extract `newCheckBlock`, G-14), `Makefile` (`examples-fetch`). The example files themselves land in Task 6 from the workflow run.

**Interfaces:** consumes `facts.Load`, `controls.LoadDefault`, `check.Evaluate`, `report.Build/WriteJSON/WriteTable`; produces `newCheckBlock`, `TestExampleReportHelpers`, `TestExamplesLoadAndCheck`, the workflow.

- [ ] **Step 1: The tests**
```go
// cmd/muster/check.go: extract newCheckBlock(set, snap, wf) from runCheck (G-14) — behaviour unchanged; TestCheck* stay green.
// examples_test.go: reportsFor(snap, set) (json bytes, table bytes) using newCheckBlock, WriteJSON and WriteTable{Width: 100}; maskReport(json) blanks check.muster_version/commit/controls_version/controls_digest (parse as map[string]any, re-marshal with sorted keys); tableBody(txt) drops the first line.
// Unit test on a synthetic snapshot (cmd/muster/testdata/full-pass.json): reportsFor twice → identical; maskReport removes exactly the four keys; a snapshot with an extra observation changes the masked JSON.
func TestExampleReportHelpers(t *testing.T) {}
// For every examples/*.json that is not a report: facts.Load; check.Evaluate; no ERROR(internal_error); masked JSON equals masked <name>-report.json; tableBody equals tableBody(<name>-report.txt). With no such file: t.Skip("no example snapshot committed under examples/ yet") — Task 6 makes it live.
func TestExamplesLoadAndCheck(t *testing.T) {}
```
- [ ] **Step 2: `examples.yml`** (`workflow_dispatch` only): build the binary; `collect` in `ubuntu:24.04` (`docker run --rm -v "$PWD/bin:/m:ro" -v "$RUNNER_TEMP/ex:/out" ubuntu:24.04 /m/muster collect --deep --out /out/ubuntu-24.04-container.json`) and on the runner (`sudo ./bin/muster collect --deep --walk-budget 15m --walk-max-entries 6000000 <the same WALK_EXCLUDES as ci.yml> --out "$RUNNER_TEMP/ex/ubuntu-24.04-vm.json"`); the F-11 rewrite for each file: `jq '.run.host.hostname = "<name>" | .run.host.boot_id = "" | .run.host.kernel = "" | .run.host.uptime_s = 0 | (.facts.sockets.listening.value // []) |= map(if (.addr | test("^(127\\.|::1$|0\\.0\\.0\\.0$|::$)") | not) then .addr = "192.0.2.1" else . end)'` (the records are `.facts.sockets.listening.value[]` with `proto, addr, port, inode, loopback`; the implementer confirms against `sockets.go`); the VM snapshot's firewall facts may carry RFC 1918 `saddr` literals from docker's rules — Task 6 reviews the first run's file and extends the rewrite or the gitleaks allowlist with exact literals; refuse a file over 4 MiB; `./bin/muster check --facts <f> --format json > <name>-report.json` and `--format table > <name>-report.txt` (with `NO_COLOR=1`, width 100); upload `examples-${{ github.run_id }}`.
- [ ] **Step 3: Rehearse the workflow's shell on the lab** (G-8: nothing produced here is committed): sync, build a static binary, run the container command with docker (`ubuntu:24.04`, `--platform linux/amd64`) into `/tmp`, apply the `jq` rewrite, and assert on the lab that the rewritten file has `hostname == "ubuntu-container"`, empty `boot_id`/`kernel`, `uptime_s == 0` and no `addr` outside loopback/wildcard/`192.0.2.1` — this proves the jq and the size check before the workflow runs; delete the files afterwards.
- [ ] **Step 4: `examples/README.md`** — the two files, where each comes from (a public image in a GitHub Actions container / the GitHub runner VM; the run id filled in by Task 6), the exact commands, the rewrite rule (hostname, boot_id, kernel, uptime, socket addresses), "no file here comes from anyone's host", and how to refresh (`gh workflow run examples.yml --ref main`, then `make examples-fetch RUN=<id>`). Makefile: `examples-fetch: gh run download $(RUN) -n examples-$(RUN) -D examples/` (guard `RUN` set).
- [ ] **Step 5: Gates, commit.** `Add the example snapshots' workflow, test and README`.

### Task 6: documents, the first runs, Execution notes and the gates (controller)

**Files:** `CONTRIBUTING.md`/`.ko.md` (Tests: a fixture must kill its clause's mutants, survivors are exclusions with reasons; a new parser needs a fuzz target and seeds; refreshing examples), `CLAUDE.md` (Tests: two lines — `MUSTER_MUTANTS_STRICT` is gone by then, so name `_mutants.yaml` and `make fuzz`; `MUSTER_ORACLE=1` on the lab), `README.md`/`.ko.md` ("Example output" paragraph pointing at `examples/`), `CHANGELOG.md` (Tooling: the four subsystems; Controls: nothing unless Task 2 changed a control), the plan's Execution notes.

- [ ] **Step 1:** `git merge-base HEAD main` is main's tip; whole-branch review (two reviewers: the mutation/fixtures side; the fuzz/oracle/examples/CI side), ONE fix wave, a scoped re-review.
- [ ] **Step 2:** Write the documents; gates (G-9), staticcheck on the lab, gitleaks, the host-string grep.
- [ ] **Step 3:** On the user's word: push, PR; trigger `fuzz.yml` and `examples.yml` on the branch (`gh workflow run … --ref stage3f-hardening`); read the fuzz shards (a crash → fix commit + seed per G-1), fetch both examples (`make examples-fetch`), review the VM file for RFC 1918 firewall literals (extend the rewrite or the gitleaks allowlist with exact literals), add the run id to `examples/README.md`, commit; CI green; merge on the user's word.
- [ ] **Step 4:** Execution notes: rulings G-11…, the mutant totals (generated/invalid/killed/excluded) and the exclusion list's size, the first nightly fuzz result, the oracle results per image, the example sizes; parked items.

## Execution notes

Executed 2026-09-17 in the worktree `stage3f-hardening` over main `0fe31c8`: spec `ec9d6e8`, plan `9283b8c`, five implementation tasks with a review and one fix round each, a two-reviewer whole-branch review, one fix wave, a scoped re-review, and the documents. Every gate in G-9 ran green on Windows and on the lab host (suite, race build over `internal/controls` and `internal/collect/...`, the four oracle pairs, staticcheck) and gitleaks over the whole range found nothing.

### Rulings settled during execution (G-15 … G-28; G-1 … G-14 are in Global Constraints)

- **G-15 (no-op mutants):** the generator never emits `expected []` for a list whose shipped default is already empty — the mutant re-encodes the original byte for byte, so nothing could kill it.
- **G-16 (the first crash):** ten seconds of fuzzing found a real defect. `aptPeriodicUnattended` indexed `strings.ToLower(l)` and sliced `l`; ToLower widens an invalid byte to the three-byte U+FFFD, so a fragment with a stray byte before the key panicked the patch collector. Fixed in its own commit with a length-preserving ASCII fold; the crasher is committed as the target's corpus file. CHANGELOG Collectors carries it.
- **G-17 (services oracle vs super-servers):** the collector's `enabled` also folds a super-server hit, which `systemctl` cannot see, so the oracle compares one-directionally for rows with an inetd name or a super-server entry: collector `false` against systemd `true` is always a mismatch; collector `true` against systemd `false` only for a row nothing else could have enabled. Test shaped, collector untouched.
- **G-18 (transient mounts):** the mountinfo pair reads `/proc/self/mountinfo` and runs `findmnt` twice and reports only a difference present in both attempts; set equality is kept.
- **G-19 (sshd oracle on a stock runner):** the CI root job writes a drop-in with all five `sshdOptions` keywords (`PermitRootLogin without-password`, so the alias map is exercised), validates it with `sshd -t`, and takes it out before the seed step; the oracle step asserts `oracle sshd: compared [1-9]`. The test itself stays tolerant — a stock configuration compares nothing and passes — because the CI step is the right owner of the vacuity assertion.
- **G-20 (PermitRootLogin fold):** measured on OpenSSH 9.6p1 (public `ubuntu:24.04`): `sshd -T` prints `without-password` whether the file says `without-password` or `prohibit-password`. The spec's one-way alias would have flagged either spelling, so the fold is symmetric and applied to both sides; every other value is compared exactly. Spec §4 corrected.
- **G-21 (manual controls' gates):** the mutation test skips a manual control only when it has no `applies_when`, no checks and no mechanisms; the four manual service controls' gates are mutated like everyone else's.
- **G-22 (a missing fact is not a kill):** a transition to `ERROR(missing_fact)` from a non-ERROR base shows no difference for that fixture. Fourteen mutants had been "killed" only because a fixture omitted the other mechanism's keys — a shape collect never writes. Those fixtures were completed with the other mechanism's keys present as `absent` envelopes, and the mutants now die on a verdict.
- **G-23 (the examples rewrite):** the jq rewrite substitutes every RFC 1918 IPv4 literal (with its CIDR suffix) in the firewall dumps and rules, the TCP-wrapper and `hosts.equiv` lines, the time-sync servers and the NFS export clients with an RFC 5737 form, sends IPv6 socket addresses to `2001:db8::1`, and ends with a whole-file assertion using the same shapes as `.gitleaks.toml`, so the workflow refuses rather than the pull request.
- **G-24 (example staleness):** the byte comparison of the committed reports runs only when the snapshot's `controls_digest` equals the embedded set's; load, evaluate and the no-`internal_error` assertion always run. This is the spec's "staleness is not gated" made precise: a control change does not turn the example test red, a broken renderer does.
- **G-25 (inventory grammar):** the fuzz inventory lists every function or method with a `[]byte` parameter in any position and follows selector calls, so a parser written as a method is seen. Five parsers the first grammar missed got targets (proftpd, xinetd, inetd, snmpd, ntp); two rsyslog helpers whose output is not proportional to their input are declared in `notParsers` with the reason.
- **G-26 (one walk-exclusion list):** `.github/walk-excludes` is read by `ci.yml` and `examples.yml`; there is no second copy to drift.
- **G-27 (fuzz.yml on its own pull requests):** a `pull_request` trigger on the workflow's path runs the shards with a five-second fuzz time, so an edit to the workflow is exercised before merge; the nightly keeps sixty seconds.
- **G-29 (registering `examples.yml`):** GitHub does not list a workflow that has never run, so a new workflow cannot be dispatched from a branch. `examples.yml` also runs on a pull request that edits it, which registered it and produced this branch's examples; refreshes use `workflow_dispatch`.
- **G-30 (the second crash):** the first sixty-second run of `fuzz.yml` found `parseNftRuleset` indexing the first word of a line that has none — a form feed is whitespace to `strings.Fields` — inside a chain. Guarded, corpus file committed, unit cases added. The nightly budget paid for itself on the first day.
- **G-31 (sshd on the runner):** the GitHub runner installs `openssh-server` without starting it, so `/run/sshd` does not exist and `sshd -t` refuses with "Missing privilege separation directory". The drop-in step creates the directory first. Neither the lab host nor the init containers showed this, because sshd runs on the one and is absent from the others.
- **G-28 (an equivalent gate):** `mail.go` and `dns.go` publish `<svc>.implementation` with `collect.OK` unconditionally, so the `present` gate can never be the sole reason a manual service control is NOT_APPLICABLE; `applies_when[1] remove` on those four controls is an exclusion, not a fixture gap. A fixture the collector cannot produce is never the answer (the same principle as G-22).

### What the reviews found

Per-task reviews: Task 1 clean; Task 2 two unreachable fixture shapes (a gid of -1, an absent PATH list) → one exclusion and one reshaped fixture; Task 3 one Important (a swallowed `go test -list` failure in the shard script) and the G-16 crash; Task 4 one Blocking (the sshd pair compared nothing on a stock runner) plus the super-server and transient-mount shapes; Task 5 two Important (the example binary built without its version; the runner collect without `--require-root`).

Whole-branch (two Fable reviewers, by area): no Blocking on the mutation side (G-21 and G-22 came from it, and an exclusion row naming an invalid mutant now errors); one Blocking on the CI side — the examples rewrite covered only the sockets, and the runner's Docker rules carry `172.17.0.0/16`, so the first VM example would have failed the secrets scan on the pull request (G-23) — plus G-24 … G-27. One fix wave of four commits plus the G-28 follow-up. The scoped re-review (Fable) confirmed every item against the rulings, reproduced the totals and the inventory, and approved with three LOW notes — a banner fixture left in an invented shape, a case-sensitive hostname pattern in the examples assertion, a corrupt committed report skipped rather than failed — which one residual commit closed.

### Deviations from the spec, as shipped

- F-6/F-7: the `pkgfiles` targets join the computed modulo split rather than a fixed shard; with fifty-five targets a nightly shard runs about fourteen minutes, not nine. `notParsers` is nearly empty — `splitLines`, `firstLine`, `sourceRaw` and `showValues` were fuzzed or routed through a parent instead of declared away (stronger than G-11 planned).
- F-8: `findmnt` runs with `-A` (without it findmnt de-duplicates rows); the oracle runs commands through `collect.RunCommand`, not raw `os/exec`; the PermitRootLogin fold is symmetric (G-20); the services rule is one-directional for super-hosted rows (G-17). Spec §4 corrected in both languages.
- F-11: the jq path guard is `(… .value | type) == "array"` — the spec's `// []` form is an invalid jq path expression when the fact carries no value.
- F-12: the staleness gate of G-24.

### Numbers

- Mutants over the 68 controls: generated 1132, invalid 4 (all the `shell_valid_screen` lint rule), killed 1112, surviving 0, excluded 16 (`controls/testdata/_mutants.yaml`); the first run had 255 survivors, all fixture gaps or equivalents. Fixtures added: 168 (all synthetic; 9 all-absent under the G-12 cap of 64; 2 base-only ACL). The package runs in about 2.4 s without the race detector.
- Fuzz: 51 targets in `internal/collect/collectors` and 4 in `internal/pkgfiles` (floor 30); inventory 79 parsers — 54 reached directly, 23 through a parent, 2 declared. Seeds-only run 0.09 s test time on the lab. Ten seconds per target on the lab found one crash (G-16), none after.
- Oracles on the lab host (root): sshd compared 1 keyword (one of five set in that file), accounts 98 rows, mountinfo 175 mounts, services 17 rows, no mismatch. In a public Rocky 9 init container: sshd skipped (no binary), accounts 50, mountinfo 16, services 17, no mismatch. A deliberate mutation of each parser turned its pair red.
- Examples (run 35199955815 on the pull request): the `ubuntu:24.04` container snapshot is 143,413 bytes and the runner-VM `--deep` snapshot 820,349 bytes after the rewrite, against the 4 MiB cap; neither carries a private address, a hostname shape or a mail address (the VM's own nftables output rules name one public Azure platform address, which is infrastructure, not identity); both pass the example test on Windows and Linux.
- First workflow runs on the pull request: `fuzz.yml` at five seconds green on both shards' runs; the dispatched sixty-second run found the G-30 crash on shard 2 and was otherwise green; `ci.yml` failed once on G-31 and once more for the same reason before the fix.

### Parked

- `examples.yml`'s pull-request trigger matches the whole pull request's changed files, so every push to a pull request that touches the workflow re-collects the examples (about fifteen minutes, an artifact nobody fetches). Harmless; a `paths` filter cannot express "only when this push changed it".
- Fuzzing one-line helpers (`firstLine`, `snmpStripComment`) for sixty seconds nightly is wasted budget; harmless, revisit if the nightly grows.
- The inventory grammar still cannot see a parser that takes its bytes as a `string`; such a parser must be declared in `coveredThrough` by hand (the test's comment says so).
