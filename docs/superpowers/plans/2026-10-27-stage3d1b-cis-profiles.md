# Stage 3D-1b — CIS Level 1 profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three built-in profiles (`cis-ubuntu2204-l1`, `cis-ubuntu2404-l1`, `cis-rhel9-l1`) generated from an index of
CIS recommendation numbers that muster derives from pinned ComplianceAsCode control files, with every CIS reference
in the control set held to that index.

**Architecture:** A pure package `internal/cisindex` decodes the pinned files (ids, levels, rules only), muster's
`map.yaml`/`review.yaml`, and builds per benchmark an index (`docs/reference/cis/<product>-<version>.json`) and a
profile (`internal/profile/builtin/cis-*.yaml`). `tools/cisindex` is the thin maintainer-run `main` that fetches,
pins, writes and `-check`s. `internal/controls` loads the index beside STIG's and lints `references.cis`;
`internal/profile` embeds the generated YAML; `cmd/muster` adds the Y-1 lint rule, the host warning and the two
drift tests; `tools/coverage` renders the CIS column and holds the disclaimer.

**Tech Stack:** Go (module `github.com/kun9497/muster`), `gopkg.in/yaml.v3`, `encoding/json`, `//go:embed`.

**Spec:** `docs/superpowers/specs/2026-10-20-stage3d1b-cis-profiles-design.md` (rulings CB-1..CB-16). Read it whole
before any task; every task cites the CB it implements.

## Global Constraints

- Source pin: ComplianceAsCode/content tag `v0.1.82`, commit `3da954fbccfb4ca611da86c9be9205d83c38bfc7`; files
  `controls/cis_ubuntu2204.yml` (2.0.0), `controls/cis_ubuntu2404.yml` (1.0.0), `products/rhel9/controls/cis_rhel9.yml`
  (2.0.0), `controls/cis_almalinux9.yml` (2.0.0, equality proof only).
- Never copy CIS text: no title, note, status, description; only `version`, entry `id`, `levels`, `rules`. The real
  files never enter the tree; tests use synthetic YAML only. The cache is `.cache/cisindex/` (already git-ignored by
  `/.cache/`).
- Grammars: rec `^[0-9]+(\.[0-9]+){1,4}$`; rule id `^[a-z0-9][a-z0-9_-]*$`; a `rules:` element containing `=` is a
  selection `var=value`.
- Product keys `ubuntu2204`, `ubuntu2404`, `rhel9` (aliases `alma9`, `rocky9`); display names "CIS Ubuntu Linux 22.04
  LTS Benchmark", "CIS Ubuntu Linux 24.04 LTS Benchmark", "CIS Red Hat Enterprise Linux 9 Benchmark".
- `internal/cisindex` imports no muster package and no `os`, `os/exec`, `net`, `net/http`, `syscall`.
- No verdict changes (CB-14): no `checks`, facts or parameter defaults change; `default` selects what it selects.
- Disclaimer sentence (CB-13), exact: `The `cis-<distro>-l1` profiles select muster's own controls that carry a CIS
  Benchmark recommendation number at Level 1 – Server; their results are muster's verdicts on muster's controls, not
  a CIS assessment, and muster is an independent publication not authorized, sponsored or otherwise approved by the
  Center for Internet Security.` No output says "CIS compliant", "CIS score", "passes CIS Level 1", "full" or a
  percentage.
- Same input, same bytes: every generated file is sorted, `json.MarshalIndent(v, "", "  ")` + `"\n"`, or yaml.v3 with
  sorted keys.
- Docs: English canonical, `.ko.md` pair in the same commit; the main design pair stays line-aligned (635 lines today).
  Plans are English only.
- Commits: personal identity (pinned); end messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  Never push, never stash/amend/rebase/force.
- Every `[]byte`-taking function gets a `Fuzz<Name>` target with seeds; `.github/workflows/fuzz.yml` lists packages by
  hand and gains each new package line in the commit that adds its first target.
- Test before call site, caller first; delete the call and see red.

## Review Focus

1. A pinned file whose entry lists the same rule id twice (`file_permissions_var_log_cloud-init` on ubuntu2204
   6.2.2.1): read as a set, the `rules` word unaffected — test in Task 2.
2. A snapshot whose `os_release` is empty, or an `id` with trailing case differences (`Ubuntu`): the warning fires
   (empty → "unknown"); matching is exact lower case as the collector writes it — test in Task 8.
3. A site profile that `extends: cis-rhel9-l1` and `exclude`s a control: the warning still fires (chain root) and Y-1
   lint still passes (a subset of a passing set) — test in Task 8.
4. A reference directory with `stig/` but no `cis/` (every existing fixture): load succeeds, `HasCIS` false, a `cis`
   entry under `--references` is reported unindexed, not a crash — test in Task 4.
5. A hand edit of `map.yaml` committed without regenerating: the offline test names the stale side
   (`TestCISMapAndReviewMatchTheIndex`) — test in Task 8 with a doctored copy in `t.TempDir()`.

---

### Task 1: `internal/cisindex` — source decoder, grammars, index type

**Files:**
- Create: `internal/cisindex/source.go`, `internal/cisindex/index.go`, `internal/cisindex/source_test.go`,
  `internal/cisindex/index_test.go`, `internal/cisindex/fuzz_test.go`, `internal/cisindex/imports_test.go`
- Modify: `.github/workflows/fuzz.yml:41-47` (add the `cisindex=` line and its `sed` arm)

**Interfaces:**
- Produces:
  - `func ValidRec(s string) bool`, `func ValidRuleID(s string) bool`
  - `func CompareRec(a, b string) int` — component-wise integer compare (`5.1.7` < `5.1.20`); only valid recs.
  - `type Selection struct{ Var, Value string }`
  - `type Entry struct{ ID string; Levels []string; Rules []string; Selections []Selection }` — `Rules` deduplicated,
    first-seen order; selections split on the first `=`.
  - `type Source struct{ Version string; Entries []Entry }` — helpers (ids failing `ValidRec`) dropped.
  - `func DecodeControls(data []byte) (*Source, error)` — yaml.v3 into a struct with only `version` and
    `controls: [{id, levels, rules}]`; unknown fields ignored (they are dropped by design, CB-2); error on a missing
    `version`, an entry without `id`, or a `rules:` element that is neither a valid rule id nor `var=value` with a
    non-empty var.
  - `func HasLevel(e Entry, level string) bool`
  - `func RuleUnion(srcs ...*Source) map[string]bool`
  - `func SameIDsAndLevels(a, b *Source) error` — names the first differing id.
  - `type Pin struct{ Repo, Tag, Commit, Path, SHA256 string }` (json `repo, tag, commit, path, sha256`)
  - `type EqualTo struct{ Path, SHA256, Compared string }` (json `path, sha256, compared`)
  - `type Counts struct{ L1Server int \`json:"l1_server"\` }`
  - `type Row struct{ Rec string; Levels []string; Controls []string; Rules string }` (json `rec, levels, controls,
    rules`)
  - `type Index struct{ Product, Benchmark, Version string; AppliesTo []string; Source Pin; EqualTo *EqualTo; Counts
    Counts; Recs []Row }` (json `product, benchmark, version, applies_to, source, equal_to,omitempty, counts, recs`)
  - `func RenderIndex(ix *Index) ([]byte, error)` — `AppliesTo` nil renders `[]`; MarshalIndent two spaces + `\n`.
  - `func DecodeIndex(data []byte) (*Index, error)` — `json.Decoder.DisallowUnknownFields`, one value, product and
    version required, every row's rec valid and rules word in `all|some|none`.

- [ ] **Step 1: Write the failing tests**
  - `TestDecodeControlsKeepsOnlyIdsLevelsRules`: synthetic YAML with `title`, `notes`, `status`, `related_rules` on
    entries; assert the decoded `Source` has the entry ids, levels, rules, and that `fmt.Sprintf("%+v", src)` contains
    none of the title strings.
  - `TestDecodeControlsDropsHelpers`: entries `reload_dconf_db`, `enable_authselect`, `1.1.1` → one entry `1.1.1`.
  - `TestDecodeControlsSplitsSelections`: `rules: [a_rule, var_x=14, sshd_idle_timeout_value=5_minutes, a_rule]` →
    `Rules == ["a_rule"]`, `Selections == [{var_x 14} {sshd_idle_timeout_value 5_minutes}]`.
  - `TestDecodeControlsRefusesBadRuleElement`: `"Bad Rule"`, `"=x"` each return an error.
  - `TestValidRuleIDAdmitsHyphens`: `kernel_module_usb-storage_disabled` true; `var=1`, `-x`, `A_b` false.
  - `TestCompareRec`: `5.1.7` < `5.1.20`; `1.10` > `1.9`; equal → 0.
  - `TestSameIDsAndLevels`: equal ids+levels with different rules → nil; a level difference → error naming the id.
  - `TestIndexRoundTrip`: `RenderIndex` then `DecodeIndex` equal; Ubuntu `AppliesTo` renders `"applies_to": []`.
  - `TestDecodeIndexIsStrict`: a row with `"title"` → error; a rules word `"full"` → error.
  - `TestCISIndexImportsNoHostPackages`: the `internal/profile/imports_test.go` pattern over
    `github.com/kun9497/muster/internal/cisindex`, refusing `os`, `os/exec`, `net`, `net/http`, `syscall` and any
    import with prefix `github.com/kun9497/muster/`.
  - `FuzzDecodeControls` and `FuzzDecodeIndex` with the test inputs as seeds; assert no panic and, on success,
    every entry id passes `ValidRec`.

- [ ] **Step 2: Run** `go test ./internal/cisindex/` — expected: build failure (package empty).
- [ ] **Step 3: Implement** the Produces list in `source.go` (decoder, grammars, `CompareRec`, `RuleUnion`,
  `SameIDsAndLevels`, `HasLevel`) and `index.go` (types, render, strict decode).
- [ ] **Step 4: Run** `go test ./internal/cisindex/ && go vet ./internal/cisindex/` — expected: PASS.
- [ ] **Step 5: Add** `cisindex=$(go test -list '^Fuzz' ./internal/cisindex/ | grep '^Fuzz')` and its
  `echo "$cisindex" | sed 's#^#./internal/cisindex/ #'` arm to `fuzz.yml`; `go test -list '^Fuzz' ./internal/cisindex/`
  lists both targets.
- [ ] **Step 6: Commit** `cisindex: decode the pinned ComplianceAsCode control files (ids, levels, rules only) and the index type (CB-2, CB-4)`.

### Task 2: `internal/cisindex` — map, review, build (membership, rules word, vars)

**Files:**
- Create: `internal/cisindex/mapfile.go`, `internal/cisindex/build.go`, `internal/cisindex/mapfile_test.go`,
  `internal/cisindex/build_test.go`; extend `internal/cisindex/fuzz_test.go`

**Interfaces:**
- Consumes: Task 1's `Source`, `Entry`, `Index`, `Row`, `Pin`, `EqualTo`, `ValidRec`, `ValidRuleID`, `CompareRec`.
- Produces:
  - `type RecRow struct{ Rec, Reason string }` (yaml `rec`, `reason`)
  - `type VarRow struct{ Var, Param string; As any; Reason string }` (yaml `var`, `param`, `as,omitempty`,
    `reason,omitempty`); `As` is the string `int` or a `map[string]any` table; `Param: "none"` requires `Reason` and
    no `As`; any other `Param` requires `As` and no `Reason`.
  - `type MapRow struct{ ID string; Rules []string; Vars []VarRow; Recs map[string][]RecRow }` (yaml `id`, `rules`,
    `vars,omitempty`, `recs,omitempty`)
  - `type ReviewRow struct{ Profile, ID, Reason string }`
  - `func DecodeMap(data []byte) ([]MapRow, error)`, `func DecodeReview(data []byte) ([]ReviewRow, error)` — strict
    (`KnownFields(true)`), one document, map rows sorted by id with no duplicate, review rows unique by
    `{profile, id}`, every reason non-empty.
  - `type Benchmark struct{ Product, Display, Profile string; AppliesTo []string; Pin Pin; EqualTo *EqualTo; Src *Source }`
  - `type Env struct{ IDs map[string]bool; ParamType func(control, param string) (string, bool); Check func(typ string, v any) error }`
  - `type ProfileOut struct{ Name string; Include []string; Params map[string]map[string]any }`
  - `func Build(b Benchmark, union map[string]bool, rows []MapRow, review []ReviewRow, env Env) (*Index, *ProfileOut, error)`
    — the error is `errors.Join` of every failure, each `"<product>: <message>"`.
  - `func Candidates(ix *Index) []string` — sorted controls on rows whose levels hold `l1_server`.
  - `func RenderProfile(p *ProfileOut) ([]byte, error)` — first line `# Generated by tools/cisindex from docs/reference/cis; do not edit.`,
    then yaml `profile`, `include`, `params` (yaml.v3 sorts map keys).
  - `var TableKey = regexp.MustCompile(`^([0-9]+|0?[0-7]{3}|[0-9]+_(min|minutes|seconds))$`)`

- [ ] **Step 1: Write the failing tests** (`build_test.go`, one synthetic `Source` fixture of ~8 entries built in Go):
  - `TestBuildReachAndRulesWord`: a row whose rules cover every rule id of entry A → `all`; one of two of entry B →
    `some`; entry C with no rule id reached by `recs:` → `none`; `Controls` on a row reached by both a rule and a
    `recs:` lists both, sorted.
  - `TestBuildDuplicateRuleIdIsASet`: entry with `rules: [r, r]` mapped by `[r]` → `all`.
  - `TestBuildRefusesRecsOnEntryWithRuleIds`: error text contains the entry's rule ids.
  - `TestBuildRefusals` (table): rule id not in `union`; rule id with `=`; map id not in `env.IDs`; `recs:` number not
    in the file; `recs:` number outside the grammar; review row not a candidate; review row naming an unknown profile.
  - `TestBuildCountsOnlyLiteralL1Server`: `counts.l1_server` equals entries whose literal levels hold `l1_server`
    (an `l2_server`-only entry not counted); `Recs` holds only mapped entries, sorted by `CompareRec`.
  - `TestBuildVars` (table): `as: int` with `14` → param 14; `027` under `as: int` → error; table `{"15_min": 900}`
    → 900; table key `cis_ubuntu2204` → error naming the key; selection with no table entry → error; the same
    variable `4` and `5` on two reached entries → error; equal on two → one value; variable not selected → no param;
    a selected variable no `vars:` row names → error naming the variable; `param: none` → no param, no error;
    `env.Check` refusing a table value → error.
  - `TestBuildReviewedOutControl`: a review row for control X on this profile → X absent from `Include` and `Params`,
    X still in the index row's `Controls`, and X's unparseable selection produces no error; but a selected variable on
    X's reached entry that no `vars:` row of X names still fails the build (the worklist is unconditional).
  - `TestBuildParamOnlyForIncluded`: a parameter is written only for an included control.
  - `TestRenderProfileParsesAsAProfile`: the bytes start with the header comment and decode with yaml.v3
    `KnownFields(true)` into a struct with `profile`, `include`, `params`.
  - `mapfile_test.go`: `TestDecodeMapIsStrict` (unknown key, unsorted ids, duplicate id, `param: none` without reason,
    `as` beside `param: none`, empty reason → each an error) and `TestDecodeReviewIsStrict`.
  - `FuzzDecodeMap`, `FuzzDecodeReview` with the valid test inputs as seeds.
- [ ] **Step 2: Run** `go test ./internal/cisindex/` — expected: FAIL (undefined names).
- [ ] **Step 3: Implement** `mapfile.go` (decoders) and `build.go`. The order inside `Build`: validate rows → reach
  (rule-id rows) and `recs:` rows → index rows and words → candidates → minus review → vars over the remaining
  controls only (CB-8 order) → profile. The named-variable check (every variable selected on an `l1_server` entry the
  control's rule ids reach has a `vars:` row) runs over every mapped control, reviewed out or not; conversion, the
  two-values conflict and the type check run over the survivors only. Whether a parameter also drives another clause
  (CB-8 "one to one") is a review judgment written into `map.yaml` as `param: none` (Task 6), not a generator check. Reach for vars is "the `l1_server` entries the control's rule ids reach".
  Table values pass `env.Check(type, v)` with the type from `env.ParamType`; an `as: int` value is an `int`.
- [ ] **Step 4: Run** `go test ./internal/cisindex/ && go vet ./internal/cisindex/` — expected: PASS.
- [ ] **Step 5: Commit** `cisindex: map.yaml and review.yaml, and the build of an index row, a candidate and a profile value (CB-5..CB-8)`.

### Task 3: `tools/cisindex` — fetch, pin, prove, write, check

**Files:**
- Create: `tools/cisindex/main.go`, `tools/cisindex/sources.json`, `tools/cisindex/main_test.go`
- Modify: `Makefile` (targets `cisindex`, `cisindex-check`, add both to `.PHONY`)

**Interfaces:**
- Consumes: Task 2's `DecodeMap`, `DecodeReview`, `Build`, `RenderProfile`; Task 1's `DecodeControls`, `RuleUnion`,
  `SameIDsAndLevels`, `RenderIndex`; `controls.LoadDefault()`, `controls.CheckParamValue`.
- Produces: `docs/reference/cis/<product>-<version>.json` (three), `internal/profile/builtin/cis-<product>-l1.yaml`
  (three). Flags: `-sources` (default `tools/cisindex/sources.json`), `-cache` (default `.cache/cisindex`), `-check`,
  `-ref-dir` (default `docs/reference/cis`), `-profile-dir` (default `internal/profile/builtin`), `-map` and `-review`
  (defaults `docs/reference/cis/map.yaml`, `docs/reference/cis/review.yaml`). Every `main_test` case passes all of them
  under `t.TempDir()`.

`sources.json` is committed in this task with real pins (download each file once, take its SHA-256, and verify it against `gh api
repos/ComplianceAsCode/content/contents/<path>?ref=3da954fbccfb4ca611da86c9be9205d83c38bfc7` — the blob's content
decoded, hashed):

```json
[
  {"product": "ubuntu2204", "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark", "version": "2.0.0", "profile": "cis-ubuntu2204-l1", "applies_to": [], "repo": "ComplianceAsCode/content", "tag": "v0.1.82", "commit": "3da954fbccfb4ca611da86c9be9205d83c38bfc7", "path": "controls/cis_ubuntu2204.yml", "sha256": "…"},
  {"product": "ubuntu2404", "…": "same shape, version 1.0.0, controls/cis_ubuntu2404.yml"},
  {"product": "rhel9", "…": "same shape, version 2.0.0, products/rhel9/controls/cis_rhel9.yml, applies_to [alma9, rocky9]"},
  {"equal_to": "rhel9", "path": "controls/cis_almalinux9.yml", "repo": "…", "tag": "…", "commit": "…", "sha256": "…"}
]
```

Download URL: `https://raw.githubusercontent.com/<repo>/<commit>/<path>`. Cache file `.cache/cisindex/<sha256>`;
a cached or fetched copy whose digest differs from the pin is refused, as `tools/refindex`'s `fetchMember` does.

- [ ] **Step 1: Write the failing tests** in `main_test.go` over a `t.TempDir()` holding synthetic sources (served from
  a pre-filled cache directory, so no network): `TestGenerateWritesIndexAndProfiles` (three JSON + three YAML written,
  bytes equal on a second run), `TestCheckDetectsDrift` (edit one output → `-check` exit 1 naming the file),
  `TestAlmaDifferenceInLevelsFails`, `TestAlmaDifferenceInRulesIsLoggedOnly` (stderr has one line naming the count),
  `TestPinMismatchRefused`. Structure `main` as `run(args []string, stdout, stderr io.Writer) int` with an injectable
  fetch so the tests never touch the network.
- [ ] **Step 2: Run** `go test ./tools/cisindex/` — expected: FAIL.
- [ ] **Step 3: Implement** `run`: load sources → fetch/verify each → decode → `SameIDsAndLevels(rhel9, alma9)` →
  `union := RuleUnion(u2204, u2404, rhel9)` (Alma excluded) → load the set, build `Env` from it
  (`ParamType` from `c.Params[name].Type`, `Check = controls.CheckParamValue`) → `Build` per benchmark → render →
  write or compare. The rhel9 index gets `EqualTo{Path, SHA256, Compared: "ids and levels"}`.
- [ ] **Step 4: Run** `go test ./tools/cisindex/` — expected: PASS.
- [ ] **Step 5: Add** `cisindex:` (`go run ./tools/cisindex`) and `cisindex-check:` (`go run ./tools/cisindex -check`)
  to the Makefile.
- [ ] **Step 6: Commit** `tools/cisindex: fetch the pinned files, prove AlmaLinux equal, write the CIS index and profiles (CB-2, CB-3, §2)`.

### Task 4: `internal/controls` — load the CIS index beside STIG's

**Files:**
- Modify: `internal/controls/references.go`
- Create: `internal/controls/testdata/refs/cis/mini-1.0.0.json`, `internal/controls/references_cis_test.go`,
  `internal/controls/fuzz_references_test.go`
- Modify: `.github/workflows/fuzz.yml` (the `controlspkg=` line for `./internal/controls/`)

**Interfaces:**
- Consumes: `cisindex.DecodeIndex`, `cisindex.Row`.
- Produces on `*ReferenceIndex`:
  - `func (x *ReferenceIndex) HasCIS(product, version, rec string) bool` — canonical product only.
  - `func (x *ReferenceIndex) CISProduct(name string) (product string, alias bool, ok bool)`
  - `func (x *ReferenceIndex) CISLevels(product, version, rec string) ([]string, bool)`
  - `func (x *ReferenceIndex) CISRows(product string) []cisindex.Row` (sorted by rec)
  - `func (x *ReferenceIndex) CISVersion(product string) string`
  - `func loadCIS(x *ReferenceIndex, files []string, read func(string) ([]byte, error)) error` plus
    `func parseCISIndex(data []byte) (*cisindex.Index, error)` (the `[]byte` seam the fuzz target drives).
- The CIS maps are separate from the STIG maps (CB-16); M-4 uniqueness applies within CIS only; no `cis/` directory
  is not an error.

The fixture `mini-1.0.0.json` (`product: mini`, `applies_to: ["minialias"]`, version `1.0.0`, rows `1.1.1`
`[l1_server]` → `muster.x.a` `all`, `2.1` `[l2_server]` → `muster.x.b` `some`).

- [ ] **Step 1: Write the failing tests**: `TestLoadCISIndexAlongsideSTIG` (the testdata `refs` dir: `HasCIS("mini",
  "1.0.0", "1.1.1")` true, wrong version false, `CISProduct("minialias") == ("mini", true, true)`, `CISLevels`
  returns `[l1_server]`); `TestLoadWithoutCISDir` (a temp dir with only `stig/` copied: no error, `HasCIS` false);
  `TestCISDuplicateProductRefused`; `TestCISIndexStrict` (a `title` key fails the load naming the file);
  `TestSTIGAndCISShareProductName` (a CIS `ubuntu2204` beside STIG `ubuntu2204` loads); `FuzzParseCISIndex`.
- [ ] **Step 2: Run** `go test ./internal/controls/ -run 'CIS'` — expected: FAIL.
- [ ] **Step 3: Implement** in `references.go`: after the STIG loop, glob `dir/cis/*.json` sorted and `loadCIS`.
- [ ] **Step 4: Run** `go test ./internal/controls/` — expected: PASS (existing STIG tests unchanged).
- [ ] **Step 5: Add** the `internal/controls` line to `fuzz.yml`.
- [ ] **Step 6: Commit** `controls: load the CIS index in its own namespace beside STIG's (CB-16)`.

### Task 5: `internal/controls` lint — `references_cis`

**Files:**
- Modify: `internal/controls/lint.go:477-481`, `internal/controls/lint_test.go`; `cmd/muster/controls.go:24-28`
  (`--references` help names `cis`), `cmd/muster/controls.go:131` (`shapeOnlyNote`)

**Interfaces:**
- Consumes: Task 4's accessors, `cisindex.ValidRec`.
- Produces: rule `references_cis` messages, exactly:
  - shape: `cis references need benchmark, version and rec` (kept); `cis reference rec %q must look like 5.1.20`;
    `cis reference benchmark %q must look like ubuntu2204` (pattern `^[a-z0-9]+$`, checked with or without an index);
    `cis reference %s@%s %s is listed twice` (benchmark, version, rec).
  - with an index: `cis benchmark %s is an alias of %s; write %s` ; `cis benchmark %q is not in %s`;
    `cis reference %s@%s %s is not in %s` (version or rec missing; `%s` = `filepath.Join(Dir, "cis")`).
- Per entry the checks are one first-match `switch`, as the STIG loop beside it: missing field → benchmark shape → rec
  shape → (index) unknown benchmark → alias → not indexed; the duplicate check runs over the whole list after.
- `shapeOnlyNote` becomes `note: stig, nist_800_53 and cis references checked for shape only; pass --references docs/reference to check them against the index`.

- [ ] **Step 1: Write the failing tests** in `lint_test.go`, one table over a one-control set with the mini index:
  each message above fires for its input; a valid `{mini, 1.0.0, 1.1.1}` passes; without an index only the shape
  messages fire. Update the test that pins `shapeOnlyNote` (`cmd/muster/controls_test.go`). Respell the shared fixture
  `goodControl` (`internal/controls/lint_test.go:54`) to `cis: [{ benchmark: mini, version: "1.0.0", rec: "1.1.1" }]`
  and `internal/controls/testdata/valid/account/example.yaml:11` likewise (update `load_test.go:21`'s expected rec);
  every zero-problem lint test over `goodControl` must stay green, with and without the `testdata/refs` index.
- [ ] **Step 2: Run** `go test ./internal/controls/ -run Lint` — expected: FAIL.
- [ ] **Step 3: Implement** the loop in `lint.go`; update the help text and the note in `cmd/muster/controls.go`.
- [ ] **Step 4: Run** `go test ./internal/controls/ ./cmd/muster/` — expected: PASS except tests that run the real
  set with `--references`: the 13 controls still spelled `ubuntu-22.04` now fail shape. Fix them in this task by
  removing their `cis:` blocks (Task 7 renders the real ones); the set's digest moves — bump `controls/VERSION` to
  `kisa-unix-2026+<today as YYYY.MM.DD>`. No golden under `internal/` embeds the version at 72cc12f (grep the old
  string to confirm); `examples/` does and is refreshed in Task 11, so the examples gate stays red on the branch until
  then, as in earlier stages.
- [ ] **Step 5: Run** `go test ./... && go run ./cmd/muster controls lint --references docs/reference` — PASS / `ok:`.
- [ ] **Step 6: Commit** `controls: lint references.cis against the CIS index; drop the hand-written ubuntu-22.04 entries (CB-9, CB-10)`.

### Task 6: The map, the review list and the first generated index and profiles

This is the judgment task: every row is muster's own review (CB-5). Use the strongest model.

**Files:**
- Create: `docs/reference/cis/map.yaml`, `docs/reference/cis/review.yaml`; generated
  `docs/reference/cis/{ubuntu2204-2.0.0,ubuntu2404-1.0.0,rhel9-2.0.0}.json`,
  `internal/profile/builtin/cis-{ubuntu2204,ubuntu2404,rhel9}-l1.yaml`, `tools/cisindex/sources.json` (sha256 filled)

**Interfaces:**
- Consumes: Task 3's generator.
- Produces: the committed index and profile files every later task reads.

Method, per control of the 117 (`go run ./cmd/muster controls list`):
1. Seed from `.superpowers/sdd/2026-10-20-stage3d1b-cis-profiles/scope-join.md` (the union join; about three in four
   pairs right). For the 59 controls without STIG references, search the decoded rule ids by ComplianceAsCode's naming
   (`sysctl_<key with _>`, `kernel_module_<m>_disabled`, `mount_option_<path>_<opt>`, `service_<x>_disabled`,
   `package_<x>_removed`, `file_permissions_<path>`, `file_owner_<path>`, `sshd_<…>`, `accounts_<…>`).
2. Keep a rule id only when it checks what the control's clauses judge (read the control's `checks`/`mechanisms` and
   the rule's name; when unsure, fetch the rule's `rule.yml` at the pinned commit and read its `ocil`/check only for
   understanding — never copy it).
3. `recs:` only for an entry with no rule id, reason in muster's own words describing the control.
4. Write `vars:` rows for every variable the generator names as unnamed, per CB-8: `as: int`, a table with keys in
   `TableKey` (`session_timeout`: `{"15_min": 900}` → `max_idle`, `{"5_minutes": 300}` → `max_interval`,
   `var_sshd_set_keepalive` `as: int` → `max_count`; `umask_policy`: `{"027": ["027", "077", "0027", "0077"]}` →
   `acceptable`; `lockout_threshold`: `as: int` → `max_attempts`), or `param: none` with a reason. An opaque word for a
   quantity the control has a parameter for (`var_password_hashing_algorithm=cis_ubuntu2204`) → `param: none` and a
   review row "the selection's value is not in the decoded source". `password_policy` gets a review row on all three
   profiles ("min_len drives the login.defs and the pwquality length; the recommendation's rule checks pwquality
   alone").
5. A review row wherever the control's judgment cannot honestly stand for the recommendation, or muster's default is
   weaker than the selection with no parameter carrying it.

- [ ] **Step 1: Run** `go run ./tools/cisindex` with an empty `map.yaml` (`[]`) and `review.yaml` (`[]`) to fill the
  cache. Expected: three indexes with empty `recs` and the `counts.l1_server` per file.
- [ ] **Step 2: Write** `map.yaml` and `review.yaml` per the method; rerun until the generator exits 0.
- [ ] **Step 3: Review** the result: for 20 rows chosen across categories, re-read the control and the rule ids and
  confirm the pair; record per benchmark the number of candidates, `all`/`some`/`none` rows, reviewed-out controls and
  `vars:` rows in the commit message.
- [ ] **Step 4: Run** `go run ./tools/cisindex -check` — exit 0; `grep -ri title docs/reference/cis internal/profile/builtin` — nothing.
- [ ] **Step 5: Commit** `cis: map muster's controls to ComplianceAsCode rule ids; generate the CIS index and the three profiles (CB-5..CB-8)`.

### Task 7: Controls carry `references.cis` as the index renders it

**Files:**
- Modify: every `controls/**/*.yaml` the index names; create `internal/controls/cisrefs_test.go`
- Modify: `controls/VERSION` (bump again if Task 5's date differs), version goldens

**Interfaces:**
- Consumes: `LoadReferenceIndex("../../docs/reference")`, `CISRows`, `cisindex.CompareRec`.
- Produces: `TestEveryCISReferenceIsTheIndex`.

- [ ] **Step 1: Write the failing test** `TestEveryCISReferenceIsTheIndex`: for each control, the expected list is
  every `{product, version, rec}` whose index row's `controls` holds it, sorted by product then `CompareRec`; compare
  with `c.References.CIS` exactly; on a difference print the expected block as YAML flow lines
  (`  cis:\n    - { benchmark: rhel9, version: "2.0.0", rec: "5.1.20" }`).
- [ ] **Step 2: Run** `go test ./internal/controls/ -run TestEveryCISReferenceIsTheIndex` — FAIL listing blocks.
- [ ] **Step 3: Paste** each printed block into its control after `kisa:` (beyond controls too, CB-12).
- [ ] **Step 4: Run** `go test ./... && make lint-controls` — PASS; the mutation test reports zero survivors.
- [ ] **Step 5: Commit** `controls: references.cis rendered from the CIS index (CB-9, CB-12)`.

### Task 8: Embedded built-ins, the Y-1 rule, the host warning and the drift tests

**Files:**
- Create: `internal/profile/builtin/default.yaml`, `internal/profile/builtins.go`, `internal/profile/cis.go`,
  `internal/profile/cis_test.go`, `cmd/muster/cis.go`, `cmd/muster/cis_test.go`
- Modify: `internal/profile/profile.go:59-77`, `cmd/muster/controls.go:262-273`, `cmd/muster/check.go:18-30,241`,
  `cmd/muster/fix.go:21,140`, `Makefile` (`lint-controls`), `.github/workflows/ci.yml:51-54`

**Interfaces:**
- Consumes: the generated YAML (Task 6), `cisindex.DecodeMap/DecodeReview/DecodeIndex/Candidates`,
  `ReferenceIndex.CISLevels`.
- Produces:
  - `internal/profile`: `//go:embed builtin/*.yaml`; `Builtins()` returns
    `["default", "cis-rhel9-l1", "cis-ubuntu2204-l1", "cis-ubuntu2404-l1", "kisa-unix-2026"]` (`default` first, then
    the CIS names sorted, then the alias; the `check` usage line uses the same order); `type CIS struct{ Profile, Benchmark string; Targets []string }` with
    `func (c CIS) Matches(id, versionID string) bool`; `func CISBenchmark(name string) (CIS, bool)`; `func
    CISRoot(chain []string) (CIS, bool)` (reads `chain[0]`, `builtin:<name>`). Targets: ubuntu2204 `[ubuntu2204]`,
    ubuntu2404 `[ubuntu2404]`, rhel9 `[rhel9, alma9, rocky9]`. Match per CB-11: ubuntu2204 ⇔ id `ubuntu` and
    version_id `22.04`; ubuntu2404 ⇔ `ubuntu`, `24.04`; rhel9 ⇔ id ∈ {`rhel`, `rocky`, `almalinux`} and the first
    dotted component of version_id `9`.
  - `cmd/muster`: `func warnCISHost(chain []string, rel facts.OSRelease, warn func(string))` emitting
    `profile <name> is built for <targets joined ", ">; the snapshot is <id> <version_id>` or `…; the snapshot's os
    release is unknown` (empty id or version_id); `func lintCISProfile(sel *Selection, idx *controls.ReferenceIndex)
    []string` returning one line per selected control lacking a reference on the benchmark (with `idx`, an indexed
    level `l1_server`; without, any entry on the benchmark): `profile <name> selects <id>, which carries no <benchmark>
    CIS reference at Level 1 – Server` / `…, which carries no <benchmark> CIS reference`.
  - `check` usage: the `--profile` line lists `default, kisa-unix-2026, cis-ubuntu2204-l1, cis-ubuntu2404-l1,
    cis-rhel9-l1` and a following paragraph holds the CB-13 sentence verbatim; `fix`'s `--profile` line (`fix.go:21`)
    names the same built-ins.

- [ ] **Step 1: Write the failing tests**
  - `internal/profile/cis_test.go`: `TestEmbeddedBuiltinsLoadStrictly` (each embedded file parses; `default` resolves to
    every control as before); `TestCISBuiltinsResolveWithTheirParams` (each CIS built-in resolves against
    `controls.LoadDefault()`, every `params` value passes `controls.CheckParamValue` against its control's type);
    `TestCISBenchmarkTable` (the four names: three found, `default` not); `TestCISMatches` (table: `ubuntu 22.04`,
    `ubuntu 24.04`, `rhel 9.4`, `rocky 9.3`, `almalinux 9`, `centos 9`, `rhel 8.9`, `Ubuntu 22.04` (no match: the
    collector writes os-release ids as given, and they are lower case), `ubuntu ""`, `"" ""`).
  - `cmd/muster/cis_test.go`: `TestCISProfilesMatchTheIndex` (per built-in: its `include` equals `Candidates` of the
    tree's index minus `review.yaml` rows for that profile); `TestCISMapAndReviewMatchTheIndex` (every `map.yaml` id
    in some row's `controls` and the reverse; every `recs:` number a row; every review row a candidate the profile
    omits; every `params` key a selected control; plus Review Focus 5: a doctored `map.yaml` copy in `t.TempDir()`
    with a removed row fails naming the control); `TestControlsLintCISProfiles` (`controls lint --references
    ../../docs/reference --profile <each CIS>` exit 0; a temp profile extending `cis-rhel9-l1` and including a control
    without a rhel9 reference fails with the message; without `--references` the shape-only path);
    `TestCheckWarnsOnAnotherHost` and `TestFixWarnsOnAnotherHost` (a Rocky 9 snapshot under `cis-ubuntu2204-l1`
    → one stderr line exact; a matching host → none; an empty os-release → "unknown"; a temp file `extends:
    cis-rhel9-l1` with an `exclude` on an Ubuntu snapshot → the warning; stdout bytes and exit code equal to a run
    without the warning); `TestUnknownProfileListsBuiltins`. Update the three tests that pin the old list substring
    `default, kisa-unix-2026` to the new joined list: `cmd/muster/selection_test.go:61`, `cmd/muster/e2e_test.go:1189`,
    `internal/profile/resolve_test.go:176`.
- [ ] **Step 2: Run** `go test ./internal/profile/ ./cmd/muster/` — FAIL.
- [ ] **Step 3: Implement** the embed (move `default` to `builtin/default.yaml` with `profile: default` and `include:
  [muster.*]`; the alias stays in Go), `cis.go`, `cmd/muster/cis.go`; call `warnCISHost(sel.Profile.Extends,
  snap.Run.Host.OSRelease, warn)` right after `resolveSelection` in `check.go` and `fix.go`; in `controls lint` run
  `lintCISProfile` after `resolveSelection` and before the profile `ok:` line, printing each line to stderr, a count
  line `muster: %d lint problem(s)` and exit 2.
- [ ] **Step 4: Add** to the Makefile `lint-controls` and to `ci.yml` (one step each) `controls lint --references
  docs/reference --profile cis-ubuntu2204-l1` and the other two.
- [ ] **Step 5: Run** `go test ./... && make lint-controls` — PASS.
- [ ] **Step 6: Commit** `profile, cmd: embed the CIS built-ins; lint Y-1; warn on a host the benchmark does not cover (CB-1, CB-10, CB-11)`.

### Task 9: Coverage column, per-benchmark line, the held disclaimer

**Files:**
- Modify: `tools/coverage/main.go`, `tools/coverage/render.go`, `tools/coverage/render_test.go`,
  `tools/coverage/main_test.go`; regenerate `docs/reference/coverage.md`

**Interfaces:**
- Consumes: `cisindex.DecodeIndex` over `<-references>/cis/*.json` (new flag `-references`, default `docs/reference`).
- Produces: a `CIS recs` column after `Automation` in the KISA table and after `STIG ids` in the beyond table: cell
  `<product> <rec>[ (some|none)][, <rec>…]` groups joined `; `, `—` when none; a section `## CIS Benchmarks` with one
  line per index in product order: `N controls map M of K Level 1 – Server recommendations (<benchmark> v<version>, via
  ComplianceAsCode <tag>)`, N the distinct controls on rows with `l1_server`, M those rows, K `counts.l1_server`, then
  the `equal_to` sentence for rhel9 ("on AlmaLinux and Rocky hosts the profile carries RHEL 9's coverage words and
  parameter values"). A `-references` directory with no `cis/` renders `—` in every CIS cell and no CIS section; a
  directory that does not exist is an error (exit 2). The disclaimer half of `-check` is Task 10's.

- [ ] **Step 1: Write the failing tests**: render with a two-row fixture index (a `some` and a `none` cell, the line's
  numbers; no rendered CIS cell or line contains `%`). In `main_test.go` add `repoReferences =
  filepath.Join(repoRoot, "docs", "reference")` and pass `-references` on every `run` call; update the pinned table rows
  in `render_test.go` to the added column (deferred and not-enrolled rows get `—`).
- [ ] **Step 2: Run** `go test ./tools/coverage/` — FAIL.
- [ ] **Step 3: Implement**; `go run ./tools/coverage` regenerates `coverage.md`.
- [ ] **Step 4: Run** `go test ./tools/coverage/ && go run ./tools/coverage -check` — PASS.
- [ ] **Step 5: Commit** `coverage: a CIS recs column and one line per benchmark (§5)`.

### Task 10: Documents

**Files:** `README.md`/`README.ko.md`, `NOTICE`, `ATTRIBUTION.md`, `CONTRIBUTING.md`/`CONTRIBUTING.ko.md`, `CHANGELOG.md`,
`CLAUDE.md`, `tools/coverage/main.go`, `tools/coverage/main_test.go`,
`docs/superpowers/specs/2026-09-02-muster-design.md`/`.ko.md`, `docs/superpowers/specs/2026-10-07-stage3d1-profiles-design.md`/`.ko.md`.

Follow the spec §5 "Documents" list item by item; the pointers there (`:50`, `:66`, `:238`, `:352`, `:509`, `:510`,
`:551`, §10.2, README `:156-158`, `:165-167`, `:241-243`) were checked at 72cc12f — re-find each by its sentence.

- [ ] **Step 1: NOTICE** gains the CB-13 sentence and the CB-15 section: heading `ComplianceAsCode`, the pin (repo, tag,
  commit, four paths), the CB-2 sentence on decoded fields, then the BSD-3-Clause text verbatim from the pinned
  `LICENSE` (fetch it at the commit; `Copyright (c) 2012-2017, Red Hat, Inc.`, three conditions, disclaimer).
- [ ] **Step 2: ATTRIBUTION.md** "CIS Benchmarks" section replaced per spec §5 (publisher and marks with ®, benchmarks
  referenced and linked, licence and terms, what is reproduced and what is not, the Rocky 9 inference, the AlmaLinux
  proof, the CB-13 sentence, the pointer to NOTICE).
- [ ] **Step 3: README pair**: status, the three profiles with one example command, the disclaimer (English verbatim;
  Korean rendering in README.ko.md), the counts at `:156-158` recomputed from the tree (`controls list`; count STIG,
  NIST and CIS carriers), the two "waits for 3D-1b" sentences.
- [ ] **Step 4: Main design pair**: each pointer; D35 (CB-4 mapped-only index, CB-9 index as source, CB-12 beyond rule)
  added at the end of §13 in both files with the same line count; `wc -l` equal on both.
- [ ] **Step 5: CONTRIBUTING pair** (beyond rule reworded at `CONTRIBUTING.md:84` and `CONTRIBUTING.ko.md:65`; "Mapping a control to CIS" section: rule ids reviewed against the
  clauses, `recs:` only for an entry with no rule id, reasons describe the control, `vars:` per CB-8, regenerate with
  `make cisindex` in the same commit), **CLAUDE.md** (a "CIS profiles (stage 3D-1b)" note: built-ins, index, generator,
  `internal/cisindex` purity, the three tests, maintainer-run `cisindex -check`; also the `make lint-controls` bullet —
  default plus the three CIS profiles — and `make cisindex`/`cisindex-check` beside `refindex`), **CHANGELOG**, the 3D-1 design pair's
  Y-1 and parked list.
- [ ] **Step 6: Hold the disclaimer**: `tools/coverage -check` also requires the CB-13 sentence (space-normalised) in
  `README.md`, `NOTICE` and `ATTRIBUTION.md` under `-readme-dir`; test it failing naming the file when one lacks it,
  and add NOTICE and ATTRIBUTION.md (with the sentence) to each temp `-readme-dir` fixture in `main_test.go`, keeping
  each case's expected first error.
- [ ] **Step 7: Run** `go run ./tools/coverage -check && go test ./... && make lint` — PASS; `grep -rn "CIS compliant\|CIS score\|passes CIS" --include=*.md . | grep -v specs/` — only the CB-13-style negations.
- [ ] **Step 8: Commit** `docs: 3D-1b — CIS profiles, the index, the boundary and D35 (English and Korean)`.

### Task 11: Branch gates and examples

- [ ] **Step 1: Run** every gate: `gofmt -l .` (empty), `go vet ./...`, `go test ./...`, `make lint-controls`,
  `go run ./tools/coverage -check`, `go run ./tools/cisindex -check`, `make shellcheck` on the lab
  (`bash C:/Users/ssk/muster-lab/lab-sync.sh <worktree>` then `lab-run.sh 'cd /root/muster-dev && make test shellcheck'`).
- [ ] **Step 2: Hand off** to the user: the push, the `examples.yml` dispatch and the examples refresh
  (`make examples-fetch RUN=<id>`, the set's digest moved; `default` runs, so no verdict should move — confirm with a
  diff) each need the user's word.

## Execution notes

- Pre-flight (wf_a091af5e-f74, 124 agents): 20 confirmed folded — the disclaimer check moved to Task 10 (Task 9's
  commit would be red), CONTRIBUTING.ko.md, the unconditional named-variable check, `goodControl` respelled, the three
  built-in-list pins, the Builtins order, `-sources`/`-map`/`-review` flags, the `minialias` fixture and a first-match
  switch, the duplicate message, the coverage tests' `-references`, CLAUDE.md's bullets. The spec's "a parameter that
  feeds another clause" test is a `map.yaml` review judgment (Task 6), not a generator check. Beyond the spec's two CIS
  accessors the plan adds `CISProduct` (alias refusal) and `CISVersion`.
