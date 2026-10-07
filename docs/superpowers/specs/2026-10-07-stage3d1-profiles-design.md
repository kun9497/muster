# Stage 3D-1 — profiles and tuning

Korean pair: `2026-10-07-stage3d1-profiles-design.ko.md`. Decisions here are Y-1 … Y-9; the main
design's §6.6 is realised by this document and gains D33.

## 1. Scope and intent

Stage 3D of the roadmap (main design §10.2) bundles three independent pieces: profiles and
tuning (§6.6), `fix --dry-run`, and two flags (`--anonymize`, `--max-age`). This cycle is the
first of them. A **profile** is the list of questions muster asks a host — which controls, with
which parameter values, at which severity. A **tuning file** is one site's values for those
parameters. Both are read by `check` alone; `collect` never sees them, every collector still runs,
and the snapshot is the same whatever profile later reads it.

Why first: it closes the §6.6 contract (D18 — the values in force are in the result), it is pure
check-side work that runs on every platform, and `fix --dry-run` (3D-2) then has a defined meaning:
"the failures of the profile in force", obtained through the same helper `check` uses (§5).

- **Y-1 — Mechanism only; the CIS profile waits for its index.** The built-in profile is `default`
  (every control; `kisa-unix-2026` is an alias of it); `cis-<distro>-l1` is the next cycle, once a
  CIS recommendation ↔ control index exists under `docs/reference/cis/` (numbers and versions only
  — CIS text is never copied, ATTRIBUTION.md). This document fixes only the naming and one
  checkable rule for that cycle: every control such a profile selects carries a `references.cis`
  entry (a lint rule of 3D-1b).
- **Y-2 — An excluded control is not evaluated and not listed.** The result records the profile
  (name, source, digest, chain) and the excluded ids; no new status, one additive row field
  (`severity_source`), the exit-code rule unchanged. The waiver rule changes in one place only: a
  waiver naming an excluded control is `not_applied` (excluded by profile), not `unknown`.
- **Y-3 — Selection by control-id globs only.** Ids already carry category and scope
  (`muster.<category>.<name>`, `muster.beyond.<name>`); `include`/`exclude` are lists of patterns.
  No named dimensions, no expression language.
- **Y-4 — Severity is overridden per control, by the same globs, later entries winning.** The
  importance → severity derivation (상 → high, 중 → medium, 하 → low) stays the default; the result
  carries each row's severity and its source.
- **Y-5 — Tuning holds site values only, applied after the profile.** Precedence: control default
  < profile `params` < tuning. Exact ids, strict typing against the control's `params` declaration.
- **Y-6 — One flag each, built-in or file.** `--profile <name|path>`, `--tuning <path>`; `extends`
  names a built-in or a path relative to the file; no profile directory, nothing inside the waiver
  file.
- **Y-7 — The profile is resolved before evaluation; the evaluator stays pure.** `internal/profile`
  resolves a profile against the loaded control set into a selected-id set, the values the chain
  sets and an ordered severity list, then merges the tuning in; `check` evaluates a subset view of
  the set; the report applies the severity map.
- **Y-8 — Strict at load, lenient at the seam.** Unknown keys, unmatched or malformed patterns,
  unknown controls or parameters, mistyped values, an unknown severity level, a cycle, a chain over
  four files and an empty selection refuse the file. A profile or tuning parameter that names a
  control the profile excludes is a warning and the value appears nowhere in the result, so a
  tuning file survives a profile swap.
- **Y-9 — Every change to the result is additive and lives in `check`.** New fields beside the old
  ones under the result's `check` block; `run` (the snapshot's provenance, §9) is untouched; the
  JSON and table goldens regenerate with a reviewed diff; the examples are refreshed from the
  branch's run.

## 2. Architecture

```
controls.LoadDefault()
   │
   ▼
profile.Resolve(set, src, open, warn) ──► Resolved{IDs, Params (chain values), Severity (ordered), SeverityByID, Digest, Chain}
   │                                                  │
   │      tuning.Load(set, path, open) ──► Tuning{Params, Digest}
   ▼                                                  ▼
profile.Merge(set, resolved, tuning, warn) ──► params in force + sources (default < profile < tuning)
   │
   ▼
cmd/muster resolveSelection(profileArg, tuningPath, set, warn) ──► Selection{subset, params, sources, SeverityByID, blocks}
   │
   ▼
check.Evaluate(snap, subset, reg, Options{Params}) ──► waiver.Apply(results, known, excluded, now, warn)
   │
   ▼
report.Build(snap, results, cb, severity) ──► JSON / table / exit code
```

- **`internal/profile` (new).** `Parse([]byte) (*File, error)` — strict YAML, one document per file
  (a second YAML document refuses the file: `more than one YAML document`; the tuning and waiver loaders
  apply the same rule). `SourceOf(s string)
  Source` — the one name-versus-path classifier (§3), used for the flag and for every `extends`
  value; `Source{Name string; Path string}`. `Resolve(set *controls.Set, src Source, open
  func(path string) ([]byte, error), warn func(string)) (*Resolved, error)` — follows `extends`
  through `open` (so the caller decides what a readable file is: `cmd/muster` wraps `trustedFile`
  and `os.ReadFile`, tests pass `os.ReadFile`), applies include/exclude, validates params and
  severity against the set, keeps every chain value in `Resolved.Params` (selected or not — the
  file's resolved content), derives `Resolved.SeverityByID` over the selected ids (last matching
  entry wins) and warns `severity entry <glob> matches only excluded controls` for an entry that
  reaches no selected control (the entry stays in the list), computes the digest. `Merge(set,
  resolved, tuning, warn) (params, sources)` — the three-way merge with per-parameter provenance
  and the ONE owner of the excluded-control warnings: a profile or tuning value for a control the
  selection excludes is warned once per (control, parameter) — `profile parameter <id>.<param>
  ignored: excluded by profile` / `tuning parameter <id>.<param> ignored: excluded by profile` —
  and dropped; a nil tuning is the no-`--tuning` case. The built-in `default` is a Go literal in the package (there is no
  YAML file for it); `Builtins()` lists the built-in names, canonical first, for refusals. Depends on `internal/controls` and `internal/tuning` only; never writes to
  stderr (§7.4).
- **`internal/tuning` (new, small).** `Parse([]byte)`, `Load(set, path, open)` — the `params:`
  map validated for unknown controls, unknown parameters and types against the full set; returns
  the per-control map and the file's digest. It does not know the selection; the exclusion warning
  is `Merge`'s.
- **`internal/controls`.** `Set.Subset(ids []string) *Set` — a view in the set's order, carrying
  the full set's `Version` and `Digest` (the controls digest names the embedded YAML, never a
  selection) and its own rebuilt id index. `CheckParamValue(typ string, v any) error` — the typing
  the lint already does for defaults, exported so the profile and tuning validators share it. No
  profile check inside `internal/controls` (it cannot import `internal/profile`): `Resolve` returns
  the refusals and `cmd/muster` reports them.
- **`internal/waiver`.** `Apply(results, known, excluded, now, warn)`: `known` is the evaluated
  subset's ids, `excluded` the rest of the loaded set; the tests run in this order — excluded →
  unknown → expired → rows — so one waiver lands in one tally: an id in `excluded` is counted
  `not_applied` with the warning `waiver for <id> not applied: excluded by profile` whatever its
  expiry and whether or not it names a subject; an id in neither set stays `unknown`. No row
  carries the note (the control has no row).
- **`internal/check`.** Unchanged in behaviour; `Options.Params` is the merged map. `Result` is
  unchanged (severity is a report concern, as today: `report.Row.Severity`).
- **`internal/report`.** `Build(snap, results, cb, severity map[string]string)` records
  `severity_source` on each row; `CheckBlock` gains `Profile`, `Tuning` and `ParamSources`; the
  table prints one profile line.
- **`cmd/muster`.** One helper, `resolveSelection(profileArg, tuningPath string, set
  *controls.Set, warn func(string)) (*Selection, error)`: `SourceOf` → `Resolve` with the trusted
  `open` → `tuning.Load` (when `tuningPath` is set) → `Merge` → `Subset`; no logic of its own beyond
  the wiring (main design §4.2). `check`, `controls lint --profile` and `controls list --profile`
  (both with an empty `tuningPath`; the trusted `open` applies to them as root too), the examples
  test (`"default", ""`; G-14: one implementation) and, in 3D-2, `fix` call it. `check --profile`, `check --tuning`;
  `controls lint --profile`; `controls list --profile`.

## 3. The profile file

```yaml
profile: site-web-2026            # [a-z0-9][a-z0-9-]*, required; may not repeat a built-in name
extends: default                  # a built-in name or a path relative to this file; optional
include: ["muster.*"]             # id globs, applied after extends
exclude: ["muster.beyond.no_deleted_executables", "muster.file.ip_port_restriction"]
params:                           # exact ids → parameter → value
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, tcp/443]
severity:                         # ordered: a later entry wins
  - { controls: "muster.beyond.*", level: low }
  - { controls: muster.file.world_writable, level: high }
```

- **Globs.** A pattern is matched against the control id with `path.Match`; `*` crosses `.` (the
  rule `Builder.Get` uses for fact globs, `internal/collect/facts.go`), so `muster.beyond.*` is
  every beyond control and `muster.file.*` one category. `?` and `[…]` are allowed (a class negates with `[^…]`, as `path.Match` reads it,
  not the shell's `[!…]`). A pattern `path.Match` rejects refuses the file naming the pattern; a well-formed pattern that matches no
  control of the loaded set refuses it too (a typo never silently selects nothing). Patterns are
  validated against the loaded set, not the selection: an `exclude` that removes nothing is legal
  and silent.
- **Names and paths (`SourceOf`).** A value with no `/`, no `\` and no `.yaml`/`.yml` suffix is a
  **name**: it is looked up among the built-ins (`default`, `kisa-unix-2026`) and refused naming
  them when it is none of them — so `Default`, `site_web` or `kisa.unix.2026` are refused as
  unknown names, never opened as files. Anything else is a **path** (`filepath` rules on every
  platform): relative to the working directory for the flag, relative to the referring file's
  directory for `extends` (an absolute `extends` value is opened as given), recorded as the cleaned
  path muster opened. The grammar
  `[a-z0-9][a-z0-9-]*` constrains what a built-in and a file's `profile:` field may be called; a
  file whose `profile:` repeats a built-in name is refused. A repeated flag keeps the last value,
  as every `check` flag does.
- **Resolution.** The `extends` chain is walked root-first; it holds at most four files, the
  built-in counted, identified by their cleaned opened paths (a longer chain, a cycle, a missing
  file or an unknown name refuses). Per file, in this order: `selection = parent.selection ∪
  matches(include) − matches(exclude)` — a parent's `exclude` is not a rule the child inherits,
  only a selection the child may add to again; `params` merge per (control, parameter), the child
  winning; `severity` entries are appended after the parent's. A file with no `extends` starts
  from the empty selection. The built-in `default` is `{profile: default, include: ["muster.*"]}`;
  `kisa-unix-2026` names the same object and resolves to it (the result and the chain show
  `default`).
- **Params.** The value is decoded against the control's declared `params.<name>.type`
  (`int`, `string`, `bool`, `list<int>`, `list<string>` — the existing vocabulary, through
  `controls.CheckParamValue`); a wrong type, an unknown parameter or an unknown control refuses
  the file. A parameter for a control the resolved selection excludes stays in `Resolved.Params` and is
  warned and dropped by `Merge` (Y-8); it reaches neither `params` nor `param_sources`.
- **Severity.** `level` ∈ {high, medium, low}; the last matching entry wins; an entry whose glob
  matches no control refuses the file; one that matches only excluded controls warns and stays in the list (and the digest); the
  per-id map the report receives is derived over the selected ids, last entry winning.
- **Empty selection** refuses the file ("profile selects no control").
- **Digest.** `sha256` of the canonical JSON of the resolved content only — `{ids: sorted,
  params: the values the chain sets (child over parent; never a control default, never the
  tuning), sorted by control then parameter, severity: [{controls, level}…] in order}`. The
  name, the source and the chain are recorded beside it, never inside it, so two files that select
  the same controls with the same values and the same severity entries have the same digest
  whatever their names, paths or the order of their `include` lists; a changed value changes it; a
  control set that ships a new default does not; a chain value for an excluded control is inside
  it (the digest names the file's resolved content — a swap that re-includes the control changes
  the selection, not the values).

## 4. The tuning file

```yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/443]
  muster.account.password_policy:
    min_len: 12
```

Exact ids, the same type validation, applied after the profile's params. A parameter for a control
the profile excludes → warning, value dropped (`Merge`). No `include`, `exclude`, `severity` or
`extends`: a tuning file carries a site's numbers and nothing that changes which questions are
asked. Its digest is `sha256` of the file's bytes, as the waiver file's is.

## 5. Integration

- **Flags.** `check --profile <name|path>` (default `default`) and `check --tuning <path>`; an empty
  value given to either flag is refused by every command that takes it (exit 2), never read as the flag's absence;
  `controls lint --profile <name|path>` runs the existing lint and then resolves the profile
  against the embedded set, printing `ok: profile <name> selects N of M controls, K excluded`
  after the existing `ok:` line (a refusal exits 2, warnings go to stderr with exit 0; the
  directories the full lint needs are still needed — this is the maintainers' and CI's command);
  `controls list --profile <name|path>` resolves the profile and prints the existing four-column
  rows (id, importance, automation, title) for the selected controls only, in set order (an
  operator's way to validate a site profile; a refusal exits 2). CI runs `controls lint --profile
  default` in the `test` job beside the existing lint call (`ci.yml`, not only the Makefile).
- **Trusted files.** When `check` runs as root, the profile, every file its `extends` chain reaches
  and the tuning file must be root-owned and not group- or other-writable, as the waiver file is
  (`trustedFile`, D12): the `open` function `cmd/muster` hands to `Resolve` and `Load` checks the
  path before reading it, so an untrusted chain file is refused at the point it is reached and
  the error names that path. As a non-root user nothing is checked. No symlink rule.
- **Flow.** `resolveSelection`: load the set → `SourceOf(--profile)` → `Resolve` → `tuning.Load`
  → `Merge` (default < profile < tuning, each value's source noted; a profile or tuning value for
  an excluded control warned once and dropped) → `set.Subset(ids)`. Then `check.Evaluate(snap, subset, reg,
  Options{Params})` → `waiver.Apply(results, known, excluded, now, warn)` → `report.Build(snap,
  results, cb, severity)` → render → the exit code from the evaluated results. A load failure of
  either file prints `muster: <reason>` and returns `exitError` (2), as a bad waiver file does.
- **Result (additive, under `check`; `run` untouched).** For the §3 example profile:

  ```json
  "check": {
    "controls_version": "kisa-unix-2026+2026.10.02", "controls_digest": "sha256:…",
    "profile": {"name": "site-web-2026", "source": "file:site.yaml", "digest": "sha256:…",
                "extends": ["builtin:default", "file:site.yaml"],
                "selected": 115, "excluded": 2,
                "excluded_ids": ["muster.beyond.no_deleted_executables", "muster.file.ip_port_restriction"]},
    "tuning": {"path": "tuning.yaml", "digest": "sha256:…"},
    "params": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": ["tcp/22", "udp/68", "udp/546", "tcp/443"]}},
    "param_sources": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": "tuning"}},
    "waivers": {"…": "…"}
  }
  ```

  `source` is `builtin` or `file:<path>` — the flag's path as given, a chain file's cleaned opened
  path; `extends` lists the chain root-first with the same spellings; `excluded_ids` is `[]` when
  nothing is excluded, never omitted. `params` keeps its shape (one entry per evaluated control that declares `params`, as today —
  a value for an excluded control appears nowhere in the result); `param_sources` has the same
  keys, one source — `default`, `profile` or `tuning` — per declared parameter. Each row
  gains `severity_source` (`importance` | `profile`) beside the existing `severity`. Without
  `--profile` the block reads `{"name": "default", "source": "builtin", "extends":
  ["builtin:default"], "selected": 117, "excluded": 0, "excluded_ids": []}`; without `--tuning`
  the `tuning` key is absent.
- **Table.** One line under the header, the paths escaped like every file-derived header string:
  `profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>])`, with
  `(<total> controls[; tuning <path>])` when nothing is excluded — `profile default (117
  controls)`, `profile site-web-2026 (115 of 117, 2 excluded; tuning tuning.yaml)`.
  `Profile` is a struct the renderers always print, and a nil `excluded_ids` renders as `[]`; the
  report goldens' `CheckBlock` carries a profile fixture (`default`, all of its controls) so the
  line they pin is a realistic one.
- **Ordering and exit code.** Rows sort by scope, severity, id as today, so a profile's severity
  moves rows; `--fail-on` and the exit code read statuses, not severity — unchanged. The summary's
  high/medium/low buckets count the severity in force.
- **Determinism.** `excluded_ids` sorted; `param_sources` rendered through the same sorted path as
  `params`; the digest is canonical JSON; the severity map is applied by sorted id.

## 6. Tests, CI and documents

- **`internal/profile`**: table tests over `testdata/*.yaml` — the extends chain (four files, a
  fifth refused, a cycle spelled `./a.yaml` and `a.yaml`, a missing file, an unknown name, the
  alias, an absolute `extends`, a chain of two whose chain-file entry is the cleaned opened path and
  whose flagged entry is the path as given), include then exclude, a child
  re-including what a parent excluded, globs crossing dots, a malformed pattern, an unmatched
  pattern, an exclude that removes nothing, params typing per declared type, severity order, the
  built-in, a file naming a built-in, empty selection, `SourceOf` (`Default`, `site_web`,
  `a/b.yaml`, `b.yml`, a Windows path), digest determinism (a reordered `include`, a renamed
  profile and a moved file → the same digest; a changed value → another; a new control default →
  the same), warnings through `warn`; `Merge` (default < profile < tuning with sources; a nil tuning; a tuning
  and a profile value on an excluded control → one warning each with the stated text and no
  entry); the severity map derived from the ordered list; an imports test on the model of
  `internal/check/imports_test.go` for both new packages (neither imports `os`, `os/exec`, `net` or
  `syscall`, so reads go through `open` alone and nothing reaches stderr). `FuzzParseProfile` and
  `FuzzParseTuning` with seeds; an inventory test in each new package on the collectors' model
  (`go/parser` over the package's sources) pins its fuzz targets, and `fuzz.yml` gains `./internal/profile` and `./internal/tuning` in its
  package listing — the pull request that edits it runs the shards (G-27); `make fuzz TARGET=…
  FUZZPKG=./internal/profile/` is noted in CONTRIBUTING.
- **`internal/controls`**: `Subset` keeps order, version, digest and `ByID`; `CheckParamValue`
  shares the lint's typing (the lint's default check calls it).
- **`internal/waiver`**: an excluded id → `not_applied` and the warning, never `unknown`, never
  silently dropped; an excluded id that is also expired → `not_applied` alone; a subject-level
  waiver on an excluded control → the same; the tallies add up.
- **`internal/report`**: `Build` with a severity map — rows, sources, sort, summary buckets; JSON
  and table goldens regenerated (`-update`) and the diff reviewed: new fields only.
- **`cmd/muster` e2e** (the profile, every chain file and the tuning file are copied into
  `t.TempDir()` with their relative layout before `check` runs — the waiver test's D12 precedent,
  because the CI root job runs this package as root): `testdata/profiles/exclude-beyond.yaml` on
  `full-pass.json` and `full-fail.json` → 68 of 117 evaluated, 49 `excluded_ids`, the exit code
  unchanged for the evaluated set; a chain of two files → the `extends` entries; a tuning file
  flipping `fail-ufw-folded-http`'s FAIL to PASS, paired with a one-control profile (`include:
  [muster.beyond.exposed_listeners_allowed]` → 1 selected, 116 excluded — also the proof of
  `include` and of the exit code following the evaluated set), asserting the row's status and
  `param_sources` = `tuning` (the precedent is `internal/check/exposure_controls_test.go`, a unit
  test over one control); a tuning parameter for an excluded control → exit 0, the warning text, no
  entry in `params`; a waiver on an excluded control → the `not_applied` tally and the warning
  text; `--profile Default` and `--profile site` → the error names the built-ins; as root
  (`os.Geteuid() == 0`, the CI root job; skipped otherwise) a profile, a chain file and a tuning
  file made group-writable with `os.Chmod` after the write (the umask strips the bit at creation)
  are each refused naming the path; `controls lint --profile` with a typo → the error names the
  pattern; `controls list --profile` → the four-column rows of the selection. The examples test
  resolves `default` through `resolveSelection` — the only change to that gate; the list-actions
  test is untouched.
- **Examples.** The control set does not change, so the controls digest holds and the examples
  gate compares bytes; the reports gain `check.profile`, `check.param_sources`, `severity_source`
  on every row and the table's profile line, so the examples are refreshed from the branch's
  `examples.yml` run before the merge (the 3C-2b precedent, W-84).
- **CI.** No new job: the `test` job gains `controls lint --profile default`; `fuzz.yml` gains the
  two packages.
- **Documents.** Main design: §6.6 rewritten as realised; **D33** (a profile is the list of
  questions asked and a tuning file the site's values; both are recorded in the result with their
  sources; an excluded control is not evaluated; severity is derived from importance unless a
  profile overrides it; a waiver on an excluded control is `not_applied`, never `unknown` or
  silent); §4.3 (+ profile and tuning files among `check`'s inputs); §6.5 ("with the reason" →
  "with the reason where a row exists"); §6.7 (one sentence on the excluded outcome, its warning,
  and that it is counted but carried by no row); §9's determinism bullet ("same profile and
  tuning"); §4.2's package table gains `internal/profile`
  and `internal/tuning` (resolve against a set; never touch the host or write stderr); §4.4's
  root-refusal sentence names profile, chain and tuning files; §7.2 lists a refused profile or
  tuning file among `check`'s exit-2 causes; §9's provenance bullet gains the `check` block's new
  fields and its severity bullet reads "derived from importance unless a profile's `severity`
  entry overrides it (3D-1)"; §10.2's 3D split into 3D-1/3D-2/3D-3 with this cycle marked merged.
  CLAUDE.md gains "## Profiles (stage 3D-1)". README pair: `--profile`, `--tuning`, the example
  profile `docs/examples/profiles/exclude-beyond.yaml` and the tuning example of §4. CHANGELOG:
  Added (profiles, tuning, the result fields), no Controls entry (the set is unchanged,
  `controls/VERSION` stays). Korean pairs in the same commits.

## 7. Evaluator and schema

- `check.Evaluate` and `check.Result` are unchanged; `Options.Params` is fed the merged map.
  `report.Row.Severity` keeps its meaning; `severity_source` is new. No fact, registry or snapshot
  change — `schema_version`, the `run` block and the controls digest stay.
- The result JSON is additive: a reader of the old shape still parses the new one. No D16 bump: no
  control's verdict changes.

## 8. Parked

- `cis-<distro>-l1` and its index (3D-1b); skipping collectors a profile cannot use; a profile
  directory for packaged installs (stage 4); profile-scoped waivers; severity classes
  (`importance → level` remapping) if per-control globs prove too verbose; `include` by `automation`
  or `importance`; a symlink rule for the trusted files (would apply to waivers too).
