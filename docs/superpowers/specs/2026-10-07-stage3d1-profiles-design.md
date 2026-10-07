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
  — CIS text is never copied, ATTRIBUTION.md). This document fixes the naming and the rule that
  such a profile's controls cite `references.cis` first; nothing else about it.
- **Y-2 — An excluded control is not evaluated and not listed.** The result records the profile
  (name, source, digest, chain) and the excluded ids; no new status, no change to the renderers'
  row contract or the exit-code rule. The waiver rule changes in one place only: a waiver naming
  an excluded control is `not_applied` (excluded by profile), not `unknown`.
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
  resolves a profile against the loaded control set into a selected-id set, merged parameters and
  a severity map; `check` evaluates a subset view of the set; the report applies the severity map.
- **Y-8 — Strict at load, lenient at the seam.** Unknown keys, unmatched or malformed patterns,
  unknown controls or parameters, mistyped values, an unknown severity level, a cycle, a chain over
  four files and an empty selection refuse the file. A profile or tuning parameter that names a
  control the profile excludes is a warning, so a tuning file survives a profile swap.
- **Y-9 — Every change to the result is additive and lives in `check`.** New fields beside the old
  ones under the result's `check` block; `run` (the snapshot's provenance, §9) is untouched; the
  JSON and table goldens regenerate with a reviewed diff; the examples are refreshed from the
  branch's run.

## 2. Architecture

```
controls.LoadDefault()  ──►  profile.Resolve(set, src, warn)  ──►  Resolved{IDs, Params, Severity, Digest, Chain}
                                       │                                      │
                                       │        tuning.Load(set, path, warn) ──► merged params (default < profile < tuning)
                                       ▼                                      ▼
                       cmd/muster resolveSelection(flags, set, warn)  ──►  Selection{subset, params, sources, severity, blocks}
                                       │
                                       ▼
              check.Evaluate(snap, subset, reg, Options{Params}) ──► waiver.Apply(results, known, excluded, …)
                                       │
                                       ▼
                       report.Build(snap, results, cb, severity)  ──►  JSON / table / exit code
```

- **`internal/profile` (new).** `Parse([]byte) (*File, error)` — strict YAML. `Resolve(set
  *controls.Set, src Source, warn func(string)) (*Resolved, error)` — `Source{Name string; Path
  string}` names a built-in (`Name`) or a file (`Path`, as given); `Resolve` follows `extends`,
  applies include/exclude, validates params and severity against the set, computes the digest.
  `Builtins()` returns the embedded `default` as a Go literal (there is no YAML file for it).
  Depends on `internal/controls` (the set, the param typing) and nothing else; it never writes to
  stderr — `warn` carries the warnings, as the waiver package does (§7.4).
- **`internal/tuning` (new, small).** `Parse([]byte)`, `Load(set, path, warn)` — the `params:` map
  with the same validation; returns the per-control map and the file's digest.
- **`internal/controls`.** `Set.Subset(ids []string) *Set` — a view in the set's order, carrying
  the full set's `Version` and `Digest` (the controls digest names the embedded YAML, never a
  selection) and its own rebuilt id index. `CheckParamValue(typ string, v any) error` — the typing
  the lint already does for defaults, exported so the profile and tuning validators share it. No
  profile check inside `internal/controls` (it cannot import `internal/profile`): `Resolve` returns
  the refusals and `cmd/muster` reports them.
- **`internal/waiver`.** `Apply` gains the excluded id set: an id in it is counted
  `not_applied` with the warning `waiver for <id> not applied: excluded by profile`; an id in
  neither set stays `unknown`. No row carries the note (the control has no row).
- **`internal/check`.** Unchanged in behaviour; `Options.Params` is the merged map. `Result` is
  unchanged (severity is a report concern, as today: `report.Row.Severity`).
- **`internal/report`.** `Build(snap, results, cb, severity map[string]string)` records
  `severity_source` on each row; `CheckBlock` gains `Profile`, `Tuning` and `ParamSources`; the
  table prints one profile line.
- **`cmd/muster`.** One helper, `resolveSelection(flags, set, warn) (*Selection, error)`, does the
  trusted-file checks, the profile resolution, the tuning load, the merge and the subset; `check`,
  the examples test (G-14: one implementation) and, in 3D-2, `fix` call it. `check --profile`,
  `check --tuning`; `controls lint --profile`; `controls list --profile`.

## 3. The profile file

```yaml
profile: site-web-2026            # [a-z0-9][a-z0-9-]*, required; may not repeat a built-in name
extends: default                  # a built-in name or a path relative to this file; optional
include: ["muster.*"]             # id globs, applied after extends
exclude: ["muster.beyond.*", "muster.file.ip_port_restriction"]
params:                           # exact ids → parameter → value
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, tcp/443]
severity:                         # ordered: a later entry wins
  - { controls: "muster.beyond.*", level: low }
  - { controls: muster.file.world_writable, level: high }
```

- **Globs.** A pattern is matched against the control id with `path.Match`; `*` crosses `.` (the
  rule `Builder.Get` uses for fact globs, `internal/collect/facts.go`), so `muster.beyond.*` is
  every beyond control and `muster.file.*` one category. `?` and `[…]` are allowed. A pattern
  `path.Match` rejects refuses the file naming the pattern; a well-formed pattern that matches no
  control of the loaded set refuses it too (a typo never silently selects nothing). Patterns are
  validated against the loaded set, not the selection: an `exclude` that removes nothing is legal
  and silent.
- **Names and paths.** A built-in name is `[a-z0-9][a-z0-9-]*` with no `/`, no `\` and no
  `.yaml`/`.yml` suffix; anything else is a path (`filepath` rules on every platform). The rule is
  the same for `--profile` and for `extends`: a name is looked up among the built-ins and, when it
  is none of them, refused with the list of built-ins; a path is read as a file — relative to the
  working directory for the flag, relative to the referring file for `extends`. A file whose
  `profile:` repeats a built-in name is refused. A repeated flag keeps the last value, as every
  `check` flag does.
- **Resolution.** The `extends` chain is walked root-first; it holds at most four files, the
  built-in counted (a longer chain, a cycle, a missing file or an unknown name refuses). Per file,
  in this order: `selection = parent.selection ∪ matches(include) − matches(exclude)` — a parent's
  `exclude` is not a rule the child inherits, only a selection the child may add to again;
  `params` merge per (control, parameter), the child winning; `severity` entries are appended
  after the parent's. A file with no `extends` starts from the empty selection. The built-in
  `default` is `{profile: default, include: ["muster.*"]}`; `kisa-unix-2026` names the same object
  and resolves to it (the result shows `default`).
- **Params.** The value is decoded against the control's declared `params.<name>.type`
  (`int`, `string`, `bool`, `list<int>`, `list<string>` — the existing vocabulary, through
  `controls.CheckParamValue`); a wrong type, an unknown parameter or an unknown control refuses
  the file. A parameter for a control the resolved selection excludes is a warning (Y-8).
- **Severity.** `level` ∈ {high, medium, low}; the last matching entry wins; an entry whose glob
  matches no control refuses the file; one that matches only excluded controls warns.
- **Empty selection** refuses the file ("profile selects no control").
- **Digest.** `sha256` of the canonical JSON of the resolved content only — `{ids: sorted,
  params: sorted by control then parameter, severity: [{controls, level}…] in order}`. The name,
  the source and the chain are recorded beside it, never inside it, so two files that select the
  same controls with the same values and the same severity entries have the same digest whatever
  their names, paths or the order of their `include` lists; a changed value changes it.

## 4. The tuning file

```yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/443]
  muster.account.password_policy:
    min_len: 12
```

Exact ids, the same type validation, applied after the profile's params. A control the profile
excludes → warning. No `include`, `exclude`, `severity` or `extends`: a tuning file carries a
site's numbers and nothing that changes which questions are asked. Its digest is the file's bytes.

## 5. Integration

- **Flags.** `check --profile <name|path>` (default `default`) and `check --tuning <path>`;
  `controls lint --profile <name|path>` runs the existing lint and then resolves the profile
  against the embedded set, printing `ok: profile <name> selects N of M controls, K excluded`
  after the existing `ok:` line (a refusal exits 2, warnings go to stderr with exit 0; the
  directories the full lint needs are still needed — this is the maintainers' and CI's command);
  `controls list --profile <name|path>` resolves and lists the selected ids only (an operator's
  way to validate a site profile; a refusal exits 2). CI runs `controls lint --profile default` in
  the `test` job beside the existing lint call (`ci.yml`, not only the Makefile).
- **Trusted files.** When `check` runs as root, the profile, every file its `extends` chain reaches
  and the tuning file must be root-owned and not group- or other-writable, as the waiver file is
  (`trustedFile`, D12); as a non-root user nothing is checked. No symlink rule.
- **Flow.** `resolveSelection`: load the set → resolve the profile → load the tuning → merge
  params (default < profile < tuning) and note each value's source → `set.Subset(ids)`. Then
  `check.Evaluate(snap, subset, reg, Options{Params})` → `waiver.Apply(results, known, excluded,
  …)` → `report.Build(snap, results, cb, severity)` → render → the exit code from the evaluated
  results. A load failure of either file prints `muster: <reason>` and returns `exitError` (2), as
  a bad waiver file does.
- **Result (additive, under `check`; `run` untouched).**

  ```json
  "check": {
    "controls_version": "kisa-unix-2026+2026.10.02", "controls_digest": "sha256:…",
    "profile": {"name": "site-web-2026", "source": "file:site.yaml", "digest": "sha256:…",
                "extends": ["builtin:default", "file:site.yaml"],
                "selected": 68, "excluded": 49, "excluded_ids": ["muster.beyond.…", "…"]},
    "tuning": {"path": "tuning.yaml", "digest": "sha256:…"},
    "params": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": ["tcp/22", "tcp/443"]}},
    "param_sources": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": "profile"}},
    "waivers": {"…": "…"}
  }
  ```

  `source` is `builtin` or `file:<path as given>` (the waiver precedent); `extends` lists the chain
  root-first with the same spellings; `excluded_ids` is `[]` when nothing is excluded, never
  omitted. `params` keeps its shape (the values in force for every evaluated control);
  `param_sources` names `default`, `profile` or `tuning` per parameter. Each row gains
  `severity_source` (`importance` | `profile`) beside the existing `severity`. Without `--profile`
  the block reads `{"name": "default", "source": "builtin", "extends": ["builtin:default"], …,
  "excluded": 0, "excluded_ids": []}`; without `--tuning` the `tuning` key is absent.
- **Table.** One line under the header, the paths escaped like every file-derived header string:
  `profile default (117 controls)`, `profile default (117 controls; tuning tuning.yaml)` or
  `profile site-web-2026 (68 of 117, 49 excluded; tuning tuning.yaml)`.
- **Ordering and exit code.** Rows sort by scope, severity, id as today, so a profile's severity
  moves rows; `--fail-on` and the exit code read statuses, not severity — unchanged. The summary's
  high/medium/low buckets count the severity in force.
- **Determinism.** `excluded_ids` sorted; `param_sources` rendered through the same sorted path as
  `params`; the digest is canonical JSON; the severity map is applied by sorted id.

## 6. Tests, CI and documents

- **`internal/profile`**: table tests over `testdata/*.yaml` — the extends chain (four files, a
  fifth refused, cycle, missing file, unknown name, the alias), include then exclude, a child
  re-including what a parent excluded, globs crossing dots, a malformed pattern, an unmatched
  pattern, an exclude that removes nothing, params typing per declared type, severity order, the
  built-in, a file naming a built-in, empty selection, digest determinism (a reordered `include`, a
  renamed profile and a moved file → the same digest; a changed value → another); warnings through
  `warn`. `FuzzParseProfile` and `FuzzParseTuning` with seeds; a one-line test in each new package
  pins its fuzz targets (`go test -list ^Fuzz`), and `fuzz.yml` gains `./internal/profile` and
  `./internal/tuning` in its package listing — the pull request that edits it runs the shards
  (G-27); `make fuzz TARGET=… FUZZPKG=./internal/profile/` is noted in CONTRIBUTING.
- **`internal/controls`**: `Subset` keeps order, version, digest and `ByID`; `CheckParamValue`
  shares the lint's typing (the lint's default check calls it).
- **`internal/waiver`**: an excluded id → `not_applied` and the warning, never `unknown`, never
  silently dropped; the tallies add up.
- **`internal/report`**: `Build` with a severity map — rows, sources, sort, summary buckets; JSON
  and table goldens regenerated (`-update`) and the diff reviewed: new fields only.
- **`cmd/muster` e2e**: `testdata/profiles/exclude-beyond.yaml` on `full-pass.json` and
  `full-fail.json` → 68 of 117 evaluated, 49 `excluded_ids`, the exit code unchanged for the
  evaluated set; a tuning file flipping `fail-ufw-folded-http`'s FAIL to PASS with `param_sources`
  = `tuning` (the exposure parameter precedent); a waiver on an excluded control → the
  `not_applied` tally and the warning text; `--profile site` with no such built-in → the error
  names the built-ins; `controls lint --profile` with a typo → the error names the pattern;
  `controls list --profile`. The examples test resolves `default` through `resolveSelection` — the
  only change to that gate; the list-actions test is untouched.
- **Examples.** The control set does not change, so the controls digest holds and the examples
  gate compares bytes; the reports gain `check.profile`, so the examples are refreshed from the
  branch's `examples.yml` run before the merge (the 3C-2b precedent, W-84).
- **CI.** No new job: the `test` job gains `controls lint --profile default`; `fuzz.yml` gains the
  two packages.
- **Documents.** Main design: §6.6 rewritten as realised, **D33** (a profile is the list of
  questions asked and a tuning file the site's values; both are recorded in the result with their
  sources; an excluded control is not evaluated), §10.2's 3D split into 3D-1/3D-2/3D-3 with this
  cycle marked merged. CLAUDE.md gains "## Profiles (stage 3D-1)". README pair: `--profile`,
  `--tuning`, the example profile `docs/examples/profiles/exclude-beyond.yaml` and the tuning
  example of §4. CHANGELOG: Added (profiles, tuning, the result fields), no Controls entry (the set
  is unchanged, `controls/VERSION` stays). Korean pairs in the same commits.

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
