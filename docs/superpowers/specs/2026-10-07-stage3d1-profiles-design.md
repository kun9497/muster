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
"the failures of the profile in force".

- **Y-1 — Mechanism only; the CIS profile waits for its index.** The built-in profile is `default`
  (every control, `kisa-unix-2026` as an alias); `cis-<distro>-l1` is the next cycle, once a CIS
  recommendation ↔ control index exists under `docs/reference/cis/` (numbers and versions only —
  CIS text is never copied, ATTRIBUTION.md). This document fixes the naming and the rule that such a
  profile's controls cite `references.cis` first; nothing else about it.
- **Y-2 — An excluded control is not evaluated and not listed.** The result records the profile
  (name, source, digest, chain) and the excluded ids; no new status, no change to the renderers'
  row contract, the exit-code rule or the waiver rule.
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
- **Y-8 — Strict at load, lenient at the seam.** Unknown keys, unmatched patterns, unknown
  controls or parameters, mistyped values, an unknown severity level, a cycle, a depth over 4 and an
  empty selection refuse the file. A profile or tuning parameter that names a control the profile
  excludes is a warning, so a tuning file survives a profile swap.
- **Y-9 — Every change to the result is additive.** New fields beside the old ones; the JSON and
  table goldens regenerate with a reviewed diff; the examples are refreshed from the branch's run.

## 2. Architecture

```
controls.LoadDefault()  ──►  profile.Resolve(set, source)  ──►  Resolved{IDs, Params, Severity, Digest…}
                                       │                                   │
                                       │        tuning.Load(set, path) ──► merge params (default < profile < tuning)
                                       ▼                                   ▼
                              set.Subset(IDs)  ──►  check.Evaluate(snap, subset, reg, Options{Params})
                                                                │
                                                                ▼
                                        report.Build(snap, results, cb, Severity)  ──►  JSON / table / exit code
```

- **`internal/profile` (new).** `Parse([]byte) (*File, error)` — strict YAML. `Resolve(set,
  Source) (*Resolved, error)` — follows `extends`, applies include/exclude, validates params and
  severity against the set, computes the digest. `Builtins()` — the embedded `default`. Depends on
  `internal/controls` (the set, the param declarations) and nothing else.
- **`internal/tuning` (new, small).** `Parse([]byte)`, `Load(set, path)` — the `params:` map with
  the same validation; returns the per-control map and the file digest.
- **`internal/controls`.** `Set.Subset(ids []string) *Set` — a view in the set's order, carrying the
  full set's `Version` and `Digest` (the controls digest names the embedded YAML, never a
  selection). `Set.ParamType(id, name)` for the validators. `lint` gains a profile check.
- **`internal/check`.** Unchanged in behaviour; `Options.Params` is the merged map. `Result` is
  unchanged (severity is a report concern, as today: `report.Row.Severity`).
- **`internal/report`.** `Build` takes the severity overrides and records `severity_source` on each
  row; `CheckBlock` gains `Profile`, `Tuning` and `ParamSources`; the table prints one profile line.
- **`cmd/muster`.** `check --profile`, `check --tuning`; `controls lint --profile`;
  `controls list --profile`.

## 3. The profile file

```yaml
profile: site-web-2026            # [a-z0-9][a-z0-9-]*, required
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
  Facts-glob rule, W-49), so `muster.beyond.*` is every beyond control and `muster.file.*` one
  category. `?` and `[…]` are allowed, a pattern that matches no control of the loaded set is an
  error (a typo never silently selects nothing).
- **Resolution.** The `extends` chain is walked root-first (depth ≤ 4; a cycle, a missing file or
  an unknown built-in refuses). Per file, in this order: `selection = parent.selection ∪
  matches(include) − matches(exclude)`; `params` merge per (control, parameter), the child
  winning; `severity` entries are appended after the parent's. A file with no `extends` starts
  from the empty selection. The built-in `default` is `{profile: default, include: ["muster.*"]}`;
  `kisa-unix-2026` names the same object.
- **Params.** The value is decoded against the control's declared `params.<name>.type`
  (`int`, `string`, `bool`, `list<int>`, `list<string>` — the existing vocabulary); a wrong type, an
  unknown parameter or an unknown control refuses the file. A parameter for a control the
  resolved selection excludes is a warning on stderr (Y-8).
- **Severity.** `level` ∈ {high, medium, low}; the last matching entry wins; an entry whose glob
  matches no control refuses the file; one that matches only excluded controls warns.
- **Empty selection** refuses the file ("profile selects no control").
- **Digest.** `sha256` of the canonical JSON `{name, chain: [source…], ids: sorted, params:
  sorted, severity: [{controls, level}…]}`. Same file, same set → same digest; two files that
  select the same controls, values and severity entries in the same order have the same digest
  whatever the order of their `include` lists.

## 4. The tuning file

```yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/443]
  muster.account.password_min_length:
    min_length: 12
```

Exact ids, the same type validation, applied after the profile's params. A control the profile
excludes → warning. No `include`, `exclude`, `severity` or `extends`: a tuning file carries a
site's numbers and nothing that changes which questions are asked. Its digest is the file's bytes.

## 5. Integration

- **Flags.** `check --profile <name|path>` (default `default`; a name is looked up among the
  built-ins first, then as a path if it contains a separator or ends in `.yaml`/`.yml`),
  `check --tuning <path>`. Both files go through `trustedFile` like the waiver file (no
  world-writable, no symlink). `controls lint --profile <path>` resolves the file against the
  embedded set and prints `ok: profile <name> selects N of M controls, K excluded`; the lint exit
  code is the existing one. `controls list --profile <path>` lists the selected ids only.
- **Flow (`runCheck`).** Load the set → resolve the profile → load the tuning → merge params →
  `set.Subset(ids)` → `check.Evaluate(snap, subset, reg, Options{Params})` → apply waivers (a waiver
  naming an excluded id is recorded `not_applied` with reason `excluded by profile`, not `unknown`)
  → `report.Build` with the severity map → render → exit code from the evaluated results. Load
  failures of either file print `muster: <reason>` and return `exitError`, as a bad waiver file
  does.
- **Result (additive).**

  ```json
  "run": {
    "profile": {"name": "site-web-2026", "source": "file:/etc/muster/site.yaml",
                "digest": "sha256:…", "extends": ["builtin:default"],
                "selected": 90, "excluded": 27, "excluded_ids": ["muster.beyond.…", "…"]},
    "tuning": {"path": "/etc/muster/tuning.yaml", "digest": "sha256:…"},
    "params": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": ["tcp/22", "tcp/443"]}},
    "param_sources": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": "profile"}}
  }
  ```

  `params` keeps its shape (values in force for every evaluated control); `param_sources` names
  `default`, `profile` or `tuning` per parameter. Each row gains `severity_source`
  (`importance` | `profile`) beside the existing `severity`. Without `--profile` the block reads
  `{"name": "default", "source": "builtin", …, "excluded": 0}`; without `--tuning` the `tuning`
  key is absent.
- **Table.** One line under the header: `profile default (117 controls)` or
  `profile site-web-2026 (90 of 117, 27 excluded; tuning /etc/muster/tuning.yaml)`.
- **Ordering and exit code.** Rows sort by scope, severity, id as today, so a profile's severity
  moves rows; `--fail-on` and the exit code read statuses, not severity — unchanged. The summary's
  high/medium/low buckets count the severity in force.
- **Determinism.** `excluded_ids` sorted; `param_sources` rendered through the same sorted path as
  `params`; the digest is canonical JSON.

## 6. Tests, CI and documents

- **`internal/profile`**: table tests over `testdata/*.yaml` — the extends chain (depth 4, cycle,
  missing file, unknown built-in), include then exclude, globs crossing dots, an unmatched pattern,
  params typing per declared type, severity order, the built-in and its alias, empty selection,
  digest determinism (a reordered `include` → the same digest; a changed value → another);
  `FuzzParseProfile` and `FuzzParseTuning` with seeds (the inventory test and the nightly fuzz pick
  them up — every function taking `[]byte` has a target).
- **`internal/controls`**: `Subset` keeps order, version and digest; `lint --profile` errors.
- **`internal/report`**: `Build` with a severity map — rows, sources, sort, summary buckets; JSON
  and table goldens regenerated (`-update`) and the diff reviewed: new fields only.
- **`cmd/muster` e2e**: `testdata/profiles/exclude-beyond.yaml` on `full-pass.json` and
  `full-fail.json` → 68 of 117 evaluated, `excluded_ids` listed, the exit code unchanged for the
  evaluated set; a tuning file flipping `fail-ufw-folded-http`'s FAIL to PASS with
  `param_sources` = `tuning` (the exposure parameter precedent); a waiver on an excluded control →
  `not_applied`; `controls lint --profile` with a typo → the error names the pattern;
  `controls list --profile`. The list-actions and examples gates are untouched.
- **Examples.** The control set does not change, so the controls digest holds and the examples
  gate compares bytes; the reports gain `run.profile`, so the examples are refreshed from the
  branch's `examples.yml` run before the merge (the 3C-2b precedent, W-84).
- **CI.** No new job. `make lint-controls` also runs `controls lint --profile` over the built-in
  default (through a `--profile builtin:default` spelling or the embedded path).
- **Documents.** Main design: §6.6 rewritten as realised, **D33** (a profile is the list of
  questions asked and a tuning file the site's values; both are recorded in the result with their
  sources; an excluded control is not evaluated), §10.2's 3D split into 3D-1/3D-2/3D-3 with this
  cycle marked merged. CLAUDE.md gains "## Profiles (stage 3D-1)". README pair: `--profile`,
  `--tuning`, the example profile `docs/examples/profiles/exclude-beyond.yaml`. CHANGELOG: Added
  (profiles, tuning, the result fields), no Controls entry (the set is unchanged, `controls/VERSION`
  stays). Korean pairs in the same commits.

## 7. Evaluator and schema

- `check.Evaluate` and `check.Result` are unchanged; `Options.Params` is fed the merged map.
  `report.Row.Severity` keeps its meaning; `severity_source` is new. No fact, registry or snapshot
  change — `schema_version` and the controls digest stay.
- The result JSON is additive: a reader of the old shape still parses the new one. No D16 bump: no
  control's verdict changes.

## 8. Parked

- `cis-<distro>-l1` and its index (3D-1b); skipping collectors a profile cannot use; a profile
  directory for packaged installs (stage 4); profile-scoped waivers; severity classes
  (`importance → level` remapping) if per-control globs prove too verbose; `include` by `automation`
  or `importance`.
