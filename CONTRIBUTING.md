# Contributing to muster

muster checks a Linux host against the KISA 2026 Unix server guide. A
contribution is usually one of three things: a control, a collector fact, or
a fix in the evaluator or the renderers. This page says how each one lands.
The design and its decision log live in
`docs/superpowers/specs/2026-09-02-muster-design.md`; read the section you
are changing before you change it. Korean: `CONTRIBUTING.ko.md`.

## Before anything else

- Go 1.25. `go build ./...`, `make test` (or `go test ./...` on a host without a
  C toolchain), `make lint`, `make lint-controls`, `make coverage`.
- `collect` is Linux-only and lives behind build tags. On another platform,
  cross-compile it (`GOOS=linux GOARCH=amd64 go vet ./... && GOOS=linux
  GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null`) and let
  CI run it.
- Never copy text from the KISA guide or a CIS Benchmark into any file.
  `docs/reference/kisa/` holds item codes, names, categories, importance and
  page numbers only; control descriptions are written in muster's own words.
  See `ATTRIBUTION.md`.
- Never commit anything that names an organisation, a host, an address, an
  alias or a credential. Fixtures use `example.org`/`example.net` names and
  RFC 5737 addresses. A snapshot captured from a private host is never
  committed, in whole or in part.

## Adding a control

1. **Scaffold it.**
   `go run ./cmd/muster controls new muster.<area>.<name> --kisa-id U-NN`
   writes `controls/<area>/<name>.yaml` with the item's importance and its
   KISA references (2026, and the 2021 number from the mapping) filled in,
   and two fixture stubs under `controls/testdata/<id>/`. Areas are
   `account`, `file`, `service`, `patch`, `log` and `beyond`. The command
   refuses an item another control already claims and an item listed in
   `docs/reference/kisa/kisa_deferred.json`: to enrol a deferred item,
   remove its deferral first. Against the shipped inventory every item is
   one or the other, so the scaffold is for the next edition's items or for
   a deferral whose stage has come.
2. **Name the facts.** Every clause reads a registered key
   (`internal/facts/registry.yaml`). If the fact does not exist yet, add it
   to the collector that owns it (below) first. A clause never reads a raw
   JSON path.
3. **Write the judgment.** `checks` for one judgment, `mechanisms` when the
   host can be judged by more than one route, `custom` only when the grammar
   of spec §6.3 cannot express it. Set `absent_means` for what an absent fact
   means (`pass`, `fail`, `not_applicable`, `manual`) and `applies_when` for
   the gate. A `manual` control carries `manual_reason` and an `evidence:`
   list of the facts a reviewer needs in front of them.
4. **Fixtures.** `controls/testdata/<id>/pass-*.json` and `fail-*.json` are
   required (`manual-*`, `na-*`, `error-*` as the control needs). Each is a
   partial snapshot holding only the keys the control reads, marked
   `"synthetic": true`. `go run ./cmd/muster snapshot extract --facts
   <snapshot> --control <id> --out <file>` cuts exactly those keys out of a
   real snapshot — review the values, remove anything that identifies the
   host, then mark it synthetic. `_expect` may pin `reason_code` and
   `exit_code`; those two keys are the only ones the fixture test reads —
   the expected status is the file-name prefix, not an `_expect` field. A
   YAML description is a plain scalar: it cannot contain the sequence `: `
   unquoted, so quote a description that needs it.
5. **Lint, test, regenerate.** `make lint-controls` (the KISA cross-check,
   the STIG/NIST index, the fixture pair, the grammar), `go test ./...`,
   then `make coverage` and commit the regenerated
   `docs/reference/coverage.md`. If the enrolled count changed, update the
   roadmap sentence in both READMEs — `-check` fails until the numbers match.
6. **References.** `references.stig` entries are `{benchmark, version, id}`
   and must exist in `docs/reference/stig/*.json`; `references.nist_800_53`
   ids must appear in some indexed rule. `make refindex` regenerates the
   index from the pinned DISA files (network); CI only reads the committed
   index.

## Adding a fact

- Register the key first: `{key, type, description, since, sensitivity,
  collector}` (+ `default_on` for settings, `subject_kind` for lists). Adding
  a key or a record field keeps `schema_version`; changing a key's type or
  meaning bumps it. The facts schema golden
  (`go test ./internal/facts -run TestFactsSchemaGolden -update`) records the
  change — review the diff.
- Every leaf is an envelope with a status: `ok`, `absent`, `denied`,
  `unsupported`, `timeout`, `error`. A status other than `ok` never produces
  PASS. A registered key the snapshot lacks reads `missing` and is
  `ERROR(missing_fact)`, never excused by `absent_means`.
- Collectors declare every path and command they touch (`Declare.Reads`,
  `Declare.Commands`); a read outside the declaration is a violation. A path
  discovered from a configuration file is read only when the declaration
  covers it; otherwise it is recorded and never opened.
- The conventions in `CLAUDE.md` bind every collector:
  - **C1** — `files.*` owns permission facts of a fixed path list; a path
    discovered from a daemon's configuration belongs to that daemon's
    collector.
  - **C2** — every leaf a clause judges is its own dotted key; a `record`
    fact is evidence for `present`/`absent` only.
  - **C3** — a configuration file that exists but cannot be read is the
    answer for every value it could set (the read's status, path-prefixed),
    never the module's default.
  - **C4** — a path the model declined to read is `absent` with the path in
    the reason; a declared file that exists and cannot be read is the read's
    status; a symlink an administrator placed at a declared main
    configuration file is `error` by design (muster reads without following
    symlinks; where a distribution ships a symlink, the collector models it).
- Honest degradation: an environment that has no such mechanism is
  `unsupported`; a root-only read as non-root is `denied`; a collector that
  needs no privilege never emits `error`. Never `time.Now` in a collector —
  ages are computed from `collected_at`.
- Same input, same bytes: sort every list, never let map order reach a
  value or a reason.

## Tests

- Write the test that drives the caller before the test of the helper. After
  adding a call site, delete the call and confirm the suite goes red; if it
  stays green, the implementation is tested, not the feature.
- Assert something that differs when the feature is gone. Prefer structural
  assertions to substrings.
- Goldens: `go test ./internal/report -run TestJSON -update`,
  `-run TestTableGolden -update`, and the facts golden above. Review every
  regenerated golden before committing it.
- CI runs the race build, the lint, the coverage check, a root collect on the
  runner VM, a non-root collect, the container matrix (Ubuntu 22.04/24.04,
  Rocky 9, AlmaLinux 9, Debian 12 as a canary), the read-only contract run,
  and the capability matrix (`docs/reference/capability-matrix.json`): facts
  that must be `denied` without root and `unsupported` without systemd.

## Documentation

English is canonical; every document has a `X.ko.md` pair updated in the
same commit. Identifiers, flags and paths stay English on both sides.
`CHANGELOG.md` is English-only; a change that alters a verdict on an existing
snapshot goes under **Controls** and bumps `controls/VERSION`.

## Commits and reviews

Commit under your own name and e-mail; the project keeps no organisation
identity. Keep a commit to one change with a subject that says what it does.
A pull request runs the whole CI matrix; a secret scan (`gitleaks`) runs over
every commit in the range, so a private hostname shape or an RFC 1918
address in a test fixture fails it — use the public example ranges.
