# muster — working notes for Claude

Design: `docs/superpowers/specs/2026-09-02-muster-design.md` (English canonical, Korean pair). It is also the
decision log (D01–D28). Read it before changing any contract: facts schema, control ids, exit codes,
waiver keys, output format.

## Build and test

- `go build ./...` (or `CGO_ENABLED=0 go build -trimpath ./cmd/muster` to match the CI build step) —
  compile everything.
- `make test` — `go test -race ./...` (needs a C toolchain for `-race`; on a host without one, run
  `go test ./...` and rely on CI, which runs on Linux, for the race build).
- `make lint` — `gofmt -l .` then `go vet ./...`.
- `make lint-controls` — `go run ./cmd/muster controls lint` (passes `--references docs/reference`, so
  STIG/NIST ids must be in the generated index).
- `make fmt` — `gofmt -l -w .` to fix formatting in place.
- `make coverage` — `go run ./tools/coverage` regenerates `docs/reference/coverage.md`; CI runs
  `go run ./tools/coverage -check` and fails when it is stale. `make refindex` — `go run ./tools/refindex`
  regenerates `docs/reference/stig/*.json` from the pinned DISA files (network; caches downloads under
  `.cache/refindex/`, git-ignored). `make refindex-check` — `go run ./tools/refindex -check`; CI does not
  run either `refindex` target and instead lints against the committed index (see `make lint-controls`).

## Layout

`cmd/muster` dispatch only. `internal/facts` snapshot types and the key registry. `internal/controls`
schema, strict loader, lint. `internal/check` the pure evaluator — it must never import `os/exec`, `net`
or touch the host (a test enforces it). `internal/waiver` waivers, applied after evaluation. `internal/report`
renderers and the exit code. `controls/` the embedded control set and its fixtures. `collect` is Linux-only
and lives behind build tags.

## Stage-2 conventions

- **C1** — `files.*` owns permission facts of a fixed candidate path list (`/etc/passwd`, `/etc/hosts`, …). A path that must be discovered from a daemon's configuration belongs to that daemon's collector.
- **C2** — every leaf a clause judges is its own dotted key; a `record` fact is evidence for `present`/`absent` only. Adding a key or a record field keeps `schema_version` (spec §5.7).
- **C3** — a configuration file a module reads that exists but cannot be read is the answer for every value it could set (the read's status, path-prefixed), never the module's default; an `enabled` fact follows the stack. Derived `pam.*` keys cite the files actually read.
- **C4** — a path the model declined to read (outside the collector's declaration) is `absent` with the path in the reason, never `error`; a declared file that exists and cannot be read is the read's status (C3); a symlink an administrator placed at a declared main configuration file is `error` by design — muster reads without following symlinks, and where a distribution ships a symlink the collector models it. A degraded leaf keeps the source it was derived from.
- Permission facts of a fixed path are written by `writePermFacts` in `internal/collect/collectors/permfacts.go`: `mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present` (+ `acl_entries` where the control judges the ACL). Register the nine (or ten) leaves per path; a stat failure reaches every leaf.
- "Mode ≤ NNN" is written as `op: in` over the subsets of NNN (there is no bit operator); the default is the guide's value (spec §6.6) and a `params.allowed_modes` relaxes it.
- `go run ./tools/coverage` regenerates `docs/reference/coverage.md`; CI fails when it is stale. `go run ./tools/refindex` regenerates `docs/reference/stig/*.json` from the pinned DISA files (network; cache in `.cache/refindex`, git-ignored); CI only reads the committed index.
- `references.stig` entries are `{benchmark, version, id}`; `benchmark` is `ubuntu2204`, `ubuntu2404`, `rhel9`, `rocky9` or `alma9`; lint rejects anything not in the index.

## Rules that are contracts

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`. A registered key the
  snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`.
- Exit codes: `check` any `ERROR` → 2 (unless `--allow-error`), any `FAIL` → 1, else 0; `collect`
  0 complete / 1 partial / 2 none. Changing these breaks other people's CI.
- Same input, same bytes. No `map` reaches the JSON or table renderer.
- Result JSON is stdout and nothing else is; warnings are stderr.
- Control and waiver YAML are decoded strictly; unknown keys are errors.
- Never copy KISA guide text or CIS Benchmark text into any file. `docs/reference/kisa/` holds item
  codes, names, categories, importance and page numbers only. See `ATTRIBUTION.md`.
- Fixtures come from public images or are marked `synthetic: true`; never from an employer or customer host.

## Tests

- Every control with a judgment has `controls/testdata/<id>/pass-*.json` and `fail-*.json`; a `manual`
  control has `manual-*.json` carrying every `evidence:` leaf (plus `na-*.json` when gated). The prefix is
  the expected status (`fail-` on a `partial` control expects `WARN`). `_expect` may add `reason_code` and
  `exit_code` — nothing else in it is read.
- Write the test that drives the caller before the test of the helper. After adding a call site, delete
  the call and confirm the suite goes red; if it stays green, the implementation is tested, not the feature.
- Assert something that differs when the call is gone. Prefer structural assertions to substrings.
- Golden files: `go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`,
  `go test ./internal/facts -run TestFactsSchemaGolden -update`. Review the diff before committing a
  regenerated golden; a facts golden change means a `since` entry or a schema version bump, except a
  description-only edit, which regenerates the golden with neither (say so in the commit).

## Documentation

English canonical, `X.ko.md` pair updated in the same commit. Plans under `docs/superpowers/plans/` are
English-only and deleted once merged. Identifiers, flags and paths stay English on both sides.

## Commits

Personal identity only (pinned in `.git/config`; see `.mailmap`). Never push from an agent session.
