# Stage 3D-2 — `fix --dry-run`: the remediation plan and the review script

Korean pair: `2026-10-07-stage3d2-fix-dry-run-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§4.1 commands, §6.2 schema, §6.6 profiles, §7 output, §10.2 roadmap, D24, D33). Profiles: `2026-10-07-stage3d1-profiles-design.md`.

## 1. Scope and intent

Stage 3D of the roadmap (main design §10.2) has three independent pieces; 3D-1 (profiles and tuning) is
merged. This cycle is the second: `muster fix --dry-run`. The main design's scope table says of
remediation, since D24: "Never applied. A remediation script can be generated for review, with risk
levels and rollback." The roadmap names the pieces: "`fix --dry-run` with risk ordering, backups,
validation commands and rollback."

`fix --dry-run` answers one question for an operator who has just read a `check` report: **what would I
change, in what order, and how do I get back.** It reads the same inputs as `check` — the snapshot, the
profile in force, the tuning file, the waiver file — evaluates them through the same evaluator, keeps the
failures, and joins them with each control's `remediation` block. From that join it renders a **plan**
(a table for people, JSON for machines) and, on request, a **review script**: one POSIX `sh` file the
operator reads and runs by hand. muster itself never executes a remediation, never writes to the host
and never substitutes a host's values into a command.

- **X-1 — `fix` never applies.** The only mode is `--dry-run`, and it is mandatory: `muster fix` without
  it, and `fix` with any other mode word, refuses with exit 2 and `fix never applies a remediation (D24);
  run fix --dry-run`. The flag is required so that no later reading of "fix" can apply silently. The
  script is a file on stdout; muster does not run it, and `internal/remedy` never imports `os/exec`.
- **X-2 — The failures of the profile in force.** The plan's rows are the `check` rows whose status is
  `FAIL` or `WARN` after the waiver file was applied: the same `resolveSelection`, the same evaluator,
  the same `waiver.Apply`. An excluded control is never planned; a waived control is counted, never
  planned; `MANUAL` and `ERROR` rows are listed as not planned so the reader sees what the plan could not
  decide. There is no second definition of "failing" anywhere.
- **X-3 — Risk first.** The plan is ordered by remediation risk (`none` < `restart_service` <
  `reboot_required` < `lockout_risk`), then by the severity in force (high before medium before low, the
  profile's override included), then by id. The script follows the plan's order block by block.
- **X-4 — One block per control, independent, backup first.** The script runs each control's remediation
  as its own function: declared backups are copied first, then the control's `script`, then its
  `validate` command; a non-zero step runs the control's `rollback` if declared, else restores the
  backups, and the block returns 1. A failed block never stops the next one; the script's exit code is 1
  if any block failed, 0 otherwise.
- **X-5 — Declared, never inferred.** What to back up (`backup`), how to confirm (`validate`) and how to
  undo (`rollback`) are fields of the control's `remediation` block, checked by `controls lint`; the
  generator never derives a path from a script body and never substitutes a snapshot value or a
  parameter into a command. A remediation whose commands would depend on a parameter has no `script`
  this cycle and stays text (§8).
- **X-6 — A way back, or no script.** Lint refuses a `script` that has neither a `rollback` nor a
  non-empty `backup`, a `script` on a control that is not `idempotent`, and `backup` or `validate`
  without a `script`. A remediation that cannot be undone or re-run is text, not a script.
- **X-7 — Mechanism plus the sixteen.** This cycle ships the schema fields, the lint rules, the plan,
  the script, the renderers, the command and the round-trip proof, and completes the sixteen controls
  that already carry a `script` with their `backup`/`validate`/`rollback`. Writing scripts for the other
  controls is content work with its own host proof and is the next cycle (§8).
- **X-8 — `--max-risk` is the one knob.** The operator can cap the risk the script will run: items above
  the cap stay in the plan, marked, and appear in the script as a commented-out block. Nothing else
  filters the plan; waivers and profiles already do that upstream.
- **X-9 — Same bytes, three formats.** The table, the JSON and the script are each deterministic for the
  same inputs; no `map` reaches a renderer; the generator reads no clock (the backup directory's timestamp
  is computed by `date` inside the script when it runs). Golden files pin all three.

## 2. Architecture

```
snapshot.json + profile + tuning + waivers
   ──(cmd/muster fix: the check pipeline — load, resolveSelection, Evaluate, waiver.Apply)──▶ []Row
[]Row + controls.Set + options ──remedy.Plan──▶ Plan
Plan ──report.FixTable / report.FixJSON──▶ stdout       Plan ──remedy.Script──▶ stdout (sh)
```

- **`internal/remedy` (new).** Pure: `Plan(run facts.Run, cb report.CheckBlock, rows []report.Row,
  set *controls.Set, opts Options) *Plan` and `Script(p *Plan) []byte`. `Options{MaxRisk string}`;
  `Plan` returns an error only for a `MaxRisk` outside the vocabulary (`Plan(…) (*Plan, error)`). Imports `internal/check`, `internal/controls`,
  `internal/report` (for `Row` and the run block) and the standard library; a test refuses `os`,
  `os/exec`, `net`, `syscall` and `time`. The package never writes to stderr or stdout.
- **`internal/report` (extended).** `FixTable(p *remedy.Plan, color bool) []byte` and
  `FixJSON(p *remedy.Plan) []byte` beside the check renderers, sharing `escape`, `paint`, `maxCell`
  and the colour policy. `Row` is unchanged.
- **`internal/controls` (extended).** `Remediation` gains `Backup []string` (`yaml:"backup,omitempty"`)
  and `Validate string` (`yaml:"validate,omitempty"`); `Lint` gains the rules of §3; the strict loader
  needs no change (unknown keys were already refused).
- **`cmd/muster` (extended).** `fix` dispatch; `runFix` reuses `parseCheckArgs`' flag shapes through a
  `fixFlags` struct and the same helpers as `runCheck` for loading, `resolveSelection` and waivers. No new
  helper duplicates the check pipeline: `runCheck`'s evaluation sequence is lifted into one function
  (`evaluate(f checkFlags, …) (*facts.Snapshot, []report.Row, CheckBlock, error)`) that both commands
  call, so the definition of a failure stays in one place (X-2).
- Cycle-free: `remedy` depends on `report`, never the reverse; the renderers take a `*remedy.Plan`.

## 3. The remediation block and lint

The block as declared (fields of `Remediation`, all under `remediation:`; the first four exist today):

```yaml
remediation:
  text_en: Set PermitRootLogin no in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, …
  text_ko: /etc/ssh/sshd_config.d/ 아래 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤 …
  risk: lockout_risk               # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  backup: [/etc/ssh/sshd_config.d/90-muster.conf, /etc/securetty]
  script: |
    …
  validate: sshd -t
  rollback: |
    …
```

Rules, each a lint problem naming the control and the field (`add("remediation", …)` as today):

- `text_en` and `text_ko` are required wherever `remediation` is present (today only `risk` is checked;
  every shipped control already carries both, so this is a pin, not a change).
- `risk` is one of the four words (unchanged).
- `script` requires `idempotent: true` — `remediation: script requires idempotent: true` (the two
  non-idempotent controls, `file/dev_no_stale_files` and `file/ip_port_restriction`, carry no script).
- `script` requires a way back: `rollback` non-empty or `backup` non-empty — `remediation: script without
  rollback or backup`.
- `backup` and `validate` require `script` — `remediation: backup without script` / `remediation:
  validate without script`.
- Every `backup` entry is an absolute path equal to its `path.Clean`, carries no `*`, `?` or `[`, and is
  unique within the list — `remediation: backup path %q is not absolute` / `is not clean` / `is a glob` /
  `is repeated`. Order is the author's; the generator keeps it.
- `script`, `validate` and `rollback` are literal `sh` text and, when present, are not blank after
  trimming — `remediation: %s is blank`. Lint does not parse shell; CI's `shellcheck` over the generated
  scripts (§7) is the gate for the bodies.

Fixtures: `controls/testdata/_lint/remediation-*.yaml` (one red file per rule) through the existing lint
fixture harness. The `controls/VERSION` bump: the sixteen controls change (new fields), so the set
version and the digest move; no judgment changes, so no fixture's expected status changes and
`TestEveryMutantIsKilled` is unaffected (the fields are outside every judgment).

The sixteen (X-7), completed in this cycle:

| group | controls | backup | validate | rollback |
|---|---|---|---|---|
| file permissions (5) | `file/{passwd,shadow,hosts,services,hosts_lpd}_permissions` | the file | `stat -c '%U:%G %a' <file>` compared with `grep -qx` to the pair the script sets | restore_backup (none declared) |
| service disabled (10) | `service/{telnet,finger,rservices,dos_services,nfs_server,automount,rpcbind,nis,tftp_talk,snmp}_disabled` | none (unit state, not a file) | `! systemctl is-enabled --quiet <unit>` per unit, `! systemctl is-active --quiet <unit>` | declared: `systemctl enable --now <unit>` for each unit the script disabled (the original state is not recorded — the operator reads the block before running it, and the plan's `why:` line names what was enabled) |
| root remote login (1) | `account/root_remote_login` | `/etc/ssh/sshd_config.d/90-muster.conf`, `/etc/securetty` | `sshd -t` | declared (exists) |

The exact unit names and expected modes are the ones each control's judgment already encodes; the
implementer reads them from the control, never invents them. Where a service control's script disables
more than one unit, the validate line checks every one.

## 4. The plan

`remedy.Plan` is the model every renderer reads. Field order is the JSON order.

```
Plan
  run         facts.Run            the snapshot's run block, byte-identical to check's
  fix         FixBlock             {profile ProfileBlock, tuning *TuningBlock, max_risk string}
  items       []Item               ordered: risk rank ↑, severity rank (high, medium, low), id
  not_planned []NotPlanned         {id, status} for every ERROR and MANUAL row, by id
  summary     Summary              planned, above_max_risk, with_script, text_only, waived,
                                   not_planned {error, manual}, by_risk {none, restart_service,
                                   reboot_required, lockout_risk}
Item
  id, title_en, title_ko
  status          fail | warn           (lower case, as the plan's own vocabulary)
  severity, severity_source           the row's, as check prints them
  risk, idempotent, automation
  reason          the row's reason, as check prints it (one line; escape at render time)
  text_en, text_ko
  script          bool                  the control declares a script
  rollback        declared | restore_backup | none   (none ⇔ script false)
  backup          []string              declared paths; [] without a script
  validate        bool
  planned         bool                  risk rank ≤ max_risk rank
```

- `planned` counts into `summary.planned`; an item above the cap counts into `above_max_risk` and not
  into `planned`. `with_script` and `text_only` partition the planned items. `waived` is the number of
  `WAIVED` rows. `by_risk` counts every item, planned or not.
- An item is one control. An `each` control with several failing subjects is one item whose `reason`
  is the row's; subject detail stays in `check`. A control whose subjects were all waived is `WAIVED` and
  not an item.
- Empty lists encode as `[]`, never `null`; `tuning` is omitted without `--tuning`; `not_planned` is
  present even when empty.
- `Plan` never carries a `map`. `by_risk` is a struct of four ints.

## 5. The script

`remedy.Script(p)` renders a fixed template. The prologue, the per-item blocks in plan order, the
epilogue. Nothing from the snapshot enters a command: run data appears only in `#` comment lines,
each value passed through the table's `escape` (which spells a newline as the two characters `\n`, so a
hostile reason cannot end the comment) and cut at `maxCell`.

```sh
#!/bin/sh
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host <host>, collected <collected_at>; controls <controls_digest>
# profile <name> (<digest>); max-risk <level>
# planned <n> (script <a>, text only <b>); above max-risk <c>; not planned: error <d>, manual <e>
set -u
umask 077
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$MUSTER_BACKUP" || exit 2
log()     { printf 'muster-fix: %s\n' "$*"; }
backup()  { for p in "$@"; do [ -e "$p" ] && mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p"; done; return 0; }
restore() { for p in "$@"; do [ -e "$MUSTER_BACKUP$p" ] && cp -a "$MUSTER_BACKUP$p" "$p"; done; return 0; }
failed=0
```

A planned item with a script (`<fn>` is `fix_` + the id with every `.` as `_`):

```sh
# ---- 1/7 muster.file.hosts_permissions [risk none] [fail, high]
# why: mode is 0664, expected one of 0600 0400 0644
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts
fix_muster_file_hosts_permissions() {
  backup /etc/hosts
  ( set -e
    chown root:root /etc/hosts && chmod 600 /etc/hosts
  ) || { log "muster.file.hosts_permissions: script failed, rolling back"; restore /etc/hosts; return 1; }
  ( set -e
    stat -c '%U:%G %a' /etc/hosts | grep -qx 'root:root 600'
  ) || { log "muster.file.hosts_permissions: validate failed, rolling back"; restore /etc/hosts; return 1; }
  log "muster.file.hosts_permissions: done"
}
fix_muster_file_hosts_permissions || failed=$((failed+1))
```

- The `backup` line is emitted only when the control declares paths; the `validate` subshell only when
  declared. The failure path is the declared `rollback` body (in its own `( set -e … )` subshell, its
  own failure logged but not re-tried) when present, else `restore <paths>`.
- Script and rollback bodies are the YAML literal, each line indented four spaces; a trailing newline is
  trimmed. A body that is empty after trimming is a lint error (§3), never an empty subshell.
- A `lockout_risk` item gets one more comment line after the header: `# keep a second session open; a
  lockout here needs console access`.
- A planned item without a script is a comment block only (header, `why:`, `do:`, `ko:`, and `# text
  only: no script declared`), no function, no call.
- An item above `--max-risk` is its full block with every line prefixed `# ` (the function and the call
  included), after a header line ending in `-- above max-risk <level>, NOT RUN`.

Epilogue:

```sh
[ "$failed" -eq 0 ] || { log "$failed block(s) failed; backups in $MUSTER_BACKUP"; exit 1; }
log "done; backups in $MUSTER_BACKUP"
```

An empty plan renders the prologue, one line `# nothing to fix`, and the epilogue, so the file is still a
valid script that exits 0.

Safety contract, pinned by tests: no line outside a `#` comment carries snapshot-derived text; two
renders are byte-equal; the generator calls no clock; the output passes `sh -n` and `shellcheck -s sh`
for every golden and both example snapshots; the rendered script for the poison snapshot (ESC and
newlines in host, reason and titles) has every snapshot-derived byte inside a comment line.

## 6. Integration

**Command.**

```
usage: muster fix --dry-run --facts <snapshot.json|-> [flags]

flags:
  --format table|json|script   output format (default table)
  --waivers <file>             waiver file, as check
  --profile <name|path>        the profile in force, as check (default: the built-in default)
  --tuning <file>              site parameter values, as check
  --max-risk none|restart_service|reboot_required|lockout_risk
                               the highest risk the script will run (default lockout_risk: everything)
  --color auto|always|never    colour (default auto); --no-color = never
```

- `--dry-run` must be present somewhere in the arguments (X-1). Any other first word after `fix`
  (`apply`, `run`, …) or its absence is the X-1 refusal.
- `--profile`, `--tuning` and `--waivers` have exactly check's semantics, refusals and warnings
  (`profile.Resolve`, `tuning.Load`, the trusted-file rule as root, `warnTo(stderr)`). An empty
  `--profile`/`--tuning` value is refused as in check (Z-30).
- `--max-risk` outside the four words refuses with exit 2 naming the words.
- No `--fail-on`, `--allow-error`, `--quiet`, `--all`: `fix` passes no judgment and shows every item.

**Flow.** `runFix`: parse flags → load the control set and the registry → read the snapshot (as check
reads it, untrusted) → `resolveSelection` → the shared `evaluate` (check's evaluation and waiver
sequence, including the controls-digest mismatch warning) → `remedy.Plan` → the renderer for `--format`
→ stdout. Warnings are stderr lines with the `muster: warning: ` prefix.

**Exit codes.** `0`: a plan was produced (items or none). `2`: it could not be — a flag error, the X-1
refusal, an unreadable or untrusted snapshot, a profile, tuning or waiver refusal, a `--max-risk` word
outside the list. **Never `1`**: `fix` does not judge the host; `check` does. The main design's exit-code
contract is unchanged, and the documents say so in one sentence so no CI counts findings through `fix`.
`ERROR` rows never change `fix`'s exit code; they are `not_planned`.

**Table** (`report.FixTable`): four header lines, a blank line, the items, a `not planned:` line.

```
muster <version> · controls <controls_version> · guide <guide_edition> · host <host> · collected <collected_at>
fix --dry-run · profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>]) · max-risk <level>
planned 7 (script 4, text only 3) · above max-risk 1 · waived 1 · not planned: error 0, manual 14
by risk: none 5 · restart_service 1 · reboot_required 0 · lockout_risk 1

#  risk             id                              status  sev   script  rollback        title
1  none             muster.file.hosts_permissions   fail    high  yes     restore_backup  /etc/hosts …
   why: mode is 0664, expected one of 0600 0400 0644
   do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
…
6  lockout_risk     muster.account.root_remote_login  fail  high  yes     declared        … (above max-risk)
   why: …
   do:  …

not planned: muster.beyond.audit_rules_persisted (error) · muster.service.nfs_exports (manual) · …
```

- Line 1 is check's first line, byte for byte (the same function). Line 2's profile part is check's
  `profileLine` text. The `title` column is `title_en`, as check's table; `do:` is `text_en`. Korean text
  is in the JSON and the script.
- Colour, when on, paints the `risk` cell: `lockout_risk` red, `reboot_required` magenta,
  `restart_service` yellow, `none` unpainted; `status` uses check's status colours.
- Every string from the snapshot or a control goes through `escape`. Cells are cut at `maxCell`.
- An empty plan prints the four header lines, a blank line and `nothing to fix`; the `not planned:` line
  follows when there is anything in it.

**JSON** (`report.FixJSON`): `{"schema_version": …, "run": …, "fix": …, "items": […], "not_planned":
[…], "summary": …}` in that order, two-space indent, trailing newline, as check's JSON. `schema_version`
is the result schema's (unchanged: the plan is a new document, not a change to the check result).

## 7. Tests, CI and documents

**Tests.**

- `internal/remedy`: `TestPlanOrdersByRiskSeverityID` (a mixed set of rows, the profile's severity
  override included), `TestPlanExcludesWaivedAndCountsThem`, `TestPlanListsErrorAndManualAsNotPlanned`,
  `TestPlanMarksItemsAboveMaxRisk`, `TestPlanEmpty`, `TestPlanHasNoMap` (reflection over the type, as
  check's), `TestScriptGolden` (`-update`; one golden per fixture: full, empty, max-risk capped, poison),
  `TestScriptBlocksAreIndependent` (structural: one function and one call per planned scripted item,
  every line of an above-cap block starts with `# `), `TestScriptRollbackDeclaredElseRestore`,
  `TestScriptCommentsCarryEverySnapshotByte` (the poison plan), `TestScriptIsDeterministic`,
  `TestRemedyImports` (`go list` imports; `os`, `os/exec`, `net`, `syscall`, `time` refused).
- `internal/report`: `TestFixTableGolden`, `TestFixJSONGolden` (`-update`), `TestFixTablePoisoned`,
  `TestFixJSONEmptyListsAreArrays`, the no-map static check extended to the fix renderers.
- `internal/controls`: one red fixture per lint rule of §3; the existing test that lints the shipped set
  covers the sixteen.
- `cmd/muster` e2e on `full-fail.json`: the three formats; `fix` without `--dry-run` → 2 and the X-1
  text; `fix apply --dry-run` → 2; unknown flag → 2; `--max-risk restart_service` marks the lockout item;
  `--profile` excluding a failing control removes it from the plan; `--waivers` turns one into `waived`;
  `--format script` passes `sh -n` (Linux only, skipped elsewhere); check and fix agree: every `FAIL`/
  `WARN` id of `check --format json` is an item and nothing else is (`TestFixAgreesWithCheck`).
- Examples: `examples/*-fix.txt`, `*-fix.json`, `*-fix.sh` for both snapshots, produced by
  `examples.yml` with `--max-risk lockout_risk` and `NO_COLOR=1`, compared byte for byte by
  `TestExamplesLoadAndCheck`; the gate is red from the first renderer commit until the refresh, as in
  3D-1 (`-skip TestExamplesLoadAndCheck` locally).

**CI.**

- The `test` job runs `shellcheck -s sh` over `examples/*-fix.sh` and the script goldens
  (`internal/remedy/testdata/*.sh`); the Ubuntu runner ships shellcheck.
- A new `fix-roundtrip` job on the init images of the container matrix (`rockylinux/rockylinux:9-ubi-init`,
  `almalinux/9-init`) and on `ubuntu:22.04`: inside the container, `collect` → `fix --dry-run --format
  script > /tmp/fix.sh` → `sh /tmp/fix.sh` (the job runs it, not muster) → `collect` → `check --format
  json`; the job asserts that every item the first plan listed as `planned` with `script: true` is now
  `PASS` or `NOT_APPLICABLE`, and that the script exited 0. Service-disable scripts are proven on the init
  images (where `systemctl` answers) and skipped on `ubuntu:22.04` by the assertion reading the first
  plan's `not_planned`/`ERROR` rows. This is the only place a generated script is ever run, and only in a
  throwaway public container.
- `make lint-controls` unchanged (the new rules run inside it).

**Documents** (English and Korean in the same commit).

- Main design: §4.1 the command table gains `fix --dry-run`; §4.3 the data-flow figure gains the plan;
  §6.2 the schema example and field list gain `backup` and `validate` with the lint rules; a new §7.5
  "`fix --dry-run`" (inputs, formats, exit codes, the template contract); §10.2 marks 3D-2 merged;
  **D34** — "`fix` never applies: the deliverable is a review script whose blocks are one per control,
  independent, backup-first and rollback-on-failure; what to back up, validate and undo is declared on the
  control and never inferred, and no host value is substituted into a command."
- `CLAUDE.md`: a "## Fix (stage 3D-2)" section (the X rulings in working-note form).
- README pair: the usage line `muster fix --dry-run --facts host.json --format script > fix.sh`, the
  roadmap entry, a sentence in "Example output" naming the six example files.
- `CHANGELOG.md`: Added (`fix --dry-run`, the three formats, `--max-risk`), Changed (the lint rules; the
  controls set version), Controls (the sixteen gain fields; no verdict changes).
- `CONTRIBUTING` pair: how to write a `script` (backup, validate, rollback, idempotent, POSIX sh,
  shellcheck, the round-trip job).
- `THREAT_MODEL.md`: one line — the script `fix --dry-run` writes is never executed by muster.

## 8. Parked

- Scripts for the controls beyond the sixteen (3D-2b, content with host proof per control): sysctl
  settings, the remaining file permissions, PAM and sshd options. A remediation whose command depends on
  a parameter (`min_len`, `allowed_ports`) needs a substitution rule first; until then it is text.
- Reading a `check` result JSON instead of a snapshot (`fix --dry-run --result`): needs the control set
  at the same digest; the plan's shape would not change.
- Recording the pre-change state of a service (enabled/active) for a faithful rollback; today the
  rollback re-enables what the script disabled.
- A per-subject plan for `each` controls (one block per world-writable file, for instance).
- `explain` (main design §4.1) is a separate cycle.
