# Stage 3D-2 — `fix --dry-run`: the remediation plan and the review script

Korean pair: `2026-10-07-stage3d2-fix-dry-run-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§4.1 commands, §6.2 schema, §6.5 statuses, §6.6 profiles, §7 output, §10.2 roadmap, D24, D33). Profiles:
`2026-10-07-stage3d1-profiles-design.md`. Review history: two fresh-review workflows (261 and 115 agents)
folded into this revision; the folds' rulings are the X list below and the "as built" sentences of §2–§7.

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
  it, and `fix` with a positional word anywhere among its arguments (a mode word such as `apply`), refuses
  with exit 2 and `fix never applies a remediation (D24); run fix --dry-run` — checked before any other flag
  error (§6). The flag is required so that no later reading of "fix" can apply silently. The
  script is a file on stdout; muster does not run it, and `internal/remedy` never imports `os/exec`.
- **X-2 — The failures of the profile in force, as the evaluator classifies them.** The plan's items are
  the `check` rows whose status is `FAIL` or `WARN` after the waiver file was applied — the same
  `resolveSelection`, the same `newCheckBlock`, the same `waiver.Apply` — with two exceptions the
  evaluator itself marks: a `WARN` whose clauses all held and whose only finding is a degraded collection
  (main design §6.5 row 13) is not a failure of the host and is listed as `not_planned` with status
  `warn_degraded`; a `FAIL` the control reached through `absent_means: fail` has nothing a script could
  act on and is a text-only item. Both are told apart by the evaluator's exported reason prefixes
  (§4), never by parsing prose in `remedy`. An excluded control is never planned; a waived control is
  counted, never planned; `MANUAL` and `ERROR` rows are `not_planned` so the reader sees what the plan
  could not decide. There is no second definition of "failing" anywhere.
- **X-3 — Risk first.** The plan is ordered by remediation risk (`none` < `restart_service` <
  `reboot_required` < `lockout_risk`), then by the severity in force (high before medium before low, the
  profile's override included), then by id. The script follows the plan's order block by block.
- **X-4 — One block per control, independent, backup first, a way back on failure.** The script runs
  each control's remediation as its own function: the declared backups are copied first and the block
  stops there if any copy fails; then the control's `script`; then its `validate` command. A non-zero
  step runs the control's declared `rollback` (when it has one) and then restores every declared backup,
  and the block returns 1. A failed block never stops the next one. The script exits 0 when every block
  ran clean, 1 when any block failed (its backups are kept), 2 when the backup directory could not be
  created or the script is not running as root — then nothing ran.
- **X-5 — Declared, never inferred.** What to back up (`backup`), how to confirm (`validate`) and how to
  undo (`rollback`) are fields of the control's `remediation` block, checked by `controls lint`; the
  generator never derives a path from a script body and never substitutes a snapshot value or a
  parameter into a command. A script applies the guide's default where the control's parameter only
  relaxes the judgment (the five file-permission scripts set the guide's mode); when a parameter of the
  control is in force from the profile or a tuning file, the item is text-only (`text_only_reason: params_tuned`) so the
  plan never tightens what a site deliberately relaxed. A remediation whose commands would have to carry a
  parameter's value has no `script` this cycle (§8).
- **X-6 — A way back, or no script.** Lint refuses a `script` that has neither a `rollback` nor a
  non-empty `backup`, a `script` on a control that is not `idempotent`, `backup` or `validate` without a
  `script`, a multi-line `validate`, a body with a here-document, and a backup path the script cannot
  carry as a bare word. A script that may create one of its declared paths declares a `rollback` that
  removes it: `restore` puts back only what existed. A remediation that cannot be undone or re-run is text,
  not a script.
- **X-7 — Mechanism plus the sixteen, rewritten for the template.** This cycle ships the schema fields,
  the lint rules, the plan, the three renderers, the command and the round-trip proof, and rewrites the
  sixteen controls that already carry a `script` so their bodies follow the template's discipline (§3:
  `set -e`-safe, one guarded line per unit, shellcheck-clean, with `backup`/`validate`/`rollback`). Writing
  scripts for the other controls is content work with its own host proof and is the next cycle (§8).
- **X-8 — `--max-risk` is the one knob.** The operator can cap the risk the script will run: items above
  the cap stay in the plan, marked, and appear in the script as a commented-out block. Nothing else
  filters the plan; waivers and profiles already do that upstream.
- **X-9 — Same bytes, three formats.** The table, the JSON and the script are each deterministic for the
  same inputs; no `map` reaches a renderer; the generator reads no clock (the backup directory's timestamp
  is computed by `date` inside the script when it runs). Golden files pin all three, and the examples gate
  compares all three for both example snapshots under the digest rule check's reports already follow.
- **X-10 — `validate` proves the step, not the verdict.** A block's `done` means its commands ran and its
  check held; whether the control now passes is `check`'s to say. The script's epilogue says so and names
  the two commands to run next. The round-trip job (§7) proves, on the named images, that the scripts of
  the seeded controls repair them; the other bodies of the sixteen are proven syntactically (`sh -n`,
  shellcheck over the all-scripted golden) and get host proof with 3D-2b (§8).

## 2. Architecture

```
snapshot.json + profile + tuning + waivers
   ──(cmd/muster fix: openFacts, resolveSelection, loadWaivers, newCheckBlock, report.Build — check's own path)──▶ *report.Report
Report + controls.Set + options ──remedy.Plan──▶ *remedy.Plan
Plan ──remedy.Table / remedy.JSON / remedy.Script──▶ stdout
```

- **`internal/remedy` (new).** The plan model and its three renderers: `Plan(rep *report.Report, set
  *controls.Set, opts Options) (*Plan, error)` (an error only for a `MaxRisk` outside the vocabulary),
  `Table(p *Plan, color bool) []byte`, `JSON(p *Plan) []byte`, `Script(p *Plan) []byte`. All pure.
  Imports: `internal/check`, `internal/controls`, `internal/facts`, `internal/report` and the standard
  library; a test (`go list -f '{{.Imports}}'`, as `internal/profile`'s) refuses `os`, `os/exec`, `net`,
  `syscall` and `time`. The package never writes to stderr or stdout.
- **`internal/report` (extended, exports only).** The pieces the fix renderers share become exported with
  their behaviour unchanged: `Escape` (control characters spelled out, cut at `MaxCell` with `…`),
  `EscapeNoCut` (the same switch without the cut — for control text, which is the plan's payload),
  `MaxCell`, `Paint`, `StatusColor`, `ProfileLine(p ProfileBlock, t *TuningBlock) string`,
  `ReasonLine(row Row) string`, `Title(row Row) string` (`title_ko`, falling back to `title_en`; today
  inline in `WriteTable`) and `HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition
  string) string` — the check table's first line, extracted from `WriteTable` so both tables call one
  function and the line stays byte-identical; the fix table feeds both from its `FixBlock`. `Row`, `Report` and `Build` are unchanged; `report` does not
  import `remedy`.
- **`internal/check` (extended, constants only).** The three reason shapes the evaluator already writes
  become exported constants: `ReasonDegradedPrefix = "collection was degraded: "`,
  `ReasonSideOnlyPrefix = "setting holds on one side only: "`, `ReasonAbsentFailPrefix = "absent counts as
  fail: "`; `eval.go` uses them where it builds the reason, and a test pins that a degraded-pass `WARN`'s
  reason is exactly `ReasonDegradedPrefix + Degraded`. No status, no schema, no judgment changes.
- **`internal/controls` (extended).** `Remediation` gains `Backup []string` (`yaml:"backup,omitempty"`)
  and `Validate string` (`yaml:"validate,omitempty"`); `Lint` gains the rules of §3; the strict loader
  needs no change (unknown keys were already refused).
- **`cmd/muster` (extended).** `fix` dispatch; `runFix` parses `fixFlags`, then calls exactly the helpers
  `runCheck` calls, in the same order — `openFacts`, the control set and registry load, `resolveSelection`,
  the waiver load (lifted from
  `runCheck` into `loadWaivers(path string) (*waiver.File, error)`, which `runCheck` switches to in the same
  commit), `newCheckBlock` (the G-14 seam the examples test also uses) and `report.Build` — and hands the
  `*report.Report` to `remedy.Plan`. No new evaluation function, no flags struct crossing the seam. Under euid
  0 `fix` prints `muster: warning: fix does not need root` to stderr, where check prints its own root
  warning.
- Cycle-free by construction: `remedy → report → check`, `remedy → check`; nothing imports `remedy` but
  `cmd/muster`.

## 3. The remediation block and lint

The block as declared (fields of `Remediation`, all under `remediation:`; six exist today, `backup` and
`validate` are new):

```yaml
remediation:
  text_en: Set PermitRootLogin no in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, …
  text_ko: /etc/ssh/sshd_config.d/ 아래 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤 …
  risk: lockout_risk               # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  backup: [/etc/ssh/sshd_config.d/00-muster.conf, /etc/securetty]
  script: |
    …
  validate: if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'; fi
  rollback: |
    …
```

**Lint rules**, each a problem with rule `remediation` (or `titles` for the title rule) and the message
given below (`Problem.String` prints `path: rule: message`, so the messages carry no prefix), each with one
`TestLintRules` case (inline YAML through `lintOne`, as every other lint rule is tested) asserting the rule
name and the message substring. "One line" means no line break after one trailing newline is trimmed; an
empty `script`/`validate`/`rollback` string reads as absent; "blank" means whitespace only:

- `text_en` and `text_ko` are required wherever `remediation` is present, carry no newline, carriage
  return or C0 byte, and are at most 1000 runes — `text_%s is blank` / `text_%s carries a line break or
  control character` / `text_%s is longer than 1000 runes`. The same no-control-character rule applies to
  `title_en`/`title_ko` under rule `titles` — `title_%s carries a line break or control character` (every
  shipped control already conforms; this is a pin).
- `risk` is one of the four words (unchanged).
- `script` requires `idempotent: true` — `script requires idempotent: true` (the two
  non-idempotent controls, `file/dev_no_stale_files` and `file/ip_port_restriction`, carry no script).
- `script` requires a way back: `rollback` non-blank or `backup` non-empty — `script without rollback or
  backup`.
- `backup` and `validate` require `script` — `backup without script` / `validate without
  script`.
- Every `backup` entry is an absolute path equal to its `path.Clean` (so no trailing `/`), matches
  `^/[A-Za-z0-9._@:+/-]+$` (so it is safe as a bare word in `sh`; no space, quote, `$`, backtick, `;`, glob
  character), and is unique within the list — `backup path %q is not absolute` / `backup path %q is not
  clean` / `backup path %q carries a character the script cannot carry` / `backup path %q is repeated`.
  Order is the author's; the generator keeps it. An entry names a regular file or a symlink, never a
  directory (`restore` refuses a destination that is a directory, §5); a path that may not exist yet is
  allowed (`backup` skips it, `restore` leaves it to the `rollback`).
- `validate` is one line — `validate must be one line`. Several conditions are joined with
  `&&`; a negated condition is written as `! cmd` inside that one AND-list, whose status is the verdict.
- `script`, `validate` and `rollback`, when present, are not blank — `%s is blank` — and carry no
  here-document (`<<`) — `%s carries a here-document` (the generator
  indents bodies, which would move a terminator off column 0).
- Lint does not parse shell. CI's `shellcheck` and `sh -n` over the all-scripted golden (§7) are the gate
  for the bodies.

**Body discipline** (CONTRIBUTING; CI enforces it through the all-scripted golden):

- A body runs in a subshell under `set -e` (§5). Every command that may legitimately fail says so on its
  own line (`cmd || true`), never through a trailing `; true`. No `2>/dev/null` that hides an error the
  operator should see.
- A body that acts on units does so per unit, existence-checked, so a unit this distribution does not ship
  is skipped and a real failure surfaces:
  `for u in telnet.socket telnet.service telnetd.service; do systemctl cat "$u" >/dev/null 2>&1 || continue;
  systemctl disable --now "$u"; systemctl mask "$u"; done`. The unit list of a service control's script,
  validate and rollback is the units of that logical service's row in
  `internal/collect/collectors/services.go` whose `provesInstall` is true (the units that are the service
  itself; for `tftp_talk_disabled`, the `tftp` and `talk` rows) — `inetd.service`/`xinetd.service` are
  probed as hosts of a service and are never in a script. The test that pins it lives in
  `internal/collect/collectors` (Linux-tagged, like the table; it reads the embedded control set) and
  asserts that every `provesInstall: true` unit of the row appears in the control's script, validate and
  rollback, and that no `provesInstall: false` unit does. Services a super-server hosts are not remediated
  by the script; the `text_en` says so and the `reachable` leaf may keep the control `FAIL` after the
  block.
- A body that acts on a file checks the file is there first and fails the block otherwise (`[ -f /etc/hosts ]`
  as the first command) — a missing file is a different finding than a wrong mode, and the plan already
  made such a row text-only (X-2), so this guard only protects a hand-edited plan.
- A body calls only commands the control's own judgment implies exist, or guards the call: `if command -v
  setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi` (the `acl` package is not in every minimal
  image).
- The script runs under `umask 077`: a body that creates a file others must read sets its mode explicitly
  (`chmod 644`) and the validate checks it.
- `validate` checks what the script set that a `stat` or a daemon query can show, and nothing the script
  did not set: a file control compares numeric owner, group (where the script sets it) and mode with
  `stat -c`; a service control reads the printed enablement state, not the exit code (`systemctl
  is-enabled` exits 0 for `static`, `indirect`, `alias` too); the sshd control asks `sshd -T`. ACL removal
  and the `/etc/securetty` edit are not re-checked by the validate: `check` proves them (X-10).
- Bodies are POSIX `sh` and shellcheck-clean at the default severity (`A && B || C` is written as `if`);
  `make shellcheck` runs it locally over the all-scripted golden.
- A declared `rollback` undoes what the script created or did (removes the drop-in, re-enables units);
  the generator's `restore` puts back the declared backups after it, so a rollback need not restore files.
- The sshd body needs a working `sshd -t`: host keys present and, on a socket-activated host, the privilege
  separation directory (`[ -d /run/sshd ] || mkdir -p /run/sshd`, guarded by `command -v sshd`); where
  `sshd -t` still fails the block fails safe and rolls back. sshd keeps the first value it reads for a
  keyword and includes its drop-ins in lexical order, so the drop-in is `00-muster.conf`; a drop-in that
  sorts before it, or a `PermitRootLogin` line before the `Include` in `sshd_config`, still wins — the
  `text_en` says so, and the validate then fails and the block rolls back.

**The sixteen (X-7), as rewritten in this cycle.** The table fixes each body's shape — the commands,
their order, the guards and the validate's clauses; the literal bodies are written in the plan, rendered by
`all-scripted.sh` and pinned by its golden.

| control | backup | script (shape) | validate | rollback |
|---|---|---|---|---|
| `file/hosts_permissions` | `/etc/hosts` | `[ -f /etc/hosts ]`; `chown root:root /etc/hosts`; `chmod 600 /etc/hosts` | `stat -c '%u %g %a' /etc/hosts \| grep -qx '0 0 600'` | restore_backup |
| `file/services_permissions` | `/etc/services` | as above with `644` | `… \| grep -qx '0 0 644'` | restore_backup |
| `file/hosts_lpd_permissions` | `/etc/hosts.lpd` | as above with `600` | `… \| grep -qx '0 0 600'` | restore_backup |
| `file/passwd_permissions` | `/etc/passwd` | `[ -f /etc/passwd ]`; `chown root:root`; `chmod 644`; guarded `setfacl -b` | `stat -c '%u %g %a' /etc/passwd \| grep -qx '0 0 644'` | restore_backup |
| `file/shadow_permissions` | `/etc/shadow` | `[ -f /etc/shadow ]`; `chown root`; `chmod 400`; guarded `setfacl -b` (the group is the distribution's: `shadow` on Debian, `root` on EL — not judged, not set) | `stat -c '%u %a' /etc/shadow \| grep -qx '0 400'` | restore_backup |
| `service/*_disabled` (10) | none (unit state is not a file) | per-unit loop over the row's `provesInstall` units: `systemctl cat` guard, `disable --now`, best-effort `mask` (`|| true`: a unit whose file is in `/etc/systemd/system` cannot be masked) | one AND-list over the same units: `for`-free, e.g. `! systemctl is-active --quiet telnet.socket && case "$(systemctl is-enabled telnet.socket 2>/dev/null)" in enabled\|enabled-runtime) false;; esac && …` (one clause pair per unit) | declared: two passes over the units, each `systemctl cat`-guarded — `unmask` every unit, then `enable --now` every unit (systemd will not start a socket whose service is still masked); every unit the script names is re-enabled (the pre-change state is not recorded, §8) |
| `account/root_remote_login` | `/etc/ssh/sshd_config.d/00-muster.conf`, `/etc/securetty` | guarded by `command -v sshd`: `/run/sshd` guard, `printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/00-muster.conf`, `chmod 644` on it, `sshd -t`; guarded `sed -i '/^pts\//d' /etc/securetty` | `if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null \| grep -qx 'permitrootlogin no'; fi` | declared: `rm -f /etc/ssh/sshd_config.d/00-muster.conf`, guarded `sshd -t`; `restore` puts `/etc/securetty` back |

`controls/VERSION` moves (the sixteen change) and so does the set digest; no judgment changes, so no
fixture's expected status changes and `TestEveryMutantIsKilled` is unaffected (the fields are outside
every judgment). CHANGELOG records it under Controls.

## 4. The plan

`remedy.Plan` is the model every renderer reads. Field order is the JSON order. `Plan` never carries a
`map` (`by_risk` and `not_planned` counts are structs; a reflection test pins it).

```
Plan
  schema_version  int                  remedy.PlanSchemaVersion (= 1; the plan's own, bumped only for a plan shape change)
  run             facts.Run            the snapshot's run block, byte-identical to check's
  fix             FixBlock             muster_version, commit, controls_version, controls_digest, snapshot_digest,
                                       guide_edition, profile (ProfileBlock), tuning (*TuningBlock, omitted
                                       without --tuning), waivers (report.WaiversBlock), max_risk
  items           []Item               ordered: risk rank ↑, severity rank (high, medium, low), id
  not_planned     []NotPlanned         {id, status: error | manual | warn_degraded, reason} by id
  summary         Summary              planned, above_max_risk, with_script, text_only, waived, clean,
                                       not_planned {error, manual, warn_degraded},
                                       by_risk {none, restart_service, reboot_required, lockout_risk}
Item
  id, title_en, title_ko
  status            fail | warn           lower case, the plan's own vocabulary
  severity, severity_source             the row's, as check prints them
  risk, idempotent, automation
  reason            report.ReasonLine(row): the code prefix when there is one, then the reason
  text_en, text_ko
  script            bool                  the control declares a script AND the item may use it (below)
  text_only_reason  "" | no_script | absent | params_tuned
  rollback          none | declared | restore_backup | both      (none ⇔ script false)
  backup            []string              declared paths; [] when script is false
  validate          bool
  planned           bool                  risk rank ≤ max_risk rank
```

- **Which rows become what.** `FAIL`/`WARN` → item, except a `WARN` whose reason is exactly
  `check.ReasonDegradedPrefix + row.Degraded` (the degraded pass) → `not_planned` with `warn_degraded`.
  `ERROR` → `not_planned/error`; `MANUAL` → `not_planned/manual`; `WAIVED` → `summary.waived`;
  `PASS`/`NOT_APPLICABLE` → `summary.clean`. Every row of the report lands in exactly one of items,
  not_planned, waived or clean, so `len(items) + len(not_planned) + waived + clean == selected`, and the
  table's reader can add them up.
- **Which items carry a script.** The control declares one, AND the row's reason does not start with
  `check.ReasonAbsentFailPrefix` (`text_only_reason: absent` — nothing to chmod), AND no parameter of the
  control has a source other than `default` in `rep.Check.ParamSources` (`text_only_reason: params_tuned`
  — the site relaxed a value the script would tighten). Otherwise `script: false` and the reason says
  why; `no_script` when the control simply has none.
- `rollback`: `declared` when the control has a `rollback` and no `backup`; `restore_backup` when it has
  `backup` and no `rollback`; `both` when it has both (the failure path runs the rollback, then the
  restore); `none` when `script` is false.
- `planned` counts into `summary.planned`; an item above the cap counts into `above_max_risk`, keeps
  its `status`, and counts in `by_risk`. `with_script` and `text_only` partition the planned items.
- An item is one control. An `each` control with several failing subjects is one item whose `reason` is
  the row's; subject detail stays in `check`. A control whose subjects were all waived is `WAIVED`.
- `not_planned[].reason` is `report.ReasonLine(row)`, as `Item.reason`.
- Items are numbered 1..N in plan order over all items, N = `len(items)`; an above-cap item keeps its
  number. `by_risk` counts every item, so its four counts sum to `len(items)` = `planned + above_max_risk`.
- Empty lists encode as `[]`, never `null`; `not_planned` is present even when empty.

## 5. The script

`remedy.Script(p)` renders a fixed template: the prologue, the per-item blocks in plan order, the
epilogue. Nothing from the snapshot or a control enters a command: run data and control text appear only
in `#` comment lines — snapshot-derived values (host, collected_at, digests, profile name, reason) through
`report.Escape` (control characters spelled out, a newline as the two characters `\n`, cut at `MaxCell`),
control-derived text (id, titles, `text_en`, `text_ko`) through `report.EscapeNoCut` (never cut: the text
is the item's payload; lint already keeps it to one line). Declared backup paths are emitted as bare
words, which the lint charset makes safe. Bodies are the YAML literal, each line indented four spaces, the
trailing newline trimmed.

```sh
#!/bin/sh
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host <host>, collected <collected_at>; controls <controls_version> <controls_digest>
# profile <name> (<digest>); max-risk <level>
# planned <n> (script <a>, text only <b>); above max-risk <c>; not planned: error <d>, manual <e>, warn_degraded <f>
set -u
umask 077
[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }
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
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; rc=1; continue; }; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0
```

- Existence is `-e || -L` throughout, so a symlink (dangling or with a relative target) is backed up and
  restored as a link. `backup` skips a declared path that does not exist, never overwrites a copy already
  in the backup directory, and returns 1 at the first copy that fails. `restore` puts back every path that
  has a copy, refuses a destination that is a directory (a link to one included), removes a destination that became a
  symlink before copying (it never writes through a link, Z-25), and returns 1 if anything could not be restored. Reusing a `MUSTER_BACKUP` directory keeps the copy from the first run:
  a block that fails in a later run restores the file as it was before the first run, discarding edits
  made in between — by design (the first copy is the original), and the epilogue says which directory was
  used. `/`, `//…` and paths with `.` or `..` components are refused.

`remedy.Build` refuses an item whose id does not match the lint's id grammar (Z-26, defence in depth); the
header renders the id through `report.EscapeNoCut`. A planned item with a script (`<fn>` is `fix_` + the id with every `.` as `_`; the id grammar admits
nothing else):

```sh
# ---- 1/8 muster.file.hosts_permissions [risk none] [fail, high]
# why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts
fix_muster_file_hosts_permissions() {
  backup /etc/hosts || { log "muster.file.hosts_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod 600 /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/hosts | grep -qx '0 0 600'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: validate failed, rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.hosts_permissions: done"
}
fix_muster_file_hosts_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))
```

- **Why neither the subshell nor the call is a condition.** `( set -e … ); rc=$?` runs the body as a
  plain command, so `set -e` is in force inside it. POSIX ignores `-e` for everything a command runs when
  that command is an operand of `||`/`&&`, the condition of `if`/`while`, or negated with `!` — a subshell
  in that position, and equally a function called in that position, which takes every subshell inside it
  along. So the block function is called as a plain command on its own line and its status read on the
  next (`[ "$?" -eq 0 ] || failed=…`); no call line carries `||`, `&&`, `if` or `!`. The same subshell
  shape is used for the validate and the declared-rollback subshells.
- The `backup` line is emitted only when the control declares paths (then the block stops on a failed
  copy); the validate subshell only when declared. The failure path is: the declared `rollback` body in
  its own `( set -e … ); rc=$?` subshell (its failure logged as `rollback failed (rc N)`, never re-tried),
  then `restore <paths>` when backups are declared — `both` runs both, in that order.
- A `lockout_risk` item gets one more comment line after the header: `# keep a second session open; a
  lockout here needs console access`.
- A planned item without a script is a comment block only: header, `why:`, `do:`, `ko:` and `# text only:
  <phrase>` with the phrase mapped one-to-one from `text_only_reason` (`no_script` → `no script declared`,
  `absent` → `the finding is an absent file`, `params_tuned` → `params tuned, see muster check --format
  json: check.param_sources`); no function, no call.
- An item above `--max-risk` renders its header line once, un-prefixed, ending in `-- above max-risk
  <level>, NOT RUN`; every following line of the block, blank lines included, is `#` followed by a space
  and the line when the line is non-empty, `#` alone when it is empty; a line that is already a comment is
  not prefixed again. For a text-only item above the cap only the header suffix changes.

Epilogue:

```sh
if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
```

An empty plan renders the prologue, one line `# nothing to fix`, and the epilogue, so the file is still a
valid script that exits 0.

Safety contract, pinned by tests (§7): no block call line is an operand of `||`/`&&`/`if`/`!`; every line
of the output is either template text, a line of a declared body, or a `#` comment — nothing snapshot- or control-derived lands anywhere else; two renders
are byte-equal; the generator calls no clock; the output of every golden passes `sh -n` and `shellcheck -s
sh` at the default severity; the poison plan (ESC, newlines and `#` in host, reason, titles and texts)
renders every derived byte inside a comment line.

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

- `--dry-run` is a flag like any other and may appear anywhere among the arguments. Before flag parsing,
  an argument that does not start with `-` and is not a flag's value (a mode word such as `apply` or
  `run`, wherever it stands), or the absence of `--dry-run`, is the X-1 refusal with its exact text. Every
  other unknown flag is `unknown flag <x>`, exit 2.
- `--profile`, `--tuning` and `--waivers` have exactly check's semantics, refusals and warnings
  (`profile.Resolve`, `tuning.Load`, the trusted-file rule as root, `warnTo(stderr)`). An empty
  `--profile`/`--tuning` value is refused as check refuses it (CLAUDE.md, Profiles).
- `--max-risk` outside the four words refuses with exit 2 naming the words.
- No `--fail-on`, `--allow-error`, `--quiet`, `--all`: `fix` passes no judgment and shows every item.

**Flow.** `runFix`, in `runCheck`'s order: parse flags (the X-1 check first) → `openFacts` (the snapshot
is untrusted input, read as check reads it; a snapshot `facts.Load` refuses is exit 2) → load the control
set and the registry → `resolveSelection` → `loadWaivers` → the root warning → `newCheckBlock` →
`report.Build` → `remedy.Plan` → the renderer for `--format` → stdout. Warnings are stderr lines with the
`muster: warning: ` prefix: fix's root warning and the profile, tuning and waiver warnings
`resolveSelection`, `profile.Merge` and `newCheckBlock` already emit, through the same `warnTo(stderr)`.

**Exit codes.** `0`: a plan was produced (items or none). `2`: it could not be — a flag error, the X-1
refusal, a snapshot `facts.Load` refuses, a profile, tuning or waiver refusal, a `--max-risk` word outside
the list, or a failing write to stdout (`muster: write: <err>`, main design §7.4) — a partial script is
never reported as success. **Never `1`**: `fix` does not judge the host; `check` does. The main design's exit-code
contract (D11) is for `check` and `collect` and is unchanged; the documents say in one sentence that `fix`
exits 0 with findings so no CI counts findings through it. `ERROR` rows never change `fix`'s exit code;
they are `not_planned`.

**Table** (`remedy.Table`): four header lines, a blank line, the items, and — only when `not_planned` is
non-empty — a blank line and the `not planned:` lines.

```
muster <version> · controls <controls_version> · guide <guide_edition> · host <host> · collected <collected_at>
fix --dry-run · <report.ProfileLine, either of its forms> · max-risk <level>
planned 7 (script 4, text only 3) · above max-risk 1 · waived 1 · clean 92 · not planned: error 1, manual 14, warn_degraded 1
by risk: none 6 · restart_service 1 · reboot_required 0 · lockout_risk 1

#  risk             id                              status  sev   script  rollback        title
1  none             muster.file.hosts_permissions   fail    high  yes     restore_backup  <title_ko>
   why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
   do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
2  none             muster.account.password_policy  fail    high  no      -               …
   why: …
   do:  … (text only: params_tuned)
…
6  lockout_risk     muster.account.root_remote_login  fail  high  yes     both            … (above max-risk)
   why: …
   do:  …

not planned:
  muster.beyond.audit_rules_loaded     error          [missing_fact] …
  muster.service.nfs_export_access     manual         …
  muster.account.lockout_threshold     warn_degraded  collection was degraded: …
```

- Line 1 is `report.HeaderLine`, byte for byte check's. Line 2's profile part is `report.ProfileLine`.
  The `title` column is `report.Title` (`title_ko`, falling back to `title_en`, as check's table) and
  `do:` is `text_ko` falling back to `text_en` — the table is Korean-first like check's; the JSON carries
  both languages and the script's comments carry both (`do:` en, `ko:` ko). A text-only item's `do:` line
  ends with `(text only: <text_only_reason>)`, the enum word verbatim; the `script` cell prints `yes`/`no`
  and the `rollback` cell the enum word, `-` for `none`; the `#` column is the item's number (§4).
- Colour, when on, paints the `risk` cell (`lockout_risk` red, `reboot_required` magenta,
  `restart_service` yellow, `none` unpainted) and the `status` cell with check's status colours.
- Snapshot-derived strings go through `report.Escape` (cut at `MaxCell`); control text through
  `report.EscapeNoCut`. Each `not planned:` row is one line: id, status, `report.Escape(reason)` (cut at
  `MaxCell`, as check's table cuts it); rows are never merged into one cell.
- An empty plan prints the four header lines, a blank line and `nothing to fix`.

**JSON** (`remedy.JSON`): `{"schema_version": …, "run": …, "fix": …, "items": […], "not_planned": […],
"summary": …}` in that order, two-space indent, trailing newline, `SetEscapeHTML(false)`, as check's JSON.

## 7. Tests, CI and documents

**Tests.**

- `internal/remedy`: `TestPlanOrdersByRiskSeverityID` (a mixed set of rows, the profile's severity
  override included), `TestPlanClassifiesEveryRow` (items + not_planned + waived + clean == selected over
  a report that has every status, a degraded-pass `WARN` built through the evaluator, an absent-fail row
  and a params-tuned control), `TestPlanMarksItemsAboveMaxRisk`, `TestPlanRollbackVocabulary`,
  `TestPlanEmpty`, `TestPlanHasNoMap` (reflection over `Plan`), `TestScriptGolden` (`-update`; goldens:
  `full.sh`, `empty.sh`, `capped.sh`, `poison.sh` and `all-scripted.sh` — a synthetic plan in which every
  scripted control of the embedded set is a failing planned item, so every body is rendered),
  `TestScriptBlocksAreIndependent` (one function and one bare call line per planned scripted item, no call
  line carries `||`, `&&`, `if` or `!`; every line of an above-cap block is a comment),
  `TestScriptBodyFailureReachesTheFailurePath` (Linux: a rendered block whose first body command is `false`
  returns 1, the following body commands do not run, and the rollback and restore do), `TestScriptFailurePathRollbackThenRestore` (the `both` block has the
  rollback subshell before the `restore` line), `TestScriptEveryLineIsTemplateBodyOrComment` (the safety
  contract, over the poison plan with poisoned control text too), `TestScriptIsDeterministic`,
  `TestTableGolden`, `TestJSONGolden` (`-update`), `TestTablePoisoned`, `TestJSONEmptyListsAreArrays`,
  `TestRemedyImports`.
- `internal/report`: the exported helpers keep their goldens (no output change); `TestHeaderLineIsCheckLineOne`.
- `internal/check`: `TestWarnReasonShapes` pins the three prefixes against the evaluator's output.
- `internal/controls`: one `TestLintRules` case per rule of §3; the shipped set lints clean.
- `cmd/muster` e2e on `full-fail.json` (its `FAIL` rows include `root_remote_login` and nine service
  controls, so the lockout and the service shapes are covered; a file-permission failure is added to a
  copy of the fixture under `t.TempDir()` for the file shape): the three formats; `fix` without
  `--dry-run` → 2 and the X-1 text; `fix apply --dry-run` and `fix --dry-run apply` → 2 and the X-1 text;
  `fix --facts f.json --dry-run` → 0; unknown flag → 2; a failing stdout writer → 2; `--max-risk
  restart_service` marks the lockout item; `--profile` excluding a failing control removes it from the
  plan; `--waivers` turns one into `waived`; `--format script` passes `sh -n` (Linux only, skipped
  elsewhere); `TestFixAgreesWithCheck`: the ids of `check --format json`'s `FAIL`/`WARN` rows equal the
  plan's items plus its `warn_degraded` rows, and nothing else. `TestServiceScriptsNameTheCollectorsUnits`
  lives in `internal/collect/collectors` (§3).
- Examples: `examples/<snapshot>-fix-report.json`, `-fix-report.txt`, `-fix-report.sh` for both
  snapshots, produced by `examples.yml` with `--max-risk lockout_risk` and `NO_COLOR=1`. The suffix
  `-report.json` keeps the gate's snapshot glob from reading the plan as a snapshot. The gate renders the
  three fix outputs through the same functions `runFix` uses, masks the same four provenance keys under
  `fix` as under `check`, drops the table's first line as `tableBody` does, compares the script whole, and
  skips all three under the same digest condition read from the committed `fix.controls_digest` (G-24).
  Until the refresh the committed check reports are skipped under G-24 (the digest moved with the
  sixteen) and the fix files are absent, which the gate reports as a failure naming the refresh — so the
  branch is red until the examples run, as in 3D-1 (`-skip TestExamplesLoadAndCheck` locally), and the
  refresh is mandatory before the merge.

**CI.**

- The `test` job runs `sh -n` and `shellcheck -s sh` (default severity) over `internal/remedy/testdata/*.sh`
  and `examples/*-fix-report.sh`, installing shellcheck when the runner image lacks it (`command -v
  shellcheck || sudo apt-get install -y shellcheck`). `make shellcheck` is the same command locally.
- A new `fix-roundtrip` job seeds failures, then proves the scripts repair them, on the init images of the
  container matrix (`rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, where `systemctl` answers) and
  on `ubuntu:22.04`; nothing in it touches a host. Per container: (1) seed — on the init images `dnf
  install -y rpcbind openssh-server acl`, `ssh-keygen -A`, `systemctl enable --now rpcbind.socket sshd`,
  `printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/99-ci.conf` (it sorts after the script's
  `00-muster.conf`, so the script's value wins: sshd keeps the first value it reads), `chmod 644
  /etc/hosts`; on `ubuntu:22.04` `apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y
  -qq acl`, `chmod 644 /etc/hosts` (`/etc/shadow` is already `0640` there); (2)
  `collect` → `fix --dry-run --format script > /tmp/fix.sh`; (3) assert the plan lists the seeded ids as
  planned items with `script: true` (init images: `muster.service.rpcbind_disabled`,
  `muster.account.root_remote_login`, `muster.file.hosts_permissions`; ubuntu: `hosts_permissions`,
  `shadow_permissions`) — a run that plans nothing fails the job rather than proving nothing; (4) `sh
  /tmp/fix.sh` (the job runs it, never muster) exits 0; (5) `collect` → `check --format json`: every seeded
  id is `PASS` or `NOT_APPLICABLE`. The seeded set is the design's hypothesis; the first run corrects it
  and the plan's Execution notes record what each image actually planned.
- `make lint-controls` unchanged (the new rules run inside it).

**Documents** (English and Korean in the same commit).

- Main design: §4.1 the Subcommands sentence moves `fix --dry-run` from "later" into the list and the
  example block gains `muster fix --dry-run --facts host.json --format script > fix.sh`; §4.3 the data-flow
  figure gains the plan; §4.4 names `check` and `fix` as the readers of the profile, tuning and waiver files,
  both under the same trusted-file rule as root; §8 "Writes" gains: `fix --dry-run` writes only to stdout and
  the review script it prints is never executed by muster;
  §6.2 the schema example and field list gain `backup` and `validate` with the lint rules; a new §7.5
  "`fix --dry-run`" (inputs, formats, exit codes, the template contract, "fix exits 0 with findings");
  §10.2 marks 3D-2 merged; **D34** — "`fix` never applies: the deliverable is a review script whose blocks
  are one per control, independent, backup-first and rollback-then-restore on failure; what to back up,
  validate and undo is declared on the control and never inferred, no host value is substituted into a
  command, and `validate` proves the step, not the verdict."
- `CLAUDE.md`: a "## Fix (stage 3D-2)" section (the X rulings in working-note form, the body discipline).
- README pair: the usage line `muster fix --dry-run --facts host.json --format script > fix.sh`, the
  roadmap entry, a sentence in "Example output" naming the six example files.
- `CHANGELOG.md`: Added (`fix --dry-run`, the three formats, `--max-risk`), Changed (the lint rules; the
  controls set version), Controls (the sixteen rewritten with `backup`/`validate`/`rollback`; no verdict
  changes).
- `CONTRIBUTING` pair: the body discipline of §3 (backup, validate, rollback, idempotent, POSIX sh,
  `set -e` safety, per-unit loops, shellcheck, the all-scripted golden, the round-trip job).
- `THREAT_MODEL.md`: one line — the script `fix --dry-run` writes is never executed by muster.

## 8. Parked

- Host proof of the twelve rewritten bodies the round-trip does not seed (eight service controls and the
  `passwd`, `services`, `hosts_lpd` permission scripts, plus whichever the first run shows unseeded); they
  are proven syntactically this cycle (3D-2b).
- Scripts for the controls beyond the sixteen (3D-2b, content with host proof per control): sysctl
  settings, the remaining file permissions, PAM and sshd options. A remediation whose command must carry
  a parameter's value (`min_len`, `allowed_ports`) needs a substitution rule first; until then it is text
  (X-5).
- Reading a `check` result JSON instead of a snapshot (`fix --dry-run --result`): needs the control set
  at the same digest; the plan's shape would not change.
- Recording the pre-change state of a service (enabled/active) for a faithful rollback; today the
  rollback re-enables every unit the script names.
- A per-subject plan for `each` controls (one block per world-writable file, for instance).
- A structural verdict marker on `check.Result` (instead of the exported reason prefixes) if a fourth
  consumer appears.
- `explain` (main design §4.1) is a separate cycle.
