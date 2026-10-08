# Stage 3D-2 — `fix --dry-run`: the remediation plan and the review script

Korean pair: `2026-10-07-stage3d2-fix-dry-run-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§4.1 commands, §6.2 schema, §6.5 statuses, §6.6 profiles, §7 output, §10.2 roadmap, D24, D33). Profiles:
`2026-10-07-stage3d1-profiles-design.md`. Review history: one fresh-review workflow (261 agents) folded into
this revision; the fold's rulings are the X list below and the "as built" sentences of §2–§7.

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
  control is in force from the profile or a tuning file, the item is text-only (`params tuned`) so the
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
  the two commands to run next; the round-trip job (§7) is the proof that the sixteen scripts turn their
  controls `PASS` on the named images.

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
  `MaxCell`, `Paint`, `StatusColor`, `ProfileLine(cb CheckBlock) string`, `ReasonLine(row Row) string`,
  `Title(row Row) string` (`title_ko`, falling back to `title_en`) and `HeaderLine(run facts.Run, cb
  CheckBlock) string` — the check table's first line, extracted from `WriteTable` so both tables call one
  function and the line stays byte-identical. `Row`, `Report` and `Build` are unchanged; `report` does not
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
  `runCheck` calls, in the same order — `openFacts`, `resolveSelection`, the waiver load (lifted from
  `runCheck` into `loadWaivers(path string) (*waiver.File, error)`, which `runCheck` switches to in the same
  commit), `newCheckBlock` (the G-14 seam the examples test also uses) and `report.Build` — and hands the
  `*report.Report` to `remedy.Plan`. No new evaluation function, no flags struct crossing the seam. `fix`
  prints check's root warning (`fix does not need root`) under euid 0.
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
  backup: [/etc/ssh/sshd_config.d/90-muster.conf, /etc/securetty]
  script: |
    …
  validate: if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'; fi
  rollback: |
    …
```

**Lint rules**, each a problem naming the control and the field (`add("remediation", …)` as today), each
with one `TestLintRules` case (inline YAML through `lintOne`, as every other lint rule is tested) asserting
the rule name and the message substring:

- `text_en` and `text_ko` are required wherever `remediation` is present, carry no newline, carriage
  return or C0 byte, and are at most 1000 runes — `remediation: text_%s is blank` / `carries a line break or
  control character` / `is longer than 1000 runes`. The same no-control-character rule applies to
  `title_en`/`title_ko` (every shipped control already conforms; this is a pin).
- `risk` is one of the four words (unchanged).
- `script` requires `idempotent: true` — `remediation: script requires idempotent: true` (the two
  non-idempotent controls, `file/dev_no_stale_files` and `file/ip_port_restriction`, carry no script).
- `script` requires a way back: `rollback` non-blank or `backup` non-empty — `remediation: script without
  rollback or backup`.
- `backup` and `validate` require `script` — `remediation: backup without script` / `remediation:
  validate without script`.
- Every `backup` entry is an absolute path equal to its `path.Clean`, does not end in `/`, matches
  `^/[A-Za-z0-9._@:+/-]+$` (so it is safe as a bare word in `sh`; no space, quote, `$`, backtick, `;`, glob
  character), and is unique within the list — `remediation: backup path %q is not absolute` / `is not
  clean` / `names a directory` / `carries a character the script cannot carry` / `is repeated`. Order is
  the author's; the generator keeps it. An entry names a regular file or a symlink, never a directory
  (`restore` cannot replace a directory); a path that may not exist yet is allowed (`backup` skips it,
  `restore` leaves it to the `rollback`).
- `validate` is one line — `remediation: validate must be one line`. Several conditions are joined with
  `&&`; a negated condition is written as `! cmd` inside that one AND-list, whose status is the verdict.
- `script`, `validate` and `rollback`, when present, are not blank after trimming — `remediation: %s is
  blank` — and carry no here-document (`<<`) — `remediation: %s carries a here-document` (the generator
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
  validate and rollback is the `units` list of that logical service's row in
  `internal/collect/collectors/services.go` (for `tftp_talk_disabled`, the `tftp` and `talk` rows), verbatim;
  a test in `cmd/muster` (which may import both packages) pins that every unit the collector probes appears
  in the control's script. Services a super-server (inetd/xinetd) hosts are not remediated by the script;
  the `text_en` says so and the `reachable` leaf may keep the control `FAIL` after the block.
- A body that acts on a file checks the file is there first and fails the block otherwise (`[ -f /etc/hosts ]`
  as the first command) — a missing file is a different finding than a wrong mode, and the plan already
  made such a row text-only (X-2), so this guard only protects a hand-edited plan.
- A body calls only commands the control's own judgment implies exist, or guards the call: `if command -v
  setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi` (the `acl` package is not in every minimal
  image).
- The script runs under `umask 077`: a body that creates a file others must read sets its mode explicitly
  (`chmod 644`) and the validate checks it.
- `validate` checks exactly the leaves the control judges and the script sets, nothing more: a file
  control compares numeric owner/group/mode with `stat -c`; a service control reads the printed enablement
  state, not the exit code (`systemctl is-enabled` exits 0 for `static`, `indirect`, `alias` too).
- Bodies are POSIX `sh` and shellcheck-clean at the default severity (`A && B || C` is written as `if`);
  `make shellcheck` runs it locally over the all-scripted golden.
- A declared `rollback` undoes what the script created or did (removes the drop-in, re-enables units);
  the generator's `restore` puts back the declared backups after it, so a rollback need not restore files.

**The sixteen (X-7), as rewritten in this cycle.** The exact strings below are the contract; the
implementer copies them, the goldens render them, the round-trip proves them.

| control | backup | script (shape) | validate | rollback |
|---|---|---|---|---|
| `file/hosts_permissions` | `/etc/hosts` | `[ -f /etc/hosts ]`; `chown root:root /etc/hosts`; `chmod 600 /etc/hosts` | `stat -c '%u %g %a' /etc/hosts \| grep -qx '0 0 600'` | restore_backup |
| `file/services_permissions` | `/etc/services` | as above with `644` | `… \| grep -qx '0 0 644'` | restore_backup |
| `file/hosts_lpd_permissions` | `/etc/hosts.lpd` | as above with `600` | `… \| grep -qx '0 0 600'` | restore_backup |
| `file/passwd_permissions` | `/etc/passwd` | `[ -f …]`; `chown root:root`; `chmod 644`; guarded `setfacl -b` | `stat -c '%u %g %a' /etc/passwd \| grep -qx '0 0 644'` | restore_backup |
| `file/shadow_permissions` | `/etc/shadow` | `[ -f …]`; `chown root`; `chmod 400`; guarded `setfacl -b` (the group is the distribution's: `shadow` on Debian, `root` on EL — not judged, not set) | `stat -c '%u %a' /etc/shadow \| grep -qx '0 400'` | restore_backup |
| `service/*_disabled` (10) | none (unit state is not a file) | per-unit loop over the collector's `units`: `systemctl cat` guard, `disable --now`, `mask` | one AND-list over the same units: `for`-free, e.g. `! systemctl is-active --quiet telnet.socket && case "$(systemctl is-enabled telnet.socket 2>/dev/null)" in enabled\|enabled-runtime) false;; esac && …` (one clause pair per unit) | declared: per-unit loop, `systemctl cat` guard, `unmask`, `enable --now` for every unit the script names (the pre-change state is not recorded, §8) |
| `account/root_remote_login` | `/etc/ssh/sshd_config.d/90-muster.conf`, `/etc/securetty` | guarded sshd drop-in (`chmod 644` on it), `sshd -t`; guarded `sed -i '/^pts\//d' /etc/securetty` | `if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null \| grep -qx 'permitrootlogin no'; fi` | declared: `rm -f /etc/ssh/sshd_config.d/90-muster.conf`, guarded `sshd -t`; `restore` puts `/etc/securetty` back |

`controls/VERSION` moves (the sixteen change) and so does the set digest; no judgment changes, so no
fixture's expected status changes and `TestEveryMutantIsKilled` is unaffected (the fields are outside
every judgment). CHANGELOG records it under Controls.

## 4. The plan

`remedy.Plan` is the model every renderer reads. Field order is the JSON order. `Plan` never carries a
`map` (`by_risk` and `not_planned` counts are structs; a reflection test pins it).

```
Plan
  schema_version  int                  report.ReportSchemaVersion (the plan is a new document; §5.7 unchanged)
  run             facts.Run            the snapshot's run block, byte-identical to check's
  fix             FixBlock             muster_version, commit, controls_version, controls_digest, snapshot_digest,
                                       guide_edition, profile (ProfileBlock), tuning (*TuningBlock, omitted
                                       without --tuning), waivers (the check WaiverBlock), max_risk
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
case "$MUSTER_BACKUP" in /?*) ;; *) printf 'muster-fix: MUSTER_BACKUP must be an absolute path\n' >&2; exit 2;; esac
mkdir -p "$MUSTER_BACKUP" || exit 2
log() { printf 'muster-fix: %s\n' "$*"; }
backup() {
  for p in "$@"; do
    [ -e "$p" ] || continue
    if [ -e "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  rc=0
  for p in "$@"; do
    [ -e "$MUSTER_BACKUP$p" ] || continue
    if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; rc=1; continue; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0
```

- `backup` skips a declared path that does not exist, never overwrites a copy already in the backup
  directory (a second run with the same `MUSTER_BACKUP` keeps the first, original copy), and returns 1 at
  the first copy that fails. `restore` puts back every path that has a copy, refuses a destination that
  became a directory, and returns 1 if anything could not be restored.

A planned item with a script (`<fn>` is `fix_` + the id with every `.` as `_`; the id grammar admits
nothing else):

```sh
# ---- 1/7 muster.file.hosts_permissions [risk none] [fail, high]
# why: a clause does not hold: files.etc_hosts.mode in [0 128 256 384]
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
fix_muster_file_hosts_permissions || failed=$((failed+1))
```

- **Why the subshell is not a condition.** `( set -e … ); rc=$?` runs the body as a plain command, so
  `set -e` is in force inside it; a subshell on the left of `||` or inside `if` would have `-e` ignored by
  POSIX and only the last command's status would count. The same shape is used for the validate and the
  declared-rollback subshells.
- The `backup` line is emitted only when the control declares paths (then the block stops on a failed
  copy); the validate subshell only when declared. The failure path is: the declared `rollback` body in
  its own `( set -e … ); rc=$?` subshell (its failure logged as `rollback failed (rc N)`, never re-tried),
  then `restore <paths>` when backups are declared — `both` runs both, in that order.
- A `lockout_risk` item gets one more comment line after the header: `# keep a second session open; a
  lockout here needs console access`.
- A planned item without a script is a comment block only: header, `why:`, `do:`, `ko:` and `# text only:
  <no script declared | the finding is an absent file | params tuned, see check.params>`; no function, no
  call.
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

Safety contract, pinned by tests (§7): every line of the output is either template text, a line of a
declared body, or a `#` comment — nothing snapshot- or control-derived lands anywhere else; two renders
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

- `--dry-run` must be present somewhere in the arguments (X-1). Any other first word after `fix`
  (`apply`, `run`, …) or its absence is the X-1 refusal.
- `--profile`, `--tuning` and `--waivers` have exactly check's semantics, refusals and warnings
  (`profile.Resolve`, `tuning.Load`, the trusted-file rule as root, `warnTo(stderr)`). An empty
  `--profile`/`--tuning` value is refused as check refuses it (CLAUDE.md, Profiles).
- `--max-risk` outside the four words refuses with exit 2 naming the words.
- No `--fail-on`, `--allow-error`, `--quiet`, `--all`: `fix` passes no judgment and shows every item.

**Flow.** `runFix`: parse flags → load the control set and the registry → `openFacts` (the snapshot is
untrusted input, read as check reads it; a snapshot `facts.Load` refuses is exit 2) → `resolveSelection`
→ `loadWaivers` → `newCheckBlock` → `report.Build` → `remedy.Plan` → the renderer for `--format` →
stdout. Warnings are stderr lines with the `muster: warning: ` prefix, the controls-digest mismatch
warning included.

**Exit codes.** `0`: a plan was produced (items or none). `2`: it could not be — a flag error, the X-1
refusal, a snapshot `facts.Load` refuses, a profile, tuning or waiver refusal, a `--max-risk` word outside
the list. **Never `1`**: `fix` does not judge the host; `check` does. The main design's exit-code
contract (D11) is for `check` and `collect` and is unchanged; the documents say in one sentence that `fix`
exits 0 with findings so no CI counts findings through it. `ERROR` rows never change `fix`'s exit code;
they are `not_planned`.

**Table** (`remedy.Table`): four header lines, a blank line, the items, and — only when `not_planned` is
non-empty — a blank line and the `not planned:` lines.

```
muster <version> · controls <controls_version> · guide <guide_edition> · host <host> · collected <collected_at>
fix --dry-run · <report.ProfileLine, either of its forms> · max-risk <level>
planned 7 (script 4, text only 3) · above max-risk 1 · waived 1 · clean 94 · not planned: error 0, manual 14, warn_degraded 0
by risk: none 5 · restart_service 1 · reboot_required 0 · lockout_risk 1

#  risk             id                              status  sev   script  rollback        title
1  none             muster.file.hosts_permissions   fail    high  yes     restore_backup  /etc/hosts 파일 소유자와 권한
   why: a clause does not hold: files.etc_hosts.mode in [0 128 256 384]
   do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
2  none             muster.account.password_policy  fail    high  no      -               …
   why: …
   do:  … (text only: params tuned)
…
6  lockout_risk     muster.account.root_remote_login  fail  high  yes     both            … (above max-risk)
   why: …
   do:  …

not planned:
  muster.beyond.audit_rules_persisted  error          [missing_fact] …
  muster.service.nfs_exports           manual         …
  muster.account.root_remote_login     warn_degraded  collection was degraded: …
```

- Line 1 is `report.HeaderLine`, byte for byte check's. Line 2's profile part is `report.ProfileLine`.
  The `title` column is `report.Title` (`title_ko`, falling back to `title_en`, as check's table) and
  `do:` is `text_ko` falling back to `text_en` — the table is Korean-first like check's; the JSON carries
  both languages and the script's comments carry both (`do:` en, `ko:` ko). A text-only item's `do:` line
  ends with `(text only: <reason>)`.
- Colour, when on, paints the `risk` cell (`lockout_risk` red, `reboot_required` magenta,
  `restart_service` yellow, `none` unpainted) and the `status` cell with check's status colours.
- Snapshot-derived strings go through `report.Escape` (cut at `MaxCell`); control text through
  `report.EscapeNoCut`; the `not planned:` block is one line per row, never cut to a single cell.
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
  `TestScriptBlocksAreIndependent` (one function and one call per planned scripted item; every line of an
  above-cap block is a comment), `TestScriptFailurePathRollbackThenRestore` (the `both` block has the
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
  `--dry-run` → 2 and the X-1 text; `fix apply --dry-run` → 2; unknown flag → 2; `--max-risk
  restart_service` marks the lockout item; `--profile` excluding a failing control removes it from the
  plan; `--waivers` turns one into `waived`; `--format script` passes `sh -n` (Linux only, skipped
  elsewhere); `TestFixAgreesWithCheck`: the ids of `check --format json`'s `FAIL`/`WARN` rows equal the
  plan's items plus its `warn_degraded` rows, and nothing else; `TestServiceScriptsNameTheCollectorsUnits`
  (every unit of the collector's row appears in the control's script).
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
  install -y rpcbind openssh-server acl`, `systemctl enable --now rpcbind.socket`, `printf
  'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/00-ci.conf`, `chmod 644 /etc/hosts`; on `ubuntu:22.04`
  `apt-get install -y acl`, `chmod 644 /etc/hosts` (`/etc/shadow` is already `0640` there); (2)
  `collect` → `fix --dry-run --format script > /tmp/fix.sh`; (3) assert the plan lists the seeded ids as
  planned items with `script: true` (init images: `muster.service.rpcbind_disabled`,
  `muster.account.root_remote_login`, `muster.file.hosts_permissions`; ubuntu: `hosts_permissions`,
  `shadow_permissions`) — a run that plans nothing fails the job rather than proving nothing; (4) `sh
  /tmp/fix.sh` (the job runs it, never muster) exits 0; (5) `collect` → `check --format json`: every seeded
  id is `PASS` or `NOT_APPLICABLE`. The seeded set is the design's hypothesis; the first run corrects it
  and the plan's Execution notes record what each image actually planned.
- `make lint-controls` unchanged (the new rules run inside it).

**Documents** (English and Korean in the same commit).

- Main design: §4.1 the command table gains `fix --dry-run`; §4.3 the data-flow figure gains the plan;
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
