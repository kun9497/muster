# Stage 3D-2b — the review script, proven: host guard, unit state, round trips

Korean pair: `2026-10-13-stage3d2b-remedy-proof-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§4.2 packages, §6.2 schema, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycle it completes:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10; §8 Parked) and its plan's Parked list. Review
history: one fresh-review workflow (145 agents: five lenses, three refuters per finding, a critic; 29
survivors and 7 critic findings) folded into this revision. Rulings of this design are the Q list.

## 1. Scope and intent

3D-2 shipped `fix --dry-run`, its plan and the review script, and rewrote the sixteen controls that carry a
`script`. Four of the sixteen are proven on a real system by the `fix-roundtrip` job (`rpcbind_disabled`,
`root_remote_login`, `hosts_permissions`, `shadow_permissions`); the other twelve (nine service controls and
the `passwd`, `services`, `hosts_lpd` permission scripts) are proven only syntactically. The ten service
rollbacks re-enable every unit they name whatever its state before, and nothing stops a script planned from
one host's snapshot from running on another. 3D-2b closes those gaps for the sixteen. It adds no new scripted
control: scripts for further controls, and the parameter-substitution rule they need, are 3D-2c.

- **Q-1 — A script runs on the host it was planned for.** The script carries the snapshot's
  `host.machine_id_hash` and refuses, before it changes anything, a host whose machine id hashes otherwise
  (exit 2). `MUSTER_ANY_HOST=1` overrides it with a warning. A snapshot without a well-formed hash turns the
  guard off, and the prologue says so where the guard would stand (§2).
- **Q-2 — A service rollback puts back what was there.** A service control declares its units
  (`remediation.units`); the template records each unit's enablement and activity before the body runs and,
  on failure, restores the persistent state it recorded — re-masking what was masked, enabling only what was
  enabled, starting only what was active — and logs what it cannot restore. The ten hand-written service
  rollbacks are deleted (§3).
- **Q-3 — Every scripted control is proven on a host, or says why it cannot be.** A table under
  `controls/testdata/` names, for each of the sixteen, the matrix rows whose round trip seeds and repairs it,
  or the reason none can. A test holds the table, the shipped set and the CI matrix equal. The matrix gains a
  Debian 12 init container built in the job from the official image. Each init row also proves the failure
  path (a deliberately failed block leaves units and files as they were) and the host guard (a script planned
  in another container is refused) (§4).
- **Q-4 — A file script only removes bits.** The five permission scripts use symbolic `chmod` that clears
  the bits the guide forbids, so a file already stricter than the guide is never loosened, and their
  validates accept every mode of the control's default. This also closes the 3D-2 parked item "a file script
  setting the guide's mode when the row failed on another leaf" (§5).
- **Q-5 — The small parked items.** Lint refuses two scripted controls sharing a backup path or a unit;
  `Escape` spells out the line and paragraph separators, the bidirectional controls and the zero-width
  format runes; the service bodies and the unit helpers pass `--quiet` to `systemctl` (§5).
- **Q-6 — No verdict changes.** No `checks`, `params` or fact changes; `controls/VERSION` moves because
  remediation blocks change, and with it the controls digest, the goldens and the examples. The plan JSON
  gains `fix.host_guard`, each item's `units` and the `units` rollback value (plan schema stays 1: additive).
  Escaping changes check's table only for a snapshot that carries the newly escaped runes (§5).

## 2. The host guard (Q-1)

**Plan.** `remedy.Build` reads `rep.Run.Host.MachineIDHash` and copies it into `FixBlock.MachineIDHash`
(`json:"-"`) when it matches `^[0-9a-f]{64}$`, leaving it empty otherwise. The JSON gains
`fix.host_guard: "on" | "off"`, placed after `fix.max_risk`. The hash is not repeated under `fix`; it is
already in the plan JSON under `run.host.machine_id_hash`, as in every report. The table is unchanged.

**Prologue order.** The prologue becomes, in this order: `set -u`; `umask 077`; `log()`; the hash helper; the
root check; the guard; the `MUSTER_BACKUP` default and case; `mkdir`; the owner check; `backup()`, `restore()`,
`save_units()`, `restore_units()`; `failed=0`. Moving `log()` up changes no behaviour (it only prints). With
the guard on:

```sh
muster_machine_id_hash() {
  id=$(tr -d '[:space:]' < "$1" 2>/dev/null) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  printf '%s' "$id" | sha256sum | cut -d' ' -f1
}
```

```sh
MUSTER_SNAPSHOT_HOST=<hash>
here=$(muster_machine_id_hash /etc/machine-id)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi
```

With the guard off, neither the helper nor the guard is emitted; one comment line stands where the guard
would: `# host guard: off (the snapshot has no machine id)`. The header lines are unchanged in both cases.

- **The id the helper accepts.** systemd writes a machine id as 32 lowercase hex characters. The helper
  deletes every whitespace character and hashes only a 32-hex id. Anything else — a missing, unreadable or
  empty file, `uninitialized`, interior junk, `sha256sum` absent — yields an empty `here`, which differs from
  any hash: refused. On a well-formed file the result equals the collector's (`strings.TrimSpace`, then
  sha256), because a valid id has no interior whitespace; on any other file the script fails closed. The
  collector reads without following a symlink; a symlinked `/etc/machine-id` gives the snapshot no hash, so
  the guard is off and the helper is never emitted.
- **The guard's limit.** Hosts cloned from one image without regenerating the id share it, and the guard
  cannot tell them apart. `THREAT_MODEL.md` says so: the guard catches the wrong snapshot, not a cloned id.
- **D34 amended**, in the main design and in §4.2's `internal/remedy` row: "no host value is substituted into
  a command" gains one exception, the machine-id hash, admitted only as 64 lowercase hex characters, which
  carry no shell syntax. `TestScriptEveryLineIsTemplateBodyOrComment` admits the one `MUSTER_SNAPSHOT_HOST=`
  line with exactly that shape as template text, and its poison plan carries a malformed hash that must
  appear on no non-comment line.
- **Exit 2 now has three causes** (not root, another host, an unusable backup directory); nothing has run in
  any of them. `MUSTER_ANY_HOST` is read only when the hashes differ.
- **The helper is a shared string.** `internal/remedy` exports the helper text as `MachineIDHashHelper` and
  renders it from that constant. `internal/collect/collectors` extracts `MachineIDHash(data []byte) string`
  (TrimSpace, then sha256 hex; empty for empty input) and `runOS` calls it.
  `TestHostGuardHashMatchesTheCollector` (`internal/remedy`, Linux build tag; a test import of `collectors`,
  which the purity test — it reads `.Imports`, not `.TestImports` — allows) runs the helper with `sh` over
  temp files holding an id with a trailing newline, CRLF, leading blanks and a leading newline, and
  requires the collector's value. Over `uninitialized`, an empty file, a missing path and a 31-character id
  it requires empty output.
- **Guard tests** (`internal/remedy`, Linux, through the rendered script with a temp machine-id path
  substituted for `/etc/machine-id` by `strings.Replace`, the test asserting that the replacement happened):
  equal hashes pass; a mismatch exits 2, prints the refusal and never creates `MUSTER_BACKUP`; a mismatch with
  `MUSTER_ANY_HOST=1` prints the warning and runs; a missing id file exits 2. `runScriptStreams` drops
  `MUSTER_ANY_HOST` from the inherited environment. `fullPlan` gains a well-formed hash, so the `full.sh`
  golden renders the guard-on prologue; `empty.sh` keeps the guard off. A `cmd/muster` e2e asserts
  `host_guard: on` for a snapshot with a hash and `off` for one without.

## 3. Unit state (Q-2)

**Schema and lint.** `Remediation` gains `Units []string` (`yaml:"units,omitempty"`). Per-control lint:

- every entry matches `^[A-Za-z0-9][A-Za-z0-9@._:-]*\.(service|socket)$`; no duplicates;
- `units` requires `script`;
- `units` counts as a way back: a `script` needs `rollback`, `backup` or `units`;
- `units` excludes both `rollback` and `backup`: a unit control undoes through its unit state alone, so no
  restore of a configuration file can run after the units have been started again;
- a `script` or `rollback` that contains `$UNITS` or `${UNITS` requires `units`;
- no `backup` path lies under `/muster-units/` (the template's state directory, below).

Set-level lint (run once over the whole set after the per-control loop; one Problem, on the later control in
id order, naming the earlier): `backup_path_shared` (two scripted controls declare the same `backup` path)
and `units_shared` (two declare the same unit). `TestLintSetRules` covers both with two-control sets.

**Plan.** `Item` gains `Units []string` (`json:"units"`, always present, `[]` when none, set only when
`Script` is true, as `Backup` is). `Item.Rollback` becomes `none | declared | restore_backup | units | both`;
`both` still means `rollback` and `backup` together (lint now forbids `units` with either). The table's
rollback column shows the same word.

**Template.** A block that declares units calls, after its (absent) `backup` line,
`save_units <u…> || { log "<id>: backup failed, nothing changed"; return 1; }`, and on each failure path
`restore_units <u…> || log "<id>: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`. The unit names are the
declared literals. The helpers, in the prologue:

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/muster-units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/muster-units/$u"
    if [ -e "$f" ] || [ -L "$f" ]; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  urc=0
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] || systemctl --quiet unmask -- "$u" || urc=1
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      enabled) systemctl --quiet enable -- "$u" || urc=1;;
      enabled-runtime) systemctl --quiet enable --runtime -- "$u" || urc=1;;
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  return $urc
}
```

- **Pass 1** unmasks every recorded unit except `absent`. The body masks persistently in `/etc`; a unit
  recorded `masked-runtime` would otherwise keep that persistent mask, which `is-enabled` hides behind the
  runtime one. **Pass 2** re-applies what was recorded: `enabled`/`enabled-runtime` are enabled again (with
  `--runtime` for the latter), `masked`/`masked-runtime` are masked again the same way, `linked*` is logged as
  not restored (the body's `disable` removes the link and the template cannot rebuild it) and makes the call
  return 1. **Pass 3** starts what was `active`, `activating` or `reloading`, except a re-masked unit (a
  masked unit cannot be started; its recorded activity is not restored). The passes keep the property 3D-2
  found (Z-23): no unit is enabled or started while a unit it needs is still masked.
- States left as the body left them after the unmask: `disabled`, `static`, `indirect`, `generated`,
  `transient`, `alias`, `bad`, `unknown`, `absent`; `inactive` is not stopped (the body already stopped it).
  A unit enabled only through hand-made `.wants` links with no `[Install]` section cannot be re-enabled by
  `enable`; that failure makes the call return 1 and logs `ROLLBACK INCOMPLETE`. `Also=` partners follow
  `enable`; the plan's probe records whether a matrix unit carries one.
- The state directory `$MUSTER_BACKUP/muster-units/` cannot collide with a backup (lint refuses backup paths
  under `/muster-units/`). The helpers use their own variable names (`u`, `f`, `ue`, `ua`, `urc`) and never
  touch the block's `rc`. A first record is kept across runs with the same `MUSTER_BACKUP`, as a first file
  copy is.
- **Bodies read the declared list.** A block that declares units emits `UNITS='<u1> <u2> …'` as the first
  line inside the body subshell, and all ten bodies are `for u in $UNITS; do … done` loops (the one-unit
  bodies included: SC2043 fires only on a literal one-word list, so the `if` form is retired). Order matters
  where a socket activates its service: lint requires every `<name>.socket` to precede `<name>.service` in
  `units`. The validates keep their explicit unit names (one line, no loop).
- **Pinned to the collector and to the validate.** `TestServiceScriptsNameTheCollectorsUnits` (Linux, beside
  the services table) compares each service control's `units`, as a set, with the `provesInstall` units of
  the rows it maps to in `services.go` (`tftp_talk_disabled` maps to two rows). It requires the unit tokens of
  the control's `validate` to equal that set, and it requires that no `script` of a unit-declaring control
  names a unit literally. It replaces the token scan of the bodies (3D-2 Task 3 N1). The ten controls are
  `automount_disabled`, `dos_services_disabled`, `finger_disabled`, `nfs_server_disabled`, `nis_disabled`,
  `rpcbind_disabled`, `rservices_disabled`, `snmp_disabled`, `telnet_disabled`, `tftp_talk_disabled`; the test
  asserts the count.
- **Executed only against a stub.** A Go test that runs a rendered script declaring units puts a stub
  `systemctl` first on `PATH`. The stub is a temp-dir script that logs its argv and answers `cat`,
  `is-enabled` and `is-active` from fixture files. Nothing in the suite reaches the runner's systemd.
  `TestUnitHelpersRestoreRecordedState` (Linux) drives every recorded state — `enabled`,
  `enabled-runtime`, `disabled` + `active`, `masked`, `masked-runtime`, `masked` + `active`, `linked`,
  `static`, `absent`, `unknown` — through a failed block. It asserts the logged call sequence, the three
  passes in order, first-record retention on a second run, and `ROLLBACK INCOMPLETE` when a stubbed call
  fails.

## 4. Proof on hosts (Q-3)

**The table.** `controls/testdata/_roundtrip.yaml` (ignored by the fixture harness, as `_mutants.yaml` is)
holds one entry per scripted control, sorted by id:

```yaml
- id: muster.service.finger_disabled
  unproven: no matrix image ships a systemd unit for a finger server
- id: muster.service.telnet_disabled
  images: [almalinux9-init, rocky9-init]
```

`TestEveryScriptedControlIsInTheRoundtripTable` (`internal/controls`) reads the table and the `fix-roundtrip`
job of `.github/workflows/ci.yml` (`yaml.v3`, already a module dependency) and asserts that:

- the table is sorted by id;
- its ids are exactly the shipped set's scripted ids;
- each entry has a non-empty, duplicate-free `images` or an `unproven` reason, not both;
- every key an `images` list names is the `key` of a matrix row;
- every matrix row has a `key` and a non-empty `seeded`;
- each row's `seeded`, split on whitespace and compared as a set, equals the ids whose `images` name that row;
- no `muster.service.*` id names a row whose `init` is `"false"`.

The image assignments are the plan's to settle. Its first task probes each image in throwaway containers.
For every unit it records whether a package ships it and whether `enable --now` brings it to `active`, and
whether `rpcbind.service` and the other units carry `Also=`. The table records what the probe found. A server
packaged only as an inetd service (Debian's `telnetd`, `fingerd`, `rsh-server`, `talkd`) is out of the
scripts' reach, which disable systemd units and leave inetd alone, and is `unproven` with that reason.

**The matrix.** The rows gain a `key` (`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`).
`debian12-init` is built in the job: `docker build` from an inline Dockerfile `FROM debian:12` that installs
`systemd systemd-sysv` and runs `/sbin/init`, started like the EL init images (`--privileged
--cgroupns=host`), with the same `is-system-running --wait` loop, which fails the job if the system never
reaches `running` or `degraded`. The seed commands move from the workflow into `ci/roundtrip/<key>.sh`; the
checkout's `ci/roundtrip/` is mounted read-only into the container beside `bin/`, and the script runs there.
`make shellcheck` and the CI shellcheck step cover `ci/roundtrip/*.sh` and fail when the glob is empty.

**Seeds** install the packages, start the units the probe proved startable (`enable --now`), and loosen the
files: `chmod 664 /etc/passwd`, `chmod 666 /etc/services` (installing `netbase` first where the image lacks
the file), `install -m 644 /dev/null /etc/hosts.lpd`, `chmod 644 /etc/hosts`. Before collecting, the job
requires every seeded unit to be settled: `active`, or `inactive` for a unit the probe marked
enable-only. A unit stuck `activating` or `failed` fails the job and names the unit. A seed that would remove
the host's own access is out of scope; none of the sixteen needs one.

**The repair run** (every row) is the 3D-2 job: collect, plan, assert every seeded id is a planned scripted
item, run the script (exit 0), collect again, every seeded id is `PASS` or `NOT_APPLICABLE`.

**The failure run** (init rows only), on a second container started and seeded like the first:

1. collect and plan inside this container — never reuse the repair run's script — and assert
   `fix.host_guard` is `on`;
2. record `systemctl is-enabled` and `is-active` of every unit the planned scripted service items declare,
   and for every backup path any planned scripted item declares, `stat -c '%u %g %a'`, `sha256sum` and, where
   `getfacl` exists, `getfacl -cp` (`absent` for a path that does not exist — the sshd block creates its
   drop-in, and the rollback must remove it);
3. copy the script and rewrite the copy, never muster's output. In every planned scripted block, the first
   line after the `( set -e` that opens the validate subshell becomes `false`. The anchor is the line after
   the body subshell's `fi`, so the body and rollback subshells are never touched. A step asserts that the
   copy differs from the original in exactly one line per planned scripted block that has a validate;
4. run the copy under `set +e`; require exit 1, one `validate failed, rolling back` line per rewritten block,
   and no `ROLLBACK INCOMPLETE` or `rollback failed` line;
5. require every unit state, stat, checksum and ACL to equal step 2's record.

**The guard run** (init rows): the repair run's script, planned in the first container, runs in the second
container before step 3. It must exit 2 with the refusal line, and step 2's record must still hold
afterwards.

Every planned scripted block takes part in the failure run, seeded or not (on Debian, for instance,
`shadow_permissions`), so the record covers everything the script would touch. The job's `timeout-minutes`
rises to 40. The plan measures the Debian build and the second container on the first branch run and
records the times in its Execution notes.

## 5. File scripts and the small items (Q-4, Q-5)

**Symbolic modes.** The five file scripts clear forbidden bits instead of setting a mode:

| control | was | becomes |
|---|---|---|
| `hosts_permissions`, `hosts_lpd_permissions` | `chmod 600` | `chmod u-xs,g-rwxs,o-rwxt` |
| `passwd_permissions`, `services_permissions` | `chmod 644` | `chmod u-xs,g-wxs,o-wxt` |
| `shadow_permissions` | `chmod 400` | `chmod u-wxs,g-rwxs,o-rwxt` |

Each `validate` becomes one line over the same `stat -c` format the control's validate uses today
(`%u %g %a`, shadow `%u %a`):

```sh
case "$(stat -c '%u %g %a' /etc/hosts)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
```

- The patterns are the modes of the control's default `allowed_modes` — or, for `passwd`, which has no
  parameter, the literal list of its mode clause — each written as `strconv.FormatInt(mode, 8)` (unpadded,
  as `%a` prints) behind the owner prefix the validate's own `stat` format implies. The trailing `*) false`
  arm is required: a `case` that matches nothing exits 0.
- `TestFileValidatesAcceptTheDefaultModes` builds each pattern list from the control and compares it with the
  validate. A Linux test then runs each validate on a temp copy whose path is substituted into the validate:
  at an allowed mode it exits 0, at a loosened mode 1.
- `text_en`/`text_ko` keep the guide's target mode and gain "(the script only clears bits; a stricter file is
  left as it is)". The owner and ACL lines are unchanged.

**Shared backup paths and units** — the two set-level rules of §3.

**Escape.** `escapeRune` also spells out, as `\u%04x`, the separators U+2028 and U+2029; the bidirectional
controls U+061C, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069; and the zero-width format runes U+200B–U+200D,
U+2060 and U+FEFF. `Escape` serves check's table as well as fix's, so a check table changes only for a
snapshot that carries those runes (CHANGELOG "Changed"). `TestEscapeSpellsOutBidiAndSeparators` pins the
list. Both poison goldens (remedy's `poison.sh`/`poison.table` and report's poisoned table test) gain them.

**`--quiet`.** The service bodies call `systemctl --quiet disable --now` and `systemctl --quiet mask`, and the
unit helpers pass `--quiet` to every changing call, so a re-run over masked units prints nothing.

## 6. Tests, CI and documents

**Tests.** The new tests named in §2–§5, and the following:

- `TestLintRules` gains a case for every per-control rule of §3.
- `TestPlanRollbackVocabulary` gains `units`.
- `TestScriptGolden` regenerates the five goldens. `full.sh` gains the guard on; `all-scripted.sh` renders the
  ten `UNITS=` bodies.
- `TestScriptUnitsBlockOrder` checks that `save_units` precedes the body subshell and that `restore_units`
  stands on every failure path.
- `TestJSONGolden` gains `host_guard` and `units`.
- The mutation test must leave zero survivors.

**CI.** The `fix-roundtrip` matrix of §4, with its repair, failure and guard runs, and the shellcheck step
over `ci/roundtrip/*.sh`. The examples refresh is mandatory before the merge, because the fix reports
change.

**Documents** (English and Korean in the same commit):

- **Main design.** D34 amended, and §4.2's `internal/remedy` row with it (§2). §6.2 gains `units` and the lint
  rules. §7.5 gains the guard, the unit helpers and exit 2's third cause. §10.2 marks 3D-2b merged and names
  3D-2c.
- **`CLAUDE.md` "Fix (stage 3D-2)".** It gains the guard, `units`, the round-trip table and the symbolic
  modes, and replaces the two sentences this design makes false ("rollbacks unmask every unit, then
  `enable --now` every unit", "A one-unit body uses `if`").
- **`CONTRIBUTING` pair.** A service script declares `units` and loops over `$UNITS`. A new scripted control
  is added to `_roundtrip.yaml`.
- **README pair.** The status line and the roadmap entry.
- **`THREAT_MODEL.md`.** The host guard, `MUSTER_ANY_HOST`, the hash in the script, and the cloned-id limit.
- **`examples/README.md`.** The fix reports now carry the guard line.
- **`CHANGELOG`.** Added: the host guard, `units`, the failure and guard runs. Changed: `Escape`, the rollback
  vocabulary, the prologue order. Controls: the sixteen's remediation blocks, with no verdict change.

## 7. Parked

- Scripts for controls beyond the sixteen, and the parameter-substitution rule they need (3D-2c).
- `fix --dry-run --result`, a per-subject plan for `each` controls, a structural verdict marker on
  `check.Result` if a fourth consumer appears, and `explain` — unchanged from 3D-2 §8.
- Restoring a `linked` unit's link, and a unit's recorded activity while it stays masked (logged, §3).
- Telling cloned hosts apart beyond the machine id (§2).
- Whatever the plan's probe marks `unproven`, with its reason, until an image packages it as a systemd unit.
