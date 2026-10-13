# Stage 3D-2b — the review script, proven: host guard, unit state, round trips

Korean pair: `2026-10-13-stage3d2b-remedy-proof-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§4.2 packages, §6.2 schema, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycle it completes:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10; §8 Parked) and its plan's Parked list. Review
history: two fresh-review workflows (145 agents: 29 survivors and 7 critic findings; 118 agents: 28 and 6),
each with five lenses, three refuters per finding and a critic, folded into this revision. Rulings of this
design are the Q list.

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
  (`remediation.units`); the template records each unit's enablement and activity, and the active units that
  stopping it would stop, before the body runs. On failure it restores the persistent state it recorded —
  re-masking what was masked, enabling only what was enabled, starting what was active, its stopped dependants
  included — then reads the enablement back and logs every unit it could not put back. The ten hand-written
  service rollbacks are deleted (§3).
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
  `Escape` spells out every format rune, the line and paragraph separators and the Hangul fillers; the
  service bodies and the unit helpers pass `--quiet` to `systemctl` to suppress its result lines (§5).
- **Q-6 — No verdict changes.** No `checks`, `params` or judgment changes; `controls/VERSION` moves because
  remediation blocks change, and with it the controls digest, the goldens and the examples. The plan JSON
  gains `fix.host_guard`, each item's `units` and the `units` rollback value (plan schema stays 1: additive).
  The snapshot header's `host.machine_id_hash` becomes empty for an id that is not 32 lowercase hex (§2).
  Escaping changes a check or fix table only where a snapshot, waiver, profile, tuning path or control text
  carries a newly escaped rune (§5).

## 2. The host guard (Q-1)

**Collector.** `internal/collect/collectors` extracts `MachineIDHash(data []byte) string`: it trims with
`strings.TrimSpace` and returns the sha256 hex of the result only when that result matches `^[0-9a-f]{32}$`,
and `""` otherwise. `runOS` calls it. An `/etc/machine-id` holding `uninitialized`, uppercase, a short id or
junk therefore yields no hash, where today any non-empty content is hashed (Q-6). `FuzzMachineIDHash`
(seeds: a valid id with LF, with CRLF, `uninitialized`, empty, 31 hex characters, an id with an interior space)
asserts the output is `""` or 64 lowercase hex, and joins `fuzzTargets`.

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
  id=$( { tr -d '[:space:]' < "$1"; } 2>/dev/null ) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  { printf '%s' "$id" | sha256sum | cut -d' ' -f1; } 2>/dev/null
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

- **Collector and helper agree.** Both accept exactly a 32-lowercase-hex id. The collector trims the ends;
  the helper deletes every whitespace character. Where they could differ — an id with interior whitespace —
  the collector yields no hash, so the guard is off and the helper is never emitted. With the guard on the
  snapshot's id was valid, and on the same host the helper computes the same value. Anything the helper
  cannot read or hash (missing, unreadable or empty file, `uninitialized`, `sha256sum` absent) yields an
  empty `here`: refused, and nothing but the refusal line reaches stderr. The collector reads without
  following a symlink, so a symlinked `/etc/machine-id` gives the snapshot no hash and the guard is off.
- **The guard's limits.** It fails open where the snapshot has no hash (a container without an id, a
  symlinked id file, a hand-edited snapshot): the script then carries no guard and says so in a comment.
  Hosts cloned from one image without regenerating the id share it, and the guard cannot tell them apart. It
  guards against running the wrong snapshot's script, not against a crafted snapshot or a cloned id.
  `THREAT_MODEL.md` states all three.
- **D34 amended**, in the main design and in §4.2's `internal/remedy` row: "no host value is substituted into
  a command" gains one exception, the machine-id hash, admitted only as 64 lowercase hex characters, which
  carry no shell syntax.
- **Exit 2 now has three causes** (not root, another host, an unusable backup directory); nothing has run in
  any of them. `MUSTER_ANY_HOST` is read only when the hashes differ.
- **The helper is a shared string.** `internal/remedy` exports the helper text as `MachineIDHashHelper` and
  renders it from that constant. `TestHostGuardHashMatchesTheCollector` (`internal/remedy`, Linux build tag;
  a test import of `collectors`, which the purity test — it reads `.Imports`, not `.TestImports` — allows)
  runs the helper with `sh` over temp files. For an id with a trailing newline, CRLF, leading blanks and a
  leading newline it requires the collector's value. For `uninitialized`, uppercase, 31 characters, an
  interior space, whitespace only, an empty file and a missing path it requires that collector and helper
  both yield empty output.
- **Guard tests** (`internal/remedy`, Linux, through the rendered script with a temp machine-id path
  substituted for `/etc/machine-id` by `strings.Replace`, the test asserting that the replacement happened):
  equal hashes pass; a mismatch exits 2, prints exactly the refusal line on stderr and never creates
  `MUSTER_BACKUP`; a mismatch with `MUSTER_ANY_HOST=1` prints the warning and runs; a missing id file exits 2
  with exactly the refusal line. `runScriptStreams` drops `MUSTER_ANY_HOST` from the inherited environment.
  `fullPlan` gains a well-formed hash, so the `full.sh` golden renders the guard-on prologue; `empty.sh` keeps
  the guard off. A `cmd/muster` e2e asserts `host_guard: on` for a snapshot with a hash and `off` for one
  without.
- **The line contract.** `TestScriptEveryLineIsTemplateBodyOrComment` — the enforcement of D34 — admits as
  template text the helper lines, the guard lines, and one `MUSTER_SNAPSHOT_HOST=` line whose value is exactly
  64 lowercase hex. Its poison plan carries a malformed hash that must appear on no non-comment line.

## 3. Unit state (Q-2)

**Schema and lint.** `Remediation` gains `Units []string` (`yaml:"units,omitempty"`). Per-control lint rules
(each a `TestLintRules` case):

- `units_charset` — every entry matches `^[A-Za-z0-9][A-Za-z0-9._:-]*(@[A-Za-z0-9._:-]+)?\.(service|socket)$`
  (a template unit needs a non-empty instance); no duplicates;
- `units_order` — every `<name>.socket` precedes `<name>.service` in `units` (a socket activates its service;
  the collector's rows list rpcbind service-first, so the order is the control's, not the collector's);
- `units_needs_script` — `units` requires `script`;
- `script_way_back` (extended) — a `script` needs `rollback`, `backup` or `units`;
- `units_exclusive` — `units` excludes both `rollback` and `backup`: a unit control undoes through its unit
  state alone, so no restore of a configuration file runs after the units have been started again;
- `units_variable` — `$UNITS` or `${UNITS` may appear only in `script`, and only when `units` is declared; a
  `validate` (where `UNITS` is unset under `set -u`) or a `rollback` that contains it is refused;
- `backup_reserved` — no `backup` path is `/muster-units` or lies under `/muster-units/` (the template's state
  directory, below);
- `script_needs_validate` — a `script` needs a `validate` (all sixteen have one; the failure run in §4 rewrites
  every block's validate).

Set-level lint (run once over the whole set after the per-control loop; one Problem, on the later control in
id order, naming the earlier): `backup_path_shared` (two scripted controls declare the same `backup` path)
and `units_shared` (two declare the same unit). `TestLintSetRules` covers both with two-control sets.

**Plan.** `Item` gains `Units []string` (`json:"units"`, placed after `backup`: …, `rollback`, `backup`,
`units`, `validate`, `planned`; always present, `[]` when none, set only when `Script` is true, as `Backup`
is). `remedy.Build` re-checks every unit against the `units_charset` pattern and refuses the plan otherwise,
as it re-checks ids (Z-26). `Item.Rollback` becomes `none | declared | restore_backup | units | both`; `both`
still means `rollback` and `backup` together (lint now forbids `units` with either). The table's rollback
column shows the same word.

**Template.** A block that declares units calls, where its `backup` line would stand,
`save_units <u…> || { log "<id>: backup failed, nothing changed"; return 1; }`, and on each failure path
`restore_units <u…> || log "<id>: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`. The unit names are the
declared literals. Each record is two files under `$MUSTER_BACKUP/muster-units/`: `<u>` holds
`<is-enabled> <is-active>`, and `<u>.deps` holds the active units that stopping `<u>` stops (systemd's
reverse `Requires=`, `BindsTo=` and `PartOf=`), one per line. The helpers, in the prologue:

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/muster-units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/muster-units/$u"
    if [ -f "$f" ] && ! grep -qx 'absent absent' "$f"; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
      : > "$f.deps" || return 1
      for d in $(systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" 2>/dev/null); do
        if systemctl is-active --quiet -- "$d"; then printf '%s\n' "$d" >> "$f.deps" || return 1; fi
      done
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
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      disabled) now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
        case "$now" in enabled|enabled-runtime) systemctl --quiet disable -- "$u" || urc=1;; esac;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u.deps" ] || continue
    while read -r d; do
      systemctl is-active --quiet -- "$d" || systemctl --quiet start -- "$d" || urc=1
    done < "$MUSTER_BACKUP/muster-units/$u.deps"
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] && continue
    now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
    [ "${now:-unknown}" = "$ue" ] || { log "$u: enablement not restored (was $ue, now ${now:-unknown})"; urc=1; }
  done
  return $urc
}
```

- **The passes.**
  1. *Unmask* every recorded unit except `absent`. The body masks persistently in `/etc`, which outranks a
     runtime mask in `/run`. Without this pass, a unit recorded `masked-runtime` would keep the body's
     persistent mask.
  2. *Enable* what was `enabled` or `enabled-runtime` (with `--runtime` for the latter), and log `linked*` as
     not restored: the body's `disable` removes the link, and the template cannot rebuild it.
  3. *Re-disable* a unit recorded `disabled` that `enable` turned on through an `Also=` partner (EL's
     `rpcbind.service` carries `Also=rpcbind.socket`).
  4. *Re-mask* what was `masked` or `masked-runtime`. This comes after every enable, so no enable refuses on
     a partner masked moments before.
  5. *Start* what was `active`, `activating` or `reloading`, except a re-masked unit (a masked unit cannot be
     started; its recorded activity is not restored).
  6. *Start* every recorded dependant that is not active again.
  7. *Read the enablement back*. Any unit whose `is-enabled` now differs from its record is logged as
     `enablement not restored`, and the call returns 1. `enable` exits 0 on a unit with no `[Install]`
     section, so only this pass shows that such a unit (one enabled through hand-made `.wants` links) stayed
     disabled.
- **Ordering.** No unit is enabled or started while a unit it needs is still masked, except where that unit
  was itself recorded masked; a masked socket in front of an active service is parked (§7).
- **States after the passes.** Every other state (`disabled`, `static`, `indirect`, `generated`, `transient`,
  `alias`, `bad`, `unknown`) is left as the body left it, after the unmask; pass 7 checks it. An `inactive`
  unit is not stopped, because the body already stopped it.
- **First record kept.** A first record is kept across runs with the same `MUSTER_BACKUP`, as a first file
  copy is, except an `absent` record. That one is rewritten once the unit exists, so a unit installed between
  runs is recorded as it then is.
- **The state directory.** `$MUSTER_BACKUP/muster-units/` cannot collide with a backup (`backup_reserved`).
  The helpers use their own variable names (`u`, `f`, `d`, `ue`, `ua`, `now`, `urc`) and never touch the
  block's `rc`. Dependant names come from systemd at run time. They are stored as file content, never as a
  path, and passed quoted after `--`.
- **Bodies read the declared list.** A block that declares units emits `UNITS='<u1> <u2> …'` as the first
  line inside the body subshell. All ten bodies are `for u in $UNITS; do … done` loops, the one-unit bodies
  included: SC2043 fires only on a literal one-word list, so the `if` form is retired. The validates keep
  their explicit unit names (one line, no loop).
- **Pinned to the collector and to the validate.** `TestServiceScriptsNameTheCollectorsUnits` (Linux, beside
  the services table) compares each service control's `units`, as a set, with the `provesInstall` units of the
  rows it maps to in `services.go` (`tftp_talk_disabled` maps to two rows). It requires the `.service`/`.socket`
  tokens of the control's `validate` to equal that set, and requires that no `script` of a unit-declaring
  control names a unit literally. This closes 3D-2 Task 3 N1 for `units` and the validates; a token scan
  still sees only `.service`/`.socket` words. The ten controls are `automount_disabled`,
  `dos_services_disabled`, `finger_disabled`, `nfs_server_disabled`, `nis_disabled`, `rpcbind_disabled`,
  `rservices_disabled`, `snmp_disabled`, `telnet_disabled` and `tftp_talk_disabled`; the test asserts the count.
- **Executed only against a stub.** A Go test that runs a rendered script declaring units puts a stub
  `systemctl` first on `PATH`. The stub is a temp-dir script that logs its argv and answers `cat`,
  `is-enabled`, `is-active` and `show` from fixture files, and changes its fixture state on `enable`,
  `disable`, `mask`, `unmask` and `start`. Nothing in the suite reaches the runner's systemd.
- **`TestUnitHelpersRestoreRecordedState`** (Linux) drives every recorded state through a failed block:
  `enabled`, `enabled-runtime`, `disabled` + `active`, `masked`, `masked-runtime`, `masked` + `active`,
  `linked`, `static`, `absent`, `unknown`, an `absent` record whose unit exists on a second run, an `Also=`
  partner turned on by `enable`, an `enable` that exits 0 but leaves the unit disabled, a masked socket with an
  enabled service, and an active dependant. It asserts:
  - the logged call sequence, with the seven passes in order;
  - that the first record is kept on a second run;
  - every `not restored` line;
  - `ROLLBACK INCOMPLETE` when a stubbed call fails.
- **The D34 line contract covers units.** `fullPlan` gains a control that declares `units`, so the `UNITS=`,
  `save_units` and `restore_units` lines are rendered and admitted explicitly by
  `TestScriptEveryLineIsTemplateBodyOrComment`. A poison control declaring the unit `x';id;'` must make
  `remedy.Build` refuse the plan.

## 4. Proof on hosts (Q-3)

**The table.** `controls/testdata/_roundtrip.yaml` (ignored by the fixture harness, as `_mutants.yaml` is)
holds one entry per scripted control, sorted by id. An entry is proven on some rows (`images`), optionally
naming the declared units those rows do not exercise (`unproven_units`), or `unproven` as a whole:

```yaml
- id: muster.service.finger_disabled
  unproven: no matrix image ships a systemd unit for a finger server
- id: muster.service.tftp_talk_disabled
  images: [almalinux9-init, rocky9-init]
  unproven_units:
    talk.socket: no package in the image's enabled repositories
- id: muster.service.telnet_disabled
  images: [almalinux9-init, rocky9-init]
```

The reason vocabulary is free text that names one of three causes:

- no systemd unit (the server ships only for inetd);
- no package in the image's enabled repositories;
- the unit cannot run in a container.

`TestEveryScriptedControlIsInTheRoundtripTable` (`internal/controls`) reads the table and the `fix-roundtrip`
job of `.github/workflows/ci.yml` (`yaml.v3`, already a module dependency). It asserts that:

- the table is sorted by id;
- its ids are exactly the shipped set's scripted ids;
- each entry has either a non-empty, duplicate-free `images` or an `unproven` reason, never both;
- `unproven_units` appears only beside `images`, and each of its keys is one of that control's declared units;
- every key an `images` list names is the `key` of a matrix row;
- every matrix row has a `key` and a non-empty `seeded`;
- each row's `seeded`, split on whitespace and compared as a set, equals the ids whose `images` name that row;
- no `muster.service.*` id names a row whose `init` is `"false"`.

**The probe.** The image assignments are the plan's to settle. Its first task probes each image in
throwaway containers and records, for every declared unit:

- whether a package in the image's enabled repositories ships it;
- whether `enable --now` brings it to `active`;
- whether it carries `Also=`, and which units `Requires=`, `BindsTo=` or `PartOf=` it.

It also records what each image ships at `/etc/machine-id`. The table records what the probe found. A server
packaged only as an inetd service (Debian's `telnetd`, `fingerd`, `rsh-server`, `talkd`) is out of the
scripts' reach, which disable systemd units and leave inetd alone, and is `unproven` with that reason. A row
does not seed a provider and its dependant unless the probe showed that the dependant is restarted by pass 6.

**The matrix.** The rows gain a `key` (`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`) and,
for the built row, `build: debian12-init` naming its local tag `muster-ci/debian12-init`. The image is built in
the job from this inline Dockerfile:

```dockerfile
FROM debian:12
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv netbase acl \
 && systemctl mask getty@tty1.service console-getty.service \
 && : > /etc/machine-id && rm -f /var/lib/dbus/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
```

Emptying `/etc/machine-id` makes systemd generate a fresh id at each container's first boot, as the EL init
images do when they ship it empty. The probe confirms that for every init image.

- **Boot.** Every init row (built or pulled) is started with `--privileged --cgroupns=host` and waited for by
  `ci/roundtrip/wait.sh <cid> <key>`. That script polls `timeout 60 docker exec <cid> systemctl
  is-system-running --wait` up to 30 times. It fails the job when the state never becomes `running` or
  `degraded`, printing `systemctl --failed`.
- **Seed scripts.** The seed commands move from the workflow into `ci/roundtrip/<key>.sh`. The checkout's
  `ci/roundtrip/` is mounted read-only into the container at `/ci`, beside `bin/` at `/m`, and the script runs
  there.
- **shellcheck.** `make shellcheck` and the CI shellcheck step cover `ci/roundtrip/*.sh` and fail when the glob
  is empty.

**Seeds.** Each `ci/roundtrip/<key>.sh` installs its packages and starts its units. On Debian-family rows the
install runs under a temporary `/usr/sbin/policy-rc.d` that exits 101, so package scripts start nothing; the
script removes it afterwards and runs `systemctl reset-failed`. The script then applies the probe's decision
per unit explicitly: `enable --now`, or `enable` alone for a unit that cannot start in a container. It
loosens the files:

- `chmod 664 /etc/passwd`;
- `chmod 666 /etc/services`, installing `netbase` first where the image lacks the file;
- `install -m 644 /dev/null /etc/hosts.lpd`;
- `chmod 644 /etc/hosts`.

Each seed script ends with its own settle check over its own two lists, `START_UNITS` and `ENABLE_ONLY_UNITS`.
Every unit in the first must be `active`, every unit in the second must be `inactive`, and anything else
fails the job naming the unit. A seed that would remove the host's own access is out of scope; none of the
sixteen needs one.

**Container layout.** Each row's work directory `$d` has one subdirectory per container: `$d/repair` and
`$d/fail`, mounted at `/out` in their own container. A single `trap` removes both containers.

**The repair run** (every row, first container) is the 3D-2 job: collect, plan, assert every seeded id is a
planned scripted item, run the script (exit 0), collect again, every seeded id is `PASS` or `NOT_APPLICABLE`.

**The failure run** (init rows only) uses a second container, started and seeded like the first:

1. collect and plan inside this container — never reuse the repair run's script — and assert that
   `fix.host_guard` is `on` in both plans and that the two plans' `run.host.machine_id_hash` values are
   non-empty and differ; otherwise fail, naming the row;
2. record:
   - `systemctl is-enabled` and `is-active` of every unit the planned scripted service items declare, and of
     every unit `Requires=`, `BindsTo=` or `PartOf=` them;
   - for every backup path any planned scripted item declares: `stat -c '%u %g %a'`, `sha256sum` and, where
     `getfacl` exists, `getfacl -cp`. A path that does not exist is recorded `absent`: the sshd block creates
     its drop-in, and the rollback must remove it;
3. **the guard run:** copy the repair run's script from `$d/repair` into `$d/fail` as `repair-fix.sh` and run it
   in this container. It must exit 2 with the refusal line, and step 2's record must still hold afterwards;
4. copy this container's script and rewrite the copy, never muster's output. The renderer emits a fixed
   comment line `  # validate` immediately before every validate subshell (admitted by the line contract).
   In each planned scripted block, the line after the one after that marker — the first command inside the
   validate subshell — becomes `    false`. A step asserts that the copy differs from the original in exactly
   one line per planned scripted block (every scripted block has a validate: `script_needs_validate`);
5. run the copy under `set +e`; require exit 1, one `validate failed, rolling back` line per block, and no
   `ROLLBACK INCOMPLETE`, `not restored` or `rollback failed` line;
6. require every unit state, stat, checksum and ACL to equal step 2's record.

Every planned scripted block takes part in the failure run, seeded or not (on Debian, for instance,
`shadow_permissions`), so the record covers everything the script would touch. The job's `timeout-minutes`
rises to 40. The plan measures the Debian build and the second container on the first branch run, and
records the times in its Execution notes.

## 5. File scripts and the small items (Q-4, Q-5)

**Symbolic modes.** The five file scripts clear forbidden bits instead of setting a mode:

| control | was | becomes |
|---|---|---|
| `hosts_permissions`, `hosts_lpd_permissions` | `chmod 600` | `chmod u-xs,g-rwxs,o-rwxt` |
| `passwd_permissions`, `services_permissions` | `chmod 644` | `chmod u-xs,g-wxs,o-wxt` |
| `shadow_permissions` | `chmod 400` | `chmod u-wxs,g-rwxs,o-rwxt` |

In `passwd_permissions` and `shadow_permissions` the `setfacl -b` line (behind its `command -v` guard) moves
before the `chmod`. On a file with an extended ACL the group bits are the ACL mask, so a `chmod` first would
change only the mask, and `setfacl -b` would then restore a wide `group::` entry as the group bits.

Each `validate` becomes one line over the same `stat -c` format the control's validate uses today
(`%u %g %a`, shadow `%u %a`):

```sh
case "$(stat -c '%u %g %a' /etc/hosts)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
```

- **The patterns** are the modes of the control's default `allowed_modes`, in its list order. For `passwd`,
  which has no parameter, they are the literal list of its mode clause. Each is written as
  `strconv.FormatInt(mode, 8)` (unpadded, as `%a` prints) behind an owner prefix. The trailing `*) false`
  arm is required, because a `case` that matches nothing exits 0.
- **`TestFileValidatesAcceptTheDefaultModes`** (`internal/controls`) pins the five ids and asserts the count.
  Its owner table is fixed in the test: `%u %g %a` with `0 0` for four controls, `%u %a` with `0` for shadow.
  It regenerates each validate byte for byte from `backup[0]`, the format, the prefix and the pattern list,
  and compares the result with the shipped validate.
- **`TestFileScriptsRepairOnARealFile`** (`internal/remedy`, Linux, skipped unless euid is 0; CI's root step
  runs it). For each control it creates a temp file, `chown 0:0`, and substitutes the path into the body and
  the validate. At every allowed mode the validate exits 0. At each loosened mode (with special bits, with an
  extended ACL carrying `g::rw` plus a named entry where `setfacl` exists) the validate exits 1, the body
  runs, and the validate then exits 0. A file stricter than the guide keeps its mode.
- **The texts.** `text_en`/`text_ko` keep the guide's target mode and gain "(the script only clears bits; a
  stricter file is left as it is)". The owner lines are unchanged.

**Shared backup paths and units** — the two set-level rules of §3.

**Escape.** `escapeRune` spells out:

- every rune of `unicode.Cf` (format: the soft hyphen, the bidirectional controls U+061C, U+200E, U+200F,
  U+202A–U+202E and U+2066–U+2069, the zero-width runes U+200B–U+200D, U+2060–U+2064, U+FEFF, U+FFF9–U+FFFB,
  and the tag block);
- `unicode.Zl` and `unicode.Zp` (U+2028, U+2029);
- the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0.

It writes them as `\u%04x`, or as `\U%08x` above U+FFFF. Every caller of `Escape` and `EscapeNoCut` gets the
change: check's and fix's tables, the script's comment lines, waiver, profile and tuning text, and control
text. Output changes only where a newly escaped rune occurs (CHANGELOG "Changed"; no shipped control text
carries one).

- **`TestEscapeSpellsOutBidiAndSeparators`** pins the classes and their edge cases: U+00AD, U+061C, U+200D,
  U+2028, U+3164, U+E0001, and a plain Hangul syllable left as it is. It exports the rune list for the poison
  tests.
- **The poison tests.** Remedy's `poison.sh`/`poison.table` goldens gain the runes. Report's
  `TestTablePoisonedSnapshotWritesNoRawControlBytes` adds them to its poison string and asserts
  `!strings.ContainsRune(out, r)` over the list. Remedy's `TestTablePoisoned` gains the same rune check.

**`--quiet`.** The service bodies call `systemctl --quiet disable --now` and `systemctl --quiet mask`, and the
unit helpers pass `--quiet` to every changing call. `--quiet` suppresses systemctl's result lines; it is not
a promise that a re-run prints nothing (systemd's own warnings and the template's `keeping the first` lines
remain).

## 6. Tests, CI and documents

**Tests.** The new tests named in §2–§5, plus the following:

- `TestLintRules` gains a case for every per-control rule of §3.
- `TestPlanRollbackVocabulary` gains `units`.
- `TestScriptGolden` regenerates the five goldens: `full.sh` gains the guard on, a units control and the
  `# validate` markers, and `all-scripted.sh` renders the ten `UNITS=` bodies.
- `TestScriptUnitsBlockOrder`: `save_units` precedes the body subshell, `restore_units` stands on every failure
  path, and every validate subshell follows a `# validate` marker.
- `TestJSONGolden` gains `host_guard` and `units` in their positions.
- `FuzzMachineIDHash` joins `fuzzTargets`.
- The mutation test must leave zero survivors.

**CI.** The `fix-roundtrip` matrix of §4 with its repair, failure and guard runs; `ci/roundtrip/wait.sh` and the
seed scripts; the shellcheck step over `ci/roundtrip/*.sh`. The examples refresh is mandatory before the
merge, because the fix reports change.

**Documents** (English and Korean in the same commit).

- **Main design.**
  - D34 amended, and §4.2's `internal/remedy` row with it (§2).
  - §6.2 gains `units` and the per-control lint rules.
  - §6.8 gains the two set-wide rules.
  - §7.5 gains the guard, the unit helpers and exit 2's third cause.
  - §10.2 marks 3D-2b merged and names 3D-2c.
- **`CLAUDE.md` "Fix (stage 3D-2)"** gains the guard, `units`, the round-trip table and the symbolic modes. It
  replaces every sentence this design makes false:
  - a `script` needs a `rollback` or `backup` (now: `rollback`, `backup` or `units`; and a `validate`);
  - `validate` is one line, `&&`-joined (now: one line, `&&`-joined conditions or a single `case` with a
    `*) false` arm);
  - the service-body sentence (now: declare `units`, loop over `$UNITS`);
  - rollbacks unmask every unit, then `enable --now` every unit;
  - a one-unit body uses `if`;
  - the `fix-roundtrip` description;
  - the exit-2 causes;
  - the `make shellcheck` bullet (now with `ci/roundtrip/*.sh`).
- **`CONTRIBUTING` pair.**
  - A service script declares `units` and loops over `$UNITS`.
  - The validate rule above.
  - A new scripted control is added to `_roundtrip.yaml`.
- **README pair.** The status line and the roadmap entry.
- **`THREAT_MODEL.md`.** The host guard, `MUSTER_ANY_HOST`, the hash in the script, and the three limits of §2:
  the guard fails open without a hash, does not catch a crafted snapshot, and cannot tell cloned ids apart.
- **`examples/README.md`.** The fix reports now carry the guard line.
- **`CHANGELOG`.**
  - Added: the host guard, `units`, the failure and guard runs.
  - Changed: `Escape`, the rollback vocabulary, the prologue order, `machine_id_hash` empty for a malformed id.
  - Controls: the sixteen's remediation blocks, with no verdict change.

## 7. Parked

- Scripts for controls beyond the sixteen, and the parameter-substitution rule they need (3D-2c).
- `fix --dry-run --result`, a per-subject plan for `each` controls, a structural verdict marker on
  `check.Result` if a fourth consumer appears, and `explain` — unchanged from 3D-2 §8.
- Restoring a `linked` unit's link, and a unit's recorded activity while it stays masked (logged, §3).
- A masked socket in front of an active service (§3 ordering).
- Telling cloned hosts apart beyond the machine id (§2).
- A token scan of unit names that are not `.service`/`.socket` words (3D-2 Task 3 N1, beyond `units`).
- Whatever the plan's probe marks `unproven` or `unproven_units`, with its reason, until an image packages it
  as a systemd unit.
