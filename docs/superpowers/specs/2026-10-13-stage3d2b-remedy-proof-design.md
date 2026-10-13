# Stage 3D-2b — the review script, proven: host guard, unit state, round trips

Korean pair: `2026-10-13-stage3d2b-remedy-proof-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§6.2 schema, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycle it completes:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10; §8 Parked). Rulings of this design are the Q list.

## 1. Scope and intent

3D-2 shipped `fix --dry-run`, its plan and the review script, and rewrote the sixteen controls that carry a
`script`. Four of the sixteen are proven on a real system by the `fix-roundtrip` job (`rpcbind_disabled`,
`root_remote_login`, `hosts_permissions`, `shadow_permissions`); the other twelve are proven only
syntactically. The service rollbacks re-enable every unit they name whatever its state before, and nothing
stops a script planned from one host's snapshot from running on another. 3D-2b closes those gaps for the
sixteen. It adds no new scripted control: scripts for further controls, and the parameter-substitution
rule they need, are 3D-2c.

- **Q-1 — A script runs on the host it was planned for.** The script carries the snapshot's
  `host.machine_id_hash` and refuses, before it changes anything, a host whose machine id hashes otherwise
  (exit 2). `MUSTER_ANY_HOST=1` overrides it with a warning. A snapshot without a well-formed hash turns the
  guard off, and the header says so (§2).
- **Q-2 — A service rollback puts back what was there.** A service control declares its units
  (`remediation.units`); the template records each unit's enablement and activity before the body runs
  and, on failure, restores exactly that — re-masking what was masked, enabling only what was enabled,
  starting only what was active. The nine hand-written service rollbacks are deleted (§3).
- **Q-3 — Every scripted control is proven on a host, or says why it cannot be.** A table under
  `controls/testdata/` names, for each of the sixteen, the images whose round trip seeds and repairs it,
  or the reason none can. A test holds the table, the shipped set and the CI matrix equal. The matrix gains
  a Debian 12 init container built in the job from the official image. Each init image also proves the
  failure path: a deliberately failed block leaves units and files as they were (§4).
- **Q-4 — A file script only removes bits.** The five permission scripts use symbolic `chmod` that clears
  the bits the guide forbids, so a file already stricter than the guide is never loosened, and their
  validates accept every mode of the control's default `allowed_modes` (§5).
- **Q-5 — The small parked items.** Lint refuses two scripted controls sharing a backup path; `Escape`
  spells out the line and paragraph separators and the bidirectional controls; the service bodies pass
  `--quiet` to `systemctl` (§5).
- **Q-6 — No verdict changes.** No `checks`, `params` or fact changes; `controls/VERSION` moves because
  remediation blocks change. The plan JSON gains `host_guard` and the `units` rollback value (plan schema
  stays 1: additive).

## 2. The host guard (Q-1)

`remedy.Build` copies `report.Snapshot.Host.MachineIDHash` into `FixBlock.MachineIDHash` when it matches
`^[0-9a-f]{64}$`, and leaves it empty otherwise. The plan JSON gains `fix.host_guard: "on" | "off"`; the hash
itself is not in the JSON (it is already in the snapshot the plan names by digest). The table is unchanged.

The prologue gains, after the root check and before the backup directory is created:

```sh
MUSTER_SNAPSHOT_HOST=<hash>
here=$(muster_machine_id_hash)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi
```

with the hash helper in the prologue:

```sh
muster_machine_id_hash() {
  id=$(cat /etc/machine-id 2>/dev/null) || id=
  id=$(printf '%s' "$id" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  [ -n "$id" ] || return 0
  printf '%s' "$id" | sha256sum | cut -d' ' -f1
}
```

- The trim mirrors the collector's `readTrim` (`strings.TrimSpace`); `$(…)` drops trailing newlines first.
  `TestHostGuardHashMatchesTheCollector` (Linux) runs the helper over machine-id files with a trailing
  newline, CRLF, leading blanks and none, and compares with the collector's Go computation.
- A host with no or an empty `/etc/machine-id` yields an empty `here`, which differs from any hash: refused.
- When the guard is off the block is replaced by one comment line, `# host guard: off (the snapshot has no
  machine id)`, and the header's first comment line is unchanged.
- **D34 amended.** "No host value is substituted into a command" gains one exception: the machine-id hash,
  admitted only as 64 lowercase hex characters, which carry no shell syntax. `TestScriptEveryLineIsTemplate
  BodyOrComment` admits exactly that one line as template text, and the poison plan carries a malformed hash
  to prove it lands nowhere.
- Exit 2 now has three causes (not root, an unusable backup directory, another host); nothing has run in any
  of them. `MUSTER_ANY_HOST` is read only when the hashes differ.

## 3. Unit state (Q-2)

**Schema and lint.** `Remediation` gains `Units []string` (`yaml:"units,omitempty"`). Lint:

- every entry matches `^[A-Za-z0-9@._:-]+\.(service|socket)$`; no duplicates;
- `units` requires `script`;
- `units` counts as a way back: a `script` needs `rollback`, `backup` or `units`;
- `units` and `rollback` are exclusive (one way to undo a unit, not two);
- in the shipped set, `TestServiceScriptsNameTheCollectorsUnits` (Linux, beside the services table) compares
  each service control's `units` with the `provesInstall` units of its rows in `services.go`, exactly and in
  order — it replaces the token scan of the bodies (3D-2 Task 3 N1).

**Template.** The prologue gains two helpers; a block that declares units calls `save_units` after `backup`,
and `restore_units` on its failure path after the declared `rollback` (there is none for these controls) and
before `restore`:

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/units/$u"
    { [ -e "$f" ] || [ -L "$f" ]; } && { log "$u: unit state exists, keeping the first"; continue; }
    if systemctl cat "$u" >/dev/null 2>&1; then
      e=$(systemctl is-enabled "$u" 2>/dev/null) || :
      a=$(systemctl is-active "$u" 2>/dev/null) || :
      printf '%s %s\n' "${e:-unknown}" "${a:-unknown}" > "$f" || return 1
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  rc=0
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$e" in masked|masked-runtime|absent) ;; *) systemctl --quiet unmask "$u" || rc=1;; esac
  done
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$e" in
      enabled) systemctl --quiet enable "$u" || rc=1;;
      enabled-runtime) systemctl --quiet enable --runtime "$u" || rc=1;;
      masked) systemctl --quiet mask "$u" || rc=1;;
      masked-runtime) systemctl --quiet mask --runtime "$u" || rc=1;;
    esac
  done
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$a" in active|activating|reloading) systemctl --quiet start "$u" || rc=1;; esac
  done
  return $rc
}
```

- The three passes keep the property 3D-2 found (Z-23): no unit is enabled or started while a unit it
  needs is still masked. Every other state (`disabled`, `static`, `indirect`, `generated`, `absent`, …)
  is left as the body left it, after the unmask; `inactive` is not stopped (the body already stopped it).
- Unit names in the state directory are the declared names, which the lint charset makes safe path
  components. A first record is kept across runs with the same `MUSTER_BACKUP`, as a first file copy is.
- A failed `save_units` stops the block before the body, with `backup failed, nothing changed` (the same
  message as a failed copy). A failed `restore_units` logs `ROLLBACK INCOMPLETE`, as `restore` does.
- **Bodies read the declared list.** A block that declares units emits `UNITS='<u1> <u2> …'` as the first
  line inside the body subshell, and the nine bodies loop over `$UNITS` instead of repeating the names. The
  value is the control's lint-checked declaration, not a host value. The validates keep their explicit unit
  names (one line, no loop).
- **Rollback vocabulary.** `Item.Rollback` becomes `none | declared | restore_backup | units | both`; `both`
  means two or more of `rollback`, `backup`, `units` are declared. The table's rollback column shows the
  same word.

## 4. Proof on hosts (Q-3)

**The table.** `controls/testdata/_roundtrip.yaml` (ignored by the fixture harness, as `_mutants.yaml` is)
holds one entry per scripted control, sorted by id:

```yaml
- id: muster.service.telnet_disabled
  images: [debian12-init, almalinux9-init]
- id: muster.service.finger_disabled
  unproven: no image of the matrix packages a finger server
```

`TestEveryScriptedControlIsInTheRoundtripTable` (`internal/controls`) asserts that the table's ids are
exactly the shipped set's scripted ids, that each entry has `images` or `unproven` and not both, and that
for each matrix row of `.github/workflows/ci.yml`'s `fix-roundtrip` job (read with `yaml.v3`) the `seeded`
list equals the ids whose `images` name that row's `key`. The image assignments in this design are the
hypothesis; the plan's first task probes each image's package set in throwaway containers and the table
records what it found.

**The matrix.** The rows gain a `key` (`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`).
`debian12-init` is built in the job: `docker build` from an inline Dockerfile `FROM debian:12` that installs
`systemd systemd-sysv` and runs `/sbin/init`, started like the EL init images (`--privileged
--cgroupns=host`). Each row's seed commands move from the workflow into `ci/roundtrip/<key>.sh`, run inside
the container; `make shellcheck` and the CI shellcheck step cover `ci/roundtrip/*.sh`. Seeds install the
packages, `systemctl enable --now` their units, and loosen the files (`chmod 664 /etc/passwd`, `chmod 666
/etc/services`, `install -m 644 /dev/null /etc/hosts.lpd`, `chmod 644 /etc/hosts`). A seed that would
remove the host's own access (no such seed exists for the sixteen) is out of scope.

**The repair run** is the 3D-2 job, per row: collect, plan, assert every seeded id is a planned scripted
item, run the script (exit 0), collect again, every seeded id is `PASS` or `NOT_APPLICABLE`.

**The failure run** (init rows only), after the repair run on a fresh container with the same seeds:

1. record `systemctl is-enabled` and `is-active` of every unit the seeded service controls declare, and
   `stat -c '%u %g %a'` of every declared backup path (`absent` when it does not exist — the sshd block
   creates its drop-in, and the rollback must remove it again);
2. copy the script and rewrite, in the copy only, the validate subshell of every seeded block so its first
   command is `false`; a step asserts the rewrite changed exactly one line per seeded block;
3. run the copy and require exit 1 and one `validate failed, rolling back` line per seeded block;
4. require the unit states and file stats to equal step 1's record.

This proves `restore_units` and `restore` against real systemd and real files; the unit test of the
template (`TestScriptBodyFailureReachesTheFailurePath`) keeps proving the shell shape under a temp dir.

## 5. File scripts and the small items (Q-4, Q-5)

**Symbolic modes.** The five file scripts clear forbidden bits instead of setting a mode:

| control | was | becomes |
|---|---|---|
| `hosts_permissions`, `hosts_lpd_permissions` | `chmod 600` | `chmod u-xs,g-rwxs,o-rwxt` |
| `passwd_permissions`, `services_permissions` | `chmod 644` | `chmod u-xs,g-wxs,o-wxt` |
| `shadow_permissions` | `chmod 400` | `chmod u-wxs,g-rwxs,o-rwxt` |

Each `validate` becomes one `case` over `stat -c '%u %g %a'` (shadow: `%u %a`) whose patterns are exactly the
modes of the control's default `allowed_modes` — or of the mode clause's literal list for `passwd`, which
has no parameter — in octal; `TestFileValidatesAcceptTheDefaultModes` derives the pattern list from the
control and compares. The `text_en`/`text_ko` keep naming the guide's mode as the target. The ACL and owner
lines are unchanged.

**Shared backup paths.** A set-level lint rule `backup_path_shared` refuses two scripted controls that
declare the same `backup` path (the first-copy rule would let one block's restore undo the other's change).
The shipped set has none.

**Escape.** `escapeRune` also spells out U+2028, U+2029, U+200E, U+200F, U+202A–U+202E and U+2066–U+2069 as
`\u%04x`. `Escape` and `EscapeNoCut` are check's too, so a check table changes only for a snapshot carrying
those runes (CHANGELOG "Changed"); `TestEscapeSpellsOutBidiAndSeparators` pins the list and the poison
golden gains them.

**`--quiet`.** The service bodies call `systemctl --quiet disable --now` and `systemctl --quiet mask`, and the
template's unit helpers pass `--quiet` throughout, so a re-run over masked units prints nothing.

## 6. Tests, CI and documents

**Tests.** The new tests named in §2–§5, and: `TestLintRules` cases for every rule of §3 and §5;
`TestPlanRollbackVocabulary` gains `units`; `TestScriptGolden` regenerates the five goldens (prologue,
guard, unit helpers; `all-scripted.sh` renders the nine `UNITS=` bodies); `TestScriptUnitsBlockOrder` (the
`save_units` line follows `backup` and precedes the body; `restore_units` precedes `restore` on the failure
path); `TestJSONGolden` gains `host_guard`; a `cmd/muster` e2e asserts `host_guard: off` on a snapshot whose
hash is empty. The mutation test must leave zero survivors.

**CI.** The `fix-roundtrip` matrix of §4 with its repair and failure runs; the shellcheck step over
`ci/roundtrip/*.sh`. The examples refresh is mandatory before the merge (the fix reports change).

**Documents** (English and Korean in the same commit). Main design: D34 amended (§2), §6.2 gains `units`
and the lint rules, §7.5 gains the guard, the unit helpers and exit 2's third cause, §10.2 marks 3D-2b
merged and names 3D-2c. `CLAUDE.md` "Fix (stage 3D-2)" gains the guard, `units`, the round-trip table and
the symbolic modes. `CONTRIBUTING` pair: a service script declares `units` and loops over `$UNITS`; a
scripted control is added to `_roundtrip.yaml`. `CHANGELOG`: Added (the host guard, `units`, the failure
run), Changed (`Escape`; the rollback vocabulary), Controls (the sixteen's remediation blocks; no verdict
change).

## 7. Parked

- Scripts for controls beyond the sixteen and the parameter-substitution rule they need (3D-2c).
- `fix --dry-run --result`, a per-subject plan for `each` controls, `explain` — unchanged from 3D-2 §8.
- Whatever the plan's probe marks `unproven`, with its reason, until an image packages it.
