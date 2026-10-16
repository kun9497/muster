# Stage 3D-2c — scripts beyond the sixteen: parameters, state records, the runner row

Korean pair: `2026-10-14-stage3d2c-remedy-scripts-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§6.2 schema, §6.8 lint, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycles it builds on:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10) and `2026-10-13-stage3d2b-remedy-proof-design.md`
(Q-1..Q-6). Rulings of this design are the E list; E-8..E-12 came out of the first spec review (five lenses,
three refuters per finding, a critic) and E-13 out of the second (four lenses over the folded draft); both
are folded in place. The family map the bodies were written from is the
cycle's ignored workspace file `family-map.md`; its findings are restated here where they bind. Section 8 records where
the build departs from this text; where they disagree, section 8 is the design as built.

## 1. Scope and intent

Sixteen controls carry a `script`. Of the 101 that do not, 88 are `auto`, and 32 of those have a body that is
a template: write a sysctl line and apply it, write a modprobe line and unload the module, clear mode bits,
replace a configuration line, write an sshd drop-in. The rest need a judgment per host (which partition to
split, which listener to allow, which account to lock) and stay text. This cycle scripts the 32 (48 scripted
controls in all), and builds the two mechanisms they need: a way for a parameter's value to reach a script,
and a way to record and restore state that is not a file's content — a mode, a sysctl value, a loaded module.

- **E-1 — A parameter reaches the script as a block variable, never as text substitution.** A control lists
  `script_params`; the template emits `P_<name>='<value>'` as the first lines of the block function, so the
  body, the validate and the declared rollback all see them. The value is the one in force (default, profile
  or tuning), and it reaches the line only when it matches the type's charset; otherwise the item is text-only
  (`params_unsafe`). The `params_tuned` rule applies only to a scripted control that declares no
  `script_params` (§2).
- **E-2 — State is recorded per block.** Every record a block takes — a file copy, a unit's state, a path's
  mode, a sysctl value, a module's load state — lives under `$MUSTER_BACKUP/blocks/<fn>/`, so a block
  restores the state it found, not the state an earlier block found. The `backup_path_shared` and
  `units_shared` lints go: two blocks may now declare the same path or unit, and the later restores to the
  state the earlier left. A declared backup path that did not exist is recorded as absent and removed on
  restore (§3).
- **E-3 — Three more state kinds.** `modes` (a path's owner, group, mode and type; `dir/*` patterns expanded by
  `find`, dotfiles included, symlinks excluded), `sysctl` (a key's runtime value) and `modules` (loaded or
  not). Each has a `save_`/`restore_` helper in the prologue, and the failure path runs them in a fixed order
  around the file restore (§3).
- **E-4 — The bodies.** Sixteen sysctl controls, three module controls, nine file-permission controls, three
  account controls and one sshd control, written to the 3D-2b discipline: bits are cleared, never set; a
  drop-in is written, never a vendor file; a value the host must supply (an account name, a path under
  `/var/log`) is enumerated on the host by the script, never read from the snapshot (§4). One existing script
  (`root_remote_login`) keeps its rollback (E-11).
- **E-5 — Absent is not always hopeless.** A control may declare `script_on_absent: true`: a FAIL the
  evaluator reached through `absent_means: fail` is then planned with its script, because the script writes
  the very line that is absent (`PASS_MIN_LEN`, a `ClientAliveInterval`). The 3D-2 rule (X-2, Z-6) stands for
  every other control (§2).
- **E-6 — The runner proves what containers cannot.** Every `beyond` control gates on `env.container eq none`,
  so the sysctl, module, bootloader and audit-log scripts are judged only on a host. `fix-roundtrip` gains a
  `runner` row that seeds, repairs and fails on the GitHub runner VM itself, without docker. It has no guard
  run (one host); its failure run re-seeds the same VM and plans afresh (§5).
- **E-7 — No verdict changes.** No `checks` or facts change. One list parameter's default order moves so that
  the first element is the value the guide names (`umask_policy.acceptable`); `op: in` does not care about
  order. `controls/VERSION` moves. Four risks move: the two forwarding controls and `usb_storage_disabled`
  to `restart_service`, `password_policy` to `lockout_risk`. The plan JSON gains `script_params`,
  `script_on_absent`, `modes`, `sysctl`, `modules` and the `state` rollback value; plan schema stays 1.
- **E-8 — A body writes a value only when the current one is outside the clause's accepted set.** A sysctl
  key judged `in [1,2]` or `gte 2` that already satisfies the clause is left alone; a `login.defs` line, a
  `faillock` line, a `pwquality` key or an account's ageing field is changed only in the tightening direction,
  and the gate reads the value the way the collector does (first line of `login.defs`, last line of
  `faillock.conf`, the merged `pwquality` chain). The value written when a write is needed is the guide's
  value, or the first element of the list in force — except a one-way guide value, where the body writes the
  list's reversible member (`unprivileged_bpf_disabled` 2, §4.1). A body therefore
  never loosens a stricter host, never tightens a key the clause already accepts (`rp_filter` 2 stays 2), and
  never touches a one-way value (`unprivileged_bpf_disabled` 1, `ptrace_scope` 3) that already passes. The
  validate proves set membership, not equality with the written value (§4.1, §4.4).
- **E-9 — `find` discipline.** A `find` or `chmod` over a directory the host may lack runs under
  `if [ -d <dir> ] && [ ! -L <dir> ]; then …; fi`, and a single path under `if [ -f p ] && [ ! -L p ]`; every
  `find` that changes a mode carries `! -type l` or the type the control judges (`-type f` on a spool); a
  validate's `find` tests the complement of the allowed bits — 07777 minus the largest allowed mode (`≤ 0640`
  → `-perm /7137`, `≤ 0600` → `/7177`, `≤ 0440` → `/7337`) — and `! -user root` where the uid is judged; a
  body never chmods through a symlink (§4.3).
- **E-10 — `password_policy` is `lockout_risk` and tightens only.** The ageing loop enumerates accounts by the
  collector's rule (a shadow field that is not empty and does not start with `!` or `*`), sets `-M` only on an
  account whose maximum is empty or larger than the parameter and `-m` only where the minimum is smaller,
  skips and logs an account whose password is already older than `max_days` (the write would expire it on
  the spot), and records each account's previous fields under `$MB` for a declared rollback that replays
  them with `chage`. `/etc/shadow` is never copied. Fields travel `:`-delimited end to end, so an empty field
  is never lost (§4.4).
- **E-11 — A declared rollback of a control whose script writes a file a daemon re-reads removes that file
  itself, then tests and reloads.** `restore`'s absent-marker pass is then a harmless second pass. The two
  sshd controls keep (and the new one gains) the `rm -f` line; the failure-path order of 3D-2 (declared
  rollback first, `restore` later) stands (§3, §4.4).
- **E-12 — The modules helper reloads with `--ignore-install`.** The record says the module was loaded; a
  `restore_modules` that honours the `install … /bin/false` line `restore` has just put back could never
  reload it. The runner failure run therefore re-collects and re-plans after the re-seed, and the seed
  removes muster's drop-ins so the same blocks are planned (§3, §5).
- **E-13 — A write's side effect on another judged key belongs to the writer.** Writing `net.ipv4.ip_forward`
  makes the kernel set `net.ipv4.conf.all.accept_redirects` to the opposite value. The `ip_forwarding_disabled`
  body reads that key before the write and puts it back after, at runtime and as a line after `ip_forward` in
  its own drop-in; the key is in that control's `sysctl` list, and the pin test admits it as the one declared
  companion key. The plan's probe records any other side effect among the sixteen controls' keys (§4.1).

## 2. Parameters in scripts (E-1, E-5)

**Schema.** `Remediation` gains `ScriptParams []string` (`yaml:"script_params,omitempty"`) and
`ScriptOnAbsent bool` (`yaml:"script_on_absent,omitempty"`). An entry is a parameter name. A list parameter is
carried whole, its elements joined by one space; a body that needs the first element takes it with
`first=${P_<name>%% *}` (no `set --`, which shellcheck flags as SC2086), and a validate that needs
membership writes the one-`case` idiom
`case " $P_<name> " in *" $(…) "*) ;; *) false;; esac`. The block variable is `P_<name>`.

**Lint** (per control; each a `TestLintRules` case):
- `script_params_declared` — every entry names a `params` key of the control, once.
- `script_params_used` — every `$P_<name>` or `${P_<name>` in `script`, `validate` or `rollback` is declared,
  and every declared entry is used in `script`.
- `script_params_needs_script`, `script_on_absent_needs_script`.
- `script_params_default_safe` — every default value an entry names passes the charset (below).

**Charset, by parameter type.** `int`: `^-?[0-9]+$`. `bool`: `true` or `false`. `string` and each element of
`list<string>`: `^[A-Za-z0-9._/@:+,=-]+$`. Each element of `list<int>`: as `int`. A whole list is its
elements joined by one space, so a body iterates it with `for x in $P_<name>`. No value can carry a quote, a
space (inside an element), `$`, a backtick, `;`, `|`, `&` or `\`, so `'…'` holds it as data.

**Where a value may stand.** A `P_` value enters a command only (a) after `=` in a `key=$P_x` word, (b) as the
operand of an option letter (`-M "$P_max_days"`) or after `--`, (c) as a non-first operand, (d) as an awk
`-v` variable, or (e) as the replacement of a `sed` `s` command whose delimiter is `|` (outside the charset;
`&` and `\` are outside it too, so the replacement is literal). A value never stands first on a line and
never where a leading `-` would read as an option. CONTRIBUTING says so, and a Linux test greps every shipped
body for a `s/` command carrying `$P_` and for a line that starts with `$P_` or `"$P_`.

**Plan.** `Item` gains `ScriptParams []ParamValue` (`json:"script_params"`, always present, `[]` when
`Script` is false or none is declared; `ParamValue{Name, Value string}` with json `name`/`value`, sorted by
name — no map, same input same bytes) and `ScriptOnAbsent bool` (`json:"script_on_absent"`: the control's
declaration, copied only when `Script` is true, else `false`). The item's field order is `…, script,
text_only_reason, script_params, script_on_absent, rollback, backup, units, modes, sysctl, modules, validate,
planned`. `remedy.Build` reads the value in force from the check block's `Params[id][name]` (the merged
values 3D-1 records), formats it (a list joined by one space), and checks the charset. A value that fails the
charset makes the item text-only with `text_only_reason: params_unsafe` (phrase in the script: `a parameter
value cannot be carried safely; see muster check --format json: check.params`); its `script_params` is then
`[]`, so no unsafe value reaches the JSON either. The `params_tuned` branch applies only when the control
declares no `script_params` and some source is not `default`.

**Absent.** When the row's reason starts with `check.ReasonAbsentFailPrefix` and the control declares
`script_on_absent: true`, the item is scripted; the 3D-2 `absent` text-only reason applies otherwise.

**Rendering.** The block function opens with one `P_<name>='<value>'` line per entry in name order, before
`MB=`; the body subshell, the validate subshell and the declared-rollback subshell inherit them. `UNITS='…'`
stays the first line of the body subshell. `templateLines` admits exactly the rendered `P_` lines. The poison
plan gains a control with `script_params: [bad]` whose value in force is `'; id; '`: the item renders
text-only, and the value appears on no non-comment line and nowhere in the JSON.

**D34, amended once more.** "No host value is substituted into a command" keeps its one exception (the
machine-id hash). A parameter's value is not a host value: it is policy the operator declared in a profile or
a tuning file, and it enters a command only as a `P_` assignment, constrained to the charset above. The main
design's `internal/remedy` row names the hash and the `P_` assignments as the two admitted non-literal classes,
both enforced by `templateLines`.

## 3. State records (E-2, E-3, E-11, E-12)

**Per-block directories.** The block function sets `MB="$MUSTER_BACKUP/blocks/<fn>"` and creates it before
anything is recorded (a failed `mkdir` is `backup failed, nothing changed`). Under it:

| kind | where | record |
|---|---|---|
| file copies | `$MB/files<path>` | `cp -a` of the path, as 3D-2 |
| absent files | `$MB/absent<path>` | an empty marker: the declared path did not exist |
| units | `$MB/units/<u>`, `<u>.deps` | as 3D-2b |
| modes | `$MB/modes.list` | one line per path: `<uid> <gid> <mode> <type> <path>` (`type` is `f`, `d` or `o`) |
| sysctl | `$MB/sysctl.list` | one line per key: `<key> <value>` (`absent` when unreadable) |
| modules | `$MB/modules.list` | one line per module: `<name> loaded\|not-loaded` |
| ageing | `$MB/ageing.list` | written by the `password_policy` body: `<account> <min> <max>` (§4.4) |

The first record of a path, unit, key or module is kept across runs with the same `MUSTER_BACKUP`, as before,
but per block: block B's record is what B found, after A ran. An absent marker is the one record that is
replaced: when the path exists on a later run, `backup` removes the marker and takes the copy (as
`save_units` replaces `absent absent` once the unit exists). The `backup_path_shared`, `units_shared` and
`backup_reserved` lints are deleted; `units_exclusive` grows to forbid `rollback`, `backup`, `modes`, `sysctl`
and `modules` beside `units` (a service block's way back is the unit state alone).

**`backup` and `restore`**, verbatim (the copy branch is 3D-2's):

```sh
backup() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      if [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
      rm -f "$MB/absent$p"
      mkdir -p "$MB/files$(dirname "$p")" && cp -a "$p" "$MB/files$p" || return 1
    else
      if [ -e "$MB/absent$p" ] || [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then continue; fi
      mkdir -p "$MB/absent$(dirname "$p")" && : > "$MB/absent$p" || return 1
    fi
  done
}
restore() {
  brc=0
  for p in "$@"; do
    if [ -e "$MB/absent$p" ]; then
      if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
      rm -f "$p" || { log "restore: $p failed"; brc=1; }
      continue
    fi
    { [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MB/files$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}
```

A marker and a copy never coexist for one path: a path copied on run 1 and gone on run 2 keeps its copy and
gets no marker, so a failure restores it. A script that creates a drop-in gets the file removed on
failure by `restore`; a control whose daemon re-reads that file still removes it in its own rollback first
(E-11), because the declared rollback runs before `restore` and the reload must see the file gone.

**`modes`.** An entry is an absolute clean path with zero, one or two trailing `/*` segments (lint
`modes_charset`: `^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`, no duplicates; a `modes`, `sysctl` or `modules` list
without a `script` is `state_needs_script`). Lint
`modes_backup_overlap`: no `backup` path of the same control equals a `modes` entry or is matched by one
(`/etc/sudoers` beside `modes: [/etc/sudoers.d/*]` is fine; `/etc/sudoers.d/x` beside it is not) — the two
fields may otherwise coexist. The helpers expand an entry with `find <dir> -mindepth k -maxdepth k ! -type l`
where `k` is the number of `/*` segments (`k = 0`: the path itself when it exists and is not a symlink) —
dotfiles included, symlinks excluded, which is the collector's view. The template emits every entry
single-quoted (`save_modes '/etc/cron.d/*' '/etc/crontab'`; the charset admits no `'`), so the shell never
expands the `*`; `templateLines` admits the quoted line, and CI's `record()` calls the helper's expansion the
same way.

```sh
modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) if [ -e "$1" ] && [ ! -L "$1" ]; then printf '%s\n' "$1"; fi;;
  esac
  return 0
}
modes_type() { if [ -f "$1" ]; then echo f; elif [ -d "$1" ]; then echo d; else echo o; fi; }
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      P="$p" awk '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == ENVIRON["P"]) f=1 } END { exit !f }' "$MB/modes.list" && continue
      if s=$(stat -c '%u %g %a' -- "$p" 2>/dev/null); then
        printf '%s %s %s\n' "$s" "$(modes_type "$p")" "$p" >> "$MB/modes.list" || exit 1
      elif [ -e "$p" ]; then
        exit 1
      else
        log "save_modes: $p vanished, not recorded"
      fi
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode t p; do
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then continue; fi
    if [ -L "$p" ] || [ "$(modes_type "$p")" != "$t" ]; then log "restore_modes: $p changed type, left as is"; mrc=1; continue; fi
    if chown -- "$uid:$gid" "$p"; then chmod -- "$mode" "$p" || mrc=1; else mrc=1; fi
  done < "$MB/modes.list"
  return $mrc
}
```

A path with a newline in its name, or one that ends in a blank (`read` strips it), is not supported (logged
as a limit in the document; none of the declared trees carries one). Whitespace inside a path survives
`read -r` because the path is the last field. The dedupe passes the path through `ENVIRON`, not `awk -v`,
which would process backslash escapes.
A path that vanishes between `find` and `stat` (logrotate under `/var/log`) is logged and skipped, not a
failed backup. `restore_modes` never writes through a symlink and never applies a file's record to a
directory or the reverse: a recorded entry the host replaced during the block is logged and counts as
incomplete, so a spool's owner cannot turn the record into a `chmod` on `/etc/shadow`.

**`sysctl`.** Entries are kernel keys (lint `sysctl_charset`: `^[a-z0-9_]+(\.[a-z0-9_-]+)+$`, no
duplicates). `sysctl` and `backup` go together: the file is the persisted side, the record the runtime
side.

```sh
save_sysctl() {
  [ -f "$MB/sysctl.list" ] || : > "$MB/sysctl.list" || return 1
  for k in "$@"; do
    awk -v k="$k" '$1 == k { f=1 } END { exit !f }' "$MB/sysctl.list" && continue
    v=$(sysctl -n -- "$k" 2>/dev/null) || v=absent
    printf '%s %s\n' "$k" "$v" >> "$MB/sysctl.list" || return 1
  done
}
restore_sysctl() {
  src=0
  for k in "$@"; do
    v=$(awk -v k="$k" '$1 == k { $1=""; sub(/^ /, ""); print; exit }' "$MB/sysctl.list")
    case "$v" in ''|absent) continue;; esac
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
```

**`modules`.** Entries are module names (lint `modules_charset`: `^[a-z0-9_-]+$`, no duplicates). The helpers fold `-` to `_` (kmod's rule) and read `/proc/modules`, whose first field is already
folded. `restore_modules` reloads with `--ignore-install` (E-12): the record says "loaded", whatever
modprobe.d says now — `restore` has just put muster's own `install … /bin/false` line back when the file
existed at block start, and a vendor `install` line is bypassed the same way (said in the document).

```sh
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if grep -q "^$n " /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe --ignore-install -- "$n" || orc=1
  done
  return $orc
}
```

**The prologue.** Order after the 3D-2b lines: `backup()`, `restore()`, `save_units()`, `restore_units()`,
`modes_paths()`, `modes_type()`, `save_modes()`, `restore_modes()`, `save_sysctl()`, `restore_sysctl()`,
`save_modules()`, `restore_modules()`, `failed=0`. Every helper line is shellcheck-clean at the default
severity (no `A && B || C` outside the exempt forms).

**The block.** Head, in order: the `P_` lines, `MB=…; mkdir -p "$MB"`, `backup <p…>`, `save_units <u…>`,
`save_modes '<e>'…`, `save_sysctl <k…>`, `save_modules <m…>`, each `|| { log "<id>: backup failed, nothing
changed"; return 1; }`; then the body subshell. Failure path, in order: the declared `rollback`,
`restore_units <u…>`, `restore_modes` (bare: it reads the block's list), `restore <p…>` (files and absent
markers), `restore_sysctl <k…>`, `restore_modules <m…>` — the runtime value is re-applied after the file that
would persist the script's value is gone, and a module is reloaded after its `install … /bin/false` line is
gone or put back. Each restore that fails logs `ROLLBACK INCOMPLETE`; the next one still runs. The helpers
use their own variables (`spec`, `p`, `s`, `t`, `k`, `v`, `m`, `n`, `mrc`, `src`, `orc`) and never the block's
`rc`. `TestScriptEveryLineIsTemplateBodyOrComment` admits the `P_` lines, the `MB` line, the five record
lines (`backup`, `save_units`, `save_modes`, `save_sysctl`, `save_modules`) and the five restore lines
(`restore_units`, `restore_modes`, `restore`, `restore_sysctl`, `restore_modules`), each with its suffix.

**Plan.** `Item` gains `Modes`, `Sysctl`, `Modules []string` (json `modes`, `sysctl`, `modules`, after
`units`; `[]` when none, set only when `Script` is true). `Build` re-checks every entry against its lint
pattern and refuses the plan otherwise (as it does ids and units). `Item.Rollback` becomes one of six words,
decided by what the control declares:

| word | declared |
|---|---|
| `none` | nothing (a text-only item) |
| `declared` | `rollback` only |
| `restore_backup` | `backup` only |
| `units` | `units` (nothing else may stand beside it) |
| `state` | one or more of `modes`, `sysctl`, `modules`, and nothing else |
| `both` | two or more of `rollback`, `backup`, state (`modes`/`sysctl`/`modules` count as one) |

The table's column shows the word.

**Tests.** A stub-free test runs `save_modes`/`restore_modes` over a temp tree (dotfiles, a symlink, a
directory entry, a two-level pattern, a pattern that matches nothing, a path with a space; first record kept
on a rerun; a recorded file replaced by a symlink and by a directory left as is with `ROLLBACK INCOMPLETE`;
`ROLLBACK INCOMPLETE` when a path is unwritable), and `backup`/`restore` over the marker cases (absent at run
1 and present at run 2 → copied; absent both runs → removed on restore; copied at run 1 and absent at run 2
→ no marker, copy restored; a marker whose path is now a directory → logged). Stub `sysctl` and `modprobe`
(as the 3D-2b `systemctl` stub, first on `PATH`, logging argv and answering from fixture files through an
environment variable only the stubs read) drive the other two; the shipped helper keeps the literal
`/proc/modules`, and the test rewrites that literal in the helper text it extracts from the Go constant
(`strings.ReplaceAll`) to point at a fixture. Cases: a readable key, an `absent` key, a key that refuses the write; a loaded
module reloaded with `--ignore-install` in argv, an unloaded one left alone, a `modprobe` that fails. A
failure-path order test checks the six failure-path steps' order (the rollback subshell and the five
restores) in a block that declares every kind. The 3D-2b
unit tests move to `$MB/units/`.

## 4. The bodies (E-4, E-8, E-9, E-10, E-11)

Every body is POSIX `sh`, shellcheck-clean at the default severity, `set -e`-safe inside the body subshell,
and uses only literal paths, `P_` variables and what it enumerates on the host. An existence guard is written
as `if [ -f p ] && [ ! -L p ]; then …; fi`, never `[ -f p ] && …` (a false test as the last line fails the
subshell). A validate is `&&`-joined conditions, a single `case` whose last arm is `*) false`, or a single
`for` over a literal list whose conditions each end `|| exit 1` (the module validates; CONTRIBUTING admits
the third shape in this cycle). Every
control gains `idempotent: true` (already true on all) and a one-line `validate` that proves the step for the
value in force. Texts keep their sentences; where a script now exists the text names the file it writes.

### 4.1 sysctl (16)

Facts of this family are judged on the runtime side (`default_on: effective`): the verdict is `/proc/sys`.
The persisted side is evidence. So a body does both: it writes a file for the next boot and applies the value
now — but only for a key whose current value is outside the clause's accepted set (E-8). File:
`/etc/sysctl.d/99-muster-<name>.conf`, where `<name>` is the control's name with `_` replaced by `-`
(`99-muster-syn-cookies-enabled.conf`; one per control, so each block owns its backup). It sorts after
systemd's `50-default.conf` and `50-coredump.conf` and after Ubuntu's `10-*.conf`, and before
`99-sysctl.conf` → `/etc/sysctl.conf`; a host whose `/etc/sysctl.conf` sets the key keeps that persisted
value, and the text says so. One line per key, no comments on value lines (a trailing `#` is part of the
value to the collector). A line is written to the file only for a key the body writes (replaced when the
file already carries the key, appended otherwise); a line for a key that now passes is kept, so the file is
never truncated. Risk `none` unless the table says otherwise. Shape, for `syn_cookies_enabled`:

```yaml
  sysctl: [net.ipv4.tcp_syncookies]
  backup: [/etc/sysctl.d/99-muster-syn-cookies-enabled.conf]
  script: |
    f=/etc/sysctl.d/99-muster-syn-cookies-enabled.conf
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in
      1) ;;
      *) sysctl -q -w net.ipv4.tcp_syncookies=1
         if grep -q '^net.ipv4.tcp_syncookies ' "$f" 2>/dev/null; then sed -i 's|^net.ipv4.tcp_syncookies .*|net.ipv4.tcp_syncookies = 1|' "$f"
         else printf '%s = %s\n' net.ipv4.tcp_syncookies 1 >> "$f"; fi;;
    esac
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  validate: "case \"$(sysctl -n net.ipv4.tcp_syncookies)\" in 1) ;; *) false;; esac"
```

A multi-key body repeats the `case` per key (the accepted arms are the clause's list, or `[2-9]|[1-9][0-9]*`
for a `gte`), and a parameter-driven one uses the list idiom of §2: `first=${P_allowed_sysrq%% *}` for the
target, `case " $P_allowed_sysrq " in *" $(sysctl -n kernel.sysrq) "*)` for the test.

| control | key → accepted set → value written when outside | params / risk |
|---|---|---|
| `aslr_and_link_protection` | `kernel.randomize_va_space` `{2}` → 2; `fs.protected_symlinks` `{1}` → 1; `fs.protected_hardlinks` `{1}` → 1; `fs.protected_fifos` `{1,2}` → 1; `fs.protected_regular` `{1,2}` → 2 | — |
| `icmp_broadcast_and_bogus_ignored` | `net.ipv4.icmp_echo_ignore_broadcasts` `{1}` → 1; `net.ipv4.icmp_ignore_bogus_error_responses` `{1}` → 1 | — |
| `icmp_redirects_ignored` | `net.ipv4.conf.{all,default}.{accept,secure,send}_redirects` `{0}` → 0 (six keys) | — |
| `ip_forwarding_disabled` | `net.ipv4.ip_forward` `allowed_forward` → its first element; companion `net.ipv4.conf.all.accept_redirects` read before and put back after (E-13) | `script_params: [allowed_forward]`; `sysctl` lists both keys; risk `restart_service` |
| `ipv6_forwarding_disabled` | `net.ipv6.conf.{all,default}.forwarding` `allowed_forward` → first | `script_params: [allowed_forward]`; risk `restart_service` |
| `ipv6_redirects_ignored` | `net.ipv6.conf.{all,default}.accept_redirects` `{0}` → 0 | — |
| `ipv6_router_advertisements_ignored` | `net.ipv6.conf.{all,default}.accept_ra` `allowed_accept_ra` → first | `script_params: [allowed_accept_ra]` |
| `ipv6_source_routing_rejected` | `net.ipv6.conf.{all,default}.accept_source_route` `{0}` → 0 | — |
| `kernel_pointer_exposure` | `kernel.kptr_restrict` `{1,2}` → 1; `kernel.dmesg_restrict` `{1}` → 1 | — |
| `ptrace_restriction` | `kernel.yama.ptrace_scope` `{1,2,3}` → 1; `kernel.perf_event_paranoid` `≥ 2` → 2 | — |
| `reverse_path_filtering` | `net.ipv4.conf.{all,default}.rp_filter` `{1,2}` → 1; `net.ipv4.conf.{all,default}.log_martians` `{1}` → 1 | — |
| `source_routing_rejected` | `net.ipv4.conf.{all,default}.accept_source_route` `{0}` → 0 | — |
| `suid_dumpable_disabled` | `fs.suid_dumpable` `{0}` → 0 | — |
| `syn_cookies_enabled` | `net.ipv4.tcp_syncookies` `{1}` → 1 | — |
| `sysrq_restricted` | `kernel.sysrq` `allowed_sysrq` → first | `script_params: [allowed_sysrq]` |
| `unprivileged_bpf_restricted` | `kernel.unprivileged_bpf_disabled` `{1,2}` → 2; `net.core.bpf_jit_harden` `{1,2}` → 2 | — |

- The accepted set of each key is the clause's list or bound, pinned by `TestSysctlScriptsNameTheControlsKeys`
  (§5) together with the key set. E-8 is what makes the one-way values safe: a host at
  `unprivileged_bpf_disabled = 1` (the value the control's text names and the STIGs require; the kernel
  refuses every later write) or at `yama.ptrace_scope = 3` passes those keys and the body never writes them,
  so a block that runs for `bpf_jit_harden` or `perf_event_paranoid` alone succeeds. When
  `unprivileged_bpf_disabled` must be written the body writes `2`, which stays writable and is in the list;
  the text names `1` and `3` as the values the script leaves alone.
- A tuned `in` list is an acceptance set and a target list: the body writes its first element, the validate
  accepts any element. `allowed_sysrq: [176]` on a host at `0` therefore FAILs the check and the body writes
  `176` — the profile said so, and the row's reason shows the value in force.
- `core_dump_policy` stays text: it is `partial`, judged by mechanism, and its runtime side (`core_pattern`)
  has no persisted reading.
- The four IPv6 controls are gated by `ipv6_disabled eq 0` and need no guard in the body. A host without Yama
  reads `absent_means: fail` with no `script_on_absent`: text-only, as today. `unprivileged_bpf_restricted` is
  `absent_means: not_applicable`, so a host without the BPF JIT key is NOT_APPLICABLE and never planned.
- `ip_forwarding_disabled` and `ipv6_forwarding_disabled` are `restart_service` in risk from now on: writing
  `0` on a router or a container host cuts forwarding at once. The others stay `none`.
- E-13: the kernel sets `net.ipv4.conf.all.accept_redirects` to `!forwarding` whenever `ip_forward` changes.
  On a docker host `all.accept_redirects` reads 0 (forwarding is on), so `icmp_redirects_ignored` passes that
  key and leaves it alone under E-8; the forwarding block, which runs later in the plan, would then turn it
  to 1. The forwarding body therefore saves the key, writes `ip_forward`, writes the saved value back, and
  persists it as the line after `ip_forward` in its own drop-in (the boot-time `sysctl.d` pass applies the
  lines in order, so the flip is undone there too). The pin test admits that one companion key.

### 4.2 Modules (3)

`disabled` means not loaded, not built in, and either `install … /bin/false` in the modprobe.d chain or not
shipped. So a body writes the line and unloads the module. File: `/etc/modprobe.d/99-muster-<name>.conf`
(`<name>` as in §4.1). kmod folds a module name to underscores when it parses modprobe.d and when it prints
`--showconfig`, so the body writes and the validate reads the folded name (`usb_storage`), whatever the
control's `where` list spells. kmod keeps the first `install` it reads in base-name order across the
directories, so a vendor file with an `install` line for the module wins over `99-muster-…`; the validate
reads the effective (first) `install` line, so such a block fails validate and rolls back, and the text names
the case (none of the eleven modules has one on the images measured). Risk: `usb_storage_disabled` moves to
`restart_service` (an unloaded `usb-storage` drops a mounted USB disk); the two uncommon-module controls stay
`none`, because a module in use makes `modprobe -r` fail and the block roll back.

```yaml
  modules: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]
  backup: [/etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf]
  script: |
    f=/etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf
    for m in cramfs freevxfs jffs2 hfs hfsplus udf; do
      n=$(printf '%s' "$m" | tr - _)
      grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f"
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    chmod 644 "$f"
  validate: "for m in cramfs freevxfs jffs2 hfs hfsplus udf; do n=$(printf '%s' \"$m\" | tr - _); [ \"$(modprobe --showconfig 2>/dev/null | awk -v m=\"$n\" '$1 == \"install\" && $2 == m { print $3; exit }')\" = /bin/false ] || exit 1; ! grep -q \"^$n \" /proc/modules || exit 1; done"
```

A `modprobe -r` that fails (module in use) fails the body: the host uses the module, and the block rolls
back. A built-in module keeps the control at FAIL, and the text says a different kernel is the only remedy.
The initramfs is not rebuilt (text). The module names in the body are the control's own `where` list,
repeated literally — the pin test of §5 holds the two equal after folding. A stub-`modprobe` test answers
`--showconfig` with the folded spelling for the `usb-storage` body, which no CI row can run (§5).

### 4.3 File permissions (9)

As 3D-2b: `chown root:root` where the control judges the owner, symbolic `chmod` that only clears bits, a
`case` validate over the default modes where one path is judged. The glob sets use `modes` and `find` under
E-9: a directory that may be absent is guarded by `if [ -d ]`, every mode-changing `find` carries `! -type l`
(or `-type f` where the control judges files only), a validate's `find` tests the complement of the allowed
bits. In the table, "`find F …`" stands for `find <dir> -mindepth 1 -maxdepth 1 -type f …` under that guard.

| control | record | body | validate |
|---|---|---|---|
| `sudoers_permissions` | `backup: [/etc/sudoers]`, `modes: [/etc/sudoers.d/*]` | `chown root /etc/sudoers; chmod u-wxs,g-wxs,o-rwxt /etc/sudoers`; `find F /etc/sudoers.d ! -name '*.*' ! -name '*~' -exec chmod go-w {} +` | `case` over `[0,40,400,440]` (the control judges uid only: format `%u %a`, prefix `0`) `&&` `find F … -perm /g+w,o+w` empty |
| `nfs_export_access` | `backup: [/etc/exports]` | `if [ -f ] && [ ! -L ]`: `chown root; chmod u-xs,g-wxs,o-wxt` (the control judges uid only) | `[ ! -f p ] \|\| [ -L p ] \|\|` a `case` over the 16 modes, `%u %a`, `0` — the guard keeps a host whose exports live only in `/etc/exports.d` from failing validate |
| `bootloader_config_permissions` | `backup: [/boot/grub/grub.cfg, /boot/grub2/grub.cfg]` | for each that is a regular file and not a symlink: `chown root:root; chmod u-xs,g-rwxs,o-rwxt` | per path, `[ ! -f p ] \|\| [ -L p ] \|\|` a `case` over `[0,200,400,600]`, `0 0`, `&&`-joined |
| `inetd_conf_permissions` | `backup: [/etc/inetd.conf, /etc/xinetd.conf]`, `modes: [/etc/xinetd.d/*]` | for each conf that exists: `chown root; chmod u-xs,g-rwxs,o-rwxt`; `find F /etc/xinetd.d -exec chmod go-w {} +` | `/etc/inetd.conf` where present by `stat` bits (`g-w`, `o-r`, uid 0), `/etc/xinetd.conf` where present by a `case` over `[0,200,400,600]` (`%u %a`, `0`), the fragments by `find F … -perm /g+w,o+w` empty |
| `audit_log_permissions` | `modes: [/var/log/audit/audit.log, /var/log/audit]` — no `backup`: a live log is never copied | `if [ -f ]`: `chown root /var/log/audit/audit.log; chmod u-xs,g-wxs,o-rwxt …`; `if [ -d ]`: `chown root /var/log/audit; chmod g-w,o-rwx /var/log/audit` | `case` over the eight modes (`%u %a`, `0`) `&&` dir bits |
| `syslog_conf_permissions` | `backup: [/etc/rsyslog.conf, /etc/systemd/journald.conf, /etc/syslog-ng/syslog-ng.conf]`, `modes: [/etc/rsyslog.d/*, /etc/systemd/journald.conf.d/*, /etc/syslog-ng/conf.d/*]` | each existing file: `chown root; chmod u-xs,g-wxs,o-rwxt`; each existing dir: `find F … -name '*.conf' -exec chown root {} + -exec chmod u-xs,g-wxs,o-rwxt {} +` | per file, `[ ! -f p ] \|\|` the `stat` test; per dir, `find F … -name '*.conf' \( -perm /7137 -o ! -user root \)` empty |
| `cron_permissions` | `modes: [/etc/crontab, /etc/anacrontab, /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny, /etc/cron.d/*, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, /etc/cron.hourly/*, /etc/cron.daily/*, /etc/cron.weekly/*, /etc/cron.monthly/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /var/spool/cron/atjobs/*, /var/spool/at/*, /etc/cron.d, /var/spool/cron, /var/spool/cron/crontabs, /var/spool/cron/atjobs, /var/spool/at]` | system and access files (`if [ -f ]`, `find F /etc/cron.d`): `chown root; chmod u-xs,g-wxs,o-rwxt`; periodic scripts (`find F` over the four dirs): `chown root; chmod o-w` (they keep `+x`: run-parts skips a non-executable); cron spools (`find F /var/spool/cron`, `find F /var/spool/cron/crontabs`): `chmod u-xs,g-wxs,o-rwxt` (a spool owned by uid ≥ 1000 is correct; the `crontabs`/`atjobs` DIRECTORIES under `/var/spool/cron` are never touched by the spool pass); at spools (`find F /var/spool/cron/atjobs`, `find F /var/spool/at`): `chmod g-wxs,o-rwxt` only — at marks a job runnable by `u+x`, and clearing it cancels the job; the nine directories (`if [ -d ]`): `chmod o-w` | system/access set `-perm /7137` empty `&&` `! -user root` empty; periodic `-perm /o+w -o ! -user root` empty; cron spools `-perm /7137` empty; at spools `-perm /7037` empty; dirs `-perm /o+w` empty — each a `find F`/`[ -d ]` guarded clause |
| `log_dir_permissions` | `modes: [/var/log, /var/log/*, /var/log/*/*]` | `find /var/log -maxdepth 2 ! -type l -perm /o+w -exec chmod o-w {} +` — the other-writable half only; the group half (a group-writable entry in a group outside `allowed_groups`) stays text: `/var/log/postgresql` root:postgres 1775 is a daemon's own directory, and `chmod g-w` there stops its logging | the same `find` empty |
| `ftpusers_permissions` | `backup: [/etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers]` | for each that exists: `chown root:root; chmod u-xs,g-wxs,o-rwxt`; never create one (an empty allow list denies every login) | per path, `[ ! -f p ] \|\|` a `case` over the eight modes, `&&`-joined |

- `sudoers_permissions` clears `u-w` too: the target is `0440`, and `visudo` writes the file through a temp
  copy, not in place.
- `log_dir_permissions` declares no `script_params`: its body does not read `allowed_groups`, so a tuned
  list keeps the 3D-2 `params_tuned` text-only rule. After the script the control may still FAIL on a host
  with a group-writable entry in an unlisted group, and the block's `done` says so through the next `check`
  (X-10); the text keeps both options (chgrp, or name the group in the parameter).
- `bootloader_config_permissions` acts only on a regular, non-symlink `grub.cfg`: on an EL host upgraded on
  UEFI (`/boot/grub2/grub.cfg` → the EFI system partition, K-28) and wherever the collector read
  `/boot/efi/EFI/*/grub.cfg`, the file sits on vfat, whose mode is the mount's `umask`/`fmask` and ignores
  `chmod` silently. The body leaves it, the validate skips it, and the text says the ESP mode is fixed in
  `fstab` (`fmask=0177`), not by `chmod`.
- `audit_log_permissions` acts on the literal default path. The collector judges the path `auditd.conf`'s
  `log_file` names; on a host with another `log_file` the literal is absent, the body does nothing (guarded),
  the control stays FAIL, and the text names that file as the operator's.
- `cron_permissions`: a pending at job (0700 by at's contract) keeps the control FAIL after the script; the
  judgment of at spools is parked for a verdict cycle (§7).
- A symlink at a fixed path the `files.*` collector reads is `error` by design (C4), so that item is ERROR and
  never planned; the five 3D-2b file bodies keep their `[ -f ]` guard. Every new single-path body uses the
  E-9 guard because its collector may judge the path a symlink names.
- `TestFileValidatesAcceptTheDefaultModes` selects by an explicit id table, not by category, and stays at the
  five 3D-2b controls (`hosts`, `hosts_lpd`, `passwd`, `services`, `shadow`) — the controls whose validate is
  exactly one `case` over `backup[0]` and the default `allowed_modes`. `nfs_export_access` (guarded),
  `sudoers_permissions` (a `case` plus a `find`) and `bootloader_config_permissions` (two paths) are checked
  by lint and the round trip; the test asserts that no other shipped scripted control has a pure-`case`
  validate. A second test derives every validate `find` mask from the control's `allowed_modes` (07777 minus
  the largest allowed mode) and compares it with the shipped text. `TestFileScriptsRepairOnARealFile` gains
  `nfs_export_access` and a symlinked-path case (left alone, validate skips it).

### 4.4 Accounts and sshd (4 new, 1 changed)

| control | record | body | params / absent / risk |
|---|---|---|---|
| `password_policy` | `backup: [/etc/login.defs, /etc/security/pwquality.conf.d/99-muster.conf]`; `rollback` replays `$MB/ageing.list` | `login.defs`: for each of `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`, rewrite EVERY uncommented line (`sed -i -E "s\|^([[:space:]]*PASS_MAX_DAYS)[[:space:]].*\|\1 $P_max_days\|"`; shadow-utils reads the last, muster the first) or append when none — only when the current first value is missing or looser (E-8); `pwquality`: `mkdir -p /etc/security/pwquality.conf.d` and `chmod 755` it (Debian ships none), then per key, write `minlen = $P_min_len` / `minclass = $P_min_classes` into `99-muster.conf` only when the merged value (`pwquality.conf`, then `conf.d/*.conf` in name order, last wins — the collector's read) is missing or smaller, `chmod 644`; then `today=$(( $(date +%s) / 86400 ))` and for every account `awk -F: -v OFS=: '$2 != "" && $2 !~ /^[!*]/ { print $1, $3, $4, $5 }' /etc/shadow` lists, read with `IFS=: read -r name last min max`: skip and log it when `last` is empty or `0` or `[ $((today - last)) -gt "$P_max_days" ]` (the write would expire it now); otherwise record `name:min:max` in `$MB/ageing.list` (an empty field written as `-1`, chage's "no limit"; first record kept) and run `chage -M "$P_max_days"` when `max` is empty or greater, `chage -m "$P_min_days"` when `min` is empty or smaller | `script_params: [max_days, min_days, min_len, min_classes]`; `script_on_absent: true`; risk `lockout_risk` (the `keep a second session open` header); validate: the first uncommented `PASS_MAX_DAYS` ≤ `$P_max_days`, `PASS_MIN_DAYS` ≥ `$P_min_days`, `PASS_MIN_LEN` ≥ `$P_min_len`, and the merged `minlen` ≥ `$P_min_len`, `minclass` ≥ `$P_min_classes` — `&&`-joined; the ageing loop is not validated (a skipped account is WARN on the next check, X-10) |
| `umask_policy` | `backup: [/etc/login.defs]` | `first=${P_acceptable%% *}`; when the first uncommented `UMASK` value is not in `$P_acceptable`, rewrite every uncommented `UMASK` line to `UMASK $first` (append when none) | `script_params: [acceptable]`; default list reordered to `["027", "022", "077", "0027", "0022", "0077"]`; validate: the first uncommented value is in the list (the `case " $P_acceptable "` idiom) |
| `lockout_threshold` | `backup: [/etc/security/faillock.conf]` | when the LAST uncommented `deny` value (the collector's and pam_faillock's read) is missing, below 1 or greater than `$P_max_attempts`, rewrite every uncommented `deny` line to `deny = $P_max_attempts` (append when none) | `script_params: [max_attempts]`; no `script_on_absent` (an absent `deny` means faillock is not stacked); validate: the last value is ≥ 1 and ≤ `$P_max_attempts`; a `deny=` argument on the pam_faillock lines wins over the file and stays text |
| `session_timeout` | `backup: [/etc/ssh/sshd_config.d/00-muster-session.conf]`; `rollback`: `rm -f` the drop-in, `sshd -t`, reload (E-11) | as `root_remote_login`: guarded by `command -v sshd`, write `ClientAliveInterval $P_max_interval` and `ClientAliveCountMax $P_max_count`, `chmod 644`, `sshd -t`, reload a running `sshd`/`ssh` | `script_params: [max_interval, max_count]`; `script_on_absent: true` (no mechanism applies ⇒ the drop-in makes one apply); validate: `command -v sshd` `&&` plain `sshd -T` (no `-C`: the judged facts carry no persona) reads both values ≥ 1 and ≤ the parameters — so a host without sshd, where the TMOUT mechanism is the only way and stays text, fails validate instead of reporting `done`, and so does a host whose earlier value (before the `Include`, or a drop-in sorting before `00-`) beats the drop-in |
| `root_remote_login` | unchanged: its rollback keeps the `rm -f` (E-11) | — | — |

- `password_policy`'s runtime side (`pass_max_days`/`pass_min_days` are judged on both sides) needs the
  `chage` loop, or the row ends WARN (`not applied`), never PASS. An account the loop skips because its
  password is already older than `max_days` keeps the runtime side above the parameter, so the row ends WARN
  and the log names the account: the operator changes that password first, then runs the script again. The
  declared rollback reads `$MB/ageing.list` and runs `chage -m <min> -M <max>` per line (an empty field is
  `-1`, chage's "no limit"). `pam.pwquality.enabled` stays what the host's PAM stack says: on a Debian-family
  host without `libpam-pwquality` the control stays FAIL after the script, and the text keeps saying to
  install it.
- `password_hash_algorithm` and `account_inactivity_lock` stay text (a rehash; a per-account `chage` over
  `login_capable` that the runner row could prove but that reads better as 3D-2d with the audit family).
- The `lockout_threshold` body is proven on the EL rows, where the seed stacks faillock through
  `authselect enable-feature with-faillock`; Debian 12 ships no `pam-auth-update` profile for faillock and
  is left out of its images.
- `session_timeout` and `root_remote_login` both write a file sshd re-reads: their rollbacks remove the
  drop-in before `sshd -t` and the reload, so the running daemon never keeps a configuration the files no
  longer hold (E-11). The init rows' failure run asserts the reload happened after the removal (the journal
  shows the reload after the `rm`, and `sshd -T` reads the pre-seed value).

## 5. Proof (E-6, E-12, E-13)

**The runner row.** `fix-roundtrip`'s matrix gains `{key: runner, kind: host, seeded: …}`; the container
rows gain `kind: container`. The run block's `x()` runs `docker exec "$cid"` on a container row and `sudo` on
the host row, and the paths differ by a prefix (`/m/muster` ↔ `./bin/muster`, `/out` ↔ `$d/repair`, `/ci`
↔ `ci/roundtrip`). The repair run is the same. The failure run has no second container: the job runs
`ci/roundtrip/runner.sh` again (it is idempotent: it removes every file muster wrote —
`/etc/sysctl.d/99-muster-*.conf`, `/etc/modprobe.d/99-muster-*.conf`,
`/etc/ssh/sshd_config.d/00-muster-session.conf`, `/etc/security/pwquality.conf.d/99-muster.conf` — re-applies
every sysctl seed with `sysctl -w`, reloads the seeded modules with `modprobe --ignore-install`, and applies
every file seed unconditionally), collects and plans afresh (the 3D-2b rule:
never reuse the repair run's script), records, runs the broken copy, and compares; the job asserts the
failure plan's scripted ids equal the repair plan's. There is no guard run on this row; the job asserts
`fix.host_guard` is `on` (the VM has a machine id). The row never starts docker (the `ip_forward` and
`rp_filter` scripts change what docker's bridge needs), and it installs `auditd` for
`audit_log_permissions`.

**`record()`** gains, per planned scripted item: `sysctl -n` of every `.sysctl[]` key, the load state of
every `.modules[]` name, and `stat -c '%u %g %a'` of every path a `.modes[]` entry expands to (through the
prologue's own `modes_paths`, extracted from the script, with the entry quoted). `.backup[]` checksums stay
as they are; no planned control backs up a file a daemon appends to.

**Runner seeds** (`ci/roundtrip/runner.sh`), per control:

| control | seed |
|---|---|
| the sixteen sysctl controls | one failing value per control, written with `sysctl -w` on both runs whatever the stock reading (image-independent): `kernel.randomize_va_space=0`, `net.ipv4.icmp_echo_ignore_broadcasts=0`, `net.ipv4.conf.default.accept_redirects=1`, `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`, `net.ipv6.conf.default.accept_redirects=1`, `net.ipv6.conf.default.accept_ra=1`, `net.ipv6.conf.all.accept_source_route=1`, `kernel.kptr_restrict=0`, `kernel.yama.ptrace_scope=0`, `net.ipv4.conf.default.log_martians=0`, `net.ipv4.conf.default.accept_source_route=1`, `fs.suid_dumpable=2`, `net.ipv4.tcp_syncookies=0`, `kernel.sysrq=176`, `net.core.bpf_jit_harden=0` — the probe confirms each is writable and FAILs its control |
| `uncommon_filesystems_disabled`, `uncommon_network_protocols_disabled` | `modprobe udf`, `modprobe sctp`, `modprobe tipc` (the modules the runner kernel ships; the rest are `unproven_units`) |
| `usb_storage_disabled` | none: `unproven` (the kernel ships no `usb-storage`) |
| `bootloader_config_permissions` | `chmod 644 /boot/grub/grub.cfg` |
| `audit_log_permissions` | `chmod 644 /var/log/audit/audit.log` (0640 is an allowed mode; mode only: the body never changes the group) |
| `session_timeout` | the image's own earliest `ClientAliveInterval` line rewritten in place to 900 (the runner image sets 120 in `/etc/ssh/sshd_config.d/50-cloudimg-settings.conf`, which sorts after `00-muster-session.conf`); the probe records where the value lives, and an image whose value sits before the `Include` is unprovable (no drop-in can win), not seedable |
| `umask_policy` | `UMASK 002` |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | as the container rows (below) |
| `password_policy` | only when the seed installs `libpam-pwquality` — the probe decides |

**Container seeds** (`ci/roundtrip/<key>.sh`), per new control — the probe confirms each:

| control | seed |
|---|---|
| `sudoers_permissions` | `sudo` installed on every image; `chmod 644 /etc/sudoers` |
| `cron_permissions` | EL rows install `cronie`; `chmod 644 /etc/crontab` |
| `syslog_conf_permissions` | `rsyslog` installed where the image lacks it, or `/etc/rsyslog.conf` planted on `ubuntu2204`; `chmod 644` on it |
| `inetd_conf_permissions` | `install -m 644 /dev/null /etc/inetd.conf` |
| `nfs_export_access` | `install -m 666 /dev/null /etc/exports` (init rows) |
| `ftpusers_permissions` | `vsftpd` installed (the control gates on an FTP daemon); its access file `chmod 644` (init rows) |
| `log_dir_permissions` | `install -m 666 /dev/null /var/log/ci.log` |
| `umask_policy` | `UMASK 002` in `/etc/login.defs` |
| `password_policy` | EL rows: a hashed account changed today; `PASS_MAX_DAYS 99999` |
| `lockout_threshold` | EL rows: `authselect enable-feature with-faillock`, `deny = 99` |
| `session_timeout` | EL rows: `ClientAliveInterval 900` in a drop-in sorting after `00-muster-session.conf` |

**The table.** Every new scripted control enters `_roundtrip.yaml`. The hypothesis the plan's probe settles:

| controls | rows |
|---|---|
| the 16 sysctl, 3 modules, `bootloader_config_permissions`, `audit_log_permissions` | `runner` only (gated `beyond`); the ESP class of the bootloader control is unproven (the runner's `/boot` is ext4) |
| `usb_storage_disabled` | `unproven`: the runner kernel ships no `usb-storage`, so the control passes there; the two uncommon-module controls carry `unproven_units` for every module the kernel does not ship |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | the four container rows (EL rows install `cronie`/`sudo`; inetd is planted as a file, EL9 has no package) and `runner` |
| `nfs_export_access`, `ftpusers_permissions` | the init rows (mode-only seeds; `ubuntu2204` has no systemd) |
| `log_dir_permissions` | the four container rows (`install -m 666 /dev/null /var/log/ci.log`); not the runner, which FAILs at stock on `/var/log/postgresql`'s group bit, the half the body leaves to the text |
| `umask_policy` | all five rows (seed `UMASK 002`) |
| `password_policy` | EL rows (pwquality stacked by authselect; seed a hashed account changed today) and `runner` only if `libpam-pwquality` is installed by the seed — the probe decides |
| `lockout_threshold` | EL rows (`authselect enable-feature with-faillock`, `deny = 99`) |
| `session_timeout` | EL rows and `runner` |

**Table test.** `TestEveryScriptedControlIsInTheRoundtripTable` reads `kind`; a `host` row has no `init`;
`muster.beyond.*` ids may name `host` rows only; `muster.service.*` ids may not name a row with
`init: "false"`. `unproven_units` keys must be declared in the control's `units`, `modules` or `sysctl`.

**Pin tests.** `TestSysctlScriptsNameTheControlsKeys` (Linux, beside the sysctl leaf table): a control's
`sysctl` list equals, as a set, the kernel keys of the facts its clauses judge, mapped through the leaf table
plus `coredump.suid_dumpable → fs.suid_dumpable` (the coredump collector's constant), and admits
`net.ipv4.conf.all.accept_redirects` as the one declared companion of `ip_forwarding_disabled` (E-13); the test also renders
the body and checks that every accepted arm of each key's `case` is the clause's list or bound.
`TestModuleScriptsNameTheControlsModules`: a control's `modules` list equals its `where` list after folding
`-` to `_`. Both replace nothing; they are new.

## 6. Lint, tests, documents

**Lint summary.** New per-control rules: `script_params_declared`, `script_params_used`,
`script_params_needs_script`, `script_params_default_safe`, `script_on_absent_needs_script`,
`modes_charset`, `modes_backup_overlap`, `sysctl_charset`, `modules_charset`, `state_needs_script`.
`units_exclusive` grows to the three record kinds. Deleted: `backup_path_shared`, `units_shared`,
`backup_reserved`. The way-back rule reads: a `script` needs `rollback`, `backup`, `units`, `modes`, `sysctl`
or `modules`.

**Tests.** The lint cases; the plan tests (`script_params` formatting for every type, the list join, the
charset refusal with an empty `script_params` in the JSON, `script_on_absent`, the six rollback words, the
per-kind `Build` refusal); the script tests of §3; the goldens regenerated (`full.sh` gains a params control
and a state control; `all-scripted.sh` renders every new body); `TestScriptEveryLineIsTemplateBodyOrComment`
admits the `P_` lines, the `MB` line, the quoted `save_modes` line and the record lines; the 3D-2b unit tests
at the new path; the file-validate test over six controls by id table; `TestFileScriptsRepairOnARealFile`
gains `nfs_export_access` and a symlinked path; the mask-derivation test; the parameter-placement grep over
every shipped body; a grep that refuses a mode-changing `find` without a type predicate; the two pin tests;
the table test. The mutation test leaves
zero survivors.

**CI.** The runner row, `ci/roundtrip/runner.sh`, `record()`'s three additions, shellcheck over the new
script. The examples refresh (`make examples-fetch RUN=<id>` from the branch's `examples.yml` run) is
mandatory before the merge: the plan fields, the new bodies and the prologue change every fix report.

**Documents** (English and Korean in the same commit). Main design: D34 amended (§2) and §4.2's
`internal/remedy` row (the hash and the `P_` assignments as the two admitted non-literal classes), §6.2 gains
the five fields and the rules, §6.8 loses the two set-wide rules, §7.5 gains the record kinds, the six
rollback words and the failure order, §10.2 marks 3D-2c merged and names 3D-2d (audit family,
`account_inactivity_lock`, the content halves). `CLAUDE.md` Fix section; `CONTRIBUTING` pair (how to write a
body: `P_` for a parameter and where it may stand, E-8's write-only-when-outside rule, E-9's `find`
discipline and mask formula, the third validate shape (one `for` over literal names, each condition
`|| exit 1`), E-13's side-effect rule, a record kind for the way back, a `modes` entry — never a `backup` — for a path the body only
re-modes, E-11 for a daemon's file); README pair; `THREAT_MODEL.md` (a parameter value enters a command only
under the charset; the unit-state path is `$MUSTER_BACKUP/blocks/<fn>/units/`); `CHANGELOG` — the Unreleased
3D-2b bullets are rewritten in place (per-block record paths; the three lints never shipped in a release)
rather than contradicted by a Changed line, and the entry gains: Added — parameters in scripts, the three
record kinds, the runner row, 32 scripts; Changed — per-block backup directories, absent paths removed on
restore, one default-list order, the risks of the two forwarding controls, `usb_storage_disabled` and
`password_policy`; Controls:
`kisa-unix-2026+2026.10.14`, no verdict change.

## 7. Parked

- Scripts for the controls that need a judgment per host (mounts, partitions, swap, secure boot, listeners,
  sudo, keys, `nfs.exports` content, `password_hash_algorithm`, `account_inactivity_lock`, the audit family) —
  3D-2d where a safe shape exists, text otherwise.
- The group half of `log_dir_permissions` (a host decision) and the at-spool judgment of `cron_permissions`
  (a pending job is 0700 by contract) — a verdict cycle.
- PAM stack edits (`pwquality`, `faillock`, `pam_umask`): text.
- The initramfs rebuild after a module is disabled.
- A persisted sysctl value that `/etc/sysctl.conf` or a later file overrides; a `grub.cfg` on the EFI system
  partition (its mode is the mount's).
- A guard run for the runner row (one host).
- Paths with a newline in `modes` trees.

## 8. As built

The implementation plan (`docs/superpowers/plans/2026-10-14-stage3d2c-remedy-scripts.md`, rulings S-1..S-50) and
its reviews changed the following. Each line names the section it amends.

- §2 A parameter never appears inside a `sed` `s` expression, whatever the delimiter: a body copies the value to
  a plain variable first. `TestShippedBodiesPlaceParametersSafely` enforces it and the line-start rule; it lives
  in `internal/controls` and runs on every platform (S-30).
- §3 The ageing record's rows are `name:min:max`.
- §4.3, §6 `TestFileScriptsRepairOnARealFile` gains `nfs_export_access` only; the symlinked-path cases are the
  `links` of `TestFileBodiesRepairATempTree` and the `Test*BodiesLeaveASymlinkedDropIn` tests.
- §3 `restore_modes` skips an entry whose owner, group, mode and type already match the record, refuses an entry
  with an ancestor directory that is not root-owned or is other-writable, and refuses an entry whose recorded owner
  is not root when its parent is group- or other-writable; a root-owned, group-writable directory (Ubuntu's
  `root:syslog 0775 /var/log`) is accepted and its group trusted. The rule is the prologue helper
  `modes_trusted`; a refusal leaves the stricter mode and the block reports `ROLLBACK INCOMPLETE` (S-24).
- §3 `backup` replaces an absent marker with a copy when the path exists on a later run with the same
  `MUSTER_BACKUP`, so that run's record holds the earlier run's file, not the path's absence.
- §3, §6 The failure-order test checks the rollback and the four record restores in one block, and
  `restore_units` in its own, since units exclude the record kinds.
- §4.1 The `gte 2` arms are spelled `[2-9]|[1-9][0-9]|[1-9][0-9][0-9]*` for clarity; the shell glob
  `[1-9][0-9]*` already needed two characters, so the accepted numbers are the same (S-21).
- §4.1, E-13 The forwarding body persists the companion `net.ipv4.conf.all.accept_redirects` line only when it
  read 0 before the write, so a persisted 1 never overrides `icmp_redirects_ignored` at boot (S-43). Writing
  `net.ipv6.conf.all.forwarding` also copies its value into `default.forwarding`; the forwarding lists, writes,
  drop-in lines and restores keep `all` before `default`, and no `sysctl` list is sorted (S-46). Every sysctl
  text says a value in `/etc/sysctl.conf` or a later-sorting file still wins at boot.
- §4.1, §4.2, §4.4 A body that finds its own drop-in path a symlink (an operator's `/dev/null` mask) logs it and
  fails the block before any write; a rollback that removes the drop-in skips a symlink (S-27).
- §4.2 Module bodies and validates loop over `mods='…'`, never a literal one-word list (S-22); both accept the
  collector's whole set of no-op install commands, and the body appends no line for a module one of them already
  disables (S-25). A built-in module cannot be unloaded: its block ends `done` and the control stays FAIL.
- §4.3 `log_dir_permissions` and the at-spool pass of `cron_permissions` change files only inside a directory
  `modes_trusted` accepts, walked by shell glob; a directory `modes_trusted` refuses (not root-owned, or other-writable, up to `/`) is logged and
  left to the operator, and the validate checks the same set, so the block ends `done` with the control FAIL
  (S-47).
- §4.3 A system crontab (`/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d/*`) or a sudoers file (`/etc/sudoers`,
  an active `/etc/sudoers.d/*`) not owned by root is never chowned or re-moded: cron and sudo ignore such a file,
  and adopting it would activate content another user wrote. The body logs `<id>: <path> is owned by uid N;
  review it before chown root, left as is`, the validate fails and the block rolls back; root-owned files are
  repaired as before (S-49).
- §4.3 `cron_permissions` clears `o-w` on its directories first and `audit_log_permissions` fixes
  `/var/log/audit` before its log; every file pass then runs only when `modes_trusted "$d/." 0` holds (logged
  and left otherwise), and the validates mirror the gate (S-50).
- §4.1 `reverse_path_filtering` keeps writing 1 (strict) and is `restart_service`: strict filtering drops
  asymmetrically routed traffic, and such a host sets 2 (final review F2).
- §4.1 A failed forwarding block puts back the global switch (`net.ipv4.ip_forward`, or IPv6's `all` and
  `default`) only; every interface's forwarding then follows the global value, because the kernel copies it.
  Both texts say so (final review F5).
- §3 `restore_modes` runs `chown -h` only when the owner or group differs from the record, so a mode-only
  restore keeps a file's `security.capability` (final review M1).
- §4.4 `umask_policy` and `password_policy` refuse a symlinked `/etc/login.defs`: the block logs it and fails
  before any write (final review K2).
- §4.3 `cron_permissions` gives a root-group access file the group its setgid reader runs as (`crontab` for
  cron, `daemon` for a setgid-`daemon` `at`) (S-26); the at-spool pass is `chmod u-s,g-wxs,o-rwxt` (S-40).
- §4.3 `audit_log_permissions` guards the file half of its validate; its text and `ftpusers_permissions`' name
  a file found elsewhere as the operator's (S-39). `ftpusers_permissions` and `nfs_export_access` run
  `chown root` only (S-13).
- §4.3, §6 The file-validate test stays at the five 3D-2b controls, selected by its owner table; its "no other
  bare stat case" assertion flags only a validate that is one stat `case` and nothing else (S-8, S-23). The
  mask-derivation test covers the masks derived from `allowed_modes` (syslog, cron).
- §4.4 `lockout_threshold`: a missing `deny`, and a missing `faillock.conf`, read as 3 on both sides; the body
  writes only outside `[1, max]`; a `faillock.conf` it creates is mode 0644 (S-9, S-41).
- §4.4 `password_policy` computes the collector's `required_classes` over the merged file chain (S-10); both
  account bodies read keys in any case, as the collector does; the ageing loop skips, with a log line, an account
  whose password is at least `max_days` old (it would expire on the spot) and a name `/etc/passwd` does not hold
  (S-42).
- §4.4, E-11 `session_timeout` keeps, per keyword, a value already in `[1, max]` and its validate is guarded by
  `command -v sshd`, so a host without sshd ends `done` (S-11, reversing the round-2 wording). Its rollback puts
  the recorded drop-in back, or removes the new one, before `sshd -t` and the reload (S-35). The failure run
  proves the files are restored, not the daemon's reload (S-31).
- §5 The runner's re-seed also puts back the stock modes of the stock-FAIL scripted paths the repair run
  tightened (`/etc/hosts`, `/etc/shadow`), and the host row checks that every seeded id is a scripted item of the
  failure plan and that the failure plan's scripted ids are a subset of the repair plan's, not that they are
  equal (S-18). `sudoers_permissions` is not seeded on the runner, whose own `sudo` reads `/etc/sudoers` (S-33).
- §5 The EL seed installs `authselect` and `passwd` and runs `authselect select minimal with-faillock --force`:
  the images have no selected configuration and rocky9 no `/etc/pam.d/passwd` (S-29). `umask_policy` is not
  proven on debian12-init, which stacks no `pam_umask`; `cron` is installed on debian12-init and ubuntu2204, and
  the round-trip script floor is 6 (S-15, S-44).
- §6 A path a daemon or the system writes to while the block runs (a live log) is a `modes` entry, never a
  `backup`; a path a body only re-modes may use either (S-38). The inetd and audit-directory bodies clear bits
  their clause would accept, a stricter result than E-8 asks for.
