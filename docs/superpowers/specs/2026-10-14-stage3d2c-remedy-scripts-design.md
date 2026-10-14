# Stage 3D-2c — scripts beyond the sixteen: parameters, state records, the runner row

Korean pair: `2026-10-14-stage3d2c-remedy-scripts-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§6.2 schema, §6.8 lint, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycles it builds on:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10) and `2026-10-13-stage3d2b-remedy-proof-design.md`
(Q-1..Q-6). Rulings of this design are the E list. The family map the bodies were written from is the
cycle's ignored workspace file `family-map.md`; its findings are restated here where they bind.

## 1. Scope and intent

Sixteen controls carry a `script`. Of the 101 that do not, 87 are `auto`, and 38 of those have a body that is
a template: write a sysctl line and apply it, write a modprobe line and unload the module, clear mode bits,
replace a configuration line, write an sshd drop-in. The rest need a judgment per host (which partition to
split, which listener to allow, which account to lock) and stay text. This cycle scripts the 38, and builds
the two mechanisms they need: a way for a parameter's value to reach a script, and a way to record and
restore state that is not a file's content — a mode, a sysctl value, a loaded module.

- **E-1 — A parameter reaches the script as a block variable, never as text substitution.** A control lists
  `script_params`; the template emits `P_<name>='<value>'` as the first lines of the body subshell, as it emits
  `UNITS=`. The value is the one in force (default, profile or tuning), and it reaches the line only when it
  matches the type's charset; otherwise the item is text-only (`params_unsafe`). The `params_tuned` rule
  applies only to a scripted control that declares no `script_params` (§2).
- **E-2 — State is recorded per block.** Every record a block takes — a file copy, a unit's state, a path's
  mode, a sysctl value, a module's load state — lives under `$MUSTER_BACKUP/blocks/<fn>/`, so a block
  restores the state it found, not the state an earlier block found. The `backup_path_shared` and
  `units_shared` lints go: two blocks may now declare the same path or unit, and the later restores to the
  state the earlier left. A declared backup path that did not exist is recorded as absent and removed on
  restore, so a script that creates a drop-in needs no `rm -f` rollback (§3).
- **E-3 — Three more state kinds.** `modes` (a path's owner, group and mode; `dir/*` patterns expanded by
  `find`, dotfiles included, symlinks excluded), `sysctl` (a key's runtime value) and `modules` (loaded or
  not). Each has a `save_`/`restore_` helper in the prologue, and the failure path runs them in a fixed order
  around the file restore (§3).
- **E-4 — The bodies.** Seventeen sysctl controls, three module controls, nine file-permission controls, four
  account controls and one sshd control, written to the 3D-2b discipline: bits are cleared, never set; a
  drop-in is written, never a vendor file; a value the host must supply (an account name, a path under
  `/var/log`) is enumerated on the host by the script, never read from the snapshot (§4).
- **E-5 — Absent is not always hopeless.** A control may declare `script_on_absent: true`: a FAIL the
  evaluator reached through `absent_means: fail` is then planned with its script, because the script writes
  the very line that is absent (`PASS_MIN_LEN`, a `ClientAliveInterval`). The 3D-2 rule (X-2, Z-6) stands for
  every other control (§2).
- **E-6 — The runner proves what containers cannot.** Every `beyond` control gates on `env.container eq none`,
  so the sysctl, module, bootloader and audit-log scripts are judged only on a host. `fix-roundtrip` gains a
  `runner` row that seeds, repairs and fails on the GitHub runner VM itself, without docker. It has no guard
  run (one host), and its failure run re-seeds the same VM (§5).
- **E-7 — No verdict changes.** No `checks` or facts change. The default order of three list parameters moves
  so that the first element is the value the guide names (`umask_policy.acceptable`); `op: in` does not care
  about order. `controls/VERSION` moves. The plan JSON gains `script_params`, `script_on_absent`, `modes`,
  `sysctl`, `modules` and the `state` rollback value; plan schema stays 1.

## 2. Parameters in scripts (E-1, E-5)

**Schema.** `Remediation` gains `ScriptParams []string` (`yaml:"script_params,omitempty"`) and
`ScriptOnAbsent bool` (`yaml:"script_on_absent,omitempty"`). An entry is a parameter name, or `name[<n>]`
for the `n`-th element (from 0) of a list parameter. The block variable is `P_<name>` either way.

**Lint** (per control; each a `TestLintRules` case):
- `script_params_declared` — every entry names a `params` key; an indexed entry names a `list<…>` parameter
  and `n` is below the default list's length; a whole-list entry is allowed (joined by one space).
- `script_params_used` — every `$P_<name>` or `${P_<name>` in `script` is declared, and every declared entry
  is used in `script`; `validate` and `rollback` may not use `$P_` (they run in their own subshells, where it
  is unset).
- `script_params_needs_script`, `script_on_absent_needs_script`.
- `script_params_default_safe` — every default value an entry names passes the charset (below).

**Charset, by parameter type.** `int`: `^-?[0-9]+$`. `bool`: `true` or `false`. `string` and each element of
`list<string>`: `^[A-Za-z0-9._/@:+,=-]+$`. Each element of `list<int>`: as `int`. A whole list is its
elements joined by one space, so a body iterates it with `for x in $P_<name>`. No value can carry a quote, a
space (inside an element), `$`, a backtick or `;`, so `'…'` holds it as data.

**Plan.** `Item` gains `ScriptParams []ParamValue` (`json:"script_params"`, always present, `[]` when none;
`ParamValue{Name, Value string}` with json `name`/`value`, sorted by name — no map, same input same bytes),
`ScriptOnAbsent bool` (`json:"script_on_absent"`). `remedy.Build` reads the value in force from the check
block's `Params[id][name]` (the merged values 3D-1 records), picks the element for an indexed entry, formats
it, and checks the charset. A value that fails the charset, or an index beyond the list in force, makes the
item text-only with `text_only_reason: params_unsafe` (phrase in the script: `a parameter value cannot be
carried safely; see muster check --format json: check.params`). The `params_tuned` branch applies only when
the control declares no `script_params` and some source is not `default`.

**Absent.** When the row's reason starts with `check.ReasonAbsentFailPrefix` and the control declares
`script_on_absent: true`, the item is scripted; the 3D-2 `absent` text-only reason applies otherwise.

**Rendering.** The body subshell opens with `( set -e`, then `UNITS='…'` when units are declared, then one
`P_<name>='<value>'` line per entry in name order, then the body. `templateLines` admits exactly the rendered
`P_` lines. The poison plan gains a control with `script_params: [bad]` whose value in force is
`'; id; '`: the item renders text-only, and the value appears on no non-comment line.

**D34, amended once more.** "No host value is substituted into a command" keeps its one exception (the
machine-id hash). A parameter's value is not a host value: it is policy the operator declared in a profile or
a tuning file, and it enters a command only as a `P_` assignment, constrained to the charset above.

## 3. State records (E-2, E-3)

**Per-block directories.** The block function sets `MB="$MUSTER_BACKUP/blocks/<fn>"` and creates it before
anything is recorded (a failed `mkdir` is `backup failed, nothing changed`). Under it:

| kind | where | record |
|---|---|---|
| file copies | `$MB/files<path>` | `cp -a` of the path, as 3D-2 |
| absent files | `$MB/absent<path>` | an empty marker: the declared path did not exist |
| units | `$MB/units/<u>`, `<u>.deps` | as 3D-2b |
| modes | `$MB/modes.list` | one line per path: `<uid> <gid> <mode> <path>` |
| sysctl | `$MB/sysctl.list` | one line per key: `<key> <value>` (`absent` when unreadable) |
| modules | `$MB/modules.list` | one line per module: `<name> loaded\|not-loaded` |

The first record of a path, unit, key or module is kept across runs with the same `MUSTER_BACKUP`, as before,
but per block: block B's record is what B found, after A ran. The `backup_path_shared`, `units_shared` and
`backup_reserved` lints are deleted; `units_exclusive` keeps forbidding `rollback`/`backup` beside `units`.

**`backup` and `restore`.** `backup` records a declared path that does not exist as absent
(`: > "$MB/absent$p"`) instead of skipping it. `restore` removes a path whose absent marker exists (`rm -f`;
a path that is now a directory is logged and counts as incomplete), and copies back a path whose copy exists,
as before. A script that creates a drop-in therefore needs no `rm -f` rollback; `root_remote_login`'s
rollback shrinks to the `sshd -t` and reload lines.

**`modes`.** An entry is an absolute clean path with zero, one or two trailing `/*` segments (lint
`modes_charset`: `^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`, no duplicates, requires `script`, excludes `backup`).
The helpers expand an entry with `find <dir> -mindepth k -maxdepth k ! -type l` where `k` is the number of
`/*` segments (`k = 0`: the path itself when it exists) — dotfiles included, symlinks excluded, which is the
collector's view.

```sh
modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) [ -e "$1" ] && [ ! -L "$1" ] && printf '%s\n' "$1";;
  esac
  return 0
}
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      awk -v p="$p" '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == p) f=1 } END { exit !f }' "$MB/modes.list" && continue
      s=$(stat -c '%u %g %a' -- "$p") || exit 1
      printf '%s %s\n' "$s" "$p" >> "$MB/modes.list" || exit 1
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode p; do
    [ -e "$p" ] || continue
    chown -- "$uid:$gid" "$p" && chmod -- "$mode" "$p" || mrc=1
  done < "$MB/modes.list"
  return $mrc
}
```

A path with a newline in its name is not supported (logged as a limit in the document; none of the
declared trees carries one). Whitespace inside a path survives `read -r` because the path is the last field.

**`sysctl`.** Entries are kernel keys (lint `sysctl_charset`: `^[a-z0-9_]+(\.[a-z0-9_-]+)+$`, no duplicates,
requires `script`). `sysctl` and `backup` go together: the file is the persisted side, the record the runtime
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
    [ -n "$v" ] && [ "$v" != absent ] || continue
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
```

**`modules`.** Entries are module names (lint `modules_charset`: `^[a-z0-9_-]+$`, no duplicates, requires
`script`). The helpers fold `-` to `_` (kmod's rule) and read `/proc/modules`.

```sh
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if awk -v m="$n" '{ gsub(/-/, "_", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe -- "$n" || orc=1
  done
  return $orc
}
```

**The block.** Head, in order: `MB=…; mkdir -p "$MB"`, `backup`, `save_units`, `save_modes`, `save_sysctl`,
`save_modules`, each `|| { log "<id>: backup failed, nothing changed"; return 1; }`; then the body subshell.
Failure path, in order: the declared `rollback`, `restore_units`, `restore_modes`, `restore` (files and
absent markers), `restore_sysctl`, `restore_modules` — the runtime value is re-applied after the file that
would persist the script's value is gone, and a module is reloaded after its `install … /bin/false` line is
gone. Each restore that fails logs `ROLLBACK INCOMPLETE`; the next one still runs. The helpers use their own
variables (`spec`, `p`, `s`, `k`, `v`, `m`, `n`, `mrc`, `src`, `orc`) and never the block's `rc`.

**Plan.** `Item` gains `Modes`, `Sysctl`, `Modules []string` (json `modes`, `sysctl`, `modules`, after
`units`; `[]` when none, set only when `Script` is true). `Build` re-checks every entry against its lint
pattern and refuses the plan otherwise (as it does ids and units). `Item.Rollback` becomes
`none | declared | restore_backup | units | state | both`: `units` when only units are declared, `state` when
`modes`, `sysctl` or `modules` are declared and nothing else, `both` when a file backup or a declared rollback
is declared beside any record kind. The table's column shows the word.

**Tests.** A stub-free test runs `save_modes`/`restore_modes` over a temp tree (dotfiles, a symlink, a
directory entry, a two-level pattern, a pattern that matches nothing, a path with a space; first record kept
on a rerun; `ROLLBACK INCOMPLETE` when a path is unwritable). Stub `sysctl` and `modprobe` (as the 3D-2b
`systemctl` stub, logging argv and answering from fixture files, with a fixture `/proc/modules` path handed
through an environment variable the stub reads) drive the other two: a readable key, an `absent` key, a key
that refuses the write; a loaded module reloaded, an unloaded one left alone, a `modprobe` that fails. A
failure-path order test checks the six restore lines' order in a block that declares every kind. The 3D-2b
unit tests move to `$MB/units/`.

## 4. The bodies (E-4)

Every body is POSIX `sh`, shellcheck-clean at the default severity, `set -e`-safe inside the body subshell,
and uses only literal paths, `P_` variables and what it enumerates on the host. Every control gains
`idempotent: true` (already true on all) and a one-line `validate` that proves the step. Texts keep their
sentences; where a script now exists the text names the file it writes.

### 4.1 sysctl (17)

Facts of this family are judged on the runtime side (`default_on: effective`): the verdict is `/proc/sys`.
The persisted side is evidence. So a body does both: it writes a file for the next boot and applies the value
now. File: `/etc/sysctl.d/99-muster-<name>.conf` (one per control, so each block owns its backup), which
sorts after systemd's `50-default.conf` and `50-coredump.conf` and after Ubuntu's `10-*.conf`, and before
`99-sysctl.conf` → `/etc/sysctl.conf`; a host whose `/etc/sysctl.conf` sets the key keeps that persisted
value, and the text says so. One line per key, no comments on value lines (a trailing `#` is part of the
value to the collector). Risk `none`. Shape, for `syn_cookies_enabled`:

```yaml
  sysctl: [net.ipv4.tcp_syncookies]
  backup: [/etc/sysctl.d/99-muster-syn-cookies.conf]
  script: |
    printf '%s = %s\n' net.ipv4.tcp_syncookies 1 > /etc/sysctl.d/99-muster-syn-cookies.conf
    chmod 644 /etc/sysctl.d/99-muster-syn-cookies.conf
    sysctl -q -w net.ipv4.tcp_syncookies=1
  validate: "[ \"$(sysctl -n net.ipv4.tcp_syncookies)\" = 1 ]"
```

| control | keys → values (first list element where a list) | params |
|---|---|---|
| `aslr_and_link_protection` | `kernel.randomize_va_space=2`, `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_fifos=1`, `fs.protected_regular=2` | — |
| `icmp_broadcast_and_bogus_ignored` | `net.ipv4.icmp_echo_ignore_broadcasts=1`, `net.ipv4.icmp_ignore_bogus_error_responses=1` | — |
| `icmp_redirects_ignored` | `net.ipv4.conf.{all,default}.{accept,secure,send}_redirects=0` (six keys) | — |
| `ip_forwarding_disabled` | `net.ipv4.ip_forward=$P_allowed_forward` | `allowed_forward[0]` |
| `ipv6_forwarding_disabled` | `net.ipv6.conf.{all,default}.forwarding=$P_allowed_forward` | `allowed_forward[0]` |
| `ipv6_redirects_ignored` | `net.ipv6.conf.{all,default}.accept_redirects=0` | — |
| `ipv6_router_advertisements_ignored` | `net.ipv6.conf.{all,default}.accept_ra=$P_allowed_accept_ra` | `allowed_accept_ra[0]` |
| `ipv6_source_routing_rejected` | `net.ipv6.conf.{all,default}.accept_source_route=0` | — |
| `kernel_pointer_exposure` | `kernel.kptr_restrict=1`, `kernel.dmesg_restrict=1` | — |
| `ptrace_restriction` | `kernel.yama.ptrace_scope=1`, `kernel.perf_event_paranoid=2` | — |
| `reverse_path_filtering` | `net.ipv4.conf.{all,default}.rp_filter=1`, `net.ipv4.conf.{all,default}.log_martians=1` | — |
| `source_routing_rejected` | `net.ipv4.conf.{all,default}.accept_source_route=0` | — |
| `suid_dumpable_disabled` | `fs.suid_dumpable=0` | — |
| `syn_cookies_enabled` | `net.ipv4.tcp_syncookies=1` | — |
| `sysrq_restricted` | `kernel.sysrq=$P_allowed_sysrq` | `allowed_sysrq[0]` |
| `unprivileged_bpf_restricted` | `kernel.unprivileged_bpf_disabled=2`, `net.core.bpf_jit_harden=2` | — |

- `unprivileged_bpf_disabled` is written as `2`, not the text's `1`: the kernel accepts no write once the
  value is `1`, so `1` could not be rolled back; `2` is in the clause's list and stays writable. The text
  changes to say so. `yama.ptrace_scope` is `1` for the same reason (`3` is one-way).
- `core_dump_policy` stays text: it is `partial`, judged by mechanism, and its runtime side (`core_pattern`)
  has no persisted reading.
- The four IPv6 controls are gated by `ipv6_disabled eq 0` and need no guard in the body. A key absent on the
  host (no Yama, no BPF JIT) is `absent_means: fail` with no `script_on_absent`: text-only, as today.
- `ip_forwarding_disabled` is `restart_service` in risk from now on: setting `0` on a router or a container
  host cuts forwarding at once. The others stay `none`.

### 4.2 Modules (3)

`disabled` means not loaded, not built in, and either `install … /bin/false` in the modprobe.d chain or not
shipped. So a body writes the line and unloads the module. File: `/etc/modprobe.d/99-muster-<name>.conf`; kmod
keeps the first `install` it reads in base-name order across the directories, so a vendor file with an
`install` line for the module would win — none of the eleven has one on the images measured, and the text
names the case. Risk `restart_service` (an unloaded `usb-storage` drops a mounted USB disk).

```yaml
  modules: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]
  backup: [/etc/modprobe.d/99-muster-uncommon-filesystems.conf]
  script: |
    : > /etc/modprobe.d/99-muster-uncommon-filesystems.conf
    for m in cramfs freevxfs jffs2 hfs hfsplus udf; do
      printf 'install %s /bin/false\n' "$m" >> /etc/modprobe.d/99-muster-uncommon-filesystems.conf
      if awk -v m="$m" '{ gsub(/-/, "_", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules; then modprobe -r -- "$m"; fi
    done
    chmod 644 /etc/modprobe.d/99-muster-uncommon-filesystems.conf
  validate: "for m in cramfs freevxfs jffs2 hfs hfsplus udf; do modprobe --showconfig 2>/dev/null | grep -q \"^install $m /bin/false\" || exit 1; ! awk -v m=\"$m\" '{ gsub(/-/, \"_\", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules || exit 1; done"
```

A `modprobe -r` that fails (module in use) fails the body: the host uses the module, and the block rolls
back. A built-in module keeps the control at FAIL, and the text says a different kernel is the only remedy.
The initramfs is not rebuilt (text). The module names in the body are the control's own `where` list,
repeated literally — the pin test of §6 holds the two equal.

### 4.3 File permissions (9)

As 3D-2b: `chown root:root` where the control judges the owner, symbolic `chmod` that only clears bits, a
`case` validate over the default modes where one path is judged. The glob sets use `modes` and `find`.

| control | record | body | validate |
|---|---|---|---|
| `sudoers_permissions` | `backup: [/etc/sudoers]`, `modes: [/etc/sudoers.d/*]` | `chown root /etc/sudoers; chmod u-wxs,g-wxs,o-rwxt /etc/sudoers`; `find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' -exec chmod go-w {} +` | `case` over `[0,40,400,440]` (the control judges uid only: format `%u %a`, prefix `0`) `&&` the `find … -perm /g+w,o+w` is empty |
| `nfs_export_access` | `backup: [/etc/exports]` | `[ -f ]; chown root:root; chmod u-xs,g-wxs,o-wxt` | `case` over the 16 modes, `%u %g %a`, `0 0` |
| `bootloader_config_permissions` | `backup: [/boot/grub/grub.cfg, /boot/grub2/grub.cfg]` | for each that exists: `chown root:root; chmod u-xs,g-rwxs,o-rwxt` | per existing path a `case` over `[0,200,400,600]`, `0 0` |
| `inetd_conf_permissions` | `backup: [/etc/inetd.conf, /etc/xinetd.conf]`, `modes: [/etc/xinetd.d/*]` | for each conf that exists: `chown root; chmod u-xs,g-rwxs,o-rwxt`; `find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -exec chmod go-w {} +` | the conf halves by `stat` bits (`g-w`, `o-r`, uid 0), the fragments by `find -perm /g+w,o+w` empty |
| `audit_log_permissions` | `backup: [/var/log/audit/audit.log]`, `modes: [/var/log/audit]` | `chown root /var/log/audit/audit.log; chmod u-xs,g-wxs,o-rwxt …; chown root /var/log/audit; chmod g-w,o-rwx /var/log/audit` | `case` over the eight modes (`%u %a`, `0`) `&&` dir bits |
| `syslog_conf_permissions` | `backup: [/etc/rsyslog.conf, /etc/systemd/journald.conf]`, `modes: [/etc/rsyslog.d/*, /etc/systemd/journald.conf.d/*, /etc/syslog-ng/syslog-ng.conf, /etc/syslog-ng/conf.d/*]` | each existing: `chown root; chmod u-xs,g-wxs,o-rwxt` (`find … -name '*.conf' -type f` for the dirs) | `find` over the same set `-perm /o+r,g+w,u+x` empty `&&` `! -user root` empty |
| `cron_permissions` | `modes: [/etc/crontab, /etc/anacrontab, /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny, /etc/cron.d/*, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, /etc/cron.hourly/*, /etc/cron.daily/*, /etc/cron.weekly/*, /etc/cron.monthly/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /var/spool/cron/atjobs/*, /var/spool/at/*, /etc/cron.d, /var/spool/cron, /var/spool/cron/crontabs, /var/spool/cron/atjobs, /var/spool/at]` | system and access files: `chown root; chmod u-xs,g-wxs,o-rwxt`; periodic scripts: `chown root; chmod o-w` (they keep `+x`: run-parts skips a non-executable); user spools: `chmod u-xs,g-wxs,o-rwxt` only (a spool owned by uid ≥ 1000 is correct); the nine directories: `chmod o-w` | `find` over the system/access set `-perm /o+rwx,g+w,u+x` empty `&&` periodic `-perm /o+w` empty `&&` spools `-perm /o+rwx,g+w` empty `&&` dirs `-perm /o+w` empty |
| `log_dir_permissions` | `modes: [/var/log, /var/log/*, /var/log/*/*]` | `find /var/log -maxdepth 2 -perm /o+w -exec chmod o-w {} +`; then for group-writable entries whose group is not in `$P_allowed_groups`: `chmod g-w` (a `set --` loop builds `! -group g` from the list) | both `find`s empty |
| `ftpusers_permissions` | `backup: [/etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers]` | for each that exists: `chown root:root; chmod u-xs,g-wxs,o-rwxt`; never create one (an empty allow list denies every login) | per existing path a `case` over the eight modes |

- `sudoers_permissions` clears `u-w` too: the target is `0440`, and `visudo` writes the file through a temp
  copy, not in place.
- `log_dir_permissions` is the one body that iterates a parameter list: `script_params: [allowed_groups]`.
  It never `chgrp`s: which group is right is the host's call, and `chmod g-w` is the safe side of the text's
  two options.
- `TestFileValidatesAcceptTheDefaultModes` grows from five to the eight controls whose judged file is one
  `backup` path with an `allowed_modes` list (`hosts`, `hosts_lpd`, `passwd`, `services`, `shadow`, `sudoers`,
  `nfs_export_access`, `bootloader_config_permissions`); the mixed ones are checked by lint and by the round
  trip only.

### 4.4 Accounts and sshd (5)

| control | record | body | params / absent |
|---|---|---|---|
| `password_policy` | `backup: [/etc/login.defs, /etc/security/pwquality.conf.d/99-muster.conf, /etc/shadow]` | `login.defs`: for each of `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`, replace the first uncommented line with `sed` or append when none (the collector reads the first); `pwquality.conf.d/99-muster.conf`: `minlen = $P_min_len`, `minclass = $P_min_classes`; then `chage -M $P_max_days -m $P_min_days` for every account whose shadow field 2 starts with `$` (enumerated on the host with `awk -F:`) | `script_params: [max_days, min_days, min_len, min_classes]`; `script_on_absent: true` |
| `umask_policy` | `backup: [/etc/login.defs]` | replace the first uncommented `UMASK` line with `UMASK $P_acceptable` (append when none) | `script_params: [acceptable[0]]`; default list reordered to `["027", "022", "077", "0027", "0022", "0077"]` |
| `lockout_threshold` | `backup: [/etc/security/faillock.conf]` | replace the `deny` line with `deny = $P_max_attempts` (append when none) | `script_params: [max_attempts]`; no `script_on_absent` (an absent `deny` means faillock is not stacked) |
| `session_timeout` | `backup: [/etc/ssh/sshd_config.d/00-muster-session.conf]` | as `root_remote_login`: guarded by `command -v sshd`, write `ClientAliveInterval $P_max_interval` and `ClientAliveCountMax $P_max_count`, `chmod 644`, `sshd -t`, reload a running `sshd`/`ssh` | `script_params: [max_interval, max_count]`; `script_on_absent: true` (no mechanism applies ⇒ the drop-in makes one apply) |
| `root_remote_login` | unchanged, rollback shrinks (E-2) | — | — |

- `password_policy`'s runtime side (`pass_max_days`/`pass_min_days` are judged on both sides) needs the
  `chage` loop, or the row ends WARN (`not applied`), never PASS. The loop names accounts the script read from
  `/etc/shadow` at run time; the `backup` of `/etc/shadow` is the way back for it. `pam.pwquality.enabled`
  stays what the host's PAM stack says: on a Debian-family host without `libpam-pwquality` the control stays
  FAIL after the script, and the text keeps saying to install it.
- `password_hash_algorithm` and `account_inactivity_lock` stay text (a rehash; a per-account `chage` over
  `login_capable` that the runner row could prove but that reads better as 3D-2d with the audit family).
- The `lockout_threshold` body is proven on the EL rows, where the seed stacks faillock through
  `authselect enable-feature with-faillock`; Debian 12 ships no `pam-auth-update` profile for faillock and
  is left out of its images.

## 5. Proof (E-6)

**The runner row.** `fix-roundtrip`'s matrix gains `{key: runner, kind: host, seeded: …}`; the container
rows gain `kind: container`. The run block's `x()` runs `docker exec "$cid"` on a container row and `sudo` on
the host row, and the paths differ by a prefix (`/m/muster` ↔ `./bin/muster`, `/out` ↔ `$d/repair`, `/ci`
↔ `ci/roundtrip`). The repair run is the same. The failure run has no second container: the job runs
`ci/roundtrip/runner.sh` again (it is idempotent), records, runs the broken copy, and compares. There is no
guard run on this row; the job asserts `fix.host_guard` is `on` (the VM has a machine id). The row never
starts docker (the `ip_forward` and `rp_filter` scripts change what docker's bridge needs), and it installs
`auditd` for `audit_log_permissions`.

**`record()`** gains, per planned scripted item: `sysctl -n` of every `.sysctl[]` key, the load state of
every `.modules[]` name, and `stat -c '%u %g %a'` of every path a `.modes[]` entry expands to (expanded as
the helper expands it).

**The table.** Every new scripted control enters `_roundtrip.yaml`. The hypothesis the plan's probe settles:

| controls | rows |
|---|---|
| the 17 sysctl, 3 modules, `bootloader_config_permissions`, `audit_log_permissions` | `runner` only (gated `beyond`) |
| `usb_storage_disabled` | `unproven`: the runner kernel ships no `usb-storage`, so the control passes there; the two uncommon-module controls carry `unproven_units` for every module the kernel does not ship |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | the four container rows (EL rows install `cronie`/`sudo`; inetd is planted as a file, EL9 has no package) and `runner` |
| `nfs_export_access`, `ftpusers_permissions` | the init rows (mode-only seeds; `ubuntu2204` has no systemd) |
| `log_dir_permissions` | all five rows (`install -m 664 -g games /dev/null /var/log/ci.log`) |
| `umask_policy` | all five rows (seed `UMASK 002`) |
| `password_policy` | EL rows (pwquality stacked by authselect; seed a hashed account) and `runner` only if `libpam-pwquality` is installed by the seed — the probe decides |
| `lockout_threshold` | EL rows (`authselect enable-feature with-faillock`, `deny = 99`) |
| `session_timeout` | EL rows and `runner` (seed `ClientAliveInterval 900` in `99-ci-session.conf`) |

**Table test.** `TestEveryScriptedControlIsInTheRoundtripTable` reads `kind`; a `host` row has no `init`;
`muster.beyond.*` ids may name `host` rows only; `muster.service.*` ids may not name a row with
`init: "false"`. `unproven_units` keys must be declared in the control's `units`, `modules` or `sysctl`.

**Pin tests.** `TestSysctlScriptsNameTheControlsKeys` (Linux, beside the sysctl leaf table): a control's
`sysctl` list equals, as a set, the kernel keys of the facts its clauses judge. `TestModuleScriptsNameTheControlsModules`:
a control's `modules` list equals its `where` list. Both replace nothing; they are new.

## 6. Lint, tests, documents

**Lint summary.** New per-control rules: `script_params_declared`, `script_params_used`,
`script_params_needs_script`, `script_params_default_safe`, `script_on_absent_needs_script`,
`modes_charset`, `modes_excludes_backup`, `sysctl_charset`, `modules_charset`, `state_needs_script`. Deleted:
`backup_path_shared`, `units_shared`, `backup_reserved`. The way-back rule reads: a `script` needs
`rollback`, `backup`, `units`, `modes`, `sysctl` or `modules`.

**Tests.** The lint cases; the plan tests (`script_params` formatting for every type, the index, the charset
refusal, `script_on_absent`, the `state` rollback word, the per-kind `Build` refusal); the script tests of
§3; the goldens regenerated (`full.sh` gains a params control and a state control; `all-scripted.sh` renders
every new body); `TestScriptEveryLineIsTemplateBodyOrComment` admits the `P_` lines and the four record
lines; the 3D-2b unit tests at the new path; the file-validate test over eight controls;
`TestFileScriptsRepairOnARealFile` over the new single-path file bodies; the two pin tests; the table test.
The mutation test leaves zero survivors.

**CI.** The runner row, `ci/roundtrip/runner.sh`, `record()`'s three additions, shellcheck over the new
script.

**Documents** (English and Korean in the same commit). Main design: D34 amended (§2), §6.2 gains the five
fields and the rules, §6.8 loses the two set-wide rules, §7.5 gains the record kinds and the failure order,
§10.2 marks 3D-2c merged and names 3D-2d (audit family, `account_inactivity_lock`, the content halves).
`CLAUDE.md` Fix section; `CONTRIBUTING` pair (how to write a body: `P_` for a parameter, a record kind for the
way back, `find` for a glob); README pair; `THREAT_MODEL.md` (a parameter value enters a command only under
the charset); `CHANGELOG` (Added: parameters in scripts, the three record kinds, the runner row, 38 scripts;
Changed: per-block backup directories, absent paths removed on restore, the three deleted lints, three
default-list orders, `ip_forwarding_disabled` risk; Controls: `kisa-unix-2026+2026.10.14`, no verdict change).

## 7. Parked

- Scripts for the controls that need a judgment per host (mounts, partitions, swap, secure boot, listeners,
  sudo, keys, `nfs.exports` content, `password_hash_algorithm`, `account_inactivity_lock`, the audit family) —
  3D-2d where a safe shape exists, text otherwise.
- PAM stack edits (`pwquality`, `faillock`, `pam_umask`): text.
- The initramfs rebuild after a module is disabled.
- A persisted sysctl value that `/etc/sysctl.conf` or a later file overrides.
- A guard run for the runner row (one host).
- Paths with a newline in `modes` trees.
