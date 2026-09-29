# Stage 3C-2a — privilege: who holds root's power without being root

*English · [한국어](2026-09-29-stage3c2a-privilege-design.ko.md)*

This document is the design for plan 3C-2a of muster: the first half of the sub-project the
3C-1 design (`2026-09-23-stage3c1-audit-integrity-design.md`, §8) left as **3C-2 "exposure
and privilege"**. On 2026-09-29 that half was split again by theme: **3C-2a "privilege"** —
which accounts, files and groups hold root's power without being root — and **3C-2b
"exposure"** — the process collector, processes running deleted executables, the
socket → process → package → firewall cross-check and the network sysctls 3B parked. This
document is 3C-2a alone; 3C-2b gets its own design once 3C-2a has merged. Decisions are
numbered P-1 … P-12 and bind the plan. Every check here is written from primary sources —
`shadow(5)`, `useradd(8)`, `lastlog(8)`, `sudoers(5)`, `capabilities(7)`, `cap_to_text(3)`,
`systemd.service(5)`, `systemd.unit(5)`, `ld.so(8)`, `sshd(8)`, `sshd_config(5)`,
`ssh-keygen(1)`, RFC 4253 §6.6, `acl(5)` — in muster's own wording, carries no CIS
recommendation number, and reproduces no benchmark text (§11 of the main design, D04). A fresh
two-reviewer pass on 2026-09-29 (controls side 5 blocking / 9 medium / 6 low; collectors side
4 blocking / 10 medium / 10 low) is folded in; where this version differs from the first draft
— the clause grammar, the capability declaration source, the walk's xattr primitive, the
lastlog record, the unit search path, the sudoers grammar, the oracle shapes — the difference
is theirs.

Seven choices were made in brainstorming and shape everything below: the split above (Q1);
every control judges what it reads and reads FAIL where the host is as it is, with
relaxation through `params` and waivers rather than through the control looking away (Q2);
dormant accounts are judged by the inactivity policy in `shadow(5)` and `useradd(8)`, and the
login history is evidence (Q3); the walk judges file capabilities against the package
declaration the way it judges setuid bits, and records ACLs without judging them (Q4); sudoers
is read to the depth of user specifications with aliases resolved, and what cannot be resolved
reads MANUAL (Q5); the systemd units judged are the services that are enabled or active
(Q6); `authorized_keys` files are inventoried without their key bodies, root's keys are judged
against `PermitRootLogin`, and key quality is judged from OpenSSH's own documentation (Q7).
The collectors are three extensions and three new ones (Q8).

## 1. Goal

Add eight controls of category `beyond` — the inactivity lock, passwordless `ALL` in
sudoers, undeclared file capabilities, writable executables of root services,
`ld.so.preload`, container-runtime sockets and their groups, root's authorized keys, and
SSH key quality — fed by three extended collectors (`accounts`, `files` (its sudo reader),
`walk`) and three new ones (`units`, `sshkeys`, `privilege`). After 3C-2a the control set is
104 controls (68 for the 67 items, unchanged, plus 36 beyond), `controls/VERSION` is
`kisa-unix-2026+2026.09.29`, and `schema_version` is unchanged (keys and record fields are
added, none changed; main §5.7). One read primitive grows: `ReadDir` can read the capability
and ACL attributes of the executables it lists, for the walk alone (P-3).

Out of scope, named so the plan does not drift: everything of 3C-2b (above); root's `PATH`
— the guide control `root_home_and_path` already judges `.` and world-writable entries of
`env.shell.root_path_entries`, and the roadmap's "root's PATH" is that control; judging ACLs
(recorded only — no primary source ranks a general ACL); the actual dormant-account list as a
verdict (evidence only, P-1); `NOPASSWD` on specific commands (evidence only); the `ALL`
command granted with a password (the stock `%wheel` / `%sudo` line); `Host_Alias` and the
host field of a user specification (every line counts as if for this host); `Defaults!command`
scopes; services that are neither enabled nor active; `.socket`, `.timer` and `.path` units;
`AuthorizedKeysFile` set to a path other than the two defaults, `AuthorizedKeysCommand`,
certificate authorities; keys of ordinary users without `from=` or `restrict` (evidence only);
rootless podman's per-user socket; `/etc/security/access.conf`; the `lastlog2` and `wtmpdb`
databases of shadow ≥ 4.15 (sqlite; their absence leaves the login history `absent`, never
the verdict); a per-release reference list of capabilities — the host's own package
metadata declares them (P-3), so `tools/suidindex` is not extended.

## 2. Principles carried from 3B and 3C-1

1. **The verdict reads the host as it is.** A stock cloud image reads FAIL on
   `sudo_nopasswd_all` (cloud-init writes `NOPASSWD:ALL` for its user), every stock release
   reads FAIL on `account_inactivity_lock` (`INACTIVE` is unset), and a docker host whose
   administrators sit in the `docker` group reads FAIL on `container_runtime_access` — the
   GitHub runner is both of the last two. Each description says so. The organisation's choice
   is recorded as a `params` value or a waiver, not assumed by the control (Q2).
2. **What muster did not see is MANUAL naming the path, never FAIL and never PASS** (C4). A
   sudoers alias muster cannot resolve, an `@include` outside the declaration, a home directory
   outside the declared patterns, a unit file that exists and cannot be read — each leaves the
   judged leaf `absent` with the reason and the control MANUAL. A declared file that cannot
   be read is the read's status (C3) → ERROR; only a path muster declined to read is `absent`.
3. **Every leaf a clause judges is its own key** (C2). `where` takes one condition, so a
   compound condition ("interactive and unset") is a collector-derived list, and the threshold
   the administrator tunes is a `params` value compared against a field the collector recorded
   (`inactive gt ${max_inactive_days}`). Every row of a judged list carries every field a
   clause names, with a neutral value when the row is about something that does not exist
   (R176: an `exists: false` row still has `other_writable: false`).
4. **Same input, same bytes.** Every list is sorted (by `path`, `name`, `unit` or `file, line`),
   capped, with `truncated: true` on the key when the cap was hit. Key bodies never enter a
   snapshot: a key is its type, its bit length, its SHA256 fingerprint and its options.
5. **Nothing here runs a policy engine.** `sudo -l` evaluates the policy and logs the attempt,
   so muster parses the files; `visudo -c` only validates and is the oracle's tool, not the
   collector's. One new command, `systemctl list-units`, with fixed arguments; one changed
   command, the walk's rpm query, which gains a column.

## 3. Facts and collectors (P-1 … P-6)

New registry keys: 19 (3 `accounts.*`, 4 `sudo.*`, 2 `walk.*`, 3 `units.*`, 4 `ssh.*`, 3
`privilege.*`, the evidence-only lists included), every one `since: 1` under the unchanged
schema version. Sensitivity is `public` unless said otherwise. Every new path a collector
reads is in its `Declaration.Reads`; the paths are listed per collector below because the
guard refuses anything else.

### P-1 — `accounts` gains the inactivity policy and the login history

`Reads` gains `/etc/default/useradd` and `/var/log/lastlog`. The shadow fields are already
read: `accounts.users` rows carry `inactive` (field 7, -1 when empty) and `expire` (field 8).
Three leaves are added.

- `accounts.login_capable` — `list<record>` `{name, uid, inactive, expire, inactive_unset,
  locked}`: the accounts the inactivity policy has to cover — every account with an
  interactive shell by the rule `files_home` already applies (`interactive()`: the shell is
  listed in `/etc/shells` and is not `nologin` or `false` — `/etc/shells` lists `nologin` on
  EL, so membership alone is not the test) that is not a system account. **Root is included**
  (`system` is false for uid 0 and root has an interactive shell): the field belongs to the
  account, and a host that sets every user's field but root's still reads FAIL until root's is
  set; the description says so. **Password-locked accounts are included** (`locked` records
  it): `shadow(5)` says such an account may log in by other means, `pam_unix` applies the
  inactivity field to a key login too, and the cloud image's default user — a `!` password
  and an authorized key — is precisely the account this control is about. `inactive_unset` is
  `inactive == -1`. On a host with no `/etc/shadow` (`password_status` `noshadow`) the field
  cannot exist: every such row is `inactive_unset: true`, and the host reads FAIL here as it
  does on U-04. Sorted by `name`. When `/etc/shadow` exists and could not be read the leaf
  carries the read's status (C3): the non-root reading is `denied`.
- `accounts.useradd.inactive` — `int`: the `INACTIVE` value of `/etc/default/useradd`
  (`useradd -D`'s file), the number of days after a password expires before the account is
  disabled for new accounts; -1 when the line is absent, commented, empty (`INACTIVE=`) or
  non-numeric (the reason says which — `useradd(8)` and shadow's `get_defaults` treat every one
  as "never"); a value written with surrounding spaces or quotes is read as `useradd -D -f`
  writes it. A file that exists and cannot be read is the read's status (C3): the file is 0644
  on Debian/Ubuntu and 0600 on EL (`shadow-utils` `%attr`), so the non-root reading is
  release-dependent and the capability matrix carries a `_notes` entry instead of a row. EL
  ships `INACTIVE=-1` written out; Ubuntu ships the line commented; both read -1.
- `accounts.lastlog` — `list<record>` `{name, uid, last_login, line, host}`, evidence only,
  `sensitivity: internal`: `/var/log/lastlog` read with `ReadFileBinary` to a limit of 32 MiB
  and decoded as fixed records indexed by uid — glibc's `struct lastlog` is `ll_time`,
  `char ll_line[32]`, `char ll_host[256]`, where `ll_time` is `int32_t` on the 32-bit-time
  ABIs and x86_64 (`__WORDSIZE_TIME64_COMPAT32`) and `__time_t` elsewhere, so the record is
  292 bytes on amd64/386/arm and 296 on arm64, ppc64le, s390x and riscv64; the size comes from
  `runtime.GOARCH`, is passed to `parseLastlog(data, recordSize)` and is recorded in the leaf's
  reason. Only the uids of `accounts.users` are decoded; `last_login` is RFC 3339 UTC or `""`
  when the record is zero ("never logged in"). A uid whose record lies past the read limit is
  not decoded and the leaf is `truncated: true`. Capped at 2000 rows, sorted by `name`. The
  file is 0664 `root:utmp`, so a non-root run reads it. Present wherever shadow < 4.15 — Ubuntu
  22.04 and 24.04, EL9, Debian 12; absent from Debian 13 / Ubuntu 24.10 onward, where shadow
  4.15 dropped `lastlog` and `lastlog2` keeps a sqlite database muster does not model — `absent`
  with that reason, and no control reads it.

### P-2 — the sudo reader (`files` collector, `files_sudo.go`) gains the rules

The sudo reader already walks the chain — `/etc/sudoers`, the `@includedir` / `#includedir`
directory, an `@include` of a declared path — and stops with `absent` naming the path when
an include points outside its declaration or a drop-in is a symlink (a `/dev/null` link is a
mask; 3C-1, J-40/J-49). The same walk now parses two more things from every line it reads
(`sudoers(5)`): alias definitions (`User_Alias`, `Runas_Alias`, `Cmnd_Alias`; `Host_Alias` is
read and ignored) and user specifications. The lexer changes with it: a `#` followed by a
digit is a uid (`#1000`), `%#` a gid, `#include` / `#includedir` are directives, and every
other `#` starts a comment; a logical line is joined across `\` continuations before it is
classified, whichever character it starts with (today's Defaults reader files every `#`-led
line as a comment). Grammar, from `sudoers(5)`:

- `User_List host_list = Cmnd_Spec_List [: host_list = Cmnd_Spec_List …]` — a `User_List`
  holds several comma-separated principals, each `user`, `%group`, `#uid`, `%#gid`,
  `+netgroup`, `%:nonunix_group`, `%:#nonunix_gid`, `User_Alias` or `ALL`, optionally `!`
  negated; one row is written per principal. `:` separates privileges on one line and starts
  runas and tags afresh.
- In a `Cmnd_Spec_List`, a `(runas)` spec and a tag (`NOPASSWD:`, `PASSWD:`, and the others)
  apply to the command they precede **and to every following command until another** of the
  same kind — `(root) NOPASSWD: /bin/a, /bin/b` runs both as root without a password.
  `(user)`, `(user:group)`, `(:group)` and `(ALL:ALL)` are all runas specs; muster records the
  spec's text and does not distinguish them for the verdict.
- A command list `ALL, !/usr/bin/su` still grants `ALL` (the man page calls negation no
  security measure); `sudoedit` is a command word.
- Aliases are resolved by substitution to a depth of eight; a cycle, an undefined alias, a
  netgroup or a non-Unix group leaves the row `resolved: false`.
- `Defaults` lines: unscoped, `Defaults:User_List`, `Defaults>Runas_List`, `Defaults@Host_List`,
  `Defaults!Cmnd_List`; a later line wins over an earlier one for the same flag (the
  `sudo.log.*` precedent).

- `sudo.rules` — `list<record>` `{file, line, principal, kind, negated, runas, nopasswd,
  commands, resolved}`, `kind` ∈ user | group | uid | gid | all | alias | netgroup |
  nonunix (after resolution an alias expands to one row per member with the member's `kind`;
  `alias`, `netgroup` and `nonunix` remain only on unresolved rows); `nopasswd` true when the
  `NOPASSWD:` tag applies to the command list; `commands` the resolved command list, `ALL`
  spelled as `ALL`, negated commands kept with their `!`. Evidence, `sensitivity: internal`,
  capped at 2000 rows, sorted by `file`, `line`.
- `sudo.nopasswd_all` — `list<string>`: the principals other than `root` and `#0` — `ALL`
  included, spelled `ALL` — that receive `ALL` as a command (negations notwithstanding) under
  `NOPASSWD:`, whatever the runas — `ubuntu` from cloud-init's `90-cloud-init-users`,
  `%admins` from an alias that expands to `ALL`, `runner` on the GitHub runner. Sorted, unique.
- `sudo.authenticate_disabled` — `bool`: after applying the lines in order, `!authenticate`
  is in force for the unscoped `Defaults`, or for any `Defaults:User_List` or
  `Defaults>Runas_List` (both are about who escalates and as whom — `Defaults>ALL
  !authenticate` turns the password off for every command run as anyone). `Defaults@host` and
  `Defaults!command` scopes are read and counted in `sudo.defaults.scoped_count` as today and
  do not set it (§1 parks them).
- `sudo.rules_unresolved` — `int`, the number of rules with `resolved: false`.

When `sudo.rules_unresolved` is not zero, `sudo.nopasswd_all` and `sudo.authenticate_disabled`
are `absent` ("N rules could not be resolved: ALIAS, +netgroup — the answer needs them") and
the control reads MANUAL (principle 2). When the chain was not fully read (an include outside
the declaration, a symlinked drop-in), all four leaves are `absent` naming the path, as
`sudo.log.*` are. Without sudo installed, `sudo.rules` is an empty list, `nopasswd_all` empty,
`authenticate_disabled` false, `rules_unresolved` 0 — the control is gated on
`sudo.installed` anyway. The registry rows say `collector: files`, as the other `sudo.*` keys
do.

### P-3 — the walk gains file capabilities and ACLs

**The primitive.** `ReadDir` today lists a directory with one `statx` per entry and closes the
directory fd before it returns; the walk holds no fd and every path-based xattr read is
guarded by `Reads`, which the walk does not have. So `ReadDir` grows an option — `ReadDir(path,
expect, ReadDirOptions{Xattrs: true})` — licensed by `Declaration.Walk` alone, under which, while
the directory fd is open, each **regular entry with any execute bit** (`mode & 0o111 != 0`) is
opened `openat(dirfd, name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC)`, checked with
`fstat` to be `S_IFREG` with the listing's (dev, ino), read with `fgetxattr` for exactly two
names — `security.capability` and `system.posix_acl_access` (two direct reads; `ENODATA` is
"no such attribute", so `flistxattr` is not called) — and closed. The results ride on the
`DirEntry`: `Caps []byte`, `ACL []byte`, `XattrErr error`. `NoWalkAccess` grows the stub; the
`--list-actions` walk row says "and reads the capability and ACL attributes of executables".
Only executables are opened: a capability on a file nobody can execute is inert
(`capabilities(7)`). The cost is per family: Debian/Ubuntu ship shared objects 0644, so the
pass opens perhaps a tenth of the regular files; the RPM family ships every `.so` 0755, so it
opens every library too. The plan's first task measures both — the lab (Ubuntu 22.04) and an
EL9 image — and records the added time against the walk budget.

**Errors.** `EACCES` / `EPERM` on the open → the path goes to `walk.skipped` with reason
`xattr_denied`; `ENOENT`, `ELOOP`, `ENXIO` or an identity mismatch after `fstat` → `vanished`
(errno in `detail`); `EOPNOTSUPP` / `ENODATA` on the read → no attribute, no row; `ERANGE` →
re-sized once as `Getxattr` does. A capability xattr whose version muster does not decode →
`walk.skipped` reason `xattr_undecoded`. `walk.skipped`'s closed vocabulary gains those two
reasons and its description becomes "every root the walk did not enter and every executable
whose attributes it could not read"; `walk.stats.truncated_counts` gains the two new lists'
keys. The walk never stops for an xattr.

**Decoding.** The VFS capability xattr (`include/uapi/linux/capability.h`): version 1 (one
u32 pair), version 2 (two pairs, permitted and inheritable, low and high words) and version 3
(version 2 plus `rootid`, the user namespace the capability is valid in), with the effective
flag in `magic_etc`. Capability indexes above the name table muster knows are spelled `cap_N`.
The row's `caps` is the **`cap_to_text(3)` canonical string** rendered from the (permitted,
inheritable, effective) triple — `cap_net_raw=ep`, `cap_chown,cap_setuid=p` — because that is
the one form both declaration sources and `getcap` share; `rootid` is recorded (0 for v1/v2)
and a v3 row with a non-zero `rootid` is judged like any other: inert in the initial user
namespace today, still a capability the package did not declare.

**Declaration.** The setuid join's three sources become two here, because capabilities are
declared where packages set them:
- rpm: the `%{FILECAPS}` tag — the walk's declared rpm query gains that column
  (`--qf "[…\t%{FILECAPS}\n]"`, empty when none), so the `--list-actions` command row changes
  and the plan says so. `reference: rpmdb`; `package_declared` is true when the tag's string
  renders to the same canonical `caps`.
- dpkg: a `.deb` cannot ship an xattr; the package's `postinst` sets it at install time with
  `setcap`. The join reads the owning package's `/var/lib/dpkg/info/<pkg>[:<arch>].postinst`
  (the glob joins the walk's `Reads`) and recognises three forms: `setcap <caps> <path>` with a
  literal path; `setcap <caps> $NAME` where `NAME=<path>` is assigned literally earlier in the
  script (`iputils-ping`'s `PROGRAM`); and `setcap [-q] - <path> < <file>` (snapd reads
  `snap-confine`'s set from a shipped file). `reference: postinst`; `package_declared` is true
  when the script names the path in a `setcap` invocation and, where the caps text is literal,
  it renders to the same canonical `caps`; `declared_caps` is that text, or `"(from file)"`
  for the third form. On the lab the five scripts that call `setcap` — `iproute2`,
  `iputils-ping`, `libgstreamer1.0-0`, `mtr-tiny`, `snapd` — cover the four files `getcap -r
  /usr` lists, so a stock Ubuntu host reads PASS through its own metadata.
- A file no package owns is `reference: unpackaged`, `package_declared: false` — the shape a
  planted binary takes, judged FAIL. The vocabulary is the walk's existing one (`rpmdb`,
  `dpkgdb`, `statoverride`, `list`, `unpackaged`, `unlisted`, `version_mismatch`, `postinst`,
  `none`); `list`, `unlisted` and `version_mismatch` do not occur here (no reference list), so
  there is no `capabilities_unverified` list and no unverified control: every decoded
  capability is judged.

- `walk.capabilities` — `list<record>` `{path, caps, rootid, package, package_declared,
  declared_caps, reference}`. Capped by `listCaps` (2000), sorted by `path`.
- `walk.acl_grants` — `list<record>` `{path, entries}`, evidence only: the executables whose
  access ACL grants write or execute to a named user or group beyond what the mode grants
  (the mask applied, `acl(5)`); `entries` in `getfacl` spelling with **numeric ids**
  (`user:1000:rwx` — the decoder never resolves names, and the check side cannot). Decoded by
  `decodeACL([]byte)`, the POSIX ACL decoder the fixed-path `acl_entries` facts already use.
  Capped, sorted. No control reads it (§1).

`walk.stats` gains the two lists' cap counters (the "thirteen fields" comment and the
registry description change with it).

### P-4 — the `units` collector

`Reads`: `*.service`, `*.service.d/*.conf`, `*.wants/*` and `*.requires/*` (the last two with
`Readlink`) under the system unit search path of `systemd.unit(5)`: `/etc/systemd/system`,
`/etc/systemd/system.control`, `/run/systemd/system`, `/run/systemd/system.control`,
`/run/systemd/transient`, `/run/systemd/generator.early`, `/run/systemd/generator`,
`/run/systemd/generator.late`, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/system`.
`Commands`: one, `systemctl list-units --type=service --state=active --plain --no-legend`
(unit, load, active, sub, description columns; `--state=active` excludes `activating` and
`reloading`; the call is a read-only D-Bus query and needs no privilege), declared as
`services` declares its `show` invocations. `Needs: none`.

A service is **in scope** when it is enabled (a `.wants`/`.requires` link names it in any
tree) or active (`list-units` lists it). For each, the unit file is found in the trees in
systemd's precedence; an instance `foo@bar.service` is looked up as its template
`foo@.service`; a unit file that is a symlink to `/dev/null` is a mask and the unit is out of
scope; a symlink whose target is a bare unit name in the same directory (Ubuntu's
`sshd.service → ssh.service` alias) is followed **by name** — `Readlink`, then that name is
looked up — once; any other symlink, and a unit no tree holds, is a row `unit_file: symlink` /
`unit_file: missing`, counted in `exec_unresolved`, its executables unjudged. The unit file
and its `.d/*.conf` drop-ins from every tree are read in systemd's order and merged by a
merger of their own (`mergeDropins` is single-valued and cannot merge `Exec*=` lists):
`[Service]` `User=` (last wins; `0` is root) and the `Exec*=` directives (`ExecStart`,
`ExecStartPre`, `ExecStartPost`, `ExecCondition`, `ExecReload`, `ExecStop`, `ExecStopPost`),
where an empty `ExecStart=` in a later file resets the list before it (`systemd.service(5)`).
The first token of each directive is the executable: prefix characters `@ - : + ! !!` are
stripped ("Command lines"), quotes removed; a token that is not an absolute path (allowed
since systemd 239) or that carries a `%` specifier (`%i`, `%I` in a template) is `resolved:
false` and not judged. A service whose merged `User=` is anything but `root`/`0` is out of
scope: its executables run without root's power.

- `units.root_services` — `list<record>` `{unit, enabled, active, user, unit_file, files,
  exec}`: `unit_file` ∈ file | symlink | missing; `files` the unit file and each drop-in read,
  `{path, mode, uid, gid}`; `exec` one row per `Exec*` first token, `{directive, path, exists,
  kind, mode, uid, gid, group_writable, other_writable, resolved}` from `Stat` of the path
  (every field present on every row — a missing file is `exists: false` with `mode -1`,
  `uid -1`, `gid -1`, both writable flags false; a symlink at the path is `kind: symlink`, not
  followed, judged by the link's own owner only). Evidence, `sensitivity: internal`, capped at
  500 units, sorted by `unit`.
- `units.exec_writable` — `list<record>` `{unit, path, why}`: the judged subset — an
  executable owned by a uid other than 0, or group-writable, or other-writable (`why` ∈
  `owner`, `group_writable`, `other_writable`), and a unit file or drop-in with the same
  three properties (`why` prefixed `unit_file:`). Sorted by `unit`, `path`. **`absent`**,
  naming the unit and path, when any in-scope unit file or drop-in exists and cannot be read:
  the unreadable file could carry the `ExecStart` that decides, so the answer is unknown and
  the control reads MANUAL (principle 2; the J-40 shape).
- `units.exec_unresolved` — `int`: rows with `resolved: false` plus units whose `unit_file`
  is `symlink` or `missing`. Evidence.

Without systemd (`env.has_systemd` false, `systemctl` cannot start, or it answers "System has
not been booted with systemd") the three leaves are `unsupported` (the `fim` timer
inventory's shape, 3C-1 J-45); a `list-units` that runs out of time is `timeout`, any other
non-zero exit `error` naming the code. The init containers of CI run systemd as PID 1 and
read `ok`; the plain images read `unsupported`, and the matrix's `no-systemd.unsupported` row
gains the three keys.

### P-5 — the `sshkeys` collector

`Reads`: `/etc/passwd`, `/etc/shells`, and — under the home patterns the `files` collector
declares, `/home/*`, `/home/*/*`, `/root` — `/.ssh/authorized_keys` and
`/.ssh/authorized_keys2`, the two defaults of `AuthorizedKeysFile` in `sshd_config(5)`.
`Needs: none`. The users are `/etc/passwd`'s local accounts with a home path, as `files_home`
selects them; a home outside the declared patterns leaves that user's row `unfollowed` with the
path (C4) **and makes the three counts `absent` naming it** — an inventory with a hole is not an
inventory, so a host with a user homed under `/srv` reads both key controls MANUAL naming the
home.

- `ssh.authorized_keys` — `list<record>` `{user, uid, path, exists, mode, owner_uid, keys,
  unparsed}`, `sensitivity: internal`: one row per file that exists (and one `exists: false`
  row per user with no file, so "no keys" is a reading, not silence); `keys` a list of
  `{line, type, bits, fingerprint, options, restricted}`. Decoding (`sshd(8)` AUTHORIZED_KEYS
  FILE FORMAT, RFC 4253 §6.6): the options field exists iff the first word is not a key type,
  and its quoted values may hold `,` and `\"`; the key blob is base64 and its inner type string
  must equal the type word, else the line is `unparsed`; `bits` for `ssh-rsa` is the bit length
  of the modulus `n` after its leading `0x00` (present when the top bit is set — a 2048-bit key
  encodes `n` in 257 bytes) is stripped; for `ecdsa-sha2-nistpXXX` the curve size from the
  inner curve name; 256 for `ssh-ed25519` and the `sk-*` types; 1024 for `ssh-dss`; 0 for
  certificate types (`*-cert-v01@openssh.com`, recorded, ignored by the controls);
  `fingerprint` `SHA256:` + **unpadded** base64 of the SHA-256 of the decoded blob (what
  `ssh-keygen -l` prints); `restricted` true when `restrict` or `from=` is among the options;
  `unparsed` the count of lines that are neither a comment, blank nor a parseable key. The key
  body itself is never stored. Capped at 200 keys per file and 500 rows.
- `ssh.root_key_count` — `int`: keys in root's two files. Both defaults are read on every
  release; EL ships `AuthorizedKeysFile .ssh/authorized_keys` uncommented, so a key in
  `authorized_keys2` there is one sshd ignores — the description of `root_authorized_keys`
  says the count includes it (a stale key file for root is a review, not a false alarm).
- `ssh.dsa_key_count` — `int`: `ssh-dss` keys across all files read.
- `ssh.rsa_keys` — `list<record>` `{user, path, line, bits, fingerprint}`: every `ssh-rsa`
  key whose modulus was read (one whose blob does not decode is in `unparsed`, never here, so
  every row carries `bits`). Sorted by `user`, `path`, `line`.

A file muster could not read (C3) puts the read's status on that row and on the three counts.
In a non-root run the load-bearing denial is `/root` itself (0700; the matrix step already
asserts `! test -r /root`), so the three counts are `denied` and both key controls read ERROR
naming it — except `root_authorized_keys` when its gate cannot be read (§4).

### P-6 — the `privilege` collector

`Reads`: `/etc/ld.so.preload`, `/etc/group`, `/etc/passwd`, and `Stat` of the four runtime
sockets `/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/podman/podman.sock`,
`/run/crio/crio.sock` — cri-o's configured `/var/run/crio/crio.sock` resolves there, and
`/var/run` is a symlink the read primitive refuses on every release, so the physical path is
the declared one. `Needs: none`.

- `privilege.ld_so_preload` — `list<string>`: the non-comment, non-blank entries of
  `/etc/ld.so.preload` (`ld.so(8)`: one library per line, whitespace-separated). A missing
  file is an `ok` empty list — the normal state; a file that exists and cannot be read is the
  read's status (C3).
- `privilege.runtime_sockets` — `list<record>` `{path, exists, mode, uid, gid, group,
  group_writable, other_writable}`: the control sockets of the four runtimes whose API is root
  (a client that can write to the socket can start a privileged container). Every row carries
  every field: a socket that does not exist (`ENOENT` on the path or any parent) is `exists:
  false`, `mode -1`, `uid -1`, `gid -1`, `group ""`, both writable flags false; a stat that
  fails otherwise (`EACCES` on `/run/podman`, 0750 root, in a non-root run on a podman host)
  puts the read's status on the leaf, path-prefixed (C3). `group` from `/etc/group` by gid.
  `/run/podman/podman.sock` exists only while root's `podman.socket` is active.
- `privilege.runtime_group_members` — `list<record>` `{group, member, uid, socket}`: for
  every existing socket that is group-writable, the members of its group with uid ≠ 0 —
  supplementary members from `/etc/group` and users whose primary gid is that group from
  `/etc/passwd` — one row per (group, member). Sorted by `group`, `member`. Empty when no
  socket exists or every group is empty (the lab's `docker` group is; the GitHub runner's is
  not — `runner` is in it).

When `/etc/group` or `/etc/passwd` cannot be read, `runtime_sockets`' `group` and the whole
`runtime_group_members` carry the read's status path-prefixed (C3). A non-root run reads all
three on a host without podman: `ld.so.preload` is 0644, `/etc/group` and `/etc/passwd` are
world-readable and `/run` is stat-able.

## 4. Controls (P-7)

Eight controls, `category: beyond`, ids `muster.beyond.<name>`, every one gated on
`env.container eq none`, every one a plain `checks` control (no mechanisms). The clause
grammar is the loader's: a `none` clause always carries a `where`; on a `list<string>` the
`where` has no `field` and the clause no `subject` (the element is the value); every `where`
is one condition; `${param}` substitutes into `expected` for `int` and `list<string>`.

`references.stig` entries were looked up in the committed index, with their versions: the
inactivity rules RHEL-09-411050 (`rhel9` V2R9), UBTU-22-411035 (`ubuntu2204` V2R9),
UBTU-24-200260 (`ubuntu2404` V1R6) and the reauthentication rules RHEL-09-432025 (`rhel9`
V2R9), UBTU-22-432010 (`ubuntu2204` V2R9), UBTU-24-300021 (`ubuntu2404` V1R6). The other six
controls cite no rule and carry muster's own rating with the primary source named in the
description. `references.nist_800_53` must be ids the index carries (`references_nist` lint):
the two cited controls take the union of their rules' mappings (`AC-2(3)`, `IA-4` /
`IA-11`, `SC-11`, `CM-6`); the four privilege-path controls take `AC-6(10)` (nine indexed
rules: non-privileged users must not execute privileged functions); the two key controls take
`IA-5(2)` (public-key-based authentication, twelve indexed rules).

| id | importance | further gate | judgment | `absent_means` |
|---|---|---|---|---|
| `account_inactivity_lock` | 중 | — | `{ fact: accounts.login_capable, op: none, subject: name, where: { field: inactive_unset, op: eq, expected: true } }`; `{ fact: accounts.login_capable, op: none, subject: name, where: { field: inactive, op: gt, expected: "${max_inactive_days}" } }`; `{ fact: accounts.useradd.inactive, op: gte, expected: 0 }`; `{ fact: accounts.useradd.inactive, op: lte, expected: "${max_inactive_days}" }` — `INACTIVE=0` (disable at expiry) passes both | fail — never reached: the leaves are `ok` or a read's status (three `_mutants.yaml` rows) |
| `sudo_nopasswd_all` | 상 | `sudo.installed eq true` | `{ fact: sudo.nopasswd_all, op: none, where: { op: not_in, expected: "${allowed_nopasswd_principals}" } }` (default `[]`); `{ fact: sudo.authenticate_disabled, op: eq, expected: false }` | manual — the chain was not fully read, or rules could not be resolved: the missing lines could carry the tag (`manual-include-outside.json`, `manual-unresolved-alias.json`) |
| `file_capabilities_declared` | 상 | (deep gate: `walk.complete`) | `{ fact: walk.capabilities, op: none, subject: path, where: { field: package_declared, op: eq, expected: false } }` | fail — never reached: a non-deep run is MANUAL at the deep gate before screening (three rows) |
| `root_unit_exec_writable` | 상 | `env.has_systemd eq true` | `{ fact: units.exec_writable, op: none, subject: path, where: { field: why, op: present } }` | manual — an in-scope unit file or drop-in exists and could not be read (`manual-unit-unreadable.json`) |
| `ld_so_preload_empty` | 상 | — | `{ fact: privilege.ld_so_preload, op: none, where: { op: not_in, expected: "${allowed_preload}" } }` (default `[]`) | fail — never reached: a missing file is an `ok` empty list (three rows) |
| `container_runtime_access` | 상 | — | `{ fact: privilege.runtime_sockets, op: none, subject: path, where: { field: other_writable, op: eq, expected: true } }`; `{ fact: privilege.runtime_group_members, op: none, subject: member, where: { field: member, op: not_in, expected: "${allowed_runtime_group_members}" } }` (default `[]`) | fail — never reached: no socket is a row with `exists: false` (three rows) |
| `root_authorized_keys` | 중 | `sshd.options.permit_root_login ne no` (`default_on: effective`) | `{ fact: ssh.root_key_count, op: eq, expected: 0 }` | manual — root's home is outside the declared patterns, or another user's is (`manual-home-outside.json`) |
| `ssh_key_quality` | 중 | — | `{ fact: ssh.dsa_key_count, op: eq, expected: 0 }`; `{ fact: ssh.rsa_keys, op: none, subject: fingerprint, where: { field: bits, op: lt, expected: "${min_rsa_bits}" } }` (default 2048) | manual — a user's home is outside the declared patterns (`manual-home-outside.json`); `unparsed` lines are evidence only and the description says the verdict covers parsed keys |

The `root_authorized_keys` gate has three outcomes, all NOT_APPLICABLE: `PermitRootLogin
no` in force; sshd not installed (the fact `absent`); and the `effective` home `absent`
because neither `sshd -T`/`-G` answered nor the files set the keyword (a non-root run on EL9,
whose `sshd_config` is 0600; a socket-activated daemon that would not answer) — on such a host
the compiled default `prohibit-password` accepts keys and the control does not see it. That
miss is accepted and written in the description, because the alternative — judging root's
keys with root login off — is a FAIL for a key nothing can use. A root key that carries
`command="…"` or `restrict` is the documented shape of `PermitRootLogin forced-commands-only`;
the gate admits it and the control FAILs it, and the description says that is a FAIL to be
waived, since a second gate condition cannot be written.

`params`: `max_inactive_days` (`int`, 35 — the cited rules' value; `shadow(5)` field 7),
`allowed_nopasswd_principals`, `allowed_preload`, `allowed_runtime_group_members`
(`list<string>`, `[]`), `min_rsa_bits` (`int`, 2048 — `sshd_config(5)`'s `RequiredRSASize`,
present from OpenSSH 9.1, defaults to 1024 and muster is stricter, saying so). A fixture
carries no parameter overrides, so the relaxation of a list parameter is proved in
`internal/check/eval_test.go` with `Options.Params` (P-9), not by a fixture; the `int`
parameters' boundaries are proved by fixtures at the exact values (P-9).

What the descriptions say, in muster's words: `account_inactivity_lock` — `useradd(8)`'s
`INACTIVE` and `shadow(5)`'s inactivity field lock an account a fixed number of days after
its password expires, the only mechanism the base system has for closing an account nobody
uses; the cited rules ask for 35 days; root is covered like every other account; a stock host
reads FAIL. `sudo_nopasswd_all` — a principal that runs any command as any user without a
password is root with an extra step; the `%sudo`/`%wheel` lines with a password are the
shipped state and pass; cloud-init's `NOPASSWD:ALL` fails, and `allowed_nopasswd_principals`
is where an image's service account is recorded on purpose. `file_capabilities_declared` —
`capabilities(7)`: a file capability gives an executable a slice of root's power without a
setuid bit, and one the package did not declare — in its rpm header or its `postinst` — is a
setuid binary nobody knows about; the setuid control's twin. `root_unit_exec_writable` — a
service that runs as root executes whatever the path names at its next start; a file a
non-root user can rewrite, or a unit file they can edit, hands them that start; a unit file
muster could not read is a look. `ld_so_preload_empty` — `ld.so(8)`: a library named here is
loaded into every dynamically linked program on the host, root's included; the file does not
exist on a stock host and any entry is a review at least, so the default allowlist is empty.
`container_runtime_access` — the runtime's API socket creates containers with any mount and
any capability; a group that can write to it is a root group, which the runtimes' own
documentation says (docker's post-install notes call the `docker` group root-equivalent); the
GitHub runner reads FAIL. `root_authorized_keys` — a key in root's file is a root login
without a password prompt wherever `PermitRootLogin` allows keys (`prohibit-password` allows
exactly that); NOT_APPLICABLE when root login is off, when sshd is absent, and when the
setting could not be read; `authorized_keys2` is counted on every release. `ssh_key_quality` —
OpenSSH disabled DSA by default in 7.0 and removed it in 9.8, so an `ssh-dss` line is dead
weight at best and a downgrade target on an old server; an RSA key below 2048 bits is under
the size OpenSSH's own `ssh-keygen(1)` has generated by default since 2014; certificate and
`sk-*` keys are recorded and not judged.

## 5. Environments (P-8)

- **root.** Everything answers. One new command (`list-units`), one changed (the rpm query's
  `%{FILECAPS}` column). The walk's xattr pass runs under `--deep` only and opens executables
  only; the plan's first task measures it on the lab (Ubuntu 22.04) and in an EL9 image and
  records the added time against the 15 m runner budget.
- **Non-root.** `accounts.login_capable` — `/etc/shadow` is root-only, `denied` (C3), the
  control ERROR; `accounts.useradd.inactive` answers on Debian/Ubuntu (0644) and is `denied` on
  EL (0600) — a matrix `_notes` entry, not a row; `accounts.lastlog` answers (0664). The four
  `sudo.*` rule leaves are `denied` (`/etc/sudoers` is 0440). `units.*` answer: unit files are
  world-readable, `list-units` needs no privilege, executables are stat-able; a root-only
  drop-in makes `units.exec_writable` `absent` naming it (MANUAL, as for root). `ssh.*`: `/root`
  is 0700, so the rows and the three counts are `denied`; `ssh_key_quality` reads ERROR naming
  it, `root_authorized_keys` ERROR where the gate is readable (Ubuntu's `sshd_config` is 0644)
  and NOT_APPLICABLE where it is not (EL9). `privilege.*` answer in full where no podman socket
  directory exists. The capability matrix's `nonroot.denied` row gains nine keys —
  `accounts.login_capable`, `sudo.rules`, `sudo.nopasswd_all`, `sudo.authenticate_disabled`,
  `sudo.rules_unresolved`, `ssh.authorized_keys`, `ssh.root_key_count`, `ssh.dsa_key_count`,
  `ssh.rsa_keys`; the non-root CI job proves the row.
- **Container.** Every beyond control is NOT_APPLICABLE by the gate. The collectors still have
  to complete so `run.complete` stays true: `units` reads `unsupported` in the plain images
  (no `systemctl`; R220 counts it as answered) and `ok` in the init images (systemd is PID 1
  there), `privilege` finds no socket (rows with `exists: false`), the file readers read
  files. The five container jobs' existing `run.complete` step covers it; the
  `no-systemd.unsupported` matrix row gains the three `units.*` keys.
- **No systemd.** `units.*` `unsupported` → `root_unit_exec_writable` NOT_APPLICABLE through
  `env.has_systemd`. Nothing else depends on it.
- **Releases.** lastlog: present on Ubuntu 22.04 and 24.04, EL9 and Debian 12 (shadow < 4.15);
  absent from Debian 13 / Ubuntu 24.10. Capability declarations: rpm `%{FILECAPS}` on EL9,
  `postinst` on the dpkg family — no reference list, no release without a source. `INACTIVE`:
  -1 on all three (EL writes it, Ubuntu comments it) — stock FAIL. sudoers: EL `%wheel ALL=(ALL)
  ALL`, Ubuntu `%sudo ALL=(ALL:ALL) ALL` — PASS; cloud-init's `90-cloud-init-users` and the
  GitHub runner's `runner` — FAIL. OpenSSH: 22.04 ships 8.9, 24.04 9.6, EL9 8.7 — all refuse
  DSA by default, so a `ssh-dss` line the control flags is one the server already ignores;
  `RequiredRSASize` exists from 9.1 (24.04 only), default 1024; EL sets `AuthorizedKeysFile` to
  the first default alone.
- **Stock snapshots.** `controls/testdata/_hosts/ubuntu-22.04-stock.json` and
  `el9-stock.json` gain the new keys (the EL9 snapshot gains the walk and sshd shapes it
  lacked, so its table grows from nine to seventeen rows); `hosts_test.go` pins eight rows
  each: `account_inactivity_lock` FAIL, `sudo_nopasswd_all` PASS, `file_capabilities_declared`
  PASS (Ubuntu: the four files declared by `postinst`; EL9: `ping` declared by `%{FILECAPS}`),
  `root_unit_exec_writable` PASS, `ld_so_preload_empty` PASS, `container_runtime_access` PASS
  (no socket), `root_authorized_keys` PASS (gate holds — `prohibit-password` — and zero keys),
  `ssh_key_quality` PASS.

## 6. Tests, CI, documents (P-9 … P-12)

**P-9 fixtures and mutants.** Per control: `pass-*.json` and `fail-*.json` per clause,
`na-container.json`, and `na-*.json` per further gate (`na-no-sudo.json`, `na-no-systemd.json`,
`na-root-login-off.json`, `na-sshd-absent.json`), `manual-*.json` where the table names one,
`error-*.json` in the non-root shape the collector writes (`denied` on the leaf the read
failed). The `int` boundaries the mutation generator probes (`expected ±1`, a parameter's
default ±1): `pass-inactive-exactly-35.json` (a row with `inactive: 35` and `useradd.inactive:
35`), `fail-inactive-36.json`, `pass-useradd-inactive-0.json`, `pass-rsa-2048.json`,
`fail-rsa-2047.json`, `fail-rsa-1024.json`. List parameters default to `[]`, so they generate
no mutant and get no fixture; the relaxation is one `eval_test.go` derivation row per list
parameter (`Options.Params` naming the principal / library / member, expecting PASS). Every
fixture `synthetic: true`, every key the control names present, every judged row carrying
every field (principle 3). `_mutants.yaml` rows: the twelve `absent_means → pass |
not_applicable | manual` rows of `account_inactivity_lock`, `file_capabilities_declared`,
`ld_so_preload_empty` and `container_runtime_access`, each citing the invariant in §4's last
column; nothing else is expected — the four MANUAL controls reach `absent` through their
`manual-*` fixtures. Mutation test: zero survivors.

**P-10 parsers and fuzz targets.** Unit tests and a `Fuzz<Name>` with seeds for every
`[]byte` entry point (`TestEveryParserHasAFuzzTarget` enforces it): `parseSudoers` (alias
nesting to depth 8, a cycle, an undefined alias, `#include` vs `#uid`, a continuation on a
`#uid` line, tag and runas inheritance, the `:` privilege separator, a multi-principal list, an
`ALL` principal, `%:` groups, `ALL, !cmd`, `Defaults` scopes with a later line winning),
`parseLastlog` (both record sizes, a short tail, a future time, a zero record, a uid past the
limit), `parseAuthorizedKeys` (quoted options with commas, `restrict`, RSA modulus with and
without the leading zero, ecdsa curve, `sk-*`, a certificate, an inner type that does not
match, broken base64 → `unparsed`, a line longer than the cap), `parseUnitFile` and its
`Exec*` merger (sections, prefixes, quoting, an empty `ExecStart=` reset in a drop-in, `User=`
in a drop-in, `User=0`, a `%i` token), `decodeVfsCap` (v1, v2, v3 with rootid, truncated input,
an unknown version, an index past the table), `parseListUnits`, `parsePostinstSetcap` (the
three forms, a `setcap` inside a comment), `parseUseraddDefaults`. `decodeACL` is reused.

**P-11 oracles.** On the lab as root and in the CI root job (`MUSTER_ORACLE=1`), every pair
runs in-process under its guard and writes nothing to the host's configuration: the units
pair compares five sampled in-scope units' `ExecStart` first token and `User` with `systemctl
show -p ExecStart,User,UnitFileState`; the keys pair is a **parser oracle** — it generates one
RSA-2048, one ed25519 and, where `ssh-keygen -t dsa` still works, one DSA key under
`t.TempDir()`, writes an `authorized_keys` there with options, hands the file's bytes to
`parseAuthorizedKeys` and compares type, bits and fingerprint with `ssh-keygen -l -f`, and
lets the temporary directory go — nothing under a declared path is touched and no key material
reaches a snapshot or an artifact; the lastlog pair compares `accounts.lastlog` for uid 0 and
the invoking user with `lastlog -u`, skipping only when `/usr/bin/lastlog` is absent (the init
containers), never on the runner; the capabilities pair runs the walk in-process with
`Include: ["/usr"]` and a five-minute budget and compares its `walk.capabilities` rows with
`getcap -r /usr` as a set of (path, canonical caps), skipping only when `/usr/sbin/getcap` is
absent. The sudoers pair only validates: `visudo -c -f /etc/sudoers` (it checks the whole
include chain) must exit 0, and the collector's `rules_unresolved` on the runner must be 0 —
a policy comparison would need `sudo -l`, which principle 5 rules out. The oracle file's rule
2 is reworded from "nothing is written" to "nothing is written to the host's configuration".

**P-12 CI and documents.** Root job, **before** "collect as root": `apt-get install -y
libcap2-bin` is already implied by the runner image (`setcap` is present; the step checks),
copy `/bin/true` to `/usr/local/bin/muster-cap-probe` (a walked path outside
`.github/walk-excludes`) and `setcap cap_net_raw+ep` on it; after the snapshot, assert it
appears in `walk.capabilities` with `reference: unpackaged` and `package_declared: false`; a
step with `if: always()` removes it. Assert `privilege.ld_so_preload` is an empty `ok` list,
`sudo.nopasswd_all` is `["runner"]` and `privilege.runtime_group_members` names `runner` in
`docker` (both expected of the runner image; the first run confirms and the step is corrected
if the image differs), `accounts.useradd.inactive` is -1; the "check the root snapshot" step
keeps its `test $code -ne 2` (exit 1 is expected: `sudo_nopasswd_all`,
`container_runtime_access` and `account_inactivity_lock` FAIL there truthfully). Non-root
job: the nine new denied keys equal the matrix row. Container jobs: `run.complete` true as
today; the plain images' `no-systemd.unsupported` row gains `units.*`. Forgotten artefacts,
named: `cmd/muster/controls_test.go`'s `ok: 104 controls` (three places);
`cmd/muster/e2e_test.go`'s exhaustive status maps and `testdata/full-pass.json` /
`full-fail.json` gain the eight (the deep-gated one reads MANUAL there, as
`package_files_unmodified` does); `hosts_test.go`'s EL9 length check (17); `examples/`
refreshed through `examples.yml` before merge; `docs/reference/coverage.md` regenerated.

Documents: this spec (EN/KO); the plan (EN); the main design gains **D31 — Root's power held
outside root is one family of controls, each judged as read and relaxed only through
`params` or a waiver.** Stage 3C-2a adds six such paths — an undeclared file capability, a
root service's executable a non-root user can rewrite, an `ld.so.preload` entry, a runtime
socket's group, passwordless `ALL` in sudoers, an account the inactivity policy does not
cover — and two key controls beside them; where muster could not read the deciding file the
control is MANUAL naming the path (C4), and where the host is as shipped the verdict is the
shipped state's, FAIL included. Reversal: a new root-equivalent path is a row in this family,
not a new rule. §10.2 is relabelled "3C-2a (merged): privilege — … then 3C-2b: …", and its
3C-2 list drops "root's `PATH`" (that is `root_home_and_path`) and says dormant accounts are
judged by policy with the history as evidence. CLAUDE.md gains `## Privilege (stage 3C-2a)`
(the sudoers depth and the unresolved → MANUAL rule, the walk's executables-only xattr pass and
its two `walk.skipped` reasons, the two capability declaration sources, lastlog's record size,
the `list-units` command); README/README.ko status and roadmap; CHANGELOG Controls (the eight,
the set version, the stock FAILs), Collectors (three extensions, three new, the `ReadDir`
option, the rpm query column), Tooling (D31, the matrix rows, the oracles);
`docs/reference/coverage.md`; `docs/reference/capability-matrix.json` (the `nonroot.denied`
and `no-systemd.unsupported` rows, the `useradd.inactive` note).

## 7. What is not a fact

Not collected, so the plan does not add them: the members of `sudo`/`wheel` (U-63's family
and `accounts.admin_group_members` already carry them); `sudo -l` output; the ACL of
non-executables (beyond the fixed paths that already have `acl_entries`); key bodies; `wtmp`
and `btmp`; `/var/log/auth.log` content; the target of a `.wants` link; the environment of a
unit; the `Host_Alias` definitions; `lastlog2.db` and `wtmp.db`; a per-release capability
reference list.

## 8. Parked

- ACL as a verdict, and ACLs on non-executables in the walk.
- The actual dormant-account list as a verdict; `lastlog2` / `wtmpdb` readers (sqlite).
- `NOPASSWD` on specific commands; the host field of a user specification; `Host_Alias`;
  `Defaults@host` and `Defaults!command` scopes; `sudoers` LDAP (`sudoers.ldap(5)`).
- `AuthorizedKeysFile` set to another path (and reading the effective value to decide whether
  `authorized_keys2` counts); `AuthorizedKeysCommand`; keys of ordinary users without `from=` /
  `restrict`; certificate authorities (`TrustedUserCAKeys`); decoding certificate keys.
- Services neither enabled nor active; `.socket`, `.timer` and `.path` units' executables;
  `ExecStart` arguments that name a writable script after the executable (an interpreter
  followed by a path); systemd's search path for a relative first token.
- Rootless podman's socket; `/etc/security/access.conf`; `pam_wheel`; `su` restrictions beyond
  U-45.
- 3C-2b: the process collector, processes running deleted executables, the exposure
  cross-check (only at full firewall confidence), the network sysctls, and the join of
  `packages.verify.modified` with the walk's package table.
