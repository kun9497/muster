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
`shadow(5)`, `useradd(8)`, `lastlog(8)`, `sudoers(5)`, `capabilities(7)`, `systemd.service(5)`,
`systemd.unit(5)`, `ld.so(8)`, `sshd(8)`, `ssh-keygen(1)`, `acl(5)` — in muster's own wording,
carries no CIS recommendation number, and reproduces no benchmark text (§11 of the main
design, D04).

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
SSH key quality — fed by three extended collectors (`accounts`, `files_sudo`, `walk`) and three
new ones (`units`, `sshkeys`, `privilege`). After 3C-2a the control set is 104 controls (68 for
the 67 items, unchanged, plus 36 beyond), `controls/VERSION` is `kisa-unix-2026+2026.09.29`,
and `schema_version` is unchanged (keys and record fields are added, none changed; main
§5.7). One `tools/suidindex` extension records the file capabilities the public images
ship, so a dpkg host has a reference for them as it has for setuid bits.

Out of scope, named so the plan does not drift: everything of 3C-2b (above); root's `PATH`
— the guide control `root_home_and_path` already judges `.` and world-writable entries of
`env.shell.root_path_entries`, and the roadmap's "root's PATH" is that control; judging ACLs
(recorded only — no primary source ranks a general ACL); the actual dormant-account list as a
verdict (evidence only, §3 P-1); `NOPASSWD` on specific commands (evidence only); the
`ALL` command granted with a password (the stock `%wheel` / `%sudo` line); `Host_Alias` and
the host field of a user specification (every line counts as if for this host); services
that are neither enabled nor active; `AuthorizedKeysFile` set to a path other than the two
defaults; keys of ordinary users without `from=` or `restrict` (evidence only);
`/etc/security/access.conf`; the `lastlog2` and `wtmpdb` databases of Ubuntu 24.04 (sqlite;
their absence leaves the login history `absent`, never the verdict).

## 2. Principles carried from 3B and 3C-1

1. **The verdict reads the host as it is.** A stock cloud image reads FAIL on
   `sudo_nopasswd_all` (cloud-init writes `NOPASSWD:ALL` for its user), every stock release
   reads FAIL on `account_inactivity_lock` (`INACTIVE` is unset), and a docker host whose
   administrators sit in the `docker` group reads FAIL on `container_runtime_access`. Each
   description says so. The organisation's choice is recorded as a `params` value or a
   waiver, not assumed by the control (Q2).
2. **What muster did not see is MANUAL naming the path, never FAIL and never PASS** (C4). A
   sudoers alias muster cannot resolve, an `@include` outside the declaration, a home directory
   outside the declared patterns — each leaves its facts `absent` with the reason and the
   control MANUAL.
3. **Every leaf a clause judges is its own key** (C2). `where` takes one condition, so a
   compound condition ("login-capable and unset") is a collector-derived list, and the
   threshold the administrator tunes is a `params` value compared against a field the
   collector recorded (`inactive gt ${max_inactive_days}`).
4. **Same input, same bytes.** Every list is sorted (by `path`, `name` or `unit`), capped, with
   `truncated: true` on the key when the cap was hit. Key bodies never enter a snapshot: a key
   is its type, its bit length, its SHA256 fingerprint and its options.
5. **Nothing here runs a policy engine.** `sudo -l` evaluates the policy and logs the attempt,
   so muster parses the files; `visudo -c` only validates and is the oracle's tool, not the
   collector's. One new command, `systemctl list-units`, with fixed arguments.

## 3. Facts and collectors (P-1 … P-6)

New registry keys: 20 (3 `accounts.*`, 4 `sudo.*`, 3 `walk.*`, 3 `units.*`, 4 `ssh.*`, 3
`privilege.*`, the evidence-only lists included), every one `since: 1` under the unchanged
schema version. Sensitivity is `public` unless said otherwise.

### P-1 — `accounts` gains the inactivity policy and the login history

The shadow fields are already read: `accounts.users` rows carry `inactive` (field 7, -1 when
empty) and `expire` (field 8). Three leaves are added.

- `accounts.login_capable` — `list<record>` `{name, uid, inactive, expire, inactive_unset}`:
  the accounts the inactivity policy has to cover — not a system account (`system` false, or
  uid 0), shell listed in `/etc/shells`, password status not `locked`. `inactive_unset` is
  `inactive == -1`. This is the judged subset (principle 3); `accounts.users` stays whole.
  Sorted by `name`. When `/etc/shadow` could not be read the leaf carries the read's status
  (C3): the policy cannot be judged, and the non-root reading is `denied`.
- `accounts.useradd.inactive` — `int`: the `INACTIVE` value of `/etc/default/useradd`
  (`useradd -D`'s file), the number of days after a password expires before the account is
  disabled for new accounts; -1 when the line is absent, commented or the file does not exist
  (the reason says which — `useradd(8)` treats all three as "never"). A file that exists and
  cannot be read is the read's status (C3). EL ships `INACTIVE=-1` written out; Ubuntu ships
  the line commented; both read -1.
- `accounts.lastlog` — `list<record>` `{name, uid, last_login, line, host}`, evidence only,
  `sensitivity: internal`: `/var/log/lastlog` read with `ReadFileBinary` (a 292-byte record
  per uid — `int32 ll_time`, `char ll_line[32]`, `char ll_host[256]` — indexed by uid, so a
  sparse file is mostly holes and only the uids of `accounts.users` are decoded); `last_login`
  is RFC 3339 UTC or `""` when the record is zero ("never logged in"). Capped at 2000 rows.
  Absent on Ubuntu 24.04 (`shadow` 4.15 dropped `lastlog`; `lastlog2` keeps a sqlite database
  muster does not model) — `absent` with that reason, and the control does not read it. The
  file is 0664 `root:utmp`, so a non-root run reads it.

### P-2 — `files_sudo` gains the rules

The sudo reader already walks the chain — `/etc/sudoers`, the `@includedir` / `#includedir`
directory, an `@include` of a declared path — and stops with `absent` naming the path when
an include points outside its declaration or a drop-in is a symlink (3C-1, J-40). The same
walk now parses two more things from every line it reads (`sudoers(5)`): alias definitions
(`User_Alias`, `Runas_Alias`, `Cmnd_Alias`; `Host_Alias` is read and ignored) and user
specifications (`principal host = (runas) tags: commands`). Continuation lines (`\`) are
joined before parsing; `#include`/`#includedir` are directives, `#123` is a uid, `%#123` a
gid, `%group` a group, `+netgroup` a netgroup. Aliases are resolved by substitution to a depth
of eight; a cycle, an undefined alias or a netgroup leaves the rule `resolved: false`.

- `sudo.rules` — `list<record>` `{file, line, principal, kind, runas, nopasswd, commands,
  resolved}`, `kind` ∈ user | group | uid | gid | alias | netgroup (after resolution an alias
  expands to one row per member, `kind` that of the member; `alias` and `netgroup` remain only
  on unresolved rows); `nopasswd` true when the `NOPASSWD:` tag applies to the command list
  (tags apply to the commands after them until another tag; `PASSWD:` switches back);
  `commands` the resolved command list, `ALL` spelled as `ALL`. Evidence, `sensitivity:
  internal`, capped at 2000 rows, sorted by `file`, `line`.
- `sudo.nopasswd_all` — `list<string>`: the principals other than `root` (and `#0`) that
  receive `ALL` as a command under `NOPASSWD:`, whatever the runas — `ubuntu` from cloud-init's
  `90-cloud-init-users`, `%admins` from an alias that expands to `ALL`. Sorted, unique.
- `sudo.authenticate_disabled` — `bool`: an unscoped `Defaults !authenticate`, or a
  `Defaults:user` / `Defaults:%group` / `Defaults:User_Alias` line carrying `!authenticate`.
  `Defaults@host` and `Defaults!command` scopes are read but do not set it (they are neither
  unscoped nor about a principal); they are counted in `sudo.defaults.scoped_count` as
  today.
- `sudo.rules_unresolved` — `int`, the number of rules with `resolved: false`.

When `sudo.rules_unresolved` is not zero, `sudo.nopasswd_all` and `sudo.authenticate_disabled`
are `absent` ("N rules could not be resolved: ALIAS, +netgroup — the answer needs them") and
the control reads MANUAL (principle 2). When the chain was not fully read (3C-1's two cases),
all four leaves are `absent` naming the path, as `sudo.log.*` are. Without sudo installed,
`sudo.rules` is an empty list, `nopasswd_all` empty, `authenticate_disabled` false,
`rules_unresolved` 0 — the control is gated on `sudo.installed` anyway.

### P-3 — the walk gains file capabilities and ACLs

The walk visits every entry with one `statx`. For a **regular file with any execute bit**
(`mode & 0o111 != 0`) it now also opens the entry from its directory fd —
`openat(dirfd, name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`, so the open never follows a
link and never blocks — lists its extended attributes with `flistxattr`, reads
`security.capability` and `system.posix_acl_access` with `fgetxattr` when they are listed,
and closes it. Only executables are opened: a capability on a file nobody can execute is
inert (`capabilities(7)`), and opening every regular file would double the walk's system
calls where opening executables adds a tenth. `EACCES` on the open (a mode without owner
read, as root only under a restrictive LSM) records the path in `walk.skipped` with reason
`xattr_denied` and moves on; the walk never stops for an xattr.

- `walk.capabilities` — `list<record>` `{path, caps, effective, rootid, package,
  package_declared, declared_caps, reference}`: `caps` the sorted names of the permitted ∪
  inheritable set decoded from the VFS capability xattr (version 2 and version 3, whose
  `rootid` names the user namespace root the capability is valid for; a version muster does
  not know is a row with `caps: ["unknown"]`, never an error); `effective` the v2/v3 effective
  flag; the join columns as `walk.suid_sgid` has them — the owning package, whether that
  package declares exactly these capabilities, what it declares, and `reference` from the
  same vocabulary (`rpm`: the `%caps` column of `rpm -q --dump`; `list`: the release's
  reference file; `none`: no reference for this release). Rows whose `reference` is `none`
  go to `walk.capabilities_unverified` instead, as the setuid rows do, so the verdict is
  never taken on a file nobody could vouch for. Both capped by `listCaps` (2000), sorted by
  `path`.
- `walk.acl_grants` — `list<record>` `{path, entries}`, evidence only: the executables whose
  access ACL grants write or execute to a named user or group beyond what the mode grants
  (the mask applied, `acl(5)`); `entries` the entries in `getfacl` spelling (`user:alice:rwx`).
  Decoded by the POSIX ACL decoder the fixed-path `acl_entries` facts already use. Capped,
  sorted. No control reads it (§1).

The reference: `tools/suidindex` runs `getcap -r /` in every pinned image beside its
setuid `find` and writes a `caps` list (`{path, caps, package}`) into
`docs/reference/suid/<release>.json`; `-check` compares it like the rest of the file. The
embedded `suid` package exposes it to the join. rpm needs no reference: `%caps` is in the
package header. On the lab (Ubuntu 22.04) `getcap -r /usr` lists four files — `ping` and
`mtr-packet` with `cap_net_raw`, gstreamer's `gst-ptp-helper`, and snapd's `snap-confine`
with a set that includes `cap_sys_admin`; every one is declared by its package's `postinst`,
which is exactly what the reference has to know for the control to read PASS on a stock
host.

### P-4 — the `units` collector

`Reads`: `/etc/systemd/system/*.service`, `/run/systemd/system/*.service`,
`/usr/lib/systemd/system/*.service`, the same three with `*.service.d/*.conf`, and
`*.wants/*` and `*.requires/*` under the three (read with `Readlink` — a `.wants` entry is a
symlink whose name is the unit; the target is not followed). `Commands`: one, `systemctl
list-units --type=service --state=active --plain --no-legend`, declared as `services`
declares its `show` invocations. `Needs: none`.

A service is **in scope** when it is enabled (a `.wants`/`.requires` link names it in any of
the three trees) or active (`list-units` lists it). For each, the unit file is found in the
three trees in systemd's precedence (`/etc`, `/run`, `/usr/lib`; an `/etc` file that is a
symlink to `/dev/null` is a mask and the unit is out of scope; any other symlink at the unit
path is not followed — the row records `unit_file: symlink` and the unit reads `unresolved`),
its `.d/*.conf` drop-ins from all three trees are merged in systemd's order, and `[Service]`
is read for `User=` and the `Exec*=` directives (`ExecStart`, `ExecStartPre`,
`ExecStartPost`, `ExecCondition`, `ExecReload`, `ExecStop`, `ExecStopPost`). An empty
`ExecStart=` in a drop-in resets the list before it, as `systemd.service(5)` says. The first
token of each directive is the executable: prefix characters `@ - : + ! !!` are stripped
(`systemd.service(5)` "Command lines"), quotes removed, and a token that is not an absolute
path (allowed since systemd 239, resolved against systemd's own search path) is recorded as
`resolved: false` and not judged. A service whose `User=` is set to anything but `root` is
out of scope: its executables run without root's power.

- `units.root_services` — `list<record>` `{unit, enabled, active, user, files, exec}`:
  `files` the unit file and each drop-in read, `{path, mode, uid, gid}`; `exec` one row per
  `Exec*` first token, `{directive, path, exists, mode, uid, gid, group_writable,
  other_writable, resolved}` from `Stat` of the path (a symlink at the path is recorded
  `kind: symlink` and not followed; a missing file is `exists: false`). Evidence,
  `sensitivity: internal`, capped at 500 units, sorted by `unit`.
- `units.exec_writable` — `list<record>` `{unit, path, why}`: the judged subset — an
  executable owned by a uid other than 0, or group-writable, or other-writable (`why` ∈
  `owner`, `group_writable`, `other_writable`), and a unit file or drop-in with the same
  three properties (`why` prefixed `unit_file:`). Sorted by `unit`, `path`.
- `units.exec_unresolved` — `int`: rows with `resolved: false`, plus unit paths that were
  symlinks. Evidence.

Without systemd (`env.has_systemd` false, or `systemctl` cannot start, or it answers "System
has not been booted with systemd") the three leaves are `unsupported`; a `list-units` that
runs out of time is `timeout`, any other non-zero exit `error` naming the code (3C-1's
J-45 shape). A unit file that exists and cannot be read makes that unit's row carry the
read's status and the unit is counted neither writable nor clean — the control's `none` clause
sees the list, and the description says a denied unit file is a look.

### P-5 — the `sshkeys` collector

`Reads`: the home directories `files_home` reads (the declared patterns — `/home/*`, `/root`,
and the release-specific ones the accounts side already lists) with `/.ssh/authorized_keys`
and `/.ssh/authorized_keys2` — the two defaults of `AuthorizedKeysFile` in `sshd_config(5)`.
`Needs: none`. The users are `/etc/passwd`'s local accounts with a home path, as `files_home`
selects them; a home outside the declared patterns leaves that user's row `unfollowed` with the
path (C4).

- `ssh.authorized_keys` — `list<record>` `{user, uid, path, exists, mode, owner_uid, keys,
  unparsed}`, `sensitivity: internal`: one row per file that exists (and one `exists: false`
  row per user with no file, so "no keys" is a reading, not silence); `keys` a list of
  `{line, type, bits, fingerprint, options, restricted}` — `type` the key type word
  (`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-dss`, `sk-…`), `bits` the RSA modulus
  length for `ssh-rsa` and the curve size for ecdsa, 256 for ed25519, 1024 for `ssh-dss`,
  `fingerprint` `SHA256:` + base64 of the SHA-256 of the decoded key blob (what `ssh-keygen
  -l` prints), `options` the option words before the type (`from="…"`, `command="…"`,
  `restrict`, `no-pty`, …) with their quoted values intact, `restricted` true when `restrict`
  or `from=` is among them; `unparsed` the count of lines that are neither a comment, blank
  nor a parseable key (a broken base64 body, an unknown type). The key body itself is never
  stored. Capped at 200 keys per file and 500 rows.
- `ssh.root_key_count` — `int`: keys in root's two files. `absent` when root's home is
  outside the declaration or its files could not be read (C4/C3).
- `ssh.dsa_key_count` — `int`: `ssh-dss` keys across all files read.
- `ssh.rsa_keys` — `list<record>` `{user, path, line, bits, fingerprint}`: every `ssh-rsa`
  key, so a control judges `bits` against its parameter. Sorted by `user`, `path`, `line`.

A file muster could not read (another user's 0600 file in a non-root run) puts the read's
status on that row and on the three counts: an inventory with a hole is not an inventory, and
the non-root reading of the two key controls is ERROR naming the denial (as the audit detail
controls are in 3C-1).

### P-6 — the `privilege` collector

`Reads`: `/etc/ld.so.preload`, `/etc/group`, and `Stat` of the four runtime sockets.
`Needs: none`.

- `privilege.ld_so_preload` — `list<string>`: the non-comment, non-blank entries of
  `/etc/ld.so.preload` (`ld.so(8)`: one library per line, whitespace-separated). A missing
  file is an `ok` empty list — the normal state; a file that exists and cannot be read is the
  read's status (C3).
- `privilege.runtime_sockets` — `list<record>` `{path, exists, mode, uid, gid, group,
  group_writable, other_writable}`: `/run/docker.sock`, `/run/containerd/containerd.sock`,
  `/run/podman/podman.sock`, `/var/run/crio/crio.sock` — the control sockets of the four
  runtimes whose API is root (a client that can write to the socket can start a privileged
  container). A socket that does not exist is a row with `exists: false`. `group` from
  `/etc/group` by gid.
- `privilege.runtime_group_members` — `list<record>` `{group, member, uid, socket}`: for
  every existing socket that is group-writable, the members of its group with uid ≠ 0 —
  supplementary members from `/etc/group` and users whose primary gid is that group from
  `/etc/passwd` — one row per (group, member). Sorted by `group`, `member`. Empty when no socket
  exists or every group is empty (the lab's `docker` group is).

A non-root run reads all three: `ld.so.preload` is 0644, `/etc/group` is world-readable and
`/run` is stat-able.

## 4. Controls (P-7)

Eight controls, `category: beyond`, ids `muster.beyond.<name>`, every one gated on
`env.container eq none`; the mechanism/`absent_means` conventions of 3B and 3C-1 apply.
`references.stig` entries were looked up in the committed index: the inactivity rules
(RHEL-09-411050, UBTU-22-411035, UBTU-24-200260) and the reauthentication rules
(RHEL-09-432025, UBTU-22-432010, UBTU-24-300021); the other six controls cite no rule and
carry muster's own rating with the primary source named in the description. NIST is the
union of the cited rules' mappings (`AC-2(3)`, `IA-4`, `IA-11`, `SC-11`, `CM-6`) and `AC-6`
for the six uncited ones.

| id | importance | further gate | judgment | `absent_means` |
|---|---|---|---|---|
| `account_inactivity_lock` | 중 | — | `accounts.login_capable` `op: none, subject: name, where: {field: inactive_unset, op: eq, expected: true}`; `accounts.login_capable` `op: none, subject: name, where: {field: inactive, op: gt, expected: "${max_inactive_days}"}`; `accounts.useradd.inactive gte 0`; `accounts.useradd.inactive lte ${max_inactive_days}` | fail — shadow was read, the answer is there; stock hosts of all three releases read FAIL (`INACTIVE` unset), and the description says so |
| `sudo_nopasswd_all` | 상 | `sudo.installed eq true` | `sudo.nopasswd_all` `op: none, subject: value, where: {field: value, op: not_in, expected: "${allowed_nopasswd_principals}"}` (default `[]`); `sudo.authenticate_disabled eq false` | manual — the chain was not fully read, or rules could not be resolved: the missing lines could carry the tag; stock cloud images read FAIL through cloud-init's user |
| `file_capabilities_declared` | 상 | (deep gate: `walk.complete`) | `walk.capabilities` `op: none, subject: path, where: {field: package_declared, op: eq, expected: false}`; `walk.capabilities_unverified` is evidence | fail — the deep gate reads the completeness fact first; not run → MANUAL, incomplete → ERROR as for every walk control |
| `root_unit_exec_writable` | 상 | `env.has_systemd eq true` | `units.exec_writable` `op: none, subject: path` | manual — a unit file that could not be read (its executables are unknown) |
| `ld_so_preload_empty` | 상 | — | `privilege.ld_so_preload` `op: none, subject: value, where: {field: value, op: not_in, expected: "${allowed_preload}"}` (default `[]`) | fail — a missing file is an empty list |
| `container_runtime_access` | 상 | — | `privilege.runtime_sockets` `op: none, subject: path, where: {field: other_writable, op: eq, expected: true}`; `privilege.runtime_group_members` `op: none, subject: member, where: {field: member, op: not_in, expected: "${allowed_runtime_group_members}"}` (default `[]`) | fail — no socket is an empty list |
| `root_authorized_keys` | 중 | `sshd.options.permit_root_login ne no` (the `effective` home) | `ssh.root_key_count eq 0` | manual — root's home outside the declaration, or its files unreadable |
| `ssh_key_quality` | 중 | — | `ssh.dsa_key_count eq 0`; `ssh.rsa_keys` `op: none, subject: fingerprint, where: {field: bits, op: lt, expected: "${min_rsa_bits}"}` (default 2048) | manual — a file muster could not read leaves the counts `absent`; `unparsed` lines are evidence only and the description says the verdict covers parsed keys |

`params`: `max_inactive_days` (`int`, 35 — the cited rules' value; `shadow(5)` field 7),
`allowed_nopasswd_principals`, `allowed_preload`, `allowed_runtime_group_members`
(`list<string>`, `[]`), `min_rsa_bits` (`int`, 2048 — `sshd_config(5)`'s `RequiredRSASize`
defaults to 1024 and muster is stricter, saying so). A list parameter's fixture rule is
J-19's: one pass fixture per shipped element, and a `pass-allowlisted-*.json` per list
parameter showing the relaxation.

What the descriptions say, in muster's words: `account_inactivity_lock` — `useradd(8)`'s
`INACTIVE` and `shadow(5)`'s inactivity field lock an account a fixed number of days after
its password expires, the only mechanism the base system has for closing an account nobody
uses; the cited rules ask for 35 days; a stock host reads FAIL. `sudo_nopasswd_all` — a
principal that runs any command as any user without a password is root with an extra step;
the `%sudo`/`%wheel` lines with a password are the shipped state and pass; cloud-init's
`NOPASSWD:ALL` fails, and `allowed_nopasswd_principals` is where an image's service account
is recorded on purpose. `file_capabilities_declared` — `capabilities(7)`: a file capability
gives an executable a slice of root's power without a setuid bit, and one the package did not
declare is a setuid binary nobody knows about; the setuid control's twin. `root_unit_exec_writable`
— a service that runs as root executes whatever the path names at its next start; a file a
non-root user can rewrite, or a unit file they can edit, hands them that start. `ld_so_preload_empty`
— `ld.so(8)`: a library named here is loaded into every dynamically linked program on the
host, root's included; the file does not exist on a stock host and any entry is a review at
least, so the default allowlist is empty. `container_runtime_access` — the runtime's API
socket creates containers with any mount and any capability; a group that can write to it is
a root group, which the runtimes' own documentation says (docker's post-install notes call the
`docker` group root-equivalent). `root_authorized_keys` — a key in root's file is a root
login without a password prompt wherever `PermitRootLogin` allows keys (`prohibit-password`
allows exactly that); the control is NOT_APPLICABLE when root login is off. `ssh_key_quality`
— OpenSSH disabled DSA by default in 7.0 and removed it in 9.8, so an `ssh-dss` line is dead
weight at best and a downgrade target on an old server; an RSA key below 2048 bits is under
the size OpenSSH's own `ssh-keygen(1)` has generated by default since 2014.

## 5. Environments (P-8)

- **root.** Everything answers. One new command (`list-units`). The walk's xattr pass runs
  under `--deep` only and opens executables only; the plan's first task measures it on the
  lab (Ubuntu 22.04, a few hundred thousand entries) and the runner (600 000 entries, 15 m
  budget) and records the added time — the expectation is a tenth of the walk.
- **Non-root.** `accounts.login_capable` and `accounts.useradd.inactive` — `/etc/shadow` is
  root-only, so the first is `denied` (C3) and the control reads ERROR; `useradd` defaults are
  world-readable and answer. `accounts.lastlog` answers (0664). The four `sudo.*` rule leaves
  are `denied` (`/etc/sudoers` is 0440). `units.*` answer: unit files are world-readable,
  `list-units` needs no privilege, executables are stat-able; a drop-in under `/etc` that is
  root-only puts the read's status on that unit's row. `ssh.*`: other users' `.ssh` directories
  are 0700, so the rows and the three counts are `denied` and both key controls read ERROR
  naming the denial. `privilege.*` answer in full. The capability matrix's `nonroot.denied` row
  gains `accounts.login_capable`, the four `sudo.*` rule leaves, `ssh.authorized_keys`,
  `ssh.root_key_count`, `ssh.dsa_key_count`, `ssh.rsa_keys`; the non-root CI job proves the
  row.
- **Container.** Every beyond control is NOT_APPLICABLE by the gate. The collectors still have
  to complete so `run.complete` stays true: `units` reads `unsupported` (no systemd; R220
  counts it as answered), `privilege` finds no socket (empty lists), the file readers read
  files. The five container jobs' existing `run.complete` step covers it.
- **No systemd.** `units.*` `unsupported` → `root_unit_exec_writable` NOT_APPLICABLE through
  `env.has_systemd`. Nothing else depends on it.
- **Releases.** lastlog: present on Ubuntu 22.04 and EL9, absent on 24.04. dpkg capability
  references: generated for Ubuntu 22.04, 24.04 and Debian 12 from the pinned images (`caps`
  list); rpm needs none; a release without a reference reads `reference: none` and its rows
  are unverified evidence. `INACTIVE`: -1 on all three (EL writes it, Ubuntu comments it) —
  stock FAIL. sudoers: EL `%wheel ALL=(ALL) ALL`, Ubuntu `%sudo ALL=(ALL:ALL) ALL` — PASS;
  cloud-init's `90-cloud-init-users` — FAIL. OpenSSH: 22.04 ships 8.9, 24.04 9.6, EL9 8.7 — all
  refuse DSA by default, so a `ssh-dss` line the control flags is one the server already
  ignores; `RequiredRSASize` exists from 9.1 (24.04 only), default 1024.
- **Stock snapshots.** `controls/testdata/_hosts/ubuntu-22.04-stock.json` and
  `el9-stock.json` gain the new keys; `hosts_test.go` pins eight rows each:
  `account_inactivity_lock` FAIL, `sudo_nopasswd_all` PASS, `file_capabilities_declared` PASS
  (the four Ubuntu files declared; EL9 stock has `ping` with `cap_net_raw` declared by rpm),
  `root_unit_exec_writable` PASS, `ld_so_preload_empty` PASS, `container_runtime_access` PASS
  (no socket), `root_authorized_keys` PASS (gate holds — `prohibit-password` — and zero keys),
  `ssh_key_quality` PASS.

## 6. Tests, CI, documents (P-9 … P-12)

**P-9 fixtures and mutants.** Per control: `pass-*.json` per clause and per list-parameter
element, `fail-*.json` per clause, `na-container.json`, `manual-*.json` where the table says
manual (sudo: include outside the declaration, an unresolved alias; root keys: root's home
outside the declaration), `error-*.json` in the non-root shape the collector writes
(`denied` on the leaf the read failed). Every fixture `synthetic: true`, every key the control
names present. `_mutants.yaml` rows only for mutants no fixture can distinguish because of a
collector invariant, each checked against the collector's `absent` branches before it is
written (3C-1's X-1). Mutation test: zero survivors.

**P-10 parsers and fuzz targets.** Unit tests and a `Fuzz<Name>` with seeds for every
`[]byte` entry point (`TestEveryParserHasAFuzzTarget` enforces it): `parseSudoers` (alias
nesting to depth 8, a cycle, an undefined alias, `#include` vs `#uid`, continuation lines,
tags switching, `Defaults:` scopes), `parseLastlog` (292-byte alignment, a short tail, a
future time, a zero record), `parseAuthorizedKeys` (quoted options with commas, `restrict`,
RSA modulus length from the blob, ecdsa curve, an unknown type, broken base64 → `unparsed`,
a line longer than the cap), `parseUnitFile` (sections, `Exec*` prefixes, quoting, an empty
`ExecStart=` reset in a drop-in, `User=` in a drop-in), `decodeVfsCap` (v2, v3 with rootid,
truncated input, unknown version), `parseListUnits`. The POSIX ACL decoder is reused.

**P-11 oracles.** On the lab as root and in the CI root job (`MUSTER_ORACLE=1`): the units
pair compares five sampled in-scope units' `ExecStart` first token and `User` with `systemctl
show -p ExecStart,User,UnitFileState`; the keys pair generates one RSA-2048, one ed25519 and,
where `ssh-keygen` still can, one DSA key into a temporary home under `$RUNNER_TEMP` /
`/tmp`, writes an `authorized_keys` with options, compares type/bits/fingerprint with
`ssh-keygen -l -f`, and deletes the directory — no key material reaches a snapshot or an
artifact; the lastlog pair compares `accounts.lastlog` for uid 0 and the invoking user with
`lastlog -u` (skipped where `lastlog` is not installed — 24.04); the capabilities pair compares
the `/usr` rows of `walk.capabilities` with `getcap -r /usr` as a set of (path, caps) (deep run
only, the root job's existing snapshot). The sudoers pair only validates: `visudo -c -f` on
every file the collector read must exit 0, and the collector's `rules_unresolved` on the
runner must be 0 — a policy comparison would need `sudo -l`, which principle 5 rules out.

**P-12 CI and documents.** Root job: copy `/bin/true` to `$RUNNER_TEMP/muster-cap` under a
walked root, `setcap cap_net_raw+ep` on it, and assert the deep snapshot carries it in
`walk.capabilities` with `package_declared: false` (then remove it — after the snapshot, before
the seed step, as the sshd oracle drop-in is handled); assert `privilege.ld_so_preload` is an
empty `ok` list, `sudo.nopasswd_all` is `["runner"]` (the runner image's sudoers is expected to grant its
user `NOPASSWD:ALL` — a truthful FAIL the examples will show; the first run confirms the
expectation and the step is corrected if the image differs) and `accounts.useradd.inactive`
is -1. Non-root job: the nine new denied keys equal the matrix row. Container jobs: `run.complete`
true as today. `tools/suidindex` is extended and run once by the maintainer for the three dpkg
releases; the committed `caps` lists are what CI and the join read; `make suidindex-check`
compares.

Documents: this spec (EN/KO); the plan (EN); the main design gains **D31** ("Root's power
outside root is one family of controls: an undeclared file capability, a root service's
executable a non-root user can rewrite, an `ld.so.preload` entry, a runtime socket's group,
passwordless `ALL` in sudoers, and an account the inactivity policy does not cover — each judged
as read, relaxed only through `params` or a waiver; what muster could not read is MANUAL naming
the path. Reversal: a new root-equivalent path is a row in this family, not a new rule.") and
§10.2 relabelled "3C-2a (merged) … then 3C-2b"; CLAUDE.md gains `## Privilege (stage 3C-2a)`
(the sudoers depth and the unresolved → MANUAL rule, the walk's executables-only xattr pass,
lastlog2 unmodelled, the `list-units` command); README/README.ko status and roadmap; CHANGELOG
Controls (the eight, the set version, the stock FAILs), Collectors (three extensions, three new,
the reference `caps`), Tooling (`suidindex` `caps`, D31, the matrix row, the oracles);
`docs/reference/coverage.md` regenerated; `docs/reference/capability-matrix.json`;
`docs/reference/suid/*.json`.

## 7. What is not a fact

Not collected, so the plan does not add them: the members of `sudo`/`wheel` (U-63's family
and `accounts.admin_group_members` already carry them); `sudo -l` output; the ACL of
non-executables (beyond the fixed paths that already have `acl_entries`); key bodies; `wtmp`
and `btmp`; `/var/log/auth.log` content; the target of a `.wants` link; the environment of a
unit; the `Host_Alias` definitions; `lastlog2.db` and `wtmp.db`.

## 8. Parked

- ACL as a verdict, and ACLs on non-executables in the walk.
- The actual dormant-account list as a verdict; `lastlog2` / `wtmpdb` readers (sqlite).
- `NOPASSWD` on specific commands; the host field of a user specification; `Host_Alias`;
  `Defaults!command` scopes; `sudoers` LDAP (`sudoers.ldap(5)`).
- `AuthorizedKeysFile` set to another path; `AuthorizedKeysCommand`; keys of ordinary users
  without `from=` / `restrict`; certificate authorities (`TrustedUserCAKeys`).
- Services neither enabled nor active; `.socket`, `.timer` and `.path` units' executables;
  `ExecStart` arguments that name a writable script after the executable (an interpreter
  followed by a path).
- `/etc/security/access.conf`; `pam_wheel`; `su` restrictions beyond U-45.
- 3C-2b: the process collector, processes running deleted executables, the exposure
  cross-check (only at full firewall confidence), the network sysctls, and the join of
  `packages.verify.modified` with the walk's package table.
