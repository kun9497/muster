# Stage 3B — kernel, boot and mount: the first checks beyond the guide

*English · [한국어](2026-09-18-stage3b-kernel-boot-mount-design.ko.md)*

This document is the design for plan 3B of muster: the first controls that are not KISA
items, on the areas the main design (`2026-09-02-muster-design.md`, §10.2 "Stage 3",
§11 "Checks that are not KISA items") reserved for the sub-project agreed on 2026-09-15
as "3B kernel/boot/mount" — kernel self-protection sysctls and the three-source core-dump
policy, the boot chain, mount options and separate partitions, swap encryption, and module
blacklists with built-in detection. It is the third stage-3 sub-project (3A the walk and
3F test hardening are merged). Decisions are numbered B-1 … B-12 and bind the plan. A
fresh review on 2026-09-18 (5 blocking, 10 medium, 6 low findings) is folded in; where
this version differs from the first draft, the difference is the review's. Every check here
is written from primary sources — kernel documentation, man pages, the distributions' own
documentation — in muster's own wording, carries no CIS recommendation number, and
reproduces no benchmark text (§11 of the main design, D04).

Three choices were made in brainstorming before the design and are recorded here because
they shape everything below: the new controls run by default and the report's summary is
split into "the guide" and "beyond the guide" (B-9); controls are grouped by the risk they
address rather than one per setting or one per area (B-5); and all four areas ship in one
plan.

## 1. Goal

Add nineteen controls of category `beyond` — seven on the kernel, three on the boot chain, six
on mounts and swap, three on kernel modules — fed by six new collectors, and let the report
say how much of the verdict comes from the KISA guide and how much from beyond it. After 3B
the control set is 87 controls (68 for the 67 items, unchanged, plus 19 beyond), the
default `check` reports both, and the exit code is what it always was.

Out of scope for 3B, named so the plan does not drift: network sysctls (`ip_forward`,
`rp_filter`, redirects, syncookies — they belong with the exposure cross-check, 3C); mount
options on `/var`, `/var/log` and `/var/log/audit` (the separate-partition control covers
their existence; options follow once the four option controls here have earned their
shape); squashfs (built into every Ubuntu kernel for snap, so a "disable it" control would
fail every Ubuntu host for no gain); the kernel command line (`lockdown=`, `init_on_alloc=`);
audit pipeline health (3C); profiles that select which scope runs (3D).

## 2. Facts and collectors (B-1 … B-4)

**B-1 — fixed vocabulary as leaves, discovered sets as lists.** An `each` clause whose
`where` selects no row passes with an observation (M-6). A setting whose *absence* is the
finding — a sysctl this kernel does not have, a bootloader file that is not there — must
therefore be a leaf with an envelope of its own, so `absent` reaches `absent_means`. A set
the host decides — which mounts exist, which swap devices, whether a module is loaded — is a
`list<record>`, and where the judged rows are a fixed candidate list (mount points, module
names) the collector emits **every candidate as a row**, present or not, so that `where`
never selects nothing and a waiver can name the row (`mount:/tmp`, `module:usb-storage`).

**B-2 — six collectors, all `Needs: none`, reads only, no commands.** Each declares its
paths; nothing here runs a program. Forty keys, all `since: 1`, `sensitivity: public`
(12 sysctl + 6 coredump + 13 boot + 5 mounts + 1 modules + 3 swap):

| Collector | Keys | Type | Source |
|---|---|---|---|
| `sysctl` | `kernel.sysctl.kptr_restrict`, `dmesg_restrict`, `yama_ptrace_scope`, `randomize_va_space`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `perf_event_paranoid`, `sysrq`, `protected_symlinks`, `protected_hardlinks`, `protected_fifos`, `protected_regular` | `setting<int>`, `default_on: effective` | runtime from `/proc/sys/<path>`; persisted from `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`, `/usr/local/lib/sysctl.d/*.conf`, `/usr/lib/sysctl.d/*.conf` and `/etc/sysctl.conf`, merged the way systemd-sysctl merges them (the files sorted by name across the directories, a name in an earlier directory masking the same name later; within that order the last assignment wins; a `-` prefix and the `kernel/yama/ptrace_scope` slash form as sysctl.d(5) describes); the stock `/etc/sysctl.d/99-sysctl.conf` is a symlink to `../sysctl.conf` and is modelled — `/etc/sysctl.conf` is read at that position and the winner cites the real file — rather than reported as an error (C4, the crypto-policies precedent); effective = runtime, with the persisted value and its file in the envelope |
| `coredump` | `coredump.core_pattern` | `string` | `/proc/sys/kernel/core_pattern` |
| | `coredump.suid_dumpable` | `setting<int>` | `fs.suid_dumpable`, same two homes as above |
| | `coredump.systemd.storage`, `coredump.systemd.process_size_max` | `string`, `int` | the main file `/etc/systemd/coredump.conf` (or `/usr/lib/systemd/coredump.conf` where systemd ≥ 254 ships it there) plus the drop-ins of `/etc/systemd/coredump.conf.d`, `/run/systemd/coredump.conf.d`, `/usr/local/lib/systemd/coredump.conf.d` and `/usr/lib/systemd/coredump.conf.d`, sorted by name across the directories with `/etc` masking by name; last assignment wins; no file at all is `absent` — the daemon's default, `external`, is the daemon's, never muster's |
| | `coredump.limits.hard_core`, `coredump.limits.sources` | `int`, `list<string>` | `* hard core` or `* - core` (the `-` type sets both limits, limits.conf(5)) in `/etc/security/limits.conf` + `/etc/security/limits.d/*.conf`, last wins, `unlimited` → -1; no line → `absent` |
| `boot` | `boot.firmware` | `string` | `uefi` when `/sys/firmware/efi` exists, else `bios` |
| | `boot.secure_boot` | `bool` | the byte at offset 4 (after the four-byte attribute word) of `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`; `absent` on BIOS and on UEFI without efivarfs or the variable (a firmware in SetupMode is not enforcing either; the description says so) |
| | `boot.grub_cfg.path` + the nine `writePermFacts` leaves under `boot.grub_cfg.` | `string` + perm leaves | the first of `/boot/grub/grub.cfg`, `/boot/grub2/grub.cfg`, `/boot/efi/EFI/<vendor>/grub.cfg` that exists (stat without following a symlink, C4); a stat refused with EACCES (EL's `/boot/grub2` is 0700) is `denied` on every leaf and never "the next candidate"; none → `absent`; the collector declares `/etc/group` for the group name |
| | `boot.grub_password_set` | `bool` | `set superusers` or `password_pbkdf2` in grub.cfg, `/boot/grub2/user.cfg` (0600 on EL), `/etc/grub.d/*`; an unreadable file among them is the read's status (C3) |
| `mounts` | `mounts.points` (`subject_kind: mount`) | `list<record>` | one row per candidate `/`, `/boot`, `/home`, `/tmp`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`, `/dev/shm` from `/proc/self/mountinfo` (3A's `parseMountinfo`, extended to keep the per-mount options of field 6 and the source): `target`, `separate` (a mount exactly at the target), `mounted_by` (the mount that contains it — the target itself when `separate`), `source`, `fstype`, `options` (`list<string>`); on a row that is not separate, `source`, `fstype` and `options` are those of `mounted_by`, so the row says what governs the path today. Persisted mounts (`/etc/fstab`, `.mount` units) are not read in 3B: no control judges them |
| | `mounts.tmp.separate`, `mounts.var_tmp.separate`, `mounts.dev_shm.separate`, `mounts.home.separate` | `bool` | the same fact as the row's `separate`, as a leaf so a mechanism can gate on it (B-1) |
| `modules` | `kernel.modules` (`subject_kind: module`) | `list<record>` | one row per candidate `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `usb-storage`, `dccp`, `sctp`, `rds`, `tipc`: `name`, `loaded` (`/proc/modules`), `builtin` (`/usr/lib/modules/<release>/modules.builtin`; `/lib/modules` only on a host that is not merged-`/usr` — on the supported ones `/lib` is a symlink and a no-follow read would be an error), `available` (`modules.dep`), `blacklisted` (a `blacklist <name>` line), `install_disabled` (`install <name> /bin/false` or `/bin/true`), `disabled` (derived: `!loaded && !builtin && (install_disabled || !available)`), `sources` (`list<string>`: the modprobe.d files that mention the module, plus the one sentinel `built into the kernel` when `builtin`); `modules.dep` names are matched with their `.ko`, `.ko.zst` and `.ko.xz` suffixes stripped; modprobe.d is `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/lib/modprobe.d`, `/usr/local/lib/modprobe.d`, `.conf` files only, masking by name as modprobe.d(5) says; a module name matches with `-` and `_` folded |
| `swap` | `swap.present` | `bool` | `/proc/swaps` has a row |
| | `swap.devices` | `list<record>` | `path`, `type` (`file` \| `partition`), `encrypted`, `backing` (the block device the judgment was made on) |
| | `swap.encrypted` | `bool` | true when every device is on dm-crypt: from the device (for a swap file, the source device of the mount that contains it) read the `/sys/block/<dev>` link — every entry there is a symlink — and, for a target under `devices/virtual/block`, follow `slaves/` down until a device whose `dm/uuid` begins `CRYPT-` (encrypted) or one whose link points at a physical device (not); a swap file whose containing mount's source is not a block-device node (`overlay` in a container, `/dev/root` on a cloud image) is `unsupported` naming the source, never an error — the stock "encrypted LVM" layout has swap on an `LVM-` volume whose slave is the `CRYPT-` device; `backing` names the device the decision was made on; zram with `/sys/block/zramN/backing_dev` = `none` is memory and counts as encrypted with `backing: zram`; no swap → `absent` |

**B-3 — `/proc/sys` is read directly, and the verdict reads the runtime side.** No `sysctl` binary, no command in the declaration. `default_on: effective` (= runtime) departs from the main design's §5.3, which names `both` for sysctl: a value the kernel compiles in — `dmesg_restrict` on Ubuntu, `protected_symlinks` everywhere — has no persisted line at all, and `both` would WARN "reverts on reboot" on every host for a setting that does not revert. The persisted side is evidence in the envelope; D29 records the departure.
`/proc/sys/kernel/yama/ptrace_scope` that does not exist (Yama not built) is `absent`
with the path, and so is `fs/protected_fifos` on a kernel before 4.19. A value that does
not parse as an integer is `error` naming the path and the bytes. Five of the files are
0600 on the lab's kernel (`net/core/bpf_jit_harden` and the four `fs/protected_*`), so
without root their runtime side is `denied`; the capability matrix's `nonroot` row lists
them and controls 3 and 4 are ERROR in a non-root run. The persisted half never
decides the leaf's effective value — a host whose runtime value drifted from its
`sysctl.d` is exactly what the two homes make visible.

**B-4 — modules are decided from files, not from `modprobe`.** `modules.builtin` says a
module cannot be blacklisted; `modules.dep` says whether one could be loaded; `/proc/modules`
says whether it is; modprobe.d says what an administrator did about it. A module the tree
does not know (`available` false, `builtin` false) is disabled by absence and passes. A
built-in module has `disabled` false whatever modprobe.d says — the formula's `!builtin`
term, because a built-in is never in `/proc/modules` and an `install … /bin/false` line
would otherwise pass it — and its `sources` entry says `built into the kernel`; the control fails the row and the remediation says a rebuild or a
waiver is the only way out. When the module tree (`/usr/lib/modules/<release>`) is missing (a container, a kernel
whose modules were removed) the whole `kernel.modules` envelope is `unsupported` with the
path — never a list of half-known rows.

## 3. Controls (B-5 … B-8)

**B-5 — grouped by risk, nineteen controls, all `category: beyond`, ids
`muster.beyond.<name>`, files under `controls/beyond/`.** `importance` is muster's own
rating from the primary source and the STIG severity where a rule exists (CAT I ≈ 상, II ≈
중, III ≈ 하), and every description says why in one sentence. `references.stig` cites the
index (`docs/reference/stig`) where a rule matches; `references.cis` stays empty — a number
copied from the benchmark's own mapping is not an independently derived one — and
`references.nist_800_53` follows the STIG index. `references.kisa` is absent, which the
coverage lint allows (it counts cited items only), and a new lint rule makes the two scopes
exclusive: `category: beyond` if and only if there is no `references.kisa`. `coverage.md`
gains a "Beyond the guide" table. The STIG index carries titles only, so a `references.stig`
entry is matched by title; grub.cfg has owner and group rules there but no mode rule — the
0600 of control 8 rests on grub-mkconfig's own umask 077, cited in the description.

Every one of the nineteen carries `applies_when: [{fact: env.container, op: eq, expected:
none}]`: inside a container these facts describe the host, which the container can neither
change nor answer for (§5).

| # | Control | Importance | Judgment |
|---|---|---|---|
| 1 | `kernel_pointer_exposure` | 중 | `kptr_restrict in [1, 2]`; `dmesg_restrict eq 1`; `absent_means: fail` |
| 2 | `ptrace_restriction` | 중 | `yama_ptrace_scope in [1, 2, 3]`; `perf_event_paranoid gte 2`; `absent_means: fail` (a kernel without Yama has no ptrace scope at all; the screening of §6.5 resolves the whole control on the first absent fact, so the other clause is then evidence only) |
| 3 | `unprivileged_bpf_restricted` | 하 | `unprivileged_bpf_disabled in [1, 2]`; `bpf_jit_harden in [1, 2]`; `absent_means: not_applicable` (a kernel built without the BPF syscall or the JIT has nothing to restrict). `bpf_jit_harden` defaults to 0 and no stock Ubuntu or EL9 sysctl.d sets it, so every stock host fails this one — a real KSPP weakness, kept separate and low so it does not colour control 2 |
| 4 | `aslr_and_link_protection` | 상 | `randomize_va_space eq 2`; `protected_symlinks eq 1`; `protected_hardlinks eq 1`; `protected_fifos in [1, 2]`; `protected_regular in [1, 2]`; `absent_means: fail` |
| 5 | `sysrq_restricted` | 중 | `sysrq in ${allowed_sysrq}`, default `[0]`; `absent_means: fail`; the description names the distribution defaults (Ubuntu 176, Debian 438, EL 16) and the parameter that admits one of them |
| 6 | `core_dump_policy` | 중, `partial` | four mechanisms on `coredump.core_pattern`, first match wins: (a) `matches ^\|.*systemd-coredump` → `coredump.systemd.storage eq none` and `coredump.systemd.process_size_max eq 0`; (b) `matches ^\|/bin/(false\|true)( \|$)` — the STIG's own remediation for a disabled pattern — → a check that holds by construction (`core_pattern matches ^\|/bin/`), PASS; (c) `not_matches ^\|` → `coredump.limits.hard_core eq 0`; (d) any other pipe (apport and the like) → one check that fails by construction, `core_pattern not_matches ^\|`, so a `partial` control reads WARN with the pattern as evidence — a mechanism with no checks would PASS. `absent_means: fail`: on a host without systemd and without a limits line, `absentMeans` returns FAIL even under `partial`, the one FAIL this control can give |
| 7 | `suid_dumpable_disabled` | 중 | `coredump.suid_dumpable eq 0`; `absent_means: fail` |
| 8 | `bootloader_config_permissions` | 상 | `boot.grub_cfg.mode in` the subsets of 0600 (`params.allowed_modes`), `uid eq 0`, `gid eq 0`; `absent_means: not_applicable` (no grub.cfg: another bootloader, or none); a `denied` stat (EL without root) is ERROR, never NOT_APPLICABLE |
| 9 | `bootloader_password` | 중 | `boot.grub_password_set eq true`; `absent_means: not_applicable`; a `denied` read (EL's 0600 grub.cfg without root) is ERROR, as every denied fact is |
| 10 | `secure_boot_enabled` | 중 | `applies_when` also `boot.firmware eq uefi`; `boot.secure_boot eq true`; `absent_means: manual` (UEFI without efivarfs or the variable cannot be read from here) |
| 11 | `separate_partitions` | 중, `partial` | `mounts.points` `each`, `subject: target`, `where target in ${required_separate}` (default `[/tmp, /var, /var/tmp, /var/log, /var/log/audit, /home]`), `require separate eq true`; `absent_means: not_applicable`; a partition is an installation-time decision, so WARN |
| 12 | `tmp_mount_options` | 중 | one mechanism `when mounts.tmp.separate eq true`: `mounts.points each where target eq /tmp require options contains nodev`, and the same for `nosuid`, `noexec`; no mechanism → NOT_APPLICABLE with the evaluator's reason ("no mechanism applies to this host"); the description says that such a host's finding is control 11 |
| 13 | `var_tmp_mount_options` | 중 | as 12 for `/var/tmp` |
| 14 | `dev_shm_mount_options` | 중 | as 12 for `/dev/shm`; every systemd host has it as a separate tmpfs mounted `nosuid,nodev` without `noexec`, so stock hosts fail this one |
| 15 | `home_mount_options` | 하 | as 12 for `/home`, `nodev` and `nosuid` only; EL9's default layout gives `/home` its own volume without either, so stock EL fails it |
| 16 | `swap_encrypted` | 중 | `swap.encrypted eq true`; `absent_means: not_applicable` (no swap) |
| 17 | `uncommon_filesystems_disabled` | 하 | `kernel.modules each`, `subject: name`, `where name in [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]`, `require disabled eq true`; `absent_means: fail` (17–19) |
| 18 | `usb_storage_disabled` | 중 | as 17 for `usb-storage` |
| 19 | `uncommon_network_protocols_disabled` | 중 | as 17 for `dccp`, `sctp`, `rds`, `tipc` |

**B-6 — the mount option controls gate on a leaf, not on a row.** `applies_when` cannot read
a row, and an `each` whose `where` finds no `/tmp` row would pass. The collector therefore
also writes `mounts.<point>.separate` as a leaf, the mechanism's `when` reads it, and a host
without a separate `/tmp` gets NOT_APPLICABLE; the description points at control 11, which
is where that host's finding is.

**B-7 — what "disabled" means for a module.** `install <name> /bin/false` (or `/bin/true`)
is what disables a module; `blacklist <name>` only stops automatic loading by alias and is
recorded, not credited. A loaded module is never disabled. A module the tree does not ship
is disabled by absence. A built-in one cannot be disabled, fails, and says so.

**B-8 — parameters.** `allowed_sysrq` (list<int>, `[0]`), `allowed_modes` on control 8
(`[0600, 0400, 0200, 0000]` as the existing permission controls spell "≤ 0600"),
`required_separate` (list<string>). Nothing else is tunable; a value that should be is a
profile's business (3D).

## 4. The report: two scopes (B-9)

**B-9 — beyond runs by default; the summary says which is which; the exit code does not
change.** Decision D29 in the main design.

- `summary` keeps every existing field with its existing meaning — totals over every
  control — so a consumer that parses it today reads the same numbers. It gains
  `scopes: {guide: {...}, beyond: {...}}`, each with `controls` (a count), `automatic` by
  severity, `manual_review` and `undecidable` — the same three parts as the top level.
  `beyond` is every control of `category: beyond`, `guide` every other control — one
  predicate, so nothing falls in both or in neither, and the lint rule of B-5 keeps the
  category and the KISA reference in step; the two sum to the top level, and a test says
  so. `scopes` is a struct with a fixed field order, never a map (D20).
- Rows sort by (scope, severity, id): the guide first, beyond after — a high beyond row
  therefore prints after a low guide row, which is the point of the split. Existing outputs
  have no beyond rows, so their bytes do not move and no golden is regenerated for the order.
  Result rows gain no field — `category` already says `beyond`.
- The table's summary block gains two lines, `KISA 2026 (68 controls): pass … fail … warn
  … manual … n/a … error …` and `beyond the guide (19 controls): …` (the counts are over the
  report's results), and one separator line `— beyond the guide —` before the first beyond
  row that is shown. The table golden changes by exactly
  those lines; the commit that regenerates it says so.
- Exit codes are the contract they were: any ERROR → 2, any FAIL → 1. A FAIL beyond the
  guide is a FAIL. README and CHANGELOG say this in one sentence each; a profile (3D) is
  what gives a KISA-only user the choice, not a flag added here.

## 5. Environments (B-10)

**B-10 — beyond controls are host controls.** Inside a container all nineteen are
NOT_APPLICABLE through `applies_when` on `env.container`: the kernel's sysctls are the
host's, `/boot` is not the container's, mounts and swap are the host's arrangement, and a
module list without `/lib/modules` is not a list. The collectors still run there and write
evidence: `kernel.modules` `unsupported` naming the missing module tree and `swap.encrypted`
`unsupported` naming the overlay source (the capability matrix's `container` row gains both
and the CI container matrix checks them), `boot.firmware`
whatever `/sys/firmware/efi` says (a container on a UEFI host sees it), `boot.grub_cfg.*`
`absent`, `mounts.points` from the container's own mountinfo.

Without root most reads here still work — efivars, `/proc/swaps`, `modprobe.d`, the
module tree and seven of the twelve `/proc/sys` files are world-readable — with two
exceptions. The five 0600 sysctl files of B-3 are `denied`, so controls 3 and 4 are ERROR
without root and the capability matrix's `nonroot` row names the five keys. On EL,
`/boot/grub2` is 0700, so even the stat of grub.cfg is refused: every `boot.grub_cfg.*` leaf
and `boot.grub_password_set` (which also reads the 0600 `user.cfg`) are `denied`, and
controls 8 and 9 are ERROR — never NOT_APPLICABLE, which is what falling through to the
next candidate would have produced. Ubuntu ships `/boot/grub` and grub.cfg readable, so the
runner's non-root job reads them; the capability matrix cannot express a per-distribution
`denied`, and the two controls' descriptions carry the sentence instead. The CI container
step runs one non-root `collect` inside the Rocky and Alma init images and asserts those
`denied` statuses, which is what proves the EL path.

Without systemd nothing changes: `coredump.systemd.*` is `absent` and such a host's
`core_pattern` is not the systemd pipe, so control 6 takes mechanism (c) or (d).

On a BIOS machine `boot.firmware` is `bios`, `boot.secure_boot` is `absent`, and control 10
is NOT_APPLICABLE; on UEFI with Secure Boot off it fails, which is the truth. `--deep` is
not needed by anything here: `mounts` reads mountinfo only.

The stock lab host (Ubuntu 22.04 on VMware, BIOS, a plain swap file, no separate `/tmp` or
`/var`, sysrq 176, `suid_dumpable` 2, apport's core pattern, the distribution's
blacklists only) is expected to read: 1 PASS, 2 PASS, 3 FAIL (`bpf_jit_harden` 0), 4 PASS,
5 FAIL (176), 6 WARN (apport's pipe), 7 FAIL (2), 8 FAIL (0644), 9 FAIL, 10 NOT_APPLICABLE,
11 WARN, 12–13 NOT_APPLICABLE, 14 FAIL (`/dev/shm` without `noexec`), 15 NOT_APPLICABLE,
16 FAIL, 17–19 FAIL. That table is
the plan's acceptance test for the collectors on a real host.

## 6. Tests, CI, documents (B-11, B-12)

**B-11 — the 3F gates are the gates.** Every control has `pass-`, `fail-` and `na-`
fixtures (container, BIOS, no swap, no separate mount) and the two `partial` controls their
WARN fixtures; the mutation test must stay at zero survivors, an equivalent mutant goes into
`_mutants.yaml` with its reason. One synthetic snapshot of the stock host of §5 is checked
end to end and pins all nineteen verdicts at once. Every new parser — sysctl.d, modprobe.d,
limits, coredump.conf, modules.builtin and modules.dep, `/proc/swaps`, the grub.cfg scan —
gets a `Fuzz<Name>` target with seeds, which the inventory test enforces. One new oracle
pair: `sysctl -n <key>` for the twelve keys against the runtime leaves, under
`MUSTER_ORACLE=1` in the existing oracle step. The collectors are unit-tested through
`memAccess` on the present / absent / denied / truncated paths, proven on the lab host
against the table of §5, and on a public Rocky 9 init container for the NOT_APPLICABLE
path; the runner's root job judges the real thing. The report's invariant (scopes sum to the
total) and the (scope, severity, id) order have tests; the JSON and table goldens are
regenerated once, for the summary lines.

**B-12 — documents and the two 3A hand-offs.** The main design gains D29 and a sentence in
§9 (`scopes`) and §10.2 (3B merged); README (both languages) the count sentence — "68
controls for the 67 items, and 19 beyond the guide" — and the roadmap line; CHANGELOG under
Controls (the nineteen, `controls/VERSION` → `kisa-unix-2026+2026.09.18`, the exit-code
sentence), Collectors (the six) and Tooling (`scopes`, the coverage table); CONTRIBUTING
(both languages) a short "controls beyond the guide" rule — primary sources, no CIS number,
an importance sentence, the container gate; CLAUDE.md one line; `coverage.md` regenerated.
The committed examples are refreshed from a manual `examples.yml` run on the pull request
(the control set changes, so the digest gate would otherwise skip their byte comparison).
From 3A: three of the four record-list facts without a `subject_kind` (`files.user_rhosts`,
`files.env_files`, `files.dev_nondevice`) get `file`, which changes their observations'
subjects from `item:` to `file:` — and with them the waiver keys that name those subjects,
which is a contract change: D29 carries it and CHANGELOG says a waiver written as
`muster.x#item:/path` must become `#file:/path`; the facts golden is regenerated.
`env.shell.root_path_entries` keeps `item:` — its subject is a position, and `dir:2` would
mislead; and U-23's description gains the sentence
about rootless container stores of accounts outside `/etc/passwd`.

## 7. Parked

- Network sysctls, `/var*` mount options, squashfs, the kernel command line: §1.
- A profile that runs the guide only, or beyond only: 3D. Until then the two scopes are
  visible and the exit code counts both.
- Persisted mounts (`/etc/fstab`, `.mount` units) as evidence and a "survives reboot" rule;
  `kernel.kexec_load_disabled` and the masking of `systemd-coredump.socket` (both in the
  STIG index) — natural next rows for the kernel and core-dump controls.
- `references.cis` for beyond controls: only if a mapping is derived from the primary source
  independently of the benchmark's own text; none is claimed here.
