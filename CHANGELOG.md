# Changelog

All notable changes to muster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The binary follows
semver; the embedded control set has its own version (`controls/VERSION`,
reported as `controls_version` in every result). A change that alters a
verdict on an existing snapshot is at least a minor release and appears under
**Controls** (design decision D16). This file is English-only.

## [Unreleased]

### Controls

Control set `kisa-unix-2026+2026.09.29` (was `+2026.09.23`). Eight more controls
beyond the KISA guide (36 in all), written from `shadow(5)`, `useradd(8)`,
`sudoers(5)`, `capabilities(7)`, `systemd.service(5)`, `ld.so(8)`, `sshd(8)` and
`ssh-keygen(1)` in muster's own words: an inactivity policy over every
interactive account (root and password-locked accounts included), passwordless
`ALL` in sudoers with aliases resolved, file capabilities the owning package did
not declare, root services whose executables or their directories a non-root user
can write, `ld.so.preload`, container-runtime sockets and the
groups, owners and ACL entries that can reach them, root's authorized keys where
`PermitRootLogin` accepts keys, and DSA or short RSA keys. Every one is
NOT_APPLICABLE inside a container. Read as shipped: every stock release fails the
inactivity lock (`INACTIVE` -1), a cloud image and the GitHub runner fail
passwordless sudo, and the runner fails runtime access (`runner` in `docker`);
what muster could not read — an include or a home outside its declaration, a
linked or unreadable unit file, an executable outside the declared set, an
unresolved sudoers alias — reads MANUAL naming the path. The 68 controls for the
67 items are unchanged.

Control set `kisa-unix-2026+2026.09.23` (was `+2026.09.18`). Nine more controls
beyond the KISA guide (28 in all), written from `auditd.conf(5)`, `auditctl(8)`,
`augenrules(8)`, `aide(1)`, `sudoers(5)`, `rpm(8)` and `dpkg(1)` in muster's own
words: the audit daemon active, its rules loaded and persisted, its
configuration immutable, its disk-full and space-left actions, the permissions
of its log file and directory; system logs leaving the host (rsyslog to a
non-loopback target, or `systemd-journal-upload`); sudo's own log kept; a
file-integrity tool (AIDE) installed with a database and a schedule — a host
running only another tool reads MANUAL naming it; and packaged files
unmodified (`rpm -Va` / `dpkg --verify` under `--deep`, category `beyond`,
importance 상). Every one is NOT_APPLICABLE inside a container. A stock host
that installs auditd and nothing else reads three FAILs — rules, immutability
and the shipped `suspend` actions — which is the truth of the shipped files.
The 68 controls for the 67 items are unchanged.

- `muster.beyond.audit_log_permissions` allows a 0640 log file because
  Ubuntu's `log_group = adm` ships one; the RHEL rule it cites asks 0600.
- `muster.beyond.package_files_unmodified` reads MANUAL on a run without
  `--deep` ("run collect --deep without --no-verify"), ERROR(`verify_incomplete`)
  when verification did not finish, and NOT_APPLICABLE on a host with no
  package database.

Control set `kisa-unix-2026+2026.09.18` (was `+2026.09.16`). Nineteen controls
beyond the KISA guide, category `beyond` (`muster.beyond.*`), written from
primary sources — kernel documentation, man pages, the distributions' own
documentation — with no CIS recommendation number: kernel pointer exposure,
ptrace restriction, unprivileged BPF, ASLR and link protection, SysRq, the
core-dump policy from its three sources, `suid_dumpable`; the bootloader
file's permissions and password and Secure Boot; separate partitions and the
`nodev`/`nosuid`/`noexec` options of `/tmp`, `/var/tmp`, `/dev/shm` and
`/home`; swap encryption; and the uncommon filesystem, USB-storage and
network-protocol modules. Every one is NOT_APPLICABLE inside a container.
The 68 controls for the 67 items are unchanged. The exit code is the contract
it was: a FAIL beyond the guide is a FAIL, until a profile lets a KISA-only
user choose (D29). The report's summary gains `scopes` — the same three parts
for the guide and for beyond it — and the table two lines and a separator;
every existing summary field keeps its meaning.

- `muster.beyond.core_dump_policy` reports a host whose systemd coredump file
  sets nothing for review rather than judging it: systemd's own default stores
  dumps, and muster does not substitute the daemon's default.
- `muster.beyond.bootloader_password` counts a bootloader password only where a
  literal `grub.pbkdf2.` hash is present (grub.cfg, `/boot/grub2/user.cfg` or
  `/etc/grub.d/*`); EL's generated grub.cfg carries the template's
  `set superusers` line on every host, so that token alone proves nothing.
- Waiver keys: the observations of `files.user_rhosts`, `files.env_files` and
  `files.dev_nondevice` now carry the subject kind `file:` instead of `item:`
  (the registry names it), so a waiver written as `#item:/path` must become
  `#file:/path` (D29). `env.shell.root_path_entries` keeps `item:`; its
  subject is a position.
- U-23's description says that rootless container stores of accounts absent
  from `/etc/passwd` are walked too (description only).

Control set `kisa-unix-2026+2026.09.16` (was `+2026.09.09`). All 67 KISA 2026
Unix items are enrolled: auto 57, partial 7, manual 4 with evidence attached.
`docs/reference/kisa/kisa_deferred.json` is now empty — the three items that
waited for the deep filesystem walk are in. Every control below reads
`walk.*`, so it is MANUAL ("run collect --deep") on a snapshot collected
without `--deep`, and NOT_APPLICABLE on a container whose root layer the walk
does not enter.

Verdict-affecting changes in this version:

- `muster.file.unowned_files` (U-15, auto) fails on any entry whose uid or
  gid resolves to no local account or group. A host whose passwd database
  names a remote source, or whose nsswitch line uses NIS compat, is MANUAL
  with both nsswitch facts as evidence rather than judged on ids it cannot
  see.
- `muster.file.suid_sgid` (U-23, auto) fails on a setuid or setgid file no
  package owns, on one whose package owns it without that bit, on any path
  named in the new `forbidden_suid` parameter (empty by default — muster
  ships no list), and on a directory others may write into that has no
  sticky bit.
- `muster.file.suid_sgid_unverified` (U-23, partial) is WARN for every
  packaged setuid or setgid file whose declared mode could not be decided
  (`unlisted`, `version_mismatch`, `postinst` or `none`); the row names the
  package and the reason. These used to be invisible.
- `muster.file.hidden_entries` (U-33, partial) is WARN for every hidden file
  or directory outside the home exemption that no package declares.
  Allowlisted entries are recorded and not judged.
- The `none` clauses of ten existing controls name their observations by the
  element's `path` instead of its index in the collector's list
  (`file:/etc/crontab`, not `file:0`; `position` on the root PATH entries), so
  a waiver naming a subject must now use the path.

Control set `kisa-unix-2026+2026.09.09` (was `+2026.09.02`) enrolled 64 of the
67 items: auto 55, partial 5, manual 4. Its verdict-affecting changes, still
unreleased, were:

- A record element that lacks the field a `where`/`require` sub-clause names
  now fails that clause with a reason naming the element and the field (spec
  §5.7) and is listed as `unjudged` in the clause's evidence. It used to be
  `ERROR(internal_error)`. `present`/`absent` keep their meaning.
- An `each … where` whose `expected` is a `${param}` reference and that
  selects no element of a non-empty list now ends MANUAL, naming the
  parameter — decided once, after every clause has been evaluated, so a
  failing or degraded clause elsewhere in the control still wins. It used to
  pass vacuously, so a mistyped override could not be told from a clean host.
  A literal `where` that selects nothing still passes and records an
  observation saying so.
- Collection evidence names what was judged: `N elements; K selected;
  failing: …` / `matching: …` / `unjudged: …` (five subjects, then `+K more`)
  instead of `N elements`.
- `muster.file.ip_port_restriction` (U-28): the tcp_wrappers mechanism is
  chosen only when `libwrap` is installed (`files.libwrap_present`), and a
  host with no firewall backend must have both `libwrap` and an `ALL: ALL`
  deny in `/etc/hosts.deny`. A deny-all on a host without `libwrap` (RHEL 8
  and later ship none) used to pass.
- `automation: manual` controls carry an `evidence:` list; the MANUAL row of
  U-45, U-46, U-47 and U-49 now shows the facts the reviewer needs instead of
  only the gate facts.
- `muster.file.home_dir_exists` / `home_dir_permissions` (U-31/U-32),
  `muster.file.rhosts_forbidden` (U-27) and `muster.file.env_file_permissions`
  (U-24): an interactive account whose home lies outside the declared home
  roots (`/home/*`, `/home/*/*`, `/root`) makes the whole leaf `absent`
  naming the account, so the control is MANUAL rather than the false FAIL
  (U-31/U-32) or the silent PASS (U-24/U-27) it used to be. The dotfiles of a
  home one level down (`/home/<group>/<user>`) are now examined. A `.rhosts`
  or `.shosts` that exists but cannot be read makes `files.user_rhosts`
  `denied` (U-27 is ERROR) instead of being skipped.
- `muster.service.login_banner` (U-62): an sshd `Banner` outside the
  collector's declaration is recorded as `absent` and the control reads
  MANUAL; it used to be ERROR and made the run partial.
- `muster.account.password_policy` (U-02): an integer pwquality setting whose
  final value does not parse (libpwquality rejects such a configuration)
  makes that leaf `absent` naming the key and value; the control reads FAIL
  instead of silently keeping whatever value was applied before it (the
  compiled-in default when nothing had set the key).

Stage-2 history of the set (all merged to `main` before this version was cut;
every plan is under `docs/superpowers/plans/`):

| Plan | Merged | Items enrolled after the plan |
|---|---|---|
| 2A foundations (permission-fact template, coverage table, STIG/NIST index) | PR #1 | 8 |
| 2B accounts | PR #2 | 18 |
| 2C PAM | PR #3 | 20 |
| 2D sshd completion and banners | PR #4 | 22 |
| 2E home directories and the shell environment | PR #5 | 29 |
| 2F system files, startup and cron | PR #6 | 35 |
| 2G services and super-servers | PR #7 | 44 |
| 2H firewall | PR #8 | 45 |
| 2I logging and time synchronisation | PR #9 | 47 |
| 2J NFS, SNMP and patch hygiene | PR #10 | 52 |
| 2L FTP, mail and DNS (the first `manual` controls) | PR #11 | 64 |
| 2M the coverage and reference gate | this version | 64 |

U-01 `root_remote_login` no longer fails a host whose `PermitRootLogin` is the
compiled default or `prohibit-password`: `sshd -T` and `-G` print that value in
the pre-7.0 spelling `without-password`, which the control did not list, so
every stock release read FAIL. The collector now stores both spellings as
`prohibit-password` (they are one setting to sshd), so a host collected with
this release reads PASS; a snapshot taken by an earlier release still carries
`without-password` and still reads FAIL until it is collected again — the
verdict of a re-collected host changes, so this is a minor release (D16). On
the same host shape, U-12 `session_timeout` reads FAIL instead of ERROR and
U-62 `login_banner` MANUAL instead of ERROR when sshd does not answer and the
configuration walk stopped at an `Include` outside the declaration (below).

### Collectors

- `ReadDir` takes an option that reads the `security.capability` and
  `system.posix_acl_access` attributes of every executable it lists, from the
  open directory fd after an identity check; the walk uses it (licensed by its
  `Walk` declaration alone) and never stops for an attribute it cannot read
  (`walk.skipped` gains `xattr_denied`, `xattr_undecoded` and `xattr_error`). `walk.capabilities`
  joins each capability with the package's own declaration — rpm's `%{FILECAPS}`
  (the rpm query's fifth field) or the dpkg `postinst` `setcap` call, in its
  literal, variable, `dpkg-divert --truename` and `- <path> < <file>` forms — and
  renders the canonical `cap_to_text(3)` text with 41 named bits, accepting both
  libcap spellings; a `rootid ≠ 0` attribute is never declared. `walk.acl_grants`
  records executables whose ACL widens their mode.
- `accounts` derives `login_capable` (every interactive non-system account with
  its inactivity field), reads `/etc/default/useradd`'s `INACTIVE` as `useradd`
  does (`strtol` base 0, values below -1 rejected, the last line wins) and decodes
  `/var/log/lastlog` by architecture (292- or 296-byte records) as evidence.
- The sudo reader parses user specifications with `User_Alias`, `Runas_Alias` and
  `Cmnd_Alias` resolved to depth 8 under member and row budgets, tags and runas
  inherited along a command list and reset at `:`, negation kept, digests kept
  with their command, a comment ending at its newline even inside a
  continuation, and `#<digits>` read as a uid; `sudo.nopasswd_all` and
  `sudo.authenticate_disabled` (unscoped, `Defaults:` and `Defaults>` scopes) are
  `absent` when a rule could not be resolved.
- `units` (new) reads the enabled or active `.service` units from systemd's
  ten-directory search path with one fixed `systemctl list-units`, merges
  drop-ins by name and precedence, splits `Exec*` lines on a lone `;`, follows a
  symlinked executable one hop and judges the executable's directory too; an
  executable outside the declared set, a linked or missing unit file or an
  unreadable one leaves `units.exec_writable` `absent`.
- `sshkeys` (new) inventories `authorized_keys` and `authorized_keys2` of every
  local account without their bodies — type, bits (RSA by modulus length), SHA256
  fingerprint, options — counts root's, DSA and RSA keys, and reads `rsa-sha2-*`
  words as the RSA keys they carry; a symlinked key file or a home outside the
  declaration leaves the counts `absent`.
- `privilege` (new) reads `/etc/ld.so.preload` as glibc's loader does and the
  four container runtimes' control sockets at their `/run` paths with their
  group, owner and ACL, plus the accounts that hold a writable socket's group; a
  socket's xattrs are read through an `O_PATH` fd's `/proc/self/fd` entry, since
  a socket cannot be opened for reading.
- `audit` reads the audit daemon's rules from `/etc/audit/rules.d/*.rules` in
  the `ls -v` order augenrules loads them (falling back to `/etc/audit/audit.rules`
  when the directory is missing, as augenrules does), the last `-e` line, the
  seven disk-action keys of `auditd.conf`, and the nine permission leaves of the
  log file and its directory; the running side comes from `auditctl -l` and
  `auditctl -s`, classified by their exit codes and messages — exit 4 ("You must
  be root") is `denied` without root and `unsupported` for a root without
  CAP_AUDIT_CONTROL, exit 255 ("Operation not permitted") is `unsupported`
  because no pid namespace but the initial one reaches the kernel. 34 keys.
- `fim` models AIDE (`fim.tool` `aide`/`none`, or `absent` naming any other tool
  found), its configuration and database path (`@@define` macros resolved),
  and whether a check is armed: a `cron.daily` script with the execute bit,
  `CRON_DAILY_RUN` not set to another value and not the 24.04 systemd shim, a
  cron.d/crontab line, or a timer with a next elapse in `systemctl list-timers`.
- `pkgverify` runs `rpm -Va` or `dpkg --verify` under `--deep` as root, within
  `--verify-timeout`, and records the seven noise rules it applied with their
  counts (`config`, `doc`, `dpkg_excluded`, `ghost`, `mtime_only`, `unverifiable`,
  `unchanged`); a database that cannot be read is `error`, never an unmodified
  PASS. 7 keys.
- `logging` gains `logging.journal_upload.url` (the four systemd directories)
  and `logging.rsyslog.forwards_remote` / `remote_targets` (a loopback target is
  a relay, not forwarding; an incomplete rsyslog parse reads `absent`); the
  sudo reader gains `sudo.log.syslog`, `sudo.log.logfile` and
  `sudo.defaults.scoped_count`; the `services` table gains `auditd` and
  `journal_upload`.

- Six read-only collectors for the checks beyond the guide, none of which
  runs a command: `sysctl` (twelve kernel self-protection settings as two-home
  facts — the running value from `/proc/sys`, the persisted one merged from
  the sysctl.d directories the way systemd-sysctl merges them; the verdict
  reads the running value), `coredump` (`core_pattern`, `suid_dumpable`,
  systemd's `Storage=`/`ProcessSizeMax=` across its drop-ins, the `* hard
  core` limit), `boot` (firmware kind, Secure Boot from efivars, the
  bootloader file's nine permission leaves, the password hash), `mounts`
  (the nine candidate mount points, each row saying which mount governs it),
  `swap` (devices from `/proc/swaps`; encryption decided through the sysfs
  block links and the dm `slaves/` chain), `modules` (the eleven candidate
  modules with what the module tree under `/usr/lib/modules`, `/proc/modules`
  and modprobe.d say about each). Forty registry keys, `schema_version`
  unchanged.
- A symlink to `/dev/null` in a `.d` directory muster reads (sysctl.d,
  coredump.conf.d, modprobe.d, grub.d) is the documented way to disable a
  vendor file: it contributes nothing and is never an error; any other symlink
  there is that file's error.
- A swap file whose containing mount has no block-device node (an overlay
  root, `/dev/root`) makes `swap.encrypted` `unsupported`, never an error; a
  module tree that is missing makes `kernel.modules` `unsupported`.

- New `walk` collector: `collect --deep` (root only) walks the host's local
  filesystems once — `--walk-budget`, `--walk-max-entries`, `--walk-exclude`
  and `--walk-include` bound it — and writes nine keys: `walk.suid_sgid`,
  `walk.suid_sgid_unverified`, `walk.world_writable`, `walk.sticky_missing`,
  `walk.unowned`, `walk.hidden`, `walk.skipped`, `walk.stats` and
  `walk.complete`. Every candidate is joined to rpm's file table or to dpkg's
  file lists plus the release's reference list of declared modes, so a finding
  says which package owns the path and whether the package declares the bit.
  Without `--deep` no `walk.*` key is written at all; without root
  `walk.complete` is `denied`; a container layer the walk does not enter
  leaves every list `unsupported`.
- `Glob` over a declared directory the process may not read now reports the
  denial, and every collector that lists a declared directory reports it as
  `denied` (it used to be swallowed as an empty listing, or filed as
  `error`/`unsupported` at a few sites): `cron.files`/`cron.dirs` read
  `denied` without root, among others. The firewall presence probe keeps
  ignoring it, because the ruleset capture reports the same directory, and
  the rsyslog include listing follows the logging collector's parse-incomplete
  rule (absent, MANUAL). A non-root run that meets such a directory is now
  partial.
- Convention C4: a path muster declined to read is `absent` with the path in
  the reason, never `error` (an sshd `Banner` outside the declaration; an
  interactive home outside the home roots); a declared file that exists but
  cannot be read is the read's status; an administrator's symlink at a
  declared main configuration file stays `error` by design.
- `run.redaction.redacted_fields` lists the `sensitivity: secret` keys the
  run stored in reduced form.
- pwquality drop-ins merge through the shared drop-in helper
  (`mergeDropinsWith`), keeping the bare-word flags libpwquality accepts.
- Extended-attribute reads allocate exactly the value's size.
- The apt periodic parser folds the case of `APT::Periodic::Unattended-Upgrade`
  without changing the line's byte length; an `apt.conf` fragment carrying a
  byte that is not UTF-8 before the key used to make the patch collector
  panic. Found by the new fuzz target; the input is committed as its seed.
- The nftables ruleset parser skips a line that is only whitespace inside a
  chain instead of indexing its first word; a form feed there used to panic
  the firewall collector. Found by the first sixty-second run of the nightly
  fuzz workflow; the input is committed as its seed.
- The mountinfo parser bounds a mount's source field like every source a fact
  carries (256 bytes, cut on a rune boundary, the marker only when cut); a
  FUSE or network source longer than that used to reach the snapshot whole.
  Found by the nightly fuzz workflow; the input is committed as its seed.

### Tooling

- D31 (root's power outside root is one family of controls); the capability
  matrix's `nonroot.denied` row gains eight keys, `no-systemd.unsupported` the
  three `units.*` keys and `container.unsupported` the two new walk lists; five
  oracle pairs (units against `systemctl show`, the key parser against
  `ssh-keygen -l`, lastlog against `lastlog -u`, the walk's capabilities against
  `getcap -r` over the six executable directories of `/usr`, sudoers validated by `visudo -c`); the CI root job plants a
  `setcap` probe under `/usr/local/bin` before the collect and expects it read as
  unpackaged.
- `collect --verify-timeout <dur>` (default 30m) and `--no-verify` (both need
  `--deep`); a `--deep` run's default `--timeout` is now walk budget +
  verify timeout + 5m. A pre-existing `collect --deep --timeout <30m` is
  refused naming `--verify-timeout` — pass `--no-verify` or a smaller
  `--verify-timeout`.
- The evaluator's walk gate is a table of deep families (D30): `walk.*` and
  `packages.verify.*` controls read MANUAL / ERROR(`walk_incomplete` |
  `verify_incomplete`) / NOT_APPLICABLE from their completeness fact.
  `verify_incomplete` joins the reason-code vocabulary.
- Two oracle pairs (`rpm -Va`/`dpkg --verify` against the verify parser;
  `auditctl -s`/`-l` against the runtime reader), the capability matrix's
  non-root rows for the 28 audit keys, `packages.verify.complete` and the sudo
  log keys, a second stock-host snapshot (EL9), and CI proofs that install
  auditd and AIDE on the runner VM and in the EL init containers.

- `summary.scopes` in the JSON report and two summary lines plus a separator
  in the table split every verdict into the guide and beyond it; rows sort by
  scope first. `controls lint` keeps `category: beyond` and the absence of a
  KISA reference in step (`beyond_scope`), `controls new muster.beyond.<name>
  --importance <상|중|하>` scaffolds such a control, and `coverage.md` gains a
  "Beyond the guide" table.
- A synthetic stock-host snapshot (`controls/testdata/_hosts/`) pins the
  nineteen verdicts a stock Ubuntu 22.04 server reads; a fifth daemon oracle
  compares the twelve sysctls with `sysctl -n`; the capability matrix names
  the `/proc/sys` file that is root-only on every supported kernel
  (`bpf_jit_harden`) and the two keys a container cannot answer, and CI
  proves the EL non-root bootloader path inside the init images.

- A mutation test over the control set. `TestEveryMutantIsKilled`
  (`internal/controls`) mutates every control — operators flipped, expected
  values shifted, clauses and mechanisms removed, `absent_means` changed — and
  requires the fixtures to kill each mutant; a mutant the lint rejects, or
  that only makes the evaluator recover a panic, is invalid, not killed. The suite ships the
  fixtures that made the score exact (168 added), and
  `controls/testdata/_mutants.yaml` lists the 16 mutants no fixture can
  distinguish, each with the collector invariant that makes it equivalent.
- A fuzz target with seeds for every parser entry point (55 across
  `internal/collect/collectors` and `internal/pkgfiles`), an inventory test
  that fails when a new parser has none, and the nightly `fuzz.yml` workflow
  (four shards, a minute per target); pull requests run the seeds only.
  `make fuzz TARGET=<name> TIME=<duration>` runs one target locally.
- Daemon oracles in CI: with `MUSTER_ORACLE=1` the sshd, passwd/group,
  mountinfo and services parsers are compared with `sshd -T`, `getent`,
  `findmnt` and `systemctl` on the runner VM and inside the init containers;
  the runner's real configuration files are uploaded as a seed corpus.
- Example snapshots under `examples/`, collected by the `examples.yml`
  workflow from an `ubuntu:24.04` container and the runner VM and rewritten
  so they carry no host identity; a test checks them end to end and
  `make examples-fetch RUN=<id>` refreshes them.
- `muster controls lint` cross-checks every `references.kisa` id against the
  KISA inventory (`--kisa docs/reference/kisa`): an unknown id, an importance
  that disagrees with the inventory, an item cited by none and not deferred,
  a deferred item that a control cites, a deferral naming something that is
  not a 2026 item, and an id repeated inside one control are lint errors (an
  item judged by several controls is allowed since 3A — U-23 has two); a deferral without an id, a stage or a
  reason is rejected when the inventory loads.
  `shell_valid` may only be judged behind an `accounts.shells present`
  screen in every clause list. The unindexed-reference message names the
  index directory it was given; two index files for one product are
  rejected; without `--references` the note says references were checked
  for shape only.
- `docs/reference/coverage.md` gains a "Fact keys used by controls" section
  (spec §11), marks deferred items, and `go run ./tools/coverage -check`
  also verifies the README count sentence. `controls lint` prints the same
  usage totals.
- The clause grammar gains `not_contains` (a string, or a `list<string>`
  element, that must be absent), the counterpart of `contains`. Lint requires
  `subject` on a `none` clause over a record list, so a finding and a waiver
  name the element rather than its position. `muster controls new` notes,
  instead of refusing, an item another control already judges. A reason for
  a `present`/`absent` sub-clause no longer ends in `<nil>`.
- `tools/suidindex` generates the setuid/setgid reference lists the walk's
  dpkg join reads (`docs/reference/suid/*.json`) by running the public
  container images pinned by digest in `docs/reference/suid/sources.json` and
  asking the distribution's own package tool what it ships. Five releases are
  committed: Ubuntu 22.04 and 24.04, Debian 12, Rocky 9 and AlmaLinux 9. A
  package a base image does not install is downloaded on the host from a URL
  and SHA-256 pinned in `sources.json` and bind-mounted read-only into the
  container; the generating container gets no network and installs nothing.
  Every list records the architecture it was read from (`arch`), and the
  image is pulled and run for that platform; an image whose own `uname -m`
  disagrees is refused. `make suidindex-check` regenerates to memory and
  compares byte for byte, except for `generated`: a run on another day
  reports the date it would have stamped and passes, so the committed lists
  can be verified at any time. CI runs neither target and reads the committed
  lists, exactly as it does for `tools/refindex`. On a dpkg host of one of
  the five releases a packaged setuid file is now decided by the list instead
  of reading `none` and only warning; a file whose bit a maintainer script
  sets after unpacking (pkexec, fusermount3, the polkit agent helper) is
  reported as `postinst` and warns rather than being called a finding.
  `suid.Load` resolves a host's release in three steps — the exact
  `<id>-<version_id>.json`, then `<id>-<major>.json`, then the highest
  `<id>-<major>.<minor>.json` present, with the minors compared as numbers —
  so the lists generated from the 9.8 RHEL-family images answer for a host on
  any Rocky or AlmaLinux 9.x.
- `muster controls new` scaffolds a control and its fixture stubs;
  `muster snapshot extract` cuts the leaves a control reads (and the
  engine-read keys they imply) out of a snapshot into a fixture skeleton.
- CI checks a capability matrix (`docs/reference/capability-matrix.json`):
  facts that must be `denied` without root and `unsupported` without systemd.
  The e2e status maps are exhaustive.
- `CONTRIBUTING.md` (with its Korean pair) describes the workflow.

### Fixed
- `sshd`: an `Include` naming a path outside the collector's declaration is
  `absent` naming it (C4), no longer `error` — stock EL9's `50-redhat.conf`
  includes the crypto-policies file, and that host's `collect` reads complete
  (exit 0) instead of partial.
- `sshd`: `PermitRootLogin`'s pre-7.0 spelling `without-password` is stored
  as `prohibit-password` on every side (see Controls).
- `sshkeys`: an account whose home lies outside the collector's declaration
  is a row with an empty path and the reason; it no longer carries the
  symlink flag `unfollowed`.

## Stage 1 (2026-09-03)

`collect` and `check`, the facts schema, table and JSON output, exit codes,
waivers, the snapshot lifecycle, `controls lint` and the fixture convention,
with eight controls flowing end to end (plans 1A and 1B).
