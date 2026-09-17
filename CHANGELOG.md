# Changelog

All notable changes to muster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The binary follows
semver; the embedded control set has its own version (`controls/VERSION`,
reported as `controls_version` in every result). A change that alters a
verdict on an existing snapshot is at least a minor release and appears under
**Controls** (design decision D16). This file is English-only.

## [Unreleased]

### Controls

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

### Collectors

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

### Tooling

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

## Stage 1 (2026-09-03)

`collect` and `check`, the facts schema, table and JSON output, exit codes,
waivers, the snapshot lifecycle, `controls lint` and the fixture convention,
with eight controls flowing end to end (plans 1A and 1B).
