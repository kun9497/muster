# Changelog

All notable changes to muster are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The binary follows
semver; the embedded control set has its own version (`controls/VERSION`,
reported as `controls_version` in every result). A change that alters a
verdict on an existing snapshot is at least a minor release and appears under
**Controls** (design decision D16). This file is English-only.

## [Unreleased]

### Controls

Control set `kisa-unix-2026+2026.09.09` (was `+2026.09.02`). 64 of the 67
KISA 2026 Unix items are enrolled: auto 55, partial 5, manual 4 with evidence
attached. U-15, U-23 and U-33 wait for the deep filesystem walk (stage 3) and
are listed in `docs/reference/kisa/kisa_deferred.json`.

Verdict-affecting changes in this version:

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

### Tooling

- `muster controls lint` cross-checks every `references.kisa` id against the
  KISA inventory (`--kisa docs/reference/kisa`): an unknown id, an importance
  that disagrees with the inventory, an item cited by two controls, an item
  cited by none and not deferred, a deferred item that a control cites, a
  deferral naming something that is not a 2026 item, and an id repeated
  inside one control are lint errors; a deferral without an id, a stage or a
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
