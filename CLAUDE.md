# muster — working notes for Claude

Design: `docs/superpowers/specs/2026-09-02-muster-design.md` (English canonical, Korean pair). It is also the
decision log (D01–D34). Read it before changing any contract: facts schema, control ids, exit codes,
waiver keys, output format.

## Build and test

- `go build ./...` (or `CGO_ENABLED=0 go build -trimpath ./cmd/muster` to match the CI build step) —
  compile everything.
- `make test` — `go test -race ./...` (needs a C toolchain for `-race`; on a host without one, run
  `go test ./...` and rely on CI, which runs on Linux, for the race build).
- `make lint` — `gofmt -l .` then `go vet ./...`.
- `make lint-controls` — `go run ./cmd/muster controls lint` (passes `--references docs/reference`, so
  STIG/NIST ids must be in the generated index), then once more with `--profile default`.
- `make shellcheck` — `sh -n` and `shellcheck -s sh` over `internal/remedy/testdata/*.sh`, `examples/*-fix-report.sh`
  and `ci/roundtrip/*.sh` (at least five remedy goldens and six round-trip scripts; CI runs the same step in the
  `test` job).
- `make fmt` — `gofmt -l -w .` to fix formatting in place.
- `make coverage` — `go run ./tools/coverage` regenerates `docs/reference/coverage.md`; CI runs
  `go run ./tools/coverage -check` and fails when it is stale. `make refindex` — `go run ./tools/refindex`
  regenerates `docs/reference/stig/*.json` from the pinned DISA files (network; caches downloads under
  `.cache/refindex/`, git-ignored). `make refindex-check` — `go run ./tools/refindex -check`; CI does not
  run either `refindex` target and instead lints against the committed index (see `make lint-controls`).
  `make suidindex` / `make suidindex-check` — `go run ./tools/suidindex [-check]` regenerates or verifies
  `docs/reference/suid/*.json` from the public images pinned in `sources.json` (docker and network;
  maintainer-run; CI reads the committed lists through the embedded `suid` package).

## Layout

`cmd/muster` dispatch only. `internal/remedy` the fix plan and its renderers (pure: no `os`, `os/exec`, `net`, `syscall`, `time`). `internal/facts` snapshot types and the key registry. `internal/controls`
schema, strict loader, lint. `internal/check` the pure evaluator — it must never import `os/exec`, `net`
or touch the host (a test enforces it). `internal/waiver` waivers, applied after evaluation. `internal/report`
renderers and the exit code. `controls/` the embedded control set and its fixtures. `collect` is Linux-only
and lives behind build tags (`internal/collect/walkroots.go` is the one untagged file, so the flag parser
can name the container-storage roots on every platform). `internal/pkgfiles` holds the package-file
parsers the walk's join and `tools/suidindex` share. `docs/reference/suid/` is a Go package that embeds
the per-release reference lists of declared modes; `tools/suidindex` (maintainer-run, docker, network)
regenerates them from public images and `-check` compares.

## The walk (stage 3A)

- `collect --deep` runs the `walk` collector (root only; without root it writes `walk.complete` denied
  and nothing else). `--walk-budget`, `--walk-max-entries`, `--walk-exclude`, `--walk-include` bound it;
  `--deep` raises the default `--timeout` to walk budget + `--verify-timeout` (30m) + 5m, or budget + 5m with
  `--no-verify`. On the lab host the walk is proven through the
  session's read-only scripts, never from a checkout; the recipe lives in the session notes.
- `Declaration.Walk: true` licenses `Access.ReadDir(path, expect)` on any absolute clean path for that
  collector alone; `Readlink` is guarded by `Reads` like `Stat`. Both go through `openNoFollow`; a symlink
  is listed, never followed; a directory whose identity changed between listing and opening is `vanished`.
- Every walk list is capped (`listCaps`); a full list never stops the walk — `truncated: true` on that
  key and `walk.stats.truncated_counts` record it. `walk.skipped` rows carry a closed `reason` vocabulary
  and a `detail`. Records are maps; every list is sorted by `path`.

## Beyond the guide (stage 3B)

- `category: beyond` ⇔ no `references.kisa` (lint `beyond_scope`); ids `muster.beyond.<name>` under
  `controls/beyond/`; every beyond control gates on `env.container eq none`; importance is muster's own
  rating from a primary source, said in the description. The summary's `scopes` splits the guide from
  beyond it; the exit code counts both.
- A `/dev/null` symlink in a `.d` directory muster reads is a mask, never an error; every `/sys/block`
  entry is a symlink, so sysfs is walked through `Readlink` into `devices/virtual/block`; the module tree
  is `/usr/lib/modules` on merged-`/usr` hosts. `controls/testdata/_hosts/` holds whole-host synthetic
  snapshots (the stock Ubuntu 22.04 reading) that the fixture harness ignores and `hosts_test.go` pins.

## Integrity (stage 3C-1)

- `pkgverify` runs only under `--deep` as root (`Builder.Verify()` is set iff `--deep` without `--no-verify`);
  without root it writes `packages.verify.complete` denied and nothing else. The evaluator's deep gate is
  the `deepFamilies` table (`walk.` / `packages.verify.`): not run → MANUAL, complete false → ERROR
  (`walk_incomplete` / `verify_incomplete`), `unsupported` → NOT_APPLICABLE, denied/timeout/error → ERROR.
  The verify filter has seven named rules recorded in `packages.verify.filter`; dpkg's exit code carries no
  verdict, dpkg's `path-exclude` globs are fnmatch (`*` crosses `/`), and an all-dots rpm row is `unchanged`.
- `auditctl` gates on CAP_AUDIT_CONTROL (exit 4 "You must be root" → denied non-root / unsupported root) and
  no pid namespace but the initial one reaches the kernel (exit 255 → unsupported): no container runs auditd
  or answers `auditctl`, so the runtime paths are proven on the GitHub runner VM, which installs auditd.
  augenrules loads `rules.d/*.rules` in `ls -v` version order and, without rules.d, `/etc/audit/audit.rules`.
  `fim.tool` is `aide` / `none`, or `absent` naming the other tools found (that host reads MANUAL).
  `controls/testdata/_hosts/` holds the stock Ubuntu 22.04 and EL9 readings.

## Privilege (stage 3C-2a)

- `ReadDir(path, expect, ReadDirOptions{Xattrs: true})` — licensed by `Declaration.Walk` alone — opens each
  regular entry with an execute bit from the directory fd, `fstat`-checks it and reads `security.capability`
  and `system.posix_acl_access` onto the `DirEntry`; an entry whose attributes could not be read is a
  `walk.skipped` row (`xattr_denied`, `xattr_undecoded`, `xattr_error`, `vanished`) and never stops the walk. A capability
  is declared by the host's own package metadata — rpm's `%{FILECAPS}` (the walk's rpm query carries it as
  the fifth tab field) or the owning dpkg package's `postinst` `setcap` call (literal, `$NAME=` or
  `$(dpkg-divert --truename …)` variable, or `- <path> < <file>`) — never by a reference list; the canonical
  text is `cap_to_text(3)` with 41 named bits, and both libcap spellings are parsed. A `rootid ≠ 0` attribute
  is never declared. `walk.acl_grants` is evidence no control reads.
- `units` judges the `.service` units that are enabled or active, from the ten-directory search path, with one
  fixed command (`systemctl list-units --type=service --state=active --plain --no-legend`); `Exec*` first tokens
  are stat-ed only inside a declared executable set (`/usr/bin/*`, `/usr/sbin/*`, `/usr/lib/**`, `/usr/libexec/**`,
  `/usr/local/{bin,sbin}/*`, `/usr/share/*/*`, `/opt/*/*`, `/snap/bin/*`, `/etc/init.d/*`, the merged-`/usr`
  aliases) — a path outside it, a linked unit file, an active unit whose file is missing, or a unit file muster could not read makes
  `units.exec_writable` `absent` (MANUAL naming it); a lone `;` separates commands; `parent_writable` judges the
  executable's directory.
- The sudo reader parses user specifications with aliases resolved (depth 8, budgets of 65536 members and
  of 65536 commands the rows carry; `sudo.rules` is cut to 2000 before a row is built); a comment line ends at its newline even inside a continuation; `#<digits>` is a uid; an unresolved
  alias, netgroup or non-Unix group makes `sudo.nopasswd_all` and `sudo.authenticate_disabled` `absent` (MANUAL).
  `accounts.login_capable` is every interactive non-system account, root and password-locked accounts included;
  `lastlog` is decoded by `runtime.GOARCH` (292 bytes on amd64, ppc64le, riscv64; 296 on arm64, s390x). `sshkeys`
  never stores a key body; a symlinked `authorized_keys` reads MANUAL; `rsa-sha2-*` words carry RSA keys. A
  runtime socket's xattrs are read through an `O_PATH` fd's `/proc/self/fd` entry (a socket cannot be opened
  for reading, and a caller its mode refuses gets EACCES first — the route serves both). `/var/run/…` is never declared — it is a symlink.

## Exposure (stage 3C-2b)

- `processes` enumerates `/proc/[0-9]*` with `Glob` and reads `exe`, `fd/*`, `ns/mnt`, `root` and `mountinfo` with
  `Readlink`/`ReadFile` only (a magic link's text, never its target). A listening socket's `owners` are the
  processes whose fd tables hold `socket:[inode]` (a zombie leader with live threads through `task/*/fd/*`);
  a socket nobody holds is the kernel's (`owner_status: kernel` — WireGuard measured, kernel sockets have
  non-zero inodes) only when every fd table was read whole and pid 1 plus a kernel thread are in sight;
  inside a container, or when the pid view is partial (`hidepid`), it is `unmatched` and the listener leaves
  are `absent` (MANUAL). `mnt_ns` is `host` when the process's `ns/mnt` equals pid 1's or, in another namespace, when the mount serving the exe keys like pid 1's for the same
  path (systemd's PrivateTmp services are the host's; an overlay root or a bind over `/usr` is `foreign`);
  `package_status` is `packaged`, `unpackaged`, `snap` (by the `/snap/<name>/<rev>/` prefix), `flatpak`,
  `appimage`, `foreign_ns` or `no_index`. The package index is `internal/pkgindex`, built per collector over
  its own candidates (~130 ms dpkg, ~110 ms rpm). `Declaration.Facts` lets a collector `Get` an earlier
  collector's facts (`processes` reads `firewall.*`); `TestDeclaredFactsAreWrittenBeforeTheyAreRead` pins the
  name order.
- `firewall.rules` rows carry `{chain, via_chain, depth, table, family, proto, dport, saddr, daddr, iif, ctstate,
  action, unmodelled, raw}`; the user chains an input filter base chain jumps to are folded (depth 4, 2000 rows
  per base, once per distinct set of carried conditions, the jump's conditions inherited); a protocol set, a
  vmap, a `.` concatenation or an unknown match is `unmodelled`. A configured but inactive backend (ufw
  disabled) normalises `full` + `restricts_inbound false` — U-28 FAILs there (D16) — unless an empty nft
  ruleset hides iptables-legacy rules (cross-checked). Confidence and `restricts_inbound` read base chains
  only.
- `exposure.*` is written by `processes`: classes `deny`, `irrelevant` (no verdict, a folded jump, a non-tcp/udp
  protocol from the closed list), `loopback_only`, `state_only` (established/related/invalid only),
  `port_rule`/`any_port` (only when not unmodelled), `opaque`. Decided only at `full` with no `opaque` row in
  the listener's family (`inet` counts for both); an enabled family with no input base chain exposes its
  listeners (`no_chain_in_family`); IPv6 disabled by sysctl on `all`, `default` and every interface but `lo` is not an enabled family (W-86);
  `::` is a v4 candidate when `bindv6only` is 0; link-local is a candidate, loopback never listed. `service`
  is `tcp/<port>`; the default allow list is `tcp/22`, `udp/68`, `udp/546`. An accept-policy input chain that carries rules
  (firewalld's `filter_INPUT`; ufw beside another table's INPUT) reads `partial` → `exposed_listeners_allowed`
  MANUAL; docker's FORWARD chains never enter confidence, so a docker host with an empty accept INPUT is decided.
- `net.sysctl.*` are 28 keys read as the kernel ones (B-3) — 26 settings, `ipv6_bindv6only` and the derived
  `ipv6_disabled` (1 iff `all`, `default` and every present interface but `lo` disable IPv6: the one gate of the four IPv6
  controls and of the exposure join, W-79/W-86); the `sysctl.d` parser follows systemd: a glob key
  (`*?[`, `[!…]`) applies to every unexcluded match, a `-key` line excludes it from globs (last line wins), a
  concrete line beats any glob. Ubuntu 24.04 ships no `50-default.conf`.

## Profiles (stage 3D-1)

- `check --profile <name|path>` (default `default`; `kisa-unix-2026` is its alias) and `check --tuning <path>` are
  resolved by `cmd/muster`'s `resolveSelection` BEFORE evaluation: `profile.Resolve` walks the `extends` chain (at most
  four files, the built-in counted, identified by cleaned opened paths) and applies `parent ∪ include − exclude` per
  file (id globs through `path.Match`, `*` crosses `.`, a class negates with `[^…]`; a malformed or unmatched pattern refuses the file), keeps every
  chain value in `Resolved.Params`, appends `severity` entries (last match wins over the selected ids), and digests the
  content only (`{ids, params, severity}` — never the name, path or chain); `tuning.Load` validates a site's `params:`
  against the FULL set; `profile.Merge` is the one owner of the excluded-control warnings (`profile parameter
  <id>.<param> ignored: excluded by profile`, `tuning parameter …`) and returns the values in force with their sources.
  `check` evaluates `set.Subset(ids)` with the unchanged evaluator; an excluded control is neither evaluated nor listed.
- A value without a separator or `.yaml`/`.yml` suffix is a NAME (`Default`, `site_web` are refused naming the
  built-ins), anything else a path; `extends` resolves relative to the referring file, an absolute value as given. Files
  are read only through the `open` the command passes (`trustedFile` + `os.ReadFile`: as root, root-owned and not
  group/other-writable, chain files included); `internal/profile` and `internal/tuning` never import `os`, `os/exec`,
  `net` or `syscall` (a test enforces it) and never write stderr (`warn`). A profile, tuning or waiver file holds ONE
  YAML document (a second refuses it); an empty `--profile` or `--tuning` value is refused by every command that
  takes it, never read as the flag's absence.
- The result is additive and lives in `check`: `profile {name, source, digest, extends, selected, excluded,
  excluded_ids}`, `tuning {path, digest}` (absent without `--tuning`), `params` (controls that declare params, as
  before), `param_sources` (same keys; `default` | `profile` | `tuning`), each row's `severity_source` (`importance` |
  `profile`); the table's second line is `profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>])`
  or `profile <name> (<total> controls[; tuning <path>])`. `waiver.Apply(results, known, excluded, …)` counts a waiver on an excluded control
  `not_applied` (warned, no row). The exit code and `--fail-on` read statuses, not severity. `controls lint --profile`
  (full lint + the profile line; CI runs it with `default`) and `controls list --profile` (the four-column rows of the
  selection) share the same resolution. The examples gate byte-compares reports, so a change to the `check` block
  needs an examples refresh from the branch's `examples.yml` run before the merge.

## Fix (stages 3D-2, 3D-2b, 3D-2c, 3D-2d)

- `fix --dry-run` (mandatory; anything else is `fix never applies a remediation (D24); run fix --dry-run`, exit 2) runs
  `runCheck`'s own helpers (`openFacts` → set/registry → `resolveSelection` → `loadWaivers` → `newCheckBlock` →
  `report.Build`) and hands the report to `remedy.Build`; `--format table|json|script`, `--max-risk` the one knob. It
  exits 0 with findings (judging is check's) and 2 when no plan could be made, a failing stdout included. Items are
  FAIL/WARN rows after waivers, ordered risk → severity in force → id; a degraded pass (`Reason ==
  check.ReasonDegradedPrefix + Degraded`), ERROR and MANUAL are `not_planned`. `item()` decides text-only in this
  order (S-2): `no_script` → `absent` (an absent-means-fail row, unless the control declares `script_on_absent: true`)
  → `params_tuned` (a profile or tuning value in force, only for a control without `script_params`) → `params_unsafe`
  (a `script_params` value in force — `check.ParamValues`, the default when the check block carries none — that
  `controls.ScriptParamValue` refuses: `int` an optionally signed integer (`^-?[0-9]+$`), `bool`, a `string`/list element in `^[A-Za-z0-9._/@:+,=-]+$`, a
  list joined by one space, an empty list refused) → scripted. Items gain `script_params` (`[{name, value}]` by name) and
  `script_on_absent` after `text_only_reason` (before `rollback`), and `modes`, `sysctl`, `modules` after `units`
  (`[]`/`false` unless scripted); plan schema stays 1.
  `Build` refuses an id outside the id grammar and re-checks (S-4) every unit, `backup` path (`ValidBackupPath`),
  `modes` entry, `sysctl` key, module and `script_params` name against its lint pattern (`refusing to plan <id>: <kind>
  %q is not one a script can carry`).
- The script: `# shellcheck disable=SC2181` on line 2; prologue order `set -u`, `umask 077`, `log()`, the hash helper,
  the root check, the host guard, the `MUSTER_BACKUP` default and case, `mkdir`, the owner check, `backup()`/`restore()`,
  `save_units()`/`restore_units()`, `modes_paths()`/`modes_type()`/`save_modes()`/`restore_modes()`/`modes_trusted()`,
  `save_sysctl()`/`restore_sysctl()`, `save_modules()`/`restore_modules()`, `failed=0` (`TestScriptPrologueOrder`). Exit
  2 has three causes, nothing run in any: not root, another host (the guard), an unusable backup directory (`/`, `//…`,
  `.` and `..` components, relative, not root-owned or group/other-writable). A block function opens with one
  `  P_<name>='<value>'` line per `script_params` entry (name order; the body, validate and rollback subshells inherit
  them), then `  MB="$MUSTER_BACKUP/blocks/<fn>"; mkdir -p "$MB"`, then the records it declares in the order `backup`,
  `save_units`, `save_modes` (entries single-quoted, so the shell never expands `*`), `save_sysctl`, `save_modules` —
  each `|| { log "<id>: backup failed, nothing changed"; return 1; }`. Every record lives under the block's own `$MB`
  (two controls may declare the same path or unit): `files<path>` (`cp -a`), `absent<path>` (an empty marker for a
  declared path that did not exist; `restore` removes the path, refusing a directory), `units/<u>`, `modes.list` (`<uid>
  <gid> <mode> <f|d|o> <path>`), `sysctl.list` (`<key> <value>`, `absent` when unreadable), `modules.list` (`<name>
  loaded|not-loaded`), and a body's own files (`password_policy`'s `ageing.list`, `account_inactivity_lock`'s
  `inactive.list`). Each kind keeps its first record per
  block across runs with the same `MUSTER_BACKUP`, except an absent marker, which `backup` replaces with a copy once the
  path exists (a re-run after run 1 created a drop-in restores run 1's file). Records that describe one run (3D-2d
  O-16: `audit.loaded`, `audit.status`, `disk.keys`, `inactive.run`, `<d>.was-running`, `<d>.edited`) are removed as the
  body's first action and written fresh, never first-kept. `backup` returns 1 on a failed copy and
  the block stops; each body runs in `( set -e … ); rc=$?` and each block function is called as a bare line followed by
  `[ "$?" -eq 0 ] || failed=$((failed+1))` — POSIX turns `-e` off for anything run as an operand of `||`/`&&`/`if`/`!`.
  On failure, in this order (`TestScriptFailurePathOrder`): the declared `rollback` subshell, `restore_units`,
  `restore_modes`, `restore` (never writes through a destination symlink, refuses a directory), `restore_sysctl`
  (after the file that would persist the value is gone), `restore_modules` (`modprobe --ignore-install`, so the
  `install … /bin/false` line `restore` put back cannot stop the reload); each restore `|| log "<id>: ROLLBACK
  INCOMPLETE, backups in $MUSTER_BACKUP"`. `restore_modes` per row: skip a path now gone, refuse a symlink or a type
  change (`changed type, left as is`), skip a row whose `%u %g %a` already equals the record (no `chown` that would
  clear `security.capability`), refuse a path `modes_trusted <path> <uid>` rejects, then `chown -h` only when the owner or group differs, and `chmod`.
  `modes_trusted` (S-24): every ancestor up to `/` root-owned and not other-writable (a root-owned group-writable one —
  Ubuntu's `root:syslog 0775 /var/log` — is accepted), and a non-root recorded uid needs a parent neither group- nor
  other-writable. A fixed `  # validate` line precedes every validate subshell (the round trip's failure run keys on
  it). Snapshot text lives only in `#` comments (`report.Escape`), control text through `report.EscapeNoCut`; `Escape`
  spells out C0/C1, every `unicode.Cf` rune, U+2028/U+2029 and the Hangul fillers U+115F/U+1160/U+3164/U+FFA0 as
  `\u%04x` / `\U%08x`.
- Host guard (Q-1): `remedy.Build` copies `run.host.machine_id_hash` into the plan only when it is 64 lowercase hex
  (the one host value D34 admits into a command; a parameter value is policy, not a host value, and enters only as a
  `P_` line); `TestScriptEveryLineIsTemplateBodyOrComment`'s `templateLines` admits exactly one
  `MUSTER_SNAPSHOT_HOST=<64 hex>` line, the rendered `P_` lines, the `MB=` line and each declared record and restore
  line (the `p_params` poison's `'; uname -a; '` reaches no command line and no JSON, S-20); `fix.host_guard` is
  `on`/`off`. On: `MachineIDHashHelper` (`tr -d '[:space:]'`, 32 lowercase hex, `sha256sum`) hashes `/etc/machine-id`
  and a mismatch or an unreadable id exits 2 with one stderr line; `MUSTER_ANY_HOST=1` (read only when the hashes
  differ) runs with a warning. Off: one comment line `# host guard: off (the snapshot has no machine id)`. The
  collector's `MachineIDHash` hashes only a 32-lowercase-hex id trimmed of ASCII whitespace only (`strings.Trim(…, "
  \t\n\r\v\f")`, the set the helper's `tr` deletes; else `""`); `TestHostGuardHashMatchesTheCollector` pins the two
  together.
- Units (Q-2): `remediation.units` lists `.service`/`.socket` names; lint `units_charset` (pattern, no duplicates; a
  template unit needs an instance), `units_order` (`<n>.socket` before `<n>.service`), `units_needs_script`,
  `units_exclusive` (no `rollback`, `backup`, `modes`, `sysctl` or `modules` beside units), `units_variable` (`$UNITS`
  only in a `script` that declares units), `script_needs_validate`. `backup_reserved`, `backup_path_shared` and
  `units_shared` are gone (3D-2c: per-block records). `items[].units` follows `backup`; rollback vocabulary `none |
  declared | restore_backup | units | state | both` (`units` alone; `state` for `modes`/`sysctl`/`modules` alone;
  `both` for two or more of a rollback, a backup and a record kind). The block calls `save_units <u…>` and
  `restore_units <u…>` on every failure path, and emits `UNITS='<u…>'` first in the body subshell. `save_units` writes
  `$MB/units/<u>` (`<is-enabled> <is-active>`, or `absent absent`) and `<u>.deps` (active reverse
  `Requires=`/`BindsTo=`/`PartOf=` units), keeping a first record except `absent`. `restore_units` runs seven passes:
  unmask (all but `absent`), enable `enabled`/`enabled-runtime` (log `linked*` not restored), re-disable a `disabled`
  unit an `Also=` turned on, re-mask `masked`/`masked-runtime`, start what was active (not a re-masked one), start
  inactive dependants, read the enablement back (`enablement not restored` → 1). `restore_units` never stops a unit: the
  one enabling units body (`auditd_active`, 3D-2d) leaves a started daemon running after a failed block, and its text
  says so. Go tests run the helpers and bodies
  only against stubs (`systemctl`, `sysctl`, `modprobe`, `chage`, `sshd`, `auditctl`, `augenrules`, `postconf`,
  `postfix`, `exportfs`, `date`; an unmodelled tool fails closed with exit 99) first on `PATH`, every absolute path rebased
  under `t.TempDir()` (`TestUnitHelpersRestoreRecordedState`, `TestSysctlHelpersRecordAndRestore`,
  `TestModulesHelpersRecordAndRestore`), except `TestModesHelpersTrustRule` and `TestFileBodiesRepairATempTree`, which
  are root only and build their tree with `os.MkdirTemp("/", …)` (`modes_trusted` refuses anything under the
  other-writable `/tmp`).
- Remediation bodies (lint + CONTRIBUTING): a `script` needs `idempotent: true`, a `validate` and a way back of six
  kinds — `rollback`, `backup`, `units`, `modes`, `sysctl`, `modules` (rule `remediation`); `script_params_declared`
  (each entry a declared param, `^[a-z][a-z0-9_]*$`, once), `script_params_used` (every `$P_x`/`${P_x` declared, every
  entry used in `script`), `script_params_default_safe`, `script_params_needs_script`, `script_on_absent_needs_script`,
  `state_needs_script`, `modes_charset` (`^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`, base clean and not `/`, no duplicates),
  `modes_backup_overlap` (no `backup` path an entry covers), `sysctl_charset` (`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`),
  `modules_charset` (`^[a-z0-9][a-z0-9_-]*$`). `validate` is one line (lint), by convention `&&`-joined conditions, a
  single `case` whose last arm is `*) false` (a `case` matching nothing exits 0), or one `for` over a literal list
  whose conditions `exit 1` — or a guarded line (`[ guard ] || …`, `{ …; } || { …; }`) that accepts a leave the body
  logs (X-10); no here-document; `backup` paths absolute, clean, `^/[A-Za-z0-9._@:+/-]+$`. A `P_` value
  never starts a line and never enters a `sed` expression (copy it to a plain variable first;
  `TestShippedBodiesPlaceParametersSafely`, in `internal/controls`). E-8: a body writes only when the current value is
  outside the clause's accepted set, read the collector's way (first `login.defs` line, last `faillock.conf` `deny`
  defaulting to 3, the merged `pwquality` chain, keys in any case), and the validate proves set membership; a `gte`
  arm is a glob list (`[2-9]|[1-9][0-9]|[1-9][0-9][0-9]*`). E-9: a directory the host may lack runs under `if [ -d d ]
  && [ ! -L d ]`, one path under `[ -f p ] && [ ! -L p ]`, a mode-changing `find` carries `! -type l` or `-type f`/`-type
  d` (`TestShippedFindsCarryATypePredicate`), and a validate's `find` mask is 07777 minus the largest allowed mode
  (`/7137`, `/7177`, `/7337`; `TestFileValidateMasksDeriveFromTheDefaultModes`). E-11: a rollback whose daemon re-reads
  the file puts it back (or removes it) itself before `sshd -t` and the reload (`session_timeout` copies `$MB/files$f`
  back, S-35); 3D-2d O-9: a rollback may call the prologue's `restore <path>` first, then runs the daemon's test and
  reload or restart only when `$MB/<d>.edited` (touched before the first write) and `$MB/<d>.was-running` (written
  before any edit) exist, never on "running now". O-6: the value written is the first member of the list in force that
  the target accepts and that keeps the host up (`audit_disk_actions` never writes `email`, `exec`, `single`, `halt`).
  O-2/O-3/O-74: no body makes a one-way runtime change; no body loads audit rules into, or starts auditd over, a pending
  `-e 2`/`--loginuid-immutable` (matched anywhere on a line of `rules.d/*.rules` or `audit.rules`), whatever the runtime
  lock state, and the only reload is `auditctl --signal reload`. O-8: a new body comments a disqualifying line out
  (`# muster: `), never deletes it. Every command whose output a body, validate or rollback parses runs under `LC_ALL=C`;
  `restorecon` runs only on a file a tool replaced or created (`postconf -e`, a created file), never after `sed -i` or
  `restore`. O-10: each body's file reader is a one-line `rd_<what>()` function compared with the Go parser by
  `remediation_parity_test.go` (Linux). E-13: a write's side effect on another judged key is the writer's — `ip_forwarding_disabled` reads
  `net.ipv4.conf.all.accept_redirects` before the write, puts it back and persists it only when it was 0 (S-43);
  `ipv6_forwarding_disabled` keeps `all` before `default` (the kernel copies `all.forwarding` into `default`), and no
  `sysctl` list is ever sorted. Trust (S-24, S-47): `log_dir_permissions` and `cron_permissions`' at-spool pass change
  files only inside a directory `modes_trusted "$d/." 0` accepts, else log `<d> is not root's, left as is`; the
  validate checks the same set, so the block ends `done` and the control stays FAIL naming the path; S-50:
  `cron_permissions` clears `o-w` on its directories and `audit_log_permissions` fixes `/var/log/audit` first, and every
  file pass of the two is gated the same way. S-49: a system crontab (`/etc/crontab`, `/etc/anacrontab`,
  `/etc/cron.d/*`) or a sudoers file (`/etc/sudoers`, an active `/etc/sudoers.d/*`) not owned by root is never chowned
  or re-moded (cron and sudo ignore it; adopting it would activate another user's content): the body logs `<id>: <path>
  is owned by uid N; review it before chown root, left as is`, the validate fails and the block rolls back. A symlinked
  `/etc/login.defs` fails the `umask_policy` and `password_policy` blocks before any write (K2). S-27: a
  muster-owned drop-in (`99-muster-*.conf` under `sysctl.d`/`modprobe.d`, `pwquality.conf.d/99-muster.conf`,
  `00-muster-session.conf`) that is a symlink is logged `… is a symlink (a mask), left as is` and fails the block before
  any write; every rollback that removes it skips a symlink (3D-2d O-11: `lockout_threshold`'s `faillock.conf` and
  `root_remote_login`'s `/etc/securetty` are vendor files, K2; its `00-muster.conf` is a drop-in). A built-in module stays done-but-FAIL (no body can unload
  it). Eleven controls declare `units` (as a set, the `provesInstall` units of their rows in `services.go`;
  the validate names the same units literally and the script none — `TestServiceScriptsNameTheCollectorsUnits`, Linux):
  `auditd_active` enables (unmask, enable, start only an inactive unit over an empty kernel list with no lock pending),
  and the ten service controls disable, looping over `$UNITS` in two passes: pass 1 adds to `todo` every name `systemctl cat` finds whose `systemctl show -p
  Id --value` equals itself (an alias of a listed unit is skipped while it still resolves — Debian's
  `nfs-kernel-server.service` aliases `nfs-server.service`), pass 2 runs `systemctl --quiet disable --now` strictly and
  `systemctl --quiet mask … || true` over `todo`; no hand-written rollback, and one-unit bodies loop too (SC2043 fires
  only on a literal one-word list; module bodies open `mods='<list>'; for m in $mods`, pinned by
  `TestModuleScriptsNameTheControlsModules`). File bodies clear bits symbolically (`chmod u-xs,g-rwxs,o-rwxt` and kin,
  so a stricter file is never loosened) — the two that remove an ACL (`passwd_permissions`, `shadow_permissions`) run
  `setfacl -b` before `chmod`. `TestFileValidatesAcceptTheDefaultModes` regenerates, byte for byte, the bare stat-`case`
  validates of the five 3D-2b file controls in its owner table, and fails on any other shipped validate that is one
  `case "$(stat -c …` and nothing else. 56 bodies ship (the sixteen of 3D-2 plus 16 sysctl, 3 module, 9 file-permission
  and 4 account bodies of 3D-2c, and the 3 audit, 1 inactivity and 4 content bodies of 3D-2d); they are shellcheck-clean at the default severity and `all-scripted.sh` renders them all.
- `controls/testdata/_roundtrip.yaml` (ignored by the fixture harness) names, per scripted control sorted by id, the
  matrix rows (`images`, by `key`) that prove it, `unproven_units` (keys in `units`, `modules` or `sysctl`) with a
  reason, or `unproven: <reason>` (no systemd unit / no package in the enabled repositories / cannot run in a container /
  the kernel does not ship the module; `dos_services`, `finger`, `rservices` and `usb_storage` are unproven).
  `TestEveryScriptedControlIsInTheRoundtripTable` holds it equal to the shipped scripted set and to `fix-roundtrip`'s
  matrix: every row has `kind` `container` (with an `image`) or `host` (no `image`, `init` or `build`), `seeded` equals
  the table per row, no `muster.service.*` on a non-init row, `muster.beyond.*` on host rows only. A new scripted control
  enters the table in the same commit.
- The `fix-roundtrip` CI job (timeout 40 min) runs container rows `rocky9-init`, `almalinux9-init`, `debian12-init`
  (built from `ci/roundtrip/debian12-init.Dockerfile`, empty machine id) and `ubuntu2204`, and the host row `runner`
  (the GitHub runner VM itself; `x()` runs through `sudo`). Init rows boot through `ci/roundtrip/wait.sh`, container
  seeds are `ci/roundtrip/<key>.sh` mounted at `/ci` (`rocky9-init` regenerates the machine id its image ships; Debian
  installs under a `policy-rc.d` that exits 101; each init seed ends with a settle check over
  `START_UNITS`/`ENABLE_ONLY_UNITS`). `ci/roundtrip/runner.sh` is idempotent: it removes every muster drop-in, puts back
  the stock modes the repair run tightened (`/etc/hosts`, `/etc/shadow` and the rest), then seeds again (one failing
  value per sysctl control, `udf` loaded with `--ignore-install` (a loaded `sctp` is held in use on the runner), `UMASK 002`,
  auditd disabled but kept running, muster's `50-muster.rules` removed and the stock set loaded then `auditctl -b 4321`,
  pristine `auditd.conf` and `/etc/default/useradd` copies from `/var/lib/muster-ci` with `disk_full_action = suspend`,
  `chage -I -1` over the local login-capable accounts, …; it never writes `-e 2` or `--loginuid-immutable`). The init
  seeds start vsftpd and postfix (IPv4 only; Debian settles on `postfix@-.service`), set `anonymous_enable=YES`, export
  a tmpfs `/srv/ci … no_root_squash,fsid=1`, and every container seed puts a `+` line in `/etc/hosts.equiv`. The repair run plans,
  requires every seeded id planned and scripted, runs the script with its own `MUSTER_BACKUP`
  (`/var/backups/muster/ci-repair`), re-collects and requires the seeded ids PASS/NA. Each init row then starts a second
  container; the host row re-seeds the same VM and plans afresh (no guard run: the guard must be on and the hash stable,
  every seeded id a scripted item of the failure plan, and the failure plan's scripted ids a subset of the repair
  plan's — S-18). The guard run (containers): the first container's script must exit 2 and change nothing. The failure
  run (every validate's first command rewritten to `false` in a copy): exit 1, one `validate failed` per block, no
  `ROLLBACK INCOMPLETE`/`not restored`/`rollback failed`, and `record()` equal before and after — unit states; backup
  paths' stat, checksums and ACLs; `sysctl <k> <v>`; `module <n> loaded|not-loaded`; `mode <path> <u g a>` over each
  `modes` entry's expansion (`| sort -u`); `ageing <name> <f4> <f5> <f7>` and `shadow-rest <sha256>` (shadow with those
  fields blanked) when `password_policy` or `account_inactivity_lock` is scripted; `auditrule …` and six `audit <key>
  <v>` lines of `auditctl -s` (keys matched whole) when an audit body is; `export …` (`exportfs -s`); `vsftpd
  <is-active>`; `postfix-status <rc>` — compared by
  `same()`, which forgives a `mode` path gone since (a rotated log). It is the only place a shipped service, sshd,
  account, sysctl or module body runs against real system paths; `TestFileScriptsRepairOnARealFile` (root only; CI's
  sudo step, where `CI=true` makes a missing `setfacl` fatal) runs the five 3D-2b file bodies and `nfs_export_access`
  and their validates on temp files. The shipped-body tests (`TestFileBodiesRepairATempTree` and the sysctl, module,
  line and account body tests) run the raw `script`/`validate` strings through `runBody` — path-rebased copies with
  `log()`, the state helpers or the stubs prepended, not the rendered block; only the `Test*BodiesLeaveASymlinkedDropIn`
  tests, `TestIPv6ForwardRestoreKeepsAllBeforeDefault` and `TestSessionTimeoutRollbackRestoresBeforeTheReload` run a
  shipped body inside its rendered block (`Script()` over a one-item plan, under `t.TempDir()`). `rebaseRoot` rewrites
  only `/etc/`, `/var/` and `/boot/` paths that follow a space, newline, `(`, `'` or `|`; a new file body spells its
  paths that way, or the root-run tree test acts on the runner's real files. The examples gate byte-compares `examples/<snap>-fix-report.{json,txt,sh}` (script whole,
  JSON masked under `fix`, table without line 1), so a body or plan change needs an examples refresh from the branch's
  `examples.yml` run before the merge.
- Risk is the operational impact, not the guide's: `hosts_permissions` is `restart_service` (0600 breaks non-root
  `/etc/hosts` reads), `auditd_active` is `restart_service` (a start loads the persisted rules and disk actions),
  `rhosts_forbidden` is `restart_service` (as `rservices_disabled`), `account_inactivity_lock` is `lockout_risk` (root
  included; an account it would disable now is skipped and named), `audit_immutable` (text) is `reboot_required`,
  `ip_forwarding_disabled`/`ipv6_forwarding_disabled` are `restart_service` (forwarding off cuts a
  router's or container host's clients at once), `reverse_path_filtering` is `restart_service` (strict filtering drops
  asymmetrically routed traffic; such a host sets 2), `usb_storage_disabled` is `restart_service` (USB backup or boot
  media stop), `nis_disabled` is `lockout_risk` (stopping ypbind cuts NIS accounts), `password_policy` is `lockout_risk` (it
  sets ageing on every account with a password except root: uid 0 is skipped and logged, since an expired root password
  stops root's cron and at jobs, S-48). The sshd body reloads a running `sshd`/`ssh` and validates persona root
  (`sshd -T -C user=root,…`). The script refuses a `MUSTER_BACKUP` that root does not own or others can write (a planted
  backup would be restored over `/etc/shadow`).

## Stage-2 conventions

- **C1** — `files.*` owns permission facts of a fixed candidate path list (`/etc/passwd`, `/etc/hosts`, …). A path that must be discovered from a daemon's configuration belongs to that daemon's collector.
- **C2** — every leaf a clause judges is its own dotted key; a `record` fact is evidence for `present`/`absent` only. Adding a key or a record field keeps `schema_version` (spec §5.7).
- **C3** — a configuration file a module reads that exists but cannot be read is the answer for every value it could set (the read's status, path-prefixed), never the module's default; an `enabled` fact follows the stack. Derived `pam.*` keys cite the files actually read.
- **C4** — a path the model declined to read (outside the collector's declaration) is `absent` with the path in the reason, never `error`; a declared file that exists and cannot be read is the read's status (C3); a symlink an administrator placed at a declared main configuration file is `error` by design — muster reads without following symlinks, and where a distribution ships a symlink the collector models it. A degraded leaf keeps the source it was derived from.
- Permission facts of a fixed path are written by `writePermFacts` in `internal/collect/collectors/permfacts.go`: `mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present` (+ `acl_entries` where the control judges the ACL). Register the nine (or ten) leaves per path; a stat failure reaches every leaf.
- "Mode ≤ NNN" is written as `op: in` over the subsets of NNN (there is no bit operator); the default is the guide's value (spec §6.6) and a `params.allowed_modes` relaxes it.
- `go run ./tools/coverage` regenerates `docs/reference/coverage.md`; CI fails when it is stale. `go run ./tools/refindex` regenerates `docs/reference/stig/*.json` from the pinned DISA files (network; cache in `.cache/refindex`, git-ignored); CI only reads the committed index.
- `references.stig` entries are `{benchmark, version, id}`; `benchmark` is `ubuntu2204`, `ubuntu2404`, `rhel9`, `rocky9` or `alma9`; lint rejects anything not in the index.

## Rules that are contracts

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`. A registered key the
  snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`.
- Exit codes: `check` any `ERROR` → 2 (unless `--allow-error`), any `FAIL` → 1, else 0; `collect`
  0 complete / 1 partial / 2 none. Changing these breaks other people's CI.
- Same input, same bytes. No `map` reaches the JSON or table renderer.
- Result JSON is stdout and nothing else is; warnings are stderr.
- Control and waiver YAML are decoded strictly; unknown keys are errors.
- Never copy KISA guide text or CIS Benchmark text into any file. `docs/reference/kisa/` holds item
  codes, names, categories, importance and page numbers only. See `ATTRIBUTION.md`.
- Fixtures come from public images or are marked `synthetic: true`; never from an employer or customer host.

## Tests

- Every control with a judgment has `controls/testdata/<id>/pass-*.json` and `fail-*.json`; a `manual`
  control has `manual-*.json` carrying every `evidence:` leaf (plus `na-*.json` when gated). The prefix is
  the expected status (`fail-` on a `partial` control expects `WARN`). `_expect` may add `reason_code` and
  `exit_code` — nothing else in it is read.
- Write the test that drives the caller before the test of the helper. After adding a call site, delete
  the call and confirm the suite goes red; if it stays green, the implementation is tested, not the feature.
- Assert something that differs when the call is gone. Prefer structural assertions to substrings.
- Golden files: `go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`,
  `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden|TestJSONGolden' -update`,
  `go test ./internal/facts -run TestFactsSchemaGolden -update`. Review the diff before committing a
  regenerated golden; a facts golden change means a `since` entry or a schema version bump, except a
  description-only edit, which regenerates the golden with neither (say so in the commit).
- The mutation test (`internal/controls`, `TestEveryMutantIsKilled`) runs with the suite: a control
  change or a new fixture must leave zero survivors; a mutant no fixture can distinguish goes into
  `controls/testdata/_mutants.yaml` with a reason naming the collector invariant. Every function or
  method that takes `[]byte` needs a `Fuzz<Name>` target with seeds (`make fuzz TARGET=<name>`); the nightly `fuzz.yml`
  does the real fuzzing, PRs run the seeds only.
- `MUSTER_ORACLE=1 go test ./internal/collect/collectors -run Oracle` on the lab (root) compares the
  parsers with their daemons; CI runs it in the root job and the init containers. `examples/` comes
  only from the `examples.yml` workflow (`make examples-fetch RUN=<id>`), never from a host.

## Documentation

English canonical, `X.ko.md` pair updated in the same commit. Plans under `docs/superpowers/plans/` are
English-only and deleted once merged. Identifiers, flags and paths stay English on both sides.

## Commits

Personal identity only (pinned in `.git/config`; see `.mailmap`). Never push from an agent session.
