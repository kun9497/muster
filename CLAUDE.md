# muster — working notes for Claude

Design: `docs/superpowers/specs/2026-09-02-muster-design.md` (English canonical, Korean pair). It is also the
decision log (D01–D33). Read it before changing any contract: facts schema, control ids, exit codes,
waiver keys, output format.

## Build and test

- `go build ./...` (or `CGO_ENABLED=0 go build -trimpath ./cmd/muster` to match the CI build step) —
  compile everything.
- `make test` — `go test -race ./...` (needs a C toolchain for `-race`; on a host without one, run
  `go test ./...` and rely on CI, which runs on Linux, for the race build).
- `make lint` — `gofmt -l .` then `go vet ./...`.
- `make lint-controls` — `go run ./cmd/muster controls lint` (passes `--references docs/reference`, so
  STIG/NIST ids must be in the generated index).
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

`cmd/muster` dispatch only. `internal/facts` snapshot types and the key registry. `internal/controls`
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
  file (id globs through `path.Match`, `*` crosses `.`; a malformed or unmatched pattern refuses the file), keeps every
  chain value in `Resolved.Params`, appends `severity` entries (last match wins over the selected ids), and digests the
  content only (`{ids, params, severity}` — never the name, path or chain); `tuning.Load` validates a site's `params:`
  against the FULL set; `profile.Merge` is the one owner of the excluded-control warnings (`profile parameter
  <id>.<param> ignored: excluded by profile`, `tuning parameter …`) and returns the values in force with their sources.
  `check` evaluates `set.Subset(ids)` with the unchanged evaluator; an excluded control is neither evaluated nor listed.
- A value without a separator or `.yaml`/`.yml` suffix is a NAME (`Default`, `site_web` are refused naming the
  built-ins), anything else a path; `extends` resolves relative to the referring file, an absolute value as given. Files
  are read only through the `open` the command passes (`trustedFile` + `os.ReadFile`: as root, root-owned and not
  group/other-writable, chain files included); `internal/profile` and `internal/tuning` never import `os`, `os/exec`,
  `net` or `syscall` (a test enforces it) and never write stderr (`warn`).
- The result is additive and lives in `check`: `profile {name, source, digest, extends, selected, excluded,
  excluded_ids}`, `tuning {path, digest}` (absent without `--tuning`), `params` (controls that declare params, as
  before), `param_sources` (same keys; `default` | `profile` | `tuning`), each row's `severity_source` (`importance` |
  `profile`); the table's second line is `profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>])`
  or `(<total> controls)`. `waiver.Apply(results, known, excluded, …)` counts a waiver on an excluded control
  `not_applied` (warned, no row). The exit code and `--fail-on` read statuses, not severity. `controls lint --profile`
  (full lint + the profile line; CI runs it with `default`) and `controls list --profile` (the four-column rows of the
  selection) share the same resolution. The examples gate byte-compares reports, so a change to the `check` block
  needs an examples refresh from the branch's `examples.yml` run before the merge.

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
