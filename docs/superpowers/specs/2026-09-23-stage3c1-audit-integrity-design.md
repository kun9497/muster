# Stage 3C-1 — audit pipeline health and package integrity

*English · [한국어](2026-09-23-stage3c1-audit-integrity-design.ko.md)*

This document is the design for plan 3C-1 of muster: the first half of the sub-project the
main design (`2026-09-02-muster-design.md`, §10.2 "Stage 3") reserved as "3C audit /
exposure / root-equivalent paths (and package verification, W-8)". On 2026-09-21 the
sub-project was split by theme: **3C-1 "integrity"** — does the host record what happens to
it, and can it tell that its own files have not been changed — and **3C-2 "exposure and
privilege"** — the process collector, the socket → process → package → firewall cross-check
and root-equivalent paths, with the items 3A and 3B parked for 3C (network sysctls, file
capabilities and ACLs in the walk). This document is 3C-1 alone; 3C-2 gets its own
design once 3C-1 has merged. Decisions are numbered I-1 … I-12 and bind the plan. A fresh
review on 2026-09-23 (4 blocking, 10 medium, 16 low findings) and a measurement on the lab
host (`dpkg --verify`: 10 min 20 s wall, 1199 `missing` rows, exit 0) are folded in, and so
are the plan's pre-flight corrections of 2026-09-23 (J-1 … J-6 in the plan: the `auditctl`
exit codes, what a container can answer, dpkg's exit code and line form, the AIDE facts of the
three releases, the directory modes); where this version differs from the first draft, the
difference is theirs. Every
check here is written from primary sources — `auditd.conf(5)`, `auditctl(8)`,
`augenrules(8)`, `aide(1)` and `aide.conf(5)`, `sudoers(5)`, `rpm(8)`, `dpkg(1)`,
`journal-upload.conf(5)` — in muster's own wording, carries no CIS recommendation number,
and reproduces no benchmark text (§11 of the main design, D04).

Four choices were made in brainstorming and shape everything below: the split above (Q1);
package verification is the whole database, `rpm -Va` / `dpkg --verify` with fixed
arguments, run only under `--deep` (Q2) — so the `CommandTemplate` that 3A's W-8 expected
is not built, because nothing needs a variable argument tail any more; the auditd side
judges the pipeline's health and records the rules as evidence without judging their
content (Q3); AIDE is the file-integrity tool muster models, and a host that runs another
tool is reported for review with the tool named (Q4).

## 1. Goal

Add nine controls of category `beyond` — five on the audit daemon, one on log forwarding,
one on sudo's own log, one on the file-integrity tool, one on package integrity — fed by
three new collectors (`audit`, `fim`, `pkgverify`), two extensions (`sudo.log.*` in the
sudo reader, `journal-upload` and the rsyslog remote targets in `logging`), two new
rows of the `services` table (`auditd`, `journal_upload`) and two `collect` flags
(`--verify-timeout`, `--no-verify`). After 3C-1 the control set is
96 controls (68 for the 67 items, unchanged, plus 28 beyond), `controls/VERSION` is
`kisa-unix-2026+2026.09.23`, and `schema_version` is unchanged (keys and record fields
are added, none changed; main §5.7).

Out of scope, named so the plan does not drift: everything of 3C-2 (above); judging which
audit rules a host must carry (that is a benchmark's table, and it belongs with the CIS
profile of 3D, where `references.cis` can carry it); automatic verdicts for tools other
than AIDE; the freshness of the AIDE database; the join of verify rows with the walk's
package table (the two tools print no package name, and the join arrives with 3C-2's
process → package work); sudo's session recording (`log_input`, `log_output`) — not even as a fact, since
nothing here would read it;
whether a remote log path is encrypted. "journald persistent" was listed under audit
pipeline health in the main design and is **not** a control here: U-65 (`syslog_policy`)
already judges it on a journald-only host and file persistence on an rsyslog host, so a
second control would be the same verdict under a second id.

## 2. Principles carried from 3B

1. **The verdict reads the running state; the persisted file is evidence and the answer to
   "does it survive a reboot".** The audit daemon's rules and its immutable flag are
   two-home settings: `auditctl -l` / `auditctl -s` (fixed arguments, root) on the runtime
   side, the rules files on the persisted side, `default_on: effective` where effective is
   a copy of runtime as in 3B's sysctl (K-3).
2. **Commands have fixed arguments and an exit code is data.** `rpm -Va` exits 1 to say
   "something differs" — the `patch` collector already reads `dnf check-update`'s 100 and
   `needs-restarting`'s 1 the same way; `dpkg --verify` with no arguments always exits 0
   (its `verify()` returns a failure only for a named package that is not installed; the
   lab's 1199 `missing` rows exited 0), so the verdict is read from the rows and the exit
   code only decides between "answered" (0, or 1 with rows) and "failed". `auditctl` gates
   on the effective `CAP_AUDIT_CONTROL`, not the uid, and refuses with exit 4 before it
   touches the kernel; as root, a kernel that will not answer is told from its stderr and
   exit 255 (I-3). Any other code is `error` naming the command and the code.
3. **A path a daemon's configuration names belongs to that daemon's collector** (C1):
   `auditd.conf`'s `log_file`, `aide.conf`'s `database_in`. Permission facts are the nine
   leaves `writePermFacts` writes, no more.
4. **Noise is filtered and the filter is a fact.** What was removed from the verify output,
   by which rule, and how many rows, is in the snapshot; a PASS whose filter cannot be read
   back is not a PASS anyone can check.
5. **Every beyond control gates on `env.container eq none`.** One control depends on
   `--deep`; a run without it leaves the `packages.verify.*` keys unwritten exactly as the
   walk leaves `walk.*`, and the control reads MANUAL ("run collect --deep") through the
   rule of I-9. Without root, `packages.verify.complete` is `denied` and nothing else is
   written, as `walk.complete` is. The two commands are slow and disk-bound (the lab's
   `dpkg --verify` took ten minutes for twenty seconds of CPU), so they have their own
   limit: `--verify-timeout` (default 30 min) is the command timeout, `--deep` raises the
   default `--timeout` to walk budget + verify timeout + 5 min (collectors run one after
   another under the one deadline, and `pkgverify` sorts before `walk`, so the sum is what
   keeps a slow verify from starving the walk), and `--no-verify` keeps a deep run at its
   3A cost — the `packages.verify.*` keys stay unwritten and the control reads MANUAL
   naming the flag.
6. **Every parser is fuzzed and, where a daemon can answer, compared with it.** The three
   new parsers (audit rules, `auditd.conf`, verify output) and the four small ones
   (the `auditctl -s` reader, sudoers `Defaults`, `aide.conf` macros,
   `journal-upload.conf`) each get a `Fuzz<Name>` target with seeds; the verify parser is
   compared with the real `rpm -Va` and `dpkg --verify` output, and the runtime reader
   with `auditctl`, inside CI's containers (I-11).

## 3. Facts and collectors (I-3 … I-7)

Sixty-four registry keys: 34 `audit.*`, 9 `fim.*`, 7 `packages.verify.*`, 3 `sudo.*`,
3 `logging.*`, 8 `services.*`. No key is a prefix of another (the Builder refuses a leaf
beneath a leaf), which is why the rules list is `audit.rules.persisted` and not
`audit.rules`. Sensitivity is `public` unless said otherwise. Every list is
sorted and capped, with `truncated: true` on the key when the cap was hit.

### I-3 — the `audit` collector

Declaration: reads `/etc/audit/auditd.conf`, `/etc/audit/audit.rules`,
`/etc/audit/rules.d` (stat: the primitive's `Glob` cannot tell a missing directory from an
empty one, so the directory is probed first), `/etc/audit/rules.d/*.rules` (Glob), and, for
stat only, `/var/log`, `/var/log/audit`, `/var/log/audit/*` and `/var/log/*`; commands `/usr/sbin/auditctl -l` and
`/usr/sbin/auditctl -s` (5 s, 1 MiB each; on EL9 `/sbin` is a link to `usr/sbin`, so one
path serves both families).

- `audit.rules.present` — `setting<bool>`. Runtime: `auditctl -l` printed at least one
  rule line (its "No rules" is false). Persisted: at least one rule line (`-w`, `-a`, `-A`)
  in the persisted source. `audit.rules.loaded_count` and `audit.rules.persisted_count`
  are the two counts (`int`), evidence. `audit.rules.persisted` is `list<record>` `{file,
  line, kind, key, text}` (`internal`; `line` the line number; `kind` ∈ watch | syscall |
  control | other; `key` the `-k`/`key=` value or empty; capped at 2000 rows), the
  persisted rules as read, in file order — `augenrules` strips comments and regroups the
  control lines (`-D` first, `-e` last) before loading, so this list is the files, not the
  merged `audit.rules`.
- **The persisted source models `augenrules(8)`, which is the only loader on a systemd
  host** (`ExecStartPost=-/sbin/augenrules --load` on both families; the daemon never reads
  `/etc/audit/audit.rules` itself): the persisted answer is the `*.rules` files of
  `/etc/audit/rules.d/` in the `ls -1v` version-sort order augenrules reads them in
  (`9-x.rules` before `10-y.rules`, `99-` before `100-`). An empty directory is a persisted
  answer of "no rules" (augenrules regenerates an empty `audit.rules`); a **missing**
  directory makes `/etc/audit/audit.rules` the source — augenrules prints "No rules
  directory" and loads that file — with the ok envelopes noting the fallback; when neither
  exists the persisted side is `absent` ("neither /etc/audit/rules.d nor
  /etc/audit/audit.rules exists"). `/etc/audit/audit.rules` is also the source on a host
  without systemd. (Corrected during execution against the augenrules script, v2.8.5–v4.0;
  the plan's J-23 said lexical order and "loads nothing".) The source of each persisted envelope
  names the file(s) read; `audit.immutable`'s `winner` names the file that carried the
  deciding line.
- `audit.immutable` — `setting<bool>`. Runtime: `auditctl -s` reports `enabled 2`.
  Persisted: the **last** `-e` line of the persisted source, in load order, is `-e 2`
  (`auditctl(8)`: once `-e 2` is set the configuration is locked until reboot; a later
  `-e` line cannot take effect, so the last one written is the administrator's intent).
- `audit.status.enabled`, `audit.status.failure`, `audit.status.lost`,
  `audit.status.backlog_limit` — `int`, the four fields of `auditctl -s` as printed,
  evidence.
- `audit.conf.log_file`, `audit.conf.log_group`, `audit.conf.max_log_file_action`,
  `audit.conf.space_left_action`, `audit.conf.admin_space_left_action`,
  `audit.conf.disk_full_action`, `audit.conf.disk_error_action` — `string`, the value
  lower-cased (`auditd.conf(5)` reads them case-insensitively). A key whose line is
  missing is `absent` naming the key: `auditd.conf(5)` documents a compiled default for
  each, but the default is the daemon's decision, not the administrator's, and 3B's
  core-dump rule applies — muster does not substitute a daemon's default for a decision
  nobody made. The one exception is `log_file`: when its line is missing the collector
  looks at the documented default path `/var/log/audit/audit.log`, records the source as
  `derived` from `auditd.conf`, and the file's own existence is the proof; there is no verdict on the path
  string, only on the file it names.
- `audit.log_file.*` and `audit.log_dir.*` — the nine permission leaves each (`mode, uid,
  gid, group, group_readable, group_writable, other_readable, other_writable,
  acl_present`), of the file `log_file` names and of its parent directory. A `log_file`
  outside the declared stat patterns is C4: `absent` with the path in the reason, never
  `error`.
- Status rules (J-1). `auditctl` not on the host: the runtime side is `absent` ("auditctl
  is not installed"), never `unsupported` — the kernel may hold rules nobody can list, and
  the controls that need the runtime side are gated on the daemon being installed anyway.
  `auditctl` gates on the effective `CAP_AUDIT_CONTROL` (`audit_can_control()`), so `You
  must be root to run this program.` with exit 4 is `denied` when the run is not root and
  `unsupported` ("no CAP_AUDIT_CONTROL: an unprivileged container") when it is. The kernel
  refuses `AUDIT_GET` and `AUDIT_LIST_RULES` from any pid namespace but the initial one
  before it looks at capabilities, which `auditctl` reports as `Error sending status
  request (Operation not permitted)` (or `… rule list data request …`) with exit 255:
  `unsupported` ("kernel audit is not reachable from this pid namespace") — every
  container, privileged or not, reads that. A non-init user namespace gets ECONNREFUSED,
  which `auditctl -s` swallows (`The audit system is disabled`, exit 0, no `enabled` line):
  an exit 0 with no `enabled` line is `unsupported` ("the kernel gave no audit status"),
  never a value. `audit support not in kernel` / `Cannot open netlink audit socket`
  (`audit=0`, a kernel without `CONFIG_AUDIT`) is `unsupported`. Any other non-zero exit is
  `error`. `/etc/audit` and `rules.d` are 0750 root on both families; `/var/log/audit` is
  0700 root on EL and 0750 root:adm on Ubuntu (`log_group = adm` by Ubuntu's patch, the log
  file 0640 root:adm), so a non-root run outside group adm reads every persisted and
  permission leaf `denied` on a host with auditd; on a host without auditd they are
  `absent`, which is why the capability matrix's non-root row (§6) is asserted only where
  auditd is installed.

### I-4 — the `fim` collector

Declaration: stat of `/usr/bin/aide`, `/usr/sbin/aide`, `/usr/sbin/tripwire`,
`/usr/sbin/samhain`, `/usr/bin/osqueryd`, `/opt/osquery/bin/osqueryd`,
`/usr/sbin/integrit`, `/var/ossec/bin/wazuh-agentd`, `/var/ossec/bin/ossec-agentd`; reads
`/etc/aide/aide.conf`, `/etc/aide.conf`, `/etc/aide/aide.conf.d/*` (names only),
`/etc/default/aide`, `/etc/cron.daily/*` (names and mode), `/etc/cron.d/*`,
`/etc/crontab`; stat of `/var/lib/aide/*`; one fixed command, `systemctl list-timers
--all --no-legend --no-pager`, whose rows carry the next elapse time — the unit-file
inventory the `cron` collector uses says whether a timer is enabled, not whether it is
armed, and a `static` timer pulled in by a target is armed without being enabled.

- `fim.tool` — `string`: `aide` when the AIDE binary exists; `none` when no binary of the
  list exists; **`absent`** when AIDE is missing and at least one other tool's binary
  exists, with the reason naming them ("aide is not installed; other tools present:
  osqueryd (/usr/bin/osqueryd)"). This is the leaf the control's mechanisms select on, and
  its `absent` is what turns such a host into MANUAL with the evidence attached (§4) —
  the key means "the file-integrity tool muster models on this host", and on that host
  there is none, though there is a tool.
- `fim.aide.installed` — `bool`. `fim.aide.config_path` — `string`, the first of
  `/etc/aide/aide.conf` (Debian family) and `/etc/aide.conf` (EL) that exists; `absent`
  when neither does.
- `fim.aide.database_path` — `string`: the `file:` value of `database_in=` (aide ≥ 0.17),
  else of `database=` (older), from the configuration file, with `@@define NAME value`
  macros substituted into `@@{NAME}` references (EL9's `aide.conf` uses them; Ubuntu's has
  literal paths); every other `@@` directive (`@@include`, `@@x_include`,
  `@@x_include_setenv`) is ignored; a reference to a macro the file never defined is left
  as written and the reason says so. `fim.aide.database_present` — `bool`,
  a regular file at that path. `fim.aide.database_modified` — `string`, its mtime as
  RFC 3339 UTC, evidence.
- `fim.aide.schedules` — `list<record>` `{kind, path, armed, detail}`, `kind` ∈
  cron_daily | cron_d | crontab | timer; `armed` says the row will actually run and
  `detail` why not (J-5). A file under `/etc/cron.daily/` whose name contains `aide` is
  armed when it has the execute bit (`run-parts` skips the rest), when `/etc/default/aide`
  does not set `CRON_DAILY_RUN` to a value other than `yes` (the file ships the line
  commented and both scripts default it to `yes`, so a stock host is armed), and when it is
  not the Ubuntu 24.04 shim, which exits whenever `/run/systemd/system` exists (detected by
  that literal in the file; on a systemd host the row is `armed: false`, `detail: "runs
  only without systemd"`). A non-comment line of `/etc/cron.d/*` or `/etc/crontab` whose
  command names `aide` is armed (a commented-out line is the usual way a check is switched
  off and is not a row). A timer whose name contains `aide` — `dailyaidecheck.timer` on
  Ubuntu 24.04 (enabled by the package), `aide-check.timer` on EL9 (shipped, preset-disabled),
  an administrator's own — is armed when `systemctl list-timers --all` shows a next elapse
  time for it and the `CRON_DAILY_RUN` gate holds (the 24.04 service reads the same file).
  `fim.aide.scheduled` — `bool`, at least one armed row. A host without systemd lists cron
  rows only; a host whose timer inventory cannot be read has both leaves `unsupported`
  naming the reason.
- `fim.other_tools` — `list<record>` `{name, path}`, every other binary found.

### I-5 — the `pkgverify` collector

Declaration: commands `/usr/bin/rpm -Va` and `/usr/bin/dpkg --verify` (timeout
`--verify-timeout`, 64 MiB each; the family decides which one runs, as `patch.go`
decides); reads of `/var/lib/dpkg/info/*.md5sums` and `*.list` names only, for the
coverage count below, and of `/etc/dpkg/dpkg.cfg` and `/etc/dpkg/dpkg.cfg.d/*` for the
`path-exclude` globs. The collector runs only when `--deep` was given without
`--no-verify` and the run is root (principle 5): otherwise it writes nothing, except that
without root it writes `packages.verify.complete` as `denied` ("package verification
needs root: an unprivileged rpm -Va marks every file it cannot read as untestable").

- `packages.verify.complete` — `bool`: true when the command exited 0, or exited 1 with at
  least one parsed row, and its output was not truncated. Exit 1 with **no** parsed row is
  `error` carrying the first lines of stderr — `rpm -Va` on a locked or corrupt database
  prints its complaint to stderr, exits 1 and prints nothing else, and a host that cannot
  read its own package database must never PASS as unmodified. A killed command is
  `timeout`; any other exit code is `error` naming it; an output at the cap is `ok` false
  with `truncated: true` and a reason naming the cap, which the deep gate reads as row 10
  (I-9). `packages.verify.tool` — `string`, `rpm` or `dpkg`.
- `packages.verify.modified` — `list<record>` `{path, attributes, file_type}`
  (`internal`, capped at 5000, `subject_kind: file`): the rows left after the filter.
  `attributes` is the list of the columns that differed, in the tool's order and by name:
  `size, mode, digest, device, link, user, group, mtime, caps` for the nine columns
  `S M 5 D L U G T P` of `rpm(8)`, and `missing` for a `missing` line; `dpkg --verify`
  prints the same nine-column form (`--verify-format rpm` is its only format) and fills
  only `digest` and, for a path that is no longer a regular file, `mode`. The two tools
  differ by a space: rpm puts two spaces between the columns and the type letter, dpkg one
  (J-4), and both may append a note in parentheses — ` (Permission denied)` on a file the
  caller could not stat, ` (not installed)` / ` (replaced)` on a file in a non-normal rpm
  state — which the row keeps in `note`. `file_type` is the type letter as a word
  (`config, doc, ghost, license, readme, artifact` — rpm ≥ 4.14 prints `a` for
  `%artifact`) or empty; a letter the parser does not know (`s`, `m`, `n`) is kept as the
  letter and the row is never dropped for it.
- `packages.verify.modified_config` — the same record shape and sensitivity, the
  configuration-file rows (type `c`, and dpkg's conffiles, which it marks `c` too) —
  evidence for the reader, not judged: a changed configuration file is what
  administration looks like.
- `packages.verify.filter` — `list<string>`, the rules applied, in order, always the seven:
  `config` (type `c` → `modified_config`), `doc` (type `d`, `l` or `r`, **or a path under
  `/usr/share/doc/`, `/usr/share/man/`, `/usr/share/info/` or `/usr/share/locale/`** →
  dropped: dpkg has no documentation type letter, and the lab's 1199 `missing` rows were
  all documentation a minimised install never wrote), `dpkg_excluded` (a path matching a
  `path-exclude` glob of `dpkg.cfg` / `dpkg.cfg.d` → dropped: the administrator told dpkg
  not to install it), `ghost` (type `g` → dropped: the file is not shipped), `mtime_only`
  (the only differing column is `T` → dropped: a touched file with its content, mode and
  owner intact), `unverifiable` (no column differs and at least one is `?` → dropped: the
  tool could not test it), `unchanged` (no column differs and none is `?` — rpm prints such a row
  only for a state note such as `(not installed)` or `(replaced)` → dropped: nothing differs).
  Recording the list even though it is constant is what lets a
  later filter change be seen in a snapshot's date.
- `packages.verify.filtered_counts` — `record` `{config, doc, dpkg_excluded, ghost,
  mtime_only, unverifiable, unchanged}` (`int` each). `packages.verify.stats` — `record` `{lines,
  exit_code, duration_ms, truncated, stderr_head, packages_without_digests,
  dpkg_path_excludes}`; `stderr_head` the first three stderr lines and `unparsed_head` the first three lines the
  parser could not classify (empty when none);
  `packages_without_digests` is, on a dpkg host, the number of
  `/var/lib/dpkg/info/*.list` files with no `*.md5sums` beside them — the packages
  `dpkg --verify` silently cannot check — and 0 on an rpm host; `dpkg_path_excludes` the
  globs applied by the `dpkg_excluded` rule.
- A verify line that matches neither the nine-column form nor `missing` is counted in
  `stats.lines` and the first three such lines are kept in `stats.unparsed_head` without
  failing the key (rpm prints warnings to stdout on some hosts).

### I-6 — two extensions

- **`files_sudo`** gains `sudo.log.syslog` (`bool`: false only when an unscoped
  `Defaults` line negates it, `!syslog`; the option is on by default in `sudoers(5)` and
  a `syslog=facility` value keeps it on), `sudo.log.logfile` (`string`, the unscoped
  `logfile=` value with quotes stripped, `""` when none) and `sudo.defaults.scoped_count`
  (`int`: `Defaults:user`, `Defaults@host`, `Defaults>runas`, `Defaults!command` lines,
  counted and not interpreted — a scoped default changes one persona and the leaves say
  what the host does by default; the count tells the reader that such lines exist). A
  `Defaults` line is a comma-separated option list (`Defaults env_reset, !syslog,
  logfile="/var/log/sudo.log"`) with quoted values. Lines are read from `/etc/sudoers` and
  every file of the `@includedir` / `#includedir` directory in `sudoers(5)`'s order
  (lexical, names with `.` or ending in `~` skipped), backslash continuations joined,
  later lines winning. `/etc/sudoers` is 0440 root on both families (`sudoers.d` is 0750 on
  EL and 0755 or 0750 on the Debian family depending on the release and the image; its
  files are 0440), so a non-root run reads the three leaves as that read's status (C3) and
  the matrix's non-root row carries them.
- **`logging`** gains `logging.rsyslog.forwards_remote` (`bool`: at least one parsed
  rsyslog action is a remote target — `@host`, `@@host`, `:omfwd:`, `action(type="omfwd")`,
  which the parser already classifies as `remote` — **whose host is not loopback**
  (`127.0.0.0/8`, `::1`, `localhost`: a relay into a local shipper leaves nothing by
  itself and stays in the evidence list only); false when rsyslog is not installed,
  because then nothing forwards; `absent` when the implementation is syslog-ng ("not
  modelled") or `none` (sysklogd, BusyBox: U-65 reads those MANUAL for the same reason)),
  `logging.rsyslog.remote_targets` (`list<record>` `{rule, target, loopback}`, `internal`,
  evidence; `rule` the action text the parser kept), and `logging.journal_upload.url`
  (`string`, `internal`: the `URL=` of `[Upload]` in `/etc/systemd/journal-upload.conf`
  and `journal-upload.conf.d/*.conf`, last wins, kept as written — `systemd-journal-upload(8)`
  accepts a bare hostname and defaults the scheme to https; `""` when no file or no
  line — no file is no URL, a fact and not a default).
- **`services`** table: `auditd` {`auditd.service`} and `journal_upload`
  {`systemd-journal-upload.service`}, both `provesInstall: true`, giving the eight leaves
  `services.<name>.installed / active / enabled / unit_file_state` by the table's rules
  (`unsupported` without systemd).

### I-7 — what is not a fact

No `audit.rules.*` leaf says whether a particular rule exists; no `fim.*` leaf says the
database is fresh; no `packages.verify.*` leaf names a package. Each is in §7.

## 4. Controls (I-8)

Nine controls, `category: beyond`, ids `muster.beyond.<name>`, files under
`controls/beyond/`, every one with `applies_when: env.container eq none` first. Importance
is muster's own rating from the primary source and the description says why.

| id | importance | automation | further gate | judgment | `absent_means` |
|---|---|---|---|---|---|
| `auditd_active` | 상 | auto | — | `services.auditd.installed`, `.active`, `.enabled` all true | fail |
| `audit_rules_loaded` | 상 | auto | `services.auditd.installed eq true` | `audit.rules.present eq true` on `runtime` and on `persisted` — rules loaded by hand are lost at reboot, so both homes | fail |
| `audit_immutable` | 중 | auto | same | `audit.immutable eq true` on `runtime` and on `persisted` | fail |
| `audit_disk_actions` | 중 | auto | same | `space_left_action` and `admin_space_left_action` `in ${allowed_space_actions}` (default `[syslog, email, exec, rotate, single, halt]`), `disk_full_action in ${allowed_disk_full_actions}` (default `[syslog, rotate, exec, single, halt]`), `disk_error_action in ${allowed_disk_error_actions}` (default `[syslog, exec, single, halt]`) — each default is `auditd.conf(5)`'s value list for that key minus `ignore` (records are lost and nothing is said) and `suspend` (one syslog line, then records are lost while the host runs on); `max_log_file_action in ${allowed_rotate_actions}` (default `[rotate, keep_logs, syslog]`) | manual — a missing line lets the daemon's compiled default decide, which nobody chose |
| `audit_log_permissions` | 중 | auto | same | `audit.log_file.uid eq 0`, `audit.log_file.mode in ${allowed_modes}` (the eight bit-subsets of 0640 — 0640 rather than 0600 because Ubuntu's `log_group = adm` makes it the shipped state), `audit.log_dir.uid eq 0`, `audit.log_dir.other_readable eq false`, `audit.log_dir.other_writable eq false`, `audit.log_dir.group_writable eq false` (bits, not a 32-element list; no `other_executable` leaf exists, so 0751 passes) | manual — the file is where muster does not read (C4 names the path) or was never written; either needs a look, and `auditd_active` already says whether the daemon runs |
| `remote_log_forwarding` | 하 | auto | — | mechanisms: `logging.rsyslog.forwards_remote eq true` → `services.syslog.active eq true`; `logging.journal_upload.url ne ""` → `services.journal_upload.active eq true` and `.enabled eq true` (an enabled unit that failed at boot ships nothing); `logging.rsyslog.forwards_remote eq false` → `logging.rsyslog.forwards_remote eq true` (fails by construction: nothing leaves the host; the URL leaf cannot serve here because it is `unsupported` without systemd) | manual — a syslog-ng or sysklogd host has `forwards_remote` absent and an empty URL, so no mechanism holds |
| `sudo_logging` | 중 | auto | `sudo.installed eq true` | mechanisms: `sudo.log.syslog eq true` → passes on that; `sudo.log.syslog eq false` → `sudo.log.logfile matches ^/` | fail |
| `file_integrity_tool` | 중 | auto | — | mechanisms: `fim.tool eq aide` → `fim.aide.database_present eq true`, `fim.aide.scheduled eq true`; `fim.tool eq none` → `fim.tool ne none` (fails by construction: no tool) | manual — a host with only an unmodelled tool has `fim.tool` absent, selects no mechanism, and reads MANUAL; the evidence the row carries is `fim.tool` itself, whose reason names the tools found (the evaluator attaches the `when` facts, not `fim.other_tools`) |
| `package_files_unmodified` | 상 | auto | `--deep` (I-9) | `packages.verify.modified` `op: none, subject: path, where: {field: path, op: present}` — the deep gate reads `packages.verify.complete` before any check, so the control names no clause on it | fail |

The mechanism shape follows 3B's core-dump control: the last mechanism's `when` holds on
every judged host and its check fails, so "nothing configured" is FAIL. What reaches
`absent_means` is "no mechanism was chosen", which the evaluator applies whether the
`when` facts were absent, unsupported or simply evaluated false — main §6.5 row 5 says
only the first two, and D30 amends it to what is implemented, because
`remote_log_forwarding`'s MANUAL path (an `ok` empty URL beside an absent
`forwards_remote`) leans on the third. The two-clause `runtime` + `persisted` shape of the
audit controls is deliberate and departs from §5.3's `on: both`, which reads a one-sided
host as WARN: rules in files that the daemon never loaded, or loaded rules that the next
boot forgets, are each a FAIL here, and the description says which home the reader
should look at. A `packages.verify.modified` list that hit its cap reads ERROR
(`truncated`, exit 2), as a walk list does; the description says so. A kernel booted with
`audit=0` reads the two runtime controls NOT_APPLICABLE (`unsupported`); `auditd_active`
is the control that fires there (`ConditionKernelCommandLine=!audit=0` keeps the unit
inactive), and its description says so.

The stock readings the plan pins (I-11): **Ubuntu 22.04**, no auditd, no AIDE —
`auditd_active` FAIL, the four audit detail controls NOT_APPLICABLE (gate),
`remote_log_forwarding` FAIL, `sudo_logging` PASS, `file_integrity_tool` FAIL,
`package_files_unmodified` PASS on the public image (the GitHub runner VM reads FAIL, and
that is the truth of an image its provider customises). **EL9** (Rocky, Alma), auditd
active with the shipped `rules.d/audit.rules` (`-D`, `-b`, `-f`, no watch or syscall
rule, no `-e`) and `admin_space_left_action`, `disk_full_action` and
`disk_error_action` all `SUSPEND` —
`auditd_active` PASS, `audit_rules_loaded` FAIL, `audit_immutable` FAIL,
`audit_disk_actions` FAIL, `audit_log_permissions` PASS (0700 directory, 0600 file), the
rest as Ubuntu. Three FAILs on a stock EL9 say what is true: the daemon runs and audits
nothing.

`references.stig` entries exist in the committed index for the auditd package and service,
the disk actions, the log file and directory ownership and mode, AIDE installed and
scheduled, immutable rules and remote log offloading — not every rule on every benchmark
(the 24.04 index has no disk-full rule, the 22.04 index no immutable-rules rule); the
plan's pre-flight resolves the ids against the index as 3B's did. `references.nist_800_53` is the union of the cited rules' ids — AU-3, AU-4, AU-5, AU-5(1),
AU-9, AU-12, SI-11 across the audit controls, AU-4(1) for forwarding, SI-6 and CM-3(5) for
the integrity tool — and, where no rule is cited, an id the index carries: AU-3 for sudo,
CM-6 for package files (`SI-7`, `AU-2` and `AU-9(2)` appear in no indexed rule).

## 5. The deep-based rule (I-9, D30)

Rows 9, 10 and 10a of main §6.5 say what happens to a **walk-based** control when the walk
was not run, did not complete, or could not run. Package verification has the same three
states for the same reason (it runs only under `--deep`, only as root, and can time out),
so the rows are widened from "walk-based" to **deep-based**: a control that references any
`walk.*` key or any `packages.verify.*` key. The completeness fact is `walk.complete` for
the first set and `packages.verify.complete` for the second; the reason codes are
`walk_incomplete` and `verify_incomplete`. A completeness fact that is `unsupported` (a host
with no package database) reads NOT_APPLICABLE with `unsupported_env`, a fourth branch the
walk never needed. The evaluator's test that pins rows 9–10a gains
the second family; `verify_incomplete` joins the fixed reason-code vocabulary of main
§7.2, and the JSON and table goldens are regenerated once for it. D30 also rewrites row 5
to the implemented rule (§4). This is the only evaluator change of 3C-1.

## 6. Environments (I-10)

- **Root.** Everything answers. `auditctl` needs `CAP_AUDIT_CONTROL`; `rpm -Va` /
  `dpkg --verify` run under `--verify-timeout` inside the raised `--deep` deadline
  (principle 5) and their duration is in `packages.verify.stats`.
- **Non-root.** On a host with auditd the four audit detail controls are ERROR naming the
  denial (rules files, `auditd.conf`, `auditctl`, the log directory — every one is
  root-only on both families); `services.auditd.*` still answers (`systemctl show`);
  `pkgverify` writes the `denied` completeness key alone; `sudo.log.*` is the read's
  status of `/etc/sudoers`. The capability matrix's `nonroot.denied` row gains the 34
  `audit.*` keys, `packages.verify.complete` and the three `sudo.log.*` /
  `sudo.defaults.*` keys, and CI's non-root job installs `auditd` so that the row is
  about a denial and not about a missing package (I-11). AIDE paths are release-dependent:
  readable on Ubuntu 22.04, but EL installs `/etc/aide.conf` 0600 and `/var/lib/aide` 0700
  and Ubuntu 24.04 creates `/var/lib/aide` 0700 `_aide:root`, so a non-root run there reads
  `fim.aide.database_*` `denied` and `file_integrity_tool` ERROR — the matrix does not
  assert those keys either way, as K-31 left `protected_*` out. `journal-upload.conf` and `cron.daily` are readable without root.
- **Container.** No container can answer `auditctl` or run `auditd`: the kernel refuses
  the audit netlink requests from every pid namespace but the initial one (J-1), so a
  privileged init container — CI's EL images — reads the runtime sides `unsupported` and
  its `auditd.service` fails to register (`services.auditd.installed` true, `.active`
  false); an unprivileged container reads `unsupported` through the capability gate; a
  non-init user namespace through the silent ECONNREFUSED. None of it is a capability row:
  every one of the nine controls is NOT_APPLICABLE on the container gate regardless, so
  nothing is added to `container.unsupported`, and the runtime paths of the audit
  collector are proven on the runner VM (below). `pkgverify` runs in a container (the
  package database is there) and CI uses that to compare the parser with the real tools
  (I-11).
- **No systemd.** `services.auditd.*` and `services.journal_upload.*` are `unsupported`
  by the table's rule; `fim.aide.schedules` holds cron rows only.
- **Family differences.** `/usr/sbin/auditctl` on both, and the shipped
  `rules.d/audit.rules` is the same `10-base-config` text on both (control lines only, no
  `-e`), so a host that installs auditd and nothing else reads `audit_rules_loaded` and
  `audit_immutable` FAIL on either family. AIDE: `/usr/bin/aide` and `/etc/aide/aide.conf`
  on the Debian family, `/usr/sbin/aide` and `/etc/aide.conf` (0600) on EL; the database
  name comes from the configuration (`aide.db` there, `aide.db.gz` on EL through
  `@@define`); Ubuntu 22.04 ships `/etc/cron.daily/aide`, 24.04 `dailyaidecheck.timer`
  beside a cron.daily shim of the same name, EL9 `aide-check.timer` preset-disabled (J-5).
  `rpm -Va` fills nine columns and prints type letters; `dpkg --verify` fills the digest
  column (and `mode` for a non-regular file) and marks conffiles `c`. sudo logs through
  syslog on both by default.
- **The lab and the runner.** The lab host (Ubuntu 22.04, kernel 5.15, root) carries
  neither auditd nor AIDE, so it proves the stock-Ubuntu column of §4, the verify path
  (`dpkg --verify`, 10 min 20 s, 1199 documentation rows filtered) and the non-root
  denial of `pkgverify`; nothing is installed on it. The passing paths of the audit
  controls are proven by fixtures and by CI, where the plan arranges what the images do
  not ship (J-2): `apt-get install auditd aide aide-common` in the runner VM's root job —
  the one environment where auditd runs and `auditctl` answers — and `auditd` in the
  non-root job; `dnf install audit aide` in the two EL init containers, which prove the
  degraded shapes (`services.auditd.installed` true and `.active` false, the runtime sides
  `unsupported`, `fim.tool` `aide` with no database). The examples workflow installs
  nothing, so the committed VM example keeps the stock reading; its `--deep` run will list
  modified package files, and the FAIL on `package_files_unmodified` there is expected.

## 7. Tests, CI, documents (I-11, I-12)

**I-11 — the 3F gates are the gates.** Every control has `pass-` and `fail-` fixtures and
`na-` fixtures (the container; for the four gated audit controls also "auditd not
installed"); `audit_disk_actions`, `remote_log_forwarding` and `file_integrity_tool` have
`manual-` fixtures (a missing action line; a syslog-ng host; a host with osquery and no
AIDE). The mutation test stays at zero survivors, an equivalent mutant goes into
`_mutants.yaml` with its reason. Two whole-host synthetic snapshots under
`controls/testdata/_hosts/` — the stock Ubuntu 22.04 reading and, new, a stock EL9
reading — pin the two columns of §4 at once through `hosts_test.go`. Seven `Fuzz<Name>`
targets with seeds, enforced by the inventory test: the audit rules parser, the
`auditd.conf` parser, the `auditctl -s` reader, the verify-output parser, the sudoers
`Defaults` reader, the `aide.conf` macro reader, the `journal-upload.conf` reader. Two
oracle pairs under `MUSTER_ORACLE=1`: `TestOracleVerify` runs the family's tool itself
(`dpkg --verify` on the runner VM and the lab, `rpm -Va` in the Rocky and Alma init
images), parses it with test-owned code and requires the set of paths to agree with the
collector's rows plus its filtered counts and every line to reach a classification; it
never skips on a host with a package database. `TestOracleAudit` compares `auditctl -s`'s
`enabled` and `auditctl -l`'s rule count with the runtime reader; it skips only where
`auditctl` cannot reach the kernel (J-1), which the containers do and the runner VM, once
`auditd` is installed there, must not. Collectors are unit-tested through `memAccess` on the
present / absent / denied / truncated paths, proven on the lab (root and non-root) against
the stock-Ubuntu column, and the `--deep` run's row counts, filtered counts and duration
are recorded in the plan's Execution notes.

CI (J-2): the two EL init jobs install `audit aide` and assert with `jq` that
`services.auditd.installed` reads true, `audit.rules.present`'s runtime side reads
`unsupported`, `fim.tool` reads `aide` with `database_present` false, and
`audit_rules_loaded` reads NOT_APPLICABLE (the container gate, not `unsupported_env`);
the runner's root job installs `auditd aide aide-common`, passes `--deep --verify-timeout
20m` and asserts `services.auditd.active` true, the runtime side of `audit.rules.present`
`ok` and false, `packages.verify.complete` true with `tool` `dpkg`, and `fim.tool` `aide`;
its oracle step requires the audit and verify pairs to have compared; the non-root job
installs `auditd` and asserts `packages.verify.complete` `denied` and
`audit.conf.log_file` `denied`; the capability matrix test covers the new rows;
`examples.yml` is run once on the pull request and the six example files refreshed (the
control set changes, so the digest gate would otherwise skip their byte comparison).

**I-12 — documents.** The main design gains D30, the widened rows 9–10a and the rewritten
row 5 in §6.5, `verify_incomplete` in §7.2, the two flags in §8, and in §10.2 "3C-1
(merged)" with the remaining 3C-2 list and the sentence that closes W-8 ("whole-database
verification with fixed arguments; no `CommandTemplate`"). README (both
languages): the count sentence — "68 controls for the 67 items, and 28 beyond the guide" —
and the roadmap line. CHANGELOG under Controls (the nine, `controls/VERSION` →
`kisa-unix-2026+2026.09.23`), Collectors (the three, the two extensions, the two table
rows) and Tooling (the deep-based rule). CONTRIBUTING (both languages): one paragraph on
commands whose exit code is data. CLAUDE.md: a section "Integrity (stage 3C-1)" (the
deep-based rule and the flags; the auditctl codes; augenrules' order and fallback; what
`fim.tool`'s `absent` means). `coverage.md` regenerated. The plan
keeps its Execution notes as the earlier plans do.

## 8. Parked

- Judging the content of the audit rules (identity files, time, login records, modules,
  privileged commands): 3D, with the CIS profile and `references.cis`.
- An `auditctl` oracle against a rule set that is not empty: the runner VM's rule set is
  the shipped base configuration, so the pair compares `enabled` and a count of zero.
- `sudo.log.input` / `sudo.log.output` as facts and as a verdict; interpreting scoped
  `Defaults`.
- Automatic verdicts for Tripwire, Samhain, osquery, Wazuh (I-4's `fim.other_tools` is
  the seed); the AIDE database's age against `fim.aide.database_modified`.
- The join of `packages.verify.modified` with the walk's package table (owning package
  per row; cross-check with `walk.suid_sgid`): with 3C-2's process → package join.
- The receiving side of journal-remote; whether an rsyslog remote target is TLS.
- 3C-2 as split: the process collector, the exposure cross-check (only at full firewall
  confidence), root-equivalent paths (container-runtime sockets and groups,
  `ld.so.preload`, writable `ExecStart` of root units, root's `PATH`, file capabilities in
  the walk), network sysctls, and the four unassigned stage-3 items (dormant accounts,
  `sudoers` `NOPASSWD`/`ALL`, processes running deleted executables, `authorized_keys`
  inventory).
