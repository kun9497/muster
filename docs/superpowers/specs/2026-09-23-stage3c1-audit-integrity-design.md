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
design once 3C-1 has merged. Decisions are numbered I-1 … I-12 and bind the plan. Every
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
sudo reader, `journal-upload` and the rsyslog remote targets in `logging`) and two new
rows of the `services` table (`auditd`, `journal_upload`). After 3C-1 the control set is
96 controls (68 for the 67 items, unchanged, plus 28 beyond), `controls/VERSION` is
`kisa-unix-2026+2026.09.23`, and `schema_version` is unchanged (keys and record fields
are added, none changed; main §5.7).

Out of scope, named so the plan does not drift: everything of 3C-2 (above); judging which
audit rules a host must carry (that is a benchmark's table, and it belongs with the CIS
profile of 3D, where `references.cis` can carry it); automatic verdicts for tools other
than AIDE; the freshness of the AIDE database; the join of verify rows with the walk's
package table (the two tools print no package name, and the join arrives with 3C-2's
process → package work); sudo's session recording (`log_input`, `log_output`) as a verdict;
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
2. **Commands have fixed arguments and an exit code is data.** `rpm -Va` and
   `dpkg --verify` exit 1 to say "something differs" — the `patch` collector already reads
   `dnf check-update`'s 100 and `needs-restarting`'s 1 the same way. `auditctl` exits 1 for
   a permission it lacks or a kernel that does not answer, and the two are told apart by
   its stderr (I-3). Any other code is `error` naming the command and the code.
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
   written, as `walk.complete` is.
6. **Every parser is fuzzed and, where a daemon can answer, compared with it.** The three
   new parsers (audit rules, `auditd.conf`, verify output) and the three small ones
   (sudoers `Defaults`, `aide.conf` macros, `journal-upload.conf`) each get a `Fuzz<Name>`
   target with seeds; the verify parser is compared with the real `rpm -Va` and
   `dpkg --verify` output inside CI's containers (I-11).

## 3. Facts and collectors (I-3 … I-7)

Sixty-six registry keys: 34 `audit.*`, 9 `fim.*`, 7 `packages.verify.*`, 5 `sudo.*`,
3 `logging.*`, 8 `services.*`. Sensitivity is `public` unless said otherwise. Every list is
sorted and capped, with `truncated: true` on the key when the cap was hit.

### I-3 — the `audit` collector

Declaration: reads `/etc/audit/auditd.conf`, `/etc/audit/audit.rules`,
`/etc/audit/rules.d/*.rules` (Glob), and, for stat only, `/var/log/audit`,
`/var/log/audit/*` and `/var/log/*`; commands `/usr/sbin/auditctl -l` and
`/usr/sbin/auditctl -s` (5 s, 1 MiB each; on EL9 `/sbin` is a link to `usr/sbin`, so one
path serves both families).

- `audit.rules.present` — `setting<bool>`. Runtime: `auditctl -l` printed at least one
  rule line (its "No rules" is false). Persisted: at least one rule line (`-w`, `-a`, `-A`)
  in the persisted source. `audit.rules.loaded_count` and `audit.rules.persisted_count`
  are the two counts (`int`), evidence. `audit.rules` is `list<record>` `{file, line,
  kind, key, text}` (`internal`; `kind` ∈ watch | syscall | control | other; `key` the
  `-k`/`key=` value or empty; capped at 2000 rows), the persisted rules as read, in load
  order.
- **The persisted source models `augenrules(8)`:** when `/etc/audit/rules.d/` holds at
  least one `*.rules` file, the persisted answer is their concatenation in C-locale lexical
  order (that is what `augenrules --load` writes into `audit.rules` at daemon start, so the
  generated `audit.rules` is not read twice); when it holds none, `/etc/audit/audit.rules`
  itself is the source. The source of each persisted envelope names the file(s) read;
  `audit.immutable`'s `winner` names the file that carried the deciding line.
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
  `default`, and the file's own existence is the proof; there is no verdict on the path
  string, only on the file it names.
- `audit.log_file.*` and `audit.log_dir.*` — the nine permission leaves each (`mode, uid,
  gid, group, group_readable, group_writable, other_readable, other_writable,
  acl_present`), of the file `log_file` names and of its parent directory. A `log_file`
  outside the declared stat patterns is C4: `absent` with the path in the reason, never
  `error`.
- Status rules. `auditctl` not on the host: the runtime side is `absent` ("auditctl is
  not installed"), never `unsupported` — the kernel may hold rules nobody can list, and
  the controls that need the runtime side are gated on the daemon being installed anyway.
  `auditctl` exits 1 with `Operation not permitted` on stderr: `denied` when the run is not
  root, `unsupported` ("kernel audit is not reachable from this environment") when it is —
  a container's audit netlink socket answers that way; `Connection refused` or `audit
  support not in kernel`: `unsupported`. `/etc/audit` is 0750 root on both families and
  `/var/log/audit` is 0700, so a non-root run reads every persisted and permission leaf
  `denied`.

### I-4 — the `fim` collector

Declaration: stat of `/usr/bin/aide`, `/usr/sbin/aide`, `/usr/sbin/tripwire`,
`/usr/sbin/samhain`, `/usr/bin/osqueryd`, `/opt/osquery/bin/osqueryd`,
`/usr/sbin/integrit`, `/var/ossec/bin/wazuh-agentd`, `/var/ossec/bin/ossec-agentd`; reads
`/etc/aide/aide.conf`, `/etc/aide.conf`, `/etc/aide/aide.conf.d/*` (names only),
`/etc/cron.daily/*` (names and mode), `/etc/cron.d/*`, `/etc/crontab`; stat of
`/var/lib/aide/*`; the fixed timer inventory command the `cron` collector already declares
(`systemctl list-unit-files --type=timer --no-legend --no-pager`), declared again here so
neither collector depends on the other's order.

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
  macros substituted into `@@{NAME}` references; a reference to a macro the file never
  defined is left as written and the reason says so. `fim.aide.database_present` — `bool`,
  a regular file at that path. `fim.aide.database_modified` — `string`, its mtime as
  RFC 3339 UTC, evidence.
- `fim.aide.schedules` — `list<record>` `{kind, path, enabled}`, `kind` ∈ cron_daily |
  cron_d | crontab | timer: an executable file under `/etc/cron.daily/` whose name contains
  `aide` (`run-parts` skips a file without the execute bit, so `enabled` is that bit); a
  line of `/etc/cron.d/*` or `/etc/crontab` whose command names `aide` (`enabled` true, the
  file is the schedule); a timer unit whose name contains `aide` (`dailyaidecheck.timer`
  on Ubuntu 24.04, an administrator's `aidecheck.timer`; `enabled` from its unit-file
  state). `fim.aide.scheduled` — `bool`, at least one row with `enabled` true. A host
  without a timer inventory (no systemd) lists cron rows only.
- `fim.other_tools` — `list<record>` `{name, path}`, every other binary found.

### I-5 — the `pkgverify` collector

Declaration: commands `/usr/bin/rpm -Va` and `/usr/bin/dpkg --verify` (10 min, 64 MiB
each; the family decides which one runs, as `patch.go` decides); reads of
`/var/lib/dpkg/info/*.md5sums` and `*.list` names only, for the coverage count below. The
collector runs only when `--deep` was given and the run is root (principle 5): without
`--deep` it writes nothing; without root it writes `packages.verify.complete` as `denied`
("package verification needs root: an unprivileged rpm -Va marks every file it cannot
read as untestable") and nothing else.

- `packages.verify.complete` — `bool`: true when the command exited 0 or 1 and its output
  was not truncated; false with the reason otherwise (`timeout` when the command was
  killed, `error` naming the code, `truncated` when the output hit the cap — the last two
  are the envelope's own status, not `ok: false`). `packages.verify.tool` — `string`,
  `rpm` or `dpkg`.
- `packages.verify.modified` — `list<record>` `{path, attributes, file_type}`
  (`internal`, capped at 5000, `subject_kind: file`): the rows left after the filter.
  `attributes` is the list of the columns that differed, in the tool's order and by name:
  `size, mode, digest, device, link, user, group, mtime, caps` for the nine columns
  `S M 5 D L U G T P` of `rpm(8)`, and `missing` for a `missing` line; `dpkg --verify`
  prints the same nine-column form (`--verify-format rpm` is its only format) and can
  fill only `digest`, so its rows carry `digest` or `missing`. `file_type` is the type
  letter as a word (`config, doc, ghost, license, readme`) or empty.
- `packages.verify.modified_config` — the same record shape, the configuration-file rows
  (type `c`, and dpkg's conffiles, which it marks `c` too) — evidence for the reader, not
  judged: a changed configuration file is what administration looks like.
- `packages.verify.filter` — `list<string>`, the rules applied, in order, always the five:
  `config` (type `c` → `modified_config`), `doc` (types `d`, `l`, `r` → dropped), `ghost`
  (type `g` → dropped: the file is not shipped), `mtime_only` (the only differing column
  is `T` → dropped: a touched file with its content, mode and owner intact), `unverifiable`
  (no column differs and at least one is `?` → dropped: rpm could not test it). Recording
  the list even though it is constant is what lets a later filter change be seen in a
  snapshot's date.
- `packages.verify.filtered_counts` — `record` `{config, doc, ghost, mtime_only,
  unverifiable}` (`int` each). `packages.verify.stats` — `record` `{lines, exit_code,
  duration_ms, truncated, packages_without_digests}`; the last is, on a dpkg host, the
  number of `/var/lib/dpkg/info/*.list` files with no `*.md5sums` beside them — the
  packages `dpkg --verify` silently cannot check — and 0 on an rpm host.
- A verify line that matches neither the nine-column form nor `missing` is counted in
  `stats.lines` and the first three such lines are kept in `complete`'s reason without
  failing the key (rpm prints warnings to stdout on some hosts).

### I-6 — two extensions

- **`files_sudo`** gains `sudo.log.syslog` (`bool`: false only when an unscoped
  `Defaults` line negates it, `!syslog`; the option is on by default in `sudoers(5)` and
  a `syslog=facility` value keeps it on), `sudo.log.logfile` (`string`, the unscoped
  `logfile=` value with quotes stripped, `""` when none), `sudo.log.input` and
  `sudo.log.output` (`bool`, `log_input` / `log_output`), and `sudo.defaults.scoped_count`
  (`int`: `Defaults:user`, `Defaults@host`, `Defaults>runas`, `Defaults!command` lines,
  counted and not interpreted — a scoped default changes one persona and the leaves say
  what the host does by default). Lines are read from `/etc/sudoers` and every file of the
  `@includedir` directory in `sudoers(5)`'s order (lexical, names with `.` or `~` skipped),
  backslash continuations joined, later lines winning; `/etc/sudoers.d` is 0750 root on
  both families and a non-root run reads the five leaves as that read's status (C3).
- **`logging`** gains `logging.rsyslog.forwards_remote` (`bool`: at least one parsed
  rsyslog action is a remote target — `@host`, `@@host`, `:omfwd:`, `action(type="omfwd")`,
  which the parser already classifies as `remote`; false when rsyslog is not installed,
  because then nothing forwards; `absent` ("syslog-ng is not modelled") when the
  implementation is syslog-ng), `logging.rsyslog.remote_targets` (`list<record>` `{file,
  line, target}`, `internal`, evidence), and `logging.journal_upload.url` (`string`,
  `internal`: the `URL=` of `[Upload]` in `/etc/systemd/journal-upload.conf` and
  `journal-upload.conf.d/*.conf`, last wins; `""` when no file or no line — no file is no
  URL, a fact and not a default).
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
| `audit_disk_actions` | 중 | auto | same | `space_left_action`, `admin_space_left_action`, `disk_full_action`, `disk_error_action` each `in ${allowed_actions}` (default `[syslog, email, exec, rotate, single, halt]` — `ignore` and `suspend` discard records without telling anyone); `max_log_file_action in ${allowed_rotate_actions}` (default `[rotate, keep_logs, syslog]`) | manual — a missing line lets the daemon's compiled default decide, which nobody chose |
| `audit_log_permissions` | 중 | auto | same | `audit.log_file.uid eq 0`, `audit.log_file.mode in ${allowed_modes}` (subsets of 0640), `audit.log_dir.uid eq 0`, `audit.log_dir.mode in ${allowed_dir_modes}` (subsets of 0750) | manual — the file is where muster does not read (C4 names the path) or was never written; either needs a look, and `auditd_active` already says whether the daemon runs |
| `remote_log_forwarding` | 하 | auto | — | mechanisms: `logging.rsyslog.forwards_remote eq true` → `services.syslog.active eq true`; `logging.journal_upload.url matches ^https?://` → `services.journal_upload.enabled eq true`; `logging.rsyslog.forwards_remote eq false` → `logging.journal_upload.url matches ^https?://` (fails: nothing leaves the host) | manual — a syslog-ng host selects no mechanism |
| `sudo_logging` | 중 | auto | `sudo.installed eq true` | mechanisms: `sudo.log.syslog eq true` → passes on that; `sudo.log.syslog eq false` → `sudo.log.logfile matches ^/` | fail |
| `file_integrity_tool` | 중 | auto | — | mechanisms: `fim.tool eq aide` → `fim.aide.database_present eq true`, `fim.aide.scheduled eq true`; `fim.tool eq none` → `fim.tool eq aide` (fails: no tool) | manual — a host with only an unmodelled tool has `fim.tool` absent, selects no mechanism, and reads MANUAL with `fim.other_tools` in the evidence |
| `package_files_unmodified` | 상 | auto | `--deep` (I-9) | `packages.verify.complete eq true`; `packages.verify.modified` `op: none, subject: path, where: {field: path, op: present}` | fail |

The mechanism shape follows 3B's core-dump control: the last mechanism's `when` holds on
every judged host and its check fails, so "nothing configured" is FAIL and only a host
whose selecting fact is genuinely `absent` reaches `absent_means`.

The stock readings the plan pins (I-11): **Ubuntu 22.04**, no auditd, no AIDE —
`auditd_active` FAIL, the four audit detail controls NOT_APPLICABLE (gate),
`remote_log_forwarding` FAIL, `sudo_logging` PASS, `file_integrity_tool` FAIL,
`package_files_unmodified` PASS on the public image (the GitHub runner VM reads FAIL, and
that is the truth of an image its provider customises). **EL9** (Rocky, Alma), auditd
active with the shipped `rules.d/audit.rules` (`-D`, `-b`, `-f`, no watch or syscall
rule, no `-e`) and `admin_space_left_action = SUSPEND`, `disk_full_action = SUSPEND` —
`auditd_active` PASS, `audit_rules_loaded` FAIL, `audit_immutable` FAIL,
`audit_disk_actions` FAIL, `audit_log_permissions` PASS (0700 directory, 0600 file), the
rest as Ubuntu. Three FAILs on a stock EL9 say what is true: the daemon runs and audits
nothing.

`references.stig` entries exist in the committed index for the auditd package and service,
the four disk actions, the log file and directory ownership and mode, AIDE installed and
scheduled, and remote log offloading, on all five benchmarks; the plan's pre-flight
resolves the ids against the index as 3B's did. `references.nist_800_53`: AU-2, AU-3,
AU-4, AU-5, AU-9, AU-12 for the audit controls, AU-4(1)/AU-9(2) for forwarding, AU-3 for
sudo, SI-7 for the two integrity controls.

## 5. The deep-based rule (I-9, D30)

Rows 9, 10 and 10a of main §6.5 say what happens to a **walk-based** control when the walk
was not run, did not complete, or could not run. Package verification has the same three
states for the same reason (it runs only under `--deep`, only as root, and can time out),
so the rows are widened from "walk-based" to **deep-based**: a control that references any
`walk.*` key or any `packages.verify.*` key. The completeness fact is `walk.complete` for
the first set and `packages.verify.complete` for the second; the reason codes are
`walk_incomplete` and `verify_incomplete`. The evaluator's test that pins rows 9–10a gains
the second family. This is D30 in the main design and the only evaluator change of 3C-1.

## 6. Environments (I-10)

- **Root.** Everything answers. `auditctl` needs `CAP_AUDIT_CONTROL`; `rpm -Va` /
  `dpkg --verify` run inside the `--deep` timeout (budget + 5 min) and their duration is in
  `packages.verify.stats`.
- **Non-root.** The four audit detail controls are ERROR naming the denial (rules files,
  `auditd.conf`, `auditctl`, the log directory — every one is root-only on both families);
  `services.auditd.*` still answers (`systemctl show`); `pkgverify` writes the `denied`
  completeness key alone; `sudo.log.*` is the read's status when `sudoers.d` cannot be
  listed. The capability matrix's `nonroot.denied` row gains the 34 `audit.*` keys,
  `packages.verify.complete` and the five `sudo.log.*` / `sudo.defaults.*` keys. AIDE
  paths, `journal-upload.conf` and `cron.daily` are readable without root.
- **Container.** Kernel audit is not namespaced: `auditctl` answers `Operation not
  permitted` or `Connection refused` and the runtime sides are `unsupported`; every one of
  the nine controls is NOT_APPLICABLE on the container gate regardless. `pkgverify` can
  run in a container (the package database is there) and CI uses that to compare the
  parser with the real tools (I-11). `container.unsupported` gains `audit.rules.present`,
  `audit.immutable` and the four `audit.status.*` keys.
- **No systemd.** `services.auditd.*` and `services.journal_upload.*` are `unsupported`
  by the table's rule; `fim.aide.schedules` holds cron rows only.
- **Family differences.** `/usr/sbin/auditctl` on both. AIDE: `/usr/bin/aide` and
  `/etc/aide/aide.conf` on the Debian family, `/usr/sbin/aide` and `/etc/aide.conf` on EL;
  the database name comes from the configuration (`aide.db` there, `aide.db.gz` on EL);
  Ubuntu 22.04 ships `/etc/cron.daily/aide`, 24.04 `dailyaidecheck.timer` beside a
  cron.daily script of the same name, EL ships no schedule. `rpm -Va` fills nine columns
  and prints type letters; `dpkg --verify` fills the digest column only and marks
  conffiles `c`. sudo logs through syslog on both by default.
- **The lab and the runner.** The lab host (Ubuntu 22.04, kernel 5.15, root) carries
  neither auditd nor AIDE, so it proves the stock-Ubuntu column of §4 and the non-root
  column; the passing paths of the audit controls are proven by fixtures and by CI's EL
  init containers, where `services.auditd.active` is true and the detail controls are
  NOT_APPLICABLE on the container gate — the EL runtime side of `audit.rules.present` and
  `audit.immutable` is therefore covered by fixtures only, and §7 says so. The runner VM's
  `--deep` run will list modified package files, and the example snapshot's FAIL on
  `package_files_unmodified` is expected.

## 7. Tests, CI, documents (I-11, I-12)

**I-11 — the 3F gates are the gates.** Every control has `pass-` and `fail-` fixtures and
`na-` fixtures (the container; for the four gated audit controls also "auditd not
installed"); `audit_disk_actions`, `remote_log_forwarding` and `file_integrity_tool` have
`manual-` fixtures (a missing action line; a syslog-ng host; a host with osquery and no
AIDE). The mutation test stays at zero survivors, an equivalent mutant goes into
`_mutants.yaml` with its reason. Two whole-host synthetic snapshots under
`controls/testdata/_hosts/` — the stock Ubuntu 22.04 reading and, new, a stock EL9
reading — pin the two columns of §4 at once through `hosts_test.go`. Six `Fuzz<Name>`
targets with seeds, enforced by the inventory test: the audit rules parser, the
`auditd.conf` parser, the verify-output parser, the sudoers `Defaults` reader, the
`aide.conf` macro reader, the `journal-upload.conf` reader. Two oracle pairs under
`MUSTER_ORACLE=1`, both in CI's containers rather than on the lab: `rpm -Va` against the
verify parser in the Rocky and Alma init images, `dpkg --verify` against it in the Ubuntu
images — the line count and the set of paths must agree, and a classification of every
line must be reached. The `auditctl -l` oracle cannot run where `auditctl` cannot reach
the kernel; it is parked (§8). Collectors are unit-tested through `memAccess` on the
present / absent / denied / truncated paths, proven on the lab (root and non-root) against
the stock-Ubuntu column, and the `--deep` run's row counts, filtered counts and duration
are recorded in the plan's Execution notes.

CI: the two EL init jobs assert with `jq` that `services.auditd.active` reads true and
`audit_rules_loaded` reads NOT_APPLICABLE (`unsupported_env` is not the code — the gate
is); the runner's root job already passes `--deep` for the walk and now also produces
`packages.verify.*`, asserting `complete` true and `tool` `dpkg`; the non-root job asserts
`packages.verify.complete` `denied` and `audit.conf.log_file` `denied`; the capability
matrix test covers the new rows; `examples.yml` is run once on the pull request and the
six example files refreshed (the control set changes, so the digest gate would otherwise
skip their byte comparison).

**I-12 — documents.** The main design gains D30, the widened rows 9–10a in §6.5, and in
§10.2 "3C-1 (merged)" with the remaining 3C-2 list and the sentence that closes W-8
("whole-database verification with fixed arguments; no `CommandTemplate`"). README (both
languages): the count sentence — "68 controls for the 67 items, and 28 beyond the guide" —
and the roadmap line. CHANGELOG under Controls (the nine, `controls/VERSION` →
`kisa-unix-2026+2026.09.23`), Collectors (the three, the two extensions, the two table
rows) and Tooling (the deep-based rule). CONTRIBUTING (both languages): one paragraph on
commands whose exit code is data. CLAUDE.md: two lines under "Beyond the guide" (the
deep-based rule; what `fim.tool`'s `absent` means). `coverage.md` regenerated. The plan
keeps its Execution notes as the earlier plans do.

## 8. Parked

- Judging the content of the audit rules (identity files, time, login records, modules,
  privileged commands): 3D, with the CIS profile and `references.cis`.
- The `auditctl -l` oracle: needs a VM with auditd; whether the runner's root job installs
  `auditd` for it (a package on the runner VM, no image change) is the plan's pre-flight's
  call.
- Automatic verdicts for Tripwire, Samhain, osquery, Wazuh (I-4's `fim.other_tools` is
  the seed); the AIDE database's age against `fim.aide.database_modified`.
- The join of `packages.verify.modified` with the walk's package table (owning package
  per row; cross-check with `walk.suid_sgid`): with 3C-2's process → package join.
- `sudo.log.input` / `sudo.log.output` as a verdict; interpreting scoped `Defaults`.
- The receiving side of journal-remote; whether an rsyslog remote target is TLS.
- 3C-2 as split: the process collector, the exposure cross-check (only at full firewall
  confidence), root-equivalent paths (container-runtime sockets and groups,
  `ld.so.preload`, writable `ExecStart` of root units, root's `PATH`, file capabilities in
  the walk), network sysctls, and the four unassigned stage-3 items (dormant accounts,
  `sudoers` `NOPASSWD`/`ALL`, processes running deleted executables, `authorized_keys`
  inventory).
