# Stage 3D-2d — the audit family, the inactivity bound, and what a file says

Korean pair: `2026-10-19-stage3d2d-content-scripts-design.ko.md`. Main design: `2026-09-02-muster-design.md`
(§6.2 schema, §7.5 `fix --dry-run`, §10.2 roadmap, D24, D34). The cycles it builds on:
`2026-10-07-stage3d2-fix-dry-run-design.md` (X-1..X-10), `2026-10-13-stage3d2b-remedy-proof-design.md`
(Q-1..Q-6) and `2026-10-14-stage3d2c-remedy-scripts-design.md` (E-1..E-13; S-18..S-50 in its plan, §8 as
built). Rulings of this design are the O list (the letter H is taken by stage 2H). Two spec reviews are folded in
place: the first (six lenses, three refuters per finding, a critic: 76 findings, 63 upheld, merged into 33) and
the second over the folded draft (four lenses: 50 findings, 43 upheld, merged into 22). The scope map, both
review digests and the critic's notes are the cycle's ignored workspace (`code-map-*.md`,
`spec-review-r{1,2}.md`); their findings are restated here where they bind.

## 1. Scope and intent

Forty-eight controls carry a `script` after 3D-2c. The main design names 3D-2d as "the audit family,
`account_inactivity_lock` and the content halves of the file controls", with a script where a safe shape
exists and text otherwise. A safe shape means four things at once:

1. the body makes no one-way runtime change, and every other change it makes is either recorded and put back
   on failure or named in the control's text as staying after a failed block (O-2);
2. it writes only when the host is outside the clause's accepted set (E-8, as amended by O-6);
3. the value it writes is one muster can choose without knowing the site — no address, account, certificate,
   or wording a human must pick (O-15 says when a fixed string is not such wording);
4. a CI row runs it end to end, repair and failure both, or the branch no row reaches is pinned by a stub test
   and named as unproven on that row.

Of the 69 controls without a script, eight meet that bar, and one shipped body grows a second half. Writing them
found three collector readings that are wrong for the very files the bodies edit; they are fixed first, each in
its own commit (O-14, O-17, O-18). The rest stay text: a per-host judgment (which account, port, bit or client), a
one-way runtime write, a package install, a PAM stack edit, or an `automation: manual` control (§7).

- **O-1 — Eight new bodies and one extended body; 56 scripted controls in all.**
  - Audit family: `muster.beyond.auditd_active`, `muster.beyond.audit_rules_loaded`,
    `muster.beyond.audit_disk_actions` (§4.1–§4.3).
  - The inactivity bound: `muster.beyond.account_inactivity_lock` (§4.4).
  - Content halves: `muster.file.rhosts_forbidden` (the `/etc/hosts.equiv` half),
    `muster.service.mail_expn_vrfy` (the postfix half), `muster.service.ftp_banner` and
    `muster.service.ftp_anonymous` (the vsftpd half), and the shipped `muster.service.nfs_export_access` body
    gains the `no_root_squash` half (§4.5–§4.9).
  - No schema field, lint rule, prologue helper or record kind is added. Everything these bodies need exists
    after 3D-2c: `backup`, `units`, `script_params`, a declared `rollback`, and body-written records under `$MB`
    (the `ageing.list` pattern). §3 states the conventions they add to CONTRIBUTING.
- **O-2 — A body never makes a one-way runtime change; every other runtime effect is recorded and replayed, or
  named in the text.** `auditctl -e 2` and `--loginuid-immutable` lock kernel state until the next boot; no
  rollback can undo them, and on the runner row either would lock the VM for the rest of the job. So
  `muster.beyond.audit_immutable` stays text, and its risk becomes `reboot_required` (the operational impact of
  following the text: every later rule change needs a reboot). Recorded and replayed: the kernel audit settings
  `audit_rules_loaded`'s load can change (`enabled`, `failure`, `backlog_limit`, `backlog_wait_time`,
  `rate_limit` from `auditctl -s`, §4.2). Named in the text as staying after a failed block: `auditd_active`'s
  start (a running daemon, and the kernel audit settings its unit's load applies), `exportfs -ra` (it resyncs the
  kernel's export table to every export file), and `postfix reload` (it applies any pending `master.cf` edit).
- **O-3 — No body loads rules into, or starts auditd over, a pending one-way setting.** The test has two halves,
  read getopt-style (a flag may be glued to its value: `-e2`, `-w/etc/passwd`) under `LC_ALL=C`:
  - **runtime lock**: `auditctl -s` reports `enabled 2` or `loginuid_immutable 1` (keys matched whole, never by
    prefix);
  - **pending lock**: any line of `/etc/audit/rules.d/*.rules` or `/etc/audit/audit.rules` matching
    `(^|[[:space:]])(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable([[:space:]]|$))` (the token may stand anywhere on the line: `-b 8192 -e 2` applies the lock too). The test is broader
    than augenrules' "last `-e` wins" and at least as broad as the collector's `lastEnableValue`: a refusal costs a
    failed block whose control stays FAIL; a wrong guess costs a locked kernel.
  A refusal logs, exits 1 before any write, and the block fails (the restores run; nothing changed). Per body:
  `audit_rules_loaded` runs both halves before any load, and an `auditctl -s` that exits non-zero or prints no
  `enabled` line refuses; `auditd_active` runs both halves only before a start, and there an `auditctl -s` that
  cannot tell counts as "not locked", so a pending lock refuses (§4.1).
- **O-4 — `audit_rules_loaded` acts in three cases and leaves the fourth.** "The kernel list is empty" means
  `auditctl -l` exits 0 and prints `No rules`; "holds rules" means it exits 0 and prints something else; a
  non-zero exit refuses in a body and fails in a validate.
  - (a) **rules persisted, kernel list empty**: load them (`augenrules --load`), only while auditd is active — a
    load into a kernel with no daemon queues records nobody reads, and with a persisted `-f 2` can panic the host.
    With auditd inactive the body only regenerates, and the unit's own start loads the set.
  - (b) **kernel holds rules, nothing persisted**: left. muster does not persist `auditctl -l` output (it does not
    round-trip into rule files reliably) and does not write a floor beside an operator's live set: at reboot the
    floor would replace it. The body logs `kernel rules are not persisted; persist your own set`, the validate
    accepts this shape, the block ends `done`, the control stays FAIL (X-10).
  - (c) **both empty**: write muster's minimum watch set to `/etc/audit/rules.d/50-muster.rules`, then (a).
  - (d) **both present**: the control passes; never planned.
  Why the floor meets §1's bar (and departs from the load-only shape the scope map proposed): an auditd that runs
  with no rule records nothing a system call selects, which is the finding; the floor watches seven fixed paths
  every host has, with `wa` permissions only (low volume), under `muster-*` keys an operator can find and delete;
  the text says to replace it with the site's rules. The lines are auditctl(8) syntax with muster's own keys, not
  text from any benchmark (ATTRIBUTION note).
- **O-5 — `auditd_active` is the first units body that enables, and it amends Q-2 for that shape.** It declares
  `units: [auditd.service]`, unmasks and enables the unit, and starts it only when it is inactive, its kernel list
  is empty, and either no lock is pending or the runtime is already locked (a start under a locked runtime changes
  nothing one-way: the unit's load is refused and its `-` prefix ignores the failure). Starting auditd runs
  `augenrules --load`, whose hoisted `-D` deletes the kernel list, so an inactive unit over a non-empty list is
  enabled and not started (`kernel holds rules a start would replace; start left to the operator`). Q-2's units
  record "puts back what was there" for enablement and masking; for activity it cannot: `restore_units` never
  stops a unit, and the auditd unit refuses a manual stop anyway — a failed block leaves a started auditd running,
  with the settings its load applied. That fails toward the secure state and is said in the text.
- **O-6 — The value written is the first member of the list in force that the target accepts and that keeps the
  host up (amends E-8).** For `audit_disk_actions` the writable set is per key, from auditd.conf(5):
  `space_left_action`, `admin_space_left_action`, `disk_full_action` — `syslog`, `rotate`; `disk_error_action` —
  `syslog`; `max_log_file_action` — `rotate`, `keep_logs`, `syslog`. `email` (needs a mailbox), `exec` (a path),
  `single` and `halt` (take the host down) are never written; a list in force with no writable member leaves that
  key to the text, and the validate does not check a key the body left. E-8's "the guide's value, or the first
  element of the list in force" stands for every control where that value is always writable.
- **O-7 — The inactivity bound covers root, and skips any account it would disable on the spot.** The body edits
  `/etc/default/useradd`'s column-one `INACTIVE=` line (the line the collector and useradd read; never
  `useradd -D`, which rewrites the whole defaults set) and runs `chage -I <n>` over the local accounts the
  collector calls login-capable, root included. Unlike S-48 (the ageing loop leaves root alone), root is in: where
  root has no maximum (empty, -1 or 99999, as `password_policy` leaves it), field 7 has no effect until the
  operator gives root real ageing, and without root the control could never pass on any host. Where root (or any
  account) has a real maximum, the body logs the date the account will be disabled unless its password changes,
  root first; the text says that on a host that ages root, root's key login stops at that date. An account whose
  password has already been expired for `n` days or more is skipped and named. Each account's previous field 7
  goes to `$MB/inactive.list` (`name:old`, an empty field recorded as `-1`, first record kept); the declared
  rollback replays it. Risk becomes `lockout_risk` (was `none`).
- **O-8 — A content half is the generic edit of a file muster already judges; the rest of the control stays text,
  and the text says which half.** The plan has no clause gating: a control whose failing clause belongs to the
  half the body leaves still gets the block, which changes nothing and ends `done` while the next `check` still
  FAILs (X-10). Each half-scripted control's text therefore names the half it leaves. A new body never deletes a
  line someone wrote: a disqualifying `+` line in `/etc/hosts.equiv` is commented out with a `# muster: ` prefix;
  a key is rewritten in place where it exists and appended where it does not. The shipped `/etc/securetty` edit
  (3D-2) is unchanged.
- **O-9 — A declared rollback may call `restore <path>`; a daemon is tested, reloaded or restarted only on what
  this run recorded.** E-11 makes the declared rollback of a daemon-re-read file put the file back itself (the
  declared rollback runs before the template's `restore`). The new bodies call the prologue's `restore` instead
  of re-implementing the copy; the template's later `restore` of the same path is a harmless second pass (a test
  pins it). Two per-run markers drive the daemon steps:
  - `$MB/<daemon>.was-running`, written before any edit when the daemon runs. The body's reload or restart and the
    rollback's both key on it, never on "running now": a restart that failed leaves the unit failed, and the
    rollback must still start it again; a daemon the operator stopped since an earlier run is never started.
  - `$MB/<daemon>.edited`, touched immediately before the body's first write. The rollback runs the daemon's test
    and the reload or restart only when it exists; otherwise it restores and exits 0, so a refusal made before any
    write (a `postfix check` that already failed) never produces a `rollback failed` line.
- **O-10 — Every body that reads a file the way the collector does is checked against the collector.** E-8 rests on
  the body's reading agreeing with the Go parser. A Linux test runs each new body's read expression over the
  parser's fixtures and fuzz seeds plus hand-written edge rows and compares the answers, written against the fixed
  readers (O-14, O-17, O-18): auditd.conf (`parseAuditdConf`; rows `exec /path`, `EXEC /x`); rule presence and the
  lock (`parseAuditRules`/`auditKind`, `lastEnableValue`; the lock row is one-sided — the body must refuse wherever
  the collector reads a lock, and may refuse more); `/etc/default/useradd` (`parseUseraddDefaults`); the vsftpd
  reader (greeting and `anonymous_enable`; rows `PureFTPd ready`, `myvsftpd`, a clean `ftpd_banner` beside a
  disclosing `banner_file` and the reverse, an empty `banner_file`, `anonymous_enable=FALSE` and `=0`); postfix's
  `disable_vrfy_command` (`parsePostfixInto`/`postfixYes`; key case-folding is a known divergence); the exports
  option reader (rows for a commented line, a trailing comment, a `\` continuation, a `-opts` default list, a path
  containing the word; the collector's substring test against the body's option-scoped match is a known
  divergence, in the body's conservative direction); and the hosts.equiv line reader (factored into a pure
  `hostsEquivLines([]byte)` with a `FuzzHostsEquivLines` target, as CLAUDE.md requires of a `[]byte` function).
- **O-11 — The two shipped bodies that write without a symlink guard get one, in the body and the rollback.**
  `lockout_threshold` writes `/etc/security/faillock.conf` and `root_remote_login` writes `00-muster.conf` and
  `/etc/securetty` with no `[ -L ]` test. faillock.conf and securetty are vendor files (the K2 precedent: log
  `is a symlink, left as is`, fail the block); `00-muster.conf` is muster's drop-in (S-27). In `root_remote_login`
  both checks go at the top of the body, before the drop-in `printf`. Its rollback removes `00-muster.conf` and
  reloads sshd before the template's `restore`, so it must skip a symlink too (the `session_timeout` shape). The
  three paths join `TestAccountBodiesLeaveASymlinkedDropIn`, whose stub sshd records whether the link was present
  at reload time.
- **O-12 — Proof.** The audit and inactivity bodies are `beyond` controls gated on `env.container eq none`, so only
  the `runner` row runs them; the content bodies run on the container rows that carry their daemon, and the init
  rows start vsftpd and postfix so the restart and reload branches run. Stub-only (no row reaches them): auditd's
  start branch, the inactive-daemon load, case (b), the NFS rollback's `exportfs -ra` (the next block,
  `nfs_server_disabled`, masks it on the init rows). `record()` gains the audit kernel state, shadow field 7 and a
  checksum of the other shadow fields, the NFS export table, and vsftpd's and postfix's run state (§5). SELinux
  labels are not proven in CI: no row runs SELinux (§7).
- **O-13 — Three verdicts change, as fixes; four risks move.** The three are O-14, O-17 and O-18. No parameter
  default changes. Risks: `auditd_active` `none` → `restart_service`, `account_inactivity_lock` `none` →
  `lockout_risk`, `rhosts_forbidden` `none` → `restart_service` (the `rservices_disabled` value, so `--max-risk
  restart_service` never runs the larger r-services cut while skipping this smaller edit), `audit_immutable`
  `restart_service` → `reboot_required`. `controls/VERSION` moves. The plan JSON keeps its shape; the examples need
  a refresh.
- **O-14 — vsftpd's greeting precedence is fixed in the collector.** vsftpd sends `banner_file`'s content when that
  option is set and the file is not empty, else `ftpd_banner` when set, else its compiled greeting (vsftpd.conf(5):
  banner_file "overrides the banner string provided by the ftpd_banner option"); the collector reads the reverse
  (`publishVsftpdBanner`). A host with a clean `ftpd_banner` beside a disclosing `banner_file` reads PASS today and
  FAIL after the fix; an empty `banner_file` beside a disclosing `ftpd_banner` keeps reading FAIL. Its own commit:
  the reader, fixtures (both keys set, each way; an empty `banner_file`), the reversed `ftp_test.go` expectation, a
  fuzz seed, the facts description, a CHANGELOG "Fixed" line. The probe reads the 220 line on the wire for each
  case.
- **O-15 — A clause that only forbids content may be satisfied with a fixed neutral string.** `ftp_banner` accepts
  any greeting that names no FTP product; writing `FTP server ready.` is not policy, because the check accepts any
  string outside a closed list. `login_banner` is different: it requires a site warning, whose wording is the
  site's, and stays text. The string is never a legal notice.
- **O-16 — Records that describe this run are not first-kept.** `audit.loaded`, `audit.status`, the
  `<daemon>.was-running` and `<daemon>.edited` markers, `disk.keys` and `inactive.run` describe what THIS run saw
  and did; each body removes them as its first action and writes them fresh. File backups and `inactive.list`
  (the way back the rollback replays) stay first-kept. A rerun's rollback therefore never deletes rules, replays
  settings or restarts a daemon on the strength of an earlier run, and a rerun's validate checks only what this
  run wrote.
- **O-17 — An auditd `exec` action is judged by its first word.** `space_left_action = exec /usr/local/sbin/x` is
  the administrator's own remedy, but `parseAuditdConf` lower-cases the whole value and the list member `exec`
  never equals `exec /usr/local/sbin/x`, so the row FAILs today and a body would overwrite it with `syslog`. The
  judged action becomes the first whitespace-separated word, lower-cased; the path is kept as written and is not
  part of the verdict. Its own commit: the reader, fixtures (`exec /usr/local/sbin/x`, `EXEC /x`), a fuzz seed, the
  facts description, a CHANGELOG "Fixed" line. §4.3 compares only that word.
- **O-18 — An exports default option list is read.** exports(5) lets a line give `-opts` before its clients as
  defaults for them (a client's own options override it); the collector skips every `-` token as BSD syntax, so
  `/srv -no_root_squash host` reads `root_squash` true — a false PASS on a 상 control. `parseExportsContent` applies
  the default list to the clients after it on that line. The probe confirms nfs-utils accepts the syntax on the
  three init rows before the commit; if it does not, the collector keeps skipping and O-10 records the divergence.
  Its own commit: the reader, a `fail-` fixture, a fuzz seed, a CHANGELOG "Fixed" line.

## 2. What stays as built

- The template, its prologue, the per-block records under `$MUSTER_BACKUP/blocks/<fn>/`, the failure order
  (declared rollback → `restore_units` → `restore_modes` → `restore` → `restore_sysctl` → `restore_modules`),
  the six rollback words and every lint rule are unchanged.
- Rollback words, from the existing `rollbackWord`: `auditd_active` → `units`; `audit_rules_loaded`,
  `audit_disk_actions`, `account_inactivity_lock`, `mail_expn_vrfy`, `ftp_banner`, `ftp_anonymous`,
  `nfs_export_access` → `both` (a `backup` and a declared rollback); `rhosts_forbidden` → `restore_backup`.
- Parameters: `audit_disk_actions` lists its four list params and `account_inactivity_lock` its one int param in
  `script_params`; each is used in the body, so `script_params_used` holds. The values in force reach the body as
  `P_` lines under the charset (E-1). The int charset admits a negative value, which the inactivity body refuses
  (§4.4).
- No new body sets `script_on_absent`. `audit_rules_loaded` and `account_inactivity_lock` are `absent_means:
  fail`; their absent rows (no persisted rules and no `audit.rules`; a missing `/etc/passwd`) are text-only
  `absent`, nothing to act on. `auditd_active` is `absent_means: fail` too, but the services collector writes
  `ok:false`, not absent, for a unit that is not installed, so a not-installed row is planned and the body handles
  it (§4.1). The others are `absent_means: manual`, so their absent rows are MANUAL and never planned.
- Locale: the template does not pin one. Every body, validate and rollback that parses command output
  (`auditctl -s`/`-l`, `postconf -h`, `systemctl is-*`, `postfix status`) runs those commands under `LC_ALL=C`.
- Order in a plan (risk → severity in force → id): `audit_rules_loaded` and `auditd_active` are both 상 and
  `restart_service`, and `audit_` sorts before `auditd`, so the rules block runs first. On a host with auditd
  inactive and no rules, the rules block writes the floor and regenerates only, and `auditd_active`'s start then
  loads it; a stub test pins that a plan holding both ends with the floor loaded. On the failure run, the rules
  block's rollback runs before `auditd_active`'s `restore_units`. `audit_disk_actions` (중) runs after both, and
  its `was-running` marker is written after their changes. `nfs_export_access` runs before `nfs_server_disabled`
  (both 상, `restart_service`).

## 3. Conventions the new bodies add (CONTRIBUTING)

These go into CONTRIBUTING's "Remediation bodies" section, English and Korean.

1. **No one-way runtime change; every other runtime effect is recorded and replayed, or named in the text (O-2).**
2. **An enabling units body (O-5).** The two-pass disabling loop stays the shape for disabling. An enabling body
   loops over `$UNITS`, unmasks, enables, and starts only an inactive unit; its text says a failed block leaves a
   started unit running.
3. **A rollback that calls `restore` (O-9).** `restore <path>`; then, only when `$MB/<daemon>.edited` exists, the
   daemon's test and the reload or restart when `$MB/<daemon>.was-running` exists. Both markers are per run
   (O-16): removed first, `was-running` written before any edit, `edited` immediately before the first write.
4. **Per-run records (O-16)** are removed first and written fresh; only file backups and the replay lists are
   first-kept.
5. **Comment out, never delete (O-8)**, in new bodies: a disqualifying line is prefixed `# muster: `; the file is in
   `backup`.
6. **A tool that writes its own file is used where it reads the file the way the collector does** (`postconf -e`),
   and the file stays in `backup`. A tool that rewrites more than the one key is not used.
7. **Append to a file that may lack a final newline**: `if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >>
   "$f"; fi` first. The shipped appenders adopt it later (§7).
8. **The value written (O-6)** and **a fixed neutral string (O-15)**, as stated there.
9. **A guarded validate.** Beside the three shapes, a validate may accept a leave the body logs (X-10), as `[ guard
   ] || …` or a `{ …; } || { …; }` grouping on one line — the shape the shipped `audit_log_permissions` and
   `cron_permissions` validates already use.
10. **The reader parity test (O-10).** A body that gates on a value read from a file names that reader in the
    parity test's table.
11. **SELinux.** A body runs `restorecon` only on a file a tool replaced or created (`postconf -e`, a created
    `/etc/default/useradd` or `50-muster.rules`), never after `sed -i` (GNU sed keeps the context) and never after
    `restore` (`cp -a` keeps it), spelled `if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v
    restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi`.
12. **Upgrades.** A vendor configuration file a body edits in place is reported by the package manager at the next
    upgrade: on Debian and Ubuntu dpkg (or ucf) asks about an edited conffile; on the EL family rpm keeps the edit
    and writes the package's version beside it as `.rpmnew`. The text says so once per control, naming only the
    files the probes confirm as package-owned configuration (Debian's `main.cf` is generated by postinst and is
    not a conffile).

## 4. The bodies

Every body is POSIX `sh`, shellcheck-clean at the default severity (pinned to CI's v0.9.0), `set -e`-safe inside
the body subshell, and writes only when the value read the collector's way is outside the accepted set. It refuses
a symlinked target before any write (S-27; K2 for a vendor file), except where the collector reads a symlink at that
path as `error` (C4), so the row is never planned; there (§4.5, §4.7, §4.8) the body skips the path. Every validate
is one line in one of the three shapes or §3.9's guarded shape. Texts keep their sentences; where a script now
exists the text names what it writes and the half it leaves. lint caps each text at 1000 runes; `audit_disk_actions`
(616 English, 475 Korean today) has the least room, and sentences move into the description where the additions
overflow. Sketches fix the shape; the plan writes the bodies.

### 4.1 `muster.beyond.auditd_active` (상, risk `restart_service`)

- `units: [auditd.service]`; no `backup`, no `rollback` (`units_exclusive`).
- Body, per name in `$UNITS`, in order:
  1. When `systemctl cat` finds no such unit, log `install the audit package (audit on the EL family, auditd on
     Debian and Ubuntu)` and continue (no body installs a package).
  2. `systemctl --quiet unmask`, `systemctl --quiet enable`.
  3. When `systemctl is-active --quiet` fails: `auditctl -l` exits non-zero → log and `exit 1`; it holds rules →
     log `kernel holds rules a start would replace; start left to the operator` and continue; a lock is pending
     and the runtime is not locked (O-3; a runtime that cannot tell counts as not locked) → log and `exit 1`;
     otherwise `systemctl --quiet start`.
- Validate (one line, guarded): the unit missing passes; otherwise `is-enabled` `&&` (`is-active`, or `auditctl -l`
  exits 0 and holds rules).
- `TestServiceScriptsNameTheCollectorsUnits` counts eleven units-declaring controls, its doc comment says so, and
  its table gains the services `auditd` row (`auditd.service`).
- Stub `systemctl`/`auditctl` tests pin the start branch, which no CI row reaches: active + pending lock + disabled
  → enabled, `done`; inactive + locked runtime → started; inactive + unlocked + pending lock (`-e2` spelling) →
  refused, exit 1; inactive + pending lock + `auditctl -s` fails → refused, exit 1; inactive + non-empty list →
  enabled, not started, `done`; inactive + `auditctl -l` fails → exit 1; inactive + clean → started.
- Text: the body enables and starts the unit; the package install and the `audit=0` check stay the operator's; a
  failed block leaves a started daemon running, with the persisted control settings its load applied.

### 4.2 `muster.beyond.audit_rules_loaded` (상, risk `restart_service`)

- `backup: [/etc/audit/rules.d/50-muster.rules, /etc/audit/audit.rules]` (augenrules regenerates `audit.rules`, so
  it is restored with the drop-in and the failure run's checksums compare). augenrules also leaves
  `/etc/audit/audit.rules.prev`; it is not listed (it is augenrules' own), and the probe confirms its behaviour.
- Body, in order:
  1. `rm -f "$MB/audit.loaded" "$MB/audit.status" "$MB/auditd.edited"` (O-16).
  2. Refuse (log, `exit 1`) when `/etc/audit/rules.d` is missing or a symlink (creating it would make augenrules
     overwrite a hand-written `audit.rules`), when the drop-in path is a symlink, or under O-3 (both halves).
  3. Presence is read getopt-style, as `auditKind`: a line matching `^[[:space:]]*-[waA]` in `rules.d/*.rules`.
     Case (b) of O-4 — none persisted, the kernel holds rules — logs and ends.
  4. Case (c): touch `$MB/auditd.edited`; write `50-muster.rules`, mode 0640, with watches (permission `wa`) on
     `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` (key `muster-identity`), `/etc/sudoers`,
     `/etc/sudoers.d/` (key `muster-privilege`) and `/etc/audit/` (key `muster-audit-config`), only the lines whose
     path exists (auditctl refuses a watch on a missing path).
  5. When `systemctl is-active --quiet auditd.service` and the kernel list is empty: write `$MB/audit.status` (the
     `enabled`, `failure`, `backlog_limit`, `backlog_wait_time` and `rate_limit` lines of `auditctl -s`, keys
     matched whole — `backlog_wait_time_actual` is another key), `touch "$MB/audit.loaded"`, `augenrules --load`.
     Otherwise `augenrules` alone (regenerate).
- Validate (one line, under `LC_ALL=C`): `{ ! <persisted presence> && <kernel holds rules>; } || { <persisted
  presence> && { <auditd inactive> || <kernel holds rules>; }; }` — case (b) passes, a regenerate-only run with
  auditd inactive passes on the persisted half (the next check names the runtime half), and an `auditctl -l` that
  fails fails.
- Rollback: `restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules`; when `$MB/audit.loaded` exists
  and the runtime is not locked, replay `$MB/audit.status` (`auditctl -f`, `-b`, `--backlog_wait_time`, `-r`, and
  `-e 0|1` when the recorded `enabled` was not 2) and `auditctl -D` (the kernel list was empty before this run's
  load; deleting is the exact way back and loads no operator's pending set).
- `50-muster` sorts before the stock `audit.rules` file in `ls -v` order; augenrules hoists `-D` to the top and `-e`
  to the end whatever the order, so the stock file's `-D` does not delete muster's watches (the probe confirms on
  both families, with the exit code of a bare `augenrules` that changes nothing).
- Stub tests: the inactive-daemon branch (regenerate, no load, no marker); case (b) (exit 0, the persist message,
  `done`, nothing written); a rerun whose earlier run loaded, with a non-empty kernel list now and a forced
  failure (`-D` is not called, `audit.status` is this run's); the `-e2` spelling refusal; a plan holding this block
  and `auditd_active` over an inactive unit (the floor ends loaded).

### 4.3 `muster.beyond.audit_disk_actions` (중, risk `restart_service`)

- `script_params: [allowed_space_actions, allowed_disk_full_actions, allowed_disk_error_actions,
  allowed_rotate_actions]`; `backup: [/etc/audit/auditd.conf]`; a declared rollback.
- Read as `parseAuditdConf` does after O-17: `#` lines skipped, `key = value`, the key matched case-blind, the last
  line wins, the judged action the value's first word lower-cased. A line whose first word is in the list is never
  rewritten.
- Body: remove the per-run records (O-16); `$MB/auditd.was-running` when `auditd.service` is active. For each key
  outside its list, O-6 picks the value; the body appends the key to `$MB/disk.keys`, touches `$MB/auditd.edited`
  before the first write, copies the value to a plain variable, and rewrites every line of that key with `sed -i`,
  anchored so `space_left_action` never touches `admin_space_left_action`. A missing key is never added: that row is
  MANUAL, not FAIL, so the body never meets it.
- Reload: with the `was-running` marker, `auditctl --signal reload` and nothing else — no pid-file `kill`, which a
  stale pid file can aim at a reused pid (the probe confirms `--signal` on every family, and whether a HUP applies the five keys — read from auditd's
  reconfigure line in the journal on the runner; if it does not, the text says they apply at the next start).
  Never a restart (a restart re-runs augenrules, O-3).
- Validate (one line): an `awk` over the file with the four lists passed by `-v`, the collector's reading, checking
  only the keys in `$MB/disk.keys`, `&&` (no `was-running` marker, or `systemctl is-active --quiet
  auditd.service`). The second half is a liveness check only: auditd keeps its old settings when a reconfigure
  fails, and the collector reads the file.
- Rollback: `restore /etc/audit/auditd.conf`; with the `edited` and `was-running` markers, the same reload.
- Text adds: `rotate` deletes logs beyond `num_logs`; a tuning that lists `keep_logs` first keeps them.
- Tests: a tuned list whose first member is invalid for the key (`[rotate, syslog]` on `disk_error_action` writes
  `syslog`; `[keep_logs]` on `space_left_action` leaves the key); a list of only `halt`/`single` → exit 0, `done`,
  that key byte-identical, the other keys written; `exec /path` left; a rerun whose `disk.keys` from an earlier run
  named a key this run leaves.

### 4.4 `muster.beyond.account_inactivity_lock` (중, risk `lockout_risk`)

- `script_params: [max_inactive_days]`; `backup: [/etc/default/useradd]`; a declared rollback.
- Body:
  1. `rm -f "$MB/inactive.run"` (O-16). `n=$P_max_inactive_days`; refuse `n < 0` (the int charset admits it; a
     negative bound would disable every account whose password has expired).
  2. Refuse a symlinked `/etc/default/useradd` (K2). Read the last column-one `INACTIVE=` line, its value as C
     `strtol` base 0 (as the collector reads it); when it is missing, not a number, or outside `0..n`, rewrite every
     such line to `INACTIVE=n`, or append one (§3.7). A missing file is created mode 0644.
  3. Enumerate the local login-capable accounts the collector's way: every `/etc/passwd` row whose uid is not
     `0 < uid < UID_MIN` (the first uncommented `UID_MIN` of login.defs, default 1000) and whose shell is in
     `/etc/shells` and not `*/nologin` or `*/false`. An account only a remote NSS source holds is not in
     `/etc/passwd` and is not touched (the control reads it WARN, not planned). Before any arithmetic an empty
     `last` or `max` reads `-1`. For each account:
     - no shadow row → skip, named (`chage` would invent one);
     - field 7 a decimal integer other than -1 and at most `n` (negatives below -1 included: the clause accepts
       them) → leave;
     - field 7 non-empty and not a decimal integer → skip, named (the body cannot restore its text);
     - `last = 0` → skip, named (must change at next login; pam_unix never applies inactivity to it, so this
       over-skips, on the safe side); an empty or negative `last` while `max` is set and not 99999 → skip, named
       (pam_unix's expiry check has no guard for an unset last change: once field 7 is set the account reads
       expired); no date line is ever printed when `last <= 0`;
     - `last > 0`, `max >= 0`, and `today - last >= max + n` (today = `$(( $(date +%s) / 86400 ))`; `>=` is
       shadow's `isexpired` bound, the conservative side of pam_unix's `>`) → skip, named (`change its password
       first`);
     - otherwise: when `max` is set and not 99999, log the date the account will be disabled unless its password
       changes (root first); record `name:old` (empty → `-1`) in `$MB/inactive.list` unless the name is there;
       append the name to `$MB/inactive.run`; `chage -I n -- name`.
- Validate (one line): the useradd line is a number in `0..n` `&&` every name in `inactive.run` that still has a
  shadow row has field 7 a number in `0..n`. Skipped accounts are not validated: the block ends `done` and the next
  `check` names them (X-10, as `password_policy`'s ageing loop).
- Rollback: replay `inactive.list` with `chage -I "$old" -- "$name" || rc=1` per line, `exit $rc` at the end (an
  account deleted since is reported, the others still restored); the template's `restore` puts the useradd file
  back.
- Ordering with `password_policy` (also `lockout_risk`, 상, so it runs first): it lowers `max` only on hashed accounts
  younger than `max_days`, so the skip reads the new maximum and stays correct.
- Tests: a stub `chage` first on `PATH` covers the boundary day, `last = 0`, an empty `last` and an empty `max`,
  root with no maximum, root with a real maximum (logged date), a name with no shadow row, a junk field 7, an empty
  field 7 (rollback argv `-I -1`), the first record kept on a rerun and a name skipped on the rerun not validated, a
  negative parameter, a deleted account on rollback, a useradd file without a final newline. A second test pins the
  body's account set against `loginCapable` over the accounts fixtures.

### 4.5 `muster.file.rhosts_forbidden` — the `/etc/hosts.equiv` half (상, risk `restart_service`)

- `backup: [/etc/hosts.equiv]`.
- Body: when `/etc/hosts.equiv` is a regular file, not a symlink, comment out every line whose first non-blank
  character is `+` (`# muster: ` prefix). That covers a bare `+` and the scoped `+host` and `+@netgroup` trust the
  collector also judges; the text names both. No daemon re-reads the file (rshd reads it per connection).
- Validate: `[ ! -f /etc/hosts.equiv ] || [ -L /etc/hosts.equiv ] || ! grep -Eq '^[[:space:]]*\+'
  /etc/hosts.equiv`.
- The `~/.rhosts` and `~/.shosts` half stays text: those files sit in homes the account owns, which `modes_trusted`
  refuses (S-47).

### 4.6 `muster.service.mail_expn_vrfy` — the postfix half (중, risk `restart_service`)

- `backup: [/etc/postfix/main.cf]`; a declared rollback.
- Body: remove the per-run markers (O-16). When `postconf` is absent, log that the sendmail half is the operator's
  and change nothing. Refuse a symlinked `main.cf`. Run `postfix check` first and refuse when it already fails (a
  later failure is then the edit's, never inherited). `$MB/postfix.was-running` when `postfix status` succeeds.
  When `postconf -h disable_vrfy_command` is not `yes` (case-blind): touch `$MB/postfix.edited`, `postconf -e
  'disable_vrfy_command = yes'`, `postfix check`, and `postfix reload` with the `was-running` marker (works with and
  without systemd).
- Validate (guarded on `postconf`): `postconf -h disable_vrfy_command` is `yes` case-blind `&&` `postfix check`.
- Rollback: `restore /etc/postfix/main.cf`; with the `edited` marker, `postfix check`, then `postfix reload` with
  the `was-running` marker.
- Stub test: `postfix check` fails before the edit → exit 1, no `rollback failed` line.
- Text adds: a reload also applies any pending `master.cf` edit; the sendmail half (`PrivacyOptions` in a generated
  `sendmail.cf`) stays text.

### 4.7 `muster.service.ftp_banner` — the vsftpd half (하, risk `restart_service`)

- `backup: [/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf]` (Debian, EL); the body acts on each that is a regular file
  and not a symlink.
- Read as the collector reads after O-14: keys lower-cased, the last line wins; the greeting is `banner_file`'s
  content when that option is set and the file is not empty, else `ftpd_banner` when set, else the compiled
  greeting (a disclosure). A product is the collector's pattern, `(?i)\b(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)\b`,
  written for the body, the guard and the validate as `grep -Eiq
  '(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)'`.
- When a non-empty `banner_file` is set, the body leaves it (`banner_file <path> sets the greeting; left to the
  operator`): the file is the operator's notice, and commenting the option out would discard it. An empty one falls
  through. Otherwise, when `ftpd_banner` is unset or names a product, touch `$MB/vsftpd.edited` and rewrite every
  `ftpd_banner=` line, or append one (§3.7), as `ftpd_banner=FTP server ready.` (O-15).
- Restart: remove the per-run markers first (O-16); `$MB/vsftpd.was-running` when `systemctl is-active --quiet
  vsftpd.service`; with it, `systemctl restart vsftpd.service` (vsftpd has no reload or config test). A plan
  holding both FTP controls restarts it twice; that is accepted.
- Validate (guarded on a non-empty `banner_file`): the greeting read the same way names no product `&&` (no
  `was-running` marker, or the unit is active).
- Rollback: `restore` both paths; with the `edited` and `was-running` markers, `systemctl restart vsftpd.service` (a
  unit the body's restart left failed is started again).
- Tests: the both-keys and empty-file rows; a rerun with a `was-running` marker from an earlier run and vsftpd now
  stopped (no restart); a conf without a final newline.
- The proftpd half (`ServerIdent`) stays text; no CI image ships proftpd.

### 4.8 `muster.service.ftp_anonymous` — the vsftpd half (상, risk `restart_service`)

- The same targets, reading, markers, restart, validate shape and rollback as §4.7. When the effective
  `anonymous_enable` is not false as vsftpd reads it (`no`, `false` or `0`, case-blind; a missing key is the
  compiled YES), rewrite every `anonymous_enable=` line, or append one, as `anonymous_enable=NO`.
- The text says the body closes an anonymous service someone may have meant to run, and that the proftpd
  `<Anonymous>` block and pure-ftpd's `NoAnonymous` stay the operator's.

### 4.9 `muster.service.nfs_export_access` — the `no_root_squash` half (상, risk `restart_service`)

- The shipped body (owner and mode of `/etc/exports`, `backup: [/etc/exports]`) gains, inside its existing guard, a
  swap scoped to option lists in the text before a line's first `#`: `no_root_squash` preceded by `(`, `,` or a
  blank-led `-` that opens a default list (O-18), and followed by `,`, `)`, a blank or the line's end, becomes
  `root_squash`, one match per pass until none is left (adjacent matches share a comma). A path or client name that
  merely contains the word is untouched. The guard, the validate, the parity rows and the swap share one ERE:
  `^[^#]*([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)`.
- Markers (O-16): `$MB/nfs.was-running` when `nfs-server.service` is active (Debian's `nfs-kernel-server` is an
  alias); `$MB/nfs.edited` before the swap; with both, `exportfs -ra`. Its `exportfs` runs on the live server,
  which the next block, `nfs_server_disabled`, then stops (§2).
- Validate: the existing mode `case` `&&` no option-scoped `no_root_squash`, under the same guard.
- Rollback (new, so the word becomes `both`): `restore /etc/exports`; with both markers, `exportfs -ra`. A stub test
  pins it (§5).
- Text adds: `exportfs -ra` resyncs the kernel's table to every export file — it applies pending `/etc/exports.d`
  edits and drops runtime-only exports — and a rollback restores the files' view, not a hand-made live table. The
  wildcard half (which clients) and `/etc/exports.d/*.exports` stay text (`backup` takes no glob).

## 5. Proof

**The runner row** (`ci/roundtrip/runner.sh`, idempotent). New seeds and resets:

| control | seed / reset |
|---|---|
| `auditd_active` | `systemctl disable auditd`, kept running (`record()` compares `is-active`, and nothing can stop it again); the repair run enables it, the failure run's `restore_units` re-disables it |
| `audit_rules_loaded` | reset: `rm -f /etc/audit/rules.d/50-muster.rules`, `augenrules --load` of the stock set (the kernel list is `No rules` again), then `auditctl -b 4321`, a runtime value the persisted set does not carry, so only a working `audit.status` replay restores it; stock FAILs both clauses (case c) |
| `audit_disk_actions` | the first run saves the pristine `auditd.conf` to a path no body writes; every run copies it back, sets `disk_full_action = suspend`, and signals auditd |
| `account_inactivity_lock` | the first run saves the pristine `/etc/default/useradd` the same way; every run copies it back and runs `chage -I -1` on every local login-capable account; stock FAILs |

`runner.sh` never writes an `-e 2` or `--loginuid-immutable` anywhere, and removes muster's audit drop-in before its
`augenrules --load`. `rhosts_forbidden` is not on the runner: the VM's `files.user_rhosts` is absent (a system
account's home outside the declaration), so the row is MANUAL and never planned.

**Container rows.** `rhosts_forbidden` runs on all four (seed `printf '+\n' > /etc/hosts.equiv`, mode 0644).
`ftp_banner` (stock FAILs), `ftp_anonymous` (seed `anonymous_enable=YES`), `mail_expn_vrfy` (stock postfix FAILs)
and `nfs_export_access` (seed `/srv 192.0.2.0/24(rw,no_root_squash)`, an RFC 5737 range, then `exportfs -ra`) run on
the three init rows; `ubuntu2204` has no systemd, so the services gates read NOT_APPLICABLE there. Seed mechanics:

- the IPv6 workaround below applies to the EL and Debian seeds alike; the EL seeds install `vsftpd` and `postfix` in their first `dnf` line, and write the config seeds
  (`anonymous_enable=YES`) before the start loop; Debian installs `postfix` non-interactively with the debconf
  answers the probe settles;
- `vsftpd.service` and `postfix.service` join each init row's `START_UNITS`; on Debian, whose `postfix.service` is
  a `/bin/true` wrapper, the settle check reads `postfix@-.service` (or `postfix status`);
- the start probes run in the fix-roundtrip job's own docker (a branch dispatch), not only in the lab: the EL stock
  vsftpd (`listen_ipv6=YES`) and postfix (`inet_protocols=all`) depend on IPv6 in the runner's docker; any
  workaround (`listen=YES`/`listen_ipv6=NO`, `postconf -e inet_protocols=ipv4`) is applied by the seed before plan,
  so the record before the run captures it;
- a daemon that cannot run on a row leaves that row's `START_UNITS` and settle check, and its restart path is named
  unproven on that row in this design's §8, the plan and CONTRIBUTING (not `_roundtrip.yaml`, whose
  `unproven_units` only names declared units), with its stub test.

**`record()`** gains, per planned item: when an audit id is planned, `auditctl -l` and the `enabled`, `failure`,
`backlog_limit`, `backlog_wait_time`, `rate_limit` and `loginuid_immutable` lines of `auditctl -s` (keys matched
whole); when `password_policy` or `account_inactivity_lock` is planned, shadow fields 4, 5 and 7 per account and a
checksum of `/etc/shadow` with those three fields blanked (so a `chage` that changed anything else is caught); when
`nfs_export_access` is planned, `exportfs -s`; when an FTP id is planned, `systemctl is-active vsftpd.service`; when
`mail_expn_vrfy` is planned, `postfix status`'s exit code. `.backup[]` checksums already prove the file halves byte
for byte.

**The table.** `_roundtrip.yaml` gains the eight ids; `nfs_export_access` keeps its rows. The ci.yml `seeded` strings
change in the same commit.

| controls | rows |
|---|---|
| `auditd_active`, `audit_rules_loaded`, `audit_disk_actions`, `account_inactivity_lock` | `runner` |
| `rhosts_forbidden` | the four container rows |
| `mail_expn_vrfy`, `ftp_banner`, `ftp_anonymous`, `nfs_export_access` | the three init rows |

**Probes the plan runs first** (lab containers, the fix-roundtrip docker by branch dispatch, and the runner where the
answer depends on the VM); each answer becomes a plan ruling:

- augenrules: the hoisting of `-D`/`-e`; that a bare `augenrules` only regenerates, and its exit code when nothing
  changed; `audit.rules.prev`; which `-e` spellings auditctl accepts (if only `0`/`1`/`2`, the collector's reading
  of `-e 02` is a recorded over-read).
- auditd: the stock `auditd.conf` on Ubuntu 24.04; `auditctl --signal reload` on EL9, Debian 12, Ubuntu 22.04/24.04;
  whether a HUP applies the five action keys (the reconfigure journal line); the unit's `RefuseManualStop` and
  augenrules `ExecStartPost` (with its `-` prefix) on every row's unit file; `auditctl -s`'s exact key names on the
  runner kernel.
- postfix: the non-interactive install on the three init rows, its stock `disable_vrfy_command`, `main.cf`'s mode and
  inode after `postconf -e` under `umask 077`, whether `postfix check` creates directories, whether it starts in each
  container, whether `main.cf` is a conffile on each family.
- vsftpd: its stock `ftpd_banner`/`anonymous_enable` lines; whether it starts in each container; the 220 line read
  from port 21 with both banner keys set, each way, and with an empty banner file.
- NFS: `exportfs -ra` with the seeded line in each init container (`/srv` on the overlay root; a tmpfs with `fsid=` if
  it fails); whether nfs-utils accepts a `-opts` default list (O-18).
- SELinux: whether `sed -i`, `postconf -e` and `cp -a` keep a file's context on an EL9 host with SELinux enforcing,
  read on a lab VM where one exists; the §3.11 `restorecon` rule holds either way.
- The runner: its local login-capable accounts and their shadow fields before the first run (the `runner` account
  must not be disabled), and that no other scripted control plans because vsftpd or postfix runs on an init row.

## 6. Tests, documents

**Commits, in order.** The three collector fixes come first, each alone (O-14, O-17, O-18): the reader, its fixtures
under `controls/testdata/<id>/`, a fuzz seed for the changed parser, the mutation test at zero survivors, a
description-only facts golden regeneration (a `since` entry only if a leaf is added), a CHANGELOG "Fixed" line. Then
O-11's guards, then the bodies, then CI, then the documents.

**Tests.** Per body, shipped-body Linux tests in the 3D-2c style (paths rebased, tools stubbed first on `PATH`) as
listed in §4; the double `restore` (O-9); the per-run records on a rerun (O-16); the reader parity test (O-10); O-11's
three paths in the symlink table; the round-trip table test and the units pin as above. `all-scripted.sh`, the remedy
goldens and the shellcheck set regenerate; `examples/*-fix-report.*` change and are refreshed from the branch's
`examples.yml` run before the merge; the mutation test keeps zero survivors.

**Documents** (English and Korean in the same commit; the `.ko.md` pair of this design is written before the design
commit). Main design: §10.2 marks 3D-2d with this design's link and names what follows (3D-1b, 3D-3); D34 unchanged.
CLAUDE.md's Fix section: the enabling units body, O-2/O-3, the rollback that calls `restore`, the per-run markers, the
new seeds and `record()` lines. CONTRIBUTING pair: §3's conventions, the units-body paragraph reworded for an enabling
body. README pair: status and roadmap. THREAT_MODEL: O-2 and O-3, and "no body deletes a kernel audit rule it did not
load in this run". ATTRIBUTION: the floor's rule lines (O-4). CHANGELOG: Fixed — vsftpd's greeting precedence (O-14),
the auditd `exec` action (O-17), the exports default list (O-18); Added — the eight bodies and the `no_root_squash`
half; Changed — the four risks, the symlink guards, the `password_hash_algorithm` text; Controls: the new
`controls/VERSION`.

## 7. Parked

- **Text forever** (a per-host judgment, policy or a credential): `audit_immutable` (O-2), the wording of a login
  banner (`login_banner`), `sudo_logging` (a sudoers edit is a sudo outage risk; both stock families pass),
  `remote_log_forwarding` (a receiver), `file_integrity_tool` (a package and a baseline), `password_hash_algorithm` (a
  rehash needs the plaintext; its text gains "locking the account does not clear the finding, and never blank the
  field"), the snmp, dns, ftp TLS, firewall and account-choice controls, the four `automation: manual` mail and dns
  controls, the NFS wildcard half, the `.rhosts` half, the vsftpd non-empty `banner_file` case,
  `audit_log_permissions`'s `log_group` half (Ubuntu's `adm` is a host decision).
- **A later cycle (3D-2e candidates):** mode and owner work on user homes and dotfiles (`env_file_permissions`,
  `home_dir_permissions`, `startup_script_permissions`), account fields (`system_account_shells`,
  `ftp_account_shell`, `ftpusers_root`), `shadow_passwords` (`pwconv`), journald persistence (`syslog_policy`'s
  journald half), the TMOUT half of `session_timeout`, a mounts record kind for the four `*_mount_options` controls,
  and the super-server half of the ten service controls and the nsswitch half of `nis_disabled` (both need `backup`
  beside `units`, which `units_exclusive` forbids — a schema decision). The final-newline rule (§3.7) for the shipped
  appenders.
- SELinux label proof in CI (no row runs SELinux; §3.11 is the rule meanwhile).
- A shared "set a key" helper (each file's grammar differs: first wins, last wins, case, separators) and a lint that
  every written path is guarded and in `backup` (O-10/O-11's tests are this cycle's answer).

## 8. As built

Where this section and §1–§7 disagree, this section is the design as built. Plan rulings O-19..O-63 (the plan, the
pre-flight and the probe) and O-64..O-78 (execution, the cycle's ledger) are in
`docs/superpowers/plans/2026-10-19-stage3d2d-content-scripts.md`'s Execution notes; the ones that change this text:

- **O-74 supersedes O-5's "or the runtime is already locked" and §4.1 step 3's locked-runtime start.** `auditd_active`
  refuses a start whenever a lock is pending in `rules.d/*.rules` or `audit.rules`, whatever the runtime lock state,
  and no longer reads `auditctl -s`. `loginuid_immutable` locks only its own feature (the rule list stays writable, so
  a start's load applies a pending `-e 2`), and a start's inertness under `enabled 2` was never measured. O-3's
  "auditd_active runs both halves only before a start" now reads "runs the pending half only before a start".
- **O-41: the lock pattern matches anywhere on a line** (`-b 8192 -e 2` applies the lock too), as O-3 now spells it.
- **O-57: auditctl accepts `-e` only for the strings `0`, `1` and `2`** (`-e2` through getopt). The collector's
  `lastEnableValue` over-reads `-e 02` and `-e +2`, which auditctl rejects: a recorded divergence in the safe direction.
- **O-56 and O-29: the reload is `auditctl --signal reload` only** (audit 3.0.7, 3.0.9 and 3.1.5 all carry it); EL's
  `service auditd reload` runs `augenrules --load` first and is never used. **O-71:** `auditctl --signal` fails on a
  dead daemon; a rollback that meets one logs `rollback failed` and never starts auditd.
- **O-72 (corrected): a failed rerun of `audit_rules_loaded` restores `50-muster.rules` holding the first run's floor**
  (`backup()` replaces an absent marker with a copy once the path exists), so the file and the kernel agree.
- **O-73, O-75, the duplicate-row line:** three log lines §4 did not name — `auditctl -l failed; refused`,
  `<name>: password ageing fields are not numbers, left as is` (the fix wave widened it for a `max` below -1, O-77) and
  `<name>: more than one /etc/shadow entry, left as is`.
- **O-77: the inactivity body also skips and names an account whose `max` is below -1** (pam_unix's only guard is
  `max != -1`; shadow's `isexpired` guards `>= 0`) **and any name with more than one shadow row** (`chage` and pam_unix
  read the first row; the collector and the body the last).
- **O-64: successive exports `-opts` default lists accumulate** (measured on rocky9-init: `-no_root_squash X -rw Y`
  exports Y with `rw,no_root_squash`); O-18's collector fix adds a later list to the earlier one. **O-60:** a client's
  own `root_squash` after a default `no_root_squash` squashes on the host; the collector's substring test reads it FAIL
  (conservative, O-50).
- **O-69: the exports ERE can rename a path** whose last component ends in `,no_root_squash` or `(no_root_squash`
  before a blank, or a quoted path holding ` -no_root_squash `: an accepted pathological corner (anchoring past the
  first token would break continuation rows).
- **O-67: real `postconf -e` (postfix 3.7.11) glues its line onto a final line that lacks a newline**, so the postfix
  body runs §3.7's final-newline guard before it.
- **O-59: vsftpd hits systemd's start limit on repeated restarts**, so every restart in a body or rollback is preceded
  by `systemctl reset-failed vsftpd.service 2>/dev/null || :`. A `banner_file` of `-` or `/dev/stdin` is treated as
  operator-set (the reader never reads standard input).
- **O-68:** the NFS body removes its per-run markers at the top, outside the `/etc/exports` guard.
- **O-65 and the vsftpd case folding:** a line led by a Unicode space, and a product name spelled with U+212A or U+017F,
  are read differently by the Go collector (Unicode-aware) and the `LC_ALL=C` shell readers: recorded divergences; the
  block ends `done` and the next check names the line.
- **The `rhosts_forbidden` validate** is the count form (`[ "$(LC_ALL=C grep -Ec … || :)" = 0 ]`), equivalent to §4.5's
  `! grep -Eq`.
- **O-49 (§5):** the NFS rollback's `exportfs -ra` runs on every init row's failure run (the server is active there);
  O-12's "stub-only" wording for it is withdrawn.
- **O-60, O-37 and O-58 (§5 seeds):** the init rows export a tmpfs (`/srv/ci … fsid=1`; the overlay root cannot be
  exported), apply the IPv6 workaround on EL and Debian alike, and Debian settles on `postfix@-.service`.
- **The whole-branch review's fixes (O-79..O-84).** O-79: a trailing default list (`/srv 192.0.2.8 -no_root_squash`)
  also exports to the world (measured), so the collector mints a `*` record for it — it read a false PASS. O-80: a `-`
  token right after a `-` list is a host name to nfs-utils (it fails to resolve and exports nothing), so the collector
  ignores it and does not join it; lists separated by a client still accumulate (O-64). O-81: `rhosts_forbidden`
  refuses a `+` line that carries a `-user` or `-@netgroup` field (the first matching line decides, so commenting out a
  denial would widen trust) — the block fails and the file is left. O-82: `ftp_banner`'s reader never opens
  `banner_file`; the shell counts it only as a regular, non-symlink, non-empty file (the collector's rule), which replaces
  O-59's `-`/`/dev/stdin` case. O-83: an auditd action is reduced on the ASCII space only (a tab-joined value, which
  auditd refuses, stays whole and FAILs). O-84: `record()` fails loudly when an audit, export or shadow producer fails
  or comes back empty for a planned id.
- **The inactivity log line for a `max` below -1** reads `password ageing fields are not numbers or the maximum is
  below -1, left as is`.
- **O-85 and O-86 (the draft PR's first run).** GitHub's ubuntu-24.04 image 20261015.610 ships
  `/etc/profile.d/debuginfod.sh` as a symlink into `/usr/share/libdebuginfod-common/` (Ubuntu's postinst, under ucf);
  the env collector's no-follow read made all seven `env.shell.*` keys an error and `collect-root` failed — on main
  too. The collector now reads a profile.d entry linked to an absolute clean `/usr/share/<pkg>/<file>` through one
  level (the target opened no-follow, regular), and declines any other symlinked entry: the seven keys read absent
  naming it (C4), which the three env controls (`absent_means: fail`) read FAIL.
- **Proof as of the branch:** the four container rows' repair runs and the three init rows' guard and failure runs were
  replayed green on the lab's docker (Task 12); the runner row, IPv6 in the CI docker, the runner's accounts and `auditctl -s` keys, and whether a
  HUP applies the five disk-action keys are proven only by the PR's CI run (O-34).
