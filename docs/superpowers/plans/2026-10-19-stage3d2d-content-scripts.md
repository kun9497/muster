# Stage 3D-2d — the audit family, the inactivity bound, and what a file says: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eight more controls carry a review-script body and `nfs_export_access` gains its `no_root_squash` half (56 scripted controls), after three collector readings the bodies depend on are fixed; the audit, inactivity and content bodies are proven on the runner VM, the init containers and stub tests.

**Architecture:** No schema, lint, template or record-kind change. Three collector fixes land first, each alone (vsftpd greeting precedence, the auditd `exec` action, the exports `-opts` default list). Then two shipped bodies gain symlink guards, and the nine bodies are written in four groups (rhosts; vsftpd; postfix and NFS; audit; inactivity), each with its stub-run tests in `internal/remedy`, its reader-parity rows in `internal/collect/collectors`, its round-trip table entry and the `seeded` ids in the same commit. CI's seeds and `record()` follow, then the documents.

**Tech Stack:** Go 1.25.5, standard library, `gopkg.in/yaml.v3` (existing), POSIX `sh`, audit userspace (`auditctl`, `augenrules`), systemd, shadow-utils `chage`, postfix (`postconf`, `postfix`), vsftpd, nfs-utils `exportfs`, GitHub Actions, shellcheck v0.9.0.

**Spec:** `docs/superpowers/specs/2026-10-19-stage3d2d-content-scripts-design.md` (EN canonical, `.ko.md` pair) at `74ea340`, rulings O-1..O-18. Plan rulings continue the list from O-19. Code maps with today's line numbers: `.superpowers/sdd/2026-10-19-stage3d2d-content-scripts/plan-map-{collectors,remedy,ci,docs}.md` and the scope maps `code-map-*.md` (ignored; the controller hands each task its sections). Review digests: `spec-review-r{1,2}.md` beside them.

## Global Constraints

- muster never executes a remediation. `internal/remedy` imports no `os`, `os/exec`, `net`, `syscall` or `time` (`TestRemedyPackageHasNoHostImports`); test files may.
- No schema field, lint rule, prologue helper, record kind, text-only reason or rollback word is added (O-1). The template, the failure order (declared rollback → `restore_units` → `restore_modes` → `restore` → `restore_sysctl` → `restore_modules`) and the plan JSON shape are unchanged.
- The only snapshot value on a non-comment script line stays the machine-id hash; a parameter value enters only as a `P_<name>='<value>'` line, and a body copies it to a plain variable before any `sed` (`TestShippedBodiesPlaceParametersSafely`).
- Every body is POSIX `sh`, shellcheck-clean at the default severity under v0.9.0, `set -e`-safe in its subshell, has no here-document, a one-line `validate`, `idempotent: true`, and writes only when the value read the collector's way is outside the accepted set (E-8 as amended by O-6). Every command whose output a body, validate or rollback parses runs under `LC_ALL=C`.
- No body makes a one-way runtime change, and no body, seed or test sends `-e 2` or `--loginuid-immutable` (in any spelling) to a real `auditctl`; stub-read fixture files may contain them (O-2, O-48).
- Per-run records (`audit.loaded`, `audit.status`, `<daemon>.was-running`, `<daemon>.edited`, `disk.keys`, `inactive.run`) are removed as the body's first action and written fresh; file backups and `inactive.list` are first-kept (O-16).
- Nothing in the Go suite touches the host: every body test runs against stubs first on `PATH` (`auditctl`, `augenrules`, `systemctl`, `kill`, `chage`, `postconf`, `postfix`, `exportfs`, `sshd`) with every absolute path rebased under `t.TempDir()` and `MB` set to a temp dir. `collect-root` runs `go test ./internal/remedy/` as root on a VM with a live auditd: a test that reaches a real `auditctl` or `augenrules` corrupts the later oracle step.
- Fixtures and seeds use RFC 5737 addresses only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Documents are English canonical with the `.ko.md` pair in the same commit where a pair exists; the main design pair stays line-aligned. `CLAUDE.md`, `THREAT_MODEL.md`, `ATTRIBUTION.md`, `CHANGELOG.md` and `examples/README.md` have no pair. Never copy KISA or CIS text.
- Commits use the personal identity (pinned) and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push, amend, rebase or stash.
- From Task 5 on the control set's digest changes (Task 5 is the first commit that changes a control YAML; O-44) (`controls/VERSION` becomes `kisa-unix-2026+2026.10.19`), so `TestExamplesLoadAndCheck` skips its byte comparison with a note; every commit is green; the merge-step refresh re-pins the examples, which are never hand-edited.
- Each body task adds its `_roundtrip.yaml` entry and its ids to the ci.yml `seeded` strings in the same commit as the `script` (`TestEveryScriptedControlIsInTheRoundtripTable`). Seeds and `record()` come in Task 12. A branch push runs no CI (`ci.yml` triggers on `push: [main]` and `pull_request` only): fix-roundtrip first runs on the draft PR the Merge section opens, on the user's word (O-34).
- On Windows the Linux tests (`internal/collect/...`, `shipped_*_test.go`) do not build; each task that adds one runs it on the lab (`bash C:/Users/ssk/muster-lab/lab-sync.sh <worktree>` then `bash C:/Users/ssk/muster-lab/lab-run.sh 'go test ./internal/remedy/ -run <name>'`, tree at `/root/muster-dev`) and quotes the output; lab shellcheck is `docker run --rm -v "$PWD:/m" -w /m koalaman/shellcheck-alpine:v0.9.0 shellcheck -s sh <files>`.
- Every body planned with a script at stock on a round-trip row must end `done` there in the repair run and reach its validate in the failure run (the failure run counts one `validate failed, rolling back` per block; a refusal logs `script failed` instead and breaks the count).

## Plan rulings (O-19 …)

- **O-19 — O-17 is done in `parseAuditdConf`.** For every key but `log_file` and `log_group`, the stored value is the first whitespace-separated field of the trimmed value, lower-cased (`""` for an empty value). No `Source.Raw` is added (the leaves' bytes stay as they are for one-word values, and the examples are unaffected beyond the verdict).
- **O-20 — O-18's reading, unless the probe says otherwise.** On an exports line, a token starting with `-` sets the line's default options (`tok[1:]`) for the client tokens after it, replacing an earlier default on that line; a client's record carries `options` = the defaults, a comma, then its own options (either part omitted when empty); a line whose only tokens after the path are default lists exports to `*` with those options. `root_squash` stays `!strings.Contains(options, "no_root_squash")`. If Task 1's probe shows nfs-utils rejects or reads the syntax differently, Task 4 follows the probe, and if nfs-utils rejects it, Task 4 is dropped and the parity row records the divergence.
- **O-21 — A body's reader is a one-line shell function, and the validate repeats its program.** Each new body that gates on a file value defines its reader as `rd_<what>() { <command>; }` on one line (for example `rd_greeting() { awk '…' "$1"; }`). The parity test (`internal/collect/collectors/remediation_parity_test.go`, Linux) extracts the line by the regexp `^\s*rd_<what>\(\) \{.*\}$`, fails when it is missing, runs it with `sh` over each row's file and compares with the Go parser; a second assertion requires the function's first single-quoted string (its awk program or grep/sed pattern) to appear verbatim in the control's `validate` (the validate runs in its own subshell and cannot call the body's functions, so it repeats the program).
- **O-22 — Marker names.** `$MB/<d>.was-running` and `$MB/<d>.edited` with `<d>` one of `auditd`, `postfix`, `vsftpd`, `nfs`; `$MB/audit.loaded`, `$MB/audit.status`, `$MB/disk.keys`, `$MB/inactive.run` (per run); `$MB/inactive.list` (first-kept).
- **O-23 — Exact log strings the tests match** (the id prefix is `<control id>: `):
  - `is a symlink, left as is` (vendor file, K2) and `is a symlink (a mask), left as is` (muster drop-in, S-27), both followed by the path, as shipped.
  - `auditd_active`: `install the audit package (audit on the EL family, auditd on Debian and Ubuntu)`; `kernel holds rules a start would replace; start left to the operator`; `a one-way audit setting is pending (-e 2 or --loginuid-immutable); start refused`; `auditctl -l failed; start refused`.
  - `audit_rules_loaded`: `/etc/audit/rules.d is missing or a symlink; refused`; `a one-way audit setting is pending or in force; refused`; `auditctl -s cannot tell the lock state; refused`; `kernel rules are not persisted; persist your own set`.
  - `audit_disk_actions`: `<key>: no writable value in the list in force; left to the operator`.
  - `account_inactivity_lock`: `max_inactive_days is negative; refused`; `<name>: no /etc/shadow entry, left as is`; `<name>: inactivity field is not a number, left as is`; `<name>: must change its password at next login, left as is`; `<name>: password expired <k> days ago; the bound would disable it now; change its password first`; `<name> will be disabled on <YYYY-MM-DD> unless its password changes`.
  - `mail_expn_vrfy`: `postconf is missing; the sendmail half is the operator's`; `postfix check fails before any change; refused`.
  - `ftp_banner`: `banner_file <path> sets the greeting; left to the operator`.
- **O-24 — `controls/VERSION` is `kisa-unix-2026+2026.10.19`,** bumped in Task 5 (the first commit that changes a control YAML; O-44 moves it from Task 6).

## Pre-flight rulings (O-25 …)

The pre-flight (eight lenses, three refuters per finding, a critic: 107 findings, 93 upheld, merged into 30 items, `preflight.md` P-1..P-30) is folded here. Where a task step and a ruling below disagree, the ruling wins; the implementer of each task is handed the rulings its task names.

- **O-25 (P-1) — the postfix reader reads the row, not the host.** `rd_vrfy() { LC_ALL=C postconf -c "$1" -h disable_vrfy_command; }`, called as `rd_vrfy /etc/postfix` in the body (the validate inlines the same `postconf -c /etc/postfix -h …` text). The parity test writes each row as `<tmp>/main.cf`, passes `<tmp>`, and `t.Skip`s with a reason when `exec.LookPath("postconf")` fails: CI (no postfix in the `test` job) pins the postfix half with the `TestPostfix*` stub tests only, and the `Disable_Vrfy_Command` case-fold divergence is stub-pinned, not parity-proven.
- **O-26 (P-2) — one ERE for every exports reading.** `rd_nrs`, the sed address, the validate and the parity rows share `^[^#]*([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)`; `rd_nrs() { LC_ALL=C grep -Ec '<ERE>' "$1" || :; }`. The swap changes one match per pass, `sed -i -E 's/^([^#]*)([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)/\1\2root_squash\3/' /etc/exports`, inside a loop bounded at ten passes that stops when `rd_nrs` reads 0. Rows added to `TestNfsSwapsOnlyOptionTokens` and the parity table: `/srv/x-no_root_squash 192.0.2.9(rw)` beside a real violation (the path untouched), `#/g 192.0.2.7(no_root_squash)` (untouched), `/f 192.0.2.6(rw) # (no_root_squash)` (the comment untouched), a tab before `-no_root_squash` (swapped), a `\` continuation, and `/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)`. Design §4.9 says so.
- **O-27 (P-3, critic 6) — root-only tests are gated, and every body task also runs non-root.** `TestNfsSwapsOnlyOptionTokens` and `TestNfsRollbackReexports` start with `if os.Geteuid() != 0 { t.Skip("root: the body chowns") }` (collect-root's sudo step runs them). Every task from 5 on runs its new tests once more on the lab as a non-root user (the lab's ordinary account, or `su nobody -s /bin/sh -c 'HOME=/tmp GOCACHE=/tmp/gocache go test … -run <names>'` over a copy readable by that user) and quotes the output.
- **O-28 (P-4) — the parity harness.** `runReader(t *testing.T, fn, call string, files map[string][]byte) (stdout string, code int)` writes each file under a temp root, substitutes `{root}` in `call` and in every file's content (a conf says `banner_file={root}/etc/issue.net`), runs `sh -c` without `-e` and without forcing a locale, and returns stdout and the exit code (a non-zero exit is data). `readerLine(t, r, name string, inValidate bool) string` checks the verbatim-in-validate rule only when `inValidate`: true for `rd_plus`, `rd_greeting`, `rd_anon`, `rd_nrs`, `rd_present`, `rd_inactive` (the useradd reader); false, each with its reason in the test's table, for `rd_lock` (a refusal guard the validate never needs), `rd_action` (the validate checks lists over `disk.keys`), `rd_vrfy` (a tool call), `rd_login` (the enumeration; the validate reads `inactive.run`). `readerLine` also asserts the reader's command starts with `LC_ALL=C`. `rd_present` and `rd_lock` compare by exit code (0 = present / locked). For vsftpd the collector side keeps `/etc/issue.net` in its fake `fsAccess` (only declared paths are read) and the shell side gets the same bytes at `{root}/etc/issue.net`; the test comment says so.
- **O-29 (P-5) — auditd is reloaded with `auditctl --signal reload` only.** No pid-file `kill` (a builtin a PATH stub cannot catch, and a stale pid file can name a reused pid). Task 1 checks `--signal` on EL9, Debian 12, Ubuntu 22.04 and 24.04; if any family lacks it, the controller stops and returns to the user. The `kill` stub is dropped; `TestAuditBodiesSendNoBareKill` asserts no rendered audit body has a `kill` word. The auditctl stub needs no `--help` arm.
- **O-30 (P-6) — the NFS validate keeps its guard.** Verbatim: `[ ! -f /etc/exports ] || [ -L /etc/exports ] || { case "$(stat -c '%u %a' /etc/exports)" in <the 16 arms>) ;; *) false;; esac && [ "$(LC_ALL=C grep -Ec '<O-26 ERE>' /etc/exports || :)" = 0 ]; }`. Rows that run it and expect 0: an exports.d-only host (no `/etc/exports`), and a symlinked `/etc/exports` to a file holding `/x 192.0.2.1(no_root_squash)` (the link untouched). The rollback's last step is `if [ -f "$MB/nfs.edited" ] && [ -f "$MB/nfs.was-running" ]; then exportfs -ra; fi`.
- **O-31 (P-7) — rebasing.** One `strings.NewReplacer` pass per helper (as `shipped_test.go:112`), never sequential `ReplaceAll`; `rebaseContent` lists `/etc/vsftpd` once (it covers both confs), `/etc/hosts.equiv`, `/etc/postfix/`, `/etc/exports`; every helper test asserts no rebased text contains `root+root`. Fixture content never names a bare host path: the vsftpd rows write `banner_file=<root>/etc/issue.net`. `rebaseAudit` covers `/etc/audit/`, `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers` (which covers `/etc/sudoers.d/`). Task 10 seeds a subset (no `gshadow`, no `sudoers.d`) and asserts the exact rebased `-w` lines, and pins the unrebased floor text separately by reading `r.Script`.
- **O-32 (P-8) — stubs show order and fail closed.** Every reload, restart and `exportfs` stub appends `<verb>` and then the content of the file the daemon would read to one shared `$STUB/calls` (the `accountTree` systemctl shape); rollback tests assert `strings.HasSuffix(calls, "<verb>\n"+before)`, as `TestSessionTimeoutRollbackRestoresBeforeTheReload` does. Task 7 adds `TestContentRollbackDoubleRestoreIsHarmless`: after a forced failure, no `ROLLBACK INCOMPLETE` and no restore failure, for a conf that existed and for one that was absent. `TestPostfixAbsentLeavesTheSendmailHalf` runs with `PATH=<tmp bin with symlinks to sh, awk, grep, sed, cat, rm, tail, printf, stat, chown, chmod only>` and first asserts `command -v postconf` fails. `contentTree`, `auditTree` and the inactivity tree write fail-closed stubs (log, `exit 99`) for every host tool the body may call that the test does not model, and `selinuxenabled` exiting 1.
- **O-33 (P-9) — stub specs.** Task 9's `auditTree`: its `systemctl` is a wrapper that, on `start auditd.service`, runs the `augenrules --load` stub and then `units_test.go`'s `systemctlStub` logic (a second file in `bin`; `systemctlStub` itself is never edited, because `TestUnitHelpersRestoreRecordedState` compares `$STUB/calls` exactly); `$STUB/status` is seeded from `internal/collect/collectors/testdata/auditctl_s.sample` (it carries `backlog_wait_time_actual` and the three-field `loginuid_immutable`); `-l` prints `$STUB/rules` when non-empty, else `No rules`. Task 7's `systemctl restart` fails once while `$STUB/restart_fail_once` exists (removing it, leaving the unit inactive) and succeeds after; the test asserts both restarts and the final active state. Task 11's tree (in `shipped_inactivity_test.go`, never the shared `accountTree`, whose `password_policy` tests use real time): `chage` exits 1 for a name with no row in the rebased shadow and edits field 7 for `-I`; `date` is `case "$1" in +%s) cat "$STUB/now";; *) exec /bin/date "$@";; esac`; expected dates come from `time.Unix(…).UTC()`.
- **O-34 (P-10, critic 1) — the runner answers come from a draft PR.** Task 1 also probes Ubuntu 22.04; answers the `-e` spellings from auditctl's source or empirically with 1-valued spellings only (`-e 01`, `-e +1`, `-e1`) — never a 2-valued spelling anywhere, never on the runner or a `--pid=host` container; adds `getenforce` and `ls -Z` in the EL containers. The answers only the runner can give (whether a HUP applies the five keys there, `auditctl -s` keys on the azure kernel, the runner's login-capable accounts and their shadow fields — the `runner` account must not be disabled —, docker IPv6, that no other scripted control plans because vsftpd or postfix runs) are open rulings closed by the draft PR's run. The Merge section is reordered (below).
- **O-35 (P-11) — conffiles are measured.** Task 1 runs `dpkg-query -W -f='${Package}: ${Conffiles}\n' vsftpd auditd postfix passwd nfs-kernel-server` and `rpm -qc vsftpd audit postfix shadow-utils setup nfs-utils`; Tasks 7–11 each add the design §3.12 sentence for every edited file the probe confirmed (candidates: `vsftpd.conf`, `auditd.conf`, EL `main.cf`, `/etc/exports`, `/etc/default/useradd`).
- **O-36 (P-12) — `restorecon` only on a file a tool replaced or created.** Never after `sed -i` (GNU sed keeps the context) and never after `restore` (`cp -a` keeps it). One spelling: `if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi`, used after `postconf -e`, a created `/etc/default/useradd` and a created `50-muster.rules`. The `sed -i` restorecon lines in Tasks 7–10 are dropped. Design §3.11 says so.
- **O-37 (P-13) — seeds.** Task 1 decides, per family, the IPv6 workaround and where the export lives. Task 12 applies the workaround on EL and Debian alike (`listen=YES`/`listen_ipv6=NO` in the vsftpd conf; `postconf -e inet_protocols=ipv4` after postfix is installed) before the start loop; the export uses `/srv` only if Task 1 measured `exportfs -ra` exit 0 on all three init rows, else `mkdir -p /srv/ci; mount -t tmpfs tmpfs /srv/ci` with `/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)`. Design §5 says "EL and Debian".
- **O-38 (P-14) — the `INACTIVE` reader parses digits by hand.** One `LC_ALL=C awk` (sign; `0x` then hex digits; a leading `0` then octal digits; decimal; anything else -1; no `+0`, no `strtonum`, no `{n}` intervals), the same program in the validate. Parity rows `INACTIVE=08`, `INACTIVE= 30`, `INACTIVE=30\r`, `INACTIVE=0x`, `INACTIVE=abc`.
- **O-39 (P-15) — `inactive.run` exists after every run.** `: > "$MB/inactive.run"` right after the `rm -f`; the validate's awk selects files with `FILENAME == ARGV[1]`, never `FNR == NR`; a row "a rerun that changes no account" exits 0 with a passing validate. A missing `/etc/shells` makes `login_capable` non-ok, so the item is never planned: no fallback is written.
- **O-40 (P-16) — an unset last change with a real maximum is skipped.** pam_unix's expiry check has no guard for `sp_lstchg == -1`: once field 7 is set, such an account moves from "must change" to "expired". The body skips and names an account whose `last` is empty or below 1 while `max` is set and not 99999, and never prints a date when `last <= 0`. The Task 11 row "empty `last` → changed" becomes "empty `last` + max 60 → skipped, named"; "empty `last` + max 99999 → changed" stays. Design §4.4 says so.
- **O-41 (P-17) — the lock may stand anywhere on the line.** `rd_lock` matches `(^|[[:space:]])(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable([[:space:]]|$))`; `TestAuditRefusesAPendingLock` gains `-b 8192 -e 2` and `-D -e 2` (the body refuses where the collector reads none, which the one-sided parity allows). O-3's wording in the design follows.
- **O-42 (P-18) — the floor and `auditctl -s`.** `for p in …; do if [ -e "$p" ]; then printf -- '-w %s -p wa -k %s\n' "$p" "<key>"; fi; done > "$f"`. `s=$(LC_ALL=C auditctl -s) || { log "…: auditctl -s cannot tell the lock state; refused"; exit 1; }`, then awk over `$s`; in `auditd_active` `s=$(LC_ALL=C auditctl -s 2>/dev/null) || s=`. The refusal row's stub prints `enabled 1` and exits 1.
- **O-43 (P-19) — the inactivity rollback replays this run's names only.** For each name in `inactive.run`, the rollback replays its value from `inactive.list`; a name in an earlier run's list but not in this run's `inactive.run` keeps its current field 7 (a rerun row in `TestInactivityRollbackReplaysTheList` pins it). This matches O-16.
- **O-44 (P-20) — the version moves in Task 5.** O-24's bump goes in Task 5; its Run step notes the `TestExamplesLoadAndCheck` digest skip.
- **O-45 (P-21, P-22, P-29) — commands and small test fixes.** Task 6 Step 8 runs `go test -run 'TestRhosts' ./internal/remedy/ ./internal/collect/collectors/` (one `-run`, two packages). Task 2 Step 1 writes `a.contents = map[string][]byte{"/etc/issue.net": {}}` (the field may be nil). The new `TestFileScriptsRepairOnARealFile` stubs are written inline with `writeStub` (`shipped_test.go` is untagged; it must not reference the Linux-only `contentTree`). Task 5's rationale: the guarded body does reach the rollback with the link in place in a whole block; the rollback-alone test proves the rollback's own skip, and the whole-block row may write `ssh_active`.
- **O-46 (P-24, P-25) — named cases and texts the plan had missed.** `TestAuditRefusesAPendingLock` adds a missing `rules.d`, a symlinked `rules.d` and a symlinked `50-muster.rules`. The inactivity tests add a name skipped on the rerun whose field 7 is out of bounds (validate exit 0) and root's date line printed first. Task 11's text says what is written (`INACTIVE=` and `chage -I` per login-capable account, root included), O-7's sentence on a host that ages root, the skip rules (O-40 included), that NSS-only accounts are left, and the §3.12 sentence.
- **O-47 (P-26, P-27) — one ERE per vsftpd rewrite, and the locale inside readers.** The rewrite and its existence test share `^[[:space:]]*ftpd_banner[[:space:]]*=` with `sed`'s `I` flag (and `anonymous_enable` likewise), writing the replacement at column one; rows `FTPD_BANNER = vsFTPd` and an empty value. Every reader and its validate copy carries `LC_ALL=C` itself.
- **O-48 (P-23) — constraint wording** (folded into Global Constraints above).
- **O-49 (P-28) — CI details.** `record()`'s postfix line is `rc=0; x postfix status >/dev/null 2>&1 </dev/null || rc=$?; printf 'postfix-status %s\n' "$rc"`. The NFS rollback's `exportfs -ra` runs on every init row's failure run (the server is active there); O-12's "stub-only" wording for it is corrected in §8.
- **O-50 (P-30) — exports override, auditd start, commit wording.** O-20's joined `options` keeps the `Contains` test (a client's own `root_squash` after a default `no_root_squash` reads FAIL, conservative): recorded as a divergence, and the Task 4 CHANGELOG line names the new `*` record for a default-list-only line (the wildcard clause FAILs there). The `auditd_active` text says starting auditd applies the host's configured disk actions at once, `single` and `halt` included. The Task 2, 3 and 4 commit messages say the facts golden change is description-only.
- **O-51 (critic 2) — walk the runner plan before Task 12.** `auditd_active` and `audit_rules_loaded` are both 상/`restart_service`; `audit_` sorts first, so the rules block runs before the start. Before Task 12 the controller renders the plan from a scratch copy of `examples/ubuntu-24.04-vm.json` with the runner seeds applied by hand to its facts, records which O-4 case each audit block hits and which marker each writes, and fixes the seeds so case (c) runs on the runner; if no seed can reach (c) there, the floor is proven by stub tests only and §8 says so.
- **O-52 (critic 3) — fixtures for the new verdict paths.** Tasks 2–4 each add one control fixture per new verdict path (the empty banner file falling through: `fail-vsftpd-empty-banner-file.json`; the `exec` actions: `pass-exec-actions.json`; the `-opts` world record: `fail-default-list-world.json`) and run `TestEveryMutantIsKilled`.
- **O-53 (critic 4) — the fuzz inventory.** Any new or changed function taking `[]byte` (or a first `content`/`line` string parameter) in Tasks 2–4 gets a `Fuzz<Name>` with seeds and a `fuzzTargets` row, or a `coveredThrough` row; `TestEveryParserHasAFuzzTarget` runs in each task's Run step.
- **O-54 (critic 5) — the golden is the reviewer's rendered view.** From Task 5 the examples byte check is skipped, so each body task's review reads the `all-scripted.sh` diff line by line.

## Review Focus

1. **A rerun with the same `MUSTER_BACKUP` after the operator changed the host** (vsftpd stopped since run 1; auditd's kernel list filled by hand since run 1; an account's field 7 raised since run 1). No daemon is started, no rule is deleted, and the rerun's validate checks only what this run wrote. (Tasks 7, 10, 11: the `…Rerun…` cases.)
2. **A `-e2` or `-e 02` spelling in a persisted file, or an `auditctl -s` that fails**, on a host whose auditd is inactive. `audit_rules_loaded` refuses before any load; `auditd_active` enables and refuses the start. (Task 10: `TestAuditRefusesAPendingLock` rows.)
3. **A tuned list whose first member auditd does not accept for that key** (`allowed_disk_error_actions: [rotate, syslog]`, `[halt, single]`). The body writes `syslog`, or leaves the key and ends `done`. (Task 9: `TestDiskActionsWriteOnlyAcceptedValues`.)
4. **An account whose password expired more than `n` days ago, and root with a real maximum.** The first is skipped and named; root gets field 7 and a logged disable date. (Task 11: `TestInactivityBodySkipsAndNames`.)
5. **A `postfix check` that already fails, or a vsftpd restart that fails.** The first refuses with no `rollback failed` line; the second's rollback restarts the unit. (Tasks 7, 8: `TestPostfixRefusesABrokenConfig`, `TestVsftpdRollbackRestartsAFailedUnit`.)

---

### Task 1: The probe (controller, lab; no commit)

**Files:** `.superpowers/sdd/2026-10-19-stage3d2d-content-scripts/probe.md`, `probe.sh` (both ignored).

The design's §5 probe list is a hypothesis. This task measures what the lab can; the runner VM and the fix-roundtrip docker (IPv6, the runner's accounts, `auditctl -s` keys on the azure kernel) are measured by the branch's first CI run and recorded in the Execution notes.

- [ ] **Step 1: Write `probe.sh`**, a container half per image (`rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, the built `muster-ci/debian12-init`, `ubuntu:24.04` with systemd as a stand-in for the runner where a unit file is read). Per image, print:
  - audit: `rpm -ql audit` / `dpkg -L auditd` paths of `augenrules` and the unit file; the unit's `RefuseManualStop` and `ExecStartPost` lines; the stock `/etc/audit/auditd.conf` five action keys; `/etc/audit/rules.d/*.rules`; a run of `augenrules` (no args) over a scratch copy of rules.d containing `50-muster.rules` and the stock file, then the generated file's first and last lines (the `-D` and `-e` hoisting) and its exit code with nothing changed; whether `audit.rules.prev` appears; `auditctl --help 2>&1 | grep -c signal`.
  - postfix: install it (`dnf install -y postfix`; Debian `debconf-set-selections` with `postfix postfix/main_mailer_type select Local only` and `postfix postfix/mailname string ci.example`, then `apt-get install -y postfix`); `postconf -h disable_vrfy_command`; `stat -c '%a %i' /etc/postfix/main.cf` before and after `postconf -e 'disable_vrfy_command = yes'` under `umask 077`; whether `postfix check` creates a directory (`find /var/spool/postfix -newer` a stamp); `systemctl start postfix` (Debian `postfix@-`) and `postfix status`; `dpkg -S /etc/postfix/main.cf` / `rpm -qf`.
  - vsftpd: stock `ftpd_banner`, `banner_file`, `anonymous_enable`, `listen`, `listen_ipv6`; `systemctl start vsftpd`; when it runs, the 220 line from `printf 'QUIT\r\n' | timeout 5 nc 127.0.0.1 21` with (a) both keys set (`ftpd_banner=clean`, `banner_file` naming a file that says `vsFTPd`), (b) the reverse, (c) an empty banner file beside a disclosing `ftpd_banner`.
  - NFS (init images): write `/srv 192.0.2.0/24(rw,no_root_squash)` and run `exportfs -ra; echo $?; exportfs -s`; then `/srv2 -no_root_squash 192.0.2.7`, `/srv3 -rw`, and `/srv4 192.0.2.8(rw) -no_root_squash 192.0.2.9` each alone, `exportfs -ra` and `exportfs -v` (the `-opts` reading, O-20).
  - accounts: `/etc/default/useradd`'s `INACTIVE` line; `useradd -D` output.
- [ ] **Step 2: Run it** over `lab-run`'s stdin as 3D-2c did (`lab-sync` excludes `.superpowers/`), building the Debian image from `ci/roundtrip/debian12-init.Dockerfile`, one container at a time (NFS init containers conflict on one host). Record the output verbatim in `probe.md`.
- [ ] **Step 3: Decide**, in `probe.md`: the augenrules facts (whether `50-muster` survives the stock `-D`); the reload command per family (`auditctl --signal reload` or `kill -HUP`); whether vsftpd and postfix start in each container and the seed workaround that makes them; the vsftpd precedence on the wire (confirms O-14 or stops Task 2); the `-opts` reading (O-20, or drop Task 4); the postfix debconf answers; which edited files are package conffiles. Each decision becomes a ruling (O-25 …) in this plan's Execution notes.
- [ ] **Step 4: Report** the table and every surprise to the user before Task 2 is dispatched.

---

### Task 2: O-14 — vsftpd's greeting precedence (collector fix, its own commit)

**Files:**
- Modify: `internal/collect/collectors/ftp.go:1563-1626` (`publishVsftpdBanner` and its comment)
- Modify: `internal/facts/registry.yaml:2320-2332` (`ftp.banner_source`, `ftp.banner_text` descriptions), `internal/facts/testdata/facts-schema.golden.json` (regenerated)
- Create: `internal/collect/collectors/testdata/vsftpd.conf.banner-both`, `vsftpd.conf.banner-both-version`
- Create: `controls/testdata/muster.service.ftp_banner/fail-vsftpd-banner-file-over-clean-ftpd-banner.json`, `pass-vsftpd-clean-banner-file-over-ftpd-banner.json`, `fail-vsftpd-empty-banner-file.json`
- Test: `internal/collect/collectors/ftp_test.go:1216-1299` (`TestFtpBannerDisclosure`)
- Modify: `CHANGELOG.md` (`### Fixed`, top)

**Interfaces:** Produces the corrected `ftp.banner_source` / `ftp.banner_text` / `ftp.banner_discloses_version` reading that Tasks 7's parity rows compare against.

- [ ] **Step 1: Write the failing cases** in `TestFtpBannerDisclosure` (reverse its doc comment's first sentence): both keys, clean `ftpd_banner` + `banner_file=/etc/issue.net` holding `vsftpd.banner.version` → `banner_source` `banner_file`, discloses `true`; disclosing `ftpd_banner` + clean file (`issue_net`) → `banner_file`, `false`; empty file (`a.contents["/etc/issue.net"] = []byte{}`) + disclosing `ftpd_banner` → `ftpd_banner`, `true`; empty file, no `ftpd_banner` → `default`, `true`; a file holding only `"\n"` → `banner_file`; an undeclared `banner_file` + `ftpd_banner` → absent naming the path, never read.
- [ ] **Step 2: Run on the lab** `go test ./internal/collect/collectors/ -run TestFtpBannerDisclosure`. Expected: FAIL on the both-keys and empty-file rows.
- [ ] **Step 3: Reorder `publishVsftpdBanner`**: `banner_file` first when set (its declared / non-regular / read-error / truncated / oversized branches keep their envelopes whether or not `ftpd_banner` is set); a successful read with `len(data) == 0` falls through; then `ftpd_banner`; then the compiled greeting. Rewrite the comment to cite vsftpd.conf(5) ("overrides the banner string provided by the ftpd_banner option") and the empty-file fall-through.
- [ ] **Step 4: Fixtures.** The two `vsftpd.conf.banner-both*` collector fixtures (a `# synthetic` header, `anonymous_enable=NO`, `local_enable=YES`, `pam_service_name=vsftpd`, the two keys); the three control fixtures in the `pass-vsftpd-custom.json` shape with `banner_source` `banner_file` (source `{"kind":"file","path":"/etc/issue.net"}`) or `ftpd_banner`.
- [ ] **Step 5: Descriptions.** `ftp.banner_source`: "banner_file when it is set and the file is not empty, else ftpd_banner, else default"; `ftp.banner_text`: an empty banner_file falls through. `go test ./internal/facts -run TestFactsSchemaGolden -update`; review the diff (descriptions only).
- [ ] **Step 6: CHANGELOG** `### Fixed` top line: "vsftpd's greeting is read in vsftpd's own order: a non-empty `banner_file` wins over `ftpd_banner` (a clean `ftpd_banner` beside a disclosing banner file read PASS), and an empty banner file falls through (stage 3D-2d, O-14)."
- [ ] **Step 7: Run** on the lab `go test ./internal/collect/collectors/ -run 'TestFtp|FuzzParseVsftpdInto'`, then on Windows `go test ./internal/controls/ ./internal/facts/` (fixtures, mutation test, golden). Expected: PASS, mutation test zero survivors.
- [ ] **Step 8: Commit** `collect: read vsftpd's greeting in vsftpd's order (banner_file over ftpd_banner)` — the message says the facts golden change is description-only.

---

### Task 3: O-17 — the auditd action is its first word (collector fix, its own commit)

**Files:**
- Modify: `internal/collect/collectors/audit_parse.go:235-263` (`parseAuditdConf` and its doc comment)
- Modify: `internal/facts/registry.yaml:3084-3113` (the five `audit.conf.*_action` descriptions), the facts golden
- Modify: `internal/collect/collectors/fuzz_test.go:1495-1500` (`FuzzParseAuditdConf` glob → `testdata/auditd.conf.*`)
- Create: `internal/collect/collectors/testdata/auditd.conf.exec`
- Create: `controls/testdata/muster.beyond.audit_disk_actions/pass-exec-actions.json`
- Test: `internal/collect/collectors/audit_test.go` (new `TestAuditdConfActionIsItsFirstWord` beside `:477`)
- Modify: `CHANGELOG.md` (`### Fixed`)

**Interfaces:** Produces the O-19 reading Task 9's reader matches.

- [ ] **Step 1: Write `TestAuditdConfActionIsItsFirstWord`** (pattern `TestAuditdConfAbsentKeysAndDefaultLogFile`: `a.contents[auditdConfPath]`, `delete(a.files, auditdConfPath)`) with rows: `space_left_action = exec /usr/local/sbin/x` → `"exec"`; `disk_error_action = EXEC /x` → `"exec"`; `admin_space_left_action =\texec\t/y` → `"exec"`; `disk_full_action =` → `""` (no panic); `log_file = /Var/Log/A.log` → `"/Var/Log/A.log"`; `max_log_file_action = ROTATE` → `"rotate"`.
- [ ] **Step 2: Run on the lab.** Expected: FAIL on the three `exec` rows.
- [ ] **Step 3: Implement O-19** in `parseAuditdConf`: for keys other than `log_file`/`log_group`, `if f := strings.Fields(v); len(f) > 0 { v = strings.ToLower(f[0]) } else { v = "" }`. Update the doc comment.
- [ ] **Step 4: Seeds and fixtures.** `testdata/auditd.conf.exec` (the stock sample with `space_left_action = exec /usr/local/sbin/notify` and `disk_error_action = EXEC /usr/local/sbin/x`); widen the fuzz glob; the control fixture `pass-exec-actions.json` in `pass-values-1.json`'s shape with `space_left_action`, `disk_full_action`, `disk_error_action` = `"exec"`.
- [ ] **Step 5: Descriptions** of the five keys: "the value's first word, lower-cased (an exec action's path is not part of the value); absent when no line sets it, never the daemon's compiled default." Golden `-update`, description-only.
- [ ] **Step 6: CHANGELOG** Fixed: "An auditd `exec <path>` disk action is judged by its first word: it read FAIL because the whole value, path included, was compared (stage 3D-2d, O-17)."
- [ ] **Step 7: Run** lab `go test ./internal/collect/collectors/ -run 'TestAudit|FuzzParseAuditdConf'`, Windows `go test ./internal/controls/ ./internal/facts/`. Expected: PASS.
- [ ] **Step 8: Commit** `collect: judge an auditd action by its first word (an exec action keeps its path out of the verdict)`.

---

### Task 4: O-18 — the exports default option list (collector fix, its own commit; dropped if the probe says nfs-utils rejects it)

**Files:**
- Modify: `internal/collect/collectors/nfs.go:155-213` (`parseExportsContent`), `:236-244` only if O-20's `options` joining needs a helper
- Modify: `internal/facts/registry.yaml:1869-1875` (`nfs.exports`), the facts golden
- Create: `internal/collect/collectors/testdata/exports.default_options`
- Create: `controls/testdata/muster.service.nfs_export_access/fail-default-list-no-root-squash.json`
- Test: `internal/collect/collectors/nfs_test.go` (new `TestNfsDefaultOptionListAppliesToItsClients`; `TestNfsTrailingCommentIsNotAClient` `:186` re-scoped)
- Modify: `CHANGELOG.md` (`### Fixed`)

- [ ] **Step 1: Write `TestNfsDefaultOptionListAppliesToItsClients`** over `exports.default_options` (RFC 5737): `/srv -no_root_squash 198.51.100.7` → one record, options `no_root_squash`, `root_squash` false; `/srv2 -no_root_squash 198.51.100.8(rw)` → options `no_root_squash,rw`, false; `/srv3 -rw 198.51.100.9(no_root_squash) 198.51.100.10` → the first `rw,no_root_squash` false, the second `rw` true; `/srv4 -rw` → client `*`, wildcard true, options `rw`; `/srv5 198.51.100.11 -no_root_squash 198.51.100.12` → the first carries no defaults (true), the second false. Adjust the rows to Task 1's probe before writing them.
- [ ] **Step 2: Re-scope `TestNfsTrailingCommentIsNotAClient`**: move its `/srv6 -rw` line into the new fixture (the `/srv4` row) and keep the trailing-comment assertion on its own line.
- [ ] **Step 3: Run on the lab.** Expected: FAIL.
- [ ] **Step 4: Implement O-20** in `parseExportsContent`: walk the client tokens with a `defaults string`; a `-` token sets `defaults = ct[1:]` and continues; a client token's options are `join(defaults, own)`; when the line had no client token but a default list, emit `exportRecord(path, "*", defaults)`. Replace the BSD comment with the exports(5) reading.
- [ ] **Step 5: Fixture, description, CHANGELOG.** The control fixture (the `fail-no-root-squash.json` shape, record `{"path":"/srv","client":"198.51.100.7","options":"no_root_squash","wildcard":false,"root_squash":false}`); `nfs.exports` description gains the default-list sentence; golden `-update`; Fixed: "An exports line's `-options` default list is applied to the clients after it: `/srv -no_root_squash host` read root_squash true (stage 3D-2d, O-18)."
- [ ] **Step 6: Run** lab `go test ./internal/collect/collectors/ -run 'TestNfs|FuzzParseExportsContent'`, Windows `go test ./internal/controls/ ./internal/facts/`. Expected: PASS.
- [ ] **Step 7: Commit** `collect: apply an exports default option list to the clients after it`.

---

### Task 5: O-11 — symlink guards in `lockout_threshold` and `root_remote_login`

**Files:**
- Modify: `controls/account/lockout_threshold.yaml` (script), `controls/account/root_remote_login.yaml` (script, rollback)
- Test: `internal/remedy/shipped_bodies_test.go` (`rebaseAccounts` `:755`, `accountTree` `:735`, `TestAccountBodiesLeaveASymlinkedDropIn` `:1068-1125`)
- Modify: `internal/remedy/testdata/all-scripted.sh` (regenerated)

- [ ] **Step 1: Extend the test.** `rebaseAccounts` gains `/etc/securetty`. `accountTree`'s `systemctl` stub `reload*)` arm also appends `(00-muster.conf is a link)` when `[ -L "$ROOT/etc/ssh/sshd_config.d/00-muster.conf" ]`. Add the rows `{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "is a symlink, left as is"}`, `{"muster.account.root_remote_login", "/etc/securetty", "is a symlink, left as is"}`, `{"muster.account.root_remote_login", "/etc/ssh/sshd_config.d/00-muster.conf", "is a symlink (a mask), left as is"}`. Add `TestRootLoginRollbackSkipsASymlinkedDropIn`: the body's new guard keeps a whole block from ever reaching the rollback with the link in place, so the test runs the rollback alone (`runBody` with a `log()` prefix and `rebaseAccounts`) with the link present and `$STUB/ssh_active`: the link survives and the stub's reload line carries `(00-muster.conf is a link)`.
- [ ] **Step 2: Run on the lab** `go test ./internal/remedy/ -run 'TestAccountBodiesLeaveASymlinkedDropIn|TestRootLoginRollbackSkipsASymlinkedDropIn'`. Expected: FAIL on the three new rows.
- [ ] **Step 3: Guards.** `lockout_threshold`, first lines: `if [ -L "$fc" ]; then log "muster.account.lockout_threshold: $fc is a symlink, left as is"; exit 1; fi` after `fc=`. `root_remote_login`, at the top before the `printf`: the S-27 drop-in guard (`is a symlink (a mask), left as is`) and the K2 securetty guard (`if [ -L /etc/securetty ]; then log "…: /etc/securetty is a symlink, left as is"; exit 1; fi`); its rollback's `rm -f` becomes `[ -L /etc/ssh/sshd_config.d/00-muster.conf ] || rm -f /etc/ssh/sshd_config.d/00-muster.conf`. Keep exactly one `sed -i … /etc/securetty` line (`TestShippedSecurettySedRemovesIndentedPts`) and a missing path must not refuse (`TestShippedRootLoginReloadsTheRunningSshd`).
- [ ] **Step 4: Run** lab `go test ./internal/remedy/ -run 'TestAccount|TestShippedRootLogin|TestShippedSecuretty|TestLineBodiesTightenOnly'`, then Windows `go test ./internal/remedy/ -run TestScriptGolden -update`, review the `all-scripted.sh` diff (two blocks), `go test ./...`, lab shellcheck over `all-scripted.sh`. Expected: PASS.
- [ ] **Step 5: Commit** `remedy: refuse a symlinked faillock.conf, securetty or 00-muster.conf (O-11)`.

---

### Task 6: The version, the two text-only changes, the reader-parity harness, and `rhosts_forbidden`

**Files:**
- Modify: `controls/VERSION` (O-24)
- Modify: `controls/beyond/audit_immutable.yaml` (risk `reboot_required`), `controls/account/password_hash_algorithm.yaml` (text EN/KO)
- Modify: `internal/collect/collectors/files.go:286-314` (factor `hostsEquivLines`), `fuzz_test.go` (`FuzzHostsEquivLines`), `fuzz_inventory_test.go` (`fuzzTargets`, sorted between `FuzzGrubPasswordSet` and `FuzzListsRoot`)
- Create: `internal/collect/collectors/remediation_parity_test.go` (Linux)
- Modify: `controls/file/rhosts_forbidden.yaml` (risk, text EN/KO, `backup`, `script`, `validate`)
- Modify: `controls/testdata/_roundtrip.yaml`, `.github/workflows/ci.yml` (`seeded` of the four container rows)
- Create: `internal/remedy/shipped_content_test.go` (Linux)
- Modify: `internal/remedy/testdata/all-scripted.sh`

**Interfaces:**
- Produces: `func hostsEquivLines(data []byte) []any` (never nil); in `remediation_parity_test.go`: `func shippedBody(t *testing.T, id string) *controls.Remediation`, `func readerLine(t *testing.T, r *controls.Remediation, name string) string` (O-21 extraction; Fatal when absent or when its program is not in `r.Validate`), `func runReader(t *testing.T, fn, name string, file []byte, args ...string) string` (writes `file` to a temp path, runs `sh -ec "<fn>\n<name> <path> <args>"` under `LC_ALL=C`, returns trimmed stdout). In `shipped_content_test.go`: `func contentTree(t *testing.T) (root, bin, stub string)` with `systemctl`, `postconf`, `postfix`, `exportfs` stubs logging to `$STUB/<tool>`, `func rebaseContent(s, root string) string` (`/etc/hosts.equiv`, `/etc/vsftpd`, `/etc/vsftpd.conf`, `/etc/postfix/`, `/etc/exports`), `func contentBlock(t *testing.T, id, root string, failValidate bool) *Plan` (the `accountBlock` shape).

- [ ] **Step 1: Version and text-only changes.** `controls/VERSION` → `kisa-unix-2026+2026.10.19`. `audit_immutable` risk → `reboot_required`. `password_hash_algorithm` text EN and KO gain "Locking the account does not clear the finding, and never blank the password field." (≤ 1000 runes).
- [ ] **Step 2: Factor `hostsEquivLines`** (TrimSpace each `splitLines` line; drop blank and `#`-prefixed; `[]any{}` when none) and call it from `writeHostsEquiv`; add `FuzzHostsEquivLines` (`seeds(f, "testdata/hosts_equiv", "testdata/home_alice_rhosts")`) and its `fuzzTargets` row. Lab: `go test ./internal/collect/collectors/ -run 'TestFilesHostsEquiv|TestEveryParserHasAFuzzTarget|FuzzHostsEquivLines'` → PASS (a refactor: `TestFilesHostsEquiv` unchanged).
- [ ] **Step 3: Write the failing body tests** in `shipped_content_test.go`:
  - `TestRhostsBodyCommentsOutPlusLines`: hosts.equiv `+\n  +@ops\nhost-a\n# c\n+host-b\n` → after the body, `# muster: +\n# muster:   +@ops\nhost-a\n# c\n# muster: +host-b\n`; validate exit 0; a second run changes nothing (byte-identical).
  - a symlinked `/etc/hosts.equiv` → the body exits 0 and the link's target is untouched (C4 skip, §4 intro); a missing file → exit 0, validate exit 0.
  - `TestRhostsBlockRollsBack`: `contentBlock(…, true)` → exit 1, `validate failed`, the file restored byte for byte, no `ROLLBACK INCOMPLETE`.
- [ ] **Step 4: Write the failing parity row** `TestRhostsReaderMatchesTheCollector` in `remediation_parity_test.go`: `readerLine(t, r, "rd_plus")`; for rows `+`, `  +@ops`, `#+x`, `host`, `\t+h`, and the post-body text, `runReader(… "rd_plus" …)` prints the count of matching lines and equals the count of `hostsEquivLines` entries matching `^\+` (the clause's regexp, `regexp.MustCompile("^\\+")`).
- [ ] **Step 5: Run on the lab.** Expected: FAIL (no body).
- [ ] **Step 6: The body** (`backup: [/etc/hosts.equiv]`, risk `restart_service`, no rollback):
  ```sh
  rd_plus() { grep -Ec '^[[:space:]]*\+' "$1" || :; }
  if [ -f /etc/hosts.equiv ] && [ ! -L /etc/hosts.equiv ]; then
    if [ "$(rd_plus /etc/hosts.equiv)" != 0 ]; then sed -i 's/^\([[:space:]]*+\)/# muster: \1/' /etc/hosts.equiv; fi
  fi
  ```
  validate: `[ ! -f /etc/hosts.equiv ] || [ -L /etc/hosts.equiv ] || [ "$(grep -Ec '^[[:space:]]*\+' /etc/hosts.equiv || :)" = 0 ]`. Text EN/KO: the body comments out every `+` line of `/etc/hosts.equiv` (a bare `+`, `+host`, `+@netgroup`) with a `# muster:` prefix; `~/.rhosts` and `~/.shosts` stay the operator's.
- [ ] **Step 7: Table and matrix.** `_roundtrip.yaml` entry `muster.file.rhosts_forbidden` `images: [almalinux9-init, debian12-init, rocky9-init, ubuntu2204]` (sorted after `passwd_permissions`); add the id to the four container rows' `seeded` in byte order (plan-map-ci §2.1).
- [ ] **Step 8: Run** lab `go test ./internal/remedy/ -run 'TestRhosts' ./internal/collect/collectors/ -run 'TestRhostsReader'`; Windows `go test ./internal/remedy -run TestScriptGolden -update` (review: one new block), `go test ./...`, `go run ./cmd/muster controls lint --references docs/reference` and `--profile default`; lab shellcheck. Expected: PASS; `TestExamplesLoadAndCheck` skips its byte comparison with the digest note.
- [ ] **Step 9: Commit** `controls: comment out hosts.equiv's + lines; audit_immutable is reboot_required; version 2026.10.19`.

---

### Task 7: The vsftpd half — `ftp_banner` and `ftp_anonymous`

**Files:**
- Modify: `controls/service/ftp_banner.yaml`, `controls/service/ftp_anonymous.yaml` (text EN/KO, `backup`, `script`, `validate`, `rollback`)
- Test: `internal/remedy/shipped_content_test.go`, `internal/collect/collectors/remediation_parity_test.go`
- Modify: `_roundtrip.yaml`, ci.yml `seeded` (three init rows), `all-scripted.sh`

**Interfaces:** Consumes Task 6's `contentTree`, `contentBlock`, `readerLine`, `runReader`; Task 2's reading.

- [ ] **Step 1: Write the failing tests.**
  - `TestVsftpdBannerWritesOnlyADisclosure`: per conf (`/etc/vsftpd.conf` and `/etc/vsftpd/vsftpd.conf` each alone and both): no `ftpd_banner` → `ftpd_banner=FTP server ready.` appended (a conf without a final newline gets a newline first); `ftpd_banner=vsFTPd 3.0.5 ready` → rewritten; `ftpd_banner=Welcome` → byte-identical; `banner_file=/etc/issue.net` with a non-empty file → byte-identical and the O-23 log line; an empty banner file → falls through and rewrites.
  - `TestVsftpdAnonymousWritesNo`: missing key → `anonymous_enable=NO` appended; `YES`/`yes`/`1` → rewritten; `NO`, `false`, `0` → byte-identical.
  - `TestVsftpdRestartsOnlyAWasRunningUnit`: with `$STUB/vsftpd_active` → one `systemctl restart vsftpd.service`; without → none; a rerun whose `$MB/vsftpd.was-running` is left from an earlier run and vsftpd now stopped → none (O-16).
  - `TestVsftpdRollbackRestartsAFailedUnit`: active at the start, the stub's restart fails and leaves the unit failed, `contentBlock(…, false)` → the body fails, the rollback restores the conf and calls `restart` again; no `rollback failed`.
  - parity `TestVsftpdReadersMatchTheCollector`: `rd_greeting` and `rd_anon` over rows `PureFTPd ready`, `myvsftpd`, clean `ftpd_banner` + disclosing `banner_file` and the reverse, an empty `banner_file`, a `"\n"`-only file, `anonymous_enable=FALSE`, `=0`, a missing key; compared with `buildBegun(t, "ftp", ftpAccess(…))`'s `ftp.banner_discloses_version` and `ftp.anonymous_enabled`.
- [ ] **Step 2: Run on the lab.** Expected: FAIL.
- [ ] **Step 3: The bodies** (`backup: [/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf]`, risk `restart_service`), sharing one shape:
  - first lines: `rm -f "$MB/vsftpd.was-running" "$MB/vsftpd.edited"`; `if LC_ALL=C systemctl is-active --quiet vsftpd.service; then : > "$MB/vsftpd.was-running"; fi`;
  - readers (O-21): `rd_greeting() { … }` prints `disclose` or `clean` or `file` (a non-empty `banner_file` that the body leaves) following O-14 with the product pattern `(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)` case-blind, keys lower-cased, last line wins; `rd_anon() { … }` prints `no` when the last `anonymous_enable` is `no`/`false`/`0` case-blind, else `yes`;
  - per conf that is a regular file and not a symlink: the O-23 leave for `file`; else when the reader says `disclose`/`yes`: `: > "$MB/vsftpd.edited"`, the §3.7 newline guard, rewrite every `ftpd_banner=` (or `anonymous_enable=`) line case-blind with `sed -i`, or append; `restorecon` on the conf when `selinuxenabled` succeeds;
  - then `if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then systemctl restart vsftpd.service; fi`.
  - validate (one line): per conf, the reader's program inline says `clean`/`file` (or `no`) `&&` `{ [ ! -f "$MB/vsftpd.was-running" ] || systemctl is-active --quiet vsftpd.service; }`.
  - rollback: `restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf`; `if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then systemctl restart vsftpd.service; fi`.
  - texts EN/KO: what is written, the proftpd/pure-ftpd halves left, the restart; `ftp_anonymous` says it closes an anonymous service someone may have meant to run; the §3.12 upgrade sentence for the files the probe confirmed.
- [ ] **Step 4: Table and matrix:** entries for both ids `images: [almalinux9-init, debian12-init, rocky9-init]`; `seeded` of the three init rows.
- [ ] **Step 5: Run** lab tests, golden `-update` (two new blocks), `go test ./...`, both lint runs, lab shellcheck. Expected: PASS.
- [ ] **Step 6: Commit** `controls: write vsftpd's ftpd_banner and anonymous_enable when they disclose or allow`.

---

### Task 8: The postfix half (`mail_expn_vrfy`) and the `no_root_squash` half (`nfs_export_access`)

**Files:**
- Modify: `controls/service/mail_expn_vrfy.yaml`, `controls/service/nfs_export_access.yaml`
- Test: `shipped_content_test.go`, `remediation_parity_test.go`; `internal/remedy/shipped_test.go:177` and `shipped_bodies_test.go:592-593` (the nfs rows gain `MB` and stubs)
- Modify: `_roundtrip.yaml`, ci.yml `seeded`, `all-scripted.sh`

- [ ] **Step 1: Write the failing tests.**
  - `TestPostfixSetsVrfyOnce`: stub `postconf -h disable_vrfy_command` prints `$STUB/vrfy` (`no` → one `postconf -e disable_vrfy_command = yes` call; `YES` → none); `postfix check` logged before and after the edit; `postfix reload` only with `$MB/postfix.was-running` (stub `postfix status` exits 0 iff `$STUB/postfix_running`).
  - `TestPostfixRefusesABrokenConfig`: `postfix check` fails from the start → exit 1, the O-23 log line, `postconf -e` never called; the whole block exits 1 with no `rollback failed` (the `edited` marker is absent).
  - `TestPostfixAbsentLeavesTheSendmailHalf`: no `postconf` on `PATH` → exit 0, the O-23 line, validate exit 0.
  - `TestNfsSwapsOnlyOptionTokens`: `/srv/no_root_squash_area 192.0.2.1(rw,no_root_squash,sync)\n/b 192.0.2.2(no_root_squash)\n/c 192.0.2.3(rw,no_root_squash,no_root_squash)\n/d -no_root_squash 192.0.2.4\n/e 192.0.2.5(rw) # no_root_squash\n` → only the option tokens change (path, comment untouched); `exportfs -ra` only with both markers (stub `systemctl is-active --quiet nfs-server.service` true iff `$STUB/nfs_active`).
  - `TestNfsRollbackReexports`: active server, `contentBlock(…, true)` → `restore` then `exportfs -ra` logged after the file is back.
  - the root-only `TestFileScriptsRepairOnARealFile` row and `TestFileBodiesRepairATempTree` rows run with `MB=<tempdir>` and a `bin` holding inactive `systemctl` and logging `exportfs` stubs.
  - parity `TestPostfixAndExportsReadersMatchTheCollector`: `rd_vrfy` over `main.cf` rows (`disable_vrfy_command = yes`, `= YES`, a continuation line, a later override, absent) against `parsePostfixInto` + `postfixYes` (the case-folded key is the recorded divergence: one row asserts the body reads `Disable_Vrfy_Command` the way `postconf` does); `rd_nrs` over the exports rows above against `parseExportsContent`'s `root_squash` (one-sided: wherever the collector reads `false` on a line whose `no_root_squash` is an option token, the body must count it).
- [ ] **Step 2: Run on the lab.** Expected: FAIL.
- [ ] **Step 3: `mail_expn_vrfy` body** (`backup: [/etc/postfix/main.cf]`, risk `restart_service`): markers removed; `command -v postconf` missing → log, `exit 0`; K2 guard on `main.cf`; `postfix check` fails → log, `exit 1`; `postfix status` → `was-running`; `rd_vrfy() { LC_ALL=C postconf -h disable_vrfy_command; }`; not `yes` case-blind → `: > "$MB/postfix.edited"`, `postconf -e 'disable_vrfy_command = yes'`, `restorecon` when `selinuxenabled`, `postfix check`, reload with the marker. Validate: `if command -v postconf >/dev/null 2>&1; then case "$(LC_ALL=C postconf -h disable_vrfy_command)" in [Yy][Ee][Ss]) postfix check ;; *) false ;; esac; fi`. Rollback: `restore /etc/postfix/main.cf`; with `edited`: `postfix check`, then `postfix reload` with `was-running`. Text EN/KO: the reload applies pending `master.cf` edits; sendmail stays the operator's.
- [ ] **Step 4: `nfs_export_access` body** gains, inside its guard: markers removed at the top; `nfs.was-running` when `systemctl is-active --quiet nfs-server.service`; `rd_nrs() { … }` counts option-scoped `no_root_squash` in the text before each line's first `#`; non-zero → `: > "$MB/nfs.edited"` and a `sed -i` loop (`s/\([(,-]\)no_root_squash\([,) ]\)/\1root_squash\2/g` and the end-of-line `-no_root_squash` form, repeated until `rd_nrs` reads 0 or ten passes), `restorecon` when enabled, `exportfs -ra` with both markers. Validate gains `&& [ "$(<rd_nrs program> /etc/exports)" = 0 ]` under the same guard. A declared rollback: `restore /etc/exports`; with both markers `exportfs -ra`. Text EN/KO per §4.9.
- [ ] **Step 5: Table and matrix:** `mail_expn_vrfy` `images: [almalinux9-init, debian12-init, rocky9-init]`, seeded on the three init rows (`nfs_export_access` keeps its rows).
- [ ] **Step 6: Run** lab tests (as root for the real-file tests: `lab-run.sh 'go test ./internal/remedy/ -run "TestFileScriptsRepairOnARealFile|TestFileBodiesRepairATempTree|TestNfs|TestPostfix"'`), golden `-update`, `go test ./...`, lint, shellcheck. Expected: PASS.
- [ ] **Step 7: Commit** `controls: set postfix's disable_vrfy_command; swap no_root_squash in exports options`.

---

### Task 9: `audit_disk_actions`

**Files:**
- Modify: `controls/beyond/audit_disk_actions.yaml` (text EN/KO — move sentences into the description if the 1000-rune cap needs it — `script_params`, `backup`, `script`, `validate`, `rollback`)
- Create: `internal/remedy/shipped_audit_test.go` (Linux)
- Test: `remediation_parity_test.go`
- Modify: `_roundtrip.yaml` (`images: [runner]`), ci.yml runner `seeded`, `all-scripted.sh`

**Interfaces:** Produces in `shipped_audit_test.go`: `func auditTree(t *testing.T) (root, bin, stub string)` with an `auditctl` stub (`-l` prints `$STUB/rules` or `No rules`; `-s` prints `$STUB/status` lines or exits `$STUB/status_rc`; `-D` empties rules; `-f`/`-b`/`-r`/`-e`/`--backlog_wait_time` rewrite the status key; `--signal reload` logs; every call logged to `$STUB/auditctl`), an `augenrules` stub (no args: concatenates `$ROOT/etc/audit/rules.d/*.rules` into `$ROOT/etc/audit/audit.rules`; `--load`: the same, then copies its `-w`/`-a`/`-A` lines into `$STUB/rules`; logged), `kill` (logged), and Task 6's `systemctl` stub semantics via `units_test.go`'s `systemctlStub`; `func rebaseAudit(s, root string) string` (`/etc/audit/`, `/run/auditd.pid`); `func auditBlock(t, id, root string, failValidate bool) *Plan`.

- [ ] **Step 1: Write the failing tests.**
  - `TestDiskActionsWriteOnlyAcceptedValues`: stock EL9 (`SUSPEND` on three keys) at the defaults → `syslog` written to those three, `rotate`/`syslog` lines byte-identical; `allowed_disk_error_actions=rotate syslog` → `syslog`; `allowed_space_actions=keep_logs` → `space_left_action` left, the O-23 line, block `done`; `halt single` only → that key byte-identical, the others written, exit 0; `space_left_action = exec /usr/local/sbin/x` → left (first word `exec` is in the list); `admin_space_left_action` never touched by the `space_left_action` rewrite.
  - `TestDiskActionsReloadOnlyARunningDaemon`: `was-running` (stub `auditd.service` active) → one `auditctl --signal reload` (or `kill -HUP` per Task 1); inactive → none; a rerun's stale `disk.keys` naming a key this run leaves is not validated.
  - `TestDiskActionsRollbackRestoresThenReloads`: `auditBlock(…, true)` → conf byte-identical to before, a reload after the restore.
  - parity `TestAuditdConfReaderMatchesTheCollector`: `rd_action` (`awk -v k=<key>`, `#` lines skipped, key case-blind, last line, first word lower-cased) over `auditd.conf.sample`, `auditd.conf.exec` and rows `Space_Left_Action = SYSLOG`, a later override, a tab separator, against `parseAuditdConf`.
- [ ] **Step 2: Run on the lab.** Expected: FAIL.
- [ ] **Step 3: The body** (`script_params: [allowed_space_actions, allowed_disk_full_actions, allowed_disk_error_actions, allowed_rotate_actions]`, `backup: [/etc/audit/auditd.conf]`, risk `restart_service`): `rm -f "$MB/disk.keys" "$MB/auditd.edited" "$MB/auditd.was-running"`; K2 guard; `was-running`; `rd_action() { awk -v k="$2" '…' "$1"; }`; for each `key:list:writable` of the five (`space_left_action:$P_allowed_space_actions:syslog rotate`, `admin_space_left_action:…`, `disk_full_action:$P_allowed_disk_full_actions:syslog rotate`, `disk_error_action:$P_allowed_disk_error_actions:syslog`, `max_log_file_action:$P_allowed_rotate_actions:rotate keep_logs syslog`) — copy the list to a plain variable first; when the read value is not in the list, pick the first list member in the writable set (O-6), else log the O-23 leave; record the key in `disk.keys`, touch `edited`, `sed -i` every line of that key (anchored `^[[:space:]]*<key>[[:space:]]*=`, case-blind `I`); `restorecon` when enabled; reload with both markers (Task 1's command). Validate: one `awk` over the file with `-v` lists and `-v keys="$(cat "$MB/disk.keys" 2>/dev/null)"` checking only those keys, `&& { [ ! -f "$MB/auditd.was-running" ] || systemctl is-active --quiet auditd.service; }`. Rollback: `restore /etc/audit/auditd.conf`; reload with both markers. Text adds what is written, the never-written values, the `rotate`/`num_logs` sentence, the reload.
- [ ] **Step 4: Table and matrix:** runner row.
- [ ] **Step 5: Run** lab tests, golden, `go test ./...`, lint, `TestShippedBodiesPlaceParametersSafely` (no `P_` on a `sed` line), shellcheck. Expected: PASS.
- [ ] **Step 6: Commit** `controls: write auditd's disk actions with values that keep the host up`.

---

### Task 10: `audit_rules_loaded` and `auditd_active`

**Files:**
- Modify: `controls/beyond/audit_rules_loaded.yaml`, `controls/beyond/auditd_active.yaml` (risk `restart_service`; texts; `backup`/`units`; `script`; `validate`; `rollback` for the rules control)
- Modify: `internal/collect/collectors/remediation_units_test.go:17-52` (eleven controls; the `auditd` row; doc comment)
- Test: `shipped_audit_test.go`, `remediation_parity_test.go`
- Modify: `_roundtrip.yaml` (both `images: [runner]`), ci.yml runner `seeded`, `all-scripted.sh`
- Modify: `ATTRIBUTION.md` (`## Checks that are not KISA items`: the floor's rule lines are auditctl(8) syntax with muster's own keys)

**Interfaces:** Consumes Task 9's `auditTree`, `rebaseAudit`, `auditBlock`.

- [ ] **Step 1: Write the failing tests.**
  - `TestAuditRefusesAPendingLock` (rules control): rows `-e 2`, `-e2`, `-e 02`, `-e +2`, `--loginuid-immutable` in `rules.d/x.rules` or `audit.rules`; runtime `enabled 2`; `loginuid_immutable 1`; `auditctl -s` exiting 1 → exit 1, the O-23 line, no file written, no `augenrules` call. `-e 1` → not refused.
  - `TestAuditRulesFloorWrittenOnlyWhenBothEmpty`: case (c) with auditd active → `50-muster.rules` mode 0640 with only the lines whose path exists under the rebased root, `audit.status` written, `audit.loaded` touched, `augenrules --load` called; case (a) (a persisted `-w` rule, kernel empty, active) → no file, `--load`; case (a) inactive → `augenrules` without `--load`, no marker; case (b) (kernel holds rules, none persisted) → exit 0, the O-23 line, nothing written, validate exit 0, block `done`.
  - `TestAuditRulesRollbackDeletesOnlyWhatThisRunLoaded`: case (c) then `auditBlock(…, true)`: `auditctl -D` and the replay of `audit.status` (including `-b 4321` seeded in `$STUB/status` before the run) after `restore`; a rerun whose earlier run loaded and whose kernel list is now non-empty, forced to fail → no `-D`.
  - `TestAuditdActiveStartBranch` (units control, the stub `systemctl` from `units_test.go`): active + pending lock + disabled → enabled, no start, `done`; inactive + runtime locked → started; inactive + unlocked + `-e2` persisted → exit 1; inactive + pending lock + `auditctl -s` fails → exit 1; inactive + non-empty kernel list → enabled, not started, `done`; inactive + `auditctl -l` fails → exit 1; inactive + clean → started; no unit → the install line, `done`.
  - `TestAuditPlanFloorThenStart`: a plan holding both ids over an inactive, disabled unit with nothing persisted (rebased; `mustBuild(scriptReport(row(rules…), row(active…)))`) → the rules block writes the floor and regenerates only, the active block's start (the stub `systemctl start auditd.service` runs the `augenrules --load` stub) loads it; `$STUB/rules` ends with the floor's watches.
  - parity `TestAuditRulesReadersMatchTheCollector`: `rd_present` (`^[[:space:]]*-[waA]`) and `rd_lock` (the O-3 pattern) over `audit.rules.*` fixtures and rows `-w/etc/passwd -p wa`, `-aalways,exit -S all`, `-e2`, `-e  2`, `-e 2 # c`, `-e 02`, `-e +2`, `-b 8192`: presence equals `auditKind`'s watch/syscall count > 0; the lock is one-sided against `lastEnableValue` (`value == 2` ⇒ the body reads a lock).
  - `TestServiceScriptsNameTheCollectorsUnits` with the eleventh row.
- [ ] **Step 2: Run on the lab.** Expected: FAIL.
- [ ] **Step 3: `audit_rules_loaded` body** (`backup: [/etc/audit/rules.d/50-muster.rules, /etc/audit/audit.rules]`) per design §4.2 steps 1–5 with the O-23 lines, `rd_present() { grep -Esq '^[[:space:]]*-[waA]' "$@"; }`, `rd_lock() { grep -Esq '^[[:space:]]*(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable)' "$@"; }`, `auditctl` output read under `LC_ALL=C` with keys matched whole (`awk '$1 == "enabled" …'`); the floor written with `printf` lines (no here-document) for each path that exists; `restorecon` on the two files when enabled. Validate per §4.2. Rollback per §4.2 (the replay reads `audit.status` with `while read -r k v`).
- [ ] **Step 4: `auditd_active` body** (`units: [auditd.service]`; no unit name literal in the script — loop over `$UNITS`; `$UNITS` never in validate) per design §4.1 with the O-23 lines; validate `if systemctl cat auditd.service >/dev/null 2>&1; then systemctl is-enabled --quiet auditd.service && { systemctl is-active --quiet auditd.service || { l=$(LC_ALL=C auditctl -l) && [ "$l" != "No rules" ]; }; }; fi`. Texts EN/KO per §4.1 / §4.2 (the floor, the replace-with-your-own sentence, O-2's named effects).
- [ ] **Step 5: `remediation_units_test.go`:** the `"muster.beyond.auditd_active": {"auditd"}` row, both counts 11, the doc comment ("a units-declaring control; ten disable, one enables").
- [ ] **Step 6: Table, matrix, ATTRIBUTION.**
- [ ] **Step 7: Run** lab tests, golden, `go test ./...`, lint, shellcheck. Expected: PASS.
- [ ] **Step 8: Commit** `controls: load or persist audit rules, start auditd, never over a pending lock`.

---

### Task 11: `account_inactivity_lock`

**Files:**
- Modify: `controls/beyond/account_inactivity_lock.yaml` (risk `lockout_risk`; text EN/KO without the `useradd -D` advice; `script_params`, `backup`, `script`, `validate`, `rollback`)
- Create: `internal/remedy/shipped_inactivity_test.go` (Linux)
- Test: `remediation_parity_test.go` (`TestInactivityReadersMatchTheCollector`)
- Modify: `_roundtrip.yaml` (`images: [runner]`), ci.yml runner `seeded`, `all-scripted.sh`

**Interfaces:** Consumes `accountTree`/`rebaseAccounts` (Task 5 adds `/etc/securetty`; this task adds `/etc/default/useradd`, `/etc/shells`); a `chage` stub that edits field 7 of the rebased shadow for `-I` and logs argv; a `date` stub printing `$STUB/now` for `+%s` so the boundary rows are exact.

- [ ] **Step 1: Write the failing tests** `TestInactivityBodySkipsAndNames` (rows over a rebased passwd/shadow/shells/login.defs with `today` fixed by the `date` stub, `n=35`): root with max 99999 → `-I 35`, no date line; root with max 60, last today−10 → `-I 35` and the `will be disabled on <date>` line with `date` computed in the test; an account expired exactly `max + 35` days ago → skipped, named (`>=`); one day less → changed and dated; `last = 0` → skipped, named; empty `last` → read as -1, changed; empty `max` → changed; field 7 `20` → left; `-5` → left; `abc` → skipped, named; no shadow row → skipped, named; a nologin shell and a uid between 1 and `UID_MIN` → not enumerated; `inactive.list` gets `name:-1` for an empty field and keeps the first record on a rerun; `inactive.run` holds only this run's names; a negative `P_max_inactive_days` → exit 1, the O-23 line. `TestInactivityUseraddLine`: `INACTIVE=-1` → `INACTIVE=35`; `# INACTIVE=-1` → appended; `INACTIVE=030` (24) → left; `INACTIVE=0x30` (48) → rewritten; missing file → created mode 0644; no final newline → a newline first; a symlink → exit 1, `is a symlink, left as is`. `TestInactivityRollbackReplaysTheList`: `accountBlock(…, true)` → `chage -I -1 -- <name>` per recorded name after the body's `-I 35`, a deleted account's replay failure leaves the others restored and the rollback exits 1 with `rollback failed` (this row asserts it on purpose). Parity: the useradd reader over `useradd.default.*` fixtures and rows (`INACTIVE=030`, `0x1F`, `-2`, a later line) against `parseUseraddDefaults`; the account enumeration over the accounts fixtures against `loginCapable`.
- [ ] **Step 2: Run on the lab.** Expected: FAIL.
- [ ] **Step 3: The body** per design §4.4 with the O-23 lines; `today=$(( $(date +%s) / 86400 ))`; the scan awk builds `name:uid:shell` from `/etc/passwd` and `/etc/shells` exactly as `loginCapable` reads them; the shadow read keeps the last row per name; the date line uses `date -u -d "@$(( (last + max + n) * 86400 ))" +%F`. Validate per §4.4 reading `inactive.run`. Rollback per §4.4.
- [ ] **Step 4: Table and matrix:** runner row.
- [ ] **Step 5: Run** lab tests, golden, `go test ./...`, lint, shellcheck. Expected: PASS.
- [ ] **Step 6: Commit** `controls: bound account inactivity, root included, skipping any account it would disable now`.

---

### Task 12: CI — seeds and `record()`

**Files:**
- Modify: `ci/roundtrip/runner.sh`, `rocky9-init.sh`, `almalinux9-init.sh`, `debian12-init.sh`, `ubuntu2204.sh`
- Modify: `.github/workflows/ci.yml` (`fix-roundtrip` header comment `:506-518`, `record()` `:671-694`)

- [ ] **Step 1: `runner.sh`** (after its `systemctl is-active --quiet auditd || systemctl start auditd` line): add `/etc/audit/rules.d/50-muster.rules` to the `rm -f` list; save pristine copies on first run to `/var/lib/muster-ci/auditd.conf` and `/var/lib/muster-ci/useradd` (`mkdir -p /var/lib/muster-ci; [ -e … ] || cp -p …`), copy them back every run; `augenrules --load`; `auditctl -b 4321`; `sed -i 's/^disk_full_action.*/disk_full_action = suspend/'` on `auditd.conf` and the Task 1 reload; `chage -I -1` over every local login-capable account (the body's enumeration rule); `systemctl disable auditd` (kept running). Never an `-e 2` or `--loginuid-immutable`.
- [ ] **Step 2: Init seeds.** EL: `vsftpd postfix` move into the first `dnf` line; before the start loop, `sed -i 's/^anonymous_enable=.*/anonymous_enable=YES/'` on `/etc/vsftpd/vsftpd.conf` and Task 1's IPv6 workarounds; `vsftpd.service postfix.service` join `START_UNITS`; after `/etc/exports`: `mkdir -p /srv` and `printf '/srv 192.0.2.0/24(rw,no_root_squash)\n' > /etc/exports` (mode stays 666), `exportfs -ra`. Debian: the debconf answers before the `apt-get` line, `postfix` added to it, `anonymous_enable=YES` in `/etc/vsftpd.conf`, `vsftpd.service postfix@-.service` in `START_UNITS`, the exports seed. All four container seeds: `printf '+\n' > /etc/hosts.equiv; chmod 644 /etc/hosts.equiv`. A daemon Task 1 found cannot run leaves `START_UNITS` and gets its line in the Execution notes.
- [ ] **Step 3: `record()`** gains, gated in the `password_policy` style: any planned id in `muster.beyond.audit_rules_loaded muster.beyond.auditd_active muster.beyond.audit_disk_actions` → `x sh -c 'LC_ALL=C auditctl -l' | sed 's/^/auditrule /'` and the six `auditctl -s` keys matched whole (`awk '$1 == "enabled" || … { print "audit", $1, $2 }'`); `password_policy` or `account_inactivity_lock` → `ageing <name> <f4> <f5> <f7>` per account and `shadow-rest <sha256 of shadow with fields 4, 5, 7 blanked>`; `nfs_export_access` → `x exportfs -s | sed 's/^/export /'`; `ftp_banner` or `ftp_anonymous` → `vsftpd $(x systemctl is-active vsftpd.service || :)`; `mail_expn_vrfy` → `postfix-status <rc>`. Update the header comment.
- [ ] **Step 4: Run** lab shellcheck v0.9.0 over `ci/roundtrip/*.sh`, `sh -n` each, and a local `bash -n` plus shellcheck of the `record()` block extracted from ci.yml; `go test ./internal/controls -run TestEveryScriptedControlIsInTheRoundtripTable`. Then replay one init row's seed and repair/failure runs on the lab with docker (one container at a time), as 3D-2c did.
- [ ] **Step 5: Commit** `ci: seed the audit, inactivity and content bodies; record the kernel audit state, shadow field 7 and the daemons`.

---

### Task 13 (controller): documents

**Files:** the design pair (§8 As built), the main design pair (line-aligned), `CLAUDE.md`, `CONTRIBUTING.md`/`.ko.md`, `README.md`/`.ko.md`, `THREAT_MODEL.md`, `CHANGELOG.md`.

- [ ] **Step 1: Design pair** gains `## 8. As built` (EN and KO): every ruling O-19 onward, each place the build departs from §1–§7, the probe's answers, an unproven restart path per row if any.
- [ ] **Step 2: Main design pair** (EN :N = KO :N): `:414` §7.5 appends the 3D-2d design link and one clause (no body makes a one-way runtime change; no load or start over a pending lock); `:468` §10.2 "3D-2d (merged): eight more scripts and the no_root_squash half, fifty-six in all — the audit family, the inactivity bound, the content halves of four service and file controls — after three collector fixes — `2026-10-19-stage3d2d-content-scripts-design.md`", then 3D-3 as today.
- [ ] **Step 3: `CLAUDE.md`** Fix section (`:173` heading adds 3D-2d): the per-run records sentence at `:204-206` (O-16); Units `:233-250` (the enabling body; the stub list gains `auditctl`, `augenrules`, `postconf`/`postfix`, `exportfs`); Remediation bodies `:251-296` (O-2/O-3, O-6, O-8, O-9, O-11, the guarded validate, `LC_ALL=C`, `restorecon`, "eleven units-declaring controls", the count 56 at `:295-296`); the `fix-roundtrip` paragraph `:305-333` (the new seeds, `record()` lines); Risk `:334-342` (the four).
- [ ] **Step 4: CONTRIBUTING pair:** design §3's twelve conventions in the Remediation bodies section (EN :93-210, KO :73-167) at the paragraphs plan-map-docs §3 names.
- [ ] **Step 5: README pair** (status banner 3D-2d merged; a 3D-2d roadmap paragraph after 3D-2c's; Next: 3D-1b, 3D-3), **THREAT_MODEL** (after `:47-48`: O-2, O-3, "no body deletes a kernel audit rule it did not load in this run"; per-run markers are not first-kept), **CHANGELOG** (Added top: the eight bodies and the half, 56 in all, stage 3D-2d; Changed: the four risks, O-11's guards, the `password_hash_algorithm` text; Controls paragraph `kisa-unix-2026+2026.10.19` (was `+2026.10.14`) naming the three verdict fixes).
- [ ] **Step 6: Run** `make lint`, `make lint-controls`, `go test ./...`, `go run ./tools/coverage -check`. Commit `docs: record stage 3D-2d in the working documents`.

---

## Merge (the user's word)

Every step here waits for the user's word. Push the branch; open the PR as a **draft** (a branch push runs no CI; the PR runs every job, fix-roundtrip included); read every fix-roundtrip row end to end, close O-34's open rulings, and fix any red row on the branch (each fix a ruling in the Execution notes) before going on. Then dispatch `examples.yml` on the branch (`gh workflow run examples.yml --ref stage3d2d-content-scripts`), download into an empty scratch dir (`gh run download <id> -n examples-<id> -D <scratch>`), copy over `examples/`, review the diff (the VM example plans the four runner bodies as the stock runner reads them; the container example's verdicts move only through the three fixes), update `examples/README.md`'s run number, commit `examples: refresh from the branch's examples run`, mark the PR ready, read the final run's logs end to end, merge on the user's word, then clean up and update memory.

## Execution notes

### Pre-flight (one fresh-review workflow, 330 agents: eight lenses, three refuters per finding, a critic)

107 findings, 93 upheld, merged into 30 (3 blocking, 16 important, 11 minor); folded as O-25..O-54 above, with five design corrections (the lock pattern anywhere on the line, the `restorecon` rule, the auditctl-only reload, the unset-last-change skip, the exports ERE).

### The probe (Task 1, 2026-10-19; lab containers, one at a time: rocky9-init, almalinux9-init, debian12-init, ubuntu 22.04 and 24.04 without systemd)

Raw output: `.superpowers/sdd/2026-10-19-stage3d2d-content-scripts/probe-out.txt`. Nothing ran `auditctl` with a rule, `-D`, `-b`, `-f`, `-r` or `-e`.

- **O-55 — augenrules.** On every family the generated `audit.rules` starts `-D`, `-b 8192`, `-f 1`, then the rules in `ls -v` order (`50-muster.rules`' watch survives the stock file's `-D`), and ends with `--backlog_wait_time`; a bare `augenrules` regenerates only, prints `No change` and exits 0 when nothing changed; Debian and Ubuntu leave `audit.rules.prev`, EL does not (not in `backup`: it is augenrules' own). Every unit carries `ExecStartPost=-/sbin/augenrules --load`; only the EL unit carries `RefuseManualStop=yes`.
- **O-56 — the reload.** `auditctl --signal <signal>` exists on audit 3.0.7 (Ubuntu 22.04), 3.0.9 (Debian 12) and 3.1.5 (EL9); O-29 holds. EL's `service auditd reload` (the legacy action) runs `augenrules --load` before `auditctl --signal reload`, so no body uses it.
- **O-57 — `-e` spellings, from auditctl's source.** auditctl accepts `-e` only for the strings `0`, `1` and `2` (`strcmp`); `-e2` reaches it as `2` through getopt. `-e 02` and `-e +2` are rejected, so the collector's `lastEnableValue` over-reads them: a recorded divergence in the safe direction (the body refuses on them too).
- **O-58 — postfix.** Stock `disable_vrfy_command` is `no` on all five images (the control FAILs at stock). `postconf -e` replaces `main.cf` (a new inode, mode 644 kept), so O-36's `restorecon` applies to it. `postfix check` creates spool directories on Debian and Ubuntu (harmless). EL runs the master under `postfix.service`; Debian under `postfix@-.service` (`postfix.service` reads inactive), so the Debian seed starts and settles on `postfix@-.service`. `postfix status` works under both.
- **O-59 — vsftpd.** It starts in each init container with the stock `listen=NO`/`listen_ipv6=YES` on the lab's docker; the CI docker's IPv6 is an open question, so the seeds apply `listen=YES`/`listen_ipv6=NO` on every init row anyway (deterministic). On the wire (debian12-init): a clean `ftpd_banner` beside a disclosing `banner_file` sends the file; a disclosing `ftpd_banner` beside an empty `banner_file` sends `ftpd_banner`; neither sends `(vsFTPd 3.0.3)` — O-14 as written. Repeated restarts hit systemd's start limit (`start of the service was attempted too often`): every vsftpd restart in a body or rollback is preceded by `systemctl reset-failed vsftpd.service 2>/dev/null || :` (a plan holding both FTP controls restarts it up to four times in the failure run), and the contentTree stub accepts `reset-failed`.
- **O-60 — NFS.** `/srv` on the container's overlay root cannot be exported (`does not support NFS export`, exit 1), a tmpfs can: the seeds export `/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)` on a tmpfs (O-37). nfs-utils reads a `-opts` default list as O-20 says: `/srv -no_root_squash 192.0.2.7` exports with `no_root_squash`; `/srv -rw` exports to the world; `/srv 192.0.2.8(rw) -no_root_squash 192.0.2.9` applies the default to the later client only; `/srv -no_root_squash 192.0.2.10(root_squash)` squashes (the client's own option wins; the collector's `Contains` reads FAIL there, O-50's recorded divergence). Task 4 goes ahead.
- **O-61 — conffiles.** EL (`rpm -qc`): `vsftpd.conf`, `auditd.conf`, `main.cf`, `/etc/default/useradd`, `/etc/exports`. Debian and Ubuntu (`dpkg-query`): `auditd.conf`, `/etc/default/useradd`, `vsftpd.conf`; not `main.cf`, not `/etc/exports`. The §3.12 sentences name exactly these.
- **O-62 — accounts.** EL ships `INACTIVE=-1` at column one; Debian and Ubuntu ship `# INACTIVE=-1`. `useradd -D` prints the whole defaults set (GROUP, HOME, INACTIVE, EXPIRE, SHELL, SKEL, CREATE_MAIL_SPOOL, LOG_INIT), confirming O-7's direct edit.
- **O-63 — SELinux.** The EL containers ship `selinuxenabled`/`restorecon` with SELinux disabled (`selinuxenabled` exits 1); Debian and Ubuntu ship neither. O-36's guard never fires in CI (§7 parks label proof).
- **Open until the draft PR's run (O-34):** whether a HUP applies the five action keys on the runner (auditd's reconfigure line in the journal); `auditctl -s`'s key names on the azure kernel; the runner's login-capable accounts and shadow fields; IPv6 in the fix-roundtrip docker; that no other scripted control plans because vsftpd or postfix runs on an init row.

### Rulings settled during execution (O-64 …)

Each ends with what it costs if wrong. O-72 is given in its corrected form (the first form assumed a failed rerun removes
`50-muster.rules`; `backup()` in fact replaces an absent marker with a copy once the path exists).

- **O-64** — successive exports default lists ACCUMULATE (measured on rocky9-init: "/srv/ci -no_root_squash 192.0.2.7 -rw 192.0.2.8" gives 192.0.2.8 rw,no_root_squash; "-no_root_squash,rw … -ro" gives ro,no_root_squash): a later `-` list is appended to the defaults, never replaces them — the replace rule reads a real no_root_squash as squashed (false PASS) — if wrong, the collector over-reads no_root_squash (conservative)
- **O-65** — a hosts.equiv line led by a Unicode space (U+00A0, U+0085, U+2000–U+200A) FAILs in the collector (strings.TrimSpace) but the LC_ALL=C body leaves it: a recorded divergence, the block ends done and check names it (X-10); an ASCII-only trim in the collector is deferred to §7 — if wrong, an operator sees a done block with a FAIL on an exotic file
- **O-66** — rhosts_forbidden plans on ubuntu2204 once seeded: the stock container reads files.user_rhosts ok [] and PASSes (examples/ubuntu-24.04-container.json) — if wrong, the seed run shows MANUAL and the row drops the id
- **O-67** — postconf -e (postfix 3.7.11, measured in debian:12) appends without a newline to a main.cf lacking a final one, gluing the new line onto the last; the mail_expn_vrfy body runs the §3.7 final-newline guard before postconf -e (tested) — design §8 records it — if wrong, a harmless extra newline
- **O-68** — the NFS body removes its per-run markers at the top, outside the /etc/exports guard (implementer deviation accepted: a rerun over a vanished or symlinked exports must not leave stale markers) — matches O-16 — if wrong, none
- **O-69** — the O-26 ERE can rewrite a path whose last component ends in ",no_root_squash"/"(no_root_squash" before a blank, or a quoted path holding " -no_root_squash ": accepted as a pathological corner (anchoring past the first token breaks continuation rows); design §8 names it and the text claim is softened in the final wave — if wrong, such an export path is renamed by the swap
- **O-70** — auditTree's systemctl wrapper must run the augenrules --load stub only AFTER a successful start (systemd runs ExecStartPost after ExecStart succeeds; a masked unit loads nothing); Task 10 fixes the order because its start-branch tests depend on it — if wrong, a masked-unit test reads a floor as loaded
- **O-71** — auditctl --signal fails when auditd is not running; the audit stub models it (Task 10), and a rollback whose reload meets a dead daemon logs rollback failed honestly; the rollback never starts auditd (a start runs augenrules --load, O-3) — if wrong, an operator sees rollback failed on a host where the file was in fact restored
- **O-72 (corrected)** — backup() replaces an absent marker with a copy once the path exists (script.go backupHelpers), so a failed rerun of audit_rules_loaded restores 50-muster.rules holding the first run's floor; file and kernel agree; the rerun test pins that (78f9080) — the earlier O-72 premise was wrong — if wrong, none
- **O-73** — audit_rules_loaded logs "auditctl -l failed; refused" for a failing auditctl -l (O-23 had no line for it) — if wrong, one log string
- **O-74** — auditd_active refuses a start whenever a lock is pending (O-3 pending half), whatever the runtime lock state; the locked-runtime exemption of design O-5/§4.1 is withdrawn (loginuid_immutable locks only its feature, the rule list stays writable, so a start loads a pending -e 2; and inertness under enabled 2 is unprobed) — supersedes O-5's "or the runtime is already locked"; design §8 records it — if wrong, a STIG host with a locked kernel and an inactive auditd gets a failed block instead of a started daemon (safe)
- **O-75** — account_inactivity_lock logs "<name>: password ageing fields are not numbers, left as is" for a junk or over-long last/max (skipped, safe side; O-23 had no line) — if wrong, one log string
- **O-76 (O-51 walk, by reading seeds against bodies)** — on the runner after runner.sh: audit_rules_loaded (sorted first) hits case (c) (nothing persisted, kernel No rules, auditd active): writes the floor and --load; auditd_active finds the unit active+disabled: enables only, never starts; audit_disk_actions writes syslog over the seeded suspend and reloads (was-running). Failure run: re-seed rm 50-muster.rules, augenrules --load (stock -D clears the floor), auditctl -b 4321; rollbacks restore No rules, -b 4321, disabled, the stock conf — record() lines equal. The draft PR run confirms — if wrong, the runner row shows which case it hit
- **O-77** — account_inactivity_lock skips and names an account whose field 5 is below -1 (pam_unix treats any max other than -1 as real; shadow isexpired guards >= 0) and any name with more than one shadow row (chage and pam read the first row, the collector the last); design §4.4 note in §8 — if wrong, a hand-edited account keeps no inactivity bound
- **O-78** — the failure run replaces the whole one-line validate with "false" (ci.yml awk), so mail_expn_vrfy's guarded validate is rewritten like any other — the Task 8 note is settled — if wrong, the blocks count check fails visibly
- **O-79 (F1, measured on rocky9-init)** — "/srv/ci 192.0.2.8 -no_root_squash" exports 192.0.2.8 AND <world> with no_root_squash: a trailing default list mints a world record; the collector emits exportRecord(path, "*", defaults) when the last token is a default list — today it reads a false PASS — if wrong, a conservative extra world record
- **O-80 (F8, measured)** — a "-" token directly after a "-" list is not a second default list: nfs-utils reads it as a host name, which fails to resolve and exports nothing ("Failed to resolve -rw"); the clients after it carry only the defaults so far ("-no_root_squash -rw X" exports X ro,no_root_squash; "-root_squash -no_root_squash X" exports X root_squash); the collector ignores such a token and does not join it — amends O-64 (which stands for lists separated by a client) — if wrong, a conservative FAIL on an odd line Unmeasured: a list, an ignored `-` token and then the end of the line (`/s -a -b`) reads as a world export under `-a`; nfs-utils most likely exports nothing there (conservative).
- **O-81 (F4)** — rhosts_forbidden refuses (logs, exit 1, file untouched) a hosts.equiv "+" line carrying a "-user"/"-@netgroup" field: commenting out a first-match denial would widen trust (ruserok uses the first matching line) — if wrong, an operator edits such a file by hand
- **O-82 (F5)** — ftp_banner's awk no longer opens banner_file; the shell treats it as set only when [ -f ] && [ ! -L ] && [ -s ] (the collector's regular, non-empty rule), replacing the - and /dev/stdin special case — a FIFO, tty or special path is never opened as root — if wrong, a banner_file the collector reads absent is rewritten over (the row would read MANUAL, so unreachable via check)
- **O-83 (F7)** — an auditd action value is reduced on the ASCII SPACE only (auditd splits on spaces; a tab-joined "exec	/y" is refused by auditd and now stays whole and FAILs); "syslog extra words" and "email # note" stay honoured as their first word (auditd logs "Wrong number of arguments" and reads the first value) — if wrong, a tab-joined action reads FAIL
- **O-84 (F3)** — record() captures each producer (auditctl -l/-s, exportfs -s, the shadow awk) into a variable and exits 1 when it fails, and requires a non-empty result when the matching id is planned; no blanket pipefail — if wrong, a record step fails loudly instead of passing empty

### What the reviews found

- **Task reviews.** Tasks 2–4 were reviewed as one batch: Task 4 replaced an earlier default list where nfs-utils adds
  to it (O-64, measured) — one fix round. Task 7: the vsftpd symlink skip and the running-unit validate were untested,
  and a `banner_file=-` would read standard input — one fix round. Task 10: **critical** — `auditd_active` started auditd
  over a pending `-e 2` when only `loginuid_immutable` was locked; the design's locked-runtime exemption was wrong (O-74)
  — one fix round. Task 11: a `max` below -1 read as no maximum while pam_unix treats it as real (a lockout), and
  duplicate shadow rows (O-77) — one fix round. Tasks 5, 6, 8, 9 and 12 were clean on the first review.
- **Whole branch.** One workflow (89 agents: seven lenses, three refuters per finding, a critic): 27 findings, 19
  upheld, merged into 12 (F1 a trailing exports default list read a false PASS, O-79; F2 these rulings were only in the
  ignored ledger; F3–F12 minor). One fix wave applied F1 and F3–F12 (O-79..O-84); the controller applied F2 and the
  documents.
- **Lessons.** Measure a daemon's grammar before writing a parser rule against it: three of this cycle's corrections
  (O-64, O-79, O-80) were nfs-utils readings no one had measured. A ruling that exempts a locked state must name which
  lock: `loginuid_immutable` and `enabled 2` lock different things (O-74). A stub that runs a unit's post-start hook
  before the start hides the masked-unit case (O-70). A probe container that starts the kernel NFS server can wedge on
  `rpcbind` in D state at removal; stop nfs-server inside it first, or kill the stuck pid from the host.

### CI

(The draft PR's runs go here as they land.)
