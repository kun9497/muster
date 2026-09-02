# muster — architecture and design

*English · [한국어](2026-09-02-muster-design.ko.md)*

**Date:** 2026-09-02
**Status:** Agreed. Design approved section by section (architecture, facts schema, control format, error handling, testing) on 2026-09-02, then revised after a four-lens review; this document is the written form of that agreement and supersedes the pre-repository handoff notes.

This is the reference design for the whole project. Individual slices get their own implementation plans under `docs/superpowers/plans/`; this document records what the system is, why it is shaped this way, the contracts that must not change after the first release, and the order in which it gets built. Decisions are numbered `D01`… and referenced from the sections that depend on them; the decision log is section 13.

---

## 1. Goal and identity

**muster answers one question: does this Linux server pass muster?** It collects the facts of a host as root, writes them to a snapshot, and evaluates that snapshot — offline, without the host — against the Unix server items of the KISA technical vulnerability assessment guide for critical information infrastructure (주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드), with CIS Benchmark recommendation numbers attached as cross-references.

It is a configuration checker, not a vulnerability scanner. Its sibling [assay](https://github.com/kun9497/assay) matches packages against advisories; muster never does. The two share decisions (evidence in the result, the exit code contract, waiver rules, per-distribution logic kept apart), not code (D01).

It is an unofficial personal open-source project. It is not endorsed by KISA or by the Center for Internet Security, contains no CIS Benchmark text, claims no level of CIS compliance, and does not replace an official assessment (D02, D04).

Three properties define it and are enforced by structure rather than by discipline:

- **Unseen is unseen.** A fact that could not be read is `ERROR`, never a quiet `PASS`. Half a check is not a `PASS` either (D07).
- **Evidence rides in the result.** Every verdict carries the value it was decided on and the file and line that produced it (D08).
- **Safe to run as root.** No shell, a fixed whitelist of commands, no symlink following, a size cap on every read, a snapshot that stores derived attributes instead of secrets, and nothing written except the snapshot (D14).

## 2. Fixed decisions

| Topic | Decision | Reference |
|---|---|---|
| Relationship to assay | Separate repository, separate binary; decisions reused, code not | D01 |
| Ownership | Personal open-source project, Apache-2.0; no company code or control definitions; commits under a personal identity | D02 |
| Target OS | Linux only, permanently. First release: Ubuntu LTS 22.04 and 24.04, Rocky / AlmaLinux 9 | D03 |
| Standard | KISA guide, 2026 edition, Unix server items U-01–U-67; CIS numbers only as references; guide text never copied or vendored | D04 |
| Control model | Controls are YAML data with a small judgment vocabulary; named Go functions only for what the vocabulary cannot express | D05 |
| Collect / check split | `collect` runs as root on the host; `check` is a pure function of (snapshot, controls, waivers, params) and needs no host | D06 |
| CVE matching | Out of scope. The snapshot carries the installed package list so it can be handed to a scanner as an SBOM | D24 |
| Network checks | Host-internal only: listening sockets, firewall rules, network sysctls, unnecessary services. No port scanning | D24 |
| Remediation | Never applied. A remediation script can be generated for review, with risk levels and rollback | D24 |
| Language | Go, minimal dependencies, no CLI framework, one static binary | D28 |
| Exit codes | `2` (cannot run or cannot be trusted) > `1` (findings) > `0` (clean) | D11 |

## 3. Standard: KISA edition and references

Two editions of the guide are in circulation. The 2021 edition numbers the Unix items U-01–U-72. The 2026 edition (published by KISA on 2025-12-24; PDF dated 2025-12-23) renumbers them completely: 67 items, of which only U-01, U-03 and U-04 keep both code and meaning. Web checks left the Unix section for a new chapter (WEB-01–WEB-26); four password items merged into U-02; cron and at merged into U-37; two NFS items merged into U-40; eight items are new (U-13 hash algorithm, U-51 DNS dynamic update, U-53 FTP banner, U-59 SNMP version, U-61 SNMP access control, U-63 sudoers permissions, U-65 time synchronisation, U-67 log directory permissions); 2021 U-43 (periodic log review) is gone. Both editions were verified against the original PDFs; the item inventory, categories, importance levels and the 2021→2026 mapping live in `docs/reference/kisa/` (D04).

**muster follows the 2026 edition.** `guide_edition: kisa-unix-2026` appears in every snapshot and report. Because item numbers are not stable across editions, they are never the primary key of anything: controls have muster-native ids and carry the KISA number per edition under `references.kisa` (D16). The 2021 number is recorded so a reader of an older assessment can find the control.

The 2026 Unix section, by category and importance:

| Category | Items | 상 | 중 | 하 |
|---|---|---|---|---|
| 계정 관리 (accounts) | U-01–U-13 (13) | 6 | 3 | 4 |
| 파일 및 디렉토리 관리 (files) | U-14–U-33 (20) | 15 | 3 | 2 |
| 서비스 관리 (services) | U-34–U-63 (30) | 18 | 9 | 3 |
| 패치 관리 (patching) | U-64 (1) | 1 | 0 | 0 |
| 로그 관리 (logging) | U-65–U-67 (3) | 0 | 3 | 0 |

Two defects in the published material are recorded so control authors do not inherit them: the 2026 PDF's page 53 prints U-28's inspection text in U-26's cells (the title, threat, criterion and remediation of U-26 are correct); and U-17's relationship to 2021 U-14 is uncertain (split or new).

**What is reproduced from the guide, and what is not.** Item codes, item names, categories, importance levels and page numbers are reproduced in this repository — in `docs/reference/kisa/` and in appendix A — as a factual cross-reference index, the minimum needed to relate a muster result to an assessment. Everything else is muster's own wording: control titles, descriptions and rationale are written independently, and the guide's inspection, purpose, criterion and remediation text is never reproduced, in the reference directory or anywhere else. The guide itself is linked, not included. The guide's publisher, edition, publication date, source URL and stated copyright notice are recorded in `ATTRIBUTION.md`, and the README, the NOTICE file and `ATTRIBUTION.md` state this boundary in the same words (D04).

**CIS references.** Each control may list CIS Benchmark recommendations as `{benchmark, version, rec}` — a benchmark name, its version and the recommendation number. No recommendation title, text or audit procedure is stored; the control schema defines no field for them and rejects unknown fields; the same rule applies to `references.kisa`, which holds edition-keyed item ids and nothing else. muster reports no CIS compliance level. Two separate sources drive this: CIS publishes non-member Benchmarks under CC BY-NC-SA 4.0, whose NonCommercial and ShareAlike conditions alone are incompatible with an Apache-2.0 repository, and CIS's Terms of Use additionally prohibit creating derivative works based directly on a non-member product and representing a particular level of compliance (D04).

## 4. Architecture

### 4.1 One binary, two core commands

```
sudo muster collect --out host.json      # on the host, as root
muster check --facts host.json           # anywhere, no root
muster check --facts host.json --format json
```

Subcommands: `collect`, `check`, `controls` (`lint`, `list`; `new` from stage 2), `snapshot` (`info`, `extract`; `ls`, `rm`, `prune` from stage 4), `version`; later `fix --dry-run` and `explain`. Arguments are dispatched by hand as in assay; there is no CLI framework (D28).

### 4.2 Packages

| Package | Responsibility | Must not |
|---|---|---|
| `cmd/muster` | argument parsing, dispatch, exit codes | contain logic |
| `internal/facts` | snapshot types, the fact envelope, the key registry, `schema_version`, validation, serialisation | import `collect` |
| `internal/collect` | collector registry, the single read primitive, exec discipline, distribution adapters (`distro/ubuntu`, `distro/rhel`), the filesystem walk; Linux build tags | read controls, waivers or existing snapshots |
| `internal/controls` | control schema, strict YAML loader, embedded default set, lint | evaluate |
| `internal/check` | `Evaluate(facts, controls, waivers, params) → results` | import `os/exec`, `net`, or anything that touches the host (enforced by test) |
| `internal/waiver` | waiver file loading and matching | be consulted by `check` before evaluation — suppression is a step after |
| `internal/report` | table and JSON renderers (SARIF in stage 4), determinism, escaping | compute verdicts |

### 4.3 Data flow

```
host ──collect (root; reads only what the registry declares)──▶ snapshot.json
        0600, atomic, /var/lib/muster/snapshots/, flock
snapshot.json + controls (embedded) + waivers + params
     ──check (no root; treats the snapshot as untrusted input)──▶ results
results ──renderers──▶ table / JSON ──▶ exit code (2 > 1 > 0)
```

### 4.4 Trust boundary

The root process (`collect`) reads only what its code-level registry declares and executes only whitelisted commands; it never parses a control file, a waiver file or a previous snapshot. Data files are read only by `check`, which never needs root and warns when run as root. Controls ship embedded in the binary; an external control directory (`--controls-dir`, stage 4) is opt-in, logged with per-file digests, and refused if it collides with an embedded id. When `check` runs as root, waiver and control files that are not root-owned or are group/other-writable are refused (D14, D15).

### 4.5 Where distribution variance is absorbed

Only in `collect`: the distribution adapters and the logical-service map (`ssh`→`ssh`/`sshd`, `cron`→`cron`/`crond`, `ntp`→`chrony`/`systemd-timesyncd`/`ntpd`, `syslog`→`rsyslog`/`syslog-ng`/journald). Keys under `services.*` are always logical names, never unit names. `check` does not know which distribution produced a snapshot; a control may mention a distribution only inside `applies_when`. Mechanisms a distribution has removed (pam_tally2, `/etc/securetty`, tcp_wrappers) are handled by the control's `mechanisms` list, which is data, not adapter code (D09).

### 4.6 Extension points

A new control is one YAML file and two fixtures. A new fact is one registry entry and one collector function. A new distribution is one adapter. Anything else is a design change.

### 4.7 Platforms

Release artifacts in the first release are `linux/amd64` and `linux/arm64`. `collect` sits behind Linux build tags; `check`, `controls`, `report` and `facts` must compile on any GOOS, so a check-only build for analysts' workstations can be added later without restructuring (D23).

## 5. Facts snapshot schema

### 5.1 Shape

One JSON file, UTF-8, serialised from structs so key order is fixed. Three top-level parts:

```json
{
  "schema_version": 1,
  "run": {
    "muster_version": "0.1.0", "commit": "abc1234",
    "controls_version": "kisa-unix-2026+2026.09.01", "controls_digest": "sha256:…",
    "guide_edition": "kisa-unix-2026",
    "collected_at": "2026-09-02T06:00:00Z",
    "host": {"hostname": "web-01", "machine_id_hash": "…", "kernel": "5.14.0-…",
             "os_release": {"id": "rocky", "version_id": "9.4"}, "boot_id": "…", "uptime_s": 12345},
    "euid": 0, "capabilities": ["CAP_DAC_READ_SEARCH"],
    "env": {"container": "none", "virt": "kvm", "wsl": false, "chroot": false,
            "has_systemd": true, "sysctl_writable": true, "cloud_init": false},
    "collectors": [{"name": "sshd", "status": "ok", "ms": 41, "cmd": "/usr/sbin/sshd -T"}],
    "redaction": {"profile": "default", "include_secrets": false},
    "deep": false,
    "complete": true, "partial_failures": []
  },
  "facts": {
    "sshd": {
      "collect_method": "T", "version": "8.7", "personas_collected": false,
      "options": {
        "permit_root_login": {
          "runtime":   {"status": "ok", "value": "no", "source": {"kind": "command", "cmd": "/usr/sbin/sshd -T"}},
          "persisted": {"status": "ok", "value": "no",
                        "source": {"kind": "file", "path": "/etc/ssh/sshd_config.d/50-cloud-init.conf", "line": 2,
                                   "raw": "PermitRootLogin no"}},
          "effective": {"status": "ok", "value": "no", "source": {"kind": "command", "cmd": "/usr/sbin/sshd -T"}},
          "winner":    {"kind": "file", "path": "/etc/ssh/sshd_config.d/50-cloud-init.conf", "line": 2}
        }
      }
    }
  }
}
```

`run` is provenance: which tool and control set produced the file, when, on which host, with which privileges, in which environment, and what went wrong. It exists so that a snapshot alone reproduces an issue, so that an old snapshot cannot be mistaken for a current one, and so that a diff between snapshots can separate "the server changed" from "the rules changed" (D16, D17). `controls_version` and `controls_digest` in `run` record the control set embedded in the collecting binary; `check` evaluates with its own control set regardless, records both pairs in the result, and warns on stderr when they differ. It is never an error.

### 5.2 The fact envelope

Every leaf under `facts` is an envelope:

```
{status, value, source, truncated}
status ∈ ok | absent | denied | unsupported | timeout | error
source = {kind: file|command|proc|sys|derived, path, line, raw, cmd, exit_code}
```

The statuses mean different things and controls treat them differently: `absent` — the collector looked and the file, unit or package does not exist; `unsupported` — this distribution or environment has no such mechanism (sysctl inside a container, `/etc/securetty` on RHEL 9); `denied` — insufficient privilege, with the required privilege named; `timeout` and `error` — collection failed. `source` is where the "file and line" in every piece of evidence comes from; `raw` is the source line itself, length-capped. For `kind: derived` (a merged sysctl winner, a hash algorithm read off a shadow entry, a pwquality value assembled from several PAM lines) `path` and `line` are omitted and the envelope carries `inputs: [source, …]`, every source the value was computed from in evaluation order; renderers show the first and the count of the rest. Multi-valued keys (`ciphers`, `listen_address`, `authorized_keys_file`…) are lists from the start, because turning a string into a list later is a breaking change (D07, D08).

One further status exists only on the reading side. When `check` looks up a key its registry knows and the snapshot does not carry it at all — a snapshot older than the key, or a collector that did not run — the reader synthesises an envelope with status `missing`. `collect` never writes `missing`. It is never resolved by `absent_means`, which applies only to a fact the collector looked for and did not find; a `missing` fact always makes the control `ERROR(missing_fact)` (D07, D17).

### 5.3 Settings with two homes

A setting that lives both in the running kernel or daemon and in a persisted file is a `setting`, not a single envelope:

```
{runtime: envelope, persisted: envelope, effective: envelope, winner: source}
```

The four sides are selected only by `on:` in a control clause; no fact key ever contains a segment named after a side. Used for sysctl (`/proc/sys` versus the merge of `/etc/sysctl.conf` and every `*.conf` under `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d` and `/usr/lib/sysctl.d`, where a file in an earlier directory shadows one of the same name in a later directory and the surviving files apply in lexicographic order, the winning file and line recorded as `winner`), services (active versus unit-file state), firewall (kernel ruleset versus persisted configuration), kernel modules (loaded versus blacklisted), SELinux (`enforce` versus `/etc/selinux/config`), mounts (`mountinfo` versus `fstab`), password policy (`login.defs` versus the effective per-account fields in `shadow`; `PASS_MIN_LEN` versus pwquality), and sshd and PAM (daemon-reported versus muster's parse of the files the daemon reads).

The registry declares each setting's default side. It is `both` for kernel and daemon state that also lives in a file (sysctl, services, firewall, modules, SELinux, mounts, password ageing): both sides must satisfy the clause, and a mismatch is its own verdict with its own reason. It is `effective` where the persisted side is muster's own parse of the same files the daemon reads (sshd, PAM): `effective` is the daemon-reported side when it was collected and the parsed side, marked degraded, when it was not (D10).

### 5.4 Sections

`os`, `env`, `packages`, `accounts` (users, groups, shadow-derived fields, `login_defs`, NSS sources), `pam` (managing layer, expanded stacks, derived pwquality/faillock values with sources), `sshd` (`collect_method`, `version`, `personas_collected`, `options.*` as settings, per-persona overrides from stage 2, include sources), `sysctl` (the whole tree), `services` (logical name, unit, load/active/sub state, unit-file state including `masked`/`static`/`indirect`, triggering sockets, `installed`, `reachable`), `sockets` (listening sockets with inode, pid and executable), `firewall` (backend with detection evidence, raw dumps, normalised model, `normalization_confidence`), `logging`, `files` (permission facts for enumerated paths), `walk` (results of `--deep`: SUID/SGID, world-writable, unowned; `complete`, `skipped`), `cron` (crontabs and systemd timers as one inventory), `mounts`, `mac` (SELinux/AppArmor), `banners`, `patch` (cached update metadata, reboot required, auto-update configuration), `time_sync`, `inetd`, `snmp`. Stage 1 populates only the sections its five controls need; the others exist as types.

`reachable` is true when a connection from off the host would reach the service without further action — the unit is active, or a socket unit that activates it is listening — on an address other than loopback; it is false when the service runs but is bound only to `127.0.0.1` or `::1`, or is not running and has no listening socket unit.

Permission facts are richer than `st_mode`: `{mode, uid, gid, acl_present, acl_entries, default_acl, caps, attrs, selinux_label, has_extra_xattr}`. A file whose mode is correct but whose ACL grants group or other access is a `FAIL`; a file whose ACL is present but could not be read or parsed cannot be a `PASS` (D26).

### 5.5 Key registry

`internal/facts/registry.yaml` lists every key a control may reference: `{key, type, description, since, sensitivity, collector, default_on}`. `type` is one of `string`, `int`, `bool`, `list<string>`, `record`, `list<record>` and `setting<T>`; `sensitivity` is `public`, `internal` or `secret` (section 5.6); `default_on` exists for settings (section 5.3). Controls reference registered keys such as `sshd.options.permit_root_login` and nothing else — no raw JSON paths. `muster controls lint` fails on an unregistered key and reports keys no control uses. The registry is the contract between `collect` and `check`; it is what makes "the collector absorbs variance" enforceable rather than aspirational (D07, D09).

### 5.6 Sensitive values

The registry's `sensitivity` label decides what is stored. By default: `/etc/shadow` → hash algorithm, rounds, locked, empty-password flag and ageing fields, never the hash; `authorized_keys` → key type, bits, fingerprint, options and comment, never the key; SNMP community → whether it is a default value, its length and whether a source restriction is attached, never the string; private keys, host keys and keytabs → existence and permissions only; process command lines → `argv[0]` only. `--include-secrets` stores originals and records that fact in `run.redaction`, so the file itself says what it contains (D13).

### 5.7 Versioning

`schema_version` is an integer. Adding a key does not bump it (the key's `since` records when it appeared); changing a key's type or meaning, or removing one, does. `check` refuses a snapshot with a higher version (`exit 2`, `schema_mismatch`) and reads a lower one; a registered key the snapshot does not carry reads as `missing` (section 5.2), and every control that references it is `ERROR(missing_fact)` — never `PASS`, and never resolved by `absent_means`. A control declares `requires_facts: ">=N"` for an integer N (the only form accepted); a control whose requirement the snapshot does not meet is `ERROR(missing_fact)` naming the version, without evaluation. A reflection-generated schema golden file and a corpus of old snapshots under `testdata/snapshots/v<N>/` keep the rule honest (D17).

### 5.8 Limits

One MiB per file read (smaller for `sudoers` and `authorized_keys`); beyond that `truncated: true`. Walk results carry a count cap and `truncated_count`. A control that depends on a truncated fact cannot `PASS`.

### 5.9 Lifecycle

The default output is `/var/lib/muster/snapshots/<hostname>-<UTC timestamp>-<short digest>.json` (directory 0700, file 0600), written to a temporary file and renamed; `--out <path>` and `--out -` override. A `latest` symlink is replaced atomically. A lock at `/var/lib/muster/.lock` makes a second concurrent `collect` exit 2 naming the running PID. Free space is checked before writing. `snapshot ls|rm|prune --keep N --keep-days D` and example timer units arrive in stage 4 (D13).

## 6. Control format

### 6.1 Files and identity

One control per file under `controls/<area>/<name>.yaml`, embedded into the binary. The primary key is a stable, meaning-based id such as `muster.account.root_remote_login`; the KISA number is a reference. The set as a whole has `controls/VERSION` (for example `kisa-unix-2026+2026.09.01`) and a digest, both reported in every result. The binary follows semver; the control set has its own version, and a change that alters a verdict on an existing snapshot is at least a minor release with a `Controls` section in the changelog (D16).

### 6.2 A control

```yaml
id: muster.account.root_remote_login
title_en: Root login over SSH is disabled
title_ko: SSH를 통한 root 직접 로그인 차단
category: account                # account | file | service | patch | log | beyond
importance: 상                    # KISA importance, mandatory; severity is derived from it (section 9)
automation: auto                 # auto | partial | manual | not_applicable
references:
  kisa: { "2026": ["U-01"], "2021": ["U-01"] }
  cis:  [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]   # numbers only
requires_facts: ">=1"
applies_when:
  - { fact: services.ssh.installed, op: eq, expected: true }
absent_means: not_applicable     # no ssh service → NOT_APPLICABLE with the reason attached
params:
  allowed: { type: list<string>, default: ["no", "prohibit-password"],
             description: Values of PermitRootLogin that count as disabled }
mechanisms:                      # first mechanism whose `when` holds is the one judged
  - when:
      - { fact: sshd.options.permit_root_login, op: present }
    checks:
      - { fact: sshd.options.permit_root_login, on: effective, persona: root,
          op: in, expected: "${allowed}" }
  - when:
      - { fact: files.etc_securetty, op: present }          # legacy fallback
    checks:
      - { fact: files.etc_securetty.lines, op: none,
          where: { op: matches, expected: "^pts/" } }
remediation:
  text_en: Set PermitRootLogin no in sshd_config(.d), validate with sshd -t, restart sshd.
  text_ko: sshd_config(.d)에 PermitRootLogin no 를 설정하고 sshd -t 로 검증 후 재시작
  risk: lockout_risk             # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  script: |
    printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
  rollback: rm -f /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
decision: D09
```

Fields: `id`, `title_en`, `title_ko`, `description_en`, `description_ko` (own wording), `category`, `importance`, `automation`, `manual_reason` (required when `automation: manual`), `references` (`kisa` as edition-keyed item ids; `cis` as benchmark/version/`rec`; `isms_p` and `nist_800_53` keys reserved and empty), `requires_facts`, `applies_when`, `absent_means` (required for any control that references a fact that can be `absent`), `params`, exactly one of `checks`, `mechanisms` or `custom`, `remediation` (required when `automation: auto` or `partial`), `decision` (optional pointer into section 13).

### 6.3 Judgment vocabulary

**Clause grammar.** Every clause — under `checks`, `when`, `applies_when`, `where` and `require` alike — uses exactly the keys `{fact, op, expected}` plus the optional modifiers `on` and `persona`; inside `where` and `require`, `field` replaces `fact` and names a field of the element being examined, or is omitted when the element is a scalar. Strict decoding rejects any other key. `applies_when` and `when` are lists of clauses that must all hold; a single inline clause is shorthand for a one-element list. There is no `or`: alternatives are expressed with `mechanisms`.

**Operators.** Twelve scalar operators — `eq ne in not_in lt lte gt gte matches contains present absent` — and two collection operators, `each` and `none`. `present` and `absent` take no `expected`. `matches` takes a Go `regexp` (RE2) pattern, matched unanchored and case-sensitively against the whole value of a scalar or against each element of a list, where `.` does not match a newline; lint compiles every pattern at load. Comparison is typed by the registry, so `"0"` and `0` cannot be confused; `lt`…`gte` require a numeric type.

**Parameters.** `expected` is a literal or `${name}`. Substitution is whole-value only — the entire `expected` must be exactly `${name}` — and the parameter's value is inserted with its declared type preserved, so a list parameter yields a list. Each entry under `params` declares `{type, default, description}`; lint rejects a reference to an undeclared parameter and a default of the wrong type.

**Settings.** On a `setting` fact, `on` selects `runtime`, `persisted`, `effective` or `both`, defaulting to the registry's `default_on` for that key (section 5.3). With `both`, both sides must satisfy the clause; one side satisfying it and the other not is a `WARN` with reason "reverts on reboot" (runtime only) or "not applied" (persisted only).

**Personas.** `persona` selects an sshd Match persona — `root`, `user` or `invalid` — and is meaningful only on `sshd.options.*`. When the snapshot's sshd section has `personas_collected: false`, the clause is evaluated against the global value and the control's collection counts as degraded (section 6.5).

**Collections.** `each` and `none` apply to a `list<record>` or `list<string>` fact and produce observations (section 6.4). `each` takes `subject`, an optional `where` (a filter clause; elements that do not satisfy it are ignored) and a required `require` (a clause every remaining element must satisfy). `none` takes an optional `subject` and a required `where`; no element may satisfy it. One element that fails `require`, or one that satisfies `none`'s `where`, makes the clause fail.

**Overflow.** What the vocabulary cannot express uses `custom: <GoFunctionName>`, a function registered in `check` that reads only facts and returns observations in the same shape (D05).

### 6.4 Collections and observations

An item whose subject is a set of things is written with `each`:

```yaml
id: muster.file.world_writable
automation: partial              # evidence is automatic, the final judgment is human
checks:
  - fact: walk.world_writable
    op: each
    subject: path                # observation key → file:/var/tmp/x
    where:   { field: sticky, op: eq, expected: false }
    require: { field: package_declared, op: eq, expected: true }   # shipped that way by a package
```

Each observation is reported as `{subject, expected, actual, verdict, source}`. Subject keys have the form `<kind>:<value>`; the registry entry of the collection fixes the kind (`file`, `dir`, `user`, `group`, `unit`, `port`, `module`, `mount`, `key`) and the `subject:` field names the element field whose value fills `<value>`. A control's status follows from its observations: with `each`, every observation must hold; with `none`, no observation may exist; one failing observation fails the clause, and the table shows the first N failing observations with `--all` for the rest. A waiver can name the whole control or one observation (`muster.file.world_writable#file:/var/tmp/x`) (D08, D20).

### 6.5 Status derivation (fixed)

The rows below are evaluated in order and the first that applies decides. Fact statuses are examined for every fact a step references, including the facts used by `applies_when` and `when`.

| Step | Situation | Status |
|---|---|---|
| 1 | `requires_facts` is not met by the snapshot | `ERROR(missing_fact)`, no evaluation |
| 2 | `automation: manual` | `MANUAL` with the collected evidence |
| 3 | a fact referenced by `applies_when` is `missing`, `denied`, `timeout`, `error` or `truncated` | `ERROR` naming the fact |
| 4 | a fact referenced by `applies_when` is `absent` or `unsupported`, or `applies_when` evaluates false | `NOT_APPLICABLE` with the evidence attached |
| 5 | `mechanisms` is used and no `when` holds because every candidate fact is `absent` or `unsupported` | per `absent_means` (`pass`, `fail`, `not_applicable`, `manual`) |
| 6 | a fact referenced by the chosen `checks` is `missing`, `denied`, `timeout`, `error` or `truncated` | `ERROR` naming the privilege, limit or key |
| 7 | a fact referenced by the chosen `checks` is `unsupported` | `NOT_APPLICABLE` naming the environment |
| 8 | a fact referenced by the chosen `checks` is `absent` | per `absent_means` |
| 9 | the control is walk-based and the walk was not run | `MANUAL` ("run collect --deep") |
| 10 | the control is walk-based and `walk.complete` is false | `ERROR(walk_incomplete)` |
| 11 | a clause fails and `automation: partial` | `WARN`, listed under manual review |
| 12 | a clause fails | `FAIL` |
| 13 | all clauses hold but collection was degraded (parse fallback for a daemon-reported setting, personas requested but not collected, firewall confidence below full, a remote NSS source for account facts) | `WARN` naming the degradation |
| 14 | all clauses hold | `PASS` |

The evaluator runs the walk gate (steps 9–10) before the fact-status screening (steps 6–8) for walk-based controls, so a walk that was not run yields `MANUAL`, not `ERROR` for the absent walk facts.

Waivers are applied after the table, to `FAIL` and `WARN` only: a matching, valid waiver turns the result into `WAIVED`, counted and shown. A waiver never applies to `ERROR`, `NOT_APPLICABLE` or `MANUAL`; when one matches such a control it is recorded as not applied, with the reason, and the exit code is unchanged.

`WARN` therefore means one of three things and the reason says which: collection was degraded (step 13); the criterion holds but a risk signal remains (a `both` setting satisfied on one side only, section 6.3); or the judgment is a human one (step 11). `MANUAL` means no automatic judgment is possible and evidence is attached. Neither affects the exit code unless asked (D18).

### 6.6 Parameters and profiles

`params` declares thresholds with types and defaults; judgments reference them (section 6.3). In stage 1 only the defaults exist. `--tuning <file>` (organisation values) and profiles (`{extends, include, exclude, params, severity}`, with a built-in profile named `default`) arrive in stage 3. The parameter values in force are recorded in the result (D18).

### 6.7 Waivers

The file follows assay's D102:

```yaml
waivers:
  - control: muster.file.world_writable
    subject: "file:/var/tmp/legacy.sock"   # optional; absent means the whole control
    reason: legacy batch job creates this socket; migration planned 2026-Q4   # mandatory
    expires: 2026-12-31                    # optional, inclusive
```

A waiver without a reason, with an unknown key, or with no match field is refused at load. An expired waiver stops waiving and warns. A waiver naming a control id that does not exist warns. A waiver suppresses only `FAIL` and `WARN` (section 6.5): a control whose status is `ERROR` is never waived — the waiver is recorded as not applied and the exit code stays 2, and `--allow-error` is the only way to take errors out of the exit code. A waived finding moves to `WAIVED`: it is out of the exit code and always in the summary ("waived N, of which M expire within 30 days"). When `check` runs as root, a waiver file that is not root-owned or is group/other-writable is refused (D12).

### 6.8 Lint

`muster controls lint` rejects: unknown keys (strict decoding), duplicate ids, unregistered fact keys, unknown `custom` function names, a clause key outside the grammar of section 6.3, a `matches` pattern that does not compile, a reference to an undeclared parameter or a default of the wrong type, `manual` without `manual_reason`, `auto` or `partial` without `remediation`, missing `importance`, a control that can meet an `absent` fact without `absent_means`, `references.cis` entries with any field beyond `benchmark`, `version` and `rec`, `references.kisa` values that are not edition-keyed lists of item ids, and a control without its fixture pair. From stage 2 it also cross-checks the id set against the 67-item master list in `docs/reference/kisa/` for missing or duplicated KISA references.

## 7. Error handling and exit codes

The rule: no failure becomes a silent `PASS`, and the tool itself neither crashes nor hangs.

### 7.1 collect

Collectors are isolated. One failing collector records its status, reason and duration in `run.collectors[]`, marks its facts `error` (or `timeout`, `denied`), sets `run.complete=false` and names itself in `run.partial_failures`; the others continue. The snapshot is written with whatever succeeded — but only ever as a completed temporary file renamed into place, so a half-written snapshot cannot exist.

| Failure | Result |
|---|---|
| command timeout (5 s default, per-collector override) or global deadline (`--timeout`, 5 min default) | process group killed; fact `timeout` |
| insufficient privilege | fact `denied` with the required privilege named; `--require-root` exits 2 before writing anything when euid ≠ 0 |
| symlink, FIFO, device, oversized or binary file | refused or truncated by the read primitive; `error` / `truncated`; never blocks |
| walk over budget | `walk.complete=false`, stop point and `skipped[]` recorded |
| unknown distribution | `os.family=unknown`, warning, file-based collectors only |
| container, WSL, masked `/proc` | affected facts `unsupported` |
| another `collect` holds the lock | nothing written; exit 2 naming the PID and start time |
| low free space, output path is a symlink or in a world-writable directory, output exists without `--force` | nothing written; exit 2 |
| panic | top-level recover; exit 2; no snapshot |

Exit codes for `collect`: `0` complete snapshot; `1` snapshot written but incomplete (partial failures or denials); `2` no snapshot. `--require-complete` turns `1` into `2` (D11).

### 7.2 check

Input is untrusted. A snapshot that fails to parse, exceeds decode size or nesting limits, or has a higher `schema_version` produces no result and exit 2 (`schema_mismatch`). A lower version is read with missing keys as `missing` (section 5.2). A failing external control directory, or a waiver file with a missing reason, unknown key or no match field, is exit 2 (embedded controls cannot fail at runtime because CI lints them). A waiver naming an unknown control id is a warning recorded in the result.

Controls are isolated: a panic inside one control's evaluation (typically a custom function) makes that control `ERROR(internal_error)`; the rest are evaluated. The top-level recover is the last line and exits 2.

`ERROR` reasons are a fixed vocabulary — `permission_denied`, `timeout`, `truncated`, `unsupported_env`, `parse_error`, `missing_fact`, `schema_mismatch`, `walk_incomplete`, `internal_error` — carried in the JSON alongside the human text so CI can match on them. The summary always states how many facts failed to collect.

Exit codes for `check`: any `ERROR` → `2`; otherwise any `FAIL` → `1`; otherwise `0`. `--allow-error` reports errors but computes the exit code from failures alone (for snapshots known to be partial, such as non-root runs). `--fail-on` defaults to `fail`: `fail` exits 1 on any `FAIL`; `warn` and `manual` additionally exit 1 on `WARN` or `MANUAL`; `none` exits 0 for every finding status and leaves only the `ERROR` → 2 rule in force. The precedence `2 > 1 > 0` holds under every combination and is fixed by golden tests (D11).

### 7.3 Honest degradation

When a full judgment is impossible the engine — not the individual control — degrades to a status that cannot be mistaken for a clean pass (section 6.5, step 13): `sshd -T` unavailable → file parsing, judged, `WARN`; personas requested but not collected → judged against the global value, `WARN`; firewall normalisation confidence `partial` or `none` → `MANUAL` with the raw ruleset attached, never `FAIL`/`PASS`; NSS has a remote account source (sssd, ldap, winbind) → account controls `WARN` ("local files only"); an ACL present but unreadable → `ERROR` even if the mode is right; patch metadata cache stale → `WARN` with its age.

### 7.4 Channels

Result JSON goes to stdout and nothing else does; warnings, progress and `-v` logs go to stderr. No log files are ever written. A closed or failing stdout is exit 2. Table output escapes C0/C1 control characters, ANSI sequences and carriage returns in evidence values and truncates long values, because a snapshot from a compromised host is a normal input.

## 8. Security of the tool itself

muster runs as root on other people's production hosts, and its output is the most concentrated description of a host an attacker could ask for. The following are contracts, tested, not guidance (D14).

- **Commands.** Only commands registered in the collector registry run: absolute path, fixed arguments, per-command timeout, output cap. No shell. The environment is discarded and rebuilt (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`, `TZ=UTC`; `LD_PRELOAD`, `LD_LIBRARY_PATH` and `IFS` never inherited). Processes run in their own group so a timeout kills descendants.
- **Reads.** Every file read goes through one primitive with two tiers, and the tier used is recorded in the fact's `source`. Tier 1 is `openat2` with `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS` (Linux 5.6 and later — every first-release target), which refuses any symbolic link in any path component. Tier 2, for kernels or seccomp profiles that reject `openat2`, walks the path component by component with `openat(O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC)` from `/`, which gives the same guarantee. No tier follows a symlink anywhere in the path; `os.Root` is not used, because it follows links inside its root. After opening, `fstat` confirms a regular file (FIFOs, devices and sockets are refused); a size cap applies; a NUL byte marks the file binary and its content is not stored; a world-writable or non-root-owned parent sets `path_untrusted`.
- **Walk.** Off by default (`--deep`). Local filesystems only, decided from `/proc/self/mountinfo`: `nfs`, `cifs`, `smb3`, `fuse.*`, `sshfs`, `afs`, overlay and snap mounts are excluded; autofs mount points are not even `stat`ed; `/proc`, `/sys`, `/dev`, `/run` are skipped; no symlink is followed; a `(dev, ino)` set breaks cycles; a time and count budget ends the walk with `complete=false`; `nice`, and `ionice` where the I/O scheduler honours it, lower its priority.
- **Writes.** The snapshot is the only file `collect` ever writes. No service is restarted, no setting changed, no network connection made by any subcommand, no package metadata refreshed, no update check, no telemetry. CI runs `collect` in a network-less container on a read-only bind mount to prove it.
- **Data files.** Root never parses a control, waiver or old snapshot. `check` refuses writable data files when root and treats snapshots as hostile input (decode limits, no execution of anything it contains, no reuse of its paths as output paths, escaped rendering).
- **Snapshot confidentiality.** Redaction by default (section 5.6); 0600 in a 0700 directory; never `/tmp` by default; a lifecycle with a lock and retention (section 5.9). A `--anonymize` mode for sharing (stable hashing of hostnames, addresses and user names) arrives in stage 3 together with the invariant test that anonymised and original snapshots produce identical verdicts.
- **Limits stated, not implied.** `THREAT_MODEL.md` records the trust boundary and says plainly that a host already compromised (`LD_PRELOAD`, replaced binaries, reverted settings) can make muster report `PASS`; muster is not an intrusion detector. `SECURITY.md` gives the reporting path and supported versions.
- **Release integrity** (stage 4): reproducible static build (`CGO_ENABLED=0 -trimpath`, pinned Go), `checksums.txt`, GitHub artifact attestation (SLSA Build L2 stated as such), keyless cosign signature, SBOM, `govulncheck` in CI, deb and rpm packages, verification instructions before installation instructions, no `curl | sh`.

## 9. Output and UX contract

- Table output for humans; JSON for everything else; SARIF in stage 4.
- Same snapshot, same control set, same parameters → byte-identical JSON. Volatile values (time, host, durations, versions) live only under `run`. Results are sorted by severity then id. Locale and time zone do not affect output.
- **Severity** is `high`, `medium` or `low`, derived from KISA importance (상 → `high`, 중 → `medium`, 하 → `low`) until a profile overrides it in stage 3. It is the sort key, the `--severity` filter key (stage 2) and the SARIF level (stage 4).
- **Result provenance.** Every result carries the snapshot's `run` block unchanged, plus a `check` block: the evaluating binary's version and commit, its `controls_version` and `controls_digest`, the `snapshot_digest`, `waivers: {path, digest, applied, not_applied}`, and the parameter values in force.
- **Summary.** A summary block always precedes the table, in three parts: automatic verdicts by severity (`PASS`, `FAIL`, `WARN`), items under manual review (`MANUAL` and partial-control `WARN`), and undecidable items (`ERROR`, `NOT_APPLICABLE`, `WAIVED`) — followed by the count of facts that failed to collect and the waivers expiring within 30 days. There is no single hardening score; a ratio, if shown, states its denominator and excludes `MANUAL` and `NOT_APPLICABLE` (D18).
- `NO_COLOR`, `TERM=dumb` and a non-TTY disable colour and box drawing; `--no-color` / `--color=always` override. Korean item titles are laid out with East Asian width 2.
- `--quiet` shows `FAIL` and worse; `-v`/`-vv` show per-collector commands and timings. Filters `--only`, `--skip`, `--category`, `--severity` arrive in stage 2. Configuration files are deferred to v2; flags and environment variables are enough for v1.
- `muster collect --list-actions` prints, from the registry, every path read, every command run, the privilege each needs and the single path written, as a table or JSON. It is the document a change-control reviewer reads.
- `muster version` prints the binary version, commit, build date, control set version and guide edition.

## 10. Scope and staging

### 10.1 Classification rule

An item is classified by the kind of fact its judgment needs, not by its KISA category:

- **auto** — the judgment follows from collected facts.
- **partial** — the evidence is collected automatically but the final judgment is a human one (which accounts are unnecessary, which SUID files are legitimate). Violations are reported as `WARN` with the observation list, and the item is counted under manual review.
- **manual** — an interview or an external fact is required; evidence is attached.
- **deferred (service)** — the judgment needs a parser for a specific daemon's own configuration that v1 does not ship: mail (postfix, sendmail), DNS (bind), and FTP daemon configuration (vsftpd, proftpd). Items that read a plain file or a service state — `ftpusers`, telnet, NFS exports, `snmpd.conf` communities — are not deferred. In v1 the deferred items are enrolled as `manual` with the evidence muster can collect (installed, running, version string) and their `manual_reason` names the deferral.
- **not_applicable** — the mechanism does not exist on the supported platforms; the control says why.

Against the 2026 list this gives **51 auto, 7 partial, 9 deferred, 0 manual-only, 0 not-applicable** — 58 of 67 judged automatically in some form. The per-item table is appendix A; from stage 2 it is regenerated by joining the control set (ids, `automation`) with the reference inventory in `docs/reference/kisa/` (item names), and CI checks that the committed table matches.

### 10.2 Stages

**Stage 1 — skeleton.** `collect` and `check`; the facts schema with envelope, settings, registry and provenance; the read primitive, exec discipline and collector registry with `--list-actions`; the walk skeleton (`--deep` flag, boundaries, budget, `complete`) without the walk; table and JSON output with the determinism contract; exit codes; waivers; snapshot lifecycle (path, naming, lock); redaction policy; controls lint; fixture convention and registry test; result invariants; secret scanning of `testdata/`; the top-level recover guard; `THREAT_MODEL.md`, `SECURITY.md`, `ATTRIBUTION.md`; README pair. Five controls flow end to end, chosen to exercise the machinery, each with the minimum collector capability stage 1 must deliver:

- `U-01` (sshd, `mechanisms`, `persona`): `sshd -T` global values only, `personas_collected: false`, no include tracing — so the control evaluates and reports `WARN` (degraded) until stage 2 adds personas.
- `U-02` (password policy, two-home settings, `params`): `login.defs` and per-account `shadow` ageing fields; the pwquality clauses join in stage 2 with the PAM collector.
- `U-16` (`/etc/passwd`, permission fact): mode, owner, group and `acl_present` from the ACL xattr; ACL entries are parsed in stage 2, so a file with an ACL present is `FAIL` in stage 1 with the reason naming the unparsed ACL.
- `U-52` (Telnet, service normalisation, `absent_means: pass`): `systemctl show` for the mapped units and listening sockets from `/proc/net/tcp`; socket-activation and `masked`/`static` handling complete in stage 2.
- `U-25` (world-writable, walk, `each`, partial): judged only against synthetic fixtures in stage 1 — the walk that populates `walk.world_writable` arrives in stage 3, so on a real stage-1 snapshot U-25 is `MANUAL` ("run collect --deep"). Its purpose in stage 1 is to fix the `each`, observation and subject-waiver contracts.

**Stage 2 — both distributions, every automatable item.** Collectors complete: sshd (`-G` → `-T` → parse fallback with method recorded; Match personas; include sources), services (socket activation, masked/static/indirect, logical names), PAM (authselect / pam-auth-update / manual detection, stack expansion, derived pwquality and faillock with sources), firewall (backend detection, raw dumps, minimal normalised model with confidence), logging as a function (journald-only hosts), network sysctls with the kernel's per-parameter composition of `all` and per-interface values (maximum for `rp_filter`, logical OR for `send_redirects`, `accept_redirects` depending on that interface's forwarding) with `default` collected as the template for future interfaces and never folded into an effective value, and IPv6 pairs; the whole `/proc/sys` tree; MAC status (SELinux/AppArmor, runtime versus config); NSS remote-source detection; inetd/xinetd; banners; time synchronisation; `snmpd.conf` (versions enabled, communities redacted to default/length/source-restriction); patch hygiene from cached metadata; account state (hash algorithm, empty passwords); the `env` block; ACL entries. All 58 auto and partial items enrolled with fixtures; the 9 deferred items enrolled as manual with evidence. CI matrix (`ubuntu:22.04`, `ubuntu:24.04`, `rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, `debian:12` as a canary), `sudo muster collect` on the GitHub runner VM, the capability-matrix test, the non-root job. Coverage table generated and committed. Parser oracle tests. Example snapshots captured from public images. `snapshot extract`, `controls new`, `CONTRIBUTING.md`.

**Stage 3 — high-value checks beyond the list, from the same collector.** The walk itself, joined with package-declared permissions (`rpm -V` / `dpkg --verify`, noise filtered and the filter recorded); file capabilities and ACLs in the walk; kernel self-protection sysctls and the three-source core-dump policy; boot chain (grub.cfg permissions, Secure Boot state); mount options, separate partitions, swap encryption, module blacklists with built-in detection; audit pipeline health (auditd rules present and immutable, journald persistent, remote forwarding, sudo logging, a file-integrity tool installed and scheduled); exposure cross-check (socket → process → package versus firewall, only when firewall confidence is full); root-equivalent paths (container-runtime sockets and their groups, `ld.so.preload`, writable `ExecStart` of root units, root's `PATH`); dormant accounts; `sudoers` `NOPASSWD`/`ALL` beyond U-63's permission check; processes running deleted executables; `authorized_keys` inventory; `fix --dry-run` with risk ordering, backups, validation commands and rollback; tuning and profiles; `--anonymize` with its invariant test; `--max-age`; control YAML mutation testing; parser fuzzing.

**Stage 4 — public release.** Snapshot diff separating server changes from rule changes; SARIF with schema validation; the full bilingual documentation pair with a drift check; release integrity (section 8); `--controls-dir`; `snapshot ls|rm|prune` and timer units; install/upgrade/remove contract in the packages (remove keeps snapshots and warns, purge deletes them); DCO and a PR template that asks whether any benchmark text was copied; README positioning table and demo; the Lynis differential with a pinned version, `lynis-report.dat` parsing, a mapping table and per-image baselines, in the role of a coverage-gap detector.

### 10.3 Deferred to a later release

Per-service configuration items (mail, DNS, FTP daemon configuration — the 9 deferred items), multi-host aggregation, an agentless SSH mode, file-integrity baselines, certificate expiry, OS end-of-life detection, cloud VM items, ISMS-P and NIST mappings (the `references` keys are reserved), configuration files, kernel lockdown and command-line checks, Ansible output, APT/YUM repositories, Homebrew, Docker images, a check-only build for macOS and Windows.

### 10.4 Never

CVE matching, runtime detection, container and Kubernetes benchmarks, external port scanning, applying remediation, a single hardening score, CIS Benchmark text (D24).

## 11. Testing

The two lessons taken from assay are "the helper is covered; nothing calls it" and "guards that exist but are not held". Everything below moves them from discipline into CI.

**Control fixtures (primary).** Every control has `controls/testdata/<id>/{pass,fail,na}-*.json` — partial snapshots containing only the keys the control reads, cut from real snapshots with `muster snapshot extract`, each with a provenance header (image digest, capture date) or `synthetic: true`. A registry test walks all controls and fails CI when a `PASS` fixture, a `FAIL` fixture, a declared `NOT_APPLICABLE`/`ERROR` fixture, or a per-distribution fixture is missing. Coverage is measured as controls-with-fixtures over all controls (gate: 100 %) and as facts-used over facts-collected (report); Go line coverage is measured but gated only on `internal/check`.

**Result invariants.** `FAIL` and `WARN` carry a value and a reason; `MANUAL` carries evidence; no result exists without evidence; the status derivation table (section 6.5) and the exit code precedence hold for every fixture, whose expected exit code is part of its golden file.

**Contract tests (stage 1).** `internal/check` imports neither `os/exec` nor `net` (`go list -deps`). `collect` cannot read a path or run a command outside the registry (file and exec access sit behind interfaces the test replaces). The read primitive leaks nothing and never blocks on a pathological tree: symlink loops, a symlink to `/etc/shadow` in every path position, FIFOs, oversized files, names with newlines, a ten-thousand-entry directory. The snapshot writer honours 0600, atomicity and refusal to overwrite. The reflection schema golden and the old-snapshot corpus enforce section 5.7, including that a key added after a snapshot was taken reads as `missing` and yields `ERROR`, never `PASS`.

**Golden output and determinism.** Table and JSON renderers have `-update` golden tests; byte-identical output for identical input; volatile fields only under `run`; stable sort; locale and TZ independence; East Asian width, 40-column, `NO_COLOR` and non-TTY variants. SARIF is validated against the 2.1.0 schema in stage 4.

**Lint in CI (stage 1).** Section 6.8, plus `gitleaks` over `testdata/` from the first fixture commit with rules for private key blocks, `$6$`/`$y$` password hashes, `ssh-rsa AAAA` keys, and non-personal e-mail domains and internal-hostname shapes. The rule patterns themselves are generic; no organisation's name or domain is committed.

**Parser oracles (stage 2).** The correctness oracle is the daemon, not Lynis: parsers are compared value by value against `sshd -T`/`-G`, `sysctl -a`, `systemctl show -p` and `getent passwd` in container CI, with seed corpora taken from the CI images' real files.

**CI and capability matrix (stage 2).** Images as in section 10.2; `-race`, `gofmt`, `go vet`, `staticcheck`. The GitHub runner is a real VM with systemd and passwordless sudo, so `sudo muster collect` there yields sysctl and service facts without a local VM. Two tests matter most: a capability matrix that fixes, per environment, the facts that must be `unsupported` or `denied` and fails when a control depending on them passes; and a non-root job in which every unreadable fact must be `ERROR`. A container job succeeds not when many controls pass but when everything unseen is `ERROR` or `NOT_APPLICABLE` with a reason.

**Stage 3.** Mutation testing of control YAML (operator flip, expected-value substitution, clause removal, distribution-condition removal; 100 % kill rate with a documented exclusion list; gremlins on custom functions only). Native fuzzing of every parser with committed seed corpora, thirty seconds per parser on pull requests and longer nightly.

**Stage 4.** The Lynis differential as a coverage-gap detector with a pinned version, parsed `lynis-report.dat`, a mapping table and per-image baselines so only new disagreements are signal.

**Writing rules (to live in `CLAUDE.md`).** Write the test that drives the caller before the test of the helper. Delete each new call site and confirm the suite goes red; if it stays green the implementation is tested, not the feature. Assert something that differs when the call is gone. Prefer structural assertions to substrings.

**Not done.** No BDD framework, no global line-coverage gate, no benchmarks beyond the walk.

## 12. Documentation, licensing and contribution hygiene

- **Bilingual, English canonical.** Every user-facing document ships as `X.md` and `X.ko.md`, updated in the same commit; when they disagree, English is right. Implementation plans are English-only and deleted once their slice has merged. Identifiers, flags and paths stay English on both sides. Control text has per-language fields (`title_en`/`title_ko`, `description_en`/`description_ko`); KISA terms keep their Korean form with an English gloss (D22).
- **Attribution boundary.** `ATTRIBUTION.md` records the guide's publisher, edition, publication date, source URL and the copyright notice KISA states on its site, and then the boundary of section 3: only item codes, item names, categories, importance levels and page numbers are reproduced, as a cross-reference index; control titles, descriptions and rationale are original wording; no inspection, criterion or remediation text from the guide appears anywhere in the repository; the guide itself is not included; CIS references are benchmark name, version and recommendation number only; muster judges no CIS compliance. The README, the NOTICE file and `ATTRIBUTION.md` state this boundary in the same words so they cannot drift, and the README carries the "unofficial, not affiliated, not a substitute for an official assessment" notice (D04).
- **Checks that are not KISA items.** Stage 3 adds checks (mount options, module blacklists, kernel self-protection, audit pipeline health) that CIS-style benchmarks also cover. They are written from primary sources — kernel documentation, man pages, distribution documentation — in muster's own wording, carry no CIS recommendation number unless the mapping is independently derived, and reproduce no benchmark text. What the attribution boundary forbids is copying CIS's text and structure, not checking facts about a kernel.
- **License and identity.** Apache-2.0, `NOTICE` present. Commits use a personal identity; the repository's local git configuration pins it and a `.mailmap` documents it. Fixtures are captured only from public images; snapshots from any employer or customer host are never committed (D02).
- **Decision log.** Section 13 of this document is the decision log; a control may cite a decision with `decision: Dnn`. Contracts (facts schema, control ids, exit codes, waiver keys) change only with a decision entry.
- **Contribution.** From stage 2, `CONTRIBUTING.md` describes adding a control as `controls new` → fixtures → `controls lint` → `go test`. From stage 4, DCO sign-off and a pull-request template with the "no benchmark text copied" checkbox.
- **Corrections to the handoff notes.** The pre-repository notes described CIS material as "free to read, redistribution restricted"; the actual position is the two-source one in section 3. They also described the tool as "implementing the KISA guide"; public wording says muster *follows the structure and numbering of* the guide and is unaffiliated. They assumed the 2021 edition; the 2026 edition is followed instead, which removed the web items from the Unix scope.

## 13. Decision log

Each entry: what was decided, why, and what it would cost to reverse.

- **D01 — Separate from assay; decisions shared, code not.** assay stays a vulnerability scanner. Sharing `internal/` packages across modules would need a public API neither project wants yet. Reversal: extracting shared catalogers later is possible without touching either tool's contracts.
- **D02 — Personal, public, Apache-2.0, personal identity.** No company code, control definitions or hosts. The repository's local git identity is pinned to the author's personal GitHub address because a single employer-signed commit cannot be removed from history.
- **D03 — Linux only; Ubuntu 22.04/24.04 and Rocky/Alma 9 first.** Two families from the start force the adapter structure to exist. Reversal: none intended.
- **D04 — KISA 2026 edition; codes, names, categories and importance reproduced as an index; no guide text; CIS numbers only.** The 2026 edition renumbered everything and removed the web items; following 2021 would ship a stale numbering. The CC BY-NC-SA licence on non-member CIS Benchmarks and CIS's Terms of Use together forbid what an Apache-2.0 repository would otherwise do with them. KISA's site states an all-rights-reserved notice; the index reproduces only what an assessment reader needs to relate a result to the guide. Reversal of the edition choice: cheap, because ids are muster-native (D16).
- **D05 — Controls are data.** A control is YAML with twelve scalar operators and two collection operators; the vocabulary is deliberately too small to express everything, and the overflow goes to named Go functions that still read only facts. Reversal: adding operators is compatible; removing one is a control-format break.
- **D06 — Collect/check split; check is pure; no `command` in check.** Offline re-evaluation, fixture tests and the supply-chain boundary all depend on `check` never touching the host. The handoff's draft judgment type list included `command`; it was removed because a data file that runs root commands is a data file only in name. Reversal: would break every fixture and the threat model.
- **D07 — Unseen is unseen, enforced by the envelope.** Every fact carries a status; `absent`, `denied`, `unsupported`, `timeout`, `error`, `truncated` and the reader-side `missing` cannot produce `PASS` on their own. Go zero values would otherwise turn a missing key into a passing comparison. Reversal: a schema major bump.
- **D08 — Evidence in the result, as observations with source path and line.** Anything left to log lines effectively does not exist. Reversal: an output-contract break.
- **D09 — Distribution variance lives in the collector; removed mechanisms are control data.** `check` is distribution-blind; `mechanisms` orders alternatives per control. Reversal: none intended.
- **D10 — Runtime and persisted are both collected.** A setting safe now but not on disk, or on disk but not applied, is its own finding. Reversal: a schema major bump.
- **D11 — Exit codes.** `check`: any `ERROR` → 2 (opt out with `--allow-error`), any `FAIL` → 1, else 0; `--fail-on` raises `WARN`/`MANUAL`. `collect`: 0 complete, 1 partial, 2 none (`--require-complete`). Reversal: breaks other people's CI; fixed now.
- **D12 — Waivers are counted and reasoned, never silent; subject-level keys; never for `ERROR`.** Mandatory reason, optional inclusive expiry, strict keys, always shown in the summary; keyed by control or by observation subject; a waiver cannot turn an unread fact into a clean run. Reversal: none intended.
- **D13 — Snapshot confidentiality and lifecycle.** Derived attributes instead of secrets, 0600 in 0700, a standard directory, atomic writes, a lock, retention commands in stage 4. Reversal: cannot un-leak a snapshot; fixed before any snapshot exists.
- **D14 — Safe as root, tested.** Command whitelist, environment reset, timeouts, the two-tier read primitive that never follows a symlink, walk boundaries, snapshot-only writes, no network in any subcommand, no telemetry, no update checks. Reversal: none intended.
- **D15 — Controls embedded; external opt-in with digests.** The trust boundary at runtime is the binary; contributions arrive through pull requests. `--controls-dir` is a stage-4 addition and changes no contract.
- **D16 — muster-native control ids; control set versioned apart from the binary.** KISA numbers are references per edition. Reversal: an id change breaks every waiver file; ids are permanent once released.
- **D17 — Integer `schema_version`; higher refused, lower read with `missing`.** A key the snapshot does not carry is an error for the controls that need it, never a silent absence. Reversal: a schema major bump.
- **D18 — Status semantics, mandatory importance, derived severity, no single score.** `WARN`, `MANUAL`, `WAIVED`, `NOT_APPLICABLE` have fixed meanings and a fixed evaluation order; KISA importance is a required control field from which severity is derived; the summary has three parts. Reversal: an output-contract break.
- **D19 — Applicability is declared by the control.** `applies_when`, `absent_means`, environment facts; unknown distributions are `unknown`, not assumed. Reversal: compatible additions only.
- **D20 — Deterministic output.** Byte-identical JSON for identical input; volatile values only under `run`. Reversal: would break snapshot diff.
- **D21 — Testing shape.** Fixtures per control are mandatory; invariants and contract tests are in CI from stage 1; the parser oracle is the daemon; Lynis is a coverage-gap detector. Reversal: none intended.
- **D22 — Bilingual documentation, English canonical.** Same-commit rule; plans English-only and deleted after merge; control text per language.
- **D23 — v1 artifacts are Linux; the check side compiles anywhere.** Build tags keep `collect` Linux-only so a workstation build is a packaging decision, not a refactor.
- **D24 — Scope boundaries.** Classification by kind of fact; the deferred list; the never list. The web items are no longer a Unix concern in the 2026 edition.
- **D25 — Non-root is a first-class path.** `denied` facts, `ERROR` with the privilege named, `--require-root` for CI; `check` never needs root.
- **D26 — Permission facts include ACLs, capabilities and attributes.** `st_mode` alone gives silently wrong answers.
- **D27 — Patch hygiene uses cached package metadata only.** `collect` never refreshes package metadata or holds a package-manager lock; a stale cache is a `WARN` with its age.
- **D28 — Go, minimal dependencies, no CLI framework, one static binary.** The same choice as assay, for the same reasons: a single file to copy onto an air-gapped host, no runtime, and a dependency list short enough to audit. Reversal: none intended.

## 14. Open points

- U-17's mapping (split from 2021 U-14 versus new) is recorded as uncertain in `docs/reference/kisa/kisa_mapping.json`; it does not affect the control, only its 2021 reference.
- Whether example snapshots for the README are captured from the GitHub runner VM or from the CI containers is a stage 2 choice; both carry provenance.
- The set of collectors enabled without `--deep` on a first run is tuned in stage 2 against measured run time on the CI images; the budget defaults in section 7.1 are starting values.

## Appendix A — KISA 2026 Unix items and their v1 classification

Legend: auto — judged from facts; partial — evidence automatic, judgment human (`WARN` on violations); deferred — daemon configuration parser not in v1, enrolled as `manual` with evidence. Item codes and names are reproduced from the guide as a cross-reference index (section 3); muster's own titles and descriptions live in the controls.

| ID | Item name (KISA) | Imp. | v1 |
|---|---|---|---|
| U-01 | root 계정 원격 접속 제한 | 상 | auto |
| U-02 | 비밀번호 관리정책 설정 | 상 | auto |
| U-03 | 계정 잠금 임계값 설정 | 상 | auto |
| U-04 | 비밀번호 파일 보호 | 상 | auto |
| U-05 | root 이외의 UID가 '0' 금지 | 상 | auto |
| U-06 | 사용자 계정 su 기능 제한 | 상 | auto |
| U-07 | 불필요한 계정 제거 | 하 | partial |
| U-08 | 관리자 그룹에 최소한의 계정 포함 | 중 | partial |
| U-09 | 계정이 존재하지 않는 GID 금지 | 하 | auto |
| U-10 | 동일한 UID 금지 | 중 | auto |
| U-11 | 사용자 Shell 점검 | 하 | auto |
| U-12 | 세션 종료 시간 설정 | 하 | auto |
| U-13 | 안전한 비밀번호 암호화 알고리즘 사용 | 중 | auto |
| U-14 | root 홈, 패스 디렉터리 권한 및 패스 설정 | 상 | auto |
| U-15 | 파일 및 디렉터리 소유자 설정 | 상 | auto (walk) |
| U-16 | /etc/passwd 파일 소유자 및 권한 설정 | 상 | auto |
| U-17 | 시스템 시작 스크립트 권한 설정 | 상 | auto |
| U-18 | /etc/shadow 파일 소유자 및 권한 설정 | 상 | auto |
| U-19 | /etc/hosts 파일 소유자 및 권한 설정 | 상 | auto |
| U-20 | /etc/(x)inetd.conf 파일 소유자 및 권한 설정 | 상 | auto |
| U-21 | /etc/(r)syslog.conf 파일 소유자 및 권한 설정 | 상 | auto |
| U-22 | /etc/services 파일 소유자 및 권한 설정 | 상 | auto |
| U-23 | SUID, SGID, Sticky bit 설정 파일 점검 | 상 | partial (walk) |
| U-24 | 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 | 상 | auto |
| U-25 | world writable 파일 점검 | 상 | partial (walk) |
| U-26 | /dev에 존재하지 않는 device 파일 점검 | 상 | auto |
| U-27 | $HOME/.rhosts, hosts.equiv 사용 금지 | 상 | auto |
| U-28 | 접속 IP 및 포트 제한 | 상 | auto (mechanisms; `MANUAL` when firewall confidence is partial) |
| U-29 | hosts.lpd 파일 소유자 및 권한 설정 | 하 | auto |
| U-30 | UMASK 설정 관리 | 중 | auto |
| U-31 | 홈 디렉토리 소유자 및 권한 설정 | 중 | auto |
| U-32 | 홈 디렉토리로 지정한 디렉토리의 존재 관리 | 중 | auto |
| U-33 | 숨겨진 파일 및 디렉토리 검색 및 제거 | 하 | partial (walk) |
| U-34 | Finger 서비스 비활성화 | 상 | auto |
| U-35 | 공유 서비스에 대한 익명 접근 제한 설정 | 상 | deferred |
| U-36 | r 계열 서비스 비활성화 | 상 | auto |
| U-37 | crontab 설정파일 권한 설정 미흡 | 상 | auto |
| U-38 | DoS 공격에 취약한 서비스 비활성화 | 상 | auto |
| U-39 | 불필요한 NFS 서비스 비활성화 | 상 | auto |
| U-40 | NFS 접근 통제 | 상 | auto |
| U-41 | 불필요한 automountd 제거 | 상 | auto |
| U-42 | 불필요한 RPC 서비스 비활성화 | 상 | auto |
| U-43 | NIS, NIS+ 점검 | 상 | auto |
| U-44 | tftp, talk 서비스 비활성화 | 상 | auto |
| U-45 | 메일 서비스 버전 점검 | 상 | deferred |
| U-46 | 일반 사용자의 메일 서비스 실행 방지 | 상 | deferred |
| U-47 | 스팸 메일 릴레이 제한 | 상 | deferred |
| U-48 | expn, vrfy 명령어 제한 | 중 | deferred |
| U-49 | DNS 보안 버전 패치 | 상 | deferred |
| U-50 | DNS Zone Transfer 설정 | 상 | deferred |
| U-51 | DNS 서비스의 취약한 동적 업데이트 설정 금지 | 중 | deferred |
| U-52 | Telnet 서비스 비활성화 | 중 | auto |
| U-53 | FTP 서비스 정보 노출 제한 | 하 | deferred |
| U-54 | 암호화되지 않는 FTP 서비스 비활성화 | 중 | auto |
| U-55 | FTP 계정 Shell 제한 | 중 | auto |
| U-56 | FTP 서비스 접근 제어 설정 | 하 | auto |
| U-57 | Ftpusers 파일 설정 | 중 | auto |
| U-58 | 불필요한 SNMP 서비스 구동 점검 | 중 | auto |
| U-59 | 안전한 SNMP 버전 사용 | 상 | auto |
| U-60 | SNMP Community String 복잡성 설정 | 중 | auto |
| U-61 | SNMP Access Control 설정 | 상 | auto |
| U-62 | 로그인 시 경고 메시지 설정 | 하 | partial |
| U-63 | sudo 명령어 접근 관리 | 중 | auto |
| U-64 | 주기적 보안 패치 및 벤더 권고사항 적용 | 상 | partial |
| U-65 | NTP 및 시각 동기화 설정 | 중 | auto |
| U-66 | 정책에 따른 시스템 로깅 설정 | 중 | auto |
| U-67 | 로그 디렉터리 소유자 및 권한 설정 | 중 | auto |

Totals: auto 51, partial 7, deferred 9.
