# muster

*English · [한국어](README.ko.md)*

**Does this Linux server pass muster?** `muster` collects the facts of a host as
root, then evaluates them — offline, from the snapshot alone — against the Unix
server items (U-xx) of the KISA technical vulnerability assessment guide for
critical information infrastructure, with CIS Benchmark, DISA STIG and NIST SP
800-53 numbers attached as cross-references where a mapping is filed.

In Korean security practice this kind of check is called a CCE assessment
(configuration vulnerabilities, as opposed to CVE). muster is a CCE checker for
the Linux server asset class: KISA is the primary standard, and global
benchmarks (CIS Benchmarks, DISA STIG, NIST SP 800-53) are attached as
references and, later, offered as selectable profiles.

> **Status: stage 2 complete (September 2026).** Stage 1 — the skeleton:
> `collect`, `check`, waivers, exit codes, eight controls end to end — and
> stage 2 — every automatable KISA item — are merged: the foundations with
> DISA STIG and NIST SP 800-53 references, accounts, the PAM stacks, the
> completed sshd collector with login banners, home directories and the shell
> environment, system-file, startup and cron permissions, services and
> super-servers, the firewall, logging and time synchronisation, NFS, SNMP and
> patch hygiene, FTP, mail and DNS, and the closing coverage-and-reference
> gate. 64 of the 67 items are enrolled; the three that need the deep
> filesystem walk (U-15, U-23, U-33) are deferred to stage 3, and U-25
> (world-writable files) is enrolled but reads `MANUAL` until that same walk
> lands. Which item is judged by which control, with its automation class, and
> which fact keys the controls read is generated into
> [the coverage table](docs/reference/coverage.md) and checked by CI, which
> also runs the collector as root on a VM, as a normal user, inside Ubuntu
> 22.04/24.04 and Rocky/Alma 9 containers (with Debian 12 as a non-blocking
> canary), in a read-only container without a network, and against
> [a capability matrix](docs/reference/capability-matrix.json) of facts that
> must read `denied` without root and `unsupported` without systemd. The
> architecture, contracts and release scope are written up in
> [the design specification](docs/superpowers/specs/2026-09-02-muster-design.md);
> changes that alter a verdict are recorded in [CHANGELOG.md](CHANGELOG.md).
> The stage-3 and stage-4 items below are the plan, not a promise.

> **Not affiliated.** muster is an unofficial personal project. It is not
> endorsed by KISA or by the Center for Internet Security, it contains no CIS
> Benchmark text (only recommendation numbers), it does not claim any level of
> CIS compliance, and it does not replace an official vulnerability assessment.

## What it does

```
sudo muster collect --out host.json      # on the host, as root: facts snapshot
muster check --facts host.json           # anywhere, no root: table + exit code
muster check --facts host.json --format json
muster controls lint --references docs/reference   # the control set's own gate
```

- **`collect`** runs on the host and writes one JSON snapshot: the OS release
  and environment, the package list, effective `sshd` settings (with the
  `Match` personas), the PAM stacks and the policy derived from them, service,
  socket and super-server state, listening sockets, the firewall backend and
  its rules, accounts and password policy, home directories and the shell
  environment, login banners, the permissions of system files, startup scripts,
  cron entries and `sudoers`, logging and time synchronisation, NFS exports,
  SNMP (with
  communities reduced to their shape, never the string), patch state, and FTP,
  mail and DNS configuration. It writes nothing else, restarts nothing, and
  never touches the network.
- **`check`** reads a snapshot plus a control set and reports, per control:
  `PASS`, `FAIL`, `WARN`, `MANUAL`, `NOT_APPLICABLE`, `ERROR` or `WAIVED`,
  always with the evidence that produced the verdict (the value, the file and
  line it came from, the reason). It does not need the host.
- **Controls are data.** Each KISA item is a YAML control with a small judgment
  vocabulary; an item that cannot be expressed that way can call a named Go
  function, and today none needs to. Distribution differences are absorbed in
  the collector, so a control is written once against normalized facts.
- **Waivers** live in a file with a mandatory reason and an optional expiry.
  A waived finding is counted and shown, never silently dropped, and a waiver
  never covers an `ERROR`.
- **Exit codes** are a contract: `2` (could not run or cannot be trusted)
  outranks `1` (findings) outranks `0` (clean). `MANUAL` items do not fail the
  run unless you ask them to.

## Principles

- **Unseen is unseen.** A fact that could not be read is `ERROR`, never a quiet
  `PASS`. Half a check is not a `PASS` either: items that need an interview are
  reported as `MANUAL` with whatever evidence was collected, and so is a host
  whose layout muster declined to read (a home outside the usual roots, a
  configuration construct outside the parser's model) — named in the reason,
  never guessed.
- **Evidence rides in the result.** If the reason for a verdict only exists in a
  log line, it effectively does not exist.
- **Runtime and persisted are both checked.** A firewall whose kernel ruleset is
  live but whose configuration on disk would not bring it back, a password
  policy that differs between `login.defs` and the running PAM stack, or a
  service that is `enabled` but socket-activated, is reported as what it is,
  not folded into one boolean.
- **Safe to run as root.** No shell, a fixed whitelist of commands with absolute
  paths and timeouts, no symlink following, a size cap on every file read, and a
  snapshot that stores derived attributes (hash algorithm, machine-id hash, an
  SNMP community's length and whether it is a default) rather than secrets.
  `muster collect --list-actions` prints exactly what the collector reads and
  runs.

## What it deliberately does not do

- **CVE matching.** The snapshot carries the installed package list so it can be
  handed to a vulnerability scanner such as [assay](https://github.com/kun9497/assay)
  as an SBOM; muster itself never matches advisories.
- **Runtime detection** (eBPF, process monitoring) — tools like Tetragon exist.
- **Container and Kubernetes benchmarks** — kube-bench exists.
- **External port scanning.** Network checks are host-internal only: listening
  sockets, firewall rules, unnecessary services.
- **Applying fixes.** Every judged control carries its remediation text, risk
  level and rollback, so a script can be generated for review later; muster
  never executes one.
- **Other asset classes.** Windows, DBMS, web/WAS, network and security devices
  have their own sections of the KISA guide. They would be sibling tools sharing
  muster's control and report contracts, never part of this codebase.

## Targets

Linux only, permanently. The first release targets **Ubuntu LTS (22.04, 24.04)**
and **Rocky / AlmaLinux 9**; supporting both from the start forces the
distribution-variance structure to exist rather than be retrofitted.

## Standards

The control set follows the structure and numbering of the Unix server section
of the **2026 edition** of the KISA guide (주요정보통신기반시설 기술적 취약점
분석·평가 방법 상세가이드, published 2025-12-24): 67 items, U-01–U-67. Every
control carries its KISA item number per edition, including the 2021 number
where the 2021 edition had the item, so older assessments can still be related
to a result.

From the guide, this repository reproduces only item codes, item names,
categories, importance levels and page numbers, as a cross-reference index
(`docs/reference/kisa/`). Control titles, descriptions and rationale are
muster's own wording; no inspection, criterion or remediation text from the
guide is included, and the guide itself is not included. CIS Benchmark
references are benchmark name, version and recommendation number only, and
muster judges no CIS compliance. See [ATTRIBUTION.md](ATTRIBUTION.md).

Global benchmarks are cross-references, not a second rulebook. Of the 64
controls, 25 carry DISA STIG rule ids, 20 carry NIST SP 800-53 control ids and
13 carry CIS Benchmark recommendation numbers; the mappings are still being
filled in, and a control gets one only where the benchmark judges the same
criterion. `muster controls lint` refuses a STIG or
NIST id that is not in the committed index and cross-checks every KISA item
number against the 67-item inventory, so an item can be neither forgotten nor
claimed twice. From stage 3 a `cis-<distro>-l1`
profile can select controls and parameters from the same collector. muster records the
numbers, never the benchmark text, and certifies no level of CIS or STIG
compliance. The STIG and NIST identifiers a control may cite are generated
into `docs/reference/stig/` from DISA's public files by `tools/refindex`.
This repository reproduces only STIG and CCI identifiers, severities and
titles, never their discussion, check and fix text. See
[ATTRIBUTION.md](ATTRIBUTION.md).

## Roadmap

1. **Skeleton.** `collect` and `check`, the facts schema, table and JSON
   output, exit codes, waivers, and eight controls flowing end to end.
2. **Both distributions, every automatable KISA item.** Collectors for Ubuntu
   and Rocky; 64 of the 67 items judged automatically or with automatic
   evidence (55 auto, 5 partial, 4 manual with the evidence attached). The
   remaining three — file and directory ownership (U-15), SUID/SGID/sticky
   files (U-23) and hidden files (U-33) — need the deep filesystem walk of
   stage 3 and are listed as deferred in `docs/reference/coverage.md`. Every
   control gains DISA STIG and NIST SP 800-53 reference numbers where a
   mapping exists, and `controls lint` cross-checks every KISA reference
   against the 67-item inventory.
3. **The deep filesystem walk, high-value checks beyond the list, and
   profiles**, from the same collector: the walk that enrols the three deferred
   items (file ownership, SUID/SGID/sticky files, hidden files), package
   integrity, world-writable files, file capabilities
   and ACLs, cron and timer inventory, `authorized_keys` inventory, processes
   running deleted binaries, kernel self-protection sysctls, mount options,
   audit pipeline health, patch hygiene, exposure of listening sockets versus
   firewall rules. Profiles select controls and parameters: `kisa-unix-2026`
   stays the default, and a `cis-<distro>-l1` profile covers the CIS Level 1
   server recommendations for the target distributions, with `references.cis`
   as those controls' primary reference.
4. **Public release.** Snapshot diff, SARIF, bilingual docs, signed reproducible
   builds with SBOM, deb/rpm packages, and a differential comparison against
   Lynis.

Deferred to a later release: multi-host aggregation, an agentless SSH mode, an
ISMS-P mapping, file-integrity baselines, certificate expiry, OS end-of-life
detection, cloud VM items.

## Documents and contributing

- [CONTRIBUTING.md](CONTRIBUTING.md) — adding a control (`muster controls new`
  scaffolds it, `muster snapshot extract` cuts its fixture out of a snapshot),
  adding a fact, the collector conventions, the test discipline, and what
  must never be committed.
- [CHANGELOG.md](CHANGELOG.md) — the control set's version and every change
  that alters a verdict.
- [docs/reference/coverage.md](docs/reference/coverage.md) — which KISA item
  is judged by which control, and which fact keys the controls read; generated,
  checked by CI.
- [docs/reference/kisa/](docs/reference/kisa/) — the item inventory and the
  deferred items; [docs/reference/stig/](docs/reference/stig/) — the STIG and
  NIST identifiers a control may cite.
- [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md),
  [ATTRIBUTION.md](ATTRIBUTION.md).

## Relationship to assay

[assay](https://github.com/kun9497/assay) is a vulnerability scanner; muster is a
configuration checker. They share decisions (evidence in the result, the exit
code contract, waiver rules, per-distribution logic kept separate), not code.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
