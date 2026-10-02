# Stage 3C-2b — exposure: what is actually reachable, and who is serving it

**Status:** design, approved in conversation on 2026-10-02; the Korean pair is
`2026-10-02-stage3c2b-exposure-design.ko.md`. Parent: `2026-09-02-muster-design.md` (D01–D31;
this stage adds D32). Predecessors: 3C-1 (`2026-09-23-stage3c1-audit-integrity-design.md`) and
3C-2a (`2026-09-29-stage3c2a-privilege-design.md`), whose §8 parked the items this stage takes.

## 1. Scope and intent

The guide asks whether unnecessary services run (U-52's socket table) and whether a firewall
exists (U-28). Neither says what a host actually offers to the network: which listening
sockets a packet from off the host can reach through the firewall as configured, which process
answers on each, and whether that process is something the package manager put there. 3C-2b
reads that join and judges it as read: a listener reachable from off the host must be on the
host's own allow list, a listener must belong to a package, and no process may run an
executable that is no longer the file on disk. Beside the join, the kernel's network sysctls —
the knobs that decide whether the host forwards, honours ICMP redirects and source routes, and
filters spoofed source addresses — join the `sysctl` collector of 3B.

Decisions settled in the brainstorm (X-1 … X-6):

- **X-1 — scope.** The "exposure" set: a process collector, processes running deleted
  executables, the exposure cross-check against the firewall, the network sysctls. Out: the join
  of `packages.verify.modified` with the walk's package table (3C-1 §8, stays parked),
  `fix --dry-run`, profiles and the CIS reference (3D), `--anonymize`, `--max-age` (3E).
- **X-2 — three controls on the join.** An exposed listener not on the allow list FAILs; a
  listener whose executable belongs to no package FAILs; a process running a deleted executable
  FAILs. Each is judged as read and relaxed only through `params` or a waiver (D31's
  philosophy).
- **X-3 — the process collector reads as much as it may.** Every pid is enumerated; a process
  whose `exe` or `fd` directory the run cannot read is a row with `denied`, and a judged leaf
  that would have to omit such a row is `denied` itself. Root reads everything; a non-root run
  reads its own processes and ERRORs the three controls (the `nonroot.denied` row). No deep gate.
- **X-4 — the package index is built in every collect.** The dpkg lists or the fixed rpm query
  the walk already uses, extracted into a package the walk and the process collector share and
  built once when both run; cost measured and bounded.
- **X-5 — six network-sysctl controls**, one per topic, each judging `all` and `default` and
  both sides of the setting; forwarding is read as it is (a docker host FAILs and relaxes through
  a parameter).
- **X-6 — "reachable through the firewall".** At full normalisation confidence: every
  non-loopback listener when inbound is not restricted; otherwise a listener whose protocol and
  port match an accept rule, whatever the rule's source (the source is recorded, and a
  management port opened to one subnet is still a service reachable from off the host). An
  accept rule the normalisation cannot express as "protocol and port" — one that selects on an
  interface, a connection state or anything else the rule table does not carry — makes the
  host's exposure verdict MANUAL (X-6's safeguard), as does partial confidence.

## 2. Architecture

Two collectors change and none is added to the sorted run list:

- **`processes` (new)** — enumerates `/proc`, joins each listening socket of the host with its
  owning process (the `/proc/<pid>/fd` links), joins each executable with the package index,
  and — because the firewall collector has already run (collectors run in name order,
  `firewall` < `processes`, and a test pins that order) — derives the `exposure.*` facts from the
  firewall's normalised rules. It writes three families: `processes.*`, `exposure.*` and nothing
  else. The `Builder` gains one read accessor, `Get(key) (facts.Envelope, bool)`, so a collector
  can read a fact an earlier collector wrote; nothing else about the builder changes.
- **`sysctl` (3B, extended)** — gains twenty-three `net.sysctl.*` keys, read exactly as the
  kernel ones are (B-3: `/proc/sys` for the runtime side, the `sysctl.d` chain for the persisted
  side, no command).
- **`firewall` (2H, one record field)** — each `firewall.rules` row gains `family` (`v4`, `v6`
  or `inet`), which the parser already knows per dump and per nft table; a record field keeps
  `schema_version` (C2).
- **`pkgindex` (new internal package)** — the dpkg list reader (`/var/lib/dpkg/info/*.list`,
  `statoverride`, the postinst name) and the rpm file-table query the walk's join uses today
  move here unchanged; the walk's join and the process collector call it. The extraction is a
  behaviour-preserving refactor and the first task of the plan.

The evaluator does not change except where §7 says (a `where` field op is already present).
The report's `scopes.beyond` count grows by thirteen. The exit code is unchanged.

## 3. Facts

### P-1 `processes.*`

Declaration: `Reads` `/proc/[0-9]*/status`, `/proc/[0-9]*/cmdline`, `/proc/[0-9]*/exe`,
`/proc/[0-9]*/fd`, `/proc/[0-9]*/fd/*` (never `/proc/self` or `/proc/thread-self`; a pid read
through `/proc/self` would be the collector's own), plus the package index's declaration
(`/var/lib/dpkg/info/*.list`, `/var/lib/dpkg/statoverride`, the fixed `rpm -qa --qf` query)
and the socket tables `/proc/self/net/{tcp,udp,tcp6,udp6}` (the same four files `sockets` and
`services` read — R232: the table is read once per collector, never per socket). `Needs: none`.
`exe` and `fd/*` are read with `Readlink` only; the link target is never opened.

Enumeration: every numeric entry of `/proc` (threads under `task/` are not entries of `/proc`;
a pid that vanishes between listing and reading leaves no row and increments
`processes.stats.vanished`). Per process: `status` gives `Name`, `PPid` and the real `Uid`;
`cmdline` gives the first NUL-separated token (capped at 4 KiB; a kernel thread has an empty
`cmdline`); `exe` gives the link target. A kernel thread — `exe` ENOENT with an empty `cmdline`
— is a row with `kind: kernel` and is judged by nothing.

- `processes.list` — `list<record>` `{pid, ppid, uid, name, cmd, exe, exe_deleted,
  exe_read_status, kind, package, package_status}`, sorted by `pid`, capped at 4096 rows
  (`truncated: true` past it; the counts below still see every process). `exe_deleted` is true
  when `readlink` returned a target ending in ` (deleted)` — `proc(5)`'s own notation for an
  executable unlinked or replaced since exec; an upgraded daemon not yet restarted and a binary
  removed from disk after it started read the same. `exe_read_status` is `ok`, `denied` (another
  account's process in a non-root run, EACCES) or `error`. `kind` is `user` or `kernel`.
  `package` is the index's owner of the `exe` path (` (deleted)` stripped first; a deleted
  executable's path may still be owned — the row says `package_status: deleted` then), and
  `package_status` is `packaged`, `unpackaged`, `deleted` or `no_index` (the index could not be
  built — the leaf below carries the index read's status). `sensitivity: internal` (command
  names and paths).
- `processes.deleted_executables` — `list<record>` `{pid, uid, name, exe}`: the judged subset
  (C2). When any user-kind process's `exe` could not be read, the leaf is that read's status
  (`denied` in a non-root run), never the subset of what was readable — a PASS on the processes
  the run could see would be a PASS on evidence not read.
- `processes.listeners` — `list<record>` `{proto, addr, port, loopback, inode, pid, uid, name,
  exe, package, package_status, owner_status}`: every listening socket of the host (the same
  rows `sockets.listening` lists, re-read here) with its owning process found through
  `/proc/<pid>/fd/*` links of the form `socket:[<inode>]`. `owner_status` is `ok`, `unmatched`
  (every `fd` directory was read and no process holds the inode — a socket in another network
  namespace, or one closed between the two reads) or `denied` (an `fd` directory could not be
  read, so the owner may be a process the run could not see); `pid` is -1 on the last two. When
  any `fd` directory was `denied`, the leaf itself is `denied`. Capped at 2000 rows; sorted by
  `proto`, `port`, `addr`.
- `processes.unpackaged_listeners` — `list<record>` `{pid, name, exe, proto, addr, port,
  reason}`: the judged subset — listeners, loopback included, whose executable the index does
  not own (`reason: unpackaged`) or whose executable is deleted (`reason: deleted` — the file
  that answers is not the file the package shipped). The index's read status when it could not
  be built; `denied` as `processes.listeners` is.
- `processes.stats` — record `{count, kernel_threads, denied, vanished, index_source, index_ms,
  fd_reads, elapsed_ms}`; `index_source` is `dpkg`, `rpm` or `none`.

Budgets: at most 4096 `fd` entries per process (past it the process's sockets are matched from
what was read and `owner_status` of an unmatched socket stays `unmatched`), 5 s for the whole
enumeration (past it `processes.list` is `truncated` and the judged leaves carry
`truncated: true`, which the evaluator reads as `ERROR(truncated)`). The package index is
bounded as the walk bounds it today.

Statuses (C3/C4): a masked `/proc` (`ErrProcfsMasked`, the `sockets` collector's test) is
`unsupported` on every `processes.*` key; `/proc/<pid>/exe` or `fd` EACCES is the row's
`exe_read_status`/`owner_status` and the judged leaves' `denied`; an index that cannot be built
(dpkg lists denied, the rpm query failing) puts that read's status on
`processes.unpackaged_listeners` and `package_status: no_index` on every row.

### P-2 `exposure.*` (written by `processes`)

Inputs: `processes.listeners` (above) and the firewall collector's facts, read through
`Builder.Get`: `firewall.normalization_confidence`, `firewall.restricts_inbound`,
`firewall.rules`, `firewall.backend`. A test pins that `firewall` sorts before `processes`;
should a future collector break the order, `exposure.*` reads `error` naming the missing fact.

Rule classification — every `firewall.rules` row whose `action` is accept is classed:

- `port_rule`: `proto` is `tcp` or `udp` and `dport` is a port, a range `a-b` or a set
  `{a, b, c}` the parser can enumerate (a set of at most 256 ports; a named set is `opaque`);
- `any_port`: `proto` and `dport` are both empty — an accept of everything the chain sees;
- `opaque`: anything else — an accept whose selector the rule table does not carry (interface,
  connection state, ICMP type, a named set, an address-only match with no port).

Exposure, decided only at `normalization_confidence: full` with no `opaque` rule in an input
chain of the listener's family:

- `restricts_inbound: false` → every non-loopback listener is exposed, `via: open_policy`;
- `restricts_inbound: true` → a listener is exposed when an `any_port` rule exists in its
  family (`via: any_port_rule`) or a `port_rule` matches its protocol and port
  (`via: rule`, the rule's `chain` and `saddr` recorded); otherwise `filtered`.
- A socket bound to `0.0.0.0` or `::` is a candidate in its family; `::` is also a v4 candidate
  (dual-stack binding, the kernel's default `bindv6only=0`); a specific address is a candidate
  unless loopback (`127.0.0.0/8`, `::1`) or link-local (`fe80::/10`, `169.254.0.0/16`), which
  are recorded and never exposed. A `firewall.rules` row without `family` (an older snapshot)
  applies to both families.

Keys:

- `exposure.listeners` — `list<record>` `{proto, addr, port, service, pid, name, exe, package,
  exposed, via, rule_chain, rule_source, reason}` for every non-loopback listener; `service` is
  `"<proto>/<port>"` (`tcp/22`), the string the allow list names; sorted by `proto`, `port`,
  `addr`. Evidence.
- `exposure.exposed` — `list<record>` `{service, proto, addr, port, pid, name, package, via,
  rule_chain, rule_source}`: the exposed subset (judged). `absent` naming the cause when the
  verdict cannot be read — `normalization confidence is partial`, `opaque accept rule in
  <chain>: <raw>` — so the control is MANUAL; the firewall read's status (`unsupported`,
  `denied`) when the firewall could not be read; `denied` when `processes.listeners` is.
- `exposure.opaque_rules` — `list<record>` `{chain, family, action, raw}`: evidence of what
  stopped the verdict.
- `exposure.stats` — record `{listeners, exposed, filtered, loopback, link_local, opaque_rules,
  confidence}`.

A host with no firewall (`firewall.backend: none`) has `restricts_inbound: false` at full
confidence, so every non-loopback listener is exposed and the control FAILs beside U-28: the two
say cause and consequence, and the descriptions say so.

### P-3 `net.sysctl.*` (the `sysctl` collector)

Twenty-three `setting<int>` keys, `default_on: effective` (= runtime, B-3), each with the two
homes of `sysctl.d` as its persisted side, `since: 1`:

| key | sysctl |
|---|---|
| `ipv4_ip_forward` | `net.ipv4.ip_forward` |
| `ipv6_all_forwarding` | `net.ipv6.conf.all.forwarding` |
| `ipv4_all_accept_redirects`, `ipv4_default_accept_redirects` | `net.ipv4.conf.{all,default}.accept_redirects` |
| `ipv4_all_secure_redirects`, `ipv4_default_secure_redirects` | `net.ipv4.conf.{all,default}.secure_redirects` |
| `ipv4_all_send_redirects`, `ipv4_default_send_redirects` | `net.ipv4.conf.{all,default}.send_redirects` |
| `ipv6_all_accept_redirects`, `ipv6_default_accept_redirects` | `net.ipv6.conf.{all,default}.accept_redirects` |
| `ipv4_all_accept_source_route`, `ipv4_default_accept_source_route` | `net.ipv4.conf.{all,default}.accept_source_route` |
| `ipv6_all_accept_source_route`, `ipv6_default_accept_source_route` | `net.ipv6.conf.{all,default}.accept_source_route` |
| `ipv4_all_rp_filter`, `ipv4_default_rp_filter` | `net.ipv4.conf.{all,default}.rp_filter` |
| `ipv4_all_log_martians`, `ipv4_default_log_martians` | `net.ipv4.conf.{all,default}.log_martians` |
| `ipv4_icmp_echo_ignore_broadcasts` | `net.ipv4.icmp_echo_ignore_broadcasts` |
| `ipv4_icmp_ignore_bogus_error_responses` | `net.ipv4.icmp_ignore_bogus_error_responses` |
| `ipv4_tcp_syncookies` | `net.ipv4.tcp_syncookies` |
| `ipv6_all_accept_ra`, `ipv6_default_accept_ra` | `net.ipv6.conf.{all,default}.accept_ra` |

`all` applies to every interface now, `default` to every interface created later
(`ip-sysctl.rst`); a host whose `all` is tight and `default` loose gives a new interface — a
container's veth, a VPN — the loose value, so both are judged. Per-interface values are not
collected (§8). A kernel without IPv6 (`/proc/sys/net/ipv6` absent) makes every `ipv6_*` key
`absent` with the reason "IPv6 is not built or is disabled", and the controls read that as
NOT_APPLICABLE (§4).

## 4. Controls

Thirteen `category: beyond` controls, ids `muster.beyond.<name>` under `controls/beyond/`,
every one gated on `env.container eq none` (a container's processes, firewall and network
namespace are not the host's policy), `automation: auto`. Importance is muster's own rating from
the primary source named in each description.

| # | id | importance | clauses (`checks`) | absent_means |
|---|---|---|---|---|
| 1 | `exposed_listeners_allowed` | 상 | `{ fact: exposure.exposed, op: none, subject: service, where: { field: service, op: not_in, expected: "${allowed_ports}" } }`; `params.allowed_ports: list<string>` default `["tcp/22"]` | manual — partial confidence, an opaque accept rule (`manual-*` fixtures) |
| 2 | `listeners_packaged` | 중 | `{ fact: processes.unpackaged_listeners, op: none, subject: exe, where: { field: exe, op: not_in, expected: "${allowed_executables}" } }`; `params.allowed_executables: list<string>` default `[]` | fail — never reached: the leaf is `ok` or a read's status (three `_mutants.yaml` rows) |
| 3 | `no_deleted_executables` | 중 | `{ fact: processes.deleted_executables, op: none, subject: pid, where: { field: pid, op: present } }` | fail — never reached, as above (three rows) |
| 4 | `ip_forwarding_disabled` | 중 | `{ fact: net.sysctl.ipv4_ip_forward, op: in, expected: "${allowed_forward}" }`; `params.allowed_forward: list<int>` default `[0]` | fail |
| 5 | `ipv6_forwarding_disabled` | 중 | `net.sysctl.ipv6_all_forwarding in ${allowed_forward}` (same parameter name and default) | not_applicable (no IPv6) |
| 6 | `icmp_redirects_ignored` | 중 | the six ipv4 keys `eq 0`: accept, secure and send redirects × all/default | fail |
| 7 | `ipv6_redirects_ignored` | 중 | the two ipv6 accept_redirects keys `eq 0` | not_applicable |
| 8 | `source_routing_rejected` | 중 | the two ipv4 accept_source_route keys `eq 0` | fail |
| 9 | `ipv6_source_routing_rejected` | 중 | the two ipv6 accept_source_route keys `eq 0` | not_applicable |
| 10 | `reverse_path_filtering` | 중 | `ipv4_all_rp_filter in [1, 2]`, `ipv4_default_rp_filter in [1, 2]`, `ipv4_all_log_martians eq 1`, `ipv4_default_log_martians eq 1` | fail |
| 11 | `icmp_broadcast_and_bogus_ignored` | 하 | `ipv4_icmp_echo_ignore_broadcasts eq 1`, `ipv4_icmp_ignore_bogus_error_responses eq 1` | fail |
| 12 | `syn_cookies_enabled` | 중 | `ipv4_tcp_syncookies eq 1` | fail |
| 13 | `ipv6_router_advertisements_ignored` | 중 | the two ipv6 accept_ra keys `eq 0` | not_applicable |

**Why IPv4 and IPv6 are separate controls (X-7).** A control has one `absent_means`, and an
IPv6 key is `absent` on a kernel without IPv6 while an IPv4 key is never absent; a control
mixing the two would have to choose between FAIL on a kernel without IPv6 and NOT_APPLICABLE on
a missing IPv4 file. The brainstorm's six topics therefore ship as thirteen controls: 36 → 49
beyond. `rp_filter` accepts 1 (strict) and 2 (loose — Ubuntu's shipped value, right for
asymmetric routing) because both filter spoofed sources; 0 FAILs.

Descriptions (muster's words, no KISA or CIS text): the primary source and the rating's reason;
the stock reading (§5: stock Ubuntu FAILs redirects, source routing, martians and RA; a docker
or libvirt host FAILs forwarding as read and relaxes through `allowed_forward: [0, 1]`); the
MANUAL/NOT_APPLICABLE/ERROR cases; for control 1 the relation to U-28 and U-52 (cause and
consequence, not duplication) and that the allow list is the host's own declaration of what it
serves; for control 2 that `/usr/local` daemons are the common honest FAIL and
`allowed_executables` names them; for control 3 that the usual answer is a restart after an
upgrade (`needrestart`, `dnf needs-restarting`) and the rarer one is a binary removed under a
running process.

References: `nist_800_53` — control 1 `CM-7`, `SC-7`; control 2 `CM-7(5)`; control 3 `SI-2`,
`CM-7(5)`; the sysctl controls `SC-7`, `SC-5` (syncookies), `CM-6`. `references.stig` where the
committed index has a matching id (the plan's pre-flight checks each; lint rejects an unknown
id). `subject_kind`: controls 1–2 `exe`/`service` strings (no NSS), control 3 `pid`; none
triggers the remote-NSS WARN.

## 5. Environments and stock readings

- **Non-root.** `processes.deleted_executables`, `processes.listeners`,
  `processes.unpackaged_listeners` and therefore `exposure.exposed` are `denied` (another
  account's `exe` and `fd`), so controls 1–3 read ERROR; `processes.list` stays `ok` with
  `exe_read_status: denied` on other accounts' rows (a `_notes` entry); `net.sysctl.*` answer
  (`/proc/sys/net` is world-readable, as is the `sysctl.d` chain). `nonroot.denied` gains four
  keys.
- **No systemd.** Nothing changes: `/proc` and `/proc/sys` only.
- **Container.** Every control NOT_APPLICABLE through the gate. The collectors still run:
  `processes.*` read the container's pid namespace (`ok`), a masked `/proc` is `unsupported`
  (the `sockets` precedent — no new `container.unsupported` row); `net.sysctl.*` read the
  container's namespace values (`ok`).
- **Stock Ubuntu 22.04 (hypothesis; the lab measures, V-18 of 3C-2a).** Listeners: sshd on
  `tcp/22` (`0.0.0.0`, `::`), systemd-resolved on `127.0.0.53` (loopback), chrony on `udp/323`
  (loopback) and `udp/123` if configured; `ufw` inactive on a stock server → `firewall.backend
  none` → every non-loopback listener exposed → control 1 PASS only when nothing but `tcp/22` is
  reachable — the lab host (docker's proxy, a kubelet) FAILs as read and the `_hosts` snapshot
  pins the stock shape, sshd alone, PASS. Control 2 PASS, control 3 PASS (freshly booted).
  Sysctls (Ubuntu's `10-network-security.conf` sets only `rp_filter 2`): forwarding 0 PASS (1 on
  a docker host); `accept_redirects` all 0 / default 1 FAIL; `secure_redirects` 1 FAIL;
  `send_redirects` 1 FAIL; `accept_source_route` all 0 / default 1 FAIL; `rp_filter` 2/2 and
  `log_martians` 0 → FAIL; `echo_ignore_broadcasts 1` / `bogus 1` PASS; `syncookies 1` PASS;
  ipv6 `accept_redirects 1` FAIL, `accept_source_route 0` PASS, `accept_ra 1` FAIL, `forwarding
  0` PASS. Six of the thirteen read FAIL on a stock host (6, 8, 10, 7, 13 and — on a docker host — 4); the descriptions say so.
- **Stock EL9 (hypothesis).** Measured in `rockylinux/rockylinux:9-ubi-init` for the process
  facts (sshd in the container); the network sysctls CANNOT be measured in a container (the
  values are the container's network namespace), so the EL9 `_hosts` rows for them are the
  kernel's documented defaults with firewalld's own `net.ipv4.ip_forward` behaviour noted, and
  the snapshot's `_notes` says the sysctl rows are unmeasured until an EL VM exists. firewalld
  active with the `public` zone (ssh allowed) is the stock firewall: `backend nft`, confidence
  — the plan verifies on the lab's EL9 image whether firewalld's generated ruleset normalises
  to `full` (its `filter_INPUT` chain accepts by jump into zone chains, which the normaliser may
  class `partial`); if `partial`, stock EL9 reads control 1 MANUAL and the description says so.
- **The GitHub runner (root job).** No firewall (`backend none`) → control 1 FAILs with
  whatever listens beside sshd (the examples run tells; the CI assert is written after the first
  run, never the collector); control 2 is expected PASS (the runner agent is not a listener);
  control 3 is measured before it is asserted (an image built and not rebooted may run upgraded
  daemons); the sysctl controls read the Ubuntu 24.04 shape above.

## 6. Tests, CI and documents

- **Fixtures.** Control 1: `pass-ssh-only`, `fail-http-exposed`, `fail-open-policy-dns`
  (`backend none`, `udp/53` on `0.0.0.0`), `pass-filtered` (a `port_rule` set that reaches none
  of the listeners), `pass-open-policy-ssh-only`, `manual-partial-confidence`,
  `manual-opaque-rule`, `error-firewall-denied`, `error-nonroot` (`processes.listeners`
  denied), `na-container`. The allow-list parameter is proven in `internal/check`
  (`fail-http-exposed` PASSes with `allowed_ports: ["tcp/22", "tcp/80"]`), never through a
  fixture (3C-2a V-13). Control 2: `pass-all-packaged`, `fail-usr-local-daemon`,
  `fail-deleted-listener`, `error-nonroot`, `error-no-index`, `na-container`; the parameter test
  allows the `/usr/local` path. Control 3: `pass-none`, `fail-one`, `error-nonroot`,
  `na-container`. Each sysctl control: `pass-*`, a `fail-*` per clause where `all` and
  `default` each disagree once, `fail-stock-ubuntu` where the stock reading fails,
  `fail-persisted-only` (runtime right, `sysctl.d` wrong — the setting's effective side is
  runtime, so this one PASSes: the fixture is `pass-persisted-drift` and the description says
  drift is reported, not judged, as 3B does), `na-container`; the IPv6 controls add
  `na-no-ipv6`. Every fixture `synthetic: true`; every judged row carries every field (3C-2a
  V-9).
- **Mutation test.** Zero survivors. `_mutants.yaml` gains the `absent_means` rows of controls
  2 and 3 (three each — the leaf is `ok` or a hard status, never `absent`); every other control
  reaches `absent` through a fixture.
- **Oracles (lab root; CI root job).** `TestOracleListeners`: `processes.listeners` against
  `ss -tulpnH` (iproute2, fixed arguments; the oracle's own command, not the collector's) —
  proto, port and pid of every row compared, `compared N` logged. `TestOracleSysctlNet`: the
  existing sysctl oracle's `sysctl -n` comparison extended to the twenty-three keys.
  `TestOracleDeletedExecutable`: the test copies `/bin/sleep` into `t.TempDir()`, starts it,
  unlinks the copy, runs the collector and asserts its own child's row reads `exe_deleted:
  true`; the child is killed by the test (nothing on the host changes). `exposure.*` has no
  daemon to ask; its rule classifier is unit-tested over every row shape the firewall parser
  emits.
- **Fuzz.** `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink`, `FuzzClassifyRule`,
  `FuzzParsePortSpec`, with seeds; the nightly does the rest.
- **Capability matrix.** `nonroot.denied` += `processes.deleted_executables`,
  `processes.listeners`, `processes.unpackaged_listeners`, `exposure.exposed`; `_notes` +=
  `processes.list` (ok with denied rows), `exposure.exposed` on a host without a firewall.
- **CI.** Root job: `jq` asserts on `processes.stats.index_source == "dpkg"`, a `tcp/22` row in
  `exposure.listeners` with `exposed true, via open_policy`, and the five oracle `compared`
  greps; the non-root job asserts the four `denied` keys through the matrix; container jobs
  nothing new. `cmd/muster/collect_test.go`'s list-actions gain nothing (no new collector
  command; the rpm query is already listed).
- **Documents.** The main design gains **D32** — *exposure is read as the join of listeners,
  processes and the firewall as configured, and the allow list is the host's own declaration* —
  and §10.2's 3C-2b entry is restated (what came here; `fix --dry-run`, profiles/CIS,
  `--anonymize`, `--max-age` to 3D/3E). CLAUDE.md gains "Exposure (stage 3C-2b)". README and
  README.ko say 49 beyond controls. CHANGELOG: Controls (`+2026.10.xx`, thirteen, the stock
  FAILs), Collectors (`processes`, the index package, `net.sysctl.*`, the rule `family` field),
  Tooling (D32, the matrix rows, the three oracles). The registry description of
  `sockets.listening` drops "pid and executable" (it never carried them; the process collector
  does). Korean pairs in the same commits.

## 7. Evaluator and schema

- No new operator. Control 3's "any row" clause uses the existing `where` field op `present`
  on a field every row carries. Control 1's `subject` names the `service` string the collector
  writes, so the reason reads `tcp/8080 (pid 1234 nginx)` without a second field lookup.
- `Builder.Get(key)` is the one addition to `internal/collect`: a read of the tree a collector
  earlier in the sorted run wrote. The run-order dependency (`firewall` before `processes`) is
  pinned by `TestCollectorOrderHasFirewallBeforeProcesses`; an `exposure.*` key written when the
  firewall facts are missing reads `error` naming them (a programming error, never a host
  state).
- Schema version unchanged: twenty-three `net.sysctl.*` keys, nine `processes.*`/`exposure.*`
  keys, all `since: 1`; `firewall.rules` rows gain `family` (C2). The facts golden regenerates
  with the new entries.
- `sockets.listening` is unchanged in shape; its description is corrected (description-only
  golden change).

## 8. Parked

- Per-interface sysctls (`conf.<if>.*`); `net.ipv4.conf.*.arp_*`; `tcp_timestamps`,
  `tcp_rfc1337`; `net.core.*` beyond `bpf_jit_harden`.
- nftables named sets as port selectors; jumps into user chains beyond what the normaliser
  already folds; `nat`/DNAT (docker's published ports live there — the `docker-proxy` listener
  is still a listener and appears in `exposure.*`); multiple network namespaces (`ip netns`);
  rules matching on interface or connection state (today `opaque` → MANUAL).
- UDP: an unconnected UDP socket reads as listening whether it serves or merely waits for
  replies (chrony's `udp/323` is loopback; a client's ephemeral socket is not) — a UDP listener
  on a high port is reported as read.
- Package judgment of processes that are not listeners (control 2 judges listeners only;
  `processes.list` carries `package_status` for every process as evidence).
- `needrestart` / `needs-restarting` as a verdict source; the join of `packages.verify.modified`
  with the package index (3C-1 §8); the owning package of a deleted executable's path as a
  reason for control 3.
- firewalld's zone model as a first-class normalisation (today its generated ruleset is
  normalised like any nft ruleset).
