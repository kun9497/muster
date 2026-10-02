# Stage 3C-2b — exposure: what is actually reachable, and who is serving it

**Status:** design, approved in conversation on 2026-10-02 and corrected from two fresh reviews
(collector side and control side) the same day; the Korean pair is
`2026-10-02-stage3c2b-exposure-design.ko.md`. Parent: `2026-09-02-muster-design.md` (D01–D31; this
stage adds D32). Predecessors: 2H (the firewall collector this stage grows), 3C-1
(`2026-09-23-stage3c1-audit-integrity-design.md`) and 3C-2a
(`2026-09-29-stage3c2a-privilege-design.md`), whose §8 parked the items this stage takes.

## 1. Scope and intent

The guide asks whether unnecessary services run (U-52's socket table) and whether a firewall
exists (U-28). Neither says what a host actually offers to the network: which listening sockets
a packet from off the host can reach through the firewall as configured, which process answers
on each, and whether that process is something the package manager put there. 3C-2b reads that
join and judges it as read: a listener reachable from off the host must be on the host's own
allow list, a listener must belong to a package, and no process may run an executable that is no
longer the file on disk. Beside the join, the kernel's network sysctls — the knobs that decide
whether the host forwards, honours ICMP redirects and source routes, and filters spoofed source
addresses — join the `sysctl` collector of 3B.

Decisions settled in the brainstorm and the review (X-1 … X-9):

- **X-1 — scope.** The "exposure" set: a process collector, processes running deleted
  executables, the exposure cross-check against the firewall, the network sysctls. Out: the join
  of `packages.verify.modified` with the package index (3C-1 §8, stays parked), `fix --dry-run`,
  profiles and the CIS reference (3D), `--anonymize`, `--max-age` (3E).
- **X-2 — three controls on the join.** An exposed listener not on the allow list FAILs; a
  listener whose executable the host's package manager did not install FAILs; a process running
  a deleted executable FAILs. Each is judged as read and relaxed only through `params` or a
  waiver (D31's philosophy).
- **X-3 — the process collector reads as much as it may.** Every pid is enumerated; a process
  whose `exe` or `fd` directory the run cannot read is a row that says so, and a judged leaf that
  would have to omit such a row is `denied` itself. Root reads everything; a non-root run reads
  its own processes and ERRORs the three controls (the `nonroot.denied` row). No deep gate.
- **X-4 — the package index is built in every collect.** The dpkg lists or the fixed rpm query
  the walk already uses, extracted into a package the walk and the process collector share; its
  cost is unmeasured today and the plan's pre-flight measures it on the lab and in the EL9 image
  before the budget below is fixed.
- **X-5 — six network-sysctl topics**, each judging `all` and `default` where the sysctl has
  both, on the setting's effective side (runtime, B-3; the persisted side is evidence);
  forwarding is read as it is (a docker host FAILs and relaxes through a parameter).
- **X-6 — "reachable through the firewall".** At full normalisation confidence: every
  non-loopback listener when inbound is not restricted; otherwise a listener whose protocol and
  port match an accept rule of its family, whatever the rule's source (the source is recorded; a
  management port opened to one subnet is still a service reachable from off the host). An accept
  rule the normalisation cannot express as "protocol and port" after X-8's selectors makes the
  host's exposure verdict MANUAL, as does partial confidence.
- **X-7 — IPv4 and IPv6 are separate controls.** A control has one `absent_means`; an IPv6 key
  is absent on a kernel without IPv6 and an IPv4 key never is. `mechanisms` could keep the six
  topics, but a per-family control is what a waiver or a report reader names, so the six topics
  ship as thirteen controls.
- **X-8 — the firewall normaliser grows.** 2H's rule table carried `{chain, proto, dport, saddr,
  action}` from the input base chains only. That cannot carry an exposure verdict: ufw keeps its
  accepts in `ufw-user-input` behind two jumps, and `iif lo accept`, `ct state established
  accept` and a bare `accept` were one byte-identical row. The firewall collector now records a
  rule's family, its selectors and its raw text, and folds the user chains an input base chain
  jumps to (bounded). U-28's own normalisation confidence is unchanged except by X-9.
- **X-9 — a configured but inactive backend is no firewall.** `ufw` installed and disabled
  (stock Ubuntu Server, the GitHub runner) read `backend ufw`, confidence `partial` ("no input
  base chain") and U-28 MANUAL. A ruleset with no input base chain and no inbound rule restricts
  nothing, whatever package is installed: it now normalises `full` with `restricts_inbound:
  false`, so U-28 reads FAIL on that host and the exposure verdict can be read. A verdict changes
  on an existing snapshot shape, so this is a minor release (D16), said in the CHANGELOG under
  Controls with U-28 fixtures.

## 2. Architecture

- **`processes` (new collector)** — enumerates `/proc`, joins each listening socket with the
  processes that hold it, joins each executable with the package index, and — because the
  firewall collector has already run (collectors run in name order, `firewall` < `processes`,
  pinned by a test) — derives `exposure.*` from the firewall's rule table. It writes
  `processes.*` and `exposure.*`. The `Builder` gains `Get(key) (facts.Envelope, bool)`, fenced
  by a new `Declaration.Facts []string` (globs of the keys a collector may read; `processes`
  declares `firewall.*` and `net.sysctl.ipv6_bindv6only`): a `Get` outside the declaration is a
  programming error (the builder panics, caught by the declaration test) and `--list-actions`
  prints the declared facts as kind `fact`. The two existing header reads (`patch` and `walk`
  read `os`'s `Env` through `Header()`, J-31) are named as the precedent and left as they are.
- **`firewall` (2H, grown — X-8, X-9)** — the rule table's record gains fields, the parsers read
  the selectors they dropped, the normaliser folds user chains, and the no-chain case normalises
  `full`. §3 P-2 has the detail. `normalization_confidence` keeps its definition (full / partial /
  the read's status) with X-9's one widening.
- **`sysctl` (3B, extended)** — gains twenty-seven `net.sysctl.*` keys, read as the kernel ones
  are (B-3), and its persisted-side parser learns `sysctl.d` glob keys and `-key` exclusions
  (systemd's `50-default.conf` uses both).
- **`pkgindex` (new internal package)** — the dpkg list reader (`/var/lib/dpkg/info/*.list`,
  `statoverride`, the `.list` file per owner) and the rpm file-table query move here from the
  walk's join unchanged in behaviour; the lookup streams the lists for a candidate set as the
  walk does today (no whole-tree index in memory). The extraction is the first task of the plan;
  the process collector's query carries its own timeout (30 s) and output cap, and a timeout is
  `index_source: none` on that run.

The evaluator does not change (§7). `--list-actions` gains the process collector's rows (its
globs, its declared facts, and the rpm query it shares with the walk). The report's
`scopes.beyond` count grows by thirteen. The exit code is unchanged.

## 3. Facts

### P-1 `processes.*`

Declaration: `Reads` `/proc/[0-9]*/status`, `/proc/[0-9]*/cmdline`, `/proc/[0-9]*/exe`,
`/proc/[0-9]*/fd/*`, `/proc/[0-9]*/ns/mnt`, `/proc/1/ns/mnt`, the package index's reads and the
four socket tables `/proc/self/net/{tcp,udp,tcp6,udp6}`; `Commands` the rpm query (shared with
the walk); `Facts` `firewall.*`, `net.sysctl.ipv6_bindv6only`. `Needs: none`. Pids are
enumerated with `Glob("/proc/[0-9]*/status")`; one fd table with `Glob("/proc/<pid>/fd/*")`
(the host `Glob` reports a directory it may not search as `denied`, never as an empty match);
`exe`, `fd/*` and `ns/mnt` are read with `Readlink` only — a magic link's text, the target never
opened (`ReadDir` is licensed by `Walk` alone and is not used).

Per process: `status` gives `Name`, `PPid`, `State` and the real `Uid`; `cmdline` gives the
first NUL-separated token (4 KiB cap); `exe` the link target; `ns/mnt` the mount namespace id.
Kinds: `kernel` when the process is pid 2 or its `PPid` is 2 (kthreadd's children; `exe` is
ENOENT there), `zombie` when `State` is `Z` (no `exe`, no fds — evidence only), `user` otherwise.
A pid that vanishes between listing and reading leaves no row and increments
`processes.stats.vanished`.

- `processes.list` — `list<record>` `{pid, ppid, uid, name, cmd, exe, exe_deleted,
  exe_read_status, kind, mnt_ns, package, package_status}`, sorted by `pid`, capped at 4096 rows
  (`truncated: true` past it; the subsets below still see every process). `exe` is the link
  target with ` (deleted)` stripped; `exe_deleted` is true when the target carried it —
  `proc(5)`'s notation for an executable unlinked or replaced since exec: an upgraded daemon not
  yet restarted, a binary removed from disk after it started, and a `memfd:` executable read the
  same, and the description names the memfd case as the suspicious one. `exe_read_status` is
  `ok`, `denied` (another account's process in a non-root run, EACCES) or `error`. `mnt_ns` is
  `host` when the process's `ns/mnt` equals pid 1's, `foreign` otherwise (a container seen from
  the host, a chroot — its `exe` path is a path in another root and the host's index must not be
  asked about it). `package` is the index's owner of `exe` for a `host` process, or `snap:<name>`
  for an `exe` under `/snap/<name>/`; `package_status` is `packaged`, `unpackaged`, `snap`
  (`/snap/*`), `flatpak` (`/var/lib/flatpak/*`, `~/.local/share/flatpak/*`), `appimage`
  (`/tmp/.mount_*`), `foreign_ns`, or `no_index` (the index could not be built). A `deleted`
  executable is looked up like any other (its path may still be owned). `sensitivity: internal`.
- `processes.deleted_executables` — `list<record>` `{pid, uid, name, exe}`: the judged subset
  (C2) — `user`-kind processes with `exe_deleted`. When any `user` process's `exe` could not be
  read, the leaf is that read's status (`denied` in a non-root run), never the subset of what was
  readable. This leaf is written from `/proc` alone: it is `ok`, `denied`, `unsupported`, `error`
  or `truncated`, and never `absent`.
- `processes.listeners` — `list<record>` `{proto, family, addr, port, loopback, link_local,
  inode, owner_status, owners}`: every listening socket of the host — the rows `sockets.listening`
  lists, re-read here (R232: once per collector) — with `proto` folded to `tcp`/`udp` and
  `family` `v4`/`v6` from the table it came from, and `owners` the processes holding the socket:
  `list<{pid, uid, name, exe, exe_deleted, mnt_ns, package, package_status}>` sorted by `pid`,
  capped at 64 (a socket-activated service is held by pid 1 and the service; a prefork server
  by every worker). `owner_status` is `ok`; `kernel` when the table's inode is `0` (a
  kernel-owned socket: nfsd, ksmbd, WireGuard, rpc callbacks — `owners` empty, judged packaged
  by nature); `unmatched` when every fd table was read and no process holds the inode (another
  network namespace's socket, or one closed between the two reads); `denied` when an fd table
  could not be read. An inode of `-1` (an unparsed column) is the leaf's `error`. When any fd
  table was `denied`, the leaf is `denied`; when any socket is `unmatched`, the leaf is `absent`
  naming it (control 2 reads MANUAL — a socket nobody holds is a hole in the inventory, never a
  pass). Capped at 2000 rows; sorted by `proto`, `port`, `addr`. `truncated: true` when the
  socket tables or the index were cut.
- `processes.unpackaged_listeners` — `list<record>` `{proto, family, addr, port, pid, name,
  exe, package_status}`: the judged subset — one row per (listener, owner) whose owner's
  `package_status` is `unpackaged`, `snap`, `flatpak`, `appimage` or `foreign_ns` (a `deleted`
  executable belongs to control 3 and is not repeated here). Carries `processes.listeners`'s
  status when that is not `ok`, the index read's status when the index could not be built
  (`absent` "no package database" on a host without dpkg or rpm — control 2 reads MANUAL, the
  setuid precedent), and `truncated` as above.
- `processes.stats` — record `{count, kernel_threads, zombies, foreign_ns, denied, vanished,
  fd_reads, index_source, index_ms, elapsed_ms}`; `index_source` is `dpkg`, `rpm` or `none`.

Budgets: 65536 fd entries per process (one `readlink` each; past it the leaf is `error` naming
the pid — never a quiet `unmatched`), 5 s for the whole enumeration (past it `processes.list` is
`truncated` and every judged leaf carries `truncated: true`, which the evaluator reads as
`ERROR(truncated)`), the index's own limits (§2).

Statuses (C3/C4): a masked `/proc` (`ErrProcfsMasked`) is `unsupported` on every `processes.*`
key; `exe`/`fd`/`ns/mnt` EACCES is the row's `exe_read_status`/`owner_status` and the judged
leaves' `denied`; a cut `.list` or rpm output is `truncated` on `processes.listeners`,
`processes.unpackaged_listeners` and `exposure.exposed`.

### P-2 `firewall.rules` grown (the firewall collector, X-8 and X-9)

Record: `{chain, via_chain, depth, family, proto, dport, saddr, daddr, iif, ctstate, action,
unmodelled, raw}` — a record field added keeps `schema_version` (C2); every row carries every
field (empty strings and `false` where a selector is absent).

- `family`: nft `ip` → `v4`, `ip6` → `v6`, `inet` → `inet`; iptables-save's dump → `v4`,
  ip6tables-save's → `v6`. A `bridge`, `arp` or `netdev` table never joins the input base chains
  (today `parseNftRuleset` does not filter by family; it does now).
- `proto`: `tcp`, `udp`, another literal (`icmp`, `icmpv6`, `esp`, …), or empty. A protocol
  set (`meta l4proto { tcp, udp }`, `ip protocol { tcp, udp }`) or a vmap sets `unmodelled`
  (today the parser kept the set's last member — `udp` — so `tcp/53` behind such a rule read
  filtered).
- `dport`: a port, a range (`1000-2000` nft, `1000:2000` iptables), a set (`{ 22, 80 }` nft, `-m
  multiport --dports 22,80,443` iptables), each enumerable up to 256 ports; a symbolic service
  name, a named set (`@ports`) or a vmap sets `unmodelled`.
- `saddr`, `daddr`: the address or set text as written. `iif`: `-i X` / `iif X` / `iifname X`.
  `ctstate`: `--ctstate` / `ct state` list, lower-cased.
- `action`: `accept`, `drop`, `reject`, `return`, `jump <chain>`, `goto <chain>`, `continue`,
  `queue`, `log`, or empty (no verdict word recognised).
- `unmodelled`: true when a token the parser does not model remained in the rule's match part
  (`-m owner`, `meta mark`, `tcp flags`, `icmp type`, `-d` without the field, a set the parser
  could not enumerate, `counter`/`comment`/`-m tcp` excluded as inert).
- `raw`: the rule line as dumped, capped at 512 bytes.
- `chain`, `via_chain`, `depth`: the chain the row was read from, the input base chain whose
  jump reached it (itself for a base-chain row) and the jump depth (0 for the base chain).

Folding: for every input base chain, the rules of every chain it jumps or goes to are appended
in dump order with `depth + 1`, to a depth of 4 and 2000 folded rows per base chain (ufw's
accepts sit at depth 2: `INPUT → ufw-before-input → ufw-user-input`); a chain visited twice is
visited once; a jump past the depth or the row budget sets `unmodelled` on the jump row itself,
so the classifier reads it `opaque`. Rule order inside and across chains is ignored (an accept
counts whether or not a drop precedes it — conservative; §8). `restricts_inbound` and
`normalization_confidence` are computed as today from the base chains' policies and rule
presence, with one widening (X-9): a family with a backend configured but no input base chain
and no inbound rule — `ufw` disabled, firewalld stopped with its tables flushed, an `nftables`
service with an empty ruleset — is `full` with `restricts_inbound: false`, no longer `partial`
"no input base chain found". U-28's second mechanism (`restricts_inbound eq true`) therefore
reads FAIL where it read MANUAL: the host has no firewall, and the control says so. The
firewall's own fixtures gain `fail-ufw-inactive.json`; the CHANGELOG records the verdict change
under Controls (D16).

### P-3 `exposure.*` (written by `processes`)

Inputs: `processes.listeners`, `firewall.normalization_confidence`, `firewall.restricts_inbound`,
`firewall.rules`, `firewall.backend` (through `Builder.Get`, declared), and
`net.sysctl.ipv6_bindv6only` (written by `sysctl`, which sorts after `processes` — so this one is
read from `/proc/sys/net/ipv6/bindv6only` directly, declared in `Reads`; a kernel without IPv6
has no such file and no v6 listeners to decide).

Classification of every folded row of every input base chain:

- `deny`: `action` `drop` or `reject` — recorded, never a path in;
- `port_rule`: `action` `accept`, not `unmodelled`, `proto` `tcp` or `udp`, `dport` enumerable,
  `iif` empty or not `lo`, `ctstate` empty or containing `new` or `untracked`;
- `any_port`: `accept`, not `unmodelled`, `proto` and `dport` empty, `iif` empty, `ctstate`
  empty or containing `new`/`untracked`, `daddr` empty;
- `loopback_only`: `accept` with `iif` `lo` (nothing from off the host arrives on `lo`);
- `state_only`: `accept` whose `ctstate` has neither `new` nor `untracked` (established and
  related traffic answers a connection the host initiated or already accepted);
- `irrelevant`: `accept` whose `proto` is a literal other than `tcp`/`udp` (ICMP, ESP, IGMP —
  cannot reach a TCP or UDP listener); a `log`, `return` or `continue` row; a `jump`/`goto` row
  that was folded;
- `opaque`: everything else — an `unmodelled` accept, an accept with a `daddr` and no port, a
  jump past the fold budget, an empty `action`.

Exposure is decided only when `normalization_confidence` is `full` and no `opaque` row exists in
an input base chain of the listener's family (`inet` counts for both). Then, per non-loopback
listener (loopback is `127.0.0.0/8` and `::1`; a link-local address — `fe80::/10`,
`169.254.0.0/16` — is reachable by every neighbour on the link and IS a candidate, recorded
`link_local: true`):

- the host's families are those with a socket table (`tcp6`/`udp6` present → v6 enabled); a
  family that is enabled and has no input base chain (`ip6` or `inet`) while the other has — the
  common "iptables only, no ip6tables rules" host — exposes every listener of that family,
  `via: no_chain_in_family`;
- `restricts_inbound: false` → exposed, `via: open_policy`;
- otherwise exposed when an `any_port` row exists in the family (`via: any_port_rule`) or a
  `port_rule` matches protocol and port — range by containment, set by membership (`via: rule`,
  the row's `chain`, `saddr` and `raw` recorded); otherwise `filtered`;
- a socket on `0.0.0.0` is a v4 candidate; on `::` a v6 candidate and, when `bindv6only` is `0`,
  a v4 candidate too — exposed when either family says so; a specific address is a candidate in
  its own family.

Keys:

- `exposure.listeners` — `list<record>` `{service, proto, family, addr, port, link_local,
  owners, exposed, via, rule_chain, rule_source, rule_raw}` for every non-loopback listener;
  `service` is `"<proto>/<port>"` with `proto` `tcp` or `udp` (`tcp/22`, never `tcp6/22`), the
  string the allow list names; `owners` as in `processes.listeners`. Sorted by `proto`, `port`,
  `addr`. Evidence.
- `exposure.exposed` — `list<record>` `{service, proto, family, addr, port, pid, name, package,
  via, rule_chain, rule_source}`: the exposed subset, one row per listener (the owner shown is
  the lowest pid; `exposure.listeners` has them all). `absent` when the verdict cannot be read
  (control 1 MANUAL): partial confidence, or an `opaque` row. The evaluator renders an absent
  judged leaf as "`<fact>` is absent on this host" without the collector's reason, so the cause
  is also written where the report reader finds it: `exposure.stats.confidence` and
  `exposure.stats.manual_reason`, and `exposure.opaque_rules`. The firewall read's status when
  the firewall could not be read (`unsupported` — no `nft`/`iptables` binary as root; `denied`);
  `processes.listeners`'s status when that is not `ok`; `truncated` when either input was.
- `exposure.opaque_rules` — `list<record>` `{chain, via_chain, family, action, raw}`.
- `exposure.stats` — record `{confidence, manual_reason, listeners, exposed, filtered, loopback,
  link_local, kernel_owned, opaque_rules, folded_rules}`.

A host with no firewall binary at all reads `firewall.* unsupported` and control 1
NOT_APPLICABLE while everything is reachable — consistent with U-28's own reading of that host,
and the description says so. A host with a backend configured and nothing restricting (X-9) reads
control 1 as exposed-everything and U-28 FAIL: cause and consequence, said in both descriptions.

### P-4 `net.sysctl.*` (the `sysctl` collector)

Twenty-seven keys, `since: 1`. Twenty-five are `setting<int>` with `default_on: effective`
(= runtime, B-3) and the two homes of `sysctl.d` as the persisted side; two are evidence:

| key | sysctl |
|---|---|
| `ipv4_ip_forward` | `net.ipv4.ip_forward` |
| `ipv6_all_forwarding`, `ipv6_default_forwarding` | `net.ipv6.conf.{all,default}.forwarding` |
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
| `ipv6_all_disable_ipv6`, `ipv6_default_disable_ipv6` | `net.ipv6.conf.{all,default}.disable_ipv6` (the gate of the IPv6 controls) |
| `ipv6_bindv6only` (`int`, evidence) | `net.ipv6.bindv6only` (read by `processes` for P-3) |

`all` applies to every interface now, `default` to every interface created later
(`ip-sysctl.rst`); a host whose `all` is tight and `default` loose gives a new interface — a
container's veth, a VPN — the loose value, so both are judged. Per-interface values are not
collected (§8). A kernel without IPv6 (`/proc/sys/net/ipv6` absent — the `ipv6.disable=1` boot
parameter) makes every `ipv6_*` key `absent` with the reason "IPv6 is not built or is disabled"
(a special case of `readProcSys`'s "does not exist" keyed on the `/proc/sys/net/ipv6` prefix);
IPv6 turned off the common way — `disable_ipv6 = 1` on `all` and `default` — leaves the files
present with their defaults, so the IPv6 controls gate on both `disable_ipv6` keys being `0` (§4).

The persisted parser learns what systemd's `/usr/lib/sysctl.d/50-default.conf` writes: a glob key
(`net.ipv4.conf.*.rp_filter = 2`, applied to every matching key) and a `-key` line (`-net.ipv4.
conf.all.rp_filter`, excluding that key from the glob). Without it the persisted side of
`rp_filter` and `accept_source_route` read "no sysctl.d line sets …" on every systemd host —
wrong evidence, no verdict (B-3). That file is also why the stock hypotheses in §5 differ from the
kernel defaults.

## 4. Controls

Thirteen `category: beyond` controls, ids `muster.beyond.<name>` under `controls/beyond/`, every
one gated on `env.container eq none` (a container's processes, firewall and network namespace are
not the host's policy), `automation: auto`. Importance is muster's own rating from the primary
source named in each description.

| # | id | importance | clauses (`checks`) | absent_means |
|---|---|---|---|---|
| 1 | `exposed_listeners_allowed` | 상 | `{ fact: exposure.exposed, op: none, subject: service, where: { field: service, op: not_in, expected: "${allowed_ports}" } }`; `params.allowed_ports: list<string>` default `["tcp/22", "udp/68", "udp/546"]` — sshd, and the DHCP and DHCPv6 client sockets every address-by-DHCP host binds on `0.0.0.0:68` / `:::546` | manual — partial confidence, an opaque rule |
| 2 | `listeners_packaged` | 중 | `{ fact: processes.unpackaged_listeners, op: none, subject: exe, where: { field: exe, op: not_in, expected: "${allowed_executables}" } }`; `params.allowed_executables: list<string>` default `[]` | manual — no package database, an unmatched socket |
| 3 | `no_deleted_executables` | 중 | `{ fact: processes.deleted_executables, op: none, subject: pid, where: { field: pid, op: gte, expected: 0 } }` | fail — never reached: the leaf is `ok` or a hard status, never `absent` (three `_mutants.yaml` rows naming that invariant) |
| 4 | `ip_forwarding_disabled` | 중 | `{ fact: net.sysctl.ipv4_ip_forward, op: in, expected: "${allowed_forward}" }`; `params.allowed_forward: list<int>` default `[0]` | fail |
| 5 | `ipv6_forwarding_disabled` | 중 | `ipv6_all_forwarding in ${allowed_forward}`, `ipv6_default_forwarding in ${allowed_forward}` (same parameter) | not_applicable |
| 6 | `icmp_redirects_ignored` | 중 | the six ipv4 keys `eq 0`: accept, secure and send redirects × all/default | fail |
| 7 | `ipv6_redirects_ignored` | 중 | the two ipv6 accept_redirects keys `eq 0` | not_applicable |
| 8 | `source_routing_rejected` | 중 | the two ipv4 accept_source_route keys `eq 0` | fail |
| 9 | `ipv6_source_routing_rejected` | 중 | the two ipv6 accept_source_route keys `eq 0` | not_applicable |
| 10 | `reverse_path_filtering` | 중 | `ipv4_all_rp_filter in [1, 2]`, `ipv4_default_rp_filter in [1, 2]`, `ipv4_all_log_martians eq 1`, `ipv4_default_log_martians eq 1` | fail |
| 11 | `icmp_broadcast_and_bogus_ignored` | 하 | `ipv4_icmp_echo_ignore_broadcasts eq 1`, `ipv4_icmp_ignore_bogus_error_responses eq 1` | fail |
| 12 | `syn_cookies_enabled` | 중 | `ipv4_tcp_syncookies eq 1` | fail |
| 13 | `ipv6_router_advertisements_ignored` | 중 | `ipv6_all_accept_ra in ${allowed_accept_ra}`, `ipv6_default_accept_ra in ${allowed_accept_ra}`; `params.allowed_accept_ra: list<int>` default `[0]` (a SLAAC-addressed server names `1`; `2` is the only value that accepts RAs on a forwarding host) | not_applicable |

The four IPv6 controls (5, 7, 9, 13) carry two more `applies_when` clauses:
`net.sysctl.ipv6_all_disable_ipv6 eq 0` and `net.sysctl.ipv6_default_disable_ipv6 eq 0` — a host
that turned IPv6 off the recommended way reads NOT_APPLICABLE, not FAIL on defaults it never
uses. `rp_filter` accepts 1 (strict) and 2 (loose — systemd's shipped value, right for asymmetric
routing); 0 FAILs. `secure_redirects` is moot once `accept_redirects` is 0 and is judged anyway,
as the benchmarks do; the description says so.

Control 1's `service` contract: lower-case `<tcp|udp>/<port>`, exact match, no ranges or
wildcards (`TCP/22`, `tcp/*` match nothing — lint could not tell a typo from a port and does not
try). The `0.0.0.0` and `::` sockets of one daemon are one `service`, so one waiver covers both.
Control 2's `allowed_executables` names paths (`/usr/local/sbin/mydaemon`, `/snap/lxd/current/bin/lxd`);
a snap daemon is an honest FAIL as read (the host's package manager did not install it) and the
description says so, as it says that `foreign_ns` means a container's process serving on the
host's network namespace.

Descriptions (muster's words, no KISA or CIS text): the primary source and the rating's reason;
the stock reading (§5); the MANUAL/NOT_APPLICABLE/ERROR cases; for control 1 the relation to U-28
and U-52 (cause and consequence, not duplication) and that the allow list is the host's own
declaration of what it serves; for control 2 that `/usr/local` daemons are the common honest FAIL
and `allowed_executables` names them; for control 3 that the usual answer is a restart after an
upgrade (`needrestart`, `dnf needs-restarting`) and the rarer one is a binary removed under a
running process.

References (every id in the committed index; lint rejects an unknown one): `nist_800_53` —
control 1 `CM-7`, `CM-6`; control 2 `CM-7(5)`; control 3 `CM-7(5)`, `SI-2(6)`; controls 4–13
`CM-6`, control 12 also `SC-5`, `SC-5(2)`. `references.stig` (rhel9 V2R9, ubuntu2204 V2R9,
ubuntu2404 V1R6): 4 `RHEL-09-253075`; 5 `RHEL-09-254025`; 6 `RHEL-09-253015`, `-253040`,
`-253065`, `-253070`; 7 `RHEL-09-254015`, `-254035`; 8 `RHEL-09-253020`, `-253045`; 9
`RHEL-09-254020`, `-254040`; 10 `RHEL-09-253035`, `-253050`; 11 `RHEL-09-253055`, `-253060`; 12
`RHEL-09-253010`, `UBTU-22-253010`, `UBTU-24-600190`; 13 `RHEL-09-254010`, `-254030`; controls 1–3
none. `subject_kind`: none of the subjects is a user or group, so no control triggers the
remote-NSS WARN.

## 5. Environments and stock readings

- **Non-root.** `processes.deleted_executables`, `processes.listeners`,
  `processes.unpackaged_listeners` and therefore `exposure.exposed` are `denied` (another
  account's `exe`, `fd` and `ns/mnt`), so controls 1–3 read ERROR; `processes.list` stays `ok`
  with `exe_read_status: denied` on other accounts' rows (a `_notes` entry); `net.sysctl.*` answer
  (`/proc/sys/net` and the `sysctl.d` chain are world-readable). `nonroot.denied` gains four keys.
- **No systemd.** Nothing changes.
- **Container.** Every control NOT_APPLICABLE through the gate. The collectors still run:
  `processes.*` read the container's pid namespace (`ok`); a masked `/proc` is `unsupported` (the
  `sockets` precedent — no new `container.unsupported` row); `net.sysctl.*` read the namespace's
  values (`ok`); every process is `mnt_ns: host` relative to the container's pid 1.
- **Stock Ubuntu 22.04 / 24.04 (hypothesis; the lab measures, V-18 of 3C-2a).** `ufw`
  installed and disabled → X-9 → `full`, `restricts_inbound: false` → every non-loopback
  listener exposed: sshd `tcp/22` and the DHCP client `udp/68` → control 1 PASS with the default
  allow list; U-28 reads FAIL on that host (D16). systemd-resolved (`127.0.0.53`) and chrony
  (`udp/323`) are loopback. Control 2 PASS (every listener dpkg-owned; a 24.04 server's
  `ssh.socket` listener is held by pid 1 and sshd, both packaged); control 3 PASS on a rebooted
  host. Sysctls (kernel defaults, then `50-default.conf`'s `rp_filter 2` and
  `default.accept_source_route 0`, then Ubuntu's `10-network-security.conf`): `ip_forward 0` PASS
  (1 on a docker host); `accept_redirects` 1/1 FAIL; `secure_redirects` 1/1 FAIL;
  `send_redirects` 1/1 FAIL; `accept_source_route` 0/0 PASS; `rp_filter` 2/2 PASS, `log_martians`
  0/0 → control 10 FAIL; `echo_ignore_broadcasts 1`, `bogus 1` PASS; `syncookies 1` PASS; ipv6
  `accept_redirects 1` FAIL, `accept_source_route 0` PASS, `accept_ra 1` FAIL, `forwarding 0`
  PASS. Four of the thirteen read FAIL on a stock host (6, 7, 10, 13), five on a docker host (4);
  the descriptions say so and the lab measurement is the pin.
- **Stock EL9 (hypothesis).** firewalld active (`backend firewalld`, its nft ruleset): its
  `filter_INPUT` chain accepts by default with rules, which the normaliser classes `partial`
  today and still does — control 1 reads MANUAL on stock EL9 and the description says so;
  firewalld's zone model as a first-class normalisation is parked (§8). The process facts are
  measured in `rockylinux/rockylinux:9-ubi-init` (sshd); the sysctls' runtime side cannot be
  measured in a container (the namespace's values) and the persisted side can (the image's
  `50-default.conf`): the EL9 `_hosts` rows carry the persisted reading as the hypothesis for the
  runtime one, and `_notes` says so until an EL VM exists.
- **The GitHub runner (root job).** `ufw` disabled → X-9 → exposure decided: sshd `tcp/22` and
  the DHCP client `udp/68` (both in the default list), plus whatever the image's agents listen on
  — the examples run tells, and the CI assert is written after the first run (never the
  collector); control 2 expected PASS; control 3 measured before it is asserted (an image built
  and not rebooted may run upgraded daemons); the sysctl controls read the Ubuntu shape above.

## 6. Tests, CI and documents

- **Fixtures.** Control 1: `pass-ssh-only` (X-9 shape), `pass-filtered` (drop policy, `port_rule`
  22 only, a listener on 5432), `pass-state-and-loopback-rules` (the hand-written ruleset:
  `iif lo accept`, `ct state established,related accept`, `tcp dport 22 accept`, policy drop —
  5432 filtered), `pass-ufw-folded` (ufw's chains folded, `ufw-user-input` allows 22 only),
  `fail-ufw-folded-http` (… and 80, nginx listening), `fail-open-policy-dns`, `fail-any-port-rule`,
  `fail-v6-unfiltered` (v4 rules, no v6 chain, a `::` listener), `fail-link-local`,
  `manual-partial-confidence`, `manual-opaque-rule` (an `unmodelled` accept), `manual-proto-set`
  (`meta l4proto { tcp, udp }`), `error-firewall-denied`, `na-no-firewall-binary`
  (`exposure.exposed` carries the firewall's `unsupported`, which the evaluator reads as
  NOT_APPLICABLE on any leaf), `error-nonroot`, `na-container`. The allow-list parameter is proven in
  `internal/check` (`fail-ufw-folded-http` PASSes with `["tcp/22", "udp/68", "udp/546",
  "tcp/80"]`), never through a fixture (3C-2a V-13). Control 2: `pass-all-packaged`,
  `pass-socket-activated` (pid 1 and sshd as owners), `pass-kernel-socket` (nfsd, inode 0),
  `fail-usr-local-daemon`, `fail-snap-daemon`, `fail-foreign-ns`, `manual-no-package-db`,
  `manual-unmatched-owner`, `error-nonroot`, `error-index-timeout`, `na-container`; the parameter
  test allows the `/usr/local` path. Control 3: `pass-none`, `fail-one`, `fail-memfd`,
  `error-nonroot`, `na-container`. Each sysctl control: `pass-*`, a `fail-*` per clause where
  `all` and `default` each disagree once, `fail-stock-ubuntu` where the stock reading fails,
  `fail-all-absent` (every judged key absent — the 3B precedent that kills the `absent_means`
  mutants of the IPv4 controls), `pass-persisted-drift` (runtime right, `sysctl.d` wrong — the
  setting's effective side is runtime, so PASS; drift is reported, not judged, as 3B does),
  `na-container`; the IPv6 controls add `na-no-ipv6` (keys absent) and `na-ipv6-disabled`
  (`disable_ipv6` 1). The firewall collector's fixtures gain `fail-ufw-inactive.json` for U-28
  (X-9). Every fixture `synthetic: true`; every judged row carries every field (3C-2a V-9).
- **Mutation test.** Zero survivors. `_mutants.yaml` gains the three `absent_means` rows of
  control 3 (the leaf is written from `/proc` alone and is never `absent`); every other control
  reaches `absent` through a fixture.
- **Oracles (lab root; CI root job).** `TestOracleListeners`: `processes.listeners` against
  `ss -tulpnH` (iproute2, fixed arguments; the oracle's own command): for every row the
  proto/port match and every pid `ss` names in `users:(…)` is among `owners`; `compared N`
  logged. `TestOracleSysctlNet`: the existing sysctl oracle's `sysctl -n` comparison extended to
  the twenty-seven keys. `TestOracleDeletedExecutable`: the test copies `/bin/sleep` into
  `t.TempDir()`, starts it, unlinks the copy, runs the collector and asserts its child's row reads
  `exe_deleted: true`; the child is killed by the test (nothing on the host changes). The lab
  recipe adds a `docker run --net=host` probe to measure `mnt_ns: foreign` and that overlayfs does
  not print `(deleted)` for a running container's `exe`. The firewall fold is proven on the lab
  by enabling nothing: the lab's ruleset is dumped read-only and its folded rows compared with
  `iptables-save`/`nft list ruleset` by hand in the plan's measurement task. `exposure.*` has no
  daemon to ask; its classifier is unit-tested over every row shape the grown parser emits,
  including the six byte-identical accepts of the review (`-i lo`, `-m conntrack`, `ct state`,
  `iif "lo"`, `ip daddr … accept`, `-d … -j ACCEPT`) and the protocol set.
- **Fuzz.** `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink`, `FuzzClassifyRule`,
  `FuzzParsePortSpec`, `FuzzFoldChains`, plus the grown `FuzzParseNftRuleset` /
  `FuzzParseIptablesSave` seeds (`meta l4proto { tcp, udp }`, `--dports 22,80`, `1000:2000`,
  `tcp dport vmap { 22 : accept }`).
- **Capability matrix.** `nonroot.denied` += `processes.deleted_executables`,
  `processes.listeners`, `processes.unpackaged_listeners`, `exposure.exposed`; `_notes` +=
  `processes.list` (ok with denied rows), `exposure.exposed` on a host without a firewall binary
  (unsupported → NOT_APPLICABLE, as U-28).
- **CI.** Root job: `jq` asserts on `processes.stats.index_source == "dpkg"`, a `tcp/22` row in
  `exposure.listeners`, and the three oracle `compared`/row greps; the first run decides the
  exposure assert (`exposure.stats.confidence` and the `via` the runner actually reads), as §5
  says. The non-root job asserts the four `denied` keys through the matrix; container jobs
  nothing new. `cmd/muster/collect_test.go`'s list-actions gain the process collector's rows
  (its globs, `fact firewall.*`, the shared rpm query).
- **Documents.** The main design gains **D32** — *exposure is read as the join of listeners,
  processes and the firewall as configured, and the allow list is the host's own declaration* —
  and §10.2's 3C-2b entry is restated (what came here; `fix --dry-run`, profiles/CIS,
  `--anonymize`, `--max-age` to 3D/3E). CLAUDE.md gains "Exposure (stage 3C-2b)". README and
  README.ko say 49 beyond controls. CHANGELOG: Controls (`+2026.10.xx`, thirteen, the stock
  FAILs, U-28's verdict on an inactive backend — D16), Collectors (`processes`, the index
  package, `net.sysctl.*` and the glob keys, the grown firewall rule table and the fold),
  Tooling (D32, the matrix rows, the three oracles). `docs/reference/coverage.md` regenerated;
  `hosts_test.go`'s two tables (49 beyond on the Ubuntu table; the EL9 table grows from 17 and
  its snapshot carries the new families so no tabled control ERRORs). The registry description
  of `sockets.listening` drops "pid and executable" (it never carried them; the process collector
  does). Korean pairs in the same commits.

## 7. Evaluator and schema

- No new operator. Control 3's "any row" clause uses `pid gte 0` on a field every row carries
  (a `where` on a missing field is a silent non-hit for `present`, a `missingFieldError` for a
  comparison — the comparison is the safer idiom). Control 1's `subject` names the `service`
  string the collector writes, so the reason reads `tcp/8080` and the observation key is one per
  service.
- `Builder.Get(key)` and `Declaration.Facts` are the additions to `internal/collect`: a read of a
  fact an earlier collector wrote, allowed only for the declared globs, a miss a panic the
  declaration test catches, the declared facts printed by `--list-actions`. The run-order
  dependency is pinned by `TestDeclaredFactsAreWrittenBeforeTheyAreRead` (every declared fact's
  collector sorts before the reader); an `exposure.*` key written when a declared fact is missing
  reads `error` naming it (a programming error, never a host state).
- Schema version unchanged: twenty-seven `net.sysctl.*` keys and nine `processes.*`/`exposure.*`
  keys, all `since: 1`; `firewall.rules` rows gain eight fields (C2). The facts golden regenerates
  with the new entries; `sockets.listening`'s description change is description-only.
- The X-9 widening changes U-28's verdict on an inactive-backend host (MANUAL → FAIL): a
  Controls CHANGELOG entry, a U-28 fixture, and `controls/VERSION` bumped (D16).

## 8. Parked

- Rule order (an accept counts whether or not a drop precedes it — conservative, more FAILs,
  never a false PASS); user chains beyond depth 4 or 2000 rows (`opaque` → MANUAL).
- firewalld's zone model as a first-class normalisation (its default-accept `filter_INPUT` with
  rules reads `partial` → control 1 MANUAL on stock EL9); `nat`/DNAT (docker's published ports —
  the `docker-proxy` listener is still a listener and appears in `exposure.*`); multiple network
  namespaces (`ip netns`); named sets as port selectors; `tcp flags`, `meta mark`, `-m owner`
  selectors (today `opaque`).
- Per-interface sysctls (`conf.<if>.*`); `net.ipv4.conf.*.arp_*`; `tcp_timestamps`,
  `tcp_rfc1337`; `net.core.*` beyond `bpf_jit_harden`.
- UDP: an unconnected UDP socket reads as listening whether it serves or merely waits for replies
  (chrony's `udp/323` is loopback; a client's ephemeral socket is not) — a UDP listener on a high
  port is reported as read.
- Package judgment of processes that are not listeners (control 2 judges listeners only;
  `processes.list` carries `package_status` for every process as evidence); a snap/flatpak
  manifest as a second declaration source (today `snap` is an honest FAIL relaxed by
  `allowed_executables`).
- `needrestart` / `needs-restarting` as a verdict source; the join of `packages.verify.modified`
  with the package index (3C-1 §8); the owning package of a deleted executable's path as a reason
  for control 3.
