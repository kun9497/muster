# Stage 3C-2b Exposure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read what a host actually offers to the network — every listening socket joined with the processes that hold it, their packages, and the firewall as configured — plus the network sysctls, and judge thirteen `beyond` controls on it (104 → 117 controls; beyond 36 → 49).

**Architecture:** A new `processes` collector enumerates `/proc`, joins sockets to owners (`/proc/<pid>/fd` links) and executables to a package index shared with the walk (new `internal/pkgindex`), and derives `exposure.*` from the firewall's rule table through a new, declared `Builder.Get`. The firewall collector (2H) grows: per-rule family, selectors and raw text, user chains folded under an input base chain, and a configured-but-inactive backend read as no firewall (X-9, a U-28 verdict change). The `sysctl` collector (3B) gains 27 `net.sysctl.*` keys and reads `sysctl.d` glob keys. The evaluator does not change.

**Tech Stack:** Go 1.25, `golang.org/x/sys/unix`; linux-tagged collectors under `internal/collect/collectors`; YAML controls under `controls/beyond`; fixtures under `controls/testdata`.

**Spec:** `docs/superpowers/specs/2026-10-02-stage3c2b-exposure-design.md` (X-1…X-9; §3 P-1…P-4 facts, §4 controls, §5 environments, §6 tests/CI/documents, §7 evaluator/schema, §8 parked), committed at `158f6ea` with both design reviews folded. Execution notes at the end record every ruling settled during execution.

## Global Constraints

- **W-1 (declarations).** Every host touch goes through `Access`; a collector's reads are in `Declare.Reads` (globs, `path.Match`), its commands in `Declare.Commands`, and — new in this stage — the facts it reads from an earlier collector in `Declare.Facts` (globs over fact keys). `TestEveryCollectorStaysInsideItsDeclaration` (`collectors_test.go:2659`) runs every collector against a recording double and fails on any read outside the declaration; `Builder.Get` outside `Declare.Facts` panics so the same test catches it.
- **W-2 (Readlink only).** `/proc/<pid>/exe`, `/proc/<pid>/fd/*` and `/proc/<pid>/ns/mnt` are read with `Access.Readlink` (`readdir.go:329`: `openDirNoFollow` the parent, `Readlinkat` the base). The target is never opened. `ReadDir` is licensed by `Declaration.Walk` only and is not used. Pids are enumerated with `Glob("/proc/[0-9]*/status")`; one fd table with `Glob("/proc/<pid>/fd/*")` (the host `Glob` reports an unsearchable directory as `denied`, M-10).
- **W-3 (statuses).** C3/C4 as CLAUDE.md states them. A judged leaf that would have to omit a row the run could not read is that read's status (`denied`), never the readable subset. `truncated: true` on a judged leaf reads `ERROR(truncated)` (`eval.go` `screenEnvelope`). An `absent` judged leaf reaches `absent_means`; the evaluator renders it without the collector's reason (M1 of review B), so the cause is also written to `exposure.stats`.
- **W-4 (the rule table).** `firewall.rules` rows are `{chain, via_chain, depth, family, proto, dport, saddr, daddr, iif, ctstate, action, unmodelled, raw}`; every row every field (`""`/`false` when absent); `raw` capped at 512 bytes; `family` ∈ {`v4`, `v6`, `inet`} (nft `ip`→`v4`, `ip6`→`v6`, `inet`→`inet`; iptables-save `v4`, ip6tables-save `v6`); `bridge`/`arp`/`netdev` tables never join the input chains. Folding: depth ≤ 4, ≤ 2000 folded rows per base chain, a chain visited once, a jump past the budget sets `unmodelled` on the jump row. `normalization_confidence` keeps H-16's definition except X-9: `len(inputs)==0 && !inboundPathHasRules` is `full` + `restricts_inbound ok:false` for EVERY backend name, not only `none`.
- **W-5 (classification, spec P-3).** `deny` (drop/reject); `port_rule` (accept, !unmodelled, proto tcp|udp, dport enumerable, iif ∉ {lo}, ctstate empty or ∋ new|untracked); `any_port` (accept, !unmodelled, proto=dport=iif=daddr="", ctstate as above); `loopback_only` (accept with iif lo); `state_only` (accept whose ctstate lacks new and untracked); `irrelevant` (accept with a non-tcp/udp literal proto; log/return/continue; a folded jump/goto row); `opaque` (everything else). Exposure decided only at `full` with no `opaque` in the listener's family (`inet` counts for both).
- **W-6 (port specs).** A port is `0..65535`; a range is `a-b` (nft) or `a:b` (iptables), matched by containment; a set is nft `{ a, b }` or iptables `-m multiport --dports a,b,c`, matched by membership, at most 256 members (more → `unmodelled`); a service name, `@set`, or a vmap → `unmodelled`. A protocol set `{ tcp, udp }` or vmap → `unmodelled`.
- **W-7 (processes).** `processes.list` ≤ 4096 rows (`truncated` past it; the subsets still see every process); `owners` ≤ 64 per socket; fd entries ≤ 65536 per process (overrun → the leaf `error` naming the pid); 5 s enumeration budget (overrun → `processes.list` truncated and every judged leaf `truncated`). Kinds: `kernel` (pid 2 or PPid 2), `zombie` (`State: Z`), `user`. `exe` is stored with ` (deleted)` stripped and `exe_deleted` true. `mnt_ns` is `host` iff `readlink /proc/<pid>/ns/mnt == readlink /proc/1/ns/mnt`.
- **W-8 (owners and kernel sockets).** inode `0` → `owner_status: kernel`, `owners: []`; inode `-1` → the leaf `error`; a socket no fd table holds, every table read → `unmatched` → `processes.listeners` and `processes.unpackaged_listeners` `absent` naming the socket; any fd table `denied` → both leaves `denied`.
- **W-9 (package status vocabulary).** `packaged`, `unpackaged`, `snap` (`/snap/*`), `flatpak` (`/var/lib/flatpak/*`, `/home/*/.local/share/flatpak/*`), `appimage` (`/tmp/.mount_*`), `foreign_ns`, `no_index`. `processes.unpackaged_listeners` holds one row per (listener, owner) with status ∈ {unpackaged, snap, flatpak, appimage, foreign_ns}; `deleted` is control 3's and is not repeated.
- **W-10 (service string).** `"<tcp|udp>/<port>"`, lower-case, exact; `tcp6`/`udp6` table rows fold to `proto` + `family`. Default `allowed_ports` `["tcp/22", "udp/68", "udp/546"]`.
- **W-11 (sysctl keys).** The 27 `net.sysctl.*` keys of spec P-4 with the paths it lists: 26 are `setting<int>` `default_on: effective` (24 judged by `checks`, the two `disable_ipv6` read by the IPv6 controls' `applies_when`) and `ipv6_bindv6only` is an `int` evidence key the process collector reads for P-3. A missing `/proc/sys/net/ipv6/...` file reads `absent` "IPv6 is not built or is disabled". `parseSysctlD` learns a glob key (`net.ipv4.conf.*.rp_filter = 2`) and the exclusion form (`-net.ipv4.conf.all.rp_filter`, no `=`); the winner for a concrete key is the last concrete assignment, else the last glob that matches and does not exclude it.
- **W-12 (registry).** 36 new keys `since: 1` (9 `processes.*`/`exposure.*` + 27 `net.sysctl.*`), `schema_version` unchanged; `firewall.rules` gains eight record fields (C2); `sockets.listening`'s description drops "pid and executable" (description-only golden change, said in the commit). `go test ./internal/facts -run TestFactsSchemaGolden -update` after each registry change; review the diff.
- **W-13 (controls).** Thirteen controls as spec §4, ids `muster.beyond.<name>`, `category: beyond`, `env.container eq none` gate, `automation: auto`, `requires_facts: ">=1"`, descriptions in English and Korean in muster's words, references exactly as spec §4 (every id in `docs/reference`; lint rejects an unknown one). Fixtures carry no param overrides (3C-2a V-13); parameters are proven in `internal/check/exposure_controls_test.go` through `Options.Params`. `controls/VERSION` → `kisa-unix-2026+2026.10.02`.
- **W-14 (fixtures).** Every fixture `synthetic: true`; every judged row carries every field (3C-2a V-9); `_expect` only `reason_code`/`exit_code`. The lists of spec §6 are the minimum. `_mutants.yaml` gains exactly the three `absent_means` rows of `no_deleted_executables` with the reason "written from /proc alone: ok, denied, unsupported, error or truncated, never absent".
- **W-15 (lab).** The lab is reached only through the session's read-only scripts; build and run only under `/root/muster-dev` and a `mkdir -m 0700` directory under `/tmp`; install nothing on the lab; public images only (`rockylinux/rockylinux:9-ubi-init`, `ubuntu:24.04`); never commit a snapshot, a host name, a user name or a fingerprint from the lab. `_hosts` snapshots are synthetic shapes.
- **W-16 (gates per task).** `gofmt -l .` empty; `go vet ./...` and `GOOS=linux GOARCH=amd64 go vet ./...`; Windows `go test ./... -count=1`; lab `go test ./internal/collect/... ./cmd/muster -count=1` as root; `go run ./cmd/muster controls lint --references docs/reference`; `go run ./tools/coverage -check` (regenerate when a control changed); `go test ./internal/controls -run 'TestEveryMutantIsKilled|Host' -count=1` zero survivors; `gitleaks git --log-opts="<BASE>..HEAD" --no-banner --redact`; the session's host-string grep over `git diff <BASE>..HEAD` returns 0 (the lab's names never enter a tracked file). Every function taking `[]byte` has a `Fuzz<Name>` with seeds (`TestEveryParserHasAFuzzTarget`, `fuzz_inventory_test.go:194`).
- **W-17 (commits).** Message in the imperative, body says why; trailers `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01LjfwtnJHSH7afTYL99Pmom`; never amend, rebase, stash, force-push or push. Linux-only files carry `//go:build linux`; parsers that take `[]byte` live in untagged files so their tests and fuzz targets run on Windows.
- **W-18 (work split).** Implementers write code, tests, fixtures, controls, registry entries, the matrix, the snapshots, the CI steps and the oracles; the controller writes the design documents, CLAUDE.md, README, CHANGELOG, D32 and the Execution notes (Task 8).

### Pre-flight rulings (W-19 … W-47; two fresh reviews of the plan, 2026-10-02 — these override a task step where they differ)

- **W-19 (controls carry titles and remediation — PK B-1).** Every control has `title_en`/`title_ko` and a `remediation` block (`text_en`, `text_ko`, `risk`, `idempotent`) as `kernel_pointer_exposure.yaml` does; `risk: none` for controls 1, 2 and the sysctl controls, `restart_service` for control 3. Lint rejects a control without them.
- **W-20 (`_mutants.yaml` rows — PK H-1, H-2).** Control 3: five rows — the three `absent_means → pass|not_applicable|manual` (reason: written from `/proc` alone, never absent) and `checks[0].where expected +1` / `expected -1` (reason: pids enumerated from `/proc/[0-9]*/status` are ≥ 1, so no snapshot carries the pid 0 or −1 element that separates `gte 1`/`gte -1` from `gte 0`). Each IPv6 control (5, 7, 9, 13): its three `absent_means` rows — the gate keys and the judged keys come from the one `/proc/sys/net/ipv6` tree and go `absent` together, and `applies_when` screens before `absent_means` (`eval.go` `screen`), so no collector-shaped snapshot reaches `absent_means` with the gate holding. Twelve + five = seventeen rows; spec §6's "every other control reaches absent through a fixture" is corrected in the Execution notes.
- **W-21 (the IPv6 N/A fixtures — PK H-3, RF-5).** Each IPv6 control carries `na-no-ipv6.json` (every `ipv6_*` key absent), `na-ipv6-disabled-all.json` (`all.disable_ipv6` 1, `default` 0) and `na-ipv6-disabled-default.json` (`all` 0, `default` 1), the last two with the judged keys present at kernel defaults so removing either gate clause lets the control be judged. Review Focus 5 names the two `disabled` fixtures.
- **W-22 (every `na-*` carries the judged keys — PK H-6).** Every `na-*` fixture (and the two `disabled` ones) carries every judged key — and, on the IPv6 controls, both gate keys — with `ok` values; a missing key reads `ERROR(missing_fact)`, which the mutation harness counts as no difference (G-22), so `applies_when[0] remove` would survive. `manual-*` and `na-*` carry no `_expect`.
- **W-23 (control 1's allow-list mutants — PK H-4).** `pass-dhcp-clients.json`: the X-9 shape with `exposure.exposed` rows `tcp/22`, `udp/68` (`0.0.0.0`) and `udp/546` (`::`), all in the default list (kills `allowed_ports drop[1]`/`drop[2]`). Every `fail-*` of control 1 exposes a service outside the default list (`fail-v6-unfiltered` on `::` is `tcp/8080`, not 22; `fail-link-local` is `fe80::1` `tcp/9100`).
- **W-24 (one clause per `fail-*`; both members of an `in` list — PK H-5).** On every sysctl control each `fail-*` fixture fails exactly one clause so `checks[i] remove` dies — control 6 therefore has six, control 10 four (all/default rp_filter 0; all/default log_martians 0), and so on. Control 10 has two PASS fixtures: `pass-strict` (rp_filter 1/1) and `pass-loose` (2/2), both with log_martians 1/1, so `in [1, 2]`'s `drop[0]`/`drop[1]` die; `fail-stock-ubuntu` (2/2, 0/0) is the pin. Control 4's FAIL is `fail-docker-host` (`ip_forward` 1 — stock Ubuntu PASSes), control 5's `fail-router`; the parameter tests use those.
- **W-25 (reason codes — PK M-1).** `error-nonroot` and `error-firewall-denied` expect `permission_denied`; `error-index-timeout` expects `timeout`; all `exit_code` 2.
- **W-26 (`subject_kind` — PK M-4).** `exposure.exposed` `port` (as `sockets.listening`); `processes.unpackaged_listeners` `file`; `processes.deleted_executables` none (the observation is `item:<pid>`). The vocabulary is closed (`registry.go`).
- **W-27 (e2e and `_hosts` keys — PK M-5).** The three e2e maps gain thirteen rows each (the waiver test's too); the comments' counts are recomputed by diffing the maps and stated. `full-pass.json`, `full-fail.json` and both `_hosts` snapshots gain the 29 keys the controls read — `exposure.exposed`, `processes.unpackaged_listeners`, `processes.deleted_executables` (`ok []` in the PASS shapes) and the 26 `net.sysctl.*` settings (runtime/persisted/effective sides as 3B's `kernel.sysctl.*`) — in the collectors' shapes copied from the collectors' tests; `_hosts` needs no `firewall.rules` rows (no beyond control reads them). `TestStockHostsPinTheBeyondVerdicts` is red between Task 6 Steps 2 and 4 by design; the `len(stockEL9) != 17` message changes with the count.
- **W-28 (README counts are a gate — PK M-6).** `tools/coverage -check` reads the README sentences: Task 6 Step 4 writes exactly "and 49 beyond the guide" (README.md) and "그리고 가이드 밖 49개" (README.ko.md); Task 8 touches prose only.
- **W-29 (examples — PK M-2).** Task 7 Step 6: dispatch `examples.yml` on the branch, fetch to the session scratchpad, copy into `examples/`, commit; Task 7's exposure assert and the Execution notes read the runner's `exposure.stats` from that run. The committed examples are ufw/`partial`/MANUAL today and read `full`/`false`/FAIL plus the new families after X-9.
- **W-30 (CI greps — PK M-7).** `ci.yml` gains `oracle sysctl: compared <N>` (the exact number from the first run — there is no sysctl grep today), `oracle listeners: compared [1-9]`, `oracle deleted-exe: compared 1`.
- **W-31 (parameter tests — PK L-5).** `internal/check/exposure_controls_test.go` uses the `embedded`/`one`/`reg` helpers of `walk_controls_test.go` (package `check`); every list parameter value is `[]any{…}` (`inList` needs `[]any`).
- **W-32 (`Builder.Begin` carries the declared facts — PC B-1).** `func (b *Builder) Begin(name string, facts ...string)`; `runCollector` calls `b.Begin(c.Name, c.Declare.Facts...)`; `Get` matches the key against `b.declared[b.current]` with `path.Match`, a Setting key is `(Envelope{}, false)`, no match panics `collect: <name> reads undeclared fact <key>`. `build` in `collectors_test.go` calls `b.Begin(name, c.Declare.Facts...)`; a new `buildOn(t, name, a, b *collect.Builder)` runs a collector on a builder the test prepared (guard and violation check as `build`); `TestEveryCollectorStaysInsideItsDeclaration` calls `Begin` with the facts and wraps `c.Run` in a `recover` that fails the test instead of the binary. Task 4's collector-level test seeds `firewall.*` with `b.Begin("firewall")` + `b.Set(...)` then `buildOn(t, "processes", a, b)`; the oracles seed the firewall facts from `runFirewall` on `collect.Host()` the same way. `Builder.Get` tests use `facts.LoadRegistry()`.
- **W-33 (chains are keyed by family, table and name — PC B-2).** `type chainKey struct{ Family, Table, Name string }`; `baseChain` gains `name, table` (nft: the `table <family> <name> {` and `chain X {` headers; iptables-save: `*table`, `:CHAIN`, `-A CHAIN`); `func foldChains(bases []baseChain, byChain map[chainKey][]fwRule) []fwRule` folds every base chain with `hook == "input" && chainType == "filter"`, resolving `jump X`/`goto X` to `chainKey{bc.family, bc.table, X}` only. Tests `TestFoldChainsKeepsFamiliesApart` (the same names in `v4` and `v6`; the user accept appears once per family) and `TestFoldChainsIgnoresANatChainOfTheSameName`. In the rows, `via_chain` + `family` identify a base chain.
- **W-34 (`pkgindex` keeps the walk's index whole — PC B-3).** The Interfaces block's `pkgindex` section is the one below, not the earlier sketch: the exported `DpkgIndex` (field for field the walk's), `RPMFile`, `Index{Family, Dpkg, RPM}`, `Index.Owner(path)` for the process collector, `Options{USRMerged, RPMTimeout, RPMMaxOutput}`, `Build(ctx, a, cands, opts)` (no `hdr`), `DetectFamily`, `RPMFileTable`, `DpkgReads`, `RPMReads`, `RPMCommand`. `collectors` keeps `var rpmCommand = pkgindex.RPMCommand`, `detectFamily` and `rpmFileTable` as one-line wrappers and `type rpmFile = pkgindex.RPMFile`, so `walk_join_test.go`, `walk_caps_test.go` and `walk_test.go` compile unchanged; `joinDpkg` passes `Options{USRMerged: plan.usrMerged}`; `decideBit`, the suid reference list and the postinst join stay in `collectors`. The Step-1 baseline is the 42 tests `-run 'Join|Walk|Caps'` selects today.
- **W-35 (the process collector reads the merged-/usr aliases — PC H-1).** The declaration lists `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32` (`usrAliases`) and `/var/lib/rpm`; `mountPlan.readUsrMerged`'s loop becomes a package-level `readUsrMerged(a) map[string]string` both callers use, and the map goes to `pkgindex.Options.USRMerged` — without it 22.04's `systemd.list` (`/lib/systemd/systemd-resolved`) never matches the resolved `exe` and control 2 FAILs falsely. Test `TestProcessesJoinsAPreMergeListPath`; the lab proof records `systemd-resolved`'s row.
- **W-36 (classifier order — PC H-2).** `deny` first (drop/reject, unmodelled or not); then `irrelevant` — `log`, `return`, `continue`, a folded `jump`/`goto`, or an accept whose `proto` is a literal other than tcp/udp — whatever `unmodelled` says (ufw's `before.rules` ICMP-type, `addrtype`, `limit` and `LOG` rows are all unmodelled and all irrelevant); then `loopback_only`; then `state_only`; then `port_rule`/`any_port` only when `!unmodelled`; else `opaque`. `TestClassifyRule` adds the unmodelled variants; the nft cases add the iptables-nft spellings (`iifname "lo" counter … accept`, `ct state related,established counter … accept`, `meta l4proto icmp icmp type destination-unreachable counter … accept`, `fib daddr type local counter … return`, `limit rate 3/minute burst 10 packets counter … jump ufw-logging-deny`, `meta l4proto tcp tcp dport 22 counter … accept`); `TestFirewallUfwBeforeRulesDecide` runs ufw's stock chains (`testdata/iptables-save.ufw-allow-80` and `testdata/nft.ruleset.ufw-allow-80`, `allow 22/tcp` and `allow 80/tcp`) through `normalizeRuleset`: no folded v4 INPUT row is `opaque` and exactly two `port_rule`s name 22 and 80; `TestExposureUfwDumpDecidesHTTP` feeds those rows to `decideExposure` with a listener on `0.0.0.0:80` → exposed `via rule`, `rule_chain ufw-user-input`.
- **W-37 (fuzz targets — PC M-1).** Every new target (`FuzzParsePortSpec`, `FuzzFoldChains`, `FuzzClassifyRule`, `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink`) lives in the linux-tagged `fuzz_test.go` and is added to `fuzzTargets`; `FuzzRPMFileTable` moves to `internal/pkgindex/fuzz_test.go` (no inventory test there) and the collectors' wrapper gets a `coveredThrough` row. W-17's last sentence reads: parsers in untagged files run their unit tests on Windows; their fuzz targets live in `fuzz_test.go` (linux) and are pinned in `fuzzTargets`.
- **W-38 (`firewall_fold.go` is untagged and standard-library only — PC M-2).** `parseNftRule`, `parseIptablesRule`, `nftPortSpec`, `baseChain`, `chainKey`, `fwRule`, `fwRuleFromRecord`, `record()`, `foldChains`, `classifyRule`, `parsePortSpec` move or are born there; the file imports only the standard library (and `facts` if a type needs it, never `collect`).
- **W-39 (`ipv6_bindv6only` is written apart — PC M-3).** 26 entries join `sysctlLeaves`; `ipv6_bindv6only` (an `int` envelope key) is written separately with `b.Set("net.sysctl.ipv6_bindv6only", readProcSys(a, "/proc/sys/net/ipv6/bindv6only"))`; `TestSysctlDeclarationCoversItsReads`'s want list gains the 27 paths; the sysctl oracle compares 26 more through `sysctlLeaves` (the exact count after the first run — W-30).
- **W-40 (`HasV6` and the rule round trip — PC M-4).** `socketTables` gains `v6 bool` (set when `tcp6` or `udp6` was read); `exposureInputs.HasV6` comes from it. `fwRuleFromRecord(m map[string]any) fwRule` (untagged, beside `record()`, `TestFwRuleRecordRoundTrips`) rebuilds the rules from `b.Get("firewall.rules").Value`.
- **W-41 (the index is built per collector — PC M-5).** The readers are shared; `processes` builds an index over its exes and the walk another over its findings; a `--deep` run streams the dpkg lists twice and runs the rpm query twice. A cached index on the Builder is parked until the measurement (Task 3 Step 6, Task 7 Step 1) says the cost matters. Recorded as a deviation from spec §2/X-4 in the Execution notes.
- **W-42 (a dying process — PC M-6).** An `exe` ENOENT on a `user`-kind process re-reads `status`: pid gone, or `State` `Z`/`X` → the row is dropped and `stats.vanished`++; a surviving `user` process with ENOENT is `exe_read_status: error`. `Kthread:` from `status` (6.x) classes a kernel thread, with pid 2 / PPid 2 as the fallback.
- **W-43 (lab proofs inside containers — PC M-7).** Installs (`openssh-server`, `iproute`) and `systemctl start firewalld` happen only inside a container started for the proof and removed after it, never on the lab host; `docker run --net=host ubuntu:24.04 sleep 300` binds no port. The EL9 container runs as CI does (`--privileged --cgroupns=host`); the unprivileged-container reading (root without CAP_SYS_PTRACE cannot readlink other processes' `exe` → `processes.listeners denied`) is a matrix `_notes` row in Task 7 Step 3 and corrects spec §5's container sentence in the Execution notes.
- **W-44 (confidence reads base chains only — PC M-8).** `hasRules`/`inboundPathHasRules`, `normalization_confidence` and `restricts_inbound` are computed from base chains as today; folded rows never change them (`TestFirewallFoldedRulesDoNotChangeConfidence`).
- **W-45 (the test double — PC M-9).** `fsAccess.Readlink` consults `fails[p]` first (as `Stat` does) so a denied `exe` can be driven; `Glob` + `deniedDirs` already follow `collect.GlobDir`.
- **W-46 (parser details — PC L-7, L-8, L-6, L-9).** `counter packets N bytes N` consumes its operands; `-j REJECT --reject-with …` and `-j LOG --log-prefix "…" --log-level N` are target options (inert); `-g X` → `goto X`; `-j X` with X ∉ {ACCEPT, DROP, REJECT, RETURN, LOG, QUEUE} → `jump X`; a jump whose target is not in `byChain` (`MARK`, `TCPMSS`, `CT`, …) sets `unmodelled`. `TestSysctlConcreteBeatsGlob` puts the glob in a LATER file than the concrete line (systemd skips a glob for any explicitly set key regardless of order). `mnt_ns` is `host`, `foreign`, or `""` with `ns_read_status` `denied`/`error` on the row (a denied `ns/mnt` is `denied` on the judged leaves like a denied `exe`). `processes.listeners` is capped at 2000 rows (spec P-1) — W-7.
- **W-47 (small corrections — PC L-1..L-5, N-2, N-4; PK L-1..L-4, N-1..N-4).** Spec §2 lists `net.sysctl.ipv6_bindv6only` under `Facts`; the plan reads it from `/proc/sys` instead (`sysctl` sorts after `processes`) — a deviation recorded in the notes. The `sockets.listening` description edit is Task 3's (with the registry; description-only, said in the commit). `Options.RPMTimeout` changes only `Command.Timeout`; `allowedCommand` compares Path+Args, so one declaration row and one `--list-actions` row serve both collectors. `TestOracleListeners` names `/usr/bin/ss` through `oracleBinary` and skips where it is absent (the UBI init image). The `hosts_test.go` EL9 message changes with the count. The CHANGELOG's "(was `+2026.09.29`)" is Task 8's. RF-5 names the two `disabled` fixtures driven by `TestEveryControlHasFixturesThatBehave`; the Ubuntu `_hosts` snapshot (IPv6 on; controls 7 and 13 FAIL) is the counter-pin.

## Review Focus

1. A hand-written ruleset `policy drop; iif lo accept; ct state established,related accept; tcp dport 22 accept` with a listener on `0.0.0.0:5432` must read 5432 `filtered` and control 1 PASS — the test `TestExposureStateAndLoopbackAcceptsDoNotExpose` in Task 4.
2. ufw enabled with `ufw allow 80/tcp` and nginx on `:80`: the fold must surface the depth-2 accept and control 1 FAIL; with 22 alone, PASS — `TestFirewallFoldsUfwChains` (Task 2) and `fail-ufw-folded-http.json` (Task 6).
3. A `socket-activated` sshd on 24.04: pid 1 and sshd both own `tcp/22`; control 2 PASS, `owners` has both — `TestProcessesListenerOwnedByTwoProcesses` (Task 3).
4. A `--net=host` container's nginx: `mnt_ns: foreign` → control 2 FAIL with `package_status: foreign_ns`, never `packaged` because the host also ships `/usr/sbin/nginx` — `TestProcessesForeignMountNamespaceIsNotLookedUp` (Task 3).
5. `disable_ipv6 = 1` on all/default with IPv6 files present at defaults: controls 5, 7, 9, 13 NOT_APPLICABLE, not FAIL — `na-ipv6-disabled.json` per IPv6 control (Task 6).

---

## File Structure

- Create `internal/pkgindex/pkgindex.go` (untagged types: `Family`, `Lookup`, `Owner`), `internal/pkgindex/dpkg.go`, `internal/pkgindex/rpm.go` (linux-tagged readers moved from the walk's join), `internal/pkgindex/*_test.go`.
- Modify `internal/collect/collectors/walk_join.go`, `walk_join_dpkg.go`, `walk_join_rpm.go` to call `pkgindex` (behaviour preserved; the walk's tests unchanged and green).
- Modify `internal/collect/registry.go` (`Declaration.Facts`, `Action` kind `fact`, `ListActions`), `internal/collect/facts.go` (`Builder.Get`), `internal/collect/registry_test.go`.
- Modify `internal/collect/collectors/firewall.go` (record fields, selectors, fold, family filter, X-9) + `firewall_fold.go` (untagged: `foldChains`, `classifyRule`, `parsePortSpec`), `firewall_test.go`, `fuzz_test.go` seeds.
- Create `internal/collect/collectors/processes.go` (linux: enumeration, owners, index join, `exposure.*`), `processes_parse.go` (untagged: `parseProcStatus`, `parseCmdline`, `parseFdLink`, `stripDeleted`, `packageStatusFor`), `exposure.go` (untagged: `decideExposure`, `serviceOf`, `isLoopback`, `isLinkLocal`), `processes_test.go`, `exposure_test.go`.
- Modify `internal/collect/collectors/sysctl_parse.go` (27 leaves, glob keys, exclusions), `sysctl.go` (the IPv6 reason), `sysctl_test.go`.
- Modify `internal/facts/registry.yaml` (+36 keys, 2 description edits), golden.
- Create `controls/beyond/{exposed_listeners_allowed,listeners_packaged,no_deleted_executables,ip_forwarding_disabled,ipv6_forwarding_disabled,icmp_redirects_ignored,ipv6_redirects_ignored,source_routing_rejected,ipv6_source_routing_rejected,reverse_path_filtering,icmp_broadcast_and_bogus_ignored,syn_cookies_enabled,ipv6_router_advertisements_ignored}.yaml` and their `controls/testdata/muster.beyond.<id>/` fixtures; modify `controls/testdata/_mutants.yaml`, `controls/testdata/muster.file.ip_port_restriction/fail-ufw-inactive.json` (new), `controls/VERSION`, `cmd/muster/e2e_test.go` + `testdata/full-*.json`, `internal/check/exposure_controls_test.go` (new), `controls/testdata/_hosts/*.json`, `internal/controls/hosts_test.go`.
- Modify `docs/reference/capability-matrix.json`, `.github/workflows/ci.yml`, `cmd/muster/collect_test.go`, `internal/collect/collectors/oracle_test.go`, `docs/reference/coverage.md`.
- Controller (Task 8): `docs/superpowers/specs/2026-09-02-muster-design.md` (+`.ko.md`) D32/§10.2, `CLAUDE.md`, `README.md`/`README.ko.md`, `CHANGELOG.md`, this plan's Execution notes.

## Interfaces

```go
// internal/pkgindex (Task 1) — linux-tagged except parse.go. The walk's join and the process collector share
// the readers; the VERDICT logic (decideBit, the suid list, postinst) stays in collectors. (W-34)
type Family string // "dpkg" | "rpm" | "none"
type StatOverride struct{ User, Group string; Mode int }
type DpkgIndex struct { // the walk's dpkgIndex, exported field for field
    Owner, DeclaredPath, ListPath, ListFile map[string]string
    Overrides map[string]StatOverride; Versions map[string]string
}
type RPMFile struct{ Pkg, Owner, Group, Caps string; Mode int }
type Index struct{ Family Family; Dpkg *DpkgIndex; RPM map[string]RPMFile }
func (ix Index) Owner(path string) (pkg string, ok bool) // the one lookup the process collector needs
type Options struct{ USRMerged map[string]string; RPMTimeout time.Duration; RPMMaxOutput int64 } // zero → the walk's 120 s / 256 MiB
// Build: DetectFamily (dpkg status → dpkg; /var/lib/rpm present → rpm; else none + Absent("no package database"));
// dpkg: ReadDiversions/ReadLists/ReadOverrides/ReadVersions for exactly cands (the walk's wantedPaths shape,
// every path canonicalised through pkgfiles.CanonicalUsr(p, opts.USRMerged)); rpm: RPMCommand with opts' timeout
// and cap, then RPMFileTable. Returns the failure envelope (path-prefixed, as dpkgJoin.read does) and truncated.
func Build(ctx context.Context, a collect.Access, cands map[string]bool, opts Options) (Index, bool /*truncated*/, *facts.Envelope)
func DetectFamily(a collect.Access) Family
func RPMFileTable(stdout []byte, cands map[string]bool, truncated bool) (map[string]RPMFile, error)
var DpkgReads = []string{"/var/lib/dpkg/info/*.list", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/diversions", "/var/lib/dpkg/status"}
var RPMReads  = []string{"/var/lib/rpm"} // DetectFamily stats it
var RPMCommand = collect.Command{Path: "/usr/bin/rpm", Args: …the walk's six-field query…, Timeout: 120 * time.Second, MaxOutput: 256 << 20}

// internal/collect (Task 1)
type Declaration struct{ Reads []string; Commands []Command; Needs string; Walk bool; Facts []string }
func (b *Builder) Begin(name string, facts ...string) // W-32: the globs this collector may Get; runCollector passes c.Declare.Facts
func (b *Builder) Get(key string) (facts.Envelope, bool) // panics "collect: <collector> reads undeclared fact <key>" outside the current collector's facts; a Setting key is (Envelope{}, false)
// collectors_test.go: build(t, name, a) calls b.Begin(name, c.Declare.Facts...); buildOn(t, name, a, b) runs a collector on a prepared builder (W-32)
// Action.Kind gains "fact"; ListActions prints one row per declared fact glob.

// firewall (Task 2) — untagged helpers in firewall_fold.go
type fwRule struct{ Chain, ViaChain string; Depth int; Family, Proto, Dport, Saddr, Daddr, Iif, Ctstate, Action string; Unmodelled bool; Raw string }
func (r fwRule) record() map[string]any // the 13-field row
func fwRuleFromRecord(m map[string]any) fwRule // the inverse, for b.Get("firewall.rules") (W-40)
type chainKey struct{ Family, Table, Name string } // W-33: a chain name is unique only within (family, table)
// baseChain gains name, table (W-33)
func foldChains(bases []baseChain, byChain map[chainKey][]fwRule) []fwRule // every input filter base chain; depth ≤ 4, ≤ 2000 per base, visited once; jump/goto resolve within the base's family and table
type ruleClass string // deny | port_rule | any_port | loopback_only | state_only | irrelevant | opaque
func classifyRule(r fwRule) ruleClass
type portSpec struct{ Ranges [][2]int; Members []int; Unmodelled bool }
func parsePortSpec(s string) portSpec // "22" | "1000-2000" | "1000:2000" | "{ 22, 80 }" | "22,80,443" | names/@sets → Unmodelled
func (p portSpec) matches(port int) bool

// processes (Tasks 3–4) — untagged parsers in processes_parse.go / exposure.go
type procStatus struct{ Name string; PPid, Uid int; State string }
func parseProcStatus(data []byte) (procStatus, error)
func parseCmdline(data []byte) string // first NUL-separated token, 4 KiB cap
func parseFdLink(target string) (inode int, ok bool) // "socket:[12345]" → 12345
func stripDeleted(target string) (exe string, deleted bool)
func packageStatusFor(exe string, mntNS string, idx pkgindex.Index) (pkg, status string)
type listener struct{ Proto, Family, Addr string; Port int; Loopback, LinkLocal bool; Inode int; OwnerStatus string; Owners []owner }
type owner struct{ Pid, Uid int; Name, Exe string; ExeDeleted bool; MntNS, Package, PackageStatus string }
type exposureInputs struct{ Confidence string; Restricts *bool; Rules []fwRule; Backend string; BindV6Only int; HasV6 bool } // HasV6 from socketTables.v6 (W-40)
type exposureRow struct{ Service, Proto, Family, Addr string; Port int; LinkLocal bool; Owners []owner; Exposed bool; Via, RuleChain, RuleSource, RuleRaw string }
func decideExposure(ls []listener, in exposureInputs) (rows []exposureRow, exposed []exposureRow, opaque []fwRule, manualReason string)
func serviceOf(proto string, port int) string // "tcp/22"
func isLoopback(addr string) bool; func isLinkLocal(addr string) bool

// sysctl (Task 5)
// sysctlLeaves gains 27 entries {leaf, sysctlKey{key, path}}; parseSysctlD returns sysctlAssign{key, value, glob bool, exclude bool}
```

---

### Task 1: `pkgindex` extraction, `Builder.Get`, `Declaration.Facts`

**Files:**
- Create: `internal/pkgindex/pkgindex.go`, `internal/pkgindex/dpkg.go`, `internal/pkgindex/rpm.go`, `internal/pkgindex/pkgindex_test.go`
- Modify: `internal/collect/collectors/walk_join.go`, `walk_join_dpkg.go`, `walk_join_rpm.go`, `walk_caps.go` (the postinst lookup uses `Owner.ListFile`)
- Modify: `internal/collect/registry.go` (`Declaration.Facts`, `Action` kind `fact`, `ListActions`), `internal/collect/facts.go` (`Get`), `internal/collect/registry_test.go`, `internal/collect/facts_test.go`
- Test: `internal/collect/collectors/walk_join_test.go` (unchanged and green), `cmd/muster/collect_test.go` (list-actions gains nothing yet — the walk's rows are the same)

**Interfaces:** Produces `pkgindex.Build`, `pkgindex.Index`, `Declaration.Facts`, `Builder.Get`, `Action{Kind: "fact"}`.

- [ ] **Step 1: Pin the walk's join before moving it.** Run `go test ./internal/collect/collectors -run 'Join|Walk|Caps' -count=1 -v 2>&1 | grep -c '^--- PASS'` on the lab and record the count in the report; these tests must pass unchanged after the move.
- [ ] **Step 2: Write the failing Builder tests** in `internal/collect/facts_test.go`:

```go
func TestBuilderGetReadsADeclaredFact(t *testing.T) {
	reg := testRegistry(t) // a registry with firewall.backend and exposure.stats
	b := NewBuilder(reg)
	b.Begin("firewall")
	b.Set("firewall.backend", facts.Envelope{Status: facts.StatusOK, Value: "ufw"})
	b.Begin("processes")
	b.declared = map[string][]string{"processes": {"firewall.*"}} // set by Run from the collector's Declaration
	e, ok := b.Get("firewall.backend")
	if !ok || e.Value != "ufw" {
		t.Fatalf("Get = %+v %v", e, ok)
	}
	if _, ok := b.Get("firewall.nothing"); ok {
		t.Error("a key never set must not be found")
	}
}

func TestBuilderGetOutsideTheDeclarationPanics(t *testing.T) {
	b := NewBuilder(testRegistry(t))
	b.Begin("processes")
	b.declared = map[string][]string{"processes": {"firewall.*"}}
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "undeclared fact") {
			t.Fatalf("recover = %v", r)
		}
	}()
	b.Get("net.sysctl.ipv4_ip_forward")
}
```

- [ ] **Step 3: Run them** (`go test ./internal/collect -run TestBuilderGet -count=1`): FAIL — `Get` undefined.
- [ ] **Step 4: Implement.** `Declaration` gains `Facts []string`; `Builder` gains `declared map[string][]string` filled by `runCollector` from `c.Declare.Facts` under `c.Name`; `Get` matches `key` against the current collector's globs with `path.Match` (a glob `firewall.*` matches `firewall.backend`; `*` does not cross `.` — document that one glob per family is the idiom) and returns `b.leaf(key)` as an envelope (a `facts.Setting` is returned as its effective side — only envelopes are declared here; a setting key in `Facts` is a lint error of the declaration test). `ListActions` emits `Action{Collector, Kind: "fact", Target: glob, Needs}` per declared glob. `TestEveryCollectorStaysInsideItsDeclaration` gains: for every collector, every `Facts` glob names a family whose collector sorts before it (`TestDeclaredFactsAreWrittenBeforeTheyAreRead`, in `collectors_test.go`, using `collect.All()` order and the registry's `collector:` field).
- [ ] **Step 5: Extract `pkgindex`.** Move `dpkgIndex`, `newDpkgIndex`, `readLists`, `readDiversions`, `readOverrides`, `readVersions`, `wantedPaths`, `dpkgListPackage`, `listEntryFor`, `dpkgListKey` and `rpmFileTable`/`rpmCommand` into `internal/pkgindex` (linux-tagged files `dpkg.go`, `rpm.go`; the parsers that take `[]byte` — `rpmFileTable`'s line loop over `pkgfiles.ParseRPMFileLine`, the `.list` reader — into an untagged `parse.go` with `FuzzDpkgList`/`FuzzRPMTable` seeds moved from the collectors' fuzz tests). `Build` keeps the walk's behaviour: `detectFamily` (dpkg status file → dpkg; rpm binary → rpm; else `none` with the `absent("no package database")` envelope), the same read limits (`dpkgJoinReadLimit`), the `truncated` flag. The walk's join calls `pkgindex.Build` and keeps `decideBit`/the suid reference list in the collectors package (they are the walk's verdict logic, not the index). `walk_caps.go`'s `readPostinst(listFile)` takes `Owner.ListFile`.
- [ ] **Step 6: Run the walk's tests on the lab** — the Step 1 count unchanged, `go test ./internal/collect/... -count=1` green; Windows `go test ./internal/pkgindex -count=1` green (the untagged parsers); `go run ./cmd/muster collect --list-actions` output unchanged for `walk` (compare before/after on the lab: `diff <(old) <(new)` empty).
- [ ] **Step 7: Gates (W-16) and commit:** `Extract the package index the walk's join builds into internal/pkgindex, and let a collector read a declared fact of an earlier one`.

### Task 2: The firewall collector grows (X-8, X-9)

**Files:**
- Create: `internal/collect/collectors/firewall_fold.go` (untagged), `firewall_fold_test.go`
- Modify: `internal/collect/collectors/firewall.go` (`parseNftRule`, `parseIptablesRule`, `parseNftRuleset`, `parseIptablesSave`, `normalizeRuleset`, `runFirewall`'s confidence switch), `firewall_test.go`, `fuzz_test.go` (seeds), `internal/facts/registry.yaml` (`firewall.rules` description), the facts golden
- Create: `controls/testdata/muster.file.ip_port_restriction/fail-ufw-inactive.json`; Modify: `controls/file/ip_port_restriction.yaml` description (the inactive-backend sentence, EN/KO)

**Interfaces:** Produces `fwRule`, `foldChains`, `classifyRule`, `parsePortSpec` (consumed by Task 4).

- [ ] **Step 1: Failing parser tests** (`firewall_fold_test.go`, untagged — these run on Windows):

```go
func TestParseNftRuleRecordsSelectors(t *testing.T) {
	cases := []struct{ line string; want fwRule }{
		{`iif "lo" accept`, fwRule{Iif: "lo", Action: "accept"}},
		{`ct state established,related accept`, fwRule{Ctstate: "established,related", Action: "accept"}},
		{`ip daddr 224.0.0.251 accept`, fwRule{Daddr: "224.0.0.251", Action: "accept"}},
		{`tcp dport 22 accept`, fwRule{Proto: "tcp", Dport: "22", Action: "accept"}},
		{`meta l4proto { tcp, udp } th dport 53 accept`, fwRule{Dport: "53", Action: "accept", Unmodelled: true}},
		{`tcp dport vmap { 22 : accept, 80 : drop }`, fwRule{Proto: "tcp", Unmodelled: true}},
		{`jump ufw-before-input`, fwRule{Action: "jump ufw-before-input"}},
		{`counter packets 0 bytes 0 accept`, fwRule{Action: "accept"}}, // counter is inert
		{`meta mark 0x1 accept`, fwRule{Action: "accept", Unmodelled: true}},
	}
	for _, c := range cases {
		got := parseNftRule("INPUT", strings.Fields(c.line))
		got.Raw, got.Chain = "", ""
		if got != c.want { t.Errorf("%q: got %+v want %+v", c.line, got, c.want) }
	}
}

func TestParseIptablesRuleRecordsSelectors(t *testing.T) {
	cases := []struct{ line string; want fwRule }{
		{`-A INPUT -i lo -j ACCEPT`, fwRule{Iif: "lo", Action: "accept"}},
		{`-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT`, fwRule{Ctstate: "related,established", Action: "accept"}},
		{`-A INPUT -p tcp -m multiport --dports 22,80,443 -j ACCEPT`, fwRule{Proto: "tcp", Dport: "22,80,443", Action: "accept"}},
		{`-A INPUT -p tcp -m tcp --dport 1000:2000 -j ACCEPT`, fwRule{Proto: "tcp", Dport: "1000:2000", Action: "accept"}},
		{`-A INPUT -d 198.51.100.1/32 -j ACCEPT`, fwRule{Daddr: "198.51.100.1/32", Action: "accept"}},
		{`-A INPUT -j ufw-before-input`, fwRule{Action: "jump ufw-before-input"}},
		{`-A INPUT -m owner --uid-owner 0 -j ACCEPT`, fwRule{Action: "accept", Unmodelled: true}},
	}
	// … as above
}

func TestFoldChainsReachesUfwUserInput(t *testing.T) {
	by := map[string][]fwRule{
		"INPUT":            {{Chain: "INPUT", Action: "jump ufw-before-input"}, {Chain: "INPUT", Action: "jump ufw-after-input"}},
		"ufw-before-input": {{Chain: "ufw-before-input", Iif: "lo", Action: "accept"}, {Chain: "ufw-before-input", Action: "jump ufw-user-input"}},
		"ufw-user-input":   {{Chain: "ufw-user-input", Proto: "tcp", Dport: "80", Action: "accept"}},
		"ufw-after-input":  {},
	}
	rows := foldChains([]baseChain{{hook: "input", family: "v4"}}, by, []string{"INPUT"})
	var depths []int
	for _, r := range rows { if r.Dport == "80" { depths = append(depths, r.Depth); if r.ViaChain != "INPUT" { t.Error(r.ViaChain) } } }
	if !slices.Equal(depths, []int{2}) { t.Fatalf("depths %v", depths) }
}

func TestFoldChainsStopsAtDepthAndMarksTheJump(t *testing.T) { /* a 6-deep chain: the depth-5 jump row is Unmodelled and nothing deeper appears */ }
func TestFoldChainsVisitsACycleOnce(t *testing.T) { /* A→B→A */ }
func TestFoldChainsBudget(t *testing.T) { /* 2001 rules in a jumped chain → 2000 rows and the jump row Unmodelled */ }

func TestClassifyRule(t *testing.T) {
	cases := []struct{ r fwRule; want ruleClass }{
		{fwRule{Action: "drop"}, "deny"},
		{fwRule{Action: "accept", Proto: "tcp", Dport: "22"}, "port_rule"},
		{fwRule{Action: "accept"}, "any_port"},
		{fwRule{Action: "accept", Iif: "lo"}, "loopback_only"},
		{fwRule{Action: "accept", Ctstate: "established,related"}, "state_only"},
		{fwRule{Action: "accept", Ctstate: "new,established", Proto: "tcp", Dport: "22"}, "port_rule"},
		{fwRule{Action: "accept", Proto: "icmp"}, "irrelevant"},
		{fwRule{Action: "jump ufw-user-input"}, "irrelevant"},
		{fwRule{Action: "log"}, "irrelevant"},
		{fwRule{Action: "accept", Unmodelled: true}, "opaque"},
		{fwRule{Action: "accept", Daddr: "198.51.100.1"}, "opaque"},
		{fwRule{Action: ""}, "opaque"},
	}
	// …
}

func TestParsePortSpec(t *testing.T) {
	// "22" matches 22 only; "1000-2000" and "1000:2000" contain 1500 not 2001; "{ 22, 80 }" and "22,80,443" members; "ssh" and "@ports" Unmodelled; 257 members Unmodelled
}
```

- [ ] **Step 2: Run** `go test ./internal/collect/collectors -run 'TestParseNftRule|TestParseIptablesRule|TestFoldChains|TestClassifyRule|TestParsePortSpec' -count=1` on Windows: FAIL (undefined).
- [ ] **Step 3: Implement** `fwRule`, `record()`, `parsePortSpec`, `classifyRule`, `foldChains` in `firewall_fold.go`; rewrite `parseNftRule`/`parseIptablesRule` to return `fwRule` reading `iif`/`iifname`/`-i`, `ct state`/`-m conntrack --ctstate`/`-m state --state`, `ip daddr`/`ip6 daddr`/`-d`, `meta l4proto`/`ip protocol`/`ip6 nexthdr`/`-p`, `--dports`/`--sports` (multiport), the brace sets through `nftPortSpec`, and set `Unmodelled` for any remaining token that is not in the inert list (`counter`, `packets`, `bytes`, `comment "…"`, `-m tcp`, `-m udp`, `-m multiport`, `--sport`, `-m comment --comment …`); keep `Raw` (512 bytes). `parseNftRuleset` keeps every chain's rules in `byChain` (not only base/input), records table family per chain, skips `bridge`/`arp`/`netdev` tables; `parseIptablesSave` likewise keeps user chains (`-A <chain>`); `normalizeRuleset` folds through `foldChains` and emits `record()` rows for the folded set of every input base chain. The confidence switch: `case len(inputs) == 0 && !inboundPathHasRules:` → `full`, `restricts = collect.OK(false, cr.src)` with the reason text "no input base chain and no inbound rule: nothing restricts inbound" when `name != "none"` (X-9). Every other branch unchanged.
- [ ] **Step 4: Collector tests** (`firewall_test.go`, linux-tagged, lab): `TestFirewallFoldsUfwChains` (an `iptables-save` fixture of ufw with `allow 80/tcp`: `firewall.rules` holds the depth-2 accept with `via_chain INPUT`), `TestFirewallInactiveUfwNormalisesFull` (ufw installed, `ENABLED=no`, empty tables → `normalization_confidence full`, `restricts_inbound ok false`), `TestFirewallBridgeTableIsIgnored`, existing tests adapted to the 13-field rows (every existing fixture's rows gain the new fields with `""`/`false`).
- [ ] **Step 5: U-28 fixture.** `controls/testdata/muster.file.ip_port_restriction/fail-ufw-inactive.json`: `firewall.backend ufw`, `normalization_confidence full`, `restricts_inbound ok false`, `rules []`, `files.etc_hosts_deny_all false`, `libwrap_present false` → FAIL (mechanism 2). Update the control's descriptions (EN/KO) with one sentence: an installed but inactive ufw/firewalld/nftables is no firewall and FAILs. Mutation test zero survivors.
- [ ] **Step 6: Registry.** `firewall.rules` description names the thirteen fields and the fold; golden regenerated (description + the row shape is not in the golden — record fields are not schema; say "description-only" in the commit if the diff is only text).
- [ ] **Step 7: Fuzz seeds** for `FuzzParseNftRuleset` / `FuzzParseIptablesSave` gain the lines of Step 1; new `FuzzParsePortSpec`, `FuzzFoldChains` (a synthetic dump → fold; must not loop or allocate past the budget).
- [ ] **Step 8: Lab proof (read-only).** `lab-run.sh` dumps the lab's ruleset (`iptables-save`, `nft list ruleset`), the implementer runs `muster collect` to a 0700 dir and compares `firewall.rules` with the dump by eye: every accept of every user chain reached from INPUT appears once with the right depth; record counts in the report.
- [ ] **Step 9: Gates and commit:** `Fold the firewall's user chains and record each rule's family, selectors and text; an inactive backend restricts nothing`.

### Task 3: The `processes` collector (P-1)

**Files:**
- Create: `internal/collect/collectors/processes.go` (linux), `processes_parse.go` (untagged), `processes_test.go`, `processes_parse_test.go`, `testdata/proc_status_sshd`, `testdata/proc_status_kthread`, `testdata/proc_status_zombie`
- Modify: `internal/facts/registry.yaml` (+5 `processes.*` keys), golden; `collectors_test.go` (`fsAccess` gains `links` for `/proc/*/exe`, `/proc/*/fd/*`, `/proc/*/ns/mnt` — already a map; `deniedDirs` for an unreadable fd table)

**Interfaces:** Consumes `pkgindex.Build`, `listeningSockets` (sockets.go). Produces `listener`, `owner`, `processes.*` keys (consumed by Task 4).

- [ ] **Step 1: Failing parser tests** (untagged): `parseProcStatus` on the three fixtures (Name/PPid/Uid/State), `parseCmdline` (NUL split, 4 KiB cap, empty), `parseFdLink` (`socket:[123]` → 123; `pipe:[4]`, `/dev/null`, `anon_inode:[eventpoll]` → !ok), `stripDeleted` (`/usr/sbin/nginx (deleted)` → deleted; `/memfd:x (deleted)` → deleted; plain path → false), `packageStatusFor` (`/snap/lxd/1/bin/lxd` → `snap:lxd`/`snap`; `/var/lib/flatpak/app/x` → flatpak; `/tmp/.mount_abc/AppRun` → appimage; foreign → `foreign_ns` without consulting the index — use a stub index that panics when asked).
- [ ] **Step 2: Failing collector tests** (linux, `processes_test.go`), through `build(t, "processes", a)` with an `fsAccess` whose `files` hold `/proc/<pid>/status`, `/proc/<pid>/cmdline`, `/proc/self/net/*` tables, `links` hold `/proc/<pid>/exe`, `/proc/<pid>/fd/N`, `/proc/<pid>/ns/mnt`, `/proc/1/ns/mnt`, and `cmds`/`files` hold the index inputs:
  - `TestProcessesListsUserKernelAndZombie` (kinds; `exe_read_status`; `exe_deleted`);
  - `TestProcessesListenerOwnedByTwoProcesses` (pid 1 and sshd hold inode 7 → `owners` two rows, sorted);
  - `TestProcessesInodeZeroIsUnmatchedNotKernel` (inode 0 → `unmatched`, W-89);
  - `TestProcessesUnmatchedSocketMakesTheLeavesAbsent` (inode 99 held by nobody → `processes.listeners` and `unpackaged_listeners` absent naming `tcp/2049`);
  - `TestProcessesDeniedFdTableMakesTheLeavesDenied` (`deniedDirs["/proc/42/fd"]`);
  - `TestProcessesDeniedExeMakesDeletedExecutablesDenied`;
  - `TestProcessesForeignMountNamespaceIsNotLookedUp` (ns differs; the index would own the path; status `foreign_ns`);
  - `TestProcessesUnpackagedListenerRows` (one row per listener×owner with status in W-9; a `deleted` owner not repeated);
  - `TestProcessesNoPackageDatabaseIsAbsent` (no dpkg status, no rpm → `unpackaged_listeners` absent "no package database"; `package_status no_index` on rows);
  - `TestProcessesFdBudgetOverrunIsAnError` (65537 fd links);
  - `TestProcessesMaskedProcIsUnsupported`;
  - `TestProcessesListIsTruncatedPast4096`.
- [ ] **Step 3: Run** → FAIL (no collector).
- [ ] **Step 4: Implement** `processes.go`: `Declare: collect.Declaration{Reads: append([]string{"/proc/[0-9]*/status", "/proc/[0-9]*/cmdline", "/proc/[0-9]*/exe", "/proc/[0-9]*/fd/*", "/proc/[0-9]*/ns/mnt", "/proc/1/ns/mnt", "/proc/sys/net/ipv6/bindv6only"}, append(procNetPaths(), pkgindex.DpkgReads...)...), Commands: []collect.Command{pkgindex.RPMCommand}, Facts: []string{"firewall.*"}, Needs: "none"}`. Enumerate pids from the status glob; read status/cmdline/exe/ns per pid with a `time.Since(start) > 5s` check per process; sockets through `listeningSockets(a)`; fd tables per `user`/`zombie` pid, `parseFdLink` → inode → owners; the index via `pkgindex.Build(ctx, a, b.Header(), cands, pkgindex.Options{RPMTimeout: 30 * time.Second})` where `cands` is the set of distinct `host` exes; write the five keys and `processes.stats`. Registry entries per spec P-1 (descriptions in muster's words), `since: 1`.
- [ ] **Step 5: Fuzz** `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink` with seeds.
- [ ] **Step 6: Lab proof.** Root collect to a 0700 dir: count rows, kinds, `owner_status` values, `index_source`, `elapsed_ms`, `index_ms` (the X-4 measurement — record it); non-root collect as `nobody` (`runuser -u nobody -- sh -c 'umask 077; mkdir /tmp/p-$$ && …'`): the three judged leaves `denied`. In `rockylinux/rockylinux:9-ubi-init` with `openssh-server`: `index_source rpm`, `index_ms`, the sshd row `packaged`. A `docker run --net=host ubuntu:24.04 sleep 300` on the lab: its row reads `mnt_ns foreign` from the host's collect, and its `exe` carries no `(deleted)`.
- [ ] **Step 7: Gates and commit:** `Add the processes collector: every process, every listening socket's owners, and the package each executable came from`.

### Task 4: `exposure.*` (P-3)

**Files:**
- Create: `internal/collect/collectors/exposure.go` (untagged: `decideExposure`, `serviceOf`, `isLoopback`, `isLinkLocal`), `exposure_test.go`
- Modify: `processes.go` (reads `firewall.*` through `b.Get`, `/proc/sys/net/ipv6/bindv6only` through `a.ReadFile`, writes `exposure.*`), `internal/facts/registry.yaml` (+4 `exposure.*` keys), golden

**Interfaces:** Consumes `fwRule`, `classifyRule`, `parsePortSpec`, `Builder.Get`. Produces `exposure.*` keys.

- [ ] **Step 1: Failing tests** (untagged `exposure_test.go` over `decideExposure`): `TestExposureStateAndLoopbackAcceptsDoNotExpose` (Review Focus 1), `TestExposureOpenPolicyExposesEveryNonLoopback`, `TestExposureAnyPortRule`, `TestExposurePortRuleRangeAndSet`, `TestExposureOpaqueRuleIsManual` (manualReason names chain and raw), `TestExposurePartialConfidenceIsManual`, `TestExposureNoChainInFamilyExposesV6` (v4 base chain only, HasV6, a `::` listener → exposed `via no_chain_in_family`), `TestExposureInetChainCoversBoth`, `TestExposureDualStackBindAsksBothFamilies` (`::` with `BindV6Only 0` exposed by a v4 rule; with 1 not), `TestExposureLinkLocalIsACandidate`, `TestExposureLoopbackNeverListed`, `TestExposureServiceSpelling` (`tcp6` row → `tcp/22`), `TestExposureIrrelevantRulesDoNotBlock` (icmp accept beside port rules → decided).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** `decideExposure` per W-5/W-6 and spec P-3; in `processes.go` after the listeners: `conf, _ := b.Get("firewall.normalization_confidence")` etc.; the firewall's status other than `ok` → every `exposure.*` key carries it (`unsupported` → NOT_APPLICABLE through the evaluator; `denied` → ERROR); `processes.listeners` not `ok` → `exposure.exposed` carries that status; `manualReason != ""` → `exposure.exposed` `absent` with the reason and `exposure.stats.manual_reason`; `truncated` propagated. Registry entries per spec P-3.
- [ ] **Step 4: Collector-level test** (linux): `TestProcessesWritesExposureFromTheFirewallFacts` — a double that pre-seeds the builder with firewall facts (call `runFirewall` on a canned ufw dump first through `build` of a two-collector sequence, or set the facts directly on the builder under `Begin("firewall")`) then runs `processes`: `exposure.exposed` holds `tcp/80`; `TestProcessesExposureErrorsWhenFirewallFactsMissing` (no firewall facts → `error` naming `firewall.normalization_confidence`).
- [ ] **Step 5: Fuzz** `FuzzClassifyRule` (over a line → `parseNftRule` → classify; must not panic), seeds the review's six accepts.
- [ ] **Step 6: Lab proof.** Root collect on the lab: `exposure.stats`, `exposure.exposed` rows, `manual_reason` (the lab runs docker — expect `opaque` or decided; record which). `rockylinux:9-ubi-init` with firewalld started (`systemctl start firewalld` inside the container only): `confidence partial` → `exposure.exposed` absent "normalization confidence is partial".
- [ ] **Step 7: Gates and commit:** `Derive exposure.* from the listeners and the firewall's folded rule table`.

### Task 5: Network sysctls (P-4)

**Files:**
- Modify: `internal/collect/collectors/sysctl_parse.go` (27 leaves; `parseSysctlD` globs and exclusions; `mergeSysctl` resolves them), `sysctl.go` (the IPv6 reason), `sysctl_test.go`, `testdata/sysctl.d_50-default.conf` (systemd's file, verbatim from a public image), `internal/facts/registry.yaml` (+27 keys), golden, `fuzz_test.go` (`FuzzParseSysctlD` seeds)

- [ ] **Step 1: Failing tests:** `TestParseSysctlDGlobAndExclusion` (`net.ipv4.conf.*.rp_filter = 2` + `-net.ipv4.conf.all.rp_filter` → `default.rp_filter` persisted 2, `all.rp_filter` "no sysctl.d line sets"); `TestSysctlNetLeavesAreRead` (27 files → 27 keys ok); `TestSysctlIPv6AbsentReadsNotBuilt` (`/proc/sys/net/ipv6` missing → every ipv6 key absent with the fixed reason; v4 keys ok); `TestSysctlConcreteBeatsGlob`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** `sysctlAssign` gains `glob, exclude bool`; `mergeSysctl` applies concrete assignments last-wins, then globs (`path.Match` after `/`→`.` normalisation) to every leaf key not excluded; `readProcSys` special-cases the `/proc/sys/net/ipv6/` prefix on ENOENT. Registry entries per spec P-4 (`ipv6_bindv6only` type `int`, collector `sysctl`; the 24 settings `default_on: effective`; the two `disable_ipv6` settings).
- [ ] **Step 4: Lab proof.** Root collect: the 27 values on the lab and the persisted winners (expect `rp_filter` persisted 2 from `50-default.conf`); `sysctl -n` for each compared by hand (the oracle in Task 7 automates it).
- [ ] **Step 5: Gates and commit:** `Read the network sysctls and the sysctl.d glob keys systemd ships`.

### Task 6: Thirteen controls, fixtures, parameters, tables

**Files:**
- Create: the thirteen `controls/beyond/*.yaml`, their fixture directories (spec §6 lists), `internal/check/exposure_controls_test.go`
- Modify: `controls/testdata/_mutants.yaml` (+3), `controls/VERSION`, `cmd/muster/e2e_test.go` (+13 rows in each map; the comment counts), `cmd/muster/testdata/full-pass.json`/`full-fail.json` (every new key in the collectors' shapes), `controls/testdata/_hosts/ubuntu-22.04-stock.json` (families `processes`, `exposure`, `net.sysctl`; `firewall.rules` rows in the 13-field shape; `firewall.*` per X-9), `el9-stock.json` (idem; firewalld partial), `internal/controls/hosts_test.go` (+13 rows each table; EL9 17 → 30), `README.md`/`README.ko.md` (36 → 49), `docs/reference/coverage.md`

- [ ] **Step 1: Write the controls** exactly as spec §4 (clauses, params, `absent_means`, gates incl. the two `disable_ipv6` `applies_when` on the IPv6 controls, references), descriptions EN/KO per spec §4's description paragraph (no KISA/CIS text).
- [ ] **Step 2: Fixtures** per spec §6, each `synthetic: true`, every judged row every field; `_expect` where a reason code is asserted (`error-*` → `permission_denied`, exit 2; `manual-*` nothing). Run `go test ./internal/controls -count=1`: fixtures and the mutation test green; add `_mutants.yaml` rows only for `no_deleted_executables`.
- [ ] **Step 3: Parameter tests** (`internal/check/exposure_controls_test.go`, the 3C-2a `privilege_controls_test.go` pattern): `fail-ufw-folded-http.json` PASSes with `allowed_ports` + `tcp/80` and FAILs without; `fail-usr-local-daemon.json` PASSes with `allowed_executables` + the path; `fail-stock-ubuntu` of control 4 PASSes with `allowed_forward [0, 1]`; control 13 with `allowed_accept_ra [0, 1]`.
- [ ] **Step 4: Tables.** `controls/VERSION` `kisa-unix-2026+2026.10.02`; lint `ok: 117 controls, set kisa-unix-2026+2026.10.02`; e2e maps (+13; the full-fail comment's unchanged count recomputed by diffing the maps — say the number); `_hosts` snapshots and `hosts_test.go` (the pins are the spec §5 hypotheses, replaced by Task 7's measurement); README 49; coverage regenerated.
- [ ] **Step 5: Gates and commit** (`Add the thirteen exposure controls; control set +2026.10.02`).

### Task 7: Measure, pin, oracles, matrix, CI

**Files:**
- Modify: `controls/testdata/_hosts/*.json`, `internal/controls/hosts_test.go` (measured pins), `internal/collect/collectors/oracle_test.go` (+3 pairs), `docs/reference/capability-matrix.json`, `.github/workflows/ci.yml`, `cmd/muster/collect_test.go`, `docs/reference/coverage.md`

- [ ] **Step 1: Measure (V-18).** Lab root collect (non-deep) → the eight controls' inputs and statuses (counts only; no identifiers); `rockylinux:9-ubi-init` with `openssh-server` and firewalld started inside the container → process facts, `index_source rpm`, `exposure.stats.confidence partial`, the sysctl persisted winners from `/usr/lib/sysctl.d/50-default.conf`. Pin the `_hosts` snapshots as synthetic shapes of the measurement; `_notes` say what is unmeasured (EL9 runtime sysctls). A row that differs from spec §5 is a ruling in the report.
- [ ] **Step 2: Oracles.** `TestOracleListeners` (`ss -tulpnH`: for every `processes.listeners` row a line with the same proto and port exists, and every `pid=` in its `users:(…)` is among `owners`; log `oracle listeners: compared N`); `TestOracleSysctlNet` (extend the existing sysctl oracle's key list to the 27; the compared count grows); `TestOracleDeletedExecutable` (copy `/bin/sleep` to `t.TempDir()`, `exec.Command(copy, "300").Start()`, `os.Remove(copy)`, run the collector, find the child's row with `exe_deleted true`, `cmd.Process.Kill()`; log `oracle deleted-exe: compared 1`). Header rule 2 unchanged ("Nothing is written to the host's configuration, started, stopped or installed" — the child is the test's own process).
- [ ] **Step 3: Matrix.** `nonroot.denied` += `processes.deleted_executables`, `processes.listeners`, `processes.unpackaged_listeners`, `exposure.exposed`; `_notes` += `processes.list` (ok with denied rows), `exposure.exposed` (unsupported without a firewall binary).
- [ ] **Step 4: CI.** Root job: `jq -e '.facts.processes.stats.value.index_source == "dpkg"'`, `jq -e 'any(.facts.exposure.listeners.value[]; .service == "tcp/22")'`, the three oracle greps (`oracle listeners: compared [1-9]`, `oracle sysctl: compared` count ≥ the old + 27, `oracle deleted-exe: compared 1`); the exposure verdict assert is written AFTER the first run from `exposure.stats` (the report says what the runner read). `collect_test.go` list-actions: `processes` rows (`read /proc/[0-9]*/status`, `fact firewall.*`, the rpm command).
- [ ] **Step 5: Gates and commit** (`Pin the stock exposure readings, add the three oracle pairs, the matrix rows and the CI asserts`).

### Task 8: Documents, whole-branch review, Execution notes (controller)

- [ ] **Step 1: Documents.** Main design D32 (EN/KO) and §10.2 restated; CLAUDE.md "Exposure (stage 3C-2b)"; README pair 49; CHANGELOG (Controls: `+2026.10.02`, thirteen, the stock FAILs, U-28's inactive-backend verdict — D16; Collectors; Tooling); registry `sockets.listening` description; the spec's §5 hypotheses replaced by the measurement where they differed (rulings).
- [ ] **Step 2: Two fresh whole-branch reviews** (collectors+firewall side: Tasks 1–5, 7; controls+documents side: Tasks 6–8) on the most capable model; one fix wave; one scoped re-review.
- [ ] **Step 3: Final gates** (W-16 over `main..HEAD`, lab staticcheck@2025.1.1, oracles), Execution notes, merge menu.

## Execution notes

Executed 2026-10-06 in the worktree `stage3c2b-exposure` over main `0c2a8d5`, by the SDD pipeline of
this plan: one implementer per task (opus; a fresh one after four fix rounds), one task reviewer (opus),
scoped re-reviews (opus where the round changed behaviour, sonnet otherwise), the controller writing
the documents and ruling on every deviation. Every ruling below is also in the SDD ledger with the
measurement behind it.

### Rulings settled during execution (W-48 …)

- **W-48** the Task 1 baseline is 47 Join/Walk/Caps tests (the pre-flight's 42 was wrong). **W-49** a
  `Facts` glob is anchored at the family (`path.Match`'s `*` crosses `.`, so `firewall.*` covers nested
  keys); a setting inside the glob is allowed and `Get` returns `(Envelope{}, false)` for it. **W-50**
  `pkgindex.Index.Source *facts.Source`.
- **W-51** on a jump row `unmodelled` is redefined by the fold — cleared on a jump it followed
  (→ `irrelevant`), set on one it could not (→ `opaque`). **W-52** `portSpec` → `fwPortSpec` (services.go
  owns `portSpec`). **W-53** test and brief addresses come from the RFC 5737 documentation ranges; a 10/8 host address that
  reached a commit is allowlisted by that commit's hash in `.gitleaks.toml` (336765d, f64f5ed — the e916e0a
  precedent), never by a path or a literal.
- **W-54** the fold carries the jump row's conditions (`proto`, `dport`, `saddr`, `daddr`, `iif`,
  `ctstate`) onto every row folded through it where that row's field is empty; both set and different →
  `unmodelled`. **W-55** a rule with no verdict (`-m recent --set`; an nft rule ending without a verdict
  word) is `action: none` → `irrelevant`, distinct from an unrecognised verdict word (→ `opaque`); an
  unknown nft statement word reads `none` too (no accepting target exists). **W-56** a `.` concatenation
  operand → `unmodelled` with the field empty; `irrelevant` only for a protocol in a closed list of known
  non-tcp/udp names. **W-57/W-61** an empty nft read is cross-checked against the declared `iptables-save` (iptables-nft, whose "iptables-legacy tables present" warning arrives on stderr);
  legacy rules, iptables-nft's "iptables-legacy tables present" warning or a truncated legacy dump read
  `partial` — on the all-accept-no-rules branch too (Debian's stock `nftables.conf` + legacy rules would
  otherwise read a false U-28 FAIL). **W-58** `ct state dnat`/`snat` → `opaque`. **W-59** rows carry
  `table` — fourteen fields. **W-60** a chain is folded once per distinct set of carried conditions
  reaching it (ufw end-to-end: v4 50 / v6 46 rows). **W-62** the ufw fixtures carry `limit 22/tcp` and
  `allow 80/tcp`.
- **W-63/W-65** `mnt_ns` keys on the mount that serves the exe (longest mount-point prefix:
  `dev + path.Join(root, exe − mountpoint)` + fstype + source) compared with pid 1's key for the same
  path, plus `Readlink /proc/<pid>/root == "/"` — `ns/mnt` equality made 88 stock systemd services
  (`PrivateTmp`, `ProtectSystem`) `foreign` and every stock host FAIL control 2. **W-64** `snap` by the
  `/snap/<name>/<rev>/` prefix before the index is asked. **W-66** MEASURED: a kernel socket's inode is not
  0 (WireGuard `udp/51820` in a privileged ubuntu:24.04 container: inode 363387305, udp6 363387306), so the
  W-8 premise fell; an unheld socket after every table was read whole is `owner_status: kernel`. **W-67**
  inside a container the pid view may be partial → `unmatched` → the listener leaves `absent`. **W-68** a
  zombie leader with live threads is read through `task/*/fd/*` under the one budget. **W-69** `kernel`
  also requires pid 1's row with its `ns/mnt` and `mountinfo` read and at least one kernel thread in sight
  (`hidepid` hides both). **W-70** a zombie leader holding a socket is an owner failure (`absent`) →
  MANUAL. **W-71** the budget test needs no clock seam: the double sets `processesBudget = -1` inside its
  Readlink. **W-72** a row counts only if every ancestor on its parent chain is the topmost at its own mount
  point (a `/usr/lib` child mount under a later bind over `/usr`). **W-73** among mounts on one point the
  last listed wins (kernel creation order; mount ids are reused).
- **W-74** `BaseFamilies` come from the firewall's `raw_dumps` re-parsed. **W-75** opacity is per family.
  **W-76** v6 is not an enabled family when both `disable_ipv6` files read 1 (`via: ipv6_disabled`,
  `exposure.stats.ipv6_disabled`); an unreadable `bindv6only` with a `::` socket is that read's status
  (C3).
- **W-77** the `50-default.conf` fixture is systemd 249's from ubuntu:22.04; Ubuntu 24.04 ships none (its
  network defaults come from procps' `10-network-security.conf` or the kernel). **W-78** among exclusion
  lines for one key the last wins; `[!…]` is rewritten to `[^…]` per component; a repeated glob keeps its
  first place.
- **W-79** `applies_when` is ANDed, so two `disable_ipv6 eq 0` gates read NOT_APPLICABLE when only one leaf
  is 1 — a host with `default.disable_ipv6 = 1` and `all = 0` still speaks IPv6 and would miss a FAIL. The
  `sysctl` collector derives `net.sysctl.ipv6_disabled` (1 iff both read 1 — widened to every interface by W-86; the worse read's status
  otherwise; `source` the two `/proc` paths) and the four IPv6 controls gate on it alone — the same
  predicate as W-76. P-4 is 28 keys. **W-80** the allow entry is the path as `/proc/<pid>/exe` resolves
  it (a snap's carries the revision — a waiver fits better). **W-81** control 10 cites `RHEL-09-253025`
  and `-253030` (the `log_martians` items) too.
- **W-86** IPv6 is "disabled" only when `all`, `default` and every present interface but `lo` read
  `disable_ipv6 = 1` (the whole-branch review's S6: `all = 1` with one interface re-enabled speaks IPv6).
  **W-87** the normaliser's `partial` on the lab is measured: accept-policy input chains carrying rules — ufw's
  `filter INPUT` beside a `kubearmor` table's INPUT — not docker's FORWARD chains, which never enter
  confidence; every "docker host reads MANUAL" sentence was corrected. **W-88** a process in pid 1's mount
  namespace is `host` by `ns/mnt` equality alone (a chroot inside it keeps host paths); the exe-mount key
  decides for other namespaces. **W-89** a LISTEN row with inode 0 is `unmatched` → MANUAL, never `kernel`.
- **W-82 → W-85** the deleted-exe oracle cannot run a copy of `/bin/sleep`: on EL9 that is a 52-byte
  shebang script onto `coreutils --coreutils-prog-shebang=sleep` (`coreutils-single`), so the copy's `exe`
  is `/usr/bin/coreutils` and nothing is deleted (the review's argv[0] theory was wrong; measured in the
  rocky and alma init images). The test copies its own binary into `t.TempDir()` and runs it as a sleeper
  through `MUSTER_ORACLE_SLEEPER=1` (an `init()` hook; `Pdeathsig: SIGKILL`), asserts the child alive and
  its `exe` the copy, then unlinks and collects. **W-83** the run-status rule stands: in an unprivileged
  multi-uid container another uid's process refuses its `exe`/`fd` links, the process leaves read `denied`
  and `collect` exits 1 while every control reading them is NOT_APPLICABLE; the contract job (muster the
  only process) stays complete. **W-84** the examples refresh follows the last control-description edit
  (a later edit resets the examples gate's byte comparison to "skipped"); the runner's reading then goes
  into spec §5 and here in a docs-only follow-up.

### What the reviews found

- Task 1 (foundations, pkgindex): approved; the declaration test's panic path and the `Get` miss semantics
  tightened (W-49).
- Task 2 (firewall fold): one fix round of eleven items; the Important residuals were the fuzz row bound
  and the legacy cross-check on the all-accept branch (W-61); the re-reviewer ran fourteen rule shapes
  through a scratch copy and found the fold byte-identical over fifty runs.
- Task 3 (processes): four fix rounds. Two Important findings changed the model — the mount-key test
  (`ns/mnt` equality was a false FAIL on every stock host, W-63/W-65) and the kernel-socket inode premise
  (measured, W-66); then `hidepid`'s partial pid view (a false PASS: every unheld socket read `kernel`,
  W-69) and the zombie leader with an unpackaged daemon (W-70); the ancestor-chain visibility (W-72) and
  a spuriously-failing timing test (W-71). The fourth round went to a fresh implementer; the controller
  checked the production diff and broke nine assertions deliberately, each red.
- Task 4 (exposure): approved with one Important — IPv6 disabled by sysctl still counted as an enabled
  family (W-76). Two known limits recorded (bindv6only vs `IPV6_V6ONLY`; nft + legacy ip6tables).
- Task 5 (sysctl): approved with three Minors on systemd parity (`[!…]`, a repeated glob's place, an
  exclusion followed by a concrete line — W-78).
- Task 6 (controls): approved, 0 Blocking; the one Important was the ANDed IPv6 gate (W-79); the Minors
  were description truths (the snap path, per-control params, EL9's rp_filter, 24.04) and two fixture
  shapes the collector never writes.
- Task 7 (measure, oracles, CI): spec approved; quality rejected once on the deleted-exe oracle's sleeper
  (B-1 → W-85); the reverse-direction listeners oracle accepted; the exposure source carried the firewall
  source twice (fixed).
- Whole-branch review: see the ledger entry of the run (added below after it completes).

### Deviations from the spec, as shipped

- P-1: `mnt_ns` is the exe's mount key, not `ns/mnt` equality (W-63/W-65/W-72/W-73); `owner_status:
  kernel` is the unheld socket after a whole read with pid 1 and a kernel thread in sight, not inode 0
  (W-66/W-69); `owners_count`; zombie leaders (W-68/W-70). The declaration gained `task/*/fd/*`, the `conf/*/disable_ipv6` glob (W-86),
  `mountinfo`, `root` and the two `disable_ipv6` reads.
- P-2: the fold carries jump conditions and folds once per condition set (W-54/W-60); `action: none`;
  fourteen fields; the legacy cross-check (W-57/W-61).
- P-3: per-family opacity (W-75); `BaseFamilies` from `raw_dumps` (W-74); `via: undecided`;
  `ipv6_disabled` (W-76); `exposure.opaque_rules` carries `table`.
- P-4: 28 keys — the derived `ipv6_disabled` (W-79); `50-default.conf` where shipped (W-77); last-line
  exclusion (W-78).
- §4: one IPv6 gate key; control 10's two extra STIG ids; the snap example path.
- §5: EL9's `default.rp_filter` is 1 from `rocky-release`'s `50-redhat.conf` (the image ships no
  `50-default.conf`; a VM gets it from `systemd-udev`), `all.rp_filter` the kernel's 0 — control 10 FAILs
  on `log_martians` either way; firewalld's ruleset has 7 `opaque` rows of its own; the Ubuntu `sysctl.d`
  order is `10-network-security.conf` then `50-default.conf`; stock 24.04 fails control 8 too (no persisted
  `accept_source_route` over the kernel's `default` 1) — the examples run confirms.
- §6: `pass-filtered` has nothing listening on 22 (the spec's version could not be an empty list);
  `_mutants.yaml` gained 17 rows, not 3 (control 3's five and the twelve IPv6 gate rows); the deleted-exe
  oracle plants a copy of the test binary (W-85); `TestOracleSysctl` is extended rather than a new pair;
  the sysctl grep is the exact `compared 39`; the listeners oracle checks both directions.
- `cmd/muster/controls_test.go` (three `ok: 104 controls` asserts → 117) and
  `TestSysctlDeclarationCoversItsReads` (39 → 40 keys, 27 → 28 net leaves) were edited though no task
  listed them — both count what the collector writes.

### Numbers

- Controls 104 → 117 (36 → 49 beyond); set `kisa-unix-2026+2026.09.29` → `+2026.10.02` (D16: U-28's
  verdict on an inactive backend). Fixtures: 115 new (control 1: 17, control 2: 11, control 3: 5, the ten
  sysctl controls 82). Mutation at the end of Task 8: 1974 generated, 4 invalid, 1923 killed, 0 surviving, 47 excluded (+17 rows).
- Facts: 5 `processes.*`, 4 `exposure.*`, 28 `net.sysctl.*`; `firewall.rules` rows 5 → 14 fields;
  schema version unchanged.
- Index cost (X-4): dpkg 128–154 ms on the lab, rpm 105–125 ms in the EL9 container — rebuilt per
  collector, no cache (W-41 stands).
- Lab (22.04, docker + kubelet + ufw active, root): 388 processes (151 user, 237 kernel threads), 24
  listeners (every owner matched, none kernel), 12 unpackaged-listener rows (9 `foreign_ns`, 3
  `unpackaged`), 7 deleted executables, 16 folded rules, `partial` → control 1 MANUAL; the thirteen read
  1 MANUAL / 7 FAIL / 5 PASS. EL9 container: 8 processes, 2 listeners (sshd v4/v6), 25 folded / 7 opaque
  rows, `partial`.
- Oracles on the lab: listeners 24, deleted-exe 1, sysctl 39 (12 + 26 + `bindv6only`); the deleted-exe pair
  PASSes in the rocky 9 and alma 9 init containers (`compared 1`), where the listeners pair skips (no `ss`).
- Kernel-socket measurement: WireGuard `udp/51820` inode 363387305 / udp6 363387306 (W-66).

### Parked

- Rule order (an accept counts whether or not a drop precedes it); user chains beyond depth 4 / 2000 rows
  — firewalld's `filter_IN_policy_allow-host-ipv6_*` jumps sit past the depth and read `opaque` (evidence
  only; no control reads them); the zone model as a first-class normalisation.
- A revision-independent allow-list spelling for snaps (today the path carries the revision; a waiver
  fits); a snap/flatpak manifest as a second declaration source.
- `bindv6only` 1 with `IPV6_V6ONLY` cleared by the daemon (read v6-only); nft for v4 with legacy ip6tables
  for v6 (v6 reads `no_chain_in_family`); per-interface sysctls; `/opt/*/*/*` executables; multiple
  network namespaces; named sets as port selectors.
- An EL VM to measure the EL9 runtime sysctls (the `_hosts` rows carry the persisted winners as the
  hypothesis); nfsd/ksmbd kernel sockets unmeasured (not loaded on the lab).
- A future `net.sysctl.*` key must bump the CI `compared 39` (a comment in `ci.yml` says so).
