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
// internal/pkgindex (Task 1) — untagged API, linux-tagged readers.
type Family string // "dpkg" | "rpm" | "none"
type Owner struct{ Package, DeclaredPath, ListFile string } // ListFile: the dpkg .list that owned the path ("" on rpm)
type Index interface {
    Family() Family
    Owner(path string) (Owner, bool)
}
// Build streams the lists for exactly the candidate paths (the walk's wantedPaths shape); rpm runs the fixed query.
// Returns the index, the family detected, truncated, and an envelope describing the failure (absent "no package
// database", denied/error/timeout) — nil when ok.
func Build(ctx context.Context, a collect.Access, hdr *facts.Run, cands map[string]bool, opts Options) (Index, bool /*truncated*/, *facts.Envelope)
type Options struct{ RPMTimeout time.Duration; RPMMaxOutput int64 } // zero → the walk's 120 s / 256 MiB
var DpkgReads = []string{"/var/lib/dpkg/info/*.list", "/var/lib/dpkg/statoverride", "/var/lib/dpkg/diversions", "/var/lib/dpkg/status"}
var RPMCommand = collect.Command{Path: "/usr/bin/rpm", Args: …the walk's six-field query…, Timeout: 120 * time.Second, MaxOutput: 256 << 20}

// internal/collect (Task 1)
type Declaration struct{ Reads []string; Commands []Command; Needs string; Walk bool; Facts []string }
func (b *Builder) Get(key string) (facts.Envelope, bool) // panics "collect: <collector> reads undeclared fact <key>" outside Declare.Facts of the collector named by Begin
// Action.Kind gains "fact"; ListActions prints one row per declared fact glob.

// firewall (Task 2) — untagged helpers in firewall_fold.go
type fwRule struct{ Chain, ViaChain string; Depth int; Family, Proto, Dport, Saddr, Daddr, Iif, Ctstate, Action string; Unmodelled bool; Raw string }
func (r fwRule) record() map[string]any // the 13-field row
func foldChains(bases []baseChain, byChain map[string][]fwRule, inputs []string) []fwRule // depth ≤ 4, ≤ 2000 per base, visited once
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
type exposureInputs struct{ Confidence string; Restricts *bool; Rules []fwRule; Backend string; BindV6Only int; HasV6 bool }
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
		{`-A INPUT -d 10.0.0.1/32 -j ACCEPT`, fwRule{Daddr: "10.0.0.1/32", Action: "accept"}},
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
		{fwRule{Action: "accept", Daddr: "10.0.0.1"}, "opaque"},
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
  - `TestProcessesKernelSocketIsOwnerStatusKernel` (inode 0);
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

### Rulings settled during execution (X-10 …)

### What the reviews found

### Deviations from the spec, as shipped

### Numbers

### Parked
