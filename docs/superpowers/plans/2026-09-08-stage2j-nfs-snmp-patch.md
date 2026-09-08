# Stage 2J — NFS, SNMP and Patch Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol the five remaining KISA 2026 items the spec groups as plan 2J — U-40 (NFS 접근 통제), U-59 (안전한 SNMP 버전 사용), U-60 (SNMP Community String 복잡성 설정), U-61 (SNMP Access Control 설정) and U-64 (주기적 보안 패치 및 벤더 권고사항 적용) — with three new collectors (`nfs`, `snmp`, `patch`) that judge only from files and cached metadata, never store a community string, never refresh package metadata (D27), and degrade honestly where they cannot see.

**Architecture:** Three small collectors, one seam-free of the `services` table (2G already publishes `services.nfs_server.*` and `services.snmp.*`, so 2J edits neither `services.go` nor the logical-service table). `nfs` parses `/etc/exports` + `/etc/exports.d/*.exports` into per-path-per-client records with `wildcard` and `root_squash` DERIVED (the kernel default squashes root; a path with no client spec is exported to the world) and adds the fixed-path permission facts of `/etc/exports` through `writePermFacts` (the merged 2021 U-69 half of U-40); `exportfs -v` is a root-only corroboration flag, not the judged source. `snmp` parses `snmpd.conf` + includes + the root-only persistent state file into `versions_enabled`, `communities` (REDACTED to `{ref, kind, is_default, length, source_restricted}` — the string is never emitted), `v3_users` (never the keys), `access_rules` (VACM) and `agent_addresses`. `patch` detects the manager (apt/dnf), reads ONLY cached metadata (`/var/lib/apt/lists`, `/var/cache/dnf/*/repodata`), runs the cache-only simulations (`apt-get -s upgrade`, `dnf --cacheonly check-update` with the exit-100 rule, `dnf --cacheonly updateinfo`), and publishes `metadata_age_s`, `pending_security_count`, `reboot_required`, `auto_update.enabled` (two-sided) and `packages.installed` (the inventory plan 2L consumes). Every command failure that is an environment limitation → `unsupported` (R220); a root-only file read as non-root → `denied` (an honest ERROR, proven by the unit test and the lab non-root run — NOT by the `collect-nonroot` CI leg, where snmpd is absent and the reads are simply `absent`; Ruling J-27).

**Tech Stack:** Go 1.25.x, Linux-only collectors behind build tags; the exec discipline (`collect.Command`, byte-identical declaration/run/test key); `writePermFacts` (2A) for `/etc/exports`; `mergeDropins` is NOT needed here; YAML controls using `applies_when`, `each … subject … require`, `none … where`, `op: in` over mode subsets, `gte`/`lte`, `list<string>`/`int` params, `absent_means: manual`; one `partial` control (U-64) whose `fail-*` fixtures expect WARN.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` (§5.3 two-sided settings; §5.6 no parameter may expose a secret — `is_default` is collector-embedded; §6.3–6.6 grammar incl. `each`, `none`, params; §6.5 steps 3/8/13 — "patch metadata cache stale → WARN with its age"; §10.2 "`snmpd.conf` (versions enabled, communities redacted to default/length/source-restriction)", "patch hygiene from cached metadata"; D14 never invoke a daemon for a version; **D27 cached metadata only, never a refresh**). The plan argues from the spec; conflicts resolve against it. Scope brief with all citations: `<session-scratchpad>/2j-scope-brief.md`.

## Global Constraints

- **Numbering (Ruling J-1):** the spec names ONE plan "2J NFS, SNMP and patch hygiene" (twelve plans, no 2K). The analysis's 2J/2K split is folded back: 2J owns nfs + snmp + patch + `packages.installed`; plan 2L depends on 2J for `packages.installed`.
- **Control set count: 47 → 52** — this plan is authored against main @ d2bac56 (45 controls) but is MERGED AFTER plan 2I (which lands 47). Task 6 rebases onto the post-2I main FIRST and then reconciles every count seam against the live main: 47 → 52; coverage `auto 43 → 47, partial 4 → 5, manual 0` → `52 of 67 items enrolled (auto 47, partial 5, manual 0).` If 2I has not merged when Task 6 runs, STOP and wait — never reconcile against a stale main.
- **Registry `schema_version` stays 1.** All new keys are additions (C2; §5.7). Put 2J's entries in ONE contiguous block at the END of `registry.yaml` (after whatever 2I appended) so a rebase is a clean append; regenerate the golden with `go test ./internal/facts -run TestFactsSchemaGolden -update` after the rebase. `subject_kind` only on `files.etc_exports.*`? No — `writePermFacts` leaves are scalars; NO `subject_kind` anywhere in this plan (no valid kind fits `packages`/`communities`/`exports`; the R229 lesson).
- **The verbatim `packages.installed` entry (Ruling J-15 — plan 2L quotes this IDENTICALLY so its early fixtures match and its post-2J rebase resolves to a pure duplicate deletion):**
  ```yaml
  - key: packages.installed
    type: list<record>
    description: Installed packages as {name, version, arch} read from the package database (dpkg status on apt hosts, rpm -qa on dnf hosts); a version is evidence only and is never obtained by invoking a daemon.
    since: 1
    sensitivity: internal
    collector: patch
  ```
- **D27 / CI network (hard):** `collect` NEVER runs `apt-get update`, `dnf check-update` without `--cacheonly`, `dnf makecache`, or anything that touches a repository. `collect-contract` runs with `--network none`; a refresh would hang or fail and, worse, would be a design violation. Only cached metadata and cache-only simulations.
- **Clock and mtime (Ruling J-21 — CROSS-PLAN dependency):** `patch.metadata_age_s` and `patch.days_since_last_install` are `CollectedAt − mtime`. "Now" is `b.Header().CollectedAt` (the R54 single-clock-read precedent), **never `time.Now()` inside a collector** (determinism; same input, same bytes); the test sets `CollectedAt` before `Run`. The mtime comes from `collect.ReadMeta.ModTime`, **which plan 2I's Task 2 adds** (2I lands before 2J, and 2I's `logging.log_targets.mtime_age_s` needs the same field). After Task 6's rebase, 2J adds it ONLY if the rebased base still lacks it: `ModTime time.Time` on `ReadMeta` (`internal/collect/types.go`), populated in `fillMeta` (`internal/collect/readfile.go`, the real access) and served by the `fsAccess` test double (a `mtime` seed on `stats[...]`). `ReadMeta` is NOT a fact — the facts golden and `schema_version` are untouched either way.
- **Honest degradation (R220 / H-17):** (a) a command that cannot run because the environment lacks it (`dnf` on Ubuntu, `exportfs` absent, `needs-restarting` absent on Rocky) → `unsupported` — never `error`; a command that hits its `Timeout` (Ruling J-24) is likewise `unsupported`, with the reason naming the timeout so a slow host is never mistaken for a clean one; (b) a ROOT-ONLY file read as non-root (`/var/lib/snmp/snmpd.conf`, `/var/lib/net-snmp/snmpd.conf`, Ubuntu's 0600 `/etc/snmp/snmpd.conf`) → `FromReadError` → `denied` (honest ERROR). **Ruling J-27:** that `denied` shape is proven by the UNIT TEST (`fails[stateFile] = ErrPermission`) and by the lab-host non-root run ONLY — on the GitHub runner snmpd is not installed, so the snmp reads are ENOENT → `absent`, not `denied`; `collect-nonroot`'s `ERROR > 0` invariant is satisfied by the pre-existing collectors and this plan must not claim to supply it; (c) `exportfs -v` non-root failure → `nfs.exports_runtime_collected` `ok:false` (it is corroboration, not the judged source — never denied/error); (d) **Ruling J-25:** NO package-metadata cache at all (never updated, `--read-only` container) → `patch.metadata_age_s` AND `patch.pending_security_count` BOTH `absent` → MANUAL; a cache that EXISTS but carries no security channel → `pending_security_count` `unsupported` → NOT_APPLICABLE. `mergeSoft` lets `unsupported` beat `absent`, so mixing the two in the no-cache case would silently read NA instead of MANUAL. The `collect-contract` leg's `.run.complete == true` must hold: every registered 2J key is set on every path (unsupported/absent/ok), never left `missing`.
- **Redaction (Ruling J-7):** the collector NEVER emits a community string, a v3 auth/priv key, or any secret; `snmp.communities` records are `{ref, kind, is_default, length, source_restricted}` with `ref` an opaque ordinal (`c1`, `c2`, … in file order — NOT a hash: a hash of a short string is trivially reversible); `snmp.v3_users` records are `{name, auth_proto, priv_proto, level}`. `is_default` is computed in the collector against an EMBEDDED well-known list (`public`, `private`, `community`, `snmp`, `snmpd`, `manager`, `admin`, `default`, `cisco`, `secret`, `read`, `write`) — not a parameter (§5.6). Both keys carry `sensitivity: secret` — the first use of that level; the snapshot writer's `Redaction` header is static today, so the protection is the collector's field discipline (state this in the code comment; sensitivity-driven redaction machinery is 2M/beyond).
- **U-64 is `partial` (Ruling J-3):** its `fail-*` fixtures expect WARN (CLAUDE.md). A mandatory clause `patch.metadata_age_s lte ${max_metadata_age_s}` (param, default `604800` = 7 days) makes a stale cache WARN with its age (spec step 13) instead of PASSing silently (the analysis's riskiest decision #1). **Ruling J-25 settles the two "cannot see" shapes, which are NOT the same:** (i) a host with NO cache at all emits `metadata_age_s` **absent** AND `pending_security_count` **absent** → the control reads **MANUAL** ("no package metadata cache; the host may never have been updated — metadata is never refreshed by muster, D27"); (ii) a host WITH a cache but no security channel emits `pending_security_count` **`unsupported`** (never 0) → NOT_APPLICABLE. The earlier "no cache → MANUAL via an unsupported count" wording was wrong: `mergeSoft` makes `unsupported` beat `absent`, so that shape reads NA. `reboot_required`, `auto_update.enabled`, `held_packages`, `days_since_last_install` are EVIDENCE only (a centrally orchestrated fleet may disable auto-updates by policy — Ruling J-4).
- **Every fact leaf is an envelope; a non-ok status never yields PASS.** A registered key the snapshot lacks is `missing` → ERROR, never `absent_means`.
- **Same input, same bytes.** Sort exports records (path, client), communities (file order is the `ref` order — deterministic), packages (name, arch), pending updates (name).
- **`references.stig` only cites ids present in `docs/reference/stig/*.json`.** Verified: U-64 → `rhel9 V2R9 RHEL-09-211015`. NO SNMP rule exists in any indexed benchmark; the NFS ids in the index are package-absence rules (U-39's, already cited by 2G) — U-40/U-59/U-60/U-61 ship `references.kisa` only. No `make refindex`.
- **KISA ids (verified against `docs/reference/kisa/kisa_mapping.json`):** U-40 `{ "2026": ["U-40"], "2021": ["U-25", "U-69"] }` (merged — access control + config-file permission); U-59 `{ "2026": ["U-59"], "2021": [] }` (new); U-60 `{ "2026": ["U-60"], "2021": ["U-67"] }`; U-61 `{ "2026": ["U-61"], "2021": [] }` (new); U-64 `{ "2026": ["U-64"], "2021": ["U-42"] }`.
- **Never copy KISA/CIS text.** Descriptions are muster's own words, EN canonical + KO pair. **Fixtures are `synthetic: true`**; never a lab snapshot (D02).
- **Fixture addresses (Ruling J-32):** EVERY address in `internal/collect/collectors/testdata/*` and in `controls/testdata/*` is from an RFC 5737 documentation range — `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — and **never** an RFC 1918 range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). gitleaks scans every PR commit (the 2H lesson); the `.gitleaks.toml` allowlist is not something to lean on.
- **Categories mirror KISA:** U-40/U-59/U-60/U-61 are 서비스 관리 → `service`; U-64 is 패치 관리 → `patch`. Ids: `muster.service.nfs_export_access`, `muster.service.snmp_version`, `muster.service.snmp_community_strength`, `muster.service.snmp_access_control`, `muster.patch.security_updates`. All five PASS in BOTH shared e2e fixtures (the H-15 convention — the waiver e2e counts exactly 10 waived FAILs).
- **Seams this plan does NOT touch:** `services.go` (rows exist), `files.go`'s existing candidate lists except the ONE added `/etc/exports` permission block (Task 1), `firewall.go`, `logging.go`/`timesync.go` (2I's). Overlap with 2I is limited to the append-only registry/golden/count seams handled by Task 6's rebase.
- **LAB TOKEN:** plan 2I holds the lab host until it merges. Every lab step in this plan is marked `[LAB TOKEN]` — run it ONLY after the controller states the token is 2J's (post-2I merge); until then verify with `GOOS=linux GOARCH=amd64 go vet ./... && go build ./...` + `go test -c` and report the lab step as DEFERRED. Never edit or replace `lab-sync.sh`/`lab-run.sh`; always sync immediately before run.
- **Controller boundary rulings (folded in):**
  - **J-5:** the `patch` collector needs no root (dpkg/apt/dnf caches are world-readable; `apt-get -s` and `dnf --cacheonly` are unprivileged simulations) → `Needs: "none"`, every command failure → `unsupported` (environment), never denied; `needs-restarting -r` absent → `reboot_required` unsupported (its exit code alone never invents a finding — the analysis's riskiest decision #3).
  - **J-6:** the `snmp` collector's root-only files → non-root `denied` (honest ERROR); a missing state file as root → `absent` v3 users (no v3 configured), never an error.
  - **J-8/J-9/J-10:** U-59 = no v1/v2c enabled (`none` over `versions_enabled`); U-60 = every community `is_default == false` AND `length gte ${min_length}` (param default `8`); U-61 = every community `source_restricted == true` (VACM rules and `agent_addresses` are evidence — a loopback-only agent is evidence, not a pass).
  - **J-11:** U-40 = every export `wildcard == false` AND `root_squash == true` AND `/etc/exports` mode ≤ 0644 owned by root (the merged U-69 half via `files.etc_exports.*`). File-only judged source; `exportfs -v` corroborates.
  - **J-16 (rebase recipe, Task 6):** `git rebase main` (post-2I) → resolve `registry.yaml` by keeping BOTH appended blocks with 2J's after 2I's (`LoadRegistry` rejects duplicates — run `go test ./internal/facts` immediately) → `go test ./internal/facts -run TestFactsSchemaGolden -update` → `go run ./tools/coverage` → bump the count literals against the live main → full gates.

---

## File Structure

**Collectors — create/modify:**
- `internal/collect/collectors/nfs.go` + `nfs_test.go` + testdata (`exports.world`, `exports.restricted`, `exports.d/10-extra.exports`) — **new** (Task 1); one `writePermFacts` block for `/etc/exports` added to the `files` collector's fixed candidate list (Task 1).
- `internal/collect/collectors/snmp.go` + `snmp_test.go` + testdata (`snmpd.conf.v2c-public`, `snmpd.conf.v3-only`, `snmpd.conf.com2sec`, `snmpd.conf.includes`, `var-lib-snmpd.conf.v3`) — **new** (Task 2).
- `internal/collect/collectors/patch.go` + `patch_test.go` + testdata (`apt-get.s-upgrade.security`, `apt-get.s-upgrade.none`, `dnf.check-update.100`, `dnf.updateinfo.list`, `dpkg.status.sample`, `rpm.qa.sample`, `apt.20auto-upgrades`, `dnf.automatic.conf`) — **new** (Task 3).
- **Conditional (Ruling J-21):** `internal/collect/types.go` (`ReadMeta.ModTime`), `internal/collect/readfile.go` (`fillMeta`) and the `fsAccess` double in `internal/collect/collectors/collectors_test.go` (`stats[...]` `mtime` seed) — **only if plan 2I's Task 2 has not already added `ReadMeta.ModTime` when Task 6 rebases**. Check first; do not duplicate the field.
- `internal/facts/registry.yaml` + golden — new `nfs.*`, `files.etc_exports.*`, `snmp.*`, `patch.*`, `packages.installed` keys (ONE contiguous block at EOF).
- Register the three collectors at the assembly site (`register.go`, where `firewallCollector`/`timesyncCollector` are listed).

**Controls — create:**
- `controls/service/nfs_export_access.yaml` (U-40), `controls/service/snmp_version.yaml` (U-59), `controls/service/snmp_community_strength.yaml` (U-60), `controls/service/snmp_access_control.yaml` (U-61) — Task 4.
- `controls/patch/security_updates.yaml` (U-64) — Task 5 (create `controls/patch/` — the `*/*.yaml` embed picks up a new subdirectory automatically; confirm).
- Fixtures under `controls/testdata/<id>/`.

**Reconciliation — modify (Task 6, after the rebase):** `cmd/muster/controls_test.go` (`ok: 47 controls` ×2 → 52), `cmd/muster/e2e_test.go` (spelled-out counts + both maps), `cmd/muster/testdata/full-{pass,fail}.json`, `docs/reference/coverage.md` (regenerated).

---

## Interfaces (produced by this plan)

All `since: 1`; sensitivity `public` unless noted; NO `subject_kind`.
- `nfs.exports` — `list<record>` `{path, client, options, wildcard, root_squash}`; one record per path × client spec; a path with no client spec yields one record with `client: "*"`, `wildcard: true`. `root_squash` = NOT `no_root_squash` in options. Judged.
- `nfs.exports_source` — `list<string>` — the files read in order (evidence).
- `nfs.exports_runtime_collected` — `bool` — whether `exportfs -v` ran successfully (root); evidence.
- `files.etc_exports.{mode,uid,gid,group,group_readable,group_writable,other_readable,other_writable,acl_present}` — the nine `writePermFacts` leaves (Task 1); mode/uid judged.
- `snmp.versions_enabled` — `list<string>` — subset of `[v1, v2c, v3]` inferred from the directive set incl. the state file. Judged (`none`).
- `snmp.communities` — `list<record>` `{ref, kind (ro|rw), is_default, length, source_restricted}`, `sensitivity: secret`. Judged (`each`).
- `snmp.v3_users` — `list<record>` `{name, auth_proto, priv_proto, level}`, `sensitivity: secret`. Evidence.
- `snmp.access_rules` — `list<record>` `{kind (com2sec|group|view|access), name, sec_model, sec_level, source, read_view, write_view}`. Evidence.
- `snmp.agent_addresses` — `list<string>`. Evidence.
- `snmp.config_files` — `list<string>`; `snmp.parse_complete` — `bool` (false when an include could not be read). Evidence; when `parse_complete` is false the three judged lists are `absent` → MANUAL.
- `patch.manager` — `string` (`apt` | `dnf` | `unknown`).
- `patch.metadata_age_s` — `int` — `b.Header().CollectedAt` minus the newest cached-metadata **mtime** (`ReadMeta.ModTime`, Ruling J-21; apt: newest `/var/lib/apt/lists/*Packages` or `update-success-stamp`; dnf: newest `repomd.xml`); **`absent` when no cache exists at all** (Ruling J-25 — and then `pending_security_count` is `absent` too, so the control reads MANUAL). Judged (`lte`).
- `patch.pending_updates` — `list<record>` `{name, current, candidate, origin}` — from the cache-only simulation. Evidence.
- `patch.security_metadata_available` — `bool`. **Definition (Ruling J-26):** apt → true iff a file matching `*-security_*Packages` (or the `*_InRelease` of a `-security` suite) exists under `/var/lib/apt/lists`; dnf → true iff the newest cached `repomd.xml` contains `<data type="updateinfo">`. `dnf updateinfo` exiting 0 with empty output is NOT evidence of "no security updates" unless that metadata exists.
- `patch.pending_security_count` — `int`; **`unsupported`** when a cache exists but `security_metadata_available` is false (never 0), **`absent`** when there is no cache at all (Ruling J-25). Judged (`eq 0`).
- `patch.reboot_required` — `bool` (`/run/reboot-required` on apt — **never `/var/run/...`, which is a symlink the read primitive refuses**, Ruling J-20; `needs-restarting -r` on dnf; `unsupported` when the tool is absent, and `unsupported("container")` when `b.Header().Env.Container != "none"` without running anything, Ruling J-31). Evidence.
- `patch.days_since_last_install` — `int` (newest `dpkg.log` install / `rpm -qa --last`), computed against `b.Header().CollectedAt` under the same clock rule as `metadata_age_s` (Ruling J-21); evidence.
- `patch.auto_update.enabled` — `setting<bool>`, `default_on: both` — persisted from `20auto-upgrades`/`dnf-automatic.conf`, runtime from the timer/unit state is NOT probed (would need a services row) → runtime side `unsupported("not probed in this version")`. Evidence only.
- `patch.held_packages` — `list<string>`. Evidence.
- `packages.installed` — the verbatim entry above. Consumed by 2L.

---

### Task 1: `nfs` collector + `/etc/exports` permission facts

**Files:** create `nfs.go`, `nfs_test.go`, testdata; modify the `files` collector's fixed-path list (one `writePermFacts` block for `/etc/exports`); `registry.yaml` + golden; `register.go`.

**Interfaces:** consumes `collect.Access`, `collect.Command`, `collect.Unsupported`, `FromReadError`, `writePermFacts`, `buildBegun`; produces `nfs.*` and `files.etc_exports.*`.

- [ ] **Step 1: Failing tests**
```go
// A path with no client spec exports to the world; no_root_squash is derived.
func TestNfsExportsWorldAndRootSquash(t *testing.T) {
	a := nfsAccess(map[string]string{"/etc/exports": "exports.world"}, nil) // fixture: "/srv/share\n/srv/data 192.0.2.0/24(rw,no_root_squash)\n" — RFC 5737 only (Ruling J-32), never an RFC 1918 host
	b := buildBegun(t, "nfs", a)
	recs := okList(t, b, "nfs.exports")
	// /srv/share → client "*", wildcard true, root_squash true; /srv/data → wildcard false, root_squash false
}
// exports.d fragments are read in sorted order; a missing /etc/exports with fragments still parses.
func TestNfsExportsDFragments(t *testing.T) { /* /etc/exports.d/10-extra.exports */ }
// exportfs -v unavailable (non-root or absent) → exports_runtime_collected ok:false, never error; Worst ok.
func TestNfsExportfsUnavailableIsNotAnError(t *testing.T) { /* unmapped command → ok:false; Worst == ok */ }
// An existing-but-unreadable /etc/exports → denied on nfs.exports (C3), not a silent empty list.
func TestNfsUnreadableExportsIsDenied(t *testing.T) { /* fails["/etc/exports"]=ErrPermission */ }
// No exports files at all → nfs.exports ok:[] (a definite "nothing exported"), never missing.
func TestNfsNoExportsIsEmptyNotMissing(t *testing.T) {}
```
`nfsAccess` initialises `files, cmds, fails, dirs, stats` (the R226/I-20 lesson). **Ruling J-32:** every address in every fixture of this plan is RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and never RFC 1918 — gitleaks scans every PR commit (the 2H lesson).

- [ ] **Step 2: Run red.** `GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null` compiles; the Linux suite runs on the lab host `[LAB TOKEN]` or in CI.

- [ ] **Step 3: Implement**
- `Declare.Reads`: `/etc/exports`, `/etc/exports.d/*.exports`. `Declare.Commands`: `/usr/sbin/exportfs -v` (one form, byte-identical). `Needs: "none"` (exportfs is corroboration).
- Parse: skip `#` comments/blank; join `\`-continued lines; first token = path (quoted paths allowed); remaining tokens = client specs `client(options)` (options may be absent → kernel defaults: `ro`, `root_squash`); no client spec → one record `{client:"*", wildcard:true}`. `wildcard` = client is `*` or contains `*`/`?` or is a bare `@netgroup`-less empty; a CIDR/hostname/netgroup is not a wildcard. `root_squash` = options lack `no_root_squash`. Sort records by (path, client).
- `exports_source` = files read; `exports_runtime_collected` = `exportfs -v` ran with exit 0 (else `ok:false`, never denied/error — comment why).
- Unreadable existing file → `FromReadError` on `nfs.exports` (+ `exports_source`); no files → `ok:[]`.
- `files.etc_exports.*`: call `writePermFacts` for `/etc/exports` in the `files` collector (declare the path there); a missing file → the established absent shape of the 2A template; register the nine leaves.

- [ ] **Step 4: Register keys (contiguous EOF block), golden `-update`, gates** (`gofmt`, `GOOS=linux go vet`, staticcheck, `go test ./internal/facts`). `[LAB TOKEN]` lab run deferred unless the token is 2J's.

- [ ] **Step 5: Commit.** "Add the nfs collector and the /etc/exports permission facts".

---

### Task 2: `snmp` collector with redaction

**Files:** create `snmp.go`, `snmp_test.go`, testdata; `registry.yaml` + golden; `register.go`.

- [ ] **Step 1: Failing tests**
```go
// rocommunity public / rwcommunity s3cr3tLongOne 192.0.2.0/24 → v2c enabled; two communities:
// c1 {ro, is_default true, length 6, source_restricted false}, c2 {rw, false, 12, true}; the strings never appear in the snapshot.
func TestSnmpCommunitiesAreRedacted(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{"/etc/snmp/snmpd.conf": "snmpd.conf.v2c-public"}, nil))
	recs := okList(t, b, "snmp.communities")
	// assert the five fields, then assert the raw strings are absent from the serialized snapshot.
}

// Ruling J-29: no helper renders a Builder, so serialise the tree directly — `facts.Envelope` has JSON
// tags, so this is the whole helper. Add it to snmp_test.go.
func treeJSON(t *testing.T, b *facts.Builder) []byte {
	t.Helper()
	data, err := json.Marshal(b.Tree())
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	return data
}
// Usage: `if bytes.Contains(treeJSON(t, b), []byte("s3cr3tLongOne")) { t.Fatal("community string leaked") }`.
// Assert on the fixture's UNIQUE strings for the whole tree; "public" may legitimately appear elsewhere
// (a source path, a view name), so assert its absence only within the `snmp` subtree.
// com2sec: community is the LAST field; source is the middle field.
func TestSnmpCom2secSourceAndCommunity(t *testing.T) {}
// v3-only (createUser in the state file, no ro/rwcommunity/com2sec) → versions_enabled [v3], communities [].
func TestSnmpV3OnlyFromStateFile(t *testing.T) {}
// includeFile/includeDir followed; an unreadable include → parse_complete false, judged lists ABSENT (→ MANUAL).
func TestSnmpUnreadableIncludeMakesJudgedListsAbsent(t *testing.T) {}
// Non-root: the 0600 config / root-only state file → denied on the judged leaves (honest ERROR), never a silent "no v3".
func TestSnmpNonRootStateFileIsDenied(t *testing.T) { /* fails[stateFile]=ErrPermission → denied */ }
// Root, state file missing → v3_users ok:[] (nothing persisted), not error.
func TestSnmpMissingStateFileIsEmpty(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `Declare.Reads`: `/etc/snmp/snmpd.conf`, `/etc/snmp/snmpd.local.conf`, `/etc/snmp/snmpd.conf.d/*.conf`, `/var/lib/snmp/snmpd.conf`, `/var/lib/net-snmp/snmpd.conf`; an `includeFile`/`includeDir` outside the declaration → recorded (`declared()` probe), `parse_complete: false`, never touched. `Needs: "root"` (documentation; classification is `FromReadError`). Directives: `rocommunity|rwcommunity <string> [source] [oid]` (community = 2nd token; source = 3rd token when it is not an OID/`-V`), `rocommunity6`/`rwcommunity6` likewise, `com2sec <name> <source> <community>` (community LAST), `group`, `view`, `access` (VACM → `access_rules`), `createUser`/`rouser`/`rwuser` (v3 → `v3_users` with level from `auth`/`priv`/`noauth`), `agentaddress`/`agentAddress`. `versions_enabled`: `v1`/`v2c` when any ro/rw community or a `com2sec` with a v1/v2c `group` model exists; `v3` when any v3 user exists. `source_restricted` = source present and not in {`default`, `0.0.0.0`, `0.0.0.0/0`, `::/0`, `""`}. `is_default` = string ∈ the embedded list (case-insensitive). `length` = utf8 rune count. NEVER store the string; assert in tests that the raw strings are absent from the serialized snapshot. Unreadable-existing → `FromReadError` (denied for non-root — honest); missing state file as root → `v3_users ok:[]`.
- [ ] **Step 4: Register (`snmp.communities`/`snmp.v3_users` `sensitivity: secret` — first use; code comment that redaction is field discipline), golden, gates.** `[LAB TOKEN]` deferred.
- [ ] **Step 5: Commit.** "Add the snmp collector with redacted communities".

---

### Task 3: `patch` collector + `packages.installed`

**Files:** create `patch.go`, `patch_test.go`, testdata; `registry.yaml` + golden; `register.go`.

- [ ] **Step 1: Failing tests**
```go
// apt: newest Packages list stamps metadata_age_s; `apt-get -s upgrade` lists 2 pending, 1 from a -security origin → pending_security_count 1.
func TestPatchAptSecurityCountFromSimulation(t *testing.T) {}
// Ruling J-21: the age is CollectedAt − mtime, taken from the header clock, not time.Now().
// Seed stats["/var/lib/apt/lists/…_Packages"].mtime and b.Header().CollectedAt so the expected age is EXACT
// (e.g. mtime = CollectedAt − 3600 → metadata_age_s == 3600); a second run with the same seeds is byte-identical.
func TestPatchMetadataAgeUsesCollectedAtAndModTime(t *testing.T) {}
// dnf: `dnf --cacheonly check-update` exit 100 is SUCCESS-with-updates (never an error); exit 0 → zero pending.
func TestPatchDnfExit100IsUpdatesNotError(t *testing.T) {}
// Ruling J-26: a cache EXISTS but has no security channel (no *-security_*Packages / no <data type="updateinfo">)
// → security_metadata_available false AND pending_security_count UNSUPPORTED, never 0 — even when
// `dnf --cacheonly updateinfo list security` exits 0 with empty stdout.
func TestPatchNoSecurityMetadataIsUnsupportedNotZero(t *testing.T) {}
// Ruling J-25: NO metadata cache at all (read-only container) → metadata_age_s ABSENT *and*
// pending_security_count ABSENT (→ MANUAL, not NA: `mergeSoft` would let a single `unsupported` win); run complete.
func TestPatchNoCacheIsAbsentOnBothLeaves(t *testing.T) {}
// Ruling J-20: reboot detection stats/reads /run/reboot-required and /run/reboot-required.pkgs.
// Assert BOTH that the /run paths are the ones consulted and that "/var/run/reboot-required" is never
// touched (seed the double with the /var/run keys only → the fact must NOT become true/ok).
func TestPatchRebootRequiredUsesRunNotVarRun(t *testing.T) {}
// needs-restarting absent (Rocky default) → reboot_required unsupported; /run/reboot-required present → true.
func TestPatchRebootRequiredShapes(t *testing.T) {}
// Ruling J-31: in a container (b.Header().Env.Container != "none") reboot_required is unsupported("container")
// and needs-restarting is NEVER run (assert the command is absent from the double's call log).
func TestPatchRebootRequiredInContainerSkipsCommand(t *testing.T) {}
// packages.installed from dpkg status / rpm -qa, sorted by (name, arch); never invokes a daemon.
// Ruling J-23: the test key is built from the SAME `rpmQaCmd` const as the declaration and the run.
func TestPatchPackagesInstalled(t *testing.T) {}
// Ruling J-24: a command that times out → unsupported, with the reason naming the timeout (never a silent NA).
func TestPatchCommandTimeoutIsUnsupportedWithReason(t *testing.T) {}
// Worst("patch") == ok on every degraded shape (R220).
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `Declare.Reads`: `/var/lib/apt/lists/*`, `/var/lib/apt/periodic/update-success-stamp`, **`/run/reboot-required`**, **`/run/reboot-required.pkgs`** (Ruling J-20 — `/var/run` is a symlink to `/run` on every supported family; `readfile.go`'s `RESOLVE_NO_SYMLINKS` returns `ErrSymlink`, `FromReadError` maps it to **error**, and one error envelope flips `run.complete` and breaks `collect-contract` + `collect-root --require-complete`. Precedent for the real path: `os.go`'s `/run/.containerenv`, `services.go`'s `/run/systemd/system`), `/var/lib/dpkg/status`, `/var/log/dpkg.log`, `/var/cache/dnf/*/repodata/repomd.xml`, `/etc/dnf/automatic.conf`, `/etc/apt/apt.conf.d/10periodic`, `/etc/apt/apt.conf.d/20auto-upgrades`. No other declared path has a symlinked component on stock images (`/var/lock` and `/var/run` are the only two — audit before adding any path). `Declare.Commands` — byte-identical between declaration, run and test key, and built from the shared consts below:
```go
// Ruling J-23: rpm expands \t and \n in a query format itself, so the Args string must hold the
// literal BACKSLASH-t / BACKSLASH-n characters, never real control bytes — a raw TAB or LF would
// split a `--list-actions` table row (commandString) and put a newline in every evidence Source.Cmd.
// Written as a Go RAW string; declaration, run and the test key all use this one const (the H-21 shape).
const rpmQaFormat = `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`

// Ruling J-24: RunCommand's default Timeout is 5 s and a timeout becomes `unsupported` — a false NA.
// dnf (Python start-up + solv cache) and apt-get -s on a big host routinely need more, so set both
// fields explicitly on the four heavy commands. allowedCommand compares Path+Args only, so Timeout and
// MaxOutput are free (internal/collect/exec.go — Timeout default :69-71, MaxOutput on the same struct).
// Ruling J-30: `-o Debug::NoLocking=1` is belt-and-braces so an unprivileged simulation never fails on
// the apt lock; it is part of the declared Args, so it appears identically in the run and the test key.
var patchCommands = []collect.Command{
	{Path: "/usr/bin/apt-get", Args: []string{"-s", "upgrade", "-o", "Debug::NoLocking=1"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20},
	{Path: "/usr/bin/dnf", Args: []string{"--cacheonly", "check-update"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20},
	{Path: "/usr/bin/dnf", Args: []string{"--cacheonly", "updateinfo", "list", "security"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20},
	{Path: "/usr/bin/rpm", Args: []string{"-qa", "--qf", rpmQaFormat}, Timeout: 60 * time.Second, MaxOutput: 8 << 20},
	{Path: "/usr/bin/apt-mark", Args: []string{"showhold"}},
	{Path: "/usr/bin/needs-restarting", Args: []string{"-r"}},
}
```
**NEVER** `apt-get update` / `dnf check-update` without `--cacheonly` / `dnf makecache` (D27). `Needs: "none"`.
- Manager: `apt` if `/var/lib/dpkg/status` exists, else `dnf` if `/var/cache/dnf` exists, else `unknown` (all patch leaves `unsupported("no supported package manager")`, `packages.installed ok:[]`).
- apt: parse `Inst <pkg> [<cur>] (<cand> <origin…>)` lines (skip every non-`Inst ` line — the unprivileged NOTE block goes to stdout too); origin containing `-security` (or `esm-apps`/`esm-infra`) → security. dnf: `check-update` exit 100 → parse `<name>.<arch>  <ver>  <repo>` rows (exit 0 → none; other → unsupported); `updateinfo list security` → count, but ONLY when `security_metadata_available` is true.
- **`security_metadata_available` (Ruling J-26) — a FILE-based definition, not an exit code.** apt: true iff a file matching `*-security_*Packages` (or the `*_InRelease` of a `-security` suite) exists under `/var/lib/apt/lists`. dnf: true iff the newest cached `repomd.xml` contains `<data type="updateinfo">`. Rationale: `dnf --cacheonly updateinfo list security` exits 0 with empty stdout BOTH when there is no updateinfo metadata and when nothing is pending, so exit 0 + empty output is never by itself evidence of "no security updates". Both inputs are reads this plan already declares; add a test for each family.
- **`metadata_age_s` (Ruling J-21):** `b.Header().CollectedAt` − the newest cache **mtime** taken from `ReadMeta.ModTime` (apt lists `*_Packages` or the stamp; dnf `repomd.xml`) — never `time.Now()`. `days_since_last_install` (`dpkg.log` `status installed` / `rpm -qa --last`) uses the same header clock. If the rebased base lacks `ReadMeta.ModTime` (2I's Task 2 normally supplies it) add the field per the Global Constraints note first.
- **No cache at all (Ruling J-25):** emit `metadata_age_s` **absent** AND `pending_security_count` **absent**, with the reason "no package metadata cache; the host may never have been updated (metadata is never refreshed by muster, D27)" → U-64 reads **MANUAL**. Do NOT make the count `unsupported` here: `mergeSoft` lets `unsupported` beat `absent` and the control would silently read NOT_APPLICABLE. A cache that exists but has no security channel keeps the count `unsupported` → NA.
- `reboot_required`: **container first** (Ruling J-31) — when `b.Header().Env.Container != "none"` (filled by the `os` collector; `All()` is name-sorted, so `os` runs before `patch`) set `unsupported("container")` and run nothing. Otherwise apt = `/run/reboot-required` exists; dnf = `needs-restarting -r` exit 1 → true, 0 → false, unavailable → `unsupported`. `auto_update.enabled`: persisted from `APT::Periodic::Unattended-Upgrade "1"` / `[commands] apply_updates = yes`; runtime side `unsupported("not probed in this version")` — both sides always set. `held_packages` from `apt-mark showhold` / dnf `versionlock` (unsupported if absent). `packages.installed` from dpkg status (`Package`/`Version`/`Architecture` stanzas, `Status: install ok installed`) or the `rpmQaFormat` output; sorted by (name, arch).
- Every command failure → `unsupported` with the first stderr line (the `cronTimers` shape); never denied/error. A `Timeout` expiry is the same shape but its reason NAMES the timeout (Ruling J-24) so a slow host is never mistaken for a host with nothing to report.
- [ ] **Step 4: Register (incl. the VERBATIM `packages.installed` entry), golden, gates.** If this task had to add `ReadMeta.ModTime` (Ruling J-21), the facts golden must NOT change — `ReadMeta` is a read's metadata, not a fact; a golden diff there means something leaked into the snapshot. `[LAB TOKEN]` deferred.
- [ ] **Step 5: Commit.** "Add the patch collector and the installed-package inventory".

---

### Task 4: NFS + SNMP controls (U-40, U-59, U-60, U-61) + fixtures

**Files:** the four `controls/service/*.yaml` + fixtures.

- [ ] **Step 1: U-40 `controls/service/nfs_export_access.yaml`** (category service, 상, auto, kisa `{2026:[U-40], 2021:[U-25, U-69]}`, kisa-only, `requires_facts: ">=1"`, `absent_means: manual`):
```yaml
applies_when:
  - { fact: services.nfs_server.installed, op: eq, expected: true }   # Ruling J-22 — `op: present` does NOT gate
checks:
  - { fact: nfs.exports, op: each, subject: path, require: { field: wildcard, op: eq, expected: false } }
  - { fact: nfs.exports, op: each, subject: path, require: { field: root_squash, op: eq, expected: true } }
  - { fact: files.etc_exports.mode, op: in, expected: [0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420] } # 0644 or any subset of its bits — copied verbatim from controls/file/passwd_permissions.yaml (Ruling J-28)
  - { fact: files.etc_exports.uid, op: eq, expected: 0 }
```
**Ruling J-22:** `present` holds for any `ok` envelope, and the services collector writes `ok:false` (not absent) for a unit that is not installed — so `op: present` would run the checks on every host and a host with no NFS server would read MANUAL, contradicting the description. `op: eq, expected: true` gives NOT_APPLICABLE for `installed ok:false`, and `unsupported` (no systemd) screens to NA as well.
**Ruling J-28:** the mode list above is the exact sorted literal from `controls/file/passwd_permissions.yaml` — copied, not re-derived.
Description states: judged from the export files; `exportfs -v` corroborates when root; a host with no NFS server is not applicable. `risk: restart_service`, remediation `exportfs -ra` after fixing `/etc/exports`. Confirm the `each … subject … require` shape against `controls/file/log_dir_permissions.yaml` (U-67).

- [ ] **Step 2: U-59 `snmp_version.yaml`** (상, auto, kisa `{2026:[U-59], 2021:[]}`, kisa-only): `applies_when: [{ fact: services.snmp.installed, op: eq, expected: true }]` (Ruling J-22 — never `op: present`); check `{ fact: snmp.versions_enabled, op: none, where: { op: in, expected: [v1, v2c] } }` (the U-43 precedent `controls/service/nis_disabled.yaml`). `absent_means: manual` (the judged lists are absent when `parse_complete` is false).

- [ ] **Step 3: U-60 `snmp_community_strength.yaml`** (중, auto, kisa `{2026:[U-60], 2021:[U-67]}`): `applies_when: [{ fact: services.snmp.installed, op: eq, expected: true }]` (Ruling J-22); `params: min_length: { type: int, default: 8, description: "Minimum number of characters in an SNMP community string" }` (Ruling J-19 — every flow-mapping `description` in this plan is QUOTED, so a comma or a colon inside it cannot end the value and break the strict decoder); checks two `each` over `snmp.communities` with `subject: ref`: `require {field: is_default, op: eq, expected: false}` and `require {field: length, op: gte, expected: "${min_length}"}` (confirm an `int` param substitutes inside `require.expected` — precedent: session_timeout.yaml's `${…}` on an int; if `gte` with a param is not supported inside `require`, use the literal default `8` and note it). `absent_means: manual`.

- [ ] **Step 4: U-61 `snmp_access_control.yaml`** (상, auto, kisa `{2026:[U-61], 2021:[]}`): `applies_when: [{ fact: services.snmp.installed, op: eq, expected: true }]` (Ruling J-22); `each` over `snmp.communities` `subject: ref` `require {field: source_restricted, op: eq, expected: true}`; description says VACM rules and agent addresses are recorded as evidence, and a loopback-only agent does not by itself pass. `absent_means: manual`.

- [ ] **Step 5: Fixtures** (every fixture carries every leaf the `applies_when`/checks read; RFC 5737 addresses only, Ruling J-32): per control `pass-*` and `fail-*` (both with `installed` `{"status":"ok","value":true}`, so the gate holds), `manual-parse-incomplete` (judged list absent), `na-not-installed` (`installed` `{"status":"ok","value":false}` → NA under the Ruling J-22 gate) and `na-no-systemd` (`installed` `unsupported` → NA via the screen). U-40 adds `fail-world.json` (wildcard), `fail-no-root-squash.json`, `fail-mode.json` (0664), `pass-empty.json` (exports `[]`, perms ok → PASS: nothing exported is not a finding). U-60 adds `fail-default-public.json`, `fail-short.json`. U-61 adds `fail-unrestricted.json`.

- [ ] **Step 6: Lint + evaluate + commit.** `controls lint --references docs/reference` (count = 45+4 = 49 here, before the rebase; fine), `go test ./internal/controls/...`. Commit "Add the NFS export and SNMP controls".

---

### Task 5: U-64 patch control (partial) + fixtures

- [ ] **Step 1: `controls/patch/security_updates.yaml`** (category patch, 상, **automation: partial**, kisa `{2026:[U-64], 2021:[U-42]}`, stig `rhel9 V2R9 RHEL-09-211015`, `requires_facts: ">=1"`, `absent_means: manual`):
```yaml
params:
  max_metadata_age_s: { type: int, default: 604800, description: "Oldest acceptable age of the cached package metadata, in seconds" }
applies_when:
  - { fact: patch.manager, op: in, expected: [apt, dnf] }
checks:
  - { fact: patch.metadata_age_s, op: lte, expected: "${max_metadata_age_s}" }
  - { fact: patch.pending_security_count, op: eq, expected: 0 }
```
**Ruling J-19 (blocking):** the `description` MUST be quoted — inside a YAML flow mapping an unquoted comma ends the value and the strict decoder (`KnownFields(true)`) fails with `field in seconds not found in type controls.Param`. The same rule was applied to every flow-mapping scalar in this plan's YAML; the `patch.manager op: in [apt, dnf]` gate reads a string and stays as it is.
**Ruling J-25:** the `applies_when` gate is unchanged, but the two "cannot see" shapes differ — no cache at all → BOTH judged leaves `absent` → MANUAL; a cache without a security channel → `pending_security_count` `unsupported` → NOT_APPLICABLE.
Description: judged from cached metadata only (never refreshed, D27); a stale cache is reported with its age; **a host with no package metadata cache at all is MANUAL — it may never have been updated**; when a cache exists but carries no security metadata the result is not applicable; reboot-required and auto-update state are evidence. `partial` because a pending count from a cache cannot prove the host is current (spec Appendix A). Confirm `lte` exists in `orderedOps` (sibling of `gte`) and that an int param substitutes in `expected`.

- [ ] **Step 2: Fixtures** — `pass-current.json` (age 3600, count 0), `fail-pending.json` (count 2 → **WARN**, partial), `fail-stale-cache.json` (age 30 days → WARN "with its age"), `manual-no-cache.json` (**Ruling J-25: `patch.metadata_age_s` AND `patch.pending_security_count` BOTH `absent`** → MANUAL; a fixture with the count `unsupported` here would evaluate NA, because `mergeSoft` lets `unsupported` beat `absent` — that is the shape `na-no-security-metadata.json` tests), `na-no-security-metadata.json` (age ok, `pending_security_count` unsupported → NA), `na-unknown-manager.json`.
- [ ] **Step 3: Lint + evaluate + commit.** "Add the security-updates patch-hygiene control".

---

### Task 6: rebase onto the post-2I main, then reconcile 47 → 52

- [ ] **Step 0 (gate):** confirm plan 2I has MERGED (`git -C <main> log --oneline -3` shows the 2I merge). If not, STOP and report — do not reconcile against a stale main.
- [ ] **Step 1:** `git rebase main` (Ruling J-16). Resolve `internal/facts/registry.yaml` by keeping both EOF blocks (2I's, then 2J's); run `go test ./internal/facts` at once (`LoadRegistry` rejects any duplicate key); regenerate the golden (`-update`); resolve `register.go` (both collector registrations).
- [ ] **Step 2:** `cmd/muster/controls_test.go`: both `ok: 47 controls` → `ok: 52 controls`. `e2e_test.go`: "forty-seven"→"fifty-two", "forty-six"→"fifty-one"; add the five ids to BOTH maps as PASS (H-15 — never FAIL in `full-fail.json`; the waiver literal at ~`:101` stays). `full-{pass,fail}.json`: the same passing facts for all five (nfs exports `[]` or restricted + perms ok; snmp v3-only with restricted long communities or `[]`; patch age 3600, security count 0, manager apt). Every read leaf present.
  **Ruling J-22 (blocking) — the shared fixtures are missing the gate leaves.** `cmd/muster/testdata/full-pass.json` and `full-fail.json` today carry `services.nfs_server.{active,enabled,reachable}` and `services.snmp.{…}` but **no `installed` leaf at all**, so either gate form would resolve `installed` as `missing` → `screen()` hard → **ERROR(missing_fact)**, breaking `TestCheckEndToEnd…` and the waiver tally. BOTH files must gain `services.nfs_server.installed` and `services.snmp.installed` as `{"status":"ok","value":true}` (leave `active`/`enabled`/`reachable` `false`, so `nfs_server_disabled`/`snmp_disabled` keep their current statuses), plus every other leaf the five controls read: `nfs.exports`, `files.etc_exports.{mode,uid}`, `snmp.{versions_enabled,communities}`, `patch.{manager,metadata_age_s,pending_security_count}`. Verify by loading both files after the edit — a missing leaf is an ERROR, not a MANUAL.
- [ ] **Step 3:** `go run ./tools/coverage` → `52 of 67 items enrolled (auto 47, partial 5, manual 0).`; `-check` passes. READMEs unchanged unless a count sentence exists.
- [ ] **Step 4:** Full gates: `go test ./...` (Windows), `GOOS=linux go vet ./... && go build ./...`, staticcheck, lint → `ok: 52 controls`, coverage -check. `[LAB TOKEN]` — by now 2I has merged, so the token is 2J's: run all three collectors on the lab host (root + non-root). **Ruling J-27:** the snmp `denied` shape is expected on the LAB HOST (snmpd installed) and in the unit test only; on the GitHub `collect-nonroot` runner snmpd is absent, so the snmp reads are ENOENT → `absent`, and that leg's `ERROR > 0` invariant is met by the pre-existing collectors — do not predict or assert a 2J-sourced ERROR there. On the lab non-root run expect: snmp state file `denied`, patch `unsupported`/ok (never denied), nfs `exports_runtime_collected` false. Never commit a snapshot.
  **CI predictions after the rulings** (state them before the run; a deviation is a finding, not a surprise): `collect-contract` (`--network none`, no systemd) — U-40/59/60/61 NOT_APPLICABLE (`installed` unsupported, Ruling J-22), U-64 **MANUAL** if the image has no metadata cache at all (both leaves absent, Ruling J-25) or NA if a cache exists without a security channel, `run.complete == true` (no `/var/run` read, Ruling J-20). Init containers (root, dnf, no cache) — U-64 MANUAL, the four service controls NA (`installed ok:false`). `collect-root` (fresh apt lists) — U-64 WARN or PASS, never ERROR. `collect-nonroot` — patch/nfs never denied; no 2J-sourced ERROR (Ruling J-27).
- [ ] **Step 5: Commit.** "Enrol the NFS, SNMP and patch controls in the coverage and e2e snapshots".

---

## Self-Review

**1. Spec coverage.** §10.2 `snmpd.conf` (versions, redacted communities), "patch hygiene from cached metadata" (D27), the `patch` and `snmp` snapshot sections; §5.6 (embedded `is_default`); step 13 "stale cache → WARN with its age" realised by the mandatory `lte` clause on a `partial` control (no engine change). U-40's merged 2021 scope (U-25 + U-69) → exports content + `/etc/exports` permission facts. `packages.installed` for 2L (D14: versions from the package DB, never a daemon).

**2. Placeholder scan.** The `≤ 0644` subset list is now the verbatim sorted literal from `controls/file/passwd_permissions.yaml` (Ruling J-28); the two remaining grammar confirmations (an `int` param inside `require`/`expected`, `lte` in `orderedOps`) each name a merged precedent and were both verified by the pre-flight through the real engine. All five YAML blocks were decoded through the real loader (the 2I lesson) — the one failure, the unquoted flow-mapping `description`, is fixed by Ruling J-19, and every flow-mapping scalar in this plan is now quoted.

**3. Type consistency.** Judged: `nfs.exports` (`each`), `files.etc_exports.{mode,uid}`, `snmp.versions_enabled` (`none`), `snmp.communities` (`each`, `secret`), `patch.metadata_age_s` (`int`, `lte`), `patch.pending_security_count` (`int`, `eq`). Evidence: the rest. `applies_when` gates: `services.nfs_server.installed`, `services.snmp.installed` (2G, exist), `patch.manager`.

**Risks (for the pre-flight and reviews):**
- **R-a (secret leakage):** any code path that copies a community string or v3 key into a record, reason, or source `raw` field is a defect; the redaction test must grep the serialized snapshot.
- **R-b (D27):** any declared command that could refresh metadata is a defect; `--network none` in CI makes it a hang.
- **R-c (exit 100):** `dnf --cacheonly check-update` exit 100 is success; treating it as failure yields a false "no updates" or a false unsupported.
- **R-d (collect-nonroot, Ruling J-27):** on the GitHub runner snmpd is not installed, so the snmp facts are `absent`, NOT `denied` — the leg's `ERROR > 0` invariant comes from the pre-existing collectors and 2J must not be credited with it. The `denied` shape is proven by the unit test (`fails[stateFile] = ErrPermission`) and by the lab-host non-root run. The nfs/patch collectors must never be denied anywhere (they need no root).
- **R-g (symlinked paths, Ruling J-20):** any `/var/run/...` (or `/var/lock/...`) declaration is a defect — `RESOLVE_NO_SYMLINKS` → `ErrSymlink` → `error` → `run.complete false` → two CI legs fail. Use `/run/...`.
- **R-h (clock, Ruling J-21):** `time.Now()` anywhere in a collector is a defect (non-determinism); the age facts read `b.Header().CollectedAt` and `ReadMeta.ModTime`. If the post-rebase base has no `ReadMeta.ModTime`, adding it is 2J's job — check before duplicating 2I's field.
- **R-i (gating, Ruling J-22):** `op: present` on an `installed` leaf never gates (it holds for `ok:false`); the four service controls use `op: eq, expected: true`, and both shared e2e fixtures must carry the `installed` leaves or every one of them is ERROR(missing_fact).
- **R-e (rebase):** registry EOF interleaving with 2I; `LoadRegistry` duplicate rejection is the safety net; count seams reconciled only against the live post-2I main.
- **R-f (U-64 partial fixtures):** `fail-*` → WARN, not FAIL.
