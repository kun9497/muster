# Stage 2I — Logging and Time Synchronisation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol the two KISA 2026 logging-category items U-65 (NTP 및 시각 동기화 설정) and U-66 (정책에 따른 시스템 로깅 설정) by adding a `timesync` collector, a `logging` collector (rsyslog rules → per-facility coverage, journald as a function with a three-tier drop-in merge), the `ntp`/`syslog` rows the `services` table still lacks, and two controls that judge time synchronisation by an active provider with a configured source and logging by **facility coverage, never by path** — degrading to MANUAL (never a fabricated verdict) wherever the configuration cannot be modelled with confidence.

**Architecture:** Three small pieces, each honest about what it cannot see. (1) `services` gains `ntp` and `syslog` logical rows (table-driven since 2G), so `services.ntp.*`/`services.syslog.*` give the running-daemon side with the existing euid/no-systemd degrade loop. (2) A `timesync` collector reads the provider configs (chrony / systemd-timesyncd / ntpd) for the persisted server list and runs ONE unprivileged runtime oracle, `timedatectl show-timesync --all` + `timedatectl show -p NTP,NTPSynchronized`, because timesyncd ships its config fully commented and only the daemon knows its compiled-in servers; a `timedatectl` that cannot run is an environment limitation → `unsupported` (R220 — it needs no root, so it is never `denied`). (3) A `logging` collector detects the implementation (rsyslog / syslog-ng / journald-only / none), parses rsyslog selectors, `omfile` actions, forwarding and includes into per-**facility** coverage records (a path-based clause is a guaranteed FAIL on one distro family), stats the file targets for persistence, and merges journald's `/usr/lib` < `/etc` < `/run` drop-ins through a shared helper into a two-sided `journald.storage` setting. Judged leaves are emitted **`absent`** when the parse is incomplete or carries unmodelled constructs, so `absent_means: manual` yields MANUAL (the R241/2H pattern, no engine change).

**Tech Stack:** Go 1.25.x, Linux-only collectors behind build tags; `systemctl show` via the services table; `timedatectl` via the exec discipline; config files under `/etc/chrony*`, `/etc/systemd/timesyncd.conf{,.d}`, `/etc/ntp.conf`, `/etc/rsyslog.conf` + `/etc/rsyslog.d/*.conf`, `/etc/syslog-ng/`, `/{usr/lib,etc,run}/systemd/journald.conf{,.d}`; YAML controls using `applies_when`, `mechanisms`, `each … where … require`, a `list<string>` `${facilities}` param, and `absent_means: manual`; fixtures under `controls/testdata/<id>/{pass,fail,manual,na}-*.json`.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` (§4/§5.3 two-sided settings incl. the sysctl drop-in shadowing rule; §6.3–6.6 clause grammar incl. `each`, params; §6.5 steps 3/8/13; §10.2 "logging as a function (journald-only hosts)", "time synchronisation"; the logical-service map `ntp`→chrony/systemd-timesyncd/ntpd, `syslog`→rsyslog/syslog-ng/journald (line ~108); D09). The plan argues from the spec; conflicts resolve against it. Scope brief with all citations: `<session-scratchpad>/2i-scope-brief.md`.

## Global Constraints

- **Control set count: 45 → 47** (two new `auto` controls; coverage becomes `auto 43, partial 4, manual 0`). Every count seam in the final task lands on 47.
- **Registry `schema_version` stays 1.** All new keys are pure additions (C2; spec §5.7). Regenerate the golden with `go test ./internal/facts -run TestFactsSchemaGolden -update`; additions only, each `since: 1`. `subject_kind` appears on exactly ONE new key — `logging.rsyslog.coverage` (`list<record>`, `subject_kind: facility`, the first real use of the `facility` kind the registry already accepts) — and on no scalar key (registry.go rejects it there; the R229 lesson).
- **Every fact leaf is an envelope; a non-ok status never yields PASS.** A registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`.
- **Honest degradation (R220 / H-17) is mandatory and CI-enforced.** The `collect-contract` leg (root, systemd-less, `--network none --read-only` ubuntu:24.04) asserts `.run.complete == true`. `timedatectl` there cannot run → the `timesync` runtime leaves (`time_sync.synchronized`, and for the timesyncd branch `time_sync.servers`/`server_count`) are **`unsupported`**, never `error`/`denied`. `timedatectl show` needs no privilege, so — unlike the firewall ruleset — its failure is NEVER classified `denied`: it is always an environment limitation (`cronTimers` R220 pattern), not the euid split. The new `services.ntp`/`services.syslog` rows inherit the table's degrade loop (unsupported on a no-systemd host) automatically. The `logging` collector is pure file reads (world-readable by default): an existing-but-unreadable file is a `FromReadError`/`denied` envelope (C3), never a silent default.
- **MANUAL-on-uncertainty via `absent_means: manual`, no engine change (§7.3 pattern from 2H).** The judged leaves `logging.rsyslog.coverage` (when `parse_complete == false` OR `unmodelled > 0`) and `time_sync.servers`/`server_count` (timesyncd branch when `timedatectl` is unavailable) are emitted **`absent`** with a reason; both controls carry `absent_means: manual`. **Under-claiming (MANUAL) is the safe direction; never a confidently-wrong PASS/FAIL** (the H-16 lesson).
- **U-66 keys on facility, never on a path** (analysis riskiest decision #1): Ubuntu logs auth to `/var/log/auth.log`, RHEL to `/var/log/secure`; the control asks "is facility X logged to a persistent target", expressed with `each … where {facility in ${facilities}} require {…}` over `logging.rsyslog.coverage`, with `facilities` a `list<string>` control param (spec §6.6 — the required set is data, tunable, defaulting to the guide's intent). A `*` selector covers every facility; `facility.none` exclusions are honoured.
- **`time_sync.synchronized` is evidence only, never a clause** (analysis riskiest decision #2 — a freshly booted or air-gapped host is not a finding).
- **Same input, same bytes.** Sort drop-in files, server lists (de-duplicated), rule and coverage records deterministically; no `map` reaches output.
- **`references.stig` only cites ids present in `docs/reference/stig/*.json`** (lint rejects others). Verified ids for this plan: U-65 → `rhel9 V2R9 RHEL-09-252010` (chrony installed), `RHEL-09-252015` (chronyd enabled); U-66 → `rhel9 V2R9 RHEL-09-652010` (rsyslog installed), `RHEL-09-652020` (rsyslog active). **Do NOT cite the Ubuntu chrony-only / timesyncd-forbidden rules (UBTU-22-215015/020/025, UBTU-24-100700)** — their criterion (chrony mandatory, timesyncd forbidden) is the opposite polarity of KISA U-65 (any provider); citing them would misrepresent. Ubuntu has no rsyslog-policy rule → U-66 is kisa-only on Ubuntu. No `make refindex`.
- **KISA ids (verified against `docs/reference/kisa/kisa_mapping.json`):** U-65 is `relation: new` with **no 2021 predecessor** (`from_2021: []`) — express the 2021 side exactly the way the merged `relation: new` control U-67 `controls/file/log_dir_permissions.yaml` does (copy its `references.kisa` shape); U-66 ← 2021 **U-72** (`renumbered`, importance raised 하→중): `{ "2026": ["U-66"], "2021": ["U-72"] }`.
- **Never copy KISA/CIS text.** Descriptions are muster's own words, EN canonical + KO pair.
- **Fixtures are `synthetic: true`**, never from a real host; never commit a lab snapshot (D02).
- **Category `log`** (KISA files U-65/U-66 under 로그 관리; muster's category mirrors KISA's taxonomy — valid values are account|file|service|patch|log|beyond). Ids: `muster.log.time_sync` (U-65), `muster.log.syslog_policy` (U-66). Both PASS in BOTH shared e2e fixtures (the H-15 convention: the waiver e2e counts exactly 10 waived FAILs; a new FAIL in `full-fail.json` breaks it).
- **Controller boundary rulings (folded in):**
  - **I-1:** U-65 PASS = `services.ntp.active == true` AND `time_sync.server_count >= 1`; FAIL = active provider with zero sources, or no active provider; NA (via `applies_when` on `services.ntp.installed`) on a no-systemd host. `synchronized` is evidence.
  - **I-2:** U-66 = three mechanisms in order: syslog daemon (rsyslog/syslog-ng → facility coverage), journald-only (→ `logging.journald.persistent == true`), none (→ FAIL). Remote forwarding is evidence only (beyond the item; the STIG's offload bar is higher than KISA's).
  - **I-3:** one runtime command, `timedatectl` (unprivileged); no `chronyc`/`ntpq` (extra exec surface, socket-dependent). chrony/ntpd server lists come from files (authoritative there); the timesyncd list comes from `timedatectl show-timesync` (its file ships commented) merged with any `NTP=` lines.
  - **I-4:** 2I adds the `ntp` and `syslog` rows to the `services` table (2I's analysis dependency "2G services.{syslog,cron}" does not resolve against anything merged). The analysis keys `time_sync.active_providers`/`service_active`/`unit_file_state` are **dropped** as redundant with `services.ntp.*` — the control ANDs facts from both collectors (as U-43 ANDs `services.nis.*` with `accounts.nss.*`). No `reachable`/ports on either row (123/udp and 514 are not judged; avoids a false-negative class).
  - **I-5:** journald's three-tier drop-in precedence becomes a SHARED helper (`internal/collect/collectors/dropin.go`) modelled on the spec's sysctl rule — "a file in an earlier directory shadows one of the same name in a later directory and the surviving files apply in lexicographic order" — with directory order `/etc/systemd/journald.conf.d` > `/run/systemd/journald.conf.d` > `/usr/lib/systemd/journald.conf.d` for shadowing, the main `/etc/systemd/journald.conf` applied first, later files winning per key. 2I uses it for journald only; migrating the inline pwquality/faillock copies is parked for 2M.
  - **I-6:** v1 models rsyslog classic selectors (`facility.priority[;…] target`, incl. `*`, `,` lists, `.none`, `=`/`!` priority modifiers ignored-but-noted), `omfile` RainerScript actions (`action(type="omfile" file="…")`), forwarding targets (`@host`, `@@host`, `action(type="omfwd" …)`) as `target_kind: remote`, `~`/`stop`/`discard`, and `$IncludeConfig`/`include(file=…)` (followed; an include that cannot be read → `parse_complete: false`). Any other construct (`if … then`, `ruleset(…)`, property filters `:msg, contains, …`, templates) is counted in `rsyslog.unmodelled` (evidence) and makes `coverage` **absent** → MANUAL. syslog-ng configs are NOT parsed in v1 → `implementation: syslog-ng` with `coverage` absent → MANUAL (honest).
  - **I-7:** `logging.logrotate.*` from the analysis is **deferred** (not needed by U-65/U-66's judgment).
  - **I-8:** `logging.journald.persistent` (judged bool) = `Storage=persistent`, or `Storage=auto` (or unset — systemd's default is `auto`) with `/var/log/journal` present; `volatile`/`none`, or `auto` without the directory → false. `journald.storage` stays a two-sided evidence setting (persisted = merged `Storage=`, runtime = whether `/var/log/journal` exists), both sides always set (H-18).

---

## File Structure

**Collectors — create/modify:**
- `internal/collect/collectors/services.go` — append the `ntp` and `syslog` rows to `var services` (Task 1).
- `internal/collect/collectors/timesync.go` + `timesync_test.go` — **new** `timesync` collector (Task 1).
- `internal/collect/collectors/dropin.go` + tests — **new** shared drop-in merge helper (Task 3).
- `internal/collect/collectors/logging.go` + `logging_test.go` — **new** `logging` collector: implementation detection, rsyslog parse, coverage, log targets (Task 2); journald settings via the helper (Task 3).
- `internal/facts/registry.yaml` + `internal/facts/testdata/facts-schema.golden.json` — new `services.ntp.*`, `services.syslog.*`, `time_sync.*`, `logging.*` keys.
- Register both collectors at the assembly site (grep where `firewallCollector` was added in 2H — `register.go` — add `timesyncCollector`, `loggingCollector` the same way).

**Controls (Task 4) — create:**
- `controls/log/time_sync.yaml` (U-65) + `controls/testdata/muster.log.time_sync/`
- `controls/log/syslog_policy.yaml` (U-66) + `controls/testdata/muster.log.syslog_policy/`
- (Create `controls/log/` if no `log`-category control exists yet; confirm the embed pattern picks up a new subdirectory — grep `controls/embed.go` or the `//go:embed` directive.)

**Reconciliation (Task 5) — modify:**
- `cmd/muster/controls_test.go` (`ok: 45 controls` ×2 → 47), `cmd/muster/e2e_test.go` (two spelled-out counts + both maps), `cmd/muster/testdata/full-{pass,fail}.json`, `docs/reference/coverage.md` (regenerated), README pair only if a count sentence exists (none today).

---

## Interfaces (produced by this plan)

New fact keys (all `since: 1`, `sensitivity: public` unless noted):
- `services.ntp.{installed,active,unit_file_state,enabled}` and `services.syslog.{installed,active,unit_file_state,enabled}` — from the services table rows (no `reachable`).
- `time_sync.provider` — `string`: `chrony` | `timesyncd` | `ntpd` | `none` — which provider's configuration is present (persisted view; evidence).
- `time_sync.servers` — `list<string>` — de-duplicated, sorted server/pool names from the provider config **and** (timesyncd) `timedatectl show-timesync`; **`absent`** on the timesyncd branch when `timedatectl` is unavailable (the effective list is unknowable).
- `time_sync.server_count` — `int` — `len(servers)`; same absence rule. **Judged leaf.**
- `time_sync.synchronized` — `bool` — `timedatectl show -p NTPSynchronized`; `unsupported` when the command cannot run. Evidence only.
- `logging.syslog.implementation` — `string`: `rsyslog` | `syslog-ng` | `journald-only` | `none`.
- `logging.rsyslog.rules` — `list<record>` `{facility, priority, target, target_kind}` (`target_kind`: file|remote|user|pipe|module|discard).
- `logging.rsyslog.parse_complete` — `bool` — false when an include could not be read.
- `logging.rsyslog.unmodelled` — `int` — count of constructs v1 does not model.
- `logging.rsyslog.coverage` — `list<record>` `{facility, logged, priority_floor, target, persistent}`, `subject_kind: facility`; **`absent`** when `parse_complete` is false or `unmodelled > 0`. **Judged leaf.**
- `logging.log_targets` — `list<record>` `{path, exists, persistent, mtime_age_s}` — stat of every file target named by the rules.
- `logging.journald.storage` — `setting<string>`, `default_on: both` — persisted = merged `Storage=`, runtime = `persistent`/`volatile` by `/var/log/journal` presence.
- `logging.journald.forward_to_syslog` — `bool` — merged `ForwardToSyslog=` (evidence).
- `logging.journald.persistent` — `bool` — **judged leaf** for the journald-only mechanism (I-8).

---

### Task 1: `ntp`/`syslog` service rows + the `timesync` collector

**Files:**
- Modify: `internal/collect/collectors/services.go` (table), `internal/facts/registry.yaml` (+golden), the collector registration site.
- Create: `internal/collect/collectors/timesync.go`, `timesync_test.go`, testdata (`timedatectl.show-timesync`, `timedatectl.show`, `chrony.conf.pool`, `ntp.conf.servers`, `timesyncd.conf.commented`).

**Interfaces:**
- Consumes: the `logicalService`/`unitRef` table shape (2G), `collect.Command`, `collect.Unsupported`, `readErrorEnv`/`FromReadError`, the `buildBegun` test helper (2H — it calls `Begin` so `Worst` assertions are real), `allUnitsNotFound()` (table-driven since 2G; extend automatically by iterating the table).
- Produces: `services.ntp.*`, `services.syslog.*`, `time_sync.{provider,servers,server_count,synchronized}`.

- [ ] **Step 1: Write the failing tests**

```go
// The new rows exist and degrade with the table: on a no-systemd host every
// services.ntp.*/services.syslog.* key is unsupported and Worst stays ok.
func TestServicesNtpAndSyslogRowsDegradeWithTheTable(t *testing.T) {
	b := buildBegun(t, "services", &fsAccess{}) // no /run/systemd/system
	for _, k := range []string{"services.ntp.installed", "services.ntp.active", "services.syslog.installed", "services.syslog.enabled"} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s = %s, want unsupported", k, e.Status)
		}
	}
	if got := b.Worst("services"); got != facts.StatusOK {
		t.Errorf(`Worst("services") = %s, want ok`, got)
	}
}

// chrony: servers come from the files; timedatectl is not consulted for the list.
func TestTimesyncChronyServersFromFiles(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.pool"}, nil)
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "chrony" { t.Errorf("provider: %+v", e) }
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value != 2 { t.Errorf("server_count: %+v", e) }
}

// timesyncd with a fully commented config: the list comes from timedatectl show-timesync.
func TestTimesyncTimesyncdServersFromTimedatectl(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/systemd/timesyncd.conf": "timesyncd.conf.commented"},
		map[string]cmdResult{timedatectlShowTimesyncKey: {file: "timedatectl.show-timesync"}, timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value == 0 { t.Errorf("server_count from timedatectl: %+v", e) }
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusOK { t.Errorf("synchronized: %+v", e) }
}

// timesyncd + timedatectl unavailable (systemd-less container): the list is ABSENT
// (→ MANUAL), synchronized is unsupported, and the run stays complete (R220).
func TestTimesyncTimedatectlUnavailableIsAbsentNotError(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/systemd/timesyncd.conf": "timesyncd.conf.commented"}, nil) // commands unmapped → Err
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusAbsent { t.Errorf("servers must be absent: %+v", e) }
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusUnsupported { t.Errorf("synchronized: %+v", e) }
	if got := b.Worst("timesync"); got != facts.StatusOK { t.Errorf(`Worst("timesync") = %s, want ok`, got) }
}
```

Write `timesyncAccess(files, cmds)` mirroring `servicesAccess`/`firewallAccess` in `collectors_test.go`/`firewall_test.go` (canned command stdout from a testdata file keyed by the exact Path+Args string). Add the testdata files.

- [ ] **Step 2: Run to confirm failure.** `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run 'TestServicesNtp|TestTimesync'`

- [ ] **Step 3: Add the services rows**

Append to `var services` (keep ordering stable; both rows `provesInstall: true`, no `inetdNames`, no `servers`, no `ports`):
```go
{name: "ntp", units: []unitRef{{"chrony.service", true}, {"chronyd.service", true}, {"systemd-timesyncd.service", true}, {"ntpd.service", true}, {"ntp.service", true}, {"ntpsec.service", true}}},
{name: "syslog", units: []unitRef{{"rsyslog.service", true}, {"syslog-ng.service", true}}},
```
`declaredShowCommands()` and the no-systemd degrade loop pick them up automatically; `allUnitsNotFound()` is table-driven (2G) so existing tests stay green.

- [ ] **Step 4: Implement the `timesync` collector**

- `Declare.Reads`: `/etc/chrony.conf`, `/etc/chrony/chrony.conf`, `/etc/chrony/conf.d/*.conf`, `/etc/chrony/sources.d/*.sources`, `/etc/systemd/timesyncd.conf`, `/etc/systemd/timesyncd.conf.d/*.conf`, `/etc/ntp.conf`, `/etc/ntpsec/ntp.conf`. `Declare.Commands`: exactly two, byte-identical in declaration/run/test key: `/usr/bin/timedatectl show-timesync --all` and `/usr/bin/timedatectl show -p NTP -p NTPSynchronized`. `Needs: "none"`.
- `provider`: `chrony` if any chrony config exists; else `timesyncd` if `timesyncd.conf` exists (or its `.d`); else `ntpd` if an ntp.conf exists; else `none`. (Evidence — the running daemon is `services.ntp.*`.)
- `servers`: chrony — `server|pool|peer <name>` lines (+ `sourcedir` dirs' `*.sources`); ntpd — `server|pool <name>`; timesyncd — `NTP=`/`FallbackNTP=` from the merged conf **plus** `ServerName=`/`SystemNTPServers=`/`FallbackNTPServers=` from `timedatectl show-timesync`. De-duplicate, sort. `server_count = len`.
- **Degradation:** `timedatectl` failure (Err / TimedOut / non-zero) → `synchronized` = `collect.Unsupported("timedatectl unavailable: <first stderr line>")`; and ONLY on the `timesyncd` branch, `servers`/`server_count` = `collect.Absent("effective NTP server list unknown: timedatectl unavailable; see timesyncd.conf")` (files alone cannot know the compiled-in fallback). Never `denied`, never `error` (the command is unprivileged — document this in a comment contrasting it with the firewall euid split). An existing-but-unreadable config → `FromReadError` on `servers`/`server_count`/`provider` (C3).
- Sources: a `derived` source listing the files/commands read, one fresh pointer per envelope.

- [ ] **Step 5: Register keys, regenerate golden, gates.** Add `services.ntp.*`/`services.syslog.*` (4 each), `time_sync.provider` (string), `time_sync.servers` (`list<string>`, NO subject_kind), `time_sync.server_count` (int), `time_sync.synchronized` (bool). `GOOS=linux GOARCH=amd64 go test ./internal/facts -run TestFactsSchemaGolden -update` (additions-only). `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ ./internal/facts`; gofmt; `GOOS=linux go vet ./...`; staticcheck.

- [ ] **Step 6: Lab host.** Sync + run (READ-ONLY scratchpad `lab-sync.sh`/`lab-run.sh` via the PowerShell tool with Git Bash explicitly; never edit them). The lab host is Ubuntu 22.04 (systemd-timesyncd or chrony): report `time_sync.provider`, `server_count`, `synchronized`, and `services.ntp.active`; root collect must be complete. Never commit a host snapshot.

- [ ] **Step 7: Commit.** `git add internal/collect/collectors/services.go internal/collect/collectors/timesync.go internal/collect/collectors/timesync_test.go internal/collect/collectors/testdata/ internal/collect/collectors/register.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json` — "Add the ntp/syslog service rows and the timesync collector".

---

### Task 2: `logging` collector — implementation, rsyslog rules, facility coverage, log targets

**Files:**
- Create: `internal/collect/collectors/logging.go`, `logging_test.go`, testdata (`rsyslog.conf.ubuntu`, `rsyslog.d/50-default.conf`, `rsyslog.conf.rhel`, `rsyslog.conf.rainerscript-if` (unmodelled), `rsyslog.conf.include-missing`).
- Modify: `internal/facts/registry.yaml` (+golden), the registration site.

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Glob`, `Stat`), `FromReadError`, the `facility` subject kind (already valid in `registry.go`).
- Produces: `logging.syslog.implementation`, `logging.rsyslog.{rules,parse_complete,unmodelled,coverage}`, `logging.log_targets`. (`logging.journald.*` lands in Task 3.)

- [ ] **Step 1: Write the failing tests**

```go
// Ubuntu default: "*.*;auth,authpriv.none -/var/log/syslog" + "auth,authpriv.* /var/log/auth.log"
// → auth AND authpriv logged to persistent targets; kern/daemon/cron covered by the catch-all.
func TestLoggingUbuntuDefaultCoversFacilitiesByFacilityNotPath(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.ubuntu", "/etc/rsyslog.d/50-default.conf": "rsyslog.d/50-default.conf"}, /* targets exist */ []string{"/var/log/syslog", "/var/log/auth.log"})
	b := buildBegun(t, "logging", a)
	if e := env(t, b, "logging.syslog.implementation"); e.Value != "rsyslog" { t.Fatalf("impl: %+v", e) }
	cov := okList(t, b, "logging.rsyslog.coverage")
	for _, f := range []string{"auth", "authpriv", "kern", "daemon", "cron"} {
		rec := findFacility(t, cov, f)
		if rec["logged"] != true || rec["persistent"] != true { t.Errorf("%s: %+v", f, rec) }
	}
}

// RHEL default: "authpriv.* /var/log/secure" etc. → same facilities logged, different paths.
func TestLoggingRhelDefaultCoversFacilities(t *testing.T) { /* rsyslog.conf.rhel; /var/log/secure, /var/log/messages exist */ }

// An include the collector cannot read → parse_complete false → coverage ABSENT (→ MANUAL).
func TestLoggingUnreadableIncludeMakesCoverageAbsent(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.include-missing"}, nil)
	a.fails["/etc/rsyslog.d/10-custom.conf"] = os.ErrPermission
	b := buildBegun(t, "logging", a)
	if e := env(t, b, "logging.rsyslog.parse_complete"); e.Value != false { t.Errorf("parse_complete: %+v", e) }
	if e := env(t, b, "logging.rsyslog.coverage"); e.Status != facts.StatusAbsent { t.Errorf("coverage must be absent: %+v", e) }
}

// An unmodelled RainerScript construct → unmodelled > 0 → coverage ABSENT (under-claim, never a guess).
func TestLoggingUnmodelledRainerScriptMakesCoverageAbsent(t *testing.T) { /* rsyslog.conf.rainerscript-if */ }

// No rsyslog/syslog-ng config or unit evidence on a systemd host → journald-only.
func TestLoggingJournaldOnlyImplementation(t *testing.T) { /* no rsyslog files; /run/systemd/system present → "journald-only" */ }

// A file target that does not exist is not persistent; a remote target is target_kind remote.
func TestLoggingTargetsPersistenceAndRemote(t *testing.T) { /* "*.* @@logs.example.invalid:514" + a missing /var/log/foo */ }
```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement**

- **Implementation detection:** `rsyslog` if `/etc/rsyslog.conf` exists; else `syslog-ng` if `/etc/syslog-ng/syslog-ng.conf` exists; else `journald-only` if `/run/systemd/system` exists; else `none`. (The running-daemon side is `services.syslog.*`; the control ANDs it.)
- **rsyslog parse (I-6):** read `/etc/rsyslog.conf`; follow `$IncludeConfig <glob>` and `include(file="…")` (declare `/etc/rsyslog.d/*.conf` and the include globs in `Declare.Reads`); sorted glob order. Classic selector lines → one rule record per `facility` × target after expanding `,` lists, `*`, and `;` compound selectors; `.none` records an exclusion for that facility on that target. RainerScript `action(type="omfile" file="…")` → file target; `omfwd`/`@host`/`@@host` → `remote`; `~`/`stop` → `discard`; `:omusrmsg:`/user lists → `user`; `|` → `pipe`. Anything else non-blank/non-comment (`if`, `ruleset`, `:msg,`, `template(`, `module(` is fine — modules are not rules; count only rule-ish constructs) → `unmodelled++`. `parse_complete = false` iff an include could not be read (record the path in the coverage reason).
- **Coverage derivation:** for each syslog facility name (`auth authpriv cron daemon ftp kern lpr mail news syslog user uucp local0..local7`), `logged` = some rule (incl. `*`) targets it and no `.none` on that target excludes it, with a `file` or `remote` target; `priority_floor` = the lowest priority selected; `target` = the first such target; `persistent` = the target is a file that exists (per `log_targets`) — remote-only coverage is `logged: true, persistent: false` (evidence; the control requires persistence — a central-forwarding host with no local file will read MANUAL/FAIL per the control's `${facilities}` — document in the description). Emit as `list<record>` sorted by facility. **Emit `absent` instead when `parse_complete == false` or `unmodelled > 0`.**
- **log_targets:** stat every distinct file target (`-`-prefixed async paths stripped): `{path, exists, persistent(=exists && regular file), mtime_age_s}`; a stat that is denied → that record's fields carry the error envelope shape used by 2E's home_dirs (`stat_status`) — mirror it.
- A missing `/etc/rsyslog.conf` is simply "not rsyslog"; an existing-but-unreadable one → `FromReadError` on all `rsyslog.*` leaves.

- [ ] **Step 4: Register keys (`coverage` carries `subject_kind: facility`; `rules`/`log_targets` carry none — confirm what `registry.go` requires for list types), regenerate golden (additions-only), gates.** Note the golden/lint path for `subject_kind: facility` is exercised for the first time — if `TestFactsSchemaGolden` or lint rejects it, that is a real finding to report, not to work around.

- [ ] **Step 5: Lab host run** (Ubuntu 22.04 with rsyslog): report `implementation`, `parse_complete`, `unmodelled`, and whether `coverage` came back `ok` with auth/authpriv/kern persistent — the realistic proof that the Ubuntu default config is fully modelled (if it reads `absent`, the default config has a construct I-6 must model; fix and re-run, do not widen the unmodelled net).

- [ ] **Step 6: Commit.** "Add the logging collector: rsyslog rules and per-facility coverage".

---

### Task 3: journald as a function — the shared drop-in helper + `journald.*`

**Files:**
- Create: `internal/collect/collectors/dropin.go` (+ tests in `dropin_test.go`).
- Modify: `internal/collect/collectors/logging.go` (+ tests), `internal/facts/registry.yaml` (+golden).

**Interfaces:**
- Produces: `mergeDropins(a collect.Access, main string, dirs []string, glob string) (values map[string]string, inputs []facts.Source, readErr error)` — returns the last-write-wins key/values over: the `main` file first, then the surviving drop-ins where a file in an EARLIER `dirs` entry shadows a same-named file in a later one, applied in lexicographic basename order; `inputs` lists every file actually read; `readErr` is the FIRST read error of an existing file (R148: it poisons every derived value). Deterministic.
- Produces: `logging.journald.storage` (`setting<string>`, `default_on: both`), `logging.journald.forward_to_syslog` (bool), `logging.journald.persistent` (bool, judged).

- [ ] **Step 1: Write the failing tests**

```go
// /etc shadows /run shadows /usr/lib for the SAME basename; survivors apply in basename order; later wins.
func TestMergeDropinsShadowingAndOrder(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/systemd/journald.conf":                       "journald.conf.main",       // Storage=auto
		"/usr/lib/systemd/journald.conf.d/10-vendor.conf":  "journald.d.10-vendor",     // Storage=volatile (shadowed by /etc 10-vendor)
		"/etc/systemd/journald.conf.d/10-vendor.conf":      "journald.d.10-vendor-etc", // Storage=persistent
		"/run/systemd/journald.conf.d/20-runtime.conf":     "journald.d.20-runtime",    // ForwardToSyslog=yes
	}, nil)
	vals, inputs, err := mergeDropins(a, "/etc/systemd/journald.conf",
		[]string{"/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d", "/usr/lib/systemd/journald.conf.d"}, "*.conf")
	if err != nil { t.Fatal(err) }
	if vals["Storage"] != "persistent" || vals["ForwardToSyslog"] != "yes" { t.Errorf("vals: %+v", vals) }
	if len(inputs) != 3 { t.Errorf("inputs (shadowed file must NOT be read/listed): %+v", inputs) }
}

// Storage=auto + /var/log/journal present → persistent true; auto without the dir → false; persistent → true; volatile → false.
func TestJournaldPersistentDerivation(t *testing.T) { /* four sub-cases */ }

// An existing-but-unreadable drop-in poisons every journald leaf with the read error (C3), never a default.
func TestJournaldUnreadableDropinIsNotADefault(t *testing.T) { /* fails["/etc/systemd/journald.conf.d/10-x.conf"]=ErrPermission → storage/forward/persistent denied */ }
```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement `mergeDropins` and the journald leaves**

- Helper: read `main` (missing is fine — systemd defaults apply; an existing-unreadable main is `readErr`); glob each dir (sorted), build a basename→path map honouring shadowing (first dir wins), then sort survivors by basename and read them in order; parse `Key=Value` under any `[Section]` (journald has one section; keep the parser section-agnostic but record the section), last write wins; `#`/`;` comments and blank lines skipped; a value of `""` resets (systemd semantics — document). Declare the three dirs' globs and the main file in `Declare.Reads`.
- `journald.storage`: persisted side = merged `Storage` (default `auto` when unset — systemd's documented default); runtime side = `persistent` if `Stat("/var/log/journal")` is a directory, else `volatile`; both sides always set; a stat that is denied → that side `FromReadError` (never ErrorEnv for "not modelled").
- `journald.forward_to_syslog`: merged `ForwardToSyslog` (`yes`/`no`; default `no` — document). Evidence.
- `journald.persistent` (I-8): true iff `Storage == persistent` OR (`Storage ∈ {auto, ""}` AND `/var/log/journal` exists). On a non-systemd host (no `/run/systemd/system`) all three journald leaves are `unsupported("no systemd journald on this host")`. `readErr` → all three carry it.

- [ ] **Step 4: Register the three keys (`setting<string>` with `default_on: both` for storage), regenerate golden (additions-only), gates; lab-host run reports `journald.storage` both sides and `journald.persistent`.**

- [ ] **Step 5: Commit.** "Merge journald drop-ins through a shared helper and derive persistence".

---

### Task 4: the two controls + fixtures

**Files:**
- Create: `controls/log/time_sync.yaml`, `controls/log/syslog_policy.yaml`, fixtures under `controls/testdata/muster.log.time_sync/` and `controls/testdata/muster.log.syslog_policy/`.

**Interfaces:**
- Consumes: `services.ntp.{installed,active}`, `time_sync.server_count`, `logging.syslog.implementation`, `services.syslog.active`, `logging.rsyslog.coverage`, `logging.journald.persistent`.

- [ ] **Step 1: U-65 `controls/log/time_sync.yaml`**

```yaml
id: muster.log.time_sync
title_en: System time is synchronised from a configured source
title_ko: 시스템 시각이 설정된 소스와 동기화된다
description_en: A time-synchronisation daemon (chrony, systemd-timesyncd or ntpd) is running and has at least one configured time source. Whether the clock is currently in sync is recorded as evidence only — a freshly booted or air-gapped host is not a finding. On a host without systemd the daemon state cannot be read and the result is not applicable.
description_ko: 시각 동기화 데몬(chrony, systemd-timesyncd, ntpd)이 실행 중이고 설정된 시각 소스가 하나 이상 있다. 현재 동기화 여부는 증거로만 기록한다 — 막 부팅했거나 망분리된 호스트는 결함이 아니다. systemd 가 없는 호스트에서는 데몬 상태를 읽을 수 없어 해당 없음으로 처리한다.
category: log
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-65"] }   # relation: new — copy the exact 2021-side shape from controls/file/log_dir_permissions.yaml (U-67, also new)
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-252010 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-252015 }
requires_facts: ">=1"
absent_means: manual
applies_when:
  - { fact: services.ntp.installed, op: present }
checks:
  - { fact: services.ntp.active, op: eq, expected: true }
  - { fact: time_sync.server_count, op: <the numeric at-least operator U-12 session_timeout uses for ClientAliveCountMax ≥ 1 — copy its exact op name>, expected: 1 }
remediation:
  text_en: Install and enable a time-synchronisation daemon (chrony on RHEL-family, systemd-timesyncd or chrony on Ubuntu) and configure at least one reachable NTP server or pool.
  text_ko: 시각 동기화 데몬을 설치·활성화하고(RHEL 계열은 chrony, Ubuntu 는 systemd-timesyncd 또는 chrony) 접근 가능한 NTP 서버나 pool 을 하나 이상 설정합니다.
  risk: restart_service
  idempotent: true
decision: D09
```
The STIG ids are chrony-specific while U-65 accepts any provider — say so in one sentence of `description_en/ko` ("the cited STIG rules require chrony specifically"). The implementer confirms the numeric op name against `controls/service/session_timeout.yaml` (U-12) and the `relation: new` kisa shape against U-67.

- [ ] **Step 2: U-66 `controls/log/syslog_policy.yaml`** (mechanisms in order; no `name:` field — label with comments; the 2H-verified shape)

```yaml
id: muster.log.syslog_policy
title_en: System logging covers the security-relevant facilities persistently
title_ko: 시스템 로깅이 보안 관련 facility 를 영구 저장한다
description_en: A syslog daemon (rsyslog or syslog-ng) or systemd-journald keeps the security-relevant facilities in persistent local storage. The judgment is by facility, never by file path, so Ubuntu's auth.log and RHEL's secure both count. Remote forwarding is recorded as evidence only. When the rsyslog configuration uses constructs muster does not model, or an include could not be read, the result is MANUAL with the parse evidence, never a guess; syslog-ng configurations are not parsed in this version and read MANUAL.
description_ko: syslog 데몬(rsyslog 또는 syslog-ng) 또는 systemd-journald 가 보안 관련 facility 를 로컬 영구 저장소에 남긴다. 파일 경로가 아니라 facility 로 판단하므로 Ubuntu 의 auth.log 와 RHEL 의 secure 가 모두 인정된다. 원격 전송은 증거로만 기록한다. rsyslog 설정에 muster 가 모델링하지 않는 구문이 있거나 include 를 읽을 수 없으면 파싱 증거를 첨부한 MANUAL 로 처리하며 추정하지 않는다. syslog-ng 설정은 이 버전에서 파싱하지 않아 MANUAL 로 처리한다.
category: log
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-66"], "2021": ["U-72"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-652010 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-652020 }
params:
  facilities:
    type: list<string>
    default: [auth, authpriv, kern, daemon, cron]
    description_en: The syslog facilities that must be logged to a persistent local target.
    description_ko: 로컬 영구 저장소에 반드시 기록되어야 하는 syslog facility 목록.
requires_facts: ">=1"
absent_means: manual
applies_when:
  - { fact: logging.syslog.implementation, op: present }
mechanisms:
  # syslog daemon: the parsed rules must cover every required facility persistently
  - when:   [{ fact: logging.syslog.implementation, op: in, expected: [rsyslog, syslog-ng] }]
    checks:
      - { fact: services.syslog.active, op: eq, expected: true }
      - fact: logging.rsyslog.coverage
        op: each
        where:   { field: facility, op: in, expected: ${facilities} }
        require:
          - { field: logged, op: eq, expected: true }
          - { field: persistent, op: eq, expected: true }
  # journald-only host: the journal itself must be persistent
  - when:   [{ fact: logging.syslog.implementation, op: eq, expected: journald-only }]
    checks: [{ fact: logging.journald.persistent, op: eq, expected: true }]
  # nothing logs
  - when:   [{ fact: logging.syslog.implementation, op: eq, expected: none }]
    checks: [{ fact: logging.journald.persistent, op: eq, expected: true }]
remediation:
  text_en: Configure rsyslog (or syslog-ng) so that auth, authpriv, kern, daemon and cron messages are written to files under /var/log, or set Storage=persistent in journald.conf on a journald-only host.
  text_ko: rsyslog(또는 syslog-ng)에서 auth, authpriv, kern, daemon, cron 메시지가 /var/log 아래 파일에 기록되도록 설정하거나, journald 만 쓰는 호스트에서는 journald.conf 의 Storage=persistent 를 설정합니다.
  risk: restart_service
  idempotent: true
decision: D09
```
**The implementer MUST confirm the exact `each`/`where`/`require`/`field` grammar and the `${facilities}` list-param substitution against the merged 2F controls** (`controls/file/log_dir_permissions.yaml` U-67 uses `each where … require … in ${allowed_groups}`) and `internal/controls/schema.go`; adjust key names to the real grammar, never invent one. Verify `params` shape (type/default/description) against an existing param-carrying control. Trace (2H-verified composition): coverage `absent` → MANUAL via `absent_means`; implementation `unsupported`/missing → NA via `applies_when` (note: on a non-systemd host implementation is `none`, not unsupported — that host FAILs mechanism 3, which is correct: nothing logs).

- [ ] **Step 3: Fixtures** (every fixture carries every leaf the selected mechanism's `when` and `checks` read — an omitted registered key is `missing` → ERROR; mirror the 2H fixtures' envelope shape)

`muster.log.time_sync/`: `pass-chrony.json` (ntp installed/active ok:true, server_count ok:2, provider chrony, synchronized ok:true); `pass-timesyncd.json` (server_count from timedatectl ok:1); `fail-no-sources.json` (active ok:true, server_count ok:0); `fail-inactive.json` (active ok:false, server_count ok:2); `manual-timedatectl-unavailable.json` (active ok:true, `time_sync.server_count` **absent**, provider timesyncd) → MANUAL; `na-no-systemd.json` (`services.ntp.installed` unsupported) → NOT_APPLICABLE.

`muster.log.syslog_policy/`: `pass-rsyslog-ubuntu.json` (implementation rsyslog, syslog.active ok:true, coverage with auth/authpriv/kern/daemon/cron logged+persistent, journald.persistent present); `pass-rsyslog-rhel.json` (same facilities, targets `/var/log/secure`/`messages`); `pass-journald-only.json` (implementation journald-only, journald.persistent ok:true); `fail-facility-missing.json` (coverage where `auth` is `logged:false`); `fail-remote-only.json` (auth `logged:true, persistent:false`); `fail-journald-volatile.json` (journald-only, persistent ok:false); `manual-unmodelled.json` (implementation rsyslog, syslog.active ok:true, coverage **absent** with `rsyslog.unmodelled` ok:3) → MANUAL; `manual-syslog-ng.json` (implementation syslog-ng, coverage absent) → MANUAL; `na-unsupported.json` (implementation unsupported) → NOT_APPLICABLE.

- [ ] **Step 4: Lint + evaluate.** `go run ./cmd/muster controls lint --references docs/reference` → "ok: 47 controls" (the `each`/params/`facility`-kind path must load); `go test ./internal/controls/...` → every fixture yields its prefix status (esp. both `manual-*` → MANUAL, `na-*` → NOT_APPLICABLE, `fail-remote-only` → FAIL). If the `each … ${facilities}` clause does not decode, STOP and report the exact lint error rather than dropping the param.

- [ ] **Step 5: Commit.** "Add the time synchronisation and system logging controls".

---

### Task 5: count, coverage, e2e and README reconciliation

- [ ] **Step 1:** both `ok: 45 controls` → `ok: 47 controls` (`cmd/muster/controls_test.go:36,75`).
- [ ] **Step 2:** `cmd/muster/e2e_test.go`: "forty-five" → "forty-seven" (~line 189), "forty-four" → "forty-six" (~line 249); add `muster.log.time_sync` and `muster.log.syslog_policy` to BOTH maps as **PASS** (H-15: the waiver e2e's `Applied != 10 || Unknown != 1` at ~line 102 must stay untouched — do NOT make either FAIL in `full-fail.json`; the per-control `fail-*.json` fixtures prove the FAIL path).
- [ ] **Step 3:** `full-pass.json` AND `full-fail.json`: add the same passing facts for both controls — `services.ntp.installed/active` ok:true, `time_sync.server_count` ok:2 (+`provider`, `servers`, `synchronized` for realism), `logging.syslog.implementation` ok "rsyslog", `services.syslog.active` ok:true, `logging.rsyslog.coverage` with the five default facilities logged+persistent, `logging.journald.persistent` ok:true. Every fact a mechanism's `when`/`checks` reads must be present.
- [ ] **Step 4:** `go run ./tools/coverage` → line 4 `47 of 67 items enrolled (auto 43, partial 4, manual 0).`; `go run ./tools/coverage -check` passes. README pair: grep for a count sentence; none exists today — leave unchanged and say so.
- [ ] **Step 5:** `go test ./...` (Windows, no -race); `GOOS=linux GOARCH=amd64 go vet ./... && go build ./...`; `GOOS=linux staticcheck ./...`; lint → "ok: 47 controls"; coverage -check.
- [ ] **Step 6: Commit.** "Enrol the time-sync and logging controls in the coverage and e2e snapshots".

---

## Self-Review

**1. Spec coverage.** §10.2 "time synchronisation" → `timesync` collector + U-65; "logging as a function (journald-only hosts)" → the journald-only mechanism on `journald.persistent` and the three-tier drop-in merge (I-5, the sysctl shadowing rule from §4); the logical-service map `ntp`/`syslog` → the two services rows (I-4); §6.6 params → `${facilities}`; §6.5 step 8 + `absent_means: manual` → MANUAL on incomplete/unmodelled parse; step 13's "degraded" WARN row is deliberately not wired (as in 2H, H-23). D09: remote forwarding and syslog-ng are data-level limitations stated in the description, not adapter code.

**2. Placeholder scan.** Two deliberately-flagged grammar confirmations (the numeric at-least op name from U-12; the `each`/params shape from U-67) have exact precedents named — the implementer copies, never invents. The `relation: new` kisa shape copies U-67. Everything else is concrete.

**3. Type consistency.** `time_sync.server_count` int (judged, `absent` on the timesyncd/no-timedatectl branch); `logging.rsyslog.coverage` `list<record>` with `subject_kind: facility` (judged via `each`, `absent` when not confident); `logging.journald.persistent` bool (judged); `journald.storage` `setting<string>` both sides; `services.ntp/syslog.*` the standard four leaves, no `reachable`. U-65 reads `services.ntp.{installed,active}` + `time_sync.server_count`; U-66 reads `logging.syslog.implementation`, `services.syslog.active`, `logging.rsyslog.coverage`, `logging.journald.persistent` — all registered.

**Risks (for the pre-flight scan and reviews):**
- **R-a (grammar):** `each … where {field … in ${facilities}} require […]` with a `list<string>` param, and the numeric ≥ op — the plan names precedents; the pre-flight must confirm the exact key names and that a list param substitutes inside `where.expected`.
- **R-b (first use of `subject_kind: facility`):** registry validation and the golden test have never seen it; a rejection is a real finding.
- **R-c (coverage derivation correctness):** `*` catch-all and `.none` exclusions must compose correctly (Ubuntu's `*.*;auth,authpriv.none -/var/log/syslog` must NOT count as covering auth; `auth,authpriv.* /var/log/auth.log` must). The two default-config tests plus the lab run guard this.
- **R-d (over-claiming on RainerScript):** anything not modelled → `absent` → MANUAL. The `unmodelled` counter must be conservative (count unknown rule-like lines) but not so broad that every stock Ubuntu config reads MANUAL (the lab run is the check).
- **R-e (timesyncd + no timedatectl → absent, not FAIL):** a container or a host where `timedatectl` errors must never read "zero sources → FAIL".
- **R-f (CI):** systemd-less legs → `services.ntp/syslog` unsupported → U-65 NA; `logging.syslog.implementation` is `rsyslog` when the image ships `/etc/rsyslog.conf` (ubuntu:22.04 does) but `services.syslog.active` is unsupported → the syslog mechanism's `services.syslog.active` check screens NA-or-hard? `unsupported` in `checks` → NOT_APPLICABLE (screen). Confirm in the pre-flight: a container with rsyslog.conf present but no systemd yields NA, not ERROR, for U-66. `collect-root` (Ubuntu 24.04 runner: timesyncd + rsyslog) must yield PASS or MANUAL, never ERROR.
