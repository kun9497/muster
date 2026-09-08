# Stage 2I — Logging and Time Synchronisation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol the two KISA 2026 logging-category items U-65 (NTP 및 시각 동기화 설정) and U-66 (정책에 따른 시스템 로깅 설정) by adding a `timesync` collector, a `logging` collector (rsyslog rules → per-facility coverage, journald as a function with a four-tier drop-in merge), the `ntp`/`syslog` rows the `services` table still lacks, and two controls that judge time synchronisation by an active provider with a configured source and logging by **facility coverage, never by path** — degrading to MANUAL (never a fabricated verdict) wherever the configuration cannot be modelled with confidence.

**Architecture:** Three small pieces, each honest about what it cannot see. (1) `services` gains `ntp` and `syslog` logical rows (table-driven since 2G), so `services.ntp.*`/`services.syslog.*` give the running-daemon side with the existing euid/no-systemd degrade loop. (2) A `timesync` collector reads the provider configs (chrony / systemd-timesyncd / ntpd) for the persisted server list and runs **two separate unprivileged oracles** (Ruling I-16): `timedatectl show -p NTP -p NTPSynchronized`, the only input to `synchronized`, and `timedatectl show-timesync --all`, declared always but run **only on the timesyncd branch** (it fails on every chrony/ntpd host) because timesyncd ships its config fully commented and only the daemon knows its compiled-in servers; a `timedatectl` that cannot run is an environment limitation → `unsupported` (R220 — it needs no root, so it is never `denied`). (3) A `logging` collector detects the implementation (rsyslog / syslog-ng / journald-only / none), parses rsyslog selectors, `omfile` actions, forwarding and includes into per-**facility** coverage records **in rule order** (a path-based clause is a guaranteed FAIL on one distro family), records the file targets, and merges journald's `/usr/lib` < `/usr/local/lib` < `/run` < `/etc` drop-ins through a shared helper (built in Task 1, Ruling I-19) into a two-sided `journald.storage` setting. Judged leaves are emitted **`absent`** when the parse is incomplete or carries unmodelled constructs, so `absent_means: manual` yields MANUAL (the R241/2H pattern, no engine change).

**Tech Stack:** Go 1.25.x, Linux-only collectors behind build tags; `systemctl show` via the services table; `timedatectl` via the exec discipline; config files under `/etc/chrony*`, `/run/chrony-dhcp/`, `/etc/systemd/timesyncd.conf{,.d}`, `/etc/ntp.conf`, `/etc/rsyslog.conf` + `/etc/rsyslog.d/*.conf`, `/etc/syslog-ng/`, `/{usr/lib,usr/local/lib,run,etc}/systemd/journald.conf{,.d}`, and — declared, never wandered outside — `/var/log/*`, `/var/log/*/*`, `/run/systemd/system`; YAML controls using `applies_when`, `mechanisms`, `each … where … require`, a `list<string>` `${facilities}` param, and `absent_means: manual`; fixtures under `controls/testdata/<id>/{pass,fail,manual,na}-*.json`.

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
  - **I-2 (amended by Ruling I-11):** U-66 = **two** mechanisms in order: syslog daemon (rsyslog/syslog-ng → facility coverage), journald-only (→ `logging.journald.persistent == true`). There is **no third "none → FAIL" mechanism**: `implementation == none` ⇔ no systemd ⇒ `journald.persistent` is `unsupported` ⇒ such a mechanism could only ever yield NOT_APPLICABLE, never FAIL. A `none` host falls through "no mechanism applies" → `absent_means: manual` → **MANUAL**, which is the honest verdict (sysklogd, BusyBox `syslogd` and metalog are not detected in v1). Remote forwarding is evidence only (beyond the item; the STIG's offload bar is higher than KISA's).
  - **I-3:** one runtime command, `timedatectl` (unprivileged); no `chronyc`/`ntpq` (extra exec surface, socket-dependent). chrony/ntpd server lists come from files (authoritative there); the timesyncd list comes from `timedatectl show-timesync` (its file ships commented) merged with any `NTP=` lines.
  - **I-4:** 2I adds the `ntp` and `syslog` rows to the `services` table (2I's analysis dependency "2G services.{syslog,cron}" does not resolve against anything merged). The analysis keys `time_sync.active_providers`/`service_active`/`unit_file_state` are **dropped** as redundant with `services.ntp.*` — the control ANDs facts from both collectors (as U-43 ANDs `services.nis.*` with `accounts.nss.*`). No `reachable`/ports on either row (123/udp and 514 are not judged; avoids a false-negative class).
  - **I-5 (amended by Rulings I-19 and I-23):** journald's drop-in precedence becomes a SHARED helper (`internal/collect/collectors/dropin.go`) modelled on the spec's sysctl rule — "a file in an earlier directory shadows one of the same name in a later directory and the surviving files apply in lexicographic order" — with the **four-tier** directory order `/etc/systemd/journald.conf.d` > `/run/systemd/journald.conf.d` > `/usr/local/lib/systemd/journald.conf.d` > `/usr/lib/systemd/journald.conf.d` for shadowing, the main file `/etc/systemd/journald.conf` applied first (falling back to `/usr/lib/systemd/journald.conf` when the `/etc` copy is absent — systemd ≥ 254 ships it there), later files winning per key. **The helper lands in Task 1**, before the `timesync` collector, because timesyncd's `/etc,/run,/usr/local/lib,/usr/lib` chain uses it too; Task 3 only consumes it for journald. Migrating the inline pwquality/faillock copies is parked for 2M.
  - **I-6 (rewritten by Ruling I-12 — the unmodelled net must not turn stock Ubuntu MANUAL):** v1 models
    - classic selectors (`facility.priority[;…] target`, incl. `*`, `,` lists, `.none`, `=`/`!` priority modifiers ignored-but-noted);
    - the **`&` continuation line** — reuse the previous line's filter with a new action;
    - `omfile` RainerScript actions (`action(type="omfile" file="…")`), forwarding targets (`@host`, `@@host`, `action(type="omfwd" …)`) as `target_kind: remote`, `~`/`stop`/`discard`, user (`:omusrmsg:`) and pipe (`|`) targets;
    - `$IncludeConfig <glob>` / `include(file="…" [mode="optional"])` — followed, extra attributes tolerated; an include that cannot be read → `parse_complete: false`.
    - **Property-based filters** (`:property, compare-op, "value" action`, e.g. `20-ufw.conf`'s `:msg,contains,"[UFW "` and `21-cloudinit.conf`'s `:syslogtag, isequal, "[CLOUDINIT]"`) are **additive routing** — they add a destination for a tagged subset and can never un-log a facility, so they are **coverage-neutral**: count them in the new evidence int `logging.rsyslog.property_filters` (registered), **NOT** in `unmodelled`. A `& stop` / `& ~` following a property filter discards that tagged subset only, never a facility — same treatment.
    - **Not rules and NOT unmodelled:** legacy `$Directive` lines other than `$IncludeConfig` (`$FileOwner`, `$FileCreateMode`, `$Umask`, `$PrivDropToUser`, `$WorkDirectory`, `$RepeatedMsgReduction`, `$ActionFileDefaultTemplate`, `$AddUnixListenSocket`, …), and `module(`, `global(`, `input(`, `main_queue(`, `template(` / `$template` (a template changes format, not routing).
    - **Only these count in `rsyslog.unmodelled`** (evidence) and make `coverage` **absent** → MANUAL: `if … then`, `ruleset(` / `call`, `?TemplateName` dynamic file targets, and `:omfile:` / `:omfwd:` with unparsable arguments.
    - syslog-ng configs are NOT parsed in v1 → `implementation: syslog-ng` with `coverage` absent → MANUAL (honest).
    - **Acceptance:** a stock Ubuntu host (with `20-ufw.conf`, `21-cloudinit.conf`, `postfix.conf`) MUST read `coverage` ok with `unmodelled 0` — proven on the lab host in Task 2 Step 5.
  - **I-7:** `logging.logrotate.*` from the analysis is **deferred** (not needed by U-65/U-66's judgment).
  - **I-8:** `logging.journald.persistent` (judged bool) = `Storage=persistent`, or `Storage=auto` (or unset — systemd's default is `auto`) with `/var/log/journal` present; `volatile`/`none`, or `auto` without the directory → false. `journald.storage` stays a two-sided evidence setting (persisted = merged `Storage=`, runtime = whether `/var/log/journal` exists), both sides always set (H-18).

---

## File Structure

**Collectors — create/modify:**
- `internal/collect/collectors/services.go` — append the `ntp` and `syslog` rows to `var services` (Task 1).
- `internal/collect/collectors/dropin.go` + `dropin_test.go` — **new** shared drop-in merge helper (**Task 1**, built first: the `timesync` collector needs it for timesyncd's `/etc,/run,/usr/local/lib,/usr/lib` chain — Ruling I-19).
- `internal/collect/collectors/timesync.go` + `timesync_test.go` — **new** `timesync` collector (Task 1, on top of the helper).
- `internal/collect/collectors/logging.go` + `logging_test.go` — **new** `logging` collector: implementation detection, rsyslog parse, coverage, log targets (Task 2); journald leaves via the helper (Task 3).
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

New fact keys — **22 in total** (8 `services.*` + 4 `time_sync.*` + 10 `logging.*`; the tenth `logging.*` key is `rsyslog.property_filters` from Ruling I-12), all `since: 1`, `sensitivity: public` unless noted:
- `services.ntp.{installed,active,unit_file_state,enabled}` and `services.syslog.{installed,active,unit_file_state,enabled}` — from the services table rows (no `reachable`).
- `time_sync.provider` — `string`: `chrony` | `timesyncd` | `ntpd` | `none` — which provider's configuration is present (persisted view; evidence).
- `time_sync.servers` — `list<string>` — de-duplicated, sorted server/pool/peer/refclock sources from the provider config **and** (timesyncd) `timedatectl show-timesync`; **`absent`** on the timesyncd branch when `timedatectl` is unavailable, and when a chrony `sourcedir`/`confdir` points outside the declaration (Rulings I-16/I-17). **`provider == none` → `ok: []`** (Ruling I-18) — never unset.
- `time_sync.server_count` — `int` — `len(servers)`; same absence rule; `ok: 0` when `provider == none`. **Judged leaf** (`gte`, so it must be registered `int`).
- `time_sync.synchronized` — `bool` — from `timedatectl show -p NTP -p NTPSynchronized` **only** (Ruling I-16); `unsupported` when that command cannot run. Evidence only.
- `logging.syslog.implementation` — `string`: `rsyslog` | `syslog-ng` | `journald-only` | `none`.
- `logging.rsyslog.rules` — `list<record>` `{facility, priority, target, target_kind}` (`target_kind`: file|remote|user|pipe|module|discard).
- `logging.rsyslog.parse_complete` — `bool` — false when an include could not be read, or named a path outside the declaration (Ruling I-10).
- `logging.rsyslog.unmodelled` — `int` — count of constructs v1 does not model (`if … then`, `ruleset(`/`call`, `?TemplateName`, unparsable `:omfile:`/`:omfwd:` — Ruling I-12 and nothing else).
- `logging.rsyslog.property_filters` — `int` — count of property-based filter lines (`:msg,contains,…`). **Evidence only; coverage-neutral** (Ruling I-12).
- `logging.rsyslog.coverage` — `list<record>` `{facility, logged, priority_floor, target, persistent}`, `subject_kind: facility`; **`absent`** when `parse_complete` is false or `unmodelled > 0`. **Judged leaf.** `persistent` = the winning target is a **local file target kind**, not "the file exists" (Ruling I-15).
- `logging.log_targets` — `list<record>` `{path, exists, persistent, mtime_age_s, stat_status}` — stat of every declared file target named by the rules; a target outside the declaration is recorded with `stat_status: undeclared` and never stat-ed (Ruling I-10). `exists`/`mtime_age_s` are evidence only.
- `logging.journald.storage` — `setting<string>`, `default_on: both` — persisted = merged `Storage=`, runtime = `persistent`/`volatile` by `/var/log/journal` presence.
- `logging.journald.forward_to_syslog` — `bool` — merged `ForwardToSyslog=` (evidence).
- `logging.journald.persistent` — `bool` — **judged leaf** for the journald-only mechanism (I-8).

---

### Task 1: the shared drop-in helper + `ntp`/`syslog` service rows + the `timesync` collector

**Ruling I-19:** `dropin.go` (and `mergeDropins`, its shadowing/order test) moved here from Task 3 — the timesyncd branch reads a merged `timesyncd.conf` chain, so the helper must exist before the collector's tests can be written. Task 3 keeps only the journald leaves built on it.

**Files:**
- Modify: `internal/collect/collectors/services.go` (table), `internal/facts/registry.yaml` (+golden), the collector registration site.
- Create: `internal/collect/collectors/dropin.go`, `dropin_test.go`; `internal/collect/collectors/timesync.go`, `timesync_test.go`, testdata (`timedatectl.show-timesync`, `timedatectl.show`, `chrony.conf.pool`, `chrony.conf.sourcedir`, `ntp.conf.servers`, `timesyncd.conf.commented`, `timesyncd.d.10-ntp`, and the `journald.*` drop-in files the helper test uses).

**Interfaces:**
- Consumes: the `logicalService`/`unitRef` table shape (2G), `collect.Command`, `collect.Unsupported`, `readErrorEnv`/`FromReadError`, the `buildBegun` test helper (2H — it calls `Begin` so `Worst` assertions are real, and it already fails a test on any read-guard violation, `firewall_test.go:45-47`), `allUnitsNotFound()` (table-driven since 2G; extend automatically by iterating the table).
- Produces: `mergeDropins(a collect.Access, main string, dirs []string, glob string) (values map[string]string, inputs []facts.Source, readErr error)` — last-write-wins key/values over the `main` file first, then the surviving drop-ins where a file in an EARLIER `dirs` entry shadows a same-named file in a later one, applied in lexicographic basename order; `inputs` lists every file actually read; `readErr` is the FIRST read error of an existing file (R148: it poisons every derived value). Deterministic.
- Produces: `services.ntp.*`, `services.syslog.*`, `time_sync.{provider,servers,server_count,synchronized}`.

- [ ] **Step 1: Write the failing tests**

```go
// The helper first (Ruling I-19): /etc shadows /run shadows /usr/local/lib shadows
// /usr/lib for the SAME basename; survivors apply in basename order; later wins.
func TestMergeDropinsShadowingAndOrder(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/systemd/journald.conf":                      "journald.conf.main",       // Storage=auto
		"/usr/lib/systemd/journald.conf.d/10-vendor.conf": "journald.d.10-vendor",     // Storage=volatile (shadowed)
		"/etc/systemd/journald.conf.d/10-vendor.conf":     "journald.d.10-vendor-etc", // Storage=persistent
		"/run/systemd/journald.conf.d/20-runtime.conf":    "journald.d.20-runtime",    // ForwardToSyslog=yes
	}, nil)
	vals, inputs, err := mergeDropins(a, "/etc/systemd/journald.conf",
		[]string{"/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d",
			"/usr/local/lib/systemd/journald.conf.d", "/usr/lib/systemd/journald.conf.d"}, "*.conf")
	if err != nil { t.Fatal(err) }
	if vals["Storage"] != "persistent" || vals["ForwardToSyslog"] != "yes" { t.Errorf("vals: %+v", vals) }
	if len(inputs) != 3 { t.Errorf("inputs (shadowed file must NOT be read/listed): %+v", inputs) }
}

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

// Ruling I-16: show-timesync is a timesyncd-only oracle and is not even run on a
// chrony host; `synchronized` follows `show` alone and stays ok there.
func TestTimesyncChronyKeepsSynchronizedWithoutShowTimesync(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.pool"},
		map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}}) // show-timesync unmapped → would fail
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.synchronized"); e.Status != facts.StatusOK { t.Errorf("synchronized: %+v", e) }
	if a.ran[timedatectlShowTimesyncKey] { t.Error("show-timesync must not run on the chrony branch") }
}

// Ruling I-17: refclock lines and a declared sourcedir count as sources.
func TestTimesyncChronyRefclockAndSourcedirCount(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/chrony/chrony.conf":            "chrony.conf.sourcedir", // refclock PHC … + sourcedir /run/chrony-dhcp
		"/run/chrony-dhcp/eth0.sources":      "chrony.sources.dhcp",
	}, map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value.(int) < 2 { t.Errorf("server_count: %+v", e) }
}

// Rulings I-10 + I-17: a sourcedir outside the declaration is RECORDED, never read;
// servers/server_count go absent (→ MANUAL) and the path never reaches a.reads.
func TestTimesyncUndeclaredSourcedirIsRecordedNotRead(t *testing.T) {
	a := timesyncAccess(map[string]string{"/etc/chrony/chrony.conf": "chrony.conf.sourcedir-odd"}, nil) // sourcedir /opt/ntp
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusAbsent { t.Errorf("servers: %+v", e) }
	for _, p := range a.reads { if strings.HasPrefix(p, "/opt/ntp") { t.Fatalf("read an undeclared path: %s", p) } }
}

// Ruling I-18: no provider config at all — the judged leaf is ok:0, never unset
// (an unset registered key is missing → ERROR(missing_fact), not FAIL).
func TestTimesyncNoProviderIsZeroNotMissing(t *testing.T) {
	a := timesyncAccess(nil, map[string]cmdResult{timedatectlShowKey: {file: "timedatectl.show"}})
	b := buildBegun(t, "timesync", a)
	if e := env(t, b, "time_sync.provider"); e.Value != "none" { t.Errorf("provider: %+v", e) }
	if e := env(t, b, "time_sync.server_count"); e.Status != facts.StatusOK || e.Value.(int) != 0 { t.Errorf("server_count: %+v", e) }
	if e := env(t, b, "time_sync.servers"); e.Status != facts.StatusOK { t.Errorf("servers: %+v", e) }
}
```

**Ruling I-20 — test-double details (the R226 lesson).** Write `timesyncAccess(files, cmds)` mirroring `servicesAccess`/`firewallAccess` (`collectors_test.go:1707-1719` / `firewall_test.go:23-25`), but **initialise `files`, `cmds`, `fails`, `dirs`, `stats` all five** — `firewallAccess` initialises only two and a later `a.fails[…] = …` on a nil map panics. Seed `dirs["/run/systemd/system"]` wherever a systemd host is meant (as `servicesAccess` does); `TestServicesNtpAndSyslogRowsDegradeWithTheTable` correctly passes a bare `&fsAccess{}` (no marker). Directory-ness is judged by `ReadMeta.Kind == "dir"`, and `fsAccess.Stat` on a `dirs` entry returns mode 0755 with **no `Kind`** — so a directory the collector must recognise needs a `stats[path] = {…, kind: "dir"}` seed (copy `collectors_test.go:1614`'s `/var/log/journal`). The command key is the exact `strings.TrimSpace(Path + " " + strings.Join(Args, " "))` string (`collectors_test.go:173-175`) — byte-identical in declaration, run and test: `/usr/bin/timedatectl show -p NTP -p NTPSynchronized` and `/usr/bin/timedatectl show-timesync --all`; an unmapped command returns `ExitCode -1, Err: os.ErrNotExist` (line 179), which is exactly the "timedatectl unavailable" shape. Add an `a.ran`/`a.reads` recorder if the fake lacks one. Add the testdata files.

- [ ] **Step 2: Run to confirm failure.** `go test ./internal/collect/collectors/ -run 'TestMergeDropins|TestServicesNtp|TestTimesync'` **on the lab host** (or in CI). **Ruling I-20:** `GOOS=linux GOARCH=amd64 go test` on this Windows worktree only cross-*compiles* a Linux test binary it cannot execute — locally run `GOOS=linux go vet ./...` and `GOOS=linux go build ./...` for the compile check, and run the Linux-tagged suites through the read-only `lab-sync.sh`/`lab-run.sh` scripts or rely on CI (`ci.yml:82` runs them under sudo). The same applies to every `go test` line in Tasks 1–3.

- [ ] **Step 3: Add the services rows**

Append to `var services` (keep ordering stable; both rows `provesInstall: true`, no `inetdNames`, no `servers`, no `ports`):
```go
{name: "ntp", units: []unitRef{{"chrony.service", true}, {"chronyd.service", true}, {"systemd-timesyncd.service", true}, {"ntpd.service", true}, {"ntp.service", true}, {"ntpsec.service", true}}},
{name: "syslog", units: []unitRef{{"rsyslog.service", true}, {"syslog-ng.service", true}}},
```
`declaredShowCommands()` and the no-systemd degrade loop pick them up automatically; `allUnitsNotFound()` is table-driven (2G) so existing tests stay green.

- [ ] **Step 4: Implement `mergeDropins` and the `timesync` collector**

- **`mergeDropins` (Ruling I-19, helper first):** read `main` (missing is fine — the daemon's defaults apply; an existing-but-unreadable main is `readErr`); glob each dir in order, build a basename→path map honouring shadowing (**first dir wins**), then sort the survivors by basename and read them in that order; parse `Key=Value` under any `[Section]` (keep the parser section-agnostic but record the section), last write wins; `#`/`;` comments and blank lines skipped; a value of `""` resets (systemd semantics — document). The caller declares the dirs' globs and the main file in its own `Declare.Reads`.
- `Declare.Reads`: `/etc/chrony.conf`, `/etc/chrony/chrony.conf`, `/etc/chrony/conf.d/*.conf`, `/etc/chrony/sources.d/*.sources`, **`/run/chrony-dhcp/*.sources`** (Ruling I-17 — DHCP-supplied servers on Ubuntu 22.04+/Rocky 9), `/etc/systemd/timesyncd.conf`, `/etc/systemd/timesyncd.conf.d/*.conf`, `/run/systemd/timesyncd.conf.d/*.conf`, `/usr/local/lib/systemd/timesyncd.conf.d/*.conf`, `/usr/lib/systemd/timesyncd.conf.d/*.conf`, `/etc/ntp.conf`, `/etc/ntpsec/ntp.conf`. `Declare.Commands`: exactly two, byte-identical in declaration/run/test key: `/usr/bin/timedatectl show-timesync --all` and `/usr/bin/timedatectl show -p NTP -p NTPSynchronized`. `Needs: "none"`.
- `provider`: `chrony` if any chrony config exists; else `timesyncd` if `timesyncd.conf` exists (or its `.d`); else `ntpd` if an ntp.conf exists; else `none`. (Evidence — the running daemon is `services.ntp.*`.)
- `servers`: chrony — `server|pool|peer <name>` lines **and `refclock <driver> <arg …>` lines, recorded as `refclock:<driver>:<arg>` (Ruling I-17)**, plus the `*.sources`/`*.conf` files named by any `sourcedir`/`confdir` directive; ntpd — `server|pool <name>`; timesyncd — `NTP=`/`FallbackNTP=` from the `mergeDropins` chain (`/etc` > `/run` > `/usr/local/lib` > `/usr/lib`) **plus** `ServerName=`, `SystemNTPServers=`, `FallbackNTPServers=`, **`LinkNTPServers=` and `RuntimeNTPServers=` (Ruling I-24 — networkd/DHCP)** from `timedatectl show-timesync`. De-duplicate, sort. `server_count = len`.
- **Ruling I-18 — `provider == none`:** `servers` = `ok: []`, `server_count` = `ok: 0`, `synchronized` from `show` as usual. Never leave a judged leaf unset: an unset registered key is `missing` → `ERROR(missing_fact)`, which would break the `collect-root` zero-ERROR gate; the control then FAILs on `services.ntp.active`, which is the intended "no active provider" verdict.
- **Ruling I-10 — never stat or glob an undeclared path.** A `sourcedir`/`confdir` outside the declared set is recorded with the sshd `declared()` probe pattern (`internal/collect/collectors/sshd.go:621-626`) and **never touched**; `servers`/`server_count` then go `absent` with the path in the reason → MANUAL. `guardedAccess` turns a violation into collector `error` → `run.complete=false`, which breaks `collect-root --require-complete` and `collect-contract`; `buildBegun` already fails the test on any violation.
- **Degradation (Ruling I-16 — the two commands are separate oracles):** `timedatectl show -p NTP -p NTPSynchronized` is the ONLY input to `synchronized`; its failure (Err / TimedOut / non-zero) → `synchronized` = `collect.Unsupported("timedatectl unavailable: <first stderr line>")`. `timedatectl show-timesync --all` is **declared always but run ONLY on the timesyncd branch** — it reads `org.freedesktop.timesync1`, which only systemd-timesyncd provides, so it exits non-zero on every chrony/ntpd host and running it there would be expected-failure noise in the run header. Only *its* failure, and only on the timesyncd branch, makes `servers`/`server_count` = `collect.Absent("effective NTP server list unknown: timedatectl unavailable; see timesyncd.conf")` (files alone cannot know the compiled-in fallback). Never `denied`, never `error` (both commands are unprivileged — document this in a comment contrasting it with the firewall euid split). An existing-but-unreadable config → `FromReadError` on `servers`/`server_count`/`provider` (C3).
- Sources: a `derived` source listing the files/commands read, one fresh pointer per envelope.

- [ ] **Step 5: Register keys, regenerate golden, gates.** Add `services.ntp.*`/`services.syslog.*` (4 each), `time_sync.provider` (string), `time_sync.servers` (`list<string>`, NO subject_kind), `time_sync.server_count` (**`int`** — `lint.go:306` requires an `int`/`setting<int>` fact behind the `gte` op U-65 uses, Ruling I-9), `time_sync.synchronized` (bool). `go test ./internal/facts -run TestFactsSchemaGolden -update` (runs on Windows; additions-only). Collector tests on the lab host/CI (Ruling I-20); locally `gofmt -l .`, `GOOS=linux go vet ./...`, `GOOS=linux go build ./...`, staticcheck.

- [ ] **Step 6: Lab host.** Sync + run (READ-ONLY scratchpad `lab-sync.sh`/`lab-run.sh` via the PowerShell tool with Git Bash explicitly; never edit them). The lab host is Ubuntu 22.04 (systemd-timesyncd or chrony): report `time_sync.provider`, `server_count`, `synchronized`, and `services.ntp.active`; root collect must be complete. **Ruling I-16 check:** run `/usr/bin/timedatectl show -p NTP -p NTPSynchronized` by hand and confirm it prints **two** lines (`NTP=…`, `NTPSynchronized=…`) — timedatectl does not split a comma list the way `systemctl` does, and the repeated-flag form is the safe one. Never commit a host snapshot.

- [ ] **Step 7: Commit.** `git add internal/collect/collectors/services.go internal/collect/collectors/dropin.go internal/collect/collectors/dropin_test.go internal/collect/collectors/timesync.go internal/collect/collectors/timesync_test.go internal/collect/collectors/testdata/ internal/collect/collectors/register.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json` — "Add the drop-in merge helper, the ntp/syslog service rows and the timesync collector".

---

### Task 2: `logging` collector — implementation, rsyslog rules, facility coverage, log targets

**Files:**
- Create: `internal/collect/collectors/logging.go`, `logging_test.go`, testdata (`rsyslog.conf.ubuntu`, `rsyslog.d/50-default.conf`, **`rsyslog.d/20-ufw.conf`** (`:msg,contains,"[UFW "`), **`rsyslog.d/21-cloudinit.conf`** (`:syslogtag, isequal, "[CLOUDINIT]"` + `& stop`), `rsyslog.conf.rhel`, `rsyslog.conf.rainerscript-if` (unmodelled), `rsyslog.conf.include-missing`, **`rsyslog.conf.stop-before`** (a `stop` ahead of the covering rule), **`rsyslog.conf.undeclared-target`**).
- Modify: `internal/facts/registry.yaml` (+golden), the registration site.

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Glob`, `Stat`), `FromReadError`, the `declared()` probe pattern (`sshd.go:621-626`), the `facility` subject kind (already valid in `registry.go`).
- Produces: `logging.syslog.implementation`, `logging.rsyslog.{rules,parse_complete,unmodelled,property_filters,coverage}`, `logging.log_targets`. (`logging.journald.*` lands in Task 3.)

- [ ] **Step 1: Write the failing tests**

```go
// Ruling I-14: ".none" is scoped to ITS selector line, not to the target path.
// Ubuntu default: "auth,authpriv.* /var/log/auth.log" logs both; the separate
// "*.*;auth,authpriv.none -/var/log/syslog" line excludes them ON THAT LINE ONLY;
// kern/daemon/cron are covered by that catch-all. Judged by facility, never by path.
// Ruling I-12: the stock 20-ufw.conf / 21-cloudinit.conf property filters must NOT
// make coverage absent — they are additive routing, counted as evidence.
func TestLoggingUbuntuDefaultCoversFacilitiesByFacilityNotPath(t *testing.T) {
	a := loggingAccess(map[string]string{
		"/etc/rsyslog.conf":              "rsyslog.conf.ubuntu",
		"/etc/rsyslog.d/50-default.conf": "rsyslog.d/50-default.conf",
		"/etc/rsyslog.d/20-ufw.conf":     "rsyslog.d/20-ufw.conf",
		"/etc/rsyslog.d/21-cloudinit.conf": "rsyslog.d/21-cloudinit.conf",
	}, /* targets exist */ []string{"/var/log/syslog", "/var/log/auth.log"})
	b := buildBegun(t, "logging", a)
	if e := env(t, b, "logging.syslog.implementation"); e.Value != "rsyslog" { t.Fatalf("impl: %+v", e) }
	cov := okList(t, b, "logging.rsyslog.coverage")
	for _, f := range []string{"auth", "authpriv", "kern", "daemon", "cron"} {
		rec := findFacility(t, cov, f)
		if rec["logged"] != true || rec["persistent"] != true { t.Errorf("%s: %+v", f, rec) }
	}
	if e := env(t, b, "logging.rsyslog.unmodelled"); e.Value.(int) != 0 { t.Errorf("stock Ubuntu must be fully modelled: %+v", e) }
	if e := env(t, b, "logging.rsyslog.property_filters"); e.Value.(int) != 2 { t.Errorf("property_filters (evidence, coverage-neutral): %+v", e) }
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

// Ruling I-15: persistent = the target is a LOCAL FILE target kind, never "the file
// exists". A remote-only facility is logged:true, persistent:false; a file target that
// does not exist yet (fresh host, omfile creates it on first write) is persistent:true
// with log_targets.exists false as evidence.
func TestLoggingPersistenceIsTargetKindNotExistence(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.rhel"}, nil /* nothing exists yet */)
	b := buildBegun(t, "logging", a)
	rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "authpriv")
	if rec["logged"] != true || rec["persistent"] != true { t.Errorf("fresh host must not FAIL: %+v", rec) }
	// "*.* @@logs.example.invalid:514" only → logged true, persistent false.
}

// Ruling I-13: rules are ordered. "auth.* stop" (or "auth.* ~") BEFORE the catch-all
// means auth never reaches the file — coverage must not read it as logged.
func TestLoggingSelectorDiscardBeforeCoveringRuleRemovesFacility(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.stop-before"}, []string{"/var/log/syslog"})
	b := buildBegun(t, "logging", a)
	rec := findFacility(t, okList(t, b, "logging.rsyslog.coverage"), "auth")
	if rec["logged"] != false { t.Errorf("a discard ahead of the covering rule must remove auth: %+v", rec) }
}

// Ruling I-10, modelled on TestSshdBannerOutsideDeclarationIsRecordedNotRead
// (collectors_test.go:476): a rule target outside Declare.Reads is RECORDED, never
// stat-ed — a guard violation would make the collector error and the run incomplete.
func TestLoggingUndeclaredTargetIsRecordedNotStatted(t *testing.T) {
	a := loggingAccess(map[string]string{"/etc/rsyslog.conf": "rsyslog.conf.undeclared-target"}, nil) // target /opt/logs/app.log
	b := buildBegun(t, "logging", a)
	tgt := okList(t, b, "logging.log_targets")
	if findPath(t, tgt, "/opt/logs/app.log")["stat_status"] != "undeclared" { t.Errorf("targets: %+v", tgt) }
	for _, p := range a.reads { if strings.HasPrefix(p, "/opt/logs") { t.Fatalf("touched an undeclared path: %s", p) } }
}
```

**Ruling I-20 — `loggingAccess(files, existingTargets)` details.** Initialise **all five** maps (`files, cmds, fails, dirs, stats`): `TestLoggingUnreadableIncludeMakesCoverageAbsent` assigns `a.fails[…] = os.ErrPermission` and a nil map panics. Seed `dirs["/run/systemd/system"]` for the journald-only/implementation-detection tests (as `servicesAccess` does at `collectors_test.go:1707-1719`); directory-ness is judged by `ReadMeta.Kind == "dir"`, which `fsAccess.Stat` returns only from `stats`, so a directory needs `stats[path] = {…, kind: "dir"}` (copy the `/var/log/journal` seed at `collectors_test.go:1614`). `findFacility` and `findPath` are new helpers; `env`, `okList`, `leaf`, `buildBegun` exist. Run on the lab host or CI, not on Windows.

- [ ] **Step 2: Run to confirm failure.** (Lab host / CI — see Task 1 Step 2.)

- [ ] **Step 3: Implement**

- **`Declare.Reads` (Ruling I-10 — BLOCKING):** `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/syslog-ng/syslog-ng.conf`, `/run/systemd/system`, **`/var/log/*` and `/var/log/*/*`** (the second also covers `/var/log/journal` for Task 3), plus the journald main file(s) and drop-in globs of Ruling I-23 (`/etc/systemd/journald.conf`, `/usr/lib/systemd/journald.conf`, and `{/etc,/run,/usr/local/lib,/usr/lib}/systemd/journald.conf.d/*.conf`). `guardedAccess.Stat`/`Glob` (`registry.go:302-311`) require a `path.Match` against a declared entry (no `**`); a violation makes the collector `error` → `run.complete=false` → `collect-root --require-complete` (ci.yml:64) and `collect-contract` (`.run.complete == true`) fail. `buildBegun` already fails a test on any violation, so the Ubuntu fixture would go red immediately.
- **Anything outside the declaration is RECORDED, never touched** (copy `sshd.go:621-626 declared()`): a rule target → a `log_targets` row with `stat_status: undeclared`; a `$IncludeConfig`/`include()` path → `parse_complete: false` with the path in the reason (→ coverage absent → MANUAL). Never widen `Reads` to `**`-ish patterns to make a path fit.
- **Implementation detection:** `rsyslog` if `/etc/rsyslog.conf` exists; else `syslog-ng` if `/etc/syslog-ng/syslog-ng.conf` exists; else `journald-only` if `/run/systemd/system` exists; else `none`. (The running-daemon side is `services.syslog.*`; the control ANDs it.)
- **rsyslog parse (I-6 as rewritten by Ruling I-12):** read `/etc/rsyslog.conf`; follow `$IncludeConfig <glob>` and `include(file="…" [mode="optional"])` — extra attributes tolerated — in sorted glob order. Classic selector lines → one rule record per `facility` × target after expanding `,` lists, `*`, and `;` compound selectors; `.none` records an exclusion **for that selector line** (Ruling I-14). A leading **`&`** continuation line reuses the previous line's filter with a new action. RainerScript `action(type="omfile" file="…")` → file target; `omfwd`/`@host`/`@@host` → `remote`; `~`/`stop` → `discard`; `:omusrmsg:`/user lists → `user`; `|` → `pipe`.
  **Property-based filters** (`:property, compare-op, "value" action`) are additive routing: `property_filters++`, coverage-neutral, and an `& stop`/`& ~` following one discards that tagged subset only — never a facility. **Not rules at all** (neither counted nor unmodelled): legacy `$Directive` lines other than `$IncludeConfig`, and `module(`, `global(`, `input(`, `main_queue(`, `template(`/`$template`. **`unmodelled++` for exactly four things:** `if … then`, `ruleset(`/`call`, `?TemplateName` dynamic file targets, and `:omfile:`/`:omfwd:` with unparsable arguments. `parse_complete = false` iff an include could not be read or lay outside the declaration (record the path in the coverage reason).
- **Coverage derivation — in rule order (Ruling I-13):** walk the rules in file order for each syslog facility name (`auth authpriv cron daemon ftp kern lpr mail news syslog user uucp local0..local7`). A **selector-based discard (`stop`/`~`) matching facility F BEFORE F's persistent rule removes F from coverage**, and the discarding line goes in the reason — never the "any rule targets it" shortcut, which is a confidently wrong PASS. `logged` = a rule (incl. `*`) selects the facility on a line whose own selector does not `.none` it, with a `file` or `remote` target; `priority_floor` = the lowest priority selected; `target` = the first such target; **`persistent` = that target's kind is a local `file`** (Ruling I-15) — *not* "the file exists": omfile creates it on first write, so an existence test false-FAILs a fresh RHEL/Alma host that has no `/var/log/secure` yet. Remote-only coverage is `logged: true, persistent: false` (a central-forwarding host with no local file reads FAIL against the default `${facilities}` — say so in the description). Emit as `list<record>` sorted by facility. **Emit `absent` instead when `parse_complete == false` or `unmodelled > 0`.**
- **`.none` scope (Ruling I-14):** the exclusion belongs to the selector line it appears on, never to the target path — two lines writing the same file are independent. This composes the defaults correctly. Ubuntu: `auth,authpriv.* /var/log/auth.log` logs auth/authpriv; `*.*;auth,authpriv.none -/var/log/syslog` excludes them on that line only; cron/daemon/kern are covered by that catch-all. RHEL: `*.info;mail.none;authpriv.none;cron.none /var/log/messages` covers auth/daemon/kern at floor `info`; `authpriv.* /var/log/secure`; `cron.* /var/log/cron` (the existing `collectors/testdata/rsyslog_conf` is this shape).
- **log_targets:** stat every distinct **declared** file target (`-`-prefixed async paths stripped): `{path, exists, persistent(= target kind is a local file), mtime_age_s, stat_status}`; `exists`/`mtime_age_s` are evidence only. A denied stat → that record's error-envelope shape from 2E's home_dirs (`stat_status`) — mirror it; an undeclared path → `stat_status: undeclared` with no stat at all.
- **Ruling I-27 (cross-plan primitive — `mtime_age_s` needs a modification time and a clock):** `collect.ReadMeta` (`internal/collect/types.go`) carries NO modification time today, and no collector has a clock. Task 2 adds it, because plan 2J (`patch.metadata_age_s`, `days_since_last_install`) will REUSE it after rebasing onto this branch: (a) add `ModTime time.Time` to `ReadMeta`, populate it in the real access's `fillMeta` (from `os.FileInfo.ModTime()`) and in the `fsAccess` test double (a `mtime` field on the `stats[...]` seed; zero when unseeded); (b) "now" is `b.Header().CollectedAt` (the R54 precedent) — never `time.Now()` inside a collector — so the same snapshot always yields the same bytes; `mtime_age_s = CollectedAt − ModTime` in whole seconds, and a zero `ModTime` yields the field omitted/`null`, never a fabricated age; (c) `ReadMeta` is not a fact, so the facts golden is untouched. Add a test that a seeded mtime produces the expected age and that an unseeded stat does not invent one.
- A missing `/etc/rsyslog.conf` is simply "not rsyslog"; an existing-but-unreadable one → `FromReadError` on all `rsyslog.*` leaves.

- [ ] **Step 4: Register keys — seven here** (`syslog.implementation`, `rsyslog.rules`, `rsyslog.parse_complete`, `rsyslog.unmodelled`, **`rsyslog.property_filters`** (`int`, Ruling I-12), `rsyslog.coverage`, `log_targets` — `coverage` carries `subject_kind: facility`; `rules`/`log_targets` carry none — confirm what `registry.go` requires for list types), regenerate golden (additions-only), gates. With Task 1's 12 and Task 3's 3 the plan registers **22 keys**. Note the golden/lint path for `subject_kind: facility` is exercised for the first time — if `TestFactsSchemaGolden` or lint rejects it, that is a real finding to report, not to work around.

- [ ] **Step 5: Lab host run** (Ubuntu 22.04 with rsyslog): report `implementation`, `parse_complete`, `unmodelled`, `property_filters`, and whether `coverage` came back `ok` with auth/authpriv/kern persistent. **Ruling I-12 acceptance (must hold, not merely be reported): a stock Ubuntu host — with `/etc/rsyslog.d/20-ufw.conf`, `21-cloudinit.conf` and `postfix.conf` present — MUST read `coverage` ok with `unmodelled 0`.** If it reads `absent`, the default config carries a construct the model must add; fix the parser and re-run — do not widen the unmodelled net, and do not accept a MANUAL verdict on a stock host.

- [ ] **Step 6: Commit.** "Add the logging collector: rsyslog rules and per-facility coverage".

---

### Task 3: journald as a function — the `journald.*` leaves on the shared helper

**Ruling I-19:** `dropin.go`, `dropin_test.go`, `mergeDropins` and its shadowing/order test now live in **Task 1**. This task only *consumes* the helper.

**Files:**
- Modify: `internal/collect/collectors/logging.go` (+ tests), `internal/facts/registry.yaml` (+golden).

**Interfaces:**
- Consumes: `mergeDropins` (Task 1).
- Produces: `logging.journald.storage` (`setting<string>`, `default_on: both`), `logging.journald.forward_to_syslog` (bool), `logging.journald.persistent` (bool, judged).

- [ ] **Step 1: Write the failing tests**

```go
// Storage=auto + /var/log/journal present → persistent true; auto without the dir → false; persistent → true; volatile → false.
// Ruling I-20: /var/log/journal is a directory only if stats["/var/log/journal"] has
// kind:"dir" (copy collectors_test.go:1614); a dirs[] seed alone returns no Kind.
func TestJournaldPersistentDerivation(t *testing.T) { /* four sub-cases */ }

// An existing-but-unreadable drop-in poisons every journald leaf with the read error (C3), never a default.
func TestJournaldUnreadableDropinIsNotADefault(t *testing.T) { /* fails["/etc/systemd/journald.conf.d/10-x.conf"]=ErrPermission → storage/forward/persistent denied */ }
```

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement the journald leaves on `mergeDropins`**

- **Chain (Ruling I-23):** main file `/etc/systemd/journald.conf`, falling back to `/usr/lib/systemd/journald.conf` when the `/etc` copy is absent (systemd ≥ 254 ships it there); directory order `/etc/systemd/journald.conf.d` > `/run/systemd/journald.conf.d` > **`/usr/local/lib/systemd/journald.conf.d`** > `/usr/lib/systemd/journald.conf.d`. All of them — both main files and the four globs — are in the `logging` collector's `Declare.Reads` (Task 2 Step 3, Ruling I-10), together with `/var/log/*/*` for `/var/log/journal`.
- `journald.storage`: persisted side = merged `Storage` (default `auto` when unset — systemd's documented default); runtime side = `persistent` if `Stat("/var/log/journal")` is a directory, else `volatile`; both sides always set; a stat that is denied → that side `FromReadError` (never ErrorEnv for "not modelled").
- `journald.forward_to_syslog`: merged `ForwardToSyslog` (`yes`/`no`; default `no` — document). Evidence.
- `journald.persistent` (I-8): true iff `Storage == persistent` OR (`Storage ∈ {auto, ""}` AND `/var/log/journal` exists). On a non-systemd host (no `/run/systemd/system`) all three journald leaves are `unsupported("no systemd journald on this host")`. `readErr` → all three carry it.

- [ ] **Step 4: Register the three keys (`setting<string>` with `default_on: both` for storage), regenerate golden (additions-only), gates; lab-host run reports `journald.storage` both sides and `journald.persistent`.**

- [ ] **Step 5: Commit.** "Derive the journald settings through the shared drop-in helper".

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
description_en: A time-synchronisation daemon (chrony, systemd-timesyncd or ntpd) is running and has at least one configured time source. Whether the clock is currently in sync is recorded as evidence only — a freshly booted or air-gapped host is not a finding. The cited STIG rules require chrony specifically; this control accepts any of the three providers. On a systemd-timesyncd host whose daemon is stopped the effective server list cannot be read and the result is MANUAL rather than a failure — muster under-claims rather than guess. On a host without systemd the daemon state cannot be read and the result is not applicable.
description_ko: 시각 동기화 데몬(chrony, systemd-timesyncd, ntpd)이 실행 중이고 설정된 시각 소스가 하나 이상 있다. 현재 동기화 여부는 증거로만 기록한다 — 막 부팅했거나 망분리된 호스트는 결함이 아니다. 인용한 STIG 규칙은 chrony 만 요구하지만 이 항목은 세 데몬을 모두 인정한다. systemd-timesyncd 가 멈춰 있는 호스트에서는 실제 서버 목록을 읽을 수 없어 실패가 아닌 MANUAL 로 처리한다 — 추정하지 않고 낮춰 판단한다. systemd 가 없는 호스트에서는 데몬 상태를 읽을 수 없어 해당 없음으로 처리한다.
category: log
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-65"], "2021": [] }   # Ruling I-22: exactly this line (relation: new — the U-67 shape, controls/file/log_dir_permissions.yaml:10)
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-252010 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-252015 }
requires_facts: ">=1"
absent_means: manual
applies_when:
  - { fact: services.ntp.installed, op: present }
checks:
  - { fact: services.ntp.active, op: eq, expected: true }
  - { fact: time_sync.server_count, op: gte, expected: 1 }   # Ruling I-9: verified — `gte` (lint.go:50 orderedOps, controls/account/session_timeout.yaml:29,32,35); lint.go:306 requires the fact to be registered `int`, which time_sync.server_count is
remediation:
  text_en: Install and enable a time-synchronisation daemon (chrony on RHEL-family, systemd-timesyncd or chrony on Ubuntu) and configure at least one reachable NTP server or pool.
  text_ko: 시각 동기화 데몬을 설치·활성화하고(RHEL 계열은 chrony, Ubuntu 는 systemd-timesyncd 또는 chrony) 접근 가능한 NTP 서버나 pool 을 하나 이상 설정합니다.
  risk: restart_service
  idempotent: true
decision: D09
```
**Ruling I-22:** the two placeholders are resolved — the op is `gte` (`controls/account/session_timeout.yaml`, *account*, not `controls/service/`) and the kisa line is written out in full. The STIG-is-chrony-only and the inactive-timesyncd-reads-MANUAL sentences (Ruling I-25) are already in `description_en/ko` above; keep both sides in step.

- [ ] **Step 2: U-66 `controls/log/syslog_policy.yaml`** (mechanisms in order; no `name:` field — label with comments; the 2H-verified shape). **Ruling I-9: the block below is the pre-flight's corrected form — it decodes through `controls.LoadFS` and lints clean; write it verbatim.** Four things were wrong before and must stay fixed: `"${facilities}"` is **quoted** (a bare `${…}` inside a flow mapping is a YAML syntax error; `lint.go:39 paramRefRe` needs the whole string to be `${name}`); `params.<name>.description` is **one** field (`schema.go:73-77` — the Korean parameter text lives in the control's `description_ko`); `where`/`require` are **single clauses**, so two requirements need **two `each` clauses**; and every `each` needs `subject: facility` (`lint.go:272`). Precedent for all four: `controls/file/log_dir_permissions.yaml` (U-67), which uses two `each` lines and `expected: "${allowed_groups}"` at line 22.

```yaml
id: muster.log.syslog_policy
title_en: System logging covers the security-relevant facilities persistently
title_ko: 시스템 로깅이 보안 관련 facility 를 영구 저장한다
description_en: A syslog daemon (rsyslog or syslog-ng) or systemd-journald keeps the security-relevant facilities in persistent local storage. The judgment is by facility, never by file path, so Ubuntu's auth.log and RHEL's secure both count. Remote forwarding is recorded as evidence only. When the rsyslog configuration uses constructs muster does not model, or an include could not be read, the result is MANUAL with the parse evidence, never a guess; syslog-ng configurations are not parsed in this version and read MANUAL. A facility that only reaches a remote collector is recorded as logged but not persistent and does not satisfy the requirement. A host with neither a syslog daemon configuration nor systemd may still be running a logger this version does not detect, so it reads MANUAL rather than a failure.
description_ko: syslog 데몬(rsyslog 또는 syslog-ng) 또는 systemd-journald 가 보안 관련 facility 를 로컬 영구 저장소에 남긴다. 파일 경로가 아니라 facility 로 판단하므로 Ubuntu 의 auth.log 와 RHEL 의 secure 가 모두 인정된다. 원격 전송은 증거로만 기록한다. rsyslog 설정에 muster 가 모델링하지 않는 구문이 있거나 include 를 읽을 수 없으면 파싱 증거를 첨부한 MANUAL 로 처리하며 추정하지 않는다. syslog-ng 설정은 이 버전에서 파싱하지 않아 MANUAL 로 처리한다. 원격 수집 서버로만 보내는 facility 는 기록은 되지만 영구 저장으로 인정하지 않는다. syslog 데몬 설정도 systemd 도 없는 호스트는 이 버전이 탐지하지 못하는 로거를 쓰고 있을 수 있어 실패가 아닌 MANUAL 로 처리한다.
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
    default: ["auth", "authpriv", "kern", "daemon", "cron"]
    description: The syslog facilities that must be logged to a persistent local target
requires_facts: ">=1"
absent_means: manual
applies_when:
  - { fact: logging.syslog.implementation, op: present }
mechanisms:
  # syslog daemon: the parsed rules must cover every required facility persistently
  # (two `each` clauses — `require` is ONE clause, so one requirement each)
  - when:   [{ fact: logging.syslog.implementation, op: in, expected: [rsyslog, syslog-ng] }]
    checks:
      - { fact: services.syslog.active, op: eq, expected: true }
      - { fact: logging.rsyslog.coverage, op: each, subject: facility, where: { field: facility, op: in, expected: "${facilities}" }, require: { field: logged, op: eq, expected: true } }
      - { fact: logging.rsyslog.coverage, op: each, subject: facility, where: { field: facility, op: in, expected: "${facilities}" }, require: { field: persistent, op: eq, expected: true } }
  # journald-only host: the journal itself must be persistent
  - when:   [{ fact: logging.syslog.implementation, op: eq, expected: journald-only }]
    checks: [{ fact: logging.journald.persistent, op: eq, expected: true }]
  # Ruling I-11: there is NO third mechanism for `implementation: none`. `none` implies
  # no systemd, so journald.persistent is unsupported and any such mechanism could only
  # yield NOT_APPLICABLE. The host falls through "no mechanism applies" → absent_means:
  # manual → MANUAL, which is honest: sysklogd, BusyBox syslogd and metalog exist and
  # v1 does not detect them.
remediation:
  text_en: Configure rsyslog (or syslog-ng) so that auth, authpriv, kern, daemon and cron messages are written to files under /var/log, or set Storage=persistent in journald.conf on a journald-only host.
  text_ko: rsyslog(또는 syslog-ng)에서 auth, authpriv, kern, daemon, cron 메시지가 /var/log 아래 파일에 기록되도록 설정하거나, journald 만 쓰는 호스트에서는 journald.conf 의 Storage=persistent 를 설정합니다.
  risk: restart_service
  idempotent: true
decision: D09
```
**Ruling I-9 — the grammar is verified, not to be re-litigated.** The pre-flight decoded this block through the real strict loader and linter and evaluated it against synthetic snapshots: `each` = `{fact, op: each, subject, where?, require}` with single `*Clause` sub-clauses of `field/op/expected` (`schema.go:16-26`, `lint.go:265-296`), and a `list<string>` param inside `where.expected` substitutes per element (`collection.go:116` → `compare("in", …)` → `inList`). Precedent: `controls/file/log_dir_permissions.yaml` (U-67). Write the block as given; do not "adjust key names" against a guess. Verified composition: coverage `absent` → MANUAL via `absent_means`; `implementation` unsupported, or any check fact unsupported, → NOT_APPLICABLE via the screen (`eval.go:188-198`); `implementation: none` matches **no** mechanism → `absent_means: manual` → **MANUAL** (Ruling I-11 — a non-systemd host without rsyslog/syslog-ng is not proof that nothing logs).

- [ ] **Step 3: Fixtures** (every fixture carries every leaf the selected mechanism's `when` and `checks` read — an omitted registered key is `missing` → ERROR; mirror the 2H fixtures' envelope shape)

`muster.log.time_sync/`: `pass-chrony.json` (ntp installed/active ok:true, server_count ok:2, provider chrony, synchronized ok:true); `pass-timesyncd.json` (server_count from timedatectl ok:1); `fail-no-sources.json` (active ok:true, server_count ok:0); `fail-inactive.json` (active ok:false, server_count ok:2); **`fail-no-provider.json`** (Ruling I-21: `services.ntp.installed` **ok:false**, `active` ok:false, `server_count` ok:0 → FAIL — `present` holds on any ok envelope, so `applies_when` does not screen it out); `manual-timedatectl-unavailable.json` (active ok:true, `time_sync.server_count` **absent**, provider timesyncd) → MANUAL; `na-no-systemd.json` (`services.ntp.installed` unsupported) → NOT_APPLICABLE.

`muster.log.syslog_policy/`: `pass-rsyslog-ubuntu.json` (implementation rsyslog, syslog.active ok:true, coverage with auth/authpriv/kern/daemon/cron logged+persistent, journald.persistent present); `pass-rsyslog-rhel.json` (same facilities, targets `/var/log/secure`/`messages`); `pass-journald-only.json` (implementation journald-only, journald.persistent ok:true); `fail-facility-missing.json` (coverage where `auth` is `logged:false`); `fail-remote-only.json` (auth `logged:true, persistent:false`); `fail-journald-volatile.json` (journald-only, persistent ok:false); `manual-unmodelled.json` (implementation rsyslog, syslog.active ok:true, coverage **absent** with `rsyslog.unmodelled` ok:3) → MANUAL; **`manual-syslog-ng.json`** (implementation syslog-ng, coverage absent, **`services.syslog.active` ok:true** — Ruling I-21: an `unsupported` there makes `mergeSoft` choose NA, not MANUAL) → MANUAL; **`manual-none-no-systemd.json`** (Ruling I-11: implementation `none`, `services.syslog.active` unsupported, coverage absent, journald leaves unsupported → MANUAL, "no mechanism applies"); **`na-container-rsyslog-conf.json`** (Ruling I-21, the R-f case: implementation rsyslog, `services.syslog.active` **unsupported**, coverage ok → NOT_APPLICABLE); `na-unsupported.json` (implementation unsupported) → NOT_APPLICABLE.

Two `each` clauses over the same list produce two `facility:auth` observations when auth fails both — expected output, not a bug. Fixture prefixes `manual-`/`na-` are accepted (`internal/controls/fixtures_test.go:19-22`).

- [ ] **Step 4: Lint + evaluate.** `go run ./cmd/muster controls lint --references docs/reference` → "ok: 47 controls" (the `each`/params/`facility`-kind path must load); `go test ./internal/controls/...` → every fixture yields its prefix status (esp. both `manual-*` → MANUAL, `na-*` → NOT_APPLICABLE, `fail-remote-only` → FAIL). If the `each … ${facilities}` clause does not decode, STOP and report the exact lint error rather than dropping the param.

- [ ] **Step 5: Commit.** "Add the time synchronisation and system logging controls".

---

### Task 5: count, coverage, e2e and README reconciliation

- [ ] **Step 1:** both `ok: 45 controls` → `ok: 47 controls` (`cmd/muster/controls_test.go:36,75`).
- [ ] **Step 2:** `cmd/muster/e2e_test.go`: "forty-five" → "forty-seven" (~line 189), "forty-four" → "forty-six" (~line 249); add `muster.log.time_sync` and `muster.log.syslog_policy` to BOTH maps as **PASS** (H-15: the waiver e2e's `Applied != 10 || Unknown != 1` at **`cmd/muster/e2e_test.go:101`** (Ruling I-22) must stay untouched — do NOT make either FAIL in `full-fail.json`; the per-control `fail-*.json` fixtures prove the FAIL path).
- [ ] **Step 3:** `full-pass.json` AND `full-fail.json`: add the same passing facts for both controls — `services.ntp.installed/active` ok:true, `time_sync.server_count` ok:2 (+`provider`, `servers`, `synchronized` for realism), `logging.syslog.implementation` ok "rsyslog", `services.syslog.active` ok:true, `logging.rsyslog.coverage` with the five default facilities logged+persistent, `logging.journald.persistent` ok:true. Every fact a mechanism's `when`/`checks` reads must be present.
- [ ] **Step 4:** `go run ./tools/coverage` → line 4 `47 of 67 items enrolled (auto 43, partial 4, manual 0).`; `go run ./tools/coverage -check` passes. README pair: grep for a count sentence; none exists today — leave unchanged and say so.
- [ ] **Step 5:** `go test ./...` (Windows, no -race); `GOOS=linux GOARCH=amd64 go vet ./... && go build ./...`; `GOOS=linux staticcheck ./...`; lint → "ok: 47 controls"; coverage -check.
- [ ] **Step 6: Commit.** "Enrol the time-sync and logging controls in the coverage and e2e snapshots".

---

## Self-Review

**1. Spec coverage.** §10.2 "time synchronisation" → `timesync` collector + U-65; "logging as a function (journald-only hosts)" → the journald-only mechanism on `journald.persistent` and the **four-tier** drop-in merge (I-5 + Ruling I-23, the sysctl shadowing rule from §4); the logical-service map `ntp`/`syslog` → the two services rows (I-4); §6.6 params → `${facilities}`; §6.5 step 8 + `absent_means: manual` → MANUAL on an incomplete/unmodelled parse **and on a `none` host with no mechanism** (Ruling I-11); step 13's "degraded" WARN row is deliberately not wired (as in 2H, H-23). D09: remote forwarding and syslog-ng are data-level limitations stated in the description, not adapter code.

**2. Placeholder scan.** None left: the pre-flight resolved both grammar placeholders — the numeric at-least op is `gte` (`controls/account/session_timeout.yaml`) and the corrected `each`/`params` block (Ruling I-9) decodes and lints as written, with U-67 as the precedent. The `relation: new` kisa line is spelled out. Everything is concrete.

**3. Type consistency.** `time_sync.server_count` int (judged via `gte`, so `int` is mandatory; `absent` on the timesyncd/no-timedatectl branch, `ok: 0` when `provider == none`); `logging.rsyslog.coverage` `list<record>` with `subject_kind: facility` (judged via two `each` clauses, `absent` when not confident); `logging.rsyslog.property_filters` int (evidence, Ruling I-12); `logging.journald.persistent` bool (judged); `journald.storage` `setting<string>` both sides; `services.ntp/syslog.*` the standard four leaves, no `reachable`. 22 new keys in total. U-65 reads `services.ntp.{installed,active}` + `time_sync.server_count`; U-66 reads `logging.syslog.implementation`, `services.syslog.active`, `logging.rsyslog.coverage`, `logging.journald.persistent` — all registered.

**Risks (updated by the pre-flight rulings):**
- **R-a (grammar): CLOSED by Ruling I-9** — the corrected block was decoded through `controls.LoadFS` and evaluated; a `list<string>` param does substitute inside `where.expected`.
- **R-b (first use of `subject_kind: facility`):** verified valid (`registry.go:43,75-77`) and additive in the golden; still, a rejection at implementation time is a real finding, not something to work around.
- **R-c (coverage derivation correctness): now three rules, not one** — `.none` scoped per selector line (I-14), discards honoured in rule order (I-13), `persistent` = local file target kind (I-15). The two default-config tests, the discard test and the lab run guard this.
- **R-d (over-claiming on RainerScript): bounded by Ruling I-12** — only four constructs count as unmodelled; property filters and `$Directive`/`module(`/`template(` lines do not. The lab-host acceptance (stock Ubuntu: `coverage` ok, `unmodelled 0`) is the check.
- **R-e (timesyncd + no timedatectl → absent, not FAIL):** unchanged, and now split per command (I-16) so a chrony host keeps `synchronized`.
- **R-f (CI): confirmed by the pre-flight.** Systemd-less legs → `services.ntp/syslog` unsupported → U-65 NA (`applies_when`); with `/etc/rsyslog.conf` present but no systemd, `services.syslog.active` unsupported screens U-66 to NOT_APPLICABLE (pinned by `na-container-rsyslog-conf.json`), never ERROR. `collect-root` (Ubuntu 24.04 runner: timesyncd + rsyslog) must yield PASS or MANUAL, never ERROR — which requires Ruling I-18 (`provider == none` never leaves a judged leaf unset) and Ruling I-10 (no undeclared stat, so `run.complete` stays true).
