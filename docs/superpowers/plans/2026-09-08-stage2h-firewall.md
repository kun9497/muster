# Stage 2H — Firewall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a new `firewall` collector (backend detection, kernel-ruleset capture, a minimal normalised model with an explicit `normalization_confidence`) plus the TCP-wrapper `files.*` facts, and enrol the one KISA 2026 firewall control U-28 (접속 IP 및 포트 제한) — which passes on a host that restricts inbound access (a default-deny firewall or a `hosts.deny ALL`), fails when it can confidently see no restriction, and degrades to MANUAL (never a fabricated PASS/FAIL) when the ruleset cannot be normalised.

**Architecture:** A new Linux-only `firewall` collector detects the backend from persisted config (ufw / firewalld / nftables / iptables / none, with evidence) and reads the kernel ruleset as the runtime oracle (`nft list ruleset`, else `iptables-save`/`ip6tables-save`) — it never shells out to `ufw`/`firewall-cmd` (dbus dependency). From the ruleset it derives the inbound default policy and a single judged boolean `firewall.restricts_inbound`, carrying a `normalization_confidence`. **Any command failure — missing `CAP_NET_ADMIN`, no netlink, tool absent — degrades to `unsupported`, never `denied`/`error`, so the run stays complete (the R220 lesson).** U-28 is a `mechanisms` control (firewall OR tcp_wrappers) whose judged leaf is `absent` when confidence is below `full`, so `absent_means: manual` yields MANUAL there — no new engine machinery.

**Tech Stack:** Go 1.25.x, Linux-only collector behind build tags; `nft`/`iptables-save`/`ip6tables-save` via the existing exec discipline; config files under `/etc/ufw`, `/etc/firewalld`, `/etc/nftables.conf`, `/etc/iptables/`; `/etc/hosts.allow` + `/etc/hosts.deny`; YAML control with `mechanisms` and `absent_means: manual`; fixtures as `controls/testdata/<id>/{pass,fail,manual,na}-*.json`.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` (design + decision log; §5.1/§5.3 two-sided settings incl. firewall; §6.5 steps 3/6/8/13; §7.3 firewall confidence→MANUAL; D09 tcp_wrappers is a `mechanisms` data item; the KISA table row for U-28; the recorded PDF page-53 defect note). The plan argues from the spec; conflicts resolve against it. Scope brief with all source citations: `<session-scratchpad>/2h-scope-brief.md`.

## Global Constraints

- **Control set count: 44 → 45** (one new `auto` control; coverage becomes `auto 41, partial 4, manual 0`). Every count seam in the final task lands on 45.
- **Registry `schema_version` stays 1.** The whole `firewall.*` section and the three `files.etc_hosts_*` keys are pure additions (C2; spec §5.7). Regenerate the facts golden with `go test ./internal/facts -run TestFactsSchemaGolden -update`; the diff must be additions only, each `since: 1`.
- **Every fact leaf is an envelope; a status other than `ok` never yields PASS.** A registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`.
- **No-capability / no-tool / no-netfilter degradation is mandatory and CI-enforced (R220).** The `collect-contract` CI leg runs `muster collect` in a `--network none --read-only` `ubuntu:24.04` container that runs as root **but without `CAP_NET_ADMIN`** (Docker drops it), and asserts `.run.complete == true`. A `nft`/`iptables-save` failure there must become `firewall.backend`/`firewall.restricts_inbound` = **`unsupported`** (confidence `none`), never `denied`/`error` — otherwise the firewall collector's `Worst()` is non-ok and the run goes partial. The collector must classify its own command failures (like `cronTimers` in `cron.go`), not rely on `Needs: root` denied-wrapping. Firewall collector `Needs: "none"`.
- **MANUAL-on-low-confidence via `absent_means: manual`, not new engine code (§7.3).** The collector emits the judged leaf `firewall.restricts_inbound` as `ok:true`/`ok:false` only at `normalization_confidence: full`; at `partial`/`none` (a backend was seen but the ruleset can't be normalised) it emits that leaf **`absent`** with a reason that references the raw dump, and U-28 carries `absent_means: manual` (precedent `controls/account/root_remote_login.yaml`). Confirm eval.go's step-8 absent-screening + `mechanisms` interaction during execution (see Task 4); if `absent_means: manual` cannot express this cleanly with `mechanisms`, fall back to a single-mechanism control and record a ruling.
- **Same input, same bytes.** No `map` reaches the JSON/table renderer; sort rule records and raw-dump records deterministically.
- **`references.stig` only cites ids in `docs/reference/stig/*.json`.** No firewall rule id exists in the committed index today, so **U-28 ships `references.kisa` only** (like `telnet_disabled.yaml`). Do NOT run `make refindex` or add STIG content in this plan.
- **Never copy KISA/CIS text.** Control `description_*`/`title_*` are muster's own words. U-28's own criterion text is unavailable/unreliable in the source (the 2026 PDF page-53 defect diverted it onto U-26's page); design the judgment from the item name + generic domain knowledge, documented honestly, never from a PDF quote.
- **Fixtures are `synthetic: true`**, never from a real host; never commit a snapshot captured from the lab host (D02). `firewall.raw_dumps` is `sensitivity: internal`.
- **Two-sided settings (spec §5.3).** `firewall.enabled` and `firewall.default_policy.{input,forward}` are `setting<…>` with `default_on: both`: runtime = the kernel ruleset, persisted = the backend's config. Follow the sysctl/services setting shape already in the registry.
- **KISA ids (verified against `docs/reference/kisa/kisa_mapping.json`):** U-28 ← 2021 U-18, clean 1:1 renumber (`{ "2026": ["U-28"], "2021": ["U-18"] }`).
- **Controller boundary rulings (folded in):**
  - **H-2:** 2H builds the TCP-wrapper facts (`files.etc_hosts_allow_lines`, `files.etc_hosts_deny_lines`, `files.etc_hosts_deny_all`) in the **files** collector (C1: fixed-path files belong to `files`), used as U-28's second mechanism and pre-delivering the fact 2L/U-56 needs. No other merged plan owns them.
  - **H-4:** v1 reaches `full` confidence ONLY when the kernel ruleset is read AND its inbound default policy is unambiguously determinable; everything else is `partial`/`none` → MANUAL. Under-claiming (MANUAL) is the safe direction; never a confidently-wrong PASS/FAIL.
  - **H-11:** control category is `file` (muster's category mirrors KISA's taxonomy, which files U-28 under 파일 및 디렉토리 관리); id `muster.file.ip_port_restriction`. (`network` is not in the category vocabulary and this plan does not add one.)

---

## File Structure

**Collector (Tasks 1–2) — create/modify:**
- `internal/collect/collectors/firewall.go` — **new**: the `firewall` collector (backend detection, kernel-ruleset capture, raw dumps, self-classified command-failure→unsupported, normalisation, `restricts_inbound`).
- `internal/collect/collectors/firewall_test.go` — **new**: collector tests incl. the no-capability degrade (unsupported, run stays complete) and the nft/iptables default-policy normalisation.
- `internal/collect/collectors/files_hosts.go` (or extend an existing `files_*.go`) — **new/modify** (Task 3): the `/etc/hosts.allow` + `/etc/hosts.deny` reader producing `files.etc_hosts_allow_lines`, `files.etc_hosts_deny_lines`, `files.etc_hosts_deny_all`.
- `internal/facts/registry.yaml` + the facts golden — new `firewall.*` and `files.etc_hosts_*` keys.
- Confirm the new collector is registered where collectors are assembled (grep for where `servicesCollector`/`cronCollector` are added to the collector list; add `firewallCollector` the same way).

**Control (Task 4) — create:**
- `controls/file/ip_port_restriction.yaml` (U-28) + fixtures under `controls/testdata/muster.file.ip_port_restriction/`.

**Reconciliation (Task 5) — modify:**
- `cmd/muster/controls_test.go` (two `ok: 44 controls` → `ok: 45 controls`), `cmd/muster/e2e_test.go` (two spelled-out count comments + both control-id→status maps), `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `docs/reference/coverage.md` (regenerated), `README.md`/`README.ko.md` (only if a service-coverage sentence exists — likely no count sentence to bump).

---

## Interfaces (produced by this plan)

New fact keys (all `since: 1`):
- `firewall.backend` — `string` (collector `firewall`) — `ufw` / `firewalld` / `nftables` / `iptables` / `none`, with detection evidence in the source; `unsupported` envelope when the kernel ruleset cannot be read at all.
- `firewall.enabled` — `setting<bool>`, `default_on: both` — runtime = a non-empty kernel ruleset; persisted = the backend config/unit state.
- `firewall.default_policy.input` / `firewall.default_policy.forward` — `setting<string>`, `default_on: both` — base-chain policy / default-zone target (`drop`/`reject`/`accept`/…).
- `firewall.restricts_inbound` — `bool` (the JUDGED leaf) — `ok:true` when full-confidence inbound is default-deny (or a full-confidence restricting ruleset); `ok:false` when full-confidence no restriction; **`absent`** (reason references the raw dump) when confidence is `partial`/`none` but a backend was seen; **`unsupported`** when no backend/ruleset is determinable (container/no-capability).
- `firewall.normalization_confidence` — `string` — `full` / `partial` / `none` (evidence for the degradation).
- `firewall.rules` — `list<record>` — normalised rules `{chain, proto, dport, saddr, action}` (evidence; a default policy alone is not restriction).
- `firewall.raw_dumps` — `list<record>` `{source, content, truncated}`, **`sensitivity: internal`** — the verbatim tool output the normalisation was derived from (content capped; see Task 1).
- `files.etc_hosts_allow_lines` / `files.etc_hosts_deny_lines` — `list<string>` (collector `files`) — non-comment lines of `/etc/hosts.allow` / `/etc/hosts.deny`.
- `files.etc_hosts_deny_all` — `bool` (collector `files`) — true when `/etc/hosts.deny` contains an `ALL: ALL` (deny-everything) line; the derived bool exists because `matches` on a list holds only when every element matches.

---

### Task 1: firewall collector — detection, ruleset capture, raw dumps, safe degradation

**Files:**
- Create: `internal/collect/collectors/firewall.go`, `internal/collect/collectors/firewall_test.go`
- Modify: `internal/facts/registry.yaml`; the collector-registration site.

**Interfaces:**
- Consumes: `collect.Access` (`Run`, `ReadFile`, `Glob`, `Stat`), `collect.Unsupported`, `collect.Command`, `facts.Builder`, and the existing envelope constructors (grep `internal/collect/facts.go` for `Unsupported`, `ErrorEnv`, `commandFailure`, and how `cron.go`'s `cronTimers` builds a command and classifies failure — mirror it).
- Produces: `firewallCollector` with `Needs: "none"`; `firewall.backend`, `firewall.enabled`, `firewall.default_policy.{input,forward}`, `firewall.restricts_inbound` (absent/unsupported in T1 — normalisation lands in T2), `firewall.normalization_confidence`, `firewall.rules` (empty in T1), `firewall.raw_dumps`.

- [ ] **Step 1: Write the failing test — capture the ruleset when readable, degrade to unsupported when not, and never make the run partial**

Create `firewall_test.go`. Use the real collector-test helpers (grep `collectors_test.go` for how `services_test`/`cron` tests build access + assert — `build(t, "firewall", access)`, `env(t, b, key)`, `b.Worst("firewall")`, a fake `Access` whose `Run` returns a canned `collect.CommandResult` from a testdata file, and `fails`/`files` maps). Two load-bearing tests:

```go
// A readable kernel ruleset → backend detected, raw dump captured, run complete.
func TestFirewallCapturesRulesetWhenReadable(t *testing.T) {
	a := firewallAccess(/* nft list ruleset → testdata/nft.ruleset.drop; /etc/nftables.conf present */)
	b := build(t, "firewall", a)
	if e := env(t, b, "firewall.backend"); e.Status != facts.StatusOK {
		t.Fatalf("backend: %+v", e)
	}
	if e := env(t, b, "firewall.raw_dumps"); e.Status != facts.StatusOK {
		t.Errorf("raw_dumps should be captured: %+v", e)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok`, got)
	}
}

// No CAP_NET_ADMIN / tool missing → unsupported, NOT denied/error; run stays complete (R220).
func TestFirewallNoCapabilityDegradesToUnsupported(t *testing.T) {
	a := firewallAccess(/* nft AND iptables-save both fail with a permission/netlink error */)
	b := build(t, "firewall", a)
	for _, k := range []string{"firewall.backend", "firewall.restricts_inbound", "firewall.normalization_confidence"} {
		e := env(t, b, k)
		if e.Status == facts.StatusDenied || e.Status == facts.StatusError {
			t.Errorf("%s = %s, must NOT be denied/error (would break collect-contract)", k, e.Status)
		}
	}
	if e := env(t, b, "firewall.backend"); e.Status != facts.StatusUnsupported {
		t.Errorf("backend = %s, want unsupported when the ruleset cannot be read", e.Status)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok (unsupported ranks ok, run stays complete)`, got)
	}
}
```

Add the testdata files the tests need (e.g. `testdata/nft.ruleset.drop` — an `nft list ruleset` dump with an `input` base chain `policy drop`; `testdata/iptables-save.accept` — an `*filter … :INPUT ACCEPT` dump).

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run TestFirewall`
Expected: FAIL — collector undefined.

- [ ] **Step 3: Implement backend detection + ruleset capture + self-classified degradation**

- Declare the commands (as `collect.Command` values, mirror `cron.go`'s `cronTimersCmd`): `nft -a list ruleset` (`/usr/sbin/nft`), `iptables-save`, `ip6tables-save`. Declare `Reads` for the persisted config files: `/etc/ufw/ufw.conf`, `/etc/ufw/user.rules`, `/etc/default/ufw`, `/etc/firewalld/firewalld.conf`, `/etc/firewalld/zones/*.xml`, `/etc/nftables.conf`, `/etc/iptables/rules.v4`.
- **Runtime side (the oracle):** run `nft list ruleset`; if it fails (Err/TimedOut/non-zero exit), fall back to `iptables-save` (+`ip6tables-save`). Capture whatever succeeds into `firewall.raw_dumps` (one record per command, `{source, content, truncated}`; cap `content` at 64 KiB with `truncated:true` past that — do NOT reuse the 256-byte single-line cap). **If NO ruleset command succeeds**, set `firewall.backend`, `firewall.restricts_inbound`, `firewall.normalization_confidence` (= "none"), `firewall.default_policy.*`, `firewall.enabled` (runtime side) all to `collect.Unsupported("no readable kernel firewall ruleset: <first stderr line or exit>")` — NEVER `commandFailure`/denied/error. This is the R220-critical path.
- **Backend name** (evidence): detect from the persisted config that exists — `firewalld.conf`/zones → `firewalld`; `/etc/ufw/*` with `ENABLED=yes` → `ufw`; `/etc/nftables.conf` or a non-empty nft ruleset → `nftables`; `/etc/iptables/rules.v4` or iptables-save output → `iptables`; none of the above but a readable (empty) ruleset → `none`. Record the detection evidence in the source.
- In T1, leave `firewall.restricts_inbound` = `collect.Absent("normalization pending")` and `firewall.normalization_confidence` = `"none"` when a ruleset WAS read (T2 fills in the real normalisation); leave `firewall.rules` an empty `ok` list. (This keeps T1 independently green and the collector safe.)
- `firewall.enabled` (`setting<bool>`, both sides): runtime = ruleset non-empty; persisted = backend config present/enabled.

- [ ] **Step 4: Register the keys**

Add the `firewall.*` keys to `registry.yaml` (see Interfaces for names/types). `firewall.enabled` and `firewall.default_policy.{input,forward}` are `setting<…>` with `default_on: both` (follow the sysctl/services setting entries). `firewall.raw_dumps` carries `sensitivity: internal`; do NOT set `subject_kind` on scalar keys (registry rejects it on non-`list<` types — the R229 lesson). Register the collector at the assembly site.

- [ ] **Step 5: Regenerate golden + gates**

`GOOS=linux GOARCH=amd64 go test ./internal/facts -run TestFactsSchemaGolden -update` (review: additions-only, `since: 1`, `schema_version` unchanged). Then `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ ./internal/facts`, `gofmt -l`, `GOOS=linux GOARCH=amd64 go vet ./...`, `GOOS=linux staticcheck ./internal/collect/...`.

- [ ] **Step 6: Lab-host verification (R220 reality check)**

The lab host has a real ruleset. Sync + run the collector there via the READ-ONLY scratchpad scripts (`lab-sync.sh`/`lab-run.sh` at `C:\Users\ssk\AppData\Local\Temp\claude\C--Users-ssk-muster\b1637add-0c8f-4028-9be6-5e5664159bdd\scratchpad\`; run via the PowerShell tool with Git Bash explicitly; NEVER edit them). Confirm `muster collect` yields a complete run with `firewall.*` present and `firewall.raw_dumps` captured, and that a non-root run does not make the firewall collector `denied`/`error` (it should still capture or degrade to unsupported). Report what backend + default policy the host shows. **Never commit a snapshot from the host.** If unreachable after 2-3 tries, report and rely on CI.

- [ ] **Step 7: Commit**

```bash
git add internal/collect/collectors/firewall.go internal/collect/collectors/firewall_test.go internal/collect/collectors/testdata/ internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Add the firewall collector: detection, ruleset capture, safe degradation"
```

---

### Task 2: firewall normalisation — default policy + confidence + restricts_inbound

**Files:**
- Modify: `internal/collect/collectors/firewall.go`, `internal/collect/collectors/firewall_test.go`

**Interfaces:**
- Consumes: the raw dumps captured in T1.
- Produces: `firewall.default_policy.{input,forward}` (real values), `firewall.normalization_confidence` (`full` when determinable), `firewall.restricts_inbound` (`ok:true/false` at `full`, `absent` otherwise), `firewall.rules` (parsed records where cheap).

- [ ] **Step 1: Write the failing tests**

```go
// nftables input base chain "policy drop" → full confidence, restricts_inbound ok:true.
func TestFirewallNftDropIsRestricted(t *testing.T) {
	a := firewallAccess(/* nft ruleset with `chain input { type filter hook input priority 0; policy drop; }` */)
	b := build(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Fatalf("confidence: %+v", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound: %+v", e)
	}
}

// iptables INPUT policy ACCEPT with no restricting rules → full confidence, restricts_inbound ok:false.
func TestFirewallIptablesAcceptIsNotRestricted(t *testing.T) { /* :INPUT ACCEPT … */ }

// A ruleset shape we do not confidently model → partial confidence → restricts_inbound ABSENT (→ MANUAL).
func TestFirewallUnparseableRulesetIsPartialAbsent(t *testing.T) {
	a := firewallAccess(/* nft ruleset with multiple input hooks / forms the parser does not fully model */)
	b := build(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value == "full" {
		t.Fatalf("must not claim full on an unmodelled ruleset: %+v", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound must be ABSENT at partial confidence (→ MANUAL): %+v", e)
	}
}
```

- [ ] **Step 2: Run to confirm failure.** `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run TestFirewall`

- [ ] **Step 3: Implement the minimal normaliser (H-4 scope)**

- Parse the kernel ruleset for the **inbound default policy**:
  - nftables: find the base chain with `hook input`; read its `policy drop|accept`. If exactly one input base chain with a clear policy → determinable. Multiple input base chains, or no base chain policy line → not determinable → `partial`.
  - iptables-save: the `:INPUT <POLICY>` line in `*filter`.
- Set `firewall.default_policy.input`/`.forward` from what was parsed (setting: runtime = kernel, persisted = the config-file policy where cheaply readable — otherwise leave the persisted side degraded per the two-home rule).
- Set `firewall.normalization_confidence = "full"` ONLY when the inbound default policy is unambiguously determined; else `"partial"`.
- Derive `firewall.restricts_inbound`:
  - `full` + default input `drop`/`reject` → `ok:true`.
  - `full` + default input `accept` (and no full-confidence restricting rule model) → `ok:false`.
  - `partial`/`none` → `collect.Absent("firewall confidence <level>: ruleset not normalisable; see firewall.raw_dumps")`.
- Populate `firewall.rules` with the records you do parse (evidence). Keep it minimal; do NOT let a rich ruleset you cannot fully model claim `full`.
- Document in a code comment exactly what v1 treats as `full` (the H-4 boundary) so a reviewer can see the under-claim is deliberate.

- [ ] **Step 4: Gates + lab host.** Regenerate golden only if a key/type changed (it should not — values only). `GOOS=linux` test/vet/staticcheck; gofmt. Re-run on the lab host (Step 1.6) and report the real host's confidence + restricts_inbound.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/firewall.go internal/collect/collectors/firewall_test.go internal/collect/collectors/testdata/
git commit -m "Normalise the inbound default policy with an explicit confidence"
```

---

### Task 3: TCP-wrapper files facts (hosts.allow / hosts.deny)

**Files:**
- Create/modify: a `files` collector source (e.g. `internal/collect/collectors/files_hosts.go`); `internal/facts/registry.yaml` + golden; test.

**Interfaces:**
- Produces: `files.etc_hosts_allow_lines`, `files.etc_hosts_deny_lines` (`list<string>`), `files.etc_hosts_deny_all` (`bool`), collector `files`.

- [ ] **Step 1: Write the failing test**

```go
// hosts.deny with "ALL: ALL" → etc_hosts_deny_all true; comments/blank lines excluded from the line lists.
func TestHostsDenyAllDetected(t *testing.T) {
	a := filesAccess(map[string]string{
		"/etc/hosts.deny":  "# comment\nALL: ALL\n",
		"/etc/hosts.allow": "sshd: 10.0.0.0/8\n",
	})
	b := build(t, "files", a)
	if e := env(t, b, "files.etc_hosts_deny_all"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("deny_all: %+v", e)
	}
	if e := env(t, b, "files.etc_hosts_deny_lines"); e.Status != facts.StatusOK /* value == ["ALL: ALL"] */ {
		t.Errorf("deny_lines: %+v", e)
	}
}

// Missing files → deny_all ok:false, line lists empty ok (never a fabricated absent that mis-screens U-28).
func TestHostsFilesMissing(t *testing.T) { /* ENOENT → etc_hosts_deny_all ok:false, lines [] ok */ }

// An existing-but-unreadable hosts.deny is a read error, not a silent false (C3 honesty).
func TestHostsDenyUnreadableIsNotSilentFalse(t *testing.T) { /* permission denied → denied envelope on the leaves */ }
```

Use the `files` collector's existing test harness + line-reading/`permRow` helpers (grep `files_startup.go`/`files_sudo.go` for the content-reading pattern and the read-error envelope).

- [ ] **Step 2: Run to confirm failure.**

- [ ] **Step 3: Implement the reader**

Read `/etc/hosts.deny` and `/etc/hosts.allow`; strip comments (`#…`) and blank lines into the `*_lines` lists; `etc_hosts_deny_all` = true iff a deny line matches `ALL\s*:\s*ALL` (case-insensitive, tolerant of `PARANOID`/spacing). ENOENT → `deny_all` `ok:false`, lines `[] ok` (a host with no tcp_wrappers simply isn't restricting via it — `ok:false`, not `absent`, so U-28's tcp_wrappers mechanism reads a definite "no"). An existing-but-unreadable file → a read-error envelope on all three leaves (never a silent false — C3).

- [ ] **Step 4: Register keys + golden + gates.** Add the three `files.*` keys (`sensitivity: public`; `since: 1`; `list<string>` may carry `subject_kind` if the file's other list keys do — match neighbours). Regenerate golden (additions-only). `GOOS=linux` test/vet/staticcheck; gofmt.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/files_hosts.go internal/collect/collectors/*_test.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Add the TCP-wrapper hosts.allow/deny files facts"
```

---

### Task 4: U-28 control + fixtures

**Files:**
- Create: `controls/file/ip_port_restriction.yaml` + `controls/testdata/muster.file.ip_port_restriction/*.json`

**Interfaces:**
- Consumes: `firewall.backend`, `firewall.restricts_inbound`, `files.etc_hosts_deny_all`.

- [ ] **Step 1: Write the control**

`controls/file/ip_port_restriction.yaml`:

```yaml
id: muster.file.ip_port_restriction
title_en: Inbound access is restricted by IP and port
title_ko: 접속 IP 및 포트가 제한되어 있다
description_en: The host restricts inbound access — a default-deny host firewall (nftables, iptables, ufw or firewalld) or a TCP-wrapper "ALL: ALL" deny in /etc/hosts.deny. When the firewall ruleset cannot be normalised with confidence the result is MANUAL with the raw ruleset attached, never a guessed pass or fail.
description_ko: 호스트가 인바운드 접속을 제한한다 — 기본 차단(default-deny) 호스트 방화벽(nftables/iptables/ufw/firewalld) 또는 /etc/hosts.deny 의 "ALL: ALL" 차단. 방화벽 규칙을 신뢰도 있게 정규화할 수 없으면 원본 규칙을 첨부한 MANUAL 로 처리하며, 통과/실패를 추정하지 않는다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-28"], "2021": ["U-18"] }
requires_facts: ">=1"
absent_means: manual
mechanisms:
  - name: firewall
    when: { fact: firewall.backend, op: in, expected: [nftables, iptables, ufw, firewalld] }
    checks:
      - { fact: firewall.restricts_inbound, op: eq, expected: true }
  - name: tcp_wrappers
    when: { fact: firewall.backend, op: eq, expected: none }
    checks:
      - { fact: files.etc_hosts_deny_all, op: eq, expected: true }
remediation:
  text_en: Enable a host firewall with a default-deny inbound policy (ufw default deny incoming; firewalld default zone target DROP; or an nftables/iptables INPUT policy of drop with explicit allow rules), or deny by default in /etc/hosts.deny (ALL: ALL) and allow only required sources in /etc/hosts.allow.
  text_ko: 기본 차단 인바운드 정책의 호스트 방화벽을 설정하거나(ufw default deny incoming; firewalld 기본 zone target DROP; nftables/iptables INPUT 정책 drop + 명시적 허용 규칙), /etc/hosts.deny 에서 기본 차단(ALL: ALL) 후 /etc/hosts.allow 에 필요한 출발지만 허용합니다.
  risk: network_lockout
  idempotent: false
decision: D09
```

**Ruling H-5 / verify against eval.go:** the intended behaviour — firewall backend present but `firewall.restricts_inbound` `absent` (confidence below full) → the whole control is MANUAL via `absent_means: manual`; `unsupported` backend → NOT_APPLICABLE; `full` deny → PASS; `full` open + no `hosts.deny ALL` → FAIL. **Confirm the `mechanisms` + `absent_means` + step-8 interaction actually produces this** by reading `internal/check/eval.go` (steps 3/6/8, and how `mechanisms[].when`/`checks` and `absent_means` compose) and by the fixtures below. If `absent_means: manual` does not compose with `mechanisms` as intended, simplify to a single non-mechanism check on `firewall.restricts_inbound` (dropping the tcp_wrappers mechanism to a documented follow-up) and record the ruling in the ledger — a correct MANUAL-on-partial is more important than the second mechanism. Verify `risk: network_lockout` is an accepted `risk` enum value (grep the schema/lint); if not, use the closest accepted value.

- [ ] **Step 2: Fixtures** (mirror an existing control's envelope shape; every fixture carries the leaves the selected mechanism checks)

- `pass-firewall-deny.json` — `firewall.backend` ok `"nftables"`, `firewall.restricts_inbound` ok:true → PASS.
- `pass-tcpwrappers.json` — `firewall.backend` ok `"none"`, `files.etc_hosts_deny_all` ok:true → PASS.
- `fail-open.json` — `firewall.backend` ok `"iptables"`, `firewall.restricts_inbound` ok:false → FAIL.
- `fail-tcpwrappers-open.json` — `firewall.backend` ok `"none"`, `files.etc_hosts_deny_all` ok:false → FAIL.
- `manual-partial-confidence.json` — `firewall.backend` ok `"firewalld"`, `firewall.restricts_inbound` **absent**, `firewall.normalization_confidence` ok `"partial"` → MANUAL (via `absent_means: manual`). This is the §7.3 case.
- `na-nobackend.json` — `firewall.backend` **unsupported** (container/no-capability) → NOT_APPLICABLE.

Confirm each fixture's filename prefix maps to its status (grep the fixture-harness `prefixStatus` for the `manual-`/`na-` prefixes — the 2G U-43 fix used `manual-`; NA uses `na-`).

- [ ] **Step 3: Lint + evaluate**

`go run ./cmd/muster controls lint --references docs/reference` → the id resolves, no STIG ref (kisa only), fixtures present, "ok: 45 controls". `go test ./internal/controls/...` → every fixture yields its prefix status (esp. `manual-partial-confidence` → MANUAL and `na-nobackend` → NOT_APPLICABLE).

- [ ] **Step 4: Commit**

```bash
git add controls/file/ip_port_restriction.yaml controls/testdata/muster.file.ip_port_restriction
git commit -m "Add the U-28 inbound access restriction control"
```

---

### Task 5: count, coverage, e2e and README reconciliation

**Files:**
- Modify: `cmd/muster/controls_test.go`, `cmd/muster/e2e_test.go`, `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `docs/reference/coverage.md`, `README.md`, `README.ko.md`.

- [ ] **Step 1: Count assertions.** Both `ok: 44 controls` → `ok: 45 controls` in `controls_test.go`.

- [ ] **Step 2: e2e snapshots.** Update the two spelled-out count comments in `e2e_test.go` ("forty-four"→"forty-five", "forty-three"→"forty-four"). Add `muster.file.ip_port_restriction` to both control-id→status maps. In `full-pass.json` give U-28 a full-confidence PASS shape (`firewall.backend` ok `"nftables"`, `firewall.restricts_inbound` ok:true, `firewall.normalization_confidence` ok `"full"`, plus `files.etc_hosts_*` present); in `full-fail.json` give it a full-confidence FAIL (`firewall.restricts_inbound` ok:false, `files.etc_hosts_deny_all` ok:false, backend a real value). Keep confidence `full` in both so the "flip one thing" assertion holds (do NOT let U-28 read MANUAL in these shared fixtures). Every referenced judged leaf must be present.

- [ ] **Step 3: Coverage.** `go run ./tools/coverage` → line 4 becomes `45 of 67 items enrolled (auto 41, partial 4, manual 0).` and the U-28 row shows the control id. `go run ./tools/coverage -check` passes.

- [ ] **Step 4: README.** Grep `README.md`/`README.ko.md` for a control-count / coverage sentence; update only if one exists (EN+KO together), else leave unchanged. Report which.

- [ ] **Step 5: Full suite + cross gates.** `go test ./...` (Windows, no -race); `GOOS=linux GOARCH=amd64 go vet ./...`; `GOOS=linux GOARCH=amd64 go build ./...`; `GOOS=linux staticcheck ./...`; `go run ./cmd/muster controls lint --references docs/reference` → "ok: 45 controls"; `go run ./tools/coverage -check`.

- [ ] **Step 6: Commit**

```bash
git add cmd/muster docs/reference/coverage.md README.md README.ko.md
git commit -m "Enrol the U-28 firewall control in the coverage and e2e snapshots"
```

---

## Self-Review

**1. Spec coverage.** §10.2's 2H "firewall" → one control U-28, built on a new `firewall` collector (backend detection, kernel-ruleset oracle, minimal normalised model with `normalization_confidence`, raw dumps) plus the TCP-wrapper `files.*` facts. §5.1/§5.3 two-sided settings → `firewall.enabled`/`default_policy.*` as `setting` with `default_on: both`. §7.3 firewall-confidence→MANUAL → `absent_means: manual` on the collector-derived `restricts_inbound` (no new engine machinery). D09 tcp_wrappers as a `mechanisms` data item → U-28's second mechanism. The R220 lesson → self-classified command-failure→unsupported (Task 1 Global Constraint).

**2. Placeholder scan.** The control YAML is complete; every fixture and every collector behaviour is concretely specified. The two deliberately-flagged unknowns each have a fallback: the `mechanisms` + `absent_means: manual` composition (Task 4 — verify against eval.go, fall back to a single check) and the `risk` enum value (verify against the schema). The normaliser's `full`-confidence boundary (H-4) is stated and to be code-commented.

**3. Type consistency.** `firewall.restricts_inbound` is the only judged leaf (`bool`, or `absent`/`unsupported`); `firewall.enabled`/`default_policy.{input,forward}` are `setting`; `firewall.rules`/`raw_dumps` are `list<record>`; `firewall.backend`/`normalization_confidence` are `string`. `files.etc_hosts_{allow,deny}_lines` are `list<string>`, `files.etc_hosts_deny_all` is `bool`. U-28 references only `firewall.backend`, `firewall.restricts_inbound`, `files.etc_hosts_deny_all` — all registered.

**Risks (for the pre-flight scan and reviews):**
- **R-a (R220, load-bearing):** any firewall command failure that reaches `denied`/`error` breaks `collect-contract` (`.run.complete == true`) — the collector MUST self-classify to `unsupported`. The `TestFirewallNoCapabilityDegradesToUnsupported` test and the CI leg both guard this.
- **R-b (MANUAL machinery):** if `absent_means: manual` does not compose with `mechanisms`, U-28 could mis-resolve a partial-confidence host to PASS/FAIL/NA instead of MANUAL. Verify against eval.go and the `manual-partial-confidence` fixture; fall back to a single-mechanism control if needed.
- **R-c (over-claiming confidence):** a normaliser that claims `full` on a ruleset it half-understands produces a confident wrong PASS/FAIL. Keep the `full` boundary narrow (single clear input base-chain policy) and prefer `partial`→MANUAL.
- **R-d (false FAIL from tcp_wrappers absence):** a host restricting only via tcp_wrappers with no firewall must not FAIL — the `firewall.backend == none` mechanism checks `files.etc_hosts_deny_all`, and a missing hosts.deny is `ok:false` only when we could read (ENOENT), so a host with neither firewall nor tcp_wrappers deny is a true FAIL, while an unreadable state degrades honestly.
- **R-e (CI proves mostly the degrade path):** the non-privileged container legs see no netfilter → U-28 NOT_APPLICABLE; only `collect-root` (a real VM) and the `--privileged` rocky/alma legs exercise a real ruleset. The per-control fixtures are the proof of PASS/FAIL/MANUAL.
