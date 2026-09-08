# Stage 2G — Services and super-servers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol nine KISA 2026 "disable the unnecessary service" controls (U-34, U-36, U-38, U-39, U-41, U-42, U-43, U-44, U-58) by generalising the existing `services` collector from a two-service hard-coded map into a table-driven collector that reports install/active/unit-file/enabled/reachable facts for every logical service, and by extracting the telnet-only inetd/xinetd content scan into a shared super-server reader.

**Architecture:** All new facts live under `services.<logical-name>.*` produced by the existing `internal/collect/collectors/services.go` collector (no new collector). A logical-service *table* replaces the `logicalUnits` map and the hand-written `switch name` dispatch; one generic loop probes each service's systemd units, folds in a shared inetd/xinetd content scan, and derives an `enabled` boolean and (for services with fixed ports) a `reachable` boolean from `sockets.listening`. Each control ANDs `active == false` with `enabled == false` (plus `reachable == false` where a fixed port exists), following the merged `muster.service.telnet_disabled` template, with `absent_means: pass` so a stock host that has never had the service passes.

**Tech Stack:** Go 1.25.x, Linux-only collector behind build tags; `systemctl show -p LoadState,ActiveState,UnitFileState,SubState`; `/proc/net/{tcp,tcp6,udp,udp6}` via the existing `sockets` collector; YAML controls with the §6.3–6.6 clause grammar; fixtures as `controls/testdata/<id>/{pass,fail,na}-*.json`.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` (design + decision log D01–D28; §10.2 stage 2; §4 the four sides; D09 logical-service map; D10 two-home settings; D19 service normalisation). The plan argues from the spec; conflicts resolve against it. Scope brief with all source citations: `<session-scratchpad>/2g-scope-brief.md`.

## Global Constraints

- **Control set count: 35 → 44** (nine new `auto` controls; coverage becomes `auto 40, partial 4, manual 0`). Every count seam in Task 6 must land on 44.
- **Registry `schema_version` stays 1.** Every new key is a pure leaf/record addition (project convention C2; spec §5.7). Regenerate the facts golden with `go test ./internal/facts -run TestFactsSchemaGolden -update`; the diff must be additions only, each carrying `since: 1`.
- **Every fact leaf is an envelope; a status other than `ok` never yields PASS.** A registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means` (CLAUDE.md "Rules that are contracts").
- **`absent_means: pass` reason string is a hard CI match.** The non-root and container CI jobs allow `absent` evidence under a PASS **only** when the result `reason` starts with the literal `absent counts as pass` (`.github/workflows/ci.yml`). Do not invent a new reason string; reuse the engine path the telnet control already exercises.
- **No-systemd / masked-procfs degradation is mandatory and CI-enforced.** On a host with no `/run/systemd/system`, every `services.<n>.*` key this plan registers must be `unsupported`, never left `missing`. On a host whose `/proc/net/tcp` is masked, every `reachable` leaf must be `unsupported`, never `absent`. The `collect-contract` CI leg runs in a systemd-less read-only `ubuntu:24.04` container and asserts `.run.complete == true`; a `missing`/`error`/`denied` status on any registered `services.*` key there makes the run partial and fails the leg (the R220 lesson from 2F). This is Task 1's most important behaviour.
- **Same input, same bytes.** No `map` reaches the JSON/table renderer; iterate the service table and any map by sorted key (mirror the existing `slices.Sorted(maps.Keys(...))` in `declaredShowCommands`).
- **STIG/NIST references may cite only ids present in `docs/reference/stig/*.json`.** Lint rejects any other. Only three 2G items have an indexed id (see each task); the rest ship `references.kisa` only, exactly as `telnet_disabled.yaml` does. Do **not** run `make refindex` or add STIG content in this plan.
- **Never copy KISA/CIS text.** Control `description_*`/`title_*` are muster's own words. `references.kisa` is edition-keyed id lists only.
- **Fixtures are `synthetic: true`** (or from public images), never from a real host; never commit a snapshot captured from the lab host (spec D02).
- **U-52 polarity note (load-bearing):** the 2021 id for U-52 (`U-60`) describes the *opposite* polarity (2021 asked "is SSH used", 2026 asks "is Telnet open"). U-52 is already merged and out of scope; do not "fix" its references. Every 2G item's 2021 id is a clean 1:1 renumber (see per-task `references.kisa`), verified against `docs/reference/kisa/kisa_mapping.json`.
- **Boundary rulings (controller, folded into this plan):**
  - **U-54 (unencrypted FTP) is NOT in 2G** — it is 2L (FTP). The `stage2-analysis.md` plan table listing it under 2G is a transcription slip.
  - **U-35 (anonymous shared-service access) is NOT in 2G** — it is 2L (vsftpd-shaped).
  - **NFS access control (U-40), SNMP version/community/ACL (U-59/60/61), and patch hygiene stay in 2J.** 2G publishes only the service-state evidence 2J depends on: `services.nfs_server.installed` and `services.snmp.installed` (spec 2J dependency line).
  - **RPC/NIS `reachable` is not judged.** `rpcbind`, `ypserv`/`ypbind`, `autofs` bind dynamic ports via the portmapper that `sockets.listening` (fixed `/proc/net` ports) cannot see; their controls judge `active`/`enabled` only. Do not fabricate a `reachable` leaf for a service with no fixed port — omit the key entirely for those services.

---

## File Structure

**Collector (Task 1 & 2) — modify:**
- `internal/collect/collectors/services.go` — replace `logicalUnits map[string][]unitRef` and the `switch name` dispatch with a `[]logicalService` table and one generic per-service loop; parse `UnitFileState` (already on the wire; drop the `SubState` parse per R235); derive `enabled`; generalise `hasNonLoopbackTCPPort` to proto+multi-port; iterate the table in the no-systemd degrade path.
- `internal/collect/collectors/services_super.go` — **new** file: the shared inetd/xinetd content reader extracted and generalised from `telnetFromLegacy` (a super-server entry lookup by service-name field / server-program suffix for a set of names).
- `internal/collect/collectors/services_test.go` (or the existing `collectors_test.go` block for services) — table-driven collector tests incl. the no-systemd and masked-procfs degrade assertions.
- `internal/facts/registry.yaml` + `internal/facts/testdata/schema_golden.json` (or the golden path the `-update` flag writes) — new `services.<n>.*` keys.

**Controls (Tasks 3–5) — create** under `controls/service/` with fixtures under `controls/testdata/<id>/`:
- `finger_disabled.yaml` (U-34), `rservices_disabled.yaml` (U-36), `dos_services_disabled.yaml` (U-38)
- `nfs_server_disabled.yaml` (U-39), `automount_disabled.yaml` (U-41), `rpcbind_disabled.yaml` (U-42), `nis_disabled.yaml` (U-43)
- `tftp_talk_disabled.yaml` (U-44), `snmp_disabled.yaml` (U-58)

**Reconciliation (Task 6) — modify:**
- `cmd/muster/controls_test.go` (two `ok: 35 controls` → `ok: 44 controls`), `cmd/muster/e2e_test.go` (two control-id→status maps + the two spelled-out count comments "thirty-five"→"forty-four" and "thirty-four"→"forty-three", R230), `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `docs/reference/coverage.md` (regenerated), `README.md`/`README.ko.md` (only if a service-coverage sentence exists — no count sentence to bump today, R230).

---

## Interfaces (produced by this plan, consumed by later tasks and 2J)

New fact keys (collector `services`, all `since: 1`), per logical service `<n>`:
- `services.<n>.installed` — `bool` — a unit or super-server entry proving the software is present.
- `services.<n>.active` — `bool` — running now (systemd `ActiveState=active`, or a live inetd entry, or a non-loopback listener).
- `services.<n>.unit_file_state` — `string` — the systemd `UnitFileState` of the first unit in list order whose `LoadState != "not-found"` (R222); `"not-found"` when no unit is found (R231, not `"absent"`). Values: `enabled`, `disabled`, `masked`, `static`, `indirect`, `generated`, `alias`, `enabled-runtime`, `not-found`. Evidence only.
- `services.<n>.enabled` — `bool` — **derived**: will start at boot / on socket activation, or is enabled in inetd/xinetd. Judged leaf.
- `services.<n>.reachable` — `bool` — a non-loopback listening socket exists on one of `<n>`'s fixed ports. **Only registered for services with fixed ports** (finger, rservices, dos_services, nfs_server, rpcbind, tftp, talk, snmp, telnet). Absent for automount, nis, ssh.

Logical services introduced (fact segment → nature): `finger`, `rservices` (rsh/rlogin/rexec), `dos_services` (echo/discard/daytime/chargen), `nfs_server`, `automount`, `rpcbind`, `nis` (ypserv/ypbind/…), `tftp`, `talk` (talk/ntalk), `snmp`. Existing `ssh` and `telnet` gain the new leaves (`active`, `unit_file_state`, `enabled` for both; `telnet` keeps `reachable`).

For 2J: `services.nfs_server.installed`, `services.snmp.installed` are guaranteed present (or `unsupported` with reason on a no-systemd host).

---

### Task 1: Table-driven services collector core

**Files:**
- Modify: `internal/collect/collectors/services.go`
- Modify: `internal/facts/registry.yaml`
- Test: `internal/collect/collectors/services_test.go` (create if the services tests currently live inline in `collectors_test.go`; either is acceptable — keep one home for them)

**Interfaces:**
- Consumes: `collect.Access` (`Stat`, `Run`), `collect.Unsupported`, `facts.Builder`, the `sockets` collector's `listeningSockets(a)` and `socketReadEnvelope(err)` (both in `sockets.go`), `procNetPaths()`.
- Produces: the `logicalService`/`portSpec` types and the `var services []logicalService` table; `services.<n>.{installed,active,unit_file_state,enabled}` for all, `.reachable` for fixed-port services.

- [ ] **Step 1: Write the failing test — the table drives every service, and the no-systemd path degrades every key**

Add to the services test block in `collectors_test.go`. **Ruling R226 — use the REAL test helpers** (the ones the plan drafted, `newFakeAccess`/`showKey`/`cmdOut`/`reg(t)`/`snap.Lookup`/`mustBool`, do not exist): `servicesAccess(files, cmds)` (collectors_test.go:1700, pre-seeds `/run/systemd/system`), `&fsAccess{}` for the no-systemd case, `showLine(unit)` (1682), `cmdResult{file: "<testdata name>"}` (canned stdout comes from a testdata FILE), `build(t, "services", a)` (212), `env(t, b, key)` (243, returns `facts.Envelope`), `b.Keys("services")` and `b.Worst("services")` (facts.go:118,162), and enumerate registry keys via `facts.LoadRegistry()` then `reg.Keys[i].Collector == "services"` / `.Key` (registry.go:22-36). `readErrorEnv(p string, err error)` lives in pam_derive.go:63.

**Ruling R226 — rebuild `allUnitsNotFound()` table-driven FIRST.** `allUnitsNotFound()` (collectors_test.go:1688-1698) is a hard-coded 8-unit list; `fsAccess.Run` returns `os.ErrNotExist` for any unmapped command, so once the table grows every new unit turns into an `Err` and every existing services test errors. Rebuild it from the table before adding the new tests:

```go
func allUnitsNotFound() map[string]cmdResult {
	out := map[string]cmdResult{}
	for _, svc := range services {
		for _, u := range svc.units {
			out[showLine(u.name)] = cmdResult{file: "systemctl.notfound"}
		}
	}
	return out
}
```

**Ruling R226 — new testdata files** the tests below need: `internal/collect/collectors/testdata/systemctl.enabled.inactive` (`LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\nSubState=dead\n`), `systemctl.alias.inactive` (`UnitFileState=alias`, R228), `systemctl.masked` (`LoadState=masked\nActiveState=inactive\nUnitFileState=masked\nSubState=dead\n`, R231), and `proc_net_udp6_snmp` (a non-loopback `::` listener on port 161 / `0x00A1`, R221).

```go
func TestServicesTableEmitsAllLeavesPerService(t *testing.T) {
	// finger.socket enabled but inactive → enabled==true, active==false.
	cmds := allUnitsNotFound()
	cmds[showLine("finger.socket")] = cmdResult{file: "systemctl.enabled.inactive"}
	b := build(t, "services", servicesAccess(nil, cmds))
	if e := env(t, b, "services.finger.active"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("finger.active: %+v", e)
	}
	if e := env(t, b, "services.finger.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("finger.enabled (enabled-but-stopped is still enabled): %+v", e)
	}
	if e := env(t, b, "services.finger.unit_file_state"); e.Value != "enabled" {
		t.Errorf("finger.unit_file_state: %+v", e)
	}
	if e := env(t, b, "services.finger.installed"); e.Value != true {
		t.Errorf("finger.installed: %+v", e)
	}
}

// Ruling R222: enabled is the OR over every probed unit, not the canonical one.
func TestServicesEnabledOredAcrossUnits(t *testing.T) {
	// NIS client: canonical ypserv.service not-found, sibling ypbind.service
	// enabled-but-stopped ⇒ enabled==true (catches the NIS-client false-PASS class).
	cmds := allUnitsNotFound()
	cmds[showLine("ypbind.service")] = cmdResult{file: "systemctl.enabled.inactive"}
	b := build(t, "services", servicesAccess(nil, cmds))
	if e := env(t, b, "services.nis.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("nis.enabled must OR across units: %+v", e)
	}
	if e := env(t, b, "services.nis.active"); e.Value != false {
		t.Errorf("nis.active: %+v", e)
	}
}

// Ruling R228: alias must not count as enabled.
func TestServicesAliasIsNotEnabled(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("nfs-kernel-server.service")] = cmdResult{file: "systemctl.alias.inactive"}
	b := build(t, "services", servicesAccess(nil, cmds))
	if e := env(t, b, "services.nfs_server.enabled"); e.Value != false {
		t.Errorf("alias must not count as enabled: %+v", e)
	}
}

// Ruling R231: masked IS installed, but not enabled and not active.
func TestServicesMaskedCountsAsInstalled(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("snmpd.service")] = cmdResult{file: "systemctl.masked"}
	b := build(t, "services", servicesAccess(nil, cmds))
	if e := env(t, b, "services.snmp.installed"); e.Value != true {
		t.Errorf("masked IS installed: %+v", e)
	}
	if e := env(t, b, "services.snmp.enabled"); e.Value != false {
		t.Errorf("masked is not enabled: %+v", e)
	}
	if e := env(t, b, "services.snmp.active"); e.Value != false {
		t.Errorf("masked is not active: %+v", e)
	}
}

// Ruling R221: a ::-bound daemon appears only in udp6/tcp6 (proto prefix match).
func TestServicesReachableMatchesIPv6Listener(t *testing.T) {
	a := servicesAccess(map[string]string{"/proc/self/net/udp6": "proc_net_udp6_snmp"}, allUnitsNotFound())
	b := build(t, "services", a)
	if e := env(t, b, "services.snmp.reachable"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("::-bound port 161 must be reachable: %+v", e)
	}
}

func TestServicesNoSystemdDegradesEveryRegisteredKey(t *testing.T) {
	b := build(t, "services", &fsAccess{}) // no /run/systemd/system
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	// Every services.* key the registry declares must be present and unsupported,
	// so the run stays complete on a systemd-less container (R220).
	for _, k := range reg.Keys {
		if k.Collector != "services" {
			continue
		}
		if e := env(t, b, k.Key); e.Status != facts.StatusUnsupported {
			t.Errorf("%s = %s, want unsupported on no-systemd host", k.Key, e.Status)
		}
	}
	if got := b.Worst("services"); got != facts.StatusOK {
		t.Errorf(`Worst("services") = %s, want ok (unsupported ranks ok, run stays complete)`, got)
	}
}
```

The intent — *every registered `services.*` key is `unsupported`, and `Worst("services")==ok`* — is the assertion that must hold. Mirror `TestCronTimersInventoryAndFailure`'s `Worst(...)==ok` shape from 2F.

- [ ] **Step 2: Run the tests to confirm they fail**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run 'TestServicesTable|TestServicesNoSystemd'`
Expected: FAIL — new leaves/keys not produced; degrade path only writes the old 4-key list.

- [ ] **Step 3: Introduce the logical-service table**

Replace `var logicalUnits map[string][]unitRef` (lines ~52–65) with:

```go
type portSpec struct {
	proto string // "tcp" or "udp"
	port  int
}

type logicalService struct {
	name       string     // fact segment under services.
	units      []unitRef  // systemd units; provesInstall keeps its established meaning (R223), NOT "canonical for unit_file_state"
	inetdNames []string   // inetd.conf field-0 names / xinetd.d service names (super-server hosting)
	servers    []string   // real server-program basenames to match against the inetd/xinetd server field (R233)
	ports      []portSpec // fixed listening ports for the reachable leaf; empty ⇒ no reachable leaf
}

// Order is the emission order; keep it stable (same input, same bytes).
//
// Ruling R223: reuse the existing ssh and telnet unitRef lists UNCHANGED —
// verbatim from services.go:52-65 `logicalUnits` (ssh keeps ssh.service /
// sshd.service / ssh.socket; telnet keeps telnet.socket / telnet.service /
// telnetd.service plus the inetd.service / xinetd.service entries with their
// CURRENT provesInstall flags per R63). Only APPEND the new logical services.
// `provesInstall` keeps its established meaning (proves-installed vs the
// "systemd did not answer" distinction); it is NOT "the canonical unit for
// unit_file_state" (that is R222's first-loaded rule). Every genuinely new
// real unit (finger/rservices/dos/nfs/automount/rpcbind/nis/tftp/talk/snmp)
// gets provesInstall: true.
var services = []logicalService{
	// ssh and telnet: verbatim from services.go logicalUnits (do not change the unit lists or flags).
	{name: "ssh", units: []unitRef{{"ssh.service", true}, {"sshd.service", true}, {"ssh.socket", true}}},
	{name: "telnet", units: []unitRef{{"telnet.socket", true}, {"telnet.service", true}, {"telnetd.service", true}, {"inetd.service", false}, {"xinetd.service", false}}, inetdNames: []string{"telnet"}, servers: []string{"telnetd", "in.telnetd"}, ports: []portSpec{{"tcp", 23}}},
	// New logical services (all real units provesInstall: true; R234/R246 give tftp both the RHEL 9 tftp.service and the socket-activated Debian atftpd.socket).
	{name: "finger", units: []unitRef{{"finger.socket", true}, {"fingerd.service", true}}, inetdNames: []string{"finger"}, servers: []string{"in.fingerd"}, ports: []portSpec{{"tcp", 79}}},
	{name: "rservices", units: []unitRef{{"rsh.socket", true}, {"rlogin.socket", true}, {"rexec.socket", true}}, inetdNames: []string{"shell", "login", "exec"}, servers: []string{"in.rshd", "in.rlogind", "in.rexecd"}, ports: []portSpec{{"tcp", 514}, {"tcp", 513}, {"tcp", 512}}},
	{name: "dos_services", units: []unitRef{{"echo.socket", true}, {"discard.socket", true}, {"daytime.socket", true}, {"chargen.socket", true}}, inetdNames: []string{"echo", "discard", "daytime", "chargen"}, ports: []portSpec{{"tcp", 7}, {"udp", 7}, {"tcp", 9}, {"udp", 9}, {"tcp", 13}, {"udp", 13}, {"tcp", 19}, {"udp", 19}}},
	{name: "nfs_server", units: []unitRef{{"nfs-server.service", true}, {"nfs-kernel-server.service", true}}, ports: []portSpec{{"tcp", 2049}, {"udp", 2049}}},
	{name: "automount", units: []unitRef{{"autofs.service", true}}},
	{name: "rpcbind", units: []unitRef{{"rpcbind.service", true}, {"rpcbind.socket", true}}, ports: []portSpec{{"tcp", 111}, {"udp", 111}}},
	{name: "nis", units: []unitRef{{"ypserv.service", true}, {"ypbind.service", true}, {"ypxfrd.service", true}, {"yppasswdd.service", true}}},
	{name: "tftp", units: []unitRef{{"tftp.socket", true}, {"tftp.service", true}, {"tftpd.service", true}, {"tftpd-hpa.service", true}, {"atftpd.socket", true}, {"atftpd.service", true}}, inetdNames: []string{"tftp"}, servers: []string{"in.tftpd", "atftpd"}, ports: []portSpec{{"udp", 69}}},
	{name: "talk", units: []unitRef{{"talk.socket", true}, {"ntalk.socket", true}}, inetdNames: []string{"talk", "ntalk"}, servers: []string{"in.talkd", "in.ntalkd"}, ports: []portSpec{{"udp", 517}, {"udp", 518}}},
	{name: "snmp", units: []unitRef{{"snmpd.service", true}}, ports: []portSpec{{"udp", 161}}},
}
```

**Ruling R234:** all systemd unit names in this table must be verified against the real CI-image / lab-host units before the collector is considered done — a wrong unit name silently reads as not-installed → false PASS. The implementer runs the collector on the lab host and checks the real unit names for nfs/rpcbind/snmp/nis/tftp/autofs.

`declaredShowCommands()` must now iterate `services` (flattening `units`) instead of `logicalUnits`; keep the sorted-key determinism (sort the flattened unit names).

- [ ] **Step 4: Parse UnitFileState and derive `enabled`**

`showValues` already receives `UnitFileState` on the wire (the command asks for it). Extend it to return `UnitFileState`. **Ruling R235:** do NOT parse `SubState` — nothing reads it; the show command may still request it, only the parsing is dropped. Keep `active = (ActiveState == "active")` deliberately (unchanged from today; avoids regressing ssh/telnet).

```go
// enabledFromUnitFile reports whether a unit's UnitFileState means "will start
// at boot or on socket activation" (Ruling R228).
//   enabled, enabled-runtime → true
//   indirect                 → active (a socket unit that is actually listening)
//   generated                → active (sysv-generator stamps every init.d script
//                              "generated" whether or not an rcN.d/S* link exists)
//   alias                    → false (e.g. Ubuntu nfs-kernel-server.service reports
//                              "alias" regardless of the target's enable state; the
//                              target unit is in the same list and answers for itself)
//   static, disabled, masked, bad, "", not-found → false
func enabledFromUnitFile(state string, active bool) bool {
	switch state {
	case "enabled", "enabled-runtime":
		return true
	case "indirect", "generated":
		return active
	default: // alias, static, disabled, masked, bad, "", not-found
		return false
	}
}
```

**Ruling R222 — `enabled` is the OR over EVERY probed unit** of the service: `enabled ← OR_{u in svc.units} enabledFromUnitFile(state_u, active_u)`, then OR'd with the super-server verdict (Task 2). It is NOT derived from the canonical/provesInstall unit alone (that class of bug false-PASSes the NIS-client / tftpd-hpa / rlogin.socket enabled-but-stopped sibling).

**Ruling R222 — `unit_file_state` (evidence only)** = the `UnitFileState` of the FIRST unit in list order whose `LoadState != "not-found"`; **Ruling R231:** default `"not-found"` (systemd's own `LoadState` word) when no unit is found — NOT `"absent"`, which collides with the envelope-status vocabulary.

**Ruling R231 — `installed` rule change:** `installed ← LoadState != "not-found"` (OR super-server entry OR reachable), which now counts `masked` as installed (differs from today's `== "loaded"`). This is intended — a masked unit IS installed. Add a `masked` collector fixture/test: `LoadState=masked`, `UnitFileState=masked` ⇒ `installed=true, enabled=false, active=false`.

- [ ] **Step 5: Generalise the port helper**

Replace `hasNonLoopbackTCPPort(list []any, port int) bool` with:

```go
// hasNonLoopbackPort reports whether any listening socket in the sockets.listening
// list matches one of the given proto+port pairs on a non-loopback address.
func hasNonLoopbackPort(list []any, ports []portSpec) bool {
	for _, ps := range ports {
		for _, row := range list {
			m, ok := row.(map[string]any)
			if !ok {
				continue
			}
			// Ruling R221: compare proto by PREFIX, not equality — sockets.listening
			// rows carry "tcp"/"tcp6"/"udp"/"udp6" (sockets.go:46-54); a ::-bound
			// daemon (snmpd/rpcbind/nfsd/fingerd) appears only in tcp6/udp6.
			if strings.HasPrefix(asString(m["proto"]), ps.proto) && asInt(m["port"]) == ps.port && !asBool(m["loopback"]) {
				return true
			}
		}
	}
	return false
}
```

Use the record field names actually present in `sockets.listening` (grep `sockets.go` `parseProcNet` for the exact keys — the scope brief lists `proto, addr, port, inode, loopback`). Keep any existing `asString`/`asInt` helpers; add minimal ones if absent. **Ruling R221:** `port` is a Go `int` in this record path (`asInt` returns `int`, not `float64`).

- [ ] **Step 6: One generic per-service loop + no-systemd degrade over the table**

Replace the `switch name { case "ssh": …; case "telnet": … }` dispatch with a loop over `services`. **Ruling R232:** call `listeningSockets(a)` ONCE before the per-service loop (not inside it — otherwise up to 48 procfs reads and 12 chances to disagree with `sockets.listening`); capture its error/truncation and file `socketReadEnvelope(err)` / the truncation `ErrorEnv` (services.go:284-295) on EVERY fixed-port service's `reachable` leaf. For each service:
- `installed` ← any unit found (LoadState ≠ "not-found", so `masked` counts — R231) OR a super-server entry (Task 2) OR (`reachable` true).
- `active` ← systemd `ActiveState=active` on any unit, OR a live super-server entry, OR (for a fixed-port service) `reachable`.
- `unit_file_state` ← first unit in list order whose `LoadState != "not-found"` (R222); `"not-found"` when no unit is found (R231). Evidence only.
- `enabled` ← OR over EVERY probed unit's `enabledFromUnitFile(state_u, active_u)` (R222), OR the super-server entry is enabled (Task 2 folds in).
- `reachable` (fixed-port services only) ← `hasNonLoopbackPort(t.listening, svc.ports)` from the single pre-loop `listeningSockets(a)`, and `socketReadEnvelope`/`unsupported` when `/proc/net` is masked (reuse the telnet path at services.go line ~284/290).

**Ruling R224 — a complete sweep never emits `absent` on a judged leaf.** When the unit sweep is COMPLETE (systemd answered, nothing loaded), every JUDGED leaf (`active`, `enabled`, `reachable`) is `ok:false` — NOT `absent`. Rationale: spec §6.5 step 8 (eval.go:187-197) screens the whole control on the first `absent` fact BEFORE clauses run, so an `absent` leaf on a multi-fact control (U-44 tftp+talk, U-43 service+nsswitch) would PASS via `absent_means` even when a sibling leaf proves a live service. `unit_file_state` (evidence) may still be `"not-found"`. Keep `absent_means: pass` on the controls as a belt-and-braces default only (for the incomplete-sweep / never-registered case).

The no-systemd branch must iterate the table and emit `unsupported` for **every** leaf the service registers (including `reachable` where applicable), replacing the hard-coded 4-key list. **Ruling R239:** this branch deliberately pre-empts super-server and socket evidence — everything is `unsupported`, even the `reachable` that `/proc/net` could answer — consistent with today's telnet behaviour and required by the collect-contract leg:

```go
if _, err := a.Stat(systemdMarker); err != nil {
	reason := "no systemd on this host or inside this container"
	for _, svc := range services {
		b.Set("services."+svc.name+".installed", collect.Unsupported(reason))
		b.Set("services."+svc.name+".active", collect.Unsupported(reason))
		b.Set("services."+svc.name+".unit_file_state", collect.Unsupported(reason))
		b.Set("services."+svc.name+".enabled", collect.Unsupported(reason))
		if len(svc.ports) > 0 {
			b.Set("services."+svc.name+".reachable", collect.Unsupported(reason))
		}
	}
	return nil
}
```

Keep `setSSH`/`setTelnet` only if they still add value; otherwise delete them (the generic loop supersedes them) and confirm the suite goes red then green.

- [ ] **Step 7: Register the new keys**

Add to `internal/facts/registry.yaml`, for each logical service, the leaves it emits. `installed`/`active`/`enabled`/`reachable` are `type: bool`; `unit_file_state` is `type: string`. `ssh` gains `active`, `unit_file_state`, `enabled` (no `reachable`); `telnet` gains `active`, `unit_file_state`, `enabled` (keeps `reachable`). Keep entries grouped and sorted the way the file already groups `services.*`.

**Ruling R229:** do NOT set `subject_kind` on the new scalar keys — registry.go:75-77 rejects it on non-`list<` types (`LoadRegistry` fails). Each new key carries exactly: `type`, `description`, `since: 1`, `sensitivity: public`, `collector: services` — nothing else.

- [ ] **Step 8: Regenerate the facts golden and run gates**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/facts -run TestFactsSchemaGolden -update` then review the diff — additions only, each `since: 1`, no `schema_version` change.
Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ ./internal/facts` (all green), `gofmt -l`, `GOOS=linux GOARCH=amd64 go vet ./...`, and `GOOS=linux staticcheck ./internal/collect/... ./internal/facts/...`.

- [ ] **Step 9: Commit**

```bash
git add internal/collect/collectors/services.go internal/collect/collectors/services_test.go internal/facts/registry.yaml internal/facts/testdata/schema_golden.json
git commit -m "Generalise the services collector to a logical-service table"
```

---

### Task 2: Shared super-server (inetd/xinetd) reader

**Files:**
- Create: `internal/collect/collectors/services_super.go`
- Modify: `internal/collect/collectors/services.go` (call the shared reader from the per-service loop; delete `telnetFromLegacy` once its callers use the generic reader)
- Test: `internal/collect/collectors/services_test.go`

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Glob`, `Run`), `inetdConf`, `xinetdGlob` (existing consts in `services.go`).
- Produces: a once-per-run super-server read and a per-service lookup. **Ruling R227:** `readSuperServers(a)` parses `inetdConf` and the `xinetdGlob` fragments ONCE per run and probes the super-server host units ONCE per run — `openbsd-inetd.service`, `inetutils-inetd.service`, `inetd.service`, `xinetd.service` (all `provesInstall:false`; Debian/Ubuntu have no `inetd.service`, only the first two). The per-service lookup `(s superServers) match(names, servers []string) (installed, enabled, active, found bool, ev *facts.Envelope)` returns: `installed` unconditionally when an entry is present; `enabled` only when its host super-server is enabled (or its state is unknown/unprobed); `active` only when the host super-server is active. **Ruling R233:** match by inetd NAME plus the explicit `servers []string` basenames against the server-program field — no `<name>d`/`in.<name>d` suffix heuristic.

- [ ] **Step 1: Write the failing test**

**Ruling R226 — use the real helpers.** `fsAccess.files` maps a host path to a **testdata FILE NAME** (collectors_test.go:38), not raw content, so add testdata files: `inetd.conf.rsh` (`shell\tstream\ttcp\tnowait\troot\t/usr/sbin/in.rshd\tin.rshd\n`) and `inetd.conf.finger.commented` (`#finger\tstream\ttcp\tnowait\tnobody\t/usr/sbin/in.fingerd\n`). `systemctl.loaded.inactive` (UnitFileState=disabled) already exists for the host-stopped case.

```go
func TestSuperServerReaderMatchesByNameAndServer(t *testing.T) {
	// openbsd-inetd running+enabled; a live 'shell' entry ⇒ r-services enabled+active.
	cmds := allUnitsNotFound()
	cmds[showLine("openbsd-inetd.service")] = cmdResult{file: "systemctl.loaded.active"}
	s := readSuperServers(servicesAccess(map[string]string{inetdConf: "inetd.conf.rsh"}, cmds))
	installed, enabled, active, found, ev := s.match([]string{"shell", "login", "exec"}, []string{"in.rshd", "in.rlogind", "in.rexecd"})
	if ev != nil {
		t.Fatalf("unexpected envelope: %+v", ev)
	}
	if !found || !installed || !enabled || !active {
		t.Fatalf("live shell entry, inetd running: found=%v installed=%v enabled=%v active=%v, want all true", found, installed, enabled, active)
	}
}

// Ruling R227: an entry does not become enabled/active when its host super-server is disabled/stopped.
func TestSuperServerEntryGatedByHostState(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("openbsd-inetd.service")] = cmdResult{file: "systemctl.loaded.inactive"} // installed, disabled, stopped
	s := readSuperServers(servicesAccess(map[string]string{inetdConf: "inetd.conf.rsh"}, cmds))
	installed, enabled, active, found, _ := s.match([]string{"shell"}, []string{"in.rshd"})
	if !found || !installed {
		t.Fatalf("entry present: found=%v installed=%v", found, installed)
	}
	if enabled || active {
		t.Errorf("host inetd disabled/stopped ⇒ entry not enabled/active: enabled=%v active=%v", enabled, active)
	}
}

func TestSuperServerReaderIgnoresCommentsAndOtherNames(t *testing.T) {
	s := readSuperServers(servicesAccess(map[string]string{inetdConf: "inetd.conf.finger.commented"}, allUnitsNotFound()))
	installed, enabled, _, found, ev := s.match([]string{"finger"}, []string{"in.fingerd"})
	if ev != nil {
		t.Fatal(ev)
	}
	if found || installed || enabled {
		t.Fatalf("commented finger: found=%v installed=%v enabled=%v, want false", found, installed, enabled)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run TestSuperServer`
Expected: FAIL — `superServerState` undefined.

- [ ] **Step 3: Implement the shared reader**

Generalise the logic in `telnetFromLegacy` (services.go lines ~307–355) into a once-per-run `readSuperServers(a)`: read `inetdConf`, glob `xinetdGlob`, and probe the four super-server host units. Parse each source into `{name, serverBasename, entryEnabled}` entries.

- `/etc/inetd.conf`: split each non-comment line on whitespace; field 0 is the service name; field 5 (`inetdServerField`) is the server program. A `disable = yes` is not expressible in inetd.conf, so an uncommented line is an **entry present** (`entryEnabled = true` at the file level).
- xinetd fragments: a `service <name>` block is an entry; `entryEnabled = false` when it contains `disable = yes`.
- **Ruling R233 — matching:** `(s superServers) match(names, servers)` matches an entry when `entry.name` equals any requested `name`, OR `entry.serverBasename` equals any requested `servers` basename. Do NOT use the `in.<name>d`/`<name>d` suffix heuristic — it does not fit r-services (`in.rshd` ≠ `shelld`) and only adds false positives. With tcpd wrapping, field 0 is still the service name, so name matching is complete for inetd.conf.
- **Ruling R227 — host gating (the promotion to judged leaves):** a matched entry contributes `installed` unconditionally; `enabled` only when the host super-server is enabled (via `enabledFromUnitFile` over the four host units) OR the host state is unknown/unprobed; `active` only when a host super-server is `ActiveState=active`. A stale `/etc/inetd.conf` on a host whose inetd is stopped/disabled must not FAIL.
- **Ruling R237 — over-strict note (comment only, no code):** note in the reader's comment that xinetd global `defaults { disabled = … }` / `enabled = …` in `/etc/xinetd.conf` are NOT read (a fragment with `disable = no` could still be globally disabled). This is over-strict, not a false PASS; do not add code for it now.

Return a read-error envelope (`readErrorEnv(p, err)`, pam_derive.go:63) when a file that exists cannot be read, mirroring the honest-degradation rule (a config that exists but is unreadable is not "absent"); a missing `inetd.conf`/no xinetd fragments ⇒ `found=false`, no envelope.

- [ ] **Step 4: Wire it into the per-service loop and delete `telnetFromLegacy`**

Call `readSuperServers(a)` ONCE before the per-service loop (alongside the single `listeningSockets(a)` from R232). In the loop, for a service with `inetdNames`/`servers`, call `s.match(svc.inetdNames, svc.servers)`; OR its `installed`/`enabled`/`active` into the systemd-derived values; propagate any envelope onto that service's `enabled`/`active` leaves (a read error is not a silent pass). Delete `telnetFromLegacy`/`inetdTelnet`/`xinetdTelnet`.

**Ruling R227 — the reader now always runs, so `TestServicesSkipsLegacyFilesWhenSystemdProvesTelnet` (collectors_test.go:1955) must be replaced/rewritten.** That test asserts `/etc/inetd.conf` is NOT read once a telnet unit loaded — which conflicts with reading the config once per run for every `inetdNames` service. Rewrite it (and `TestServicesReadsLegacyFilesWhenSystemdDidNotProveTelnet`) so it no longer asserts on `a.reads` for `inetd.conf`; instead assert that telnet's **judged** result (`installed`/`enabled`/`active`) is unchanged when systemd proves telnet — systemd evidence dominates when present. Record this test change as a ledger ruling in the ledger's Task 2 entry. Telnet's behaviour is preserved by the telnet fixtures + e2e (Task 6).

- [ ] **Step 5: Run tests + gates**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/` (green), `gofmt -l`, `go vet`, `staticcheck`.

- [ ] **Step 6: Commit**

```bash
git add internal/collect/collectors/services_super.go internal/collect/collectors/services.go internal/collect/collectors/services_test.go
git commit -m "Extract a shared inetd/xinetd super-server reader"
```

---

### Task 3: Super-server controls — U-34 finger, U-36 r-services, U-38 DoS-prone

**Files:**
- Create: `controls/service/finger_disabled.yaml`, `controls/service/rservices_disabled.yaml`, `controls/service/dos_services_disabled.yaml`
- Create fixtures under `controls/testdata/muster.service.{finger,rservices,dos_services}_disabled/`
- Test: driven by the existing control-fixture harness (`internal/controls` + `cmd/muster` e2e); no new Go test file.

**Interfaces:**
- Consumes: `services.{finger,rservices,dos_services}.{active,enabled,reachable}` from Tasks 1–2.

- [ ] **Step 1: Write the finger control (template for all three)**

`controls/service/finger_disabled.yaml`:

```yaml
id: muster.service.finger_disabled
title_en: The finger service is not enabled or reachable
title_ko: finger 서비스가 활성화되어 있지 않다
description_en: No finger server may be active, enabled at boot, hosted by inetd/xinetd, or listening on a non-loopback address. A host without any finger server passes.
description_ko: finger 서버가 활성이거나 부팅 시 시작되도록 설정되어 있거나 inetd/xinetd 로 구동되거나 루프백 외 주소에서 대기하면 안 됩니다. finger 서버가 전혀 없는 호스트는 통과합니다.
category: service
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-34"], "2021": ["U-19"] }
requires_facts: ">=1"
absent_means: pass
checks:
  - { fact: services.finger.active, op: eq, expected: false }
  - { fact: services.finger.enabled, op: eq, expected: false }
  - { fact: services.finger.reachable, op: eq, expected: false }
remediation:
  text_en: Disable and mask the finger service or remove the finger server package, and remove any inetd/xinetd finger entry.
  text_ko: finger 서비스를 비활성화·mask 하거나 finger 서버 패키지를 제거하고, inetd/xinetd 의 finger 항목을 제거합니다.
  risk: restart_service
  idempotent: true
  script: systemctl disable --now finger.socket 2>/dev/null; systemctl mask finger.socket 2>/dev/null; true
  rollback: systemctl unmask finger.socket 2>/dev/null; true
decision: D19
```

- [ ] **Step 2: Write U-36 r-services and U-38 DoS-prone from the same template**

`rservices_disabled.yaml` (`id: muster.service.rservices_disabled`, importance 상, kisa `{ "2026": ["U-36"], "2021": ["U-21"] }`, checks on `services.rservices.{active,enabled,reachable}`). This one **carries a STIG reference** (indexed):

```yaml
references:
  kisa: { "2026": ["U-36"], "2021": ["U-21"] }
  stig:
    - { benchmark: ubuntu2204, version: "V2R9", id: "UBTU-22-215030" }
    - { benchmark: ubuntu2404, version: "V1R6", id: "UBTU-24-100040" }
```

`dos_services_disabled.yaml` (`id: muster.service.dos_services_disabled`, importance 상, kisa `{ "2026": ["U-38"], "2021": ["U-23"] }`, checks on `services.dos_services.{active,enabled,reachable}`; description names echo/discard/daytime/chargen). No STIG id exists — `references.kisa` only.

- [ ] **Step 3: Fixtures — one `pass-absent`, one `pass-disabled`, one `fail-*`, one `na-container` per control**

Mirror the telnet fixtures exactly (`synthetic: true`, envelope-per-leaf). For each control produce:
- `pass-absent.json` — every judged leaf `absent` (service never present).
- `pass-disabled.json` — `active:false`, `enabled:false`, `reachable:false` all `ok`.
- `fail-enabled.json` — `enabled:true` (`ok`) with `active:false` (the enabled-but-stopped case the analysis called out as a must-FAIL), the others `ok:false`.
- For finger/rservices/dos, also `fail-reachable.json` — `reachable:true` (`ok`) with a `source`.
- `na-container.json` — every judged leaf `unsupported` with `run.env.container` set (⇒ NOT_APPLICABLE), copying the telnet `na-container.json` shape.

Example `controls/testdata/muster.service.finger_disabled/fail-enabled.json`:

```json
{"synthetic": true, "schema_version":1,"run":{},"facts":{"services":{"finger":{"active":{"status":"ok","value":false},"enabled":{"status":"ok","value":true,"source":{"kind":"command","cmd":"/usr/bin/systemctl show finger.socket"}},"reachable":{"status":"ok","value":false}}}}}
```

- [ ] **Step 4: Lint + evaluate**

Run: `go run ./cmd/muster controls lint --references docs/reference` → the new ids resolve, STIG ids accepted, fixture pairs present.
Run: `go test ./internal/controls/...` → every fixture yields its prefix's status.

- [ ] **Step 5: Commit**

```bash
git add controls/service/finger_disabled.yaml controls/service/rservices_disabled.yaml controls/service/dos_services_disabled.yaml controls/testdata/muster.service.finger_disabled controls/testdata/muster.service.rservices_disabled controls/testdata/muster.service.dos_services_disabled
git commit -m "Add the finger, r-services and DoS-prone service controls"
```

---

### Task 4: RPC-family controls — U-39 NFS, U-41 automountd, U-42 RPC, U-43 NIS

**Files:**
- Create: `controls/service/nfs_server_disabled.yaml`, `controls/service/automount_disabled.yaml`, `controls/service/rpcbind_disabled.yaml`, `controls/service/nis_disabled.yaml` + fixtures.

**Interfaces:**
- Consumes: `services.{nfs_server,automount,rpcbind,nis}.{active,enabled}`, `services.{nfs_server,rpcbind}.reachable`, and (U-43 only) `accounts.nss.passwd_sources`/`accounts.nss.group_sources`.

- [ ] **Step 1: Write U-39, U-41, U-42 (service-state only)**

Each ANDs `active == false` and `enabled == false`. `nfs_server` and `rpcbind` additionally AND `reachable == false` (fixed ports 2049/111). `automount` has no fixed port — no `reachable` check. kisa/importance: U-39 `{ "2026":["U-39"],"2021":["U-24"] }` 상; U-41 `{ "2026":["U-41"],"2021":["U-26"] }` 상; U-42 `{ "2026":["U-42"],"2021":["U-27"] }` 상. No STIG ids exist for these — `references.kisa` only.

`controls/service/nfs_server_disabled.yaml` checks:

```yaml
checks:
  - { fact: services.nfs_server.active, op: eq, expected: false }
  - { fact: services.nfs_server.enabled, op: eq, expected: false }
  - { fact: services.nfs_server.reachable, op: eq, expected: false }
```

Description must state the honest scope: this judges only whether the NFS **server** is running/enabled; NFS *access control* (exports) is a separate control (U-40, 2J). Remediation `systemctl disable --now nfs-server.service`.

- [ ] **Step 2: Write U-43 NIS (service state + nsswitch)**

`nis_disabled.yaml` (`id: muster.service.nis_disabled`, importance 상, kisa `{ "2026":["U-43"],"2021":["U-28"] }`). It carries the ypserv STIG id:

```yaml
references:
  kisa: { "2026": ["U-43"], "2021": ["U-28"] }
  stig:
    - { benchmark: rhel9, version: "V2R9", id: "RHEL-09-215030" }
```

Primary checks are the service state (`services.nis.active`/`enabled` == false — ypserv/ypbind covered by the `nis` unit list). Add an nsswitch screen so a host resolving accounts through NIS FAILs even without a running local ypserv.

**Ruling R225 — use the working clause shape.** The drafted `none:`/`value:` YAML does NOT decode (schema.go:16-26 uses `KnownFields(true)`; `none` is an OP, and the sub-key is `expected`, not `value`). Use the precedent shape (controls/account/root_remote_login.yaml:32), and drop `nis+` — it is not an nsswitch token (`nisplus` is):

```yaml
checks:
  - { fact: services.nis.active, op: eq, expected: false }
  - { fact: services.nis.enabled, op: eq, expected: false }
  - { fact: accounts.nss.passwd_sources, op: none, where: { op: in, expected: ["nis", "nisplus"] } }
  - { fact: accounts.nss.group_sources,  op: none, where: { op: in, expected: ["nis", "nisplus"] } }
```

**Ruling R225:** this nsswitch screen only bites given R224 — the `services.nis.*` leaves are `ok:false` (not `absent`) on a complete sweep, so §6.5 step 8 does not screen the control out before the clauses run.

**Correction (R241, stage-2G whole-branch review).** The original claim here — that `accounts.nss.*_sources` "are always present (2B guarantees they are never absent)" — is FALSE. `registry.yaml` documents both keys as **absent** when the file or the `passwd:`/`group:` line is missing, and `accounts_nss.go` emits `collect.Absent(...)` in exactly those cases. With `absent_means: pass` this let a live NIS false-PASS: §6.5 step 8 screens the whole control on the first `absent` fact before the `services.nis.*` clauses run, and the "absent counts as pass" reason even satisfied the CI jq invariant. U-43 therefore uses **`absent_means: manual`** (the precedent of `controls/account/root_remote_login.yaml`, which judges these same two facts): a missing nsswitch source line yields MANUAL — never PASS — while `ok` still runs the clauses and `unsupported` is still NOT_APPLICABLE.

**Ruling R236 — honesty note in the U-43 description.** The description must state that a NIS client resolving via nsswitch `compat` mode with `+` entries is NOT detected (mirrors the `accounts.nss.remote` registry warning) — so the control can pass a compat-mode NIS client.

- [ ] **Step 3: Fixtures**

Per control: `pass-absent`, `pass-disabled`, `fail-enabled` (enabled-but-stopped), plus `fail-reachable` for nfs_server/rpcbind, plus `na-container`. For `nis_disabled` add `fail-nss-nis.json` where `services.nis.*` are ok-false but `accounts.nss.passwd_sources` = `{"status":"ok","value":["files","nis"]}` (proves the nsswitch screen bites), and ensure `pass-*` fixtures set the sources to `["files"]`/`["files","systemd"]` so they don't trip it. (R241: because U-43 now uses `absent_means: manual`, its `pass-absent` fixture became `manual-absent`, and a `manual-nss-line-missing` fixture — a live NIS with `accounts.nss.group_sources` absent — asserts MANUAL, proving that path is not a PASS.)

- [ ] **Step 4: Lint + evaluate + commit**

Run: `go run ./cmd/muster controls lint --references docs/reference`; `go test ./internal/controls/...`.

```bash
git add controls/service/nfs_server_disabled.yaml controls/service/automount_disabled.yaml controls/service/rpcbind_disabled.yaml controls/service/nis_disabled.yaml controls/testdata/muster.service.nfs_server_disabled controls/testdata/muster.service.automount_disabled controls/testdata/muster.service.rpcbind_disabled controls/testdata/muster.service.nis_disabled
git commit -m "Add the NFS, automount, RPC and NIS service controls"
```

---

### Task 5: U-44 tftp/talk and U-58 SNMP

**Files:**
- Create: `controls/service/tftp_talk_disabled.yaml`, `controls/service/snmp_disabled.yaml` + fixtures.

**Interfaces:**
- Consumes: `services.{tftp,talk,snmp}.{active,enabled,reachable}`.

- [ ] **Step 1: Write U-44 (one control judging both tftp and talk)**

`tftp_talk_disabled.yaml` (`id: muster.service.tftp_talk_disabled`, importance 상, kisa `{ "2026":["U-44"],"2021":["U-29"] }`). The 2026 item adds **ntalk** (kisa_mapping note) — the `talk` logical service already includes `ntalk` (port 518/udp and inetd name `ntalk`), so no extra key is needed; state this in the description. It carries the RHEL9 tftp STIG id:

```yaml
references:
  kisa: { "2026": ["U-44"], "2021": ["U-29"] }
  stig:
    - { benchmark: rhel9, version: "V2R9", id: "RHEL-09-215060" }
checks:
  - { fact: services.tftp.active, op: eq, expected: false }
  - { fact: services.tftp.enabled, op: eq, expected: false }
  - { fact: services.tftp.reachable, op: eq, expected: false }
  - { fact: services.talk.active, op: eq, expected: false }
  - { fact: services.talk.enabled, op: eq, expected: false }
  - { fact: services.talk.reachable, op: eq, expected: false }
```

- [ ] **Step 2: Write U-58 SNMP**

`snmp_disabled.yaml` (`id: muster.service.snmp_disabled`, importance 중, kisa `{ "2026":["U-58"],"2021":["U-66"] }`). No STIG id — `references.kisa` only. Checks `services.snmp.{active,enabled,reachable}` == false. Description: an unnecessary SNMP agent must not be running; deeper SNMP hardening (version, community strings, ACLs) is U-59/60/61 (2J). Remediation `systemctl disable --now snmpd.service`.

- [ ] **Step 3: Fixtures** — `pass-absent`, `pass-disabled`, `fail-enabled`, `fail-reachable`, `na-container` for each; for `tftp_talk` add `fail-talk-reachable.json` so both halves of the AND are exercised independently.

- [ ] **Step 4: Lint + evaluate + commit**

```bash
git add controls/service/tftp_talk_disabled.yaml controls/service/snmp_disabled.yaml controls/testdata/muster.service.tftp_talk_disabled controls/testdata/muster.service.snmp_disabled
git commit -m "Add the tftp/talk and SNMP service controls"
```

---

### Task 6: Count, coverage, e2e and README reconciliation

**Files:**
- Modify: `cmd/muster/controls_test.go`, `cmd/muster/e2e_test.go`, `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `docs/reference/coverage.md`, `README.md`, `README.ko.md`.

**Interfaces:** consumes every control id from Tasks 3–5.

- [ ] **Step 1: Bump the lint count assertions**

In `cmd/muster/controls_test.go`, change both `strings.Contains(out.String(), "ok: 35 controls")` (lines ~36 and ~75) to `"ok: 44 controls"`.

Run: `go test ./cmd/muster/ -run TestControlsLint` → expected FAIL first if run before the controls exist; after Tasks 3–5 it must pass. (Order Task 6 last so no task commit is left red — the L10 discipline from prior stages.)

- [ ] **Step 2: Enrol the nine controls in the e2e snapshots**

**Rulings R224/R240:** add to `cmd/muster/testdata/full-pass.json` the nine services' passing facts with the REAL live-host shape — every judged leaf `ok:false` (NOT `absent`), because a complete sweep never emits `absent` on a judged leaf (R224). This makes the e2e leg prove the live path a real host takes. The `pass-absent.json` control fixtures are kept as synthetic edge cases (they also pin the "absent counts as pass" CI reason contract). Add to `full-fail.json` the facts that make each new control FAIL (one enabled/reachable leaf `ok:true`).

**Ruling R230 — two spelled-out count comments in `cmd/muster/e2e_test.go`, not one:** `:167` "the thirty-five embedded controls" → "forty-four" and `:217` "the other thirty-four controls are unchanged" → "forty-three". Update both control-id→expected-status maps (add nine entries each) and both comments.

- [ ] **Step 3: Regenerate coverage**

Run: `go run ./tools/coverage` → `docs/reference/coverage.md` line 4 becomes `44 of 67 items enrolled (auto 40, partial 4, manual 0).` and U-34/36/38/39/41/42/43/44/58 rows show their control ids. Do not hand-edit; run `go run ./tools/coverage -check` to confirm it is not stale.

- [ ] **Step 4: README service coverage**

**Ruling R230:** `README.md:25` / `README.ko.md:21` only LINK the generated coverage table — there is no "N controls" sentence to bump. Verify no control-count sentence exists in the READMEs; update only if a service-coverage sentence is present, else leave the READMEs unchanged (do NOT fabricate a sentence). If touched, keep the `.ko.md` pair in the same commit; identifiers/paths stay English on both sides.

- [ ] **Step 5: Full suite + cross gates**

Run: `go test ./...` (Windows: no `-race`); `GOOS=linux GOARCH=amd64 go vet ./...`; `GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null`; `GOOS=linux staticcheck ./...`; `go run ./cmd/muster controls lint --references docs/reference` → `ok: 44 controls`.

- [ ] **Step 6: Commit**

```bash
git add cmd/muster docs/reference/coverage.md README.md README.ko.md
git commit -m "Enrol the nine 2G service controls in the coverage and e2e snapshots"
```

---

## Self-Review

**1. Spec coverage.** §10.2's 2G subject "services and super-servers" → nine controls covering finger (U-34), r-services (U-36), DoS-prone (U-38), NFS server (U-39), automountd (U-41), RPC (U-42), NIS (U-43), tftp/talk (U-44), SNMP-running (U-58). NFS access control (U-40), SNMP config depth (U-59/60/61) and patch stay in 2J; 2G publishes the `services.nfs_server.installed`/`services.snmp.installed` evidence 2J's dependency line requires (Task 1 registers them). FTP (U-53/54/56/57) and U-35/U-45–U-51 are 2L. D09 logical-service map → the `services` table (Task 1). D19 service normalisation → `unit_file_state`/masked/static/indirect handling (Task 1 Step 4).

**2. Placeholder scan.** Every control's full YAML or a complete template is given; every fixture has an example or an exact shape to copy from the merged telnet fixtures; the collector code blocks are concrete. The two former soft spots are now pinned: the U-43 nsswitch clause is fixed to the working `op: none` / `where: { op: in, expected: [...] }` shape (R225), and the registry key enumeration in the no-systemd test uses `facts.LoadRegistry()` + `reg.Keys[i].Collector == "services"` / `.Key` (R226).

**3. Type consistency.** `services.<n>.installed/active/enabled/reachable` are `bool`; `unit_file_state` is `string`. `reachable` is registered and checked **only** for fixed-port services (finger, rservices, dos_services, nfs_server, rpcbind, tftp, talk, snmp, telnet) and omitted for automount, nis, ssh — the controls match (automount/nis check only active+enabled). `portSpec{proto,port}` and `hasNonLoopbackPort(list, []portSpec)` are used consistently in Task 1 Steps 5–6. `enabledFromUnitFile(state, active)` is defined once (Step 4) and used in Step 6 and folded with the super-server `enabled` (Task 2 Step 4).

**Risks (for the pre-flight scan and reviews to probe):**
- **R-a (unit name coverage, analysis "riskiest decision #1"):** one wrong unit name silently reads as "not installed" → a running service passes. The table's unit lists must cover both Debian/Ubuntu and RHEL/Rocky/Alma names (e.g. `nfs-server.service` vs `nfs-kernel-server.service`). **Ruling R234:** ALL systemd unit names in the Task 1 table must be verified against the real CI-image / lab-host units before the collector is considered done; the implementer runs the collector on the lab host and checks the real unit names for nfs/rpcbind/snmp/nis/tftp/autofs (`atftpd.service`/`atftpd.socket` added to `tftp` for the socket-activated Debian atftpd package, and `tftp.service` for RHEL 9 tftp-server — R246).
- **R-b (enabled-but-stopped):** `active==false` alone must not pass; the `enabled` AND-term and the `fail-enabled` fixtures guard this. Verify `enabledFromUnitFile` returns true for `enabled` with `active=false`.
- **R-c (masked-procfs → reachable):** every `reachable` leaf must be `unsupported` (not `absent`) when `/proc/net/tcp` is masked, or the container CI leg mis-passes; reuse `socketReadEnvelope`.
- **R-d (no-systemd completeness):** the degrade loop must cover **every** registered leaf including `reachable`; the `collect-contract` leg fails otherwise. This is the R220 lesson made a first-class test.
- **R-e (CI proves only the absent path):** none of these daemons ship on the CI images, so every 2G control PASSes via `absent_means: pass` in CI; the `fail-*` fixtures are the only proof of the positive path. Keep them.
- **R-f (honest FTP/RPC boundaries):** U-39's description must not imply it covers NFS export ACLs; U-42/U-43 judge active/enabled only (no fabricated `reachable`).

---

## Execution notes (2026-09-08, SDD, controller = Fable/Opus 4.8)

Executed via subagent-driven development in worktree `stage2g-services` over main @ `29ff172` (2F merged). Delivered: the `services` collector generalised from a two-service hard-coded map into a 12-entry logical-service table (`services.go`), a shared inetd/xinetd super-server reader (`services_super.go`) replacing the deleted `telnetFromLegacy`, 57 registered `services.*` keys (12 × {installed, active, unit_file_state, enabled} + 9 × reachable; additions-only, `schema_version` still 1), and nine new `auto` controls U-34/U-36/U-38/U-39/U-41/U-42/U-43/U-44/U-58. **Control set 29→44** (auto 40, partial 4, manual 0). ssh/telnet unit lists kept verbatim (R223); each control ANDs `active==false` + `enabled==false` (+ `reachable==false` for fixed-port services), with `absent_means: pass` except U-43 which uses `absent_means: manual` (R241).

**Boundary rulings (controller):** G-1 U-54 excluded (→2L), G-2 U-35 excluded (→2L), G-3 nine controls, G-4 RPC/NIS/automount judged active+enabled only (no fabricated reachable), G-5 2G publishes `services.nfs_server.installed`/`services.snmp.installed` for 2J, G-6 STIG cites only the three indexed families (U-36 rsh-server, U-43 ypserv, U-44 tftp), G-8 no-systemd degrade over the whole table.

**Pre-flight rulings R221–R240** (Fable pre-flight scan; folded into the plan pre-execution): proto compared by prefix so tcp6/udp6 listeners match (R221); `enabled` OR-ed over every probed unit, not the canonical one (R222); ssh/telnet units kept verbatim (R223); a complete sweep emits `ok:false`, never `absent`, on judged leaves so §6.5 step-8 screening cannot mis-PASS (R224); the working U-43 `op: none`/`where: {op: in, expected}` clause (R225); real test helpers + table-driven `allUnitsNotFound` (R226); super-server host-unit gating (R227); `alias`→false / `generated`→active unit-file mapping (R228); no `subject_kind` on scalar keys (R229); the two e2e count comments (R230); `unit_file_state` default `"not-found"`, masked = installed (R231); one pre-loop `listeningSockets` (R232); name/servers matching, no suffix heuristic (R233); `atftpd.service` + lab unit-name verification (R234); drop `SubState` parse (R235); R236 compat-mode honesty note; R237–R240 comments/fixture shape.

**Execution:** Task 1 (collector) took one fix round — the `active` leaf folded a socket-read error as a false `ok:false` (false-PASS on masked `/proc/net`); fixed to surface the `reachEnv` envelope (commit `88c90f1`). Tasks 2–6 passed task review first time; Task 2's tests were run on the lab host by its reviewer (196 pass) after the implementer used a wrong scratchpad path.

**Whole-branch Fable review** found one BLOCKING and five SHOULD-FIX; rulings **R241–R250**, all fixed in one consolidated fix wave (commits `c9964c3`, `b53d213`) except R250 (optional legacy unit names, parked). The BLOCKING (R241): U-43 false-PASSed a live NIS when `accounts.nss.*_sources` was `absent` — R225's premise that 2B never emits those absent was WRONG (they are `absent` when the nsswitch line is missing), and §6.5 step-8 + `absent_means: pass` resolved to PASS with a reason that even satisfies the CI jq invariant. Fixed with `absent_means: manual` (a live NIS + missing nsswitch line now → MANUAL, never PASS). Also fixed: xinetd `server_args` clobbering the `server` basename (R242), silent host-probe-failure negatives (R243), a false U-44 description (R244), a missing unreadable-inetd.conf honesty test (R245), and tftp unit-name gaps `tftp.service`/`atftpd.socket` (R246). Scoped re-review: PASS.

**Lab host:** Ubuntu 22.04 lab host has none of nfs/rpcbind-daemon/snmp/nis/tftp/autofs installed, so positive `LoadState=loaded` was never observed for the new daemons (R234 mitigation: each service lists multiple canonical Debian/Ubuntu + RHEL unit candidates; the reviewer verified no table name is wrong for the stated families). All collector unit tests pass on the lab host; controls/e2e/facts/check suites green natively; `controls lint` → `ok: 44 controls`; `coverage -check` clean. CI (the container legs incl. the systemd-less `collect-contract` leg) is the final proof of the no-systemd degrade and the absent-path PASS.

**Parked:** R250 (legacy `nis.service`/`rlinetd.service` unit names, outside the Ubuntu 22.04/24.04 + EL9 targets); NICE #9 addressed; the R234 positive unit verification remains CI-confirmed only.
