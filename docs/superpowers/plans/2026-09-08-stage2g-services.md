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
- `internal/collect/collectors/services.go` — replace `logicalUnits map[string][]unitRef` and the `switch name` dispatch with a `[]logicalService` table and one generic per-service loop; parse `UnitFileState`/`SubState` (already on the wire); derive `enabled`; generalise `hasNonLoopbackTCPPort` to proto+multi-port; iterate the table in the no-systemd degrade path.
- `internal/collect/collectors/services_super.go` — **new** file: the shared inetd/xinetd content reader extracted and generalised from `telnetFromLegacy` (a super-server entry lookup by service-name field / server-program suffix for a set of names).
- `internal/collect/collectors/services_test.go` (or the existing `collectors_test.go` block for services) — table-driven collector tests incl. the no-systemd and masked-procfs degrade assertions.
- `internal/facts/registry.yaml` + `internal/facts/testdata/schema_golden.json` (or the golden path the `-update` flag writes) — new `services.<n>.*` keys.

**Controls (Tasks 3–5) — create** under `controls/service/` with fixtures under `controls/testdata/<id>/`:
- `finger_disabled.yaml` (U-34), `rservices_disabled.yaml` (U-36), `dos_services_disabled.yaml` (U-38)
- `nfs_server_disabled.yaml` (U-39), `automount_disabled.yaml` (U-41), `rpcbind_disabled.yaml` (U-42), `nis_disabled.yaml` (U-43)
- `tftp_talk_disabled.yaml` (U-44), `snmp_disabled.yaml` (U-58)

**Reconciliation (Task 6) — modify:**
- `cmd/muster/controls_test.go` (two `ok: 35 controls` → `ok: 44 controls`), `cmd/muster/e2e_test.go` (two control-id→status maps + the "thirty-four unchanged" comment), `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `docs/reference/coverage.md` (regenerated), `README.md`/`README.ko.md` (service coverage line).

---

## Interfaces (produced by this plan, consumed by later tasks and 2J)

New fact keys (collector `services`, all `since: 1`), per logical service `<n>`:
- `services.<n>.installed` — `bool` — a unit or super-server entry proving the software is present.
- `services.<n>.active` — `bool` — running now (systemd `ActiveState=active`, or a live inetd entry, or a non-loopback listener).
- `services.<n>.unit_file_state` — `string` — the systemd `UnitFileState` of the proving unit (`enabled`, `disabled`, `masked`, `static`, `indirect`, `generated`, `alias`, `enabled-runtime`, or `absent` when no unit exists); evidence only.
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

Add to the services test file. The first test proves the collector emits the full leaf set for a service from the table (not a hard-coded switch); the second is the load-bearing degrade test.

```go
func TestServicesTableEmitsAllLeavesPerService(t *testing.T) {
	a := newFakeAccess() // systemd present: Stat("/run/systemd/system") ok
	a.stat["/run/systemd/system"] = fakeStat{}
	// finger.socket enabled but inactive → must be caught as enabled==true, active==false
	a.cmd[showKey("finger.socket")] = cmdOut{stdout: "LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\nSubState=dead\n"}
	b := facts.NewBuilder(reg(t))
	if err := runServices(context.Background(), a, b); err != nil {
		t.Fatal(err)
	}
	snap := b.Snapshot()
	mustBool(t, snap, "services.finger.active", false)
	mustBool(t, snap, "services.finger.enabled", true) // enabled-but-stopped is still enabled
	mustString(t, snap, "services.finger.unit_file_state", "enabled")
	mustBool(t, snap, "services.finger.installed", true)
}

func TestServicesNoSystemdDegradesEveryRegisteredKey(t *testing.T) {
	a := newFakeAccess() // Stat("/run/systemd/system") returns an error
	b := facts.NewBuilder(reg(t))
	if err := runServices(context.Background(), a, b); err != nil {
		t.Fatal(err)
	}
	snap := b.Snapshot()
	// Every services.* key the registry declares must be present and unsupported,
	// so the run stays complete on a systemd-less container (R220).
	for _, key := range reg(t).KeysForCollector("services") {
		env, ok := snap.Lookup(key)
		if !ok {
			t.Fatalf("%s missing on no-systemd host (would ERROR at check time)", key)
		}
		if env.Status != facts.StatusUnsupported {
			t.Errorf("%s = %s, want unsupported on no-systemd host", key, env.Status)
		}
	}
	if got := b.Worst("services"); got != facts.StatusOK {
		t.Errorf(`Worst("services") = %s, want ok (unsupported ranks ok, run stays complete)`, got)
	}
}
```

If `reg(t).KeysForCollector(...)` does not exist, use the registry accessor that lists keys by collector (grep `internal/facts` for the method the golden test already uses to enumerate keys); if none exists, enumerate the expected key list literally from the table in the test. The intent — *every registered `services.*` key is `unsupported`, and `Worst("services")==ok`* — is the assertion that must hold. Mirror `TestCronTimersInventoryAndFailure`'s `Worst(...)==ok` shape from 2F.

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
	units      []unitRef  // systemd units; the provesInstall unit is canonical for unit_file_state
	inetdNames []string   // inetd.conf field-0 names / xinetd.d service names (super-server hosting)
	ports      []portSpec // fixed listening ports for the reachable leaf; empty ⇒ no reachable leaf
}

// Order is the emission order; keep it stable (same input, same bytes).
var services = []logicalService{
	{name: "ssh", units: []unitRef{{"ssh.service", true}, {"sshd.service", false}}},
	{name: "telnet", units: []unitRef{{"telnet.socket", true}, {"telnet.service", false}, {"telnetd.service", false}}, inetdNames: []string{"telnet"}, ports: []portSpec{{"tcp", 23}}},
	{name: "finger", units: []unitRef{{"finger.socket", true}, {"fingerd.service", false}}, inetdNames: []string{"finger"}, ports: []portSpec{{"tcp", 79}}},
	{name: "rservices", units: []unitRef{{"rsh.socket", true}, {"rlogin.socket", false}, {"rexec.socket", false}}, inetdNames: []string{"shell", "login", "exec"}, ports: []portSpec{{"tcp", 514}, {"tcp", 513}, {"tcp", 512}}},
	{name: "dos_services", units: []unitRef{{"echo.socket", true}, {"discard.socket", false}, {"daytime.socket", false}, {"chargen.socket", false}}, inetdNames: []string{"echo", "discard", "daytime", "chargen"}, ports: []portSpec{{"tcp", 7}, {"udp", 7}, {"tcp", 9}, {"udp", 9}, {"tcp", 13}, {"udp", 13}, {"tcp", 19}, {"udp", 19}}},
	{name: "nfs_server", units: []unitRef{{"nfs-server.service", true}, {"nfs-kernel-server.service", false}}, ports: []portSpec{{"tcp", 2049}, {"udp", 2049}}},
	{name: "automount", units: []unitRef{{"autofs.service", true}}},
	{name: "rpcbind", units: []unitRef{{"rpcbind.service", true}, {"rpcbind.socket", false}}, ports: []portSpec{{"tcp", 111}, {"udp", 111}}},
	{name: "nis", units: []unitRef{{"ypserv.service", true}, {"ypbind.service", false}, {"ypxfrd.service", false}, {"yppasswdd.service", false}}},
	{name: "tftp", units: []unitRef{{"tftp.socket", true}, {"tftpd.service", false}, {"tftpd-hpa.service", false}}, inetdNames: []string{"tftp"}, ports: []portSpec{{"udp", 69}}},
	{name: "talk", units: []unitRef{{"talk.socket", true}, {"ntalk.socket", false}}, inetdNames: []string{"talk", "ntalk"}, ports: []portSpec{{"udp", 517}, {"udp", 518}}},
	{name: "snmp", units: []unitRef{{"snmpd.service", true}}, ports: []portSpec{{"udp", 161}}},
}
```

`declaredShowCommands()` must now iterate `services` (flattening `units`) instead of `logicalUnits`; keep the sorted-key determinism (sort the flattened unit names).

- [ ] **Step 4: Parse UnitFileState/SubState and derive `enabled`**

`showValues` already receives `UnitFileState`/`SubState` on the wire (the command asks for them). Extend it to return them, and add:

```go
// enabledFromUnitFile reports whether a unit's UnitFileState means "will start
// at boot or on socket activation". masked/disabled/absent ⇒ false; static and
// indirect ⇒ false unless the unit is also active (a dependency pulled it in).
func enabledFromUnitFile(state string, active bool) bool {
	switch state {
	case "enabled", "enabled-runtime", "alias", "generated":
		return true
	case "indirect":
		return active // a socket unit that is actually listening
	default: // disabled, masked, static, bad, absent, ""
		return false
	}
}
```

Record `services.<n>.unit_file_state` as the canonical (provesInstall) unit's state, defaulting to `"absent"` when no unit is found.

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
			if asString(m["proto"]) == ps.proto && asInt(m["port"]) == ps.port && !asBool(m["loopback"]) {
				return true
			}
		}
	}
	return false
}
```

Use the record field names actually present in `sockets.listening` (grep `sockets.go` `parseProcNet` for the exact keys — the scope brief lists `proto, addr, port, inode, loopback`). Keep any existing `asString`/`asInt` helpers; add minimal ones if absent.

- [ ] **Step 6: One generic per-service loop + no-systemd degrade over the table**

Replace the `switch name { case "ssh": …; case "telnet": … }` dispatch with a loop over `services`. For each service:
- `installed` ← any unit found (LoadState≠not-found) OR a super-server entry (Task 2) OR (`reachable` true).
- `active` ← systemd `ActiveState=active` on any unit, OR a live super-server entry, OR (for a fixed-port service) `reachable`.
- `unit_file_state` ← canonical unit's state (string).
- `enabled` ← `enabledFromUnitFile(state, active)` OR the super-server entry is enabled (Task 2 folds in).
- `reachable` (fixed-port services only) ← `hasNonLoopbackPort(listeningSockets(a), svc.ports)`, and `socketReadEnvelope`/`unsupported` when `/proc/net` is masked (reuse the telnet path at services.go line ~284/290).

The no-systemd branch must iterate the table and emit `unsupported` for **every** leaf the service registers (including `reachable` where applicable), replacing the hard-coded 4-key list:

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

Add to `internal/facts/registry.yaml`, for each logical service, the leaves it emits (all `since: 1`, `collector: services`). `installed`/`active`/`enabled`/`reachable` are `type: bool`; `unit_file_state` is `type: string`. `ssh` gains `active`, `unit_file_state`, `enabled` (no `reachable`); `telnet` gains `active`, `unit_file_state`, `enabled` (keeps `reachable`). Keep entries grouped and sorted the way the file already groups `services.*`. Set `subject_kind`/`sensitivity` consistently with the existing `services.*` entries (they are not `internal`).

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
- Consumes: `collect.Access` (`ReadFile`, `Glob`), `inetdConf`, `xinetdGlob` (existing consts in `services.go`).
- Produces: `superServerState(a, names []string) (enabled bool, active bool, found bool, ev *facts.Envelope)` — one lookup for a set of inetd/xinetd service names, folded into a logical service's `installed`/`active`/`enabled`.

- [ ] **Step 1: Write the failing test**

```go
func TestSuperServerReaderMatchesAnyName(t *testing.T) {
	a := newFakeAccess()
	a.files[inetdConf] = "shell\tstream\ttcp\tnowait\troot\t/usr/sbin/in.rshd\tin.rshd\n" +
		"#login\tstream\ttcp\tnowait\troot\t/usr/sbin/in.rlogind\n" // commented ⇒ not enabled
	en, act, found, ev := superServerState(a, []string{"shell", "login", "exec"})
	if ev != nil {
		t.Fatalf("unexpected envelope: %+v", ev)
	}
	if !found || !en || !act {
		t.Fatalf("live 'shell' entry: found=%v enabled=%v active=%v, want all true", found, en, act)
	}
}

func TestSuperServerReaderIgnoresCommentsAndOtherNames(t *testing.T) {
	a := newFakeAccess()
	a.files[inetdConf] = "#finger\tstream\ttcp\tnowait\tnobody\t/usr/sbin/in.fingerd\n"
	en, _, found, ev := superServerState(a, []string{"finger"})
	if ev != nil {
		t.Fatal(ev)
	}
	if found || en {
		t.Fatalf("commented finger: found=%v enabled=%v, want false", found, en)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `GOOS=linux GOARCH=amd64 go test ./internal/collect/collectors/ -run TestSuperServer`
Expected: FAIL — `superServerState` undefined.

- [ ] **Step 3: Implement the shared reader**

Generalise the logic in `telnetFromLegacy` (services.go lines ~307–355): read `inetdConf`, then glob `xinetdGlob`, and match by inetd service name. For `/etc/inetd.conf`: split each non-comment line on whitespace; field 0 is the service name; a `disable = yes` is not expressible in inetd.conf, so a present, uncommented line ⇒ enabled+active. For xinetd fragments: a `service <name>` block is enabled unless it contains `disable = yes` (and active if enabled — xinetd starts on demand). Match if `field0`/block-name equals any requested name **or** the server-program basename has the classic `in.<name>d`/`<name>d` suffix. Return a read-error envelope (`readErrorEnv`-style) when a file that exists cannot be read, mirroring the honest-degradation rule (a config that exists but is unreadable is not "absent"); a missing `inetd.conf`/no xinetd fragments ⇒ `found=false`, no envelope.

- [ ] **Step 4: Wire it into the per-service loop and delete `telnetFromLegacy`**

In the Task 1 loop, for a service with `inetdNames`, call `superServerState`; OR its `enabled`/`active`/`installed` into the systemd-derived values; propagate any envelope onto that service's `enabled`/`active` leaves (a read error is not a silent pass). Delete `telnetFromLegacy`/`inetdTelnet`/`xinetdTelnet` and confirm telnet's own behaviour is unchanged by the existing telnet fixtures (Task 6 e2e) and its collector test.

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

Primary checks are the service state (`services.nis.active`/`enabled` == false — ypserv/ypbind covered by the `nis` unit list). Add an nsswitch screen so a host resolving accounts through NIS FAILs even without a running local ypserv. Express it with the §6.3–6.6 `none` clause over the `list<string>` sources; **the implementer must confirm the exact clause shape against `internal/controls/schema.go` and the merged 2B/2C controls that already read list facts, and adjust keys/operators to match**:

```yaml
checks:
  - { fact: services.nis.active, op: eq, expected: false }
  - { fact: services.nis.enabled, op: eq, expected: false }
  - fact: accounts.nss.passwd_sources
    none:
      where: { op: in, value: ["nis", "nisplus", "nis+"] }
  - fact: accounts.nss.group_sources
    none:
      where: { op: in, value: ["nis", "nisplus", "nis+"] }
```

If the grammar cannot express "the list contains none of these" cleanly, fall back to the service-state checks alone and record a ruling in the ledger (the nsswitch screen is a strengthening, not the core of U-43). `accounts.nss.*_sources` are always present (2B guarantees they are never absent), so they do not need `absent_means`.

- [ ] **Step 3: Fixtures**

Per control: `pass-absent`, `pass-disabled`, `fail-enabled` (enabled-but-stopped), plus `fail-reachable` for nfs_server/rpcbind, plus `na-container`. For `nis_disabled` add `fail-nss-nis.json` where `services.nis.*` are ok-false but `accounts.nss.passwd_sources` = `{"status":"ok","value":["files","nis"]}` (proves the nsswitch screen bites), and ensure `pass-*` fixtures set the sources to `["files"]`/`["files","systemd"]` so they don't trip it.

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

Add to `cmd/muster/testdata/full-pass.json` the nine services' passing facts (all judged leaves `ok:false`, or `absent` for a clean "never present" host — match how the other passing service facts are shaped there), and to `full-fail.json` the facts that make each new control FAIL (one enabled/reachable leaf `ok:true`). Update both control-id→expected-status maps in `cmd/muster/e2e_test.go` (add nine entries each) and the "thirty-four controls are unchanged" comment count.

- [ ] **Step 3: Regenerate coverage**

Run: `go run ./tools/coverage` → `docs/reference/coverage.md` line 4 becomes `44 of 67 items enrolled (auto 40, partial 4, manual 0).` and U-34/36/38/39/41/42/43/44/58 rows show their control ids. Do not hand-edit; run `go run ./tools/coverage -check` to confirm it is not stale.

- [ ] **Step 4: README service coverage**

Update the coverage sentence/table in `README.md` and its `README.ko.md` pair (same commit) to reflect 44 controls and the newly covered service items. Identifiers/paths stay English on both sides.

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

**2. Placeholder scan.** Every control's full YAML or a complete template is given; every fixture has an example or an exact shape to copy from the merged telnet fixtures; the collector code blocks are concrete. The two soft spots are called out explicitly, not hidden: the U-43 nsswitch clause (implementer confirms the §6.3–6.6 shape, falls back to service-state and records a ruling) and the registry key enumeration in the no-systemd test (use the registry's collector-key accessor or a literal list). Both have a defined fallback.

**3. Type consistency.** `services.<n>.installed/active/enabled/reachable` are `bool`; `unit_file_state` is `string`. `reachable` is registered and checked **only** for fixed-port services (finger, rservices, dos_services, nfs_server, rpcbind, tftp, talk, snmp, telnet) and omitted for automount, nis, ssh — the controls match (automount/nis check only active+enabled). `portSpec{proto,port}` and `hasNonLoopbackPort(list, []portSpec)` are used consistently in Task 1 Steps 5–6. `enabledFromUnitFile(state, active)` is defined once (Step 4) and used in Step 6 and folded with the super-server `enabled` (Task 2 Step 4).

**Risks (for the pre-flight scan and reviews to probe):**
- **R-a (unit name coverage, analysis "riskiest decision #1"):** one wrong unit name silently reads as "not installed" → a running service passes. The table's unit lists must cover both Debian/Ubuntu and RHEL/Rocky/Alma names (e.g. `nfs-server.service` vs `nfs-kernel-server.service`). Pre-flight and the lab-host run should confirm the real unit names on the CI images.
- **R-b (enabled-but-stopped):** `active==false` alone must not pass; the `enabled` AND-term and the `fail-enabled` fixtures guard this. Verify `enabledFromUnitFile` returns true for `enabled` with `active=false`.
- **R-c (masked-procfs → reachable):** every `reachable` leaf must be `unsupported` (not `absent`) when `/proc/net/tcp` is masked, or the container CI leg mis-passes; reuse `socketReadEnvelope`.
- **R-d (no-systemd completeness):** the degrade loop must cover **every** registered leaf including `reachable`; the `collect-contract` leg fails otherwise. This is the R220 lesson made a first-class test.
- **R-e (CI proves only the absent path):** none of these daemons ship on the CI images, so every 2G control PASSes via `absent_means: pass` in CI; the `fail-*` fixtures are the only proof of the positive path. Keep them.
- **R-f (honest FTP/RPC boundaries):** U-39's description must not imply it covers NFS export ACLs; U-42/U-43 judge active/enabled only (no fabricated `reachable`).
