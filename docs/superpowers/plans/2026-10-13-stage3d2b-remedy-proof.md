# Stage 3D-2b — the review script, proven: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The review script `fix --dry-run` writes refuses a host other than the snapshot's, restores each service unit's recorded state on failure, and every one of the sixteen scripted controls is proven on a real system in CI or names why it cannot be.

**Architecture:** The collector hashes only a well-formed machine id (`collectors.MachineIDHash`). `remedy.Build` carries the hash, as `FixBlock.MachineIDHash`/`HostGuard`, and each item's declared `units`. `remedy.Script` builds its prologue per plan: the guard, the hash helper and the unit helpers `save_units`/`restore_units`, then a `# validate` marker before every validate subshell. The controls gain `remediation.units` with eight named lint rules and two set-level ones. The ten service controls lose their hand-written rollbacks, and the five file scripts clear bits symbolically. `report.Escape` spells out the format class. CI's `fix-roundtrip` grows a Debian init row, seed scripts under `ci/roundtrip/`, a failure run and a guard run, and the matrix is pinned to `controls/testdata/_roundtrip.yaml` by a Go test.

**Tech Stack:** Go 1.25.5, standard library, `gopkg.in/yaml.v3` (existing), POSIX `sh`, systemd, docker in CI, shellcheck.

**Spec:** `docs/superpowers/specs/2026-10-13-stage3d2b-remedy-proof-design.md` (EN canonical, `.ko.md` pair) at `6838df9`, rulings Q-1..Q-6. Code map with exact current line numbers: `.superpowers/sdd/2026-10-13-stage3d2b-remedy-proof/code-map.md` (ignored; the controller hands its sections to each task).

## Global Constraints

- muster never executes a remediation. `internal/remedy` imports no `os`, `os/exec`, `net`, `syscall` or `time` (`TestRemedyPackageHasNoHostImports`, which reads `.Imports` only); test files may import them.
- The only snapshot value on a non-comment script line is the machine-id hash, and only as exactly 64 lowercase hex characters on the one `MUSTER_SNAPSHOT_HOST=` line (D34 amended).
- The script exits 2 for three causes, and nothing has run in any of them: not root, another host, an unusable backup directory. `fix` exits 0 whenever a plan was produced and 2 when it could not be; never 1. `check` and `collect` exit codes are unchanged.
- The block function call stays a bare line followed by `[ "$?" -eq 0 ] || failed=$((failed+1))`.
- Same input, same bytes, in all three formats; no `map` in `remedy.Plan`; the generator reads no clock.
- Control YAML is decoded strictly; the new field is `Units []string` with `yaml:"units,omitempty"`.
- No control judgment changes. `controls/VERSION` becomes `kisa-unix-2026+2026.10.13`.
- Nothing in the Go suite reaches the runner's systemd: unit helpers are executed only against a stub `systemctl` first on `PATH`.
- Documents are English canonical with the `.ko.md` pair in the same commit where a pair exists. `THREAT_MODEL.md` and `examples/README.md` have no pair. Identifiers stay English.
- Commits use the personal identity (pinned) and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push, amend, rebase or stash.
- From Task 6 on, the examples gate (`TestExamplesLoadAndCheck`) is red until the examples refresh (a merge step). Locally run `go test ./... -skip TestExamplesLoadAndCheck` and quote its failure once.
- On Windows the `internal/collect/...` tests and every `needSh`/Linux test do not run; the lab run (root) and CI cover them.

## Rulings carried from the code map (the spec as built)

- **T-1** `script_way_back` is not a rule name today: the check is rule `"remediation"`, message `"script without rollback or backup"` (`lint.go:133`). It keeps rule `"remediation"` and its message becomes `"script without rollback, backup or units"`. The eight new per-control rules carry their own names as rule ids (`units_charset`, `units_order`, `units_needs_script`, `units_exclusive`, `units_variable`, `backup_reserved`, `script_needs_validate`). `script_way_back` names the extended `"remediation"` check in prose only.
- **T-2** The set-level rules `backup_path_shared` and `units_shared` attach the Problem to the later control in id order (ControlID and Path set), as `beyond_scope` does (`lint.go:431-437`), not the M-2 empty-id form. They run in `Lint` beside `lintKISACoverage` (`lint.go:352`). The mutation harness lints one control at a time (`mutants_test.go:221`), so they never fire there.
- **T-3** `remedy.Build` checks units after `item()` returns (the Z-26 spot, `plan.go:162-168`); `item` keeps its signature. The pattern is exported as `controls.ValidUnitName(u string) bool` beside `ValidControlID`.
- **T-4** `FixBlock` gains, after `MaxRisk`, `HostGuard string \`json:"host_guard"\`` and `MachineIDHash string \`json:"-"\``. `HostGuard` is a real field, because `cmd/muster`'s `decodePlan` disallows unknown fields. `TestPlanCopiesProvenance` and `TestPlanItemCopiesEveryField` gain the new fields.
- **T-5** The prologue stops being a const: `func prologue(p *Plan) string` assembles fixed pieces (`prologueHead`, `machineIDHashHelper` (exported as `MachineIDHashHelper`), the guard, `prologueBackup`, `unitHelpers`, `failed=0`). `templateLines` in the test builds its set from `prologue(p)`.
- **T-6** The existing `restore()` assigns the block's global `rc`. It is renamed to `brc` inside `restore()` (the unit helpers use `urc`), and goldens re-render. No behaviour change: `restore` is always followed by `return 1`.
- **T-7** `runScriptStreams` gains a sibling `runScriptWith(t, p, dir, backupDir, o runOpts) (all, stderr string, code int)`, where `type runOpts struct{ replace [][2]string; pathPrefix string; env []string }`. `runScriptStreams` calls it with zero options. Both drop `MUSTER_ANY_HOST` from the inherited environment.
- **T-8** `fixture_test.go`'s `testControls` gains `muster.test.g_units` (restart_service, `units: [g.socket, g.service]`, a `$UNITS` loop body, a one-line validate). Counts move: the scripted count in `TestScriptBlocksAreIndependent` goes 3 → 4, the `full.*` goldens re-render, and the plan tests that count items gain one. `scriptReport` stays hash-free; only `fullPlan` sets `rep.Run.Host.MachineIDHash` to `sha256("0123456789abcdef0123456789abcdef")` = `3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9` (computed in the test with `crypto/sha256`, so the literal appears only in the golden).
- **T-9** The Escape rune test list cannot cross packages from a `_test.go` file. `internal/report` exports `func SpelledOut(r rune) bool`, the predicate `escapeRune` uses for the new classes. The poison tests in `report` and `remedy` take a fixed sample (`U+00AD U+061C U+200B U+200D U+202E U+2028 U+2029 U+2066 U+FEFF U+3164 U+E0001`), assert `SpelledOut` for each, and assert that none appears raw in the output.
- **T-10** `MachineIDHash` lives in the untagged new file `internal/collect/collectors/machineid.go`, so `internal/remedy`'s test can import it on every platform, and `os.go` calls it. `FuzzMachineIDHash` goes in `fuzz_test.go` (Linux tag), and `fuzzTargets` gains it between `FuzzListsRoot` and `FuzzModuleStates`.
- **T-11** The pin test `TestServiceScriptsNameTheCollectorsUnits` is rewritten, not extended. Today it requires every unit in script, validate and rollback; the new bodies name none, and rollbacks are gone.
- **T-12** `controls/testdata/_roundtrip.yaml` is embedded by `//go:embed VERSION */*.yaml` (as `_mutants.yaml` is) but never loaded (`LoadFS` skips `testdata`). The test reads it from disk at `../../controls/testdata/_roundtrip.yaml`, and `ci.yml` at `../../.github/workflows/ci.yml`.
- **T-13** The examples refresh will show the VM example's script guard-on (its snapshot carries `c0fe69bd…35a8`) and the container example's guard-off. `examples/README.md` says which.

## Review Focus

1. **A host whose `/etc/machine-id` reads `uninitialized` or is empty**, planned on itself. The collector writes no hash, the script carries the guard-off comment and runs. (Task 1: `TestMachineIDHashRefusesMalformedIDs`; Task 6: `TestScriptGuardOffWithoutAHash`.)
2. **The operator re-runs a failed script with the same `MUSTER_BACKUP` after installing a unit.** The `absent` record is rewritten, so the second failure restores the now-present unit's real state. (Task 6: the `absent then present` case of `TestUnitHelpersRestoreRecordedState`.)
3. **`/etc/shadow` at `0000` (RHEL's stock mode).** The symbolic script leaves it at `0000` and the validate accepts it. (Task 4: the `0000` row of `TestFileScriptsRepairOnARealFile`.)
4. **A unit name with `'`, `;` or a leading `-` reaching the plan from a hand-edited control set.** `remedy.Build` refuses the plan and nothing renders. (Task 5: `TestPlanRefusesAnUnsafeUnit`.)
5. **The script copied to a second host and run there without `MUSTER_ANY_HOST`.** Exit 2, exactly the refusal line on stderr, `MUSTER_BACKUP` never created. (Task 6: `TestScriptRefusesAnotherHost`; Task 8: the CI guard run.)

---

### Task 1: The probe (controller, lab with docker; no commit)

**Files:** `.superpowers/sdd/2026-10-13-stage3d2b-remedy-proof/probe.md` (ignored), `.superpowers/sdd/2026-10-13-stage3d2b-remedy-proof/probe.sh` (ignored).

The spec's image assignments are a hypothesis (§4 "The probe"). This task measures them; Task 8 writes the table from the result.

- [ ] **Step 1: Write `probe.sh`.** It takes an image and a `--build-debian` flag, starts the container the way §4 does (`--privileged --cgroupns=host`, `/sbin/init`, the Debian Dockerfile of spec §4 built as `muster-ci/debian12-init`), and prints one line per unit of the ten service controls (`automount: autofs.service`; `dos_services: echo.socket discard.socket daytime.socket chargen.socket`; `finger: finger.socket fingerd.service`; `nfs_server: nfs-server.service nfs-kernel-server.service`; `nis: ypserv.service ypbind.service ypxfrd.service yppasswdd.service`; `rpcbind: rpcbind.socket rpcbind.service`; `rservices: rsh.socket rlogin.socket rexec.socket`; `snmp: snmpd.service`; `telnet: telnet.socket telnet.service telnetd.service`; `tftp_talk: tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket`). Each line has five fields: the package that ships it (EL: `dnf provides '*/<unit>'`; Debian: `apt-get install` of the candidate package named in the table below, then `systemctl cat <unit>`; candidates `autofs`, `openbsd-inetd`, `fingerd`, `nfs-kernel-server`, `nis`, `rpcbind`, `rsh-server`, `snmpd`, `telnetd`, `tftpd-hpa`, `atftpd`, `talkd`), whether `systemctl enable --now` makes it `active`, its `Also=` (`systemctl show -p Also --value`), the units that `Requires=`/`BindsTo=`/`PartOf=` it (`systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value`), and the state after `systemctl reset-failed`. It also prints the image's `/etc/machine-id` content length at first boot of two containers and whether the two ids differ.
- [ ] **Step 2: Run it on the lab** for `rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init` and the built `debian12-init`. On Debian, install under `policy-rc.d` exit 101 as the seeds will. Record the output verbatim in `probe.md`.
- [ ] **Step 3: Decide the table.** In `probe.md`, write one `_roundtrip.yaml` entry per scripted control (sixteen):
  - `images` where the probe made every exercised unit `active`, or `enable` alone for a unit that cannot start in a container;
  - `unproven_units` for declared units the rows do not exercise;
  - `unproven` when no row can seed the control.
  
  Also write per row the `START_UNITS`/`ENABLE_ONLY_UNITS` lists and the package lists. The file controls go on every row whose image ships the file (`hosts_lpd` on all; `services` where `/etc/services` exists or `netbase` installs it). `root_remote_login` stays on the EL rows. `shadow_permissions` goes on `ubuntu2204`, plus every row where the stock mode fails the default (`0640` on Debian). Flag any provider/dependant pair on one row (spec §4: allowed only if pass 6 restarts the dependant).
- [ ] **Step 4: Report** the table, the machine-id finding (do two containers of one image get distinct ids?) and every surprise to the user before Task 8 is dispatched.

---

### Task 2: `MachineIDHash` — the collector hashes only a well-formed id

**Files:**
- Create: `internal/collect/collectors/machineid.go` (no build tag)
- Modify: `internal/collect/collectors/os.go:156-162`
- Test: `internal/collect/collectors/machineid_test.go` (no build tag), `internal/collect/collectors/fuzz_test.go`, `internal/collect/collectors/fuzz_inventory_test.go:41`

**Interfaces:**
- Produces: `func MachineIDHash(data []byte) string`. It applies `strings.TrimSpace`, and when the result matches `^[0-9a-f]{32}$` it returns the lowercase hex sha256 of the result; otherwise it returns `""`.

- [ ] **Step 1: Write the failing test** `machineid_test.go`:

```go
package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestMachineIDHashRefusesMalformedIDs(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(id))
	want := hex.EncodeToString(sum[:])
	for _, c := range []struct {
		name, in, want string
	}{
		{"plain", id, want},
		{"trailing LF", id + "\n", want},
		{"CRLF", id + "\r\n", want},
		{"leading blanks", "  \t" + id, want},
		{"leading LF", "\n" + id, want},
		{"uninitialized", "uninitialized\n", ""},
		{"uppercase", "0123456789ABCDEF0123456789ABCDEF", ""},
		{"31 chars", id[:31], ""},
		{"33 chars", id + "0", ""},
		{"interior space", id[:16] + " " + id[16:], ""},
		{"whitespace only", " \n\t", ""},
		{"empty", "", ""},
	} {
		if got := MachineIDHash([]byte(c.in)); got != c.want {
			t.Errorf("%s: MachineIDHash(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/collect/collectors -run TestMachineIDHash -count=1`. On Windows the package's untagged files build; if the package fails to build on Windows for unrelated tagged files, run it on the lab. Expected: FAIL, `undefined: MachineIDHash`.
- [ ] **Step 3: Implement** `machineid.go`:

```go
package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// MachineIDHash is the snapshot's host identity: the sha256 of a well-formed
// machine id (32 lowercase hex characters after trimming), and "" for
// anything else. The review script's host guard computes the same value
// (internal/remedy MachineIDHashHelper), so a malformed id turns the guard
// off instead of refusing the host it was planned on (3D-2b Q-1).
func MachineIDHash(data []byte) string {
	id := strings.TrimSpace(string(data))
	if !machineIDRe.MatchString(id) {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}
```

  In `os.go`, replace the `if id := readTrim(...)` block with `h.MachineIDHash = MachineIDHash([]byte(readTrim(a, "/etc/machine-id")))`. Keep the comment. Drop the now-unused `crypto/sha256` and `encoding/hex` imports from `os.go` if nothing else uses them.

- [ ] **Step 4: Add the fuzz target** in `fuzz_test.go`, after `FuzzListsRoot`:

```go
func FuzzMachineIDHash(f *testing.F) {
	for _, s := range []string{"0123456789abcdef0123456789abcdef\n", "0123456789abcdef0123456789abcdef\r\n", "uninitialized\n", "", "0123456789abcdef0123456789abcde", "0123456789abcdef 0123456789abcdef"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzBody(t, "MachineIDHash", func() any { return MachineIDHash(data) }, len(data))
		got := MachineIDHash(data)
		if got != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) {
			t.Fatalf("MachineIDHash = %q: neither empty nor 64 lowercase hex", got)
		}
	})
}
```

  Add `"FuzzMachineIDHash",` to `fuzzTargets` between `"FuzzListsRoot"` and `"FuzzModuleStates"`. If `regexp` is not yet imported in `fuzz_test.go`, add it.

- [ ] **Step 5: Run** on the lab (Linux):

  ```
  go test ./internal/collect/collectors -run 'TestMachineIDHash|TestOSFillsTheRunHeader|TestEveryParserHasAFuzzTarget|FuzzMachineIDHash' -count=1
  ```

  Expected: PASS. `TestOSFillsTheRunHeader`'s fixture id is valid, so it stays green.

- [ ] **Step 6: Mutation check.** Delete the `!machineIDRe.MatchString(id)` guard (hash any trimmed id), run `TestMachineIDHashRefusesMalformedIDs`, and see it go red. Restore.
- [ ] **Step 7: Commit** "Hash only a well-formed machine id, so a malformed one leaves the snapshot without a host identity". The body names the `machine_id_hash` header change (Q-6) and the fuzz target.

---

### Task 3: `remediation.units` and the remediation lint rules

**Files:**
- Modify: `internal/controls/schema.go:104-113` (field)
- Modify: `internal/controls/lint.go:49-56, 71-75, 104-160, 352` (regexes, `ValidUnitName`, `lintRemediation`, set rules)
- Test: `internal/controls/lint_test.go` (new cases in `TestLintRules` at the remediation block ~80-114; new `TestLintSetRules`)

**Interfaces:**
- Produces: `Remediation.Units []string` (`yaml:"units,omitempty"`), placed after `Backup`; `func ValidUnitName(u string) bool`; Problem rules `units_charset`, `units_order`, `units_needs_script`, `units_exclusive`, `units_variable`, `backup_reserved`, `script_needs_validate`, `backup_path_shared`, `units_shared`; the `remediation` message `script without rollback, backup or units`.

- [ ] **Step 1: Write the failing cases.** Append to `TestLintRules`' table, after the `"accept empty script without rollback"` case:

```go
		{name: "units charset", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: ["-x.service"] }`), rule: "units_charset", msg: `unit "-x.service"`},
		{name: "units bare template", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: ["foo@.service"] }`), rule: "units_charset", msg: `unit "foo@.service"`},
		{name: "units quote", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: ["x';id;'.service"] }`), rule: "units_charset"},
		{name: "units duplicate", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [a.service, a.service] }`), rule: "units_charset", msg: `unit "a.service" is repeated`},
		{name: "accept units instance", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: ["getty@tty1.service"] }`), rule: "units_charset", absent: true},
		{name: "units order", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [rpcbind.service, rpcbind.socket] }`), rule: "units_order", msg: "rpcbind.socket must precede rpcbind.service"},
		{name: "accept units order", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [rpcbind.socket, rpcbind.service, other.service] }`), rule: "units_order", absent: true},
		{name: "units without script", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, units: [a.service] }`), rule: "units_needs_script", msg: "units without script"},
		{name: "units way back", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [a.service] }`), rule: "remediation", absent: true},
		{name: "units with rollback", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", rollback: "true", units: [a.service] }`), rule: "units_exclusive", msg: "units excludes rollback"},
		{name: "units with backup", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/etc/hosts], units: [a.service] }`), rule: "units_exclusive", msg: "units excludes backup"},
		{name: "UNITS without units", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "for u in $UNITS; do :; done", validate: "true", rollback: "true" }`), rule: "units_variable", msg: "script uses $UNITS without units"},
		{name: "UNITS in validate", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "echo ${UNITS}", units: [a.service] }`), rule: "units_variable", msg: "validate uses $UNITS"},
		{name: "backup reserved exact", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/muster-units] }`), rule: "backup_reserved", msg: `backup path "/muster-units"`},
		{name: "backup reserved under", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/muster-units/x] }`), rule: "backup_reserved"},
		{name: "accept backup named like it", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/muster-unitsx] }`), rule: "backup_reserved", absent: true},
		{name: "script without validate", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", rollback: "true" }`), rule: "script_needs_validate", msg: "script without validate"},
```

  The existing cases `"script not idempotent"`, `"backup relative"`, `"backup unclean"`, `"backup trailing slash"`, `"backup charset"`, `"backup glob"`, `"backup repeated"`, `"script blank"` and `"rollback here-document"` have a script but no validate. They will now also raise `script_needs_validate`, which is harmless: each case asserts only its own rule. The `"script without way back"` case's msg changes to `"script without rollback, backup or units"`.

  Add after `TestLintRules`:

```go
func TestLintSetRules(t *testing.T) {
	scripted := func(id, extra string) string {
		y := strings.Replace(goodControl, "id: muster.account.good", "id: "+id, 1)
		return strings.Replace(y, "remediation: { text_en: t, text_ko: 조치, risk: lockout_risk, idempotent: true }",
			"remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: \"true\", validate: \"true\", "+extra+" }", 1)
	}
	for _, c := range []struct {
		name, a, b, rule, msg string
	}{
		{"backup shared", scripted("muster.account.aa", "backup: [/etc/hosts]"), scripted("muster.account.bb", "backup: [/etc/hosts]"), "backup_path_shared", `backup path "/etc/hosts" is also declared by muster.account.aa`},
		{"units shared", scripted("muster.account.aa", "units: [x.service]"), scripted("muster.account.bb", "units: [x.service]"), "units_shared", `unit "x.service" is also declared by muster.account.aa`},
	} {
		t.Run(c.name, func(t *testing.T) {
			ps := problemsOf(lintSet(t, LintOptions{CustomFuncs: map[string]bool{}}, c.b, c.a), c.rule)
			if len(ps) != 1 || ps[0].ControlID != "muster.account.bb" || ps[0].Path == "" || !strings.Contains(ps[0].Message, c.msg) {
				t.Fatalf("%s: problems %+v", c.rule, ps)
			}
		})
	}
	ps := lintSet(t, LintOptions{CustomFuncs: map[string]bool{}}, scripted("muster.account.aa", "backup: [/etc/a]"), scripted("muster.account.bb", "backup: [/etc/b]"))
	if len(problemsOf(ps, "backup_path_shared")) != 0 {
		t.Fatalf("distinct paths flagged: %+v", ps)
	}
}
```

  (The files are written in argument order `c0`=b, `c1`=a, so the test also proves that "later" means id order, not file order.)

- [ ] **Step 2: Run** `go test ./internal/controls -run 'TestLintRules|TestLintSetRules' -count=1`. Expected: FAIL (unknown field `units`, missing rules).
- [ ] **Step 3: Implement.** Add to `schema.go`'s `Remediation`, after `Backup`: `Units []string \`yaml:"units,omitempty"\``. In `lint.go`'s var block add `unitRe = regexp.MustCompile(\`^[A-Za-z0-9][A-Za-z0-9._:-]*(@[A-Za-z0-9._:-]+)?\.(service|socket)$\`)`. After `ValidControlID`:

```go
// ValidUnitName reports whether u is a unit name a remediation may declare
// (3D-2b §3): it starts with a letter or digit, carries a non-empty instance
// if it is a template, and ends .service or .socket. The review script puts
// it on a command line, so remedy.Build checks it again.
func ValidUnitName(u string) bool { return unitRe.MatchString(u) }
```

  In `lintRemediation`, replace the way-back check and append the new rules before the backup loop:

```go
	if hasScript && strings.TrimSpace(r.Rollback) == "" && len(r.Backup) == 0 && len(r.Units) == 0 {
		add("remediation", "script without rollback, backup or units")
	}
	if hasScript && r.Validate == "" {
		add("script_needs_validate", "script without validate")
	}
	if len(r.Units) > 0 && !hasScript {
		add("units_needs_script", "units without script")
	}
	if len(r.Units) > 0 && strings.TrimSpace(r.Rollback) != "" {
		add("units_exclusive", "units excludes rollback: the unit state is the way back")
	}
	if len(r.Units) > 0 && len(r.Backup) > 0 {
		add("units_exclusive", "units excludes backup: the unit state is the way back")
	}
	usesUnits := func(s string) bool { return strings.Contains(s, "$UNITS") || strings.Contains(s, "${UNITS") }
	if usesUnits(r.Script) && len(r.Units) == 0 {
		add("units_variable", "script uses $UNITS without units")
	}
	if usesUnits(r.Validate) {
		add("units_variable", "validate uses $UNITS, which only the script subshell sets")
	}
	if usesUnits(r.Rollback) {
		add("units_variable", "rollback uses $UNITS, which only the script subshell sets")
	}
	seenUnit, pos := map[string]bool{}, map[string]int{}
	for i, u := range r.Units {
		if !unitRe.MatchString(u) {
			add("units_charset", "unit %q is not a unit name a script can carry", u)
		}
		if seenUnit[u] {
			add("units_charset", "unit %q is repeated", u)
		}
		seenUnit[u] = true
		pos[u] = i
	}
	for _, u := range r.Units {
		if stem, ok := strings.CutSuffix(u, ".service"); ok {
			if j, has := pos[stem+".socket"]; has && j > pos[u] {
				add("units_order", "%s.socket must precede %s", stem, u)
			}
		}
	}
```

  In the backup loop add, after the charset case:

```go
		if p == "/muster-units" || strings.HasPrefix(p, "/muster-units/") {
			add("backup_reserved", "backup path %q is the script's unit-state directory", p)
		}
```

  Add the set-level function and call it in `Lint` next to `lintKISACoverage`: `out = append(out, lintSharedRemediation(s)...)`.

```go
// lintSharedRemediation refuses two scripted controls that declare the same
// backup path or the same unit (3D-2b §3): the first-record rule would let one
// block's restore undo the other's change. The Problem names the later
// control in id order (the set is sorted by id), as beyond_scope does.
func lintSharedRemediation(s *Set) []Problem {
	var out []Problem
	paths, units := map[string]string{}, map[string]string{}
	for i := range s.Controls {
		c := &s.Controls[i]
		r := c.Remediation
		if r == nil || strings.TrimSpace(r.Script) == "" {
			continue
		}
		for _, p := range r.Backup {
			if first, ok := paths[p]; ok {
				out = append(out, Problem{ControlID: c.ID, Path: c.Path, Rule: "backup_path_shared", Message: fmt.Sprintf("backup path %q is also declared by %s", p, first)})
				continue
			}
			paths[p] = c.ID
		}
		for _, u := range r.Units {
			if first, ok := units[u]; ok {
				out = append(out, Problem{ControlID: c.ID, Path: c.Path, Rule: "units_shared", Message: fmt.Sprintf("unit %q is also declared by %s", u, first)})
				continue
			}
			units[u] = c.ID
		}
	}
	return out
}
```

- [ ] **Step 4: Run** `go test ./internal/controls -count=1` (including `TestEveryMutantIsKilled` and `TestLintOfEmbeddedSetIsClean`) and `go run ./cmd/muster controls lint --references docs/reference`. Expected: PASS and `ok:`. The shipped set is clean: all sixteen have a validate and none declares units yet. If `TestLintOfEmbeddedSetIsClean` names a control, stop and report: the code map says none should.
- [ ] **Step 5: Mutation check.** Remove the `len(r.Units) == 0` term from the way-back check, see `"units way back"` go red, and restore. Remove `lintSharedRemediation` from `Lint`, see `TestLintSetRules` go red, and restore.
- [ ] **Step 6: Commit** "Declare a remediation's units and lint them: charset, order, exclusivity, the $UNITS variable, a validate for every script, and no shared backups or units". The body names T-1 and T-2.

---

### Task 4: The sixteen remediation blocks rewritten, the unit pin, the file validates

**Files:**
- Modify: `controls/service/{automount,dos_services,finger,nfs_server,nis,rpcbind,rservices,snmp,telnet,tftp_talk}_disabled.yaml` (remediation blocks)
- Modify: `controls/file/{hosts,hosts_lpd,passwd,services,shadow}_permissions.yaml` (remediation blocks)
- Modify: `controls/VERSION` → `kisa-unix-2026+2026.10.13`
- Rewrite: `internal/collect/collectors/remediation_units_test.go` (T-11)
- Test: `internal/controls/file_validates_test.go` (new, package `controls_test`)
- Test: `internal/remedy/shipped_test.go` (new `TestFileScriptsRepairOnARealFile`)

**Interfaces:**
- Consumes: `Remediation.Units` (Task 3).
- Produces: the shipped blocks the goldens of Task 6 render.

- [ ] **Step 1: Write the failing pin test.** Replace the body of `remediation_units_test.go` after `unitToken`:

```go
// TestServiceScriptsNameTheCollectorsUnits pins 3D-2b §3: a service control
// declares as units exactly the provesInstall units of its rows (as a set;
// the order is the control's, socket before service), its validate names
// exactly those, its script names none literally (it loops over $UNITS), and
// it has no rollback (the unit state is the way back).
func TestServiceScriptsNameTheCollectorsUnits(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]string{
		"muster.service.telnet_disabled":       {"telnet"},
		"muster.service.finger_disabled":       {"finger"},
		"muster.service.rservices_disabled":    {"rservices"},
		"muster.service.dos_services_disabled": {"dos_services"},
		"muster.service.nfs_server_disabled":   {"nfs_server"},
		"muster.service.automount_disabled":    {"automount"},
		"muster.service.rpcbind_disabled":      {"rpcbind"},
		"muster.service.nis_disabled":          {"nis"},
		"muster.service.tftp_talk_disabled":    {"tftp", "talk"},
		"muster.service.snmp_disabled":         {"snmp"},
	}
	byName := map[string]logicalService{}
	for _, s := range services {
		byName[s.name] = s
	}
	declaring := 0
	for _, c := range set.Controls {
		if c.Remediation != nil && len(c.Remediation.Units) > 0 {
			declaring++
			if _, ok := rows[c.ID]; !ok {
				t.Errorf("%s declares units but is not mapped to a services row", c.ID)
			}
		}
	}
	if declaring != 10 || len(rows) != 10 {
		t.Fatalf("%d controls declare units, %d mapped; want 10 and 10", declaring, len(rows))
	}
	for id, names := range rows {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil {
			t.Fatalf("%s: no remediation", id)
		}
		r := c.Remediation
		own := map[string]bool{}
		for _, n := range names {
			svc, ok := byName[n]
			if !ok {
				t.Fatalf("%s: no logical service %q", id, n)
			}
			for _, u := range svc.units {
				if u.provesInstall {
					own[u.name] = true
				}
			}
		}
		declared := map[string]bool{}
		for _, u := range r.Units {
			declared[u] = true
		}
		if !sameSet(declared, own) {
			t.Errorf("%s: units %v, want the provesInstall set %v", id, r.Units, keys(own))
		}
		inValidate := map[string]bool{}
		for _, u := range unitToken.FindAllString(r.Validate, -1) {
			inValidate[u] = true
		}
		if !sameSet(inValidate, own) {
			t.Errorf("%s: validate names %v, want %v", id, keys(inValidate), keys(own))
		}
		if us := unitToken.FindAllString(r.Script, -1); len(us) != 0 {
			t.Errorf("%s: script names %v literally; it must loop over $UNITS", id, us)
		}
		if strings.TrimSpace(r.Rollback) != "" {
			t.Errorf("%s: has a rollback; units are the way back", id)
		}
		for _, u := range append(append([]string{}, superServerExtraHostUnits...), "inetd.service", "xinetd.service") {
			if declared[u] {
				t.Errorf("%s: declares super-server unit %s", id, u)
			}
		}
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

  Imports become `regexp`, `sort`, `strings`, `testing` and `controls`.

  Write `internal/controls/file_validates_test.go`:

```go
package controls_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestFileValidatesAcceptTheDefaultModes pins 3D-2b §5: each file control's
// validate is one case over its stat format whose patterns are exactly its
// default modes, unpadded octal, behind a fixed owner prefix, ending *) false.
func TestFileValidatesAcceptTheDefaultModes(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string][2]string{ // id -> {stat format, owner prefix}
		"muster.file.hosts_permissions":     {"%u %g %a", "0 0"},
		"muster.file.hosts_lpd_permissions": {"%u %g %a", "0 0"},
		"muster.file.passwd_permissions":    {"%u %g %a", "0 0"},
		"muster.file.services_permissions":  {"%u %g %a", "0 0"},
		"muster.file.shadow_permissions":    {"%u %a", "0"},
	}
	if len(owners) != 5 {
		t.Fatal("five file controls")
	}
	for id, o := range owners {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil || len(c.Remediation.Backup) != 1 {
			t.Fatalf("%s: want one backup path", id)
		}
		var modes []any
		if p, ok := c.Params["allowed_modes"]; ok {
			modes = p.Default.([]any)
		} else {
			modes = modeClauseList(t, c) // passwd: the literal list of its mode clause
		}
		pats := make([]string, len(modes))
		for i, m := range modes {
			pats[i] = "'" + o[1] + " " + strconv.FormatInt(int64(toInt(t, m)), 8) + "'"
		}
		want := `case "$(stat -c '` + o[0] + `' ` + c.Remediation.Backup[0] + `)" in ` + strings.Join(pats, "|") + ") ;; *) false;; esac"
		if got := strings.TrimSuffix(c.Remediation.Validate, "\n"); got != want {
			t.Errorf("%s:\n got %s\nwant %s", id, got, want)
		}
	}
}
```

  Write `modeClauseList(t, c controls.Control) []any` and `toInt(t, v any) int` in the same file. The first finds the check whose `fact` ends `.mode` with `op: in` and returns its `Expected` as `[]any`; read `schema.go`'s check type for the field names. The second accepts `int`, `int64`, `uint64` and `float64`. If the YAML decoder yields a type it does not know, `t.Fatalf` with that type.

  Append to `internal/remedy/shipped_test.go`:

```go
// TestFileScriptsRepairOnARealFile runs each shipped file body on a temp copy
// owned 0:0 (root only; CI's sudo step runs it): at every allowed mode the
// validate holds; at a loosened mode it fails, the body runs, and it then
// holds; a file stricter than the guide keeps its mode (3D-2b Q-4).
func TestFileScriptsRepairOnARealFile(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown the temp file to 0:0")
	}
	cases := []struct {
		id       string
		allowed  []uint32 // numeric modes, special bits included (chmod takes them as octal)
		loosened []uint32
		stricter uint32
	}{
		{"muster.file.hosts_permissions", []uint32{0, 0o200, 0o400, 0o600}, []uint32{0o644, 0o666, 0o4600, 0o1600}, 0o400},
		{"muster.file.hosts_lpd_permissions", []uint32{0, 0o600}, []uint32{0o644, 0o2600}, 0o400},
		{"muster.file.passwd_permissions", []uint32{0o644, 0o444, 0o600}, []uint32{0o664, 0o666, 0o755}, 0o444},
		{"muster.file.services_permissions", []uint32{0o644, 0o400}, []uint32{0o666, 0o744}, 0o400},
		{"muster.file.shadow_permissions", []uint32{0, 0o400}, []uint32{0o640, 0o600, 0o4400}, 0},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			r := shippedRemediation(t, c.id)
			orig := r.Backup[0]
			bin := t.TempDir() // runBody prepends it to PATH; nothing is stubbed here
			// run sets the temp file to mode (and a wide ACL when acl), runs the
			// validate, the body and the validate again, and returns both exits
			// and the mode %a prints afterwards.
			run := func(mode uint32, acl bool) (pre, post int, after string) {
				dir := t.TempDir()
				f := filepath.Join(dir, "target")
				if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(f, 0, 0); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command("chmod", strconv.FormatUint(uint64(mode), 8), f).CombinedOutput(); err != nil {
					t.Fatalf("chmod %o: %v %s", mode, err, out)
				}
				if acl {
					if out, err := exec.Command("setfacl", "-m", "u:nobody:rw,g::rw", f).CombinedOutput(); err != nil {
						t.Fatalf("setfacl: %v %s", err, out)
					}
				}
				body := strings.ReplaceAll(r.Script, orig, f)
				val := strings.ReplaceAll(r.Validate, orig, f)
				_, pre = runBody(t, dir, bin, val)
				if out, code := runBody(t, dir, bin, body); code != 0 {
					t.Fatalf("body exit %d at %o: %s", code, mode, out)
				}
				_, post = runBody(t, dir, bin, val)
				out, err := exec.Command("stat", "-c", "%a", f).Output()
				if err != nil {
					t.Fatal(err)
				}
				return pre, post, strings.TrimSpace(string(out))
			}
			for _, m := range c.allowed {
				if pre, post, _ := run(m, false); pre != 0 || post != 0 {
					t.Errorf("allowed %o: validate %d before, %d after", m, pre, post)
				}
			}
			for _, m := range c.loosened {
				if pre, post, _ := run(m, false); pre == 0 || post != 0 {
					t.Errorf("loosened %o: validate %d before (want non-zero), %d after (want 0)", m, pre, post)
				}
			}
			if strings.Contains(r.Script, "setfacl") {
				if _, err := exec.LookPath("setfacl"); err == nil {
					if pre, post, _ := run(c.allowed[len(c.allowed)-1], true); pre == 0 || post != 0 {
						t.Errorf("acl: validate %d before (want non-zero), %d after (want 0)", pre, post)
					}
				}
			}
			if _, _, after := run(c.stricter, false); after != strconv.FormatUint(uint64(c.stricter), 8) {
				t.Errorf("stricter %o became %s", c.stricter, after)
			}
		})
	}
}
```

  `shipped_test.go` gains the imports `strconv` and `os/exec` if absent. The validates never accept a four-digit `%a`, so a special bit left behind is a failure. The ACL case uses the last allowed mode: `stat %a` of a file with an extended ACL prints the mask as the group bits, and the validate must fail until the script removes the ACL and clears the bits.

- [ ] **Step 2: Run** on the lab as root:

  ```
  go test ./internal/collect/collectors -run TestServiceScriptsNameTheCollectorsUnits -count=1
  go test ./internal/controls -run TestFileValidatesAcceptTheDefaultModes -count=1
  sudo env PATH="$PATH" go test ./internal/remedy -run TestFileScriptsRepairOnARealFile -count=1
  ```

  Expected: FAIL, because the current blocks name units literally, carry rollbacks and set absolute modes.

- [ ] **Step 3: Rewrite the ten service blocks.** Each keeps `text_en`, `text_ko`, `risk`, `idempotent: true` and its `validate` line unchanged. Each gains `units:` (the list below, in this order), replaces `script` with the loop, and deletes `rollback`:

```yaml
  units: [<U1>, <U2>, ...]
  script: |
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
```

| control | units |
|---|---|
| automount_disabled | `[autofs.service]` |
| dos_services_disabled | `[echo.socket, discard.socket, daytime.socket, chargen.socket]` |
| finger_disabled | `[finger.socket, fingerd.service]` |
| nfs_server_disabled | `[nfs-server.service, nfs-kernel-server.service]` |
| nis_disabled | `[ypserv.service, ypbind.service, ypxfrd.service, yppasswdd.service]` |
| rpcbind_disabled | `[rpcbind.socket, rpcbind.service]` |
| rservices_disabled | `[rsh.socket, rlogin.socket, rexec.socket]` |
| snmp_disabled | `[snmpd.service]` |
| telnet_disabled | `[telnet.socket, telnet.service, telnetd.service]` |
| tftp_talk_disabled | `[tftp.socket, tftp.service, tftpd.service, tftpd-hpa.service, atftpd.socket, atftpd.service, talk.socket, ntalk.socket]` |

  Automount and snmp drop their `if` form for the same loop.

- [ ] **Step 4: Rewrite the five file blocks.** `text_en`/`text_ko` keep their sentences and gain, after the first sentence, EN ` (the script only clears bits; a stricter file is left as it is)` and KO ` (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)`. Scripts and validates:

```yaml
# hosts_permissions
  script: |
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod u-xs,g-rwxs,o-rwxt /etc/hosts
  validate: "case \"$(stat -c '%u %g %a' /etc/hosts)\" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac"
# hosts_lpd_permissions
  script: |
    [ -f /etc/hosts.lpd ]
    chown root:root /etc/hosts.lpd
    chmod u-xs,g-rwxs,o-rwxt /etc/hosts.lpd
  validate: "case \"$(stat -c '%u %g %a' /etc/hosts.lpd)\" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac"
# passwd_permissions
  script: |
    [ -f /etc/passwd ]
    chown root:root /etc/passwd
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi
    chmod u-xs,g-wxs,o-wxt /etc/passwd
  validate: "case \"$(stat -c '%u %g %a' /etc/passwd)\" in '0 0 0'|'0 0 4'|'0 0 40'|'0 0 44'|'0 0 200'|'0 0 204'|'0 0 240'|'0 0 244'|'0 0 400'|'0 0 404'|'0 0 440'|'0 0 444'|'0 0 600'|'0 0 604'|'0 0 640'|'0 0 644') ;; *) false;; esac"
# services_permissions
  script: |
    [ -f /etc/services ]
    chown root:root /etc/services
    chmod u-xs,g-wxs,o-wxt /etc/services
  validate: "case \"$(stat -c '%u %g %a' /etc/services)\" in '0 0 0'|'0 0 4'|'0 0 40'|'0 0 44'|'0 0 200'|'0 0 204'|'0 0 240'|'0 0 244'|'0 0 400'|'0 0 404'|'0 0 440'|'0 0 444'|'0 0 600'|'0 0 604'|'0 0 640'|'0 0 644') ;; *) false;; esac"
# shadow_permissions
  script: |
    [ -f /etc/shadow ]
    chown root /etc/shadow
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/shadow; fi
    chmod u-wxs,g-rwxs,o-rwxt /etc/shadow
  validate: "case \"$(stat -c '%u %a' /etc/shadow)\" in '0 0'|'0 400') ;; *) false;; esac"
```

  Write the services validate in full, the same sixteen patterns with `/etc/services`. Set `controls/VERSION` to `kisa-unix-2026+2026.10.13`.

- [ ] **Step 5: Run** the three commands of Step 2 again, then:

  ```
  go run ./cmd/muster controls lint --references docs/reference
  go test ./internal/controls ./internal/check -count=1
  go run ./tools/coverage -check
  ```

  Expected: PASS and `ok:`. Then run `go test ./internal/remedy -count=1`. Expected: the `all-scripted` golden and `TestScriptAllScriptedCoversTheShippedSet` change. Regenerate with `-update` **only** for `all-scripted.sh`, read the diff (ten loops over `$UNITS`, no service rollbacks, symbolic chmods), and note that the `UNITS=` lines arrive in Task 6. On the lab, render each body through `sh -n`, and through `shellcheck -s sh` if the lab has it.
- [ ] **Step 6: Mutation check.** Put a literal `rpcbind.socket` back into the rpcbind script, see the pin test go red, and restore. Drop `*) false` from the hosts validate, see `TestFileValidatesAcceptTheDefaultModes` go red, and restore.
- [ ] **Step 7: Commit** "Declare the ten service controls' units and drop their rollbacks; clear file bits symbolically with validates over the default modes". The body names the VERSION bump, T-11 and "no judgment changed".

---

### Task 5: The plan — `HostGuard`, `Units`, the `units` rollback value

**Files:**
- Modify: `internal/remedy/plan.go:27-38` (FixBlock), `43-67` (Item), `129-138` (fill), `162-168` (unit check), `228-240` (rollback switch)
- Test: `internal/remedy/plan_test.go` (`TestPlanCopiesProvenance` ~271-298, `TestPlanItemCopiesEveryField` ~353-371, `TestPlanRollbackVocabulary` ~153-197, `TestPlanJSONShape` ~393-443, new `TestPlanHostGuard`, new `TestPlanRefusesAnUnsafeUnit`)
- Modify: `internal/remedy/fixture_test.go:42-98` (T-8: `g_units`)

**Interfaces:**
- Consumes: `controls.ValidUnitName` (Task 3).
- Produces:
  - `FixBlock.HostGuard string` (`json:"host_guard"`, `"on"`|`"off"`, after `MaxRisk`);
  - `FixBlock.MachineIDHash string` (`json:"-"`);
  - `Item.Units []string` (`json:"units"`, after `Backup`, `[]` when none);
  - `Item.Rollback` gains `"units"`.

- [ ] **Step 1: Write the failing tests.** Add `g_units` to `testControls` (T-8). Write its YAML with the same `controlHead` shape as `b_restart` and this remediation:

```yaml
remediation:
  text_en: t
  text_ko: 조치
  risk: restart_service
  idempotent: true
  units: [g.socket, g.service]
  script: |
    for u in $UNITS; do systemctl --quiet disable --now "$u"; done
  validate: "! systemctl is-active --quiet g.service"
```

  In `plan_test.go`:

```go
func TestPlanHostGuard(t *testing.T) {
	h := strings.Repeat("c", 64) // any 64 lowercase hex
	for _, c := range []struct{ in, guard, hash string }{
		{h, "on", h},
		{"", "off", ""},
		{strings.ToUpper(h), "off", ""},
		{h[:63], "off", ""},
		{h + "'; id; '", "off", ""},
	} {
		rep := testReport(row("muster.test.a_none", "FAIL", "r", "", "high"))
		rep.Run.Host.MachineIDHash = c.in
		p := build(t, rep, Options{})
		if p.Fix.HostGuard != c.guard || p.Fix.MachineIDHash != c.hash {
			t.Errorf("hash %q: guard %q hash %q, want %q %q", c.in, p.Fix.HostGuard, p.Fix.MachineIDHash, c.guard, c.hash)
		}
	}
}

func TestPlanRefusesAnUnsafeUnit(t *testing.T) {
	set := testSet(t)
	for i := range set.Controls {
		if set.Controls[i].ID == "muster.test.g_units" {
			set.Controls[i].Remediation.Units = []string{"g.socket", "x';id;'.service"}
		}
	}
	_, err := Build(testReport(row("muster.test.g_units", "FAIL", "r", "", "high")), set, Options{})
	if err == nil || !strings.Contains(err.Error(), `refusing to plan muster.test.g_units: unit "x';id;'.service"`) {
		t.Fatalf("err = %v", err)
	}
}
```

  (`testReport` and `testSet` are the fixture helpers; if `Build` needs a report from `scriptReport`, use the helper `TestPlanRefusesAnUnexpectedID` uses at `plan_test.go:213-230`.) Extend `TestPlanRollbackVocabulary`'s `want` with `"muster.test.g_units": {rollback: "units", backup: 0, script: true, validate: true}` (match the existing struct's fields), and add its FAIL row to the report the test builds. Extend `TestPlanJSONShape` to assert that a text-only item's JSON has `"units": []`, that `g_units` has `"units": ["g.socket", "g.service"]`, and that `fix.host_guard` exists. Update `TestPlanCopiesProvenance`'s `want` with `HostGuard: "off"` and `TestPlanItemCopiesEveryField`'s `want` with `Units: []string{}`.

- [ ] **Step 2: Run** `go test ./internal/remedy -run 'TestPlan' -count=1`. Expected: FAIL (unknown fields).
- [ ] **Step 3: Implement.** In `FixBlock`, after `MaxRisk`:

```go
	HostGuard       string              `json:"host_guard"` // on | off (3D-2b Q-1)
	MachineIDHash   string              `json:"-"`          // the snapshot's, when well formed; the script's guard compares it
```

  In `Item`, after `Backup`: `Units []string \`json:"units"\``. Update the `Rollback` comment to `none | declared | restore_backup | units | both`. In `Build`'s FixBlock fill:

```go
	hash, guard := "", "off"
	if machineHashRe.MatchString(rep.Run.Host.MachineIDHash) {
		hash, guard = rep.Run.Host.MachineIDHash, "on"
	}
```

  Set `HostGuard: guard, MachineIDHash: hash`. Declare `var machineHashRe = regexp.MustCompile(\`^[0-9a-f]{64}$\`)` (add `regexp` to the imports). After `p.Items = append(p.Items, item(row, set, cb, maxRank))`, check the units:

```go
			for _, u := range p.Items[len(p.Items)-1].Units {
				if !controls.ValidUnitName(u) {
					return nil, fmt.Errorf("refusing to plan %s: unit %q is not a unit name a script can carry", row.ID, u)
				}
			}
```

  In `item()`, the text-only initialiser gains `Units: []string{}`. The script branch sets `it.Units = append([]string{}, r.Units...)`, and its switch becomes:

```go
		hasRB, hasBK, hasU := strings.TrimSpace(r.Rollback) != "", len(r.Backup) > 0, len(r.Units) > 0
		switch {
		case hasRB && hasBK:
			it.Rollback = "both"
		case hasU:
			it.Rollback = "units"
		case hasRB:
			it.Rollback = "declared"
		default:
			it.Rollback = "restore_backup"
		}
```

- [ ] **Step 4: Run** `go test ./internal/remedy -count=1`. Expected: the plan tests PASS. Goldens (`full.json`, `full.table`, `full.sh`, `all-scripted.sh`) and the count assertions that include `g_units` fail.
  - Fix the counts: in `TestScriptBlocksAreIndependent`, scripted goes 3 → 4. Fix every count the new item moves, and nothing else.
  - Run `go test ./internal/remedy -run 'TestTableGolden|TestJSONGolden' -update`, read the diff (one `g_units` item, `units` arrays, `host_guard: "off"`), and run again without `-update`.
  - `TestScriptGolden` stays red until Task 6. Note it, and do not update `.sh` goldens here.
- [ ] **Step 5: Mutation check.** Return `guard = "on"` unconditionally, see `TestPlanHostGuard` go red, and restore. Remove the unit loop in `Build`, see `TestPlanRefusesAnUnsafeUnit` go red, and restore.
- [ ] **Step 6: Commit** "Plan the host guard and each item's units: on only for a well-formed hash, the units rollback, unsafe unit names refused". The body names T-3, T-4 and T-8, and notes that the script goldens are red until the next commit.

---

### Task 6: The script — prologue, guard, unit helpers, `# validate`

**Files:**
- Modify: `internal/remedy/script.go` (whole prologue; `failurePath` 106-120; `block` 125-172)
- Test: `internal/remedy/script_test.go` (`templateLines` 306-335, `runScriptStreams` 457-497, `fullPlan` 52-71, `poisonPlan` 133-158, new tests)
- Test: `internal/remedy/hostguard_test.go` (new; imports `internal/collect/collectors`, untagged per T-10)
- Test: `internal/remedy/units_test.go` (new)
- Goldens: `internal/remedy/testdata/*.sh`

**Interfaces:**
- Consumes: `FixBlock.MachineIDHash`, `FixBlock.HostGuard`, `Item.Units` (Task 5); `collectors.MachineIDHash` (Task 2).
- Produces:
  - `const MachineIDHashHelper string`;
  - `func prologue(p *Plan) string`;
  - the template lines `MUSTER_SNAPSHOT_HOST=<64 hex>`, `# host guard: off (the snapshot has no machine id)`, `  save_units <u…> || { log "<id>: backup failed, nothing changed"; return 1; }`, `    UNITS='<u…>'`, `    restore_units <u…> || log "<id>: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`, `  # validate`.

- [ ] **Step 1: Write the failing tests.** In `script_test.go`:
  - `fullPlan` sets `rep.Run.Host.MachineIDHash` to the sha256 of `0123456789abcdef0123456789abcdef` (compute it in the test with `crypto/sha256`, T-8).
  - `poisonPlan` sets it to `"'; id; '" + strings.Repeat("a", 56)` and asserts `p.Fix.HostGuard == "off"`.
  - `templateLines(p)` starts from `strings.Split(prologue(p)+epilogue, "\n")`. Per item with `Units` it adds the `save_units`, `UNITS=` and `restore_units` lines in their exact rendered forms, and per item with `Validate` it adds `"  # validate"`.
  - `TestScriptEveryLineIsTemplateBodyOrComment` additionally requires that the only non-comment line containing a 64-hex run is `MUSTER_SNAPSHOT_HOST=<p.Fix.MachineIDHash>`, and that the poison hash string never appears on a non-comment line.
  - Add `runOpts`/`runScriptWith` (T-7). `runScriptStreams` becomes `runScriptWith(t, p, dir, backupDir, runOpts{})`, and the env is built from `os.Environ()` minus any `MUSTER_ANY_HOST=` entry.

```go
type runOpts struct {
	replace    [][2]string // applied to the rendered script, each must change it
	pathPrefix string      // prepended to PATH
	env        []string
}
```

  New tests in `script_test.go`:

```go
func TestScriptGuardOffWithoutAHash(t *testing.T) {
	s := string(Script(emptyPlan(t)))
	if !strings.Contains(s, "\n# host guard: off (the snapshot has no machine id)\n") || strings.Contains(s, "muster_machine_id_hash") || strings.Contains(s, "MUSTER_SNAPSHOT_HOST") {
		t.Fatalf("guard-off prologue wrong:\n%s", s)
	}
}

func TestScriptPrologueOrder(t *testing.T) {
	s := string(Script(fullPlan(t)))
	order := []string{"set -u\n", "umask 077\n", "log() {", "muster_machine_id_hash() {", rootCheckLine, "MUSTER_SNAPSHOT_HOST=", `MUSTER_BACKUP="${MUSTER_BACKUP:-`, `mkdir -p "$MUSTER_BACKUP" || exit 2`, backupOwnerLine, "backup() {", "restore() {", "save_units() {", "restore_units() {", "failed=0\n"}
	at := 0
	for _, o := range order {
		i := strings.Index(s[at:], o)
		if i < 0 {
			t.Fatalf("prologue: %q missing or out of order", o)
		}
		at += i + len(o)
	}
}

func TestScriptUnitsBlockOrder(t *testing.T) {
	ls := lines(Script(fullPlan(t)))
	fn := fnName("muster.test.g_units")
	in, saw := false, map[string]int{}
	for i, l := range ls {
		if l == fn+"() {" {
			in = true
		}
		if !in {
			continue
		}
		switch {
		case strings.HasPrefix(l, "  save_units g.socket g.service || "):
			saw["save"] = i
		case l == "    UNITS='g.socket g.service'":
			if ls[i-1] != "  ( set -e" {
				t.Errorf("UNITS= not the first body line: after %q", ls[i-1])
			}
			saw["units"] = i
		case strings.HasPrefix(l, "    restore_units g.socket g.service || log "):
			saw["restore"]++
		case l == "  # validate":
			if ls[i+1] != "  ( set -e" {
				t.Errorf("# validate not before the validate subshell")
			}
			saw["marker"] = i
		case l == "}":
			in = false
		}
	}
	if saw["save"] == 0 || saw["units"] <= saw["save"] || saw["restore"] != 2 || saw["marker"] == 0 {
		t.Fatalf("units block shape: %v", saw)
	}
}
```

  `hostguard_test.go`:

```go
package remedy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect/collectors"
)

// TestHostGuardHashMatchesTheCollector pins 3D-2b §2: on every id the
// collector hashes, the script's helper computes the same value; on every id
// it refuses, both yield nothing.
func TestHostGuardHashMatchesTheCollector(t *testing.T) {
	needSh(t)
	const id = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	helper := filepath.Join(dir, "h.sh")
	if err := os.WriteFile(helper, []byte(MachineIDHashHelper+"\nmuster_machine_id_hash \"$1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, content string
		missing       bool
	}{
		{"trailing LF", id + "\n", false}, {"CRLF", id + "\r\n", false}, {"leading blanks", "  " + id, false}, {"leading LF", "\n" + id, false},
		{"uninitialized", "uninitialized\n", false}, {"uppercase", strings.ToUpper(id), false}, {"31", id[:31], false},
		{"interior space", id[:16] + " " + id[16:], false}, {"whitespace", " \n", false}, {"empty", "", false}, {"missing", "", true},
	} {
		p := filepath.Join(dir, "mid-"+strings.ReplaceAll(c.name, " ", "_"))
		if !c.missing {
			if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("sh", helper, p).Output()
		if err != nil {
			t.Fatalf("%s: helper: %v", c.name, err)
		}
		want := ""
		if !c.missing {
			want = collectors.MachineIDHash([]byte(c.content))
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s: helper %q, collector %q", c.name, got, want)
		}
	}
}

func guardPlan(t *testing.T, hash string) *Plan {
	t.Helper()
	return &Plan{Fix: FixBlock{MaxRisk: "lockout_risk", HostGuard: "on", MachineIDHash: hash}}
}

func TestScriptRefusesAnotherHost(t *testing.T) {
	needSh(t)
	const id = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(mid, []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	same := collectors.MachineIDHash([]byte(id))
	other := strings.Repeat("b", 64)
	repl := runOpts{replace: [][2]string{{"muster_machine_id_hash /etc/machine-id", "muster_machine_id_hash " + mid}}}
	const refusal = "muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n"

	backup := filepath.Join(dir, "bk-same")
	if _, _, code := runScriptWith(t, guardPlan(t, same), dir, backup, repl); code != 0 {
		t.Fatalf("same host: exit %d", code)
	}
	backup = filepath.Join(dir, "bk-other")
	_, stderr, code := runScriptWith(t, guardPlan(t, other), dir, backup, repl)
	if code != 2 || stderr != refusal || exists(backup) {
		t.Fatalf("other host: exit %d stderr %q backup created %v", code, stderr, exists(backup))
	}
	o := repl
	o.env = []string{"MUSTER_ANY_HOST=1"}
	all, _, code := runScriptWith(t, guardPlan(t, other), dir, filepath.Join(dir, "bk-any"), o)
	if code != 0 || !strings.Contains(all, "muster-fix: warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1") {
		t.Fatalf("override: exit %d out %q", code, all)
	}
	missing := runOpts{replace: [][2]string{{"muster_machine_id_hash /etc/machine-id", "muster_machine_id_hash " + filepath.Join(dir, "none")}}}
	_, stderr, code = runScriptWith(t, guardPlan(t, same), dir, filepath.Join(dir, "bk-missing"), missing)
	if code != 2 || stderr != refusal {
		t.Fatalf("missing id: exit %d stderr %q", code, stderr)
	}
}
```


  `units_test.go` holds the stub, the plan and the two tests:

```go
package remedy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// systemctlStub stands in for systemctl in the unit-helper tests: one state
// file per unit under $STUB/state/<u> ("<enabled> <active>"), every call
// appended to $STUB/calls. noinstall/<u> makes enable a silent no-op (a unit
// with no [Install] section), also/<u> names a partner enable turns on,
// deps/<u> the units that stopping <u> stops, fail/<u> makes mask fail.
const systemctlStub = `printf '%s\n' "$*" >> "$STUB/calls"
q= rt= now= verb= u=
for a in "$@"; do
  case "$a" in
    --quiet) q=1;; --runtime) rt=1;; --now) now=1;;
    --|--value|-p|RequiredBy|BoundBy|ConsistsOf) ;;
    *) if [ -z "$verb" ]; then verb=$a; else u=$a; fi;;
  esac
done
f="$STUB/state/$u"
get() { [ -f "$f" ] || return 1; read -r se sa < "$f"; }
put() { printf '%s %s\n' "$1" "$2" > "$f"; }
case "$verb" in
  cat) [ -f "$f" ];;
  is-enabled) get || { echo not-found; exit 1; }; echo "$se"; case "$se" in enabled|enabled-runtime) exit 0;; esac; exit 1;;
  is-active) get || { [ -n "$q" ] || echo inactive; exit 3; }; [ -n "$q" ] || echo "$sa"; [ "$sa" = active ];;
  show) if [ -f "$STUB/deps/$u" ]; then cat "$STUB/deps/$u"; fi;;
  enable) get || exit 1; [ -f "$STUB/noinstall/$u" ] && exit 0
    case "$se" in masked*) exit 1;; esac
    if [ -n "$rt" ]; then put enabled-runtime "$sa"; else put enabled "$sa"; fi
    if [ -f "$STUB/also/$u" ]; then p=$(cat "$STUB/also/$u"); read -r pe pa < "$STUB/state/$p"; printf 'enabled %s\n' "$pa" > "$STUB/state/$p"; fi;;
  disable) get || exit 1
    if [ -n "$now" ]; then put disabled inactive; else put disabled "$sa"; fi
    if [ -n "$now" ] && [ -f "$STUB/deps/$u" ]; then
      for d in $(cat "$STUB/deps/$u"); do read -r de da < "$STUB/state/$d"; printf '%s inactive\n' "$de" > "$STUB/state/$d"; done
    fi;;
  mask) [ -f "$STUB/fail/$u" ] && exit 1; get || exit 1
    if [ -n "$rt" ]; then put masked-runtime "$sa"; else put masked "$sa"; fi;;
  unmask) get || exit 1; case "$se" in masked*) put disabled "$sa";; esac;;
  start) get || exit 1; case "$se" in masked*) exit 1;; esac; put "$se" active;;
  *) exit 1;;
esac
`

func unitsPlan(units []string) *Plan {
	return &Plan{Fix: FixBlock{MaxRisk: "lockout_risk", HostGuard: "off"}, Items: []Item{{
		ID: "muster.test.u", Risk: "restart_service", Status: "fail", Severity: "high",
		Script: true, Planned: true, Units: units, Backup: []string{}, Rollback: "units",
		ScriptBody:  "for u in $UNITS; do\n  systemctl --quiet disable --now -- \"$u\"\n  systemctl --quiet mask -- \"$u\" || true\ndone\nfalse\n",
		Validate:    true,
		ValidateCmd: "true",
	}}}
}

// newStub returns the stub's bin directory (put first on PATH) and its state root.
func newStub(t *testing.T, before map[string]string) (bin, stub string) {
	t.Helper()
	bin, stub = t.TempDir(), t.TempDir()
	writeStub(t, bin, "systemctl", systemctlStub)
	for u, s := range before {
		write(t, stub, "state/"+u, s)
	}
	return bin, stub
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func touch(t *testing.T, root, rel string) { t.Helper(); write(t, root, rel, "") }

func state(t *testing.T, stub, u string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stub, "state", u))
	if err != nil {
		return "absent"
	}
	return strings.TrimSpace(string(b))
}

// TestUnitHelpersRestoreRecordedState drives each recorded state through a
// failed units block against the stub and checks the end state and the
// logs (3D-2b §3).
func TestUnitHelpersRestoreRecordedState(t *testing.T) {
	needSh(t)
	cases := []struct {
		name     string
		units    []string
		before   map[string]string // unit -> "<enabled> <active>"
		setup    func(t *testing.T, stub string)
		after    map[string]string // nil: only the logs and the failure are checked
		logs     []string
		wantFail bool // ROLLBACK INCOMPLETE expected
	}{
		{"enabled active", []string{"a.service"}, map[string]string{"a.service": "enabled active"}, nil, map[string]string{"a.service": "enabled active"}, nil, false},
		{"enabled-runtime", []string{"a.service"}, map[string]string{"a.service": "enabled-runtime active"}, nil, map[string]string{"a.service": "enabled-runtime active"}, nil, false},
		{"disabled active", []string{"a.service"}, map[string]string{"a.service": "disabled active"}, nil, map[string]string{"a.service": "disabled active"}, nil, false},
		{"masked", []string{"a.service"}, map[string]string{"a.service": "masked inactive"}, nil, map[string]string{"a.service": "masked inactive"}, nil, false},
		{"masked-runtime", []string{"a.service"}, map[string]string{"a.service": "masked-runtime inactive"}, nil, map[string]string{"a.service": "masked-runtime inactive"}, nil, false},
		{"masked active", []string{"a.service"}, map[string]string{"a.service": "masked active"}, nil, map[string]string{"a.service": "masked inactive"}, nil, false},
		{"linked", []string{"a.service"}, map[string]string{"a.service": "linked active"}, nil, nil, []string{"a.service: was linked; the link is not restored"}, true},
		{"static", []string{"a.service"}, map[string]string{"a.service": "static active"}, nil, nil, []string{"a.service: enablement not restored (was static, now disabled)"}, true},
		{"absent", []string{"a.service"}, map[string]string{}, nil, map[string]string{"a.service": "absent"}, nil, false},
		{"no install section", []string{"a.service"}, map[string]string{"a.service": "enabled active"}, func(t *testing.T, s string) { touch(t, s, "noinstall/a.service") }, nil, []string{"a.service: enablement not restored (was enabled, now disabled)"}, true},
		{"also partner", []string{"a.socket", "a.service"}, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled active"}, func(t *testing.T, s string) { write(t, s, "also/a.service", "a.socket") }, map[string]string{"a.socket": "disabled inactive", "a.service": "enabled active"}, nil, false},
		{"masked socket enabled service", []string{"a.socket", "a.service"}, map[string]string{"a.socket": "masked inactive", "a.service": "enabled active"}, nil, map[string]string{"a.socket": "masked inactive", "a.service": "enabled active"}, nil, false},
		{"dependant restarted", []string{"a.service"}, map[string]string{"a.service": "enabled active", "dep.service": "enabled active"}, func(t *testing.T, s string) { write(t, s, "deps/a.service", "dep.service") }, map[string]string{"a.service": "enabled active", "dep.service": "enabled active"}, nil, false},
		{"mask fails", []string{"a.service"}, map[string]string{"a.service": "masked inactive"}, func(t *testing.T, s string) { touch(t, s, "fail/a.service") }, nil, []string{"muster.test.u: ROLLBACK INCOMPLETE"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bin, stub := newStub(t, c.before)
			if c.setup != nil {
				c.setup(t, stub)
			}
			dir := t.TempDir()
			all, _, code := runScriptWith(t, unitsPlan(c.units), dir, filepath.Join(dir, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub}})
			if code != 1 || !strings.Contains(all, "muster.test.u: script failed (rc 1), rolling back") {
				t.Fatalf("exit %d, want 1 with the script-failed line:\n%s", code, all)
			}
			for _, l := range c.logs {
				if !strings.Contains(all, l) {
					t.Errorf("output lacks %q:\n%s", l, all)
				}
			}
			if got := strings.Contains(all, "ROLLBACK INCOMPLETE"); got != c.wantFail {
				t.Errorf("ROLLBACK INCOMPLETE %v, want %v:\n%s", got, c.wantFail, all)
			}
			for u, want := range c.after {
				if got := state(t, stub, u); got != want {
					t.Errorf("%s: %q, want %q", u, got, want)
				}
			}
		})
	}
}

// TestUnitHelpersKeepTheFirstRecord pins the first-record rule and its one
// exception: a record of an absent unit is rewritten once the unit exists.
func TestUnitHelpersKeepTheFirstRecord(t *testing.T) {
	needSh(t)
	dir := t.TempDir()
	bk := filepath.Join(dir, "bk")
	bin, stub := newStub(t, map[string]string{"a.service": "enabled active"})
	opts := runOpts{pathPrefix: bin, env: []string{"STUB=" + stub}}
	if _, _, code := runScriptWith(t, unitsPlan([]string{"a.service"}), dir, bk, opts); code != 1 {
		t.Fatalf("first run exit %d", code)
	}
	write(t, stub, "state/a.service", "disabled inactive") // the operator changed it between runs
	all, _, code := runScriptWith(t, unitsPlan([]string{"a.service"}), dir, bk, opts)
	if code != 1 || !strings.Contains(all, "a.service: unit state exists, keeping the first") || state(t, stub, "a.service") != "enabled active" {
		t.Fatalf("second run: exit %d state %q:\n%s", code, state(t, stub, "a.service"), all)
	}

	bk2 := filepath.Join(dir, "bk2")
	bin2, stub2 := newStub(t, map[string]string{})
	opts2 := runOpts{pathPrefix: bin2, env: []string{"STUB=" + stub2}}
	if _, _, code := runScriptWith(t, unitsPlan([]string{"b.service"}), dir, bk2, opts2); code != 1 {
		t.Fatalf("absent run exit %d", code)
	}
	write(t, stub2, "state/b.service", "enabled active") // installed between runs
	all, _, code = runScriptWith(t, unitsPlan([]string{"b.service"}), dir, bk2, opts2)
	if code != 1 || strings.Contains(all, "b.service: unit state exists") || state(t, stub2, "b.service") != "enabled active" {
		t.Fatalf("absent then present: exit %d state %q:\n%s", code, state(t, stub2, "b.service"), all)
	}
}
```

  `writeStub` writes `#!/bin/sh\n` + body at 0o755 (`shipped_test.go:51`). `runScriptWith` puts `pathPrefix` first on `PATH`. If `write`/`touch` collide with existing helper names in the package, rename them `stubWrite`/`stubTouch`.

- [ ] **Step 2: Run** `go test ./internal/remedy -count=1` (Windows compiles; the Linux subtests skip) and on the lab. Expected: FAIL (`undefined: prologue`, `undefined: MachineIDHashHelper`, missing lines).
- [ ] **Step 3: Implement `script.go`.** Replace the `prologue` const with pieces and a builder:

```go
// MachineIDHashHelper computes the host identity the snapshot carries
// (collectors.MachineIDHash): the sha256 of a 32-lowercase-hex machine id,
// nothing for anything else. Its errors go nowhere: the guard's refusal is
// the only line a failure prints (3D-2b §2).
const MachineIDHashHelper = `muster_machine_id_hash() {
  id=$( { tr -d '[:space:]' < "$1"; } 2>/dev/null ) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  { printf '%s' "$id" | sha256sum | cut -d' ' -f1; } 2>/dev/null
}`

const guardOff = "# host guard: off (the snapshot has no machine id)"

const guardBody = `here=$(muster_machine_id_hash /etc/machine-id)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi`
```

  `prologueHead` is `set -u`, `umask 077` and `log() { printf 'muster-fix: %s\n' "$*"; }`. `prologueBackup` is the `MUSTER_BACKUP` default, the `case`, the `mkdir`, `backupOwnerLine`, `backup()` and `restore()`; in `restore()` rename `rc` to `brc` (T-6). `unitHelpers` is the two functions of spec §3, verbatim. Then:

```go
// prologue is the script's fixed part for this plan (3D-2b §2 order): the
// guard and its helper only when the snapshot carried a well-formed hash.
func prologue(p *Plan) string {
	var b strings.Builder
	b.WriteString(prologueHead + "\n")
	if p.Fix.HostGuard == "on" {
		b.WriteString(MachineIDHashHelper + "\n" + rootCheckLine + "\n")
		b.WriteString("MUSTER_SNAPSHOT_HOST=" + p.Fix.MachineIDHash + "\n" + guardBody + "\n")
	} else {
		b.WriteString(rootCheckLine + "\n" + guardOff + "\n")
	}
	b.WriteString(prologueBackup + "\n" + unitHelpers + "\nfailed=0\n")
	return b.String()
}
```

  `HostGuard == "on"` is only ever set with a hash that matched `^[0-9a-f]{64}$` (Task 5). `Script` writes `prologue(p)` where it wrote the const.

  In `block()`, after the backup line:

```go
		if len(it.Units) > 0 {
			lines = append(lines, fmt.Sprintf(`  save_units %s || { log "%s: backup failed, nothing changed"; return 1; }`, strings.Join(it.Units, " "), it.ID))
		}
		lines = append(lines, "  ( set -e")
		if len(it.Units) > 0 {
			lines = append(lines, "    UNITS='"+strings.Join(it.Units, " ")+"'")
		}
```

  Before the validate subshell: `lines = append(lines, "  # validate", "  ( set -e", …)`. In `failurePath`, after the rollback subshell and before the restore line:

```go
	if len(it.Units) > 0 {
		out = append(out, fmt.Sprintf(`%srestore_units %s || log "%s: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`, pfx, strings.Join(it.Units, " "), it.ID))
	}
```

- [ ] **Step 4: Run.**
  1. `go test ./internal/remedy -run TestScriptGolden -update`.
  2. Read every golden diff:
     - the prologue order;
     - `full.sh` guard-on with the fixture hash;
     - `empty.sh`, `capped.sh` and `poison.sh` guard-off;
     - the `# validate` markers;
     - `g_units`' `save_units`/`UNITS=`/`restore_units`;
     - `all-scripted.sh`'s ten `UNITS=` lines;
     - `restore()`'s `brc`.
  3. Run `go test ./internal/remedy -count=1` (Windows), then as root on the lab with `-race`, then `make shellcheck` on the lab (or note that CI covers it).
- [ ] **Step 5: Mutation check.**
  1. Emit the guard before `log()` (swap the two writes), and see `TestScriptPrologueOrder` and `TestScriptRefusesAnotherHost`'s override assertion go red.
  2. Drop pass 7 from `unitHelpers`, and see the `no install section` case go red.
  3. Drop the `# validate` marker, and see `TestScriptUnitsBlockOrder` go red.

  Restore each.
- [ ] **Step 6: Commit** "Guard the review script by the snapshot's machine id, record and restore unit state, and mark every validate". The body names T-5, T-6 and T-7, the prologue order, and "goldens regenerated: prologue, guard, units, markers".

---

### Task 7: Escape spells out the format class; `fix` e2e for the guard

**Files:**
- Modify: `internal/report/table.go:57-74` (`escapeRune`, new `SpelledOut`)
- Test: `internal/report/table_test.go` (new `TestEscapeSpellsOutBidiAndSeparators`; extend `TestTablePoisonedSnapshotWritesNoRawControlBytes` ~221-270)
- Test: `internal/remedy/render_test.go` (`TestTablePoisoned` ~54-73), `internal/remedy/script_test.go` (`poisonControls` text gains the runes)
- Test: `cmd/muster/fix_test.go` (new `TestFixHostGuard`)

**Interfaces:**
- Produces: `func SpelledOut(r rune) bool`, which is true for `unicode.Cf`, `unicode.Zl`, `unicode.Zp`, U+115F, U+1160, U+3164 and U+FFA0.

- [ ] **Step 1: Write the failing tests.**

```go
var spelledSample = []rune{0x00ad, 0x061c, 0x200b, 0x200d, 0x202e, 0x2028, 0x2029, 0x2066, 0xfeff, 0x3164, 0xe0001}

func TestEscapeSpellsOutBidiAndSeparators(t *testing.T) {
	for _, r := range spelledSample {
		if !SpelledOut(r) {
			t.Errorf("U+%04X not spelled out", r)
		}
		got := Escape(string(r))
		want := fmt.Sprintf(`\u%04x`, r)
		if r > 0xffff {
			want = fmt.Sprintf(`\U%08x`, r)
		}
		if got != want {
			t.Errorf("Escape(U+%04X) = %q, want %q", r, got, want)
		}
	}
	if Escape("한글 a") != "한글 a" || SpelledOut('한') {
		t.Error("plain Hangul and ASCII must pass through")
	}
}
```

  In `TestTablePoisonedSnapshotWritesNoRawControlBytes`, make the poison string `poison + string(spelledSample)` for this test only (keep the shared `poison` const). After the existing byte checks, assert `!strings.ContainsRune(out, r)` for each rune of `spelledSample`. In remedy, define a `spelledSample` of its own with the same eleven runes (T-9). Append them to `poisonControls`' `text_en` (YAML `\u` escapes; `\U000E0001` for the tag rune) and to the poisoned row reason. `TestTablePoisoned` and `TestScriptEveryLineIsTemplateBodyOrComment` assert `report.SpelledOut(r)` and that no raw rune appears.

  `fix_test.go`:

```go
func TestFixHostGuard(t *testing.T) {
	raw, err := os.ReadFile(fullFail)
	if err != nil {
		t.Fatal(err)
	}
	h := strings.Repeat("c", 64)
	with := bytes.Replace(raw, []byte(`"hostname":`), []byte(`"machine_id_hash":"`+h+`","hostname":`), 1)
	if bytes.Equal(with, raw) {
		t.Fatal("fixture has no hostname key to anchor on")
	}
	p := filepath.Join(t.TempDir(), "h.json")
	if err := os.WriteFile(p, with, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := planJSON(t, "--dry-run", "--facts", p, "--format", "json").Fix.HostGuard; got != "on" {
		t.Errorf("with hash: host_guard %q", got)
	}
	if got := planJSON(t, "--dry-run", "--facts", fullFail, "--format", "json").Fix.HostGuard; got != "off" {
		t.Errorf("without hash: host_guard %q", got)
	}
	code, out, _ := runFixArgs(t, "--dry-run", "--facts", p, "--format", "script")
	if code != 0 || !bytes.Contains(out, []byte("\nMUSTER_SNAPSHOT_HOST="+h+"\n")) {
		t.Fatalf("script: exit %d, guard line missing", code)
	}
}
```

  If `full-fail.json` is compact JSON with a different key spelling, anchor the replace the way `hostsCopy` does (`fix_test.go:55-73`).

- [ ] **Step 2: Run** `go test ./internal/report ./internal/remedy ./cmd/muster -run 'Escape|Poison|HostGuard' -count=1`. Expected: FAIL (`undefined: SpelledOut`; the runes pass through raw).
- [ ] **Step 3: Implement.** In `table.go` import `unicode`:

```go
// SpelledOut reports whether Escape writes r as an escape rather than the rune
// itself, beyond the C0/C1 controls: every format rune (bidirectional controls,
// zero-width runes, the tag block), the line and paragraph separators, and the
// Hangul fillers that render as nothing (3D-2b Q-5).
func SpelledOut(r rune) bool {
	switch r {
	case 0x115f, 0x1160, 0x3164, 0xffa0:
		return true
	}
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}
```

  In `escapeRune`, add the case `case SpelledOut(r) && r > 0xffff: fmt.Fprintf(b, \`\U%08x\`, r)` and the case `case SpelledOut(r): fmt.Fprintf(b, \`\u%04x\`, r)` before `default`. Keep the existing cases first.

- [ ] **Step 4: Run.**
  1. `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden' -update` (the poison goldens gain the escapes). Read the diff.
  2. `go test ./... -count=1 -skip TestExamplesLoadAndCheck`. Expected: PASS.
  3. `go test ./cmd/muster -run TestExamplesLoadAndCheck -count=1`, and quote its failure (the fix examples differ until the refresh).
- [ ] **Step 5: Mutation check.** Return `false` from `SpelledOut`, and see `TestEscapeSpellsOutBidiAndSeparators` and both poison tests go red. Restore.
- [ ] **Step 6: Commit** "Spell out the format runes, separators and Hangul fillers wherever text is escaped, and test fix's host guard end to end". The body names T-9 and the CHANGELOG "Changed" entry.

---

### Task 8: CI — the round-trip table, seed scripts, the Debian row, the failure and guard runs

**Files:**
- Create: `controls/testdata/_roundtrip.yaml` (from Task 1's `probe.md`)
- Create: `internal/controls/roundtrip_test.go` (package `controls_test`)
- Create: `ci/roundtrip/wait.sh`, `ci/roundtrip/rocky9-init.sh`, `ci/roundtrip/almalinux9-init.sh`, `ci/roundtrip/ubuntu2204.sh`, `ci/roundtrip/debian12-init.sh`, `ci/roundtrip/debian12-init.Dockerfile`
- Modify: `.github/workflows/ci.yml` (shellcheck step L29-43; the `fix-roundtrip` job L499-566)
- Modify: `Makefile:49-54`

**Interfaces:**
- Consumes: the table decided in Task 1; the `# validate` marker and `host_guard` (Task 6).

- [ ] **Step 1: Write the failing test** `roundtrip_test.go`:

```go
package controls_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/controls"
)

type roundtripEntry struct {
	ID            string            `yaml:"id"`
	Images        []string          `yaml:"images"`
	UnprovenUnits map[string]string `yaml:"unproven_units"`
	Unproven      string            `yaml:"unproven"`
}

type matrixRow struct {
	Key, Image, Init, Seeded, Build string
}

func TestEveryScriptedControlIsInTheRoundtripTable(t *testing.T) {
	raw, err := os.ReadFile(fixtureRoot + "/_roundtrip.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var table []roundtripEntry
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&table); err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []matrixRow `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(ci, &wf); err != nil {
		t.Fatal(err)
	}
	rows := wf.Jobs["fix-roundtrip"].Strategy.Matrix.Include
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	scripted := map[string]*controls.Remediation{}
	for i := range set.Controls {
		if r := set.Controls[i].Remediation; r != nil && strings.TrimSpace(r.Script) != "" {
			scripted[set.Controls[i].ID] = r
		}
	}
	// sorted, exactly the scripted ids, images xor unproven, unproven_units keys declared
	ids := make([]string, len(table))
	for i, e := range table {
		ids[i] = e.ID
		if (len(e.Images) == 0) == (e.Unproven == "") {
			t.Errorf("%s: needs images or unproven, not both or neither", e.ID)
		}
		if len(e.UnprovenUnits) > 0 && len(e.Images) == 0 {
			t.Errorf("%s: unproven_units without images", e.ID)
		}
		r := scripted[e.ID]
		for u := range e.UnprovenUnits {
			if r == nil || !contains(r.Units, u) {
				t.Errorf("%s: unproven unit %s is not declared", e.ID, u)
			}
		}
		seen := map[string]bool{}
		for _, k := range e.Images {
			if seen[k] {
				t.Errorf("%s: image %s repeated", e.ID, k)
			}
			seen[k] = true
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Error("table not sorted by id")
	}
	if len(ids) != len(scripted) {
		t.Errorf("table has %d ids, set has %d scripted", len(ids), len(scripted))
	}
	for _, id := range ids {
		if scripted[id] == nil {
			t.Errorf("%s: in the table, not a scripted control", id)
		}
	}
	keys := map[string]matrixRow{}
	for _, r := range rows {
		if r.Key == "" || strings.TrimSpace(r.Seeded) == "" {
			t.Errorf("matrix row %q: needs key and seeded", r.Image)
		}
		keys[r.Key] = r
	}
	for _, e := range table {
		for _, k := range e.Images {
			r, ok := keys[k]
			if !ok {
				t.Errorf("%s: image %s is no matrix row's key", e.ID, k)
			}
			if strings.HasPrefix(e.ID, "muster.service.") && r.Init == "false" {
				t.Errorf("%s: service control on non-init row %s", e.ID, k)
			}
		}
	}
	for k, r := range keys {
		want := map[string]bool{}
		for _, e := range table {
			if contains(e.Images, k) {
				want[e.ID] = true
			}
		}
		got := map[string]bool{}
		for _, id := range strings.Fields(r.Seeded) {
			got[id] = true
		}
		if len(got) != len(want) {
			t.Errorf("row %s: seeded %v, table %v", k, got, want)
		}
		for id := range want {
			if !got[id] {
				t.Errorf("row %s: table names %s, seeded does not", k, id)
			}
		}
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run** `go test ./internal/controls -run TestEveryScriptedControlIsInTheRoundtripTable -count=1`. Expected: FAIL (no table; no `key`).
- [ ] **Step 3: Write `_roundtrip.yaml`** from `probe.md`. Start it with a header comment saying what the file is and that `TestEveryScriptedControlIsInTheRoundtripTable` pins it to `ci.yml`. Then write the sixteen entries, sorted by id, with the reasons in the spec's three-cause wording.
- [ ] **Step 4: Write the CI scripts.**
  - `ci/roundtrip/debian12-init.Dockerfile` is the spec §4 Dockerfile, verbatim.
  - `ci/roundtrip/wait.sh`:

```sh
#!/bin/sh
# wait.sh <cid> <key>: wait for systemd in the container to settle; fail the job otherwise.
set -eu
cid=$1 key=$2 state=
i=0
while [ "$i" -lt 30 ]; do
  state=$(timeout 60 docker exec "$cid" systemctl is-system-running --wait 2>/dev/null) || :
  case "$state" in running|degraded) exit 0;; esac
  i=$((i+1)); sleep 2
done
printf '%s: boot did not settle (state %s)\n' "$key" "${state:-none}" >&2
docker exec "$cid" systemctl --failed --no-pager >&2 || :
exit 1
```

  Each `ci/roundtrip/<key>.sh` runs inside the container from `/ci` and follows this shape. The package names and the two lists come from `probe.md`; the `rocky9-init` lists are shown as an example only.

```sh
#!/bin/sh
# Seed rocky9-init for the round trip (3D-2b §4). Runs inside the container.
set -eu
START_UNITS="rpcbind.socket sshd.service"
ENABLE_ONLY_UNITS=""
dnf install -y -q rpcbind openssh-server acl
ssh-keygen -A
for u in $START_UNITS; do systemctl enable --now "$u"; done
for u in $ENABLE_ONLY_UNITS; do systemctl enable "$u"; done
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/99-ci.conf
chmod 664 /etc/passwd
[ -f /etc/services ] && chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
bad=0
for u in $START_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = active ] || { echo "seed: $u is ${s:-unknown}, want active" >&2; bad=1; }; done
for u in $ENABLE_ONLY_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = inactive ] || { echo "seed: $u is ${s:-unknown}, want inactive" >&2; bad=1; }; done
exit "$bad"
```

  `debian12-init.sh` wraps its `apt-get install` like this:

```sh
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends <packages>
rm -f /usr/sbin/policy-rc.d
systemctl reset-failed
```

- [ ] **Step 5: Rewrite the `fix-roundtrip` job.**
  - `timeout-minutes: 40`.
  - Matrix rows: `key`, `image`, `init`, `seeded`, plus `build: debian12-init` on the Debian row, whose `image` is `muster-ci/debian12-init`.
  - Steps: checkout, setup-go, build muster; then `if: matrix.build != ''` → `docker build -t muster-ci/debian12-init -f ci/roundtrip/debian12-init.Dockerfile ci/roundtrip`; then one `run` block:

```sh
set -eu
d="$RUNNER_TEMP/rt"; mkdir -m 700 "$d" "$d/repair" "$d/fail"
start() { # start <dir>: prints the container id
  if [ "${{ matrix.init }}" = "true" ]; then
    docker run -d --privileged --cgroupns=host -v "$PWD/bin:/m:ro" -v "$PWD/ci/roundtrip:/ci:ro" -v "$1:/out" "${{ matrix.image }}" /sbin/init
  else
    docker run -d -v "$PWD/bin:/m:ro" -v "$PWD/ci/roundtrip:/ci:ro" -v "$1:/out" "${{ matrix.image }}" sleep infinity
  fi
}
c1=$(start "$d/repair"); c2=
trap 'docker rm -f $c1 $c2 >/dev/null 2>&1 || true' EXIT
[ "${{ matrix.init }}" = "true" ] && sh ci/roundtrip/wait.sh "$c1" "${{ matrix.key }}"
docker exec "$c1" sh /ci/${{ matrix.key }}.sh
plan() { # plan <cid> <dir>: collect, then the JSON plan and the script into <dir>
  docker exec "$1" /m/muster collect --out /out/before.json || true
  sudo chown "$(id -u)" "$2/before.json"
  ./bin/muster fix --dry-run --facts "$2/before.json" --format json > "$2/plan.json"
  ./bin/muster fix --dry-run --facts "$2/before.json" --format script > "$2/fix.sh"
  test -s "$2/plan.json"; test -s "$2/fix.sh"
}
plan "$c1" "$d/repair"
for id in ${{ matrix.seeded }}; do
  jq -e --arg id "$id" '[.items[] | select(.id == $id and .planned and .script)] | length == 1' "$d/repair/plan.json" > /dev/null \
    || { echo "seeded $id is not a planned scripted item"; jq '.items[] | {id, planned, script, text_only_reason}' "$d/repair/plan.json"; exit 1; }
done
docker exec "$c1" sh /out/fix.sh
docker exec "$c1" /m/muster collect --out /out/after.json || true
sudo chown "$(id -u)" "$d/repair/after.json"
set +e; ./bin/muster check --facts "$d/repair/after.json" --format json > "$d/repair/after-report.json"; set -e
for id in ${{ matrix.seeded }}; do
  jq -e --arg id "$id" '[.results[] | select(.id == $id and (.status == "PASS" or .status == "NOT_APPLICABLE"))] | length == 1' "$d/repair/after-report.json" > /dev/null \
    || { echo "$id did not pass after the script"; jq --arg id "$id" '.results[] | select(.id == $id)' "$d/repair/after-report.json"; exit 1; }
done
[ "${{ matrix.init }}" = "true" ] || exit 0
# failure and guard runs (3D-2b §4)
c2=$(start "$d/fail"); sh ci/roundtrip/wait.sh "$c2" "${{ matrix.key }}"
docker exec "$c2" sh /ci/${{ matrix.key }}.sh
plan "$c2" "$d/fail"
h1=$(jq -r .run.host.machine_id_hash "$d/repair/plan.json"); h2=$(jq -r .run.host.machine_id_hash "$d/fail/plan.json")
g1=$(jq -r .fix.host_guard "$d/repair/plan.json"); g2=$(jq -r .fix.host_guard "$d/fail/plan.json")
[ "$g1" = on ] && [ "$g2" = on ] && [ -n "$h1" ] && [ "$h1" != "$h2" ] \
  || { echo "${{ matrix.key }}: the two containers need distinct machine ids (guard $g1/$g2, hash $h1/$h2)"; exit 1; }
record() { # record <cid>: unit states and backup-path stats/checksums/ACLs of the planned scripted items
  jq -r '.items[] | select(.planned and .script) | .units[]' "$d/fail/plan.json" | sort -u > "$d/fail/units"
  : > "$d/fail/deps"
  while read -r u; do docker exec "$1" systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" | tr ' ' '\n' >> "$d/fail/deps" || :; done < "$d/fail/units"
  sort -u "$d/fail/units" "$d/fail/deps" | sed '/^$/d' | while read -r u; do
    printf '%s %s %s\n' "$u" "$(docker exec "$1" systemctl is-enabled -- "$u" 2>/dev/null || :)" "$(docker exec "$1" systemctl is-active -- "$u" 2>/dev/null || :)"
  done
  jq -r '.items[] | select(.planned and .script) | .backup[]' "$d/fail/plan.json" | sort -u | while read -r p; do
    docker exec "$1" sh -c 'p=$1; if [ -e "$p" ] || [ -L "$p" ]; then printf "%s %s %s\n" "$p" "$(stat -c "%u %g %a" "$p")" "$(sha256sum < "$p" | cut -d" " -f1)"; command -v getfacl >/dev/null && getfacl -cp "$p" 2>/dev/null; else printf "%s absent\n" "$p"; fi' _ "$p"
  done
}
record "$c2" > "$d/fail/record-before"
cp "$d/repair/fix.sh" "$d/fail/repair-fix.sh"
set +e; docker exec "$c2" sh /out/repair-fix.sh > "$d/fail/guard.out" 2>&1; gc=$?; set -e
[ "$gc" -eq 2 ] && grep -qx 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway' "$d/fail/guard.out" \
  || { echo "guard run: exit $gc"; cat "$d/fail/guard.out"; exit 1; }
record "$c2" > "$d/fail/record-guard"; diff "$d/fail/record-before" "$d/fail/record-guard"
awk 'prev == "  # validate" { print; getline; print "    false"; prev = ""; next } { print; prev = $0 }' "$d/fail/fix.sh" > "$d/fail/broken.sh"
blocks=$(jq '[.items[] | select(.planned and .script)] | length' "$d/fail/plan.json")
changed=$(diff "$d/fail/fix.sh" "$d/fail/broken.sh" | grep -c '^>' || :)
[ "$changed" -eq "$blocks" ] || { echo "rewrite changed $changed lines for $blocks blocks"; exit 1; }
set +e; docker exec "$c2" sh /out/broken.sh > "$d/fail/broken.out" 2>&1; bc=$?; set -e
cat "$d/fail/broken.out"
[ "$bc" -eq 1 ] || { echo "failure run: exit $bc, want 1"; exit 1; }
[ "$(grep -c 'validate failed, rolling back' "$d/fail/broken.out")" -eq "$blocks" ] || { echo "not every block rolled back"; exit 1; }
! grep -qE 'ROLLBACK INCOMPLETE|not restored|rollback failed' "$d/fail/broken.out" || { echo "a rollback was incomplete"; exit 1; }
record "$c2" > "$d/fail/record-after"
diff "$d/fail/record-before" "$d/fail/record-after"
```

  The `awk` keeps the `  ( set -e` line after the marker and replaces the line after it, the first validate command, with `    false`. Check the rendered `full.sh` shape before relying on it: marker, then `  ( set -e`, then the command.

- [ ] **Step 6: Shellcheck coverage.** In the `test` job's shellcheck step and in `make shellcheck`, add a loop over `ci/roundtrip/*.sh` that counts files and fails when none was checked, the way the remedy goldens loop does. The Makefile line:

```make
	@n=0; for f in ci/roundtrip/*.sh; do sh -n "$$f" || exit 1; shellcheck -s sh "$$f" || exit 1; n=$$((n+1)); done; [ "$$n" -ge 5 ] || { echo "shellcheck: $$n roundtrip scripts checked, want at least 5"; exit 1; }
```

  Update the Makefile comment above the target.

- [ ] **Step 7: Validate.**
  1. Run `go test ./internal/controls -count=1`. Expected: PASS.
  2. YAML-parse the workflow (`python -I -X utf8 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" .github/workflows/ci.yml`), and run actionlint if reachable.
  3. On the lab with docker, run the job's script by hand for `debian12-init` and one EL row. Define `matrix.*` as shell variables and keep the shell copy in the sdd directory, not the repo. Record the times (spec §4: the plan records them).
  4. Run `make shellcheck` on the lab.
- [ ] **Step 8: Mutation check.**
  1. Remove one id from a row's `seeded`, and see the table test go red.
  2. In the lab run, comment out `restore_units` in a copy of `broken.sh`, and see step 5's `diff` fail.

  Restore both.
- [ ] **Step 9: Commit** "Pin the round trip to a table of the sixteen, add the Debian init row, seed scripts and a failure and guard run per init row". The body names T-12 and the measured times.

---

### Task 9 (controller): documents

**Files:** main design EN/KO (D34 L552, §4.2 L94, §6.2 L282, §6.8 L370, §7.5 L414, §10.2 L468), `CLAUDE.md` (L3-4 "D01–D34" stays; L16-17; the Fix section L172-201), `CONTRIBUTING.md` L93-110 and L220-227, `CONTRIBUTING.ko.md` L73-89 and L176-180, `README.md` L17-28 and L203-218, `README.ko.md` L15-23 and L178-186, `THREAT_MODEL.md` (Trust boundary L18-19, Limits L37-42), `examples/README.md` (L3-4, L68, L86-95), `CHANGELOG.md` (Added L12, Changed L40, Controls L54, Tooling L435). Line numbers are the code map's §ci-report 4-11.

- [ ] **Step 1:** Write each change the spec §6 lists, in EN and KO together. The CLAUDE.md sentences to replace are the eight named in spec §6. The `fix-roundtrip` sentence also mentions `TestFileScriptsRepairOnARealFile`, which runs shipped file bodies on temp files.
- [ ] **Step 2:** Run `go run ./tools/coverage -check` and `make lint-controls`. Run `grep -n "enable --now every unit\|A one-unit body uses\|rollback or backup;" CLAUDE.md CONTRIBUTING*.md` and expect no hits.
- [ ] **Step 3: Commit** "Record stage 3D-2b in the documents: D34's hash exception, units, the round-trip table, the guard's limits".

---

## Merge (the user's word)

The steps after the user says to merge:

1. Push the branch.
2. Run `examples.yml` on it.
3. Fetch its artifact with `gh run download <id> -n examples-<id> -D <empty scratch dir>`, then copy it into `examples/`. On Windows `make examples-fetch` cannot overwrite existing files.
4. Read the diff: the VM script guard-on, the container script guard-off, `units` arrays, `host_guard`, and status counts unchanged. Commit it.
5. Open the PR.
6. CI green, including the first failure and guard runs.
7. Merge, delete the remote branch, and remove the worktree.

## Execution notes

(Filled in during execution: rulings T-14 onward, the probe's table, the CI times.)
