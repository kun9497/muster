# Stage 3D-2c — scripts beyond the sixteen: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Thirty-two more controls carry a review-script body. A profile's or tuning's parameter reaches a body as a `P_<name>` block variable, and every block records the state it changes (file copies, unit states, modes, sysctl values, module load states) under its own directory and restores it on failure. A `runner` row on the GitHub VM proves the bodies that only a host can judge.

**Architecture:** `internal/controls` gains five `Remediation` fields, the parameter formatter `ScriptParamValue` and validators for the new entry kinds, ten lint rules, and loses three. `remedy.Build` formats the values in force into `Item.ScriptParams`, copies `Modes`/`Sysctl`/`Modules`, scripts an absent-means-fail row when the control says so, and names the way back in six words. `remedy.Script` opens every block with its `P_` lines and `MB="$MUSTER_BACKUP/blocks/<fn>"`, and records and restores the state kinds through eight new prologue helpers in a fixed order. The bodies are written in four families, pinned to the collectors by two Linux tests, and run against stubs and temp trees in the Go suite. CI's `fix-roundtrip` gains a `kind` per row and a host row with its own seed.

**Tech Stack:** Go 1.25.5, standard library, `gopkg.in/yaml.v3` (existing), POSIX `sh`, procps `sysctl`, kmod `modprobe`, shadow-utils `chage`, OpenSSH `sshd -T`, GitHub Actions, shellcheck.

**Spec:** `docs/superpowers/specs/2026-10-14-stage3d2c-remedy-scripts-design.md` (EN canonical, `.ko.md` pair) at `bbc354a`, rulings E-1..E-13. Code map with today's line numbers: `.superpowers/sdd/2026-10-14-stage3d2c-remedy-scripts/code-map-{remedy,controls,check,yaml,ci,docs}.md` (ignored; the controller hands each task its sections). Review digests: `review-round{1,2}.md` beside them.

## Global Constraints

- muster never executes a remediation. `internal/remedy` imports no `os`, `os/exec`, `net`, `syscall` or `time` (`TestRemedyPackageHasNoHostImports`); test files may.
- The only snapshot value on a non-comment script line stays the machine-id hash on the one `MUSTER_SNAPSHOT_HOST=` line. A parameter value enters only as a `  P_<name>='<value>'` line whose value passed `controls.ScriptParamValue` (D34 amended, spec §2).
- The block function call stays a bare line followed by `[ "$?" -eq 0 ] || failed=$((failed+1))`. `fix` exit codes, `check` and `collect` exit codes are unchanged. The script still exits 2 only for its three causes.
- Same input, same bytes in all three formats; no `map` in `remedy.Plan`; the generator reads no clock.
- Control YAML is decoded strictly. The new fields are `ScriptParams []string 'yaml:"script_params,omitempty"'`, `ScriptOnAbsent bool 'yaml:"script_on_absent,omitempty"'`, `Modes`, `Sysctl`, `Modules []string` (`yaml:"modes,omitempty"`, `sysctl`, `modules`).
- No `checks`, `mechanisms`, `applies_when` or `absent_means` change. One parameter default moves (`umask_policy.acceptable` order). `controls/VERSION` becomes `kisa-unix-2026+2026.10.14`.
- Every body is POSIX `sh`, shellcheck-clean at the default severity (`all-scripted.sh` is shellchecked by `make shellcheck` and CI), `set -e`-safe in its subshell, and writes a value only when the current one is outside the clause's accepted set (E-8).
- Nothing in the Go suite touches the host's sysctls, modules, accounts or sshd: the helper and body tests run against stub `sysctl`, `modprobe`, `chage`, `sshd` and `systemctl` first on `PATH`, with every absolute path rebased under `t.TempDir()`.
- Documents are English canonical with the `.ko.md` pair in the same commit where a pair exists. `THREAT_MODEL.md`, `CHANGELOG.md` and `examples/README.md` have no pair. Identifiers stay English.
- Commits use the personal identity (pinned) and the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push, amend, rebase or stash.
- From Task 5 on, the control set's digest changes and the examples gate (`TestExamplesLoadAndCheck`) skips its byte comparison with a note (G-24). The merge-step refresh re-pins the examples. Tasks 3–4 change only `internal/remedy` while the set is unchanged, so the gate compares bytes there and goes red on the fix-report examples; that is expected and quoted once in each of those task reports (T-19 precedent), never "fixed" by editing `examples/`.
- On Windows the `needSh`/Linux tests and `internal/collect/...` do not run; each task that adds one runs it on the lab (`lab-sync.sh` then `lab-run.sh 'cd /root/muster && go test ./internal/remedy/ -run <name>'`, as root for the root-only ones) and quotes the output.

## Rulings carried from the code map (the spec as built)

- **S-1** A value in force missing from `cb.Params` falls back to the default: `remedy` computes `check.ParamValues(c, cb.Params[row.ID])` (production always carries every name; the remedy fixtures carry none). An empty list, or any element failing the charset, is `params_unsafe`. A `script_params` entry must also match the parameter-name grammar `^[a-z][a-z0-9_]*$` (`controls.ValidParamName`), checked by `script_params_declared` and re-checked by `Build`.
- **S-2** Text-only order in `item()`: `no_script` → `absent` (only when `!r.ScriptOnAbsent`) → `params_tuned` (only when `len(r.ScriptParams) == 0`) → `params_unsafe` (the formatter refused a value) → scripted. `TestPlanAbsentBeforeTuned` keeps passing.
- **S-3** Every scripted block's head is, in order: one `  P_<name>='<value>'` line per `ScriptParams` entry (name order), then the literal `  MB="$MUSTER_BACKUP/blocks/<fn>"; mkdir -p "$MB" || { log "<id>: backup failed, nothing changed"; return 1; }`, then the five record lines when their list is non-empty. `<fn>` is `fix_` + the id with `.` → `_` (already the function name). The `ROLLBACK INCOMPLETE` suffix keeps `backups in $MUSTER_BACKUP`.
- **S-4** `Build` re-checks, after `item()`, every `Backup` path (`controls.ValidBackupPath`: `backupPathRe` and `path.Clean`), `Modes` entry (`ValidModesEntry`), `Sysctl` key (`ValidSysctlKey`), `Modules` name (`ValidModuleName`) and `ScriptParams` name (`ValidParamName`), each refusal `refusing to plan <id>: <kind> %q is not <a …> a script can carry`. Backup paths were never re-checked before; the new check is harmless to every shipped control.
- **S-5** `lintRemediation(r, add)` becomes `lintRemediation(c *Control, add)` (call site `lint.go:279`) so the `script_params` rules see `c.Params`.
- **S-6** The way-back check keeps rule id `remediation`; its message becomes `script without rollback, backup, units, modes, sysctl or modules` (lint_test case renamed accordingly). The ten new rules carry their own ids. `units_exclusive` gains three messages: `units excludes modes|sysctl|modules: the unit state is the way back`.
- **S-7** `modes_charset` also requires the entry's base (the entry with its `/*` segments stripped) to be clean (`path.Clean(base) == base`) and not `/`. `modes_backup_overlap`: a backup path equal to a `k = 0` entry, or under an entry's base with exactly `k` more components, is refused. `modules_charset` is `^[a-z0-9][a-z0-9_-]*$` (the spec's class, starting with a letter or digit, as `units_charset` does).
- **S-8** `TestFileValidatesAcceptTheDefaultModes` stays at the five 3D-2b controls, selected by its owner table (spec §4.3; §6's "six" is the slip, corrected in Task 10). Its "no other pure-case validate" assertion is narrowed to validates of the form `case "$(stat -c `, because the sysctl and umask validates are single `case` statements too.
- **S-9** `lockout_threshold`: the collector seeds `deny = 3` before it reads `faillock.conf` (`pam_derive.go:420`). The body's gate and the validate read the last uncommented `deny`, defaulting to 3, and write only when that value is outside `[1, $P_max_attempts]`. A `deny=` on the pam_faillock lines stays text (the text says so).
- **S-10** `password_policy`'s class gate computes the collector's `required_classes` = max(`minclass`, count of `dcredit`/`ucredit`/`lcredit`/`ocredit` ≤ −1) over the merged file chain, with `minlen` defaulting to 8, and writes `minclass` only when that is below `$P_min_classes`. Arguments on the `pam_pwquality.so` line win over every file and stay text. The account enumeration matches `parseShadow` too: `NF >= 8 && $1 !~ /^#/`.
- **S-11** `session_timeout`: the body writes, per keyword, the value in force when it already lies in `[1, max]`, else the parameter (so a stricter host's value is kept; E-8). The validate is guarded like `root_remote_login`'s (`if command -v sshd …; then …; fi`), so a host without sshd ends `done` and the next `check` still FAILs naming the TMOUT mechanism — a body that cannot apply must not fail every sshd-less host's script, CI's `ubuntu2204` and `debian12-init` rows included. This reverses the round-2 wording of spec §4.4 (Task 10 corrects it).
- **S-12** `audit_log_permissions` never `chgrp`s: the group clause (`allowed_groups`) stays text, as `log_dir_permissions`'s group half does. A tuned `allowed_modes`/`allowed_groups` on any file control keeps `params_tuned` (none of them declares `script_params`).
- **S-13** `ftpusers_permissions` and `nfs_export_access` `chown root` only (both judge uid alone).
- **S-14** The roundtrip test's `matrixRow` gains `Kind string`; every row must carry `kind` ∈ {`container`, `host`}; a `host` row carries no `image`, `init` or `build`; `muster.beyond.*` ids name `host` rows only; `unproven_units` keys must be in `units` ∪ `modules` ∪ `sysctl`. The `_roundtrip.yaml` header gains a fourth cause: the kernel ships no such module.
- **S-15** CI: there is no `x()` today; Task 9 introduces `x()`, `cid`, and the path variables. Line `[ init = true ] || exit 0` becomes `[ "$KIND" = host ] || [ "${{ matrix.init }}" = "true" ] || exit 0`. The host row sets `MUSTER_BACKUP` explicitly per run (`/var/backups/muster/ci-repair`, `ci-fail`) so the two runs never share a directory. `debian12-init` and `ubuntu2204` install `cron` for `cron_permissions`. The round-trip script floor moves from 5 to 6 (Makefile, ci.yml, CLAUDE.md).
- **S-16** Remedy fixtures gain `muster.test.h_params` (an `int` and a `list<string>` `script_params`), `muster.test.i_state` (`modes`, `sysctl`, `modules`), `muster.test.j_absent` (`script_on_absent`) and `muster.test.k_both` (`backup` + `sysctl`). `fullPlan` gains rows for `h_params` and `i_state`; `poisonControls` gains `muster.test.p_params`.
- **S-17** Documents: `THREAT_MODEL.md` has no pair; the §6.2 sentence loses "outside `/muster-units`"; §7.5's "proven on throwaway containers" and D34's "independent" are reworded; the CHANGELOG 10.14 Controls paragraph names the one default reorder (Task 10).

## Review Focus

1. **A host already stricter than the default** (`perf_event_paranoid = 4`, `kptr_restrict = 2`, `PASS_MAX_DAYS 60`, `UMASK 077`, `deny = 3`, `ClientAliveInterval 120`) whose control FAILs on another key. The body writes nothing for the passing keys and the validate accepts the stricter value. (Task 5: the "stricter" cases of `TestSysctlBodiesWriteOnlyOutsideTheSet`; Task 8: the stricter rows of `TestAccountBodies`.)
2. **A host at a one-way value** (`unprivileged_bpf_disabled = 1`, `yama.ptrace_scope = 3`) failing only the companion key. The body never writes the one-way key, so the block succeeds. (Task 5: the stub `sysctl` refuses writes to a key marked one-way and the case asserts exit 0.)
3. **A re-run with the same `MUSTER_BACKUP` after the path changed**: absent at run 1 then present (copied on run 2), and copied at run 1 then gone (no marker, the copy is restored). (Task 4: `TestBackupMarkerCases`.)
4. **A recorded mode entry replaced by a symlink to `/etc/shadow` between record and failure.** `restore_modes` leaves it, logs it and the block reports `ROLLBACK INCOMPLETE`. (Task 4: `TestModesHelpersRefuseASwappedEntry`.)
5. **A tuned value that cannot be carried** (`'; id; '`, an empty list). The item is text-only `params_unsafe`, and the value appears on no non-comment line and nowhere in the JSON. (Task 3: `TestPlanParamsUnsafe`; Task 4: the poison assertions.)

---

### Task 1: The probe (controller, lab; no commit)

**Files:** `.superpowers/sdd/2026-10-14-stage3d2c-remedy-scripts/probe.md`, `probe.sh` (both ignored).

The spec's seed tables and row placements are a hypothesis (spec §5). This task measures what can be measured off the runner; the runner itself is proven by the branch's first CI run.

- [ ] **Step 1: Write `probe.sh`.** Two halves.
  - Host half (read-only on the lab host, as root): for each of the sixteen seed keys of spec §5, print `key stock-value writable` where `writable` is the exit status of `sysctl -q -w key=<its own current value>` (a no-op write). Print `modinfo -n` (or `missing`) for the eleven modules and whether each is loaded. Print `sshd -T | grep -i '^clientalive'` and the files under `/etc/ssh/sshd_config.d/` that set `ClientAliveInterval`. Print `dpkg -S /etc/security/faillock.conf` and whether `libpam-pwquality` is installable (`apt-cache policy libpam-pwquality`).
  - Container half (docker, as in 3D-2b): for each of `rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, the built `muster-ci/debian12-init` and `ubuntu:22.04`, start the image as the CI job does, install the packages of spec §5's container seed table (`sudo cronie rsyslog vsftpd authselect` on EL; `sudo cron rsyslog vsftpd` on Debian/Ubuntu under `policy-rc.d` exit 101), then print the stat (`%u %g %a %F`) of every path the nine file controls and four account controls judge, the first `PASS_MAX_DAYS`/`PASS_MIN_DAYS`/`PASS_MIN_LEN`/`UMASK` lines of `/etc/login.defs`, the merged pwquality `minlen`/`minclass`/credits, the last `deny` of `faillock.conf`, `authselect current` on EL, and whether `sshd -T` runs.
- [ ] **Step 2: Run it.** Send both files over `lab-run`'s stdin (`lab-sync` excludes `.superpowers/`), e.g. `lab-run.sh 'mkdir -p /root/muster-probe && cat > /root/muster-probe/probe.sh' < .superpowers/sdd/2026-10-14-stage3d2c-remedy-scripts/probe.sh`, and build the Debian image from `ci/roundtrip/debian12-init.Dockerfile` the same way. Record the output verbatim in `probe.md`.
- [ ] **Step 3: Decide.** In `probe.md` write, per container row: the package additions, the per-control seed lines (spec §5 container table), and which new controls FAIL at stock there (they will be planned with a script on that row even when not seeded — every such body must succeed on that row). Write the `_roundtrip.yaml` entries for the 32 controls (images or `unproven`/`unproven_units` with a reason). Decide `password_policy` on `runner` (only if `libpam-pwquality` is installable there; else the EL rows only). Confirm, from `examples/ubuntu-24.04-vm.json`, the runner's `ClientAliveInterval` file (`50-cloudimg-settings.conf`) and the modules it ships (`udf`, `sctp`, `tipc`).
- [ ] **Step 4: Report** the table and every surprise to the user before Task 9 is dispatched.

---

### Task 2: `internal/controls` — the five fields, the formatter, the validators, the lint rules

**Files:**
- Modify: `internal/controls/schema.go:104-114` (`Remediation`)
- Modify: `internal/controls/params.go` (add `ScriptParamValue`)
- Modify: `internal/controls/lint.go` (regexes `:49-56`, validators beside `ValidUnitName` `:82`, `lintRemediation` `:111-210`, delete `lintSharedRemediation` `:212-241` and its call `:434`)
- Test: `internal/controls/lint_test.go` (`TestLintRules` `:70-352`, `TestLintSetRules` `:1309-1332`), new `internal/controls/params_script_test.go`

**Interfaces:**
- Produces: `Remediation.ScriptParams []string`, `.ScriptOnAbsent bool`, `.Modes []string`, `.Sysctl []string`, `.Modules []string`; `func ScriptParamValue(typ string, v any) (string, bool)`; `func ValidParamName(n string) bool`; `func ValidBackupPath(p string) bool`; `func ValidModesEntry(e string) bool`; `func ValidSysctlKey(k string) bool`; `func ValidModuleName(m string) bool`.

- [ ] **Step 1: Write the failing formatter test** `internal/controls/params_script_test.go`:

```go
package controls

import "testing"

func TestScriptParamValueFormatsAndRefuses(t *testing.T) {
	cases := []struct {
		typ  string
		v    any
		want string
		ok   bool
	}{
		{"int", 90, "90", true},
		{"int", -1, "-1", true},
		{"int", "90", "", false},
		{"bool", true, "true", true},
		{"bool", false, "false", true},
		{"string", "027", "027", true},
		{"string", "a.b/c@d:e+f,g=h-i_j", "a.b/c@d:e+f,g=h-i_j", true},
		{"string", "'; id; '", "", false},
		{"string", "a b", "", false},
		{"string", "", "", false},
		{"string", "$(id)", "", false},
		{"string", "a|b", "", false},
		{"list<int>", []any{0}, "0", true},
		{"list<int>", []any{0, 176}, "0 176", true},
		{"list<int>", []any{}, "", false},
		{"list<int>", []any{"0"}, "", false},
		{"list<string>", []any{"027", "022"}, "027 022", true},
		{"list<string>", []any{"ok", "bad;"}, "", false},
		{"list<string>", "027", "", false},
		{"weird", 1, "", false},
	}
	for _, c := range cases {
		got, ok := ScriptParamValue(c.typ, c.v)
		if got != c.want || ok != c.ok {
			t.Errorf("ScriptParamValue(%q, %#v) = %q, %v; want %q, %v", c.typ, c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestEntryValidators(t *testing.T) {
	for _, c := range []struct {
		f    func(string) bool
		name string
		in   string
		ok   bool
	}{
		{ValidParamName, "param", "max_days", true},
		{ValidParamName, "param", "Max", false},
		{ValidParamName, "param", "1x", false},
		{ValidBackupPath, "backup", "/etc/hosts", true},
		{ValidBackupPath, "backup", "/etc//hosts", false},
		{ValidBackupPath, "backup", "/etc/a b", false},
		{ValidModesEntry, "modes", "/etc/cron.d/*", true},
		{ValidModesEntry, "modes", "/var/log/*/*", true},
		{ValidModesEntry, "modes", "/etc/crontab", true},
		{ValidModesEntry, "modes", "/etc/x/*/*/*", false},
		{ValidModesEntry, "modes", "/etc/x//*", false},
		{ValidModesEntry, "modes", "/etc/./x/*", false},
		{ValidModesEntry, "modes", "/*", false},
		{ValidModesEntry, "modes", "/etc/'x/*", false},
		{ValidSysctlKey, "sysctl", "net.ipv4.conf.all.accept_redirects", true},
		{ValidSysctlKey, "sysctl", "kernel", false},
		{ValidSysctlKey, "sysctl", "net.ipv4.ip_forward=1", false},
		{ValidModuleName, "module", "usb-storage", true},
		{ValidModuleName, "module", "usb_storage", true},
		{ValidModuleName, "module", "-x", false}, // S-7: a name starts with a letter or digit
		{ValidModuleName, "module", "a b", false},
	} {
		if got := c.f(c.in); got != c.ok {
			t.Errorf("%s %q: got %v, want %v", c.name, c.in, got, c.ok)
		}
	}
}
```

- [ ] **Step 2: Run it** — `go test ./internal/controls -run 'TestScriptParamValue|TestEntryValidators'`. Expected: build failure, `undefined: ScriptParamValue`.

- [ ] **Step 3: Add the fields.** In `schema.go`, `Remediation` becomes:

```go
type Remediation struct {
	TextEn         string   `yaml:"text_en"`
	TextKo         string   `yaml:"text_ko"`
	Risk           string   `yaml:"risk"` // none | restart_service | reboot_required | lockout_risk
	Idempotent     bool     `yaml:"idempotent"`
	Script         string   `yaml:"script,omitempty"`
	ScriptParams   []string `yaml:"script_params,omitempty"`    // 3D-2c E-1: params the script reads as $P_<name>
	ScriptOnAbsent bool     `yaml:"script_on_absent,omitempty"` // 3D-2c E-5: an absent-means-fail row is scripted
	Rollback       string   `yaml:"rollback,omitempty"`
	Backup         []string `yaml:"backup,omitempty"`
	Units          []string `yaml:"units,omitempty"`
	Modes          []string `yaml:"modes,omitempty"`  // 3D-2c E-3: paths whose owner, group and mode are recorded
	Sysctl         []string `yaml:"sysctl,omitempty"` // 3D-2c E-3: kernel keys whose runtime value is recorded
	Modules        []string `yaml:"modules,omitempty"`
	Validate       string   `yaml:"validate,omitempty"`
}
```

(Keep the existing comment lines on the old fields as they are.)

- [ ] **Step 4: Add the formatter** to `params.go` (add `regexp`, `strconv`, `strings` to its imports):

```go
var (
	scriptIntRe = regexp.MustCompile(`^-?[0-9]+$`)
	scriptStrRe = regexp.MustCompile(`^[A-Za-z0-9._/@:+,=-]+$`)
)

// ScriptParamValue formats a parameter value for a review script's
// P_<name>='<value>' line (3D-2c E-1) and reports whether the value can be
// carried: an int as digits, a bool as true/false, a string or each list
// element in a charset with no quote, blank, $, backtick, ;, |, & or \, and
// a list as its elements joined by one space. An empty list cannot be.
func ScriptParamValue(typ string, v any) (string, bool) {
	switch typ {
	case "int":
		n, ok := v.(int)
		if !ok {
			return "", false
		}
		s := strconv.Itoa(n)
		return s, scriptIntRe.MatchString(s)
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return "", false
		}
		return strconv.FormatBool(b), true
	case "string":
		s, ok := v.(string)
		if !ok || !scriptStrRe.MatchString(s) {
			return "", false
		}
		return s, true
	case "list<int>", "list<string>":
		xs, ok := v.([]any)
		if !ok || len(xs) == 0 {
			return "", false
		}
		elem := strings.TrimSuffix(strings.TrimPrefix(typ, "list<"), ">")
		parts := make([]string, 0, len(xs))
		for _, x := range xs {
			s, ok := ScriptParamValue(elem, x)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}
```

- [ ] **Step 5: Add the validators** to `lint.go`. Extend the `var (` block after `unitRe`:

```go
	modesEntryRe = regexp.MustCompile(`^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`)
	sysctlKeyRe  = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`)
	moduleNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	paramNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	pVarRe       = regexp.MustCompile(`\$\{?P_([A-Za-z0-9_]+)`)
```

and after `ValidUnitName`:

```go
// ValidParamName reports whether n can name a P_<n> block variable (3D-2c S-1).
func ValidParamName(n string) bool { return paramNameRe.MatchString(n) }

// ValidBackupPath reports whether p is an absolute clean path in the charset
// the review script carries (the backup lint's rule; remedy.Build re-checks it).
func ValidBackupPath(p string) bool { return backupPathRe.MatchString(p) && path.Clean(p) == p }

// modesBase splits a modes entry into its base path and its number of /*
// segments.
func modesBase(e string) (string, int) {
	k := 0
	for k < 2 && strings.HasSuffix(e, "/*") {
		e, k = strings.TrimSuffix(e, "/*"), k+1
	}
	return e, k
}

// ValidModesEntry reports whether e is an absolute clean path followed by at
// most two /* segments (3D-2c E-3, S-7).
func ValidModesEntry(e string) bool {
	if !modesEntryRe.MatchString(e) {
		return false
	}
	base, _ := modesBase(e)
	return base != "/" && path.Clean(base) == base
}

// ValidSysctlKey reports whether k is a dotted kernel key (3D-2c E-3).
func ValidSysctlKey(k string) bool { return sysctlKeyRe.MatchString(k) }

// ValidModuleName reports whether m is a module name the helpers carry.
func ValidModuleName(m string) bool { return moduleNameRe.MatchString(m) }
```

- [ ] **Step 6: Run the formatter test** — `go test ./internal/controls -run 'TestScriptParamValue|TestEntryValidators'`. Expected: PASS.

- [ ] **Step 7: Write the failing lint cases.** In `TestLintRules`:
  - Change the case `script without way back` to `msg: "script without rollback, backup, units, modes, sysctl or modules"`.
  - Delete the three `backup reserved …` cases and the duplicate `script without validate` at the end of the keyed block (the first one stays).
  - Add, after `UNITS in validate`:

```go
		{name: "accept state as the way back", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", sysctl: [kernel.sysrq] }`), rule: "remediation", absent: true},
		{name: "state without script", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, modules: [udf] }`), rule: "state_needs_script", msg: "modes, sysctl or modules without script"},
		{name: "units with modes", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [a.service], modes: [/etc/x] }`), rule: "units_exclusive", msg: "units excludes modes"},
		{name: "units with sysctl", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [a.service], sysctl: [kernel.sysrq] }`), rule: "units_exclusive", msg: "units excludes sysctl"},
		{name: "units with modules", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", units: [a.service], modules: [udf] }`), rule: "units_exclusive", msg: "units excludes modules"},
		{name: "modes charset", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", modes: ["/etc/x/*/*/*"] }`), rule: "modes_charset", msg: `modes entry "/etc/x/*/*/*"`},
		{name: "modes unclean", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", modes: ["/etc/x//*"] }`), rule: "modes_charset"},
		{name: "modes repeated", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", modes: [/etc/x, /etc/x] }`), rule: "modes_charset", msg: `modes entry "/etc/x" is repeated`},
		{name: "modes overlap exact", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/etc/x], modes: [/etc/x] }`), rule: "modes_backup_overlap", msg: `backup path "/etc/x" is also covered by modes entry "/etc/x"`},
		{name: "modes overlap glob", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/etc/x.d/a], modes: ["/etc/x.d/*"] }`), rule: "modes_backup_overlap"},
		{name: "accept modes beside a backup", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/etc/sudoers], modes: ["/etc/sudoers.d/*"] }`), rule: "modes_backup_overlap", absent: true},
		{name: "accept a deeper backup beside a one-level glob", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", backup: [/etc/x.d/a/b], modes: ["/etc/x.d/*"] }`), rule: "modes_backup_overlap", absent: true},
		{name: "sysctl charset", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", sysctl: ["kernel.sysrq=1"] }`), rule: "sysctl_charset", msg: `sysctl key "kernel.sysrq=1"`},
		{name: "sysctl repeated", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", sysctl: [kernel.sysrq, kernel.sysrq] }`), rule: "sysctl_charset", msg: "is repeated"},
		{name: "modules charset", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", modules: ["Bad Mod"] }`), rule: "modules_charset", msg: `module "Bad Mod"`},
		{name: "modules repeated", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", modules: [udf, udf] }`), rule: "modules_charset", msg: "is repeated"},
		{name: "script_params without script", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script_params: [allowed] }`), rule: "script_params_needs_script", msg: "script_params without script"},
		{name: "script_on_absent without script", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script_on_absent: true }`), rule: "script_on_absent_needs_script", msg: "script_on_absent without script"},
		{name: "script_params undeclared", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "echo $P_nope", validate: "true", rollback: "true", script_params: [nope] }`), rule: "script_params_declared", msg: `script param "nope" is not a declared parameter`},
		{name: "script_params bad name", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", rollback: "true", script_params: [Bad] }`), rule: "script_params_declared", msg: `script param "Bad" is not a parameter name`},
		{name: "script_params repeated", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "echo $P_allowed", validate: "true", rollback: "true", script_params: [allowed, allowed] }`), rule: "script_params_declared", msg: "is repeated"},
		{name: "script_params unused", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", rollback: "true", script_params: [allowed] }`), rule: "script_params_used", msg: `script param "allowed" is not used in script`},
		{name: "P_ undeclared in validate", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "echo $P_allowed", validate: "test ${P_other}", rollback: "true", script_params: [allowed] }`), rule: "script_params_used", msg: "validate uses $P_other"},
		{name: "accept P_ in validate and rollback", yaml: rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "echo $P_allowed", validate: "test -n \"$P_allowed\"", rollback: "echo ${P_allowed}", script_params: [allowed] }`), rule: "script_params_used", absent: true},
		{name: "script_params default unsafe", yaml: strings.Replace(rem(`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "echo $P_allowed", validate: "true", rollback: "true", script_params: [allowed] }`), `default: ["no"]`, `default: ["a b"]`, 1), rule: "script_params_default_safe", msg: `script param "allowed" default`},
```

  - Replace `TestLintSetRules` with the new contract:

```go
// E-2: blocks record per block, so two scripted controls may declare the
// same backup path or the same unit; the set lints clean.
func TestLintSetAllowsSharedRemediation(t *testing.T) {
	scripted := func(id, extra string) string {
		c := strings.Replace(goodControl, "id: muster.account.good", "id: "+id, 1)
		return strings.Replace(c, "remediation: { text_en: t, text_ko: 조치, risk: lockout_risk, idempotent: true }",
			`remediation: { text_en: t, text_ko: 조치, risk: none, idempotent: true, script: "true", validate: "true", `+extra+` }`, 1)
	}
	for _, c := range []struct{ name, extra string }{
		{"backup shared", "backup: [/etc/hosts]"},
		{"units shared", "units: [a.service]"},
	} {
		ps := lintSet(t, LintOptions{CustomFuncs: map[string]bool{}}, scripted("muster.account.aa", c.extra), scripted("muster.account.bb", c.extra))
		for _, p := range ps {
			if p.Rule == "backup_path_shared" || p.Rule == "units_shared" {
				t.Errorf("%s: %v", c.name, p)
			}
		}
	}
}
```

- [ ] **Step 8: Run** `go test ./internal/controls -run 'TestLintRules|TestLintSetAllows'`. Expected: FAIL on every new case (rules not reported) and on the renamed message.

- [ ] **Step 9: Rewrite `lintRemediation`.** Change the signature and its call (`lint.go:279`: `lintRemediation(c, add)`). Replace the body from `hasScript := …` to the end of the function with:

```go
	hasScript := strings.TrimSpace(r.Script) != ""
	hasState := len(r.Modes) > 0 || len(r.Sysctl) > 0 || len(r.Modules) > 0
	if hasScript && !r.Idempotent {
		add("remediation", "script requires idempotent: true")
	}
	if hasScript && strings.TrimSpace(r.Rollback) == "" && len(r.Backup) == 0 && len(r.Units) == 0 && !hasState {
		add("remediation", "script without rollback, backup, units, modes, sysctl or modules")
	}
	if hasScript && r.Validate == "" {
		add("script_needs_validate", "script without validate")
	}
	if len(r.Units) > 0 && !hasScript {
		add("units_needs_script", "units without script")
	}
	if hasState && !hasScript {
		add("state_needs_script", "modes, sysctl or modules without script")
	}
	if len(r.ScriptParams) > 0 && !hasScript {
		add("script_params_needs_script", "script_params without script")
	}
	if r.ScriptOnAbsent && !hasScript {
		add("script_on_absent_needs_script", "script_on_absent without script")
	}
	if len(r.Units) > 0 {
		for _, x := range []struct {
			name string
			has  bool
		}{{"rollback", strings.TrimSpace(r.Rollback) != ""}, {"backup", len(r.Backup) > 0}, {"modes", len(r.Modes) > 0}, {"sysctl", len(r.Sysctl) > 0}, {"modules", len(r.Modules) > 0}} {
			if x.has {
				add("units_exclusive", "units excludes %s: the unit state is the way back", x.name)
			}
		}
	}
	// ... the three usesUnits checks, the units_charset and units_order loops,
	// "backup without script", "validate without script" and the one-line
	// validate check stay exactly as they are ...
	lintScriptParams(c, add)
	lintStateEntries(r, add)
	seen := map[string]bool{}
	for _, p := range r.Backup {
		switch {
		case !strings.HasPrefix(p, "/"):
			add("remediation", "backup path %q is not absolute", p)
		case path.Clean(p) != p:
			add("remediation", "backup path %q is not clean", p)
		case !backupPathRe.MatchString(p):
			add("remediation", "backup path %q carries a character the script cannot carry", p)
		}
		if seen[p] {
			add("remediation", "backup path %q is repeated", p)
		}
		seen[p] = true
	}
}

// lintScriptParams holds script_params to the control's declared params and
// to the bodies that read them (3D-2c E-1).
func lintScriptParams(c *Control, add func(rule, format string, args ...any)) {
	r := c.Remediation
	declared := map[string]bool{}
	for _, n := range r.ScriptParams {
		switch {
		case !ValidParamName(n):
			add("script_params_declared", "script param %q is not a parameter name", n)
			continue
		case declared[n]:
			add("script_params_declared", "script param %q is repeated", n)
			continue
		}
		declared[n] = true
		p, ok := c.Params[n]
		if !ok {
			add("script_params_declared", "script param %q is not a declared parameter", n)
			continue
		}
		if _, safe := ScriptParamValue(p.Type, p.Default); !safe {
			add("script_params_default_safe", "script param %q default %v cannot be carried by a script", n, p.Default)
		}
	}
	usedInScript := map[string]bool{}
	for _, b := range []struct{ name, v string }{{"script", r.Script}, {"validate", r.Validate}, {"rollback", r.Rollback}} {
		for _, m := range pVarRe.FindAllStringSubmatch(b.v, -1) {
			if b.name == "script" {
				usedInScript[m[1]] = true
			}
			if !declared[m[1]] {
				add("script_params_used", "%s uses $P_%s, which script_params does not declare", b.name, m[1])
			}
		}
	}
	for _, n := range r.ScriptParams {
		if declared[n] && !usedInScript[n] {
			add("script_params_used", "script param %q is not used in script", n)
		}
	}
}

// lintStateEntries checks the modes, sysctl and modules lists (3D-2c E-3).
func lintStateEntries(r *Remediation, add func(rule, format string, args ...any)) {
	seen := map[string]bool{}
	for _, e := range r.Modes {
		if !ValidModesEntry(e) {
			add("modes_charset", "modes entry %q is not an absolute clean path with at most two /* segments", e)
		}
		if seen[e] {
			add("modes_charset", "modes entry %q is repeated", e)
		}
		seen[e] = true
		base, k := modesBase(e)
		for _, b := range r.Backup {
			rest, under := strings.CutPrefix(b, base+"/")
			if (k == 0 && b == base) || (k > 0 && under && strings.Count(rest, "/") == k-1) {
				add("modes_backup_overlap", "backup path %q is also covered by modes entry %q", b, e)
			}
		}
	}
	for _, x := range []struct {
		rule, kind string
		list       []string
		valid      func(string) bool
	}{{"sysctl_charset", "sysctl key", r.Sysctl, ValidSysctlKey}, {"modules_charset", "module", r.Modules, ValidModuleName}} {
		seen := map[string]bool{}
		for _, v := range x.list {
			if !x.valid(v) {
				add(x.rule, "%s %q is not one a script can carry", x.kind, v)
			}
			if seen[v] {
				add(x.rule, "%s %q is repeated", x.kind, v)
			}
			seen[v] = true
		}
	}
}
```

  Delete the old `units_exclusive` pair (now the loop), the `backup_reserved` check, the function `lintSharedRemediation` with its doc comment, and its call `out = append(out, lintSharedRemediation(s)...)`. Keep `r := c.Remediation` as the first line of `lintRemediation`.

- [ ] **Step 10: Run** `go test ./internal/controls/`. Expected: PASS, including `TestEveryMutantIsKilled` and `TestLintOfEmbeddedSetIsClean` (no shipped control uses the new fields yet). `gofmt -l .` and `go vet ./...` clean.

- [ ] **Step 11: Commit**

```bash
git add internal/controls/schema.go internal/controls/params.go internal/controls/params_script_test.go internal/controls/lint.go internal/controls/lint_test.go
git commit -m "controls: script_params, script_on_absent and the modes/sysctl/modules records, with their lint rules and validators"
```

---
### Task 3: The plan — `ScriptParams`, `ScriptOnAbsent`, the state lists, the six rollback words

**Files:**
- Modify: `internal/remedy/plan.go` (`Item` `:49-74`, the refusals `:181-185`, `item` `:224-263`)
- Test: `internal/remedy/fixture_test.go` (`testControls` `:42-109`), `internal/remedy/plan_test.go`

**Interfaces:**
- Consumes: Task 2's `Remediation` fields, `controls.ScriptParamValue`, `ValidParamName`, `ValidBackupPath`, `ValidModesEntry`, `ValidSysctlKey`, `ValidModuleName`; `check.ParamValues(c *controls.Control, overrides map[string]any) map[string]any` (`internal/check/value.go:21`).
- Produces: `type ParamValue struct{ Name, Value string }` (json `name`, `value`); `Item.ScriptParams []ParamValue`, `Item.ScriptOnAbsent bool`, `Item.Modes`, `Item.Sysctl`, `Item.Modules []string`; text-only reason `params_unsafe`; rollback word `state`.

- [ ] **Step 1: Add the fixture shapes** to `testControls` (and change the comment above it to "the shapes the planner distinguishes"):

```go
	"muster.test.h_params": `automation: auto
params:
  limit: { type: int, default: 5, description: d }
  names: { type: list<string>, default: ["a", "b"], description: d }
remediation:
  text_en: fix h
  text_ko: 조치 h
  risk: none
  idempotent: true
  script_params: [names, limit]
  script: |
    for n in $P_names; do printf '%s %s\n' "$n" "$P_limit" >> /etc/h.conf; done
  backup: [/etc/h.conf]
  validate: '[ "$P_limit" -ge 1 ]'
`,
	"muster.test.i_state": `automation: auto
remediation:
  text_en: fix i
  text_ko: 조치 i
  risk: none
  idempotent: true
  modes: ["/etc/i.d/*", /etc/i.conf]
  sysctl: [kernel.i_key]
  modules: [i-mod]
  script: chmod o-w /etc/i.conf
  validate: "true"
`,
	"muster.test.j_absent": `automation: auto
remediation:
  text_en: fix j
  text_ko: 조치 j
  risk: none
  idempotent: true
  script_on_absent: true
  script: printf 'J 1\n' >> /etc/j.conf
  backup: [/etc/j.conf]
  validate: grep -q '^J 1$' /etc/j.conf
`,
	"muster.test.k_both": `automation: auto
remediation:
  text_en: fix k
  text_ko: 조치 k
  risk: none
  idempotent: true
  sysctl: [kernel.k_key]
  backup: [/etc/k.conf]
  script: printf 'kernel.k_key = 1\n' > /etc/k.conf
  validate: "true"
`,
```

- [ ] **Step 2: Write the failing plan tests** in `plan_test.go`:

```go
func TestPlanScriptParamsCarryTheValueInForce(t *testing.T) {
	rep := testReport(row("muster.test.h_params", "FAIL", "r", "", "high"))
	// no Check.Params: the defaults are in force (S-1)
	it := itemByID(t, build(t, rep, Options{}), "muster.test.h_params")
	want := []ParamValue{{Name: "limit", Value: "5"}, {Name: "names", Value: "a b"}}
	if !it.Script || !reflect.DeepEqual(it.ScriptParams, want) {
		t.Fatalf("defaults: script %v, params %+v; want %+v", it.Script, it.ScriptParams, want)
	}
	rep.Check.Params = map[string]map[string]any{"muster.test.h_params": {"limit": 9, "names": []any{"x"}}}
	rep.Check.ParamSources = map[string]map[string]string{"muster.test.h_params": {"limit": "tuning", "names": "profile"}}
	it = itemByID(t, build(t, rep, Options{}), "muster.test.h_params")
	want = []ParamValue{{Name: "limit", Value: "9"}, {Name: "names", Value: "x"}}
	if !it.Script || it.TextOnlyReason != "" || !reflect.DeepEqual(it.ScriptParams, want) {
		t.Fatalf("tuned: script %v, reason %q, params %+v; want %+v (a control with script_params is never params_tuned)", it.Script, it.TextOnlyReason, it.ScriptParams, want)
	}
}

func TestPlanParamsUnsafe(t *testing.T) {
	for _, bad := range []map[string]any{
		{"limit": 5, "names": []any{"'; id; '"}},
		{"limit": 5, "names": []any{}},
		{"limit": "5", "names": []any{"a"}},
	} {
		rep := testReport(row("muster.test.h_params", "FAIL", "r", "", "high"))
		rep.Check.Params = map[string]map[string]any{"muster.test.h_params": bad}
		it := itemByID(t, build(t, rep, Options{}), "muster.test.h_params")
		if it.Script || it.TextOnlyReason != "params_unsafe" || len(it.ScriptParams) != 0 || it.ScriptParams == nil {
			t.Errorf("%v: script %v, reason %q, params %#v; want text-only params_unsafe with []", bad, it.Script, it.TextOnlyReason, it.ScriptParams)
		}
	}
}

func TestPlanScriptOnAbsent(t *testing.T) {
	rep := testReport(
		row("muster.test.j_absent", "FAIL", check.ReasonAbsentFailPrefix+"no PASS_MIN_LEN", "", "high"),
		row("muster.test.a_none", "FAIL", check.ReasonAbsentFailPrefix+"no file", "", "high"),
	)
	p := build(t, rep, Options{})
	if j := itemByID(t, p, "muster.test.j_absent"); !j.Script || !j.ScriptOnAbsent || j.TextOnlyReason != "" {
		t.Errorf("j_absent: script %v, on_absent %v, reason %q", j.Script, j.ScriptOnAbsent, j.TextOnlyReason)
	}
	if a := itemByID(t, p, "muster.test.a_none"); a.Script || a.ScriptOnAbsent || a.TextOnlyReason != "absent" {
		t.Errorf("a_none: script %v, on_absent %v, reason %q", a.Script, a.ScriptOnAbsent, a.TextOnlyReason)
	}
}

func TestPlanCopiesTheStateLists(t *testing.T) {
	it := itemByID(t, build(t, testReport(row("muster.test.i_state", "FAIL", "r", "", "high")), Options{}), "muster.test.i_state")
	if !reflect.DeepEqual(it.Modes, []string{"/etc/i.d/*", "/etc/i.conf"}) || !reflect.DeepEqual(it.Sysctl, []string{"kernel.i_key"}) || !reflect.DeepEqual(it.Modules, []string{"i-mod"}) {
		t.Fatalf("i_state lists: %v %v %v", it.Modes, it.Sysctl, it.Modules)
	}
}

func TestPlanRefusesAnUnsafeStateEntry(t *testing.T) {
	for _, c := range []struct {
		id, want string
		mutate   func(*controls.Remediation)
	}{
		{"muster.test.i_state", `modes entry "/etc/x';id;'"`, func(r *controls.Remediation) { r.Modes = []string{"/etc/x';id;'"} }},
		{"muster.test.i_state", `sysctl key "k;id"`, func(r *controls.Remediation) { r.Sysctl = []string{"k;id"} }},
		{"muster.test.i_state", `module "m id"`, func(r *controls.Remediation) { r.Modules = []string{"m id"} }},
		{"muster.test.a_none", `backup path "/etc/a b"`, func(r *controls.Remediation) { r.Backup = []string{"/etc/a b"} }},
		{"muster.test.h_params", `script param "Bad"`, func(r *controls.Remediation) { r.ScriptParams = []string{"Bad"} }},
	} {
		set := testSet(t)
		for i := range set.Controls {
			if set.Controls[i].ID == c.id {
				c.mutate(set.Controls[i].Remediation)
			}
		}
		_, err := Build(testReport(row(c.id, "FAIL", "r", "", "high")), set, Options{})
		if err == nil || !strings.Contains(err.Error(), "refusing to plan "+c.id+": "+c.want) {
			t.Errorf("%s: err = %v, want %q", c.id, err, c.want)
		}
	}
}
```

  `TestPlanRefusesAnUnsafeStateEntry`'s `h_params` case needs a declared `Bad` param to reach the formatter; the refusal is by name, so `item()` must not refuse it first: the name check runs in `Build` after `item()`, and `scriptParams` (Step 4) returns `params_unsafe` for an undeclared name — so the expected refusal comes from `Build`'s `ScriptParams` name check over the *control's* list. Implement the check over `c.Remediation.ScriptParams` (looked up by id), not over `it.ScriptParams`.

  Extend `TestPlanRollbackVocabulary`: add rows `h_params`, `i_state`, `k_both` (FAIL) and want entries `"muster.test.h_params": {"restore_backup", []string{"/etc/h.conf"}, true, true}`, `"muster.test.i_state": {"state", []string{}, true, true}`, `"muster.test.k_both": {"both", []string{"/etc/k.conf"}, true, true}`.

  Extend `TestPlanItemCopiesEveryField`'s `want` with `ScriptParams: []ParamValue{}, ScriptOnAbsent: false, Modes: []string{}, Sysctl: []string{}, Modules: []string{}`.

  Extend `TestPlanJSONShape` (and `render_test.go`'s `TestJSONEmptyListsAreArrays`) so the text-only `d_reboot` item's `script_params`, `modes`, `sysctl` and `modules` are each the JSON `[]`, and `script_on_absent` is `false`. Add a field-order assertion to `TestPlanJSONShape`:

```go
	keys := regexp.MustCompile(`"([a-z_]+)":`).FindAllStringSubmatch(string(mustJSONItem(t, data, 0)), -1)
	var order []string
	for _, k := range keys {
		order = append(order, k[1])
	}
	wantOrder := "id title_en title_ko status severity severity_source risk idempotent automation reason text_en text_ko script text_only_reason script_params script_on_absent rollback backup units modes sysctl modules validate planned"
	if strings.Join(order, " ") != wantOrder {
		t.Errorf("item field order:\n got %s\nwant %s", strings.Join(order, " "), wantOrder)
	}
```

  with the helper (add `regexp` to the test imports):

```go
// mustJSONItem returns item i of a marshalled plan, compact, in field order.
// c_lockout is item 0 by risk order only when it is the one lockout item; the
// test passes the index it means.
func mustJSONItem(t *testing.T, data []byte, i int) []byte {
	t.Helper()
	var p struct{ Items []json.RawMessage }
	if err := json.Unmarshal(data, &p); err != nil || len(p.Items) <= i {
		t.Fatalf("items: %v (%d)", err, len(p.Items))
	}
	return p.Items[i]
}
```

  (`ScriptParams` holds `{name, value}` objects, so the regexp's `"name":`/`"value":` would only appear for a scripted params item; `TestPlanJSONShape`'s three rows carry none.)

- [ ] **Step 3: Run** `go test ./internal/remedy -run 'TestPlan'`. Expected: build failure (`undefined: ParamValue`), then FAILs.

- [ ] **Step 4: Implement.** In `plan.go`:

```go
// ParamValue is one parameter a script reads as P_<Name> (3D-2c E-1), with
// the value in force formatted for the script. A slice of these, sorted by
// name, keeps the plan free of maps.
type ParamValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
```

  `Item` gains, after `TextOnlyReason` (whose comment becomes `"" | no_script | absent | params_tuned | params_unsafe`):

```go
	ScriptParams   []ParamValue `json:"script_params"`    // [] unless scripted (E-1)
	ScriptOnAbsent bool         `json:"script_on_absent"` // the control's declaration, when scripted (E-5)
```

  the `Rollback` comment becomes `none | declared | restore_backup | units | state | both`, and after `Units`:

```go
	Modes   []string `json:"modes"`   // [] unless scripted (E-3)
	Sysctl  []string `json:"sysctl"`
	Modules []string `json:"modules"`
```

  `item()`'s literal gains `ScriptParams: []ParamValue{}, Modes: []string{}, Sysctl: []string{}, Modules: []string{}`. Its switch becomes:

```go
	switch {
	case strings.TrimSpace(r.Script) == "":
		it.TextOnlyReason = "no_script"
	case strings.HasPrefix(row.Reason, check.ReasonAbsentFailPrefix) && !r.ScriptOnAbsent: // Z-6: the bare reason
		it.TextOnlyReason = "absent"
	case len(r.ScriptParams) == 0 && tuned(cb.ParamSources[row.ID]):
		it.TextOnlyReason = "params_tuned"
	default:
		vals, ok := scriptParams(c, cb.Params[row.ID])
		if !ok {
			it.TextOnlyReason = "params_unsafe"
			break
		}
		it.Script = true
		it.ScriptBody, it.ValidateCmd, it.RollbackBody = r.Script, strings.TrimSuffix(r.Validate, "\n"), r.Rollback
		it.ScriptParams, it.ScriptOnAbsent = vals, r.ScriptOnAbsent
		it.Backup = append([]string{}, r.Backup...)
		it.Validate = r.Validate != ""
		it.Units = append([]string{}, r.Units...)
		it.Modes = append([]string{}, r.Modes...)
		it.Sysctl = append([]string{}, r.Sysctl...)
		it.Modules = append([]string{}, r.Modules...)
		it.Rollback = rollbackWord(r)
	}
```

  and two helpers after `item`:

```go
// scriptParams formats the value in force of each script_params entry (S-1:
// the default when the check block carries none), sorted by name; false when
// any value cannot be carried.
func scriptParams(c *controls.Control, inForce map[string]any) ([]ParamValue, bool) {
	vals := check.ParamValues(c, inForce)
	names := append([]string(nil), c.Remediation.ScriptParams...)
	sort.Strings(names)
	out := []ParamValue{}
	for _, n := range names {
		p, ok := c.Params[n]
		if !ok {
			return nil, false
		}
		s, ok := controls.ScriptParamValue(p.Type, vals[n])
		if !ok {
			return nil, false
		}
		out = append(out, ParamValue{Name: n, Value: s})
	}
	return out, true
}

// rollbackWord names the way back a scripted item declares (3D-2c §3): units
// alone; two or more of rollback, backup and state; or the one it has.
func rollbackWord(r *controls.Remediation) string {
	if len(r.Units) > 0 {
		return "units"
	}
	hasRB, hasBK := strings.TrimSpace(r.Rollback) != "", len(r.Backup) > 0
	hasST := len(r.Modes)+len(r.Sysctl)+len(r.Modules) > 0
	n := 0
	for _, b := range []bool{hasRB, hasBK, hasST} {
		if b {
			n++
		}
	}
	switch {
	case n >= 2:
		return "both"
	case hasST:
		return "state"
	case hasRB:
		return "declared"
	}
	return "restore_backup"
}
```

  Replace the units re-check after `p.Items = append(...)` with:

```go
			if err := recheck(row.ID, set, p.Items[len(p.Items)-1]); err != nil {
				return nil, err
			}
```

  and add:

```go
// recheck refuses a plan whose declared names the script would put on a
// command line outside their lint patterns (3D-2b T-3, 3D-2c S-4): the set
// may be hand-built.
func recheck(id string, set *controls.Set, it Item) error {
	kinds := []struct {
		kind  string
		list  []string
		valid func(string) bool
	}{
		{"unit", it.Units, controls.ValidUnitName},
		{"backup path", it.Backup, controls.ValidBackupPath},
		{"modes entry", it.Modes, controls.ValidModesEntry},
		{"sysctl key", it.Sysctl, controls.ValidSysctlKey},
		{"module", it.Modules, controls.ValidModuleName},
	}
	if c, ok := set.ByID(id); ok && c.Remediation != nil {
		kinds = append(kinds, struct {
			kind  string
			list  []string
			valid func(string) bool
		}{"script param", c.Remediation.ScriptParams, controls.ValidParamName})
	}
	for _, k := range kinds {
		for _, v := range k.list {
			if !k.valid(v) {
				return fmt.Errorf("refusing to plan %s: %s %q is not one a script can carry", id, k.kind, v)
			}
		}
	}
	return nil
}
```

  The unit refusal message changes from `unit %q is not a unit name a script can carry` to `unit %q is not one a script can carry`; `TestPlanRefusesAnUnsafeUnit` checks only the prefix `refusing to plan muster.test.g_units: unit "x';id;'.service"`, which still holds.

- [ ] **Step 5: Run** `go test ./internal/remedy/ -run 'TestPlan|TestJSON'`. Expected: PASS. Then `go test ./internal/remedy/`: the script goldens and `TestScriptEveryLineIsTemplateBodyOrComment` do not move yet (no fixture row in `fullPlan` uses a new shape), and `TestJSONGolden`'s `full.json`/`empty.json` gain the five fields per item — regenerate with `go test ./internal/remedy -run 'TestJSONGolden' -update`, review the diff (five keys per item, nothing else), and re-run. `go test ./cmd/muster/`: `TestFixThreeFormats` decodes with `DisallowUnknownFields` into `remedy.Plan` and passes; the examples gate compares the fix-report JSON byte for byte while the control set is unchanged and goes red on `examples/*-fix-report.json` (the five new keys). Quote that failure in the report; do not edit `examples/`.

- [ ] **Step 6: Commit**

```bash
git add internal/remedy/plan.go internal/remedy/plan_test.go internal/remedy/fixture_test.go internal/remedy/render_test.go internal/remedy/testdata/full.json internal/remedy/testdata/empty.json
git commit -m "remedy: carry script_params values, script_on_absent and the state lists; six rollback words; re-check every name a script carries"
```

---

### Task 4: The script — per-block records, the state helpers, the block head and the failure order

**Files:**
- Modify: `internal/remedy/script.go` (`prologueBackup` `:48-72`, `unitHelpers` `:76-149`, `prologue` `:154-165`, `textOnlyPhrase` `:177-181`, `failurePath` `:225-240`, `block` `:245-298`)
- Test: `internal/remedy/script_test.go` (`fullPlan` `:55-77`, `poisonControls` `:118-137`, `poisonPlan` `:160-189`, `templateLines` `:337-375`, `TestScriptEveryLineIsTemplateBodyOrComment` `:377-412`, `TestScriptPrologueOrder` `:492-503`, `TestScriptBackupFailureStopsTheBlock` `:667-707`), new `internal/remedy/state_test.go`; goldens `internal/remedy/testdata/{full,empty,capped,poison,all-scripted}.sh`, `full.table`, `poison.table`, `full.json`

**Interfaces:**
- Consumes: Task 3's `Item` fields.
- Produces: the prologue constants `stateHelpers` (the eight new functions), the block head of S-3, the failure order rollback → `restore_units` → `restore_modes` → `restore` → `restore_sysctl` → `restore_modules`; `textOnlyPhrase["params_unsafe"]`.

- [ ] **Step 1: Write the failing helper tests** `internal/remedy/state_test.go`:

```go
package remedy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helperScript is the prologue's helpers with log() and $MB set, for running
// them directly under sh (the block functions call them the same way).
func helperScript(mb, body string) string {
	return "set -u\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\nMB=" + shQuote(mb) + "\nmkdir -p \"$MB\"\n" +
		backupHelpers + "\n" + stateHelpers + "\n" + body + "\n"
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func runSh(t *testing.T, script, bin string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	path := os.Getenv("PATH")
	if bin != "" {
		path = bin + string(os.PathListSeparator) + path
	}
	cmd.Env = append(os.Environ(), append([]string{"PATH=" + path}, env...)...)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func mode(t *testing.T, p string) string {
	t.Helper()
	out, err := exec.Command("stat", "-c", "%a", p).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestModesHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	d := filepath.Join(root, "d")
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "d/a"), filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	save := "save_modes " + shQuote(d+"/*") + " " + shQuote(d+"/*/*") + " " + shQuote(filepath.Join(root, "none")+"/*") + " || exit 9"
	if out, code := runSh(t, helperScript(mb, save), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	rec, _ := os.ReadFile(filepath.Join(mb, "modes.list"))
	for _, want := range []string{"/d/a\n", "/d/.hidden\n", "/d/with space\n", "/d/sub\n", "/d/sub/x\n"} {
		if !strings.Contains(string(rec), want) {
			t.Errorf("modes.list lacks %q:\n%s", want, rec)
		}
	}
	if strings.Contains(string(rec), "/d/link") {
		t.Errorf("modes.list records a symlink:\n%s", rec)
	}
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if err := os.Chmod(filepath.Join(root, p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a rerun keeps the first record: the 0600 modes are not recorded
	if out, code := runSh(t, helperScript(mb, save), ""); code != 0 {
		t.Fatalf("rerun: %d %s", code, out)
	}
	if out, code := runSh(t, helperScript(mb, "restore_modes"), ""); code != 0 {
		t.Fatalf("restore: %d %s", code, out)
	}
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if got := mode(t, filepath.Join(root, p)); got != "644" {
			t.Errorf("%s restored to %s, want 644", p, got)
		}
	}
}

func TestModesHelpersRefuseASwappedEntry(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	victim := filepath.Join(root, "victim")
	f := filepath.Join(root, "spool", "job")
	for _, p := range []string{victim, f} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runSh(t, helperScript(mb, "save_modes "+shQuote(filepath.Join(root, "spool")+"/*")+" || exit 9"), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, f); err != nil { // the spool's owner swaps its entry
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, "restore_modes"), "")
	if code == 0 || !strings.Contains(out, "restore_modes: "+f+" changed type, left as is") {
		t.Fatalf("restore over a swapped entry: exit %d, %s", code, out)
	}
	if got := mode(t, victim); got != "600" {
		t.Errorf("restore_modes wrote through the symlink: victim is %s", got)
	}
}

func TestBackupMarkerCases(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "drop.conf")
	run := func(body string) string {
		out, code := runSh(t, helperScript(mb, body), "")
		if code != 0 {
			t.Fatalf("%s: exit %d %s", body, code, out)
		}
		return out
	}
	// absent at run 1: a marker; restore removes what the body created
	run("backup " + shQuote(p) + " || exit 9")
	if err := os.WriteFile(p, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("restore " + shQuote(p) + " || exit 9")
	if exists(p) {
		t.Fatal("restore left a path that was absent at backup")
	}
	// absent at run 1, present at run 2: the marker is replaced by a copy
	if err := os.WriteFile(p, []byte("operator"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("backup " + shQuote(p) + " || exit 9")
	if exists(filepath.Join(mb, "absent"+p)) || !exists(filepath.Join(mb, "files"+p)) {
		t.Fatal("run 2 kept the marker or took no copy")
	}
	if err := os.WriteFile(p, []byte("script"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("restore " + shQuote(p) + " || exit 9")
	if b, _ := os.ReadFile(p); string(b) != "operator" {
		t.Fatalf("restore after run 2: %q, want the operator's copy", b)
	}
	// copied at run 1, gone at run 2: no marker beside the copy, the copy is restored
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	run("backup " + shQuote(p) + " || exit 9")
	if exists(filepath.Join(mb, "absent"+p)) {
		t.Fatal("a marker was written beside a copy")
	}
	run("restore " + shQuote(p) + " || exit 9")
	if b, _ := os.ReadFile(p); string(b) != "operator" {
		t.Fatalf("restore after the path was gone: %q", b)
	}
	// a marker whose path is now a directory is logged and counts as incomplete
	q := filepath.Join(root, "dir.conf")
	run("backup " + shQuote(q) + " || exit 9")
	if err := os.Mkdir(q, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, "restore "+shQuote(q)), "")
	if code == 0 || !strings.Contains(out, "restore: "+q+" is now a directory, left as is") {
		t.Fatalf("restore over a directory: exit %d %s", code, out)
	}
}

// sysctlStub keeps one file per key under $SYSCTL_STATE; a key with a
// .oneway file refuses a write once its value is in that file; every -w is
// logged to $SYSCTL_STATE/calls.
const sysctlStub = `s="$SYSCTL_STATE"
case "$1" in
  -n) shift; [ "$1" = -- ] && shift; f="$s/$1"; [ -f "$f" ] || exit 255; cat "$f";;
  -q) shift; [ "$1" = -w ] && shift; [ "$1" = -- ] && shift
      k=${1%%=*}; v=${1#*=}; [ -f "$s/$k" ] || exit 255
      if [ -f "$s/$k.oneway" ] && grep -qx "$(cat "$s/$k")" "$s/$k.oneway"; then exit 1; fi
      printf '%s\n' "$v" > "$s/$k"; printf 'w %s=%s\n' "$k" "$v" >> "$s/calls";;
  *) exit 2;;
esac
`

const modprobeStub = `s="$MODPROBE_STATE"
printf '%s\n' "$*" >> "$s/calls"
case "$1" in
  --ignore-install) shift; [ "$1" = -- ] && shift; [ -f "$s/fail" ] && exit 1; printf '%s 16384 0 - Live 0x0\n' "$1" >> "$s/modules";;
  -r) shift; [ "$1" = -- ] && shift; [ -f "$s/busy" ] && exit 1; grep -v "^$1 " "$s/modules" > "$s/m.new" || :; mv "$s/m.new" "$s/modules";;
  --showconfig) cat "$s"/conf/* 2>/dev/null | awk '$1 == "install" { gsub(/-/, "_", $2) } { print }';;
  *) exit 2;;
esac
`

func TestSysctlHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	bin, st, mb := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "sysctl", sysctlStub)
	for k, v := range map[string]string{"kernel.a": "0", "kernel.b": "2"} {
		if err := os.WriteFile(filepath.Join(st, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := "SYSCTL_STATE=" + st
	script := helperScript(mb, `save_sysctl kernel.a kernel.b kernel.missing || exit 9
sysctl -q -w kernel.a=1; sysctl -q -w kernel.b=1
save_sysctl kernel.a || exit 9
restore_sysctl kernel.a kernel.b kernel.missing`)
	if out, code := runSh(t, script, bin, env); code != 0 {
		t.Fatalf("exit %d %s", code, out)
	}
	for k, want := range map[string]string{"kernel.a": "0", "kernel.b": "2"} {
		if b, _ := os.ReadFile(filepath.Join(st, k)); strings.TrimSpace(string(b)) != want {
			t.Errorf("%s restored to %q, want %s", k, b, want)
		}
	}
	rec, _ := os.ReadFile(filepath.Join(mb, "sysctl.list"))
	if !strings.Contains(string(rec), "kernel.missing absent\n") || strings.Count(string(rec), "kernel.a ") != 1 {
		t.Errorf("sysctl.list:\n%s", rec)
	}
	// a refused write is incomplete, and the next key is still restored
	if err := os.WriteFile(filepath.Join(st, "kernel.a.oneway"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, "sysctl -q -w kernel.a=1; sysctl -q -w kernel.b=1\nrestore_sysctl kernel.a kernel.b"), bin, env)
	if code == 0 {
		t.Fatalf("a refused restore returned 0: %s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(st, "kernel.b")); strings.TrimSpace(string(b)) != "2" {
		t.Errorf("kernel.b after a refused kernel.a: %q", b)
	}
}

func TestModulesHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	bin, st, mb := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "modprobe", modprobeStub)
	procModules := filepath.Join(st, "modules")
	if err := os.WriteFile(procModules, []byte("udf 16384 0 - Live 0x0\nusb_storage 16384 0 - Live 0x0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	helpers := strings.ReplaceAll(stateHelpers, "/proc/modules", procModules)
	script := "set -u\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\nMB=" + shQuote(mb) + "\n" + helpers + `
save_modules udf usb-storage sctp || exit 9
modprobe -r udf; modprobe -r usb_storage
restore_modules udf usb-storage sctp`
	if out, code := runSh(t, script, bin, "MODPROBE_STATE="+st); code != 0 {
		t.Fatalf("exit %d %s", code, out)
	}
	calls, _ := os.ReadFile(filepath.Join(st, "calls"))
	for _, want := range []string{"--ignore-install -- udf\n", "--ignore-install -- usb_storage\n"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("calls lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(string(calls), "sctp") {
		t.Errorf("a module not loaded at record time was loaded:\n%s", calls)
	}
	if err := os.WriteFile(filepath.Join(st, "fail"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runSh(t, script, bin, "MODPROBE_STATE="+st); code == 0 {
		t.Fatalf("a failing modprobe returned 0: %s", out)
	}
}
```

  Add to `script_test.go` a failure-order test:

```go
func TestScriptFailurePathOrder(t *testing.T) {
	it := Item{ID: "muster.test.order", Status: "fail", Severity: "high", Risk: "none", Planned: true, Script: true,
		ScriptBody: "true", Validate: true, ValidateCmd: "true", RollbackBody: "true", Rollback: "both",
		Backup: []string{"/etc/o.conf"}, Modes: []string{"/etc/o.d/*"}, Sysctl: []string{"kernel.o"}, Modules: []string{"o"},
		ScriptParams: []ParamValue{}}
	text := strings.Join(block(1, 1, it, "lockout_risk"), "\n")
	branch := text[strings.Index(text, `log "muster.test.order: validate failed, rolling back"`):]
	last := -1
	for _, step := range []string{"    ( set -e", "    restore_modes ||", "    restore /etc/o.conf ||", "    restore_sysctl kernel.o ||", "    restore_modules o ||"} {
		i := strings.Index(branch, step)
		if i <= last {
			t.Fatalf("%q out of order in the failure path:\n%s", step, branch)
		}
		last = i
	}
	head := text[:strings.Index(text, "  ( set -e")]
	last = -1
	for _, step := range []string{`  MB="$MUSTER_BACKUP/blocks/fix_muster_test_order"; mkdir -p "$MB" ||`, "  backup /etc/o.conf ||", "  save_modes '/etc/o.d/*' ||", "  save_sysctl kernel.o ||", "  save_modules o ||"} {
		i := strings.Index(head, step)
		if i <= last {
			t.Fatalf("%q out of order in the block head:\n%s", step, head)
		}
		last = i
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/remedy -run 'TestScriptFailurePathOrder'` (Windows) and, on the lab, `go test ./internal/remedy -run 'TestModes|TestBackupMarker|TestSysctlHelpers|TestModulesHelpers'`. Expected: build failure (`undefined: backupHelpers`, `stateHelpers`).

- [ ] **Step 3: Split and rewrite the prologue constants.** `prologueBackup` keeps only the `MUSTER_BACKUP` lines and `backupOwnerLine`; `backup()`/`restore()` move to a new constant `backupHelpers`, rewritten verbatim from spec §3 with the round-2 else-branch:

```go
// backupHelpers copy a block's declared paths under $MB/files and mark the
// absent ones under $MB/absent (3D-2c E-2); restore removes a path that was
// absent and copies back one that was not. They keep their status in brc,
// never the block's rc (T-6).
const backupHelpers = `backup() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      if [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
      rm -f "$MB/absent$p"
      mkdir -p "$MB/files$(dirname "$p")" && cp -a "$p" "$MB/files$p" || return 1
    else
      if [ -e "$MB/absent$p" ] || [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then continue; fi
      mkdir -p "$MB/absent$(dirname "$p")" && : > "$MB/absent$p" || return 1
    fi
  done
}
restore() {
  brc=0
  for p in "$@"; do
    if [ -e "$MB/absent$p" ]; then
      if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
      rm -f "$p" || { log "restore: $p failed"; brc=1; }
      continue
    fi
    { [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MB/files$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}`
```

  In `unitHelpers`, replace every `$MUSTER_BACKUP/muster-units` with `$MB/units` (fourteen places; `mkdir -p "$MB/units" || return 1`).

  Add `stateHelpers`, verbatim from spec §3 with the round-2 changes (`ENVIRON` dedupe, `case` in `restore_sysctl`, `grep` on `/proc/modules`, `--ignore-install`):

```go
// stateHelpers record and restore the three state kinds (3D-2c E-3): a
// path's owner, group, mode and type; a sysctl key's runtime value; a
// module's load state. Each keeps the first record per block; each restore
// returns 1 when anything was left as is.
const stateHelpers = `modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) if [ -e "$1" ] && [ ! -L "$1" ]; then printf '%s\n' "$1"; fi;;
  esac
  return 0
}
modes_type() { if [ -f "$1" ]; then echo f; elif [ -d "$1" ]; then echo d; else echo o; fi; }
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      P="$p" awk '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == ENVIRON["P"]) f=1 } END { exit !f }' "$MB/modes.list" && continue
      if s=$(stat -c '%u %g %a' -- "$p" 2>/dev/null); then
        printf '%s %s %s\n' "$s" "$(modes_type "$p")" "$p" >> "$MB/modes.list" || exit 1
      elif [ -e "$p" ]; then
        exit 1
      else
        log "save_modes: $p vanished, not recorded"
      fi
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode t p; do
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then continue; fi
    if [ -L "$p" ] || [ "$(modes_type "$p")" != "$t" ]; then log "restore_modes: $p changed type, left as is"; mrc=1; continue; fi
    if chown -- "$uid:$gid" "$p"; then chmod -- "$mode" "$p" || mrc=1; else mrc=1; fi
  done < "$MB/modes.list"
  return $mrc
}
save_sysctl() {
  [ -f "$MB/sysctl.list" ] || : > "$MB/sysctl.list" || return 1
  for k in "$@"; do
    awk -v k="$k" '$1 == k { f=1 } END { exit !f }' "$MB/sysctl.list" && continue
    v=$(sysctl -n -- "$k" 2>/dev/null) || v=absent
    printf '%s %s\n' "$k" "$v" >> "$MB/sysctl.list" || return 1
  done
}
restore_sysctl() {
  src=0
  for k in "$@"; do
    v=$(awk -v k="$k" '$1 == k { $1=""; sub(/^ /, ""); print; exit }' "$MB/sysctl.list")
    case "$v" in ''|absent) continue;; esac
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if grep -q "^$n " /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe --ignore-install -- "$n" || orc=1
  done
  return $orc
}`
```

  `prologue()`'s last write becomes `b.WriteString(prologueBackup + "\n" + backupHelpers + "\n" + unitHelpers + "\n" + stateHelpers + "\nfailed=0\n")`. `textOnlyPhrase` gains `"params_unsafe": "a parameter value cannot be carried safely; see muster check --format json: check.params"`.

- [ ] **Step 4: Rewrite the block head and the failure path.** In `block()`, replace the lines from `lines = append(lines, fn+"() {")` through the `save_units` append with:

```go
		lines = append(lines, fn+"() {")
		for _, pv := range it.ScriptParams {
			lines = append(lines, "  P_"+pv.Name+"='"+pv.Value+"'")
		}
		stop := ` || { log "` + it.ID + `: backup failed, nothing changed"; return 1; }`
		lines = append(lines, `  MB="$MUSTER_BACKUP/blocks/`+fn+`"; mkdir -p "$MB"`+stop)
		quoted := make([]string, len(it.Modes))
		for i, e := range it.Modes {
			quoted[i] = "'" + e + "'"
		}
		for _, rec := range []struct {
			cmd  string
			args []string
		}{{"backup", it.Backup}, {"save_units", it.Units}, {"save_modes", quoted}, {"save_sysctl", it.Sysctl}, {"save_modules", it.Modules}} {
			if len(rec.args) > 0 {
				lines = append(lines, "  "+rec.cmd+" "+strings.Join(rec.args, " ")+stop)
			}
		}
```

  `failurePath` becomes:

```go
// failurePath is the way back (3D-2c §3): the declared rollback in its own
// subshell, then each record kind's restore in a fixed order — units, modes,
// files and absent markers, sysctl values (after the file that would persist
// the script's value is gone), modules (after their install line is gone or
// put back).
func failurePath(it Item, pfx string) []string {
	var out []string
	if strings.TrimSpace(it.RollbackBody) != "" {
		out = append(out, pfx+"( set -e")
		out = append(out, indent(it.RollbackBody, pfx+"  ")...)
		out = append(out, pfx+"); rrc=$?",
			fmt.Sprintf(`%s[ "$rrc" -eq 0 ] || log "%s: rollback failed (rc $rrc)"`, pfx, it.ID))
	}
	incomplete := ` || log "` + it.ID + `: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`
	for _, rs := range []struct {
		cmd  string
		args []string
		bare bool
	}{{"restore_units", it.Units, false}, {"restore_modes", it.Modes, true}, {"restore", it.Backup, false}, {"restore_sysctl", it.Sysctl, false}, {"restore_modules", it.Modules, false}} {
		switch {
		case len(rs.args) == 0:
		case rs.bare:
			out = append(out, pfx+rs.cmd+incomplete)
		default:
			out = append(out, pfx+rs.cmd+" "+strings.Join(rs.args, " ")+incomplete)
		}
	}
	return out
}
```

- [ ] **Step 5: Teach the template test the new lines.** In `templateLines`, inside the item loop, after the `Units` block add:

```go
		stop := ` || { log "` + id + `: backup failed, nothing changed"; return 1; }`
		incomplete := ` || log "` + id + `: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`
		ok[`  MB="$MUSTER_BACKUP/blocks/`+fn+`"; mkdir -p "$MB"`+stop] = true
		for _, pv := range it.ScriptParams {
			ok["  P_"+pv.Name+"='"+pv.Value+"'"] = true
		}
		if len(it.Modes) > 0 {
			q := make([]string, len(it.Modes))
			for i, e := range it.Modes {
				q[i] = "'" + e + "'"
			}
			ok["  save_modes "+strings.Join(q, " ")+stop] = true
			ok["    restore_modes"+incomplete] = true
		}
		if len(it.Sysctl) > 0 {
			ks := strings.Join(it.Sysctl, " ")
			ok["  save_sysctl "+ks+stop] = true
			ok["    restore_sysctl "+ks+incomplete] = true
		}
		if len(it.Modules) > 0 {
			ms := strings.Join(it.Modules, " ")
			ok["  save_modules "+ms+stop] = true
			ok["    restore_modules "+ms+incomplete] = true
		}
```

  In `TestScriptEveryLineIsTemplateBodyOrComment`'s line loop, add after the `poisonHash` check:

```go
			if strings.Contains(l, "'; id; '") {
				t.Errorf("%s line %d carries the unsafe parameter value: %q", g.name, i+1, l)
			}
```

  Extend `TestScriptPrologueOrder`'s list: after `restore_units() {` insert `modes_paths() {`, `modes_type() {`, `save_modes() {`, `restore_modes() {`, `save_sysctl() {`, `restore_sysctl() {`, `save_modules() {`, `restore_modules() {`; and move `backup() {`, `restore() {` after `backupOwnerLine` (they still follow it).

- [ ] **Step 6: Extend the plans.** `fullPlan` gains the rows `row("muster.test.h_params", "FAIL", "clause does not hold", "", "medium")` and `row("muster.test.i_state", "FAIL", "clause does not hold", "", "medium")` after `g_units`; `TestScriptBlocksAreIndependent`'s planned-scripted count goes from 4 to 6. `poisonControls` gains:

```go
	"muster.test.p_params": `automation: auto
params:
  bad: { type: string, default: ok, description: d }
remediation:
  text_en: fix p
  text_ko: 조치 p
  risk: none
  idempotent: true
  script_params: [bad]
  script: printf '%s\n' "$P_bad" > /etc/p.conf
  backup: [/etc/p.conf]
  validate: "true"
`,
```

  and `poisonPlan` adds `"muster.test.p_params"` to its row loop, sets `rep.Check.Params = map[string]map[string]any{"muster.test.p_params": {"bad": "'; id; '"}}`, asserts `len(p.Items) != 3`, and asserts the `p_params` item is `params_unsafe`. Add to `render_test.go`:

```go
func TestJSONCarriesNoUnsafeParameter(t *testing.T) {
	if bytes.Contains(JSON(poisonPlan(t)), []byte("'; id; '")) {
		t.Fatal("the unsafe parameter value reached the plan JSON")
	}
}
```

  `TestScriptBackupFailureStopsTheBlock` makes the copy fail at the new layout: the blocking file goes at `filepath.Join(bk, "blocks", "fix_muster_test_backup_fails", "files"+tmp, "a")` (create its parent as a directory and `a` as a directory so `cp -a` onto it fails), instead of `bk+tmp/a`. `TestScriptReusedBackupKeepsTheFirstCopy` and the other hand-built-item tests keep their assertions (their log lines are unchanged).

- [ ] **Step 7: Run and regenerate.** `go test ./internal/remedy/` on Windows: everything but the goldens passes. Regenerate: `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden|TestJSONGolden' -update`. Review the diff: every block gains its `MB=` line; `full.sh` gains the `h_params` and `i_state` blocks (two `P_` lines; `save_modes '/etc/i.d/*' '/etc/i.conf'`, `save_sysctl kernel.i_key`, `save_modules i-mod` and their three restores); `poison.sh` gains a text-only `p_params` block reading `# text only: a parameter value cannot be carried safely; …`; the prologue gains `backup()`/`restore()` on `$MB` and the eight state helpers; `all-scripted.sh` changes only by the prologue and `MB=` lines (16 blocks). Then run the whole package on the lab with root (`lab-run.sh 'cd /root/muster && go test ./internal/remedy/'`) and `make shellcheck` there through the shellcheck image (`docker run --rm -v /root/muster:/mnt koalaman/shellcheck-alpine:stable sh -c 'cd /mnt && for f in internal/remedy/testdata/*.sh; do shellcheck -s sh "$f" || exit 1; done'`). Expected: PASS and clean. `go test ./cmd/muster/`: the examples gate is red on the fix reports (template change, set unchanged) — quote it once.

- [ ] **Step 8: Commit**

```bash
git add internal/remedy/script.go internal/remedy/script_test.go internal/remedy/state_test.go internal/remedy/render_test.go internal/remedy/testdata
git commit -m "remedy: per-block record directories, the modes/sysctl/modules helpers, P_ lines and the six-step failure path"
```

---
### Task 5: The sixteen sysctl bodies, their pin, and `controls/VERSION`

**Files:**
- Modify: the sixteen `controls/beyond/*.yaml` of spec §4.1 (their `remediation:` blocks), `controls/VERSION`
- Create: `internal/collect/collectors/remediation_sysctl_test.go` (Linux), `internal/remedy/shipped_bodies_test.go` (Linux)
- Modify: `controls/testdata/_roundtrip.yaml` (Step 6)

**Interfaces:**
- Consumes: Task 2's fields and lint; Task 4's helpers (the bodies record through `save_sysctl`/`restore_sysctl` and the file through `backup`/`restore`).
- Produces: `shippedControl(t, id) *controls.Control` and `pEnv(t, c) []string` in `shipped_bodies_test.go`, used by Tasks 6–8.

**The body shape.** Every sysctl control's remediation gains `sysctl: [<keys>]`, `backup: [/etc/sysctl.d/99-muster-<name>.conf]` (`<name>` = the control name with `_` → `-`), a `script` that is the header below, one `case` line per key, and the `chmod` line, and a one-line `validate` that is the same `case` lines with `*) false;;` in place of the write, joined by ` && `. The header:

```sh
f=/etc/sysctl.d/99-muster-<name>.conf
put() {
  sysctl -q -w "$1=$2"
  if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
}
```

A literal key line is `case "$(sysctl -n <key>)" in <arms>) ;; *) put <key> <value>;; esac`. A parameter key line is `case " $P_<param> " in *" $(sysctl -n <key>) "*) ;; *) put <key> "$first";; esac`, preceded once by `first=${P_<param>%% *}`. The last script line is `if [ -f "$f" ]; then chmod 644 "$f"; fi`. `syn_cookies_enabled`, in full:

```yaml
remediation:
  text_en: Write net.ipv4.tcp_syncookies = 1 into /etc/sysctl.d/99-muster-syn-cookies-enabled.conf and apply it with sysctl --system; <the rest of today's sentence unchanged>
  text_ko: <today's text, with the same file named>
  risk: none
  idempotent: true
  sysctl: [net.ipv4.tcp_syncookies]
  backup: [/etc/sysctl.d/99-muster-syn-cookies-enabled.conf]
  script: |
    f=/etc/sysctl.d/99-muster-syn-cookies-enabled.conf
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in 1) ;; *) put net.ipv4.tcp_syncookies 1;; esac
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  validate: |
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in 1) ;; *) false;; esac
```

(Every new validate is a `|` block scalar of one line: the lint's `oneLine` trims its one trailing newline, and no quoting rule of YAML can bite.)

The keys, arms and values, in the order the `sysctl:` list, the `case` lines and the validate carry them:

| control (`muster.beyond.`) | key: arms → value | params / risk |
|---|---|---|
| `aslr_and_link_protection` | `kernel.randomize_va_space`: `2` → 2; `fs.protected_symlinks`: `1` → 1; `fs.protected_hardlinks`: `1` → 1; `fs.protected_fifos`: `1\|2` → 1; `fs.protected_regular`: `1\|2` → 2 | — |
| `icmp_broadcast_and_bogus_ignored` | `net.ipv4.icmp_echo_ignore_broadcasts`: `1` → 1; `net.ipv4.icmp_ignore_bogus_error_responses`: `1` → 1 | — |
| `icmp_redirects_ignored` | `net.ipv4.conf.all.accept_redirects`, `net.ipv4.conf.default.accept_redirects`, `net.ipv4.conf.all.secure_redirects`, `net.ipv4.conf.default.secure_redirects`, `net.ipv4.conf.all.send_redirects`, `net.ipv4.conf.default.send_redirects`: each `0` → 0 | — |
| `ip_forwarding_disabled` | `net.ipv4.ip_forward`: `$P_allowed_forward` → `$first`, then the companion (below) | `script_params: [allowed_forward]`; risk `restart_service` |
| `ipv6_forwarding_disabled` | `net.ipv6.conf.all.forwarding`, `net.ipv6.conf.default.forwarding`: `$P_allowed_forward` → `$first` | `script_params: [allowed_forward]`; risk `restart_service` |
| `ipv6_redirects_ignored` | `net.ipv6.conf.all.accept_redirects`, `net.ipv6.conf.default.accept_redirects`: `0` → 0 | — |
| `ipv6_router_advertisements_ignored` | `net.ipv6.conf.all.accept_ra`, `net.ipv6.conf.default.accept_ra`: `$P_allowed_accept_ra` → `$first` | `script_params: [allowed_accept_ra]` |
| `ipv6_source_routing_rejected` | `net.ipv6.conf.all.accept_source_route`, `net.ipv6.conf.default.accept_source_route`: `0` → 0 | — |
| `kernel_pointer_exposure` | `kernel.kptr_restrict`: `1\|2` → 1; `kernel.dmesg_restrict`: `1` → 1 | — |
| `ptrace_restriction` | `kernel.yama.ptrace_scope`: `1\|2\|3` → 1; `kernel.perf_event_paranoid`: `[2-9]\|[1-9][0-9]*` → 2 | — |
| `reverse_path_filtering` | `net.ipv4.conf.all.rp_filter`, `net.ipv4.conf.default.rp_filter`: `1\|2` → 1; `net.ipv4.conf.all.log_martians`, `net.ipv4.conf.default.log_martians`: `1` → 1 | — |
| `source_routing_rejected` | `net.ipv4.conf.all.accept_source_route`, `net.ipv4.conf.default.accept_source_route`: `0` → 0 | — |
| `suid_dumpable_disabled` | `fs.suid_dumpable`: `0` → 0 | — |
| `syn_cookies_enabled` | `net.ipv4.tcp_syncookies`: `1` → 1 | — |
| `sysrq_restricted` | `kernel.sysrq`: `$P_allowed_sysrq` → `$first` | `script_params: [allowed_sysrq]` |
| `unprivileged_bpf_restricted` | `kernel.unprivileged_bpf_disabled`: `1\|2` → 2; `net.core.bpf_jit_harden`: `1\|2` → 2 | — |

(The `\|` in the table is Markdown's escape; the YAML carries a plain `|`.)

`ip_forwarding_disabled`'s script, in full (E-13: the companion is read before the write and put back after, and its `sysctl:` list is `[net.ipv4.ip_forward, net.ipv4.conf.all.accept_redirects]`, in that order, so `restore_sysctl` puts `ip_forward` back first and the companion last):

```sh
f=/etc/sysctl.d/99-muster-ip-forwarding-disabled.conf
put() {
  sysctl -q -w "$1=$2"
  if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
}
first=${P_allowed_forward%% *}
case " $P_allowed_forward " in
  *" $(sysctl -n net.ipv4.ip_forward) "*) ;;
  *) r=$(sysctl -n net.ipv4.conf.all.accept_redirects)
     put net.ipv4.ip_forward "$first"
     put net.ipv4.conf.all.accept_redirects "$r";;
esac
if [ -f "$f" ]; then chmod 644 "$f"; fi
```

and its validate is `case " $P_allowed_forward " in *" $(sysctl -n net.ipv4.ip_forward) "*) ;; *) false;; esac`.

**Texts.** In each `text_en`, replace "into a file under /etc/sysctl.d" (and a following ", for example /etc/sysctl.d/60-….conf,") with "into /etc/sysctl.d/99-muster-<name>.conf"; make the same edit in `text_ko`. `unprivileged_bpf_restricted`: "kernel.unprivileged_bpf_disabled = 1" becomes "kernel.unprivileged_bpf_disabled = 2 (1 locks the setting until reboot, so the review script writes 2 and leaves a host already at 1 alone)", and `text_ko` gains the same parenthesis ("1은 재부팅 전까지 설정을 잠그므로 검토 스크립트는 2를 쓰고, 이미 1인 호스트는 그대로 둡니다"). `ptrace_restriction` gains ", and leaves a host at kernel.yama.ptrace_scope = 3, which locks until reboot, alone" (KO: "재부팅 전까지 잠기는 kernel.yama.ptrace_scope = 3인 호스트는 그대로 둡니다"). `ip_forwarding_disabled` gains "; writing 0 cuts forwarding at once on a router or a container host" (KO: "0을 쓰면 라우터나 컨테이너 호스트의 포워딩이 바로 끊깁니다").

- [ ] **Step 1: Write the failing body test** `internal/remedy/shipped_bodies_test.go`:

```go
//go:build linux

package remedy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func shippedControl(t *testing.T, id string) *controls.Control {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := set.ByID(id)
	if !ok || c.Remediation == nil {
		t.Fatalf("no shipped remediation for %s", id)
	}
	return c
}

// pEnv is the P_ assignments a block would carry at the defaults, as
// environment entries for runBody.
func pEnv(t *testing.T, c *controls.Control) []string {
	t.Helper()
	var env []string
	for _, n := range c.Remediation.ScriptParams {
		v, ok := controls.ScriptParamValue(c.Params[n].Type, c.Params[n].Default)
		if !ok {
			t.Fatalf("%s: default of %s cannot be carried", c.ID, n)
		}
		env = append(env, "P_"+n+"="+v)
	}
	return env
}

// sysctlKeys: per key, a value its control FAILs on and a different value
// it accepts (the stricter or other accepted member).
var sysctlKeys = map[string][2]string{
	"kernel.randomize_va_space": {"0", "2"}, "fs.protected_symlinks": {"0", "1"}, "fs.protected_hardlinks": {"0", "1"},
	"fs.protected_fifos": {"0", "2"}, "fs.protected_regular": {"0", "1"},
	"net.ipv4.icmp_echo_ignore_broadcasts": {"0", "1"}, "net.ipv4.icmp_ignore_bogus_error_responses": {"0", "1"},
	"net.ipv4.conf.all.accept_redirects": {"1", "0"}, "net.ipv4.conf.default.accept_redirects": {"1", "0"},
	"net.ipv4.conf.all.secure_redirects": {"1", "0"}, "net.ipv4.conf.default.secure_redirects": {"1", "0"},
	"net.ipv4.conf.all.send_redirects": {"1", "0"}, "net.ipv4.conf.default.send_redirects": {"1", "0"},
	"net.ipv4.ip_forward": {"1", "0"}, "net.ipv6.conf.all.forwarding": {"1", "0"}, "net.ipv6.conf.default.forwarding": {"1", "0"},
	"net.ipv6.conf.all.accept_redirects": {"1", "0"}, "net.ipv6.conf.default.accept_redirects": {"1", "0"},
	"net.ipv6.conf.all.accept_ra": {"1", "0"}, "net.ipv6.conf.default.accept_ra": {"1", "0"},
	"net.ipv6.conf.all.accept_source_route": {"1", "0"}, "net.ipv6.conf.default.accept_source_route": {"1", "0"},
	"kernel.kptr_restrict": {"0", "2"}, "kernel.dmesg_restrict": {"0", "1"},
	"kernel.yama.ptrace_scope": {"0", "2"}, "kernel.perf_event_paranoid": {"1", "4"},
	"net.ipv4.conf.all.rp_filter": {"0", "2"}, "net.ipv4.conf.default.rp_filter": {"0", "2"},
	"net.ipv4.conf.all.log_martians": {"0", "1"}, "net.ipv4.conf.default.log_martians": {"0", "1"},
	"net.ipv4.conf.all.accept_source_route": {"1", "0"}, "net.ipv4.conf.default.accept_source_route": {"1", "0"},
	"fs.suid_dumpable": {"2", "0"}, "net.ipv4.tcp_syncookies": {"0", "1"}, "kernel.sysrq": {"176", "0"},
	"kernel.unprivileged_bpf_disabled": {"0", "1"}, "net.core.bpf_jit_harden": {"0", "1"},
}

// companion keys are recorded and put back, never judged by their control.
var companion = map[string]string{"muster.beyond.ip_forwarding_disabled": "net.ipv4.conf.all.accept_redirects"}

func sysctlControls(t *testing.T) []*controls.Control {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var out []*controls.Control
	for i := range set.Controls {
		if r := set.Controls[i].Remediation; r != nil && len(r.Sysctl) > 0 {
			out = append(out, &set.Controls[i])
		}
	}
	if len(out) != 16 {
		t.Fatalf("%d controls declare sysctl, want 16", len(out))
	}
	return out
}

// runSysctlBody seeds the stub with state, runs the body and then the
// validate with the file under a temp sysctl.d, and returns the stub's write
// calls, the file's lines and the two exit codes.
func runSysctlBody(t *testing.T, c *controls.Control, state map[string]string, oneway map[string]string) (calls, file []string, body, validate int) {
	t.Helper()
	bin, st, dir := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "sysctl", sysctlStub)
	for k, v := range state {
		if err := os.WriteFile(filepath.Join(st, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range oneway {
		if err := os.WriteFile(filepath.Join(st, k+".oneway"), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := c.Remediation
	rebase := func(s string) string { return strings.ReplaceAll(s, "/etc/sysctl.d/", dir+"/") }
	env := append(pEnv(t, c), "SYSCTL_STATE="+st)
	if out, code := runBody(t, dir, bin, rebase(r.Script), env...); code != 0 {
		body = code
		t.Logf("%s body: %s", c.ID, out)
	}
	_, validate = runBody(t, dir, bin, rebase(r.Validate), env...)
	if b, err := os.ReadFile(filepath.Join(st, "calls")); err == nil {
		calls = strings.Fields(strings.ReplaceAll(string(b), "w ", ""))
	}
	if b, err := os.ReadFile(rebase(r.Backup[0])); err == nil {
		file = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	return calls, file, body, validate
}

func TestSysctlBodiesWriteOnlyOutsideTheSet(t *testing.T) {
	needSh(t)
	for _, c := range sysctlControls(t) {
		t.Run(c.ID, func(t *testing.T) {
			judged := []string{}
			for _, k := range c.Remediation.Sysctl {
				if k != companion[c.ID] {
					judged = append(judged, k)
				}
			}
			failing, passing := map[string]string{}, map[string]string{}
			for _, k := range c.Remediation.Sysctl {
				v, ok := sysctlKeys[k]
				if !ok {
					t.Fatalf("no test values for %s", k)
				}
				failing[k], passing[k] = v[0], v[1]
			}
			if k := companion[c.ID]; k != "" {
				failing[k] = "0" // the companion is not judged: it keeps its value
			}
			calls, file, body, val := runSysctlBody(t, c, failing, nil)
			if body != 0 || val != 0 {
				t.Fatalf("failing host: body %d, validate %d", body, val)
			}
			if len(calls) < len(judged) || len(file) < len(judged) {
				t.Fatalf("failing host: %d writes %v, %d file lines %v; want one per judged key (%d)", len(calls), calls, len(file), file, len(judged))
			}
			calls, file, body, val = runSysctlBody(t, c, passing, nil)
			if body != 0 || val != 0 || len(calls) != 0 || len(file) != 0 {
				t.Fatalf("passing host: body %d, validate %d, writes %v, file %v; want no write and no file", body, val, calls, file)
			}
		})
	}
}

// E-8 keeps the one-way values safe: the body never writes a key that
// passes, so a host locked at 1 (or 3) is repaired on its other key.
func TestSysctlBodiesLeaveOneWayValues(t *testing.T) {
	needSh(t)
	for _, c := range []struct{ id, locked, lockedAt, other, otherFail string }{
		{"muster.beyond.unprivileged_bpf_restricted", "kernel.unprivileged_bpf_disabled", "1", "net.core.bpf_jit_harden", "0"},
		{"muster.beyond.ptrace_restriction", "kernel.yama.ptrace_scope", "3", "kernel.perf_event_paranoid", "1"},
	} {
		ctl := shippedControl(t, c.id)
		calls, _, body, val := runSysctlBody(t, ctl, map[string]string{c.locked: c.lockedAt, c.other: c.otherFail}, map[string]string{c.locked: c.lockedAt})
		if body != 0 || val != 0 {
			t.Errorf("%s: body %d, validate %d", c.id, body, val)
		}
		for _, w := range calls {
			if strings.HasPrefix(w, c.locked+"=") {
				t.Errorf("%s: wrote the locked key: %v", c.id, calls)
			}
		}
	}
}

// E-13: the forwarding body reads the companion before it writes ip_forward
// and writes it back after, at runtime and as the next line of its file.
func TestIPForwardBodyPutsTheCompanionBack(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.beyond.ip_forwarding_disabled")
	calls, file, body, val := runSysctlBody(t, c, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv4.conf.all.accept_redirects": "0"}, nil)
	if body != 0 || val != 0 {
		t.Fatalf("body %d, validate %d", body, val)
	}
	if strings.Join(calls, " ") != "net.ipv4.ip_forward=0 net.ipv4.conf.all.accept_redirects=0" {
		t.Errorf("writes %v", calls)
	}
	if strings.Join(file, "|") != "net.ipv4.ip_forward = 0|net.ipv4.conf.all.accept_redirects = 0" {
		t.Errorf("file %v", file)
	}
}
```

- [ ] **Step 2: Write the failing pin test** `internal/collect/collectors/remediation_sysctl_test.go`:

```go
//go:build linux

package collectors

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestSysctlScriptsNameTheControlsKeys pins 3D-2c §5: a control's sysctl list
// is, as a set, the kernel keys of the facts its checks judge (plus the one
// declared companion, E-13), and each key's case arms in the script and the
// validate are the clause's accepted set, written to a member of it.
func TestSysctlScriptsNameTheControlsKeys(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	leaf := map[string]string{"coredump.suid_dumpable": suidDumpableKey.key}
	for _, l := range sysctlLeaves {
		leaf[l.leaf] = l.key
	}
	companions := map[string]string{"muster.beyond.ip_forwarding_disabled": "net.ipv4.conf.all.accept_redirects"}
	n := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil || len(r.Sysctl) == 0 {
			continue
		}
		n++
		judged := map[string]controls.Clause{}
		for _, cl := range c.Checks {
			k, ok := leaf[cl.Fact]
			if !ok {
				t.Errorf("%s: clause fact %s is not a sysctl leaf", c.ID, cl.Fact)
				continue
			}
			judged[k] = cl
		}
		want := []string{}
		for k := range judged {
			want = append(want, k)
		}
		if k := companions[c.ID]; k != "" {
			want = append(want, k)
		}
		got := append([]string(nil), r.Sysctl...)
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: sysctl %v, want %v", c.ID, got, want)
		}
		for k, cl := range judged {
			q := regexp.QuoteMeta(k)
			switch e := cl.Expected.(type) {
			case string: // "${param}"
				p := strings.TrimSuffix(strings.TrimPrefix(e, "${"), "}")
				head := `case " \$P_` + p + ` " in\s+\*" \$\(sysctl -n ` + q + `\) "\*\) ;;`
				if !regexp.MustCompile(`(?s)` + head + `\s+\*\) .*?put ` + q + ` "\$first"`).MatchString(r.Script) {
					t.Errorf("%s: no parameter case for %s over $P_%s in the script", c.ID, k, p)
				}
				if !regexp.MustCompile(head + ` \*\) false;; esac`).MatchString(r.Validate) {
					t.Errorf("%s: no parameter case for %s in the validate", c.ID, k)
				}
			default:
				arms := armsOf(t, c.ID, cl)
				m := regexp.MustCompile(`case "\$\(sysctl -n ` + q + `\)" in ` + regexp.QuoteMeta(arms) + `\) ;; \*\) put ` + q + ` ([0-9]+);; esac`).FindStringSubmatch(r.Script)
				if m == nil {
					t.Errorf("%s: no case for %s with arms %s in the script", c.ID, k, arms)
					continue
				}
				if !accepts(cl, m[1]) {
					t.Errorf("%s: %s is written as %s, which its clause does not accept", c.ID, k, m[1])
				}
				if !strings.Contains(r.Validate, `case "$(sysctl -n `+k+`)" in `+arms+`) ;; *) false;; esac`) {
					t.Errorf("%s: no case for %s with arms %s in the validate", c.ID, k, arms)
				}
			}
		}
	}
	if n != 16 {
		t.Errorf("%d controls declare sysctl, want 16", n)
	}
}

func armsOf(t *testing.T, id string, cl controls.Clause) string {
	switch cl.Op {
	case "eq":
		return fmt.Sprint(cl.Expected)
	case "in":
		var xs []string
		for _, x := range cl.Expected.([]any) {
			xs = append(xs, fmt.Sprint(x))
		}
		return strings.Join(xs, "|")
	case "gte":
		if fmt.Sprint(cl.Expected) == "2" {
			return "[2-9]|[1-9][0-9]*"
		}
	}
	t.Errorf("%s: no arms rule for op %s %v", id, cl.Op, cl.Expected)
	return ""
}

func accepts(cl controls.Clause, v string) bool {
	switch cl.Op {
	case "eq":
		return fmt.Sprint(cl.Expected) == v
	case "in":
		for _, x := range cl.Expected.([]any) {
			if fmt.Sprint(x) == v {
				return true
			}
		}
	case "gte":
		var n, min int
		fmt.Sscan(v, &n)
		fmt.Sscan(fmt.Sprint(cl.Expected), &min)
		return n >= min
	}
	return false
}
```

- [ ] **Step 3: Run** on the lab: `go test ./internal/remedy/ -run 'TestSysctlBodies|TestIPForward'` and `go test ./internal/collect/collectors/ -run TestSysctlScriptsNameTheControlsKeys`. Expected: FAIL (`0 controls declare sysctl, want 16`).

- [ ] **Step 4: Write the sixteen remediation blocks** as specified above, the four risk lines (`ip_forwarding_disabled` and `ipv6_forwarding_disabled` → `restart_service`), the texts, and `controls/VERSION` → `kisa-unix-2026+2026.10.14`.

- [ ] **Step 5: Run.** Windows: `go test ./internal/controls/` (lint clean, `TestEveryMutantIsKilled` zero survivors), `go run ./cmd/muster controls lint --references docs/reference` and `--profile default`. Lab: the Step 3 tests, now PASS; `go test ./internal/remedy/ -run TestScriptGolden -update` regenerates `all-scripted.sh` (32 blocks) — review the diff, then the shellcheck image over `internal/remedy/testdata/*.sh`. `TestScriptAllScriptedCoversTheShippedSet` goes from 16 to 32 here (it becomes 48 at Task 8): derive it instead — replace the literal with a count of shipped controls whose `Remediation.Script` is not blank, and assert that count is ≥ 16. The examples gate now skips with the G-24 note (quote it once).

- [ ] **Step 6: Round-trip table.** `TestEveryScriptedControlIsInTheRoundtripTable` requires every scripted control in `_roundtrip.yaml` and every `images` entry to be a matrix row. The `runner` row lands in Task 9, so this task adds the sixteen entries as `unproven: "the runner row (Task 9) proves it; containers gate beyond controls out"` and Task 9 replaces each with `images: [runner]`. Keep the file sorted by id.

- [ ] **Step 7: Commit**

```bash
git add controls/VERSION controls/beyond controls/testdata/_roundtrip.yaml internal/remedy/shipped_bodies_test.go internal/remedy/script_test.go internal/remedy/testdata/all-scripted.sh internal/collect/collectors/remediation_sysctl_test.go
git commit -m "controls: sixteen sysctl scripts that write only outside the accepted set, pinned to the collector's keys"
```

---

### Task 6: The three module bodies and their pin

**Files:**
- Modify: `controls/beyond/usb_storage_disabled.yaml`, `uncommon_filesystems_disabled.yaml`, `uncommon_network_protocols_disabled.yaml`; `controls/testdata/_roundtrip.yaml`
- Create: `internal/controls/remediation_modules_test.go`
- Modify: `internal/remedy/shipped_bodies_test.go`

**Interfaces:**
- Consumes: `modprobeStub` (Task 4, `state_test.go`), `shippedControl`, `runBody`.

**The body shape** (`<list>` is the control's `where` list as spelled there; `<name>` is the control name with `_` → `-`):

```yaml
  modules: [<list>]
  backup: [/etc/modprobe.d/99-muster-<name>.conf]
  script: |
    f=/etc/modprobe.d/99-muster-<name>.conf
    for m in <list>; do
      n=$(printf '%s' "$m" | tr - _)
      grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f"
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    chmod 644 "$f"
  validate: |
    for m in <list>; do n=$(printf '%s' "$m" | tr - _); [ "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" = /bin/false ] || exit 1; ! grep -q "^$n " /proc/modules || exit 1; done
```

| control | `<list>` | `<name>` | risk |
|---|---|---|---|
| `muster.beyond.usb_storage_disabled` | `usb-storage` | `usb-storage-disabled` | `restart_service` |
| `muster.beyond.uncommon_filesystems_disabled` | `cramfs freevxfs jffs2 hfs hfsplus udf` | `uncommon-filesystems-disabled` | `none` |
| `muster.beyond.uncommon_network_protocols_disabled` | `dccp sctp rds tipc` | `uncommon-network-protocols-disabled` | `none` |

(In the YAML flow list the modules are comma-separated: `modules: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]`.) Texts: replace the example file "/etc/modprobe.d/50-….conf" with "/etc/modprobe.d/99-muster-<name>.conf", and the instruction to rebuild the initramfs gains "(the review script does not)" — KO "(검토 스크립트는 하지 않습니다)". Add the sentence "A vendor file with its own install line for the module wins over this one; the review script's validate then fails and the block rolls back." (KO: "모듈에 자기 install 줄을 둔 벤더 파일이 이 파일을 이기며, 그때 검토 스크립트의 validate가 실패해 블록이 롤백됩니다.")

- [ ] **Step 1: Write the failing pin test** `internal/controls/remediation_modules_test.go`:

```go
package controls_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// TestModuleScriptsNameTheControlsModules pins 3D-2c §5: a control's modules
// list is its where list, and the body and validate loop over exactly it.
func TestModuleScriptsNameTheControlsModules(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil || len(r.Modules) == 0 {
			continue
		}
		n++
		var where []string
		for _, x := range c.Checks[0].Where.Expected.([]any) {
			where = append(where, fmt.Sprint(x))
		}
		if strings.Join(r.Modules, " ") != strings.Join(where, " ") {
			t.Errorf("%s: modules %v, where %v", c.ID, r.Modules, where)
		}
		loop := "for m in " + strings.Join(where, " ") + "; do"
		if !strings.Contains(r.Script, loop) || !strings.Contains(r.Validate, loop) {
			t.Errorf("%s: script or validate does not loop over %q", c.ID, loop)
		}
	}
	if n != 3 {
		t.Errorf("%d controls declare modules, want 3", n)
	}
}
```

  Add to `shipped_bodies_test.go`:

```go
func TestModuleBodiesWriteFoldedLinesAndUnload(t *testing.T) {
	needSh(t)
	for _, id := range []string{"muster.beyond.usb_storage_disabled", "muster.beyond.uncommon_filesystems_disabled", "muster.beyond.uncommon_network_protocols_disabled"} {
		t.Run(id, func(t *testing.T) {
			c := shippedControl(t, id)
			r := c.Remediation
			bin, st := t.TempDir(), t.TempDir()
			writeStub(t, bin, "modprobe", modprobeStub)
			if err := os.Mkdir(filepath.Join(st, "conf"), 0o755); err != nil {
				t.Fatal(err)
			}
			var loaded strings.Builder
			for _, m := range r.Modules {
				fmt.Fprintf(&loaded, "%s 16384 0 - Live 0x0\n", strings.ReplaceAll(m, "-", "_"))
			}
			procModules := filepath.Join(st, "modules")
			if err := os.WriteFile(procModules, []byte(loaded.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			rebase := func(s string) string {
				return strings.ReplaceAll(strings.ReplaceAll(s, "/etc/modprobe.d/", filepath.Join(st, "conf")+"/"), "/proc/modules", procModules)
			}
			env := "MODPROBE_STATE=" + st
			for run := 1; run <= 2; run++ { // the second run changes nothing
				if out, code := runBody(t, st, bin, rebase(r.Script), env); code != 0 {
					t.Fatalf("run %d: body %d %s", run, code, out)
				}
				if out, code := runBody(t, st, bin, rebase(r.Validate), env); code != 0 {
					t.Fatalf("run %d: validate %d %s", run, code, out)
				}
			}
			conf, _ := os.ReadFile(rebase(r.Backup[0]))
			for _, m := range r.Modules {
				line := "install " + strings.ReplaceAll(m, "-", "_") + " /bin/false\n"
				if strings.Count(string(conf), line) != 1 {
					t.Errorf("conf carries %q %d times:\n%s", line, strings.Count(string(conf), line), conf)
				}
			}
			if left, _ := os.ReadFile(procModules); len(strings.TrimSpace(string(left))) != 0 {
				t.Errorf("modules still loaded: %s", left)
			}
			// a module in use fails the body, so the block rolls back
			if err := os.WriteFile(procModules, []byte(loaded.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(st, "busy"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, code := runBody(t, st, bin, rebase(r.Script), env); code == 0 {
				t.Error("a module in use did not fail the body")
			}
		})
	}
}
```

  (add `fmt` to the file's imports).

- [ ] **Step 2: Run** `go test ./internal/controls -run TestModuleScripts` (Windows) and the body test on the lab. Expected: FAIL (`0 controls declare modules`).
- [ ] **Step 3: Write the three blocks**, the risk change and the texts.
- [ ] **Step 4: Run** both tests (PASS), `go test ./internal/controls/`, the lint commands, regenerate `all-scripted.sh` (35 blocks) and shellcheck it on the lab. Add the three `_roundtrip.yaml` entries as in Task 5 Step 6.
- [ ] **Step 5: Commit**

```bash
git add controls/beyond/usb_storage_disabled.yaml controls/beyond/uncommon_filesystems_disabled.yaml controls/beyond/uncommon_network_protocols_disabled.yaml controls/testdata/_roundtrip.yaml internal/controls/remediation_modules_test.go internal/remedy/shipped_bodies_test.go internal/remedy/testdata/all-scripted.sh
git commit -m "controls: three module scripts with folded install lines, unloading only what is loaded"
```

---
### Task 7: The nine file-permission bodies

**Files:**
- Modify: `controls/account/sudoers_permissions.yaml`, `controls/service/nfs_export_access.yaml`, `controls/beyond/bootloader_config_permissions.yaml`, `controls/file/inetd_conf_permissions.yaml`, `controls/beyond/audit_log_permissions.yaml`, `controls/file/syslog_conf_permissions.yaml`, `controls/account/cron_permissions.yaml`, `controls/file/log_dir_permissions.yaml`, `controls/service/ftpusers_permissions.yaml`; `controls/testdata/_roundtrip.yaml`
- Modify: `internal/controls/file_validates_test.go` (`:14-64`)
- Modify: `internal/remedy/shipped_bodies_test.go`, `internal/remedy/shipped_test.go` (`TestFileScriptsRepairOnARealFile` `:161-242`)

**Interfaces:**
- Consumes: `shippedControl`, `runBody` (Task 5); the `modes` helpers (Task 4).

Every body below is verbatim. A guard is `if [ -f p ] && [ ! -L p ]` for a file and `if [ -d d ] && [ ! -L d ]` for a directory (E-9); a validate is a `|` block scalar of one line. `risk` stays as it is. Texts keep their sentences and gain only what a control's note says, plus — on the six controls listed after the last block — the sentence "The review script never follows a symlink." (KO: "검토 스크립트는 심볼릭 링크를 따라가지 않습니다.")

**`muster.account.sudoers_permissions`**

```yaml
  backup: [/etc/sudoers]
  modes: ["/etc/sudoers.d/*"]
  script: |
    if [ -f /etc/sudoers ] && [ ! -L /etc/sudoers ]; then
      chown root /etc/sudoers
      chmod u-wxs,g-wxs,o-rwxt /etc/sudoers
    fi
    if [ -d /etc/sudoers.d ] && [ ! -L /etc/sudoers.d ]; then
      find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' -exec chmod go-w {} +
    fi
  validate: |
    case "$(stat -c '%u %a' /etc/sudoers)" in '0 0'|'0 40'|'0 400'|'0 440') ;; *) false;; esac && [ -z "$(find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' -perm /022 2>/dev/null)" ]
```

**`muster.service.nfs_export_access`** (uid only, S-13; the exports content half stays text)

```yaml
  backup: [/etc/exports]
  script: |
    if [ -f /etc/exports ] && [ ! -L /etc/exports ]; then
      chown root /etc/exports
      chmod u-xs,g-wxs,o-wxt /etc/exports
    fi
  validate: |
    [ ! -f /etc/exports ] || [ -L /etc/exports ] || case "$(stat -c '%u %a' /etc/exports)" in '0 0'|'0 4'|'0 40'|'0 44'|'0 200'|'0 204'|'0 240'|'0 244'|'0 400'|'0 404'|'0 440'|'0 444'|'0 600'|'0 604'|'0 640'|'0 644') ;; *) false;; esac
```

**`muster.beyond.bootloader_config_permissions`** (text gains: "A grub.cfg on the EFI system partition takes its mode from the mount's fmask, set in fstab (fmask=0177); the review script leaves it." KO: "EFI 시스템 파티션의 grub.cfg는 마운트의 fmask에서 모드를 받으므로 fstab에서 정합니다(fmask=0177). 검토 스크립트는 그대로 둡니다.")

```yaml
  backup: [/boot/grub/grub.cfg, /boot/grub2/grub.cfg]
  script: |
    for p in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root:root "$p"
        chmod u-xs,g-rwxs,o-rwxt "$p"
      fi
    done
  validate: |
    for p in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do [ ! -f "$p" ] || [ -L "$p" ] || case "$(stat -c '%u %g %a' "$p")" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) exit 1;; esac; done
```

**`muster.file.inetd_conf_permissions`**

```yaml
  backup: [/etc/inetd.conf, /etc/xinetd.conf]
  modes: ["/etc/xinetd.d/*"]
  script: |
    for p in /etc/inetd.conf /etc/xinetd.conf; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-rwxs,o-rwxt "$p"
      fi
    done
    if [ -d /etc/xinetd.d ] && [ ! -L /etc/xinetd.d ]; then
      find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -exec chmod go-w {} +
    fi
  validate: |
    { [ ! -f /etc/inetd.conf ] || [ -L /etc/inetd.conf ] || [ -z "$(find /etc/inetd.conf \( -perm /024 -o ! -user root \))" ]; } && { [ ! -f /etc/xinetd.conf ] || [ -L /etc/xinetd.conf ] || case "$(stat -c '%u %a' /etc/xinetd.conf)" in '0 0'|'0 200'|'0 400'|'0 600') ;; *) false;; esac; } && [ -z "$(find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -perm /022 2>/dev/null)" ]
```

**`muster.beyond.audit_log_permissions`** (no `backup`: a live log is never copied; the group clause stays text, S-12 — the text says "the review script changes owner and mode only; a log in a group outside params.allowed_groups needs chgrp or the group named in the parameter", KO: "검토 스크립트는 소유자와 모드만 바꿉니다. params.allowed_groups 밖 그룹의 로그는 chgrp하거나 그 그룹을 파라미터에 적어야 합니다.")

```yaml
  modes: [/var/log/audit/audit.log, /var/log/audit]
  script: |
    if [ -f /var/log/audit/audit.log ] && [ ! -L /var/log/audit/audit.log ]; then
      chown root /var/log/audit/audit.log
      chmod u-xs,g-wxs,o-rwxt /var/log/audit/audit.log
    fi
    if [ -d /var/log/audit ] && [ ! -L /var/log/audit ]; then
      chown root /var/log/audit
      chmod g-w,o-rwx /var/log/audit
    fi
  validate: |
    case "$(stat -c '%u %a' /var/log/audit/audit.log)" in '0 0'|'0 200'|'0 400'|'0 600'|'0 40'|'0 240'|'0 440'|'0 640') ;; *) false;; esac && [ -z "$(find /var/log/audit -maxdepth 0 \( -perm /026 -o ! -user root \))" ]
```

**`muster.file.syslog_conf_permissions`** (mask 7137 = 07777 minus 0640, the largest default allowed mode)

```yaml
  backup: [/etc/rsyslog.conf, /etc/systemd/journald.conf, /etc/syslog-ng/syslog-ng.conf]
  modes: ["/etc/rsyslog.d/*", "/etc/systemd/journald.conf.d/*", "/etc/syslog-ng/conf.d/*"]
  script: |
    for p in /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
    for d in /etc/rsyslog.d /etc/systemd/journald.conf.d /etc/syslog-ng/conf.d; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then
        find "$d" -mindepth 1 -maxdepth 1 -type f -name '*.conf' -exec chown root {} + -exec chmod u-xs,g-wxs,o-rwxt {} +
      fi
    done
  validate: |
    for p in /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf /etc/rsyslog.d /etc/systemd/journald.conf.d /etc/syslog-ng/conf.d; do [ ! -e "$p" ] || [ -L "$p" ] || [ -z "$(find "$p" -maxdepth 1 -type f \( -path "$p" -o -name '*.conf' \) \( -perm /7137 -o ! -user root \))" ] || exit 1; done
```

**`muster.account.cron_permissions`** (text gains: "A pending at job keeps the execute bit at uses to mark it runnable, so this control stays FAIL until the job has run; the review script never clears it." KO: "대기 중인 at 작업은 실행 가능 표시인 실행 비트를 유지하므로, 그 작업이 실행될 때까지 이 control은 FAIL로 남습니다. 검토 스크립트는 그 비트를 지우지 않습니다.")

```yaml
  modes: [/etc/crontab, /etc/anacrontab, /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny, "/etc/cron.d/*", /etc/cron.d, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*", /var/spool/cron, "/var/spool/cron/*", /var/spool/cron/crontabs, "/var/spool/cron/crontabs/*", /var/spool/cron/atjobs, "/var/spool/cron/atjobs/*", /var/spool/at, "/var/spool/at/*"]
  script: |
    for p in /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
    if [ -d /etc/cron.d ] && [ ! -L /etc/cron.d ]; then
      find /etc/cron.d -mindepth 1 -maxdepth 1 -type f -exec chown root {} + -exec chmod u-xs,g-wxs,o-rwxt {} +
    fi
    for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then
        find "$d" -mindepth 1 -maxdepth 1 -type f -exec chown root {} + -exec chmod o-w {} +
      fi
    done
    for d in /var/spool/cron /var/spool/cron/crontabs; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then
        find "$d" -mindepth 1 -maxdepth 1 -type f -exec chmod u-xs,g-wxs,o-rwxt {} +
      fi
    done
    for d in /var/spool/cron/atjobs /var/spool/at; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then
        find "$d" -mindepth 1 -maxdepth 1 -type f -exec chmod g-wxs,o-rwxt {} +
      fi
    done
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then chmod o-w "$d"; fi
    done
  validate: |
    [ -z "$(find /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.d -maxdepth 1 -type f \( -perm /7137 -o ! -user root \) 2>/dev/null)" ] && [ -z "$(find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -mindepth 1 -maxdepth 1 -type f \( -perm /002 -o ! -user root \) 2>/dev/null)" ] && [ -z "$(find /var/spool/cron /var/spool/cron/crontabs -mindepth 1 -maxdepth 1 -type f -perm /7137 2>/dev/null)" ] && [ -z "$(find /var/spool/cron/atjobs /var/spool/at -mindepth 1 -maxdepth 1 -type f -perm /7037 2>/dev/null)" ] && [ -z "$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at -maxdepth 0 -type d -perm /002 2>/dev/null)" ]
```

  `-type f` keeps the spool pass off the `crontabs`/`atjobs` directories under `/var/spool/cron` (spec §4.3). `modes_backup_overlap` holds (no `backup`).

**`muster.file.log_dir_permissions`** (the other-writable half; the group half stays text — the text says so; no `script_params`)

```yaml
  modes: [/var/log, "/var/log/*", "/var/log/*/*"]
  script: |
    find /var/log -maxdepth 2 ! -type l -perm /002 -exec chmod o-w {} +
  validate: |
    [ -z "$(find /var/log -maxdepth 2 ! -type l -perm /002 2>/dev/null)" ]
```

**`muster.service.ftpusers_permissions`** (uid only, S-13; never creates a file)

```yaml
  backup: [/etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers]
  script: |
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
  validate: |
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers; do [ ! -f "$p" ] || [ -L "$p" ] || case "$(stat -c '%u %a' "$p")" in '0 0'|'0 40'|'0 200'|'0 240'|'0 400'|'0 440'|'0 600'|'0 640') ;; *) exit 1;; esac; done
```

The "symlink" sentence goes on `bootloader_config_permissions`, `inetd_conf_permissions`, `syslog_conf_permissions`, `cron_permissions`, `log_dir_permissions` and `ftpusers_permissions`.

- [ ] **Step 1: Rewrite the selection of `TestFileValidatesAcceptTheDefaultModes`** (S-8). Replace its category scan (`:26-40`) with:

```go
	// S-8: the owner table is the set; every other shipped scripted control
	// must not validate with a bare stat case, so a new one is added here.
	for id := range owners {
		c, ok := set.ByID(id)
		if !ok || c.Remediation == nil || strings.TrimSpace(c.Remediation.Script) == "" {
			t.Fatalf("%s: not a shipped scripted control", id)
		}
	}
	for _, c := range set.Controls {
		r := c.Remediation
		if r == nil || strings.TrimSpace(r.Script) == "" || owners[c.ID] != [2]string{} {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(r.Validate), `case "$(stat -c `) {
			t.Errorf("%s validates with a bare stat case: add it to the owner table", c.ID)
		}
	}
```

  and keep the per-owner regeneration loop. Add the mask-derivation test beside it:

```go
// E-9: a validate's find mask over an allowed_modes set is 07777 minus the
// largest default mode, so a bit the clause forbids is never missed.
func TestFileValidateMasksDeriveFromTheDefaultModes(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"muster.file.syslog_conf_permissions", "muster.account.cron_permissions"} {
		c, _ := set.ByID(id)
		max := int64(0)
		for _, m := range c.Params["allowed_modes"].Default.([]any) {
			if v := int64(toInt(t, m)); v > max {
				max = v
			}
		}
		mask := "-perm /" + strconv.FormatInt(0o7777&^max, 8)
		if !strings.Contains(c.Remediation.Validate, mask) {
			t.Errorf("%s: validate lacks %q (largest allowed mode %o)", id, mask, max)
		}
	}
}
```

  (`toInt` exists in the file; add `strconv` if missing.)

- [ ] **Step 2: Write the failing temp-tree test** (root only) in `shipped_bodies_test.go`:

```go
// rebaseRoot moves every absolute path a file body names under root.
func rebaseRoot(s, root string) string {
	for _, pre := range []string{"/etc/", "/var/", "/boot/"} {
		s = strings.ReplaceAll(s, " "+pre, " "+root+pre)
		s = strings.ReplaceAll(s, "\n"+pre, "\n"+root+pre)
		s = strings.ReplaceAll(s, "("+pre, "("+root+pre)
		s = strings.ReplaceAll(s, "'"+pre, "'"+root+pre)
	}
	return s
}

type treeFile struct {
	path string
	mode os.FileMode
	dir  bool
}

func TestFileBodiesRepairATempTree(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown under the temp tree")
	}
	cases := []struct {
		id       string
		loosened []treeFile // modes the control FAILs on
		kept     []treeFile // modes the body must not change
	}{
		{"muster.account.sudoers_permissions", []treeFile{{"/etc/sudoers", 0o644, false}, {"/etc/sudoers.d/a", 0o664, false}}, []treeFile{{"/etc/sudoers.d/README.txt", 0o666, false}}},
		{"muster.service.nfs_export_access", []treeFile{{"/etc/exports", 0o666, false}}, nil},
		{"muster.beyond.bootloader_config_permissions", []treeFile{{"/boot/grub/grub.cfg", 0o644, false}}, nil},
		{"muster.file.inetd_conf_permissions", []treeFile{{"/etc/inetd.conf", 0o644, false}, {"/etc/xinetd.d/x", 0o666, false}}, nil},
		{"muster.beyond.audit_log_permissions", []treeFile{{"/var/log/audit", 0o755, true}, {"/var/log/audit/audit.log", 0o644, false}}, nil},
		{"muster.file.syslog_conf_permissions", []treeFile{{"/etc/rsyslog.conf", 0o644, false}, {"/etc/rsyslog.d/50.conf", 0o644, false}}, []treeFile{{"/etc/rsyslog.d/notes.txt", 0o644, false}}},
		{"muster.account.cron_permissions", []treeFile{{"/etc/crontab", 0o644, false}, {"/etc/cron.d/x", 0o644, false}, {"/etc/cron.daily/y", 0o757, false}, {"/var/spool/cron/crontabs/u", 0o644, false}}, []treeFile{{"/var/spool/cron/atjobs/a0001", 0o700, false}, {"/var/spool/cron/crontabs", 0o1730, true}}},
		{"muster.file.log_dir_permissions", []treeFile{{"/var/log/x.log", 0o666, false}, {"/var/log/sub/y.log", 0o646, false}}, []treeFile{{"/var/log/grp.log", 0o664, false}}},
		{"muster.service.ftpusers_permissions", []treeFile{{"/etc/ftpusers", 0o644, false}}, nil},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			r := shippedControl(t, c.id).Remediation
			root, bin := t.TempDir(), t.TempDir()
			mk := func(f treeFile) string {
				p := filepath.Join(root, f.path)
				if f.dir {
					if err := os.MkdirAll(p, 0o755); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if out, err := exec.Command("chmod", strconv.FormatUint(uint64(f.mode), 8), p).CombinedOutput(); err != nil {
					t.Fatalf("chmod %s: %v %s", p, err, out) // chmod(1), so the setgid and sticky bits land too
				}
				return p
			}
			for _, f := range append(append([]treeFile{}, c.loosened...), c.kept...) {
				mk(f)
			}
			// a symlink beside the set is never followed
			victim := mk(treeFile{"/victim", 0o666, false})
			for _, l := range []string{"/var/log/link", "/etc/cron.d/link", "/etc/sudoers.d/link"} {
				_ = os.MkdirAll(filepath.Dir(filepath.Join(root, l)), 0o755)
				_ = os.Symlink(victim, filepath.Join(root, l))
			}
			body, val := rebaseRoot(" "+r.Script, root), rebaseRoot(" "+r.Validate, root)
			if _, code := runBody(t, root, bin, val); code == 0 && len(c.loosened) > 0 {
				t.Error("validate passed on the loosened tree")
			}
			if out, code := runBody(t, root, bin, body); code != 0 {
				t.Fatalf("body %d: %s", code, out)
			}
			if out, code := runBody(t, root, bin, val); code != 0 {
				t.Fatalf("validate after the body %d: %s", code, out)
			}
			for _, f := range c.kept {
				if got := mode(t, filepath.Join(root, f.path)); got != strconv.FormatUint(uint64(f.mode&0o7777), 8) {
					t.Errorf("%s changed to %s", f.path, got)
				}
			}
			if got := mode(t, victim); got != "666" {
				t.Errorf("a body followed a symlink: the victim is %s", got)
			}
		})
	}
}
```

  (Add `os/exec` and `strconv` to the imports.) `mode` is Task 4's helper. The modes in the table are numeric (`0o1730` is the octal `1730` chmod(1) takes).

  Extend `TestFileScriptsRepairOnARealFile`'s table with `{"muster.service.nfs_export_access", <the 16 allowed modes>, []uint32{0o666, 0o664, 0o4644}, 0o600}` — its body and validate name `/etc/exports`, replaced by the temp file as the test does.

- [ ] **Step 3: Run** `go test ./internal/controls -run 'TestFileValidates'` (Windows; FAIL for the mask test until the bodies exist) and, on the lab as root, `go test ./internal/remedy/ -run 'TestFileBodiesRepairATempTree|TestFileScriptsRepairOnARealFile'`. Expected: FAIL.
- [ ] **Step 4: Write the nine blocks and the text sentences.**
- [ ] **Step 5: Run** the Step 3 tests (PASS), `go test ./internal/controls/` (zero mutant survivors), the two lint commands, regenerate `all-scripted.sh` (44 blocks) and shellcheck it on the lab. Add the nine `_roundtrip.yaml` entries: `unproven: "the rows land in Task 9"` for each (Task 9 writes their rows from the probe).
- [ ] **Step 6: Commit**

```bash
git add controls/account/sudoers_permissions.yaml controls/service/nfs_export_access.yaml controls/beyond/bootloader_config_permissions.yaml controls/file/inetd_conf_permissions.yaml controls/beyond/audit_log_permissions.yaml controls/file/syslog_conf_permissions.yaml controls/account/cron_permissions.yaml controls/file/log_dir_permissions.yaml controls/service/ftpusers_permissions.yaml controls/testdata/_roundtrip.yaml internal/controls/file_validates_test.go internal/remedy/shipped_bodies_test.go internal/remedy/shipped_test.go internal/remedy/testdata/all-scripted.sh
git commit -m "controls: nine file-permission scripts that never follow a symlink, with validates masked from the default modes"
```

---

### Task 8: The account and sshd bodies

**Files:**
- Modify: `controls/account/password_policy.yaml`, `umask_policy.yaml`, `lockout_threshold.yaml`, `session_timeout.yaml`; `controls/testdata/_roundtrip.yaml`; the `umask_policy` fixtures if the mutation test asks (Step 5)
- Modify: `internal/remedy/shipped_bodies_test.go`, `internal/remedy/script_test.go` (`TestScriptAllScriptedCoversTheShippedSet` now counts 48)

**Interfaces:**
- Consumes: `shippedControl`, `pEnv`, `runBody`, `writeStub` (Tasks 5, 3D-2b).

**`muster.account.password_policy`** — risk `lockout_risk`; text gains "The review script tightens PASS_* in /etc/login.defs, writes minlen/minclass to /etc/security/pwquality.conf.d/99-muster.conf only where the merged value is looser, and applies the ageing with chage to every account with a password hash except one whose password is already older than the maximum (it would expire on the spot; change it first). Arguments on the pam_pwquality.so line win over the files." (KO: "검토 스크립트는 /etc/login.defs의 PASS_* 값을 조이고, 합친 값이 더 느슨할 때만 minlen/minclass를 /etc/security/pwquality.conf.d/99-muster.conf에 쓰며, 비밀번호 해시가 있는 모든 계정에 chage로 기간을 적용합니다. 단, 비밀번호가 이미 최대 기간보다 오래된 계정은 그 자리에서 만료되므로 건너뜁니다(먼저 비밀번호를 바꾸세요). pam_pwquality.so 줄의 인자는 파일보다 우선합니다.")

```yaml
  risk: lockout_risk
  idempotent: true
  script_params: [max_days, min_days, min_len, min_classes]
  script_on_absent: true
  backup: [/etc/login.defs, /etc/security/pwquality.conf.d/99-muster.conf]
  script: |
    ld=/etc/login.defs
    first_val() { awk -v k="$1" '$1 == k { print $2; exit }' "$ld"; }
    set_key() {
      if grep -Eq "^[[:space:]]*$1[[:space:]]" "$ld"; then sed -i -E "s|^([[:space:]]*$1)[[:space:]].*|\1 $2|" "$ld"; else printf '%s %s\n' "$1" "$2" >> "$ld"; fi
    }
    v=$(first_val PASS_MAX_DAYS)
    case "$v" in ''|*[!0-9]*) set_key PASS_MAX_DAYS "$P_max_days";; *) if [ "$v" -gt "$P_max_days" ]; then set_key PASS_MAX_DAYS "$P_max_days"; fi;; esac
    v=$(first_val PASS_MIN_DAYS)
    case "$v" in ''|*[!0-9]*) set_key PASS_MIN_DAYS "$P_min_days";; *) if [ "$v" -lt "$P_min_days" ]; then set_key PASS_MIN_DAYS "$P_min_days"; fi;; esac
    v=$(first_val PASS_MIN_LEN)
    case "$v" in ''|*[!0-9]*) set_key PASS_MIN_LEN "$P_min_len";; *) if [ "$v" -lt "$P_min_len" ]; then set_key PASS_MIN_LEN "$P_min_len"; fi;; esac
    pf=/etc/security/pwquality.conf.d/99-muster.conf
    merged() { # minlen and required classes over the file chain, last wins (the collector's read)
      for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        if [ -f "$f" ]; then cat "$f"; fi
      done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; print ml, rc }'
    }
    pput() {
      if [ ! -d /etc/security/pwquality.conf.d ]; then mkdir -p /etc/security/pwquality.conf.d; chmod 755 /etc/security/pwquality.conf.d; fi
      if grep -q "^$1 " "$pf" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$pf"; else printf '%s = %s\n' "$1" "$2" >> "$pf"; fi
      chmod 644 "$pf"
    }
    set -- $(merged)
    if [ "$1" -lt "$P_min_len" ]; then pput minlen "$P_min_len"; fi
    if [ "$2" -lt "$P_min_classes" ]; then pput minclass "$P_min_classes"; fi
    today=$(( $(date +%s) / 86400 ))
    awk -F: -v OFS=: 'NF >= 8 && $1 !~ /^#/ && $2 != "" && $2 !~ /^[!*]/ { print $1, $3, $4, $5 }' /etc/shadow > "$MB/ageing.scan"
    while IFS=: read -r name last min max; do
      case "$last" in ''|0|*[!0-9]*) log "password_policy: $name has no last-change day, left as is"; continue;; esac
      if [ $((today - last)) -gt "$P_max_days" ]; then log "password_policy: $name: password older than $P_max_days days, change it first"; continue; fi
      awk -F: -v n="$name" '$1 == n { f = 1 } END { exit !f }' "$MB/ageing.list" 2>/dev/null || printf '%s:%s:%s\n' "$name" "${min:--1}" "${max:--1}" >> "$MB/ageing.list"
      case "$max" in ''|*[!0-9]*) chage -M "$P_max_days" -- "$name";; *) if [ "$max" -gt "$P_max_days" ]; then chage -M "$P_max_days" -- "$name"; fi;; esac
      case "$min" in ''|*[!0-9]*) chage -m "$P_min_days" -- "$name";; *) if [ "$min" -lt "$P_min_days" ]; then chage -m "$P_min_days" -- "$name"; fi;; esac
    done < "$MB/ageing.scan"
  rollback: |
    if [ -f "$MB/ageing.list" ]; then
      while IFS=: read -r name min max; do chage -m "$min" -M "$max" -- "$name"; done < "$MB/ageing.list"
    fi
  validate: |
    awk '$1 == "PASS_MAX_DAYS" && a == "" { a = $2 } $1 == "PASS_MIN_DAYS" && b == "" { b = $2 } $1 == "PASS_MIN_LEN" && c == "" { c = $2 } END { exit !(a != "" && a + 0 <= M && b + 0 >= m && c + 0 >= l) }' M="$P_max_days" m="$P_min_days" l="$P_min_len" /etc/login.defs && for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do if [ -f "$f" ]; then cat "$f"; fi; done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; exit !(ml >= L && rc >= C) }' L="$P_min_len" C="$P_min_classes"
```

  `set -- $(merged)` is the one unquoted expansion: its words are two integers awk printed. Precede it with `# shellcheck disable=SC2046` on its own line in the body (a body comment is allowed; `templateLines` admits every body line). `$MB` is the block's directory (the body, validate and rollback subshells inherit it); the scan file and the ageing record live there. `pput`'s `mkdir` leaves the directory behind on rollback (spec §4.4).

**`muster.account.umask_policy`** — the default list becomes `["027", "022", "077", "0027", "0022", "0077"]`; text: "Set UMASK 027" stays.

```yaml
  script_params: [acceptable]
  backup: [/etc/login.defs]
  script: |
    ld=/etc/login.defs
    first=${P_acceptable%% *}
    v=$(awk '$1 == "UMASK" { print $2; exit }' "$ld")
    case " $P_acceptable " in
      *" $v "*) ;;
      *) if grep -Eq '^[[:space:]]*UMASK[[:space:]]' "$ld"; then sed -i -E "s|^([[:space:]]*UMASK)[[:space:]].*|\1 $first|" "$ld"; else printf 'UMASK %s\n' "$first" >> "$ld"; fi;;
    esac
  validate: |
    case " $P_acceptable " in *" $(awk '$1 == "UMASK" { print $2; exit }' /etc/login.defs) "*) ;; *) false;; esac
```

  (An empty `v` cannot match: the list is joined by single spaces, so `"  "` never occurs in it.)

**`muster.account.lockout_threshold`** (S-9; text gains "A deny= argument on the pam_faillock lines wins over the file; the review script edits the file only." KO: "pam_faillock 줄의 deny= 인자는 파일보다 우선하며, 검토 스크립트는 파일만 고칩니다.")

```yaml
  script_params: [max_attempts]
  backup: [/etc/security/faillock.conf]
  script: |
    fc=/etc/security/faillock.conf
    v=$(awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k) } k == "deny" { d = $2 } END { gsub(/[[:space:]]/, "", d); print d }' "$fc" 2>/dev/null)
    case "$v" in ''|*[!0-9]*) v=3;; esac
    if [ "$v" -lt 1 ] || [ "$v" -gt "$P_max_attempts" ]; then
      if grep -Eq '^[[:space:]]*deny[[:space:]]*=' "$fc" 2>/dev/null; then sed -i -E "s|^([[:space:]]*deny)[[:space:]]*=.*|\1 = $P_max_attempts|" "$fc"; else printf 'deny = %s\n' "$P_max_attempts" >> "$fc"; fi
    fi
  validate: |
    awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k) } k == "deny" { d = $2 } END { gsub(/[[:space:]]/, "", d); if (d == "") d = 3; exit !(d + 0 >= 1 && d + 0 <= M) }' M="$P_max_attempts" /etc/security/faillock.conf
```

**`muster.account.session_timeout`** (S-11; text: "ClientAliveCountMax 1" becomes "a ClientAliveCountMax of at most params.max_count", and it gains "in /etc/ssh/sshd_config.d/00-muster-session.conf, keeping a value already in range; an earlier ClientAliveInterval before the Include beats any drop-in" — KO likewise)

```yaml
  script_params: [max_interval, max_count]
  script_on_absent: true
  backup: [/etc/ssh/sshd_config.d/00-muster-session.conf]
  script: |
    if command -v sshd >/dev/null 2>&1; then
      [ -d /run/sshd ] || mkdir -p /run/sshd
      i=$(sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" { print $2 }')
      c=$(sshd -T 2>/dev/null | awk '$1 == "clientalivecountmax" { print $2 }')
      case "$i" in ''|*[!0-9]*) i="$P_max_interval";; *) if [ "$i" -lt 1 ] || [ "$i" -gt "$P_max_interval" ]; then i="$P_max_interval"; fi;; esac
      case "$c" in ''|*[!0-9]*) c="$P_max_count";; *) if [ "$c" -lt 1 ] || [ "$c" -gt "$P_max_count" ]; then c="$P_max_count"; fi;; esac
      printf 'ClientAliveInterval %s\nClientAliveCountMax %s\n' "$i" "$c" > /etc/ssh/sshd_config.d/00-muster-session.conf
      chmod 644 /etc/ssh/sshd_config.d/00-muster-session.conf
      sshd -t
      if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
      if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
    fi
  rollback: |
    rm -f /etc/ssh/sshd_config.d/00-muster-session.conf
    if command -v sshd >/dev/null 2>&1; then
      sshd -t
      if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
      if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
    fi
  validate: |
    if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" { i = $2 } $1 == "clientalivecountmax" { c = $2 } END { exit !(i >= 1 && i <= I && c >= 1 && c <= C) }' I="$P_max_interval" C="$P_max_count"; fi
```

- [ ] **Step 1: Write the failing body tests** in `shipped_bodies_test.go`:

```go
// accountTree stubs chage, sshd and systemctl for the account bodies: chage
// logs its argv; sshd -T answers from the muster drop-in when it exists (it
// sorts first, and the first value wins) and from $STUB/sshd_T otherwise;
// sshd -t succeeds; systemctl reports nothing active.
func accountTree(t *testing.T) (root, bin, stub string) {
	root, bin, stub = t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "chage", `printf '%s\n' "$*" >> "$STUB/chage"`+"\n")
	writeStub(t, bin, "systemctl", `printf '%s\n' "$*" >> "$STUB/systemctl"; [ "$1" = is-active ] && exit 1; exit 0`+"\n")
	writeStub(t, bin, "sshd", `case "$1" in
  -t) exit 0;;
  -T) d="$ROOT/etc/ssh/sshd_config.d/00-muster-session.conf"
      if [ -f "$d" ]; then tr 'A-Z' 'a-z' < "$d"; else cat "$STUB/sshd_T"; fi;;
esac
`)
	return root, bin, stub
}

func rebaseAccounts(s, root string) string {
	for _, p := range []string{"/etc/login.defs", "/etc/security/", "/etc/shadow", "/etc/ssh/", "/run/sshd"} {
		s = strings.ReplaceAll(s, p, root+p)
	}
	return s
}

func TestPasswordPolicyBodyTightensOnly(t *testing.T) {
	needSh(t)
	c := shippedControl(t, "muster.account.password_policy")
	r := c.Remediation
	root, bin, stub := accountTree(t)
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	today := int(time.Now().Unix() / 86400)
	write("/etc/login.defs", "#PASS_MAX_DAYS 1\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS 2\nPASS_MAX_DAYS 99999\n")
	write("/etc/security/pwquality.conf", "minlen = 14\n")
	write("/etc/shadow", fmt.Sprintf("root:*:%d:0:99999:7:::\nfresh:$6$x:%d::99999:7:::\nold:$6$x:%d:0:99999:7:::\nstrict:$6$x:%d:5:30:7:::\nlegacy:abcDEF:%d:::7:::\n#c:$6$x:1:0:1:::\n", today, today, today-400, today, today))
	mb := t.TempDir()
	env := append(pEnv(t, c), "MB="+mb, "STUB="+stub, "ROOT="+root)
	body := "log() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAccounts(r.Script, root)
	out, code := runBody(t, root, bin, body, env...)
	if code != 0 {
		t.Fatalf("body %d: %s", code, out)
	}
	ld, _ := os.ReadFile(filepath.Join(root, "/etc/login.defs"))
	if !strings.Contains(string(ld), "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 2\nPASS_MAX_DAYS 90\n") || !strings.Contains(string(ld), "PASS_MIN_LEN 8\n") || !strings.Contains(string(ld), "#PASS_MAX_DAYS 1\n") {
		t.Errorf("login.defs:\n%s", ld)
	}
	pw, _ := os.ReadFile(filepath.Join(root, "/etc/security/pwquality.conf.d/99-muster.conf"))
	if string(pw) != "minclass = 3\n" {
		t.Errorf("drop-in %q: minlen 14 is stricter and stays; minclass is written", pw)
	}
	calls, _ := os.ReadFile(filepath.Join(stub, "chage"))
	got := string(calls)
	for _, w := range []string{"-M 90 -- fresh\n", "-m 1 -- fresh\n", "-M 90 -- legacy\n", "-m 1 -- legacy\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("chage lacks %q:\n%s", w, got)
		}
	}
	for _, never := range []string{"-- root\n", "-- old\n", "-M 90 -- strict\n", "-m 1 -- strict\n", "#c"} {
		if strings.Contains(got, never) {
			t.Errorf("chage carries %q:\n%s", never, got)
		}
	}
	if !strings.Contains(out, "password_policy: old: password older than 90 days, change it first") {
		t.Errorf("no skip log for old: %s", out)
	}
	rec, _ := os.ReadFile(filepath.Join(mb, "ageing.list"))
	if !strings.Contains(string(rec), "legacy:-1:-1\n") || !strings.Contains(string(rec), "fresh:-1:99999\n") {
		t.Errorf("ageing.list:\n%s", rec)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(r.Validate, root), env...); code != 0 {
		t.Errorf("validate %d: %s", code, out)
	}
	if out, code := runBody(t, root, bin, rebaseAccounts(r.Rollback, root), env...); code != 0 {
		t.Errorf("rollback %d: %s", code, out)
	}
	if calls, _ := os.ReadFile(filepath.Join(stub, "chage")); !strings.Contains(string(calls), "-m -1 -M 99999 -- fresh\n") || !strings.Contains(string(calls), "-m -1 -M -1 -- legacy\n") {
		t.Errorf("rollback replay:\n%s", calls)
	}
}

func TestLineBodiesTightenOnly(t *testing.T) {
	needSh(t)
	for _, c := range []struct {
		id, file, before, after string
	}{
		{"muster.account.umask_policy", "/etc/login.defs", "UMASK 002\n", "UMASK 027\n"},
		{"muster.account.umask_policy", "/etc/login.defs", "UMASK 077\n", "UMASK 077\n"},
		{"muster.account.umask_policy", "/etc/login.defs", "# none\n", "# none\nUMASK 027\n"},
		{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "deny = 3\ndeny = 99\n", "deny = 5\ndeny = 5\n"},
		{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "# deny = 3\n", "# deny = 3\n"},
		{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "deny = 0\n", "deny = 5\n"},
		{"muster.account.lockout_threshold", "/etc/security/faillock.conf", "deny = 2\n", "deny = 2\n"},
	} {
		ctl := shippedControl(t, c.id)
		root, bin, stub := accountTree(t)
		p := filepath.Join(root, c.file)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c.before), 0o644); err != nil {
			t.Fatal(err)
		}
		env := append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root)
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Script, root), env...); code != 0 {
			t.Fatalf("%s %q: body %d %s", c.id, c.before, code, out)
		}
		if b, _ := os.ReadFile(p); string(b) != c.after {
			t.Errorf("%s %q: file %q, want %q", c.id, c.before, b, c.after)
		}
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Validate, root), env...); code != 0 {
			t.Errorf("%s %q: validate %d %s", c.id, c.before, code, out)
		}
	}
}

func TestSessionTimeoutKeepsAValueInRange(t *testing.T) {
	needSh(t)
	ctl := shippedControl(t, "muster.account.session_timeout")
	for _, c := range []struct{ answer, want string }{
		{"clientaliveinterval 900\nclientalivecountmax 3\n", "ClientAliveInterval 300\nClientAliveCountMax 3\n"},
		{"clientaliveinterval 120\nclientalivecountmax 9\n", "ClientAliveInterval 120\nClientAliveCountMax 3\n"},
		{"clientaliveinterval 0\nclientalivecountmax 3\n", "ClientAliveInterval 300\nClientAliveCountMax 3\n"},
	} {
		root, bin, stub := accountTree(t)
		_ = os.MkdirAll(filepath.Join(root, "/etc/ssh/sshd_config.d"), 0o755)
		if err := os.WriteFile(filepath.Join(stub, "sshd_T"), []byte(c.answer), 0o644); err != nil {
			t.Fatal(err)
		}
		env := append(pEnv(t, ctl), "STUB="+stub, "ROOT="+root)
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Script, root), env...); code != 0 {
			t.Fatalf("%q: body %d %s", c.answer, code, out)
		}
		if b, _ := os.ReadFile(filepath.Join(root, "/etc/ssh/sshd_config.d/00-muster-session.conf")); string(b) != c.want {
			t.Errorf("%q: drop-in %q, want %q", c.answer, b, c.want)
		}
		if out, code := runBody(t, root, bin, rebaseAccounts(ctl.Remediation.Validate, root), env...); code != 0 {
			t.Errorf("%q: validate %d %s", c.answer, code, out)
		}
	}
}
```

  (Add `fmt` and `time` to the test file's imports; `time` is allowed in tests. In the password case, `fresh` and `legacy` get both writes, `strict` none (30 ≤ 90, 5 ≥ 1), `old` is skipped and logged, and `root` (`*`) and the `#c` comment line are never read.)

- [ ] **Step 2: Run** on the lab: `go test ./internal/remedy/ -run 'TestPasswordPolicyBody|TestLineBodies|TestSessionTimeout'`. Expected: FAIL (no script).
- [ ] **Step 3: Write the four blocks**, the risk change, the default-list reorder and the texts.
- [ ] **Step 4: Run** the Step 2 tests (PASS). Run `go test ./internal/remedy/ -run TestShippedRootLogin` (unchanged control, unchanged behaviour).
- [ ] **Step 5: Mutation and fixtures.** `go test ./internal/controls/ -run TestEveryMutantIsKilled`. The reorder makes `umask_policy`'s `params.acceptable.default drop[0]` drop `"027"`: if it survives, add `controls/testdata/muster.account.umask_policy/fail-umask-027-dropped.json` — copy the existing `pass-*.json` fixture whose `accounts.login_defs.umask` is `"022"`, set it to `"027"`, and rename it `pass-umask-027.json` (a PASS at the default that the mutant turns FAIL kills it). Re-run until zero survivors.
- [ ] **Step 6: Run** `go test ./...` (Windows), the two lint commands, regenerate `all-scripted.sh` (48 blocks), shellcheck it on the lab, and `go test ./internal/remedy/ ./internal/collect/collectors/ ./internal/controls/` on the lab as root. Add the four `_roundtrip.yaml` entries as `unproven: "the rows land in Task 9"`.
- [ ] **Step 7: Commit**

```bash
git add controls/account/password_policy.yaml controls/account/umask_policy.yaml controls/account/lockout_threshold.yaml controls/account/session_timeout.yaml controls/testdata internal/remedy/shipped_bodies_test.go internal/remedy/script_test.go internal/remedy/testdata/all-scripted.sh
git commit -m "controls: password, umask, lockout and session scripts that only tighten; password_policy is lockout_risk"
```

---
### Task 9: CI — `kind` per row, the runner row, the seeds, `record()`, the round-trip table

**Files:**
- Modify: `.github/workflows/ci.yml` (`fix-roundtrip` `:506-639`; the `test` job's round-trip floor `:44-50`), `Makefile` (`:49-56`)
- Create: `ci/roundtrip/runner.sh`
- Modify: `ci/roundtrip/{rocky9-init,almalinux9-init,debian12-init,ubuntu2204}.sh`, `controls/testdata/_roundtrip.yaml`
- Modify: `internal/controls/roundtrip_test.go` (`:13-142`)

**Interfaces:**
- Consumes: Task 1's `probe.md` (seed lines, package lists, row placements, the `password_policy`-on-runner decision).

- [ ] **Step 1: Write the failing table-test changes** in `roundtrip_test.go`:
  - `matrixRow` becomes `struct{ Key, Kind, Image, Init, Seeded, Build string }`.
  - After the rows are read, add:

```go
	hostRow := map[string]bool{}
	for _, r := range rows {
		switch r.Kind {
		case "container":
			if r.Image == "" {
				t.Errorf("matrix row %q: a container row needs an image", r.Key)
			}
		case "host":
			hostRow[r.Key] = true
			if r.Image != "" || r.Init != "" || r.Build != "" {
				t.Errorf("matrix row %q: a host row carries no image, init or build", r.Key)
			}
		default:
			t.Errorf("matrix row %q: kind %q, want container or host", r.Key, r.Kind)
		}
	}
	for _, e := range table {
		if !strings.HasPrefix(e.ID, "muster.beyond.") {
			continue
		}
		for _, img := range e.Images {
			if !hostRow[img] {
				t.Errorf("%s: a beyond control gates containers out, so it may name host rows only, not %q", e.ID, img)
			}
		}
	}
```

  - The `unproven_units` membership check accepts a key in `r.Units`, `r.Modules` or `r.Sysctl` (message: `unproven unit %q is not declared in units, modules or sysctl`).
  - The "needs key and seeded" message prints `r.Key`, not `r.Image`.
  - (Use the names the test already has for the decoded table and rows; `table` and `rows` stand for them here.)

- [ ] **Step 2: Run** `go test ./internal/controls -run TestEveryScriptedControlIsInTheRoundtripTable`. Expected: FAIL (`kind ""`).

- [ ] **Step 3: The matrix.** Add `kind: container` to the four rows. Append the host row (its `seeded` from `probe.md`; the hypothesis is):

```yaml
          - key: runner
            kind: host
            seeded: >-
              muster.account.cron_permissions muster.account.session_timeout
              muster.account.umask_policy muster.beyond.aslr_and_link_protection
              muster.beyond.audit_log_permissions muster.beyond.bootloader_config_permissions
              muster.beyond.icmp_broadcast_and_bogus_ignored muster.beyond.icmp_redirects_ignored
              muster.beyond.ip_forwarding_disabled muster.beyond.ipv6_forwarding_disabled
              muster.beyond.ipv6_redirects_ignored muster.beyond.ipv6_router_advertisements_ignored
              muster.beyond.ipv6_source_routing_rejected muster.beyond.kernel_pointer_exposure
              muster.beyond.ptrace_restriction muster.beyond.reverse_path_filtering
              muster.beyond.source_routing_rejected muster.beyond.suid_dumpable_disabled
              muster.beyond.syn_cookies_enabled muster.beyond.sysrq_restricted
              muster.beyond.uncommon_filesystems_disabled muster.beyond.uncommon_network_protocols_disabled
              muster.beyond.unprivileged_bpf_restricted muster.file.inetd_conf_permissions
              muster.file.syslog_conf_permissions
```

  `sudoers_permissions` is NOT seeded on the runner: the job's own `sudo` reads `/etc/sudoers`, and a seed that loosens it could stop every later step. The container rows' `seeded` lists gain the new ids `probe.md` assigns them (hypothesis: the EL rows gain `cron_permissions`, `sudoers_permissions`, `umask_policy`, `password_policy`, `lockout_threshold`, `session_timeout`, `nfs_export_access`, `ftpusers_permissions`, `inetd_conf_permissions`, `syslog_conf_permissions`, `log_dir_permissions`; `debian12-init` gains the same minus `password_policy`, `lockout_threshold`, `session_timeout`; `ubuntu2204` gains `cron_permissions`, `sudoers_permissions`, `umask_policy`, `inetd_conf_permissions`, `syslog_conf_permissions`, `log_dir_permissions`).

- [ ] **Step 4: The run step.** Add `env: { KIND: "${{ matrix.kind }}" }` to the step, and replace its `run:` with:

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
c1=; c2=; cid=
trap '[ -z "$c1$c2" ] || docker rm -f $c1 $c2 >/dev/null 2>&1 || true' EXIT
# x runs a command on the system under test: the container, or the runner VM itself (3D-2c §5)
x() { if [ "$KIND" = host ]; then sudo "$@"; else docker exec "$cid" "$@"; fi; }
if [ "$KIND" = host ]; then M=./bin/muster; S=ci/roundtrip; else M=/m/muster; S=/ci; fi
out() { if [ "$KIND" = host ]; then printf '%s' "$1"; else printf /out; fi; } # out <dir>: <dir> as the system under test sees it
seed() { x sh "$S/${{ matrix.key }}.sh"; }
plan() { # plan <dir>: collect, then the JSON plan and the script into <dir>
  x "$M" collect --out "$(out "$1")/before.json" || true
  sudo chown "$(id -u)" "$1/before.json"
  ./bin/muster fix --dry-run --facts "$1/before.json" --format json > "$1/plan.json"
  ./bin/muster fix --dry-run --facts "$1/before.json" --format script > "$1/fix.sh"
  test -s "$1/plan.json"; test -s "$1/fix.sh"
}
runfix() { # runfix <dir> <script>: run <dir>/<script> with that run's own backup directory
  x env MUSTER_BACKUP="/var/backups/muster/ci-$(basename "$1")" sh "$(out "$1")/$2"
}
if [ "$KIND" = container ]; then
  c1=$(start "$d/repair"); cid=$c1
  [ "${{ matrix.init }}" = "true" ] && sh ci/roundtrip/wait.sh "$c1" "${{ matrix.key }}"
fi
seed
plan "$d/repair"
for id in ${{ matrix.seeded }}; do
  jq -e --arg id "$id" '[.items[] | select(.id == $id and .planned and .script)] | length == 1' "$d/repair/plan.json" > /dev/null \
    || { echo "seeded $id is not a planned scripted item"; jq '.items[] | {id, planned, script, text_only_reason}' "$d/repair/plan.json"; exit 1; }
done
runfix "$d/repair" fix.sh
x "$M" collect --out "$(out "$d/repair")/after.json" || true
sudo chown "$(id -u)" "$d/repair/after.json"
set +e; ./bin/muster check --facts "$d/repair/after.json" --format json > "$d/repair/after-report.json"; set -e
for id in ${{ matrix.seeded }}; do
  jq -e --arg id "$id" '[.results[] | select(.id == $id and (.status == "PASS" or .status == "NOT_APPLICABLE"))] | length == 1' "$d/repair/after-report.json" > /dev/null \
    || { echo "$id did not pass after the script"; jq --arg id "$id" '.results[] | select(.id == $id)' "$d/repair/after-report.json"; exit 1; }
done
[ "$KIND" = host ] || [ "${{ matrix.init }}" = "true" ] || exit 0
# failure and guard runs (3D-2b §4); the host row re-seeds the same VM and has no guard run (3D-2c §5)
if [ "$KIND" = container ]; then
  c2=$(start "$d/fail"); cid=$c2; sh ci/roundtrip/wait.sh "$c2" "${{ matrix.key }}"
fi
seed
plan "$d/fail"
h1=$(jq -r .run.host.machine_id_hash "$d/repair/plan.json"); h2=$(jq -r .run.host.machine_id_hash "$d/fail/plan.json")
g1=$(jq -r .fix.host_guard "$d/repair/plan.json"); g2=$(jq -r .fix.host_guard "$d/fail/plan.json")
if [ "$KIND" = container ]; then
  [ "$g1" = on ] && [ "$g2" = on ] && [ -n "$h1" ] && [ "$h1" != "$h2" ] \
    || { echo "${{ matrix.key }}: the two containers need distinct machine ids (guard $g1/$g2, hash $h1/$h2)"; exit 1; }
else
  [ "$g1" = on ] && [ "$g2" = on ] && [ -n "$h1" ] && [ "$h1" = "$h2" ] \
    || { echo "runner: the guard must be on and the machine id stable (guard $g1/$g2, hash $h1/$h2)"; exit 1; }
  ids() { jq -r '[.items[] | select(.planned and .script) | .id] | sort | .[]' "$1"; }
  [ "$(ids "$d/repair/plan.json")" = "$(ids "$d/fail/plan.json")" ] \
    || { echo "runner: the failure plan's scripted ids differ from the repair plan's"; ids "$d/repair/plan.json"; echo ---; ids "$d/fail/plan.json"; exit 1; }
fi
sed -n '/^modes_paths() {/,/^}/p' "$d/fail/fix.sh" > "$d/fail/modes_paths.sh"
record() { # unit states; backup-path stats, checksums and ACLs; sysctl values; module load states; modes-entry stats
  jq -r '.items[] | select(.planned and .script) | .units[]' "$d/fail/plan.json" | sort -u > "$d/fail/units"
  : > "$d/fail/deps"
  while read -r u; do x systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" < /dev/null | tr ' ' '\n' >> "$d/fail/deps" || :; done < "$d/fail/units"
  sort -u "$d/fail/units" "$d/fail/deps" | sed '/^$/d' | while read -r u; do
    printf '%s %s %s\n' "$u" "$(x systemctl is-enabled -- "$u" < /dev/null 2>/dev/null || :)" "$(x systemctl is-active -- "$u" < /dev/null 2>/dev/null || :)"
  done
  jq -r '.items[] | select(.planned and .script) | .backup[]' "$d/fail/plan.json" | sort -u | while read -r p; do
    x sh -c 'p=$1; if [ -e "$p" ] || [ -L "$p" ]; then printf "%s %s %s\n" "$p" "$(stat -c "%u %g %a" "$p")" "$(sha256sum < "$p" | cut -d" " -f1)"; if command -v getfacl >/dev/null; then getfacl -cp "$p" 2>/dev/null || :; fi; else printf "%s absent\n" "$p"; fi' _ "$p" < /dev/null
  done
  jq -r '.items[] | select(.planned and .script) | .sysctl[]' "$d/fail/plan.json" | sort -u | while read -r k; do
    printf 'sysctl %s %s\n' "$k" "$(x sysctl -n -- "$k" < /dev/null 2>/dev/null || echo absent)"
  done
  jq -r '.items[] | select(.planned and .script) | .modules[]' "$d/fail/plan.json" | sort -u | while read -r m; do
    n=$(printf '%s' "$m" | tr - _)
    if x grep -q "^$n " /proc/modules < /dev/null; then printf 'module %s loaded\n' "$n"; else printf 'module %s not-loaded\n' "$n"; fi
  done
  jq -r '.items[] | select(.planned and .script) | .modes[]' "$d/fail/plan.json" | sort -u | while IFS= read -r e; do
    x sh -c '. "$1"; modes_paths "$2" | while IFS= read -r p; do printf "mode %s %s\n" "$p" "$(stat -c "%u %g %a" -- "$p")"; done' _ "$(out "$d/fail")/modes_paths.sh" "$e" < /dev/null
  done | sort
}
same() { # same <before> <after>: equal records, except that a modes-entry path gone since (a rotated log) is no difference
  diff <(grep -v '^mode ' "$1") <(grep -v '^mode ' "$2")
  grep '^mode ' "$1" | while read -r _ p rest; do
    a=$(grep -F "mode $p " "$2" || :)
    [ -z "$a" ] || [ "$a" = "mode $p $rest" ] || { echo "mode of $p: before $rest, after ${a#mode "$p" }"; exit 1; }
  done
}
record > "$d/fail/record-before"
if [ "$KIND" = container ]; then
  cp "$d/repair/fix.sh" "$d/fail/repair-fix.sh"
  set +e; runfix "$d/fail" repair-fix.sh > "$d/fail/guard.out" 2>&1; gc=$?; set -e
  [ "$gc" -eq 2 ] && grep -qx 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway' "$d/fail/guard.out" \
    || { echo "guard run: exit $gc"; cat "$d/fail/guard.out"; exit 1; }
  record > "$d/fail/record-guard"; same "$d/fail/record-before" "$d/fail/record-guard"
fi
awk 'prev == "  # validate" { print; getline; print "    false"; prev = ""; next } { print; prev = $0 }' "$d/fail/fix.sh" > "$d/fail/broken.sh"
blocks=$(jq '[.items[] | select(.planned and .script)] | length' "$d/fail/plan.json")
changed=$(diff "$d/fail/fix.sh" "$d/fail/broken.sh" | grep -c '^>' || :)
[ "$changed" -eq "$blocks" ] || { echo "rewrite changed $changed lines for $blocks blocks"; exit 1; }
set +e; runfix "$d/fail" broken.sh > "$d/fail/broken.out" 2>&1; bc=$?; set -e
cat "$d/fail/broken.out"
[ "$bc" -eq 1 ] || { echo "failure run: exit $bc, want 1"; exit 1; }
[ "$(grep -c 'validate failed, rolling back' "$d/fail/broken.out")" -eq "$blocks" ] || { echo "not every block rolled back"; exit 1; }
! grep -qE 'ROLLBACK INCOMPLETE|not restored|rollback failed' "$d/fail/broken.out" || { echo "a rollback was incomplete"; exit 1; }
record > "$d/fail/record-after"
same "$d/fail/record-before" "$d/fail/record-after"
```

  The step runs under GitHub's default `bash -e` (`diff <(…)` needs bash); the header comment of the job (`:506-511`) gains "A host row (3D-2c) runs on the runner VM itself: no container, no guard run, and the failure run re-seeds the same VM." On the runner the repair plan also carries every stock-FAIL scripted control (for example `hosts_permissions` → 0600), so non-root `/etc/hosts` reads fail until the failure run restores it; the job's non-root steps (`jq`, `./bin/muster fix`) read only the run directory.

- [ ] **Step 5: `ci/roundtrip/runner.sh`** (shellcheck-clean, `set -eu`):

```sh
#!/bin/sh
# runner.sh seeds the GitHub runner VM for the fix-roundtrip host row
# (3D-2c §5). It is idempotent: it removes every file a review script wrote,
# then applies every seed again, so the failure run plans the same blocks.
set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v auditctl >/dev/null 2>&1; then apt-get update -q && apt-get install -y -q auditd; fi
rm -f /etc/sysctl.d/99-muster-*.conf /etc/modprobe.d/99-muster-*.conf \
  /etc/ssh/sshd_config.d/00-muster-session.conf /etc/security/pwquality.conf.d/99-muster.conf
for kv in kernel.randomize_va_space=0 net.ipv4.icmp_echo_ignore_broadcasts=0 net.ipv4.conf.default.accept_redirects=1 \
  net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.accept_redirects=1 \
  net.ipv6.conf.default.accept_ra=1 net.ipv6.conf.all.accept_source_route=1 kernel.kptr_restrict=0 \
  kernel.yama.ptrace_scope=0 net.ipv4.conf.default.log_martians=0 net.ipv4.conf.default.accept_source_route=1 \
  fs.suid_dumpable=2 net.ipv4.tcp_syncookies=0 kernel.sysrq=176 net.core.bpf_jit_harden=0; do
  sysctl -q -w "$kv"
done
for m in udf sctp tipc; do modprobe --ignore-install "$m"; done
chmod 644 /boot/grub/grub.cfg /var/log/audit/audit.log /etc/crontab /etc/rsyslog.conf
install -m 644 /dev/null /etc/inetd.conf
sed -i 's/^ClientAliveInterval .*/ClientAliveInterval 900/' /etc/ssh/sshd_config.d/50-cloudimg-settings.conf
if grep -q '^UMASK' /etc/login.defs; then sed -i 's/^UMASK.*/UMASK 002/' /etc/login.defs; else printf 'UMASK 002\n' >> /etc/login.defs; fi
```

  (The `sysctl` seed list, the module list and the `ClientAliveInterval` file are `probe.md`'s; if it found the value elsewhere, the seed rewrites that file.) Edit the four container seeds per `probe.md`: the package additions (EL: `sudo cronie rsyslog vsftpd`, and `authselect enable-feature with-faillock` plus `deny = 99` in `/etc/security/faillock.conf`; Debian/Ubuntu: `sudo cron rsyslog vsftpd` under the existing `policy-rc.d`), and the per-control seed lines of spec §5's container table (`chmod 644 /etc/sudoers /etc/crontab /etc/rsyslog.conf`, `install -m 644 /dev/null /etc/inetd.conf`, `install -m 666 /dev/null /etc/exports` on init rows, `chmod 644` on the vsftpd access file, `install -m 666 /dev/null /var/log/ci.log`, `UMASK 002`, on EL `PASS_MAX_DAYS 99999` and a hashed account changed today — `useradd -m ci && printf 'ci:%s
' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' 
')" | chpasswd` (a random password: no literal for the secret scanner) — and `ClientAliveInterval 900` in `/etc/ssh/sshd_config.d/99-ci.conf`, which sorts after `00-muster-session.conf`).

- [ ] **Step 6: The floors.** `ci.yml`'s round-trip loop floor `[ "$n" -ge 5 ]` becomes 6, as does the Makefile's (`roundtrip scripts checked, want at least 6`, and its comment).

- [ ] **Step 7: The table.** In `_roundtrip.yaml`, the header's list of causes gains "or the kernel does not ship the module"; each of the 32 entries Tasks 5–8 wrote as `unproven: "… Task 9"` becomes its `probe.md` row list (`images: [runner]` for the beyond controls; `unproven_units` for each module the runner kernel does not ship — `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus` and `dccp`, `rds`, with the reason "the runner kernel does not ship it"); `usb_storage_disabled` stays `unproven: "the runner kernel does not ship usb-storage"`; `bootloader_config_permissions` gains no note (its ESP class is in the spec's §7).

- [ ] **Step 8: Run** `go test ./internal/controls/ -run TestEveryScriptedControlIsInTheRoundtripTable` (PASS), shellcheck `ci/roundtrip/*.sh` on the lab through the image, and `go test ./...` on Windows.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/ci.yml Makefile ci/roundtrip controls/testdata/_roundtrip.yaml internal/controls/roundtrip_test.go
git commit -m "ci: a kind per round-trip row, the runner host row and its seed, state records in record(), and the table"
```

The branch's first CI run is the runner row's proof; until it is green, Task 9 is not done.

---

### Task 10 (controller): documents and the spec corrections

**Files:** the main design pair, `CLAUDE.md`, the `CONTRIBUTING` pair, the `README` pair, `THREAT_MODEL.md`, `CHANGELOG.md`, the 3D-2c spec pair. Line numbers from `code-map-docs.md`.

- [ ] **Step 1: The 3D-2c spec pair** (the spec as built): §6 "the file-validate test over six controls" → five (S-8); §4.4 `lockout_threshold` → the missing-`deny` default of 3 and the `[1, max]` gate (S-9); `password_policy` → `required_classes` and the PAM-argument note (S-10); `session_timeout` → the per-keyword value-in-range rule and the guarded validate (S-11, reversing the round-2 wording); §4.3 `ftpusers`/`nfs` `chown root` (S-13); `modules_charset` start rule (S-7). One sentence each, EN and KO.
- [ ] **Step 2: Main design pair** (line-aligned, EN = KO line): `:552` D34 — after the hash clause, "a parameter's value is not a host value: it enters a command only as a `P_` assignment under the type charset (3D-2c)", and "independent" becomes "independent, each recording and restoring what it found"; `:94` the `internal/remedy` row names the hash and the `P_` assignments as the two admitted non-literal classes, both enforced by `templateLines`; `:282` §6.2 adds `script_params`, `script_on_absent`, `modes`, `sysctl`, `modules`, the way back of six kinds, drops "outside `/muster-units`", says units exclude the three record kinds, "stages 3D-2, 3D-2b and 3D-2c"; `:370` §6.8 replaces the shared-path sentence with "From stage 3D-2c each block records under its own directory, so two controls may declare the same path or unit."; `:414` §7.5 adds the `P_` lines, `$MUSTER_BACKUP/blocks/<fn>/`, the record kinds, the six rollback words and the failure order, rewords "proven on throwaway containers" to "proven in CI (containers, and the runner VM for what a container cannot judge)", and links the 3D-2c design; `:468` §10.2 marks 3D-2c merged with its design link and names 3D-2d (the audit family, `account_inactivity_lock`, the content halves).
- [ ] **Step 3: `CLAUDE.md`** `## Fix` (`:173-252`) per the code map's table: the heading gains 3D-2c; the plan bullet (S-2's order, `params_unsafe`, `script_on_absent`, S-4's re-checks); the script bullet (the prologue's new helpers before `failed=0`, `MB=` and `P_` lines, the six-step failure order, `$MB/files`, `$MB/absent`); the host-guard bullet (`templateLines` also admits the `P_`, `MB` and record lines); the units bullet (`$MB/units/<u>`, the three deleted lints, `units_exclusive` over the record kinds, the six words); the bodies bullet (the way back of six kinds, the third validate shape, the three new charsets, E-8, E-9's guards and mask formula, E-11, E-13, the file-validate test by owner table, 48 shipped bodies); the round-trip bullets (`kind`, the `runner` host row and `ci/roundtrip/runner.sh`, `record()`'s three additions, `same`, floors 6); the risk bullet (the forwarding controls and `usb_storage_disabled` `restart_service`, `password_policy` `lockout_risk`). The build list's "five round-trip scripts" → six.
- [ ] **Step 4: `CONTRIBUTING` pair** `### Remediation bodies`: the way back of six kinds; `P_<name>` and its five positions (never first on a line, never in an `s/` command — use `|`); E-8 (write only when outside the accepted set; validate set membership); E-9 (guards, `! -type l`/`-type f`, the mask formula); a `modes` entry, never a `backup`, for a path a body only re-modes; E-11 (a daemon's file is removed in the rollback before the reload); E-13 (a write's side effect on another judged key is the writer's); the third validate shape; the CI list in `## Tests` gains the runner row.
- [ ] **Step 5: `README` pair**: the status banner (3D-2c merged), a 3D-2c roadmap paragraph after 3D-2b's, "Next" → 3D-2d, 3D-1b, 3D-3. **`THREAT_MODEL.md`** (`:20-26`): the unit-state path `$MUSTER_BACKUP/blocks/<fn>/units/`; "a parameter value enters a command only as a `P_` assignment under the type charset"; `restore_modes` never writes through a symlink or across types; `restore_modules` bypasses an `install` line with `--ignore-install`. **`CHANGELOG.md`**: rewrite the Unreleased 3D-2b bullets in place (`:21-33` per-block record paths, the three lints never shipped in a release; `:80-81` six rollback words; `:91-97`); Added — parameters in scripts, the three record kinds, the runner row, 32 scripts; Changed — per-block backup directories, absent paths removed on restore, `umask_policy.acceptable`'s default order, the risks; Controls — `kisa-unix-2026+2026.10.14` (was `+2026.10.13`): remediation blocks and one parameter default order, no verdict change.
- [ ] **Step 6: Commit** the pairs together (`docs: record stage 3D-2c in the working documents`), after `make lint`, `make lint-controls` and `go test ./...` pass.

---

## Merge (the user's word)

1. The user says push: `git push -u origin stage3d2c-remedy-scripts`; dispatch `examples.yml` on the branch (`gh workflow run examples.yml --ref stage3d2c-remedy-scripts`).
2. Download the artifact into an empty scratch directory (`gh run download <id> -n examples-<id> -D <scratch>`; `make examples-fetch` will not overwrite), copy the files over `examples/`, review the diff (the fix reports gain the five item fields, the `MB=` lines, the new helpers and the runner VM's stock-FAIL blocks; the check reports change only by `umask_policy`'s parameter order), update `examples/README.md`'s run number, and commit (`examples: refresh from the branch's examples run`).
3. Open the PR (body ends with the Claude Code line); watch CI. The `fix-roundtrip` runner row is new: read its log whole on the first run, even when green.
4. Merge on the user's word; remove the worktree and the branch; update the project memory.

## Execution notes

(Rulings, review findings and the lab and CI runs go here as the tasks land.)
