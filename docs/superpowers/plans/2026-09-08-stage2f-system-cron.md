# Stage 2F — System File, Startup and Cron Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `cron` collector (the crontab/spool/`at` configuration and the systemd timer inventory) and extend the `files` collector with the permission facts of system startup scripts, the syslog/journald configuration, the inetd/xinetd configuration, the sudoers file and its drop-ins (plus the `sudo.*` derived keys), and the `/var/log` tree, then judge six KISA items with them: U-17 (startup scripts), U-20 (inetd config), U-21 (syslog config), U-37 (crontab files), U-63 (sudoers), U-67 (log directory).

**Architecture:** A new `cron` collector enumerates the cron and `at` configuration — `/etc/crontab`, `/etc/anacrontab`, the `/etc/cron.{d,hourly,daily,weekly,monthly}` drop-ins, the `cron.allow`/`cron.deny`/`at.allow`/`at.deny` access files, and the per-user spools under `/var/spool/cron` (Rocky) and `/var/spool/cron/crontabs` (Ubuntu) — as permission rows with a precomputed `owner_ok`, plus a best-effort systemd timer inventory; it declares `Needs: root` because the spools are root-only. The `files` collector gains, from stat over fixed paths and sorted globs, the startup-unit rows (with `is_symlink`/`target` so a link is filtered by a `where` clause, not judged), the syslog/journald and inetd/xinetd config rows, the sudoers file and drop-in rows (root-only read → `denied` for a non-root run), the `sudo.{installed,includedir,secure_path}` derived keys, and the `/var/log` tree with a per-row `group_writable_unexpected` precomputed against an allowed-group set. Every enumeration distinguishes a genuinely empty result (an `ok` empty list — a vacuous `each` correctly passes) from a failed one (the read's error status — never a silent empty), so a denied directory never reads as "nothing to check". Controls judge these with the existing `each`/`none`/`where`/`require` grammar; the guide's mode criteria are `params` defaults.

**Tech Stack:** Go 1.25 stdlib, YAML controls decoded strictly, JSON fixtures, the lab host (Ubuntu 22.04) and CI's Ubuntu 24.04 plus the Rocky/Alma 9 init containers (different spool layouts, `/etc/init.d` a symlink on RHEL, `/var/log` group `syslog` vs `root`).

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — §5.2 (envelopes, `Source.Kind`), §5.4 (`files` permission facts of enumerated paths; the `cron` section; the `sudo` addition), §5.6 (sensitivity), §5.7 (additive record fields keep `schema_version`), §6.3–6.6 (grammar; `each` with `subject`/`where`/`require`, `none` with `where`; `${param}`; mode-subset `in`), §6.5 (screening; a non-ok fact never PASSes), §7.3 (honest degradation), §10.2 (plan 2F), appendix A rows U-17/U-20/U-21/U-37/U-63/U-67. Execution notes of 2A–2E carry rulings R89–R201.

## Global Constraints

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`; a registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never resolved by `absent_means`.
- **A failed enumeration is the read's error, never an empty list (spec §7.3; the shared 2F hazard).** A glob or directory read that FAILS (denied, error) makes the affected list fact carry that read's status — so a control's `each`/`none` over it screens to `ERROR`, not a vacuous PASS. A genuinely empty result (the directory exists and is readable but holds nothing to judge) is an `ok` empty list `[]any{}`; a vacuous `each` over it is a correct PASS ("no such file is unsafe"). Never emit `[]` for a read that failed.
- **Mode "≤ NNN" is `op: in` over the bit-subsets of NNN (spec §6.6, C1 precedent).** There is no bit operator; the default is the guide's value and a `params.allowed_modes` relaxes it. Both distribution families ship `/etc/crontab`, `/etc/cron.d` and `/etc/rsyslog.conf` at `0644`, so where the guide wants `0640` a stock host FAILs and the control's description states the deviation.
- **C1** — `files.*` owns the permission facts of fixed candidate paths and of paths reached by a fixed glob set; a path discovered from a daemon's own configuration belongs to that daemon's collector. Cron config lives in the `cron` collector because its spools and per-user layout are cron's own, not a fixed `files.*` candidate.
- Permission facts of a fixed path use `writePermFacts` (`internal/collect/collectors/permfacts.go`); a per-row list uses the same mode/uid/gid/group-writable/other-writable shape inline. A stat failure reaches every leaf/field of that path or row.
- No judgment in collectors (D09): the collector records mode/owner/`is_symlink`/`owner_ok`/`group_writable_unexpected`; whether `0644` is too permissive, which groups may own a writable log dir, or whether `cron.allow` must exist lives in the controls' `params`, whose defaults are the guide's criterion (§6.6) even where a stock host then fails; the deviation is stated in the control's description.
- Every host touch goes through `Access` and every path a collector reads/stats/globs is in its `Declare.Reads`; `readLimit` on every `ReadFile`; a command a collector runs is in its `Declare.Commands`. No new module dependency. New Go files under `internal/collect/collectors` carry `//go:build linux`.
- Same input, same bytes: fixed path order, sorted globs, list rows in a stable order (glob-sorted, or spool user order); no `map` iteration reaching a `Set` value's order (a `map[string]any` record is fine — `encoding/json` sorts its keys).
- Control and waiver YAML decode strictly; every control has `pass-*`/`fail-*` fixtures (`fail-` on a `partial` control expects `WARN`; `warn-`/`error-`/`manual-`/`na-` prefixes exist), `synthetic: true`, and only the leaves the control reads; `controls lint --references docs/reference` must end `ok: 35 controls`; every `references.stig` id must exist in `docs/reference/stig/`, every NIST id in the index union.
- Never copy KISA guide text, CIS/DISA text or a distribution's packaged files verbatim: fixtures are synthetic (own wording, `synthetic: true`); titles/descriptions/remediation are muster's own words, English and Korean both; identifiers/flags/paths stay English on both sides. Nothing from the lab host is committed; no host name, address, alias or credential in any file.
- Registry additions carry `since: 1`, `sensitivity: public`, and their `collector`; the facts schema golden is regenerated with `go test ./internal/facts -run TestFactsSchemaGolden -update` and reviewed (new keys get `since` lines; no type change, so no `schema_version` bump). Exit codes unchanged.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/collect/collectors/cron.go` (new, T1) | `cronCollector`, `runCron`, the config/spool enumeration, the `owner_ok` rule, the systemd timer inventory. |
| `internal/collect/collectors/files_startup.go` (new, T2) | `startupScripts`/`startupDirs` (SysV + systemd unit rows with `is_symlink`/`target`); `syslogConfigs`/`journaldConfigs`; `inetdPerm` (`etc_inetd_conf.*`, `etc_xinetd_conf.*`, `xinetd_d`). |
| `internal/collect/collectors/files_sudo.go` (new, T3) | `sudoersFacts` (`etc_sudoers.*`, `etc_sudoers_d.*`, `sudoers_d_entries`) and the `sudo.{installed,includedir,secure_path}` derivation; `logTree` (`log_dirs`/`log_files` with `group_writable_unexpected`). |
| `internal/collect/collectors/files.go` (modify, T2/T3) | `runFiles` calls the new enumerations; `filesReads()` gains the fixed paths and globs. |
| `internal/collect/collectors/collectors_test.go` (T1–T3) | cron and files tests. |
| `internal/collect/collectors/register.go` (T1) | `collect.Register(cronCollector)` after `filesCollector`. |
| `internal/collect/collectors/testdata/*` (T1–T3) | crontab/spool, startup unit, syslog, inetd, sudoers and /var/log fixtures. |
| `internal/facts/registry.yaml`, `internal/facts/testdata/facts-schema.golden.json` (T1–T3) | new keys (T1 cron 3; T2 startup 2 + syslog 2 + inetd 3; T3 sudoers 5 + sudo 3 + log 2). |
| `controls/file/startup_script_permissions.yaml`, `syslog_conf_permissions.yaml`, `inetd_conf_permissions.yaml`, `log_dir_permissions.yaml` + fixtures (T4/T5) | U-17, U-21, U-20, U-67. |
| `controls/account/cron_permissions.yaml`, `sudoers_permissions.yaml` + fixtures (T4/T5) | U-37, U-63. |
| `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go` (`29` → `35`), `docs/reference/coverage.md`, `README.md`, `README.ko.md` (T4/T5/T6) | End-to-end snapshots, counts, coverage, README. |

Key inventory this plan adds (20 keys):

| Key | Type | Collector | Task | Meaning |
|---|---|---|---|---|
| `cron.files` | `list<record>` | cron | T1 | Every cron/`at` config file present: `path`, `scope` (`system`\|`user`\|`access`), `user` (for a spool file), `mode`, `uid`, `gid`, `group`, `owner_ok`, `group_writable`, `other_writable`. |
| `cron.dirs` | `list<record>` | cron | T1 | The cron directories and spools that exist: `path`, `mode`, `uid`, `gid`, `group`, `group_writable`, `other_writable`. |
| `cron.timers` | `list<record>` | cron | T1 | systemd timer unit-file inventory: `name`, `state`. Best-effort; a systemctl failure makes this the command's error, not an empty list. |
| `files.startup_scripts` | `list<record>` | files | T2 | SysV init scripts and systemd unit files under the startup dirs: `path`, `mode`, `uid`, `gid`, `is_symlink`, `target`, `group_writable`, `other_writable`. |
| `files.startup_dirs` | `list<record>` | files | T2 | The startup directories themselves: `path`, `mode`, `uid`, `gid`, `group_writable`, `other_writable`. |
| `files.syslog_configs` | `list<record>` | files | T2 | `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/syslog-ng/*` permission rows: `path`, `mode`, `uid`, `gid`, `group_writable`, `other_writable`. |
| `files.journald_configs` | `list<record>` | files | T2 | `/etc/systemd/journald.conf` and `journald.conf.d/*.conf` permission rows (same fields). |
| `files.etc_inetd_conf.{mode,uid,group_writable,other_readable}` | int×2, bool×2 | files | T2 | `/etc/inetd.conf` permission facts (absent on both stock families). |
| `files.etc_xinetd_conf.{mode,uid}` + `files.xinetd_d` | int×2, list<record> | files | T2 | `/etc/xinetd.conf` permissions and per-fragment permission rows under `/etc/xinetd.d`. |
| `files.etc_sudoers.{mode,uid,gid,acl_present}` | int×3, bool | files | T3 | `/etc/sudoers` permission facts (root-only read → `denied` for a non-root run). |
| `files.etc_sudoers_d.{mode,uid,gid,acl_present}` + `files.sudoers_d_entries` | int×3, bool, list<record> | files | T3 | The `/etc/sudoers.d` directory and its entries (`path`, `mode`, `uid`, `gid`, `group_writable`, `other_writable`, `ignored` for a name sudo skips — a `~` suffix or a `.`). |
| `files.log_dirs` + `files.log_files` | list<record>×2 | files | T3 | `/var/log` tree rows: `path`, `mode`, `uid`, `gid`, `group` (name), `group_writable`, `other_writable`. No `group_writable_unexpected` flag — U-67 owns the log-group allowlist as a `params` value and judges `each where {group_writable} require {group in allowed}`, keeping the policy in the control (D09), not the collector. |
| `sudo.installed` | `bool` | files | T3 | `/etc/sudoers` (or `/usr/bin/sudo`) exists. |
| `sudo.includedir` | `string` | files | T3 | The `@includedir`/`#includedir` directory named in `/etc/sudoers` (`""` when none — drop-ins are then inert). |
| `sudo.secure_path` | `string` | files | T3 | The `Defaults secure_path=…` value (`""` when unset). |

`sudo.*` keys carry `collector: files` (the files collector reads `/etc/sudoers`, C1 for a fixed path). Not built here: cron *content* judgment (which jobs run — inventory only); the systemd timer *permission* rows (timer unit files are startup units, judged by `startup_scripts`); `files.bin_su`/`bin_sudo` setuid facts (2L/2M — U-06 already judges su via PAM). The `/var/log` walk is bounded by a row cap with `truncated`, like the `/dev` walk.

---

### Task 1: The cron collector

**Files:**
- Create: `internal/collect/collectors/cron.go`, cron tests in `collectors_test.go`
- Modify: `internal/collect/collectors/register.go` (register after `filesCollector`), `internal/facts/registry.yaml` (3 keys), golden
- Create fixtures under `internal/collect/collectors/testdata/`: `crontab`, `cron_d_entry`, `cron_allow`, `spool_user`, `systemctl_list_timers.txt`

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Stat`, `Glob`, `Run`), `collect.Builder` (`Set`), `facts.Source`; the shared helpers `splitLines`, `readLimit`, `collect.OK`/`OKRead`/`Absent`/`FromReadError`; `groupNames(a)` (gid→name, from permfacts.go); the systemctl command shape from services.go (`systemctlPath`).
- Produces:
  - `cronCollector` (`Name: "cron"`, `Declare.Reads` = the fixed cron/at config paths and spool globs below, `Declare.Commands` = the timer-list command, `Needs: "root"`).
  - `runCron(ctx, a, b) error`.
  - `cronRow(a, path, scope, user string, groups map[int]string) map[string]any` and `dirRow(...)`.
  - `cronTimers(ctx, a) facts.Envelope`.

- [ ] **Step 1: Write the failing test — config files and the owner_ok rule**

```go
// cron.files lists every cron/at config file that exists, with a precomputed
// owner_ok (root-owned, or the spool owner for a per-user spool file) and the
// group/other-writable flags. A world-writable /etc/crontab is owner_ok true
// but group/other-writable true, which U-37 will fail.
func TestCronConfigFiles(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/crontab":               "crontab",
			"/etc/cron.d/muster":         "cron_d_entry",
			"/etc/cron.allow":            "cron_allow",
			"/var/spool/cron/crontabs/alice": "spool_user",
			"/etc/group":                 "group",
		},
		stats: map[string]statResult{
			"/etc/crontab":                   {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/etc/cron.d/muster":             {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/etc/cron.allow":                {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
			"/var/spool/cron/crontabs/alice": {mode: 0o600, uid: 1000, gid: 1000, kind: "regular"},
		},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	byPath := map[string]map[string]any{}
	for _, r := range rows { m := r.(map[string]any); byPath[m["path"].(string)] = m }
	if byPath["/etc/crontab"]["owner_ok"] != true || byPath["/etc/crontab"]["scope"] != "system" {
		t.Errorf("crontab %v", byPath["/etc/crontab"])
	}
	if byPath["/var/spool/cron/crontabs/alice"]["owner_ok"] != true || byPath["/var/spool/cron/crontabs/alice"]["user"] != "alice" {
		t.Errorf("a per-user spool file owned by that user is owner_ok: %v", byPath["/var/spool/cron/crontabs/alice"])
	}
	if byPath["/etc/cron.allow"]["scope"] != "access" {
		t.Errorf("cron.allow is scope access: %v", byPath["/etc/cron.allow"])
	}
}
```

Fixtures (synthetic, own content): `crontab` (a couple of comment + schedule lines), `cron_d_entry`, `cron_allow` (`root` on a line), `spool_user` (a schedule line), reuse `group`.

- [ ] **Step 2: Run it — fails (no cron collector)**

Run: `go test ./internal/collect/collectors/ -run TestCronConfigFiles -v` → FAIL (`collectorNamed` cannot find `cron`).

- [ ] **Step 3: Implement `cron.go`**

```go
//go:build linux

package collectors

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	etcCrontab   = "/etc/crontab"
	etcAnacrontab = "/etc/anacrontab"
)

// cronConfigGlobs are the fixed drop-in and access globs; cronSpoolGlobs are
// the per-user spools (Rocky /var/spool/cron, Ubuntu /var/spool/cron/crontabs).
var (
	cronDropInGlobs = []string{
		"/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*",
	}
	cronAccessFiles = []string{"/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"}
	cronSpoolGlobs  = []string{"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/var/spool/atjobs/*"}
	cronDirs        = []string{
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
		"/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/atjobs",
	}
	cronTimersCmd = collect.Command{Path: systemctlPath, Args: []string{"list-unit-files", "--type=timer", "--no-legend", "--no-pager"}}
)

var cronCollector = collect.Collector{
	Name: "cron",
	Declare: collect.Declaration{
		Reads: cronReads(),
		Commands: []collect.Command{cronTimersCmd},
		Needs: "root",
	},
	Run: runCron,
}

func cronReads() []string {
	reads := []string{etcCrontab, etcAnacrontab, groupPath}
	reads = append(reads, cronAccessFiles...)
	reads = append(reads, cronDropInGlobs...)
	reads = append(reads, cronSpoolGlobs...)
	reads = append(reads, cronDirs...)
	return reads
}

func runCron(ctx context.Context, a collect.Access, b *collect.Builder) error {
	groups, _, _ := groupNames(a)
	files := []any{}
	// Fixed system config files.
	for _, p := range []string{etcCrontab, etcAnacrontab} {
		if row, ok := cronRow(a, p, "system", "", groups); ok {
			files = append(files, row)
		}
	}
	for _, p := range cronAccessFiles {
		if row, ok := cronRow(a, p, "access", "", groups); ok {
			files = append(files, row)
		}
	}
	// Drop-in globs.
	for _, g := range cronDropInGlobs {
		matches, err := a.Glob(g)
		if err != nil {
			b.Set("cron.files", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.dirs", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.timers", cronTimers(ctx, a))
			return nil
		}
		sort.Strings(matches)
		for _, m := range matches {
			if row, ok := cronRow(a, m, "system", "", groups); ok {
				files = append(files, row)
			}
		}
	}
	// Per-user spools: the file's basename is the user.
	for _, g := range cronSpoolGlobs {
		matches, err := a.Glob(g)
		if err != nil {
			b.Set("cron.files", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.dirs", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.timers", cronTimers(ctx, a))
			return nil
		}
		sort.Strings(matches)
		for _, m := range matches {
			if row, ok := cronRow(a, m, "user", path.Base(m), groups); ok {
				files = append(files, row)
			}
		}
	}
	b.Set("cron.files", collect.OK(files, &facts.Source{Kind: "file", Path: "/etc/crontab"}))
	b.Set("cron.dirs", cronDirRows(a, groups))
	b.Set("cron.timers", cronTimers(ctx, a))
	return nil
}
```

`cronRow`, `cronDirRows`, `cronTimers`:

```go
// cronRow stats one cron/at file. ok is false only when the path does not
// exist (ENOENT) — a stat that failed for any other reason still yields a row
// carrying that failure via mode -1 and owner_ok false, so a denied file is a
// finding, not a silent skip. owner_ok is root-owned, or (for a user spool)
// owned by the user the spool names.
func cronRow(a collect.Access, p, scope, user string, groups map[int]string) (map[string]any, bool) {
	meta, err := a.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		return map[string]any{
			"path": p, "scope": scope, "user": user, "mode": -1, "uid": -1, "gid": -1,
			"group": "", "owner_ok": false, "group_writable": false, "other_writable": false,
			"reason": readReason(p, err),
		}, true
	}
	ownerOK := int(meta.UID) == 0
	if scope == "user" && user != "" {
		// A per-user spool file is legitimately owned by that user or by root.
		ownerOK = int(meta.UID) == 0 || namedUID(groups, user) // see note
	}
	return map[string]any{
		"path": p, "scope": scope, "user": user,
		"mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
		"group": groups[int(meta.GID)],
		"owner_ok":       ownerOK,
		"group_writable": meta.Mode&0o020 != 0,
		"other_writable": meta.Mode&0o002 != 0,
	}, true
}
```

**owner_ok-for-a-user-spool ruling (state in the report):** a per-user spool file (`/var/spool/cron/crontabs/alice`) is correctly owned by `alice` or by `root`. muster does not have `alice`'s uid from `/etc/group` (that is `/etc/passwd`), and the cron collector does not read `/etc/passwd`. Rather than add a passwd read, treat `owner_ok` for a user spool as `uid == 0 || uid == <the file's own uid> matches a non-system uid` is unknowable here; **the simplest correct rule is `owner_ok = (uid == 0) || (the file's owner name via groups is empty AND uid >= 1000)`** — no: implement it as `owner_ok = uid == 0 || uid >= 1000` (a spool file owned by any real user is acceptable; a spool file owned by another *system* account is the anomaly U-37 cares about). Replace the `namedUID` placeholder above with `int(meta.UID) >= 1000`. Do not add a passwd read for this.

```go
func cronDirRows(a collect.Access, groups map[int]string) facts.Envelope {
	rows := []any{}
	for _, d := range cronDirs {
		meta, err := a.Stat(d)
		if err != nil {
			continue // a dir that is not there is not a finding; a denied one is caught by its glob above
		}
		rows = append(rows, map[string]any{
			"path": d, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group": groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		})
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: "/etc/cron.d"})
}

// cronTimers is a best-effort systemd timer inventory. A systemctl that could
// not run makes this the command's error (never a clean empty list), so the
// absence of timers cannot be confused with an unreadable systemd.
func cronTimers(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, cronTimersCmd)
	src := out.Source(cronTimersCmd)
	if out.Err != nil || out.TimedOut || out.ExitCode != 0 {
		e := commandFailure("systemctl list-unit-files --type=timer", out, src, false)
		return e
	}
	rows := []any{}
	for _, line := range splitLines(out.Stdout) {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasSuffix(f[0], ".timer") {
			rows = append(rows, map[string]any{"name": f[0], "state": f[1]})
		}
	}
	return withTruncation(collect.OK(rows, src), out.Truncated)
}
```

Add imports `errors`, `io/fs` (for the ENOENT check in `cronRow`). Reuse `readReason` (pam_parse.go), `commandFailure`/`withTruncation` (register.go), `systemctlPath`/`groupPath` (services.go/accounts).

- [ ] **Step 4: Run the config-files test — passes**

Run: `go test ./internal/collect/collectors/ -run TestCronConfigFiles -v` → PASS.

- [ ] **Step 5: The remaining cron tests**

```go
// A denied cron drop-in GLOB makes cron.files/dirs the read error, never an
// empty list (the vacuous-each hazard).
func TestCronDeniedGlobIsError(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats:   map[string]statResult{"/etc/crontab": {mode: 0o644, kind: "regular"}},
		globErr: os.ErrPermission}
	b := build(t, "cron", a)
	if e := env(t, b, "cron.files"); e.Status != facts.StatusDenied {
		t.Errorf("a denied glob must make cron.files denied, not []: %+v", e)
	}
}

// The systemd timer inventory parses the systemctl table; a systemctl failure
// is the command's error, not an empty list.
func TestCronTimersInventoryAndFailure(t *testing.T) {
	ok := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o644, kind: "regular"}},
		cmds:  map[string]cmdResult{"/usr/bin/systemctl list-unit-files --type=timer --no-legend --no-pager": {file: "systemctl_list_timers.txt"}},
	}
	rows := okList(t, build(t, "cron", ok), "cron.timers")
	if len(rows) == 0 || rows[0].(map[string]any)["name"] == "" {
		t.Fatalf("timers %v", rows)
	}
	bad := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o644, kind: "regular"}},
		cmds:  map[string]cmdResult{"/usr/bin/systemctl list-unit-files --type=timer --no-legend --no-pager": {exitCode: 1, stderr: "fail\n"}},
	}
	if e := env(t, build(t, "cron", bad), "cron.timers"); e.Status == facts.StatusOK {
		t.Errorf("a failed systemctl must not be an ok empty list: %+v", e)
	}
}

// A world-writable /etc/crontab is recorded group/other-writable so U-37 fails.
func TestCronWorldWritableCrontab(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/crontab": "crontab", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/crontab": {mode: 0o646, uid: 0, kind: "regular"}},
	}
	rows := okList(t, build(t, "cron", a), "cron.files")
	if rows[0].(map[string]any)["other_writable"] != true {
		t.Errorf("0646 crontab is other-writable: %v", rows[0])
	}
}
```

Fixture `systemctl_list_timers.txt`: two synthetic lines like `logrotate.timer enabled` / `fstrim.timer static`.

- [ ] **Step 6: Register the three keys and regenerate the golden**

Add to `registry.yaml` a `cron.*` block — all `since: 1`, `sensitivity: public`, `collector: cron`: `cron.files` (list<record>), `cron.dirs` (list<record>), `cron.timers` (list<record>). Descriptions one line each, own words. Regenerate: `go test ./internal/facts -run TestFactsSchemaGolden -update`, review (3 keys, no bump).

- [ ] **Step 7: Windows gates and commit**

```
gofmt -l internal/collect/collectors/cron.go
GOOS=linux GOARCH=amd64 go vet ./internal/collect/...
GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null
go test ./internal/facts/ -count=1
go run ./cmd/muster controls lint --references docs/reference
```
Then sync to the lab host and `bash lab-run.sh 'go test ./internal/collect/collectors/ -run TestCron -count=1'` (the real spool layout and the systemctl timer table).

```bash
git add internal/collect/collectors/cron.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/collect/collectors/register.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Add the cron collector: crontab, spool and at configuration plus the timer inventory"
```

---

### Task 2: Startup scripts, syslog/journald and inetd/xinetd permission facts

**Files:**
- Create: `internal/collect/collectors/files_startup.go`, tests in `collectors_test.go`
- Modify: `internal/collect/collectors/files.go` (`filesReads()` and a call from `runFiles`), `internal/facts/registry.yaml` (7 keys), golden
- Create fixtures: `initd_script`, `systemd_unit`, `rsyslog_conf`, `xinetd_fragment`

**Interfaces:**
- Consumes: `collect.Access` (`Stat`, `Glob`, `ReadFile`), `collect.Builder`, `facts.Source`, `collect.ErrSymlink`; `groupNames(a)`; `splitLines`, `readLimit`, `collect.OK`/`Absent`/`FromReadError`.
- Produces (all called from `runFiles` after the `/dev` block, before the `securetty` block):
  - `startupScripts(a, groups) facts.Envelope` → `files.startup_scripts`, and `startupDirs(a, groups) facts.Envelope` → `files.startup_dirs`.
  - `syslogConfigs(a, groups) facts.Envelope` → `files.syslog_configs`; `journaldConfigs(a, groups) facts.Envelope` → `files.journald_configs`.
  - `writeInetdPerm(b, a, groups)` → `files.etc_inetd_conf.*` (4 leaves), `files.etc_xinetd_conf.*` (2 leaves) + `files.xinetd_d` (list<record>).
  - `permRow(a, path string, groups map[int]string) (map[string]any, bool)` — a shared row builder: stat one path into `{path, mode, uid, gid, group, group_writable, other_writable, is_symlink}`; `ok=false` on ENOENT; a `collect.ErrSymlink` sets `is_symlink:true` with the other fields defaulted; any other stat error yields a row carrying `mode:-1` and a `reason` (a finding, never a silent skip).

- [ ] **Step 1: Write the failing test — startup scripts, symlink filtered**

```go
// startup_scripts lists SysV init scripts and systemd unit files with mode
// and is_symlink. An enabled-unit symlink (Stat returns ErrSymlink) is
// is_symlink:true so U-17 can filter it with `where is_symlink eq false`; a
// world-writable regular init script is other_writable:true so U-17 fails it.
func TestFilesStartupScripts(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/init.d/muster": "initd_script", "/etc/systemd/system/muster.service": "systemd_unit", "/etc/group": "group"},
		stats: map[string]statResult{
			"/etc/init.d/muster":                {mode: 0o755, uid: 0, gid: 0, kind: "regular"},
			"/etc/systemd/system/muster.service": {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
		},
		fails: map[string]error{"/etc/systemd/system/multi-user.target.wants/muster.service": collect.ErrSymlink},
	}
	// the wants-symlink is discoverable via Glob of /etc/systemd/system/*/*
	a.files["/etc/systemd/system/multi-user.target.wants/muster.service"] = "" // present for Glob
	rows := okList(t, build(t, "files", a), "files.startup_scripts")
	byPath := map[string]map[string]any{}
	for _, r := range rows { m := r.(map[string]any); byPath[m["path"].(string)] = m }
	if byPath["/etc/init.d/muster"]["other_writable"] != false || byPath["/etc/init.d/muster"]["is_symlink"] != false {
		t.Errorf("regular init script %v", byPath["/etc/init.d/muster"])
	}
	if byPath["/etc/systemd/system/multi-user.target.wants/muster.service"]["is_symlink"] != true {
		t.Errorf("an enabled-unit symlink must be is_symlink:true: %v", byPath["/etc/systemd/system/multi-user.target.wants/muster.service"])
	}
}
```

Fixtures: `initd_script` (a `#!/bin/sh` + a comment line), `systemd_unit` (a `[Unit]`/`[Service]` stub), reuse `group`.

- [ ] **Step 2: Run it — FAIL (`files.startup_scripts` not present).**

Run: `go test ./internal/collect/collectors/ -run TestFilesStartupScripts -v`

- [ ] **Step 3: Implement `files_startup.go`**

```go
//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"sort"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var (
	// SysV scripts: /etc/init.d is a symlink to /etc/rc.d/init.d on the RHEL
	// family, so both roots are globbed; a run enumerates whichever resolves.
	startupScriptGlobs = []string{
		"/etc/init.d/*", "/etc/rc.d/init.d/*",
		"/etc/systemd/system/*", "/etc/systemd/system/*/*",
		"/etc/rc0.d/*", "/etc/rc1.d/*", "/etc/rc2.d/*", "/etc/rc3.d/*",
		"/etc/rc4.d/*", "/etc/rc5.d/*", "/etc/rc6.d/*",
	}
	startupDirList = []string{
		"/etc/init.d", "/etc/rc.d/init.d", "/etc/systemd/system",
		"/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d",
		"/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d",
	}
	syslogConfGlobs   = []string{"/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf", "/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng/conf.d/*.conf"}
	journaldConfGlobs = []string{"/etc/systemd/journald.conf", "/etc/systemd/journald.conf.d/*.conf"}
	xinetdConfPath    = "/etc/xinetd.conf"
	inetdConfPath     = "/etc/inetd.conf"
	xinetdDGlob       = "/etc/xinetd.d/*"
)

// permRow stats one path into a permission row. ok is false only on ENOENT.
// A final-component symlink (Stat returns ErrSymlink) is is_symlink:true with
// the numeric fields defaulted (the link's own perms do not matter — its
// target is judged where it lives). Any other stat error yields a row with
// mode -1 and a reason, so a denied path is a finding, not a silent skip.
func permRow(a collect.Access, p string, groups map[int]string) (map[string]any, bool) {
	rec := map[string]any{
		"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
		"group_writable": false, "other_writable": false, "is_symlink": false,
	}
	meta, err := a.Stat(p)
	switch {
	case err == nil:
		rec["mode"], rec["uid"], rec["gid"] = int(meta.Mode), int(meta.UID), int(meta.GID)
		rec["group"] = groups[int(meta.GID)]
		rec["group_writable"] = meta.Mode&0o020 != 0
		rec["other_writable"] = meta.Mode&0o002 != 0
	case errors.Is(err, collect.ErrSymlink):
		rec["is_symlink"] = true
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	default:
		rec["reason"] = readReason(p, err)
	}
	return rec, true
}

// globRows stats every match of each glob (sorted, deduplicated) into a
// permission row. A glob that FAILS makes the whole fact the read error
// (never a partial/empty list — the vacuous-each hazard, §7.3).
func globRows(a collect.Access, globs []string, groups map[int]string, src *facts.Source) facts.Envelope {
	seen := map[string]bool{}
	var paths []string
	for _, g := range globs {
		m, err := a.Glob(g)
		if err != nil {
			return collect.FromReadError(err, collect.ReadMeta{})
		}
		for _, p := range m {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)
	rows := []any{}
	for _, p := range paths {
		if row, ok := permRow(a, p, groups); ok {
			rows = append(rows, row)
		}
	}
	return collect.OK(rows, src)
}

func startupScripts(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, startupScriptGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/systemd/system"})
}

func startupDirs(a collect.Access, groups map[int]string) facts.Envelope {
	rows := []any{}
	for _, d := range startupDirList {
		if row, ok := permRow(a, d, groups); ok {
			rows = append(rows, row)
		}
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: "/etc/init.d"})
}

func syslogConfigs(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, syslogConfGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/rsyslog.conf"})
}

func journaldConfigs(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, journaldConfGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/systemd/journald.conf"})
}
```

The inetd/xinetd facts:

```go
// writeInetdPerm publishes the inetd/xinetd permission facts. inetd.conf and
// xinetd.conf are fixed paths; xinetd_d is the per-fragment rows. All are
// absent on both stock families, which is a definite state, not an error.
func writeInetdPerm(b *collect.Builder, a collect.Access, groups map[int]string) {
	// /etc/inetd.conf: mode, uid, group_writable, other_readable.
	if meta, err := a.Stat(inetdConfPath); err == nil {
		b.Set("files.etc_inetd_conf.mode", collect.OK(int(meta.Mode), permSrc(inetdConfPath)))
		b.Set("files.etc_inetd_conf.uid", collect.OK(int(meta.UID), permSrc(inetdConfPath)))
		b.Set("files.etc_inetd_conf.group_writable", collect.OK(meta.Mode&0o020 != 0, permSrc(inetdConfPath)))
		b.Set("files.etc_inetd_conf.other_readable", collect.OK(meta.Mode&0o004 != 0, permSrc(inetdConfPath)))
	} else {
		e := statAbsentOrError(inetdConfPath, err)
		for _, k := range []string{"mode", "uid", "group_writable", "other_readable"} {
			b.Set("files.etc_inetd_conf."+k, e)
		}
	}
	// /etc/xinetd.conf: mode, uid.
	if meta, err := a.Stat(xinetdConfPath); err == nil {
		b.Set("files.etc_xinetd_conf.mode", collect.OK(int(meta.Mode), permSrc(xinetdConfPath)))
		b.Set("files.etc_xinetd_conf.uid", collect.OK(int(meta.UID), permSrc(xinetdConfPath)))
	} else {
		e := statAbsentOrError(xinetdConfPath, err)
		b.Set("files.etc_xinetd_conf.mode", e)
		b.Set("files.etc_xinetd_conf.uid", e)
	}
	b.Set("files.xinetd_d", globRows(a, []string{xinetdDGlob}, groups, &facts.Source{Kind: "file", Path: "/etc/xinetd.d"}))
}

func permSrc(p string) *facts.Source { return &facts.Source{Kind: "sys", Path: p} }

// statAbsentOrError maps a stat error to absent (ENOENT — a definite "not
// configured") or the read error (anything else).
func statAbsentOrError(p string, err error) facts.Envelope {
	if errors.Is(err, fs.ErrNotExist) {
		return collect.Absent(p + " does not exist")
	}
	return collect.FromReadError(err, collect.ReadMeta{})
}
```

- [ ] **Step 4: Wire into `runFiles` and extend `filesReads()`**

In `files.go`, add to `filesReads()`: `startupScriptGlobs...`, `startupDirList...`, `syslogConfGlobs...`, `journaldConfGlobs...`, `inetdConfPath`, `xinetdConfPath`, `xinetdDGlob`. In `runFiles`, after the `/dev` block and before the `securetty` block:

```go
	b.Set("files.startup_scripts", startupScripts(a, groups))
	b.Set("files.startup_dirs", startupDirs(a, groups))
	b.Set("files.syslog_configs", syslogConfigs(a, groups))
	b.Set("files.journald_configs", journaldConfigs(a, groups))
	writeInetdPerm(b, a, groups)
```

- [ ] **Step 5: The remaining Task-2 tests**

```go
// A denied startup glob makes files.startup_scripts the read error, not [].
func TestFilesStartupDeniedGlobIsError(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}, globErr: os.ErrPermission}
	if e := env(t, build(t, "files", a), "files.startup_scripts"); e.Status != facts.StatusDenied {
		t.Errorf("denied glob → denied, not []: %+v", e)
	}
}

// syslog config rows are recorded; a world-writable rsyslog.conf is flagged.
func TestFilesSyslogConfigs(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/rsyslog.conf": "rsyslog_conf", "/etc/group": "group"},
		stats: map[string]statResult{"/etc/rsyslog.conf": {mode: 0o646, uid: 0, kind: "regular"}},
	}
	rows := okList(t, build(t, "files", a), "files.syslog_configs")
	if len(rows) != 1 || rows[0].(map[string]any)["other_writable"] != true {
		t.Fatalf("syslog rows %v", rows)
	}
}

// inetd/xinetd are absent on a stock host: the fixed leaves are absent, the
// fragment list an ok empty list.
func TestFilesInetdAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	b := build(t, "files", a)
	if e := env(t, b, "files.etc_inetd_conf.mode"); e.Status != facts.StatusAbsent {
		t.Errorf("absent inetd.conf → absent leaf: %+v", e)
	}
	if l := okList(t, b, "files.xinetd_d"); len(l) != 0 {
		t.Errorf("no xinetd.d fragments → ok empty list, got %v", l)
	}
}
```

Fixture `rsyslog_conf` (a couple of synthetic rules), `xinetd_fragment`.

- [ ] **Step 6: Register the seven keys, regenerate the golden**

`files.startup_scripts`, `files.startup_dirs`, `files.syslog_configs`, `files.journald_configs` (list<record>); `files.etc_inetd_conf.{mode,uid,group_writable,other_readable}` (int×2,bool×2); `files.etc_xinetd_conf.{mode,uid}` (int×2) + `files.xinetd_d` (list<record>). All `since: 1`, `sensitivity: public`, `collector: files`. Regenerate + review.

- [ ] **Step 7: Windows gates + lab host, commit**

Windows gates as in Task 1; then `bash lab-run.sh 'go test ./internal/collect/collectors/ -run "TestFilesStartup|TestFilesSyslog|TestFilesInetd" -count=1'` (the real `/etc/systemd/system` tree with its `.wants` symlinks). Commit:

```bash
git add internal/collect/collectors/files_startup.go internal/collect/collectors/files.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Collect startup-script, syslog/journald and inetd/xinetd permission facts"
```

---

### Task 3: sudoers, the sudo.* keys and the /var/log tree

**Files:**
- Create: `internal/collect/collectors/files_sudo.go`, tests in `collectors_test.go`
- Modify: `internal/collect/collectors/files.go` (`filesReads()` and `runFiles`), `internal/facts/registry.yaml` (10 keys), golden
- Create fixtures: `sudoers`, `sudoers_d_entry`, `varlog_tree` (exercised via `dirs`/`stats`)

**Interfaces:**
- Consumes: `collect.Access`, `collect.Builder`, `facts.Source`; `groupNames(a)`; `splitLines`, `readLimit`, `collect.OK`/`Absent`/`FromReadError`; the `permSrc`/`statAbsentOrError` helpers from Task 2.
- Produces (called from `runFiles`):
  - `sudoersFacts(b, a, groups)` → `files.etc_sudoers.{mode,uid,gid,acl_present}`, `files.etc_sudoers_d.{mode,uid,gid,acl_present}`, `files.sudoers_d_entries` (list<record>), and `sudo.{installed,includedir,secure_path}`.
  - `logTree(a, groups) (dirs, files facts.Envelope)` → `files.log_dirs`, `files.log_files`.

**Ruling folded here (state in the report):** the `/var/log` rows carry `group` (name) and `group_writable`/`other_writable` — the collector does NOT precompute a `group_writable_unexpected` flag. U-67 owns the log-group allowlist as a `params` value and judges `each where {group_writable} require {group in allowed}`, so the policy stays in the control (D09), not the collector, and no compound-`where` is needed.

- [ ] **Step 1: Write the failing test — sudoers perms, drop-ins, and sudo.***

```go
// sudoers permission facts come from stat (works non-root); sudo.includedir
// and secure_path are parsed from /etc/sudoers content (root-only read). A
// drop-in ending in ~ or containing . is ignored:true (sudo skips it).
func TestFilesSudoers(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/sudoers": "sudoers", "/etc/sudoers.d/muster": "sudoers_d_entry", "/etc/group": "group"},
		stats: map[string]statResult{
			"/etc/sudoers":          {mode: 0o440, uid: 0, gid: 0, kind: "regular"},
			"/etc/sudoers.d":        {mode: 0o750, uid: 0, gid: 0, kind: "dir"},
			"/etc/sudoers.d/muster": {mode: 0o440, uid: 0, gid: 0, kind: "regular"},
		},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_sudoers.mode").Value != 0o440 || env(t, b, "files.etc_sudoers.uid").Value != 0 {
		t.Errorf("sudoers perms %+v", env(t, b, "files.etc_sudoers.mode"))
	}
	if env(t, b, "sudo.installed").Value != true {
		t.Error("sudo.installed")
	}
	if env(t, b, "sudo.secure_path").Value != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("secure_path %+v", env(t, b, "sudo.secure_path"))
	}
	rows := okList(t, b, "files.sudoers_d_entries")
	if len(rows) != 1 || rows[0].(map[string]any)["ignored"] != false {
		t.Fatalf("drop-in rows %v", rows)
	}
}
```

Fixtures: `sudoers` (synthetic: a comment, `Defaults secure_path="/usr/sbin:/usr/bin:/sbin:/bin"`, `@includedir /etc/sudoers.d`, `root ALL=(ALL:ALL) ALL`), `sudoers_d_entry` (a `%group ALL=…` line).

- [ ] **Step 2: Run it — FAIL (`files.etc_sudoers.mode` not present).**

Run: `go test ./internal/collect/collectors/ -run TestFilesSudoers -v`

- [ ] **Step 3: Implement `files_sudo.go`**

```go
//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	sudoersPath  = "/etc/sudoers"
	sudoersDDir  = "/etc/sudoers.d"
	sudoersDGlob = "/etc/sudoers.d/*"
	varLogDir    = "/var/log"
	varLogGlob1  = "/var/log/*"
	varLogGlob2  = "/var/log/*/*"
	logMaxEntries = 4096
)

// sudoersFacts writes the sudoers permission facts (stat only), the drop-in
// entries, and the sudo.* derived keys parsed from /etc/sudoers content.
func sudoersFacts(b *collect.Builder, a collect.Access, groups map[int]string) {
	// Permission facts of /etc/sudoers (stat; works without reading it).
	if meta, err := a.Stat(sudoersPath); err == nil {
		b.Set("files.etc_sudoers.mode", collect.OK(int(meta.Mode), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.uid", collect.OK(int(meta.UID), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.gid", collect.OK(int(meta.GID), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.acl_present", aclPresent(a, sudoersPath))
	} else {
		e := statAbsentOrError(sudoersPath, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers."+k, e)
		}
	}
	// The drop-in directory and its entries.
	if meta, err := a.Stat(sudoersDDir); err == nil {
		b.Set("files.etc_sudoers_d.mode", collect.OK(int(meta.Mode), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.uid", collect.OK(int(meta.UID), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.gid", collect.OK(int(meta.GID), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.acl_present", aclPresent(a, sudoersDDir))
	} else {
		e := statAbsentOrError(sudoersDDir, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers_d."+k, e)
		}
	}
	b.Set("files.sudoers_d_entries", sudoersDropIns(a, groups))
	// sudo.* derived from reading /etc/sudoers (root-only). A non-root run
	// gets a denied read → the three sudo.* keys carry that status.
	writeSudoDerived(b, a)
}

// sudoersDropIns lists /etc/sudoers.d entries. sudo ignores a name ending in
// ~ or containing a "." (a backup or dotted file), recorded as ignored:true
// so the control skips it.
func sudoersDropIns(a collect.Access, groups map[int]string) facts.Envelope {
	matches, err := a.Glob(sudoersDGlob)
	if err != nil {
		return collect.FromReadError(err, collect.ReadMeta{})
	}
	sort.Strings(matches)
	rows := []any{}
	for _, p := range matches {
		row, ok := permRow(a, p, groups)
		if !ok {
			continue
		}
		base := path.Base(p)
		row["ignored"] = strings.HasSuffix(base, "~") || strings.Contains(base, ".")
		rows = append(rows, row)
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: sudoersDDir})
}

// writeSudoDerived parses /etc/sudoers for the @includedir directory and the
// Defaults secure_path. installed is whether /etc/sudoers exists at all.
func writeSudoDerived(b *collect.Builder, a collect.Access) {
	data, meta, err := a.ReadFile(sudoersPath, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			src := &facts.Source{Kind: "derived"}
			b.Set("sudo.installed", collect.OK(false, src))
			b.Set("sudo.includedir", collect.OK("", src))
			b.Set("sudo.secure_path", collect.OK("", src))
			return
		}
		e := readErrorEnv(sudoersPath, err) // path-prefixed (C3)
		b.Set("sudo.installed", collect.OK(true, permSrc(sudoersPath))) // the file exists; we just cannot read it
		b.Set("sudo.includedir", e)
		b.Set("sudo.secure_path", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: sudoersPath}
	includedir, securePath := "", ""
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "@includedir") || strings.HasPrefix(line, "#includedir") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				includedir = f[1]
			}
		}
		if strings.HasPrefix(line, "Defaults") && strings.Contains(line, "secure_path") {
			if _, v, ok := strings.Cut(line, "secure_path="); ok {
				securePath = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	_ = meta
	b.Set("sudo.installed", collect.OK(true, src))
	b.Set("sudo.includedir", collect.OK(includedir, src))
	b.Set("sudo.secure_path", collect.OK(securePath, src))
}
```

`aclPresent` — reuse the existing ACL helper the 2A permfacts uses (it reads the `system.posix_acl_access` xattr via `Getxattr`); if a standalone `aclPresent(a, path) facts.Envelope` does not already exist, factor the check `writePermFacts` already performs into one, or set `acl_present` from `a.Llistxattr(path)` containing `system.posix_acl_access`. Read `permfacts.go` first and reuse its exact mechanism so the two agree.

The `/var/log` tree:

```go
// logTree walks /var/log one and two levels deep (bounded), recording each
// entry's group name and the group/other-writable flags. U-67 owns the
// allowed-group policy, so no "unexpected" flag is precomputed here (D09).
func logTree(a collect.Access, groups map[int]string) (facts.Envelope, facts.Envelope) {
	var paths []string
	for _, g := range []string{varLogGlob1, varLogGlob2} {
		m, err := a.Glob(g)
		if err != nil {
			e := collect.FromReadError(err, collect.ReadMeta{})
			return e, e
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	truncated := false
	if len(paths) > logMaxEntries {
		paths = paths[:logMaxEntries]
		truncated = true
	}
	dirs, files := []any{}, []any{}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if err != nil {
			// a symlink or unreadable entry: record it as a finding row so a
			// denied log path is visible, never silently dropped.
			row := map[string]any{"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
				"group_writable": false, "other_writable": false, "reason": readReason(p, err)}
			files = append(files, row)
			continue
		}
		row := map[string]any{
			"path": p, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group": groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		}
		if meta.Kind == "dir" {
			dirs = append(dirs, row)
		} else {
			files = append(files, row)
		}
	}
	src := &facts.Source{Kind: "file", Path: varLogDir}
	de := withTruncation(collect.OK(dirs, src), truncated)
	fe := withTruncation(collect.OK(files, src), truncated)
	return de, fe
}
```

- [ ] **Step 4: Wire into `runFiles` and `filesReads()`**

`filesReads()` gains `sudoersPath`, `sudoersDDir`, `sudoersDGlob`, `varLogDir`, `varLogGlob1`, `varLogGlob2`. In `runFiles`, after the Task-2 block:

```go
	sudoersFacts(b, a, groups)
	ld, lf := logTree(a, groups)
	b.Set("files.log_dirs", ld)
	b.Set("files.log_files", lf)
```

- [ ] **Step 5: The remaining Task-3 tests**

```go
// A non-root run cannot read /etc/sudoers: sudo.secure_path is denied, but
// the stat-based perm facts and sudo.installed still succeed.
func TestFilesSudoersDeniedRead(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/sudoers": os.ErrPermission},
		stats: map[string]statResult{"/etc/sudoers": {mode: 0o440, uid: 0, kind: "regular"}},
		files: map[string]string{"/etc/group": "group"},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_sudoers.mode").Value != 0o440 {
		t.Errorf("stat still works: %+v", env(t, b, "files.etc_sudoers.mode"))
	}
	if e := env(t, b, "sudo.secure_path"); e.Status != facts.StatusDenied {
		t.Errorf("a denied read → denied secure_path: %+v", e)
	}
}

// /var/log rows carry the group name and writable flags; a denied log glob is
// the read error, not an empty list.
func TestFilesLogTree(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		dirs:  map[string]bool{"/var/log": true, "/var/log/journal": true},
		stats: map[string]statResult{
			"/var/log":          {mode: 0o755, uid: 0, gid: 0, kind: "dir"},
			"/var/log/journal":  {mode: 0o2755, uid: 0, gid: 4, kind: "dir"}, // gid 4 = adm in the group fixture
			"/var/log/syslog":   {mode: 0o640, uid: 104, gid: 4, kind: "regular"},
		},
	}
	a.files["/var/log/syslog"] = "" // present for Glob
	b := build(t, "files", a)
	ld := okList(t, b, "files.log_dirs")
	if len(ld) < 1 {
		t.Fatalf("log_dirs %v", ld)
	}
	denied := &fsAccess{files: map[string]string{"/etc/group": "group"}, globErr: os.ErrPermission}
	if e := env(t, build(t, "files", denied), "files.log_dirs"); e.Status != facts.StatusDenied {
		t.Errorf("denied /var/log glob → denied, not []: %+v", e)
	}
}
```

Ensure the `group` fixture maps gid 4 → `adm` and gid 104 → `syslog` (adjust the fixture or the test's gids to match the committed `group` fixture).

- [ ] **Step 6: Register the ten keys, regenerate the golden**

`files.etc_sudoers.{mode,uid,gid,acl_present}`, `files.etc_sudoers_d.{mode,uid,gid,acl_present}`, `files.sudoers_d_entries` (list<record>), `files.log_dirs`, `files.log_files` (list<record>) — all `collector: files`; `sudo.installed` (bool), `sudo.includedir` (string), `sudo.secure_path` (string) — `collector: files`. All `since: 1`, `sensitivity: public`. Regenerate + review.

- [ ] **Step 7: Windows gates + lab host, commit**

Windows gates; then `bash lab-run.sh 'go test ./internal/collect/collectors/ -run "TestFilesSudoers|TestFilesLogTree" -count=1'` and `bash lab-run.sh 'go test ./internal/collect/... -count=1'` (the real /etc/sudoers stat, the sudoers.d drop-ins, and the /var/log tree with its adm/syslog groups). Commit:

```bash
git add internal/collect/collectors/files_sudo.go internal/collect/collectors/files.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Collect sudoers permission facts, the sudo.* keys and the /var/log tree"
```

---

### Task 4: The startup, syslog and inetd controls (U-17, U-21, U-20)

**Files:**
- Create: `controls/file/startup_script_permissions.yaml` (U-17), `controls/file/syslog_conf_permissions.yaml` (U-21), `controls/file/inetd_conf_permissions.yaml` (U-20) + fixture directories
- Modify: `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go` (`29` → `32`), `docs/reference/coverage.md`

**Interfaces:**
- Consumes: `files.startup_scripts`/`startup_dirs`, `files.syslog_configs`, `files.etc_inetd_conf.*`/`etc_xinetd_conf.*`/`xinetd_d` (T2).
- Produces: three controls; count reaches 32; the e2e snapshots carry the three controls' facts (per the L10 reorder — bump the count and coverage in THIS commit so `cmd/muster` stays green).

- [ ] **Step 1: Write the three controls**

`controls/file/startup_script_permissions.yaml` (U-17):
```yaml
id: muster.file.startup_script_permissions
title_en: System startup scripts are not writable by group or others
title_ko: 시스템 시작 스크립트가 그룹·기타 사용자에게 쓰기 불가능하다
description_en: Every SysV init script and systemd unit file under the startup directories must be owned by root and not group- or world-writable, so no other user can alter what runs at boot. Enabled-unit symlinks are not judged (their target is judged where it lives); a startup file muster could not stat is reported. A world-writable startup script is a direct root-code-execution path.
description_ko: 시작 디렉터리 아래의 모든 SysV init 스크립트와 systemd 유닛 파일은 root 소유여야 하고 그룹·전체 쓰기가 가능하면 안 되어, 다른 사용자가 부팅 시 실행되는 것을 바꿀 수 없어야 합니다. 활성화된 유닛 심볼릭 링크는 판정하지 않으며(대상 파일은 그 위치에서 판정), stat 할 수 없었던 시작 파일은 보고합니다. 전체 쓰기 가능한 시작 스크립트는 곧바로 root 코드 실행 경로가 됩니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-17"], "2021": ["U-14"] }
requires_facts: ">=1"
absent_means: manual
checks:
  - { fact: files.startup_scripts, op: each, subject: path, where: { field: is_symlink, op: eq, expected: false }, require: { field: group_writable, op: eq, expected: false } }
  - { fact: files.startup_scripts, op: each, subject: path, where: { field: is_symlink, op: eq, expected: false }, require: { field: other_writable, op: eq, expected: false } }
  - { fact: files.startup_scripts, op: none, where: { field: mode, op: eq, expected: -1 } }
  - { fact: files.startup_dirs, op: none, where: { field: other_writable, op: eq, expected: true } }
remediation:
  text_en: chmod go-w each group- or world-writable startup script and its directory, and chown them to root; investigate any startup file that could not be read.
  text_ko: 그룹·전체 쓰기 가능한 시작 스크립트와 그 디렉터리에 chmod go-w 를 적용하고 root 로 chown 하며, 읽을 수 없었던 시작 파일은 조사합니다.
  risk: none
  idempotent: true
```

`controls/file/syslog_conf_permissions.yaml` (U-21):
```yaml
id: muster.file.syslog_conf_permissions
title_en: The syslog configuration is 0640 or stricter and owned by root
title_ko: syslog 설정이 0640 이하로 엄격하며 root 소유이다
description_en: The rsyslog/syslog-ng configuration files must be mode 0640 or stricter and owned by root, so no other user can read or redirect the logging pipeline. Both distribution families ship /etc/rsyslog.conf at 0644, so a stock host fails this by the guide's 0640 criterion until an operator tightens it (params.allowed_modes relaxes the threshold where local policy differs).
description_ko: rsyslog/syslog-ng 설정 파일은 mode 0640 이하로 엄격하고 root 소유여야, 다른 사용자가 로깅 파이프라인을 읽거나 바꿀 수 없습니다. 두 배포판 계열 모두 /etc/rsyslog.conf 를 0644 로 배포하므로, 운영자가 조일 때까지 가이드의 0640 기준으로는 기본 설치가 실패합니다(로컬 정책이 다르면 params.allowed_modes 로 기준을 완화).
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-21"], "2021": ["U-11"] }
requires_facts: ">=1"
absent_means: manual
params:
  allowed_modes: { type: list<int>, default: [0, 32, 128, 160, 256, 288, 384, 416], description: syslog config modes at 0640 or stricter (bit-subsets of 0640) }
checks:
  - { fact: files.syslog_configs, op: each, subject: path, where: { field: mode, op: ne, expected: -1 }, require: { field: mode, op: in, expected: "${allowed_modes}" } }
  - { fact: files.syslog_configs, op: each, subject: path, where: { field: mode, op: ne, expected: -1 }, require: { field: uid, op: eq, expected: 0 } }
  - { fact: files.syslog_configs, op: none, where: { field: mode, op: eq, expected: -1 } }
remediation:
  text_en: chmod 0640 /etc/rsyslog.conf and the files under /etc/rsyslog.d, and chown them to root; investigate any config that could not be read.
  text_ko: /etc/rsyslog.conf 와 /etc/rsyslog.d 아래 파일에 chmod 0640 을 적용하고 root 로 chown 하며, 읽을 수 없었던 설정은 조사합니다.
  risk: none
  idempotent: true
```

`controls/file/inetd_conf_permissions.yaml` (U-20):
```yaml
id: muster.file.inetd_conf_permissions
title_en: The inetd/xinetd configuration is owned by root and not exposed
title_ko: inetd/xinetd 설정이 root 소유이며 노출되지 않는다
description_en: Where an inetd or xinetd super-server is configured, /etc/inetd.conf must not be group-writable or world-readable, and /etc/xinetd.conf and its fragments must be mode 0600 or stricter and not writable by others. Neither super-server is installed on a stock Ubuntu or Rocky host, so the control passes by default and only judges a host that actually runs one.
description_ko: inetd 또는 xinetd 슈퍼서버가 설정된 경우 /etc/inetd.conf 는 그룹 쓰기·전체 읽기가 가능하면 안 되고, /etc/xinetd.conf 와 그 조각은 mode 0600 이하로 엄격하며 타인이 쓸 수 없어야 합니다. 기본 Ubuntu·Rocky 에는 두 슈퍼서버 모두 설치되지 않으므로 기본적으로 통과하고, 실제로 슈퍼서버를 쓰는 호스트만 판정합니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-20"], "2021": ["U-10"] }
requires_facts: ">=1"
absent_means: pass
params:
  allowed_modes: { type: list<int>, default: [0, 128, 256, 384], description: config modes at 0600 or stricter (bit-subsets of 0600) }
mechanisms:
  - when:
      - { fact: files.etc_inetd_conf.mode, op: present }
    checks:
      - { fact: files.etc_inetd_conf.group_writable, op: eq, expected: false }
      - { fact: files.etc_inetd_conf.other_readable, op: eq, expected: false }
  - when:
      - { fact: files.etc_xinetd_conf.mode, op: present }
    checks:
      - { fact: files.etc_xinetd_conf.mode, op: in, expected: "${allowed_modes}" }
      - { fact: files.etc_xinetd_conf.uid, op: eq, expected: 0 }
      - { fact: files.xinetd_d, op: none, where: { field: other_writable, op: eq, expected: true } }
      - { fact: files.xinetd_d, op: none, where: { field: group_writable, op: eq, expected: true } }
remediation:
  text_en: chmod 0600 /etc/inetd.conf or /etc/xinetd.conf and its fragments, chown them to root, and prefer removing the super-server if no service needs it.
  text_ko: /etc/inetd.conf 또는 /etc/xinetd.conf 와 그 조각에 chmod 0600 을 적용하고 root 로 chown 하며, 필요한 서비스가 없으면 슈퍼서버 제거를 우선합니다.
  risk: none
  idempotent: true
```

- [ ] **Step 2: Fixtures**

`startup_script_permissions/`: `pass-clean.json` (startup_scripts two rows: one is_symlink true skipped, one regular not writable; startup_dirs not other-writable → PASS), `fail-world-writable.json` (a non-symlink script other_writable true → FAIL), `fail-denied.json` (a row mode -1 → FAIL via the none-mode-eq-minus1 clause), `manual-absent.json` (`files.startup_scripts` absent → MANUAL).
`syslog_conf_permissions/`: `pass-0640.json` (one row mode 416=0640, uid 0 → PASS), `fail-0644.json` (mode 420=0644 → FAIL, the stock case), `fail-not-root.json` (uid 100 → FAIL), `manual-absent.json`.
`inetd_conf_permissions/`: `pass-absent.json` (`etc_inetd_conf.mode` absent AND `etc_xinetd_conf.mode` absent → absent_means pass), `pass-xinetd-clean.json` (etc_xinetd_conf.mode 384=0600 uid 0, xinetd_d rows not writable → PASS via mechanism 2), `fail-inetd-world-readable.json` (etc_inetd_conf.mode present, other_readable true → FAIL via mechanism 1), `fail-xinetd-fragment-writable.json` (a xinetd_d row other_writable true → FAIL). Every fixture carries only the leaves its mechanism reads.

- [ ] **Step 3: e2e, counts, coverage (L10 — keep cmd/muster green in this commit)**

Add to `full-pass.json` and `full-fail.json` under `facts.files`: `startup_scripts` (a clean row + a symlink row), `startup_dirs` (clean), `syslog_configs` (a mode 0640 uid 0 row — so U-21 PASSes), `etc_inetd_conf`/`etc_xinetd_conf` absent + `xinetd_d` `[]` (so U-20 passes via absent_means). All three controls PASS in both snapshots (full-fail keeps root_remote_login as its only FAIL). `cmd/muster/controls_test.go`: both `"ok: 29 controls"` → `"ok: 32 controls"`. `e2e_test.go`: add the three controls to both maps as PASS. `docs/reference/coverage.md`: `go run ./tools/coverage`; `-check` exit 0 (U-17, U-20, U-21 enrolled, 32 items).

- [ ] **Step 4: Lint, behaviour test, commit**

```
go run ./cmd/muster controls lint --references docs/reference   # ok: 32 controls
go run ./cmd/muster controls lint --fixtures controls/testdata  # ok: 32 controls
go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1
go test ./internal/check/ ./internal/controls/ ./cmd/muster/ -count=1
go run ./tools/coverage -check
```

```bash
git add controls/file/startup_script_permissions.yaml controls/file/syslog_conf_permissions.yaml controls/file/inetd_conf_permissions.yaml controls/testdata cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md
git commit -m "Add the startup-script, syslog and inetd permission controls"
```

---

### Task 5: The cron, sudoers and log-directory controls (U-37, U-63, U-67)

**Files:**
- Create: `controls/account/cron_permissions.yaml` (U-37), `controls/account/sudoers_permissions.yaml` (U-63), `controls/file/log_dir_permissions.yaml` (U-67) + fixtures
- Modify: `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go` (`32` → `35`), `docs/reference/coverage.md`

**Interfaces:**
- Consumes: `cron.files`/`cron.dirs` (T1), `files.etc_sudoers.*`/`sudoers_d_entries`/`sudo.installed` (T3), `files.log_dirs`/`log_files` (T3).
- Produces: three controls; count reaches 35.

- [ ] **Step 1: Write the three controls**

`controls/account/cron_permissions.yaml` (U-37):
```yaml
id: muster.account.cron_permissions
title_en: Cron configuration files are 0640 or stricter and owned appropriately
title_ko: cron 설정 파일이 0640 이하로 엄격하며 소유가 적절하다
description_en: Every crontab and cron drop-in must be mode 0640 or stricter, must not be group- or world-writable, and a system or access file must be owned by root; the cron directories must not be world-writable. Both distribution families ship /etc/crontab and /etc/cron.d at 0644, so a stock host fails this by the guide's 0640 criterion until an operator tightens it. A file muster could not stat is reported rather than skipped.
description_ko: 모든 crontab 과 cron 드롭인은 mode 0640 이하로 엄격하고 그룹·전체 쓰기가 가능하면 안 되며, 시스템·접근 제어 파일은 root 소유여야 하고, cron 디렉터리는 전체 쓰기가 가능하면 안 됩니다. 두 배포판 계열 모두 /etc/crontab 과 /etc/cron.d 를 0644 로 배포하므로 운영자가 조일 때까지 가이드의 0640 기준으로는 기본 설치가 실패합니다. stat 할 수 없었던 파일은 건너뛰지 않고 보고합니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-37"], "2021": ["U-22", "U-65"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232040 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232230 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232235 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
params:
  allowed_modes: { type: list<int>, default: [0, 32, 128, 160, 256, 288, 384, 416], description: cron file modes at 0640 or stricter (bit-subsets of 0640) }
checks:
  - { fact: cron.files, op: none, where: { field: mode, op: eq, expected: -1 } }
  - { fact: cron.files, op: each, subject: path, where: { field: mode, op: ne, expected: -1 }, require: { field: mode, op: in, expected: "${allowed_modes}" } }
  - { fact: cron.files, op: none, where: { field: other_writable, op: eq, expected: true } }
  - { fact: cron.files, op: each, subject: path, where: { field: scope, op: in, expected: ["system", "access"] }, require: { field: owner_ok, op: eq, expected: true } }
  - { fact: cron.dirs, op: none, where: { field: other_writable, op: eq, expected: true } }
remediation:
  text_en: chmod 0640 the crontab files and cron drop-ins, chown the system files to root, and chmod o-w the cron directories.
  text_ko: crontab 파일과 cron 드롭인에 chmod 0640 을 적용하고 시스템 파일을 root 로 chown 하며 cron 디렉터리에 chmod o-w 를 적용합니다.
  risk: none
  idempotent: true
```

`controls/account/sudoers_permissions.yaml` (U-63):
```yaml
id: muster.account.sudoers_permissions
title_en: sudoers and its drop-ins are 0440 and owned by root
title_ko: sudoers 와 드롭인이 0440 이며 root 소유이다
description_en: /etc/sudoers must be mode 0440 or stricter and owned by root, and every non-ignored file under /etc/sudoers.d must not be group- or world-writable, so no other user can grant themselves sudo. A drop-in sudo skips (a name ending in ~ or containing a dot) is not judged. The control applies only where sudo is installed; the effective secure_path is collected as evidence but not judged here.
description_ko: /etc/sudoers 는 mode 0440 이하로 엄격하고 root 소유여야 하며, /etc/sudoers.d 아래 무시되지 않는 모든 파일은 그룹·전체 쓰기가 가능하면 안 되어, 다른 사용자가 스스로 sudo 를 부여할 수 없어야 합니다. sudo 가 건너뛰는 드롭인(이름이 ~ 로 끝나거나 점을 포함)은 판정하지 않습니다. 이 컨트롤은 sudo 가 설치된 곳에만 적용하며, 유효 secure_path 는 근거로 수집하되 여기서 판정하지 않습니다.
category: account
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-63"], "2021": [] }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
applies_when:
  - { fact: sudo.installed, op: eq, expected: true }
absent_means: manual
params:
  allowed_modes: { type: list<int>, default: [0, 32, 256, 288], description: sudoers modes at 0440 or stricter (bit-subsets of 0440) }
checks:
  - { fact: files.etc_sudoers.mode, op: in, expected: "${allowed_modes}" }
  - { fact: files.etc_sudoers.uid, op: eq, expected: 0 }
  - { fact: files.sudoers_d_entries, op: each, subject: path, where: { field: ignored, op: eq, expected: false }, require: { field: other_writable, op: eq, expected: false } }
  - { fact: files.sudoers_d_entries, op: each, subject: path, where: { field: ignored, op: eq, expected: false }, require: { field: group_writable, op: eq, expected: false } }
remediation:
  text_en: chmod 0440 /etc/sudoers and chown it to root; chmod go-w each active file under /etc/sudoers.d.
  text_ko: /etc/sudoers 에 chmod 0440 을 적용하고 root 로 chown 하며, /etc/sudoers.d 아래 활성 파일에 chmod go-w 를 적용합니다.
  risk: none
  idempotent: true
```

`controls/file/log_dir_permissions.yaml` (U-67):
```yaml
id: muster.file.log_dir_permissions
title_en: Log directories and files are not writable beyond their owning group
title_ko: 로그 디렉터리·파일이 소유 그룹 밖에서 쓰기 불가능하다
description_en: No entry under /var/log may be world-writable, and a group-writable entry must be owned by one of the groups permitted to write logs (root, syslog, adm, utmp). This lets the normal logging groups own their files while flagging a log path a non-log group can write. The permitted groups are a parameter, so a site with a different logging group can adjust it.
description_ko: /var/log 아래의 어떤 항목도 전체 쓰기가 가능하면 안 되고, 그룹 쓰기가 가능한 항목은 로그 기록이 허용된 그룹(root, syslog, adm, utmp) 중 하나가 소유해야 합니다. 이렇게 하면 정상 로깅 그룹이 자기 파일을 소유하면서, 로그 그룹이 아닌 그룹이 쓸 수 있는 로그 경로를 표시합니다. 허용 그룹은 파라미터라 다른 로깅 그룹을 쓰는 사이트는 조정할 수 있습니다.
category: file
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-67"], "2021": [] }
  stig:
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-232025 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-700120 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232025 }
  nist_800_53: ["SI-11"]
requires_facts: ">=1"
absent_means: manual
params:
  allowed_groups: { type: list<string>, default: ["root", "syslog", "adm", "utmp"], description: groups permitted to have group-write on a /var/log entry }
checks:
  - { fact: files.log_dirs, op: none, where: { field: other_writable, op: eq, expected: true } }
  - { fact: files.log_dirs, op: each, subject: path, where: { field: group_writable, op: eq, expected: true }, require: { field: group, op: in, expected: "${allowed_groups}" } }
  - { fact: files.log_files, op: none, where: { field: other_writable, op: eq, expected: true } }
  - { fact: files.log_files, op: each, subject: path, where: { field: group_writable, op: eq, expected: true }, require: { field: group, op: in, expected: "${allowed_groups}" } }
remediation:
  text_en: chmod o-w each world-writable log path; for a group-writable path owned by an unexpected group, chown it to root or a logging group, or add that group to the parameter if it is legitimate.
  text_ko: 전체 쓰기 가능한 로그 경로에 chmod o-w 를 적용하고, 예상치 못한 그룹이 소유한 그룹-쓰기 경로는 root 나 로깅 그룹으로 chown 하거나, 정당하면 그 그룹을 파라미터에 추가합니다.
  risk: none
  idempotent: true
```

- [ ] **Step 2: Fixtures**

`cron_permissions/`: `pass-0640.json` (cron.files rows mode 416, owner_ok true, not writable; cron.dirs not other-writable → PASS), `fail-0644.json` (a row mode 420 → FAIL, the stock case), `fail-world-writable.json` (other_writable true → FAIL), `fail-denied.json` (a row mode -1 → FAIL), `fail-not-owned.json` (a system-scope row owner_ok false → FAIL), `fail-absent.json` (`cron.files` absent → absent_means fail).
`sudoers_permissions/`: `pass-clean.json` (sudo.installed true, etc_sudoers mode 288=0440 uid 0, a sudoers_d_entries row ignored false not writable → PASS), `fail-mode.json` (etc_sudoers mode 420 → FAIL), `fail-dropin-writable.json` (a non-ignored drop-in group_writable true → FAIL), `pass-ignored-dropin.json` (a group-writable drop-in but ignored true → PASS, skipped), `na-no-sudo.json` (sudo.installed false → NOT_APPLICABLE), `error-denied.json` (etc_sudoers.mode denied → ERROR permission_denied; `_expect` reason_code permission_denied).
`log_dir_permissions/`: `pass-clean.json` (log_dirs/log_files: a syslog-group-writable file with group "adm" in the allowed set → PASS), `fail-world-writable.json` (a log file other_writable true → FAIL), `fail-unexpected-group.json` (a group-writable dir owned by group "staff" not in allowed → FAIL), `manual-absent.json` (log_dirs absent → MANUAL).

- [ ] **Step 3: e2e, counts, coverage (L10)**

Add to both snapshots: `cron.files` (a 0640 owner_ok row), `cron.dirs` (not other-writable), `cron.timers` `[]`; `files.etc_sudoers` (mode 288, uid 0), `files.etc_sudoers_d` + `sudoers_d_entries` (a clean row or `[]`), `sudo.installed` true (+ includedir/secure_path); `files.log_dirs`/`log_files` (clean, group-writable only by allowed groups). All three PASS in both snapshots (full-fail: only root_remote_login FAILs). **Note:** U-37 requires 0640 cron files — give the snapshots 0640 (416), not the stock 0644, so U-37 PASSes. `controls_test.go`: `"ok: 32 controls"` → `"ok: 35 controls"`. `e2e_test.go`: add the three as PASS in both maps. `coverage.md`: regenerate → 35 items.

- [ ] **Step 4: Lint, behaviour test, real host, commit**

```
go run ./cmd/muster controls lint --references docs/reference   # ok: 35 controls
go run ./cmd/muster controls lint --fixtures controls/testdata  # ok: 35 controls
go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1
go test ./internal/check/ ./internal/controls/ ./cmd/muster/ -count=1
go run ./tools/coverage -check
```
Then the lab host, root, stock Ubuntu 22.04: `collect --require-root --require-complete`, `check --format json`; report the `<id> <status>` lines for the six new controls and the leaves `.facts.cron.files` count, `.facts.files.log_dirs` count, `.facts.sudo.secure_path.value`. Quote only those. (Expect `cron_permissions` and `syslog_conf_permissions` FAIL on the stock 0644 files — the documented guide criterion — and `sudoers_permissions`/`log_dir_permissions`/`startup_script_permissions`/`inetd_conf_permissions` PASS.)

```bash
git add controls/account/cron_permissions.yaml controls/account/sudoers_permissions.yaml controls/file/log_dir_permissions.yaml controls/testdata cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md
git commit -m "Add the cron, sudoers and log-directory permission controls"
```

---

### Task 6: README and final reconciliation

**Files:**
- Modify: `README.md`, `README.ko.md`, `cmd/muster/e2e_test.go` (count comments), verify `docs/reference/coverage.md`

- [ ] **Step 1:** README pair — extend the merged-plans sentence to name this plan (English: add ", and the system-file, startup and cron permission checks."; Korean: mirror with a single conjunction). No control ids enumerated; nothing else changes. Read the current sentence first to match its wording.
- [ ] **Step 2:** `e2e_test.go` — update the human-readable control-count comments to thirty-five. The maps and `controls_test.go` counts are already at 35 from Task 5.
- [ ] **Step 3:** Verify: `go run ./tools/coverage -check` exit 0 (already at 35 from Task 5); `go run ./cmd/muster controls lint --references docs/reference --fixtures controls/testdata` both `ok: 35 controls`; `gofmt -l .`; `GOOS=linux GOARCH=amd64 go vet ./...`; `go test ./internal/facts/ ./internal/check/ ./internal/controls/ ./cmd/muster/ -count=1`.
- [ ] **Step 4:** Commit.

```bash
git add README.md README.ko.md cmd/muster/e2e_test.go
git commit -m "Reconcile the system-file, startup and cron controls end to end"
```

---

## Self-review

**Spec coverage.** §5.4 `cron` section → T1; `files` startup/syslog/journald/inetd/sudoers/log rows and the `sudo` addition → T2/T3. §6.5 screening & mixed-absence → U-20 uses `mechanisms` (inetd vs xinetd), the other controls read one collector's list facts (no cross-fact absent screen). §7.3 honesty → a failed glob is the read error, never `[]`; a denied file is a `mode:-1`/reason row flagged by a `none where mode eq -1` clause; sudo content read failure is path-prefixed (C3). §10.2 items U-17/U-20/U-21/U-37/U-63/U-67 → T4/T5. STIG where a clean DISA rule exists (U-37 cron, U-67 log dir); U-17/U-20/U-21/U-63 carry KISA (and NIST where general). The 2021 ids match `kisa_mapping.json` (U-17←U-14, U-20←U-10, U-21←U-11, U-37←U-22/U-65, U-63←(none), U-67←(none)).

**Placeholder scan.** The `namedUID` placeholder in T1's `cronRow` is explicitly replaced by the owner_ok ruling (`uid >= 1000`); `aclPresent` is specified as "reuse permfacts.go's exact mechanism". No TBD/TODO.

**Type consistency.** `permRow` returns the shared row shape used by startup/syslog/xinetd/log; `cronRow` adds `scope`/`user`/`owner_ok`; mode-subset params are `list<int>`; `allowed_groups` is `list<string>`; the `none where {field: mode, op: eq, expected: -1}` clauses catch denied rows uniformly. Control ids: `muster.file.{startup_script_permissions,syslog_conf_permissions,inetd_conf_permissions,log_dir_permissions}`, `muster.account.{cron_permissions,sudoers_permissions}`. Count 29 → 35 (T4 +3, T5 +3).

**Risks called out.** (1) The vacuous-`each` / failed-glob hazard — every list fact carries the read error on a failed glob and a `mode:-1` row for a denied stat, with a `none where mode eq -1` guard clause. (2) The guide's 0640 vs the stock 0644 — U-21 and U-37 FAIL a stock host by design, stated in their descriptions; the e2e snapshots use 0640 so the suite is green. (3) U-67's log-group allowlist lives in the control (`params`, judged by `each where group_writable require group in allowed`), not precomputed in the collector (D09). (4) U-20's mixed-absence — `mechanisms` on inetd vs xinetd, `absent_means: pass` when neither is present.

## Execution notes

<!-- Filled in after execution: rulings R202+, the pre-flight scan, the whole-branch review, the fix wave, the real-host proof, and the items carried forward. -->
