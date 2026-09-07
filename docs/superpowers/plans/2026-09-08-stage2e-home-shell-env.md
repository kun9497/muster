# Stage 2E — Home Directories and the Shell Environment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `env` collector's shell facts (the effective `TMOUT`, `umask` and root `PATH` parsed from the system profile files, each assignment recorded with its `conditional`/`exported`/`readonly`/`scope` flags) and the `files` collector's home-and-environment enumeration (`home_dirs`, `env_files`, `user_rhosts`, `root_home`, `etc_hosts_equiv`, `dev_entries`), then judge eight KISA items with them: amend U-12 to gain its shell-`TMOUT` mechanism, and enrol U-14 (root home and PATH), U-24 (environment-variable files), U-26 (non-device files under /dev), U-27 (`.rhosts`/`hosts.equiv`), U-30 (UMASK), U-31 (home permissions) and U-32 (home existence).

**Architecture:** A new `env` collector reads the system shell-startup files (`/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc` or `/etc/bashrc`, `/etc/csh.cshrc`, root's dotfiles) and records every `TMOUT`, `umask` and `PATH` assignment as a structured row — the winning effective value plus every assignment with the file, line, and whether it sits inside a conditional block, is exported, is readonly, or is symbolic — so a control judges the value while the evidence shows where it came from and whether muster could be sure it always runs. The `files` collector gains a home-directory enumeration keyed on `/etc/passwd`: one row per account with its home stat as a three-value `stat_status` (ok/absent/denied — never conflating an unreadable 0700 home with a missing one), an `interactive` flag (the account's shell is a real login shell, so Ubuntu's thirty `/nonexistent` service homes are filtered out rather than reported), owner and filesystem facts; the per-home shell-environment files and `.rhosts`/`.shosts` as derived flags (owner_ok, has_plus, entry_count — never the file body); `/root` and `/etc/hosts.equiv` permission facts; and a bounded `/dev` walk that flags a regular file living on `devtmpfs`. Controls judge these with the existing `each`/`none` grammar; a `denied` stat is a finding with the path named, never a silent pass.

**Tech Stack:** Go 1.25 stdlib, YAML controls decoded strictly, JSON fixtures, the lab host (Ubuntu 22.04) and CI's Ubuntu 24.04 plus the Rocky/Alma 9 init containers (different profile-file names, home roots and nologin paths).

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — §5.2 (envelopes, `Source.Kind`), §5.4 (`env` section: `container`, `has_systemd`, `shell.*`; `files` section: `home_dirs`, `env_files`, `user_rhosts`, `root_home`, `dev_entries`; the `sudo` addition is 2F, not here), §5.6 (sensitivity — `user_rhosts` and `last_login` are `internal`), §5.7 (additive record fields keep `schema_version`), §6.3–6.6 (clause grammar; `each` with `subject`/`where`/`require`, `none` with `where`; `${param}`), §6.5 (screening, step 13), §7.3 (honest degradation), §10.2 (plan 2E), appendix A rows U-12/U-14/U-24/U-26/U-27/U-30/U-31/U-32. Execution notes of 2A–2D carry rulings R89–R174.

## Global Constraints

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`; a registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never resolved by `absent_means`.
- **A home that cannot be stat'd is `denied`, not absent (spec §7.3).** `files.home_dirs` carries `stat_status` ∈ {`ok`,`absent`,`denied`}: `ok` when the stat succeeded, `absent` only when the path genuinely does not exist (`ENOENT`), `denied` when the stat failed for any other reason (a 0700 parent, EACCES). A control must never let a `denied` row read as a clean pass — U-27's `absent_means: pass` would otherwise excuse an unreadable home.
- **The interactive filter (U-31/U-32/U-24, riskiest decision).** An account is `interactive` when its login shell is a real shell — present in `/etc/shells` and not a `*/nologin` or `*/false` path. Ubuntu ships ~30 service accounts with home `/nonexistent` and shell `/usr/sbin/nologin`; judging their homes would produce dozens of false findings per host, so home and env-file controls judge only interactive accounts. `root` (shell `/bin/bash`) is interactive; a service account is not.
- No judgment in collectors (D09): the collector records the value, the assignment sites and the flags; whether a `umask` of `022` is strict enough, whether a `TMOUT` is short enough, or which `PATH` elements are acceptable lives in the controls' `params`, whose defaults are the guide's criterion (§6.6) even where a stock host then fails; the deviation is stated in the control's description.
- Every host touch goes through `Access` and every path a collector reads is in its `Declare.Reads`; a home glob is a multi-segment declaration (`/home/*/.bashrc`, `/root/.*`). `readLimit` on every `ReadFile`; a `.rhosts`/profile file is read for its lines but only derived flags are stored, never the body. No new module dependency. New Go files under `internal/collect/collectors` carry `//go:build linux`.
- Same input, same bytes: profile files parsed in a fixed order, `profile.d` and home globs sorted, `PATH` elements in position order, `/dev` entries sorted, home rows in `/etc/passwd` order; no `map` iteration reaching a `Set` value's order (a `map[string]any` record is fine — `encoding/json` sorts its keys).
- Control and waiver YAML decode strictly; every control has `pass-*`/`fail-*` fixtures (`fail-` on a `partial` control expects `WARN`; `warn-`, `error-`, `manual-`, `na-` prefixes exist), `synthetic: true`, and only the leaves the control reads; `controls lint --references docs/reference` must end `ok: 29 controls`; every `references.stig` id must exist in `docs/reference/stig/`, every NIST id in the index union.
- Never copy KISA guide text, CIS/DISA text or a distribution's packaged files verbatim: fixtures are synthetic (own wording, `synthetic: true`); titles/descriptions/remediation are muster's own words, English and Korean both; identifiers, flags and paths stay English on both sides. Nothing from the lab host is committed; no host name, address, alias or credential in any file.
- Registry additions carry `since: 1`, `sensitivity: public` (except `user_rhosts` → `internal`), and their `collector`; the facts schema golden is regenerated with `go test ./internal/facts -run TestFactsSchemaGolden -update` and its diff reviewed (new keys get `since` lines; no type change, so no `schema_version` bump). Exit codes unchanged.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/collect/collectors/env.go` (new, T1) | `envCollector`, `runEnv`, the profile-file list, and the assembly of `env.shell.*`. |
| `internal/collect/collectors/env_parse.go` (new, T1) | `parseShellFile` — the line scanner that recognises `TMOUT=`, `umask`, `export`, `readonly`, `PATH=` and tracks conditional depth; `shellAssignment`, `pathEntries`. |
| `internal/collect/collectors/files_home.go` (new, T2) | `homeDirs`, `envFiles`, `userRhosts` — the `/etc/passwd`-keyed enumeration, the interactive filter, the mountinfo fstype lookup. |
| `internal/collect/collectors/files.go` (modify, T3) | `runFiles` gains `root_home`, `etc_hosts_equiv`, `dev_entries` and calls the T2 home enumeration; `Declare.Reads` extended. |
| `internal/collect/collectors/files_dev.go` (new, T3) | `devEntries` — the bounded `/dev` walk with mountinfo fstype and the `dev_nondevice` derivation. |
| `internal/collect/collectors/collectors_test.go` (T1–T3) | env and files tests (the one Linux-only collector test file). |
| `internal/collect/collectors/register.go` (T1) | `collect.Register(envCollector)` after `osCollector`. |
| `internal/collect/collectors/testdata/*` (T1–T3) | profile fixtures (`profile`, `profile.d_*.sh`, `bash.bashrc`, root dotfiles) and passwd/shells/mountinfo/home fixtures. |
| `internal/facts/registry.yaml`, `internal/facts/testdata/facts-schema.golden.json` (T1–T3) | new keys (T1 7 `env.shell.*`; T2 3 — `home_dirs`, `env_files`, `user_rhosts`; T3 3 — `root_home.*` group, `etc_hosts_equiv.*`+`_lines`, `dev_entries`+`dev_nondevice`). |
| `controls/account/session_timeout.yaml` (modify, T4) | U-12 gains the shell-`TMOUT` mechanism and its STIG refs. |
| `controls/account/umask_policy.yaml` (new, T4) | U-30. |
| `controls/account/root_home_and_path.yaml` (new, T4) | U-14. |
| `controls/file/env_file_permissions.yaml`, `dev_no_stale_files.yaml`, `rhosts_forbidden.yaml`, `home_dir_permissions.yaml`, `home_dir_exists.yaml` (new, T5) | U-24, U-26, U-27, U-31, U-32. |
| `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go`, `docs/reference/coverage.md`, `README.md`, `README.ko.md` (T6) | End-to-end snapshots, counts (`22` → `29`), coverage table, README merged-plans sentence. |

Key inventory this plan adds (13 keys):

| Key | Type | Collector | Task | Meaning |
|---|---|---|---|---|
| `env.shell.tmout` | `int` | env | T1 | Effective `TMOUT` seconds across the system profile files; `0` when never set (bash reads 0 as no timeout). |
| `env.shell.tmout_exported` | `bool` | env | T1 | The winning `TMOUT` is `export`ed (otherwise a login shell child does not inherit it). |
| `env.shell.tmout_readonly` | `bool` | env | T1 | The winning `TMOUT` is `readonly` (a user cannot unset it). |
| `env.shell.tmout_settings` | `list<record>` | env | T1 | Every `TMOUT` assignment: `path`, `line`, `value`, `exported`, `readonly`, `conditional`. |
| `env.shell.umask_settings` | `list<record>` | env | T1 | Every `umask` assignment: `path`, `line`, `value`, `symbolic`, `conditional`, `scope` (`system`\|`root`). |
| `env.shell.root_path_raw` | `string` | env | T1 | The winning `PATH` assignment for root, verbatim, with the file and line as its source. |
| `env.shell.root_path_entries` | `list<record>` | env | T1 | Each `PATH` element: `position`, `value`, `exists`, `mode`, `uid`, `gid`, `group_writable`, `world_writable`, `is_dot` (empty/`.`/relative), `unresolved`. |
| `files.home_dirs` | `list<record>` | files | T2 | One row per `/etc/passwd` home: `user`, `uid`, `home`, `stat_status` (ok\|absent\|denied), `is_dir`, `mode`, `owner_uid`, `owner_matches`, `group_writable`, `other_writable`, `interactive`, `on_remote_fs`. `subject_kind: dir`. |
| `files.env_files` | `list<record>` | files | T2 | System and per-user shell-environment files present: `path`, `scope` (`system`\|`user`), `home_user`, `mode`, `owner_uid`, `owner_ok`, `group_writable`, `other_writable`, `is_symlink`. |
| `files.user_rhosts` | `list<record>` | files | T2 | Per-home `.rhosts`/`.shosts` and `/etc/hosts.equiv` reach: `path`, `home_user`, `owner_ok`, `has_plus`, `entry_count`. Derived flags only, never the body. `sensitivity: internal`. |
| `files.root_home.{mode,uid,gid,group_writable,other_writable,acl_present}` | int×3, bool×3 | files | T3 | Permission facts of `/root` from stat only. |
| `files.etc_hosts_equiv.{mode,uid}` + `files.etc_hosts_equiv_lines` | int×2, list<string> | files | T3 | `/etc/hosts.equiv` permissions and its non-comment lines. |
| `files.dev_entries` + `files.dev_nondevice` | list<record>×2 | files | T3 | Bounded `/dev` enumeration (`name`, `kind`, `fstype`, `mode`, `uid`) and the derived rows that are a regular file on `devtmpfs`/`tmpfs`. |

Not built here: `sudo.{installed,includedir,secure_path}` (2F — so U-14 judges root home and root PATH only, and gains its `secure_path` clause in 2F); `accounts.last_login` and the per-user `PATH` of non-root accounts (later); the U-24 `csh`/`ksh` dotfiles beyond the ones listed (recorded as a 2M candidate). The `env.container`/`env.has_systemd` keys stay `collector: os` (2A) and are not moved.

---

### Task 1: The env collector — TMOUT, umask and root PATH from the profile files

**Files:**
- Create: `internal/collect/collectors/env.go`, `internal/collect/collectors/env_parse.go`, and env tests in `collectors_test.go`
- Create fixtures under `internal/collect/collectors/testdata/`: `profile`, `profile.d_10-muster.sh`, `profile.d_99-tmout.sh`, `bash.bashrc`, `root_bashrc`, `root_profile`, `csh.cshrc`
- Modify: `internal/collect/collectors/register.go` (register `envCollector` after `osCollector`), `internal/facts/registry.yaml` (7 keys), golden regenerated

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Stat`, `Glob`), `collect.Builder` (`Set`), `facts.Source`, and the shared helpers `splitLines`, `readLimit`, `collect.OK`, `collect.OKRead`, `collect.Absent`, `collect.FromReadError`.
- Produces:
  - `envCollector` (`Name: "env"`, `Declare.Reads` = the profile files and home dotfile paths below, `Needs: "none"`).
  - `runEnv(ctx, a, b) error`.
  - `parseShellFile(data []byte, path string) []shellAssignment` — one row per `TMOUT`/`umask`/`PATH`/`export`/`readonly` line, with `conditional` set when the line is inside an `if`/`case`/`for`/`while`/`&&`/`||` block (tracked by keyword depth).
  - `shellAssignment{Kind string; Value string; Path string; Line int; Exported, Readonly, Conditional, Symbolic bool; Scope string}` (Kind ∈ `tmout|umask|path`).
  - `pathEntries(a, raw string) []any` — split a `PATH` value on `:` and stat each element.

- [ ] **Step 1: Write the failing test for the effective TMOUT**

Add to `collectors_test.go`:

```go
// The winning TMOUT is the last unconditional assignment across the profile
// files read in order; its exported/readonly flags come from that line (or a
// later export/readonly of the same name). A value set only inside an `if`
// block is recorded with conditional=true and does not win.
func TestEnvEffectiveTMOUT(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/profile":                 "profile",              // TMOUT=600; export TMOUT
			"/etc/profile.d/99-tmout.sh":   "profile.d_99-tmout.sh",// readonly TMOUT (no value)
		},
	}
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600", e)
	}
	if env(t, b, "env.shell.tmout_exported").Value != true {
		t.Error("TMOUT is exported")
	}
	if env(t, b, "env.shell.tmout_readonly").Value != true {
		t.Error("TMOUT is readonly")
	}
	settings := okList(t, b, "env.shell.tmout_settings")
	if len(settings) < 1 {
		t.Fatalf("tmout_settings %v", settings)
	}
}
```

Fixtures:
- `profile` — a synthetic `/etc/profile`: a comment line, `TMOUT=600`, `export TMOUT`, `umask 022`, `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `export PATH`.
- `profile.d_99-tmout.sh` — `readonly TMOUT`.
- `profile.d_10-muster.sh` — `if [ "$UID" -ge 1000 ]; then umask 002; fi` (a conditional umask, scope system).
- `bash.bashrc` — `umask 022`.
- `root_bashrc` — `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` (root scope).
- `root_profile`, `csh.cshrc` — minimal.

- [ ] **Step 2: Run it — fails (no env collector)**

Run: `go test ./internal/collect/collectors/ -run TestEnvEffectiveTMOUT -v`
Expected: FAIL — `collectorNamed` cannot find `env`.

- [ ] **Step 3: Implement `env.go`**

```go
//go:build linux

package collectors

import (
	"context"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	etcProfile   = "/etc/profile"
	profileDGlob = "/etc/profile.d/*.sh"
	bashBashrc   = "/etc/bash.bashrc" // Debian family
	etcBashrc    = "/etc/bashrc"      // RHEL family
	cshCshrc     = "/etc/csh.cshrc"
)

// systemProfiles is the fixed read order: the login profile, its drop-ins
// (sorted), then the interactive-shell rc files. Order matters because the
// last unconditional assignment wins, so it must be deterministic.
var rootDotfiles = []string{"/root/.bash_profile", "/root/.bashrc", "/root/.profile"}

var envCollector = collect.Collector{
	Name: "env",
	Declare: collect.Declaration{
		Reads: append([]string{etcProfile, profileDGlob, bashBashrc, etcBashrc, cshCshrc}, rootDotfiles...),
		Needs: "none",
	},
	Run: runEnv,
}

func runEnv(_ context.Context, a collect.Access, b *collect.Builder) error {
	var all []shellAssignment
	for _, p := range profileReadOrder(a) {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			continue // a missing/denied profile file is not an env failure; the winner logic sees what it can
		}
		_ = meta
		all = append(all, parseShellFile(data, p)...)
	}
	writeTMOUT(b, all)
	writeUmask(b, all)
	writeRootPath(a, b, all)
	return nil
}

// profileReadOrder returns the profile files that exist, in the fixed order,
// with profile.d sorted. Both distro bashrc names are included; only the one
// that exists contributes.
func profileReadOrder(a collect.Access) []string {
	out := []string{etcProfile}
	if matches, err := a.Glob(profileDGlob); err == nil {
		sort.Strings(matches)
		out = append(out, matches...)
	}
	out = append(out, bashBashrc, etcBashrc, cshCshrc)
	out = append(out, rootDotfiles...)
	return out
}
```

`writeTMOUT`, `writeUmask`, `writeRootPath`:

```go
func writeTMOUT(b *collect.Builder, all []shellAssignment) {
	var winner *shellAssignment
	exported, readonly := false, false
	rows := []any{}
	for i := range all {
		s := all[i]
		if s.Kind != "tmout" {
			continue
		}
		rows = append(rows, map[string]any{
			"path": s.Path, "line": s.Line, "value": s.Value,
			"exported": s.Exported, "readonly": s.Readonly, "conditional": s.Conditional,
		})
		if s.Exported {
			exported = true
		}
		if s.Readonly {
			readonly = true
		}
		if !s.Conditional && s.Value != "" { // a bare `readonly TMOUT` has no value; it does not win
			w := s
			winner = &w
		}
	}
	src := &facts.Source{Kind: "derived"}
	val := 0
	if winner != nil {
		if n, err := strconv.Atoi(strings.TrimSpace(winner.Value)); err == nil {
			val = n
			src = &facts.Source{Kind: "file", Path: winner.Path, Line: winner.Line}
		}
	}
	b.Set("env.shell.tmout", collect.OK(val, src))
	b.Set("env.shell.tmout_exported", collect.OK(exported, src))
	b.Set("env.shell.tmout_readonly", collect.OK(readonly, src))
	b.Set("env.shell.tmout_settings", collect.OK(rows, &facts.Source{Kind: "derived"}))
}

func writeUmask(b *collect.Builder, all []shellAssignment) {
	rows := []any{}
	for _, s := range all {
		if s.Kind != "umask" {
			continue
		}
		rows = append(rows, map[string]any{
			"path": s.Path, "line": s.Line, "value": s.Value,
			"symbolic": s.Symbolic, "conditional": s.Conditional, "scope": s.Scope,
		})
	}
	b.Set("env.shell.umask_settings", collect.OK(rows, &facts.Source{Kind: "derived"}))
}

func writeRootPath(a collect.Access, b *collect.Builder, all []shellAssignment) {
	var winner *shellAssignment
	for i := range all {
		if all[i].Kind == "path" && !all[i].Conditional {
			w := all[i]
			winner = &w
		}
	}
	if winner == nil {
		e := collect.Absent("no PATH assignment in the system profile files")
		b.Set("env.shell.root_path_raw", e)
		b.Set("env.shell.root_path_entries", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: winner.Path, Line: winner.Line, Raw: sourceRaw("PATH=" + winner.Value)}
	b.Set("env.shell.root_path_raw", collect.OK(winner.Value, src))
	b.Set("env.shell.root_path_entries", collect.OK(pathEntries(a, winner.Value), src))
}
```

- [ ] **Step 4: Implement `env_parse.go`**

```go
//go:build linux

package collectors

import (
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

type shellAssignment struct {
	Kind                                   string // tmout | umask | path
	Value                                  string
	Path                                   string
	Line                                   int
	Exported, Readonly, Conditional, Symbolic bool
	Scope                                  string
}

// parseShellFile scans a POSIX/bash startup file for TMOUT, umask and PATH.
// It tracks a coarse conditional depth: a line that opens an if/for/while/
// case block, or is joined with && or ||, raises depth; `fi`/`done`/`esac`
// lower it. An assignment at depth>0 is conditional (muster cannot prove it
// always runs). This is deliberately structural, not a shell interpreter.
func parseShellFile(data []byte, p string) []shellAssignment {
	var out []shellAssignment
	depth := 0
	scope := "system"
	if strings.HasPrefix(p, "/root/") {
		scope = "root"
	}
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(cutComment(raw))
		if line == "" {
			continue
		}
		opens, closes := blockDelta(line)
		conditional := depth > 0
		// TMOUT
		if v, ok := assignmentValue(line, "TMOUT"); ok {
			out = append(out, shellAssignment{Kind: "tmout", Value: v, Path: p, Line: i + 1,
				Exported: strings.HasPrefix(line, "export "), Conditional: conditional})
		}
		if name, ok := readonlyName(line); ok && name == "TMOUT" {
			out = append(out, shellAssignment{Kind: "tmout", Value: assignedInline(line, "TMOUT"), Path: p, Line: i + 1,
				Readonly: true, Conditional: conditional})
		}
		if name, ok := exportName(line); ok && name == "TMOUT" {
			out = append(out, shellAssignment{Kind: "tmout", Value: "", Path: p, Line: i + 1, Exported: true, Conditional: conditional})
		}
		// umask
		if fields := strings.Fields(line); len(fields) >= 2 && (fields[0] == "umask" || (fields[0] == "builtin" && fields[1] == "umask")) {
			val := fields[len(fields)-1]
			out = append(out, shellAssignment{Kind: "umask", Value: val, Path: p, Line: i + 1,
				Symbolic: !isOctalMask(val), Conditional: conditional, Scope: scope})
		}
		// PATH
		if v, ok := assignmentValue(line, "PATH"); ok {
			out = append(out, shellAssignment{Kind: "path", Value: v, Path: p, Line: i + 1, Conditional: conditional, Scope: scope})
		}
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
	}
	return out
}
```

helpers in the same file:

```go
// cutComment drops an unquoted trailing comment. A `#` inside single or
// double quotes is kept; this is a coarse scan, not a shell lexer, so a `#`
// after an odd number of quotes is treated as literal.
func cutComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inD { inS = !inS }
		case '"':
			if !inS { inD = !inD }
		case '#':
			if !inS && !inD && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i]
			}
		}
	}
	return line
}

// assignmentValue returns the RHS of `name=value` or `export name=value`,
// with surrounding quotes stripped. ok is false when the line is not an
// assignment to name.
func assignmentValue(line, name string) (string, bool) {
	l := strings.TrimPrefix(line, "export ")
	l = strings.TrimSpace(l)
	prefix := name + "="
	if !strings.HasPrefix(l, prefix) {
		return "", false
	}
	v := strings.TrimSpace(l[len(prefix):])
	v = strings.Trim(v, `"'`)
	return v, true
}

func assignedInline(line, name string) string { v, _ := assignmentValue(strings.TrimPrefix(line, "readonly "), name); return v }

func exportName(line string) (string, bool) {
	if !strings.HasPrefix(line, "export ") { return "", false }
	rest := strings.TrimSpace(strings.TrimPrefix(line, "export "))
	if i := strings.IndexByte(rest, '='); i >= 0 { return rest[:i], true }
	return strings.Fields(rest)[0], true
}

func readonlyName(line string) (string, bool) {
	if !strings.HasPrefix(line, "readonly ") { return "", false }
	rest := strings.TrimSpace(strings.TrimPrefix(line, "readonly "))
	if i := strings.IndexByte(rest, '='); i >= 0 { return rest[:i], true }
	return strings.Fields(rest)[0], true
}

func isOctalMask(v string) bool {
	if len(v) < 3 || len(v) > 4 { return false }
	_, err := strconv.ParseInt(v, 8, 32)
	return err == nil
}

// blockDelta counts shell block openers and closers on one line.
func blockDelta(line string) (opens, closes int) {
	f := strings.Fields(line)
	for _, w := range f {
		switch w {
		case "if", "for", "while", "until", "case":
			opens++
		case "fi", "done", "esac":
			closes++
		}
	}
	if strings.HasSuffix(strings.TrimSpace(line), "&&") || strings.HasSuffix(strings.TrimSpace(line), "||") {
		// a continuation whose body is on the next line; treat the body as conditional
		opens++
	}
	return opens, closes
}

// pathEntries splits a PATH value and stats each element. An empty element,
// ".", or a relative path is is_dot (a working-directory injection risk); a
// stat failure is unresolved. Reads go through Access so the guard applies,
// but a PATH element outside the declaration is simply marked unresolved
// rather than read (it is a directory stat, not a file read).
func pathEntries(a collect.Access, raw string) []any {
	out := []any{}
	for i, el := range strings.Split(raw, ":") {
		rec := map[string]any{"position": i, "value": el}
		if el == "" || el == "." || !strings.HasPrefix(el, "/") {
			rec["is_dot"] = true
			out = append(out, rec)
			continue
		}
		rec["is_dot"] = false
		meta, err := a.Stat(el)
		if err != nil {
			rec["unresolved"] = true
			out = append(out, rec)
			continue
		}
		rec["unresolved"] = false
		rec["exists"] = true
		rec["mode"] = int(meta.Mode)
		rec["uid"] = int(meta.UID)
		rec["gid"] = int(meta.GID)
		rec["group_writable"] = meta.Mode&0o020 != 0
		rec["world_writable"] = meta.Mode&0o002 != 0
		out = append(out, rec)
	}
	return out
}
```

(`cutComment`/`sourceRaw` already exist for other collectors — if `cutComment` is not yet shared, define it here; a later plan can hoist it.)

- [ ] **Step 5: Run the TMOUT test — passes**

Run: `go test ./internal/collect/collectors/ -run TestEnvEffectiveTMOUT -v` → PASS.

- [ ] **Step 6: The remaining env tests**

```go
// A conditional umask does not win and is flagged; a system-scope and a
// root-scope umask are both recorded with the right scope.
func TestEnvUmaskSettings(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/profile":                "profile",               // umask 022 (system, unconditional)
		"/etc/profile.d/10-muster.sh": "profile.d_10-muster.sh", // umask 002 inside an if (conditional)
		"/root/.bashrc":               "root_bashrc",
	}}
	rows := okList(t, build(t, "env", a), "env.shell.umask_settings")
	var sawConditional, sawSystem bool
	for _, r := range rows {
		m := r.(map[string]any)
		if m["value"] == "002" && m["conditional"] == true { sawConditional = true }
		if m["value"] == "022" && m["scope"] == "system" && m["conditional"] == false { sawSystem = true }
	}
	if !sawConditional || !sawSystem {
		t.Errorf("umask rows %v", rows)
	}
}

// Root PATH is split into positioned entries; an empty element is is_dot, a
// missing directory is unresolved, a world-writable one carries the flag.
func TestEnvRootPathEntries(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/root/.bashrc": "root_bashrc_badpath"}, // PATH=/usr/bin::/opt/x
		stats: map[string]statResult{
			"/usr/bin": {mode: 0o755, kind: "dir"},
			"/opt/x":   {mode: 0o777, kind: "dir"},
		},
	}
	entries := okList(t, build(t, "env", a), "env.shell.root_path_entries")
	if len(entries) != 3 {
		t.Fatalf("entries %v, want 3 (/usr/bin, empty, /opt/x)", entries)
	}
	if entries[1].(map[string]any)["is_dot"] != true {
		t.Error("the empty element between :: must be is_dot")
	}
	if entries[2].(map[string]any)["world_writable"] != true {
		t.Error("/opt/x is world-writable")
	}
}

// A profile file that cannot be read does not fail the collector; the winner
// is computed from what was readable.
func TestEnvUnreadableProfileIsSkipped(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/profile": "profile"},
		fails: map[string]error{"/etc/bash.bashrc": os.ErrPermission},
	}
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout from the readable profile %+v", e)
	}
}
```

Fixtures to add: `root_bashrc_badpath` (`PATH=/usr/bin::/opt/x` then `export PATH`).

- [ ] **Step 7: Register the seven keys and regenerate the golden**

Add to `registry.yaml` an `env.shell.*` block — all `since: 1`, `sensitivity: public`, `collector: env`:

```yaml
  - key: env.shell.tmout
    type: int
    description: Effective TMOUT in seconds from the system profile files; 0 when unset (bash reads 0 as no timeout).
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.tmout_exported
    type: bool
    description: Whether the winning TMOUT is exported so child login shells inherit it.
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.tmout_readonly
    type: bool
    description: Whether TMOUT is made readonly so a user cannot unset it.
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.tmout_settings
    type: list<record>
    description: Every TMOUT assignment - path, line, value, exported, readonly, conditional.
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.umask_settings
    type: list<record>
    description: Every umask assignment - path, line, value, symbolic, conditional, scope.
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.root_path_raw
    type: string
    description: The winning PATH assignment for root, verbatim, with its file and line.
    since: 1
    sensitivity: public
    collector: env
  - key: env.shell.root_path_entries
    type: list<record>
    description: Each root PATH element - position, value, exists, mode, uid, gid, group_writable, world_writable, is_dot, unresolved.
    since: 1
    sensitivity: public
    collector: env
```

Regenerate: `go test ./internal/facts -run TestFactsSchemaGolden -update`, review (7 added keys, no version bump).

- [ ] **Step 8: Windows gates and commit**

```
gofmt -l internal/collect/collectors/env.go internal/collect/collectors/env_parse.go
GOOS=linux GOARCH=amd64 go vet ./internal/collect/...
GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null
go test ./internal/facts/ -count=1
go run ./cmd/muster controls lint --references docs/reference
```
Then sync to the lab host and run `bash lab-run.sh 'go test ./internal/collect/collectors/ -run TestEnv -count=1'`.

```bash
git add internal/collect/collectors/env.go internal/collect/collectors/env_parse.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/collect/collectors/register.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Add the env collector: TMOUT, umask and root PATH from the profile files"
```

---

### Task 2: The files collector's home, environment-file and rhosts enumeration

**Files:**
- Create: `internal/collect/collectors/files_home.go`, tests in `collectors_test.go`
- Modify: `internal/collect/collectors/files.go` (`Declare.Reads` and a call from `runFiles`), `internal/facts/registry.yaml` (3 keys), golden
- Create fixtures: `passwd_home` (a synthetic /etc/passwd with root + one interactive user + one service account), `shells_home`, `mountinfo`, `home_alice_bashrc`, `home_alice_rhosts`

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Stat`, `Glob`, `Allowed`), `collect.Builder`, `facts.Source`; the in-package helpers `parsePasswd(data) ([]passwdRow, int)` (fields `name, uid, gid, home, shell, line`), `loginShells(a) (map[string]bool, facts.Envelope)`, `splitLines`, `readLimit`, `collect.OK`/`Absent`/`FromReadError`; `declared(a, path)` (the guard probe from sshd.go).
- Produces:
  - `homeDirs(a, rows []passwdRow, shells map[string]bool, mounts mountTable) facts.Envelope` → `files.home_dirs`.
  - `envFiles(a, rows []passwdRow, shells map[string]bool) facts.Envelope` → `files.env_files`.
  - `userRhosts(a, rows []passwdRow, shells map[string]bool) facts.Envelope` → `files.user_rhosts`.
  - `mountTable` and `readMounts(a) mountTable` with method `fstype(path string) string` (longest mount-point prefix wins; `""` when unknown).
  - `interactive(shell string, shells map[string]bool) bool` — shell is in `shells` and is not a `*/nologin` or `*/false` path.

- [ ] **Step 1: Write the failing test — interactive filter and stat tri-state**

```go
// home_dirs has one row per passwd home. A service account (nologin shell,
// /nonexistent home) is interactive=false and its absent home is NOT a
// finding. root and an interactive user are interactive=true; an unreadable
// home (parent EACCES) is stat_status=denied, never absent.
func TestFilesHomeDirsInteractiveAndTriState(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo"},
		dirs:  map[string]bool{"/root": true, "/home/alice": true},
		stats: map[string]statResult{
			"/root":       {mode: 0o700, uid: 0, gid: 0, kind: "dir"},
			"/home/alice": {mode: 0o755, uid: 1000, gid: 1000, kind: "dir"},
		},
		fails: map[string]error{"/home/bob": os.ErrPermission}, // interactive, but parent denies stat
	}
	rows := okList(t, build(t, "files", a), "files.home_dirs")
	byUser := map[string]map[string]any{}
	for _, r := range rows { m := r.(map[string]any); byUser[m["user"].(string)] = m }
	if byUser["svc"]["interactive"] != false {
		t.Error("a nologin service account must be interactive=false")
	}
	if byUser["alice"]["stat_status"] != "ok" || byUser["alice"]["owner_matches"] != true {
		t.Errorf("alice %v", byUser["alice"])
	}
	if byUser["bob"]["stat_status"] != "denied" {
		t.Errorf("bob's unreadable home must be denied, not absent: %v", byUser["bob"])
	}
}
```

Fixtures:
- `passwd_home`:
```
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001:Bob:/home/bob:/bin/bash
svc:x:150:150:Service:/nonexistent:/usr/sbin/nologin
```
- `shells_home`: `/bin/bash` / `/bin/sh` / `/usr/bin/bash` (one per line; `nologin` deliberately absent).
- `mountinfo`: two synthetic lines giving `/` fstype `ext4` and `/home` fstype `ext4` (so `on_remote_fs` is false; a third test can add an `nfs` line).

- [ ] **Step 2: Run it — fails (no home_dirs)**

Run: `go test ./internal/collect/collectors/ -run TestFilesHomeDirsInteractiveAndTriState -v` → FAIL (`files.home_dirs` not present).

- [ ] **Step 3: Implement `files_home.go`**

```go
//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var interactiveHomeRoots = []string{"/home/*", "/root"}

// interactive reports whether shell is a real login shell: present in the
// /etc/shells set and not a nologin/false path. Service accounts on both
// families use /usr/sbin/nologin (or /sbin/nologin) or /bin/false, which are
// not listed in /etc/shells, so this filters them out (spec §10.2, the
// U-31/U-32 false-finding hazard).
func interactive(shell string, shells map[string]bool) bool {
	if strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") || shell == "" {
		return false
	}
	return shells[shell]
}

func homeDirs(a collect.Access, rows []passwdRow, shells map[string]bool, mounts mountTable) facts.Envelope {
	out := []any{}
	for _, r := range rows {
		rec := map[string]any{
			"user": r.name, "uid": r.uid, "home": r.home,
			"interactive": interactive(r.shell, shells),
		}
		// Only stat a home inside the declaration; an interactive home is
		// essentially always /home/* or /root. An undeclared home cannot be
		// examined under our declaration: record it as denied with a reason,
		// never as absent (which absent_means could excuse).
		if r.home == "" || !declared(a, r.home) {
			rec["stat_status"] = "denied"
			rec["reason"] = "home path outside the collector's declaration"
			out = append(out, rec)
			continue
		}
		meta, err := a.Stat(r.home)
		switch {
		case err == nil:
			rec["stat_status"] = "ok"
			rec["is_dir"] = meta.Kind == "dir"
			rec["mode"] = int(meta.Mode)
			rec["owner_uid"] = int(meta.UID)
			rec["owner_matches"] = int(meta.UID) == r.uid
			rec["group_writable"] = meta.Mode&0o020 != 0
			rec["other_writable"] = meta.Mode&0o002 != 0
			rec["on_remote_fs"] = isRemoteFS(mounts.fstype(r.home))
		case errors.Is(err, fs.ErrNotExist):
			rec["stat_status"] = "absent"
		default:
			rec["stat_status"] = "denied"
			rec["reason"] = readReason(r.home, err)
		}
		out = append(out, rec)
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}
```

`envFiles`, `userRhosts`, and the mount table:

```go
// systemEnvFiles are the fixed system-scope shell environment files; userEnv
// names are the per-home dotfiles. Both families' names are listed; only the
// ones that exist become rows.
var systemEnvFiles = []string{etcProfile, bashBashrc, etcBashrc, cshCshrc}
var userEnvNames = []string{".bashrc", ".bash_profile", ".profile", ".cshrc", ".login", ".bash_login"}

func envFiles(a collect.Access, rows []passwdRow, shells map[string]bool) facts.Envelope {
	out := []any{}
	for _, p := range systemEnvFiles {
		if meta, err := a.Stat(p); err == nil {
			out = append(out, envFileRow(p, "system", "", meta))
		}
	}
	for _, r := range rows {
		if !interactive(r.shell, shells) {
			continue
		}
		for _, name := range userEnvNames {
			p := path.Join(r.home, name)
			if !declared(a, p) {
				continue
			}
			if meta, err := a.Stat(p); err == nil {
				out = append(out, envFileRow(p, "user", r.name, meta))
			}
		}
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}

func envFileRow(p, scope, homeUser string, meta collect.ReadMeta) map[string]any {
	return map[string]any{
		"path": p, "scope": scope, "home_user": homeUser,
		"mode": int(meta.Mode), "owner_uid": int(meta.UID),
		"owner_ok":       meta.Kind != "symlink" && (int(meta.UID) == 0 || homeUser == "" || true), // see note
		"group_writable": meta.Mode&0o020 != 0,
		"other_writable": meta.Mode&0o002 != 0,
		"is_symlink":     meta.Kind == "symlink",
	}
}
```

**owner_ok ruling (state in the report):** `owner_ok` means the file is owned by the account whose home it sits in, or by root (root-owned system files are fine). Compute it as `owner_uid == home account's uid || owner_uid == 0`; the placeholder `true` above is a stand-in — implement the real comparison by passing the account uid into `envFileRow` (system-scope files require `owner_uid == 0`). Do not ship the `|| true`.

```go
// userRhosts records .rhosts/.shosts under each interactive home and
// /etc/hosts.equiv, as derived flags only (never the body): owner_ok,
// has_plus (a line that is exactly "+" or begins "+ "), entry_count.
func userRhosts(a collect.Access, rows []passwdRow, shells map[string]bool) facts.Envelope {
	out := []any{}
	scan := func(p, homeUser string, ownerUID int) {
		if !declared(a, p) {
			return
		}
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			return // absent or denied: no row (a denied .rhosts is not itself a finding; the file may not exist)
		}
		plus, count := false, 0
		for _, l := range splitLines(data) {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			count++
			if l == "+" || strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "+\t") {
				plus = true
			}
		}
		out = append(out, map[string]any{
			"path": p, "home_user": homeUser,
			"owner_ok": int(meta.UID) == ownerUID || int(meta.UID) == 0,
			"has_plus": plus, "entry_count": count,
		})
	}
	for _, r := range rows {
		if !interactive(r.shell, shells) {
			continue
		}
		scan(path.Join(r.home, ".rhosts"), r.name, r.uid)
		scan(path.Join(r.home, ".shosts"), r.name, r.uid)
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}
```

The mount table:

```go
type mountTable struct{ points map[string]string } // mount point -> fstype

// readMounts parses /proc/self/mountinfo. Each line's field 5 is the mount
// point and the token after " - " is the filesystem type.
func readMounts(a collect.Access) mountTable {
	t := mountTable{points: map[string]string{}}
	data, _, err := a.ReadFile("/proc/self/mountinfo", readLimit)
	if err != nil {
		return t
	}
	for _, line := range splitLines(data) {
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		f := strings.Fields(line[:sep])
		after := strings.Fields(line[sep+3:])
		if len(f) < 5 || len(after) < 1 {
			continue
		}
		t.points[f[4]] = after[0]
	}
	return t
}

// fstype returns the fstype of the longest mount point that is a prefix of p.
func (t mountTable) fstype(p string) string {
	best, bestFS := -1, ""
	for mp, fs := range t.points {
		if (p == mp || strings.HasPrefix(p, strings.TrimSuffix(mp, "/")+"/")) && len(mp) > best {
			best, bestFS = len(mp), fs
		}
	}
	return bestFS
}

func isRemoteFS(fs string) bool {
	switch fs {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "afs", "fuse.sshfs", "9p", "ceph", "glusterfs":
		return true
	}
	return false
}
```

- [ ] **Step 4: Wire into `runFiles` and extend `Declare.Reads`**

In `files.go`, add to `Declare.Reads`: `shellsPath`, `"/proc/self/mountinfo"`, the home roots `"/home/*"`, `"/root"`, and the per-home dotfile globs for every name in `userEnvNames` plus `.rhosts`/`.shosts` under both `/home/*/` and `/root/` (e.g. `"/home/*/.bashrc"`, …, `"/root/.rhosts"`). Then in `runFiles`, after the existing permission facts:

```go
	prows, _ := parsePasswd(mustRead(a, passwdPath)) // reuse a small read helper; a denied passwd already surfaces via files.etc_passwd
	shells, _ := loginShells(a)
	mounts := readMounts(a)
	b.Set("files.home_dirs", homeDirs(a, prows, shells, mounts))
	b.Set("files.env_files", envFiles(a, prows, shells))
	b.Set("files.user_rhosts", userRhosts(a, prows, shells))
```

If `/etc/passwd` cannot be read, set all three to the read error (they cannot be enumerated) rather than an empty list — a denied passwd must not read as "no homes". Add a helper that returns the passwd bytes or, on error, writes the three keys as `collect.FromReadError(...)` and returns early from the home block.

- [ ] **Step 5: The remaining Task-2 tests**

```go
// A denied /etc/passwd makes the three enumerations the read error, never an
// empty list.
func TestFilesHomeEnumDeniedPasswdIsError(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/etc/passwd": os.ErrPermission},
		files: map[string]string{"/etc/shells": "shells_home"}}
	b := build(t, "files", a)
	for _, k := range []string{"files.home_dirs", "files.env_files", "files.user_rhosts"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s must be denied, not an empty list: %+v", k, e)
		}
	}
}

// A .rhosts with a bare "+" is recorded has_plus=true with entry_count, body
// never stored; env_files marks a non-owner file owner_ok=false.
func TestFilesRhostsAndEnvFiles(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo",
			"/home/alice/.rhosts": "home_alice_rhosts", // contains "+"
			"/home/alice/.bashrc": "home_alice_bashrc",
		},
		stats: map[string]statResult{
			"/home/alice/.rhosts": {mode: 0o644, uid: 1000, kind: "regular"},
			"/home/alice/.bashrc": {mode: 0o644, uid: 0, kind: "regular"}, // root-owned in alice's home
		},
	}
	b := build(t, "files", a)
	rh := okList(t, b, "files.user_rhosts")
	if len(rh) != 1 || rh[0].(map[string]any)["has_plus"] != true {
		t.Fatalf("user_rhosts %v", rh)
	}
	ef := okList(t, b, "files.env_files")
	var alicebashrc map[string]any
	for _, r := range ef { m := r.(map[string]any); if m["path"] == "/home/alice/.bashrc" { alicebashrc = m } }
	if alicebashrc == nil || alicebashrc["owner_ok"] != true { // root-owned is ok
		t.Errorf(".bashrc row %v", alicebashrc)
	}
}
```

Fixtures: `home_alice_rhosts` (`+`), `home_alice_bashrc` (`umask 022`). `home_alice_bashrc` is read? No — env_files only stats; `.rhosts` is read. Ensure the `files` map provides bytes for the read path and `stats` for the stat paths.

- [ ] **Step 6: Register the three keys, regenerate the golden**

`files.home_dirs` (`list<record>`, `subject_kind: dir`, `sensitivity: public`), `files.env_files` (`list<record>`, `sensitivity: public`), `files.user_rhosts` (`list<record>`, `sensitivity: internal`). All `since: 1`, `collector: files`. Descriptions one line each, own words. Regenerate the golden and review.

- [ ] **Step 7: Windows gates + lab host, commit**

Windows gates as in Task 1; then `bash lab-sync.sh <worktree>` and `bash lab-run.sh 'go test ./internal/collect/collectors/ -run "TestFilesHome|TestFilesRhosts" -count=1'` (the mountinfo/home walk against a real host confirms `on_remote_fs` and the interactive filter). Commit:

```bash
git add internal/collect/collectors/files_home.go internal/collect/collectors/files.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Enumerate home directories, shell environment files and .rhosts in the files collector"
```

---

### Task 3: /root, /etc/hosts.equiv and the /dev walk

**Files:**
- Create: `internal/collect/collectors/files_dev.go`, tests in `collectors_test.go`
- Modify: `internal/collect/collectors/files.go` (`runFiles`, `Declare.Reads`), `internal/facts/registry.yaml` (root_home group + hosts_equiv + dev keys), golden
- Create fixtures: `hosts_equiv`, and a `/dev` set exercised through `dirs`/`stats`/`files` maps

**Interfaces:**
- Consumes: `writePermFacts` (for `/root` — but see the ruling below), `collect.Access` (`Glob`, `Stat`, `ReadFile`), the `mountTable` from Task 2, `splitLines`.
- Produces:
  - `devEntries(a, mounts mountTable) (entries facts.Envelope, nondevice facts.Envelope)` → `files.dev_entries`, `files.dev_nondevice`.
  - the `files.root_home.*` leaves and `files.etc_hosts_equiv.*` + `files.etc_hosts_equiv_lines`.

- [ ] **Step 1: Write the failing test — a regular file on devtmpfs is dev_nondevice**

```go
// /dev holds device nodes; a regular file living on devtmpfs (or tmpfs at
// /dev) is a stale/planted file U-26 flags. A character/block device is not.
func TestFilesDevNonDevice(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/proc/self/mountinfo": "mountinfo_dev"}, // /dev -> devtmpfs
		dirs:  map[string]bool{"/dev": true},
		stats: map[string]statResult{
			"/dev/null":    {mode: 0o666, kind: "chardev"},
			"/dev/planted": {mode: 0o644, kind: "regular"},
		},
	}
	// Glob("/dev/*") over the fixture returns both entries.
	b := build(t, "files", a)
	nd := okList(t, b, "files.dev_nondevice")
	if len(nd) != 1 || nd[0].(map[string]any)["name"] != "planted" {
		t.Fatalf("dev_nondevice %v, want just the regular file", nd)
	}
	all := okList(t, b, "files.dev_entries")
	if len(all) < 2 {
		t.Errorf("dev_entries should list every /dev node: %v", all)
	}
}
```

Fixture `mountinfo_dev`: a line giving `/dev` fstype `devtmpfs`.

- [ ] **Step 2: Run it — FAIL (no dev_entries).**

Run: `go test ./internal/collect/collectors/ -run TestFilesDevNonDevice -v`

- [ ] **Step 3: Implement `files_dev.go`**

```go
//go:build linux

package collectors

import (
	"path"
	"sort"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const devMaxEntries = 4096 // a bound so a pathological /dev cannot blow the snapshot

// devEntries walks /dev one and two levels deep (globs, sorted), stats each,
// and records name/kind/fstype/mode/uid. dev_nondevice is the derived subset
// that is a regular file on a devtmpfs/tmpfs mount — the planted-file case.
func devEntries(a collect.Access, mounts mountTable) (facts.Envelope, facts.Envelope) {
	var paths []string
	for _, g := range []string{"/dev/*", "/dev/*/*"} {
		if m, err := a.Glob(g); err == nil {
			paths = append(paths, m...)
		}
	}
	sort.Strings(paths)
	if len(paths) > devMaxEntries {
		paths = paths[:devMaxEntries]
	}
	entries := []any{}
	nondevice := []any{}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if err != nil {
			continue
		}
		fs := mounts.fstype(p)
		rec := map[string]any{
			"name": path.Base(p), "path": p, "kind": meta.Kind,
			"fstype": fs, "mode": int(meta.Mode), "uid": int(meta.UID),
		}
		entries = append(entries, rec)
		if meta.Kind == "regular" && (fs == "devtmpfs" || fs == "tmpfs") {
			nondevice = append(nondevice, rec)
		}
	}
	src := &facts.Source{Kind: "file", Path: "/dev"}
	return collect.OK(entries, src), collect.OK(nondevice, src)
}
```

- [ ] **Step 4: Wire /root, /etc/hosts.equiv and /dev into `runFiles`**

Add to `Declare.Reads`: `"/root"`, `"/etc/hosts.equiv"`, `"/dev/*"`, `"/dev/*/*"`. In `runFiles` (reuse the `mounts` from Task 2 — compute it once and pass it to both `homeDirs` and `devEntries`):

- `/root`: **ruling** — `writePermFacts` registers ten leaves including `group`/`group_readable`/`acl_entries` that `/root` does not need; register only the six `root_home` leaves named in the key inventory. Either add a `writePermFactsSubset` or write the six leaves inline from a single `a.Stat("/root")` (mode/uid/gid + group_writable/other_writable/acl_present); a stat failure reaches all six. Prefer inline to avoid over-registering.
- `/etc/hosts.equiv`: `files.etc_hosts_equiv.{mode,uid}` from stat, and `files.etc_hosts_equiv_lines` from a read (non-comment lines, `[]any{}` when empty, the read error on both keys when denied — the same shape `files.etc_hosts_lpd_lines` already uses).
- `/dev`: `de, nd := devEntries(a, mounts); b.Set("files.dev_entries", de); b.Set("files.dev_nondevice", nd)`.

- [ ] **Step 5: The remaining Task-3 tests**

```go
// /root permission facts come from stat only; a stat failure reaches all six
// leaves.
func TestFilesRootHome(t *testing.T) {
	a := &fsAccess{stats: map[string]statResult{"/root": {mode: 0o700, uid: 0, gid: 0, kind: "dir"}},
		files: map[string]string{"/proc/self/mountinfo": "mountinfo"}}
	b := build(t, "files", a)
	if env(t, b, "files.root_home.mode").Value != 0o700 {
		t.Errorf("root_home.mode %+v", env(t, b, "files.root_home.mode"))
	}
	if env(t, b, "files.root_home.other_writable").Value != false {
		t.Error("0700 /root is not other-writable")
	}
}

// /etc/hosts.equiv lines are recorded; an absent file yields absent leaves,
// not an error.
func TestFilesHostsEquiv(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/hosts.equiv": "hosts_equiv", "/proc/self/mountinfo": "mountinfo"},
		stats: map[string]statResult{"/etc/hosts.equiv": {mode: 0o644, uid: 0, kind: "regular"}}}
	lines := okList(t, build(t, "files", a), "files.etc_hosts_equiv_lines")
	if len(lines) == 0 {
		t.Error("hosts.equiv non-comment lines must be recorded")
	}
}
```

Fixture `hosts_equiv`: `+` on a line (a synthetic dangerous entry) and a comment.

- [ ] **Step 6: Register the keys, regenerate the golden**

Register `files.root_home.{mode,uid,gid,group_writable,other_writable,acl_present}` (int×3, bool×3), `files.etc_hosts_equiv.{mode,uid}` (int×2) + `files.etc_hosts_equiv_lines` (list<string>), `files.dev_entries` + `files.dev_nondevice` (list<record>). All `since: 1`, `sensitivity: public`, `collector: files`. Regenerate + review.

- [ ] **Step 7: Windows gates + lab host, commit**

Windows gates; then `bash lab-run.sh 'go test ./internal/collect/collectors/ -run "TestFilesDev|TestFilesRootHome|TestFilesHostsEquiv" -count=1'` and `bash lab-run.sh 'go test ./internal/collect/... -count=1'` (the real /dev walk and mountinfo). Commit:

```bash
git add internal/collect/collectors/files_dev.go internal/collect/collectors/files.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Add /root, /etc/hosts.equiv and the bounded /dev walk to the files collector"
```

---

### Task 4: U-12's shell-TMOUT mechanism, U-30 (UMASK) and U-14 (root home and PATH)

**Files:**
- Modify: `controls/account/session_timeout.yaml` (U-12) + a new fixture
- Create: `controls/account/umask_policy.yaml` (U-30) + fixtures, `controls/account/root_home_and_path.yaml` (U-14) + fixtures

**Interfaces:**
- Consumes: `env.shell.tmout`/`.tmout_exported` (T1), `env.shell.root_path_raw`/`.root_path_entries` (T1), `accounts.login_defs.umask` (2B), `pam.umask_module.enabled` (2C), `files.root_home.*` (T3).
- Produces: U-12 with two mechanisms; the U-30 and U-14 controls; count reaches 24 after this task (U-30, U-14 new).

- [ ] **Step 1: Amend U-12 — add the shell-TMOUT mechanism and resolve 2D's S3**

In `controls/account/session_timeout.yaml`:
- Drop the `applies_when: [{fact: services.ssh.installed, ...}]` block (the control now applies to any host — a host with neither an sshd timeout nor a shell TMOUT genuinely has no idle timeout, and `absent_means: fail` states that).
- **R (resolves 2D S3):** add `{ fact: sshd.options.client_alive_count_max, on: effective, op: present }` to mechanism 1's `when`, so a parse-fallback host whose config has `ClientAliveInterval` but no `ClientAliveCountMax` line falls through to the TMOUT mechanism (or `absent_means`) instead of FAILing where the daemon path would PASS.
- Add mechanism 2 (shell TMOUT) and a `max_idle` param:
```yaml
params:
  max_interval: { type: int, default: 300, description: The largest ClientAliveInterval in seconds that counts as a session timeout }
  max_count: { type: int, default: 3, description: The largest ClientAliveCountMax that counts as a session timeout }
  max_idle: { type: int, default: 600, description: The largest shell TMOUT in seconds that counts as a session timeout }
mechanisms:
  - when:
      - { fact: sshd.options.client_alive_interval, on: effective, op: gte, expected: 1 }
      - { fact: sshd.options.client_alive_count_max, on: effective, op: present }
    checks:
      - { fact: sshd.options.client_alive_interval, on: effective, op: lte, expected: "${max_interval}" }
      - { fact: sshd.options.client_alive_count_max, on: effective, op: gte, expected: 1 }
      - { fact: sshd.options.client_alive_count_max, on: effective, op: lte, expected: "${max_count}" }
  - when:
      - { fact: env.shell.tmout, op: gte, expected: 1 }
    checks:
      - { fact: env.shell.tmout, op: lte, expected: "${max_idle}" }
      - { fact: env.shell.tmout_exported, op: eq, expected: true }
```
- Add the shell-idle STIG refs to the existing `references.stig` list:
```yaml
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-412030 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-200060 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-412035 }
```
- Rewrite the description (EN+KO) to say both mechanisms are now judged (SSH `ClientAlive` or a shell `TMOUT` that is set, at most `max_idle`, and exported), and drop the "applies only where sshd is installed / TMOUT added in a later plan" sentence.

New U-12 fixtures in `controls/testdata/muster.account.session_timeout/`:
- `pass-tmout.json` — `sshd.options.client_alive_interval.effective` 0 (mechanism 1 `when` fails), `env.shell.tmout` 600, `env.shell.tmout_exported` true → PASS (mechanism 2). (No `services.ssh.installed` needed now.)
- `fail-tmout-not-exported.json` — tmout 600, exported false → mechanism 2 chosen, check fails → FAIL.
- Update the existing `na-no-ssh.json`: it asserted NOT_APPLICABLE via the old `applies_when`. Now the control applies; rename/replace it with `fail-no-timeout.json` — ssh not installed (interval absent), tmout 0 → no mechanism → `absent_means: fail` → FAIL. (Confirm the other existing fixtures still hold: `pass-interval-300`/`pass-interval-60-count-3` still PASS via mechanism 1; `fail-count-0`/`fail-interval-too-long`/`fail-count-too-high` still FAIL; `warn-parse-fallback` — add `client_alive_count_max` effective present so mechanism 1 stays chosen and it stays WARN.)

- [ ] **Step 2: Write U-30 (`controls/account/umask_policy.yaml`)**

```yaml
id: muster.account.umask_policy
title_en: The default file-creation mask denies group and other write
title_ko: 기본 파일 생성 마스크가 그룹·기타 쓰기를 막는다
description_en: The default UMASK in login.defs must be 022 or stricter so new files are not group- or world-writable, and pam_umask must be stacked so the mask applies to sessions that never read /etc/profile (cron, non-login SSH). The parameter lists the masks that count as strict enough; a host that sets a weaker mask, or that does not stack pam_umask, is reported. Every umask assignment muster found in the shell profile files is attached as evidence but not judged here, because a symbolic mask cannot be compared numerically by the clause grammar; a weak profile mask shows in the evidence for review.
description_ko: login.defs 의 기본 UMASK 가 022 이상으로 엄격해 새 파일이 그룹·전체 쓰기 가능이 되지 않아야 하고, /etc/profile 을 읽지 않는 세션(cron, 비로그인 SSH)에도 마스크가 적용되도록 pam_umask 가 올라가 있어야 합니다. 파라미터는 충분히 엄격한 것으로 인정하는 마스크 목록이며, 더 약한 마스크를 설정했거나 pam_umask 를 올리지 않은 호스트는 보고됩니다. 셸 프로파일 파일에서 찾은 모든 umask 설정은 근거로 첨부되지만, 기호식 마스크는 절 문법으로 수치 비교를 할 수 없어 여기서 판정하지 않고 근거로만 검토에 제공됩니다.
category: account
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-30"], "2021": ["U-56"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411025 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
params:
  acceptable: { type: list<string>, default: ["022", "027", "077", "0022", "0027", "0077"], description: UMASK values that deny at least group and other write }
checks:
  - { fact: accounts.login_defs.umask, op: in, expected: "${acceptable}" }
  - { fact: pam.umask_module.enabled, op: eq, expected: true }
remediation:
  text_en: Set UMASK 027 in /etc/login.defs and ensure a "session optional pam_umask.so" line is present in the login and non-login PAM session stacks (pam-auth-update on Debian, authselect on RHEL).
  text_ko: /etc/login.defs 에 UMASK 027 을 설정하고 로그인·비로그인 PAM 세션 스택에 "session optional pam_umask.so" 줄이 있게 합니다(Debian 은 pam-auth-update, RHEL 은 authselect).
  risk: none
  idempotent: true
```

- [ ] **Step 3: Write U-14 (`controls/account/root_home_and_path.yaml`)**

```yaml
id: muster.account.root_home_and_path
title_en: root's home directory and PATH are safe
title_ko: root 홈 디렉터리와 PATH 가 안전하다
description_en: root's home directory must be owned by root and not group- or world-writable, and root's PATH (as set in the system profile files) must not contain an empty element, ".", a relative directory, or a world-writable directory - any of which lets another user place a binary that root would run. When the profile files set no PATH for root, only the home-directory permissions are judged; the sudo secure_path is added in a later plan. A world-writable or non-root-owned home is a direct privilege-escalation path.
description_ko: root 홈 디렉터리는 root 소유여야 하고 그룹·전체 쓰기가 가능하면 안 되며, (시스템 프로파일 파일에 설정된) root 의 PATH 에 빈 요소, ".", 상대 경로, 전체 쓰기 가능 디렉터리가 있으면 안 됩니다. 어느 것이든 다른 사용자가 root 가 실행할 바이너리를 심을 수 있게 합니다. 프로파일 파일이 root PATH 를 설정하지 않으면 홈 디렉터리 권한만 판정하며, sudo secure_path 는 이후 플랜에서 추가됩니다. 전체 쓰기 가능하거나 root 소유가 아닌 홈은 곧바로 권한 상승 경로가 됩니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-14"], "2021": ["U-19"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411055 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
mechanisms:
  - when:
      - { fact: env.shell.root_path_raw, op: present }
    checks:
      - { fact: files.root_home.uid, op: eq, expected: 0 }
      - { fact: files.root_home.group_writable, op: eq, expected: false }
      - { fact: files.root_home.other_writable, op: eq, expected: false }
      - { fact: env.shell.root_path_entries, op: none, where: { field: is_dot, op: eq, expected: true } }
      - { fact: env.shell.root_path_entries, op: none, where: { field: world_writable, op: eq, expected: true } }
  - when:
      - { fact: files.root_home.uid, op: present }
    checks:
      - { fact: files.root_home.uid, op: eq, expected: 0 }
      - { fact: files.root_home.group_writable, op: eq, expected: false }
      - { fact: files.root_home.other_writable, op: eq, expected: false }
remediation:
  text_en: chown root:root /root, chmod 700 /root, and remove any empty, ".", relative, or world-writable entry from root's PATH in /etc/profile and root's shell startup files.
  text_ko: chown root:root /root, chmod 700 /root 를 적용하고, /etc/profile 과 root 의 셸 시작 파일에서 root PATH 의 빈 요소, ".", 상대 경로, 전체 쓰기 가능 항목을 제거합니다.
  risk: none
  idempotent: true
```

- [ ] **Step 4: Fixtures for U-30 and U-14**

`controls/testdata/muster.account.umask_policy/`:
- `pass-022.json` — `accounts.login_defs.umask` ok "022", `pam.umask_module.enabled` ok true → PASS.
- `pass-077.json` — umask "077", pam true → PASS.
- `fail-weak-umask.json` — umask "000", pam true → FAIL.
- `fail-no-pam-umask.json` — umask "022", pam.umask_module.enabled ok false → FAIL.
- `error-pam-umask.json` — `pam.umask_module.enabled` `{"status":"error","reason":"PAM stack incomplete"}` → ERROR(parse_error); `_expect: {"status":"ERROR","reason_code":"parse_error"}`.

`controls/testdata/muster.account.root_home_and_path/`:
- `pass-clean.json` — `env.shell.root_path_raw` ok "/usr/sbin:/usr/bin"; `env.shell.root_path_entries` two rows, both is_dot false / world_writable false; `files.root_home` uid 0, group_writable false, other_writable false → PASS (mechanism 1).
- `fail-world-writable-path.json` — a root_path_entries row with world_writable true → FAIL.
- `fail-dot-in-path.json` — a row with is_dot true (empty element) → FAIL.
- `fail-home-group-writable.json` — root_home group_writable true → FAIL.
- `pass-no-path.json` — `env.shell.root_path_raw` `{"status":"absent","reason":"no PATH assignment"}`; root_home uid 0, not writable → PASS (mechanism 2, home only).
- `error-home-denied.json` — `files.root_home.uid` `{"status":"denied","reason":"/root: permission denied"}` (other leaves too) → ERROR(permission_denied); `_expect: {"status":"ERROR","reason_code":"permission_denied"}`.

- [ ] **Step 5: Lint and the behaviour test**

```
go run ./cmd/muster controls lint --references docs/reference
go run ./cmd/muster controls lint --fixtures controls/testdata
go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1
go test ./internal/check/ -count=1
```
Both lints must end `ok: 24 controls`. Confirm the reworked U-12 fixtures all behave.

- [ ] **Step 6: Commit**

```bash
git add controls/account/session_timeout.yaml controls/account/umask_policy.yaml controls/account/root_home_and_path.yaml controls/testdata
git commit -m "Add U-12's shell-TMOUT mechanism and the UMASK and root-home controls"
```

---

### Task 5: The home and environment controls — U-24, U-26, U-27, U-31, U-32

**Files:**
- Create: `controls/file/env_file_permissions.yaml`, `dev_no_stale_files.yaml`, `rhosts_forbidden.yaml`, `home_dir_permissions.yaml`, `home_dir_exists.yaml` + fixture directories

**Interfaces:**
- Consumes: `files.env_files`, `files.dev_nondevice`, `files.user_rhosts`, `files.etc_hosts_equiv_lines`, `files.home_dirs` (T2/T3).
- Produces: five controls; count reaches 29.

- [ ] **Step 1: Write the five controls**

`controls/file/env_file_permissions.yaml` (U-24):
```yaml
id: muster.file.env_file_permissions
title_en: Shell environment files are owned correctly and not writable by others
title_ko: 셸 환경변수 파일이 올바른 소유자를 갖고 타인이 쓸 수 없다
description_en: Every system and per-user shell environment file (/etc/profile, the bashrc files, and each interactive user's dotfiles) must be owned by root or by the account whose home it sits in, and must not be group- or world-writable, so no other user can inject commands into a login. A symlinked environment file is treated as not correctly owned. Only interactive accounts' dotfiles are examined; service accounts with a nologin shell are skipped.
description_ko: 모든 시스템·사용자별 셸 환경변수 파일(/etc/profile, bashrc 계열, 각 대화형 사용자의 dotfile)은 root 또는 그 홈의 계정이 소유해야 하고 그룹·전체 쓰기가 가능하면 안 되어, 다른 사용자가 로그인에 명령을 주입할 수 없어야 합니다. 심볼릭 링크인 환경 파일은 소유가 올바르지 않은 것으로 봅니다. nologin 셸을 쓰는 서비스 계정은 건너뛰고 대화형 계정의 dotfile 만 점검합니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-24"], "2021": ["U-53"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232045 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: manual
checks:
  - { fact: files.env_files, op: none, where: { field: owner_ok, op: eq, expected: false } }
  - { fact: files.env_files, op: none, where: { field: group_writable, op: eq, expected: true } }
  - { fact: files.env_files, op: none, where: { field: other_writable, op: eq, expected: true } }
remediation:
  text_en: chown the file to root or the home owner and chmod go-w; replace a symlinked environment file with a regular file.
  text_ko: 해당 파일을 root 또는 홈 소유자로 chown 하고 chmod go-w 를 적용하며, 심볼릭 링크인 환경 파일은 일반 파일로 교체합니다.
  risk: none
  idempotent: true
```

`controls/file/dev_no_stale_files.yaml` (U-26):
```yaml
id: muster.file.dev_no_stale_files
title_en: /dev holds no regular files
title_ko: /dev 에 일반 파일이 없다
description_en: /dev is served by devtmpfs and should hold only device nodes. A regular file living there is either a leftover or a planted file used to smuggle data past a device-only expectation, so any regular file on the /dev filesystem is reported. Device nodes, directories and symlinks are not flagged.
description_ko: /dev 는 devtmpfs 가 제공하며 장치 노드만 있어야 합니다. 그곳의 일반 파일은 잔재이거나, 장치만 있으리라는 기대를 우회해 데이터를 숨기는 데 쓰이는 심어진 파일이므로, /dev 파일시스템의 일반 파일은 모두 보고합니다. 장치 노드·디렉터리·심볼릭 링크는 표시하지 않습니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-26"], "2021": ["U-58"] }
requires_facts: ">=1"
absent_means: manual
checks:
  - { fact: files.dev_nondevice, op: none, where: { field: name, op: present } }
remediation:
  text_en: Investigate each regular file under /dev; remove it once you have confirmed nothing legitimate created it (a package or an application writing to /dev is the exception to check first).
  text_ko: /dev 아래의 각 일반 파일을 조사하고, 정당하게 생성된 것이 없음을 확인한 뒤 제거합니다(패키지나 애플리케이션이 /dev 에 쓰는 경우가 먼저 확인할 예외입니다).
  risk: none
  idempotent: false
```

`controls/file/rhosts_forbidden.yaml` (U-27):
```yaml
id: muster.file.rhosts_forbidden
title_en: No .rhosts or hosts.equiv grants blanket trust
title_ko: .rhosts 나 hosts.equiv 가 무조건 신뢰를 허용하지 않는다
description_en: The r-command trust files must not grant blanket access - no interactive user's ~/.rhosts or ~/.shosts may contain a "+" entry, and /etc/hosts.equiv must not begin a line with "+". A "+" trusts every host or user, defeating authentication. Only the trust files muster could read are judged here; a home directory muster could not read is reported by the home-permission control (U-31). The absence of any such file is compliant.
description_ko: r-command 신뢰 파일이 무조건 접근을 허용하면 안 됩니다. 어떤 대화형 사용자의 ~/.rhosts 나 ~/.shosts 도 "+" 항목을 담으면 안 되고, /etc/hosts.equiv 도 줄을 "+" 로 시작하면 안 됩니다. "+" 는 모든 호스트나 사용자를 신뢰해 인증을 무력화합니다. 여기서는 muster 가 읽을 수 있었던 신뢰 파일만 판정하며, 읽을 수 없었던 홈 디렉터리는 홈 권한 컨트롤(U-31)이 보고합니다. 그런 파일이 아예 없으면 양호입니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-27"], "2021": ["U-17"] }
requires_facts: ">=1"
absent_means: pass
checks:
  - { fact: files.user_rhosts, op: none, where: { field: has_plus, op: eq, expected: true } }
  - { fact: files.etc_hosts_equiv_lines, op: none, where: { op: matches, expected: "^\\+" } }
remediation:
  text_en: Remove the "+" entries from the offending ~/.rhosts, ~/.shosts and /etc/hosts.equiv, or remove the files entirely if r-command trust is not in use.
  text_ko: 문제되는 ~/.rhosts, ~/.shosts, /etc/hosts.equiv 에서 "+" 항목을 제거하거나, r-command 신뢰를 쓰지 않으면 파일을 아예 삭제합니다.
  risk: none
  idempotent: true
```

`controls/file/home_dir_permissions.yaml` (U-31):
```yaml
id: muster.file.home_dir_permissions
title_en: Interactive home directories are owned by their user and not writable by others
title_ko: 대화형 홈 디렉터리가 사용자 소유이며 타인이 쓸 수 없다
description_en: Each interactive account's home directory must be owned by that account and must not be group- or world-writable. A home muster could not stat (an unreadable parent) is reported here rather than passed silently, since an unexaminable home could hide anything. Service accounts with a nologin shell are skipped so a host's thirty /nonexistent service homes do not each become a finding.
description_ko: 각 대화형 계정의 홈 디렉터리는 해당 계정 소유여야 하고 그룹·전체 쓰기가 가능하면 안 됩니다. muster 가 stat 할 수 없었던 홈(상위 디렉터리를 읽을 수 없는 경우)은 조용히 통과시키지 않고 여기서 보고합니다. 점검 불가한 홈은 무엇이든 숨길 수 있기 때문입니다. nologin 셸의 서비스 계정은 건너뛰어, 호스트의 서른 개 /nonexistent 서비스 홈이 각각 findings 가 되지 않게 합니다.
category: file
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-31"], "2021": ["U-59"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232050 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411070 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: manual
checks:
  - { fact: files.home_dirs, op: each, subject: user, where: { field: interactive, op: eq, expected: true }, require: { field: owner_matches, op: eq, expected: true } }
  - { fact: files.home_dirs, op: each, subject: user, where: { field: interactive, op: eq, expected: true }, require: { field: group_writable, op: eq, expected: false } }
  - { fact: files.home_dirs, op: each, subject: user, where: { field: interactive, op: eq, expected: true }, require: { field: other_writable, op: eq, expected: false } }
remediation:
  text_en: chown each interactive home to its account and chmod go-w (0750 or stricter). Where a home could not be stat'd, fix the parent directory's permissions so it can be audited.
  text_ko: 각 대화형 홈을 해당 계정으로 chown 하고 chmod go-w(0750 이상 엄격)를 적용합니다. stat 할 수 없었던 홈은 상위 디렉터리 권한을 고쳐 점검할 수 있게 합니다.
  risk: none
  idempotent: true
```

`controls/file/home_dir_exists.yaml` (U-32):
```yaml
id: muster.file.home_dir_exists
title_en: Every interactive account has a home directory that exists
title_ko: 모든 대화형 계정이 실제 존재하는 홈 디렉터리를 가진다
description_en: Each interactive account's home directory named in /etc/passwd must exist and be a directory. An account whose home is missing lands in / on login and may write into unexpected places; an account whose home muster could not stat is reported rather than assumed present. Service accounts with a nologin shell (whose home is often /nonexistent by design) are skipped.
description_ko: /etc/passwd 에 적힌 각 대화형 계정의 홈 디렉터리가 실제로 존재하고 디렉터리여야 합니다. 홈이 없는 계정은 로그인 시 / 로 떨어져 예상치 못한 곳에 쓸 수 있으며, muster 가 stat 할 수 없었던 홈은 존재한다고 단정하지 않고 보고합니다. nologin 셸의 서비스 계정(홈이 흔히 의도적으로 /nonexistent)은 건너뜁니다.
category: file
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-32"], "2021": ["U-60"] }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411065 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411020 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: manual
checks:
  - { fact: files.home_dirs, op: each, subject: user, where: { field: interactive, op: eq, expected: true }, require: { field: stat_status, op: eq, expected: "ok" } }
  - { fact: files.home_dirs, op: each, subject: user, where: { field: interactive, op: eq, expected: true }, require: { field: is_dir, op: eq, expected: true } }
remediation:
  text_en: Create the missing home directory (mkhomedir_helper or mkdir + chown + chmod 0750), or correct the home path in /etc/passwd. Where a home could not be stat'd, fix the parent directory's permissions.
  text_ko: 없는 홈 디렉터리를 생성하거나(mkhomedir_helper 또는 mkdir + chown + chmod 0750) /etc/passwd 의 홈 경로를 바로잡습니다. stat 할 수 없었던 홈은 상위 디렉터리 권한을 고칩니다.
  risk: none
  idempotent: true
```

- [ ] **Step 2: Fixtures**

Each fixture is `{"synthetic": true, "schema_version": 1, "run": {}, "facts": {"files": {…}}}` with only the leaves the control reads. `home_dirs` rows must carry `user`, `interactive`, and the fields the control requires (`owner_matches`/`group_writable`/`other_writable`/`stat_status`/`is_dir`), with the collector's rule that a non-`ok` row still carries `owner_matches`/`group_writable`/`other_writable` as `false`.

- `env_file_permissions/`: `pass-clean.json` (two env_files rows, owner_ok true, not writable → PASS); `fail-group-writable.json` (a row group_writable true → FAIL); `fail-not-owned.json` (owner_ok false → FAIL); `fail-symlink.json` (is_symlink true, owner_ok false → FAIL); `manual-empty.json` (`files.env_files` `{"status":"absent","reason":"…"}` → MANUAL). Note: an empty `[]` list PASSes vacuously, so use `absent` (not `[]`) for the manual case.
- `dev_no_stale_files/`: `pass-clean.json` (`files.dev_nondevice` `[]` → PASS); `fail-regular.json` (one row `{name,kind:"regular"}` → FAIL); `manual-absent.json` (`dev_nondevice` absent → MANUAL).
- `rhosts_forbidden/`: `pass-none.json` (`user_rhosts` `[]`, `etc_hosts_equiv_lines` `[]` → PASS); `pass-rhosts-no-plus.json` (a user_rhosts row has_plus false → PASS); `fail-plus.json` (a row has_plus true → FAIL); `fail-hosts-equiv-plus.json` (`etc_hosts_equiv_lines` `["+"]` → FAIL); `pass-absent.json` (`user_rhosts` `[]` and `etc_hosts_equiv_lines` `[]` — the compliant empty case is PASS, not absent; a genuinely absent `files.user_rhosts` → `absent_means: pass`). Confirm `etc_hosts_equiv_lines` is `[]` (not absent) when the file does not exist, per Task 3's ruling.
- `home_dir_permissions/`: `pass-clean.json` (root + alice interactive, owner_matches true, not writable; a svc row interactive false is ignored → PASS); `fail-group-writable.json` (alice group_writable true → FAIL); `fail-not-owned.json` (owner_matches false → FAIL); `fail-denied.json` (alice interactive, stat_status "denied", owner_matches false → FAIL — the unreadable-home hazard surfaces as a finding); `manual-absent.json` (`files.home_dirs` absent → MANUAL).
- `home_dir_exists/`: `pass-clean.json` (interactive homes stat_status ok, is_dir true → PASS); `fail-missing.json` (alice interactive, stat_status "absent" → FAIL); `fail-denied.json` (stat_status "denied" → FAIL); `pass-service-skipped.json` (only a nologin svc account with stat_status absent, interactive false → PASS, vacuously — the service home is skipped); `manual-absent.json` (home_dirs absent → MANUAL).

- [ ] **Step 3: Lint, behaviour test, real host**

```
go run ./cmd/muster controls lint --references docs/reference   # ok: 29 controls
go run ./cmd/muster controls lint --fixtures controls/testdata  # ok: 29 controls
go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1
go test ./internal/check/ ./internal/controls/ -count=1
```
Then the lab host, root, stock Ubuntu 22.04: `bash lab-sync.sh <worktree>`, build, `collect --require-root --require-complete`, `check --format json`; report the `<id> <status>` lines for the seven new/amended controls and the leaves `.facts.env.shell.tmout.value`, `.facts.files.home_dirs` count, `.facts.files.dev_nondevice` count. Quote only those.

- [ ] **Step 4: Commit**

```bash
git add controls/file/env_file_permissions.yaml controls/file/dev_no_stale_files.yaml controls/file/rhosts_forbidden.yaml controls/file/home_dir_permissions.yaml controls/file/home_dir_exists.yaml controls/testdata
git commit -m "Add the environment-file, /dev, rhosts and home-directory controls"
```

---

### Task 6: End-to-end snapshots, counts, coverage and the README

**Files:**
- Modify: `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go` (`22` → `29`), `docs/reference/coverage.md` (regenerated), `README.md`, `README.ko.md`

- [ ] **Step 1: Extend the snapshots**

Add to `full-pass.json` under `facts.env`: `shell.tmout` 0, `shell.tmout_exported` false, `shell.umask_settings` `[]`, `shell.root_path_raw` "/usr/sbin:/usr/bin", `shell.root_path_entries` two clean rows. Under `facts.accounts.login_defs`: `umask` "022" (if not already present from 2B — check; 2B added it). Under `facts.pam`: `umask_module.enabled` true (2C added the key; ensure the snapshot carries it). Under `facts.files`: `root_home` (uid 0, not writable), `env_files` (two clean rows), `user_rhosts` `[]`, `etc_hosts_equiv_lines` `[]`, `home_dirs` (root + one interactive user, ok/owned/not-writable), `dev_nondevice` `[]`. Make every new-control verdict a PASS. For `full-fail.json`, keep its single existing FAIL and add the SAME clean env/files values so the seven new controls PASS there too (a second FAIL would break the R26 invariant unless intended — keep root_remote_login the only FAIL).

**U-12 in the snapshots:** the pass snapshot must satisfy U-12 now that it always applies — give `full-pass.json` a passing mechanism (either `sshd.options.client_alive_interval` 300 + `client_alive_count_max` 1, already present from 2D, or `env.shell.tmout` 600 exported). Confirm `full-fail.json` also passes U-12 (it has the sshd timeout from 2D). If either snapshot has sshd count 0 / interval 0 and no TMOUT, U-12 would now FAIL there — set a passing mechanism.

- [ ] **Step 2: e2e maps and counts**

`e2e_test.go`: add the seven new controls to both expected-status maps as PASS (in the fail map the only FAIL stays `root_remote_login`). Update the count comments (twenty-nine). `controls_test.go`: both `"ok: 22 controls"` → `"ok: 29 controls"`.

- [ ] **Step 3: Coverage**

```
go run ./tools/coverage
go run ./tools/coverage -check
```
`docs/reference/coverage.md` now shows U-14, U-24, U-26, U-27, U-30, U-31, U-32 enrolled; header `29 of 67 items enrolled (auto 25, partial 4, manual 0)`.

- [ ] **Step 4: README pair**

Extend the merged-plans sentence to name this plan: `README.md` "...and the completed sshd collector with login banners, and the home-directory and shell-environment checks."; `README.ko.md` "...완성된 sshd 수집기와 로그인 배너, 그리고 홈 디렉터리·셸 환경 점검." No control ids enumerated; nothing else changes.

- [ ] **Step 5: Gates and the host**

Windows: `gofmt -l .`; `GOOS=linux GOARCH=amd64 go vet ./...`; `go test ./internal/facts/ ./internal/check/ ./internal/controls/ ./cmd/muster/ -count=1`; both lints `ok: 29 controls`; `go run ./tools/coverage -check` exit 0. Host: sync and `bash lab-run.sh 'sudo env PATH="$PATH" go test ./internal/collect/... ./cmd/muster/ -count=1 -race -shuffle=on'`, plus a real `collect`/`check` proof as in Task 5.

- [ ] **Step 6: Commit**

```bash
git add cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md README.md README.ko.md
git commit -m "Enrol the home and shell-environment controls end to end and regenerate the coverage table"
```

---

## Self-review

**Spec coverage.** §5.4 env `shell.*` → T1; files `home_dirs`/`env_files`/`user_rhosts`/`root_home`/`etc_hosts_equiv`/`dev_entries` → T2/T3. §6.5 screening and the mixed-absence hazard → U-12/U-14 use `mechanisms` so an absent PATH or count does not screen the whole control; U-27 relies on `etc_hosts_equiv_lines` being `[]` (not absent) when the file is missing (Task 3 ruling). §7.3 honesty → `stat_status` distinguishes `denied` from `absent`; a denied home is a finding, not a pass. §10.2 items U-12 (amended), U-14, U-24, U-26, U-27, U-30, U-31, U-32 → T4/T5. Every new control carries `references.stig`/`nist_800_53` where a mapping exists (U-26 and U-27 have no clean DISA rule and carry KISA only).

**Placeholder scan.** The one `|| true` in `envFileRow` is explicitly flagged as a stand-in with the real computation specified in the owner_ok ruling — the implementer must not ship it. `mustRead` in Task 2 Step 4 is named and its behaviour (return bytes, or write the three keys as the read error and return) is specified. No other TBD/TODO.

**Type consistency.** `shellAssignment.Kind` ∈ `tmout|umask|path`; `home_dirs.stat_status` ∈ `ok|absent|denied`; `interactive` is a bool on every `home_dirs` row; `env.shell.tmout` is int, `tmout_exported`/`tmout_readonly` bool; control ids `muster.account.{umask_policy,root_home_and_path}` and `muster.file.{env_file_permissions,dev_no_stale_files,rhosts_forbidden,home_dir_permissions,home_dir_exists}`. Count 22 → 29 (7 new). The `each`/`where`/`require`/`subject` grammar matches spec §6.6; `none where {op: matches}` on `etc_hosts_equiv_lines` (a `list<string>`) omits `field` (scalar element), as the grammar requires.

**Risks called out.** (1) The mixed-absence screening — handled by `mechanisms` in U-12/U-14 and by the `[]`-when-absent ruling for `etc_hosts_equiv_lines`. (2) The interactive filter is load-bearing for U-24/U-31/U-32; if `/etc/shells` is unreadable, `loginShells` returns the libc default set, so the filter still holds (a 2B behaviour). (3) A `denied` home must reach the controls as a finding, not an absent that `absent_means: pass` (U-27) could excuse — U-27 does not read `home_dirs`, and U-31/U-32 flag the denied row. (4) The collector must fill `owner_matches`/`group_writable`/`other_writable` on every `home_dirs` row (false when not `ok`) so U-31's `each … require` never compares an absent field.

## Execution notes

<!-- Filled in after execution: rulings R175+, the pre-flight scan, the whole-branch review, the fix wave, the real-host proof, and the items carried forward. -->
