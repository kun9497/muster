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
| `env.shell.root_path_entries` | `list<record>` | env | T1 | Each `PATH` element: `position`, `value`, `exists`, `mode`, `uid`, `gid`, `group_writable`, `world_writable`, `is_dot` (empty/`.`/relative), `variable` (`$`/`~`), `unresolved`, `undeclared` (outside the declared PATH-dir set). |
| `files.home_dirs` | `list<record>` | files | T2 | One row per `/etc/passwd` home: `user`, `uid`, `home`, `stat_status` (ok\|absent\|denied), `is_dir`, `mode`, `owner_uid`, `owner_matches`, `group_writable`, `other_writable`, `interactive`, `on_remote_fs`. `subject_kind: user`. |
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
- Create fixtures under `internal/collect/collectors/testdata/`: `profile`, `profile.d_10-muster.sh`, `profile.d_99-tmout.sh`, `bash.bashrc`, `root_bashrc`, `root_bashrc_badpath`, `root_profile`, `csh.cshrc`, `profile_tmout_oneline`, `profile_tmout_declare`
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
- `profile.d_10-muster.sh` — a conditional umask (scope system), multi-line so the depth tracking is genuine:
  ```
  if [ "$UID" -ge 1000 ]; then
      umask 002
  fi
  ```
- `profile_tmout_oneline` — `TMOUT=600; export TMOUT` (two statements on one line; R184).
- `profile_tmout_declare` — `declare -xr TMOUT=600` (a declaration keyword with -x/-r flags; R184).
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
	"errors"
	"io/fs"
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

// pathCandidateDirs is the fixed set of directories a system/root PATH may
// name; pathEntries stats only an element that is in this declared set (R175),
// so the collector never stats an arbitrary directory outside Declare.Reads.
var pathCandidateDirs = []string{
	"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
	"/sbin", "/bin", "/snap/bin", "/root/bin", "/usr/games", "/usr/local/games",
}

var envCollector = collect.Collector{
	Name: "env",
	Declare: collect.Declaration{
		Reads: append(append([]string{etcProfile, profileDGlob, bashBashrc, etcBashrc, cshCshrc}, rootDotfiles...), pathCandidateDirs...),
		Needs: "none",
	},
	Run: runEnv,
}

// envShellKeys are the seven env.shell.* leaves this collector writes; a
// profile file that is present but unreadable is the answer for every value it
// could set, so the read error is written to all of them (C3, R183).
var envShellKeys = []string{
	"env.shell.tmout", "env.shell.tmout_exported", "env.shell.tmout_readonly",
	"env.shell.tmout_settings", "env.shell.umask_settings",
	"env.shell.root_path_raw", "env.shell.root_path_entries",
}

func runEnv(_ context.Context, a collect.Access, b *collect.Builder) error {
	var all []shellAssignment
	for _, p := range profileReadOrder(a) {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // a profile file that simply does not exist contributes nothing
			}
			// C3 (R183): a present-but-unreadable profile file — denied, or any
			// other error — is the answer for every value it could set; write
			// the path-prefixed read error to all seven keys and stop.
			e := collect.FromReadError(err, meta)
			for _, k := range envShellKeys {
				b.Set(k, e)
			}
			return nil
		}
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
	rows := []any{}
	winnerIdx := -1
	for i := range all {
		s := all[i]
		if s.Kind != "tmout" {
			continue
		}
		rows = append(rows, map[string]any{
			"path": s.Path, "line": s.Line, "value": s.Value,
			"exported": s.Exported, "readonly": s.Readonly, "conditional": s.Conditional,
		})
		if !s.Conditional && s.Value != "" { // a bare `readonly TMOUT` has no value; it does not win
			winnerIdx = i
		}
	}
	src := &facts.Source{Kind: "derived"}
	val := 0
	exported, readonly := false, false
	if winnerIdx >= 0 {
		w := all[winnerIdx]
		// exported/readonly come from the winning assignment itself plus any
		// LATER unconditional export/readonly of TMOUT — not OR'd across every
		// row, so a conditional `export TMOUT` does not falsely mark it (L4).
		exported, readonly = w.Exported, w.Readonly
		for j := winnerIdx + 1; j < len(all); j++ {
			s := all[j]
			if s.Kind != "tmout" || s.Conditional {
				continue
			}
			exported = exported || s.Exported
			readonly = readonly || s.Readonly
		}
		if n, err := strconv.Atoi(strings.TrimSpace(w.Value)); err == nil {
			val = n
			src = &facts.Source{Kind: "file", Path: w.Path, Line: w.Line}
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
		full := strings.TrimSpace(cutComment(raw))
		if full == "" {
			continue
		}
		// blockDelta is computed on the whole physical line; conditional depth
		// applies to the statements on it.
		opens, closes := blockDelta(full)
		conditional := depth > 0
		// A single physical line may hold several statements separated by an
		// unquoted `;` (e.g. `TMOUT=600; export TMOUT`); scan each (R184).
		for _, line := range splitStatements(full) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// TMOUT: a declaration keyword (declare/typeset/export/readonly
			// with optional -x/-r/-xr flags) assigning it, else a bare
			// assignment, else a bare export/readonly of the name (R184).
			if v, exported, readonly, ok := declAssignment(line, "TMOUT"); ok {
				out = append(out, shellAssignment{Kind: "tmout", Value: v, Path: p, Line: i + 1,
					Exported: exported, Readonly: readonly, Conditional: conditional})
			} else if v, ok := assignmentValue(line, "TMOUT"); ok {
				out = append(out, shellAssignment{Kind: "tmout", Value: v, Path: p, Line: i + 1,
					Exported: strings.HasPrefix(line, "export "), Conditional: conditional})
			} else if name, ok := exportName(line); ok && name == "TMOUT" {
				out = append(out, shellAssignment{Kind: "tmout", Value: "", Path: p, Line: i + 1, Exported: true, Conditional: conditional})
			} else if name, ok := readonlyName(line); ok && name == "TMOUT" {
				out = append(out, shellAssignment{Kind: "tmout", Value: "", Path: p, Line: i + 1, Readonly: true, Conditional: conditional})
			}
			// umask
			if fields := strings.Fields(line); len(fields) >= 2 && (fields[0] == "umask" || (fields[0] == "builtin" && fields[1] == "umask")) {
				val := fields[len(fields)-1]
				out = append(out, shellAssignment{Kind: "umask", Value: val, Path: p, Line: i + 1,
					Symbolic: !isOctalMask(val), Conditional: conditional, Scope: scope})
			}
			// PATH: same declaration-keyword forms, then a bare assignment.
			if v, exported, _, ok := declAssignment(line, "PATH"); ok {
				out = append(out, shellAssignment{Kind: "path", Value: v, Path: p, Line: i + 1, Exported: exported, Conditional: conditional, Scope: scope})
			} else if v, ok := assignmentValue(line, "PATH"); ok {
				out = append(out, shellAssignment{Kind: "path", Value: v, Path: p, Line: i + 1, Conditional: conditional, Scope: scope})
			}
		}
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
	}
	return out
}
```

**Single-line `if …; then umask …; fi` (L5, noted):** splitting on `;` does not turn a
`then umask 002` fragment into a recognised `umask` statement (its first field is
`then`), and `blockDelta` nets to zero on such a line, so a umask set inside a
one-line `if` is not recorded as conditional. This is an accepted coarse-scan
limitation; the conditional-umask fixture uses the multi-line form (below) so its
`conditional=true` is genuine.

helpers in the same file:

```go
// splitStatements splits a line on unquoted `;` so several statements on one
// physical line are scanned independently, e.g. `TMOUT=600; export TMOUT` (R184).
func splitStatements(line string) []string {
	out := []string{}
	inS, inD := false, false
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ';':
			if !inS && !inD {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	return append(out, line[start:])
}

// declAssignment recognises a declaration keyword (declare, typeset, export or
// readonly) with optional -x/-r/-xr flags assigning name — `declare -xr
// TMOUT=600`, `export -r PATH=…`, `readonly TMOUT=600`, `export TMOUT=600` —
// and reports the value plus whether the form exports (-x, or the `export`
// keyword) and/or makes the name readonly (-r, or the `readonly` keyword) (R184).
func declAssignment(line, name string) (value string, exported, readonly, ok bool) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", false, false, false
	}
	switch f[0] {
	case "export":
		exported = true
	case "readonly":
		readonly = true
	case "declare", "typeset":
	default:
		return "", false, false, false
	}
	rest := f[1:]
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		if strings.Contains(rest[0], "x") {
			exported = true
		}
		if strings.Contains(rest[0], "r") {
			readonly = true
		}
		rest = rest[1:]
	}
	prefix := name + "="
	if len(rest) == 0 || !strings.HasPrefix(rest[0], prefix) {
		return "", false, false, false
	}
	v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(rest[0], prefix)), `"'`)
	return v, exported, readonly, true
}

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

// pathEntries splits a PATH value and stats each element. Every row is first
// initialised with all fields the controls judge, defaulted (R176), then a
// branch overwrites what it learns:
//   - an element beginning with $ or ~ is an unexpanded variable, recorded
//     variable+unresolved, never is_dot (R180);
//   - an empty element, ".", or a relative path is is_dot (a
//     working-directory injection risk);
//   - an element outside the declared PATH-dir set is NOT stat'd — it is
//     unresolved+undeclared (R175), so the collector never stats an arbitrary
//     directory (the guard would otherwise reject it);
//   - a declared element is stat'd; a stat failure is unresolved.
func pathEntries(a collect.Access, raw string) []any {
	out := []any{}
	for i, el := range strings.Split(raw, ":") {
		rec := map[string]any{
			"position": i, "value": el,
			"exists": false, "unresolved": false,
			"is_dot": false, "variable": false, "undeclared": false,
			"group_writable": false, "world_writable": false,
			"mode": -1, "uid": -1, "gid": -1,
		}
		switch {
		case strings.HasPrefix(el, "$") || strings.HasPrefix(el, "~"):
			rec["variable"] = true
			rec["unresolved"] = true
			out = append(out, rec)
			continue
		case el == "" || el == "." || !strings.HasPrefix(el, "/"):
			rec["is_dot"] = true
			out = append(out, rec)
			continue
		}
		if !declared(a, el) {
			rec["unresolved"] = true
			rec["undeclared"] = true
			out = append(out, rec)
			continue
		}
		meta, err := a.Stat(el)
		if err != nil {
			rec["unresolved"] = true
			out = append(out, rec)
			continue
		}
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

(`sourceRaw` already exists for other collectors and is reused; `cutComment` is
*not* shared — it is defined in this file (L3).)

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

// Root PATH is split into positioned entries. An empty element is is_dot; a
// declared world-writable directory carries world_writable=true; an element
// outside the declared PATH-dir set is not stat'd but marked
// unresolved+undeclared (R175); a $/~ element is variable+unresolved (R180).
func TestEnvRootPathEntries(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/root/.bashrc": "root_bashrc_badpath"}, // PATH=/usr/bin::/usr/local/games:/opt/x:$HOME/bin
		stats: map[string]statResult{
			"/usr/bin":         {mode: 0o755, kind: "dir"},
			"/usr/local/games": {mode: 0o777, kind: "dir"}, // declared and world-writable
		},
	}
	entries := okList(t, build(t, "env", a), "env.shell.root_path_entries")
	if len(entries) != 5 {
		t.Fatalf("entries %v, want 5 (/usr/bin, empty, /usr/local/games, /opt/x, $HOME/bin)", entries)
	}
	if entries[1].(map[string]any)["is_dot"] != true {
		t.Error("the empty element between :: must be is_dot")
	}
	if entries[2].(map[string]any)["world_writable"] != true {
		t.Error("/usr/local/games is world-writable")
	}
	if entries[3].(map[string]any)["undeclared"] != true || entries[3].(map[string]any)["unresolved"] != true {
		t.Errorf("/opt/x is outside the declared PATH-dir set: unresolved+undeclared, never stat'd: %v", entries[3])
	}
	if entries[4].(map[string]any)["variable"] != true || entries[4].(map[string]any)["is_dot"] == true {
		t.Errorf("$HOME/bin is an unexpanded variable, not is_dot: %v", entries[4])
	}
}

// A profile file that cannot be read (denied — not ENOENT) is the answer for
// every value it could set: all seven env.shell.* keys carry the path-prefixed
// read error (C3, R183), never a value salvaged from the other files.
func TestEnvDeniedProfileIsAnError(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/profile": "profile"},
		fails: map[string]error{"/etc/bash.bashrc": os.ErrPermission},
	}
	b := build(t, "env", a)
	if e := env(t, b, "env.shell.tmout"); e.Status != facts.StatusDenied {
		t.Errorf("a denied profile file must make env.shell.tmout denied, got %+v", e)
	}
}

// A line may hold several statements separated by an unquoted `;`, and a
// declaration keyword (declare/typeset/export/readonly) with -x/-r/-xr flags
// assigns TMOUT just as a bare assignment does (R184).
func TestEnvTMOUTDeclarationForms(t *testing.T) {
	b := build(t, "env", &fsAccess{files: map[string]string{"/etc/profile": "profile_tmout_oneline"}})
	if e := env(t, b, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600 from `TMOUT=600; export TMOUT`", e)
	}
	if env(t, b, "env.shell.tmout_exported").Value != true {
		t.Error("the trailing `export TMOUT` marks it exported")
	}

	b2 := build(t, "env", &fsAccess{files: map[string]string{"/etc/profile": "profile_tmout_declare"}})
	if e := env(t, b2, "env.shell.tmout"); e.Value != 600 {
		t.Errorf("tmout %+v, want 600 from `declare -xr TMOUT=600`", e)
	}
	if env(t, b2, "env.shell.tmout_readonly").Value != true {
		t.Error("`declare -xr` makes TMOUT readonly")
	}
}
```

Fixtures to add: `root_bashrc_badpath` (`PATH=/usr/bin::/usr/local/games:/opt/x:$HOME/bin` then `export PATH`); `profile_tmout_oneline` (`TMOUT=600; export TMOUT`); `profile_tmout_declare` (`declare -xr TMOUT=600`).

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
    description: Each root PATH element - position, value, exists, mode, uid, gid, group_writable, world_writable, is_dot, variable, unresolved, undeclared.
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
- Create fixtures: `passwd_home` (a synthetic /etc/passwd with root + one interactive user + one service account), `shells_home`, `mountinfo`, `mountinfo_nfs`, `home_alice_bashrc`, `home_alice_rhosts`

**Interfaces:**
- Consumes: `collect.Access` (`ReadFile`, `Stat`, `Glob`, `Allowed`), `collect.Builder`, `facts.Source`; the in-package helpers `parsePasswd(data) ([]passwdRow, int)` (fields `name, uid, gid, home, shell, line`), `loginShells(a) (map[string]bool, facts.Envelope)`, `splitLines`, `readLimit`, `collect.OK`/`Absent`/`FromReadError`; `declared(a, path)` (the guard probe from sshd.go).
- Produces:
  - `homeDirs(a, rows []passwdRow, shells map[string]bool, mounts mountTable) facts.Envelope` → `files.home_dirs`.
  - `envFiles(a, rows []passwdRow, shells map[string]bool) facts.Envelope` → `files.env_files`; the row helpers `envFileRow(p, scope, homeUser string, uid int, meta collect.ReadMeta)` and `envSymlinkRow(p, scope, homeUser string)`.
  - `userRhosts(a, rows []passwdRow, shells map[string]bool) facts.Envelope` → `files.user_rhosts`.
  - `passwdRows(a, b) ([]passwdRow, bool)` — reads/parses `/etc/passwd`, or writes the three enumeration keys as the read error and returns `false`.
  - `mountTable` and `readMounts(a) mountTable` with methods `fstype(path string) string` and `mountPoint(path string) string` (longest mount-point prefix wins; `""` when unknown).
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
		// R176: initialise EVERY field the controls where/require on, defaulted,
		// BEFORE the branch, so U-31/U-32's `each … require` never compares an
		// absent field on a denied/absent row (which would ERROR, not FAIL).
		rec := map[string]any{
			"user": r.name, "uid": r.uid, "home": r.home,
			"interactive":    interactive(r.shell, shells),
			"is_dir":         false,
			"owner_matches":  false,
			"group_writable": false,
			"other_writable": false,
			"on_remote_fs":   false,
			"mode":           -1,
			"owner_uid":      -1,
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
		case errors.Is(err, collect.ErrSymlink):
			// Stat returns ErrSymlink (an error) for a final symlink; it never
			// reaches the ok branch, so a home that is a symlink is unexaminable
			// and reported denied, not passed (R182).
			rec["stat_status"] = "denied"
			rec["reason"] = readReason(r.home, err)
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
	stat := func(p, scope, homeUser string, uid int) {
		meta, err := a.Stat(p)
		switch {
		case err == nil:
			out = append(out, envFileRow(p, scope, homeUser, uid, meta))
		case errors.Is(err, collect.ErrSymlink):
			// Stat never returns a nil-error symlink (R182); a symlinked
			// environment file surfaces here as an unowned, unexaminable row.
			out = append(out, envSymlinkRow(p, scope, homeUser))
		}
		// absent/denied: no row (the file need not exist).
	}
	for _, p := range systemEnvFiles {
		stat(p, "system", "", 0) // system files must be root-owned (uid 0)
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
			stat(p, "user", r.name, r.uid)
		}
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}

// envFileRow describes an environment file muster could stat. owner_ok means
// the file is owned by the account whose home it sits in, or by root
// (root-owned system files are fine); system-scope callers pass uid=0 (L3).
func envFileRow(p, scope, homeUser string, uid int, meta collect.ReadMeta) map[string]any {
	return map[string]any{
		"path": p, "scope": scope, "home_user": homeUser,
		"mode": int(meta.Mode), "owner_uid": int(meta.UID),
		"owner_ok":       int(meta.UID) == uid || int(meta.UID) == 0,
		"group_writable": meta.Mode&0o020 != 0,
		"other_writable": meta.Mode&0o002 != 0,
		"is_symlink":     false,
	}
}

// envSymlinkRow is the row for a symlinked environment file: not correctly
// owned, with the write flags defaulted false so U-24's `none where` clauses
// have every field they read (R176/R182).
func envSymlinkRow(p, scope, homeUser string) map[string]any {
	return map[string]any{
		"path": p, "scope": scope, "home_user": homeUser,
		"mode": -1, "owner_uid": -1,
		"owner_ok":       false,
		"group_writable": false,
		"other_writable": false,
		"is_symlink":     true,
	}
}
```

**owner_ok (L3, R182):** `owner_ok` means the file is owned by the account whose home it sits in, or by root (root-owned system files are fine). `envFileRow` takes the account uid and computes `owner_uid == uid || owner_uid == 0`; system-scope callers pass `uid = 0` (they must be root-owned). A symlinked environment file never reaches `envFileRow` — `Stat` returns `ErrSymlink`, and `envSymlinkRow` emits `is_symlink: true, owner_ok: false`. No stand-in expression remains.

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

// mountPoint returns the longest mount point that is a prefix of p — the mount
// that actually serves p — or "" when unknown. U-26 uses it to keep only /dev
// entries whose serving mount is exactly "/dev" (R181), so a node under a
// deeper mount (/dev/shm, /dev/mqueue, /dev/pts, /dev/hugepages) is not judged
// as a stray /dev file.
func (t mountTable) mountPoint(p string) string {
	best, bestMP := -1, ""
	for mp := range t.points {
		if (p == mp || strings.HasPrefix(p, strings.TrimSuffix(mp, "/")+"/")) && len(mp) > best {
			best, bestMP = len(mp), mp
		}
	}
	return bestMP
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

In `files.go`, add to `Declare.Reads`: `shellsPath`, `"/proc/self/mountinfo"`, the four `systemEnvFiles` (`etcProfile`, `bashBashrc`, `etcBashrc`, `cshCshrc` — R178, so `envFiles` may stat them), the home roots `"/home/*"`, `"/root"`, **the deeper home root `"/home/*/*"`** (R187, so a home one level down such as `/home/dept/alice` is declared rather than reported unexaminable), and the per-home dotfile globs for every name in `userEnvNames` plus `.rhosts`/`.shosts` under both `/home/*/` and `/root/` (e.g. `"/home/*/.bashrc"`, …, `"/root/.rhosts"`). Then in `runFiles`, after the existing permission facts (compute `mounts` once so Task 3's `devEntries` reuses it):

```go
	mounts := readMounts(a)
	if prows, ok := passwdRows(a, b); ok {
		shells, _ := loginShells(a)
		b.Set("files.home_dirs", homeDirs(a, prows, shells, mounts))
		b.Set("files.env_files", envFiles(a, prows, shells))
		b.Set("files.user_rhosts", userRhosts(a, prows, shells))
	}
```

`passwdRows` (L2) is the concrete passwd-read helper: a denied `/etc/passwd` must not read as "no homes", so it writes the three enumeration keys as the read error and returns `false`, and the caller skips the home block:

```go
// passwdRows reads and parses /etc/passwd. On a read error it writes the three
// home-enumeration keys as the read error (a denied passwd must not read as an
// empty enumeration) and returns ok=false so the caller skips the home block.
func passwdRows(a collect.Access, b *collect.Builder) ([]passwdRow, bool) {
	data, meta, err := a.ReadFile(passwdPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, meta)
		b.Set("files.home_dirs", e)
		b.Set("files.env_files", e)
		b.Set("files.user_rhosts", e)
		return nil, false
	}
	rows, _ := parsePasswd(data)
	return rows, true
}
```

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

// A genuinely missing home is stat_status "absent" (ENOENT), distinct from a
// denied one; root and an interactive user are interactive=true (the filter's
// positive half); a home on an nfs mount carries on_remote_fs=true (R191).
func TestFilesHomeDirsAbsentAndRemoteFS(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd_home", "/etc/shells": "shells_home", "/proc/self/mountinfo": "mountinfo_nfs"},
		dirs:  map[string]bool{"/root": true, "/home/alice": true},
		stats: map[string]statResult{
			"/root":       {mode: 0o700, uid: 0, gid: 0, kind: "dir"},
			"/home/alice": {mode: 0o755, uid: 1000, gid: 1000, kind: "dir"}, // on the nfs /home
		},
		// /home/bob is declared but present nowhere -> Stat returns ENOENT -> absent
	}
	rows := okList(t, build(t, "files", a), "files.home_dirs")
	byUser := map[string]map[string]any{}
	for _, r := range rows { m := r.(map[string]any); byUser[m["user"].(string)] = m }
	if byUser["root"]["interactive"] != true || byUser["alice"]["interactive"] != true {
		t.Error("root and alice have real login shells -> interactive=true")
	}
	if byUser["bob"]["stat_status"] != "absent" {
		t.Errorf("bob's missing home must be absent (ENOENT), not denied: %v", byUser["bob"])
	}
	if byUser["alice"]["on_remote_fs"] != true {
		t.Errorf("alice's home on nfs must be on_remote_fs=true: %v", byUser["alice"])
	}
}
```

Fixtures: `home_alice_rhosts` (`+`), `home_alice_bashrc` (`umask 022`). `home_alice_bashrc` is read? No — env_files only stats; `.rhosts` is read. Ensure the `files` map provides bytes for the read path and `stats` for the stat paths. `mountinfo_nfs` — like `mountinfo` but the `/home` line's fstype is `nfs`, so `on_remote_fs` is true for `/home/alice`.

- [ ] **Step 6: Register the three keys, regenerate the golden**

`files.home_dirs` (`list<record>`, `subject_kind: user` — the row's subject is the account from `/etc/passwd`, not the directory (R190); it feeds remote-NSS degradation and observation rendering), `files.env_files` (`list<record>`, `sensitivity: public`), `files.user_rhosts` (`list<record>`, `sensitivity: internal`). All `since: 1`, `collector: files`. Descriptions one line each, own words. Regenerate the golden and review.

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
		// fsAccess.Glob scans the files+dirs maps (not stats), so the /dev
		// nodes must be present there for the walk to enumerate them (R188);
		// stats supplies each node's kind.
		files: map[string]string{
			"/proc/self/mountinfo": "mountinfo_dev", // /dev -> devtmpfs
			"/dev/null":            "",              // present so Glob("/dev/*") sees it
			"/dev/planted":         "",
		},
		dirs: map[string]bool{"/dev": true},
		stats: map[string]statResult{
			"/dev/null":    {mode: 0o666, kind: "chardev"},
			"/dev/planted": {mode: 0o644, kind: "regular"},
		},
	}
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
// that is a regular file whose serving mount is exactly /dev (R181) — the
// planted-file case; a file under a deeper mount such as /dev/shm is excluded.
func devEntries(a collect.Access, mounts mountTable) (facts.Envelope, facts.Envelope) {
	var paths []string
	for _, g := range []string{"/dev/*", "/dev/*/*"} {
		if m, err := a.Glob(g); err == nil {
			paths = append(paths, m...)
		}
	}
	sort.Strings(paths)
	truncated := false
	if len(paths) > devMaxEntries {
		paths = paths[:devMaxEntries]
		truncated = true
	}
	entries := []any{}
	nondevice := []any{}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if err != nil {
			continue
		}
		rec := map[string]any{
			"name": path.Base(p), "path": p, "kind": meta.Kind,
			"fstype": mounts.fstype(p), "mode": int(meta.Mode), "uid": int(meta.UID),
		}
		entries = append(entries, rec)
		// R181: a stray file counts only when the mount actually serving it is
		// exactly /dev — never a deeper mount (/dev/shm, /dev/mqueue, /dev/pts,
		// /dev/hugepages), whose tmpfs regular files are legitimate.
		if meta.Kind == "regular" && mounts.mountPoint(p) == "/dev" {
			nondevice = append(nondevice, rec)
		}
	}
	src := &facts.Source{Kind: "file", Path: "/dev"}
	de, nd := collect.OK(entries, src), collect.OK(nondevice, src)
	if truncated {
		// R189: a bounded walk that hit the cap must say so on BOTH envelopes,
		// so a control screens rather than reading a silently-truncated /dev
		// list as complete.
		de.Truncated, nd.Truncated = true, true
		de.Reason = "hit the devMaxEntries bound; the /dev listing is incomplete"
		nd.Reason = de.Reason
	}
	return de, nd
}
```

- [ ] **Step 4: Wire /root, /etc/hosts.equiv and /dev into `runFiles`**

Add to `Declare.Reads`: `"/root"`, `"/etc/hosts.equiv"`, `"/dev/*"`, `"/dev/*/*"`. In `runFiles` (reuse the `mounts` from Task 2 — compute it once and pass it to both `homeDirs` and `devEntries`):

- `/root`: **ruling** — `writePermFacts` registers ten leaves including `group`/`group_readable`/`acl_entries` that `/root` does not need; register only the six `root_home` leaves named in the key inventory. Either add a `writePermFactsSubset` or write the six leaves inline from a single `a.Stat("/root")` (mode/uid/gid + group_writable/other_writable/acl_present); a stat failure reaches all six. Prefer inline to avoid over-registering.
- `/etc/hosts.equiv`: `files.etc_hosts_equiv.{mode,uid}` and `files.etc_hosts_equiv_lines` from a single read (mode/uid from the read's `ReadMeta`, non-comment lines for the list). **Ruling (R177):** on ENOENT the file simply does not exist, which is compliant, so `files.etc_hosts_equiv_lines` is `collect.OK([]any{}, &facts.Source{Kind: "derived"})` with `Reason` `"/etc/hosts.equiv does not exist"` — **not** `absent` — so U-27's `none where {op: matches}` passes vacuously instead of screening to `absent_means`; the two perm leaves (`mode`, `uid`) are `absent` in that ENOENT case. A denied or other read error writes the read error (`collect.FromReadError(err, meta)`) to **all three** keys. This mirrors the `files.etc_securetty_lines` read shape — the real precedent for a line list (`files.etc_hosts_lpd` carries only permission leaves, no line list).
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

// /etc/hosts.equiv non-comment lines are recorded; a file that does not exist
// (ENOENT) yields an OK empty line list — NOT absent (R177) — so U-27 passes
// vacuously rather than screening to absent_means.
func TestFilesHostsEquiv(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/hosts.equiv": "hosts_equiv", "/proc/self/mountinfo": "mountinfo"},
		stats: map[string]statResult{"/etc/hosts.equiv": {mode: 0o644, uid: 0, kind: "regular"}}}
	lines := okList(t, build(t, "files", a), "files.etc_hosts_equiv_lines")
	if len(lines) == 0 {
		t.Error("hosts.equiv non-comment lines must be recorded")
	}

	// No /etc/hosts.equiv at all: the lines key is an OK empty list, not absent.
	none := &fsAccess{files: map[string]string{"/proc/self/mountinfo": "mountinfo"}}
	e := env(t, build(t, "files", none), "files.etc_hosts_equiv_lines")
	if e.Status != facts.StatusOK {
		t.Fatalf("a missing hosts.equiv must leave etc_hosts_equiv_lines OK, got %+v", e)
	}
	if l, _ := e.Value.([]any); len(l) != 0 {
		t.Errorf("a missing hosts.equiv must yield [], got %v", e.Value)
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

- [ ] **Step 1: Amend U-12 — add the shell-TMOUT mechanism**

In `controls/account/session_timeout.yaml`:
- Drop the `applies_when: [{fact: services.ssh.installed, ...}]` block (the control now applies to any host — a host with neither an sshd timeout nor a shell TMOUT genuinely has no idle timeout, and `absent_means: fail` states that).
- **Do NOT add a `client_alive_count_max present` term to mechanism 1's `when` (R185).** That change was reverted: it does not fix 2D's S3, it only moves the FAIL to the fall-through. Mechanism 1's `when` stays `[{ fact: sshd.options.client_alive_interval, on: effective, op: gte, expected: 1 }]`. Under parse-fallback — a config with `ClientAliveInterval` set but no `ClientAliveCountMax` line — mechanism 1 is selected and its count checks FAIL, where a running daemon (which reports the documented default count) would PASS. This is a known parse-fallback limitation; the real fix (having the sshd collector report the documented default for an absent-but-defaulted directive) is **parked to a follow-up**, not done here.
- Add mechanism 2 (shell TMOUT) and a `max_idle` param:
```yaml
params:
  max_interval: { type: int, default: 300, description: The largest ClientAliveInterval in seconds that counts as a session timeout }
  max_count: { type: int, default: 3, description: The largest ClientAliveCountMax that counts as a session timeout }
  max_idle: { type: int, default: 600, description: The largest shell TMOUT in seconds that counts as a session timeout }
mechanisms:
  - when:
      - { fact: sshd.options.client_alive_interval, on: effective, op: gte, expected: 1 }
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
- Rewrite the description (EN+KO) to say both mechanisms are now judged (SSH `ClientAlive` or a shell `TMOUT` that is set, at most `max_idle`, and exported), and drop the "applies only where sshd is installed / TMOUT added in a later plan" sentence. **State honestly (R185)** that under parse-fallback — a config with `ClientAliveInterval` set but no `ClientAliveCountMax` line — U-12 FAILs where the running daemon would PASS, because muster judges the parsed config rather than the daemon's documented default; note this is a known parse-fallback limitation whose real fix is parked to a follow-up. Do **not** claim this amendment "resolves 2D's S3".

**U-12 fixture-shape rule (R179).** Every U-12 fixture carries `sshd.options.client_alive_interval.effective` — it is mechanism 1's `when` fact, and a *missing* setting key is `ERROR(missing_fact)`, not a skipped mechanism. Fixtures that select mechanism 2 or fall through to `absent_means` also carry `env.shell.tmout` (ok `0` for "no timeout"). Fixtures that stay on mechanism 1 also carry `sshd.options.client_alive_count_max.effective` (the mechanism-1 checks read it).

New U-12 fixtures in `controls/testdata/muster.account.session_timeout/`:
- `pass-tmout.json` — `sshd.options.client_alive_interval.effective` 0 (mechanism 1 `when` fails), `env.shell.tmout` 600, `env.shell.tmout_exported` true → PASS (mechanism 2). (No `services.ssh.installed` needed now.)
- `fail-tmout-not-exported.json` — `client_alive_interval.effective` 0, `env.shell.tmout` 600, exported false → mechanism 2 chosen, check fails → FAIL.
- Update the existing `na-no-ssh.json`: it asserted NOT_APPLICABLE via the old `applies_when`. Now the control applies; rename/replace it with `fail-no-timeout.json` — `client_alive_interval.effective` 0 (no sshd timeout), `env.shell.tmout` 0 → no mechanism `when` matches → `absent_means: fail` → FAIL.
- `fail-interval-0.json` (an existing/renamed fixture) gains `env.shell.tmout` ok `0`, so with `client_alive_interval.effective` 0 no mechanism matches → `absent_means: fail` → FAIL.
- Confirm the other existing fixtures still hold: `pass-interval-300`/`pass-interval-60-count-3` still PASS via mechanism 1 (each carries `client_alive_count_max.effective`); `fail-count-0`/`fail-interval-too-long`/`fail-count-too-high` still FAIL; `warn-parse-fallback` carries `client_alive_interval.effective` (selects mechanism 1) and `client_alive_count_max.effective` (the mechanism-1 checks resolve against it) and stays WARN.

- [ ] **Step 2: Write U-30 (`controls/account/umask_policy.yaml`)**

```yaml
id: muster.account.umask_policy
title_en: The default file-creation mask denies group and other write
title_ko: 기본 파일 생성 마스크가 그룹·기타 쓰기를 막는다
description_en: The default UMASK in login.defs must be 022 or stricter so new files are not group- or world-writable, and pam_umask must be stacked so the mask applies to sessions that never read /etc/profile (cron, non-login SSH). The parameter lists the masks that count as strict enough; a host that sets a weaker mask, or that does not stack pam_umask, is reported.
description_ko: login.defs 의 기본 UMASK 가 022 이상으로 엄격해 새 파일이 그룹·전체 쓰기 가능이 되지 않아야 하고, /etc/profile 을 읽지 않는 세션(cron, 비로그인 SSH)에도 마스크가 적용되도록 pam_umask 가 올라가 있어야 합니다. 파라미터는 충분히 엄격한 것으로 인정하는 마스크 목록이며, 더 약한 마스크를 설정했거나 pam_umask 를 올리지 않은 호스트는 보고됩니다.
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
  kisa: { "2026": ["U-14"], "2021": ["U-05"] }
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

**Keep the whole `cmd/muster` package green at this commit (L10/L12).** Adding U-14 and U-30 (and the U-12 amendment) makes them evaluate in the end-to-end run, so the count test, the coverage table and the e2e snapshots must all move in this commit — not be deferred to Task 6 — or `go test ./cmd/muster/` goes red:
- `cmd/muster/controls_test.go`: both `"ok: 22 controls"` → `"ok: 24 controls"`.
- Extend both e2e snapshots (`cmd/muster/testdata/full-{pass,fail}.json`) with the facts these three controls read, so each resolves to PASS rather than `ERROR(missing_fact)`: under `facts.env.shell` — `tmout` 600 + `tmout_exported` true (or an sshd `ClientAlive` pair) so U-12 passes, `root_path_raw` "/usr/sbin:/usr/bin" and two clean `root_path_entries`; under `facts.files` — `root_home` (uid 0, not writable); under `facts.accounts.login_defs` — `umask` "022"; under `facts.pam` — `umask_module.enabled` true. **`accounts.login_defs.umask` and `pam.umask_module.enabled` are NOT in the snapshots today (L12) — without them U-30 `ERROR(missing_fact)`s.**
- `cmd/muster/e2e_test.go`: add `muster.account.root_home_and_path` and `muster.account.umask_policy` to both expected-status maps as PASS (the fail map's only FAIL stays `root_remote_login`), and confirm U-12 stays PASS in both.
- Regenerate the coverage table so it is not stale at this commit: `go run ./tools/coverage` then `go run ./tools/coverage -check` (exit 0); `docs/reference/coverage.md` now enrols U-14 and U-30 (24 items).
- `go test ./cmd/muster/ -count=1` passes.

- [ ] **Step 6: Commit**

```bash
git add controls/account/session_timeout.yaml controls/account/umask_policy.yaml controls/account/root_home_and_path.yaml controls/testdata \
        cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md
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
  kisa: { "2026": ["U-24"], "2021": ["U-14"] }
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
description_en: /dev is served by devtmpfs and should hold only device nodes. A regular file living there is either a leftover or a planted file used to smuggle data past a device-only expectation, so any regular file whose serving mount is exactly /dev is reported. Device nodes, directories and symlinks are not flagged, and neither is a regular file under a deeper mount such as /dev/shm, /dev/mqueue or /dev/pts (each its own tmpfs, where regular files are legitimate).
description_ko: /dev 는 devtmpfs 가 제공하며 장치 노드만 있어야 합니다. 그곳의 일반 파일은 잔재이거나, 장치만 있으리라는 기대를 우회해 데이터를 숨기는 데 쓰이는 심어진 파일이므로, 서비스 마운트가 정확히 /dev 인 일반 파일은 모두 보고합니다. 장치 노드·디렉터리·심볼릭 링크는 표시하지 않으며, /dev/shm·/dev/mqueue·/dev/pts 같은 더 깊은 마운트(각자 tmpfs 로, 일반 파일이 정상) 아래의 일반 파일도 표시하지 않습니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-26"], "2021": ["U-16"] }
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
description_en: Each interactive account's home directory must be owned by that account and must not be group- or world-writable. A home muster could not stat (an unreadable parent) is reported here rather than passed silently, since an unexaminable home could hide anything. A home directory outside the declared home roots (not under /home, /home/*/ or /root) likewise cannot be examined under the collector's declaration and is reported as denied — a finding — rather than assumed compliant. Service accounts with a nologin shell are skipped so a host's thirty /nonexistent service homes do not each become a finding.
description_ko: 각 대화형 계정의 홈 디렉터리는 해당 계정 소유여야 하고 그룹·전체 쓰기가 가능하면 안 됩니다. muster 가 stat 할 수 없었던 홈(상위 디렉터리를 읽을 수 없는 경우)은 조용히 통과시키지 않고 여기서 보고합니다. 점검 불가한 홈은 무엇이든 숨길 수 있기 때문입니다. 선언된 홈 루트(/home, /home/*/, /root) 밖의 홈 디렉터리도 수집기 선언으로는 점검할 수 없어 양호로 가정하지 않고 denied(발견 항목)로 보고합니다. nologin 셸의 서비스 계정은 건너뛰어, 호스트의 서른 개 /nonexistent 서비스 홈이 각각 findings 가 되지 않게 합니다.
category: file
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-31"], "2021": ["U-57"] }
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
description_en: Each interactive account's home directory named in /etc/passwd must exist and be a directory. An account whose home is missing lands in / on login and may write into unexpected places; an account whose home muster could not stat is reported rather than assumed present. A home outside the declared home roots (not under /home, /home/*/ or /root) cannot be examined under the collector's declaration and is reported as denied — a finding — rather than assumed present. Service accounts with a nologin shell (whose home is often /nonexistent by design) are skipped.
description_ko: /etc/passwd 에 적힌 각 대화형 계정의 홈 디렉터리가 실제로 존재하고 디렉터리여야 합니다. 홈이 없는 계정은 로그인 시 / 로 떨어져 예상치 못한 곳에 쓸 수 있으며, muster 가 stat 할 수 없었던 홈은 존재한다고 단정하지 않고 보고합니다. 선언된 홈 루트(/home, /home/*/, /root) 밖의 홈은 수집기 선언으로 점검할 수 없어 존재한다고 가정하지 않고 denied(발견 항목)로 보고합니다. nologin 셸의 서비스 계정(홈이 흔히 의도적으로 /nonexistent)은 건너뜁니다.
category: file
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-32"], "2021": ["U-58"] }
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

Each fixture is `{"synthetic": true, "schema_version": 1, "run": {}, "facts": {"files": {…}}}` with only the leaves the control reads. `home_dirs` rows must carry `user`, `interactive`, and the fields the control requires (`owner_matches`/`group_writable`/`other_writable`/`stat_status`/`is_dir`), with the collector's rule (R176) that a non-`ok` row still carries `owner_matches`/`group_writable`/`other_writable`/`is_dir` as `false` (and `mode`/`owner_uid` as `-1`), so `each … require` never compares an absent field.

- `env_file_permissions/`: `pass-clean.json` (two env_files rows, owner_ok true, not writable → PASS); `fail-group-writable.json` (a row group_writable true → FAIL); `fail-not-owned.json` (owner_ok false → FAIL); `fail-symlink.json` (one row matching the collector's `envSymlinkRow` shape (R182): `is_symlink` true, `owner_ok` false, `group_writable` false, `other_writable` false, `mode` -1, `owner_uid` -1 → FAIL on the owner_ok clause); `manual-empty.json` (`files.env_files` `{"status":"absent","reason":"…"}` → MANUAL). Note: an empty `[]` list PASSes vacuously, so use `absent` (not `[]`) for the manual case.
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

**Keep the whole `cmd/muster` package green at this commit (L10).** These five controls now evaluate in the end-to-end run, so bump the count, extend the snapshots and update the e2e maps here, in this commit:
- `cmd/muster/controls_test.go`: both `"ok: 24 controls"` → `"ok: 29 controls"`.
- Extend both e2e snapshots (`cmd/muster/testdata/full-{pass,fail}.json`) with the facts these five controls read, so each resolves to PASS: under `facts.files` — `env_files` (two clean rows), `user_rhosts` `[]`, `etc_hosts_equiv_lines` `[]`, `home_dirs` (root + one interactive user, ok/owned/not-writable), `dev_nondevice` `[]`.
- `cmd/muster/e2e_test.go`: add `muster.file.env_file_permissions`, `muster.file.dev_no_stale_files`, `muster.file.rhosts_forbidden`, `muster.file.home_dir_permissions`, `muster.file.home_dir_exists` to both expected-status maps as PASS (the fail map's only FAIL stays `root_remote_login`).
- Regenerate the coverage table: `go run ./tools/coverage` then `go run ./tools/coverage -check` (exit 0); `docs/reference/coverage.md` now enrols U-24, U-26, U-27, U-31, U-32 (29 items).
- `go test ./cmd/muster/ -count=1` passes.

Then the lab host, root, stock Ubuntu 22.04: `bash lab-sync.sh <worktree>`, build, `collect --require-root --require-complete`, `check --format json`; report the `<id> <status>` lines for the seven new/amended controls and the leaves `.facts.env.shell.tmout.value`, `.facts.files.home_dirs` count, `.facts.files.dev_nondevice` count. Quote only those.

- [ ] **Step 4: Commit**

```bash
git add controls/file/env_file_permissions.yaml controls/file/dev_no_stale_files.yaml controls/file/rhosts_forbidden.yaml controls/file/home_dir_permissions.yaml controls/file/home_dir_exists.yaml controls/testdata \
        cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md
git commit -m "Add the environment-file, /dev, rhosts and home-directory controls"
```

---

### Task 6: End-to-end snapshots, counts, coverage and the README

**Files:**
- Modify: `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go` (count comments), `README.md`, `README.ko.md`, and verify `docs/reference/coverage.md`

**Note on the count/coverage split (L10).** `cmd/muster/controls_test.go`'s `"22 controls"` string and `docs/reference/coverage.md` are already bumped incrementally — to `24` in Task 4 (U-14, U-30) and to `29` in Task 5 (U-24, U-26, U-27, U-31, U-32) — and each of those tasks also added its controls' facts and PASS map entries to the e2e snapshots, so no earlier commit carries a red `cmd/muster` test or a stale coverage table. Task 6 therefore only reconciles the snapshots as a whole, updates the e2e count comments, refreshes the README, and runs the final verification.

- [ ] **Step 1: Reconcile the snapshots**

Confirm both snapshots carry the complete set of new facts introduced across Tasks 4–5 and that every new control's verdict is correct. The full new-fact set each snapshot must carry: under `facts.env` — `shell.tmout` (600 exported, or 0 with a passing sshd pair), `shell.tmout_exported`, `shell.umask_settings` `[]`, `shell.root_path_raw` "/usr/sbin:/usr/bin", `shell.root_path_entries` two clean rows; under `facts.accounts.login_defs` — `umask` "022"; under `facts.pam` — `umask_module.enabled` true; under `facts.files` — `root_home` (uid 0, not writable), `env_files` (two clean rows), `user_rhosts` `[]`, `etc_hosts_equiv_lines` `[]`, `home_dirs` (root + one interactive user, ok/owned/not-writable), `dev_nondevice` `[]`. **`accounts.login_defs.umask` and `pam.umask_module.enabled` are NOT present in the snapshots today (L12); they must be added (in Task 4, with U-30) or U-30 `ERROR(missing_fact)`s.** Every new-control verdict is PASS. For `full-fail.json`, keep its single existing FAIL and the SAME clean env/files values so the seven new controls PASS there too (a second FAIL would break the R26 invariant — keep `root_remote_login` the only FAIL).

**U-12 in the snapshots:** now that U-12 always applies, the pass snapshot must satisfy it — a passing mechanism (either `sshd.options.client_alive_interval` 300 + `client_alive_count_max` 1, already present from 2D, or `env.shell.tmout` 600 exported). Confirm `full-fail.json` also passes U-12 (it has the sshd timeout from 2D). If either snapshot has sshd count 0 / interval 0 and no TMOUT, U-12 would FAIL there — set a passing mechanism. (This U-12 reconciliation lands with the U-12 amendment in Task 4; Task 6 verifies it.)

- [ ] **Step 2: e2e count comments**

`e2e_test.go`: the seven new controls are already in both expected-status maps as PASS (added in Tasks 4–5; the fail map's only FAIL stays `root_remote_login`). Update the count comments to twenty-nine. `controls_test.go`'s `"ok: … controls"` strings are already at `29` from Task 5 — do not touch them again here.

- [ ] **Step 3: Coverage verification**

```
go run ./tools/coverage -check
```
Exit 0: `docs/reference/coverage.md` is already at 29 items from Task 5 (U-14, U-24, U-26, U-27, U-30, U-31, U-32 enrolled; header `29 of 67 items enrolled (auto 25, partial 4, manual 0)`). Regenerate with `go run ./tools/coverage` only if `-check` reports drift.

- [ ] **Step 4: README pair**

Extend the merged-plans sentence to name this plan: `README.md` "...and the completed sshd collector with login banners, and the home-directory and shell-environment checks."; `README.ko.md` "...완성된 sshd 수집기와 로그인 배너, 그리고 홈 디렉터리·셸 환경 점검." No control ids enumerated; nothing else changes.

- [ ] **Step 5: Gates and the host**

Windows: `gofmt -l .`; `GOOS=linux GOARCH=amd64 go vet ./...`; `go test ./internal/facts/ ./internal/check/ ./internal/controls/ ./cmd/muster/ -count=1`; both lints `ok: 29 controls`; `go run ./tools/coverage -check` exit 0. Host: sync and `bash lab-run.sh 'sudo env PATH="$PATH" go test ./internal/collect/... ./cmd/muster/ -count=1 -race -shuffle=on'`, plus a real `collect`/`check` proof as in Task 5.

- [ ] **Step 6: Commit**

```bash
git add cmd/muster/testdata cmd/muster/e2e_test.go README.md README.ko.md
git commit -m "Reconcile the home and shell-environment controls end to end"
```
(`cmd/muster/controls_test.go` and `docs/reference/coverage.md` were committed in Tasks 4–5; Task 6 adds only the snapshot reconciliation, the e2e count comments and the README.)

---

## Self-review

**Spec coverage.** §5.4 env `shell.*` → T1; files `home_dirs`/`env_files`/`user_rhosts`/`root_home`/`etc_hosts_equiv`/`dev_entries` → T2/T3. §6.5 screening and the mixed-absence hazard → U-12/U-14 use `mechanisms` so an absent PATH or count does not screen the whole control; U-27 relies on `etc_hosts_equiv_lines` being `[]` (not absent) when the file is missing (Task 3 ruling). §7.3 honesty → `stat_status` distinguishes `denied` from `absent`; a denied home is a finding, not a pass. §10.2 items U-12 (amended), U-14, U-24, U-26, U-27, U-30, U-31, U-32 → T4/T5. Every new control carries `references.stig`/`nist_800_53` where a mapping exists (U-26 and U-27 have no clean DISA rule and carry KISA only).

**Placeholder scan.** No stand-ins remain: `envFileRow` takes the account uid and computes `owner_ok` directly (the earlier disjunction stand-in is gone, L3), a symlinked environment file is handled by `envSymlinkRow` (R182), and the passwd read is the concrete `passwdRows(a, b) ([]passwdRow, bool)` helper (L2), which writes the three enumeration keys as the read error and returns `false` on a denied `/etc/passwd`. Nothing is deferred.

**Type consistency.** `shellAssignment.Kind` ∈ `tmout|umask|path`; `home_dirs.stat_status` ∈ `ok|absent|denied`; `interactive` is a bool on every `home_dirs` row; `env.shell.tmout` is int, `tmout_exported`/`tmout_readonly` bool; control ids `muster.account.{umask_policy,root_home_and_path}` and `muster.file.{env_file_permissions,dev_no_stale_files,rhosts_forbidden,home_dir_permissions,home_dir_exists}`. Count 22 → 29 (7 new). The `each`/`where`/`require`/`subject` grammar matches spec §6.6; `none where {op: matches}` on `etc_hosts_equiv_lines` (a `list<string>`) omits `field` (scalar element), as the grammar requires.

**Risks called out.** (1) The mixed-absence screening — handled by `mechanisms` in U-12/U-14 and by the `[]`-when-absent ruling for `etc_hosts_equiv_lines`. (2) The interactive filter is load-bearing for U-24/U-31/U-32; if `/etc/shells` is unreadable, `loginShells` returns the libc default set, so the filter still holds (a 2B behaviour). (3) A `denied` home must reach the controls as a finding, not an absent that `absent_means: pass` (U-27) could excuse — U-27 does not read `home_dirs`, and U-31/U-32 flag the denied row. (4) The collector must fill `owner_matches`/`group_writable`/`other_writable` on every `home_dirs` row (false when not `ok`) so U-31's `each … require` never compares an absent field.

## Execution notes

Executed 2026-09-07 by subagent-driven development on branch `stage2e-home-shell-env` (fourteen commits over `112e99c`, these notes included), developed on Windows and tested on a Linux lab host as root (every Linux collector test, the real home-directory and `/dev` walks, and the collect/e2e suites ran there; the Rocky/Alma differences — nologin paths, `pam_umask` in `postlogin`, home roots — are exercised by synthetic fixtures and CI's init containers). Two fable reviews ran: a fresh pre-flight scan of the plan (the first attempt as a fork degenerated into a recap and was discarded and re-dispatched) found 5 blocking and 12 should-rule defects; the whole-branch review after execution found 2 blocking and 4 should-fix. One consolidated fix wave cleared the whole-branch findings. Ruling numbers continue the ledger (R1–R174 belong to plans 1A–2D; R175–R195 are pre-flight and mid-execution, R196–R201 are the final fix wave).

- **The env collector (T1).** The effective `TMOUT`, `umask` and root `PATH` are parsed from the fixed profile-file read order (last unconditional assignment wins). **R175:** `pathEntries` never stats an undeclared directory — a fixed candidate PATH-dir list is declared and `declared()` is probed first; an undeclared element is `unresolved+undeclared`, never a guard violation. **R180:** a `$…`/`~…` element is `variable+unresolved`, not `is_dot`. **R183 (C3):** a present-but-unreadable profile file writes the path-prefixed read error (via the shared `readErrorEnv`) to all seven `env.shell.*` keys, never a value salvaged from the readable rest. **R184:** the scanner splits each line on an unquoted `;` and recognises `declare|typeset|export|readonly` flag forms.
- **The files home enumeration (T2).** One `home_dirs` row per `/etc/passwd` account with a three-value `stat_status` (`ok`/`absent`/`denied` — an unreadable home is `denied`, never conflated with a missing one) and an `interactive` flag (a real login shell in `/etc/shells`, so Ubuntu's `/nonexistent` service homes are filtered out). **R176 (the load-bearing rule):** every row initialises `owner_matches`/`group_writable`/`other_writable`/`is_dir`/`mode`/`owner_uid` before the stat branch, so U-31/U-32's `each … require` on a denied or absent interactive row is a clean FAIL, never `ERROR(internal_error)`. **R182:** a final-component symlink returns `ErrSymlink` (an error), handled explicitly (env-file row `is_symlink:true`; home row `denied`). **R190:** `files.home_dirs` is `subject_kind: user`. **L2:** a denied `/etc/passwd` writes the three enumeration keys as the read error, not an empty list.
- **/root, hosts.equiv and /dev (T3).** `/root` gets six permission leaves inline (not the ten-leaf `writePermFacts`). **R177:** `files.etc_hosts_equiv_lines` is `[]` (ok, "does not exist") when the file is missing — not absent — so U-27 does not screen to `absent_means` and a `+` in a `.rhosts` still FAILs. **R181/R193:** `mountTable.mountPoint` (deferred from T2 to its first caller here) drives an exact-`/dev`-mount filter: `dev_nondevice` flags a regular file only when its longest-prefix mount point is exactly `/dev`, so a `/dev/shm` (tmpfs) file is listed in `dev_entries` but never as a stray file — verified on the live host (a `/dev/shm` probe appeared in `dev_entries` and not in `dev_nondevice`).
- **The evaluator's persona work was 2D**; 2E's controls use the existing grammar. **The mixed-absence hazard** — an absent fact screening a whole control to `absent_means` before the intended clause runs — was dodged by giving U-12 and U-14 `mechanisms` (an absent PATH or a host without sshd falls to the next mechanism, not to `absent_means`), and by R177's `[]`-when-absent for U-27.
- **Controls (T4/T5).** U-12 gained a shell-`TMOUT` mechanism (interval-or-TMOUT, either satisfies) and its shell-idle STIG refs. **R185:** the `client_alive_count_max present` term I had added to U-12's mechanism-1 `when` was reverted — it did not fix 2D's S3 (it only moved the FAIL to the fall-through); the description states honestly that under parse-fallback with an interval but no count line U-12 FAILs where the running daemon PASSes, and the real fix is parked. U-30 (UMASK) judges `login.defs` UMASK plus `pam_umask` stacked; **R186** dropped an unbacked "evidence" promise from its description. U-14 (root home + PATH) uses two mechanisms so a host with no unconditionally-set root PATH is judged on the home alone; `sudo secure_path` is 2F. U-24/U-26/U-27/U-31/U-32 judge the env-file, `/dev`, `.rhosts` and home facts.
- **The count/coverage/e2e bump was moved into T4 and T5 (L10)** so no task commit carried a red `cmd/muster` test or a stale coverage table; the e2e snapshots gained `accounts.login_defs.umask` and `pam.umask_module.enabled` (L12) so U-30 evaluates rather than `ERROR`ing. Control set 22 → 29 (auto 25, partial 4).
- **R195 (data correctness, caught during execution).** The plan's 2021 KISA ids were wrong for five controls versus `kisa_mapping.json` (lint shape-checks only): corrected to U-14←U-05, U-24←U-14, U-26←U-16, U-31←U-57, U-32←U-58 (U-27←U-17 and U-30←U-56 were already right).
- **Whole-branch fix wave (R196–R201).** R196: U-14's PATH check judged only the last `PATH=` line, so a stock RHEL `PATH=$PATH:$HOME/bin` masked an earlier dangerous element — `writeRootPath` now splices `$PATH` self-references and judges the accumulated value (a false PASS on a 상-importance control, fixed). R197: `env.shell.tmout` now takes its winner from system-scope files only, so a root-only `TMOUT` no longer yields a host-wide U-12 PASS. R198/R199: a denied `/etc/shells` (which would make every bash account non-interactive → vacuous pass) and an unreadable `/proc/self/mountinfo` (→ a clean empty `dev_nondevice`) now surface as the read's status rather than a silent pass. R200: U-27's description no longer claims U-31 reports a read-denied `.rhosts`. R201: the README conjunction and the U-12 remediation's shell alternative.
- **Real-host proof (root, stock Ubuntu 22.04).** The env, home-walk and `/dev` collector tests and the full `internal/collect/...` and `cmd/muster` suites ran green on the lab host; the `/dev/shm` exclusion was confirmed on the live host. No host identifier, address, alias or credential is in any tracked file (every commit greps clean).
- **Carried forward (2F/2M).** S1: a `.rhosts`/env-file muster could not READ (a 0700 home on a non-root run, or an NFS root-squash export) is dropped rather than emitted as a `denied` row with a U-27/U-24 clause — the collection gap is documented in U-27's text; the row emission is parked. S2: an interactive account whose home is outside `/home/*`, `/home/*/*` or `/root` (a database account under `/var/lib/*`) reports `denied` "outside the declaration" and false-fails U-31/U-32 — declare more home roots or document the class. S6 (from 2D): U-12's parse-fallback count case. `sudo.secure_path` for U-14 (2F). The `env_parse` conditional scanner treats a `&&`/`||`-joined or one-line `if` assignment as unconditional in the safe (FAIL) direction. `env.shell.umask_settings` is collected as evidence but judged by no control yet.
