# Stage 2B — Account Facts and Controls Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the `accounts` collector (login.defs strings and boundaries, user record joins, groups, administrative group membership, shadow-in-use, `/etc/shells`, NSS sources) and the `/etc/shadow` permission facts, wire the spec's remote-NSS degradation into the check engine, and enrol the ten KISA account items U-04, U-05, U-07, U-08, U-09, U-10, U-11, U-13, U-18 and U-55 as controls with fixtures.

**Architecture:** The `accounts` collector reads `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/login.defs`, `/etc/shells` and `/etc/nsswitch.conf` once each through `Access` and derives joins in Go (duplicate uids, primary group existence, shell validity, administrative membership); the check side judges those derived facts with the existing `each`/`none` grammar and never re-parses files. Cross-file joins whose inputs can be unreadable are their own keys (`accounts.orphan_gids`, `accounts.admin_group_members`, `accounts.shadow_in_use`) so a denied read reaches the control as `ERROR`, while joins inside `/etc/passwd` itself are fields of `accounts.users`. `/etc/shadow` permission facts come from the 2A template in the `files` collector. Step 13 of the derivation gains one more degradation: an account control judged while NSS names a remote source reports `WARN`.

**Tech Stack:** Go 1.25 (stdlib only, `golang.org/x/sys/unix` already present), YAML controls decoded strictly, JSON fixtures, the lab host and CI containers for Linux tests.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — §5.4 (sections), §5.6 (sensitive values: hash algorithm, locked and empty-password flags only, never the hash), §5.7 (record fields are additive; a missing field never yields PASS), §6.3–6.4 (grammar, `each`/`none`, subject kinds `user`/`group`), §6.5 step 13 and §7.3 (remote NSS source → account controls `WARN`), §6.6 (defaults are the guide's criterion), §10.2 (plan 2B), appendix A rows U-04, U-05, U-07 (partial), U-08 (partial), U-09, U-10, U-11, U-13, U-18, U-55. Plan 2A's Execution notes carry rulings R89–R124; R121 (U-22 owner-name leaf) is not touched here.

## Global Constraints

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`; a registered key the snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`. A fact whose input could not be read carries that read's status (`denied`, `absent`, `error`), never a confident value.
- `/etc/shadow` material: the snapshot holds the hash algorithm id (`$6$`, `$y$`, … or `legacy`), the lock and empty-password flags and the ageing fields — never a salt, a digest or one byte of the password field (spec §5.6). `accounts.users` stays `sensitivity: internal`.
- Same input, same bytes: user and group records in file order, derived lists in a stated order, no `map` iteration reaching a `Set` value (a `map[string]any` record is fine — `encoding/json` sorts its keys).
- No judgment in collectors (D09): collectors join and count; the criterion (which shells are interactive, which accounts are unnecessary, which hashes are strong) lives in the control and its `params`, whose defaults are the guide's criterion (§6.6) even where a stock host then fails — the deviation is recorded in the control's description.
- Every host touch goes through `Access`; every path a collector reads is in its `Declare.Reads`; no new module dependency; `internal/check` never imports `os/exec`, `net` or touches the host; new Go files under `internal/collect/collectors` carry `//go:build linux`.
- Control and waiver YAML decode strictly; every control has `pass-*`/`fail-*` fixtures (a `fail-` fixture on a `partial` control expects `WARN`; `warn-` fixtures expect `WARN`), `synthetic: true`, only the leaves the control reads; `controls lint --references docs/reference` must end `ok: 18 controls`; STIG ids must exist in `docs/reference/stig/`, NIST ids in the index union.
- Never copy KISA guide text or CIS Benchmark text; titles and descriptions are muster's own words, English and Korean both; identifiers stay English on both sides. Fixtures come from public images or are `synthetic: true`; nothing from the lab host is committed; no host name, address, alias or credential in any file.
- Registry additions carry `since: 1`, `collector`, `sensitivity`; adding fields to `accounts.users` does not bump `schema_version` (§5.7); the facts schema golden is regenerated with `go test ./internal/facts -run TestFactsSchemaGolden -update` and its diff reviewed.
- Exit codes are unchanged: `check` any `ERROR` → 2, any `FAIL` → 1; `collect` 0/1/2; lint problems → 2.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/collect/collectors/accounts.go` | Collector declaration and `runAccounts`; login.defs reader (`value`, `str`, `intOr`), shadow parsing (existing), the run's ordering of `Set` calls. Grows to ~330 lines; the passwd/group/shells/nss parsing moves out to keep it readable. |
| `internal/collect/collectors/accounts_passwd.go` (new, T2) | `passwdRow`, `parsePasswd`, `loginShells`, `deriveUsers` — the `accounts.users` record and its in-file joins. |
| `internal/collect/collectors/accounts_groups.go` (new, T3) | `groupRow`, `parseGroup`, `groupRecords`, `orphanGIDs`, `adminGroupMembers`, `shadowInUse`. |
| `internal/collect/collectors/accounts_nss.go` (new, T4) | `nssSources`, `nssRemote` — `/etc/nsswitch.conf` parsing. |
| `internal/collect/collectors/accounts_test.go` (new, T1; grows T2–T4) | Tests for the new account facts; the three existing accounts tests stay in `collectors_test.go`. |
| `internal/collect/collectors/testdata/{login.defs_2b,passwd_2b,shadow_2b,group_2b,shells_2b,nsswitch.conf,nsswitch_sss.conf}` | Synthetic fixtures for the joins. |
| `internal/collect/collectors/files.go` (T5) | Declares `/etc/shadow` and writes `files.etc_shadow.*` through `writePermFacts`. |
| `internal/facts/registry.yaml`, `internal/facts/testdata/facts-schema.golden.json` | 28 new keys (T1 9, T2 2, T3 4, T4 3, T5 10) and the `accounts.users` description. |
| `internal/check/eval.go`, `internal/check/results.go`, `internal/check/eval_test.go` (T4) | `remoteNSS` step-13 hook and its constant. |
| `controls/account/{shadow_passwords,root_only_uid_zero,primary_group_exists,unique_uids,system_account_shells,unnecessary_accounts,admin_group_minimal,password_hash_algorithm}.yaml`, `controls/file/shadow_permissions.yaml`, `controls/service/ftp_account_shell.yaml` (T6–T7) | The ten controls. |
| `controls/testdata/<id>/*.json` (T6–T7) | Fixtures. |
| `cmd/muster/testdata/full-{pass,fail}.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go`, `docs/reference/coverage.md`, `README.md`, `README.ko.md` (T7) | End-to-end snapshots, counts and the coverage table. |

Key inventory this plan adds (28 keys; every one `since: 1`):

| Key | Type | Collector | Task |
|---|---|---|---|
| `accounts.login_defs.pass_warn_age` | `setting<int>` (`default_on: both`) | accounts | T1 |
| `accounts.login_defs.uid_min`, `.sys_uid_max`, `.sha_crypt_min_rounds` | `int` | accounts | T1 |
| `accounts.login_defs.umask`, `.home_mode`, `.encrypt_method`, `.env_supath`, `.env_path` | `string` | accounts | T1 |
| `accounts.shells` | `list<string>` | accounts | T2 |
| `accounts.parse_failures` | `int` | accounts | T2 (T3 adds the group count) |
| `accounts.groups` | `list<record>`, `subject_kind: group` | accounts | T3 |
| `accounts.orphan_gids` | `list<record>`, `subject_kind: user` | accounts | T3 |
| `accounts.admin_group_members` | `list<record>`, `subject_kind: user` | accounts | T3 |
| `accounts.shadow_in_use` | `bool` | accounts | T3 |
| `accounts.nss.passwd_sources`, `.group_sources` | `list<string>` | accounts | T4 |
| `accounts.nss.remote` | `bool` | accounts | T4 |
| `files.etc_shadow.{mode,uid,gid,group,group_readable,group_writable,other_readable,other_writable,acl_present,acl_entries}` | as `files.etc_passwd.*` | files | T5 |

`accounts.users` gains the fields `home` (string), `system` (bool), `shadowed` (bool), `uid_duplicate` (bool), `name_duplicate` (bool), `shell_valid` (bool) on every row, and `locked` (bool) beside the existing shadow-derived fields; `hash_algo` (already written) is documented. Analysis keys not built here: `accounts.last_login` (lastlog needs a positional-read primitive and is gone on Ubuntu 24.04; no 2B item needs it), `accounts.duplicate_uids` (the per-user `uid_duplicate` flag plus observations name the colliding users) and `accounts.nis_domain` (no 2B item reads it).

---

### Task 1: login.defs strings, boundaries and PASS_WARN_AGE

**Files:**
- Modify: `internal/collect/collectors/accounts.go` (the `loginDefs` reader gains `str` and `intOr`; `runAccounts` writes nine more keys; `ageingExtremes` gains the warn minimum)
- Create: `internal/collect/collectors/accounts_test.go`, `internal/collect/collectors/testdata/login.defs_2b`, `internal/collect/collectors/testdata/shadow_2b`
- Modify: `internal/facts/registry.yaml` (9 keys), `internal/facts/testdata/facts-schema.golden.json` (regenerated)

**Interfaces:**
- Consumes: `loginDefs{lines, meta, err}` and `(loginDefs).value(key string) facts.Envelope` (existing); `shadowRow` (existing); `collect.OKRead`, `collect.Absent`, `collect.FromReadError`; `b.SetSetting`.
- Produces: `func (d loginDefs) str(key string) facts.Envelope` (the value after the key, trimmed, verbatim); `func (d loginDefs) intOr(key string, def int) int` (the integer value or `def` when unset/unparsable/unreadable — used by Task 2 for `UID_MIN`); `func ageingWarn(rows []shadowRow, meta collect.ReadMeta) facts.Envelope` (minimum `warn` over hashed rows); the nine registry keys listed in the inventory. `shadow_2b` (used by Tasks 2–3 too) is created here.

- [ ] **Step 1: Write the fixtures and the failing test**

`internal/collect/collectors/testdata/login.defs_2b` (tabs or spaces both occur in real files; keep the `UMASKX` decoy line before `UMASK`):

```
# synthetic login.defs for plan 2B
PASS_MAX_DAYS	90
PASS_MIN_DAYS	1
PASS_WARN_AGE	7
PASS_MIN_LEN	8
UID_MIN 1000
UID_MAX 60000
SYS_UID_MAX 999
UMASKX 077
UMASK		022
HOME_MODE	0750
ENCRYPT_METHOD SHA512
SHA_CRYPT_MIN_ROUNDS 5000
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin
```

`internal/collect/collectors/testdata/shadow_2b` (every hash is the literal word "hashhash…"; `toor` is a locked account that still holds an MD5 hash, `carol` a legacy 13-character DES-style field, `bob` an empty field):

```
root:$6$saltsalt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19000:0:99999:7:::
toor:!$1$saltsalt$hashhashhashhashhashhash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
sync:*:19000:0:99999:7:::
lp:*:19000:0:99999:7:::
ftp:!!:19000:0:99999:7:::
svc:!:19000:0:99999:7:::
alice:$y$j9T$saltsalt$hashhashhashhashhashhashhashhashhashhashhash:19500:1:90:14:::
bob::19500:0:99999:7:::
carol:hashhashhashh:19500:0:99999:3:::
dave:$5$saltsalt$hashhashhashhashhashhashhashhash:19500:0:99999:7:::
```

`internal/collect/collectors/accounts_test.go`:

```go
//go:build linux

package collectors

import (
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// Task 1: login.defs values that are not numbers are kept verbatim, the
// boundaries are integers, and a key must match whole (UMASKX is not UMASK).
func TestLoginDefsStringsAndBoundaries(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs_2b",
		"/etc/shadow":     "shadow_2b",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	for key, want := range map[string]any{
		"accounts.login_defs.umask":                "022",
		"accounts.login_defs.home_mode":            "0750",
		"accounts.login_defs.encrypt_method":       "SHA512",
		"accounts.login_defs.env_supath":           "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"accounts.login_defs.env_path":             "PATH=/usr/local/bin:/usr/bin:/bin",
		"accounts.login_defs.uid_min":              1000,
		"accounts.login_defs.sys_uid_max":          999,
		"accounts.login_defs.sha_crypt_min_rounds": 5000,
	} {
		if e := env(t, b, key); e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("%s = %+v, want %v", key, e, want)
		}
	}
	if e := env(t, b, "accounts.login_defs.umask"); e.Source == nil || e.Source.Line != 10 {
		t.Errorf("umask must cite line 10 (the UMASK line, not the UMASKX decoy): %+v", e.Source)
	}
	w := setting(t, b, "accounts.login_defs.pass_warn_age")
	if w.Persisted == nil || w.Persisted.Value != 7 || w.Runtime == nil || w.Runtime.Value != 3 || w.Runtime.Source.Kind != "derived" {
		t.Errorf("pass_warn_age persisted %+v runtime %+v (runtime is the minimum warn over hashed rows: carol's 3)", w.Persisted, w.Runtime)
	}
}

func TestLoginDefsUnsetStringIsAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd", "/etc/shadow": "shadow"}}
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.login_defs.umask"); e.Status != facts.StatusAbsent {
		t.Errorf("UMASK is not in the stage-1 fixture: %+v", e)
	}
	if e := env(t, b, "accounts.login_defs.uid_min"); e.Status != facts.StatusOK || e.Value != 1000 {
		t.Errorf("UID_MIN 1000 is in the stage-1 fixture: %+v", e)
	}
}

func TestLoginDefsIntOrFallsBack(t *testing.T) {
	d := loginDefs{lines: []string{"UID_MIN abc", "SYS_UID_MAX 999"}}
	if got := d.intOr("UID_MIN", 1000); got != 1000 {
		t.Errorf("unparsable UID_MIN must fall back, got %d", got)
	}
	if got := d.intOr("SYS_UID_MAX", 999); got != 999 {
		t.Errorf("got %d", got)
	}
	if got := d.intOr("UID_MAX", 60000); got != 60000 {
		t.Errorf("unset UID_MAX must fall back, got %d", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/collectors/ -run "TestLoginDefs" -v -count=1`
Expected: FAIL — `d.intOr undefined`, then a panic on the unregistered key `accounts.login_defs.umask` once the registry lags.

- [ ] **Step 3: Implement**

`internal/facts/registry.yaml` — append after `accounts.login_defs.pass_min_len` (keep the file's style; `since: 1`, `sensitivity: public`, `collector: accounts`):

```yaml
  - key: accounts.login_defs.pass_warn_age
    type: setting<int>
    description: PASS_WARN_AGE - persisted in login.defs, effective as the minimum warn field over existing accounts' shadow rows.
    since: 1
    sensitivity: public
    collector: accounts
    default_on: both
  - key: accounts.login_defs.uid_min
    type: int
    description: UID_MIN from login.defs, the lowest uid of a regular (non-system) account.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.sys_uid_max
    type: int
    description: SYS_UID_MAX from login.defs, the highest uid useradd assigns to a system account.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.sha_crypt_min_rounds
    type: int
    description: SHA_CRYPT_MIN_ROUNDS from login.defs.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.umask
    type: string
    description: UMASK from login.defs, verbatim (a mask, not a number).
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.home_mode
    type: string
    description: HOME_MODE from login.defs, verbatim.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.encrypt_method
    type: string
    description: ENCRYPT_METHOD from login.defs, verbatim (SHA512, YESCRYPT, ...); PAM may override it.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.env_supath
    type: string
    description: ENV_SUPATH from login.defs, verbatim (the PATH= assignment for root logins).
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.login_defs.env_path
    type: string
    description: ENV_PATH from login.defs, verbatim (the PATH= assignment for other logins).
    since: 1
    sensitivity: public
    collector: accounts
```

`internal/collect/collectors/accounts.go` — add to the `loginDefs` reader:

```go
// str returns key's value verbatim — everything after the key, trimmed —
// with the line as evidence. login.defs values such as ENV_SUPATH contain
// "=" and ":" and UMASK is a mask, so nothing is parsed as a number here.
// The key must be followed by whitespace: UMASKX is not UMASK.
func (d loginDefs) str(key string) facts.Envelope {
	if d.err != nil {
		return collect.FromReadError(d.err, d.meta)
	}
	for i, raw := range d.lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(line, key)
		if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		return collect.OKRead(strings.TrimSpace(rest), &facts.Source{
			Kind: "file", Path: loginDefsPath, Line: i + 1, Raw: sourceRaw(raw),
		}, d.meta)
	}
	return collect.Absent(key + " is not set in " + loginDefsPath)
}

// intOr is value(key) for callers that need a number to work with rather
// than a fact to report: the integer when the key is set and parses, def
// otherwise (unset, unparsable or an unreadable file).
func (d loginDefs) intOr(key string, def int) int {
	e := d.value(key)
	if e.Status != facts.StatusOK {
		return def
	}
	n, ok := e.Value.(int)
	if !ok {
		return def
	}
	return n
}

// ageingWarn is the smallest PASS_WARN_AGE that applies to an account with
// a password hash (shadow field 6), the runtime side of pass_warn_age.
func ageingWarn(rows []shadowRow, meta collect.ReadMeta) facts.Envelope {
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: shadowPath}}}
	mn := -1
	for _, r := range rows {
		if r.status != "hashed" || r.warn < 0 {
			continue
		}
		if mn < 0 || r.warn < mn {
			mn = r.warn
		}
	}
	if mn < 0 {
		return collect.Absent("no account with a password hash carries this ageing field")
	}
	return collect.OKRead(mn, derived, meta)
}
```

In `runAccounts`, right after the `pass_min_len` line, add the persisted reads, and after `maxR, minR = ageingExtremes(rows, smeta)` derive the warn side:

```go
	b.Set("accounts.login_defs.pass_min_len", defs.value("PASS_MIN_LEN"))
	maxP, minP, warnP := defs.value("PASS_MAX_DAYS"), defs.value("PASS_MIN_DAYS"), defs.value("PASS_WARN_AGE")
	// Fixed order (same input, same bytes): the integer boundaries, then the
	// verbatim strings.
	b.Set("accounts.login_defs.uid_min", defs.value("UID_MIN"))
	b.Set("accounts.login_defs.sys_uid_max", defs.value("SYS_UID_MAX"))
	b.Set("accounts.login_defs.sha_crypt_min_rounds", defs.value("SHA_CRYPT_MIN_ROUNDS"))
	for _, k := range [...]struct{ leaf, name string }{
		{"umask", "UMASK"}, {"home_mode", "HOME_MODE"}, {"encrypt_method", "ENCRYPT_METHOD"},
		{"env_supath", "ENV_SUPATH"}, {"env_path", "ENV_PATH"},
	} {
		b.Set("accounts.login_defs."+k.leaf, defs.str(k.name))
	}

	shadowData, smeta, serr := a.ReadFile(shadowPath, readLimit)
	var rows []shadowRow
	var maxR, minR, warnR facts.Envelope
	if serr != nil {
		maxR = collect.FromReadError(serr, smeta)
		minR = collect.FromReadError(serr, smeta)
		warnR = collect.FromReadError(serr, smeta)
	} else {
		rows = parseShadow(shadowData)
		maxR, minR = ageingExtremes(rows, smeta)
		warnR = ageingWarn(rows, smeta)
	}
	b.SetSetting("accounts.login_defs.pass_max_days", facts.Setting{Runtime: &maxR, Persisted: &maxP})
	b.SetSetting("accounts.login_defs.pass_min_days", facts.Setting{Runtime: &minR, Persisted: &minP})
	b.SetSetting("accounts.login_defs.pass_warn_age", facts.Setting{Runtime: &warnR, Persisted: &warnP})
```

(The existing comment on the unreadable-shadow branch stays.) Regenerate the golden: `go test ./internal/facts -run TestFactsSchemaGolden -update` and check the diff adds exactly nine `"Key":` entries.

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/collectors/ -run "TestLoginDefs|TestAccounts" -v -count=1` (the three stage-1 accounts tests must stay green), then `go test ./internal/collect/... -race -shuffle=on -count=1`. Windows: `go test ./... -count=1`, `go run ./cmd/muster controls lint --references docs/reference` (`ok: 8 controls`, the unused-keys note grows by nine).

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/accounts.go internal/collect/collectors/accounts_test.go internal/collect/collectors/testdata/login.defs_2b internal/collect/collectors/testdata/shadow_2b internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Read login.defs strings, uid boundaries and PASS_WARN_AGE"
```

---

### Task 2: The user record's joins, the hash-algorithm fix and /etc/shells

**Files:**
- Create: `internal/collect/collectors/accounts_passwd.go`, `internal/collect/collectors/testdata/passwd_2b`, `internal/collect/collectors/testdata/shells_2b`
- Modify: `internal/collect/collectors/accounts.go` (`hashAlgo`; `Declare.Reads` gains `/etc/shells`; the passwd loop in `runAccounts` is replaced by `parsePasswd` + `deriveUsers`; `parse_failures` written), `internal/collect/collectors/accounts_test.go`
- Modify: `internal/facts/registry.yaml` (`accounts.shells`, `accounts.parse_failures`; the `accounts.users` description), golden regenerated

**Interfaces:**
- Consumes: `loginDefs.intOr("UID_MIN", 1000)` (T1); `shadowRow` and `parseShadow` (existing); `passwordStatus` (existing).
- Produces: `type passwdRow struct{ name, home, shell string; uid, gid int; shadowed bool; line int }`; `func parsePasswd(data []byte) (rows []passwdRow, failures int)`; `func loginShells(a collect.Access) (set map[string]bool, list facts.Envelope)`; `func deriveUsers(rows []passwdRow, shadow map[string]shadowRow, haveShadow bool, uidMin int, shells map[string]bool) []any`. Task 3 consumes `parsePasswd`'s rows (for the group joins) and the `failures` count; Task 6's controls read the fields `uid`, `name`, `system`, `shell_valid`, `uid_duplicate`, `password_status`, `hash_algo`.

- [ ] **Step 1: Write the fixtures and the failing tests**

`internal/collect/collectors/testdata/passwd_2b` (13 kept rows plus one dropped line; `toor` is a uid-0 alias, `alice`/`bob` share uid 1000, `alice` appears twice, `carol`'s gid 4242 has no group, `ftp` has an interactive shell, `dave` carries hash material in the passwd field, `badu` has a non-numeric uid):

```
root:x:0:0:root:/root:/bin/bash
toor:x:0:0:alias:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/bin/bash
svc:x:998:998::/:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1000:1001::/home/bob:/bin/bash
carol:x:1001:4242::/home/carol:/bin/bash
alice:x:1002:1000::/home/alice2:/bin/sh
dave:hashhashhashh:1003:1000::/home/dave:/bin/bash
mangled line without fields
badu:x:notanumber:1000::/home/badu:/bin/bash
```

`internal/collect/collectors/testdata/shells_2b`:

```
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash

/bin/dash
```

Append to `internal/collect/collectors/accounts_test.go`:

```go
func accounts2B() *fsAccess {
	return &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs_2b",
		"/etc/passwd":     "passwd_2b",
		"/etc/shadow":     "shadow_2b",
		"/etc/shells":     "shells_2b",
	}}
}

func userNamed(t *testing.T, users []any, name string, nth int) map[string]any {
	t.Helper()
	seen := 0
	for _, u := range users {
		m := u.(map[string]any)
		if m["name"] == name {
			if seen == nth {
				return m
			}
			seen++
		}
	}
	t.Fatalf("no user %q (occurrence %d)", name, nth)
	return nil
}

// Task 2: the joins inside /etc/passwd are fields of every user record,
// a mangled file is counted, and the shell's validity comes from /etc/shells.
func TestAccountsUsersCarryTheInFileJoins(t *testing.T) {
	b := build(t, "accounts", accounts2B())
	users := okList(t, b, "accounts.users")
	if len(users) != 13 {
		t.Fatalf("%d users, want 13 (12 well-formed rows plus badu with uid -1)", len(users))
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 2 {
		t.Errorf("parse_failures = %+v, want 2 (the mangled line and badu's uid)", e)
	}
	root := userNamed(t, users, "root", 0)
	if root["home"] != "/root" || root["system"] != false || root["shadowed"] != true || root["uid_duplicate"] != true || root["name_duplicate"] != false || root["shell_valid"] != true {
		t.Errorf("root %v", root)
	}
	if toor := userNamed(t, users, "toor", 0); toor["uid_duplicate"] != true || toor["system"] != false {
		t.Errorf("toor %v (uid 0 is neither system nor unique)", toor)
	}
	if d := userNamed(t, users, "daemon", 0); d["system"] != true || d["shell_valid"] != false {
		t.Errorf("daemon %v", d)
	}
	if s := userNamed(t, users, "sync", 0); s["shell_valid"] != false {
		t.Errorf("sync %v (/bin/sync is not in /etc/shells)", s)
	}
	if f := userNamed(t, users, "ftp", 0); f["shell_valid"] != true || f["system"] != true {
		t.Errorf("ftp %v", f)
	}
	a1, a2 := userNamed(t, users, "alice", 0), userNamed(t, users, "alice", 1)
	if a1["uid_duplicate"] != true || a1["name_duplicate"] != true || a2["name_duplicate"] != true || a2["uid_duplicate"] != false {
		t.Errorf("alice rows %v %v", a1, a2)
	}
	if bob := userNamed(t, users, "bob", 0); bob["uid_duplicate"] != true || bob["password_status"] != "nopass" {
		t.Errorf("bob %v", bob)
	}
	if dave := userNamed(t, users, "dave", 0); dave["shadowed"] != false || dave["hash_algo"] != "$5$" {
		t.Errorf("dave %v (passwd field is not x; shadow row still joins)", dave)
	}
	if badu := userNamed(t, users, "badu", 0); badu["uid"] != -1 || badu["system"] != false {
		t.Errorf("badu %v (an unparsable uid is -1 and never system)", badu)
	}
	if e := env(t, b, "accounts.shells"); e.Status != facts.StatusOK {
		t.Errorf("shells %+v", e)
	} else if l := e.Value.([]any); len(l) != 4 || l[0] != "/bin/sh" || l[3] != "/bin/dash" {
		t.Errorf("shells %v (comments and blank lines dropped, order kept)", l)
	}
	for _, u := range users {
		for k, v := range u.(map[string]any) {
			if s, ok := v.(string); ok && strings.Contains(s, "hashhash") {
				t.Fatalf("hash material leaked into %s=%q", k, s)
			}
		}
	}
}

// R (analysis #15): a locked account that still holds a hash reports the
// hash's algorithm — the lock is its own flag. A hash without a "$id$"
// prefix is "legacy"; a bare lock marker has no algorithm at all.
func TestAccountsLockedAccountsKeepTheirHashAlgorithm(t *testing.T) {
	b := build(t, "accounts", accounts2B())
	users := okList(t, b, "accounts.users")
	if toor := userNamed(t, users, "toor", 0); toor["password_status"] != "locked" || toor["locked"] != true || toor["hash_algo"] != "$1$" {
		t.Errorf("toor %v", toor)
	}
	if svc := userNamed(t, users, "svc", 0); svc["locked"] != true || svc["hash_algo"] != "" {
		t.Errorf("svc %v (\"!\" alone is a lock without a hash)", svc)
	}
	if ftp := userNamed(t, users, "ftp", 0); ftp["locked"] != true || ftp["hash_algo"] != "" {
		t.Errorf("ftp %v (\"!!\" is a lock without a hash)", ftp)
	}
	if carol := userNamed(t, users, "carol", 0); carol["hash_algo"] != "legacy" || carol["password_status"] != "hashed" || carol["locked"] != false {
		t.Errorf("carol %v", carol)
	}
	if root := userNamed(t, users, "root", 0); root["locked"] != false || root["hash_algo"] != "$6$" {
		t.Errorf("root %v", root)
	}
}

func TestHashAlgoStripsLockMarkersAndNamesLegacy(t *testing.T) {
	for in, want := range map[string]string{
		"$6$salt$digest": "$6$", "!$6$salt$digest": "$6$", "!!$y$j9T$x$y": "$y$", "*$1$a$b": "$1$",
		"!": "", "!!": "", "*": "", "": "", "hashhashhashh": "legacy", "!hashhashhashh": "legacy",
		"$$": "", "$toolongidentifier$x": "",
	} {
		if got := hashAlgo(in); got != want {
			t.Errorf("hashAlgo(%q) = %q, want %q", in, got, want)
		}
	}
}

// /etc/shells missing is legitimate (getusershell(3) then answers /bin/sh
// and /bin/csh), so shell_valid still exists on every row and the list
// fact reports absent.
func TestAccountsShellsFallBackToTheLibcDefault(t *testing.T) {
	a := accounts2B()
	delete(a.files, "/etc/shells")
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.shells"); e.Status != facts.StatusAbsent {
		t.Errorf("shells %+v", e)
	}
	users := okList(t, b, "accounts.users")
	if r := userNamed(t, users, "root", 0); r["shell_valid"] != false {
		t.Errorf("root %v (/bin/bash is not in the libc fallback set)", r)
	}
	if a2 := userNamed(t, users, "alice", 1); a2["shell_valid"] != true {
		t.Errorf("alice2 %v (/bin/sh is)", a2)
	}
}
```

Add `"strings"` to the test file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/collectors/ -run "TestAccountsUsersCarry|TestAccountsLocked|TestHashAlgo|TestAccountsShells" -v -count=1`
Expected: FAIL — `accounts2B` compiles but `accounts.parse_failures` panics as unregistered; `TestHashAlgoStripsLockMarkers` fails on `"!$6$…"` (today `""`).

- [ ] **Step 3: Implement**

Registry (append after `accounts.users`; also replace `accounts.users`'s `description` with the text below):

```yaml
    description: Local accounts in /etc/passwd order with name, uid, gid, home, shell, system (0 < uid < UID_MIN), shadowed (passwd field is x), uid_duplicate, name_duplicate, shell_valid (shell listed in /etc/shells) and, when /etc/shadow was read, password_status (hashed | locked | nopass), locked, hash_algo ("$6$"-style id, "legacy" for a hash without one, "" when there is no hash) and the ageing fields; no hashes. Ageing fields are -1 when the shadow field is empty, and uid/gid are -1 when the passwd field is unparsable.
```

```yaml
  - key: accounts.shells
    type: list<string>
    description: The login shells listed in /etc/shells, in file order; absent when the file does not exist (libc then treats /bin/sh and /bin/csh as the valid shells).
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.parse_failures
    type: int
    description: Lines of /etc/passwd and /etc/group that could not be parsed as an account or group (too few fields, a non-numeric uid or gid); a mangled file must not read as a clean host.
    since: 1
    sensitivity: public
    collector: accounts
```

`internal/collect/collectors/accounts_passwd.go`:

```go
//go:build linux

package collectors

import (
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const shellsPath = "/etc/shells"

// passwdRow is one /etc/passwd line. shadowed is whether the password
// field defers to /etc/shadow ("x"); anything else in that field is hash
// material or an empty password, and neither is kept.
type passwdRow struct {
	name, home, shell string
	uid, gid          int
	shadowed          bool
	line              int
}

// parsePasswd keeps every line with the seven passwd fields and counts the
// rest, so a mangled file shows up as parse_failures rather than as a
// shorter, cleaner-looking account list. A row whose uid or gid is not a
// number is kept with -1 (the stage-1 contract) and counted as a failure.
// Blank lines and comments are neither.
func parsePasswd(data []byte) (rows []passwdRow, failures int) {
	for i, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			failures++
			continue
		}
		r := passwdRow{name: f[0], shadowed: f[1] == "x", uid: intField(f[2]), gid: intField(f[3]), home: f[5], shell: f[6], line: i + 1}
		if r.uid < 0 || r.gid < 0 {
			failures++
		}
		rows = append(rows, r)
	}
	return rows, failures
}

// libcShells is what getusershell(3) answers when /etc/shells is missing.
var libcShells = []string{"/bin/sh", "/bin/csh"}

// loginShells reads /etc/shells into a set for the shell_valid join and a
// list fact for evidence. A missing file is a legitimate state (the libc
// fallback applies, and the fact is absent); an unreadable one is reported
// on the fact and the fallback still keeps shell_valid present on every
// row, so a control never meets a record without the field.
func loginShells(a collect.Access) (map[string]bool, facts.Envelope) {
	data, meta, err := a.ReadFile(shellsPath, readLimit)
	if err != nil {
		set := map[string]bool{}
		for _, s := range libcShells {
			set[s] = true
		}
		return set, collect.FromReadError(err, meta)
	}
	set := map[string]bool{}
	list := []any{} // R50: never nil
	for _, l := range splitLines(data) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		set[l] = true
		list = append(list, l)
	}
	return set, collect.OKRead(list, &facts.Source{Kind: "file", Path: shellsPath}, meta)
}

// deriveUsers builds the accounts.users records: the passwd fields, the
// joins that need only /etc/passwd itself (duplicate uid, duplicate name,
// system by the UID_MIN boundary, shell validity by /etc/shells) and, when
// /etc/shadow was read, the shadow-derived fields. Rows keep file order.
func deriveUsers(rows []passwdRow, shadow map[string]shadowRow, haveShadow bool, uidMin int, shells map[string]bool) []any {
	uidCount := map[int]int{}
	nameCount := map[string]int{}
	for _, r := range rows {
		if r.uid >= 0 {
			uidCount[r.uid]++
		}
		nameCount[r.name]++
	}
	users := []any{} // R50: a host with no parsable accounts yields [], not null
	for _, r := range rows {
		u := map[string]any{
			"name":           r.name,
			"uid":            r.uid,
			"gid":            r.gid,
			"home":           r.home,
			"shell":          r.shell,
			"system":         r.uid > 0 && r.uid < uidMin,
			"shadowed":       r.shadowed,
			"uid_duplicate":  r.uid >= 0 && uidCount[r.uid] > 1,
			"name_duplicate": nameCount[r.name] > 1,
			"shell_valid":    shells[r.shell],
		}
		// Without shadow the row simply has no password or ageing fields,
		// rather than zeroes that would read as a policy nobody set.
		if s, ok := shadow[r.name]; haveShadow && ok {
			u["password_status"] = s.status
			u["locked"] = s.status == "locked"
			u["hash_algo"] = s.algo
			u["last_change"] = s.lastChange
			u["min"] = s.min
			u["max"] = s.max
			u["warn"] = s.warn
			u["inactive"] = s.inactive
			u["expire"] = s.expire
		}
		users = append(users, u)
	}
	return users
}
```

`accounts.go` — replace `hashAlgo`'s body and the top of its comment:

```go
// hashAlgo returns the "$id$" prefix of a crypt hash and nothing else: no
// salt, no digest, not one byte of either. The field is first stripped of
// the "!" and "*" characters that lock an account, because a locked
// account holding an MD5 hash still holds an MD5 hash — the lock is
// reported as its own field. A non-empty remainder with no "$id$" prefix
// is hash material of a legacy scheme (DES, BSDi) and is named "legacy".
//
// The id has to look like one — 1 to 8 alphanumeric characters, which
// covers every crypt scheme in use ("1", "5", "6", "y", "2b", "gy",
// "argon2id") — because a malformed password field is not evidence of an
// algorithm, it is hash material. Without that check a line whose second
// "$" lands far into the digest would copy the digest into the snapshot
// under the name "hash_algo". The result is built from the id rather than
// sliced out of pw, so it cannot keep the whole shadow line alive behind
// it either.
func hashAlgo(pw string) string {
	pw = strings.TrimLeft(pw, "!*")
	if pw == "" {
		return ""
	}
	if !strings.HasPrefix(pw, "$") {
		return "legacy"
	}
	id, _, ok := strings.Cut(pw[1:], "$")
	if !ok || len(id) == 0 || len(id) > 8 || !isAlphanumeric(id) {
		return ""
	}
	return "$" + id + "$"
}
```

`accounts.go` — the declaration and the tail of `runAccounts` (replace everything from `pwData, pmeta, perr := …` to the end):

```go
var accountsCollector = collect.Collector{
	Name:    "accounts",
	Declare: collect.Declaration{Reads: []string{loginDefsPath, passwdPath, shadowPath, shellsPath}, Needs: "root"},
	Run:     runAccounts,
}
```

```go
	pwData, pmeta, perr := a.ReadFile(passwdPath, readLimit)
	shells, shellsEnv := loginShells(a)
	b.Set("accounts.shells", shellsEnv)
	if perr != nil {
		e := collect.FromReadError(perr, pmeta)
		b.Set("accounts.users", e)
		b.Set("accounts.parse_failures", e)
		return nil
	}
	prows, failures := parsePasswd(pwData)
	byName := make(map[string]shadowRow, len(rows))
	for _, r := range rows {
		byName[r.name] = r
	}
	users := deriveUsers(prows, byName, serr == nil, defs.intOr("UID_MIN", 1000), shells)
	b.Set("accounts.users", collect.OKRead(users, &facts.Source{Kind: "file", Path: passwdPath}, pmeta))
	b.Set("accounts.parse_failures", collect.OK(failures, &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: passwdPath}}}))
	return nil
```

Regenerate the golden (two new keys; the `accounts.users` description changes its `Description` line).

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/collectors/ -run "TestAccounts|TestHashAlgo|TestLoginDefs" -v -count=1` — the stage-1 tests `TestAccountsDerivesRuntimeAgeingWithoutStoringHashes` (3 users, root `$6$`, svc `locked`, alice `$y$`), `TestAccountsShadowDeniedIsDeniedNotAbsent` (no `password_status` when shadow is denied) and `TestAccountsRejectsAnImplausibleHashId` must stay green; then `go test ./internal/collect/... -race -shuffle=on -count=1`. Windows: `go test ./... -count=1`, `GOOS=linux GOARCH=amd64 go vet ./...`.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/accounts.go internal/collect/collectors/accounts_passwd.go internal/collect/collectors/accounts_test.go internal/collect/collectors/testdata/passwd_2b internal/collect/collectors/testdata/shells_2b internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Derive the in-file account joins, keep a locked account's hash algorithm and read /etc/shells"
```

---

### Task 3: Groups, orphan gids, administrative membership and shadow-in-use

**Files:**
- Create: `internal/collect/collectors/accounts_groups.go`, `internal/collect/collectors/testdata/group_2b`
- Modify: `internal/collect/collectors/accounts.go` (`Declare.Reads` gains `/etc/group`; `runAccounts` reads it and writes four keys; `parse_failures` becomes the sum), `internal/collect/collectors/accounts_test.go`
- Modify: `internal/facts/registry.yaml` (4 keys), golden regenerated

**Interfaces:**
- Consumes: `passwdRow`, `parsePasswd` (T2); `groupPath` (defined in `permfacts.go` by 2A); `collect.OK`, `collect.OKRead`, `collect.FromReadError`.
- Produces: `type groupRow struct{ name string; gid int; members []string; line int }`; `func parseGroup(data []byte) (rows []groupRow, failures int)`; `func groupRecords(rows []groupRow) []any`; `func orphanGIDs(users []passwdRow, groups []groupRow) []any`; `var adminGroups = []string{"root", "wheel", "sudo", "admin"}`; `func adminGroupMembers(users []passwdRow, groups []groupRow) []any`; `func shadowInUse(users []passwdRow, serr error, smeta, pmeta collect.ReadMeta) facts.Envelope`; the keys `accounts.groups`, `accounts.orphan_gids`, `accounts.admin_group_members`, `accounts.shadow_in_use`. Tasks 6–7 read `orphan_gids` (fields `name`, `gid`), `admin_group_members` (fields `name`, `group`, `via`) and `shadow_in_use`.

- [ ] **Step 1: Write the fixture and the failing tests**

`internal/collect/collectors/testdata/group_2b` (`alice` and `dupgid` share gid 1000; `broken` has too few fields; `nogroup` is there so `sync`'s gid 65534 resolves; `carol`'s 4242 deliberately does not):

```
root:x:0:
daemon:x:1:
lp:x:7:
wheel:x:10:carol
sudo:x:27:alice,bob,alice
users:x:50:
svc:x:998:
alice:x:1000:
bob:x:1001:
dupgid:x:1000:
nogroup:x:65534:
broken
```

Append to `accounts_test.go` (add `"os"` to its imports):

```go
func accounts2BWithGroup() *fsAccess {
	a := accounts2B()
	a.files["/etc/group"] = "group_2b"
	return a
}

func record(t *testing.T, list []any, i int) map[string]any {
	t.Helper()
	if i >= len(list) {
		t.Fatalf("element %d of %d", i, len(list))
	}
	return list[i].(map[string]any)
}

// Task 3: groups keep file order and count their listed members; the
// primary-group join and the administrative membership are their own keys.
func TestAccountsGroupsOrphansAndAdminMembers(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	groups := okList(t, b, "accounts.groups")
	if len(groups) != 11 {
		t.Fatalf("%d groups, want 11", len(groups))
	}
	sudo := record(t, groups, 4)
	if sudo["name"] != "sudo" || sudo["gid"] != 27 || sudo["member_count"] != 2 || sudo["gid_duplicate"] != false {
		t.Errorf("sudo %v (a member listed twice counts once)", sudo)
	}
	if m := sudo["members"].([]any); len(m) != 2 || m[0] != "alice" || m[1] != "bob" {
		t.Errorf("sudo members %v", m)
	}
	if g := record(t, groups, 7); g["name"] != "alice" || g["gid_duplicate"] != true {
		t.Errorf("alice group %v", g)
	}
	if g := record(t, groups, 9); g["name"] != "dupgid" || g["gid_duplicate"] != true {
		t.Errorf("dupgid %v", g)
	}
	if g := record(t, groups, 0); g["member_count"] != 0 || g["gid_duplicate"] != false {
		t.Errorf("root group %v", g)
	}
	orphans := okList(t, b, "accounts.orphan_gids")
	if len(orphans) != 1 || record(t, orphans, 0)["name"] != "carol" || record(t, orphans, 0)["gid"] != 4242 {
		t.Errorf("orphan_gids %v", orphans)
	}
	admins := okList(t, b, "accounts.admin_group_members")
	want := []map[string]any{
		{"name": "toor", "group": "root", "via": "primary"},
		{"name": "carol", "group": "wheel", "via": "secondary"},
		{"name": "alice", "group": "sudo", "via": "secondary"},
		{"name": "bob", "group": "sudo", "via": "secondary"},
	}
	if len(admins) != len(want) {
		t.Fatalf("admin_group_members %v", admins)
	}
	for i, w := range want {
		got := record(t, admins, i)
		for k, v := range w {
			if got[k] != v {
				t.Errorf("admin[%d] %v, want %v", i, got, w)
			}
		}
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 3 {
		t.Errorf("parse_failures %+v, want 3 (two passwd, one group)", e)
	}
}

func TestAccountsShadowInUse(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	if e := env(t, b, "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "dave") {
		t.Errorf("%+v (dave keeps hash material in /etc/passwd)", e)
	}
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd", "/etc/shadow": "shadow"}}
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("stage-1 fixtures: %+v", e)
	}
	delete(a.files, "/etc/shadow")
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "/etc/shadow") {
		t.Errorf("no shadow file: %+v", e)
	}
	a.fails = map[string]error{"/etc/shadow": os.ErrPermission}
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/shadow: ") {
		t.Errorf("denied shadow: %+v", e)
	}
}

// A denied /etc/group costs the three group-derived keys and nothing else:
// users and the passwd-only joins still come out, and parse_failures counts
// what was parsed.
func TestAccountsGroupDeniedReachesOnlyTheGroupJoins(t *testing.T) {
	a := accounts2B()
	a.fails = map[string]error{"/etc/group": os.ErrPermission}
	b := build(t, "accounts", a)
	for _, k := range []string{"accounts.groups", "accounts.orphan_gids", "accounts.admin_group_members"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/group: ") {
			t.Errorf("%s = %+v", k, e)
		}
	}
	if users := okList(t, b, "accounts.users"); len(users) != 13 {
		t.Errorf("%d users", len(users))
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 2 {
		t.Errorf("parse_failures %+v", e)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/collectors/ -run "TestAccountsGroups|TestAccountsShadowInUse|TestAccountsGroupDenied" -v -count=1`
Expected: FAIL — panic on the unregistered `accounts.groups`, then `no such key` for the others.

- [ ] **Step 3: Implement**

Registry (append after `accounts.parse_failures`):

```yaml
  - key: accounts.groups
    type: list<record>
    description: Local groups in /etc/group order with name, gid, members (the listed secondary members, duplicates removed), member_count and gid_duplicate.
    since: 1
    sensitivity: public
    collector: accounts
    subject_kind: group
  - key: accounts.orphan_gids
    type: list<record>
    description: Accounts whose primary gid names no group in /etc/group, as name and gid in /etc/passwd order; [] when every primary group exists; carries the read's status when /etc/passwd or /etc/group is unreadable.
    since: 1
    sensitivity: public
    collector: accounts
    subject_kind: user
  - key: accounts.admin_group_members
    type: list<record>
    description: Members of the administrative groups root, wheel, sudo and admin other than the root account itself - name, group and via (primary when the account's gid is the group's, secondary when listed in /etc/group) - in /etc/group order, primary members before secondary ones.
    since: 1
    sensitivity: public
    collector: accounts
    subject_kind: user
  - key: accounts.shadow_in_use
    type: bool
    description: Whether /etc/shadow exists and every /etc/passwd entry defers to it (password field x); a false names the first account that does not; carries the read's status when /etc/shadow or /etc/passwd is unreadable.
    since: 1
    sensitivity: public
    collector: accounts
```

`internal/collect/collectors/accounts_groups.go`:

```go
//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// groupRow is one /etc/group line; members are the listed (secondary)
// members with duplicates removed, in list order.
type groupRow struct {
	name    string
	gid     int
	members []string
	line    int
}

// parseGroup mirrors parsePasswd: four fields or the line counts as a
// parse failure; a non-numeric gid is kept as -1 and counted.
func parseGroup(data []byte) (rows []groupRow, failures int) {
	for i, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			failures++
			continue
		}
		r := groupRow{name: f[0], gid: intField(f[2]), line: i + 1}
		if r.gid < 0 {
			failures++
		}
		seen := map[string]bool{}
		for _, m := range strings.Split(f[3], ",") {
			m = strings.TrimSpace(m)
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			r.members = append(r.members, m)
		}
		rows = append(rows, r)
	}
	return rows, failures
}

// groupRecords is the accounts.groups value: file order, member_count from
// the de-duplicated member list, gid_duplicate over the whole file.
func groupRecords(rows []groupRow) []any {
	gidCount := map[int]int{}
	for _, r := range rows {
		if r.gid >= 0 {
			gidCount[r.gid]++
		}
	}
	out := []any{} // R50
	for _, r := range rows {
		members := []any{}
		for _, m := range r.members {
			members = append(members, m)
		}
		out = append(out, map[string]any{
			"name":          r.name,
			"gid":           r.gid,
			"members":       members,
			"member_count":  len(r.members),
			"gid_duplicate": r.gid >= 0 && gidCount[r.gid] > 1,
		})
	}
	return out
}

// orphanGIDs lists the accounts whose primary gid is not any group's gid,
// in passwd order. A row with an unparsable gid (-1) is not an orphan: it
// is already a parse failure.
func orphanGIDs(users []passwdRow, groups []groupRow) []any {
	exists := map[int]bool{}
	for _, g := range groups {
		if g.gid >= 0 {
			exists[g.gid] = true
		}
	}
	out := []any{}
	for _, u := range users {
		if u.gid >= 0 && !exists[u.gid] {
			out = append(out, map[string]any{"name": u.name, "gid": u.gid})
		}
	}
	return out
}

// adminGroups are the groups whose membership the administrator items
// judge (root on every host, wheel on the RHEL family, sudo and admin on
// the Debian family).
var adminGroups = []string{"root", "wheel", "sudo", "admin"}

// adminGroupMembers lists, for each administrative group in /etc/group
// order, the accounts that belong to it other than root itself: first the
// accounts whose primary gid is the group's (passwd order), then the listed
// secondary members (list order). An account is listed once per group.
func adminGroupMembers(users []passwdRow, groups []groupRow) []any {
	admin := map[string]bool{}
	for _, g := range adminGroups {
		admin[g] = true
	}
	out := []any{}
	for _, g := range groups {
		if !admin[g.name] {
			continue
		}
		seen := map[string]bool{"root": true}
		add := func(name, via string) {
			if seen[name] {
				return
			}
			seen[name] = true
			out = append(out, map[string]any{"name": name, "group": g.name, "via": via})
		}
		for _, u := range users {
			if u.gid >= 0 && u.gid == g.gid {
				add(u.name, "primary")
			}
		}
		for _, m := range g.members {
			add(m, "secondary")
		}
	}
	return out
}

// shadowInUse derives accounts.shadow_in_use from the two reads. A missing
// /etc/shadow is a legitimate (and bad) state, so it is a false with the
// reason, not an absent fact; an unreadable one is the read's status, so a
// control can never turn "could not look" into "not in use".
func shadowInUse(users []passwdRow, serr error, smeta, pmeta collect.ReadMeta) facts.Envelope {
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: passwdPath}, {Kind: "file", Path: shadowPath}}}
	if serr != nil {
		if errors.Is(serr, fs.ErrNotExist) {
			e := collect.OK(false, derived)
			e.Reason = shadowPath + " does not exist"
			e.Truncated = pmeta.Truncated
			return e
		}
		e := collect.FromReadError(serr, smeta)
		e.Reason = shadowPath + ": " + e.Reason
		return e
	}
	e := collect.OK(true, derived)
	e.Truncated = smeta.Truncated || pmeta.Truncated
	for _, u := range users {
		if !u.shadowed {
			e.Value = false
			e.Reason = "account " + u.name + " keeps its password field in " + passwdPath
			break
		}
	}
	return e
}
```

`accounts.go` — the declaration gains `groupPath`, and the tail of `runAccounts` (from `pwData, pmeta, perr := …`) becomes:

```go
var accountsCollector = collect.Collector{
	Name:    "accounts",
	Declare: collect.Declaration{Reads: []string{loginDefsPath, passwdPath, shadowPath, groupPath, shellsPath}, Needs: "root"},
	Run:     runAccounts,
}
```

```go
	pwData, pmeta, perr := a.ReadFile(passwdPath, readLimit)
	shells, shellsEnv := loginShells(a)
	b.Set("accounts.shells", shellsEnv)
	gData, gmeta, gerr := a.ReadFile(groupPath, readLimit)
	var grows []groupRow
	gfail := 0
	if gerr == nil {
		grows, gfail = parseGroup(gData)
	}
	groupErr := func() facts.Envelope {
		e := collect.FromReadError(gerr, gmeta)
		e.Reason = groupPath + ": " + e.Reason
		return e
	}
	if perr != nil {
		// Without /etc/passwd there are no accounts to report or to join;
		// the groups themselves are still a fact when /etc/group was read.
		e := collect.FromReadError(perr, pmeta)
		b.Set("accounts.users", e)
		if gerr != nil {
			b.Set("accounts.groups", groupErr())
		} else {
			b.Set("accounts.groups", collect.OKRead(groupRecords(grows), &facts.Source{Kind: "file", Path: groupPath}, gmeta))
		}
		b.Set("accounts.orphan_gids", e)
		b.Set("accounts.admin_group_members", e)
		b.Set("accounts.shadow_in_use", e)
		b.Set("accounts.parse_failures", e)
		return nil
	}
	prows, failures := parsePasswd(pwData)
	byName := make(map[string]shadowRow, len(rows))
	for _, r := range rows {
		byName[r.name] = r
	}
	users := deriveUsers(prows, byName, serr == nil, defs.intOr("UID_MIN", 1000), shells)
	b.Set("accounts.users", collect.OKRead(users, &facts.Source{Kind: "file", Path: passwdPath}, pmeta))
	joined := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: passwdPath}, {Kind: "file", Path: groupPath}}}
	if gerr != nil {
		b.Set("accounts.groups", groupErr())
		b.Set("accounts.orphan_gids", groupErr())
		b.Set("accounts.admin_group_members", groupErr())
	} else {
		b.Set("accounts.groups", collect.OKRead(groupRecords(grows), &facts.Source{Kind: "file", Path: groupPath}, gmeta))
		b.Set("accounts.orphan_gids", collect.OKRead(orphanGIDs(prows, grows), joined, gmeta))
		b.Set("accounts.admin_group_members", collect.OKRead(adminGroupMembers(prows, grows), joined, gmeta))
	}
	b.Set("accounts.shadow_in_use", shadowInUse(prows, serr, smeta, pmeta))
	inputs := []facts.Source{{Kind: "file", Path: passwdPath}}
	if gerr == nil {
		inputs = append(inputs, facts.Source{Kind: "file", Path: groupPath})
	}
	b.Set("accounts.parse_failures", collect.OK(failures+gfail, &facts.Source{Kind: "derived", Inputs: inputs}))
	return nil
```

Regenerate the golden (four new keys).

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/collectors/ -run "TestAccounts|TestLoginDefs|TestHashAlgo" -v -count=1`, then `go test ./internal/collect/... -race -shuffle=on -count=1`. Windows: `go test ./... -count=1`, `GOOS=linux GOARCH=amd64 go vet ./...`.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/accounts.go internal/collect/collectors/accounts_groups.go internal/collect/collectors/accounts_test.go internal/collect/collectors/testdata/group_2b internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Collect groups, orphan gids, administrative membership and shadow-in-use"
```

---

### Task 4: NSS sources and the remote-source degradation

**Files:**
- Create: `internal/collect/collectors/accounts_nss.go`, `internal/collect/collectors/testdata/nsswitch.conf`, `internal/collect/collectors/testdata/nsswitch_sss.conf`
- Modify: `internal/collect/collectors/accounts.go` (`Declare.Reads` gains `/etc/nsswitch.conf`; `runAccounts` writes three keys), `internal/collect/collectors/accounts_test.go`
- Modify: `internal/facts/registry.yaml` (3 keys), golden regenerated
- Modify: `internal/check/results.go` (`degradedRemoteNSS`), `internal/check/eval.go` (`remoteNSS` and its call), `internal/check/eval_test.go` (four derivation-table cases and a control helper)

**Interfaces:**
- Consumes: `e.reg.Resolve(e.snap, key)` and the `parseFallback` pattern in `eval.go`; `degradedParseFallback` naming in `results.go`.
- Produces: `func nssSources(data []byte, db string) (sources []string, line int, found bool)`; `func nssRemote(sourceLists ...[]string) bool`; keys `accounts.nss.passwd_sources`, `accounts.nss.group_sources`, `accounts.nss.remote`; `const degradedRemoteNSS = "remote NSS account source; judged on local files only"`; `func (e *env) remoteNSS(cls []controls.Clause) bool`. Later plans (2C, 2E) rely on the same hook for their account facts.

- [ ] **Step 1: Write the fixtures and the failing tests**

`internal/collect/collectors/testdata/nsswitch.conf`:

```
# /etc/nsswitch.conf
passwd:         files systemd
group:          files systemd
shadow:         files
hosts:          files dns
```

`internal/collect/collectors/testdata/nsswitch_sss.conf`:

```
passwd: files sss [NOTFOUND=return] ldap
group:  files sss
shadow: files sss
```

Append to `accounts_test.go`:

```go
// Task 4: the NSS sources of the two account databases, bracketed actions
// removed, and the derived "any remote source" flag.
func TestAccountsNSSSourcesAndRemote(t *testing.T) {
	a := accounts2BWithGroup()
	a.files["/etc/nsswitch.conf"] = "nsswitch.conf"
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.nss.passwd_sources"); e.Status != facts.StatusOK || e.Source == nil || e.Source.Line != 2 {
		t.Errorf("%+v", e)
	} else if l := e.Value.([]any); len(l) != 2 || l[0] != "files" || l[1] != "systemd" {
		t.Errorf("%v", l)
	}
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != false || e.Source.Kind != "derived" {
		t.Errorf("%+v", e)
	}

	a.files["/etc/nsswitch.conf"] = "nsswitch_sss.conf"
	b = build(t, "accounts", a)
	if l := okList(t, b, "accounts.nss.passwd_sources"); len(l) != 3 || l[1] != "sss" || l[2] != "ldap" {
		t.Errorf("%v (the [NOTFOUND=return] action is not a source)", l)
	}
	if e := env(t, b, "accounts.nss.remote"); e.Value != true {
		t.Errorf("%+v", e)
	}
}

func TestAccountsNSSFileMissingMeansLocal(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	if e := env(t, b, "accounts.nss.passwd_sources"); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v (glibc resolves from files when nsswitch.conf is missing)", e)
	}
	a := accounts2BWithGroup()
	a.fails = map[string]error{"/etc/nsswitch.conf": os.ErrPermission}
	b = build(t, "accounts", a)
	for _, k := range []string{"accounts.nss.passwd_sources", "accounts.nss.group_sources", "accounts.nss.remote"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s = %+v (unknown is not local)", k, e)
		}
	}
}

func TestNSSSourcesParsing(t *testing.T) {
	data := []byte("passwd: files sss [NOTFOUND=return] ldap\n# group: comment\ngroup:files\n")
	if s, line, ok := nssSources(data, "passwd"); !ok || line != 1 || strings.Join(s, ",") != "files,sss,ldap" {
		t.Errorf("%v %d %v", s, line, ok)
	}
	if s, line, ok := nssSources(data, "group"); !ok || line != 3 || strings.Join(s, ",") != "files" {
		t.Errorf("%v %d %v", s, line, ok)
	}
	if _, _, ok := nssSources(data, "shadow"); ok {
		t.Error("shadow is not listed")
	}
	if nssRemote([]string{"files", "systemd"}, []string{"compat"}) {
		t.Error("files/systemd/compat are local")
	}
	if !nssRemote([]string{"files"}, []string{"files", "winbind"}) {
		t.Error("winbind is remote")
	}
}
```

`internal/check/eval_test.go` — add a control helper beside `passMaxDaysControl` and four cases to `TestDerivationTable` after the two parse-fallback cases:

```go
// nopassControl reads an accounts.* list fact, which is what makes the
// step-13 remote-NSS degradation (spec §7.3) apply to it.
func nopassControl() controls.Control {
	return controls.Control{
		ID: "muster.account.shadow_passwords", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "fail",
		Checks:      []controls.Clause{{Fact: "accounts.users", Op: "none", Subject: "name", Where: &controls.Clause{Field: "password_status", Op: "eq", Expected: "nopass"}}},
		Remediation: &controls.Remediation{Risk: "lockout_risk"},
	}
}
```

```go
		// Spec §7.3: an account control judged while NSS names a remote
		// source is a degraded judgment — local files are only part of it.
		{"13 remote NSS source degrades a holding account control to WARN",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"users":{"status":"ok","value":[{"name":"root","password_status":"hashed"}]}}}`,
			nopassControl(), WARN, "",
			func(t *testing.T, r Result) {
				if r.Degraded != degradedRemoteNSS {
					t.Errorf("want Degraded=%q, got %q", degradedRemoteNSS, r.Degraded)
				}
				if !strings.Contains(r.Reason, "remote NSS") {
					t.Errorf("reason must name the degradation: %q", r.Reason)
				}
			}},
		{"13 remote NSS source leaves a failing account control at FAIL",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}},"users":{"status":"ok","value":[{"name":"bob","password_status":"nopass"}]}}}`,
			nopassControl(), FAIL, "", nil},
		{"13 remote NSS source does not touch a non-account control",
			`{"accounts":{"nss":{"remote":{"status":"ok","value":true}}},"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`,
			telnetControl("auto", "pass"), PASS, "", nil},
		{"13 an unreadable nsswitch is not a remote source",
			`{"accounts":{"nss":{"remote":{"status":"denied","reason":"/etc/nsswitch.conf: permission denied"}},"users":{"status":"ok","value":[{"name":"root","password_status":"hashed"}]}}}`,
			nopassControl(), PASS, "", nil},
```

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/collectors/ -run "TestAccountsNSS|TestNSSSources" -v -count=1` → FAIL (`nssSources` undefined). Windows: `go test ./internal/check/ -run TestDerivationTable -count=1` → FAIL (`degradedRemoteNSS` undefined).

- [ ] **Step 3: Implement**

Registry (append after `accounts.shadow_in_use`):

```yaml
  - key: accounts.nss.passwd_sources
    type: list<string>
    description: The sources on the passwd line of /etc/nsswitch.conf, in order, with bracketed actions removed; absent when the file or the line is missing (glibc then resolves from files).
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.nss.group_sources
    type: list<string>
    description: The sources on the group line of /etc/nsswitch.conf, in order, with bracketed actions removed; absent when the file or the line is missing.
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.nss.remote
    type: bool
    description: Whether the passwd or group database names a source other than files, compat, systemd or db (sss, ldap, nis, winbind, ...); account controls judged on the local files report WARN while this is true (spec section 7.3).
    since: 1
    sensitivity: public
    collector: accounts
```

`internal/collect/collectors/accounts_nss.go`:

```go
//go:build linux

package collectors

import (
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const nsswitchPath = "/etc/nsswitch.conf"

// localNSS are the sources that answer from this host's own files or
// runtime; anything else means accounts also come from somewhere else.
var localNSS = map[string]bool{"files": true, "compat": true, "systemd": true, "db": true}

// nssSources returns the sources of database db from nsswitch.conf: the
// words after "db:" that are not bracketed actions such as
// [NOTFOUND=return]. found is false when no such line exists (comments do
// not count), and line is the 1-based line of the one that does.
func nssSources(data []byte, db string) (sources []string, line int, found bool) {
	for i, raw := range splitLines(data) {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, rest, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(name) != db {
			continue
		}
		for _, w := range strings.Fields(rest) {
			if strings.HasPrefix(w, "[") || strings.HasSuffix(w, "]") {
				continue
			}
			sources = append(sources, w)
		}
		return sources, i + 1, true
	}
	return nil, 0, false
}

// nssRemote is true when any listed source is not local.
func nssRemote(sourceLists ...[]string) bool {
	for _, l := range sourceLists {
		for _, s := range l {
			if !localNSS[strings.ToLower(s)] {
				return true
			}
		}
	}
	return false
}

// writeNSS sets the three accounts.nss keys. A missing file is the glibc
// default (files), so remote is a confident false; an unreadable one is
// the read's status on every key, because "could not read" is not "local".
func writeNSS(a collect.Access, b *collect.Builder) {
	data, meta, err := a.ReadFile(nsswitchPath, readLimit)
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: nsswitchPath}}}
	if err != nil {
		e := collect.FromReadError(err, meta)
		if e.Status == facts.StatusAbsent {
			for _, k := range []string{"accounts.nss.passwd_sources", "accounts.nss.group_sources"} {
				b.Set(k, collect.Absent(nsswitchPath+" does not exist; libc resolves from files"))
			}
			b.Set("accounts.nss.remote", collect.OK(false, derived))
			return
		}
		e.Reason = nsswitchPath + ": " + e.Reason
		b.Set("accounts.nss.passwd_sources", e)
		b.Set("accounts.nss.group_sources", e)
		b.Set("accounts.nss.remote", e)
		return
	}
	var lists [][]string
	for _, db := range [...]struct{ key, name string }{{"accounts.nss.passwd_sources", "passwd"}, {"accounts.nss.group_sources", "group"}} {
		sources, line, found := nssSources(data, db.name)
		if !found {
			b.Set(db.key, collect.Absent(db.name+" is not listed in "+nsswitchPath))
			continue
		}
		lists = append(lists, sources)
		list := []any{} // R50
		for _, s := range sources {
			list = append(list, s)
		}
		b.Set(db.key, collect.OKRead(list, &facts.Source{Kind: "file", Path: nsswitchPath, Line: line}, meta))
	}
	b.Set("accounts.nss.remote", collect.OKRead(nssRemote(lists...), derived, meta))
}
```

`accounts.go`: the declaration's `Reads` gains `nsswitchPath` (after `shellsPath`), and `runAccounts` calls `writeNSS(a, b)` as its last statement before `return nil` on BOTH return paths (the passwd-unreadable branch and the normal end) — simplest: call it right after `b.Set("accounts.shells", shellsEnv)` so it runs once, before the branch.

`internal/check/results.go` — beside `degradedParseFallback`:

```go
	// degradedRemoteNSS marks an account control judged on the local files
	// while nsswitch names a remote source too (spec §7.3).
	degradedRemoteNSS = "remote NSS account source; judged on local files only"
```

`internal/check/eval.go` — after the parse-fallback block:

```go
	// Step 13 (spec §7.3): account facts come from the local files; when
	// NSS also resolves accounts remotely, a holding judgment is partial.
	if all.Degraded == "" && e.remoteNSS(checks) {
		all.Degraded = degradedRemoteNSS
	}
```

```go
// remoteNSS reports whether any clause reads an accounts.* fact (other
// than the nss facts themselves) while the snapshot says accounts.nss.remote
// is true. A missing, denied or absent nss fact is not a remote source.
func (e *env) remoteNSS(cls []controls.Clause) bool {
	reads := false
	for _, cl := range cls {
		if strings.HasPrefix(cl.Fact, "accounts.") && !strings.HasPrefix(cl.Fact, "accounts.nss.") {
			reads = true
			break
		}
	}
	if !reads {
		return false
	}
	res, err := e.reg.Resolve(e.snap, "accounts.nss.remote")
	if err != nil || res.Envelope == nil || res.Envelope.Status != facts.StatusOK {
		return false
	}
	remote, _ := res.Envelope.Value.(bool)
	return remote
}
```

Regenerate the golden (three keys).

- [ ] **Step 4: Run the tests to verify they pass**

Windows: `go test ./internal/check/ -run TestDerivationTable -v -count=1` (the four new cases and every existing one), `go test ./... -count=1`. Host: `go test ./internal/collect/collectors/ -run "TestAccountsNSS|TestNSSSources" -v -count=1`, `go test ./internal/collect/... -race -shuffle=on -count=1`. Confirm `internal/check/imports_test.go` still passes (no new import).

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/accounts.go internal/collect/collectors/accounts_nss.go internal/collect/collectors/accounts_test.go internal/collect/collectors/testdata/nsswitch.conf internal/collect/collectors/testdata/nsswitch_sss.conf internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json internal/check/results.go internal/check/eval.go internal/check/eval_test.go
git commit -m "Collect the NSS account sources and degrade account controls under a remote source"
```

---

### Task 5: /etc/shadow permission facts

**Files:**
- Modify: `internal/collect/collectors/files.go` (declare `/etc/shadow`; one `writePermFacts` call), `internal/collect/collectors/permfacts_test.go`
- Modify: `internal/facts/registry.yaml` (10 keys), golden regenerated

**Interfaces:**
- Consumes: `writePermFacts(b, a, prefix, path string, groups map[int]string, groupMeta collect.ReadMeta, groupErr error, withACL bool)` and `groupNames` (2A); `shadowPath` (declared in `accounts.go`, same package); the `fsAccess` double's `stats`/`statResult`.
- Produces: `files.etc_shadow.{mode,uid,gid,group,group_readable,group_writable,other_readable,other_writable,acl_present,acl_entries}`, read by Task 7's `muster.file.shadow_permissions`.

- [ ] **Step 1: Write the failing test**

Append to `internal/collect/collectors/permfacts_test.go`:

```go
// Task 5 (2B): /etc/shadow gets the full template including ACL entries —
// a named ACL entry on shadow defeats a 0400 mode just as it does on passwd.
func TestFilesShadowPermissionFacts(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		stats: map[string]statResult{"/etc/shadow": {mode: 0o640, uid: 0, gid: 42, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_shadow.mode"); v.Status != facts.StatusOK || v.Value != 0o640 {
		t.Errorf("mode %+v", v)
	}
	if v := env(t, b, "files.etc_shadow.group"); v.Value != "shadow" {
		t.Errorf("group %+v", v)
	}
	for k, want := range map[string]bool{"group_readable": true, "group_writable": false, "other_readable": false, "other_writable": false, "acl_present": false} {
		if v := env(t, b, "files.etc_shadow."+k); v.Value != want {
			t.Errorf("%s = %+v, want %v", k, v, want)
		}
	}
	if l, ok := env(t, b, "files.etc_shadow.acl_entries").Value.([]any); !ok || len(l) != 0 {
		t.Errorf("acl_entries %+v", env(t, b, "files.etc_shadow.acl_entries"))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Host: `go test ./internal/collect/collectors/ -run TestFilesShadowPermissionFacts -v -count=1` → FAIL (panic: unregistered key `files.etc_shadow.mode`).

- [ ] **Step 3: Implement**

Registry — right after `files.etc_passwd.acl_entries`, the ten entries in the order `mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present, acl_entries`, copying the wording of the `files.etc_passwd.*` entries with `/etc/shadow` substituted (`collector: files`, `since: 1`, `sensitivity: public`; `mode` int "raw 0o7777 bits (e.g. 256 for 0400)", `uid`/`gid` int, `group` string, the four bools, `acl_present` bool, `acl_entries` `list<string>`).

`files.go`: add `shadowPath` to `Declare.Reads` (after `passwdPath`) and, right after the passwd template call:

```go
	writePermFacts(b, a, "files.etc_shadow", shadowPath, groups, gmeta, gerr, true)
```

The `files` collector stays `Needs: none`: `Stat` and the ACL xattr read need no read permission on the file, and a denied one is the leaf's own status. Regenerate the golden (ten keys).

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/collectors/ -run "TestFiles|TestWritePermFacts|TestPasswd" -v -count=1`, `go test ./internal/collect/... -race -shuffle=on -count=1`. Windows: `go test ./... -count=1`; `go run ./cmd/muster controls lint --references docs/reference` still `ok: 8 controls`.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/collectors/files.go internal/collect/collectors/permfacts_test.go internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json
git commit -m "Report the /etc/shadow permission facts"
```

---

### Task 6: Five account controls judged on the user records

**Files:**
- Create: `controls/account/shadow_passwords.yaml`, `controls/account/root_only_uid_zero.yaml`, `controls/account/primary_group_exists.yaml`, `controls/account/unique_uids.yaml`, `controls/account/system_account_shells.yaml` and their fixture directories under `controls/testdata/`
- Modify: `cmd/muster/controls_test.go` (`ok: 8 controls` → `ok: 13 controls`)

**Interfaces:**
- Consumes: `accounts.users` fields `name`, `uid`, `system`, `shell_valid`, `uid_duplicate`, `password_status` (T2); `accounts.shadow_in_use` (T3); `accounts.orphan_gids` fields `name`, `gid` (T3); the `each`/`none` grammar (`subject`, `where`, `require`; sub-clauses take `field`, `op`, `expected` only; `each` needs `subject` and `require`, `none` needs `where`); `references.stig` entries must be in `docs/reference/stig/` and `nist_800_53` ids in the index.
- Produces: the five control ids used by Task 7's e2e maps: `muster.account.shadow_passwords`, `muster.account.root_only_uid_zero`, `muster.account.primary_group_exists`, `muster.account.unique_uids`, `muster.account.system_account_shells`.

- [ ] **Step 1: Write the controls**

`controls/account/shadow_passwords.yaml`:

```yaml
id: muster.account.shadow_passwords
title_en: Passwords are stored only as hashes in /etc/shadow
title_ko: 비밀번호가 /etc/shadow 에만 해시로 저장된다
description_en: Every /etc/passwd entry must defer to /etc/shadow (an "x" password field), /etc/shadow must exist, and no account may have an empty password field. Hash material in the world-readable /etc/passwd, or an empty field, means the password file does not protect the credentials.
description_ko: 모든 /etc/passwd 항목이 비밀번호 필드 "x" 로 /etc/shadow 를 참조해야 하고, /etc/shadow 가 존재해야 하며, 비밀번호 필드가 비어 있는 계정이 없어야 합니다. 누구나 읽을 수 있는 /etc/passwd 에 해시가 있거나 필드가 비어 있으면 비밀번호 파일이 자격 증명을 보호하지 못합니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-04"], "2021": ["U-04"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "7.2.1" }
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "7.2.2" }
  stig:
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-611055 }
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-611065 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-400220 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-300027 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-611140 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-611155 }
  nist_800_53: ["IA-5(1)", "CM-6"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.shadow_in_use, op: eq, expected: true }
  - { fact: accounts.users, op: none, subject: name, where: { field: password_status, op: eq, expected: nopass } }
remediation:
  text_en: Run pwconv so every hash lives in /etc/shadow, then set a password for, or lock, every account whose password field is empty (passwd -l <name>).
  text_ko: pwconv 를 실행해 모든 해시를 /etc/shadow 로 옮기고, 비밀번호 필드가 비어 있는 계정은 비밀번호를 설정하거나 잠급니다 (passwd -l <name>).
  risk: lockout_risk
  idempotent: true
```

`controls/account/root_only_uid_zero.yaml`:

```yaml
id: muster.account.root_only_uid_zero
title_en: root is the only account with uid 0
title_ko: uid 0 인 계정은 root 뿐이다
description_en: Any account whose uid is 0 is root under another name, with every privilege and none of the accountability. Only the account named root may carry uid 0.
description_ko: uid 가 0 인 계정은 이름만 다른 root 이며 모든 권한을 갖지만 책임 추적이 되지 않습니다. root 라는 이름의 계정만 uid 0 을 가질 수 있습니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-05"], "2021": ["U-44"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.4.2.1" }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411100 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.users, op: each, subject: name, where: { field: uid, op: eq, expected: 0 }, require: { field: name, op: eq, expected: root } }
remediation:
  text_en: Give every non-root account that has uid 0 its own uid (usermod -u <new-uid> <name>) or delete it; check its files with find / -user <name> afterwards.
  text_ko: uid 가 0 인 root 외 계정에 고유한 uid 를 부여하거나 (usermod -u <new-uid> <name>) 삭제하고, 이후 find / -user <name> 으로 소유 파일을 확인합니다.
  risk: lockout_risk
  idempotent: true
```

`controls/account/primary_group_exists.yaml`:

```yaml
id: muster.account.primary_group_exists
title_en: Every account's primary group exists
title_ko: 모든 계정의 기본 그룹이 존재한다
description_en: An account whose primary gid names no group in /etc/group creates files owned by a group nobody administers, and a group later created with that gid inherits them. Every primary gid must exist.
description_ko: 기본 gid 가 /etc/group 에 없는 계정은 아무도 관리하지 않는 그룹 소유의 파일을 만들며, 나중에 그 gid 로 생성되는 그룹이 이를 물려받습니다. 모든 기본 gid 가 존재해야 합니다.
category: account
importance: 하
automation: auto
references:
  kisa: { "2026": ["U-09"], "2021": ["U-51"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "7.2.3" }
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.orphan_gids, op: none, subject: name, where: { field: gid, op: gte, expected: 0 } }
remediation:
  text_en: Create the missing group (groupadd -g <gid> <name>) or move the account to an existing one (usermod -g <group> <name>).
  text_ko: 누락된 그룹을 만들거나 (groupadd -g <gid> <name>) 계정을 기존 그룹으로 옮깁니다 (usermod -g <group> <name>).
  risk: none
  idempotent: true
```

(The `none … gte 0` clause reads "the list is empty": every element of `orphan_gids` has a non-negative gid, so any element is a hit. `present` is not used in a sub-clause because lint's `each`/`none` rules were written for value operators.)

`controls/account/unique_uids.yaml`:

```yaml
id: muster.account.unique_uids
title_en: No two accounts share a uid
title_ko: 두 계정이 같은 uid 를 갖지 않는다
description_en: Two accounts with one uid are one identity to the kernel: file ownership, process ownership and audit records cannot tell them apart. Every uid must belong to exactly one account.
description_ko: uid 가 같은 두 계정은 커널에게 하나의 신원이어서 파일·프로세스 소유와 감사 기록으로 구분할 수 없습니다. 모든 uid 는 정확히 한 계정의 것이어야 합니다.
category: account
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-10"], "2021": ["U-52"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "7.2.5" }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411030 }
  nist_800_53: ["AU-3(1)", "IA-2", "IA-8"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.users, op: none, subject: name, where: { field: uid_duplicate, op: eq, expected: true } }
remediation:
  text_en: Assign a new uid to all but one of the accounts sharing it (usermod -u <new-uid> <name>) and re-own their files (find / -user <old-uid> -exec chown <name> {} +).
  text_ko: uid 를 공유하는 계정 중 하나만 남기고 새 uid 를 부여한 뒤 (usermod -u <new-uid> <name>) 파일 소유를 다시 맞춥니다 (find / -user <old-uid> -exec chown <name> {} +).
  risk: none
  idempotent: true
```

`controls/account/system_account_shells.yaml`:

```yaml
id: muster.account.system_account_shells
title_en: System accounts have no login shell
title_ko: 시스템 계정에 로그인 셸이 없다
description_en: An account below UID_MIN exists to own a service, not to log in. Its shell must not be one of the login shells in /etc/shells; nologin, false and the single-purpose programs such as sync qualify.
description_ko: UID_MIN 미만의 계정은 서비스를 소유하기 위한 것이지 로그인용이 아닙니다. 그 셸은 /etc/shells 에 있는 로그인 셸이면 안 되며, nologin, false 와 sync 같은 단일 목적 프로그램은 허용됩니다.
category: account
importance: 하
automation: auto
references:
  kisa: { "2026": ["U-11"], "2021": ["U-53"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.4.2.7" }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-411035 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.users, op: each, subject: name, where: { field: system, op: eq, expected: true }, require: { field: shell_valid, op: eq, expected: false } }
remediation:
  text_en: Set the shell of each listed system account to nologin (usermod -s /usr/sbin/nologin <name> on Debian and Ubuntu, /sbin/nologin on Rocky and AlmaLinux).
  text_ko: 나열된 시스템 계정의 셸을 nologin 으로 바꿉니다 (Debian·Ubuntu 는 usermod -s /usr/sbin/nologin <name>, Rocky·AlmaLinux 는 /sbin/nologin).
  risk: none
  idempotent: true
```

- [ ] **Step 2: Write the fixtures**

Every fixture: `{"synthetic": true, "schema_version": 1, "run": {}, "facts": {...}}` with only the leaves the control reads; user records carry only the fields the clauses touch. One line per file is fine.

`controls/testdata/muster.account.shadow_passwords/`:
- `pass-shadowed.json` — `accounts.shadow_in_use` ok `true`; `accounts.users` ok `[{"name":"root","password_status":"hashed"},{"name":"alice","password_status":"hashed"},{"name":"svc","password_status":"locked"}]`.
- `fail-hash-in-passwd.json` — `shadow_in_use` `{"status":"ok","value":false,"reason":"account dave keeps its password field in /etc/passwd"}`; the same users.
- `fail-empty-password.json` — `shadow_in_use` ok `true`; users `[{"name":"root","password_status":"hashed"},{"name":"bob","password_status":"nopass"}]`.
- `error-shadow-denied.json` — `shadow_in_use` `{"status":"denied","reason":"/etc/shadow: needs root"}`; users `[{"name":"root"}]` (no shadow fields, as the collector writes without shadow).
- `warn-remote-nss.json` — `pass-shadowed.json`'s facts plus `accounts.nss.remote` ok `true` (`_expect`: none; the prefix expects `WARN`).

`controls/testdata/muster.account.root_only_uid_zero/`:
- `pass-root-only.json` — users `[{"name":"root","uid":0},{"name":"alice","uid":1000}]`.
- `fail-uid0-alias.json` — users `[{"name":"root","uid":0},{"name":"toor","uid":0},{"name":"alice","uid":1000}]`.
- `fail-absent.json` — `accounts.users` `{"status":"absent","reason":"not present"}` (a host with no readable passwd cannot pass).

`controls/testdata/muster.account.primary_group_exists/`:
- `pass-all-exist.json` — `accounts.orphan_gids` ok `[]`.
- `fail-orphan.json` — ok `[{"name":"carol","gid":4242}]`.
- `error-group-denied.json` — `{"status":"denied","reason":"/etc/group: needs root"}`.

`controls/testdata/muster.account.unique_uids/`:
- `pass-unique.json` — users `[{"name":"root","uid_duplicate":false},{"name":"alice","uid_duplicate":false}]`.
- `fail-duplicate.json` — users `[{"name":"root","uid_duplicate":false},{"name":"alice","uid_duplicate":true},{"name":"bob","uid_duplicate":true}]`.

`controls/testdata/muster.account.system_account_shells/`:
- `pass-nologin.json` — users `[{"name":"root","system":false,"shell_valid":true},{"name":"daemon","system":true,"shell_valid":false},{"name":"sync","system":true,"shell_valid":false},{"name":"alice","system":false,"shell_valid":true}]`.
- `fail-interactive-system-account.json` — the same with `{"name":"ftp","system":true,"shell_valid":true}` added.

`cmd/muster/controls_test.go`: `"ok: 8 controls"` → `"ok: 13 controls"`.

- [ ] **Step 3: Lint and test**

Run: `go run ./cmd/muster controls lint --references docs/reference` → `ok: 13 controls`. If lint rejects the `nist_800_53` or `stig` shape, read `internal/controls/references.go` and `lint.go` for the accepted form (Task 10 of plan 2A) and adjust the YAML, never lint. Then `go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1`, `go test ./cmd/muster/ -count=1`, and for the two named cases run the CLI directly and quote the reason: `go run ./cmd/muster check --facts controls/testdata/muster.account.root_only_uid_zero/fail-uid0-alias.json --format json` (the observation subject is `user:toor`) and `…/muster.account.shadow_passwords/warn-remote-nss.json` (status `WARN`, reason names the remote NSS source).

- [ ] **Step 4: Commit**

```bash
git add controls/account cmd/muster/controls_test.go controls/testdata
git commit -m "Add the shadow, uid-0, primary-group, unique-uid and system-shell account controls"
```

---

### Task 7: The remaining five controls, the end-to-end snapshots and the coverage table

**Files:**
- Create: `controls/account/unnecessary_accounts.yaml`, `controls/account/admin_group_minimal.yaml`, `controls/account/password_hash_algorithm.yaml`, `controls/file/shadow_permissions.yaml`, `controls/service/ftp_account_shell.yaml` and their fixture directories
- Modify: `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `cmd/muster/e2e_test.go`, `cmd/muster/controls_test.go` (`13` → `18`), `docs/reference/coverage.md` (regenerated), `README.md`, `README.ko.md`

**Interfaces:**
- Consumes: `accounts.users` fields `name`, `hash_algo`, `shell_valid` (T2); `accounts.admin_group_members` fields `name`, `group` (T3); `accounts.shadow_in_use` (T3); `accounts.login_defs.encrypt_method` (T1); `files.etc_shadow.{uid,mode,acl_entries}` (T5); `list<int>`/`list<string>` params with `${name}` substitution (2A).
- Produces: the ten-control set (18 in total), e2e coverage of all ten, the regenerated coverage table.

- [ ] **Step 1: Write the controls**

`controls/account/unnecessary_accounts.yaml` (partial: whether an account is unnecessary on this host is a human call; the guide's example names are the default):

```yaml
id: muster.account.unnecessary_accounts
title_en: Accounts that are not needed have been removed
title_ko: 불필요한 계정이 제거되어 있다
description_en: Accounts created by packages that are not in use (printing, uucp) widen the attack surface for nothing. The parameter names the accounts the guide gives as examples; a stock Ubuntu or Rocky host keeps lp and uucp, so this reports WARN there until the operator removes them or adjusts the list.
description_ko: 사용하지 않는 패키지가 만든 계정(인쇄, uucp)은 공격 표면만 넓힙니다. 파라미터는 가이드가 예로 드는 계정 이름이며, 기본 설치된 Ubuntu 와 Rocky 는 lp 와 uucp 를 갖고 있으므로 운영자가 제거하거나 목록을 조정하기 전까지 WARN 으로 보고됩니다.
category: account
importance: 하
automation: partial
references:
  kisa: { "2026": ["U-07"], "2021": ["U-49"] }
requires_facts: ">=1"
absent_means: fail
params:
  unnecessary: { type: list<string>, default: ["lp", "uucp", "nuucp"], description: Account names that should not exist on this host }
checks:
  - { fact: accounts.users, op: none, subject: name, where: { field: name, op: in, expected: "${unnecessary}" } }
remediation:
  text_en: Remove each listed account with userdel <name> after confirming nothing on the host runs as it (ps -u <name>; find / -user <name>).
  text_ko: 호스트에서 해당 계정으로 실행되는 것이 없음을 확인한 뒤 (ps -u <name>; find / -user <name>) userdel <name> 으로 제거합니다.
  risk: none
  idempotent: true
```

`controls/account/admin_group_minimal.yaml` (partial):

```yaml
id: muster.account.admin_group_minimal
title_en: The root group holds no account other than root
title_ko: root 그룹에 root 외의 계정이 없다
description_en: Membership of the root group grants group access to everything root owns. No account other than root may have it as primary or secondary group; members of wheel, sudo and admin are attached as evidence for the operator's review.
description_ko: root 그룹의 구성원은 root 소유 파일 전부에 그룹 권한을 갖습니다. root 외의 계정이 이를 기본 또는 보조 그룹으로 가져서는 안 되며, wheel·sudo·admin 의 구성원은 운영자 검토를 위한 증거로 첨부됩니다.
category: account
importance: 중
automation: partial
references:
  kisa: { "2026": ["U-08"], "2021": ["U-50"] }
  stig:
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-432015 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-600130 }
  nist_800_53: ["SC-3"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.admin_group_members, op: none, subject: name, where: { field: group, op: eq, expected: root } }
remediation:
  text_en: Remove the account from the root group (gpasswd -d <name> root) or give it another primary group (usermod -g <group> <name>).
  text_ko: 계정을 root 그룹에서 제거하거나 (gpasswd -d <name> root) 다른 기본 그룹을 지정합니다 (usermod -g <group> <name>).
  risk: none
  idempotent: true
```

`controls/account/password_hash_algorithm.yaml`:

```yaml
id: muster.account.password_hash_algorithm
title_en: Passwords are hashed with a strong algorithm
title_ko: 비밀번호가 안전한 알고리즘으로 해시된다
description_en: ENCRYPT_METHOD in login.defs must name an allowed algorithm and every stored hash - including those of locked accounts - must use one. MD5 and the legacy DES scheme are not allowed; SHA-256, SHA-512 and yescrypt are. Passwords must live in /etc/shadow for the hashes to be judged at all.
description_ko: login.defs 의 ENCRYPT_METHOD 가 허용 알고리즘이어야 하고, 잠긴 계정의 것을 포함한 모든 저장 해시가 허용 알고리즘을 써야 합니다. MD5 와 구형 DES 방식은 허용되지 않고 SHA-256, SHA-512, yescrypt 는 허용됩니다. 해시를 판단하려면 비밀번호가 /etc/shadow 에 있어야 합니다.
category: account
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-13"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.4.1.4" }
  stig:
    - { benchmark: ubuntu2204, version: V2R9, id: UBTU-22-611070 }
    - { benchmark: ubuntu2404, version: V1R6, id: UBTU-24-400400 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-671015 }
  nist_800_53: ["IA-7", "IA-5(1)"]
requires_facts: ">=1"
absent_means: fail
params:
  allowed_methods: { type: list<string>, default: ["SHA256", "SHA512", "YESCRYPT"], description: ENCRYPT_METHOD values that count as strong }
  allowed_hashes: { type: list<string>, default: ["$5$", "$6$", "$y$", "$gy$"], description: crypt hash ids that count as strong }
checks:
  - { fact: accounts.login_defs.encrypt_method, op: in, expected: "${allowed_methods}" }
  - { fact: accounts.shadow_in_use, op: eq, expected: true }
  - { fact: accounts.users, op: each, subject: name, where: { field: hash_algo, op: ne, expected: "" }, require: { field: hash_algo, op: in, expected: "${allowed_hashes}" } }
remediation:
  text_en: Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs, make the PAM password stack use the same algorithm, and have every listed account change its password so the hash is regenerated.
  text_ko: /etc/login.defs 에 ENCRYPT_METHOD SHA512 (또는 YESCRYPT) 를 설정하고 PAM password 스택이 같은 알고리즘을 쓰게 한 뒤, 나열된 계정의 비밀번호를 변경해 해시를 다시 생성합니다.
  risk: none
  idempotent: true
```

`controls/file/shadow_permissions.yaml`:

```yaml
id: muster.file.shadow_permissions
title_en: /etc/shadow is owned by root and readable by root only
title_ko: /etc/shadow 가 root 소유이고 root 만 읽을 수 있다
description_en: The guide's criterion is owner root and mode 0400 or stricter, and no named POSIX ACL entry may widen it. Ubuntu ships /etc/shadow as root:shadow 0640 so that setgid helpers can read it; that host fails this control until the mode is tightened or allowed_modes is widened deliberately (0640 is 416).
description_ko: 가이드 기준은 소유자 root, 모드 0400 이하이며 특정 사용자·그룹에 대한 POSIX ACL 항목이 이를 넓혀서는 안 됩니다. Ubuntu 는 setgid 도우미가 읽을 수 있도록 /etc/shadow 를 root:shadow 0640 으로 배포하므로, 모드를 조이거나 allowed_modes 를 의도적으로 넓히기 (0640 은 416) 전까지 그 호스트는 실패합니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-18"], "2021": ["U-08"] }
  cis:
    - { benchmark: ubuntu-22.04, version: "2.0.0", rec: "7.1.5" }
  stig:
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232150 }
    - { benchmark: rhel9, version: V2R9, id: RHEL-09-232270 }
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
params:
  allowed_modes: { type: list<int>, default: [0, 256], description: Modes that count as 0400 or stricter (0400 and every subset of its bits) }
checks:
  - { fact: files.etc_shadow.uid, op: eq, expected: 0 }
  - { fact: files.etc_shadow.mode, op: in, expected: "${allowed_modes}" }
  - { fact: files.etc_shadow.acl_entries, op: none, where: { op: matches, expected: "^(user|group):[^:]+:" } }
remediation:
  text_en: chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow
  text_ko: chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow
  risk: none
  idempotent: true
  script: chown root /etc/shadow && chmod 400 /etc/shadow && setfacl -b /etc/shadow
```

`controls/service/ftp_account_shell.yaml`:

```yaml
id: muster.service.ftp_account_shell
title_en: The ftp account cannot log in interactively
title_ko: ftp 계정으로 대화형 로그인을 할 수 없다
description_en: The account an FTP daemon runs anonymous sessions as exists to own the FTP tree, not to log in. When an account named ftp exists its shell must not be one of the login shells in /etc/shells; a host without such an account passes.
description_ko: FTP 데몬이 익명 세션에 쓰는 계정은 FTP 트리를 소유하기 위한 것이지 로그인용이 아닙니다. ftp 라는 계정이 있으면 그 셸이 /etc/shells 의 로그인 셸이면 안 되며, 그런 계정이 없는 호스트는 통과합니다.
category: service
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-55"], "2021": ["U-62"] }
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: accounts.users, op: each, subject: name, where: { field: name, op: eq, expected: ftp }, require: { field: shell_valid, op: eq, expected: false } }
remediation:
  text_en: usermod -s /usr/sbin/nologin ftp (Debian and Ubuntu) or usermod -s /sbin/nologin ftp (Rocky and AlmaLinux).
  text_ko: usermod -s /usr/sbin/nologin ftp (Debian·Ubuntu) 또는 usermod -s /sbin/nologin ftp (Rocky·AlmaLinux).
  risk: none
  idempotent: true
```

- [ ] **Step 2: Write the fixtures**

`controls/testdata/muster.account.unnecessary_accounts/`: `pass-none-present.json` (users `[{"name":"root"},{"name":"alice"}]`), `fail-lp-present.json` (users `[{"name":"root"},{"name":"lp"},{"name":"alice"}]` → `WARN`, partial).

`controls/testdata/muster.account.admin_group_minimal/`: `pass-root-group-empty.json` (`admin_group_members` ok `[{"name":"alice","group":"sudo","via":"secondary"}]`), `pass-no-admins.json` (ok `[]`), `fail-extra-root-member.json` (ok `[{"name":"toor","group":"root","via":"primary"},{"name":"alice","group":"sudo","via":"secondary"}]` → `WARN`).

`controls/testdata/muster.account.password_hash_algorithm/`: `pass-sha512-and-yescrypt.json` (`encrypt_method` ok `"SHA512"`, `shadow_in_use` ok `true`, users `[{"name":"root","hash_algo":"$6$"},{"name":"svc","hash_algo":""},{"name":"alice","hash_algo":"$y$"}]`), `fail-md5-hash-on-locked-account.json` (same but `{"name":"toor","hash_algo":"$1$"}` added), `fail-legacy-hash.json` (`{"name":"carol","hash_algo":"legacy"}` added), `fail-encrypt-method-md5.json` (`encrypt_method` `"MD5"`), `fail-hash-in-passwd.json` (`shadow_in_use` `false`), `fail-encrypt-method-unset.json` (`encrypt_method` `{"status":"absent","reason":"ENCRYPT_METHOD is not set in /etc/login.defs"}`).

`controls/testdata/muster.file.shadow_permissions/`: `pass-0400.json` (uid 0, mode 256, `acl_entries` `[]`), `pass-0000.json` (mode 0), `fail-0640.json` (mode 416), `fail-owner.json` (uid 42, mode 256), `fail-named-acl.json` (mode 256, `acl_entries` `["user::r--","user:1000:r--","group::---","mask::r--","other::---"]`), `fail-absent.json` (all three absent), `error-acl-unreadable.json` (uid 0, mode 256, `acl_entries` `{"status":"error","reason":"decode ACL: bad version"}`).

`controls/testdata/muster.service.ftp_account_shell/`: `pass-no-ftp-account.json` (users `[{"name":"root"},{"name":"alice"}]`), `pass-ftp-nologin.json` (users `[{"name":"ftp","shell_valid":false}]`), `fail-ftp-interactive.json` (users `[{"name":"ftp","shell_valid":true}]`).

- [ ] **Step 3: End-to-end snapshots, counts and docs**

`cmd/muster/testdata/full-pass.json` and `full-fail.json` (read them first — `facts.accounts.login_defs` and `facts.files` already exist; merge, do not replace): add to `facts.accounts` — `users` ok `[{"name":"root","uid":0,"gid":0,"home":"/root","shell":"/bin/bash","system":false,"shadowed":true,"uid_duplicate":false,"name_duplicate":false,"shell_valid":true,"password_status":"hashed","locked":false,"hash_algo":"$6$"},{"name":"alice","uid":1000,"gid":1000,"home":"/home/alice","shell":"/bin/bash","system":false,"shadowed":true,"uid_duplicate":false,"name_duplicate":false,"shell_valid":true,"password_status":"hashed","locked":false,"hash_algo":"$y$"}]`, `shadow_in_use` ok `true`, `orphan_gids` ok `[]`, `admin_group_members` ok `[{"name":"alice","group":"sudo","via":"secondary"}]`, and under `login_defs` `encrypt_method` ok `"SHA512"`; add to `facts.files` — `etc_shadow` with `uid` ok `0`, `mode` ok `0`, `acl_entries` ok `[]`. Every envelope carries `"source": {"kind": "file", "path": "/etc/passwd"}` (or the matching file) as the existing entries do.

`cmd/muster/e2e_test.go`: both expected-status maps gain the ten ids as `PASS`; the only `FAIL` stays `muster.account.root_remote_login` in the fail snapshot; update the "eight controls"/"seven unchanged" comments to eighteen/seventeen.

`cmd/muster/controls_test.go`: `"ok: 13 controls"` → `"ok: 18 controls"`.

`docs/reference/coverage.md`: `go run ./tools/coverage`, then `go run ./tools/coverage -check` (exit 0); ten more items show a control.

`README.md` / `README.ko.md`: the sentence that counts eight controls now counts eighteen and names the account family (U-04, U-05, U-07, U-08, U-09, U-10, U-11, U-13, U-18, U-55) — both files in the same commit, identifiers English on both sides.

- [ ] **Step 4: Lint, test and the real host**

Windows: `go run ./cmd/muster controls lint --references docs/reference` → `ok: 18 controls`; `go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1`; `go test ./cmd/muster/ -count=1`; `go run ./tools/coverage -check`; `go test ./... -count=1`; gitleaks tree scan clean.

Host (root, stock Ubuntu 22.04): sync, build into a 0700 temp dir, `collect --require-root --require-complete` (exit 0), `check --format json`; expected statuses — `shadow_passwords PASS`, `root_only_uid_zero PASS`, `unnecessary_accounts WARN` (lp, uucp exist), `admin_group_minimal PASS`, `primary_group_exists PASS`, `unique_uids PASS`, `system_account_shells PASS`, `password_hash_algorithm PASS`, `shadow_permissions FAIL` (root:shadow 0640), `ftp_account_shell PASS`; the exit code stays 1. Quote only the status lines and the `accounts.nss.remote` leaf; copy nothing else off the host.

- [ ] **Step 5: Commit**

```bash
git add controls/account controls/file controls/service controls/testdata cmd/muster/testdata cmd/muster/e2e_test.go cmd/muster/controls_test.go docs/reference/coverage.md README.md README.ko.md
git commit -m "Add the remaining account controls and enrol all ten in the end-to-end snapshots"
```

---

## Self-review

**Spec coverage (plan 2B items and the stage-2 mechanisms they need):**

| Requirement | Task |
|---|---|
| U-04 password file protection (shadow in use, no empty password) | T3 facts, T6 control |
| U-05 root is the only uid 0 | T2 (`uid` field), T6 |
| U-07 unnecessary accounts (partial) | T2, T7 |
| U-08 administrative group membership (partial) | T3 (`admin_group_members`), T7 |
| U-09 primary gid exists | T3 (`orphan_gids`), T6 |
| U-10 unique uids | T2 (`uid_duplicate`), T6 |
| U-11 system account shells | T2 (`system`, `shell_valid` from `/etc/shells`), T6 |
| U-13 hash algorithm (login.defs and every stored hash, locked accounts included) | T1 (`encrypt_method`), T2 (`hashAlgo` fix), T7 |
| U-18 /etc/shadow owner, mode, ACL | T5, T7 |
| U-55 ftp account shell | T2, T7 |
| §7.3 remote NSS source → account controls WARN | T4 |
| §5.6 no hash material in the snapshot | T2 tests assert it on every field |
| §5.7 record fields additive, `schema_version` unchanged | T2 (description only) |
| login.defs strings for 2C (ENCRYPT_METHOD, rounds) and 2E (UID_MIN, UMASK, HOME_MODE, ENV_*PATH) | T1 |
| §6.6 guide-literal defaults with the stock-host deviation stated | T7 (U-07 `lp`/`uucp`, U-18 Ubuntu 0640) |

Not built, on purpose: `accounts.last_login`, `accounts.duplicate_uids`, `accounts.nis_domain` (see the key inventory); the lint cross-check of `references.kisa` against the inventory (2M); the owner-name leaf for U-22 (2F, R121).

**Placeholder scan:** no TBD/TODO; every code step carries its code; every fixture lists its facts; `present` was avoided in sub-clauses (T6 note).

**Type consistency:** `writePermFacts` is the 8-parameter 2A form (T5); `parsePasswd` returns `(rows []passwdRow, failures int)` and T3 consumes both; `deriveUsers(rows, shadow, haveShadow, uidMin, shells)` is called with `defs.intOr("UID_MIN", 1000)` (T1) in T2 and unchanged in T3; `loginShells` returns `(map[string]bool, facts.Envelope)`; `nssSources` returns `(sources, line, found)` and `writeNSS` uses all three; the check-side helper `nopassControl` uses `Subject: "name"` as the YAML controls do; `groupPath` comes from `permfacts.go` (2A) and `shadowPath` from `accounts.go`, both in package `collectors`.
