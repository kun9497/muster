# Stage 2A — Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay the shared ground every later stage-2 plan builds on — the vocabulary additions, the corrected status derivation, a file-type-aware read primitive, the permission-fact template with POSIX ACL decoding, the environment fact keys, the coverage table, the STIG/CCI reference index and its lint — and prove it end to end with four permission controls (U-16 refined, U-19, U-22, U-29).

**Architecture:** Nothing here changes the shape of a snapshot or a control beyond additive keys and fields. The check side gains one operator and two subject kinds and moves `automation: manual` below `applies_when` in the derivation table. The collect side gains file-type information in `ReadMeta`, a seventh `Access` method (`Getxattr`), a shared permission-fact writer that every fixed-path file uses, and an ACL decoder. Two committed tools (`tools/coverage`, `tools/refindex`) generate documents under `docs/reference/` from the control set and from DISA's public STIG/CCI files; lint reads the generated index so a control can only cite an identifier that exists.

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3` and `golang.org/x/sys` (the only direct dependencies; `encoding/xml` and `archive/zip` are standard library), Linux lab host for `internal/collect` tests, GitHub Actions for the container matrix.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — §3 (global references, as amended 2026-09-03), §5.2–5.5 (envelopes, settings, sections, registry), §5.7 (versioning: record fields are additive), §6.3 (operators incl. `not_matches`), §6.4 (subject kinds incl. `facility`, `zone`), §6.5 (derivation table, rows 2–4 reordered), §6.6 (defaults are the guide's criterion), §8, §10.2 (stage 2 as plans 2A–2M), §11. The decomposition analysis that produced this plan lives outside the repository; its conventions are restated in Task 4.

## Global Constraints

- Module `github.com/kun9497/muster`, `go 1.25`; direct dependencies stay exactly `gopkg.in/yaml.v3` and `golang.org/x/sys` (D28). Tools under `tools/` are ordinary packages in the same module; they must not import `internal/collect` (Linux-only) so `go build ./...` stays green on every GOOS.
- `internal/check` keeps its import contract (no `os/exec`, `net`, `os` file APIs; `internal/check/imports_test.go`).
- Fact statuses are exactly `ok | absent | denied | unsupported | timeout | error` (+ reader-side `missing`); result statuses exactly `PASS | FAIL | WARN | MANUAL | NOT_APPLICABLE | ERROR | WAIVED`; reason codes exactly `permission_denied | timeout | truncated | unsupported_env | parse_error | missing_fact | schema_mismatch | walk_incomplete | internal_error`.
- Every leaf under `facts` is an envelope of its own; a `record` fact is evidence for `present`/`absent` only, never field-addressed by a clause (spec §5.2, §6.3). Adding keys or record fields keeps `schema_version: 1` (spec §5.7).
- Every collector declares every path it reads and every command it runs; `Guard` enforces it and `--list-actions` prints it (spec §8, §9). New reads in this plan: `/etc/group`, `/etc/hosts`, `/etc/services`, `/etc/hosts.lpd`; no new commands.
- Every file read goes through the read primitive (no symlink followed, regular files only for content, size cap with `Truncated`); xattr values are read through the same no-follow fd.
- Controls: muster-native ids, `references.kisa` per edition (`"2026"` primary, `"2021"` from `docs/reference/kisa/kisa_mapping.json`), `references.cis` numbers only, `references.stig` and `references.nist_800_53` only with identifiers present in `docs/reference/stig/*.json`; a default parameter is the guide's criterion (spec §6.6); `requires_facts` mandatory; `absent_means` explicit where a fact can be absent; every control has ≥1 `pass-*.json` and ≥1 `fail-*.json` fixture, every fixture synthetic with `"synthetic": true` (spec §11, D02).
- Determinism: JSON byte-identical for identical input; no `map` iteration reaches output; generated documents are byte-identical across runs (sorted keys, no timestamps other than the source's own release date).
- No text from the KISA guide, a CIS Benchmark or a STIG check procedure is stored; STIG rule ids, group ids, severities and titles and CCI/NIST identifiers are reproduced (DISA publications are US Government works), and `ATTRIBUTION.md` says so.
- Commit after every task with the repository's trailer lines; never push; run the Linux tests on the lab host through the controller's read-only scripts; nothing captured from that host is committed.
- Windows is the development host: `gofmt -l .`, `go vet ./...`, `go build ./...`, `GOOS=linux GOARCH=amd64 go vet ./...`, cross-compiled Linux test binaries and cross `staticcheck` must all pass there.

---

## File structure

| Path | Responsibility |
|---|---|
| `internal/check/value.go` | `not_matches` on strings |
| `internal/controls/lint.go` | `not_matches` in `scalarOps` and `lintExpected`; STIG/NIST reference validation against the index |
| `internal/controls/schema.go` | `References.STIG []STIGRef` |
| `internal/controls/references.go` | loader for `docs/reference/stig/*.json` used by lint (`ReferenceIndex`) |
| `internal/facts/registry.go` | subject kinds `facility`, `zone` |
| `internal/facts/registry.yaml` | new keys: `env.*`, `files.etc_passwd.{group,group_readable,group_writable,other_readable,other_writable,acl_entries}`, `files.etc_hosts.*`, `files.etc_services.*`, `files.etc_hosts_lpd.*` |
| `internal/check/eval.go` | derivation rows 2–4 reordered (applies_when before manual) |
| `internal/collect/types.go`, `readfile.go` | `ReadMeta.Kind`, `ReadMeta.Rdev` |
| `internal/collect/registry.go` | `Access.Getxattr`, `hostAccess.Getxattr` via `Fgetxattr`, guard |
| `internal/collect/collectors/acl.go` | POSIX ACL xattr decoder |
| `internal/collect/collectors/permfacts.go` | the permission-fact template (`writePermFacts`), `/etc/group` name lookup |
| `internal/collect/collectors/files.go` | uses the template for passwd, hosts, services, hosts.lpd |
| `internal/collect/collectors/os.go` | also writes `env.container`, `env.has_systemd` |
| `controls/file/{passwd_permissions,hosts_permissions,services_permissions,hosts_lpd_permissions}.yaml` + `controls/testdata/…` | the four controls and fixtures |
| `tools/coverage/main.go` | generates and checks `docs/reference/coverage.md` |
| `tools/refindex/{main.go,xccdf.go,cci.go,sources.json}` | generates `docs/reference/stig/*.json` from pinned DISA files |
| `docs/reference/stig/{ubuntu2204-v2r9,ubuntu2404-v1r6,rhel9-v2r9}.json` | generated STIG index (committed) |
| `docs/reference/coverage.md` | generated coverage table (committed) |
| `ATTRIBUTION.md`, `CLAUDE.md`, `.gitignore`, `Makefile`, `.github/workflows/ci.yml` | attribution for DISA material, conventions, cache ignore, targets, coverage check and Debian canary |

---

### Task 1: `not_matches` and the `facility`/`zone` subject kinds

**Files:**
- Modify: `internal/check/value.go` (string branch of `compare`), `internal/check/value_test.go`
- Modify: `internal/controls/lint.go` (`scalarOps`, `lintExpected`), `internal/controls/lint_test.go`
- Modify: `internal/facts/registry.go` (`validSubjectKind`), `internal/facts/registry_test.go`
- Modify: `internal/check/eval.go` (`describe` needs no change: it prints `op` verbatim)

**Interfaces:**
- Consumes: `compare(op string, actual, expected any, typ string) (bool, error)` in `internal/check/value.go`; `scalarOps` set and `lintExpected(cl Clause, add func(string, string, ...any), where string)` in `internal/controls/lint.go`; `validSubjectKind` in `internal/facts/registry.go`.
- Produces: `not_matches` accepted on `string` facts (and on `setting<string>` sides, which go through the same `compare`), rejected on lists with the error `op "not_matches" is not valid on a list`; registry entries may carry `subject_kind: facility` or `subject_kind: zone`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/check/value_test.go`:

```go
func TestNotMatchesIsTheNegationOfMatchesOnStrings(t *testing.T) {
	cases := []struct {
		actual, pattern string
		want            bool
	}{
		{"vsftpd 3.0.5", `(?i)vsftpd`, false},
		{"Welcome", `(?i)vsftpd`, true},
		{"", `.`, true},
	}
	for _, c := range cases {
		got, err := compare("not_matches", c.actual, c.pattern, "string")
		if err != nil {
			t.Fatalf("%q not_matches %q: %v", c.actual, c.pattern, err)
		}
		if got != c.want {
			t.Errorf("%q not_matches %q = %v, want %v", c.actual, c.pattern, got, c.want)
		}
	}
	if _, err := compare("not_matches", "x", "(", "string"); err == nil {
		t.Error("an invalid pattern must be an error, not false")
	}
	if _, err := compare("not_matches", []any{"a"}, "a", "list<string>"); err == nil {
		t.Error("not_matches is scalar-only; a list must be an error")
	}
	if _, err := compare("not_matches", 3, "3", "int"); err == nil {
		t.Error("not_matches on an int must be an error")
	}
}
```

Append to `internal/controls/lint_test.go` (the file has a helper that lints one YAML control string; use the same one the existing `matches` test uses — its name is visible at the top of the file as the function every `TestLint…` calls; call it here as that helper):

```go
func TestLintAcceptsNotMatchesWithAPatternAndRejectsItOnLists(t *testing.T) {
	ok := `
id: muster.file.banner_test
title_en: t
title_ko: t
description_en: d
description_ko: d
category: file
importance: 하
automation: auto
references: { kisa: { "2026": ["U-53"] } }
requires_facts: ">=1"
absent_means: pass
checks:
  - { fact: sshd.collect_method, op: not_matches, expected: "(?i)parse" }
`
	if probs := lintOne(t, ok); len(probs) != 0 {
		t.Fatalf("not_matches with a pattern must lint clean: %v", probs)
	}
	bad := strings.Replace(ok, `expected: "(?i)parse"`, `expected: 3`, 1)
	if probs := lintOne(t, bad); !hasRule(probs, "clause_grammar") {
		t.Errorf("not_matches without a string pattern must be a clause_grammar problem: %v", probs)
	}
	onList := strings.Replace(ok, "fact: sshd.collect_method", "fact: files.etc_securetty_lines", 1)
	if probs := lintOne(t, onList); !hasRule(probs, "clause_grammar") {
		t.Errorf("not_matches on a list fact must be a clause_grammar problem: %v", probs)
	}
}
```

If `lintOne`/`hasRule` do not exist under those names, use the file's existing single-control lint helper and problem-rule predicate; do not add a second copy of either.

Append to `internal/facts/registry_test.go`:

```go
func TestRegistryAcceptsFacilityAndZoneSubjectKinds(t *testing.T) {
	for _, kind := range []string{"facility", "zone"} {
		if !validSubjectKind[kind] {
			t.Errorf("subject kind %q must be valid (spec §6.4)", kind)
		}
	}
	if validSubjectKind["banana"] {
		t.Error("unknown subject kinds must stay invalid")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/check/ -run TestNotMatches -v && go test ./internal/controls/ -run TestLintAcceptsNotMatches -v && go test ./internal/facts/ -run TestRegistryAcceptsFacility -v`
Expected: FAIL — `op "not_matches" is not valid on string`, a `clause_grammar` problem on the clean control ("unknown op"), and the kinds reported invalid.

- [ ] **Step 3: Implement**

`internal/check/value.go`, string branch of `compare` — extend the `case "eq", "ne", "contains", "matches":` group to include `"not_matches"` and add its arm:

```go
		case "eq", "ne", "contains", "matches", "not_matches":
			e, ok := expected.(string)
			if !ok {
				return false, fmt.Errorf("expected %v is not a string", expected)
			}
			switch op {
			case "eq":
				return a == e, nil
			case "ne":
				return a != e, nil
			case "contains":
				return strings.Contains(a, e), nil
			case "matches", "not_matches":
				re, err := regexp.Compile(e)
				if err != nil {
					return false, err
				}
				m := re.MatchString(a)
				if op == "not_matches" {
					return !m, nil
				}
				return m, nil
			}
```

`compareList` (lists) must not accept it: its `switch op` has no `not_matches` case, so it falls to the existing `default` error; make that error message read `op %q is not valid on a list` if it does not already. Add the doc line above `compare`: `// not_matches is scalar-only (spec §6.3): on a list, "no element matches" is what none/where express.`

`internal/controls/lint.go`:

```go
	scalarOps        = set("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "matches", "not_matches", "contains", "present", "absent")
```

and in `lintExpected`:

```go
	case "matches", "not_matches":
		s, ok := cl.Expected.(string)
		if !ok {
			add("clause_grammar", "%s: %s needs a string pattern", where, cl.Op)
			return
		}
		if _, err := regexp.Compile(s); err != nil {
			add("clause_grammar", "%s: pattern %q does not compile: %v", where, s, err)
		}
```

Then, where lint checks an op against the fact's registry type (the branch that already rejects `lt` on a string — search for `"numeric"` or `lt` in `lintClause`), add: a `not_matches` clause whose fact type starts with `list<` is a `clause_grammar` problem `"%s: not_matches is scalar-only; use none with a where clause"`.

`internal/facts/registry.go`:

```go
var validSubjectKind = map[string]bool{"file": true, "dir": true, "user": true, "group": true, "unit": true, "port": true, "module": true, "mount": true, "key": true, "facility": true, "zone": true}
```

and the comment on `Entry.SubjectKind` lists the two new kinds.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/check/ ./internal/controls/ ./internal/facts/ -count=1 -v -run 'TestNotMatches|TestLintAcceptsNotMatches|TestRegistryAcceptsFacility'`
Expected: PASS. Then `go test ./... -count=1` stays green (the facts schema golden does not change: `SubjectKind` is a string).

- [ ] **Step 5: Commit**

```bash
git add internal/check/value.go internal/check/value_test.go internal/controls/lint.go internal/controls/lint_test.go internal/facts/registry.go internal/facts/registry_test.go
git commit -m "Add not_matches and the facility and zone subject kinds"
```

---

### Task 2: `applies_when` before `automation: manual` (spec §6.5 rows 2–4)

**Files:**
- Modify: `internal/check/eval.go` (`evalOne`, the "Step 2" block), `internal/check/eval_test.go`
- Modify: `internal/controls/fixtures_test.go` (`checkInvariants`: a MANUAL result still needs evidence; a NOT_APPLICABLE from a manual control needs evidence too — both already required)

**Interfaces:**
- Consumes: `evalOne(e *env, c *controls.Control) Result`, `e.screen(cls, &r, screenApplies)`, `e.evalClause(cl)`, `fail(r, status, code, reason)`, `e.evidenceFor(keys)`, `e.describe(cl)`.
- Produces: the derivation order 1 → applies_when hard status (ERROR) → applies_when absent/unsupported/false (NOT_APPLICABLE) → manual/not_applicable automation → mechanisms/checks. Nothing else changes.

- [ ] **Step 1: Write the failing test**

Add to the `TestDerivationTable` cases in `internal/check/eval_test.go` (follow the existing case struct: name, control YAML or struct, snapshot facts, wanted status/code/reason substring). Three cases:

```go
		{
			name: "4 manual control whose applies_when holds is MANUAL with evidence",
			control: `
id: muster.service.mail_version
automation: manual
manual_reason: needs the MTA configuration parser
applies_when: { fact: services.ssh.installed, op: eq, expected: true }
requires_facts: ">=1"
`,
			facts:      `{"services":{"ssh":{"installed":{"status":"ok","value":true}}}}`,
			wantStatus: MANUAL,
			wantReason: "needs the MTA configuration parser",
			wantEvidenceKeys: []string{"services.ssh.installed"},
		},
		{
			name: "3 manual control whose applies_when is false is NOT_APPLICABLE, not MANUAL",
			control: `
id: muster.service.mail_version
automation: manual
manual_reason: needs the MTA configuration parser
applies_when: { fact: services.ssh.installed, op: eq, expected: true }
requires_facts: ">=1"
`,
			facts:      `{"services":{"ssh":{"installed":{"status":"ok","value":false}}}}`,
			wantStatus: NotApplicable,
			wantReason: "applies_when does not hold",
		},
		{
			name: "2 manual control whose applies_when fact is denied is ERROR",
			control: `
id: muster.service.mail_version
automation: manual
manual_reason: needs the MTA configuration parser
applies_when: { fact: services.ssh.installed, op: eq, expected: true }
requires_facts: ">=1"
`,
			facts:      `{"services":{"ssh":{"installed":{"status":"denied","reason":"needs root"}}}}`,
			wantStatus: ERROR,
			wantCode:   PermissionDenied,
		},
```

Use the table's actual field names (`wantEvidenceKeys` may be new: if the table has no evidence-key assertion, add the field and the assertion loop `for _, k := range tc.wantEvidenceKeys { if !hasEvidence(got, k) { t.Errorf(...) } }` with a small `hasEvidence` helper over `Result.Evidence[].Fact`). The existing case for a manual control without `applies_when` (if any) keeps its expectation: MANUAL.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/check/ -run 'TestDerivationTable' -v -count=1`
Expected: the "applies_when is false" case FAILS (got MANUAL, want NOT_APPLICABLE) and the "denied" case FAILS (got MANUAL, want ERROR).

- [ ] **Step 3: Reorder `evalOne`**

In `internal/check/eval.go`, move the `// Step 2.` block below the `// Steps 3-4.` block and renumber the comments so the code reads:

```go
	// Step 1.
	if need, ok := requiredVersion(c.RequiresFacts); ok && e.snap.SchemaVersion < need {
		return fail(r, ERROR, MissingFact, fmt.Sprintf("control requires facts schema >=%d; snapshot is %d", need, e.snap.SchemaVersion))
	}
	// Steps 2-3 (spec §6.5 as amended 2026-09-03): applies_when is screened
	// and evaluated before the automation class is looked at, so a manual
	// control on a host where it does not apply is NOT_APPLICABLE rather
	// than a permanent MANUAL row.
	if len(c.AppliesWhen) > 0 {
		if res, done := e.screen(c.AppliesWhen, &r, screenApplies); done {
			return res
		}
		for _, cl := range c.AppliesWhen {
			out := e.evalClause(cl)
			if out.Err != nil {
				return fail(r, ERROR, InternalError, out.Err.Error())
			}
			r.Evidence = append(r.Evidence, out.Evidence...)
			if !out.Holds {
				return fail(r, NotApplicable, "", "applies_when does not hold: "+e.describe(cl))
			}
		}
	}
	// Step 4.
	if c.Automation == "manual" || c.Automation == "not_applicable" {
		if len(c.AppliesWhen) == 0 {
			r.Evidence = e.evidenceFor(clauseFacts(c.AppliesWhen))
		}
		if c.Automation == "manual" {
			r.Status, r.Reason = MANUAL, c.ManualReason
		} else {
			r.Status, r.Reason = NotApplicable, c.ManualReason
		}
		return r
	}
	// Step 5: choose the judgment.
```

(`r.Evidence` already holds the applies_when evidence when `applies_when` exists; the `len == 0` guard keeps the old behaviour for a manual control without one.) Update every comment in the file that says "step 2" for the manual branch or "steps 3-4" for applies_when to the new numbers; `screen`'s doc comment says "(spec §6.5 steps 2-3)".

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/check/ -count=1 && go test ./internal/controls/ -count=1 && go test ./cmd/muster/ -count=1`
Expected: PASS. The five embedded controls have no `automation: manual`, so no fixture expectation changes; `TestEveryControlHasFixturesThatBehave` stays green.

- [ ] **Step 5: Commit**

```bash
git add internal/check/eval.go internal/check/eval_test.go
git commit -m "Evaluate applies_when before the manual automation class"
```

---

### Task 3: File kind and device number in `ReadMeta`

**Files:**
- Modify: `internal/collect/types.go` (`ReadMeta`), `internal/collect/readfile.go` (`fillMeta`, `Stat` doc), `internal/collect/readfile_test.go`
- Test runs on the lab host (Linux).

**Interfaces:**
- Produces: `ReadMeta.Kind string` — one of `regular | dir | symlink | chardev | blockdev | fifo | socket | unknown`; `ReadMeta.Rdev uint64` (raw `st_rdev`, meaningful for `chardev`/`blockdev`). `Stat` fills both for any kind (it already refuses to follow a final symlink and reports it as `ErrSymlink`, so `Kind == "symlink"` is only ever seen through the error path: keep that behaviour). `ReadFile` fills them before its `ErrNotRegular` return so a caller that reads a directory by mistake sees `Kind: "dir"` in the meta it gets back with the error.

- [ ] **Step 1: Write the failing tests**

Append to `internal/collect/readfile_test.go` (Linux-tagged file):

```go
func TestStatReportsTheFileKind(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, filepath.Join(dir, "f"), "x", 0o644)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	cases := map[string]string{filepath.Join(dir, "f"): "regular", filepath.Join(dir, "d"): "dir", fifo: "fifo", "/dev/null": "chardev"}
	for p, want := range cases {
		meta, err := Stat(p)
		if err != nil {
			t.Fatalf("Stat(%s): %v", p, err)
		}
		if meta.Kind != want {
			t.Errorf("Stat(%s).Kind = %q, want %q", p, meta.Kind, want)
		}
	}
	null, _ := Stat("/dev/null")
	if null.Rdev == 0 {
		t.Error("/dev/null must report a non-zero rdev")
	}
	_, meta, err := ReadFile(filepath.Join(dir, "d"), 10)
	if !errors.Is(err, ErrNotRegular) || meta.Kind != "dir" {
		t.Errorf("ReadFile on a dir: err=%v kind=%q", err, meta.Kind)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Sync and run on the lab host: `go test ./internal/collect/ -run TestStatReportsTheFileKind -v -count=1`
Expected: FAIL — `meta.Kind undefined`.

- [ ] **Step 3: Implement**

`internal/collect/types.go`, inside `ReadMeta` after `Mode`:

```go
	// Kind is the file type from st_mode's S_IFMT bits: regular | dir |
	// symlink | chardev | blockdev | fifo | socket | unknown. Rdev is the raw
	// st_rdev, meaningful for chardev and blockdev only.
	Kind string
	Rdev uint64
```

`internal/collect/readfile.go`:

```go
func fillMeta(m *ReadMeta, st *unix.Stat_t) {
	m.Size = st.Size
	m.Mode = uint32(st.Mode & 0o7777)
	m.UID, m.GID = st.Uid, st.Gid
	m.Kind = kindOf(st.Mode)
	m.Rdev = uint64(st.Rdev)
}

// kindOf names the S_IFMT file type so collectors never compare mode bits
// themselves.
func kindOf(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "regular"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFCHR:
		return "chardev"
	case unix.S_IFBLK:
		return "blockdev"
	case unix.S_IFIFO:
		return "fifo"
	case unix.S_IFSOCK:
		return "socket"
	}
	return "unknown"
}
```

`ReadFile` already calls `fillMeta` before the `S_IFREG` check, so the `ErrNotRegular` path returns the kind; confirm by reading the function and move the `fillMeta` call above the check if it is not.

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/ -v -count=1` (all), `go test ./internal/collect/... -race -shuffle=on -count=1`. Windows: `go build ./...`, `GOOS=linux GOARCH=amd64 go vet ./...`.
Expected: PASS; the schema golden is unaffected (`ReadMeta` is not a snapshot type).

- [ ] **Step 5: Commit**

```bash
git add internal/collect/types.go internal/collect/readfile.go internal/collect/readfile_test.go
git commit -m "Report the file kind and device number in ReadMeta"
```

---

### Task 4: `Access.Getxattr` and the POSIX ACL decoder

**Files:**
- Modify: `internal/collect/registry.go` (`Access` interface, `hostAccess.Getxattr`, `guardedAccess.Getxattr`), `internal/collect/registry_test.go` (`fakeAccess`), `internal/collect/run_test.go` (`quietAccess`)
- Create: `internal/collect/collectors/acl.go`, `internal/collect/collectors/acl_test.go`
- Modify: `internal/collect/collectors/collectors_test.go` (`fsAccess` gains `Getxattr`)

**Interfaces:**
- Consumes: `openNoFollow(p string, flags int) (int, string, error)` and `openFlags` in `internal/collect/readfile.go`; the guard's `allowedPath`/`violate` helpers; `unix.Fgetxattr`.
- Produces (package `collect`): `Access` gains `Getxattr(path, name string) ([]byte, error)` (seven methods). `hostAccess.Getxattr` opens through the primitive with the same flags as `Llistxattr`, reads with `unix.Fgetxattr` into a 64 KiB buffer and returns the value; `ENODATA`/`EOPNOTSUPP` propagate unchanged so callers classify them. The guard treats it as a read (declared path required) and records a violation otherwise.
- Produces (package `collectors`): `func decodeACL(b []byte) ([]string, error)` — decodes a `system.posix_acl_access` value into entries in file order, `user::rw-`, `user:1000:rw-`, `group::r--`, `group:27:r-x`, `mask::rw-`, `other::r--` (numeric ids, never resolved); `func aclEntries(a collect.Access, p string) (entries []string, present bool, err error)` — `present=false, entries=nil` when the attribute is not listed or the filesystem has no xattr support; a decode failure is an error with `present=true`.

- [ ] **Step 1: Write the failing tests**

`internal/collect/collectors/acl_test.go`:

```go
//go:build linux

package collectors

import (
	"encoding/binary"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// aclBlob builds a system.posix_acl_access value: version 2 header, then
// 8-byte entries {tag uint16, perm uint16, id uint32}, little-endian.
func aclBlob(entries ...[3]uint32) []byte {
	b := make([]byte, 4, 4+8*len(entries))
	binary.LittleEndian.PutUint32(b, 2)
	for _, e := range entries {
		var rec [8]byte
		binary.LittleEndian.PutUint16(rec[0:], uint16(e[0]))
		binary.LittleEndian.PutUint16(rec[2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(rec[4:], e[2])
		b = append(b, rec[:]...)
	}
	return b
}

const undefinedID = 0xFFFFFFFF

func fiveEntryACL() []byte {
	return aclBlob(
		[3]uint32{0x01, 6, undefinedID}, // user::rw-
		[3]uint32{0x02, 6, 1000},        // user:1000:rw-
		[3]uint32{0x04, 4, undefinedID}, // group::r--
		[3]uint32{0x10, 6, undefinedID}, // mask::rw-
		[3]uint32{0x20, 4, undefinedID}, // other::r--
	)
}

func TestDecodeACLRendersEveryTag(t *testing.T) {
	blob := aclBlob(
		[3]uint32{0x01, 6, undefinedID},
		[3]uint32{0x02, 6, 1000},
		[3]uint32{0x04, 4, undefinedID},
		[3]uint32{0x08, 5, 27},
		[3]uint32{0x10, 6, undefinedID},
		[3]uint32{0x20, 4, undefinedID},
	)
	got, err := decodeACL(blob)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user::rw-", "user:1000:rw-", "group::r--", "group:27:r-x", "mask::rw-", "other::r--"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDecodeACLRejectsGarbage(t *testing.T) {
	for name, blob := range map[string][]byte{
		"short":       {1, 2, 3},
		"bad version": append([]byte{9, 0, 0, 0}, aclBlob([3]uint32{0x01, 6, undefinedID})[4:]...),
		"ragged":      append(aclBlob([3]uint32{0x01, 6, undefinedID}), 1, 2, 3),
		"unknown tag": aclBlob([3]uint32{0x40, 6, undefinedID}),
	} {
		if _, err := decodeACL(blob); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestACLEntriesOnTheRealHost sets an ACL through the raw xattr on a file
// in t.TempDir() and reads it back through the production Access, so
// Getxattr is exercised end to end under the guard.
func TestACLEntriesOnTheRealHost(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/f"
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(p, "system.posix_acl_access", fiveEntryACL(), 0); err != nil {
		t.Skipf("filesystem without ACL xattr support: %v", err)
	}
	c := collect.Collector{Name: "t", Declare: collect.Declaration{Reads: []string{p}, Needs: "none"}, Run: func(context.Context, collect.Access, *collect.Builder) error { return nil }}
	g := collect.Guard(collect.Host(), c)
	entries, present, err := aclEntries(g, p)
	if err != nil || !present {
		t.Fatalf("entries=%v present=%v err=%v", entries, present, err)
	}
	if len(entries) != 5 || entries[1] != "user:1000:rw-" {
		t.Errorf("entries = %v", entries)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Errorf("declared read must not be a violation: %v", v)
	}
	plain := dir + "/plain"
	if err := os.WriteFile(plain, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2 := collect.Collector{Name: "t2", Declare: collect.Declaration{Reads: []string{plain}, Needs: "none"}, Run: c.Run}
	if entries, present, err := aclEntries(collect.Guard(collect.Host(), c2), plain); err != nil || present || entries != nil {
		t.Errorf("no ACL: entries=%v present=%v err=%v", entries, present, err)
	}
}
```

(`context` is imported for the no-op `Run`; `Register` is not called, so the registry is untouched.)

Add a guard test to `internal/collect/registry_test.go`:

```go
func TestGuardTreatsGetxattrAsARead(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/passwd"}, Needs: "none"}, Run: noopRun}
	g := Guard(&fakeAccess{}, c)
	if _, err := g.Getxattr("/etc/passwd", "system.posix_acl_access"); err != nil && !errors.Is(err, unix.ENODATA) {
		t.Errorf("declared: %v", err)
	}
	if _, err := g.Getxattr("/etc/shadow", "system.posix_acl_access"); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared: err=%v", err)
	}
	if v := g.Violations(); len(v) != 1 {
		t.Errorf("violations = %v", v)
	}
}
```

`fakeAccess`, `quietAccess` and the collectors' `fsAccess` each gain `Getxattr`: the two fakes return `nil, unix.ENODATA`; `fsAccess` returns the value from a new field `xattrs map[string]map[string][]byte` (path → name → value), `unix.ENODATA` when missing, and its `Llistxattr` lists the names in `xattrs[path]`.

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/... -run 'TestDecodeACL|TestACLEntries|TestGuardTreatsGetxattr' -v -count=1`
Expected: FAIL — compile errors (`Getxattr` not in the interface, `decodeACL` undefined).

- [ ] **Step 3: Implement**

`internal/collect/registry.go` — in the `Access` interface after `Llistxattr`:

```go
	// Getxattr returns the value of one extended attribute of path, read
	// through the same no-follow open Llistxattr uses. ENODATA and
	// EOPNOTSUPP propagate unchanged so the caller can classify them.
	Getxattr(path, name string) ([]byte, error)
```

`hostAccess`:

```go
func (hostAccess) Getxattr(p, name string) ([]byte, error) {
	p = rewriteProcSelf(p)
	fd, _, err := openNoFollow(p, openFlags)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	buf := make([]byte, 64<<10)
	n, err := unix.Fgetxattr(fd, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
```

`guardedAccess`, next to `Llistxattr` and with the same shape as the existing read-like methods (they call `allowedPath` and `violate`; copy their exact form):

```go
func (g *guardedAccess) Getxattr(p, name string) ([]byte, error) {
	clean, ok := g.allowedPath(p)
	if !ok {
		g.violate("getxattr", p)
		return nil, ErrUndeclared
	}
	return g.inner.Getxattr(clean, name)
}
```

Update the interface's doc comment ("seven methods") and any package comment that enumerates them.

`internal/collect/collectors/acl.go`:

```go
//go:build linux

package collectors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// POSIX ACL xattr encoding (fs/posix_acl.c): a 4-byte little-endian version
// (2) followed by 8-byte entries {tag u16, perm u16, id u32}.
const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclGroup     = 0x08
	aclMask      = 0x10
	aclOther     = 0x20
	aclXattrName = "system.posix_acl_access"
)

// decodeACL renders an access ACL as setfacl-style entries in file order.
// Named users and groups are rendered by numeric id, never resolved, so the
// snapshot carries no name lookup the check side could not reproduce.
func decodeACL(b []byte) ([]string, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("acl: %d bytes is not a header plus whole entries", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != aclVersion {
		return nil, fmt.Errorf("acl: version %d, want %d", v, aclVersion)
	}
	out := make([]string, 0, (len(b)-4)/8)
	for off := 4; off < len(b); off += 8 {
		tag := binary.LittleEndian.Uint16(b[off:])
		perm := binary.LittleEndian.Uint16(b[off+2:])
		id := binary.LittleEndian.Uint32(b[off+4:])
		var entry string
		switch tag {
		case aclUserObj:
			entry = "user::"
		case aclUser:
			entry = "user:" + strconv.FormatUint(uint64(id), 10) + ":"
		case aclGroupObj:
			entry = "group::"
		case aclGroup:
			entry = "group:" + strconv.FormatUint(uint64(id), 10) + ":"
		case aclMask:
			entry = "mask::"
		case aclOther:
			entry = "other::"
		default:
			return nil, fmt.Errorf("acl: unknown tag 0x%x", tag)
		}
		out = append(out, entry+rwx(perm))
	}
	return out, nil
}

func rwx(perm uint16) string {
	s := []byte("---")
	if perm&4 != 0 {
		s[0] = 'r'
	}
	if perm&2 != 0 {
		s[1] = 'w'
	}
	if perm&1 != 0 {
		s[2] = 'x'
	}
	return string(s)
}

// aclEntries lists p's access ACL. present is false when the attribute is
// not set or the filesystem has no xattr support; any other failure
// propagates so the fact becomes denied or error rather than a confident
// "no ACL".
func aclEntries(a collect.Access, p string) ([]string, bool, error) {
	names, err := a.Llistxattr(p)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		return nil, false, err
	}
	found := false
	for _, n := range names {
		if n == aclXattrName {
			found = true
			break
		}
	}
	if !found {
		return nil, false, nil
	}
	raw, err := a.Getxattr(p, aclXattrName)
	if err != nil {
		if errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		return nil, false, err
	}
	entries, err := decodeACL(raw)
	if err != nil {
		return nil, true, err
	}
	return entries, true, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/... -race -shuffle=on -count=1` and the three named tests with `-v`. Windows: `go build ./...`, `GOOS=linux GOARCH=amd64 go vet ./...`, `GOOS=linux GOARCH=amd64 go test -c -o /dev/null ./internal/collect/` and the same for `./internal/collect/collectors/`.
Expected: PASS; `TestACLEntriesOnTheRealHost` PASSES (not skips) on the lab host's ext4 `/tmp`.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/registry.go internal/collect/registry_test.go internal/collect/run_test.go internal/collect/collectors/acl.go internal/collect/collectors/acl_test.go internal/collect/collectors/collectors_test.go
git commit -m "Add Getxattr to Access and decode POSIX ACL entries"
```

---

### Task 5: The permission-fact template and the four fixed-path files

**Files:**
- Create: `internal/collect/collectors/permfacts.go`, `internal/collect/collectors/permfacts_test.go`, `internal/collect/collectors/testdata/group`
- Modify: `internal/collect/collectors/files.go` (declares `/etc/group`, `/etc/hosts`, `/etc/services`, `/etc/hosts.lpd`; uses the template for passwd, hosts, services, hosts.lpd; the securetty block is unchanged), `internal/collect/collectors/collectors_test.go` (the double learns `kind`; existing passwd tests keep passing)
- Modify: `internal/facts/registry.yaml` (33 keys), `internal/facts/testdata/facts-schema.golden.json` (regenerated with `-update`)

**Interfaces:**
- Conventions, restated here because every later plan uses them: **C1** — `files.*` owns permission facts of a fixed candidate path list; a path that must be discovered from a daemon's configuration belongs to that daemon's collector. **C2** — every leaf a clause judges is its own dotted key; `record` is evidence for `present`/`absent` only.
- Produces (package `collectors`):
  - `func groupNames(a collect.Access) (map[int]string, error)` — gid → name from `/etc/group` (declared); malformed lines are skipped.
  - `func writePermFacts(b *collect.Builder, a collect.Access, prefix, path string, groups map[int]string, withACL bool)` — writes `<prefix>.mode` (int, raw 0o7777 bits), `<prefix>.uid`, `<prefix>.gid` (int), `<prefix>.group` (string, `""` when the gid has no name), `<prefix>.group_readable`, `<prefix>.group_writable`, `<prefix>.other_readable`, `<prefix>.other_writable` (bool, from the mode bits), `<prefix>.acl_present` (bool) and, when `withACL`, `<prefix>.acl_entries` (`list<string>`, `[]` when no ACL). On a `Stat` error every leaf gets `collect.FromReadError(err, meta)`, so an absent file is `absent` on every leaf and a denied one `denied` on every leaf. A non-regular kind is still reported (a directory's mode is a fact); nothing here reads content.
- Registry keys (all `collector: files`, `since: 1`, `sensitivity: public`): `files.etc_passwd.{group,group_readable,group_writable,other_readable,other_writable,acl_entries}` (6, joining the existing four), and `files.etc_hosts.*`, `files.etc_services.*`, `files.etc_hosts_lpd.*` (9 each: mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present).

- [ ] **Step 1: Write the failing tests**

`internal/collect/collectors/testdata/group`:

```
root:x:0:
shadow:x:42:
adm:x:4:syslog,alice
broken line without fields
```

`internal/collect/collectors/permfacts_test.go` (Linux-tagged). Read `collectors_test.go` first: it defines the `fsAccess` double, `build(t, name, a)` and `env(t, b, key)`. Extend the double's stat record with a `kind string` field that its `Stat` copies into `ReadMeta.Kind`, and give it `xattrs map[string]map[string][]byte` (Task 4). Then:

```go
//go:build linux

package collectors

import (
	"os"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

func TestGroupNamesReadsEtcGroup(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	got, err := groupNames(a)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "root" || got[42] != "shadow" || got[4] != "adm" || len(got) != 3 {
		t.Errorf("groups = %v", got)
	}
}

func TestWritePermFactsLeavesForAFixedPath(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		stats: map[string]statResult{"/etc/hosts": {mode: 0o644, uid: 0, gid: 42, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_hosts.mode"); v.Status != facts.StatusOK || v.Value != 0o644 {
		t.Errorf("mode %+v", v)
	}
	if v := env(t, b, "files.etc_hosts.group"); v.Value != "shadow" {
		t.Errorf("group %+v", v)
	}
	for k, want := range map[string]bool{"group_readable": true, "group_writable": false, "other_readable": true, "other_writable": false, "acl_present": false} {
		if v := env(t, b, "files.etc_hosts."+k); v.Value != want {
			t.Errorf("%s = %+v, want %v", k, v, want)
		}
	}
}

func TestWritePermFactsAbsentAndDeniedReachEveryLeaf(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}, fails: map[string]error{"/etc/hosts.lpd": os.ErrNotExist, "/etc/services": os.ErrPermission}}
	b := build(t, "files", a)
	for _, k := range permLeaves {
		if v := env(t, b, "files.etc_hosts_lpd."+k); v.Status != facts.StatusAbsent {
			t.Errorf("hosts.lpd %s = %v, want absent", k, v.Status)
		}
		if v := env(t, b, "files.etc_services."+k); v.Status != facts.StatusDenied {
			t.Errorf("services %s = %v, want denied", k, v.Status)
		}
	}
}

func TestPasswdACLEntriesAreListed(t *testing.T) {
	a := &fsAccess{
		files:  map[string]string{"/etc/group": "group"},
		stats:  map[string]statResult{"/etc/passwd": {mode: 0o644, uid: 0, gid: 0, kind: "regular"}},
		xattrs: map[string]map[string][]byte{"/etc/passwd": {"system.posix_acl_access": fiveEntryACL()}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_passwd.acl_present"); v.Value != true {
		t.Errorf("acl_present %+v", v)
	}
	entries := env(t, b, "files.etc_passwd.acl_entries").Value.([]any)
	if len(entries) != 5 || entries[1] != "user:1000:rw-" {
		t.Errorf("acl_entries = %v", entries)
	}
	if v := env(t, b, "files.etc_hosts.acl_present"); v.Status != facts.StatusAbsent {
		t.Errorf("a path without a stat entry must be absent, got %v", v.Status)
	}
}

func TestGroupFailureDoesNotHideThePermissionFacts(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/group": os.ErrPermission},
		stats: map[string]statResult{"/etc/hosts": {mode: 0o600, uid: 0, gid: 0, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_hosts.mode"); v.Status != facts.StatusOK {
		t.Errorf("mode must not depend on /etc/group: %+v", v)
	}
	if v := env(t, b, "files.etc_hosts.group"); v.Status != facts.StatusDenied {
		t.Errorf("group name must carry the /etc/group failure, got %+v", v)
	}
}
```

Use the double's real field names (`stats`, `statResult`, `fails`, `xattrs` are what the tests above assume; if `collectors_test.go` names them differently, use its names and do not add a second double).

- [ ] **Step 2: Run the tests to verify they fail**

Host: `go test ./internal/collect/collectors/ -run 'TestGroupNames|TestWritePermFacts|TestPasswdACLEntries|TestGroupFailure' -v -count=1`
Expected: FAIL — undefined `groupNames`/`writePermFacts`/`permLeaves`, then panics on unregistered keys until the registry gains them.

- [ ] **Step 3: Implement**

`internal/facts/registry.yaml` — append the 33 entries in the file's style. Order: passwd's six new leaves right after `files.etc_passwd.acl_present`, then hosts, services, hosts_lpd, each `mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present`. Two examples:

```yaml
  - key: files.etc_passwd.acl_entries
    type: list<string>
    description: Access ACL entries of /etc/passwd in setfacl form with numeric ids (user::rw-, user:1000:rw-, group::r--, mask::rw-, other::r--); empty when no ACL is set.
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_hosts.other_writable
    type: bool
    description: Whether the other permission bits of /etc/hosts include write (derived from mode).
    since: 1
    sensitivity: public
    collector: files
```

Descriptions for the rest follow the existing `files.etc_passwd.*` wording (`Permission bits of /etc/hosts as an integer (e.g. 384 for 0600).`, `Owner uid of /etc/hosts.`, `Group gid of /etc/hosts.`, `Group name for the gid of /etc/hosts from /etc/group; empty when the gid has no name.`, `Whether the group permission bits of /etc/hosts include read (derived from mode).`, `Whether a POSIX ACL xattr is present on /etc/hosts.`).

`internal/collect/collectors/permfacts.go`:

```go
//go:build linux

package collectors

import (
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const groupPath = "/etc/group"

// groupNames maps gid to group name from /etc/group. Malformed lines are
// skipped: the name is a convenience for the reader; the judgment is on
// the numeric gid leaf.
func groupNames(a collect.Access) (map[int]string, error) {
	data, _, err := a.ReadFile(groupPath, readLimit)
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, l := range splitLines(data) {
		f := strings.Split(l, ":")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if _, dup := out[gid]; !dup {
			out[gid] = f[0]
		}
	}
	return out, nil
}

// permLeaves are the leaves every fixed-path permission fact carries
// (conventions C1/C2 in plan 2A).
var permLeaves = []string{"mode", "uid", "gid", "group", "group_readable", "group_writable", "other_readable", "other_writable", "acl_present"}

// writePermFacts writes the permission facts of one fixed path under
// prefix. A Stat failure reaches every leaf with the same envelope, so an
// absent file is absent everywhere and a denied one denied everywhere —
// never a partial set the check side could misread as "no ACL". groupErr
// is the error groupNames returned, if any: the group-name leaf carries it
// instead of a silent "".
func writePermFacts(b *collect.Builder, a collect.Access, prefix, path string, groups map[int]string, groupErr error, withACL bool) {
	leaves := permLeaves
	if withACL {
		leaves = append(append([]string{}, permLeaves...), "acl_entries")
	}
	meta, err := a.Stat(path)
	if err != nil {
		e := collect.FromReadError(err, meta)
		for _, k := range leaves {
			b.Set(prefix+"."+k, e)
		}
		return
	}
	src := &facts.Source{Kind: "file", Path: path}
	mode := int(meta.Mode)
	b.Set(prefix+".mode", collect.OK(mode, src))
	b.Set(prefix+".uid", collect.OK(int(meta.UID), src))
	b.Set(prefix+".gid", collect.OK(int(meta.GID), src))
	if groupErr != nil {
		b.Set(prefix+".group", collect.FromReadError(groupErr, collect.ReadMeta{}))
	} else {
		b.Set(prefix+".group", collect.OK(groups[int(meta.GID)], &facts.Source{Kind: "file", Path: groupPath}))
	}
	b.Set(prefix+".group_readable", collect.OK(mode&0o040 != 0, src))
	b.Set(prefix+".group_writable", collect.OK(mode&0o020 != 0, src))
	b.Set(prefix+".other_readable", collect.OK(mode&0o004 != 0, src))
	b.Set(prefix+".other_writable", collect.OK(mode&0o002 != 0, src))
	entries, present, aerr := aclEntries(a, path)
	if aerr != nil {
		e := collect.FromReadError(aerr, meta)
		b.Set(prefix+".acl_present", e)
		if withACL {
			b.Set(prefix+".acl_entries", e)
		}
		return
	}
	b.Set(prefix+".acl_present", collect.OK(present, src))
	if withACL {
		list := []any{} // R50: never nil
		for _, e := range entries {
			list = append(list, e)
		}
		b.Set(prefix+".acl_entries", collect.OK(list, src))
	}
}
```

`internal/collect/collectors/files.go` — constants, declaration and the start of `runFiles`:

```go
const (
	passwdPath    = "/etc/passwd"
	securettyPath = "/etc/securetty"
	hostsPath     = "/etc/hosts"
	servicesPath  = "/etc/services"
	hostsLpdPath  = "/etc/hosts.lpd"
)

var filesCollector = collect.Collector{
	Name:    "files",
	Declare: collect.Declaration{Reads: []string{passwdPath, securettyPath, groupPath, hostsPath, servicesPath, hostsLpdPath}, Needs: "none"},
	Run:     runFiles,
}

func runFiles(_ context.Context, a collect.Access, b *collect.Builder) error {
	groups, gerr := groupNames(a)
	writePermFacts(b, a, "files.etc_passwd", passwdPath, groups, gerr, true)
	writePermFacts(b, a, "files.etc_hosts", hostsPath, groups, gerr, false)
	writePermFacts(b, a, "files.etc_services", servicesPath, groups, gerr, false)
	writePermFacts(b, a, "files.etc_hosts_lpd", hostsLpdPath, groups, gerr, false)
	// /etc/securetty: unchanged from stage 1 …
```

Delete the old `aclPresent` function and the hand-written passwd block it served. Regenerate the golden: `go test ./internal/facts -run TestFactsSchemaGolden -update` (Windows is fine; the golden reflects the registry).

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/collectors/ -v -count=1` (all — `TestEveryCollectorStaysInsideItsDeclaration` and the real-host smoke test must still pass; extend the smoke test to assert `files.etc_hosts.mode` is `ok` with a value in `0..0o7777`), then `go test ./... -race -shuffle=on -count=1`. Windows: `go test ./... -count=1` (golden), cross vet, cross test builds.
Expected: PASS. The stage-1 passwd fixtures keep their four original leaves, so `TestEveryControlHasFixturesThatBehave` is unaffected until Task 7 changes the control.

- [ ] **Step 5: Commit**

```bash
git add internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json internal/collect/collectors/permfacts.go internal/collect/collectors/permfacts_test.go internal/collect/collectors/files.go internal/collect/collectors/collectors_test.go internal/collect/collectors/testdata/group
git commit -m "Write permission facts through one template for the fixed-path files"
```

---

### Task 6: `env.container` and `env.has_systemd` as fact keys

**Files:**
- Modify: `internal/facts/registry.yaml` (2 keys), `internal/facts/testdata/facts-schema.golden.json` (regenerated)
- Modify: `internal/collect/collectors/os.go`, `internal/collect/collectors/collectors_test.go`

**Interfaces:**
- Produces: `env.container` (`string`: the same value the `os` collector writes to `Run.Env.Container`: `none | docker | podman | lxc | systemd-nspawn | wsl` — use the exact vocabulary `os.go` already emits) and `env.has_systemd` (`bool`, `/run/systemd/system` exists). Both `collector: os`, `since: 1`, `sensitivity: public`. Later plans gate `services.*` controls on `env.has_systemd` and firewall on `env.container` through `applies_when`.

- [ ] **Step 1: Write the failing test**

Append to `collectors_test.go` beside the existing `os` collector tests; build the double the way those tests express "this marker exists" (read them first and reuse the same fields):

```go
func TestOSWritesEnvContainerAndSystemdAsFacts(t *testing.T) {
	a := osDoubleWithDockerAndSystemd(t) // the same fixture the existing docker/systemd os test builds; extract it into this helper if it is inline
	b := build(t, "os", a)
	if v := env(t, b, "env.container"); v.Status != facts.StatusOK || v.Value != "docker" {
		t.Errorf("env.container = %+v", v)
	}
	if v := env(t, b, "env.has_systemd"); v.Status != facts.StatusOK || v.Value != true {
		t.Errorf("env.has_systemd = %+v", v)
	}
	if h := b.Header(); h.Env.Container != "docker" || !h.Env.HasSystemd {
		t.Errorf("header must agree with the facts: %+v", h.Env)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Host: `go test ./internal/collect/collectors/ -run TestOSWritesEnv -v -count=1` — Expected: FAIL (panic: unregistered key `env.container`).

- [ ] **Step 3: Implement**

Registry (append after the last `accounts.*` key, before `walk.*`):

```yaml
  - key: env.container
    type: string
    description: Container runtime detected from filesystem markers (none, docker, podman, lxc, systemd-nspawn, wsl); the same value the run header carries.
    since: 1
    sensitivity: public
    collector: os
  - key: env.has_systemd
    type: bool
    description: Whether /run/systemd/system exists, so unit state can be asked of systemd.
    since: 1
    sensitivity: public
    collector: os
```

`os.go`: where `hdr.Env.Container` and `hdr.Env.HasSystemd` are assigned, add

```go
	b.Set("env.container", collect.OK(hdr.Env.Container, &facts.Source{Kind: "file", Path: containerMarker}))
	b.Set("env.has_systemd", collect.OK(hdr.Env.HasSystemd, &facts.Source{Kind: "file", Path: "/run/systemd/system"}))
```

where `containerMarker` is the marker path that decided the value (`/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup`, `/proc/version`) or `/proc/1/cgroup` for `none` — return it from the existing detection helper as a second value. Regenerate the golden.

- [ ] **Step 4: Run the tests to verify they pass**

Host: `go test ./internal/collect/... -race -shuffle=on -count=1`; Windows: `go test ./... -count=1`.

- [ ] **Step 5: Commit**

```bash
git add internal/facts/registry.yaml internal/facts/testdata/facts-schema.golden.json internal/collect/collectors/os.go internal/collect/collectors/collectors_test.go
git commit -m "Expose the container and systemd detection as env facts"
```

---

### Task 7: Controls U-16 (refined), U-19, U-22, U-29 with fixtures

**Files:**
- Modify: `controls/file/passwd_permissions.yaml`, its fixtures under `controls/testdata/muster.file.passwd_permissions/`
- Create: `controls/file/hosts_permissions.yaml`, `controls/file/services_permissions.yaml`, `controls/file/hosts_lpd_permissions.yaml` and their fixture directories
- Modify: `internal/controls/lint.go` only if `list<int>` is not yet an accepted `params` type
- Modify: `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `cmd/muster/e2e_test.go`

**Interfaces:**
- Consumes: `files.etc_passwd.acl_entries`, `files.etc_hosts.{uid,mode}`, `files.etc_services.{uid,mode}`, `files.etc_hosts_lpd.{uid,mode}` (Task 5); `none` with a `where` over a `list<string>` (the element is the subject, so the sub-clause has no `field`); the mode-subset lists (1A ruling R22: the vocabulary has no bit operator, so "0600 or stricter" is `in` over the subsets of 0600).
- The KISA 2021 number for each item comes from `docs/reference/kisa/kisa_mapping.json` — read it, never guess. `references.stig` stays empty in this plan (the index lands in Task 9; per-control mapping is plan 2M).
- Defaults are the guide's criterion (spec §6.6): `/etc/hosts` and `/etc/hosts.lpd` root-owned and 0600 or stricter; `/etc/services` root-owned and 0644 or stricter. The description names the distribution default where it differs (both families ship `/etc/hosts` as 0644) and the parameter that relaxes it.

- [ ] **Step 1: Write the controls**

`controls/file/hosts_permissions.yaml`:

```yaml
id: muster.file.hosts_permissions
title_en: /etc/hosts is owned by root and readable by root only
title_ko: /etc/hosts 가 root 소유이고 root 만 읽을 수 있다
description_en: The guide's criterion is owner root and mode 0600 or stricter. Ubuntu and Rocky ship /etc/hosts as 0644, so a stock host fails until the mode is tightened or allowed_modes is widened deliberately.
description_ko: 가이드 기준은 소유자 root, 모드 0600 이하입니다. Ubuntu 와 Rocky 는 /etc/hosts 를 0644 로 배포하므로, 모드를 조이거나 allowed_modes 를 의도적으로 넓히기 전까지 기본 설치는 실패합니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-19"], "2021": ["<the 2021 code for U-19 from kisa_mapping.json>"] }
requires_facts: ">=1"
absent_means: fail
params:
  allowed_modes: { type: list<int>, default: [0, 128, 256, 384], description: Modes that count as 0600 or stricter (0600 and every subset of its bits) }
checks:
  - { fact: files.etc_hosts.uid, op: eq, expected: 0 }
  - { fact: files.etc_hosts.mode, op: in, expected: "${allowed_modes}" }
remediation:
  text_en: chown root:root /etc/hosts; chmod 600 /etc/hosts
  text_ko: chown root:root /etc/hosts; chmod 600 /etc/hosts
  risk: none
  idempotent: true
  script: chown root:root /etc/hosts && chmod 600 /etc/hosts
```

Replace the `"2021"` placeholder with the real code from the mapping file (and drop the key if the mapping has none for that item). If `list<int>` is not in lint's accepted `params` types (check the param-type set in `internal/controls/lint.go`; stage 1 used `list<string>`), add it with the default-element check (every element an integer) in this task and say so in the report; `in` on an `int` fact against an integer list already works (`inList(toInt)`).

`controls/file/services_permissions.yaml` — the same shape over `files.etc_services.*`: title "/etc/services is owned by root and not writable by group or others" / "/etc/services 가 root 소유이고 그룹과 다른 사용자가 쓸 수 없다", `allowed_modes` default the sixteen subsets of 0644 `[0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420]`, `absent_means: fail`, remediation `chown root:root /etc/services; chmod 644 /etc/services`, references U-22 (+ its 2021 code).

`controls/file/hosts_lpd_permissions.yaml` — over `files.etc_hosts_lpd.*`: title "/etc/hosts.lpd, when present, is owned by root and readable by root only", `allowed_modes` default `[0, 128, 256, 384]`, `absent_means: pass` with a description sentence "The file need not exist; an absent file passes.", remediation `chown root:root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd`, references U-29 (+ its 2021 code).

`controls/file/passwd_permissions.yaml` — replace the `acl_present` clause with an entry check and reword the description:

```yaml
description_en: Owner and group must be root, mode must be 0644 or stricter, and no named user or group may be granted access through a POSIX ACL. The base ACL entries (user::, group::, mask::, other::) mirror the mode and are allowed.
description_ko: 소유자와 그룹이 root 여야 하고 모드가 0644 이하여야 하며 POSIX ACL 로 특정 사용자나 그룹에 접근을 부여하면 안 됩니다. 모드를 그대로 반영하는 기본 ACL 항목(user::, group::, mask::, other::)은 허용합니다.
checks:
  - { fact: files.etc_passwd.uid, op: eq, expected: 0 }
  - { fact: files.etc_passwd.gid, op: eq, expected: 0 }
  - { fact: files.etc_passwd.mode, op: in, expected: [0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420] } # 0644 or any subset of its bits
  - { fact: files.etc_passwd.acl_entries, op: none, where: { op: matches, expected: "^(user|group):[^:]+:" } } # a named entry widens access whatever its bits
```

`acl_present` stays registered and written (evidence) but leaves the checks; `remediation` keeps `setfacl -b`.

- [ ] **Step 2: Write the fixtures**

Every fixture: `"synthetic": true`, `"schema_version": 1`, `"run": {}`, and only the leaves the control reads, e.g.

```json
{"synthetic":true,"schema_version":1,"run":{},"facts":{"files":{"etc_hosts":{"uid":{"status":"ok","value":0,"source":{"kind":"file","path":"/etc/hosts"}},"mode":{"status":"ok","value":384,"source":{"kind":"file","path":"/etc/hosts"}}}}}}
```

- `muster.file.passwd_permissions/`: add `fail-named-acl.json` (uid 0, gid 0, mode 420, `acl_entries` `["user::rw-","user:1000:rw-","group::r--","mask::rw-","other::r--"]`); change `fail-acl.json` so its `acl_entries` carries a named entry (an `acl_present: true` alone no longer fails) and give every other passwd fixture `"acl_entries": {"status":"ok","value":[]}` (or `absent`/`denied` where the fixture's other leaves are) — the control reads the key, and a fixture missing it would be `ERROR(missing_fact)`, which is the spec's rule, not a fixture convenience.
- `muster.file.hosts_permissions/`: `pass-0600.json` (uid 0, mode 384), `fail-0644.json` (mode 420), `fail-owner.json` (uid 1000, mode 384), `fail-absent.json` (both leaves `absent` → FAIL through `absent_means: fail`).
- `muster.file.services_permissions/`: `pass-0644.json`, `fail-0664.json` (mode 436), `fail-owner.json`.
- `muster.file.hosts_lpd_permissions/`: `pass-absent.json` (both leaves `absent` → PASS), `pass-0600.json`, `fail-0644.json`, `fail-owner.json`.
- `cmd/muster/testdata/full-pass.json` and `full-fail.json` gain `files.etc_hosts.{uid,mode}` (0/384), `files.etc_services.{uid,mode}` (0/420), `files.etc_hosts_lpd.{uid,mode}` (`absent`), `files.etc_passwd.acl_entries` (ok, `[]`), so the three new controls PASS in both e2e snapshots (the e2e FAIL stays U-01's). `cmd/muster/e2e_test.go`'s expected-status map gains the three ids as PASS.

- [ ] **Step 3: Lint and test**

Run: `go run ./cmd/muster controls lint` → `ok: 8 controls` (after the fixtures are complete; a missing `pass-`/`fail-` pair is a lint error). Then `go test ./internal/controls/ -run TestEveryControlHasFixturesThatBehave -v -count=1` and `go test ./cmd/muster/ -count=1`.
Expected: every fixture produces its promised status for the reason its name implies — read the `-v` output: `fail-named-acl` fails on the `none` clause naming `user:1000:rw-`, `fail-owner` on the `uid` clause, `pass-absent` (hosts.lpd) passes through `absent_means`.

- [ ] **Step 4: End to end on the host**

Sync, build, and in a `mktemp -d` directory as root: `./bin/muster collect --out "$d/s.json" --require-root --require-complete; echo $?` (0), then `./bin/muster check --facts "$d/s.json" --format json | jq -r '.results[] | select(.id | startswith("muster.file.")) | .id + " " + .status'` — expect `hosts_permissions FAIL` (stock 0644), `services_permissions PASS`, `hosts_lpd_permissions PASS`, `passwd_permissions PASS`; quote only those lines; `rm -rf "$d"`.

- [ ] **Step 5: Commit**

```bash
git add controls/ cmd/muster/testdata cmd/muster/e2e_test.go internal/controls/lint.go
git commit -m "Add the hosts, services and hosts.lpd permission controls and judge the passwd ACL entries"
```

---

### Task 8: The coverage table generator

**Files:**
- Create: `tools/coverage/main.go`, `tools/coverage/render.go`, `tools/coverage/render_test.go`, `docs/reference/coverage.md` (generated, committed)
- Modify: `Makefile` (`coverage` target), `.github/workflows/ci.yml` (`test` job gains a `coverage table is current` step after `controls lint`)

**Interfaces:**
- Consumes: `controls.LoadDefault() (*Set, error)` (embedded set; `Set.Controls []Control` or whatever the accessor is — read `internal/controls/load.go`), `Control.References.KISA["2026"]`, `Control.Automation`; `docs/reference/kisa/kisa_items_latest.json` (`[{id, name_ko, category, importance, page}]`).
- Produces: `go run ./tools/coverage` writes `docs/reference/coverage.md`; `go run ./tools/coverage -check` exits 1 with a unified-diff-style message when the committed file differs from what would be generated. The document is byte-identical across runs: rows sorted by KISA id, no timestamps.
- `tools/coverage` imports `internal/controls` and `internal/facts` only — never `internal/collect` (Linux-only) — so `go build ./...` stays green everywhere.

- [ ] **Step 1: Write the failing test**

`tools/coverage/render_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func TestRenderJoinsItemsWithControlsInIDOrder(t *testing.T) {
	items := []kisaItem{
		{ID: "U-02", NameKo: "비밀번호 관리정책 설정", Importance: "상"},
		{ID: "U-01", NameKo: "root 계정 원격 접속 제한", Importance: "상"},
		{ID: "U-45", NameKo: "메일 서비스 버전 점검", Importance: "상"},
	}
	set := []controls.Control{
		{ID: "muster.account.root_remote_login", Automation: "auto", References: controls.References{KISA: map[string][]string{"2026": {"U-01"}}}},
		{ID: "muster.service.mail_version", Automation: "manual", References: controls.References{KISA: map[string][]string{"2026": {"U-45"}}}},
	}
	got := render(items, set)
	wantLines := []string{
		"| U-01 | root 계정 원격 접속 제한 | 상 | muster.account.root_remote_login | auto | enrolled |",
		"| U-02 | 비밀번호 관리정책 설정 | 상 | — | — | not enrolled |",
		"| U-45 | 메일 서비스 버전 점검 | 상 | muster.service.mail_version | manual | enrolled |",
	}
	for _, l := range wantLines {
		if !strings.Contains(got, l) {
			t.Errorf("missing line %q in:\n%s", l, got)
		}
	}
	if strings.Index(got, "| U-01 |") > strings.Index(got, "| U-02 |") {
		t.Error("rows must be in KISA id order regardless of input order")
	}
	if !strings.Contains(got, "2 of 3 items enrolled (auto 1, partial 0, manual 1)") {
		t.Errorf("summary line missing in:\n%s", got)
	}
	if !strings.HasPrefix(got, "<!-- Generated by go run ./tools/coverage; do not edit. -->\n") {
		t.Error("the file must announce that it is generated")
	}
	if render(items, set) != got {
		t.Error("render must be deterministic")
	}
}

func TestRenderFlagsAControlWithoutAKISAItem(t *testing.T) {
	items := []kisaItem{{ID: "U-01", NameKo: "x", Importance: "상"}}
	set := []controls.Control{{ID: "muster.beyond.sudoers", Automation: "auto", References: controls.References{KISA: map[string][]string{"2026": {"U-99"}}}}}
	got := render(items, set)
	if !strings.Contains(got, "muster.beyond.sudoers") || !strings.Contains(got, "U-99") || !strings.Contains(got, "unknown item") {
		t.Errorf("a reference to an item that is not in the inventory must be listed under unknown items:\n%s", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./tools/coverage/ -v` — Expected: FAIL — `kisaItem`/`render` undefined.

- [ ] **Step 3: Implement**

`tools/coverage/render.go`:

```go
package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/controls"
)

type kisaItem struct {
	ID         string `json:"id"`
	NameKo     string `json:"name_ko"`
	Category   string `json:"category"`
	Importance string `json:"importance"`
	Page       int    `json:"page"`
}

const header = "<!-- Generated by go run ./tools/coverage; do not edit. -->\n"

// render joins the KISA inventory with the embedded control set. One row
// per item in id order; a control citing an item that is not in the
// inventory is listed separately so a typo in references.kisa is visible.
func render(items []kisaItem, set []controls.Control) string {
	byItem := map[string][]controls.Control{}
	known := map[string]bool{}
	for _, it := range items {
		known[it.ID] = true
	}
	var unknown []string
	for _, c := range set {
		for _, id := range c.References.KISA["2026"] {
			if !known[id] {
				unknown = append(unknown, fmt.Sprintf("| %s | %s | unknown item |", c.ID, id))
				continue
			}
			byItem[id] = append(byItem[id], c)
		}
	}
	sorted := append([]kisaItem(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("# KISA 2026 Unix items — coverage\n\n")
	counts := map[string]int{}
	enrolled := 0
	var rows []string
	for _, it := range sorted {
		cs := byItem[it.ID]
		if len(cs) == 0 {
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | — | — | not enrolled |", it.ID, it.NameKo, it.Importance))
			continue
		}
		enrolled++
		sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
		for _, c := range cs {
			counts[c.Automation]++
			rows = append(rows, fmt.Sprintf("| %s | %s | %s | %s | %s | enrolled |", it.ID, it.NameKo, it.Importance, c.ID, c.Automation))
		}
	}
	fmt.Fprintf(&b, "%d of %d items enrolled (auto %d, partial %d, manual %d).\n\n", enrolled, len(sorted), counts["auto"], counts["partial"], counts["manual"])
	b.WriteString("| ID | Item (KISA) | Imp. | Control | Automation | Status |\n|---|---|---|---|---|---|\n")
	b.WriteString(strings.Join(rows, "\n"))
	b.WriteString("\n")
	if len(unknown) > 0 {
		sort.Strings(unknown)
		b.WriteString("\n## References to unknown items\n\n| Control | Reference | Status |\n|---|---|---|\n")
		b.WriteString(strings.Join(unknown, "\n"))
		b.WriteString("\n")
	}
	return b.String()
}
```

`tools/coverage/main.go`:

```go
// Command coverage renders docs/reference/coverage.md from the embedded
// control set and the KISA item inventory, or checks that the committed
// file is current (-check). It never touches internal/collect.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/kun9497/muster/internal/controls"
)

func main() {
	out := flag.String("out", "docs/reference/coverage.md", "file to write")
	inv := flag.String("kisa", "docs/reference/kisa/kisa_items_latest.json", "KISA item inventory")
	check := flag.Bool("check", false, "exit 1 if the committed file differs instead of writing")
	flag.Parse()
	data, err := os.ReadFile(*inv)
	if err != nil {
		fatal(err)
	}
	var items []kisaItem
	if err := json.Unmarshal(data, &items); err != nil {
		fatal(fmt.Errorf("%s: %w", *inv, err))
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fatal(err)
	}
	got := []byte(render(items, set.Controls))
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil || !bytes.Equal(have, got) {
			fmt.Fprintf(os.Stderr, "coverage: %s is out of date; run: go run ./tools/coverage\n", *out)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, got, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "coverage: %v\n", err)
	os.Exit(2)
}
```

(Use the real accessor for the set's controls — `set.Controls`, `set.All()`, whatever `load.go` exposes.) Then generate: `go run ./tools/coverage` → `docs/reference/coverage.md` (8 items enrolled after Task 7). `Makefile`: `coverage:\n\tgo run ./tools/coverage` and `lint-controls` unchanged. CI `test` job, after `controls lint`: `- name: coverage table is current\n  run: go run ./tools/coverage -check`.

- [ ] **Step 4: Run the tests and the check**

Run: `go test ./tools/coverage/ -count=1 -v`, `go run ./tools/coverage -check` (exit 0 after generating), then edit the committed file by hand, run `-check` again (exit 1), regenerate.

- [ ] **Step 5: Commit**

```bash
git add tools/coverage docs/reference/coverage.md Makefile .github/workflows/ci.yml
git commit -m "Generate and check the KISA coverage table"
```

---

### Task 9: The STIG/CCI reference index generator

**Files:**
- Create: `tools/refindex/main.go`, `tools/refindex/xccdf.go`, `tools/refindex/xccdf_test.go`, `tools/refindex/cci.go`, `tools/refindex/cci_test.go`, `tools/refindex/sources.json`, `tools/refindex/testdata/{mini-xccdf.xml,mini-cci.xml}`
- Create (generated): `docs/reference/stig/ubuntu2204-v2r9.json`, `docs/reference/stig/ubuntu2404-v1r6.json`, `docs/reference/stig/rhel9-v2r9.json`
- Modify: `.gitignore` (`/.cache/`), `Makefile` (`refindex`, `refindex-check`)

**Interfaces:**
- Inputs, pinned in `tools/refindex/sources.json` (the implementer downloads each once, computes its SHA-256 and pins it; the controller verifies the digests against an independent download):

```json
[
  {"product": "ubuntu2204", "benchmark": "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide", "version": "V2R9",
   "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V2R9_STIG.zip", "sha256": "<pin>",
   "member": "U_CAN_Ubuntu_22-04_LTS_V2R9_Manual_STIG/U_CAN_Ubuntu_22-04_LTS_STIG_V2R9_Manual-xccdf.xml"},
  {"product": "ubuntu2404", "benchmark": "Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide", "version": "V1R6",
   "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_24-04_LTS_V1R6_STIG.zip", "sha256": "<pin>",
   "member": "U_CAN_Ubuntu_24-04_LTS_V1R6_Manual_STIG/U_CAN_Ubuntu_24-04_LTS_STIG_V1R6_Manual-xccdf.xml"},
  {"product": "rhel9", "benchmark": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide", "version": "V2R9", "applies_to": ["rocky9", "alma9"],
   "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V2R9_STIG.zip", "sha256": "<pin>",
   "member": "U_RHEL_9_V2R9_Manual_STIG/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml"},
  {"product": "cci", "url": "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CCI_List.zip", "sha256": "<pin>", "member": "U_CCI_List.xml"}
]
```

- Produces: `go run ./tools/refindex [-cache .cache/refindex] [-out docs/reference/stig] [-check]` — downloads each URL into the cache (skipped when the cached file's digest already matches), refuses a digest mismatch, opens the zip, parses the XCCDF and the CCI list, and writes one JSON per STIG product:

```json
{
  "product": "rhel9",
  "applies_to": ["rocky9", "alma9"],
  "benchmark": "Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
  "version": "V2R9",
  "release_info": "Release: 9 Benchmark Date: 01 Jul 2026",
  "source": {"url": "…", "sha256": "…", "member": "…"},
  "cci_list": {"version": "2025-01-23", "sha256": "…"},
  "rules": [
    {"stig_id": "RHEL-09-211010", "group_id": "V-257777", "rule_id": "SV-257777r1155676_rule", "severity": "high",
     "title": "RHEL 9 must be a vendor-supported release.", "ccis": ["CCI-000366"], "nist": ["CM-6"]}
  ]
}
```

  `rules` sorted by `stig_id`; `nist` per rule is the sorted, de-duplicated union over its CCIs of the CCI list's `NIST SP 800-53 Revision 5` index (falling back to `Revision 4`, then the unversioned `NIST SP 800-53`), normalised to a control id: `AC-6 (10)` → `AC-6(10)`, `CM-6 b` → `CM-6`, `AC-1 a 1` → `AC-1` (regex `^([A-Z]{2}-\d+)(?:\s*\((\d+)\))?`). `-check` regenerates in memory and compares with the committed files byte for byte. Output is `json.MarshalIndent(v, "", "  ")` plus a trailing newline; nothing from `time.Now()`.
- The generator reproduces STIG rule ids, group ids, severities and titles and CCI/NIST identifiers only — never `description`, `check-content` or `fixtext` (Task 11 records why in ATTRIBUTION.md).
- Tests use two tiny synthetic XML files under `testdata/`; no test touches the network.

- [ ] **Step 1: Write the failing tests**

`tools/refindex/testdata/mini-xccdf.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="MINI_STIG">
<plain-text id="release-info">Release: 1 Benchmark Date: 01 Jan 2026</plain-text>
<version>1</version>
<Group id="V-000002"><title>SRG-OS-000002</title><description>&lt;GroupDescription&gt;&lt;/GroupDescription&gt;</description>
<Rule id="SV-000002r2_rule" weight="10.0" severity="medium"><version>MINI-00-000020</version><title>Second rule</title><description>ignored</description>
<ident system="http://cyber.mil/cci">CCI-000068</ident><ident system="http://cyber.mil/cci">CCI-000366</ident>
<fixtext fixref="F-1">ignored</fixtext><check system="C-1"><check-content>ignored</check-content></check></Rule></Group>
<Group id="V-000001"><title>SRG-OS-000001</title><description>x</description>
<Rule id="SV-000001r1_rule" weight="10.0" severity="high"><version>MINI-00-000010</version><title>First rule</title>
<ident system="http://cyber.mil/cci">CCI-000366</ident></Rule></Group>
</Benchmark>
```

`tools/refindex/testdata/mini-cci.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<cci_list xmlns="http://iase.disa.mil/cci"><metadata><version>2025-01-23</version><publishdate>2025-01-23</publishdate></metadata>
<cci_items>
<cci_item id="CCI-000068"><status>draft</status><definition>d</definition><type>technical</type><references>
<reference creator="NIST" title="NIST SP 800-53" version="3" index="AC-17 (2)" />
<reference creator="NIST" title="NIST SP 800-53 Revision 4" version="4" index="AC-17 (2)" />
<reference creator="NIST" title="NIST SP 800-53 Revision 5" version="5" index="AC-17 (2)" /></references></cci_item>
<cci_item id="CCI-000366"><status>draft</status><definition>d</definition><type>policy</type><references>
<reference creator="NIST" title="NIST SP 800-53" version="3" index="CM-6 b" />
<reference creator="NIST" title="NIST SP 800-53 Revision 4" version="4" index="CM-6 b" /></references></cci_item>
</cci_items></cci_list>
```

`tools/refindex/xccdf_test.go`:

```go
package main

import (
	"os"
	"testing"
)

func TestParseXCCDFCollectsRulesInStigIDOrder(t *testing.T) {
	data, err := os.ReadFile("testdata/mini-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	bench, err := parseXCCDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if bench.ReleaseInfo != "Release: 1 Benchmark Date: 01 Jan 2026" {
		t.Errorf("release info %q", bench.ReleaseInfo)
	}
	if len(bench.Rules) != 2 || bench.Rules[0].StigID != "MINI-00-000010" || bench.Rules[1].StigID != "MINI-00-000020" {
		t.Fatalf("rules %+v", bench.Rules)
	}
	r := bench.Rules[1]
	if r.GroupID != "V-000002" || r.RuleID != "SV-000002r2_rule" || r.Severity != "medium" || r.Title != "Second rule" {
		t.Errorf("rule %+v", r)
	}
	if len(r.CCIs) != 2 || r.CCIs[0] != "CCI-000068" || r.CCIs[1] != "CCI-000366" {
		t.Errorf("ccis %v", r.CCIs)
	}
}

func TestParseXCCDFRejectsARuleWithoutAStigID(t *testing.T) {
	bad := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>t</title></Rule></Group></Benchmark>`
	if _, err := parseXCCDF([]byte(bad)); err == nil {
		t.Error("a rule without <version> (the STIG id) must be an error")
	}
}
```

`tools/refindex/cci_test.go`:

```go
package main

import (
	"os"
	"testing"
)

func TestParseCCIPrefersRevision5ThenFallsBack(t *testing.T) {
	data, err := os.ReadFile("testdata/mini-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseCCI(data)
	if err != nil {
		t.Fatal(err)
	}
	if list.Version != "2025-01-23" {
		t.Errorf("version %q", list.Version)
	}
	if got := list.NIST["CCI-000068"]; len(got) != 1 || got[0] != "AC-17(2)" {
		t.Errorf("CCI-000068 → %v, want [AC-17(2)] from Revision 5", got)
	}
	if got := list.NIST["CCI-000366"]; len(got) != 1 || got[0] != "CM-6" {
		t.Errorf("CCI-000366 → %v, want [CM-6] from Revision 4 with the paragraph letter dropped", got)
	}
}

func TestNistIDNormalisation(t *testing.T) {
	cases := map[string]string{"AC-6 (10)": "AC-6(10)", "CM-6 b": "CM-6", "AC-1 a 1": "AC-1", "IA-5 (1) (c)": "IA-5(1)", "SC-8": "SC-8", "garbage": ""}
	for in, want := range cases {
		if got := nistID(in); got != want {
			t.Errorf("nistID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIndexJSONIsDeterministic(t *testing.T) {
	x, _ := os.ReadFile("testdata/mini-xccdf.xml")
	c, _ := os.ReadFile("testdata/mini-cci.xml")
	bench, _ := parseXCCDF(x)
	list, _ := parseCCI(c)
	src := source{Product: "mini", Benchmark: "Mini", Version: "V1R1", URL: "u", SHA256: "s", Member: "m"}
	a, err := renderIndex(src, bench, list, "cci-sha")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := renderIndex(src, bench, list, "cci-sha")
	if string(a) != string(b) {
		t.Error("renderIndex must be deterministic")
	}
	if !strings.Contains(string(a), `"nist": [
        "AC-17(2)",
        "CM-6"
      ]`) {
		t.Errorf("rule nist union missing or unsorted:\n%s", a)
	}
	if a[len(a)-1] != '\n' {
		t.Error("output must end with a newline")
	}
}
```

(`strings` imported in that file.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./tools/refindex/ -v` — Expected: FAIL — undefined `parseXCCDF`, `parseCCI`, `nistID`, `renderIndex`, `source`.

- [ ] **Step 3: Implement**

`tools/refindex/xccdf.go`:

```go
package main

import (
	"encoding/xml"
	"fmt"
	"sort"
)

type xccdfRule struct {
	StigID   string   `json:"stig_id"`
	GroupID  string   `json:"group_id"`
	RuleID   string   `json:"rule_id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	CCIs     []string `json:"ccis"`
	NIST     []string `json:"nist"`
}

type benchmark struct {
	ReleaseInfo string
	Rules       []xccdfRule
}

// parseXCCDF reads the DISA manual XCCDF (XCCDF 1.1). Only identifiers,
// severity and the rule title are kept; description, check-content and
// fixtext are skipped unread (ATTRIBUTION.md).
func parseXCCDF(data []byte) (*benchmark, error) {
	var doc struct {
		PlainText []struct {
			ID   string `xml:"id,attr"`
			Text string `xml:",chardata"`
		} `xml:"plain-text"`
		Groups []struct {
			ID   string `xml:"id,attr"`
			Rule struct {
				ID       string `xml:"id,attr"`
				Severity string `xml:"severity,attr"`
				Version  string `xml:"version"`
				Title    string `xml:"title"`
				Idents   []struct {
					System string `xml:"system,attr"`
					Value  string `xml:",chardata"`
				} `xml:"ident"`
			} `xml:"Rule"`
		} `xml:"Group"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("xccdf: %w", err)
	}
	b := &benchmark{}
	for _, p := range doc.PlainText {
		if p.ID == "release-info" {
			b.ReleaseInfo = p.Text
		}
	}
	for _, g := range doc.Groups {
		r := g.Rule
		if r.Version == "" {
			return nil, fmt.Errorf("xccdf: group %s: rule %s has no <version> (STIG id)", g.ID, r.ID)
		}
		rule := xccdfRule{StigID: r.Version, GroupID: g.ID, RuleID: r.ID, Severity: r.Severity, Title: r.Title, CCIs: []string{}, NIST: []string{}}
		for _, id := range r.Idents {
			if id.System == "http://cyber.mil/cci" {
				rule.CCIs = append(rule.CCIs, id.Value)
			}
		}
		sort.Strings(rule.CCIs)
		b.Rules = append(b.Rules, rule)
	}
	sort.Slice(b.Rules, func(i, j int) bool { return b.Rules[i].StigID < b.Rules[j].StigID })
	return b, nil
}
```

`tools/refindex/cci.go`:

```go
package main

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
)

type cciList struct {
	Version string
	NIST    map[string][]string // CCI id → normalised NIST 800-53 control ids
}

var nistRe = regexp.MustCompile(`^([A-Z]{2}-\d+)(?:\s*\((\d+)\))?`)

// nistID reduces a CCI reference index ("AC-6 (10)", "CM-6 b", "AC-1 a 1")
// to a control or enhancement id; "" when it is not one.
func nistID(index string) string {
	m := nistRe.FindStringSubmatch(index)
	if m == nil {
		return ""
	}
	if m[2] != "" {
		return m[1] + "(" + m[2] + ")"
	}
	return m[1]
}

// parseCCI maps every CCI to NIST 800-53 ids, preferring the Revision 5
// references, then Revision 4, then the unversioned title.
func parseCCI(data []byte) (*cciList, error) {
	var doc struct {
		Version string `xml:"metadata>version"`
		Items   []struct {
			ID   string `xml:"id,attr"`
			Refs []struct {
				Title string `xml:"title,attr"`
				Index string `xml:"index,attr"`
			} `xml:"references>reference"`
		} `xml:"cci_items>cci_item"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("cci: %w", err)
	}
	out := &cciList{Version: doc.Version, NIST: map[string][]string{}}
	for _, it := range doc.Items {
		best := -1
		var ids map[string]bool
		for _, r := range it.Refs {
			rank := map[string]int{"NIST SP 800-53 Revision 5": 3, "NIST SP 800-53 Revision 4": 2, "NIST SP 800-53": 1}[r.Title]
			if rank == 0 || rank < best {
				continue
			}
			if rank > best {
				best, ids = rank, map[string]bool{}
			}
			if id := nistID(r.Index); id != "" {
				ids[id] = true
			}
		}
		list := make([]string, 0, len(ids))
		for id := range ids {
			list = append(list, id)
		}
		sort.Strings(list)
		out.NIST[it.ID] = list
	}
	return out, nil
}
```

`tools/refindex/main.go` (download, digest, zip, render, check):

```go
// Command refindex builds docs/reference/stig/*.json from DISA's public
// STIG XCCDF files and CCI list, pinned by URL and SHA-256 in sources.json.
// Only identifiers, severities and titles are reproduced.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type source struct {
	Product   string   `json:"product"`
	AppliesTo []string `json:"applies_to,omitempty"`
	Benchmark string   `json:"benchmark,omitempty"`
	Version   string   `json:"version,omitempty"`
	URL       string   `json:"url"`
	SHA256    string   `json:"sha256"`
	Member    string   `json:"member"`
}

type index struct {
	Product     string      `json:"product"`
	AppliesTo   []string    `json:"applies_to,omitempty"`
	Benchmark   string      `json:"benchmark"`
	Version     string      `json:"version"`
	ReleaseInfo string      `json:"release_info"`
	Source      indexSource `json:"source"`
	CCIList     indexCCI    `json:"cci_list"`
	Rules       []xccdfRule `json:"rules"`
}

type indexSource struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Member string `json:"member"`
}

type indexCCI struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func main() {
	cache := flag.String("cache", ".cache/refindex", "download cache directory (git-ignored)")
	out := flag.String("out", "docs/reference/stig", "output directory")
	srcPath := flag.String("sources", "tools/refindex/sources.json", "pinned sources")
	check := flag.Bool("check", false, "exit 1 if the committed files differ instead of writing")
	flag.Parse()
	raw, err := os.ReadFile(*srcPath)
	if err != nil {
		fatal(err)
	}
	var sources []source
	if err := json.Unmarshal(raw, &sources); err != nil {
		fatal(fmt.Errorf("%s: %w", *srcPath, err))
	}
	var cci *cciList
	var cciSHA string
	for _, s := range sources {
		if s.Product == "cci" {
			data, sha, err := fetchMember(*cache, s)
			if err != nil {
				fatal(err)
			}
			if cci, err = parseCCI(data); err != nil {
				fatal(err)
			}
			cciSHA = sha
		}
	}
	if cci == nil {
		fatal(fmt.Errorf("sources.json has no cci entry"))
	}
	stale := false
	for _, s := range sources {
		if s.Product == "cci" {
			continue
		}
		data, _, err := fetchMember(*cache, s)
		if err != nil {
			fatal(err)
		}
		bench, err := parseXCCDF(data)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", s.Product, err))
		}
		got, err := renderIndex(s, bench, cci, cciSHA)
		if err != nil {
			fatal(err)
		}
		path := filepath.Join(*out, s.Product+"-"+strings.ToLower(s.Version)+".json")
		if *check {
			have, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(have, got) {
				fmt.Fprintf(os.Stderr, "refindex: %s is out of date; run: go run ./tools/refindex\n", path)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(*out, 0o755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s (%d rules)\n", path, len(bench.Rules))
	}
	if stale {
		os.Exit(1)
	}
}

// renderIndex joins the parsed benchmark with the CCI list and encodes it
// deterministically.
func renderIndex(s source, b *benchmark, cci *cciList, cciSHA string) ([]byte, error) {
	idx := index{Product: s.Product, AppliesTo: s.AppliesTo, Benchmark: s.Benchmark, Version: s.Version, ReleaseInfo: b.ReleaseInfo,
		Source: indexSource{URL: s.URL, SHA256: s.SHA256, Member: s.Member}, CCIList: indexCCI{Version: cci.Version, SHA256: cciSHA}}
	for _, r := range b.Rules {
		set := map[string]bool{}
		for _, c := range r.CCIs {
			for _, n := range cci.NIST[c] {
				set[n] = true
			}
		}
		r.NIST = make([]string, 0, len(set))
		for n := range set {
			r.NIST = append(r.NIST, n)
		}
		sort.Strings(r.NIST)
		idx.Rules = append(idx.Rules, r)
	}
	if idx.Rules == nil {
		idx.Rules = []xccdfRule{}
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// fetchMember returns the named member of the zip at s.URL, downloading
// into the cache when the cached copy is missing or its digest differs,
// and refusing a downloaded file whose digest does not match the pin.
func fetchMember(cache string, s source) ([]byte, string, error) {
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return nil, "", err
	}
	local := filepath.Join(cache, filepath.Base(s.URL))
	blob, err := os.ReadFile(local)
	if err != nil || digest(blob) != s.SHA256 {
		client := &http.Client{Timeout: 5 * time.Minute}
		resp, err := client.Get(s.URL)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", s.URL, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, "", fmt.Errorf("%s: HTTP %d", s.URL, resp.StatusCode)
		}
		blob, err = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return nil, "", err
		}
		if got := digest(blob); got != s.SHA256 {
			return nil, "", fmt.Errorf("%s: sha256 %s, pinned %s — refusing", s.URL, got, s.SHA256)
		}
		if err := os.WriteFile(local, blob, 0o644); err != nil {
			return nil, "", err
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", local, err)
	}
	for _, f := range zr.File {
		if f.Name == s.Member {
			rc, err := f.Open()
			if err != nil {
				return nil, "", err
			}
			defer rc.Close()
			data, err := io.ReadAll(io.LimitReader(rc, 64<<20))
			return data, s.SHA256, err
		}
	}
	return nil, "", fmt.Errorf("%s: member %s not found", local, s.Member)
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "refindex: %v\n", err)
	os.Exit(2)
}
```

Then: download the four files by running the tool once with placeholder pins? No — the tool refuses a digest mismatch, so first compute the digests: `curl -sL -A Mozilla/5.0 -o .cache/refindex/<name> <url>` for each, `sha256sum` them, write the real digests into `sources.json`, then `go run ./tools/refindex` (it finds the cached files, verifies, and writes the three JSON files). Report the digests and the rule counts (expected 445 / 188 / 194 per the DISA files as of this plan). `.gitignore` gains `/.cache/`. `Makefile` gains `refindex:\n\tgo run ./tools/refindex` and `refindex-check:\n\tgo run ./tools/refindex -check`. CI does not run `refindex` (network dependency); the committed JSON is what lint reads.

- [ ] **Step 4: Run the tests and generate**

Run: `go test ./tools/refindex/ -count=1 -v`; `go run ./tools/refindex` (network, once); `go run ./tools/refindex -check` (exit 0); `jq '.rules | length' docs/reference/stig/rhel9-v2r9.json` → 445; `jq -r '.rules[] | select(.stig_id=="RHEL-09-211010") | .title, (.nist|join(","))' docs/reference/stig/rhel9-v2r9.json` → `RHEL 9 must be a vendor-supported release.` and `CM-6`; `gitleaks` tree scan still clean (titles contain no secret-shaped strings; if the `internal-hostname` rule trips on a title, narrow with an exact-literal allowlist, never a path).

- [ ] **Step 5: Commit**

```bash
git add tools/refindex docs/reference/stig .gitignore Makefile
git commit -m "Generate the STIG and CCI reference index from pinned DISA files"
```

---

### Task 10: `references.stig` in the schema and lint against the index

**Files:**
- Modify: `internal/controls/schema.go` (`STIGRef`, `References.STIG`), `internal/controls/lint.go` (`LintOptions.References`, rules `references_stig`, `references_nist`), `internal/controls/lint_test.go`
- Create: `internal/controls/references.go`, `internal/controls/references_test.go`, `internal/controls/testdata/refs/stig/mini-v1r1.json`
- Modify: `cmd/muster/controls.go` (`--references <dir>`, default `docs/reference`), `cmd/muster/controls_test.go`, `internal/controls/fixtures_test.go` (`TestLintOfEmbeddedSetIsClean` passes `References` loaded from `../../docs/reference`)

**Interfaces:**
- Produces (package `controls`):
  - `type STIGRef struct { Benchmark string `yaml:"benchmark"`; Version string `yaml:"version"`; ID string `yaml:"id"` }` and `References.STIG []STIGRef `yaml:"stig,omitempty"`` — a control writes `stig: [{ benchmark: rhel9, version: V2R9, id: RHEL-09-232010 }]`; `benchmark` is the index's `product` (or one of its `applies_to` names: `rocky9`, `alma9` resolve to `rhel9`).
  - `type ReferenceIndex struct { … }`, `func LoadReferenceIndex(dir string) (*ReferenceIndex, error)` — reads every `dir/stig/*.json`; `func (x *ReferenceIndex) HasSTIG(benchmark, version, id string) bool`; `func (x *ReferenceIndex) HasNIST(id string) bool` (union of every rule's `nist` across products).
  - `LintOptions.References *ReferenceIndex`; rule `references_stig`: each `STIGRef` must resolve (`benchmark` unknown, `version` not the indexed one, or `id` absent are each a problem naming which); rule `references_nist`: each `nist_800_53` entry must match `^[A-Z]{2}-\d+(\(\d+\))?$` and, when an index is loaded, exist in it. With `References == nil` the NIST format check still runs, and the STIG rule reports `references_stig: no reference index loaded` for every control that carries a `stig` reference, so a run without the index cannot pass a control that cites one.
- `muster controls lint --references <dir>` (default `docs/reference`); a missing `<dir>/stig` directory is an error like a missing fixture directory (R35).

- [ ] **Step 1: Write the failing tests**

`internal/controls/testdata/refs/stig/mini-v1r1.json`:

```json
{
  "product": "mini",
  "applies_to": ["mini-clone"],
  "benchmark": "Mini STIG",
  "version": "V1R1",
  "release_info": "Release: 1",
  "source": {"url": "u", "sha256": "s", "member": "m"},
  "cci_list": {"version": "2025-01-23", "sha256": "c"},
  "rules": [
    {"stig_id": "MINI-00-000010", "group_id": "V-000001", "rule_id": "SV-000001r1_rule", "severity": "high", "title": "First rule", "ccis": ["CCI-000366"], "nist": ["CM-6"]},
    {"stig_id": "MINI-00-000020", "group_id": "V-000002", "rule_id": "SV-000002r2_rule", "severity": "medium", "title": "Second rule", "ccis": ["CCI-000068", "CCI-000366"], "nist": ["AC-17(2)", "CM-6"]}
  ]
}
```

`internal/controls/references_test.go`:

```go
package controls

import "testing"

func TestLoadReferenceIndexResolvesProductsAliasesAndNIST(t *testing.T) {
	x, err := LoadReferenceIndex("testdata/refs")
	if err != nil {
		t.Fatal(err)
	}
	if !x.HasSTIG("mini", "V1R1", "MINI-00-000010") {
		t.Error("indexed id must resolve")
	}
	if !x.HasSTIG("mini-clone", "V1R1", "MINI-00-000020") {
		t.Error("an applies_to alias must resolve to its product")
	}
	for _, bad := range [][3]string{{"mini", "V1R2", "MINI-00-000010"}, {"mini", "V1R1", "MINI-00-999999"}, {"other", "V1R1", "MINI-00-000010"}} {
		if x.HasSTIG(bad[0], bad[1], bad[2]) {
			t.Errorf("%v must not resolve", bad)
		}
	}
	if !x.HasNIST("AC-17(2)") || !x.HasNIST("CM-6") || x.HasNIST("AC-99") {
		t.Error("NIST union is wrong")
	}
}

func TestLoadReferenceIndexRejectsAMissingDirectory(t *testing.T) {
	if _, err := LoadReferenceIndex("testdata/does-not-exist"); err == nil {
		t.Error("a missing stig directory must be an error, never an empty index")
	}
}
```

`internal/controls/lint_test.go` — using the file's single-control lint helper, but passing `LintOptions{References: x}` (extend the helper with an options parameter or add a sibling `lintOneWith(t, yaml, opts)`):

```go
func TestLintValidatesSTIGAndNISTReferencesAgainstTheIndex(t *testing.T) {
	x, err := LoadReferenceIndex("testdata/refs")
	if err != nil {
		t.Fatal(err)
	}
	base := `
id: muster.file.ref_test
title_en: t
title_ko: t
description_en: d
description_ko: d
category: file
importance: 하
automation: auto
references:
  kisa: { "2026": ["U-19"] }
  stig: [{ benchmark: mini, version: V1R1, id: MINI-00-000010 }]
  nist_800_53: ["CM-6"]
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: files.etc_hosts.uid, op: eq, expected: 0 }
`
	if probs := lintOneWith(t, base, LintOptions{References: x}); len(probs) != 0 {
		t.Fatalf("valid references must lint clean: %v", probs)
	}
	cases := map[string]string{
		"unknown benchmark": strings.Replace(base, "benchmark: mini", "benchmark: nope", 1),
		"wrong version":     strings.Replace(base, "version: V1R1", "version: V9R9", 1),
		"unknown id":        strings.Replace(base, "MINI-00-000010", "MINI-00-777777", 1),
		"nist not indexed":  strings.Replace(base, `["CM-6"]`, `["AC-99"]`, 1),
		"nist bad format":   strings.Replace(base, `["CM-6"]`, `["cm6"]`, 1),
	}
	for name, y := range cases {
		probs := lintOneWith(t, y, LintOptions{References: x})
		if !hasRule(probs, "references_stig") && !hasRule(probs, "references_nist") {
			t.Errorf("%s: want a references problem, got %v", name, probs)
		}
	}
	if probs := lintOneWith(t, base, LintOptions{References: nil}); !hasRule(probs, "references_stig") {
		t.Errorf("without an index a stig reference must be a problem, got %v", probs)
	}
}
```

`cmd/muster/controls_test.go`: a test that `controls lint --references <tempdir without stig/>` exits 2 with a message naming the directory, and that `--references docs/reference` (from the repository root; the test can `os.Chdir` to `../..` the way the existing lint tests do) succeeds.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controls/ -run 'TestLoadReferenceIndex|TestLintValidatesSTIG' -v` — Expected: FAIL — undefined; and the strict YAML decoder rejects `stig:` as an unknown key until the schema gains it.

- [ ] **Step 3: Implement**

`schema.go`:

```go
type STIGRef struct {
	Benchmark string `yaml:"benchmark"` // index product or one of its applies_to aliases (rhel9, rocky9, alma9, ubuntu2204, ubuntu2404)
	Version   string `yaml:"version"`   // the indexed release, e.g. V2R9
	ID        string `yaml:"id"`        // the STIG id, e.g. RHEL-09-232010
}

type References struct {
	KISA      map[string][]string `yaml:"kisa,omitempty"`
	CIS       []CISRef            `yaml:"cis,omitempty"`
	STIG      []STIGRef           `yaml:"stig,omitempty"`
	ISMSP     []string            `yaml:"isms_p,omitempty"`
	NIST80053 []string            `yaml:"nist_800_53,omitempty"`
}
```

`references.go`:

```go
package controls

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// ReferenceIndex is what tools/refindex generated under docs/reference/stig:
// which STIG ids exist per product and release, and the NIST 800-53 ids
// they map to. Lint accepts only identifiers found here (spec §3).
type ReferenceIndex struct {
	products map[string]string          // product or alias → product
	versions map[string]string          // product → indexed version
	stig     map[string]map[string]bool // product → id set
	nist     map[string]bool
}

var nistIDRe = regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`)

// LoadReferenceIndex reads every dir/stig/*.json. A missing directory or an
// empty one is an error: an index that silently has nothing in it would let
// no reference through, and lint would blame every control.
func LoadReferenceIndex(dir string) (*ReferenceIndex, error) {
	files, err := filepath.Glob(filepath.Join(dir, "stig", "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("reference index: no stig/*.json under %s (run: go run ./tools/refindex)", dir)
	}
	sort.Strings(files)
	x := &ReferenceIndex{products: map[string]string{}, versions: map[string]string{}, stig: map[string]map[string]bool{}, nist: map[string]bool{}}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Product   string   `json:"product"`
			AppliesTo []string `json:"applies_to"`
			Version   string   `json:"version"`
			Rules     []struct {
				StigID string   `json:"stig_id"`
				NIST   []string `json:"nist"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if doc.Product == "" || doc.Version == "" {
			return nil, fmt.Errorf("%s: product and version are required", f)
		}
		x.products[doc.Product] = doc.Product
		for _, a := range doc.AppliesTo {
			x.products[a] = doc.Product
		}
		x.versions[doc.Product] = doc.Version
		ids := map[string]bool{}
		for _, r := range doc.Rules {
			ids[r.StigID] = true
			for _, n := range r.NIST {
				x.nist[n] = true
			}
		}
		x.stig[doc.Product] = ids
	}
	return x, nil
}

// HasSTIG reports whether id exists in the indexed release of benchmark
// (a product name or an applies_to alias).
func (x *ReferenceIndex) HasSTIG(benchmark, version, id string) bool {
	p, ok := x.products[benchmark]
	if !ok || x.versions[p] != version {
		return false
	}
	return x.stig[p][id]
}

// HasNIST reports whether id appears in any indexed rule's NIST mapping.
func (x *ReferenceIndex) HasNIST(id string) bool { return x.nist[id] }

// ValidNISTID is the format check that runs even without an index.
func ValidNISTID(id string) bool { return nistIDRe.MatchString(id) }
```

`lint.go` — `LintOptions` gains `References *ReferenceIndex`; next to the existing `references_cis` loop:

```go
		for _, r := range c.References.STIG {
			switch {
			case r.Benchmark == "" || r.Version == "" || r.ID == "":
				add("references_stig", "stig references need benchmark, version and id")
			case opts.References == nil:
				add("references_stig", "no reference index loaded; %s@%s %s cannot be verified", r.Benchmark, r.Version, r.ID)
			case !opts.References.HasSTIG(r.Benchmark, r.Version, r.ID):
				add("references_stig", "stig reference %s@%s %s is not in docs/reference/stig", r.Benchmark, r.Version, r.ID)
			}
		}
		for _, n := range c.References.NIST80053 {
			if !ValidNISTID(n) {
				add("references_nist", "nist_800_53 reference %q must look like AC-6 or AC-6(10)", n)
				continue
			}
			if opts.References != nil && !opts.References.HasNIST(n) {
				add("references_nist", "nist_800_53 reference %q appears in no indexed STIG rule", n)
			}
		}
```

`cmd/muster/controls.go`: flag `--references <dir>` (default `docs/reference`), loaded with `controls.LoadReferenceIndex`; a load error is printed as `muster: %v` and exits 2 (mirror the fixture-directory handling); passed as `LintOptions{References: idx}`. Usage text gains the flag. `fixtures_test.go`'s `TestLintOfEmbeddedSetIsClean` loads `LoadReferenceIndex("../../docs/reference")` and passes it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/controls/ ./cmd/muster/ -count=1`, `go run ./cmd/muster controls lint` → `ok: 8 controls` (no control cites STIG yet; the index loads). Then prove the negative end to end: temporarily add `stig: [{ benchmark: rhel9, version: V2R9, id: RHEL-09-000000 }]` to `hosts_permissions.yaml`, run lint → a `references_stig` problem naming the id; revert.

- [ ] **Step 5: Commit**

```bash
git add internal/controls/schema.go internal/controls/lint.go internal/controls/lint_test.go internal/controls/references.go internal/controls/references_test.go internal/controls/testdata/refs internal/controls/fixtures_test.go cmd/muster/controls.go cmd/muster/controls_test.go
git commit -m "Validate STIG and NIST references against the generated index"
```

---

### Task 11: Attribution, conventions and the Debian canary

**Files:**
- Modify: `ATTRIBUTION.md` (new section "DISA STIGs and the CCI list"), `CLAUDE.md` (conventions C1/C2, the permission template, the two tools, the cache directory), `README.md` and `README.ko.md` (one sentence each under Standards: the index exists and where), `.github/workflows/ci.yml` (`collect-containers` matrix gains `debian:12` as a canary that may fail)

**Interfaces:**
- Produces: documentation only, plus one CI matrix leg. The canary leg uses `continue-on-error: ${{ matrix.canary == 'true' }}` so a Debian regression is visible without blocking merges (spec §10.2 names `debian:12` as a canary).

- [ ] **Step 1: Write the documents**

`ATTRIBUTION.md`, after the CIS section:

```markdown
## DISA STIGs and the CCI list

- **Publisher:** Defense Information Systems Agency (DISA), United States Department of Defense.
- **Documents:** Canonical Ubuntu 22.04 LTS STIG, Canonical Ubuntu 24.04 LTS STIG, Red Hat Enterprise Linux 9 STIG, and the Control Correlation Identifier (CCI) list, downloaded from https://public.cyber.mil/stigs/ at the releases pinned in `tools/refindex/sources.json`.
- **Status:** works of the United States Government, not subject to copyright in the United States (17 U.S.C. § 105).

**What this repository reproduces:** STIG rule ids (`RHEL-09-…`, `UBTU-22-…`), group ids (`V-…`), rule ids (`SV-…`), severities, rule titles, CCI identifiers and the NIST SP 800-53 control ids the CCI list maps them to, in `docs/reference/stig/`, generated by `tools/refindex` from the pinned files. A control may cite one of these identifiers under `references.stig` and `references.nist_800_53`; lint accepts only identifiers present in the index.

**What it does not reproduce:** STIG check-content, fix text and discussion, and CCI definitions. muster judges its own controls and claims no STIG compliance level; the RHEL 9 STIG is applied to Rocky Linux 9 and AlmaLinux 9 as a documented inference, not a DISA statement.
```

`CLAUDE.md`, a new section:

```markdown
## Stage-2 conventions

- **C1** — `files.*` owns permission facts of a fixed candidate path list (`/etc/passwd`, `/etc/hosts`, …). A path that must be discovered from a daemon's configuration belongs to that daemon's collector.
- **C2** — every leaf a clause judges is its own dotted key; a `record` fact is evidence for `present`/`absent` only. Adding a key or a record field keeps `schema_version` (spec §5.7).
- Permission facts of a fixed path are written by `writePermFacts` in `internal/collect/collectors/permfacts.go`: `mode, uid, gid, group, group_readable, group_writable, other_readable, other_writable, acl_present` (+ `acl_entries` where the control judges the ACL). Register the nine (or ten) leaves per path; a stat failure reaches every leaf.
- "Mode ≤ NNN" is written as `op: in` over the subsets of NNN (there is no bit operator); the default is the guide's value (spec §6.6) and a `params.allowed_modes` relaxes it.
- `go run ./tools/coverage` regenerates `docs/reference/coverage.md`; CI fails when it is stale. `go run ./tools/refindex` regenerates `docs/reference/stig/*.json` from the pinned DISA files (network; cache in `.cache/refindex`, git-ignored); CI only reads the committed index.
- `references.stig` entries are `{benchmark, version, id}`; `benchmark` is `ubuntu2204`, `ubuntu2404`, `rhel9`, `rocky9` or `alma9`; lint rejects anything not in the index.
```

`README.md` (Standards section) one sentence: "The STIG and NIST identifiers a control may cite are generated into `docs/reference/stig/` from DISA's public files by `tools/refindex`; see `ATTRIBUTION.md`." and the Korean equivalent in `README.ko.md`.

CI: in `collect-containers`, add to the matrix `- image: debian:12\n  init: "false"\n  canary: "true"`, give every other entry `canary: "false"`, and set `continue-on-error: ${{ matrix.canary == 'true' }}` on the job. The Debian leg runs the same steps; its `services.*` are `unsupported` (no systemd) like the plain Ubuntu images.

- [ ] **Step 2: Validate**

Run: the YAML parse from the scratch directory (job names + step counts; the matrix now has five entries), `grep -n "/tmp/\|--deep\|include-secrets" .github/workflows/ci.yml` → nothing; `gitleaks` tree scan clean; read the three documents once more for any organisation, host or credential string (none).

- [ ] **Step 3: Commit**

```bash
git add ATTRIBUTION.md CLAUDE.md README.md README.ko.md .github/workflows/ci.yml
git commit -m "Attribute the DISA material, record the stage-2 conventions and add the Debian canary"
```

---

## Self-review

**Spec coverage (stage 2 items of §10.2 that 2A owns):** vocabulary additions `not_matches` and the `facility`/`zone` kinds (T1 ↔ §6.3, §6.4); derivation rows 2–4 (T2 ↔ §6.5); file kind for later enumeration items (T3, used by 2E/2F); the permission-fact shape and the ACL entries that §10.2 names for U-16 (T4–T5, T7); `env.*` gates for later `applies_when` (T6); the coverage table "generated and committed" with a CI check (T8 ↔ §10.2, §11); the reference index, its generator and lint (T9–T10 ↔ §3 as amended); attribution and the `debian:12` canary (T11 ↔ §12, §10.2). Deferred to the plans that first need them: the drop-in merge helper (2C), `list<int>` params if lint lacks it (T7 adds it only if needed), the capability-matrix test and example snapshots (2M).

**Placeholder scan:** the only intentional placeholders are the `<pin>` digests in `sources.json` and the `<the 2021 code …>` in Task 7 — both are values the implementer computes or reads from a committed file and must replace before committing; every code step carries its code.

**Type consistency:** `ReadMeta.Kind`/`Rdev` (T3) are read by nothing in this plan beyond tests (2E/2F consume them); `Access.Getxattr` (T4) is consumed by `aclEntries` (T4) and through it by `writePermFacts` (T5); `permLeaves` (T5) is used by the T5 tests; `env.container`/`env.has_systemd` (T6) are keys, not Go symbols; `render(items []kisaItem, set []controls.Control)` (T8) matches its test; `parseXCCDF`, `parseCCI`, `nistID`, `renderIndex(source, *benchmark, *cciList, string)` (T9) match their tests; `LoadReferenceIndex`, `HasSTIG`, `HasNIST`, `ValidNISTID`, `LintOptions.References` (T10) match `lint_test.go` and `controls.go`.

## Execution notes

Executed 2026-09-03 by subagent-driven development on branch `stage2a-foundations` (17 commits over `a958275`), developed on Windows and tested on a Linux lab host as root (every Linux test, the real-host smoke of the permission facts and the four controls, and the final `-race -shuffle` run happened there; the container legs and the Debian canary are validated by CI). A pre-flight scan found 8 blocking and 20 lesser defects in the task text; where the task text disagreed with the spec or the code it was amended, the spec and the code won. The built result differs from the task text in these ways (ruling numbers refer to the execution ledger; R1–R88 belong to plans 1A and 1B):

- **Lint tests (T1, T7, T10; R89, R97, R104, R114, R117).** Lint tests use the existing `lintOne`/`rules` helpers and every test control that must lint clean carries `remediation`. `list<int>` is a param type (with an every-element-is-an-integer default check); the sub-clause `field` guard stays about fact types, which have no `list<int>`. One named-ACL fixture (`fail-named-acl.json`) replaces `fail-acl.json`; `acl_present` stays written but leaves the passwd checks.
- **Derivation (T2, R101, R108).** The dead `len(AppliesWhen)==0` branch was dropped, the cases are `controls.Control` literals verified by `evidenceHasFact`, and the case names follow the amended §6.5 rows.
- **Access and doubles (T4, R90–R93, R102, R112).** `guardedAccess.Getxattr` uses the one-argument `violate`; `fakeAccess.Getxattr` records the read and the cleaned-path test wants five; `fsAccess` keeps `xattrs` (names) and gains `xattrValues` (values), `stats map[string]statResult{mode, uid, gid, kind}` consulted before the `modes` fallback, and a `truncated` map; `aclEntries` returns `present == true` whenever the attribute was listed, independent of `err`.
- **Permission facts (T5, R92, R100, R103, R109–R111, R116).** `groupNames` returns the read's `ReadMeta`; `writePermFacts` takes `groupMeta` and `groupErr` and builds `<prefix>.group` with `OKRead` (truncation propagates) or with the read's status and a reason prefixed `/etc/group: `; the other leaves never depend on `/etc/group`; a Stat failure reaches every leaf including `acl_entries`; `aclPresent` was deleted. Tests pin the every-leaf propagation, group truncation, an unnamed gid and a duplicate gid.
- **Env facts (T6, R94, R95, R113).** `env.container` is what `containerKind` emits — `none | docker | podman | lxc | other` — with the deciding marker as its source (`/proc/1/comm` for none/other); WSL stays a header bool; `TestOSFillsTheRunHeader` expects exactly the two keys.
- **Controls (T7, R96, R104, R114).** `controls_test.go` expects eight controls; 2021 codes come from `kisa_mapping.json` (U-16←U-07, U-19←U-09, U-22←U-12, U-29←U-55); `hosts_lpd_permissions` carries the inventory's importance `하` (the task text had inherited `상` from the template); README pair names the three new controls.
- **Coverage (T8, R105).** `.PHONY` lists `coverage`; `-check` prints a unified-diff-style message (prefix/suffix trim, no LCS) and exits 1.
- **Reference index (T9, R99, R105, R106, R115, R119).** Pins equal the controller's independently computed digests (RHEL 9 V2R9, Ubuntu 22.04 V2R9, Ubuntu 24.04 V1R6, CCI list 2025-01-23); rule counts 445/188/194; the fetch sends a browser-like User-Agent; a `<Group>` with other than one `<Rule>` is refused; unresolved CCIs are tallied on stderr (0/0/0 today); `-check` needs the cache or the network and therefore never runs in CI. The index stores identifiers, severities and titles only.
- **References and lint (T10, R97, R98, R120).** `--references` is opt-in for the binary (a default of `docs/reference` would fail outside the repository root); without it only the shape of STIG/NIST references is checked; `make lint-controls` and the CI `controls lint` step pass `--references docs/reference`; a missing `stig/` directory is exit 2.
- **Documentation (T11, R106).** One DISA boundary sentence is shared verbatim by `ATTRIBUTION.md` and `NOTICE`; the READMEs point at `ATTRIBUTION.md`; the pin-refresh procedure, the `-check` cache requirement and the NIST normalisation (control id and enhancement only) are recorded.
- **Parked (R118 and the task reviews).** The ACL observation summarises the list ("5 elements") instead of naming the matching entry — check-side list summarisation, for plan 2M's gate; lint's unindexed-id message hardcodes `docs/reference/stig`; `--references ""` degrades to shape-only; the index reader keeps one file per product; `unifiedDiff` in `tools/coverage` has no unit test; `hostAccess.Getxattr` allocates a flat 64 KiB per call.
- **Final review (fable) and the fix wave (R121–R123).** Merge-ready with no blocking finding; one tests-and-docs commit followed: the ACL-failure branch of `writePermFacts` (both leaves `error`, and the listed-but-valueless race) and `tools/refindex`'s digest refusal and cache revalidation are pinned by tests (the fetcher became an injectable package variable), the DISA boundary sentence appears in the READMEs too, the e2e comments count eight controls, and the rule sort is stable on `(StigID, RuleID)`. Two findings carry design weight and are deferred: U-22 admits an owner of root, bin or sys in the guide while `services_permissions` requires uid 0 — widening it needs an owner-name leaf (bin is uid 2 on Debian and 1 on RHEL), which plan 2F adds to the template (R121; stock Ubuntu and Rocky are root-owned, so no false FAIL today); `env.container` and `env.has_systemd` are `ok` even when the deciding marker is unreadable, which the plan that first gates `applies_when` on them decides (R122). The task text's "`--references` (default `docs/reference`)" is superseded by R120. Real-host proof on stock Ubuntu 22.04: collect complete (exit 0), check exit 1 with `hosts_permissions` FAIL (0644), `passwd_permissions`, `services_permissions` and `hosts_lpd_permissions` PASS, `env.container` `none` from `/proc/1/comm`, `env.has_systemd` `true`.
- **Carried forward (spec §10.2, §6.8).** The drop-in merge helper goes to 2C; the lint cross-check of `references.kisa` against the 67-item inventory and an automated importance-vs-inventory check (the R117 class of bug) go to 2M's gate; result ordering is importance-then-id, so `hosts_lpd_permissions` (하) renders last by design.
