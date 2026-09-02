# Stage 1A — check side (facts schema, controls, evaluator, waivers, report, CLI) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build everything in muster that does not need a Linux host — the facts snapshot schema and registry, the control loader and lint, the evaluator with its fixed status derivation, waivers, the JSON and table renderers, the exit-code contract and the `muster check` / `muster controls` commands — so that `muster check --facts <fixture>` runs end to end on the five stage-1 controls with fixtures, on any OS.

**Architecture:** A single Go module with no CLI framework. `internal/facts` owns the snapshot types, the fact envelope and the key registry; `internal/controls` owns the YAML schema, the strict loader and lint; `internal/check` is a pure function `Evaluate(snapshot, set, waivers, params) → results` that imports neither `os/exec` nor `net`; `internal/waiver` loads and matches waiver files; `internal/report` renders results and computes the exit code; `cmd/muster` dispatches. Controls and their fixtures live under `controls/` at the repository root and are embedded. Plan 1B (collect side, Linux only) builds on the same types.

**Tech Stack:** Go 1.25 (`go 1.25` in `go.mod`; CI pins the exact toolchain), `gopkg.in/yaml.v3` (the only direct dependency in this plan), standard library `encoding/json`, `regexp`, `embed`, `testing`.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — sections 4 (architecture), 5 (facts schema), 6 (control format), 7.2 (check errors and exit codes), 9 (output contract), 10.2 (stage 1), 11 (testing), 12 (documentation). Read the spec before starting any task; every task below cites the section it implements.

## Global Constraints

- Module path `github.com/kun9497/muster`; `go 1.25`; no CLI framework; direct dependencies in this plan: `gopkg.in/yaml.v3` only (spec §2 "Language", D28).
- `internal/check` must not import `os/exec`, `net`, or `os` file APIs; it reads only what it is handed (spec §4.2, D06). Task 3 adds the test that enforces it; keep it green.
- Every fact leaf is an envelope `{status, value, source, truncated}`; statuses are exactly `ok | absent | denied | unsupported | timeout | error`, plus the reader-side `missing` that only `check` synthesises (spec §5.2).
- Result statuses are exactly `PASS | FAIL | WARN | MANUAL | NOT_APPLICABLE | ERROR | WAIVED` (spec §6.5). `ERROR` reason codes are exactly `permission_denied | timeout | truncated | unsupported_env | parse_error | missing_fact | schema_mismatch | walk_incomplete | internal_error` (spec §7.2).
- Exit codes: `check` — any `ERROR` → 2 (unless `--allow-error`), else any `FAIL` → 1, else 0; `--fail-on` defaults to `fail` (spec §7.2, D11).
- JSON output is byte-identical for identical input; volatile values live only under `run`; results sorted by severity (`high`, `medium`, `low`) then id (spec §9, D20). Never serialise a Go `map` into output — use structs or sorted slices.
- Result JSON goes to stdout and nothing else does; warnings go to stderr (spec §7.4).
- Control YAML and waiver YAML are decoded strictly (`yaml.v3` `KnownFields(true)`); an unknown key is an error (spec §6.8, §6.7).
- Control text, README and docs are English canonical with Korean pairs; identifiers stay English (spec §12). Never copy KISA guide text or CIS Benchmark text into any file (spec §3, `ATTRIBUTION.md`).
- Commit after every task with the trailer lines used by this repository (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and the `Claude-Session:` line) when Claude authored the change. Never push.
- Windows is a supported development host for this plan: paths in code use `path` for fact keys and `filepath` only for real files; tests must not assume `/`.

---

## File structure

| Path | Responsibility |
|---|---|
| `go.mod`, `go.sum` | module, Go version floor, yaml.v3 |
| `.gitattributes` | `* text=auto eol=lf` so LF is canonical on Windows checkouts |
| `Makefile` | `build`, `test`, `lint`, `fmt`, `tidy`, `lint-controls` |
| `cmd/muster/main.go` | dispatch, exit-code constants, top-level recover guard, `version`, `help` |
| `cmd/muster/check.go` | `check` argument parsing and wiring |
| `cmd/muster/controls.go` | `controls lint` and `controls list` |
| `internal/facts/envelope.go` | `Status`, `Source`, `Envelope`, `Setting` |
| `internal/facts/snapshot.go` | `Snapshot`, `Run` header structs, `Load` with limits and version check |
| `internal/facts/registry.go`, `registry.yaml` | `Registry`, `Entry`, `Lookup`, `Resolve` (synthesises `missing`) |
| `internal/facts/schema_golden_test.go`, `testdata/facts-schema.golden.json` | reflection golden of the `run` header and registry keys |
| `controls/embed.go`, `controls/VERSION` | embedded control set and version |
| `controls/<area>/<name>.yaml` | the five stage-1 controls |
| `controls/testdata/<id>/{pass,fail,na,warn,manual,error}-*.json` | fixtures |
| `internal/controls/schema.go` | `Control`, `Clause`, `ClauseList`, `Mechanism`, `Param`, `Remediation`, `References` |
| `internal/controls/load.go` | `LoadFS`, `LoadDefault`, strict decoding, `Set`, digest |
| `internal/controls/lint.go` | `Lint(set, registry) []Problem` |
| `internal/check/results.go` | `Status`, `Result`, `Observation`, `Evidence`, `ReasonCode` |
| `internal/check/value.go` | typed comparison, regex, param substitution |
| `internal/check/clause.go` | scalar clause evaluation, setting sides, personas |
| `internal/check/collection.go` | `each` / `none` → observations |
| `internal/check/eval.go` | `Evaluate`, the 14-step derivation |
| `internal/check/imports_test.go` | forbidden-import contract test |
| `internal/waiver/waiver.go` | `Load`, `File`, `Match`, `Apply` |
| `internal/report/report.go` | `Report`, `CheckBlock`, `Summary`, severity mapping, sorting |
| `internal/report/json.go` | JSON renderer |
| `internal/report/table.go`, `width.go` | table renderer, escaping, East Asian width |
| `internal/report/exitcode.go` | `ExitCode` |
| `internal/controls/fixtures_test.go` | registry test over all controls and fixtures; result invariants |
| `.github/workflows/ci.yml` | gofmt, vet, staticcheck, `go test -race`, `controls lint`, gitleaks |
| `.gitleaks.toml` | generic secret rules for `testdata/` |
| `CLAUDE.md` | writing rules for tests (spec §11) and repository conventions |
| `THREAT_MODEL.md`, `SECURITY.md` | spec §8 |

Fixture convention (spec §11): a fixture is a partial snapshot JSON — the same shape as a real snapshot (`schema_version`, `run`, `facts`) containing only the keys the control reads. The filename prefix states the expected status: `pass-`, `fail-`, `warn-`, `manual-`, `na-` (NOT_APPLICABLE), `error-`. A fixture may carry a top-level `"_expect": {"reason_code": "...", "exit_code": N}` for finer assertions; `_expect` is stripped before evaluation.

---

### Task 1: Module skeleton, dispatch and the recover guard

**Files:**
- Create: `go.mod`, `.gitattributes`, `Makefile`, `cmd/muster/main.go`, `cmd/muster/main_test.go`

**Interfaces:**
- Produces: `func run(args []string, stdout, stderr io.Writer) int` in package `main`; constants `exitOK = 0`, `exitFindings = 1`, `exitError = 2`; `var version, commit, date = "dev", "none", "unknown"` set by ldflags.

- [ ] **Step 1: Create the module and repository files**

`go.mod`:

```
module github.com/kun9497/muster

go 1.25
```

`.gitattributes`:

```
* text=auto eol=lf
*.png binary
```

`Makefile`:

```makefile
BINARY  := muster
PKG     := ./cmd/muster
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build test lint fmt tidy lint-controls clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test -race ./...

lint:
	gofmt -l . && go vet ./...

lint-controls:
	go run $(PKG) controls lint

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

clean:
	rm -rf bin
```

- [ ] **Step 2: Write the failing test for dispatch and exit codes**

`cmd/muster/main_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersionPrintsThreeFields(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"version"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stderr=%q", code, exitOK, errb.String())
	}
	for _, want := range []string{"muster ", "commit ", "built "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("version output %q lacks %q", out.String(), want)
		}
	}
}

func TestRunUnknownCommandIsExit2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"bogus"}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on error, got %q", out.String())
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("stderr %q lacks 'unknown command'", errb.String())
	}
}

func TestRunNoArgsPrintsHelpAndExits2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "usage:") {
		t.Errorf("stderr %q lacks usage", errb.String())
	}
}

func TestRunRecoversFromPanicWithExit2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"__panic_for_test"}, &out, &errb)
	if code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	if !strings.Contains(errb.String(), "internal error") {
		t.Errorf("stderr %q lacks 'internal error'", errb.String())
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./cmd/muster/ -run TestRun -v`
Expected: FAIL — `undefined: run`, `undefined: exitOK`.

- [ ] **Step 4: Write the minimal main**

`cmd/muster/main.go`:

```go
// Command muster checks whether a Linux server passes muster: collect facts as
// root, then evaluate the snapshot offline against the KISA Unix server items.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes are a CLI contract (spec §7, D11): CI must be able to tell "ran
// and found something" from "could not run or cannot be trusted".
const (
	exitOK       = 0 // completed, nothing at or above the fail-on threshold
	exitFindings = 1 // completed, findings at or above the threshold
	exitError    = 2 // could not run, or the result cannot be trusted
)

// Set by -ldflags at build time (see Makefile).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `usage: muster <command> [flags]

commands:
  check      evaluate a facts snapshot against the embedded controls
  controls   lint or list the embedded controls
  version    print version, commit and build date
  help       print this message
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a command and returns its exit code. It never panics: the
// recover guard turns any panic into exit 2 (spec §7.2), because a crash that
// leaks exit 0 or 1 would break the exit-code contract.
func run(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "muster: internal error: %v\n", r)
			code = exitError
		}
	}()
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "muster %s\ncommit %s\nbuilt %s\n", version, commit, date)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "controls":
		return runControls(args[1:], stdout, stderr)
	case "__panic_for_test":
		panic("deliberate")
	default:
		fmt.Fprintf(stderr, "muster: unknown command %q\n%s", args[0], usage)
		return exitError
	}
}
```

Add temporary stubs so the package compiles (Tasks 13 and 15 replace them):

`cmd/muster/check.go`:

```go
package main

import (
	"fmt"
	"io"
)

func runCheck(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "muster: check is not implemented yet")
	return exitError
}
```

`cmd/muster/controls.go`:

```go
package main

import (
	"fmt"
	"io"
)

func runControls(args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "muster: controls is not implemented yet")
	return exitError
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `gofmt -l . && go vet ./... && go test ./cmd/muster/ -v`
Expected: PASS for all four tests; gofmt prints nothing.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitattributes Makefile cmd/muster/
git commit -m "Add module skeleton, dispatch and exit-code contract"
```

---

### Task 2: Fact envelope, source and setting types

**Files:**
- Create: `internal/facts/envelope.go`, `internal/facts/envelope_test.go`

**Interfaces:**
- Produces (package `facts`):
  - `type Status string` with constants `StatusOK="ok"`, `StatusAbsent="absent"`, `StatusDenied="denied"`, `StatusUnsupported="unsupported"`, `StatusTimeout="timeout"`, `StatusError="error"`, `StatusMissing="missing"`; `func (s Status) Valid() bool` (true for the six collector statuses, false for `missing` and unknown strings); `func (s Status) CanPass() bool` (true only for `ok`).
  - `type Source struct { Kind string; Path string; Line int; Raw string; Cmd string; ExitCode *int; Inputs []Source }` with JSON tags `kind, path, line, raw, cmd, exit_code, inputs` and `omitempty` on all but `kind`.
  - `type Envelope struct { Status Status; Value any; Source *Source; Truncated bool; Reason string }` with JSON tags `status, value, source, truncated, reason`; `omitempty` on all but `status`.
  - `type Setting struct { Runtime, Persisted, Effective *Envelope; Winner *Source }` with JSON tags `runtime, persisted, effective, winner`, all `omitempty`.
  - `func Missing(key string) *Envelope` — returns `{Status: StatusMissing, Reason: "key " + key + " is not present in this snapshot"}`.

- [ ] **Step 1: Write the failing test**

`internal/facts/envelope_test.go`:

```go
package facts

import (
	"encoding/json"
	"testing"
)

func TestStatusValidAndCanPass(t *testing.T) {
	cases := []struct {
		s       Status
		valid   bool
		canPass bool
	}{
		{StatusOK, true, true},
		{StatusAbsent, true, false},
		{StatusDenied, true, false},
		{StatusUnsupported, true, false},
		{StatusTimeout, true, false},
		{StatusError, true, false},
		{StatusMissing, false, false},
		{Status("bogus"), false, false},
	}
	for _, c := range cases {
		if got := c.s.Valid(); got != c.valid {
			t.Errorf("%q.Valid()=%v want %v", c.s, got, c.valid)
		}
		if got := c.s.CanPass(); got != c.canPass {
			t.Errorf("%q.CanPass()=%v want %v", c.s, got, c.canPass)
		}
	}
}

func TestEnvelopeJSONRoundTripKeepsFieldOrderAndOmitsEmpty(t *testing.T) {
	code := 0
	e := Envelope{
		Status: StatusOK,
		Value:  "no",
		Source: &Source{Kind: "file", Path: "/etc/ssh/sshd_config", Line: 2, Raw: "PermitRootLogin no", ExitCode: &code},
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"status":"ok","value":"no","source":{"kind":"file","path":"/etc/ssh/sshd_config","line":2,"raw":"PermitRootLogin no","exit_code":0}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	var back Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Status != StatusOK || back.Value != "no" || back.Source.Line != 2 || *back.Source.ExitCode != 0 {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestDerivedSourceCarriesInputs(t *testing.T) {
	s := Source{Kind: "derived", Inputs: []Source{{Kind: "file", Path: "/etc/sysctl.d/99-a.conf", Line: 3}}}
	b, _ := json.Marshal(s)
	want := `{"kind":"derived","inputs":[{"kind":"file","path":"/etc/sysctl.d/99-a.conf","line":3}]}`
	if string(b) != want {
		t.Fatalf("got %s want %s", b, want)
	}
}

func TestSettingOmitsAbsentSides(t *testing.T) {
	s := Setting{Effective: &Envelope{Status: StatusOK, Value: "no"}}
	b, _ := json.Marshal(s)
	if string(b) != `{"effective":{"status":"ok","value":"no"}}` {
		t.Fatalf("got %s", b)
	}
}

func TestMissingEnvelope(t *testing.T) {
	m := Missing("sshd.options.permit_root_login")
	if m.Status != StatusMissing || m.Reason == "" {
		t.Fatalf("got %+v", m)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/facts/ -v`
Expected: FAIL — package does not exist / undefined identifiers.

- [ ] **Step 3: Write the types**

`internal/facts/envelope.go`:

```go
// Package facts defines the snapshot that collect writes and check reads:
// the run header, the fact envelope, two-home settings and the key registry
// (spec §5).
package facts

// Status is the collection status of one fact. The six collector statuses are
// written by collect; StatusMissing exists only on the reading side and is
// synthesised by check for a registered key the snapshot does not carry
// (spec §5.2, D07).
type Status string

const (
	StatusOK          Status = "ok"
	StatusAbsent      Status = "absent"      // the collector looked; the thing does not exist
	StatusDenied      Status = "denied"      // insufficient privilege; Reason names it
	StatusUnsupported Status = "unsupported" // this distribution or environment has no such mechanism
	StatusTimeout     Status = "timeout"
	StatusError       Status = "error"
	StatusMissing     Status = "missing" // reader-side only; never written by collect
)

// Valid reports whether s is one of the six statuses a collector may write.
func (s Status) Valid() bool {
	switch s {
	case StatusOK, StatusAbsent, StatusDenied, StatusUnsupported, StatusTimeout, StatusError:
		return true
	}
	return false
}

// CanPass reports whether a clause over a fact with this status may produce
// PASS. Only "ok" can; everything else is decided by the derivation table
// (spec §6.5) and never reaches a clause.
func (s Status) CanPass() bool { return s == StatusOK }

// Source says where a value came from (spec §5.2, D08). For Kind "derived",
// Path and Line are empty and Inputs lists every source the value was
// computed from, in evaluation order.
type Source struct {
	Kind     string   `json:"kind"` // file | command | proc | sys | derived
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Raw      string   `json:"raw,omitempty"` // the source line itself, length-capped by the collector
	Cmd      string   `json:"cmd,omitempty"`
	ExitCode *int     `json:"exit_code,omitempty"`
	Inputs   []Source `json:"inputs,omitempty"`
}

// Envelope is every leaf under "facts" (spec §5.2). Value is nil unless
// Status is "ok"; its Go type after JSON decoding is string, float64, bool,
// []any or map[string]any, and the registry entry says which is expected.
type Envelope struct {
	Status    Status  `json:"status"`
	Value     any     `json:"value,omitempty"`
	Source    *Source `json:"source,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Reason    string  `json:"reason,omitempty"` // required privilege, limit hit, or error text
}

// Setting is a value that lives both in the running kernel or daemon and in
// a persisted file (spec §5.3, D10). The sides are selected only by a
// clause's `on:`; no fact key contains a side name.
type Setting struct {
	Runtime   *Envelope `json:"runtime,omitempty"`
	Persisted *Envelope `json:"persisted,omitempty"`
	Effective *Envelope `json:"effective,omitempty"`
	Winner    *Source   `json:"winner,omitempty"`
}

// Missing builds the reader-side envelope for a registered key the snapshot
// does not carry. It is never resolved by absent_means and always yields
// ERROR(missing_fact) (spec §5.2, §5.7).
func Missing(key string) *Envelope {
	return &Envelope{Status: StatusMissing, Reason: "key " + key + " is not present in this snapshot"}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/facts/ -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/facts/
git commit -m "Add fact envelope, source and setting types"
```

---

### Task 3: Snapshot types, `Load` with limits and the schema-version rule

**Files:**
- Create: `internal/facts/snapshot.go`, `internal/facts/snapshot_test.go`, `internal/check/imports_test.go`

**Interfaces:**
- Produces (package `facts`):
  - `const SchemaVersion = 1`
  - `type Host struct { Hostname, MachineIDHash, Kernel string; OSRelease OSRelease; BootID string; UptimeS int64 }` (tags `hostname, machine_id_hash, kernel, os_release, boot_id, uptime_s`); `type OSRelease struct { ID, VersionID, Family string }` (tags `id, version_id, family`).
  - `type Env struct { Container string; Virt string; WSL, Chroot, HasSystemd, SysctlWritable, CloudInit bool }` (tags `container, virt, wsl, chroot, has_systemd, sysctl_writable, cloud_init`).
  - `type CollectorRun struct { Name, Status string; Ms int64; Cmd, Reason string }` (tags `name, status, ms, cmd, reason`; `omitempty` on cmd/reason).
  - `type Redaction struct { Profile string; IncludeSecrets bool; RedactedFields []string }` (tags `profile, include_secrets, redacted_fields`).
  - `type Run struct { MusterVersion, Commit, ControlsVersion, ControlsDigest, GuideEdition, CollectedAt string; Host Host; EUID int; Capabilities []string; Env Env; Collectors []CollectorRun; Redaction Redaction; Deep, Complete bool; PartialFailures []string }` (tags as in spec §5.1: `muster_version, commit, controls_version, controls_digest, guide_edition, collected_at, host, euid, capabilities, env, collectors, redaction, deep, complete, partial_failures`).
  - `type Snapshot struct { SchemaVersion int; Run Run; Facts map[string]any }` (tags `schema_version, run, facts`).
  - `var ErrSchemaMismatch = errors.New("schema_mismatch")`; `var ErrTooLarge = errors.New("snapshot exceeds size limit")`; `var ErrTooDeep = errors.New("snapshot exceeds nesting limit")`.
  - `const MaxSnapshotBytes = 64 << 20`, `const MaxDepth = 32`.
  - `func Load(r io.Reader) (*Snapshot, error)` — reads at most `MaxSnapshotBytes`+1 (error if exceeded), decodes, rejects `schema_version > SchemaVersion` with an error wrapping `ErrSchemaMismatch`, rejects nesting deeper than `MaxDepth` with `ErrTooDeep`, rejects `schema_version < 1`.
  - `func (s *Snapshot) Digest() string` — `sha256:` + hex of the canonical re-encoding (`json.Marshal` of the struct).

- [ ] **Step 1: Write the failing tests**

`internal/facts/snapshot_test.go`:

```go
package facts

import (
	"errors"
	"strings"
	"testing"
)

const minimalSnapshot = `{
  "schema_version": 1,
  "run": {"muster_version": "0.1.0", "collected_at": "2026-09-02T06:00:00Z",
          "host": {"hostname": "web-01", "os_release": {"id": "rocky", "version_id": "9.4", "family": "rhel"}},
          "euid": 0, "env": {"container": "none", "has_systemd": true}, "complete": true},
  "facts": {"services": {"ssh": {"installed": {"status": "ok", "value": true}}}}
}`

func TestLoadMinimalSnapshot(t *testing.T) {
	s, err := Load(strings.NewReader(minimalSnapshot))
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 1 || s.Run.Host.Hostname != "web-01" || !s.Run.Complete {
		t.Errorf("decoded badly: %+v", s.Run)
	}
	if _, ok := s.Facts["services"]; !ok {
		t.Errorf("facts tree lost: %v", s.Facts)
	}
}

func TestLoadRefusesHigherSchemaVersion(t *testing.T) {
	_, err := Load(strings.NewReader(`{"schema_version": 99, "run": {}, "facts": {}}`))
	if !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("err=%v, want ErrSchemaMismatch", err)
	}
}

func TestLoadRefusesZeroOrMissingSchemaVersion(t *testing.T) {
	for _, in := range []string{`{"run": {}, "facts": {}}`, `{"schema_version": 0, "run": {}, "facts": {}}`} {
		if _, err := Load(strings.NewReader(in)); !errors.Is(err, ErrSchemaMismatch) {
			t.Errorf("%s: err=%v, want ErrSchemaMismatch", in, err)
		}
	}
}

func TestLoadRefusesOversizedInput(t *testing.T) {
	big := `{"schema_version":1,"run":{},"facts":{"pad":"` + strings.Repeat("x", MaxSnapshotBytes) + `"}}`
	if _, err := Load(strings.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err=%v, want ErrTooLarge", err)
	}
}

func TestLoadRefusesDeepNesting(t *testing.T) {
	deep := `{"schema_version":1,"run":{},"facts":` + strings.Repeat(`{"a":`, MaxDepth+2) + `1` + strings.Repeat(`}`, MaxDepth+2) + `}`
	if _, err := Load(strings.NewReader(deep)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("err=%v, want ErrTooDeep", err)
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	if _, err := Load(strings.NewReader(`{"schema_version": 1,`)); err == nil {
		t.Fatal("malformed JSON must fail")
	}
}

func TestDigestIsStableAndPrefixed(t *testing.T) {
	a, _ := Load(strings.NewReader(minimalSnapshot))
	b, _ := Load(strings.NewReader(minimalSnapshot))
	if a.Digest() != b.Digest() || !strings.HasPrefix(a.Digest(), "sha256:") {
		t.Fatalf("digests %q %q", a.Digest(), b.Digest())
	}
}
```

`internal/check/imports_test.go` (the package is created here so the contract exists before any evaluator code; spec §4.2, §11):

```go
package check

import (
	"os/exec"
	"strings"
	"testing"
)

// Forbidden imports make check impure: it must be a function of the snapshot,
// the control set, the waivers and the parameters, and nothing on the host
// (spec §4.2, D06). Direct and transitive dependencies are both checked.
func TestCheckPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/kun9497/muster/internal/check").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	forbidden := []string{"os/exec", "net", "net/http", "syscall", "golang.org/x/sys"}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, f := range forbidden {
			if dep == f || strings.HasPrefix(dep, f+"/") {
				t.Errorf("internal/check depends on forbidden package %s", dep)
			}
		}
	}
}
```

Also create `internal/check/doc.go` so the package compiles:

```go
// Package check evaluates a facts snapshot against a control set. It is a
// pure function of its inputs (spec §4.2, D06): no host access of any kind.
package check
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/facts/ ./internal/check/ -v`
Expected: `facts` FAILs on undefined `Load`; `check` PASSes (nothing forbidden yet) — keep it, it is the guard.

- [ ] **Step 3: Write `snapshot.go`**

```go
package facts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SchemaVersion is the facts schema this binary writes and the highest it
// reads (spec §5.7, D17).
const SchemaVersion = 1

// Limits applied before decoding untrusted input (spec §7.2).
const (
	MaxSnapshotBytes = 64 << 20
	MaxDepth         = 32
)

var (
	ErrSchemaMismatch = errors.New("schema_mismatch")
	ErrTooLarge       = errors.New("snapshot exceeds size limit")
	ErrTooDeep        = errors.New("snapshot exceeds nesting limit")
)

type OSRelease struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Family    string `json:"family"` // debian | rhel | unknown
}

type Host struct {
	Hostname      string    `json:"hostname"`
	MachineIDHash string    `json:"machine_id_hash"`
	Kernel        string    `json:"kernel"`
	OSRelease     OSRelease `json:"os_release"`
	BootID        string    `json:"boot_id"`
	UptimeS       int64     `json:"uptime_s"`
}

type Env struct {
	Container      string `json:"container"` // none | docker | podman | lxc | other
	Virt           string `json:"virt"`      // none | kvm | vmware | ... | unknown
	WSL            bool   `json:"wsl"`
	Chroot         bool   `json:"chroot"`
	HasSystemd     bool   `json:"has_systemd"`
	SysctlWritable bool   `json:"sysctl_writable"`
	CloudInit      bool   `json:"cloud_init"`
}

type CollectorRun struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | denied | timeout | error | skipped
	Ms     int64  `json:"ms"`
	Cmd    string `json:"cmd,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Redaction struct {
	Profile        string   `json:"profile"` // default | none
	IncludeSecrets bool     `json:"include_secrets"`
	RedactedFields []string `json:"redacted_fields,omitempty"`
}

// Run is the provenance header (spec §5.1).
type Run struct {
	MusterVersion   string         `json:"muster_version"`
	Commit          string         `json:"commit"`
	ControlsVersion string         `json:"controls_version"`
	ControlsDigest  string         `json:"controls_digest"`
	GuideEdition    string         `json:"guide_edition"`
	CollectedAt     string         `json:"collected_at"`
	Host            Host           `json:"host"`
	EUID            int            `json:"euid"`
	Capabilities    []string       `json:"capabilities"`
	Env             Env            `json:"env"`
	Collectors      []CollectorRun `json:"collectors"`
	Redaction       Redaction      `json:"redaction"`
	Deep            bool           `json:"deep"`
	Complete        bool           `json:"complete"`
	PartialFailures []string       `json:"partial_failures"`
}

// Snapshot is one facts file. Facts is the decoded JSON tree; leaves are
// resolved through the Registry (Task 4) so check never walks raw paths.
type Snapshot struct {
	SchemaVersion int            `json:"schema_version"`
	Run           Run            `json:"run"`
	Facts         map[string]any `json:"facts"`
}

// Load reads and validates a snapshot from untrusted input (spec §7.2): size
// and nesting limits first, then the schema-version rule.
func Load(r io.Reader) (*Snapshot, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSnapshotBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if len(data) > MaxSnapshotBytes {
		return nil, ErrTooLarge
	}
	if err := checkDepth(data, MaxDepth); err != nil {
		return nil, err
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	if s.SchemaVersion < 1 {
		return nil, fmt.Errorf("%w: snapshot has no valid schema_version", ErrSchemaMismatch)
	}
	if s.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: snapshot schema_version %d is newer than this binary supports (%d)", ErrSchemaMismatch, s.SchemaVersion, SchemaVersion)
	}
	if s.Facts == nil {
		s.Facts = map[string]any{}
	}
	return &s, nil
}

// checkDepth walks the token stream and rejects nesting beyond max without
// building the tree, so a hostile input cannot exhaust memory first.
func checkDepth(data []byte, max int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse snapshot: %w", err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > max {
					return ErrTooDeep
				}
			case '}', ']':
				depth--
			}
		}
	}
}

// Digest is the sha256 of the canonical re-encoding, reported by check so a
// result names the exact snapshot it was computed from (spec §9).
func (s *Snapshot) Digest() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/facts/ ./internal/check/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/facts/snapshot.go internal/facts/snapshot_test.go internal/check/
git commit -m "Add snapshot types, Load with limits, and the check import contract"
```

---

### Task 4: Key registry and `Resolve` (synthesising `missing`)

**Files:**
- Create: `internal/facts/registry.go`, `internal/facts/registry.yaml`, `internal/facts/registry_test.go`
- Modify: `go.mod` (add `gopkg.in/yaml.v3`)

**Interfaces:**
- Produces (package `facts`):
  - `type Entry struct { Key, Type, Description string; Since int; Sensitivity, Collector, DefaultOn, SubjectKind string }` (yaml tags `key, type, description, since, sensitivity, collector, default_on, subject_kind`).
  - `type Registry struct { SchemaVersion int; Keys []Entry }` plus an unexported index.
  - `func LoadRegistry() (*Registry, error)` — parses the embedded `registry.yaml` strictly; errors on duplicate keys, unknown `type`, unknown `sensitivity`, a `default_on` on a non-setting type, or a `subject_kind` on a non-list type.
  - `func (r *Registry) Lookup(key string) (Entry, bool)`.
  - `func (r *Registry) IsSetting(e Entry) bool` — true when `Type` starts with `setting<`.
  - `type Resolved struct { Entry Entry; Envelope *Envelope; Setting *Setting }`.
  - `func (r *Registry) Resolve(s *Snapshot, key string) (Resolved, error)` — error `ErrUnregistered` if the key is not in the registry; otherwise walks `s.Facts` by dotted path; if the leaf is absent → `Envelope: Missing(key)`; if the entry is a setting, decodes the leaf into `Setting` (each present side must be an envelope) else into `Envelope`; a leaf that is not an object with `status` (or a setting object) → `Envelope{Status: StatusError, Reason: "malformed fact"}`.
  - `var ErrUnregistered = errors.New("fact key is not registered")`.
- Registry contents for stage 1 (exact keys; later tasks reference them):

| key | type | sensitivity | collector | default_on / subject_kind |
|---|---|---|---|---|
| `services.ssh.installed` | bool | public | services | |
| `services.ssh.active` | bool | public | services | |
| `services.telnet.installed` | bool | public | services | |
| `services.telnet.reachable` | bool | public | services | |
| `sockets.listening` | list<record> | internal | sockets | subject_kind `port` |
| `sshd.collect_method` | string | public | sshd | |
| `sshd.personas_collected` | bool | public | sshd | |
| `sshd.options.permit_root_login` | setting<string> | public | sshd | default_on `effective` |
| `files.etc_securetty` | record | public | files | |
| `files.etc_securetty.lines` | list<string> | public | files | |
| `files.etc_passwd.mode` | int | public | files | |
| `files.etc_passwd.uid` | int | public | files | |
| `files.etc_passwd.gid` | int | public | files | |
| `files.etc_passwd.acl_present` | bool | public | files | |
| `accounts.login_defs.pass_max_days` | setting<int> | public | accounts | default_on `both` |
| `accounts.login_defs.pass_min_days` | setting<int> | public | accounts | default_on `both` |
| `accounts.login_defs.pass_min_len` | int | public | accounts | |
| `accounts.users` | list<record> | internal | accounts | subject_kind `user` |
| `walk.world_writable` | list<record> | internal | walk | subject_kind `file` |
| `walk.complete` | bool | public | walk | |

- [ ] **Step 1: Write the failing tests**

`internal/facts/registry_test.go`:

```go
package facts

import (
	"errors"
	"strings"
	"testing"
)

func TestRegistryLoadsAndIndexesKeys(t *testing.T) {
	r, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	e, ok := r.Lookup("sshd.options.permit_root_login")
	if !ok {
		t.Fatal("key not found")
	}
	if e.Type != "setting<string>" || e.DefaultOn != "effective" || !r.IsSetting(e) {
		t.Errorf("entry %+v", e)
	}
	if _, ok := r.Lookup("nope.nothing"); ok {
		t.Error("unregistered key must not resolve")
	}
	for _, e := range r.Keys {
		if e.Since < 1 || e.Sensitivity == "" || e.Collector == "" || e.Description == "" {
			t.Errorf("entry %q is incomplete: %+v", e.Key, e)
		}
	}
}

func TestResolveEnvelopeSettingAndMissing(t *testing.T) {
	r, _ := LoadRegistry()
	s, err := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{
	  "services": {"ssh": {"installed": {"status":"ok","value":true}}},
	  "sshd": {"options": {"permit_root_login": {
	      "runtime": {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}},
	      "effective": {"status":"ok","value":"no"}}}}
	}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Resolve(s, "services.ssh.installed")
	if err != nil || got.Envelope == nil || got.Envelope.Status != StatusOK || got.Envelope.Value != true {
		t.Fatalf("envelope: %+v err=%v", got, err)
	}
	got, err = r.Resolve(s, "sshd.options.permit_root_login")
	if err != nil || got.Setting == nil || got.Setting.Effective.Value != "no" || got.Setting.Persisted != nil {
		t.Fatalf("setting: %+v err=%v", got, err)
	}
	got, err = r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope == nil || got.Envelope.Status != StatusMissing {
		t.Fatalf("missing: %+v err=%v", got, err)
	}
	if _, err := r.Resolve(s, "not.registered"); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("err=%v want ErrUnregistered", err)
	}
}

func TestResolveMalformedLeafIsError(t *testing.T) {
	r, _ := LoadRegistry()
	s, _ := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk":{"complete": true}}}`))
	got, err := r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope.Status != StatusError || !strings.Contains(got.Envelope.Reason, "malformed") {
		t.Fatalf("%+v err=%v", got, err)
	}
}

func TestResolveMissingWhenIntermediateIsNotObject(t *testing.T) {
	r, _ := LoadRegistry()
	s, _ := Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":{"walk": 5}}`))
	got, err := r.Resolve(s, "walk.complete")
	if err != nil || got.Envelope.Status != StatusMissing {
		t.Fatalf("%+v err=%v", got, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/facts/ -run 'TestRegistry|TestResolve' -v`
Expected: FAIL — undefined `LoadRegistry`, `Resolve`.

- [ ] **Step 3: Add the dependency and write the registry**

Run: `go get gopkg.in/yaml.v3@v3.0.1 && go mod tidy`

`internal/facts/registry.yaml` (every key stage 1 references; descriptions are muster's own words):

```yaml
schema_version: 1
keys:
  - key: services.ssh.installed
    type: bool
    description: An SSH server package or unit exists on the host.
    since: 1
    sensitivity: public
    collector: services
  - key: services.ssh.active
    type: bool
    description: The SSH service is running or socket-activated.
    since: 1
    sensitivity: public
    collector: services
  - key: services.telnet.installed
    type: bool
    description: A telnet server package, unit or inetd entry exists on the host.
    since: 1
    sensitivity: public
    collector: services
  - key: services.telnet.reachable
    type: bool
    description: A telnet server would accept a connection from off the host (active unit or listening socket unit, non-loopback).
    since: 1
    sensitivity: public
    collector: services
  - key: sockets.listening
    type: list<record>
    description: Listening TCP/UDP sockets with proto, address, port, inode, pid and executable.
    since: 1
    sensitivity: internal
    collector: sockets
    subject_kind: port
  - key: sshd.collect_method
    type: string
    description: How sshd options were obtained - G, T or parse.
    since: 1
    sensitivity: public
    collector: sshd
  - key: sshd.personas_collected
    type: bool
    description: Whether per-persona (Match) values were collected; false means options hold global values only.
    since: 1
    sensitivity: public
    collector: sshd
  - key: sshd.options.permit_root_login
    type: setting<string>
    description: Effective PermitRootLogin value (daemon-reported versus parsed files).
    since: 1
    sensitivity: public
    collector: sshd
    default_on: effective
  - key: files.etc_securetty
    type: record
    description: Presence and permission facts of /etc/securetty (absent on RHEL 8+ and Debian-family).
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_securetty.lines
    type: list<string>
    description: Non-comment lines of /etc/securetty.
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_passwd.mode
    type: int
    description: Permission bits of /etc/passwd as an integer (e.g. 420 for 0644).
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_passwd.uid
    type: int
    description: Owner uid of /etc/passwd.
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_passwd.gid
    type: int
    description: Group gid of /etc/passwd.
    since: 1
    sensitivity: public
    collector: files
  - key: files.etc_passwd.acl_present
    type: bool
    description: Whether a POSIX ACL xattr is present on /etc/passwd.
    since: 1
    sensitivity: public
    collector: files
  - key: accounts.login_defs.pass_max_days
    type: setting<int>
    description: PASS_MAX_DAYS - persisted in login.defs, effective as the maximum over existing accounts' shadow fields.
    since: 1
    sensitivity: public
    collector: accounts
    default_on: both
  - key: accounts.login_defs.pass_min_days
    type: setting<int>
    description: PASS_MIN_DAYS - persisted in login.defs, effective as the minimum over existing accounts' shadow fields.
    since: 1
    sensitivity: public
    collector: accounts
    default_on: both
  - key: accounts.login_defs.pass_min_len
    type: int
    description: PASS_MIN_LEN from login.defs (ignored by PAM when pwquality is present; stage 2 adds the pwquality side).
    since: 1
    sensitivity: public
    collector: accounts
  - key: accounts.users
    type: list<record>
    description: Local accounts with name, uid, gid, shell, password_status and ageing fields; no hashes.
    since: 1
    sensitivity: internal
    collector: accounts
    subject_kind: user
  - key: walk.world_writable
    type: list<record>
    description: World-writable files found by the deep walk, with path, sticky, uid, gid, package_declared.
    since: 1
    sensitivity: internal
    collector: walk
    subject_kind: file
  - key: walk.complete
    type: bool
    description: Whether the deep walk finished within its budget.
    since: 1
    sensitivity: public
    collector: walk
```

`internal/facts/registry.go`:

```go
package facts

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed registry.yaml
var registryYAML []byte

// ErrUnregistered is returned by Resolve for a key no control may reference
// (spec §5.5).
var ErrUnregistered = errors.New("fact key is not registered")

// Entry describes one key a control may reference (spec §5.5).
type Entry struct {
	Key         string `yaml:"key"`
	Type        string `yaml:"type"` // string | int | bool | list<string> | record | list<record> | setting<T>
	Description string `yaml:"description"`
	Since       int    `yaml:"since"`
	Sensitivity string `yaml:"sensitivity"`  // public | internal | secret
	Collector   string `yaml:"collector"`
	DefaultOn   string `yaml:"default_on,omitempty"`   // settings only: runtime | persisted | effective | both
	SubjectKind string `yaml:"subject_kind,omitempty"` // list types only: file | dir | user | group | unit | port | module | mount | key
}

// Registry is the single truth for fact keys, their types and sensitivity.
type Registry struct {
	SchemaVersion int     `yaml:"schema_version"`
	Keys          []Entry `yaml:"keys"`
	byKey         map[string]Entry
}

var validTypes = map[string]bool{"string": true, "int": true, "bool": true, "list<string>": true, "record": true, "list<record>": true}
var validSensitivity = map[string]bool{"public": true, "internal": true, "secret": true}
var validOn = map[string]bool{"runtime": true, "persisted": true, "effective": true, "both": true}
var validSubjectKind = map[string]bool{"file": true, "dir": true, "user": true, "group": true, "unit": true, "port": true, "module": true, "mount": true, "key": true}

// LoadRegistry parses the embedded registry strictly and validates it.
func LoadRegistry() (*Registry, error) {
	var r Registry
	dec := yaml.NewDecoder(bytes.NewReader(registryYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry.yaml: %w", err)
	}
	r.byKey = make(map[string]Entry, len(r.Keys))
	for _, e := range r.Keys {
		if _, dup := r.byKey[e.Key]; dup {
			return nil, fmt.Errorf("registry.yaml: duplicate key %q", e.Key)
		}
		isSetting := strings.HasPrefix(e.Type, "setting<") && strings.HasSuffix(e.Type, ">")
		inner := e.Type
		if isSetting {
			inner = strings.TrimSuffix(strings.TrimPrefix(e.Type, "setting<"), ">")
		}
		if !validTypes[inner] {
			return nil, fmt.Errorf("registry.yaml: key %q has unknown type %q", e.Key, e.Type)
		}
		if !validSensitivity[e.Sensitivity] {
			return nil, fmt.Errorf("registry.yaml: key %q has unknown sensitivity %q", e.Key, e.Sensitivity)
		}
		if e.DefaultOn != "" && (!isSetting || !validOn[e.DefaultOn]) {
			return nil, fmt.Errorf("registry.yaml: key %q: default_on %q is only valid on a setting type", e.Key, e.DefaultOn)
		}
		if isSetting && e.DefaultOn == "" {
			return nil, fmt.Errorf("registry.yaml: setting key %q needs default_on", e.Key)
		}
		if e.SubjectKind != "" && (!strings.HasPrefix(e.Type, "list<") || !validSubjectKind[e.SubjectKind]) {
			return nil, fmt.Errorf("registry.yaml: key %q: subject_kind %q is only valid on a list type", e.Key, e.SubjectKind)
		}
		if e.Since < 1 {
			return nil, fmt.Errorf("registry.yaml: key %q needs since >= 1", e.Key)
		}
		r.byKey[e.Key] = e
	}
	return &r, nil
}

// Lookup returns the entry for key.
func (r *Registry) Lookup(key string) (Entry, bool) {
	e, ok := r.byKey[key]
	return e, ok
}

// IsSetting reports whether e is a two-home setting (spec §5.3).
func (r *Registry) IsSetting(e Entry) bool { return strings.HasPrefix(e.Type, "setting<") }

// Resolved is the outcome of looking a key up in a snapshot: exactly one of
// Envelope or Setting is set.
type Resolved struct {
	Entry    Entry
	Envelope *Envelope
	Setting  *Setting
}

// Resolve looks key up in s. A registered key the snapshot does not carry
// resolves to a "missing" envelope (spec §5.2); an unregistered key is an
// error, because controls may reference registered keys only (spec §5.5).
func (r *Registry) Resolve(s *Snapshot, key string) (Resolved, error) {
	e, ok := r.byKey[key]
	if !ok {
		return Resolved{}, fmt.Errorf("%w: %s", ErrUnregistered, key)
	}
	leaf, found := walk(s.Facts, strings.Split(key, "."))
	if !found {
		return Resolved{Entry: e, Envelope: Missing(key)}, nil
	}
	obj, isObj := leaf.(map[string]any)
	if !isObj {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: leaf is not an object"}}, nil
	}
	raw, _ := json.Marshal(obj)
	if r.IsSetting(e) {
		var st Setting
		if err := json.Unmarshal(raw, &st); err != nil || (st.Runtime == nil && st.Persisted == nil && st.Effective == nil) {
			return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: setting has no sides"}}, nil
		}
		return Resolved{Entry: e, Setting: &st}, nil
	}
	if _, hasStatus := obj["status"]; !hasStatus {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: no status"}}, nil
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Resolved{Entry: e, Envelope: &Envelope{Status: StatusError, Reason: "malformed fact: " + err.Error()}}, nil
	}
	return Resolved{Entry: e, Envelope: &env}, nil
}

// walk descends a decoded JSON tree by path segments. A segment that lands on
// a non-object before the last step means the key is not present.
func walk(tree map[string]any, segs []string) (any, bool) {
	var cur any = tree
	for _, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/facts/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/facts/registry.go internal/facts/registry.yaml internal/facts/registry_test.go
git commit -m "Add the fact key registry and Resolve with reader-side missing"
```

---

### Task 5: Reflection schema golden

**Files:**
- Create: `internal/facts/schema_golden_test.go`, `internal/facts/testdata/facts-schema.golden.json`

**Interfaces:**
- Consumes: `Run`, `Registry` from Tasks 3–4.
- Produces: a golden file that changes whenever a `run` field or a registry key is added, removed or retyped, so the reviewer sees the schema change (spec §5.7, §11).

- [ ] **Step 1: Write the golden test with an `-update` flag**

`internal/facts/schema_golden_test.go`:

```go
package facts

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

type fieldDesc struct {
	JSON string `json:"json"`
	Type string `json:"type"`
}

type schemaDesc struct {
	SchemaVersion int                    `json:"schema_version"`
	Run           map[string][]fieldDesc `json:"run"` // struct name → fields
	Keys          []Entry                `json:"keys"`
}

func describe(t reflect.Type, into map[string][]fieldDesc) {
	if t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || into[t.Name()] != nil {
		return
	}
	var fields []fieldDesc
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		fields = append(fields, fieldDesc{JSON: tag, Type: f.Type.String()})
		describe(f.Type, into)
	}
	into[t.Name()] = fields
}

// The golden changes whenever the run header or the registry changes shape,
// which forces the author through the versioning rule of spec §5.7.
func TestFactsSchemaGolden(t *testing.T) {
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	desc := schemaDesc{SchemaVersion: SchemaVersion, Run: map[string][]fieldDesc{}, Keys: reg.Keys}
	describe(reflect.TypeOf(Run{}), desc.Run)
	got, _ := json.MarshalIndent(desc, "", "  ")
	got = append(got, '\n')
	path := filepath.Join("testdata", "facts-schema.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("facts schema changed; if intended, bump SchemaVersion or add `since`, then run: go test ./internal/facts -run TestFactsSchemaGolden -update\n--- got ---\n%s", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails without a golden**

Run: `go test ./internal/facts/ -run TestFactsSchemaGolden -v`
Expected: FAIL — "read golden (run with -update to create)".

- [ ] **Step 3: Create the golden and verify**

Run: `go test ./internal/facts/ -run TestFactsSchemaGolden -update && go test ./internal/facts/ -run TestFactsSchemaGolden -v`
Expected: the second run PASSes. Open `internal/facts/testdata/facts-schema.golden.json` and confirm it lists `Run`, `Host`, `OSRelease`, `Env`, `CollectorRun`, `Redaction` with their JSON names and the 20 registry keys.

- [ ] **Step 4: Commit**

```bash
git add internal/facts/schema_golden_test.go internal/facts/testdata/facts-schema.golden.json
git commit -m "Add reflection golden for the facts schema"
```

---

### Task 6: Control schema, strict loader and the embedded set

**Files:**
- Create: `controls/embed.go`, `controls/VERSION`, `internal/controls/schema.go`, `internal/controls/load.go`, `internal/controls/load_test.go`, `internal/controls/testdata/valid/account/example.yaml`, `internal/controls/testdata/unknown_key/account/bad.yaml`

**Interfaces:**
- Produces (package `controls`, path `internal/controls`):
  - `type Clause struct { Fact, Field, Op string; Expected any; On, Persona, Subject string; Where, Require *Clause }` (yaml tags `fact, field, op, expected, on, persona, subject, where, require`, all `omitempty` except `op`).
  - `type ClauseList []Clause` — YAML accepts a single mapping or a sequence (spec §6.3).
  - `type Mechanism struct { When ClauseList; Checks []Clause }` (tags `when, checks`).
  - `type Param struct { Type string; Default any; Description string }` (tags `type, default, description`).
  - `type CISRef struct { Benchmark, Version, Rec string }` (tags `benchmark, version, rec`).
  - `type References struct { KISA map[string][]string; CIS []CISRef; ISMSP []string; NIST80053 []string }` (tags `kisa, cis, isms_p, nist_800_53`, all `omitempty`).
  - `type Remediation struct { TextEn, TextKo, Risk string; Idempotent bool; Script, Rollback string }` (tags `text_en, text_ko, risk, idempotent, script, rollback`).
  - `type Control struct { ID, TitleEn, TitleKo, DescriptionEn, DescriptionKo, Category, Importance, Automation, ManualReason string; References References; RequiresFacts string; AppliesWhen ClauseList; AbsentMeans string; Params map[string]Param; Checks []Clause; Mechanisms []Mechanism; Custom string; Remediation *Remediation; Decision string; Path string }` (yaml tags `id, title_en, title_ko, description_en, description_ko, category, importance, automation, manual_reason, references, requires_facts, applies_when, absent_means, params, checks, mechanisms, custom, remediation, decision`; `Path` is `yaml:"-"`, filled by the loader).
  - `func (c *Control) SortedParamNames() []string`.
  - `type Set struct { Version string; Digest string; Controls []Control }` with `func (s *Set) ByID(id string) (*Control, bool)`; `Controls` sorted by `ID`.
  - `func LoadFS(fsys fs.FS) (*Set, error)` — reads `VERSION` at the root, then every `*.yaml` under any directory except `testdata`, decoding each with `KnownFields(true)`; an error names the file. Digest is `sha256:` over the concatenation of `path + "\n" + content` for every file in sorted path order plus the VERSION text.
  - `func LoadDefault() (*Set, error)` — `LoadFS(controlsembed.FS)` where `controlsembed` is the root package `github.com/kun9497/muster/controls`.
- Produces (package `controls`, path `controls/`): `var FS embed.FS` embedding `VERSION` and `*/*.yaml`.

- [ ] **Step 1: Write the failing tests**

`internal/controls/testdata/valid/VERSION`:

```
test-set+2026.09.02
```

`internal/controls/testdata/valid/account/example.yaml`:

```yaml
id: muster.account.example
title_en: Example control
title_ko: 예시 컨트롤
description_en: Exercises every schema field.
description_ko: 스키마의 모든 필드를 사용합니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-01"], "2021": ["U-01"] }
  cis: [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]
requires_facts: ">=1"
applies_when: { fact: services.ssh.installed, op: eq, expected: true }
absent_means: not_applicable
params:
  allowed: { type: list<string>, default: ["no", "prohibit-password"], description: Allowed values }
mechanisms:
  - when:
      - { fact: sshd.options.permit_root_login, op: present }
    checks:
      - { fact: sshd.options.permit_root_login, on: effective, persona: root, op: in, expected: ${allowed} }
  - when: { fact: files.etc_securetty, op: present }
    checks:
      - { fact: files.etc_securetty.lines, op: none, where: { op: matches, expected: "^pts/" } }
remediation:
  text_en: Set PermitRootLogin no.
  text_ko: PermitRootLogin no 로 설정합니다.
  risk: lockout_risk
  idempotent: true
  script: "printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/90-muster.conf && sshd -t"
  rollback: rm -f /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
decision: D09
```

`internal/controls/testdata/unknown_key/VERSION`: `bad+1`

`internal/controls/testdata/unknown_key/account/bad.yaml`:

```yaml
id: muster.account.bad
title_en: Bad
title_ko: 나쁨
category: account
importance: 상
automation: auto
absent_means: fail
checks:
  - { fact: services.ssh.installed, op: eq, expected: true, expcted: true }
```

`internal/controls/load_test.go`:

```go
package controls

import (
	"os"
	"strings"
	"testing"
)

func TestLoadFSDecodesEveryField(t *testing.T) {
	set, err := LoadFS(os.DirFS("testdata/valid"))
	if err != nil {
		t.Fatal(err)
	}
	if set.Version != "test-set+2026.09.02" || !strings.HasPrefix(set.Digest, "sha256:") {
		t.Fatalf("version %q digest %q", set.Version, set.Digest)
	}
	c, ok := set.ByID("muster.account.example")
	if !ok {
		t.Fatal("control not loaded")
	}
	if c.Importance != "상" || c.Automation != "auto" || c.References.KISA["2026"][0] != "U-01" || c.References.CIS[0].Rec != "5.1.20" {
		t.Errorf("scalar fields: %+v", c)
	}
	if len(c.AppliesWhen) != 1 || c.AppliesWhen[0].Fact != "services.ssh.installed" {
		t.Errorf("applies_when single mapping must become a one-element list: %+v", c.AppliesWhen)
	}
	if len(c.Mechanisms) != 2 || len(c.Mechanisms[0].When) != 1 || len(c.Mechanisms[1].When) != 1 {
		t.Errorf("mechanisms: %+v", c.Mechanisms)
	}
	if c.Mechanisms[0].Checks[0].Persona != "root" || c.Mechanisms[0].Checks[0].Expected != "${allowed}" {
		t.Errorf("clause modifiers: %+v", c.Mechanisms[0].Checks[0])
	}
	if c.Mechanisms[1].Checks[0].Where == nil || c.Mechanisms[1].Checks[0].Where.Op != "matches" {
		t.Errorf("where sub-clause: %+v", c.Mechanisms[1].Checks[0])
	}
	if c.Params["allowed"].Type != "list<string>" || c.Remediation == nil || !c.Remediation.Idempotent || c.Remediation.Risk != "lockout_risk" {
		t.Errorf("params/remediation: %+v %+v", c.Params, c.Remediation)
	}
	if c.Path != "account/example.yaml" {
		t.Errorf("path %q", c.Path)
	}
}

func TestLoadFSRejectsUnknownKeys(t *testing.T) {
	_, err := LoadFS(os.DirFS("testdata/unknown_key"))
	if err == nil || !strings.Contains(err.Error(), "expcted") || !strings.Contains(err.Error(), "account/bad.yaml") {
		t.Fatalf("err=%v, want a strict-decoding error naming the key and file", err)
	}
}

func TestLoadDefaultEmbeddedSet(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == "" || len(set.Controls) == 0 {
		t.Fatalf("embedded set: version %q, %d controls", set.Version, len(set.Controls))
	}
	for i := 1; i < len(set.Controls); i++ {
		if set.Controls[i-1].ID >= set.Controls[i].ID {
			t.Fatalf("controls not sorted by id: %q before %q", set.Controls[i-1].ID, set.Controls[i].ID)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controls/ -v`
Expected: FAIL — undefined `LoadFS`, `LoadDefault`.

- [ ] **Step 3: Write the schema, the loader and the embed package**

`controls/VERSION`:

```
kisa-unix-2026+2026.09.02
```

`controls/embed.go`:

```go
// Package controls embeds the default control set (spec §6.1, D15). Controls
// live at controls/<area>/<name>.yaml; fixtures under controls/testdata are
// read from disk by tests and are not embedded.
package controls

import "embed"

//go:embed VERSION */*.yaml
var FS embed.FS
```

(Create a placeholder `controls/account/.keep` is not needed: Task 15 adds real YAML; until then the glob would fail to compile. Add the first real control now — the U-01 file from Task 15 Step 1 — or temporarily create `controls/account/root_remote_login.yaml` with the exact content shown in Task 15. Do the latter: copy that YAML in this task so the embed compiles, and Task 15 keeps it.)

`internal/controls/schema.go`:

```go
// Package controls defines the control YAML schema (spec §6), loads sets
// strictly and lints them.
package controls

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// Clause is one judgment (spec §6.3). Under checks/when/applies_when it names
// a fact; under where/require it names a field of the element being examined
// (or neither, for a scalar element).
type Clause struct {
	Fact     string  `yaml:"fact,omitempty"`
	Field    string  `yaml:"field,omitempty"`
	Op       string  `yaml:"op"`
	Expected any     `yaml:"expected,omitempty"`
	On       string  `yaml:"on,omitempty"`
	Persona  string  `yaml:"persona,omitempty"`
	Subject  string  `yaml:"subject,omitempty"`
	Where    *Clause `yaml:"where,omitempty"`
	Require  *Clause `yaml:"require,omitempty"`
}

// ClauseList accepts either one mapping (shorthand for a one-element list)
// or a sequence of mappings (spec §6.3).
type ClauseList []Clause

func (l *ClauseList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		var c Clause
		if err := n.Decode(&c); err != nil {
			return err
		}
		*l = ClauseList{c}
		return nil
	case yaml.SequenceNode:
		var cs []Clause
		if err := n.Decode(&cs); err != nil {
			return err
		}
		*l = ClauseList(cs)
		return nil
	default:
		return fmt.Errorf("line %d: clause list must be a mapping or a sequence", n.Line)
	}
}

type Mechanism struct {
	When   ClauseList `yaml:"when"`
	Checks []Clause   `yaml:"checks"`
}

type Param struct {
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
	Description string `yaml:"description"`
}

type CISRef struct {
	Benchmark string `yaml:"benchmark"`
	Version   string `yaml:"version"`
	Rec       string `yaml:"rec"`
}

type References struct {
	KISA      map[string][]string `yaml:"kisa,omitempty"`
	CIS       []CISRef            `yaml:"cis,omitempty"`
	ISMSP     []string            `yaml:"isms_p,omitempty"`
	NIST80053 []string            `yaml:"nist_800_53,omitempty"`
}

type Remediation struct {
	TextEn     string `yaml:"text_en"`
	TextKo     string `yaml:"text_ko"`
	Risk       string `yaml:"risk"` // none | restart_service | reboot_required | lockout_risk
	Idempotent bool   `yaml:"idempotent"`
	Script     string `yaml:"script,omitempty"`
	Rollback   string `yaml:"rollback,omitempty"`
}

// Control is one YAML file (spec §6.2).
type Control struct {
	ID            string           `yaml:"id"`
	TitleEn       string           `yaml:"title_en"`
	TitleKo       string           `yaml:"title_ko"`
	DescriptionEn string           `yaml:"description_en"`
	DescriptionKo string           `yaml:"description_ko"`
	Category      string           `yaml:"category"`   // account | file | service | patch | log | beyond
	Importance    string           `yaml:"importance"` // 상 | 중 | 하
	Automation    string           `yaml:"automation"` // auto | partial | manual | not_applicable
	ManualReason  string           `yaml:"manual_reason,omitempty"`
	References    References       `yaml:"references"`
	RequiresFacts string           `yaml:"requires_facts"`
	AppliesWhen   ClauseList       `yaml:"applies_when,omitempty"`
	AbsentMeans   string           `yaml:"absent_means,omitempty"` // pass | fail | not_applicable | manual
	Params        map[string]Param `yaml:"params,omitempty"`
	Checks        []Clause         `yaml:"checks,omitempty"`
	Mechanisms    []Mechanism      `yaml:"mechanisms,omitempty"`
	Custom        string           `yaml:"custom,omitempty"`
	Remediation   *Remediation     `yaml:"remediation,omitempty"`
	Decision      string           `yaml:"decision,omitempty"`

	Path string `yaml:"-"` // relative path inside the set, filled by the loader
}

// SortedParamNames returns parameter names in a fixed order so nothing that
// walks Params can leak map order into output (spec §9, D20).
func (c *Control) SortedParamNames() []string {
	names := make([]string, 0, len(c.Params))
	for n := range c.Params {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
```

`internal/controls/load.go`:

```go
package controls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	controlsembed "github.com/kun9497/muster/controls"
)

// Set is one loaded control set: its version, a digest over every file, and
// the controls sorted by id (spec §6.1).
type Set struct {
	Version  string
	Digest   string
	Controls []Control
	byID     map[string]int
}

// ByID returns the control with the given id.
func (s *Set) ByID(id string) (*Control, bool) {
	i, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return &s.Controls[i], true
}

// LoadDefault loads the control set embedded in the binary (D15).
func LoadDefault() (*Set, error) { return LoadFS(controlsembed.FS) }

// LoadFS loads VERSION and every *.yaml outside testdata from fsys, decoding
// each file strictly so a misspelled key is an error, not a silent PASS
// (spec §6.8).
func LoadFS(fsys fs.FS) (*Set, error) {
	verBytes, err := fs.ReadFile(fsys, "VERSION")
	if err != nil {
		return nil, fmt.Errorf("control set has no VERSION file: %w", err)
	}
	set := &Set{Version: strings.TrimSpace(string(verBytes)), byID: map[string]int{}}
	var paths []string
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk control set: %w", err)
	}
	sort.Strings(paths)
	h := sha256.New()
	h.Write(verBytes)
	for _, p := range paths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		h.Write([]byte(p + "\n"))
		h.Write(data)
		var c Control
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if c.ID == "" {
			return nil, fmt.Errorf("%s: control has no id", p)
		}
		c.Path = path.Clean(p)
		set.Controls = append(set.Controls, c)
	}
	sort.Slice(set.Controls, func(i, j int) bool { return set.Controls[i].ID < set.Controls[j].ID })
	for i, c := range set.Controls {
		if _, dup := set.byID[c.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate control id %q", c.Path, c.ID)
		}
		set.byID[c.ID] = i
	}
	set.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return set, nil
}
```

Note: yaml.v3's `KnownFields(true)` reports an unknown key as `field expcted not found in type controls.Clause`, which contains the key name; the loader prefixes the file path, satisfying the test.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/controls/ ./controls/ -v`
Expected: PASS (three tests). If the embed glob fails because `controls/account` is empty, add the U-01 YAML from Task 15 now.

- [ ] **Step 5: Commit**

```bash
git add controls/ internal/controls/
git commit -m "Add control schema, strict loader and embedded set"
```

---

### Task 7: Control lint

**Files:**
- Create: `internal/controls/lint.go`, `internal/controls/lint_test.go`
- Modify: `cmd/muster/controls.go`

**Interfaces:**
- Consumes: `Set`, `Control` (Task 6); `facts.Registry` (Task 4).
- Produces (package `controls`):
  - `type Problem struct { ControlID, Path, Rule, Message string }`; `func (p Problem) String() string` → `"<path>: <rule>: <message>"`.
  - `type LintOptions struct { CustomFuncs map[string]bool; FixtureDir string }` — `FixtureDir` empty skips the fixture-pair rule.
  - `func Lint(set *Set, reg *facts.Registry, opts LintOptions) []Problem` — sorted by path then rule; empty slice means clean.
  - Rules (names are the `Rule` field): `id_format` (`^muster\.[a-z]+\.[a-z0-9_]+$`), `category`, `importance`, `automation`, `manual_reason` (required iff `manual`), `remediation` (required for `auto`/`partial`; `risk` must be one of the four), `titles` (`title_en` and `title_ko` non-empty), `judgment` (exactly one of `checks`/`mechanisms`/`custom` unless `automation` is `manual` or `not_applicable`, which take none), `absent_means` (required when the control has any judgment; value in the four), `requires_facts` (`^>=[1-9][0-9]*$`), `fact_key` (every `fact` in applies_when/when/checks is registered), `custom_func` (name in `opts.CustomFuncs`), `clause_grammar` (see below), `param` (`${name}` declared; `default` matches `type`; `type` in `string|int|bool|list<string>`), `references_kisa` (keys are four digits; values match `^U-\d{2}$`), `references_cis` (benchmark, version, rec non-empty), `fixtures` (`<FixtureDir>/<id>/pass-*.json` and `fail-*.json` both exist).
  - `clause_grammar`: `op` ∈ the fourteen; `present`/`absent` have no `expected`; other scalar ops have `expected`; `each` requires `subject` and `require` (and `where` optional), `none` requires `where`; `where`/`require` sub-clauses use `field` not `fact`; `on` ∈ `runtime|persisted|effective|both` and only on a setting-typed fact; `persona` ∈ `root|user|invalid` and only on a fact whose key starts with `sshd.options.`; `matches` patterns compile with `regexp.Compile`; `lt|lte|gt|gte` only on `int` or `setting<int>` facts; `each`/`none` only on `list<...>` facts.

- [ ] **Step 1: Write the failing tests**

`internal/controls/lint_test.go`:

```go
package controls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

func lintOne(t *testing.T, yamlText string, opts LintOptions) []Problem {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("t+1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "account"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "account", "c.yaml"), []byte(yamlText), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := LoadFS(os.DirFS(dir))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return Lint(set, reg, opts)
}

func rules(ps []Problem) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.Rule] = true
	}
	return m
}

const goodControl = `id: muster.account.good
title_en: Good
title_ko: 좋음
description_en: d
description_ko: 설명
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-01"] }
  cis: [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]
requires_facts: ">=1"
absent_means: not_applicable
params:
  allowed: { type: list<string>, default: ["no"], description: d }
checks:
  - { fact: sshd.options.permit_root_login, on: effective, persona: root, op: in, expected: ${allowed} }
remediation: { text_en: t, text_ko: 조치, risk: lockout_risk, idempotent: true }
`

func TestLintCleanControlHasNoProblems(t *testing.T) {
	if ps := lintOne(t, goodControl, LintOptions{}); len(ps) != 0 {
		t.Fatalf("unexpected problems: %v", ps)
	}
}

func TestLintRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		rule string
	}{
		{"bad id", `id: U-01
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
`, "id_format"},
		{"manual without reason", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
`, "manual_reason"},
		{"auto without remediation", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
`, "remediation"},
		{"unregistered fact", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: nope.key, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "fact_key"},
		{"present with expected", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: present, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"bad regex", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: files.etc_securetty.lines, op: none, where: { op: matches, expected: "(" } }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"on without setting", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, on: runtime, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "clause_grammar"},
		{"undeclared param", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: ${nope} }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "param"},
		{"kisa ref format", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: manual
manual_reason: r
references: { kisa: { "2026": ["U-1"] } }
`, "references_kisa"},
		{"missing absent_means", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "absent_means"},
		{"two judgments", `id: muster.account.x
title_en: t
title_ko: 제목
category: account
importance: 상
automation: auto
absent_means: fail
checks: [{ fact: services.ssh.installed, op: eq, expected: true }]
custom: Whatever
remediation: { text_en: t, text_ko: 조치, risk: none }
`, "judgment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rules(lintOne(t, c.yaml, LintOptions{CustomFuncs: map[string]bool{}}))
			if !got[c.rule] {
				t.Fatalf("want rule %q among %v", c.rule, got)
			}
		})
	}
}

func TestLintFixturePairRule(t *testing.T) {
	fx := t.TempDir()
	os.MkdirAll(filepath.Join(fx, "muster.account.good"), 0o755)
	os.WriteFile(filepath.Join(fx, "muster.account.good", "pass-one.json"), []byte("{}"), 0o644)
	ps := lintOne(t, goodControl, LintOptions{FixtureDir: fx})
	if !rules(ps)["fixtures"] {
		t.Fatalf("missing fail fixture must be reported: %v", ps)
	}
	os.WriteFile(filepath.Join(fx, "muster.account.good", "fail-one.json"), []byte("{}"), 0o644)
	if ps := lintOne(t, goodControl, LintOptions{FixtureDir: fx}); len(ps) != 0 {
		t.Fatalf("unexpected: %v", ps)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controls/ -run TestLint -v`
Expected: FAIL — undefined `Lint`, `LintOptions`, `Problem`.

- [ ] **Step 3: Write lint**

`internal/controls/lint.go`:

```go
package controls

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/facts"
)

// Problem is one lint finding. Rule is a stable name CI can match on.
type Problem struct {
	ControlID string
	Path      string
	Rule      string
	Message   string
}

func (p Problem) String() string { return fmt.Sprintf("%s: %s: %s", p.Path, p.Rule, p.Message) }

// LintOptions carries what lint cannot know on its own: the registered
// custom functions (owned by check) and where fixtures live.
type LintOptions struct {
	CustomFuncs map[string]bool
	FixtureDir  string
}

var (
	idRe            = regexp.MustCompile(`^muster\.[a-z]+\.[a-z0-9_]+$`)
	requiresFactsRe = regexp.MustCompile(`^>=[1-9][0-9]*$`)
	kisaYearRe      = regexp.MustCompile(`^[0-9]{4}$`)
	kisaItemRe      = regexp.MustCompile(`^U-[0-9]{2}$`)
	paramRefRe      = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

	validCategory    = set("account", "file", "service", "patch", "log", "beyond")
	validImportance  = set("상", "중", "하")
	validAutomation  = set("auto", "partial", "manual", "not_applicable")
	validAbsentMeans = set("pass", "fail", "not_applicable", "manual")
	validRisk        = set("none", "restart_service", "reboot_required", "lockout_risk")
	validOn          = set("runtime", "persisted", "effective", "both")
	validPersona     = set("root", "user", "invalid")
	validParamType   = set("string", "int", "bool", "list<string>")
	scalarOps        = set("eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte", "matches", "contains", "present", "absent")
	orderedOps       = set("lt", "lte", "gt", "gte")
	collectionOps    = set("each", "none")
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Lint applies every rule of spec §6.8 to set and returns the problems sorted
// by path then rule. An empty result means the set is clean.
func Lint(s *Set, reg *facts.Registry, opts LintOptions) []Problem {
	var out []Problem
	for i := range s.Controls {
		c := &s.Controls[i]
		add := func(rule, format string, args ...any) {
			out = append(out, Problem{ControlID: c.ID, Path: c.Path, Rule: rule, Message: fmt.Sprintf(format, args...)})
		}
		if !idRe.MatchString(c.ID) {
			add("id_format", "id %q must look like muster.<area>.<name>", c.ID)
		}
		if c.TitleEn == "" || c.TitleKo == "" {
			add("titles", "title_en and title_ko are required")
		}
		if !validCategory[c.Category] {
			add("category", "unknown category %q", c.Category)
		}
		if !validImportance[c.Importance] {
			add("importance", "importance must be 상, 중 or 하; got %q", c.Importance)
		}
		if !validAutomation[c.Automation] {
			add("automation", "unknown automation %q", c.Automation)
		}
		if c.Automation == "manual" && strings.TrimSpace(c.ManualReason) == "" {
			add("manual_reason", "manual controls must state manual_reason")
		}
		if (c.Automation == "auto" || c.Automation == "partial") && c.Remediation == nil {
			add("remediation", "%s controls must carry remediation", c.Automation)
		}
		if c.Remediation != nil && !validRisk[c.Remediation.Risk] {
			add("remediation", "unknown remediation risk %q", c.Remediation.Risk)
		}
		judgments := 0
		if len(c.Checks) > 0 {
			judgments++
		}
		if len(c.Mechanisms) > 0 {
			judgments++
		}
		if c.Custom != "" {
			judgments++
		}
		hasJudgment := c.Automation == "auto" || c.Automation == "partial"
		if hasJudgment && judgments != 1 {
			add("judgment", "exactly one of checks, mechanisms or custom is required; found %d", judgments)
		}
		if !hasJudgment && judgments != 0 {
			add("judgment", "%s controls carry no judgment", c.Automation)
		}
		if hasJudgment && !validAbsentMeans[c.AbsentMeans] {
			add("absent_means", "absent_means must be pass, fail, not_applicable or manual; got %q", c.AbsentMeans)
		}
		if c.RequiresFacts != "" && !requiresFactsRe.MatchString(c.RequiresFacts) {
			add("requires_facts", "requires_facts must be >=N; got %q", c.RequiresFacts)
		}
		if c.Custom != "" && !opts.CustomFuncs[c.Custom] {
			add("custom_func", "unknown custom function %q", c.Custom)
		}
		for name, p := range c.Params {
			if !validParamType[p.Type] {
				add("param", "param %q has unknown type %q", name, p.Type)
			} else if !paramDefaultMatches(p) {
				add("param", "param %q default %v does not match type %s", name, p.Default, p.Type)
			}
		}
		for year, items := range c.References.KISA {
			if !kisaYearRe.MatchString(year) {
				add("references_kisa", "kisa reference key %q must be a four-digit edition year", year)
			}
			for _, it := range items {
				if !kisaItemRe.MatchString(it) {
					add("references_kisa", "kisa reference %q must look like U-01", it)
				}
			}
		}
		for _, r := range c.References.CIS {
			if r.Benchmark == "" || r.Version == "" || r.Rec == "" {
				add("references_cis", "cis references need benchmark, version and rec")
			}
		}
		for _, cl := range c.AppliesWhen {
			lintClause(c, cl, reg, add, "applies_when")
		}
		for _, cl := range c.Checks {
			lintClause(c, cl, reg, add, "checks")
		}
		for mi, m := range c.Mechanisms {
			for _, cl := range m.When {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].when", mi))
			}
			for _, cl := range m.Checks {
				lintClause(c, cl, reg, add, fmt.Sprintf("mechanisms[%d].checks", mi))
			}
		}
		if opts.FixtureDir != "" && hasJudgment {
			for _, prefix := range []string{"pass-", "fail-"} {
				matches, _ := filepath.Glob(filepath.Join(opts.FixtureDir, c.ID, prefix+"*.json"))
				if len(matches) == 0 {
					add("fixtures", "no %s*.json fixture under %s", prefix, filepath.Join(opts.FixtureDir, c.ID))
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Rule < out[j].Rule
	})
	if out == nil {
		out = []Problem{}
	}
	return out
}

func paramDefaultMatches(p Param) bool {
	switch p.Type {
	case "string":
		_, ok := p.Default.(string)
		return ok
	case "int":
		_, ok := p.Default.(int)
		return ok
	case "bool":
		_, ok := p.Default.(bool)
		return ok
	case "list<string>":
		xs, ok := p.Default.([]any)
		if !ok {
			return false
		}
		for _, x := range xs {
			if _, ok := x.(string); !ok {
				return false
			}
		}
		return true
	}
	return false
}

// lintClause checks one top-level clause and, for collections, its
// sub-clauses, against the grammar of spec §6.3.
func lintClause(c *Control, cl Clause, reg *facts.Registry, add func(string, string, ...any), where string) {
	if cl.Fact == "" {
		add("clause_grammar", "%s: clause needs fact", where)
		return
	}
	if cl.Field != "" {
		add("clause_grammar", "%s: field is only valid inside where/require", where)
	}
	entry, ok := reg.Lookup(cl.Fact)
	if !ok {
		add("fact_key", "%s: fact %q is not registered", where, cl.Fact)
		return
	}
	isSetting := reg.IsSetting(entry)
	isList := strings.HasPrefix(entry.Type, "list<")
	switch {
	case scalarOps[cl.Op]:
		lintScalarOp(cl, entry, add, where)
		if cl.Where != nil || cl.Require != nil || cl.Subject != "" {
			add("clause_grammar", "%s: where/require/subject are only valid with each or none", where)
		}
	case collectionOps[cl.Op]:
		if !isList {
			add("clause_grammar", "%s: %s needs a list-typed fact; %s is %s", where, cl.Op, cl.Fact, entry.Type)
		}
		if cl.Expected != nil || cl.On != "" || cl.Persona != "" {
			add("clause_grammar", "%s: %s takes no expected/on/persona", where, cl.Op)
		}
		if cl.Op == "each" && (cl.Subject == "" || cl.Require == nil) {
			add("clause_grammar", "%s: each needs subject and require", where)
		}
		if cl.Op == "none" && cl.Where == nil {
			add("clause_grammar", "%s: none needs where", where)
		}
		for _, sub := range []*Clause{cl.Where, cl.Require} {
			if sub == nil {
				continue
			}
			if sub.Fact != "" || sub.Where != nil || sub.Require != nil || sub.On != "" || sub.Persona != "" {
				add("clause_grammar", "%s: sub-clauses use field, op and expected only", where)
			}
			if !scalarOps[sub.Op] {
				add("clause_grammar", "%s: sub-clause op %q is not a scalar operator", where, sub.Op)
			}
			lintExpected(*sub, add, where)
		}
	default:
		add("clause_grammar", "%s: unknown op %q", where, cl.Op)
	}
	if cl.On != "" && (!isSetting || !validOn[cl.On]) {
		add("clause_grammar", "%s: on=%q is only valid on a setting-typed fact", where, cl.On)
	}
	if cl.Persona != "" && (!validPersona[cl.Persona] || !strings.HasPrefix(cl.Fact, "sshd.options.")) {
		add("clause_grammar", "%s: persona=%q is only valid on sshd.options.* facts", where, cl.Persona)
	}
	if orderedOps[cl.Op] && entry.Type != "int" && entry.Type != "setting<int>" {
		add("clause_grammar", "%s: %s needs an int fact", where, cl.Op)
	}
	if s, ok := cl.Expected.(string); ok {
		if m := paramRefRe.FindStringSubmatch(s); m != nil {
			if _, declared := c.Params[m[1]]; !declared {
				add("param", "%s: parameter %q is not declared", where, m[1])
			}
		}
	}
}

func lintScalarOp(cl Clause, entry facts.Entry, add func(string, string, ...any), where string) {
	lintExpected(cl, add, where)
}

func lintExpected(cl Clause, add func(string, string, ...any), where string) {
	switch cl.Op {
	case "present", "absent":
		if cl.Expected != nil {
			add("clause_grammar", "%s: %s takes no expected", where, cl.Op)
		}
	case "matches":
		s, ok := cl.Expected.(string)
		if !ok {
			add("clause_grammar", "%s: matches needs a string pattern", where)
			return
		}
		if _, err := regexp.Compile(s); err != nil {
			add("clause_grammar", "%s: pattern %q does not compile: %v", where, s, err)
		}
	default:
		if cl.Expected == nil && scalarOps[cl.Op] {
			add("clause_grammar", "%s: %s needs expected", where, cl.Op)
		}
	}
}

// FixtureDirExists is a small helper for the CLI: lint the fixture pair only
// when the directory is present on disk.
func FixtureDirExists(dir string) bool {
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}
```

Wire the CLI, replacing the stub in `cmd/muster/controls.go`:

```go
package main

import (
	"fmt"
	"io"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func runControls(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: muster controls <lint|list>")
		return exitError
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	switch args[0] {
	case "lint":
		opts := controls.LintOptions{CustomFuncs: map[string]bool{}}
		if controls.FixtureDirExists("controls/testdata") {
			opts.FixtureDir = "controls/testdata"
		}
		problems := controls.Lint(set, reg, opts)
		for _, p := range problems {
			fmt.Fprintln(stderr, p)
		}
		if len(problems) > 0 {
			fmt.Fprintf(stderr, "muster: %d lint problem(s)\n", len(problems))
			return exitError
		}
		fmt.Fprintf(stdout, "ok: %d controls, set %s\n", len(set.Controls), set.Version)
		return exitOK
	case "list":
		for _, c := range set.Controls {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", c.ID, c.Importance, c.Automation, c.TitleEn)
		}
		return exitOK
	default:
		fmt.Fprintf(stderr, "muster: unknown controls subcommand %q\n", args[0])
		return exitError
	}
}
```

(Task 10 replaces `map[string]bool{}` with `check.CustomFuncs()` once that exists.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/controls/ -v && go run ./cmd/muster controls lint`
Expected: PASS; the lint command prints `ok: N controls, set kisa-unix-2026+2026.09.02` (fixture problems may appear until Task 15 adds fixtures — that is expected and acceptable at this point only; do not merge with red lint).

- [ ] **Step 5: Commit**

```bash
git add internal/controls/lint.go internal/controls/lint_test.go cmd/muster/controls.go
git commit -m "Add control lint and the controls lint/list commands"
```

---

### Task 8: Typed values, operators, regex and parameter substitution

**Files:**
- Create: `internal/check/results.go`, `internal/check/value.go`, `internal/check/value_test.go`

**Interfaces:**
- Consumes: `facts.Entry` (type strings), `controls.Param`.
- Produces (package `check`):
  - `type Status string` with constants `PASS`, `FAIL`, `WARN`, `MANUAL`, `NotApplicable = "NOT_APPLICABLE"`, `ERROR`, `WAIVED`.
  - `type ReasonCode string` with constants `PermissionDenied="permission_denied"`, `Timeout="timeout"`, `Truncated="truncated"`, `UnsupportedEnv="unsupported_env"`, `ParseError="parse_error"`, `MissingFact="missing_fact"`, `SchemaMismatch="schema_mismatch"`, `WalkIncomplete="walk_incomplete"`, `InternalError="internal_error"`.
  - `type Evidence struct { Fact string; Status facts.Status; Value any; Source *facts.Source; Side string }` (JSON tags `fact, status, value, source, side`; `omitempty` on value/source/side).
  - `type Observation struct { Subject string; Expected any; Actual any; Verdict string; Source *facts.Source }` (tags `subject, expected, actual, verdict, source`).
  - `type WaiverNote struct { Applied bool; Reason string; Expires string; Subject string; NotAppliedBecause string }` (tags `applied, reason, expires, subject, not_applied_because`).
  - `type Result struct { ID, TitleEn, TitleKo, Category, Importance, Automation string; Status Status; ReasonCode ReasonCode; Reason string; Degraded string; Evidence []Evidence; Observations []Observation; Waiver *WaiverNote; Mechanism int }` (tags `id, title_en, title_ko, category, importance, automation, status, reason_code, reason, degraded, evidence, observations, waiver, mechanism`; `omitempty` on reason_code, reason, degraded, evidence, observations, waiver, mechanism).
  - `func compare(op string, actual any, expected any, typ string) (bool, error)` — typed comparison: `typ` is the registry base type (`string|int|bool|list<string>`); JSON numbers arrive as `float64` and must be integral for `int`; `in`/`not_in` need a `[]any` expected; `contains` on `list<string>` means element equality, on `string` means substring; `matches` compiles the pattern (RE2, unanchored, case-sensitive) and, on a list, is true when every element matches; `lt|lte|gt|gte` on ints only; `eq|ne` on scalars and on lists (order-sensitive equality).
  - `func substitute(expected any, params map[string]any) (any, error)` — whole-value `${name}` only; unknown name is an error; a string that merely contains `${` elsewhere is returned unchanged.
  - `func ParamValues(c *controls.Control, overrides map[string]any) map[string]any` — defaults from the control, overridden by `overrides` (stage 1 passes nil); YAML `[]any` defaults kept as `[]any`.

- [ ] **Step 1: Write the failing tests**

`internal/check/value_test.go`:

```go
package check

import (
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func TestCompareTypedScalars(t *testing.T) {
	cases := []struct {
		op   string
		act  any
		exp  any
		typ  string
		want bool
		err  bool
	}{
		{"eq", "no", "no", "string", true, false},
		{"ne", "no", "yes", "string", true, false},
		{"eq", float64(0), 0, "int", true, false},
		{"eq", "0", 0, "int", false, true}, // "0" is not an int: typed comparison
		{"lt", float64(89), 90, "int", true, false},
		{"gte", float64(90), 90, "int", true, false},
		{"lt", float64(1.5), 2, "int", false, true}, // non-integral number for int type
		{"eq", true, true, "bool", true, false},
		{"in", "prohibit-password", []any{"no", "prohibit-password"}, "string", true, false},
		{"not_in", "yes", []any{"no", "prohibit-password"}, "string", true, false},
		{"in", "x", "not-a-list", "string", false, true},
		{"contains", "PermitRootLogin no", "RootLogin", "string", true, false},
		{"matches", "pts/0", "^pts/", "string", true, false},
		{"matches", "PTS/0", "^pts/", "string", false, false}, // case-sensitive
		{"matches", "a\nb", "a.b", "string", false, false},    // . does not match newline
		{"matches", "x", "(", "string", false, true},
		{"present", "anything", nil, "string", true, false},
		{"bogus", "x", "x", "string", false, true},
	}
	for _, c := range cases {
		got, err := compare(c.op, c.act, c.exp, c.typ)
		if (err != nil) != c.err {
			t.Errorf("%s %v %v: err=%v want err=%v", c.op, c.act, c.exp, err, c.err)
			continue
		}
		if got != c.want {
			t.Errorf("%s %v %v: got %v want %v", c.op, c.act, c.exp, got, c.want)
		}
	}
}

func TestCompareLists(t *testing.T) {
	list := []any{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}
	if ok, _ := compare("contains", list, "chacha20-poly1305@openssh.com", "list<string>"); !ok {
		t.Error("contains on list must match an element")
	}
	if ok, _ := compare("contains", list, "chacha20", "list<string>"); ok {
		t.Error("contains on list is element equality, not substring")
	}
	if ok, _ := compare("matches", list, "@openssh\\.com$", "list<string>"); !ok {
		t.Error("matches on list is true when every element matches")
	}
	if ok, _ := compare("matches", list, "^aes", "list<string>"); ok {
		t.Error("matches on list must fail when one element does not match")
	}
	if ok, _ := compare("eq", list, []any{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}, "list<string>"); !ok {
		t.Error("eq on lists compares elements in order")
	}
}

func TestSubstituteWholeValueOnly(t *testing.T) {
	params := map[string]any{"allowed": []any{"no", "prohibit-password"}, "days": 90}
	got, err := substitute("${allowed}", params)
	if err != nil {
		t.Fatal(err)
	}
	if xs, ok := got.([]any); !ok || len(xs) != 2 {
		t.Fatalf("list param must keep its type: %#v", got)
	}
	if got, _ := substitute("${days}", params); got != 90 {
		t.Errorf("int param must keep its type: %#v", got)
	}
	if got, _ := substitute("/home/${x}", params); got != "/home/${x}" {
		t.Errorf("embedded ${...} is not substitution: %#v", got)
	}
	if _, err := substitute("${nope}", params); err == nil {
		t.Error("unknown parameter must error")
	}
	if got, _ := substitute(90, params); got != 90 {
		t.Errorf("non-string expected passes through: %#v", got)
	}
}

func TestParamValuesDefaultsAndOverrides(t *testing.T) {
	c := &controls.Control{Params: map[string]controls.Param{
		"days": {Type: "int", Default: 90},
		"list": {Type: "list<string>", Default: []any{"a"}},
	}}
	v := ParamValues(c, map[string]any{"days": 60})
	if v["days"] != 60 || len(v["list"].([]any)) != 1 {
		t.Fatalf("%#v", v)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/check/ -run 'TestCompare|TestSubstitute|TestParam' -v`
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Write `results.go` and `value.go`**

`internal/check/results.go`:

```go
package check

import "github.com/kun9497/muster/internal/facts"

// Status is a control's outcome (spec §6.5).
type Status string

const (
	PASS          Status = "PASS"
	FAIL          Status = "FAIL"
	WARN          Status = "WARN"
	MANUAL        Status = "MANUAL"
	NotApplicable Status = "NOT_APPLICABLE"
	ERROR         Status = "ERROR"
	WAIVED        Status = "WAIVED"
)

// ReasonCode is the fixed vocabulary CI matches on (spec §7.2).
type ReasonCode string

const (
	PermissionDenied ReasonCode = "permission_denied"
	Timeout          ReasonCode = "timeout"
	Truncated        ReasonCode = "truncated"
	UnsupportedEnv   ReasonCode = "unsupported_env"
	ParseError       ReasonCode = "parse_error"
	MissingFact      ReasonCode = "missing_fact"
	SchemaMismatch   ReasonCode = "schema_mismatch"
	WalkIncomplete   ReasonCode = "walk_incomplete"
	InternalError    ReasonCode = "internal_error"
)

// Evidence is one fact the verdict was decided on (D08).
type Evidence struct {
	Fact   string        `json:"fact"`
	Status facts.Status  `json:"status"`
	Value  any           `json:"value,omitempty"`
	Source *facts.Source `json:"source,omitempty"`
	Side   string        `json:"side,omitempty"` // runtime | persisted | effective, for settings
}

// Observation is one element of a collection judgment (spec §6.4).
type Observation struct {
	Subject  string        `json:"subject"`
	Expected any           `json:"expected,omitempty"`
	Actual   any           `json:"actual,omitempty"`
	Verdict  string        `json:"verdict"` // pass | fail
	Source   *facts.Source `json:"source,omitempty"`
}

// WaiverNote records how a waiver touched a result (spec §6.7).
type WaiverNote struct {
	Applied           bool   `json:"applied"`
	Reason            string `json:"reason,omitempty"`
	Expires           string `json:"expires,omitempty"`
	Subject           string `json:"subject,omitempty"`
	NotAppliedBecause string `json:"not_applied_because,omitempty"`
}

// Result is one control's outcome with everything needed to explain it.
type Result struct {
	ID           string        `json:"id"`
	TitleEn      string        `json:"title_en"`
	TitleKo      string        `json:"title_ko"`
	Category     string        `json:"category"`
	Importance   string        `json:"importance"`
	Automation   string        `json:"automation"`
	Status       Status        `json:"status"`
	ReasonCode   ReasonCode    `json:"reason_code,omitempty"`
	Reason       string        `json:"reason,omitempty"`
	Degraded     string        `json:"degraded,omitempty"`
	Evidence     []Evidence    `json:"evidence,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	Waiver       *WaiverNote   `json:"waiver,omitempty"`
	Mechanism    int           `json:"mechanism,omitempty"` // 1-based index of the mechanism judged; 0 when checks/custom
}
```

`internal/check/value.go`:

```go
package check

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"

	"github.com/kun9497/muster/internal/controls"
)

var paramRef = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

// ParamValues merges a control's defaults with overrides (stage 3 tuning);
// stage 1 passes nil overrides.
func ParamValues(c *controls.Control, overrides map[string]any) map[string]any {
	out := make(map[string]any, len(c.Params))
	for _, name := range c.SortedParamNames() {
		out[name] = c.Params[name].Default
	}
	for k, v := range overrides {
		if _, declared := c.Params[k]; declared {
			out[k] = v
		}
	}
	return out
}

// substitute resolves `${name}` as a whole value with the parameter's own
// type preserved (spec §6.3). Anything else passes through unchanged.
func substitute(expected any, params map[string]any) (any, error) {
	s, ok := expected.(string)
	if !ok {
		return expected, nil
	}
	m := paramRef.FindStringSubmatch(s)
	if m == nil {
		return expected, nil
	}
	v, ok := params[m[1]]
	if !ok {
		return nil, fmt.Errorf("parameter %q is not declared", m[1])
	}
	return v, nil
}

// baseType strips setting<...> so comparisons see the inner type.
func baseType(typ string) string {
	if strings.HasPrefix(typ, "setting<") {
		return strings.TrimSuffix(strings.TrimPrefix(typ, "setting<"), ">")
	}
	return typ
}

// compare applies op to a fact value and an expected value, typed by the
// registry (spec §6.3). JSON numbers arrive as float64; for "int" they must
// be integral. Returns an error for a type mismatch or an unknown op, which
// the evaluator turns into ERROR(internal_error) rather than a guess.
func compare(op string, actual, expected any, typ string) (bool, error) {
	typ = baseType(typ)
	switch op {
	case "present":
		return true, nil // reached only for status ok; absence is decided by the derivation table
	case "absent":
		return false, nil
	}
	if strings.HasPrefix(typ, "list<") {
		return compareList(op, actual, expected)
	}
	switch typ {
	case "int":
		a, err := toInt(actual)
		if err != nil {
			return false, fmt.Errorf("actual: %w", err)
		}
		switch op {
		case "eq", "ne", "lt", "lte", "gt", "gte":
			e, err := toInt(expected)
			if err != nil {
				return false, fmt.Errorf("expected: %w", err)
			}
			switch op {
			case "eq":
				return a == e, nil
			case "ne":
				return a != e, nil
			case "lt":
				return a < e, nil
			case "lte":
				return a <= e, nil
			case "gt":
				return a > e, nil
			case "gte":
				return a >= e, nil
			}
		case "in", "not_in":
			return inList(op, a, expected, func(x any) (any, error) { return toInt(x) })
		}
		return false, fmt.Errorf("op %q is not valid on int", op)
	case "bool":
		a, ok := actual.(bool)
		if !ok {
			return false, fmt.Errorf("actual %#v is not a bool", actual)
		}
		e, ok := expected.(bool)
		if !ok {
			return false, fmt.Errorf("expected %#v is not a bool", expected)
		}
		switch op {
		case "eq":
			return a == e, nil
		case "ne":
			return a != e, nil
		}
		return false, fmt.Errorf("op %q is not valid on bool", op)
	case "string":
		a, ok := actual.(string)
		if !ok {
			return false, fmt.Errorf("actual %#v is not a string", actual)
		}
		switch op {
		case "eq", "ne", "contains", "matches":
			e, ok := expected.(string)
			if !ok {
				return false, fmt.Errorf("expected %#v is not a string", expected)
			}
			switch op {
			case "eq":
				return a == e, nil
			case "ne":
				return a != e, nil
			case "contains":
				return strings.Contains(a, e), nil
			case "matches":
				re, err := regexp.Compile(e)
				if err != nil {
					return false, err
				}
				return re.MatchString(a), nil
			}
		case "in", "not_in":
			return inList(op, a, expected, func(x any) (any, error) {
				s, ok := x.(string)
				if !ok {
					return nil, fmt.Errorf("%#v is not a string", x)
				}
				return s, nil
			})
		}
		return false, fmt.Errorf("op %q is not valid on string", op)
	}
	return false, fmt.Errorf("unsupported type %q", typ)
}

func compareList(op string, actual, expected any) (bool, error) {
	xs, ok := actual.([]any)
	if !ok {
		return false, fmt.Errorf("actual %#v is not a list", actual)
	}
	switch op {
	case "eq", "ne":
		ys, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("expected %#v is not a list", expected)
		}
		eq := reflect.DeepEqual(xs, ys)
		if op == "eq" {
			return eq, nil
		}
		return !eq, nil
	case "contains":
		for _, x := range xs {
			if x == expected {
				return true, nil
			}
		}
		return false, nil
	case "matches":
		pat, ok := expected.(string)
		if !ok {
			return false, fmt.Errorf("expected %#v is not a pattern", expected)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, err
		}
		for _, x := range xs {
			s, ok := x.(string)
			if !ok || !re.MatchString(s) {
				return false, nil
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("op %q is not valid on a list", op)
}

func inList(op string, a any, expected any, conv func(any) (any, error)) (bool, error) {
	xs, ok := expected.([]any)
	if !ok {
		return false, fmt.Errorf("expected %#v is not a list", expected)
	}
	found := false
	for _, x := range xs {
		v, err := conv(x)
		if err != nil {
			return false, err
		}
		if v == a {
			found = true
		}
	}
	if op == "in" {
		return found, nil
	}
	return !found, nil
}

func toInt(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case float64:
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("%v is not an integer", n)
		}
		return int64(n), nil
	}
	return 0, fmt.Errorf("%#v is not an int", v)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/check/ -v`
Expected: PASS, including the import-contract test.

- [ ] **Step 5: Commit**

```bash
git add internal/check/
git commit -m "Add result types, typed comparison and parameter substitution"
```

---

### Task 9: Scalar clauses, setting sides, personas and collections

**Files:**
- Create: `internal/check/clause.go`, `internal/check/collection.go`, `internal/check/clause_test.go`

**Interfaces:**
- Consumes: `facts.Registry.Resolve`, `compare`, `substitute`.
- Produces (package `check`):
  - `type env struct { snap *facts.Snapshot; reg *facts.Registry; params map[string]any; personas bool }` — evaluation context; `personas` is `facts.sshd.personas_collected` resolved once per evaluation.
  - `type clauseOutcome struct { Holds bool; Evidence []Evidence; Observations []Observation; Degraded string; Err error }`.
  - `func (e *env) evalClause(cl controls.Clause) clauseOutcome` — resolves the fact; assumes the caller has already handled non-`ok` statuses (the derivation table does that in Task 10) and therefore returns `Err` if it meets a non-`ok` envelope; for settings picks sides per `on` (default from the registry): `both` = both `runtime` and `persisted` must exist with status `ok` and satisfy; one side satisfying and the other not → `Holds=false` with `Degraded` set to `"reverts on reboot"` (runtime holds, persisted fails) or `"not applied"` (persisted holds, runtime fails) — the derivation table maps that to `WARN`; a side that is absent entirely is treated as that side failing with the same degradation text; `effective`/`runtime`/`persisted` = that side alone; `persona` set while `e.personas` is false → evaluate the global value and set `Degraded="personas not collected"`.
  - `func (e *env) evalCollection(cl controls.Clause, entry facts.Entry, list []any) clauseOutcome` — `each`: filter by `where` (element field clause), every remaining element must satisfy `require`; `none`: no element may satisfy `where`; observations for every failing element (and, for `each`, passing ones too, verdict `pass`), subject `<kind>:<value>` from the registry's `subject_kind` and the clause's `subject` field; elements are `map[string]any` (records) or scalars (then `field` is empty and the element itself is compared).
  - `func fieldClause(sub *controls.Clause, elem any) (bool, error)` — evaluates a `where`/`require` sub-clause against an element; the field's type is inferred from the Go value (`string`, `bool`, integral `float64` → `int`, `[]any` → `list<string>`).

- [ ] **Step 1: Write the failing tests**

`internal/check/clause_test.go`:

```go
package check

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func newEnv(t *testing.T, snapshotJSON string) *env {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.Load(strings.NewReader(snapshotJSON))
	if err != nil {
		t.Fatal(err)
	}
	return &env{snap: s, reg: reg, params: map[string]any{}, personas: personasCollected(s, reg)}
}

const sshdSnap = `{"schema_version":1,"run":{},"facts":{
  "sshd": {"personas_collected": {"status":"ok","value":false},
           "options": {"permit_root_login": {
              "runtime":   {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}},
              "persisted": {"status":"ok","value":"yes","source":{"kind":"file","path":"/etc/ssh/sshd_config","line":40,"raw":"PermitRootLogin yes"}},
              "effective": {"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}}}}},
  "accounts": {"login_defs": {"pass_max_days": {
              "runtime":   {"status":"ok","value":99999},
              "persisted": {"status":"ok","value":90,"source":{"kind":"file","path":"/etc/login.defs","line":160}}}}},
  "services": {"ssh": {"installed": {"status":"ok","value":true}}}
}}`

func TestEvalClauseEffectiveSideWithPersonaDegradation(t *testing.T) {
	e := newEnv(t, sshdSnap)
	out := e.evalClause(controls.Clause{Fact: "sshd.options.permit_root_login", On: "effective", Persona: "root", Op: "in", Expected: []any{"no", "prohibit-password"}})
	if out.Err != nil || !out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
	if out.Degraded != "personas not collected" {
		t.Errorf("degraded=%q", out.Degraded)
	}
	if len(out.Evidence) != 1 || out.Evidence[0].Side != "effective" || out.Evidence[0].Value != "no" {
		t.Errorf("evidence %+v", out.Evidence)
	}
}

func TestEvalClauseBothSidesMismatchIsDegradedNotHolding(t *testing.T) {
	e := newEnv(t, sshdSnap)
	out := e.evalClause(controls.Clause{Fact: "accounts.login_defs.pass_max_days", Op: "lte", Expected: 90}) // default_on both
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if out.Holds {
		t.Fatal("runtime 99999 > 90 must not hold")
	}
	if out.Degraded != "not applied" {
		t.Errorf("degraded=%q, want 'not applied' (persisted holds, runtime fails)", out.Degraded)
	}
	if len(out.Evidence) != 2 {
		t.Errorf("both sides must be evidence: %+v", out.Evidence)
	}
}

func TestEvalClauseScalarAndParam(t *testing.T) {
	e := newEnv(t, sshdSnap)
	e.params["want"] = true
	out := e.evalClause(controls.Clause{Fact: "services.ssh.installed", Op: "eq", Expected: "${want}"})
	if out.Err != nil || !out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
}

func TestEvalClauseRefusesNonOKEnvelope(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"denied","reason":"root"}}}}}`)
	out := e.evalClause(controls.Clause{Fact: "services.ssh.installed", Op: "eq", Expected: true})
	if out.Err == nil {
		t.Fatal("a non-ok envelope must never reach comparison")
	}
}

const walkSnap = `{"schema_version":1,"run":{},"facts":{"walk":{
  "world_writable": {"status":"ok","value":[
     {"path":"/var/tmp/legacy.sock","sticky":false,"package_declared":false},
     {"path":"/tmp","sticky":true,"package_declared":true},
     {"path":"/usr/lib/x","sticky":false,"package_declared":true}]},
  "complete": {"status":"ok","value":true}}}}`

func TestEvalCollectionEachProducesObservations(t *testing.T) {
	e := newEnv(t, walkSnap)
	cl := controls.Clause{Fact: "walk.world_writable", Op: "each", Subject: "path",
		Where:   &controls.Clause{Field: "sticky", Op: "eq", Expected: false},
		Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}
	out := e.evalClause(cl)
	if out.Err != nil {
		t.Fatal(out.Err)
	}
	if out.Holds {
		t.Fatal("legacy.sock is not package-declared; clause must not hold")
	}
	if len(out.Observations) != 2 {
		t.Fatalf("two non-sticky elements → two observations, got %+v", out.Observations)
	}
	if out.Observations[0].Subject != "file:/var/tmp/legacy.sock" || out.Observations[0].Verdict != "fail" {
		t.Errorf("%+v", out.Observations[0])
	}
	if out.Observations[1].Subject != "file:/usr/lib/x" || out.Observations[1].Verdict != "pass" {
		t.Errorf("%+v", out.Observations[1])
	}
}

func TestEvalCollectionNoneOnScalarList(t *testing.T) {
	e := newEnv(t, `{"schema_version":1,"run":{},"facts":{"files":{"etc_securetty":{"status":"ok","value":{},"lines":{"status":"ok","value":["console","tty1","pts/0"]}}}}}`)
	cl := controls.Clause{Fact: "files.etc_securetty.lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}
	out := e.evalClause(cl)
	if out.Err != nil || out.Holds {
		t.Fatalf("holds=%v err=%v", out.Holds, out.Err)
	}
	if len(out.Observations) != 1 || out.Observations[0].Actual != "pts/0" {
		t.Errorf("%+v", out.Observations)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/check/ -run 'TestEval' -v`
Expected: FAIL — undefined `env`, `evalClause`, `personasCollected`.

- [ ] **Step 3: Write `clause.go` and `collection.go`**

`internal/check/clause.go`:

```go
package check

import (
	"fmt"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// env is one evaluation's context: the snapshot, the registry, the parameter
// values in force and whether sshd personas were collected.
type env struct {
	snap     *facts.Snapshot
	reg      *facts.Registry
	params   map[string]any
	personas bool
}

// clauseOutcome is what one clause decided and the evidence it used.
type clauseOutcome struct {
	Holds        bool
	Evidence     []Evidence
	Observations []Observation
	Degraded     string
	Err          error
}

// personasCollected reads sshd.personas_collected; false when absent.
func personasCollected(s *facts.Snapshot, reg *facts.Registry) bool {
	r, err := reg.Resolve(s, "sshd.personas_collected")
	if err != nil || r.Envelope == nil || r.Envelope.Status != facts.StatusOK {
		return false
	}
	b, _ := r.Envelope.Value.(bool)
	return b
}

// evalClause evaluates one top-level clause whose facts the caller has
// already screened for non-ok statuses (spec §6.5 steps 6-8 run first). A
// non-ok envelope reaching here is therefore an internal error.
func (e *env) evalClause(cl controls.Clause) clauseOutcome {
	r, err := e.reg.Resolve(e.snap, cl.Fact)
	if err != nil {
		return clauseOutcome{Err: err}
	}
	expected, err := substitute(cl.Expected, e.params)
	if err != nil {
		return clauseOutcome{Err: err}
	}
	if cl.Op == "each" || cl.Op == "none" {
		if r.Envelope == nil || r.Envelope.Status != facts.StatusOK {
			return clauseOutcome{Err: fmt.Errorf("fact %s is not ok", cl.Fact)}
		}
		list, ok := r.Envelope.Value.([]any)
		if !ok {
			return clauseOutcome{Err: fmt.Errorf("fact %s is not a list", cl.Fact)}
		}
		return e.evalCollection(cl, r.Entry, list, r.Envelope.Source)
	}
	if r.Setting != nil {
		return e.evalSetting(cl, r, expected)
	}
	if r.Envelope.Status != facts.StatusOK {
		return clauseOutcome{Err: fmt.Errorf("fact %s has status %s", cl.Fact, r.Envelope.Status)}
	}
	holds, err := compare(cl.Op, r.Envelope.Value, expected, r.Entry.Type)
	if err != nil {
		return clauseOutcome{Err: fmt.Errorf("%s: %w", cl.Fact, err)}
	}
	return clauseOutcome{Holds: holds, Evidence: []Evidence{{Fact: cl.Fact, Status: facts.StatusOK, Value: r.Envelope.Value, Source: r.Envelope.Source}}}
}

// evalSetting applies `on` (default from the registry) to a two-home setting
// (spec §5.3, §6.3). With both, one side holding and the other not is
// reported as degraded so the derivation table can make it WARN.
func (e *env) evalSetting(cl controls.Clause, r facts.Resolved, expected any) clauseOutcome {
	on := cl.On
	if on == "" {
		on = r.Entry.DefaultOn
	}
	var degraded string
	if cl.Persona != "" && !e.personas {
		degraded = "personas not collected"
	}
	side := func(name string, env *facts.Envelope) (bool, Evidence, error) {
		if env == nil {
			return false, Evidence{Fact: cl.Fact, Status: facts.StatusAbsent, Side: name}, nil
		}
		if env.Status != facts.StatusOK {
			return false, Evidence{Fact: cl.Fact, Status: env.Status, Side: name, Source: env.Source}, fmt.Errorf("fact %s side %s has status %s", cl.Fact, name, env.Status)
		}
		ok, err := compare(cl.Op, env.Value, expected, r.Entry.Type)
		return ok, Evidence{Fact: cl.Fact, Status: facts.StatusOK, Value: env.Value, Source: env.Source, Side: name}, err
	}
	switch on {
	case "runtime", "persisted", "effective":
		var env *facts.Envelope
		switch on {
		case "runtime":
			env = r.Setting.Runtime
		case "persisted":
			env = r.Setting.Persisted
		default:
			env = r.Setting.Effective
		}
		if env == nil {
			return clauseOutcome{Err: fmt.Errorf("fact %s has no %s side", cl.Fact, on)}
		}
		holds, ev, err := side(on, env)
		if err != nil {
			return clauseOutcome{Err: err}
		}
		return clauseOutcome{Holds: holds, Evidence: []Evidence{ev}, Degraded: degraded}
	case "both":
		rh, rev, rerr := side("runtime", r.Setting.Runtime)
		ph, pev, perr := side("persisted", r.Setting.Persisted)
		if rerr != nil {
			return clauseOutcome{Err: rerr}
		}
		if perr != nil {
			return clauseOutcome{Err: perr}
		}
		out := clauseOutcome{Holds: rh && ph, Evidence: []Evidence{rev, pev}, Degraded: degraded}
		switch {
		case rh && !ph:
			out.Degraded = "reverts on reboot"
		case ph && !rh:
			out.Degraded = "not applied"
		}
		return out
	}
	return clauseOutcome{Err: fmt.Errorf("unknown side %q", on)}
}
```

`internal/check/collection.go`:

```go
package check

import (
	"fmt"
	"math"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// evalCollection implements each and none (spec §6.3, §6.4). Every element
// examined becomes an observation keyed <kind>:<subject value>.
func (e *env) evalCollection(cl controls.Clause, entry facts.Entry, list []any, src *facts.Source) clauseOutcome {
	out := clauseOutcome{Holds: true, Evidence: []Evidence{{Fact: cl.Fact, Status: facts.StatusOK, Value: fmt.Sprintf("%d elements", len(list)), Source: src}}}
	kind := entry.SubjectKind
	if kind == "" {
		kind = "item"
	}
	for i, elem := range list {
		subject := fmt.Sprintf("%s:%s", kind, subjectValue(cl.Subject, elem, i))
		switch cl.Op {
		case "each":
			if cl.Where != nil {
				sel, err := fieldClause(cl.Where, elem)
				if err != nil {
					return clauseOutcome{Err: err}
				}
				if !sel {
					continue
				}
			}
			ok, err := fieldClause(cl.Require, elem)
			if err != nil {
				return clauseOutcome{Err: err}
			}
			obs := Observation{Subject: subject, Expected: cl.Require.Expected, Actual: fieldValue(cl.Require.Field, elem), Verdict: "pass"}
			if !ok {
				obs.Verdict = "fail"
				out.Holds = false
			}
			out.Observations = append(out.Observations, obs)
		case "none":
			hit, err := fieldClause(cl.Where, elem)
			if err != nil {
				return clauseOutcome{Err: err}
			}
			if hit {
				out.Holds = false
				out.Observations = append(out.Observations, Observation{Subject: subject, Expected: fmt.Sprintf("not %s %v", cl.Where.Op, cl.Where.Expected), Actual: fieldValue(cl.Where.Field, elem), Verdict: "fail"})
			}
		}
	}
	return out
}

// subjectValue picks the element field named by `subject`, or the element
// itself for scalars; the index is the fallback so subjects stay unique.
func subjectValue(field string, elem any, i int) string {
	if field == "" {
		if s, ok := elem.(string); ok {
			return s
		}
		return fmt.Sprint(i)
	}
	if m, ok := elem.(map[string]any); ok {
		if v, ok := m[field]; ok {
			return fmt.Sprint(v)
		}
	}
	return fmt.Sprint(i)
}

func fieldValue(field string, elem any) any {
	if field == "" {
		return elem
	}
	if m, ok := elem.(map[string]any); ok {
		return m[field]
	}
	return nil
}

// fieldClause evaluates a where/require sub-clause against one element. The
// field's type is inferred from the decoded JSON value.
func fieldClause(sub *controls.Clause, elem any) (bool, error) {
	if sub == nil {
		return false, fmt.Errorf("sub-clause is nil")
	}
	v := fieldValue(sub.Field, elem)
	if v == nil {
		if sub.Op == "absent" {
			return true, nil
		}
		if sub.Op == "present" {
			return false, nil
		}
		return false, fmt.Errorf("element has no field %q", sub.Field)
	}
	typ := "string"
	switch x := v.(type) {
	case bool:
		typ = "bool"
	case float64:
		if x == math.Trunc(x) {
			typ = "int"
		}
	case []any:
		typ = "list<string>"
	}
	return compare(sub.Op, v, sub.Expected, typ)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/check/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/check/
git commit -m "Add clause evaluation with setting sides, personas and collections"
```

---

### Task 10: `Evaluate` and the 14-step status derivation

**Files:**
- Create: `internal/check/eval.go`, `internal/check/eval_test.go`, `internal/check/custom.go`
- Modify: `cmd/muster/controls.go` (pass `check.CustomFuncs()` to lint)

**Interfaces:**
- Consumes: `env`, `evalClause`, `facts.Registry`, `controls.Set`.
- Produces (package `check`):
  - `type Options struct { Params map[string]map[string]any }` — per-control parameter overrides (stage 3 tuning; nil in stage 1).
  - `func Evaluate(snap *facts.Snapshot, set *controls.Set, reg *facts.Registry, opts Options) []Result` — one `Result` per control in `set.Controls` order; never panics (a panic inside one control becomes `ERROR(internal_error)` for that control).
  - `func CustomFuncs() map[string]bool` — names of registered custom functions (empty in stage 1) and `type CustomFunc func(e *env, c *controls.Control) clauseOutcome`; registry `var customs = map[string]CustomFunc{}`.
  - The derivation implemented exactly as spec §6.5, in this order:
    1. `requires_facts` unmet → `ERROR(missing_fact)`.
    2. `automation: manual` → `MANUAL` with evidence for every fact the control names in `applies_when` (resolved, any status).
    3. any `applies_when` fact `missing|denied|timeout|error` or `truncated` → `ERROR` (code by status: missing→`missing_fact`, denied→`permission_denied`, timeout→`timeout`, error→`parse_error`, truncated→`truncated`).
    4. any `applies_when` fact `absent|unsupported`, or a clause false → `NOT_APPLICABLE` with evidence.
    5. `mechanisms`: choose the first whose `when` facts are all `ok` and clauses all hold; if none can be chosen because every `when` fact is `absent|unsupported` → `absent_means`; if a `when` fact is `missing|denied|timeout|error|truncated` → `ERROR` as in step 3.
    6. any fact referenced by the chosen `checks` `missing|denied|timeout|error` or `truncated` → `ERROR`.
    7. any such fact `unsupported` → `NOT_APPLICABLE` (`unsupported_env` in the reason).
    8. any such fact `absent` → `absent_means`.
    9. walk-based control (any referenced fact key starts with `walk.`) and `walk.complete` is `missing` or `absent` → `MANUAL` "run collect --deep".
    10. walk-based and `walk.complete` is `ok` with value `false` → `ERROR(walk_incomplete)`.
    11. a clause fails and `automation: partial` → `WARN`.
    12. a clause fails → `FAIL`.
    13. all hold but any clause outcome is degraded → `WARN` (reason = the degradation text; `Degraded` set).
    14. all hold → `PASS`.
  - `absent_means` mapping: `pass`→`PASS`, `fail`→`FAIL`, `not_applicable`→`NOT_APPLICABLE`, `manual`→`MANUAL`; reason names the absent fact.

- [ ] **Step 1: Write the failing table-driven test**

`internal/check/eval_test.go`:

```go
package check

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func snap(t *testing.T, factsJSON string) *facts.Snapshot {
	t.Helper()
	s, err := facts.Load(strings.NewReader(`{"schema_version":1,"run":{},"facts":` + factsJSON + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func one(c controls.Control) *controls.Set {
	c.Path = "test/" + c.ID + ".yaml"
	return &controls.Set{Version: "t", Digest: "sha256:0", Controls: []controls.Control{c}}
}

var reg = func() *facts.Registry { r, _ := facts.LoadRegistry(); return r }()

func telnetControl(automation, absentMeans string) controls.Control {
	return controls.Control{
		ID: "muster.service.telnet_disabled", Importance: "중", Category: "service", Automation: automation, AbsentMeans: absentMeans,
		RequiresFacts: ">=1",
		Checks:        []controls.Clause{{Fact: "services.telnet.reachable", Op: "eq", Expected: false}},
		Remediation:   &controls.Remediation{Risk: "none"},
	}
}

func TestDerivationTable(t *testing.T) {
	cases := []struct {
		name   string
		facts  string
		ctl    controls.Control
		status Status
		code   ReasonCode
	}{
		{"14 pass", `{"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`, telnetControl("auto", "pass"), PASS, ""},
		{"12 fail", `{"services":{"telnet":{"reachable":{"status":"ok","value":true}}}}`, telnetControl("auto", "pass"), FAIL, ""},
		{"11 partial warn", `{"services":{"telnet":{"reachable":{"status":"ok","value":true}}}}`, telnetControl("partial", "pass"), WARN, ""},
		{"8 absent means pass", `{"services":{"telnet":{"reachable":{"status":"absent"}}}}`, telnetControl("auto", "pass"), PASS, ""},
		{"8 absent means na", `{"services":{"telnet":{"reachable":{"status":"absent"}}}}`, telnetControl("auto", "not_applicable"), NotApplicable, ""},
		{"7 unsupported", `{"services":{"telnet":{"reachable":{"status":"unsupported","reason":"container"}}}}`, telnetControl("auto", "pass"), NotApplicable, UnsupportedEnv},
		{"6 denied", `{"services":{"telnet":{"reachable":{"status":"denied","reason":"needs root"}}}}`, telnetControl("auto", "pass"), ERROR, PermissionDenied},
		{"6 truncated", `{"services":{"telnet":{"reachable":{"status":"ok","value":false,"truncated":true}}}}`, telnetControl("auto", "pass"), ERROR, Truncated},
		{"6 missing key never absent_means", `{}`, telnetControl("auto", "pass"), ERROR, MissingFact},
		{"1 requires_facts unmet", `{"services":{"telnet":{"reachable":{"status":"ok","value":false}}}}`, func() controls.Control { c := telnetControl("auto", "pass"); c.RequiresFacts = ">=2"; return c }(), ERROR, MissingFact},
		{"2 manual", `{}`, controls.Control{ID: "muster.log.review", Importance: "하", Category: "log", Automation: "manual", ManualReason: "interview"}, MANUAL, ""},
		{"4 applies_when false", `{"services":{"ssh":{"installed":{"status":"ok","value":false}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), NotApplicable, ""},
		{"3 applies_when denied", `{"services":{"ssh":{"installed":{"status":"denied","reason":"root"}},"telnet":{"reachable":{"status":"ok","value":true}}}}`,
			func() controls.Control {
				c := telnetControl("auto", "pass")
				c.AppliesWhen = controls.ClauseList{{Fact: "services.ssh.installed", Op: "eq", Expected: true}}
				return c
			}(), ERROR, PermissionDenied},
		{"9 walk not run", `{"walk":{"world_writable":{"status":"ok","value":[]}}}`,
			controls.Control{ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "pass", Remediation: &controls.Remediation{Risk: "none"},
				Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path", Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}}},
			MANUAL, ""},
		{"10 walk incomplete", `{"walk":{"world_writable":{"status":"ok","value":[]},"complete":{"status":"ok","value":false}}}`,
			controls.Control{ID: "muster.file.world_writable", Importance: "상", Category: "file", Automation: "partial", AbsentMeans: "pass", Remediation: &controls.Remediation{Risk: "none"},
				Checks: []controls.Clause{{Fact: "walk.world_writable", Op: "each", Subject: "path", Require: &controls.Clause{Field: "package_declared", Op: "eq", Expected: true}}}},
			ERROR, WalkIncomplete},
		{"13 degraded warn", `{"sshd":{"personas_collected":{"status":"ok","value":false},"options":{"permit_root_login":{"effective":{"status":"ok","value":"no"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Persona: "root", Op: "eq", Expected: "no"}}},
			WARN, ""},
		{"5 mechanisms fallback", `{"files":{"etc_securetty":{"status":"ok","value":{},"lines":{"status":"ok","value":["console"]}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty.lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			PASS, ""},
		{"5 no mechanism applies", `{"files":{"etc_securetty":{"status":"absent"}},"sshd":{"options":{"permit_root_login":{"effective":{"status":"absent"}}}}}`,
			controls.Control{ID: "muster.account.root_remote_login", Importance: "상", Category: "account", Automation: "auto", AbsentMeans: "not_applicable", Remediation: &controls.Remediation{Risk: "lockout_risk"},
				Mechanisms: []controls.Mechanism{
					{When: controls.ClauseList{{Fact: "sshd.options.permit_root_login", Op: "present"}}, Checks: []controls.Clause{{Fact: "sshd.options.permit_root_login", On: "effective", Op: "eq", Expected: "no"}}},
					{When: controls.ClauseList{{Fact: "files.etc_securetty", Op: "present"}}, Checks: []controls.Clause{{Fact: "files.etc_securetty.lines", Op: "none", Where: &controls.Clause{Op: "matches", Expected: "^pts/"}}}},
				}},
			NotApplicable, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Evaluate(snap(t, c.facts), one(c.ctl), reg, Options{})
			if len(res) != 1 {
				t.Fatalf("%d results", len(res))
			}
			r := res[0]
			if r.Status != c.status || r.ReasonCode != c.code {
				t.Fatalf("status=%s code=%q reason=%q, want %s %q", r.Status, r.ReasonCode, r.Reason, c.status, c.code)
			}
			if r.Status != MANUAL && r.Status != PASS && r.Reason == "" && r.Status != NotApplicable {
				t.Errorf("non-pass result must carry a reason: %+v", r)
			}
			if (r.Status == FAIL || r.Status == WARN) && len(r.Evidence) == 0 && len(r.Observations) == 0 {
				t.Errorf("FAIL/WARN must carry evidence: %+v", r)
			}
		})
	}
}

func TestEvaluateIsolatesPanics(t *testing.T) {
	customs["__panic"] = func(e *env, c *controls.Control) clauseOutcome { panic("boom") }
	defer delete(customs, "__panic")
	c := controls.Control{ID: "muster.beyond.panic", Importance: "하", Category: "beyond", Automation: "auto", AbsentMeans: "fail", Custom: "__panic", Remediation: &controls.Remediation{Risk: "none"}}
	res := Evaluate(snap(t, `{}`), one(c), reg, Options{})
	if res[0].Status != ERROR || res[0].ReasonCode != InternalError {
		t.Fatalf("%+v", res[0])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/check/ -run 'TestDerivation|TestEvaluateIsolates' -v`
Expected: FAIL — undefined `Evaluate`, `Options`, `customs`.

- [ ] **Step 3: Write `custom.go` and `eval.go`**

`internal/check/custom.go`:

```go
package check

import "github.com/kun9497/muster/internal/controls"

// CustomFunc is the overflow for what the YAML vocabulary cannot express
// (spec §6.3). It reads only facts through e and returns a clause outcome.
type CustomFunc func(e *env, c *controls.Control) clauseOutcome

// customs is the registry lint consults through CustomFuncs(). Stage 1 has
// none; later stages register functions from an init() in this package.
var customs = map[string]CustomFunc{}

// CustomFuncs returns the registered names, for lint.
func CustomFuncs() map[string]bool {
	out := make(map[string]bool, len(customs))
	for name := range customs {
		out[name] = true
	}
	return out
}
```

`internal/check/eval.go`:

```go
package check

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// Options carries per-control parameter overrides (stage 3 tuning).
type Options struct {
	Params map[string]map[string]any
}

// Evaluate is the pure function of spec §4.2: one Result per control, in
// set order, never panicking (a panic inside one control is that control's
// ERROR(internal_error), spec §7.2).
func Evaluate(snap *facts.Snapshot, set *controls.Set, reg *facts.Registry, opts Options) []Result {
	out := make([]Result, 0, len(set.Controls))
	personas := personasCollected(snap, reg)
	for i := range set.Controls {
		c := &set.Controls[i]
		e := &env{snap: snap, reg: reg, params: ParamValues(c, opts.Params[c.ID]), personas: personas}
		out = append(out, evalOne(e, c))
	}
	return out
}

func evalOne(e *env, c *controls.Control) (r Result) {
	r = Result{ID: c.ID, TitleEn: c.TitleEn, TitleKo: c.TitleKo, Category: c.Category, Importance: c.Importance, Automation: c.Automation}
	defer func() {
		if p := recover(); p != nil {
			r.Status, r.ReasonCode, r.Reason = ERROR, InternalError, fmt.Sprintf("panic while evaluating: %v", p)
			r.Evidence, r.Observations = nil, nil
		}
	}()
	// Step 1.
	if need, ok := requiredVersion(c.RequiresFacts); ok && e.snap.SchemaVersion < need {
		return fail(r, ERROR, MissingFact, fmt.Sprintf("control requires facts schema >=%d; snapshot is %d", need, e.snap.SchemaVersion))
	}
	// Step 2.
	if c.Automation == "manual" || c.Automation == "not_applicable" {
		r.Evidence = e.evidenceFor(clauseFacts(c.AppliesWhen))
		if c.Automation == "manual" {
			r.Status, r.Reason = MANUAL, c.ManualReason
		} else {
			r.Status, r.Reason = NotApplicable, c.ManualReason
		}
		return r
	}
	// Steps 3-4.
	if len(c.AppliesWhen) > 0 {
		if res, done := e.screen(clauseFacts(c.AppliesWhen), &r, screenApplies); done {
			return res
		}
		for _, cl := range c.AppliesWhen {
			out := e.evalClause(cl)
			if out.Err != nil {
				return fail(r, ERROR, InternalError, out.Err.Error())
			}
			r.Evidence = append(r.Evidence, out.Evidence...)
			if !out.Holds {
				return fail(r, NotApplicable, "", "applies_when does not hold: "+describe(cl))
			}
		}
	}
	// Step 5: choose the judgment.
	checks := c.Checks
	if len(c.Mechanisms) > 0 {
		chosen := -1
		sawUnavailable := false
		for mi, m := range c.Mechanisms {
			keys := clauseFacts(m.When)
			st := e.worstStatus(keys)
			if st.hard {
				return fail(r, ERROR, st.code, st.reason)
			}
			if st.status == facts.StatusAbsent || st.status == facts.StatusUnsupported {
				sawUnavailable = true
				continue
			}
			holds := true
			for _, cl := range m.When {
				out := e.evalClause(cl)
				if out.Err != nil {
					return fail(r, ERROR, InternalError, out.Err.Error())
				}
				if !out.Holds {
					holds = false
					break
				}
			}
			if holds {
				chosen = mi
				break
			}
		}
		if chosen < 0 {
			if sawUnavailable || true {
				return e.absentMeans(r, c, "no mechanism applies to this host")
			}
		}
		checks = c.Mechanisms[chosen].Checks
		r.Mechanism = chosen + 1
	}
	if c.Custom != "" {
		fn, ok := customs[c.Custom]
		if !ok {
			return fail(r, ERROR, InternalError, "custom function "+c.Custom+" is not registered")
		}
		return finish(r, c, fn(e, c))
	}
	// Steps 6-8.
	keys := clauseFacts(checks)
	if st := e.worstStatus(keys); st.hard {
		return fail(r, ERROR, st.code, st.reason)
	} else if st.status == facts.StatusUnsupported {
		return fail(r, NotApplicable, UnsupportedEnv, st.reason)
	} else if st.status == facts.StatusAbsent {
		return e.absentMeans(r, c, st.reason)
	}
	// Steps 9-10.
	if walkBased(keys) {
		wc, _ := e.reg.Resolve(e.snap, "walk.complete")
		switch {
		case wc.Envelope == nil || wc.Envelope.Status == facts.StatusMissing || wc.Envelope.Status == facts.StatusAbsent:
			return fail(r, MANUAL, "", "the deep walk was not run; run collect --deep")
		case wc.Envelope.Status == facts.StatusOK:
			if done, _ := wc.Envelope.Value.(bool); !done {
				return fail(r, ERROR, WalkIncomplete, "the deep walk did not finish within its budget")
			}
		default:
			return fail(r, ERROR, codeFor(wc.Envelope), "walk.complete: "+wc.Envelope.Reason)
		}
	}
	// Steps 11-14.
	all := clauseOutcome{Holds: true}
	for _, cl := range checks {
		out := e.evalClause(cl)
		if out.Err != nil {
			return fail(r, ERROR, InternalError, out.Err.Error())
		}
		all.Evidence = append(all.Evidence, out.Evidence...)
		all.Observations = append(all.Observations, out.Observations...)
		if !out.Holds {
			all.Holds = false
			if all.Degraded == "" {
				all.Degraded = out.Degraded
			}
			all.Err = nil
			if r.Reason == "" {
				r.Reason = "clause does not hold: " + describe(cl)
			}
		}
		if out.Degraded != "" && all.Degraded == "" {
			all.Degraded = out.Degraded
		}
	}
	return finish(r, c, all)
}

// finish applies steps 11-14 to the combined clause outcome.
func finish(r Result, c *controls.Control, all clauseOutcome) Result {
	r.Evidence = append(r.Evidence, all.Evidence...)
	r.Observations = all.Observations
	if all.Err != nil {
		return fail(r, ERROR, InternalError, all.Err.Error())
	}
	if !all.Holds {
		if all.Degraded != "" {
			r.Degraded = all.Degraded
			if all.Degraded == "reverts on reboot" || all.Degraded == "not applied" {
				r.Status = WARN
				r.Reason = "setting holds on one side only: " + all.Degraded
				return r
			}
		}
		if c.Automation == "partial" {
			r.Status = WARN
			if r.Reason == "" {
				r.Reason = "observations need human review"
			}
			return r
		}
		r.Status = FAIL
		if r.Reason == "" {
			r.Reason = "a clause does not hold"
		}
		return r
	}
	if all.Degraded != "" {
		r.Status, r.Degraded, r.Reason = WARN, all.Degraded, "collection was degraded: "+all.Degraded
		return r
	}
	r.Status = PASS
	return r
}

type screening struct {
	hard   bool
	status facts.Status
	code   ReasonCode
	reason string
}

// worstStatus screens the facts a step references (spec §6.5 steps 3 and 6):
// hard failures first, then unsupported, then absent.
func (e *env) worstStatus(keys []string) screening {
	var soft screening
	for _, k := range keys {
		res, err := e.reg.Resolve(e.snap, k)
		if err != nil {
			return screening{hard: true, code: InternalError, reason: err.Error()}
		}
		envs := []*facts.Envelope{}
		if res.Setting != nil {
			for _, side := range []*facts.Envelope{res.Setting.Runtime, res.Setting.Persisted, res.Setting.Effective} {
				if side != nil {
					envs = append(envs, side)
				}
			}
			if len(envs) == 0 {
				envs = append(envs, facts.Missing(k))
			}
		} else {
			envs = append(envs, res.Envelope)
		}
		for _, env := range envs {
			switch env.Status {
			case facts.StatusMissing, facts.StatusDenied, facts.StatusTimeout, facts.StatusError:
				return screening{hard: true, status: env.Status, code: codeFor(env), reason: k + ": " + env.Reason}
			case facts.StatusOK:
				if env.Truncated {
					return screening{hard: true, status: env.Status, code: Truncated, reason: k + " was truncated at the read limit"}
				}
			case facts.StatusUnsupported:
				if soft.status != facts.StatusUnsupported {
					soft = screening{status: facts.StatusUnsupported, reason: k + ": " + env.Reason}
				}
			case facts.StatusAbsent:
				if soft.status == "" {
					soft = screening{status: facts.StatusAbsent, reason: k + " is absent on this host"}
				}
			}
		}
	}
	return soft
}

func screenApplies(st screening) (Status, ReasonCode) {
	if st.hard {
		return ERROR, st.code
	}
	return NotApplicable, ""
}

// screen applies worstStatus to applies_when facts (steps 3-4).
func (e *env) screen(keys []string, r *Result, _ func(screening) (Status, ReasonCode)) (Result, bool) {
	st := e.worstStatus(keys)
	if st.hard {
		return fail(*r, ERROR, st.code, st.reason), true
	}
	if st.status == facts.StatusAbsent || st.status == facts.StatusUnsupported {
		return fail(*r, NotApplicable, "", "applies_when: "+st.reason), true
	}
	return *r, false
}

func (e *env) absentMeans(r Result, c *controls.Control, why string) Result {
	switch c.AbsentMeans {
	case "pass":
		r.Status, r.Reason = PASS, "absent counts as pass: "+why
	case "fail":
		r.Status, r.Reason = FAIL, "absent counts as fail: "+why
	case "manual":
		r.Status, r.Reason = MANUAL, "absent needs review: "+why
	default:
		r.Status, r.Reason = NotApplicable, why
	}
	return r
}

func codeFor(env *facts.Envelope) ReasonCode {
	switch env.Status {
	case facts.StatusMissing:
		return MissingFact
	case facts.StatusDenied:
		return PermissionDenied
	case facts.StatusTimeout:
		return Timeout
	case facts.StatusError:
		return ParseError
	}
	if env.Truncated {
		return Truncated
	}
	return InternalError
}

func fail(r Result, s Status, code ReasonCode, reason string) Result {
	r.Status, r.ReasonCode, r.Reason = s, code, reason
	return r
}

func (e *env) evidenceFor(keys []string) []Evidence {
	var out []Evidence
	for _, k := range keys {
		res, err := e.reg.Resolve(e.snap, k)
		if err != nil {
			continue
		}
		if res.Envelope != nil {
			out = append(out, Evidence{Fact: k, Status: res.Envelope.Status, Value: res.Envelope.Value, Source: res.Envelope.Source})
		}
	}
	return out
}

func clauseFacts(cls []controls.Clause) []string {
	seen := map[string]bool{}
	var out []string
	for _, cl := range cls {
		if cl.Fact != "" && !seen[cl.Fact] {
			seen[cl.Fact] = true
			out = append(out, cl.Fact)
		}
	}
	return out
}

func walkBased(keys []string) bool {
	for _, k := range keys {
		if strings.HasPrefix(k, "walk.") {
			return true
		}
	}
	return false
}

func requiredVersion(s string) (int, bool) {
	if !strings.HasPrefix(s, ">=") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, ">="))
	return n, err == nil
}

func describe(cl controls.Clause) string {
	return fmt.Sprintf("%s %s %v", cl.Fact, cl.Op, cl.Expected)
}
```

Replace `map[string]bool{}` in `cmd/muster/controls.go` with `check.CustomFuncs()` and add the import `"github.com/kun9497/muster/internal/check"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/check/ -v && go test ./cmd/muster/`
Expected: PASS for all derivation cases and the panic isolation test; the import-contract test still passes.

- [ ] **Step 5: Commit**

```bash
git add internal/check/ cmd/muster/controls.go
git commit -m "Add Evaluate with the fixed 14-step status derivation"
```

---

### Task 11: Waivers — load, validate, match, apply

**Files:**
- Create: `internal/waiver/waiver.go`, `internal/waiver/waiver_test.go`

**Interfaces:**
- Consumes: `check.Result`, `check.Status`, `check.WaiverNote`.
- Produces (package `waiver`):
  - `type Waiver struct { Control, Subject, Reason, Expires string }` (yaml tags `control, subject, reason, expires`).
  - `type File struct { Waivers []Waiver }` (tag `waivers`) plus `Path` and `Digest` fields filled by `Load`.
  - `var ErrInvalid = errors.New("invalid waiver file")`.
  - `func Load(r io.Reader, path string) (*File, error)` — strict decode; errors (wrapping `ErrInvalid`) for: unknown key, empty `control`, empty or whitespace `reason`, `expires` not `YYYY-MM-DD`.
  - `func (f *File) Apply(results []check.Result, known map[string]bool, now time.Time, warn func(string)) Applied` — for each result with status `FAIL` or `WARN` and a matching, unexpired waiver (control equal; subject empty or equal to one of the result's failing observation subjects, in which case only that observation is waived and the result stays `FAIL`/`WARN` if other failing observations remain), sets `Status=WAIVED` and `Waiver=&WaiverNote{Applied: true, Reason, Expires, Subject}`; for a matching waiver on `ERROR`, `NOT_APPLICABLE`, `MANUAL` or `PASS`, sets `Waiver=&WaiverNote{Applied: false, NotAppliedBecause: "status <S> is not waivable"}` and leaves the status; an expired waiver never applies and `warn("waiver for <control> expired on <date>")`; a waiver whose control id is not in `known` → `warn("waiver names unknown control <id>")`.
  - `type Applied struct { Applied, NotApplied, Expired, Unknown int; ExpiringSoon int }` — `ExpiringSoon` counts applied waivers expiring within 30 days of `now`.
  - Subject-level semantics: a waiver with `subject` removes that observation from the result's failing set (verdict stays recorded, `Observation.Verdict` becomes `"waived"`); if no failing observation remains the result becomes `WAIVED`.

- [ ] **Step 1: Write the failing tests**

`internal/waiver/waiver_test.go`:

```go
package waiver

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/check"
)

var now = time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

func TestLoadRefusesReasonlessUnknownKeyAndBadDate(t *testing.T) {
	bad := []string{
		"waivers:\n  - control: muster.a.b\n    reason: ''\n",
		"waivers:\n  - control: muster.a.b\n    reason: ok\n    expries: 2026-12-31\n",
		"waivers:\n  - control: muster.a.b\n    reason: ok\n    expires: 12/31/2026\n",
		"waivers:\n  - reason: ok\n",
	}
	for _, in := range bad {
		if _, err := Load(strings.NewReader(in), "w.yaml"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: err=%v want ErrInvalid", in, err)
		}
	}
}

func TestLoadGoodFileHasDigest(t *testing.T) {
	f, err := Load(strings.NewReader("waivers:\n  - control: muster.a.b\n    reason: because\n    expires: 2026-12-31\n"), "w.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if f.Path != "w.yaml" || !strings.HasPrefix(f.Digest, "sha256:") || len(f.Waivers) != 1 {
		t.Fatalf("%+v", f)
	}
}

func results() []check.Result {
	return []check.Result{
		{ID: "muster.a.fail", Status: check.FAIL, Reason: "x"},
		{ID: "muster.a.err", Status: check.ERROR, ReasonCode: check.PermissionDenied},
		{ID: "muster.a.obs", Status: check.WARN, Observations: []check.Observation{
			{Subject: "file:/a", Verdict: "fail"}, {Subject: "file:/b", Verdict: "fail"}}},
	}
}

func TestApplyWaivesFailNeverError(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.fail\n    reason: r\n  - control: muster.a.err\n    reason: r\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[0].Status != check.WAIVED || rs[0].Waiver == nil || !rs[0].Waiver.Applied {
		t.Errorf("FAIL must be waived: %+v", rs[0])
	}
	if rs[1].Status != check.ERROR || rs[1].Waiver == nil || rs[1].Waiver.Applied || !strings.Contains(rs[1].Waiver.NotAppliedBecause, "ERROR") {
		t.Errorf("ERROR must never be waived: %+v", rs[1])
	}
	if a.Applied != 1 || a.NotApplied != 1 || len(warnings) != 0 {
		t.Errorf("%+v %v", a, warnings)
	}
}

func TestApplySubjectLevelAndExpiry(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r\n    expires: 2026-09-10\n  - control: muster.a.fail\n    reason: r\n    expires: 2026-01-01\n  - control: muster.zzz\n    reason: r\n"), "w.yaml")
	rs := results()
	var warnings []string
	a := f.Apply(rs, map[string]bool{"muster.a.fail": true, "muster.a.err": true, "muster.a.obs": true}, now, func(s string) { warnings = append(warnings, s) })
	if rs[2].Status != check.WARN || rs[2].Observations[0].Verdict != "waived" || rs[2].Observations[1].Verdict != "fail" {
		t.Errorf("subject waiver must waive one observation and keep the result: %+v", rs[2])
	}
	if rs[0].Status != check.FAIL {
		t.Errorf("expired waiver must not apply: %+v", rs[0])
	}
	if a.Expired != 1 || a.Unknown != 1 || a.ExpiringSoon != 1 {
		t.Errorf("%+v", a)
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "expired") || !strings.Contains(joined, "unknown control") {
		t.Errorf("warnings: %v", warnings)
	}
}

func TestApplyWaivesResultWhenAllObservationsWaived(t *testing.T) {
	f, _ := Load(strings.NewReader("waivers:\n  - control: muster.a.obs\n    subject: file:/a\n    reason: r\n  - control: muster.a.obs\n    subject: file:/b\n    reason: r\n"), "w.yaml")
	rs := results()
	f.Apply(rs, map[string]bool{"muster.a.obs": true}, now, func(string) {})
	if rs[2].Status != check.WAIVED {
		t.Errorf("%+v", rs[2])
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/waiver/ -v`
Expected: FAIL — package missing.

- [ ] **Step 3: Write `waiver.go`**

```go
// Package waiver loads waiver files and applies them after evaluation
// (spec §6.7, D12): a waiver is counted and reasoned, never silent, and never
// covers an ERROR.
package waiver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/check"
)

var ErrInvalid = errors.New("invalid waiver file")

type Waiver struct {
	Control string `yaml:"control"`
	Subject string `yaml:"subject,omitempty"`
	Reason  string `yaml:"reason"`
	Expires string `yaml:"expires,omitempty"` // YYYY-MM-DD, inclusive
}

type File struct {
	Waivers []Waiver `yaml:"waivers"`
	Path    string   `yaml:"-"`
	Digest  string   `yaml:"-"`
}

// Applied is the tally shown in every summary.
type Applied struct {
	Applied, NotApplied, Expired, Unknown, ExpiringSoon int
}

// Load decodes strictly and validates every rule of spec §6.7.
func Load(r io.Reader, path string) (*File, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	for i, w := range f.Waivers {
		if strings.TrimSpace(w.Control) == "" {
			return nil, fmt.Errorf("%w: %s: waiver %d names no control", ErrInvalid, path, i+1)
		}
		if strings.TrimSpace(w.Reason) == "" {
			return nil, fmt.Errorf("%w: %s: waiver %d for %s has no reason", ErrInvalid, path, i+1, w.Control)
		}
		if w.Expires != "" {
			if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
				return nil, fmt.Errorf("%w: %s: waiver %d expires %q is not YYYY-MM-DD", ErrInvalid, path, i+1, w.Expires)
			}
		}
	}
	sum := sha256.Sum256(data)
	f.Path, f.Digest = path, "sha256:"+hex.EncodeToString(sum[:])
	return &f, nil
}

func (w Waiver) expired(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	exp, _ := time.Parse("2006-01-02", w.Expires)
	return !now.Before(exp.AddDate(0, 0, 1)) // inclusive of the named day
}

func (w Waiver) expiringSoon(now time.Time) bool {
	if w.Expires == "" {
		return false
	}
	exp, _ := time.Parse("2006-01-02", w.Expires)
	return exp.Before(now.AddDate(0, 0, 30))
}

// Apply mutates results in place. Only FAIL and WARN are waivable; a waiver
// that matches any other status is recorded as not applied so the reader
// sees it, and the exit code is untouched.
func (f *File) Apply(results []check.Result, known map[string]bool, now time.Time, warn func(string)) Applied {
	var tally Applied
	byControl := map[string][]Waiver{}
	for _, w := range f.Waivers {
		if !known[w.Control] {
			tally.Unknown++
			warn(fmt.Sprintf("waiver names unknown control %s", w.Control))
			continue
		}
		if w.expired(now) {
			tally.Expired++
			warn(fmt.Sprintf("waiver for %s expired on %s and no longer applies", w.Control, w.Expires))
			continue
		}
		byControl[w.Control] = append(byControl[w.Control], w)
	}
	for i := range results {
		r := &results[i]
		ws := byControl[r.ID]
		if len(ws) == 0 {
			continue
		}
		if r.Status != check.FAIL && r.Status != check.WARN {
			r.Waiver = &check.WaiverNote{Applied: false, Reason: ws[0].Reason, NotAppliedBecause: fmt.Sprintf("status %s is not waivable", r.Status)}
			tally.NotApplied++
			continue
		}
		whole := false
		for _, w := range ws {
			if w.Subject == "" {
				whole = true
				r.Waiver = &check.WaiverNote{Applied: true, Reason: w.Reason, Expires: w.Expires}
				if w.expiringSoon(now) {
					tally.ExpiringSoon++
				}
				break
			}
		}
		if whole {
			r.Status = check.WAIVED
			tally.Applied++
			continue
		}
		remaining := 0
		for oi := range r.Observations {
			o := &r.Observations[oi]
			if o.Verdict != "fail" {
				continue
			}
			for _, w := range ws {
				if w.Subject == o.Subject {
					o.Verdict = "waived"
					r.Waiver = &check.WaiverNote{Applied: true, Reason: w.Reason, Expires: w.Expires, Subject: w.Subject}
					if w.expiringSoon(now) {
						tally.ExpiringSoon++
					}
					break
				}
			}
			if o.Verdict == "fail" {
				remaining++
			}
		}
		if r.Waiver != nil && r.Waiver.Applied {
			tally.Applied++
			if remaining == 0 {
				r.Status = check.WAIVED
			}
		}
	}
	return tally
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/waiver/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/waiver/
git commit -m "Add waiver loading and post-evaluation application"
```

---

### Task 12: Report assembly, severity, summary and the JSON renderer

**Files:**
- Create: `internal/report/report.go`, `internal/report/json.go`, `internal/report/report_test.go`, `internal/report/testdata/basic.json.golden`

**Interfaces:**
- Consumes: `check.Result`, `facts.Run`, `waiver.Applied`.
- Produces (package `report`):
  - `func Severity(importance string) string` — `상`→`high`, `중`→`medium`, `하`→`low`, anything else → `low`.
  - `type CheckBlock struct { MusterVersion, Commit, ControlsVersion, ControlsDigest, SnapshotDigest, GuideEdition string; Waivers WaiversBlock; Params map[string]map[string]any }` (tags `muster_version, commit, controls_version, controls_digest, snapshot_digest, guide_edition, waivers, params`; `params` omitempty). `type WaiversBlock struct { Path, Digest string; Applied, NotApplied, Expired, Unknown, ExpiringSoon int }` (tags `path, digest, applied, not_applied, expired, unknown, expiring_soon`).
  - `type Summary struct { Automatic map[string]StatusCounts; ManualReview int; Undecidable UndecidableCounts; FactsFailed int; WaiversExpiringSoon int }` where `Automatic` is keyed by severity `high|medium|low` — rendered from a struct, not a map, in JSON: use `type SeverityCounts struct { High, Medium, Low StatusCounts }` (tags `high, medium, low`) instead of a map. `type StatusCounts struct { Pass, Fail, Warn int }` (tags `pass, fail, warn`). `type UndecidableCounts struct { Error, NotApplicable, Waived int }` (tags `error, not_applicable, waived`). Final: `type Summary struct { Automatic SeverityCounts; ManualReview int; Undecidable UndecidableCounts; FactsFailed int; WaiversExpiringSoon int }` (tags `automatic, manual_review, undecidable, facts_failed, waivers_expiring_soon`). `ManualReview` counts `MANUAL` results plus `WARN` results whose `Automation` is `partial`; those `WARN`s are excluded from `Automatic`.
  - `type Row struct { check.Result; Severity string }` — JSON flattens the embedded result and adds `severity`.
  - `type Report struct { SchemaVersion int; Run facts.Run; Check CheckBlock; Summary Summary; Results []Row }` (tags `schema_version, run, check, summary, results`); `SchemaVersion` is the report's own schema, constant `ReportSchemaVersion = 1`.
  - `func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock) *Report` — computes severity per row, sorts rows by severity (`high` first) then id, computes the summary, sets `FactsFailed` from `run.collectors` with status other than `ok` plus `run.partial_failures`.
  - `func WriteJSON(w io.Writer, r *Report) error` — `json.NewEncoder` with `SetIndent("", "  ")` and `SetEscapeHTML(false)`; output ends with a newline.
  - Determinism: no maps except `Params` (rendered with sorted keys by `encoding/json`, which sorts map keys — acceptable) — everything else is structs and slices.

- [ ] **Step 1: Write the failing golden test**

`internal/report/report_test.go`:

```go
package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sampleReport(t *testing.T) *Report {
	t.Helper()
	snap, err := facts.Load(strings.NewReader(`{"schema_version":1,"run":{"muster_version":"0.1.0","collected_at":"2026-09-02T06:00:00Z",
	  "host":{"hostname":"web-01"},"collectors":[{"name":"sshd","status":"ok","ms":41},{"name":"walk","status":"skipped","ms":0}],
	  "complete":true,"partial_failures":[]},"facts":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	results := []check.Result{
		{ID: "muster.file.world_writable", Importance: "상", Automation: "partial", Status: check.WARN, Reason: "observations need human review",
			Observations: []check.Observation{{Subject: "file:/var/tmp/x", Expected: true, Actual: false, Verdict: "fail"}}},
		{ID: "muster.service.telnet_disabled", Importance: "중", Automation: "auto", Status: check.PASS},
		{ID: "muster.account.root_remote_login", Importance: "상", Automation: "auto", Status: check.FAIL, Reason: "clause does not hold",
			Evidence: []check.Evidence{{Fact: "sshd.options.permit_root_login", Status: facts.StatusOK, Value: "yes", Side: "effective",
				Source: &facts.Source{Kind: "file", Path: "/etc/ssh/sshd_config", Line: 40, Raw: "PermitRootLogin yes"}}}},
		{ID: "muster.file.passwd_permissions", Importance: "상", Automation: "auto", Status: check.ERROR, ReasonCode: check.PermissionDenied, Reason: "needs root"},
		{ID: "muster.account.password_policy", Importance: "상", Automation: "auto", Status: check.WAIVED, Waiver: &check.WaiverNote{Applied: true, Reason: "r", Expires: "2026-09-20"}},
		{ID: "muster.log.review", Importance: "하", Automation: "manual", Status: check.MANUAL, Reason: "interview"},
	}
	cb := CheckBlock{MusterVersion: "0.1.0", Commit: "abc1234", ControlsVersion: "kisa-unix-2026+2026.09.02", ControlsDigest: "sha256:c", SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026",
		Waivers: WaiversBlock{Path: "w.yaml", Digest: "sha256:w", Applied: 1, ExpiringSoon: 1}}
	return Build(snap, results, cb)
}

func TestBuildSortsAndSummarises(t *testing.T) {
	r := sampleReport(t)
	ids := []string{}
	for _, row := range r.Results {
		ids = append(ids, row.ID)
	}
	want := "muster.account.password_policy,muster.account.root_remote_login,muster.file.passwd_permissions,muster.file.world_writable,muster.service.telnet_disabled,muster.log.review"
	if strings.Join(ids, ",") != want {
		t.Fatalf("order %v", ids)
	}
	s := r.Summary
	if s.Automatic.High.Fail != 1 || s.Automatic.Medium.Pass != 1 || s.Automatic.High.Warn != 0 {
		t.Errorf("automatic %+v", s.Automatic)
	}
	if s.ManualReview != 2 { // MANUAL + partial WARN
		t.Errorf("manual review %d", s.ManualReview)
	}
	if s.Undecidable.Error != 1 || s.Undecidable.Waived != 1 || s.FactsFailed != 1 || s.WaiversExpiringSoon != 1 {
		t.Errorf("undecidable %+v facts_failed %d expiring %d", s.Undecidable, s.FactsFailed, s.WaiversExpiringSoon)
	}
	if r.Results[0].Severity != "high" || r.Results[5].Severity != "low" {
		t.Errorf("severity %+v", r.Results)
	}
}

func TestJSONIsDeterministicAndMatchesGolden(t *testing.T) {
	var a, b bytes.Buffer
	if err := WriteJSON(&a, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, sampleReport(t)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two renders of the same input differ")
	}
	if !bytes.HasSuffix(a.Bytes(), []byte("\n")) {
		t.Error("output must end with a newline")
	}
	golden := filepath.Join("testdata", "basic.json.golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(golden, a.Bytes(), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(a.Bytes(), want) {
		t.Fatalf("JSON differs from golden; if intended run: go test ./internal/report -run TestJSON -update\n%s", a.String())
	}
}

func TestSeverityMapping(t *testing.T) {
	for in, want := range map[string]string{"상": "high", "중": "medium", "하": "low", "": "low"} {
		if got := Severity(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/report/ -v`
Expected: FAIL — package missing.

- [ ] **Step 3: Write `report.go` and `json.go`**

`internal/report/report.go`:

```go
// Package report assembles results into the output contract of spec §9 and
// renders it as JSON or a table. Same input, same bytes (D20).
package report

import (
	"sort"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/facts"
)

// ReportSchemaVersion is the result JSON's own schema version.
const ReportSchemaVersion = 1

// Severity derives the sort and filter key from KISA importance (spec §9).
func Severity(importance string) string {
	switch importance {
	case "상":
		return "high"
	case "중":
		return "medium"
	default:
		return "low"
	}
}

var severityRank = map[string]int{"high": 0, "medium": 1, "low": 2}

type WaiversBlock struct {
	Path         string `json:"path,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Applied      int    `json:"applied"`
	NotApplied   int    `json:"not_applied"`
	Expired      int    `json:"expired"`
	Unknown      int    `json:"unknown"`
	ExpiringSoon int    `json:"expiring_soon"`
}

// CheckBlock names the evaluating binary, control set, snapshot and waivers
// (spec §9 "Result provenance").
type CheckBlock struct {
	MusterVersion   string                    `json:"muster_version"`
	Commit          string                    `json:"commit"`
	ControlsVersion string                    `json:"controls_version"`
	ControlsDigest  string                    `json:"controls_digest"`
	SnapshotDigest  string                    `json:"snapshot_digest"`
	GuideEdition    string                    `json:"guide_edition"`
	Waivers         WaiversBlock              `json:"waivers"`
	Params          map[string]map[string]any `json:"params,omitempty"`
}

type StatusCounts struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Warn int `json:"warn"`
}

type SeverityCounts struct {
	High   StatusCounts `json:"high"`
	Medium StatusCounts `json:"medium"`
	Low    StatusCounts `json:"low"`
}

type UndecidableCounts struct {
	Error         int `json:"error"`
	NotApplicable int `json:"not_applicable"`
	Waived        int `json:"waived"`
}

// Summary is the three-part summary of spec §9: automatic verdicts by
// severity, items under manual review, undecidable items.
type Summary struct {
	Automatic           SeverityCounts    `json:"automatic"`
	ManualReview        int               `json:"manual_review"`
	Undecidable         UndecidableCounts `json:"undecidable"`
	FactsFailed         int               `json:"facts_failed"`
	WaiversExpiringSoon int               `json:"waivers_expiring_soon"`
}

// Row is one result plus its derived severity.
type Row struct {
	check.Result
	Severity string `json:"severity"`
}

type Report struct {
	SchemaVersion int        `json:"schema_version"`
	Run           facts.Run  `json:"run"`
	Check         CheckBlock `json:"check"`
	Summary       Summary    `json:"summary"`
	Results       []Row      `json:"results"`
}

// Build sorts by severity then id and computes the summary.
func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock) *Report {
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		rows = append(rows, Row{Result: r, Severity: Severity(r.Importance)})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if severityRank[rows[i].Severity] != severityRank[rows[j].Severity] {
			return severityRank[rows[i].Severity] < severityRank[rows[j].Severity]
		}
		return rows[i].ID < rows[j].ID
	})
	var s Summary
	for _, row := range rows {
		bucket := &s.Automatic.Low
		switch row.Severity {
		case "high":
			bucket = &s.Automatic.High
		case "medium":
			bucket = &s.Automatic.Medium
		}
		switch row.Status {
		case check.PASS:
			bucket.Pass++
		case check.FAIL:
			bucket.Fail++
		case check.WARN:
			if row.Automation == "partial" {
				s.ManualReview++
			} else {
				bucket.Warn++
			}
		case check.MANUAL:
			s.ManualReview++
		case check.ERROR:
			s.Undecidable.Error++
		case check.NotApplicable:
			s.Undecidable.NotApplicable++
		case check.WAIVED:
			s.Undecidable.Waived++
		}
	}
	for _, c := range snap.Run.Collectors {
		if c.Status != "ok" {
			s.FactsFailed++
		}
	}
	s.WaiversExpiringSoon = cb.Waivers.ExpiringSoon
	return &Report{SchemaVersion: ReportSchemaVersion, Run: snap.Run, Check: cb, Summary: s, Results: rows}
}
```

`internal/report/json.go`:

```go
package report

import (
	"encoding/json"
	"io"
)

// WriteJSON renders the report as indented JSON with a trailing newline.
// encoding/json sorts map keys, so the only map (check.params) is stable too.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
```

- [ ] **Step 4: Create the golden, then run the tests**

Run: `go test ./internal/report/ -run TestJSON -update && go test ./internal/report/ -v`
Expected: PASS. Open `internal/report/testdata/basic.json.golden` and confirm `results` starts with `muster.account.password_policy` (high, WAIVED) and the summary reads `"high":{"pass":0,"fail":1,"warn":0}`, `"manual_review":2`.

- [ ] **Step 5: Commit**

```bash
git add internal/report/
git commit -m "Add report assembly, severity, summary and the JSON renderer"
```

---

### Task 13: Table renderer with East Asian width, escaping and colour rules

**Files:**
- Create: `internal/report/table.go`, `internal/report/width.go`, `internal/report/table_test.go`, `internal/report/testdata/basic.table.golden`, `internal/report/testdata/basic.table.narrow.golden`

**Interfaces:**
- Consumes: `Report`.
- Produces (package `report`):
  - `type TableOptions struct { Color bool; Width int; Quiet bool; MaxObservations int }` — `Width` 0 means 100; `MaxObservations` 0 means 5.
  - `func WriteTable(w io.Writer, r *Report, o TableOptions) error` — writes the summary block, then one row per result: `STATUS  SEV   ID  TITLE(ko if present, else en)  REASON`, then indented evidence (`fact = value  (path:line)`) and up to `MaxObservations` observations for FAIL/WARN, with `(+N more, use --all)` when truncated; `Quiet` hides `PASS`, `NOT_APPLICABLE`, `WAIVED` and `MANUAL` rows. Colour only when `o.Color`.
  - `func escape(s string) string` — replaces C0 controls except `\t`, C1 controls, and ESC-led sequences with `\uXXXX`/`\x1b` escapes; replaces `\r` with `\\r`; truncates to 200 runes with `…`.
  - `func displayWidth(s string) int` and `func padRight(s string, w int) string` in `width.go` — East Asian wide ranges count 2: Hangul Jamo/Syllables (`0x1100–0x115F`, `0xAC00–0xD7A3`), CJK Unified and extensions (`0x2E80–0x303E`, `0x3041–0x33FF`, `0x3400–0x4DBF`, `0x4E00–0x9FFF`, `0xF900–0xFAFF`), fullwidth forms (`0xFF00–0xFF60`, `0xFFE0–0xFFE6`), and `0x20000–0x3FFFD`; combining marks (`0x0300–0x036F`) count 0.
  - `func ColorEnabled(flag string, noColorEnv, term string, isTTY bool) bool` — `flag` is `""|"auto"|"always"|"never"`; `always` → true; `never` → false; `auto`/`""` → `isTTY && noColorEnv == "" && term != "dumb"`.

- [ ] **Step 1: Write the failing tests**

`internal/report/table_test.go`:

```go
package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisplayWidthCountsHangulAsTwo(t *testing.T) {
	if w := displayWidth("root 계정"); w != 9 { // 4 + 1 + 2*2
		t.Errorf("width %d", w)
	}
	if got := padRight("계정", 6); got != "계정  " {
		t.Errorf("%q", got)
	}
}

func TestEscapeNeutralisesTerminalSequences(t *testing.T) {
	in := "PASS\x1b[32m fake \r\x07 tab\tok"
	got := escape(in)
	if strings.ContainsAny(got, "\x1b\r\x07") {
		t.Fatalf("control bytes survived: %q", got)
	}
	if !strings.Contains(got, "\t") {
		t.Error("tab must survive")
	}
	long := strings.Repeat("가", 300)
	if w := len([]rune(escape(long))); w != 201 {
		t.Errorf("truncation to 200 runes + ellipsis, got %d", w)
	}
}

func TestColorEnabled(t *testing.T) {
	if ColorEnabled("always", "1", "dumb", false) != true {
		t.Error("always wins")
	}
	if ColorEnabled("never", "", "xterm", true) != false {
		t.Error("never wins")
	}
	if ColorEnabled("auto", "", "xterm", true) != true || ColorEnabled("auto", "1", "xterm", true) != false ||
		ColorEnabled("auto", "", "dumb", true) != false || ColorEnabled("", "", "xterm", false) != false {
		t.Error("auto must honour TTY, NO_COLOR and TERM=dumb")
	}
}

func TestTableGoldenWideAndNarrow(t *testing.T) {
	r := sampleReport(t)
	for _, c := range []struct {
		name string
		opts TableOptions
	}{{"basic.table.golden", TableOptions{Width: 100}}, {"basic.table.narrow.golden", TableOptions{Width: 40}}} {
		var buf bytes.Buffer
		if err := WriteTable(&buf, r, c.opts); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(buf.Bytes(), []byte("\x1b")) {
			t.Error("no colour without Color=true")
		}
		golden := filepath.Join("testdata", c.name)
		if *update {
			os.WriteFile(golden, buf.Bytes(), 0o644)
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read golden (run with -update to create): %v", err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s differs:\n%s", c.name, buf.String())
		}
	}
}

func TestTableQuietHidesPassAndManual(t *testing.T) {
	var buf bytes.Buffer
	WriteTable(&buf, sampleReport(t), TableOptions{Quiet: true})
	out := buf.String()
	if strings.Contains(out, "muster.service.telnet_disabled") || strings.Contains(out, "muster.log.review") {
		t.Errorf("quiet must hide PASS and MANUAL rows:\n%s", out)
	}
	if !strings.Contains(out, "muster.account.root_remote_login") || !strings.Contains(out, "muster.file.passwd_permissions") {
		t.Errorf("quiet must keep FAIL and ERROR rows:\n%s", out)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/report/ -run 'TestDisplayWidth|TestEscape|TestColor|TestTable' -v`
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Write `width.go` and `table.go`**

`internal/report/width.go`:

```go
package report

import "strings"

// wide lists East Asian wide/fullwidth ranges (inclusive). Korean item titles
// are the common case (spec §9).
var wide = [][2]rune{
	{0x1100, 0x115F}, {0x2E80, 0x303E}, {0x3041, 0x33FF}, {0x3400, 0x4DBF},
	{0x4E00, 0x9FFF}, {0xAC00, 0xD7A3}, {0xF900, 0xFAFF}, {0xFF00, 0xFF60},
	{0xFFE0, 0xFFE6}, {0x20000, 0x3FFFD},
}

func runeWidth(r rune) int {
	if r >= 0x0300 && r <= 0x036F {
		return 0
	}
	for _, rg := range wide {
		if r >= rg[0] && r <= rg[1] {
			return 2
		}
	}
	return 1
}

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func padRight(s string, width int) string {
	if d := width - displayWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// truncateWidth cuts s so it fits width, appending "…" if anything was cut.
func truncateWidth(s string, width int) string {
	if displayWidth(s) <= width {
		return s
	}
	var b strings.Builder
	w := 0
	for _, r := range s {
		rw := runeWidth(r)
		if w+rw > width-1 {
			break
		}
		b.WriteRune(r)
		w += rw
	}
	return b.String() + "…"
}
```

`internal/report/table.go`:

```go
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/muster/internal/check"
)

type TableOptions struct {
	Color           bool
	Width           int
	Quiet           bool
	MaxObservations int
}

// ColorEnabled applies the rules of spec §9: --color=always/never win;
// otherwise colour only on a TTY without NO_COLOR and not TERM=dumb.
func ColorEnabled(flag, noColorEnv, term string, isTTY bool) bool {
	switch flag {
	case "always":
		return true
	case "never":
		return false
	}
	return isTTY && noColorEnv == "" && term != "dumb"
}

const maxCell = 200

// escape neutralises anything a hostile snapshot could use to repaint the
// terminal (spec §7.4): C0/C1 controls, ESC, CR; tabs survive.
func escape(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxCell {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r == '\t':
			b.WriteRune(r)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == 0x1b:
			b.WriteString(`\x1b`)
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var statusColor = map[check.Status]string{
	check.PASS: "32", check.FAIL: "31", check.WARN: "33", check.ERROR: "35",
	check.MANUAL: "36", check.NotApplicable: "90", check.WAIVED: "90",
}

func paint(on bool, code, s string) string {
	if !on || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func hidden(o TableOptions, s check.Status) bool {
	if !o.Quiet {
		return false
	}
	switch s {
	case check.PASS, check.NotApplicable, check.WAIVED, check.MANUAL:
		return true
	}
	return false
}

// WriteTable renders the summary block and one row per result (spec §9).
func WriteTable(w io.Writer, r *Report, o TableOptions) error {
	if o.Width <= 0 {
		o.Width = 100
	}
	if o.MaxObservations <= 0 {
		o.MaxObservations = 5
	}
	s := r.Summary
	fmt.Fprintf(w, "muster %s · controls %s · guide %s · host %s · collected %s\n",
		r.Check.MusterVersion, r.Check.ControlsVersion, r.Check.GuideEdition, escape(r.Run.Host.Hostname), r.Run.CollectedAt)
	fmt.Fprintf(w, "automatic  high %d/%d/%d  medium %d/%d/%d  low %d/%d/%d  (pass/fail/warn)\n",
		s.Automatic.High.Pass, s.Automatic.High.Fail, s.Automatic.High.Warn,
		s.Automatic.Medium.Pass, s.Automatic.Medium.Fail, s.Automatic.Medium.Warn,
		s.Automatic.Low.Pass, s.Automatic.Low.Fail, s.Automatic.Low.Warn)
	fmt.Fprintf(w, "manual review %d  ·  undecidable error %d / n-a %d / waived %d  ·  facts failed %d  ·  waivers expiring within 30d %d\n\n",
		s.ManualReview, s.Undecidable.Error, s.Undecidable.NotApplicable, s.Undecidable.Waived, s.FactsFailed, s.WaiversExpiringSoon)

	idWidth := 12
	for _, row := range r.Results {
		if l := len(row.ID); l > idWidth {
			idWidth = l
		}
	}
	titleWidth := o.Width - 8 - 8 - idWidth - 4
	if titleWidth < 10 {
		titleWidth = 10
	}
	for _, row := range r.Results {
		if hidden(o, row.Status) {
			continue
		}
		title := row.TitleKo
		if title == "" {
			title = row.TitleEn
		}
		status := paint(o.Color, statusColor[row.Status], padRight(string(row.Status), 14))
		fmt.Fprintf(w, "%s %s %s  %s\n", status, padRight(row.Severity, 6), padRight(row.ID, idWidth), truncateWidth(escape(title), titleWidth))
		if row.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", escape(reasonLine(row)))
		}
		if row.Waiver != nil {
			if row.Waiver.Applied {
				fmt.Fprintf(w, "    waived: %s (expires %s)\n", escape(row.Waiver.Reason), orNone(row.Waiver.Expires))
			} else {
				fmt.Fprintf(w, "    waiver not applied: %s\n", escape(row.Waiver.NotAppliedBecause))
			}
		}
		if row.Status == check.FAIL || row.Status == check.WARN || row.Status == check.ERROR {
			for _, ev := range row.Evidence {
				fmt.Fprintf(w, "    %s%s = %s%s\n", ev.Fact, sideSuffix(ev.Side), escape(fmt.Sprint(ev.Value)), sourceSuffix(ev))
			}
			shown := 0
			failing := 0
			for _, ob := range row.Observations {
				if ob.Verdict == "pass" {
					continue
				}
				failing++
				if shown < o.MaxObservations {
					fmt.Fprintf(w, "    %s: expected %v, actual %v (%s)\n", escape(ob.Subject), ob.Expected, escape(fmt.Sprint(ob.Actual)), ob.Verdict)
					shown++
				}
			}
			if failing > shown {
				fmt.Fprintf(w, "    (+%d more, use --all)\n", failing-shown)
			}
		}
	}
	return nil
}

func reasonLine(row Row) string {
	if row.ReasonCode != "" {
		return fmt.Sprintf("[%s] %s", row.ReasonCode, row.Reason)
	}
	return row.Reason
}

func orNone(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func sideSuffix(side string) string {
	if side == "" {
		return ""
	}
	return "@" + side
}

func sourceSuffix(ev check.Evidence) string {
	if ev.Source == nil {
		return ""
	}
	switch {
	case ev.Source.Path != "" && ev.Source.Line > 0:
		return fmt.Sprintf("  (%s:%d)", ev.Source.Path, ev.Source.Line)
	case ev.Source.Path != "":
		return "  (" + ev.Source.Path + ")"
	case ev.Source.Cmd != "":
		return "  (" + ev.Source.Cmd + ")"
	}
	return ""
}
```

- [ ] **Step 4: Create the goldens, then run the tests**

Run: `go test ./internal/report/ -run TestTableGolden -update && go test ./internal/report/ -v`
Expected: PASS. Open both goldens and confirm: the narrow one truncates titles with `…`, Korean titles are padded to align, the ERROR row shows `[permission_denied]`, the WAIVED row shows `waived: r (expires 2026-09-20)`, no ESC bytes anywhere.

- [ ] **Step 5: Commit**

```bash
git add internal/report/
git commit -m "Add the table renderer with East Asian width and terminal escaping"
```

---

### Task 14: Exit code contract and the `check` command

**Files:**
- Create: `internal/report/exitcode.go`, `internal/report/exitcode_test.go`, `cmd/muster/trust_linux.go`, `cmd/muster/trust_other.go`, `cmd/muster/check_test.go`
- Modify: `cmd/muster/check.go` (replace the stub)

**Interfaces:**
- Produces (package `report`):
  - `type ExitOptions struct { AllowError bool; FailOn string }` — `FailOn` ∈ `fail|warn|manual|none`, empty means `fail`.
  - `func ExitCode(results []check.Result, o ExitOptions) int` — any `ERROR` and not `AllowError` → 2; else by `FailOn`: `none` → 0; `fail` → any `FAIL` → 1; `warn` → any `FAIL` or `WARN` → 1; `manual` → any `FAIL`, `WARN` or `MANUAL` → 1 (each level includes the ones below it); else 0. `WAIVED`, `NOT_APPLICABLE` never count.
- Produces (package `main`):
  - `func runCheck(args []string, stdout, stderr io.Writer) int` with flags `--facts <path|->` (required), `--format table|json` (default `table`), `--waivers <path>`, `--allow-error`, `--fail-on <fail|warn|manual|none>`, `--quiet`, `--all`, `--color <auto|always|never>`, `--no-color` (= `--color never`). Unknown flag or missing `--facts` → usage on stderr, exit 2. Snapshot load error → `muster: <error>` on stderr, exit 2. Waiver load error → exit 2. Warnings from waivers → stderr, prefixed `muster: warning: `. Only the rendered report goes to stdout.
  - `func trustedFile(path string) (bool, string)` — on Linux (`trust_linux.go`, build tag `linux`): false with a reason when the process is root (`os.Geteuid()==0`) and the file is not owned by uid 0 or has group/other write bits; on other platforms (`trust_other.go`, `//go:build !linux`): always true. Applied to `--waivers`.
  - The `CheckBlock` is filled with `version`, `commit`, the embedded set's `Version`/`Digest`, `snap.Digest()`, `"kisa-unix-2026"`, and the waiver tally.

- [ ] **Step 1: Write the failing tests**

`internal/report/exitcode_test.go`:

```go
package report

import (
	"testing"

	"github.com/kun9497/muster/internal/check"
)

func rs(statuses ...check.Status) []check.Result {
	out := make([]check.Result, len(statuses))
	for i, s := range statuses {
		out[i] = check.Result{ID: "x", Status: s}
	}
	return out
}

func TestExitCodePrecedence(t *testing.T) {
	cases := []struct {
		name string
		res  []check.Result
		opts ExitOptions
		want int
	}{
		{"clean", rs(check.PASS, check.NotApplicable, check.WAIVED), ExitOptions{}, 0},
		{"fail", rs(check.PASS, check.FAIL), ExitOptions{}, 1},
		{"error outranks fail", rs(check.FAIL, check.ERROR), ExitOptions{}, 2},
		{"allow-error drops to fail", rs(check.FAIL, check.ERROR), ExitOptions{AllowError: true}, 1},
		{"allow-error clean", rs(check.PASS, check.ERROR), ExitOptions{AllowError: true}, 0},
		{"warn default 0", rs(check.WARN), ExitOptions{}, 0},
		{"warn with fail-on warn", rs(check.WARN), ExitOptions{FailOn: "warn"}, 1},
		{"manual default 0", rs(check.MANUAL), ExitOptions{}, 0},
		{"manual with fail-on manual", rs(check.MANUAL), ExitOptions{FailOn: "manual"}, 1},
		{"fail-on manual includes warn", rs(check.WARN), ExitOptions{FailOn: "manual"}, 1},
		{"fail-on none ignores fail", rs(check.FAIL), ExitOptions{FailOn: "none"}, 0},
		{"fail-on none keeps error", rs(check.FAIL, check.ERROR), ExitOptions{FailOn: "none"}, 2},
		{"waived never counts", rs(check.WAIVED), ExitOptions{FailOn: "manual"}, 0},
	}
	for _, c := range cases {
		if got := ExitCode(c.res, c.opts); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}
```

`cmd/muster/check_test.go` (error paths only; the end-to-end run is Task 15):

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckRequiresFacts(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--facts") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCheckRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "x.json", "--bogus"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--bogus") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCheckSchemaMismatchIsExit2WithEmptyStdout(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "new.json")
	os.WriteFile(p, []byte(`{"schema_version": 99, "run": {}, "facts": {}}`), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", p}, &out, &errb); code != exitError || out.Len() != 0 || !strings.Contains(errb.String(), "schema_mismatch") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

func TestCheckBadWaiverFileIsExit2(t *testing.T) {
	dir := t.TempDir()
	snap := filepath.Join(dir, "s.json")
	os.WriteFile(snap, []byte(`{"schema_version": 1, "run": {}, "facts": {}}`), 0o644)
	w := filepath.Join(dir, "w.yaml")
	os.WriteFile(w, []byte("waivers:\n  - control: muster.a.b\n    reason: ''\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--facts", snap, "--waivers", w}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "reason") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/report/ -run TestExitCode -v; go test ./cmd/muster/ -run TestCheck -v`
Expected: FAIL — undefined `ExitCode`; the CLI tests fail because the stub ignores flags.

- [ ] **Step 3: Write `exitcode.go`, the trust helpers and the command**

`internal/report/exitcode.go`:

```go
package report

import "github.com/kun9497/muster/internal/check"

// ExitOptions selects what counts as a finding (spec §7.2, D11).
type ExitOptions struct {
	AllowError bool
	FailOn     string // fail | warn | manual | none; "" means fail
}

// ExitCode applies the contract 2 > 1 > 0. Errors outrank findings unless
// the caller explicitly allows them; WAIVED and NOT_APPLICABLE never count.
func ExitCode(results []check.Result, o ExitOptions) int {
	failOn := o.FailOn
	if failOn == "" {
		failOn = "fail"
	}
	var hasError, hasFail, hasWarn, hasManual bool
	for _, r := range results {
		switch r.Status {
		case check.ERROR:
			hasError = true
		case check.FAIL:
			hasFail = true
		case check.WARN:
			hasWarn = true
		case check.MANUAL:
			hasManual = true
		}
	}
	if hasError && !o.AllowError {
		return 2
	}
	switch failOn {
	case "none":
		return 0
	case "manual":
		if hasFail || hasWarn || hasManual {
			return 1
		}
	case "warn":
		if hasFail || hasWarn {
			return 1
		}
	default:
		if hasFail {
			return 1
		}
	}
	return 0
}
```

`cmd/muster/trust_other.go`:

```go
//go:build !linux

package main

// trustedFile has nothing to check off Linux: check does not run as root
// there in a way that matters, and the ownership model differs.
func trustedFile(path string) (bool, string) { return true, "" }
```

`cmd/muster/trust_linux.go`:

```go
//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

// trustedFile refuses, when running as root, a data file that someone other
// than root could have written (spec §4.4, §6.7): a waiver file on the host
// is the one data file that can turn a FAIL into a clean run.
func trustedFile(path string) (bool, string) {
	if os.Geteuid() != 0 {
		return true, ""
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, err.Error()
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 {
		return false, fmt.Sprintf("%s is owned by uid %d, not root", path, sys.Uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return false, fmt.Sprintf("%s is group- or world-writable (%04o)", path, st.Mode().Perm())
	}
	return true, ""
}
```

`cmd/muster/check.go`:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/waiver"
)

const checkUsage = `usage: muster check --facts <snapshot.json|-> [flags]

flags:
  --format table|json        output format (default table)
  --waivers <file>           waiver file (reason mandatory, expiry optional)
  --allow-error              compute the exit code from findings even when controls are ERROR
  --fail-on fail|warn|manual|none   what exits 1 (default fail)
  --quiet                    hide PASS, NOT_APPLICABLE, WAIVED and MANUAL rows
  --all                      show every failing observation
  --color auto|always|never  colour (default auto); --no-color = never
`

type checkFlags struct {
	facts, format, waivers, failOn, color string
	allowError, quiet, all              bool
}

func parseCheckArgs(args []string) (checkFlags, error) {
	f := checkFlags{format: "table", failOn: "fail", color: "auto"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--facts":
			f.facts, err = next()
		case "--format":
			f.format, err = next()
		case "--waivers":
			f.waivers, err = next()
		case "--fail-on":
			f.failOn, err = next()
		case "--color":
			f.color, err = next()
		case "--no-color":
			f.color = "never"
		case "--allow-error":
			f.allowError = true
		case "--quiet":
			f.quiet = true
		case "--all":
			f.all = true
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	if f.facts == "" {
		return f, errors.New("--facts is required")
	}
	if f.format != "table" && f.format != "json" {
		return f, fmt.Errorf("--format must be table or json, got %q", f.format)
	}
	switch f.failOn {
	case "fail", "warn", "manual", "none":
	default:
		return f, fmt.Errorf("--fail-on must be fail, warn, manual or none, got %q", f.failOn)
	}
	switch f.color {
	case "auto", "always", "never":
	default:
		return f, fmt.Errorf("--color must be auto, always or never, got %q", f.color)
	}
	return f, nil
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	f, err := parseCheckArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, checkUsage)
		return exitError
	}
	var in io.Reader = os.Stdin
	if f.facts != "-" {
		fh, err := os.Open(f.facts)
		if err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		defer fh.Close()
		in = fh
	}
	snap, err := facts.Load(in)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	var wf *waiver.File
	if f.waivers != "" {
		if ok, why := trustedFile(f.waivers); !ok {
			fmt.Fprintf(stderr, "muster: refusing waiver file: %s\n", why)
			return exitError
		}
		fh, err := os.Open(f.waivers)
		if err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		wf, err = waiver.Load(fh, f.waivers)
		fh.Close()
		if err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "muster: warning: check does not need root")
	}

	results := check.Evaluate(snap, set, reg, check.Options{})
	cb := report.CheckBlock{
		MusterVersion: version, Commit: commit,
		ControlsVersion: set.Version, ControlsDigest: set.Digest,
		SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026",
	}
	if snap.Run.ControlsDigest != "" && snap.Run.ControlsDigest != set.Digest {
		fmt.Fprintf(stderr, "muster: warning: snapshot was collected with control set %s; evaluating with %s\n", snap.Run.ControlsVersion, set.Version)
	}
	if wf != nil {
		known := map[string]bool{}
		for _, c := range set.Controls {
			known[c.ID] = true
		}
		tally := wf.Apply(results, known, time.Now().UTC(), func(msg string) { fmt.Fprintf(stderr, "muster: warning: %s\n", msg) })
		cb.Waivers = report.WaiversBlock{Path: wf.Path, Digest: wf.Digest, Applied: tally.Applied, NotApplied: tally.NotApplied, Expired: tally.Expired, Unknown: tally.Unknown, ExpiringSoon: tally.ExpiringSoon}
	}
	rep := report.Build(snap, results, cb)

	switch f.format {
	case "json":
		if err := report.WriteJSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "muster: write: %v\n", err)
			return exitError
		}
	default:
		isTTY := false
		if fh, ok := stdout.(*os.File); ok {
			if st, err := fh.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
				isTTY = true
			}
		}
		opts := report.TableOptions{Color: report.ColorEnabled(f.color, os.Getenv("NO_COLOR"), os.Getenv("TERM"), isTTY), Quiet: f.quiet}
		if f.all {
			opts.MaxObservations = 1 << 30
		}
		if err := report.WriteTable(stdout, rep, opts); err != nil {
			fmt.Fprintf(stderr, "muster: write: %v\n", err)
			return exitError
		}
	}
	return report.ExitCode(results, report.ExitOptions{AllowError: f.allowError, FailOn: f.failOn})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/report/ ./cmd/muster/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/report/exitcode.go internal/report/exitcode_test.go cmd/muster/
git commit -m "Add the exit-code contract and the check command"
```

---

### Task 15: The five stage-1 controls, their fixtures, the fixture registry test and the end-to-end run

**Files:**
- Create: `controls/account/root_remote_login.yaml`, `controls/account/password_policy.yaml`, `controls/file/passwd_permissions.yaml`, `controls/file/world_writable.yaml`, `controls/service/telnet_disabled.yaml`, fixtures under `controls/testdata/<id>/`, `internal/controls/fixtures_test.go`, `cmd/muster/testdata/full-pass.json`, `cmd/muster/testdata/full-fail.json`, `cmd/muster/e2e_test.go`
- Modify: `docs/superpowers/specs/2026-09-02-muster-design.md` §10.2 (one sentence, see Step 3)

**Interfaces:**
- Consumes: everything above.
- Produces: a green `go run ./cmd/muster controls lint`, and `muster check --facts cmd/muster/testdata/full-pass.json` exiting 0.
- Fixture rule (spec §11): every control has at least one `pass-*.json` and one `fail-*.json`; a fixture's prefix is its expected status; `_expect` may add `reason_code` and `exit_code`.

- [ ] **Step 1: Write the five controls**

`controls/account/root_remote_login.yaml`:

```yaml
id: muster.account.root_remote_login
title_en: Root cannot log in directly over SSH
title_ko: root 계정이 SSH로 직접 로그인할 수 없다
description_en: The SSH daemon's effective PermitRootLogin must not allow a root password login. Where sshd is absent, the legacy /etc/securetty list must not allow pseudo-terminals.
description_ko: sshd의 유효 PermitRootLogin 값이 root 패스워드 로그인을 허용하면 안 됩니다. sshd가 없는 경우 구형 /etc/securetty 목록이 가상 터미널을 허용하면 안 됩니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-01"], "2021": ["U-01"] }
  cis: [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]
requires_facts: ">=1"
applies_when:
  - { fact: services.ssh.installed, op: eq, expected: true }
absent_means: not_applicable
params:
  allowed: { type: list<string>, default: ["no", "prohibit-password"], description: PermitRootLogin values that count as disabled }
mechanisms:
  - when:
      - { fact: sshd.options.permit_root_login, op: present }
    checks:
      - { fact: sshd.options.permit_root_login, on: effective, persona: root, op: in, expected: ${allowed} }
  - when:
      - { fact: files.etc_securetty, op: present }
    checks:
      - { fact: files.etc_securetty.lines, op: none, where: { op: matches, expected: "^pts/" } }
remediation:
  text_en: Set PermitRootLogin no in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, then restart sshd while keeping a second session open.
  text_ko: /etc/ssh/sshd_config.d/ 아래 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤, 다른 세션을 열어 둔 채 sshd 를 재시작합니다.
  risk: lockout_risk
  idempotent: true
  script: |
    printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
  rollback: rm -f /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
decision: D09
```

`controls/account/password_policy.yaml`:

```yaml
id: muster.account.password_policy
title_en: Password ageing and length policy is set
title_ko: 비밀번호 사용 기간과 길이 정책이 설정되어 있다
description_en: Maximum and minimum password age from login.defs must apply to existing accounts too, and the minimum length must meet the parameter. Stage 2 adds the pwquality side.
description_ko: login.defs의 최대·최소 사용 기간이 기존 계정에도 적용되어야 하고, 최소 길이가 파라미터를 충족해야 합니다. 2단계에서 pwquality 쪽을 더합니다.
category: account
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-02"], "2021": ["U-02", "U-46", "U-47", "U-48"] }
requires_facts: ">=1"
absent_means: fail
params:
  max_days: { type: int, default: 90, description: Maximum password age in days }
  min_days: { type: int, default: 1, description: Minimum password age in days }
  min_len: { type: int, default: 8, description: Minimum password length }
checks:
  - { fact: accounts.login_defs.pass_max_days, op: lte, expected: ${max_days} }
  - { fact: accounts.login_defs.pass_min_days, op: gte, expected: ${min_days} }
  - { fact: accounts.login_defs.pass_min_len, op: gte, expected: ${min_len} }
remediation:
  text_en: Set PASS_MAX_DAYS, PASS_MIN_DAYS and PASS_MIN_LEN in /etc/login.defs, then apply the ageing values to existing accounts with chage.
  text_ko: /etc/login.defs 에 PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_MIN_LEN 을 설정하고, 기존 계정에는 chage 로 사용 기간 값을 적용합니다.
  risk: none
  idempotent: true
decision: D10
```

`controls/file/passwd_permissions.yaml`:

```yaml
id: muster.file.passwd_permissions
title_en: /etc/passwd is owned by root and not writable by others
title_ko: /etc/passwd 가 root 소유이고 다른 사용자가 쓸 수 없다
description_en: Owner and group must be root, mode must be 0644 or stricter, and no POSIX ACL may widen access. In stage 1 an ACL that is present cannot be parsed, so its presence fails the control.
description_ko: 소유자와 그룹이 root 여야 하고 모드가 0644 이하여야 하며 POSIX ACL 이 접근을 넓히면 안 됩니다. 1단계에서는 ACL 을 해석하지 못하므로 ACL 이 있으면 실패로 봅니다.
category: file
importance: 상
automation: auto
references:
  kisa: { "2026": ["U-16"], "2021": ["U-07"] }
requires_facts: ">=1"
absent_means: fail
checks:
  - { fact: files.etc_passwd.uid, op: eq, expected: 0 }
  - { fact: files.etc_passwd.gid, op: eq, expected: 0 }
  - { fact: files.etc_passwd.mode, op: lte, expected: 420 }
  - { fact: files.etc_passwd.acl_present, op: eq, expected: false }
remediation:
  text_en: chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd
  text_ko: chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd
  risk: none
  idempotent: true
  script: chown root:root /etc/passwd && chmod 644 /etc/passwd && setfacl -b /etc/passwd
decision: D26
```

`controls/file/world_writable.yaml`:

```yaml
id: muster.file.world_writable
title_en: No unexpected world-writable files
title_ko: 예상치 못한 world-writable 파일이 없다
description_en: World-writable files without the sticky bit that no package declares that way need a human decision. Requires the deep walk.
description_ko: sticky bit 가 없고 어떤 패키지도 그렇게 배포하지 않은 world-writable 파일은 사람의 판단이 필요합니다. deep walk 가 필요합니다.
category: file
importance: 상
automation: partial
references:
  kisa: { "2026": ["U-25"], "2021": ["U-15"] }
requires_facts: ">=1"
absent_means: pass
checks:
  - fact: walk.world_writable
    op: each
    subject: path
    where:   { field: sticky, op: eq, expected: false }
    require: { field: package_declared, op: eq, expected: true }
remediation:
  text_en: Review each listed path; remove the world-writable bit with chmod o-w unless the application requires it, and record a waiver with the reason if it does.
  text_ko: 나열된 경로를 검토합니다. 애플리케이션이 요구하지 않으면 chmod o-w 로 world-writable 비트를 제거하고, 요구한다면 사유를 적은 waiver 를 남깁니다.
  risk: none
  idempotent: true
decision: D20
```

`controls/service/telnet_disabled.yaml`:

```yaml
id: muster.service.telnet_disabled
title_en: Telnet is not reachable
title_ko: Telnet 서비스에 접속할 수 없다
description_en: No telnet server may be active, socket-activated or listening on a non-loopback address. A host without any telnet server passes.
description_ko: telnet 서버가 활성이거나 소켓 활성화되어 있거나 루프백 외 주소에서 대기하면 안 됩니다. telnet 서버가 전혀 없는 호스트는 통과합니다.
category: service
importance: 중
automation: auto
references:
  kisa: { "2026": ["U-52"], "2021": ["U-60"] }
requires_facts: ">=1"
absent_means: pass
checks:
  - { fact: services.telnet.reachable, op: eq, expected: false }
remediation:
  text_en: Stop and mask the telnet socket and service, or remove the telnet server package; use SSH instead.
  text_ko: telnet 소켓과 서비스를 중지·mask 하거나 telnet 서버 패키지를 제거하고, 대신 SSH 를 사용합니다.
  risk: restart_service
  idempotent: true
  script: systemctl disable --now telnet.socket telnet.service 2>/dev/null; systemctl mask telnet.socket telnet.service
  rollback: systemctl unmask telnet.socket telnet.service
decision: D19
```

- [ ] **Step 2: Write the fixtures**

Every fixture is a full JSON document; `run` may be `{}`. Create these files (one JSON object per file, exactly as shown):

`controls/testdata/muster.account.root_remote_login/pass-personas.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"personas_collected":{"status":"ok","value":true},"options":{"permit_root_login":{"effective":{"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}}}}}}}
```
`controls/testdata/muster.account.root_remote_login/warn-global-only.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"personas_collected":{"status":"ok","value":false},"options":{"permit_root_login":{"effective":{"status":"ok","value":"prohibit-password","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}}}}}}}
```
`controls/testdata/muster.account.root_remote_login/fail-yes.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"personas_collected":{"status":"ok","value":true},"options":{"permit_root_login":{"effective":{"status":"ok","value":"yes","source":{"kind":"file","path":"/etc/ssh/sshd_config","line":40,"raw":"PermitRootLogin yes"}}}}}}}
```
`controls/testdata/muster.account.root_remote_login/na-no-ssh.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":false}}}}}
```
`controls/testdata/muster.account.root_remote_login/pass-securetty-fallback.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"personas_collected":{"status":"ok","value":true},"options":{"permit_root_login":{"effective":{"status":"absent"}}}},"files":{"etc_securetty":{"status":"ok","value":{"mode":384},"lines":{"status":"ok","value":["console","tty1"]}}}}}
```
`controls/testdata/muster.account.root_remote_login/error-denied.json`
```json
{"_expect":{"reason_code":"permission_denied","exit_code":2},"schema_version":1,"run":{},"facts":{"services":{"ssh":{"installed":{"status":"ok","value":true}}},"sshd":{"personas_collected":{"status":"ok","value":true},"options":{"permit_root_login":{"effective":{"status":"denied","reason":"sshd -T needs root"}}}}}}
```

`controls/testdata/muster.account.password_policy/pass-defaults.json`
```json
{"schema_version":1,"run":{},"facts":{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90,"source":{"kind":"derived","inputs":[{"kind":"file","path":"/etc/shadow"}]}},"persisted":{"status":"ok","value":90,"source":{"kind":"file","path":"/etc/login.defs","line":160,"raw":"PASS_MAX_DAYS 90"}}},"pass_min_days":{"runtime":{"status":"ok","value":1},"persisted":{"status":"ok","value":1,"source":{"kind":"file","path":"/etc/login.defs","line":161}}},"pass_min_len":{"status":"ok","value":8,"source":{"kind":"file","path":"/etc/login.defs","line":162}}}}}}
```
`controls/testdata/muster.account.password_policy/fail-unlimited.json`
```json
{"schema_version":1,"run":{},"facts":{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":99999},"persisted":{"status":"ok","value":99999,"source":{"kind":"file","path":"/etc/login.defs","line":160,"raw":"PASS_MAX_DAYS 99999"}}},"pass_min_days":{"runtime":{"status":"ok","value":0},"persisted":{"status":"ok","value":0}},"pass_min_len":{"status":"ok","value":5}}}}}
```
`controls/testdata/muster.account.password_policy/warn-not-applied.json`
```json
{"schema_version":1,"run":{},"facts":{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":99999,"source":{"kind":"derived","inputs":[{"kind":"file","path":"/etc/shadow"}]}},"persisted":{"status":"ok","value":90,"source":{"kind":"file","path":"/etc/login.defs","line":160,"raw":"PASS_MAX_DAYS 90"}}},"pass_min_days":{"runtime":{"status":"ok","value":1},"persisted":{"status":"ok","value":1}},"pass_min_len":{"status":"ok","value":8}}}}}
```
`controls/testdata/muster.account.password_policy/error-missing.json`
```json
{"_expect":{"reason_code":"missing_fact","exit_code":2},"schema_version":1,"run":{},"facts":{}}
```

`controls/testdata/muster.file.passwd_permissions/pass-0644.json`
```json
{"schema_version":1,"run":{},"facts":{"files":{"etc_passwd":{"mode":{"status":"ok","value":420,"source":{"kind":"sys","path":"/etc/passwd"}},"uid":{"status":"ok","value":0},"gid":{"status":"ok","value":0},"acl_present":{"status":"ok","value":false}}}}}
```
`controls/testdata/muster.file.passwd_permissions/fail-0666.json`
```json
{"schema_version":1,"run":{},"facts":{"files":{"etc_passwd":{"mode":{"status":"ok","value":438,"source":{"kind":"sys","path":"/etc/passwd"}},"uid":{"status":"ok","value":0},"gid":{"status":"ok","value":0},"acl_present":{"status":"ok","value":false}}}}}
```
`controls/testdata/muster.file.passwd_permissions/fail-acl.json`
```json
{"schema_version":1,"run":{},"facts":{"files":{"etc_passwd":{"mode":{"status":"ok","value":420},"uid":{"status":"ok","value":0},"gid":{"status":"ok","value":0},"acl_present":{"status":"ok","value":true,"source":{"kind":"sys","path":"/etc/passwd"}}}}}}
```
`controls/testdata/muster.file.passwd_permissions/fail-absent.json`
```json
{"schema_version":1,"run":{},"facts":{"files":{"etc_passwd":{"mode":{"status":"absent"},"uid":{"status":"absent"},"gid":{"status":"absent"},"acl_present":{"status":"absent"}}}}}
```

`controls/testdata/muster.file.world_writable/pass-all-declared.json`
```json
{"schema_version":1,"run":{"deep":true},"facts":{"walk":{"world_writable":{"status":"ok","value":[{"path":"/tmp","sticky":true,"package_declared":true},{"path":"/var/lib/x/spool","sticky":false,"package_declared":true}]},"complete":{"status":"ok","value":true}}}}
```
`controls/testdata/muster.file.world_writable/warn-legacy-socket.json`
```json
{"schema_version":1,"run":{"deep":true},"facts":{"walk":{"world_writable":{"status":"ok","value":[{"path":"/var/tmp/legacy.sock","sticky":false,"package_declared":false},{"path":"/tmp","sticky":true,"package_declared":true}]},"complete":{"status":"ok","value":true}}}}
```
`controls/testdata/muster.file.world_writable/fail-none-declared.json`
```json
{"_expect":{"exit_code":0},"schema_version":1,"run":{"deep":true},"facts":{"walk":{"world_writable":{"status":"ok","value":[{"path":"/opt/app/data","sticky":false,"package_declared":false}]},"complete":{"status":"ok","value":true}}}}
```
(Because the control is `partial`, this "fail" fixture is expected to be `WARN`; name it `warn-none-declared.json` instead and keep `fail-` for a synthetic non-partial case — see Step 4: the fixture rule for a `partial` control is that a `fail-*.json` fixture is expected to produce `WARN`. Implement that mapping in the test: prefix `fail` on a `partial` control expects `WARN`.)
`controls/testdata/muster.file.world_writable/manual-no-walk.json`
```json
{"schema_version":1,"run":{"deep":false},"facts":{"walk":{"world_writable":{"status":"absent"}}}}
```
`controls/testdata/muster.file.world_writable/error-incomplete.json`
```json
{"_expect":{"reason_code":"walk_incomplete","exit_code":2},"schema_version":1,"run":{"deep":true},"facts":{"walk":{"world_writable":{"status":"ok","value":[]},"complete":{"status":"ok","value":false}}}}
```

`controls/testdata/muster.service.telnet_disabled/pass-not-reachable.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"telnet":{"installed":{"status":"ok","value":true},"reachable":{"status":"ok","value":false,"source":{"kind":"command","cmd":"/usr/bin/systemctl show telnet.socket"}}}}}}
```
`controls/testdata/muster.service.telnet_disabled/pass-absent.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"telnet":{"installed":{"status":"ok","value":false},"reachable":{"status":"absent"}}}}}
```
`controls/testdata/muster.service.telnet_disabled/fail-listening.json`
```json
{"schema_version":1,"run":{},"facts":{"services":{"telnet":{"installed":{"status":"ok","value":true},"reachable":{"status":"ok","value":true,"source":{"kind":"proc","path":"/proc/net/tcp","raw":"0.0.0.0:23 LISTEN"}}}}}}
```
`controls/testdata/muster.service.telnet_disabled/na-container.json`
```json
{"schema_version":1,"run":{"env":{"container":"docker"}},"facts":{"services":{"telnet":{"installed":{"status":"unsupported","reason":"no init system inside the container"},"reachable":{"status":"unsupported","reason":"no init system inside the container"}}}}}
```

- [ ] **Step 3: Record the stage-1 ACL behaviour in the spec**

In `docs/superpowers/specs/2026-09-02-muster-design.md` §10.2, change the U-16 bullet's last clause from "so a file with an ACL present is `WARN` in stage 1" to "so a file with an ACL present is `FAIL` in stage 1 with the reason naming the unparsed ACL" (the clause vocabulary has no per-clause degradation; a present-but-unparsed ACL cannot be `PASS`, and `FAIL` is the honest status until stage 2 parses entries). Make the same one-line change in the `.ko.md`.

- [ ] **Step 4: Write the fixture registry test and the end-to-end test**

`internal/controls/fixtures_test.go` (external test package, so it may import `check` and `report` without a cycle):

```go
package controls_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/report"
)

const fixtureRoot = "../../controls/testdata"

var prefixStatus = map[string]check.Status{
	"pass": check.PASS, "fail": check.FAIL, "warn": check.WARN, "manual": check.MANUAL,
	"na": check.NotApplicable, "error": check.ERROR,
}

type expect struct {
	ReasonCode string `json:"reason_code"`
	ExitCode   *int   `json:"exit_code"`
}

func loadFixture(t *testing.T, path string) (*facts.Snapshot, expect) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Expect expect `json:"_expect"`
	}
	json.Unmarshal(raw, &meta)
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	delete(tree, "_expect")
	cleaned, _ := json.Marshal(tree)
	s, err := facts.Load(strings.NewReader(string(cleaned)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return s, meta.Expect
}

// Every control has pass and fail fixtures, every fixture produces the status
// its name promises, and every result honours the invariants of spec §11.
func TestEveryControlHasFixturesThatBehave(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range set.Controls {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			dir := filepath.Join(fixtureRoot, c.ID)
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			sort.Strings(files)
			seen := map[string]bool{}
			for _, f := range files {
				name := filepath.Base(f)
				prefix := strings.SplitN(name, "-", 2)[0]
				want, ok := prefixStatus[prefix]
				if !ok {
					t.Fatalf("%s: unknown fixture prefix %q", name, prefix)
				}
				if prefix == "fail" && c.Automation == "partial" {
					want = check.WARN
				}
				seen[prefix] = true
				snap, exp := loadFixture(t, f)
				one := &controls.Set{Version: set.Version, Digest: set.Digest, Controls: []controls.Control{c}}
				res := check.Evaluate(snap, one, reg, check.Options{})
				r := res[0]
				if r.Status != want {
					t.Errorf("%s: status %s (%s: %s), want %s", name, r.Status, r.ReasonCode, r.Reason, want)
				}
				if exp.ReasonCode != "" && string(r.ReasonCode) != exp.ReasonCode {
					t.Errorf("%s: reason_code %q want %q", name, r.ReasonCode, exp.ReasonCode)
				}
				if exp.ExitCode != nil {
					if got := report.ExitCode(res, report.ExitOptions{}); got != *exp.ExitCode {
						t.Errorf("%s: exit code %d want %d", name, got, *exp.ExitCode)
					}
				}
				checkInvariants(t, name, r)
			}
			if c.Automation == "auto" || c.Automation == "partial" {
				for _, p := range []string{"pass", "fail"} {
					if !seen[p] {
						t.Errorf("control %s has no %s-*.json fixture under %s", c.ID, p, dir)
					}
				}
			}
		})
	}
}

func checkInvariants(t *testing.T, name string, r check.Result) {
	t.Helper()
	switch r.Status {
	case check.FAIL, check.WARN:
		if r.Reason == "" {
			t.Errorf("%s: %s without reason", name, r.Status)
		}
		if len(r.Evidence) == 0 && len(r.Observations) == 0 {
			t.Errorf("%s: %s without evidence or observations", name, r.Status)
		}
	case check.ERROR:
		if r.ReasonCode == "" || r.Reason == "" {
			t.Errorf("%s: ERROR without reason code and text: %+v", name, r)
		}
	case check.MANUAL:
		if r.Reason == "" {
			t.Errorf("%s: MANUAL without reason", name)
		}
	case check.NotApplicable:
		if r.Reason == "" {
			t.Errorf("%s: NOT_APPLICABLE without reason", name)
		}
	}
}

func TestLintOfEmbeddedSetIsClean(t *testing.T) {
	set, _ := controls.LoadDefault()
	reg, _ := facts.LoadRegistry()
	problems := controls.Lint(set, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs(), FixtureDir: fixtureRoot})
	for _, p := range problems {
		t.Error(p)
	}
}
```

`cmd/muster/testdata/full-pass.json` (every stage-1 key, all passing; `sshd.personas_collected` true so U-01 is `PASS`, `walk` absent so U-25 is `MANUAL`):

```json
{"schema_version":1,
 "run":{"muster_version":"0.1.0","commit":"abc1234","controls_version":"kisa-unix-2026+2026.09.02","controls_digest":"","guide_edition":"kisa-unix-2026",
        "collected_at":"2026-09-02T06:00:00Z","host":{"hostname":"fixture-host","os_release":{"id":"ubuntu","version_id":"22.04","family":"debian"}},
        "euid":0,"capabilities":[],"env":{"container":"none","virt":"kvm","has_systemd":true,"sysctl_writable":true},
        "collectors":[{"name":"services","status":"ok","ms":3},{"name":"sshd","status":"ok","ms":41,"cmd":"/usr/sbin/sshd -T"},{"name":"files","status":"ok","ms":1},{"name":"accounts","status":"ok","ms":2}],
        "redaction":{"profile":"default","include_secrets":false},"deep":false,"complete":true,"partial_failures":[]},
 "facts":{
  "services":{"ssh":{"installed":{"status":"ok","value":true},"active":{"status":"ok","value":true}},
              "telnet":{"installed":{"status":"ok","value":false},"reachable":{"status":"absent"}}},
  "sshd":{"collect_method":{"status":"ok","value":"T"},"personas_collected":{"status":"ok","value":true},
          "options":{"permit_root_login":{"effective":{"status":"ok","value":"no","source":{"kind":"command","cmd":"/usr/sbin/sshd -T"}}}}},
  "files":{"etc_passwd":{"mode":{"status":"ok","value":420,"source":{"kind":"sys","path":"/etc/passwd"}},"uid":{"status":"ok","value":0},"gid":{"status":"ok","value":0},"acl_present":{"status":"ok","value":false}}},
  "accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":90},"persisted":{"status":"ok","value":90,"source":{"kind":"file","path":"/etc/login.defs","line":160}}},
                            "pass_min_days":{"runtime":{"status":"ok","value":1},"persisted":{"status":"ok","value":1}},
                            "pass_min_len":{"status":"ok","value":8}}},
  "walk":{"world_writable":{"status":"absent"}}
 }}
```

`cmd/muster/testdata/full-fail.json`: identical to `full-pass.json` except `sshd.options.permit_root_login.effective.value` is `"yes"` with source `{"kind":"file","path":"/etc/ssh/sshd_config","line":40,"raw":"PermitRootLogin yes"}`.

`cmd/muster/e2e_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCheckEndToEndJSONAndTable(t *testing.T) {
	var out1, out2, errb bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out1, &errb); code != exitOK {
		t.Fatalf("exit %d stderr %q", code, errb.String())
	}
	if code := run([]string{"check", "--facts", "testdata/full-pass.json", "--format", "json"}, &out2, &errb); code != exitOK {
		t.Fatal(code)
	}
	if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
		t.Fatal("JSON output is not deterministic")
	}
	var rep map[string]any
	if err := json.Unmarshal(out1.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if rep["schema_version"].(float64) != 1 || rep["check"].(map[string]any)["guide_edition"] != "kisa-unix-2026" {
		t.Errorf("report header: %v", rep["check"])
	}
	var table bytes.Buffer
	if code := run([]string{"check", "--facts", "testdata/full-fail.json", "--color", "never"}, &table, &errb); code != exitFindings {
		t.Fatalf("exit %d, want 1 for a FAIL; stderr %q", code, errb.String())
	}
	if !bytes.Contains(table.Bytes(), []byte("muster.account.root_remote_login")) || bytes.Contains(table.Bytes(), []byte("\x1b")) {
		t.Errorf("table output:\n%s", table.String())
	}
	var quiet bytes.Buffer
	run([]string{"check", "--facts", "testdata/full-fail.json", "--quiet", "--fail-on", "none"}, &quiet, &errb)
	if bytes.Contains(quiet.Bytes(), []byte("muster.service.telnet_disabled")) {
		t.Error("--quiet must hide PASS rows")
	}
}
```

- [ ] **Step 5: Run everything**

Run: `gofmt -l . && go vet ./... && go test ./... && go run ./cmd/muster controls lint && go run ./cmd/muster check --facts cmd/muster/testdata/full-pass.json; echo "exit=$?"`
Expected: all tests PASS; lint prints `ok: 5 controls, set kisa-unix-2026+2026.09.02`; the table shows U-01 PASS, U-02 PASS, U-16 PASS, U-52 PASS, U-25 MANUAL and `exit=0`.

- [ ] **Step 6: Commit**

```bash
git add controls/ internal/controls/fixtures_test.go cmd/muster/testdata cmd/muster/e2e_test.go docs/superpowers/specs/
git commit -m "Add the five stage-1 controls, their fixtures and the end-to-end check"
```

---

### Task 16: CI, secret scanning, CLAUDE.md, THREAT_MODEL.md and SECURITY.md

**Files:**
- Create: `.github/workflows/ci.yml`, `.gitleaks.toml`, `CLAUDE.md`, `THREAT_MODEL.md`, `SECURITY.md`

**Interfaces:**
- Consumes: the whole tree.
- Produces: a CI that fails on gofmt, vet, staticcheck, tests, lint problems or a secret in `testdata/`; the two security documents spec §8 requires; the writing rules of spec §11.

- [ ] **Step 1: Write the CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
          check-latest: false
      - name: gofmt
        run: test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
      - name: vet
        run: go vet ./...
      - name: staticcheck
        run: go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...
      - name: test
        run: go test -race ./...
      - name: controls lint
        run: go run ./cmd/muster controls lint
      - name: build
        run: CGO_ENABLED=0 go build -trimpath ./...
  secrets:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .gitleaks.toml
```

`.gitleaks.toml` (generic patterns only — no organisation name or domain, spec §11):

```toml
title = "muster testdata rules"

[extend]
useDefault = true

[[rules]]
id = "unix-password-hash"
description = "crypt(3) password hash committed in a fixture"
regex = '''\$(1|5|6|y|2[aby]?)\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{20,}'''

[[rules]]
id = "ssh-public-key-material"
description = "SSH public key body committed in a fixture (fingerprints are fine, bodies are not)"
regex = '''ssh-(rsa|ed25519|dss|ecdsa)\s+AAAA[0-9A-Za-z+/]{40,}'''

[[rules]]
id = "private-key-block"
description = "PEM private key block"
regex = '''-----BEGIN [A-Z ]*PRIVATE KEY-----'''

[[rules]]
id = "non-personal-email"
description = "an e-mail address on a non-personal domain in tracked files"
regex = '''[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com)(?!example\.(com|org|net))[A-Za-z0-9.-]+\.(com|net|org|io|co|kr)'''
[rules.allowlist]
paths = ['''go\.sum''', '''LICENSE''']
```

- [ ] **Step 2: Write `CLAUDE.md`**

```markdown
# muster — working notes for Claude

Design: `docs/superpowers/specs/2026-09-02-muster-design.md` (English canonical, Korean pair). It is also the
decision log (D01–D28). Read it before changing any contract: facts schema, control ids, exit codes,
waiver keys, output format.

## Layout

`cmd/muster` dispatch only. `internal/facts` snapshot types and the key registry. `internal/controls`
schema, strict loader, lint. `internal/check` the pure evaluator — it must never import `os/exec`, `net`
or touch the host (a test enforces it). `internal/waiver` waivers, applied after evaluation. `internal/report`
renderers and the exit code. `controls/` the embedded control set and its fixtures. `collect` is Linux-only
and lives behind build tags.

## Rules that are contracts

- Every fact leaf is an envelope; a status other than `ok` never produces `PASS`. A registered key the
  snapshot lacks is `missing` → `ERROR(missing_fact)`, never `absent_means`.
- Exit codes: `check` any `ERROR` → 2 (unless `--allow-error`), any `FAIL` → 1, else 0; `collect`
  0 complete / 1 partial / 2 none. Changing these breaks other people's CI.
- Same input, same bytes. No `map` reaches the JSON or table renderer.
- Result JSON is stdout and nothing else is; warnings are stderr.
- Control and waiver YAML are decoded strictly; unknown keys are errors.
- Never copy KISA guide text or CIS Benchmark text into any file. `docs/reference/kisa/` holds item
  codes, names, categories, importance and page numbers only. See `ATTRIBUTION.md`.
- Fixtures come from public images or are marked `synthetic: true`; never from an employer or customer host.

## Tests

- Every control has `controls/testdata/<id>/pass-*.json` and `fail-*.json`; the prefix is the expected
  status (`fail-` on a `partial` control expects `WARN`). `_expect` may add `reason_code` and `exit_code`.
- Write the test that drives the caller before the test of the helper. After adding a call site, delete
  the call and confirm the suite goes red; if it stays green, the implementation is tested, not the feature.
- Assert something that differs when the call is gone. Prefer structural assertions to substrings.
- Golden files: `go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`,
  `go test ./internal/facts -run TestFactsSchemaGolden -update`. Review the diff before committing a
  regenerated golden; a facts golden change means a `since` entry or a schema version bump.

## Documentation

English canonical, `X.ko.md` pair updated in the same commit. Plans under `docs/superpowers/plans/` are
English-only and deleted once merged. Identifiers, flags and paths stay English on both sides.

## Commits

Personal identity only (pinned in `.git/config`; see `.mailmap`). Never push from an agent session.
```

- [ ] **Step 3: Write `THREAT_MODEL.md` and `SECURITY.md`**

`THREAT_MODEL.md`:

```markdown
# Threat model

muster runs as root on production hosts and produces the most concentrated description of a host an
attacker could ask for. This document says what the tool trusts, what it refuses, and what it cannot do.
The contracts here are tested; the design specification (section 8) is the source.

## Trust boundary

- `collect` runs as root. It reads only paths its collector registry declares and runs only commands on a
  fixed whitelist (absolute path, fixed arguments, timeout, output cap, no shell, rebuilt environment).
  It never parses a control file, a waiver file or a previous snapshot. It writes exactly one file: the
  snapshot. It makes no network connection.
- `check` does not need root and warns when run as root. It treats the snapshot as untrusted input
  (size and nesting limits, no execution of anything it contains, escaped rendering) and, when root,
  refuses waiver and control files that are not root-owned or are group/other-writable.
- Controls are embedded in the binary. An external control directory is opt-in, logged with digests and
  refused on id collision.

## What the snapshot contains and does not

By default: derived attributes instead of secrets — hash algorithm rather than hash, key fingerprint
rather than key, whether an SNMP community is a default value rather than the string. `--include-secrets`
records itself in the snapshot header. Files are 0600 in a 0700 directory, written atomically, never
under `/tmp` by default.

## Reads and the filesystem walk

Every read goes through one primitive that never follows a symbolic link in any path component
(`openat2` with `RESOLVE_NO_SYMLINKS`, or a component-wise `O_NOFOLLOW` walk), refuses FIFOs, devices
and sockets, and caps size. The deep walk is off by default, stays on local filesystems, never enters
`/proc`, `/sys`, `/dev`, `/run` or autofs mount points, and ends with `complete=false` when over budget.

## Limits

- A host that is already compromised — `LD_PRELOAD`, replaced binaries, settings reverted before a run —
  can make muster report `PASS`. muster is not an intrusion detector and does not attest the host.
- muster evaluates configuration, not exposure: it does not scan ports from outside or match CVEs.
- Results depend on the control set version; a report names the set it was produced with.

## Reporting

See `SECURITY.md`.
```

`SECURITY.md`:

```markdown
# Security policy

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security → Report a vulnerability). Do not
open a public issue for a vulnerability in muster itself. Expect an acknowledgement within seven days.

Findings about hosts that muster reported on are not vulnerabilities in muster; do not send them here.

## Supported versions

Until 1.0, only the latest tagged release receives fixes.

## Scope

The threat model is in `THREAT_MODEL.md`. In scope: anything that makes `collect` write, execute or
transmit more than it declares; anything that makes `check` execute content from a snapshot, control or
waiver file; a data file turning an `ERROR` into a clean exit; a snapshot storing a secret that the
redaction policy says it must not.
```

- [ ] **Step 4: Verify locally**

Run: `gofmt -l . && go vet ./... && go test -race ./... && go run ./cmd/muster controls lint`
Expected: all green (on Windows `-race` needs a C toolchain; if unavailable run `go test ./...` and note that CI runs `-race` on Linux).

- [ ] **Step 5: Commit**

```bash
git add .github/ .gitleaks.toml CLAUDE.md THREAT_MODEL.md SECURITY.md
git commit -m "Add CI, secret scanning rules, CLAUDE.md, threat model and security policy"
```

---

## Self-review

**Spec coverage (stage 1 items in §10.2 that this plan implements):** facts schema with envelope (T2), settings (T2, T9), registry (T4), provenance (T3); determinism (T12–13); exit codes (T14); waivers (T11); redaction policy — a schema decision recorded in `registry.yaml` `sensitivity` (T4) and enforced by the collector in Plan 1B; controls lint (T7); fixture convention and registry test (T15); result invariants (T15); secret scanning (T16); recover guard (T1); `THREAT_MODEL.md`, `SECURITY.md` (T16); README pair and `ATTRIBUTION.md` already exist. **Left to Plan 1B (Linux):** `collect`, the read primitive, exec discipline, the collector registry with `--list-actions`, the walk skeleton, the snapshot lifecycle (path, naming, lock, 0600 atomic write), the five collectors, `collect` exit codes, `--require-root`.

**Spec deviations recorded:** §10.2 U-16 stage-1 behaviour is `FAIL` on ACL present (T15 Step 3 edits the spec). `--fail-on manual` includes `WARN` (T14) — §7.2 says "respectively"; the inclusive reading keeps the levels ordered and is what the test fixes.

**Placeholder scan:** no TBD/TODO; every code step has code; `controls/account/root_remote_login.yaml` is needed by the embed glob in T6 and is defined in full in T15 Step 1 — T6 says to copy it forward.

**Type consistency:** `facts.Status`, `facts.Envelope`, `facts.Setting`, `facts.Registry.Resolve` (T2/T4) are what `check` consumes (T8–T10); `check.Result`/`Status`/`ReasonCode` (T8) are what `waiver` (T11) and `report` (T12–T14) consume; `controls.Clause` field names (T6) match the lint (T7) and evaluator (T9–T10); `report.ExitCode` signature (T14) is used by the fixture test (T15).

## What comes next

Plan 1B (`docs/superpowers/plans/2026-09-02-stage1b-collect-side.md`) builds the Linux side on top of these types: the read primitive, exec discipline, the collector registry and `--list-actions`, the snapshot lifecycle, the five collectors that populate the keys in `registry.yaml`, redaction, `collect` exit codes and the Linux CI job. It must be executed on a Linux host with root (a CI container or a lab VM); nothing in it runs on Windows.

## Execution notes

Executed 2026-09-02/03 by subagent-driven development on branch `stage1a-check-side`. Where the task text above disagreed with the spec, or its code turned out defective, the controller ruled and the spec won. The built result differs from the task text in these ways (ruling numbers refer to the execution ledger):

- **Parameter references (T7, T15, spec §6.2).** `${name}` inside a YAML flow mapping is quoted, `expected: "${allowed}"`; an unquoted brace ends the mapping (R5).
- **Derivation (T10, spec §6.5).** For walk-based controls the walk gate (steps 9–10) runs before fact-status screening (steps 6–8); a sentence was added to §6.5 (R2). Screening is per selected side, and `both` with one absent side degrades to `WARN` instead of erroring (R15). Every non-`PASS` result carries evidence, including `ERROR`/`NOT_APPLICABLE` from steps 3, 5, 6, 7 and the walk gate (R16, R25); evidence is deduplicated per fact, side, status and value. A hard clause failure is never shadowed by another clause's side-mismatch degradation. Step 13's parse-fallback degradation for `sshd.options.*` is implemented (R34). `describe()` renders substituted parameters and the `where`/`require` sub-clause of `each`/`none` (R27). `toInt` rejects non-integral and out-of-int64 numbers, and `Resolve` turns any status a collector may not write into an `error` envelope.
- **Waivers (T11).** Tallies are per entry; shadowed and unmatched subject waivers produce warnings (R17); duplicate `(control, subject)` pairs are refused at load (R33); "expiring soon" is inclusive of day 30.
- **Report (T12–T14).** `facts_failed` counts collector runs with status other than `ok` (R19). Every snapshot-derived string the table writes, including `source.path`, `source.cmd`, `collected_at` and observation values, passes through `escape`; the narrow golden differs from the wide one (R20, R21). `CheckBlock.Params` is populated for controls that declare parameters (R30).
- **Controls and fixtures (T15).** `passwd_permissions` compares the mode with `op: in` over the 16 bit-subsets of `0644` because the vocabulary has no bit operator (R22). `root_remote_login`'s description and remediation cover the securetty mechanism, and both it and `world_writable` use `absent_means: manual` (R23, R28). Extra fixtures: `fail-securetty-pts`, `fail-0642`, `manual-absent-list`, `manual-nothing-readable`, `warn-parse-fallback`, `fail-both-sides-plus-mismatch`. The e2e test asserts status per control id and every exit code, and runs `--waivers` end to end (R26). Every fixture carries a top-level `"synthetic": true`. The fact written as `files.etc_securetty.lines` in T4 and T15 above is keyed `files.etc_securetty_lines`, a sibling leaf, so every leaf stays an envelope (R32; Plan 1B updated to write the sibling).
- **CI and lint (T16, T7).** The gitleaks rules are written for RE2 (no lookaheads) with literal allowlists (R29), plus internal-hostname and private-IPv4 rules (R31). `controls lint` fails when the fixture directory is missing, accepts `--fixtures DIR`, and prints registered keys no control uses (R35).
- **Parked for stage 1B/2 (R36).** SHA-pinned actions, duplicate JSON keys in a snapshot, the `__panic_for_test` seam, the stat-then-open window on `--waivers` (low), `Observation.Source`, a coverage gate on `internal/check`.
