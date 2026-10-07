# Stage 3D-1 — profiles and tuning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `check --profile <name|path>` selects controls, parameter values and severities through a profile file (or the built-in `default`), `check --tuning <path>` layers a site's parameter values on top, and the result records the profile, the tuning file and every value's source — without evaluating or listing an excluded control.

**Architecture:** Two new pure packages — `internal/profile` (parse, classify a name or path, resolve the `extends` chain against the loaded control set into selected ids, chain values, an ordered severity list and a content digest; merge the tuning in with per-parameter provenance) and `internal/tuning` (parse and validate a site's `params:`). `cmd/muster` wires them in one helper, `resolveSelection`, that `check`, `controls lint --profile`, `controls list --profile` and the examples test share; the evaluator is untouched and runs over a `Set.Subset`; `waiver.Apply` learns the excluded set; `report.Build` applies the severity map and the `check` block gains `profile`, `tuning` and `param_sources`.

**Tech Stack:** Go 1.25 (no cgo on the Windows dev box; `-race` on the lab and CI), `gopkg.in/yaml.v3` strict decoding (as `waiver.Load`), `encoding/json` canonical digests, `path.Match` globs, the existing golden/e2e/fuzz harnesses.

**Spec:** `docs/superpowers/specs/2026-10-07-stage3d1-profiles-design.md` (+ `.ko.md`), decisions Y-1..Y-9. The code map the plan was written from: `.superpowers/sdd/2026-10-07-stage3d1-profiles/code-map.md` (git-ignored; verbatim signatures at HEAD `e7a084c`).

## Global Constraints

- **Z-1 — The result is additive and lives in `check`.** `CheckBlock` field order after the change: `muster_version, commit, controls_version, controls_digest, snapshot_digest, guide_edition, profile, tuning (omitted when nil), waivers, params (omitted when nil), param_sources (omitted when nil)`. `Row` gains `severity_source` after `severity`. `run` is never touched (spec Y-9, main design §9).
- **Z-2 — Strict YAML everywhere.** `profile.Parse` and `tuning.Parse` use `yaml.NewDecoder` + `KnownFields(true)` and tolerate `io.EOF` exactly as `waiver.Load` does; an unknown key is an error naming the file.
- **Z-3 — Values keep yaml.v3's shapes.** A profile or tuning value is validated by `controls.CheckParamValue(typ, v)` and stored as decoded: `int`, `string`, `bool`, `[]any` of `int` or `string` — never `[]string`/`[]int` (the evaluator's comparators and `check.params` rendering expect `[]any`).
- **Z-4 — Determinism.** Every list the result or the digest carries is sorted by the producer (`excluded_ids`, `ids`, chain in walk order); maps reach the renderer only through `encoding/json` (sorted keys) as `check.params` does today; a nil `[]string` destined for JSON is `[]string{}`.
- **Z-5 — No host access in the new packages.** `internal/profile` and `internal/tuning` import none of `os`, `os/exec`, `net`, `syscall`; they read files only through the `open func(string) ([]byte, error)` the caller passes; `path/filepath` is allowed (pure string work); warnings go through `warn func(string)`.
- **Z-6 — The evaluator is untouched.** No edit to `internal/check` except none; `check.Options.Params` receives the merged map; `Evaluate` runs over the subset.
- **Z-7 — Contracts that stay.** Exit codes (`report.ExitCode` reads statuses); `--fail-on` semantics; the `ok: %d controls, set %s` lint line byte-identical; `controls list`'s four-column row format; `maskedCheckKeys` unchanged; the controls digest unchanged (no YAML edit, `controls/VERSION` stays `kisa-unix-2026+2026.10.02`); schema_version unchanged.
- **Z-8 — Naming.** Built-in names: `default` and its alias `kisa-unix-2026`; a built-in's result/chain spelling is `builtin` / `builtin:default`; a file's is `file:<path>` (the flag's path as given; a chain file's cleaned opened path). Warning texts, verbatim: `profile parameter <id>.<param> ignored: excluded by profile`, `tuning parameter <id>.<param> ignored: excluded by profile`, `severity entry <glob> matches only excluded controls`, `waiver for <id> not applied: excluded by profile`. Refusal texts start with the file's path (`<path>: …`) and reach the user as `muster: <reason>`.
- **Z-9 — Tests before code, every task; commits end with the two trailers (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Claude-Session: https://claude.ai/code/session_01LjfwtnJHSH7afTYL99Pmom`); never amend/rebase/stash/push; documents in English and Korean in the same commit (Task 7).
- **Z-10 — Gates per task (W-16 of 3C-2b, carried):** `gofmt -l .` empty; `go vet ./...` and `GOOS=linux GOARCH=amd64 go vet ./...`; Windows `go test ./... -count=1`; the lab (root, through the two read-only scripts only) `go test ./... -count=1` + `staticcheck ./...` silent for Tasks 4–6 (Tasks 1–3 are pure and need no lab run); `go run ./cmd/muster controls lint --references docs/reference` (`ok: 117 controls, set kisa-unix-2026+2026.10.02`); `go run ./tools/coverage -check`; `gitleaks git --log-opts="<base>..HEAD" --no-banner --redact` clean; the host-string grep 0.

## Review Focus

1. **A profile value for a control the profile excludes.** Expected: one warning (`profile parameter <id>.<param> ignored: excluded by profile`), the value in `Resolved.Params` and the digest but in neither `check.params` nor `check.param_sources`, exit 0. Pinned in Task 3 (`TestMergeWarnsAndDropsValuesForExcludedControls`) and Task 6 (e2e `TestCheckProfileTuningForExcludedControlWarns`).
2. **A chain that reaches one file through two spellings (`./a.yaml` and `a.yaml`).** Expected: refused as a cycle by the cleaned path, not as "chain over four files". Pinned in Task 3 (`TestResolveRefusesACycleSpelledTwoWays`).
3. **`--profile Default` (a typo that is no built-in and no path).** Expected: refused naming the built-ins, never opened as a file. Pinned in Task 3 (`TestSourceOf`) and Task 6 (e2e `TestCheckProfileUnknownNameNamesTheBuiltins`).
4. **A waiver on a control the profile excludes, expired or not.** Expected: counted `not_applied` once, warned, never `unknown`, never silently dropped. Pinned in Task 4 (`TestApplyCountsAnExcludedWaiverAsNotApplied`, incl. the expired and subject-level cases).
5. **A group-writable profile, chain file or tuning file when `check` runs as root.** Expected: refused naming that path, exit 2, empty stdout. Pinned in Task 6 (e2e `TestCheckRootRefusesWritableProfileFiles`, skipped unless euid 0 — the CI root job runs it).

---

### Task 1: `internal/controls` — `Set.Subset` and `CheckParamValue`

**Files:**
- Modify: `internal/controls/load.go` (after `ByID`, line 33)
- Modify: `internal/controls/lint.go:149-155` (the param loop) and `:316-351` (`paramDefaultMatches`)
- Create: `internal/controls/params.go`
- Test: `internal/controls/subset_test.go`, `internal/controls/params_test.go`

**Interfaces:**
- Consumes: `Set{Version, Digest, Controls, byID}`, `Control.Params map[string]Param`, `Param{Type, Default}`, `validParamType`.
- Produces: `func (s *Set) Subset(ids []string) *Set` — a view holding, in the set's order, the controls whose id is in `ids` (unknown ids ignored), with `Version` and `Digest` copied verbatim and `byID` rebuilt; `func CheckParamValue(typ string, v any) error` — nil when `v` has the shape `paramDefaultMatches` accepted for `typ`, otherwise `fmt.Errorf("value %v is not a %s", v, typ)` (an unknown `typ` → `fmt.Errorf("unknown parameter type %q", typ)`).

- [ ] **Step 1: Write the failing tests**

```go
// internal/controls/subset_test.go
package controls

import "testing"

func testSet() *Set {
	s := &Set{Version: "v", Digest: "sha256:d", Controls: []Control{
		{ID: "muster.account.a", Importance: "상"},
		{ID: "muster.beyond.b", Importance: "중", Params: map[string]Param{"n": {Type: "int", Default: 1}}},
		{ID: "muster.file.c", Importance: "하"},
	}}
	s.byID = map[string]int{}
	for i, c := range s.Controls {
		s.byID[c.ID] = i
	}
	return s
}

func TestSubsetKeepsOrderVersionDigestAndByID(t *testing.T) {
	s := testSet()
	sub := s.Subset([]string{"muster.file.c", "muster.account.a", "muster.no.such"})
	if got := len(sub.Controls); got != 2 {
		t.Fatalf("subset has %d controls, want 2", got)
	}
	if sub.Controls[0].ID != "muster.account.a" || sub.Controls[1].ID != "muster.file.c" {
		t.Errorf("subset order %q %q, want the set's order", sub.Controls[0].ID, sub.Controls[1].ID)
	}
	if sub.Version != s.Version || sub.Digest != s.Digest {
		t.Errorf("subset version/digest %q %q, want the full set's", sub.Version, sub.Digest)
	}
	if c, ok := sub.ByID("muster.file.c"); !ok || c.ID != "muster.file.c" {
		t.Errorf("ByID on the subset: %v %v", c, ok)
	}
	if _, ok := sub.ByID("muster.beyond.b"); ok {
		t.Errorf("ByID found an excluded control on the subset")
	}
	if len(s.Controls) != 3 {
		t.Errorf("Subset mutated the full set")
	}
}

func TestSubsetOfALiteralSetRebuildsTheIndex(t *testing.T) {
	s := &Set{Controls: []Control{{ID: "x"}, {ID: "y"}}} // byID nil, as tests build sets
	sub := s.Subset([]string{"y"})
	if c, ok := sub.ByID("y"); !ok || c.ID != "y" {
		t.Fatalf("ByID on a subset of a literal set: %v %v", c, ok)
	}
}
```

```go
// internal/controls/params_test.go
package controls

import "testing"

func TestCheckParamValueAcceptsTheDeclaredShapes(t *testing.T) {
	ok := []struct {
		typ string
		v   any
	}{
		{"int", 5}, {"string", "x"}, {"bool", true},
		{"list<int>", []any{1, 2}}, {"list<string>", []any{"a"}}, {"list<string>", []any{}},
	}
	for _, c := range ok {
		if err := CheckParamValue(c.typ, c.v); err != nil {
			t.Errorf("CheckParamValue(%s, %v) = %v, want nil", c.typ, c.v, err)
		}
	}
	bad := []struct {
		typ string
		v   any
	}{
		{"int", "5"}, {"int", int64(5)}, {"int", 5.0}, {"string", 5}, {"bool", "true"},
		{"list<int>", []any{"1"}}, {"list<int>", []int{1}}, {"list<string>", []string{"a"}},
		{"list<string>", "a"}, {"list<string>", []any{1}}, {"record", 1},
	}
	for _, c := range bad {
		if err := CheckParamValue(c.typ, c.v); err == nil {
			t.Errorf("CheckParamValue(%s, %#v) = nil, want an error", c.typ, c.v)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/controls -run 'TestSubset|TestCheckParamValue' -count=1`
Expected: compile errors `s.Subset undefined`, `undefined: CheckParamValue`.

- [ ] **Step 3: Implement**

```go
// internal/controls/load.go — after ByID
// Subset is a view of the set holding, in the set's order, the controls whose
// id is in ids (an id the set does not know is ignored). It carries the full
// set's Version and Digest: the controls digest names the embedded YAML,
// never a selection (stage 3D-1, Y-7).
func (s *Set) Subset(ids []string) *Set {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	sub := &Set{Version: s.Version, Digest: s.Digest, byID: map[string]int{}}
	for _, c := range s.Controls {
		if want[c.ID] {
			sub.byID[c.ID] = len(sub.Controls)
			sub.Controls = append(sub.Controls, c)
		}
	}
	return sub
}
```

```go
// internal/controls/params.go
package controls

import "fmt"

// CheckParamValue reports whether v has the shape a parameter of type typ
// takes: yaml.v3's own decoding of a scalar or a sequence (int, string,
// bool, []any of int or string) — the same test the lint applies to a
// declared default, shared with the profile and tuning loaders (3D-1).
func CheckParamValue(typ string, v any) error {
	ok := false
	switch typ {
	case "string":
		_, ok = v.(string)
	case "int":
		_, ok = v.(int)
	case "bool":
		_, ok = v.(bool)
	case "list<string>", "list<int>":
		xs, isList := v.([]any)
		if !isList {
			return fmt.Errorf("value %v is not a %s", v, typ)
		}
		ok = true
		for _, x := range xs {
			if typ == "list<string>" {
				_, ok = x.(string)
			} else {
				_, ok = x.(int)
			}
			if !ok {
				break
			}
		}
	default:
		return fmt.Errorf("unknown parameter type %q", typ)
	}
	if !ok {
		return fmt.Errorf("value %v is not a %s", v, typ)
	}
	return nil
}
```

In `lint.go`, replace the body of `paramDefaultMatches` with `return CheckParamValue(p.Type, p.Default) == nil` (keep the function and its call site at `:152` so the lint message is unchanged).

- [ ] **Step 4: Run the tests and the lint**

Run: `go test ./internal/controls -count=1` then `go run ./cmd/muster controls lint --references docs/reference`
Expected: all ok; `ok: 117 controls, set kisa-unix-2026+2026.10.02` (every default still matches).

- [ ] **Step 5: Commit**

```bash
git add internal/controls/load.go internal/controls/params.go internal/controls/lint.go internal/controls/subset_test.go internal/controls/params_test.go
git commit -m "Give the control set a subset view and share the parameter typing the lint applies"
```

---

### Task 2: `internal/tuning` — parse and load a site's values

**Files:**
- Create: `internal/tuning/tuning.go`, `internal/tuning/tuning_test.go`, `internal/tuning/fuzz_test.go`, `internal/tuning/testdata/fuzz/FuzzParseTuning/seed1` (and `seed2`), `internal/tuning/imports_test.go`, `internal/tuning/fuzz_inventory_test.go`
- Test: as above

**Interfaces:**
- Consumes: `controls.Set` (`ByID`, `Control.Params`), `controls.CheckParamValue`.
- Produces:
  ```go
  package tuning
  var ErrInvalid = errors.New("invalid tuning file")
  type File struct{ Params map[string]map[string]any `yaml:"params"` }
  type Tuning struct{ Params map[string]map[string]any; Path, Digest string }
  func Parse(data []byte) (*File, error)
  func Load(set *controls.Set, path string, open func(string) ([]byte, error)) (*Tuning, error)
  ```
  `Load` reads through `open`, parses strictly, refuses an unknown control (`<path>: tuning names unknown control <id>`), an unknown parameter (`<path>: control <id> has no parameter <name>`) or a mistyped value (`<path>: <id>.<name>: value … is not a <type>`), and returns the map as decoded plus `sha256:` of the bytes. It never sees the selection (the exclusion warning is `profile.Merge`'s).

- [ ] **Step 1: Write the failing tests**

```go
// internal/tuning/tuning_test.go
package tuning

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func set() *controls.Set {
	s := &controls.Set{Controls: []controls.Control{
		{ID: "muster.account.password_policy", Params: map[string]controls.Param{"min_len": {Type: "int", Default: 8}}},
		{ID: "muster.beyond.exposed_listeners_allowed", Params: map[string]controls.Param{"allowed_ports": {Type: "list<string>", Default: []any{"tcp/22"}}}},
		{ID: "muster.file.world_writable"},
	}}
	return s.Subset([]string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.file.world_writable"})
}

func openString(src string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(src), nil }
}

func TestLoadReadsValidatesAndDigests(t *testing.T) {
	src := "params:\n  muster.account.password_policy:\n    min_len: 12\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n"
	tn, err := Load(set(), "site/tuning.yaml", openString(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tn.Path != "site/tuning.yaml" || !strings.HasPrefix(tn.Digest, "sha256:") {
		t.Errorf("path/digest %q %q", tn.Path, tn.Digest)
	}
	if tn.Params["muster.account.password_policy"]["min_len"] != 12 {
		t.Errorf("min_len = %#v, want int 12", tn.Params["muster.account.password_policy"]["min_len"])
	}
	ports, ok := tn.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any)
	if !ok || len(ports) != 2 || ports[1] != "tcp/443" {
		t.Errorf("allowed_ports = %#v, want []any{tcp/22, tcp/443}", tn.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"])
	}
	tn2, _ := Load(set(), "elsewhere.yaml", openString(src))
	if tn2.Digest != tn.Digest {
		t.Errorf("digest depends on the path: %s vs %s", tn.Digest, tn2.Digest)
	}
}

func TestLoadRefusals(t *testing.T) {
	cases := map[string]string{
		"unknown key":       "params: {}\nseverity: []\n",
		"unknown control":   "params:\n  muster.no.such:\n    x: 1\n",
		"unknown parameter": "params:\n  muster.account.password_policy:\n    max_len: 1\n",
		"wrong type":        "params:\n  muster.account.password_policy:\n    min_len: twelve\n",
		"list of wrong kind": "params:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [22]\n",
		"not a map":         "params: 3\n",
	}
	for name, src := range cases {
		_, err := Load(set(), "t.yaml", openString(src))
		if err == nil {
			t.Errorf("%s: Load accepted %q", name, src)
			continue
		}
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "t.yaml") {
			t.Errorf("%s: error %v should wrap ErrInvalid and name the path", name, err)
		}
	}
}

func TestLoadOpenErrorAndEmptyFile(t *testing.T) {
	if _, err := Load(set(), "missing.yaml", func(string) ([]byte, error) { return nil, os.ErrNotExist }); err == nil {
		t.Errorf("Load swallowed the open error")
	}
	tn, err := Load(set(), "empty.yaml", openString(""))
	if err != nil || len(tn.Params) != 0 {
		t.Errorf("an empty file is a tuning with no params: %v %v", tn, err)
	}
}
```

```go
// internal/tuning/fuzz_test.go
package tuning

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseTuning(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/fuzz/FuzzParseTuning/seed*")
	for _, s := range seeds {
		b, err := os.ReadFile(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("params:\n  a.b:\n    c: [1, 2]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil && file != nil {
			t.Fatalf("error with a file: %v", err)
		}
	})
}
```

Seeds: `testdata/fuzz/FuzzParseTuning/seed1` = the `src` of `TestLoadReadsValidatesAndDigests`; `seed2` = `params: {}\n`.

```go
// internal/tuning/imports_test.go
package tuning

import (
	"os/exec"
	"strings"
	"testing"
)

// The tuning package reads files only through the open function its caller
// passes and never writes to stderr (3D-1 Z-5): no host API is imported.
func TestTuningPackageHasNoHostImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/kun9497/muster/internal/tuning").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch imp {
		case "os", "os/exec", "net", "syscall":
			t.Errorf("internal/tuning imports %s", imp)
		}
	}
}
```

```go
// internal/tuning/fuzz_inventory_test.go
package tuning

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fuzzTargets pins the package's fuzz targets; every function taking []byte
// must be a direct callee of one (the collectors' inventory rule, slimmed).
var fuzzTargets = []string{"FuzzParseTuning"}

func TestEveryParserHasAFuzzTarget(t *testing.T) {
	inventory := byteTakers(t)
	targets := fuzzTargetCalls(t)
	var declared []string
	for name := range targets {
		declared = append(declared, name)
	}
	slices.Sort(declared)
	if !slices.Equal(declared, fuzzTargets) {
		t.Errorf("fuzz_test.go declares %v, fuzzTargets pins %v", declared, fuzzTargets)
	}
	for _, fn := range inventory {
		covered := false
		for _, calls := range targets {
			if calls[fn] {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s takes []byte and no fuzz target calls it", fn)
		}
	}
}

func byteTakers(t *testing.T) []string {
	t.Helper()
	names, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	var out []string
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, p := range fn.Type.Params.List {
				if arr, ok := p.Type.(*ast.ArrayType); ok && arr.Len == nil {
					if el, ok := arr.Elt.(*ast.Ident); ok && el.Name == "byte" {
						out = append(out, fn.Name.Name)
					}
				}
			}
		}
	}
	return out
}

func fuzzTargetCalls(t *testing.T) map[string]map[string]bool {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), "fuzz_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch f := c.Fun.(type) {
				case *ast.Ident:
					calls[f.Name] = true
				case *ast.SelectorExpr:
					calls[f.Sel.Name] = true
				}
			}
			return true
		})
		out[fn.Name.Name] = calls
	}
	return out
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/tuning -count=1`
Expected: build failure (`undefined: Load`, `Parse`, `ErrInvalid`).

- [ ] **Step 3: Implement `tuning.go`**

```go
// Package tuning reads one site's parameter values for muster's controls
// (stage 3D-1, spec §4): exact control ids, strictly typed, applied after the
// profile by profile.Merge. The package never touches the host: files come
// through the open function the caller passes (Z-5).
package tuning

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/controls"
)

var ErrInvalid = errors.New("invalid tuning file")

// File is the tuning file as decoded.
type File struct {
	Params map[string]map[string]any `yaml:"params"`
}

// Tuning is a validated tuning file.
type Tuning struct {
	Params map[string]map[string]any
	Path   string
	Digest string
}

// Parse decodes a tuning file strictly (Z-2). An empty file is a File with
// no params.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return &f, nil
}

// Load reads path through open, parses it and validates every entry against
// the control set: an unknown control, an unknown parameter or a value of the
// wrong shape refuses the file naming the path. The digest is sha256 of the
// bytes, as the waiver file's is.
func Load(set *controls.Set, path string, open func(string) ([]byte, error)) (*Tuning, error) {
	data, err := open(path)
	if err != nil {
		return nil, err
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, errors.Unwrap(err))
	}
	if err := Validate(set, f.Params); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, path, err)
	}
	sum := sha256.Sum256(data)
	return &Tuning{Params: f.Params, Path: path, Digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// Validate checks a params map against the set: ids must exist, parameters
// must be declared, values must have the declared type (shared with the
// profile loader, which validates its params the same way).
func Validate(set *controls.Set, params map[string]map[string]any) error {
	ids := make([]string, 0, len(params))
	for id := range params {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, ok := set.ByID(id)
		if !ok {
			return fmt.Errorf("tuning names unknown control %s", id)
		}
		names := make([]string, 0, len(params[id]))
		for n := range params[id] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p, declared := c.Params[n]
			if !declared {
				return fmt.Errorf("control %s has no parameter %s", id, n)
			}
			if err := controls.CheckParamValue(p.Type, params[id][n]); err != nil {
				return fmt.Errorf("%s.%s: %v", id, n, err)
			}
		}
	}
	return nil
}
```

Note: the test set in `tuning_test.go` is built through `Subset` so `ByID` works on a literal set (Task 1).

- [ ] **Step 4: Run the tests and the fuzz seeds**

Run: `go test ./internal/tuning -count=1 -v | tail -20` and `go test ./internal/tuning -run '^$' -fuzz FuzzParseTuning -fuzztime 10s`
Expected: all PASS, incl. `TestEveryParserHasAFuzzTarget` (inventory = `Parse`) and `TestTuningPackageHasNoHostImports`; no crash in 10 s.

- [ ] **Step 5: Commit**

```bash
git add internal/tuning
git commit -m "Add the tuning package: a site's parameter values, strictly typed against the control set"
```

---

### Task 3: `internal/profile` — parse, classify, resolve, merge, digest

**Files:**
- Create: `internal/profile/profile.go` (types, `Parse`, `SourceOf`, built-ins), `internal/profile/resolve.go` (`Resolve`, chain, globs, severity, digest), `internal/profile/merge.go` (`Merge`), `internal/profile/profile_test.go`, `internal/profile/resolve_test.go`, `internal/profile/merge_test.go`, `internal/profile/fuzz_test.go`, `internal/profile/testdata/fuzz/FuzzParseProfile/seed1`, `internal/profile/testdata/*.yaml` (`base.yaml`, `child.yaml`, `cycle-a.yaml`, `cycle-b.yaml`, `five-1.yaml`…`five-5.yaml`), `internal/profile/imports_test.go`, `internal/profile/fuzz_inventory_test.go` (copy Task 2's two test files with the package name and `fuzzTargets = []string{"FuzzParseProfile"}`)

**Interfaces:**
- Consumes: `controls.Set` (`Controls`, `ByID`, `Subset`), `controls.CheckParamValue`, `tuning.Tuning`, `tuning.Validate`.
- Produces:
  ```go
  package profile
  var ErrInvalid = errors.New("invalid profile")
  type SeverityEntry struct{ Controls string `yaml:"controls"`; Level string `yaml:"level"` }
  type File struct {
      Profile  string                    `yaml:"profile"`
      Extends  string                    `yaml:"extends,omitempty"`
      Include  []string                  `yaml:"include,omitempty"`
      Exclude  []string                  `yaml:"exclude,omitempty"`
      Params   map[string]map[string]any `yaml:"params,omitempty"`
      Severity []SeverityEntry           `yaml:"severity,omitempty"`
  }
  type Source struct{ Name, Path string }   // exactly one set
  func SourceOf(s string) Source
  func Builtins() []string                  // {"default", "kisa-unix-2026"}
  func Parse(data []byte) (*File, error)
  type Resolved struct {
      Name         string            // "default" for the built-in and its alias
      Source       string            // "builtin" | "file:<path as given>"
      Chain        []string          // root-first: "builtin:default", "file:<cleaned path>", …
      IDs          []string          // sorted selected ids
      Params       map[string]map[string]any // the chain's own values, child over parent, selected or not
      Severity     []SeverityEntry   // parent entries then child entries
      SeverityByID map[string]string // over the selected ids, last matching entry wins
      Digest       string            // "sha256:" of {ids, params, severity}
  }
  func Resolve(set *controls.Set, src Source, open func(string) ([]byte, error), warn func(string)) (*Resolved, error)
  func Merge(set *controls.Set, r *Resolved, t *tuning.Tuning, warn func(string)) (params map[string]map[string]any, sources map[string]map[string]string)
  ```
  `Merge` returns one entry per selected control that declares params, every declared parameter present with its value in force and its source (`default` | `profile` | `tuning`); a profile or tuning value for an excluded control is warned (Z-8 texts) and absent; `t` may be nil.

- [ ] **Step 1: Write the failing tests** (the main ones; the implementer adds the table rows the spec §6 lists — a fifth chain file, a missing file, an unknown name, a malformed pattern, an unmatched pattern, a no-op exclude, each param type, a file naming a built-in, empty selection)

```go
// internal/profile/profile_test.go
package profile

import "testing"

func TestSourceOf(t *testing.T) {
	cases := map[string]Source{
		"default":          {Name: "default"},
		"kisa-unix-2026":   {Name: "kisa-unix-2026"},
		"Default":          {Name: "Default"},
		"site_web":         {Name: "site_web"},
		"kisa.unix.2026":   {Name: "kisa.unix.2026"},
		"site.yaml":        {Path: "site.yaml"},
		"b.yml":            {Path: "b.yml"},
		"a/b.yaml":         {Path: "a/b.yaml"},
		"./site":           {Path: "./site"},
		`C:\muster\p.yaml`: {Path: `C:\muster\p.yaml`},
		"profiles\\x":      {Path: "profiles\\x"},
	}
	for in, want := range cases {
		if got := SourceOf(in); got != want {
			t.Errorf("SourceOf(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestParseIsStrict(t *testing.T) {
	if _, err := Parse([]byte("profile: a\ninclude: [x]\nincldue: [y]\n")); err == nil {
		t.Errorf("an unknown key parsed")
	}
	f, err := Parse([]byte("profile: a\nseverity:\n  - { controls: \"muster.*\", level: low }\n"))
	if err != nil || f.Profile != "a" || len(f.Severity) != 1 || f.Severity[0].Level != "low" {
		t.Errorf("Parse: %+v %v", f, err)
	}
}
```

```go
// internal/profile/resolve_test.go
package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func set() *controls.Set {
	s := &controls.Set{Version: "v", Digest: "sha256:d", Controls: []controls.Control{
		{ID: "muster.account.password_policy", Importance: "상", Params: map[string]controls.Param{"min_len": {Type: "int", Default: 8}}},
		{ID: "muster.beyond.exposed_listeners_allowed", Importance: "중", Params: map[string]controls.Param{"allowed_ports": {Type: "list<string>", Default: []any{"tcp/22"}}}},
		{ID: "muster.beyond.no_deleted_executables", Importance: "중"},
		{ID: "muster.file.ip_port_restriction", Importance: "상"},
		{ID: "muster.file.world_writable", Importance: "하"},
	}}
	return s.Subset([]string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.beyond.no_deleted_executables", "muster.file.ip_port_restriction", "muster.file.world_writable"})
}

// files is an in-memory filesystem for open; keys are cleaned paths.
func files(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if s, ok := m[filepath.Clean(p)]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
}

func noWarn(t *testing.T) func(string) {
	return func(msg string) { t.Errorf("unexpected warning %q", msg) }
}

func TestResolveBuiltinDefaultAndAlias(t *testing.T) {
	for _, name := range []string{"default", "kisa-unix-2026"} {
		r, err := Resolve(set(), Source{Name: name}, nil, noWarn(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Name != "default" || r.Source != "builtin" || len(r.Chain) != 1 || r.Chain[0] != "builtin:default" {
			t.Errorf("%s: name/source/chain %q %q %v", name, r.Name, r.Source, r.Chain)
		}
		if len(r.IDs) != 5 || r.IDs[0] != "muster.account.password_policy" {
			t.Errorf("%s: ids %v", name, r.IDs)
		}
		if len(r.SeverityByID) != 0 || len(r.Params) != 0 {
			t.Errorf("%s: the built-in sets no severity or params", name)
		}
	}
}

func TestResolveChainIncludeExcludeParamsSeverity(t *testing.T) {
	fs := files(map[string]string{
		"profiles/base.yaml": "profile: base\nextends: default\nexclude: [\"muster.beyond.*\"]\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n",
		"profiles/site.yaml": "profile: site\nextends: base.yaml\ninclude: [muster.beyond.exposed_listeners_allowed]\nparams:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n  muster.beyond.no_deleted_executables: {}\nseverity:\n  - { controls: muster.file.world_writable, level: high }\n",
	})
	r, err := Resolve(set(), Source{Path: "profiles/site.yaml"}, fs, noWarn(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantIDs := []string{"muster.account.password_policy", "muster.beyond.exposed_listeners_allowed", "muster.file.ip_port_restriction", "muster.file.world_writable"}
	if strings.Join(r.IDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("ids %v, want %v (the child re-includes one beyond control)", r.IDs, wantIDs)
	}
	wantChain := []string{"builtin:default", "file:" + filepath.Clean("profiles/base.yaml"), "file:profiles/site.yaml"}
	if strings.Join(r.Chain, ",") != strings.Join(wantChain, ",") {
		t.Errorf("chain %v, want %v", r.Chain, wantChain)
	}
	if r.Source != "file:profiles/site.yaml" || r.Name != "site" {
		t.Errorf("source/name %q %q", r.Source, r.Name)
	}
	if r.SeverityByID["muster.file.world_writable"] != "high" || r.SeverityByID["muster.file.ip_port_restriction"] != "low" {
		t.Errorf("severity map %v: the later entry wins, the earlier still applies elsewhere", r.SeverityByID)
	}
	if _, has := r.SeverityByID["muster.account.password_policy"]; has {
		t.Errorf("an unmatched control has no severity entry: %v", r.SeverityByID)
	}
	if got := r.Params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any); len(got) != 2 {
		t.Errorf("params %v", r.Params)
	}
}

func TestResolveRefusesACycleSpelledTwoWays(t *testing.T) {
	fs := files(map[string]string{
		"a.yaml": "profile: a\nextends: ./b.yaml\ninclude: [\"muster.*\"]\n",
		"b.yaml": "profile: b\nextends: a.yaml\n",
	})
	_, err := Resolve(set(), Source{Path: "./a.yaml"}, fs, noWarn(t))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("want a cycle error, got %v", err)
	}
}

func TestResolveChainLengthFourFilesFiveRefused(t *testing.T) {
	m := map[string]string{"p1.yaml": "profile: p1\ninclude: [\"muster.*\"]\n"}
	for i := 2; i <= 5; i++ {
		m[fmt.Sprintf("p%d.yaml", i)] = fmt.Sprintf("profile: p%d\nextends: p%d.yaml\n", i, i-1)
	}
	fs := files(m)
	if _, err := Resolve(set(), Source{Path: "p4.yaml"}, fs, noWarn(t)); err != nil {
		t.Errorf("four files: %v", err)
	}
	if _, err := Resolve(set(), Source{Path: "p5.yaml"}, fs, noWarn(t)); err == nil || !strings.Contains(err.Error(), "four files") {
		t.Errorf("five files should refuse naming the limit, got %v", err)
	}
	// With the built-in at the root, three files plus default is the limit.
	m["q1.yaml"] = "profile: q1\nextends: default\n"
	m["q2.yaml"] = "profile: q2\nextends: q1.yaml\n"
	m["q3.yaml"] = "profile: q3\nextends: q2.yaml\n"
	m["q4.yaml"] = "profile: q4\nextends: q3.yaml\n"
	if _, err := Resolve(set(), Source{Path: "q3.yaml"}, fs, noWarn(t)); err != nil {
		t.Errorf("three files over the built-in: %v", err)
	}
	if _, err := Resolve(set(), Source{Path: "q4.yaml"}, fs, noWarn(t)); err == nil {
		t.Errorf("four files over the built-in is five in the chain")
	}
}

func TestResolveRefusals(t *testing.T) {
	cases := map[string]string{
		"unknown extends name":     "profile: x\nextends: nope\ninclude: [\"muster.*\"]\n",
		"missing extends file":     "profile: x\nextends: gone.yaml\ninclude: [\"muster.*\"]\n",
		"malformed pattern":        "profile: x\ninclude: [\"muster.[\"]\n",
		"unmatched pattern":        "profile: x\ninclude: [\"muster.nothing.*\"]\n",
		"bad name grammar":         "profile: Site\ninclude: [\"muster.*\"]\n",
		"names a built-in":         "profile: default\ninclude: [\"muster.*\"]\n",
		"empty selection":          "profile: x\ninclude: [\"muster.*\"]\nexclude: [\"muster.*\"]\n",
		"unknown control in params": "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.no.such: {a: 1}\n",
		"unknown parameter":        "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.account.password_policy: {max_len: 1}\n",
		"wrong type":               "profile: x\ninclude: [\"muster.*\"]\nparams:\n  muster.account.password_policy: {min_len: \"8\"}\n",
		"unknown level":            "profile: x\ninclude: [\"muster.*\"]\nseverity:\n  - { controls: \"muster.*\", level: critical }\n",
		"severity matches nothing": "profile: x\ninclude: [\"muster.*\"]\nseverity:\n  - { controls: \"muster.nothing.*\", level: low }\n",
		"missing profile name":     "include: [\"muster.*\"]\n",
	}
	for name, src := range cases {
		_, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), func(string) {})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "x.yaml") {
			t.Errorf("%s: %v should wrap ErrInvalid and name the file", name, err)
		}
	}
	if _, err := Resolve(set(), Source{Name: "nope"}, nil, func(string) {}); err == nil || !strings.Contains(err.Error(), "default, kisa-unix-2026") {
		t.Errorf("an unknown built-in name must list the built-ins: %v", err)
	}
}

func TestResolveWarnsForSeverityOnExcludedOnlyAndKeepsTheEntry(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.*\"]\nseverity:\n  - { controls: \"muster.beyond.*\", level: low }\n"
	var warnings []string
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), func(m string) { warnings = append(warnings, m) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || warnings[0] != "severity entry muster.beyond.* matches only excluded controls" {
		t.Errorf("warnings %v", warnings)
	}
	if len(r.Severity) != 1 || len(r.SeverityByID) != 0 {
		t.Errorf("the entry stays in the list (%d) and reaches no selected id (%v)", len(r.Severity), r.SeverityByID)
	}
}

func TestResolveNoOpExcludeIsSilentAndAbsoluteExtendsOpensAsGiven(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "base.yaml")
	fs := files(map[string]string{
		abs:      "profile: base\ninclude: [\"muster.*\"]\n",
		"c.yaml": "profile: c\nextends: " + abs + "\nexclude: [\"muster.beyond.*\"]\n",
		"d.yaml": "profile: d\nextends: c.yaml\nexclude: [\"muster.beyond.*\"]\n",
	})
	r, err := Resolve(set(), Source{Path: "d.yaml"}, fs, noWarn(t))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.Chain[0] != "file:"+filepath.Clean(abs) {
		t.Errorf("an absolute extends is opened as given: %v", r.Chain)
	}
	if len(r.IDs) != 3 {
		t.Errorf("ids %v", r.IDs)
	}
}

func TestDigestNamesContentOnly(t *testing.T) {
	a := "profile: a\nextends: default\ninclude: [muster.file.world_writable, muster.account.password_policy]\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n"
	b := "profile: b\nextends: default\ninclude: [muster.account.password_policy, muster.file.world_writable]\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\nseverity:\n  - { controls: \"muster.file.*\", level: low }\n"
	c := strings.Replace(a, "min_len: 12", "min_len: 13", 1)
	ra, _ := Resolve(set(), Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": a}), noWarn(t))
	rb, _ := Resolve(set(), Source{Path: "y/b.yaml"}, files(map[string]string{"y/b.yaml": b}), noWarn(t))
	rc, _ := Resolve(set(), Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": c}), noWarn(t))
	if ra.Digest != rb.Digest {
		t.Errorf("name, path and include order must not change the digest: %s vs %s", ra.Digest, rb.Digest)
	}
	if ra.Digest == rc.Digest {
		t.Errorf("a changed value must change the digest")
	}
	// A new control default changes nothing: the digest holds the chain's values only.
	s2 := set()
	s2.Controls[0].Params["min_len"] = controls.Param{Type: "int", Default: 10}
	rd, _ := Resolve(s2, Source{Path: "x/a.yaml"}, files(map[string]string{"x/a.yaml": a}), noWarn(t))
	if rd.Digest != ra.Digest {
		t.Errorf("a control default leaked into the digest")
	}
	if !strings.HasPrefix(ra.Digest, "sha256:") {
		t.Errorf("digest %q", ra.Digest)
	}
}
```

(`fmt` must be imported in `resolve_test.go`.)

```go
// internal/profile/merge_test.go
package profile

import (
	"testing"

	"github.com/kun9497/muster/internal/tuning"
)

func TestMergePrecedenceAndSources(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.no_deleted_executables\"]\nparams:\n  muster.account.password_policy: {min_len: 12}\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/22, tcp/443]\n"
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), noWarn(t))
	if err != nil {
		t.Fatal(err)
	}
	tn := &tuning.Tuning{Params: map[string]map[string]any{"muster.beyond.exposed_listeners_allowed": {"allowed_ports": []any{"tcp/22"}}}}
	params, sources := Merge(set(), r, tn, noWarn(t))
	if params["muster.account.password_policy"]["min_len"] != 12 || sources["muster.account.password_policy"]["min_len"] != "profile" {
		t.Errorf("profile value: %v %v", params["muster.account.password_policy"], sources["muster.account.password_policy"])
	}
	if got := params["muster.beyond.exposed_listeners_allowed"]["allowed_ports"].([]any); len(got) != 1 || sources["muster.beyond.exposed_listeners_allowed"]["allowed_ports"] != "tuning" {
		t.Errorf("tuning wins over the profile: %v %v", got, sources)
	}
	if _, has := params["muster.file.world_writable"]; has {
		t.Errorf("a control without params has no entry")
	}
	if _, has := params["muster.beyond.no_deleted_executables"]; has {
		t.Errorf("an excluded control has no entry")
	}
	// Default values are present with source default.
	params2, sources2 := Merge(set(), r, nil, noWarn(t))
	if sources2["muster.beyond.exposed_listeners_allowed"]["allowed_ports"] != "profile" || params2["muster.account.password_policy"]["min_len"] != 12 {
		t.Errorf("nil tuning: %v %v", params2, sources2)
	}
	rd, _ := Resolve(set(), Source{Name: "default"}, nil, noWarn(t))
	p3, s3 := Merge(set(), rd, nil, noWarn(t))
	if p3["muster.account.password_policy"]["min_len"] != 8 || s3["muster.account.password_policy"]["min_len"] != "default" {
		t.Errorf("defaults: %v %v", p3, s3)
	}
}

func TestMergeWarnsAndDropsValuesForExcludedControls(t *testing.T) {
	src := "profile: x\nextends: default\nexclude: [\"muster.beyond.*\"]\nparams:\n  muster.beyond.exposed_listeners_allowed:\n    allowed_ports: [tcp/443]\n"
	var warnings []string
	warn := func(m string) { warnings = append(warnings, m) }
	r, err := Resolve(set(), Source{Path: "x.yaml"}, files(map[string]string{"x.yaml": src}), warn)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Resolve must not warn for params: %v", warnings)
	}
	if _, kept := r.Params["muster.beyond.exposed_listeners_allowed"]; !kept {
		t.Errorf("Resolve keeps every chain value: %v", r.Params)
	}
	tn := &tuning.Tuning{Params: map[string]map[string]any{"muster.beyond.exposed_listeners_allowed": {"allowed_ports": []any{"tcp/80"}}}}
	params, sources := Merge(set(), r, tn, warn)
	want := []string{
		"profile parameter muster.beyond.exposed_listeners_allowed.allowed_ports ignored: excluded by profile",
		"tuning parameter muster.beyond.exposed_listeners_allowed.allowed_ports ignored: excluded by profile",
	}
	if len(warnings) != 2 || warnings[0] != want[0] || warnings[1] != want[1] {
		t.Errorf("warnings %v, want %v", warnings, want)
	}
	if _, has := params["muster.beyond.exposed_listeners_allowed"]; has {
		t.Errorf("an excluded control has no entry: %v %v", params, sources)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/profile -count=1`
Expected: build failure (undefined `Resolve`, `Merge`, `SourceOf`, `Parse`).

- [ ] **Step 3: Implement `profile.go`**

```go
// Package profile reads muster's profiles — the list of questions check asks
// a host: which controls, with which parameter values, at which severity
// (stage 3D-1, spec §3) — and merges a site's tuning in. It never touches the
// host: files come through the open function the caller passes and
// warnings through warn (Z-5).
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrInvalid = errors.New("invalid profile")

// SeverityEntry maps the controls a glob selects to a severity level; the
// last matching entry wins.
type SeverityEntry struct {
	Controls string `yaml:"controls"`
	Level    string `yaml:"level"`
}

// File is a profile file as decoded.
type File struct {
	Profile  string                    `yaml:"profile"`
	Extends  string                    `yaml:"extends,omitempty"`
	Include  []string                  `yaml:"include,omitempty"`
	Exclude  []string                  `yaml:"exclude,omitempty"`
	Params   map[string]map[string]any `yaml:"params,omitempty"`
	Severity []SeverityEntry           `yaml:"severity,omitempty"`
}

// Source names a built-in profile (Name) or a profile file (Path); exactly
// one is set.
type Source struct {
	Name string
	Path string
}

var nameGrammar = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// SourceOf classifies a --profile or extends value (spec §3): a value with
// no separator and no .yaml/.yml suffix is a name, anything else a path.
// The caller decides what an unknown name means (Resolve refuses it).
func SourceOf(s string) Source {
	lower := strings.ToLower(s)
	if strings.ContainsAny(s, `/\`) || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
		return Source{Path: s}
	}
	return Source{Name: s}
}

// builtins holds the embedded profiles as Go literals; kisa-unix-2026 is an
// alias of default (Y-1).
var builtins = map[string]*File{
	"default": {Profile: "default", Include: []string{"muster.*"}},
}

var builtinAliases = map[string]string{"kisa-unix-2026": "default"}

// Builtins lists the built-in names, canonical names first, for refusals.
func Builtins() []string { return []string{"default", "kisa-unix-2026"} }

func builtin(name string) (*File, string, bool) {
	if canon, ok := builtinAliases[name]; ok {
		name = canon
	}
	f, ok := builtins[name]
	return f, name, ok
}

// Parse decodes a profile file strictly (Z-2).
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return &f, nil
}

// cleanPath is the identity of a profile file inside a chain: the path
// muster opens, cleaned (spec §3 "Names and paths").
func cleanPath(p string) string { return filepath.Clean(p) }
```

- [ ] **Step 4: Implement `resolve.go`**

```go
package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/tuning"
)

// Resolved is a profile resolved against a control set.
type Resolved struct {
	Name         string
	Source       string
	Chain        []string
	IDs          []string
	Params       map[string]map[string]any
	Severity     []SeverityEntry
	SeverityByID map[string]string
	Digest       string
}

const maxChain = 4

var levels = map[string]bool{"high": true, "medium": true, "low": true}

// link is one file of the chain in walk order (root first).
type link struct {
	file  *File
	label string // "builtin:default" or "file:<cleaned path>"
	where string // the string refusals name: the path, or "builtin:<name>"
}

// Resolve walks the extends chain root-first and applies include/exclude,
// params and severity per file (spec §3). open reads a file by path; warn
// receives the severity warning. Every refusal wraps ErrInvalid and names
// the file.
func Resolve(set *controls.Set, src Source, open func(string) ([]byte, error), warn func(string)) (*Resolved, error) {
	chain, err := loadChain(src, open)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, c := range set.Controls {
		known[c.ID] = true
	}
	selected := map[string]bool{}
	r := &Resolved{Params: map[string]map[string]any{}, SeverityByID: map[string]string{}}
	for _, l := range chain {
		r.Chain = append(r.Chain, l.label)
		for _, p := range l.file.Include {
			ids, err := match(set, p, l.where)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				selected[id] = true
			}
		}
		for _, p := range l.file.Exclude {
			ids, err := match(set, p, l.where)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				delete(selected, id)
			}
		}
		if err := tuning.Validate(set, l.file.Params); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, l.where, err)
		}
		for id, ps := range l.file.Params {
			if r.Params[id] == nil {
				r.Params[id] = map[string]any{}
			}
			for n, v := range ps {
				r.Params[id][n] = v
			}
		}
		for _, e := range l.file.Severity {
			if !levels[e.Level] {
				return nil, fmt.Errorf("%w: %s: severity level %q is not high, medium or low", ErrInvalid, l.where, e.Level)
			}
			if _, err := match(set, e.Controls, l.where); err != nil {
				return nil, err
			}
			r.Severity = append(r.Severity, e)
		}
	}
	for id := range selected {
		r.IDs = append(r.IDs, id)
	}
	sort.Strings(r.IDs)
	if len(r.IDs) == 0 {
		return nil, fmt.Errorf("%w: %s: profile selects no control", ErrInvalid, chain[len(chain)-1].where)
	}
	for _, e := range r.Severity {
		hit := false
		for _, id := range r.IDs {
			if ok, _ := path.Match(e.Controls, id); ok {
				r.SeverityByID[id] = e.Level
				hit = true
			}
		}
		if !hit {
			warn(fmt.Sprintf("severity entry %s matches only excluded controls", e.Controls))
		}
	}
	last := chain[len(chain)-1]
	r.Name = last.file.Profile
	r.Source = "builtin"
	if src.Path != "" {
		r.Source = "file:" + src.Path
	}
	r.Digest = digest(r)
	return r, nil
}

// loadChain follows extends from src to the root and returns the chain root
// first: at most four files, the built-in counted, identified by cleaned
// paths for the cycle test.
func loadChain(src Source, open func(string) ([]byte, error)) ([]link, error) {
	var chain []link // leaf first, reversed at the end
	seen := map[string]bool{}
	cur := src
	referrer := ""
	for {
		var l link
		if cur.Name != "" {
			f, canon, ok := builtin(cur.Name)
			if !ok {
				return nil, fmt.Errorf("%w: unknown profile %q; the built-ins are %s", ErrInvalid, cur.Name, joinNames())
			}
			l = link{file: f, label: "builtin:" + canon, where: "builtin:" + canon}
		} else {
			p := cur.Path
			if referrer != "" && !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(referrer), p)
			}
			p = cleanPath(p)
			// The cycle identity is the cleaned opened path, never the label
			// (the flag's file is labelled as given): ./a.yaml and a.yaml are
			// one file.
			if seen["file:"+p] {
				return nil, fmt.Errorf("%w: %s: extends cycle through %s", ErrInvalid, p, p)
			}
			seen["file:"+p] = true
			data, err := open(p)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, p, err)
			}
			f, err := Parse(data)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrInvalid, p, errors.Unwrap(err))
			}
			if f.Profile == "" {
				return nil, fmt.Errorf("%w: %s: profile name is required", ErrInvalid, p)
			}
			if !nameGrammar.MatchString(f.Profile) {
				return nil, fmt.Errorf("%w: %s: profile name %q is not [a-z0-9][a-z0-9-]*", ErrInvalid, p, f.Profile)
			}
			if _, _, isBuiltin := builtin(f.Profile); isBuiltin {
				return nil, fmt.Errorf("%w: %s: profile name %q is a built-in's", ErrInvalid, p, f.Profile)
			}
			label := "file:" + p
			if referrer == "" {
				label = "file:" + src.Path // the flag's path as given
			}
			l = link{file: f, label: label, where: p}
			referrer = p
		}
		if cur.Name != "" {
			seen[l.label] = true // a built-in is its own identity
		}
		chain = append(chain, l)
		if len(chain) > maxChain {
			return nil, fmt.Errorf("%w: %s: extends chain is longer than four files", ErrInvalid, chain[0].where)
		}
		if l.file.Extends == "" || cur.Name != "" {
			break
		}
		cur = SourceOf(l.file.Extends)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// match returns the ids of the set a pattern selects; a malformed pattern or
// one that matches nothing refuses (spec §3 "Globs").
func match(set *controls.Set, pattern, where string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, fmt.Errorf("%w: %s: pattern %q: %v", ErrInvalid, where, pattern, err)
	}
	var ids []string
	for _, c := range set.Controls {
		if ok, _ := path.Match(pattern, c.ID); ok {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: %s: pattern %q matches no control", ErrInvalid, where, pattern)
	}
	return ids, nil
}

func joinNames() string {
	out := ""
	for i, n := range Builtins() {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// digest is sha256 over the canonical JSON of the resolved content only —
// ids, the chain's values and the ordered severity entries — never the name,
// source or chain (spec §3 "Digest"). encoding/json sorts map keys.
func digest(r *Resolved) string {
	doc := struct {
		IDs      []string                  `json:"ids"`
		Params   map[string]map[string]any `json:"params"`
		Severity []SeverityEntry           `json:"severity"`
	}{IDs: r.IDs, Params: r.Params, Severity: r.Severity}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err) // the shapes are yaml scalars and lists; marshalling cannot fail
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
```

Note the two subtleties the tests pin: the cycle check uses the label of a *file* (`file:<cleaned>`), so `./a.yaml` and `a.yaml` collide; the chain length counts the built-in. A built-in has no `extends` and ends the walk. `errors` must be imported in `resolve.go`.

- [ ] **Step 5: Implement `merge.go`**

```go
package profile

import (
	"fmt"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/tuning"
)

// Merge computes the parameter values in force for every selected control
// that declares params — default < profile < tuning — and each value's
// source. A profile or tuning value for a control the selection excludes
// is warned once per (control, parameter) and dropped (Y-8). t may be nil.
func Merge(set *controls.Set, r *Resolved, t *tuning.Tuning, warn func(string)) (map[string]map[string]any, map[string]map[string]string) {
	selected := map[string]bool{}
	for _, id := range r.IDs {
		selected[id] = true
	}
	params := map[string]map[string]any{}
	sources := map[string]map[string]string{}
	var tparams map[string]map[string]any
	if t != nil {
		tparams = t.Params
	}
	for i := range set.Controls {
		c := &set.Controls[i]
		if !selected[c.ID] {
			for _, n := range sortedKeys(r.Params[c.ID]) {
				warn(fmt.Sprintf("profile parameter %s.%s ignored: excluded by profile", c.ID, n))
			}
			for _, n := range sortedKeys(tparams[c.ID]) {
				warn(fmt.Sprintf("tuning parameter %s.%s ignored: excluded by profile", c.ID, n))
			}
			continue
		}
		if len(c.Params) == 0 {
			continue
		}
		params[c.ID] = map[string]any{}
		sources[c.ID] = map[string]string{}
		for _, n := range c.SortedParamNames() {
			params[c.ID][n], sources[c.ID][n] = c.Params[n].Default, "default"
			if v, ok := r.Params[c.ID][n]; ok {
				params[c.ID][n], sources[c.ID][n] = v, "profile"
			}
			if v, ok := tparams[c.ID][n]; ok {
				params[c.ID][n], sources[c.ID][n] = v, "tuning"
			}
		}
	}
	return params, sources
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

(`sort` imported.) Then `fuzz_test.go` with `FuzzParseProfile` on the Task 2 model (seed1 = the `src` of `TestResolveChainIncludeExcludeParamsSeverity`'s `site.yaml`), `imports_test.go` and `fuzz_inventory_test.go` copied from Task 2 with `package profile` / `internal/profile` / `fuzzTargets = []string{"FuzzParseProfile"}`.

- [ ] **Step 6: Run everything**

Run: `go test ./internal/profile ./internal/tuning ./internal/controls -count=1 -v | grep -E '^(--- |ok|FAIL)'` and `go test ./internal/profile -run '^$' -fuzz FuzzParseProfile -fuzztime 10s`
Expected: every test PASS; `go vet ./internal/profile` clean; the inventory test lists `Parse` only (the `digest`/`match` helpers take no `[]byte`).

- [ ] **Step 7: Commit**

```bash
git add internal/profile
git commit -m "Add the profile package: parse, classify, resolve the extends chain, merge the tuning, digest the content"
```

---

### Task 4: `internal/waiver` — an excluded control's waiver is `not_applied`

**Files:**
- Modify: `internal/waiver/waiver.go:107-125` (`Apply`)
- Modify: `internal/waiver/waiver_test.go` (the nine call sites gain `nil` or a map as the new third argument)
- Modify: `cmd/muster/check.go:139` (the call site — keep compiling: pass `nil` now; Task 6 passes the real set)

**Interfaces:**
- Produces: `func (f *File) Apply(results []check.Result, known, excluded map[string]bool, now time.Time, warn func(string)) Applied` — checks per waiver in the order excluded → unknown → expired → rows; an id in `excluded` increments `NotApplied` and warns `waiver for <id> not applied: excluded by profile` (the subject, when set, is appended as ` (subject <s>)`), whatever its expiry; `known` is the evaluated subset's ids; a nil `excluded` is allowed.

- [ ] **Step 1: Write the failing test** (in `waiver_test.go`, using the file's existing helpers for results and `now`)

```go
func TestApplyCountsAnExcludedWaiverAsNotApplied(t *testing.T) {
	f := &File{Waivers: []Waiver{
		{Control: "muster.beyond.x", Reason: "r"},
		{Control: "muster.beyond.x", Subject: "file:/a", Reason: "r"},
		{Control: "muster.beyond.y", Reason: "r", Expires: "2000-01-01"}, // excluded AND expired
		{Control: "muster.nope", Reason: "r"},
	}}
	rs := []check.Result{{ID: "muster.account.a", Status: check.FAIL}}
	var warnings []string
	tally := f.Apply(rs, map[string]bool{"muster.account.a": true}, map[string]bool{"muster.beyond.x": true, "muster.beyond.y": true}, time.Now(), func(m string) { warnings = append(warnings, m) })
	if tally.NotApplied != 3 || tally.Unknown != 1 || tally.Expired != 0 || tally.Applied != 0 {
		t.Errorf("tally %+v: want not_applied 3 (one expired, one with a subject), unknown 1, expired 0", tally)
	}
	want := []string{
		"waiver for muster.beyond.x not applied: excluded by profile",
		"waiver for muster.beyond.x not applied: excluded by profile (subject file:/a)",
		"waiver for muster.beyond.y not applied: excluded by profile",
		"waiver names unknown control muster.nope",
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Errorf("warnings:\n%s\nwant:\n%s", strings.Join(warnings, "\n"), strings.Join(want, "\n"))
	}
	if rs[0].Waiver != nil {
		t.Errorf("no row carries an excluded waiver")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/waiver -run TestApplyCountsAnExcludedWaiverAsNotApplied -count=1`
Expected: compile error (too many arguments to `Apply`).

- [ ] **Step 3: Implement**

```go
func (f *File) Apply(results []check.Result, known, excluded map[string]bool, now time.Time, warn func(string)) Applied {
	var tally Applied
	byControl := map[string][]Waiver{}
	for _, w := range f.Waivers {
		if excluded[w.Control] {
			tally.NotApplied++
			msg := fmt.Sprintf("waiver for %s not applied: excluded by profile", w.Control)
			if w.Subject != "" {
				msg += fmt.Sprintf(" (subject %s)", w.Subject)
			}
			warn(msg)
			continue
		}
		if !known[w.Control] {
			// … unchanged
```

Update the nine test call sites (`f.Apply(rs, known, nil, now, warn)`) and `check.go:139` (`wf.Apply(results, known, nil, time.Now().UTC(), warn)`).

- [ ] **Step 4: Run the suite**

Run: `go test ./internal/waiver ./cmd/muster -count=1`
Expected: all ok (the waiver e2e still sees the unknown-control warning).

- [ ] **Step 5: Commit**

```bash
git add internal/waiver cmd/muster/check.go
git commit -m "Count a waiver on a control the profile excludes as not applied, never unknown"
```

---

### Task 5: `internal/report` — the profile block, parameter sources and the severity in force

**Files:**
- Modify: `internal/report/report.go` (`CheckBlock`, `Row`, `Build`), `internal/report/json.go` (comment), `internal/report/table.go:116-134` (the profile line)
- Modify: `internal/report/report_test.go` (`sampleReport`, the two `Build` calls, a new severity test), `internal/report/table_test.go` (four `Build` calls; `TestTableScopeLinesAndSeparator`/`TestTableQuietHidesPassAndManual` line positions if they index lines)
- Regenerate: `internal/report/testdata/basic.json.golden`, `basic.table.golden`, `basic.table.narrow.golden`

**Interfaces:**
- Produces:
  ```go
  type ProfileBlock struct {
      Name        string   `json:"name"`
      Source      string   `json:"source"`
      Digest      string   `json:"digest"`
      Extends     []string `json:"extends"`
      Selected    int      `json:"selected"`
      Excluded    int      `json:"excluded"`
      ExcludedIDs []string `json:"excluded_ids"`
  }
  type TuningBlock struct{ Path string `json:"path"`; Digest string `json:"digest"` }
  // CheckBlock, in this field order (Z-1):
  //   MusterVersion, Commit, ControlsVersion, ControlsDigest, SnapshotDigest, GuideEdition,
  //   Profile ProfileBlock `json:"profile"`, Tuning *TuningBlock `json:"tuning,omitempty"`,
  //   Waivers, Params, ParamSources map[string]map[string]string `json:"param_sources,omitempty"`
  type Row struct{ check.Result; Severity string `json:"severity"`; SeveritySource string `json:"severity_source"` }
  func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock, severity map[string]string) *Report
  ```
  `Build` sets `Severity = severity[id]` with `SeveritySource = "profile"` when the map names the id, else `Severity(importance)` with `"importance"`; it normalises a nil `ExcludedIDs`/`Extends` to `[]string{}` before encoding. The table prints, as line 2, `profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>])`, or `profile <name> (<total> controls[; tuning <path>])` when `Excluded == 0`, every string through `escape`.

- [ ] **Step 1: Write the failing tests**

```go
// report_test.go — add
func TestBuildAppliesTheSeverityMapAndNamesItsSource(t *testing.T) {
	snap := sampleSnapshot(t) // lift the snapshot construction out of sampleReport (report_test.go:19-41) into this helper first
	results := []check.Result{
		{ID: "muster.file.world_writable", Importance: "하", Status: check.FAIL},
		{ID: "muster.account.a", Importance: "상", Status: check.PASS},
	}
	rep := Build(snap, results, CheckBlock{}, map[string]string{"muster.file.world_writable": "high"})
	byID := map[string]Row{}
	for _, r := range rep.Results {
		byID[r.ID] = r
	}
	if r := byID["muster.file.world_writable"]; r.Severity != "high" || r.SeveritySource != "profile" {
		t.Errorf("overridden row: %q %q", r.Severity, r.SeveritySource)
	}
	if r := byID["muster.account.a"]; r.Severity != "high" || r.SeveritySource != "importance" {
		t.Errorf("derived row: %q %q", r.Severity, r.SeveritySource)
	}
	if rep.Summary.Automatic.High.Fail != 1 || rep.Summary.Automatic.Low.Fail != 0 {
		t.Errorf("the summary counts the severity in force: %+v", rep.Summary.Automatic)
	}
	if rep.Check.Profile.ExcludedIDs == nil || rep.Check.Profile.Extends == nil {
		t.Errorf("nil slices must render as []: %+v", rep.Check.Profile)
	}
}
```

In `sampleReport` give the `CheckBlock` literal `Profile: ProfileBlock{Name: "default", Source: "builtin", Digest: "sha256:p", Extends: []string{"builtin:default"}, Selected: 6, Excluded: 0, ExcludedIDs: []string{}}` and `ParamSources: nil`; change every `Build(snap, results, cb)` call to `Build(snap, results, cb, nil)`. Add to `table_test.go`:

```go
func TestTablePrintsTheProfileLine(t *testing.T) {
	rep := sampleReportWithTitles(t)
	rep.Check.Profile = ProfileBlock{Name: "site\x1b[31m", Source: "file:s.yaml", Extends: []string{"builtin:default", "file:s.yaml"}, Selected: 4, Excluded: 2, ExcludedIDs: []string{"a", "b"}}
	rep.Check.Tuning = &TuningBlock{Path: "t.yaml", Digest: "sha256:t"}
	var b bytes.Buffer
	if err := WriteTable(&b, rep, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(b.String(), "\n")
	if lines[1] != "profile site\\x1b[31m (4 of 6, 2 excluded; tuning t.yaml)" { // escape's spelling of ESC
		t.Errorf("line 2 = %q", lines[1])
	}
	rep.Check.Profile = ProfileBlock{Name: "default", Source: "builtin", Extends: []string{"builtin:default"}, Selected: 6, ExcludedIDs: []string{}}
	rep.Check.Tuning = nil
	b.Reset()
	_ = WriteTable(&b, rep, TableOptions{Width: 100})
	if l := strings.Split(b.String(), "\n")[1]; l != "profile default (6 controls)" {
		t.Errorf("line 2 = %q", l)
	}
}
```

(Check `escape`'s actual rendering of ESC in `table.go:56-83` and write the expected string accordingly — the test must use the real spelling.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/report -count=1`
Expected: compile errors (`Build` arity, `ProfileBlock` undefined).

- [ ] **Step 3: Implement**

```go
// report.go
type ProfileBlock struct { … as in Interfaces … }
type TuningBlock struct { … }

type CheckBlock struct {
	MusterVersion   string                       `json:"muster_version"`
	Commit          string                       `json:"commit"`
	ControlsVersion string                       `json:"controls_version"`
	ControlsDigest  string                       `json:"controls_digest"`
	SnapshotDigest  string                       `json:"snapshot_digest"`
	GuideEdition    string                       `json:"guide_edition"`
	Profile         ProfileBlock                 `json:"profile"`
	Tuning          *TuningBlock                 `json:"tuning,omitempty"`
	Waivers         WaiversBlock                 `json:"waivers"`
	Params          map[string]map[string]any    `json:"params,omitempty"`
	ParamSources    map[string]map[string]string `json:"param_sources,omitempty"`
}

type Row struct {
	check.Result
	Severity       string `json:"severity"`
	SeveritySource string `json:"severity_source"`
}

func Build(snap *facts.Snapshot, results []check.Result, cb CheckBlock, severity map[string]string) *Report {
	if cb.Profile.ExcludedIDs == nil {
		cb.Profile.ExcludedIDs = []string{}
	}
	if cb.Profile.Extends == nil {
		cb.Profile.Extends = []string{}
	}
	rows := make([]Row, 0, len(results))
	for _, r := range results {
		row := Row{Result: r, Severity: Severity(r.Importance), SeveritySource: "importance"}
		if lvl, ok := severity[r.ID]; ok {
			row.Severity, row.SeveritySource = lvl, "profile"
		}
		rows = append(rows, row)
	}
	// … the rest unchanged
```

```go
// table.go — after the "muster …" header line
	fmt.Fprintln(w, profileLine(r.Check))
```

```go
// profileLine is the table's second line (spec §5 "Table").
func profileLine(cb CheckBlock) string {
	p := cb.Profile
	total := p.Selected + p.Excluded
	var s string
	if p.Excluded == 0 {
		s = fmt.Sprintf("profile %s (%d controls", escape(p.Name), total)
	} else {
		s = fmt.Sprintf("profile %s (%d of %d, %d excluded", escape(p.Name), p.Selected, total, p.Excluded)
	}
	if cb.Tuning != nil {
		s += "; tuning " + escape(cb.Tuning.Path)
	}
	return s + ")"
}
```

Update `json.go`'s comment ("the only map" → "the maps (check.params, check.param_sources)").

- [ ] **Step 4: Regenerate the goldens, review the diff, run the package**

Run: `go test ./internal/report -run TestJSON -update`, `go test ./internal/report -run TestTableGolden -update`, then `git diff internal/report/testdata | head -80` and `go test ./internal/report -count=1`
Expected: the JSON golden gains `profile` (with the fixture), `severity_source` on every row, no other change; both table goldens gain line 2 `profile default (6 controls)`; all tests PASS (fix any test that indexed header lines by position).

- [ ] **Step 5: Commit**

```bash
git add internal/report
git commit -m "Record the profile, the tuning file, the parameter sources and the severity in force in the report"
```

---

### Task 6: `cmd/muster` — `resolveSelection`, the flags, lint/list, the examples test, e2e, CI

**Files:**
- Create: `cmd/muster/selection.go`, `cmd/muster/selection_test.go`, `cmd/muster/testdata/profiles/exclude-beyond.yaml`, `cmd/muster/testdata/profiles/one-control.yaml`, `cmd/muster/testdata/profiles/chain-base.yaml`, `cmd/muster/testdata/profiles/chain-child.yaml`, `cmd/muster/testdata/tuning/ports.yaml`, `cmd/muster/testdata/tuning/excluded.yaml`
- Modify: `cmd/muster/check.go` (`checkUsage`, `checkFlags`, `parseCheckArgs`, `newCheckBlock`, `runCheck`), `cmd/muster/controls.go` (`controlsUsage`, lint flag loop + ok line, list), `cmd/muster/trust_linux.go` (comment), `cmd/muster/examples_test.go:44-45`, `cmd/muster/e2e_test.go` (new tests + `assertSelection` helper), `cmd/muster/check_test.go` (bad profile/tuning file → exit 2)
- Modify: `.github/workflows/ci.yml:29-30` (+ step), `.github/workflows/fuzz.yml:40-44`, `Makefile:28-29` (`lint-controls`), `CONTRIBUTING.md:176-184` + `CONTRIBUTING.ko.md` (the fuzz paragraph)

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  ```go
  type Selection struct {
      Subset       *controls.Set
      Params       map[string]map[string]any
      Sources      map[string]map[string]string
      SeverityByID map[string]string
      Known        map[string]bool   // the subset's ids
      Excluded     map[string]bool   // the loaded set's ids not selected
      Profile      report.ProfileBlock
      Tuning       *report.TuningBlock
  }
  func resolveSelection(profileArg, tuningPath string, set *controls.Set, warn func(string)) (*Selection, error)
  func newCheckBlock(sel *Selection, snap *facts.Snapshot, reg *facts.Registry, wf *waiver.File, warn func(string)) ([]check.Result, report.CheckBlock)
  ```
  `resolveSelection` builds `open := func(p string) ([]byte, error) { if ok, why := trustedFile(p); !ok { return nil, fmt.Errorf("refusing %s: %s", p, why) }; return os.ReadFile(p) }`, calls `profile.SourceOf`, `profile.Resolve`, `tuning.Load` (when `tuningPath != ""`), `profile.Merge`, `set.Subset`; `Profile.ExcludedIDs` is the sorted complement; an error is returned as is (the caller prints `muster: <err>`).

- [ ] **Step 1: Fixtures**

```yaml
# cmd/muster/testdata/profiles/exclude-beyond.yaml — the KISA guide alone
profile: exclude-beyond
extends: default
exclude: ["muster.beyond.*"]
```

```yaml
# cmd/muster/testdata/profiles/one-control.yaml
profile: one-control
include: [muster.beyond.exposed_listeners_allowed]
```

```yaml
# cmd/muster/testdata/profiles/chain-base.yaml
profile: chain-base
extends: default
severity:
  - { controls: "muster.beyond.*", level: low }
```

```yaml
# cmd/muster/testdata/profiles/chain-child.yaml
profile: chain-child
extends: chain-base.yaml
exclude: [muster.beyond.no_deleted_executables]
```

```yaml
# cmd/muster/testdata/tuning/ports.yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/80]
```

```yaml
# cmd/muster/testdata/tuning/excluded.yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/80]
```

- [ ] **Step 2: Write the failing tests** — `selection_test.go` (unit, Windows-runnable) and the e2e tests. Every e2e test copies its profile/tuning files into `t.TempDir()` first through a helper:

```go
// e2e_test.go — helper
// stageFiles copies testdata files into a temp dir with their relative
// layout (the waiver precedent: the CI root job runs this package as root
// and trustedFile refuses files it did not own).
func stageFiles(t *testing.T, rel ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, r := range rel {
		b, err := os.ReadFile(filepath.Join("testdata", r))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, r)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// assertSelection keeps M-17's exhaustiveness for a profile run: the
// evaluated ids are exactly want's keys with those statuses, the excluded
// ids are exactly excluded, and together they are the embedded set.
func assertSelection(t *testing.T, jsonBytes []byte, want map[string]string, excluded []string) {
	t.Helper()
	var rep struct {
		Check struct {
			Profile struct {
				Selected    int      `json:"selected"`
				Excluded    int      `json:"excluded"`
				ExcludedIDs []string `json:"excluded_ids"`
			} `json:"profile"`
		} `json:"check"`
		Results []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonBytes, &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.ID] = r.Status
	}
	for id, st := range want {
		if got[id] != st {
			t.Errorf("%s: status %q, want %q", id, got[id], st)
		}
	}
	for id := range got {
		if _, named := want[id]; !named {
			t.Errorf("%s evaluated but not named by want", id)
		}
	}
	if strings.Join(rep.Check.Profile.ExcludedIDs, ",") != strings.Join(excluded, ",") {
		t.Errorf("excluded_ids %v, want %v", rep.Check.Profile.ExcludedIDs, excluded)
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if len(want)+len(excluded) != len(set.Controls) || rep.Check.Profile.Selected+rep.Check.Profile.Excluded != len(set.Controls) {
		t.Errorf("%d evaluated + %d excluded != %d loaded", len(want), len(excluded), len(set.Controls))
	}
}
```

Tests to write (each named, each asserting structure):
- `TestCheckProfileExcludeBeyondEvaluatesTheGuideOnly` — `full-fail.json` + `profiles/exclude-beyond.yaml` (staged) → exit `exitFindings`; `assertSelection` with the 68 guide statuses (take the full-fail map used by `TestCheckEndToEndJSONAndTable` minus the beyond ids) and the 49 `muster.beyond.*` ids sorted; `check.profile.name == "exclude-beyond"`, `source == "file:<staged path>"`, `extends == ["builtin:default", "file:<staged path>"]`; `full-pass.json` → exit 0.
- `TestCheckProfileChainOfTwoRecordsTheOpenedPaths` — `chain-child.yaml` + `chain-base.yaml` staged together → `extends == ["builtin:default", "file:<cleaned staged chain-base path>", "file:<staged child path as given>"]`, `excluded_ids == [muster.beyond.no_deleted_executables]`, every `muster.beyond.*` row has `severity_source == "profile"` and `severity == "low"`, a guide row has `"importance"`.
- `TestCheckProfileOneControlWithTuningFlipsTheVerdict` — facts `../../controls/testdata/muster.beyond.exposed_listeners_allowed/fail-ufw-folded-http.json`, `profiles/one-control.yaml`, `tuning/ports.yaml` → exit 0, one row PASS, `check.param_sources[id].allowed_ports == "tuning"`, `check.params[id].allowed_ports` has four entries, `check.tuning.path` set; without `--tuning` the row is FAIL and exit 1.
- `TestCheckProfileTuningForExcludedControlWarns` — `full-pass.json`, `exclude-beyond.yaml`, `tuning/excluded.yaml` → exit 0, stderr contains `muster: warning: tuning parameter muster.beyond.exposed_listeners_allowed.allowed_ports ignored: excluded by profile`, `check.params` lacks that id.
- `TestCheckProfileWaiverOnExcludedControlIsNotApplied` — `full-fail.json`, `exclude-beyond.yaml`, a waiver file naming `muster.beyond.no_deleted_executables` → `check.waivers.not_applied == 1`, `unknown == 0`, the warning text.
- `TestCheckProfileUnknownNameNamesTheBuiltins` — `--profile Default` and `--profile site` → exit 2, empty stdout, stderr contains `default, kisa-unix-2026`.
- `TestCheckProfileDefaultBlock` — no flags → `check.profile == {name default, source builtin, extends [builtin:default], selected 117, excluded 0, excluded_ids []}`, no `tuning` key.
- `TestCheckRootRefusesWritableProfileFiles` — `if os.Geteuid() != 0 { t.Skip(…) }`; stage `chain-child.yaml`+`chain-base.yaml`, `tuning/ports.yaml`; for each of the three files in turn `os.Chmod(path, 0o664)` → exit 2, stderr names that path, stdout empty; restore `0o600` after each.
- `TestControlsLintProfileAndListProfile` — `controls lint <repo flags> --profile default` → stdout contains both `ok: 117 controls` and `ok: profile default selects 117 of 117 controls, 0 excluded`; `--profile testdata/profiles/exclude-beyond.yaml` (staged) → `selects 68 of 117 controls, 49 excluded`; a typo profile (`include: ["muster.nothing.*"]`) → exit 2 naming the pattern; `controls list --profile <staged exclude-beyond>` → 68 lines of four tab-separated columns, none starting `muster.beyond.`.
- `check_test.go`: `TestCheckBadProfileFileIsExit2` and `TestCheckBadTuningFileIsExit2` on the `TestCheckBadWaiverFileIsExit2` model.
- `selection_test.go`: `resolveSelection("default", "", set, warn)` → 117 selected, `Known` 117, `Excluded` empty, `Profile.Source == "builtin"`; `resolveSelection("Default", …)` → error naming the built-ins.

- [ ] **Step 3: Run to verify failure**

Run: `go test ./cmd/muster -count=1`
Expected: build failures (`resolveSelection` undefined, flags unknown).

- [ ] **Step 4: Implement `selection.go`**

```go
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/profile"
	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/tuning"
)

// Selection is what check evaluates: the profile's subset of the control
// set, the parameter values in force with their sources, the severity map
// and the two provenance blocks (stage 3D-1, spec §5).
type Selection struct {
	Subset       *controls.Set
	Params       map[string]map[string]any
	Sources      map[string]map[string]string
	SeverityByID map[string]string
	Known        map[string]bool
	Excluded     map[string]bool
	Profile      report.ProfileBlock
	Tuning       *report.TuningBlock
}

// resolveSelection is the one seam check, controls lint/list --profile, the
// examples test and (3D-2) fix share: the trusted-file rule, the profile
// resolution, the tuning load, the merge and the subset — no logic of its
// own beyond the wiring (main design §4.2).
func resolveSelection(profileArg, tuningPath string, set *controls.Set, warn func(string)) (*Selection, error) {
	open := func(p string) ([]byte, error) {
		if ok, why := trustedFile(p); !ok {
			return nil, fmt.Errorf("refusing %s: %s", p, why)
		}
		return os.ReadFile(p)
	}
	r, err := profile.Resolve(set, profile.SourceOf(profileArg), open, warn)
	if err != nil {
		return nil, err
	}
	var tn *tuning.Tuning
	var tb *report.TuningBlock
	if tuningPath != "" {
		if tn, err = tuning.Load(set, tuningPath, open); err != nil {
			return nil, err
		}
		tb = &report.TuningBlock{Path: tn.Path, Digest: tn.Digest}
	}
	params, sources := profile.Merge(set, r, tn, warn)
	sel := &Selection{Subset: set.Subset(r.IDs), Params: params, Sources: sources, SeverityByID: r.SeverityByID,
		Known: map[string]bool{}, Excluded: map[string]bool{}, Tuning: tb}
	for _, id := range r.IDs {
		sel.Known[id] = true
	}
	excluded := []string{}
	for _, c := range set.Controls {
		if !sel.Known[c.ID] {
			sel.Excluded[c.ID] = true
			excluded = append(excluded, c.ID)
		}
	}
	sort.Strings(excluded)
	sel.Profile = report.ProfileBlock{Name: r.Name, Source: r.Source, Digest: r.Digest, Extends: r.Chain,
		Selected: len(r.IDs), Excluded: len(excluded), ExcludedIDs: excluded}
	return sel, nil
}
```

- [ ] **Step 5: Wire `check.go`**

`checkFlags` gains `profile, tuning string`; the struct literal in `parseCheckArgs` sets `profile: "default"`; two `case` arms `"--profile"` and `"--tuning"` (last value wins); `checkUsage` gains two lines. `newCheckBlock(sel *Selection, snap, reg, wf, warn)`: `opts := check.Options{Params: sel.Params}`, `results := check.Evaluate(snap, sel.Subset, reg, opts)`, `cb.Profile, cb.Tuning = sel.Profile, sel.Tuning`, the params loop runs over `sel.Subset.Controls` and also fills `cb.ParamSources` from `sel.Sources` (nil when empty), the waiver call becomes `wf.Apply(results, sel.Known, sel.Excluded, time.Now().UTC(), warn)`. `runCheck`: after the registry load, `sel, err := resolveSelection(f.profile, f.tuning, set, warnFn)` → on error `muster: %v` + `exitError`; `report.Build(snap, results, cb, sel.SeverityByID)`. Define the warn closure once and pass it to both.

- [ ] **Step 6: Wire `controls.go`**

`lint`: a `--profile` arm (`profileArg := ""`), and after the `ok:` line: if `profileArg != ""`, `sel, err := resolveSelection(profileArg, "", set, warnTo(stderr))`; on error `muster: %v` + `exitError`; else `fmt.Fprintf(stdout, "ok: profile %s selects %d of %d controls, %d excluded\n", sel.Profile.Name, sel.Profile.Selected, len(set.Controls), sel.Profile.Excluded)`. `list`: a flag loop on the lint model with `--profile` only; `sub := set`; with a profile, `sel, err := resolveSelection(…)` and `sub = sel.Subset`; the loop prints `sub.Controls` with the existing format. `controlsUsage` gains `--profile <name|path>` under lint and a `flags (list):` block. `trust_linux.go`'s comment: "a waiver, profile or tuning file on the host can change what check reports".

- [ ] **Step 7: Wire `examples_test.go`**

```go
	sel, err := resolveSelection("default", "", set, func(msg string) { t.Logf("check warning: %s", msg) })
	if err != nil {
		t.Fatalf("resolve default profile: %v", err)
	}
	results, cb := newCheckBlock(sel, snap, reg, nil, func(msg string) { t.Logf("check warning: %s", msg) })
	rep := report.Build(snap, results, cb, sel.SeverityByID)
```

- [ ] **Step 8: CI, fuzz, Makefile, CONTRIBUTING**

`ci.yml` after the `controls lint` step:
```yaml
      - name: controls lint, built-in profile
        run: go run ./cmd/muster controls lint --references docs/reference --profile default
```
`fuzz.yml`: two lines `profile=$(go test -list '^Fuzz' ./internal/profile/ | grep '^Fuzz')`, `tuning=$(go test -list '^Fuzz' ./internal/tuning/ | grep '^Fuzz')` and two `echo … | sed 's#^#./internal/profile/ #'` / `./internal/tuning/` entries in the brace group. `Makefile` `lint-controls`: a second line `go run $(PKG) controls lint --references docs/reference --profile default`. `CONTRIBUTING.md` (+ `.ko.md`): name `internal/profile` and `internal/tuning` beside the two packages and add `FUZZPKG=./internal/profile/` to the `make fuzz` example.

- [ ] **Step 9: Run the gates**

Run: `gofmt -l .`; `go vet ./... && GOOS=linux GOARCH=amd64 go vet ./...`; `go test ./... -count=1`; `go run ./cmd/muster controls lint --references docs/reference --profile default`; `go run ./tools/coverage -check`; `python -X utf8 -c "import yaml;yaml.safe_load(open('.github/workflows/ci.yml',encoding='utf-8'));yaml.safe_load(open('.github/workflows/fuzz.yml',encoding='utf-8'))"`; on the lab as root `go test ./... -count=1` (the root-mode refusal test runs there) and `staticcheck ./...`.
Expected: all green; the lab run shows `TestCheckRootRefusesWritableProfileFiles` PASS (not SKIP).

- [ ] **Step 10: Commit** (two commits: the command and tests; the CI/fuzz/Makefile/CONTRIBUTING edits)

```bash
git add cmd/muster
git commit -m "Resolve the profile and the tuning file before check evaluates, and teach lint and list the profile"
git add .github/workflows/ci.yml .github/workflows/fuzz.yml Makefile CONTRIBUTING.md CONTRIBUTING.ko.md
git commit -m "Fuzz the profile and tuning parsers nightly and lint the built-in profile in CI"
```

---

### Task 7: Documents, whole-branch review, examples, Execution notes (controller)

**Files:**
- Modify: `docs/superpowers/specs/2026-09-02-muster-design.md` + `.ko.md` (§4.2 package table rows for `internal/profile`/`internal/tuning`; §4.3 inputs; §4.4 root-refusal sentence; §6.5 "with the reason where a row exists"; §6.6 rewritten as realised; §6.7 the excluded outcome; §7.2 exit-2 causes; §9 provenance fields, severity sentence, determinism bullet; §10.2 3D split into 3D-1 (merged) / 3D-2 / 3D-3; **D33** after D32)
- Modify: `CLAUDE.md` (decision log D01–D33; new section "## Profiles (stage 3D-1)" before "## Stage-2 conventions"), `README.md` + `README.ko.md` (status, `--profile`/`--tuning` usage, the example profile), `CHANGELOG.md` (Added: profiles, tuning, the result fields; no Controls entry)
- Create: `docs/examples/profiles/exclude-beyond.yaml` (the Task 6 fixture, with a comment header), `docs/examples/profiles/tuning.yaml` (§4's example)
- Modify: this plan's Execution notes

- [ ] **Step 1: Fold the documents** (the controller writes a fold script with `--check`, as in 3C-2b; English and Korean in one commit).
- [ ] **Step 2: Whole-branch review** as an ultracode workflow: fresh finders by area (profile/tuning packages; waiver/report/cmd wiring; e2e/CI/fuzz; documents and contracts) → refuters → critic; fix wave; scoped re-review.
- [ ] **Step 3: Final gates** on Windows and the lab (root, `-race`, staticcheck).
- [ ] **Step 4: Merge menu** (the user's word): push → the branch's `examples.yml` run → `examples/` refreshed (reports gain `check.profile`, `check.param_sources`, `severity_source`, the table's line 2) → PR → CI → merge → cleanup.
- [ ] **Step 5: Execution notes** — rulings Z-11…, reviews, deviations, numbers, parked.

## Execution notes

### Rulings settled during execution (Z-11 …)

### What the reviews found

### Deviations from the spec, as shipped

### Numbers

### Parked
