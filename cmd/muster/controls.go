package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

const controlsUsage = `usage: muster controls <lint|list|new> [flags]

flags (lint):
  --fixtures <dir>     directory holding the control fixtures (default controls/testdata)
  --references <dir>   directory holding the generated STIG/NIST reference index (dir/stig/*.json,
                        see docs/reference); without this flag, stig and nist_800_53 references are
                        checked for shape only, never for existence in the index; with it, every id
                        must exist in the index
  --kisa <dir>         directory holding the KISA item inventory (default docs/reference/kisa); every
                        references.kisa id must be an item of the edition it is filed under, the
                        control's importance must match the item's, and every current-edition item
                        must be claimed by exactly one control or listed in kisa_deferred.json

flags (new): run "muster controls new" with no arguments to see them
`

const controlsNewUsage = `usage: muster controls new <id> --kisa-id U-NN [flags]

Scaffolds one control: <out>/<area>/<name>.yaml from the id (muster.<area>.<name>)
and a pair of synthetic fixture stubs under <fixtures>/<id>. Everything it writes
is a placeholder in muster's own words -- replace the titles, the descriptions,
the placeholder fact key and the remediation with what this control really
judges, and fill the stubs in: they carry no facts and no expectation, so the
fixture test cannot pass until you do.

It refuses rather than overwrite: an existing YAML or an existing fixture
directory stops the run before anything is written.

flags:
  --kisa-id U-NN       the current-edition KISA item this control implements (required);
                        its importance and its 2021 ancestors are read from the inventory
  --automation <kind>  auto, partial or manual (default auto); a manual skeleton carries
                        manual_reason and evidence instead of checks and remediation
  --kisa-dir <dir>     directory holding the KISA item inventory and kisa_mapping.json
                        (default docs/reference/kisa)
  --out <dir>          control set root the YAML is written under (default controls)
  --fixtures <dir>     fixture root the stubs are written under (default controls/testdata)

exit codes: 0 wrote the skeleton; 1 refused (a bad id, an item the inventory does
not list or has deferred, a path that already exists); 2 bad flags or an I/O error.
`

// defaultFixtureDir is where the fixtures live relative to the repository
// root, which is where lint is meant to run.
const defaultFixtureDir = "controls/testdata"

// defaultKISADir is where the KISA item inventory lives relative to the
// repository root, the same way defaultFixtureDir does.
const defaultKISADir = "docs/reference/kisa"

// defaultControlSetDir is the control set root controls new writes into,
// again relative to the repository root.
const defaultControlSetDir = "controls"

// kisaPriorEdition is the edition kisa_mapping.json maps the current one
// back to. controls.LatestKISAEdition names the current one; there is no
// constant for the older list because nothing but this mapping reads it.
const kisaPriorEdition = "2021"

// kisaMappingFile holds, per current-edition item, the 2021 items it came
// from (a rename, a split or a merge). controls new copies that list into
// references.kisa so a new control cites both editions from the start.
const kisaMappingFile = "kisa_mapping.json"

// kisaDeferredFile is the list of current-edition items muster has said in
// writing it does not implement yet. controls new names it when it refuses
// to scaffold one of them.
const kisaDeferredFile = "kisa_deferred.json"

// scaffoldFactKey is the registered fact key the placeholder clause and the
// placeholder evidence list name. It is deliberately a fact every host
// carries, so a scaffold that is run and forgotten fails loudly on its own
// emptiness rather than on an unresolvable key.
const scaffoldFactKey = "patch.manager"

// scaffoldHeader is the note the developer reads first when they open the
// file controls new wrote.
const scaffoldHeader = `# Scaffolded by "muster controls new". Every TODO below is a placeholder in
# muster's own words: never paste guide text into this file (ATTRIBUTION.md).
# Replace the titles, the descriptions and the placeholder fact key with what
# this control really judges, then fill in the fixture stubs beside it.
`

// fixtureStub is what both scaffolded fixtures hold: the synthetic marker
// D02 demands, a schema version, and the three blocks the author fills in.
const fixtureStub = `{"synthetic": true, "schema_version": 1, "run": {}, "facts": {}, "_expect": {}}
`

// shapeOnlyNote tells the reader that the stig and nist_800_53 ids in this
// run were checked for shape only. Without it a clean lint reads as though
// every id had been verified against the index (M-4).
const shapeOnlyNote = "note: stig and nist_800_53 references checked for shape only; pass --references docs/reference to check them against the index"

// usageNote renders the fact-key report of spec §11 as the one line lint
// prints: how many registered keys a control reads, how many the engine
// reads on its own, and the keys nobody reads. The three numbers account for
// every registered key. The list is omitted, along with the "unused:" label,
// when there is nothing to list -- a set that reads everything it collects
// should say so and stop.
//
// It takes the unused keys rather than deriving them from usage: they are
// controls.UnusedKeys, in registry order (spec §5.5, M-40/M-42), and the
// report groups them by collector instead.
func usageNote(usage []controls.CollectorUsage, unused []string) string {
	registered, used, engine := controls.Totals(usage)
	note := fmt.Sprintf("note: %d of %d registered fact keys are used by a control (%d read by the engine)", used, registered, engine)
	if len(unused) > 0 {
		note += "; unused: " + strings.Join(unused, ", ")
	}
	return note
}

func runControls(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, controlsUsage)
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
		fixtures := defaultFixtureDir
		references := ""
		kisaDir := defaultKISADir
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--fixtures":
				if i+1 >= len(rest) {
					fmt.Fprintf(stderr, "muster: flag %s needs a value\n%s", rest[i], controlsUsage)
					return exitError
				}
				i++
				fixtures = rest[i]
			case "--references":
				if i+1 >= len(rest) {
					fmt.Fprintf(stderr, "muster: flag %s needs a value\n%s", rest[i], controlsUsage)
					return exitError
				}
				i++
				references = rest[i]
			case "--kisa":
				if i+1 >= len(rest) {
					fmt.Fprintf(stderr, "muster: flag %s needs a value\n%s", rest[i], controlsUsage)
					return exitError
				}
				i++
				kisaDir = rest[i]
			default:
				fmt.Fprintf(stderr, "muster: unknown flag %s\n%s", rest[i], controlsUsage)
				return exitError
			}
		}
		// R35: a missing fixture directory used to make lint skip the
		// fixture-pair rule and still print "ok" -- a green light it had not
		// earned. It is an error now.
		if !controls.DirExists(fixtures) {
			fmt.Fprintf(stderr, "muster: fixture directory %s does not exist; run controls lint from the repository root or pass --fixtures <dir>\n", fixtures)
			return exitError
		}
		// --references is opt-in (R98): omitting it means stig and
		// nist_800_53 references are checked for shape only, never for
		// existence. When given, a missing or empty <dir>/stig is an I/O
		// failure like a missing fixture directory, not a silently skipped
		// rule.
		var refIndex *controls.ReferenceIndex
		if references != "" {
			idx, err := controls.LoadReferenceIndex(references)
			if err != nil {
				fmt.Fprintf(stderr, "muster: %v\n", err)
				return exitError
			}
			refIndex = idx
		}
		// M-2/M-26: the inventory cross-check is not optional, so a missing
		// inventory directory is an error the way a missing fixture directory
		// is (R35), never a silently skipped rule. The directory checks run
		// in the order fixtures, references, kisa.
		if !controls.DirExists(kisaDir) {
			fmt.Fprintf(stderr, "muster: kisa inventory directory %s does not exist; run controls lint from the repository root or pass --kisa <dir>\n", kisaDir)
			return exitError
		}
		inventory, err := controls.LoadKISA(kisaDir)
		if err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		// Spec §11 / M-3: report facts used, not facts collected -- how much
		// of the registry a control reads, how much the engine reads on its
		// own, and which keys nobody reads. Some of the last are collected
		// for controls that do not exist yet, so this never fails the lint.
		fmt.Fprintln(stdout, usageNote(controls.FactUsage(set, reg), controls.UnusedKeys(set, reg)))
		// Printed here, after every directory check, so a run that fails on
		// --fixtures or --kisa does not first hand out advice about a flag
		// that had nothing to do with the failure.
		if refIndex == nil {
			fmt.Fprintln(stdout, shapeOnlyNote)
		}
		problems := controls.Lint(set, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs(), FixtureDir: fixtures, References: refIndex, KISA: inventory})
		for _, p := range problems {
			fmt.Fprintln(stderr, p)
		}
		if len(problems) > 0 {
			fmt.Fprintf(stderr, "muster: %d lint problem(s)\n", len(problems))
			return exitError
		}
		fmt.Fprintf(stdout, "ok: %d controls, set %s\n", len(set.Controls), set.Version)
		return exitOK
	case "new":
		return runControlsNew(args[1:], stdout, stderr)
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

// newFlags is what controls new was asked for: the control id and where to
// read the inventory and write the files.
type newFlags struct {
	id, kisaID, automation, kisaDir, out, fixtures string
}

func parseControlsNewArgs(args []string) (newFlags, error) {
	f := newFlags{automation: "auto", kisaDir: defaultKISADir, out: defaultControlSetDir, fixtures: defaultFixtureDir}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return f, errors.New("controls new needs a control id as its first argument")
	}
	f.id = args[0]
	for i := 1; i < len(args); i++ {
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
		case "--kisa-id":
			f.kisaID, err = next()
		case "--automation":
			f.automation, err = next()
		case "--kisa-dir":
			f.kisaDir, err = next()
		case "--out":
			f.out, err = next()
		case "--fixtures":
			f.fixtures, err = next()
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	if f.kisaID == "" {
		return f, errors.New("--kisa-id is required")
	}
	switch f.automation {
	case "auto", "partial", "manual":
	default:
		return f, fmt.Errorf("--automation must be auto, partial or manual, got %q", f.automation)
	}
	return f, nil
}

// runControlsNew writes the control skeleton and its fixture stubs (M-16,
// spec §6.2). It checks everything it can before it writes anything: a
// refusal must leave the tree exactly as it found it, or the developer is
// left with half a control and no way to tell which half.
func runControlsNew(args []string, stdout, stderr io.Writer) int {
	f, err := parseControlsNewArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, controlsNewUsage)
		return exitError
	}
	if !controls.ValidControlID(f.id) {
		fmt.Fprintf(stderr, "muster: %q is not a control id; ids look like muster.<area>.<name>, lowercase\n", f.id)
		return exitRefused
	}
	segments := strings.Split(f.id, ".")
	area, name := segments[1], segments[2]
	if !slices.Contains(controls.Categories(), area) {
		fmt.Fprintf(stderr, "muster: %q is not a control category, so an id with the area %q has nowhere to live; use one of %s\n",
			area, area, strings.Join(controls.Categories(), ", "))
		return exitRefused
	}
	inventory, err := controls.LoadKISA(f.kisaDir)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitRefused
	}
	item, known := inventory.Item(controls.LatestKISAEdition, f.kisaID)
	if !known {
		fmt.Fprintf(stderr, "muster: %s is not an item of the %s inventory in %s\n", f.kisaID, controls.LatestKISAEdition, f.kisaDir)
		return exitRefused
	}
	// M-37: a deferred item is one muster has said in writing it does not
	// implement yet. A control that cites it makes the set-level coverage
	// rule fail on the deferral it has just contradicted, so the row goes
	// first and the control second.
	if inventory.IsDeferred(f.kisaID) {
		fmt.Fprintf(stderr, "muster: %s is deferred in %s; drop its row there first, or the set-level coverage rule fails on the deferral this control contradicts\n",
			f.kisaID, filepath.Join(f.kisaDir, kisaDeferredFile))
		return exitRefused
	}
	from2021, err := kisaAncestors(f.kisaDir, f.kisaID)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitRefused
	}

	yamlPath := filepath.Join(f.out, area, name+".yaml")
	fixtureDir := filepath.Join(f.fixtures, f.id)
	for _, p := range []string{yamlPath, fixtureDir} {
		switch _, err := os.Stat(p); {
		case err == nil:
			fmt.Fprintf(stderr, "muster: %s already exists; controls new never overwrites\n", p)
			return exitRefused
		case !errors.Is(err, os.ErrNotExist):
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
	}

	body, err := marshalControl(scaffoldControl(f, area, item, from2021))
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Dir(yamlPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	if err := os.WriteFile(yamlPath, append([]byte(scaffoldHeader), body...), 0o644); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "wrote %s\n", yamlPath)
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	for _, stub := range fixtureStubNames(f.automation) {
		p := filepath.Join(fixtureDir, stub)
		if err := os.WriteFile(p, []byte(fixtureStub), 0o644); err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		fmt.Fprintf(stdout, "wrote %s\n", p)
	}
	return exitOK
}

// fixtureStubNames are the fixture files to scaffold: the prefix of a
// fixture is the status it must produce, so the pair a control gets is the
// pair its automation can reach (controls/testdata, CLAUDE.md).
func fixtureStubNames(automation string) []string {
	if automation == "manual" {
		return []string{"manual-example.json", "na-example.json"}
	}
	return []string{"pass-example.json", "fail-example.json"}
}

// marshalControl renders a control as the YAML the strict loader reads back,
// indented two spaces like every file already in the set. yaml.v3 sorts the
// keys of the one map involved (references.kisa), so the same control always
// renders the same bytes.
func marshalControl(c *controls.Control) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// scaffoldControl builds the Control the YAML is marshalled from, so the
// file that lands on disk is by construction a value the strict loader
// accepts: nothing hand-written can misspell a key.
func scaffoldControl(f newFlags, area string, item controls.KISAItem, from2021 []string) *controls.Control {
	c := &controls.Control{
		ID:            f.id,
		TitleEn:       "TODO: what " + f.kisaID + " requires of this host, in one line",
		TitleKo:       "TODO: " + item.NameKo,
		DescriptionEn: "TODO: what this control judges, why it matters and what it deliberately does not decide -- in muster's own words.",
		DescriptionKo: "TODO: 이 통제가 무엇을 판단하고, 왜 중요하며, 무엇을 판단하지 않는지 muster 자신의 문장으로 적는다.",
		Category:      area,
		Importance:    item.Importance,
		Automation:    f.automation,
		References: controls.References{KISA: map[string][]string{
			controls.LatestKISAEdition: {f.kisaID},
			kisaPriorEdition:           from2021,
		}},
		RequiresFacts: ">=1",
		// The safe default: until the author decides what an absent fact
		// means for this item, it means a human has to look (spec §6.5).
		AbsentMeans: "manual",
	}
	if f.automation == "manual" {
		c.ManualReason = "TODO: why muster declines to judge this item, and what the reviewer must read to decide it."
		c.Evidence = []string{scaffoldFactKey}
		return c
	}
	c.Checks = []controls.Clause{{Fact: scaffoldFactKey, Op: "present"}}
	c.Remediation = &controls.Remediation{
		TextEn:     "TODO: the commands or edits that fix this, in the order an operator runs them.",
		TextKo:     "TODO: 운영자가 실행하는 순서대로, 이 문제를 고치는 명령이나 편집 절차를 적는다.",
		Risk:       "none",
		Idempotent: true,
	}
	return c
}

// kisaAncestors returns the prior-edition items the given current-edition
// item came from, read from kisa_mapping.json. An item with no ancestor
// (a 2026 addition) has an empty list, which is a statement and is written
// as one; an item the mapping does not mention at all is a hole in the file,
// and controls new says so rather than guessing an empty list for it.
func kisaAncestors(dir, id string) ([]string, error) {
	path := filepath.Join(dir, kisaMappingFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Mapping []struct {
			LatestID string   `json:"latest_id"`
			From2021 []string `json:"from_2021"`
		} `json:"mapping"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, row := range doc.Mapping {
		if row.LatestID == id {
			return append([]string{}, row.From2021...), nil
		}
	}
	return nil, fmt.Errorf("%s: no row for %s, so its %s ancestors cannot be derived", path, id, kisaPriorEdition)
}
