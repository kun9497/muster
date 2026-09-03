package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

const controlsUsage = `usage: muster controls <lint|list> [flags]

flags (lint):
  --fixtures <dir>     directory holding the control fixtures (default controls/testdata)
  --references <dir>   directory holding the generated STIG/NIST reference index (dir/stig/*.json,
                        see docs/reference); without this flag, stig and nist_800_53 references are
                        checked for shape only, never for existence in the index; with it, every id
                        must exist in the index
`

// defaultFixtureDir is where the fixtures live relative to the repository
// root, which is where lint is meant to run.
const defaultFixtureDir = "controls/testdata"

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
			default:
				fmt.Fprintf(stderr, "muster: unknown flag %s\n%s", rest[i], controlsUsage)
				return exitError
			}
		}
		// R35: a missing fixture directory used to make lint skip the
		// fixture-pair rule and still print "ok" -- a green light it had not
		// earned. It is an error now.
		if !controls.FixtureDirExists(fixtures) {
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
		// Spec §5.5: report registered keys no control uses. Some are read by
		// the evaluator itself, so this never fails the lint.
		if unused := controls.UnusedKeys(set, reg); len(unused) > 0 {
			fmt.Fprintf(stdout, "note: %d registered fact keys are used by no control: %s\n", len(unused), strings.Join(unused, ", "))
		}
		problems := controls.Lint(set, reg, controls.LintOptions{CustomFuncs: check.CustomFuncs(), FixtureDir: fixtures, References: refIndex})
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
