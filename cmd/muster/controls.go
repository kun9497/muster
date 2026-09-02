package main

import (
	"fmt"
	"io"

	"github.com/kun9497/muster/internal/check"
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
		opts := controls.LintOptions{CustomFuncs: check.CustomFuncs()}
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
