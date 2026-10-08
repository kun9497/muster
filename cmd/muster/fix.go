package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/remedy"
	"github.com/kun9497/muster/internal/report"
)

const fixUsage = `usage: muster fix --dry-run --facts <snapshot.json|-> [flags]

flags:
  --format table|json|script   output format (default table)
  --waivers <file>             waiver file, as check
  --profile <name|path>        the profile in force, as check (default: the built-in default)
  --tuning <file>              site parameter values, as check
  --max-risk none|restart_service|reboot_required|lockout_risk
                               the highest risk the script will run (default lockout_risk: everything)
  --color auto|always|never    colour (default auto); --no-color = never
`

// x1Refusal is the one answer to a fix without --dry-run or with any
// positional word (X-1): muster never applies a remediation (D24).
const x1Refusal = "fix never applies a remediation (D24); run fix --dry-run"

// fixValueFlags are the flags that take a value (Z-12); the pre-pass skips
// that value, whatever it is, and an unknown flag takes none.
var fixValueFlags = map[string]bool{"--facts": true, "--format": true, "--waivers": true, "--profile": true, "--tuning": true, "--max-risk": true, "--color": true}

type fixFlags struct {
	facts, format, waivers, color, profile, tuning, maxRisk string
	tuningGiven                                             bool
}

func parseFixArgs(args []string) (fixFlags, error) {
	dry := false
	for i := 0; i < len(args); i++ { // Z-12 pre-pass
		a := args[i]
		switch {
		case a == "--dry-run":
			dry = true
		case fixValueFlags[a]:
			i++ // its value, whatever it is
		case !strings.HasPrefix(a, "-"):
			return fixFlags{}, errors.New(x1Refusal)
		}
	}
	if !dry {
		return fixFlags{}, errors.New(x1Refusal)
	}
	f := fixFlags{format: "table", color: "auto", profile: "default", maxRisk: "lockout_risk"}
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
		case "--dry-run":
		case "--facts":
			f.facts, err = next()
		case "--format":
			f.format, err = next()
		case "--waivers":
			f.waivers, err = next()
		case "--profile":
			f.profile, err = next()
		case "--tuning":
			f.tuning, err = next()
			f.tuningGiven = true
		case "--max-risk":
			f.maxRisk, err = next()
		case "--color":
			f.color, err = next()
		case "--no-color":
			f.color = "never"
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	switch {
	case f.facts == "":
		return f, errors.New("--facts is required")
	case f.format != "table" && f.format != "json" && f.format != "script":
		return f, fmt.Errorf("--format must be table, json or script, got %q", f.format)
	case f.color != "auto" && f.color != "always" && f.color != "never":
		return f, fmt.Errorf("--color must be auto, always or never, got %q", f.color)
	}
	switch f.maxRisk {
	case "none", "restart_service", "reboot_required", "lockout_risk":
	default:
		return f, fmt.Errorf("--max-risk must be none, restart_service, reboot_required or lockout_risk, got %q", f.maxRisk)
	}
	return f, nil
}

// runFix runs check's own pipeline on a snapshot, then plans the
// remediation of its FAIL/WARN rows and renders the plan. It never runs
// the script it writes; its exit code is 0 when a plan was produced, with
// or without items, and 2 when it could not be. Never 1.
func runFix(args []string, stdout, stderr io.Writer) int {
	f, err := parseFixArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, fixUsage)
		return exitError
	}
	snap, _, err := openFacts(f.facts)
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
	warn := warnTo(stderr)
	var tuningPath *string
	if f.tuningGiven {
		tuningPath = &f.tuning
	}
	sel, err := resolveSelection(f.profile, tuningPath, set, warn)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	wf, err := loadWaivers(f.waivers)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "muster: warning: fix does not need root")
	}
	results, cb := newCheckBlock(sel, snap, reg, wf, warn)
	rep := report.Build(snap, results, cb, sel.SeverityByID)
	p, err := remedy.Build(rep, set, remedy.Options{MaxRisk: f.maxRisk})
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	var body []byte
	switch f.format {
	case "json":
		body = remedy.JSON(p)
	case "script":
		body = remedy.Script(p)
	default:
		body = remedy.Table(p, report.ColorEnabled(f.color, os.Getenv("NO_COLOR"), os.Getenv("TERM"), stdoutIsTTY(stdout)))
	}
	if _, err := stdout.Write(body); err != nil {
		fmt.Fprintf(stderr, "muster: write: %v\n", err)
		return exitError
	}
	return exitOK
}
