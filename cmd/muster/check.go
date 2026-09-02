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
	allowError, quiet, all                bool
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
