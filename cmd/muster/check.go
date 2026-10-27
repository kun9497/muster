package main

import (
	"bytes"
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
  --profile <name|path>      which controls to evaluate: a built-in (default, cis-rhel9-l1,
                             cis-ubuntu2204-l1, cis-ubuntu2404-l1, kisa-unix-2026)
                             or a profile file (default: the built-in default)
  --tuning <file>            site parameter values, over the profile's and the controls' defaults
  --allow-error              compute the exit code from findings even when controls are ERROR
  --fail-on fail|warn|manual|none   what exits 1 (default fail)
  --quiet                    hide PASS, NOT_APPLICABLE, WAIVED and MANUAL rows
  --all                      show every failing observation
  --color auto|always|never  colour (default auto); --no-color = never

` + cisDisclaimer + "\n"

// cisDisclaimer is CB-13's sentence, in the words README.md, NOTICE and
// ATTRIBUTION.md carry; check's usage names the CIS built-ins, so it says it.
const cisDisclaimer = "The `cis-<distro>-l1` profiles select muster's own controls that carry a CIS Benchmark " +
	"recommendation number at Level 1 – Server; their results are muster's verdicts on muster's controls, not a CIS " +
	"assessment, and muster is an independent publication not authorized, sponsored or otherwise approved by the " +
	"Center for Internet Security."

type checkFlags struct {
	facts, format, waivers, failOn, color string
	profile, tuning                       string
	tuningGiven                           bool // --tuning was given, even as ""
	allowError, quiet, all                bool
}

func parseCheckArgs(args []string) (checkFlags, error) {
	f := checkFlags{format: "table", failOn: "fail", color: "auto", profile: "default"}
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
		case "--profile":
			f.profile, err = next()
		case "--tuning":
			f.tuning, err = next()
			f.tuningGiven = true
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

// openFacts reads the snapshot at path -- or standard input, for "-" --
// and returns both the validated snapshot and the bytes it was decoded
// from. check needs only the snapshot; snapshot extract needs the bytes
// too, to decode the fact tree a second time with json.Number, so the two
// commands read their --facts flag through one function rather than two
// copies of the same size, depth and schema handling (spec 7.2).
func openFacts(path string) (*facts.Snapshot, []byte, error) {
	var in io.Reader = os.Stdin
	if path != "-" {
		fh, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer fh.Close()
		in = fh
	}
	// The same limit facts.Load applies, read here so the bytes can be
	// handed back: Load sees one byte more than the maximum and rejects it.
	data, err := io.ReadAll(io.LimitReader(in, facts.MaxSnapshotBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read snapshot: %w", err)
	}
	snap, err := facts.Load(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	return snap, data, nil
}

// newCheckBlock is everything check does between a loaded snapshot and
// report.Build: it evaluates the snapshot over the selection's subset with
// the parameter values in force, records those values and their sources,
// applies the waiver file and returns the provenance block the report
// carries. warn receives the body of each warning line -- the caller decides
// where warnings go, so the command can prefix them and a test can collect
// them (spec §7.4: warnings are stderr, never stdout).
//
// G-14: the example test (examples_test.go) regenerates a committed report
// through this function. A committed report is only evidence that this
// binary produces it if the bytes the test compares came through the same
// code, so there is one implementation and not two that can drift.
func newCheckBlock(sel *Selection, snap *facts.Snapshot, reg *facts.Registry, wf *waiver.File, warn func(string)) ([]check.Result, report.CheckBlock) {
	set := sel.Subset
	opts := check.Options{Params: sel.Params}
	results := check.Evaluate(snap, set, reg, opts)
	cb := report.CheckBlock{
		MusterVersion: version, Commit: commit,
		ControlsVersion: set.Version, ControlsDigest: set.Digest,
		SnapshotDigest: snap.Digest(), GuideEdition: "kisa-unix-2026",
		Profile: sel.Profile, Tuning: sel.Tuning,
	}
	// I5/R30: record the parameter values that were actually in force, for
	// every control that declares any (spec §6.6, §9). encoding/json sorts
	// map keys, so this stays byte-identical for identical input.
	for i := range set.Controls {
		c := &set.Controls[i]
		if len(c.Params) == 0 {
			continue
		}
		if cb.Params == nil {
			cb.Params = make(map[string]map[string]any, len(set.Controls))
		}
		cb.Params[c.ID] = check.ParamValues(c, opts.Params[c.ID])
		if src := sel.Sources[c.ID]; len(src) > 0 {
			if cb.ParamSources == nil {
				cb.ParamSources = make(map[string]map[string]string, len(set.Controls))
			}
			cb.ParamSources[c.ID] = src
		}
	}
	if snap.Run.ControlsDigest != "" && snap.Run.ControlsDigest != set.Digest {
		warn(fmt.Sprintf("snapshot was collected with control set %s; evaluating with %s", snap.Run.ControlsVersion, set.Version))
	}
	if wf != nil {
		// A waiver on a control the profile excludes is not_applied, never
		// unknown: known is the subset, excluded the rest of the loaded set.
		tally := wf.Apply(results, sel.Known, sel.Excluded, time.Now().UTC(), warn)
		cb.Waivers = report.WaiversBlock{Path: wf.Path, Digest: wf.Digest, Applied: tally.Applied, NotApplied: tally.NotApplied, Expired: tally.Expired, Unknown: tally.Unknown, ExpiringSoon: tally.ExpiringSoon}
	}
	return results, cb
}

// loadWaivers reads the waiver file check and fix share (Z-13). An empty
// path means no waiver file, as --waivers "" always has; a file the trust
// gate refuses is "refusing waiver file: <why>".
func loadWaivers(path string) (*waiver.File, error) {
	if path == "" {
		return nil, nil
	}
	if ok, why := trustedFile(path); !ok {
		return nil, fmt.Errorf("refusing waiver file: %s", why)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return waiver.Load(fh, path)
}

// stdoutIsTTY reports whether w is a character device, which is what
// --color auto asks (Z-16).
func stdoutIsTTY(w io.Writer) bool {
	fh, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := fh.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	f, err := parseCheckArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, checkUsage)
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
	// The full set goes in: the merge warns about a value for a control the
	// profile excludes, which only the full set still names.
	var tuningPath *string
	if f.tuningGiven {
		tuningPath = &f.tuning
	}
	sel, err := resolveSelection(f.profile, tuningPath, set, warn)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	// CB-11: a CIS profile on a host its benchmark does not cover still evaluates; stderr says so.
	hostWarning(sel.Profile.Extends, snap.Run.Host.OSRelease, warn)
	wf, err := loadWaivers(f.waivers)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(stderr, "muster: warning: check does not need root")
	}

	results, cb := newCheckBlock(sel, snap, reg, wf, warn)
	rep := report.Build(snap, results, cb, sel.SeverityByID)

	switch f.format {
	case "json":
		if err := report.WriteJSON(stdout, rep); err != nil {
			fmt.Fprintf(stderr, "muster: write: %v\n", err)
			return exitError
		}
	default:
		opts := report.TableOptions{Color: report.ColorEnabled(f.color, os.Getenv("NO_COLOR"), os.Getenv("TERM"), stdoutIsTTY(stdout)), Quiet: f.quiet}
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
