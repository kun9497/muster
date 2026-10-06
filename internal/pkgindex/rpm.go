//go:build linux

package pkgindex

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// RPMCommand asks the rpm database for a line per packaged FILE: the owning
// package, the file's mode, its owner and group as rpm recorded them
// (names, never ids), the file capabilities the package declares and the
// path. The "=" prefix repeats the package name on every line, and the path
// is last, so a line splits on the first five tabs and whitespace in a path
// is harmless. The caps column is conditional (V-5, V-24): a package whose
// header has no FILECAPS tag at all prints an empty field rather than
// "(none)", and a file without capabilities in a package that has some
// prints an empty string too, so "" always means "declares none".
//
// A large host has close to a million packaged files at roughly 80 bytes a
// line, hence the 256 MiB cap and the two-minute timeout: the cap is a limit
// on muster's memory, not an expectation, and a capture that hits it is
// reported as truncated rather than as a failure. No digest is printed —
// %{FILEDIGESTS} would make the command far more expensive and the index
// verifies nothing.
//
// Options.RPMTimeout and Options.RPMMaxOutput change Timeout and MaxOutput
// only: the guard compares Path and Args, so one declaration row serves
// every caller whatever bounds it runs the query under.
var RPMCommand = collect.Command{
	Path:      "/usr/bin/rpm",
	Args:      []string{"-qa", "--qf", "[%{=NAME}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%|FILECAPS?{%{FILECAPS}}|\t%{FILENAMES}\n]"},
	Timeout:   120 * time.Second,
	MaxOutput: 256 << 20,
}

// rpmLabel names the command in a reason. The whole command line, format
// string and all, is in the envelope's Source; a reason is read by a person.
const rpmLabel = "rpm -qa"

// buildRPM runs the file-table query and keeps the candidate rows. A
// failure envelope carries the command's source and, when the capture was
// capped too, the truncation flag; the returned truncated is then false,
// since there is no table it could qualify.
func buildRPM(ctx context.Context, a collect.Access, cands map[string]bool, opts Options) (Index, bool, *facts.Envelope) {
	cmd := RPMCommand
	if opts.RPMTimeout > 0 {
		cmd.Timeout = opts.RPMTimeout
	}
	if opts.RPMMaxOutput > 0 {
		cmd.MaxOutput = int(opts.RPMMaxOutput)
	}
	res := a.Run(ctx, cmd)
	src := res.Source(cmd)
	ix := Index{Family: FamilyRPM, Source: src}
	fail := func(e facts.Envelope) (Index, bool, *facts.Envelope) {
		e.Source = src
		e.Truncated = e.Truncated || res.Truncated
		return ix, false, &e
	}
	switch {
	case res.TimedOut:
		return fail(collect.TimeoutEnv(rpmLabel + " timed out"))
	case res.Err != nil:
		return fail(collect.ErrorEnv(rpmLabel + ": " + res.Err.Error()))
	case res.ExitCode != 0:
		// Every caller runs as root, so a refusal here is not a privilege
		// problem this process could fix by being someone else; it is a
		// database that would not answer, which is an error.
		reason := rpmLabel + " exited " + strconv.Itoa(res.ExitCode)
		if s := firstLine(res.Stderr); s != "" {
			reason += ": " + s
		}
		return fail(collect.ErrorEnv(reason))
	}
	table, err := RPMFileTable(res.Stdout, cands, res.Truncated)
	if err != nil {
		return fail(collect.ErrorEnv(rpmLabel + ": " + err.Error()))
	}
	// A capped capture is still an answer as far as it goes: what was parsed
	// is real, and truncated says the silence means nothing.
	ix.RPM = table
	return ix, res.Truncated, nil
}

// firstLine is the first non-blank line of b, trimmed.
func firstLine(b []byte) string {
	for _, line := range splitLines(b) {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}
