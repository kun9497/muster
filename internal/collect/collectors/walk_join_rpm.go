//go:build linux

package collectors

import (
	"bufio"
	"bytes"
	"context"
	"strconv"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgfiles"
)

// rpmCommand asks the rpm database for a line per packaged FILE: the owning
// package, the file's mode, its owner and group as rpm recorded them
// (names, never ids) and the path. The "=" prefix repeats the package name
// on every line, and the path is last, so a line splits on the first four
// tabs and whitespace in a path is harmless.
//
// A large host has close to a million packaged files at roughly 80 bytes a
// line, hence the 256 MiB cap and the two-minute timeout: the cap is a limit
// on muster's memory, not an expectation, and a capture that hits it is
// reported as truncated rather than as a failure. No digest is printed —
// %{FILEDIGESTS} would make the command far more expensive and 3A verifies
// nothing (W-8).
var rpmCommand = collect.Command{
	Path:      "/usr/bin/rpm",
	Args:      []string{"-qa", "--qf", "[%{=NAME}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILENAMES}\n]"},
	Timeout:   120 * time.Second,
	MaxOutput: 256 << 20,
}

// rpmLabel names the command in a reason. The whole command line, format
// string and all, is in the envelope's Source; a reason is read by a person.
const rpmLabel = "rpm -qa"

// rpmMaxLine bounds one line of the table. PATH_MAX is 4 KiB, so 64 KiB is
// far more than any real line needs: a line that overruns it is a stream
// that is not the table muster asked for, and the join says so rather than
// stopping silently and reporting the rest of the host as unpackaged.
const rpmMaxLine = 64 << 10

// rpmFile is one row of the file table, for a candidate path only.
type rpmFile struct {
	pkg, owner, group string
	mode              int
}

// joinRPM runs the file-table query and decides every candidate from it. The
// rpm database carries modes, so there is nothing it cannot decide: a path
// it holds is declared (or not) by the mode rpm recorded, and a path it does
// not hold is unpackaged. The reference list is never consulted — on this
// family it is cross-check evidence for the maintainer, not an input (W-7).
func joinRPM(ctx context.Context, a collect.Access, cands map[string]bool, r *walkResult) joinOutcome {
	res := a.Run(ctx, rpmCommand)
	src := res.Source(rpmCommand)
	out := joinOutcome{source: src}
	fail := func(e facts.Envelope) joinOutcome {
		e.Source = src
		e = withTruncation(e, res.Truncated)
		out.failed = &e
		return out
	}
	switch {
	case res.TimedOut:
		return fail(collect.TimeoutEnv(rpmLabel + " timed out"))
	case res.Err != nil:
		return fail(collect.ErrorEnv(rpmLabel + ": " + res.Err.Error()))
	case res.ExitCode != 0:
		// The walk runs as root, so a refusal here is not a privilege
		// problem this process could fix by being someone else; it is a
		// database that would not answer, which is an error.
		reason := rpmLabel + " exited " + strconv.Itoa(res.ExitCode)
		if s := firstLine(res.Stderr); s != "" {
			reason += ": " + s
		}
		return fail(collect.ErrorEnv(reason))
	}
	table, err := rpmFileTable(res.Stdout, cands)
	if err != nil {
		return fail(collect.ErrorEnv(rpmLabel + ": " + err.Error()))
	}
	// A capped capture is still an answer as far as it goes: what was parsed
	// is real, and truncated says the silence means nothing.
	out.truncated = res.Truncated
	applyRPM(r, table)
	return out
}

// rpmFileTable streams the query's output and keeps the candidate lines
// alone, so the memory the join costs is bounded by the number of findings
// and not by the number of files on the host.
func rpmFileTable(stdout []byte, cands map[string]bool) (map[string]rpmFile, error) {
	table := make(map[string]rpmFile, len(cands))
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), rpmMaxLine)
	for sc.Scan() {
		pkg, mode, owner, group, p, ok := pkgfiles.ParseRPMFileLine(sc.Text())
		if !ok || !cands[p] {
			continue
		}
		table[p] = rpmFile{pkg: pkg, owner: owner, group: group, mode: mode}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return table, nil
}

// applyRPM writes the table's answer onto every candidate row. A path the
// table does not hold keeps the fields the traversal initialised — package
// "", package_declared false, reference unpackaged — which is exactly the
// answer for a file no package owns.
func applyRPM(r *walkResult, table map[string]rpmFile) {
	for _, row := range r.lists.suid {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		bits := candidateBits(row)
		row["package"] = f.pkg
		row["package_declared"] = f.mode&bits == bits
		row["declared_mode"] = f.mode
		row["declared_owner"], row["declared_group"] = f.owner, f.group
		row["reference"] = refRPMDB
	}
	for _, row := range r.lists.worldWritable {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		row["package"] = f.pkg
		row["package_declared"] = f.mode&0o002 != 0
		row["reference"] = refRPMDB
	}
	for _, row := range r.lists.hidden {
		f, ok := table[rowField(row, "path")]
		if !ok {
			continue
		}
		// A hidden entry carries no bit to compare, so being owned by a
		// package IS the declaration (W-6).
		row["package"] = f.pkg
		row["package_declared"] = true
		row["reference"] = refRPMDB
	}
}
