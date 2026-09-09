// Command coverage renders docs/reference/coverage.md from the embedded
// control set, the KISA item inventory and the fact registry, or checks that
// the committed file -- and the roadmap sentence of both READMEs -- is
// current (-check). It never touches internal/collect.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

// run is the whole command. It takes its arguments and its error stream so
// that -check, which is what CI runs, is testable without a subprocess.
// Exit codes: 0 current or written, 1 stale, 2 could not be determined.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "docs/reference/coverage.md", "file to write")
	kisaDir := fs.String("kisa-dir", "docs/reference/kisa", "directory holding the KISA item inventory")
	readmeDir := fs.String("readme-dir", ".", "directory holding README.md and README.ko.md, whose roadmap sentence -check verifies")
	check := fs.Bool("check", false, "exit 1 if the committed file differs instead of writing")
	if err := fs.Parse(args); err != nil {
		// -h and -help print the usage and are not a failure to determine
		// anything; a bad flag is.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	inventory, err := controls.LoadKISA(*kisaDir)
	if err != nil {
		return fatal(stderr, err)
	}
	items := inventory.Items[controls.LatestKISAEdition]
	set, err := controls.LoadDefault()
	if err != nil {
		return fatal(stderr, err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		return fatal(stderr, err)
	}
	got := []byte(render(items, inventory.Deferred, controls.FactUsage(set, reg), set.Controls))
	if *check {
		// Both halves of the gate run every time and the worst code wins,
		// so a contributor who is stale in the table and in the prose
		// learns about both in one run instead of one per run.
		code := 0
		have, err := os.ReadFile(*out)
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "coverage: %s does not exist; run: go run ./tools/coverage\n", *out)
			code = 1
		case !bytes.Equal(have, got):
			fmt.Fprintf(stderr, "coverage: %s is out of date; run: go run ./tools/coverage\n", *out)
			io.WriteString(stderr, unifiedDiff(*out, have, got))
			code = 1
		}
		if c := checkREADMEs(stderr, *readmeDir, enrolledCount(items, inventory.Deferred, set.Controls), len(items)); c > code {
			code = c
		}
		return code
	}
	if err := os.WriteFile(*out, got, 0o644); err != nil {
		return fatal(stderr, err)
	}
	return 0
}

// checkREADMEs verifies that the roadmap sentence of both READMEs still
// carries the live coverage numbers (M-20). The sentence is a claim about
// what muster judges, and a stale claim is worse than none; the generated
// table alone cannot keep it honest, because nothing regenerates prose.
//
// Both sides are whitespace-normalised before matching (M-24), so a sentence
// that wraps the fragment across a line break -- which the Korean one does --
// still matches, and reflowing a paragraph never fails the gate.
func checkREADMEs(stderr io.Writer, dir string, enrolled, total int) int {
	for _, f := range []struct{ name, fragment string }{
		{"README.md", fmt.Sprintf("%d of the %d items", enrolled, total)},
		{"README.ko.md", fmt.Sprintf("%d개 중 %d개", total, enrolled)},
	} {
		data, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return fatal(stderr, err)
		}
		if !strings.Contains(normalizeSpace(string(data)), normalizeSpace(f.fragment)) {
			fmt.Fprintf(stderr, "coverage: %s does not mention %q; update the roadmap sentence\n", f.name, f.fragment)
			return 1
		}
	}
	return 0
}

// normalizeSpace collapses every run of whitespace, newlines included, to a
// single space so that a fragment split across lines still matches.
func normalizeSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

func fatal(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "coverage: %v\n", err)
	return 2
}

// unifiedDiff renders a minimal unified-diff-style report naming path and
// showing what changed between the committed bytes (have) and what the
// generator produces now (want). It is not a general-purpose diff
// algorithm: it trims the common prefix and common suffix of lines and
// reports the remaining span as a single hunk, which is enough to show a
// reviewer exactly which lines are stale.
func unifiedDiff(path string, have, want []byte) string {
	haveLines := strings.Split(string(have), "\n")
	wantLines := strings.Split(string(want), "\n")

	prefix := 0
	for prefix < len(haveLines) && prefix < len(wantLines) && haveLines[prefix] == wantLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(haveLines)-prefix && suffix < len(wantLines)-prefix &&
		haveLines[len(haveLines)-1-suffix] == wantLines[len(wantLines)-1-suffix] {
		suffix++
	}

	removed := haveLines[prefix : len(haveLines)-suffix]
	added := wantLines[prefix : len(wantLines)-suffix]

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s (committed)\n", path)
	fmt.Fprintf(&b, "+++ %s (generated)\n", path)
	fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", prefix+1, len(removed), prefix+1, len(added))
	for _, l := range removed {
		fmt.Fprintf(&b, "-%s\n", l)
	}
	for _, l := range added {
		fmt.Fprintf(&b, "+%s\n", l)
	}
	return b.String()
}
