// Command coverage renders docs/reference/coverage.md from the embedded
// control set and the KISA item inventory, or checks that the committed
// file is current (-check). It never touches internal/collect.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kun9497/muster/internal/controls"
)

func main() {
	out := flag.String("out", "docs/reference/coverage.md", "file to write")
	inv := flag.String("kisa", "docs/reference/kisa/kisa_items_latest.json", "KISA item inventory")
	check := flag.Bool("check", false, "exit 1 if the committed file differs instead of writing")
	flag.Parse()
	data, err := os.ReadFile(*inv)
	if err != nil {
		fatal(err)
	}
	var items []kisaItem
	if err := json.Unmarshal(data, &items); err != nil {
		fatal(fmt.Errorf("%s: %w", *inv, err))
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fatal(err)
	}
	got := []byte(render(items, set.Controls))
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "coverage: %s does not exist; run: go run ./tools/coverage\n", *out)
			os.Exit(1)
		}
		if !bytes.Equal(have, got) {
			fmt.Fprintf(os.Stderr, "coverage: %s is out of date; run: go run ./tools/coverage\n", *out)
			os.Stderr.WriteString(unifiedDiff(*out, have, got))
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*out, got, 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "coverage: %v\n", err)
	os.Exit(2)
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
