//go:build !linux

package main

import (
	"fmt"
	"io"
)

// runCollect off Linux answers the same way for every flag combination:
// there is nothing to collect here. It still parses the command line first
// (R58), so a typo is reported as a typo — with the same message and the
// same exit code as on the host the command will really run on — rather
// than being swallowed by the platform message.
func runCollect(args []string, _, stderr io.Writer) int {
	if _, err := parseCollectFlags(args); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, collectUsage)
		return exitError
	}
	fmt.Fprintln(stderr, "muster: collect requires Linux")
	return exitError
}
