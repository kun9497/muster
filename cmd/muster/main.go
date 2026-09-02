// Command muster checks whether a Linux server passes muster: collect facts as
// root, then evaluate the snapshot offline against the KISA Unix server items.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes are a CLI contract (spec §7, D11): CI must be able to tell "ran
// and found something" from "could not run or cannot be trusted".
const (
	exitOK       = 0 // completed, nothing at or above the fail-on threshold
	exitFindings = 1 // completed, findings at or above the threshold
	exitError    = 2 // could not run, or the result cannot be trusted
)

// Set by -ldflags at build time (see Makefile).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const usage = `usage: muster <command> [flags]

commands:
  check      evaluate a facts snapshot against the embedded controls
  controls   lint or list the embedded controls
  version    print version, commit and build date
  help       print this message
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a command and returns its exit code. It never panics: the
// recover guard turns any panic into exit 2 (spec §7.2), because a crash that
// leaks exit 0 or 1 would break the exit-code contract.
func run(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "muster: internal error: %v\n", r)
			code = exitError
		}
	}()
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "muster %s\ncommit %s\nbuilt %s\n", version, commit, date)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "controls":
		return runControls(args[1:], stdout, stderr)
	case "__panic_for_test":
		panic("deliberate")
	default:
		fmt.Fprintf(stderr, "muster: unknown command %q\n%s", args[0], usage)
		return exitError
	}
}
