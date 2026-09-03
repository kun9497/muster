//go:build linux

// Package collectors holds the stage-1 collectors. Importing it registers
// every one of them; each declares the paths it reads and the commands it
// runs, and the guard refuses anything outside that declaration (spec §9,
// §11). Nothing here touches the host except through collect.Access (R46).
package collectors

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// readLimit caps an ordinary configuration file. The kernel socket tables
// are larger and have their own limit (procNetLimit).
const readLimit = 1 << 20

// rawCap is how much of a source line a fact may carry (R64). A snapshot is
// evidence for a finding, not a copy of the host's files.
const rawCap = 256

func init() {
	collect.Register(osCollector)
	collect.Register(servicesCollector)
	collect.Register(socketsCollector)
	collect.Register(sshdCollector)
	collect.Register(filesCollector)
	collect.Register(accountsCollector)
	collect.Register(walkCollector)
}

// splitLines splits file or command output into lines and drops a trailing
// carriage return, so a CRLF-terminated file parses exactly like an LF one.
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines
}

// sourceRaw is the evidence line a fact carries: the source line itself,
// capped at rawCap bytes and cut on a rune boundary so the cap can never
// split a UTF-8 sequence (R64).
func sourceRaw(line string) string {
	line = strings.TrimSuffix(line, "\r")
	if len(line) <= rawCap {
		return line
	}
	cut := rawCap
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "…"
}

// firstLine is the first non-empty line of a command's stderr — the reason a
// failed command carries.
func firstLine(b []byte) string {
	for _, line := range splitLines(b) {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	return ""
}

// commandFailure classifies a command that ran but did not succeed: denied
// when the command said so, error otherwise, with the first stderr line as
// the reason and the command itself as the source (R59).
func commandFailure(what string, out collect.Output, src *facts.Source) facts.Envelope {
	reason := firstLine(out.Stderr)
	if reason == "" {
		if out.Err != nil {
			reason = what + ": " + out.Err.Error()
		} else {
			reason = what + " exited " + strconv.Itoa(out.ExitCode)
		}
	}
	e := collect.ErrorEnv(reason)
	if strings.Contains(string(out.Stderr), "Permission denied") {
		e = collect.Denied(reason)
	}
	e.Source = src
	return e
}

// intField parses a numeric colon-separated field. An empty or unparsable
// field means "unset" — which chage prints as "never" — and is recorded as
// -1, never as 0, so it can never be mistaken for a real zero-day policy.
func intField(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}
