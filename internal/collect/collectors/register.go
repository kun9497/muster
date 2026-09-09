//go:build linux

// Package collectors holds the stage-1 collectors. Importing it registers
// every one of them; each declares the paths it reads and the commands it
// runs, and the guard refuses anything outside that declaration (spec §9,
// §11). Nothing here touches the host except through collect.Access (R46).
package collectors

import (
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// euid is os.Geteuid; tests substitute it so the privilege rule below can be
// exercised from a suite that runs as whichever account started it (R84).
// Production code never assigns to it.
var euid = os.Geteuid

// readLimit caps an ordinary configuration file. The kernel socket tables
// are larger and have their own limit (procNetLimit).
const readLimit = 1 << 20

// rawCap is how much of a source line a fact may carry (R64). A snapshot is
// evidence for a finding, not a copy of the host's files.
const rawCap = 256

func init() {
	collect.Register(osCollector)
	collect.Register(envCollector)
	collect.Register(servicesCollector)
	collect.Register(socketsCollector)
	collect.Register(sshdCollector)
	collect.Register(bannersCollector)
	collect.Register(filesCollector)
	collect.Register(cronCollector)
	collect.Register(accountsCollector)
	collect.Register(pamCollector)
	collect.Register(firewallCollector)
	collect.Register(loggingCollector)
	collect.Register(timesyncCollector)
	collect.Register(nfsCollector)
	collect.Register(snmpCollector)
	collect.Register(ftpCollector)
	collect.Register(mailCollector)
	collect.Register(patchCollector)
	collect.Register(walkCollector)
}

// filesSource renders the provenance of a value computed from files: a plain
// file source when exactly one file contributed, the repository's derived
// shape (accounts.go's precedent) when several did, and NOTHING when none
// did — an envelope must never cite a path the collector did not read.
// Shared by the snmp and nfs collectors, both of which parse one main file
// plus a drop-in directory and must cite whichever of them existed.
func filesSource(files []string) *facts.Source {
	switch len(files) {
	case 0:
		return nil
	case 1:
		return &facts.Source{Kind: "file", Path: files[0]}
	}
	inputs := make([]facts.Source, 0, len(files))
	for _, f := range files {
		inputs = append(inputs, facts.Source{Kind: "file", Path: f})
	}
	return &facts.Source{Kind: "derived", Inputs: inputs}
}

// pathReason prefixes a read's reason with the file it came from (C3), so a
// denied read names itself rather than leaving the reader to guess which of
// the several files a collector opens could not be opened. Shared by the
// nfs and patch collectors, both of which read a set of files discovered by
// a glob.
func pathReason(p string, e facts.Envelope) facts.Envelope {
	e.Reason = p + ": " + e.Reason
	return e
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
// when the privilege was the problem, error otherwise, with the first
// stderr line as the reason and the command itself as the source (R59).
//
// needsRoot is the declaring collector's Needs == "root". R84: a root-only
// command that fails while this process is not root failed for want of the
// privilege, whatever it printed — `sshd -T` as a normal user says "Could
// not load host key" or "no hostkeys available", never "Permission denied",
// and filing that as an error would have the run header report "facts with
// status error" where spec §7.1/D25 wants denied with the privilege named.
// The stderr substring stays as the rule for everything else, including a
// root-only command that failed while this process WAS root: there the
// message is the only evidence there is.
func commandFailure(what string, out collect.Output, src *facts.Source, needsRoot bool) facts.Envelope {
	reason := firstLine(out.Stderr)
	if reason == "" {
		if out.Err != nil {
			reason = what + ": " + out.Err.Error()
		} else {
			reason = what + " exited " + strconv.Itoa(out.ExitCode)
		}
	}
	var e facts.Envelope
	switch {
	case needsRoot && euid() != 0:
		e = collect.Denied(what + " requires root: " + reason)
	case strings.Contains(string(out.Stderr), "Permission denied"):
		e = collect.Denied(reason)
	default:
		e = collect.ErrorEnv(reason)
	}
	e.Source = src
	return withTruncation(e, out.Truncated)
}

// withTruncation marks an envelope built from a command whose capture hit
// the output cap. It is the command-side counterpart of the read
// primitive's ReadMeta.Truncated that OKRead carries (R70): a value parsed
// out of a partial stream must never be read as the whole answer, and a
// reason taken from a partial stderr may itself be cut short.
func withTruncation(e facts.Envelope, truncated bool) facts.Envelope {
	e.Truncated = e.Truncated || truncated
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
