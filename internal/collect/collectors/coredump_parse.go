//go:build linux

package collectors

import (
	"math"
	"strconv"
	"strings"
)

// confFile is one file of a merged configuration chain: where it came from
// and what it held, in the order the chain applies them.
type confFile struct {
	path string
	data []byte
}

// coredumpValue is one assignment of a [Coredump] key, with the line it came
// from so the fact can cite it. set distinguishes "this file assigned an
// empty value" from "this file said nothing".
type coredumpValue struct {
	set   bool
	value string
	line  int
	raw   string
}

// coredumpConf is what ONE coredump.conf file sets; the last assignment in
// the file wins, as it does for systemd.
type coredumpConf struct {
	storage coredumpValue
	sizeMax coredumpValue
}

// coredumpWinner is the assignment that survived the whole chain and the
// file it came from.
type coredumpWinner struct {
	coredumpValue
	file string
}

// parseCoredumpConf reads one coredump.conf or drop-in. Only the [Coredump]
// section counts: journald.conf's own Storage= would otherwise be read as a
// core-dump policy by a file that merely shares a key name, and an
// assignment before any section header belongs to no section at all.
func parseCoredumpConf(data []byte) coredumpConf {
	var out coredumpConf
	section := ""
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if !strings.EqualFold(section, "Coredump") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val := coredumpValue{set: true, value: strings.TrimSpace(v), line: i + 1, raw: sourceRaw(raw)}
		switch strings.TrimSpace(k) {
		case "Storage":
			out.storage = val
		case "ProcessSizeMax":
			out.sizeMax = val
		}
	}
	return out
}

// mergeCoredumpConf applies the chain in order and returns the last
// assignment of each key together with the file that made it, plus the
// files that were read.
func mergeCoredumpConf(files []confFile) (storage, sizeMax coredumpWinner, seen []string) {
	for _, f := range files {
		seen = append(seen, f.path)
		conf := parseCoredumpConf(f.data)
		if conf.storage.set {
			storage = coredumpWinner{coredumpValue: conf.storage, file: f.path}
		}
		if conf.sizeMax.set {
			sizeMax = coredumpWinner{coredumpValue: conf.sizeMax, file: f.path}
		}
	}
	return storage, sizeMax, seen
}

// sizeSuffixes are systemd's binary size suffixes, in the order their
// exponent grows. systemd takes K to mean 1024, not 1000, and accepts no
// "B" suffix.
const sizeSuffixes = "KMGTPE"

// parseSizeValue parses a systemd size: a decimal number with an optional
// binary suffix. It refuses anything else — a negative number, a "2GB", a
// word — rather than guessing, so the caller can report the bytes it saw.
// An overflow is refused for the same reason: a silently wrapped size would
// be a confident wrong answer.
func parseSizeValue(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	// The last BYTE, upper-cased by hand: strings.ToUpper may change the
	// length of a non-ASCII string, and indexing the result by this one's
	// length would then be out of range.
	last := s[len(s)-1]
	if last >= 'a' && last <= 'z' {
		last -= 'a' - 'A'
	}
	if i := strings.IndexByte(sizeSuffixes, last); i >= 0 {
		for range i + 1 {
			mult *= 1024
		}
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	if n > math.MaxInt64/mult {
		return 0, false
	}
	return n * mult, true
}

// limitLine is one `* hard core <value>` or `* - core <value>` line of
// limits.conf, with unlimited recorded as -1.
type limitLine struct {
	value int
	line  int
	raw   string
}

// parseLimitsCore returns the lines of one limits.conf-style file that set a
// HARD core limit for EVERY user. A `@group` or a named-user domain binds
// only those accounts and says nothing about the host's policy; a `soft`
// line is a default a process may raise on its own; `-` sets both limits
// (limits.conf(5)) and so counts as the hard one.
func parseLimitsCore(data []byte) []limitLine {
	var out []limitLine
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "*" {
			continue
		}
		if t := strings.ToLower(f[1]); t != "hard" && t != "-" {
			continue
		}
		if !strings.EqualFold(f[2], "core") {
			continue
		}
		v, ok := parseLimitValue(f[3])
		if !ok {
			continue
		}
		out = append(out, limitLine{value: v, line: i + 1, raw: sourceRaw(raw)})
	}
	return out
}

// parseLimitValue reads a limits.conf value: a count of 1024-byte blocks for
// the core item, or one of the three spellings of no limit, which the fact
// carries as -1.
func parseLimitValue(field string) (int, bool) {
	switch strings.ToLower(field) {
	case "unlimited", "infinity", "-1":
		return -1, true
	}
	n, err := strconv.Atoi(field)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
