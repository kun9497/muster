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
		if section != "Coredump" {
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
// exponent grows: K is 1024, not 1000. "B" is a suffix too, with a factor of
// one, and so is the empty string — which is why a bare number parses and
// "2GB" does not (systemd consumes the "G" and then fails on the leftover
// "B", where a number was due).
const sizeSuffixes = "KMGTPE"

// sizeInfinity is what systemd spells "infinity": no limit at all.
const sizeInfinity = "infinity"

// parseSizeValue parses a size the way systemd's parse_size does, which is
// what ProcessSizeMax= is read with:
//
//   - a decimal number with an optional binary suffix, and "B"/"b" as a
//     suffix of factor one;
//   - a decimal FRACTION of a suffix ("1.5G");
//   - CONCATENATION of several such terms ("1G512M"), summed;
//   - "infinity", the one word that is a size.
//
// Everything else is refused rather than guessed, so the caller can report
// the bytes it saw as an `error` instead of publishing a number the daemon
// would never have computed: a negative number, a trailing "2GB", a word, a
// term with no digits, and an overflow — a silently wrapped size would be a
// confident wrong answer.
func parseSizeValue(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if s == sizeInfinity {
		return math.MaxInt64, true
	}
	var total int64
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t")
		whole, rest, ok := leadingDigits(s)
		if !ok {
			return 0, false
		}
		s = rest
		n, err := strconv.ParseInt(whole, 10, 64)
		if err != nil {
			return 0, false
		}
		// The fraction is carried as a float only between here and the
		// multiplication: systemd does the same, and the factor it is
		// multiplied by is at most 2^60, so the product stays exact enough
		// that no size an operator writes can round to a different byte.
		frac := 0.0
		if strings.HasPrefix(s, ".") {
			digits, rest, ok := leadingDigits(s[1:])
			if !ok {
				return 0, false
			}
			f, err := strconv.ParseFloat("0."+digits, 64)
			if err != nil {
				return 0, false
			}
			frac, s = f, rest
		}
		s = strings.TrimLeft(s, " \t")
		mult := int64(1)
		if len(s) > 0 {
			c := s[0]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			if i := strings.IndexByte(sizeSuffixes, c); i >= 0 {
				for range i + 1 {
					mult *= 1024
				}
				s = s[1:]
			} else if c == 'B' {
				s = s[1:]
			}
		}
		if n > math.MaxInt64/mult {
			return 0, false
		}
		term := n * mult
		if frac > 0 {
			term += int64(frac * float64(mult))
		}
		if term > math.MaxInt64-total {
			return 0, false
		}
		total += term
	}
	return total, true
}

// leadingDigits splits the run of ASCII digits at the front of s from the
// rest, and reports whether there was one at all. A term with no digits —
// "-1", "high", the "B" left over from "2GB" — is not a size.
func leadingDigits(s string) (digits, rest string, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:], i > 0
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
