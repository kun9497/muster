//go:build linux

package collectors

import (
	"maps"
	"strconv"
	"strings"
)

// The three conf files the pam collector reads are each read by its own
// module's parser, and the three disagree (H-5, H-6): libpwquality matches
// names case-blind and stops a file at the first line it cannot take,
// pam_faillock matches them case-sensitively and ignores what it cannot take,
// and pam_pwhistory's lookup stops at the first line that names the key. One
// shared reader would be wrong for at least two of them, so each has its own
// below, named after the upstream function it follows. They share the C
// locale's isspace, strcasecmp's ASCII-only folding (asciiLower, patch.go:
// strings.ToLower would turn the Kelvin sign into a k) and glibc's sscanf "%u".

// cSpace is isspace(3) in the C locale: what every one of the upstream
// readers trims and splits on. Go's unicode.IsSpace is wider (U+0085, U+00A0).
func cSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// trimCSpace trims cSpace bytes from both ends of s.
func trimCSpace(s string) string {
	i, j := 0, len(s)
	for i < j && cSpace(s[i]) {
		i++
	}
	for j > i && cSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

// confLines splits a conf file into its lines as fgets/getline hand them to
// the upstream readers: at "\n", with the number of each (1-based). The empty
// piece after a final newline is not a line.
func confLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// scanUnsigned reads s the way glibc's sscanf "%u" (bits 32) or "%hu" (bits
// 16) does: leading blanks skipped, an optional sign, then at least one
// decimal digit; the digits are converted as strtoul does — saturating at
// ULONG_MAX on overflow, a "-" negating modulo 2^64 — and the result is cut to
// bits, the way scanf stores it into an unsigned int or short. Anything after
// the digits is ignored ("5abc" reads 5). ok is false when no digit converts,
// which is sscanf returning 0.
func scanUnsigned(s string, bits uint) (uint64, bool) {
	i := 0
	for i < len(s) && cSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, false
	}
	n, err := strconv.ParseUint(s[start:i], 10, 64)
	if err != nil {
		n = ^uint64(0) // ERANGE: strtoul returns ULONG_MAX, sign or not
	} else if neg {
		n = -n
	}
	return n & (1<<bits - 1), true
}

// lineStop is the line at which a reader stops reading a file: its number and
// its text after the comment is cut and the blanks trimmed, or, for a line
// refused for its shape (too long, a NUL byte), Why says which instead.
type lineStop struct {
	Line int
	Text string
	Why  string
}

// pwqualityMaxLine is libpwquality's PWQSETTINGS_MAX_LINELEN: read_config_file
// reads a line with fgets into a buffer one byte longer, so a line of this
// many bytes or more before its "\n" fills the buffer without its newline,
// and that chunk is PWQ_ERROR_CFGFILE_MALFORMED.
const pwqualityMaxLine = 1023

// pwqualityDropinName is libpwquality's filter_conf (settings.c), which
// scandir applies to pwquality.conf.d: an entry is read when the FIRST
// ".conf" in its name ends the name. A hidden name is read too ("." starts
// no exclusion there); "a.conf.conf" is not. comp_func orders the survivors
// with strcmp, which is the bytewise sort mergeDropinsWith already does.
func pwqualityDropinName(base string) bool {
	i := strings.Index(base, ".conf")
	return i >= 0 && i+len(".conf") == len(base)
}

// pwqualityKind is how libpwquality's set_name_value treats a setting.
type pwqualityKind int

const (
	pwqInt  pwqualityKind = iota + 1 // strtol base 10; a bad value is an error
	pwqStr                           // the value as written
	pwqFlag                          // present means set; the value is ignored
)

// pwqualityNames are the 21 names set_name_value (libpwquality settings.c)
// knows; any other name is an error that stops the file. It is a lookup table
// only and never reaches a renderer.
var pwqualityNames = map[string]pwqualityKind{
	"difok": pwqInt, "minlen": pwqInt, "dcredit": pwqInt, "ucredit": pwqInt, "lcredit": pwqInt,
	"ocredit": pwqInt, "minclass": pwqInt, "maxrepeat": pwqInt, "maxclassrepeat": pwqInt,
	"maxsequence": pwqInt, "gecoscheck": pwqInt, "dictcheck": pwqInt, "usercheck": pwqInt,
	"usersubstr": pwqInt, "enforcing": pwqInt, "retry": pwqInt,
	"badwords": pwqStr, "dictpath": pwqStr, "allowclasses": pwqStr,
	"enforce_for_root": pwqFlag, "local_users_only": pwqFlag,
}

// pwqualityInt reads an integer value as set_name_value does: strtol base 10
// over the whole value (a sign is accepted, trailing characters are not), and
// an empty value, an overflow, INT_MAX and INT_MIN are errors.
func pwqualityInt(v string) (int, bool) {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n >= 1<<31-1 || n <= -(1<<31) {
		return 0, false
	}
	return int(n), true
}

// parsePwqualityInto applies one pwquality conf file to kv the way
// libpwquality's read_config_file (settings.c) reads it: each line is cut at
// its first "#" and trimmed, a blank line is skipped, the name ends at the
// first blank or "=", and the blanks and at most one "=" after it are skipped
// (splitNameValue, H-16); the rest is the value. Names are stored ASCII lower-cased (set_name_value uses
// strcasecmp); an integer is stored in its decimal form, a flag with an empty
// value. The first line whose name is unknown or whose integer set_name_value
// refuses stops the file: the lines before it stay applied, and the line is
// returned so pwquality_read_config's caller can skip every later file. nil
// means the whole file was read.
//
// A line fgets cannot hand over whole stops the file the same way (H-9,
// PWQ_ERROR_CFGFILE_MALFORMED): one of pwqualityMaxLine bytes or more, and
// one holding a NUL byte, which strlen cuts short of its newline. Any NUL is
// taken as a stop — on a last line at EOF libpwquality would read the part
// before it, so this is the conservative side. The caller reads the chain
// with ReadFileBinary so the NUL reaches this test (chainReader.binary).
func parsePwqualityInto(data []byte, kv map[string]string) *lineStop {
	for i, raw := range confLines(data) {
		if strings.IndexByte(raw, 0) >= 0 {
			return &lineStop{Line: i + 1, Why: "NUL byte"}
		}
		if len(raw) >= pwqualityMaxLine {
			return &lineStop{Line: i + 1, Why: "line of " + strconv.Itoa(pwqualityMaxLine) + " bytes or more"}
		}
		l, _, _ := strings.Cut(raw, "#")
		l = trimCSpace(l)
		if l == "" {
			continue
		}
		name, v := splitNameValue(l)
		name = asciiLower(name)
		switch pwqualityNames[name] {
		case pwqInt:
			n, ok := pwqualityInt(v)
			if !ok {
				return &lineStop{Line: i + 1, Text: l}
			}
			kv[name] = strconv.Itoa(n)
		case pwqStr:
			kv[name] = v
		case pwqFlag:
			kv[name] = ""
		default:
			return &lineStop{Line: i + 1, Text: l}
		}
	}
	return nil
}

// splitNameValue splits a comment-cut, trimmed, non-blank line the way both
// libpwquality's and pam_faillock's read_config_file do (H-16): the name ends
// at the first blank or "=" (eq records an "="), then blanks are skipped
// along with at most ONE "=" — only when the name did not already end at one
// — and the value is everything after that. A second "=" is the value's
// first character: "minlen == 14" has the value "= 14".
func splitNameValue(l string) (name, value string) {
	end := 0
	for end < len(l) && !cSpace(l[end]) && l[end] != '=' {
		end++
	}
	name, v := l[:end], l[end:]
	eq := false
	if v != "" {
		eq = v[0] == '='
		v = v[1:]
	}
	for len(v) > 0 && (cSpace(v[0]) || (v[0] == '=' && !eq)) {
		if v[0] == '=' {
			eq = true
		}
		v = v[1:]
	}
	return name, v
}

// confSetting is one name and value in file order.
type confSetting struct{ name, value string }

// parseFaillockConf splits faillock.conf into its settings in file order the
// way pam_faillock's read_config_file (faillock_config.c) does: each line is
// cut at its first "#" and trimmed, a blank line is skipped, the key ends at
// the first blank or "=", and the blanks after it are skipped along with ONE
// "=" (a key ended by "=" has had its one); the rest is the value. Names keep
// their case — set_conf_opt compares them with strcmp — and every line is
// kept, so the caller applies them in order and the last one wins.
func parseFaillockConf(data []byte) []confSetting {
	var out []confSetting
	for _, raw := range confLines(data) {
		l, _, _ := strings.Cut(raw, "#")
		l = trimCSpace(l)
		if l == "" {
			continue
		}
		name, v := splitNameValue(l)
		out = append(out, confSetting{name, v})
	}
	return out
}

// faillockMaxTime is pam_faillock's MAX_TIME_INTERVAL (one week): a longer
// fail_interval, unlock_time or root_unlock_time is refused.
const faillockMaxTime = 604800

// faillockOpts is the part of pam_faillock's options muster reads, as
// set_conf_opt leaves it after a run of settings.
type faillockOpts struct {
	vals map[string]int
	// rootSet: a root_unlock_time was taken; otherwise the module uses the
	// effective unlock_time for root.
	rootSet bool
	// denyRoot: even_deny_root was named, or root_unlock_time (which implies
	// it, whatever its value).
	denyRoot bool
}

// clone copies o so one stack line can be resolved on top of the conf file
// without disturbing it.
func (o faillockOpts) clone() faillockOpts {
	o.vals = maps.Clone(o.vals)
	return o
}

// set applies one setting as pam_faillock's set_conf_opt does: names are
// case-sensitive and an unknown one is ignored; deny is sscanf "%hu"; the
// three times are sscanf "%u" bounded by MAX_TIME_INTERVAL, the two unlock
// times also taking never for 0; a value that does not convert leaves the
// field as it was. It serves faillock.conf's lines and the module arguments
// alike, since args_parse hands each argument to the same function.
func (o *faillockOpts) set(name, value string) {
	switch name {
	case "deny":
		if n, ok := scanUnsigned(value, 16); ok {
			o.vals["deny"] = int(n)
		}
	case "fail_interval", "unlock_time", "root_unlock_time":
		if name == "root_unlock_time" {
			o.denyRoot = true
		}
		var n uint64
		var ok bool
		if value == "never" && name != "fail_interval" {
			n, ok = 0, true
		} else {
			n, ok = scanUnsigned(value, 32)
			ok = ok && n <= faillockMaxTime
		}
		if ok {
			o.vals[name] = int(n)
			if name == "root_unlock_time" {
				o.rootSet = true
			}
		}
	case "even_deny_root":
		o.denyRoot = true
	}
}

// setArgs applies a stack line's arguments as pam_faillock's args_parse does:
// an argument with "=" is split at the first one into name and value, any
// other is a name with an empty value; preauth, authfail and authsucc select
// the mode and are not settings.
func (o *faillockOpts) setArgs(args []string) {
	for _, a := range args {
		name, value, _ := strings.Cut(a, "=")
		switch a {
		case "preauth", "authfail", "authsucc":
			continue
		}
		o.set(name, value)
	}
}

// pwhistoryRemember finds remember in pwhistory.conf the way pam_pwhistory
// does (pwhistory_config.c through pam_modutil_search_key in
// pam_modutil_searchkey.c): each line is cut at its first "#", leading blanks
// are skipped, the key ends at a space, a tab or "=", and the run of blanks
// and "=" after it is skipped; the FIRST line whose key is remember, compared
// case-blind, is the answer, and later ones are never seen. Its value is read
// with sscanf "%u". found is false when no line names the key; ok is false
// when the first one's value does not convert (the module then keeps its
// default). line is that line's number.
func pwhistoryRemember(data []byte) (n, line int, found, ok bool) {
	for i, raw := range confLines(data) {
		l, _, _ := strings.Cut(raw, "#")
		for l != "" && cSpace(l[0]) {
			l = l[1:]
		}
		if l == "" {
			continue
		}
		end := strings.IndexAny(l, " \t=")
		key, v := l, ""
		if end >= 0 {
			key, v = l[:end], l[end+1:]
			for v != "" && (cSpace(v[0]) || v[0] == '=') {
				v = v[1:]
			}
		}
		if asciiLower(key) != "remember" {
			continue
		}
		u, ok := scanUnsigned(v, 32)
		return int(u), i + 1, true, ok
	}
	return 0, 0, false, false
}
