package collectors

import (
	"bytes"
	"encoding/binary"
	"math"
	"runtime"
	"sort"
	"strings"
	"time"
)

// The inactivity policy and the login history (P-1). This file has no build
// tag: it decodes bytes, touches nothing, and is tested on every platform.
// loginCapable, which joins the account files, lives beside the other
// account joins in accounts_login.go.

const (
	useraddDefaultsPath = "/etc/default/useradd"
	lastlogPath         = "/var/log/lastlog"
	// lastlogReadLimit bounds the sparse lastlog read: 32 MiB holds the
	// records of every uid below ~114 000 at 292 bytes each. A uid whose
	// record lies further in is not decoded and the leaf says truncated.
	lastlogReadLimit = 32 << 20
	lastlogRowCap    = 2000 // V-12
)

// parseUseraddDefaults reads INACTIVE from /etc/default/useradd the way
// shadow's get_defaults does (V-7, useradd(8)): a line counts only when it
// starts at column one with "INACTIVE="; its value is C strtol with base 0
// (030 is 24, 0x10 is 16) that must consume the whole value; a later line
// overwrites an earlier one; and an empty, non-numeric or out-of-range value
// or one below -1 is refused and read as -1, "never". The reason says why
// the answer is -1 and is empty for any other value.
func parseUseraddDefaults(data []byte) (inactive int, reason string) {
	inactive, reason = -1, "INACTIVE is absent from "+useraddDefaultsPath+" (useradd's default is -1, never)"
	matched := false
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "INACTIVE=")
		if !ok {
			if !matched && commentedInactive(line) {
				reason = "INACTIVE is commented out in " + useraddDefaultsPath + " (useradd's default is -1, never)"
			}
			continue
		}
		matched = true
		n, why := strtolBase0(value)
		switch {
		case why != "":
			inactive, reason = -1, "INACTIVE is "+why+" in "+useraddDefaultsPath+"; useradd ignores it (-1, never)"
		case n < -1:
			inactive, reason = -1, "INACTIVE is below -1 in "+useraddDefaultsPath+"; useradd ignores it (-1, never)"
		case n == -1:
			inactive, reason = -1, "INACTIVE=-1 in "+useraddDefaultsPath+": the inactivity period is not enforced"
		default:
			inactive, reason = int(n), ""
		}
	}
	return inactive, reason
}

// commentedInactive is a line that would be an INACTIVE= line once its
// comment markers were removed — the stock Ubuntu "# INACTIVE=-1".
func commentedInactive(line string) bool {
	rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t"), "#")
	if !ok {
		return false
	}
	return strings.HasPrefix(strings.TrimLeft(rest, "# \t"), "INACTIVE=")
}

// strtolBase0 is C strtol(s, &end, 0) as shadow's getlong uses it: leading
// isspace skipped, an optional sign, then 0x/0X hex, a leading 0 octal, or
// decimal; the value fails when s is empty, when no digit was read or
// characters are left over, and on overflow (ERANGE). why is "" on success,
// else "empty" or "not a number".
func strtolBase0(s string) (n int64, why string) {
	if s == "" {
		return 0, "empty"
	}
	i := 0
	for i < len(s) && strings.IndexByte(" \t\n\v\f\r", s[i]) >= 0 {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	base := uint64(10)
	switch {
	case i+2 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') && hexDigit(s[i+2]) >= 0:
		// "0x" with no hex digit after it is the number 0 followed by
		// an "x" strtol stops at, which the case below refuses.
		base, i = 16, i+2
	case i < len(s) && s[i] == '0':
		base = 8
	}
	start := i
	var v uint64
	overflow := false
	for ; i < len(s); i++ {
		d := hexDigit(s[i])
		if d < 0 || uint64(d) >= base {
			break
		}
		if v > (math.MaxUint64-uint64(d))/base {
			overflow = true
		} else {
			v = v*base + uint64(d)
		}
	}
	if i == start || i != len(s) {
		return 0, "not a number"
	}
	if overflow || (!neg && v > math.MaxInt64) || (neg && v > 1<<63) {
		return 0, "not a number (out of range)"
	}
	if neg {
		return -int64(v), ""
	}
	return int64(v), ""
}

func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// lastlogRecordSize is sizeof(struct lastlog) on the running architecture
// (V-1).
func lastlogRecordSize() int { return lastlogRecordSizeFor(runtime.GOARCH) }

// lastlogRecordSizeFor follows glibc's bits/utmp.h: ll_time is 32 bits where
// __WORDSIZE_TIME64_COMPAT32 is set (and on 32-bit time_t ABIs), so the
// record is 4+32+256 = 292 bytes; it is a 64-bit __time_t on arm64, s390x
// and loong64, 8+32+256 = 296. An architecture glibc's table does not name
// here reads as 292, the common layout.
func lastlogRecordSizeFor(arch string) int {
	switch arch {
	case "arm64", "s390x", "loong64":
		return 296
	default: // amd64, 386, arm, ppc64, ppc64le, riscv64, mips64, mips64le, …
		return 292
	}
}

// parseLastlog decodes the lastlog records of the uids given: record u sits
// at u*recordSize, ll_time first (uint32 in the 292 layout — glibc 2.40
// declares it unsigned — int64 in the 296 one, host byte order), then
// ll_line[32] and ll_host[256], each NUL-terminated. A uid whose whole record
// is not in data reads as the zero record, as lastlog(8) treats one past the
// end of the sparse file; a zero ll_time is "never logged in", last_login "".
// The caller removes the uids a truncated read cannot answer for. Rows
// {name, uid, last_login, line, host}, sorted by name then uid; an unknown
// record size decodes nothing.
func parseLastlog(data []byte, recordSize int, uids map[int]string) []any {
	type row struct {
		name              string
		uid               int
		login, line, host string
	}
	var timeSize int
	switch recordSize {
	case 292:
		timeSize = 4
	case 296:
		timeSize = 8
	default:
		return []any{}
	}
	rows := make([]row, 0, len(uids))
	for uid, name := range uids {
		if uid < 0 {
			continue
		}
		r := row{name: name, uid: uid}
		// Bounded by division before any multiplication: a passwd uid
		// such as 2^62-1 would wrap uid*recordSize negative and pass an
		// offset test. uid < len/size is "the whole record is in data".
		if uid < len(data)/recordSize {
			off := uid * recordSize
			rec := data[off : off+recordSize]
			var secs int64
			if timeSize == 4 {
				secs = int64(binary.NativeEndian.Uint32(rec))
			} else {
				secs = int64(binary.NativeEndian.Uint64(rec))
			}
			if secs != 0 {
				r.login = time.Unix(secs, 0).UTC().Format(time.RFC3339)
			}
			r.line = lastlogCString(rec[timeSize : timeSize+32])
			r.host = lastlogCString(rec[timeSize+32:])
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].name != rows[j].name {
			return rows[i].name < rows[j].name
		}
		return rows[i].uid < rows[j].uid
	})
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"name": r.name, "uid": r.uid, "last_login": r.login, "line": r.line, "host": r.host,
		})
	}
	return out
}

// lastlogCString is a fixed char array up to its first NUL, with any byte
// that is not UTF-8 replaced so the same file gives the same snapshot bytes.
func lastlogCString(field []byte) string {
	if i := bytes.IndexByte(field, 0); i >= 0 {
		field = field[:i]
	}
	return strings.ToValidUTF8(string(field), "�")
}
