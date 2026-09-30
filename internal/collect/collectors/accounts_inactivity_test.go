package collectors

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
)

// P-1, V-7: the INACTIVE line of /etc/default/useradd is read the way
// shadow's get_defaults reads it — column one, strtol base 0, the last line
// wins, and every value useradd would refuse is "never" (-1) with the reason
// naming which refusal it was.
func TestParseUseraddDefaultsLastLineWinsAndBounds(t *testing.T) {
	seed := func(name string) string {
		t.Helper()
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	cases := []struct {
		name, data string
		want       int
		reason     string // a substring of the reason; "" means the reason must be empty
	}{
		{"stock Ubuntu (commented)", seed("useradd.default.ubuntu"), -1, "INACTIVE is commented"},
		{"EL9 (written -1)", seed("useradd.default.el9"), -1, "INACTIVE=-1"},
		{"35 days", seed("useradd.default.35"), 35, ""},
		{"literal 35", "INACTIVE=35\n", 35, ""},
		{"zero", "INACTIVE=0\n", 0, ""},
		{"octal", "INACTIVE=030\n", 24, ""},
		{"hex", "INACTIVE=0x10\n", 16, ""},
		{"strtol skips leading space in the value", "INACTIVE= 35\n", 35, ""},
		{"empty", "INACTIVE=\n", -1, "empty"},
		{"not a number", "INACTIVE=abc\n", -1, "not a number"},
		{"trailing characters", "INACTIVE=35d\n", -1, "not a number"},
		{"0x with no hex digit", "INACTIVE=0x\n", -1, "not a number"},
		{"a bad octal digit", "INACTIVE=08\n", -1, "not a number"},
		{"trailing carriage return", "INACTIVE=35\r\n", -1, "not a number"},
		{"out of range", "INACTIVE=99999999999999999999\n", -1, "not a number"},
		{"below -1", "INACTIVE=-2\n", -1, "below -1"},
		{"leading space is not the line", " INACTIVE=30\n", -1, "absent"},
		{"no line at all", "SHELL=/bin/sh\n", -1, "absent"},
		{"empty file", "", -1, "absent"},
		{"a commented later line does not count", "INACTIVE=35\n#INACTIVE=10\n", 35, ""},
		{"the last line wins", "INACTIVE=10\nINACTIVE=35\n", 35, ""},
		{"the last line wins even when it is refused", "INACTIVE=35\nINACTIVE=abc\n", -1, "not a number"},
		{"no final newline", "INACTIVE=35", 35, ""},
		{"INACTIVEX is not INACTIVE", "INACTIVEX=5\n", -1, "absent"},
	}
	for _, c := range cases {
		got, reason := parseUseraddDefaults([]byte(c.data))
		if got != c.want {
			t.Errorf("%s: inactive %d, want %d (reason %q)", c.name, got, c.want, reason)
		}
		if c.reason == "" && reason != "" {
			t.Errorf("%s: reason %q, want none", c.name, reason)
		}
		if c.reason != "" && !strings.Contains(reason, c.reason) {
			t.Errorf("%s: reason %q, want it to contain %q", c.name, reason, c.reason)
		}
	}
}

// lastlogRecord is one struct lastlog as a test writes it.
type lastlogRecord struct {
	time       int64
	line, host string
}

// lastlogBytes lays records out as shadow's lastlog writes
// them: record u at u*size, the time in host byte order in the first 4
// (292) or 8 (296) bytes, then ll_line[32] and ll_host[256]; every record
// not given is zero, as in the sparse file.
func lastlogBytes(size, count int, recs map[int]lastlogRecord) []byte {
	out := make([]byte, size*count)
	ts := size - 288
	for uid, r := range recs {
		rec := out[uid*size : (uid+1)*size]
		if ts == 4 {
			binary.NativeEndian.PutUint32(rec, uint32(r.time))
		} else {
			binary.NativeEndian.PutUint64(rec, uint64(r.time))
		}
		copy(rec[ts:ts+32], r.line)
		copy(rec[ts+32:], r.host)
	}
	return out
}

// lastlogSeed is the synthetic file both committed seeds hold: uid 0 logged
// in once, uid 1000's record is zero, 1001 records in all.
func lastlogSeed(size int) []byte {
	return lastlogBytes(size, 1001, map[int]lastlogRecord{0: {1700000000, "pts/0", "203.0.113.5"}})
}

func littleEndian() bool { return binary.NativeEndian.Uint16([]byte{1, 0}) == 1 }

func lastlogRowsByName(t *testing.T, rows []any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

// P-1, V-1: both record layouts decode the same login; a zero record, a uid
// past the end of the file and a trailing partial record all read as "never
// logged in", which is what lastlog(8) prints for them.
func TestParseLastlogBothLayouts(t *testing.T) {
	uids := map[int]string{0: "root", 1000: "alice"}
	for _, size := range []int{292, 296} {
		// The committed seeds are these bytes (the fuzz corpus reads them),
		// so they cannot drift from what the test decodes.
		committed, err := os.ReadFile("testdata/lastlog." + map[int]string{292: "292", 296: "296"}[size])
		if err != nil {
			t.Fatal(err)
		}
		// The seeds are little-endian; a big-endian host decodes its own
		// byte order and has nothing to compare them with.
		if littleEndian() && !bytes.Equal(committed, lastlogSeed(size)) {
			t.Errorf("testdata/lastlog.%d differs from lastlogSeed(%d)", size, size)
		}
		rows := parseLastlog(lastlogSeed(size), size, uids)
		if len(rows) != 2 {
			t.Fatalf("%d: %d rows, want 2: %v", size, len(rows), rows)
		}
		first, second := rows[0].(map[string]any), rows[1].(map[string]any)
		if first["name"] != "alice" || second["name"] != "root" {
			t.Errorf("%d: rows are not sorted by name: %v", size, rows)
		}
		want := map[string]map[string]any{
			"root":  {"name": "root", "uid": 0, "last_login": "2023-11-14T22:13:20Z", "line": "pts/0", "host": "203.0.113.5"},
			"alice": {"name": "alice", "uid": 1000, "last_login": "", "line": "", "host": ""},
		}
		got := lastlogRowsByName(t, rows)
		for name, w := range want {
			for k, v := range w {
				if got[name][k] != v {
					t.Errorf("%d: %s.%s = %#v, want %#v", size, name, k, got[name][k], v)
				}
			}
			if len(got[name]) != len(w) {
				t.Errorf("%d: %s carries %v, want exactly the fields %v", size, name, got[name], w)
			}
		}

		// A uid whose record lies past the end of the file is a zero record.
		past := lastlogRowsByName(t, parseLastlog(lastlogSeed(size), size, map[int]string{5000: "late"}))
		if r := past["late"]; r == nil || r["last_login"] != "" || r["uid"] != 5000 {
			t.Errorf("%d: a uid past EOF must read as never logged in: %v", size, past)
		}

		// A trailing partial record is not decoded, even when its bytes
		// would say something.
		data := lastlogBytes(size, 2, map[int]lastlogRecord{0: {1700000000, "pts/0", "h"}, 1: {1700000001, "pts/1", "x"}})
		partial := lastlogRowsByName(t, parseLastlog(data[:2*size-10], size, map[int]string{0: "root", 1: "daemon"}))
		if partial["daemon"]["last_login"] != "" || partial["daemon"]["line"] != "" {
			t.Errorf("%d: a partial record must read as zero: %v", size, partial["daemon"])
		}
		if partial["root"]["last_login"] != "2023-11-14T22:13:20Z" {
			t.Errorf("%d: the whole record before the partial one must decode: %v", size, partial["root"])
		}
	}

	// The 296 layout's time is 64 bits: a value above 2^32 decodes whole.
	big := lastlogBytes(296, 1, map[int]lastlogRecord{0: {1 << 33, "tty1", ""}})
	if r := lastlogRowsByName(t, parseLastlog(big, 296, map[int]string{0: "root"}))["root"]; r["last_login"] != "2242-03-16T12:56:32Z" {
		t.Errorf("296: a 64-bit time must decode whole: %v", r)
	}
	// The 292 layout's time is unsigned (glibc 2.40): 0xFFFFFFFF is 2106.
	top := lastlogBytes(292, 1, map[int]lastlogRecord{0: {0xFFFFFFFF, "tty1", ""}})
	if r := lastlogRowsByName(t, parseLastlog(top, 292, map[int]string{0: "root"}))["root"]; r["last_login"] != "2106-02-07T06:28:15Z" {
		t.Errorf("292: the time must be read as uint32: %v", r)
	}
	// A uid whose offset would overflow is past the file: the zero record,
	// never a wrapped offset and a panic.
	// 2^62-1 and 2^63-1 on 64-bit ints.
	for _, huge := range []int{math.MaxInt >> 1, math.MaxInt} {
		for _, size := range []int{292, 296} {
			rows := lastlogRowsByName(t, parseLastlog(make([]byte, 2*size), size, map[int]string{huge: "huge"}))
			if r := rows["huge"]; r == nil || r["uid"] != huge || r["last_login"] != "" || r["line"] != "" {
				t.Errorf("%d: uid %d must be a zero row: %v", size, huge, rows)
			}
		}
	}
	// An unknown record size decodes nothing rather than guessing.
	if rows := parseLastlog(lastlogSeed(292), 300, uids); rows == nil || len(rows) != 0 {
		t.Errorf("an unknown record size must yield [], got %#v", rows)
	}
	// No uids asked for, no rows — and never null.
	if rows := parseLastlog(lastlogSeed(292), 292, nil); rows == nil || len(rows) != 0 {
		t.Errorf("no uids must yield [], got %#v", rows)
	}
}

// V-1: the record size follows glibc's __WORDSIZE_TIME64_COMPAT32 per
// architecture, 292 when unknown.
func TestLastlogRecordSizeByArch(t *testing.T) {
	for arch, want := range map[string]int{
		"amd64": 292, "386": 292, "arm": 292, "ppc64": 292, "ppc64le": 292, "riscv64": 292,
		"mips64": 292, "mips64le": 292,
		"arm64": 296, "s390x": 296, "loong64": 296,
		"wasm": 292,
	} {
		if got := lastlogRecordSizeFor(arch); got != want {
			t.Errorf("lastlogRecordSizeFor(%q) = %d, want %d", arch, got, want)
		}
	}
	if got, want := lastlogRecordSize(), lastlogRecordSizeFor(runtime.GOARCH); got != want {
		t.Errorf("lastlogRecordSize() = %d, want %d for %s", got, want, runtime.GOARCH)
	}
	if runtime.GOARCH == "amd64" && lastlogRecordSize() != 292 {
		t.Errorf("amd64 must be 292, got %d", lastlogRecordSize())
	}
}
