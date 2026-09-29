package collectors

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// vfsCapVector reads one of the testdata/vfscap.* seeds, which hold the raw
// attribute bytes: the kernel layout of include/uapi/linux/capability.h
// filled in by hand.
func vfsCapVector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecodeVfsCapVectors(t *testing.T) {
	cases := []struct {
		file, text string
		version    int
		rootID     uint32
	}{
		{"vfscap.v2-net-raw-ep", "cap_net_raw=ep", 2, 0},
		{"vfscap.v3-net-raw-ep-root0", "cap_net_raw=ep", 3, 0},
		{"vfscap.v2-chown-setuid-p", "cap_chown,cap_setuid=p", 2, 0},
		{"vfscap.v2-mixed", "cap_net_bind_service=ei cap_net_raw+ep", 2, 0},
		{"vfscap.v2-perfmon-bpf-ep", "cap_perfmon,cap_bpf=ep", 2, 0},
		{"vfscap.v1-net-raw-ep", "cap_net_raw=ep", 1, 0},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			cs, err := decodeVfsCap(vfsCapVector(t, c.file))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := capText(cs); got != c.text {
				t.Errorf("capText = %q, want %q", got, c.text)
			}
			if cs.Version != c.version || cs.RootID != c.rootID {
				t.Errorf("version/rootid = %d/%d, want %d/%d", cs.Version, cs.RootID, c.version, c.rootID)
			}
			// The text the file renders to parses back to the file's own set.
			back, err := parseCapText(c.text)
			if err != nil || !sameCaps(back, cs) {
				t.Errorf("parseCapText(%q) = %+v, %v; want the decoded %+v", c.text, back, err, cs)
			}
		})
	}
}

// Review Focus 2: the kernel accepts a revision only at its own size, so a
// 20-byte attribute that claims revision 3 is no capability at all.
func TestDecodeVfsCapRejectsSizeMismatch(t *testing.T) {
	v2 := vfsCapVector(t, "vfscap.v2-net-raw-ep")
	rev3in20 := append([]byte{0x01, 0x00, 0x00, 0x03}, v2[4:]...)
	rev2in24 := append(append([]byte{0x01, 0x00, 0x00, 0x02}, v2[4:]...), 0, 0, 0, 0)
	rev4 := append([]byte{0x00, 0x00, 0x00, 0x04}, v2[4:]...)
	for name, b := range map[string][]byte{
		"revision 3 in 20 bytes": rev3in20,
		"revision 2 in 24 bytes": rev2in24,
		"revision 4":             rev4,
		"3 bytes":                {0x01, 0x00, 0x00},
		"nothing":                nil,
	} {
		if cs, err := decodeVfsCap(b); err == nil {
			t.Errorf("%s: decoded %+v, want an error", name, cs)
		}
	}
}

// V-3: every spelling a declaration source may use for one set is one set.
func TestParseCapTextSpellings(t *testing.T) {
	want := capSet{Permitted: 1 << 13, Effective: true}
	for _, s := range []string{"cap_net_raw+ep", "cap_net_raw=ep", "CAP_NET_RAW=pe", "13=ep", "0xd=ep", "015=ep", "cap_net_raw=+ep", "= cap_net_raw+ep"} {
		got, err := parseCapText(s)
		if err != nil || !sameCaps(got, want) {
			t.Errorf("parseCapText(%q) = %+v, %v; want %+v", s, got, err, want)
		}
	}
	const round = "cap_setfcap=eip cap_chown+ep"
	if cs, err := parseCapText(round); err != nil || capText(cs) != round {
		t.Errorf("round trip of %q = %q, %v", round, capText(cs), err)
	}
	// The pairs libcap's own test table gives for the compact form.
	for in, out := range map[string]string{
		"= cap_chown+iep cap_chown-i":             "cap_chown=ep",
		"= cap_setfcap,cap_chown+iep cap_chown-i": "cap_setfcap=eip cap_chown+ep",
		"=i =p":          "=p",
		"all+pie":        "=eip",
		"all=p+ie-e":     "=ip",
		"cap_fowner+p-i": "cap_fowner=p",
	} {
		cs, err := parseCapText(in)
		if err != nil || capText(cs) != out {
			t.Errorf("capText(parseCapText(%q)) = %q, %v; want %q", in, capText(cs), err, out)
		}
	}
	if cs, err := parseCapText("="); err != nil || cs.Permitted != 0 || cs.Inheritable != 0 || cs.Effective {
		t.Errorf("parseCapText(\"=\") = %+v, %v; want the empty set", cs, err)
	}
	if capText(capSet{}) != "=" {
		t.Errorf("capText(empty) = %q, want \"=\"", capText(capSet{}))
	}
	// The effective flag on empty masks raises nothing: it is the empty set
	// (found by FuzzDecodeVfsCap).
	flagOnly := capSet{Effective: true, Version: 2}
	if capText(flagOnly) != "=" || !sameCaps(flagOnly, capSet{}) {
		t.Errorf("flag-only set renders %q and compares %v, want \"=\" and equal to empty", capText(flagOnly), sameCaps(flagOnly, capSet{}))
	}
	for _, bad := range []string{"cap_bogus=p", "", "cap_net_raw", "cap_net_raw+", "+ep", "cap_net_raw=x", "64=p", "1_3=ep", "0b1101=ep", "0o15=ep"} {
		if cs, err := parseCapText(bad); err == nil {
			t.Errorf("parseCapText(%q) = %+v, want an error", bad, cs)
		}
	}
}

// §1.3: the most common state is the default, so a set that raises almost
// everything is written as the default and the one exception; a bit past the
// named ones is spelled by its number.
func TestCapTextMajorityDefault(t *testing.T) {
	all := namedMask() &^ (1 << 21) // every named bit but cap_sys_admin
	if got := capText(capSet{Permitted: all, Effective: true}); got != "=ep cap_sys_admin-ep" {
		t.Errorf("capText = %q, want %q", got, "=ep cap_sys_admin-ep")
	}
	if got := capText(capSet{Permitted: all | 1<<41}); got != "=p cap_sys_admin-p 41+p" {
		t.Errorf("capText = %q, want %q", got, "=p cap_sys_admin-p 41+p")
	}
	if got := capText(capSet{Permitted: 1 << 41}); got != "= 41+p" {
		t.Errorf("capText = %q, want %q", got, "= 41+p")
	}
	// A tie goes to the lower state: 20 bits p against 21 nothing is the
	// nothing default; 21 p against 20 nothing is the p default.
	var twenty, twentyOne uint64
	for n := 0; n < 20; n++ {
		twenty |= 1 << n
	}
	twentyOne = twenty | 1<<20
	if got := capText(capSet{Permitted: twenty}); strings.HasPrefix(got, "=p") {
		t.Errorf("20 of 41 raised rendered %q with the raised default", got)
	}
	if got := capText(capSet{Permitted: twentyOne}); !strings.HasPrefix(got, "=p ") {
		t.Errorf("21 of 41 raised rendered %q, want the raised default", got)
	}
	// Whatever renders parses back to itself.
	for _, cs := range []capSet{{Permitted: all | 1<<41}, {Permitted: twentyOne, Inheritable: 1 << 3, Effective: true}} {
		back, err := parseCapText(capText(cs))
		if err != nil || !sameCaps(back, cs) {
			t.Errorf("parseCapText(capText(%+v)) = %+v, %v", cs, back, err)
		}
	}
}

// A LOW-1: capText is held to libcap's own cap_to_text(3) bytes. Each blob
// is the security.capability value setcap wrote and each text what getcap
// printed for it, measured with libcap 2.44 (Ubuntu 22.04, kernel 5.15, 41
// named bits); the majority default is libcap's, all=ep included.
func TestCapTextMatchesLibcap(t *testing.T) {
	for _, c := range []struct{ hex, getcap string }{
		{"01000002ffffffff00000000ff01000000000000", "=ep"},
		{"0100000200300000000000000000000000000000", "cap_net_admin,cap_net_raw=ep"},
		{"01000002ffffdfff00000000ff01000000000000", "=ep cap_sys_admin-ep"},
		{"01000002ffffffffffffffffff010000ff010000", "=eip"},
		{"0000000280000000002000000000000000000000", "cap_net_raw=i cap_setuid+p"},
		{"00000002ffffffff00200000ff01000000000000", "=p cap_net_raw+i"},
		{"0100000200200000000000000000000000000000", "cap_net_raw=ep"},
	} {
		raw, err := hex.DecodeString(c.hex)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := decodeVfsCap(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if got := capText(cs); got != c.getcap {
			t.Errorf("capText(%s) = %q, getcap printed %q", c.hex, got, c.getcap)
		}
		back, err := parseCapText(c.getcap)
		if err != nil || !sameCaps(back, cs) {
			t.Errorf("parseCapText(%q) = %+v, %v; want %+v", c.getcap, back, err, cs)
		}
	}
}
