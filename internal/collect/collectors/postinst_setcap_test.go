package collectors

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func readSeed(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParsePostinstSetcapForms(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []postinstCap
	}{
		{"seed iputils-ping: a variable set from dpkg-divert --truename", string(readSeed(t, "postinst.iputils-ping")),
			[]postinstCap{{Path: "/bin/ping", Caps: "cap_net_raw+ep", Truename: true}}},
		{"seed mtr-tiny: a literal path", string(readSeed(t, "postinst.mtr-tiny")),
			[]postinstCap{{Path: "/usr/bin/mtr-packet", Caps: "cap_net_raw+ep"}}},
		{"seed snapd: the set read from a file", string(readSeed(t, "postinst.snapd-caps")),
			[]postinstCap{{Path: "/usr/lib/snapd/snap-confine", FromFile: true}}},
		{"a literal assignment, braces and quotes",
			"PROGRAM=/usr/bin/ping\nif setcap cap_net_raw+ep \"${PROGRAM}\"; then :; fi\n",
			[]postinstCap{{Path: "/usr/bin/ping", Caps: "cap_net_raw+ep"}}},
		{"a truename substitution used directly",
			"setcap cap_net_raw+ep $(dpkg-divert --truename /usr/bin/foo)\n",
			[]postinstCap{{Path: "/usr/bin/foo", Caps: "cap_net_raw+ep", Truename: true}}},
		{"iproute2: quoted caps, then a removal that declares nothing",
			"if ! setcap \"cap_dac_override,cap_sys_admin,cap_net_admin=ep\" /bin/ip; then\n  setcap \"-r\" /bin/ip\nfi\n",
			[]postinstCap{{Path: "/bin/ip", Caps: "cap_dac_override,cap_sys_admin,cap_net_admin=ep"}}},
		{"options, a continuation and two pairs",
			"setcap -q -n 0 cap_chown=p /usr/bin/a \\\n  cap_kill=p /usr/bin/b 2>/dev/null || true\n",
			[]postinstCap{{Path: "/usr/bin/a", Caps: "cap_chown=p"}, {Path: "/usr/bin/b", Caps: "cap_kill=p"}}},
		{"a setcap in a comment, an echo and a heredoc are not calls",
			"# setcap cap_sys_admin+ep /usr/bin/x\necho setcap cap_sys_admin+ep /usr/bin/x\ncat <<EOF\nsetcap cap_sys_admin+ep /usr/bin/y\nEOF\n",
			nil},
		{"an unknown variable, a relative path and a reassigned name are unresolved calls",
			"setcap cap_net_raw+ep $NOPE\nsetcap cap_net_raw+ep bin/ping\nP=/usr/bin/p\nP=$(uname -m)\nsetcap cap_net_raw+ep $P\nsetcap $CAPS /usr/bin/c\n",
			[]postinstCap{{Unresolved: true}, {Unresolved: true}, {Unresolved: true}, {Path: "/usr/bin/c", Unresolved: true}}},
		{"setcap - needs something on standard input",
			"setcap - /usr/bin/a\ncat /usr/share/a.caps | setcap -q - /usr/bin/b\n",
			[]postinstCap{{Path: "/usr/bin/a", Unresolved: true}, {Path: "/usr/bin/b", FromFile: true}}},
		{"after && and in a then branch on one line",
			"command -v setcap >/dev/null && setcap cap_net_raw+ep /usr/bin/q; if true; then setcap cap_net_raw+p /usr/bin/r; fi\n",
			[]postinstCap{{Path: "/usr/bin/q", Caps: "cap_net_raw+ep"}, {Path: "/usr/bin/r", Caps: "cap_net_raw+p"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePostinstSetcap([]byte(c.data))
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parsePostinstSetcap = %+v, want %+v", got, c.want)
			}
		})
	}
}

// The fuzz target's seeds, run as a plain test so they are exercised on every
// platform (FuzzParsePostinstSetcap itself lives in the Linux-only
// fuzz_test.go with the inventory).
func TestParsePostinstSetcapSeeds(t *testing.T) {
	seedsFound, err := filepath.Glob("testdata/postinst.*")
	if err != nil || len(seedsFound) == 0 {
		t.Fatalf("no postinst seeds: %v", err)
	}
	for _, s := range seedsFound {
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		first, second := parsePostinstSetcap(data), parsePostinstSetcap(data)
		if len(first) == 0 || !reflect.DeepEqual(first, second) {
			t.Errorf("%s: %+v / %+v, want one deterministic call at least", s, first, second)
		}
	}
}
