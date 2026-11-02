package anonymize

import (
	"bytes"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"testing"
)

func FuzzHost(f *testing.F) {
	for _, s := range []string{"", "*", "ALL", "root", "a", "web.site.example.test", "WEB.Site.Example.", "..", ".a.", "a..b", "xn--bcher-kva.example"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string) {
		got := k.Host(s)
		if got != k.Host(s) {
			t.Fatal("not deterministic")
		}
		if s == "" && got != "" {
			t.Fatal("empty")
		}
		if strings.HasSuffix(s, ".") != strings.HasSuffix(got, ".") {
			t.Fatalf("trailing dot: %q -> %q", s, got)
		}
		if got != strings.ToLower(got) && !Kept(s) {
			t.Fatalf("upper case in %q", got)
		}
		if Kept(s) && got != s {
			t.Fatalf("kept name changed: %q -> %q", s, got)
		}
	})
}

var accountOut = regexp.MustCompile(`^[%+\-@#]*(u[a-z2-7]{12}|[0-9]*)$`)

func FuzzAccount(f *testing.F) {
	for _, s := range []string{"", "root", "%admins", "+@ng", "#1001", "#x", "-n", "@", "#", "ALL", "*"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string) {
		got := k.Account(s)
		if got != k.Account(s) {
			t.Fatal("not deterministic")
		}
		if got != s && !accountOut.MatchString(got) {
			t.Fatalf("shape: %q -> %q", s, got)
		}
		if s == "" && got != "" {
			t.Fatal("empty")
		}
	})
}

func FuzzAddrToken(f *testing.F) {
	for _, s := range []string{"", "::1", "fe80::1%eth0", "[fd00::1]:53", "udp6:[fd00::1]:514", "tcp:192.0.2.1:514",
		"192.0.2.0/255.255.255.0", "198.51.100.1-198.51.100.9", "{ 192.0.2.1, 2001:db8::/48 }", "::ffff:192.0.2.1",
		"64:ff9b::c000:201", "fd00::/7", "web.example", "{}", "[::1]:99999"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := k.AddrToken(s)
		got2, ok2 := k.AddrToken(s)
		if got != got2 || ok != ok2 {
			t.Fatal("not deterministic")
		}
		if !ok {
			if got != "" {
				t.Fatalf("%q: no match but output %q", s, got)
			}
			return
		}
		if _, ok := k.AddrToken(got); !ok {
			t.Fatalf("%q -> %q, which is not an address form", s, got)
		}
		if a, err := netip.ParseAddr(s); err == nil {
			b, err := netip.ParseAddr(got)
			if err != nil || tClass(a) != tClass(b) {
				t.Fatalf("%q -> %q: class %s -> %s", s, got, tClass(a), tClass(b))
			}
			if a.Zone() != b.Zone() {
				t.Fatalf("%q -> %q: zone", s, got)
			}
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			q, err := netip.ParsePrefix(got)
			if err != nil || q.Bits() != p.Bits() {
				t.Fatalf("%q -> %q: length", s, got)
			}
		}
	})
}

func FuzzMapPath(f *testing.F) {
	for _, s := range []string{"", "/", "/home/alice/x", "/home//a", "/srv/app/bob/f", "/var/spool/cron/crontabs/carol",
		"/etc/cron.d/carol", "relative/x", "/home/", "/var/log", "//"} {
		f.Add(s)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	h := testHomes()
	f.Fuzz(func(t *testing.T, s string) {
		got := k.MapPath(s, h)
		if got != k.MapPath(s, h) {
			t.Fatal("not deterministic")
		}
		if !strings.HasPrefix(s, "/") && got != s {
			t.Fatalf("relative path changed: %q -> %q", s, got)
		}
		in, out := strings.Split(s, "/"), strings.Split(got, "/")
		if len(in) != len(out) {
			t.Fatalf("component count: %q -> %q", s, got)
		}
		for i := range in {
			if in[i] != out[i] && out[i] != k.Account(in[i]) {
				t.Fatalf("component %d of %q -> %q is not its account pseudonym", i, s, got)
			}
			if i == 0 || !strings.HasPrefix(s, "/") || in[i] == "" || in[i] == "." || in[i] == ".." {
				continue
			}
			parent := path.Clean("/" + strings.Join(in[1:i], "/"))
			at := parent == "/home" || namePositions[parent] || homeEligible(path.Join(parent, in[i]), in[i], h)
			if at && h.names[out[i]] {
				t.Fatalf("component %d of %q -> %q: a mapped name in clear at an AX-6 position", i, s, got)
			}
		}
	})
}

func FuzzHostOrAddr(f *testing.F) {
	for _, s := range []string{"", "*", "@ng", "@@(o)log.example:514", "udp:h:161", "*.site.example", ":0", "a.b.", "[::1]:53", "@", "@("} {
		f.Add(s, false)
		f.Add(s, true)
	}
	k, _ := NewKey(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, s string, netgroup bool) {
		w := &walker{k: k, ledger: NewLedger(), classes: map[string]bool{}, replaced: map[string]bool{}}
		got := w.hostOrAddr("f", s, netgroup)
		if got != (&walker{k: k, ledger: NewLedger(), classes: map[string]bool{}, replaced: map[string]bool{}}).hostOrAddr("f", s, netgroup) {
			t.Fatal("not deterministic")
		}
		if (got == Placeholder) != w.replaced["f"] {
			t.Fatalf("%q -> %q: replaced %v", s, got, w.replaced["f"])
		}
		if s == "" && got != "" {
			t.Fatal("empty")
		}
	})
}

// FuzzNewKey: NewKey accepts exactly 32 bytes, keeps a copy (a later change
// to the input moves nothing) and derives one key id from one input.
func FuzzNewKey(f *testing.F) {
	for _, s := range [][]byte{nil, {}, {0}, bytes.Repeat([]byte{7}, 31), bytes.Repeat([]byte{7}, 32),
		bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{7}, 33), bytes.Repeat([]byte{1}, 64)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		k, err := NewKey(raw)
		if (err == nil) != (len(raw) == 32) {
			t.Fatalf("len %d: err %v", len(raw), err)
		}
		if err != nil {
			if k != nil {
				t.Fatal("a refused key is not nil")
			}
			return
		}
		id := k.ID()
		if len(id) != 16 {
			t.Fatalf("key id %q", id)
		}
		raw[0] ^= 0xff
		if k.ID() != id {
			t.Fatal("the key aliases its input")
		}
	})
}
