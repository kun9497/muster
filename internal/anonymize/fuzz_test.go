package anonymize

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

func FuzzHost(f *testing.F) {
	for _, s := range []string{"", "a", "web.corp.test", "WEB.Corp.", "..", ".a.", "a..b", "xn--bcher-kva.example"} {
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
		if got != strings.ToLower(got) {
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
