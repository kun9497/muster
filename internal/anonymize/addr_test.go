package anonymize

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

// The test's own copy of §1.1's lists, independent of addr.go. IPv4 blocks are
// built from octets (no dotted literal of private or public space here).
func v4p(a, b, c, d byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
}

var (
	tKept = []netip.Prefix{
		v4p(0, 0, 0, 0, 8), v4p(127, 0, 0, 0, 8), v4p(224, 0, 0, 0, 4), v4p(240, 0, 0, 0, 4),
		v4p(255, 255, 255, 255, 32), v4p(192, 0, 2, 0, 24), v4p(198, 51, 100, 0, 24), v4p(203, 0, 113, 0, 24),
		netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
	}
	tRange = []netip.Prefix{
		v4p(10, 0, 0, 0, 8), v4p(100, 64, 0, 0, 10), v4p(169, 254, 0, 0, 16), v4p(172, 16, 0, 0, 12),
		v4p(192, 168, 0, 0, 16), v4p(198, 18, 0, 0, 15),
		netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	}
	tEmbed = []netip.Prefix{netip.MustParsePrefix("::ffff:0:0/96"), netip.MustParsePrefix("64:ff9b::/96")}
)

// low32 returns the IPv4 address in the low 32 bits of a.
func low32(a netip.Addr) netip.Addr {
	b := a.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// tClass names the class of a: "kept", "range <block>", "public", or for an
// embedded IPv4 "embed <block> " + the class of the IPv4 part.
func tClass(a netip.Addr) string {
	a = a.WithZone("")
	for _, e := range tEmbed {
		if e.Contains(a) {
			return "embed " + e.String() + " " + tClass(low32(a))
		}
	}
	for _, p := range tKept {
		if p.Contains(a) {
			return "kept"
		}
	}
	for _, p := range tRange {
		if p.Contains(a) {
			return "range " + p.String()
		}
	}
	return "public"
}

func randIn(r *rand.Rand, p netip.Prefix) netip.Addr {
	n := p.Addr().BitLen()
	var b [16]byte
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	base := p.Masked().Addr().AsSlice()
	for i := 0; i < p.Bits(); i++ {
		bit := base[i/8] >> (7 - i%8) & 1
		b[i/8] = b[i/8]&^(1<<(7-i%8)) | bit<<(7-i%8)
	}
	if n == 32 {
		return netip.AddrFrom4([4]byte(b[:4]))
	}
	return netip.AddrFrom16(b)
}

func randPublic(r *rand.Rand, v6 bool) netip.Addr {
	for {
		var a netip.Addr
		if v6 {
			a = randIn(r, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		} else {
			a = randIn(r, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		}
		if tClass(a) == "public" {
			return a
		}
	}
}

// refAddr is an independent bit-by-bit statement of the PRF for an in-range
// IPv4 or IPv6 address: bit i (i >= keep) is flipped by the low bit of the first
// byte of HMAC(sub("address"), family || i || first i input bits).
func refAddr(k *Key, a netip.Addr, keep int) netip.Addr {
	in := a.AsSlice()
	out := append([]byte(nil), in...)
	fam := byte(6)
	if a.Is4() {
		fam = 4
	}
	for i := keep; i < len(in)*8; i++ {
		msg := []byte{fam, byte(i)}
		pre := make([]byte, (i+7)/8)
		copy(pre, in[:len(pre)])
		if i%8 != 0 {
			pre[len(pre)-1] &= byte(0xff << (8 - i%8))
		}
		m := hmac.New(sha256.New, k.sub(ClassAddress))
		m.Write(append(msg, pre...))
		if m.Sum(nil)[0]&1 == 1 {
			out[i/8] ^= 1 << (7 - i%8)
		}
	}
	r, _ := netip.AddrFromSlice(out)
	return r
}

func commonBits(a, b netip.Addr) int {
	x, y := a.AsSlice(), b.AsSlice()
	n := 0
	for i := range x {
		d := x[i] ^ y[i]
		if d == 0 {
			n += 8
			continue
		}
		for d&0x80 == 0 {
			n++
			d <<= 1
		}
		return n
	}
	return n
}

func TestAddrKeptRangesReturnThemselves(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(1, 2))
	for _, p := range tKept {
		cases := []netip.Addr{p.Masked().Addr()}
		for i := 0; i < 2000; i++ {
			cases = append(cases, randIn(r, p))
		}
		for _, a := range cases {
			if got := k.Addr(a); got != a {
				t.Fatalf("kept %s (%s) -> %s", a, p, got)
			}
		}
	}
	for _, s := range []string{"::", "::1", "255.255.255.255", "0.0.0.0", "127.0.0.1", "192.0.2.10", "ff02::1", "2001:db8::5"} {
		a := netip.MustParseAddr(s)
		if got := k.Addr(a); got != a {
			t.Errorf("kept %s -> %s", a, got)
		}
	}
}

func TestAddrInRangeStaysInItsRange(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(3, 4))
	for _, p := range tRange {
		moved := 0
		for i := 0; i < 4000; i++ {
			a := randIn(r, p)
			got := k.Addr(a)
			if !p.Contains(got) {
				t.Fatalf("%s left %s: %s", a, p, got)
			}
			if want := refAddr(k, a, p.Bits()); got != want {
				t.Fatalf("%s -> %s, reference PRF says %s", a, got, want)
			}
			if got != a {
				moved++
			}
		}
		if moved < 3900 {
			t.Errorf("%s: only %d of 4000 addresses moved", p, moved)
		}
	}
}

func TestAddrInRangeIsInjective(t *testing.T) {
	k := testKey(t, 7)
	check := func(p netip.Prefix, block netip.Prefix) {
		seen := map[netip.Addr]netip.Addr{}
		for a := p.Masked().Addr(); p.Contains(a); a = a.Next() {
			got := k.Addr(a)
			if !block.Contains(got) {
				t.Fatalf("%s left %s: %s", a, block, got)
			}
			if prev, ok := seen[got]; ok {
				t.Fatalf("%s and %s both map to %s", prev, a, got)
			}
			seen[got] = a
		}
	}
	check(v4p(10, 0, 0, 0, 24), v4p(10, 0, 0, 0, 8))
	check(v4p(192, 168, 0, 0, 16), v4p(192, 168, 0, 0, 16))
	check(netip.MustParsePrefix("fd12:3456::/112"), netip.MustParsePrefix("fc00::/7"))
}

func TestAddrPublicStaysPublicAndInjective(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(5, 6))
	n := 1 << 20
	if testing.Short() {
		n = 1 << 14
	}
	seen := make(map[netip.Addr]netip.Addr, n)
	moved := 0
	for i := 0; i < n; i++ {
		a := randPublic(r, false)
		got := k.Addr(a)
		if c := tClass(got); c != "public" {
			t.Fatalf("public %s -> %s (%s)", a, got, c)
		}
		if prev, ok := seen[got]; ok && prev != a {
			t.Fatalf("%s and %s both map to %s", prev, a, got)
		}
		seen[got] = a
		if got != a {
			moved++
		}
	}
	if moved < n-n/100 {
		t.Errorf("only %d of %d public addresses moved", moved, n)
	}
	for i := 0; i < 1<<12; i++ {
		a := randPublic(r, true)
		if got := k.Addr(a); tClass(got) != "public" || got == a {
			t.Fatalf("public %s -> %s (%s)", a, got, tClass(got))
		}
	}
}

// Public addresses next to every block: flip one bit of the block's network
// address inside its prefix, randomise the rest; whatever is public must stay so.
func TestAddrPublicNearEveryBoundaryStaysPublic(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(7, 8))
	all := append(append(append([]netip.Prefix{}, tKept...), tRange...), tEmbed...)
	tried := 0
	for _, p := range all {
		base := p.Masked().Addr().AsSlice()
		for j := 0; j < p.Bits(); j++ {
			b := append([]byte(nil), base...)
			b[j/8] ^= 1 << (7 - j%8)
			na, _ := netip.AddrFromSlice(b)
			for s := 0; s < 8; s++ {
				a := randIn(r, netip.PrefixFrom(na, j+1))
				if tClass(a) != "public" {
					continue
				}
				tried++
				if got := k.Addr(a); tClass(got) != "public" {
					t.Fatalf("public %s (next to %s) -> %s (%s)", a, p, got, tClass(got))
				}
			}
		}
	}
	if tried < 2000 {
		t.Errorf("only %d boundary addresses tried", tried)
	}
}

func TestAddrPreservesPrefixes(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(9, 10))
	gen := []func() netip.Addr{
		func() netip.Addr { return randPublic(r, false) },
		func() netip.Addr { return randPublic(r, true) },
		func() netip.Addr { return randIn(r, v4p(10, 0, 0, 0, 8)) },
		func() netip.Addr { return randIn(r, v4p(172, 16, 0, 0, 12)) },
		func() netip.Addr { return randIn(r, netip.MustParsePrefix("fe80::/10")) },
	}
	for gi, g := range gen {
		for i := 0; i < 3000; i++ {
			a := g()
			n := r.IntN(a.BitLen() + 1)
			b := randIn(r, netip.PrefixFrom(a, n))
			if tClass(b) != tClass(a) {
				continue
			}
			want := commonBits(a, b)
			if got := commonBits(k.Addr(a), k.Addr(b)); got != want {
				t.Fatalf("gen %d: %s and %s share %d bits, outputs %s and %s share %d", gi, a, b, want, k.Addr(a), k.Addr(b), got)
			}
		}
	}
}

func TestPrefixKeepsContainment(t *testing.T) {
	k := testKey(t, 7)
	r := rand.New(rand.NewPCG(11, 12))
	nets := []netip.Prefix{v4p(10, 20, 0, 0, 16), v4p(192, 168, 7, 0, 24), v4p(172, 17, 0, 0, 16), netip.MustParsePrefix("fd00:1:2::/48")}
	for i := 0; i < 20; i++ {
		a := randPublic(r, false)
		nets = append(nets, netip.PrefixFrom(a, 8+r.IntN(24)).Masked())
		b := randPublic(r, true)
		nets = append(nets, netip.PrefixFrom(b, 16+r.IntN(100)).Masked())
	}
	for _, p := range nets {
		mp := k.Prefix(p)
		if mp.Bits() != p.Bits() {
			t.Fatalf("%s -> %s: length changed", p, mp)
		}
		if mp.Addr() != k.Addr(p.Addr()) {
			t.Fatalf("%s -> %s: network not mapped as an address", p, mp)
		}
		for j := 0; j < 200; j++ {
			h := randIn(r, p)
			if tClass(h) != tClass(p.Addr()) {
				continue
			}
			if !mp.Contains(k.Addr(h)) {
				t.Fatalf("%s in %s, but %s not in %s", h, p, k.Addr(h), mp)
			}
		}
	}
}

func TestPrefixWithHostBitsKeepsLength(t *testing.T) {
	k := testKey(t, 7)
	a := netip.AddrFrom4([4]byte{10, 1, 2, 3})
	p := netip.PrefixFrom(a, 16)
	got := k.Prefix(p)
	if got.Bits() != 16 || got.Addr() != k.Addr(a) {
		t.Fatalf("%s -> %s, want %s/16", p, got, k.Addr(a))
	}
	tok, ok := k.AddrToken(a.String() + "/16")
	if !ok || tok != k.Addr(a).String()+"/16" {
		t.Fatalf("token %s/16 -> %q %v", a, tok, ok)
	}
	if (netip.Prefix{}) != k.Prefix(netip.Prefix{}) {
		t.Error("invalid prefix changed")
	}
}

func TestAddrEmbeddedIPv4(t *testing.T) {
	k := testKey(t, 7)
	v4 := netip.AddrFrom4([4]byte{10, 9, 8, 7})
	mapped := netip.AddrFrom16(v4.As16())
	got := k.Addr(mapped)
	if !got.Is4In6() || got.Unmap() != k.Addr(v4) {
		t.Fatalf("::ffff:%s -> %s, want ::ffff:%s", v4, got, k.Addr(v4))
	}
	nat := netip.MustParsePrefix("64:ff9b::/96")
	b := nat.Addr().As16()
	copy(b[12:], v4.AsSlice())
	got = k.Addr(netip.AddrFrom16(b))
	if !nat.Contains(got) || low32(got) != k.Addr(v4) {
		t.Fatalf("64:ff9b::%s -> %s, want low 32 bits %s", v4, got, k.Addr(v4))
	}
	pub := netip.AddrFrom4([4]byte{8, 8, 4, 4})
	if got := k.Addr(netip.AddrFrom16(pub.As16())); got.Unmap() != k.Addr(pub) || tClass(got.Unmap()) != "public" {
		t.Fatalf("::ffff:%s -> %s", pub, got)
	}
	lo := netip.MustParseAddr("::ffff:127.0.0.1")
	if got := k.Addr(lo); got != lo {
		t.Fatalf("%s -> %s", lo, got)
	}
}

func TestAddrZoneKept(t *testing.T) {
	k := testKey(t, 7)
	a := netip.MustParseAddr("fe80::1%eth0")
	got := k.Addr(a)
	if got.Zone() != "eth0" || !netip.MustParsePrefix("fe80::/10").Contains(got.WithZone("")) || got.WithZone("") == a.WithZone("") {
		t.Fatalf("%s -> %s", a, got)
	}
	tok, ok := k.AddrToken("fe80::1%eth0")
	if !ok || tok != got.String() || !strings.HasSuffix(tok, "%eth0") {
		t.Fatalf("token -> %q %v", tok, ok)
	}
}

func TestAddrTokenForms(t *testing.T) {
	k := testKey(t, 7)
	priv := netip.AddrFrom4([4]byte{10, 1, 2, 3})
	priv2 := netip.AddrFrom4([4]byte{192, 168, 1, 20})
	pub := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	v6 := netip.MustParseAddr("fd00::42")
	m := func(a netip.Addr) string { return k.Addr(a).String() }
	three := strings.Join([]string{"8", "8", "8"}, ".")
	cases := []struct{ in, want string }{
		{"", ""},
		{priv.String(), m(priv)},
		{pub.String(), m(pub)},
		{v6.String(), m(v6)},
		{"192.0.2.1", "192.0.2.1"},
		{priv.String() + "/24", k.Addr(priv).String() + "/24"},
		{"fd00::/8", k.Addr(netip.MustParseAddr("fd00::")).String() + "/8"},
		{priv.String() + "/255.255.255.0", m(priv) + "/255.255.255.0"},
		{priv.String() + ":514", m(priv) + ":514"},
		{"[" + v6.String() + "]:123", "[" + m(v6) + "]:123"},
		{"[fe80::1%eth0]:22", "[" + m(netip.MustParseAddr("fe80::1%eth0")) + "]:22"},
		{"udp:" + priv.String(), "udp:" + m(priv)},
		{"tcp:" + priv.String() + ":514", "tcp:" + m(priv) + ":514"},
		{"udp6:[" + v6.String() + "]:514", "udp6:[" + m(v6) + "]:514"},
		{"tcp6:" + v6.String(), "tcp6:" + m(v6)},
		{"udp6:[::1]:514", "udp6:[::1]:514"},
		{priv.String() + "-" + priv2.String(), m(priv) + "-" + m(priv2)},
		{"{ " + priv.String() + ", " + pub.String() + "/16 }", "{ " + m(priv) + ", " + m(pub) + "/16 }"},
		{"{" + priv.String() + "," + priv2.String() + "-" + pub.String() + "}", "{" + m(priv) + "," + m(priv2) + "-" + m(pub) + "}"},
		{"127.0.0.1:8080", "127.0.0.1:8080"},
	}
	for _, c := range cases {
		got, ok := k.AddrToken(c.in)
		if !ok || got != c.want {
			t.Errorf("AddrToken(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	for _, s := range []string{
		"web.example", "localhost", three, pub.String() + "/33", priv.String() + "/255.0.255.0", priv.String() + ":99999",
		priv.String() + ":", priv.String() + ":x", "[::1]", "[::1]:", "[" + pub.String() + "]:5", "::1:80:", "udp:", "udp:web.example",
		"sctp:" + priv.String(), priv.String() + "-", "-" + priv.String(), "a-b", "{ }", "{}", "{ " + priv.String() + ", web }",
		"{ " + priv.String() + ",, " + pub.String() + " }", " " + priv.String(), priv.String() + " ", pub.String() + "%eth0",
		"fe80::1%eth0/64", "fe80::1%eth0-fe80::2", "*", "any", "udp:udp:" + priv.String(), "{ {" + pub.String() + "} }",
	} {
		if got, ok := k.AddrToken(s); ok {
			t.Errorf("AddrToken(%q) = %q, true; want false", s, got)
		}
	}
}

// Known answers for the all-0x07 key, computed independently with python -I
// (hmac, hashlib, ipaddress) from the construction: sub = HMAC(K,
// "muster/anon/v1/address"); bit i flipped by HMAC(sub, fam || i || first i
// bits)[0] & 1 from bit `keep` on, where keep is the range prefix length for an
// in-range address and, for a public one, the largest min(common+1, len) over
// every block of the family. IPv4 results are written as octets.
func TestAddrKnownAnswers(t *testing.T) {
	k := testKey(t, 7)
	for _, c := range []struct {
		in, want netip.Addr
	}{
		{netip.AddrFrom4([4]byte{10, 1, 2, 3}), netip.AddrFrom4([4]byte{10, 95, 68, 61})},
		{netip.AddrFrom4([4]byte{8, 8, 8, 8}), netip.AddrFrom4([4]byte{9, 161, 115, 219})},
		{netip.MustParseAddr("fd00::42"), netip.MustParseAddr("fc6f:dc64:dd5:ad5f:1191:b499:38b1:410f")},
		{netip.MustParseAddr("2a00:1450::1"), netip.MustParseAddr("2cde:5e0e:9665:a964:1760:6cf:f56:1307")},
		{netip.AddrFrom16(netip.AddrFrom4([4]byte{10, 1, 2, 3}).As16()), netip.AddrFrom16(netip.AddrFrom4([4]byte{10, 95, 68, 61}).As16())},
	} {
		if got := k.Addr(c.in); got != c.want {
			t.Errorf("Addr(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}
