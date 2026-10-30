package anonymize

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"net/netip"
	"strings"
)

// The address map of spec §1.1. Every output bit i is the input bit i XOR a
// function of the first i input bits only:
//
//   - inside a kept block, and at every bit where the input prefix so far is a
//     proper ancestor of a kept, in-range or embedded block, the bit is kept;
//   - inside an in-range block, from the block's length on, and at every other
//     bit of a public address, the bit is flipped by the keyed PRF: the low bit
//     of the first byte of HMAC(sub("address"), family || i || the first i
//     input bits packed MSB-first, unused trailing bits zero);
//   - inside an embedded block (::ffff:0:0/96, 64:ff9b::/96) the 96-bit prefix
//     is kept and the low 32 bits are mapped by the IPv4 rules.
//
// That triangular form makes the map a bijection of the whole address space
// (each bit decodes from the output prefix already decoded) and prefix
// preserving. A block's address never leaves it (its prefix bits are kept),
// and a public address never enters one: by induction its first L bits equal
// the block's only while they are an ancestor of it, where no bit flips, so it
// would have been in the block already. Being injective and class-keeping on
// finite classes, it is a bijection of each class (addr_test.go tests it).

type blockKind int

const (
	blockKept blockKind = iota
	blockRange
	blockEmbed
)

type block struct {
	p    netip.Prefix
	kind blockKind
}

// IPv4 blocks are built from octets: no dotted literal of private space here.
func v4block(a, b, c, d byte, bits int, kind blockKind) block {
	return block{netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits), kind}
}

func v6block(s string, kind blockKind) block { return block{netip.MustParsePrefix(s), kind} }

var (
	v4Blocks = []block{
		v4block(0, 0, 0, 0, 8, blockKept),
		v4block(127, 0, 0, 0, 8, blockKept),
		v4block(224, 0, 0, 0, 4, blockKept),
		v4block(240, 0, 0, 0, 4, blockKept),
		v4block(255, 255, 255, 255, 32, blockKept),
		v4block(192, 0, 2, 0, 24, blockKept),
		v4block(198, 51, 100, 0, 24, blockKept),
		v4block(203, 0, 113, 0, 24, blockKept),
		v4block(10, 0, 0, 0, 8, blockRange),
		v4block(100, 64, 0, 0, 10, blockRange),
		v4block(169, 254, 0, 0, 16, blockRange),
		v4block(172, 16, 0, 0, 12, blockRange),
		v4block(192, 168, 0, 0, 16, blockRange),
		v4block(198, 18, 0, 0, 15, blockRange),
	}
	v6Blocks = []block{
		v6block("::/128", blockKept),
		v6block("::1/128", blockKept),
		v6block("ff00::/8", blockKept),
		v6block("2001:db8::/32", blockKept),
		v6block("fc00::/7", blockRange),
		v6block("fe80::/10", blockRange),
		v6block("::ffff:0:0/96", blockEmbed),
		v6block("64:ff9b::/96", blockEmbed),
	}
)

// Addr maps an address by §1.1; a zone is kept, the invalid Addr returned as is.
func (k *Key) Addr(a netip.Addr) netip.Addr {
	if !a.IsValid() {
		return a
	}
	zone := a.Zone()
	m := hmac.New(sha256.New, k.sub(ClassAddress))
	return mapAddr(m, a.WithZone("")).WithZone(zone)
}

// Prefix maps the address part of p by Addr and keeps its length; host bits a
// CIDR was written with are mapped as part of the address, never cleared.
func (k *Key) Prefix(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return p
	}
	return netip.PrefixFrom(k.Addr(p.Addr()), p.Bits())
}

func mapAddr(m hash.Hash, a netip.Addr) netip.Addr {
	blocks, fam := v6Blocks, byte(6)
	if a.Is4() {
		blocks, fam = v4Blocks, 4
	}
	in := a.AsSlice()
	for _, b := range blocks {
		if !b.p.Contains(a) {
			continue
		}
		switch b.kind {
		case blockKept:
			return a
		case blockEmbed:
			b16 := a.As16()
			low := mapAddr(m, netip.AddrFrom4([4]byte(b16[12:]))).As4()
			copy(b16[12:], low[:])
			return netip.AddrFrom16(b16)
		default:
			return fromSlice(flipFrom(m, fam, in, b.p.Bits()))
		}
	}
	// Public: bits 0..keep-1 are those where the prefix so far is a proper
	// ancestor of some block, i.e. keep = max over blocks of common+1 (a
	// public address shares fewer than the block's length bits with it).
	keep := 0
	for _, b := range blocks {
		if c := commonPrefix(in, b.p.Addr().AsSlice()) + 1; c > keep {
			keep = c
		}
	}
	return fromSlice(flipFrom(m, fam, in, keep))
}

func fromSlice(b []byte) netip.Addr {
	a, _ := netip.AddrFromSlice(b)
	return a
}

func commonPrefix(x, y []byte) int {
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
		break
	}
	return n
}

// flipFrom flips each bit i >= from of in by the PRF of the first i input bits.
func flipFrom(m hash.Hash, fam byte, in []byte, from int) []byte {
	out := append([]byte(nil), in...)
	buf := make([]byte, 2+len(in))
	var sum [sha256.Size]byte
	for i := from; i < len(in)*8; i++ {
		n := (i + 7) / 8
		buf[0], buf[1] = fam, byte(i)
		copy(buf[2:2+n], in[:n])
		if r := i % 8; r != 0 {
			buf[1+n] &= byte(0xff << (8 - r))
		}
		m.Reset()
		m.Write(buf[:2+n])
		if m.Sum(sum[:0])[0]&1 == 1 {
			out[i/8] ^= 1 << (7 - i%8)
		}
	}
	return out
}

var transports = []string{"udp6:", "tcp6:", "udp:", "tcp:"}

// AddrToken maps every address in s when s as a whole is one §1.1 form: an
// address (a zone kept), a CIDR, an IPv4 address with a dotted netmask,
// addr:port, [v6]:port, any of those after a transport prefix (udp:, tcp:,
// udp6:, tcp6:), a range a-b, or an nft set { a, b } of addresses, CIDRs and
// ranges with its separators kept. It reports false, and "", when s is none of
// them; the empty string maps to itself (AX-4).
func (k *Key) AddrToken(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	if strings.HasPrefix(s, "{") {
		return k.set(s)
	}
	for _, t := range transports {
		if rest, ok := strings.CutPrefix(s, t); ok {
			out, ok := k.hostPort(rest)
			if !ok {
				return "", false
			}
			return t + out, true
		}
	}
	return k.hostPort(s)
}

func (k *Key) set(s string) (string, bool) {
	inner, ok := strings.CutSuffix(s[1:], "}")
	if !ok {
		return "", false
	}
	parts := strings.Split(inner, ",")
	for i, part := range parts {
		core := strings.Trim(part, " \t")
		if core == "" {
			return "", false
		}
		out, ok := k.element(core)
		if !ok {
			return "", false
		}
		lead := strings.Index(part, core)
		parts[i] = part[:lead] + out + part[lead+len(core):]
	}
	return "{" + strings.Join(parts, ",") + "}", true
}

// hostPort: an element, [v6]:port, or IPv4:port.
func (k *Key) hostPort(s string) (string, bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", false
		}
		a, ok := parseAddr(s[1:end])
		if !ok || !a.Is6() {
			return "", false
		}
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") || !validPort(rest[1:]) {
			return "", false
		}
		return "[" + k.Addr(a).String() + "]" + rest, true
	}
	if out, ok := k.element(s); ok {
		return out, true
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 || !validPort(s[i+1:]) {
		return "", false
	}
	a, ok := parseAddr(s[:i])
	if !ok || !a.Is4() {
		return "", false
	}
	return k.Addr(a).String() + s[i:], true
}

// element: an address, a CIDR, an IPv4 address with a dotted netmask, or a
// range of two unzoned addresses of one family.
func (k *Key) element(s string) (string, bool) {
	if a, ok := parseAddr(s); ok {
		return k.Addr(a).String(), true
	}
	if l, r, ok := strings.Cut(s, "/"); ok {
		if p, err := netip.ParsePrefix(s); err == nil {
			return k.Prefix(p).String(), true
		}
		a, err1 := netip.ParseAddr(l)
		m, err2 := netip.ParseAddr(r)
		if err1 != nil || err2 != nil || !a.Is4() || !m.Is4() || !contiguous(m.As4()) {
			return "", false
		}
		return k.Addr(a).String() + "/" + r, true
	}
	if l, r, ok := strings.Cut(s, "-"); ok {
		a, ok1 := parseAddr(l)
		b, ok2 := parseAddr(r)
		if !ok1 || !ok2 || a.Zone() != "" || b.Zone() != "" || a.BitLen() != b.BitLen() {
			return "", false
		}
		return k.Addr(a).String() + "-" + k.Addr(b).String(), true
	}
	return "", false
}

// parseAddr parses an address whose zone, if any, is an interface name.
func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, c := range a.Zone() {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '@' || c == '-') {
			return netip.Addr{}, false
		}
	}
	return a, true
}

func validPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n <= 65535
}

func contiguous(m [4]byte) bool {
	v := uint32(m[0])<<24 | uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
	inv := ^v
	return inv&(inv+1) == 0
}
