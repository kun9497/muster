package collectors

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// File capabilities (P-3, V-3). This file has no build tag: it decodes bytes
// and renders text, touches nothing, and is tested on every platform.
//
// A capability set is carried as the triple the kernel stores — permitted,
// inheritable and the single effective flag — plus the namespace root of a
// revision-3 attribute. Every comparison muster makes between a declaration
// and a file is triple to triple after parsing, never string to string: the
// two libcap spellings of one set (`cap_net_raw=ep` and `= cap_net_raw+ep`)
// are one set.
type capSet struct {
	Permitted, Inheritable uint64
	Effective              bool
	RootID                 uint32
	Version                int
}

// capNames are the capability names by bit, 0 through 40 (the kernel's
// include/uapi/linux/capability.h up to CAP_CHECKPOINT_RESTORE). The count is
// fixed rather than read from the running kernel so the text one file renders
// to does not depend on which host rendered it; a higher bit is spelled as
// its number, as libcap spells a bit it has no name for.
var capNames = [41]string{"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice", "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod", "cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap", "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm", "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf", "cap_checkpoint_restore"}

const (
	capNamedBits = len(capNames)
	capMaxBits   = 64 // two 32-bit words, the most the attribute can carry

	vfsCapRevisionMask = 0xFF000000
	vfsCapEffective    = 0x000001
	vfsCapRevision1    = 0x01000000
	vfsCapRevision2    = 0x02000000
	vfsCapRevision3    = 0x03000000
)

// decodeVfsCap decodes a security.capability attribute (the kernel's
// struct vfs_cap_data / vfs_ns_cap_data, every field little-endian whatever
// the host's byte order). The size must be exactly the one the revision
// names — 12, 20 or 24 bytes — because the kernel refuses any other, and an
// attribute the kernel would refuse is not a capability the file has.
func decodeVfsCap(b []byte) (capSet, error) {
	if len(b) < 4 {
		return capSet{}, fmt.Errorf("capability attribute of %d bytes", len(b))
	}
	magic := binary.LittleEndian.Uint32(b)
	var c capSet
	var want int
	switch magic & vfsCapRevisionMask {
	case vfsCapRevision1:
		c.Version, want = 1, 12
	case vfsCapRevision2:
		c.Version, want = 2, 20
	case vfsCapRevision3:
		c.Version, want = 3, 24
	default:
		return capSet{}, fmt.Errorf("capability attribute revision 0x%08x", magic&vfsCapRevisionMask)
	}
	if len(b) != want {
		return capSet{}, fmt.Errorf("capability attribute revision %d of %d bytes, want %d", c.Version, len(b), want)
	}
	c.Effective = magic&vfsCapEffective != 0
	c.Permitted = uint64(binary.LittleEndian.Uint32(b[4:]))
	c.Inheritable = uint64(binary.LittleEndian.Uint32(b[8:]))
	if c.Version >= 2 {
		c.Permitted |= uint64(binary.LittleEndian.Uint32(b[12:])) << 32
		c.Inheritable |= uint64(binary.LittleEndian.Uint32(b[16:])) << 32
	}
	if c.Version == 3 {
		c.RootID = binary.LittleEndian.Uint32(b[20:])
	}
	return c, nil
}

// sameCaps compares two sets the way the kernel applies them: the permitted
// and inheritable masks and the effective flag — which raises nothing when
// both masks are empty, so an empty set with the flag is the empty set. The
// namespace root is not part of a declaration — no package text can name
// one.
func sameCaps(x, y capSet) bool {
	return x.Permitted == y.Permitted && x.Inheritable == y.Inheritable && x.raises() == y.raises()
}

func (c capSet) raises() bool { return c.Effective && c.Permitted|c.Inheritable != 0 }

// The state of one capability, as libcap's cap_to_text groups them:
// effective 1, permitted 2, inheritable 4.
const (
	capStE = 1
	capStP = 2
	capStI = 4
)

// capState is one bit's state. With the effective flag on, the file's
// effective set is its permitted and inheritable sets together (libcap
// reads a file's attribute that way), so a bit in either is effective too.
func capState(c capSet, n int) int {
	bit := uint64(1) << uint(n)
	t := 0
	if c.Permitted&bit != 0 {
		t |= capStP
	}
	if c.Inheritable&bit != 0 {
		t |= capStI
	}
	if c.Effective && t != 0 {
		t |= capStE
	}
	return t
}

// capLetters spells a state in libcap's fixed order: e, i, p.
func capLetters(t int) string {
	var s strings.Builder
	if t&capStE != 0 {
		s.WriteByte('e')
	}
	if t&capStI != 0 {
		s.WriteByte('i')
	}
	if t&capStP != 0 {
		s.WriteByte('p')
	}
	return s.String()
}

// capText renders a set as cap_to_text(3) does in libcap 2.41 and later, the
// form getcap prints and rpm stores: the most common state over the named
// bits is the default (ties go to the lower state, so "nothing" wins a tie),
// written first as "=" and its letters; then, from the highest state down,
// each other state's names with the operator that moves them from the
// default — and when the default is nothing, the first group drops the
// leading "=" and takes "=" as its operator ("cap_net_raw=ep"). Bits past
// the named ones are appended by number with "+". An empty set is "=".
func capText(c capSet) string {
	var histo [8]int
	for n := 0; n < capNamedBits; n++ {
		histo[capState(c, n)]++
	}
	m := 7
	for t := 6; t >= 0; t-- {
		if histo[t] >= histo[m] {
			m = t
		}
	}
	buf := "=" + capLetters(m)
	for t := 7; t >= 0; t-- {
		if t == m || histo[t] == 0 {
			continue
		}
		var names []string
		for n := 0; n < capNamedBits; n++ {
			if capState(c, n) == t {
				names = append(names, capNames[n])
			}
		}
		joined := strings.Join(names, ",")
		raise := t &^ m
		if raise != 0 && buf == "=" {
			// The default is nothing and this is the first group.
			buf = joined + "=" + capLetters(raise)
		} else {
			buf += " " + joined
			if raise != 0 {
				buf += "+" + capLetters(raise)
			}
		}
		if lower := m &^ t; lower != 0 {
			buf += "-" + capLetters(lower)
		}
	}
	for t := 7; t > 0; t-- {
		var nums []string
		for n := capNamedBits; n < capMaxBits; n++ {
			if capState(c, n) == t {
				nums = append(nums, strconv.Itoa(n))
			}
		}
		if len(nums) != 0 {
			buf += " " + strings.Join(nums, ",") + "+" + capLetters(t)
		}
	}
	return buf
}

// parseCapText reads a capability text in the grammar of cap_from_text(3)
// (cap_text_formats(7)), which covers both libcap spellings and whatever a
// maintainer script hands setcap: whitespace-separated clauses, each a
// comma-separated list of names (case-insensitive), numbers or "all",
// followed by one or more operator/flag pairs applied left to right to a set
// that starts empty. "=" first clears the listed capabilities and then
// raises the flags that follow (none is allowed, and "=" with no list means
// all); "+" and "-" need a list and at least one flag; "=+" and "=-" clear
// and then raise or lower. The result's effective flag is "any effective
// bit", which is how libcap writes a file's attribute.
func parseCapText(s string) (capSet, error) {
	var e, p, i uint64
	clauses := strings.Fields(s)
	if len(clauses) == 0 {
		return capSet{}, fmt.Errorf("empty capability text")
	}
	for _, cl := range clauses {
		at := strings.IndexAny(cl, "=+-")
		if at < 0 {
			return capSet{}, fmt.Errorf("capability clause %q has no operator", cl)
		}
		var list uint64
		if at == 0 {
			if cl[0] != '=' {
				return capSet{}, fmt.Errorf("capability clause %q: %q needs a list", cl, cl[0])
			}
			list = namedMask()
		} else {
			var err error
			if list, err = capList(cl[:at]); err != nil {
				return capSet{}, err
			}
		}
		rest := cl[at:]
		for rest != "" {
			op := rest[0]
			if op != '=' && op != '+' && op != '-' {
				return capSet{}, fmt.Errorf("capability clause %q: unexpected %q", cl, op)
			}
			rest = rest[1:]
			if op == '=' {
				e, p, i = e&^list, p&^list, i&^list
				if rest != "" && (rest[0] == '+' || rest[0] == '-') {
					op = rest[0]
					rest = rest[1:]
				}
			}
			flags := 0
			for rest != "" && strings.IndexByte("eip", rest[0]) >= 0 {
				switch rest[0] {
				case 'e':
					flags |= capStE
				case 'i':
					flags |= capStI
				case 'p':
					flags |= capStP
				}
				rest = rest[1:]
			}
			if flags == 0 && op != '=' {
				return capSet{}, fmt.Errorf("capability clause %q: %q needs a flag", cl, op)
			}
			for _, s := range []struct {
				set  *uint64
				flag int
			}{{&e, capStE}, {&p, capStP}, {&i, capStI}} {
				switch {
				case flags&s.flag == 0:
				case op == '-':
					*s.set &^= list
				default:
					*s.set |= list
				}
			}
		}
	}
	return capSet{Permitted: p, Inheritable: i, Effective: e != 0}, nil
}

// namedMask is "all": every named bit, as libcap bounds "all" by the names
// it knows.
func namedMask() uint64 { return uint64(1)<<capNamedBits - 1 }

// capList reads a clause's comma-separated capability list.
func capList(s string) (uint64, error) {
	var mask uint64
	for _, name := range strings.Split(s, ",") {
		n, err := capIndex(name)
		if err != nil {
			return 0, err
		}
		if n < 0 {
			mask |= namedMask()
			continue
		}
		mask |= uint64(1) << uint(n)
	}
	return mask, nil
}

// capIndex is one list element's bit, or -1 for "all". A name is matched
// whole and without regard to case; a number is read as strtoul(3) base 0
// reads it and must fit the attribute's 64 bits.
func capIndex(name string) (int, error) {
	lower := strings.ToLower(name)
	if lower == "all" {
		return -1, nil
	}
	for n, known := range capNames {
		if lower == known {
			return n, nil
		}
	}
	if v, err := strconv.ParseUint(name, 0, 8); err == nil && v < capMaxBits {
		return int(v), nil
	}
	return 0, fmt.Errorf("unknown capability %q", name)
}
