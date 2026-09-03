//go:build linux

package collectors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// POSIX ACL xattr encoding (fs/posix_acl.c): a 4-byte little-endian version
// (2) followed by 8-byte entries {tag u16, perm u16, id u32}.
const (
	aclVersion   = 2
	aclUserObj   = 0x01
	aclUser      = 0x02
	aclGroupObj  = 0x04
	aclGroup     = 0x08
	aclMask      = 0x10
	aclOther     = 0x20
	aclXattrName = "system.posix_acl_access"
)

// decodeACL renders an access ACL as setfacl-style entries in file order.
// Named users and groups are rendered by numeric id, never resolved, so the
// snapshot carries no name lookup the check side could not reproduce.
func decodeACL(b []byte) ([]string, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("acl: %d bytes is not a header plus whole entries", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != aclVersion {
		return nil, fmt.Errorf("acl: version %d, want %d", v, aclVersion)
	}
	out := make([]string, 0, (len(b)-4)/8)
	for off := 4; off < len(b); off += 8 {
		tag := binary.LittleEndian.Uint16(b[off:])
		perm := binary.LittleEndian.Uint16(b[off+2:])
		id := binary.LittleEndian.Uint32(b[off+4:])
		var entry string
		switch tag {
		case aclUserObj:
			entry = "user::"
		case aclUser:
			entry = "user:" + strconv.FormatUint(uint64(id), 10) + ":"
		case aclGroupObj:
			entry = "group::"
		case aclGroup:
			entry = "group:" + strconv.FormatUint(uint64(id), 10) + ":"
		case aclMask:
			entry = "mask::"
		case aclOther:
			entry = "other::"
		default:
			return nil, fmt.Errorf("acl: unknown tag 0x%x", tag)
		}
		out = append(out, entry+rwx(perm))
	}
	return out, nil
}

func rwx(perm uint16) string {
	s := []byte("---")
	if perm&4 != 0 {
		s[0] = 'r'
	}
	if perm&2 != 0 {
		s[1] = 'w'
	}
	if perm&1 != 0 {
		s[2] = 'x'
	}
	return string(s)
}

// aclEntries lists p's access ACL. present is false when the attribute is
// not set or the filesystem has no xattr support; any other failure
// propagates so the fact becomes denied or error rather than a confident
// "no ACL".
func aclEntries(a collect.Access, p string) ([]string, bool, error) {
	names, err := a.Llistxattr(p)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		return nil, false, err
	}
	found := false
	for _, n := range names {
		if n == aclXattrName {
			found = true
			break
		}
	}
	if !found {
		return nil, false, nil
	}
	raw, err := a.Getxattr(p, aclXattrName)
	if err != nil {
		if errors.Is(err, unix.ENODATA) {
			return nil, false, nil
		}
		return nil, false, err
	}
	entries, err := decodeACL(raw)
	if err != nil {
		return nil, true, err
	}
	return entries, true, nil
}
