// Package collect gathers host facts as root and writes the snapshot
// (spec §4, §5, §8). Everything but this file is Linux-only: this one
// carries no build tag purely so the package still compiles elsewhere for
// `go build ./...` and `go vet ./...` on a developer's machine. There are
// deliberately no non-Linux stubs of the read primitive (R58/M7) — off
// Linux there is nothing to collect, the collect command says so in
// cmd/muster, and a stub that answered "not supported" would be a second
// place for that sentence to live and drift.
//
// /proc/self and other magic links are refused by both read-primitive
// tiers (RESOLVE_NO_MAGICLINKS on tier 1; tier 2 never resolves a magic
// link because it never resolves anything but plain directory entries).
// Collectors declare and request the "/proc/self/..." form; Access (Task 3)
// rewrites it to the real numeric pid immediately before calling the
// primitive, so collector code never builds /proc/<pid>/... itself.
package collect

// ReadMeta describes how a file was read and what it looked like.
type ReadMeta struct {
	Tier string // openat2 | componentwise

	// Size is the fstat size before the read: 0 on procfs, and possibly
	// stale for a file growing concurrently. Truncated is computed from
	// the bytes actually read, not from Size.
	Size int64

	Truncated bool
	Binary    bool

	// Mode is the raw POSIX permission bits (0o7777 mask: permissions
	// plus setuid/setgid/sticky) as fstat reported them. os.FileMode
	// cannot carry bits 9-11, so this is a plain uint32, not
	// os.FileMode; collectors store int(meta.Mode).
	Mode uint32

	// Kind is the file type from st_mode's S_IFMT bits: regular | dir |
	// symlink | chardev | blockdev | fifo | socket | unknown. Rdev is the raw
	// st_rdev, meaningful for chardev and blockdev only.
	Kind string
	Rdev uint64

	UID, GID        uint32
	ParentUntrusted bool
}
