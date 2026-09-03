// Package collect gathers host facts as root and writes the snapshot
// (spec §4, §5, §8). Everything but this file and collect_other.go is
// Linux-only.
package collect

import "os"

// ReadMeta describes how a file was read and what it looked like.
type ReadMeta struct {
	Tier            string // openat2 | componentwise
	Size            int64
	Truncated       bool
	Binary          bool
	Mode            os.FileMode
	UID, GID        uint32
	ParentUntrusted bool
}
