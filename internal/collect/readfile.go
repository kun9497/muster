//go:build linux

package collect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrNotRegular = errors.New("not a regular file")
	ErrSymlink    = errors.New("symbolic link in path")
)

const openFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

// forceComponentwise skips tier 1 (openat2) so tests can exercise tier 2's
// component-wise walk directly (R49); production code never sets it.
var forceComponentwise bool

// openNoFollow opens path without following a symlink in any component
// (spec §8 "Reads"): tier 1 openat2 with RESOLVE_NO_SYMLINKS, tier 2 a
// component-wise walk with O_NOFOLLOW. Returns the fd and the tier used.
func openNoFollow(p string, flags int) (int, string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return -1, "", fmt.Errorf("path %q must be absolute and clean", p)
	}
	if !forceComponentwise {
		how := unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
		fd, err := unix.Openat2(unix.AT_FDCWD, p, &how)
		switch {
		case err == nil:
			return fd, "openat2", nil
		case errors.Is(err, unix.ELOOP):
			return -1, "openat2", fmt.Errorf("%s: %w", p, ErrSymlink)
		case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM), errors.Is(err, unix.EINVAL):
			// kernel without openat2, or a seccomp profile that rejects it: tier 2
		default:
			return -1, "openat2", err
		}
	}
	return openComponentwise(p, flags)
}

// openComponentwise is tier 2. R49: opening an intermediate component with
// O_PATH|O_NOFOLLOW does not ELOOP on a symlink — it returns an fd referring
// to the link itself — so every intermediate fd is fstat'd here: S_IFLNK is
// ErrSymlink, any other non-directory is ENOTDIR, giving tier 2 the same
// guarantee as tier 1 before we ever descend into it.
//
// p == "/" is handled separately: splitting it the normal way yields a
// single empty component, and opening "" relative to a directory fd is
// ENOENT, not the ErrNotRegular that tier 1 gives for the same input (open
// succeeds, fstat then finds a directory). Opening "/" directly with the
// caller's flags keeps both tiers agreeing.
func openComponentwise(p string, flags int) (int, string, error) {
	if p == "/" {
		fd, err := unix.Open("/", flags, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return -1, "componentwise", fmt.Errorf("%s: %w", p, ErrSymlink)
			}
			return -1, "componentwise", err
		}
		return fd, "componentwise", nil
	}
	dir, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "componentwise", err
	}
	comps := strings.Split(strings.Trim(p, "/"), "/")
	for i, c := range comps {
		last := i == len(comps)-1
		f := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			f = flags
		}
		next, err := unix.Openat(dir, c, f, 0)
		unix.Close(dir)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return -1, "componentwise", fmt.Errorf("%s: %w", p, ErrSymlink)
			}
			return -1, "componentwise", err
		}
		if !last {
			var st unix.Stat_t
			if err := unix.Fstat(next, &st); err != nil {
				unix.Close(next)
				return -1, "componentwise", err
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				unix.Close(next)
				return -1, "componentwise", fmt.Errorf("%s: %w", p, ErrSymlink)
			case unix.S_IFDIR:
				// directory: continue the walk
			default:
				unix.Close(next)
				return -1, "componentwise", fmt.Errorf("%s: %w", p, unix.ENOTDIR)
			}
		}
		dir = next
	}
	return dir, "componentwise", nil
}

// ReadFile reads a regular file with a size cap. A symlink anywhere in the
// path, a FIFO, device or socket, or a relative path is an error; a file
// over the limit is returned truncated and flagged; a NUL byte marks the
// file binary and its content is not returned.
func ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	if limit < 0 {
		return nil, ReadMeta{}, fmt.Errorf("%s: limit must be >= 0, got %d", p, limit)
	}
	fd, tier, err := openNoFollow(p, openFlags)
	meta := ReadMeta{Tier: tier}
	if err != nil {
		return nil, meta, err
	}
	// os.NewFile takes ownership of fd; from here on defer f.Close() is the
	// only close of it (never both unix.Close(fd) and f.Close()).
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, meta, err
	}
	fillMeta(&meta, &st)
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, meta, fmt.Errorf("%s: %w", p, ErrNotRegular)
	}
	meta.ParentUntrusted = parentUntrusted(p)
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, meta, err
	}
	if int64(len(data)) > limit {
		data = data[:limit]
		meta.Truncated = true
	}
	if bytes.IndexByte(data, 0) >= 0 {
		meta.Binary = true
		return nil, meta, nil
	}
	return data, meta, nil
}

// Stat resolves like ReadFile but only stats the final component; a final
// symlink is ErrSymlink, never followed. Kind and Rdev are filled for any
// file type before that check, so Kind == "symlink" is only ever seen
// alongside the ErrSymlink return, never on a nil-error result.
func Stat(p string) (ReadMeta, error) {
	fd, tier, err := openNoFollow(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	meta := ReadMeta{Tier: tier}
	if err != nil {
		return meta, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return meta, err
	}
	fillMeta(&meta, &st)
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return meta, fmt.Errorf("%s: %w", p, ErrSymlink)
	}
	meta.ParentUntrusted = parentUntrusted(p)
	return meta, nil
}

func fillMeta(m *ReadMeta, st *unix.Stat_t) {
	m.Size = st.Size
	m.Mode = uint32(st.Mode & 0o7777)
	m.UID, m.GID = st.Uid, st.Gid
	m.Kind = kindOf(st.Mode)
	m.Rdev = uint64(st.Rdev)
	// Timespec.Unix widens Sec/Nsec, which are 32-bit on some
	// architectures, so this is the portable spelling (Ruling I-27).
	sec, nsec := st.Mtim.Unix()
	m.ModTime = time.Unix(sec, nsec)
}

// kindOf names the S_IFMT file type so collectors never compare mode bits
// themselves.
func kindOf(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return "regular"
	case unix.S_IFDIR:
		return "dir"
	case unix.S_IFLNK:
		return "symlink"
	case unix.S_IFCHR:
		return "chardev"
	case unix.S_IFBLK:
		return "blockdev"
	case unix.S_IFIFO:
		return "fifo"
	case unix.S_IFSOCK:
		return "socket"
	}
	return "unknown"
}

// parentUntrusted reports whether p's parent directory is not root-owned or
// is group/world-writable. R68: the parent is resolved through the same
// no-follow primitive used for the read itself (openNoFollow, both tiers),
// not a second unix.Lstat call — an independent Lstat would re-resolve
// every ancestor component and could be raced by a symlink an attacker
// swaps in between the two resolutions, letting a world-writable parent
// report ParentUntrusted=false. Any error resolving the parent (including
// a symlink ancestor — already refused by the read itself) is untrusted.
func parentUntrusted(p string) bool {
	fd, _, err := openNoFollow(path.Dir(p), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return true
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return true
	}
	return st.Uid != 0 || st.Mode&(unix.S_IWOTH|unix.S_IWGRP) != 0
}

// DeniedReason turns a permission error into the reason a denied fact
// carries (spec §7.1). R42: classify via errors.Is against the fs sentinel
// (satisfied both by a raw syscall.Errno, whose Is method matches EACCES
// and EPERM, and by an os/fs-wrapped error), not by comparing to
// unix.EACCES/unix.EPERM directly.
func DeniedReason(err error) (string, bool) {
	if errors.Is(err, fs.ErrPermission) {
		return "requires root or CAP_DAC_READ_SEARCH", true
	}
	return "", false
}
