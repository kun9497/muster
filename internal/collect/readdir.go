//go:build linux

package collect

import (
	"errors"
	"fmt"
	"path"
	"sort"

	"golang.org/x/sys/unix"
)

// Identity is the (device, inode) pair that names one directory. The walk
// carries it from the listing that produced a child to the call that opens
// that child, so a directory swapped underneath the traversal is caught
// rather than descended into (ErrVanished).
type Identity struct{ Dev, Ino uint64 }

// DirEntry is one name in a listing, stat'ed without following a symlink.
// It is deliberately not a ReadMeta: the walk judges ownership, mode and
// file type over millions of entries and never reads content, so it carries
// only what the walk's rules need, plus the mount identity that decides a
// boundary.
//
// Mode is the 0o7777 permission bits alone (setuid, setgid, sticky and the
// nine rwx bits); the file type lives in Kind, named by kindOf. MntID is
// only meaningful when MntIDKnown — STATX_MNT_ID arrived in Linux 5.8, and
// an older kernel simply leaves the mask bit clear rather than failing.
type DirEntry struct {
	Name string
	Kind string
	Mode uint32
	UID  uint32
	GID  uint32

	Dev uint64
	Ino uint64

	MntID      uint64
	MntIDKnown bool

	Size int64

	Caps     []byte // security.capability, nil when absent or not asked for
	ACL      []byte // system.posix_acl_access, nil when absent or not asked for
	XattrErr error  // the open/fstat/fgetxattr failure for this entry, nil when none; wraps the errno or ErrVanished
}

// ReadDirOptions says what a listing reads beyond the stat of each entry.
//
// Xattrs: read Caps/ACL of every regular entry with an execute bit. Each such
// entry is opened relative to the listed directory (never following a
// symlink, never blocking, never acquiring a terminal), checked to still be
// the regular file statx reported, and its security.capability and
// system.posix_acl_access read from that fd. A failure is the entry's
// XattrErr, never the listing's: one unreadable executable must not cost
// the walk the directory it sits in.
type ReadDirOptions struct{ Xattrs bool } // Xattrs: read Caps/ACL of every regular entry with an execute bit

// Listing is one directory: the directory itself (Self, whose Name is
// always empty — it is not one of its own entries) and its children sorted
// by Name, with "." and ".." dropped. Sorting here rather than at each call
// site is what makes a walk of the same tree produce the same bytes twice.
type Listing struct {
	Self    DirEntry
	Entries []DirEntry
}

// The two attributes ReadDirOptions.Xattrs reads from each executable: its
// file capabilities and its POSIX access ACL.
var xattrCapability = "security.capability"
var xattrACLAccess = "system.posix_acl_access"

// ErrVanished means the directory that was opened is not the one the
// listing named: its (dev, ino) no longer matches the Identity the caller
// expected. It is the walk's answer to a directory replaced between being
// listed and being descended into, and it is not an error about the host —
// the traversal records it and moves on.
var ErrVanished = errors.New("directory changed between listing and opening")

// ErrNoWalk is what an Access that does not implement the walk answers to
// ReadDir and Readlink.
var ErrNoWalk = errors.New("this Access does not implement the walk")

// NoWalkAccess gives the two walk methods to an Access that has no business
// answering them. Every test double in this repository that is not itself
// exercising the walk embeds it — fakeAccess and recordingWalkAccess's base
// in registry_test.go, quietAccess (and through it capAccess) in
// run_test.go, fsAccess in the collectors' tests — so adding a method to
// Access does not mean hand-writing a stub in each of them, and a double
// that is asked to list a directory says so plainly instead of answering
// with a silently empty listing.
type NoWalkAccess struct{}

func (NoWalkAccess) ReadDir(string, Identity, ReadDirOptions) (Listing, error) {
	return Listing{}, ErrNoWalk
}

func (NoWalkAccess) Readlink(string) (string, error) { return "", ErrNoWalk }

// ReadDir lists one directory without following a symlink in any component
// of p and without following any entry: the directory is opened through the
// same no-follow primitive every other read goes through (openNoFollow,
// both tiers), and each name is stat'ed relative to that one fd, so nothing
// between opening and stat'ing can be redirected by a path the kernel
// re-resolves.
//
// expect, when non-zero, is the identity the caller believes this path has
// — the (dev, ino) the parent's listing reported. A mismatch is ErrVanished
// and no listing at all: the walk must never report facts about a directory
// it did not mean to be in. A zero expect skips the check, which is how a
// root is listed.
//
// An entry that disappears between getdents and statx is skipped rather
// than failing the directory: on a live host that is ordinary churn, and
// the alternative would be to lose the whole listing over one temporary
// file. Any other statx failure fails the listing, named by the entry it
// happened on.
//
// opts.Xattrs adds the attributes of every regular entry with an execute
// bit (readEntryXattrs); a failure there is that entry's XattrErr and
// never fails the listing.
func (hostAccess) ReadDir(p string, expect Identity, opts ReadDirOptions) (Listing, error) {
	fd, err := openDirNoFollow(rewriteProcSelf(p), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return Listing{}, err
	}
	defer unix.Close(fd)
	self, err := statxAt(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
	if err != nil {
		return Listing{}, fmt.Errorf("%s: %w", p, err)
	}
	if expect != (Identity{}) && (self.Dev != expect.Dev || self.Ino != expect.Ino) {
		return Listing{}, fmt.Errorf("%s: %w", p, ErrVanished)
	}
	names, err := readNames(fd)
	if err != nil {
		return Listing{}, fmt.Errorf("%s: %w", p, err)
	}
	sort.Strings(names)
	out := Listing{Self: self}
	for _, n := range names {
		e, err := statEntry(fd, n, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return Listing{}, fmt.Errorf("%s/%s: %w", p, n, err)
		}
		e.Name = n
		if opts.Xattrs && e.Kind == "regular" && e.Mode&0o111 != 0 {
			readEntryXattrs(fd, &e)
		}
		out.Entries = append(out.Entries, e)
	}
	return out, nil
}

// readEntryXattrs reads the capability and access-ACL attributes of the
// listed entry e, relative to the listing's own directory fd, and records
// them (or the failure) on e. The caller has already decided e is a regular
// file with an execute bit, from the statx the listing made.
//
// The open is O_NOFOLLOW (a symlink put in the file's place is ELOOP, never
// followed), O_NONBLOCK and O_NOCTTY (a FIFO or tty put in its place can
// neither block the walk nor become its controlling terminal) and
// O_RDONLY, which is all fgetxattr needs. The fd is then fstat'ed: an
// object that is not a regular file, or not the (dev, ino) statx reported,
// replaced the entry between the two calls, and its attributes would
// describe something the listing never saw — that is ErrVanished, and
// nothing is read (an object put in the entry's place between the calls
// is opened once — read-only, non-blocking, no controlling tty — before it
// is rejected; the check can only follow the open). statxAt stores Mkdev(major, minor), the same glibc dev_t
// encoding Stat_t.Dev carries, so the two compare directly.
//
// An attribute that is not set (ENODATA), or a filesystem that has no
// attributes of that namespace (EOPNOTSUPP), is nil with no error. Any other
// failure is XattrErr, the first one winning; the open's error is left
// unwrapped for the walk to classify.
func readEntryXattrs(dirfd int, e *DirEntry) {
	ofd, err := unix.Openat(dirfd, e.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		e.XattrErr = err
		return
	}
	defer unix.Close(ofd)
	var st unix.Stat_t
	if err := unix.Fstat(ofd, &st); err != nil {
		e.XattrErr = err
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Dev) != e.Dev || st.Ino != e.Ino {
		e.XattrErr = ErrVanished
		return
	}
	caps, cerr := fgetxattrOpt(ofd, xattrCapability)
	acl, aerr := fgetxattrOpt(ofd, xattrACLAccess)
	e.Caps, e.ACL = caps, acl
	if cerr != nil {
		e.XattrErr = cerr
	} else if aerr != nil {
		e.XattrErr = aerr
	}
}

// fgetxattrOpt reads one attribute of an open fd, sized from the attribute
// itself and re-sized once on ERANGE (the value grew between the two
// calls), as Getxattr does. An attribute that is not there, or a
// filesystem that does not support it, is nil with no error.
func fgetxattrOpt(fd int, name string) ([]byte, error) {
	v, err := fgetxattrSized(fd, name)
	if errors.Is(err, unix.ERANGE) {
		v, err = fgetxattrSized(fd, name)
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

func fgetxattrSized(fd int, name string) ([]byte, error) {
	size, err := unix.Fgetxattr(fd, name, nil)
	if err != nil {
		return nil, err
	}
	return readXattr(fd, name, size)
}

// openDirNoFollow opens p as a directory through openNoFollow and names a
// final-component symlink for what it is.
//
// O_DIRECTORY changes which refusal the kernel reports: openat2 with
// RESOLVE_NO_SYMLINKS answers ELOOP for a symlink at an INTERMEDIATE
// component, but ENOTDIR when the FINAL component is itself a symlink,
// because the "must be a directory" check fires before the trailing-symlink
// check (measured on the lab host, 5.15). Every other read in this package
// answers ErrSymlink for a final symlink, and a degraded walk fact should
// say "symbolic link in path" rather than "not a directory" for the same
// situation, so an ENOTDIR is re-examined here with a second
// O_PATH|O_NOFOLLOW open — exactly how Stat looks at a final component —
// and reported as ErrSymlink when that is what it was.
//
// The re-examination happens only on the error path: the path is already
// refused, and the second open can only change the NAME of the refusal,
// never turn one into a success. If it cannot tell (the entry went away, or
// the fstat failed) the original ENOTDIR stands.
func openDirNoFollow(p string, flags int) (int, error) {
	fd, _, err := openNoFollow(p, flags)
	if err == nil || !errors.Is(err, unix.ENOTDIR) {
		return fd, err
	}
	probe, _, perr := openNoFollow(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if perr != nil {
		return -1, err
	}
	defer unix.Close(probe)
	var st unix.Stat_t
	if ferr := unix.Fstat(probe, &st); ferr == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return -1, fmt.Errorf("%s: %w", p, ErrSymlink)
	}
	return -1, err
}

// readNames returns the entry names of an open directory fd, with "." and
// ".." dropped (unix.ParseDirent drops them). Getdents is called in a loop
// until it reports 0 bytes, since one call only fills the buffer it is
// given.
func readNames(fd int) ([]string, error) {
	buf := make([]byte, 64<<10)
	var names []string
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return names, nil
		}
		_, _, names = unix.ParseDirent(buf[:n], -1, names)
	}
}

// statEntry is the per-ENTRY stat ReadDir makes, as a variable so a test can
// stand in a failure the host will not produce on demand: the two branches
// that follow it — a name that vanished between getdents and statx is
// dropped, any other failure fails the whole listing — are otherwise only
// reachable by racing a live filesystem, which is not a test. Production
// never assigns it, and the directory's OWN stat deliberately still calls
// statxAt directly, so a test that scripts entry failures cannot
// accidentally break Self.
var statEntry = statxAt

// statxAt stats name relative to dirfd (or dirfd itself, with an empty name
// and AT_EMPTY_PATH) and renders the result as a DirEntry. STATX_MNT_ID is
// asked for alongside the basic stats; a kernel that does not know it
// leaves the bit clear in the returned mask, which is what MntIDKnown
// reports, so the walk can tell "not on this mount" from "cannot tell".
func statxAt(dirfd int, name string, flags int) (DirEntry, error) {
	var st unix.Statx_t
	if err := unix.Statx(dirfd, name, flags, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &st); err != nil {
		return DirEntry{}, err
	}
	return DirEntry{
		Kind:       kindOf(uint32(st.Mode)),
		Mode:       uint32(st.Mode) & 0o7777,
		UID:        st.Uid,
		GID:        st.Gid,
		Dev:        unix.Mkdev(st.Dev_major, st.Dev_minor),
		Ino:        st.Ino,
		MntID:      st.Mnt_id,
		MntIDKnown: st.Mask&unix.STATX_MNT_ID != 0,
		Size:       int64(st.Size),
	}, nil
}

// Readlink returns the target of the symlink at p, read with Readlinkat
// relative to p's parent directory — opened through openNoFollow, so a
// symlink anywhere ABOVE the final component is ErrSymlink rather than
// silently traversed. Only the final component is the link being read; its
// target is returned exactly as stored, relative or absolute, and is never
// resolved here.
//
// "/" has no final component to read and is refused along with a relative
// or unclean path, before anything is opened.
func (hostAccess) Readlink(p string) (string, error) {
	p = rewriteProcSelf(p)
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return "", fmt.Errorf("path %q must be absolute and clean", p)
	}
	dir, err := openDirNoFollow(path.Dir(p), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return "", err
	}
	defer unix.Close(dir)
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(dir, path.Base(p), buf)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	// Readlinkat does not NUL-terminate and does not report truncation: it
	// silently returns as much as fits. A target that exactly filled PATH_MAX
	// may therefore be short of its real value, and a truncated target is
	// worse than no target — it names a different file. Refuse it instead.
	if n == len(buf) {
		return "", fmt.Errorf("%s: symlink target too long (%d bytes or more)", p, n)
	}
	return string(buf[:n]), nil
}
