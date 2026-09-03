//go:build linux

package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultSnapshotDir = "/var/lib/muster/snapshots"
	LockPath           = "/var/lib/muster/.lock"
)

// MinFreeBytes is the free-space floor WriteSnapshot requires beyond the
// snapshot's own size (spec §5.9). It is typed uint64, not left as an
// untyped constant, so the comparison against unix.Statfs_t's
// Bavail*Bsize (also uint64) is unambiguous at the call site.
const MinFreeBytes uint64 = 64 << 20

var (
	ErrExists       = errors.New("snapshot exists; use --force")
	ErrUntrustedDir = errors.New("output directory is a symlink or world-writable")
	ErrNoSpace      = errors.New("not enough free space for a snapshot")
	ErrLocked       = errors.New("another muster collect is running")
)

// SnapshotName is <host>-<utc time>-<short digest>.json (spec §5.9): the
// hostname sanitised to [A-Za-z0-9._-] (anything else becomes '_'), the
// collectedAt timestamp with ':' removed, and the first 12 hex characters
// of digest after its "sha256:" prefix.
//
// digest is expected to be the sha256 of the exact bytes being written to
// disk (WriteSnapshot computes it that way via digestOf, over data as
// handed to it — not a re-parse). `check`'s reported snapshot_digest, by
// contrast, is computed over a canonical re-encoding of the parsed
// document it reads back. The two digests differ by design: this name's
// digest identifies the file as written, not the canonical form check
// later derives from it.
func SnapshotName(hostname, collectedAt, digest string) string {
	h := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, hostname)
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return fmt.Sprintf("%s-%s-%s.json", h, strings.ReplaceAll(collectedAt, ":", ""), d)
}

// digestOf is the sha256 of the exact bytes about to be written to disk;
// see SnapshotName's comment for why this is not the same value `check`
// later reports as snapshot_digest.
func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// WriteOptions selects the destination. R54: WriteSnapshot never reads the
// clock or the hostname itself — when Out is empty, the generated name is
// built from Hostname and CollectedAt, which the caller supplies (the run
// header, Task 6, records CollectedAt once as RFC3339 UTC and reuses it
// everywhere, including here).
type WriteOptions struct {
	Out   string // "" = Dir + generated name; "-" = stdout; else a path
	Force bool
	Dir   string

	Hostname    string // used to build the generated name when Out == ""
	CollectedAt string // RFC3339 UTC; used to build the generated name when Out == ""
}

// trustedDir refuses a parent directory that is a symlink or world-writable
// (spec §5.9) — Lstat so a symlinked parent is caught rather than resolved.
func trustedDir(dir string) error {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK || st.Mode&unix.S_IWOTH != 0 {
		return ErrUntrustedDir
	}
	return nil
}

// WriteSnapshot writes data atomically with 0600 (spec §5.9, §7.1). The
// only file collect ever writes goes through here.
func WriteSnapshot(data []byte, o WriteOptions, stdout io.Writer) (string, error) {
	if o.Out == "-" {
		_, err := stdout.Write(data)
		return "-", err
	}
	dir, name := "", ""
	generated := o.Out == ""
	if generated {
		dir = o.Dir
		if dir == "" {
			dir = DefaultSnapshotDir
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		name = SnapshotName(o.Hostname, o.CollectedAt, digestOf(data))
	} else {
		dir, name = filepath.Split(o.Out)
		dir = filepath.Clean(dir)
	}
	if err := trustedDir(dir); err != nil {
		return "", err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err == nil {
		if free := uint64(fs.Bavail) * uint64(fs.Bsize); free < MinFreeBytes+uint64(len(data)) {
			return "", ErrNoSpace
		}
	}
	final := filepath.Join(dir, name)
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d", name, os.Getpid()))
	fd, err := unix.Open(tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := finalizeRename(tmp, final, o.Force); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if generated {
		latestTmp := filepath.Join(dir, fmt.Sprintf(".latest.tmp-%d", os.Getpid()))
		os.Remove(latestTmp)
		if err := os.Symlink(name, latestTmp); err == nil {
			os.Rename(latestTmp, filepath.Join(dir, "latest"))
		}
	}
	return final, nil
}

// finalizeRename places tmp at final (R62). When Force is false it uses
// Renameat2 with RENAME_NOREPLACE: the existence check and the placement
// are one atomic kernel operation, so there is no window between "check
// final doesn't exist" and "rename onto it" for a second collect (or an
// attacker) to race — unlike a separate Lstat-then-Rename, which is
// exactly that race. On a filesystem whose kernel or overlay doesn't
// support RENAME_NOREPLACE (EINVAL/ENOSYS/ENOTSUP) it falls back to
// Lstat-then-Rename, accepting that narrower race only where the atomic
// path is unavailable. Force always overwrites unconditionally, matching
// the brief's "--force" contract.
func finalizeRename(tmp, final string, force bool) error {
	if force {
		return os.Rename(tmp, final)
	}
	err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, final, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST):
		return ErrExists
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP):
		if _, statErr := os.Lstat(final); statErr == nil {
			return ErrExists
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		return os.Rename(tmp, final)
	default:
		return err
	}
}

// Lock is the flock that keeps two muster collects from interleaving.
// AcquireLock (the default lock file) and AcquireDirLock (an explicit
// --out directory, R73) both return one, and Release works identically
// for either.
type Lock struct{ fd int }

// AcquireLock takes an exclusive, non-blocking lock on the lock file at
// path and records the holder.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := make([]byte, 128)
		n, _ := unix.Pread(fd, holder, 0)
		if n < 0 {
			// R62: never trust a syscall wrapper's count enough to slice on
			// it unchecked — treat a negative n (which Pread should never
			// actually return, but nothing guarantees it across every
			// kernel/libc combination) as "no holder text" rather than
			// panicking on holder[:n].
			n = 0
		}
		unix.Close(fd)
		return nil, fmt.Errorf("%w (holder: pid %s)", ErrLocked, strings.TrimSpace(string(holder[:n])))
	}
	unix.Ftruncate(fd, 0)
	unix.Pwrite(fd, []byte(fmt.Sprintf("%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))), 0)
	return &Lock{fd: fd}, nil
}

// AcquireDirLock takes an exclusive, non-blocking flock on dir itself
// rather than on a lock file inside it (R73): Task 6 uses this for
// `--out <path>` runs, where muster has no business creating a lock file
// inside a directory it doesn't own. There is nowhere to record holder
// text without writing into that directory, so on EWOULDBLOCK the error
// just names dir; any other Open/Flock error is returned as-is rather than
// folded into ErrLocked.
func AcquireDirLock(dir string) (*Lock, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, dir)
		}
		return nil, err
	}
	return &Lock{fd: fd}, nil
}

// Release drops the lock. It only flocks LOCK_UN and closes the fd — never
// writes or unlinks anything — so the same implementation is correct for a
// lock file (AcquireLock) and a directory (AcquireDirLock) alike (R73).
func (l *Lock) Release() {
	if l != nil && l.fd >= 0 {
		unix.Flock(l.fd, unix.LOCK_UN)
		unix.Close(l.fd)
		l.fd = -1
	}
}
