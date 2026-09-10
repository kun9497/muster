//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Access is the only way a collector touches the host. The real one wraps
// the read primitive and the exec discipline; tests substitute a double
// (R46/R60).
type Access interface {
	ReadFile(path string, limit int64) ([]byte, ReadMeta, error)
	Stat(path string) (ReadMeta, error)
	Glob(pattern string) ([]string, error)
	Llistxattr(path string) ([]string, error)

	// Getxattr returns the value of one extended attribute of path, read
	// through the same no-follow open Llistxattr uses. ENODATA and
	// EOPNOTSUPP propagate unchanged so the caller can classify them.
	Getxattr(path, name string) ([]byte, error)

	Run(ctx context.Context, c Command) Output

	// Writable is an environment probe — answers whether this process may
	// write here (read-only mounts, namespaces); for root that is true
	// unless the mount forbids it; not a permission-bit check.
	Writable(path string) bool
}

// Declaration is what a collector says it will read and run (spec §9
// --list-actions, §11 contract tests).
type Declaration struct {
	Reads    []string
	Commands []Command
	Needs    string // root | none
}

// Collector is one registered fact source.
type Collector struct {
	Name    string
	Declare Declaration
	Run     func(ctx context.Context, a Access, b *Builder) error
}

var registry = map[string]Collector{}

// Register adds a collector. A duplicate name, a Needs outside {root, none}
// and a nil Run are all programming errors caught here rather than at
// collection time.
func Register(c Collector) {
	if _, dup := registry[c.Name]; dup {
		panic("collector registered twice: " + c.Name)
	}
	if c.Declare.Needs != "root" && c.Declare.Needs != "none" {
		panic(fmt.Sprintf("collector %s: Needs must be %q or %q, got %q", c.Name, "root", "none", c.Declare.Needs))
	}
	if c.Run == nil {
		panic("collector " + c.Name + ": Run must not be nil")
	}
	registry[c.Name] = c
}

// All returns collectors sorted by name so runs are deterministic.
func All() []Collector {
	out := make([]Collector, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Reset clears the registry (tests only) and puts the built-ins back, so
// the default registry is never silently empty: the "muster"
// pseudo-collector reads /proc/self/status for the run header's privilege
// block (R60) and belongs to every run, not to whichever test registered
// last.
func Reset() {
	registry = map[string]Collector{}
	registerBuiltins()
}

// commandString renders a declared command the way both --list-actions and
// the run header's CollectorRun.Cmd show it, so the document a reviewer
// approves and the record of what ran cannot drift apart.
func commandString(c Command) string {
	return strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " "))
}

// rewriteProcSelf turns a declared "/proc/self/..." target into the real
// path for this process (R40): the read primitive refuses magic links
// outright (RESOLVE_NO_MAGICLINKS on tier 1; tier 2 never resolves anything
// but a plain directory entry, so it never even reaches the magic link), so
// hostAccess substitutes the numeric pid immediately before calling it. The
// guard still matches the DECLARED "/proc/self/..." form — collectors
// declare and request that form, never the rewritten one, and ListActions
// prints it unchanged.
func rewriteProcSelf(p string) string {
	const prefix = "/proc/self/"
	if strings.HasPrefix(p, prefix) {
		return "/proc/" + strconv.Itoa(os.Getpid()) + "/" + strings.TrimPrefix(p, prefix)
	}
	return p
}

// hostAccess is the production Access.
type hostAccess struct{}

// Host is the real host; collectors run against it under Guard. It is the
// only Access that touches this machine — everything else in a test is a
// double — so an out-of-package integration test names it here rather than
// re-implementing the read primitive, the /proc/self rewrite and the exec
// discipline it wraps (R77).
func Host() Access { return hostAccess{} }

func (hostAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	return ReadFile(rewriteProcSelf(p), limit)
}

func (hostAccess) Stat(p string) (ReadMeta, error) { return Stat(rewriteProcSelf(p)) }

// globDir is the literal directory a pattern lists: the longest leading part
// with no "*", "?" or "[", reduced to its parent when the segment that part
// ends in is the one holding the meta-character. The pattern is cleaned
// first, so a dynamic pattern carrying a trailing slash still names a
// directory. A pattern with no meta-character at all is its own answer —
// filepath.Glob then only stats that one path, and the probe below turns
// ENOTDIR into a fall-through.
func globDir(pattern string) string {
	p := path.Clean(pattern)
	i := strings.IndexAny(p, "*?[")
	if i < 0 {
		return p
	}
	return path.Dir(p[:i+1])
}

// Glob is filepath.Glob, with the directory it is about to list probed
// first (M-10). filepath.Glob discards the EACCES it gets from a directory
// this process may not search and answers with an empty list, so a non-root
// run reads "there is nothing there" where the honest answer is "we were
// not allowed to look" — a clean empty list is exactly what a control reads
// as a PASS. The probe opens the pattern's literal directory through the
// same no-follow primitive every other read goes through and returns the
// denial named by that directory; the wrapped Errno satisfies
// errors.Is(err, fs.ErrPermission), so each caller's FromReadError files it
// as denied without any of them learning a new error shape.
//
// ANY other probe outcome falls through to filepath.Glob unchanged —
// success, ENOENT, ENOTDIR, ErrSymlink, ELOOP, a relative or unclean
// pattern. In particular a match reached through a symlinked directory is
// still read through ReadFile/Stat afterward, and the read primitive
// refuses it there (ErrSymlink): Glob does not re-implement the no-follow
// walk itself, it only ever names candidates.
func (hostAccess) Glob(pattern string) ([]string, error) {
	dir := globDir(pattern)
	fd, _, err := openNoFollow(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	switch {
	case err == nil:
		unix.Close(fd)
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return filepath.Glob(pattern)
}

// Llistxattr lists a file's extended attributes without following a symlink
// in any path component. It opens the path through the same no-follow
// primitive ReadFile uses (openNoFollow with openFlags) and lists the
// already-open fd's attributes with Flistxattr — never unix.Llistxattr on
// the path, which resolves every component but the last and would defeat
// the guarantee this package exists to give.
func (hostAccess) Llistxattr(p string) ([]string, error) {
	fd, _, err := openNoFollow(rewriteProcSelf(p), openFlags)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Flistxattr(fd, buf)
	if err != nil {
		return nil, err
	}
	return splitXattrNames(buf[:n]), nil
}

// splitXattrNames splits the NUL-separated name list Flistxattr fills in.
func splitXattrNames(buf []byte) []string {
	var out []string
	for _, name := range strings.Split(strings.TrimRight(string(buf), "\x00"), "\x00") {
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// Getxattr returns the value of one extended attribute of p, opened through
// the same no-follow primitive Llistxattr uses. ENODATA/EOPNOTSUPP propagate
// unchanged so the caller (aclEntries) can tell "not set" from a real
// failure.
//
// M-11: the buffer is sized from the attribute itself — Fgetxattr with a nil
// destination returns the value's length — and allocated exactly, the way
// Llistxattr already sizes its name list, rather than reserving a flat
// 64 KiB for every ACL probe. The value can still grow between the two
// calls, which the kernel reports as ERANGE; that is re-sized once and read
// again, and a second ERANGE is returned to the caller as the error it is,
// never a silently truncated value.
func (hostAccess) Getxattr(p, name string) ([]byte, error) {
	fd, _, err := openNoFollow(rewriteProcSelf(p), openFlags)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	size, err := unix.Fgetxattr(fd, name, nil)
	if err != nil {
		return nil, err
	}
	v, err := readXattr(fd, name, size)
	if errors.Is(err, unix.ERANGE) {
		if size, err = unix.Fgetxattr(fd, name, nil); err != nil {
			return nil, err
		}
		v, err = readXattr(fd, name, size)
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// readXattr reads one attribute into a buffer of exactly size bytes. A zero
// size is an empty attribute: there is nothing to read, and a zero-length
// destination would make Fgetxattr a second sizing call rather than a read.
func readXattr(fd int, name string, size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Fgetxattr(fd, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Writable is an environment probe — answers whether this process may
// write here (read-only mounts, namespaces); for root that is true unless
// the mount forbids it; not a permission-bit check (R72). It goes through
// the same no-follow primitive as ReadFile/Stat rather than unix.Access,
// which accepts an unclean path and follows every symlink in it: probing
// "/etc/ssh/../login.defs" as writable must answer for /etc/login.defs
// itself, never for whatever /etc/ssh happens to resolve to. A relative or
// unclean path is refused outright, before anything is opened.
//
// The final component still needs its own check, the same way Stat does:
// opening it with O_PATH|O_NOFOLLOW succeeds and returns an fd referring to
// the symlink itself rather than ELOOPing (confirmed on the lab host — a
// symlink's own permission bits are typically 0777, so without this check
// Faccessat would report the link "writable" regardless of its target), so
// a final-component symlink is refused by fstat-ing the fd and rejecting
// S_IFLNK before ever asking Faccessat.
func (hostAccess) Writable(p string) bool {
	p = rewriteProcSelf(p)
	if !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	fd, _, err := openNoFollow(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return false
	}
	return unix.Faccessat(fd, "", unix.W_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS) == nil
}

func (hostAccess) Run(ctx context.Context, c Command) Output { return RunCommand(ctx, c) }

// ErrUndeclared is returned by the guard when a collector reaches outside
// its declaration; the run test in Task 6 fails on any violation.
var ErrUndeclared = errors.New("access outside the collector's declaration")

// ErrSkipped marks a collector that chose not to run (its Needs was not
// met, or it decided the host does not apply); later tasks record it in the
// run header rather than treating it as a failure.
var ErrSkipped = errors.New("collector skipped")

// guardedAccess is an Access that records any read or command outside the
// collector's declaration and refuses it with ErrUndeclared.
type guardedAccess struct {
	inner      Access
	decl       Declaration
	name       string
	violations []string
}

// Guard wraps a with the collector's declaration.
func Guard(a Access, c Collector) *guardedAccess {
	return &guardedAccess{inner: a, decl: c.Declare, name: c.Name}
}

// Violations returns every access this guard refused, in the order they
// happened.
func (g *guardedAccess) Violations() []string { return g.violations }

// Allowed reports whether path matches the collector's declared reads,
// without recording a violation (R55) — for a collector that wants to
// probe optionally (e.g. "does this alternate config exist") without that
// probe itself counting as a violation when it doesn't.
func (g *guardedAccess) Allowed(p string) bool {
	_, ok := g.allowedPath(p)
	return ok
}

// allowedPath matches p against the declared Reads globs after cleaning it,
// and returns the CLEANED path alongside the verdict (R72): the match
// itself is decided on the cleaned form, so the caller must go on to use
// that same cleaned form for the actual access — matching "/etc/ssh/../login.defs"
// against a declaration for "/etc/login.defs" and then handing the ORIGINAL,
// unclean string to inner would let the kernel resolve it through whatever
// "/etc/ssh" happens to be, defeating the declaration the match just
// approved.
func (g *guardedAccess) allowedPath(p string) (string, bool) {
	clean := path.Clean(p)
	for _, r := range g.decl.Reads {
		if ok, _ := path.Match(r, clean); ok || r == clean {
			return clean, true
		}
	}
	return clean, false
}

// allowedCommand requires an exact match: the same path and exactly the
// same arguments, via slices.Equal (R65) — not a prefix. A declaration of
// "sshd -T" does not license "sshd -T -f x"; a collector that needs a
// different invocation declares it.
func (g *guardedAccess) allowedCommand(c Command) bool {
	for _, d := range g.decl.Commands {
		if d.Path == c.Path && slices.Equal(d.Args, c.Args) {
			return true
		}
	}
	return false
}

func (g *guardedAccess) violate(what string) error {
	g.violations = append(g.violations, g.name+": "+what)
	return fmt.Errorf("%w: %s %s", ErrUndeclared, g.name, what)
}

func (g *guardedAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	clean, ok := g.allowedPath(p)
	if !ok {
		return nil, ReadMeta{}, g.violate("read " + p)
	}
	return g.inner.ReadFile(clean, limit)
}

// Stat, Llistxattr, Getxattr and Writable are guarded the same way ReadFile
// is: a path must match a declared Reads entry, and a violation is recorded
// the same way (R46/R60). All five pass the CLEANED path to inner (R72), not
// the original string the collector supplied — see allowedPath.
func (g *guardedAccess) Stat(p string) (ReadMeta, error) {
	clean, ok := g.allowedPath(p)
	if !ok {
		return ReadMeta{}, g.violate("stat " + p)
	}
	return g.inner.Stat(clean)
}

func (g *guardedAccess) Glob(pattern string) ([]string, error) {
	if _, ok := g.allowedPath(pattern); !ok {
		return nil, g.violate("glob " + pattern)
	}
	return g.inner.Glob(pattern)
}

func (g *guardedAccess) Llistxattr(p string) ([]string, error) {
	clean, ok := g.allowedPath(p)
	if !ok {
		return nil, g.violate("llistxattr " + p)
	}
	return g.inner.Llistxattr(clean)
}

func (g *guardedAccess) Getxattr(p, name string) ([]byte, error) {
	clean, ok := g.allowedPath(p)
	if !ok {
		return nil, g.violate("getxattr " + p)
	}
	return g.inner.Getxattr(clean, name)
}

// Writable is authorised against the same Declaration.Reads a read would
// be — a collector that wants to probe writability of a path must declare
// it as a read, so --list-actions prints a "read" row for it like any other
// declared target.
func (g *guardedAccess) Writable(p string) bool {
	clean, ok := g.allowedPath(p)
	if !ok {
		// g.violate's returned error is discarded: Writable's signature
		// (bool only, per the Access interface) can't surface it, but the
		// violation is still recorded in g.violations by the call itself.
		g.violate("writable " + p)
		return false
	}
	return g.inner.Writable(clean)
}

func (g *guardedAccess) Run(ctx context.Context, c Command) Output {
	if !g.allowedCommand(c) {
		return Output{ExitCode: -1, Err: g.violate("run " + c.Path + " " + strings.Join(c.Args, " "))}
	}
	return g.inner.Run(ctx, c)
}

// Action is one row of --list-actions (spec §9).
type Action struct {
	Collector string `json:"collector"`
	Kind      string `json:"kind"` // read | command | write
	Target    string `json:"target"`
	Needs     string `json:"needs"`
}

// ListActions renders the registry as the document a change-control
// reviewer reads: every path read, every command run, the single write. A
// /proc/self target is printed in its declared form, never the pid muster
// substitutes at run time (R40). The result is sorted by (collector, kind,
// target) so the document is deterministic regardless of the order a
// collector declared its reads and commands in.
func ListActions() []Action {
	var out []Action
	for _, c := range All() {
		for _, r := range c.Declare.Reads {
			out = append(out, Action{Collector: c.Name, Kind: "read", Target: r, Needs: c.Declare.Needs})
		}
		for _, cmd := range c.Declare.Commands {
			out = append(out, Action{Collector: c.Name, Kind: "command", Target: commandString(cmd), Needs: c.Declare.Needs})
		}
	}
	out = append(out, Action{Collector: "muster", Kind: "write", Target: DefaultSnapshotDir + "/<hostname>-<time>-<digest>.json", Needs: "root"})
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Target < b.Target
	})
	return out
}

// WriteActions prints actions as a table or JSON; any other format is
// rejected. The table ends with a legend line whenever any target starts
// with /proc/self, since that is the declared form printed above, not the
// pid substituted at run time (R40).
func WriteActions(w io.Writer, actions []Action, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(actions)
	case "table":
		hasProcSelf := false
		for _, a := range actions {
			if _, err := fmt.Fprintf(w, "%-10s %-8s %-5s %s\n", a.Collector, a.Kind, a.Needs, a.Target); err != nil {
				return err
			}
			if strings.HasPrefix(a.Target, "/proc/self/") {
				hasProcSelf = true
			}
		}
		if hasProcSelf {
			if _, err := fmt.Fprintln(w, "self = the collector's own pid"); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("collect: unknown --list-actions format %q (want %q or %q)", format, "table", "json")
	}
}
