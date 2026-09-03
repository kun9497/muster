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
	Run(ctx context.Context, c Command) Output
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

// Register adds a collector; a duplicate name is a programming error.
func Register(c Collector) {
	if _, dup := registry[c.Name]; dup {
		panic("collector registered twice: " + c.Name)
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

// Reset clears the registry (tests only).
func Reset() { registry = map[string]Collector{} }

// DefaultSnapshotDir is where collect writes snapshots. It is declared here
// only as a placeholder; Task 4 moves it to writer.go.
const DefaultSnapshotDir = "/var/lib/muster/snapshots"

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

func (hostAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	return ReadFile(rewriteProcSelf(p), limit)
}

func (hostAccess) Stat(p string) (ReadMeta, error) { return Stat(rewriteProcSelf(p)) }

// Glob is filepath.Glob. A match reached through a symlinked directory is
// still read through ReadFile/Stat afterward, and the read primitive
// refuses it there (ErrSymlink) — Glob does not need to re-implement the
// no-follow walk itself, it only ever names candidates.
func (hostAccess) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }

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

func (hostAccess) Writable(p string) bool { return unix.Access(rewriteProcSelf(p), unix.W_OK) == nil }

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
func (g *guardedAccess) Allowed(p string) bool { return g.allowedPath(p) }

func (g *guardedAccess) allowedPath(p string) bool {
	p = path.Clean(p)
	for _, r := range g.decl.Reads {
		if ok, _ := path.Match(r, p); ok || r == p {
			return true
		}
	}
	return false
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
	if !g.allowedPath(p) {
		return nil, ReadMeta{}, g.violate("read " + p)
	}
	return g.inner.ReadFile(p, limit)
}

// Stat, Llistxattr and Writable are guarded the same way ReadFile is: a
// path must match a declared Reads entry, and a violation is recorded the
// same way (R46/R60).
func (g *guardedAccess) Stat(p string) (ReadMeta, error) {
	if !g.allowedPath(p) {
		return ReadMeta{}, g.violate("stat " + p)
	}
	return g.inner.Stat(p)
}

func (g *guardedAccess) Glob(pattern string) ([]string, error) {
	if !g.allowedPath(pattern) {
		return nil, g.violate("glob " + pattern)
	}
	return g.inner.Glob(pattern)
}

func (g *guardedAccess) Llistxattr(p string) ([]string, error) {
	if !g.allowedPath(p) {
		return nil, g.violate("llistxattr " + p)
	}
	return g.inner.Llistxattr(p)
}

func (g *guardedAccess) Writable(p string) bool {
	if !g.allowedPath(p) {
		g.violate("writable " + p)
		return false
	}
	return g.inner.Writable(p)
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
// substitutes at run time (R40).
func ListActions() []Action {
	var out []Action
	for _, c := range All() {
		for _, r := range c.Declare.Reads {
			out = append(out, Action{Collector: c.Name, Kind: "read", Target: r, Needs: c.Declare.Needs})
		}
		for _, cmd := range c.Declare.Commands {
			out = append(out, Action{Collector: c.Name, Kind: "command", Target: strings.TrimSpace(cmd.Path + " " + strings.Join(cmd.Args, " ")), Needs: c.Declare.Needs})
		}
	}
	out = append(out, Action{Collector: "muster", Kind: "write", Target: DefaultSnapshotDir + "/<hostname>-<time>-<digest>.json", Needs: "root"})
	return out
}

// WriteActions prints actions as a table or JSON. The table ends with a
// legend line whenever any target starts with /proc/self, since that is
// the declared form printed above, not the pid substituted at run time
// (R40).
func WriteActions(w io.Writer, actions []Action, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(actions)
	}
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
}
