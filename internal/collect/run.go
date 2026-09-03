//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/facts"
)

// ErrNotRoot is returned when --require-root was given and this process is
// not root. Nothing is collected and nothing is written.
var ErrNotRoot = errors.New("collect requires root (--require-root)")

// defaultTimeout is the global deadline when Options.Timeout is zero
// (spec §7.1).
const defaultTimeout = 5 * time.Minute

// Options for one collect run.
//
// Two flags of the collect command deliberately have no field here. R52:
// --include-secrets is not offered in stage 1 — nothing stores an original
// secret, so the header always says profile "default", include_secrets
// false, and an option that could only ever lie is not worth having.
// R47/R76: --deep is accepted by the command, which warns that the walk
// arrives in stage 3; the walk collector writes nothing and run.deep stays
// false, so an Options.Deep that changed nothing would be a trap. Both
// arrive with the behaviour they name. --require-complete is likewise not
// here: it selects an exit code and never changes what is collected or
// written, so it is a parameter of ExitCodeFor instead.
type Options struct {
	Out         string // "" = the default snapshot directory; "-" = stdout
	Force       bool
	Timeout     time.Duration // 0 = defaultTimeout
	RequireRoot bool

	Version         string
	Commit          string
	ControlsVersion string
	ControlsDigest  string

	LockPath string           // "" = LockPath; guards the default destination only
	Now      func() time.Time // nil = time.Now
	Access   Access           // nil = Host()
}

// Outcome is what the command needs to report and to choose an exit code.
type Outcome struct {
	Path     string
	Complete bool
	Partial  []string
	// Warnings are conditions that did not stop the snapshot from being
	// written — R74's failed `latest` link is the only one in stage 1. The
	// command prints them on stderr; they never change the exit code.
	Warnings []string
	Header   facts.Run
}

// procSelfStatus is the only path collect reads on its own behalf, and it
// is read like any other: declared by a collector and checked by the guard
// (R60).
const procSelfStatus = "/proc/self/status"

// statusReadLimit caps /proc/self/status. It is a few hundred bytes on
// every kernel; the cap only bounds a hostile or fake Access.
const statusReadLimit = 64 << 10

// maxCapText bounds the raw mask recorded in the header. CapEff is 16 hex
// digits; anything longer is not a mask muster understands, and the header
// is provenance, not a place to park a file's contents.
const maxCapText = 32

// capBits is the table R53 fixes: the capabilities collect's behaviour
// actually depends on, in ascending bit order, which is also alphabetical
// order — so run.capabilities is byte-identical for two hosts with the same
// effective set.
var capBits = []struct {
	bit  uint
	name string
}{
	{2, "CAP_DAC_READ_SEARCH"},
	{12, "CAP_NET_ADMIN"},
	{21, "CAP_SYS_ADMIN"},
}

// capabilities decodes CapEff from /proc/self/status against capBits and
// keeps the raw mask, so a capability outside the table is still visible to
// a reader of the snapshot. It returns an empty, non-nil list when the file
// cannot be read or carries no CapEff line: the header field has no
// omitempty, and a JSON null would be a third meaning beside "none" and
// "some" (R53).
func capabilities(a Access) []string {
	names := []string{}
	data, _, err := a.ReadFile(procSelfStatus, statusReadLimit)
	if err != nil {
		return names
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		hexMask := strings.TrimSpace(rest)
		if len(hexMask) > maxCapText {
			hexMask = hexMask[:maxCapText]
		}
		mask, err := strconv.ParseUint(hexMask, 16, 64)
		if err != nil {
			return []string{"raw:" + hexMask}
		}
		for _, c := range capBits {
			if mask&(1<<c.bit) != 0 {
				names = append(names, c.name)
			}
		}
		return append(names, "raw:"+hexMask)
	}
	return names
}

// musterCollector reads /proc/self/status for the privilege block of the
// run header. It is a registered collector rather than a private read
// inside Run so that the one path collect reads for itself is declared,
// guarded and printed by --list-actions like every other read (R60).
var musterCollector = Collector{
	Name:    "muster",
	Declare: Declaration{Reads: []string{procSelfStatus}, Needs: "none"},
	Run: func(_ context.Context, a Access, b *Builder) error {
		h := b.Header()
		h.EUID = os.Geteuid()
		h.Capabilities = capabilities(a)
		return nil
	},
}

func init() { Register(musterCollector) }

// Run executes every registered collector and writes the snapshot
// (spec §7.1). Nothing is written when --require-root fails or the lock is
// held. A collector that fails, times out or reaches outside its
// declaration makes the run partial; the others still run and the snapshot
// is still written, with whatever succeeded.
func Run(ctx context.Context, o Options, stdout io.Writer) (Outcome, error) {
	if o.RequireRoot && os.Geteuid() != 0 {
		return Outcome{}, ErrNotRoot
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Access == nil {
		o.Access = Host()
	}
	lock, err := acquire(o)
	if err != nil {
		return Outcome{}, err
	}
	defer lock.Release()

	reg, err := facts.LoadRegistry()
	if err != nil {
		return Outcome{}, err
	}
	b := NewBuilder(reg)
	hdr := b.Header()
	hdr.MusterVersion, hdr.Commit = o.Version, o.Commit
	hdr.ControlsVersion, hdr.ControlsDigest = o.ControlsVersion, o.ControlsDigest
	hdr.GuideEdition = "kisa-unix-2026"
	// R54: the clock is read once, here, and the same string names the file
	// and dates the header.
	hdr.CollectedAt = o.Now().UTC().Format(time.RFC3339)
	// The muster collector fills both of these from /proc/self/status
	// (R60). They are seeded here so that a registry without it — a test
	// that called Reset — still cannot publish a header claiming root or a
	// null capability list.
	hdr.EUID = os.Geteuid()
	hdr.Capabilities = []string{}
	// R52: stage 1 stores no original secret value.
	hdr.Redaction = facts.Redaction{Profile: "default", IncludeSecrets: false}
	hdr.Collectors = []facts.CollectorRun{}
	hdr.PartialFailures = []string{}

	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	complete := true
	for _, c := range All() {
		run := runCollector(ctx, c, o, b)
		hdr.Collectors = append(hdr.Collectors, run)
		if run.Status != "ok" && run.Status != "skipped" {
			complete = false
			// All() is sorted by name, so partial_failures comes out
			// sorted without sorting it again.
			hdr.PartialFailures = append(hdr.PartialFailures, c.Name)
		}
	}
	hdr.Complete = complete
	if hdr.Host.Hostname == "" {
		// The os collector normally fills this from /etc/hostname; fall
		// back so the generated file name is never "-<time>-<digest>".
		hdr.Host.Hostname, _ = os.Hostname()
	}

	snap := facts.Snapshot{SchemaVersion: facts.SchemaVersion, Run: *hdr, Facts: b.Tree()}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return Outcome{}, err
	}
	data = append(data, '\n')
	// R54: the writer never reads the clock or the hostname itself; both
	// come from the header this run just built.
	path, err := WriteSnapshot(data, WriteOptions{
		Out: o.Out, Force: o.Force, Hostname: hdr.Host.Hostname, CollectedAt: hdr.CollectedAt,
	}, stdout)
	out := Outcome{Path: path, Complete: complete, Partial: hdr.PartialFailures, Header: *hdr}
	switch {
	case err == nil:
	case errors.Is(err, ErrLatestNotUpdated):
		// R74: the snapshot on disk is the contract, the convenience link
		// is not. The run succeeded; the failure is reported as a warning.
		out.Warnings = append(out.Warnings, err.Error())
	default:
		return Outcome{}, err
	}
	return out, nil
}

// acquire takes the lock that guards this run's destination (R44/R73): the
// shared lock file for the default snapshot directory, the destination
// directory itself for an explicit --out path — muster has no business
// creating a lock file in a directory it does not own — and nothing at all
// for --out -, which writes to a pipe and has no destination to guard.
func acquire(o Options) (*Lock, error) {
	switch {
	case o.Out == "-":
		return nil, nil
	case o.Out == "":
		if o.LockPath == "" {
			o.LockPath = LockPath
		}
		return AcquireLock(o.LockPath)
	default:
		dir := filepath.Dir(o.Out)
		lock, err := AcquireDirLock(dir)
		if err != nil && !errors.Is(err, ErrLocked) {
			// ErrLocked already names the directory; anything else is a
			// bare errno from opening it — "permission denied" on its own
			// leaves the user guessing which path was refused.
			return nil, fmt.Errorf("lock the output directory %s: %w", dir, err)
		}
		return lock, err
	}
}

// runCollector runs one collector under the guard and records what
// happened (R56/R66/R71). Every collector gets its own guard, its own
// recover and the same global deadline.
func runCollector(ctx context.Context, c Collector, o Options, b *Builder) facts.CollectorRun {
	g := Guard(o.Access, c)
	b.Begin(c.Name)
	start := o.Now()
	status, reason := callRun(ctx, c, g, b)
	// A violation outranks whatever the collector itself reported: a
	// collector that reached outside its declaration must never be filed
	// as ok or skipped, and the reason names what it reached for.
	if v := g.Violations(); len(v) > 0 {
		status, reason = "error", strings.Join(v, "; ")
	}
	if status == "" {
		// R56/R71: the collector returned cleanly, so its status is the
		// worst status among the facts it actually wrote — a collector
		// that recorded nothing but denials is not "ok".
		status = string(b.Worst(c.Name))
	}
	return facts.CollectorRun{
		Name:   c.Name,
		Status: status,
		Ms:     o.Now().Sub(start).Milliseconds(),
		Cmd:    firstCommand(c),
		Reason: reason,
	}
}

// callRun invokes the collector and classifies its return. An empty status
// means "the collector returned cleanly" — the caller derives the status
// from the facts it wrote. A panic is contained here: one broken collector
// costs its own facts, never the snapshot.
func callRun(ctx context.Context, c Collector, a Access, b *Builder) (status, reason string) {
	defer func() {
		if p := recover(); p != nil {
			status, reason = "error", fmt.Sprintf("panic: %v", p)
		}
	}()
	err := c.Run(ctx, a, b)
	switch {
	case errors.Is(err, ErrSkipped):
		return "skipped", ""
	case ctx.Err() != nil:
		return "timeout", "global deadline exceeded"
	case err != nil:
		return "error", err.Error()
	}
	return "", ""
}

// firstCommand is the collector's first declared command, rendered the way
// --list-actions renders it (R66). CollectorRun.Cmd holds one string, so a
// collector that runs several is represented by the first it declared;
// --list-actions is where the full set lives.
func firstCommand(c Collector) string {
	if len(c.Declare.Commands) == 0 {
		return ""
	}
	cmd := c.Declare.Commands[0]
	return strings.TrimSpace(cmd.Path + " " + strings.Join(cmd.Args, " "))
}

// ExitCodeFor maps an outcome to the collect contract (spec §7.1, D11): 0
// complete, 1 partial, 2 nothing written — or 2 for a partial snapshot when
// --require-complete was given. requireComplete never changes what was
// written, only how this run is reported to CI.
func ExitCodeFor(out Outcome, err error, requireComplete bool) int {
	switch {
	case err != nil:
		return 2
	case !out.Complete && requireComplete:
		return 2
	case !out.Complete:
		return 1
	}
	return 0
}
