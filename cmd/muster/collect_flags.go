package main

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
)

const collectUsage = `usage: muster collect [flags]

flags:
  --out <path|->        snapshot path (default /var/lib/muster/snapshots/<host>-<time>-<digest>.json)
  --force               overwrite an existing --out path
  --deep                run the filesystem walk (needs root; raises the default --timeout to --walk-budget + 5m)
  --walk-budget <dur>   wall-time limit for the walk (default 10m; needs --deep)
  --walk-max-entries <n>  entries the walk may visit (default 2000000; needs --deep)
  --walk-exclude <path> a root the walk must not enter, repeatable (needs --deep)
  --walk-include <path> a container-storage root to walk after all, repeatable; the fixed set only (needs --deep)
  --timeout <duration>  global deadline (default 5m)
  --require-root        exit 2 without writing when not root
  --require-complete    exit 2 (instead of 1) when the snapshot is partial
  --list-actions        print every path read, command run and the file written, then exit
  --format table|json   with --list-actions (default table)
`

// defaultWalkBudget and defaultWalkMaxEntries are the walk's two limits
// (spec §2, W-12). They are applied whether or not --deep was given —
// collectOpts always carries the values a walk would run with — and they
// matter only when it was: collect.Run reads Options.Walk under Deep alone.
const (
	defaultWalkBudget     = 10 * time.Minute
	defaultWalkMaxEntries = 2_000_000
	// walkTimeoutMargin is what the rest of the collect run keeps beyond
	// the walk's budget when --deep raises the default deadline. Under the
	// plain 5m default a 10m walk could only ever end as a deadline.
	walkTimeoutMargin = 5 * time.Minute
)

// collectOpts is the parsed command line. It is deliberately not
// collect.Options: that type is Linux-only, and this parser is shared with
// the build for every other platform (R58), which must reject an unknown
// flag exactly the way Linux does before it says collect needs Linux. The
// parser does import internal/collect for the one file of the package that
// carries no build tag — the fixed container-storage set --walk-include is
// validated against, which is a list of literal paths and needs no host.
type collectOpts struct {
	out             string
	force           bool
	deep            bool
	walkBudget      time.Duration
	walkMaxEntries  int
	walkExclude     []string
	walkInclude     []string
	timeout         time.Duration
	timeoutGiven    bool
	requireRoot     bool
	requireComplete bool
	listActions     bool
	format          string
}

func parseCollectFlags(args []string) (collectOpts, error) {
	o := collectOpts{format: "table", walkBudget: defaultWalkBudget, walkMaxEntries: defaultWalkMaxEntries}
	formatGiven := false
	// walkFlag is the first walk flag seen, so a walk flag without --deep
	// is refused naming the flag the operator actually typed.
	walkFlag := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--out":
			o.out, err = next()
		case "--format":
			formatGiven = true
			o.format, err = next()
		case "--timeout":
			var v string
			if v, err = next(); err == nil {
				o.timeoutGiven = true
				if o.timeout, err = time.ParseDuration(v); err != nil {
					err = fmt.Errorf("--timeout: %w", err)
				}
			}
		case "--force":
			o.force = true
		case "--deep":
			o.deep = true
		case "--walk-budget":
			markWalkFlag(&walkFlag, a)
			var v string
			if v, err = next(); err == nil {
				if o.walkBudget, err = time.ParseDuration(v); err != nil {
					err = fmt.Errorf("--walk-budget: %w", err)
				}
			}
		case "--walk-max-entries":
			markWalkFlag(&walkFlag, a)
			var v string
			if v, err = next(); err == nil {
				o.walkMaxEntries, err = entryCap(v)
			}
		case "--walk-exclude":
			markWalkFlag(&walkFlag, a)
			var v string
			if v, err = next(); err == nil {
				if err = checkWalkPath(a, v); err == nil {
					o.walkExclude = append(o.walkExclude, v)
				}
			}
		case "--walk-include":
			markWalkFlag(&walkFlag, a)
			var v string
			if v, err = next(); err == nil {
				// L-9: --walk-include takes an entry off the fixed
				// container-storage set and does nothing else. Any other
				// value — /proc, a remote mount, an arbitrary directory —
				// would turn it into a general override of the boundaries
				// the walk exists to keep.
				if !slices.Contains(collect.ContainerStorageRoots(), v) {
					err = fmt.Errorf("--walk-include: %s is not a container-storage root", v)
				} else {
					o.walkInclude = append(o.walkInclude, v)
				}
			}
		case "--require-root":
			o.requireRoot = true
		case "--require-complete":
			o.requireComplete = true
		case "--list-actions":
			o.listActions = true
		default:
			return o, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return o, err
		}
	}
	if o.format != "table" && o.format != "json" {
		return o, fmt.Errorf("--format must be table or json, got %q", o.format)
	}
	// The snapshot has one format. --format elsewhere would silently do
	// nothing, and silently doing nothing is how a CI job ends up trusting
	// output it never got.
	if formatGiven && !o.listActions {
		return o, errors.New("--format is only meaningful with --list-actions")
	}
	// The same reasoning binds the walk flags: a budget or an exclusion
	// given without --deep tunes a walk that will not run, and an operator
	// who believes an exclusion applied is worse off than one told it did
	// not (W-12).
	if walkFlag != "" && !o.deep {
		return o, fmt.Errorf("%s needs --deep", walkFlag)
	}
	if o.deep && !o.timeoutGiven {
		o.timeout = o.walkBudget + walkTimeoutMargin
	}
	// A budget the deadline cannot hold buys a half-seen filesystem: the
	// walk is killed, walk.complete is false and every walk-based control
	// is ERROR(walk_incomplete). Better to refuse the pair now, naming
	// both, than to spend the deadline finding that out. The default budget
	// counts as a budget — an explicit --timeout below 10m is refused
	// exactly as an explicit --walk-budget above the deadline is.
	if o.deep && o.walkBudget > o.timeout {
		return o, fmt.Errorf("--walk-budget %s exceeds --timeout %s", o.walkBudget, o.timeout)
	}
	return o, nil
}

// markWalkFlag remembers the first walk flag on the command line.
func markWalkFlag(seen *string, flag string) {
	if *seen == "" {
		*seen = flag
	}
}

// entryCap parses --walk-max-entries. Zero or a negative count is refused
// rather than read as "no limit": the flag is a cap, and a walk that visits
// nothing is not one an operator asks for by number.
func entryCap(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("--walk-max-entries: %w", err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("--walk-max-entries must be greater than 0, got %d", n)
	}
	return n, nil
}

// checkWalkPath refuses a --walk-exclude value that is not an absolute,
// already-clean path. The walk compares it against mount points and
// directory paths by prefix, so "data" or "/data/../etc" would exclude
// something other than what it says. The check uses path, not filepath:
// this parser runs on Windows too, where filepath would answer for Windows
// paths a Linux host will never see.
func checkWalkPath(flag, v string) error {
	if !strings.HasPrefix(v, "/") || path.Clean(v) != v {
		return fmt.Errorf("%s: %s must be an absolute, clean path", flag, v)
	}
	return nil
}
