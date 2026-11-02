package main

import (
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/snapshots"
)

// errRmNotBoth is an rm that mixes the two ways of naming files (RA-11).
var errRmNotBoth = errors.New("rm takes bare names under --dir or full paths of one directory, not both")

type rmFlags struct {
	dir    string
	dryRun bool
	names  []string
}

// parseRmArgs reads the flags, then the names. A name holding '/' is a full
// path and must be absolute -- rm never guesses a directory -- and is split
// into its directory, opened as the snapshot directory, and its base. Every
// full path names the same directory, and full paths are never mixed with
// bare names or an explicit --dir (RA-11). "--" ends the flags.
func parseRmArgs(args []string) (rmFlags, error) {
	f := rmFlags{dir: snapshots.DefaultDir}
	dirSet := false
	i := 0
flags:
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
			break flags
		case a == "--dir":
			if i+1 >= len(args) {
				return f, fmt.Errorf("flag %s needs a value", a)
			}
			i++
			if args[i] == "" {
				return f, fmt.Errorf("flag %s needs a non-empty value", a)
			}
			f.dir, dirSet = args[i], true
		case a == "--dry-run":
			f.dryRun = true
		case strings.HasPrefix(a, "-") && a != "-":
			return f, fmt.Errorf("unknown flag %s", a)
		default:
			break flags
		}
	}
	names := args[i:]
	if len(names) == 0 {
		return f, errors.New("rm needs at least one name")
	}
	var fullDir string
	full, bare := 0, 0
	for _, n := range names {
		if !strings.Contains(n, "/") {
			bare++
			f.names = append(f.names, n)
			continue
		}
		if !strings.HasPrefix(n, "/") {
			return f, fmt.Errorf("%s is not an absolute path; rm never guesses a directory", report.Escape(n))
		}
		// Snapshot paths are Linux paths on every platform, so path, not
		// path/filepath, splits them.
		dir := path.Dir(n)
		if full > 0 && dir != fullDir {
			return f, errRmNotBoth
		}
		fullDir = dir
		full++
		f.names = append(f.names, path.Base(n))
	}
	if full > 0 {
		if bare > 0 || dirSet {
			return f, errRmNotBoth
		}
		f.dir = fullDir
	}
	return f, nil
}

type pruneFlags struct {
	dir    string
	dryRun bool
	b      snapshots.Bounds
}

// parsePruneArgs reads --keep and --keep-days (non-negative integers, each
// at most once), --dir and --dry-run; with neither bound it returns
// snapshots.ErrNoBounds.
func parsePruneArgs(args []string) (pruneFlags, error) {
	f := pruneFlags{dir: snapshots.DefaultDir}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			if args[i] == "" {
				return "", fmt.Errorf("flag %s needs a non-empty value", a)
			}
			return args[i], nil
		}
		bound := func(n *int, has *bool) error {
			if *has {
				return fmt.Errorf("flag %s given twice", a)
			}
			v, err := next()
			if err != nil {
				return err
			}
			k, err := strconv.Atoi(v)
			if err != nil || k < 0 {
				return fmt.Errorf("flag %s needs a non-negative integer", a)
			}
			*n, *has = k, true
			return nil
		}
		var err error
		switch a {
		case "--keep":
			err = bound(&f.b.Keep, &f.b.HasKeep)
		case "--keep-days":
			err = bound(&f.b.KeepDays, &f.b.HasKeepDays)
		case "--dir":
			f.dir, err = next()
		case "--dry-run":
			f.dryRun = true
		default:
			return f, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return f, err
		}
	}
	if !f.b.HasKeep && !f.b.HasKeepDays {
		return f, snapshots.ErrNoBounds
	}
	return f, nil
}

// validRmName is a name rm may hand to the directory fd: not empty, "." or
// "..", no '/', and no control byte (Review Focus 1).
func validRmName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c == '/' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// kindRefusal says why rm will not remove a name the pre-pass stat-ed.
func kindRefusal(name, dir string, k dirKind) string {
	n := report.Escape(name)
	switch k {
	case kindAbsent:
		return fmt.Sprintf("%s does not exist in %s; nothing removed", n, report.EscapeNoCut(dir))
	case kindDir:
		return fmt.Sprintf("%s is a directory; rm removes only regular files, nothing removed", n)
	case kindSymlink:
		return fmt.Sprintf("%s is a symlink; rm removes only regular files, nothing removed", n)
	default:
		return fmt.Sprintf("%s is not a regular file; nothing removed", n)
	}
}

// warnAboveNewest warns once per newer or unreadable entry that sorts above
// the newest ok one (RA-4): prune never removes it, and latest never points
// at it.
func warnAboveNewest(stderr io.Writer, entries []snapshots.Entry) {
	newest, ok := snapshots.Newest(entries)
	if !ok {
		return
	}
	sorted := slices.Clone(entries)
	snapshots.Sort(sorted)
	for _, e := range sorted {
		if e.Name == newest.Name {
			return
		}
		if e.Class == snapshots.ClassNewer || e.Class == snapshots.ClassUnreadable {
			fmt.Fprintf(stderr, "muster: warning: %s is %s and newer than the newest readable snapshot %s\n",
				report.Escape(e.Name), e.Class, report.Escape(newest.Name))
		}
	}
}

// openLocked opens the snapshot directory (RL-18) and takes the lock collect
// takes over it, so nothing is written while files are removed.
func openLocked(dir string, stderr io.Writer) (*snapshotDir, dirLock, bool) {
	d, err := openSnapshotDir(dir)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return nil, nil, false
	}
	l, err := d.lock()
	if err != nil {
		d.close()
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return nil, nil, false
	}
	return d, l, true
}

// removeAll removes names in order and stops at the first failure; what is
// already removed stays removed, and the message says how far it got.
func removeAll(d *snapshotDir, names []string, stderr io.Writer) ([]string, bool) {
	var removed []string
	for i, n := range names {
		if err := d.remove(n); err != nil {
			fmt.Fprintf(stderr, "muster: %v; stopped after %d of %d\n", err, i, len(names))
			return removed, false
		}
		removed = append(removed, n)
	}
	return removed, true
}

// repointAfter re-points latest when its target was removed: to the newest
// ok entry left, or away when none is. warn gives the RA-4 warning over what
// is left first (rm; prune has already given it).
func repointAfter(d *snapshotDir, entries []snapshots.Entry, latest latestLink, removed []string, warn bool, stderr io.Writer) bool {
	if !latest.present || !slices.Contains(removed, latest.target) {
		return true
	}
	var remaining []snapshots.Entry
	for _, e := range entries {
		if !slices.Contains(removed, e.Name) {
			remaining = append(remaining, e)
		}
	}
	if warn {
		warnAboveNewest(stderr, remaining)
	}
	target, ok := snapshots.Repoint(remaining)
	if !ok {
		target = ""
	}
	if err := d.repointLatest(target); err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return false
	}
	if target == "" {
		fmt.Fprintln(stderr, "muster: latest link removed")
	} else {
		fmt.Fprintf(stderr, "muster: latest -> %s\n", report.Escape(target))
	}
	return true
}

// runSnapshotRm removes the named regular files (RL-16, RL-18). Every name
// is checked before anything is removed (RA-3); stdout is silent unless
// --dry-run. Exit 0 removed, 2 refused or an I/O error.
func runSnapshotRm(args []string, stdout, stderr io.Writer) int {
	f, err := parseRmArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, snapshotUsage)
		return exitError
	}
	d, l, ok := openLocked(f.dir, stderr)
	if !ok {
		return exitError
	}
	defer d.close()
	defer l.Release()
	entries, _, latest, err := d.list()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	var names []string
	for _, n := range f.names {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	// RA-8: latest by name first, so a regular file called latest gets the
	// same answer as the link.
	if slices.Contains(names, "latest") {
		fmt.Fprintln(stderr, "muster: latest is a link; name the snapshot it points at")
		return exitError
	}
	for _, n := range names {
		if !validRmName(n) {
			fmt.Fprintf(stderr, "muster: %s is not a file name in %s\n", report.Escape(n), report.EscapeNoCut(f.dir))
			return exitError
		}
	}
	for _, n := range names {
		k, err := d.stat(n)
		if err != nil {
			fmt.Fprintf(stderr, "muster: stat %s/%s: %v\n", report.EscapeNoCut(f.dir), report.Escape(n), err)
			return exitError
		}
		if k != kindRegular {
			fmt.Fprintf(stderr, "muster: %s\n", kindRefusal(n, f.dir, k))
			return exitError
		}
	}
	if f.dryRun {
		for _, n := range names {
			fmt.Fprintf(stdout, "would remove %s\n", report.Escape(n))
		}
		return exitOK
	}
	removed, ok := removeAll(d, names, stderr)
	if !repointAfter(d, entries, latest, removed, true, stderr) || !ok {
		return exitError
	}
	return exitOK
}

// runSnapshotPrune removes the ok snapshots outside the bounds, never the
// newest (RL-17), reading the clock once after the listing (RA-7). Exit 0
// pruned, 2 no bound, refused or an I/O error.
func runSnapshotPrune(args []string, stdout, stderr io.Writer) int {
	f, err := parsePruneArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, snapshotUsage)
		return exitError
	}
	d, l, ok := openLocked(f.dir, stderr)
	if !ok {
		return exitError
	}
	defer d.close()
	defer l.Release()
	entries, _, latest, err := d.list()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	nowT := commandClock()
	warnAboveNewest(stderr, entries)
	doomed, err := snapshots.Prune(entries, f.b, nowT)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	names := make([]string, 0, len(doomed))
	for _, e := range doomed {
		names = append(names, e.Name)
	}
	if f.dryRun {
		for _, n := range names {
			fmt.Fprintf(stdout, "would remove %s\n", report.Escape(n))
		}
		return exitOK
	}
	removed, ok := removeAll(d, names, stderr)
	if !repointAfter(d, entries, latest, removed, false, stderr) || !ok {
		return exitError
	}
	return exitOK
}
