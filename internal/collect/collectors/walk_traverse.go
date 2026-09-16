//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// walkClock is the traversal's view of time: the moment the walk began and
// the function that says what time it is now. It is a parameter rather than
// a call to time.Now inside the loop so a test can jump the clock past the
// budget without sleeping, and so the budget is measured from the start of
// the WALK rather than from the start of the collection.
type walkClock struct {
	start time.Time
	now   func() time.Time
}

func (c walkClock) elapsed() time.Duration {
	if c.now == nil {
		return 0
	}
	return c.now().Sub(c.start)
}

// walkLists are the finding lists one traversal produced, each a slice of
// records in the same shape the fact carries (A-14: a record is a
// map[string]any, so encoding/json emits its keys sorted and no field order
// is smuggled into the output).
//
// suid holds every setuid/setgid candidate the traversal found; the package
// join (W-6/W-7) is what later splits it into walk.suid_sgid and
// walk.suid_sgid_unverified, so suidUnverified is empty here and exists only
// so the cap indices and the join have one shape to work with.
//
// truncated and truncatedCounts are indexed by the cap constants of
// walk_hidden.go. truncatedCounts counts every row OFFERED to a list,
// whether it was kept or refused, which is what walk.stats.truncated_counts
// reports; for the hidden list it counts the non-allowlisted candidates
// alone, because the allowlisted ones have a cap and a counter of their own
// (allowlistedHidden) and, by §2, never set truncated.
type walkLists struct {
	suid, suidUnverified, worldWritable, stickyMissing, unowned, hidden, skipped []map[string]any

	truncated         [capCount]bool
	truncatedCounts   [capCount]int
	allowlistedHidden int
}

// walkResult is everything one traversal learned: the lists, the counts
// walk.stats publishes, and how the walk ended. complete is false only when
// a limit stopped it, and stopReason is then one of time_budget,
// entry_budget or deadline with lastPath naming the directory the walk was
// about to read.
type walkResult struct {
	lists walkLists

	entries, dirs, files, symlinks int

	complete             bool
	stopReason, lastPath string
	mntIDFallback        bool
}

// frame is one directory waiting to be listed. ident is the identity the
// parent's listing gave it, which ReadDir checks against the directory it
// actually opens (zero for a root, which nothing listed). mntID is the mount
// the directory is on, so a child on another mount is recognised as a
// boundary. underHidden says the directory is at or below a hidden
// directory: the walk descends into one but records only the entry, never
// its children (§3).
type frame struct {
	path        string
	ident       collect.Identity
	mntID       uint64
	underHidden bool
}

// traverse walks every mount the plan entered and sorts what it finds into
// the finding lists (W-3, W-4). It touches the host only through a, never
// follows a symlink (a symlink is an entry, never a directory to open),
// never leaves the mounts the plan chose, and never visits one directory
// twice. It does not apply the scheduling priority — the collector's walk
// goroutine does that (A-5), on the thread it locked — and it does not write
// a fact: it returns what the collector writes.
//
// A budget of zero or an entry limit of zero is no limit at all. The collect
// command refuses a non-positive --walk-budget, so on a real run both are
// set; leaving them off here is what lets a test say which limit it is
// about.
func traverse(ctx context.Context, a collect.Access, plan mountPlan, ids idTables, opts collect.WalkOptions, clock walkClock) walkResult {
	w := &walker{
		a: a, plan: plan, ids: ids, opts: opts, clock: clock,
		visited: map[collect.Identity]bool{},
		planned: map[string]bool{},
	}
	w.r.complete = true
	// The roots the plan already decided about are the walk's first skipped
	// rows and count toward the cap like any other (A-15); planned also
	// answers, for the st_dev fallback, whether a mount point the walk
	// stumbles on is one mountinfo carried.
	for _, s := range plan.skipped {
		w.planned[s.path] = true
		w.addSkip(s.path, s.reason, s.detail)
	}

	stack := w.roots()
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if reason := w.stopped(ctx); reason != "" {
			w.r.complete, w.r.stopReason, w.r.lastPath = false, reason, f.path
			break
		}
		l, err := w.a.ReadDir(f.path, f.ident)
		if err != nil {
			reason, detail := skipReason(err)
			w.addSkip(f.path, reason, detail)
			continue
		}
		if f.ident == (collect.Identity{}) { // a root: nothing listed it
			self := collect.Identity{Dev: l.Self.Dev, Ino: l.Self.Ino}
			if w.visited[self] {
				// Two entered mounts on one directory. The plan drops the
				// bind aliases it can see in mountinfo; this is the last
				// line of defence, and reporting the tree twice would
				// double every finding under it.
				w.addSkip(f.path, "bind_duplicate", "")
				continue
			}
			w.visited[self] = true
			if l.Self.MntIDKnown {
				f.mntID = l.Self.MntID
			} else {
				w.r.mntIDFallback = true
			}
		}
		stack = w.listing(f, l, stack)
	}
	w.r.lists.sort()
	return w.r
}

// walker is one traversal's mutable state, so the rules below read as
// methods on it rather than as a function with nine parameters.
type walker struct {
	a       collect.Access
	plan    mountPlan
	ids     idTables
	opts    collect.WalkOptions
	clock   walkClock
	visited map[collect.Identity]bool
	planned map[string]bool
	r       walkResult
}

// roots are the mount points the plan entered, sorted by mount point and
// pushed so that the first of them is the first popped. Each carries a zero
// identity (nothing listed a root, so there is nothing to check it against)
// and mountinfo's mount id, which the root's own listing replaces with the
// id the kernel reports.
//
// A mount point at or under an excluded root is not walked: the plan's
// exclusion is about a subtree, and a store that is its own mount — a
// /var/lib/docker on its own logical volume is the ordinary case — would
// otherwise be walked through the front door. The plan already wrote the
// row that says why.
//
// underHidden is derived from the mount point itself, so a mount under a
// hidden directory is treated exactly as the directory it is mounted on
// would have been.
func (w *walker) roots() []frame {
	rows := make([]mountRow, 0, len(w.plan.enter))
	for _, r := range w.plan.enter {
		rows = append(rows, r)
	}
	slices.SortFunc(rows, func(x, y mountRow) int {
		if c := strings.Compare(x.mountPoint, y.mountPoint); c != 0 {
			return c
		}
		return x.id - y.id
	})
	out := make([]frame, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		if w.underExcludedRoot(r.mountPoint) {
			continue
		}
		out = append(out, frame{
			path:        r.mountPoint,
			mntID:       uint64(r.id),
			underHidden: pathUnderHidden(r.mountPoint),
		})
	}
	return out
}

func (w *walker) underExcludedRoot(p string) bool {
	for root := range w.plan.excludedRoots {
		if underOrEqual(p, root) {
			return true
		}
	}
	return false
}

// stopped names the limit that ends the traversal, checked before every
// directory: the context first (a cancelled context is the run's global
// deadline and outranks everything), then the wall-clock budget, then the
// number of entries seen (§2).
func (w *walker) stopped(ctx context.Context) string {
	if ctx.Err() != nil {
		return "deadline"
	}
	if w.opts.Budget > 0 && w.clock.elapsed() > w.opts.Budget {
		return "time_budget"
	}
	if w.opts.MaxEntries > 0 && w.r.entries >= w.opts.MaxEntries {
		return "entry_budget"
	}
	return ""
}

// listing judges every entry of one directory and returns the stack with
// the directories to descend into pushed onto it, reversed so that they are
// popped in the order the listing gave them.
func (w *walker) listing(f frame, l collect.Listing, stack []frame) []frame {
	var children []frame
	for _, e := range l.Entries {
		p := path.Join(f.path, e.Name)
		w.r.entries++
		switch e.Kind {
		case "dir":
			w.r.dirs++
		case "regular":
			w.r.files++
		case "symlink":
			w.r.symlinks++
		}
		w.candidates(f, e, p)
		if e.Kind != "dir" {
			continue // a symlink is never opened, and nothing else can be
		}
		if child, ok := w.descend(f, l, e, p); ok {
			children = append(children, child)
		}
	}
	for i := len(children) - 1; i >= 0; i-- {
		stack = append(stack, children[i])
	}
	return stack
}

// descend decides whether one directory entry becomes a frame: an excluded
// root is passed over silently (the plan wrote its row before the walk
// began), a directory already visited is a cycle or a bind alias, and a
// directory on another mount is decided by the boundary rules.
func (w *walker) descend(f frame, l collect.Listing, e collect.DirEntry, p string) (frame, bool) {
	if w.plan.excludedRoots[p] {
		return frame{}, false
	}
	ident := collect.Identity{Dev: e.Dev, Ino: e.Ino}
	if w.visited[ident] {
		w.addSkip(p, "bind_duplicate", "")
		return frame{}, false
	}
	if w.crossesMount(e, l.Self, f.mntID) {
		w.crossed(e, p)
		return frame{}, false
	}
	w.visited[ident] = true
	return frame{
		path:        p,
		ident:       ident,
		mntID:       f.mntID,
		underHidden: f.underHidden || strings.HasPrefix(e.Name, "."),
	}, true
}

// crossesMount reports whether an entry is on another mount than the
// directory that listed it. The mount id is the exact answer — it tells two
// btrfs subvolumes and a mid-walk automount apart, where st_dev does not —
// and the device is the fallback for a kernel that does not report one
// (PF-7), or for the single entry whose stat happened not to carry it.
func (w *walker) crossesMount(e, self collect.DirEntry, mntID uint64) bool {
	if w.byDev(e) {
		return e.Dev != self.Dev
	}
	return e.MntID != mntID
}

func (w *walker) byDev(e collect.DirEntry) bool { return w.r.mntIDFallback || !e.MntIDKnown }

// crossed records what the walk does with a directory on another mount.
// Every mount mountinfo carried is passed over here, for one of two
// reasons: a mount the plan entered is a root of its own and is walked from
// there, and descending into it from the parent too would report every
// finding under it twice; a mount the plan did not enter already has the
// row that says why. What is left is a mount that appeared after mountinfo
// was read — an automount that fired — and that is unlisted_mount.
func (w *walker) crossed(e collect.DirEntry, p string) {
	if w.byDev(e) {
		if w.deviceEntered(e.Dev) {
			return
		}
		// Without mount ids the only mounts the walk can name are the ones
		// it entered, so a planned root is recognised by its path instead.
		if w.planned[p] {
			return
		}
		w.addSkip(p, "unlisted_mount", "")
		return
	}
	if w.plan.known[int(e.MntID)] {
		return
	}
	w.addSkip(p, "unlisted_mount", "")
}

// deviceEntered reports whether one of the entered mounts is on this
// device, which is how the st_dev fallback tells "a mount I am going to
// walk from its own root" from "a mount I know nothing about". A bind alias
// the plan dropped shares its device with the mount that was kept, so it is
// recognised here too and adds no row.
func (w *walker) deviceEntered(dev uint64) bool {
	for _, r := range w.plan.enter {
		if r.devNum == dev {
			return true
		}
	}
	return false
}

// candidates applies the four conditions of W-4 plus the hidden rule to one
// entry. The unowned rule sees every kind, symlinks included — a symlink
// has an owner, and find -nouser reports it; the mode-based rules see every
// entry that is not a symlink, whose own mode says nothing about the file it
// names.
func (w *walker) candidates(f frame, e collect.DirEntry, p string) {
	uidKnown, uidClass := w.ids.uidKnown(e.UID)
	gidKnown, gidClass := w.ids.gidKnown(e.GID)
	if !uidKnown || !gidKnown {
		w.r.lists.addRow(capUnowned, map[string]any{
			"path": p, "kind": e.Kind, "uid": int(e.UID), "gid": int(e.GID),
			"uid_known": uidKnown, "gid_known": gidKnown,
			"uid_class": uidClass, "gid_class": gidClass,
		})
	}
	w.hidden(f, e, p)
	if e.Kind == "symlink" {
		return
	}
	if e.Mode&0o002 != 0 {
		w.r.lists.addRow(capWorldWritable, map[string]any{
			"path": p, "kind": e.Kind, "sticky": e.Mode&0o1000 != 0,
			"uid": int(e.UID), "gid": int(e.GID),
			"package": "", "package_declared": false, "reference": "unpackaged",
		})
		if e.Kind == "dir" && e.Mode&0o1000 == 0 {
			w.r.lists.addRow(capStickyMissing, map[string]any{
				"path": p, "mode": int(e.Mode), "uid": int(e.UID), "gid": int(e.GID),
			})
		}
	}
	if e.Kind == "regular" && e.Mode&0o6000 != 0 {
		// Every candidate goes into one list; the package join splits it
		// into walk.suid_sgid and walk.suid_sgid_unverified and fills the
		// package and declaration fields, which are initialised here so
		// that a run whose join failed still emits records of one shape.
		w.r.lists.addRow(capSUIDSGID, map[string]any{
			"path": p, "mode": int(e.Mode), "uid": int(e.UID), "gid": int(e.GID),
			"setuid": e.Mode&0o4000 != 0, "setgid": e.Mode&0o2000 != 0,
			"package": "", "package_declared": false,
			"declared_mode": nil, "declared_owner": "", "declared_group": "", "declared_path": "",
			"reference": "unpackaged",
		})
	}
}

// hidden applies A-16: a name beginning with a dot is a candidate unless it
// is already inside a hidden directory (the directory itself was recorded;
// its tree is not a finding), inside a user home at any depth, or a direct
// child of a service home. An allowlisted candidate is still recorded, with
// allowlisted true — the list shows, it never hides — but under a cap of
// its own, so a deployed source tree's .git directories cannot crowd out the
// entries somebody actually hid.
func (w *walker) hidden(f frame, e collect.DirEntry, p string) {
	if f.underHidden || !strings.HasPrefix(e.Name, ".") {
		return
	}
	if underUserHome(p) || directChildOfServiceHome(p, w.plan.homes) {
		return
	}
	allowlisted := hiddenAllowlisted(p, e.Name)
	row := map[string]any{
		"path": p, "kind": e.Kind, "uid": int(e.UID),
		"package": "", "package_declared": false, "reference": "unpackaged",
		"allowlisted": allowlisted,
	}
	if allowlisted {
		w.r.lists.addAllowlistedHidden(row)
		return
	}
	w.r.lists.addRow(capHidden, row)
}

func (w *walker) addSkip(p, reason, detail string) {
	w.r.lists.addRow(capSkipped, map[string]any{"path": p, "reason": reason, "detail": detail})
}

// skipReason maps a failed listing to the closed vocabulary of A-15. A
// directory this process may not search is denied; a directory that is not
// there any more, is not a directory any more, or is not the one that was
// listed, is vanished. Every other errno is vanished too — the vocabulary
// is closed, and a list of reasons that grew a row per errno would be a list
// nothing could be written against — with the errno itself in detail so
// nothing is lost. The errno alone is the detail, not the wrapped error: the
// row already carries the path, and repeating it there would only make two
// runs of one host differ in a field nobody reads.
func skipReason(err error) (reason, detail string) {
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM), errors.Is(err, fs.ErrPermission):
		return "denied", ""
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP),
		errors.Is(err, collect.ErrVanished), errors.Is(err, collect.ErrSymlink):
		return "vanished", ""
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		return "vanished", errno.Error()
	}
	return "vanished", err.Error()
}

// pathUnderHidden reports whether any component of a path is a hidden name,
// which is what the hidden rule would have decided for a directory reached
// by walking down to it. It is asked once per mount, never per entry.
func pathUnderHidden(p string) bool {
	for _, c := range strings.Split(strings.Trim(p, "/"), "/") {
		if strings.HasPrefix(c, ".") {
			return true
		}
	}
	return false
}

// at is the list one cap index names. The indices are constants of
// walk_hidden.go, so the default is unreachable; it panics rather than
// returning nil because a new list added without a case here must fail
// loudly on the first row it is given, not silently drop every one.
func (l *walkLists) at(i int) *[]map[string]any {
	switch i {
	case capSUIDSGID:
		return &l.suid
	case capSUIDUnverified:
		return &l.suidUnverified
	case capWorldWritable:
		return &l.worldWritable
	case capStickyMissing:
		return &l.stickyMissing
	case capUnowned:
		return &l.unowned
	case capHidden:
		return &l.hidden
	case capSkipped:
		return &l.skipped
	}
	panic("walk: no list for cap index")
}

// addRow offers one record to a list. Every row is counted, kept or not, so
// walk.stats.truncated_counts says how many there really were; the row is
// appended while the list is below its cap, and the first refusal sets
// truncated. A full list never stops the walk (§2) — the traversal goes on
// counting, because the count is what tells a reader that the list they are
// looking at is a sample.
//
// The number of rows kept is the number offered clamped to the cap, which is
// why the cap is decided from truncatedCounts rather than from len: the
// hidden list also holds allowlisted rows, which have their own cap and must
// not push the judged ones out.
func (l *walkLists) addRow(i int, row map[string]any) {
	full := l.truncatedCounts[i] >= listCaps[i]
	l.truncatedCounts[i]++
	if full {
		l.truncated[i] = true
		return
	}
	list := l.at(i)
	*list = append(*list, row)
}

// addAllowlistedHidden records a hidden entry the allowlist passed over.
// They share walk.hidden with the judged rows but not its cap: beyond
// allowlistedHiddenCap they are only counted, and they never set truncated
// — a truncated walk.hidden must mean the walk stopped recording entries
// somebody hid, not that a host has many source trees (§2).
func (l *walkLists) addAllowlistedHidden(row map[string]any) {
	if l.allowlistedHidden < allowlistedHiddenCap {
		l.hidden = append(l.hidden, row)
	}
	l.allowlistedHidden++
}

// sort puts every list in path order and walk.skipped in path-then-reason
// order (A-14), which is what makes two walks of one unchanged host produce
// the same bytes however the kernel handed the names over.
func (l *walkLists) sort() {
	for i := 0; i < capCount; i++ {
		if i == capSkipped {
			continue
		}
		list := l.at(i)
		slices.SortStableFunc(*list, func(x, y map[string]any) int {
			return strings.Compare(rowField(x, "path"), rowField(y, "path"))
		})
	}
	slices.SortStableFunc(l.skipped, func(x, y map[string]any) int {
		if c := strings.Compare(rowField(x, "path"), rowField(y, "path")); c != 0 {
			return c
		}
		return strings.Compare(rowField(x, "reason"), rowField(y, "reason"))
	})
}

func rowField(row map[string]any, name string) string {
	s, _ := row[name].(string)
	return s
}
