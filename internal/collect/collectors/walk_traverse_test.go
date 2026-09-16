//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// The scripted trees below are synthetic: no path, uid or name here came
// from a real host. They are written as a map of directory path -> entries
// and turned into collect.Listings by buildTree, which assigns every
// directory a unique (dev, ino) and makes the entry in the parent agree
// with the listing the child path has — the identity check the walk's
// ReadDir makes would otherwise fail on every descent.

// entOpt adjusts one scripted entry. Only the fields a test cares about are
// ever set by hand; buildTree fills the rest.
type entOpt func(*collect.DirEntry)

func owner(uid, gid uint32) entOpt { return func(e *collect.DirEntry) { e.UID, e.GID = uid, gid } }

// inode pins an entry's inode number, which is how a test scripts two names
// for one directory (a bind alias) or an entry whose identity will not match
// the directory that is opened.
func inode(n uint64) entOpt { return func(e *collect.DirEntry) { e.Ino = n } }

// device pins an entry's device, for the st_dev fallback where a mount
// boundary is a change of device rather than of mount id.
func device(n uint64) entOpt { return func(e *collect.DirEntry) { e.Dev = n } }

func treeDir(name string, mode uint32, opts ...entOpt) collect.DirEntry {
	return treeEnt(name, "dir", mode, opts)
}

func treeFile(name string, mode uint32, opts ...entOpt) collect.DirEntry {
	return treeEnt(name, "regular", mode, opts)
}

// treeLink is a symlink with the 0o777 mode every symlink has on Linux —
// so a test that walks one proves the mode rules skip symlinks rather than
// reporting every link as world-writable.
func treeLink(name string, opts ...entOpt) collect.DirEntry {
	return treeEnt(name, "symlink", 0o777, opts)
}

func treeEnt(name, kind string, mode uint32, opts []entOpt) collect.DirEntry {
	e := collect.DirEntry{Name: name, Kind: kind, Mode: mode, MntIDKnown: true}
	for _, o := range opts {
		o(&e)
	}
	return e
}

// devFor is the device number the scripted tree gives a mount: one device
// per mount, as a real host has for everything except bind mounts (the plan
// drops those) and btrfs subvolumes.
func devFor(mnt uint64) uint64 { return 2048 + mnt }

// buildTree turns a directory path -> entries description into the listings
// fsAccess serves. Every directory the description mentions gets a unique
// inode, its device and mount id from the mount it is on (mounts names the
// mount points), and the entry in the parent carries exactly the identity
// the child's listing reports. A directory that is mentioned as an entry but
// has no entry of its own in spec has no listing: ReadDir answers ENOENT for
// it, which is how a test scripts a directory that vanished.
func buildTree(spec map[string][]collect.DirEntry, mounts map[string]uint64) map[string]collect.Listing {
	type ident struct {
		dev, ino, mnt uint64
		known         bool
		mode          uint32
	}
	parentOf := map[string]collect.DirEntry{}
	set := map[string]bool{}
	for p, entries := range spec {
		set[p] = true
		for _, e := range entries {
			if e.Kind == "dir" {
				c := path.Join(p, e.Name)
				set[c] = true
				parentOf[c] = e
			}
		}
	}
	sorted := make([]string, 0, len(set))
	for p := range set {
		sorted = append(sorted, p)
	}
	slices.Sort(sorted) // a parent always sorts before its children

	id := map[string]ident{}
	for i, p := range sorted {
		e, hasParent := parentOf[p]
		cur := ident{mnt: 1, known: true, mode: 0o755}
		if hasParent {
			cur.mode, cur.known = e.Mode, e.MntIDKnown
		}
		switch {
		case mounts[p] != 0:
			cur.mnt = mounts[p]
		case p != "/":
			cur.mnt = id[path.Dir(p)].mnt
		}
		cur.dev, cur.ino = devFor(cur.mnt), uint64(1000+i)
		if hasParent && e.Dev != 0 {
			cur.dev = e.Dev
		}
		if hasParent && e.Ino != 0 {
			cur.ino = e.Ino
		}
		id[p] = cur
	}

	out := map[string]collect.Listing{}
	n := uint64(0)
	for _, p := range sorted {
		entries, scripted := spec[p]
		if !scripted {
			continue
		}
		cur := id[p]
		l := collect.Listing{Self: collect.DirEntry{
			Kind: "dir", Mode: cur.mode, Dev: cur.dev, Ino: cur.ino, MntID: cur.mnt, MntIDKnown: cur.known,
		}}
		for _, e := range entries {
			if e.Kind == "dir" {
				c := id[path.Join(p, e.Name)]
				e.Dev, e.Ino, e.MntID = c.dev, c.ino, c.mnt
			} else {
				if e.Dev == 0 {
					e.Dev = cur.dev
				}
				if e.Ino == 0 {
					n++
					e.Ino = 9000 + n
				}
				e.MntID = cur.mnt
			}
			l.Entries = append(l.Entries, e)
		}
		out[p] = l
	}
	return out
}

// forgetMntIDs is a kernel without STATX_MNT_ID: every stat still reports a
// device, none reports a mount id.
func forgetMntIDs(tree map[string]collect.Listing) map[string]collect.Listing {
	for p, l := range tree {
		l.Self.MntIDKnown = false
		entries := slices.Clone(l.Entries)
		for i := range entries {
			entries[i].MntIDKnown = false
		}
		l.Entries = entries
		tree[p] = l
	}
	return tree
}

// setSelf rewrites one listing's own identity, which is how a test scripts
// the directory that was swapped between being listed and being opened.
func setSelf(tree map[string]collect.Listing, p string, dev, ino uint64) {
	l := tree[p]
	l.Self.Dev, l.Self.Ino = dev, ino
	tree[p] = l
}

// planSpec describes the mount plan the traversal is handed, without going
// through planMounts: which mounts are entered (id -> mount point), which
// ids mountinfo carried but the plan did not enter, and the roots it
// excluded (each already carrying the skipped row the plan wrote).
type planSpec struct {
	enter    map[int]string
	known    []int
	excluded []string
	skipped  []skipRow
}

func (s planSpec) build() mountPlan {
	p := mountPlan{
		enter:         map[int]mountRow{},
		known:         map[int]bool{},
		excludedRoots: map[string]bool{},
		homes:         walkHomes(),
		rootType:      "ext4",
		rootWalkable:  true,
	}
	for id, point := range s.enter {
		p.enter[id] = mountRow{id: id, dev: fmt.Sprintf("0:%d", id), devNum: devFor(uint64(id)), root: "/", mountPoint: point, fstype: "ext4"}
		p.known[id] = true
	}
	for _, id := range s.known {
		p.known[id] = true
	}
	for _, root := range s.excluded {
		p.excludedRoots[root] = true
		if slices.ContainsFunc(s.skipped, func(r skipRow) bool { return r.path == root }) {
			continue // the caller gave the root a row of its own
		}
		p.skipped = append(p.skipped, skipRow{path: root, reason: "container_storage"})
	}
	p.skipped = append(p.skipped, s.skipped...)
	slices.SortStableFunc(p.skipped, func(a, b skipRow) int { return strings.Compare(a.path, b.path) })
	return p
}

// walkHomes is the home set of the scripted passwd file the trees below
// assume: alice at /home/alice, postgres at /var/lib/postgresql, www-data at
// /var/www. It goes through the real classifier, so the hidden rule under
// test is the one the collector will use.
func walkHomes() []homeRoot {
	return classifyHomes([]passwdRow{
		{name: "root", uid: 0, gid: 0, home: "/root"},
		{name: "alice", uid: 1000, gid: 1000, home: "/home/alice"},
		{name: "postgres", uid: 113, gid: 113, home: "/var/lib/postgresql"},
		{name: "www-data", uid: 33, gid: 33, home: "/var/www"},
	})
}

// walkIDs stands in for loadIDTables: 0, 33, 113 and 1000 are accounts,
// 100000..165535 is alice's delegated sub-id range, systemd's dynamic range
// answers for itself, and everything else is unknown.
func walkIDs() idTables {
	class := func(id uint32) (bool, string) {
		switch {
		case id == 0 || id == 33 || id == 113 || id == 1000:
			return true, classPasswd
		case id >= 100000 && id < 165536:
			return true, classSubID
		case id >= dynamicUIDMin && id <= dynamicUIDMax:
			return true, classDynamic
		}
		return false, classUnknown
	}
	return idTables{uidKnown: class, gidKnown: class}
}

// frozenClock never advances, so a test that is not about the budget cannot
// trip it.
func frozenClock() walkClock {
	start := time.Unix(1700000000, 0)
	return walkClock{start: start, now: func() time.Time { return start }}
}

// traverseTree traverses with no budget and no entry limit: both are only
// enforced when positive, so a test says what it is about. It is the
// traversal alone — the collector's own runWalk is exercised by walk_test.go.
func traverseTree(a collect.Access, plan mountPlan) walkResult {
	return traverse(context.Background(), a, plan, walkIDs(), collect.WalkOptions{}, frozenClock())
}

func rowPaths(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r["path"].(string))
	}
	return out
}

func rowFor(t *testing.T, rows []map[string]any, p string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if r["path"] == p {
			return r
		}
	}
	t.Fatalf("no row for %s in %v", p, rowPaths(rows))
	return nil
}

func sortedReadDirs(a *fsAccess) []string {
	out := slices.Clone(a.readDirs)
	slices.Sort(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// mainTree is the tree TestTraverseSortsEveryCandidate and the determinism
// test walk: one root filesystem (mount 1), a tmpfs at /tmp (mount 2), an
// excluded /run, and one entry for every candidate rule and every home
// exemption.
func mainTree() (*fsAccess, mountPlan) {
	spec := map[string][]collect.DirEntry{
		"/": {
			treeDir("etc", 0o755),
			treeDir("home", 0o755),
			treeDir("run", 0o755),
			treeDir("tmp", 0o1777),
			treeDir("usr", 0o755),
			treeDir("var", 0o755),
		},
		"/etc":             {treeFile(".pwd.lock", 0o600)},
		"/home":            {treeDir(".snapshots", 0o755), treeDir("alice", 0o700, owner(1000, 1000))},
		"/home/.snapshots": {},
		"/home/alice":      {treeFile(".bashrc", 0o644, owner(1000, 1000))},
		"/tmp":             {treeDir(".X11-unix", 0o1777)},
		"/tmp/.X11-unix":   {},
		"/usr":             {treeDir("bin", 0o755), treeDir("sbin", 0o755)},
		"/usr/bin": {
			treeLink("link", owner(70000, 0)),
			treeFile("passwd", 0o4755),
			treeFile("python3", 0o755),
			treeFile("su", 0o4755),
		},
		"/usr/sbin":            {treeFile(".hidden-helper", 0o755, owner(70000, 0))},
		"/var":                 {treeDir("lib", 0o755), treeDir("tmp", 0o755), treeDir("www", 0o755)},
		"/var/lib":             {treeDir("postgresql", 0o700, owner(113, 113)), treeDir("x", 0o755), treeDir("y", 0o755), treeDir("z", 0o755)},
		"/var/lib/postgresql":  {treeFile(".psql_history", 0o600, owner(113, 113))},
		"/var/lib/x":           {treeDir("spool", 0o777)},
		"/var/lib/x/spool":     {},
		"/var/lib/y":           {treeFile("f", 0o644, owner(100005, 0))},
		"/var/lib/z":           {treeFile("g", 0o644, owner(61200, 0))},
		"/var/tmp":             {treeDir("open", 0o777)},
		"/var/tmp/open":        {},
		"/var/www":             {treeDir("html", 0o755, owner(33, 33))},
		"/var/www/html":        {treeDir(".cache", 0o755, owner(33, 33))},
		"/var/www/html/.cache": {},
	}
	// The mount ids are deliberately not in mount-point order: mountinfo
	// numbers mounts in the order they were made, and the walk's roots are
	// sorted by mount point, not by id.
	tree := buildTree(spec, map[string]uint64{"/": 7, "/tmp": 3})
	plan := planSpec{
		enter:    map[int]string{7: "/", 3: "/tmp"},
		excluded: []string{"/run"},
		skipped:  []skipRow{{path: "/run", reason: "pseudo_path"}},
	}.build()
	return &fsAccess{tree: tree}, plan
}

// Every candidate rule of W-4 over one tree, with the home exemptions of
// A-16 and the id classes of W-5. Each list comes back sorted by path
// (A-14) and each record carries exactly the fields the registry names.
func TestTraverseSortsEveryCandidate(t *testing.T) {
	a, plan := mainTree()
	r := traverseTree(a, plan)

	if !r.complete || r.stopReason != "" || r.lastPath != "" {
		t.Errorf("complete = %v, stopReason = %q, lastPath = %q; want a finished walk", r.complete, r.stopReason, r.lastPath)
	}
	if r.mntIDFallback {
		t.Error("mntIDFallback = true although every listing reported a mount id")
	}
	if r.entries != 32 || r.dirs != 22 || r.files != 9 || r.symlinks != 1 {
		t.Errorf("entries/dirs/files/symlinks = %d/%d/%d/%d, want 32/22/9/1", r.entries, r.dirs, r.files, r.symlinks)
	}

	cases := []struct {
		name string
		rows []map[string]any
		want []string
	}{
		{"suid", r.lists.suid, []string{"/usr/bin/passwd", "/usr/bin/su"}},
		{"sticky_missing", r.lists.stickyMissing, []string{"/var/lib/x/spool", "/var/tmp/open"}},
		{"world_writable", r.lists.worldWritable, []string{"/tmp", "/tmp/.X11-unix", "/var/lib/x/spool", "/var/tmp/open"}},
		{"hidden", r.lists.hidden, []string{"/etc/.pwd.lock", "/home/.snapshots", "/tmp/.X11-unix", "/usr/sbin/.hidden-helper", "/var/www/html/.cache"}},
		{"unowned", r.lists.unowned, []string{"/usr/bin/link", "/usr/sbin/.hidden-helper"}},
	}
	for _, c := range cases {
		if got := rowPaths(c.rows); !slices.Equal(got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	if len(r.lists.suidUnverified) != 0 {
		t.Errorf("suidUnverified = %v, want empty until the join splits the candidates", rowPaths(r.lists.suidUnverified))
	}

	// One record per list, whole, so the field set is pinned and not only
	// the paths.
	want := map[string]map[string]any{
		"suid": {
			"path": "/usr/bin/su", "mode": 0o4755, "uid": 0, "gid": 0, "setuid": true, "setgid": false,
			"package": "", "package_declared": false, "declared_mode": nil, "declared_owner": "",
			"declared_group": "", "declared_path": "", "reference": "unpackaged",
		},
		"world_writable": {
			"path": "/tmp", "kind": "dir", "sticky": true, "uid": 0, "gid": 0,
			"package": "", "package_declared": false, "reference": "unpackaged",
		},
		"sticky_missing": {"path": "/var/tmp/open", "mode": 0o777, "uid": 0, "gid": 0},
		"unowned": {
			"path": "/usr/bin/link", "kind": "symlink", "uid": 70000, "gid": 0,
			"uid_known": false, "gid_known": true, "uid_class": classUnknown, "gid_class": classPasswd,
		},
		"hidden": {
			"path": "/etc/.pwd.lock", "kind": "regular", "uid": 0, "package": "",
			"package_declared": false, "reference": "unpackaged", "allowlisted": true,
		},
	}
	got := map[string]map[string]any{
		"suid":           rowFor(t, r.lists.suid, "/usr/bin/su"),
		"world_writable": rowFor(t, r.lists.worldWritable, "/tmp"),
		"sticky_missing": rowFor(t, r.lists.stickyMissing, "/var/tmp/open"),
		"unowned":        rowFor(t, r.lists.unowned, "/usr/bin/link"),
		"hidden":         rowFor(t, r.lists.hidden, "/etc/.pwd.lock"),
	}
	for _, list := range sortedKeys(want) {
		if !reflect.DeepEqual(got[list], want[list]) {
			t.Errorf("%s record = %#v, want %#v", list, got[list], want[list])
		}
	}
	// A hidden entry that is not allowlisted says so rather than omitting
	// the field.
	if row := rowFor(t, r.lists.hidden, "/home/.snapshots"); row["allowlisted"] != false {
		t.Errorf("/home/.snapshots allowlisted = %v, want false", row["allowlisted"])
	}
	if r.lists.allowlistedHidden != 2 {
		t.Errorf("allowlistedHidden = %d, want 2 (/etc/.pwd.lock and /tmp/.X11-unix)", r.lists.allowlistedHidden)
	}
	if r.lists.truncatedCounts[capHidden] != 3 {
		t.Errorf("truncatedCounts[hidden] = %d, want 3 non-allowlisted candidates", r.lists.truncatedCounts[capHidden])
	}

	// The plan's rows are the walk's starting skipped list, and the
	// traversal added nothing to them.
	wantSkipped := []map[string]any{{"path": "/run", "reason": "pseudo_path", "detail": ""}}
	if !reflect.DeepEqual(r.lists.skipped, wantSkipped) {
		t.Errorf("skipped = %v, want the plan's rows %v", r.lists.skipped, wantSkipped)
	}
	// The order directories are read in is part of the contract, not an
	// accident: it is what decides which subtree a budget-stopped walk saw.
	// Depth first, roots in mount-point order, entries in the order the
	// listing gave them, and every scripted directory exactly once.
	wantOrder := []string{
		"/", "/etc", "/home", "/home/.snapshots", "/home/alice",
		"/usr", "/usr/bin", "/usr/sbin",
		"/var", "/var/lib", "/var/lib/postgresql", "/var/lib/x", "/var/lib/x/spool",
		"/var/lib/y", "/var/lib/z", "/var/tmp", "/var/tmp/open",
		"/var/www", "/var/www/html", "/var/www/html/.cache",
		"/tmp", "/tmp/.X11-unix",
	}
	if !slices.Equal(a.readDirs, wantOrder) {
		t.Errorf("listed %v, want %v in this order", a.readDirs, wantOrder)
	}
	if got, want := sortedReadDirs(a), sortedKeys(a.tree); !slices.Equal(got, want) {
		t.Errorf("listed %v, want every scripted directory: %v", got, want)
	}
}

// A directory that cannot be listed is one skipped row and nothing else: its
// siblings are still walked and the walk still finishes (A-15).
func TestTraverseRecordsDeniedAndVanished(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/": {
			treeDir("acces", 0o755),
			treeDir("eio", 0o755),
			treeDir("eloop", 0o755),
			treeDir("enoent", 0o755),
			treeDir("enotdir", 0o755),
			treeDir("eperm", 0o755),
			treeDir("gone", 0o755),
			treeDir("ok", 0o755),
			treeDir("symlinked", 0o755),
		},
		"/ok": {treeFile("su", 0o4755)},
	}
	a := &fsAccess{
		tree: buildTree(spec, nil),
		dirErrs: map[string]error{
			"/acces":     unix.EACCES,
			"/eperm":     unix.EPERM,
			"/enoent":    unix.ENOENT,
			"/enotdir":   unix.ENOTDIR,
			"/eloop":     unix.ELOOP,
			"/symlinked": collect.ErrSymlink,
			"/gone":      collect.ErrVanished,
			"/eio":       unix.EIO,
		},
	}
	// Two mounts at one path — an overmount the plan recorded twice — are
	// what puts the reason tie-break of A-14 to work.
	plan := planSpec{enter: map[int]string{1: "/"}, skipped: []skipRow{
		{path: "/mnt", reason: "excluded_type", detail: "nfs4"},
		{path: "/mnt", reason: "bind_duplicate"},
	}}.build()
	r := traverseTree(a, plan)

	want := []map[string]any{
		{"path": "/acces", "reason": "denied", "detail": ""},
		{"path": "/eio", "reason": "vanished", "detail": "input/output error"},
		{"path": "/eloop", "reason": "vanished", "detail": ""},
		{"path": "/enoent", "reason": "vanished", "detail": ""},
		{"path": "/enotdir", "reason": "vanished", "detail": ""},
		{"path": "/eperm", "reason": "denied", "detail": ""},
		{"path": "/gone", "reason": "vanished", "detail": ""},
		{"path": "/mnt", "reason": "bind_duplicate", "detail": ""},
		{"path": "/mnt", "reason": "excluded_type", "detail": "nfs4"},
		{"path": "/symlinked", "reason": "vanished", "detail": ""},
	}
	if !reflect.DeepEqual(r.lists.skipped, want) {
		t.Errorf("skipped = %v, want %v", r.lists.skipped, want)
	}
	if !r.complete || r.stopReason != "" {
		t.Errorf("complete = %v, stopReason = %q; a directory that cannot be listed does not stop the walk", r.complete, r.stopReason)
	}
	if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/ok/su"}) {
		t.Errorf("suid = %v, want the sibling directory still walked", got)
	}
}

// The directory that was opened is not the one the parent listed: ReadDir
// answers ErrVanished, the row says vanished and nothing inside it is
// recorded.
func TestTraverseIdentityMismatch(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/":  {treeDir("a", 0o755)},
		"/a": {treeFile("su", 0o4755)},
	}
	tree := buildTree(spec, nil)
	setSelf(tree, "/a", devFor(1), 4242) // the entry in / still names the old inode
	a := &fsAccess{tree: tree}

	r := traverseTree(a, planSpec{enter: map[int]string{1: "/"}}.build())

	want := []map[string]any{{"path": "/a", "reason": "vanished", "detail": ""}}
	if !reflect.DeepEqual(r.lists.skipped, want) {
		t.Errorf("skipped = %v, want %v", r.lists.skipped, want)
	}
	if len(r.lists.suid) != 0 {
		t.Errorf("suid = %v, want nothing from a directory that was swapped", rowPaths(r.lists.suid))
	}
	if r.entries != 1 {
		t.Errorf("entries = %d, want only the entry in / that named it", r.entries)
	}
}

// A mount id the plan entered is walked from its own root and never a second
// time from the parent that listed it; an id mountinfo carried but the plan
// did not enter is passed over silently (the plan already recorded it); an
// id mountinfo never carried is unlisted_mount (W-3).
func TestTraverseHonoursMountBoundaries(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/": {
			treeDir("entered", 0o755),
			treeDir("notentered", 0o755),
			treeDir("automount", 0o755),
		},
		"/entered":    {treeFile("su", 0o4755)},
		"/notentered": {treeFile("nfs-su", 0o4755)},
		"/automount":  {treeFile("auto-su", 0o4755)},
	}
	tree := buildTree(spec, map[string]uint64{"/": 1, "/entered": 2, "/notentered": 7, "/automount": 9})
	a := &fsAccess{tree: tree}

	plan := planSpec{enter: map[int]string{1: "/", 2: "/entered"}, known: []int{7}}.build()
	r := traverseTree(a, plan)

	if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/entered/su"}) {
		t.Errorf("suid = %v, want only the entered mount's file", got)
	}
	want := []map[string]any{{"path": "/automount", "reason": "unlisted_mount", "detail": ""}}
	if !reflect.DeepEqual(r.lists.skipped, want) {
		t.Errorf("skipped = %v, want %v", r.lists.skipped, want)
	}
	if got, want := sortedReadDirs(a), []string{"/", "/entered"}; !slices.Equal(got, want) {
		t.Errorf("listed %v, want %v — an entered mount is walked once, from its own root", got, want)
	}

	// The id the kernel reports for a root's own directory replaces the one
	// mountinfo carried: a walk that kept mountinfo's would read every entry
	// of that mount as a boundary into a mount nothing had heard of.
	t.Run("kernel mount id wins", func(t *testing.T) {
		spec := map[string][]collect.DirEntry{"/": {treeDir("a", 0o755)}, "/a": {treeFile("su", 0o4755)}}
		a := &fsAccess{tree: buildTree(spec, map[string]uint64{"/": 4})}
		r := traverseTree(a, planSpec{enter: map[int]string{9: "/"}}.build())
		if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/a/su"}) {
			t.Errorf("suid = %v, want the root's own subtree walked", got)
		}
		if len(r.lists.skipped) != 0 {
			t.Errorf("skipped = %v, want nothing", r.lists.skipped)
		}
	})
}

// A (dev, ino) already visited is bind_duplicate and is not descended, both
// for a second name of one directory and for a second root on it.
func TestTraverseBreaksCycles(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/":  {treeDir("a", 0o755, inode(4100)), treeDir("b", 0o755, inode(4100))},
		"/a": {treeFile("su", 0o4755)},
		"/b": {treeFile("su", 0o4755)},
	}
	a := &fsAccess{tree: buildTree(spec, nil)}
	r := traverseTree(a, planSpec{enter: map[int]string{1: "/"}}.build())

	if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/a/su"}) {
		t.Errorf("suid = %v, want the directory reported once", got)
	}
	want := []map[string]any{{"path": "/b", "reason": "bind_duplicate", "detail": ""}}
	if !reflect.DeepEqual(r.lists.skipped, want) {
		t.Errorf("skipped = %v, want %v", r.lists.skipped, want)
	}
	if slices.Contains(a.readDirs, "/b") {
		t.Errorf("listed %v, want /b never opened", a.readDirs)
	}

	// Two roots on one directory — an alias the plan failed to drop — walk
	// once, for the same reason.
	rootSpec := map[string][]collect.DirEntry{
		"/one": {treeFile("su", 0o4755)},
		"/two": {treeFile("su", 0o4755)},
	}
	tree := buildTree(rootSpec, map[string]uint64{"/one": 1, "/two": 2})
	setSelf(tree, "/two", devFor(1), tree["/one"].Self.Ino)
	rr := traverseTree(&fsAccess{tree: tree}, planSpec{enter: map[int]string{1: "/one", 2: "/two"}}.build())
	if got := rowPaths(rr.lists.suid); !slices.Equal(got, []string{"/one/su"}) {
		t.Errorf("suid = %v, want one row from two roots on one directory", got)
	}
	if got := rowPaths(rr.lists.skipped); !slices.Equal(got, []string{"/two"}) {
		t.Errorf("skipped = %v, want the second root recorded once", got)
	}
}

// A symlink is an entry, never a directory to open, whatever it points at.
func TestTraverseNeverFollowsSymlinks(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/": {treeLink("link"), treeDir("real", 0o755)},
		"/real": {
			treeLink("inner"),
			treeFile("su", 0o4755),
		},
	}
	a := &fsAccess{tree: buildTree(spec, nil), links: map[string]string{"/link": "/real", "/real/inner": "/real"}}
	r := traverseTree(a, planSpec{enter: map[int]string{1: "/"}}.build())

	for _, p := range []string{"/link", "/real/inner"} {
		if slices.Contains(a.readDirs, p) {
			t.Errorf("ReadDir(%s) was called: %v", p, a.readDirs)
		}
	}
	if r.symlinks != 2 || r.dirs != 1 {
		t.Errorf("symlinks/dirs = %d/%d, want 2/1", r.symlinks, r.dirs)
	}
	if len(r.lists.worldWritable) != 0 {
		t.Errorf("worldWritable = %v, want nothing: a symlink's 0o777 mode is not a finding", rowPaths(r.lists.worldWritable))
	}
	if len(r.lists.skipped) != 0 {
		t.Errorf("skipped = %v, want nothing: a symlink is not a directory the walk refused", r.lists.skipped)
	}
}

// An excluded root is not entered and adds no second row — the plan already
// wrote one — and a path of the excluded set that is a file is simply a
// file. A mount whose mount point lies under an excluded root is not walked
// either, however the plan listed it.
func TestTraverseSkipsExcludedRoots(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/": {
			treeDir("store", 0o755),
			treeFile("marker", 0o666),
			treeDir("data", 0o755),
		},
		"/store":    {treeFile("su", 0o4755)},
		"/data":     {treeDir("sub", 0o755)},
		"/data/sub": {treeFile("su", 0o4755)},
	}
	tree := buildTree(spec, map[string]uint64{"/": 1, "/data/sub": 3})
	a := &fsAccess{tree: tree}
	plan := planSpec{
		enter:    map[int]string{1: "/", 3: "/data/sub"},
		excluded: []string{"/store", "/marker", "/data"},
	}.build()

	r := traverseTree(a, plan)

	if slices.Contains(a.readDirs, "/store") || slices.Contains(a.readDirs, "/data") || slices.Contains(a.readDirs, "/data/sub") {
		t.Errorf("listed %v, want no excluded root entered", a.readDirs)
	}
	if got := rowPaths(r.lists.skipped); !slices.Equal(got, []string{"/data", "/marker", "/store"}) {
		t.Errorf("skipped = %v, want exactly the plan's three rows", got)
	}
	if got := rowPaths(r.lists.worldWritable); !slices.Equal(got, []string{"/marker"}) {
		t.Errorf("worldWritable = %v, want the excluded path that is a file judged as one", got)
	}
	if len(r.lists.suid) != 0 {
		t.Errorf("suid = %v, want nothing from inside an excluded root", rowPaths(r.lists.suid))
	}
}

// Each of the three limits stops the traversal where it stands, names
// itself and names the directory it was about to read.
func TestTraverseBudgets(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/":  {treeDir("a", 0o755), treeDir("b", 0o755), treeDir("c", 0o755)},
		"/a": {treeFile("1", 0o644), treeFile("2", 0o644), treeFile("3", 0o644)},
		"/b": {treeFile("1", 0o644)},
		"/c": {treeFile("1", 0o644)},
	}
	newAccess := func() *fsAccess { return &fsAccess{tree: buildTree(spec, nil)} }
	plan := planSpec{enter: map[int]string{1: "/"}}.build()

	t.Run("entry_budget", func(t *testing.T) {
		a := newAccess()
		r := traverse(context.Background(), a, plan, walkIDs(), collect.WalkOptions{MaxEntries: 5}, frozenClock())
		if r.complete || r.stopReason != "entry_budget" || r.lastPath != "/b" {
			t.Errorf("complete/stopReason/lastPath = %v/%q/%q, want false/entry_budget//b", r.complete, r.stopReason, r.lastPath)
		}
		if r.entries != 6 {
			t.Errorf("entries = %d, want the 6 seen before the limit was noticed", r.entries)
		}
		if slices.Contains(a.readDirs, "/b") || slices.Contains(a.readDirs, "/c") {
			t.Errorf("listed %v, want the walk stopped before /b", a.readDirs)
		}
	})

	t.Run("time_budget", func(t *testing.T) {
		a := newAccess()
		start := time.Unix(1700000000, 0)
		calls := 0
		clock := walkClock{start: start, now: func() time.Time {
			calls++
			if calls > 2 {
				return start.Add(9 * time.Minute)
			}
			return start
		}}
		r := traverse(context.Background(), a, plan, walkIDs(), collect.WalkOptions{Budget: time.Minute}, clock)
		if r.complete || r.stopReason != "time_budget" || r.lastPath != "/b" {
			t.Errorf("complete/stopReason/lastPath = %v/%q/%q, want false/time_budget//b", r.complete, r.stopReason, r.lastPath)
		}
		if got, want := sortedReadDirs(a), []string{"/", "/a"}; !slices.Equal(got, want) {
			t.Errorf("listed %v, want %v", got, want)
		}
	})

	t.Run("deadline", func(t *testing.T) {
		a := newAccess()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := traverse(ctx, a, plan, walkIDs(), collect.WalkOptions{}, frozenClock())
		if r.complete || r.stopReason != "deadline" || r.lastPath != "/" {
			t.Errorf("complete/stopReason/lastPath = %v/%q/%q, want false/deadline//", r.complete, r.stopReason, r.lastPath)
		}
		if len(a.readDirs) != 0 {
			t.Errorf("listed %v, want nothing after the context was cancelled", a.readDirs)
		}
	})
}

// A full list is written truncated and the walk goes on (§2): every row is
// counted whether it was kept or not, and the allowlisted hidden rows have
// a cap and a counter of their own that never sets truncated.
func TestTraverseCapsWithoutStopping(t *testing.T) {
	t.Run("world_writable", func(t *testing.T) {
		wide := make([]collect.DirEntry, 0, 2001)
		for i := 0; i < 2001; i++ {
			wide = append(wide, treeFile(fmt.Sprintf("w%05d", i), 0o666))
		}
		spec := map[string][]collect.DirEntry{
			"/":       {treeDir("a-wide", 0o755), treeDir("z-late", 0o755)},
			"/a-wide": wide,
			"/z-late": {treeFile("su", 0o4755)},
		}
		a := &fsAccess{tree: buildTree(spec, nil)}
		r := traverseTree(a, planSpec{enter: map[int]string{1: "/"}}.build())

		if len(r.lists.worldWritable) != listCaps[capWorldWritable] {
			t.Errorf("worldWritable kept %d rows, want %d", len(r.lists.worldWritable), listCaps[capWorldWritable])
		}
		if !r.lists.truncated[capWorldWritable] || r.lists.truncatedCounts[capWorldWritable] != 2001 {
			t.Errorf("truncated/count = %v/%d, want true/2001", r.lists.truncated[capWorldWritable], r.lists.truncatedCounts[capWorldWritable])
		}
		if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/z-late/su"}) {
			t.Errorf("suid = %v, want the directory walked after the cap was reached", got)
		}
		if !r.complete || r.stopReason != "" {
			t.Errorf("complete = %v, stopReason = %q; a full list never stops the walk", r.complete, r.stopReason)
		}
	})

	t.Run("hidden", func(t *testing.T) {
		many := make([]collect.DirEntry, 0, 10001)
		for i := 0; i < 10001; i++ {
			many = append(many, treeFile(fmt.Sprintf(".h%05d", i), 0o644))
		}
		spec := map[string][]collect.DirEntry{"/": {treeDir("opt", 0o755)}, "/opt": many}
		r := traverseTree(&fsAccess{tree: buildTree(spec, nil)}, planSpec{enter: map[int]string{1: "/"}}.build())

		if len(r.lists.hidden) != listCaps[capHidden] {
			t.Errorf("hidden kept %d rows, want %d", len(r.lists.hidden), listCaps[capHidden])
		}
		if !r.lists.truncated[capHidden] || r.lists.truncatedCounts[capHidden] != 10001 {
			t.Errorf("truncated/count = %v/%d, want true/10001", r.lists.truncated[capHidden], r.lists.truncatedCounts[capHidden])
		}
		if r.lists.allowlistedHidden != 0 {
			t.Errorf("allowlistedHidden = %d, want 0", r.lists.allowlistedHidden)
		}
	})

	t.Run("allowlisted_hidden", func(t *testing.T) {
		spec := map[string][]collect.DirEntry{"/": {treeDir("opt", 0o755)}}
		top := make([]collect.DirEntry, 0, 2001)
		for i := 0; i < 2001; i++ {
			name := fmt.Sprintf("p%05d", i)
			top = append(top, treeDir(name, 0o755))
			spec["/opt/"+name] = []collect.DirEntry{treeFile(".git", 0o644)}
		}
		spec["/opt"] = top
		r := traverseTree(&fsAccess{tree: buildTree(spec, nil)}, planSpec{enter: map[int]string{1: "/"}}.build())

		if len(r.lists.hidden) != allowlistedHiddenCap {
			t.Errorf("hidden kept %d rows, want %d allowlisted ones", len(r.lists.hidden), allowlistedHiddenCap)
		}
		if r.lists.allowlistedHidden != 2001 {
			t.Errorf("allowlistedHidden = %d, want 2001", r.lists.allowlistedHidden)
		}
		if r.lists.truncated[capHidden] || r.lists.truncatedCounts[capHidden] != 0 {
			t.Errorf("truncated/count = %v/%d, want false/0: an allowlisted row never truncates the list", r.lists.truncated[capHidden], r.lists.truncatedCounts[capHidden])
		}
		if !r.complete {
			t.Error("complete = false, want the walk to have finished")
		}
	})

	t.Run("skipped", func(t *testing.T) {
		plan := planSpec{enter: map[int]string{1: "/"}}.build()
		for i := 0; i < listCaps[capSkipped]+1; i++ {
			plan.skipped = append(plan.skipped, skipRow{path: fmt.Sprintf("/s%05d", i), reason: "container_storage"})
		}
		r := traverseTree(&fsAccess{tree: buildTree(map[string][]collect.DirEntry{"/": {}}, nil)}, plan)
		if len(r.lists.skipped) != listCaps[capSkipped] || !r.lists.truncated[capSkipped] {
			t.Errorf("skipped kept %d rows, truncated %v; want %d and true — the plan's rows count toward the cap",
				len(r.lists.skipped), r.lists.truncated[capSkipped], listCaps[capSkipped])
		}
		if r.lists.truncatedCounts[capSkipped] != listCaps[capSkipped]+1 {
			t.Errorf("truncatedCounts[skipped] = %d, want %d", r.lists.truncatedCounts[capSkipped], listCaps[capSkipped]+1)
		}
	})
}

// Same tree, same bytes: twice over, and once with the listings handed back
// in the opposite order (A-14).
func TestTraverseIsDeterministic(t *testing.T) {
	encode := func(t *testing.T, r walkResult) string {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"suid": r.lists.suid, "suid_unverified": r.lists.suidUnverified,
			"world_writable": r.lists.worldWritable, "sticky_missing": r.lists.stickyMissing,
			"unowned": r.lists.unowned, "hidden": r.lists.hidden, "skipped": r.lists.skipped,
			"counts": r.lists.truncatedCounts, "truncated": r.lists.truncated,
			"allowlisted_hidden": r.lists.allowlistedHidden,
			"entries":            r.entries, "dirs": r.dirs, "files": r.files, "symlinks": r.symlinks,
			"complete": r.complete, "stop_reason": r.stopReason, "last_path": r.lastPath,
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}

	a1, plan := mainTree()
	first := encode(t, traverseTree(a1, plan))

	a2, plan2 := mainTree()
	if second := encode(t, traverseTree(a2, plan2)); second != first {
		t.Errorf("a second traversal differs:\n%s\n%s", first, second)
	}

	a3, plan3 := mainTree()
	a3.shuffle = true
	if reversed := encode(t, traverseTree(a3, plan3)); reversed != first {
		t.Errorf("a traversal of the same tree listed in reverse differs:\n%s\n%s", first, reversed)
	}
}

// A hidden directory is one row; what is inside it is not hidden, but every
// other rule still judges it (§3).
func TestHiddenDirectoryRecordsOnlyItself(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/":               {treeDir("opt", 0o755)},
		"/opt":            {treeDir(".cache", 0o755)},
		"/opt/.cache":     {treeDir("a", 0o755), treeFile(".inner", 0o644)},
		"/opt/.cache/a":   {treeDir("b", 0o755)},
		"/opt/.cache/a/b": {treeFile("tool", 0o4755), treeFile(".deep", 0o666)},
	}
	a := &fsAccess{tree: buildTree(spec, nil)}
	r := traverseTree(a, planSpec{enter: map[int]string{1: "/"}}.build())

	if got := rowPaths(r.lists.hidden); !slices.Equal(got, []string{"/opt/.cache"}) {
		t.Errorf("hidden = %v, want only the hidden directory itself", got)
	}
	if got := rowPaths(r.lists.suid); !slices.Equal(got, []string{"/opt/.cache/a/b/tool"}) {
		t.Errorf("suid = %v, want the walk to have descended into the hidden directory", got)
	}
	if got := rowPaths(r.lists.worldWritable); !slices.Equal(got, []string{"/opt/.cache/a/b/.deep"}) {
		t.Errorf("worldWritable = %v, want the other rules still applied inside a hidden directory", got)
	}

	// A mount point under a hidden directory is a root of its own: its
	// children are under a hidden directory all the same.
	mspec := map[string][]collect.DirEntry{
		"/":             {treeDir("opt", 0o755)},
		"/opt":          {treeDir(".cache", 0o755)},
		"/opt/.cache":   {treeDir("m", 0o755)},
		"/opt/.cache/m": {treeFile(".inner", 0o644)},
	}
	tree := buildTree(mspec, map[string]uint64{"/": 1, "/opt/.cache/m": 2})
	rr := traverseTree(&fsAccess{tree: tree}, planSpec{enter: map[int]string{1: "/", 2: "/opt/.cache/m"}}.build())
	if got := rowPaths(rr.lists.hidden); !slices.Equal(got, []string{"/opt/.cache"}) {
		t.Errorf("hidden = %v, want only the hidden directory itself across the mount boundary", got)
	}
}

// Without STATX_MNT_ID the boundary is a change of device, matched against
// the devices mountinfo gave the mounts the plan entered (PF-7).
func TestTraverseFallsBackToDev(t *testing.T) {
	spec := map[string][]collect.DirEntry{
		"/": {
			treeDir("entered", 0o755),
			treeDir("planned", 0o755),
			treeDir("automount", 0o755),
			treeDir("same", 0o755),
		},
		"/entered":   {treeFile("su", 0o4755)},
		"/planned":   {treeFile("planned-su", 0o4755)},
		"/automount": {treeFile("auto-su", 0o4755)},
		"/same":      {treeFile("same-su", 0o4755)},
	}
	tree := forgetMntIDs(buildTree(spec, map[string]uint64{"/": 1, "/entered": 2, "/planned": 7, "/automount": 9}))
	a := &fsAccess{tree: tree}
	plan := planSpec{
		enter:   map[int]string{1: "/", 2: "/entered"},
		skipped: []skipRow{{path: "/planned", reason: "excluded_type", detail: "nfs4"}},
	}.build()

	r := traverseTree(a, plan)

	if !r.mntIDFallback {
		t.Error("mntIDFallback = false, want true when no listing reports a mount id")
	}
	if got, want := rowPaths(r.lists.suid), []string{"/entered/su", "/same/same-su"}; !slices.Equal(got, want) {
		t.Errorf("suid = %v, want %v — the same device is not a boundary, a foreign one is", got, want)
	}
	want := []map[string]any{
		{"path": "/automount", "reason": "unlisted_mount", "detail": ""},
		{"path": "/planned", "reason": "excluded_type", "detail": "nfs4"},
	}
	if !reflect.DeepEqual(r.lists.skipped, want) {
		t.Errorf("skipped = %v, want %v", r.lists.skipped, want)
	}
}
