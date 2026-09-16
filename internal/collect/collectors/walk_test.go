//go:build linux

package collectors

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The tree below is synthetic: invented uids, invented packages, real
// distribution spellings and no host anywhere. It has one entry for every
// rule the collector has to carry all the way into a fact — a declared and
// an undeclared setuid binary, a world-writable directory with and without
// the sticky bit, a symlink nobody owns, an allowlisted hidden file and one
// that is not — on two mounts, matching the two rows of the `mountinfo`
// fixture (/ is mount 1, /home is mount 2).
var walkTreeSpec = map[string][]collect.DirEntry{
	"/":                {treeDir("etc", 0o755), treeDir("home", 0o755), treeDir("srv", 0o755), treeDir("usr", 0o755), treeDir("var", 0o755)},
	"/etc":             {treeFile(".pwd.lock", 0o600)},
	"/home":            {treeDir("alice", 0o700, owner(1000, 1000))},
	"/home/alice":      {treeFile(".bashrc", 0o644, owner(1000, 1000))},
	"/srv":             {treeDir("share", 0o777)},
	"/srv/share":       {},
	"/usr":             {treeDir("bin", 0o755), treeDir("sbin", 0o755)},
	"/usr/bin":         {treeFile("su", 0o4755), treeFile("python3", 0o4755), treeLink("link", owner(70000, 0))},
	"/usr/sbin":        {treeFile(".h", 0o600)},
	"/var":             {treeDir("lib", 0o755)},
	"/var/lib":         {treeDir("x", 0o755)},
	"/var/lib/x":       {treeDir("spool", 0o1777)},
	"/var/lib/x/spool": {},
}

// walkAccess is the host the collector suite runs against: the four id
// files, the two-mount mountinfo, an rpm database and the scripted tree.
func walkAccess() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			mountinfoPath: "mountinfo",
			passwdPath:    "passwd",
			groupPath:     "group",
			subuidPath:    "subuid.sample",
			subgidPath:    "subgid.sample",
		},
		dirs: map[string]bool{rpmDBDir: true},
		cmds: map[string]cmdResult{cmdKey(rpmCommand): {file: "rpm.qa-files.sample"}},
		tree: buildTree(walkTreeSpec, map[string]uint64{"/": 1, "/home": 2}),
	}
}

// deepWalk runs the walk collector the way collect.Run does — Begin first,
// so Keys and Worst can be asked about what it wrote, and under the guard,
// so a read outside the declaration fails the test rather than being served.
// --deep is armed with opts; the caller that wants it disarmed uses build().
func deepWalk(ctx context.Context, t *testing.T, a collect.Access, opts collect.WalkOptions) (*collect.Builder, error) {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	b.SetWalk(opts)
	b.Begin("walk")
	c := collectorNamed(t, "walk")
	g := collect.Guard(a, c)
	runErr := c.Run(ctx, g, b)
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("walk touched undeclared targets: %v", v)
	}
	return b, runErr
}

// walkRun is deepWalk as root with no limits, which is what every test but
// the privilege and budget ones is about.
func walkRun(t *testing.T, a collect.Access) *collect.Builder {
	t.Helper()
	withEUID(t, 0)
	b, err := deepWalk(context.Background(), t, a, collect.WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return b
}

// walkKeys is every fact key the collector wrote, sorted.
func walkKeys(b *collect.Builder) []string { return b.Keys("walk") }

// walkRows reads an ok list fact back as the records it carries, so a test
// can assert on fields rather than on `any`.
func walkRows(t *testing.T, b *collect.Builder, key string) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	for _, v := range okList(t, b, key) {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: row %#v is not a record", key, v)
		}
		out = append(out, m)
	}
	return out
}

func walkStatsValue(t *testing.T, b *collect.Builder) map[string]any {
	t.Helper()
	e := env(t, b, "walk.stats")
	if e.Status != facts.StatusOK {
		t.Fatalf("walk.stats: %+v", e)
	}
	m, ok := e.Value.(map[string]any)
	if !ok {
		t.Fatalf("walk.stats value is %#v, not a record", e.Value)
	}
	return m
}

// allWalkKeys is the nine keys a walk that ran writes.
var allWalkKeys = []string{
	"walk.complete", "walk.hidden", "walk.skipped", "walk.stats",
	"walk.sticky_missing", "walk.suid_sgid", "walk.suid_sgid_unverified",
	"walk.unowned", "walk.world_writable",
}

// walkUnownedPaths is what the scripted tree leaves unowned: alice's two
// entries, whose primary gid no /etc/group line claims, and the symlink
// owned by a uid nothing accounts for.
var walkUnownedPaths = []string{"/home/alice", "/home/alice/.bashrc", "/usr/bin/link"}

// walkJoinedKeys are the four lists the package join decides; the join's
// failure reaches these and nothing else.
var walkJoinedKeys = []string{"walk.hidden", "walk.suid_sgid", "walk.suid_sgid_unverified", "walk.world_writable"}

// W-1: without --deep the collector writes no key at all, so walk.* stays
// absent from an ordinary snapshot and the controls read MANUAL rather than
// a verdict built on a walk that never ran. It replaces stage 1's
// TestWalkDeclaresAndWritesNothing, whose other half — an empty declaration
// — is no longer true.
func TestWalkWritesNothingWithoutDeep(t *testing.T) {
	withEUID(t, 0)
	a := walkAccess()
	b := build(t, "walk", a)
	if len(b.Tree()) != 0 {
		t.Errorf("walk wrote %v without --deep", b.Tree())
	}
	if len(a.readDirs) != 0 || len(a.reads) != 0 {
		t.Errorf("walk touched the host without --deep: reads %v, readdirs %v", a.reads, a.readDirs)
	}
}

// W-1: as a normal user the walk writes exactly one key and returns nil, so
// the collector's status derives from that fact (denied), the run is partial
// and main §6.5 row 10a makes the controls ERROR naming the denial — never a
// "run collect --deep" MANUAL the operator already obeyed.
func TestWalkAsNonRootIsDenied(t *testing.T) {
	withEUID(t, 1000)
	a := walkAccess()
	b, err := deepWalk(context.Background(), t, a, collect.WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := walkKeys(b); !slices.Equal(got, []string{"walk.complete"}) {
		t.Fatalf("keys = %v, want walk.complete alone", got)
	}
	e := env(t, b, "walk.complete")
	if e.Status != facts.StatusDenied || e.Reason != "the walk needs root" {
		t.Errorf("walk.complete = %+v, want denied %q", e, "the walk needs root")
	}
	if w := b.Worst("walk"); w != facts.StatusDenied {
		t.Errorf("collector status = %s, want denied", w)
	}
	if len(a.readDirs) != 0 {
		t.Errorf("a denied walk listed %v", a.readDirs)
	}
}

// §7: without the mount table there are no boundaries, so the walk does not
// start. walk.complete carries that read's own envelope with the file
// prefixed (C3) and no other key is written — an empty list here would read
// as "the walk found nothing".
func TestWalkMountinfoFailureIsTheCompleteKey(t *testing.T) {
	withEUID(t, 0)
	a := walkAccess()
	a.fails = map[string]error{mountinfoPath: unix.EACCES}
	b, err := deepWalk(context.Background(), t, a, collect.WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := walkKeys(b); !slices.Equal(got, []string{"walk.complete"}) {
		t.Fatalf("keys = %v, want walk.complete alone", got)
	}
	e := env(t, b, "walk.complete")
	if e.Status != facts.StatusDenied {
		t.Errorf("walk.complete = %+v, want denied", e)
	}
	if !strings.HasPrefix(e.Reason, mountinfoPath+": ") {
		t.Errorf("reason %q does not name %s", e.Reason, mountinfoPath)
	}
	if len(a.readDirs) != 0 {
		t.Errorf("the walk listed %v although it had no mount table", a.readDirs)
	}
}

// A-24: a mountinfo that WAS read and carries no root row is not a read
// failure; it is an error naming the file, never "could not be read".
func TestWalkMountinfoWithoutARootRowIsAnError(t *testing.T) {
	withEUID(t, 0)
	a := walkAccess()
	a.files[mountinfoPath] = "mountinfo.no-root"
	b, err := deepWalk(context.Background(), t, a, collect.WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := walkKeys(b); !slices.Equal(got, []string{"walk.complete"}) {
		t.Fatalf("keys = %v, want walk.complete alone", got)
	}
	e := env(t, b, "walk.complete")
	if e.Status != facts.StatusError {
		t.Errorf("walk.complete = %+v, want error", e)
	}
	if !strings.Contains(e.Reason, mountinfoPath) {
		t.Errorf("reason %q does not name %s", e.Reason, mountinfoPath)
	}
}

// §7: a root filesystem the walk does not enter — a container's overlay —
// makes every list unsupported, which main §6.5 row 7 turns into
// NOT_APPLICABLE. walk.complete is true: the walk did finish, it simply had
// nothing it was allowed to walk, and the skipped row says which type.
func TestWalkUnwalkableRootIsUnsupported(t *testing.T) {
	withEUID(t, 0)
	a := walkAccess()
	a.files[mountinfoPath] = "mountinfo.overlay-root"
	b := walkRun(t, a)

	if got := walkKeys(b); !slices.Equal(got, allWalkKeys) {
		t.Fatalf("keys = %v, want %v", got, allWalkKeys)
	}
	wantReason := "root filesystem is overlay; the walk answers for a host, not for a container layer"
	for _, key := range []string{"walk.suid_sgid", "walk.suid_sgid_unverified", "walk.world_writable", "walk.sticky_missing", "walk.unowned", "walk.hidden"} {
		e := env(t, b, key)
		if e.Status != facts.StatusUnsupported || e.Reason != wantReason {
			t.Errorf("%s = %+v, want unsupported %q", key, e, wantReason)
		}
	}
	if e := env(t, b, "walk.complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("walk.complete = %+v, want ok true", e)
	}
	want := map[string]any{"path": "/", "reason": "excluded_type", "detail": "overlay"}
	rows := walkRows(t, b, "walk.skipped")
	if len(rows) != 1 || !mapsEqual(rows[0], want) {
		t.Errorf("walk.skipped = %v, want exactly %v", rows, want)
	}
	stats := walkStatsValue(t, b)
	if stats["entries"] != 0 || stats["stop_reason"] != "" {
		t.Errorf("stats = %v, want no entries and no stop reason", stats)
	}
	if len(a.readDirs) != 0 {
		t.Errorf("the walk listed %v on an unwalkable root", a.readDirs)
	}
}

// The whole collector over one host: nine keys, every list ok, the join's
// fields on the rows a control reads, and walk.stats carrying exactly the
// thirteen fields the registry names.
func TestWalkHappyPath(t *testing.T) {
	a := walkAccess()
	b := walkRun(t, a)

	if got := walkKeys(b); !slices.Equal(got, allWalkKeys) {
		t.Fatalf("keys = %v, want %v", got, allWalkKeys)
	}
	if e := env(t, b, "walk.complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("walk.complete = %+v, want ok true", e)
	}
	for _, key := range allWalkKeys {
		if e := env(t, b, key); e.Status != facts.StatusOK {
			t.Errorf("%s = %+v, want ok", key, e)
		}
	}

	lists := map[string][]string{
		"walk.suid_sgid":            {"/usr/bin/python3", "/usr/bin/su"},
		"walk.suid_sgid_unverified": {},
		"walk.world_writable":       {"/srv/share", "/var/lib/x/spool"},
		"walk.sticky_missing":       {"/srv/share"},
		// alice's gid is a primary group /etc/group has no line for, which
		// is exactly the dangling ownership the rule looks for; the symlink
		// is owned by a uid nothing on this host accounts for.
		"walk.unowned": {"/home/alice", "/home/alice/.bashrc", "/usr/bin/link"},
		"walk.hidden":  {"/etc/.pwd.lock", "/usr/sbin/.h"},
	}
	for _, key := range sortedKeys(lists) {
		if got := rowPaths(walkRows(t, b, key)); !slices.Equal(got, lists[key]) {
			t.Errorf("%s = %v, want %v", key, got, lists[key])
		}
	}

	// W-6: a world-writable row a control reads carries the join's verdict,
	// not only the path the traversal found.
	ww := walkRows(t, b, "walk.world_writable")
	checkRow(t, ww, "/var/lib/x/spool", map[string]any{
		"kind": "dir", "sticky": true, "package": "spooler", "package_declared": true, "reference": refRPMDB,
	})
	checkRow(t, ww, "/srv/share", map[string]any{
		"kind": "dir", "sticky": false, "package": "web-assets", "package_declared": false, "reference": refRPMDB,
	})
	checkRow(t, walkRows(t, b, "walk.suid_sgid"), "/usr/bin/su", map[string]any{
		"package": "util-linux", "package_declared": true, "reference": refRPMDB,
	})
	// The joined lists cite the command that decided them; the rest cite the
	// walk itself.
	for _, key := range walkJoinedKeys {
		if src := env(t, b, key).Source; src == nil || src.Kind != "command" || src.Cmd != cmdKey(rpmCommand) {
			t.Errorf("%s source = %+v, want the rpm command", key, src)
		}
	}
	for _, key := range []string{"walk.complete", "walk.sticky_missing", "walk.unowned", "walk.skipped", "walk.stats"} {
		if src := env(t, b, key).Source; src == nil || src.Kind != "derived" {
			t.Errorf("%s source = %+v, want derived", key, src)
		}
	}

	// walk.skipped is provenance: every root the plan refused, with the
	// three fields of the vocabulary.
	skipped := walkRows(t, b, "walk.skipped")
	if !slices.Contains(rowPaths(skipped), "/var/lib/docker") {
		t.Errorf("walk.skipped %v lacks the fixed container-storage set", rowPaths(skipped))
	}
	for _, row := range skipped {
		if got := sortedKeys(row); !slices.Equal(got, []string{"detail", "path", "reason"}) {
			t.Fatalf("skipped row fields = %v, want [detail path reason]", got)
		}
	}

	stats := walkStatsValue(t, b)
	wantStats := []string{
		"allowlisted_hidden", "config_unreadable", "dirs", "entries", "files", "home_roots",
		"ioprio_applied", "last_path", "mnt_id_fallback", "nice_applied", "stop_reason",
		"symlinks", "truncated_counts",
	}
	if got := sortedKeys(stats); !slices.Equal(got, wantStats) {
		t.Fatalf("walk.stats fields = %v, want %v", got, wantStats)
	}
	entries, dirs, files, symlinks := stats["entries"].(int), stats["dirs"].(int), stats["files"].(int), stats["symlinks"].(int)
	if entries == 0 || entries != dirs+files+symlinks {
		t.Errorf("entries/dirs/files/symlinks = %d/%d/%d/%d", entries, dirs, files, symlinks)
	}
	if stats["stop_reason"] != "" || stats["last_path"] != "" || stats["mnt_id_fallback"] != false {
		t.Errorf("stats = %v, want a finished walk that needed no st_dev fallback", stats)
	}
	// A-29: the two hidden counters are disjoint — .pwd.lock is allowlisted
	// and is NOT in truncated_counts.hidden, .h is judged and is.
	counts, ok := stats["truncated_counts"].(map[string]any)
	if !ok {
		t.Fatalf("truncated_counts is %#v, not a record", stats["truncated_counts"])
	}
	wantCounts := []string{"hidden", "skipped", "sticky_missing", "suid_sgid", "suid_sgid_unverified", "unowned", "world_writable"}
	if got := sortedKeys(counts); !slices.Equal(got, wantCounts) {
		t.Errorf("truncated_counts fields = %v, want %v", got, wantCounts)
	}
	if counts["hidden"] != 1 || stats["allowlisted_hidden"] != 1 {
		t.Errorf("hidden counters = %v / %v, want one judged and one allowlisted", counts["hidden"], stats["allowlisted_hidden"])
	}
	// home_roots is what the hidden rule used, one row per account plus the
	// two prefix rows.
	homes, ok := stats["home_roots"].([]any)
	if !ok {
		t.Fatalf("home_roots is %#v, not a list", stats["home_roots"])
	}
	if len(homes) != 4 {
		t.Errorf("home_roots = %v, want the two prefix rows plus root and alice", homes)
	}
	if got := sortedKeys(homes[0].(map[string]any)); !slices.Equal(got, []string{"kind", "path", "user"}) {
		t.Errorf("home_roots row fields = %v, want [kind path user]", got)
	}
	if cfg, ok := stats["config_unreadable"].([]any); !ok || len(cfg) != 0 {
		t.Errorf("config_unreadable = %#v, want an empty list", stats["config_unreadable"])
	}
}

// §7: the join is one operation, so a table nobody could read leaves every
// list it decides unanswerable — and leaves every other key exactly as the
// traversal found it.
func TestWalkJoinFailurePoisonsOnlyJoinedLists(t *testing.T) {
	a := walkAccess()
	a.cmds[cmdKey(rpmCommand)] = cmdResult{exitCode: 1, stderr: "rpm: database is locked\n"}
	b := walkRun(t, a)

	for _, key := range walkJoinedKeys {
		e := env(t, b, key)
		if e.Status != facts.StatusError {
			t.Errorf("%s = %+v, want error", key, e)
		}
		if !strings.Contains(e.Reason, "rpm -qa") {
			t.Errorf("%s reason %q does not name the command", key, e.Reason)
		}
	}
	// Unaffected: what these say does not depend on any package database.
	if got := rowPaths(walkRows(t, b, "walk.sticky_missing")); !slices.Equal(got, []string{"/srv/share"}) {
		t.Errorf("sticky_missing = %v", got)
	}
	if got := rowPaths(walkRows(t, b, "walk.unowned")); !slices.Equal(got, walkUnownedPaths) {
		t.Errorf("unowned = %v, want %v", got, walkUnownedPaths)
	}
	if e := env(t, b, "walk.complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("walk.complete = %+v, want ok true", e)
	}
	if len(walkRows(t, b, "walk.skipped")) == 0 {
		t.Error("walk.skipped lost its rows to the join's failure")
	}
	if stats := walkStatsValue(t, b); stats["entries"] == 0 {
		t.Error("walk.stats lost its counters to the join's failure")
	}
}

// §7: a host with no package database cannot answer, so the joined lists are
// absent and absent_means: manual turns that into MANUAL — never a PASS on
// rows nothing could decide.
func TestWalkNoPackageDatabaseIsAbsent(t *testing.T) {
	a := walkAccess()
	a.dirs = nil
	a.cmds = nil
	b := walkRun(t, a)

	for _, key := range walkJoinedKeys {
		e := env(t, b, key)
		if e.Status != facts.StatusAbsent || e.Reason != noPackageDBReason {
			t.Errorf("%s = %+v, want absent %q", key, e, noPackageDBReason)
		}
	}
	if got := rowPaths(walkRows(t, b, "walk.unowned")); !slices.Equal(got, walkUnownedPaths) {
		t.Errorf("unowned = %v, want the traversal's own answer %v", got, walkUnownedPaths)
	}
}

// C3: /etc/passwd unreadable means nothing on this host can say which uids
// are accounted for, so walk.unowned carries that read's status with the
// path in the reason. Every other list still answers.
func TestWalkIDFilesFailureReachesUnowned(t *testing.T) {
	a := walkAccess()
	a.fails = map[string]error{passwdPath: unix.EACCES}
	b := walkRun(t, a)

	e := env(t, b, "walk.unowned")
	if e.Status != facts.StatusDenied {
		t.Fatalf("walk.unowned = %+v, want denied", e)
	}
	if !strings.HasPrefix(e.Reason, passwdPath+": ") {
		t.Errorf("reason %q does not name %s", e.Reason, passwdPath)
	}
	for _, key := range []string{"walk.sticky_missing", "walk.skipped", "walk.stats", "walk.complete", "walk.world_writable"} {
		if s := env(t, b, key).Status; s != facts.StatusOK {
			t.Errorf("%s status = %s, want ok", key, s)
		}
	}
	// R70: a capped id file is not a failed read — the ids that were read
	// are real and the flag says the rest are not known.
	a2 := walkAccess()
	a2.truncated = map[string]bool{subuidPath: true}
	b2 := walkRun(t, a2)
	e2 := env(t, b2, "walk.unowned")
	if e2.Status != facts.StatusOK || !e2.Truncated {
		t.Errorf("walk.unowned = %+v, want ok and truncated", e2)
	}
}

// walkWideTree is one directory holding more world-writable files than the
// list's own cap, and nothing else that any other list judges: the entries
// are regular files (so no sticky_missing row), owned by root (so no
// unowned row) and plainly named (so no hidden row). It is what makes a
// dropped truncation flag on ONE list visible against six that stay false.
func walkWideTree(n int) map[string][]collect.DirEntry {
	entries := make([]collect.DirEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, treeFile(fmt.Sprintf("f%05d", i), 0o666))
	}
	return map[string][]collect.DirEntry{
		"/":     {treeDir("home", 0o755), treeDir("srv", 0o755)},
		"/home": {},
		"/srv":  entries,
	}
}

// untruncated asserts that every key but the named ones is ok and carries no
// truncation, which is what makes a flag set on the right list mean anything.
func untruncated(t *testing.T, b *collect.Builder, except ...string) {
	t.Helper()
	for _, key := range allWalkKeys {
		if slices.Contains(except, key) {
			continue
		}
		if e := env(t, b, key); e.Truncated {
			t.Errorf("%s = %+v, want no truncation", key, e)
		}
	}
}

// §2/R70: a fact built from a sample must say so, or a control reads the
// absence of a row as the absence of the thing. The walk has two independent
// sources of truncation — a list that hit its own cap, and a package table
// the join read only in part — and the collector has to forward each onto
// the keys it belongs to and onto no others.
func TestWalkForwardsBothTruncationFlags(t *testing.T) {
	wwCap := listCaps[capWorldWritable]
	wide := func(a *fsAccess) *fsAccess {
		a.tree = buildTree(walkWideTree(wwCap+1), map[string]uint64{"/": 1, "/home": 2})
		return a
	}
	cutTable := func(a *fsAccess) *fsAccess {
		a.cmds[cmdKey(rpmCommand)] = cmdResult{file: "rpm.qa-files.cut", truncated: true}
		return a
	}

	t.Run("a list at its cap", func(t *testing.T) {
		b := walkRun(t, wide(walkAccess()))
		e := env(t, b, "walk.world_writable")
		if e.Status != facts.StatusOK || !e.Truncated {
			t.Errorf("walk.world_writable = %+v, want ok and truncated", e)
		}
		if n := len(walkRows(t, b, "walk.world_writable")); n != wwCap {
			t.Errorf("rows = %d, want the cap (%d)", n, wwCap)
		}
		// The count is what says how many there really were, and it is the
		// reason the fact is a sample rather than the answer.
		counts := walkStatsValue(t, b)["truncated_counts"].(map[string]any)
		if counts["world_writable"] != wwCap+1 {
			t.Errorf("truncated_counts.world_writable = %v, want %d", counts["world_writable"], wwCap+1)
		}
		untruncated(t, b, "walk.world_writable")
	})

	t.Run("a package table read in part", func(t *testing.T) {
		b := walkRun(t, cutTable(walkAccess()))
		for _, key := range walkJoinedKeys {
			e := env(t, b, key)
			if e.Status != facts.StatusOK || !e.Truncated {
				t.Errorf("%s = %+v, want ok and truncated: the table was read only in part", key, e)
			}
		}
		// Nothing the join did not decide is affected: these three answer
		// from what the traversal saw, and it saw all of it.
		untruncated(t, b, walkJoinedKeys...)
	})

	// walk.skipped has a cap and a flag of its own, and it is the list a
	// reviewer reads to judge whether the walk saw what it should have: a
	// sample of the roots it refused, presented as the whole set, would be
	// the most misleading of the seven.
	t.Run("the skipped list at its cap", func(t *testing.T) {
		withEUID(t, 0)
		skipCap := listCaps[capSkipped]
		exclude := make([]string, 0, skipCap+1)
		for i := 0; i <= skipCap; i++ {
			exclude = append(exclude, fmt.Sprintf("/excluded%05d", i))
		}
		b, err := deepWalk(context.Background(), t, walkAccess(), collect.WalkOptions{Exclude: exclude})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		e := env(t, b, "walk.skipped")
		if e.Status != facts.StatusOK || !e.Truncated {
			t.Errorf("walk.skipped = %+v, want ok and truncated", e)
		}
		if n := len(walkRows(t, b, "walk.skipped")); n != skipCap {
			t.Errorf("rows = %d, want the cap (%d)", n, skipCap)
		}
		counts := walkStatsValue(t, b)["truncated_counts"].(map[string]any)
		if n, _ := counts["skipped"].(int); n <= skipCap {
			t.Errorf("truncated_counts.skipped = %v, want more than the cap (%d)", counts["skipped"], skipCap)
		}
		untruncated(t, b, "walk.skipped")
	})

	t.Run("both at once", func(t *testing.T) {
		b := walkRun(t, cutTable(wide(walkAccess())))
		// world_writable is both at its cap and joined from a partial
		// table; either alone would set the flag, and both must keep it.
		if e := env(t, b, "walk.world_writable"); e.Status != facts.StatusOK || !e.Truncated {
			t.Errorf("walk.world_writable = %+v, want ok and truncated", e)
		}
		if e := env(t, b, "walk.suid_sgid"); !e.Truncated {
			t.Errorf("walk.suid_sgid = %+v, want the join's truncation", e)
		}
		untruncated(t, b, walkJoinedKeys...)
	})
}

// §2: a limit stops the walk without costing it what it had already seen.
// The entry budget is the collector's own answer (complete false, a stop
// reason); the run's deadline is the caller's, so the collector reports it
// by returning ctx.Err() and collect.Run files the collector as timeout.
func TestWalkBudgetAndDeadline(t *testing.T) {
	t.Run("entry budget", func(t *testing.T) {
		withEUID(t, 0)
		a := walkAccess()
		b, err := deepWalk(context.Background(), t, a, collect.WalkOptions{MaxEntries: 3})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		if e := env(t, b, "walk.complete"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("walk.complete = %+v, want ok false", e)
		}
		stats := walkStatsValue(t, b)
		if stats["stop_reason"] != "entry_budget" {
			t.Errorf("stop_reason = %v, want entry_budget", stats["stop_reason"])
		}
		if stats["last_path"] == "" {
			t.Error("last_path must name the directory the walk was about to read")
		}
		// The lists still carry what was seen before the budget ran out.
		for _, key := range []string{"walk.suid_sgid", "walk.world_writable", "walk.skipped"} {
			if s := env(t, b, key).Status; s != facts.StatusOK {
				t.Errorf("%s status = %s, want ok", key, s)
			}
		}
	})

	t.Run("deadline", func(t *testing.T) {
		withEUID(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		a := walkAccess()
		b, err := deepWalk(ctx, t, a, collect.WalkOptions{})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want the context's own error", err)
		}
		if e := env(t, b, "walk.complete"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("walk.complete = %+v, want ok false", e)
		}
		if got := walkStatsValue(t, b)["stop_reason"]; got != "deadline" {
			t.Errorf("stop_reason = %v, want deadline", got)
		}
	})
}

// A panic in the traversal happens on the walk goroutine, where the
// recover in collect.callRun cannot see it: without a recover of its own it
// would take the process down. It is a defect in muster, so every key says
// error and names it — no key may keep a value a broken walk produced.
func TestWalkPanicInTheWalkerIsAnError(t *testing.T) {
	orig := walkTraverse
	t.Cleanup(func() { walkTraverse = orig })
	walkTraverse = func(context.Context, collect.Access, mountPlan, idTables, collect.WalkOptions, walkClock) walkResult {
		panic("walk: no list for cap index")
	}
	a := walkAccess()
	b := walkRun(t, a)

	if got := walkKeys(b); !slices.Equal(got, allWalkKeys) {
		t.Fatalf("keys = %v, want %v", got, allWalkKeys)
	}
	for _, key := range allWalkKeys {
		e := env(t, b, key)
		if e.Status != facts.StatusError {
			t.Errorf("%s = %+v, want error", key, e)
		}
		if !strings.Contains(e.Reason, "no list for cap index") {
			t.Errorf("%s reason %q does not name the panic", key, e.Reason)
		}
	}
	if w := b.Worst("walk"); w != facts.StatusError {
		t.Errorf("collector status = %s, want error", w)
	}
}

// §9: the walk is one row of the document a change-control reviewer
// approves, beside every path it reads and the one command it runs.
func TestWalkDeclaresItself(t *testing.T) {
	c := collectorNamed(t, "walk")
	if c.Declare.Needs != "root" || !c.Declare.Walk {
		t.Errorf("declaration = %+v, want the walk licence and root", c.Declare)
	}
	if !slices.IsSorted(c.Declare.Reads) {
		t.Errorf("declared reads are not sorted: %v", c.Declare.Reads)
	}
	for _, want := range []string{
		mountinfoPath, passwdPath, groupPath, subuidPath, subgidPath,
		dockerDaemonPath, containersStoragePath, containerdConfigPath,
		dpkgStatusPath, dpkgInfoGlob, dpkgDiversionsPath, dpkgStatOverridePath, rpmDBDir,
		"/var/lib/docker", "/bin", "/lib64",
	} {
		if !slices.Contains(c.Declare.Reads, want) {
			t.Errorf("%q is not declared: %v", want, c.Declare.Reads)
		}
	}

	var walkRow, cmdRow bool
	for _, act := range collect.ListActions() {
		if act.Collector != "walk" {
			continue
		}
		switch {
		case act.Kind == "walk":
			walkRow = true
			if act.Needs != "root" || act.Target != "every local filesystem, no symlink followed, boundaries and exclusions as declared" {
				t.Errorf("walk row = %+v", act)
			}
		case act.Kind == "command":
			cmdRow = true
			if act.Target != cmdKey(rpmCommand) {
				t.Errorf("command row = %+v, want %q", act, cmdKey(rpmCommand))
			}
		}
	}
	if !walkRow || !cmdRow {
		t.Errorf("--list-actions is missing the walk row (%v) or the rpm command row (%v)", walkRow, cmdRow)
	}
}

// mapsEqual compares two records field by field, so a failure says which
// record differed rather than printing two maps.
func mapsEqual(got, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
