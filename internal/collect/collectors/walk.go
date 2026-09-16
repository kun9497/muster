//go:build linux

package collectors

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The walk is the one collector that reads the whole filesystem (W-1). It
// runs only under `collect --deep`, needs root, and assembles the four
// pieces the files beside this one provide: the id tables and the home set,
// the mount plan, the traversal, and the package join. Nothing here decides
// a rule — every rule lives in the file that owns it — and nothing here
// touches the host except through collect.Access.
//
// It is off by default because a whole-filesystem traversal is not
// something a snapshot should do behind an operator's back, and because a
// snapshot with no walk.* keys is honestly readable: main §6.5 row 9 turns
// the absence into MANUAL ("run collect --deep"), never into a PASS on
// lists nobody produced.
var walkCollector = collect.Collector{
	Name: "walk",
	Declare: collect.Declaration{
		Needs:    "root",
		Walk:     true,
		Reads:    walkReads(),
		Commands: []collect.Command{rpmCommand},
	},
	Run: runWalk,
}

// walkReads is everything the walk reads by path. The traversal itself is
// licensed by Declaration.Walk, not by this list (a glob could not honestly
// describe "every local filesystem"); these are the fixed files the plan,
// the id tables and the join open: the mount table, the four id files, the
// three container configuration files, dpkg's four database paths and rpm's
// directory, the fixed container-storage set the plan probes for symlinks,
// and the six merged-/usr aliases the join canonicalises through. Sorted,
// so --list-actions prints the same document however this file is edited.
func walkReads() []string {
	out := []string{
		mountinfoPath, passwdPath, groupPath, subuidPath, subgidPath,
		dockerDaemonPath, containersStoragePath, containerdConfigPath,
		dpkgStatusPath, dpkgInfoGlob, dpkgDiversionsPath, dpkgStatOverridePath, rpmDBDir,
	}
	out = append(out, collect.ContainerStorageRoots()...)
	out = append(out, usrAliases...)
	slices.Sort(out)
	return out
}

// walkTraverse is traverse behind a variable so a test can make the walk
// goroutine fail the one way it is allowed to fail — a programming error in
// the cap table, which traverse answers with a panic. Nothing else
// reassigns it.
var walkTraverse = traverse

// findingList is one of the six lists a control or a warning reads: the key
// it is written under, the cap index whose truncation flag it carries, and
// whether the package join decides it (W-6). A joined list cites the join's
// evidence and, when the join failed, carries its envelope instead of rows;
// the other two answer from what the traversal saw and nothing else.
type findingList struct {
	key    string
	cap    int
	joined bool
}

var findingLists = []findingList{
	{"walk.suid_sgid", capSUIDSGID, true},
	{"walk.suid_sgid_unverified", capSUIDUnverified, true},
	{"walk.world_writable", capWorldWritable, true},
	{"walk.sticky_missing", capStickyMissing, false},
	{"walk.unowned", capUnowned, false},
	{"walk.hidden", capHidden, true},
}

// idFileOrder is the order an id-file failure is looked for in, so a host
// where two of them are unreadable always reports the same one.
var idFileOrder = []string{passwdPath, groupPath, subuidPath, subgidPath}

// walkOutcome is what the walk goroutine hands back: the traversal's
// result, whether the two priority calls took, and the panic text when the
// traversal failed the one way it can.
type walkOutcome struct {
	r            walkResult
	nice, ioprio bool
	panicked     string
}

// runWalk is the collector (W-1, §7). Every branch writes only the keys it
// names: a walk that was not asked for writes none, a walk that may not run
// writes walk.complete alone, and a walk that ran writes all nine.
func runWalk(ctx context.Context, a collect.Access, b *collect.Builder) error {
	opts, ok := b.Walk()
	if !ok {
		return nil // --deep was not given: walk.* stays absent (main §6.5 row 9)
	}
	if euid() != 0 {
		// One key, and nil: the collector's status then derives from the
		// fact (denied), the run is partial, and row 10a makes every
		// walk-based control ERROR naming the denial rather than telling
		// the operator to pass a flag they already passed.
		b.Set("walk.complete", collect.Denied("the walk needs root"))
		return nil
	}

	ids, idFail := loadIDTables(a)
	homes := classifyHomes(ids.rows)
	plan, err := planMounts(a, opts, homes)
	if err != nil {
		// Without the mount table there are no boundaries, and a walk with
		// no boundaries is the one thing the design refuses. No list is
		// written: an empty one would read as "the walk found nothing".
		b.Set("walk.complete", mountinfoFailure(err))
		return nil
	}

	derived := &facts.Source{Kind: "derived"}
	if !plan.rootWalkable {
		writeUnwalkableRoot(b, plan, derived)
		return nil
	}

	out := walkTree(ctx, a, plan, ids, opts)
	if out.panicked != "" {
		writeWalkPanic(b, out.panicked)
		return nil
	}
	jo := joinCandidates(ctx, a, b.Header(), plan, &out.r)
	writeWalkFacts(b, plan, out, jo, idFail, derived)
	if out.r.stopReason == "deadline" {
		// The run's global deadline, not a limit of the walk's own: the
		// collector reports it as collect.Run's callRun expects, which
		// files the collector as timeout rather than as a clean run.
		return ctx.Err()
	}
	return nil
}

// mountinfoFailure turns planMounts' error into walk.complete (A-24). A
// file that could not be READ carries that read's own envelope with the
// path prefixed (C3). A file that was read and carried no mount, or no root
// mount, is neither denied nor absent: it is an error naming the file, and
// saying "could not be read" there would be false.
func mountinfoFailure(err error) facts.Envelope {
	if errors.Is(err, errNoMountRow) || errors.Is(err, errNoRootMount) {
		return collect.ErrorEnv(err.Error())
	}
	e := collect.FromReadError(err, collect.ReadMeta{})
	e.Reason = mountinfoPath + ": " + e.Reason
	return e
}

// writeUnwalkableRoot answers for a host whose root filesystem is not one
// the walk enters — a container's overlay, a squashfs appliance, a type the
// positive list has never heard of (§7). Every list is unsupported, which
// main §6.5 row 7 turns into NOT_APPLICABLE; walk.complete is true, because
// the walk did finish — it simply had nothing it was allowed to enter — and
// the one skipped row says which type it was.
func writeUnwalkableRoot(b *collect.Builder, plan mountPlan, derived *facts.Source) {
	reason := fmt.Sprintf("root filesystem is %s; the walk answers for a host, not for a container layer", plan.rootType)
	for _, l := range findingLists {
		b.Set(l.key, collect.Unsupported(reason))
	}
	b.Set("walk.complete", collect.OK(true, derived))
	b.Set("walk.skipped", collect.OK(planSkipRows(plan.skipped), derived))
	b.Set("walk.stats", collect.OK(walkStats(plan, walkResult{}, false, false), derived))
}

// walkTree runs the traversal on a goroutine of its own, locked to one
// thread. Both priority settings are per-thread on Linux (A-5), so the
// thread that asks for them has to be the thread that reads; the goroutine
// never unlocks, so the thread dies with it rather than going back to the
// pool carrying an idle I/O class.
//
// The recover is this function's own, not collect.callRun's: that one runs
// on the collector's goroutine and cannot see a panic on another, which
// would take the whole process down and cost the snapshot every other
// collector had produced. The collector waits for the walker even when the
// context is already done — the walker checks ctx.Err() before every
// directory and returns of its own accord — so no goroutine is left behind
// reading the filesystem after the run has moved on.
func walkTree(ctx context.Context, a collect.Access, plan mountPlan, ids idTables, opts collect.WalkOptions) walkOutcome {
	clock := walkClock{start: time.Now(), now: time.Now}
	done := make(chan walkOutcome, 1)
	go func() {
		var out walkOutcome
		defer func() {
			if p := recover(); p != nil {
				out.panicked = fmt.Sprintf("%v", p)
			}
			done <- out
		}()
		runtime.LockOSThread()
		out.nice, out.ioprio = applyPriority()
		out.r = walkTraverse(ctx, a, plan, ids, opts, clock)
	}()
	return <-done
}

// writeWalkPanic answers for a defect in muster itself. A panic leaves the
// lists half-built and nothing may be read from them, so every one of the
// nine keys carries the same error naming the panic: a reader sees a broken
// walk, and no control reads a list that a crash decided the contents of.
func writeWalkPanic(b *collect.Builder, panicked string) {
	e := collect.ErrorEnv("the walk panicked: " + panicked)
	for _, l := range findingLists {
		b.Set(l.key, e)
	}
	for _, key := range []string{"walk.complete", "walk.skipped", "walk.stats"} {
		b.Set(key, e)
	}
}

// writeWalkFacts writes the nine keys of a walk that ran (§7). The source
// says what decided each one: the walk itself for the lists it judged
// alone, the package database for the four the join decided.
func writeWalkFacts(b *collect.Builder, plan mountPlan, out walkOutcome, jo joinOutcome, idFail map[string]facts.Envelope, derived *facts.Source) {
	r := &out.r
	b.Set("walk.complete", collect.OK(r.complete, derived))
	for _, l := range findingLists {
		src := derived
		if l.joined {
			src = jo.source
		}
		e := collect.OK(rowsValue(*r.lists.at(l.cap)), src)
		e.Truncated = r.lists.truncated[l.cap]
		switch {
		case l.joined && jo.failed != nil:
			// The join is one operation: a table nobody could read leaves
			// every list it decides as unanswerable as the others.
			e = *jo.failed
		case l.joined && jo.truncated:
			// The rows that were joined are real; the absence of a row
			// means nothing, which is exactly what truncated says.
			e.Truncated = true
		case l.key == "walk.unowned":
			e = unownedEnvelope(e, idFail)
		}
		b.Set(l.key, e)
	}
	skipped := collect.OK(rowsValue(r.lists.skipped), derived)
	skipped.Truncated = r.lists.truncated[capSkipped]
	b.Set("walk.skipped", skipped)
	b.Set("walk.stats", collect.OK(walkStats(plan, out.r, out.nice, out.ioprio), derived))
}

// unownedEnvelope applies C3 to walk.unowned: if one of the four id files
// could not be read, nothing on this host can say which ids are accounted
// for, so the fact is that read's status with the path in the reason rather
// than a list computed from the files that did answer. A file that is
// simply not there says nothing — a host with no /etc/subuid has no
// delegation to miss — and a file whose read hit the size cap is still an
// answer as far as it goes, forwarded as ok with truncated (R70).
func unownedEnvelope(ok facts.Envelope, failures map[string]facts.Envelope) facts.Envelope {
	truncated := false
	for _, p := range idFileOrder {
		e, found := failures[p]
		if !found {
			continue
		}
		switch e.Status {
		case facts.StatusDenied, facts.StatusError, facts.StatusTimeout:
			return e
		case facts.StatusOK:
			truncated = true
		}
	}
	ok.Truncated = ok.Truncated || truncated
	return ok
}

// walkStats is the walk's own account of itself: the thirteen fields the
// registry names, and no fourteenth. It is provenance — no control reads it
// — and it is what tells a reviewer whether the walk saw what it should
// have: how much it looked at, why it stopped, how many rows each list
// refused, which container configuration it could not read, which homes the
// hidden rule used, and whether it managed to step out of the way.
func walkStats(plan mountPlan, r walkResult, nice, ioprio bool) map[string]any {
	counts := map[string]any{"skipped": r.lists.truncatedCounts[capSkipped]}
	for _, l := range findingLists {
		counts[strings.TrimPrefix(l.key, "walk.")] = r.lists.truncatedCounts[l.cap]
	}
	configs := make([]any, 0, len(plan.configUnreadable))
	for _, c := range plan.configUnreadable {
		configs = append(configs, map[string]any{"path": c.path, "status": c.status})
	}
	homes := make([]any, 0, len(plan.homes))
	for _, h := range plan.homes {
		homes = append(homes, map[string]any{"path": h.path, "user": h.user, "kind": h.kind})
	}
	return map[string]any{
		"entries":     r.entries,
		"dirs":        r.dirs,
		"files":       r.files,
		"symlinks":    r.symlinks,
		"stop_reason": r.stopReason,
		"last_path":   r.lastPath,
		// A-29: the hidden count is the judged candidates alone;
		// allowlisted_hidden counts the ones the allowlist passed over, and
		// the two are disjoint, so neither hides the other.
		"truncated_counts":   counts,
		"allowlisted_hidden": r.lists.allowlistedHidden,
		"config_unreadable":  configs,
		"home_roots":         homes,
		"mnt_id_fallback":    r.mntIDFallback,
		"nice_applied":       nice,
		"ioprio_applied":     ioprio,
	}
}

// planSkipRows renders the roots the plan refused before the walk began, for
// the one branch that writes walk.skipped without a traversal.
func planSkipRows(rows []skipRow) []any {
	out := make([]any, 0, len(rows))
	for _, s := range rows {
		out = append(out, map[string]any{"path": s.path, "reason": s.reason, "detail": s.detail})
	}
	return out
}

// rowsValue boxes a list of records for the Builder. Builder.Set normalises
// a nil []any into an empty one but cannot normalise a nil
// []map[string]any, which would reach the snapshot as JSON null — a third
// meaning beside "empty" and "some" that nothing can be written against.
func rowsValue(rows []map[string]any) []any {
	out := make([]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, r)
	}
	return out
}
