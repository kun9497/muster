//go:build linux

package collectors

import (
	"context"
	"fmt"
	"slices"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// mountCandidates are the nine paths spec B-2 judges, in the spec's order.
// Ruling K-5: every one of them is a row on every host, present or not, so a
// control's `where` can never select nothing and a waiver can always name
// `mount:/tmp`. The order is the spec's, not sorted — a reader of the
// snapshot walks the tree the way an installer lays it out.
var mountCandidates = []string{
	"/", "/boot", "/home", "/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/dev/shm",
}

// separateLeaves are the four candidates B-6 also publishes as a leaf of its
// own. A mechanism's `when` cannot read a row, and an `each` whose `where`
// found no /tmp row would pass; the leaf is what lets the option controls say
// NOT_APPLICABLE on a host whose /tmp is part of the root filesystem and
// leave that host's finding to the separate-partition control.
var separateLeaves = []struct{ target, key string }{
	{"/tmp", "mounts.tmp.separate"},
	{"/var/tmp", "mounts.var_tmp.separate"},
	{"/dev/shm", "mounts.dev_shm.separate"},
	{"/home", "mounts.home.separate"},
}

// mountsCollector writes what governs each of the nine candidate paths
// TODAY: the kernel's own mount table, not fstab. Spec B-2 leaves the
// persisted side out of 3B on purpose — no control judges it — and the one
// file here is the one file the walk already parses.
var mountsCollector = collect.Collector{
	Name:    "mounts",
	Declare: collect.Declaration{Reads: []string{mountinfoPath}, Needs: "none"},
	Run:     runMounts,
}

func runMounts(_ context.Context, a collect.Access, b *collect.Builder) error {
	rows, meta, readErr := mountinfoRows(a)
	if readErr != nil {
		// C3: the one file that could answer every key here could not be
		// read, so it is the answer for every key here — never a list of
		// rows that would read as "nothing is separate".
		b.Set("mounts.points", *readErr)
		for _, l := range separateLeaves {
			b.Set(l.key, *readErr)
		}
		return nil
	}

	src := &facts.Source{Kind: "proc", Path: mountinfoPath}
	points := make([]map[string]any, 0, len(mountCandidates))
	separate := map[string]bool{}
	for _, target := range mountCandidates {
		g := governingMount(rows, target)
		separate[target] = g.mountPoint == target
		points = append(points, map[string]any{
			"target":     target,
			"separate":   separate[target],
			"mounted_by": g.mountPoint,
			"source":     g.source,
			"fstype":     g.fstype,
			"options":    listValue(g.options),
		})
	}
	b.Set("mounts.points", collect.OKRead(rowsValue(points), src, meta))
	for _, l := range separateLeaves {
		b.Set(l.key, collect.OKRead(separate[l.target], src, meta))
	}
	return nil
}

// governingMount is the mount that decides what a path is on: the DEEPEST
// mount whose mount point is a prefix of the target, which is "/" at worst.
// A candidate that has a mount exactly at it is separate and governs itself.
//
// Two mounts can share a mount point — an over-mount hides the one beneath —
// and the higher mount id is the one on top, the same rule planMounts uses to
// pick the real root out of a rootfs stack. Comparing by mount-point LENGTH
// is a total order here because two different prefixes of one path can never
// be the same length.
func governingMount(rows []mountRow, target string) mountRow {
	var best mountRow
	found := false
	for _, r := range rows {
		if !underOrEqual(target, r.mountPoint) {
			continue
		}
		switch {
		case !found,
			len(r.mountPoint) > len(best.mountPoint),
			len(r.mountPoint) == len(best.mountPoint) && r.id > best.id:
			best, found = r, true
		}
	}
	return best
}

// mountinfoRows reads and parses the mount table for the collectors that are
// not the walk, returning the envelope every key must carry when it could not
// be had. A mountinfo with no row at "/" is an error rather than a set of
// rows with nothing governing them: a mount table that does not describe the
// root of the tree it belongs to is not one this host can be judged from, and
// the walk's own sentinel says so in the same words.
func mountinfoRows(a collect.Access) ([]mountRow, collect.ReadMeta, *facts.Envelope) {
	data, meta, err := a.ReadFile(mountinfoPath, mountinfoReadLimit)
	if err != nil {
		e := readErrorEnv(mountinfoPath, err)
		return nil, meta, &e
	}
	rows, err := parseMountinfo(data)
	if err != nil {
		e := collect.ErrorEnv(fmt.Sprintf("%s: %v", mountinfoPath, err))
		return nil, meta, &e
	}
	if !slices.ContainsFunc(rows, func(r mountRow) bool { return r.mountPoint == "/" }) {
		e := collect.ErrorEnv(fmt.Sprintf("%s: %v", mountinfoPath, errNoRootMount))
		return nil, meta, &e
	}
	return rows, meta, nil
}

// listValue boxes a record's string list as []any. A record reaches the
// snapshot through encoding/json, where a nil []string is `null` — a third
// meaning beside "no options" and "these options" that no clause can be
// written against — so the slice is always built, never returned as it came.
func listValue(vs []string) []any {
	out := make([]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, v)
	}
	return out
}
