//go:build linux

package collectors

import (
	"path"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const devMaxEntries = 4096 // a bound so a pathological /dev cannot blow the snapshot

// mountPoint returns the mount point actually serving p: the longest mount
// point that is a prefix of p. It mirrors fstype's longest-prefix match but
// returns the mount point itself, so devEntries can tell a file served
// exactly by the /dev mount from one under a deeper mount such as /dev/shm
// (R181). Task 2 defined mountTable/fstype and deferred this method to here.
func (t mountTable) mountPoint(p string) string {
	best, bestMP := -1, ""
	for mp := range t.points {
		if (p == mp || strings.HasPrefix(p, strings.TrimSuffix(mp, "/")+"/")) && len(mp) > best {
			best, bestMP = len(mp), mp
		}
	}
	return bestMP
}

// devEntries walks /dev one and two levels deep (globs, sorted), stats each,
// and records name/kind/fstype/mode/uid. dev_nondevice is the derived subset
// that is a regular file whose serving mount is exactly /dev (R181) — the
// planted-file case; a file under a deeper mount such as /dev/shm is excluded.
func devEntries(a collect.Access, mounts mountTable) (facts.Envelope, facts.Envelope) {
	var paths []string
	for _, g := range []string{"/dev/*", "/dev/*/*"} {
		if m, err := a.Glob(g); err == nil {
			paths = append(paths, m...)
		}
	}
	sort.Strings(paths)
	truncated := false
	if len(paths) > devMaxEntries {
		paths = paths[:devMaxEntries]
		truncated = true
	}
	entries := []any{}
	nondevice := []any{}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if err != nil {
			continue
		}
		rec := map[string]any{
			"name": path.Base(p), "path": p, "kind": meta.Kind,
			"fstype": mounts.fstype(p), "mode": int(meta.Mode), "uid": int(meta.UID),
		}
		entries = append(entries, rec)
		// R181: a stray file counts only when the mount actually serving it is
		// exactly /dev — never a deeper mount (/dev/shm, /dev/mqueue, /dev/pts,
		// /dev/hugepages), whose tmpfs regular files are legitimate.
		if meta.Kind == "regular" && mounts.mountPoint(p) == "/dev" {
			nondevice = append(nondevice, rec)
		}
	}
	src := &facts.Source{Kind: "file", Path: "/dev"}
	de, nd := collect.OK(entries, src), collect.OK(nondevice, src)
	if truncated {
		// R189: a bounded walk that hit the cap must say so on BOTH envelopes,
		// so a control screens rather than reading a silently-truncated /dev
		// list as complete.
		de.Truncated, nd.Truncated = true, true
		de.Reason = "hit the devMaxEntries bound; the /dev listing is incomplete"
		nd.Reason = de.Reason
	}
	return de, nd
}
