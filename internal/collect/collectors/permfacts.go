//go:build linux

package collectors

import (
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const groupPath = "/etc/group"

// groupNames maps gid to group name from /etc/group. Malformed lines are
// skipped: the name is a convenience for the reader; the judgment is on
// the numeric gid leaf. The read's meta comes back with the map so the
// caller can carry the truncation flag onto every group-name leaf (R70) —
// a /etc/group that hit the read cap may be missing the very entry a name
// was looked up in.
func groupNames(a collect.Access) (map[int]string, collect.ReadMeta, error) {
	data, meta, err := a.ReadFile(groupPath, readLimit)
	if err != nil {
		return nil, meta, err
	}
	out := map[int]string{}
	for _, l := range splitLines(data) {
		f := strings.Split(l, ":")
		if len(f) < 3 || f[0] == "" {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		if _, dup := out[gid]; !dup {
			out[gid] = f[0]
		}
	}
	return out, meta, nil
}

// permLeaves are the leaves every fixed-path permission fact carries
// (conventions C1/C2 in plan 2A).
var permLeaves = []string{"mode", "uid", "gid", "group", "group_readable", "group_writable", "other_readable", "other_writable", "acl_present"}

// writePermFacts writes the permission facts of one fixed path under
// prefix. A Stat failure reaches every leaf with the same envelope, so an
// absent file is absent everywhere and a denied one denied everywhere —
// never a partial set the check side could misread as "no ACL".
//
// groups, groupMeta and groupErr are what groupNames returned, passed in
// once per run rather than re-read per path. They belong to the group-name
// leaf alone: on success it is built with OKRead so a truncated
// /etc/group marks the name it may have missed (R70), and on failure it
// carries that failure — with /etc/group named in the reason, since the
// path that failed is not the path this call is about — instead of a
// silent "". Every other leaf comes from Stat and is unaffected.
func writePermFacts(b *collect.Builder, a collect.Access, prefix, path string, groups map[int]string, groupMeta collect.ReadMeta, groupErr error, withACL bool) {
	leaves := permLeaves
	if withACL {
		leaves = append(append([]string{}, permLeaves...), "acl_entries")
	}
	meta, err := a.Stat(path)
	if err != nil {
		e := collect.FromReadError(err, meta)
		for _, k := range leaves {
			b.Set(prefix+"."+k, e)
		}
		return
	}
	src := &facts.Source{Kind: "file", Path: path}
	// R51/R69: the raw 0o7777 bits as fstat reported them, not
	// FileMode.Perm(), which cannot carry setuid, setgid or sticky and
	// would silently report 0o4755 as 0o755.
	mode := int(meta.Mode)
	b.Set(prefix+".mode", collect.OK(mode, src))
	b.Set(prefix+".uid", collect.OK(int(meta.UID), src))
	b.Set(prefix+".gid", collect.OK(int(meta.GID), src))
	if groupErr != nil {
		e := collect.FromReadError(groupErr, groupMeta)
		e.Reason = groupPath + ": " + e.Reason
		b.Set(prefix+".group", e)
	} else {
		b.Set(prefix+".group", collect.OKRead(groups[int(meta.GID)], &facts.Source{Kind: "file", Path: groupPath}, groupMeta))
	}
	b.Set(prefix+".group_readable", collect.OK(mode&0o040 != 0, src))
	b.Set(prefix+".group_writable", collect.OK(mode&0o020 != 0, src))
	b.Set(prefix+".other_readable", collect.OK(mode&0o004 != 0, src))
	b.Set(prefix+".other_writable", collect.OK(mode&0o002 != 0, src))
	entries, present, aerr := aclEntries(a, path)
	if aerr != nil {
		e := collect.FromReadError(aerr, meta)
		b.Set(prefix+".acl_present", e)
		if withACL {
			b.Set(prefix+".acl_entries", e)
		}
		return
	}
	b.Set(prefix+".acl_present", collect.OK(present, src))
	if withACL {
		list := []any{} // R50: never nil
		for _, e := range entries {
			list = append(list, e)
		}
		b.Set(prefix+".acl_entries", collect.OK(list, src))
	}
}
