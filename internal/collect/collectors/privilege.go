//go:build linux

package collectors

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The privilege collector (P-6): what the dynamic loader preloads into every
// program, and who can write to the control socket of a container runtime
// whose API is root. The ld.so.preload grammar is privilege_parse.go's.

const (
	ldSoPreloadPath = "/etc/ld.so.preload"

	privilegeLdSoPreload   = "privilege.ld_so_preload"
	privilegeSockets       = "privilege.runtime_sockets"
	privilegeGroupMembers  = "privilege.runtime_group_members"
	socketGroupWritableBit = 0o020
	socketOtherWritableBit = 0o002
)

// runtimeSockets are the control sockets of the four runtimes, at their
// physical paths: /var/run is a symlink to /run on every release and the
// read primitive refuses a symlink, so cri-o's configured
// /var/run/crio/crio.sock is declared as /run/crio/crio.sock.
var runtimeSockets = []string{"/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock", "/run/crio/crio.sock"}

var privilegeCollector = collect.Collector{
	Name: "privilege",
	Declare: collect.Declaration{
		// V-10: never /var/run/... (a symlink the primitive refuses).
		Reads: []string{ldSoPreloadPath, groupPath, passwdPath, "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock", "/run/crio/crio.sock"},
		Needs: "none",
	},
	Run: runPrivilege,
}

// socketStat is one runtime socket's Stat.
type socketStat struct {
	path   string
	exists bool
	mode   int
	uid    int
	gid    int
}

func runPrivilege(_ context.Context, a collect.Access, b *collect.Builder) error {
	b.Set(privilegeLdSoPreload, ldSoPreload(a))

	groupData, groupMeta, groupErr := a.ReadFile(groupPath, readLimit)
	var groups []groupRow
	names := map[int]string{}
	if groupErr == nil {
		groups, _ = parseGroup(groupData)
		for _, g := range groups {
			if _, dup := names[g.gid]; !dup && g.gid >= 0 {
				names[g.gid] = g.name
			}
		}
	}
	passwdData, passwdMeta, passwdErr := a.ReadFile(passwdPath, readLimit)

	// Every socket is stat-ed; the first failure other than "not there"
	// is the whole leaf (C3), and the members derive from it.
	var socks []socketStat
	var sockErr *facts.Envelope
	inputs := make([]facts.Source, 0, len(runtimeSockets)+2)
	for _, p := range runtimeSockets {
		inputs = append(inputs, facts.Source{Kind: "file", Path: p})
		meta, err := a.Stat(p)
		switch {
		case err == nil:
			socks = append(socks, socketStat{path: p, exists: true, mode: int(meta.Mode), uid: int(meta.UID), gid: int(meta.GID)})
		case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
			socks = append(socks, socketStat{path: p, mode: -1, uid: -1, gid: -1})
		case sockErr == nil:
			e := readErrorEnv(p, err)
			e.Source = &facts.Source{Kind: "file", Path: p}
			sockErr = &e
		}
	}
	if sockErr != nil {
		b.Set(privilegeSockets, *sockErr)
		b.Set(privilegeGroupMembers, *sockErr)
		return nil
	}

	sockInputs := slices.Clone(inputs)
	if groupErr == nil {
		sockInputs = append(sockInputs, facts.Source{Kind: "file", Path: groupPath})
	}
	rows := make([]any, 0, len(socks))
	for _, s := range socks {
		group := ""
		if s.exists && groupErr == nil {
			group = names[s.gid]
		}
		rows = append(rows, map[string]any{
			"path":           s.path,
			"exists":         s.exists,
			"mode":           s.mode,
			"uid":            s.uid,
			"gid":            s.gid,
			"group":          group,
			"group_writable": s.exists && s.mode&socketGroupWritableBit != 0,
			"other_writable": s.exists && s.mode&socketOtherWritableBit != 0,
		})
	}
	// A truncated /etc/group may be missing the very line a name was
	// looked up in (R70).
	b.Set(privilegeSockets, withTruncation(collect.OK(rows, &facts.Source{Kind: "derived", Inputs: sockInputs}), groupErr == nil && groupMeta.Truncated))

	switch {
	case groupErr != nil:
		e := readErrorEnv(groupPath, groupErr)
		e.Source = &facts.Source{Kind: "file", Path: groupPath}
		b.Set(privilegeGroupMembers, e)
		return nil
	case passwdErr != nil:
		e := readErrorEnv(passwdPath, passwdErr)
		e.Source = &facts.Source{Kind: "file", Path: passwdPath}
		b.Set(privilegeGroupMembers, e)
		return nil
	}
	users, _ := parsePasswd(passwdData)
	members := groupMembers(socks, names, groups, users)
	memberInputs := append(inputs, facts.Source{Kind: "file", Path: groupPath}, facts.Source{Kind: "file", Path: passwdPath})
	b.Set(privilegeGroupMembers, withTruncation(collect.OK(members, &facts.Source{Kind: "derived", Inputs: memberInputs}), groupMeta.Truncated || passwdMeta.Truncated))
	return nil
}

// ldSoPreload is the privilege.ld_so_preload envelope: a missing file is the
// normal state, an ok empty list; one that exists and cannot be read is the
// read's status (C3).
func ldSoPreload(a collect.Access) facts.Envelope {
	src := &facts.Source{Kind: "file", Path: ldSoPreloadPath}
	data, meta, err := a.ReadFile(ldSoPreloadPath, readLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return collect.OK([]any{}, src)
	case err != nil:
		e := readErrorEnv(ldSoPreloadPath, err)
		e.Source = src
		return e
	}
	list := []any{}
	for _, entry := range parseLdSoPreload(data) {
		list = append(list, entry)
	}
	return withTruncation(collect.OK(list, src), meta.Truncated)
}

// groupMembers lists, for every existing group-writable socket, the accounts
// that hold its gid: the supplementary members of every /etc/group line with
// that gid (the kernel checks the number, so each such line grants it) and
// the /etc/passwd accounts whose primary gid it is, uid 0 left out (root
// needs no group to reach a socket). One row per (group, member, socket),
// sorted by group, member and socket; a member /etc/passwd does not name
// has uid -1. Never nil.
func groupMembers(socks []socketStat, names map[int]string, groups []groupRow, users []passwdRow) []any {
	uidOf := map[string]int{}
	for _, u := range users {
		if _, dup := uidOf[u.name]; !dup {
			uidOf[u.name] = u.uid
		}
	}
	type member struct {
		group, name, socket string
		uid                 int
	}
	var found []member
	for _, s := range socks {
		if !s.exists || s.mode&socketGroupWritableBit == 0 {
			continue
		}
		seen := map[string]bool{}
		add := func(name string) {
			if seen[name] {
				return
			}
			seen[name] = true
			uid, known := uidOf[name]
			if !known {
				uid = -1
			}
			if uid == 0 {
				return
			}
			found = append(found, member{group: names[s.gid], name: name, socket: s.path, uid: uid})
		}
		for _, g := range groups {
			if g.gid == s.gid {
				for _, m := range g.members {
					add(m)
				}
			}
		}
		for _, u := range users {
			if u.gid == s.gid {
				add(u.name)
			}
		}
	}
	slices.SortFunc(found, func(x, y member) int {
		return cmp.Or(cmp.Compare(x.group, y.group), cmp.Compare(x.name, y.name), cmp.Compare(x.socket, y.socket))
	})
	out := make([]any, 0, len(found))
	for _, m := range found {
		out = append(out, map[string]any{"group": m.group, "member": m.name, "uid": m.uid, "socket": m.socket})
	}
	return out
}
