//go:build linux

package collectors

import (
	"path"
	"slices"
	"strings"
)

// homeRoot is one directory the walk treats as somebody's home (A-16). The
// hidden rule reads it — a dotfile in a home is the normal state and is not
// a finding — and the mount plan reads it too, because a home is where a
// rootless container store lives.
//
// kind is "user" or "service". The two kinds are exempt differently: a user
// home exempts a dotfile at any depth (a whole ~/.config tree is ordinary),
// a service home exempts its direct children only (/var/www/html/.cache is
// a served tree, not a lived-in one). user is the account the pw_dir came
// from, and is empty on the two prefix rows, which stand for /root and
// every directory under /home whatever /etc/passwd says.
type homeRoot struct{ path, user, kind string }

// homePrefixRows are the two user-home roots the rule always carries. They
// are prefixes, not directories that must exist: the rule is "a path under
// /root/ or /home/<name>/", so it holds for an account /etc/passwd does not
// list (an LDAP user whose home was created by pam_mkhomedir) and on a host
// whose /etc/passwd could not be read at all.
var homePrefixRows = []homeRoot{
	{path: "/root", kind: "user"},
	{path: "/home", kind: "user"},
}

// notAHome is A-16's exclusion list: pw_dir values that name a system
// directory rather than a home. Stock /etc/passwd carries nobody:/ on the
// RHEL family and daemon:/usr/sbin on the Debian family, and treating those
// as homes would exempt the whole filesystem, or the whole of /usr/sbin,
// from the hidden rule. "/" is excluded by equality only — every path is
// under it, so "equal or under" there would exclude every home there is.
var notAHome = []string{
	"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/usr", "/etc",
	"/dev", "/boot", "/proc", "/sys", "/run", "/tmp", "/var/tmp",
}

// classifyHomes turns /etc/passwd rows into the home set the walk uses. The
// two prefix rows come first, then every service home sorted by path and
// then by account, so the recorded set is byte-identical for the same file
// (A-14). A pw_dir shared by several accounts — _apt, messagebus and
// tcpdump all sit on /nonexistent — yields one row per account, and a
// pw_dir that does not exist is still a row: the set says what the rule
// used, not what the filesystem has.
//
// A pw_dir that is itself a user home (/root, /home/alice) adds no row: the
// two prefix rows already cover it at any depth. rows nil — an unreadable
// /etc/passwd — therefore yields the two prefix rows alone, which degrades
// toward RECORDING a service home's dotfiles rather than toward hiding
// them: the walk would rather report a normal dotfile than miss one.
func classifyHomes(rows []passwdRow) []homeRoot {
	service := make([]homeRoot, 0, len(rows))
	for _, r := range rows {
		if !strings.HasPrefix(r.home, "/") {
			continue // an empty or relative pw_dir names no directory
		}
		h := path.Clean(r.home)
		if h == "/" || underOrEqualAny(h, notAHome) {
			continue
		}
		if underOrEqual(h, "/root") || underOrEqual(h, "/home") {
			continue // already covered by the prefix rows
		}
		service = append(service, homeRoot{path: h, user: r.name, kind: "service"})
	}
	slices.SortFunc(service, func(a, b homeRoot) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(a.user, b.user)
	})
	out := make([]homeRoot, 0, len(homePrefixRows)+len(service))
	out = append(out, homePrefixRows...)
	return append(out, service...)
}

// underUserHome reports whether p lies inside a user home — under /root/ or
// at least one component below /home/<name> (A-16). The home directory
// itself is not under a home, so /home/alice is not exempt while
// /home/alice/.bashrc is, and /home/.snapshots — a btrfs snapshot
// directory, not anybody's home — stays a hidden candidate.
func underUserHome(p string) bool {
	if strings.HasPrefix(p, "/root/") {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/home/")
	if !ok {
		return false
	}
	name, sub, ok := strings.Cut(rest, "/")
	return ok && name != "" && sub != ""
}

// directChildOfServiceHome reports whether p is an immediate child of a
// service home. Deeper entries are candidates: /var/lib/postgresql/.psql_history
// is a daemon's own dotfile, /var/www/html/.cache is content under a served
// tree.
func directChildOfServiceHome(p string, homes []homeRoot) bool {
	dir := path.Dir(p)
	for _, h := range homes {
		if h.kind == "service" && h.path == dir {
			return true
		}
	}
	return false
}
