//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"sort"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var (
	// SysV scripts: /etc/init.d is a symlink to /etc/rc.d/init.d on the RHEL
	// family, so both roots are globbed; a run enumerates whichever resolves.
	startupScriptGlobs = []string{
		"/etc/init.d/*", "/etc/rc.d/init.d/*",
		"/etc/systemd/system/*", "/etc/systemd/system/*/*",
		"/etc/rc0.d/*", "/etc/rc1.d/*", "/etc/rc2.d/*", "/etc/rc3.d/*",
		"/etc/rc4.d/*", "/etc/rc5.d/*", "/etc/rc6.d/*",
		// RHEL keeps the runlevel link trees under /etc/rc.d as well.
		"/etc/rc.d/rc0.d/*", "/etc/rc.d/rc1.d/*", "/etc/rc.d/rc2.d/*", "/etc/rc.d/rc3.d/*",
		"/etc/rc.d/rc4.d/*", "/etc/rc.d/rc5.d/*", "/etc/rc.d/rc6.d/*",
	}
	startupDirList = []string{
		"/etc/init.d", "/etc/rc.d/init.d", "/etc/systemd/system",
		"/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d",
		"/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d",
		"/etc/rc.d/rc0.d", "/etc/rc.d/rc1.d", "/etc/rc.d/rc2.d", "/etc/rc.d/rc3.d",
		"/etc/rc.d/rc4.d", "/etc/rc.d/rc5.d", "/etc/rc.d/rc6.d",
	}
	syslogConfGlobs   = []string{"/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf", "/etc/syslog-ng/syslog-ng.conf", "/etc/syslog-ng/conf.d/*.conf"}
	journaldConfGlobs = []string{"/etc/systemd/journald.conf", "/etc/systemd/journald.conf.d/*.conf"}
	xinetdConfPath    = "/etc/xinetd.conf"
	// inetd.conf (/etc/inetd.conf) and the xinetd.d glob (/etc/xinetd.d/*) reuse
	// services.go's existing `inetdConf` and `xinetdGlob` consts — do not
	// redeclare them here (a duplicate const in the same package is a compile
	// error). Only /etc/xinetd.conf is new, declared above as xinetdConfPath.
)

// permRow stats one path into a permission row. ok is false only on ENOENT.
// A final-component symlink (Stat returns ErrSymlink) is is_symlink:true with
// the numeric fields defaulted (the link's own perms do not matter — its
// target is judged where it lives). Any other stat error yields a row with
// mode -1 and a reason, so a denied path is a finding, not a silent skip.
func permRow(a collect.Access, p string, groups map[int]string) (map[string]any, bool) {
	rec := map[string]any{
		"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
		"group_writable": false, "other_writable": false, "is_symlink": false,
	}
	meta, err := a.Stat(p)
	switch {
	case err == nil:
		rec["mode"], rec["uid"], rec["gid"] = int(meta.Mode), int(meta.UID), int(meta.GID)
		// group is evidence only — no control judges a permRow's group name, so a
		// truncated/denied /etc/group is not propagated here (unlike U-67's log
		// rows in logTree, which judge group and carry the read error).
		rec["group"] = groups[int(meta.GID)]
		rec["group_writable"] = meta.Mode&0o020 != 0
		rec["other_writable"] = meta.Mode&0o002 != 0
	case errors.Is(err, collect.ErrSymlink):
		rec["is_symlink"] = true
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	default:
		rec["reason"] = readReason(p, err)
	}
	return rec, true
}

// globRows stats every match of each glob (sorted, deduplicated) into a
// permission row. A glob that FAILS makes the whole fact the read error
// (never a partial/empty list — the vacuous-each hazard, §7.3).
func globRows(a collect.Access, globs []string, groups map[int]string, src *facts.Source) facts.Envelope {
	seen := map[string]bool{}
	var paths []string
	for _, g := range globs {
		m, err := a.Glob(g)
		if err != nil {
			return collect.FromReadError(err, collect.ReadMeta{})
		}
		for _, p := range m {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths)
	rows := []any{}
	for _, p := range paths {
		// A directory matched by a glob (a `.wants`/`.d` subdirectory under
		// /etc/systemd/system caught by /etc/systemd/system/*) is not a startup
		// file — only its regular files and symlinks are rows. Stat that resolves
		// to a dir is skipped; a final-component symlink returns ErrSymlink (not
		// nil), so it is NOT skipped here and permRow records it is_symlink:true.
		if meta, err := a.Stat(p); err == nil && meta.Kind == "dir" {
			continue
		}
		if row, ok := permRow(a, p, groups); ok {
			rows = append(rows, row)
		}
	}
	return collect.OK(rows, src)
}

func startupScripts(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, startupScriptGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/systemd/system"})
}

func startupDirs(a collect.Access, groups map[int]string) facts.Envelope {
	rows := []any{}
	for _, d := range startupDirList {
		if row, ok := permRow(a, d, groups); ok {
			rows = append(rows, row)
		}
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: "/etc/init.d"})
}

func syslogConfigs(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, syslogConfGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/rsyslog.conf"})
}

func journaldConfigs(a collect.Access, groups map[int]string) facts.Envelope {
	return globRows(a, journaldConfGlobs, groups, &facts.Source{Kind: "file", Path: "/etc/systemd/journald.conf"})
}

// writeInetdPerm publishes the inetd/xinetd permission facts. inetd.conf and
// xinetd.conf are fixed paths; xinetd_d is the per-fragment rows. All are
// absent on both stock families, which is a definite state, not an error.
func writeInetdPerm(b *collect.Builder, a collect.Access, groups map[int]string) {
	// /etc/inetd.conf: mode, uid, group_writable, other_readable.
	if meta, err := a.Stat(inetdConf); err == nil {
		b.Set("files.etc_inetd_conf.mode", collect.OK(int(meta.Mode), permSrc(inetdConf)))
		b.Set("files.etc_inetd_conf.uid", collect.OK(int(meta.UID), permSrc(inetdConf)))
		b.Set("files.etc_inetd_conf.group_writable", collect.OK(meta.Mode&0o020 != 0, permSrc(inetdConf)))
		b.Set("files.etc_inetd_conf.other_readable", collect.OK(meta.Mode&0o004 != 0, permSrc(inetdConf)))
	} else {
		e := statAbsentOrError(inetdConf, err)
		for _, k := range []string{"mode", "uid", "group_writable", "other_readable"} {
			b.Set("files.etc_inetd_conf."+k, e)
		}
	}
	// /etc/xinetd.conf: mode, uid.
	if meta, err := a.Stat(xinetdConfPath); err == nil {
		b.Set("files.etc_xinetd_conf.mode", collect.OK(int(meta.Mode), permSrc(xinetdConfPath)))
		b.Set("files.etc_xinetd_conf.uid", collect.OK(int(meta.UID), permSrc(xinetdConfPath)))
	} else {
		e := statAbsentOrError(xinetdConfPath, err)
		b.Set("files.etc_xinetd_conf.mode", e)
		b.Set("files.etc_xinetd_conf.uid", e)
	}
	b.Set("files.xinetd_d", globRows(a, []string{xinetdGlob}, groups, &facts.Source{Kind: "file", Path: "/etc/xinetd.d"}))
}

func permSrc(p string) *facts.Source { return &facts.Source{Kind: "file", Path: p} }

// statAbsentOrError maps a stat error to absent (ENOENT — a definite "not
// configured") or the read error (anything else).
func statAbsentOrError(p string, err error) facts.Envelope {
	if errors.Is(err, fs.ErrNotExist) {
		return collect.Absent(p + " does not exist")
	}
	return collect.FromReadError(err, collect.ReadMeta{})
}
