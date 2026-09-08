//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	sudoersPath   = "/etc/sudoers"
	sudoersDDir   = "/etc/sudoers.d"
	sudoersDGlob  = "/etc/sudoers.d/*"
	varLogDir     = "/var/log"
	varLogGlob1   = "/var/log/*"
	varLogGlob2   = "/var/log/*/*"
	logMaxEntries = 4096
	// sudoersReadLimit caps the /etc/sudoers content read (for the @includedir
	// and secure_path parse); /etc/sudoers is small, so 256 KiB is ample and
	// well under the 1 MiB readLimit used for larger files.
	sudoersReadLimit = 256 * 1024
)

var securePathRe = regexp.MustCompile(`secure_path\s*=\s*(.*)`)

// sudoersFacts writes the sudoers permission facts (stat only), the drop-in
// entries, and the sudo.* derived keys parsed from /etc/sudoers content.
func sudoersFacts(b *collect.Builder, a collect.Access, groups map[int]string) {
	// Permission facts of /etc/sudoers (stat; works without reading it).
	if meta, err := a.Stat(sudoersPath); err == nil {
		b.Set("files.etc_sudoers.mode", collect.OK(int(meta.Mode), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.uid", collect.OK(int(meta.UID), permSrc(sudoersPath)))
		b.Set("files.etc_sudoers.gid", collect.OK(int(meta.GID), permSrc(sudoersPath)))
		// acl_present follows writeRootHome/writePermFacts: the ACL probe's
		// error is the answer for the leaf (denied on a non-root run, since the
		// xattr read needs the file open O_RDONLY), never a quiet false.
		_, present, aerr := aclEntries(a, sudoersPath)
		if aerr != nil {
			b.Set("files.etc_sudoers.acl_present", collect.FromReadError(aerr, meta))
		} else {
			b.Set("files.etc_sudoers.acl_present", collect.OK(present, permSrc(sudoersPath)))
		}
	} else {
		e := statAbsentOrError(sudoersPath, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers."+k, e)
		}
	}
	// The drop-in directory and its entries.
	if meta, err := a.Stat(sudoersDDir); err == nil {
		b.Set("files.etc_sudoers_d.mode", collect.OK(int(meta.Mode), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.uid", collect.OK(int(meta.UID), permSrc(sudoersDDir)))
		b.Set("files.etc_sudoers_d.gid", collect.OK(int(meta.GID), permSrc(sudoersDDir)))
		_, present, aerr := aclEntries(a, sudoersDDir)
		if aerr != nil {
			b.Set("files.etc_sudoers_d.acl_present", collect.FromReadError(aerr, meta))
		} else {
			b.Set("files.etc_sudoers_d.acl_present", collect.OK(present, permSrc(sudoersDDir)))
		}
	} else {
		e := statAbsentOrError(sudoersDDir, err)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_sudoers_d."+k, e)
		}
	}
	b.Set("files.sudoers_d_entries", sudoersDropIns(a, groups))
	// sudo.* derived from reading /etc/sudoers (root-only). A non-root run
	// gets a denied read → the three sudo.* keys carry that status.
	writeSudoDerived(b, a)
}

// sudoersDropIns lists /etc/sudoers.d entries. sudo ignores a name ending in
// ~ or containing a "." (a backup or dotted file), recorded as ignored:true
// so the control skips it.
func sudoersDropIns(a collect.Access, groups map[int]string) facts.Envelope {
	matches, err := a.Glob(sudoersDGlob)
	if err != nil {
		return collect.FromReadError(err, collect.ReadMeta{})
	}
	sort.Strings(matches)
	rows := []any{}
	for _, p := range matches {
		row, ok := permRow(a, p, groups)
		if !ok {
			continue
		}
		base := path.Base(p)
		row["ignored"] = strings.HasSuffix(base, "~") || strings.Contains(base, ".")
		rows = append(rows, row)
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: sudoersDDir})
}

// writeSudoDerived parses /etc/sudoers for the @includedir directory and the
// Defaults secure_path. installed is whether /etc/sudoers exists at all.
func writeSudoDerived(b *collect.Builder, a collect.Access) {
	data, meta, err := a.ReadFile(sudoersPath, sudoersReadLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			src := &facts.Source{Kind: "derived"}
			b.Set("sudo.installed", collect.OK(false, src))
			b.Set("sudo.includedir", collect.OK("", src))
			b.Set("sudo.secure_path", collect.OK("", src))
			return
		}
		e := readErrorEnv(sudoersPath, err)                             // path-prefixed (C3)
		b.Set("sudo.installed", collect.OK(true, permSrc(sudoersPath))) // the file exists; we just cannot read it
		b.Set("sudo.includedir", e)
		b.Set("sudo.secure_path", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: sudoersPath}
	includedir, securePath := "", ""
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "@includedir") || strings.HasPrefix(line, "#includedir") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				includedir = f[1]
			}
		}
		if strings.HasPrefix(line, "Defaults") && strings.Contains(line, "secure_path") {
			// secure_path may carry spaces around the "=" (Rocky ships
			// `Defaults    secure_path = /sbin:...`), so match with a regex.
			if m := securePathRe.FindStringSubmatch(line); m != nil {
				securePath = strings.Trim(strings.TrimSpace(m[1]), `"`)
			}
		}
	}
	_ = meta
	b.Set("sudo.installed", collect.OK(true, src))
	b.Set("sudo.includedir", collect.OK(includedir, src))
	b.Set("sudo.secure_path", collect.OK(securePath, src))
}

// logTree records /var/log itself as a log_dirs row, then walks it one and two
// levels deep (bounded), recording each entry's group name and the
// group/other-writable flags. U-67 owns the allowed-group policy, so no
// "unexpected" flag is precomputed here (D09).
func logTree(a collect.Access, groups map[int]string) (facts.Envelope, facts.Envelope) {
	var paths []string
	for _, g := range []string{varLogGlob1, varLogGlob2} {
		m, err := a.Glob(g)
		if err != nil {
			e := collect.FromReadError(err, collect.ReadMeta{})
			return e, e
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	truncated := false
	if len(paths) > logMaxEntries {
		paths = paths[:logMaxEntries]
		truncated = true
	}
	dirs, files := []any{}, []any{}
	// /var/log itself is a log_dirs row (its own perms matter to U-67/SI-11).
	if meta, err := a.Stat(varLogDir); err == nil {
		dirs = append(dirs, map[string]any{
			"path": varLogDir, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group":          groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		})
	}
	for _, p := range paths {
		meta, err := a.Stat(p)
		if errors.Is(err, collect.ErrSymlink) {
			// A symlinked log entry is not itself a finding (its target is
			// judged where it lives): is_symlink:true and no reason, so the
			// reason-guard leaves it alone.
			files = append(files, map[string]any{
				"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
				"group_writable": false, "other_writable": false, "is_symlink": true,
			})
			continue
		}
		if err != nil {
			// an unreadable entry: record it as a finding row (carrying a
			// reason) so a denied log path is visible, never silently dropped.
			row := map[string]any{"path": p, "mode": -1, "uid": -1, "gid": -1, "group": "",
				"group_writable": false, "other_writable": false, "reason": readReason(p, err)}
			files = append(files, row)
			continue
		}
		row := map[string]any{
			"path": p, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			"group":          groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		}
		if meta.Kind == "dir" {
			dirs = append(dirs, row)
		} else {
			files = append(files, row)
		}
	}
	src := &facts.Source{Kind: "file", Path: varLogDir}
	de := withTruncation(collect.OK(dirs, src), truncated)
	fe := withTruncation(collect.OK(files, src), truncated)
	return de, fe
}
