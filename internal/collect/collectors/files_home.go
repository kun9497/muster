//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// interactive reports whether shell is a real login shell: present in the
// /etc/shells set and not a nologin/false path. Service accounts on both
// families use /usr/sbin/nologin (or /sbin/nologin) or /bin/false, which are
// not listed in /etc/shells, so this filters them out (spec §10.2, the
// U-31/U-32 false-finding hazard).
func interactive(shell string, shells map[string]bool) bool {
	if strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") || shell == "" {
		return false
	}
	return shells[shell]
}

func homeDirs(a collect.Access, rows []passwdRow, shells map[string]bool, mounts mountTable) facts.Envelope {
	out := []any{}
	// undeclared names the INTERACTIVE accounts whose home muster declined to
	// examine (M-12/M-32). Their homes cannot be judged at all, so the whole
	// leaf becomes absent below rather than shipping denied rows U-31/U-32
	// would read as a finding.
	var undeclared []string
	for _, r := range rows {
		// R176: initialise EVERY field the controls where/require on, defaulted,
		// BEFORE the branch, so U-31/U-32's `each … require` never compares an
		// absent field on a denied/absent row (which would ERROR, not FAIL).
		rec := map[string]any{
			"user": r.name, "uid": r.uid, "home": r.home,
			"interactive":    interactive(r.shell, shells),
			"is_dir":         false,
			"owner_matches":  false,
			"group_writable": false,
			"other_writable": false,
			"on_remote_fs":   false,
			"mode":           -1,
			"owner_uid":      -1,
		}
		// Only stat a home inside the declaration; an interactive home is
		// essentially always /home/* or /root. An undeclared home cannot be
		// examined under our declaration: record it as denied with a reason,
		// never as absent (which absent_means could excuse).
		if r.home == "" || !declared(a, r.home) {
			if interactive(r.shell, shells) {
				undeclared = append(undeclared, r.name+" ("+r.home+")")
			}
			rec["stat_status"] = "denied"
			rec["reason"] = "home path outside the collector's declaration"
			out = append(out, rec)
			continue
		}
		meta, err := a.Stat(r.home)
		switch {
		case err == nil:
			rec["stat_status"] = "ok"
			rec["is_dir"] = meta.Kind == "dir"
			rec["mode"] = int(meta.Mode)
			rec["owner_uid"] = int(meta.UID)
			rec["owner_matches"] = int(meta.UID) == r.uid
			rec["group_writable"] = meta.Mode&0o020 != 0
			rec["other_writable"] = meta.Mode&0o002 != 0
			rec["on_remote_fs"] = isRemoteFS(mounts.fstype(r.home))
		case errors.Is(err, fs.ErrNotExist):
			rec["stat_status"] = "absent"
		case errors.Is(err, collect.ErrSymlink):
			// Stat returns ErrSymlink (an error) for a final symlink; it never
			// reaches the ok branch, so a home that is a symlink is unexaminable
			// and reported denied, not passed (R182).
			rec["stat_status"] = "denied"
			rec["reason"] = readReason(r.home, err)
		default:
			rec["stat_status"] = "denied"
			rec["reason"] = readReason(r.home, err)
		}
		out = append(out, rec)
	}
	src := &facts.Source{Kind: "file", Path: passwdPath}
	// M-12/M-32 (convention C4): a path muster CHOSE not to read is absent with
	// the path in the reason, never a denied row. An interactive home outside
	// the declaration is unexaminable, so the leaf as a whole is absent and
	// names each account (sorted by user, so the same host produces the same
	// bytes); U-31/U-32 then read MANUAL rather than the false FAIL a denied
	// row would produce. A NON-interactive account (/nonexistent on every stock
	// host) keeps its denied row and leaves the leaf ok.
	if len(undeclared) > 0 {
		slices.Sort(undeclared)
		e := collect.Absent("home path outside the collector's declaration: " + strings.Join(undeclared, ", "))
		e.Source = src
		return e
	}
	return collect.OK(out, src)
}

// systemEnvFiles are the fixed system-scope shell environment files; userEnv
// names are the per-home dotfiles. Both families' names are listed; only the
// ones that exist become rows.
var systemEnvFiles = []string{etcProfile, bashBashrc, etcBashrc, cshCshrc}
var userEnvNames = []string{".bashrc", ".bash_profile", ".profile", ".cshrc", ".login", ".bash_login"}

func envFiles(a collect.Access, rows []passwdRow, shells map[string]bool) facts.Envelope {
	out := []any{}
	stat := func(p, scope, homeUser string, uid int) {
		meta, err := a.Stat(p)
		switch {
		case err == nil:
			out = append(out, envFileRow(p, scope, homeUser, uid, meta))
		case errors.Is(err, collect.ErrSymlink):
			// Stat never returns a nil-error symlink (R182); a symlinked
			// environment file surfaces here as an unowned, unexaminable row.
			out = append(out, envSymlinkRow(p, scope, homeUser))
		}
		// absent/denied: no row (the file need not exist).
	}
	for _, p := range systemEnvFiles {
		stat(p, "system", "", 0) // system files must be root-owned (uid 0)
	}
	for _, r := range rows {
		if !interactive(r.shell, shells) {
			continue
		}
		for _, name := range userEnvNames {
			p := path.Join(r.home, name)
			if !declared(a, p) {
				continue
			}
			stat(p, "user", r.name, r.uid)
		}
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}

// envFileRow describes an environment file muster could stat. owner_ok means
// the file is owned by the account whose home it sits in, or by root
// (root-owned system files are fine); system-scope callers pass uid=0 (L3).
func envFileRow(p, scope, homeUser string, uid int, meta collect.ReadMeta) map[string]any {
	return map[string]any{
		"path": p, "scope": scope, "home_user": homeUser,
		"mode": int(meta.Mode), "owner_uid": int(meta.UID),
		"owner_ok":       int(meta.UID) == uid || int(meta.UID) == 0,
		"group_writable": meta.Mode&0o020 != 0,
		"other_writable": meta.Mode&0o002 != 0,
		"is_symlink":     false,
	}
}

// envSymlinkRow is the row for a symlinked environment file: not correctly
// owned, with the write flags defaulted false so U-24's `none where` clauses
// have every field they read (R176/R182).
func envSymlinkRow(p, scope, homeUser string) map[string]any {
	return map[string]any{
		"path": p, "scope": scope, "home_user": homeUser,
		"mode": -1, "owner_uid": -1,
		"owner_ok":       false,
		"group_writable": false,
		"other_writable": false,
		"is_symlink":     true,
	}
}

// userRhosts records .rhosts/.shosts under each interactive home, as derived
// flags only (never the body): owner_ok, has_plus (a line that is exactly "+"
// or begins "+ "), entry_count.
func userRhosts(a collect.Access, rows []passwdRow, shells map[string]bool) facts.Envelope {
	out := []any{}
	// readErr is the FIRST .rhosts/.shosts that EXISTS but this process cannot
	// read (M-13/M-30, convention C3): it becomes the whole leaf, because a
	// dropped row would let U-27 pass on a file nobody could see. It is local
	// to this call — never a package-level variable — so one host's denied read
	// cannot leak into the next collection.
	var readErr *facts.Envelope
	scan := func(p, homeUser string, ownerUID int) {
		if !declared(a, p) {
			return
		}
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && readErr == nil {
				e := readErrorEnv(p, err)
				readErr = &e
			}
			return // ENOENT: no row, the file need not exist
		}
		plus, count := false, 0
		for _, l := range splitLines(data) {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			count++
			if l == "+" || strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "+\t") {
				plus = true
			}
		}
		out = append(out, map[string]any{
			"path": p, "home_user": homeUser,
			"owner_ok": int(meta.UID) == ownerUID || int(meta.UID) == 0,
			"has_plus": plus, "entry_count": count,
		})
	}
	for _, r := range rows {
		if !interactive(r.shell, shells) {
			continue
		}
		scan(path.Join(r.home, ".rhosts"), r.name, r.uid)
		scan(path.Join(r.home, ".shosts"), r.name, r.uid)
	}
	if readErr != nil {
		// The read's status is the answer for the leaf, path-prefixed and
		// carrying no source list (the precedent passwdRows and untrustedShells
		// set for an enumeration that could not be completed).
		return *readErr
	}
	return collect.OK(out, &facts.Source{Kind: "file", Path: passwdPath})
}

type mountTable struct{ points map[string]string } // mount point -> fstype

// readMounts parses /proc/self/mountinfo. Each line's field 5 is the mount
// point and the token after " - " is the filesystem type. The read error is
// returned (not swallowed) so the /dev walk can surface it rather than
// reporting a clean empty dev_nondevice for an unreadable mountinfo (S4).
func readMounts(a collect.Access) (mountTable, error) {
	t := mountTable{points: map[string]string{}}
	data, _, err := a.ReadFile("/proc/self/mountinfo", readLimit)
	if err != nil {
		return t, err
	}
	for _, line := range splitLines(data) {
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		f := strings.Fields(line[:sep])
		after := strings.Fields(line[sep+3:])
		if len(f) < 5 || len(after) < 1 {
			continue
		}
		t.points[f[4]] = after[0]
	}
	return t, nil
}

// fstype returns the fstype of the longest mount point that is a prefix of p.
func (t mountTable) fstype(p string) string {
	best, bestFS := -1, ""
	for mp, fs := range t.points {
		if (p == mp || strings.HasPrefix(p, strings.TrimSuffix(mp, "/")+"/")) && len(mp) > best {
			best, bestFS = len(mp), fs
		}
	}
	return bestFS
}

func isRemoteFS(fs string) bool {
	switch fs {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "afs", "fuse.sshfs", "9p", "ceph", "glusterfs":
		return true
	}
	return false
}
