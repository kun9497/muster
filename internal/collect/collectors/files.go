//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	passwdPath     = "/etc/passwd"
	securettyPath  = "/etc/securetty"
	hostsPath      = "/etc/hosts"
	servicesPath   = "/etc/services"
	hostsLpdPath   = "/etc/hosts.lpd"
	hostsEquivPath = "/etc/hosts.equiv"
	rootHome       = "/root"
)

var filesCollector = collect.Collector{
	Name:    "files",
	Declare: collect.Declaration{Reads: filesReads(), Needs: "none"},
	Run:     runFiles,
}

// filesReads is the fixed candidate list plus the home-enumeration targets:
// /etc/shells and /proc/self/mountinfo, the four system-scope shell
// environment files (R178, so envFiles may stat them), the home roots
// /home/* and /root, the deeper home root /home/*/* (R187, so a home one
// level down such as /home/dept/alice is declared rather than reported
// unexaminable), and the per-home dotfile globs for every env-file name plus
// .rhosts/.shosts under both /home/*/ and /root/.
func filesReads() []string {
	reads := []string{passwdPath, shadowPath, securettyPath, groupPath, hostsPath, servicesPath, hostsLpdPath}
	reads = append(reads, hostsEquivPath, shellsPath, "/proc/self/mountinfo")
	reads = append(reads, systemEnvFiles...)
	reads = append(reads, "/home/*", "/home/*/*", rootHome)
	// The bounded /dev walk (one and two levels deep) for the stray-file check.
	reads = append(reads, "/dev/*", "/dev/*/*")
	dotfiles := append(append([]string{}, userEnvNames...), ".rhosts", ".shosts")
	for _, name := range dotfiles {
		reads = append(reads, "/home/*/"+name, "/root/"+name)
	}
	return reads
}

func runFiles(_ context.Context, a collect.Access, b *collect.Builder) error {
	// C1: files.* owns the permission facts of a fixed candidate path
	// list. /etc/group is read once and its outcome — names, meta and
	// error — is handed to every path, so one denied /etc/group costs the
	// group-name leaf and nothing else.
	groups, gmeta, gerr := groupNames(a)
	writePermFacts(b, a, "files.etc_passwd", passwdPath, groups, gmeta, gerr, true)
	writePermFacts(b, a, "files.etc_shadow", shadowPath, groups, gmeta, gerr, true)
	writePermFacts(b, a, "files.etc_hosts", hostsPath, groups, gmeta, gerr, false)
	writePermFacts(b, a, "files.etc_services", servicesPath, groups, gmeta, gerr, false)
	writePermFacts(b, a, "files.etc_hosts_lpd", hostsLpdPath, groups, gmeta, gerr, false)

	// The home, environment-file and .rhosts enumeration, keyed on /etc/passwd
	// (C1: a path discovered from a daemon's configuration belongs to that
	// daemon; a home named in /etc/passwd is this collector's). mounts is
	// computed once here so Task 3's /dev walk reuses the same table.
	mounts := readMounts(a)
	if prows, ok := passwdRows(a, b); ok {
		shells, _ := loginShells(a)
		b.Set("files.home_dirs", homeDirs(a, prows, shells, mounts))
		b.Set("files.env_files", envFiles(a, prows, shells))
		b.Set("files.user_rhosts", userRhosts(a, prows, shells))
	}

	// /root's own permission facts (U-14), /etc/hosts.equiv (U-27) and the
	// bounded /dev stray-file walk (U-26). mounts is reused, not re-read.
	writeRootHome(b, a, rootHome)
	writeHostsEquiv(b, a)
	de, nd := devEntries(a, mounts)
	b.Set("files.dev_entries", de)
	b.Set("files.dev_nondevice", nd)

	// /etc/securetty is absent on RHEL 8+ and on the Debian family; the
	// control that reads it treats that as "this mechanism is not in use".
	data, smeta, err := a.ReadFile(securettyPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, smeta)
		b.Set("files.etc_securetty", e)
		b.Set("files.etc_securetty_lines", e)
		return nil
	}
	ssrc := &facts.Source{Kind: "file", Path: securettyPath}
	lines := []any{} // R50: an empty file yields [], never null
	for _, l := range splitLines(data) {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	// R70: file-derived facts carry the read's truncation flag.
	b.Set("files.etc_securetty", collect.OKRead(map[string]any{
		"mode": int(smeta.Mode),
		"uid":  int(smeta.UID),
		"gid":  int(smeta.GID),
	}, ssrc, smeta))
	b.Set("files.etc_securetty_lines", collect.OKRead(lines, ssrc, smeta))
	return nil
}

// passwdRows reads and parses /etc/passwd. On a read error it writes the three
// home-enumeration keys as the read error (a denied passwd must not read as an
// empty enumeration) and returns ok=false so the caller skips the home block.
func passwdRows(a collect.Access, b *collect.Builder) ([]passwdRow, bool) {
	data, meta, err := a.ReadFile(passwdPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, meta)
		b.Set("files.home_dirs", e)
		b.Set("files.env_files", e)
		b.Set("files.user_rhosts", e)
		return nil, false
	}
	rows, _ := parsePasswd(data)
	return rows, true
}

// writeRootHome records /root's permission facts: only the six leaves U-14
// judges (mode, uid, gid, group_writable, other_writable, acl_present), not
// the ten writePermFacts registers — /root needs no group name, group/other
// readable bits or acl_entries list. Five come from a single Stat and
// acl_present from the ACL probe; a Stat failure reaches all six with the
// same envelope, so an absent /root is absent everywhere and a denied one
// denied everywhere (R176).
func writeRootHome(b *collect.Builder, a collect.Access, p string) {
	leaves := []string{"mode", "uid", "gid", "group_writable", "other_writable", "acl_present"}
	meta, err := a.Stat(p)
	if err != nil {
		e := collect.FromReadError(err, meta)
		for _, k := range leaves {
			b.Set("files.root_home."+k, e)
		}
		return
	}
	src := &facts.Source{Kind: "file", Path: p}
	mode := int(meta.Mode)
	b.Set("files.root_home.mode", collect.OK(mode, src))
	b.Set("files.root_home.uid", collect.OK(int(meta.UID), src))
	b.Set("files.root_home.gid", collect.OK(int(meta.GID), src))
	b.Set("files.root_home.group_writable", collect.OK(mode&0o020 != 0, src))
	b.Set("files.root_home.other_writable", collect.OK(mode&0o002 != 0, src))
	// acl_present follows the same rule as writePermFacts: a probe error is the
	// answer for the leaf, never a quiet false.
	_, present, aerr := aclEntries(a, p)
	if aerr != nil {
		b.Set("files.root_home.acl_present", collect.FromReadError(aerr, meta))
		return
	}
	b.Set("files.root_home.acl_present", collect.OK(present, src))
}

// writeHostsEquiv records /etc/hosts.equiv's mode and uid and its non-comment
// lines from a single read. R177: a file that does not exist is compliant, so
// files.etc_hosts_equiv_lines is an OK empty list (never absent — absent would
// let U-27's `none where {op: matches}` screen to absent_means and pass a "+"
// .rhosts the wrong way), while the two perm leaves are absent. A denied or
// other read error writes that read error to all three keys. This mirrors the
// files.etc_securetty_lines read shape (the real line-list precedent);
// files.etc_hosts_lpd carries only permission leaves, no line list.
func writeHostsEquiv(b *collect.Builder, a collect.Access) {
	data, meta, err := a.ReadFile(hostsEquivPath, readLimit)
	switch {
	case err == nil:
		src := &facts.Source{Kind: "file", Path: hostsEquivPath}
		b.Set("files.etc_hosts_equiv.mode", collect.OKRead(int(meta.Mode), src, meta))
		b.Set("files.etc_hosts_equiv.uid", collect.OKRead(int(meta.UID), src, meta))
		lines := []any{} // R50: an empty file yields [], never null
		for _, l := range splitLines(data) {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		b.Set("files.etc_hosts_equiv_lines", collect.OKRead(lines, src, meta))
	case errors.Is(err, fs.ErrNotExist):
		absent := collect.Absent("/etc/hosts.equiv does not exist")
		b.Set("files.etc_hosts_equiv.mode", absent)
		b.Set("files.etc_hosts_equiv.uid", absent)
		lines := collect.OK([]any{}, &facts.Source{Kind: "derived"})
		lines.Reason = "/etc/hosts.equiv does not exist"
		b.Set("files.etc_hosts_equiv_lines", lines)
	default:
		e := collect.FromReadError(err, meta)
		b.Set("files.etc_hosts_equiv.mode", e)
		b.Set("files.etc_hosts_equiv.uid", e)
		b.Set("files.etc_hosts_equiv_lines", e)
	}
}
