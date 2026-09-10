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
// .rhosts/.shosts under /home/*/, /home/*/*/ and /root/. The dotfile globs
// MIRROR the declared home roots (M-53): a root that is declared but whose
// dotfiles are not would be stat'd and then have its .rhosts and shell files
// silently skipped, which is the vacuous PASS C4 exists to prevent. A home
// deeper than the declared roots stays undeclared on purpose - the enumerations
// then name it and go absent (M-52).
func filesReads() []string {
	reads := []string{passwdPath, shadowPath, securettyPath, groupPath, hostsPath, servicesPath, hostsLpdPath, exportsPath}
	reads = append(reads, hostsEquivPath, hostsAllowPath, hostsDenyPath, shellsPath, "/proc/self/mountinfo")
	reads = append(reads, systemEnvFiles...)
	reads = append(reads, "/home/*", "/home/*/*", rootHome)
	// The bounded /dev walk (one and two levels deep) for the stray-file check.
	reads = append(reads, "/dev/*", "/dev/*/*")
	// Startup scripts and dirs, syslog/journald configs, and the inetd/xinetd
	// permission facts. inetdConf and xinetdGlob reuse services.go's consts;
	// only xinetdConfPath is new (declaring a path files also declares that
	// services declares is harmless — the guard matches on the string).
	reads = append(reads, startupScriptGlobs...)
	reads = append(reads, startupDirList...)
	reads = append(reads, syslogConfGlobs...)
	reads = append(reads, journaldConfGlobs...)
	reads = append(reads, inetdConf, xinetdConfPath, xinetdGlob)
	// sudoers permission facts and the sudo.* derivation, plus the /var/log tree.
	reads = append(reads, sudoersPath, sudoersDDir, sudoersDGlob)
	reads = append(reads, varLogDir, varLogGlob1, varLogGlob2)
	dotfiles := append(append([]string{}, userEnvNames...), ".rhosts", ".shosts")
	for _, name := range dotfiles {
		reads = append(reads, "/home/*/"+name, "/home/*/*/"+name, "/root/"+name)
	}
	// The TCP wrappers library, declared literally: files.libwrap_present is
	// a presence probe over the paths its shared object lives at (L-9).
	return append(reads, libwrapPaths...)
}

// libwrapPaths is where libwrap.so.0 lives on the distributions muster
// judges — the Debian/Ubuntu multiarch directories for the two supported
// architectures, the RHEL-family /usr/lib64, and the plain /usr/lib of a
// 32-bit build. RHEL 8 and later ship no libwrap at all, which is exactly
// what the fact exists to say.
//
// C-1: no candidate may sit under a merged-usr alias. /lib64 and /lib are
// symlinks into /usr on every host muster targets, and the read primitive
// refuses a symlinked component (spec §8), so a candidate there would answer
// ErrSymlink — which pathPresent counts as occupied — and the probe would
// read true on every such host whether or not the library is installed. The
// alias targets are the candidates instead: /usr/lib64/libwrap.so.0 is what
// /lib64/libwrap.so.0 resolves to, and the unmerged Debian layout puts the
// library under /lib/<multiarch>, never /lib64.
var libwrapPaths = []string{
	"/usr/lib/x86_64-linux-gnu/libwrap.so.0",
	"/usr/lib/aarch64-linux-gnu/libwrap.so.0",
	"/usr/lib64/libwrap.so.0",
	"/usr/lib/libwrap.so.0",
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
	// /etc/exports' own permission facts (C1: a fixed path belongs here even
	// though its CONTENT is the nfs collector's — U-40's merged 2021 U-69
	// half). exportsPath is nfs.go's constant; declaring it in both
	// collectors is harmless (the guard matches on the string).
	writePermFacts(b, a, "files.etc_exports", exportsPath, groups, gmeta, gerr, false)

	// The home, environment-file and .rhosts enumeration, keyed on /etc/passwd
	// (C1: a path discovered from a daemon's configuration belongs to that
	// daemon; a home named in /etc/passwd is this collector's). mounts is
	// computed once here so Task 3's /dev walk reuses the same table.
	mounts, mountsErr := readMounts(a)
	if prows, ok := passwdRows(a, b); ok {
		shells, shellsEnv := loginShells(a)
		if e, untrusted := untrustedShells(shellsEnv); untrusted {
			// S3: /etc/shells could not be read from the file (denied/error, or
			// the libc-default fallback that omits /bin/bash). Every bash account
			// would then wrongly read as non-interactive and U-24/U-27/U-31/U-32
			// would pass vacuously, so the three enumerations carry that status
			// instead of a clean empty enumeration — the same shape as the
			// denied-passwd early return.
			b.Set("files.home_dirs", e)
			b.Set("files.env_files", e)
			b.Set("files.user_rhosts", e)
		} else {
			b.Set("files.home_dirs", homeDirs(a, prows, shells, mounts))
			b.Set("files.env_files", envFiles(a, prows, shells))
			b.Set("files.user_rhosts", userRhosts(a, prows, shells))
		}
	}

	// /root's own permission facts (U-14), /etc/hosts.equiv (U-27) and the
	// bounded /dev stray-file walk (U-26). mounts is reused, not re-read.
	writeRootHome(b, a, rootHome)
	writeHostsEquiv(b, a)
	writeHostsWrappers(b, a)
	if mountsErr != nil {
		// S4: an unreadable /proc/self/mountinfo makes the /dev stray-file
		// detection unreliable (no mount is known, so mountPoint answers "" and
		// nothing is flagged). Surface that read error on both dev keys rather
		// than publishing a clean empty dev_nondevice — a vacuous PASS for U-26.
		e := collect.FromReadError(mountsErr, collect.ReadMeta{})
		b.Set("files.dev_entries", e)
		b.Set("files.dev_nondevice", e)
	} else {
		de, nd := devEntries(a, mounts)
		b.Set("files.dev_entries", de)
		b.Set("files.dev_nondevice", nd)
	}

	// Startup scripts/dirs, the syslog and journald configuration inventories,
	// and the inetd/xinetd permission facts (U-17/U-21/U-20). groups is reused.
	b.Set("files.startup_scripts", startupScripts(a, groups))
	b.Set("files.startup_dirs", startupDirs(a, groups))
	b.Set("files.syslog_configs", syslogConfigs(a, groups))
	b.Set("files.journald_configs", journaldConfigs(a, groups))
	writeInetdPerm(b, a, groups)

	// sudoers permission facts, the sudo.* derived keys (U-63) and the
	// /var/log tree (U-67). groups is reused.
	sudoersFacts(b, a, groups)
	ld, lf := logTree(a, groups, gmeta, gerr)
	b.Set("files.log_dirs", ld)
	b.Set("files.log_files", lf)

	// Ruling L-9/L-20: whether this host has TCP wrappers at all. anyPresent
	// counts a symlink or a denied stat as present, so ok:false means every
	// candidate was ENOENT — the RHEL 8+ shape, where a tcp_wrappers=YES
	// setting and a deny-all /etc/hosts.deny restrict nothing. Evidence for
	// the operator and for 2M's U-28 gate; no control in this stage reads it.
	b.Set("files.libwrap_present", collect.OK(anyPresent(a, libwrapPaths),
		&facts.Source{Kind: "derived"}))

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

// untrustedShells reports whether the /etc/shells enumeration can be trusted
// for the interactive-home classification. It can only be trusted when it was
// read from the file itself (StatusOK with a file source). A denied/error
// read, or the libc-default fallback (StatusOK sourced "derived", which omits
// /bin/bash), is not: every bash account would then read as non-interactive
// and the home controls would pass vacuously (S3). When it is untrusted the
// returned envelope carries a screening status — the read error unchanged for
// a denied/error, or a denied envelope with the fallback's reason so the home
// enumeration keys never publish a clean list from an untrusted shell set.
func untrustedShells(shellsEnv facts.Envelope) (facts.Envelope, bool) {
	fromFile := shellsEnv.Status == facts.StatusOK && shellsEnv.Source != nil && shellsEnv.Source.Kind == "file"
	if fromFile {
		return facts.Envelope{}, false
	}
	if shellsEnv.Status != facts.StatusOK {
		e := shellsEnv
		e.Value = nil // a read error carries no value; drop the source list too
		e.Source = nil
		return e, true
	}
	// The libc-default fallback: StatusOK but not from the file. Turn it into a
	// denied envelope (never absent, which absent_means could excuse) carrying
	// its reason, so the home controls screen rather than pass vacuously.
	return collect.Denied(shellsEnv.Reason), true
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
