//go:build linux

package collectors

import (
	"context"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	passwdPath    = "/etc/passwd"
	securettyPath = "/etc/securetty"
	hostsPath     = "/etc/hosts"
	servicesPath  = "/etc/services"
	hostsLpdPath  = "/etc/hosts.lpd"
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
	reads = append(reads, shellsPath, "/proc/self/mountinfo")
	reads = append(reads, systemEnvFiles...)
	reads = append(reads, "/home/*", "/home/*/*", "/root")
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
