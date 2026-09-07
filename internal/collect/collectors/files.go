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
	Declare: collect.Declaration{Reads: []string{passwdPath, shadowPath, securettyPath, groupPath, hostsPath, servicesPath, hostsLpdPath}, Needs: "none"},
	Run:     runFiles,
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
