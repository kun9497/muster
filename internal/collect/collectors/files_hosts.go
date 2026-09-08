//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	hostsAllowPath = "/etc/hosts.allow"
	hostsDenyPath  = "/etc/hosts.deny"
)

// hostsDenyAllRe matches a tcp_wrappers "ALL : ALL" daemon:client rule at the
// start of a hosts.deny line, case-insensitive and tolerant of spacing and a
// trailing ": DENY"/"PARANOID"/"spawn ..." clause.
var hostsDenyAllRe = regexp.MustCompile(`(?i)^\s*ALL\s*:\s*ALL\b`)

// writeHostsWrappers records the TCP-wrapper hosts.allow/hosts.deny facts
// that U-28's tcp_wrappers mechanism reads (and that U-56/2L will reuse). C1:
// these are fixed-path files, so they belong to the files collector, not the
// firewall one.
//
// A host with no /etc/hosts.deny at all is not restricted by tcp_wrappers:
// ENOENT answers files.etc_hosts_deny_all with an OK false (a definite "no",
// never absent — an absent value is exactly what absent_means could excuse,
// and U-28 needs a screenable answer) and both line lists as an OK empty
// list, mirroring files.etc_hosts_equiv_lines (R177). An existing-but-
// unreadable file is a read error on every leaf it could have set (C3):
// never a silent false.
func writeHostsWrappers(b *collect.Builder, a collect.Access) {
	allowLines, allowMeta, allowExisted, allowErr := readHostsLines(a, hostsAllowPath)
	b.Set("files.etc_hosts_allow_lines", hostsLinesEnvelope(allowLines, allowMeta, allowExisted, allowErr, hostsAllowPath))

	denyLines, denyMeta, denyExisted, denyErr := readHostsLines(a, hostsDenyPath)
	b.Set("files.etc_hosts_deny_lines", hostsLinesEnvelope(denyLines, denyMeta, denyExisted, denyErr, hostsDenyPath))

	switch {
	case denyErr != nil:
		// Existing-but-unreadable: the same read error reaches deny_all too,
		// never a quiet false (C3).
		b.Set("files.etc_hosts_deny_all", readErrorEnv(hostsDenyPath, denyErr))
	case !denyExisted:
		e := collect.OK(false, &facts.Source{Kind: "derived"})
		e.Reason = hostsDenyPath + " does not exist"
		b.Set("files.etc_hosts_deny_all", e)
	default:
		denyAll := false
		for _, l := range denyLines {
			if hostsDenyAllRe.MatchString(l) {
				denyAll = true
				break
			}
		}
		src := &facts.Source{Kind: "file", Path: hostsDenyPath}
		b.Set("files.etc_hosts_deny_all", collect.OKRead(denyAll, src, denyMeta))
	}
}

// readHostsLines reads p and splits it into non-comment, non-blank lines,
// mirroring the three ReadFile outcomes (R148): a successful read
// (lines, meta, true, nil), a missing file (nil, meta, false, nil), and any
// other error (nil, meta, false, err) that the caller must surface, never
// paper over.
func readHostsLines(a collect.Access, p string) (lines []string, meta collect.ReadMeta, existed bool, err error) {
	data, meta, err := a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, meta, false, nil
		}
		return nil, meta, false, err
	}
	for _, l := range splitLines(data) {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, meta, true, nil
}

// hostsLinesEnvelope turns one readHostsLines outcome into the envelope for
// its *_lines key: a read error on the file (path-prefixed, C3), an OK empty
// list with a "does not exist" reason when the file is absent (R177 shape —
// never absent itself, since a missing file is a definite "no configuration"
// rather than an unknown), or the OK line list from the file otherwise.
func hostsLinesEnvelope(lines []string, meta collect.ReadMeta, existed bool, err error, p string) facts.Envelope {
	if err != nil {
		return readErrorEnv(p, err)
	}
	if !existed {
		e := collect.OK([]any{}, &facts.Source{Kind: "derived"})
		e.Reason = p + " does not exist"
		return e
	}
	return collect.OKRead(toAnyList(lines), &facts.Source{Kind: "file", Path: p}, meta)
}

// toAnyList renders a []string as the []any a fact value carries, an empty
// input yielding [] rather than null (R50).
func toAnyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
