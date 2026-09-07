//go:build linux

package collectors

import (
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	nsswitchPath = "/etc/nsswitch.conf"
	// sssdConfPath is stat'd (never read) only to decide whether "sss" in
	// nsswitch.conf is evidence of a remote source (R127): authselect lists
	// "sss" on every RHEL-family host whether or not sssd has a domain
	// configured, so the file's presence is what actually distinguishes
	// the two.
	sssdConfPath = "/etc/sssd/sssd.conf"
)

// localNSS are the sources that answer from this host's own files or
// runtime; anything else means accounts also come from somewhere else.
// "sss" is deliberately not in this set: whether it counts as remote
// depends on whether sssd is actually configured (see nssRemote).
var localNSS = map[string]bool{"files": true, "compat": true, "systemd": true, "db": true}

// nssSources returns the sources of database db from nsswitch.conf: the
// words after "db:" that are not part of a bracketed action such as
// [NOTFOUND=return] or a multi-word one such as
// [SUCCESS=return NOTFOUND=continue UNAVAIL=continue]. glibc truncates a
// line at the first "#" wherever it appears, not only at the start, so a
// trailing "# comment" is dropped the same way a whole-line comment is.
// found is false when no such line exists (comments do not count), and
// line is the 1-based line of the one that does.
func nssSources(data []byte, db string) (sources []string, line int, found bool) {
	for i, raw := range splitLines(data) {
		l := raw
		if idx := strings.IndexByte(l, '#'); idx >= 0 {
			l = l[:idx]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		name, rest, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(name) != db {
			continue
		}
		inAction := false
		for _, w := range strings.Fields(rest) {
			if strings.HasPrefix(w, "[") {
				inAction = true
			}
			if inAction {
				if strings.HasSuffix(w, "]") {
					inAction = false
				}
				continue
			}
			sources = append(sources, w)
		}
		return sources, i + 1, true
	}
	return nil, 0, false
}

// nssRemote is true when any listed source is not local: not one of files,
// compat, systemd or db, and — R127 — not "sss" unless sssConfigured is
// true, since authselect writes "sss" into nsswitch.conf regardless of
// whether sssd actually has a domain configured.
func nssRemote(sourceLists [][]string, sssConfigured bool) bool {
	for _, l := range sourceLists {
		for _, s := range l {
			s = strings.ToLower(s)
			if localNSS[s] {
				continue
			}
			if s == "sss" && !sssConfigured {
				continue
			}
			return true
		}
	}
	return false
}

// nssListsSss reports whether "sss" appears on either source line, so
// writeNSS can explain a false accounts.nss.remote that would otherwise
// look like an ordinary local host (R127).
func nssListsSss(lists [][]string) bool {
	for _, l := range lists {
		for _, s := range l {
			if strings.EqualFold(s, "sss") {
				return true
			}
		}
	}
	return false
}

// writeNSS sets the three accounts.nss keys. A missing file is the glibc
// default (files), so remote is a confident false; an unreadable one is
// the read's status on every key, because "could not read" is not "local".
func writeNSS(a collect.Access, b *collect.Builder) {
	data, meta, err := a.ReadFile(nsswitchPath, readLimit)
	if err != nil {
		e := collect.FromReadError(err, meta)
		if e.Status == facts.StatusAbsent {
			// sssd.conf is never consulted on this path: with nsswitch.conf
			// itself missing there is nothing for "sss" to appear in.
			derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: nsswitchPath}}}
			for _, k := range []string{"accounts.nss.passwd_sources", "accounts.nss.group_sources"} {
				b.Set(k, collect.Absent(nsswitchPath+" does not exist; libc resolves from files"))
			}
			b.Set("accounts.nss.remote", collect.OK(false, derived))
			return
		}
		e.Reason = nsswitchPath + ": " + e.Reason
		b.Set("accounts.nss.passwd_sources", e)
		b.Set("accounts.nss.group_sources", e)
		b.Set("accounts.nss.remote", e)
		return
	}
	var lists [][]string
	for _, db := range [...]struct{ key, name string }{{"accounts.nss.passwd_sources", "passwd"}, {"accounts.nss.group_sources", "group"}} {
		sources, line, found := nssSources(data, db.name)
		if !found {
			b.Set(db.key, collect.Absent(db.name+" is not listed in "+nsswitchPath))
			continue
		}
		lists = append(lists, sources)
		list := []any{} // R50
		for _, s := range sources {
			list = append(list, s)
		}
		b.Set(db.key, collect.OKRead(list, &facts.Source{Kind: "file", Path: nsswitchPath, Line: line}, meta))
	}

	// R127: a Stat error of any kind means sssd is not configured — a
	// denied stat on a 0600 root-only file is impossible for this
	// root-only collector, so in practice this is ENOENT, the common case
	// of sssd not being installed at all.
	_, statErr := a.Stat(sssdConfPath)
	sssConfigured := statErr == nil

	// The remote verdict is derived from both files this path actually
	// consulted: the source lists parsed from nsswitch.conf, and the
	// sssd.conf Stat that decided whether a listed "sss" counts.
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: nsswitchPath}, {Kind: "file", Path: sssdConfPath}}}
	remoteVal := nssRemote(lists, sssConfigured)
	remoteEnv := collect.OKRead(remoteVal, derived, meta)
	// Fix round 1: the caveat is attached only when it actually explains the
	// answer — a false remote where "sss" alone was excluded. On a true
	// remote (some other source already made it so) the caveat would invite
	// the wrong inference that sss was the reason.
	if !remoteVal && !sssConfigured && nssListsSss(lists) {
		remoteEnv.Reason = "sss listed but " + sssdConfPath + " absent: not counted"
	}
	b.Set("accounts.nss.remote", remoteEnv)
}
