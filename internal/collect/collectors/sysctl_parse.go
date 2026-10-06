//go:build linux

package collectors

import (
	"path"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// sysctlKey pairs a sysctl variable with the /proc/sys file that holds its
// runtime value: "kernel.kptr_restrict" is read from
// "/proc/sys/kernel/kptr_restrict". The path is spelled out rather than
// derived, so the twelve of spec B-2 (plus fs.suid_dumpable, which the
// coredump collector owns) can be read off one table; a test asserts each
// one IS the /proc/sys form of its name, which is what makes the spelling
// safe to review.
type sysctlKey struct{ key, path string }

// sysctlLeaves are the twelve kernel self-protection sysctls of spec B-2 and
// the twenty-six network settings of spec P-4, each in its spec's order. Adding one is a registry change and a control change;
// this table alone is not the contract.
var sysctlLeaves = []struct {
	leaf string // the registered fact key
	sysctlKey
}{
	{"kernel.sysctl.kptr_restrict", sysctlKey{"kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict"}},
	{"kernel.sysctl.dmesg_restrict", sysctlKey{"kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict"}},
	{"kernel.sysctl.yama_ptrace_scope", sysctlKey{"kernel.yama.ptrace_scope", "/proc/sys/kernel/yama/ptrace_scope"}},
	{"kernel.sysctl.randomize_va_space", sysctlKey{"kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space"}},
	{"kernel.sysctl.unprivileged_bpf_disabled", sysctlKey{"kernel.unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled"}},
	{"kernel.sysctl.bpf_jit_harden", sysctlKey{"net.core.bpf_jit_harden", "/proc/sys/net/core/bpf_jit_harden"}},
	{"kernel.sysctl.perf_event_paranoid", sysctlKey{"kernel.perf_event_paranoid", "/proc/sys/kernel/perf_event_paranoid"}},
	{"kernel.sysctl.sysrq", sysctlKey{"kernel.sysrq", "/proc/sys/kernel/sysrq"}},
	{"kernel.sysctl.protected_symlinks", sysctlKey{"fs.protected_symlinks", "/proc/sys/fs/protected_symlinks"}},
	{"kernel.sysctl.protected_hardlinks", sysctlKey{"fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks"}},
	{"kernel.sysctl.protected_fifos", sysctlKey{"fs.protected_fifos", "/proc/sys/fs/protected_fifos"}},
	{"kernel.sysctl.protected_regular", sysctlKey{"fs.protected_regular", "/proc/sys/fs/protected_regular"}},

	// The network sysctls of spec P-4, in its order. ipv6_bindv6only is not
	// here: it is an int evidence key, not a setting, and runSysctl writes it
	// apart (W-39).
	{"net.sysctl.ipv4_ip_forward", sysctlKey{"net.ipv4.ip_forward", "/proc/sys/net/ipv4/ip_forward"}},
	{"net.sysctl.ipv6_all_forwarding", sysctlKey{"net.ipv6.conf.all.forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"}},
	{"net.sysctl.ipv6_default_forwarding", sysctlKey{"net.ipv6.conf.default.forwarding", "/proc/sys/net/ipv6/conf/default/forwarding"}},
	{"net.sysctl.ipv4_all_accept_redirects", sysctlKey{"net.ipv4.conf.all.accept_redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects"}},
	{"net.sysctl.ipv4_default_accept_redirects", sysctlKey{"net.ipv4.conf.default.accept_redirects", "/proc/sys/net/ipv4/conf/default/accept_redirects"}},
	{"net.sysctl.ipv4_all_secure_redirects", sysctlKey{"net.ipv4.conf.all.secure_redirects", "/proc/sys/net/ipv4/conf/all/secure_redirects"}},
	{"net.sysctl.ipv4_default_secure_redirects", sysctlKey{"net.ipv4.conf.default.secure_redirects", "/proc/sys/net/ipv4/conf/default/secure_redirects"}},
	{"net.sysctl.ipv4_all_send_redirects", sysctlKey{"net.ipv4.conf.all.send_redirects", "/proc/sys/net/ipv4/conf/all/send_redirects"}},
	{"net.sysctl.ipv4_default_send_redirects", sysctlKey{"net.ipv4.conf.default.send_redirects", "/proc/sys/net/ipv4/conf/default/send_redirects"}},
	{"net.sysctl.ipv6_all_accept_redirects", sysctlKey{"net.ipv6.conf.all.accept_redirects", "/proc/sys/net/ipv6/conf/all/accept_redirects"}},
	{"net.sysctl.ipv6_default_accept_redirects", sysctlKey{"net.ipv6.conf.default.accept_redirects", "/proc/sys/net/ipv6/conf/default/accept_redirects"}},
	{"net.sysctl.ipv4_all_accept_source_route", sysctlKey{"net.ipv4.conf.all.accept_source_route", "/proc/sys/net/ipv4/conf/all/accept_source_route"}},
	{"net.sysctl.ipv4_default_accept_source_route", sysctlKey{"net.ipv4.conf.default.accept_source_route", "/proc/sys/net/ipv4/conf/default/accept_source_route"}},
	{"net.sysctl.ipv6_all_accept_source_route", sysctlKey{"net.ipv6.conf.all.accept_source_route", "/proc/sys/net/ipv6/conf/all/accept_source_route"}},
	{"net.sysctl.ipv6_default_accept_source_route", sysctlKey{"net.ipv6.conf.default.accept_source_route", "/proc/sys/net/ipv6/conf/default/accept_source_route"}},
	{"net.sysctl.ipv4_all_rp_filter", sysctlKey{"net.ipv4.conf.all.rp_filter", "/proc/sys/net/ipv4/conf/all/rp_filter"}},
	{"net.sysctl.ipv4_default_rp_filter", sysctlKey{"net.ipv4.conf.default.rp_filter", "/proc/sys/net/ipv4/conf/default/rp_filter"}},
	{"net.sysctl.ipv4_all_log_martians", sysctlKey{"net.ipv4.conf.all.log_martians", "/proc/sys/net/ipv4/conf/all/log_martians"}},
	{"net.sysctl.ipv4_default_log_martians", sysctlKey{"net.ipv4.conf.default.log_martians", "/proc/sys/net/ipv4/conf/default/log_martians"}},
	{"net.sysctl.ipv4_icmp_echo_ignore_broadcasts", sysctlKey{"net.ipv4.icmp_echo_ignore_broadcasts", "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"}},
	{"net.sysctl.ipv4_icmp_ignore_bogus_error_responses", sysctlKey{"net.ipv4.icmp_ignore_bogus_error_responses", "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses"}},
	{"net.sysctl.ipv4_tcp_syncookies", sysctlKey{"net.ipv4.tcp_syncookies", "/proc/sys/net/ipv4/tcp_syncookies"}},
	{"net.sysctl.ipv6_all_accept_ra", sysctlKey{"net.ipv6.conf.all.accept_ra", "/proc/sys/net/ipv6/conf/all/accept_ra"}},
	{"net.sysctl.ipv6_default_accept_ra", sysctlKey{"net.ipv6.conf.default.accept_ra", "/proc/sys/net/ipv6/conf/default/accept_ra"}},
	{"net.sysctl.ipv6_all_disable_ipv6", sysctlKey{"net.ipv6.conf.all.disable_ipv6", "/proc/sys/net/ipv6/conf/all/disable_ipv6"}},
	{"net.sysctl.ipv6_default_disable_ipv6", sysctlKey{"net.ipv6.conf.default.disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6"}},
}

// sysctlBindV6Only is net.ipv6.bindv6only, the evidence key of spec P-4: the
// processes collector reads it to know whether a "::" socket also accepts
// IPv4 (P-3). It is a plain int, so it is not a sysctlLeaves row (W-39).
const (
	sysctlBindV6OnlyLeaf = "net.sysctl.ipv6_bindv6only"
	sysctlBindV6OnlyPath = "/proc/sys/net/ipv6/bindv6only"
)

// sysctlIPv6Prefix is the /proc/sys directory a kernel without IPv6 does not
// have (the ipv6.disable=1 boot parameter, or IPv6 not built): a missing file
// under it says that, not merely that one knob is unknown (spec P-4).
const sysctlIPv6Prefix = "/proc/sys/net/ipv6/"

// The persisted half of a sysctl: sysctl.d(5)'s four directories in
// DESCENDING precedence — a base name in an earlier one masks the same name
// in every later one — plus /etc/sysctl.conf, which `sysctl --system` applies
// last of all.
var sysctlDirs = []string{
	"/etc/sysctl.d",
	"/run/sysctl.d",
	"/usr/local/lib/sysctl.d",
	"/usr/lib/sysctl.d",
}

const (
	sysctlConfPath = "/etc/sysctl.conf"
	// sysctlConfLink is the ONE symlink this collector models. Debian and
	// Ubuntu ship /etc/sysctl.d/99-sysctl.conf pointing at ../sysctl.conf;
	// the no-follow read primitive refuses it, and reporting the stock
	// layout of a supported distribution as an error would be muster's bug
	// rather than the host's (C4, the crypto-policies precedent).
	sysctlConfLink = "/etc/sysctl.d/99-sysctl.conf"
)

// sysctlPersistedReads is the persisted half of a declaration: the four
// directories' *.conf globs and the main file. Both collectors that resolve
// a sysctl — sysctl and coredump — declare exactly this.
func sysctlPersistedReads() []string {
	reads := make([]string, 0, len(sysctlDirs)+1)
	for _, d := range sysctlDirs {
		reads = append(reads, path.Join(d, "*.conf"))
	}
	return append(reads, sysctlConfPath)
}

// sysctlAssign is one "key = value" line of a sysctl.d file. ignoreMissing
// records the "-" prefix, which tells systemd-sysctl not to complain when
// the kernel has no such knob; the assignment itself still applies, so it is
// evidence rather than a filter.
//
// glob marks a key with a glob character in it ("net.ipv4.conf.*.rp_filter
// = 2"): systemd-sysctl applies it to every variable it matches that no line
// names explicitly. exclude marks a "-key" line with no "=" at all
// ("-net.ipv4.conf.all.rp_filter"): it assigns nothing and keeps the globs
// off that key (sysctl.d(5); systemd's own 50-default.conf ships both).
type sysctlAssign struct {
	key           string
	value         string
	ignoreMissing bool
	glob          bool
	exclude       bool
	line          int
	raw           string
}

// sysctlFile is one file of the chain and what it assigns, in file order.
type sysctlFile struct {
	path    string
	assigns []sysctlAssign
}

// sysctlWinner is the assignment that survived the merge for one variable.
type sysctlWinner struct {
	value string
	file  string
	line  int
	raw   string
}

// sysctlScan is one pass over the persisted chain: the files that were read
// in application order, the FIRST file that exists and could not be read
// (C3: it is the answer for every value the chain could set), and whether
// any read hit the size cap.
type sysctlScan struct {
	files     []sysctlFile
	readErr   *facts.Envelope
	truncated bool
}

func (s *sysctlScan) fail(p string, err error) {
	if s.readErr == nil {
		e := readErrorEnv(p, err)
		s.readErr = &e
	}
}

// read applies one file of the chain. A path that is not there is simply not
// part of this host's chain; what every other shape means is chainReadFailed's
// judgment (the one link a distribution itself ships at 99-sysctl.conf is
// handled by the caller, before the read).
func (s *sysctlScan) read(a collect.Access, p string) {
	data, meta, err := a.ReadFile(p, readLimit)
	if err != nil {
		if chainReadFailed(a, p, err) {
			s.fail(p, err)
		}
		return
	}
	s.truncated = s.truncated || meta.Truncated
	s.files = append(s.files, sysctlFile{path: p, assigns: parseSysctlD(data)})
}

// sysctlFiles resolves the chain the way `sysctl --system` resolves it: every
// *.conf of the four directories, the FIRST directory to offer a base name
// owning it, the survivors applied in lexicographic BASE-NAME order
// whichever directory each came from (sysctl.d(5): "the entry in the file
// with the lexicographically latest name will take precedence"), and
// /etc/sysctl.conf last.
//
// systemd-sysctl itself NEVER reads /etc/sysctl.conf — that file is not one
// of the directories sysctl.d(5) lists, which is the whole reason Debian and
// Ubuntu ship the /etc/sysctl.d/99-sysctl.conf symlink pointing at it. The
// last position is therefore procps' `sysctl --system` order, which is what a
// host actually applies at boot (K-20: on the lab procps.service is an alias
// of systemd-sysctl.service, so the two agree on everything else).
//
// That stock symlink is modelled: when it points at /etc/sysctl.conf, the
// main file is read AT THAT POSITION and is not read again at the end, so a
// winner cites the real file and the byte-for-byte same assignments are not
// applied twice.
func sysctlFiles(a collect.Access) sysctlScan {
	var s sysctlScan
	chosen := map[string]string{}
	var bases []string
	for _, d := range sysctlDirs {
		pattern := path.Join(d, "*.conf")
		matches, err := a.Glob(pattern)
		if err != nil {
			s.fail(pattern, err)
			continue
		}
		slices.Sort(matches)
		for _, m := range matches {
			base := path.Base(m)
			if _, dup := chosen[base]; dup {
				continue
			}
			chosen[base] = m
			bases = append(bases, base)
		}
	}
	slices.Sort(bases)

	mainRead := false
	for _, base := range bases {
		p := chosen[base]
		if p == sysctlConfLink {
			if target, ok := linkTarget(a, p); ok && target == sysctlConfPath {
				s.read(a, sysctlConfPath)
				mainRead = true
				continue
			}
		}
		s.read(a, p)
	}
	if !mainRead {
		s.read(a, sysctlConfPath)
	}
	return s
}

// sysctlEntry is one line that survived the merge: a value, or an exclusion.
type sysctlEntry struct {
	sysctlWinner
	pattern string // the key as written; a glob for a glob entry
	exclude bool
}

// sysctlWinners is the merged chain: the last line naming each key exactly,
// and the glob lines in the order they apply.
type sysctlWinners struct {
	exact map[string]sysctlEntry
	globs []sysctlEntry
}

// mergeSysctl reduces the chain the way systemd-sysctl does. The files are
// already in application order, and a later line for the same key - an
// assignment or a "-key" exclusion - replaces the earlier one, so the last
// line naming a key exactly is the one that counts. Glob lines are kept in
// the order they apply. A later line with the same pattern follows
// systemd's parse_file: when its value and its exclusion flag equal the
// entry already there, that entry stays where it is (and keeps citing its
// own line); only a different line replaces it and moves to the end.
func mergeSysctl(files []sysctlFile) sysctlWinners {
	w := sysctlWinners{exact: map[string]sysctlEntry{}}
	for _, f := range files {
		for _, as := range f.assigns {
			e := sysctlEntry{
				sysctlWinner: sysctlWinner{value: as.value, file: f.path, line: as.line, raw: as.raw},
				pattern:      as.key,
				exclude:      as.exclude,
			}
			if !as.glob {
				w.exact[as.key] = e
				continue
			}
			i := slices.IndexFunc(w.globs, func(g sysctlEntry) bool { return g.pattern == as.key })
			if i >= 0 {
				if old := w.globs[i]; old.value == e.value && old.exclude == e.exclude {
					continue
				}
				w.globs = slices.Delete(w.globs, i, i+1)
			}
			w.globs = append(w.globs, e)
		}
	}
	return w
}

// lookup is the persisted value of one concrete variable. A line naming the
// key exactly beats every glob WHATEVER the file order - systemd-sysctl
// skips a glob for any key the chain names explicitly - and when that line
// is a "-key" exclusion nothing is assigned at all. Otherwise the last glob
// that matches it and assigns a value wins.
func (w sysctlWinners) lookup(key string) (sysctlWinner, bool) {
	if e, ok := w.exact[key]; ok {
		if e.exclude {
			return sysctlWinner{}, false
		}
		return e.sysctlWinner, true
	}
	for i := len(w.globs) - 1; i >= 0; i-- {
		g := w.globs[i]
		if !g.exclude && sysctlGlobMatch(g.pattern, key) {
			return g.sysctlWinner, true
		}
	}
	return sysctlWinner{}, false
}

// sysctlGlobMatch matches a dotted glob key against a dotted variable one
// component at a time: systemd-sysctl expands the glob as a /proc/sys path,
// so "*" stands for one directory and never crosses a ".". glob(3) negates a
// class with "[!...]", which path.Match spells "[^...]".
func sysctlGlobMatch(pattern, key string) bool {
	pp := strings.Split(pattern, ".")
	kp := strings.Split(key, ".")
	if len(pp) != len(kp) {
		return false
	}
	for i := range pp {
		if ok, err := path.Match(globNegation(pp[i]), kp[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// globNegation rewrites the "[!" that opens a bracket class to path.Match's
// "[^". A "[!" inside a class, or after a backslash, is left alone.
func globNegation(p string) string {
	if !strings.Contains(p, "[!") {
		return p
	}
	b := []byte(p)
	inClass := false
	for i := 0; i < len(b); i++ {
		switch {
		case !inClass && b[i] == '\\':
			i++
		case !inClass && b[i] == '[':
			inClass = true
			if i+1 < len(b) && b[i+1] == '!' {
				b[i+1] = '^'
				i++
			}
		case inClass && b[i] == ']':
			inClass = false
		}
	}
	return string(b)
}

// parseSysctlD reads one sysctl.d file. Blank lines and lines whose first
// non-space character is "#" or ";" are comments; a leading "-" is the
// ignore-if-missing prefix; a "-key" line with no "=" excludes that key from
// the globs, and any other line with no "=" is not an assignment; a key with
// a glob character in it is a glob; and the key may be spelled with slashes.
func parseSysctlD(data []byte) []sysctlAssign {
	var out []sysctlAssign
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		ignore := strings.HasPrefix(line, "-")
		if ignore {
			line = strings.TrimSpace(line[1:])
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok && !ignore {
			continue
		}
		k = normalizeSysctlName(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		out = append(out, sysctlAssign{
			key:           k,
			value:         strings.TrimSpace(v),
			ignoreMissing: ignore,
			glob:          strings.ContainsAny(k, "*?["),
			exclude:       !ok,
			line:          i + 1,
			raw:           sourceRaw(raw),
		})
	}
	return out
}

// normalizeSysctlName turns the slash spelling of a variable into the dotted
// one. sysctl.d(5) decides by the FIRST separator: "kernel/yama/ptrace_scope"
// is the slash form and becomes dots, while "net.ipv4.conf.eth0.1.rp_filter"
// is already dotted and is left alone — which is the whole point of the
// slash form, since an interface name may contain a dot.
func normalizeSysctlName(name string) string {
	if i := strings.IndexAny(name, "/."); i >= 0 && name[i] == '/' {
		return strings.ReplaceAll(name, "/", ".")
	}
	return name
}
