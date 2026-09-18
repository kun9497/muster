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

// sysctlLeaves are the twelve kernel self-protection sysctls of spec B-2, in
// the spec's order. Adding one is a registry change and a control change;
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
}

// The persisted half of a sysctl: sysctl.d(5)'s four directories in
// DESCENDING precedence — a base name in an earlier one masks the same name
// in every later one — plus /etc/sysctl.conf, which systemd-sysctl applies
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
type sysctlAssign struct {
	key           string
	value         string
	ignoreMissing bool
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

// sysctlFiles resolves the chain the way systemd-sysctl resolves it: every
// *.conf of the four directories, the FIRST directory to offer a base name
// owning it, the survivors applied in lexicographic BASE-NAME order
// whichever directory each came from (sysctl.d(5): "the entry in the file
// with the lexicographically latest name will take precedence"), and
// /etc/sysctl.conf last.
//
// The stock /etc/sysctl.d/99-sysctl.conf symlink is modelled: when it points
// at /etc/sysctl.conf, the main file is read AT THAT POSITION and is not
// read again at the end, so a winner cites the real file and the byte-for-
// byte same assignments are not applied twice.
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

// mergeSysctl reduces the chain to one winner per variable: the files are
// already in application order, so the last assignment seen wins.
func mergeSysctl(files []sysctlFile) map[string]sysctlWinner {
	out := map[string]sysctlWinner{}
	for _, f := range files {
		for _, as := range f.assigns {
			out[as.key] = sysctlWinner{value: as.value, file: f.path, line: as.line, raw: as.raw}
		}
	}
	return out
}

// parseSysctlD reads one sysctl.d file. Blank lines and lines whose first
// non-space character is "#" or ";" are comments; a line with no "=" is not
// an assignment; a leading "-" is the ignore-if-missing prefix; and the key
// may be spelled with slashes.
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
		if !ok {
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
