//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// sysctlCollector writes the twelve kernel self-protection sysctls of spec
// B-2 and the twenty-six network settings of spec P-4 as two-home settings,
// and net.ipv6.bindv6only as a plain int (P-4's one evidence key).
//
// B-3: there is NO sysctl binary in the declaration and no command at all —
// /proc/sys is the kernel's own answer and reading it needs no program. The
// judged side is the runtime one (default_on: effective, and effective IS
// runtime): a value the kernel compiles in has no persisted line anywhere,
// and a control that read both sides would warn "this reverts on reboot" on
// every host for a setting that does not revert. The persisted side rides
// along in the envelope, which is what makes a host whose running value has
// drifted from its sysctl.d visible at all.
var sysctlCollector = collect.Collector{
	Name:    "sysctl",
	Declare: collect.Declaration{Reads: sysctlReads(), Needs: "none"},
	Run:     runSysctl,
}

func sysctlReads() []string {
	reads := make([]string, 0, len(sysctlLeaves)+len(sysctlDirs)+3)
	for _, l := range sysctlLeaves {
		reads = append(reads, l.path)
	}
	reads = append(reads, sysctlBindV6OnlyPath, sysctlDisableV6Glob)
	return append(reads, sysctlPersistedReads()...)
}

func runSysctl(_ context.Context, a collect.Access, b *collect.Builder) error {
	scan := sysctlFiles(a)
	winners := mergeSysctl(scan.files)
	runtime := map[string]facts.Envelope{}
	for _, l := range sysctlLeaves {
		s := sysctlSetting(a, l.sysctlKey, scan, winners)
		runtime[l.leaf] = *s.Runtime
		b.SetSetting(l.leaf, s)
	}
	b.Set(sysctlBindV6OnlyLeaf, readProcSys(a, sysctlBindV6OnlyPath))
	b.Set(sysctlIPv6DisabledLeaf, ipv6Disabled(a, runtime[sysctlDisableAllLeaf], runtime[sysctlDisableDefaultLeaf]))
	return nil
}

// The derived gate of the IPv6 controls (W-79, W-86): IPv6 is off only
// when disable_ipv6 is 1 on all, on default AND on every present interface
// but lo, the predicate the exposure verdict uses too (W-76). One leaf alone
// is no gate: default=1 with all=0 leaves IPv6 live on every present
// interface, and all=1, default=1 with conf.eth1.disable_ipv6=0 (the "IPv6 on
// one interface" recipe) leaves it live on eth1 — the kernel's drop test is
// the device's own flag, which a later per-interface write re-enables.
const (
	sysctlIPv6DisabledLeaf   = "net.sysctl.ipv6_disabled"
	sysctlDisableAllLeaf     = "net.sysctl.ipv6_all_disable_ipv6"
	sysctlDisableDefaultLeaf = "net.sysctl.ipv6_default_disable_ipv6"
	// sysctlDisableV6Glob is every conf/<name>/disable_ipv6, all and
	// default included; both this collector and processes declare it.
	sysctlDisableV6Glob = sysctlIPv6Prefix + "conf/*/disable_ipv6"
)

// ipv6InterfaceFiles lists the per-interface disable_ipv6 files of W-86:
// every conf/<if> but all, default (read as settings of their own) and lo
// (loopback traffic never comes from off the host), sorted. A conf directory
// this run may not list is the answer for the predicate (C3); a kernel
// without IPv6 has no conf directory and lists nothing.
func ipv6InterfaceFiles(a collect.Access) ([]string, *facts.Envelope) {
	matches, err := a.Glob(sysctlDisableV6Glob)
	if err != nil {
		e := readFailure(sysctlDisableV6Glob, err)
		return nil, &e
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		switch path.Base(path.Dir(m)) {
		case "all", "default", "lo":
			continue
		}
		out = append(out, m)
	}
	slices.Sort(out)
	return out, nil
}

// ipv6DisabledRank orders the statuses a derived leaf can inherit: a read
// that failed outweighs one that found nothing, so the worse of the two
// reads is the answer when either is not ok.
func ipv6DisabledRank(s facts.Status) int {
	switch s {
	case facts.StatusOK:
		return 0
	case facts.StatusAbsent:
		return 1
	case facts.StatusUnsupported:
		return 2
	case facts.StatusDenied:
		return 3
	case facts.StatusTimeout:
		return 4
	default: // error
		return 5
	}
}

// ipv6Disabled derives net.sysctl.ipv6_disabled from the runtime sides of
// the two disable_ipv6 settings and every present interface's own file
// (W-86): 1 iff every one reads 1, else 0; when any read is not ok, the
// worst read's status and reason (a missing all or default keeps "IPv6 is
// not built or is disabled"). An interface whose file vanished between the
// listing and the read is gone, not a value.
func ipv6Disabled(a collect.Access, all, def facts.Envelope) facts.Envelope {
	// Every file read is the source on every branch: a failed read keeps
	// the evidence of what was read (C4).
	src := &facts.Source{Kind: "derived", Inputs: []facts.Source{
		{Kind: "proc", Path: sysctlIPv6Prefix + "conf/all/disable_ipv6"},
		{Kind: "proc", Path: sysctlIPv6Prefix + "conf/default/disable_ipv6"},
	}}
	reads := []facts.Envelope{all, def}
	ifaces, globFail := ipv6InterfaceFiles(a)
	if globFail != nil {
		reads = append(reads, *globFail)
	}
	for _, p := range ifaces {
		e := readProcSys(a, p)
		if e.Status == facts.StatusAbsent {
			continue
		}
		src.Inputs = append(src.Inputs, facts.Source{Kind: "proc", Path: p})
		reads = append(reads, e)
	}
	w := reads[0]
	for _, e := range reads[1:] {
		if ipv6DisabledRank(e.Status) > ipv6DisabledRank(w.Status) {
			w = e
		}
	}
	if w.Status != facts.StatusOK {
		return facts.Envelope{Status: w.Status, Reason: w.Reason, Source: src}
	}
	v := 1
	for _, e := range reads {
		if e.Value != 1 {
			v = 0
		}
	}
	return collect.OK(v, src)
}

// sysctlSetting builds one leaf's two-home envelope (K-3). Effective is a
// COPY of runtime rather than the same envelope, and the winner a copy of
// its source, so nothing downstream can change one side by writing to
// another (R147).
func sysctlSetting(a collect.Access, k sysctlKey, scan sysctlScan, winners sysctlWinners) facts.Setting {
	runtime := readProcSys(a, k.path)
	effective := copyEnvelope(runtime)
	persisted := sysctlPersisted(k, scan, winners)
	s := facts.Setting{Runtime: &runtime, Persisted: &persisted, Effective: &effective}
	if runtime.Source != nil {
		winner := *runtime.Source
		s.Winner = &winner
	}
	return s
}

// readProcSys is the runtime side: the integer the kernel publishes, with
// the file as a "proc" source. The three failures are distinct and none of
// them is a value — a knob this kernel does not have (Yama unbuilt,
// fs/protected_fifos before 4.19) is absent with the path, a file this run
// may not read (five of the twelve are 0600) is the read's status, and bytes
// that are not an integer are an error naming the path and what was there.
func readProcSys(a collect.Access, p string) facts.Envelope {
	data, meta, err := a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if strings.HasPrefix(p, sysctlIPv6Prefix) {
				return collect.Absent(p + " does not exist: IPv6 is not built or is disabled")
			}
			return collect.Absent(p + " does not exist")
		}
		return readErrorEnv(p, err)
	}
	v := strings.TrimSpace(string(data))
	// Base 0, the same reading the persisted side uses: one rule for the two
	// halves of a setting, so the runtime and persisted values of the same
	// knob can never be read off the same text differently. The kernel prints
	// these knobs in decimal, which base 0 reads unchanged.
	n, cerr := strconv.ParseInt(v, 0, 64)
	if cerr != nil {
		return collect.ErrorEnv(p + ": " + strconv.Quote(sourceRaw(v)) + " is not an integer")
	}
	return collect.OKRead(int(n), &facts.Source{Kind: "proc", Path: p}, meta)
}

// sysctlPersisted is the sysctl.d side of one variable.
func sysctlPersisted(k sysctlKey, scan sysctlScan, winners sysctlWinners) facts.Envelope {
	// C3: a file of the chain that exists and could not be read is the
	// answer for every value the chain could have set.
	if scan.readErr != nil {
		return *scan.readErr
	}
	w, ok := winners.lookup(k.key)
	if !ok {
		// "No line sets it" is a conclusion about bytes that were all read.
		// A file of the chain cut at the read cap may have carried that line
		// past the cut, so the absent branch marks the truncation the way the
		// OK branch below does.
		return withTruncation(collect.Absent("no sysctl.d line sets "+k.key), scan.truncated)
	}
	// The kernel's own proc_get_long takes the base from the text, so
	// "0x1f" and "0177" are the values it would apply; base 0 reads them the
	// same way and a decimal value is unaffected.
	n, err := strconv.ParseInt(w.value, 0, 64)
	if err != nil {
		return collect.ErrorEnv(w.file + ": " + strconv.Quote(sourceRaw(w.value)) + " is not an integer for " + k.key)
	}
	src := &facts.Source{Kind: "file", Path: w.file, Line: w.line, Raw: w.raw}
	return withTruncation(collect.OK(int(n), src), scan.truncated)
}

// copyEnvelope duplicates an envelope and the source it points at, so two
// sides of a setting never share storage (R147).
func copyEnvelope(e facts.Envelope) facts.Envelope {
	if e.Source != nil {
		src := *e.Source
		e.Source = &src
	}
	return e
}
