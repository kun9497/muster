//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// sysctlCollector writes the twelve kernel self-protection sysctls of spec
// B-2 as two-home settings.
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
	reads := make([]string, 0, len(sysctlLeaves)+len(sysctlDirs)+1)
	for _, l := range sysctlLeaves {
		reads = append(reads, l.path)
	}
	return append(reads, sysctlPersistedReads()...)
}

func runSysctl(_ context.Context, a collect.Access, b *collect.Builder) error {
	scan := sysctlFiles(a)
	winners := mergeSysctl(scan.files)
	for _, l := range sysctlLeaves {
		b.SetSetting(l.leaf, sysctlSetting(a, l.sysctlKey, scan, winners))
	}
	return nil
}

// sysctlSetting builds one leaf's two-home envelope (K-3). Effective is a
// COPY of runtime rather than the same envelope, and the winner a copy of
// its source, so nothing downstream can change one side by writing to
// another (R147).
func sysctlSetting(a collect.Access, k sysctlKey, scan sysctlScan, winners map[string]sysctlWinner) facts.Setting {
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
func sysctlPersisted(k sysctlKey, scan sysctlScan, winners map[string]sysctlWinner) facts.Envelope {
	// C3: a file of the chain that exists and could not be read is the
	// answer for every value the chain could have set.
	if scan.readErr != nil {
		return *scan.readErr
	}
	w, ok := winners[k.key]
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
