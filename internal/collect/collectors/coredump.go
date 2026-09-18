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

const (
	corePatternPath  = "/proc/sys/kernel/core_pattern"
	suidDumpablePath = "/proc/sys/fs/suid_dumpable"
	limitsConfPath   = "/etc/security/limits.conf"
	limitsDGlob      = "/etc/security/limits.d/*.conf"
)

// suidDumpableKey is the thirteenth sysctl of B-2: it lives with the
// core-dump policy rather than with the twelve self-protection knobs,
// because what it decides is whether a setuid program's dump is written at
// all.
var suidDumpableKey = sysctlKey{key: "fs.suid_dumpable", path: suidDumpablePath}

// coredumpMains are the main coredump.conf candidates in the order systemd
// itself looks for them: /etc is the administrator's copy, and systemd 254
// and later ship the vendor file under /usr/lib instead of /etc. The FIRST
// that exists is the main file; the other is not consulted.
var coredumpMains = []string{"/etc/systemd/coredump.conf", "/usr/lib/systemd/coredump.conf"}

// coredumpDropinDirs are the drop-in directories in DESCENDING precedence: a
// base name in an earlier one masks the same name in every later one.
var coredumpDropinDirs = []string{
	"/etc/systemd/coredump.conf.d",
	"/run/systemd/coredump.conf.d",
	"/usr/local/lib/systemd/coredump.conf.d",
	"/usr/lib/systemd/coredump.conf.d",
}

// coredumpCollector writes the six core-dump leaves of spec B-2. Three
// mechanisms decide whether a crash leaves a dump on disk and who may read
// it — the kernel's core_pattern and suid_dumpable, systemd-coredump's own
// configuration, and the RLIMIT_CORE that PAM applies at login — so each is
// its own leaf and the control decides which one governs this host.
var coredumpCollector = collect.Collector{
	Name:    "coredump",
	Declare: collect.Declaration{Reads: coredumpReads(), Needs: "none"},
	Run:     runCoredump,
}

func coredumpReads() []string {
	reads := []string{corePatternPath, suidDumpablePath}
	reads = append(reads, sysctlPersistedReads()...)
	reads = append(reads, coredumpMains...)
	for _, d := range coredumpDropinDirs {
		reads = append(reads, path.Join(d, "*.conf"))
	}
	return append(reads, limitsConfPath, limitsDGlob)
}

func runCoredump(_ context.Context, a collect.Access, b *collect.Builder) error {
	b.Set("coredump.core_pattern", readCorePattern(a))

	scan := sysctlFiles(a)
	b.SetSetting("coredump.suid_dumpable", sysctlSetting(a, suidDumpableKey, scan, mergeSysctl(scan.files)))

	writeCoredumpConf(a, b)
	writeCoredumpLimits(a, b)
	return nil
}

// readCorePattern is the kernel's pattern verbatim, trailing newline
// trimmed: a control matches against it — a "|" pipe means a handler takes
// the dump — so the value is the evidence and muster never paraphrases it.
func readCorePattern(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFile(corePatternPath, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.Absent(corePatternPath + " does not exist")
		}
		return readErrorEnv(corePatternPath, err)
	}
	src := &facts.Source{Kind: "proc", Path: corePatternPath}
	return collect.OKRead(strings.TrimSpace(string(data)), src, meta)
}

// coredumpScan is one pass over a merged configuration chain.
type coredumpScan struct {
	files     []confFile
	readErr   *facts.Envelope
	truncated bool
}

func (s *coredumpScan) fail(p string, err error) {
	if s.readErr == nil {
		e := readErrorEnv(p, err)
		s.readErr = &e
	}
}

// read applies one file of a chain and reports whether the path EXISTS at
// all, which is what decides the main-file candidate. chainReadFailed gives
// the classification: absent is not part of this host's chain, a symlink is
// this file's error, and any other non-regular entry sets nothing.
func (s *coredumpScan) read(a collect.Access, p string) bool {
	data, meta, err := a.ReadFile(p, readLimit)
	if err != nil {
		if chainReadFailed(err) {
			s.fail(p, err)
		}
		return !errors.Is(err, fs.ErrNotExist)
	}
	s.truncated = s.truncated || meta.Truncated
	s.files = append(s.files, confFile{path: p, data: data})
	return true
}

// coredumpConfFiles resolves the coredump.conf chain the way systemd
// resolves a drop-in chain: the main file first, then every *.conf of the
// four directories with the first directory to offer a base name owning it,
// applied in lexicographic base-name order.
func coredumpConfFiles(a collect.Access) coredumpScan {
	var s coredumpScan
	for _, main := range coredumpMains {
		if s.read(a, main) {
			break
		}
	}
	chosen := map[string]string{}
	var bases []string
	for _, d := range coredumpDropinDirs {
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
	for _, base := range bases {
		s.read(a, chosen[base])
	}
	return s
}

// writeCoredumpConf publishes systemd-coredump's two judged settings.
//
// Neither has a muster-side default. systemd-coredump's own default is
// Storage=external, and a host with no coredump.conf anywhere is `absent`
// rather than "external": the default belongs to the daemon and could change
// with it, and the control's absent_means decides what an unconfigured host
// means.
func writeCoredumpConf(a collect.Access, b *collect.Builder) {
	scan := coredumpConfFiles(a)
	if scan.readErr != nil {
		// C3: a file of the chain that exists and could not be read is the
		// answer for every value the chain could have set.
		b.Set("coredump.systemd.storage", *scan.readErr)
		b.Set("coredump.systemd.process_size_max", *scan.readErr)
		return
	}
	storage, sizeMax, seen := mergeCoredumpConf(scan.files)

	if !storage.set {
		b.Set("coredump.systemd.storage", collect.Absent(coredumpUnsetReason("Storage", seen)))
	} else {
		b.Set("coredump.systemd.storage",
			withTruncation(collect.OK(storage.value, coredumpSource(storage)), scan.truncated))
	}

	switch {
	case !sizeMax.set:
		b.Set("coredump.systemd.process_size_max", collect.Absent(coredumpUnsetReason("ProcessSizeMax", seen)))
	default:
		n, ok := parseSizeValue(sizeMax.value)
		if !ok {
			b.Set("coredump.systemd.process_size_max", collect.ErrorEnv(
				sizeMax.file+": "+strconv.Quote(sourceRaw(sizeMax.value))+" is not a size for ProcessSizeMax"))
			return
		}
		b.Set("coredump.systemd.process_size_max",
			withTruncation(collect.OK(int(n), coredumpSource(sizeMax)), scan.truncated))
	}
}

func coredumpSource(w coredumpWinner) *facts.Source {
	return &facts.Source{Kind: "file", Path: w.file, Line: w.line, Raw: w.raw}
}

// coredumpUnsetReason distinguishes the two ways a key can be unset, because
// they are different findings: a host with no coredump.conf at all, and a
// host whose files are all comments.
func coredumpUnsetReason(key string, seen []string) string {
	if len(seen) == 0 {
		return "no coredump.conf on this host, so nothing sets " + key
	}
	return "no coredump.conf line sets " + key
}

// writeCoredumpLimits publishes the RLIMIT_CORE that pam_limits applies at
// login: the last `* hard core` or `* - core` line of limits.conf and then
// of limits.d in base-name order, with `unlimited` carried as -1.
func writeCoredumpLimits(a collect.Access, b *collect.Builder) {
	var scan coredumpScan
	scan.read(a, limitsConfPath)
	matches, err := a.Glob(limitsDGlob)
	if err != nil {
		scan.fail(limitsDGlob, err)
	} else {
		slices.Sort(matches)
		for _, m := range matches {
			scan.read(a, m)
		}
	}
	if scan.readErr != nil {
		b.Set("coredump.limits.hard_core", *scan.readErr)
		b.Set("coredump.limits.sources", *scan.readErr)
		return
	}

	var winner *limitLine
	var winnerFile string
	sources := make([]any, 0, len(scan.files))
	for _, f := range scan.files {
		sources = append(sources, f.path)
		if lines := parseLimitsCore(f.data); len(lines) > 0 {
			last := lines[len(lines)-1]
			winner, winnerFile = &last, f.path
		}
	}
	b.Set("coredump.limits.sources", withTruncation(collect.OK(sources, filesSource(pathsOf(scan.files))), scan.truncated))
	if winner == nil {
		b.Set("coredump.limits.hard_core", collect.Absent("no limits.conf line sets a hard core limit for *"))
		return
	}
	src := &facts.Source{Kind: "file", Path: winnerFile, Line: winner.line, Raw: winner.raw}
	b.Set("coredump.limits.hard_core", withTruncation(collect.OK(winner.value, src), scan.truncated))
}

func pathsOf(files []confFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.path)
	}
	return out
}

// chainReadFailed reports whether a failed read of one file in a merged
// configuration chain is the chain's ANSWER rather than a file that simply
// contributes nothing.
//
// A path that is not there is not part of this host's chain. A SYMLINK is
// the chain's answer: muster reads without following links, so a fragment an
// administrator symlinked in cannot be read, and C4 makes that the honest
// `error` rather than a silent omission that would look like "sets nothing".
// Every other non-regular entry — a directory, a device, a socket named
// *.conf — sets nothing and is skipped, which is the crypto-policies lesson:
// a shape that cannot carry settings must degrade, never error.
func chainReadFailed(err error) bool {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false
	case errors.Is(err, collect.ErrSymlink):
		return true
	default:
		return !nonRegular(err)
	}
}
