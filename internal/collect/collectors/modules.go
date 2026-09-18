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
	modulesKey = "kernel.modules"

	// kernelReleasePath is the running kernel's release, which is the name of
	// its module directory. os.go reads the same file for the run header;
	// `uname -r` is the same string and muster runs no command for it.
	kernelReleasePath = "/proc/sys/kernel/osrelease"
	procModulesPath   = "/proc/modules"

	// usrModulesDir is where the module tree lives (K-14). Every supported
	// distribution is merged-/usr, so /lib is a symlink there and a no-follow
	// read under it would be an error rather than an answer; libModulesDir is
	// consulted only on a host that has no /usr/lib/modules at all.
	usrModulesDir = "/usr/lib/modules"
	libModulesDir = "/lib/modules"

	modulesDepName     = "modules.dep"
	modulesBuiltinName = "modules.builtin"

	// builtinSentinel is the one entry of a row's sources that is not a file:
	// a built-in module is not configured anywhere, and the row has to say
	// where its verdict came from (B-4).
	builtinSentinel = "built into the kernel"

	installFalse = "/bin/false"
	installTrue  = "/bin/true"
)

// moduleCandidates are the eleven modules of spec B-2, in the spec's order.
// K-5: every one of them is a row on every host whose tree could be read,
// present or not, so an `each` clause never selects nothing and a waiver can
// name the row it excuses.
var moduleCandidates = []string{
	"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf",
	"usb-storage", "dccp", "sctp", "rds", "tipc",
}

// modprobeDirs are modprobe.d(5)'s directories in DESCENDING precedence: a
// base name in an earlier one masks the same name in every later one, and
// kmod applies the survivors in BASE-NAME order whichever directory each came
// from — /usr/lib/aa.conf is applied before /etc/zz.conf.
//
// /usr/lib and /lib are both listed because they are one directory on a
// merged-/usr host and two on anything else: /usr/lib comes first, so on a
// merged host every base name /lib offers is already owned and is never read
// through the symlink, and on a host where /lib/modprobe.d is real its files
// are the last word, which is where kmod puts them.
var modprobeDirs = []string{
	"/etc/modprobe.d",
	"/run/modprobe.d",
	"/usr/local/lib/modprobe.d",
	"/usr/lib/modprobe.d",
	"/lib/modprobe.d",
}

// modulesCollector answers one question per candidate module — could this
// host load it, and did an administrator stop it — from files alone (B-4).
// Nothing here runs modprobe: `modprobe --showconfig` would answer with the
// same files, and a collector that shelled out would report the tool's
// opinion where muster wants the host's own state.
var modulesCollector = collect.Collector{
	Name:    "modules",
	Declare: collect.Declaration{Reads: modulesReads(), Needs: "none"},
	Run:     runModules,
}

func modulesReads() []string {
	reads := []string{kernelReleasePath, procModulesPath, usrModulesDir}
	for _, root := range []string{usrModulesDir, libModulesDir} {
		reads = append(reads,
			path.Join(root, "*", modulesDepName),
			path.Join(root, "*", modulesBuiltinName))
	}
	for _, d := range modprobeDirs {
		reads = append(reads, path.Join(d, "*.conf"))
	}
	return reads
}

func runModules(_ context.Context, a collect.Access, b *collect.Builder) error {
	b.Set(modulesKey, moduleList(a))
	return nil
}

// moduleList builds the whole fact. It is one envelope rather than eleven
// leaves, so every failure below is the answer for ALL eleven rows: a run
// that could not read the tree or the modprobe.d chain must not publish a
// list that reads as "nothing is configured" (C3).
func moduleList(a collect.Access) facts.Envelope {
	// os.go reads the same file for the run header, where a failure can only
	// be dropped; here it decides which directory the tree is in, so the
	// read's own status is the answer for the whole fact (C3).
	data, _, err := a.ReadFile(kernelReleasePath, osReadLimit)
	if err != nil {
		return readErrorEnv(kernelReleasePath, err)
	}
	release := strings.TrimSpace(string(data))
	switch {
	case release == "":
		return collect.Unsupported(kernelReleasePath + " is empty, so the module tree cannot be named")
	case strings.Contains(release, "/"):
		return collect.ErrorEnv(kernelReleasePath + ": " + strconv.Quote(sourceRaw(release)) + " is not a kernel release")
	}

	// K-14: /lib/modules is consulted only where /usr/lib/modules is not
	// there. On a merged-/usr host /lib is a symlink, and reading through it
	// would be an error on every such host.
	root := usrModulesDir
	if _, err := a.Stat(usrModulesDir); err != nil {
		// Only "it is not there" is evidence that this host keeps its modules
		// somewhere else. A stat refused for any other reason says nothing
		// about the layout, and falling through to /lib would answer a
		// question nobody could see the answer to (C3).
		if !errors.Is(err, fs.ErrNotExist) {
			return readErrorEnv(usrModulesDir, err)
		}
		root = libModulesDir
	}
	tree := path.Join(root, release)

	inputs := []facts.Source{{Kind: "proc", Path: procModulesPath}}
	procData, meta, err := a.ReadFile(procModulesPath, readLimit)
	if err != nil {
		return readErrorEnv(procModulesPath, err)
	}
	truncated := meta.Truncated

	// The dependency index is what says a module exists at all, so its
	// absence is the absence of the tree: a container, or a kernel whose
	// modules were removed, has nothing here to judge (B-2, B-10).
	depPath := path.Join(tree, modulesDepName)
	depData, meta, err := a.ReadFile(depPath, readLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return collect.Unsupported(tree + " has no " + modulesDepName + ": this host carries no module tree for its running kernel")
	case err != nil:
		return readErrorEnv(depPath, err)
	}
	truncated = truncated || meta.Truncated
	inputs = append(inputs, facts.Source{Kind: "file", Path: depPath})

	// A tree without modules.builtin is a tree all the same — the index is
	// generated per build and an old one may not have it — and then nothing
	// is built in as far as this host can say.
	builtinPath := path.Join(tree, modulesBuiltinName)
	builtinData, meta, err := a.ReadFile(builtinPath, readLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		builtinData = nil
	case err != nil:
		return readErrorEnv(builtinPath, err)
	default:
		truncated = truncated || meta.Truncated
		inputs = append(inputs, facts.Source{Kind: "file", Path: builtinPath})
	}

	scan := modprobeFiles(a)
	if scan.readErr != nil {
		return *scan.readErr
	}
	truncated = truncated || scan.truncated
	for _, f := range scan.files {
		inputs = append(inputs, facts.Source{Kind: "file", Path: f.path})
	}

	states := moduleStates(procData, depData, builtinData, scan.files)
	rows := make([]map[string]any, 0, len(moduleCandidates))
	for _, name := range moduleCandidates {
		rows = append(rows, states[foldModuleName(name)].row(name))
	}
	src := &facts.Source{Kind: "derived", Inputs: inputs}
	return withTruncation(collect.OK(rowsValue(rows), src), truncated)
}

// modprobeFiles resolves the modprobe.d chain the way kmod resolves it: every
// *.conf of the four directories, the first directory to offer a base name
// owning it, the survivors applied in base-name order.
func modprobeFiles(a collect.Access) chainScan {
	var s chainScan
	for _, p := range dropinPaths(a, modprobeDirs, &s) {
		s.read(a, p)
	}
	return s
}

// moduleState is what the four sources said about one candidate.
type moduleState struct {
	loaded, builtin, available, blacklisted, installDisabled bool

	// installSeen records that an install directive for this module has
	// already been applied: kmod keeps the FIRST command it reads for a
	// module and ignores every later one. "First" is in the chain's read
	// order, which is base-name order across the directories — NOT directory
	// order — so /usr/lib/aa.conf's install line beats /etc/zz.conf's, and
	// masking is what gives /etc the last word on a base name it shares.
	installSeen bool

	sources []string
}

// row renders one record (K-5). The field names are spec B-2's exactly, and
// `disabled` is B-4's formula rather than any single source's opinion: a
// loaded module is not disabled whatever modprobe.d says, a built-in one
// cannot be disabled at all, and a module the tree does not ship is disabled
// by absence.
func (st *moduleState) row(name string) map[string]any {
	sources := st.sources
	if st.builtin {
		sources = append(slices.Clone(sources), builtinSentinel)
	}
	return map[string]any{
		"name":             name,
		"loaded":           st.loaded,
		"builtin":          st.builtin,
		"available":        st.available,
		"blacklisted":      st.blacklisted,
		"install_disabled": st.installDisabled,
		"disabled":         !st.loaded && !st.builtin && (st.installDisabled || !st.available),
		"sources":          listValue(sources),
	}
}

// moduleStates folds the four sources into one state per candidate. Only the
// eleven are tracked: the point of the fact is the eleven rows, and a map of
// every module on the host would be a copy of its module tree.
func moduleStates(procData, depData, builtinData []byte, files []confFile) map[string]*moduleState {
	states := make(map[string]*moduleState, len(moduleCandidates))
	for _, name := range moduleCandidates {
		states[foldModuleName(name)] = &moduleState{}
	}
	for _, name := range parseProcModules(procData) {
		if st := states[name]; st != nil {
			st.loaded = true
		}
	}
	for _, name := range parseModulesDep(depData) {
		if st := states[name]; st != nil {
			st.available = true
		}
	}
	for _, name := range parseModulesBuiltin(builtinData) {
		if st := states[name]; st != nil {
			st.builtin = true
		}
	}

	for _, f := range files {
		mentioned := map[string]bool{}
		for _, d := range parseModprobeD(f.data) {
			st := states[d.module]
			if st == nil {
				continue
			}
			mentioned[d.module] = true
			switch d.kind {
			case "blacklist":
				// B-7: blacklist only stops loading by alias, so it is
				// recorded and never credited as "disabled".
				st.blacklisted = true
			case "install":
				if !st.installSeen {
					st.installSeen, st.installDisabled = true, installDisables(d.command)
				}
			}
		}
		// Candidate order, never the mention map's: a fact is the same bytes
		// on every run of the same host (D20).
		for _, name := range moduleCandidates {
			folded := foldModuleName(name)
			if mentioned[folded] {
				states[folded].sources = append(states[folded].sources, f.path)
			}
		}
	}
	return states
}
