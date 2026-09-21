//go:build linux

package collectors

import (
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// Every fixture this suite reads is SYNTHETIC. modules.dep, modules.builtin
// and /proc/modules are generated files with no comment syntax, so they carry
// no provenance line of their own: they were written by hand for these tests,
// with invented module paths and all-zero load addresses, and no host was read
// to make any of them.

// testRelease is what the kernel-osrelease fixture says, and therefore the
// directory the module tree lives in for every case below.
const testRelease = "6.8.0-31-generic"

var (
	usrTree = usrModulesDir + "/" + testRelease
	libTree = libModulesDir + "/" + testRelease
)

func moduleFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return data
}

// moduleTreeFiles is the host every case starts from: the kernel release, the
// loaded-module table and a module tree with both indexes under root.
func moduleTreeFiles(root string) map[string]string {
	return map[string]string{
		kernelReleasePath:                   "kernel-osrelease",
		procModulesPath:                     "proc_modules.sample",
		path.Join(root, modulesDepName):     "modules.dep.sample",
		path.Join(root, modulesBuiltinName): "modules.builtin.sample",
	}
}

// moduleDouble serves those files plus whatever modprobe.d the case adds.
// /usr/lib/modules exists as a directory unless a case drops it, because that
// is the fork K-14 turns on.
func moduleDouble(files map[string]string) *fsAccess {
	return &fsAccess{files: files, dirs: map[string]bool{usrModulesDir: true}}
}

func withConf(files map[string]string, conf map[string]string) map[string]string {
	for p, f := range conf {
		files[p] = f
	}
	return files
}

func moduleRow(t *testing.T, list []any, name string) map[string]any {
	t.Helper()
	for _, v := range list {
		r, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("kernel.modules carries %#v, not a record", v)
		}
		if r["name"] == name {
			return r
		}
	}
	t.Fatalf("kernel.modules has no row for %s", name)
	return nil
}

// rowFlag reads one boolean field of a row, failing rather than panicking
// when the collector wrote something else there.
func rowFlag(t *testing.T, row map[string]any, field string) bool {
	t.Helper()
	v, ok := row[field].(bool)
	if !ok {
		t.Fatalf("row %v: %s is %#v, not a bool", row["name"], field, row[field])
	}
	return v
}

func rowSources(t *testing.T, row map[string]any) []string {
	t.Helper()
	list, ok := row["sources"].([]any)
	if !ok {
		t.Fatalf("row %v: sources is %#v, not a list", row["name"], row["sources"])
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("row %v: sources carries %#v, not a string", row["name"], v)
		}
		out = append(out, s)
	}
	return out
}

// B-4: the module tree's two indexes are the only things that say whether a
// module could be loaded at all, and both name modules by a compressed object
// path. The name a row is keyed by is the base name with the compression
// suffix stripped and "-" folded to "_", which is how modprobe itself treats
// usb-storage and usb_storage as one module.
func TestParseModulesBuiltinAndDep(t *testing.T) {
	dep := parseModulesDep(moduleFixture(t, "modules.dep.sample"))
	wantDep := []string{"cramfs", "freevxfs", "hfsplus", "udf", "usb_storage", "dccp", "sctp", "rds", "tipc", "squashfs"}
	if !slices.Equal(dep, wantDep) {
		t.Errorf("parseModulesDep =\n%v\nwant\n%v", dep, wantDep)
	}

	// modules.builtin is a bare list of object paths: "kernel/fs/jffs2/jffs2.ko"
	// is the module jffs2, and the .ko.zst and .ko.xz a compressing
	// distribution writes are the same name.
	builtin := parseModulesBuiltin(moduleFixture(t, "modules.builtin.sample"))
	wantBuiltin := []string{"jffs2", "ext4", "crypto_engine"}
	if !slices.Equal(builtin, wantBuiltin) {
		t.Errorf("parseModulesBuiltin =\n%v\nwant\n%v", builtin, wantBuiltin)
	}

	if foldModuleName("usb-storage") != foldModuleName("usb_storage") {
		t.Errorf("usb-storage folds to %q and usb_storage to %q, want one name",
			foldModuleName("usb-storage"), foldModuleName("usb_storage"))
	}

	// /proc/modules is the loaded set: the first field of each row is the
	// module, already in the folded spelling the kernel uses.
	loaded := parseProcModules(moduleFixture(t, "proc_modules.sample"))
	if want := []string{"sctp", "libcrc32c"}; !slices.Equal(loaded, want) {
		t.Errorf("parseProcModules = %v, want %v", loaded, want)
	}
}

// modprobe.d(5)'s grammar, as much of it as a row depends on: the directive,
// the module it names, and for install the command that decides whether the
// module is disabled or merely hooked.
func TestParseModprobeD(t *testing.T) {
	got := parseModprobeD(moduleFixture(t, "modprobe.d-blacklist.conf"))
	want := []modprobeDirective{
		{kind: "blacklist", module: "tipc"},
		{kind: "install", module: "udf", command: "/bin/false"},
		{kind: "install", module: "sctp", command: "/bin/false"},
		{kind: "install", module: "rds", command: "/sbin/modprobe --ignore-install rds"},
		{kind: "options", module: "usb_storage"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseModprobeD =\n%+v\nwant\n%+v", got, want)
	}

	// B-7: "install <name> /bin/false" (or /bin/true) is what disables a
	// module. The idiom that hooks a module without disabling it runs
	// modprobe itself, and reading that as "disabled" would pass a host on
	// which the module loads exactly as before.
	for _, c := range []struct {
		command string
		want    bool
	}{
		{"/bin/false", true},
		{"/bin/true", true},
		{"/sbin/modprobe --ignore-install usb-storage", false},
		{"", false},
	} {
		if got := installDisables(c.command); got != c.want {
			t.Errorf("installDisables(%q) = %v, want %v", c.command, got, c.want)
		}
	}

	// kmod's two rules: a trailing backslash joins the next physical line,
	// and a "#" comments a line out only when it is the FIRST character.
	// A "#" further along is an ordinary argument and stays inside an install
	// command - cutting there could turn a command muster does not recognise
	// into /bin/false, which is the one direction that turns a live module
	// into a PASS.
	cont := parseModprobeD(moduleFixture(t, "modprobe.d-continuation.conf"))
	wantCont := []modprobeDirective{
		{kind: "install", module: "dccp", command: "/bin/true"},
		{kind: "blacklist", module: "hfsplus"},
		{kind: "install", module: "squashfs", command: "/bin/false # kmod keeps this inside the command"},
	}
	if !slices.Equal(cont, wantCont) {
		t.Errorf("parseModprobeD(continuation) =\n%+v\nwant\n%+v", cont, wantCont)
	}

	// The directory chain: /etc owns a base name the vendor directory also
	// carries, and a file that is not *.conf is not part of the chain at all -
	// both would flip cramfs to disabled if they were read.
	a := moduleDouble(withConf(moduleTreeFiles(usrTree), map[string]string{
		"/etc/modprobe.d/blacklist.conf":     "modprobe.d-blacklist.conf",
		"/etc/modprobe.d/notes.txt":          "modprobe.d-notes.txt",
		"/usr/lib/modprobe.d/blacklist.conf": "modprobe.d-vendor.conf",
	}))
	rows := okList(t, build(t, "modules", a), modulesKey)
	cramfs := moduleRow(t, rows, "cramfs")
	if rowFlag(t, cramfs, "install_disabled") || rowFlag(t, cramfs, "disabled") {
		t.Errorf("cramfs = %v, want neither install_disabled nor disabled: the vendor file is masked and notes.txt is not a .conf", cramfs)
	}
	if usb := moduleRow(t, rows, "usb-storage"); rowFlag(t, usb, "blacklisted") {
		t.Errorf("usb-storage = %v, want blacklisted false: the vendor file that blacklists it is masked by /etc", usb)
	}
	if slices.Contains(a.reads, "/etc/modprobe.d/notes.txt") {
		t.Error("read /etc/modprobe.d/notes.txt: only *.conf is part of the chain")
	}
	if slices.Contains(a.reads, "/usr/lib/modprobe.d/blacklist.conf") {
		t.Error("read the vendor blacklist.conf: /etc owns that base name")
	}
}

// K-5 and B-4: the eleven candidates are always rows, in the spec's order,
// and `disabled` is the formula over what the tree, /proc/modules and
// modprobe.d said - never a paraphrase of one of them.
func TestModuleRowsAndDisabled(t *testing.T) {
	a := moduleDouble(withConf(moduleTreeFiles(usrTree), map[string]string{
		"/etc/modprobe.d/50-continuation.conf": "modprobe.d-continuation.conf",
		"/etc/modprobe.d/blacklist.conf":       "modprobe.d-blacklist.conf",
	}))
	b := build(t, "modules", a)
	rows := okList(t, b, modulesKey)

	var names []string
	for _, v := range rows {
		names = append(names, v.(map[string]any)["name"].(string))
	}
	if !slices.Equal(names, moduleCandidates) {
		t.Fatalf("rows = %v\nwant the eleven candidates in order %v", names, moduleCandidates)
	}

	// K-5: a row carries the spec's eight fields and nothing else, on every
	// row - a field a control could read must not depend on which module it
	// landed on.
	wantFields := []string{"available", "blacklisted", "builtin", "disabled", "install_disabled", "loaded", "name", "sources"}
	for _, v := range rows {
		got := slices.Sorted(maps.Keys(v.(map[string]any)))
		if !slices.Equal(got, wantFields) {
			t.Errorf("row %v has fields %v, want %v", v.(map[string]any)["name"], got, wantFields)
		}
	}

	const etcBlacklist = "/etc/modprobe.d/blacklist.conf"
	const etcContinuation = "/etc/modprobe.d/50-continuation.conf"
	for _, c := range []struct {
		name                                                string
		loaded, builtin, available, blacklisted, installDis bool
		disabled                                            bool
		sources                                             []string
	}{
		// In the tree, nothing said about it: it can load, and it is not disabled.
		{name: "cramfs", available: true},
		{name: "freevxfs", available: true},
		// Built in: never in /proc/modules, never in modules.dep, and no
		// modprobe.d line can disable it - which is why the formula has a
		// !builtin term and the row says where that came from.
		{name: "jffs2", builtin: true, sources: []string{builtinSentinel}},
		// Not in the tree at all: disabled by absence.
		{name: "hfs", disabled: true},
		// Blacklisted alone stops automatic loading by alias; modprobe by name
		// still loads it, so it is recorded and not credited.
		{name: "hfsplus", available: true, blacklisted: true, sources: []string{etcContinuation}},
		{name: "udf", available: true, installDis: true, disabled: true, sources: []string{etcBlacklist}},
		// Mentioned by an options line only: evidence, no field of its own.
		{name: "usb-storage", available: true, sources: []string{etcBlacklist}},
		{name: "dccp", available: true, installDis: true, disabled: true, sources: []string{etcContinuation}},
		// Loaded right now: whatever modprobe.d says, this kernel has it.
		{name: "sctp", loaded: true, available: true, installDis: true, sources: []string{etcBlacklist}},
		// The install line runs modprobe itself, so the module still loads.
		{name: "rds", available: true, sources: []string{etcBlacklist}},
		{name: "tipc", available: true, blacklisted: true, sources: []string{etcBlacklist}},
	} {
		row := moduleRow(t, rows, c.name)
		for _, f := range []struct {
			field string
			want  bool
		}{
			{"loaded", c.loaded},
			{"builtin", c.builtin},
			{"available", c.available},
			{"blacklisted", c.blacklisted},
			{"install_disabled", c.installDis},
			{"disabled", c.disabled},
		} {
			if got := rowFlag(t, row, f.field); got != f.want {
				t.Errorf("%s.%s = %v, want %v (row %v)", c.name, f.field, got, f.want, row)
			}
		}
		want := c.sources
		if want == nil {
			want = []string{}
		}
		if got := rowSources(t, row); !slices.Equal(got, want) {
			t.Errorf("%s.sources = %v, want %v", c.name, got, want)
		}
	}

	// The envelope cites what it was derived from, so a reader can see which
	// files the eleven rows were decided by.
	e := env(t, b, modulesKey)
	if e.Source == nil || e.Source.Kind != "derived" {
		t.Fatalf("kernel.modules source = %+v, want a derived source", e.Source)
	}
	var cited []string
	for _, in := range e.Source.Inputs {
		cited = append(cited, in.Path)
	}
	for _, p := range []string{procModulesPath, path.Join(usrTree, modulesDepName), etcBlacklist} {
		if !slices.Contains(cited, p) {
			t.Errorf("kernel.modules cites %v, which does not name %s", cited, p)
		}
	}
}

// B-2 and K-14: without a module tree there is nothing to judge, and the
// fallback to /lib exists only for a host that is not merged-/usr. A chain
// this run may not read is that read's status, never a list of rows that
// would read as "nothing is configured".
func TestModulesTreeMissingIsUnsupported(t *testing.T) {
	// A container: /usr/lib/modules is there, the running kernel's tree is not.
	none := moduleDouble(map[string]string{
		kernelReleasePath: "kernel-osrelease",
		procModulesPath:   "proc_modules.sample",
	})
	e := env(t, build(t, "modules", none), modulesKey)
	if e.Status != facts.StatusUnsupported {
		t.Errorf("kernel.modules with no tree = %+v, want unsupported", e)
	}
	if !strings.Contains(e.Reason, usrTree) {
		t.Errorf("reason %q does not name %s", e.Reason, usrTree)
	}
	if e.Value != nil {
		t.Errorf("kernel.modules with no tree carries %#v, want no rows", e.Value)
	}

	// K-14: on a merged-/usr host /lib is a symlink, and a no-follow read of
	// it would be an error. So /usr/lib/modules existing is the whole test,
	// and /lib/modules is never consulted.
	usr := moduleDouble(moduleTreeFiles(usrTree))
	build(t, "modules", usr)
	for _, p := range usr.reads {
		if strings.HasPrefix(p, libModulesDir+"/") {
			t.Errorf("read %s although %s exists", p, usrModulesDir)
		}
	}

	// K-27: a merged-/usr host with no /usr/lib/modules at all — every
	// minimal container, which is where spec §5 promises unsupported and
	// where the capability matrix's container row asserts it. What decides it
	// is /lib itself: it is the symlink merged-/usr makes it, so /lib/modules
	// IS the /usr/lib/modules just found missing and the answer is that same
	// absence. Reporting an error here would put kernel.modules outside the
	// statuses B-10 allows in a container.
	merged := &fsAccess{files: map[string]string{
		kernelReleasePath: "kernel-osrelease",
		procModulesPath:   "proc_modules.sample",
	}}
	merged.links = map[string]string{libDir: "usr/lib"}
	e = env(t, build(t, "modules", merged), modulesKey)
	if e.Status != facts.StatusUnsupported {
		t.Errorf("kernel.modules on a merged-/usr host with no module tree = %+v, want unsupported", e)
	}
	if !strings.Contains(e.Reason, usrTree) || !strings.Contains(e.Reason, libDir) {
		t.Errorf("reason %q must name both %s and %s", e.Reason, usrTree, libDir)
	}
	if e.Value != nil {
		t.Errorf("kernel.modules on a merged-/usr host carries %#v, want no rows", e.Value)
	}
	if slices.Contains(merged.reads, path.Join(libTree, modulesDepName)) {
		t.Errorf("%s is a symlink, so %s must not be read at all: %v", libDir, libTree, merged.reads)
	}

	// K-27, the other shape, and the reason the rule is asked of /lib rather
	// than inferred from the error the modules.dep read returns: on a host
	// whose /lib is a REAL directory, a symlink at or above modules.dep is an
	// administrator's doing and a finding about that host (C4). It must keep
	// the read's own status; calling it "merged-/usr" would be a false
	// statement AND would hide the finding behind unsupported.
	linked := &fsAccess{files: map[string]string{
		kernelReleasePath: "kernel-osrelease",
		procModulesPath:   "proc_modules.sample",
	}}
	linked.dirs = map[string]bool{libDir: true}
	linked.fails = map[string]error{path.Join(libTree, modulesDepName): collect.ErrSymlink}
	e = env(t, build(t, "modules", linked), modulesKey)
	if e.Status != facts.StatusError {
		t.Errorf("kernel.modules with a symlinked %s under a real %s = %+v, want error",
			path.Join(libTree, modulesDepName), libDir, e)
	}
	if !strings.Contains(e.Reason, path.Join(libTree, modulesDepName)) {
		t.Errorf("reason %q does not name the file that could not be read", e.Reason)
	}

	// A host that is not merged-/usr: no /usr/lib/modules directory at all,
	// /lib a real directory (K-27: that is what licenses the fallback), and
	// the tree where it always was.
	lib := &fsAccess{files: moduleTreeFiles(libTree), dirs: map[string]bool{libDir: true}}
	rows := okList(t, build(t, "modules", lib), modulesKey)
	if len(rows) != len(moduleCandidates) {
		t.Errorf("rows from %s = %d, want %d", libTree, len(rows), len(moduleCandidates))
	}

	// C3: a modprobe.d directory this run may not search is the answer for
	// every row the chain could have decided.
	denied := moduleDouble(moduleTreeFiles(usrTree))
	denied.deniedDirs = map[string]bool{"/etc/modprobe.d": true}
	e = env(t, build(t, "modules", denied), modulesKey)
	if e.Status != facts.StatusDenied {
		t.Errorf("kernel.modules with a denied modprobe.d = %+v, want denied", e)
	}
	if !strings.Contains(e.Reason, "/etc/modprobe.d") {
		t.Errorf("reason %q does not name the directory", e.Reason)
	}

	// C3 again, on each of the three files the fact cannot be had without:
	// the tree's index, the loaded-module table, and the module directory
	// itself. A stat of /usr/lib/modules refused is NOT evidence that this
	// host keeps its modules under /lib - it is evidence of nothing, and
	// forking on it would publish an answer nobody could see.
	for _, c := range []struct {
		what string
		path string
	}{
		{"modules.dep", path.Join(usrTree, modulesDepName)},
		{"/proc/modules", procModulesPath},
		{"the module directory", usrModulesDir},
	} {
		a := moduleDouble(moduleTreeFiles(usrTree))
		a.fails = map[string]error{c.path: unix.EACCES}
		e = env(t, build(t, "modules", a), modulesKey)
		if e.Status != facts.StatusDenied {
			t.Errorf("kernel.modules with %s denied = %+v, want denied", c.what, e)
		}
		if !strings.Contains(e.Reason, c.path) {
			t.Errorf("reason %q does not name %s", e.Reason, c.path)
		}
		if strings.HasPrefix(c.path, usrModulesDir) && slices.Contains(a.reads, path.Join(libTree, modulesDepName)) {
			t.Errorf("%s denied and the collector read %s anyway", c.what, libTree)
		}
	}

	// The kernel release names the tree, so its read carries its own status
	// too: gone is the read's status, and a file that is there but says
	// nothing is a host this collector cannot answer for.
	files := moduleTreeFiles(usrTree)
	delete(files, kernelReleasePath)
	e = env(t, build(t, "modules", moduleDouble(files)), modulesKey)
	if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, kernelReleasePath) {
		t.Errorf("kernel.modules with no %s = %+v, want absent naming it", kernelReleasePath, e)
	}

	empty := moduleTreeFiles(usrTree)
	empty[kernelReleasePath] = "kernel-osrelease.empty"
	e = env(t, build(t, "modules", moduleDouble(empty)), modulesKey)
	if e.Status != facts.StatusUnsupported || !strings.Contains(e.Reason, kernelReleasePath) {
		t.Errorf("kernel.modules with an empty %s = %+v, want unsupported naming it", kernelReleasePath, e)
	}
}

// Ruling K-21: a symlink to /dev/null in a .d directory is the documented way
// to mask a vendor file. It contributes nothing, it still masks the same base
// name in the directories below it, and it is not an error. Any OTHER symlink
// is that file's error (C4), because muster reads without following one and a
// fragment it cannot read must not look like "sets nothing".
func TestModprobeDNullMaskAndSymlink(t *testing.T) {
	masked := moduleDouble(withConf(moduleTreeFiles(usrTree), map[string]string{
		"/usr/lib/modprobe.d/zz-masked.conf": "modprobe.d-masked.conf",
	}))
	// The link is listed by Glob like any other entry, its read answers
	// ErrSymlink the way the no-follow primitive answers one, and Readlink
	// says where it points.
	masked.files["/etc/modprobe.d/zz-masked.conf"] = "modprobe.d-masked.conf"
	masked.fails = map[string]error{"/etc/modprobe.d/zz-masked.conf": collect.ErrSymlink}
	masked.links = map[string]string{"/etc/modprobe.d/zz-masked.conf": devNull}

	b := build(t, "modules", masked)
	row := moduleRow(t, okList(t, b, modulesKey), "freevxfs")
	if rowFlag(t, row, "install_disabled") || rowFlag(t, row, "disabled") {
		t.Errorf("freevxfs = %v, want neither: the vendor file that disables it is masked", row)
	}
	if slices.Contains(masked.reads, "/usr/lib/modprobe.d/zz-masked.conf") {
		t.Error("read the vendor file the /dev/null link masks")
	}

	other := moduleDouble(moduleTreeFiles(usrTree))
	other.files["/etc/modprobe.d/local.conf"] = "modprobe.d-blacklist.conf"
	other.fails = map[string]error{"/etc/modprobe.d/local.conf": collect.ErrSymlink}
	other.links = map[string]string{"/etc/modprobe.d/local.conf": "/opt/hardening/modprobe.conf"}
	e := env(t, build(t, "modules", other), modulesKey)
	if e.Status != facts.StatusError {
		t.Errorf("kernel.modules with a symlinked fragment = %+v, want error", e)
	}
	if !strings.Contains(e.Reason, "/etc/modprobe.d/local.conf") {
		t.Errorf("reason %q does not name the link", e.Reason)
	}
}

// K-4: the collector declares every path it reads, runs nothing, and writes
// exactly the one key of B-2.
func TestModulesDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "modules")
	if c.Declare.Needs != "none" {
		t.Errorf("Needs %q, want none", c.Declare.Needs)
	}
	if len(c.Declare.Commands) != 0 {
		t.Errorf("declares %d commands, want none: modprobe is never run", len(c.Declare.Commands))
	}
	if c.Declare.Walk {
		t.Error("declares the walk licence: modprobe.d is globbed, never listed as a tree")
	}

	want := []string{
		"/etc/modprobe.d/*.conf",
		// K-27: /lib itself, because whether the /lib/modules fallback is a
		// real directory or the merged-/usr alias is a question about /lib.
		"/lib",
		"/lib/modprobe.d/*.conf",
		"/lib/modules/*/modules.builtin",
		"/lib/modules/*/modules.dep",
		"/proc/modules",
		"/proc/sys/kernel/osrelease",
		"/run/modprobe.d/*.conf",
		"/usr/lib/modprobe.d/*.conf",
		"/usr/lib/modules",
		"/usr/lib/modules/*/modules.builtin",
		"/usr/lib/modules/*/modules.dep",
		"/usr/local/lib/modprobe.d/*.conf",
	}
	got := slices.Clone(c.Declare.Reads)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Reads =\n%v\nwant\n%v", got, want)
	}

	b := buildBegun(t, "modules", moduleDouble(moduleTreeFiles(usrTree)))
	if keys := b.Keys("modules"); !slices.Equal(keys, []string{modulesKey}) {
		t.Errorf("wrote %v, want just %s", keys, modulesKey)
	}
}

// bigModulesDep renders a modules.dep of at least size bytes whose LAST line
// is the candidate the assertion is about, so a read that stopped early loses
// exactly that line. The filler names are invented and no host was read for
// them (the fixture note at the top of this file applies).
func bigModulesDep(size int, last string) []byte {
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "kernel/drivers/filler/filler%06d.ko:\n", i)
	}
	fmt.Fprintf(&b, "kernel/fs/%s/%s.ko:\n", last, last)
	return []byte(b.String())
}

// The two module INDEXES are read under a cap of their own, the way the mount
// table is: modules.dep lists every module of the tree and passes the general
// 1 MiB readLimit on an ordinary distribution kernel. A cut index is silently
// a SHORTER module list — "this host does not have hfs" — which is a wrong
// finding rather than an honest truncation, so the cap has to clear a real
// tree.
func TestModulesIndexesAreReadUnderTheirOwnCap(t *testing.T) {
	const candidate = "hfs"
	files := moduleTreeFiles(usrTree)
	delete(files, path.Join(usrTree, modulesDepName))
	a := moduleDouble(files)
	a.contents = map[string][]byte{
		path.Join(usrTree, modulesDepName): bigModulesDep(2<<20, candidate),
	}

	b := build(t, "modules", a)
	e := env(t, b, modulesKey)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s = %+v, want ok", modulesKey, e)
	}
	if e.Truncated {
		t.Errorf("%s is truncated at 2 MiB; the index cap is %d bytes", modulesKey, modulesDepReadLimit)
	}
	row := moduleRow(t, okList(t, b, modulesKey), candidate)
	if !rowFlag(t, row, "available") {
		t.Errorf("%s = %v, want available: its line is past 1 MiB and the whole index must be read", candidate, row)
	}

	// Past the index cap the read is cut and SAYS so — the envelope carries
	// truncated, which is what stops a control reading the short list as the
	// whole answer.
	over := moduleDouble(files)
	over.contents = map[string][]byte{
		path.Join(usrTree, modulesDepName): bigModulesDep(modulesDepReadLimit+(1<<16), candidate),
	}
	if e := env(t, build(t, "modules", over), modulesKey); !e.Truncated {
		t.Errorf("%s = %+v, want truncated: the index is larger than the cap", modulesKey, e)
	}
}

// B-7: `install <name> <a command that does nothing>` is the "never load
// this" idiom whichever way an administrator spelled the command. /bin and
// /usr/bin are one directory on a merged-/usr host and two elsewhere, and
// modprobe runs the command through /bin/sh, which finds a bare word on PATH.
func TestInstallDisablesEverySpellingOfANoop(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"/bin/false", true},
		{"/bin/true", true},
		{"/usr/bin/false", true},
		{"/usr/bin/true", true},
		{"false", true},
		{"true", true},
		{"/bin/false # never", true},
		{"  /usr/bin/true  ", true},
		{"/sbin/modprobe --ignore-install cramfs", false},
		{"/bin/falsely", false},
		{"/opt/false", false},
		{"logger false", false},
		{"", false},
	} {
		if got := installDisables(tc.command); got != tc.want {
			t.Errorf("installDisables(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

// The spellings have to survive the whole collector, not just the predicate:
// a module whose install line says `/usr/bin/false` is disabled in the row a
// control reads.
func TestModulesInstallNoopThroughTheCollector(t *testing.T) {
	files := withConf(moduleTreeFiles(usrTree), nil)
	a := moduleDouble(files)
	a.contents = map[string][]byte{
		"/etc/modprobe.d/99-noops.conf": []byte("install cramfs /usr/bin/false\ninstall freevxfs true\n"),
	}
	rows := okList(t, build(t, "modules", a), modulesKey)
	for _, name := range []string{"cramfs", "freevxfs"} {
		row := moduleRow(t, rows, name)
		if !rowFlag(t, row, "install_disabled") || !rowFlag(t, row, "disabled") {
			t.Errorf("%s = %v, want install_disabled and disabled", name, row)
		}
	}
}
