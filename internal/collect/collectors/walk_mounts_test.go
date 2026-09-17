//go:build linux

package collectors

import (
	"os"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
)

// mountDouble serves one mountinfo fixture and nothing else: every other
// path the plan probes is ENOENT, which is the shape of a host with no
// container storage configured and no merged-/usr symlinks.
func mountDouble(fixture string) *fsAccess {
	return &fsAccess{files: map[string]string{"/proc/self/mountinfo": fixture}}
}

func mustPlan(t *testing.T, a *fsAccess, opts collect.WalkOptions, homes []homeRoot) mountPlan {
	t.Helper()
	p, err := planMounts(a, opts, homes)
	if err != nil {
		t.Fatalf("planMounts: %v", err)
	}
	return p
}

// enterPoints is the enter set as the traversal will read it: the mount
// points it will list, sorted, which is also what Task 5b pushes as roots.
func enterPoints(p mountPlan) []string {
	out := make([]string, 0, len(p.enter))
	for id, row := range p.enter {
		if row.id != id {
			panic("enter is keyed by something other than the mount id")
		}
		out = append(out, row.mountPoint)
	}
	slices.Sort(out)
	return out
}

// skipsOtherThan returns the skipped rows whose reason is not the given one,
// so a test about mount boundaries can ignore the fixed container-storage
// rows every plan carries.
func skipsOtherThan(p mountPlan, reason string) []skipRow {
	out := []skipRow{}
	for _, r := range p.skipped {
		if r.reason != reason {
			out = append(out, r)
		}
	}
	return out
}

func hasSkip(p mountPlan, want skipRow) bool { return slices.Contains(p.skipped, want) }

func skipsFor(p mountPlan, path string) []skipRow {
	out := []skipRow{}
	for _, r := range p.skipped {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

// parseMountinfo reads id, parent, "major:minor", root, mount point (octal
// escapes decoded) and the fstype from the field after the lone "-".
func TestParseMountinfoFields(t *testing.T) {
	data := []byte(`36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
40 36 0:35 / /mnt/my\040disk rw shared:2 master:3 - vfat /dev/sdb1 rw
41 36 0:36 /a\040b\011c /srv/x\134y rw - tmpfs tmpfs rw

nonsense
42 36 0:37 / /no/separator rw,relatime
`)
	got, err := parseMountinfo(data)
	if err != nil {
		t.Fatalf("parseMountinfo: %v", err)
	}
	want := []mountRow{
		{id: 36, parent: 35, dev: "98:0", devNum: unix.Mkdev(98, 0), root: "/mnt1", mountPoint: "/mnt2", fstype: "ext3"},
		{id: 40, parent: 36, dev: "0:35", devNum: unix.Mkdev(0, 35), root: "/", mountPoint: "/mnt/my disk", fstype: "vfat"},
		{id: 41, parent: 36, dev: "0:36", devNum: unix.Mkdev(0, 36), root: "/a b\tc", mountPoint: `/srv/x\y`, fstype: "tmpfs"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseMountinfo =\n%+v\nwant\n%+v", got, want)
	}
	if _, err := parseMountinfo([]byte("\n# nothing here\n")); err == nil {
		t.Error("a mountinfo with no parseable row must be an error, not an empty plan")
	}
}

// W-2: the enter set is the positive list of local types, and the four
// pseudo paths are excluded by path whatever their type — a mount UNDER one
// of them is decided by the path rule first.
func TestPlanEntersOnlyLocalTypes(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{}, nil)
	if !p.rootWalkable || p.rootType != "ext4" {
		t.Errorf("root: type %q walkable %v, want ext4 true", p.rootType, p.rootWalkable)
	}
	if got, want := enterPoints(p), []string{"/", "/boot", "/tmp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enter = %v, want %v", got, want)
	}
	for _, id := range []int{23, 24, 25, 26, 28, 31, 40, 41, 45, 50} {
		if !p.known[id] {
			t.Errorf("known is missing mount id %d", id)
		}
	}
	want := []skipRow{
		{path: "/dev", reason: "pseudo_path"},
		{path: "/proc", reason: "pseudo_path"},
		{path: "/run", reason: "pseudo_path"},
		{path: "/run/user/1000", reason: "pseudo_path"},
		{path: "/srv/nfs", reason: "excluded_type", detail: "nfs4"},
		{path: "/sys", reason: "pseudo_path"},
		{path: "/sys/kernel/debug", reason: "pseudo_path"},
	}
	if got := skipsOtherThan(p, "container_storage"); !reflect.DeepEqual(got, want) {
		t.Errorf("skipped (without the container-storage rows) =\n%+v\nwant\n%+v", got, want)
	}
}

// W-2: two mounts of the same device whose roots are related are aliases;
// the one entered is root "/" first, then the shortest mount point, then the
// lexicographically first.
func TestPlanRemovesBindAliasesDeterministically(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.bind-alias"), collect.WalkOptions{}, nil)
	if got, want := enterPoints(p), []string{"/", "/a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enter = %v, want %v", got, want)
	}
	for _, id := range []int{45, 51} {
		if _, ok := p.enter[id]; ok {
			t.Errorf("mount %d is an alias and must not be entered", id)
		}
	}
	for _, path := range []string{"/srv/data", "/b"} {
		if !hasSkip(p, skipRow{path: path, reason: "bind_duplicate"}) {
			t.Errorf("%s must be skipped as bind_duplicate; skipped = %+v", path, skipsOtherThan(p, "container_storage"))
		}
	}
}

// W-2: btrfs subvolumes share a device but their roots are unrelated, so
// neither is an alias of the other.
func TestPlanKeepsBtrfsSubvolumesApart(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.btrfs-subvol"), collect.WalkOptions{}, nil)
	if got, want := enterPoints(p), []string{"/", "/home"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enter = %v, want %v", got, want)
	}
	if got := skipsOtherThan(p, "container_storage"); len(got) != 0 {
		t.Errorf("no subvolume may be skipped, got %+v", got)
	}
}

// W-2: on a btrfs host the top level is often mounted as well, with subtree
// root "/" while the root filesystem is the subvolume /@. The root
// filesystem is the alias kept whatever its subtree root is: keeping
// /mnt/btrfs instead would push / and /home out as duplicates and the walk
// would answer for /mnt/btrfs/@/…, which no package join can match.
func TestPlanKeepsTheRootFilesystemOverTheBtrfsTopLevel(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.btrfs-toplevel"), collect.WalkOptions{}, nil)
	if got, want := enterPoints(p), []string{"/", "/home"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enter = %v, want %v", got, want)
	}
	if _, ok := p.enter[50]; ok {
		t.Error("the btrfs top level is an alias of the root filesystem and must not be entered")
	}
	if !hasSkip(p, skipRow{path: "/mnt/btrfs", reason: "bind_duplicate"}) {
		t.Errorf("/mnt/btrfs must be skipped as bind_duplicate; skipped = %+v", skipsOtherThan(p, "container_storage"))
	}
}

// §7: a host booted without an initramfs keeps the kernel's own rootfs row
// under the real root. The row that decides the walk is the TOP of the stack
// at "/", so such a host reads ext4 and is walked.
func TestPlanTakesTheTopOfTheRootStack(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.rootfs-stack"), collect.WalkOptions{}, nil)
	if !p.rootWalkable || p.rootType != "ext4" {
		t.Errorf("root: type %q walkable %v, want ext4 true", p.rootType, p.rootWalkable)
	}
	if got, want := enterPoints(p), []string{"/", "/boot"}; !reflect.DeepEqual(got, want) {
		t.Errorf("enter = %v, want %v", got, want)
	}
	if !hasSkip(p, skipRow{path: "/", reason: "excluded_type", detail: "rootfs"}) {
		t.Errorf("the rootfs row must still be recorded as excluded_type; skipped = %+v", skipsOtherThan(p, "container_storage"))
	}
}

// §7: a root filesystem that is not on the positive list (an overlay in a
// container) is recorded and nothing is entered — the walk answers for a
// host, not for an image layer.
func TestPlanFlagsAnUnwalkableRoot(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.overlay-root"), collect.WalkOptions{}, nil)
	if p.rootWalkable || p.rootType != "overlay" {
		t.Errorf("root: type %q walkable %v, want overlay false", p.rootType, p.rootWalkable)
	}
	if len(p.enter) != 0 {
		t.Errorf("nothing may be entered on an unwalkable root, got %+v", p.enter)
	}
	if !hasSkip(p, skipRow{path: "/", reason: "excluded_type", detail: "overlay"}) {
		t.Errorf("skipped = %+v, want the root recorded as excluded_type overlay", p.skipped)
	}
}

// W-2/L-9: the fixed container-storage set is excluded, --walk-include takes
// exactly one entry off it and --walk-exclude adds a root of its own.
func TestPlanContainerStorageAndFlags(t *testing.T) {
	fixed := collect.ContainerStorageRoots()
	p := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{}, nil)
	for _, r := range fixed {
		if !p.excludedRoots[r] {
			t.Errorf("%s must be an excluded root", r)
		}
		if !hasSkip(p, skipRow{path: r, reason: "container_storage"}) {
			t.Errorf("%s must be skipped as container_storage", r)
		}
	}

	inc := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{Include: []string{"/var/lib/docker"}}, nil)
	if inc.excludedRoots["/var/lib/docker"] {
		t.Error("--walk-include /var/lib/docker must take it off the excluded set")
	}
	if got := skipsFor(inc, "/var/lib/docker"); len(got) != 0 {
		t.Errorf("--walk-include /var/lib/docker must leave no skipped row, got %+v", got)
	}
	for _, r := range fixed {
		if r == "/var/lib/docker" {
			continue
		}
		if !inc.excludedRoots[r] {
			t.Errorf("--walk-include removed more than it names: %s is no longer excluded", r)
		}
	}

	exc := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{Exclude: []string{"/data"}}, nil)
	if !exc.excludedRoots["/data"] {
		t.Error("--walk-exclude /data must add it to the excluded set")
	}
	if !hasSkip(exc, skipRow{path: "/data", reason: "excluded_by_flag"}) {
		t.Errorf("skipped = %+v, want /data as excluded_by_flag", exc.skipped)
	}
}

// W-2: a fixed-set path that is a symlink names its target through Readlink
// (the link path is the detail); the three configuration files name the
// roots the host actually configured; a configuration file that exists and
// cannot be read is recorded and the fixed set still applies.
func TestPlanConfiguredRootsAndUnreadableConfig(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/proc/self/mountinfo":         "mountinfo.ubuntu",
			"/etc/containers/storage.conf": "storage.conf.graphroot",
			"/etc/containerd/config.toml":  "containerd.config.toml.root",
		},
		fails: map[string]error{"/etc/docker/daemon.json": os.ErrPermission},
		links: map[string]string{
			"/var/lib/docker":     "/data/docker",
			"/var/lib/containers": "../lib/containers-store",
		},
	}
	p := mustPlan(t, a, collect.WalkOptions{}, nil)
	want := []skipRow{
		{path: "/data/docker", reason: "container_storage", detail: "/var/lib/docker"},
		{path: "/var/lib/containers-store", reason: "container_storage", detail: "/var/lib/containers"},
		{path: "/data/containers/storage", reason: "container_storage", detail: "/etc/containers/storage.conf"},
		{path: "/data/rootless/storage", reason: "container_storage", detail: "/etc/containers/storage.conf"},
		{path: "/data/containerd", reason: "container_storage", detail: "/etc/containerd/config.toml"},
	}
	for _, w := range want {
		if !hasSkip(p, w) {
			t.Errorf("%+v is missing from skipped = %+v", w, p.skipped)
		}
		if !p.excludedRoots[w.path] {
			t.Errorf("%s must be an excluded root", w.path)
		}
	}
	if !p.excludedRoots["/var/lib/docker"] {
		t.Error("a symlinked fixed-set path stays excluded itself")
	}
	if got, cu := []configRead{{path: "/etc/docker/daemon.json", status: "denied"}}, p.configUnreadable; !reflect.DeepEqual(cu, got) {
		t.Errorf("configUnreadable = %+v, want %+v", cu, got)
	}
	if hasSkip(p, skipRow{path: "/data/docker-root", reason: "container_storage", detail: "/etc/docker/daemon.json"}) {
		t.Error("a daemon.json that could not be read must not contribute a root")
	}

	a.files["/etc/docker/daemon.json"] = "daemon.json.data-root"
	delete(a.fails, "/etc/docker/daemon.json")
	readable := mustPlan(t, a, collect.WalkOptions{}, nil)
	if !hasSkip(readable, skipRow{path: "/data/docker-root", reason: "container_storage", detail: "/etc/docker/daemon.json"}) {
		t.Errorf("skipped = %+v, want daemon.json's data-root", readable.skipped)
	}
	if len(readable.configUnreadable) != 0 {
		t.Errorf("configUnreadable = %+v, want none", readable.configUnreadable)
	}
}

// W-2: every home the walk knows about contributes its two rootless storage
// roots; the two prefix rows, which name no account, contribute none.
func TestPlanPerHomeRootlessRoots(t *testing.T) {
	homes := []homeRoot{
		{path: "/root", user: "", kind: "user"},
		{path: "/home", user: "", kind: "user"},
		{path: "/home/alice", user: "alice", kind: "user"},
		{path: "/var/lib/postgresql", user: "postgres", kind: "service"},
	}
	p := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{}, homes)
	for _, h := range []string{"/home/alice", "/var/lib/postgresql"} {
		for _, sub := range []string{"/.local/share/containers", "/.local/share/docker"} {
			if !p.excludedRoots[h+sub] {
				t.Errorf("%s must be an excluded root", h+sub)
			}
			if !hasSkip(p, skipRow{path: h + sub, reason: "container_storage"}) {
				t.Errorf("%s must be skipped as container_storage", h+sub)
			}
		}
	}
	for _, h := range []string{"/root", "/home"} {
		if p.excludedRoots[h+"/.local/share/containers"] {
			t.Errorf("the %s prefix row names no account and must contribute no rootless root", h)
		}
	}
	if !reflect.DeepEqual(p.homes, homes) {
		t.Errorf("the plan must carry the home set it was given, got %+v", p.homes)
	}
}

// W-7: the join canonicalises a package's file list through the merged-/usr
// symlinks, so the plan records which of the six aliases point into /usr.
func TestPlanRecordsUsrMerged(t *testing.T) {
	a := mountDouble("mountinfo.ubuntu")
	a.links = map[string]string{
		"/bin":   "usr/bin",
		"/sbin":  "usr/sbin",
		"/lib":   "/usr/lib",
		"/lib32": "/opt/lib32",
	}
	p := mustPlan(t, a, collect.WalkOptions{}, nil)
	want := map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin", "/lib": "/usr/lib"}
	if !reflect.DeepEqual(p.usrMerged, want) {
		t.Errorf("usrMerged = %+v, want %+v (a link outside /usr is not a merged-/usr alias)", p.usrMerged, want)
	}
}

// A-16/A-23: /root and /home are the two user-home prefixes, and every
// account whose pw_dir survives the exclusion list is a row of its own —
// user kind under /root or /home, service kind anywhere else — because an
// account row is what names the rootless container stores under that home.
func TestClassifyHomes(t *testing.T) {
	data, err := os.ReadFile("testdata/passwd.homes")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rows, _ := parsePasswd(data)
	want := []homeRoot{
		{path: "/root", user: "", kind: "user"},
		{path: "/home", user: "", kind: "user"},
		{path: "/home/alice", user: "alice", kind: "user"},
		{path: "/nonexistent", user: "_apt", kind: "service"},
		{path: "/nonexistent", user: "messagebus", kind: "service"},
		{path: "/nonexistent", user: "tcpdump", kind: "service"},
		{path: "/root", user: "root", kind: "user"},
		{path: "/var/lib/postgresql", user: "postgres", kind: "service"},
		{path: "/var/www", user: "www-data", kind: "service"},
	}
	if got := classifyHomes(rows); !reflect.DeepEqual(got, want) {
		t.Errorf("classifyHomes =\n%+v\nwant\n%+v", got, want)
	}
	// An unreadable /etc/passwd reaches this with no rows at all: the two
	// prefix rows alone, so the rule degrades toward recording a service
	// home's dotfiles, never toward hiding them.
	if got, want := classifyHomes(nil), want[:2]; !reflect.DeepEqual(got, want) {
		t.Errorf("classifyHomes(nil) = %+v, want %+v", got, want)
	}
}

// A-16: a user home exempts its dotfiles at any depth; a service home
// exempts its direct children only.
func TestHomeRules(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/root/.bashrc", true},
		{"/root/.config/x/.y", true},
		{"/root", false},
		{"/home/alice/.config/x/.y", true},
		{"/home/alice/.bashrc", true},
		{"/home/.snapshots", false},
		{"/home/alice", false},
		{"/home", false},
		{"/var/www/html/.cache", false},
		{"/rootkit/.x", false},
	} {
		if got := underUserHome(tc.path); got != tc.want {
			t.Errorf("underUserHome(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}

	homes := []homeRoot{
		{path: "/root", kind: "user"},
		{path: "/home", kind: "user"},
		{path: "/var/lib/postgresql", user: "postgres", kind: "service"},
		{path: "/var/www", user: "www-data", kind: "service"},
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/var/lib/postgresql/.psql_history", true},
		{"/var/www/.bashrc", true},
		{"/var/www/html/.cache", false},
		{"/var/lib/postgresql/data/.x", false},
		{"/root/.bashrc", false}, // a user home, exempt by underUserHome instead
	} {
		if got := directChildOfServiceHome(tc.path, homes); got != tc.want {
			t.Errorf("directChildOfServiceHome(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// A-23, end to end: the home set a real /etc/passwd produces must reach the
// excluded roots, so a rootless store under a USER home — /root and
// /home/alice are where podman and rootless docker actually put one — is
// excluded exactly as a service home's is. This is the composition
// classifyHomes and planMounts are used in by the collector; testing the
// two apart would let a home set that names no account pass both.
func TestPlanRootlessRootsFromPasswd(t *testing.T) {
	data, err := os.ReadFile("testdata/passwd.homes")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rows, _ := parsePasswd(data)
	p := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{}, classifyHomes(rows))
	for _, home := range []string{"/root", "/home/alice", "/var/www", "/var/lib/postgresql", "/nonexistent"} {
		for _, sub := range []string{"/.local/share/containers", "/.local/share/docker"} {
			if !p.excludedRoots[home+sub] {
				t.Errorf("%s must be an excluded root", home+sub)
			}
			if !hasSkip(p, skipRow{path: home + sub, reason: "container_storage"}) {
				t.Errorf("%s must be skipped as container_storage", home+sub)
			}
		}
	}
	// nobody:/ and daemon:/usr/sbin are not homes, so neither contributes a
	// store: excluding /.local/share/containers or /usr/sbin/.local/... would
	// be an exclusion nobody asked for.
	for _, notAHome := range []string{"/", "/usr/sbin"} {
		if p.excludedRoots[notAHome+"/.local/share/containers"] {
			t.Errorf("%s is not a home and must contribute no store", notAHome)
		}
	}
}

// C4: a configuration file this collector did not declare is absent — the
// path muster declined to read — never an error about the host.
func TestPlanUndeclaredConfigIsAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/proc/self/mountinfo":    "mountinfo.ubuntu",
		"/etc/docker/daemon.json": "daemon.json.data-root",
	}}
	g := collect.Guard(a, collect.Collector{
		Name:    "walk",
		Declare: collect.Declaration{Reads: []string{mountinfoPath, containersStoragePath, containerdConfigPath}, Walk: true},
	})
	p, err := planMounts(g, collect.WalkOptions{}, nil)
	if err != nil {
		t.Fatalf("planMounts: %v", err)
	}
	// The other two files are declared and simply are not there, so the one
	// row is the one file the guard refused.
	want := []configRead{{path: dockerDaemonPath, status: "absent"}}
	if !reflect.DeepEqual(p.configUnreadable, want) {
		t.Errorf("configUnreadable = %+v, want %+v", p.configUnreadable, want)
	}
	if hasSkip(p, skipRow{path: "/data/docker-root", reason: "container_storage", detail: dockerDaemonPath}) {
		t.Error("a file the guard refused must not contribute a root")
	}
}

// A-14: an empty configUnreadable is an empty list, not a nil that would
// serialise as null in walk.stats.
func TestPlanEmptyConfigUnreadableIsNotNil(t *testing.T) {
	p := mustPlan(t, mountDouble("mountinfo.ubuntu"), collect.WalkOptions{}, nil)
	if p.configUnreadable == nil {
		t.Error("configUnreadable must be an empty list, not nil")
	}
}
