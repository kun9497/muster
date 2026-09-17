//go:build linux

package collectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// mountinfoPath is the one file the plan cannot do without: it names every
// mount, its device, its subtree root and its type, which is what decides a
// boundary. mountinfoReadLimit is generous because a container host carries
// thousands of rows — the cap only bounds a hostile or fake Access.
const (
	mountinfoPath      = "/proc/self/mountinfo"
	mountinfoReadLimit = 4 << 20
)

// localTypes is W-2's positive list: the filesystem types the walk enters.
// Anything else — a network filesystem, a fuse mount, an overlay, a kernel
// pseudo-filesystem, or a type this list has never heard of — is not
// entered, so an unknown type errs on the side of not touching it. tmpfs is
// on the list on purpose: /tmp and /var/tmp are where U-25 and the sticky
// half of U-23 live.
var localTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"f2fs": true, "jfs": true, "reiserfs": true, "zfs": true, "tmpfs": true,
	"ramfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
	"iso9660": true, "udf": true, "erofs": true,
}

// pseudoPaths are excluded by path whatever their type, and so is every
// mount under them: /proc and /sys are the kernel talking, /dev is
// devtmpfs and its submounts, /run is the boot's scratch space. A mount
// under one of them is decided by this rule first — a tmpfs at
// /run/user/1000 is on the positive list and still not walked.
var pseudoPaths = []string{"/proc", "/sys", "/dev", "/run"}

// usrAliases are the six top-level directories a merged-/usr distribution
// ships as symlinks into /usr. The package join (W-7) canonicalises a
// package's file list through the ones that really are links, which is why
// the plan records them: it is already stat'ing and readlink'ing fixed
// paths, and the join has no Access of its own to ask.
var usrAliases = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// The three configuration files that can move a container store off its
// conventional path, in the order walk.stats.config_unreadable lists them.
const (
	dockerDaemonPath      = "/etc/docker/daemon.json"
	containersStoragePath = "/etc/containers/storage.conf"
	containerdConfigPath  = "/etc/containerd/config.toml"
)

// The two ways a mountinfo that WAS read can still be unusable. They are
// sentinels rather than inline errors so the collector can tell them from a
// read failure (A-24): a file muster read and could not plan a walk from is
// an error naming the file, never "could not be read", which would be false.
var (
	errNoMountRow  = errors.New("no mount is listed")
	errNoRootMount = errors.New("no mount is the root filesystem")
)

var (
	// storageRootRE matches podman's two store paths in storage.conf. The
	// file is TOML, but muster has no TOML decoder and needs two scalars:
	// a line-anchored key = "value" is the shape every stock file has, and
	// a value that is not an absolute clean path is discarded anyway.
	storageRootRE = regexp.MustCompile(`^\s*(?:graphroot|rootless_storage_path)\s*=\s*"([^"]*)"`)
	// containerdRootRE matches containerd's top-level root. Only the
	// occurrence before the first [section] header counts — plugins have a
	// root of their own that is not the store.
	containerdRootRE = regexp.MustCompile(`^\s*root\s*=\s*"([^"]*)"`)
)

// mountRow is one line of mountinfo, reduced to what the plan judges.
//
// dev is mountinfo's "major:minor" text, the grouping key for bind aliases;
// devNum is the same pair as the st_dev the kernel reports, which is the
// boundary test on a kernel without STATX_MNT_ID (PF-7). root is the
// subtree of the device that is mounted — "/" for an ordinary mount, a
// subdirectory for a bind mount, a subvolume for btrfs — and it is what
// tells a bind alias from a second subvolume.
type mountRow struct {
	id, parent int
	dev        string
	devNum     uint64
	root       string
	mountPoint string
	fstype     string
}

// skipRow is one row of walk.skipped (A-15): a root the walk did not enter
// and why. reason is the closed vocabulary; detail is "" except the fstype
// for excluded_type, the symlink's own path for a container root reached
// through readlink, the configuration file for a configured root, and the
// errno text for a vanished row the traversal adds later.
type skipRow struct{ path, reason, detail string }

// skipRowValue renders one skipped root as the record walk.skipped carries.
// The plan writes its rows before the first directory is opened and the
// traversal adds more as it goes; both go through here, so one vocabulary
// can never be published in two shapes.
func skipRowValue(s skipRow) map[string]any {
	return map[string]any{"path": s.path, "reason": s.reason, "detail": s.detail}
}

// configRead is one row of walk.stats.config_unreadable: a container
// configuration file that exists and could not be read, with the read's
// status word. Such a file is not a root — the walk cannot know where it
// points — so the fixed set still applies and the control descriptions say
// that a configured root the walk could not learn may surface as findings.
type configRead struct{ path, status string }

// mountPlan is everything the traversal needs to know before it opens the
// first directory: which mounts it enters, which paths it must not enter,
// which roots were skipped and why, and the home set the hidden rule uses.
type mountPlan struct {
	enter            map[int]mountRow
	known            map[int]bool
	excludedRoots    map[string]bool
	skipped          []skipRow
	homes            []homeRoot
	configUnreadable []configRead
	usrMerged        map[string]string
	rootType         string
	rootWalkable     bool
}

// exclude records one root the traversal must not enter. The first reason
// for a path wins: a path that is both a container store and a --walk-exclude
// value is one row, not two, and walk.skipped stays one row per root.
func (p *mountPlan) exclude(root, reason, detail string) {
	if root == "" || p.excludedRoots[root] {
		return
	}
	p.excludedRoots[root] = true
	p.skipped = append(p.skipped, skipRow{path: root, reason: reason, detail: detail})
}

// parseMountinfo reads the fields the plan judges out of /proc/self/mountinfo.
// A line is "id parent major:minor root mount_point options [optional...] -
// fstype source superopts": the optional fields are variable in number, so
// the separator is a field that is exactly "-" (neither a path nor a
// comma-joined option list can be), and the fstype is the field after it.
// Fields 4 and 5 carry octal escapes for space, tab, newline and backslash.
//
// A line that does not parse is dropped rather than failing the file: one
// mangled row must not cost the walk every boundary it knows. A file with
// no parseable row at all is an error — every mount namespace has at least
// its own root, so that is not a host muster can plan a walk for.
func parseMountinfo(data []byte) ([]mountRow, error) {
	var rows []mountRow
	for _, line := range splitLines(data) {
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		if sep < 6 || len(f) < sep+2 {
			continue
		}
		id, err := strconv.Atoi(f[0])
		parent, perr := strconv.Atoi(f[1])
		major, minor, ok := splitDev(f[2])
		if err != nil || perr != nil || !ok {
			continue
		}
		rows = append(rows, mountRow{
			id:         id,
			parent:     parent,
			dev:        f[2],
			devNum:     unix.Mkdev(major, minor),
			root:       unescapeMountField(f[3]),
			mountPoint: unescapeMountField(f[4]),
			fstype:     f[sep+1],
		})
	}
	if len(rows) == 0 {
		return nil, errNoMountRow
	}
	return rows, nil
}

func splitDev(s string) (major, minor uint32, ok bool) {
	maj, min, found := strings.Cut(s, ":")
	if !found {
		return 0, 0, false
	}
	a, err := strconv.ParseUint(maj, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	b, err := strconv.ParseUint(min, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint32(a), uint32(b), true
}

// unescapeMountField decodes the \OOO octal escapes mountinfo uses for the
// four characters that would otherwise break its field splitting: space
// (\040), tab (\011), newline (\012) and backslash (\134). A backslash that
// does not begin a three-digit octal escape is kept as itself.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// planMounts decides, before the first directory is opened, which mounts
// the walk enters and which roots it must not (W-2). The error is the
// mountinfo read's — the caller turns it into walk.complete and writes no
// list — or a mountinfo that carried no usable row: without the mount table
// there is no boundary rule, and a walk with no boundaries is the one thing
// the design refuses.
func planMounts(a collect.Access, opts collect.WalkOptions, homes []homeRoot) (mountPlan, error) {
	data, _, err := a.ReadFile(mountinfoPath, mountinfoReadLimit)
	if err != nil {
		return mountPlan{}, err
	}
	rows, err := parseMountinfo(data)
	if err != nil {
		return mountPlan{}, fmt.Errorf("%s: %w", mountinfoPath, err)
	}
	slices.SortStableFunc(rows, func(x, y mountRow) int { return x.id - y.id })

	p := mountPlan{
		enter:            map[int]mountRow{},
		known:            map[int]bool{},
		excludedRoots:    map[string]bool{},
		skipped:          []skipRow{},
		homes:            homes,
		configUnreadable: []configRead{},
		usrMerged:        map[string]string{},
	}
	// The root is the TOP of the stack at "/", not the first row: a host
	// booted without an initramfs keeps the kernel's own `rootfs / rootfs`
	// row underneath the real filesystem, and taking the first would answer
	// "unsupported" for every file on an ordinary ext4 host.
	root, haveRoot := mountRow{}, false
	for _, r := range rows {
		p.known[r.id] = true
		if r.mountPoint == "/" && (!haveRoot || r.id > root.id) {
			root, haveRoot = r, true
		}
	}
	if !haveRoot {
		return mountPlan{}, fmt.Errorf("%s: %w", mountinfoPath, errNoRootMount)
	}
	p.rootType, p.rootWalkable = root.fstype, localTypes[root.fstype]
	if !p.rootWalkable {
		// A container's overlay root, a squashfs appliance, a type the list
		// has never heard of: nothing is entered, and the one row says which
		// type it was. Nothing else is probed — no root was excluded,
		// because none was going to be walked.
		p.skipped = append(p.skipped, skipRow{path: "/", reason: "excluded_type", detail: p.rootType})
		return p, nil
	}

	var candidates []mountRow
	for _, r := range rows {
		switch {
		case underPseudoPath(r.mountPoint):
			p.skipped = append(p.skipped, skipRow{path: r.mountPoint, reason: "pseudo_path"})
		case !localTypes[r.fstype]:
			p.skipped = append(p.skipped, skipRow{path: r.mountPoint, reason: "excluded_type", detail: r.fstype})
		default:
			candidates = append(candidates, r)
		}
	}
	p.resolveAliases(candidates)
	p.excludeRoots(a, opts, homes)
	p.readUsrMerged(a)

	slices.SortStableFunc(p.skipped, func(x, y skipRow) int {
		if c := strings.Compare(x.path, y.path); c != 0 {
			return c
		}
		return strings.Compare(x.reason, y.reason)
	})
	return p, nil
}

// resolveAliases fills the enter set, dropping bind aliases. Two mounts are
// aliases when they share a device and one's subtree root equals or lies
// under the other's: the same files reached by two paths, and walking both
// would report every finding twice. The one kept is the mount AT "/", then
// the mount whose subtree root is "/", then the shortest mount point, then
// the lexicographically first — a total order, so the same mountinfo always
// keeps the same mount.
//
// The root filesystem is ranked first because it is the one mount the walk
// cannot do without. On a btrfs host whose "/" is the subvolume /@ while the
// top level is mounted as well (/mnt/btrfs, subtree root "/"), ranking root
// "/" first would keep /mnt/btrfs and push both / and /home out as bind
// duplicates: the walk would answer for /mnt/btrfs/@/etc/…, no package
// join would match and the home exemption would never fire.
//
// A row is compared against every mount kept so far, not only the first:
// btrfs subvolumes share a device with unrelated roots (/@ and /@home), and
// a third mount must be judged against whichever of them it belongs to.
func (p *mountPlan) resolveAliases(candidates []mountRow) {
	groups := map[string][]mountRow{}
	for _, r := range candidates {
		groups[r.dev] = append(groups[r.dev], r)
	}
	devs := make([]string, 0, len(groups))
	for dev := range groups {
		devs = append(devs, dev)
	}
	slices.Sort(devs)
	for _, dev := range devs {
		group := groups[dev]
		slices.SortStableFunc(group, func(x, y mountRow) int {
			if (x.mountPoint == "/") != (y.mountPoint == "/") {
				if x.mountPoint == "/" {
					return -1
				}
				return 1
			}
			if (x.root == "/") != (y.root == "/") {
				if x.root == "/" {
					return -1
				}
				return 1
			}
			if c := len(x.mountPoint) - len(y.mountPoint); c != 0 {
				return c
			}
			return strings.Compare(x.mountPoint, y.mountPoint)
		})
		var kept []mountRow
		for _, r := range group {
			if slices.ContainsFunc(kept, func(k mountRow) bool { return pathRelated(k.root, r.root) }) {
				p.skipped = append(p.skipped, skipRow{path: r.mountPoint, reason: "bind_duplicate"})
				continue
			}
			kept = append(kept, r)
			p.enter[r.id] = r
		}
	}
}

// excludeRoots collects every path the traversal must not enter that is not
// decided by the enter set: the fixed container-storage set less
// --walk-include, the targets of fixed-set paths that are themselves
// symlinks, the roots the host configured, the per-home rootless stores,
// and --walk-exclude last, so a flag value that is already a container root
// keeps the reason that explains it best.
func (p *mountPlan) excludeRoots(a collect.Access, opts collect.WalkOptions, homes []homeRoot) {
	include := make(map[string]bool, len(opts.Include))
	for _, v := range opts.Include {
		include[v] = true
	}
	for _, r := range collect.ContainerStorageRoots() {
		if include[r] {
			continue
		}
		p.exclude(r, "container_storage", "")
		// /var/lib/docker -> /data/docker is as common as data-root. The
		// walk never follows the link; it reads it, and the target joins
		// the set with the link as the detail. A path that is not a
		// symlink, or not there at all, adds nothing.
		if target, ok := linkTarget(a, r); ok {
			p.exclude(target, "container_storage", r)
		}
	}
	for _, c := range p.configuredRoots(a) {
		p.exclude(c.path, "container_storage", c.detail)
	}
	for _, h := range homes {
		if h.user == "" {
			continue // a prefix row names no account and so no store
		}
		p.exclude(h.path+"/.local/share/containers", "container_storage", "")
		p.exclude(h.path+"/.local/share/docker", "container_storage", "")
	}
	for _, e := range opts.Exclude {
		p.exclude(e, "excluded_by_flag", "")
	}
}

// configuredRoot is one store path a configuration file named, with the
// file as its detail.
type configuredRoot struct{ path, detail string }

// configuredRoots reads the three container configuration files in the
// order config_unreadable lists them. A file that is not there says
// nothing; a file that exists and cannot be read is recorded and still says
// nothing — the walk cannot invent where it points, and the fixed set is
// what remains.
func (p *mountPlan) configuredRoots(a collect.Access) []configuredRoot {
	var out []configuredRoot
	if data, ok := p.readConfig(a, dockerDaemonPath); ok {
		var cfg struct {
			DataRoot string `json:"data-root"`
		}
		// A daemon.json that is not JSON names no root. It is readable, so
		// it is not a config_unreadable row: the operator's own tooling
		// reports a broken daemon.json far louder than muster would.
		if json.Unmarshal(data, &cfg) == nil {
			if v, ok := storeRoot(cfg.DataRoot); ok {
				out = append(out, configuredRoot{path: v, detail: dockerDaemonPath})
			}
		}
	}
	if data, ok := p.readConfig(a, containersStoragePath); ok {
		for _, line := range splitLines(data) {
			if m := storageRootRE.FindStringSubmatch(line); m != nil {
				if v, ok := storeRoot(m[1]); ok {
					out = append(out, configuredRoot{path: v, detail: containersStoragePath})
				}
			}
		}
	}
	if data, ok := p.readConfig(a, containerdConfigPath); ok {
		for _, line := range splitLines(data) {
			if strings.HasPrefix(strings.TrimSpace(line), "[") {
				break // a plugin's root is not the store's
			}
			if m := containerdRootRE.FindStringSubmatch(line); m != nil {
				if v, ok := storeRoot(m[1]); ok {
					out = append(out, configuredRoot{path: v, detail: containerdConfigPath})
				}
				break
			}
		}
	}
	return out
}

// readConfig reads one container configuration file. A missing file is
// silence; anything else that failed is a config_unreadable row carrying
// the read's own status word.
func (p *mountPlan) readConfig(a collect.Access, file string) ([]byte, bool) {
	data, meta, err := a.ReadFile(file, readLimit)
	if err == nil {
		return data, true
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
		return nil, false
	}
	status := string(collect.FromReadError(err, meta).Status)
	if errors.Is(err, collect.ErrUndeclared) {
		// C4: a path muster declined to read is absent, never error. The
		// guard refuses a file this collector did not declare, and that is
		// a fact about muster, not about the host.
		status = string(facts.StatusAbsent)
	}
	p.configUnreadable = append(p.configUnreadable, configRead{path: file, status: status})
	return nil, false
}

// readUsrMerged records which of the six top-level aliases are symlinks
// into /usr, so the package join can canonicalise a file list that still
// says /bin/su on a merged-/usr host.
func (p *mountPlan) readUsrMerged(a collect.Access) {
	for _, alias := range usrAliases {
		target, ok := linkTarget(a, alias)
		if ok && underOrEqual(target, "/usr") {
			p.usrMerged[alias] = target
		}
	}
}

// linkTarget reports where a symlink at p points, as an absolute clean
// path. The stat is what identifies a symlink — the read primitives never
// follow one, so ErrSymlink is the answer for a link and nothing else is —
// and a relative target is resolved against the link's own directory,
// textually, without asking the kernel to resolve anything.
func linkTarget(a collect.Access, p string) (string, bool) {
	if _, err := a.Stat(p); !errors.Is(err, collect.ErrSymlink) {
		return "", false
	}
	target, err := a.Readlink(p)
	if err != nil || target == "" {
		return "", false
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(path.Dir(p), target)
	}
	return storeRoot(path.Clean(target))
}

// storeRoot accepts a configured or linked path only when it is absolute
// and already clean: a relative value, or one with a .. left in it, names
// something other than what it says once the traversal compares it by
// prefix. "/" is refused too — excluding it would turn the walk into an
// expensive no-op without saying so, the same trap --walk-exclude / is
// refused for.
func storeRoot(v string) (string, bool) {
	if !strings.HasPrefix(v, "/") || v == "/" || path.Clean(v) != v {
		return "", false
	}
	return v, true
}

func underPseudoPath(p string) bool { return underOrEqualAny(p, pseudoPaths) }

func underOrEqualAny(p string, roots []string) bool {
	return slices.ContainsFunc(roots, func(root string) bool { return underOrEqual(p, root) })
}

// underOrEqual is the prefix test every boundary in the walk uses: p is
// root itself or lies below it, compared by whole components so /home never
// matches /homework.
func underOrEqual(p, root string) bool {
	if p == root {
		return true
	}
	if root == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, root+"/")
}

// pathRelated reports whether two mount roots name overlapping subtrees,
// which is what makes two mounts of one device aliases rather than two
// independent subvolumes.
func pathRelated(a, b string) bool { return underOrEqual(a, b) || underOrEqual(b, a) }
