//go:build linux

package collectors

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// linkPair is one /sys/block or /dev/mapper entry the double serves. Every
// entry of both directories is a SYMLINK, relative, pointing either into the
// virtual tree or at a disk on a bus; ruling K-15 is what the collector reads,
// and a double that served anything else would prove nothing about a host.
type linkPair struct{ path, target string }

func sysLink(dev string) linkPair {
	return linkPair{"/sys/block/" + dev, "../devices/virtual/block/" + dev}
}

func diskLink(dev string) linkPair {
	return linkPair{"/sys/block/" + dev,
		"../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/" + dev}
}

func linkMap(pairs ...linkPair) map[string]string {
	m := map[string]string{}
	for _, p := range pairs {
		m[p.path] = p.target
	}
	return m
}

// swapDouble builds the Access one swap layout is read through. Every sysfs
// entry is spelled the way the kernel spells it: /sys/block is links only,
// the device's own attributes are files under /sys/devices/virtual/block, and
// a slaves/ entry is listed by name and never followed.
type swapLayout struct {
	swaps  string            // the /proc/swaps fixture
	mounts string            // the mountinfo fixture, "" when no swap FILE needs one
	links  map[string]string // host path -> stored link target
	files  map[string]string // host path -> testdata fixture
	dirs   []string          // listable entries, e.g. one slaves/<name>
	fails  map[string]error
}

func swapDouble(l swapLayout) *fsAccess {
	files := map[string]string{procSwapsPath: l.swaps}
	if l.mounts != "" {
		files[mountinfoPath] = l.mounts
	}
	for p, f := range l.files {
		files[p] = f
	}
	dirs := map[string]bool{}
	for _, d := range l.dirs {
		dirs[d] = true
	}
	return &fsAccess{files: files, links: l.links, dirs: dirs, fails: l.fails}
}

func swapRow(t *testing.T, list []any, path string) map[string]any {
	t.Helper()
	for _, v := range list {
		r, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("swap.devices carries %#v, not a record", v)
		}
		if r["path"] == path {
			return r
		}
	}
	t.Fatalf("swap.devices has no row for %s", path)
	return nil
}

// /proc/swaps is a header and then one row per device: the file name, whether
// it is a file on a filesystem or a device of its own, and three numbers this
// collector does not judge. A host with the header alone has no swap, and
// then there is nothing to decide encryption about — absent, never false,
// which is what lets control 16 read NOT_APPLICABLE.
func TestParseProcSwaps(t *testing.T) {
	none := build(t, "swap", swapDouble(swapLayout{swaps: "proc_swaps.none"}))
	if e := env(t, none, "swap.present"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("swap.present with no row = %+v, want ok false", e)
	}
	if list := okList(t, none, "swap.devices"); len(list) != 0 {
		t.Errorf("swap.devices with no row = %v, want an empty list", list)
	}
	if e := env(t, none, "swap.encrypted"); e.Status != facts.StatusAbsent {
		t.Errorf("swap.encrypted with no swap = %+v, want absent", e)
	} else if !strings.Contains(e.Reason, procSwapsPath) {
		t.Errorf("swap.encrypted reason %q does not name %s", e.Reason, procSwapsPath)
	}

	// A swap FILE keeps the kind the kernel printed, which is what sends the
	// resolver through the mount table rather than straight at a device node.
	file := build(t, "swap", swapDouble(swapLayout{
		swaps:  "proc_swaps.sample",
		mounts: "mountinfo.overlay-root",
	}))
	if e := env(t, file, "swap.present"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("swap.present with a row = %+v, want ok true", e)
	}
	list := okList(t, file, "swap.devices")
	if len(list) != 1 {
		t.Fatalf("swap.devices = %v, want one row", list)
	}
	if r := swapRow(t, list, "/swap.img"); r["type"] != swapTypeFile {
		t.Errorf("/swap.img row = %v, want type file", r)
	}

	// A device row keeps "partition", the kernel's other word.
	part := build(t, "swap", swapDouble(swapLayout{
		swaps: "proc_swaps.partitions",
		links: linkMap(sysLink("dm-1"), diskLink("sda")),
		files: map[string]string{"/sys/devices/virtual/block/dm-1/dm/uuid": "dm.uuid.crypt"},
	}))
	plist := okList(t, part, "swap.devices")
	if len(plist) != 2 {
		t.Fatalf("swap.devices = %v, want two rows", plist)
	}
	if r := swapRow(t, plist, "/dev/dm-1"); r["type"] != "partition" {
		t.Errorf("/dev/dm-1 row = %v, want type partition", r)
	}
}

// K-15: the decision is made by reading the /sys/block links and walking the
// dm slaves below them, never by resolving a path through the kernel and
// never by running a command.
func TestSwapEncryptedThroughSlaves(t *testing.T) {
	// The stock "encrypted LVM" layout: swap is a logical volume, whose one
	// slave is the dm-crypt device the installer put the volume group on.
	t.Run("lvm on luks", func(t *testing.T) {
		b := build(t, "swap", swapDouble(swapLayout{
			swaps: "proc_swaps.partitions",
			links: linkMap(sysLink("dm-1"), sysLink("dm-0"), diskLink("sda")),
			files: map[string]string{
				"/sys/devices/virtual/block/dm-1/dm/uuid": "dm.uuid.lvm",
				"/sys/devices/virtual/block/dm-0/dm/uuid": "dm.uuid.crypt",
			},
			dirs: []string{"/sys/devices/virtual/block/dm-1/slaves/dm-0"},
		}))
		r := swapRow(t, okList(t, b, "swap.devices"), "/dev/dm-1")
		if r["encrypted"] != true || r["backing"] != "dm-0" {
			t.Errorf("/dev/dm-1 row = %v, want encrypted true backing dm-0", r)
		}
		// The second device of that fixture is a bare partition, so the host
		// leaf is false even though the first device is encrypted.
		if e := env(t, b, "swap.encrypted"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("swap.encrypted = %+v, want ok false: one device of two is bare", e)
		}
	})

	// A partition has no /sys/block entry of its own — sysfs lists it under
	// its disk — so the disk is what says the name is a real device, and the
	// partition is terminal: nothing below it can encrypt it.
	t.Run("bare partition", func(t *testing.T) {
		b := build(t, "swap", swapDouble(swapLayout{
			swaps: "proc_swaps.partitions",
			links: linkMap(sysLink("dm-1"), diskLink("sda")),
			files: map[string]string{"/sys/devices/virtual/block/dm-1/dm/uuid": "dm.uuid.crypt"},
		}))
		r := swapRow(t, okList(t, b, "swap.devices"), "/dev/sda2")
		if r["encrypted"] != false || r["backing"] != "sda2" {
			t.Errorf("/dev/sda2 row = %v, want encrypted false backing sda2", r)
		}
	})

	// A swap FILE is traced through the mount that contains it: the mount's
	// source is a /dev/mapper name, which is a link to the dm node, and the
	// walk goes on from there. The lab's own layout — LVM, no LUKS.
	t.Run("swap file on an lvm root", func(t *testing.T) {
		b := build(t, "swap", swapDouble(swapLayout{
			swaps:  "proc_swaps.sample",
			mounts: "mountinfo.ubuntu-stock",
			links:  linkMap(linkPair{"/dev/mapper/vg-root", "../dm-0"}, sysLink("dm-0"), diskLink("vda")),
			files:  map[string]string{"/sys/devices/virtual/block/dm-0/dm/uuid": "dm.uuid.lvm"},
			dirs:   []string{"/sys/devices/virtual/block/dm-0/slaves/vda2"},
		}))
		r := swapRow(t, okList(t, b, "swap.devices"), "/swap.img")
		if r["encrypted"] != false || r["backing"] != "vda2" {
			t.Errorf("/swap.img row = %v, want encrypted false backing vda2 — the volume group's slave", r)
		}
		if e := env(t, b, "swap.encrypted"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("swap.encrypted = %+v, want ok false", e)
		}
	})

	// zram holds everything in memory when it has no backing store, and
	// memory is never carried away on a disk.
	t.Run("zram with no backing store", func(t *testing.T) {
		b := build(t, "swap", swapDouble(swapLayout{
			swaps: "proc_swaps.zram",
			links: linkMap(sysLink("zram0")),
			files: map[string]string{"/sys/devices/virtual/block/zram0/backing_dev": "zram.backing_dev.none"},
		}))
		r := swapRow(t, okList(t, b, "swap.devices"), "/dev/zram0")
		if r["encrypted"] != true || r["backing"] != zramBacking {
			t.Errorf("/dev/zram0 row = %v, want encrypted true backing zram", r)
		}
		if e := env(t, b, "swap.encrypted"); e.Status != facts.StatusOK || e.Value != true {
			t.Errorf("swap.encrypted = %+v, want ok true", e)
		}
	})

	// A declared sysfs file that EXISTS and cannot be read is the only thing
	// that may take the leaf: a run that could not see the dm layer must not
	// publish "not encrypted" as though it had looked.
	t.Run("an unreadable dm uuid is the read's status", func(t *testing.T) {
		b := build(t, "swap", swapDouble(swapLayout{
			swaps: "proc_swaps.zram",
			links: linkMap(sysLink("zram0")),
			fails: map[string]error{"/sys/devices/virtual/block/zram0/dm/uuid": os.ErrPermission},
		}))
		e := env(t, b, "swap.encrypted")
		if e.Status != facts.StatusDenied {
			t.Fatalf("swap.encrypted = %+v, want denied", e)
		}
		if !strings.Contains(e.Reason, "/sys/devices/virtual/block/zram0/dm/uuid") {
			t.Errorf("reason %q does not name the file that refused", e.Reason)
		}
	})
}

// K-16: a swap file whose containing mount is not on a block device this
// kernel lists is UNSUPPORTED naming the source, never an error — the run
// stays complete and control 16 reads NOT_APPLICABLE rather than ERROR.
func TestSwapUnresolvableSourceIsUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name, mounts, source string
	}{
		{"an overlay root in a container", "mountinfo.overlay-root", "overlay"},
		{"the legacy /dev/root of a cloud image", "mountinfo.dev-root", "/dev/root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := swapDouble(swapLayout{swaps: "proc_swaps.sample", mounts: tc.mounts})
			b := buildBegun(t, "swap", a)

			e := env(t, b, "swap.encrypted")
			if e.Status != facts.StatusUnsupported {
				t.Fatalf("swap.encrypted = %+v, want unsupported", e)
			}
			if !strings.Contains(e.Reason, tc.source) {
				t.Errorf("reason %q does not name the source %q", e.Reason, tc.source)
			}
			// Unsupported ranks as ok, so the run is still complete: a
			// container must not report a partial collect over a fact about
			// the host it is not on.
			if w := b.Worst("swap"); w != facts.StatusOK {
				t.Errorf("Worst(swap) = %v, want ok: an unsupported leaf does not spoil the run", w)
			}
			// The other two keys are still answered — the device IS there,
			// and only the judgment about it could not be made.
			if p := env(t, b, "swap.present"); p.Status != facts.StatusOK || p.Value != true {
				t.Errorf("swap.present = %+v, want ok true", p)
			}
			if r := swapRow(t, okList(t, b, "swap.devices"), "/swap.img"); r["encrypted"] != false {
				t.Errorf("/swap.img row = %v, want encrypted false — nothing showed it to be", r)
			}
		})
	}
}

// parentDisk is what tells /dev/sda2 (a partition of a disk sysfs lists) from
// /dev/root (a name no kernel ever published), without muster stat'ing a path
// in /dev it did not declare.
func TestParentDisk(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"sda2", "sda"},
		{"vda1", "vda"},
		{"nvme0n1p2", "nvme0n1"},
		{"mmcblk0p1", "mmcblk0"},
		{"root", "root"},
		{"dm-1", "dm-"},
		{"1", "1"},
	} {
		if got := parentDisk(tc.name); got != tc.want {
			t.Errorf("parentDisk(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// C3: /proc/swaps itself is the answer for every key here when it cannot be
// read, and a kernel that has no /proc/swaps at all is absent, not false.
func TestSwapReadErrorReachesEveryKey(t *testing.T) {
	keys := []string{"swap.present", "swap.devices", "swap.encrypted"}

	denied := &fsAccess{fails: map[string]error{procSwapsPath: os.ErrPermission}}
	b := build(t, "swap", denied)
	for _, k := range keys {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, procSwapsPath) {
			t.Errorf("%s = %+v, want denied naming %s", k, e, procSwapsPath)
		}
	}

	b = build(t, "swap", &fsAccess{})
	for _, k := range keys {
		if e := env(t, b, k); e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, procSwapsPath) {
			t.Errorf("%s with no %s = %+v, want absent naming it", k, procSwapsPath, e)
		}
	}
}

// K-4: the collector declares every sysfs glob it reaches through, runs
// nothing, and writes exactly the three keys of B-2.
func TestSwapDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "swap")
	if c.Declare.Needs != "none" {
		t.Errorf("Needs %q, want none", c.Declare.Needs)
	}
	if len(c.Declare.Commands) != 0 {
		t.Errorf("declares %d commands, want none", len(c.Declare.Commands))
	}
	if c.Declare.Walk {
		t.Error("declares the walk licence: the sysfs links are read, never listed as a tree")
	}

	want := []string{
		"/dev/mapper/*",
		"/proc/self/mountinfo",
		"/proc/swaps",
		"/sys/block/*",
		"/sys/devices/virtual/block/*/backing_dev",
		"/sys/devices/virtual/block/*/dm/uuid",
		"/sys/devices/virtual/block/*/slaves/*",
	}
	got := slices.Clone(c.Declare.Reads)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Reads =\n%v\nwant\n%v", got, want)
	}

	b := buildBegun(t, "swap", swapDouble(swapLayout{
		swaps: "proc_swaps.zram",
		links: linkMap(sysLink("zram0")),
		files: map[string]string{"/sys/devices/virtual/block/zram0/backing_dev": "zram.backing_dev.none"},
	}))
	if keys := b.Keys("swap"); !slices.Equal(keys, []string{"swap.devices", "swap.encrypted", "swap.present"}) {
		t.Errorf("wrote %v, want the three keys of B-2", keys)
	}
}
