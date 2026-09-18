//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	procSwapsPath = "/proc/swaps"

	devDir        = "/dev/"
	devMapperDir  = "/dev/mapper"
	devMapperGlob = "/dev/mapper/*"

	// sysBlockDir holds one SYMLINK per block device the kernel knows —
	// never a partition, which lives under its disk — and the link's target
	// is what says whether the device is virtual (dm, md, loop, zram) or a
	// disk on a bus. Ruling K-15: the collector reads those links and never
	// asks the kernel to resolve one for it.
	sysBlockDir  = "/sys/block"
	sysBlockGlob = "/sys/block/*"

	// sysBlockPartGlob is ruling K-23: a partition is a real DIRECTORY under
	// its disk (/sys/block/sda/sda2), so the probe that says a partition name
	// is a device on this host is a Stat of that directory, not the presence
	// of the disk alone. A disk that has no such entry does not have that
	// partition, whatever the name looks like.
	sysBlockPartGlob = "/sys/block/*/*"

	sysVirtualBlockDir = "/sys/devices/virtual/block"
	dmUUIDGlob         = "/sys/devices/virtual/block/*/dm/uuid"
	slavesGlob         = "/sys/devices/virtual/block/*/slaves/*"
	backingDevGlob     = "/sys/devices/virtual/block/*/backing_dev"

	// cryptUUIDPrefix is what device-mapper puts in front of every dm-crypt
	// target's uuid, whatever the header format: CRYPT-LUKS2-…, CRYPT-LUKS1-…
	// and the CRYPT-PLAIN-… of a plain dm-crypt swap all begin with it.
	cryptUUIDPrefix = "CRYPT-"

	// zramNoBacking is what a zram device with no backing store reports: it
	// lives entirely in memory, which is never written to a disk an attacker
	// can carry away, and B-2 counts that as encrypted with backing "zram".
	zramNoBacking = "none"
	zramBacking   = "zram"

	swapTypeFile = "file"

	// swapWalkDepth bounds the slaves recursion. A stack deeper than this is
	// not a layout: it is a sysfs that is lying to us, and the bound is what
	// keeps the collector from following it forever.
	swapWalkDepth = 16
)

// swapCollector answers one question — is everything this host may page out
// to written to encrypted storage — and the evidence for it. Nothing here
// runs lsblk, blkid or cryptsetup: /proc/swaps names the devices and the
// sysfs block tree says what each one sits on.
var swapCollector = collect.Collector{
	Name: "swap",
	Declare: collect.Declaration{Reads: []string{
		procSwapsPath,
		// A swap FILE is on a filesystem, and the mount table is the only
		// thing that says which device that filesystem is.
		mountinfoPath,
		devMapperGlob,
		sysBlockGlob, sysBlockPartGlob, dmUUIDGlob, slavesGlob, backingDevGlob,
	}, Needs: "none"},
	Run: runSwap,
}

// swapEntry is one row of /proc/swaps: what is being paged to and whether it
// is a file on a filesystem or a device of its own.
type swapEntry struct{ path, kind string }

// parseProcSwaps reads the device list the kernel publishes. The first line
// is the column header; every row after it is "Filename Type Size Used
// Priority", with the file name carrying the same octal escapes mountinfo
// uses. A row with fewer than the two judged fields is dropped rather than
// failing the file: the kernel writes no such row, and one mangled line must
// not cost the answer for the devices that did parse.
func parseProcSwaps(data []byte) []swapEntry {
	out := []swapEntry{}
	for i, line := range splitLines(data) {
		if i == 0 {
			continue // the column header
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		out = append(out, swapEntry{path: unescapeMountField(f[0]), kind: f[1]})
	}
	return out
}

func runSwap(_ context.Context, a collect.Access, b *collect.Builder) error {
	data, meta, err := a.ReadFile(procSwapsPath, readLimit)
	if err != nil {
		e := readErrorEnv(procSwapsPath, err)
		if errors.Is(err, fs.ErrNotExist) {
			e = collect.Absent(procSwapsPath + " does not exist, so this kernel has no swap at all")
		}
		b.Set("swap.present", e)
		b.Set("swap.devices", e)
		b.Set("swap.encrypted", e)
		return nil
	}

	entries := parseProcSwaps(data)
	src := &facts.Source{Kind: "proc", Path: procSwapsPath}
	b.Set("swap.present", collect.OKRead(len(entries) > 0, src, meta))

	r := newSwapResolver(a)
	rows := make([]map[string]any, 0, len(entries))
	decisions := make([]swapDecision, 0, len(entries))
	for _, e := range entries {
		d := r.decide(e)
		decisions = append(decisions, d)
		rows = append(rows, map[string]any{
			"path":      e.path,
			"type":      e.kind,
			"encrypted": d.encrypted,
			"backing":   d.backing,
		})
	}
	b.Set("swap.devices", collect.OKRead(rowsValue(rows), src, meta))
	b.Set("swap.encrypted", swapEncrypted(decisions, r, meta))
	return nil
}

// swapDecision is what the resolver could say about one swap device.
// backing names the device the judgment was made on — the dm-crypt target
// that encrypts it, the physical partition it ends at, or, when there was no
// judgment, whatever the walk stopped at, so the row's evidence always says
// where the answer came from.
type swapDecision struct {
	encrypted bool
	backing   string
	// fail is set when no answer could be had: unsupported for a source that
	// is not a block device this kernel lists (K-16), or the read's own
	// status for a declared sysfs file that exists and could not be read.
	fail *facts.Envelope
}

// swapEncrypted is the host-level leaf. A read failure wins over every
// answer, the way grubPassword's chain does: a run that could not see
// everything must not publish a verdict as though it had. An unresolvable
// source comes next — "every device is encrypted" cannot be asserted about a
// set with a member nobody could look at — and only then is the answer the
// AND over the devices, which is what "every device is on dm-crypt" means.
func swapEncrypted(decisions []swapDecision, r *swapResolver, meta collect.ReadMeta) facts.Envelope {
	if len(decisions) == 0 {
		return collect.Absent(procSwapsPath + " lists no swap device")
	}
	var readFail, unsupported *facts.Envelope
	all := true
	for i := range decisions {
		d := decisions[i]
		if d.fail != nil {
			all = false
			switch {
			case d.fail.Status == facts.StatusUnsupported:
				if unsupported == nil {
					unsupported = d.fail
				}
			case readFail == nil:
				readFail = d.fail
			}
			continue
		}
		all = all && d.encrypted
	}
	switch {
	case readFail != nil:
		return *readFail
	case unsupported != nil:
		return *unsupported
	}
	return collect.OKRead(all, &facts.Source{Kind: "derived", Inputs: r.inputs()}, meta)
}

// inputs is the provenance of the host leaf: /proc/swaps always, the mount
// table only when a swap FILE sent the resolver through it, and the sysfs
// block tree the verdict was read out of. C3 — an envelope cites what was
// read, and a snapshot whose swap is a file must let a reader see that the
// mount table is part of the answer.
func (r *swapResolver) inputs() []facts.Source {
	in := []facts.Source{{Kind: "proc", Path: procSwapsPath}}
	if r.mountRead {
		in = append(in, facts.Source{Kind: "proc", Path: mountinfoPath})
	}
	return append(in, facts.Source{Kind: "sys", Path: sysBlockDir})
}

// swapResolver holds the reads one collect shares across devices: the mount
// table, which is needed only when a swap FILE has to be traced to the device
// its filesystem is on, and is therefore read at most once and only then.
type swapResolver struct {
	a         collect.Access
	rows      []mountRow
	mountErr  *facts.Envelope
	mountRead bool

	// decided memoizes one device's verdict by name. A device reached twice
	// is the same device: a dm-thin pool whose data and metadata halves both
	// sit on one dm-crypt node reaches that node through two paths, and a
	// guard that answered "seen already, not encrypted" the second time would
	// fail control 16 on a layout that is entirely encrypted. resolving is
	// the in-flight set, which only a sysfs that contradicts itself can hit.
	decided   map[string]swapDecision
	resolving map[string]bool
}

func newSwapResolver(a collect.Access) *swapResolver {
	return &swapResolver{a: a, decided: map[string]swapDecision{}, resolving: map[string]bool{}}
}

// decide resolves one swap device to a verdict. A swap file is traced to the
// source of the mount that contains it first; everything else is the device
// /proc/swaps named.
func (r *swapResolver) decide(e swapEntry) swapDecision {
	source := e.path
	if e.kind == swapTypeFile {
		s, fail := r.fileSource(e.path)
		if fail != nil {
			return swapDecision{backing: e.path, fail: fail}
		}
		source = s
	}
	return r.resolveSource(source, 0)
}

// fileSource is the device the filesystem holding a swap file is mounted
// from. C3: a mount table that could not be read is the answer for the leaf,
// never a guess about what the file is on.
func (r *swapResolver) fileSource(p string) (string, *facts.Envelope) {
	if !r.mountRead {
		r.rows, _, r.mountErr = mountinfoRows(r.a)
		r.mountRead = true
	}
	if r.mountErr != nil {
		return "", r.mountErr
	}
	return governingMount(r.rows, p).source, nil
}

// resolveSource turns a source as /proc/swaps or mountinfo spells it into a
// device name and hands it to the sysfs walk.
//
// K-16: a source that is not a block-device node — "overlay" in a container,
// the legacy "/dev/root" of a cloud image, a device path this kernel lists
// nowhere — is UNSUPPORTED naming the source, never an error, so run.complete
// stays true and control 16 reads NOT_APPLICABLE rather than ERROR.
func (r *swapResolver) resolveSource(source string, depth int) swapDecision {
	if !strings.HasPrefix(source, devDir) {
		return swapDecision{backing: source, fail: unresolvableSwapSource(source)}
	}
	name := strings.TrimPrefix(source, devDir)
	if path.Dir(source) == devMapperDir {
		// Every /dev/mapper entry is a symlink to the dm-N node beside it,
		// and the dm name is what sysfs is keyed by.
		target, err := r.a.Readlink(source)
		if err != nil {
			if e, isRead := swapReadFail(source, err); isRead {
				return swapDecision{backing: source, fail: e}
			}
			return swapDecision{backing: source, fail: unresolvableSwapSource(source)}
		}
		if !strings.HasPrefix(target, "/") {
			target = path.Join(devMapperDir, target)
		}
		name = path.Base(path.Clean(target))
	}
	if name == "" || strings.Contains(name, "/") {
		// A /dev/disk/by-uuid/… or /dev/vg/lv path: a link this collector
		// does not declare, so it is not one muster may follow (C4).
		return swapDecision{backing: source, fail: unresolvableSwapSource(source)}
	}
	return r.resolveDevice(name, depth)
}

// resolveDevice is the sysfs half of ruling K-15. /sys/block/<dev> is read as
// the symlink it is: a target under ../devices/virtual/block is a device the
// kernel composed and can be walked down, and a target anywhere else is a
// disk on a bus — terminal, and not encrypted, because only device-mapper
// encrypts.
//
// A name with no /sys/block entry at all is a PARTITION, which sysfs lists as
// a directory UNDER its disk and never at the top. Ruling K-23: the probe is
// therefore /sys/block/<disk>/<name> — the partition's own directory — and not
// the mere presence of the disk, which would accept "/dev/sda9" on a host
// whose sda has two partitions. A name whose disk does not list it is not a
// block device on this host, which is the other half of K-16: it is how
// "/dev/root" is told from "/dev/sda2" without muster ever stat'ing a path in
// /dev it did not declare.
//
// The probe is a GLOB of the disk's directory, read for names only, exactly as
// K-15 reads slaves/ — not a Stat of the partition path. Every entry of
// /sys/block is a symlink (K-15's own premise), so no path underneath one can
// be opened no-follow: a Stat of /sys/block/sda/sda3 is refused with "symbolic
// link in path" on every real host, which would turn a bare LVM partition into
// an ERROR. Glob names candidates without resolving them, and a name is all
// this probe wants.
//
// The verdict is memoized under the device's name, so a node two branches of
// one dm stack share is decided once and read twice.
func (r *swapResolver) resolveDevice(name string, depth int) swapDecision {
	if d, ok := r.decided[name]; ok {
		return d
	}
	if depth > swapWalkDepth {
		return swapDecision{backing: name, fail: ptr(collect.Unsupported(
			"the device stack under " + name + " is deeper than muster follows"))}
	}
	if r.resolving[name] {
		// A device that is its own ancestor: sysfs contradicting itself. The
		// verdict is being decided further up the stack and will be applied
		// there, so this one is NEUTRAL in the AND rather than a false.
		return swapDecision{encrypted: true, backing: name}
	}
	r.resolving[name] = true
	d := r.resolveUncached(name, depth)
	delete(r.resolving, name)
	r.decided[name] = d
	return d
}

func (r *swapResolver) resolveUncached(name string, depth int) swapDecision {
	target, err := r.sysBlockLink(name)
	switch {
	case err != nil:
		if e, isRead := swapReadFail(path.Join(sysBlockDir, name), err); isRead {
			return swapDecision{backing: name, fail: e}
		}
		// Not listed at the top of the block tree: a partition, if its disk
		// lists it, and nothing this kernel knows if it does not.
		disk := parentDisk(name)
		if disk == name {
			return swapDecision{backing: name, fail: unresolvableSwapSource(devDir + name)}
		}
		listed, lerr := r.diskLists(disk, name)
		if lerr != nil {
			return swapDecision{backing: name, fail: lerr}
		}
		if !listed {
			return swapDecision{backing: name, fail: unresolvableSwapSource(devDir + name)}
		}
		return swapDecision{backing: name}
	case path.Dir(target) != sysVirtualBlockDir:
		return swapDecision{backing: name} // a disk on a bus: terminal
	}
	return r.resolveVirtual(path.Base(target), depth)
}

// sysBlockLink reads one /sys/block entry as the symlink it is and resolves a
// relative target textually against /sys/block, the way linkTarget does for
// every other link muster reads. Readlink is guarded by Reads exactly as Stat
// is (K-15), so no stat is needed to learn the entry is a link: a name that is
// not one answers EINVAL and is treated as a name that is not there.
func (r *swapResolver) sysBlockLink(name string) (string, error) {
	p := path.Join(sysBlockDir, name)
	target, err := r.a.Readlink(p)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(target, "/") {
		target = path.Join(sysBlockDir, target)
	}
	return path.Clean(target), nil
}

// diskLists reports whether a disk's own sysfs directory lists a partition of
// that name. A disk that is not there lists nothing, which is the same answer
// and the same finding: this kernel does not have the device the source named.
func (r *swapResolver) diskLists(disk, name string) (bool, *facts.Envelope) {
	pattern := path.Join(sysBlockDir, disk, "*")
	matches, err := r.a.Glob(pattern)
	if err != nil {
		return false, ptr(globReadError(pattern, err, collect.ErrorEnv(pattern+": "+err.Error())))
	}
	return slices.ContainsFunc(matches, func(m string) bool { return path.Base(m) == name }), nil
}

// resolveVirtual walks a device the kernel composed. dm first: a uuid that
// begins CRYPT- is the answer, and any other dm device — the LVM volume the
// stock "encrypted LVM" installation puts swap on — is followed down its
// slaves. A device with no dm/uuid is not device-mapper at all: zram with no
// backing store is memory and counts as encrypted, and anything else is
// terminal.
func (r *swapResolver) resolveVirtual(name string, depth int) swapDecision {
	uuidPath := path.Join(sysVirtualBlockDir, name, "dm", "uuid")
	data, _, err := r.a.ReadFile(uuidPath, readLimit)
	switch {
	case err == nil:
		if strings.HasPrefix(strings.TrimSpace(string(data)), cryptUUIDPrefix) {
			return swapDecision{encrypted: true, backing: name}
		}
		return r.resolveSlaves(name, depth)
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		// K-15: no dm/uuid means "not a dm device", not a read failure.
		return r.resolveZram(name)
	}
	return swapDecision{backing: name, fail: ptr(readErrorEnv(uuidPath, err))}
}

// resolveZram asks the one other virtual device whose storage is not a disk.
// backing_dev reads "none" when a zram holds everything in memory; a zram
// with a real backing store, and every other virtual device, is terminal.
func (r *swapResolver) resolveZram(name string) swapDecision {
	p := path.Join(sysVirtualBlockDir, name, "backing_dev")
	data, _, err := r.a.ReadFile(p, readLimit)
	switch {
	case err == nil:
		if strings.TrimSpace(string(data)) == zramNoBacking {
			return swapDecision{encrypted: true, backing: zramBacking}
		}
		return swapDecision{backing: name}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return swapDecision{backing: name}
	}
	return swapDecision{backing: name, fail: ptr(readErrorEnv(p, err))}
}

// resolveSlaves follows a dm device that is not itself dm-crypt down to what
// it is built on. Every slave must be encrypted for the device to be: a
// volume group striped across one encrypted and one bare physical volume
// pages to the bare one, so "any" would be a false pass. The FIRST slave that
// is not encrypted, in name order, is the one backing names, which is what
// puts the operator in front of the disk they have to deal with.
func (r *swapResolver) resolveSlaves(name string, depth int) swapDecision {
	pattern := path.Join(sysVirtualBlockDir, name, "slaves", "*")
	matches, err := r.a.Glob(pattern)
	if err != nil {
		return swapDecision{backing: name, fail: ptr(globReadError(pattern, err,
			collect.ErrorEnv(pattern+": "+err.Error())))}
	}
	slices.Sort(matches)
	if len(matches) == 0 {
		return swapDecision{backing: name}
	}

	out := swapDecision{encrypted: true, backing: name}
	first := true
	for _, m := range matches {
		d := r.resolveDevice(path.Base(m), depth+1)
		if d.fail != nil {
			return d
		}
		if first || (out.encrypted && !d.encrypted) {
			out.backing = d.backing
		}
		first = false
		out.encrypted = out.encrypted && d.encrypted
	}
	return out
}

// parentDisk is the disk a partition name belongs to: sda2 -> sda, vda1 ->
// vda, nvme0n1p2 -> nvme0n1, mmcblk0p1 -> mmcblk0. A name that is not a
// partition name is returned UNCHANGED, and the caller reads "disk == name" as
// "this is not a partition of anything" — which is what makes "root", the
// /dev/root of a cloud image that no kernel ever published, resolve to
// nothing.
//
// Two shapes are not partition names. A name with no trailing digits at all is
// one. So is a name whose digits follow a "-": dm-1, and every other kernel
// family that numbers itself that way, is a whole device with a /sys/block
// entry of its own, so a dm-1 that reached here is a name this host does not
// have — "dm-" is not a disk and must never be probed as one.
func parentDisk(name string) string {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	if i == len(name) || i == 0 || name[i-1] == '-' {
		return name
	}
	// nvme and mmcblk separate the partition number with a "p" that only
	// counts as a separator when a digit precedes it, so "loop1p" would not
	// be mistaken for one.
	if i > 1 && name[i-1] == 'p' && name[i-2] >= '0' && name[i-2] <= '9' {
		i--
	}
	return name[:i]
}

// unresolvableSwapSource is K-16's envelope: the source is named, the status
// is unsupported so Builder.Worst still ranks the run complete, and the
// reason says what muster could not do rather than blaming the host.
func unresolvableSwapSource(source string) *facts.Envelope {
	return ptr(collect.Unsupported(source + " is not a block device this kernel lists under " + sysBlockDir +
		", so there is nothing to decide encryption from"))
}

// swapReadFail separates a sysfs path that is simply not there — the ordinary
// answer for a partition, for a device with no dm layer, for a name no kernel
// published — from one that exists and refused to be read, which is the only
// thing that may take the leaf (C3).
func swapReadFail(p string, err error) (*facts.Envelope, bool) {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.EINVAL):
		return nil, false
	}
	return ptr(readErrorEnv(p, err)), true
}

func ptr[T any](v T) *T { return &v }
