//go:build linux

package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
)

// osReadLimit caps the small identity files this collector reads; none of
// them is more than a few hundred bytes on any supported distribution.
const osReadLimit = 64 << 10

const (
	dockerMarker  = "/.dockerenv"
	podmanMarker  = "/run/.containerenv"
	cloudInitDir  = "/var/lib/cloud"
	sysctlNetDir  = "/proc/sys/net"
	dmiProduct    = "/sys/devices/virtual/dmi/id/product_name"
	procOneCgroup = "/proc/1/cgroup"
	procOneComm   = "/proc/1/comm"
)

// osCollector fills the run header — the host and env blocks of spec §5.1 —
// rather than any registry key, so it writes nothing through Set.
//
// R40: the read primitive refuses every symlink, and on Ubuntu 22.04/24.04
// and Rocky/Alma 9 both /etc/os-release (→ ../usr/lib/os-release) and
// /sys/class/dmi/id (→ ../../devices/virtual/dmi/id) are symlinks. So the
// declaration names the real files: /usr/lib/os-release as the fallback and
// the DMI attribute under /sys/devices/virtual.
var osCollector = collect.Collector{
	Name: "os",
	Declare: collect.Declaration{Reads: []string{
		"/etc/os-release", "/usr/lib/os-release",
		"/etc/hostname", "/etc/machine-id",
		"/proc/sys/kernel/osrelease", "/proc/sys/kernel/random/boot_id",
		"/proc/uptime", "/proc/version",
		procOneCgroup, procOneComm,
		dockerMarker, podmanMarker, systemdMarker, cloudInitDir,
		dmiProduct,
		// R46: sysctl_writable is answered by Access.Writable, which the
		// guard authorises against Reads, so the probe is declared here
		// and --list-actions prints a row for it.
		sysctlNetDir,
	}, Needs: "none"},
	Run: runOS,
}

func readTrim(a collect.Access, p string) string {
	data, _, err := a.ReadFile(p, osReadLimit)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func exists(a collect.Access, p string) bool { _, err := a.Stat(p); return err == nil }

// osReleaseText returns the first readable of /etc/os-release and
// /usr/lib/os-release. On the distributions muster supports the first is a
// symlink to the second, which the read primitive refuses outright, so the
// canonical file is a fallback rather than an alternative spelling (R40).
func osReleaseText(a collect.Access) string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, _, err := a.ReadFile(p, osReadLimit); err == nil {
			return string(data)
		}
	}
	return ""
}

// containerKind names what this process is running inside, or "none". A
// docker container has /.dockerenv and a podman one /run/.containerenv; an
// LXC container has neither, only "lxc" in pid 1's cgroup. pid 1's own name
// is the last resort: on a host it is the init system, so anything else
// means we are inside something this list does not name.
func containerKind(a collect.Access) string {
	switch {
	case exists(a, dockerMarker):
		return "docker"
	case exists(a, podmanMarker):
		return "podman"
	case strings.Contains(readTrim(a, procOneCgroup), "lxc"):
		return "lxc"
	}
	switch readTrim(a, procOneComm) {
	case "", "systemd", "init":
		return "none"
	}
	return "other"
}

// virtOf maps a DMI product name to the hypervisor it identifies. An empty
// product name is bare metal ("none"); an unreadable one is "unknown" and
// is decided by the caller, which is the only place that can tell the two
// apart.
func virtOf(product string) string {
	p := strings.ToLower(product)
	switch {
	case strings.Contains(p, "kvm"):
		return "kvm"
	case strings.Contains(p, "vmware"):
		return "vmware"
	case strings.Contains(p, "virtualbox"):
		return "virtualbox"
	case strings.Contains(p, "virtual machine"):
		return "hyperv"
	default:
		return "none"
	}
}

// osFamily is the distribution family a control's applies_when tests. ID is
// authoritative where it is one muster knows; ID_LIKE decides the rest.
func osFamily(id, idLike string) string {
	switch id {
	case "ubuntu", "debian":
		return "debian"
	case "rocky", "almalinux", "rhel", "centos", "fedora":
		return "rhel"
	}
	switch {
	case strings.Contains(idLike, "rhel"), strings.Contains(idLike, "fedora"):
		return "rhel"
	case strings.Contains(idLike, "debian"):
		return "debian"
	}
	return "unknown"
}

func runOS(_ context.Context, a collect.Access, b *collect.Builder) error {
	h := &b.Header().Host
	e := &b.Header().Env

	h.Hostname = readTrim(a, "/etc/hostname")
	// Only the hash of the machine id ever leaves the host: it identifies
	// a snapshot's origin across runs without naming the machine.
	if id := readTrim(a, "/etc/machine-id"); id != "" {
		sum := sha256.Sum256([]byte(id))
		h.MachineIDHash = hex.EncodeToString(sum[:])
	}
	h.Kernel = readTrim(a, "/proc/sys/kernel/osrelease")
	h.BootID = readTrim(a, "/proc/sys/kernel/random/boot_id")
	if up := strings.Fields(readTrim(a, "/proc/uptime")); len(up) > 0 {
		seconds, err := strconv.ParseFloat(up[0], 64)
		if err == nil {
			h.UptimeS = int64(seconds)
		}
	}

	var idLike string
	for _, line := range splitLines([]byte(osReleaseText(a))) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			h.OSRelease.ID = v
		case "VERSION_ID":
			h.OSRelease.VersionID = v
		case "ID_LIKE":
			idLike = v
		}
	}
	h.OSRelease.Family = osFamily(h.OSRelease.ID, idLike)

	e.Container = containerKind(a)
	e.WSL = strings.Contains(strings.ToLower(readTrim(a, "/proc/version")), "microsoft")
	e.HasSystemd = exists(a, systemdMarker)
	// R46: whether this process may write sysctls is an environment probe,
	// answered by Access so the guard sees it, never by unix.Access.
	e.SysctlWritable = a.Writable(sysctlNetDir)
	e.CloudInit = exists(a, cloudInitDir)
	if product, _, err := a.ReadFile(dmiProduct, osReadLimit); err != nil {
		e.Virt = "unknown" // no DMI here: a container, or a kernel without it
	} else {
		e.Virt = virtOf(strings.TrimSpace(string(product)))
	}
	return nil
}
