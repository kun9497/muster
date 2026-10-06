package collectors

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/pkgindex"
)

// This file is untagged so its tests run on every platform; the collector
// that calls it is processes.go (linux). The listener and owner types are the
// interface the exposure derivation (Task 4) reads.

// cmdlineCap is how much of /proc/<pid>/cmdline the first token is taken
// from (spec P-1): a command line is evidence, and an argument list can run
// to megabytes.
const cmdlineCap = 4 << 10

// procStatus is what the collector reads from /proc/<pid>/status: the name,
// the parent, the real uid, the one-letter state and, on kernels that print
// it (6.x), the Kthread flag (W-42).
type procStatus struct {
	Name       string
	PPid, Uid  int
	State      string
	Kthread    bool
	HasKthread bool
}

// errProcStatus is a status file that lacks a line every process has.
var errProcStatus = errors.New("status lacks Name, State, PPid or Uid")

// parseProcStatus reads the "Key:\tvalue" lines of a status file. State is
// its first letter ("S (sleeping)" -> "S"); Uid is the first of the four
// columns (real, effective, saved, filesystem), the account that started the
// process. A file without Name, State, PPid and Uid is not a process's
// status and is an error rather than a zero-valued row.
func parseProcStatus(data []byte) (procStatus, error) {
	var st procStatus
	var seen struct{ name, state, ppid, uid bool }
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Name":
			st.Name, seen.name = val, true
		case "State":
			if val != "" {
				st.State, seen.state = val[:1], true
			}
		case "PPid":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				st.PPid, seen.ppid = n, true
			}
		case "Uid":
			if f := strings.Fields(val); len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil && n >= 0 {
					st.Uid, seen.uid = n, true
				}
			}
		case "Kthread":
			st.HasKthread, st.Kthread = true, val == "1"
		}
	}
	if !seen.name || !seen.state || !seen.ppid || !seen.uid {
		return procStatus{}, errProcStatus
	}
	return st, nil
}

// parseCmdline is the first NUL-separated token of a command line, from at
// most cmdlineCap bytes. A process that rewrote its argv into one string
// ("sshd: alice [priv]") has no NUL and is returned whole, within the cap.
func parseCmdline(data []byte) string {
	if len(data) > cmdlineCap {
		data = data[:cmdlineCap]
	}
	s := string(data)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseFdLink is the inode of a socket fd's link text, "socket:[12345]".
// Every other target — a pipe, a file, an anon inode — is not a socket.
func parseFdLink(target string) (inode int, ok bool) {
	inner, found := strings.CutPrefix(target, "socket:[")
	if !found {
		return 0, false
	}
	digits, found := strings.CutSuffix(inner, "]")
	if !found || digits == "" {
		return 0, false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

// deletedSuffix is proc(5)'s notation for an executable unlinked or replaced
// since exec.
const deletedSuffix = " (deleted)"

// stripDeleted splits proc(5)'s " (deleted)" off an exe link's text.
func stripDeleted(target string) (exe string, deleted bool) {
	if s, ok := strings.CutSuffix(target, deletedSuffix); ok {
		return s, true
	}
	return target, false
}

// The package_status vocabulary (W-9). unpackagedStatuses are the ones
// processes.unpackaged_listeners holds.
const (
	pkgPackaged   = "packaged"
	pkgUnpackaged = "unpackaged"
	pkgSnap       = "snap"
	pkgFlatpak    = "flatpak"
	pkgAppImage   = "appimage"
	pkgForeignNS  = "foreign_ns"
	pkgNoIndex    = "no_index"

	nsHost    = "host"
	nsForeign = "foreign"
)

var unpackagedStatuses = map[string]bool{
	pkgUnpackaged: true, pkgSnap: true, pkgFlatpak: true, pkgAppImage: true, pkgForeignNS: true,
}

// packageStatusFor says where exe came from. A process outside the host's
// mount namespace names a path in another root, so the host's index is never
// asked about it; the snap, flatpak and AppImage shapes are decided by the
// path alone; everything else is the index's answer, and an index that could
// not be built (Family neither dpkg nor rpm — the zero Index a failed build
// is passed as, or a host with no database) is no_index, never unpackaged.
func packageStatusFor(exe string, mntNS string, idx pkgindex.Index) (pkg, status string) {
	if mntNS != nsHost {
		return "", pkgForeignNS
	}
	if rest, ok := strings.CutPrefix(exe, "/snap/"); ok {
		name, _, _ := strings.Cut(rest, "/")
		if name != "" {
			return "snap:" + name, pkgSnap
		}
	}
	if strings.HasPrefix(exe, "/var/lib/flatpak/") || isHomeFlatpak(exe) {
		return "", pkgFlatpak
	}
	if strings.HasPrefix(exe, "/tmp/.mount_") {
		return "", pkgAppImage
	}
	if idx.Family != pkgindex.FamilyDpkg && idx.Family != pkgindex.FamilyRPM {
		return "", pkgNoIndex
	}
	if p, ok := idx.Owner(exe); ok {
		return p, pkgPackaged
	}
	return "", pkgUnpackaged
}

// isHomeFlatpak is /home/<user>/.local/share/flatpak/..., a per-user
// installation.
func isHomeFlatpak(exe string) bool {
	rest, ok := strings.CutPrefix(exe, "/home/")
	if !ok {
		return false
	}
	user, tail, ok := strings.Cut(rest, "/")
	return ok && user != "" && strings.HasPrefix(tail, ".local/share/flatpak/")
}

// isLinkLocal is an address in fe80::/10 or 169.254.0.0/16.
func isLinkLocal(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLinkLocalUnicast()
}

// owner is one process holding a listening socket.
type owner struct {
	Pid, Uid      int
	Name, Exe     string
	ExeDeleted    bool
	MntNS         string
	Package       string
	PackageStatus string
}

func (o owner) record() map[string]any {
	return map[string]any{
		"pid": o.Pid, "uid": o.Uid, "name": o.Name, "exe": o.Exe, "exe_deleted": o.ExeDeleted,
		"mnt_ns": o.MntNS, "package": o.Package, "package_status": o.PackageStatus,
	}
}

// listener is one listening socket of the host with the processes holding
// it. Proto is tcp or udp and Family v4 or v6, folded from the table the row
// came from; OwnerStatus is ok, kernel, unmatched or denied.
type listener struct {
	Proto, Family, Addr string
	Port                int
	Loopback, LinkLocal bool
	Inode               int
	OwnerStatus         string
	Owners              []owner
}

// record is the processes.listeners row; owners are capped at ownersCap.
func (l listener) record(ownersCap int) map[string]any {
	owners := make([]any, 0, min(len(l.Owners), ownersCap))
	for i, o := range l.Owners {
		if i == ownersCap {
			break
		}
		owners = append(owners, o.record())
	}
	return map[string]any{
		"proto": l.Proto, "family": l.Family, "addr": l.Addr, "port": l.Port,
		"loopback": l.Loopback, "link_local": l.LinkLocal, "inode": l.Inode,
		"owner_status": l.OwnerStatus, "owners": owners,
	}
}

// foldProto turns a socket table's name into the listener's proto and
// family: tcp6 is tcp over v6.
func foldProto(table string) (proto, family string) {
	if p, ok := strings.CutSuffix(table, "6"); ok {
		return p, "v6"
	}
	return table, "v4"
}
