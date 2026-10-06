//go:build linux

package collectors

import (
	"fmt"
	"io/fs"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgindex"
)

// fakeProc is one scripted process: its status fields, command line, exe
// link, mount namespace and fd links (fd number -> link text).
type fakeProc struct {
	pid, ppid, uid int
	name, state    string
	kthread        string            // "", "0" or "1": the Kthread line, printed only when set
	threads        int               // the Threads line, printed only when > 0
	tasks          map[string]string // task fd links: "<tid>/<fd>" -> link text
	cmdline        string
	exe            string // "" leaves the link out (a kernel thread's ENOENT)
	ns             string // "" -> the host's namespace
	root           string // the root link: "" -> "/"; "-" leaves it out
	fds            map[int]string
}

const hostMntNS = "mnt:[4026531841]"

func procStatusText(p fakeProc) string {
	state := p.state
	if state == "" {
		state = "S (sleeping)"
	}
	s := fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\n",
		p.name, state, p.pid, p.pid, p.ppid, p.uid, p.uid, p.uid, p.uid)
	if p.kthread != "" {
		s += "Kthread:\t" + p.kthread + "\n"
	}
	if p.threads > 0 {
		s += "Threads:\t" + strconv.Itoa(p.threads) + "\n"
	}
	return s
}

// tcpRow is one LISTEN row of a /proc/net/tcp-shaped table.
func tcpRow(i int, addrHex string, port, inode int, state string) string {
	return fmt.Sprintf("   %d: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n",
		i, addrHex, port, state, inode)
}

const procNetHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpTable is a tcp table whose rows listen on 0.0.0.0 at the given
// port -> inode pairs, in the order given.
func tcpTable(rows ...[2]int) []byte {
	s := procNetHeader
	for i, r := range rows {
		s += tcpRow(i, "00000000", r[0], r[1], tcpListen)
	}
	return []byte(s)
}

// procHost is an fsAccess holding the processes, pid 1's namespace, a dpkg
// database that owns /usr/sbin/sshd and /usr/lib/systemd/systemd, and the tcp
// table.
func procHost(tcp []byte, procs ...fakeProc) *fsAccess {
	a := &fsAccess{
		contents: map[string][]byte{
			"/proc/self/net/tcp":                          []byte(tcp),
			pkgindex.DpkgStatusPath:                       []byte("Package: openssh-server\nStatus: install ok installed\nVersion: 1:8.9p1\n\nPackage: systemd\nStatus: install ok installed\nVersion: 249\n"),
			pkgindex.DpkgInfoDir + "/openssh-server.list": []byte("/.\n/usr/sbin/sshd\n"),
			pkgindex.DpkgInfoDir + "/systemd.list":        []byte("/lib/systemd/systemd-resolved\n/usr/lib/systemd/systemd\n"),
		},
		links: map[string]string{procInitMntNS: hostMntNS},
		fails: map[string]error{},
	}
	a.contents[procPath(1, "mountinfo")] = []byte(hostMountinfo)
	for _, p := range procs {
		addProc(a, p)
	}
	return a
}

func addProc(a *fsAccess, p fakeProc) {
	a.contents[procPath(p.pid, "status")] = []byte(procStatusText(p))
	if p.cmdline != "" {
		a.contents[procPath(p.pid, "cmdline")] = []byte(p.cmdline)
	}
	if p.exe != "" {
		a.links[procPath(p.pid, "exe")] = p.exe
	}
	ns := p.ns
	if ns == "" {
		ns = hostMntNS
	}
	a.links[procPath(p.pid, "ns/mnt")] = ns
	switch p.root {
	case "":
		a.links[procPath(p.pid, "root")] = "/"
	case "-":
	default:
		a.links[procPath(p.pid, "root")] = p.root
	}
	for k, t := range p.tasks {
		tid, fd, _ := strings.Cut(k, "/")
		a.links[procPath(p.pid, "task/"+tid+"/fd/"+fd)] = t
	}
	for fd, t := range p.fds {
		a.links[procPath(p.pid, "fd/"+strconv.Itoa(fd))] = t
	}
}

// The stock trio: systemd (pid 1), kthreadd (pid 2) and sshd.
func initProc(fds map[int]string) fakeProc {
	return fakeProc{pid: 1, ppid: 0, name: "systemd", cmdline: "/sbin/init\x00splash\x00", exe: "/usr/lib/systemd/systemd", fds: fds}
}

var kthreadd = fakeProc{pid: 2, ppid: 0, name: "kthreadd"}

func sshdProc(fds map[int]string) fakeProc {
	return fakeProc{pid: 812, ppid: 1, name: "sshd", cmdline: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", exe: "/usr/sbin/sshd", fds: fds}
}

// denyLink makes a link answer EACCES, as a magic link another account's
// process owns answers a non-root readlink.
func denyLink(a *fsAccess, p string) {
	delete(a.links, p)
	a.fails[p] = fmt.Errorf("%s: %w", p, unix.EACCES)
}

func rowsByPid(t *testing.T, list []any) map[int]map[string]any {
	t.Helper()
	out := map[int]map[string]any{}
	for _, r := range list {
		m := r.(map[string]any)
		out[m["pid"].(int)] = m
	}
	return out
}

func TestProcessesListsUserKernelAndZombie(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}),
		initProc(nil), kthreadd,
		fakeProc{pid: 31, ppid: 2, name: "kworker/0:1", state: "I (idle)"},
		fakeProc{pid: 40, ppid: 7, name: "worker", state: "I (idle)", kthread: "1"},
		sshdProc(map[int]string{3: "socket:[7]", 4: "/dev/null"}),
		fakeProc{pid: 900, ppid: 812, uid: 1000, name: "nginx", exe: "/usr/sbin/nginx (deleted)"},
		fakeProc{pid: 950, ppid: 1, uid: 1000, name: "defunct", state: "Z (zombie)"},
	)
	b := build(t, "processes", a)
	rows := rowsByPid(t, okList(t, b, "processes.list"))
	if len(rows) != 7 {
		t.Fatalf("%d rows: %v", len(rows), rows)
	}
	for pid, want := range map[int]string{1: "user", 2: "kernel", 31: "kernel", 40: "kernel", 812: "user", 900: "user", 950: "zombie"} {
		if rows[pid]["kind"] != want {
			t.Errorf("pid %d kind %v, want %s", pid, rows[pid]["kind"], want)
		}
	}
	sshd := rows[812]
	if sshd["exe"] != "/usr/sbin/sshd" || sshd["exe_read_status"] != "ok" || sshd["exe_deleted"] != false ||
		sshd["mnt_ns"] != "host" || sshd["ns_read_status"] != "ok" || sshd["package"] != "openssh-server" ||
		sshd["package_status"] != "packaged" || sshd["ppid"] != 1 || sshd["cmd"] != "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups" {
		t.Errorf("sshd row %v", sshd)
	}
	if rows[1]["cmd"] != "/sbin/init" {
		t.Errorf("init cmd %v", rows[1]["cmd"])
	}
	nginx := rows[900]
	if nginx["exe"] != "/usr/sbin/nginx" || nginx["exe_deleted"] != true || nginx["package_status"] != "unpackaged" || nginx["uid"] != 1000 {
		t.Errorf("nginx row %v", nginx)
	}
	for _, pid := range []int{2, 950} {
		if rows[pid]["exe_read_status"] != "" || rows[pid]["exe"] != "" || rows[pid]["package_status"] != "" {
			t.Errorf("pid %d carries an executable: %v", pid, rows[pid])
		}
	}
	del := okList(t, b, "processes.deleted_executables")
	if len(del) != 1 || del[0].(map[string]any)["pid"] != 900 || del[0].(map[string]any)["exe"] != "/usr/sbin/nginx" {
		t.Errorf("deleted_executables %v", del)
	}
	stats := env(t, b, "processes.stats").Value.(map[string]any)
	if stats["count"] != 7 || stats["kernel_threads"] != 3 || stats["zombies"] != 1 || stats["index_source"] != "dpkg" || stats["vanished"] != 0 {
		t.Errorf("stats %v", stats)
	}
}

func listenerRows(t *testing.T, b *collect.Builder) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range okList(t, b, "processes.listeners") {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestProcessesListenerOwnedByTwoProcesses(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}),
		sshdProc(map[int]string{3: "socket:[7]", 5: "socket:[7]"}), initProc(map[int]string{40: "socket:[7]"}))
	b := build(t, "processes", a)
	ls := listenerRows(t, b)
	if len(ls) != 1 {
		t.Fatalf("%v", ls)
	}
	l := ls[0]
	if l["owner_status"] != "ok" || l["proto"] != "tcp" || l["family"] != "v4" || l["port"] != 22 || l["inode"] != 7 || l["addr"] != "0.0.0.0" {
		t.Errorf("listener %v", l)
	}
	owners := l["owners"].([]any)
	if len(owners) != 2 || owners[0].(map[string]any)["pid"] != 1 || owners[1].(map[string]any)["pid"] != 812 {
		t.Fatalf("owners %v, want pid 1 then 812, each once", owners)
	}
	if o := owners[1].(map[string]any); o["package"] != "openssh-server" || o["package_status"] != "packaged" || o["mnt_ns"] != "host" {
		t.Errorf("sshd owner %v", o)
	}
	if got := okList(t, b, "processes.unpackaged_listeners"); len(got) != 0 {
		t.Errorf("unpackaged %v", got)
	}
}

func TestProcessesKernelSocketIsOwnerStatusKernel(t *testing.T) {
	a := procHost(tcpTable([2]int{2049, 0}), initProc(nil))
	b := build(t, "processes", a)
	ls := listenerRows(t, b)
	if len(ls) != 1 || ls[0]["owner_status"] != "kernel" || len(ls[0]["owners"].([]any)) != 0 {
		t.Fatalf("%v", ls)
	}
	if got := okList(t, b, "processes.unpackaged_listeners"); len(got) != 0 {
		t.Errorf("a kernel socket is packaged by nature: %v", got)
	}
}

// W-66: a kernel-owned socket has a real inode (the lab's WireGuard socket
// printed 363387305). When every fd table was read whole and none holds the
// inode, the socket is the kernel's; when a table failed, it is unmatched
// and the leaf carries the failure.
func TestProcessesUnheldSocketIsTheKernels(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil), kthreadd)
	b := build(t, "processes", a)
	ls := listenerRows(t, b)
	if len(ls) != 2 || ls[1]["port"] != 2049 || ls[1]["owner_status"] != "kernel" || len(ls[1]["owners"].([]any)) != 0 || ls[1]["owners_count"] != 0 {
		t.Fatalf("%v", ls)
	}
	if got := okList(t, b, "processes.unpackaged_listeners"); len(got) != 0 {
		t.Errorf("a kernel socket is packaged by nature: %v", got)
	}

	a = procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil),
		fakeProc{pid: 42, ppid: 1, name: "other", exe: "/usr/bin/other", fds: map[int]string{3: "socket:[1]"}})
	a.fails[procPath(42, "fd/3")] = fmt.Errorf("%s: %w", procPath(42, "fd/3"), unix.EIO)
	delete(a.links, procPath(42, "fd/3"))
	a.contents[procPath(42, "fd/3")] = []byte("x") // listed by Glob, its readlink fails
	b = build(t, "processes", a)
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
		if e := env(t, b, k); e.Status != facts.StatusError || !strings.Contains(e.Reason, "/proc/42/fd/3") {
			t.Errorf("%s = %+v, want error naming the fd link (never kernel on a partial read)", k, e)
		}
	}
}

func TestProcessesDeniedFdTableMakesTheLeavesDenied(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}, [2]int{2049, 99}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil),
		fakeProc{pid: 42, ppid: 1, uid: 1000, name: "other", exe: "/usr/bin/other"})
	a.deniedDirs = map[string]bool{"/proc/42/fd": true}
	b := build(t, "processes", a)
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/proc/42/fd") {
			t.Errorf("%s = %+v, want denied naming /proc/42/fd (an unheld socket is not the kernel's when a table was refused)", k, e)
		}
	}
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusOK {
		t.Errorf("deleted_executables %+v: an fd table is not its input", e)
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["denied"] != 1 {
		t.Errorf("stats %v", s)
	}
}

// S4: a status file cut at the read limit is a failure, never a parse of
// the bytes before the cut (Groups: precedes Threads: and Kthread:, so a cut
// file would read a thread-less leader). The listener leaves and
// deleted_executables carry it, naming the path and the limit.
func TestProcessesCutStatusIsAFailure(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}, [2]int{5432, 9}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil),
		fakeProc{pid: 950, ppid: 1, uid: 113, name: "postgres", exe: "/usr/lib/postgresql/14/bin/postgres", fds: map[int]string{5: "socket:[9]"}})
	a.truncated = map[string]bool{procPath(950, "status"): true}
	b := build(t, "processes", a)
	want := fmt.Sprintf("%s: cut at the %d-byte limit", procPath(950, "status"), procStatusLimit)
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners", "processes.deleted_executables"} {
		if e := env(t, b, k); e.Status != facts.StatusError || e.Reason != want {
			t.Errorf("%s = %+v, want error %q", k, e, want)
		}
	}
	if _, ok := rowsByPid(t, okList(t, b, "processes.list"))[950]; ok {
		t.Errorf("pid 950 is listed from a cut status file")
	}
}

func TestProcessesDeniedExeMakesDeletedExecutablesDenied(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil),
		fakeProc{pid: 42, ppid: 1, uid: 1000, name: "other", exe: "/usr/bin/other"})
	denyLink(a, procPath(42, "exe"))
	b := build(t, "processes", a)
	e := env(t, b, "processes.deleted_executables")
	if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/proc/42/exe") {
		t.Errorf("deleted_executables = %+v, want denied naming /proc/42/exe", e)
	}
	if r := rowsByPid(t, okList(t, b, "processes.list"))[42]; r["exe_read_status"] != "denied" || r["package_status"] != "" {
		t.Errorf("row %v", r)
	}
	// pid 42 holds no listener, so the listener leaves stand.
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusOK {
		t.Errorf("listeners %+v", e)
	}
}

func TestProcessesDeniedNsMntMakesTheLeavesDenied(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil))
	denyLink(a, procPath(812, "ns/mnt"))
	b := build(t, "processes", a)
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/proc/812/ns/mnt") {
			t.Errorf("%s = %+v, want denied naming the ns link", k, e)
		}
	}
	r := rowsByPid(t, okList(t, b, "processes.list"))[812]
	if r["mnt_ns"] != "" || r["ns_read_status"] != "denied" || r["package_status"] != "" {
		t.Errorf("row %v", r)
	}
	// pid 1's namespace unreadable: no process can be classed host.
	a = procHost(tcpTable([2]int{22, 7}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil))
	denyLink(a, procInitMntNS)
	b = build(t, "processes", a)
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, procInitMntNS) {
		t.Errorf("listeners = %+v, want denied naming pid 1's ns link", e)
	}
}

func TestProcessesForeignMountNamespaceIsNotLookedUp(t *testing.T) {
	// The container's sshd sits at a path the host's index owns; it is
	// still foreign_ns, never packaged.
	a := procHost(tcpTable([2]int{2222, 8}), initProc(nil),
		fakeProc{pid: 3000, ppid: 2990, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532999]", fds: map[int]string{3: "socket:[8]"}})
	a.contents[procPath(3000, "mountinfo")] = []byte(overlayMountinfo)
	b := build(t, "processes", a)
	r := rowsByPid(t, okList(t, b, "processes.list"))[3000]
	if r["mnt_ns"] != "foreign" || r["package_status"] != "foreign_ns" || r["package"] != "" {
		t.Errorf("row %v", r)
	}
	unp := okList(t, b, "processes.unpackaged_listeners")
	if len(unp) != 1 || unp[0].(map[string]any)["package_status"] != "foreign_ns" || unp[0].(map[string]any)["port"] != 2222 {
		t.Errorf("unpackaged %v", unp)
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["foreign_ns"] != 1 {
		t.Errorf("stats %v", s)
	}
}

func TestProcessesUnpackagedListenerRows(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}, [2]int{8080, 10}, [2]int{9000, 11}, [2]int{9100, 12}),
		initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}),
		fakeProc{pid: 500, ppid: 1, uid: 1000, name: "app", exe: "/opt/app/bin/app", fds: map[int]string{3: "socket:[10]"}},
		fakeProc{pid: 501, ppid: 500, uid: 1000, name: "app", exe: "/opt/app/bin/app", fds: map[int]string{3: "socket:[10]"}},
		fakeProc{pid: 600, ppid: 1, name: "lxd", exe: "/snap/lxd/1/bin/lxd", fds: map[int]string{3: "socket:[11]"}},
		fakeProc{pid: 700, ppid: 1, name: "old", exe: "/opt/old/old (deleted)", fds: map[int]string{3: "socket:[12]"}},
	)
	b := build(t, "processes", a)
	unp := okList(t, b, "processes.unpackaged_listeners")
	var got []string
	for _, r := range unp {
		m := r.(map[string]any)
		got = append(got, fmt.Sprintf("%s/%v %v %v %v", m["proto"], m["port"], m["pid"], m["package_status"], m["family"]))
		if m["exe"] == "" || m["name"] == "" || m["addr"] != "0.0.0.0" {
			t.Errorf("row %v", m)
		}
	}
	want := []string{"tcp/8080 500 unpackaged v4", "tcp/8080 501 unpackaged v4", "tcp/9000 600 snap v4"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("unpackaged rows\n got %v\nwant %v (a deleted owner is not repeated)", got, want)
	}
	if r := rowsByPid(t, okList(t, b, "processes.list"))[600]; r["package"] != "snap:lxd" {
		t.Errorf("snap row %v", r)
	}
}

func TestProcessesNoPackageDatabaseIsAbsent(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}))
	for p := range maps.Clone(a.contents) {
		if strings.HasPrefix(p, "/var/lib/dpkg/") {
			delete(a.contents, p)
		}
	}
	b := build(t, "processes", a)
	if e := env(t, b, "processes.unpackaged_listeners"); e.Status != facts.StatusAbsent || e.Reason != "no package database" {
		t.Errorf("unpackaged = %+v", e)
	}
	if r := rowsByPid(t, okList(t, b, "processes.list"))[812]; r["package_status"] != "no_index" {
		t.Errorf("row %v", r)
	}
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusOK {
		t.Errorf("listeners %+v", e)
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["index_source"] != "none" {
		t.Errorf("stats %v", s)
	}
}

// Task 1 review item (a): Index.Owner answers from a partly built index, so a
// failed build must be checked before any lookup. The diversions file is
// refused, the build fails, yet the .list that owns sshd was read: sshd must
// read no_index, never packaged — and /opt/app no_index, never unpackaged.
func TestProcessesFailedIndexIsNoIndexNotUnpackaged(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}, [2]int{8080, 10}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}),
		fakeProc{pid: 500, ppid: 1, uid: 1000, name: "app", exe: "/opt/app/bin/app", fds: map[int]string{3: "socket:[10]"}})
	a.fails[pkgindex.DpkgDiversionsPath] = fmt.Errorf("%s: %w", pkgindex.DpkgDiversionsPath, unix.EACCES)
	b := build(t, "processes", a)
	rows := rowsByPid(t, okList(t, b, "processes.list"))
	for _, pid := range []int{1, 812, 500} {
		if rows[pid]["package_status"] != "no_index" || rows[pid]["package"] != "" {
			t.Errorf("pid %d row %v, want no_index", pid, rows[pid])
		}
	}
	e := env(t, b, "processes.unpackaged_listeners")
	if e.Status != facts.StatusDenied || !strings.Contains(e.Reason, pkgindex.DpkgDiversionsPath) {
		t.Errorf("unpackaged = %+v, want the index read's status naming the file", e)
	}
	if st := env(t, b, "processes.stats").Value.(map[string]any); st["index_source"] != "none" {
		t.Errorf("stats %v: a failed build is no index source", st)
	}
	for _, l := range listenerRows(t, b) {
		for _, o := range l["owners"].([]any) {
			if s := o.(map[string]any)["package_status"]; s != "no_index" {
				t.Errorf("owner %v", o)
			}
		}
	}
}

// W-35: a pre-merge .list line (/lib/systemd/systemd-resolved) matches the
// /usr/lib path the kernel reports, through the merged-/usr aliases the
// collector reads.
func TestProcessesJoinsAPreMergeListPath(t *testing.T) {
	resolved := fakeProc{pid: 600, ppid: 1, uid: 101, name: "systemd-resolve", exe: "/usr/lib/systemd/systemd-resolved", fds: map[int]string{12: "socket:[30]"}}
	tcp := []byte(procNetHeader + tcpRow(0, "3500007F", 53, 30, tcpListen))
	a := procHost(tcp, initProc(nil), resolved)
	a.links["/lib"] = "usr/lib"
	b := build(t, "processes", a)
	r := rowsByPid(t, okList(t, b, "processes.list"))[600]
	if r["package"] != "systemd" || r["package_status"] != "packaged" {
		t.Errorf("resolved row %v, want packaged by systemd", r)
	}
	if ls := listenerRows(t, b); len(ls) != 1 || ls[0]["loopback"] != true || ls[0]["addr"] != "127.0.0.53" {
		t.Errorf("listeners %v", ls)
	}
	// Without the alias the same host reads it unpackaged: the alias is
	// what made the match.
	delete(a.links, "/lib")
	b = build(t, "processes", a)
	if r := rowsByPid(t, okList(t, b, "processes.list"))[600]; r["package_status"] != "unpackaged" {
		t.Errorf("without the alias: %v", r)
	}
}

func TestProcessesFdBudgetOverrunIsAnError(t *testing.T) {
	fds := make(map[int]string, procFdCap+1)
	for i := 0; i <= procFdCap; i++ {
		fds[i] = "/dev/null"
	}
	a := procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}),
		fakeProc{pid: 777, ppid: 1, name: "fdhog", exe: "/usr/bin/fdhog", fds: fds})
	old := processesBudget
	processesBudget = time.Hour
	defer func() { processesBudget = old }()
	b := build(t, "processes", a)
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
		if e := env(t, b, k); e.Status != facts.StatusError || !strings.Contains(e.Reason, "pid 777") {
			t.Errorf("%s = %+v, want error naming pid 777", k, e)
		}
	}
}

func TestProcessesMaskedProcIsUnsupported(t *testing.T) {
	a := procHost(nil, initProc(nil))
	delete(a.contents, "/proc/self/net/tcp")
	b := build(t, "processes", a)
	for _, k := range []string{"processes.list", "processes.deleted_executables", "processes.listeners", "processes.unpackaged_listeners", "processes.stats"} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s = %+v, want unsupported", k, e)
		}
	}
	// A /proc that lists no process at all is masked too.
	a = procHost(tcpTable([2]int{22, 7}))
	b = build(t, "processes", a)
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusUnsupported {
		t.Errorf("no pids: %+v", e)
	}
}

func TestProcessesListIsTruncatedPast4096(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil))
	for pid := 3; pid <= procListCap+2; pid++ {
		addProc(a, fakeProc{pid: pid, ppid: 2, name: "kworker"})
	}
	old := processesBudget
	processesBudget = time.Hour
	defer func() { processesBudget = old }()
	b := build(t, "processes", a)
	e := env(t, b, "processes.list")
	if e.Status != facts.StatusOK || !e.Truncated || len(e.Value.([]any)) != procListCap {
		t.Fatalf("list status %s truncated %v rows %d", e.Status, e.Truncated, len(e.Value.([]any)))
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["count"] != procListCap+1 {
		t.Errorf("stats %v: every process is counted", s)
	}
	if e := env(t, b, "processes.deleted_executables"); e.Truncated {
		t.Errorf("the subsets see every process: %+v", e)
	}
}

func TestProcessesBudgetOverrunTruncatesEveryJudgedLeaf(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}))
	old := processesBudget
	processesBudget = -1
	defer func() { processesBudget = old }()
	b := build(t, "processes", a)
	for _, k := range []string{"processes.list", "processes.deleted_executables", "processes.listeners", "processes.unpackaged_listeners"} {
		if e := env(t, b, k); !e.Truncated {
			t.Errorf("%s = %+v, want truncated", k, e)
		}
	}
	// No table was read, so the unheld socket is unmatched, never the
	// kernel's (W-66).
	if ls := listenerRows(t, b); len(ls) != 1 || ls[0]["owner_status"] != "unmatched" {
		t.Errorf("listeners %v", ls)
	}
}

// vanishing serves a status file once: the second read finds the process
// gone, as a process that exits between two reads does.
type vanishing struct {
	*fsAccess
	gone  string
	reads int
}

func (v *vanishing) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	if p == v.gone {
		v.reads++
		if v.reads > 1 {
			return nil, collect.ReadMeta{}, fs.ErrNotExist
		}
	}
	return v.fsAccess.ReadFile(p, limit)
}

// W-42: an exe ENOENT on a user process re-reads status. Gone, or Z/X, is a
// dropped row and stats.vanished; a process still there is exe_read_status
// error and the deleted-executable leaf's error.
func TestProcessesDyingProcessIsVanished(t *testing.T) {
	dying := fakeProc{pid: 66, ppid: 1, name: "dying"} // no exe link: ENOENT
	a := procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}), dying)
	b := build(t, "processes", &vanishing{fsAccess: a, gone: procPath(66, "status")})
	if _, ok := rowsByPid(t, okList(t, b, "processes.list"))[66]; ok {
		t.Error("a process gone under the read left a row")
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["vanished"] != 1 {
		t.Errorf("stats %v", s)
	}
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusOK {
		t.Errorf("deleted_executables %+v", e)
	}

	dead := fakeProc{pid: 66, ppid: 1, name: "dying", state: "X (dead)"}
	b = build(t, "processes", procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}), dead))
	if _, ok := rowsByPid(t, okList(t, b, "processes.list"))[66]; ok {
		t.Error("a dead (X) process left a row")
	}

	b = build(t, "processes", procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}), dying))
	if r := rowsByPid(t, okList(t, b, "processes.list"))[66]; r["exe_read_status"] != "error" {
		t.Errorf("a surviving process with no exe: %v", r)
	}
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusError || !strings.Contains(e.Reason, "/proc/66/exe") {
		t.Errorf("deleted_executables %+v", e)
	}
}

func TestProcessesV6TableFoldsToFamily(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil), sshdProc(map[int]string{3: "socket:[9]"}))
	a.contents["/proc/self/net/tcp6"] = []byte(procNetHeader +
		tcpRow(0, "000080FE00000000FF005450B6AD1DFE", 22, 9, tcpListen))
	b := build(t, "processes", a)
	ls := listenerRows(t, b)
	if len(ls) != 1 || ls[0]["proto"] != "tcp" || ls[0]["family"] != "v6" || ls[0]["link_local"] != true {
		t.Errorf("%v", ls)
	}
}

func TestProcessesBadInodeIsAnError(t *testing.T) {
	tcp := []byte(procNetHeader + strings.Replace(tcpRow(0, "00000000", 22, 7, tcpListen), " 7 1 ", " x 1 ", 1))
	a := procHost(tcp, initProc(nil))
	b := build(t, "processes", a)
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusError || !strings.Contains(e.Reason, "tcp/22") {
		t.Errorf("listeners %+v", e)
	}
}

const (
	hostMountinfo    = "29 1 253:0 / / rw,relatime shared:1 - ext4 /dev/mapper/vg-root rw\n30 29 0:26 / /proc rw,nosuid shared:12 - proc proc rw\n"
	sandboxMountinfo = "612 611 253:0 / / ro,relatime master:1 - ext4 /dev/mapper/vg-root rw\n613 612 0:26 / /proc rw,nosuid - proc proc rw\n640 612 253:0 /tmp/systemd-private-x/tmp /tmp rw,relatime - ext4 /dev/mapper/vg-root rw\n"
	protectMountinfo = "612 611 253:0 / / rw,relatime master:1 - ext4 /dev/mapper/vg-root rw\n615 612 253:0 /usr /usr ro,relatime master:1 - ext4 /dev/mapper/vg-root rw\n"
	bindUsrMountinfo = "612 611 253:0 / / rw,relatime master:1 - ext4 /dev/mapper/vg-root rw\n616 612 253:0 /opt/vendor/usr /usr ro,relatime - ext4 /dev/mapper/vg-root rw\n"
	bindExeMountinfo = "612 611 253:0 / / rw,relatime master:1 - ext4 /dev/mapper/vg-root rw\n617 612 253:0 /tmp/x /usr/sbin/sshd rw,relatime - ext4 /dev/mapper/vg-root rw\n"
	sysextMountinfo  = "612 611 253:0 / / rw,relatime master:1 - ext4 /dev/mapper/vg-root rw\n618 612 0:61 / /usr ro,relatime - overlay overlay ro,lowerdir=/run/extensions/x\n"
	overlayMountinfo = "900 880 0:52 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A\n"
	rootDirMountinfo = "700 699 253:0 /srv/jail / rw,relatime - ext4 /dev/mapper/vg-root rw\n"
)

// W-65: a process in a mount namespace of its own is host only when its
// exe's own mount names the file pid 1 sees at that path. A systemd service
// with PrivateTmp= (the host's / at /) or ProtectSystem= (a read-only bind of
// /usr from the same device) is host and is looked up (the lab's
// systemd-resolved); a bind of another directory over /usr or over the exe,
// an extension overlay on /usr, a container's overlay at /, a root within
// the filesystem (RootDirectory=) or a root link other than / (a debug pod's
// chroot /host) is foreign; an unreadable mountinfo is the row's error (R-3).
func TestProcessesSandboxedServiceSeesTheHostRoot(t *testing.T) {
	tcp := []byte(procNetHeader + tcpRow(0, "3500007F", 53, 30, tcpListen))
	a := procHost(tcp, initProc(nil),
		fakeProc{pid: 600, ppid: 1, uid: 101, name: "systemd-resolve", exe: "/usr/lib/systemd/systemd-resolved", ns: "mnt:[4026532301]", fds: map[int]string{12: "socket:[30]"}},
		fakeProc{pid: 610, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"},
		fakeProc{pid: 620, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532320]"},
		fakeProc{pid: 630, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532330]"},
		fakeProc{pid: 640, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532340]"},
		fakeProc{pid: 3000, ppid: 2990, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026532999]"},
		fakeProc{pid: 3100, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026533000]"},
		fakeProc{pid: 3200, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026533001]"},
		fakeProc{pid: 3300, ppid: 1, name: "sshd", exe: "/usr/sbin/sshd", ns: "mnt:[4026533002]", root: "/host"},
	)
	a.links["/lib"] = "usr/lib"
	for pid, mi := range map[int]string{1: hostMountinfo, 600: sandboxMountinfo, 610: protectMountinfo, 620: bindUsrMountinfo,
		630: bindExeMountinfo, 640: sysextMountinfo, 3000: overlayMountinfo, 3100: rootDirMountinfo, 3300: sandboxMountinfo} {
		a.contents[procPath(pid, "mountinfo")] = []byte(mi)
	}
	b := build(t, "processes", a)
	rows := rowsByPid(t, okList(t, b, "processes.list"))
	if r := rows[600]; r["mnt_ns"] != "host" || r["package_status"] != "packaged" || r["package"] != "systemd" {
		t.Errorf("PrivateTmp resolved %v, want host and packaged by systemd", r)
	}
	if r := rows[610]; r["mnt_ns"] != "host" || r["package"] != "openssh-server" {
		t.Errorf("ProtectSystem shape %v, want host and packaged", r)
	}
	for _, pid := range []int{620, 630, 640, 3000, 3100, 3300} {
		if r := rows[pid]; r["mnt_ns"] != "foreign" || r["package_status"] != "foreign_ns" {
			t.Errorf("pid %d %v, want foreign", pid, r)
		}
	}
	if r := rows[3200]; r["mnt_ns"] != "" || r["ns_read_status"] != "error" || r["package_status"] != "" {
		t.Errorf("unreadable mountinfo %v, want ns_read_status error", r)
	}
	if got := okList(t, b, "processes.unpackaged_listeners"); len(got) != 0 {
		t.Errorf("unpackaged %v", got)
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["foreign_ns"] != 6 {
		t.Errorf("stats %v", s)
	}
	// Without pid 1's mountinfo nothing can be matched to it: the row's
	// error and the owner's, never a quiet foreign (R-3).
	delete(a.contents, procPath(1, "mountinfo"))
	b = build(t, "processes", a)
	if r := rowsByPid(t, okList(t, b, "processes.list"))[600]; r["mnt_ns"] != "" || r["ns_read_status"] != "error" {
		t.Errorf("no host mountinfo: %v", r)
	}
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusError || !strings.Contains(e.Reason, "/proc/1/mountinfo") {
		t.Errorf("listeners %+v, want error naming pid 1's mountinfo", e)
	}
}

// M-3: one namespace's mountinfo is read once, through its first process.
func TestProcessesReadsOneMountinfoPerNamespace(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil),
		fakeProc{pid: 610, ppid: 1, name: "a", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"},
		fakeProc{pid: 611, ppid: 610, name: "b", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"})
	a.contents[procPath(1, "mountinfo")] = []byte(hostMountinfo)
	a.contents[procPath(610, "mountinfo")] = []byte(protectMountinfo)
	a.contents[procPath(611, "mountinfo")] = []byte(protectMountinfo)
	b := build(t, "processes", a)
	if r := rowsByPid(t, okList(t, b, "processes.list"))[611]; r["mnt_ns"] != "host" {
		t.Errorf("row %v", r)
	}
	n := 0
	for _, p := range a.reads {
		if strings.HasSuffix(p, "/mountinfo") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d mountinfo reads, want 2 (pid 1 and the namespace once): %v", n, a.reads)
	}
}

// W-64: a snap is named by its /snap/<name>/<rev>/ path in the namespace
// snap-confine gave it; the row keeps mnt_ns foreign and the foreign count.
func TestProcessesForeignNamespaceSnapIsSnap(t *testing.T) {
	a := procHost(tcpTable([2]int{8443, 40}), initProc(nil),
		fakeProc{pid: 700, ppid: 1, name: "lxd", exe: "/snap/lxd/24322/bin/lxd", ns: "mnt:[4026532700]", fds: map[int]string{3: "socket:[40]"}})
	a.contents[procPath(700, "mountinfo")] = []byte(overlayMountinfo)
	b := build(t, "processes", a)
	r := rowsByPid(t, okList(t, b, "processes.list"))[700]
	if r["mnt_ns"] != "foreign" || r["package_status"] != "snap" || r["package"] != "snap:lxd" {
		t.Errorf("row %v", r)
	}
	unp := okList(t, b, "processes.unpackaged_listeners")
	if len(unp) != 1 || unp[0].(map[string]any)["package_status"] != "snap" {
		t.Errorf("unpackaged %v", unp)
	}
	if s := env(t, b, "processes.stats").Value.(map[string]any); s["foreign_ns"] != 1 {
		t.Errorf("stats %v", s)
	}
}

// M-1: a socket held by 65 processes shows 64 owners and owners_count 65,
// and the 65th, the only unpackaged one, is still judged.
func TestProcessesSixtyFifthOwnerIsJudged(t *testing.T) {
	a := procHost(tcpTable([2]int{80, 50}), initProc(nil))
	for i := 0; i < 65; i++ {
		exe := "/usr/sbin/sshd"
		if i == 64 {
			exe = "/opt/w/worker"
		}
		addProc(a, fakeProc{pid: 1000 + i, ppid: 1, name: "w", exe: exe, fds: map[int]string{3: "socket:[50]"}})
	}
	b := build(t, "processes", a)
	ls := listenerRows(t, b)
	if len(ls) != 1 || len(ls[0]["owners"].([]any)) != 64 || ls[0]["owners_count"] != 65 {
		t.Fatalf("listeners %v", ls)
	}
	unp := okList(t, b, "processes.unpackaged_listeners")
	if len(unp) != 1 || unp[0].(map[string]any)["pid"] != 1064 {
		t.Errorf("unpackaged %v, want the 65th owner", unp)
	}
}

// flakyExe answers ENOENT the first time a process's exe is read, as a link
// read in a race does.
type flakyExe struct {
	*fsAccess
	exe   string
	reads int
}

func (f *flakyExe) Readlink(p string) (string, error) {
	if p == f.exe {
		f.reads++
		if f.reads == 1 {
			return "", fs.ErrNotExist
		}
	}
	return f.fsAccess.Readlink(p)
}

// M-4: one ENOENT on a live process's exe is read again before it is filed
// as an error.
func TestProcessesExeIsReadAgainAfterOneENOENT(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil), fakeProc{pid: 66, ppid: 1, name: "x", exe: "/usr/sbin/sshd"})
	b := build(t, "processes", &flakyExe{fsAccess: a, exe: procPath(66, "exe")})
	if r := rowsByPid(t, okList(t, b, "processes.list"))[66]; r["exe_read_status"] != "ok" || r["exe"] != "/usr/sbin/sshd" {
		t.Errorf("row %v", r)
	}
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusOK {
		t.Errorf("deleted_executables %+v", e)
	}
}

// M-6: a cut socket table marks the listeners answer truncated, but an
// absent index envelope keeps its own cause.
func TestProcessesTruncationGoesOnAnswersOnly(t *testing.T) {
	a := procHost(tcpTable([2]int{22, 7}), initProc(nil), sshdProc(map[int]string{3: "socket:[7]"}))
	for p := range maps.Clone(a.contents) {
		if strings.HasPrefix(p, "/var/lib/dpkg/") {
			delete(a.contents, p)
		}
	}
	a.truncated = map[string]bool{"/proc/self/net/tcp": true}
	b := build(t, "processes", a)
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusOK || !e.Truncated {
		t.Errorf("listeners %+v, want ok and truncated", e)
	}
	if e := env(t, b, "processes.unpackaged_listeners"); e.Status != facts.StatusAbsent || e.Truncated {
		t.Errorf("unpackaged %+v, want absent without the truncation", e)
	}
}

// W-67: inside a container the pid view may be partial, so a socket no
// visible process holds is unmatched and both leaves absent naming it; on
// the host (none, or an Env the os collector could not fill) the same
// reading is the kernel's.
func TestProcessesUnheldSocketInsideAContainerIsAbsent(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, container := range []string{"docker", "none", ""} {
		a := procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil), kthreadd)
		b := collect.NewBuilder(reg)
		b.Header().Env.Container = container
		b = buildOn(t, "processes", a, b)
		if container != "docker" {
			if ls := listenerRows(t, b); ls[1]["owner_status"] != "kernel" {
				t.Errorf("container %q: %v", container, ls[1])
			}
			continue
		}
		for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
			e := env(t, b, k)
			if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "tcp/2049") || !strings.Contains(e.Reason, "docker container") {
				t.Errorf("%s = %+v, want absent naming tcp/2049 and the container", k, e)
			}
		}
	}
}

// W-68: a zombie leader whose live threads hold the socket: its own fd/ is
// empty, the socket is found through its tasks, and the owner is the leader.
func TestProcessesZombieLeaderThreadsHoldTheSocket(t *testing.T) {
	leader := fakeProc{pid: 950, ppid: 1, name: "srv", state: "Z (zombie)", threads: 2,
		tasks: map[string]string{"951/3": "socket:[60]", "951/4": "/dev/null"}}
	b := build(t, "processes", procHost(tcpTable([2]int{9090, 60}), initProc(nil), kthreadd, leader))
	// The owner is found through the tasks, and it cannot be judged: its
	// exe and namespace are unreadable, so both leaves are absent naming it
	// (W-70) — never a pass on an unjudged daemon.
	for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "owner 950 is a zombie leader") {
			t.Errorf("%s = %+v, want absent naming the zombie leader 950", k, e)
		}
	}
	// With Threads: 1 the tasks are not consulted, and the socket nobody
	// else holds is the kernel's.
	leader.threads = 1
	b = build(t, "processes", procHost(tcpTable([2]int{9090, 60}), initProc(nil), kthreadd, leader))
	if ls := listenerRows(t, b); ls[0]["owner_status"] != "kernel" {
		t.Errorf("a one-thread zombie: %v", ls)
	}
}

// W-69: a run that cannot see pid 1 or any kernel thread (hidepid=2, or a
// pid namespace the os collector does not call a container) refuses no fd
// table, yet the holder of a socket may be out of sight: an unheld socket is
// unmatched and both leaves absent naming it and the partial view. The
// stock view (pid 1, kthreadd, a service) reads the same socket kernel.
func TestProcessesHiddenPidViewIsAbsent(t *testing.T) {
	for name, procs := range map[string][]fakeProc{
		"no pid 1, no kernel thread": {sshdProc(map[int]string{3: "socket:[7]"})},
		"pid 1, no kernel thread":    {sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil)},
		"no pid 1":                   {sshdProc(map[int]string{3: "socket:[7]"}), kthreadd},
	} {
		b := build(t, "processes", procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), procs...))
		for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
			e := env(t, b, k)
			if e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "tcp/2049") || !strings.Contains(e.Reason, "pid 1 or the kernel threads are not visible") {
				t.Errorf("%s: %s = %+v, want absent naming tcp/2049 and the partial view", name, k, e)
			}
		}
	}
	a := procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil), kthreadd)
	delete(a.contents, procPath(1, "mountinfo"))
	b := build(t, "processes", a)
	if e := env(t, b, "processes.listeners"); e.Status != facts.StatusAbsent {
		t.Errorf("pid 1's mountinfo unread: %+v, want absent", e)
	}
	b = build(t, "processes", procHost(tcpTable([2]int{22, 7}, [2]int{2049, 363387305}), sshdProc(map[int]string{3: "socket:[7]"}), initProc(nil), kthreadd))
	if ls := listenerRows(t, b); ls[1]["owner_status"] != "kernel" {
		t.Errorf("stock view: %v", ls[1])
	}
}

// R-4: of two mounts stacked on /usr, the exe lies on the topmost — the one
// no other is mounted on — whatever order mountinfo lists them in.
func TestExeMountKeyTakesTheTopmostStackedMount(t *testing.T) {
	under := mountRow{id: 20, parent: 1, dev: "253:0", root: "/usr", mountPoint: "/usr", fstype: "ext4", source: "/dev/vda1"}
	over := mountRow{id: 30, parent: 20, dev: "0:61", root: "/", mountPoint: "/usr", fstype: "overlay", source: "overlay"}
	root := mountRow{id: 1, parent: 0, dev: "253:0", root: "/", mountPoint: "/", fstype: "ext4", source: "/dev/vda1"}
	for _, rows := range [][]mountRow{{root, under, over}, {root, over, under}} {
		k, ok := exeMountKey(rows, "/usr/sbin/sshd")
		if !ok || k != "0:61 /sbin/sshd overlay overlay" {
			t.Errorf("key %q, want the overlay's", k)
		}
	}
}

// slowDeniedExe refuses one exe and spends the enumeration budget while
// doing so, so the run is cut after it. The collector runs on the test's
// goroutine, so the budget is set here without a race and without a clock
// (W-71).
type slowDeniedExe struct {
	*fsAccess
	exe string
}

func (d *slowDeniedExe) Readlink(p string) (string, error) {
	if p == d.exe {
		processesBudget = -1
		return "", fmt.Errorf("%s: %w", p, unix.EACCES)
	}
	return d.fsAccess.Readlink(p)
}

// R-5: a deleted-executables failure keeps its own cause when the budget
// also ran out: denied, not denied-and-truncated.
func TestProcessesDeletedFailureIsNotMarkedTruncated(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil), fakeProc{pid: 42, ppid: 1, name: "x", exe: "/usr/bin/x"}, sshdProc(nil))
	old := processesBudget
	processesBudget = time.Hour
	defer func() { processesBudget = old }()
	b := build(t, "processes", &slowDeniedExe{fsAccess: a, exe: procPath(42, "exe")})
	if e := env(t, b, "processes.list"); !e.Truncated {
		t.Fatalf("list %+v: the budget did not run out", e)
	}
	if e := env(t, b, "processes.deleted_executables"); e.Status != facts.StatusDenied || e.Truncated {
		t.Errorf("deleted_executables %+v, want denied without the truncation", e)
	}
}

// R-3: a failed mountinfo read is that process's error and is not memoised:
// the next process of the namespace reads the table and is judged.
func TestProcessesFailedMountinfoIsNotMemoised(t *testing.T) {
	a := procHost(tcpTable(), initProc(nil),
		fakeProc{pid: 610, ppid: 1, name: "a", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"},
		fakeProc{pid: 611, ppid: 610, name: "b", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"})
	a.contents[procPath(611, "mountinfo")] = []byte(protectMountinfo)
	b := build(t, "processes", a)
	rows := rowsByPid(t, okList(t, b, "processes.list"))
	if rows[610]["ns_read_status"] != "error" || rows[611]["mnt_ns"] != "host" || rows[611]["ns_read_status"] != "ok" {
		t.Errorf("610 %v\n611 %v", rows[610], rows[611])
	}
}

// F-2: a mount whose parent chain passes through a mount hidden at its own
// point is hidden too: the /usr/lib child left under a later bind over /usr
// never wins the longest prefix, whatever order the unrelated rows take.
// Of the two mounts on /usr the later listed is the topmost when neither is
// mounted on the other; when the bind is mounted on the old /usr (the shape
// a plain mount --bind makes), the order does not matter at all.
func TestExeMountKeyIgnoresAMountHiddenByAnOvermount(t *testing.T) {
	root := mountRow{id: 1, parent: 0, dev: "253:0", root: "/", mountPoint: "/", fstype: "ext4", source: "/dev/vda1"}
	usr := mountRow{id: 20, parent: 1, dev: "253:0", root: "/usr", mountPoint: "/usr", fstype: "ext4", source: "/dev/vda1"}
	lib := mountRow{id: 25, parent: 20, dev: "253:1", root: "/", mountPoint: "/usr/lib", fstype: "ext4", source: "/dev/vdb1"}
	bind := mountRow{id: 30, parent: 1, dev: "253:2", root: "/vendor/usr", mountPoint: "/usr", fstype: "ext4", source: "/dev/vdc1"}
	const want = "253:2 /vendor/usr/lib/x ext4 /dev/vdc1"
	for _, rows := range [][]mountRow{{root, usr, lib, bind}, {lib, usr, bind, root}} {
		if k, ok := exeMountKey(rows, "/usr/lib/x"); !ok || k != want {
			t.Errorf("rows %v: key %q, want the bind's", rows, k)
		}
	}
	onUsr := bind
	onUsr.parent = 20
	for _, rows := range [][]mountRow{{root, usr, lib, onUsr}, {onUsr, lib, usr, root}} {
		if k, ok := exeMountKey(rows, "/usr/lib/x"); !ok || k != want {
			t.Errorf("rows %v: key %q, want the bind's", rows, k)
		}
	}
	// Without the bind the child is visible and is the exe's mount.
	if k, ok := exeMountKey([]mountRow{lib, usr, root}, "/usr/lib/x"); !ok || k != "253:1 /x ext4 /dev/vdb1" {
		t.Errorf("key %q, want the /usr/lib mount's", k)
	}
}

func mountinfoReads(a *fsAccess, p string) int {
	n := 0
	for _, r := range a.reads {
		if r == p {
			n++
		}
	}
	return n
}

// F-3: a failure of pid 1's table and a table cut at the limit are read once
// per namespace, not once per process; a process that vanished under the
// read (ENOENT, ESRCH) leaves the table to the namespace's next process:
// pid 1's is then read for each of the three and once more for the
// pid-view check (W-69).
func TestProcessesFailedMountinfoIsMemoisedUnlessVanished(t *testing.T) {
	procs := []fakeProc{initProc(nil), kthreadd,
		{pid: 610, ppid: 1, name: "a", exe: "/usr/sbin/sshd", ns: "mnt:[4026532310]"},
		{pid: 620, ppid: 1, name: "b", exe: "/usr/sbin/sshd", ns: "mnt:[4026532320]"},
		{pid: 621, ppid: 620, name: "c", exe: "/usr/sbin/sshd", ns: "mnt:[4026532320]"}}
	host := procPath(1, "mountinfo")
	for _, tc := range []struct {
		name  string
		err   error
		reads int
	}{
		{"pid 1 EIO", unix.EIO, 1},
		{"pid 1 EACCES", unix.EACCES, 1},
		{"pid 1 ESRCH", unix.ESRCH, 4},
		{"pid 1 ENOENT", fs.ErrNotExist, 4},
	} {
		a := procHost(tcpTable(), procs...)
		delete(a.contents, host)
		a.fails[host] = fmt.Errorf("%s: %w", host, tc.err)
		b := build(t, "processes", a)
		if n := mountinfoReads(a, host); n != tc.reads {
			t.Errorf("%s: pid 1's table read %d times, want %d", tc.name, n, tc.reads)
		}
		rows := rowsByPid(t, okList(t, b, "processes.list"))
		for _, pid := range []int{610, 620, 621} {
			if r := rows[pid]; r["mnt_ns"] != "" || r["ns_read_status"] == "ok" {
				t.Errorf("%s: pid %d %v, want the table's failure", tc.name, pid, r)
			}
		}
	}

	// A pid 1 table with no row the parser takes is every process's too.
	a := procHost(tcpTable(), procs...)
	a.contents[host] = []byte("garbage\n")
	b := build(t, "processes", a)
	if n := mountinfoReads(a, host); n != 1 {
		t.Errorf("unparsable: pid 1's table read %d times, want 1", n)
	}
	if r := rowsByPid(t, okList(t, b, "processes.list"))[621]; r["mnt_ns"] != "" || r["ns_read_status"] != "error" {
		t.Errorf("unparsable: pid 621 %v, want error", r)
	}

	// A cut table of a namespace of its own: read once, through its first
	// process, and the failure is every process's of it.
	a = procHost(tcpTable(), procs...)
	for _, pid := range []int{610, 620, 621} {
		a.contents[procPath(pid, "mountinfo")] = []byte(protectMountinfo)
	}
	a.truncated = map[string]bool{procPath(620, "mountinfo"): true}
	b = build(t, "processes", a)
	if n, m := mountinfoReads(a, procPath(620, "mountinfo")), mountinfoReads(a, procPath(621, "mountinfo")); n != 1 || m != 0 {
		t.Errorf("cut table read %d times through 620 and %d through 621, want 1 and 0", n, m)
	}
	rows := rowsByPid(t, okList(t, b, "processes.list"))
	for _, pid := range []int{620, 621} {
		if r := rows[pid]; r["mnt_ns"] != "" || r["ns_read_status"] != "error" {
			t.Errorf("pid %d %v, want error", pid, r)
		}
	}
	if r := rows[610]; r["mnt_ns"] != "host" {
		t.Errorf("pid 610 %v, want host", r)
	}
}

// F-4, F-5: every way a namespace of its own cannot be matched to pid 1's is
// the row's ns_read_status and the owner's failure on both listener leaves,
// never a quiet foreign: a table cut at the limit (pid 1's or the process's),
// a root link that cannot be read, a table with no row under the exe, and an
// exe that could not be read.
func TestProcessesUnmatchedNamespaceIsTheOwnersFailure(t *testing.T) {
	const pid = 600
	for _, tc := range []struct {
		name, status, reason string
		edit                 func(a *fsAccess)
	}{
		{"pid 1's table cut", "error", "/proc/1/mountinfo: cut at", func(a *fsAccess) {
			a.truncated = map[string]bool{procPath(1, "mountinfo"): true}
		}},
		{"own table cut", "error", "/proc/600/mountinfo: cut at", func(a *fsAccess) {
			a.truncated = map[string]bool{procPath(pid, "mountinfo"): true}
		}},
		{"root link denied", "denied", "/proc/600/root", func(a *fsAccess) { denyLink(a, procPath(pid, "root")) }},
		{"root link EIO", "error", "/proc/600/root", func(a *fsAccess) {
			delete(a.links, procPath(pid, "root"))
			a.fails[procPath(pid, "root")] = fmt.Errorf("%s: %w", procPath(pid, "root"), unix.EIO)
		}},
		{"no row under the exe", "error", "no mountinfo row of pid 600", func(a *fsAccess) {
			a.contents[procPath(pid, "mountinfo")] = []byte("613 612 0:26 / /proc rw,nosuid - proc proc rw\n")
		}},
		{"exe denied", "denied", "/proc/600/exe", func(a *fsAccess) { denyLink(a, procPath(pid, "exe")) }},
		{"exe EIO", "error", "/proc/600/exe", func(a *fsAccess) {
			delete(a.links, procPath(pid, "exe"))
			a.fails[procPath(pid, "exe")] = fmt.Errorf("%s: %w", procPath(pid, "exe"), unix.EIO)
		}},
	} {
		a := procHost(tcpTable([2]int{53, 30}), initProc(nil), kthreadd,
			fakeProc{pid: pid, ppid: 1, uid: 101, name: "systemd-resolve", exe: "/usr/lib/systemd/systemd-resolved", ns: "mnt:[4026532301]", fds: map[int]string{12: "socket:[30]"}})
		a.contents[procPath(pid, "mountinfo")] = []byte(sandboxMountinfo)
		tc.edit(a)
		b := build(t, "processes", a)
		r := rowsByPid(t, okList(t, b, "processes.list"))[pid]
		if r["mnt_ns"] != "" || r["ns_read_status"] != tc.status {
			t.Errorf("%s: row %v, want mnt_ns \"\" and ns_read_status %s", tc.name, r, tc.status)
		}
		for _, k := range []string{"processes.listeners", "processes.unpackaged_listeners"} {
			if e := env(t, b, k); string(e.Status) != tc.status || !strings.Contains(e.Reason, tc.reason) {
				t.Errorf("%s: %s = %+v, want %s naming %q", tc.name, k, e, tc.status, tc.reason)
			}
		}
		if s := env(t, b, "processes.stats").Value.(map[string]any); s["foreign_ns"] != 0 {
			t.Errorf("%s: stats %v, want no foreign process", tc.name, s)
		}
	}
}
