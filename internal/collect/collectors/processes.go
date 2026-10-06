//go:build linux

package collectors

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/pkgindex"
)

// The processes collector (spec P-1) reads every process from /proc, every
// listening socket's owners through the /proc/<pid>/fd links, and the
// package each executable came from through internal/pkgindex. It reads as
// much as it may (X-3): a process whose exe or fd table the run cannot read
// is a row that says so, and a judged leaf that would have to omit such a
// row carries that read's status instead of the readable subset (W-3).
//
// exe, fd/* and ns/mnt are magic links: they are read with Readlink alone,
// which opens the parent directory without following and reads the link's
// text — the target is never opened (W-2).

// The budgets of W-7 and spec P-1.
const (
	procListCap      = 4096
	procOwnersCap    = 64
	procFdCap        = 65536
	procListenersCap = 2000
	procStatusLimit  = 64 << 10
)

// processesBudget bounds the enumeration (W-7). A variable so a test can
// drive the overrun; nothing else assigns it.
var processesBudget = 5 * time.Second

// processesIndexTimeout bounds the rpm query this collector runs: a shallow
// collect must not wait the walk's two minutes for it (X-4).
const processesIndexTimeout = 30 * time.Second

const (
	// procTaskFdGlob licenses a zombie leader's task fd tables (W-68). The
	// task segment is * rather than [0-9]*: the guard matches the pattern
	// handed to Glob, /proc/<pid>/task/*/fd/*, against the declaration, and
	// a literal * in that pattern is not a digit.
	procTaskFdGlob = "/proc/[0-9]*/task/*/fd/*"
	procStatusGlob = "/proc/[0-9]*/status"
	procInitMntNS  = "/proc/1/ns/mnt"
)

var processesCollector = collect.Collector{
	Name: "processes",
	Declare: collect.Declaration{
		Reads:    processesReads(),
		Commands: []collect.Command{pkgindex.RPMCommand},
		// The exposure derivation reads the firewall's facts; the firewall
		// collector sorts before this one.
		Facts: []string{"firewall.*"},
		Needs: "none",
	},
	Run: runProcesses,
}

// processesReads is the declaration: the per-process files and links, the
// merged-/usr aliases the index canonicalises through (W-35), the socket
// tables, and the package databases.
func processesReads() []string {
	out := []string{
		procStatusGlob,
		"/proc/[0-9]*/cmdline",
		"/proc/[0-9]*/exe",
		"/proc/[0-9]*/fd/*",
		procTaskFdGlob,
		"/proc/[0-9]*/ns/mnt",
		"/proc/[0-9]*/mountinfo",
		"/proc/[0-9]*/root",
		procInitMntNS,
		procBindV6Only, procDisableV6All, procDisableV6Default,
	}
	out = append(out, usrAliases...)
	out = append(out, procNetPaths()...)
	out = append(out, pkgindex.DpkgReads...)
	return append(out, pkgindex.RPMReads...)
}

// Process kinds (W-7).
const (
	kindKernel = "kernel"
	kindZombie = "zombie"
	kindUser   = "user"
)

// procRow is one process as read.
type procRow struct {
	pid, ppid, uid int
	name, cmd, exe string
	exeDeleted     bool
	exeStatus      string // ok | denied | error; "" on a kernel thread or a zombie, which have no executable
	kind           string
	mntNS          string // host | foreign | "" when not read
	nsStatus       string // ok | denied | error; "" on a kernel thread or a zombie
	pkg, pkgStatus string
	threads        int // the status Threads count (W-68)
}

func (r procRow) record() map[string]any {
	return map[string]any{
		"pid": r.pid, "ppid": r.ppid, "uid": r.uid, "name": r.name, "cmd": r.cmd,
		"exe": r.exe, "exe_deleted": r.exeDeleted, "exe_read_status": r.exeStatus,
		"kind": r.kind, "mnt_ns": r.mntNS, "ns_read_status": r.nsStatus,
		"package": r.pkg, "package_status": r.pkgStatus,
	}
}

func (r procRow) owner() owner {
	return owner{Pid: r.pid, Uid: r.uid, Name: r.name, Exe: r.exe, ExeDeleted: r.exeDeleted,
		MntNS: r.mntNS, Package: r.pkg, PackageStatus: r.pkgStatus}
}

// failure is the first read failure of one class, kept as the envelope the
// leaves it reaches carry.
type failure struct{ env *facts.Envelope }

func (f *failure) set(e facts.Envelope) {
	if f.env == nil {
		f.env = &e
	}
}

// readFailure classifies a read error with the path in the reason (C3).
func readFailure(p string, err error) facts.Envelope {
	e := collect.FromReadError(err, collect.ReadMeta{})
	if e.Status == facts.StatusAbsent {
		// A file a process had a moment ago is not an absence the leaf may
		// read as "nothing there".
		e = collect.ErrorEnv(err.Error())
	}
	if !strings.Contains(e.Reason, p) {
		e.Reason = p + ": " + e.Reason
	}
	return e
}

// procScan is one enumeration's state.
type procScan struct {
	a       collect.Access
	rows    map[int]*procRow
	hostNS  string
	hostErr *facts.Envelope // pid 1's ns/mnt could not be read

	// mounts memoises one parsed mountinfo per mount namespace (the ns/mnt
	// link text): every process of a namespace sees the same table (W-65).
	mounts map[string]nsMounts

	// wanted are the listening sockets' inodes; holders maps each to the
	// pids whose fd table holds it.
	wanted  map[int]bool
	holders map[int][]int

	statusFail failure // a status file that exists and cannot be read
	exeFail    failure // a user process's exe could not be read
	fdDenied   failure // an fd table (or a link in it) refused
	fdError    failure // an fd table failed otherwise
	fdOverrun  failure // an fd table past procFdCap
	ownerFail  map[int]facts.Envelope

	budgetHit bool
	// container is the run header's Env.Container: inside one, the pid
	// namespace may hide the processes holding a host socket (W-67).
	container                                           string
	kernel, zombies, foreign, denied, vanished, fdReads int
}

func runProcesses(ctx context.Context, a collect.Access, b *collect.Builder) error {
	start := time.Now()
	keys := []string{"processes.list", "processes.deleted_executables", "processes.listeners", "processes.unpackaged_listeners", "processes.stats"}
	setAll := func(e facts.Envelope) {
		for _, k := range keys {
			b.Set(k, e)
		}
		writeExposure(a, b, nil, e, false)
	}

	socks, sockErr := listeningSockets(a)
	if errors.Is(sockErr, ErrProcfsMasked) {
		setAll(socketReadEnvelope(sockErr))
		return nil
	}
	statuses, err := a.Glob(procStatusGlob)
	if err != nil {
		setAll(readFailure("/proc", err))
		return nil
	}
	if len(statuses) == 0 {
		// This process is itself a process: a /proc that lists none is
		// masked, not a host with nothing running.
		setAll(collect.Unsupported("procfs lists no process under /proc"))
		return nil
	}

	s := &procScan{a: a, rows: map[int]*procRow{}, wanted: map[int]bool{}, holders: map[int][]int{}, ownerFail: map[int]facts.Envelope{}, mounts: map[string]nsMounts{}, container: b.Header().Env.Container}
	var listeners []listener
	inodeBad := ""
	if sockErr == nil {
		listeners, inodeBad = foldListeners(socks.list)
		for _, l := range listeners {
			if l.Inode > 0 {
				s.wanted[l.Inode] = true
			}
		}
	}
	if t, err := a.Readlink(procInitMntNS); err == nil {
		s.hostNS = t
	} else {
		e := readFailure(procInitMntNS, err)
		s.hostErr = &e
	}

	pids := pidsOf(statuses)
	for _, pid := range pids {
		if time.Since(start) > processesBudget {
			s.budgetHit = true
			break
		}
		s.scan(pid)
	}

	// The index is asked about the executables of host processes only; a
	// foreign process's exe is a path in another root (spec P-1).
	cands := map[string]bool{}
	for _, r := range s.rows {
		if r.kind == kindUser && r.exeStatus == "ok" && r.mntNS == nsHost {
			cands[r.exe] = true
		}
	}
	idxStart := time.Now()
	ix, idxTrunc, idxFail := pkgindex.Build(ctx, a, cands, pkgindex.Options{USRMerged: readUsrMerged(a), RPMTimeout: processesIndexTimeout})
	idxMs := time.Since(idxStart).Milliseconds()
	lookup := ix
	idxSource := string(ix.Family)
	if idxFail != nil {
		idxSource = string(pkgindex.FamilyNone)
		// A partly built index answers Owner from what it read; a failed
		// build must never make a path unpackaged, so it is not consulted.
		lookup = pkgindex.Index{}
	}
	for _, r := range s.rows {
		// A process whose exe or namespace was not read has no answer: its
		// row says which read failed, and the leaves that would judge it
		// carry that read's status.
		if r.kind != kindUser || r.exeStatus != "ok" || r.nsStatus != "ok" {
			continue
		}
		r.pkg, r.pkgStatus = packageStatusFor(r.exe, r.mntNS, lookup)
	}

	ordered := make([]*procRow, 0, len(s.rows))
	for _, r := range s.rows {
		ordered = append(ordered, r)
	}
	slices.SortFunc(ordered, func(x, y *procRow) int { return cmp.Compare(x.pid, y.pid) })

	src := &facts.Source{Kind: "proc", Path: "/proc"}
	b.Set("processes.list", s.listEnv(ordered, src))
	b.Set("processes.deleted_executables", s.deletedEnv(ordered, src))

	var lst, unp facts.Envelope
	if sockErr != nil {
		lst = socketReadEnvelope(sockErr)
		unp = lst
	} else {
		lst, unp = s.listenerEnvs(listeners, inodeBad, socks, ix, idxFail)
		// The cut goes on an answer only: a denied or absent envelope keeps
		// its own cause (M-6).
		trunc := socks.truncated || idxTrunc || s.budgetHit
		if lst.Status == facts.StatusOK {
			lst.Truncated = lst.Truncated || trunc
		}
		if unp.Status == facts.StatusOK {
			unp.Truncated = unp.Truncated || trunc
		}
	}
	b.Set("processes.listeners", lst)
	b.Set("processes.unpackaged_listeners", unp)
	writeExposure(a, b, listeners, lst, socks.v6)

	stats := map[string]any{
		"count": len(s.rows), "kernel_threads": s.kernel, "zombies": s.zombies, "foreign_ns": s.foreign,
		"denied": s.denied, "vanished": s.vanished, "fd_reads": s.fdReads,
		"index_source": idxSource, "index_ms": idxMs, "elapsed_ms": time.Since(start).Milliseconds(),
	}
	b.Set("processes.stats", collect.OK(stats, src))
	return nil
}

// pidsOf turns the status glob's matches into pids, ascending. A name that
// is not all digits (the glob's [0-9]* admits "1a") is not a process.
func pidsOf(statuses []string) []int {
	var out []int
	for _, p := range statuses {
		dir := path.Base(path.Dir(p))
		n, err := strconv.Atoi(dir)
		if err != nil || n <= 0 || strconv.Itoa(n) != dir {
			continue
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func procPath(pid int, rest string) string { return "/proc/" + strconv.Itoa(pid) + "/" + rest }

// readStatus reads and parses one status file. gone reports a process that
// is not there any more.
func (s *procScan) readStatus(pid int) (st procStatus, gone bool, fail *facts.Envelope) {
	p := procPath(pid, "status")
	data, _, err := s.a.ReadFile(p, procStatusLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return procStatus{}, true, nil
		}
		e := readFailure(p, err)
		return procStatus{}, false, &e
	}
	st, err = parseProcStatus(data)
	if err != nil {
		e := collect.ErrorEnv(p + ": " + err.Error())
		return procStatus{}, false, &e
	}
	return st, false, nil
}

// scan reads one process and, for a user process or a zombie, its fd table.
func (s *procScan) scan(pid int) {
	st, gone, fail := s.readStatus(pid)
	switch {
	case gone:
		s.vanished++
		return
	case fail != nil:
		if fail.Status == facts.StatusDenied {
			s.denied++
		}
		s.statusFail.set(*fail)
		return
	}
	r := &procRow{pid: pid, ppid: st.PPid, uid: st.Uid, name: st.Name, threads: st.Threads}
	switch {
	case st.HasKthread && st.Kthread, !st.HasKthread && (pid == 2 || st.PPid == 2):
		r.kind = kindKernel
		s.kernel++
		s.rows[pid] = r
		return
	case st.State == "Z":
		r.kind = kindZombie
		s.zombies++
	default:
		r.kind = kindUser
		if !s.readExe(r) {
			s.vanished++
			return
		}
		if data, _, err := s.a.ReadFileBinary(procPath(pid, "cmdline"), cmdlineCap); err == nil {
			r.cmd = parseCmdline(data)
		}
		s.readNS(r)
	}
	s.rows[pid] = r
	if !s.readFds(r) {
		delete(s.rows, pid)
		if r.kind == kindZombie {
			s.zombies--
		}
		if r.mntNS == nsForeign {
			s.foreign--
		}
		s.vanished++
	}
}

// readExe reads a user process's exe link. It returns false when the
// process died under the read: exe ENOENT and a re-read status that is gone
// or Z/X (W-42).
func (s *procScan) readExe(r *procRow) bool {
	p := procPath(r.pid, "exe")
	t, err := s.a.Readlink(p)
	if err == nil {
		r.exe, r.exeDeleted = stripDeleted(t)
		r.exeStatus = "ok"
		return true
	}
	if errors.Is(err, fs.ErrNotExist) {
		// An exiting task loses its exe before it becomes a zombie: ask
		// status whether it is going, then read the link once more before
		// filing an error (W-42, M-4).
		if s.dying(r.pid) {
			return false
		}
		if t, err = s.a.Readlink(p); err == nil {
			r.exe, r.exeDeleted = stripDeleted(t)
			r.exeStatus = "ok"
			return true
		}
		if errors.Is(err, fs.ErrNotExist) && s.dying(r.pid) {
			return false
		}
	}
	e := readFailure(p, err)
	r.exeStatus = string(e.Status)
	if e.Status != facts.StatusDenied {
		r.exeStatus = string(facts.StatusError)
		e.Status = facts.StatusError
	} else {
		s.denied++
	}
	s.exeFail.set(e)
	s.ownerFail[r.pid] = e
	return true
}

// dying reports a process whose status is gone or reads Z or X.
func (s *procScan) dying(pid int) bool {
	st, gone, _ := s.readStatus(pid)
	return gone || st.State == "Z" || st.State == "X"
}

// readNS classes the process's mount namespace against pid 1's.
func (s *procScan) readNS(r *procRow) {
	if s.hostErr != nil {
		r.nsStatus = string(s.hostErr.Status)
		if s.hostErr.Status != facts.StatusDenied {
			r.nsStatus = string(facts.StatusError)
		}
		s.noteOwnerFail(r.pid, *s.hostErr)
		return
	}
	p := procPath(r.pid, "ns/mnt")
	t, err := s.a.Readlink(p)
	if err != nil {
		e := readFailure(p, err)
		if e.Status != facts.StatusDenied {
			e.Status = facts.StatusError
		} else {
			s.denied++
		}
		r.nsStatus = string(e.Status)
		s.noteOwnerFail(r.pid, e)
		return
	}
	host := t == s.hostNS
	if !host && r.exeStatus != "ok" {
		// Which file a namespace of its own names cannot be told without
		// the exe: the exe's failure is the row's, never a quiet foreign
		// (F-5). readExe already noted it for the owner and counted a denial.
		r.nsStatus = r.exeStatus
		return
	}
	if !host {
		var fail *facts.Envelope
		if host, fail = s.seesHostExe(r, t); fail != nil {
			// A root link or a mountinfo that could not be read is the
			// row's failure, never a quiet foreign (R-3).
			e := *fail
			if e.Status != facts.StatusDenied {
				e.Status = facts.StatusError
			} else {
				s.denied++
			}
			r.nsStatus = string(e.Status)
			s.noteOwnerFail(r.pid, e)
			return
		}
	}
	r.nsStatus = "ok"
	if host {
		r.mntNS = nsHost
	} else {
		r.mntNS = nsForeign
		s.foreign++
	}
}

// nsMounts is one namespace's parsed mountinfo, or the failure a read of it
// met that the next process of the namespace would meet again (F-3).
type nsMounts struct {
	rows []mountRow
	fail *facts.Envelope
}

// mountsOf is the mountinfo of the namespace ns, read through pid the first
// time the namespace is met.
func (s *procScan) mountsOf(ns string, pid int) (nsMounts, *facts.Envelope) {
	if m, ok := s.mounts[ns]; ok {
		return m, m.fail
	}
	p := procPath(pid, "mountinfo")
	data, meta, err := s.a.ReadFile(p, mountinfoReadLimit)
	if err != nil {
		e := readFailure(p, err)
		// A process that vanished under the read leaves the namespace to
		// its next process (R-3); any other failure of pid 1's table is
		// every process's, and is not read again per process (F-3).
		if pid == 1 && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
			s.mounts[ns] = nsMounts{fail: &e}
		}
		return nsMounts{}, &e
	}
	if meta.Truncated {
		// A cut table may lack the very mount the exe lies on. The cut is
		// the namespace's size, not a race: every process of it would read
		// the same 4 MiB and discard them (F-3).
		e := collect.ErrorEnv(fmt.Sprintf("%s: cut at the %d-byte limit", p, mountinfoReadLimit))
		s.mounts[ns] = nsMounts{fail: &e}
		return nsMounts{}, &e
	}
	rows, err := parseMountinfo(data)
	if err != nil {
		e := collect.ErrorEnv(p + ": " + err.Error())
		if pid == 1 {
			s.mounts[ns] = nsMounts{fail: &e}
		}
		return nsMounts{}, &e
	}
	m := nsMounts{rows: rows}
	s.mounts[ns] = m
	return m, nil
}

// seesHostExe reports whether a process in a mount namespace of its own
// sees, at its exe path, the very file pid 1 sees there (W-65). systemd gives
// every service with PrivateTmp=, ProtectSystem= or ProtectHome= a namespace
// of its own (systemd-resolved on a stock host); ProtectSystem='s read-only
// bind of /usr names the same file on the same device, so it is host. A
// container (an overlay at /), a bind over the exe or over /usr from
// elsewhere, an extension image or a root other than / (RootDirectory=, a
// debug pod's chroot /host) is not: its exe text names a file the host's
// index must not be asked about. A root link or a mountinfo that cannot be
// read is the failure returned (R-3).
func (s *procScan) seesHostExe(r *procRow, ns string) (bool, *facts.Envelope) {
	if r.exe == "" {
		return false, nil
	}
	rp := procPath(r.pid, "root")
	root, err := s.a.Readlink(rp)
	if err != nil {
		e := readFailure(rp, err)
		return false, &e
	}
	if root != "/" {
		return false, nil
	}
	host, fail := s.mountsOf(s.hostNS, 1)
	if fail != nil {
		return false, fail
	}
	mine, fail := s.mountsOf(ns, r.pid)
	if fail != nil {
		return false, fail
	}
	hk, hok := exeMountKey(host.rows, r.exe)
	k, ok := exeMountKey(mine.rows, r.exe)
	if !hok || !ok {
		e := collect.ErrorEnv(fmt.Sprintf("no mountinfo row of pid %d or pid 1 lies under %s", r.pid, r.exe))
		return false, &e
	}
	return k == hk, nil
}

// exeMountKey names the file at exe as a mount table resolves it: the
// device, the path within that device (the mount's root joined with the rest
// of exe past the mount point), the type and the source of the visible mount
// whose mount point is the longest path prefix of exe. A mount is visible
// when it and every mount on its parent chain is the topmost at its own
// mount point: a /usr/lib mount left under a later bind over /usr is hidden
// by the bind and never chosen (F-2).
func exeMountKey(rows []mountRow, exe string) (string, bool) {
	top := topMounts(rows)
	byID := make(map[int]int, len(rows))
	for i, m := range rows {
		byID[m.id] = i
	}
	// The chain is walked from the mount up; a parent at its child's own
	// mount point is the mount the child is stacked on, which the child
	// covers by design, so it is passed over rather than judged.
	visible := func(i int) bool {
		if top[rows[i].mountPoint] != i {
			return false
		}
		for range len(rows) + 1 {
			j, ok := byID[rows[i].parent]
			if !ok || j == i {
				return true
			}
			if rows[j].mountPoint != rows[i].mountPoint && top[rows[j].mountPoint] != j {
				return false
			}
			i = j
		}
		return false // a parent cycle, which no kernel table holds
	}
	best := -1
	for i, m := range rows {
		mp := m.mountPoint
		if mp != "/" && exe != mp && !strings.HasPrefix(exe, mp+"/") {
			continue
		}
		if best >= 0 && len(mp) <= len(rows[best].mountPoint) {
			continue
		}
		if visible(i) {
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	m := rows[best]
	rel := strings.TrimPrefix(exe, m.mountPoint)
	if m.mountPoint == "/" {
		rel = exe
	}
	return m.dev + " " + path.Join(m.root, rel) + " " + m.fstype + " " + m.source, true
}

// topMounts maps each mount point to the index of its topmost row. Mounts
// stacked on one point: the topmost is the one no other of them is mounted
// on (its id is nobody's parent there); among several such, the last listed,
// as the kernel lists a namespace's mounts in the order they were made (R-4).
func topMounts(rows []mountRow) map[string]int {
	at := map[string][]int{}
	for i, m := range rows {
		at[m.mountPoint] = append(at[m.mountPoint], i)
	}
	top := make(map[string]int, len(at))
	for mp, idx := range at {
		top[mp] = idx[len(idx)-1]
		for k := len(idx) - 1; k >= 0; k-- {
			covered := false
			for _, o := range idx {
				if o != idx[k] && rows[o].parent == rows[idx[k]].id {
					covered = true
					break
				}
			}
			if !covered {
				top[mp] = idx[k]
				break
			}
		}
	}
	return top
}

// pidViewWhole reports whether this run sees the initial pid namespace
// whole: pid 1's row is there, its ns/mnt and mountinfo were read, and a
// kernel thread was seen (kernel threads live in the initial pid namespace
// only, and hidepid hides them from a non-root run) (W-69).
func (s *procScan) pidViewWhole() bool {
	if _, ok := s.rows[1]; !ok || s.hostErr != nil || s.kernel == 0 {
		return false
	}
	_, fail := s.mountsOf(s.hostNS, 1)
	return fail == nil
}

func (s *procScan) noteOwnerFail(pid int, e facts.Envelope) {
	if _, ok := s.ownerFail[pid]; !ok {
		s.ownerFail[pid] = e
	}
}

// readFds reads one fd table and records which wanted sockets it holds. It
// returns false when the process is gone (the table ENOENT).
func (s *procScan) readFds(r *procRow) bool {
	dir := procPath(r.pid, "fd")
	pattern := dir + "/*"
	if r.kind == kindZombie && r.threads > 1 {
		// A zombie leader's own fd/ is empty once it has exited, but its
		// live threads still hold the group's files: read them through the
		// tasks, every link counted against the one budget (W-68).
		dir = procPath(r.pid, "task")
		pattern = dir + "/*/fd/*"
	}
	links, err := s.a.Glob(pattern)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		e := readFailure(dir, err)
		if e.Status == facts.StatusDenied {
			s.denied++
			s.fdDenied.set(e)
		} else {
			s.fdError.set(e)
		}
		return true
	}
	if len(links) > procFdCap {
		s.fdOverrun.set(collect.ErrorEnv(fmt.Sprintf("%s: %d fd entries, past the %d budget (pid %d)", dir, len(links), procFdCap, r.pid)))
		return true
	}
	held := map[int]bool{}
	for _, l := range links {
		s.fdReads++
		t, err := s.a.Readlink(l)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // the fd closed between the listing and the read
			}
			e := readFailure(l, err)
			if e.Status == facts.StatusDenied {
				s.denied++
				s.fdDenied.set(e)
			} else {
				s.fdError.set(e)
			}
			return true
		}
		if ino, ok := parseFdLink(t); ok && s.wanted[ino] && !held[ino] {
			held[ino] = true
			s.holders[ino] = append(s.holders[ino], r.pid)
		}
	}
	return true
}

// listEnv is processes.list: every row, capped.
func (s *procScan) listEnv(rows []*procRow, src *facts.Source) facts.Envelope {
	list := make([]any, 0, min(len(rows), procListCap))
	for i, r := range rows {
		if i == procListCap {
			break
		}
		list = append(list, r.record())
	}
	e := collect.OK(list, src)
	e.Truncated = len(rows) > procListCap || s.budgetHit
	return e
}

// deletedEnv is processes.deleted_executables: the user processes whose exe
// carried " (deleted)", or the status of a read that would have to be
// omitted (spec P-1: never absent).
func (s *procScan) deletedEnv(rows []*procRow, src *facts.Source) facts.Envelope {
	for _, f := range []failure{s.statusFail, s.exeFail} {
		if f.env != nil {
			return *f.env // a failure keeps its own cause (R-5)
		}
	}
	list := []any{}
	for _, r := range rows {
		if r.kind == kindUser && r.exeDeleted {
			list = append(list, map[string]any{"pid": r.pid, "uid": r.uid, "name": r.name, "exe": r.exe})
		}
	}
	e := collect.OK(list, src)
	e.Truncated = s.budgetHit
	return e
}

// foldListeners turns the socket tables' rows into listeners, sorted by
// proto, port and addr. bad names the first row whose inode column did not
// parse (-1): that row's owners can never be known.
func foldListeners(rows []any) (out []listener, bad string) {
	for _, raw := range rows {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		table, _ := m["proto"].(string)
		addr, _ := m["addr"].(string)
		port, _ := m["port"].(int)
		inode, _ := m["inode"].(int)
		loop, _ := m["loopback"].(bool)
		proto, family := foldProto(table)
		l := listener{Proto: proto, Family: family, Addr: addr, Port: port, Loopback: loop,
			LinkLocal: isLinkLocal(addr), Inode: inode, Owners: []owner{}}
		if inode < 0 && bad == "" {
			bad = fmt.Sprintf("%s/%d on %s", proto, port, addr)
		}
		out = append(out, l)
	}
	slices.SortFunc(out, func(x, y listener) int {
		return cmp.Or(cmp.Compare(x.Proto, y.Proto), cmp.Compare(x.Port, y.Port), cmp.Compare(x.Addr, y.Addr),
			cmp.Compare(x.Family, y.Family), cmp.Compare(x.Inode, y.Inode))
	})
	return out, bad
}

// listenerEnvs joins the listeners to their owners and derives the two
// listener leaves. The order of the failures is the order of their weight:
// a socket whose inode did not parse and an fd table past its budget are
// errors no reading could fix; a refused table or owner read is denied; any
// other failed table is an error. A socket nobody holds after every table
// was read whole is the kernel's (W-66: the lab's WireGuard socket printed
// inode 363387305, not 0); without a whole read it is unmatched, and the
// leaf already carries the failure or the budget's truncation.
func (s *procScan) listenerEnvs(ls []listener, inodeBad string, socks socketTables, ix pkgindex.Index, idxFail *facts.Envelope) (facts.Envelope, facts.Envelope) {
	// Every fd table was read whole: none refused, none past its budget or
	// failed, no status unreadable, the enumeration not cut short. Only then
	// does "no process holds it" mean the kernel does (W-66).
	allRead := s.fdDenied.env == nil && s.fdOverrun.env == nil && s.fdError.env == nil &&
		s.statusFail.env == nil && !s.budgetHit
	// Inside a container the pid namespace may hide the holder of a host
	// socket (--net=host without --pid=host): an unheld socket is then a
	// hole in the inventory, never the kernel's (W-67). An empty Container
	// is not a container (J-31).
	partial := ""
	switch {
	case s.container != "" && s.container != "none":
		partial = "inside a " + s.container + " container the pid view may be partial"
	case !s.pidViewWhole():
		// hidepid=2/invisible, or a pid namespace the os collector does not
		// call a container (unshare -p --mount-proc, PrivatePIDs=): no
		// table was refused, yet the holder may be out of sight (W-69).
		partial = "pid 1 or the kernel threads are not visible to this run, so the pid view may be partial"
	}
	var unheld []string
	var ownerFail *facts.Envelope
	for i := range ls {
		l := &ls[i]
		switch {
		case l.Inode == 0:
			l.OwnerStatus = "kernel"
			continue
		case l.Inode < 0:
			l.OwnerStatus = "error"
			continue
		}
		pids := slices.Clone(s.holders[l.Inode])
		slices.Sort(pids)
		for _, pid := range pids {
			r, ok := s.rows[pid]
			if !ok {
				continue
			}
			if e, failed := s.ownerFail[pid]; failed && ownerFail == nil {
				e := e
				ownerFail = &e
			}
			if r.kind == kindZombie && ownerFail == nil {
				// A zombie leader's live threads hold the socket, but its
				// exe and namespace cannot be read: the owner cannot be
				// judged, so neither can the leaves (W-70).
				e := collect.Absent(fmt.Sprintf("owner %d is a zombie leader: exe and namespace unreadable", pid))
				ownerFail = &e
			}
			l.Owners = append(l.Owners, r.owner())
		}
		switch {
		case len(l.Owners) > 0:
			l.OwnerStatus = "ok"
		case s.fdDenied.env != nil:
			l.OwnerStatus = "denied"
		case allRead && partial == "":
			// A kernel-owned socket has a real inode that no fd table
			// holds (measured: WireGuard's udp and udp6 sockets; nfsd was
			// not measured); one closed between the two reads is no longer
			// a listener.
			l.OwnerStatus = "kernel"
		case allRead:
			l.OwnerStatus = "unmatched"
			unheld = append(unheld, fmt.Sprintf("%s/%d on %s (inode %d)", l.Proto, l.Port, l.Addr, l.Inode))
		default:
			l.OwnerStatus = "unmatched"
		}
	}

	var fail *facts.Envelope
	switch {
	case inodeBad != "":
		e := collect.ErrorEnv("the socket table's inode column did not parse for " + inodeBad)
		fail = &e
	case s.fdOverrun.env != nil:
		fail = s.fdOverrun.env
	case s.fdDenied.env != nil:
		fail = s.fdDenied.env
	case ownerFail != nil:
		fail = ownerFail
	case s.statusFail.env != nil:
		fail = s.statusFail.env
	case s.fdError.env != nil:
		fail = s.fdError.env
	case len(unheld) > 0:
		e := collect.Absent("no process this run can see holds the listening socket " + strings.Join(unheld, ", ") + "; " + partial)
		fail = &e
	}
	if fail != nil {
		return *fail, *fail
	}

	src := socks.src
	list := make([]any, 0, min(len(ls), procListenersCap))
	unpRows := []map[string]any{}
	for i, l := range ls {
		if i < procListenersCap {
			list = append(list, l.record(procOwnersCap))
		}
		for _, o := range l.Owners {
			if o.ExeDeleted || !unpackagedStatuses[o.PackageStatus] {
				continue
			}
			unpRows = append(unpRows, map[string]any{
				"proto": l.Proto, "family": l.Family, "addr": l.Addr, "port": l.Port,
				"pid": o.Pid, "name": o.Name, "exe": o.Exe, "package_status": o.PackageStatus,
			})
		}
	}
	lst := collect.OK(list, src)
	lst.Truncated = len(ls) > procListenersCap

	if idxFail != nil {
		return lst, *idxFail
	}
	unpList := make([]any, 0, min(len(unpRows), procListenersCap))
	for i, r := range unpRows {
		if i == procListenersCap {
			break
		}
		unpList = append(unpList, r)
	}
	unpSrc := &facts.Source{Kind: "derived", Inputs: slices.Clone(src.Inputs)}
	if ix.Source != nil {
		unpSrc.Inputs = append(unpSrc.Inputs, *ix.Source)
	}
	unp := collect.OK(unpList, unpSrc)
	unp.Truncated = lst.Truncated || len(unpRows) > procListenersCap
	return lst, unp
}

// The IPv6 sysctls the exposure verdict reads from /proc/sys: the sysctl
// collector sorts after this one (W-47, W-76).
const (
	procBindV6Only       = "/proc/sys/net/ipv6/bindv6only"
	procDisableV6All     = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	procDisableV6Default = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
)

// readProcInt reads one integer sysctl file. A kernel without IPv6 has no
// such file (present false, no failure); a file that exists and cannot be
// read or parsed is the failure (C3).
func readProcInt(a collect.Access, p string) (n int, present bool, fail *facts.Envelope) {
	data, _, err := a.ReadFile(p, 64)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		e := readFailure(p, err)
		return 0, false, &e
	}
	n, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		e := collect.ErrorEnv(p + ": not an integer")
		return 0, false, &e
	}
	return n, true, nil
}

// exposureFirewallKeys are the firewall facts the exposure verdict reads, in
// the order their failure is reported.
var exposureFirewallKeys = []string{
	"firewall.normalization_confidence", "firewall.rules", "firewall.backend", "firewall.raw_dumps", "firewall.restricts_inbound",
}

// carry is a failure envelope handed on to a derived leaf: its status, with
// the key it came from named in the reason.
func carry(key string, e facts.Envelope) facts.Envelope {
	return facts.Envelope{Status: e.Status, Reason: key + ": " + e.Reason}
}

// writeExposure derives the four exposure.* keys (spec P-3) from the
// listeners and the firewall's facts. A firewall fact that was not written is
// a programming error (firewall sorts before processes, so only a run that
// left it out can miss it): every key is an error naming it. A firewall read
// that did not answer is every key's status (unsupported reads
// NOT_APPLICABLE, denied ERROR). processes.listeners that is not ok is the
// status of the two leaves built from it. An undecided verdict makes
// exposure.exposed absent with the cause, written also to
// exposure.stats.manual_reason, since the evaluator renders an absent judged
// leaf without the collector's reason (W-3).
func writeExposure(a collect.Access, b *collect.Builder, ls []listener, lst facts.Envelope, hasV6 bool) {
	keys := []string{"exposure.listeners", "exposure.exposed", "exposure.opaque_rules", "exposure.stats"}
	setAll := func(e facts.Envelope) {
		for _, k := range keys {
			b.Set(k, e)
		}
	}
	fw := map[string]facts.Envelope{}
	for _, k := range exposureFirewallKeys {
		e, ok := b.Get(k)
		if !ok {
			setAll(collect.ErrorEnv(k + " was not written before the processes collector ran"))
			return
		}
		fw[k] = e
	}
	conf := fw["firewall.normalization_confidence"]
	for _, k := range exposureFirewallKeys[:4] {
		if fw[k].Status != facts.StatusOK {
			setAll(carry(k, fw[k]))
			return
		}
	}
	confidence, _ := conf.Value.(string)
	var restricts *bool
	if r := fw["firewall.restricts_inbound"]; r.Status == facts.StatusOK {
		v, ok := r.Value.(bool)
		if !ok {
			setAll(collect.ErrorEnv("firewall.restricts_inbound: not a bool"))
			return
		}
		restricts = &v
	} else if confidence == "full" {
		// A full normalisation always answers restricts_inbound; one that
		// did not is that read's failure.
		setAll(carry("firewall.restricts_inbound", r))
		return
	}
	rulesEnv := fw["firewall.rules"]
	rawRules, _ := rulesEnv.Value.([]any)
	rules := make([]fwRule, 0, len(rawRules))
	for _, r := range rawRules {
		if m, ok := r.(map[string]any); ok {
			rules = append(rules, fwRuleFromRecord(m))
		}
	}
	dumps, _ := fw["firewall.raw_dumps"].Value.([]any)

	in := exposureInputs{Confidence: confidence, Restricts: restricts, Rules: rules, HasV6: hasV6,
		BaseFamilies: inputBaseFamilies(dumps)}
	// bindv6only decides whether a socket on :: takes v4 traffic; a file
	// that exists and cannot be read is the answer for every :: listener (C3).
	bind, _, bindFail := readProcInt(a, procBindV6Only)
	in.BindV6Only = bind
	// disable_ipv6 on all and default both 1: the kernel drops every inbound
	// IPv6 packet, so v6 is no enabled family (W-76). Either file unreadable
	// is the answer for every v6 candidate (C3); v6 then stays enabled.
	allOff, allOK, allFail := readProcInt(a, procDisableV6All)
	defOff, defOK, defFail := readProcInt(a, procDisableV6Default)
	v6Fail := cmp.Or(allFail, defFail)
	in.V6Disabled = v6Fail == nil && allOK && defOK && allOff == 1 && defOff == 1

	listenersOK := lst.Status == facts.StatusOK
	var cands []listener
	if listenersOK {
		cands = ls
	}
	rows, exposed, opaque, manual := decideExposure(cands, in)

	// The firewall's source once: the confidence and the rule table are
	// written from the same capture, so the rules' source stands for both,
	// and the confidence's only when the rules carry none.
	src := &facts.Source{Kind: "derived"}
	fwSrc := rulesEnv.Source
	if fwSrc == nil {
		fwSrc = conf.Source
	}
	for _, s := range []*facts.Source{fwSrc, lst.Source} {
		if s != nil {
			src.Inputs = append(src.Inputs, *s)
		}
	}

	opaqueList := make([]any, 0, min(len(opaque), procListenersCap))
	for i, r := range opaque {
		if i == procListenersCap {
			break
		}
		opaqueList = append(opaqueList, opaqueRecord(r))
	}
	opaqueEnv := collect.OK(opaqueList, src)
	opaqueEnv.Truncated = rulesEnv.Truncated || len(opaque) > procListenersCap
	b.Set("exposure.opaque_rules", opaqueEnv)

	stats := map[string]any{
		"confidence": confidence, "manual_reason": manual, "listeners": len(rows), "exposed": len(exposed),
		"filtered": 0, "loopback": 0, "link_local": 0, "kernel_owned": 0,
		"opaque_rules": len(opaque), "folded_rules": len(rules), "ipv6_disabled": in.V6Disabled,
	}
	if !listenersOK {
		e := carry("processes.listeners", lst)
		b.Set("exposure.listeners", e)
		b.Set("exposure.exposed", e)
		stats["manual_reason"] = e.Reason
		b.Set("exposure.stats", collect.OK(stats, src))
		return
	}
	for _, l := range ls {
		if l.Loopback || isLoopback(l.Addr) {
			stats["loopback"] = stats["loopback"].(int) + 1
		}
	}
	for _, r := range rows {
		if r.Via == viaFiltered || r.Via == viaV6Off {
			stats["filtered"] = stats["filtered"].(int) + 1
		}
		if r.LinkLocal {
			stats["link_local"] = stats["link_local"].(int) + 1
		}
		if r.OwnerStatus == "kernel" {
			stats["kernel_owned"] = stats["kernel_owned"].(int) + 1
		}
	}

	list := make([]any, 0, min(len(rows), procListenersCap))
	for i, r := range rows {
		if i == procListenersCap {
			break
		}
		list = append(list, r.record(procOwnersCap))
	}
	lstEnv := collect.OK(list, src)
	lstEnv.Truncated = lst.Truncated || len(rows) > procListenersCap
	b.Set("exposure.listeners", lstEnv)

	var exp facts.Envelope
	anyDual, anyV6 := false, false
	for _, r := range rows {
		anyDual = anyDual || r.Addr == "::"
		anyV6 = anyV6 || slices.Contains(candidateFamilies(r.Addr, in.BindV6Only), "v6")
	}
	switch {
	case bindFail != nil && anyDual:
		exp = carry("net.ipv6.bindv6only", *bindFail)
		stats["manual_reason"] = exp.Reason
	case v6Fail != nil && anyV6:
		exp = carry("net.ipv6.conf.disable_ipv6", *v6Fail)
		stats["manual_reason"] = exp.Reason
	case manual != "":
		exp = collect.Absent(manual)
	default:
		expList := make([]any, 0, min(len(exposed), procListenersCap))
		for i, r := range exposed {
			if i == procListenersCap {
				break
			}
			expList = append(expList, r.exposedRecord())
		}
		exp = collect.OK(expList, src)
		// The cut goes on an answer only: a failure keeps its own cause
		// (M-6).
		exp.Truncated = lst.Truncated || rulesEnv.Truncated || len(exposed) > procListenersCap
	}
	b.Set("exposure.exposed", exp)
	b.Set("exposure.stats", collect.OK(stats, src))
}
