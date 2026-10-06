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
	procStatusGlob = "/proc/[0-9]*/status"
	procInitMntNS  = "/proc/1/ns/mnt"
)

var processesCollector = collect.Collector{
	Name: "processes",
	Declare: collect.Declaration{
		Reads:    processesReads(),
		Commands: []collect.Command{pkgindex.RPMCommand},
		// Declared now, read by the exposure derivation (Task 4); the
		// firewall collector sorts before this one.
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
		"/proc/[0-9]*/ns/mnt",
		"/proc/[0-9]*/mountinfo",
		"/proc/[0-9]*/root",
		procInitMntNS,
		"/proc/sys/net/ipv6/bindv6only",
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

	budgetHit                                           bool
	kernel, zombies, foreign, denied, vanished, fdReads int
}

func runProcesses(ctx context.Context, a collect.Access, b *collect.Builder) error {
	start := time.Now()
	keys := []string{"processes.list", "processes.deleted_executables", "processes.listeners", "processes.unpackaged_listeners", "processes.stats"}
	setAll := func(e facts.Envelope) {
		for _, k := range keys {
			b.Set(k, e)
		}
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

	s := &procScan{a: a, rows: map[int]*procRow{}, wanted: map[int]bool{}, holders: map[int][]int{}, ownerFail: map[int]facts.Envelope{}, mounts: map[string]nsMounts{}}
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
	r := &procRow{pid: pid, ppid: st.PPid, uid: st.Uid, name: st.Name}
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
	r.nsStatus = "ok"
	if t == s.hostNS || s.seesHostExe(r, t) {
		r.mntNS = nsHost
	} else {
		r.mntNS = nsForeign
		s.foreign++
	}
}

// nsMounts is one parsed mountinfo; ok is false when it could not be read
// or parsed.
type nsMounts struct {
	rows []mountRow
	ok   bool
}

// mountsOf is the mountinfo of the namespace ns, read through pid the first
// time the namespace is met.
func (s *procScan) mountsOf(ns string, pid int) nsMounts {
	if m, ok := s.mounts[ns]; ok {
		return m
	}
	var m nsMounts
	if data, _, err := s.a.ReadFile(procPath(pid, "mountinfo"), mountinfoReadLimit); err == nil {
		if rows, err := parseMountinfo(data); err == nil {
			m = nsMounts{rows: rows, ok: true}
		}
	}
	s.mounts[ns] = m
	return m
}

// seesHostExe reports whether a process in a mount namespace of its own
// sees, at its exe path, the very file pid 1 sees there (W-65). systemd gives
// every service with PrivateTmp=, ProtectSystem= or ProtectHome= a namespace
// of its own (systemd-resolved on a stock host); ProtectSystem='s read-only
// bind of /usr names the same file on the same device, so it is host. A
// container (an overlay at /), a bind over the exe or over /usr from
// elsewhere, an extension image, a root other than / (RootDirectory=, a
// debug pod's chroot /host) or a table that cannot be read is not: its exe
// text names a file the host's index must not be asked about.
func (s *procScan) seesHostExe(r *procRow, ns string) bool {
	if r.exeStatus != "ok" || r.exe == "" {
		return false
	}
	if root, err := s.a.Readlink(procPath(r.pid, "root")); err != nil || root != "/" {
		return false
	}
	host := s.mountsOf(s.hostNS, 1)
	mine := s.mountsOf(ns, r.pid)
	if !host.ok || !mine.ok {
		return false
	}
	hk, hok := exeMountKey(host.rows, r.exe)
	k, ok := exeMountKey(mine.rows, r.exe)
	return hok && ok && k == hk
}

// exeMountKey names the file at exe as a mount table resolves it: the
// device, the path within that device (the mount's root joined with the rest
// of exe past the mount point), the type and the source of the topmost mount
// whose mount point is the longest path prefix of exe.
func exeMountKey(rows []mountRow, exe string) (string, bool) {
	best := -1
	for i, m := range rows {
		mp := m.mountPoint
		if mp != "/" && exe != mp && !strings.HasPrefix(exe, mp+"/") {
			continue
		}
		if best < 0 || len(mp) >= len(rows[best].mountPoint) {
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

func (s *procScan) noteOwnerFail(pid int, e facts.Envelope) {
	if _, ok := s.ownerFail[pid]; !ok {
		s.ownerFail[pid] = e
	}
}

// readFds reads one fd table and records which wanted sockets it holds. It
// returns false when the process is gone (the table ENOENT).
func (s *procScan) readFds(r *procRow) bool {
	dir := procPath(r.pid, "fd")
	links, err := s.a.Glob(dir + "/*")
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
			e := *f.env
			e.Truncated = s.budgetHit
			return e
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
			l.Owners = append(l.Owners, r.owner())
		}
		switch {
		case len(l.Owners) > 0:
			l.OwnerStatus = "ok"
		case s.fdDenied.env != nil:
			l.OwnerStatus = "denied"
		case allRead:
			// A kernel-owned socket (WireGuard, nfsd, lockd, ksmbd) has a
			// real inode that no fd table holds; one closed between the two
			// reads is no longer a listener.
			l.OwnerStatus = "kernel"
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
