//go:build linux

package collectors

import (
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// P-6: the privilege collector. Every test runs it through build(), under
// the guard, so a read or stat outside the declaration fails the test (V-10).

const (
	dockerSock     = "/run/docker.sock"
	containerdSock = "/run/containerd/containerd.sock"
	podmanSock     = "/run/podman/podman.sock"
	crioSock       = "/run/crio/crio.sock"
)

// socketRowFields and memberRowFields are the fields every row carries
// (V-9), existing or not.
var (
	socketRowFields = []string{"path", "exists", "kind", "mode", "uid", "gid", "group", "group_writable", "other_writable", "owner_nonroot", "acl_present"}
	memberRowFields = []string{"group", "member", "uid", "socket"}
)

// privilegeAccess is a host with /etc/group and /etc/passwd, no socket and
// no /etc/ld.so.preload.
func privilegeAccess(group, passwd string) *fsAccess {
	return &fsAccess{
		contents: map[string][]byte{groupPath: []byte(group), passwdPath: []byte(passwd)},
		files:    map[string]string{},
		fails:    map[string]error{},
		stats:    map[string]statResult{},
	}
}

const (
	stockGroup  = "root:x:0:\ndocker:x:999:alice\nusers:x:100:\n"
	stockPasswd = "root:x:0:0:root:/root:/bin/bash\n" +
		"alice:x:1001:1001::/home/alice:/bin/bash\n" +
		"bob:x:1002:999::/home/bob:/bin/bash\n"
)

func deniedErr(op, p string) error { return &fs.PathError{Op: op, Path: p, Err: unix.EACCES} }

// rowsOf checks every row of an ok list carries exactly fields and returns
// the rows.
func rowsOf(t *testing.T, b *collect.Builder, key string, fields []string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range okList(t, b, key) {
		m := r.(map[string]any)
		for _, f := range fields {
			if _, ok := m[f]; !ok {
				t.Errorf("%s row %v lacks %s", key, m, f)
			}
		}
		if len(m) != len(fields) {
			t.Errorf("%s row %v has %d fields, want %d", key, m, len(m), len(fields))
		}
		out = append(out, m)
	}
	return out
}

func socketShape(r map[string]any) string {
	return fmt.Sprintf("%s exists=%v kind=%q mode=%v uid=%v gid=%v group=%q gw=%v ow=%v nonroot=%v acl=%v",
		r["path"], r["exists"], r["kind"], r["mode"], r["uid"], r["gid"], r["group"], r["group_writable"], r["other_writable"],
		r["owner_nonroot"], r["acl_present"])
}

func memberShape(r map[string]any) string {
	return fmt.Sprintf("%s %s %v %s", r["group"], r["member"], r["uid"], r["socket"])
}

func shapes(rows []map[string]any, f func(map[string]any) string) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, f(r))
	}
	return out
}

func absentSocket(p string) string {
	return p + ` exists=false kind="" mode=-1 uid=-1 gid=-1 group="" gw=false ow=false nonroot=false acl=false`
}

func TestPrivilegePreload(t *testing.T) {
	a := privilegeAccess(stockGroup, stockPasswd)
	b := build(t, "privilege", a)
	e := env(t, b, "privilege.ld_so_preload")
	if e.Status != facts.StatusOK || !reflect.DeepEqual(e.Value, []any{}) || e.Source == nil || e.Source.Kind != "file" || e.Source.Path != ldSoPreloadPath {
		t.Errorf("no file: %+v", e)
	}

	a.fails[ldSoPreloadPath] = deniedErr("open", ldSoPreloadPath)
	b = build(t, "privilege", a)
	if e := env(t, b, "privilege.ld_so_preload"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, ldSoPreloadPath+": ") {
		t.Errorf("denied: %+v", e)
	}

	delete(a.fails, ldSoPreloadPath)
	a.files[ldSoPreloadPath] = "ld.so.preload.sample"
	b = build(t, "privilege", a)
	want := []any{"/usr/lib/libfoo.so", "/usr/lib/libbar.so", "/opt/x.so"}
	if e := env(t, b, "privilege.ld_so_preload"); e.Status != facts.StatusOK || !reflect.DeepEqual(e.Value, want) || e.Source == nil || e.Source.Path != ldSoPreloadPath {
		t.Errorf("present: %+v", e)
	}
}

func TestPrivilegeRuntimeSockets(t *testing.T) {
	a := privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	b := build(t, "privilege", a)

	got := shapes(rowsOf(t, b, "privilege.runtime_sockets", socketRowFields), socketShape)
	want := []string{
		dockerSock + ` exists=true kind="socket" mode=432 uid=0 gid=999 group="docker" gw=true ow=false nonroot=false acl=false`,
		absentSocket(containerdSock),
		absentSocket(podmanSock),
		absentSocket(crioSock),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sockets\n got %s\nwant %s", strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}

	members := rowsOf(t, b, "privilege.runtime_group_members", memberRowFields)
	got = shapes(members, memberShape)
	want = []string{"docker alice 1001 " + dockerSock, "docker bob 1002 " + dockerSock}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
	// uid is an int, as every uid fact is.
	if len(members) > 0 && members[0]["uid"] != 1001 {
		t.Errorf("uid %#v", members[0]["uid"])
	}

	// Two group-writable sockets on one group: one row per socket, sorted
	// by group, member, socket; a root member never appears, and a member
	// both supplementary and primary is one row.
	a.contents[groupPath] = []byte("root:x:0:\ndocker:x:999:root,bob,alice\n")
	a.stats[crioSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	a.stats[containerdSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 0}
	b = build(t, "privilege", a)
	got = shapes(rowsOf(t, b, "privilege.runtime_group_members", memberRowFields), memberShape)
	want = []string{
		"docker alice 1001 " + crioSock, "docker alice 1001 " + dockerSock,
		"docker bob 1002 " + crioSock, "docker bob 1002 " + dockerSock,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[1]; r["group"] != "root" {
		t.Errorf("containerd row %s", socketShape(r))
	}
}

func TestPrivilegeSocketAndGroupFailures(t *testing.T) {
	// An empty docker group and no one with it as primary: no members.
	a := privilegeAccess("docker:x:999:\n", "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n")
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	b := build(t, "privilege", a)
	if m := okList(t, b, "privilege.runtime_group_members"); !reflect.DeepEqual(m, []any{}) {
		t.Errorf("empty group: %v", m)
	}

	// A world-writable socket.
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o666, uid: 0, gid: 999}
	b = build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["other_writable"] != true || r["group_writable"] != true {
		t.Errorf("0666: %s", socketShape(r))
	}

	// A socket that is not group-writable contributes no member.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o600, uid: 0, gid: 999}
	b = build(t, "privilege", a)
	if m := okList(t, b, "privilege.runtime_group_members"); len(m) != 0 {
		t.Errorf("0600 socket: %v", m)
	}

	// A stat that fails for want of privilege on /run/podman (V-35): the
	// whole sockets leaf, and the members derived from it, are denied.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	a.fails[podmanSock] = deniedErr("stat", podmanSock)
	b = build(t, "privilege", a)
	for _, k := range []string{"privilege.runtime_sockets", "privilege.runtime_group_members"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, podmanSock+": ") {
			t.Errorf("%s: %+v", k, e)
		}
	}

	// ENOTDIR on a parent is a socket that does not exist.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.fails[containerdSock] = &fs.PathError{Op: "stat", Path: containerdSock, Err: unix.ENOTDIR}
	b = build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[1]; socketShape(r) != absentSocket(containerdSock) {
		t.Errorf("ENOTDIR: %s", socketShape(r))
	}

	// /etc/group unreadable: the row's group is "" and the members carry
	// the read's status, path-prefixed (C3).
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	delete(a.contents, groupPath)
	a.fails[groupPath] = deniedErr("open", groupPath)
	b = build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["group"] != "" || r["exists"] != true || r["gid"] != 999 {
		t.Errorf("group denied: %s", socketShape(r))
	}
	if e := env(t, b, "privilege.runtime_group_members"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, groupPath+": ") {
		t.Errorf("members with /etc/group denied: %+v", e)
	}

	// /etc/group missing: members absent naming it (V-27).
	a.fails = map[string]error{}
	b = build(t, "privilege", a)
	if e := env(t, b, "privilege.runtime_group_members"); e.Status != facts.StatusAbsent || e.Reason != groupPath+": not present" {
		t.Errorf("members with no /etc/group: %+v", e)
	}

	// /etc/passwd unreadable: the members carry its status; the group name
	// still comes from /etc/group.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	delete(a.contents, passwdPath)
	a.fails[passwdPath] = deniedErr("open", passwdPath)
	b = build(t, "privilege", a)
	if e := env(t, b, "privilege.runtime_group_members"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, passwdPath+": ") {
		t.Errorf("members with /etc/passwd denied: %+v", e)
	}
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["group"] != "docker" {
		t.Errorf("passwd denied: %s", socketShape(r))
	}
}

// statRecorder records every path Stat is asked for.
type statRecorder struct {
	*fsAccess
	stated []string
}

func (s *statRecorder) Stat(p string) (collect.ReadMeta, error) {
	s.stated = append(s.stated, p)
	return s.fsAccess.Stat(p)
}

func TestPrivilegePublishesEveryKey(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range reg.Keys {
		if k.Collector == "privilege" {
			keys = append(keys, k.Key)
		}
	}
	want := []string{"privilege.ld_so_preload", "privilege.runtime_sockets", "privilege.runtime_group_members"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("registered privilege keys %v, want %v", keys, want)
	}
	withDocker := privilegeAccess(stockGroup, stockPasswd)
	withDocker.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	podmanDenied := privilegeAccess(stockGroup, stockPasswd)
	podmanDenied.fails[podmanSock] = deniedErr("stat", podmanSock)
	allDenied := privilegeAccess("", "")
	for _, p := range []string{ldSoPreloadPath, groupPath, passwdPath} {
		delete(allDenied.contents, p)
		allDenied.fails[p] = deniedErr("open", p)
	}
	for name, a := range map[string]*fsAccess{"empty": {}, "docker": withDocker, "podman denied": podmanDenied, "all denied": allDenied} {
		rec := &statRecorder{fsAccess: a}
		b := build(t, "privilege", rec)
		for _, k := range keys {
			if _, ok := leaf(t, b, k).(facts.Envelope); !ok {
				t.Errorf("%s: %s not written", name, k)
			}
		}
		for _, p := range append(append([]string{}, rec.stated...), a.reads...) {
			if strings.HasPrefix(p, "/var/run") {
				t.Errorf("%s: touched %s", name, p)
			}
		}
		if !reflect.DeepEqual(rec.stated, runtimeSockets) {
			t.Errorf("%s: stated %v, want %v", name, rec.stated, runtimeSockets)
		}
	}
}

// V-51: a non-root owner or a POSIX ACL reaches the runtime API without the
// group, so both are recorded on every row; kind says what is at the path.
func TestPrivilegeSocketOwnerACLAndKind(t *testing.T) {
	a := privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 1000, gid: 999}
	b := build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["owner_nonroot"] != true || r["acl_present"] != false {
		t.Errorf("uid 1000: %s", socketShape(r))
	}

	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	a.xattrValues = map[string]map[string][]byte{dockerSock: {aclXattrName: fiveEntryACL()}}
	b = build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["acl_present"] != true || r["owner_nonroot"] != false {
		t.Errorf("ACL: %s", socketShape(r))
	}

	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "regular", mode: 0o644, uid: 0, gid: 0}
	b = build(t, "privilege", a)
	if r := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)[0]; r["kind"] != "regular" || r["exists"] != true {
		t.Errorf("regular file: %s", socketShape(r))
	}

	// An xattr read that fails is the whole leaf's status, as a stat is.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	a.fails[dockerSock] = deniedErr("flistxattr", dockerSock)
	b = build(t, "privilege", a)
	for _, k := range []string{"privilege.runtime_sockets", "privilege.runtime_group_members"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, dockerSock+": ") {
			t.Errorf("xattr denied, %s: %+v", k, e)
		}
	}

	// A symlink at a socket path is an error naming the path once.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.links = map[string]string{dockerSock: "/elsewhere"}
	b = build(t, "privilege", a)
	e := env(t, b, "privilege.runtime_sockets")
	if e.Status != facts.StatusError || strings.Count(e.Reason, dockerSock) != 1 || !strings.HasPrefix(e.Reason, dockerSock+": ") {
		t.Errorf("symlink: %+v", e)
	}
}

func TestPrivilegeNeutralRowAndUnknownMember(t *testing.T) {
	a := privilegeAccess("docker:x:999:ghost\n", stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	b := build(t, "privilege", a)
	rows := rowsOf(t, b, "privilege.runtime_sockets", socketRowFields)
	neutral := map[string]any{"path": crioSock, "exists": false, "kind": "", "mode": -1, "uid": -1, "gid": -1, "group": "",
		"group_writable": false, "other_writable": false, "owner_nonroot": false, "acl_present": false}
	if !reflect.DeepEqual(rows[3], neutral) {
		t.Errorf("neutral row %#v\nwant %#v", rows[3], neutral)
	}
	// ghost is in /etc/group but not /etc/passwd: uid -1, still a row.
	got := shapes(rowsOf(t, b, "privilege.runtime_group_members", memberRowFields), memberShape)
	want := []string{"docker bob 1002 " + dockerSock, "docker ghost -1 " + dockerSock}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("members %v, want %v", got, want)
	}
}

func TestPrivilegeTruncation(t *testing.T) {
	var names []string
	for i := 0; i < 4096; i++ {
		names = append(names, fmt.Sprintf("m%04d", i))
	}
	a := privilegeAccess("docker:x:999:"+strings.Join(names, ",")+"\n", stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	b := build(t, "privilege", a)
	if rows := okList(t, b, "privilege.runtime_group_members"); len(rows) != runtimeMembersRows {
		t.Errorf("%d member rows, want %d", len(rows), runtimeMembersRows)
	}
	if e := env(t, b, "privilege.runtime_group_members"); !e.Truncated {
		t.Errorf("members past the cap not truncated: %+v", e.Status)
	}
	if e := env(t, b, "privilege.runtime_sockets"); e.Truncated {
		t.Errorf("sockets truncated by the members cap")
	}

	// A truncated /etc/group read may miss the line a name or a member
	// came from: both leaves say so.
	a = privilegeAccess(stockGroup, stockPasswd)
	a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
	a.truncated = map[string]bool{groupPath: true}
	b = build(t, "privilege", a)
	for _, k := range []string{"privilege.runtime_sockets", "privilege.runtime_group_members"} {
		if e := env(t, b, k); !e.Truncated {
			t.Errorf("%s not truncated after a truncated /etc/group", k)
		}
	}
	// A truncated /etc/passwd, the members only.
	a.truncated = map[string]bool{passwdPath: true}
	b = build(t, "privilege", a)
	if e := env(t, b, "privilege.runtime_group_members"); !e.Truncated {
		t.Errorf("members not truncated after a truncated /etc/passwd")
	}
	if e := env(t, b, "privilege.runtime_sockets"); e.Truncated {
		t.Errorf("sockets truncated by /etc/passwd")
	}
}

// V-53: once the stat found the socket, an xattr read that fails, even with
// ENOENT (no procfs for the /proc/self/fd route), is the leaf's error,
// never a socket that is not there.
func TestPrivilegeXattrNotExistAfterStatIsError(t *testing.T) {
	for _, errno := range []error{unix.ENOENT, unix.ENOTDIR} {
		a := privilegeAccess(stockGroup, stockPasswd)
		a.stats[dockerSock] = statResult{kind: "socket", mode: 0o660, uid: 0, gid: 999}
		a.fails[dockerSock] = &fs.PathError{Op: "listxattr", Path: "/proc/self/fd/3", Err: errno}
		b := build(t, "privilege", a)
		for _, k := range []string{"privilege.runtime_sockets", "privilege.runtime_group_members"} {
			if e := env(t, b, k); e.Status != facts.StatusError || !strings.HasPrefix(e.Reason, dockerSock+": ") {
				t.Errorf("%v, %s: %+v", errno, k, e)
			}
		}
	}
}
