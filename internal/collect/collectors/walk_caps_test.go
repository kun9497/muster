//go:build linux

package collectors

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The capability and ACL half of the walk (P-3). Every host below is
// synthetic: invented packages beside the real distribution spellings of the
// four files a stock Ubuntu host sets capabilities on, and no host anywhere.

// capAttr is a revision-2 security.capability attribute with the given
// permitted and inheritable masks and effective flag — the form setcap
// writes.
func capAttr(permitted, inheritable uint64, effective bool) []byte {
	b := make([]byte, 20)
	magic := uint32(vfsCapRevision2)
	if effective {
		magic |= vfsCapEffective
	}
	binary.LittleEndian.PutUint32(b, magic)
	binary.LittleEndian.PutUint32(b[4:], uint32(permitted))
	binary.LittleEndian.PutUint32(b[8:], uint32(inheritable))
	binary.LittleEndian.PutUint32(b[12:], uint32(permitted>>32))
	binary.LittleEndian.PutUint32(b[16:], uint32(inheritable>>32))
	return b
}

func capBits(names ...string) uint64 {
	var m uint64
	for _, n := range names {
		i, err := capIndex(n)
		if err != nil || i < 0 {
			panic(n)
		}
		m |= 1 << i
	}
	return m
}

var (
	netRawEP  = capAttr(capBits("cap_net_raw"), 0, true)
	netRawP   = capAttr(capBits("cap_net_raw"), 0, false)
	netAdmEP  = capAttr(capBits("cap_net_admin"), 0, true)
	gstPTPCap = capAttr(capBits("cap_net_bind_service", "cap_net_admin"), 0, true)
	snapCaps  = capAttr(capBits("cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_setgid",
		"cap_setuid", "cap_sys_chroot", "cap_sys_ptrace", "cap_sys_admin", "cap_sys_resource"), 0, false)
)

// capHost is a walkable host with the given regular files (path -> mode),
// every parent directory created 0755, on the two-mount mountinfo fixture.
// The family is decided by what the caller adds: dpkg's status file or
// rpm's directory.
func capHost(files map[string]uint32) *fsAccess {
	spec := map[string][]collect.DirEntry{"/": {treeDir("home", 0o755)}, "/home": {}}
	var ensure func(d string)
	ensure = func(d string) {
		if _, ok := spec[d]; ok {
			return
		}
		parent := path.Dir(d)
		ensure(parent)
		spec[parent] = append(spec[parent], treeDir(path.Base(d), 0o755))
		spec[d] = []collect.DirEntry{}
	}
	for _, p := range sortedKeys(files) {
		ensure(path.Dir(p))
		spec[path.Dir(p)] = append(spec[path.Dir(p)], treeFile(path.Base(p), files[p]))
	}
	return &fsAccess{
		files: map[string]string{
			mountinfoPath: "mountinfo",
			passwdPath:    "passwd",
			groupPath:     "group",
			subuidPath:    "subuid.sample",
			subgidPath:    "subgid.sample",
		},
		contents:    map[string][]byte{},
		fails:       map[string]error{},
		xattrValues: map[string]map[string][]byte{},
		xattrErrs:   map[string]error{},
		tree:        buildTree(spec, map[string]uint64{"/": 1, "/home": 2}),
	}
}

// dpkgCapHost is capHost on a merged-/usr Debian-family host.
func dpkgCapHost(files map[string]uint32) *fsAccess {
	a := capHost(files)
	a.files[dpkgStatusPath] = "dpkg.status.walk"
	a.links = mergedUsrLinks()
	return a
}

func (a *fsAccess) setCaps(p string, v []byte) {
	if a.xattrValues[p] == nil {
		a.xattrValues[p] = map[string][]byte{}
	}
	a.xattrValues[p]["security.capability"] = v
}

func (a *fsAccess) setACL(p string, v []byte) {
	if a.xattrValues[p] == nil {
		a.xattrValues[p] = map[string][]byte{}
	}
	a.xattrValues[p][aclXattrName] = v
}

// capRows runs the walk and returns walk.capabilities, which must be ok.
func capRowsOf(t *testing.T, a *fsAccess) (*collect.Builder, []map[string]any) {
	t.Helper()
	b := walkRun(t, a)
	return b, walkRows(t, b, "walk.capabilities")
}

func TestParsePostinstSetcapForms(t *testing.T) {
	cases := []struct {
		name string
		data string
		want []postinstCap
	}{
		{"seed iputils-ping: a variable set from dpkg-divert --truename", string(readSeed(t, "postinst.iputils-ping")),
			[]postinstCap{{Path: "/bin/ping", Caps: "cap_net_raw+ep"}}},
		{"seed mtr-tiny: a literal path", string(readSeed(t, "postinst.mtr-tiny")),
			[]postinstCap{{Path: "/usr/bin/mtr-packet", Caps: "cap_net_raw+ep"}}},
		{"seed snapd: the set read from a file", string(readSeed(t, "postinst.snapd-caps")),
			[]postinstCap{{Path: "/usr/lib/snapd/snap-confine", FromFile: true}}},
		{"a literal assignment, braces and quotes",
			"PROGRAM=/usr/bin/ping\nif setcap cap_net_raw+ep \"${PROGRAM}\"; then :; fi\n",
			[]postinstCap{{Path: "/usr/bin/ping", Caps: "cap_net_raw+ep"}}},
		{"iproute2: quoted caps, then a removal that declares nothing",
			"if ! setcap \"cap_dac_override,cap_sys_admin,cap_net_admin=ep\" /bin/ip; then\n  setcap \"-r\" /bin/ip\nfi\n",
			[]postinstCap{{Path: "/bin/ip", Caps: "cap_dac_override,cap_sys_admin,cap_net_admin=ep"}}},
		{"options, a continuation and two pairs",
			"setcap -q -n 0 cap_chown=p /usr/bin/a \\\n  cap_kill=p /usr/bin/b 2>/dev/null || true\n",
			[]postinstCap{{Path: "/usr/bin/a", Caps: "cap_chown=p"}, {Path: "/usr/bin/b", Caps: "cap_kill=p"}}},
		{"a setcap in a comment, an echo and a heredoc are not calls",
			"# setcap cap_sys_admin+ep /usr/bin/x\necho setcap cap_sys_admin+ep /usr/bin/x\ncat <<EOF\nsetcap cap_sys_admin+ep /usr/bin/y\nEOF\n",
			nil},
		{"an unknown variable, a relative path and a reassigned name are skipped",
			"setcap cap_net_raw+ep $NOPE\nsetcap cap_net_raw+ep bin/ping\nP=/usr/bin/p\nP=$(uname -m)\nsetcap cap_net_raw+ep $P\n",
			nil},
		{"after && and in a then branch on one line",
			"command -v setcap >/dev/null && setcap cap_net_raw+ep /usr/bin/q; if true; then setcap cap_net_raw+p /usr/bin/r; fi\n",
			[]postinstCap{{Path: "/usr/bin/q", Caps: "cap_net_raw+ep"}, {Path: "/usr/bin/r", Caps: "cap_net_raw+p"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePostinstSetcap([]byte(c.data))
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("parsePostinstSetcap = %+v, want %+v", got, c.want)
			}
		})
	}
}

func readSeed(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// P-3: iputils-ping sets its capability through a variable the script
// assigns from dpkg-divert --truename, and the join finds the script
// through the .list that owns the path.
func TestWalkCapabilitiesDeclaredByPostinstVariable(t *testing.T) {
	a := dpkgCapHost(map[string]uint32{"/usr/bin/ping": 0o755})
	a.setCaps("/usr/bin/ping", netRawEP)
	a.contents["/var/lib/dpkg/info/iputils-ping.list"] = []byte("/.\n/bin\n/bin/ping\n")
	a.files["/var/lib/dpkg/info/iputils-ping.postinst"] = "postinst.iputils-ping"
	_, rows := capRowsOf(t, a)
	checkRow(t, rows, "/usr/bin/ping", map[string]any{
		"caps": "cap_net_raw=ep", "rootid": 0, "package": "iputils-ping", "package_declared": true,
		"declared_caps": "cap_net_raw+ep", "reference": refPostinst, "reason": "",
	})
	if got := sortedKeys(rows[0]); !slices.Equal(got, []string{"caps", "declared_caps", "package", "package_declared", "path", "reason", "reference", "rootid"}) {
		t.Errorf("row fields = %v", got)
	}
}

func TestWalkCapabilitiesPostinstForms(t *testing.T) {
	a := dpkgCapHost(map[string]uint32{"/usr/bin/mtr-packet": 0o755, "/usr/lib/snapd/snap-confine": 0o755})
	a.setCaps("/usr/bin/mtr-packet", netRawEP)
	a.setCaps("/usr/lib/snapd/snap-confine", snapCaps)
	a.contents["/var/lib/dpkg/info/mtr-tiny.list"] = []byte("/usr/bin/mtr-packet\n")
	a.files["/var/lib/dpkg/info/mtr-tiny.postinst"] = "postinst.mtr-tiny"
	a.contents["/var/lib/dpkg/info/snapd.list"] = []byte("/usr/lib/snapd/snap-confine\n/usr/lib/snapd/snap-confine.caps\n")
	a.files["/var/lib/dpkg/info/snapd.postinst"] = "postinst.snapd-caps"
	_, rows := capRowsOf(t, a)
	checkRow(t, rows, "/usr/bin/mtr-packet", map[string]any{
		"caps": "cap_net_raw=ep", "package": "mtr-tiny", "package_declared": true,
		"declared_caps": "cap_net_raw+ep", "reference": refPostinst,
	})
	checkRow(t, rows, "/usr/lib/snapd/snap-confine", map[string]any{
		"caps":    "cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p",
		"package": "snapd", "package_declared": true, "declared_caps": "(from file)", "reference": refPostinst,
	})
}

func TestWalkCapabilitiesUndeclared(t *testing.T) {
	a := dpkgCapHost(map[string]uint32{
		"/opt/x/tool": 0o755, "/usr/bin/quiet": 0o755, "/usr/bin/other": 0o755, "/usr/bin/noscript": 0o755,
	})
	for _, p := range []string{"/opt/x/tool", "/usr/bin/quiet", "/usr/bin/noscript"} {
		a.setCaps(p, netRawEP)
	}
	a.setCaps("/usr/bin/other", netAdmEP)
	a.contents["/var/lib/dpkg/info/quiet.list"] = []byte("/usr/bin/quiet\n")
	a.contents["/var/lib/dpkg/info/quiet.postinst"] = []byte("#!/bin/sh\nset -e\nexit 0\n")
	a.contents["/var/lib/dpkg/info/other.list"] = []byte("/usr/bin/other\n")
	a.contents["/var/lib/dpkg/info/other.postinst"] = []byte("setcap cap_net_raw+ep /usr/bin/other\n")
	a.contents["/var/lib/dpkg/info/noscript.list"] = []byte("/usr/bin/noscript\n")
	_, rows := capRowsOf(t, a)
	checkRow(t, rows, "/opt/x/tool", map[string]any{
		"package": "", "package_declared": false, "declared_caps": "", "reference": refUnpackaged,
	})
	checkRow(t, rows, "/usr/bin/quiet", map[string]any{
		"package": "quiet", "package_declared": false, "declared_caps": "", "reference": refPostinst,
	})
	checkRow(t, rows, "/usr/bin/other", map[string]any{
		"caps": "cap_net_admin=ep", "package": "other", "package_declared": false,
		"declared_caps": "cap_net_raw+ep", "reference": refPostinst,
	})
	// A script that is not there declares nothing, and says nothing either:
	// most packages have no postinst.
	checkRow(t, rows, "/usr/bin/noscript", map[string]any{
		"package": "noscript", "package_declared": false, "declared_caps": "", "reference": refPostinst, "reason": "",
	})
}

// V-24: the caps column precedes the path, both libcap spellings declare,
// an empty column declares nothing, and a tab in a path survives. The
// sample is the Rocky 9 image's own table (iputils' %caps files and
// shadow-utils'; ping carries none).
func TestWalkCapabilitiesRPMFileCaps(t *testing.T) {
	a := capHost(map[string]uint32{
		"/usr/bin/arping": 0o755, "/usr/bin/clockdiff": 0o755, "/usr/bin/newuidmap": 0o755, "/usr/bin/ping": 0o755,
		"/usr/bin/oldspell": 0o755, "/opt/v/a\tb": 0o755,
	})
	a.dirs = map[string]bool{rpmDBDir: true}
	sample := readSeed(t, "rpm_files_caps.sample")
	extra := "oldlib\t0100755\troot\troot\t= cap_net_raw+p\t/usr/bin/oldspell\n" +
		"vendor\t0100755\troot\troot\tcap_net_raw=p\t/opt/v/a\tb\n"
	a.cmds = map[string]cmdResult{cmdKey(rpmCommand): {stdout: append(slices.Clone(sample), extra...)}}
	a.setCaps("/usr/bin/arping", netRawP)
	a.setCaps("/usr/bin/clockdiff", netRawP)
	a.setCaps("/usr/bin/newuidmap", capAttr(capBits("cap_setuid"), 0, true))
	a.setCaps("/usr/bin/ping", netRawP)
	a.setCaps("/usr/bin/oldspell", netRawP)
	a.setCaps("/opt/v/a\tb", netRawP)
	b, rows := capRowsOf(t, a)
	for _, p := range []string{"/usr/bin/arping", "/usr/bin/clockdiff"} {
		checkRow(t, rows, p, map[string]any{
			"caps": "cap_net_raw=p", "package": "iputils", "package_declared": true,
			"declared_caps": "cap_net_raw=p", "reference": refRPMDB,
		})
	}
	checkRow(t, rows, "/usr/bin/newuidmap", map[string]any{
		"caps": "cap_setuid=ep", "package": "shadow-utils", "package_declared": true, "declared_caps": "cap_setuid=ep", "reference": refRPMDB,
	})
	checkRow(t, rows, "/usr/bin/oldspell", map[string]any{
		"package": "oldlib", "package_declared": true, "declared_caps": "= cap_net_raw+p", "reference": refRPMDB,
	})
	// ping's line has an empty caps column: a capability on it is not the
	// package's.
	checkRow(t, rows, "/usr/bin/ping", map[string]any{
		"package": "iputils", "package_declared": false, "declared_caps": "", "reference": refRPMDB,
	})
	checkRow(t, rows, "/opt/v/a\tb", map[string]any{
		"package": "vendor", "package_declared": true, "reference": refRPMDB,
	})
	if src := env(t, b, "walk.capabilities").Source; src == nil || src.Cmd != cmdKey(rpmCommand) {
		t.Errorf("walk.capabilities source = %+v, want the rpm command", src)
	}
	if !strings.Contains(cmdKey(rpmCommand), "\t%|FILECAPS?{%{FILECAPS}}|\t%{FILENAMES}\n]") {
		t.Errorf("rpm query %q does not carry the caps column before the path", cmdKey(rpmCommand))
	}
}

// aclOf builds an access ACL: user::rwx, the named entries, group:: r-x,
// the mask and other:: r-x.
func aclOf(mask uint32, named ...[3]uint32) []byte {
	entries := [][3]uint32{{0x01, 7, undefinedID}}
	entries = append(entries, named...)
	entries = append(entries, [3]uint32{0x04, 5, undefinedID}, [3]uint32{0x10, mask, undefinedID}, [3]uint32{0x20, 5, undefinedID})
	return aclBlob(entries...)
}

func TestWalkACLGrantsWidenOnly(t *testing.T) {
	a := capHost(map[string]uint32{
		"/usr/local/bin/tool": 0o755, "/usr/local/bin/tame": 0o755, "/usr/local/bin/masked": 0o755,
		"/usr/local/bin/group": 0o755, "/usr/local/bin/data": 0o644,
	})
	a.dirs = map[string]bool{rpmDBDir: true}
	a.cmds = map[string]cmdResult{cmdKey(rpmCommand): {file: "rpm.qa-files.sample"}}
	a.setACL("/usr/local/bin/tool", aclOf(7, [3]uint32{0x02, 7, 1000}))
	a.setACL("/usr/local/bin/tame", aclOf(5, [3]uint32{0x02, 5, 1000}))
	a.setACL("/usr/local/bin/masked", aclOf(5, [3]uint32{0x02, 7, 1000})) // the mask takes the w away
	a.setACL("/usr/local/bin/group", aclOf(7, [3]uint32{0x08, 6, 27}, [3]uint32{0x02, 4, 1001}))
	a.setACL("/usr/local/bin/data", aclOf(7, [3]uint32{0x02, 7, 1000})) // not an executable: never opened
	b := walkRun(t, a)
	rows := walkRows(t, b, "walk.acl_grants")
	if got := rowPaths(rows); !slices.Equal(got, []string{"/usr/local/bin/group", "/usr/local/bin/tool"}) {
		t.Fatalf("walk.acl_grants = %v", got)
	}
	checkRow(t, rows, "/usr/local/bin/tool", map[string]any{"entries": []any{"user:1000:rwx"}})
	checkRow(t, rows, "/usr/local/bin/group", map[string]any{"entries": []any{"group:27:rw-"}})
	if got := sortedKeys(rows[0]); !slices.Equal(got, []string{"entries", "path"}) {
		t.Errorf("row fields = %v", got)
	}
	if src := env(t, b, "walk.acl_grants").Source; src == nil || src.Kind != "derived" {
		t.Errorf("walk.acl_grants source = %+v, want derived", src)
	}
}

// V-39: an entry whose attributes could not be read is a skip, whatever the
// double also put in Caps; the walk goes on and still finishes.
func TestWalkXattrErrorsAreSkipsNotStops(t *testing.T) {
	a := capHost(map[string]uint32{"/usr/bin/a": 0o755, "/usr/bin/b": 0o755, "/usr/bin/c": 0o755, "/usr/bin/d": 0o755, "/usr/bin/e": 0o755})
	a.dirs = map[string]bool{rpmDBDir: true}
	a.cmds = map[string]cmdResult{cmdKey(rpmCommand): {file: "rpm.qa-files.sample"}}
	a.setCaps("/usr/bin/a", netRawEP)
	a.xattrErrs["/usr/bin/a"] = unix.EACCES
	a.xattrErrs["/usr/bin/b"] = collect.ErrVanished
	a.setCaps("/usr/bin/c", []byte{0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0})
	a.xattrErrs["/usr/bin/d"] = unix.EIO
	a.setACL("/usr/bin/e", []byte{1, 2, 3})
	b := walkRun(t, a)
	if e := env(t, b, "walk.complete"); e.Value != true {
		t.Fatalf("walk.complete = %+v, want true", e)
	}
	if rows := walkRows(t, b, "walk.capabilities"); len(rows) != 0 {
		t.Errorf("walk.capabilities = %v, want none", rowPaths(rows))
	}
	skipped := walkRows(t, b, "walk.skipped")
	checkRow(t, skipped, "/usr/bin/a", map[string]any{"reason": "xattr_denied", "detail": ""})
	checkRow(t, skipped, "/usr/bin/b", map[string]any{"reason": "vanished"})
	checkRow(t, skipped, "/usr/bin/c", map[string]any{"reason": "xattr_undecoded"})
	checkRow(t, skipped, "/usr/bin/d", map[string]any{"reason": "vanished", "detail": unix.EIO.Error()})
	checkRow(t, skipped, "/usr/bin/e", map[string]any{"reason": "xattr_undecoded"})
	for _, p := range []string{"/usr/bin/b", "/usr/bin/c", "/usr/bin/e"} {
		if rowField(rowFor(t, skipped, p), "detail") == "" {
			t.Errorf("%s: skipped row carries no detail", p)
		}
	}
}

func TestWalkCapabilitiesCap(t *testing.T) {
	files := map[string]uint32{}
	for i := 0; i <= listCaps[capCapabilities]; i++ {
		files[fmt.Sprintf("/opt/many/t%04d", i)] = 0o755
	}
	a := capHost(files)
	a.dirs = map[string]bool{rpmDBDir: true}
	a.cmds = map[string]cmdResult{cmdKey(rpmCommand): {file: "rpm.qa-files.sample"}}
	for p := range files {
		a.setCaps(p, netRawEP)
	}
	b := walkRun(t, a)
	e := env(t, b, "walk.capabilities")
	if n := len(e.Value.([]any)); n != 2000 || !e.Truncated {
		t.Errorf("walk.capabilities = %d rows, truncated %v; want 2000, true", n, e.Truncated)
	}
	counts := walkStatsValue(t, b)["truncated_counts"].(map[string]any)
	if counts["capabilities"] != 2001 || counts["acl_grants"] != 0 {
		t.Errorf("truncated_counts = %v, want capabilities 2001 and acl_grants 0", counts)
	}
}

// V-22: an unreadable script is an undeclared row with a reason, never a
// failed join.
func TestWalkPostinstUnreadableIsUndeclared(t *testing.T) {
	a := dpkgCapHost(map[string]uint32{"/usr/bin/mtr-packet": 0o755})
	a.setCaps("/usr/bin/mtr-packet", netRawEP)
	a.contents["/var/lib/dpkg/info/mtr-tiny.list"] = []byte("/usr/bin/mtr-packet\n")
	a.files["/var/lib/dpkg/info/mtr-tiny.postinst"] = "postinst.mtr-tiny"
	a.fails["/var/lib/dpkg/info/mtr-tiny.postinst"] = fmt.Errorf("open: %w", unix.EACCES)
	b, rows := capRowsOf(t, a)
	checkRow(t, rows, "/usr/bin/mtr-packet", map[string]any{
		"package": "mtr-tiny", "package_declared": false, "declared_caps": "", "reference": refPostinst,
	})
	if r := rowField(rowFor(t, rows, "/usr/bin/mtr-packet"), "reason"); !strings.HasPrefix(r, "/var/lib/dpkg/info/mtr-tiny.postinst: ") {
		t.Errorf("reason %q does not name the script", r)
	}
	for _, key := range []string{"walk.suid_sgid", "walk.world_writable", "walk.hidden"} {
		if e := env(t, b, key); e.Status != facts.StatusOK {
			t.Errorf("%s = %+v, want ok: the join did not fail", key, e)
		}
	}
}

func TestWalkCapabilitiesMultiArchPostinst(t *testing.T) {
	const helper = "/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper"
	a := dpkgCapHost(map[string]uint32{helper: 0o755})
	a.setCaps(helper, gstPTPCap)
	a.contents["/var/lib/dpkg/info/libgstreamer1.0-0:amd64.list"] = []byte(helper + "\n")
	a.contents["/var/lib/dpkg/info/libgstreamer1.0-0:amd64.postinst"] = []byte(
		"if command -v setcap > /dev/null; then\n    if setcap cap_net_bind_service,cap_net_admin+ep " + helper + "; then\n        echo ok\n    fi\nfi\n")
	_, rows := capRowsOf(t, a)
	checkRow(t, rows, helper, map[string]any{
		"caps": "cap_net_bind_service,cap_net_admin=ep", "package": "libgstreamer1.0-0", "package_declared": true,
		"declared_caps": "cap_net_bind_service,cap_net_admin+ep", "reference": refPostinst,
	})
	if !slices.Contains(a.reads, "/var/lib/dpkg/info/libgstreamer1.0-0:amd64.postinst") {
		t.Errorf("the multi-arch postinst was never read: %v", a.reads)
	}
}

// A diverted file sits at the diverted-to name; the package that shipped
// it lists, and its script names, the original.
func TestWalkCapabilitiesDivertedPath(t *testing.T) {
	a := dpkgCapHost(map[string]uint32{"/usr/bin/foo.distrib": 0o755})
	a.setCaps("/usr/bin/foo.distrib", netRawEP)
	a.contents[dpkgDiversionsPath] = []byte("/usr/bin/foo\n/usr/bin/foo.distrib\nfoo-wrapper\n")
	a.contents["/var/lib/dpkg/info/foo.list"] = []byte("/usr/bin/foo\n")
	a.contents["/var/lib/dpkg/info/foo-wrapper.list"] = []byte("/usr/bin/foo\n")
	a.contents["/var/lib/dpkg/info/foo.postinst"] = []byte("P=$(dpkg-divert --truename /bin/foo)\nsetcap cap_net_raw+ep $P\n")
	_, rows := capRowsOf(t, a)
	checkRow(t, rows, "/usr/bin/foo.distrib", map[string]any{
		"package": "foo", "package_declared": true, "declared_caps": "cap_net_raw+ep", "reference": refPostinst,
	})
}
