package collectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/pkgindex"
)

func readProcFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseProcStatus(t *testing.T) {
	for _, tc := range []struct {
		file string
		want procStatus
	}{
		{"proc_status_sshd", procStatus{Name: "sshd", PPid: 1, Uid: 0, State: "S", HasKthread: true, Threads: 1}},
		{"proc_status_kthread", procStatus{Name: "kworker/0:1-events", PPid: 2, Uid: 0, State: "I", HasKthread: true, Kthread: true, Threads: 1}},
		{"proc_status_zombie", procStatus{Name: "defunct-child", PPid: 4200, Uid: 1000, State: "Z", Threads: 1}},
	} {
		got, err := parseProcStatus(readProcFixture(t, tc.file))
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.file, got, tc.want)
		}
	}
}

func TestParseProcStatusRefusesAFileWithoutTheCoreLines(t *testing.T) {
	for _, data := range []string{"", "Name:\tx\nState:\tS\nPPid:\t1\n", "Name:\tx\nState:\tS\nPPid:\tx\nUid:\t0\n", "Name:\tx\nState:\t\nPPid:\t1\nUid:\t0\n"} {
		if _, err := parseProcStatus([]byte(data)); err == nil {
			t.Errorf("%q parsed", data)
		}
	}
}

func TestParseCmdline(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/usr/sbin/sshd\x00-D\x00", "/usr/sbin/sshd"},
		{"sshd: alice [priv]", "sshd: alice [priv]"},
		{"", ""},
		{"\x00", ""},
	} {
		if got := parseCmdline([]byte(tc.in)); got != tc.want {
			t.Errorf("parseCmdline(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("a", 3*cmdlineCap)
	if got := parseCmdline([]byte(long)); len(got) != cmdlineCap {
		t.Errorf("a %d-byte token came back %d bytes, the cap is %d", len(long), len(got), cmdlineCap)
	}
}

func TestParseFdLink(t *testing.T) {
	if n, ok := parseFdLink("socket:[123]"); !ok || n != 123 {
		t.Errorf("socket:[123] -> %d %v", n, ok)
	}
	if n, ok := parseFdLink("socket:[0]"); !ok || n != 0 {
		t.Errorf("socket:[0] -> %d %v", n, ok)
	}
	for _, s := range []string{"pipe:[4]", "/dev/null", "anon_inode:[eventpoll]", "socket:[]", "socket:[-1]", "socket:[12", "socket:[1a]", "socket:[99999999999999999999]"} {
		if n, ok := parseFdLink(s); ok {
			t.Errorf("%q -> %d, want not a socket", s, n)
		}
	}
}

func TestStripDeleted(t *testing.T) {
	for _, tc := range []struct {
		in, exe string
		deleted bool
	}{
		{"/usr/sbin/nginx (deleted)", "/usr/sbin/nginx", true},
		{"/memfd:x (deleted)", "/memfd:x", true},
		{"/usr/sbin/nginx", "/usr/sbin/nginx", false},
		{"/opt/a (deleted) b", "/opt/a (deleted) b", false},
	} {
		exe, deleted := stripDeleted(tc.in)
		if exe != tc.exe || deleted != tc.deleted {
			t.Errorf("stripDeleted(%q) = %q %v", tc.in, exe, deleted)
		}
	}
}

func TestPackageStatusFor(t *testing.T) {
	// The index owns every path this test names, so a status other than
	// packaged proves the index was not the answer.
	owns := map[string]string{
		"/usr/sbin/sshd": "openssh-server", "/snap/lxd/1/bin/lxd": "x", "/var/lib/flatpak/app/x": "x",
		"/home/a/.local/share/flatpak/app/y": "x", "/tmp/.mount_abc/AppRun": "x",
	}
	dpkg := pkgindex.Index{Family: pkgindex.FamilyDpkg, Dpkg: &pkgindex.DpkgIndex{Owner: owns}}
	for _, tc := range []struct {
		exe, ns     string
		idx         pkgindex.Index
		pkg, status string
	}{
		{"/usr/sbin/sshd", nsHost, dpkg, "openssh-server", pkgPackaged},
		{"/usr/local/bin/x", nsHost, dpkg, "", pkgUnpackaged},
		{"/snap/lxd/1/bin/lxd", nsHost, dpkg, "snap:lxd", pkgSnap},
		{"/var/lib/flatpak/app/x", nsHost, dpkg, "", pkgFlatpak},
		{"/home/a/.local/share/flatpak/app/y", nsHost, dpkg, "", pkgFlatpak},
		{"/tmp/.mount_abc/AppRun", nsHost, dpkg, "", pkgAppImage},
		{"/usr/sbin/sshd", nsForeign, dpkg, "", pkgForeignNS},
		{"/snap/lxd/24322/bin/lxd", nsForeign, dpkg, "snap:lxd", pkgSnap},
		{"/snap/hello/x1/bin/hello", nsForeign, pkgindex.Index{}, "snap:hello", pkgSnap},
		{"/snap/lxd/current/bin/lxd", nsForeign, dpkg, "", pkgForeignNS},
		{"/snap/foo", nsForeign, dpkg, "", pkgForeignNS},
		{"/snap/lxd/1/", nsHost, dpkg, "", pkgUnpackaged},
		{"/usr/sbin/sshd", "", dpkg, "", pkgForeignNS},
		{"/usr/sbin/sshd", nsHost, pkgindex.Index{}, "", pkgNoIndex},
		{"/usr/sbin/sshd", nsHost, pkgindex.Index{Family: pkgindex.FamilyNone}, "", pkgNoIndex},
		{"/usr/sbin/sshd", nsHost, pkgindex.Index{Family: pkgindex.FamilyRPM, RPM: map[string]pkgindex.RPMFile{"/usr/sbin/sshd": {Pkg: "openssh-server"}}}, "openssh-server", pkgPackaged},
	} {
		pkg, status := packageStatusFor(tc.exe, tc.ns, tc.idx)
		if pkg != tc.pkg || status != tc.status {
			t.Errorf("packageStatusFor(%q, %q, %s) = %q %q, want %q %q", tc.exe, tc.ns, tc.idx.Family, pkg, status, tc.pkg, tc.status)
		}
	}
}

func TestFoldProtoAndLinkLocal(t *testing.T) {
	for _, tc := range []struct{ in, proto, family string }{{"tcp", "tcp", "v4"}, {"tcp6", "tcp", "v6"}, {"udp", "udp", "v4"}, {"udp6", "udp", "v6"}} {
		if p, f := foldProto(tc.in); p != tc.proto || f != tc.family {
			t.Errorf("foldProto(%q) = %q %q", tc.in, p, f)
		}
	}
	for addr, want := range map[string]bool{"fe80::1": true, "169.254.1.1": true, "::": false, "192.0.2.1": false, "": false} {
		if isLinkLocal(addr) != want {
			t.Errorf("isLinkLocal(%q) != %v", addr, want)
		}
	}
}
