package pkgindex

import (
	"reflect"
	"testing"
)

func TestParseDpkgStatusKeepsTheInstalledInNameArchOrder(t *testing.T) {
	data := []byte("Package: zlib1g\nStatus: install ok installed\nArchitecture: i386\nVersion: 2\n\n" +
		"Package: zlib1g\r\nStatus: install ok installed\r\nArchitecture: amd64\r\nVersion: 1\r\n\r\n" +
		"Package: gone\nStatus: deinstall ok config-files\nVersion: 9\n\n" +
		"Package: adduser\nStatus: install ok installed\nDescription: x\n folded: line\nVersion: 3\n")
	want := []DpkgPackage{{Name: "adduser", Version: "3"}, {Name: "zlib1g", Version: "1", Arch: "amd64"}, {Name: "zlib1g", Version: "2", Arch: "i386"}}
	if got := ParseDpkgStatus(data); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDpkgStatus = %+v, want %+v", got, want)
	}
}

func TestDpkgListPackage(t *testing.T) {
	for in, want := range map[string]string{
		"/var/lib/dpkg/info/util-linux:amd64.list": "util-linux",
		"/var/lib/dpkg/info/passwd.list":           "passwd",
	} {
		if got := DpkgListPackage(in); got != want {
			t.Errorf("DpkgListPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDpkgListPathsSkipsBlankLines(t *testing.T) {
	got := dpkgListPaths([]byte("/.\n  /bin/su \r\n\n\t\n/usr/bin/a b\n"))
	if want := []string{"/.", "/bin/su", "/usr/bin/a b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("dpkgListPaths = %q, want %q", got, want)
	}
}

func TestParseDiversionsCanonicalisesAndDropsTheEmpty(t *testing.T) {
	data := []byte("/bin/foo\n/bin/foo.distrib\nfoo-wrapper\n/x\n/x\nself\n\n/y\nnobody\n/a\n/b\nincomplete")
	got := parseDiversions(data, map[string]string{"/bin": "/usr/bin"})
	want := []diversion{
		{from: "/usr/bin/foo", to: "/usr/bin/foo.distrib", by: "foo-wrapper"},
		{from: "/a", to: "/b", by: "incomplete"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseDiversions = %+v, want %+v", got, want)
	}
}

func TestParseStatOverridesKeepsThePathWhole(t *testing.T) {
	data := []byte("root crontab 2755 /bin/crontab\nroot root 104755 /usr/bin/a b\nroot root 9z /usr/bin/x\nshort line\n")
	got := parseStatOverrides(data, map[string]string{"/bin": "/usr/bin"})
	want := []statOverrideLine{
		{path: "/usr/bin/crontab", ov: StatOverride{User: "root", Group: "crontab", Mode: 0o2755}},
		{path: "/usr/bin/a b", ov: StatOverride{User: "root", Group: "root", Mode: 0o4755}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseStatOverrides = %+v, want %+v", got, want)
	}
}

func TestRPMFileTableDropsTheCutLineOfACappedCapture(t *testing.T) {
	data := []byte("util-linux\t0104755\troot\troot\t\t/usr/bin/su\nx\t0100644\troot\troot\t\t/var/lib/x/spool")
	cands := map[string]bool{"/usr/bin/su": true, "/var/lib/x/spool": true}
	whole, err := RPMFileTable(data, cands, false)
	if err != nil || len(whole) != 2 {
		t.Fatalf("whole = %v %v, want both rows", whole, err)
	}
	cut, err := RPMFileTable(data, cands, true)
	if err != nil || len(cut) != 1 || cut["/usr/bin/su"].Pkg != "util-linux" {
		t.Errorf("cut = %v %v, want su alone", cut, err)
	}
}
