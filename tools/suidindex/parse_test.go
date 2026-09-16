package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kun9497/muster/docs/reference/suid"
)

// sampleRelease is the release the committed testdata/image-output.sample
// was produced for: three packages the image installs and two the tool
// downloads, with the two placeholder digests the sample's `== deb` headers
// carry.
func sampleRelease() suid.Release {
	return suid.Release{
		ID: "ubuntu", VersionID: "22.04",
		Image:  "docker.io/library/ubuntu:22.04",
		Digest: "sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7",
		Packages: []suid.SourcePackage{
			{Name: "util-linux", Reason: "the image installs it"},
			{Name: "passwd", Reason: "the image installs it"},
			{Name: "login", Reason: "the image installs it"},
			{Name: "at", Reason: "a scheduled-job host installs it",
				URL: "https://example.invalid/at.deb", SHA256: strings.Repeat("1", 64)},
			{Name: "sudo", Reason: "almost every managed host installs it",
				URL: "https://example.invalid/sudo.deb", SHA256: strings.Repeat("2", 64)},
		},
	}
}

func sampleOutput(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/image-output.sample")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The one test that says what the tool is for: the script's output becomes a
// list the join can read. Every rule the reference list depends on is
// asserted here on real output shapes — the pre-merge /bin/su canonicalised
// through the image's OWN symlink table, the archive's tar listing read with
// the same parser the collector uses, the version of an image package from
// dpkg-query and of an extended one from the .deb's control, and the whole
// thing sorted.
func TestAssembleListFromImageOutput(t *testing.T) {
	got, warnings, err := assembleList(sampleRelease(), "2026-09-16", "amd64", sampleOutput(t))
	if err != nil {
		t.Fatalf("assembleList: %v", err)
	}
	if got.Distro != "ubuntu" || got.Release != "22.04" {
		t.Errorf("header = %q/%q, want the image's own os-release", got.Distro, got.Release)
	}
	if got.ImageDigest != sampleRelease().Digest || got.Generated != "2026-09-16" || got.Arch != "amd64" {
		t.Errorf("digest %q generated %q arch %q", got.ImageDigest, got.Generated, got.Arch)
	}
	wantPkgs := []suid.Package{
		{Name: "at", Version: "3.2.5-1ubuntu1", PostinstSetsMode: true},
		{Name: "login", Version: "1:4.8.1-2ubuntu2.2"},
		{Name: "passwd", Version: "1:4.8.1-2ubuntu2.2"},
		{Name: "sudo", Version: "1.9.9-1ubuntu2.6"},
		{Name: "util-linux", Version: "2.37.2-4ubuntu3"},
	}
	if !reflect.DeepEqual(got.Packages, wantPkgs) {
		t.Errorf("packages = %+v\nwant %+v", got.Packages, wantPkgs)
	}
	wantEntries := []suid.Entry{
		{Path: "/etc/login.defs", Mode: 0o644, Owner: "root", Group: "root", Package: "login"},
		{Path: "/etc/sudoers", Mode: 0o640, Owner: "root", Group: "root", Package: "sudo"},
		{Path: "/usr/bin/at", Mode: 0o6755, Owner: "daemon", Group: "daemon", Package: "at"},
		{Path: "/usr/bin/atq", Mode: 0o755, Owner: "root", Group: "root", Package: "at"},
		{Path: "/usr/bin/chage", Mode: 0o2755, Owner: "root", Group: "shadow", Package: "passwd"},
		{Path: "/usr/bin/dmesg", Mode: 0o755, Owner: "root", Group: "root", Package: "util-linux"},
		{Path: "/usr/bin/faillog", Mode: 0o755, Owner: "root", Group: "root", Package: "login"},
		{Path: "/usr/bin/mount", Mode: 0o4755, Owner: "root", Group: "root", Package: "util-linux"},
		{Path: "/usr/bin/passwd", Mode: 0o4755, Owner: "root", Group: "root", Package: "passwd"},
		{Path: "/usr/bin/su", Mode: 0o4755, Owner: "root", Group: "root", Package: "login"},
		{Path: "/usr/bin/sudo", Mode: 0o4755, Owner: "root", Group: "root", Package: "sudo"},
		{Path: "/usr/bin/umount", Mode: 0o4755, Owner: "root", Group: "root", Package: "util-linux"},
		{Path: "/usr/sbin/useradd", Mode: 0o755, Owner: "root", Group: "root", Package: "passwd"},
	}
	if !reflect.DeepEqual(got.Entries, wantEntries) {
		t.Errorf("entries =\n%+v\nwant\n%+v", got.Entries, wantEntries)
	}
	// The one path two packages list keeps the first in (path, package)
	// order and is named on stderr rather than silently dropped.
	var dup int
	for _, w := range warnings {
		if strings.Contains(w, "/etc/login.defs") && strings.Contains(w, "util-linux") && strings.Contains(w, "keeps login") {
			dup++
		}
	}
	if dup != 1 {
		t.Errorf("warnings = %v, want exactly one naming /etc/login.defs, util-linux and the row kept", warnings)
	}
}

// The directory row in the sample is not an entry: a mode on a directory is
// not a declaration about a file, and a list that held /usr/bin would be
// joined against the walk's own directory rows.
func TestAssembleListDropsNonRegularArchiveRows(t *testing.T) {
	got, _, err := assembleList(sampleRelease(), "2026-09-16", "amd64", sampleOutput(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got.Entries {
		if e.Path == "/usr/bin" {
			t.Fatalf("the directory row became an entry: %+v", e)
		}
	}
	out := strings.Replace(string(sampleOutput(t)),
		"-rwxr-xr-x root/root      1024 2024-01-01 00:00 ./usr/bin/atq",
		"lrwxrwxrwx root/root         0 2024-01-01 00:00 ./usr/bin/atq -> at", 1)
	got, _, err = assembleList(sampleRelease(), "2026-09-16", "amd64", []byte(out))
	if err != nil {
		t.Fatalf("a symlink row must be skipped, not an error: %v", err)
	}
	if _, ok := entryOf(got, "/usr/bin/atq"); ok {
		t.Error("a symlink row became an entry; its mode says nothing about a file")
	}
}

// The canonicalisation uses the IMAGE's table and only the aliases that
// point into /usr, exactly as mountPlan.readUsrMerged does on a host. The
// sample's /libx32 points outside /usr, so a file under it stays where it is
// — and a list that moved it would never join.
func TestAssembleListCanonicalisesOnlyUsrAliases(t *testing.T) {
	out := strings.Replace(string(sampleOutput(t)),
		"755 root root /usr/bin/dmesg",
		"755 root root /usr/bin/dmesg\n644 root root /libx32/ld.so.conf", 1)
	got, _, err := assembleList(sampleRelease(), "2026-09-16", "amd64", []byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := entryOf(got, "/libx32/ld.so.conf"); !ok {
		t.Errorf("an alias pointing outside /usr must not be canonicalised; entries = %+v", got.Entries)
	}
	if _, ok := entryOf(got, "/usr/bin/su"); !ok {
		t.Error("/bin/su was not canonicalised into /usr/bin/su")
	}
}

func entryOf(l suid.List, p string) (suid.Entry, bool) {
	for _, e := range l.Entries {
		if e.Path == p {
			return e, true
		}
	}
	return suid.Entry{}, false
}

// Every way the script can lie about what it did is an error naming the
// problem. A generator that half-succeeded and wrote a short list would be
// worse than one that refused: the join reads a missing file as "the
// distribution does not ship this bit", which is a finding.
func TestAssembleListRefusesBrokenOutput(t *testing.T) {
	base := string(sampleOutput(t))
	cases := []struct {
		name, out, want string
	}{
		{"no sections", "hello\n", "== osrelease"},
		{"unknown section", base + "== mystery\n", "mystery"},
		{"wrong distro", strings.Replace(base, "ubuntu\n22.04", "debian\n12", 1), "debian"},
		{"package with no version", strings.Replace(base, "util-linux 2.37.2-4ubuntu3\n", "", 1), "util-linux"},
		{"extended package with no archive", strings.Replace(base, "== deb sudo "+strings.Repeat("2", 64), "== modes nothing", 1), "sudo"},
		{"archive digest is not the pin", strings.Replace(base, strings.Repeat("1", 64), strings.Repeat("9", 64), 1), "sha256"},
		{"unreadable stat line", strings.Replace(base, "755 root root /usr/bin/dmesg", "whoops", 1), "whoops"},
		{"unreadable archive line", strings.Replace(base, "-rw-r----- root/root      1234 2024-01-01 00:00 ./etc/sudoers", "-rw-r-----", 1), "-rw-r-----"},
		{"no entries at all", "== osrelease\nubuntu\n22.04\n== arch\nx86_64\n== usrmerge\n== versions\n", "no entries"},
		{"no arch section", strings.Replace(base, "== arch\nx86_64\n", "", 1), "== arch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := assembleList(sampleRelease(), "2026-09-16", "amd64", []byte(c.out))
			if err == nil {
				t.Fatalf("assembleList accepted %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one naming %q", err, c.want)
			}
		})
	}
}

// postinst_sets_mode is the difference between "the distribution does not
// ship this setuid" (a finding) and "the distribution sets it after
// unpacking" (unverifiable). It is read off the maintainer scripts, so the
// decision is a text one and testable without an image — and every line
// below is one this tool actually read out of a public archive.
//
// A LITERAL target has to be a file the package ships. The walk only ever
// makes a regular file a setuid candidate (walk_traverse.go), so a chmod on
// a directory or on a path the archive does not contain can never decide
// anything the join will ask about, and flagging the package for it would
// cost a WARN on every one of its real files for nothing. A computed target
// keeps the generous answer, because the archive gives no way to know.
func TestPostinstSetsMode(t *testing.T) {
	// What the package ships, in the canonical form the list holds. fuse3's
	// script says /bin/fusermount3 and the list says /usr/bin/fusermount3,
	// so the lookup has to canonicalise before it decides.
	shipped := map[string]bool{
		"/usr/bin/wall": true, "/usr/lib/x": true, "/usr/bin/foo": true,
		"/usr/sbin/bar": true, "/usr/bin/y": true, "/etc/sudoers": true,
		"/etc/x": true, "/usr/bin/fusermount3": true, "/usr/bin/pkexec": true,
	}
	merged := map[string]string{"/bin": "/usr/bin", "/sbin": "/usr/sbin"}
	cases := []struct {
		line string
		want bool
	}{
		{"	chmod 4755 $2/usr/bin/at", true},
		{"chmod 2755 /usr/bin/wall", true},
		{"  chmod 6755 /usr/lib/x", true},
		{"chmod u+s /usr/bin/foo", true},
		{"chmod a+rwxs /usr/bin/foo", true},
		{"chmod 0755 /usr/bin/foo", false},
		{"chmod 644 /etc/sudoers", false},
		{"chmod 1777 /run/screen", false},
		{"chmod u+x /usr/sbin/bar", false},
		{"chmod 4755", false}, // no operand: not a claim about a shipped file
		{"echo chmodding", false},
		{"", false},
		// fuse3's own line: pre-merge on the left, canonical in the list.
		{"    chmod 4755 /bin/fusermount3", true},
		// A literal target the archive does not ship decides nothing.
		{"chmod -R g+s /var/spool/mail", false},
		{"# chmod 4755 /usr/bin", false},
		{"chmod 4755 /usr/bin/not-in-this-package", false},
		// policykit-1 and postfix compute the mode AND the target, so the
		// archive's text never spells either. A scan that insisted on a
		// literal would call every ordinary /usr/bin/pkexec a finding.
		{"	chmod $MODE $FILE", true},
		{`chmod "$mode" "$file"`, true},
		{"chmod ${MODE} /usr/bin/pkexec", true},
		{"chmod $3 \"$1\"", true},
		// dbus sets the mode through dpkg's own override table, which has
		// exactly the effect a chmod would; its target is computed too.
		{`dpkg-statoverride --update --add root "$MESSAGEUSER" 4754 "$LAUNCHER"`, true},
		// postfix's override names a literal DIRECTORY, which is not a
		// candidate the walk could ever raise.
		{"dpkg-statoverride --update --add postfix postdrop 02710 /var/spool/postfix/public", false},
		{"dpkg-statoverride --add root root 0755 /usr/bin/x", false},
		{"dpkg-statoverride --remove /usr/sbin/postdrop >/dev/null 2>&1 || true", false},
		{"if ! dpkg-statoverride --list $FILE > /dev/null 2>&1; then", false},
	}
	for _, c := range cases {
		line, got := postinstSetsMode([]string{c.line}, shipped, merged)
		if got != c.want {
			t.Errorf("postinstSetsMode(%q) = %v, want %v", c.line, got, c.want)
		}
		if got && line != strings.TrimSpace(c.line) {
			t.Errorf("postinstSetsMode(%q) reported the line as %q", c.line, line)
		}
	}
	if line, ok := postinstSetsMode([]string{"chmod 644 /etc/x", "chmod u+s /usr/bin/y"}, shipped, merged); !ok || line != "chmod u+s /usr/bin/y" {
		t.Errorf("one qualifying line among several = (%q, %v)", line, ok)
	}
}

// The flag is not a bare boolean in a generated file: the run says which
// maintainer-script line it read it off, so a maintainer can check the
// judgement without unpacking the archive again.
func TestPostinstFlagCarriesItsEvidence(t *testing.T) {
	_, warnings, err := assembleList(sampleRelease(), "2026-09-16", "amd64", sampleOutput(t))
	if err != nil {
		t.Fatal(err)
	}
	var found string
	for _, w := range warnings {
		if strings.Contains(w, "postinst sets a mode") {
			found = w
		}
	}
	if !strings.Contains(found, "at:") || !strings.Contains(found, "chmod 4755 $2/usr/bin/at") {
		t.Errorf("warnings = %v, want one naming at and the line it was read off", warnings)
	}
	// sudo's only mode line is an ordinary 0644, so it reports nothing.
	for _, w := range warnings {
		if strings.Contains(w, "sudo") && strings.Contains(w, "postinst") {
			t.Errorf("sudo was flagged: %s", w)
		}
	}
}

// -check is only useful if it says WHICH file moved. A byte comparison that
// printed "differs" would send the maintainer back to a diff of a
// forty-thousand-line JSON file.
func TestDescribeDifferenceNamesTheFirstDifferingThing(t *testing.T) {
	base := suid.List{
		Distro: "ubuntu", Release: "22.04", ImageDigest: "sha256:aa", Generated: "2026-09-16",
		Packages: []suid.Package{{Name: "at", Version: "1"}, {Name: "sudo", Version: "2"}},
		Entries: []suid.Entry{
			{Path: "/usr/bin/at", Mode: 0o4755, Owner: "root", Group: "root", Package: "at"},
			{Path: "/usr/bin/sudo", Mode: 0o4755, Owner: "root", Group: "root", Package: "sudo"},
		},
	}
	enc := func(l suid.List) []byte {
		b, err := renderList(l)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if msg, kind := describeDifference(enc(base), enc(base)); kind != diffNone {
		t.Errorf("identical lists differ: %s", msg)
	}
	// A run on another day moves `generated` and nothing else. That is not
	// drift — it is the clock — so -check reports it and passes; the
	// maintainer can verify the committed lists on any day.
	later := base
	later.Generated = "2026-11-30"
	msg, kind := describeDifference(enc(base), enc(later))
	if kind != diffDateOnly {
		t.Errorf("a date-only difference = %v (%s), want diffDateOnly", kind, msg)
	}
	if !strings.Contains(msg, "2026-11-30") || !strings.Contains(msg, "2026-09-16") {
		t.Errorf("the date-only message %q names neither date", msg)
	}
	// A date that moves ALONGSIDE real drift is still drift.
	both := later
	both.Entries = append([]suid.Entry(nil), base.Entries...)
	both.Entries[1].Mode = 0o755
	if msg, kind := describeDifference(enc(base), enc(both)); kind != diffReal || !strings.Contains(msg, "/usr/bin/sudo") {
		t.Errorf("drift under a new date = (%q, %v), want the path and diffReal", msg, kind)
	}
	mutate := func(f func(*suid.List)) string {
		l := base
		l.Packages = append([]suid.Package(nil), base.Packages...)
		l.Entries = append([]suid.Entry(nil), base.Entries...)
		f(&l)
		msg, kind := describeDifference(enc(base), enc(l))
		if kind != diffReal {
			t.Fatalf("difference reported as %v: %s", kind, msg)
		}
		return msg
	}
	for _, c := range []struct {
		name string
		f    func(*suid.List)
		want string
	}{
		{"mode", func(l *suid.List) { l.Entries[1].Mode = 0o755 }, "/usr/bin/sudo"},
		{"owner", func(l *suid.List) { l.Entries[0].Owner = "daemon" }, "/usr/bin/at"},
		{"added", func(l *suid.List) {
			l.Entries = append(l.Entries, suid.Entry{Path: "/usr/bin/zz", Package: "at"})
		}, "/usr/bin/zz"},
		{"removed", func(l *suid.List) { l.Entries = l.Entries[:1] }, "/usr/bin/sudo"},
		{"version", func(l *suid.List) { l.Packages[1].Version = "3" }, "sudo"},
		{"digest", func(l *suid.List) { l.ImageDigest = "sha256:bb" }, "image_digest"},
	} {
		if got := mutate(c.f); !strings.Contains(got, c.want) {
			t.Errorf("%s: message %q does not name %q", c.name, got, c.want)
		}
	}
}

// A package name reaches a shell script, so the tool refuses one that is not
// a Debian/RPM package name rather than quoting its way around it.
func TestScriptRefusesAnUnsafePackageName(t *testing.T) {
	rel := sampleRelease()
	if _, err := scriptFor(rel); err != nil {
		t.Fatalf("scriptFor(a real release): %v", err)
	}
	rel.Packages = append(rel.Packages, suid.SourcePackage{Name: "at; rm -rf /", Reason: "hostile"})
	if _, err := scriptFor(rel); err == nil {
		t.Fatal("scriptFor accepted a package name with a shell metacharacter")
	}
	rpm := suid.Release{ID: "rocky", VersionID: "9", Image: "x", Packages: []suid.SourcePackage{{Name: "sudo", Reason: "r"}}}
	s, err := scriptFor(rpm)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "rpm -ql") || strings.Contains(s, "dpkg -L") {
		t.Error("the rpm family's script must read rpm -ql and never dpkg -L")
	}
	deb, err := scriptFor(sampleRelease())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dpkg -L", "dpkg-query -W", `dpkg-deb --fsys-tarfile "/debs/$d.deb"`, "archives='at sudo'", "dpkg-deb -e", "-perm /6000", "uname -m"} {
		if !strings.Contains(deb, want) {
			t.Errorf("the dpkg script does not run %q", want)
		}
	}
}

// The whole -check path, with the image replaced by the recorded sample:
// a committed list that has drifted is reported by path and the run fails.
func TestCheckReportsTheDifferingPathAndFails(t *testing.T) {
	dir := t.TempDir()
	rel, out, sources := stubbedRelease(t, dir)

	// A clean check first, so the failure below is about the drift and not
	// about the harness.
	o := options{sourcesPath: sources, outDir: dir, cacheDir: dir, check: true, generated: "2026-09-16"}
	want, _, err := assembleList(rel, "2026-09-16", "amd64", out)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := renderList(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ubuntu-22.04.json", blob, 0o644); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	if err := run(o, &log); err != nil {
		t.Fatalf("-check against the list just generated: %v (%s)", err, log.String())
	}

	// Now move one mode and check again.
	drifted := strings.Replace(string(blob), `"path": "/usr/bin/sudo",`+"\n      "+`"mode": 2541`,
		`"path": "/usr/bin/sudo",`+"\n      "+`"mode": 493`, 1)
	if drifted == string(blob) {
		t.Fatalf("the fixture did not contain the mode to move:\n%s", blob)
	}
	if err := os.WriteFile(dir+"/ubuntu-22.04.json", []byte(drifted), 0o644); err != nil {
		t.Fatal(err)
	}
	log.Reset()
	err = run(o, &log)
	if err == nil {
		t.Fatal("-check passed against a list that had drifted")
	}
	if !strings.Contains(log.String(), "/usr/bin/sudo") {
		t.Errorf("the report does not name the differing path: %s", log.String())
	}

	// And without -check the same run rewrites the file.
	o.check = false
	log.Reset()
	if err := run(o, &log); err != nil {
		t.Fatalf("generate: %v (%s)", err, log.String())
	}
	got, err := os.ReadFile(dir + "/ubuntu-22.04.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(blob) {
		t.Error("generating did not restore the list the script describes")
	}
}

// A release whose committed list is missing entirely is a -check failure
// too: a list that was deleted must not read as "nothing to compare".
func TestCheckFailsWhenTheListIsMissing(t *testing.T) {
	dir := t.TempDir()
	_, _, sources := stubbedRelease(t, dir)
	var log strings.Builder
	err := run(options{sourcesPath: sources, outDir: dir, cacheDir: dir, check: true, generated: "2026-09-16"}, &log)
	if err == nil {
		t.Fatal("-check passed with no committed list")
	}
	if !strings.Contains(log.String(), "ubuntu-22.04.json") {
		t.Errorf("the report does not name the missing file: %s", log.String())
	}
}

// stubbedRelease writes a sources.json for the sample release into dir,
// pinning the two archives to the digests of the bytes the stubbed download
// returns, and replaces the script runner with the recorded sample. It
// returns the release, the sample output with those digests substituted, and
// the sources path.
func stubbedRelease(t *testing.T, dir string) (suid.Release, []byte, string) {
	t.Helper()
	body := map[string][]byte{"at": []byte("at-archive"), "sudo": []byte("sudo-archive")}
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	rel := sampleRelease()
	out := string(sampleOutput(t))
	for i, p := range rel.Packages {
		b, ok := body[p.Name]
		if !ok {
			continue
		}
		out = strings.Replace(out, "== deb "+p.Name+" "+p.SHA256, "== deb "+p.Name+" "+sum(b), 1)
		rel.Packages[i].SHA256 = sum(b)
	}

	oldDownload, oldRun := download, runScript
	t.Cleanup(func() { download, runScript = oldDownload, oldRun })
	download = func(url string) ([]byte, error) {
		for name, b := range body {
			if strings.Contains(url, name) {
				return b, nil
			}
		}
		return nil, os.ErrNotExist
	}
	runScript = func(o options, image, debsDir, script string, network bool) ([]byte, error) {
		if network {
			t.Error("generation must run with no network; only -resolve may reach the archive")
		}
		for name := range body {
			if _, err := os.Stat(debsDir + "/" + name + ".deb"); err != nil {
				t.Errorf("%s.deb was not staged for the bind mount: %v", name, err)
			}
		}
		return []byte(out), nil
	}

	blob, err := json.MarshalIndent(suid.Sources{Releases: []suid.Release{rel}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := dir + "/sources.json"
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	return rel, []byte(out), path
}

// The downloaded archive is verified before it is written anywhere, so a
// rotated URL fails loudly instead of quietly regenerating a different list.
func TestADownloadThatDoesNotMatchThePinIsRefused(t *testing.T) {
	dir := t.TempDir()
	_, _, sources := stubbedRelease(t, dir)
	download = func(url string) ([]byte, error) { return []byte("something else entirely"), nil }
	var log strings.Builder
	err := run(options{sourcesPath: sources, outDir: dir, cacheDir: dir, generated: "2026-09-16"}, &log)
	if err == nil {
		t.Fatal("a mismatched archive was accepted")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("err = %v, want one naming the digest", err)
	}
	if _, statErr := os.Stat(dir + "/ubuntu-22.04.json"); statErr == nil {
		t.Error("a list was written from an archive that failed its pin")
	}
}

// Two releases pin archives that share a file name and are different files —
// mtr-tiny_0.95-1_amd64.deb on Ubuntu is not the one on Debian. A cache keyed
// by the name alone would make each release evict the other's copy, so the
// digest leads the name.
func TestCacheNameSeparatesTwoArchivesWithOneFileName(t *testing.T) {
	a := suid.SourcePackage{Name: "mtr-tiny", URL: "http://a.invalid/pool/m/mtr/mtr-tiny_0.95-1_amd64.deb", SHA256: strings.Repeat("a", 64)}
	b := suid.SourcePackage{Name: "mtr-tiny", URL: "http://b.invalid/pool/m/mtr/mtr-tiny_0.95-1_amd64.deb", SHA256: strings.Repeat("b", 64)}
	if cacheName(a) == cacheName(b) {
		t.Fatalf("both archives cache as %q", cacheName(a))
	}
	// A URL-escaped Debian version must not put a stray character into a file
	// name; %2b and ~ are both ordinary in a .deb URL.
	esc := suid.SourcePackage{Name: "sudo", URL: "http://x.invalid/sudo_1.9.13p3-1%2bdeb12u4_amd64.deb", SHA256: strings.Repeat("c", 64)}
	for _, r := range cacheName(esc) {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-", r) {
			t.Errorf("cacheName(%q) = %q contains %q", esc.URL, cacheName(esc), r)
		}
	}
}

// -check on another day must still be usable: the date moves on every run by
// construction, so a run that differs in `generated` alone says so and
// passes, while anything else fails as before.
func TestCheckPassesWhenOnlyTheDateMoved(t *testing.T) {
	dir := t.TempDir()
	rel, out, sources := stubbedRelease(t, dir)
	want, _, err := assembleList(rel, "2026-09-16", "amd64", out)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := renderList(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ubuntu-22.04.json", blob, 0o644); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	o := options{sourcesPath: sources, outDir: dir, cacheDir: dir, arch: "amd64", check: true, generated: "2026-11-30"}
	if err := run(o, &log); err != nil {
		t.Fatalf("-check a day later: %v (%s)", err, log.String())
	}
	if !strings.Contains(log.String(), "2026-11-30") {
		t.Errorf("the run said nothing about the date it would have stamped: %s", log.String())
	}
}

// The image the tool ran is pinned to one architecture, because a
// distribution can ship a binary setuid on one and not on another. An image
// whose own uname disagrees with the pin is refused rather than written out
// under the wrong name.
func TestArchMismatchIsRefused(t *testing.T) {
	out := strings.Replace(string(sampleOutput(t)), "== arch\nx86_64", "== arch\naarch64", 1)
	if out == string(sampleOutput(t)) {
		t.Fatal("the sample carries no == arch section")
	}
	_, _, err := assembleList(sampleRelease(), "2026-09-16", "amd64", []byte(out))
	if err == nil || !strings.Contains(err.Error(), "aarch64") {
		t.Errorf("err = %v, want one naming the machine the image reported", err)
	}
	// And the pin is what lands in the list, under its Go name.
	l, _, err := assembleList(sampleRelease(), "2026-09-16", "amd64", sampleOutput(t))
	if err != nil || l.Arch != "amd64" {
		t.Errorf("arch = %q (%v), want amd64", l.Arch, err)
	}
}

// `docker image inspect` reports every repository the local image is known
// by. Taking the first would pin a list to whatever tag happened to be
// pulled alongside it, so the entry has to be the one for the image asked
// for — and no entry at all is a refusal, not a guess.
func TestImageDigestPicksTheMatchingRepository(t *testing.T) {
	repos := []string{
		"rockylinux/rockylinux@sha256:" + strings.Repeat("a", 64),
		"ubuntu@sha256:" + strings.Repeat("b", 64),
		"mymirror.invalid/ubuntu@sha256:" + strings.Repeat("c", 64),
	}
	for _, c := range []struct{ image, want string }{
		{"docker.io/library/ubuntu:22.04", "sha256:" + strings.Repeat("b", 64)},
		{"ubuntu:22.04", "sha256:" + strings.Repeat("b", 64)},
		{"docker.io/rockylinux/rockylinux:9", "sha256:" + strings.Repeat("a", 64)},
		{"mymirror.invalid/ubuntu:22.04", "sha256:" + strings.Repeat("c", 64)},
	} {
		got, err := matchingDigest(c.image, repos)
		if err != nil || got != c.want {
			t.Errorf("matchingDigest(%q) = (%q, %v), want %q", c.image, got, err, c.want)
		}
	}
	if got, err := matchingDigest("docker.io/library/debian:12", repos); err == nil {
		t.Errorf("matchingDigest(debian) = %q, want a refusal", got)
	}
	if _, err := matchingDigest("docker.io/library/ubuntu:22.04", nil); err == nil {
		t.Error("an image with no RepoDigests was accepted")
	}
}
