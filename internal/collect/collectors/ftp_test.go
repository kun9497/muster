//go:build linux

package collectors

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// ftpAccess builds the double for the ftp collector. Ruling I-20: every map
// a test of this collector reaches into is initialised here — a later
// `a.fails[…] = …`, `a.stats[…] = …` or `a.truncated[…] = …` on a nil map
// panics — and Ruling L-31: `stats` carries
// `kind: "dir"` for /run/systemd/system and `kind: "regular"` for every
// daemon binary, derived from the configuration files the fixture seeds,
// exactly as loggingAccess does.
//
// Ruling L-3: a configuration file names an implementation only when the
// daemon's BINARY is installed too, so a fixture that seeds one seeds the
// other; a test about a conffile left behind by a removed package deletes
// the binary again.
func ftpAccess(files map[string]string) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	stats := map[string]statResult{"/run/systemd/system": {mode: 0o755, kind: "dir"}}
	for p := range files {
		var bin string
		switch {
		case p == vsftpdDebianConf || p == vsftpdRhelConf:
			bin = vsftpdBin
		case p == proftpdDebianConf || p == proftpdRhelConf:
			bin = proftpdBin
		case p == pureFtpdConf || strings.HasPrefix(p, "/etc/pure-ftpd/conf/"):
			bin = pureFtpdBin
		default:
			continue
		}
		stats[bin] = statResult{mode: 0o755, kind: "regular"}
	}
	return &fsAccess{
		files:     files,
		cmds:      map[string]cmdResult{},
		fails:     map[string]error{},
		dirs:      map[string]bool{"/run/systemd/system": true},
		stats:     stats,
		truncated: map[string]bool{},
	}
}

// ftpJudgedLeaves are the leaves a control judges, as opposed to the
// evidence leaves (implementation, config_files, parse_complete,
// unmodelled) that stay ok whatever the parse found. Ruling L-4: a
// construct outside the model makes every one of them ABSENT.
var ftpJudgedLeaves = []string{
	"ftp.local_enabled",
	"ftp.anonymous_enabled",
	"ftp.tls_enforced",
	"ftp.tcp_wrappers",
	"ftp.userlist_enable",
	"ftp.userlist_deny",
	"ftp.userlist_file",
	"ftp.access_files",
	"ftp.access_file_present",
	"ftp.root_denied",
	"ftp.banner_source",
	"ftp.banner_text",
	"ftp.banner_discloses_version",
}

// ftpBool fetches an ok bool leaf, reporting the envelope rather than a bare
// "want true" when the collector degraded instead of answering.
func ftpBool(t *testing.T, b *collect.Builder, key string) bool {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v, want an ok bool", key, e)
	}
	v, ok := e.Value.(bool)
	if !ok {
		t.Fatalf("%s: value %#v is not a bool", key, e.Value)
	}
	return v
}

// Debian's stock file: anonymous off, local logins on, no TLS and no
// tcp_wrappers line at all, so tcp_wrappers falls to its compiled default NO.
func TestFtpVsftpdDebianStock(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.debian"})
	a.stats["/etc/vsftpd.user_list"] = statResult{mode: 0o600, kind: "regular"}
	b := buildBegun(t, "ftp", a)

	if e := env(t, b, "ftp.implementation"); e.Status != facts.StatusOK || e.Value != "vsftpd" {
		t.Fatalf("implementation %+v, want ok vsftpd", e)
	}
	for _, c := range []struct {
		key  string
		want bool
	}{
		{"ftp.local_enabled", true},
		{"ftp.anonymous_enabled", false},
		{"ftp.tls_enforced", false},
		{"ftp.tcp_wrappers", false},
		{"ftp.userlist_enable", false},
		{"ftp.userlist_deny", true},
	} {
		if got := ftpBool(t, b, c.key); got != c.want {
			t.Errorf("%s = %v, want %v", c.key, got, c.want)
		}
	}
	// The Debian build's user list is the flat /etc/vsftpd.user_list; the
	// value is that default only because the candidate exists.
	if e := env(t, b, "ftp.userlist_file"); e.Status != facts.StatusOK || e.Value != "/etc/vsftpd.user_list" {
		t.Errorf("userlist_file %+v, want the Debian default", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v", e)
	}
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("unmodelled %+v, want 0", e)
	}
	if got := stringList(t, b, "ftp.config_files"); !slices.Equal(got, []string{"/etc/vsftpd.conf"}) {
		t.Errorf("config_files %v", got)
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok`, w)
	}
}

// An empty configuration leaves anonymous_enable at the COMPILED default,
// which is YES in both builds (tunables.c). Debian's man page says
// "Default: NO" — a doc-only patch that never reached the code (Ruling
// L-25) — so a reader holding the man page must not "fix" this.
func TestFtpVsftpdAnonymousDefaultIsYes(t *testing.T) {
	b := build(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.anon-default"}))
	if !ftpBool(t, b, "ftp.anonymous_enabled") {
		t.Error("anonymous_enable unset must read as the compiled default YES")
	}
	// local_enable's compiled default is NO, and the same file sets neither.
	if ftpBool(t, b, "ftp.local_enabled") {
		t.Error("local_enable unset must read as the compiled default NO")
	}
	// No user list is configured and neither candidate is on disk: a path is
	// not invented.
	if e := env(t, b, "ftp.userlist_file"); e.Status != facts.StatusAbsent {
		t.Errorf("userlist_file %+v, want absent when no candidate exists", e)
	}
}

// ssl_enable=YES with the force_local_* defaults (both YES) enforces TLS on
// a local-only server; exempting the data channel does not.
func TestFtpVsftpdTLSEnforced(t *testing.T) {
	on := build(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.tls"}))
	if !ftpBool(t, on, "ftp.tls_enforced") {
		t.Error("ssl_enable=YES with the force_local_* defaults must enforce TLS")
	}
	off := build(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.tls-nodata"}))
	if ftpBool(t, off, "ftp.tls_enforced") {
		t.Error("force_local_data_ssl=NO leaves the transfer in clear: not enforced")
	}
}

// Ruling L-24: /etc/vsftpd/*.conf matches the main file itself, so only the
// OTHER matches are extra instances this model does not attribute.
func TestFtpVsftpdSecondInstanceIsUnmodelled(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd/vsftpd.conf": "vsftpd.conf.rhel",
		"/etc/vsftpd/extra.conf":  "vsftpd.conf.extra-instance",
	}))
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 (the extra instance only)", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v: the main file was read in full", e)
	}
	for _, k := range ftpJudgedLeaves {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent while an instance is unmodelled", k, e.Status)
		}
		if !strings.Contains(e.Reason, "/etc/vsftpd/extra.conf") {
			t.Errorf("%s reason %q must name the unmodelled instance", k, e.Reason)
		}
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok (absent ranks ok)`, w)
	}

	// A host carrying BOTH layouts: the Debian file wins the probe order, so
	// the RHEL one is a second instance like any other — the exclusion is
	// the file actually parsed, not a fixed path.
	both := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":        "vsftpd.conf.debian",
		"/etc/vsftpd/vsftpd.conf": "vsftpd.conf.rhel",
	}))
	if e := env(t, both, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the unparsed second layout", e)
	}
	if e := env(t, both, "ftp.anonymous_enabled"); e.Status != facts.StatusAbsent ||
		!strings.Contains(e.Reason, vsftpdRhelConf) {
		t.Errorf("anonymous_enabled %+v must be absent and name the second instance", e)
	}
}

// Ruling L-3 / the 2I IR-7 lesson: dpkg keeps the conffile after the package
// is removed, so a configuration file alone must never drive a verdict.
func TestFtpLeftoverConffileIsNotAnImplementation(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.rhel"})
	delete(a.stats, vsftpdBin) // the package was removed; the conffile stayed
	b := build(t, "ftp", a)
	e := env(t, b, "ftp.implementation")
	if e.Status != facts.StatusOK || e.Value != "none" {
		t.Fatalf("implementation %+v, want ok none", e)
	}
	if !strings.Contains(e.Reason, "/etc/vsftpd.conf") {
		t.Errorf("reason %q must name the leftover file", e.Reason)
	}
	for _, k := range ftpJudgedLeaves {
		if s := env(t, b, k).Status; s != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent: nothing serves FTP here", k, s)
		}
	}
}

// Ruling L-23: pure-ftpd is decided by its binary plus a readable
// pure-ftpd.conf OR a non-empty /etc/pure-ftpd/conf/* glob — never a
// directory stat, which the declaration does not cover.
func TestFtpPureFtpdDetectedByGlob(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/pure-ftpd/conf/NoAnonymous": "pure-ftpd.d_NoAnonymous",
		"/etc/pure-ftpd/conf/TLS":         "pure-ftpd.d_TLS",
	})
	b := build(t, "ftp", a)
	if e := env(t, b, "ftp.implementation"); e.Status != facts.StatusOK || e.Value != "pure-ftpd" {
		t.Fatalf("implementation %+v, want ok pure-ftpd", e)
	}
	// What ENFORCES L-23 is the guard: build() fails the test on any access
	// outside the declaration, and neither /etc/pure-ftpd nor
	// /etc/pure-ftpd/conf is declared, so a directory stat could not have
	// got this far. This scan of the read log is the second belt — it sees
	// ReadFile only.
	for _, r := range a.reads {
		if r == "/etc/pure-ftpd/conf" || r == "/etc/pure-ftpd" {
			t.Errorf("the model must not read %q — the declaration does not cover it", r)
		}
	}
	if ftpBool(t, b, "ftp.anonymous_enabled") {
		t.Error("NoAnonymous yes must read as anonymous disabled")
	}
	if ftpBool(t, b, "ftp.tls_enforced") {
		t.Error("TLS 1 still permits a cleartext session: not enforced")
	}
	if got := stringList(t, b, "ftp.config_files"); !slices.Equal(got,
		[]string{"/etc/pure-ftpd/conf/NoAnonymous", "/etc/pure-ftpd/conf/TLS"}) {
		t.Errorf("config_files %v, want both fragments sorted", got)
	}

	// The single-file (RHEL) style is the same model read from one file.
	one := build(t, "ftp", ftpAccess(map[string]string{"/etc/pure-ftpd/pure-ftpd.conf": "pure-ftpd.conf.stock"}))
	if !ftpBool(t, one, "ftp.tls_enforced") {
		t.Error("TLS 2 refuses a cleartext session: enforced")
	}
	// tcp_wrappers and the vsftpd user list are not pure-ftpd concepts.
	for _, k := range []string{"ftp.tcp_wrappers", "ftp.userlist_enable", "ftp.userlist_deny", "ftp.userlist_file"} {
		if s := env(t, one, k).Status; s != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent on pure-ftpd", k, s)
		}
	}
}

// proftpd's stock file has no <Anonymous> block; a <VirtualHost> that wraps
// a modelled directive is not attributed to the server (Ruling L-4).
func TestFtpProftpdStockAndVirtualHost(t *testing.T) {
	stock := build(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.stock"}))
	if e := env(t, stock, "ftp.implementation"); e.Status != facts.StatusOK || e.Value != "proftpd" {
		t.Fatalf("implementation %+v, want ok proftpd", e)
	}
	if ftpBool(t, stock, "ftp.anonymous_enabled") {
		t.Error("no <Anonymous> block means no anonymous login")
	}
	if !ftpBool(t, stock, "ftp.local_enabled") {
		t.Error("proftpd serves local accounts")
	}
	if ftpBool(t, stock, "ftp.tls_enforced") {
		t.Error("no TLSEngine means no TLS")
	}
	if e := env(t, stock, "ftp.unmodelled"); e.Value != 0 {
		t.Errorf("unmodelled %+v, want 0 on the stock file", e)
	}

	anon := build(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.anonymous"}))
	if !ftpBool(t, anon, "ftp.anonymous_enabled") {
		t.Error("an <Anonymous> block is an anonymous login")
	}

	vh := build(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.virtualhost"}))
	if e := env(t, vh, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the <VirtualHost> block", e)
	}
	for _, k := range ftpJudgedLeaves {
		e := env(t, vh, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent while a <VirtualHost> holds modelled directives", k, e.Status)
		}
		if !strings.Contains(e.Reason, "VirtualHost") {
			t.Errorf("%s reason %q must name the construct", k, e.Reason)
		}
	}
}

// Ruling L-5: a proftpd Include the declaration covers is read; one outside
// it is recorded and never touched.
func TestFtpProftpdIncludeIsDeclaredOrRecorded(t *testing.T) {
	in := build(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":    "proftpd.conf.include",
		"/etc/proftpd/conf.d/tls.conf": "proftpd.conf.d_tls",
	}))
	if !ftpBool(t, in, "ftp.tls_enforced") {
		t.Error("the declared fragment's TLSEngine/TLSRequired must be attributed")
	}
	if got := stringList(t, in, "ftp.config_files"); !slices.Equal(got,
		[]string{"/etc/proftpd/conf.d/tls.conf", "/etc/proftpd/proftpd.conf"}) {
		t.Errorf("config_files %v, want both files sorted", got)
	}

	a := ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.include-undeclared"})
	out := build(t, "ftp", a)
	if e := env(t, out, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the undeclared Include", e)
	}
	for _, r := range a.reads {
		if r == "/usr/local/etc/proftpd-site.conf" {
			t.Fatal("an undeclared Include must be recorded, never read")
		}
	}
	if e := env(t, out, "ftp.tls_enforced"); e.Status != facts.StatusAbsent ||
		!strings.Contains(e.Reason, "/usr/local/etc/proftpd-site.conf") {
		t.Errorf("tls_enforced %+v must be absent and name the include", e)
	}
}

// Every modelled proftpd directive read at the top level keeps the parse
// complete and the model attributed.
func TestFtpProftpdTopLevelDirectives(t *testing.T) {
	b := build(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.ident-off"}))
	if e := env(t, b, "ftp.unmodelled"); e.Value != 0 {
		t.Errorf("unmodelled %+v, want 0", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Value != true {
		t.Errorf("parse_complete %+v", e)
	}
	if !ftpBool(t, b, "ftp.tls_enforced") {
		t.Error("TLSEngine on + TLSRequired on at the top level enforce TLS")
	}
}

// Ruling L-35: a modelled directive is the SERVER's setting only at the top
// level. TLSRequired inside <Anonymous> covers the anonymous area alone, so
// a local login is still served in clear — attributing it would be a false
// PASS for U-54, which is the over-claim H-16 forbids. <Anonymous> and
// <Directory> are neutral containers: they hide what is inside them without
// making the file unjudgeable.
func TestFtpProftpdAttributesTopLevelOnly(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.anon-tls"}))
	if e := env(t, b, "ftp.tls_enforced"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("tls_enforced %+v, want ok false: TLSRequired is scoped to <Anonymous>", e)
	}
	if !ftpBool(t, b, "ftp.anonymous_enabled") {
		t.Error("the <Anonymous> opener is read at the top level and still names an anonymous login")
	}
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("unmodelled %+v, want 0: <Anonymous>, <Directory> and <Limit> are neutral containers", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Value != true {
		t.Errorf("parse_complete %+v", e)
	}

	// The same rule at the level below the published leaves, for the
	// directives Task 2 judges: only the top-level ones reach the model.
	pro := proftpdModelOf(t, ftpAccess(nil), "proftpd.conf.anon-tls")
	for _, k := range []string{"tlsengine", "useftpusers"} {
		if _, ok := pro[k]; !ok {
			t.Errorf("%s is at the top level and must be attributed", k)
		}
	}
	for _, k := range []string{"tlsrequired", "rootlogin"} {
		if v, ok := pro[k]; ok {
			t.Errorf("%s = %q was attributed from inside a section", k, v)
		}
	}
}

// proftpdModelOf parses one proftpd fixture through the collector's own
// parser and returns the directives it attributed to the SERVER. It reaches
// below the published leaves on purpose: RootLogin and UseFtpUsers are
// Task 2's, and the scope rule that decides them is this task's.
func proftpdModelOf(t *testing.T, a *fsAccess, fixture string) map[string]string {
	t.Helper()
	data, err := os.ReadFile("testdata/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	p := &ftpParse{a: a, seen: map[string]bool{}, pro: map[string]string{}}
	p.parseProftpd("/etc/proftpd/proftpd.conf", data, 0, nil)
	return p.pro
}

// Ruling L-37: the stock Debian proftpd.conf includes its fragment
// DIRECTORY by name, with no glob. The declaration covers that directory's
// contents, so the fragments are read rather than making every stock host
// unjudgeable.
func TestFtpProftpdDirectoryIncludeIsRead(t *testing.T) {
	empty := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.include-dir"}))
	if e := env(t, empty, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Fatalf("unmodelled %+v, want 0: an empty fragment directory is not a construct outside the model", e)
	}
	if e := env(t, empty, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v", e)
	}
	if e := env(t, empty, "ftp.tls_enforced"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("tls_enforced %+v, want ok false: nothing sets TLSRequired", e)
	}

	withFragment := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":           "proftpd.conf.include-dir",
		"/etc/proftpd/conf.d/10-tls-required": "proftpd.conf.d_tlsrequired",
	}))
	if !ftpBool(t, withFragment, "ftp.tls_enforced") {
		t.Error("a fragment's top-level TLSRequired completes the server's TLS requirement")
	}
	if got := stringList(t, withFragment, "ftp.config_files"); !slices.Equal(got,
		[]string{"/etc/proftpd/conf.d/10-tls-required", "/etc/proftpd/proftpd.conf"}) {
		t.Errorf("config_files %v, want both files sorted", got)
	}
}

// Ruling L-39: proftpd inlines an included file AT THE INCLUDE POINT, so a
// fragment pulled in from inside a section inherits that section's context.
// Parsing it at depth 0 would make a fragment's TLSRequired the server's
// answer — the same false PASS for U-54 that the top-level rule closed,
// reached through the include path.
func TestFtpProftpdIncludeInheritsTheIncludeSite(t *testing.T) {
	withFragment := func(main string) *fsAccess {
		return ftpAccess(map[string]string{
			"/etc/proftpd/proftpd.conf":  main,
			"/etc/proftpd/conf.d/10-tls": "proftpd.conf.d_tls-and-root",
		})
	}

	// Included from inside a <VirtualHost>: the fragment configures that
	// host, and the section is the construct this model does not attribute,
	// counted once.
	vh := buildBegun(t, "ftp", withFragment("proftpd.conf.include-in-vhost"))
	if e := env(t, vh, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the <VirtualHost> the fragment landed in", e)
	}
	e := env(t, vh, "ftp.tls_enforced")
	if e.Status != facts.StatusAbsent {
		t.Errorf("tls_enforced %+v, want absent: the fragment is a virtual host's", e)
	}
	if !strings.Contains(e.Reason, "VirtualHost") {
		t.Errorf("tls_enforced reason %q must name the section", e.Reason)
	}

	// Included from inside <Anonymous>: a neutral container, so nothing is
	// attributed and nothing is unmodelled — TLSEngine on alone does not
	// enforce TLS.
	anon := buildBegun(t, "ftp", withFragment("proftpd.conf.include-in-anon"))
	if e := env(t, anon, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Fatalf("unmodelled %+v, want ok 0: <Anonymous> is a neutral container", e)
	}
	if e := env(t, anon, "ftp.tls_enforced"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("tls_enforced %+v, want ok false", e)
	}
	pro := proftpdModelOf(t, withFragment("proftpd.conf.include-in-anon"), "proftpd.conf.include-in-anon")
	for _, k := range []string{"tlsrequired", "rootlogin"} {
		if v, ok := pro[k]; ok {
			t.Errorf("%s = %q was attributed from a fragment included inside <Anonymous>", k, v)
		}
	}

	// A top-level Include is unchanged: that fragment IS the server's.
	top := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":           "proftpd.conf.include-dir",
		"/etc/proftpd/conf.d/10-tls-required": "proftpd.conf.d_tlsrequired",
	}))
	if !ftpBool(t, top, "ftp.tls_enforced") {
		t.Error("a fragment included at the top level completes the server's TLS requirement")
	}
}

// Ruling L-40: a closing tag that does not match the innermost open section
// is a file proftpd itself refuses to start on. Popping blindly would
// re-attribute everything after it to the server; the honest answer is that
// the file cannot be modelled.
func TestFtpProftpdMismatchedCloseIsUnmodelled(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.mismatched-close"})
	b := buildBegun(t, "ftp", a)
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the mismatched closing tag", e)
	}
	if e := env(t, b, "ftp.tls_enforced"); e.Status != facts.StatusAbsent ||
		!strings.Contains(e.Reason, "</Limit>") {
		t.Errorf("tls_enforced %+v must be absent and name the line", e)
	}
	if v, ok := proftpdModelOf(t, a, "proftpd.conf.mismatched-close")["tlsrequired"]; ok {
		t.Errorf("tlsrequired = %q: the stray tag must not have popped the open section", v)
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok`, w)
	}
}

// Ruling L-41: the widened conf.d glob matches whatever is in the directory,
// including an admin's stash subdirectory. The read primitive refuses a
// non-regular file, and that refusal must SKIP the entry — one error
// envelope would flip run.complete and hand CI exit code 2 for a benign
// directory.
func TestFtpProftpdSkipsNonRegularFragments(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":           "proftpd.conf.include-dir",
		"/etc/proftpd/conf.d/10-tls-required": "proftpd.conf.d_tlsrequired",
	})
	a.dirs["/etc/proftpd/conf.d/disabled"] = true
	a.fails["/etc/proftpd/conf.d/disabled"] = fmt.Errorf("%s: %w", "/etc/proftpd/conf.d/disabled", collect.ErrNotRegular)
	b := buildBegun(t, "ftp", a)
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Fatalf("unmodelled %+v, want 0", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v, want ok true", e)
	}
	if !ftpBool(t, b, "ftp.tls_enforced") {
		t.Error("the regular fragment is still read")
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok: a stash directory is not an error`, w)
	}
}

// R70/Ruling L-38: the read primitive answers a file past the cap with the
// prefix, Truncated true and NO error, so a directive written past it is
// invisible and a confident answer built from the prefix is a false PASS.
func TestFtpTruncatedConfIsAbsent(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.debian"})
	a.truncated["/etc/vsftpd.conf"] = true
	b := buildBegun(t, "ftp", a)
	for _, k := range ftpJudgedLeaves {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent when the file was cut at the cap", k, e.Status)
		}
		if !strings.Contains(e.Reason, "/etc/vsftpd.conf") {
			t.Errorf("%s reason %q must name the file that was cut", k, e.Reason)
		}
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete %+v, want ok false", e)
	}
	if e := env(t, b, "ftp.config_files"); !e.Truncated {
		t.Errorf("config_files %+v must carry the truncation flag", e)
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok (absent ranks ok, the run stays complete)`, w)
	}
}

// The user list can be an ALLOW list, and an explicit userlist_file is the
// value — the distro default is only the fallback.
func TestFtpVsftpdUserlistAllowList(t *testing.T) {
	b := build(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.userlist-allow"}))
	if !ftpBool(t, b, "ftp.userlist_enable") {
		t.Error("userlist_enable=YES")
	}
	if ftpBool(t, b, "ftp.userlist_deny") {
		t.Error("userlist_deny=NO makes the list an allow list")
	}
	if e := env(t, b, "ftp.userlist_file"); e.Status != facts.StatusOK || e.Value != "/etc/vsftpd/allowed_users" {
		t.Errorf("userlist_file %+v, want the explicit path", e)
	}
}

// The RHEL build's default user list is /etc/vsftpd/user_list, chosen
// because that candidate is the one on disk.
func TestFtpVsftpdRhelUserlistDefault(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd/vsftpd.conf": "vsftpd.conf.rhel"})
	a.stats["/etc/vsftpd/user_list"] = statResult{mode: 0o600, kind: "regular"}
	b := build(t, "ftp", a)
	if e := env(t, b, "ftp.userlist_file"); e.Status != facts.StatusOK || e.Value != "/etc/vsftpd/user_list" {
		t.Errorf("userlist_file %+v, want the RHEL default", e)
	}
	if !ftpBool(t, b, "ftp.tcp_wrappers") {
		t.Error("tcp_wrappers=YES")
	}
	if !ftpBool(t, b, "ftp.anonymous_enabled") {
		t.Error("anonymous_enable=YES")
	}
}

// C3: a file that EXISTS but cannot be read is the answer for every value it
// could set — never the module's compiled default.
func TestFtpUnreadableConfIsDenied(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.debian"})
	a.fails["/etc/vsftpd.conf"] = unix.EACCES
	a.stats["/etc/vsftpd.conf"] = statResult{mode: 0o600, kind: "regular"}
	b := buildBegun(t, "ftp", a)
	if e := env(t, b, "ftp.implementation"); e.Value != "vsftpd" {
		t.Fatalf("implementation %+v: the binary and the file are both there", e)
	}
	for _, k := range ftpJudgedLeaves {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s = %s, want denied", k, e.Status)
		}
		if !strings.Contains(e.Reason, "/etc/vsftpd.conf") {
			t.Errorf("%s reason %q must name the file (C3)", k, e.Reason)
		}
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete %+v, want ok false", e)
	}
	// Ruling L-52 (C3, mail's L-49 shape): the file this collector knows is
	// there and could not open is not an ok empty list of configuration
	// files - an ok list asserts found AND readable.
	cf := env(t, b, "ftp.config_files")
	if cf.Status != facts.StatusDenied {
		t.Errorf("config_files %+v, want denied - never ok with the file silently omitted", cf)
	}
	if !strings.Contains(cf.Reason, "/etc/vsftpd.conf") {
		t.Errorf("config_files reason %q must name the file it could not open", cf.Reason)
	}
	// Ruling L-36: the Worst assertions elsewhere in this file are only
	// meaningful because this one shows the builder really does rank the
	// collector's envelopes — build(), which never calls Begin, reports ok
	// here whatever the collector wrote.
	if w := b.Worst("ftp"); w != facts.StatusDenied {
		t.Errorf(`Worst("ftp") = %s, want denied`, w)
	}
}

// A host with no FTP daemon at all: absent judged leaves, ok evidence and a
// complete run (Ruling L-7 — the collect contract must stay complete).
func TestFtpNoDaemonIsAbsentNotMissing(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(nil))
	if e := env(t, b, "ftp.implementation"); e.Status != facts.StatusOK || e.Value != "none" {
		t.Fatalf("implementation %+v, want ok none", e)
	}
	for _, k := range ftpJudgedLeaves {
		if s := env(t, b, k).Status; s != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent", k, s)
		}
	}
	if got := stringList(t, b, "ftp.config_files"); len(got) != 0 {
		t.Errorf("config_files %v, want an ok empty list", got)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v: there was nothing to fail to read", e)
	}
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("unmodelled %+v", e)
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok`, w)
	}
	// Ruling L-60: services.ftp.installed is TRUE on a host that only answers
	// on port 21, and that host reaches this same branch — no conffile of a
	// modelled daemon with its binary. The reason may therefore report what
	// this collector looked for and did not find; it may not tell the reader
	// no FTP daemon is installed, which the gate it is read beside denies.
	for _, k := range ftpJudgedLeaves {
		r := env(t, b, k).Reason
		if strings.Contains(r, "installed on this host") {
			t.Errorf("%s reason %q contradicts a port-21 listener with no modelled configuration", k, r)
		}
		if !strings.Contains(r, "no modelled FTP daemon configuration is present") {
			t.Errorf("%s reason %q must say what was looked for and not found", k, r)
		}
	}
}

// Ruling L-8: the three new rows are rows of the services TABLE, so they
// carry the table's shapes — five leaves each (a row with ports gets
// reachable), their units in the declaration derived from the table, and
// R239's no-systemd degradation for every one of the fifteen leaves.
func TestServicesFtpMailDnsRowsDegradeWithTheTable(t *testing.T) {
	want := []struct {
		name  string
		units []string
		ports []portSpec
	}{
		{"ftp", []string{"vsftpd.service", "vsftpd.socket", "proftpd.service", "proftpd.socket", "pure-ftpd.service"}, []portSpec{{"tcp", 21}}},
		{"mail", []string{"postfix.service", "postfix@-.service", "sendmail.service", "exim4.service", "exim.service"}, []portSpec{{"tcp", 25}}},
		{"dns", []string{"named.service", "bind9.service", "named-chroot.service", "unbound.service"}, []portSpec{{"udp", 53}, {"tcp", 53}}},
	}
	rows := map[string]logicalService{}
	for _, svc := range services {
		rows[svc.name] = svc
	}
	declared := map[string]bool{}
	for _, c := range declaredShowCommands() {
		declared[c.Args[len(c.Args)-1]] = true
	}
	b := buildBegun(t, "services", &fsAccess{}) // no /run/systemd/system
	for _, w := range want {
		row, ok := rows[w.name]
		if !ok {
			t.Fatalf("the services table has no %q row", w.name)
		}
		var units []string
		for _, u := range row.units {
			if !u.provesInstall {
				t.Errorf("%s: unit %s must prove installation (R63)", w.name, u.name)
			}
			if !declared[u.name] {
				t.Errorf("%s: unit %s is not in the declared systemctl commands", w.name, u.name)
			}
			units = append(units, u.name)
		}
		if !slices.Equal(units, w.units) {
			t.Errorf("%s units = %v, want %v", w.name, units, w.units)
		}
		if !slices.Equal(row.ports, w.ports) {
			t.Errorf("%s ports = %v, want %v", w.name, row.ports, w.ports)
		}
		for _, l := range []string{"installed", "active", "unit_file_state", "enabled", "reachable"} {
			k := "services." + w.name + "." + l
			if e := env(t, b, k); e.Status != facts.StatusUnsupported {
				t.Errorf("%s = %s, want unsupported on a host without systemd", k, e.Status)
			}
		}
	}
	// The ftp row is the one a super-server can host.
	if ftp := rows["ftp"]; !slices.Equal(ftp.inetdNames, []string{"ftp"}) ||
		!slices.Equal(ftp.servers, []string{"vsftpd", "proftpd", "in.ftpd", "pure-ftpd"}) {
		t.Errorf("ftp inetd hosting = %v / %v", ftp.inetdNames, ftp.servers)
	}
	if w := b.Worst("services"); w != facts.StatusOK {
		t.Errorf(`Worst("services") = %s, want ok`, w)
	}
}

// Ruling L-9/L-20: libwrap presence is anyPresent over the library's
// candidate paths — a symlink counts — and ok:false only when every
// candidate is ENOENT. There is no denied branch.
func TestFilesLibwrapPresent(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		stats: map[string]statResult{
			// The Debian multiarch path is usually a symlink to the
			// versioned object, and a symlink counts as present.
			"/usr/lib/x86_64-linux-gnu/libwrap.so.0": {mode: 0o777, kind: "symlink"},
		},
	}
	if e := env(t, build(t, "files", a), "files.libwrap_present"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("libwrap_present %+v, want ok true", e)
	}
	none := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	if e := env(t, build(t, "files", none), "files.libwrap_present"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("libwrap_present %+v, want ok false when every candidate is ENOENT", e)
	}
}

// Ruling L-42: the skip must key on the read primitive's whole non-regular
// class, not on ErrNotRegular alone. A socket answers open(2) with ENXIO and
// a path whose component was replaced answers ENOTDIR, and either would
// otherwise become an error envelope — run.complete false and CI exit code 2
// — for something that was never configuration.
func TestFtpProftpdSkipsEveryNonRegularFragment(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":           "proftpd.conf.include-dir",
		"/etc/proftpd/conf.d/10-tls-required": "proftpd.conf.d_tlsrequired",
	})
	// dirs is fsAccess's "occupies the path but is not a readable file" map,
	// which is what makes Glob match these entries at all; the error each
	// read answers with is what the collector has to classify.
	for _, e := range []struct {
		path string
		err  error
	}{
		{"/etc/proftpd/conf.d/control.sock", unix.ENXIO},
		{"/etc/proftpd/conf.d/queue.fifo", unix.EISDIR},
		{"/etc/proftpd/conf.d/vanished", unix.ENOTDIR},
	} {
		a.dirs[e.path] = true
		a.fails[e.path] = fmt.Errorf("%s: %w", e.path, e.err)
	}
	a.stats["/etc/proftpd/conf.d/control.sock"] = statResult{mode: 0o755, kind: "socket"}
	b := buildBegun(t, "ftp", a)
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Fatalf("unmodelled %+v, want 0", e)
	}
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v, want ok true", e)
	}
	if !ftpBool(t, b, "ftp.tls_enforced") {
		t.Error("the regular fragment is still read")
	}
	if w := b.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok: a socket under conf.d is not an error`, w)
	}
}

// Ruling L-42: the closing-tag guard is len(stack) > len(base), never
// len(stack) > 0. A fragment included from INSIDE a section may not close
// that section: popping it would attribute everything below the stray tag to
// the server, which is the false PASS L-35 closed, reached through the
// include path.
func TestFtpProftpdFragmentCannotCloseTheIncludersSection(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":    "proftpd.conf.include-in-anon",
		"/etc/proftpd/conf.d/10-stray": "proftpd.conf.d_stray-close",
	})
	b := buildBegun(t, "ftp", a)
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the stray closing tag", e)
	}
	e := env(t, b, "ftp.tls_enforced")
	if e.Status != facts.StatusAbsent {
		t.Errorf("tls_enforced %+v, want absent while the fragment cannot be modelled", e)
	}
	if !strings.Contains(e.Reason, "</Anonymous>") {
		t.Errorf("tls_enforced reason %q must name the stray tag", e.Reason)
	}
	// The load-bearing assertion: with the guard mutated to len(stack) > 0 the
	// fragment's TLSRequired becomes the SERVER's answer.
	if v, ok := proftpdModelOf(t, a, "proftpd.conf.include-in-anon")["tlsrequired"]; ok {
		t.Errorf("tlsrequired = %q: the fragment popped its includer's section", v)
	}
}

// Ruling L-42, mirroring L-40: a section still open at end of file is a file
// proftpd refuses to start on. The reason names the section, and a fragment
// is judged against its OWN base, so a fragment that closes everything it
// opened is complete even when its includer left a section open around it.
func TestFtpProftpdUnclosedSectionIsUnmodelled(t *testing.T) {
	main := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf": "proftpd.conf.unclosed",
	}))
	if e := env(t, main, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the unclosed section", e)
	}
	for _, k := range ftpJudgedLeaves {
		e := env(t, main, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent while a section is left open", k, e.Status)
		}
		if !strings.Contains(e.Reason, "<Anonymous>") {
			t.Errorf("%s reason %q must name the unclosed section", k, e.Reason)
		}
	}
	if w := main.Worst("ftp"); w != facts.StatusOK {
		t.Errorf(`Worst("ftp") = %s, want ok`, w)
	}

	frag := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf":       "proftpd.conf.include-dir",
		"/etc/proftpd/conf.d/10-unclosed": "proftpd.conf.d_unclosed",
	}))
	if e := env(t, frag, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the fragment's unclosed section", e)
	}
	e := env(t, frag, "ftp.tls_enforced")
	if !strings.Contains(e.Reason, "/etc/proftpd/conf.d/10-unclosed") ||
		!strings.Contains(e.Reason, "<Directory>") {
		t.Errorf("tls_enforced reason %q must name the fragment and the section", e.Reason)
	}
}

// ftpAccessRow fetches one ftp.access_files record by path, failing the test
// rather than panicking when the collector published something else.
func ftpAccessRow(t *testing.T, b *collect.Builder, want string) map[string]any {
	t.Helper()
	for _, v := range okList(t, b, "ftp.access_files") {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("ftp.access_files element %#v is not a record", v)
		}
		if rec["path"] == want {
			return rec
		}
	}
	t.Fatalf("ftp.access_files has no row for %s (rows %v)", want, ftpAccessPaths(t, b))
	return nil
}

// ftpAccessPaths is every access-file row's path, in publication order, so a
// test can pin both the membership and the sort.
func ftpAccessPaths(t *testing.T, b *collect.Builder) []string {
	t.Helper()
	out := []string{}
	for _, v := range okList(t, b, "ftp.access_files") {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("ftp.access_files element %#v is not a record", v)
		}
		p, _ := rec["path"].(string)
		out = append(out, p)
	}
	return out
}

// ftpRowField asserts one record field, reporting the whole row on a
// mismatch so a wrong role or a stat that did not land is visible at once.
func ftpRowField(t *testing.T, rec map[string]any, field string, want any) {
	t.Helper()
	if got := rec[field]; got != want {
		t.Errorf("%v: %s = %#v, want %#v", rec["path"], field, got, want)
	}
}

// Ruling L-21: the deny source is /etc/pam.d/ + pam_service_name, and the
// list it names carries the permission fields U-56 judges. Ruling L-15: mode
// is the INT of the raw 0o7777 bits, exactly as writePermFacts stores it, so
// 0640 is 416.
func TestFtpAccessFilesDebianPamDeny(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
		"/etc/ftpusers":     "ftpusers.root",
	})
	a.stats["/etc/ftpusers"] = statResult{mode: 0o640, uid: 0, gid: 42, kind: "regular"}
	b := buildBegun(t, "ftp", a)

	if got := ftpAccessPaths(t, b); !slices.Equal(got, []string{"/etc/ftpusers"}) {
		t.Fatalf("access_files paths %v, want the PAM list alone", got)
	}
	rec := ftpAccessRow(t, b, "/etc/ftpusers")
	for _, c := range []struct {
		field string
		want  any
	}{
		{"role", "pam_deny"},
		{"exists", true},
		{"root_listed", true},
		{"stat_status", "ok"},
		{"mode", 416},
		{"uid", 0},
		{"gid", 42},
	} {
		ftpRowField(t, rec, c.field, c.want)
	}
	if !ftpBool(t, b, "ftp.access_file_present") {
		t.Error("access_file_present must be true when a row exists")
	}
	e := env(t, b, "ftp.root_denied")
	if e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("root_denied %+v, want ok true", e)
	}
	if !strings.Contains(e.Reason, "/etc/ftpusers") {
		t.Errorf("root_denied reason %q must name the file that denies root", e.Reason)
	}
	// The pam.d file is a SOURCE, not an access file: /etc/pam.d/vsftpd is
	// 0644 on every Debian host, and recording it as a row would fail U-56
	// for a permission that is correct.
	if got := ftpAccessPaths(t, b); slices.Contains(got, "/etc/pam.d/vsftpd") {
		t.Errorf("access_files %v must not carry the pam.d service file itself", got)
	}
}

// The RHEL shape: PAM names /etc/vsftpd/ftpusers and userlist_enable=YES adds
// the build's own user list, so there are two rows, sorted by path.
func TestFtpAccessFilesRhelUserlistDeny(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/vsftpd/vsftpd.conf": "vsftpd.conf.rhel",
		"/etc/pam.d/vsftpd":       "pam.d.vsftpd.rhel",
		"/etc/vsftpd/ftpusers":    "ftpusers.root",
		"/etc/vsftpd/user_list":   "user_list.noroot",
	})
	b := buildBegun(t, "ftp", a)
	if got := ftpAccessPaths(t, b); !slices.Equal(got,
		[]string{"/etc/vsftpd/ftpusers", "/etc/vsftpd/user_list"}) {
		t.Fatalf("access_files paths %v, want both files sorted", got)
	}
	ftpRowField(t, ftpAccessRow(t, b, "/etc/vsftpd/ftpusers"), "role", "pam_deny")
	ftpRowField(t, ftpAccessRow(t, b, "/etc/vsftpd/ftpusers"), "root_listed", true)
	ftpRowField(t, ftpAccessRow(t, b, "/etc/vsftpd/user_list"), "role", "userlist_deny")
	ftpRowField(t, ftpAccessRow(t, b, "/etc/vsftpd/user_list"), "root_listed", false)
	if e := env(t, b, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("root_denied %+v, want ok true: the PAM list names root", e)
	}
}

// userlist_deny=NO turns the same file into an ALLOW list, which refuses every
// account it does not name: root absent from it DENIES root, and root present
// in it permits root. The deny reading of the same file is the opposite
// verdict, so this is the assertion that catches a flipped semantics.
func TestFtpUserlistAllowSemantics(t *testing.T) {
	withList := func(list string) *fsAccess {
		return ftpAccess(map[string]string{
			"/etc/vsftpd.conf":      "vsftpd.conf.userlist-allow-declared",
			"/etc/pam.d/vsftpd":     "pam.d.vsftpd.nolistfile",
			"/etc/vsftpd/user_list": list,
		})
	}
	off := buildBegun(t, "ftp", withList("user_list.noroot"))
	ftpRowField(t, ftpAccessRow(t, off, "/etc/vsftpd/user_list"), "role", "userlist_allow")
	if e := env(t, off, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("root_denied %+v, want ok true: an allow list that omits root refuses it", e)
	}
	on := buildBegun(t, "ftp", withList("user_list.root"))
	if e := env(t, on, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("root_denied %+v, want ok false: the allow list names root", e)
	}

	// The same file read as a DENY list, which is what userlist_deny leaves
	// it: now naming root is what refuses root, and omitting it is not.
	denyList := func(list string) *fsAccess {
		return ftpAccess(map[string]string{
			"/etc/vsftpd.conf":      "vsftpd.conf.userlist-deny",
			"/etc/pam.d/vsftpd":     "pam.d.vsftpd.nolistfile",
			"/etc/vsftpd/user_list": list,
		})
	}
	named := buildBegun(t, "ftp", denyList("user_list.root"))
	ftpRowField(t, ftpAccessRow(t, named, "/etc/vsftpd/user_list"), "role", "userlist_deny")
	if e := env(t, named, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("root_denied %+v, want ok true: the deny list names root", e)
	}
	if e := env(t, buildBegun(t, "ftp", denyList("user_list.noroot")), "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("root_denied %+v, want ok false: the deny list omits root", e)
	}

	// The same semantics reached through PAM: sense=allow over a declared file.
	pam := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":      "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd":     "pam.d.vsftpd.allow",
		"/etc/vsftpd/user_list": "user_list.noroot",
	}))
	ftpRowField(t, ftpAccessRow(t, pam, "/etc/vsftpd/user_list"), "role", "pam_allow")
	if e := env(t, pam, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("root_denied %+v, want ok true: pam_listfile sense=allow omits root", e)
	}
}

// Nothing denies root and nothing allow-lists anyone: a definite finding, not
// an absent leaf. A deny list that exists and simply does not name root is the
// same answer, and its row still carries the permissions U-56 judges.
func TestFtpRootNotDeniedIsFalse(t *testing.T) {
	none := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.nolistfile",
	}))
	if e := env(t, none, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != false {
		t.Fatalf("root_denied %+v, want ok false when no list denies root", e)
	}
	if got := ftpAccessPaths(t, none); len(got) != 0 {
		t.Errorf("access_files %v, want an ok empty list", got)
	}
	if e := env(t, none, "ftp.access_file_present"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("access_file_present %+v, want ok false", e)
	}

	listed := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
		"/etc/ftpusers":     "ftpusers.noroot",
	}))
	if e := env(t, listed, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("root_denied %+v, want ok false: the list exists and omits root", e)
	}
}

// local_enable=NO refuses every local account, root included, whatever the
// lists say.
func TestFtpLocalDisabledDeniesRoot(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.anon-only",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.nolistfile",
	}))
	e := env(t, b, "ftp.root_denied")
	if e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("root_denied %+v, want ok true", e)
	}
	if !strings.Contains(e.Reason, "local") {
		t.Errorf("root_denied reason %q must say local logins are disabled", e.Reason)
	}
}

// Rulings L-21 and L-22: pam_service_name picks the pam.d file, and both a
// service name and a listfile path outside the declaration are RECORDED and
// never opened - a path muster's change control never approved is not a path
// it reads.
func TestFtpUndeclaredPamListfileIsRecorded(t *testing.T) {
	ftpService := ftpAccess(map[string]string{
		"/etc/vsftpd.conf": "vsftpd.conf.pam-ftp",
		"/etc/pam.d/ftp":   "pam.d.ftp.debian",
		"/etc/ftpusers":    "ftpusers.root",
	})
	b := buildBegun(t, "ftp", ftpService)
	if e := env(t, b, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("root_denied %+v, want ok true through /etc/pam.d/ftp", e)
	}
	if slices.Contains(ftpService.reads, "/etc/pam.d/vsftpd") {
		t.Error("pam_service_name=ftp must not send the collector to /etc/pam.d/vsftpd")
	}

	site := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.pam-other"})
	other := buildBegun(t, "ftp", site)
	// Ruling L-43: the service file the collector never opened poisons the
	// whole access picture, not root_denied alone.
	ftpAccessLeavesBlocked(t, other, facts.StatusAbsent, "/etc/pam.d/vsftpd-site")
	if slices.Contains(site.reads, "/etc/pam.d/vsftpd-site") {
		t.Error("an undeclared PAM service file must be recorded, never read")
	}

	undeclared := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.undeclared",
	})
	out := buildBegun(t, "ftp", undeclared)
	ftpAccessLeavesBlocked(t, out, facts.StatusAbsent, "/etc/vsftpd/deny_users")
	if slices.Contains(undeclared.reads, "/etc/vsftpd/deny_users") {
		t.Error("an undeclared listfile must be recorded, never read")
	}
}

// A deny list that STATS but cannot be READ: the permission fields are known,
// so U-56 can still judge them, the content is not, and root_denied is absent
// rather than a confident false.
func TestFtpAccessFileStatOkButReadDenied(t *testing.T) {
	a := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
		"/etc/ftpusers":     "ftpusers.root",
	})
	a.stats["/etc/ftpusers"] = statResult{mode: 0o600, uid: 0, gid: 0, kind: "regular"}
	a.fails["/etc/ftpusers"] = unix.EACCES
	b := buildBegun(t, "ftp", a)
	rec := ftpAccessRow(t, b, "/etc/ftpusers")
	ftpRowField(t, rec, "stat_status", "ok")
	ftpRowField(t, rec, "exists", true)
	ftpRowField(t, rec, "mode", 384)
	ftpRowField(t, rec, "root_listed", false)
	if _, ok := rec["reason"]; !ok {
		t.Errorf("%v carries no reason for the read it could not do", rec["path"])
	}
	e := env(t, b, "ftp.root_denied")
	if e.Status != facts.StatusAbsent {
		t.Fatalf("root_denied %+v, want absent: the only deny list could not be read", e)
	}
	if !strings.Contains(e.Reason, "/etc/ftpusers") {
		t.Errorf("root_denied reason %q must name the file", e.Reason)
	}
	// The run stays complete: an unreadable ftpusers says nothing about
	// anonymous logins, and C3 binds a file to the values it could set.
	if e := env(t, b, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v, want ok true", e)
	}
	if s := env(t, b, "ftp.anonymous_enabled").Status; s != facts.StatusOK {
		t.Errorf("anonymous_enabled = %s, want ok: the access list cannot set it", s)
	}
}

// The greeting: ftpd_banner wins over banner_file, a custom line that does not
// name the product is not a disclosure, and an unset banner is the compiled
// greeting, whose text is NOT invented.
func TestFtpBannerDisclosure(t *testing.T) {
	unset := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.nolistfile",
	}))
	if e := env(t, unset, "ftp.banner_source"); e.Status != facts.StatusOK || e.Value != "default" {
		t.Fatalf("banner_source %+v, want ok default", e)
	}
	e := env(t, unset, "ftp.banner_text")
	if e.Status != facts.StatusOK || e.Value != "" {
		t.Errorf("banner_text %+v, want an ok empty string: the compiled text is not invented", e)
	}
	if !strings.Contains(strings.ToLower(e.Reason), "vsftpd") {
		t.Errorf("banner_text reason %q must name the product whose greeting is served", e.Reason)
	}
	if !ftpBool(t, unset, "ftp.banner_discloses_version") {
		t.Error("vsftpd's compiled greeting names the product")
	}

	plain := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.banner"}))
	if e := env(t, plain, "ftp.banner_source"); e.Value != "ftpd_banner" {
		t.Errorf("banner_source %+v, want ftpd_banner", e)
	}
	if e := env(t, plain, "ftp.banner_text"); e.Value != "Welcome. Authorized use only." {
		t.Errorf("banner_text %+v", e)
	}
	if ftpBool(t, plain, "ftp.banner_discloses_version") {
		t.Error("a custom greeting that names no product is not a disclosure")
	}

	named := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.banner-version"}))
	if !ftpBool(t, named, "ftp.banner_discloses_version") {
		t.Error("a greeting naming vsFTPd discloses the product")
	}

	file := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf": "vsftpd.conf.banner-file",
		"/etc/issue.net":   "issue_net",
	}))
	if e := env(t, file, "ftp.banner_source"); e.Value != "banner_file" {
		t.Errorf("banner_source %+v, want banner_file", e)
	}
	if e := env(t, file, "ftp.banner_text"); e.Status != facts.StatusOK ||
		!strings.Contains(fmt.Sprint(e.Value), "Authorized use only") {
		t.Errorf("banner_text %+v, want the file's text", e)
	}
	if ftpBool(t, file, "ftp.banner_discloses_version") {
		t.Error("the banner file names no product")
	}

	fileNamed := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf": "vsftpd.conf.banner-file",
		"/etc/issue.net":   "vsftpd.banner.version",
	}))
	if !ftpBool(t, fileNamed, "ftp.banner_discloses_version") {
		t.Error("a banner FILE naming vsFTPd discloses the product too")
	}

	// Ruling L-5: a banner file outside the declaration is recorded and never
	// opened, so its text and the verdict built on it are absent.
	site := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.banner-file-undeclared"})
	outside := buildBegun(t, "ftp", site)
	if e := env(t, outside, "ftp.banner_source"); e.Status != facts.StatusOK || e.Value != "banner_file" {
		t.Errorf("banner_source %+v, want ok banner_file", e)
	}
	for _, k := range []string{"ftp.banner_text", "ftp.banner_discloses_version"} {
		e := env(t, outside, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent", k, e.Status)
		}
		if !strings.Contains(e.Reason, "/srv/ftp/welcome.txt") {
			t.Errorf("%s reason %q must name the file it did not read", k, e.Reason)
		}
	}
	if slices.Contains(site.reads, "/srv/ftp/welcome.txt") {
		t.Error("an undeclared banner file must be recorded, never read")
	}
}

// proftpd: ServerIdent decides the greeting and RootLogin decides the root
// login, both at the top level only (Ruling L-35). /etc/ftpusers is an access
// file whenever UseFtpUsers is not off.
func TestFtpProftpdIdentAndRootLogin(t *testing.T) {
	stock := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.stock"}))
	if e := env(t, stock, "ftp.banner_source"); e.Status != facts.StatusOK || e.Value != "default" {
		t.Fatalf("banner_source %+v, want ok default when ServerIdent is unset", e)
	}
	if !ftpBool(t, stock, "ftp.banner_discloses_version") {
		t.Error("proftpd's default identification names the product")
	}
	e := env(t, stock, "ftp.root_denied")
	if e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("root_denied %+v, want ok true: RootLogin defaults to off", e)
	}
	if !strings.Contains(e.Reason, "RootLogin") {
		t.Errorf("root_denied reason %q must name the directive", e.Reason)
	}
	// UseFtpUsers is on, so /etc/ftpusers is an access file even when it is
	// not there - and an absent row never claims mode 0 owned by root (L-15).
	rec := ftpAccessRow(t, stock, "/etc/ftpusers")
	ftpRowField(t, rec, "role", "ftpusers")
	ftpRowField(t, rec, "stat_status", "absent")
	ftpRowField(t, rec, "exists", false)
	ftpRowField(t, rec, "mode", -1)
	ftpRowField(t, rec, "uid", -1)
	ftpRowField(t, rec, "gid", -1)
	if e := env(t, stock, "ftp.access_file_present"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("access_file_present %+v, want ok false", e)
	}

	off := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.ident-off"}))
	if e := env(t, off, "ftp.banner_source"); e.Value != "serverident" {
		t.Errorf("banner_source %+v, want serverident", e)
	}
	if ftpBool(t, off, "ftp.banner_discloses_version") {
		t.Error("ServerIdent off suppresses the product name")
	}

	root := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/proftpd/proftpd.conf": "proftpd.conf.rootlogin-on"}))
	if e := env(t, root, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("root_denied %+v, want ok false: RootLogin on and no list names root", e)
	}
	if e := env(t, root, "ftp.banner_text"); e.Status != facts.StatusOK || e.Value != "FTP service ready" {
		t.Errorf("banner_text %+v, want the quoted identification string", e)
	}
	if ftpBool(t, root, "ftp.banner_discloses_version") {
		t.Error("a custom identification string that names no product is not a disclosure")
	}

	listed := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf": "proftpd.conf.rootlogin-on",
		"/etc/ftpusers":             "ftpusers.root",
	}))
	if e := env(t, listed, "ftp.root_denied"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("root_denied %+v, want ok true: /etc/ftpusers names root", e)
	}
}

// pure-ftpd refuses every account below MinUID, which is at least 1 in every
// build, so root cannot log in at all; its greeting is not configurable in
// this model, so the banner leaves are absent rather than guessed.
func TestFtpPureFtpdRootAndBanner(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/pure-ftpd/pure-ftpd.conf": "pure-ftpd.conf.stock"}))
	e := env(t, b, "ftp.root_denied")
	if e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("root_denied %+v, want ok true", e)
	}
	if !strings.Contains(e.Reason, "MinUID") {
		t.Errorf("root_denied reason %q must name the evidence", e.Reason)
	}
	for _, k := range []string{"ftp.banner_source", "ftp.banner_text", "ftp.banner_discloses_version"} {
		if s := env(t, b, k).Status; s != facts.StatusAbsent {
			t.Errorf("%s = %s, want absent on pure-ftpd", k, s)
		}
	}
	if got := ftpAccessPaths(t, b); len(got) != 0 {
		t.Errorf("access_files %v, want an ok empty list", got)
	}
}

// ftpAccessLeavesBlocked asserts that all three access leaves carry the same
// status and name the source that could not be examined. Ruling L-43: a set
// that could not be COMPLETED is not evidence a control may judge, however
// clean the rows the collector did reach.
func ftpAccessLeavesBlocked(t *testing.T, b *collect.Builder, status facts.Status, name string) {
	t.Helper()
	for _, k := range []string{"ftp.access_files", "ftp.access_file_present", "ftp.root_denied"} {
		e := env(t, b, k)
		if e.Status != status {
			t.Errorf("%s = %s, want %s", k, e.Status, status)
		}
		if !strings.Contains(e.Reason, name) {
			t.Errorf("%s reason %q must name %s", k, e.Reason, name)
		}
	}
}

// Ruling L-43/L-44: a blind access source or a row the collector could not
// examine degrades access_files, access_file_present AND root_denied. U-56
// must never PASS over a list nobody opened, and must never FAIL on a blind
// spot either.
func TestFtpBlindAccessSourceDegradesEveryLeaf(t *testing.T) {
	// A clean, readable user list beside a PAM service file the declaration
	// does not cover. The row that WAS examined must not turn the set into
	// evidence: the site's own deny list could be world-writable.
	withList := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":      "vsftpd.conf.pam-other-userlist",
		"/etc/vsftpd/user_list": "user_list.noroot",
	}))
	ftpAccessLeavesBlocked(t, withList, facts.StatusAbsent, "/etc/pam.d/vsftpd-site")

	// The same host with no user list at all: still absent, never the
	// affirmative "names no per-account access list" that would FAIL U-56 on
	// a file the collector never opened.
	bare := buildBegun(t, "ftp", ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.pam-other"}))
	ftpAccessLeavesBlocked(t, bare, facts.StatusAbsent, "/etc/pam.d/vsftpd-site")

	// An UNDECLARED row beside a clean one: `where exists eq true` would drop
	// it silently and let the clean row carry the control.
	mixed := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":      "vsftpd.conf.userlist-deny",
		"/etc/pam.d/vsftpd":     "pam.d.vsftpd.undeclared",
		"/etc/vsftpd/user_list": "user_list.noroot",
	})
	mb := buildBegun(t, "ftp", mixed)
	ftpAccessLeavesBlocked(t, mb, facts.StatusAbsent, "/etc/vsftpd/deny_users")
	if slices.Contains(mixed.reads, "/etc/vsftpd/deny_users") {
		t.Error("an undeclared listfile must be recorded, never read")
	}

	// A denied STAT is the same blind spot: the permission fields U-56 judges
	// were never obtained.
	denied := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
	})
	denied.fails["/etc/ftpusers"] = unix.EACCES
	ftpAccessLeavesBlocked(t, buildBegun(t, "ftp", denied), facts.StatusAbsent, "/etc/ftpusers")

	// C3: a denied read of the PAM service file itself carries the READ's
	// status, not a bare absence - an operator needs to see it is a privilege
	// problem and not a host without FTP access control.
	pamDenied := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
	})
	pamDenied.fails["/etc/pam.d/vsftpd"] = unix.EACCES
	ftpAccessLeavesBlocked(t, buildBegun(t, "ftp", pamDenied), facts.StatusDenied, "/etc/pam.d/vsftpd")

	// Ruling L-46: the PAM service file was READ, but the read stopped at the
	// cap, so a pam_listfile line past it names a list nobody has seen. The
	// deny line before the cap is not licence to call the set complete.
	pamCut := ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.debian",
		"/etc/ftpusers":     "ftpusers.root",
	})
	pamCut.truncated["/etc/pam.d/vsftpd"] = true
	cut := buildBegun(t, "ftp", pamCut)
	ftpAccessLeavesBlocked(t, cut, facts.StatusAbsent, "/etc/pam.d/vsftpd was cut at the read limit")
	// The configuration files themselves were read in full: only the PAM
	// stack was cut, and that is an access-set blind spot, not a parse one.
	if e := env(t, cut, "ftp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v: vsftpd.conf itself was read in full", e)
	}

	// Ruling L-46: an oversized userlist_file names a list this collector
	// cannot even identify, so the set is incomplete - never an ok list
	// carrying only the rows some OTHER source happened to name.
	over := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf": "vsftpd.conf.userlist-oversized",
	}))
	ftpAccessLeavesBlocked(t, over, facts.StatusAbsent, "longer than this collector stores")
	// The leaf and the set agree about the same blind spot.
	if e := env(t, over, "ftp.userlist_file"); e.Status != facts.StatusAbsent {
		t.Errorf("userlist_file %+v, want absent alongside the set", e)
	}
}

// Ruling L-45: a pam_listfile.so line refuses a login only when its control
// field makes a failure refuse one, it filters on the account name, it names
// a sense, and it applies to everybody. A line that fails any of those is
// still recorded - it names a real list whose permissions U-56 judges - but
// it cannot decide root_denied, which is then absent naming the construct.
func TestFtpPamListfileControlFlags(t *testing.T) {
	for _, c := range []struct {
		fixture string
		names   string
	}{
		{"pam.d.vsftpd.optional", "optional"},
		{"pam.d.vsftpd.bracket", "default=ignore"},
		{"pam.d.vsftpd.apply", "apply="},
		{"pam.d.vsftpd.nosense", "sense="},
		// Ruling L-46: a line that names a sense but no item= is refused for
		// the MISSING item, and the reason must name that construct - not the
		// sense= the line does carry.
		{"pam.d.vsftpd.noitem", "item="},
	} {
		b := buildBegun(t, "ftp", ftpAccess(map[string]string{
			"/etc/vsftpd.conf":  "vsftpd.conf.debian",
			"/etc/pam.d/vsftpd": c.fixture,
			"/etc/ftpusers":     "ftpusers.root",
		}))
		e := env(t, b, "ftp.root_denied")
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s: root_denied %+v, want absent: the line cannot refuse a login on its own", c.fixture, e)
		}
		if !strings.Contains(e.Reason, c.names) {
			t.Errorf("%s: root_denied reason %q must name the construct", c.fixture, e.Reason)
		}
		// The file is still a row: U-56 judges a list's permissions whatever
		// the PAM line does with it, and its stat succeeded.
		ftpRowField(t, ftpAccessRow(t, b, "/etc/ftpusers"), "role", "pam_deny")
		ftpRowField(t, ftpAccessRow(t, b, "/etc/ftpusers"), "stat_status", "ok")
	}

	// item=group names a list of GROUPS. It can still refuse root, so it is
	// not ignored - but it is not a per-account list either, and judging its
	// permissions as one would be a finding about the wrong file.
	group := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":  "vsftpd.conf.debian",
		"/etc/pam.d/vsftpd": "pam.d.vsftpd.group",
		"/etc/ftpusers":     "ftpusers.root",
	}))
	ftpAccessLeavesBlocked(t, group, facts.StatusAbsent, "item=group")
}

// A RootLogin argument proftpd itself refuses to start on is a construct
// outside the model, not the default off: reading it as off would be a
// confident verdict on a configuration that cannot run.
func TestFtpProftpdUnrecognisedRootLoginIsUnmodelled(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/proftpd/proftpd.conf": "proftpd.conf.rootlogin-garbage",
	}))
	if e := env(t, b, "ftp.unmodelled"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Fatalf("unmodelled %+v, want ok 1 for the unrecognised RootLogin", e)
	}
	e := env(t, b, "ftp.root_denied")
	if e.Status != facts.StatusAbsent {
		t.Errorf("root_denied %+v, want absent", e)
	}
	if !strings.Contains(e.Reason, "RootLogin") {
		t.Errorf("root_denied reason %q must name the directive", e.Reason)
	}
}

// One file named twice with OPPOSITE senses keeps both rows: dropping either
// would hide half of what decides the login, and a last-wins would turn an
// allow list into a deny list on a reader's screen.
func TestFtpAccessRowsKeepBothSenses(t *testing.T) {
	b := buildBegun(t, "ftp", ftpAccess(map[string]string{
		"/etc/vsftpd.conf":      "vsftpd.conf.userlist-deny",
		"/etc/pam.d/vsftpd":     "pam.d.vsftpd.allow",
		"/etc/vsftpd/user_list": "user_list.root",
	}))
	if got := ftpAccessPaths(t, b); !slices.Equal(got,
		[]string{"/etc/vsftpd/user_list", "/etc/vsftpd/user_list"}) {
		t.Fatalf("access_files paths %v, want the file once per role it plays", got)
	}
	roles := []string{}
	for _, v := range okList(t, b, "ftp.access_files") {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("access_files element %#v is not a record", v)
		}
		roles = append(roles, fmt.Sprint(rec["role"]))
	}
	if !slices.Equal(roles, []string{"pam_allow", "userlist_deny"}) {
		t.Errorf("roles %v, want both senses kept and ordered", roles)
	}
}

// An oversized userlist_file makes the LEAF absent, so the row must not fall
// through to a build default the configuration never named - the two would
// then disagree about which file vsftpd reads.
func TestFtpOversizedUserlistFileNamesNoRow(t *testing.T) {
	// The build default is ON DISK, so falling through would find a real
	// path and publish a row for it.
	a := ftpAccess(nil)
	a.stats[vsftpdDebianUserList] = statResult{mode: 0o600, kind: "regular"}
	p := &ftpParse{
		a:      a,
		vsftpd: map[string]string{"userlist_file": "/etc/vsftpd/" + strings.Repeat("a", maxTokenValue)},
	}
	if got, ok := p.userlistPath(); ok {
		t.Errorf("userlistPath = %q, want no path: the value is longer than this collector stores", got)
	}
	if e := p.userlistFile(nil); e.Status != facts.StatusAbsent {
		t.Errorf("userlist_file %+v, want absent - the leaf and the row must agree", e)
	}
}
