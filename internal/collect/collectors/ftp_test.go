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
