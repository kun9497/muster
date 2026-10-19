//go:build linux

package remedy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// The content bodies (3D-2d §4.5–§4.9) edit what a file says: hosts.equiv,
// the vsftpd and postfix configurations, /etc/exports. Their tests run under
// a temporary root with every host tool a content body may call stubbed
// first on PATH (contentTree), the body's paths rebased under that root
// (rebaseContent), and the whole block built from the shipped control
// (contentBlock).

// contentTree returns a temporary root, a bin directory of stubs and the
// stubs' log directory. Every stub appends its argv to $STUB/<tool>. The
// verbs a content test models answer; anything else fails closed (exit 99),
// so a body that reaches a tool the test did not model fails its block
// rather than touching the host (O-32):
//   - systemctl: is-active (0 iff $STUB/active/<unit> exists), reset-failed
//     (0, O-59), reload/restart/try-restart/reload-or-restart (0); a restart
//     leaves the unit active, except that while $STUB/restart_fail_once
//     exists the restart removes it, leaves the unit inactive and exits 1
//     (O-33: a restart that fails once and succeeds after);
//   - postfix: check (0), reload (0);
//   - exportfs: any arguments (0);
//   - postconf, restorecon: not modelled (99);
//   - selinuxenabled: exit 1 (SELinux off).
//
// A reload, restart or exportfs appends its argv and then the content of the
// file the daemon would read at that moment to the one shared $STUB/calls,
// so a test reads the order of edits and reloads from one log. The stubs
// need STUB and ROOT in the environment.
func contentTree(t *testing.T) (root, bin, stub string) {
	t.Helper()
	root, bin, stub = t.TempDir(), t.TempDir(), t.TempDir()
	const reads = `reads() {
  case "$1" in
    vsftpd*) for f in "$ROOT/etc/vsftpd.conf" "$ROOT/etc/vsftpd/vsftpd.conf"; do if [ -f "$f" ]; then cat "$f"; fi; done;;
    postfix*) cat "$ROOT/etc/postfix/main.cf" 2>/dev/null || echo "(no main.cf)";;
    exports) cat "$ROOT/etc/exports" 2>/dev/null || echo "(no exports)";;
  esac
}
`
	writeStub(t, bin, "systemctl", `printf '%s\n' "$*" >> "$STUB/systemctl"
`+reads+`u=; for a in "$@"; do u=$a; done
case "$1" in
  is-active) [ -e "$STUB/active/$u" ]; exit;;
  reset-failed) exit 0;;
  reload|restart|try-restart|reload-or-restart) printf '%s\n' "$*" >> "$STUB/calls"; reads "$u" >> "$STUB/calls"
    if [ "$1" = restart ] && [ -e "$STUB/restart_fail_once" ]; then rm -f "$STUB/restart_fail_once" "$STUB/active/$u"; exit 1; fi
    if [ "$1" = restart ]; then mkdir -p "$STUB/active" && : > "$STUB/active/$u"; fi
    exit 0;;
esac
exit 99
`)
	writeStub(t, bin, "postfix", `printf '%s\n' "$*" >> "$STUB/postfix"
`+reads+`case "$*" in
  check) exit 0;;
  reload) printf 'postfix %s\n' "$*" >> "$STUB/calls"; reads postfix >> "$STUB/calls"; exit 0;;
esac
exit 99
`)
	writeStub(t, bin, "exportfs", `printf '%s\n' "$*" >> "$STUB/exportfs"
`+reads+`printf 'exportfs %s\n' "$*" >> "$STUB/calls"; reads exports >> "$STUB/calls"
exit 0
`)
	for _, tool := range []string{"postconf", "restorecon"} {
		writeStub(t, bin, tool, `printf '%s\n' "$*" >> "$STUB/`+tool+`"
exit 99
`)
	}
	writeStub(t, bin, "selinuxenabled", "exit 1\n")
	return root, bin, stub
}

// rebaseContent prefixes root to every host path a content body names, in
// one pass (O-31): /etc/vsftpd covers /etc/vsftpd.conf and /etc/vsftpd/, and
// /etc/postfix covers the directory a `postconf -c /etc/postfix` names.
func rebaseContent(s, root string) string {
	return strings.NewReplacer(
		"/etc/hosts.equiv", root+"/etc/hosts.equiv",
		"/etc/vsftpd", root+"/etc/vsftpd",
		"/etc/postfix", root+"/etc/postfix",
		"/etc/exports", root+"/etc/exports",
	).Replace(s)
}

// contentBlock is the plan of one FAIL row of the shipped control id, its
// backup, body, validate and rollback rebased under root (the accountBlock
// shape); failValidate makes the validate `false`.
func contentBlock(t *testing.T, id, root string, failValidate bool) *Plan {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := set.ByID(id)
	if !ok {
		t.Fatalf("%s: no such control in the shipped set", id)
	}
	p := mustBuild(t, scriptReport(row(id, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
	if len(p.Items) != 1 || !p.Items[0].Script || !p.Items[0].Planned {
		t.Fatalf("%s: plan %+v, want one planned scripted item", id, p.Items)
	}
	it := &p.Items[0]
	for i := range it.Backup {
		it.Backup[i] = rebaseContent(it.Backup[i], root)
	}
	it.ScriptBody = rebaseContent(it.ScriptBody, root)
	it.ValidateCmd = rebaseContent(it.ValidateCmd, root)
	it.RollbackBody = rebaseContent(it.RollbackBody, root)
	for _, s := range append([]string{it.ScriptBody, it.ValidateCmd, it.RollbackBody}, it.Backup...) {
		if strings.Contains(s, root+root) {
			t.Fatalf("%s: rebased twice: %s", id, s)
		}
	}
	if failValidate {
		it.ValidateCmd = "false"
	}
	return p
}

func TestRebaseContentRebasesEachPathOnce(t *testing.T) {
	const root = "/tmp/r"
	in := "/etc/hosts.equiv /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/postfix/main.cf postconf -c /etc/postfix -h x /etc/exports /etc/passwd"
	want := "/tmp/r/etc/hosts.equiv /tmp/r/etc/vsftpd.conf /tmp/r/etc/vsftpd/vsftpd.conf /tmp/r/etc/postfix/main.cf postconf -c /tmp/r/etc/postfix -h x /tmp/r/etc/exports /etc/passwd"
	got := rebaseContent(in, root)
	if got != want || strings.Contains(got, root+root) {
		t.Errorf("rebaseContent:\n got %s\nwant %s", got, want)
	}
}

// O-32: what a test does not model fails closed, and the modelled verbs log
// to the shared calls file with the content the daemon would read.
func TestContentTreeStubsFailClosed(t *testing.T) {
	needSh(t)
	root, bin, stub := contentTree(t)
	writeUnder(t, root, "/etc/vsftpd.conf", "listen=YES\n")
	env := []string{"STUB=" + stub, "ROOT=" + root}
	for _, c := range []struct {
		cmd  string
		code int
	}{
		{"systemctl enable vsftpd.service", 99},
		{"systemctl is-active --quiet vsftpd.service", 1},
		{"systemctl reset-failed vsftpd.service", 0},
		{"systemctl restart vsftpd.service", 0},
		{"postconf -h smtpd_banner", 99},
		{"postfix start", 99},
		{"restorecon -- /etc/postfix/main.cf", 99},
		{"selinuxenabled", 1},
		{"exportfs -ra", 0},
		{`: > "$STUB/restart_fail_once"; systemctl restart vsftpd.service`, 1},
		{"systemctl is-active --quiet vsftpd.service", 1},
		{"systemctl restart vsftpd.service", 0},
		{"systemctl is-active --quiet vsftpd.service", 0},
	} {
		if out, code := runBody(t, root, bin, c.cmd, env...); code != c.code {
			t.Errorf("%s: exit %d, want %d\n%s", c.cmd, code, c.code, out)
		}
	}
	if got, want := readFile(t, filepath.Join(stub, "calls")), "restart vsftpd.service\nlisten=YES\nexportfs -ra\n(no exports)\n"+
		"restart vsftpd.service\nlisten=YES\nrestart vsftpd.service\nlisten=YES\n"; got != want {
		t.Errorf("calls %q, want %q", got, want)
	}
}

// runContentBody runs the shipped script of r rebased under root, as the
// review script does (umask 077, log defined), and returns its output and
// exit code.
func runContentBody(t *testing.T, r *controls.Remediation, root, bin, stub string) (string, int) {
	t.Helper()
	return runContentBodyIn(t, r, root, bin, stub, t.TempDir())
}

// runContentBodyIn is runContentBody with the block's record directory MB
// given, so a test can run the body twice over the same records (O-16).
func runContentBodyIn(t *testing.T, r *controls.Remediation, root, bin, stub, mb string) (string, int) {
	t.Helper()
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseContent(r.Script, root)
	return runBody(t, root, bin, body, "MB="+mb, "STUB="+stub, "ROOT="+root)
}

// §4.5: every line whose first non-blank character is "+" is commented out
// with the "# muster: " prefix and keeps its own text; other lines, comments
// included, are left as they are; the validate fails before and passes
// after; a second run changes nothing.
func TestRhostsBodyCommentsOutPlusLines(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.file.rhosts_forbidden")
	root, bin, stub := contentTree(t)
	f := filepath.Join(root, "/etc/hosts.equiv")
	writeUnder(t, root, "/etc/hosts.equiv", "+\n  +@ops\nhost-a\n# c\n+host-b\n")
	validate := rebaseContent(r.Validate, root)
	if out, code := runBody(t, root, bin, validate); code == 0 {
		t.Fatalf("the validate passes over the + lines\n%s", out)
	}
	if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
		t.Fatalf("body exit %d\n%s", code, out)
	}
	const want = "# muster: +\n# muster:   +@ops\nhost-a\n# c\n# muster: +host-b\n"
	if got := readFile(t, f); got != want {
		t.Fatalf("hosts.equiv is\n%q\nwant\n%q", got, want)
	}
	if fi, err := os.Stat(f); err != nil {
		t.Error(err)
	} else if fi.Mode().Perm() != 0o644 {
		t.Errorf("hosts.equiv mode %v, want 0644 kept", fi.Mode())
	}
	if out, code := runBody(t, root, bin, validate); code != 0 {
		t.Errorf("validate exit %d after the body\n%s", code, out)
	}
	if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
		t.Fatalf("second run exit %d\n%s", code, out)
	}
	if got := readFile(t, f); got != want {
		t.Errorf("the second run changed hosts.equiv to %q", got)
	}
	if _, err := os.Stat(filepath.Join(stub, "calls")); err == nil {
		t.Errorf("the body reloaded something: %s", readFile(t, filepath.Join(stub, "calls")))
	}
}

// §4 intro, C4: the collector reads a symlinked /etc/hosts.equiv as an
// error, so the row is never planned; the body skips the path and the link's
// target is untouched. A missing file is compliant: nothing to do.
func TestRhostsBodySkipsASymlinkAndAMissingFile(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.file.rhosts_forbidden")
	t.Run("symlink", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		victim := filepath.Join(root, "victim")
		writeUnder(t, root, "/victim", "+\n")
		link := filepath.Join(root, "/etc/hosts.equiv")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		if got, err := os.Readlink(link); err != nil || got != victim {
			t.Errorf("hosts.equiv is %q (%v), want the link to %s", got, err, victim)
		}
		if got := readFile(t, victim); got != "+\n" {
			t.Errorf("the link's target holds %q", got)
		}
		if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root)); code != 0 {
			t.Errorf("validate exit %d over the link\n%s", code, out)
		}
	})
	t.Run("missing", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		if exists(filepath.Join(root, "/etc/hosts.equiv")) {
			t.Error("the body created hosts.equiv")
		}
		if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root)); code != 0 {
			t.Errorf("validate exit %d without the file\n%s", code, out)
		}
	})
}

// A failed validate puts hosts.equiv back byte for byte through the
// template's restore of the backup; the way back is complete.
func TestRhostsBlockRollsBack(t *testing.T) {
	needSh(t)
	root, bin, stub := contentTree(t)
	const before = "+\n  +@ops\nhost-a\n"
	writeUnder(t, root, "/etc/hosts.equiv", before)
	p := contentBlock(t, "muster.file.rhosts_forbidden", root, true)
	out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 1 || !strings.Contains(out, "validate failed") {
		t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
	}
	if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
		t.Errorf("the way back was incomplete\n%s", out)
	}
	if got := readFile(t, filepath.Join(root, "/etc/hosts.equiv")); got != before {
		t.Errorf("hosts.equiv is %q after the block, want %q", got, before)
	}
	saved := filepath.Join(root, "bk", "blocks", fnName("muster.file.rhosts_forbidden"), "files", root, "/etc/hosts.equiv")
	if got := readFile(t, saved); got != before {
		t.Errorf("the backup holds %q, want %q", got, before)
	}
}

// vsftpdLayouts are the places the vsftpd bodies act on (§4.7: Debian's
// /etc/vsftpd.conf, EL's /etc/vsftpd/vsftpd.conf), each alone and both.
var vsftpdLayouts = []struct {
	name  string
	confs []string
}{
	{"debian", []string{"/etc/vsftpd.conf"}},
	{"el", []string{"/etc/vsftpd/vsftpd.conf"}},
	{"both", []string{"/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"}},
}

// vsftpdRow is one configuration a vsftpd body runs over: the conf's text
// ({root} is the test root, so banner_file names the rebased issue.net), the
// banner file's text when issue is set, and the conf the body leaves.
type vsftpdRow struct {
	name, conf string
	issue      *string
	want       string
	leave      bool // the O-23 banner_file line is logged
}

func strp(s string) *string { return &s }

// runVsftpdRows runs the shipped body of id over every row in every layout:
// the conf the body leaves, its mode kept, the leave line, a validate that
// passes after the body, a second run that changes nothing, and no restart
// (vsftpd is not running).
func runVsftpdRows(t *testing.T, id string, rows []vsftpdRow) {
	t.Helper()
	r := shippedRemediation(t, id)
	for _, lay := range vsftpdLayouts {
		for _, row := range rows {
			t.Run(lay.name+"/"+row.name, func(t *testing.T) {
				root, bin, stub := contentTree(t)
				sub := func(s string) string { return strings.ReplaceAll(s, "{root}", root) }
				for _, c := range lay.confs {
					writeUnder(t, root, c, sub(row.conf))
				}
				if row.issue != nil {
					writeUnder(t, root, "/etc/issue.net", *row.issue)
				}
				out, code := runContentBody(t, r, root, bin, stub)
				if code != 0 {
					t.Fatalf("body exit %d\n%s", code, out)
				}
				for _, c := range lay.confs {
					f := filepath.Join(root, c)
					if got := readFile(t, f); got != sub(row.want) {
						t.Errorf("%s is\n%q\nwant\n%q", c, got, sub(row.want))
					}
					if fi, err := os.Stat(f); err != nil {
						t.Error(err)
					} else if fi.Mode().Perm() != 0o644 {
						t.Errorf("%s mode %v, want 0644 kept", c, fi.Mode())
					}
				}
				leave := id + ": banner_file " + root + "/etc/issue.net sets the greeting; left to the operator"
				if n := strings.Count(out, leave); row.leave && n != len(lay.confs) || !row.leave && n != 0 {
					t.Errorf("the leave line %q appears %d times (leave %v, %d confs)\n%s", leave, n, row.leave, len(lay.confs), out)
				}
				if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root), "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root); code != 0 {
					t.Errorf("validate exit %d after the body\n%s", code, out)
				}
				if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
					t.Fatalf("second run exit %d\n%s", code, out)
				}
				for _, c := range lay.confs {
					if got := readFile(t, filepath.Join(root, c)); got != sub(row.want) {
						t.Errorf("the second run changed %s to %q", c, got)
					}
				}
				if exists(filepath.Join(stub, "calls")) {
					t.Errorf("a stopped vsftpd was restarted: %s", readFile(t, filepath.Join(stub, "calls")))
				}
			})
		}
	}
}

// §4.7, O-14, O-15, O-47: the greeting is read in vsftpd's order (a
// non-empty banner_file, else ftpd_banner, else the compiled greeting, which
// names the product); only a greeting that names a product is rewritten, to
// the fixed neutral string at column one, every ftpd_banner line alike, or
// appended after a newline guard; a non-empty banner_file is the operator's
// notice and is left, logged.
func TestVsftpdBannerWritesOnlyADisclosure(t *testing.T) {
	needSh(t)
	const ready = "ftpd_banner=FTP server ready.\n"
	const bf = "banner_file={root}/etc/issue.net\n"
	runVsftpdRows(t, "muster.service.ftp_banner", []vsftpdRow{
		{name: "unset", conf: "listen=YES\n", want: "listen=YES\n" + ready},
		{name: "no final newline", conf: "listen=YES", want: "listen=YES\n" + ready},
		{name: "empty file", conf: "", want: ready},
		{name: "commented", conf: "#ftpd_banner=Welcome\n", want: "#ftpd_banner=Welcome\n" + ready},
		{name: "product", conf: "listen=YES\nftpd_banner=vsFTPd 3.0.5 ready\nx=1\n", want: "listen=YES\n" + ready + "x=1\n"},
		{name: "upper key", conf: "  FTPD_BANNER = vsFTPd\n", want: ready},
		{name: "empty value", conf: "ftpd_banner=\n", want: ready},
		{name: "every line", conf: "ftpd_banner=Welcome\nftpd_banner=ProFTPD here\n", want: ready + ready},
		{name: "clean", conf: "ftpd_banner=Welcome\n", want: "ftpd_banner=Welcome\n"},
		{name: "clean last", conf: "ftpd_banner=vsftpd\nftpd_banner=Welcome\n", want: "ftpd_banner=vsftpd\nftpd_banner=Welcome\n"},
		{name: "banner file", conf: "ftpd_banner=vsFTPd 3.0.5\n" + bf, issue: strp("Authorized use only.\n"),
			want: "ftpd_banner=vsFTPd 3.0.5\n" + bf, leave: true},
		{name: "disclosing banner file", conf: "ftpd_banner=Welcome\n" + bf, issue: strp("220 vsFTPd 3.0.5\n"),
			want: "ftpd_banner=Welcome\n" + bf, leave: true},
		{name: "empty banner file", conf: "ftpd_banner=vsFTPd 3.0.5\n" + bf, issue: strp(""),
			want: ready + bf},
		{name: "empty banner file alone", conf: bf, issue: strp(""), want: bf + ready},
	})
}

// §4.8: anonymous_enable is false only as vsftpd reads NO, FALSE or 0, case
// blind; anything else, a missing key (the compiled YES) included, becomes
// anonymous_enable=NO at column one on every line, or appended.
func TestVsftpdAnonymousWritesNo(t *testing.T) {
	needSh(t)
	const no = "anonymous_enable=NO\n"
	same := func(name, conf string) vsftpdRow { return vsftpdRow{name: name, conf: conf, want: conf} }
	runVsftpdRows(t, "muster.service.ftp_anonymous", []vsftpdRow{
		{name: "missing", conf: "listen=YES\n", want: "listen=YES\n" + no},
		{name: "missing, no final newline", conf: "listen=YES", want: "listen=YES\n" + no},
		{name: "commented", conf: "#anonymous_enable=NO\n", want: "#anonymous_enable=NO\n" + no},
		{name: "YES", conf: "anonymous_enable=YES\nlisten=YES\n", want: no + "listen=YES\n"},
		{name: "yes", conf: "anonymous_enable=yes\n", want: no},
		{name: "1", conf: "anonymous_enable=1\n", want: no},
		{name: "upper key", conf: "  ANONYMOUS_ENABLE = YES\n", want: no},
		{name: "last wins", conf: "anonymous_enable=NO\nanonymous_enable=YES\n", want: no + no},
		same("NO", "anonymous_enable=NO\n"),
		same("false", "anonymous_enable=false\n"),
		same("0", "anonymous_enable=0\n"),
		same("spaced No", " Anonymous_Enable = No \n"),
	})
}

// vsftpdIDs are the two vsftpd bodies, each with a conf it edits and what
// the edit leaves.
var vsftpdIDs = []struct{ id, conf, edited string }{
	{"muster.service.ftp_banner", "ftpd_banner=vsFTPd 3.0.5\n", "ftpd_banner=FTP server ready.\n"},
	{"muster.service.ftp_anonymous", "anonymous_enable=YES\n", "anonymous_enable=NO\n"},
}

// O-9, O-16, O-59: the restart keys on this run's was-running marker and on
// an edit: a running vsftpd is restarted once after the edit, preceded by a
// reset-failed; a stopped one, an unedited conf, and a rerun whose
// was-running marker is left from an earlier run while vsftpd is now
// stopped are never restarted.
func TestVsftpdRestartsOnlyAWasRunningUnit(t *testing.T) {
	needSh(t)
	for _, v := range vsftpdIDs {
		r := shippedRemediation(t, v.id)
		run := func(t *testing.T, conf string, active bool, mb string) (root, stub string) {
			t.Helper()
			root, bin, stub := contentTree(t)
			writeUnder(t, root, "/etc/vsftpd.conf", conf)
			if active {
				writeUnder(t, stub, "/active/vsftpd.service", "")
			}
			if out, code := runContentBodyIn(t, r, root, bin, stub, mb); code != 0 {
				t.Fatalf("body exit %d\n%s", code, out)
			}
			return root, stub
		}
		t.Run(v.id+"/running", func(t *testing.T) {
			mb := t.TempDir()
			_, stub := run(t, v.conf, true, mb)
			if got, want := readFile(t, filepath.Join(stub, "calls")), "restart vsftpd.service\n"+v.edited; got != want {
				t.Errorf("calls %q, want one restart over the edited conf %q", got, want)
			}
			if got := readFile(t, filepath.Join(stub, "systemctl")); !strings.Contains(got, "reset-failed vsftpd.service\nrestart vsftpd.service\n") {
				t.Errorf("the restart is not preceded by a reset-failed (O-59):\n%s", got)
			}
			if !exists(filepath.Join(mb, "vsftpd.was-running")) || !exists(filepath.Join(mb, "vsftpd.edited")) {
				t.Error("the run left no was-running or edited marker")
			}
		})
		t.Run(v.id+"/stopped", func(t *testing.T) {
			root, stub := run(t, v.conf, false, t.TempDir())
			if exists(filepath.Join(stub, "calls")) {
				t.Errorf("a stopped vsftpd was restarted: %s", readFile(t, filepath.Join(stub, "calls")))
			}
			if got := readFile(t, filepath.Join(root, "/etc/vsftpd.conf")); got != v.edited {
				t.Errorf("conf %q, want %q", got, v.edited)
			}
		})
		t.Run(v.id+"/running, nothing to edit", func(t *testing.T) {
			_, stub := run(t, v.edited, true, t.TempDir())
			if exists(filepath.Join(stub, "calls")) {
				t.Errorf("an unedited vsftpd was restarted: %s", readFile(t, filepath.Join(stub, "calls")))
			}
		})
		t.Run(v.id+"/rerun with an earlier marker", func(t *testing.T) {
			mb := t.TempDir()
			writeUnder(t, mb, "/vsftpd.was-running", "")
			writeUnder(t, mb, "/vsftpd.edited", "")
			_, stub := run(t, v.conf, false, mb)
			if exists(filepath.Join(stub, "calls")) {
				t.Errorf("an earlier run's marker restarted a stopped vsftpd: %s", readFile(t, filepath.Join(stub, "calls")))
			}
			if exists(filepath.Join(mb, "vsftpd.was-running")) {
				t.Error("the earlier run's was-running marker survived this run")
			}
		})
	}
}

// O-9, O-33: a restart that fails leaves the unit failed; the body fails,
// and the declared rollback restores the conf and restarts vsftpd again on
// the strength of this run's was-running marker, never on "running now".
func TestVsftpdRollbackRestartsAFailedUnit(t *testing.T) {
	needSh(t)
	for _, v := range vsftpdIDs {
		t.Run(v.id, func(t *testing.T) {
			root, bin, stub := contentTree(t)
			before := "listen=YES\n" + v.conf
			writeUnder(t, root, "/etc/vsftpd.conf", before)
			writeUnder(t, stub, "/active/vsftpd.service", "")
			writeUnder(t, stub, "/restart_fail_once", "")
			p := contentBlock(t, v.id, root, false)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 || !strings.Contains(out, v.id+": script failed") {
				t.Fatalf("exit %d, want 1 after the failed restart\n%s", code, out)
			}
			if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
				t.Errorf("the way back was incomplete\n%s", out)
			}
			calls := readFile(t, filepath.Join(stub, "calls"))
			if want := "restart vsftpd.service\nlisten=YES\n" + v.edited + "restart vsftpd.service\n" + before; calls != want {
				t.Errorf("calls %q, want the failed restart over the edit, then one over the restored conf %q", calls, want)
			}
			if !exists(filepath.Join(stub, "active", "vsftpd.service")) {
				t.Error("vsftpd is not active after the rollback's restart")
			}
			if got := readFile(t, filepath.Join(root, "/etc/vsftpd.conf")); got != before {
				t.Errorf("conf %q after the block, want %q", got, before)
			}
		})
	}
}

// O-9, O-32: the declared rollback restores the confs, and the template's
// restore that follows is a harmless second pass: a conf that existed is put
// back byte for byte, one that was absent stays absent, and neither pass
// logs a failure.
func TestContentRollbackDoubleRestoreIsHarmless(t *testing.T) {
	needSh(t)
	for _, v := range vsftpdIDs {
		for _, lay := range vsftpdLayouts[:2] {
			t.Run(v.id+"/"+lay.name, func(t *testing.T) {
				root, bin, stub := contentTree(t)
				present := lay.confs[0]
				absent := "/etc/vsftpd/vsftpd.conf"
				if present == absent {
					absent = "/etc/vsftpd.conf"
				}
				before := "listen=YES\n" + v.conf
				writeUnder(t, root, present, before)
				writeUnder(t, stub, "/active/vsftpd.service", "")
				p := contentBlock(t, v.id, root, true)
				out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
				if code != 1 || !strings.Contains(out, v.id+": validate failed") {
					t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
				}
				for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
					if strings.Contains(out, bad) {
						t.Errorf("the output carries %q\n%s", bad, out)
					}
				}
				if got := readFile(t, filepath.Join(root, present)); got != before {
					t.Errorf("%s is %q after the block, want %q", present, got, before)
				}
				if exists(filepath.Join(root, absent)) {
					t.Errorf("%s, absent before the block, exists after it", absent)
				}
				if calls := readFile(t, filepath.Join(stub, "calls")); !strings.HasSuffix(calls, "restart vsftpd.service\n"+before) {
					t.Errorf("calls %q, want the rollback's restart over the restored conf", calls)
				}
			})
		}
	}
}
