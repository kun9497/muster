//go:build linux

package remedy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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
//     (O-33: a restart that fails once and succeeds after), and while
//     $STUB/restart_dies exists it exits 0 but leaves the unit inactive (a
//     daemon that dies right after its start);
//   - postfix: check (0, or 1 while $STUB/check_fails exists), status (0
//     iff $STUB/postfix_running exists), reload (0);
//   - postconf: only with -c <dir>, over <dir>/main.cf: -h
//     disable_vrfy_command prints the value as postconf reads it (a name is
//     matched case-sensitively, a line led by white space continues the one
//     above, the last assignment wins, the compiled default is no; another
//     key is not modelled), and -e '<key> = <value>' rewrites every
//     assignment of key in place and drops their continuation lines, or
//     appends the line after the file's last byte (postconf 3.7 adds no
//     newline a file lacks), through a new file renamed over main.cf with
//     its mode (postconf's own replace, O-58; measured against postfix
//     3.7.11); a missing main.cf exits 1;
//   - exportfs: any arguments (0);
//   - restorecon: not modelled (99);
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
    if [ "$1" = restart ] && [ -e "$STUB/restart_dies" ]; then rm -f "$STUB/active/$u"; exit 0; fi
    if [ "$1" = restart ]; then mkdir -p "$STUB/active" && : > "$STUB/active/$u"; fi
    exit 0;;
esac
exit 99
`)
	writeStub(t, bin, "postfix", `printf '%s\n' "$*" >> "$STUB/postfix"
`+reads+`case "$*" in
  check) [ ! -e "$STUB/check_fails" ]; exit;;
  status) [ -e "$STUB/postfix_running" ]; exit;;
  reload) printf 'postfix %s\n' "$*" >> "$STUB/calls"; reads postfix >> "$STUB/calls"; exit 0;;
esac
exit 99
`)
	writeStub(t, bin, "postconf", `printf '%s\n' "$*" >> "$STUB/postconf"
dir=; op=; arg=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c) [ "$#" -ge 2 ] || exit 99; dir=$2; shift 2;;
    -h|-e) [ "$#" -ge 2 ] && [ -z "$op" ] || exit 99; op=$1; arg=$2; shift 2;;
    *) exit 99;;
  esac
done
[ -n "$dir" ] && [ -n "$op" ] || exit 99
f=$dir/main.cf
[ -f "$f" ] || { echo "postconf: fatal: open $f: No such file or directory" >&2; exit 1; }
case "$op" in
  -h) [ "$arg" = disable_vrfy_command ] || exit 99
    awk -v k="$arg" '
      /^[ \t]*(#|$)/ { next }
      /^[ \t]/ { if (cur) { s = $0; sub(/^[ \t]+/, "", s); v = v " " s }; next }
      { cur = 0; i = index($0, "="); if (i == 0) next; n = substr($0, 1, i - 1); sub(/[ \t]+$/, "", n)
        if (n == k) { cur = 1; found = 1; v = substr($0, i + 1); sub(/^[ \t]+/, "", v) } }
      END { if (!found) v = "no"; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v); print v }' "$f";;
  -e) k=${arg%%=*}; k=${k%"${k##*[! ]}"}
    if awk -v k="$k" '{ i = index($0, "="); if (i && $0 !~ /^[ \t]/) { n = substr($0, 1, i - 1); sub(/[ \t]+$/, "", n); if (n == k) f = 1 } } END { exit !f }' "$f"; then
      awk -v k="$k" -v line="$arg" '
        /^[ \t]*(#|$)/ { skip = 0; print; next }
        /^[ \t]/ { if (!skip) print; next }
        { skip = 0; i = index($0, "="); n = ""; if (i) { n = substr($0, 1, i - 1); sub(/[ \t]+$/, "", n) }
          if (i && n == k) { print line; skip = 1; next }
          print }' "$f" > "$f.postconf-new"
    else
      { cat "$f"; printf '%s\n' "$arg"; } > "$f.postconf-new"
    fi &&
      chmod "$(stat -c %a "$f")" "$f.postconf-new" && mv -f "$f.postconf-new" "$f";;
esac
`)
	writeStub(t, bin, "exportfs", `printf '%s\n' "$*" >> "$STUB/exportfs"
`+reads+`printf 'exportfs %s\n' "$*" >> "$STUB/calls"; reads exports >> "$STUB/calls"
exit 0
`)
	writeStub(t, bin, "restorecon", `printf '%s\n' "$*" >> "$STUB/restorecon"
exit 99
`)
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
		{`: > "$STUB/restart_dies"; systemctl restart vsftpd.service`, 0},
		{`rm "$STUB/restart_dies"; systemctl is-active --quiet vsftpd.service`, 1},
		{"postfix check", 0},
		{"postfix status", 1},
		{`: > "$STUB/check_fails"; postfix check`, 1},
		{`rm "$STUB/check_fails"; : > "$STUB/postfix_running"; postfix status`, 0},
		{`postconf -c "$ROOT/etc/postfix" -h disable_vrfy_command`, 1},
		{`mkdir -p "$ROOT/etc/postfix"; : > "$ROOT/etc/postfix/main.cf"; postconf -c "$ROOT/etc/postfix" -h disable_vrfy_command`, 0},
		{`postconf -c "$ROOT/etc/postfix" -h smtpd_banner`, 99},
		{`postconf -c "$ROOT/etc/postfix" -n`, 99},
		{`postconf -e 'disable_vrfy_command = yes'`, 99},
	} {
		if out, code := runBody(t, root, bin, c.cmd, env...); code != c.code {
			t.Errorf("%s: exit %d, want %d\n%s", c.cmd, code, c.code, out)
		}
	}
	if got, want := readFile(t, filepath.Join(stub, "calls")), "restart vsftpd.service\nlisten=YES\nexportfs -ra\n(no exports)\n"+
		"restart vsftpd.service\nlisten=YES\nrestart vsftpd.service\nlisten=YES\nrestart vsftpd.service\nlisten=YES\n"; got != want {
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

// O-81: ruserok uses the first matching line, and a "+" line whose user
// field is "-user" or "-@netgroup" denies that user; commenting it out would
// let a later line admit them. The body refuses such a file (logs, exit 1)
// and leaves it byte for byte; the block fails and changes nothing.
func TestRhostsBodyRefusesADenyLine(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.file.rhosts_forbidden")
	for _, before := range []string{
		"+ -alice\ntrusted.example\n",
		"  +@ops\t-@contractors\n+\n",
		"+host-a -bob\n",
	} {
		t.Run(before, func(t *testing.T) {
			root, bin, stub := contentTree(t)
			writeUnder(t, root, "/etc/hosts.equiv", before)
			out, code := runContentBody(t, r, root, bin, stub)
			if code != 1 || !strings.Contains(out, "muster.file.rhosts_forbidden: "+filepath.Join(root, "/etc/hosts.equiv")+" has a '+' line that denies a user; edit it by hand") {
				t.Fatalf("body exit %d, want 1 and the refusal\n%s", code, out)
			}
			if got := readFile(t, filepath.Join(root, "/etc/hosts.equiv")); got != before {
				t.Errorf("hosts.equiv is %q, want %q untouched", got, before)
			}
			p := contentBlock(t, "muster.file.rhosts_forbidden", root, false)
			out, _, code = runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 || strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
				t.Fatalf("block exit %d, want 1 with a complete way back\n%s", code, out)
			}
			if got := readFile(t, filepath.Join(root, "/etc/hosts.equiv")); got != before {
				t.Errorf("hosts.equiv is %q after the block, want %q", got, before)
			}
		})
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
	leave      bool   // the O-23 banner_file line is logged
	leavePath  string // the path the leave line names; {root}/etc/issue.net when empty
	special    string // "fifo" or "symlink": /etc/issue.net is made so (O-82)
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
				switch row.special {
				case "fifo":
					writeUnder(t, root, "/etc/.keep", "")
					if err := syscall.Mkfifo(filepath.Join(root, "/etc/issue.net"), 0o644); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					writeUnder(t, root, "/banner", "Authorized use only.\n")
					if err := os.Symlink(filepath.Join(root, "/banner"), filepath.Join(root, "/etc/issue.net")); err != nil {
						t.Fatal(err)
					}
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
				lp := row.leavePath
				if lp == "" {
					lp = "{root}/etc/issue.net"
				}
				leave := id + ": banner_file " + sub(lp) + " sets the greeting; left to the operator"
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
		// O-82: the body never opens banner_file; the shell names a greeting
		// file only for a non-empty regular file that is not a symlink, as the
		// collector does. "-" (a relative name), /dev/stdin (a symlink), a
		// FIFO and a symlink are no greeting file to the body, so a disclosing
		// ftpd_banner beside them is rewritten; the collector reads each of
		// them absent (MANUAL), so the row is never planned there.
		{name: "banner file is stdin", conf: "ftpd_banner=vsFTPd\nbanner_file=-\n", want: ready + "banner_file=-\n"},
		{name: "banner file is /dev/stdin", conf: "ftpd_banner=vsFTPd\nbanner_file=/dev/stdin\n", want: ready + "banner_file=/dev/stdin\n"},
		{name: "banner file is a FIFO", conf: "ftpd_banner=vsFTPd\n" + bf, want: ready + bf, special: "fifo"},
		{name: "banner file is a symlink", conf: "ftpd_banner=vsFTPd\n" + bf, want: ready + bf, special: "symlink"},
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

// §4 intro, C4: the collector reads a symlinked vsftpd.conf as an error, so
// the row is never planned; the body skips the path (GNU sed -i would turn
// the operator's link into a regular file), the link and its target are
// untouched, and the validate passes over it.
func TestVsftpdBodiesSkipASymlinkedConf(t *testing.T) {
	needSh(t)
	for _, v := range vsftpdIDs {
		t.Run(v.id, func(t *testing.T) {
			r := shippedRemediation(t, v.id)
			root, bin, stub := contentTree(t)
			victim := filepath.Join(root, "victim")
			writeUnder(t, root, "/victim", v.conf)
			link := filepath.Join(root, "/etc/vsftpd.conf")
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, link); err != nil {
				t.Fatal(err)
			}
			writeUnder(t, stub, "/active/vsftpd.service", "")
			mb := t.TempDir()
			if out, code := runContentBodyIn(t, r, root, bin, stub, mb); code != 0 {
				t.Fatalf("body exit %d\n%s", code, out)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("vsftpd.conf is no longer a symlink (%v, %v)", fi, err)
			}
			if got, err := os.Readlink(link); err != nil || got != victim {
				t.Errorf("vsftpd.conf links to %q (%v), want %s", got, err, victim)
			}
			if got := readFile(t, victim); got != v.conf {
				t.Errorf("the link's target holds %q, want %q", got, v.conf)
			}
			if exists(filepath.Join(mb, "vsftpd.edited")) || exists(filepath.Join(stub, "calls")) {
				t.Error("the body wrote or restarted over a symlinked conf")
			}
			if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root), "MB="+mb, "STUB="+stub, "ROOT="+root); code != 0 {
				t.Errorf("validate exit %d over the link\n%s", code, out)
			}
		})
	}
}

// §4.7 validate: after a restart the unit this run found running must be
// active again. A whole block over a running vsftpd ends done; a restart
// that exits 0 but leaves the unit inactive fails the validate, and the
// way back restores the conf.
func TestVsftpdValidateNeedsTheRestartedUnitActive(t *testing.T) {
	needSh(t)
	for _, v := range vsftpdIDs {
		for _, dies := range []bool{false, true} {
			name := v.id + "/stays up"
			if dies {
				name = v.id + "/dies after the restart"
			}
			t.Run(name, func(t *testing.T) {
				root, bin, stub := contentTree(t)
				before := "listen=YES\n" + v.conf
				writeUnder(t, root, "/etc/vsftpd.conf", before)
				writeUnder(t, stub, "/active/vsftpd.service", "")
				if dies {
					writeUnder(t, stub, "/restart_dies", "")
				}
				p := contentBlock(t, v.id, root, false)
				out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
				conf := readFile(t, filepath.Join(root, "/etc/vsftpd.conf"))
				if !dies {
					if code != 0 || !strings.Contains(out, v.id+": done") {
						t.Fatalf("exit %d, want 0 and done\n%s", code, out)
					}
					if conf != "listen=YES\n"+v.edited {
						t.Errorf("conf %q, want the edit kept", conf)
					}
					return
				}
				if code != 1 || !strings.Contains(out, v.id+": validate failed") {
					t.Fatalf("exit %d, want 1 after the validate saw the unit down\n%s", code, out)
				}
				if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
					t.Errorf("the way back was incomplete\n%s", out)
				}
				if conf != before {
					t.Errorf("conf %q after the block, want %q", conf, before)
				}
			})
		}
	}
}

const postfixID = "muster.service.mail_expn_vrfy"

// readIf is the file's content, or "" when it does not exist.
func readIf(t *testing.T, path string) string {
	t.Helper()
	if !exists(path) {
		return ""
	}
	return readFile(t, path)
}

// postconfEdits counts the postconf -e calls the stub logged.
func postconfEdits(t *testing.T, stub string) int {
	t.Helper()
	n := 0
	for _, l := range strings.Split(readIf(t, filepath.Join(stub, "postconf")), "\n") {
		if strings.Contains(l, " -e ") {
			n++
		}
	}
	return n
}

// The postconf stub reads and writes main.cf the way postconf 3.7.11 does
// (measured in debian:12, O-58): names are case-sensitive, a
// white-space-led line continues the one above, the last assignment wins
// over the compiled no, and -e rewrites every assignment in place, or
// appends after the last byte (a missing final newline is not added),
// through a new file that keeps the mode.
func TestContentTreePostconfReadsAsPostconf(t *testing.T) {
	needSh(t)
	const yes = "disable_vrfy_command = yes\n"
	for _, c := range []struct{ name, conf, h, e string }{
		{"empty", "", "no", yes},
		{"upper value", "disable_vrfy_command = YES\n", "YES", yes},
		{"continued", "disable_vrfy_command =\n    no\nb = 2\n", "no", yes + "b = 2\n"},
		{"continued yes", "disable_vrfy_command =\n    yes\n", "yes", yes},
		{"last wins", "disable_vrfy_command = no\ndisable_vrfy_command = yes\n", "yes", yes + yes},
		{"case-folded name", "Disable_Vrfy_Command = yes\n", "no", "Disable_Vrfy_Command = yes\n" + yes},
		{"in place", "a = 1\n# disable_vrfy_command = yes\ndisable_vrfy_command = no\nb = 2\n", "no", "a = 1\n# disable_vrfy_command = yes\n" + yes + "b = 2\n"},
		{"no final newline", "a = 1", "no", "a = 1" + yes},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := contentTree(t)
			writeUnder(t, root, "/etc/postfix/main.cf", c.conf)
			f := filepath.Join(root, "/etc/postfix/main.cf")
			env := []string{"STUB=" + stub, "ROOT=" + root}
			if out, code := runBody(t, root, bin, `postconf -c "$ROOT/etc/postfix" -h disable_vrfy_command`, env...); code != 0 || out != c.h+"\n" {
				t.Errorf("-h printed %q (exit %d), want %q", out, code, c.h)
			}
			fi0, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			if out, code := runBody(t, root, bin, `postconf -c "$ROOT/etc/postfix" -e 'disable_vrfy_command = yes'`, env...); code != 0 {
				t.Fatalf("-e exit %d\n%s", code, out)
			}
			if got := readFile(t, f); got != c.e {
				t.Errorf("-e left %q, want %q", got, c.e)
			}
			fi1, err := os.Stat(f)
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(fi0, fi1) || fi1.Mode().Perm() != 0o644 {
				t.Errorf("-e kept the inode (%v) or changed the mode to %v; postconf renames a new file with the mode", os.SameFile(fi0, fi1), fi1.Mode())
			}
		})
	}
}

// §4.6, O-25, O-58: postfix check runs first; postfix status before any edit
// writes this run's was-running marker; a disable_vrfy_command postconf does
// not read as yes (case blind) is set with one postconf -e, checked again,
// and reloaded only when postfix was running. A value already yes is left.
func TestPostfixSetsVrfyOnce(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, postfixID)
	const yes = "disable_vrfy_command = yes\n"
	for _, c := range []struct {
		name, conf string
		want       string // main.cf after the body; "" when it is left as it was
		running    bool
	}{
		{"no, running", "inet_interfaces = all\ndisable_vrfy_command = no\n", "inet_interfaces = all\n" + yes, true},
		{"no, stopped", "disable_vrfy_command = no\n", yes, false},
		{"unset", "inet_interfaces = all\n", "inet_interfaces = all\n" + yes, true},
		// §3.7: postconf -e appends after the last byte, so the body ends
		// the last line first
		{"unset, no final newline", "inet_interfaces = all", "inet_interfaces = all\n" + yes, true},
		{"later override", "disable_vrfy_command = yes\ndisable_vrfy_command = no\n", yes + yes, true},
		// The recorded divergence (O-25): the collector folds the name and
		// reads yes, so check PASSes there and the row is never planned;
		// postconf matches names case-sensitively and reads the compiled no,
		// and the body acts on what postconf reads.
		{"case-folded name", "Disable_Vrfy_Command = yes\n", "Disable_Vrfy_Command = yes\n" + yes, false},
		{"YES", "disable_vrfy_command = YES\n", "", true},
		{"yes continued", "disable_vrfy_command =\n    yes\n", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := contentTree(t)
			writeUnder(t, root, "/etc/postfix/main.cf", c.conf)
			if c.running {
				writeUnder(t, stub, "/postfix_running", "")
			}
			mb := t.TempDir()
			out, code := runContentBodyIn(t, r, root, bin, stub, mb)
			if code != 0 {
				t.Fatalf("body exit %d\n%s", code, out)
			}
			edits := c.want != ""
			want := c.want
			if !edits {
				want = c.conf
			}
			f := filepath.Join(root, "/etc/postfix/main.cf")
			if got := readFile(t, f); got != want {
				t.Errorf("main.cf is %q, want %q", got, want)
			}
			if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o644 {
				t.Errorf("main.cf mode %v (%v), want 0644 kept", fi.Mode(), err)
			}
			if n := postconfEdits(t, stub); edits && n != 1 || !edits && n != 0 {
				t.Errorf("postconf -e ran %d times (edit %v)\n%s", n, edits, readIf(t, filepath.Join(stub, "postconf")))
			}
			wantPostfix := "check\nstatus\n"
			if edits {
				wantPostfix += "check\n"
				if c.running {
					wantPostfix += "reload\n"
				}
			}
			if got := readIf(t, filepath.Join(stub, "postfix")); got != wantPostfix {
				t.Errorf("postfix ran %q, want %q (a check before and after the edit, the reload only when running)", got, wantPostfix)
			}
			if got := readIf(t, filepath.Join(stub, "calls")); edits && c.running && got != "postfix reload\n"+want || !(edits && c.running) && got != "" {
				t.Errorf("calls %q (edit %v, running %v)", got, edits, c.running)
			}
			if exists(filepath.Join(mb, "postfix.edited")) != edits || exists(filepath.Join(mb, "postfix.was-running")) != c.running {
				t.Errorf("markers: edited %v (want %v), was-running %v (want %v)", exists(filepath.Join(mb, "postfix.edited")), edits,
					exists(filepath.Join(mb, "postfix.was-running")), c.running)
			}
			if out, code := runContentBodyIn(t, r, root, bin, stub, t.TempDir()); code != 0 {
				t.Fatalf("second run exit %d\n%s", code, out)
			}
			if n := postconfEdits(t, stub); edits && n != 1 || !edits && n != 0 {
				t.Errorf("the second run edited again: postconf -e ran %d times", n)
			}
			if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root), "STUB="+stub, "ROOT="+root); code != 0 {
				t.Errorf("validate exit %d after the body\n%s", code, out)
			}
		})
	}
	t.Run("validate fails before the body", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		writeUnder(t, root, "/etc/postfix/main.cf", "disable_vrfy_command = no\n")
		if out, code := runBody(t, root, bin, rebaseContent(r.Validate, root), "STUB="+stub, "ROOT="+root); code == 0 {
			t.Errorf("the validate passes over disable_vrfy_command = no\n%s", out)
		}
	})
	t.Run("rerun with an earlier marker", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		writeUnder(t, root, "/etc/postfix/main.cf", "disable_vrfy_command = no\n")
		mb := t.TempDir()
		writeUnder(t, mb, "/postfix.was-running", "")
		if out, code := runContentBodyIn(t, r, root, bin, stub, mb); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		if exists(filepath.Join(stub, "calls")) {
			t.Errorf("an earlier run's marker reloaded a stopped postfix: %s", readFile(t, filepath.Join(stub, "calls")))
		}
		if exists(filepath.Join(mb, "postfix.was-running")) {
			t.Error("the earlier run's was-running marker survived this run")
		}
	})
	// O-36: postconf -e replaces main.cf, so restorecon runs on it after the
	// edit when SELinux is enabled, and never without an edit.
	for _, edit := range []bool{true, false} {
		t.Run(fmt.Sprintf("selinux, edit %v", edit), func(t *testing.T) {
			root, bin, stub := contentTree(t)
			writeStub(t, bin, "selinuxenabled", "exit 0\n")
			writeStub(t, bin, "restorecon", `printf '%s\n' "$*" >> "$STUB/restorecon"
grep -q '^disable_vrfy_command = yes$' "$2"
`)
			conf := "disable_vrfy_command = yes\n"
			if edit {
				conf = "disable_vrfy_command = no\n"
			}
			writeUnder(t, root, "/etc/postfix/main.cf", conf)
			if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
				t.Fatalf("body exit %d\n%s", code, out)
			}
			want := ""
			if edit {
				want = "-- " + filepath.Join(root, "/etc/postfix/main.cf") + "\n"
			}
			if got := readIf(t, filepath.Join(stub, "restorecon")); got != want {
				t.Errorf("restorecon ran %q, want %q (after the edit only)", got, want)
			}
		})
	}
}

// §4.6, O-23: a configuration postfix check already refuses is never
// edited: the body refuses before any change, and the block's way back is
// clean (the edited marker is absent, so the rollback neither checks nor
// reloads).
func TestPostfixRefusesABrokenConfig(t *testing.T) {
	needSh(t)
	root, bin, stub := contentTree(t)
	const before = "disable_vrfy_command = no\n"
	writeUnder(t, root, "/etc/postfix/main.cf", before)
	writeUnder(t, stub, "/check_fails", "")
	writeUnder(t, stub, "/postfix_running", "")
	p := contentBlock(t, postfixID, root, false)
	out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 1 || !strings.Contains(out, postfixID+": script failed") {
		t.Fatalf("exit %d, want 1 after the refusal\n%s", code, out)
	}
	if !strings.Contains(out, postfixID+": postfix check fails before any change; refused") {
		t.Errorf("the refusal is not logged\n%s", out)
	}
	for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed"} {
		if strings.Contains(out, bad) {
			t.Errorf("the output carries %q\n%s", bad, out)
		}
	}
	if n := postconfEdits(t, stub); n != 0 {
		t.Errorf("postconf -e ran %d times over a broken configuration", n)
	}
	if got := readIf(t, filepath.Join(stub, "postfix")); got != "check\n" {
		t.Errorf("postfix ran %q, want the one refused check", got)
	}
	if exists(filepath.Join(stub, "calls")) {
		t.Errorf("something was reloaded: %s", readFile(t, filepath.Join(stub, "calls")))
	}
	if got := readFile(t, filepath.Join(root, "/etc/postfix/main.cf")); got != before {
		t.Errorf("main.cf is %q, want %q", got, before)
	}
}

// O-9, O-32: the declared rollback restores main.cf, checks it, and reloads
// a postfix this run found running over the restored file.
func TestPostfixRollbackReloadsTheRestoredFile(t *testing.T) {
	needSh(t)
	for _, running := range []bool{true, false} {
		t.Run(fmt.Sprintf("running %v", running), func(t *testing.T) {
			root, bin, stub := contentTree(t)
			const before = "inet_interfaces = all\ndisable_vrfy_command = no\n"
			writeUnder(t, root, "/etc/postfix/main.cf", before)
			if running {
				writeUnder(t, stub, "/postfix_running", "")
			}
			p := contentBlock(t, postfixID, root, true)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 || !strings.Contains(out, postfixID+": validate failed") {
				t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
			}
			for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
				if strings.Contains(out, bad) {
					t.Errorf("the output carries %q\n%s", bad, out)
				}
			}
			if got := readFile(t, filepath.Join(root, "/etc/postfix/main.cf")); got != before {
				t.Errorf("main.cf is %q after the block, want %q", got, before)
			}
			calls := readIf(t, filepath.Join(stub, "calls"))
			pf := readIf(t, filepath.Join(stub, "postfix"))
			if running {
				if want := "postfix reload\ninet_interfaces = all\ndisable_vrfy_command = yes\npostfix reload\n" + before; calls != want {
					t.Errorf("calls %q, want the body's reload over the edit, then the rollback's over the restored file %q", calls, want)
				}
				if !strings.HasSuffix(pf, "check\nreload\n") {
					t.Errorf("postfix ran %q; the rollback checks before it reloads", pf)
				}
			} else {
				if calls != "" {
					t.Errorf("a stopped postfix was reloaded: %s", calls)
				}
				if !strings.HasSuffix(pf, "check\ncheck\n") {
					t.Errorf("postfix ran %q; the rollback checks the restored file", pf)
				}
			}
		})
	}
}

// §4 intro, K2: a symlinked main.cf is refused before any write; the link
// and its target are untouched.
func TestPostfixRefusesASymlinkedMainCf(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, postfixID)
	root, bin, stub := contentTree(t)
	victim := filepath.Join(root, "victim")
	writeUnder(t, root, "/victim", "disable_vrfy_command = no\n")
	link := filepath.Join(root, "/etc/postfix/main.cf")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	mb := t.TempDir()
	out, code := runContentBodyIn(t, r, root, bin, stub, mb)
	if code == 0 {
		t.Fatalf("the body accepted a symlinked main.cf\n%s", out)
	}
	if want := postfixID + ": " + link + " is a symlink, left as is"; !strings.Contains(out, want) {
		t.Errorf("the log does not carry %q\n%s", want, out)
	}
	if got, err := os.Readlink(link); err != nil || got != victim {
		t.Errorf("main.cf is %q (%v), want the link to %s", got, err, victim)
	}
	if got := readFile(t, victim); got != "disable_vrfy_command = no\n" {
		t.Errorf("the link's target holds %q", got)
	}
	if postconfEdits(t, stub) != 0 || exists(filepath.Join(mb, "postfix.edited")) {
		t.Error("the body edited through the link")
	}
}

// §4.6, O-23, O-32: a host without postconf (sendmail alone) is the
// operator's: the body logs it and changes nothing, and the validate
// passes. PATH holds only the plain tools a body needs, so no postconf can
// be found anywhere.
func TestPostfixAbsentLeavesTheSendmailHalf(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, postfixID)
	bin := t.TempDir()
	for _, tool := range []string{"sh", "awk", "grep", "sed", "cat", "rm", "tail", "printf", "stat", "chown", "chmod"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	root, mb := t.TempDir(), t.TempDir()
	const conf = "disable_vrfy_command = no\n"
	writeUnder(t, root, "/etc/postfix/main.cf", conf)
	run := func(script string) (string, int) {
		t.Helper()
		cmd := exec.Command(filepath.Join(bin, "sh"), "-ec", script)
		cmd.Dir = root
		cmd.Env = []string{"PATH=" + bin, "MB=" + mb, "HOME=" + root}
		out, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		} else if err != nil {
			t.Fatalf("sh: %v", err)
		}
		return string(out), 0
	}
	if out, code := run("command -v postconf"); code == 0 {
		t.Fatalf("postconf is on the minimal PATH: %s", out)
	}
	out, code := run("umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseContent(r.Script, root))
	if code != 0 {
		t.Fatalf("body exit %d\n%s", code, out)
	}
	if want := postfixID + ": postconf is missing; the sendmail half is the operator's"; !strings.Contains(out, want) {
		t.Errorf("the log does not carry %q\n%s", want, out)
	}
	if got := readFile(t, filepath.Join(root, "/etc/postfix/main.cf")); got != conf {
		t.Errorf("main.cf is %q, want it untouched", got)
	}
	if exists(filepath.Join(mb, "postfix.edited")) || exists(filepath.Join(mb, "postfix.was-running")) {
		t.Error("the body wrote a marker without postconf")
	}
	if out, code := run(rebaseContent(r.Validate, root)); code != 0 {
		t.Errorf("validate exit %d without postconf\n%s", code, out)
	}
}

const nfsID = "muster.service.nfs_export_access"

// nfsBefore holds no_root_squash as an option token (in a client's list, or
// in a default list a blank-led "-" opens, the line's end included), in a
// path, in a client name, in a comment and behind a continuation (O-26,
// O-60, O-64); nfsAfter is what the swap leaves: only the option tokens
// change.
const nfsBefore = "/srv/no_root_squash_area 192.0.2.1(rw,no_root_squash,sync)\n" +
	"/b 192.0.2.2(no_root_squash)\n" +
	"/c 192.0.2.3(rw,no_root_squash,no_root_squash)\n" +
	"/d -no_root_squash 192.0.2.4\n" +
	"/e 192.0.2.5(rw) # no_root_squash\n" +
	"/srv/x-no_root_squash 192.0.2.9(rw) 192.0.2.10(no_root_squash)\n" +
	"#/g 192.0.2.7(no_root_squash)\n" +
	"/f 192.0.2.6(rw) # (no_root_squash)\n" +
	"/t\t-no_root_squash 192.0.2.4\n" +
	"/h \\\n\t192.0.2.11(rw,no_root_squash)\n" +
	"/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)\n" +
	"/s -no_root_squash 192.0.2.7 -rw 192.0.2.8\n" +
	"/s -no_root_squash -rw 192.0.2.9\n" +
	"/z 192.0.2.12 -no_root_squash\n" +
	"/p no_root_squash(rw)\n"

const nfsAfter = "/srv/no_root_squash_area 192.0.2.1(rw,root_squash,sync)\n" +
	"/b 192.0.2.2(root_squash)\n" +
	"/c 192.0.2.3(rw,root_squash,root_squash)\n" +
	"/d -root_squash 192.0.2.4\n" +
	"/e 192.0.2.5(rw) # no_root_squash\n" +
	"/srv/x-no_root_squash 192.0.2.9(rw) 192.0.2.10(root_squash)\n" +
	"#/g 192.0.2.7(no_root_squash)\n" +
	"/f 192.0.2.6(rw) # (no_root_squash)\n" +
	"/t\t-root_squash 192.0.2.4\n" +
	"/h \\\n\t192.0.2.11(rw,root_squash)\n" +
	"/srv/ci 192.0.2.0/24(rw,root_squash,fsid=1)\n" +
	"/s -root_squash 192.0.2.7 -rw 192.0.2.8\n" +
	"/s -root_squash -rw 192.0.2.9\n" +
	"/z 192.0.2.12 -root_squash\n" +
	"/p no_root_squash(rw)\n"

// §4.9, O-26, O-30: the swap changes only no_root_squash option tokens to
// root_squash; exportfs -ra runs only when this run swapped and found the
// server active; a host whose exports live only in /etc/exports.d and a
// symlinked /etc/exports are left, and the validate passes over both.
func TestNfsSwapsOnlyOptionTokens(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("root: the body chowns")
	}
	r := shippedRemediation(t, nfsID)
	validate := func(t *testing.T, root, bin, stub string) int {
		t.Helper()
		_, code := runBody(t, root, bin, rebaseContent(r.Validate, root), "STUB="+stub, "ROOT="+root)
		return code
	}
	run := func(t *testing.T, conf string, active bool, mb string) (root, bin, stub string) {
		t.Helper()
		root, bin, stub = contentTree(t)
		writeUnder(t, root, "/etc/exports", conf)
		if active {
			writeUnder(t, stub, "/active/nfs-server.service", "")
		}
		if out, code := runContentBodyIn(t, r, root, bin, stub, mb); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		return root, bin, stub
	}
	t.Run("stopped", func(t *testing.T) {
		mb := t.TempDir()
		root, bin, stub := run(t, nfsBefore, false, mb)
		f := filepath.Join(root, "/etc/exports")
		if got := readFile(t, f); got != nfsAfter {
			t.Errorf("exports is\n%q\nwant\n%q", got, nfsAfter)
		}
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("exports mode %v (%v), want 0644 kept", fi.Mode(), err)
		}
		if exists(filepath.Join(stub, "calls")) {
			t.Errorf("a stopped server was re-exported: %s", readFile(t, filepath.Join(stub, "calls")))
		}
		if !exists(filepath.Join(mb, "nfs.edited")) || exists(filepath.Join(mb, "nfs.was-running")) {
			t.Error("markers: want edited and no was-running")
		}
		if code := validate(t, root, bin, stub); code != 0 {
			t.Errorf("validate exit %d after the body", code)
		}
		if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
			t.Fatalf("second run exit %d\n%s", code, out)
		}
		if got := readFile(t, f); got != nfsAfter {
			t.Errorf("the second run changed exports to %q", got)
		}
	})
	t.Run("validate fails before the body", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		writeUnder(t, root, "/etc/exports", nfsBefore)
		if code := validate(t, root, bin, stub); code == 0 {
			t.Error("the validate passes over no_root_squash")
		}
	})
	t.Run("running", func(t *testing.T) {
		mb := t.TempDir()
		_, _, stub := run(t, nfsBefore, true, mb)
		if got, want := readIf(t, filepath.Join(stub, "calls")), "exportfs -ra\n"+nfsAfter; got != want {
			t.Errorf("calls %q, want one exportfs -ra over the swapped file %q", got, want)
		}
		if !exists(filepath.Join(mb, "nfs.edited")) || !exists(filepath.Join(mb, "nfs.was-running")) {
			t.Error("markers: want edited and was-running")
		}
	})
	t.Run("running, nothing to swap", func(t *testing.T) {
		mb := t.TempDir()
		_, _, stub := run(t, nfsAfter, true, mb)
		if exists(filepath.Join(stub, "calls")) {
			t.Errorf("an unchanged exports was re-exported: %s", readFile(t, filepath.Join(stub, "calls")))
		}
		if exists(filepath.Join(mb, "nfs.edited")) {
			t.Error("an edited marker without a swap")
		}
	})
	t.Run("rerun with an earlier marker", func(t *testing.T) {
		mb := t.TempDir()
		writeUnder(t, mb, "/nfs.edited", "")
		writeUnder(t, mb, "/nfs.was-running", "")
		_, _, stub := run(t, nfsAfter, true, mb)
		if exists(filepath.Join(stub, "calls")) {
			t.Errorf("an earlier run's marker re-exported: %s", readFile(t, filepath.Join(stub, "calls")))
		}
		if exists(filepath.Join(mb, "nfs.edited")) {
			t.Error("the earlier run's edited marker survived this run")
		}
	})
	t.Run("eleven on one line", func(t *testing.T) {
		// the loop is bounded at ten passes: what is left fails the validate
		conf := "/q 192.0.2.14(" + strings.Repeat("no_root_squash,", 10) + "no_root_squash)\n"
		root, bin, stub := run(t, conf, false, t.TempDir())
		if got, want := readFile(t, filepath.Join(root, "/etc/exports")), "/q 192.0.2.14(no_root_squash,"+strings.Repeat("root_squash,", 9)+"root_squash)\n"; got != want {
			t.Errorf("exports is %q, want %q", got, want)
		}
		if code := validate(t, root, bin, stub); code == 0 {
			t.Error("the validate passes over a no_root_squash the bound left")
		}
	})
	t.Run("exports.d only", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		const frag = "/x 192.0.2.1(no_root_squash)\n"
		writeUnder(t, root, "/etc/exports.d/a.exports", frag)
		writeUnder(t, stub, "/active/nfs-server.service", "")
		if out, code := runContentBody(t, r, root, bin, stub); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		if got := readFile(t, filepath.Join(root, "/etc/exports.d/a.exports")); got != frag {
			t.Errorf("the fragment is %q, want it left to the operator", got)
		}
		if exists(filepath.Join(root, "/etc/exports")) || exists(filepath.Join(stub, "calls")) {
			t.Error("the body created /etc/exports or re-exported")
		}
		if code := validate(t, root, bin, stub); code != 0 {
			t.Errorf("validate exit %d on an exports.d-only host", code)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root, bin, stub := contentTree(t)
		const target = "/x 192.0.2.1(no_root_squash)\n"
		victim := filepath.Join(root, "victim")
		writeUnder(t, root, "/victim", target)
		link := filepath.Join(root, "/etc/exports")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, link); err != nil {
			t.Fatal(err)
		}
		writeUnder(t, stub, "/active/nfs-server.service", "")
		mb := t.TempDir()
		if out, code := runContentBodyIn(t, r, root, bin, stub, mb); code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		if got, err := os.Readlink(link); err != nil || got != victim {
			t.Errorf("exports is %q (%v), want the link to %s", got, err, victim)
		}
		if got := readFile(t, victim); got != target {
			t.Errorf("the link's target holds %q", got)
		}
		if exists(filepath.Join(mb, "nfs.edited")) || exists(filepath.Join(stub, "calls")) {
			t.Error("the body swapped or re-exported through the link")
		}
		if code := validate(t, root, bin, stub); code != 0 {
			t.Errorf("validate exit %d over the link", code)
		}
	})
}

// O-9, O-30, O-32: the declared rollback restores /etc/exports and, when
// this run swapped and found the server active, re-exports the restored
// file; a stopped server is never re-exported.
func TestNfsRollbackReexports(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("root: the body chowns")
	}
	for _, active := range []bool{true, false} {
		t.Run(fmt.Sprintf("active %v", active), func(t *testing.T) {
			root, bin, stub := contentTree(t)
			writeUnder(t, root, "/etc/exports", nfsBefore)
			if active {
				writeUnder(t, stub, "/active/nfs-server.service", "")
			}
			p := contentBlock(t, nfsID, root, true)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 || !strings.Contains(out, nfsID+": validate failed") {
				t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
			}
			for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
				if strings.Contains(out, bad) {
					t.Errorf("the output carries %q\n%s", bad, out)
				}
			}
			if got := readFile(t, filepath.Join(root, "/etc/exports")); got != nfsBefore {
				t.Errorf("exports is %q after the block, want %q", got, nfsBefore)
			}
			calls := readIf(t, filepath.Join(stub, "calls"))
			if active {
				if want := "exportfs -ra\n" + nfsAfter + "exportfs -ra\n" + nfsBefore; calls != want {
					t.Errorf("calls %q, want the body's exportfs over the swap, then the rollback's over the restored file %q", calls, want)
				}
			} else if calls != "" {
				t.Errorf("a stopped server was re-exported: %s", calls)
			}
		})
	}
}
