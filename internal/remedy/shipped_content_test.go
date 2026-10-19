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
//     (0, O-59), reload/restart/try-restart/reload-or-restart (0);
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
  reload|restart|try-restart|reload-or-restart) printf '%s\n' "$*" >> "$STUB/calls"; reads "$u" >> "$STUB/calls"; exit 0;;
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
	} {
		if out, code := runBody(t, root, bin, c.cmd, env...); code != c.code {
			t.Errorf("%s: exit %d, want %d\n%s", c.cmd, code, c.code, out)
		}
	}
	if got, want := readFile(t, filepath.Join(stub, "calls")), "restart vsftpd.service\nlisten=YES\nexportfs -ra\n(no exports)\n"; got != want {
		t.Errorf("calls %q, want %q", got, want)
	}
}

// runContentBody runs the shipped script of r rebased under root, as the
// review script does (umask 077, log defined), and returns its output and
// exit code.
func runContentBody(t *testing.T, r *controls.Remediation, root, bin, stub string) (string, int) {
	t.Helper()
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseContent(r.Script, root)
	return runBody(t, root, bin, body, "MB="+t.TempDir(), "STUB="+stub, "ROOT="+root)
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
