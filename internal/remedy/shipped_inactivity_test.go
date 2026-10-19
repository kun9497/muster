//go:build linux

package remedy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/controls"
)

// The inactivity body (3D-2d §4.4, O-7, O-40, O-43) bounds useradd's
// INACTIVE= and shadow field 7 of every local login-capable account, root
// included, and skips any account the bound would disable on the spot. Its
// tests run under a temporary root with chage and date stubbed first on PATH
// (inactivityTree) and the body's paths rebased under that root
// (rebaseInactivity). The tree is this file's own, never accountTree: the
// password_policy tests read real time, these read $STUB/now. No test reaches
// the host's chage, /etc/shadow or /etc/default/useradd.

const inactivityID = "muster.beyond.account_inactivity_lock"

// inactivityToday is the day the date stub answers, far enough from any real
// day that a body reading the host's clock would be seen.
const inactivityToday = 20000

// inactivityTree returns a temporary root, a bin directory of stubs and the
// stubs' state directory (STUB); the stubs need STUB and ROOT. chage logs its
// argv to $STUB/chage and accepts only `-I <v> -- <name>`: it exits 1 for a
// name with no row in $ROOT/etc/shadow (as chage does) and otherwise writes
// <v> into field 7 of every row of that name (-1 clears it). After the edit a
// name with a $STUB/delete/<name> marker loses its row (an account deleted
// before the rollback). date prints $STUB/now for +%s and runs the real date
// otherwise (O-33). selinuxenabled exits 1; restorecon logs and exits 99.
func inactivityTree(t *testing.T) (root, bin, stub string) {
	root, bin, stub = t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "chage", `printf '%s\n' "$*" >> "$STUB/chage"
if [ "$#" -ne 4 ] || [ "$1" != -I ] || [ "$3" != -- ]; then exit 99; fi
f="$ROOT/etc/shadow"
awk -F: -v n="$4" '$1 == n { f = 1 } END { exit !f }' "$f" || { echo "chage: user '$4' does not exist in /etc/shadow" >&2; exit 1; }
awk -F: -v OFS=: -v n="$4" -v v="$2" '$1 == n { $7 = (v == "-1") ? "" : v } { print }' "$f" > "$f.new"
cat "$f.new" > "$f"
rm -f "$f.new"
if [ -e "$STUB/delete/$4" ]; then
  awk -F: -v n="$4" '$1 != n' "$f" > "$f.new"
  cat "$f.new" > "$f"
  rm -f "$f.new"
fi
`)
	writeStub(t, bin, "date", `case "$1" in +%s) cat "$STUB/now";; *) exec /bin/date "$@";; esac
`)
	writeStub(t, bin, "selinuxenabled", "exit 1\n")
	writeStub(t, bin, "restorecon", `printf '%s\n' "$*" >> "$STUB/restorecon"; exit 99`+"\n")
	writeUnder(t, stub, "/now", fmt.Sprintf("%d\n", inactivityToday*86400+3600))
	return root, bin, stub
}

// rebaseInactivity is rebaseAccounts with the two paths only this body
// reads, /etc/default/useradd and /etc/shells.
func rebaseInactivity(s, root string) string {
	s = rebaseAccounts(s, root)
	for _, p := range []string{"/etc/default/useradd", "/etc/shells"} {
		s = strings.ReplaceAll(s, p, root+p)
	}
	return s
}

func TestRebaseInactivityRebasesEachPathOnce(t *testing.T) {
	const root = "/tmp/r"
	in := "/etc/default/useradd /etc/login.defs /etc/shells /etc/passwd /etc/shadow /dev/null"
	want := "/tmp/r/etc/default/useradd /tmp/r/etc/login.defs /tmp/r/etc/shells /tmp/r/etc/passwd /tmp/r/etc/shadow /dev/null"
	if got := rebaseInactivity(in, root); got != want {
		t.Errorf("rebaseInactivity:\n got %s\nwant %s", got, want)
	}
	r := shippedRemediation(t, inactivityID)
	for _, s := range []string{r.Script, r.Validate, r.Rollback} {
		if got := rebaseInactivity(s, root); strings.Contains(got, root+root) {
			t.Errorf("rebased twice:\n%s", got)
		}
		// every host path the body names is one the tests rebase
		rest := rebaseInactivity(s, root)
		for _, p := range []string{"/etc/", "/var/", "/run/"} {
			if i := strings.Index(strings.ReplaceAll(rest, root+"/", ""), p); i >= 0 {
				t.Errorf("an unrebased %s path is left in:\n%s", p, s)
			}
		}
	}
}

// inactivityRun runs the shipped body (under the template's umask 077),
// then its validate, directly, with MB and the parameter at its default
// unless env overrides it (a later entry wins).
func inactivityRun(t *testing.T, root, bin, stub, mb string, env ...string) (out string, code int) {
	t.Helper()
	c := shippedControl(t, inactivityID)
	all := append(append(pEnv(t, c), "MB="+mb, "STUB="+stub, "ROOT="+root), env...)
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseInactivity(c.Remediation.Script, root)
	return runBody(t, root, bin, body, all...)
}

func inactivityValidate(t *testing.T, root, bin, stub, mb string) (string, int) {
	t.Helper()
	c := shippedControl(t, inactivityID)
	return runBody(t, root, bin, rebaseInactivity(c.Remediation.Validate, root), append(pEnv(t, c), "MB="+mb, "STUB="+stub, "ROOT="+root)...)
}

func inactivityRollback(t *testing.T, root, bin, stub, mb string) (string, int) {
	t.Helper()
	c := shippedControl(t, inactivityID)
	return runBody(t, root, bin, rebaseInactivity(c.Remediation.Rollback, root), append(pEnv(t, c), "MB="+mb, "STUB="+stub, "ROOT="+root)...)
}

// field7 is field 7 of name's last row in the tree's shadow, and whether a
// row exists.
func field7(t *testing.T, root, name string) (string, bool) {
	t.Helper()
	v, ok := "", false
	for _, l := range strings.Split(readFile(t, filepath.Join(root, "/etc/shadow")), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 8 && f[0] == name {
			v, ok = f[6], true
		}
	}
	return v, ok
}

// setShadow rewrites field i (0-based) of name's rows in the tree's shadow.
func setShadow(t *testing.T, root, name string, i int, v string) {
	t.Helper()
	p := filepath.Join(root, "/etc/shadow")
	lines := strings.Split(readFile(t, p), "\n")
	for k, l := range lines {
		f := strings.Split(l, ":")
		if len(f) >= 8 && f[0] == name {
			f[i] = v
			lines[k] = strings.Join(f, ":")
		}
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dayDate(d int) string { return time.Unix(int64(d)*86400, 0).UTC().Format("2006-01-02") }

// inactivityHost is a tree whose accounts cover every rule of §4.4 step 3 and
// O-40 at n=35 with today = inactivityToday. zed sits before root in passwd so
// the "root first" order is the body's, not the file's.
func inactivityHost(t *testing.T, root string) {
	t.Helper()
	const d = inactivityToday
	writeUnder(t, root, "/etc/login.defs", "# defs\nUID_MIN 1000\n")
	writeUnder(t, root, "/etc/shells", "# shells\n/bin/sh\n/bin/bash\n/usr/sbin/nologin\n")
	writeUnder(t, root, "/etc/default/useradd", "GROUP=100\nINACTIVE=-1\n")
	passwd := []string{"zed:x:1009", "root:x:0", "toor:x:0", "edge:x:1001", "edge1:x:1002", "zero:x:1003", "nolast:x:1004",
		"nolast2:x:1005", "nomax:x:1006", "in20:x:1007", "neg5:x:1008", "junk:x:1010", "ghost:x:1011", "big:x:1013",
		"agejunk:x:1014", "lockd:x:1015", "negmax:x:1017", "negmax2:x:1018", "dup:x:1019"}
	var pw strings.Builder
	for _, p := range passwd {
		pw.WriteString(p + ":100::/home/x:/bin/bash\n")
	}
	// a second big row: one account, bounded once (the scan keeps one line per name)
	pw.WriteString("big:x:1016:100::/home/x:/bin/sh\nsvc:x:1012:100::/:/usr/sbin/nologin\nsys:x:500:100::/:/bin/sh\n")
	writeUnder(t, root, "/etc/passwd", pw.String())
	shadow := fmt.Sprintf(""+
		"zed:$6$x:%d:0:60:7:::\n"+ // dated: last + 95
		"root:$6$x:%d:0:60:7:::\n"+ // root with a real maximum: dated
		"toor:$6$x:%d:0:99999:7:::\n"+ // root with no real maximum: no date
		"edge:$6$x:%d:0:60:7:::\n"+ // expired exactly max + 35 days ago: skipped (>=)
		"edge1:$6$x:%d:0:60:7:::\n"+ // one day less: changed, disabled tomorrow
		"zero:$6$x:0:0:60:7:::\n"+ // must change at next login
		"nolast:$6$x::0:60:7:::\n"+ // O-40: no last change under a real maximum
		"nolast2:$6$x::0:99999:7:::\n"+ // no last change, no real maximum: changed
		"nomax:$6$x:%d:0::7:::\n"+ // empty max: changed
		"in20:$6$x:%d:0:60:7:20::\n"+ // in bounds: left
		"neg5:$6$x:%d:0:60:7:-5::\n"+ // below -1: the clause accepts it, left
		"junk:$6$x:%d:0:60:7:abc::\n"+ // not a number: skipped
		"big:$6$x:%d:0:99999:7:99::\n"+ // above the bound: changed, 99 recorded
		"agejunk:$6$x:1x:0:60:7:::\n"+ // ageing not numbers: skipped
		"lockd:!:%d:0:99999:7:::\n"+ // a locked password is login-capable too
		"svc:*:%d:0:99999:7:::\n"+ // nologin: not enumerated
		"sys:$6$x:%d:0:99999:7:::\n"+ // 0 < uid < UID_MIN: not enumerated
		// O-77: pam_unix guards only max != -1, so a max below -1 still
		// expires the password; with the bound set it disables at once
		"negmax:$6$x:%d:0:-2:7:::\n"+
		"negmax2:$6$x::0:-2:7:::\n"+
		// O-77: chage and pam_unix read the first row, the body the last
		"dup:$6$x:%d:0:60:7:::\n"+
		"dup:$6$x:%d:0:99999:7:::\n",
		d-5, d-10, d-1000, d-95, d-94, d-500, d, d, d, d, d, d, d, d-100, d-500, d)
	writeUnder(t, root, "/etc/shadow", shadow)
}

const ail = inactivityID + ": "

// O-7, O-40, O-46: who is changed, who is skipped and named, who is left
// silently, and in which order the dates are logged.
func TestInactivityBodySkipsAndNames(t *testing.T) {
	needSh(t)
	root, bin, stub := inactivityTree(t)
	inactivityHost(t, root)
	mb := t.TempDir()
	out, code := inactivityRun(t, root, bin, stub, mb)
	if code != 0 {
		t.Fatalf("body %d:\n%s", code, out)
	}
	changed := []string{"root", "toor", "zed", "edge1", "nolast2", "nomax", "big", "lockd"}
	var want strings.Builder
	for _, n := range changed {
		want.WriteString("-I 35 -- " + n + "\n")
	}
	if got := readFile(t, filepath.Join(stub, "chage")); got != want.String() {
		t.Errorf("chage calls:\n%s\nwant (uid 0 first, then passwd order):\n%s", got, want.String())
	}
	for _, n := range changed {
		if v, _ := field7(t, root, n); v != "35" {
			t.Errorf("%s field 7 %q after the body, want 35", n, v)
		}
	}
	for n, v := range map[string]string{"in20": "20", "neg5": "-5", "junk": "abc", "edge": "", "zero": "", "nolast": "", "agejunk": "", "negmax": "", "negmax2": "", "dup": "", "svc": "", "sys": ""} {
		if got, _ := field7(t, root, n); got != v {
			t.Errorf("%s field 7 %q, want %q (left)", n, got, v)
		}
	}
	const d = inactivityToday
	rootDate := ail + "root will be disabled on " + dayDate(d-10+95) + " unless its password changes"
	zedDate := ail + "zed will be disabled on " + dayDate(d-5+95) + " unless its password changes"
	for _, w := range []string{
		rootDate, zedDate,
		ail + "edge1 will be disabled on " + dayDate(d+1) + " unless its password changes",
		ail + "edge: password expired 35 days ago; the bound would disable it now; change its password first",
		ail + "zero: must change its password at next login, left as is",
		ail + "nolast: must change its password at next login, left as is",
		ail + "junk: inactivity field is not a number, left as is",
		ail + "ghost: no " + root + "/etc/shadow entry, left as is", // the log names the rebased path
		ail + "agejunk: password ageing fields are not numbers or the maximum is below -1, left as is",
		ail + "negmax: password ageing fields are not numbers or the maximum is below -1, left as is",
		ail + "negmax2: password ageing fields are not numbers or the maximum is below -1, left as is",
		ail + "dup: more than one " + root + "/etc/shadow entry, left as is",
	} {
		if !strings.Contains(out, w+"\n") {
			t.Errorf("no log line %q:\n%s", w, out)
		}
	}
	if i, j := strings.Index(out, rootDate), strings.Index(out, zedDate); i < 0 || j < 0 || i > j {
		t.Errorf("root's date line is not printed first:\n%s", out)
	}
	for _, n := range []string{"toor", "nolast2", "nomax", "big", "lockd", "in20", "neg5", "svc", "sys"} {
		if strings.Contains(out, ail+n+" ") || strings.Contains(out, ail+n+":") {
			t.Errorf("%s is named in the log:\n%s", n, out)
		}
	}
	if got := readFile(t, filepath.Join(mb, "inactive.run")); got != strings.Join(changed, "\n")+"\n" {
		t.Errorf("inactive.run:\n%s", got)
	}
	wantList := "root:-1\ntoor:-1\nzed:-1\nedge1:-1\nnolast2:-1\nnomax:-1\nbig:99\nlockd:-1\n"
	if got := readFile(t, filepath.Join(mb, "inactive.list")); got != wantList {
		t.Errorf("inactive.list:\n%s\nwant:\n%s", got, wantList)
	}
	if got := readFile(t, filepath.Join(root, "/etc/default/useradd")); got != "GROUP=100\nINACTIVE=35\n" {
		t.Errorf("useradd: %q", got)
	}
	if out, code := inactivityValidate(t, root, bin, stub, mb); code != 0 {
		t.Errorf("validate %d: %s", code, out)
	}
	if exists(filepath.Join(stub, "restorecon")) {
		t.Errorf("restorecon ran over an edited file")
	}

	// O-39: a rerun that changes no account leaves an empty inactive.run,
	// keeps the list and passes its validate.
	if err := os.Remove(filepath.Join(stub, "chage")); err != nil {
		t.Fatal(err)
	}
	out, code = inactivityRun(t, root, bin, stub, mb)
	if code != 0 {
		t.Fatalf("rerun %d:\n%s", code, out)
	}
	if exists(filepath.Join(stub, "chage")) {
		t.Errorf("the rerun ran chage:\n%s", readFile(t, filepath.Join(stub, "chage")))
	}
	if got := readFile(t, filepath.Join(mb, "inactive.run")); got != "" {
		t.Errorf("inactive.run after a rerun that changed nothing: %q", got)
	}
	if got := readFile(t, filepath.Join(mb, "inactive.list")); got != wantList {
		t.Errorf("inactive.list after the rerun:\n%s", got)
	}
	if out, code := inactivityValidate(t, root, bin, stub, mb); code != 0 {
		t.Errorf("validate after a rerun that changed nothing %d: %s", code, out)
	}
}

// §4.4 step 1: a negative bound would disable every account whose password
// has expired; it is refused before any write.
func TestInactivityRefusesANegativeBound(t *testing.T) {
	needSh(t)
	root, bin, stub := inactivityTree(t)
	inactivityHost(t, root)
	mb := t.TempDir()
	writeUnder(t, mb, "/inactive.run", "stale\n")
	out, code := inactivityRun(t, root, bin, stub, mb, "P_max_inactive_days=-1")
	if code != 1 || !strings.Contains(out, ail+"max_inactive_days is negative; refused\n") {
		t.Fatalf("exit %d, want 1 and the refusal:\n%s", code, out)
	}
	if exists(filepath.Join(stub, "chage")) {
		t.Errorf("chage ran:\n%s", readFile(t, filepath.Join(stub, "chage")))
	}
	if got := readFile(t, filepath.Join(root, "/etc/default/useradd")); got != "GROUP=100\nINACTIVE=-1\n" {
		t.Errorf("useradd changed: %q", got)
	}
	if got := readFile(t, filepath.Join(mb, "inactive.run")); got != "" {
		t.Errorf("inactive.run %q: an earlier run's record survived a refused run (O-16)", got)
	}
}

// §4.4 step 2, O-38, O-62: the INACTIVE= line read as useradd reads it, and
// rewritten, appended or created only when that value is outside 0..n.
func TestInactivityUseraddLine(t *testing.T) {
	needSh(t)
	el9 := readFile(t, filepath.Join("..", "collect", "collectors", "testdata", "useradd.default.el9"))
	ubuntu := readFile(t, filepath.Join("..", "collect", "collectors", "testdata", "useradd.default.ubuntu"))
	for _, c := range []struct {
		name, before, after string
		missing             bool
	}{
		{name: "EL's -1", before: "GROUP=100\nINACTIVE=-1\nEXPIRE=\n", after: "GROUP=100\nINACTIVE=35\nEXPIRE=\n"},
		{name: "EL9 stock", before: el9, after: strings.Replace(el9, "\nINACTIVE=-1\n", "\nINACTIVE=35\n", 1)},
		{name: "Ubuntu's comment", before: "SHELL=/bin/sh\n# INACTIVE=-1\n", after: "SHELL=/bin/sh\n# INACTIVE=-1\nINACTIVE=35\n"},
		{name: "Ubuntu stock", before: ubuntu, after: ubuntu + "INACTIVE=35\n"},
		{name: "octal 24 kept", before: "INACTIVE=030\n", after: "INACTIVE=030\n"},
		{name: "hex 48 rewritten", before: "INACTIVE=0x30\n", after: "INACTIVE=35\n"},
		{name: "zero kept", before: "INACTIVE=0\n", after: "INACTIVE=0\n"},
		{name: "35 kept", before: "INACTIVE=35\n", after: "INACTIVE=35\n"},
		{name: "36 rewritten", before: "INACTIVE=36\n", after: "INACTIVE=35\n"},
		{name: "the last line wins", before: "INACTIVE=10\nX=1\nINACTIVE=99\n", after: "INACTIVE=35\nX=1\nINACTIVE=35\n"},
		{name: "a later good line keeps both", before: "INACTIVE=99\nINACTIVE=7\n", after: "INACTIVE=99\nINACTIVE=7\n"},
		{name: "indented is no line", before: " INACTIVE=7\n", after: " INACTIVE=7\nINACTIVE=35\n"},
		{name: "junk rewritten", before: "INACTIVE=abc\n", after: "INACTIVE=35\n"},
		{name: "CR rewritten", before: "INACTIVE=30\r\n", after: "INACTIVE=35\n"},
		{name: "no final newline", before: "SHELL=/bin/sh", after: "SHELL=/bin/sh\nINACTIVE=35\n"},
		{name: "empty file", before: "", after: "INACTIVE=35\n"},
		{name: "missing", missing: true, after: "INACTIVE=35\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := inactivityTree(t)
			writeUnder(t, root, "/etc/shells", "/bin/sh\n")
			writeUnder(t, root, "/etc/passwd", "root:x:0:0::/root:/bin/sh\n")
			writeUnder(t, root, "/etc/shadow", "root:$6$x:19000:0:99999:7:0::\n") // in bounds: no chage
			f := filepath.Join(root, "/etc/default/useradd")
			if c.missing {
				if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				writeUnder(t, root, "/etc/default/useradd", c.before)
			}
			mb := t.TempDir()
			out, code := inactivityRun(t, root, bin, stub, mb)
			if code != 0 {
				t.Fatalf("body %d:\n%s", code, out)
			}
			if got := readFile(t, f); got != c.after {
				t.Errorf("useradd:\n%q\nwant\n%q", got, c.after)
			}
			if c.missing || c.before != c.after {
				if m := mode(t, f); m != "644" {
					t.Errorf("useradd mode %s, want 644", m)
				}
			}
			if out, code := inactivityValidate(t, root, bin, stub, mb); code != 0 {
				t.Errorf("validate %d: %s", code, out)
			}
			if exists(filepath.Join(stub, "chage")) {
				t.Errorf("chage ran:\n%s", readFile(t, filepath.Join(stub, "chage")))
			}
		})
	}

	t.Run("symlink", func(t *testing.T) {
		root, bin, stub := inactivityTree(t)
		inactivityHost(t, root)
		f := filepath.Join(root, "/etc/default/useradd")
		victim := filepath.Join(root, "victim")
		writeUnder(t, root, "/victim", "INACTIVE=-1\n")
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, f); err != nil {
			t.Fatal(err)
		}
		out, code := inactivityRun(t, root, bin, stub, t.TempDir())
		if code != 1 || !strings.Contains(out, ail+f+" is a symlink, left as is\n") {
			t.Fatalf("exit %d, want 1 and the refusal:\n%s", code, out)
		}
		if got := readFile(t, victim); got != "INACTIVE=-1\n" {
			t.Errorf("the link's target holds %q", got)
		}
		if exists(filepath.Join(stub, "chage")) {
			t.Errorf("chage ran:\n%s", readFile(t, filepath.Join(stub, "chage")))
		}
	})
}

// The validate checks the useradd line and every name this run changed that
// still has a shadow row; a name the run skipped is never checked (X-10).
func TestInactivityValidate(t *testing.T) {
	needSh(t)
	for _, c := range []struct {
		name, useradd, run, shadow string
		ok                         bool
	}{
		{"in bounds", "INACTIVE=35\n", "a\n", "a:x:1:0:60:7:35::\n", true},
		{"octal useradd", "INACTIVE=030\n", "a\n", "a:x:1:0:60:7:0::\n", true},
		{"useradd above", "INACTIVE=36\n", "", "", false},
		{"useradd unset", "# INACTIVE=35\n", "", "", false},
		{"useradd -1", "INACTIVE=-1\n", "", "", false},
		{"field above", "INACTIVE=35\n", "a\n", "a:x:1:0:60:7:36::\n", false},
		{"field empty", "INACTIVE=35\n", "a\n", "a:x:1:0:60:7:::\n", false},
		{"field junk", "INACTIVE=35\n", "a\n", "a:x:1:0:60:7:abc::\n", false},
		{"the last row wins", "INACTIVE=35\n", "a\n", "a:x:1:0:60:7:35::\na:x:1:0:60:7:99::\n", false},
		{"a deleted account", "INACTIVE=35\n", "a\n", "b:x:1:0:60:7:::\n", true},
		{"an unchanged name is not checked", "INACTIVE=35\n", "", "a:x:1:0:60:7:99::\n", true},
		{"an empty run with no shadow", "INACTIVE=35\n", "", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := inactivityTree(t)
			writeUnder(t, root, "/etc/default/useradd", c.useradd)
			if c.shadow != "" {
				writeUnder(t, root, "/etc/shadow", c.shadow)
			}
			mb := t.TempDir()
			writeUnder(t, mb, "/inactive.run", c.run)
			if out, code := inactivityValidate(t, root, bin, stub, mb); (code == 0) != c.ok {
				t.Errorf("validate exit %d, want ok=%v: %s", code, c.ok, out)
			}
		})
	}
}

// inactivityBlock is the shipped block, built through the plan, with its
// paths under root.
func inactivityBlock(t *testing.T, root string, failValidate bool) *Plan {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := set.ByID(inactivityID)
	p := mustBuild(t, scriptReport(row(inactivityID, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
	if len(p.Items) != 1 || !p.Items[0].Script || !p.Items[0].Planned {
		t.Fatalf("plan %+v, want one planned scripted item", p.Items)
	}
	it := &p.Items[0]
	if it.Risk != "lockout_risk" || it.Rollback != "both" || len(it.Backup) != 1 || it.Backup[0] != "/etc/default/useradd" {
		t.Fatalf("item risk %s, rollback %s, backup %v", it.Risk, it.Rollback, it.Backup)
	}
	for i := range it.Backup {
		it.Backup[i] = rebaseInactivity(it.Backup[i], root)
	}
	it.ScriptBody = rebaseInactivity(it.ScriptBody, root)
	it.ValidateCmd = rebaseInactivity(it.ValidateCmd, root)
	it.RollbackBody = rebaseInactivity(it.RollbackBody, root)
	if failValidate {
		it.ValidateCmd = "false"
	}
	return p
}

// §4.4 rollback, O-43: a failed block replays this run's names from
// inactive.list (an empty field as -1), an account deleted since is
// reported while the others are still restored, and the template's restore
// puts useradd back.
func TestInactivityRollbackReplaysTheList(t *testing.T) {
	needSh(t)
	t.Run("failed validate", func(t *testing.T) {
		root, bin, stub := inactivityTree(t)
		const before = "GROUP=100\nINACTIVE=-1\n"
		writeUnder(t, root, "/etc/default/useradd", before)
		writeUnder(t, root, "/etc/shells", "/bin/sh\n")
		writeUnder(t, root, "/etc/passwd", "a:x:1000:100::/:/bin/sh\nb:x:1001:100::/:/bin/sh\ngone:x:1002:100::/:/bin/sh\n")
		writeUnder(t, root, "/etc/shadow", "a:$6$x:19990:0:99999:7:::\nb:$6$x:19990:0:99999:7:99::\ngone:$6$x:19990:0:99999:7:::\n")
		writeUnder(t, stub, "/delete/gone", "")
		bk := filepath.Join(root, "bk")
		out, _, code := runScriptWith(t, inactivityBlock(t, root, true), root, bk, runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
		if code != 1 || !strings.Contains(out, ail+"validate failed") {
			t.Fatalf("exit %d, want 1 and validate failed:\n%s", code, out)
		}
		// on purpose: gone's replay fails, so the declared rollback does
		if !strings.Contains(out, ail+"rollback failed (rc 1)") || strings.Contains(out, "ROLLBACK INCOMPLETE") {
			t.Errorf("want the rollback to fail on the deleted account alone:\n%s", out)
		}
		want := "-I 35 -- a\n-I 35 -- b\n-I 35 -- gone\n-I -1 -- a\n-I 99 -- b\n-I -1 -- gone\n"
		if got := readFile(t, filepath.Join(stub, "chage")); got != want {
			t.Errorf("chage calls:\n%s\nwant:\n%s", got, want)
		}
		if v, _ := field7(t, root, "a"); v != "" {
			t.Errorf("a field 7 %q after the rollback, want empty", v)
		}
		if v, _ := field7(t, root, "b"); v != "99" {
			t.Errorf("b field 7 %q after the rollback, want 99", v)
		}
		if got := readFile(t, filepath.Join(root, "/etc/default/useradd")); got != before {
			t.Errorf("useradd after the rollback: %q", got)
		}
	})

	t.Run("passing block", func(t *testing.T) {
		root, bin, stub := inactivityTree(t)
		inactivityHost(t, root)
		p := inactivityBlock(t, root, false)
		if !strings.Contains(string(Script(p)), "\n# keep a second session open; a lockout here needs console access\n") {
			t.Errorf("a lockout_risk block carries no second-session header")
		}
		out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
		if code != 0 || !strings.Contains(out, ail+"done") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if v, _ := field7(t, root, "root"); v != "35" {
			t.Errorf("root field 7 %q after a passing block", v)
		}
	})

	t.Run("rerun replays only its own names", func(t *testing.T) {
		root, bin, stub := inactivityTree(t)
		inactivityHost(t, root)
		mb := t.TempDir()
		if out, code := inactivityRun(t, root, bin, stub, mb); code != 0 {
			t.Fatalf("first run %d:\n%s", code, out)
		}
		// between the runs: big drifts above the bound again, and nomax's
		// field becomes text the body cannot restore (skipped on the rerun
		// with its field out of bounds; the validate never checks it)
		setShadow(t, root, "big", 6, "50")
		setShadow(t, root, "nomax", 6, "abc")
		if err := os.Remove(filepath.Join(stub, "chage")); err != nil {
			t.Fatal(err)
		}
		out, code := inactivityRun(t, root, bin, stub, mb)
		if code != 0 || !strings.Contains(out, ail+"nomax: inactivity field is not a number, left as is\n") {
			t.Fatalf("rerun %d:\n%s", code, out)
		}
		if got := readFile(t, filepath.Join(mb, "inactive.run")); got != "big\n" {
			t.Errorf("inactive.run after the rerun: %q", got)
		}
		if got := readFile(t, filepath.Join(mb, "inactive.list")); !strings.Contains(got, "\nbig:99\n") || strings.Contains(got, "big:50") {
			t.Errorf("inactive.list did not keep big's first record:\n%s", got)
		}
		if out, code := inactivityValidate(t, root, bin, stub, mb); code != 0 {
			t.Errorf("validate after the rerun %d (nomax is out of bounds and not this run's): %s", code, out)
		}
		if out, code := inactivityRollback(t, root, bin, stub, mb); code != 0 {
			t.Fatalf("rollback %d:\n%s", code, out)
		}
		if got := readFile(t, filepath.Join(stub, "chage")); got != "-I 35 -- big\n-I 99 -- big\n" {
			t.Errorf("chage calls of the rerun and its rollback:\n%s", got)
		}
		for n, v := range map[string]string{"big": "99", "root": "35", "nomax": "abc", "lockd": "35"} {
			if got, _ := field7(t, root, n); got != v {
				t.Errorf("%s field 7 %q after the rerun's rollback, want %q", n, got, v)
			}
		}
	})
}
