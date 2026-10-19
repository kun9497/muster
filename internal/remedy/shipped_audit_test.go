//go:build linux

package remedy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// The audit bodies (3D-2d §4.1–§4.3) act on auditd's files and on the
// kernel's audit state. Their tests run under a temporary root with every
// audit tool stubbed first on PATH (auditTree), the bodies' paths rebased
// under that root (rebaseAudit), and the whole block built from the shipped
// control (auditBlock). No test reaches the host's auditctl, augenrules or
// systemctl: collect-root runs this package as root on a VM with a live
// auditd, and a real call would corrupt its later oracle step.

const diskID = "muster.beyond.audit_disk_actions"

// auditTree returns a temporary root, a bin directory of stubs and the
// stubs' state directory (STUB). The stubs need STUB and ROOT in the
// environment. What a test does not model fails closed (log, exit 99), so a
// body that reaches a tool the test did not model fails its block rather
// than touching the host (O-32):
//   - auditctl: every call appended to $STUB/auditctl. -l prints $STUB/rules
//     when it is non-empty and "No rules" otherwise (exit 1 while
//     $STUB/list_fails exists); -s prints $STUB/status (seeded from the
//     collector's auditctl_s.sample, O-33) and exits with the number in
//     $STUB/status_rc (0 without it); -D empties $STUB/rules (and copies
//     the audit.rules it sees to $STUB/audit.rules.at-D); one or more
//     of -f, -b, -r, -e, --backlog_wait_time <n> rewrite the status key
//     (failure, backlog_limit, rate_limit, enabled, backlog_wait_time);
//     --signal reload signals the daemon: it exits 1 unless auditd.service's
//     state is active (no daemon to signal, O-71), and while
//     $STUB/reload_dies exists the daemon dies on it (the state becomes
//     inactive). -D, the
//     settings and the reload also append to $STUB/calls (see below).
//     Anything else (--loginuid-immutable, -R, -w, a glued -e2, another
//     signal) exits 99;
//   - augenrules: every call appended to $STUB/augenrules. With no argument
//     it concatenates $ROOT/etc/audit/rules.d/*.rules (glob order) into
//     $ROOT/etc/audit/audit.rules, or prints "No change" and leaves the file
//     when the result equals it (O-55); --load regenerates the same way and
//     then copies the result's -w/-a/-A lines into $STUB/rules (the load's
//     -D replaces the kernel list). A missing rules.d exits 1; any other
//     argument 99;
//   - systemctl: a wrapper (O-33) over units_test.go's systemctlStub, held
//     unchanged as bin/systemctl-units: unit state in $STUB/state/<u>
//     ("<enabled> <active>"), every call appended to $STUB/calls. On start
//     auditd.service it runs the augenrules --load stub (the unit's
//     ExecStartPost) only after a start that succeeded (O-70): a masked or
//     missing unit starts nothing and loads nothing;
//   - service, restorecon, chcon, auditd, pkill, killall: not modelled (99);
//   - selinuxenabled: exit 1 (SELinux off).
//
// $STUB/calls is the one shared log of what changed the daemon or the
// kernel, in order: systemctlStub's argv lines, "auditctl -D", "auditctl
// <settings>", "auditctl --signal reload" followed by the auditd.conf the
// daemon rereads at that moment, and "augenrules --load" followed by the
// rules it loaded. There is no kill stub: no audit body sends a signal by
// pid (O-29, TestAuditBodiesSendNoBareKill).
func auditTree(t *testing.T) (root, bin, stub string) {
	t.Helper()
	root, bin, stub = t.TempDir(), t.TempDir(), t.TempDir()
	status, err := os.ReadFile(filepath.Join("..", "collect", "collectors", "testdata", "auditctl_s.sample"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stub, "status"), status, 0o644); err != nil {
		t.Fatal(err)
	}
	writeStub(t, bin, "auditctl", `printf '%s\n' "$*" >> "$STUB/auditctl"
case "$1" in
  -l) [ "$#" -eq 1 ] || exit 99
    if [ -e "$STUB/list_fails" ]; then echo "auditctl: error listing rules" >&2; exit 1; fi
    if [ -s "$STUB/rules" ]; then cat "$STUB/rules"; else echo "No rules"; fi
    exit 0;;
  -s) [ "$#" -eq 1 ] || exit 99
    cat "$STUB/status"
    exit "$(cat "$STUB/status_rc" 2>/dev/null || echo 0)";;
  -D) [ "$#" -eq 1 ] || exit 99
    : > "$STUB/rules"; echo "auditctl -D" >> "$STUB/calls"
    cat "$ROOT/etc/audit/audit.rules" > "$STUB/audit.rules.at-D" 2>/dev/null || :
    exit 0;;
  --signal) [ "$#" -eq 2 ] && [ "$2" = reload ] || exit 99
    sa=; if [ -f "$STUB/state/auditd.service" ]; then read -r se sa < "$STUB/state/auditd.service"; fi
    [ "$sa" = active ] || { echo "auditctl: no audit daemon to signal" >&2; exit 1; }
    echo "auditctl --signal reload" >> "$STUB/calls"
    cat "$ROOT/etc/audit/auditd.conf" >> "$STUB/calls" 2>/dev/null || echo "(no auditd.conf)" >> "$STUB/calls"
    if [ -e "$STUB/reload_dies" ] && [ -f "$STUB/state/auditd.service" ]; then
      read -r se sa < "$STUB/state/auditd.service"; printf '%s inactive\n' "$se" > "$STUB/state/auditd.service"
    fi
    exit 0;;
esac
[ "$#" -gt 0 ] || exit 99
args=$*
while [ "$#" -gt 0 ]; do
  [ "$#" -ge 2 ] || exit 99
  case "$1" in -f|-b|-r|-e|--backlog_wait_time) ;; *) exit 99;; esac
  case "$2" in ''|*[!0-9]*) exit 99;; esac
  shift 2
done
echo "auditctl $args" >> "$STUB/calls"
set -- $args
while [ "$#" -gt 0 ]; do
  case "$1" in -f) k=failure;; -b) k=backlog_limit;; -r) k=rate_limit;; -e) k=enabled;; --backlog_wait_time) k=backlog_wait_time;; esac
  awk -v k="$k" -v v="$2" '$1 == k { print k " " v; f = 1; next } { print } END { if (!f) print k " " v }' "$STUB/status" > "$STUB/status.new" &&
    mv -f "$STUB/status.new" "$STUB/status"
  shift 2
done
exit 0
`)
	writeStub(t, bin, "augenrules", `printf '%s\n' "$*" >> "$STUB/augenrules"
case "$*" in ""|--load) ;; *) exit 99;; esac
d="$ROOT/etc/audit/rules.d"; out="$ROOT/etc/audit/audit.rules"
[ -d "$d" ] || { echo "augenrules: no $d" >&2; exit 1; }
: > "$STUB/augenrules.new"
for r in "$d"/*.rules; do if [ -f "$r" ]; then cat "$r" >> "$STUB/augenrules.new"; fi; done
if [ -f "$out" ] && cmp -s "$STUB/augenrules.new" "$out"; then
  rm -f "$STUB/augenrules.new"; [ "$1" = --load ] || { echo "augenrules: No change"; exit 0; }
else
  mv -f "$STUB/augenrules.new" "$out"
fi
if [ "$1" = --load ]; then
  grep -E '^[[:space:]]*-[waA]' "$out" > "$STUB/rules" || :
  echo "augenrules --load" >> "$STUB/calls"; cat "$STUB/rules" >> "$STUB/calls"
fi
exit 0
`)
	writeStub(t, bin, "systemctl-units", systemctlStub)
	writeStub(t, bin, "systemctl", `verb=; u=
for a in "$@"; do case "$a" in -*) ;; *) if [ -z "$verb" ]; then verb=$a; else u=$a; fi;; esac; done
if [ "$verb" = start ] && [ "$u" = auditd.service ]; then
  '`+filepath.Join(bin, "systemctl-units")+`' "$@" || exit
  '`+filepath.Join(bin, "augenrules")+`' --load || :
  exit 0
fi
exec '`+filepath.Join(bin, "systemctl-units")+`' "$@"
`)
	for _, tool := range []string{"service", "restorecon", "chcon", "auditd", "pkill", "killall"} {
		writeStub(t, bin, tool, `printf '%s\n' "$*" >> "$STUB/`+tool+`"
exit 99
`)
	}
	writeStub(t, bin, "selinuxenabled", "exit 1\n")
	return root, bin, stub
}

// rebaseAudit prefixes root to every host path an audit body names, in one
// pass (O-31): /etc/audit/ covers auditd.conf, rules.d and audit.rules;
// /etc/sudoers covers /etc/sudoers.d/; /etc/shadow and /etc/gshadow are
// distinct entries, so neither is rebased inside the other.
func rebaseAudit(s, root string) string {
	return strings.NewReplacer(
		"/etc/audit/", root+"/etc/audit/",
		"/etc/passwd", root+"/etc/passwd",
		"/etc/group", root+"/etc/group",
		"/etc/shadow", root+"/etc/shadow",
		"/etc/gshadow", root+"/etc/gshadow",
		"/etc/sudoers", root+"/etc/sudoers",
	).Replace(s)
}

// auditBlock is the plan of one FAIL row of the shipped control id, its
// backup, body, validate and rollback rebased under root (the contentBlock
// shape); failValidate makes the validate `false`.
func auditBlock(t *testing.T, id, root string, failValidate bool) *Plan {
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
	rebaseItem(t, it, root)
	if failValidate {
		it.ValidateCmd = "false"
	}
	return p
}

// rebaseItem rebases one planned item's backup, body, validate and
// rollback under root, failing the test on a path rebased twice.
func rebaseItem(t *testing.T, it *Item, root string) {
	t.Helper()
	for i := range it.Backup {
		it.Backup[i] = rebaseAudit(it.Backup[i], root)
	}
	it.ScriptBody = rebaseAudit(it.ScriptBody, root)
	it.ValidateCmd = rebaseAudit(it.ValidateCmd, root)
	it.RollbackBody = rebaseAudit(it.RollbackBody, root)
	for _, s := range append([]string{it.ScriptBody, it.ValidateCmd, it.RollbackBody}, it.Backup...) {
		if strings.Contains(s, root+root) {
			t.Fatalf("%s: rebased twice: %s", it.ID, s)
		}
	}
}

func TestRebaseAuditRebasesEachPathOnce(t *testing.T) {
	const root = "/tmp/r"
	in := "/etc/audit/auditd.conf /etc/audit/rules.d/50-muster.rules /etc/passwd /etc/group /etc/gshadow /etc/shadow /etc/sudoers /etc/sudoers.d/ /etc/hosts"
	want := "/tmp/r/etc/audit/auditd.conf /tmp/r/etc/audit/rules.d/50-muster.rules /tmp/r/etc/passwd /tmp/r/etc/group /tmp/r/etc/gshadow /tmp/r/etc/shadow /tmp/r/etc/sudoers /tmp/r/etc/sudoers.d/ /etc/hosts"
	got := rebaseAudit(in, root)
	if got != want || strings.Contains(got, root+root) {
		t.Errorf("rebaseAudit:\n got %s\nwant %s", got, want)
	}
}

// O-32, O-33: the audit stubs answer what the audit tests model, fail
// closed on anything else, and log the changes to the one calls file.
func TestAuditTreeStubsFailClosed(t *testing.T) {
	needSh(t)
	root, bin, stub := auditTree(t)
	writeUnder(t, root, "/etc/audit/auditd.conf", "disk_full_action = syslog\n")
	writeUnder(t, root, "/etc/audit/rules.d/10-a.rules", "-D\n-b 8192\n-w /etc/passwd -p wa -k x\n")
	writeUnder(t, stub, "/state/auditd.service", "disabled inactive\n")
	env := []string{"STUB=" + stub, "ROOT=" + root}
	for _, c := range []struct {
		cmd  string
		code int
		out  string // when set, the command's output
	}{
		{"auditctl -l", 0, "No rules\n"},
		{"auditctl -s | grep -c .", 0, "10\n"},
		{"auditctl -s | grep '^loginuid_immutable '", 0, "loginuid_immutable 0 unlocked\n"},
		{`printf '1\n' > "$STUB/status_rc"; auditctl -s >/dev/null`, 1, ""},
		{`rm "$STUB/status_rc"; auditctl -b 4321 -f 2`, 0, ""},
		{"auditctl -s | grep -E '^(backlog_limit|failure) '", 0, "failure 2\nbacklog_limit 4321\n"},
		{"auditctl -e2", 99, ""},
		{"auditctl --loginuid-immutable", 99, ""},
		{"auditctl -R /etc/audit/audit.rules", 99, ""},
		{"auditctl --signal stop", 99, ""},
		{"auditctl --signal reload", 1, ""},
		{"augenrules", 0, ""},
		{"augenrules", 0, "augenrules: No change\n"},
		{"augenrules --check", 99, ""},
		{"auditctl -l", 0, "No rules\n"},
		{"systemctl start auditd.service", 0, ""},
		{"systemctl is-active --quiet auditd.service", 0, ""},
		{"auditctl -l", 0, "-w /etc/passwd -p wa -k x\n"},
		{`: > "$STUB/list_fails"; auditctl -l`, 1, ""},
		{`rm "$STUB/list_fails"; auditctl -D; auditctl -l`, 0, "No rules\n"},
		{`: > "$STUB/reload_dies"; auditctl --signal reload; systemctl is-active --quiet auditd.service`, 1, ""},
		{"auditctl --signal reload", 1, ""},
		{`printf 'masked inactive\n' > "$STUB/state/auditd.service"; systemctl start auditd.service`, 1, ""},
		{"auditctl -l", 0, "No rules\n"},
		{`rm "$STUB/state/auditd.service"; systemctl start auditd.service`, 1, ""},
		{"auditctl -l", 0, "No rules\n"},
		{"service auditd reload", 99, ""},
		{"restorecon -- /etc/audit/auditd.conf", 99, ""},
		{"pkill -HUP auditd", 99, ""},
		{"selinuxenabled", 1, ""},
	} {
		out, code := runBody(t, root, bin, c.cmd, env...)
		if code != c.code || c.out != "" && out != c.out {
			t.Errorf("%s: exit %d, output %q; want %d, %q", c.cmd, code, out, c.code, c.out)
		}
	}
	if got := readFile(t, filepath.Join(root, "/etc/audit/audit.rules")); got != "-D\n-b 8192\n-w /etc/passwd -p wa -k x\n" {
		t.Errorf("audit.rules %q", got)
	}
	const conf = "disk_full_action = syslog\n"
	want := "auditctl -b 4321 -f 2\n" +
		"start auditd.service\naugenrules --load\n-w /etc/passwd -p wa -k x\nis-active --quiet auditd.service\n" +
		"auditctl -D\nauditctl --signal reload\n" + conf + "is-active --quiet auditd.service\n" +
		"start auditd.service\nstart auditd.service\n"
	if got := readFile(t, filepath.Join(stub, "calls")); got != want {
		t.Errorf("calls\n%q\nwant\n%q", got, want)
	}
	if !exists(filepath.Join(stub, "restorecon")) || !exists(filepath.Join(stub, "service")) {
		t.Error("a fail-closed stub did not log its call")
	}
}

// O-29, O-56: auditd is reloaded with auditctl --signal reload and nothing
// else; no rendered audit block sends a signal by pid (kill reads no PATH
// stub, and a stale pid file can name a reused pid) or runs the legacy
// service action (EL's runs augenrules --load before the signal).
func TestAuditBodiesSendNoBareKill(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	kill := regexp.MustCompile(`\b(kill|pkill|killall)\b|\bservice auditd\b`)
	n := 0
	for _, c := range set.Controls {
		if !strings.HasPrefix(c.ID, "muster.beyond.audit") || c.Remediation == nil || c.Remediation.Script == "" {
			continue
		}
		n++
		p := mustBuild(t, scriptReport(row(c.ID, "FAIL", "clause does not hold", "", importanceSeverity[c.Importance])), set, Options{})
		lines := strings.Split(string(Script(p)), "\n")
		fn := "fix_" + strings.ReplaceAll(c.ID, ".", "_")
		in := false
		for _, l := range lines {
			switch {
			case l == fn+"() {":
				in = true
			case l == "}":
				in = false
			case in && kill.MatchString(l):
				t.Errorf("%s: the rendered block signals by pid or through service: %s", c.ID, l)
			}
		}
		if !strings.Contains(strings.Join(lines, "\n"), fn+"() {") {
			t.Errorf("%s: no block %s in the rendered script", c.ID, fn)
		}
	}
	if n == 0 {
		t.Fatal("no scripted audit control; the scan proves nothing")
	}
}

// stockEL9 is the collector's auditd.conf.sample: the stock EL9 file, with
// admin_space_left_action, disk_full_action and disk_error_action SUSPEND.
func stockEL9(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "collect", "collectors", "testdata", "auditd.conf.sample"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// el9Fixed is stockEL9 as the body leaves it at the defaults: the three
// SUSPEND lines become syslog, nothing else moves.
func el9Fixed(t *testing.T) string {
	t.Helper()
	return strings.NewReplacer(
		"admin_space_left_action = SUSPEND\n", "admin_space_left_action = syslog\n",
		"disk_full_action = SUSPEND\n", "disk_full_action = syslog\n",
		"disk_error_action = SUSPEND\n", "disk_error_action = syslog\n").Replace(stockEL9(t))
}

func stockExec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "collect", "collectors", "testdata", "auditd.conf.exec"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// diskEnv is the P_ assignments of the shipped control at the defaults, with
// over replacing some of them, as environment entries.
func diskEnv(t *testing.T, over map[string]string) []string {
	t.Helper()
	var env []string
	for _, e := range pEnv(t, shippedControl(t, diskID)) {
		name := strings.TrimPrefix(e[:strings.Index(e, "=")], "P_")
		if v, ok := over[name]; ok {
			e = "P_" + name + "=" + v
		}
		env = append(env, e)
	}
	return env
}

// runAudit runs the shipped body (or, with validate, the validate) of id
// rebased under root as the review script does (umask 077, log defined),
// with the record directory mb and the parameters of env.
func runAudit(t *testing.T, id, root, bin, stub, mb string, validate bool, env []string) (string, int) {
	t.Helper()
	r := shippedRemediation(t, id)
	body := "umask 077\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\n" + rebaseAudit(r.Script, root)
	if validate {
		body = rebaseAudit(r.Validate, root)
	}
	return runBody(t, root, bin, body, append(env, "MB="+mb, "STUB="+stub, "ROOT="+root)...)
}

func leaveLine(key string) string {
	return diskID + ": " + key + ": no writable value in the list in force; left to the operator"
}

// §4.3, O-6, O-17: a key whose action (its last line's first word, lower
// cased) is outside its list has every line rewritten, at column one, to the
// first list member auditd accepts for that key and that keeps the host up;
// a key whose list holds no such member is left byte-identical and logged;
// a line whose first word is in the list is never rewritten; nothing else in
// the file moves; the validate passes after the body; a second run changes
// nothing.
func TestDiskActionsWriteOnlyAcceptedValues(t *testing.T) {
	needSh(t)
	el9 := stockEL9(t)
	sub := func(s string, kv ...string) string {
		for i := 0; i < len(kv); i += 2 {
			if !strings.Contains(s, kv[i]) {
				t.Fatalf("the fixture carries no %q", kv[i])
			}
			s = strings.Replace(s, kv[i], kv[i+1], 1)
		}
		return s
	}
	stockFixed := sub(el9,
		"admin_space_left_action = SUSPEND\n", "admin_space_left_action = syslog\n",
		"disk_full_action = SUSPEND\n", "disk_full_action = syslog\n",
		"disk_error_action = SUSPEND\n", "disk_error_action = syslog\n")
	for _, row := range []struct {
		name, conf, want string
		over             map[string]string
		keys             string   // disk.keys after the run
		leaves           []string // keys the O-23 line names
	}{
		{name: "stock EL9 at the defaults", conf: el9, want: stockFixed,
			keys: "admin_space_left_action\ndisk_full_action\ndisk_error_action\n"},
		{name: "a first member auditd rejects for the key", conf: el9, over: map[string]string{"allowed_disk_error_actions": "rotate syslog"},
			want: stockFixed, keys: "admin_space_left_action\ndisk_full_action\ndisk_error_action\n"},
		{name: "a list with no writable member", conf: el9, over: map[string]string{"allowed_space_actions": "keep_logs"},
			want: sub(el9, "disk_full_action = SUSPEND\n", "disk_full_action = syslog\n", "disk_error_action = SUSPEND\n", "disk_error_action = syslog\n"),
			keys: "disk_full_action\ndisk_error_action\n", leaves: []string{"space_left_action", "admin_space_left_action"}},
		{name: "halt and single only", conf: el9, over: map[string]string{"allowed_disk_full_actions": "halt single"},
			want: sub(el9, "admin_space_left_action = SUSPEND\n", "admin_space_left_action = syslog\n", "disk_error_action = SUSPEND\n", "disk_error_action = syslog\n"),
			keys: "admin_space_left_action\ndisk_error_action\n", leaves: []string{"disk_full_action"}},
		{name: "rotate first", conf: el9, over: map[string]string{"allowed_space_actions": "email rotate syslog"},
			want: sub(el9, "admin_space_left_action = SUSPEND\n", "admin_space_left_action = rotate\n",
				"disk_full_action = SUSPEND\n", "disk_full_action = syslog\n", "disk_error_action = SUSPEND\n", "disk_error_action = syslog\n"),
			keys: "admin_space_left_action\ndisk_full_action\ndisk_error_action\n"},
		{name: "exec actions", conf: stockExec(t),
			want: sub(stockExec(t), "admin_space_left_action = SUSPEND\n", "admin_space_left_action = syslog\n", "disk_full_action = SUSPEND\n", "disk_full_action = syslog\n"),
			keys: "admin_space_left_action\ndisk_full_action\n"},
		{name: "admin_space_left_action is its own key",
			conf: "space_left_action = suspend\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n",
			want: "space_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n",
			keys: "space_left_action\n"},
		{name: "every line of a key, any case, a tab, a comment kept",
			conf: "# space_left_action = ignore\nSpace_Left_Action = IGNORE\n  space_left_action\t=\tsuspend\nadmin_space_left_action = SINGLE\ndisk_full_action=Halt\ndisk_error_action = syslog\nmax_log_file_action = ignore\n",
			want: "# space_left_action = ignore\nspace_left_action = syslog\nspace_left_action = syslog\nadmin_space_left_action = SINGLE\ndisk_full_action=Halt\ndisk_error_action = syslog\nmax_log_file_action = rotate\n",
			keys: "space_left_action\nmax_log_file_action\n"},
		{name: "an earlier line in the list, the last outside",
			conf: "space_left_action = syslog\nspace_left_action = suspend\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = keep_logs\n",
			want: "space_left_action = syslog\nspace_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = keep_logs\n",
			keys: "space_left_action\n"},
		{name: "an empty value", conf: "space_left_action =\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n",
			want: "space_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n",
			keys: "space_left_action\n"},
		{name: "keep_logs first for a full log", conf: sub(el9, "max_log_file_action = ROTATE\n", "max_log_file_action = SUSPEND\n"),
			over: map[string]string{"allowed_rotate_actions": "keep_logs rotate"},
			want: sub(stockFixed, "max_log_file_action = ROTATE\n", "max_log_file_action = keep_logs\n"),
			keys: "max_log_file_action\nadmin_space_left_action\ndisk_full_action\ndisk_error_action\n"},
		{name: "nothing to write", conf: stockFixed, want: stockFixed},
	} {
		t.Run(row.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			f := filepath.Join(root, "/etc/audit/auditd.conf")
			writeUnder(t, root, "/etc/audit/auditd.conf", row.conf)
			if err := os.Chmod(f, 0o640); err != nil {
				t.Fatal(err)
			}
			env := diskEnv(t, row.over)
			mb := t.TempDir()
			out, code := runAudit(t, diskID, root, bin, stub, mb, false, env)
			if code != 0 {
				t.Fatalf("body exit %d\n%s", code, out)
			}
			if got := readFile(t, f); got != row.want {
				t.Errorf("auditd.conf is\n%q\nwant\n%q", got, row.want)
			}
			if fi, err := os.Stat(f); err != nil {
				t.Error(err)
			} else if fi.Mode().Perm() != 0o640 {
				t.Errorf("auditd.conf mode %v, want 0640 kept", fi.Mode())
			}
			if got := readIf(t, filepath.Join(mb, "disk.keys")); !sameLines(got, row.keys) {
				t.Errorf("disk.keys %q, want %q", got, row.keys)
			}
			if got, want := exists(filepath.Join(mb, "auditd.edited")), row.keys != ""; got != want {
				t.Errorf("auditd.edited exists %v, want %v", got, want)
			}
			for _, k := range []string{"space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action", "max_log_file_action"} {
				want := 0
				for _, l := range row.leaves {
					if l == k {
						want = 1
					}
				}
				if n := strings.Count(out, leaveLine(k)); n != want {
					t.Errorf("the leave line for %s appears %d times, want %d\n%s", k, n, want, out)
				}
			}
			if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code != 0 {
				t.Errorf("validate exit %d after the body\n%s", code, out)
			}
			if out, code := runAudit(t, diskID, root, bin, stub, mb, false, env); code != 0 {
				t.Fatalf("second run exit %d\n%s", code, out)
			}
			if got := readFile(t, f); got != row.want {
				t.Errorf("the second run changed auditd.conf to %q", got)
			}
			if exists(filepath.Join(mb, "disk.keys")) || exists(filepath.Join(mb, "auditd.edited")) {
				t.Error("the second run, which wrote nothing, left a disk.keys or edited record")
			}
			if exists(filepath.Join(stub, "auditctl")) {
				t.Errorf("an inactive auditd was signalled: %s", readFile(t, filepath.Join(stub, "auditctl")))
			}
		})
	}
}

// sameLines is whether a and b hold the same lines, in any order.
func sameLines(a, b string) bool {
	x, y := strings.Fields(a), strings.Fields(b)
	if len(x) != len(y) {
		return false
	}
	seen := map[string]int{}
	for _, s := range x {
		seen[s]++
	}
	for _, s := range y {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// The validate fails over a key the body wrote when the file says otherwise
// again (the collector's reading, the list in force), and does not look at a
// key the body did not write.
func TestDiskActionsValidateReadsOnlyThisRunsKeys(t *testing.T) {
	needSh(t)
	root, bin, stub := auditTree(t)
	env := diskEnv(t, nil)
	mb := t.TempDir()
	writeUnder(t, root, "/etc/audit/auditd.conf", "space_left_action = suspend\nadmin_space_left_action = ignore\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code != 0 {
		t.Errorf("validate exit %d with no disk.keys\n%s", code, out)
	}
	writeUnder(t, mb, "/disk.keys", "space_left_action\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code == 0 {
		t.Errorf("the validate passes over a written key that reads suspend\n%s", out)
	}
	writeUnder(t, root, "/etc/audit/auditd.conf", "space_left_action = Exec /x\nadmin_space_left_action = ignore\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code != 0 {
		t.Errorf("validate exit %d over a written key whose first word is in the list\n%s", code, out)
	}
	writeUnder(t, root, "/etc/audit/auditd.conf", "  Space_Left_Action\t=\tSYSLOG\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code != 0 {
		t.Errorf("validate exit %d over a written key read case blind, as the collector reads it\n%s", code, out)
	}
	writeUnder(t, root, "/etc/audit/auditd.conf", "admin_space_left_action = ignore\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, env); code == 0 {
		t.Errorf("the validate passes over a written key the file no longer carries\n%s", out)
	}
	writeUnder(t, root, "/etc/audit/auditd.conf", "space_left_action = rotate\n")
	if out, code := runAudit(t, diskID, root, bin, stub, mb, true, diskEnv(t, map[string]string{"allowed_space_actions": "syslog"})); code == 0 {
		t.Errorf("the validate passes over a value outside the list in force\n%s", out)
	}
}

// §4.3, O-9, O-16, O-29: the reload is auditctl --signal reload, sent once,
// only when this run wrote the file and found auditd.service active; an
// inactive daemon, an unedited file and an earlier run's markers signal
// nothing, and an earlier run's disk.keys naming a key this run leaves is
// not validated.
func TestDiskActionsReloadOnlyARunningDaemon(t *testing.T) {
	needSh(t)
	el9 := stockEL9(t)
	run := func(t *testing.T, conf, state string, mb string, env []string) (root, stub, out string) {
		t.Helper()
		root, bin, stub := auditTree(t)
		writeUnder(t, root, "/etc/audit/auditd.conf", conf)
		if state != "" {
			writeUnder(t, stub, "/state/auditd.service", state+"\n")
		}
		out, code := runAudit(t, diskID, root, bin, stub, mb, false, env)
		if code != 0 {
			t.Fatalf("body exit %d\n%s", code, out)
		}
		return root, stub, out
	}
	t.Run("running", func(t *testing.T) {
		mb := t.TempDir()
		root, stub, _ := run(t, el9, "enabled active", mb, diskEnv(t, nil))
		if got := readFile(t, filepath.Join(stub, "auditctl")); got != "--signal reload\n" {
			t.Errorf("auditctl calls %q, want one --signal reload", got)
		}
		edited := readFile(t, filepath.Join(root, "/etc/audit/auditd.conf"))
		if calls := readFile(t, filepath.Join(stub, "calls")); calls != "is-active --quiet auditd.service\nauditctl --signal reload\n"+edited {
			t.Errorf("calls %q, want the reload over the edited file", calls)
		}
		if !exists(filepath.Join(mb, "auditd.was-running")) || !exists(filepath.Join(mb, "auditd.edited")) {
			t.Error("the run left no was-running or edited marker")
		}
	})
	t.Run("inactive", func(t *testing.T) {
		mb := t.TempDir()
		_, stub, _ := run(t, el9, "enabled inactive", mb, diskEnv(t, nil))
		if exists(filepath.Join(stub, "auditctl")) {
			t.Errorf("an inactive auditd was signalled: %s", readFile(t, filepath.Join(stub, "auditctl")))
		}
		if exists(filepath.Join(mb, "auditd.was-running")) {
			t.Error("a was-running marker for an inactive auditd")
		}
	})
	t.Run("no unit", func(t *testing.T) {
		_, stub, _ := run(t, el9, "", t.TempDir(), diskEnv(t, nil))
		if exists(filepath.Join(stub, "auditctl")) {
			t.Errorf("auditd was signalled without a unit: %s", readFile(t, filepath.Join(stub, "auditctl")))
		}
	})
	t.Run("running, nothing to write", func(t *testing.T) {
		conf := "space_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n"
		_, stub, _ := run(t, conf, "enabled active", t.TempDir(), diskEnv(t, nil))
		if exists(filepath.Join(stub, "auditctl")) {
			t.Errorf("an unedited auditd was signalled: %s", readFile(t, filepath.Join(stub, "auditctl")))
		}
	})
	t.Run("rerun with an earlier run's records", func(t *testing.T) {
		mb := t.TempDir()
		writeUnder(t, mb, "/auditd.was-running", "")
		writeUnder(t, mb, "/auditd.edited", "")
		writeUnder(t, mb, "/disk.keys", "space_left_action\n")
		env := diskEnv(t, map[string]string{"allowed_space_actions": "keep_logs"})
		conf := "space_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n"
		root, stub, out := run(t, conf, "enabled inactive", mb, env)
		if !strings.Contains(out, leaveLine("space_left_action")) {
			t.Errorf("no leave line for space_left_action\n%s", out)
		}
		if exists(filepath.Join(stub, "auditctl")) {
			t.Errorf("an earlier run's markers signalled an inactive auditd: %s", readFile(t, filepath.Join(stub, "auditctl")))
		}
		for _, m := range []string{"auditd.was-running", "auditd.edited", "disk.keys"} {
			if exists(filepath.Join(mb, m)) {
				t.Errorf("the earlier run's %s survived this run", m)
			}
		}
		if got := readFile(t, filepath.Join(root, "/etc/audit/auditd.conf")); got != conf {
			t.Errorf("auditd.conf changed to %q", got)
		}
	})
}

// The whole block over a stale disk.keys: the body removes the earlier
// run's record first, so the validate checks no key this run left, and the
// block ends done.
func TestDiskActionsRerunBlockIsDone(t *testing.T) {
	needSh(t)
	root, bin, stub := auditTree(t)
	conf := "space_left_action = syslog\nadmin_space_left_action = halt\ndisk_full_action = halt\ndisk_error_action = halt\nmax_log_file_action = rotate\n"
	writeUnder(t, root, "/etc/audit/auditd.conf", conf)
	p := auditBlock(t, diskID, root, false)
	it := &p.Items[0]
	set := false
	for i := range it.ScriptParams {
		if it.ScriptParams[i].Name == "allowed_space_actions" {
			it.ScriptParams[i].Value, set = "keep_logs", true
		}
	}
	if !set {
		t.Fatal("the block carries no allowed_space_actions")
	}
	bk := filepath.Join(root, "bk")
	writeUnder(t, bk, "/blocks/"+fnName(diskID)+"/disk.keys", "space_left_action\n")
	out, _, code := runScriptWith(t, p, root, bk, runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 0 || !strings.Contains(out, diskID+": done") {
		t.Fatalf("exit %d, want 0 and done\n%s", code, out)
	}
	for _, k := range []string{"space_left_action", "admin_space_left_action"} {
		if !strings.Contains(out, leaveLine(k)) {
			t.Errorf("no leave line for %s\n%s", k, out)
		}
	}
	if got := readFile(t, filepath.Join(root, "/etc/audit/auditd.conf")); got != conf {
		t.Errorf("auditd.conf changed to %q", got)
	}
}

// O-9, O-32: on a failed validate the declared rollback restores
// auditd.conf and only then sends the reload, so the daemon rereads the file
// as it was; an inactive daemon is never signalled; the template's restore
// that follows is a harmless second pass. A daemon that dies on the reload
// fails the validate's liveness half; the rollback restores the file and its
// reload then finds no daemon (O-71), so the block reports rollback failed
// and the rollback never starts auditd.
func TestDiskActionsRollbackRestoresThenReloads(t *testing.T) {
	needSh(t)
	for _, c := range []struct {
		name   string
		state  string
		dies   bool
		forced bool
	}{
		{"running, forced failure", "enabled active", false, true},
		{"inactive, forced failure", "enabled inactive", false, true},
		{"dies on the reload", "enabled active", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			before := stockEL9(t)
			writeUnder(t, root, "/etc/audit/auditd.conf", before)
			writeUnder(t, stub, "/state/auditd.service", c.state+"\n")
			if c.dies {
				writeUnder(t, stub, "/reload_dies", "")
			}
			p := auditBlock(t, diskID, root, c.forced)
			out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
			if code != 1 || !strings.Contains(out, diskID+": validate failed") {
				t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
			}
			for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
				if c.dies && bad == "rollback failed" {
					if !strings.Contains(out, diskID+": rollback failed") {
						t.Errorf("the rollback's reload of a dead daemon did not fail the rollback\n%s", out)
					}
					continue
				}
				if strings.Contains(out, bad) {
					t.Errorf("the output carries %q\n%s", bad, out)
				}
			}
			if got := readFile(t, filepath.Join(root, "/etc/audit/auditd.conf")); got != before {
				t.Errorf("auditd.conf after the block is\n%q\nwant\n%q", got, before)
			}
			calls := readIf(t, filepath.Join(stub, "calls"))
			if c.state == "enabled inactive" {
				if exists(filepath.Join(stub, "auditctl")) {
					t.Errorf("an inactive auditd was signalled: %s", readFile(t, filepath.Join(stub, "auditctl")))
				}
				return
			}
			if got := readFile(t, filepath.Join(stub, "auditctl")); got != "--signal reload\n--signal reload\n" {
				t.Errorf("auditctl calls %q, want the body's reload and the rollback's", got)
			}
			if !strings.Contains(calls, "auditctl --signal reload\n"+el9Fixed(t)) {
				t.Errorf("the body did not reload over its edit:\n%s", calls)
			}
			if c.dies {
				if strings.Contains(calls, "start auditd.service") || state(t, stub, "auditd.service") != "enabled inactive" {
					t.Errorf("the rollback started auditd: %s, calls %q", state(t, stub, "auditd.service"), calls)
				}
				if !strings.HasSuffix(calls, "auditctl --signal reload\n"+el9Fixed(t)+"is-active --quiet auditd.service\n") {
					t.Errorf("calls %q, want nothing after the validate's liveness check", calls)
				}
				return
			}
			if !strings.HasSuffix(calls, "auditctl --signal reload\n"+before) {
				t.Errorf("calls %q, want the rollback's reload over the restored file last", calls)
			}
		})
	}
}

// K2: a symlinked auditd.conf is refused before any write: the block fails,
// the link and its target are untouched, nothing is signalled, and the way
// back is complete.
func TestDiskActionsRefuseASymlinkedConf(t *testing.T) {
	needSh(t)
	root, bin, stub := auditTree(t)
	el9 := stockEL9(t)
	victim := filepath.Join(root, "victim")
	writeUnder(t, root, "/victim", el9)
	link := filepath.Join(root, "/etc/audit/auditd.conf")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	writeUnder(t, stub, "/state/auditd.service", "enabled active\n")
	p := auditBlock(t, diskID, root, false)
	out, _, code := runScriptWith(t, p, root, filepath.Join(root, "bk"), runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	if code != 1 || !strings.Contains(out, diskID+": "+link+" is a symlink, left as is") || !strings.Contains(out, diskID+": script failed") {
		t.Fatalf("exit %d, want 1 with the K2 line\n%s", code, out)
	}
	if strings.Contains(out, "ROLLBACK INCOMPLETE") || strings.Contains(out, "rollback failed") {
		t.Errorf("the way back was incomplete\n%s", out)
	}
	if got, err := os.Readlink(link); err != nil || got != victim {
		t.Errorf("auditd.conf links to %q (%v), want %s", got, err, victim)
	}
	if got := readFile(t, victim); got != el9 {
		t.Errorf("the link's target holds %q", got)
	}
	if exists(filepath.Join(stub, "auditctl")) {
		t.Errorf("auditd was signalled over a refused conf: %s", readFile(t, filepath.Join(stub, "auditctl")))
	}
}

const (
	rulesID  = "muster.beyond.audit_rules_loaded"
	activeID = "muster.beyond.auditd_active"
)

// auditRun runs the review script of p under root with the audit stubs
// first on PATH and the backup directory bk.
func auditRun(t *testing.T, p *Plan, root, bin, stub, bk string) (string, int) {
	t.Helper()
	out, _, code := runScriptWith(t, p, root, bk, runOpts{pathPrefix: bin, env: []string{"STUB=" + stub, "ROOT=" + root}})
	return out, code
}

// floorHost seeds a subset of the paths the floor watches (O-31: no
// /etc/gshadow, no /etc/sudoers.d/) and an empty rules.d under root.
func floorHost(t *testing.T, root string) {
	t.Helper()
	for _, f := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers"} {
		writeUnder(t, root, f, "x\n")
	}
	if err := os.MkdirAll(filepath.Join(root, "/etc/audit/rules.d"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// floorWant is the floor the body writes over floorHost's root: one wa watch
// per path that exists, rebased, in the body's order.
func floorWant(root string) string {
	return "-w " + root + "/etc/passwd -p wa -k muster-identity\n" +
		"-w " + root + "/etc/group -p wa -k muster-identity\n" +
		"-w " + root + "/etc/shadow -p wa -k muster-identity\n" +
		"-w " + root + "/etc/sudoers -p wa -k muster-privilege\n" +
		"-w " + root + "/etc/audit/ -p wa -k muster-audit-config\n"
}

// setStatus replaces the line of $STUB/status whose first field is key
// (an empty line removes it).
func setStatus(t *testing.T, stub, key, line string) {
	t.Helper()
	f := filepath.Join(stub, "status")
	var out []string
	found := false
	for _, l := range strings.Split(strings.TrimSuffix(readFile(t, f), "\n"), "\n") {
		if strings.Fields(l)[0] == key {
			found = true
			if line == "" {
				continue
			}
			l = line
		}
		out = append(out, l)
	}
	if !found {
		t.Fatalf("$STUB/status carries no %s line", key)
	}
	if err := os.WriteFile(f, []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rulesMB(bk string) string { return filepath.Join(bk, "blocks", fnName(rulesID)) }

// O-31, O-42: the floor's unrebased text, the seven paths and three keys of
// §4.2 written one printf line per existing path, and its backups.
func TestAuditRulesFloorText(t *testing.T) {
	r := shippedRemediation(t, rulesID)
	for _, want := range []string{
		"for w in /etc/passwd=muster-identity /etc/group=muster-identity /etc/shadow=muster-identity /etc/gshadow=muster-identity /etc/sudoers=muster-privilege /etc/sudoers.d/=muster-privilege /etc/audit/=muster-audit-config; do\n",
		`  if [ -e "${w%%=*}" ]; then printf -- '-w %s -p wa -k %s\n' "${w%%=*}" "${w#*=}"; fi` + "\n",
		"done > \"$f\"\n  chmod 0640 \"$f\"\n",
	} {
		if !strings.Contains(r.Script, want) {
			t.Errorf("the body carries no %q", want)
		}
	}
	if got := strings.Join(r.Backup, " "); got != "/etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules" {
		t.Errorf("backup %s", got)
	}
}

// O-3, O-23, O-41, O-42, O-46, O-57: the rules body refuses before any write
// on a pending lock in any spelling the body reads (the token anywhere on a
// line of rules.d or audit.rules, glued, zero-padded or signed), on a locked
// runtime, on an auditctl -s that cannot tell, on an auditctl -l that fails,
// on a missing or symlinked rules.d and on a symlinked drop-in: the block
// fails, no file is written, augenrules is never called and the kernel is
// never touched. -e 1 is no lock.
func TestAuditRefusesAPendingLock(t *testing.T) {
	needSh(t)
	pending := rulesID + ": a one-way audit setting is pending or in force; refused"
	cannot := rulesID + ": auditctl -s cannot tell the lock state; refused"
	type refusal struct {
		name string
		seed func(t *testing.T, root, stub string)
		line func(root string) string
	}
	fixed := func(s string) func(string) string { return func(string) string { return s } }
	missing := func(root string) string {
		return rulesID + ": " + root + "/etc/audit/rules.d is missing or a symlink; refused"
	}
	var rows []refusal
	for _, l := range []string{"-e 2", "-e2", "-e 02", "-e +2", "--loginuid-immutable", "-b 8192 -e 2", "-D -e 2"} {
		for _, f := range []string{"/etc/audit/rules.d/x.rules", "/etc/audit/audit.rules"} {
			l, f := l, f
			rows = append(rows, refusal{f + ": " + l, func(t *testing.T, root, _ string) { writeUnder(t, root, f, "-D\n"+l+"\n") }, fixed(pending)})
		}
	}
	rows = append(rows,
		refusal{"runtime enabled 2", func(t *testing.T, _, stub string) { setStatus(t, stub, "enabled", "enabled 2") }, fixed(pending)},
		refusal{"runtime loginuid_immutable 1", func(t *testing.T, _, stub string) {
			setStatus(t, stub, "loginuid_immutable", "loginuid_immutable 1 locked")
		}, fixed(pending)},
		refusal{"auditctl -s exits 1", func(t *testing.T, _, stub string) {
			writeUnder(t, stub, "/status", "enabled 1\n")
			writeUnder(t, stub, "/status_rc", "1\n")
		}, fixed(cannot)},
		refusal{"auditctl -s prints no enabled line", func(t *testing.T, _, stub string) { setStatus(t, stub, "enabled", "") }, fixed(cannot)},
		refusal{"auditctl -l fails", func(t *testing.T, _, stub string) { writeUnder(t, stub, "/list_fails", "") },
			fixed(rulesID + ": auditctl -l failed; refused")},
		refusal{"rules.d missing", func(t *testing.T, root, _ string) {
			if err := os.Remove(filepath.Join(root, "/etc/audit/rules.d")); err != nil {
				t.Fatal(err)
			}
		}, missing},
		refusal{"rules.d a symlink", func(t *testing.T, root, _ string) {
			d := filepath.Join(root, "/etc/audit/rules.d")
			if err := os.Rename(d, filepath.Join(root, "/etc/audit/real.d")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.d", d); err != nil {
				t.Fatal(err)
			}
		}, missing},
		refusal{"50-muster.rules a symlink", func(t *testing.T, root, _ string) {
			writeUnder(t, root, "/victim", "victim\n")
			if err := os.Symlink(filepath.Join(root, "victim"), filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")); err != nil {
				t.Fatal(err)
			}
		}, func(root string) string {
			return rulesID + ": " + root + "/etc/audit/rules.d/50-muster.rules is a symlink (a mask), left as is"
		}},
	)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			floorHost(t, root)
			writeUnder(t, stub, "/state/auditd.service", "enabled active\n")
			r.seed(t, root, stub)
			out, code := auditRun(t, auditBlock(t, rulesID, root, false), root, bin, stub, filepath.Join(root, "bk"))
			if code != 1 || !strings.Contains(out, r.line(root)) || !strings.Contains(out, rulesID+": script failed") {
				t.Fatalf("exit %d, want 1 with %q\n%s", code, r.line(root), out)
			}
			for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
				if strings.Contains(out, bad) {
					t.Errorf("the output carries %q\n%s", bad, out)
				}
			}
			drop := filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")
			if fi, err := os.Lstat(drop); err == nil && fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("a refused run wrote %s: %q", drop, readFile(t, drop))
			}
			if exists(filepath.Join(root, "/etc/audit/real.d/50-muster.rules")) {
				t.Error("a refused run wrote through the symlinked rules.d")
			}
			if exists(filepath.Join(root, "victim")) && readFile(t, filepath.Join(root, "victim")) != "victim\n" {
				t.Error("a refused run wrote through the symlinked drop-in")
			}
			if exists(filepath.Join(stub, "augenrules")) {
				t.Errorf("augenrules was called: %s", readFile(t, filepath.Join(stub, "augenrules")))
			}
			if calls := readIf(t, filepath.Join(stub, "calls")); strings.Contains(calls, "auditctl") || strings.Contains(calls, "augenrules") {
				t.Errorf("a refused run changed the kernel: %q", calls)
			}
		})
	}
	t.Run("-e 1 is no lock", func(t *testing.T) {
		root, bin, stub := auditTree(t)
		floorHost(t, root)
		writeUnder(t, stub, "/state/auditd.service", "enabled active\n")
		writeUnder(t, root, "/etc/audit/rules.d/x.rules", "-D\n-e 1\n")
		out, code := auditRun(t, auditBlock(t, rulesID, root, false), root, bin, stub, filepath.Join(root, "bk"))
		if code != 0 || !strings.Contains(out, rulesID+": done") {
			t.Fatalf("exit %d, want 0 and done\n%s", code, out)
		}
		if got := readFile(t, filepath.Join(stub, "rules")); got != floorWant(root) {
			t.Errorf("kernel rules %q, want the floor", got)
		}
	})
}

// O-4, §4.2: the floor is written only when nothing is persisted and the
// kernel list is empty (c); persisted rules are loaded only while auditd is
// active and the kernel list is empty (a), else only regenerated; a kernel
// list nothing persists is left with the O-23 line (b). The load records the
// five kernel settings auditctl -s printed before it and the audit.loaded
// marker; a regenerate records neither.
func TestAuditRulesFloorWrittenOnlyWhenBothEmpty(t *testing.T) {
	needSh(t)
	const site = "-w /var/log/site -p wa -k site\n"
	const live = "-w /var/log/live -p wa -k live\n"
	const status = "enabled 1\nfailure 1\nrate_limit 0\nbacklog_limit 8192\nbacklog_wait_time 60000\n"
	for _, c := range []struct {
		name      string
		state     string
		persisted string // rules.d/10-site.rules, when set
		kernel    string // $STUB/rules before the run
		floor     bool   // 50-muster.rules holds the floor after
		aug       string // $STUB/augenrules after ("" = never called)
		loaded    string // $STUB/rules after ("floor" = floorWant)
		line      string // an O-23 line the run logs
	}{
		{name: "case c, active", state: "enabled active", floor: true, aug: "--load\n", loaded: "floor"},
		{name: "case c, inactive", state: "enabled inactive", floor: true, aug: "\n"},
		{name: "case a, active", state: "enabled active", persisted: site, aug: "--load\n", loaded: site},
		{name: "case a, inactive", state: "enabled inactive", persisted: site, aug: "\n"},
		{name: "case b, active", state: "enabled active", kernel: live, loaded: live,
			line: rulesID + ": kernel rules are not persisted; persist your own set"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			floorHost(t, root)
			writeUnder(t, stub, "/state/auditd.service", c.state+"\n")
			if c.persisted != "" {
				writeUnder(t, root, "/etc/audit/rules.d/10-site.rules", c.persisted)
			}
			if c.kernel != "" {
				writeUnder(t, stub, "/rules", c.kernel)
			}
			bk := filepath.Join(root, "bk")
			out, code := auditRun(t, auditBlock(t, rulesID, root, false), root, bin, stub, bk)
			if code != 0 || !strings.Contains(out, rulesID+": done") {
				t.Fatalf("exit %d, want 0 and done\n%s", code, out)
			}
			if c.line != "" && !strings.Contains(out, c.line) {
				t.Errorf("no %q\n%s", c.line, out)
			}
			drop := filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")
			if c.floor {
				if got := readIf(t, drop); got != floorWant(root) {
					t.Errorf("50-muster.rules\n%q\nwant\n%q", got, floorWant(root))
				}
				if fi, err := os.Stat(drop); err != nil || fi.Mode().Perm() != 0o640 {
					t.Errorf("50-muster.rules: %v, want mode 0640", err)
				}
			} else if exists(drop) {
				t.Errorf("50-muster.rules written: %q", readFile(t, drop))
			}
			if got := readIf(t, filepath.Join(stub, "augenrules")); got != c.aug {
				t.Errorf("augenrules calls %q, want %q", got, c.aug)
			}
			want := c.loaded
			if want == "floor" {
				want = floorWant(root)
			}
			if got := readIf(t, filepath.Join(stub, "rules")); got != want {
				t.Errorf("kernel rules %q, want %q", got, want)
			}
			mb := rulesMB(bk)
			load := c.aug == "--load\n"
			if got := exists(filepath.Join(mb, "audit.loaded")); got != load {
				t.Errorf("audit.loaded exists %v, want %v", got, load)
			}
			if got := readIf(t, filepath.Join(mb, "audit.status")); load && got != status || !load && got != "" {
				t.Errorf("audit.status %q", got)
			}
			if got := exists(filepath.Join(mb, "auditd.edited")); got != c.floor {
				t.Errorf("auditd.edited exists %v, want %v", got, c.floor)
			}
			if c.name == "case c, active" {
				want := "is-active --quiet auditd.service\naugenrules --load\n" + floorWant(root) + "is-active --quiet auditd.service\n"
				if got := readFile(t, filepath.Join(stub, "calls")); got != want {
					t.Errorf("calls\n%q\nwant\n%q", got, want)
				}
			}
			if exists(filepath.Join(stub, "restorecon")) {
				t.Errorf("restorecon ran with SELinux off: %s", readFile(t, filepath.Join(stub, "restorecon")))
			}
		})
	}
}

// O-36: with SELinux on, restorecon runs once on a 50-muster.rules this run
// created, never on one that was there.
func TestAuditRulesRestoreconOnlyOnACreatedDropIn(t *testing.T) {
	needSh(t)
	for _, pre := range []bool{false, true} {
		root, bin, stub := auditTree(t)
		writeStub(t, bin, "selinuxenabled", "exit 0\n")
		writeStub(t, bin, "restorecon", `printf '%s\n' "$*" >> "$STUB/restorecon"`+"\nexit 0\n")
		floorHost(t, root)
		writeUnder(t, stub, "/state/auditd.service", "enabled inactive\n")
		drop := filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")
		if pre {
			writeUnder(t, root, "/etc/audit/rules.d/50-muster.rules", "")
		}
		out, code := auditRun(t, auditBlock(t, rulesID, root, false), root, bin, stub, filepath.Join(root, "bk"))
		if code != 0 {
			t.Fatalf("pre %v: exit %d\n%s", pre, code, out)
		}
		want := "-- " + drop + "\n"
		if pre {
			want = ""
		}
		if got := readIf(t, filepath.Join(stub, "restorecon")); got != want {
			t.Errorf("pre %v: restorecon calls %q, want %q", pre, got, want)
		}
		if got := readFile(t, drop); got != floorWant(root) {
			t.Errorf("pre %v: 50-muster.rules %q", pre, got)
		}
	}
}

// §4.2's validate accepts a persisted set with auditd inactive, a persisted
// set the kernel holds, and a kernel set nothing persists (b); it fails a
// load that left the kernel empty and an auditctl -l that fails.
func TestAuditRulesValidate(t *testing.T) {
	needSh(t)
	for _, c := range []struct {
		name          string
		persisted     bool
		state, kernel string
		listFails     bool
		code          int
	}{
		{"persisted, inactive", true, "enabled inactive", "", false, 0},
		{"persisted, active, kernel empty", true, "enabled active", "", false, 1},
		{"persisted, active, kernel holds", true, "enabled active", "-w /x -p wa\n", false, 0},
		{"persisted, active, -l fails", true, "enabled active", "-w /x -p wa\n", true, 1},
		{"none, kernel holds", false, "enabled active", "-w /x -p wa\n", false, 0},
		{"none, kernel empty", false, "enabled inactive", "", false, 1},
		{"none, -l fails", false, "enabled active", "-w /x -p wa\n", true, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			floorHost(t, root)
			writeUnder(t, stub, "/state/auditd.service", c.state+"\n")
			writeUnder(t, root, "/etc/audit/rules.d/10-a.rules", "-D\n")
			if c.persisted {
				writeUnder(t, root, "/etc/audit/rules.d/20-b.rules", "  -A exclude,always -F msgtype=CWD\n")
			}
			if c.kernel != "" {
				writeUnder(t, stub, "/rules", c.kernel)
			}
			if c.listFails {
				writeUnder(t, stub, "/list_fails", "")
			}
			if out, code := runAudit(t, rulesID, root, bin, stub, t.TempDir(), true, nil); code != c.code {
				t.Errorf("validate exit %d, want %d\n%s", code, c.code, out)
			}
		})
	}
}

// O-2, O-9, O-16: a failed block puts the two files back, replays the five
// kernel settings this run recorded (-e only when it was not 2, then -f,
// -b, --backlog_wait_time, -r) and deletes the kernel list with -D, which
// was empty before this run's load. A rerun whose earlier run loaded, now
// over a non-empty kernel list, loads nothing, so its failure deletes
// nothing.
func TestAuditRulesRollbackDeletesOnlyWhatThisRunLoaded(t *testing.T) {
	needSh(t)
	t.Run("this run loaded", func(t *testing.T) {
		root, bin, stub := auditTree(t)
		floorHost(t, root)
		writeUnder(t, stub, "/state/auditd.service", "enabled active\n")
		setStatus(t, stub, "backlog_limit", "backlog_limit 4321")
		const before = "-D\n-b 8192\n"
		writeUnder(t, root, "/etc/audit/audit.rules", before)
		out, code := auditRun(t, auditBlock(t, rulesID, root, true), root, bin, stub, filepath.Join(root, "bk"))
		if code != 1 || !strings.Contains(out, rulesID+": validate failed") {
			t.Fatalf("exit %d, want 1 after a failed validate\n%s", code, out)
		}
		for _, bad := range []string{"ROLLBACK INCOMPLETE", "rollback failed", "restore: "} {
			if strings.Contains(out, bad) {
				t.Errorf("the output carries %q\n%s", bad, out)
			}
		}
		if exists(filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")) {
			t.Error("50-muster.rules survived the rollback")
		}
		if got := readFile(t, filepath.Join(root, "/etc/audit/audit.rules")); got != before {
			t.Errorf("audit.rules %q, want %q", got, before)
		}
		calls := readFile(t, filepath.Join(stub, "calls"))
		load := "augenrules --load\n" + floorWant(root)
		replay := "auditctl -e 1\nauditctl -f 1\nauditctl -b 4321\nauditctl --backlog_wait_time 60000\nauditctl -r 0\nauditctl -D\n"
		if !strings.HasSuffix(calls, load+replay) {
			t.Errorf("calls\n%q\nwant the load, then the replay\n%q", calls, replay)
		}
		if got := readIf(t, filepath.Join(stub, "rules")); got != "" {
			t.Errorf("kernel rules %q after the rollback", got)
		}
		if got := readIf(t, filepath.Join(stub, "audit.rules.at-D")); got != before {
			t.Errorf("at -D audit.rules was %q, want the declared rollback's restore first (%q)", got, before)
		}
		if !strings.Contains(readFile(t, filepath.Join(stub, "status")), "\nbacklog_limit 4321\n") {
			t.Error("the recorded backlog_limit was not put back")
		}
	})
	t.Run("a rerun over a loaded kernel", func(t *testing.T) {
		root, bin, stub := auditTree(t)
		floorHost(t, root)
		writeUnder(t, stub, "/state/auditd.service", "enabled active\n")
		bk := filepath.Join(root, "bk")
		if out, code := auditRun(t, auditBlock(t, rulesID, root, false), root, bin, stub, bk); code != 0 {
			t.Fatalf("first run exit %d\n%s", code, out)
		}
		first := readFile(t, filepath.Join(stub, "calls"))
		out, code := auditRun(t, auditBlock(t, rulesID, root, true), root, bin, stub, bk)
		if code != 1 || strings.Contains(out, "rollback failed") || strings.Contains(out, "ROLLBACK INCOMPLETE") {
			t.Fatalf("rerun exit %d, want 1 with a complete way back\n%s", code, out)
		}
		if rest := strings.TrimPrefix(readFile(t, filepath.Join(stub, "calls")), first); strings.Contains(rest, "auditctl") || strings.Contains(rest, "augenrules --load") {
			t.Errorf("the rerun changed the kernel: %q", rest)
		}
		if got := readFile(t, filepath.Join(stub, "rules")); got != floorWant(root) {
			t.Errorf("kernel rules %q, want the first run's floor kept", got)
		}
		for _, m := range []string{"audit.loaded", "audit.status", "auditd.edited"} {
			if exists(filepath.Join(rulesMB(bk), m)) {
				t.Errorf("the earlier run's %s survived the rerun", m)
			}
		}
		// The template's backup keeps a first FILE copy, but an "absent"
		// record is replaced by a copy once the path exists (backup()'s
		// rm -f "$MB/absent$p"), so the rerun's way back is the drop-in as
		// the first run left it: the persisted floor and the kernel's agree.
		if got := readIf(t, filepath.Join(root, "/etc/audit/rules.d/50-muster.rules")); got != floorWant(root) {
			t.Errorf("50-muster.rules after the rerun's rollback %q, want the first run's floor", got)
		}
	})
}

// §4.1, O-3, O-5, O-23: the auditd_active block unmasks and enables the
// unit, and starts it only when it is inactive, its kernel list is empty
// (auditctl -l exits 0 and prints No rules) and no lock is pending in the
// rules files, whatever the runtime lock state (O-74: neither enabled 2 nor
// loginuid_immutable 1 lifts it); a refusal fails the block and restore_units puts the unit's
// enablement back; a missing unit is the operator's install.
func TestAuditdActiveStartBranch(t *testing.T) {
	needSh(t)
	refused := activeID + ": a one-way audit setting is pending (-e 2 or --loginuid-immutable); start refused"
	for _, c := range []struct {
		name, state, persisted string
		seed                   func(t *testing.T, stub string)
		code                   int
		line, after            string
		started                bool
	}{
		{name: "active, pending lock, disabled", state: "disabled active", persisted: "-e 2", after: "enabled active"},
		{name: "inactive, enabled 2, -e 2 persisted", state: "disabled inactive", persisted: "-e 2",
			seed: func(t *testing.T, stub string) { setStatus(t, stub, "enabled", "enabled 2") }, code: 1, line: refused, after: "disabled inactive"},
		{name: "inactive, loginuid locked, enabled 1, -e 2 persisted", state: "disabled inactive", persisted: "-e 2",
			seed: func(t *testing.T, stub string) {
				setStatus(t, stub, "loginuid_immutable", "loginuid_immutable 1 locked")
			},
			code: 1, line: refused, after: "disabled inactive"},
		{name: "inactive, loginuid locked, --loginuid-immutable persisted", state: "disabled inactive", persisted: "--loginuid-immutable",
			seed: func(t *testing.T, stub string) {
				setStatus(t, stub, "loginuid_immutable", "loginuid_immutable 1 locked")
			},
			code: 1, line: refused, after: "disabled inactive"},
		{name: "inactive, unlocked, -e2 persisted", state: "disabled inactive", persisted: "-e2", code: 1, line: refused, after: "disabled inactive"},
		{name: "inactive, -b 8192 -e 2 persisted", state: "disabled inactive", persisted: "-b 8192 -e 2", code: 1, line: refused, after: "disabled inactive"},
		{name: "inactive, kernel holds rules", state: "disabled inactive",
			seed: func(t *testing.T, stub string) { writeUnder(t, stub, "/rules", "-w /var/log/live -p wa -k live\n") },
			line: activeID + ": kernel holds rules a start would replace; start left to the operator", after: "enabled inactive"},
		{name: "inactive, auditctl -l fails", state: "disabled inactive",
			seed: func(t *testing.T, stub string) { writeUnder(t, stub, "/list_fails", "") },
			code: 1, line: activeID + ": auditctl -l failed; start refused", after: "disabled inactive"},
		{name: "inactive, clean", state: "disabled inactive", after: "enabled active", started: true},
		{name: "masked, clean", state: "masked inactive", after: "enabled active", started: true},
		{name: "no unit", line: activeID + ": install the audit package (audit on the EL family, auditd on Debian and Ubuntu)", after: "absent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, bin, stub := auditTree(t)
			if err := os.MkdirAll(filepath.Join(root, "/etc/audit/rules.d"), 0o755); err != nil {
				t.Fatal(err)
			}
			if c.state != "" {
				writeUnder(t, stub, "/state/auditd.service", c.state+"\n")
			}
			if c.persisted != "" {
				writeUnder(t, root, "/etc/audit/rules.d/99-x.rules", "-D\n"+c.persisted+"\n")
			}
			if c.seed != nil {
				c.seed(t, stub)
			}
			out, code := auditRun(t, auditBlock(t, activeID, root, false), root, bin, stub, filepath.Join(root, "bk"))
			if code != c.code {
				t.Fatalf("exit %d, want %d\n%s", code, c.code, out)
			}
			end := activeID + ": done"
			if c.code != 0 {
				end = activeID + ": script failed"
			}
			if !strings.Contains(out, end) || c.line != "" && !strings.Contains(out, c.line) {
				t.Errorf("want %q and %q\n%s", end, c.line, out)
			}
			if strings.Contains(out, "ROLLBACK INCOMPLETE") {
				t.Errorf("the way back was incomplete\n%s", out)
			}
			if got := state(t, stub, "auditd.service"); got != c.after {
				t.Errorf("auditd.service %q, want %q", got, c.after)
			}
			calls := readIf(t, filepath.Join(stub, "calls"))
			if got := strings.Contains(calls, "--quiet start auditd.service\n"); got != c.started {
				t.Errorf("started %v, want %v; calls %q", got, c.started, calls)
			}
			if strings.Contains("\n"+readIf(t, filepath.Join(stub, "auditctl")), "\n-s\n") {
				t.Error("the start gate read auditctl -s; a pending lock refuses whatever the runtime says (O-74)")
			}
		})
	}
}

// §2 order in a plan: over an inactive, disabled auditd with nothing
// persisted and nothing loaded, the rules block (audit_ sorts before
// auditd) writes the floor and only regenerates, and the active block's
// start loads it through the unit's augenrules --load.
func TestAuditPlanFloorThenStart(t *testing.T) {
	needSh(t)
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	p := mustBuild(t, scriptReport(row(rulesID, "FAIL", "clause does not hold", "", "high"), row(activeID, "FAIL", "clause does not hold", "", "high")), set, Options{})
	if len(p.Items) != 2 || p.Items[0].ID != rulesID || p.Items[1].ID != activeID || !p.Items[0].Planned || !p.Items[1].Planned {
		t.Fatalf("plan %+v, want the rules block then the active block", p.Items)
	}
	root, bin, stub := auditTree(t)
	for i := range p.Items {
		rebaseItem(t, &p.Items[i], root)
	}
	floorHost(t, root)
	writeUnder(t, stub, "/state/auditd.service", "disabled inactive\n")
	out, code := auditRun(t, p, root, bin, stub, filepath.Join(root, "bk"))
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	i, j := strings.Index(out, rulesID+": done"), strings.Index(out, activeID+": done")
	if i < 0 || j < 0 || i > j {
		t.Errorf("want the rules block done, then the active block\n%s", out)
	}
	if got := readFile(t, filepath.Join(stub, "augenrules")); got != "\n--load\n" {
		t.Errorf("augenrules calls %q, want the rules block's regenerate, then the start's load", got)
	}
	if got := readFile(t, filepath.Join(stub, "rules")); got != floorWant(root) {
		t.Errorf("kernel rules %q, want the floor", got)
	}
	if got := state(t, stub, "auditd.service"); got != "enabled active" {
		t.Errorf("auditd.service %q", got)
	}
}
