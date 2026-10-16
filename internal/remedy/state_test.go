package remedy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helperScript is the prologue's helpers with log() and $MB set, for running
// them directly under sh (the block functions call them the same way).
func helperScript(mb, body string) string {
	return "set -u\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\nMB=" + shQuote(mb) + "\nmkdir -p \"$MB\"\n" +
		backupHelpers + "\n" + stateHelpers + "\n" + body + "\n"
}

// trustAll redefines modes_trusted after the helpers are sourced: t.TempDir()
// lies under the other-writable /tmp, so every entry there would be refused;
// the trust rule has its own root-only test (S-24).
const trustAll = "modes_trusted() { return 0; }\n"

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func runSh(t *testing.T, script, bin string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	path := os.Getenv("PATH")
	if bin != "" {
		path = bin + string(os.PathListSeparator) + path
	}
	cmd.Env = append(os.Environ(), append([]string{"PATH=" + path}, env...)...)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), 0
}

func mode(t *testing.T, p string) string {
	t.Helper()
	out, err := exec.Command("stat", "-c", "%a", p).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestModesHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	d := filepath.Join(root, "d")
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, "d/a"), filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	save := trustAll + "save_modes " + shQuote(d+"/*") + " " + shQuote(d+"/*/*") + " " + shQuote(filepath.Join(root, "none")+"/*") + " || exit 9"
	if out, code := runSh(t, helperScript(mb, save), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	rec, _ := os.ReadFile(filepath.Join(mb, "modes.list"))
	for _, want := range []string{"/d/a\n", "/d/.hidden\n", "/d/with space\n", "/d/sub\n", "/d/sub/x\n"} {
		if !strings.Contains(string(rec), want) {
			t.Errorf("modes.list lacks %q:\n%s", want, rec)
		}
	}
	if strings.Contains(string(rec), "/d/link") {
		t.Errorf("modes.list records a symlink:\n%s", rec)
	}
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if err := os.Chmod(filepath.Join(root, p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a rerun keeps the first record: the 0600 modes are not recorded
	if out, code := runSh(t, helperScript(mb, save), ""); code != 0 {
		t.Fatalf("rerun: %d %s", code, out)
	}
	if out, code := runSh(t, helperScript(mb, trustAll+"restore_modes"), ""); code != 0 {
		t.Fatalf("restore: %d %s", code, out)
	}
	for _, p := range []string{"d/a", "d/.hidden", "d/with space", "d/sub/x"} {
		if got := mode(t, filepath.Join(root, p)); got != "644" {
			t.Errorf("%s restored to %s, want 644", p, got)
		}
	}
}

func TestModesHelpersRefuseASwappedEntry(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	victim := filepath.Join(root, "victim")
	f := filepath.Join(root, "spool", "job")
	for _, p := range []string{victim, f} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runSh(t, helperScript(mb, "save_modes "+shQuote(filepath.Join(root, "spool")+"/*")+" || exit 9"), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, f); err != nil { // the spool's owner swaps its entry
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, trustAll+"restore_modes"), "")
	if code == 0 || !strings.Contains(out, "restore_modes: "+f+" changed type, left as is") {
		t.Fatalf("restore over a swapped entry: exit %d, %s", code, out)
	}
	if got := mode(t, victim); got != "600" {
		t.Errorf("restore_modes wrote through the symlink: victim is %s", got)
	}
}

// A recorded file the body (or anyone) replaced by a directory is left as is
// and the restore reports itself incomplete; the next entry is still restored.
func TestModesHelpersRefuseAFileTurnedDirectory(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "d", "a"), filepath.Join(root, "d", "b")
	if err := os.MkdirAll(filepath.Dir(a), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := runSh(t, helperScript(mb, trustAll+"save_modes "+shQuote(filepath.Join(root, "d")+"/*")+" || exit 9"), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(a, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, trustAll+"restore_modes"), "")
	if code != 1 || !strings.Contains(out, "restore_modes: "+a+" changed type, left as is") {
		t.Fatalf("restore over a directory: exit %d, %s", code, out)
	}
	if got := mode(t, a); got != "700" {
		t.Errorf("the directory was re-moded to %s", got)
	}
	if got := mode(t, b); got != "644" {
		t.Errorf("the entry after the refused one is %s, want 644", got)
	}
}

// A row the helper cannot put back (a chown to uid 0 as a non-root user)
// makes the restore incomplete; the loop goes on past it.
func TestModesHelpersContinuePastAnUnrestorableRow(t *testing.T) {
	needSh(t)
	if os.Geteuid() == 0 {
		t.Skip("root can chown to uid 0: the row would restore")
	}
	root, mb := t.TempDir(), t.TempDir()
	a, b := filepath.Join(root, "d", "a"), filepath.Join(root, "d", "b")
	if err := os.MkdirAll(filepath.Dir(a), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := runSh(t, helperScript(mb, trustAll+"save_modes "+shQuote(a)+" "+shQuote(b)+" || exit 9"), ""); code != 0 {
		t.Fatalf("save: %d %s", code, out)
	}
	list := filepath.Join(mb, "modes.list")
	rec, err := os.ReadFile(list)
	if err != nil {
		t.Fatal(err)
	}
	ls := strings.Split(strings.TrimSuffix(string(rec), "\n"), "\n")
	if len(ls) != 2 || !strings.HasSuffix(ls[0], " "+a) {
		t.Fatalf("modes.list:\n%s", rec)
	}
	f := strings.Fields(ls[0])
	f[0] = "0" // a row whose owner this user cannot give back
	ls[0] = strings.Join(f, " ")
	if err := os.WriteFile(list, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{a, b} {
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, code := runSh(t, helperScript(mb, trustAll+"restore_modes"), "")
	if code != 1 {
		t.Fatalf("an unrestorable row: exit %d, want 1\n%s", code, out)
	}
	if got := mode(t, a); got != "600" {
		t.Errorf("the unrestorable row was re-moded to %s", got)
	}
	if got := mode(t, b); got != "644" {
		t.Errorf("the row after the unrestorable one is %s, want 644\n%s", got, out)
	}
}

// S-24: restore_modes puts an entry back only when no one but root could have
// swapped it. Root only: the tree lives under / so that its ancestors are
// root-owned and not other-writable, unlike t.TempDir()'s /tmp.
func TestModesHelpersTrustRule(t *testing.T) {
	needSh(t)
	if os.Geteuid() != 0 {
		t.Skip("the trust rule reads root ownership: run as root")
	}
	top, err := os.MkdirTemp("/", "muster-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(top) })
	mkdir := func(p string, perm os.FileMode, uid int) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, uid, 0); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, perm); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name    string
		setup   func(dir string) string // makes the entry's directories, returns the entry
		uid     int
		restore bool
	}{
		{"other-writable parent", func(dir string) string {
			mkdir(filepath.Join(dir, "ow"), 0o777, 0)
			return filepath.Join(dir, "ow", "f")
		}, 0, false},
		{"non-root-owned grandparent", func(dir string) string {
			mkdir(filepath.Join(dir, "gp"), 0o755, 1000)
			mkdir(filepath.Join(dir, "gp", "p"), 0o755, 0)
			return filepath.Join(dir, "gp", "p", "f")
		}, 0, false},
		{"uid-1000 entry in a group-writable sticky parent", func(dir string) string {
			mkdir(filepath.Join(dir, "gs"), 0o775|os.ModeSticky, 0)
			return filepath.Join(dir, "gs", "f")
		}, 1000, false},
		{"root entry under a root-owned group-writable parent", func(dir string) string {
			mkdir(filepath.Join(dir, "gw"), 0o775, 0)
			return filepath.Join(dir, "gw", "f")
		}, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, err := os.MkdirTemp(top, "c-")
			if err != nil {
				t.Fatal(err)
			}
			mb := filepath.Join(dir, "mb")
			f := c.setup(dir)
			if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(f, c.uid, 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(f, 0o644); err != nil {
				t.Fatal(err)
			}
			if out, code := runSh(t, helperScript(mb, "save_modes "+shQuote(f)+" || exit 9"), ""); code != 0 {
				t.Fatalf("save: %d %s", code, out)
			}
			if err := os.Chmod(f, 0o600); err != nil {
				t.Fatal(err)
			}
			out, code := runSh(t, helperScript(mb, "restore_modes"), "")
			if c.restore {
				if got := mode(t, f); code != 0 || got != "644" {
					t.Fatalf("a trusted entry: exit %d, mode %s; want 0 and 644\n%s", code, got, out)
				}
				return
			}
			if code != 1 || !strings.Contains(out, "restore_modes: "+f+" is under a directory others can write, left as is") {
				t.Fatalf("an untrusted entry: exit %d, want 1 and the refusal\n%s", code, out)
			}
			if got := mode(t, f); got != "600" {
				t.Errorf("an untrusted entry was re-moded to %s (fail closed keeps 600)", got)
			}
		})
	}
}

// An entry whose recorded state equals its current state is skipped before
// anything else: no chown runs (a chown would clear security.capability).
// Stub chown and chmod first on PATH log any call; the trust rule is not
// redefined, so the /tmp entry would be refused if the skip came later.
func TestModesHelpersSkipAnEqualEntry(t *testing.T) {
	needSh(t)
	root, mb, bin := t.TempDir(), t.TempDir(), t.TempDir()
	f := filepath.Join(root, "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(bin, "calls")
	writeStub(t, bin, "chown", `printf 'chown %s\n' "$*" >> "$CALLS"`)
	writeStub(t, bin, "chmod", `printf 'chmod %s\n' "$*" >> "$CALLS"`)
	out, code := runSh(t, helperScript(mb, "save_modes "+shQuote(f)+" || exit 9\nrestore_modes"), bin, "CALLS="+calls)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if exists(calls) {
		t.Errorf("an unchanged entry was re-owned or re-moded:\n%s", readFile(t, calls))
	}
}

func TestBackupMarkerCases(t *testing.T) {
	needSh(t)
	root, mb := t.TempDir(), t.TempDir()
	p := filepath.Join(root, "drop.conf")
	run := func(body string) string {
		out, code := runSh(t, helperScript(mb, body), "")
		if code != 0 {
			t.Fatalf("%s: exit %d %s", body, code, out)
		}
		return out
	}
	// absent at run 1: a marker; restore removes what the body created
	run("backup " + shQuote(p) + " || exit 9")
	if err := os.WriteFile(p, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("restore " + shQuote(p) + " || exit 9")
	if exists(p) {
		t.Fatal("restore left a path that was absent at backup")
	}
	// absent at run 1, present at run 2: the marker is replaced by a copy
	if err := os.WriteFile(p, []byte("operator"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("backup " + shQuote(p) + " || exit 9")
	if exists(filepath.Join(mb, "absent"+p)) || !exists(filepath.Join(mb, "files"+p)) {
		t.Fatal("run 2 kept the marker or took no copy")
	}
	if err := os.WriteFile(p, []byte("script"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("restore " + shQuote(p) + " || exit 9")
	if b, _ := os.ReadFile(p); string(b) != "operator" {
		t.Fatalf("restore after run 2: %q, want the operator's copy", b)
	}
	// copied at run 1, gone at run 2: no marker beside the copy, the copy is restored
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	run("backup " + shQuote(p) + " || exit 9")
	if exists(filepath.Join(mb, "absent"+p)) {
		t.Fatal("a marker was written beside a copy")
	}
	run("restore " + shQuote(p) + " || exit 9")
	if b, _ := os.ReadFile(p); string(b) != "operator" {
		t.Fatalf("restore after the path was gone: %q", b)
	}
	// a marker whose path is now a directory is logged and counts as incomplete
	q := filepath.Join(root, "dir.conf")
	run("backup " + shQuote(q) + " || exit 9")
	if err := os.Mkdir(q, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, "restore "+shQuote(q)), "")
	if code == 0 || !strings.Contains(out, "restore: "+q+" is now a directory, left as is") {
		t.Fatalf("restore over a directory: exit %d %s", code, out)
	}
}

// sysctlStub keeps one file per key under $SYSCTL_STATE; a key with a
// .oneway file refuses a write once its value is in that file; every -w is
// logged to $SYSCTL_STATE/calls. Two writes move another key, as the kernel's
// do (probe.md, "Sysctl coupling"): a changing write to net.ipv4.ip_forward
// sets net.ipv4.conf.all.accept_redirects to its negation (E-13, S-43), and a
// write to net.ipv6.conf.all.forwarding copies the value into
// net.ipv6.conf.default.forwarding (S-46). Neither side effect is logged.
const sysctlStub = `s="$SYSCTL_STATE"
case "$1" in
  -n) shift; [ "$1" = -- ] && shift; f="$s/$1"; [ -f "$f" ] || exit 255; cat "$f";;
  -q) shift; [ "$1" = -w ] && shift; [ "$1" = -- ] && shift
      k=${1%%=*}; v=${1#*=}; [ -f "$s/$k" ] || exit 255
      old=$(cat "$s/$k")
      if [ -f "$s/$k.oneway" ] && grep -qx "$old" "$s/$k.oneway"; then exit 1; fi
      printf '%s\n' "$v" > "$s/$k"; printf 'w %s=%s\n' "$k" "$v" >> "$s/calls"
      case "$k" in
        net.ipv4.ip_forward)
          if [ "$old" != "$v" ] && [ -f "$s/net.ipv4.conf.all.accept_redirects" ]; then
            if [ "$v" = 0 ]; then n=1; else n=0; fi
            printf '%s\n' "$n" > "$s/net.ipv4.conf.all.accept_redirects"
          fi;;
        net.ipv6.conf.all.forwarding)
          if [ -f "$s/net.ipv6.conf.default.forwarding" ]; then printf '%s\n' "$v" > "$s/net.ipv6.conf.default.forwarding"; fi;;
      esac;;
  *) exit 2;;
esac
exit 0
`

// modprobeStub keeps the loaded set in $MODPROBE_STATE/modules (the
// /proc/modules format) and answers --showconfig from conf/* in name order.
// -r exits 1 for a module that is not loaded, as kmod does, and for any
// module while the busy file exists (a module in use).
const modprobeStub = `s="$MODPROBE_STATE"
printf '%s\n' "$*" >> "$s/calls"
case "$1" in
  --ignore-install) shift; [ "$1" = -- ] && shift; [ -f "$s/fail" ] && exit 1; printf '%s 16384 0 - Live 0x0\n' "$1" >> "$s/modules";;
  -r) shift; [ "$1" = -- ] && shift; grep -q "^$1 " "$s/modules" || exit 1; [ -f "$s/busy" ] && exit 1; grep -v "^$1 " "$s/modules" > "$s/m.new" || :; mv "$s/m.new" "$s/modules";;
  --showconfig) cat "$s"/conf/* 2>/dev/null | awk '$1 == "install" { gsub(/-/, "_", $2) } { print }';;
  *) exit 2;;
esac
`

func TestSysctlHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	bin, st, mb := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "sysctl", sysctlStub)
	for k, v := range map[string]string{"kernel.a": "0", "kernel.b": "2"} {
		if err := os.WriteFile(filepath.Join(st, k), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := "SYSCTL_STATE=" + st
	script := helperScript(mb, `save_sysctl kernel.a kernel.b kernel.missing || exit 9
sysctl -q -w kernel.a=1; sysctl -q -w kernel.b=1
save_sysctl kernel.a || exit 9
restore_sysctl kernel.a kernel.b kernel.missing`)
	if out, code := runSh(t, script, bin, env); code != 0 {
		t.Fatalf("exit %d %s", code, out)
	}
	for k, want := range map[string]string{"kernel.a": "0", "kernel.b": "2"} {
		if b, _ := os.ReadFile(filepath.Join(st, k)); strings.TrimSpace(string(b)) != want {
			t.Errorf("%s restored to %q, want %s", k, b, want)
		}
	}
	rec, _ := os.ReadFile(filepath.Join(mb, "sysctl.list"))
	if !strings.Contains(string(rec), "kernel.missing absent\n") || strings.Count(string(rec), "kernel.a ") != 1 {
		t.Errorf("sysctl.list:\n%s", rec)
	}
	// a refused write is incomplete, and the next key is still restored
	if err := os.WriteFile(filepath.Join(st, "kernel.a.oneway"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := runSh(t, helperScript(mb, "sysctl -q -w kernel.a=1; sysctl -q -w kernel.b=1\nrestore_sysctl kernel.a kernel.b"), bin, env)
	if code == 0 {
		t.Fatalf("a refused restore returned 0: %s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(st, "kernel.b")); strings.TrimSpace(string(b)) != "2" {
		t.Errorf("kernel.b after a refused kernel.a: %q", b)
	}
}

func TestModulesHelpersRecordAndRestore(t *testing.T) {
	needSh(t)
	bin, st, mb := t.TempDir(), t.TempDir(), t.TempDir()
	writeStub(t, bin, "modprobe", modprobeStub)
	procModules := filepath.Join(st, "modules")
	if err := os.WriteFile(procModules, []byte("udf 16384 0 - Live 0x0\nusb_storage 16384 0 - Live 0x0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	helpers := strings.ReplaceAll(stateHelpers, "/proc/modules", procModules)
	script := "set -u\nlog() { printf 'muster-fix: %s\\n' \"$*\"; }\nMB=" + shQuote(mb) + "\n" + helpers + `
save_modules udf usb-storage sctp || exit 9
modprobe -r udf; modprobe -r usb_storage
restore_modules udf usb-storage sctp`
	if out, code := runSh(t, script, bin, "MODPROBE_STATE="+st); code != 0 {
		t.Fatalf("exit %d %s", code, out)
	}
	calls, _ := os.ReadFile(filepath.Join(st, "calls"))
	for _, want := range []string{"--ignore-install -- udf\n", "--ignore-install -- usb_storage\n"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("calls lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(string(calls), "sctp") {
		t.Errorf("a module not loaded at record time was loaded:\n%s", calls)
	}
	if err := os.WriteFile(filepath.Join(st, "fail"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := runSh(t, script, bin, "MODPROBE_STATE="+st); code == 0 {
		t.Fatalf("a failing modprobe returned 0: %s", out)
	}
}
