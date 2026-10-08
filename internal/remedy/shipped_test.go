package remedy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// These tests run a shipped control's own body, with its absolute paths moved
// under t.TempDir() and the daemons it calls stubbed on PATH, so they hold the
// behaviour the body promises rather than its spelling.

func shippedRemediation(t *testing.T, id string) *controls.Remediation {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range set.Controls {
		if c.ID == id {
			if c.Remediation == nil {
				t.Fatalf("%s declares no remediation", id)
			}
			return c.Remediation
		}
	}
	t.Fatalf("no shipped control %s", id)
	return nil
}

// runBody runs body under sh -e in dir with bin first on PATH and the
// environment extra; it returns the combined output and the exit code.
func runBody(t *testing.T, dir, bin, body string, extra ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", "-ec", body)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append([]string{"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}, extra...)...)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	} else if err != nil {
		t.Fatalf("sh: %v", err)
	}
	return string(out), 0
}

func writeStub(t *testing.T, bin, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// W6: the securetty sed removes a pts/ line whatever leading whitespace it
// carries, as the collector trims it before the judgment reads it.
func TestShippedSecurettySedRemovesIndentedPts(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.account.root_remote_login")
	var sed string
	for _, l := range strings.Split(r.Script, "\n") {
		if strings.Contains(l, "sed -i") && strings.Contains(l, "/etc/securetty") {
			sed = strings.TrimSpace(l)
		}
	}
	if sed == "" {
		t.Fatalf("the script has no sed over /etc/securetty:\n%s", r.Script)
	}
	tmp := t.TempDir()
	f := filepath.Join(tmp, "securetty")
	if err := os.WriteFile(f, []byte("console\n  pts/0\npts/1\n\tpts/2\ntty1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := runBody(t, tmp, tmp, strings.ReplaceAll(sed, "/etc/securetty", f)); code != 0 {
		t.Fatalf("%s: exit %d\n%s", sed, code, out)
	}
	if got := readFile(t, f); got != "console\ntty1\n" {
		t.Errorf("after %s the file is %q, want only console and tty1", sed, got)
	}
}

// rootLoginStubs moves root_remote_login's paths under tmp and stubs sshd and
// systemctl: ssh.service is active, sshd.service is not; every call is logged.
// sshd -T prints permitrootlogin no globally and, for persona root, the value
// in $ROOT_VALUE (a Match User root block).
func rootLoginStubs(t *testing.T, body string) (tmp, bin, log, rewritten string) {
	t.Helper()
	tmp = t.TempDir()
	bin = filepath.Join(tmp, "bin")
	log = filepath.Join(tmp, "calls")
	for _, d := range []string{bin, filepath.Join(tmp, "etc/ssh/sshd_config.d"), filepath.Join(tmp, "run")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeStub(t, bin, "sshd", `printf 'sshd %s\n' "$*" >> "$CALLS"
case "$*" in
  "-T -C user=root,host=localhost,addr=127.0.0.1") printf 'permitrootlogin %s\n' "$ROOT_VALUE";;
  -T) printf 'permitrootlogin no\n';;
esac
`)
	writeStub(t, bin, "systemctl", `printf 'systemctl %s\n' "$*" >> "$CALLS"
case "$*" in
  "is-active --quiet ssh.service") exit 0;;
  "is-active --quiet sshd.service") exit 3;;
esac
`)
	rewritten = strings.NewReplacer("/etc/ssh/", tmp+"/etc/ssh/", "/run/sshd", tmp+"/run/sshd", "/etc/securetty", tmp+"/etc/securetty").Replace(body)
	return tmp, bin, log, rewritten
}

// Z-30: the script and the rollback reload the running sshd after sshd -t,
// and reload only the unit that is active.
func TestShippedRootLoginReloadsTheRunningSshd(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.account.root_remote_login")
	for _, v := range []struct{ name, body string }{{"script", r.Script}, {"rollback", r.Rollback}} {
		t.Run(v.name, func(t *testing.T) {
			tmp, bin, log, body := rootLoginStubs(t, v.body)
			if out, code := runBody(t, tmp, bin, body, "CALLS="+log, "ROOT_VALUE=no"); code != 0 {
				t.Fatalf("exit %d\n%s", code, out)
			}
			calls := readFile(t, log)
			test := strings.Index(calls, "sshd -t\n")
			reload := strings.Index(calls, "systemctl reload ssh.service\n")
			if test < 0 || reload < test {
				t.Errorf("want sshd -t, then systemctl reload ssh.service; calls:\n%s", calls)
			}
			if strings.Contains(calls, "reload sshd.service") {
				t.Errorf("reloaded the inactive sshd.service; calls:\n%s", calls)
			}
		})
	}
}

// Z-30: the validate reads persona root, as the judgment does, so a Match
// block that lets root in fails it even where the global value is no.
func TestShippedRootLoginValidateReadsPersonaRoot(t *testing.T) {
	needSh(t)
	r := shippedRemediation(t, "muster.account.root_remote_login")
	for _, v := range []struct {
		root string
		want int
	}{{"no", 0}, {"yes", 1}} {
		tmp, bin, log, validate := rootLoginStubs(t, r.Validate)
		out, code := runBody(t, tmp, bin, validate, "CALLS="+log, "ROOT_VALUE="+v.root)
		if (code == 0) != (v.want == 0) {
			t.Errorf("persona root %s: validate exit %d, want %d\n%s", v.root, code, v.want, out)
		}
	}
}
