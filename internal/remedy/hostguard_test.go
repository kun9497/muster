package remedy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect/collectors"
)

// TestHostGuardHashMatchesTheCollector pins 3D-2b §2: on every id the
// collector hashes, the script's helper computes the same value; on every id
// it refuses, both yield nothing.
func TestHostGuardHashMatchesTheCollector(t *testing.T) {
	needSh(t)
	const id = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	helper := filepath.Join(dir, "h.sh")
	if err := os.WriteFile(helper, []byte(MachineIDHashHelper+"\nmuster_machine_id_hash \"$1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, content string
		missing       bool
	}{
		{"trailing LF", id + "\n", false}, {"CRLF", id + "\r\n", false}, {"leading blanks", "  " + id, false}, {"leading LF", "\n" + id, false},
		{"uninitialized", "uninitialized\n", false}, {"uppercase", strings.ToUpper(id), false}, {"31", id[:31], false},
		{"whitespace", " \n", false}, {"empty", "", false}, {"missing", "", true},
		{"VT FF", "\v" + id + "\f", false}, {"U+00A0", " " + id + " ", false}, {"U+0085", id + "\u0085", false},
	} {
		p := filepath.Join(dir, "mid-"+strings.ReplaceAll(c.name, " ", "_"))
		if !c.missing {
			if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out, err := exec.Command("sh", helper, p).Output()
		if err != nil {
			t.Fatalf("%s: helper: %v", c.name, err)
		}
		want := ""
		if !c.missing {
			want = collectors.MachineIDHash([]byte(c.content))
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s: helper %q, collector %q", c.name, got, want)
		}
	}
	// The one input on which the two differ by design (spec §2): an id with
	// interior whitespace. The collector yields no hash, so the guard is off
	// and the helper is never emitted; what the helper would print is moot.
	if h := collectors.MachineIDHash([]byte(id[:16] + " " + id[16:])); h != "" {
		t.Fatalf("interior space: the collector must yield no hash, got %q", h)
	}
}

func guardPlan(t *testing.T, hash string) *Plan {
	t.Helper()
	return &Plan{Fix: FixBlock{MaxRisk: "lockout_risk", HostGuard: "on", MachineIDHash: hash}}
}

func TestScriptRefusesAnotherHost(t *testing.T) {
	needSh(t)
	const id = "0123456789abcdef0123456789abcdef"
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(mid, []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	same := collectors.MachineIDHash([]byte(id))
	other := strings.Repeat("b", 64)
	repl := runOpts{replace: [][2]string{{"muster_machine_id_hash /etc/machine-id", "muster_machine_id_hash " + mid}}}
	const refusal = "muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n"

	backup := filepath.Join(dir, "bk-same")
	if _, _, code := runScriptWith(t, guardPlan(t, same), dir, backup, repl); code != 0 {
		t.Fatalf("same host: exit %d", code)
	}
	backup = filepath.Join(dir, "bk-other")
	_, stderr, code := runScriptWith(t, guardPlan(t, other), dir, backup, repl)
	if code != 2 || stderr != refusal || exists(backup) {
		t.Fatalf("other host: exit %d stderr %q backup created %v", code, stderr, exists(backup))
	}
	o := repl
	o.env = []string{"MUSTER_ANY_HOST=1"}
	all, _, code := runScriptWith(t, guardPlan(t, other), dir, filepath.Join(dir, "bk-any"), o)
	if code != 0 || !strings.Contains(all, "muster-fix: warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1") {
		t.Fatalf("override: exit %d out %q", code, all)
	}
	missing := runOpts{replace: [][2]string{{"muster_machine_id_hash /etc/machine-id", "muster_machine_id_hash " + filepath.Join(dir, "none")}}}
	_, stderr, code = runScriptWith(t, guardPlan(t, same), dir, filepath.Join(dir, "bk-missing"), missing)
	if code != 2 || stderr != refusal {
		t.Fatalf("missing id: exit %d stderr %q", code, stderr)
	}
}

// TestScriptGuardRechecksTheHash pins that the renderer, not only Build,
// admits the hash: a hand-built plan that says "on" with an empty or
// malformed hash renders the guard-off comment and no MUSTER_SNAPSHOT_HOST.
func TestScriptGuardRechecksTheHash(t *testing.T) {
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("a", 64) + "; true"} {
		s := string(Script(&Plan{Fix: FixBlock{MaxRisk: "lockout_risk", HostGuard: "on", MachineIDHash: hash}}))
		if strings.Contains(s, "MUSTER_SNAPSHOT_HOST") || strings.Contains(s, "muster_machine_id_hash") {
			t.Errorf("hash %q: the guard is rendered:\n%s", hash, s)
		}
		if !strings.Contains(s, "\n"+guardOff+"\n") {
			t.Errorf("hash %q: no guard-off comment:\n%s", hash, s)
		}
	}
}
