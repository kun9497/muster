package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// anonymisedFixFail writes full-fail.json with machine_id_hash h, and its
// keyed anonymisation; it returns both paths.
func anonymisedFixFail(t *testing.T, h string) (orig, anonPath string) {
	t.Helper()
	raw, err := os.ReadFile(fullFail)
	if err != nil {
		t.Fatal(err)
	}
	with := bytes.Replace(raw, []byte(`"hostname":`), []byte(`"machine_id_hash":"`+h+`","hostname":`), 1)
	if bytes.Equal(with, raw) {
		t.Fatal("fixture has no hostname key to anchor on")
	}
	dir := t.TempDir()
	orig = filepath.Join(dir, "orig.json")
	if err := os.WriteFile(orig, with, 0o600); err != nil {
		t.Fatal(err)
	}
	anonPath = filepath.Join(dir, "anon.json")
	if code, _, stderr := anon(t, "--facts", orig, "--key", writeKey(t, dir, 32, 11), "--out", anonPath); code != exitOK {
		t.Fatalf("anonymize: exit %d, stderr %q", code, stderr)
	}
	return orig, anonPath
}

// AX-11: this muster refuses a script from an anonymised snapshot — exit 2,
// nothing on stdout, one line naming what to do — while table and json
// still plan, for a reviewer, and carry run.anonymization.
func TestFixRefusesAScriptFromAnAnonymisedSnapshot(t *testing.T) {
	_, a := anonymisedFixFail(t, strings.Repeat("c", 64))
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", a, "--format", "script")
	if code != exitError {
		t.Errorf("script: exit %d, want 2", code)
	}
	if len(out) != 0 {
		t.Errorf("script: stdout not empty:\n%s", out[:min(len(out), 200)])
	}
	if string(errb) != "muster: plan the script from the original snapshot\n" {
		t.Errorf("script: stderr %q", errb)
	}

	code, out, errb = runFixArgs(t, "--dry-run", "--facts", a, "--format", "table", "--color", "never")
	if code != exitOK || !bytes.Contains(out, []byte("fix --dry-run · ")) {
		t.Errorf("table: exit %d, stderr %q\n%s", code, errb, out)
	}
	p := planJSON(t, "--facts", a)
	if p.Run.Anonymization == nil || p.Run.Anonymization.Scheme != "muster-anon-v1" || p.Run.Anonymization.Mode != "keyed" {
		t.Errorf("json: run.anonymization %+v", p.Run.Anonymization)
	}
	if len(p.Items) == 0 {
		t.Error("json: the anonymised plan has no items")
	}
}

// AX-11: the keyed machine_id_hash makes an older muster's guard refuse.
// An older muster ignores run.anonymization (simulated by deleting it) and
// renders a guard over the keyed hash, which is no host's: it differs from
// the original's, so the guard the original host runs exits 2.
func TestFixAnonymisedGuardIsNoHosts(t *testing.T) {
	h := strings.Repeat("c", 64)
	_, a := anonymisedFixFail(t, h)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, a), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["run"].(map[string]any)
	delete(run, "anonymization")
	host := run["host"].(map[string]any)
	keyed, _ := host["machine_id_hash"].(string)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(keyed) || keyed == h {
		t.Fatalf("anonymised machine_id_hash %q: want a keyed 64-hex value other than the original", keyed)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(t.TempDir(), "older.json")
	if err := os.WriteFile(older, b, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := runFixArgs(t, "--dry-run", "--facts", older, "--format", "script")
	if code != exitOK {
		t.Fatalf("script without the header: exit %d, stderr %q", code, errb)
	}
	if !bytes.Contains(out, []byte("\nMUSTER_SNAPSHOT_HOST="+keyed+"\n")) {
		t.Error("the older script's guard does not carry the keyed hash")
	}
	if bytes.Contains(out, []byte(h)) {
		t.Error("the older script carries the original host's hash")
	}
}
