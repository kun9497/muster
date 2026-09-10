package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

var fullPassPath = filepath.Join("testdata", "full-pass.json")

// leafPaths flattens a facts tree to the dotted paths of its leaves. A leaf
// is an object carrying "status" (an envelope) or one of the setting sides,
// which is what the tree the extractor writes must be made of: whole leaves
// at their registered paths, and nothing else.
func leafPaths(tree map[string]any) []string {
	var out []string
	var walk func(map[string]any, string)
	walk = func(m map[string]any, prefix string) {
		for k, v := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			sub, isObj := v.(map[string]any)
			if !isObj || isLeafObject(sub) {
				out = append(out, p)
				continue
			}
			walk(sub, p)
		}
	}
	walk(tree, "")
	sort.Strings(out)
	return out
}

func isLeafObject(m map[string]any) bool {
	for _, k := range []string{"status", "runtime", "persisted", "effective"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

func readJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, data)
	}
	return m
}

func factsOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	f, ok := doc["facts"].(map[string]any)
	if !ok {
		t.Fatalf("output carries no facts object: %v", doc)
	}
	return f
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// controlStatus evaluates one control of the embedded set against the
// snapshot at path. It is how the extracted fixture is held to the only
// promise that matters: it must decide the control the way the snapshot it
// was cut from does.
func controlStatus(t *testing.T, path, id string) check.Status {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	snap, err := facts.Load(fh)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range check.Evaluate(snap, set, reg, check.Options{}) {
		if r.ID == id {
			return r.Status
		}
	}
	t.Fatalf("%s: no result for %s", path, id)
	return ""
}

// M-16: extract cuts exactly the leaves the control reads out of a snapshot
// -- applies_when and every mechanism's when/checks for U-28 -- copies them
// content-faithfully, and carries a provenance block that names the OS but never
// the host.
func TestSnapshotExtractKeepsOnlyWhatTheControlReads(t *testing.T) {
	out := filepath.Join(t.TempDir(), "f.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", "muster.file.ip_port_restriction", "--out", out}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d, want %d; stdout %q stderr %q", code, exitOK, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("extract wrote no %s: %v", out, err)
	}
	got := readJSON(t, data)
	src, err := os.ReadFile(fullPassPath)
	if err != nil {
		t.Fatal(err)
	}
	source := readJSON(t, src)

	if want := []string{"_provenance", "facts", "run", "schema_version", "synthetic"}; !reflect.DeepEqual(sortedKeys(got), want) {
		t.Errorf("top-level keys %v, want %v", sortedKeys(got), want)
	}
	// D02: what comes off a host is not synthetic, and only a human may say
	// otherwise. The fixture test rejects the file until one does.
	if got["synthetic"] != false {
		t.Errorf(`synthetic = %v, want false`, got["synthetic"])
	}
	if got["schema_version"] != source["schema_version"] {
		t.Errorf("schema_version %v, want the snapshot's %v", got["schema_version"], source["schema_version"])
	}
	if m, ok := got["run"].(map[string]any); !ok || len(m) != 0 {
		t.Errorf("run = %v, want an empty object", got["run"])
	}

	prov, ok := got["_provenance"].(map[string]any)
	if !ok {
		t.Fatalf("_provenance = %v, want an object", got["_provenance"])
	}
	if want := []string{"collected_at", "muster_version", "os_id", "os_version_id"}; !reflect.DeepEqual(sortedKeys(prov), want) {
		t.Errorf("_provenance keys %v, want %v", sortedKeys(prov), want)
	}
	srcRun := source["run"].(map[string]any)
	srcHost := srcRun["host"].(map[string]any)
	srcOS := srcHost["os_release"].(map[string]any)
	for _, c := range []struct {
		field string
		want  any
	}{
		{"muster_version", srcRun["muster_version"]},
		{"collected_at", srcRun["collected_at"]},
		{"os_id", srcOS["id"]},
		{"os_version_id", srcOS["version_id"]},
	} {
		if prov[c.field] != c.want {
			t.Errorf("_provenance.%s = %v, want %v", c.field, prov[c.field], c.want)
		}
	}
	// The one thing the provenance block must never carry.
	host, _ := srcHost["hostname"].(string)
	if host == "" {
		t.Fatal("the source snapshot names no host, so this test proves nothing")
	}
	if strings.Contains(string(data), host) {
		t.Errorf("the extract must not carry the hostname %q:\n%s", host, data)
	}

	// Exactly the keys U-28 reads: applies_when (firewall.backend) and the
	// three mechanisms' when/checks, files.libwrap_present among them since
	// M-9 gated the tcp_wrappers mechanism on it.
	// firewall.normalization_confidence sits beside them in the snapshot and
	// no clause names it.
	want := []string{"files.etc_hosts_deny_all", "files.libwrap_present", "firewall.backend", "firewall.restricts_inbound"}
	if leaves := leafPaths(factsOf(t, got)); !reflect.DeepEqual(leaves, want) {
		t.Errorf("extracted leaves %v, want %v", leaves, want)
	}
	// Content-faithful, not re-encoded (object keys are sorted by the
	// encoder, nothing else changes): files.etc_hosts_deny_all is
	// {"status":"ok","value":false}, and value is omitempty on the envelope
	// type, so a copy that went through the registry would drop it.
	srcFacts := factsOf(t, source)
	for _, k := range want {
		if !reflect.DeepEqual(leafAt(t, factsOf(t, got), k), leafAt(t, srcFacts, k)) {
			t.Errorf("%s: extracted leaf %v differs from the snapshot's %v", k, leafAt(t, factsOf(t, got), k), leafAt(t, srcFacts, k))
		}
	}

	// The point of the whole command: the cut-down file decides U-28 the way
	// the snapshot it came from does.
	full := controlStatus(t, fullPassPath, "muster.file.ip_port_restriction")
	cut := controlStatus(t, out, "muster.file.ip_port_restriction")
	if full != check.PASS {
		t.Fatalf("the source snapshot decides U-28 %s, so this test proves nothing", full)
	}
	if cut != full {
		t.Errorf("the extract decides U-28 %s; the snapshot it came from decides %s", cut, full)
	}

	// M-54: the same promise, for a control the engine resolves keys of its
	// own while it evaluates. root_remote_login is judged on sshd.options.*,
	// and the engine reads sshd.personas_collected and sshd.collect_method
	// beside it -- a fixture cut without them degrades where the host did
	// not, which is the one thing this command may never do.
	const withEngineKeys = "muster.account.root_remote_login"
	engineOut := filepath.Join(t.TempDir(), "rrl.json")
	var engineStdout, engineStderr bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", withEngineKeys, "--out", engineOut}, &engineStdout, &engineStderr); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, engineStderr.String())
	}
	fullEngine := controlStatus(t, fullPassPath, withEngineKeys)
	if fullEngine != check.PASS {
		t.Fatalf("the source snapshot decides %s %s, so this test proves nothing", withEngineKeys, fullEngine)
	}
	if cutEngine := controlStatus(t, engineOut, withEngineKeys); cutEngine != fullEngine {
		t.Errorf("the extract decides %s %s; the snapshot it came from decides %s", withEngineKeys, cutEngine, fullEngine)
	}

	// EV-1: the remote-NSS degradation is decided by the REGISTRY (a clause
	// fact whose subject_kind is user or group), not by an accounts. prefix.
	// files.home_dirs is subject_kind user, so a host with a remote NSS source
	// reads U-32 WARN; a fixture cut without accounts.nss.remote would read
	// PASS -- a fixture claiming a verdict its host never gave.
	remoteSrc := filepath.Join(t.TempDir(), "remote-nss.json")
	writeWithRemoteNSS(t, fullPassPath, remoteSrc)
	const subjectKeyed = "muster.file.home_dir_exists"
	remoteOut := filepath.Join(t.TempDir(), "home.json")
	var remoteStdout, remoteStderr bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", remoteSrc, "--control", subjectKeyed, "--out", remoteOut}, &remoteStdout, &remoteStderr); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, remoteStderr.String())
	}
	fullRemote := controlStatus(t, remoteSrc, subjectKeyed)
	if fullRemote != check.WARN {
		t.Fatalf("the source snapshot decides %s %s, want WARN, so this test proves nothing", subjectKeyed, fullRemote)
	}
	if cutRemote := controlStatus(t, remoteOut, subjectKeyed); cutRemote != fullRemote {
		t.Errorf("the extract decides %s %s; the snapshot it came from decides %s", subjectKeyed, cutRemote, fullRemote)
	}
}

// writeWithRemoteNSS copies a snapshot with facts.accounts.nss.remote set to
// ok:true, which is how a host with an LDAP or SSSD account source reads. The
// committed snapshot has no such leaf (its account source is files), so the
// degradation is added here rather than in the shared fixture, where it would
// move every account control's e2e row.
func writeWithRemoteNSS(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	var snap map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&snap); err != nil {
		t.Fatal(err)
	}
	tree, ok := snap["facts"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no facts tree", src)
	}
	accounts, ok := tree["accounts"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no accounts subtree", src)
	}
	nss, ok := accounts["nss"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no accounts.nss subtree", src)
	}
	nss["remote"] = map[string]any{"status": "ok", "value": true}
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func leafAt(t *testing.T, tree map[string]any, key string) any {
	t.Helper()
	var cur any = tree
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	return cur
}

// M-16: walk.complete gates the deep walk in the engine, so a control that
// reads any walk.* key needs it in its fixture although no clause names it;
// a manual control's evidence keys are read the same way as its clauses; and
// a control id the set does not carry is refused.
func TestSnapshotExtractWalkAndEvidenceKeys(t *testing.T) {
	dir := t.TempDir()

	// walk.complete is asked for even when the snapshot does not carry it,
	// and a key the snapshot lacks is named on stderr rather than invented.
	out := filepath.Join(dir, "walk.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", "muster.file.world_writable", "--out", out}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing: walk.complete") {
		t.Errorf("stderr %q must name walk.complete as missing", stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if leaves := leafPaths(factsOf(t, readJSON(t, data))); !reflect.DeepEqual(leaves, []string{"walk.world_writable"}) {
		t.Errorf("extracted leaves %v, want just walk.world_writable", leaves)
	}

	// A snapshot that does carry it: both leaves come through, the rest does
	// not.
	withWalk := filepath.Join(dir, "with-walk.json")
	writeSnapshot(t, withWalk, `{
	  "schema_version": 1,
	  "run": {"muster_version": "0.0.1", "collected_at": "2026-09-09T00:00:00Z"},
	  "facts": {
	    "walk": {"complete": {"status": "ok", "value": true}, "world_writable": {"status": "absent"}},
	    "firewall": {"backend": {"status": "ok", "value": "none"}}
	  }
	}`)
	out2 := filepath.Join(dir, "walk2.json")
	var stdout2, stderr2 bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", withWalk, "--control", "muster.file.world_writable", "--out", out2}, &stdout2, &stderr2); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderr2.String())
	}
	data2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if leaves := leafPaths(factsOf(t, readJSON(t, data2))); !reflect.DeepEqual(leaves, []string{"walk.complete", "walk.world_writable"}) {
		t.Errorf("extracted leaves %v, want walk.complete and walk.world_writable", leaves)
	}
	if stderr2.Len() != 0 {
		t.Errorf("nothing was missing; stderr %q", stderr2.String())
	}

	// A manual control: its evidence keys are what the reviewer needs in
	// hand, so they are cut out beside the applies_when facts. Without
	// --out the file goes to stdout. M-8/Task 7: full-pass.json now carries
	// every evidence leaf the four manual controls name, so nothing is
	// missing here and stderr stays empty.
	var stdout3, stderr3 bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", "muster.service.mail_version"}, &stdout3, &stderr3); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderr3.String())
	}
	want := []string{"mail.implementation", "patch.metadata_age_s", "patch.pending_security_count", "patch.security_metadata_available", "services.mail.installed"}
	if leaves := leafPaths(factsOf(t, readJSON(t, stdout3.Bytes()))); !reflect.DeepEqual(leaves, want) {
		t.Errorf("extracted leaves %v, want %v", leaves, want)
	}
	if stderr3.Len() != 0 {
		t.Errorf("nothing was missing; stderr %q", stderr3.String())
	}

	// An evidence key the snapshot does not carry is still named on stderr,
	// the same way a missing applies_when fact is: the reviewer has to know
	// the worksheet came out short.
	thinMail := filepath.Join(dir, "thin-mail.json")
	writeSnapshot(t, thinMail, `{
	  "schema_version": 1,
	  "run": {"muster_version": "0.0.1", "collected_at": "2026-09-09T00:00:00Z"},
	  "facts": {
	    "services": {"mail": {"installed": {"status": "ok", "value": true}}},
	    "mail": {"implementation": {"status": "ok", "value": "postfix"}},
	    "patch": {"metadata_age_s": {"status": "ok", "value": 60}}
	  }
	}`)
	var stdoutThin, stderrThin bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", thinMail, "--control", "muster.service.mail_version"}, &stdoutThin, &stderrThin); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderrThin.String())
	}
	for _, k := range []string{"patch.pending_security_count", "patch.security_metadata_available"} {
		// The warning's shape, not merely a mention of the key somewhere on
		// stderr (snapshot.go writes "missing: <key>").
		if !strings.Contains(stderrThin.String(), "missing: "+k) {
			t.Errorf("stderr %q must name the evidence key %s the snapshot lacks", stderrThin.String(), k)
		}
	}

	// Content-faithful: an integer beyond float64's exact range keeps its
	// digits, and a field the envelope type does not know survives -- both
	// of which a copy through the registry would lose.
	odd := filepath.Join(dir, "odd.json")
	writeSnapshot(t, odd, `{
	  "schema_version": 1,
	  "run": {},
	  "facts": {
	    "services": {"mail": {"installed": {"status": "ok", "value": true}}},
	    "mail": {"implementation": {"status": "ok", "value": "postfix"}},
	    "patch": {
	      "metadata_age_s": {"status": "ok", "value": 9007199254740993, "collector_note": "kept"},
	      "pending_security_count": {"status": "ok", "value": 0},
	      "security_metadata_available": {"status": "ok", "value": false}
	    }
	  }
	}`)
	var stdout4, stderr4 bytes.Buffer
	if code := run([]string{"snapshot", "extract", "--facts", odd, "--control", "muster.service.mail_version"}, &stdout4, &stderr4); code != exitOK {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitOK, stderr4.String())
	}
	for _, want := range []string{"9007199254740993", `"collector_note": "kept"`, `"value": false`} {
		if !strings.Contains(stdout4.String(), want) {
			t.Errorf("the copy is not content-faithful: %q is gone\n%s", want, stdout4.String())
		}
	}

	// A control the set does not carry.
	var stdout5, stderr5 bytes.Buffer
	code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", "muster.file.no_such_control"}, &stdout5, &stderr5)
	if code != exitRefused {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitRefused, stderr5.String())
	}
	if stdout5.Len() != 0 {
		t.Errorf("stdout must stay empty on a refusal, got %q", stdout5.String())
	}
	if !strings.Contains(stderr5.String(), "muster.file.no_such_control") {
		t.Errorf("stderr %q must name the control it does not know", stderr5.String())
	}
}

func writeSnapshot(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Same input, same bytes (CLAUDE.md): the file is a fixture under review, so
// a second run must not produce a diff.
func TestSnapshotExtractIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	var first, second []byte
	for i, out := range []string{filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"snapshot", "extract", "--facts", fullPassPath, "--control", "muster.service.mail_version", "--out", out}, &stdout, &stderr); code != exitOK {
			t.Fatalf("run %d: exit %d, want %d; stderr %q", i, code, exitOK, stderr.String())
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = data
		} else {
			second = data
		}
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two runs of the same input differ:\n%s\n---\n%s", first, second)
	}
	if !bytes.HasSuffix(first, []byte("\n")) {
		t.Errorf("the file must end with a newline:\n%s", first)
	}
	if !bytes.Contains(first, []byte("\n  \"facts\": {")) {
		t.Errorf("the file must be indented for review:\n%s", first)
	}
}

// A snapshot from a real host is not cheap to reproduce, and the whole input
// is in memory by the time the extract is written -- so pointing --out at
// --facts would succeed, quietly, and leave a few hundred bytes where the
// snapshot was.
func TestSnapshotExtractRefusesToOverwriteItsOwnInput(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "snap.json")
	source, err := os.ReadFile(fullPassPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, source, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"snapshot", "extract", "--facts", snapshot, "--control", "muster.file.ip_port_restriction", "--out", snapshot}, &stdout, &stderr)
	if code != exitRefused {
		t.Fatalf("exit %d, want %d; stderr %q", code, exitRefused, stderr.String())
	}
	after, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, after) {
		t.Errorf("the snapshot was overwritten by its own extract: %d bytes, was %d", len(after), len(source))
	}
	if !strings.Contains(stderr.String(), snapshot) {
		t.Errorf("stderr %q must name the file it refused to write over", stderr.String())
	}
}
