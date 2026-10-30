package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/facts"
)

// anon runs `muster snapshot anonymize` through the command entry point.
func anon(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"snapshot", "anonymize"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// writeKey writes a key file of n bytes (byte i is seed+i) and returns its path.
func writeKey(t *testing.T, dir string, n int, seed byte) string {
	t.Helper()
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	p := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadSnap(t *testing.T, data []byte) *facts.Snapshot {
	t.Helper()
	s, err := facts.Load(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("output does not pass facts.Load: %v", err)
	}
	return s
}

// assertNotExist fails when the command left a file at p.
func assertNotExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("%s exists after a refusal (stat err %v)", p, err)
	}
}

func TestAnonymizeKeyedIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 32, 7)
	out1, out2 := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	for _, o := range []string{out1, out2} {
		code, stdout, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", o)
		if code != exitOK || stdout != "" {
			t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
		}
	}
	a, b := mustRead(t, out1), mustRead(t, out2)
	if !bytes.Equal(a, b) {
		t.Fatal("two keyed runs over the same input differ")
	}
	snap := loadSnap(t, a)
	k, err := anonymize.NewKey(mustRead(t, key))
	if err != nil {
		t.Fatal(err)
	}
	got := snap.Run.Anonymization
	if got == nil {
		t.Fatal("output has no run.anonymization")
	}
	if got.Scheme != "muster-anon-v1" || got.Mode != "keyed" || got.KeyID != k.ID() || got.KeepSet != anonymize.KeepSetVersion {
		t.Fatalf("run.anonymization = %+v", *got)
	}
	if got.Classes == nil || got.Replaced == nil {
		t.Fatalf("classes and replaced are written as lists: %+v", *got)
	}
	if snap.Run.Host.Hostname == "fixture-host" || bytes.Contains(a, []byte("fixture-host")) {
		t.Fatal("the hostname survived")
	}
	// §3: an anonymised snapshot ages like its original.
	if !bytes.Contains(a, []byte(`"collected_at": "2026-09-02T06:00:00Z"`)) {
		t.Fatal("collected_at is not byte-identical")
	}
	// A different key gives different bytes.
	key2 := writeKey(t, t.TempDir(), 32, 99)
	out3 := filepath.Join(dir, "c.json")
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", key2, "--out", out3); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if bytes.Equal(a, mustRead(t, out3)) {
		t.Fatal("two keys gave the same bytes")
	}
}

func TestAnonymizeEphemeral(t *testing.T) {
	dir := t.TempDir()
	var outs [][]byte
	for _, name := range []string{"a.json", "b.json"} {
		p := filepath.Join(dir, name)
		if code, _, stderr := anon(t, "--facts", fullPassPath, "--ephemeral", "--out", p); code != exitOK {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		outs = append(outs, mustRead(t, p))
	}
	if bytes.Equal(outs[0], outs[1]) {
		t.Fatal("two ephemeral runs gave the same bytes")
	}
	got := loadSnap(t, outs[0]).Run.Anonymization
	if got == nil || got.Mode != "ephemeral" || got.KeyID != "" {
		t.Fatalf("run.anonymization = %+v", got)
	}
	if !bytes.Contains(outs[0], []byte(`"key_id": ""`)) {
		t.Fatal("key_id is not written empty")
	}
}

func TestAnonymizeToStdout(t *testing.T) {
	key := writeKey(t, t.TempDir(), 32, 1)
	code, stdout, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", "-")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if loadSnap(t, []byte(stdout)).Run.Anonymization == nil {
		t.Fatal("stdout carries no run.anonymization")
	}
}

func TestAnonymizeFlagRefusals(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 32, 1)
	out := filepath.Join(dir, "out.json")
	for name, args := range map[string][]string{
		"neither key nor ephemeral": {"--facts", fullPassPath, "--out", out},
		"both key and ephemeral":    {"--facts", fullPassPath, "--key", key, "--ephemeral", "--out", out},
		"no out":                    {"--facts", fullPassPath, "--key", key},
		"no facts":                  {"--key", key, "--out", out},
		"unknown flag":              {"--facts", fullPassPath, "--key", key, "--out", out, "--max-age", "1h"},
		"empty key":                 {"--facts", fullPassPath, "--key", "", "--out", out},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, _ := anon(t, args...)
			if code != exitError || stdout != "" {
				t.Fatalf("exit %d stdout %q", code, stdout)
			}
			assertNotExist(t, out)
		})
	}
}

func TestAnonymizeKeyMustBe32Bytes(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64} {
		dir := t.TempDir()
		key := writeKey(t, dir, n, 3)
		out := filepath.Join(dir, "out.json")
		code, stdout, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", out)
		if code != exitError || stdout != "" || !strings.Contains(stderr, "32 bytes") {
			t.Fatalf("%d-byte key: exit %d stdout %q stderr %q", n, code, stdout, stderr)
		}
		assertNotExist(t, out)
	}
}

func TestAnonymizeRefusesAnAnonymisedInput(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 32, 5)
	first := filepath.Join(dir, "first.json")
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", first); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	second := filepath.Join(dir, "second.json")
	code, stdout, stderr := anon(t, "--facts", first, "--key", key, "--out", second)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "already anonymised") {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	assertNotExist(t, second)
}

// rewriteFixture decodes full-pass.json, lets edit change the tree and
// writes it to a new file.
func rewriteFixture(t *testing.T, dir string, edit func(doc map[string]any)) string {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(mustRead(t, fullPassPath)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "in.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnonymizeRefusesIncludeSecrets(t *testing.T) {
	dir := t.TempDir()
	in := rewriteFixture(t, dir, func(doc map[string]any) {
		doc["run"].(map[string]any)["redaction"] = map[string]any{"profile": "none", "include_secrets": true}
	})
	out := filepath.Join(dir, "out.json")
	code, stdout, stderr := anon(t, "--facts", in, "--key", writeKey(t, dir, 32, 1), "--out", out)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "include_secrets") {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	assertNotExist(t, out)
}

func TestAnonymizeRefusesASchemaItCannotRead(t *testing.T) {
	dir := t.TempDir()
	in := rewriteFixture(t, dir, func(doc map[string]any) { doc["schema_version"] = json.Number("2") })
	out := filepath.Join(dir, "out.json")
	code, stdout, _ := anon(t, "--facts", in, "--key", writeKey(t, dir, 32, 1), "--out", out)
	if code != exitError || stdout != "" {
		t.Fatalf("exit %d stdout %q", code, stdout)
	}
	assertNotExist(t, out)
}

func setVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

// AX-8: a path outside the table refuses the input with one of two
// messages, by whether the snapshot's muster is newer than this binary.
func TestAnonymizeUnclassifiedMessages(t *testing.T) {
	for _, tc := range []struct {
		name, snapVersion, binVersion, want string
	}{
		{"newer snapshot", "v1.3.0", "v1.2.0", "anonymise with muster ≥ v1.3.0"},
		{"same version", "v1.2.0", "v1.2.0", "a muster bug, please report it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setVersion(t, tc.binVersion)
			dir := t.TempDir()
			in := rewriteFixture(t, dir, func(doc map[string]any) {
				doc["run"].(map[string]any)["muster_version"] = tc.snapVersion
				doc["facts"].(map[string]any)["zz_future"] = map[string]any{
					"thing": map[string]any{"status": "ok", "value": "x"},
				}
			})
			out := filepath.Join(dir, "out.json")
			code, stdout, stderr := anon(t, "--facts", in, "--key", writeKey(t, dir, 32, 1), "--out", out)
			if code != exitError || stdout != "" {
				t.Fatalf("exit %d stdout %q", code, stdout)
			}
			if !strings.Contains(stderr, "unclassified field facts.zz_future") || !strings.Contains(stderr, tc.want) {
				t.Fatalf("stderr %q lacks %q", stderr, tc.want)
			}
			assertNotExist(t, out)
		})
	}
}

func TestUnclassifiedMessageVersionOrdering(t *testing.T) {
	const newer = "unclassified field p: anonymise with muster ≥ "
	const bug = "unclassified field p: a muster bug, please report it"
	for _, tc := range []struct{ snap, bin, want string }{
		{"v1.2.0", "dev", bug},                   // dev binary
		{"dev", "v1.2.0", bug},                   // dev snapshot
		{"v1.3.0", "5bfae2a", bug},               // tag vs hash
		{"5bfae2a", "v1.2.0", bug},               // hash vs tag
		{"v1.2.0", "v1.2.0", bug},                // equal tags
		{"", "v1.2.0", bug},                      // empty
		{"v1.2.0", "v1.3.0", bug},                // older snapshot
		{"v1.3.0", "v1.2.9", newer + "v1.3.0"},   // newer minor
		{"v2.0.0", "v1.9.9", newer + "v2.0.0"},   // newer major
		{"v1.2.10", "v1.2.9", newer + "v1.2.10"}, // numeric, not string, order
		{"v1.2.0-3-gabc1234", "v1.2.0", newer + "v1.2.0-3-gabc1234"},
		{"v1.2.0-3-gabc1234", "v1.2.0-5-gdef5678", bug}, // fewer commits
		{"v1.2.0-5-gabc1234-dirty", "v1.2.0-3-gdef5678-dirty", newer + "v1.2.0-5-gabc1234-dirty"},
		{"v1.2.0-dirty", "v1.2.0", bug},
		{"v1.3", "v1.2.0", bug}, // not a triple
		{"1.3.0", "v1.2.0", bug},
		{"v1.3.0-rc1", "v1.2.0", bug},
	} {
		if got := unclassifiedMessage(tc.snap, tc.bin, "p"); got != tc.want {
			t.Errorf("unclassifiedMessage(%q, %q) = %q, want %q", tc.snap, tc.bin, got, tc.want)
		}
	}
}

func TestAnonymizeRefusesToWriteOverItsInputOrKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	if err := os.WriteFile(in, mustRead(t, fullPassPath), 0o600); err != nil {
		t.Fatal(err)
	}
	key := writeKey(t, dir, 32, 1)
	inBefore, keyBefore := mustRead(t, in), mustRead(t, key)
	for _, args := range [][]string{
		{"--facts", in, "--key", key, "--out", in},
		{"--facts", in, "--key", key, "--out", in, "--force"},
		{"--facts", in, "--key", key, "--out", filepath.Join(dir, ".", "in.json"), "--force"},
		{"--facts", in, "--key", key, "--out", key},
		{"--facts", in, "--key", key, "--out", key, "--force"},
	} {
		code, stdout, stderr := anon(t, args...)
		if code != exitError || stdout != "" || !strings.Contains(stderr, "refusing") {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, code, stdout, stderr)
		}
	}
	if !bytes.Equal(inBefore, mustRead(t, in)) || !bytes.Equal(keyBefore, mustRead(t, key)) {
		t.Fatal("the input or the key changed")
	}
}

func TestAnonymizeExistingOut(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, 32, 1)
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(out, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", out)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "--force") {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if string(mustRead(t, out)) != "keep me" {
		t.Fatal("an existing --out was overwritten without --force")
	}
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", out, "--force"); code != exitOK {
		t.Fatalf("--force: exit %d: %s", code, stderr)
	}
	loadSnap(t, mustRead(t, out))

	// --force replaces a regular file only.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = anon(t, "--facts", fullPassPath, "--key", key, "--out", sub, "--force")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "not a regular file") {
		t.Fatalf("directory --out: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if st, err := os.Stat(sub); err != nil || !st.IsDir() {
		t.Fatal("the directory was removed")
	}
}

func TestAnonymizeOutputIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", writeKey(t, dir, 32, 1), "--out", out); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", st.Mode().Perm())
	}
}

// topKeys returns the keys of the top-level object of data in document
// order, and the keys of its "run" object.
func topKeys(t *testing.T, data []byte) (top, run []string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return objectKeys(t, data), objectKeys(t, m["run"])
}

// objectKeys returns the keys of one JSON object in document order.
func objectKeys(t *testing.T, obj []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(obj))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func runFieldOrder() []string {
	typ := reflect.TypeOf(facts.Run{})
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

func TestAnonymizeKeepsTheFixtureKeys(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "fixture.json")
	body := `{"synthetic": true, "_provenance": {"muster_version": "v1.0.0", "os_id": "ubuntu"}, "_expect": {"reason_code": "missing_fact", "exit_code": 2}, "schema_version": 1, "run": {}, "facts": {"pam": {"pwquality": {"minlen": {"status": "ok", "value": 12}}}}}`
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.json")
	if code, _, stderr := anon(t, "--facts", in, "--key", writeKey(t, dir, 32, 1), "--out", out); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	data := mustRead(t, out)
	loadSnap(t, data)
	top, run := topKeys(t, data)
	if want := []string{"schema_version", "run", "facts", "_expect", "_provenance", "synthetic"}; !reflect.DeepEqual(top, want) {
		t.Fatalf("top-level keys %v, want %v", top, want)
	}
	// The empty run block stays empty but for the mark: absent keys stay absent.
	if !reflect.DeepEqual(run, []string{"anonymization"}) {
		t.Fatalf("run keys %v", run)
	}
	doc := readJSON(t, data)
	if doc["synthetic"] != true {
		t.Fatal("synthetic lost")
	}
	if !reflect.DeepEqual(doc["_expect"], map[string]any{"reason_code": "missing_fact", "exit_code": 2.0}) {
		t.Fatalf("_expect = %v", doc["_expect"])
	}
	if !reflect.DeepEqual(doc["_provenance"], map[string]any{"muster_version": "v1.0.0", "os_id": "ubuntu"}) {
		t.Fatalf("_provenance = %v", doc["_provenance"])
	}
}

// The output is written the way collect writes a snapshot: schema_version,
// run in facts.Run field order, facts; two-space MarshalIndent.
func TestAnonymizeWritesCollectsEncoding(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", writeKey(t, dir, 32, 1), "--out", out); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	data := mustRead(t, out)
	top, run := topKeys(t, data)
	if want := []string{"schema_version", "run", "facts", "synthetic"}; !reflect.DeepEqual(top, want) {
		t.Fatalf("top-level keys %v, want %v", top, want)
	}
	order := runFieldOrder()
	if order[len(order)-1] != "anonymization" {
		t.Fatalf("anonymization is not the last field of facts.Run: %v", order)
	}
	pos := map[string]int{}
	for i, n := range order {
		pos[n] = i
	}
	for i := 1; i < len(run); i++ {
		if pos[run[i-1]] >= pos[run[i]] {
			t.Fatalf("run keys %v are not in facts.Run order", run)
		}
	}
	if !bytes.HasPrefix(data, []byte("{\n  \"schema_version\": 1,\n  \"run\": {\n    \"")) || !bytes.HasSuffix(data, []byte("}\n")) {
		t.Fatalf("not two-space MarshalIndent:\n%.200s", data)
	}
}

// encodeSnapshot reproduces collect's bytes: a collected snapshot decoded
// and encoded again is the same file.
func TestEncodeSnapshotReproducesCollect(t *testing.T) {
	for _, p := range []string{"../../examples/ubuntu-24.04-vm.json", "../../examples/ubuntu-24.04-container.json"} {
		want := mustRead(t, p)
		doc, err := decodeDocument(want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encodeSnapshot(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			i := 0
			for i < len(got) && i < len(want) && got[i] == want[i] {
				i++
			}
			lo := max(0, i-200)
			t.Fatalf("%s: re-encoding differs at byte %d:\n--- got ---\n%s\n--- want ---\n%s", p, i, got[lo:min(len(got), i+200)], want[lo:min(len(want), i+200)])
		}
	}
}

// check and fix carry run.anonymization as they carry run.
func TestCheckAndFixCarryTheMark(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if code, _, stderr := anon(t, "--facts", fullPassPath, "--key", writeKey(t, dir, 32, 1), "--out", out); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, args := range [][]string{
		{"check", "--facts", out, "--format", "json"},
		{"fix", "--dry-run", "--facts", out, "--format", "json"},
	} {
		var stdout, stderr bytes.Buffer
		run(args, &stdout, &stderr)
		var rep struct {
			Run facts.Run `json:"run"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr.String())
		}
		if rep.Run.Anonymization == nil || rep.Run.Anonymization.Mode != "keyed" {
			t.Fatalf("%v: run.anonymization = %+v", args, rep.Run.Anonymization)
		}
	}
}

func TestSnapshotUsageNamesAnonymize(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"snapshot"}, &out, &errb)
	if !strings.Contains(errb.String(), "muster snapshot anonymize --facts <in|-> (--key <file> | --ephemeral) --out <file|-> [--force]") {
		t.Fatalf("usage lacks the anonymize synopsis:\n%s", errb.String())
	}
}

// As root the command warns, and a key file another user could write is
// refused (AX-3).
func TestAnonymizeAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the trusted-file rule applies only to a root run; the CI root job and the lab run this as root")
	}
	dir := t.TempDir()
	key := writeKey(t, dir, 32, 1)
	out := filepath.Join(dir, "out.json")
	code, _, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", out)
	if code != exitOK || !strings.Contains(stderr, "warning: snapshot anonymize does not need root") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if err := os.Chmod(key, 0o666); err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(dir, "out2.json")
	code, stdout, stderr := anon(t, "--facts", fullPassPath, "--key", key, "--out", out2)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "writable") {
		t.Fatalf("untrusted key: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	assertNotExist(t, out2)
}

// FuzzDecodeDocument: whatever decodes is encoded again and decodes to the
// same tree -- the encoder orders keys, it never drops or rewrites one.
func FuzzDecodeDocument(f *testing.F) {
	f.Add(mustReadF(f, fullPassPath))
	f.Add([]byte(`{"synthetic": true, "_expect": {"exit_code": 2}, "schema_version": 1, "run": {}, "facts": {}}`))
	f.Add([]byte(`{"run": {"host": {"zz": 1, "hostname": "h"}}, "facts": {"pam": {"pwquality": {"minlen": {"reason": "r", "status": "ok", "value": 18446744073709551617}}}}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := decodeDocument(data)
		if err != nil {
			return
		}
		body, err := encodeSnapshot(doc)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		again, err := decodeDocument(body)
		if err != nil {
			t.Fatalf("re-decode: %v\n%s", err, body)
		}
		if !reflect.DeepEqual(doc, again) {
			t.Fatalf("the encoding changed the tree:\n%s", body)
		}
	})
}

func mustReadF(f *testing.F, p string) []byte {
	f.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		f.Fatal(err)
	}
	return b
}
