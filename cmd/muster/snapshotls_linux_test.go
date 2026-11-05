//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const seedHangul = "ws01-2026-09-01T120000Z-eeeeeeeeeeee.json"

// seedLsDir is seedSnapshotDir plus an ok row whose hostname is Hangul
// (RA-29) and a regular file whose name carries a newline (Review Focus 1).
func seedLsDir(t *testing.T) string {
	t.Helper()
	dir := seedSnapshotDir(t)
	writeSnapshot(t, filepath.Join(dir, seedHangul), snapBody(1, "2026-09-01T12:00:00Z", "웹서버01", seedMusterV, seedControlsV))
	writeSnapshot(t, filepath.Join(dir, "bad\n-2026-09-02T060000Z-0123456789ab.json"), "{")
	return dir
}

const wantLsRows = `NAME                                        COLLECTED             HOST      MUSTER  CONTROLS    SIZE  CLASS
web01-2026-09-03T060000Z-bbbbbbbbbbbb.json  2026-09-03T06:00:00Z  web01     9.9.9   2026.09.09  163   newer
web01-2026-09-02T060000Z-0123456789ab.json  2026-09-02T06:00:00Z  web01     0.0.1   2026.09.09  162   ok          *
ws01-2026-09-01T120000Z-eeeeeeeeeeee.json   2026-09-01T12:00:00Z  웹서버01  0.0.1   2026.09.09  168   ok
db02-2026-09-01T060000Z-aaaaaaaaaaaa.json   2026-09-01T06:00:00Z  db02      0.0.1   2026.09.09  161   ok
web01-2026-08-31T060000Z-dddddddddddd.json  -                     -         -       -           0     unreadable
web01-2026-08-30T060000Z-cccccccccccc.json  -                     -         -       -           1     unreadable
`

func runLs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"snapshot", "ls"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// Same input, same bytes; widths by display width (RA-29); a name with a
// newline is counted, never opened, and a link target is escaped (Review
// Focus 1).
func TestSnapshotLsTableIsDeterministic(t *testing.T) {
	dir := seedLsDir(t)
	code, first, stderr := runLs(t, "--dir", dir)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	_, second, _ := runLs(t, "--dir", dir)
	if !bytes.Equal([]byte(first), []byte(second)) {
		t.Fatalf("two runs differ:\n%s\n%s", first, second)
	}
	want := dir + "  (6 snapshots, 4 other files; latest -> " + seedOKNew + ")\n" + wantLsRows
	if first != want {
		t.Errorf("table:\n%s\nwant:\n%s", first, want)
	}

	if err := os.Remove(filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a\nb\x01", filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	_, out, _ := runLs(t, "--dir", dir)
	header, _, _ := strings.Cut(out, "\n")
	if want := dir + `  (6 snapshots, 4 other files; latest -> a\nb\u0001 (dangling))`; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
	if strings.Contains(out, "*") {
		t.Errorf("a dangling link marks a row:\n%s", out)
	}

	if err := os.Remove(filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	_, out, _ = runLs(t, "--dir", dir)
	header, _, _ = strings.Cut(out, "\n")
	if want := dir + "  (6 snapshots, 4 other files; no latest link)"; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
}

// The JSON keys come in the documented order, entries in Sort order.
func TestSnapshotLsJSONShape(t *testing.T) {
	dir := seedLsDir(t)
	code, out, stderr := runLs(t, "--dir", dir, "--format", "json")
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Errorf("output does not end in one newline: %q", out)
	}
	doc := readJSON(t, []byte(out))
	entries, _ := doc["entries"].([]any)
	if len(entries) != 6 {
		t.Fatalf("%d entries, want 6", len(entries))
	}
	if doc["dir"] != dir || doc["other_files"] != float64(4) {
		t.Errorf("dir, other_files = %v, %v", doc["dir"], doc["other_files"])
	}
	if want := map[string]any{"present": true, "target": seedOKNew, "state": "ok"}; !reflect.DeepEqual(doc["latest"], want) {
		t.Errorf("latest = %v", doc["latest"])
	}
	var names []string
	for _, e := range entries {
		m, _ := e.(map[string]any)
		names = append(names, m["name"].(string))
	}
	if want := []string{seedNewer, seedOKNew, seedHangul, seedOKOld, seedEmpty, seedBrace}; !reflect.DeepEqual(names, want) {
		t.Errorf("entry order %v, want %v", names, want)
	}
	second, _ := entries[1].(map[string]any)
	if second["latest"] != true || second["class"] != "ok" || second["hostname"] != "web01" || second["size"] != float64(162) {
		t.Errorf("entries[1] = %v", second)
	}

	if got, want := nthObjectKeys(t, out, 0), []string{"dir", "other_files", "latest", "entries"}; !reflect.DeepEqual(got, want) {
		t.Errorf("top-level keys %v, want %v", got, want)
	}
	if got, want := nthObjectKeys(t, out, 1), []string{"present", "target", "state"}; !reflect.DeepEqual(got, want) {
		t.Errorf("latest keys %v, want %v", got, want)
	}
	if got, want := nthObjectKeys(t, out, 2), []string{"name", "class", "size", "schema_version", "collected_at", "hostname", "muster_version", "controls_version", "latest"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entry keys %v, want %v", got, want)
	}

	if err := os.Remove(filepath.Join(dir, "latest")); err != nil {
		t.Fatal(err)
	}
	_, out, _ = runLs(t, "--dir", dir, "--format", "json")
	if doc := readJSON(t, []byte(out)); doc["latest"] != nil {
		t.Errorf("no link: latest = %v, want null", doc["latest"])
	}
}

// nthObjectKeys returns, in document order, the keys of the n-th JSON object
// to open (counting from 0).
func nthObjectKeys(t *testing.T, doc string, n int) []string {
	t.Helper()
	type frame struct {
		obj, wantKey bool
		idx          int
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	var stack []*frame
	opened := -1
	var keys []string
	valueEnded := func() {
		if len(stack) > 0 && stack[len(stack)-1].obj {
			stack[len(stack)-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{':
				opened++
				stack = append(stack, &frame{obj: true, wantKey: true, idx: opened})
			case '[':
				stack = append(stack, &frame{})
			default:
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if f.obj && f.idx == n {
					return keys
				}
				valueEnded()
			}
			continue
		}
		if top := len(stack) - 1; top >= 0 && stack[top].obj && stack[top].wantKey {
			if stack[top].idx == n {
				keys = append(keys, tok.(string))
			}
			stack[top].wantKey = false
			continue
		}
		valueEnded()
	}
	t.Fatalf("no object %d in %s", n, doc)
	return nil
}

// A directory that cannot be opened or is refused is exit 2, named on
// stderr, stdout empty; an empty directory is a listing.
func TestSnapshotLsRefusals(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	code, out, stderr := runLs(t, "--dir", missing)
	if code != exitError || out != "" || !strings.HasPrefix(stderr, "muster: ") || !strings.Contains(stderr, missing) {
		t.Errorf("missing dir: exit %d, stdout %q, stderr %q", code, out, stderr)
	}

	writable := t.TempDir()
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = runLs(t, "--dir", writable)
	if want := "muster: " + writable + " is not owned by uid " + strconv.Itoa(os.Geteuid()) + ", or is group- or world-writable\n"; code != exitError || out != "" || stderr != want {
		t.Errorf("writable dir: exit %d, stdout %q, stderr %q", code, out, stderr)
	}

	empty := t.TempDir()
	if err := os.Chmod(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runLs(t, "--dir", empty)
	if want := empty + "  (0 snapshots, 0 other files; no latest link)\nNAME  COLLECTED  HOST  MUSTER  CONTROLS  SIZE  CLASS\n"; code != exitOK || out != want {
		t.Errorf("empty dir: exit %d, stdout %q, want %q", code, out, want)
	}
	code, out, _ = runLs(t, "--dir", empty, "--format", "json")
	if want := "{\n  \"dir\": \"" + empty + "\",\n  \"other_files\": 0,\n  \"latest\": null,\n  \"entries\": []\n}\n"; code != exitOK || out != want {
		t.Errorf("empty dir json: exit %d, stdout %q, want %q", code, out, want)
	}
}
