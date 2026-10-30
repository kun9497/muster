package anonymize_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// The classification tests (3D-3 AX-8) live in an external package so that
// internal/anonymize itself never imports the control set.

func registry(t *testing.T) *facts.Registry {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func TestDefaultTableValidates(t *testing.T) {
	if err := anonymize.Default.Validate(); err != nil {
		t.Fatal(err)
	}
	if anonymize.TableVersion == "" {
		t.Fatal("TableVersion is empty")
	}
}

// Every registry key has its own value row; a list key carries an Order. No
// registry key starts with a header root or a generic set name, which the
// walker would never take for a fact (Task 4).
func TestEveryRegistryKeyIsClassified(t *testing.T) {
	var missing []string
	for _, e := range registry(t).Keys {
		root, _, _ := strings.Cut(e.Key, ".")
		switch root {
		case "schema_version", "run", "synthetic", "_expect", "_provenance", "_notes", "envelope", "setting", "source":
			t.Errorf("registry key %s starts with a reserved root", e.Key)
		}
		r, ok := anonymize.Default[e.Key]
		if !ok {
			missing = append(missing, e.Key+" ("+e.Type+")")
			continue
		}
		inner := e.Type
		if strings.HasPrefix(inner, "setting<") {
			inner = strings.TrimSuffix(strings.TrimPrefix(inner, "setting<"), ">")
		}
		switch inner {
		case "list<string>", "list<record>":
			if r.Order == "" || r.Class != "" && r.Class != anonymize.ClassKept {
				t.Errorf("%s: a list row needs an Order and no value class, got %+v", e.Key, r)
			}
			if _, ok := anonymize.Default[e.Key+"[]"]; !ok {
				missing = append(missing, e.Key+"[]")
			}
		case "record":
			if r.Class != "" {
				t.Errorf("%s: a record row is structural, got class %q", e.Key, r.Class)
			}
		default:
			if r.Class == "" {
				t.Errorf("%s: a scalar key needs a value class", e.Key)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d registry keys are not classified:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}

// Every fact row of the table belongs to a registry key, so a renamed or
// removed key cannot leave a stale row behind.
func TestEveryFactRowNamesARegistryKey(t *testing.T) {
	keys := map[string]bool{}
	for _, e := range registry(t).Keys {
		keys[e.Key] = true
	}
	var stale []string
	for row := range anonymize.Default {
		root, _, _ := strings.Cut(row, ".")
		root, _, _ = strings.Cut(root, "[]")
		switch root {
		case "schema_version", "run", "synthetic", "_expect", "_provenance", "_notes", "envelope", "setting", "source":
			continue
		}
		if factKeyOf(row, keys) == "" {
			stale = append(stale, row)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("table rows that name no registry key:\n  %s", strings.Join(stale, "\n  "))
	}
}

// factKeyOf is the registry key a fact row continues: the longest key that
// is the row or a prefix of it ending at "." or "[]".
func factKeyOf(row string, keys map[string]bool) string {
	best := ""
	for i := len(row); i > 0; i-- {
		if i < len(row) && row[i] != '.' && !strings.HasPrefix(row[i:], "[]") {
			continue
		}
		if keys[row[:i]] {
			best = row[:i]
			break
		}
	}
	return best
}

// corpus is the invariant corpus of spec §4 as it stands: every control
// fixture, the whole-host readings, the cmd/muster full fixtures and the two
// example snapshots.
func corpus(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, g := range []string{
		"../../controls/testdata/*/*.json",
		"../../cmd/muster/testdata/full-*.json",
		"../../examples/ubuntu-24.04-vm.json",
		"../../examples/ubuntu-24.04-container.json",
	} {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 1000 {
		t.Fatalf("the corpus has %d files; the globs no longer find it", len(files))
	}
	sort.Strings(files)
	return files
}

func decode(t *testing.T, file string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var doc map[string]any
	if err := d.Decode(&doc); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return doc
}

func TestEveryCorpusFieldIsClassified(t *testing.T) {
	gaps := map[string]string{}
	for _, f := range corpus(t) {
		paths, err := anonymize.Unclassified(decode(t, f), anonymize.Default)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, p := range paths {
			if _, seen := gaps[p]; !seen {
				gaps[p] = filepath.Base(filepath.Dir(f)) + "/" + filepath.Base(f)
			}
		}
	}
	if len(gaps) == 0 {
		return
	}
	list := make([]string, 0, len(gaps))
	for p, f := range gaps {
		list = append(list, p+"  ("+f+")")
	}
	sort.Strings(list)
	t.Errorf("%d unclassified corpus paths:\n  %s", len(list), strings.Join(list, "\n  "))
}

// Every corpus snapshot anonymises: no collision, no unclassified path, and
// the output still decodes as a snapshot of this schema.
func TestEveryCorpusSnapshotTransforms(t *testing.T) {
	k, err := anonymize.NewKey(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range corpus(t) {
		out, _, err := anonymize.Transform(decode(t, f), anonymize.Default, k, "keyed")
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if _, ok := out["run"]; !ok {
			continue // a control fixture has no header for facts.Load to accept
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := facts.Load(bytes.NewReader(b)); err != nil {
			t.Errorf("%s: the anonymised snapshot does not load: %v", f, err)
		}
	}
}

// The header, the envelope, the setting and the Source are classified field
// by field, reflected from their Go types (truncated included).
func TestHeaderAndEnvelopeReflection(t *testing.T) {
	var missing []string
	check := func(row string) {
		if _, ok := anonymize.Default[row]; ok {
			return
		}
		for w := range anonymize.Default {
			if base, ok := strings.CutSuffix(w, ".*"); ok && (strings.HasPrefix(row, base+".") || strings.HasPrefix(row, base+"[]")) {
				return
			}
		}
		missing = append(missing, row)
	}
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if name == "" || name == "-" {
					t.Fatalf("%s.%s has no json name", prefix, f.Name)
				}
				walk(prefix+"."+name, f.Type)
			}
		case reflect.Slice:
			check(prefix)
			walk(prefix+"[]", typ.Elem())
		default:
			check(prefix)
		}
	}
	walk("run", reflect.TypeOf(facts.Run{}))
	check("schema_version")
	for _, gen := range []struct {
		name string
		typ  reflect.Type
	}{
		{"envelope", reflect.TypeOf(facts.Envelope{})},
		{"setting", reflect.TypeOf(facts.Setting{})},
		{"source", reflect.TypeOf(facts.Source{})},
	} {
		for i := 0; i < gen.typ.NumField(); i++ {
			name, _, _ := strings.Cut(gen.typ.Field(i).Tag.Get("json"), ",")
			check(gen.name + "." + name)
		}
	}
	for _, row := range []string{"synthetic", "_notes", "_expect.reason_code", "_provenance.image"} {
		check(row)
	}
	if len(missing) > 0 {
		t.Errorf("unclassified header or envelope fields:\n  %s", strings.Join(missing, "\n  "))
	}
}

// The AX-7 pins: free text is placeholdered with its presence kept, the
// fixture keys are kept, _notes is placeholdered as a string and as a list.
func TestHeaderTextClasses(t *testing.T) {
	d := anonymize.Default
	for row, want := range map[string]anonymize.Class{
		"run.host.hostname":            anonymize.ClassHost,
		"run.host.machine_id_hash":     anonymize.ClassMachineID,
		"run.host.boot_id":             anonymize.ClassBlank,
		"run.host.uptime_s":            anonymize.ClassBlank,
		"run.collected_at":             anonymize.ClassKept,
		"run.collectors[].reason":      anonymize.ClassPlaceholder,
		"run.partial_failures[]":       anonymize.ClassPlaceholder,
		"envelope.reason":              anonymize.ClassPlaceholder,
		"envelope.status":              anonymize.ClassKept,
		"envelope.truncated":           anonymize.ClassKept,
		"source.raw":                   anonymize.ClassPlaceholder,
		"source.cmd":                   anonymize.ClassPlaceholder,
		"source.path":                  anonymize.ClassPath,
		"synthetic":                    anonymize.ClassKept,
		"_expect.*":                    anonymize.ClassKept,
		"_provenance.*":                anonymize.ClassKept,
		"_notes":                       anonymize.ClassPlaceholder,
		"_notes[]":                     anonymize.ClassPlaceholder,
		"firewall.raw_dumps[].content": anonymize.ClassBlank,
	} {
		if got := d[row].Class; got != want {
			t.Errorf("%s: class %q, want %q", row, got, want)
		}
	}
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{1}, 32))
	for _, notes := range []any{"the alice host", []any{"alice's notes", "", "bob"}} {
		doc := map[string]any{
			"synthetic":   true,
			"_notes":      notes,
			"_expect":     map[string]any{"reason_code": "missing_fact", "exit_code": json.Number("2")},
			"_provenance": map[string]any{"image": "ubuntu:24.04", "measured": "2026-10-30"},
			"facts":       map[string]any{},
		}
		out, rep, err := anonymize.Transform(doc, anonymize.Default, k, "keyed")
		if err != nil {
			t.Fatal(err)
		}
		switch n := out["_notes"].(type) {
		case string:
			if n != anonymize.Placeholder {
				t.Errorf("_notes = %q", n)
			}
		case []any:
			if !reflect.DeepEqual(n, []any{anonymize.Placeholder, "", anonymize.Placeholder}) {
				t.Errorf("_notes = %v", n)
			}
		}
		if !reflect.DeepEqual(out["_expect"], doc["_expect"]) || !reflect.DeepEqual(out["_provenance"], doc["_provenance"]) || out["synthetic"] != true {
			t.Errorf("fixture keys changed: %v", out)
		}
		if len(rep.Replaced) == 0 || !strings.HasPrefix(rep.Replaced[0], "_notes") {
			t.Errorf("replaced %v does not name _notes", rep.Replaced)
		}
	}
}

// valueOps compare a value; present and absent read presence only, and each
// and none read a list through their where and require clauses.
var valueOps = map[string]bool{
	"eq": true, "ne": true, "in": true, "not_in": true, "matches": true, "not_matches": true,
	"contains": true, "not_contains": true, "gt": true, "gte": true, "lt": true, "lte": true,
}

var collectionOps = map[string]bool{"each": true, "none": true}

// A path a clause, an applies_when or a mechanism's when reads by value is
// never placeholdered or blanked (AX-7, AX-8), and neither is a subject field
// (a placeholdered subject would merge observations).
func TestReadByValueIsNeverPlaceholder(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg := registry(t)
	reads := map[string][]string{} // table row -> controls reading it
	read := func(row, id string) { reads[row] = append(reads[row], id) }
	var clause func(c controls.Clause, id string)
	clause = func(c controls.Clause, id string) {
		if c.Fact == "" {
			return
		}
		switch {
		case collectionOps[c.Op]:
			elem := c.Fact + "[]"
			for _, sub := range []*controls.Clause{c.Where, c.Require} {
				if sub == nil || !valueOps[sub.Op] {
					continue
				}
				p := elem
				if sub.Field != "" {
					p += "." + sub.Field
				}
				read(p, id)
			}
			if c.Subject != "" {
				read(elem+"."+c.Subject, id)
			}
		case valueOps[c.Op]:
			p := c.Fact
			if c.Field != "" {
				p += "." + c.Field
			}
			read(p, id)
		}
	}
	for i := range set.Controls {
		c := &set.Controls[i]
		all := append(append([]controls.Clause(nil), c.AppliesWhen...), c.Checks...)
		for _, m := range c.Mechanisms {
			all = append(append(all, m.When...), m.Checks...)
		}
		for _, cl := range all {
			clause(cl, c.ID)
		}
		for _, k := range controls.EngineKeys(c, reg) {
			read(k, c.ID+" (engine)")
		}
	}
	if len(reads) < 50 {
		t.Fatalf("only %d read paths found; the clause walk is broken", len(reads))
	}
	rows := make([]string, 0, len(reads))
	for r := range reads {
		rows = append(rows, r)
	}
	sort.Strings(rows)
	for _, row := range rows {
		r, ok := anonymize.Default[row]
		if !ok {
			t.Errorf("%s (read by %s) has no row", row, strings.Join(reads[row], ", "))
			continue
		}
		check := func(row string, r anonymize.FieldRule) {
			switch r.Class {
			case anonymize.ClassPlaceholder, anonymize.ClassBlank:
				t.Errorf("%s is %s but %s reads it by value", row, r.Class, strings.Join(reads[row], ", "))
			}
		}
		check(row, r)
		if e, ok := anonymize.Default[row+"[]"]; ok { // contains/in over a list field reads its elements
			check(row+"[]", e)
		}
	}
}

// The walker's refusal names a path the table lacks; the table is not the
// place where that message is decided, but the error type must stay one
// Task 6 can tell apart.
func TestUnclassifiedIsTyped(t *testing.T) {
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{1}, 32))
	_, _, err := anonymize.Transform(map[string]any{"facts": map[string]any{"accounts": map[string]any{"no_such_key": map[string]any{"status": "ok"}}}}, anonymize.Default, k, "keyed")
	var u *anonymize.UnclassifiedError
	if !errors.As(err, &u) || u.Path != "facts.accounts.no_such_key" {
		t.Fatalf("err = %v", err)
	}
	got, err := anonymize.Unclassified(map[string]any{"facts": map[string]any{"accounts": map[string]any{"no_such_key": map[string]any{}, "users": map[string]any{"status": "ok", "value": []any{map[string]any{"name": "a", "nope": "x", "nope2": "y"}}}}}}, anonymize.Default)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"facts.accounts.no_such_key", "facts.accounts.users.value[].nope", "facts.accounts.users.value[].nope2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Unclassified = %v, want %v", got, want)
	}
}

// Sorted is what the Linux collectors check asks of each sorted list.
func TestSortSpecSorted(t *testing.T) {
	rec := func(name string, uid int) any {
		return map[string]any{"name": name, "uid": json.Number(strconv.Itoa(uid))}
	}
	spec := &anonymize.SortSpec{Keys: []anonymize.SortKey{{Field: "name"}, {Field: "uid", Numeric: true}}}
	if !spec.Sorted([]any{rec("a", 2), rec("a", 10), rec("b", 1)}) {
		t.Error("an ordered list is not sorted")
	}
	if spec.Sorted([]any{rec("a", 10), rec("a", 2)}) {
		t.Error("10 before 2 is sorted numerically")
	}
	if !spec.Sorted([]any{rec("a", 1), rec("a", 1)}) {
		t.Error("equal neighbours are sorted without dedup")
	}
	dedup := &anonymize.SortSpec{Keys: []anonymize.SortKey{{}}, Dedup: true}
	if dedup.Sorted([]any{"a", "a"}) || !dedup.Sorted([]any{"a", "b"}) || !dedup.Sorted(nil) {
		t.Error("dedup: equal neighbours must fail, distinct ones pass")
	}
}
