package anonymize_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
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
// fixture, the whole-host readings, the cmd/muster full and anonymisation
// fixtures and the two example snapshots.
func corpus(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, g := range []string{
		"../../controls/testdata/*/*.json",
		"../../cmd/muster/testdata/full-*.json",
		"../../cmd/muster/testdata/anonymize/*.json",
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
		"run.host.hostname":                 anonymize.ClassHost,
		"run.host.machine_id_hash":          anonymize.ClassMachineID,
		"run.host.boot_id":                  anonymize.ClassBlank,
		"run.host.uptime_s":                 anonymize.ClassBlank,
		"run.collected_at":                  anonymize.ClassKept,
		"run.collectors[].reason":           anonymize.ClassPlaceholder,
		"run.partial_failures[]":            anonymize.ClassPlaceholder,
		"envelope.reason":                   anonymize.ClassPlaceholder,
		"envelope.status":                   anonymize.ClassKept,
		"envelope.truncated":                anonymize.ClassKept,
		"source.raw":                        anonymize.ClassPlaceholder,
		"source.cmd":                        anonymize.ClassPlaceholder,
		"source.path":                       anonymize.ClassPath,
		"synthetic":                         anonymize.ClassKept,
		"_expect.*":                         anonymize.ClassKept,
		"_provenance.*":                     anonymize.ClassKept,
		"_notes":                            anonymize.ClassPlaceholder,
		"_notes[]":                          anonymize.ClassPlaceholder,
		"firewall.raw_dumps[].content":      anonymize.ClassBlank,
		"logging.rsyslog.coverage[].target": anonymize.ClassPlaceholder,
		"dns.zones[].file":                  anonymize.ClassPlaceholder,
		"swap.devices[].backing":            anonymize.ClassPlaceholder,
		"coredump.core_pattern":             anonymize.ClassPath,
		"units.root_services[].unit":        anonymize.ClassUnit,
		"units.exec_writable[].unit":        anonymize.ClassUnit,
		"cron.timers[].name":                anonymize.ClassUnit,
		"mounts.points[].options[]":         anonymize.ClassGrammar,
		"nfs.exports[].options":             anonymize.ClassGrammar,
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

// readRef is one read of a table row: the control, the op (subject for a
// subject field) and the expected value.
type readRef struct {
	id, op   string
	expected any
}

// A path a clause, an applies_when or a mechanism's when reads by value is
// never placeholdered or blanked (AX-7, AX-8), and neither is a subject field
// (a placeholdered subject would merge observations). A grammar row read by
// value has no placeholder at a token position the read sees: an anchored
// matches sees token 0, any other read every token. No clause compares a
// unit-class value with a template instance (ClassUnit maps instances).
func TestReadByValueIsNeverPlaceholder(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg := registry(t)
	reads := map[string][]readRef{}
	read := func(row, id, op string, expected any) {
		reads[row] = append(reads[row], readRef{id, op, expected})
	}
	clause := func(c controls.Clause, id string) {
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
				read(p, id, sub.Op, sub.Expected)
			}
			if c.Subject != "" {
				read(elem+"."+c.Subject, id, "subject", nil)
			}
		case valueOps[c.Op]:
			p := c.Fact
			if c.Field != "" {
				p += "." + c.Field
			}
			read(p, id, c.Op, c.Expected)
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
			read(k, c.ID+" (engine)", "eq", nil)
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
		refs := reads[row]
		var ids []string
		for _, ref := range refs {
			ids = append(ids, ref.id)
		}
		by := strings.Join(ids, ", ")
		r, ok := anonymize.Default[row]
		if !ok {
			t.Errorf("%s (read by %s) has no row", row, by)
			continue
		}
		check := func(row string, r anonymize.FieldRule) {
			switch r.Class {
			case anonymize.ClassPlaceholder, anonymize.ClassBlank:
				t.Errorf("%s is %s but %s reads it by value", row, r.Class, by)
			case anonymize.ClassGrammar:
				for _, ref := range refs {
					for _, c := range readPositions(r.Grammar, ref) {
						if c == anonymize.ClassPlaceholder || c == anonymize.ClassBlank {
							t.Errorf("%s: %s reads (%s) a token position the grammar makes %s", row, ref.id, ref.op, c)
						}
					}
				}
			case anonymize.ClassUnit:
				for _, ref := range refs {
					for _, v := range expectedStrings(ref.expected) {
						if strings.Contains(v, "@") {
							t.Errorf("%s: %s compares a template instance %q, which ClassUnit maps", row, ref.id, v)
						}
					}
				}
			}
		}
		check(row, r)
		if e, ok := anonymize.Default[row+"[]"]; ok { // contains/in over a list field reads its elements
			check(row+"[]", e)
		}
	}
}

// readPositions is the class of every grammar token position a read sees: an
// anchored matches or not_matches sees token 0, anything else every token.
func readPositions(g *anonymize.Grammar, ref readRef) []anonymize.Class {
	if p, ok := ref.expected.(string); ok && (ref.op == "matches" || ref.op == "not_matches") && strings.HasPrefix(p, "^") {
		if len(g.Tokens) > 0 {
			return []anonymize.Class{g.Tokens[0]}
		}
		return []anonymize.Class{g.Rest}
	}
	return append(append([]anonymize.Class(nil), g.Tokens...), g.Rest)
}

func expectedStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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

func fact(path string, value any) map[string]any {
	parts := strings.Split(path, ".")
	var node any = map[string]any{"status": "ok", "value": value}
	for i := len(parts) - 1; i >= 0; i-- {
		node = map[string]any{parts[i]: node}
	}
	return node.(map[string]any)
}

func merge(ms ...map[string]any) map[string]any {
	out := map[string]any{}
	var into func(dst, src map[string]any)
	into = func(dst, src map[string]any) {
		for k, v := range src {
			if d, ok := dst[k].(map[string]any); ok {
				if sm, ok := v.(map[string]any); ok {
					into(d, sm)
					continue
				}
			}
			dst[k] = v
		}
	}
	for _, m := range ms {
		into(out, m)
	}
	return out
}

func valueAt(t *testing.T, out map[string]any, path string) any {
	t.Helper()
	var node any = out["facts"]
	for _, s := range strings.Split(path, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s: no %s", path, s)
		}
		node = m[s]
	}
	return node.(map[string]any)["value"]
}

func ip(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

// Option lists keep every option word byte for byte (a clause's contains
// nodev) and map the values that name an account, a host, an address or a
// file; an export's refer= and replicas= map their paths and hosts.
func TestMountAndExportOptions(t *testing.T) {
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{3}, 32))
	addr := ip(10, 1, 2, 3)
	mapped, _ := k.AddrToken(addr)
	addr2 := ip(172, 16, 0, 9)
	mapped2, _ := k.AddrToken(addr2)
	v6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 5}).String()
	doc := map[string]any{"facts": merge(
		fact("accounts.users", []any{map[string]any{"name": "alice", "home": "/home/alice"}}),
		fact("mounts.points", []any{map[string]any{"target": "/srv/share", "options": []any{
			"nodev", "nosuid", "nodev,nosuid", "rw,relatime", "username=alice", "addr=" + addr,
			"credentials=/home/alice/.smb", "domain=corp.example", "password=hunter2", "uid=1000", "",
			"clientaddr=" + addr, "mountaddr=" + addr2, "mounthost=nfs.corp.example", "mounthost=" + addr2,
			"vers=4.2,proto=tcp,clientaddr=" + addr,
			"srcaddr=" + addr, "prefixpath=/home/alice/share", "uname=alice", "aname=/home/alice/9p",
		}}}),
		fact("nfs.exports", []any{map[string]any{"path": "/srv", "client": "*",
			"options": "rw,sync,no_root_squash,refer=/srv/a@nfs1.corp.example+" + addr + ":/srv/b@nfs2,mp=/home/alice,mountpoint=/srv/x"},
			map[string]any{"path": "/srv2", "client": "*", "options": "rw,refer=/srv/a@" + v6 + ",replicas=/srv/c"}}),
	)}
	out, rep, err := anonymize.Transform(doc, anonymize.Default, k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	alice := k.Account("alice")
	want := []any{
		"nodev", "nosuid", "nodev,nosuid", "rw,relatime", "username=" + alice, "addr=" + mapped,
		"credentials=/home/" + alice + "/.smb", "domain=" + k.Host("corp.example"), "password=" + anonymize.Placeholder,
		"uid=1000", "",
		"clientaddr=" + mapped, "mountaddr=" + mapped2, "mounthost=" + k.Host("nfs.corp.example"), "mounthost=" + mapped2,
		"vers=4.2,proto=tcp,clientaddr=" + mapped,
		"srcaddr=" + mapped, "prefixpath=/home/" + alice + "/share", "uname=" + alice, "aname=/home/" + alice + "/9p",
	}
	got := valueAt(t, out, "mounts.points").([]any)[0].(map[string]any)["options"]
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mount options\n got %q\nwant %q", got, want)
	}
	exports := valueAt(t, out, "nfs.exports").([]any)
	wantExport := "rw,sync,no_root_squash,refer=/srv/a@" + k.Host("nfs1.corp.example") + "+" + mapped + ":/srv/b@" + k.Host("nfs2") +
		",mp=/home/" + alice + ",mountpoint=/srv/x"
	if got := exports[0].(map[string]any)["options"]; got != wantExport {
		t.Errorf("export options %q, want %q", got, wantExport)
	}
	// An IPv6 host split at its colons, or a location without "@", is not a
	// clean location list: the whole value is replaced, no fragment kept.
	wantV6 := "rw,refer=" + anonymize.Placeholder + ",replicas=" + anonymize.Placeholder
	if got := exports[1].(map[string]any)["options"]; got != wantV6 {
		t.Errorf("export options %q, want %q", got, wantV6)
	}
	if !strings.Contains(strings.Join(rep.Replaced, " "), "facts.mounts.points.value[].options[]") {
		t.Errorf("replaced %v does not name the placeholdered password", rep.Replaced)
	}
}

// A unit name without "@" is kept; a template instance keeps <name>@ and the
// suffix and maps the instance, injectively, the empty instance kept.
func TestUnitInstances(t *testing.T) {
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{4}, 32))
	doc := map[string]any{"facts": merge(
		fact("units.exec_writable", []any{
			map[string]any{"unit": "getty@tty1.service", "path": "/x", "why": "owner"},
			map[string]any{"unit": "getty@tty2.service", "path": "/x", "why": "owner"},
			map[string]any{"unit": "sshd.service", "path": "/x", "why": "owner"},
			map[string]any{"unit": "getty@.service", "path": "/x", "why": "owner"},
		}),
		fact("cron.timers", []any{map[string]any{"name": "backup@alice.timer", "state": "enabled"}}),
	)}
	out, rep, err := anonymize.Transform(doc, anonymize.Default, k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	var units []string
	for _, r := range valueAt(t, out, "units.exec_writable").([]any) {
		units = append(units, r.(map[string]any)["unit"].(string))
	}
	want := []string{"getty@" + k.UnitInstance("tty1") + ".service", "getty@" + k.UnitInstance("tty2") + ".service", "sshd.service", "getty@.service"}
	sort.Strings(want) // the list re-sorts by unit
	if !reflect.DeepEqual(units, want) {
		t.Errorf("units %q, want %q", units, want)
	}
	if k.UnitInstance("tty1") == k.UnitInstance("tty2") || k.UnitInstance("") != "" || !strings.HasPrefix(k.UnitInstance("tty1"), "i") || len(k.UnitInstance("tty1")) != 13 {
		t.Errorf("UnitInstance shape: %q %q", k.UnitInstance("tty1"), k.UnitInstance(""))
	}
	if got := valueAt(t, out, "cron.timers").([]any)[0].(map[string]any)["name"]; got != "backup@"+k.UnitInstance("alice")+".timer" {
		t.Errorf("timer %q", got)
	}
	if !reflect.DeepEqual(rep.Classes, []string{"unit"}) {
		t.Errorf("classes %v, want [unit]", rep.Classes)
	}
}

// A re-sorted list never deduplicates: two values that both became the
// placeholder stay two (AX-4 keeps list lengths).
func TestSortedListsNeverDeduplicate(t *testing.T) {
	for row, r := range anonymize.Default {
		if r.Sort != nil && r.Sort.Dedup {
			t.Errorf("%s deduplicates", row)
		}
	}
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{5}, 32))
	doc := map[string]any{"facts": fact("time_sync.servers", []any{"refclock:PHC:/dev/ptp0", "refclock:SHM:0", "ntp.example.org"})}
	out, _, err := anonymize.Transform(doc, anonymize.Default, k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	if got := valueAt(t, out, "time_sync.servers").([]any); len(got) != 3 {
		t.Errorf("servers %v: the length changed", got)
	}
}

// core_pattern is a path row: a pipe or a relative pattern is left alone, so
// the matches ^| clause still reads what it read.
func TestCorePatternKeepsItsShape(t *testing.T) {
	k, _ := anonymize.NewKey(bytes.Repeat([]byte{6}, 32))
	for _, p := range []string{"|/usr/lib/systemd/systemd-coredump %P %u %g", "core.%e.%p", "/var/crash/core.%e"} {
		out, _, err := anonymize.Transform(map[string]any{"facts": fact("coredump.core_pattern", p)}, anonymize.Default, k, "keyed")
		if err != nil {
			t.Fatal(err)
		}
		if got := valueAt(t, out, "coredump.core_pattern"); got != p {
			t.Errorf("core_pattern %q -> %q", p, got)
		}
	}
}
