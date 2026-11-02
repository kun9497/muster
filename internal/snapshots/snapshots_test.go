package snapshots

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/facts"
)

const stamp = "2026-09-02T060000Z"

func TestParseName(t *testing.T) {
	for _, tc := range []struct {
		name, host, stamp string
		ok                bool
	}{
		{"web_01_prod-2026-09-02T060000Z-0123456789ab.json", "web_01_prod", stamp, true},
		{"-2026-09-02T060000Z-0123456789ab.json", "", stamp, true},
		{"a-b-c-2026-09-02T060000Z-0123456789ab.json", "a-b-c", stamp, true},
		{"web.example-2026-09-02T060000Z-0123456789ab.json", "web.example", stamp, true},
		{strings.Repeat("h", 64) + "-2026-09-02T060000Z-0123456789ab.json", strings.Repeat("h", 64), stamp, true},
		{strings.Repeat("h", 65) + "-2026-09-02T060000Z-0123456789ab.json", "", "", false},
		{strings.Repeat("h", 300) + "-2026-09-02T060000Z-0123456789ab.json", "", "", false},
		{"x-2026-09-02T060000Z-0123456789AB.json", "", "", false},
		{"x-2026-09-02T060000Z-0123456789ab.json.bak", "", "", false},
		{"x-2026-09-02T06000AZ-0123456789ab.json", "", "", false},
		{"x-2026-09-02 060000Z-0123456789ab.json", "", "", false},
		{"x-2026-09-02T060000Z_0123456789ab.json", "", "", false},
		{"x y-2026-09-02T060000Z-0123456789ab.json", "", "", false},
		{"x2026-09-02T060000Z-0123456789ab.json", "", "", false},
		{"latest", "", "", false},
		{".x.tmp-12", "", "", false},
	} {
		host, st, ok := ParseName(tc.name)
		if host != tc.host || st != tc.stamp || ok != tc.ok {
			t.Errorf("ParseName(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.name, host, st, ok, tc.host, tc.stamp, tc.ok)
		}
	}
}

func TestParseCollectedAt(t *testing.T) {
	got, err := ParseCollectedAt("2026-09-02T06:00:00Z")
	if err != nil || !got.Equal(time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC)) || got.Location() != time.UTC {
		t.Errorf("ParseCollectedAt ok = %v, %v", got, err)
	}
	for _, s := range []string{"2026-09-02T06:00:00+00:00", "2026-09-02T06:00:00.5Z", ""} {
		if _, err := ParseCollectedAt(s); err == nil {
			t.Errorf("ParseCollectedAt(%q) accepted", s)
		}
	}
}

func header(schema int, collectedAt string) facts.Header {
	h := facts.Header{SchemaVersion: schema}
	h.Run.CollectedAt = collectedAt
	h.Run.Host.Hostname = "web_01_prod"
	h.Run.MusterVersion = "2026.11.02"
	h.Run.ControlsVersion = "2026.11.01"
	return h
}

func TestClassify(t *testing.T) {
	const name = "web_01_prod-2026-09-02T060000Z-0123456789ab.json"
	ok := Classify(name, 42, header(facts.SchemaVersion, "2026-09-02T06:00:00Z"), nil)
	want := Entry{Name: name, Class: ClassOK, Size: 42, SchemaVersion: facts.SchemaVersion, CollectedAt: "2026-09-02T06:00:00Z",
		Hostname: "web_01_prod", MusterVersion: "2026.11.02", ControlsVersion: "2026.11.01"}
	if ok != want {
		t.Errorf("ok = %+v, want %+v", ok, want)
	}

	newer := Classify(name, 42, header(facts.SchemaVersion+1, "2026-09-02T06:00:00+00:00"), nil)
	want.Class, want.SchemaVersion, want.CollectedAt = ClassNewer, facts.SchemaVersion+1, "2026-09-02T06:00:00+00:00"
	if newer != want {
		t.Errorf("newer = %+v, want %+v", newer, want)
	}

	bare := Entry{Name: name, Class: ClassUnreadable, Size: 42}
	for label, e := range map[string]Entry{
		"error":         Classify(name, 42, header(facts.SchemaVersion, "2026-09-02T06:00:00Z"), errors.New("parse snapshot")),
		"schema 0":      Classify(name, 42, header(0, "2026-09-02T06:00:00Z"), nil),
		"bad collected": Classify(name, 42, header(facts.SchemaVersion, "2026-09-02 06:00:00"), nil),
	} {
		if e != bare {
			t.Errorf("%s = %+v, want %+v", label, e, bare)
		}
	}
}

// fileName spells a snapshot name for host at t, as collect writes it.
func fileName(host string, t time.Time) string {
	return host + "-" + t.UTC().Format("2006-01-02T150405Z") + "-0123456789ab.json"
}

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func okEntry(host string, t time.Time) Entry {
	return Entry{Name: fileName(host, t), Class: ClassOK, SchemaVersion: facts.SchemaVersion, CollectedAt: t.UTC().Format("2006-01-02T15:04:05Z")}
}

func names(es []Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name
	}
	return out
}

func TestSortIsNewestFirstAndTotal(t *testing.T) {
	a := okEntry("a", at("2026-09-03T00:00:00Z"))
	b := okEntry("b", at("2026-09-02T06:00:00Z"))
	c := okEntry("c", at("2026-09-01T00:00:00Z"))
	// A newer row sorts by its collected_at when it parses (name stamp is older).
	n1 := Entry{Name: fileName("n1", at("2026-08-01T00:00:00Z")), Class: ClassNewer, SchemaVersion: facts.SchemaVersion + 1, CollectedAt: "2026-09-04T00:00:00Z"}
	// RA-10: a newer row whose collected_at does not parse sorts by its name stamp.
	n2 := Entry{Name: fileName("n2", at("2026-09-02T12:00:00Z")), Class: ClassNewer, SchemaVersion: facts.SchemaVersion + 1, CollectedAt: "2026-09-02T06:00:00+00:00"}
	u1 := Entry{Name: fileName("u1", at("2026-09-10T00:00:00Z")), Class: ClassUnreadable}
	u2 := Entry{Name: fileName("u2", at("2026-08-15T00:00:00Z")), Class: ClassUnreadable}
	// Same stamp as u2: the tie falls to the name.
	u0 := Entry{Name: fileName("u0", at("2026-08-15T00:00:00Z")), Class: ClassUnreadable}
	want := []string{u1.Name, n1.Name, a.Name, n2.Name, b.Name, c.Name, u0.Name, u2.Name}

	in := []Entry{c, u2, a, n2, u1, b, u0, n1}
	got := slices.Clone(in)
	Sort(got)
	if !slices.Equal(names(got), want) {
		t.Fatalf("Sort =\n%v\nwant\n%v", names(got), want)
	}
	for _, perm := range [][]Entry{
		{n1, u0, b, u1, n2, a, u2, c},
		{a, b, c, n1, n2, u0, u1, u2},
		{u2, u1, u0, n2, n1, c, b, a},
	} {
		p := slices.Clone(perm)
		Sort(p)
		if !slices.Equal(p, got) {
			t.Errorf("Sort of a permutation =\n%v\nwant\n%v", names(p), want)
		}
	}

	newest, ok := Newest(in)
	if !ok || newest.Name != a.Name {
		t.Errorf("Newest = %q, %v; want %q (the newest ok row, not the unreadable %q)", newest.Name, ok, a.Name, u1.Name)
	}
	if _, ok := Newest([]Entry{n1, u1}); ok {
		t.Error("Newest found an ok row among none")
	}
}

func TestPruneBounds(t *testing.T) {
	now := at("2026-10-01T00:00:00Z")
	day := 24 * time.Hour
	d1 := okEntry("h", now.Add(-1*day))
	d3 := okEntry("h", now.Add(-3*day))
	d7 := okEntry("h", now.Add(-7*day))
	d7s := okEntry("h", now.Add(-7*day-time.Second))
	d30 := okEntry("h", now.Add(-30*day))
	newer := Entry{Name: fileName("h", now.Add(-60*day)), Class: ClassNewer, SchemaVersion: facts.SchemaVersion + 1, CollectedAt: now.Add(-60 * day).Format("2006-01-02T15:04:05Z")}
	unreadable := Entry{Name: fileName("h", now.Add(-90*day)), Class: ClassUnreadable}
	entries := []Entry{d30, unreadable, d1, d7s, newer, d3, d7}

	for _, tc := range []struct {
		label string
		b     Bounds
		want  []Entry
	}{
		{"keep-days 7", Bounds{KeepDays: 7, HasKeepDays: true}, []Entry{d7s, d30}},
		{"keep 2", Bounds{Keep: 2, HasKeep: true}, []Entry{d7, d7s, d30}},
		{"keep 2 and keep-days 7", Bounds{Keep: 2, KeepDays: 7, HasKeep: true, HasKeepDays: true}, []Entry{d7s, d30}},
		{"keep 4 and keep-days 7", Bounds{Keep: 4, KeepDays: 7, HasKeep: true, HasKeepDays: true}, []Entry{d30}},
		{"keep 0", Bounds{Keep: 0, HasKeep: true}, []Entry{d3, d7, d7s, d30}},
		{"keep-days 0", Bounds{KeepDays: 0, HasKeepDays: true}, []Entry{d3, d7, d7s, d30}},
	} {
		got, err := Prune(slices.Clone(entries), tc.b, now)
		if err != nil {
			t.Errorf("%s: %v", tc.label, err)
			continue
		}
		if !slices.Equal(names(got), names(tc.want)) {
			t.Errorf("%s: Prune = %v, want %v", tc.label, names(got), names(tc.want))
		}
	}

	if _, err := Prune(entries, Bounds{}, now); !errors.Is(err, ErrNoBounds) {
		t.Errorf("no bounds: err = %v, want ErrNoBounds", err)
	}
	// RL-17: the newest ok snapshot is never a candidate.
	got, err := Prune([]Entry{d30, newer, unreadable}, Bounds{Keep: 0, HasKeep: true}, now)
	if err != nil || len(got) != 0 {
		t.Errorf("one ok row, keep 0: Prune = %v, %v; want nothing", names(got), err)
	}
}

func TestRepoint(t *testing.T) {
	now := at("2026-10-01T00:00:00Z")
	old := okEntry("h", now.Add(-48*time.Hour))
	recent := okEntry("h", now.Add(-time.Hour))
	newer := Entry{Name: fileName("h", now), Class: ClassNewer, SchemaVersion: facts.SchemaVersion + 1, CollectedAt: now.Format("2006-01-02T15:04:05Z")}
	unreadable := Entry{Name: fileName("h", now.Add(time.Hour)), Class: ClassUnreadable}
	if target, ok := Repoint([]Entry{newer, old, recent, unreadable}); !ok || target != recent.Name {
		t.Errorf("Repoint = %q, %v; want %q", target, ok, recent.Name)
	}
	if target, ok := Repoint([]Entry{newer, unreadable}); ok {
		t.Errorf("Repoint = %q, true; want false", target)
	}
}
