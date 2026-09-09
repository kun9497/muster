package controls

import (
	"reflect"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// doubleRegistry is a registry built by hand rather than loaded: FactUsage
// reads Keys and nothing else, so a double can put two collectors in an
// order alphabetical sorting would reverse and interleave a third, which is
// what pins "registry order of first appearance".
func doubleRegistry(keys ...facts.Entry) *facts.Registry {
	return &facts.Registry{Keys: keys}
}

func TestFactUsagePerCollectorInRegistryOrder(t *testing.T) {
	reg := doubleRegistry(
		facts.Entry{Key: "zeta.cited", Collector: "zeta"},
		facts.Entry{Key: "walk.complete", Collector: "walk"},
		facts.Entry{Key: "zeta.other", Collector: "zeta"},
		facts.Entry{Key: "zeta.another", Collector: "zeta"},
		facts.Entry{Key: "alpha.k", Collector: "alpha"},
	)
	set := &Set{Controls: []Control{{
		ID:     "muster.file.double",
		Checks: []Clause{{Fact: "zeta.cited", Op: "eq", Expected: "x"}},
	}}}
	want := []CollectorUsage{
		{Collector: "zeta", Registered: 3, Used: 1, Engine: 0, Unused: []string{"zeta.other", "zeta.another"}},
		{Collector: "walk", Registered: 1, Used: 0, Engine: 1},
		{Collector: "alpha", Registered: 1, Used: 0, Engine: 0, Unused: []string{"alpha.k"}},
	}
	got := FactUsage(set, reg)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FactUsage =\n%#v\nwant\n%#v", got, want)
	}
	// walk.complete is read by the engine, so no control file could ever
	// make it disappear from an unused list; it must not be in one.
	for _, u := range got {
		for _, k := range u.Unused {
			if k == "walk.complete" {
				t.Errorf("%s: an engine-read key must not be reported as unused", k)
			}
		}
	}
	// Used + Engine + Unused accounts for every registered key, which is
	// what makes the summary line of the report add up.
	for _, u := range got {
		if u.Used+u.Engine+len(u.Unused) != u.Registered {
			t.Errorf("%s: %d used + %d engine + %d unused != %d registered", u.Collector, u.Used, u.Engine, len(u.Unused), u.Registered)
		}
	}

	// M-41: a key a control names is used by definition, whatever else
	// reads it. Engine counts what no control cites, or the headline claim
	// "facts used, not facts collected" would under-count the facts used.
	cites := &Set{Controls: []Control{{
		ID:     "muster.file.cites_an_engine_key",
		Checks: []Clause{{Fact: "walk.complete", Op: "present"}},
	}}}
	engineReg := doubleRegistry(facts.Entry{Key: "walk.complete", Collector: "walk"})
	wantCited := []CollectorUsage{{Collector: "walk", Registered: 1, Used: 1, Engine: 0}}
	if got := FactUsage(cites, engineReg); !reflect.DeepEqual(got, wantCited) {
		t.Errorf("a control citing an engine-read key: FactUsage =\n%#v\nwant\n%#v", got, wantCited)
	}
}

// M-3/LOW-5: both renderers state the same three numbers, so they read them
// from one place rather than each folding the slice again.
func TestTotalsSumsEveryCollector(t *testing.T) {
	registered, used, engine := Totals([]CollectorUsage{
		{Collector: "a", Registered: 5, Used: 3, Engine: 1, Unused: []string{"a.k"}},
		{Collector: "b", Registered: 2, Used: 0, Engine: 0, Unused: []string{"b.k", "b.j"}},
	})
	if registered != 7 || used != 3 || engine != 1 {
		t.Errorf("Totals = (%d, %d, %d), want (7, 3, 1)", registered, used, engine)
	}
	if r, u, e := Totals(nil); r != 0 || u != 0 || e != 0 {
		t.Errorf("Totals(nil) = (%d, %d, %d), want zeroes", r, u, e)
	}
}

// A control names facts in four places besides checks, and a manual control
// names them in evidence instead of judging them (M-8). All five count as
// use: a key a reviewer is handed is not an unused key.
func TestFactUsageCountsEveryPlaceAControlNamesAFact(t *testing.T) {
	reg := doubleRegistry(
		facts.Entry{Key: "a.applies", Collector: "a"},
		facts.Entry{Key: "a.check", Collector: "a"},
		facts.Entry{Key: "a.when", Collector: "a"},
		facts.Entry{Key: "a.mech", Collector: "a"},
		facts.Entry{Key: "a.evidence", Collector: "a"},
		facts.Entry{Key: "a.nobody", Collector: "a"},
	)
	set := &Set{Controls: []Control{
		{
			ID:          "muster.file.places",
			AppliesWhen: ClauseList{{Fact: "a.applies", Op: "present"}},
			Checks:      []Clause{{Fact: "a.check", Op: "present"}},
			Mechanisms: []Mechanism{{
				When:   ClauseList{{Fact: "a.when", Op: "present"}},
				Checks: []Clause{{Fact: "a.mech", Op: "present"}},
			}},
		},
		{ID: "muster.file.manual", Automation: "manual", Evidence: []string{"a.evidence"}},
	}}
	got := FactUsage(set, reg)
	if len(got) != 1 {
		t.Fatalf("one collector, got %#v", got)
	}
	if got[0].Used != 5 {
		t.Errorf("Used = %d, want 5 (applies_when, checks, mechanism when and checks, evidence)", got[0].Used)
	}
	if !reflect.DeepEqual(got[0].Unused, []string{"a.nobody"}) {
		t.Errorf("Unused = %v, want [a.nobody]", got[0].Unused)
	}
}

// M-3/M-40: UnusedKeys stays a wrapper over FactUsage, so the note the CLI
// prints and the table tools/coverage renders can never disagree about what
// is unused -- but it answers in registry order (spec §5.5), not in the
// report's per-collector order.
func TestUnusedKeysIsDerivedFromFactUsage(t *testing.T) {
	// alpha.k sits between the two zeta keys, so registry order and the
	// concatenation of the per-collector lists differ: registry order is
	// [alpha.k, zeta.other], the grouped order [zeta.other, alpha.k].
	reg := doubleRegistry(
		facts.Entry{Key: "zeta.cited", Collector: "zeta"},
		facts.Entry{Key: "alpha.k", Collector: "alpha"},
		facts.Entry{Key: "zeta.other", Collector: "zeta"},
	)
	set := &Set{Controls: []Control{{
		ID:     "muster.file.double",
		Checks: []Clause{{Fact: "zeta.cited", Op: "present"}},
	}}}
	if got, want := UnusedKeys(set, reg), []string{"alpha.k", "zeta.other"}; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedKeys = %v, want %v (registry order, spec §5.5)", got, want)
	}

	realSet, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	realReg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	// The same keys the report calls unused, no more and no fewer...
	fromReport := map[string]bool{}
	total := 0
	for _, u := range FactUsage(realSet, realReg) {
		for _, k := range u.Unused {
			fromReport[k] = true
			total++
		}
	}
	got := UnusedKeys(realSet, realReg)
	if len(got) != total {
		t.Errorf("UnusedKeys lists %d keys, the report %d", len(got), total)
	}
	for _, k := range got {
		if !fromReport[k] {
			t.Errorf("%s is not in any CollectorUsage.Unused", k)
		}
	}
	// ...in the order the registry lists them. The real registry mentions
	// files and services twice each, so this is not the grouped order.
	at := map[string]int{}
	for i, e := range realReg.Keys {
		at[e.Key] = i
	}
	prev := -1
	for _, k := range got {
		if at[k] <= prev {
			t.Fatalf("UnusedKeys is not in registry order: %s comes at %d, after %d", k, at[k], prev)
		}
		prev = at[k]
	}
}

// The report is only worth reading if it covers the real registry: every
// registered key belongs to exactly one collector row, and the totals add up.
func TestFactUsageCoversTheWholeRegistry(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	usage := FactUsage(set, reg)
	seen := map[string]bool{}
	total := 0
	for _, u := range usage {
		if seen[u.Collector] {
			t.Errorf("collector %s has two rows", u.Collector)
		}
		seen[u.Collector] = true
		total += u.Registered
	}
	if total != len(reg.Keys) {
		t.Errorf("rows account for %d keys, registry has %d", total, len(reg.Keys))
	}
	if usage[0].Collector != reg.Keys[0].Collector {
		t.Errorf("first row is %s, want the first collector of the registry (%s)", usage[0].Collector, reg.Keys[0].Collector)
	}
}
