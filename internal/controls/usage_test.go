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

// M-3: UnusedKeys stays as a wrapper, so the note the CLI prints and the
// table tools/coverage renders can never disagree about what is unused.
func TestUnusedKeysIsDerivedFromFactUsage(t *testing.T) {
	// alpha.k sits between the two zeta keys, so a wrapper that walks the
	// registry itself and one that concatenates the per-collector lists
	// produce different orders -- this pins the second.
	reg := doubleRegistry(
		facts.Entry{Key: "zeta.cited", Collector: "zeta"},
		facts.Entry{Key: "alpha.k", Collector: "alpha"},
		facts.Entry{Key: "zeta.other", Collector: "zeta"},
	)
	set := &Set{Controls: []Control{{
		ID:     "muster.file.double",
		Checks: []Clause{{Fact: "zeta.cited", Op: "present"}},
	}}}
	if got, want := UnusedKeys(set, reg), []string{"zeta.other", "alpha.k"}; !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedKeys = %v, want %v (the per-collector lists in order)", got, want)
	}

	realSet, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	realReg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, u := range FactUsage(realSet, realReg) {
		want = append(want, u.Unused...)
	}
	if got := UnusedKeys(realSet, realReg); !reflect.DeepEqual(got, want) {
		t.Errorf("UnusedKeys must be the concatenation of every CollectorUsage.Unused:\ngot  %v\nwant %v", got, want)
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
