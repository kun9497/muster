package profile

import (
	"slices"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

var cisNames = []string{"cis-rhel9-l1", "cis-ubuntu2204-l1", "cis-ubuntu2404-l1"}

// Every embedded built-in decodes strictly, names itself, and default still
// selects every control with no value and no severity of its own (CB-14).
func TestEmbeddedBuiltinsLoadStrictly(t *testing.T) {
	files, err := loadBuiltins()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for n, f := range files {
		names = append(names, n)
		if f.Profile != n {
			t.Errorf("builtin/%s.yaml names itself %q", n, f.Profile)
		}
		if f.Extends != "" {
			t.Errorf("builtin %s extends %q; a built-in is a chain root", n, f.Extends)
		}
	}
	slices.Sort(names)
	if want := append([]string{"default"}, cisNames...); !slices.Equal(names, sortedCopy(want)) {
		t.Errorf("embedded built-ins %v, want %v", names, want)
	}
	if got, want := Builtins(), []string{"default", "cis-rhel9-l1", "cis-ubuntu2204-l1", "cis-ubuntu2404-l1", "kisa-unix-2026"}; !slices.Equal(got, want) {
		t.Errorf("Builtins() = %v, want %v", got, want)
	}
	if d := files["default"]; !slices.Equal(d.Include, []string{"muster.*"}) || len(d.Exclude) != 0 || len(d.Params) != 0 || len(d.Severity) != 0 {
		t.Errorf("default is %+v, want include [muster.*] and nothing else", d)
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default", "kisa-unix-2026"} {
		r, err := Resolve(set, Source{Name: name}, neverOpenT(t), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.IDs) != len(set.Controls) || len(r.Params) != 0 || len(r.Severity) != 0 || r.Name != "default" {
			t.Errorf("%s resolves to %d of %d ids, params %v, severity %v, name %q", name, len(r.IDs), len(set.Controls), r.Params, r.Severity, r.Name)
		}
		if !slices.Equal(r.Chain, []string{"builtin:default"}) {
			t.Errorf("%s chain %v", name, r.Chain)
		}
	}
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	slices.Sort(out)
	return out
}

// Each CIS built-in resolves against the shipped set, selects exactly its
// include list, and every value it sets is one its control's type accepts.
func TestCISBuiltinsResolveWithTheirParams(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range cisNames {
		f, ok := Builtin(name)
		if !ok {
			t.Fatalf("Builtin(%q) not found", name)
		}
		r, err := Resolve(set, Source{Name: name}, neverOpenT(t), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.Name != name || !slices.Equal(r.Chain, []string{"builtin:" + name}) || r.Source != "builtin" {
			t.Errorf("%s: name %q chain %v source %q", name, r.Name, r.Chain, r.Source)
		}
		if !slices.Equal(r.IDs, sortedCopy(f.Include)) {
			t.Errorf("%s: resolves to %v, its include is %v", name, r.IDs, f.Include)
		}
		if len(r.IDs) == 0 || len(r.IDs) >= len(set.Controls) {
			t.Errorf("%s selects %d of %d controls", name, len(r.IDs), len(set.Controls))
		}
		for id, ps := range f.Params {
			c, ok := set.ByID(id)
			if !ok {
				t.Errorf("%s: params name %s, which is no control", name, id)
				continue
			}
			for p, v := range ps {
				decl, ok := c.Params[p]
				if !ok {
					t.Errorf("%s: %s has no parameter %s", name, id, p)
					continue
				}
				if err := controls.CheckParamValue(decl.Type, v); err != nil {
					t.Errorf("%s: %s.%s: %v", name, id, p, err)
				}
			}
		}
	}
}

func TestCISBenchmarkTable(t *testing.T) {
	want := map[string]CIS{
		"cis-ubuntu2204-l1": {Profile: "cis-ubuntu2204-l1", Benchmark: "ubuntu2204", Targets: []string{"ubuntu2204"}},
		"cis-ubuntu2404-l1": {Profile: "cis-ubuntu2404-l1", Benchmark: "ubuntu2404", Targets: []string{"ubuntu2404"}},
		"cis-rhel9-l1":      {Profile: "cis-rhel9-l1", Benchmark: "rhel9", Targets: []string{"rhel9", "alma9", "rocky9"}},
	}
	for name, w := range want {
		got, ok := CISBenchmark(name)
		if !ok || got.Profile != w.Profile || got.Benchmark != w.Benchmark || !slices.Equal(got.Targets, w.Targets) {
			t.Errorf("CISBenchmark(%q) = %+v, %v; want %+v", name, got, ok, w)
		}
		if _, isBuiltin := Builtin(name); !isBuiltin {
			t.Errorf("%s is in the CIS table but is no embedded built-in", name)
		}
	}
	for _, name := range []string{"default", "kisa-unix-2026", "cis-rhel8-l1", ""} {
		if got, ok := CISBenchmark(name); ok {
			t.Errorf("CISBenchmark(%q) = %+v, want not found", name, got)
		}
	}
	// The chain root decides (CB-11): a file extending a CIS built-in is
	// that built-in's, a file root or default is none.
	if c, ok := CISRoot([]string{"builtin:cis-rhel9-l1", "file:site.yaml"}); !ok || c.Benchmark != "rhel9" {
		t.Errorf("CISRoot over an extending file = %+v, %v", c, ok)
	}
	for _, chain := range [][]string{nil, {"builtin:default"}, {"file:cis-rhel9-l1"}, {"file:a.yaml", "builtin:cis-rhel9-l1"}} {
		if c, ok := CISRoot(chain); ok {
			t.Errorf("CISRoot(%v) = %+v, want not found", chain, c)
		}
	}
}

func TestCISMatches(t *testing.T) {
	u22, _ := CISBenchmark("cis-ubuntu2204-l1")
	u24, _ := CISBenchmark("cis-ubuntu2404-l1")
	el9, _ := CISBenchmark("cis-rhel9-l1")
	cases := []struct {
		id, version   string
		u22, u24, el9 bool
	}{
		{"ubuntu", "22.04", true, false, false},
		{"ubuntu", "24.04", false, true, false},
		{"rhel", "9.4", false, false, true},
		{"rocky", "9.3", false, false, true},
		{"almalinux", "9", false, false, true},
		{"centos", "9", false, false, false},
		{"rhel", "8.9", false, false, false},
		{"rhel", "90", false, false, false},
		{"Ubuntu", "22.04", false, false, false},
		{"ubuntu", "", false, false, false},
		{"", "", false, false, false},
	}
	for _, c := range cases {
		if got := u22.Matches(c.id, c.version); got != c.u22 {
			t.Errorf("ubuntu2204 matches %q %q = %v", c.id, c.version, got)
		}
		if got := u24.Matches(c.id, c.version); got != c.u24 {
			t.Errorf("ubuntu2404 matches %q %q = %v", c.id, c.version, got)
		}
		if got := el9.Matches(c.id, c.version); got != c.el9 {
			t.Errorf("rhel9 matches %q %q = %v", c.id, c.version, got)
		}
	}
}
