package controls_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kun9497/muster/internal/controls"
)

type roundtripEntry struct {
	ID            string            `yaml:"id"`
	Images        []string          `yaml:"images"`
	UnprovenUnits map[string]string `yaml:"unproven_units"`
	Unproven      string            `yaml:"unproven"`
}

type matrixRow struct {
	Key, Image, Init, Seeded, Build string
}

func TestEveryScriptedControlIsInTheRoundtripTable(t *testing.T) {
	raw, err := os.ReadFile(fixtureRoot + "/_roundtrip.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var table []roundtripEntry
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&table); err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []matrixRow `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(ci, &wf); err != nil {
		t.Fatal(err)
	}
	rows := wf.Jobs["fix-roundtrip"].Strategy.Matrix.Include
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	scripted := map[string]*controls.Remediation{}
	for i := range set.Controls {
		if r := set.Controls[i].Remediation; r != nil && strings.TrimSpace(r.Script) != "" {
			scripted[set.Controls[i].ID] = r
		}
	}
	// sorted, exactly the scripted ids, images xor unproven, unproven_units keys declared
	ids := make([]string, len(table))
	for i, e := range table {
		ids[i] = e.ID
		if (len(e.Images) == 0) == (e.Unproven == "") {
			t.Errorf("%s: needs images or unproven, not both or neither", e.ID)
		}
		if len(e.UnprovenUnits) > 0 && len(e.Images) == 0 {
			t.Errorf("%s: unproven_units without images", e.ID)
		}
		r := scripted[e.ID]
		for u := range e.UnprovenUnits {
			if r == nil || !contains(r.Units, u) {
				t.Errorf("%s: unproven unit %s is not declared", e.ID, u)
			}
		}
		seen := map[string]bool{}
		for _, k := range e.Images {
			if seen[k] {
				t.Errorf("%s: image %s repeated", e.ID, k)
			}
			seen[k] = true
		}
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Errorf("table not strictly sorted by id at %s", ids[i])
		}
	}
	for id := range scripted {
		if !contains(ids, id) {
			t.Errorf("%s: scripted control missing from the table", id)
		}
	}
	if len(ids) != len(scripted) {
		t.Errorf("table has %d ids, set has %d scripted", len(ids), len(scripted))
	}
	for _, id := range ids {
		if scripted[id] == nil {
			t.Errorf("%s: in the table, not a scripted control", id)
		}
	}
	keys := map[string]matrixRow{}
	for _, r := range rows {
		if r.Key == "" || strings.TrimSpace(r.Seeded) == "" {
			t.Errorf("matrix row %q: needs key and seeded", r.Image)
		}
		keys[r.Key] = r
	}
	for _, e := range table {
		for _, k := range e.Images {
			r, ok := keys[k]
			if !ok {
				t.Errorf("%s: image %s is no matrix row's key", e.ID, k)
			}
			if strings.HasPrefix(e.ID, "muster.service.") && r.Init == "false" {
				t.Errorf("%s: service control on non-init row %s", e.ID, k)
			}
		}
	}
	for k, r := range keys {
		want := map[string]bool{}
		for _, e := range table {
			if contains(e.Images, k) {
				want[e.ID] = true
			}
		}
		got := map[string]bool{}
		for _, id := range strings.Fields(r.Seeded) {
			got[id] = true
		}
		if len(got) != len(want) {
			t.Errorf("row %s: seeded %v, table %v", k, got, want)
		}
		for id := range want {
			if !got[id] {
				t.Errorf("row %s: table names %s, seeded does not", k, id)
			}
		}
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
