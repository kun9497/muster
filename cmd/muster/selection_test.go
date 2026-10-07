package main

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// resolveSelection on the built-in default selects the whole set: every id
// is known, none is excluded, and the provenance block says so.
func TestResolveSelectionDefaultSelectsTheWholeSet(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	var warnings []string
	sel, err := resolveSelection("default", nil, set, func(m string) { warnings = append(warnings, m) })
	if err != nil {
		t.Fatal(err)
	}
	if len(sel.Subset.Controls) != 117 || len(sel.Known) != 117 || len(sel.Excluded) != 0 {
		t.Errorf("subset %d, known %d, excluded %d; want 117, 117, 0", len(sel.Subset.Controls), len(sel.Known), len(sel.Excluded))
	}
	for _, c := range set.Controls {
		if !sel.Known[c.ID] {
			t.Errorf("%s is not known", c.ID)
		}
	}
	p := sel.Profile
	if p.Name != "default" || p.Source != "builtin" || p.Selected != 117 || p.Excluded != 0 || p.ExcludedIDs == nil || len(p.ExcludedIDs) != 0 {
		t.Errorf("profile block %+v", p)
	}
	if strings.Join(p.Extends, "|") != "builtin:default" || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Errorf("extends %v digest %q", p.Extends, p.Digest)
	}
	if sel.Tuning != nil {
		t.Errorf("tuning block %+v without a tuning file", sel.Tuning)
	}
	if len(sel.SeverityByID) != 0 {
		t.Errorf("severity %v from a profile with no severity entry", sel.SeverityByID)
	}
	if len(sel.Sources) == 0 || len(sel.Params) == 0 {
		t.Errorf("params %v / sources %v empty for a set that declares params", sel.Params, sel.Sources)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings %q", warnings)
	}
}

// A name that is no built-in is refused naming the built-ins (review focus 3).
func TestResolveSelectionRefusesAnUnknownName(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	sel, err := resolveSelection("Default", nil, set, func(string) {})
	if err == nil || sel != nil {
		t.Fatalf("sel %v err %v, want a refusal", sel, err)
	}
	if !strings.Contains(err.Error(), `unknown profile "Default"; the built-ins are default, kisa-unix-2026`) {
		t.Errorf("err %q", err)
	}
}
