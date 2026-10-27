package controls

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/cisindex"
)

// TestEveryCISReferenceIsTheIndex holds every control's references.cis equal
// to the rendering of the committed CIS index (CB-9, CB-12): one entry per
// index row naming the control, sorted by product then by rec compared
// component-wise. On a difference it prints the expected block.
func TestEveryCISReferenceIsTheIndex(t *testing.T) {
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	idx, err := LoadReferenceIndex("../../docs/reference")
	if err != nil {
		t.Fatal(err)
	}
	products := []string{"rhel9", "ubuntu2204", "ubuntu2404"}
	want := map[string][]CISRef{}
	for _, p := range products {
		if idx.CISVersion(p) == "" {
			t.Fatalf("the index has no product %s", p)
		}
		for _, row := range idx.CISRows(p) {
			for _, id := range row.Controls {
				want[id] = append(want[id], CISRef{Benchmark: p, Version: idx.CISVersion(p), Rec: row.Rec})
			}
		}
	}
	for id, refs := range want {
		if _, ok := set.ByID(id); !ok {
			t.Errorf("the index names %s, which is not a shipped control", id)
		}
		sort.SliceStable(refs, func(i, j int) bool {
			if refs[i].Benchmark != refs[j].Benchmark {
				return refs[i].Benchmark < refs[j].Benchmark
			}
			return cisindex.CompareRec(refs[i].Rec, refs[j].Rec) < 0
		})
	}
	for _, c := range set.Controls {
		exp := want[c.ID]
		got := c.References.CIS
		if len(exp) == len(got) {
			same := true
			for i := range exp {
				if exp[i] != got[i] {
					same = false
				}
			}
			if same {
				continue
			}
		}
		var b strings.Builder
		if len(exp) > 0 {
			b.WriteString("  cis:\n")
			for _, r := range exp {
				fmt.Fprintf(&b, "    - { benchmark: %s, version: %q, rec: %q }\n", r.Benchmark, r.Version, r.Rec)
			}
		}
		t.Errorf("%s: references.cis is not the index's rendering; expected block:\n@@ %s\n%s@@ end", c.ID, c.ID, b.String())
	}
}
