package controls

import "testing"

func testSet() *Set {
	s := &Set{Version: "v", Digest: "sha256:d", Controls: []Control{
		{ID: "muster.account.a", Importance: "상"},
		{ID: "muster.beyond.b", Importance: "중", Params: map[string]Param{"n": {Type: "int", Default: 1}}},
		{ID: "muster.file.c", Importance: "하"},
	}}
	s.byID = map[string]int{}
	for i, c := range s.Controls {
		s.byID[c.ID] = i
	}
	return s
}

func TestSubsetKeepsOrderVersionDigestAndByID(t *testing.T) {
	s := testSet()
	sub := s.Subset([]string{"muster.file.c", "muster.account.a", "muster.no.such"})
	if got := len(sub.Controls); got != 2 {
		t.Fatalf("subset has %d controls, want 2", got)
	}
	if sub.Controls[0].ID != "muster.account.a" || sub.Controls[1].ID != "muster.file.c" {
		t.Errorf("subset order %q %q, want the set's order", sub.Controls[0].ID, sub.Controls[1].ID)
	}
	if sub.Version != s.Version || sub.Digest != s.Digest {
		t.Errorf("subset version/digest %q %q, want the full set's", sub.Version, sub.Digest)
	}
	if c, ok := sub.ByID("muster.file.c"); !ok || c.ID != "muster.file.c" {
		t.Errorf("ByID on the subset: %v %v", c, ok)
	}
	if _, ok := sub.ByID("muster.beyond.b"); ok {
		t.Errorf("ByID found an excluded control on the subset")
	}
	if len(s.Controls) != 3 {
		t.Errorf("Subset mutated the full set")
	}
}

func TestSubsetOfALiteralSetRebuildsTheIndex(t *testing.T) {
	s := &Set{Controls: []Control{{ID: "x"}, {ID: "y"}}} // byID nil, as tests build sets
	sub := s.Subset([]string{"y"})
	if c, ok := sub.ByID("y"); !ok || c.ID != "y" {
		t.Fatalf("ByID on a subset of a literal set: %v %v", c, ok)
	}
}
