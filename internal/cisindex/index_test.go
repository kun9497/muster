package cisindex

import (
	"reflect"
	"strings"
	"testing"
)

func sampleIndex() *Index {
	return &Index{
		Product: "ubuntu2204", Benchmark: "synthetic", Version: "v1",
		Source: Pin{Repo: "r", Tag: "t", Commit: "c", Path: "p", SHA256: "s"},
		Counts: Counts{L1Server: 3},
		Recs:   []Row{{Rec: "1.1.1", Levels: []string{"level_1_server"}, Controls: []string{"muster.a"}, Rules: "all"}},
	}
}

func TestIndexRoundTrip(t *testing.T) {
	ix := sampleIndex()
	out, err := RenderIndex(ix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\"applies_to\": []") || strings.Contains(string(out), "equal_to") || !strings.HasSuffix(string(out), "}\n") {
		t.Fatalf("render:\n%s", out)
	}
	got, err := DecodeIndex(out)
	if err != nil {
		t.Fatal(err)
	}
	ix.AppliesTo = []string{}
	if !reflect.DeepEqual(got, ix) {
		t.Errorf("got %+v want %+v", got, ix)
	}
	ix.EqualTo = &EqualTo{Path: "p", SHA256: "s", Compared: "ids"}
	out2, _ := RenderIndex(ix)
	if !strings.Contains(string(out2), "equal_to") {
		t.Error("equal_to missing")
	}
}

func TestDecodeIndexIsStrict(t *testing.T) {
	good, _ := RenderIndex(sampleIndex())
	g := string(good)
	cases := map[string]string{
		"title":    strings.Replace(g, "\"rec\": \"1.1.1\",", "\"rec\": \"1.1.1\", \"title\": \"x\",", 1),
		"word":     strings.Replace(g, "\"all\"", "\"full\"", 1),
		"badrec":   strings.Replace(g, "\"1.1.1\"", "\"x\"", 1),
		"noprod":   strings.Replace(g, "\"ubuntu2204\"", "\"\"", 1),
		"trailing": g + "{}",
	}
	for name, c := range cases {
		if _, err := DecodeIndex([]byte(c)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := DecodeIndex(good); err != nil {
		t.Errorf("good refused: %v", err)
	}
}
