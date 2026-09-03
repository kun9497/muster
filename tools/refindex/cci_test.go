package main

import (
	"os"
	"strings"
	"testing"
)

func TestParseCCIPrefersRevision5ThenFallsBack(t *testing.T) {
	data, err := os.ReadFile("testdata/mini-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseCCI(data)
	if err != nil {
		t.Fatal(err)
	}
	if list.Version != "2025-01-23" {
		t.Errorf("version %q", list.Version)
	}
	if got := list.NIST["CCI-000068"]; len(got) != 1 || got[0] != "AC-17(2)" {
		t.Errorf("CCI-000068 → %v, want [AC-17(2)] from Revision 5", got)
	}
	if got := list.NIST["CCI-000366"]; len(got) != 1 || got[0] != "CM-6" {
		t.Errorf("CCI-000366 → %v, want [CM-6] from Revision 4 with the paragraph letter dropped", got)
	}
}

func TestNistIDNormalisation(t *testing.T) {
	cases := map[string]string{"AC-6 (10)": "AC-6(10)", "CM-6 b": "CM-6", "AC-1 a 1": "AC-1", "IA-5 (1) (c)": "IA-5(1)", "SC-8": "SC-8", "garbage": ""}
	for in, want := range cases {
		if got := nistID(in); got != want {
			t.Errorf("nistID(%q) = %q, want %q", in, got, want)
		}
	}
}

// A CCI a rule cites but the pinned CCI list does not define yields an empty
// "nist" array that looks exactly like a rule with no NIST mapping, so the
// tally is what tells the two apart. It is returned, not printed, so this
// test does not have to scrape stderr.
func TestUnresolvedCCIsTalliesMissingIDs(t *testing.T) {
	x, err := os.ReadFile("testdata/mini-xccdf-unknown-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile("testdata/mini-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	bench, err := parseXCCDF(x)
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseCCI(c)
	if err != nil {
		t.Fatal(err)
	}
	got := unresolvedCCIs(bench, list)
	// CCI-999999 is cited by both rules and must be reported once;
	// CCI-000366 is in the list and must not be reported at all.
	if len(got) != 2 || got[0] != "CCI-888888" || got[1] != "CCI-999999" {
		t.Errorf("unresolvedCCIs = %v, want sorted de-duplicated [CCI-888888 CCI-999999]", got)
	}
}

func TestUnresolvedCCIsIsEmptyWhenEveryCCIResolves(t *testing.T) {
	x, err := os.ReadFile("testdata/mini-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile("testdata/mini-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	bench, err := parseXCCDF(x)
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseCCI(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := unresolvedCCIs(bench, list); len(got) != 0 {
		t.Errorf("unresolvedCCIs = %v, want none", got)
	}
}

func TestIndexJSONIsDeterministic(t *testing.T) {
	x, err := os.ReadFile("testdata/mini-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile("testdata/mini-cci.xml")
	if err != nil {
		t.Fatal(err)
	}
	bench, err := parseXCCDF(x)
	if err != nil {
		t.Fatal(err)
	}
	list, err := parseCCI(c)
	if err != nil {
		t.Fatal(err)
	}
	src := source{Product: "mini", Benchmark: "Mini", Version: "V1R1", URL: "u", SHA256: "s", Member: "m"}
	a, err := renderIndex(src, bench, list, "cci-sha")
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderIndex(src, bench, list, "cci-sha")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("renderIndex must be deterministic")
	}
	if !strings.Contains(string(a), `"nist": [
        "AC-17(2)",
        "CM-6"
      ]`) {
		t.Errorf("rule nist union missing or unsorted:\n%s", a)
	}
	if a[len(a)-1] != '\n' {
		t.Error("output must end with a newline")
	}
}
