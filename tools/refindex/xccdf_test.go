package main

import (
	"os"
	"testing"
)

func TestParseXCCDFCollectsRulesInStigIDOrder(t *testing.T) {
	data, err := os.ReadFile("testdata/mini-xccdf.xml")
	if err != nil {
		t.Fatal(err)
	}
	bench, err := parseXCCDF(data)
	if err != nil {
		t.Fatal(err)
	}
	if bench.ReleaseInfo != "Release: 1 Benchmark Date: 01 Jan 2026" {
		t.Errorf("release info %q", bench.ReleaseInfo)
	}
	if len(bench.Rules) != 2 || bench.Rules[0].StigID != "MINI-00-000010" || bench.Rules[1].StigID != "MINI-00-000020" {
		t.Fatalf("rules %+v", bench.Rules)
	}
	r := bench.Rules[1]
	if r.GroupID != "V-000002" || r.RuleID != "SV-000002r2_rule" || r.Severity != "medium" || r.Title != "Second rule" {
		t.Errorf("rule %+v", r)
	}
	if len(r.CCIs) != 2 || r.CCIs[0] != "CCI-000068" || r.CCIs[1] != "CCI-000366" {
		t.Errorf("ccis %v", r.CCIs)
	}
}

func TestParseXCCDFRejectsARuleWithoutAStigID(t *testing.T) {
	bad := `<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><Group id="V-1"><Rule id="SV-1_rule" severity="low"><title>t</title></Rule></Group></Benchmark>`
	if _, err := parseXCCDF([]byte(bad)); err == nil {
		t.Error("a rule without <version> (the STIG id) must be an error")
	}
}
