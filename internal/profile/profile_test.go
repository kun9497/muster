package profile

import "testing"

func TestSourceOf(t *testing.T) {
	cases := map[string]Source{
		"default":          {Name: "default"},
		"kisa-unix-2026":   {Name: "kisa-unix-2026"},
		"Default":          {Name: "Default"},
		"site_web":         {Name: "site_web"},
		"kisa.unix.2026":   {Name: "kisa.unix.2026"},
		"site.yaml":        {Path: "site.yaml"},
		"b.yml":            {Path: "b.yml"},
		"a/b.yaml":         {Path: "a/b.yaml"},
		"./site":           {Path: "./site"},
		`C:\muster\p.yaml`: {Path: `C:\muster\p.yaml`},
		"profiles\\x":      {Path: "profiles\\x"},
	}
	for in, want := range cases {
		if got := SourceOf(in); got != want {
			t.Errorf("SourceOf(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestParseIsStrict(t *testing.T) {
	if _, err := Parse([]byte("profile: a\ninclude: [x]\nincldue: [y]\n")); err == nil {
		t.Errorf("an unknown key parsed")
	}
	f, err := Parse([]byte("profile: a\nseverity:\n  - { controls: \"muster.*\", level: low }\n"))
	if err != nil || f.Profile != "a" || len(f.Severity) != 1 || f.Severity[0].Level != "low" {
		t.Errorf("Parse: %+v %v", f, err)
	}
}
