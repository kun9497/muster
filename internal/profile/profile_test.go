package profile

import (
	"errors"
	"testing"
)

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

// Fix wave item 4: one YAML document per file. A second document used to be
// ignored without a word; it refuses the file now, through Parse and through
// the chain, which names the path.
func TestParseRefusesASecondDocument(t *testing.T) {
	two := "profile: a\ninclude: [\"muster.*\"]\n---\nprofile: second\nbogus: 1\n"
	f, err := Parse([]byte(two))
	if f != nil || !errors.Is(err, ErrInvalid) || err.Error() != "invalid profile: more than one YAML document" {
		t.Errorf("Parse: %+v %v, want the second document refused", f, err)
	}
	_, err = Resolve(set(), Source{Path: "p.yaml"}, files(map[string]string{"p.yaml": two}), noWarn(t))
	if !errors.Is(err, ErrInvalid) || err.Error() != "invalid profile: p.yaml: more than one YAML document" {
		t.Errorf("Resolve: %v, want the path and the second document named", err)
	}
	for _, one := range []string{"", "---\n", "# only a comment\n", "---\nprofile: a\n"} {
		if _, err := Parse([]byte(one)); err != nil {
			t.Errorf("Parse(%q): %v, want one document accepted", one, err)
		}
	}
}
