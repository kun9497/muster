package cisindex

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const sampleYAML = `
policy: Synthetic
title: SYNTHETIC POLICY TITLE
version: 'v1.0.0'
controls:
  - id: 1.1.1
    title: SYNTHETIC TITLE ONE
    status: automated
    notes: SYNTHETIC NOTE
    related_rules: [x]
    levels: [level_1_server, level_1_workstation]
    rules:
      - kernel_module_cramfs_disabled
      - var_x=14
  - id: 1.1.2
    title: SYNTHETIC TITLE TWO
    levels: [level_2_server]
    rules: []
`

func TestDecodeControlsKeepsOnlyIdsLevelsRules(t *testing.T) {
	src, err := DecodeControls([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	if src.Version != "v1.0.0" || len(src.Entries) != 2 {
		t.Fatalf("got %+v", src)
	}
	e := src.Entries[0]
	if e.ID != "1.1.1" || !reflect.DeepEqual(e.Levels, []string{"level_1_server", "level_1_workstation"}) ||
		!reflect.DeepEqual(e.Rules, []string{"kernel_module_cramfs_disabled"}) {
		t.Fatalf("entry %+v", e)
	}
	s := fmt.Sprintf("%+v", src)
	for _, bad := range []string{"SYNTHETIC TITLE", "SYNTHETIC NOTE", "SYNTHETIC POLICY", "automated"} {
		if strings.Contains(s, bad) {
			t.Errorf("decoded source holds %q", bad)
		}
	}
}

func TestDecodeControlsDropsHelpers(t *testing.T) {
	src, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: reload_dconf_db\n    rules: [a]\n  - id: enable_authselect\n  - id: 1.1.1\n    levels: [l]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Entries) != 1 || src.Entries[0].ID != "1.1.1" {
		t.Fatalf("got %+v", src.Entries)
	}
}

func TestDecodeControlsSplitsSelections(t *testing.T) {
	src, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: '1.2'\n    rules: [a_rule, var_x=14, sshd_idle_timeout_value=5_minutes, a_rule]\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := src.Entries[0]
	if !reflect.DeepEqual(e.Rules, []string{"a_rule"}) {
		t.Errorf("rules %v", e.Rules)
	}
	want := []Selection{{"var_x", "14"}, {"sshd_idle_timeout_value", "5_minutes"}}
	if !reflect.DeepEqual(e.Selections, want) {
		t.Errorf("selections %v", e.Selections)
	}
}

func TestDecodeControlsRefusesBadInput(t *testing.T) {
	for _, bad := range []string{`"Bad Rule"`, `"=x"`, `"A_b"`} {
		if _, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: '1.2'\n    rules: [" + bad + "]\n")); err == nil {
			t.Errorf("rule %s accepted", bad)
		}
	}
	if _, err := DecodeControls([]byte("controls:\n  - id: '1.2'\n")); err == nil {
		t.Error("missing version accepted")
	}
	if _, err := DecodeControls([]byte("version: v1\ncontrols:\n  - rules: [a]\n")); err == nil {
		t.Error("entry without id accepted")
	}
}

func TestValidRuleIDAdmitsHyphens(t *testing.T) {
	if !ValidRuleID("kernel_module_usb-storage_disabled") {
		t.Error("hyphen refused")
	}
	for _, s := range []string{"var=1", "-x", "A_b", ""} {
		if ValidRuleID(s) {
			t.Errorf("%q admitted", s)
		}
	}
}

func TestValidRec(t *testing.T) {
	for _, s := range []string{"1.1", "5.1.7", "1.2.3.4.5"} {
		if !ValidRec(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"1", "1.2.3.4.5.6", "a.b", "1..2", "reload_dconf_db", ""} {
		if ValidRec(s) {
			t.Errorf("%q admitted", s)
		}
	}
}

func TestCompareRec(t *testing.T) {
	if CompareRec("5.1.7", "5.1.20") >= 0 || CompareRec("1.10", "1.9") <= 0 || CompareRec("2.1", "2.1") != 0 {
		t.Error("compare order")
	}
	if CompareRec("1.2", "1.2.1") >= 0 {
		t.Error("prefix must sort first")
	}
}

func TestSameIDsAndLevels(t *testing.T) {
	a := &Source{Entries: []Entry{{ID: "1.1", Levels: []string{"l1"}, Rules: []string{"x"}}}}
	b := &Source{Entries: []Entry{{ID: "1.1", Levels: []string{"l1"}, Rules: []string{"y"}}}}
	if err := SameIDsAndLevels(a, b); err != nil {
		t.Errorf("rules differ only: %v", err)
	}
	b.Entries[0].Levels = []string{"l2"}
	if err := SameIDsAndLevels(a, b); err == nil || !strings.Contains(err.Error(), "1.1") {
		t.Errorf("level difference: %v", err)
	}
	b.Entries[0].ID = "1.2"
	if err := SameIDsAndLevels(a, b); err == nil || !strings.Contains(err.Error(), "1.") {
		t.Errorf("id difference: %v", err)
	}
}

func TestHasLevelAndRuleUnion(t *testing.T) {
	e := Entry{Levels: []string{"a", "b"}}
	if !HasLevel(e, "b") || HasLevel(e, "c") {
		t.Error("HasLevel")
	}
	u := RuleUnion(&Source{Entries: []Entry{{Rules: []string{"x"}}}}, &Source{Entries: []Entry{{Rules: []string{"y", "x"}}}})
	if len(u) != 2 || !u["x"] || !u["y"] {
		t.Errorf("union %v", u)
	}
}

func TestDecodeControlsRefusesDuplicateIDs(t *testing.T) {
	_, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: '1.2'\n  - id: 1.3\n  - id: '1.2'\n"))
	if err == nil || !strings.Contains(err.Error(), "1.2") {
		t.Fatalf("duplicate id: %v", err)
	}
}

func TestDecodeControlsRefusesBadSelections(t *testing.T) {
	for _, bad := range []string{`"A=1"`, `"a b=1"`, `"x="`, `"-x=1"`} {
		if _, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: '1.2'\n    rules: [" + bad + "]\n")); err == nil {
			t.Errorf("selection %s accepted", bad)
		}
	}
	if _, err := DecodeControls([]byte("version: v1\ncontrols:\n  - id: '1.2'\n    rules: [var_x=a=b]\n")); err != nil {
		t.Errorf("a value holding = refused: %v", err)
	}
}
