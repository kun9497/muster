package cisindex

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const l1 = "l1_server"

// fixture is a synthetic benchmark of eight entries.
func fixture() *Source {
	return &Source{Version: "2.0.0", Entries: []Entry{
		{ID: "1.1.1", Levels: []string{l1, "l1_workstation"}, Rules: []string{"ra1", "ra2"}},
		{ID: "1.1.2", Levels: []string{l1}, Rules: []string{"rb1", "rb2"}},
		{ID: "1.1.3", Levels: []string{l1}},
		{ID: "1.1.4", Levels: []string{"l2_server"}, Rules: []string{"rd"}},
		{ID: "1.1.10", Levels: []string{l1}, Rules: []string{"re", "re"}},
		{ID: "2.1", Levels: []string{l1}, Rules: []string{"rf"}},
		{ID: "2.2", Levels: []string{l1}, Rules: []string{"rg"}},
		{ID: "2.3", Levels: []string{"l2_server"}, Selections: []Selection{{"var_z", "1"}}},
	}}
}

func bench(src *Source) Benchmark {
	return Benchmark{Product: "ubuntu2204", Display: "Synthetic Benchmark", Profile: "cis-ubuntu2204-l1",
		Pin: Pin{Repo: "r", Tag: "t", Commit: "c", Path: "p", SHA256: "s"}, Src: src}
}

func unionOf(src *Source) map[string]bool { return RuleUnion(src) }

// testEnv knows the controls muster.a … muster.x and their parameters.
func testEnv() Env {
	types := map[string]string{
		"muster.a.max": "int", "muster.a.timeout": "int", "muster.a.word": "string",
		"muster.a.umasks": "list<string>", "muster.b.max": "int",
	}
	ids := map[string]bool{}
	for _, c := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "x"} {
		ids["muster."+c] = true
	}
	return Env{
		IDs: ids,
		ParamType: func(control, param string) (string, bool) {
			t, ok := types[control+"."+param]
			return t, ok
		},
		Check: func(typ string, v any) error {
			ok := false
			switch typ {
			case "int":
				_, ok = v.(int)
			case "string":
				_, ok = v.(string)
			case "list<string>":
				_, ok = v.([]any)
			}
			if !ok {
				return fmt.Errorf("value %v is not of type %s", v, typ)
			}
			return nil
		},
	}
}

func rowOf(ix *Index, rec string) *Row {
	for i := range ix.Recs {
		if ix.Recs[i].Rec == rec {
			return &ix.Recs[i]
		}
	}
	return nil
}

func mustBuild(t *testing.T, src *Source, rows []MapRow, review []ReviewRow) (*Index, *ProfileOut) {
	t.Helper()
	ix, p, err := Build(bench(src), unionOf(src), rows, review, testEnv())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return ix, p
}

func TestBuildReachAndRulesWord(t *testing.T) {
	rows := []MapRow{
		{ID: "muster.a", Rules: []string{"ra1", "ra2"}},
		{ID: "muster.b", Rules: []string{"rb1"}},
		{ID: "muster.c", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3", Reason: "x"}}, "rhel9": {{Rec: "9.9", Reason: "y"}}}},
		{ID: "muster.d", Rules: []string{"ra1"}},
	}
	ix, p := mustBuild(t, fixture(), rows, nil)
	for rec, want := range map[string]Row{
		"1.1.1": {Rec: "1.1.1", Levels: []string{l1, "l1_workstation"}, Controls: []string{"muster.a", "muster.d"}, Rules: "all"},
		"1.1.2": {Rec: "1.1.2", Levels: []string{l1}, Controls: []string{"muster.b"}, Rules: "some"},
		"1.1.3": {Rec: "1.1.3", Levels: []string{l1}, Controls: []string{"muster.c"}, Rules: "none"},
	} {
		got := rowOf(ix, rec)
		if got == nil || !reflect.DeepEqual(*got, want) {
			t.Errorf("row %s: got %+v want %+v", rec, got, want)
		}
	}
	if len(ix.Recs) != 3 {
		t.Errorf("unmapped rows written: %+v", ix.Recs)
	}
	if ix.Product != "ubuntu2204" || ix.Benchmark != "Synthetic Benchmark" || ix.Version != "2.0.0" || ix.Source.Path != "p" {
		t.Errorf("header %+v", ix)
	}
	if !reflect.DeepEqual(p.Include, []string{"muster.a", "muster.b", "muster.c", "muster.d"}) || p.Name != "cis-ubuntu2204-l1" {
		t.Errorf("profile %+v", p)
	}
}

func TestBuildRowControlsAreTheUnionOfBothReaches(t *testing.T) {
	// 1.1.3 has no rule id, so only recs: reach it; three controls name it.
	// muster.e reaches 1.1.1 by a rule id and 1.1.3 by recs:, and is listed on both.
	rows := []MapRow{
		{ID: "muster.b", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3", Reason: "x"}}}},
		{ID: "muster.e", Rules: []string{"ra2"}, Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3", Reason: "x"}}}},
		{ID: "muster.f", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3", Reason: "x"}}}},
	}
	ix, _ := mustBuild(t, fixture(), rows, nil)
	if got := rowOf(ix, "1.1.3"); got == nil || !reflect.DeepEqual(got.Controls, []string{"muster.b", "muster.e", "muster.f"}) {
		t.Errorf("1.1.3: %+v", got)
	}
	if got := rowOf(ix, "1.1.1"); got == nil || !reflect.DeepEqual(got.Controls, []string{"muster.e"}) || got.Rules != "some" {
		t.Errorf("1.1.1: %+v", got)
	}
}

func TestBuildDuplicateRuleIdIsASet(t *testing.T) {
	ix, _ := mustBuild(t, fixture(), []MapRow{{ID: "muster.a", Rules: []string{"re"}}}, nil)
	if got := rowOf(ix, "1.1.10"); got == nil || got.Rules != "all" {
		t.Errorf("1.1.10: %+v", got)
	}
}

func TestBuildRefusesRecsOnEntryWithRuleIds(t *testing.T) {
	rows := []MapRow{{ID: "muster.a", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.2", Reason: "x"}}}}}
	_, _, err := Build(bench(fixture()), unionOf(fixture()), rows, nil, testEnv())
	if err == nil || !strings.Contains(err.Error(), "rb1") || !strings.Contains(err.Error(), "rb2") || !strings.Contains(err.Error(), "1.1.2") {
		t.Fatalf("recs on an entry with rule ids: %v", err)
	}
}

func TestBuildRefusals(t *testing.T) {
	a := MapRow{ID: "muster.a", Rules: []string{"ra1"}}
	cases := []struct {
		name   string
		rows   []MapRow
		review []ReviewRow
		want   string
	}{
		{"rule not in union", []MapRow{{ID: "muster.a", Rules: []string{"ra1", "nowhere"}}}, nil, "nowhere"},
		{"rule with =", []MapRow{{ID: "muster.a", Rules: []string{"var_n=14"}}}, nil, "var_n=14"},
		{"rule outside grammar", []MapRow{{ID: "muster.a", Rules: []string{"Ra1"}}}, nil, "Ra1"},
		{"map id not a control", []MapRow{{ID: "muster.zz", Rules: []string{"ra1"}}}, nil, "muster.zz"},
		{"recs number not in file", []MapRow{{ID: "muster.c", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "9.9.9", Reason: "x"}}}}}, nil, "9.9.9"},
		{"recs number outside grammar", []MapRow{{ID: "muster.c", Recs: map[string][]RecRow{"ubuntu2204": {{Rec: "1.1.3a", Reason: "x"}}}}}, nil, "1.1.3a"},
		{"review row not a candidate", []MapRow{a}, []ReviewRow{{Profile: "cis-ubuntu2204-l1", ID: "muster.b", Reason: "x"}}, "muster.b"},
		{"review row on an l2-only control", []MapRow{a, {ID: "muster.d", Rules: []string{"rd"}}}, []ReviewRow{{Profile: "cis-ubuntu2204-l1", ID: "muster.d", Reason: "x"}}, "muster.d"},
		{"param the control does not declare", []MapRow{{ID: "muster.a", Rules: []string{"ra1"}, Vars: []VarRow{{Var: "v", Param: "nope", As: "int"}}}}, nil, "nope"},
	}
	for _, c := range cases {
		_, _, err := Build(bench(fixture()), unionOf(fixture()), c.rows, c.review, testEnv())
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "ubuntu2204: ") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A review row on another profile is not this build's to judge (CheckReviewProfiles
	// refuses an unknown profile name, TestCheckReviewProfiles).
	if _, _, err := Build(bench(fixture()), unionOf(fixture()), []MapRow{a}, []ReviewRow{{Profile: "cis-rhel9-l1", ID: "muster.b", Reason: "x"}}, testEnv()); err != nil {
		t.Errorf("other profile's row: %v", err)
	}
	// Every failure is reported, not the first.
	_, _, err := Build(bench(fixture()), unionOf(fixture()), []MapRow{{ID: "muster.zz", Rules: []string{"nowhere"}}}, nil, testEnv())
	if err == nil || !strings.Contains(err.Error(), "muster.zz") || !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("joined errors: %v", err)
	}
	if _, _, err := Build(Benchmark{Product: "p"}, nil, nil, nil, testEnv()); err == nil {
		t.Error("no source accepted")
	}
}

func TestBuildCountsOnlyLiteralL1Server(t *testing.T) {
	rows := []MapRow{
		{ID: "muster.a", Rules: []string{"rf"}},
		{ID: "muster.b", Rules: []string{"rd", "re"}},
		{ID: "muster.c", Rules: []string{"ra1"}},
	}
	ix, p := mustBuild(t, fixture(), rows, nil)
	if ix.Counts.L1Server != 6 {
		t.Errorf("l1_server count %d", ix.Counts.L1Server)
	}
	var recs []string
	for _, r := range ix.Recs {
		recs = append(recs, r.Rec)
	}
	if !reflect.DeepEqual(recs, []string{"1.1.1", "1.1.4", "1.1.10", "2.1"}) {
		t.Errorf("recs %v", recs)
	}
	// muster.b is a candidate through 1.1.10 (l1_server), not through 1.1.4 (l2_server only).
	if !reflect.DeepEqual(Candidates(ix), []string{"muster.a", "muster.b", "muster.c"}) || !reflect.DeepEqual(p.Include, Candidates(ix)) {
		t.Errorf("candidates %v include %v", Candidates(ix), p.Include)
	}
	ix2, p2 := mustBuild(t, fixture(), []MapRow{{ID: "muster.d", Rules: []string{"rd"}}}, nil)
	if len(Candidates(ix2)) != 0 || len(p2.Include) != 0 || len(ix2.Recs) != 1 {
		t.Errorf("l2-only control: %v %v", Candidates(ix2), p2.Include)
	}
}

// varsSource is a benchmark whose entries select variables.
func varsSource(sel1, sel2 []Selection) *Source {
	return &Source{Version: "1", Entries: []Entry{
		{ID: "1.1", Levels: []string{l1}, Rules: []string{"ra"}, Selections: sel1},
		{ID: "1.2", Levels: []string{l1}, Rules: []string{"rb"}, Selections: sel2},
		{ID: "1.3", Levels: []string{"l2_server"}, Rules: []string{"ra2"}, Selections: []Selection{{"var_l2", "x"}}},
		{ID: "1.4", Levels: []string{l1}, Rules: []string{"rother"}, Selections: []Selection{{"var_other", "x"}}},
	}}
}

func TestBuildVars(t *testing.T) {
	rules := []string{"ra", "rb", "ra2"}
	cases := []struct {
		name       string
		sel1, sel2 []Selection
		vars       []VarRow
		want       map[string]any // muster.a's params; nil = none
		err        string
	}{
		{"as int", []Selection{{"var_n", "14"}}, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, map[string]any{"max": 14}, ""},
		{"as int refuses a leading zero", []Selection{{"var_n", "027"}}, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, nil, "027"},
		{"as int refuses a word", []Selection{{"var_n", "cis"}}, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, nil, "cis"},
		{"table", []Selection{{"var_t", "15_min"}}, nil, []VarRow{{Var: "var_t", Param: "timeout", As: map[string]any{"15_min": 900}}}, map[string]any{"timeout": 900}, ""},
		{"table list value", []Selection{{"var_u", "027"}}, nil, []VarRow{{Var: "var_u", Param: "umasks", As: map[string]any{"027": []any{"027", "077"}}}}, map[string]any{"umasks": []any{"027", "077"}}, ""},
		{"table key outside the grammar", []Selection{{"var_t", "15_min"}}, nil, []VarRow{{Var: "var_t", Param: "word", As: map[string]any{"15_min": "a", "cis_ubuntu2204": "b"}}}, nil, "cis_ubuntu2204"},
		{"selection with no table entry", []Selection{{"var_t", "5_minutes"}}, nil, []VarRow{{Var: "var_t", Param: "timeout", As: map[string]any{"15_min": 900}}}, nil, "5_minutes"},
		{"two values", []Selection{{"var_n", "4"}}, []Selection{{"var_n", "5"}}, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, nil, "var_n"},
		{"equal on two", []Selection{{"var_n", "4"}}, []Selection{{"var_n", "4"}}, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, map[string]any{"max": 4}, ""},
		{"not selected", nil, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, nil, ""},
		{"selected but unnamed", []Selection{{"var_n", "4"}, {"var_q", "1"}}, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}}, nil, "var_q"},
		{"param none", []Selection{{"var_w", "cis"}}, nil, []VarRow{{Var: "var_w", Param: "none", Reason: "x"}}, nil, ""},
		{"check refuses a table value", []Selection{{"var_t", "15_min"}}, nil, []VarRow{{Var: "var_t", Param: "timeout", As: map[string]any{"15_min": "fifteen"}}}, nil, "fifteen"},
		{"check refuses an int for a string param", []Selection{{"var_n", "4"}}, nil, []VarRow{{Var: "var_n", Param: "word", As: "int"}}, nil, "word"},
		{"two vars on one param", []Selection{{"var_n", "4"}, {"var_m", "5"}}, nil, []VarRow{{Var: "var_n", Param: "max", As: "int"}, {Var: "var_m", Param: "max", As: "int"}}, nil, "max"},
	}
	for _, c := range cases {
		src := varsSource(c.sel1, c.sel2)
		rows := []MapRow{{ID: "muster.a", Rules: rules, Vars: c.vars}}
		_, p, err := Build(bench(src), unionOf(src), rows, nil, testEnv())
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err %v, want one naming %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(p.Params["muster.a"], c.want) {
			t.Errorf("%s: params %#v want %#v", c.name, p.Params, c.want)
		}
		if c.want == nil && len(p.Params) != 0 {
			t.Errorf("%s: params %#v", c.name, p.Params)
		}
	}
}

func TestBuildVarsReadOnlyL1EntriesTheRulesReach(t *testing.T) {
	// var_l2 is selected on an l2_server entry and var_other on an entry muster.a's
	// rules do not reach: neither needs a vars: row.
	src := varsSource(nil, nil)
	if _, _, err := Build(bench(src), unionOf(src), []MapRow{{ID: "muster.a", Rules: []string{"ra", "ra2"}}}, nil, testEnv()); err != nil {
		t.Fatal(err)
	}
}

func TestBuildReviewedOutControl(t *testing.T) {
	src := varsSource([]Selection{{"var_t", "never_listed"}}, nil)
	rows := []MapRow{
		{ID: "muster.a", Rules: []string{"ra"}, Vars: []VarRow{{Var: "var_t", Param: "timeout", As: map[string]any{"15_min": 900}}}},
		{ID: "muster.b", Rules: []string{"rb"}},
	}
	review := []ReviewRow{{Profile: "cis-ubuntu2204-l1", ID: "muster.a", Reason: "x"}}
	ix, p, err := Build(bench(src), unionOf(src), rows, review, testEnv())
	if err != nil {
		t.Fatalf("reviewed-out control's selection fails the build: %v", err)
	}
	if !reflect.DeepEqual(p.Include, []string{"muster.b"}) || p.Params["muster.a"] != nil {
		t.Errorf("profile %+v", p)
	}
	if got := rowOf(ix, "1.1"); got == nil || !reflect.DeepEqual(got.Controls, []string{"muster.a"}) {
		t.Errorf("index row 1.1: %+v", got)
	}
	// The worklist is unconditional: an unnamed selected variable fails even when reviewed out.
	src2 := varsSource([]Selection{{"var_t", "15_min"}, {"var_q", "1"}}, nil)
	_, _, err = Build(bench(src2), unionOf(src2), rows, review, testEnv())
	if err == nil || !strings.Contains(err.Error(), "var_q") || !strings.Contains(err.Error(), "muster.a") {
		t.Errorf("unnamed variable on a reviewed-out control: %v", err)
	}
}

func TestBuildParamOnlyForIncluded(t *testing.T) {
	src := varsSource([]Selection{{"var_n", "4"}}, []Selection{{"var_n", "4"}})
	rows := []MapRow{
		{ID: "muster.a", Rules: []string{"ra"}, Vars: []VarRow{{Var: "var_n", Param: "max", As: "int"}}},
		{ID: "muster.b", Rules: []string{"rb"}, Vars: []VarRow{{Var: "var_n", Param: "max", As: "int"}}},
	}
	review := []ReviewRow{{Profile: "cis-ubuntu2204-l1", ID: "muster.b", Reason: "x"}}
	_, p := mustBuild(t, src, rows, review)
	want := map[string]map[string]any{"muster.a": {"max": 4}}
	if !reflect.DeepEqual(p.Params, want) {
		t.Errorf("params %#v", p.Params)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	src := varsSource([]Selection{{"var_n", "4"}}, nil)
	rows := []MapRow{
		{ID: "muster.a", Rules: []string{"ra", "rb"}, Vars: []VarRow{{Var: "var_n", Param: "max", As: "int"}}},
		{ID: "muster.b", Rules: []string{"rb"}},
	}
	ix1, p1 := mustBuild(t, src, rows, nil)
	ix2, p2 := mustBuild(t, src, rows, nil)
	a, _ := RenderIndex(ix1)
	b, _ := RenderIndex(ix2)
	c, _ := RenderProfile(p1)
	d, _ := RenderProfile(p2)
	if !bytes.Equal(a, b) || !bytes.Equal(c, d) {
		t.Error("two builds differ")
	}
}

func TestRenderProfileParsesAsAProfile(t *testing.T) {
	p := &ProfileOut{Name: "cis-ubuntu2204-l1", Include: []string{"muster.a", "muster.b"},
		Params: map[string]map[string]any{"muster.b": {"umasks": []any{"027", "077"}, "max": 4}, "muster.a": {"max": 5}}}
	out, err := RenderProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	const header = "# Generated by tools/cisindex from docs/reference/cis; do not edit.\n"
	if !strings.HasPrefix(string(out), header) {
		t.Fatalf("header:\n%s", out)
	}
	var got struct {
		Profile string                    `yaml:"profile"`
		Include []string                  `yaml:"include"`
		Params  map[string]map[string]any `yaml:"params"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode: %v\n%s", err, out)
	}
	if got.Profile != p.Name || !reflect.DeepEqual(got.Include, p.Include) || !reflect.DeepEqual(got.Params, p.Params) {
		t.Errorf("round trip %+v", got)
	}
	if strings.Index(string(out), "muster.a:\n") > strings.Index(string(out), "muster.b:\n") {
		t.Errorf("params not sorted:\n%s", out)
	}
	empty, err := RenderProfile(&ProfileOut{Name: "cis-x-l1"})
	if err != nil || !strings.Contains(string(empty), "include: []") || strings.Contains(string(empty), "params") {
		t.Errorf("empty profile:\n%s %v", empty, err)
	}
}
