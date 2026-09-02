package check

import (
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

func TestCompareTypedScalars(t *testing.T) {
	cases := []struct {
		op   string
		act  any
		exp  any
		typ  string
		want bool
		err  bool
	}{
		{"eq", "no", "no", "string", true, false},
		{"ne", "no", "yes", "string", true, false},
		{"eq", float64(0), 0, "int", true, false},
		{"eq", "0", 0, "int", false, true}, // "0" is not an int: typed comparison
		{"lt", float64(89), 90, "int", true, false},
		{"gte", float64(90), 90, "int", true, false},
		{"lt", float64(1.5), 2, "int", false, true}, // non-integral number for int type
		{"eq", true, true, "bool", true, false},
		{"in", "prohibit-password", []any{"no", "prohibit-password"}, "string", true, false},
		{"not_in", "yes", []any{"no", "prohibit-password"}, "string", true, false},
		{"in", "x", "not-a-list", "string", false, true},
		{"contains", "PermitRootLogin no", "RootLogin", "string", true, false},
		{"matches", "pts/0", "^pts/", "string", true, false},
		{"matches", "PTS/0", "^pts/", "string", false, false}, // case-sensitive
		{"matches", "a\nb", "a.b", "string", false, false},    // . does not match newline
		{"matches", "x", "(", "string", false, true},
		{"present", "anything", nil, "string", true, false},
		{"bogus", "x", "x", "string", false, true},
	}
	for _, c := range cases {
		got, err := compare(c.op, c.act, c.exp, c.typ)
		if (err != nil) != c.err {
			t.Errorf("%s %v %v: err=%v want err=%v", c.op, c.act, c.exp, err, c.err)
			continue
		}
		if got != c.want {
			t.Errorf("%s %v %v: got %v want %v", c.op, c.act, c.exp, got, c.want)
		}
	}
}

func TestCompareLists(t *testing.T) {
	list := []any{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}
	if ok, _ := compare("contains", list, "chacha20-poly1305@openssh.com", "list<string>"); !ok {
		t.Error("contains on list must match an element")
	}
	if ok, _ := compare("contains", list, "chacha20", "list<string>"); ok {
		t.Error("contains on list is element equality, not substring")
	}
	if ok, _ := compare("matches", list, "@openssh\\.com$", "list<string>"); !ok {
		t.Error("matches on list is true when every element matches")
	}
	if ok, _ := compare("matches", list, "^aes", "list<string>"); ok {
		t.Error("matches on list must fail when one element does not match")
	}
	if ok, _ := compare("eq", list, []any{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"}, "list<string>"); !ok {
		t.Error("eq on lists compares elements in order")
	}
}

func TestSubstituteWholeValueOnly(t *testing.T) {
	params := map[string]any{"allowed": []any{"no", "prohibit-password"}, "days": 90}
	got, err := substitute("${allowed}", params)
	if err != nil {
		t.Fatal(err)
	}
	if xs, ok := got.([]any); !ok || len(xs) != 2 {
		t.Fatalf("list param must keep its type: %#v", got)
	}
	if got, _ := substitute("${days}", params); got != 90 {
		t.Errorf("int param must keep its type: %#v", got)
	}
	if got, _ := substitute("/home/${x}", params); got != "/home/${x}" {
		t.Errorf("embedded ${...} is not substitution: %#v", got)
	}
	if _, err := substitute("${nope}", params); err == nil {
		t.Error("unknown parameter must error")
	}
	if got, _ := substitute(90, params); got != 90 {
		t.Errorf("non-string expected passes through: %#v", got)
	}
}

func TestParamValuesDefaultsAndOverrides(t *testing.T) {
	c := &controls.Control{Params: map[string]controls.Param{
		"days": {Type: "int", Default: 90},
		"list": {Type: "list<string>", Default: []any{"a"}},
	}}
	v := ParamValues(c, map[string]any{"days": 60})
	if v["days"] != 60 || len(v["list"].([]any)) != 1 {
		t.Fatalf("%#v", v)
	}
}
