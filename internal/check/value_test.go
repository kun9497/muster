package check

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// I3: a float64 outside int64's range must be an error, never a silent wrap.
// int64(1e300) is implementation-defined and int64(9.3e18) wraps negative,
// which would let `lte 90` hold for a password age of 1e300 days.
func TestToIntRefusesValuesOutsideInt64(t *testing.T) {
	for _, v := range []any{1e300, -1e300, 9.3e18, -9.3e18, math.Inf(1), math.Inf(-1), math.NaN(), 1.5, "90", true, nil} {
		got, err := toInt(v)
		if err == nil {
			t.Errorf("toInt(%v) = %d, want an error", v, got)
			continue
		}
		if !errors.Is(err, ErrTypeMismatch) {
			t.Errorf("toInt(%v): err=%v, want it to wrap ErrTypeMismatch", v, err)
		}
	}
	for _, c := range []struct {
		in   any
		want int64
	}{
		{float64(90), 90}, {float64(0), 0}, {float64(-90), -90},
		{int(7), 7}, {int64(-7), -7},
		{float64(math.MinInt64), math.MinInt64},             // -2^63 is exactly representable
		{float64(4611686018427387904), 1 << 62},             // well inside the range
		{float64(9007199254740992), 9007199254740992},       // 2^53
		{float64(9223372036854774784), 9223372036854774784}, // the largest float64 below 2^63
	} {
		got, err := toInt(c.in)
		if err != nil || got != c.want {
			t.Errorf("toInt(%v) = %d, %v; want %d, nil", c.in, got, err, c.want)
		}
	}
}

// I3, end to end: an out-of-range number in the snapshot must make the
// control ERROR(internal_error) naming the key, not produce a verdict.
func TestOutOfRangeNumberIsAnErrorNamingTheKey(t *testing.T) {
	res := Evaluate(snap(t, `{"accounts":{"login_defs":{"pass_max_days":{"runtime":{"status":"ok","value":1e300},"persisted":{"status":"ok","value":1e300}}}}}`),
		one(passMaxDaysControl("auto")), reg, Options{})
	r := res[0]
	if r.Status != ERROR || r.ReasonCode != InternalError {
		t.Fatalf("status=%s code=%q reason=%q, want ERROR internal_error", r.Status, r.ReasonCode, r.Reason)
	}
	if !strings.Contains(r.Reason, "accounts.login_defs.pass_max_days") {
		t.Errorf("reason must name the key: %q", r.Reason)
	}
}

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
		// R22: "in"/"not_in" over an int fact against an int list, as used by
		// files.etc_passwd.mode's 16 bit-subsets of 0644. The actual value
		// arrives as float64 (JSON decoding); the expected list's elements
		// decode from YAML as int.
		{"in", float64(420), []any{0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420}, "int", true, false},
		{"in", float64(418), []any{0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420}, "int", false, false},
		{"not_in", float64(418), []any{0, 4, 32, 36, 128, 132, 160, 164, 256, 260, 288, 292, 384, 388, 416, 420}, "int", true, false},
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

	// Test error cases: non-string expected for contains
	if _, err := compare("contains", list, 5, "list<string>"); err == nil {
		t.Error("contains with non-string expected must error")
	}

	// Test error cases: list with non-string element (nested []any)
	mixedList := []any{"aes256-gcm@openssh.com", []any{"nested"}}
	if _, err := compare("contains", mixedList, "aes256-gcm@openssh.com", "list<string>"); err == nil {
		t.Error("contains on list with non-string element must error, not panic")
	}
	if _, err := compare("matches", mixedList, "aes", "list<string>"); err == nil {
		t.Error("matches on list with non-string element must error, not panic")
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
