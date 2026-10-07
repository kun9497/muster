package controls

import "testing"

func TestCheckParamValueAcceptsTheDeclaredShapes(t *testing.T) {
	ok := []struct {
		typ string
		v   any
	}{
		{"int", 5}, {"string", "x"}, {"bool", true},
		{"list<int>", []any{1, 2}}, {"list<string>", []any{"a"}}, {"list<string>", []any{}},
	}
	for _, c := range ok {
		if err := CheckParamValue(c.typ, c.v); err != nil {
			t.Errorf("CheckParamValue(%s, %v) = %v, want nil", c.typ, c.v, err)
		}
	}
	bad := []struct {
		typ string
		v   any
	}{
		{"int", "5"}, {"int", int64(5)}, {"int", 5.0}, {"string", 5}, {"bool", "true"},
		{"list<int>", []any{"1"}}, {"list<int>", []int{1}}, {"list<string>", []string{"a"}},
		{"list<string>", "a"}, {"list<string>", []any{1}}, {"record", 1},
	}
	for _, c := range bad {
		if err := CheckParamValue(c.typ, c.v); err == nil {
			t.Errorf("CheckParamValue(%s, %#v) = nil, want an error", c.typ, c.v)
		}
	}
}
