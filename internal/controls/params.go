package controls

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// CheckParamValue reports whether v has the shape a parameter of type typ
// takes: yaml.v3's own decoding of a scalar or a sequence (int, string,
// bool, []any of int or string) — the same test the lint applies to a
// declared default, shared with the profile and tuning loaders (3D-1).
func CheckParamValue(typ string, v any) error {
	ok := false
	switch typ {
	case "string":
		_, ok = v.(string)
	case "int":
		_, ok = v.(int)
	case "bool":
		_, ok = v.(bool)
	case "list<string>", "list<int>":
		xs, isList := v.([]any)
		if !isList {
			return fmt.Errorf("value %v is not of type %s", v, typ)
		}
		ok = true
		for _, x := range xs {
			if typ == "list<string>" {
				_, ok = x.(string)
			} else {
				_, ok = x.(int)
			}
			if !ok {
				break
			}
		}
	default:
		return fmt.Errorf("unknown parameter type %q", typ)
	}
	if !ok {
		return fmt.Errorf("value %v is not of type %s", v, typ)
	}
	return nil
}

var (
	scriptIntRe = regexp.MustCompile(`^-?[0-9]+$`)
	scriptStrRe = regexp.MustCompile(`^[A-Za-z0-9._/@:+,=-]+$`)
)

// ScriptParamValue formats a parameter value for a review script's
// P_<name>='<value>' line (3D-2c E-1) and reports whether the value can be
// carried: an int as digits, a bool as true/false, a string or each list
// element in a charset with no quote, blank, $, backtick, ;, |, & or \, and
// a list as its elements joined by one space. An empty list cannot be.
func ScriptParamValue(typ string, v any) (string, bool) {
	switch typ {
	case "int":
		n, ok := v.(int)
		if !ok {
			return "", false
		}
		s := strconv.Itoa(n)
		return s, scriptIntRe.MatchString(s)
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return "", false
		}
		return strconv.FormatBool(b), true
	case "string":
		s, ok := v.(string)
		if !ok || !scriptStrRe.MatchString(s) {
			return "", false
		}
		return s, true
	case "list<int>", "list<string>":
		xs, ok := v.([]any)
		if !ok || len(xs) == 0 {
			return "", false
		}
		elem := strings.TrimSuffix(strings.TrimPrefix(typ, "list<"), ">")
		parts := make([]string, 0, len(xs))
		for _, x := range xs {
			s, ok := ScriptParamValue(elem, x)
			if !ok {
				return "", false
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, " "), true
	}
	return "", false
}
