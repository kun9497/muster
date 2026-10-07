package controls

import "fmt"

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
