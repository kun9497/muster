package check

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"

	"github.com/kun9497/muster/internal/controls"
)

var paramRef = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]*)\}$`)

// ErrTypeMismatch marks a value that does not match the type the registry
// declares for its key. Spec §6.3: a type mismatch is an error the evaluator
// turns into ERROR(internal_error) naming the key, never a guess.
var ErrTypeMismatch = errors.New("type mismatch")

// ParamValues merges a control's defaults with overrides (stage 3 tuning);
// stage 1 passes nil overrides.
func ParamValues(c *controls.Control, overrides map[string]any) map[string]any {
	out := make(map[string]any, len(c.Params))
	for _, name := range c.SortedParamNames() {
		out[name] = c.Params[name].Default
	}
	for k, v := range overrides {
		if _, declared := c.Params[k]; declared {
			out[k] = v
		}
	}
	return out
}

// substitute resolves `${name}` as a whole value with the parameter's own
// type preserved (spec §6.3). Anything else passes through unchanged.
func substitute(expected any, params map[string]any) (any, error) {
	s, ok := expected.(string)
	if !ok {
		return expected, nil
	}
	m := paramRef.FindStringSubmatch(s)
	if m == nil {
		return expected, nil
	}
	v, ok := params[m[1]]
	if !ok {
		return nil, fmt.Errorf("parameter %q is not declared", m[1])
	}
	return v, nil
}

// baseType strips setting<...> so comparisons see the inner type.
func baseType(typ string) string {
	if strings.HasPrefix(typ, "setting<") {
		return strings.TrimSuffix(strings.TrimPrefix(typ, "setting<"), ">")
	}
	return typ
}

// compare applies op to a fact value and an expected value, typed by the
// registry (spec §6.3). JSON numbers arrive as float64; for "int" they must
// be integral. Returns an error for a type mismatch or an unknown op, which
// the evaluator turns into ERROR(internal_error) rather than a guess.
func compare(op string, actual, expected any, typ string) (bool, error) {
	typ = baseType(typ)
	switch op {
	case "present":
		return true, nil // reached only for status ok; absence is decided by the derivation table
	case "absent":
		return false, nil
	}
	if strings.HasPrefix(typ, "list<") {
		return compareList(op, actual, expected)
	}
	switch typ {
	case "int":
		a, err := toInt(actual)
		if err != nil {
			return false, fmt.Errorf("actual: %w", err)
		}
		switch op {
		case "eq", "ne", "lt", "lte", "gt", "gte":
			e, err := toInt(expected)
			if err != nil {
				return false, fmt.Errorf("expected: %w", err)
			}
			switch op {
			case "eq":
				return a == e, nil
			case "ne":
				return a != e, nil
			case "lt":
				return a < e, nil
			case "lte":
				return a <= e, nil
			case "gt":
				return a > e, nil
			case "gte":
				return a >= e, nil
			}
		case "in", "not_in":
			return inList(op, a, expected, func(x any) (any, error) { return toInt(x) })
		}
		return false, fmt.Errorf("op %q is not valid on int", op)
	case "bool":
		a, ok := actual.(bool)
		if !ok {
			return false, fmt.Errorf("actual %v is not a bool", actual)
		}
		e, ok := expected.(bool)
		if !ok {
			return false, fmt.Errorf("expected %v is not a bool", expected)
		}
		switch op {
		case "eq":
			return a == e, nil
		case "ne":
			return a != e, nil
		}
		return false, fmt.Errorf("op %q is not valid on bool", op)
	case "string":
		a, ok := actual.(string)
		if !ok {
			return false, fmt.Errorf("actual %v is not a string", actual)
		}
		switch op {
		case "eq", "ne", "contains", "matches":
			e, ok := expected.(string)
			if !ok {
				return false, fmt.Errorf("expected %v is not a string", expected)
			}
			switch op {
			case "eq":
				return a == e, nil
			case "ne":
				return a != e, nil
			case "contains":
				return strings.Contains(a, e), nil
			case "matches":
				re, err := regexp.Compile(e)
				if err != nil {
					return false, err
				}
				return re.MatchString(a), nil
			}
		case "in", "not_in":
			return inList(op, a, expected, func(x any) (any, error) {
				s, ok := x.(string)
				if !ok {
					return nil, fmt.Errorf("%v is not a string", x)
				}
				return s, nil
			})
		}
		return false, fmt.Errorf("op %q is not valid on string", op)
	}
	return false, fmt.Errorf("unsupported type %q", typ)
}

func compareList(op string, actual, expected any) (bool, error) {
	xs, ok := actual.([]any)
	if !ok {
		return false, fmt.Errorf("actual %v is not a list", actual)
	}
	// list<string> is the only list type a clause compares (spec §5.5), so
	// every element must be a string for every op below, not only for the
	// ones that reach into an element.
	for i, x := range xs {
		if _, ok := x.(string); !ok {
			return false, fmt.Errorf("list element %d is not a string: %w", i, ErrTypeMismatch)
		}
	}
	switch op {
	case "eq", "ne":
		ys, ok := expected.([]any)
		if !ok {
			return false, fmt.Errorf("expected %v is not a list", expected)
		}
		eq := reflect.DeepEqual(xs, ys)
		if op == "eq" {
			return eq, nil
		}
		return !eq, nil
	case "contains":
		e, ok := expected.(string)
		if !ok {
			return false, fmt.Errorf("expected %v is not a string", expected)
		}
		for _, x := range xs {
			if x == e {
				return true, nil
			}
		}
		return false, nil
	case "matches":
		pat, ok := expected.(string)
		if !ok {
			return false, fmt.Errorf("expected %v is not a pattern", expected)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, err
		}
		for _, x := range xs {
			s := x.(string) // Safe cast; elements already validated as strings
			if !re.MatchString(s) {
				return false, nil
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("op %q is not valid on a list", op)
}

func inList(op string, a any, expected any, conv func(any) (any, error)) (bool, error) {
	xs, ok := expected.([]any)
	if !ok {
		return false, fmt.Errorf("expected %v is not a list", expected)
	}
	found := false
	for _, x := range xs {
		v, err := conv(x)
		if err != nil {
			return false, err
		}
		if v == a {
			found = true
		}
	}
	if op == "in" {
		return found, nil
	}
	return !found, nil
}

// twoTo63 is the first float64 above int64's range. A conversion at or
// beyond it (and below -twoTo63) is undefined in Go and in practice wraps to
// the minimum int64, which would let `lte 90` hold for 1e300 (I3).
const twoTo63 = 9223372036854775808.0

func toInt(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case float64:
		// NaN fails this test too, which is what we want: it is not an
		// integer, and every comparison against it would be false.
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("%v is not an integer: %w", n, ErrTypeMismatch)
		}
		if n < -twoTo63 || n >= twoTo63 {
			return 0, fmt.Errorf("%v is outside the range of a 64-bit integer: %w", n, ErrTypeMismatch)
		}
		return int64(n), nil
	}
	return 0, fmt.Errorf("%v is not an int: %w", v, ErrTypeMismatch)
}
