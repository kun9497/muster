package anonymize

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// UnclassifiedError is a document path the table does not classify (AX-8).
// Path is spelled as a document path with [] for any list index.
type UnclassifiedError struct{ Path string }

func (e *UnclassifiedError) Error() string { return "unclassified field " + e.Path }

// ErrAlreadyAnonymized refuses an input that carries run.anonymization.
var ErrAlreadyAnonymized = errors.New("snapshot is already anonymised")

// Transform rewrites a decoded snapshot document (json.Number numbers) by the
// table and returns a new tree; doc is not changed. A first pass collects the
// account names the account rule maps and the homes the Home fields name; a
// second rewrites every value by its class, notes every mapping in a ledger
// (a collision refuses, AX-9) and re-sorts the sorted lists. A path the table
// does not classify refuses with an *UnclassifiedError. mode is "keyed" or
// "ephemeral".
func Transform(doc map[string]any, t Table, k *Key, mode string) (map[string]any, Report, error) {
	if mode != "keyed" && mode != "ephemeral" {
		return nil, Report{}, fmt.Errorf("anonymization mode %q is neither keyed nor ephemeral", mode)
	}
	if err := t.Validate(); err != nil {
		return nil, Report{}, err
	}
	if run, ok := doc["run"].(map[string]any); ok {
		if _, marked := run["anonymization"]; marked {
			return nil, Report{}, ErrAlreadyAnonymized
		}
	}
	w := &walker{t: t, k: k, prefixes: map[string]bool{}, collect: true}
	for key := range t {
		for i := 0; i < len(key); i++ {
			if key[i] == '.' || strings.HasPrefix(key[i:], "[]") {
				w.prefixes[key[:i]] = true
			}
		}
		w.prefixes[key] = true
		if base, ok := strings.CutSuffix(key, ".*"); ok {
			w.wildcards = append(w.wildcards, base)
		}
	}
	sort.Strings(w.wildcards)
	w.document(doc)
	if w.err != nil {
		return nil, Report{}, w.err
	}
	w.collect = false
	w.ledger = NewLedger()
	w.classes = map[string]bool{}
	w.replaced = map[string]bool{}
	out := w.document(doc)
	if w.err != nil {
		return nil, Report{}, w.err
	}
	return out, Report{Classes: sortedKeys(w.classes), Replaced: sortedKeys(w.replaced)}, nil
}

type walker struct {
	t         Table
	k         *Key
	prefixes  map[string]bool
	wildcards []string
	collect   bool // first pass: gather names and homes, write nothing
	homes     Homes
	ledger    *Ledger
	classes   map[string]bool
	replaced  map[string]bool
	err       error
}

func (w *walker) fail(path string) {
	if w.err == nil {
		w.err = &UnclassifiedError{Path: path}
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func reservedRoot(p string) bool {
	root, _, _ := strings.Cut(p, ".")
	return headerRoots[root] || genericRoots[root]
}

func (w *walker) document(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for _, key := range keysOf(doc) {
		if w.err != nil {
			return nil
		}
		switch {
		case key == "facts":
			m, ok := doc[key].(map[string]any)
			if !ok {
				w.fail(key)
				return nil
			}
			out[key] = w.facts("", m)
		case headerRoots[key]:
			out[key] = w.value(key, key, doc[key])
		default:
			w.fail(key)
		}
	}
	return out
}

// facts descends the facts tree by the table's fact keys: a node whose dotted
// path is a fact key is that fact's envelope or setting, a node on the way to
// one is an object of further nodes, anything else is unclassified.
func (w *walker) facts(prefix string, m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for _, key := range keysOf(m) {
		if w.err != nil {
			return nil
		}
		q := join(prefix, key)
		dp := "facts." + q
		if reservedRoot(q) || strings.Contains(q, "[]") {
			w.fail(dp)
			return nil
		}
		if _, isKey := w.t[q]; isKey {
			out[key] = w.fact(q, dp, m[key])
			continue
		}
		sub, ok := m[key].(map[string]any)
		if !ok || !w.prefixes[q] {
			w.fail(dp)
			return nil
		}
		out[key] = w.facts(q, sub)
	}
	return out
}

func (w *walker) fact(key, dp string, v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		w.fail(dp)
		return nil
	}
	if _, isEnvelope := m["status"]; isEnvelope {
		return w.envelope(key, dp, m)
	}
	return w.setting(key, dp, m)
}

func (w *walker) envelope(key, dp string, m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for _, f := range keysOf(m) {
		if w.err != nil {
			return nil
		}
		if _, ok := w.t["envelope."+f]; !ok {
			w.fail(dp + "." + f)
			return nil
		}
		switch f {
		case "value":
			out[f] = w.value(key, dp+".value", m[f])
		case "source":
			out[f] = w.source(dp+".source", m[f])
		default:
			out[f] = w.value("envelope."+f, dp+"."+f, m[f])
		}
	}
	return out
}

func isPersona(p string) bool {
	for _, n := range PersonaNames {
		if n == p {
			return true
		}
	}
	return false
}

func (w *walker) setting(key, dp string, m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for _, f := range keysOf(m) {
		if w.err != nil {
			return nil
		}
		if _, ok := w.t["setting."+f]; !ok {
			w.fail(dp + "." + f)
			return nil
		}
		v := m[f]
		switch f {
		case "runtime", "persisted", "effective":
			side, ok := v.(map[string]any)
			if !ok && v != nil {
				w.fail(dp + "." + f)
				return nil
			}
			if ok {
				out[f] = w.envelope(key, dp+"."+f, side)
			} else {
				out[f] = nil
			}
		case "winner":
			out[f] = w.source(dp+".winner", v)
		case "personas":
			ps, ok := v.(map[string]any)
			if !ok && v != nil {
				w.fail(dp + "." + f)
				return nil
			}
			if !ok {
				out[f] = nil
				continue
			}
			po := make(map[string]any, len(ps))
			for _, p := range keysOf(ps) {
				pd := dp + ".personas." + p
				pm, ok := ps[p].(map[string]any)
				if !isPersona(p) || !ok {
					w.fail(pd)
					return nil
				}
				po[p] = w.envelope(key, pd, pm)
			}
			out[f] = po
		default:
			out[f] = w.value("setting."+f, dp+"."+f, v)
		}
	}
	return out
}

// source applies the Source rows to a Source and, at any depth, its inputs.
func (w *walker) source(dp string, v any) any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		w.fail(dp)
		return nil
	}
	out := make(map[string]any, len(m))
	for _, f := range keysOf(m) {
		if w.err != nil {
			return nil
		}
		if _, ok := w.t["source."+f]; !ok {
			w.fail(dp + "." + f)
			return nil
		}
		if f != "inputs" {
			out[f] = w.value("source."+f, dp+"."+f, m[f])
			continue
		}
		in, ok := m[f].([]any)
		if !ok && m[f] != nil {
			w.fail(dp + ".inputs")
			return nil
		}
		if !ok {
			out[f] = nil
			continue
		}
		lo := make([]any, len(in))
		for i, e := range in {
			lo[i] = w.source(dp+".inputs[]", e)
		}
		out[f] = lo
	}
	return out
}

func (w *walker) wildcard(rp string) (FieldRule, bool) {
	for i := len(w.wildcards) - 1; i >= 0; i-- {
		b := w.wildcards[i]
		if strings.HasPrefix(rp, b+".") || strings.HasPrefix(rp, b+"[]") {
			return w.t[b+".*"], true
		}
	}
	return FieldRule{}, false
}

// value rewrites v at table path rp (document path dp).
func (w *walker) value(rp, dp string, v any) any {
	if w.err != nil {
		return nil
	}
	rule, exact := w.t[rp]
	if !exact {
		if wr, ok := w.wildcard(rp); ok {
			return w.deep(wr, dp, v)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		if !exact && !w.prefixes[rp] {
			w.fail(dp)
			return nil
		}
		out := make(map[string]any, len(x))
		for _, f := range keysOf(x) {
			out[f] = w.value(rp+"."+f, dp+"."+f, x[f])
		}
		if w.collect {
			w.collectHome(rp, x)
		}
		return out
	case []any:
		if !exact && !w.prefixes[rp] {
			w.fail(dp)
			return nil
		}
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = w.value(rp+"[]", dp+"[]", e)
		}
		if exact && rule.Sort != nil && !w.collect && w.err == nil {
			out = sortList(out, rule.Sort)
		}
		return out
	default:
		if !exact {
			w.fail(dp)
			return nil
		}
		return w.scalar(rule, dp, x)
	}
}

// deep applies one rule to every scalar under v (a wildcard row).
func (w *walker) deep(rule FieldRule, dp string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for _, f := range keysOf(x) {
			out[f] = w.deep(rule, dp+"."+f, x[f])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = w.deep(rule, dp+"[]", e)
		}
		return out
	default:
		return w.scalar(rule, dp, x)
	}
}

// collectHome records a record's Home fields with the record's account-class
// fields as their accounts.
func (w *walker) collectHome(rp string, m map[string]any) {
	for _, f := range keysOf(m) {
		h, ok := m[f].(string)
		if !ok || !w.t[rp+"."+f].Home {
			continue
		}
		var accts []string
		for _, g := range keysOf(m) {
			if a, ok := m[g].(string); ok && w.t[rp+"."+g].Class == ClassAccount {
				accts = append(accts, a)
			}
		}
		w.homes.AddHome(h, accts...)
	}
}

func sortList(l []any, s *SortSpec) []any {
	cmp := func(a, b any) int {
		for _, key := range s.Keys {
			if c := compareField(fieldOf(a, key.Field), fieldOf(b, key.Field), key.Numeric); c != 0 {
				return c
			}
		}
		return 0
	}
	sort.SliceStable(l, func(i, j int) bool { return cmp(l[i], l[j]) < 0 })
	if !s.Dedup || len(l) == 0 {
		return l
	}
	out := l[:1]
	for _, e := range l[1:] {
		if cmp(out[len(out)-1], e) != 0 {
			out = append(out, e)
		}
	}
	return out
}

func fieldOf(e any, f string) any {
	if f == "" {
		return e
	}
	m, _ := e.(map[string]any)
	return m[f]
}

func compareField(a, b any, numeric bool) int {
	if numeric {
		ra, rb := toRat(a), toRat(b)
		switch {
		case ra == nil && rb == nil:
			return 0
		case ra == nil:
			return -1
		case rb == nil:
			return 1
		}
		return ra.Cmp(rb)
	}
	return strings.Compare(toText(a), toText(b))
}

func toRat(v any) *big.Rat {
	var s string
	switch x := v.(type) {
	case json.Number:
		s = string(x)
	case string:
		s = x
	case float64:
		return new(big.Rat).SetFloat64(x)
	default:
		return nil
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil
	}
	return r
}

func toText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}
