package anonymize

import (
	"fmt"
	"sort"
	"strings"
)

// Class names the rule a value is rewritten by (AX-4). The Class* constants
// are its values; the first seven are also the tokens of
// run.anonymization.classes (AX-10).
type Class string

// Placeholder is the fixed text a placeholdered value becomes (AX-7).
const Placeholder = "[anonymised]"

// List orders (AX-8): a list either keeps the order it was collected in, or
// is re-sorted after mapping by its SortSpec.
const (
	OrderKept   = "kept"
	OrderSorted = "sorted"
)

// The tokenizers of a read-text grammar. SplitWhitespace: runs of spaces and
// tabs separate tokens, and are kept as they were. SplitComma: every ","
// separates two tokens (an option list such as a mount's or an export's).
const (
	SplitWhitespace = "whitespace"
	SplitComma      = "comma"
)

// Grammar rewrites a read-text value token by token (AX-7): token i by
// Tokens[i], every token past them by Rest. A bare "+" or "-" is kept; a
// leading "+" or "-" before a name is kept and the name mapped by the class.
// A token key=value whose key Values names maps its value by that class and
// keeps "key=" (an option such as username= or addr=); Values applies before
// Tokens and Rest.
type Grammar struct {
	Split  string
	Tokens []Class
	Rest   Class
	Values map[string]Class
}

// SortKey is one key of a sort spec: a record field ("" for the element
// itself) compared as a string (bytes) or as a number.
type SortKey struct {
	Field   string
	Numeric bool
}

// SortSpec re-sorts a list after mapping: by Keys in order, stably, and with
// Dedup dropping an element equal to the one before it under every key.
type SortSpec struct {
	Keys  []SortKey
	Dedup bool
}

// FieldRule classifies one table path. Class "" marks a structural path (a
// list, an envelope's value or source, a setting's side): it is classified,
// and what lies under it is classified by its own rows. Home marks a path
// field whose value is the home of the account-class fields of the same
// record (AX-6's homes are built from these).
type FieldRule struct {
	Class   Class
	Grammar *Grammar
	Sort    *SortSpec
	Order   string
	Home    bool
}

// Table classifies every path of a snapshot document (AX-8). Its keys are
// spelled in four namespaces:
//
//   - header rows, by document path from a header root (schema_version, run,
//     synthetic, _expect, _provenance, _notes): run.host.hostname,
//     run.collectors[].reason; "X.*" classifies everything under X;
//   - fact rows, by registry key and value-relative field path: <key> for the
//     value itself, <key>[] for a list element, <key>[].<field> for a record
//     field (nested: <key>[].<field>[].<sub>, <key>.<field> under a record
//     value). Every fact key has its own <key> row;
//   - envelope.<field>: the envelope fields (status, value, source, truncated,
//     reason) of every fact and of every setting side and persona;
//   - setting.<field> (runtime, persisted, effective, winner, personas) and
//     source.<field> (kind, path, line, raw, cmd, exit_code, inputs), the
//     Source rows applied to source, winner and every inputs[] at any depth.
//
// A fact key's value row applies on every side of a setting and on every
// persona. No registry key starts with a header root or a generic set name.
type Table map[string]FieldRule

// Report is what Transform did, for run.anonymization (AX-10): the classes
// that mapped at least one value to something else, and the document paths
// (with [] for any list index) whose values were placeholdered or emptied,
// both sorted.
type Report struct {
	Classes  []string
	Replaced []string
}

// PersonaNames is the closed set of sshd persona keys a setting may carry
// (sshd's personaOrder); a persona name is kept.
var PersonaNames = []string{"invalid", "root", "user"}

var headerRoots = map[string]bool{
	"schema_version": true, "run": true, "synthetic": true, "_expect": true, "_provenance": true, "_notes": true,
}

var genericRoots = map[string]bool{"envelope": true, "setting": true, "source": true}

// reportClasses are the classes run.anonymization.classes may list.
var reportClasses = map[string]bool{
	ClassAccount: true, ClassHost: true, ClassAddress: true, ClassURL: true,
	ClassFingerprint: true, ClassMachineID: true, ClassPath: true, ClassUnit: true,
}

var knownClasses = map[Class]bool{
	"": true, ClassAccount: true, ClassHost: true, ClassAddress: true, ClassURL: true, ClassFingerprint: true,
	ClassMachineID: true, ClassPath: true, ClassHostOrAddr: true, ClassHostOrNetgroup: true, ClassPlaceholder: true,
	ClassBlank: true, ClassKept: true, ClassGrammar: true, ClassUnit: true, ClassFSLocations: true,
}

// Validate checks the table's own shape: every class is known; a Grammar is
// set exactly on a ClassGrammar row, splits on whitespace and gives each
// token a value class; Home marks only a path row; every list (a row that
// some row continues with []) has its own row with an Order, and a Sort
// exactly when the order is sorted; no other row carries an Order or a Sort.
func (t Table) Validate() error {
	lists := map[string]bool{}
	for key := range t {
		for i := strings.Index(key, "[]"); i >= 0; {
			lists[key[:i]] = true
			j := strings.Index(key[i+2:], "[]")
			if j < 0 {
				break
			}
			i += 2 + j
		}
	}
	keys := make([]string, 0, len(t)+len(lists))
	for key := range t {
		keys = append(keys, key)
	}
	for l := range lists {
		if _, ok := t[l]; !ok {
			keys = append(keys, l)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		r, ok := t[key]
		fail := func(why string) error { return fmt.Errorf("anonymization table: %s: %s", key, why) }
		switch {
		case !ok:
			return fail("a list needs its own row with an Order")
		case !knownClasses[r.Class]:
			return fail(fmt.Sprintf("unknown class %q", r.Class))
		case (r.Grammar != nil) != (r.Class == ClassGrammar):
			return fail("a Grammar goes with class grammar and only there")
		case r.Home && r.Class != ClassPath:
			return fail("Home marks a path row")
		}
		if g := r.Grammar; g != nil {
			if g.Split != SplitWhitespace && g.Split != SplitComma {
				return fail(fmt.Sprintf("unknown grammar split %q", g.Split))
			}
			classes := append(append([]Class(nil), g.Tokens...), g.Rest)
			names := make([]string, 0, len(g.Values))
			for n := range g.Values {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if n == "" || strings.ContainsAny(n, "=,") {
					return fail(fmt.Sprintf("grammar value key %q", n))
				}
				classes = append(classes, g.Values[n])
			}
			for _, c := range classes {
				if c == "" || c == ClassGrammar || !knownClasses[c] {
					return fail(fmt.Sprintf("grammar token class %q is not a value class", c))
				}
			}
		}
		if !lists[key] {
			if r.Order != "" || r.Sort != nil {
				return fail("an Order or a Sort on a row that is no list")
			}
			continue
		}
		switch {
		case r.Order != OrderKept && r.Order != OrderSorted:
			return fail(fmt.Sprintf("a list needs Order %q or %q, not %q", OrderKept, OrderSorted, r.Order))
		case (r.Sort != nil) != (r.Order == OrderSorted):
			return fail("a Sort goes with the sorted order and only there")
		case r.Sort != nil && len(r.Sort.Keys) == 0:
			return fail("a Sort needs at least one key")
		}
	}
	return nil
}
