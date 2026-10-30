package anonymize

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

// SplitWhitespace is the one tokenizer of a read-text grammar: runs of spaces
// and tabs separate tokens, and are kept as they were.
const SplitWhitespace = "whitespace"

// Grammar rewrites a read-text value token by token (AX-7): token i by
// Tokens[i], every token past them by Rest. A bare "+" or "-" is kept; a
// leading "+" or "-" before a name is kept and the name mapped by the class.
type Grammar struct {
	Split  string
	Tokens []Class
	Rest   Class
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
	ClassFingerprint: true, ClassMachineID: true, ClassPath: true,
}
