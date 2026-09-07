// Package facts defines the snapshot that collect writes and check reads:
// the run header, the fact envelope, two-home settings and the key registry
// (spec §5).
package facts

// Status is the collection status of one fact. The six collector statuses are
// written by collect; StatusMissing exists only on the reading side and is
// synthesised by check for a registered key the snapshot does not carry
// (spec §5.2, D07).
type Status string

const (
	StatusOK          Status = "ok"
	StatusAbsent      Status = "absent"      // the collector looked; the thing does not exist
	StatusDenied      Status = "denied"      // insufficient privilege; Reason names it
	StatusUnsupported Status = "unsupported" // this distribution or environment has no such mechanism
	StatusTimeout     Status = "timeout"
	StatusError       Status = "error"
	StatusMissing     Status = "missing" // reader-side only; never written by collect
)

// Valid reports whether s is one of the six statuses a collector may write.
func (s Status) Valid() bool {
	switch s {
	case StatusOK, StatusAbsent, StatusDenied, StatusUnsupported, StatusTimeout, StatusError:
		return true
	}
	return false
}

// CanPass reports whether a clause over a fact with this status may produce
// PASS. Only "ok" can; everything else is decided by the derivation table
// (spec §6.5) and never reaches a clause.
func (s Status) CanPass() bool { return s == StatusOK }

// Source says where a value came from (spec §5.2, D08). For Kind "derived",
// Path and Line are empty and Inputs lists every source the value was
// computed from, in evaluation order.
type Source struct {
	Kind     string   `json:"kind"` // file | command | proc | sys | derived
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Raw      string   `json:"raw,omitempty"` // the source line itself, length-capped by the collector
	Cmd      string   `json:"cmd,omitempty"`
	ExitCode *int     `json:"exit_code,omitempty"`
	Inputs   []Source `json:"inputs,omitempty"`
}

// Envelope is every leaf under "facts" (spec §5.2). Value is nil unless
// Status is "ok"; its Go type after JSON decoding is string, float64, bool,
// []any or map[string]any, and the registry entry says which is expected.
type Envelope struct {
	Status    Status  `json:"status"`
	Value     any     `json:"value,omitempty"`
	Source    *Source `json:"source,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Reason    string  `json:"reason,omitempty"` // required privilege, limit hit, or error text
}

// Setting is a value that lives both in the running kernel or daemon and in
// a persisted file (spec §5.3, D10). The sides are selected only by a
// clause's `on:`; no fact key contains a side name.
type Setting struct {
	Runtime   *Envelope `json:"runtime,omitempty"`
	Persisted *Envelope `json:"persisted,omitempty"`
	Effective *Envelope `json:"effective,omitempty"`
	Winner    *Source   `json:"winner,omitempty"`
	// Personas holds a per-persona (sshd Match) daemon value, keyed by
	// persona name, stored only where it differs from the global side; nil
	// when personas were not collected or none override the global value.
	Personas map[string]*Envelope `json:"personas,omitempty"`
}

// Missing builds the reader-side envelope for a registered key the snapshot
// does not carry. It is never resolved by absent_means and always yields
// ERROR(missing_fact) (spec §5.2, §5.7).
func Missing(key string) *Envelope {
	return &Envelope{Status: StatusMissing, Reason: "key " + key + " is not present in this snapshot"}
}
