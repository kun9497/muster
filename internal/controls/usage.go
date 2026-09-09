package controls

import (
	"github.com/kun9497/muster/internal/facts"
)

// engineReadKeys are registered fact keys the check engine (internal/check)
// resolves directly against the registry rather than through a control's
// declarative Checks/AppliesWhen clauses, so no control ever names them in a
// Fact field: walk.complete gates the walk, sshd.collect_method decides the
// sshd parse-fallback degradation, sshd.personas_collected decides persona
// evaluation, and accounts.nss.remote decides the remote-NSS degradation
// (eval.go, clause.go). The report must not call these unused; nothing in a
// control file could ever make that report go away. The list is
// hand-maintained, and the report is where a forgotten entry becomes
// visible: a key dropped from the engine but left here shows up as engine-
// read in a collector that has no business having one (M-3).
var engineReadKeys = set("walk.complete", "sshd.collect_method", "sshd.personas_collected", "accounts.nss.remote")

// CollectorUsage is the fact-key report for one collector (spec §11: facts
// used, not facts collected). Registered is how many keys the registry files
// under the collector; Used is how many of them at least one control names,
// whether to judge them or to hand them to a reviewer as evidence; Engine is
// how many of the rest the check engine reads on its own; Unused names what
// is left, in the order the registry lists it.
//
// Used, Engine and len(Unused) partition Registered, so the three numbers
// always add up to it.
type CollectorUsage struct {
	Collector  string
	Registered int
	Used       int
	Engine     int
	Unused     []string
}

// FactUsage reports, per collector, how much of what muster collects any
// control actually reads (spec §11). Collectors come in the order the
// registry first mentions them and the unused keys in registry order, so the
// report is a stable rendering of registry order rather than of map order.
//
// M-41: a key a control names is Used, whatever else reads it -- that is
// what the headline number claims. Engine therefore counts the engine-read
// keys no control cites, which is the number worth reading as a check on the
// hand-maintained list: an entry there that a control has since taken over
// stops being counted, and one for a key nothing reads any more shows up as
// an engine key in a collector that should have none.
func FactUsage(s *Set, reg *facts.Registry) []CollectorUsage {
	used := map[string]bool{}
	mark := func(cls []Clause) {
		for _, cl := range cls {
			if cl.Fact != "" {
				used[cl.Fact] = true
			}
		}
	}
	for i := range s.Controls {
		c := &s.Controls[i]
		mark(c.AppliesWhen)
		mark(c.Checks)
		for _, m := range c.Mechanisms {
			mark(m.When)
			mark(m.Checks)
		}
		// M-8: a manual control judges nothing but names the facts the
		// reviewer needs in hand. Those facts are collected for a reason,
		// which is precisely what "used" means here.
		for _, k := range c.Evidence {
			used[k] = true
		}
	}
	var out []CollectorUsage
	at := map[string]int{}
	for _, e := range reg.Keys {
		i, seen := at[e.Collector]
		if !seen {
			i = len(out)
			at[e.Collector] = i
			out = append(out, CollectorUsage{Collector: e.Collector})
		}
		u := &out[i]
		u.Registered++
		switch {
		case used[e.Key]:
			u.Used++
		case engineReadKeys[e.Key]:
			u.Engine++
		default:
			u.Unused = append(u.Unused, e.Key)
		}
	}
	return out
}

// Totals folds a report into the three numbers both renderers state: how
// many keys are registered, how many a control reads and how many only the
// engine reads. The unused count is len of the key list, which every caller
// has anyway (UnusedKeys), and registered - used - engine besides.
func Totals(usage []CollectorUsage) (registered, used, engine int) {
	for _, u := range usage {
		registered += u.Registered
		used += u.Used
		engine += u.Engine
	}
	return registered, used, engine
}

// UnusedKeys returns the registered fact keys no control in s references, in
// registry order (spec §5.5). It is a note rather than a lint failure: some
// keys are read by the evaluator itself (see engineReadKeys) and others are
// collected for controls that do not exist yet.
//
// It is derived from FactUsage so the note and the table can never disagree
// about what is unused (M-3), but it answers in the registry's order rather
// than the report's: a collector may hold several non-contiguous runs of
// keys, so the two orders differ (M-40).
func UnusedKeys(s *Set, reg *facts.Registry) []string {
	unused := map[string]bool{}
	for _, u := range FactUsage(s, reg) {
		for _, k := range u.Unused {
			unused[k] = true
		}
	}
	var out []string
	for _, e := range reg.Keys {
		if unused[e.Key] {
			out = append(out, e.Key)
		}
	}
	return out
}
