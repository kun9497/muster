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
// how many the check engine reads on its own; Unused names the rest, in the
// order the registry lists them.
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
// A key the engine reads is counted in Engine and nowhere else, even in the
// impossible case of a control naming it: Engine is then a property of the
// registry and the hand-maintained engineReadKeys list alone, which is what
// makes it worth reading as a check on that list.
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
		case engineReadKeys[e.Key]:
			u.Engine++
		case used[e.Key]:
			u.Used++
		default:
			u.Unused = append(u.Unused, e.Key)
		}
	}
	return out
}

// UnusedKeys returns the registered fact keys no control in s references
// (spec §5.5), grouped by collector in the order FactUsage reports them. It
// is a note rather than a lint failure: some keys are read by the evaluator
// itself (see engineReadKeys) and others are collected for controls that do
// not exist yet.
func UnusedKeys(s *Set, reg *facts.Registry) []string {
	var out []string
	for _, u := range FactUsage(s, reg) {
		out = append(out, u.Unused...)
	}
	return out
}
