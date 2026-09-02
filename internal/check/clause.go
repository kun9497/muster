package check

import (
	"fmt"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// env is one evaluation's context: the snapshot, the registry, the parameter
// values in force and whether sshd personas were collected.
type env struct {
	snap     *facts.Snapshot
	reg      *facts.Registry
	params   map[string]any
	personas bool
}

// clauseOutcome is what one clause decided and the evidence it used.
type clauseOutcome struct {
	Holds        bool
	Evidence     []Evidence
	Observations []Observation
	Degraded     string
	Err          error
}

// personasCollected reads sshd.personas_collected; false when absent.
func personasCollected(s *facts.Snapshot, reg *facts.Registry) bool {
	r, err := reg.Resolve(s, "sshd.personas_collected")
	if err != nil || r.Envelope == nil || r.Envelope.Status != facts.StatusOK {
		return false
	}
	b, _ := r.Envelope.Value.(bool)
	return b
}

// evalClause evaluates one top-level clause whose facts the caller has
// already screened for non-ok statuses (spec §6.5 steps 6-8 run first). A
// non-ok envelope reaching here is therefore an internal error.
func (e *env) evalClause(cl controls.Clause) clauseOutcome {
	r, err := e.reg.Resolve(e.snap, cl.Fact)
	if err != nil {
		return clauseOutcome{Err: err}
	}
	expected, err := substitute(cl.Expected, e.params)
	if err != nil {
		return clauseOutcome{Err: err}
	}
	if cl.Op == "each" || cl.Op == "none" {
		if r.Envelope == nil || r.Envelope.Status != facts.StatusOK {
			return clauseOutcome{Err: fmt.Errorf("fact %s is not ok", cl.Fact)}
		}
		list, ok := r.Envelope.Value.([]any)
		if !ok {
			return clauseOutcome{Err: fmt.Errorf("fact %s is not a list", cl.Fact)}
		}
		return e.evalCollection(cl, r.Entry, list, r.Envelope.Source)
	}
	if r.Setting != nil {
		return e.evalSetting(cl, r, expected)
	}
	if r.Envelope.Status != facts.StatusOK {
		return clauseOutcome{Err: fmt.Errorf("fact %s has status %s", cl.Fact, r.Envelope.Status)}
	}
	holds, err := compare(cl.Op, r.Envelope.Value, expected, r.Entry.Type)
	if err != nil {
		return clauseOutcome{Err: fmt.Errorf("%s: %w", cl.Fact, err)}
	}
	return clauseOutcome{Holds: holds, Evidence: []Evidence{{Fact: cl.Fact, Status: facts.StatusOK, Value: r.Envelope.Value, Source: r.Envelope.Source}}}
}

// evalSetting applies `on` (default from the registry) to a two-home setting
// (spec §5.3, §6.3). With both, one side holding and the other not is
// reported as degraded so the derivation table can make it WARN.
func (e *env) evalSetting(cl controls.Clause, r facts.Resolved, expected any) clauseOutcome {
	on := cl.On
	if on == "" {
		on = r.Entry.DefaultOn
	}
	var degraded string
	if cl.Persona != "" && !e.personas {
		degraded = "personas not collected"
	}
	side := func(name string, env *facts.Envelope) (bool, Evidence, error) {
		if env == nil {
			return false, Evidence{Fact: cl.Fact, Status: facts.StatusAbsent, Side: name}, nil
		}
		if env.Status != facts.StatusOK {
			return false, Evidence{Fact: cl.Fact, Status: env.Status, Side: name, Source: env.Source}, fmt.Errorf("fact %s side %s has status %s", cl.Fact, name, env.Status)
		}
		ok, err := compare(cl.Op, env.Value, expected, r.Entry.Type)
		return ok, Evidence{Fact: cl.Fact, Status: facts.StatusOK, Value: env.Value, Source: env.Source, Side: name}, err
	}
	switch on {
	case "runtime", "persisted", "effective":
		var env *facts.Envelope
		switch on {
		case "runtime":
			env = r.Setting.Runtime
		case "persisted":
			env = r.Setting.Persisted
		default:
			env = r.Setting.Effective
		}
		if env == nil {
			return clauseOutcome{Err: fmt.Errorf("fact %s has no %s side", cl.Fact, on)}
		}
		holds, ev, err := side(on, env)
		if err != nil {
			return clauseOutcome{Err: err}
		}
		return clauseOutcome{Holds: holds, Evidence: []Evidence{ev}, Degraded: degraded}
	case "both":
		rh, rev, rerr := side("runtime", r.Setting.Runtime)
		ph, pev, perr := side("persisted", r.Setting.Persisted)
		if rerr != nil {
			return clauseOutcome{Err: rerr}
		}
		if perr != nil {
			return clauseOutcome{Err: perr}
		}
		out := clauseOutcome{Holds: rh && ph, Evidence: []Evidence{rev, pev}, Degraded: degraded}
		switch {
		case rh && !ph:
			out.Degraded = "reverts on reboot"
		case ph && !rh:
			out.Degraded = "not applied"
		}
		return out
	}
	return clauseOutcome{Err: fmt.Errorf("unknown side %q", on)}
}
