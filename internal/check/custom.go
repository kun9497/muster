package check

import "github.com/kun9497/muster/internal/controls"

// CustomFunc is the overflow for what the YAML vocabulary cannot express
// (spec §6.3). It reads only facts through e and returns a clause outcome.
type CustomFunc func(e *env, c *controls.Control) clauseOutcome

// customs is the registry lint consults through CustomFuncs(). Stage 1 has
// none; later stages register functions from an init() in this package.
var customs = map[string]CustomFunc{}

// CustomFuncs returns the registered names, for lint.
func CustomFuncs() map[string]bool {
	out := make(map[string]bool, len(customs))
	for name := range customs {
		out[name] = true
	}
	return out
}
