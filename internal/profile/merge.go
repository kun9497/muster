package profile

import (
	"fmt"
	"sort"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/tuning"
)

// Merge computes the parameter values in force for every selected control
// that declares params — default < profile < tuning — and each value's
// source. A profile or tuning value for a control the selection excludes
// is warned once per (control, parameter) and dropped (Y-8). t may be nil.
func Merge(set *controls.Set, r *Resolved, t *tuning.Tuning, warn func(string)) (map[string]map[string]any, map[string]map[string]string) {
	selected := map[string]bool{}
	for _, id := range r.IDs {
		selected[id] = true
	}
	params := map[string]map[string]any{}
	sources := map[string]map[string]string{}
	var tparams map[string]map[string]any
	if t != nil {
		tparams = t.Params
	}
	for i := range set.Controls {
		c := &set.Controls[i]
		if !selected[c.ID] {
			for _, n := range sortedKeys(r.Params[c.ID]) {
				warn(fmt.Sprintf("profile parameter %s.%s ignored: excluded by profile", c.ID, n))
			}
			for _, n := range sortedKeys(tparams[c.ID]) {
				warn(fmt.Sprintf("tuning parameter %s.%s ignored: excluded by profile", c.ID, n))
			}
			continue
		}
		if len(c.Params) == 0 {
			continue
		}
		params[c.ID] = map[string]any{}
		sources[c.ID] = map[string]string{}
		for _, n := range c.SortedParamNames() {
			params[c.ID][n], sources[c.ID][n] = c.Params[n].Default, "default"
			if v, ok := r.Params[c.ID][n]; ok {
				params[c.ID][n], sources[c.ID][n] = v, "profile"
			}
			if v, ok := tparams[c.ID][n]; ok {
				params[c.ID][n], sources[c.ID][n] = v, "tuning"
			}
		}
	}
	return params, sources
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
