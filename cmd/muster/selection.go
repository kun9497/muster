package main

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/profile"
	"github.com/kun9497/muster/internal/report"
	"github.com/kun9497/muster/internal/tuning"
)

// Selection is what check evaluates: the profile's subset of the control
// set, the parameter values in force with their sources, the severity map
// and the two provenance blocks (stage 3D-1, spec §5).
type Selection struct {
	Subset       *controls.Set
	Params       map[string]map[string]any
	Sources      map[string]map[string]string
	SeverityByID map[string]string
	Known        map[string]bool // the subset's ids
	Excluded     map[string]bool // the loaded set's ids the profile does not select
	Profile      report.ProfileBlock
	Tuning       *report.TuningBlock
}

// resolveSelection is the one seam check, controls lint/list --profile, the
// examples test and (3D-2) fix share: the trusted-file rule, the profile
// resolution, the tuning load, the merge and the subset -- no logic of its
// own beyond the wiring (main design §4.2). set must be the full loaded set:
// the merge warns about values for the controls the profile excludes, which a
// subset no longer names.
func resolveSelection(profileArg, tuningPath string, set *controls.Set, warn func(string)) (*Selection, error) {
	open := func(p string) ([]byte, error) {
		if ok, why := trustedFile(p); !ok {
			return nil, fmt.Errorf("refusing %s: %s", p, why)
		}
		return os.ReadFile(p)
	}
	r, err := profile.Resolve(set, profile.SourceOf(profileArg), open, warn)
	if err != nil {
		return nil, err
	}
	var tn *tuning.Tuning
	var tb *report.TuningBlock
	if tuningPath != "" {
		if tn, err = tuning.Load(set, tuningPath, open); err != nil {
			return nil, err
		}
		tb = &report.TuningBlock{Path: tn.Path, Digest: tn.Digest}
	}
	params, sources := profile.Merge(set, r, tn, warn)
	sel := &Selection{Subset: set.Subset(r.IDs), Params: params, Sources: sources, SeverityByID: r.SeverityByID,
		Known: map[string]bool{}, Excluded: map[string]bool{}, Tuning: tb}
	for _, id := range r.IDs {
		sel.Known[id] = true
	}
	excluded := []string{}
	for _, c := range set.Controls {
		if !sel.Known[c.ID] {
			sel.Excluded[c.ID] = true
			excluded = append(excluded, c.ID)
		}
	}
	sort.Strings(excluded)
	sel.Profile = report.ProfileBlock{Name: r.Name, Source: r.Source, Digest: r.Digest, Extends: r.Chain,
		Selected: len(r.IDs), Excluded: len(excluded), ExcludedIDs: excluded}
	return sel, nil
}

// warnTo is the one warning sink check and controls lint/list share: every
// warning is one stderr line with the command's prefix (spec §7.4).
func warnTo(w io.Writer) func(string) {
	return func(msg string) { fmt.Fprintf(w, "muster: warning: %s\n", msg) }
}
