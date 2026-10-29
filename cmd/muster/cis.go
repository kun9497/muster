package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/profile"
)

// hostWarning is the CB-11 warning check and fix --dry-run give; a variable
// only so a test can compare a run with and without it.
var hostWarning = warnCISHost

// warnCISHost warns, once, when the chain root is a CIS built-in whose
// benchmark does not cover the snapshot's host (CB-11). It never changes the
// result or the exit code: the profile still evaluates where it was asked to.
func warnCISHost(chain []string, rel facts.OSRelease, warn func(string)) {
	c, ok := profile.CISRoot(chain)
	if !ok || c.Matches(rel.ID, rel.VersionID) {
		return
	}
	targets := strings.Join(c.Targets, ", ")
	if rel.ID == "" || rel.VersionID == "" {
		warn(fmt.Sprintf("profile %s is built for %s; the snapshot's os release is unknown", c.Profile, targets))
		return
	}
	warn(fmt.Sprintf("profile %s is built for %s; the snapshot is %s %s", c.Profile, targets, rel.ID, rel.VersionID))
}

// lintCISProfile is Y-1's rule (CB-10): every control a profile rooted in a
// CIS built-in selects carries a references.cis entry on that benchmark —
// with idx, one whose indexed levels include l1_server; without, any entry on
// the benchmark (shapeOnlyNote says the levels were not checked). One line
// per control, in the subset's order; nil for a profile with no CIS root.
func lintCISProfile(sel *Selection, idx *controls.ReferenceIndex) []string {
	c, ok := profile.CISRoot(sel.Profile.Extends)
	if !ok {
		return nil
	}
	var out []string
	for _, ctl := range sel.Subset.Controls {
		found := false
		for _, r := range ctl.References.CIS {
			if r.Benchmark != c.Benchmark {
				continue
			}
			if idx == nil {
				found = true
				break
			}
			if lv, ok := idx.CISLevels(r.Benchmark, r.Version, r.Rec); ok && slices.Contains(lv, "l1_server") {
				found = true
				break
			}
		}
		if found {
			continue
		}
		msg := fmt.Sprintf("profile %s selects %s, which carries no %s CIS reference", sel.Profile.Name, ctl.ID, c.Benchmark)
		if idx != nil {
			msg += " at Level 1 – Server"
		}
		out = append(out, msg)
	}
	return out
}
