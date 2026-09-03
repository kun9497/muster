//go:build linux

package collectors

import (
	"context"

	"github.com/kun9497/muster/internal/collect"
)

// walkCollector is the stage-1 placeholder for the deep filesystem walk.
//
// R47/R76: it declares nothing, touches nothing and writes no fact key, so
// walk.world_writable and walk.complete stay absent from every stage-1
// snapshot and the control that needs them (U-25) resolves to MANUAL
// through its absent_means. Registering it here still puts "walk" in the
// registry, so the run header names it and a reader can see that the
// collector exists and produced nothing. --list-actions has no row for it:
// that document lists declared reads and commands, and a collector that
// declares neither contributes none — which is itself the accurate answer
// while the walk touches nothing. The --deep flag and the warning that the
// traversal is not implemented yet live in the collect command (Task 6);
// the traversal itself arrives in stage 3.
var walkCollector = collect.Collector{
	Name:    "walk",
	Declare: collect.Declaration{Needs: "root"},
	Run: func(context.Context, collect.Access, *collect.Builder) error {
		return nil
	},
}
