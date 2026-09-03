package main

import (
	"fmt"
	"time"
)

const collectUsage = `usage: muster collect [flags]

flags:
  --out <path|->        snapshot path (default /var/lib/muster/snapshots/<host>-<time>-<digest>.json)
  --force               overwrite an existing --out path
  --deep                run the filesystem walk (stage 3; not collected in stage 1)
  --timeout <duration>  global deadline (default 5m)
  --require-root        exit 2 without writing when not root
  --require-complete    exit 2 (instead of 1) when the snapshot is partial
  --list-actions        print every path read, command run and the file written, then exit
  --format table|json   with --list-actions (default table)
`

// collectOpts is the parsed command line. It is deliberately not
// collect.Options: that type is Linux-only, and this parser is shared with
// the build for every other platform (R58), which must reject an unknown
// flag exactly the way Linux does before it says collect needs Linux.
type collectOpts struct {
	out             string
	force           bool
	deep            bool
	timeout         time.Duration
	requireRoot     bool
	requireComplete bool
	listActions     bool
	format          string
}

func parseCollectFlags(args []string) (collectOpts, error) {
	o := collectOpts{format: "table"}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--out":
			o.out, err = next()
		case "--format":
			o.format, err = next()
		case "--timeout":
			var v string
			if v, err = next(); err == nil {
				if o.timeout, err = time.ParseDuration(v); err != nil {
					err = fmt.Errorf("--timeout: %w", err)
				}
			}
		case "--force":
			o.force = true
		case "--deep":
			o.deep = true
		case "--require-root":
			o.requireRoot = true
		case "--require-complete":
			o.requireComplete = true
		case "--list-actions":
			o.listActions = true
		default:
			return o, fmt.Errorf("unknown flag %s", a)
		}
		if err != nil {
			return o, err
		}
	}
	if o.format != "table" && o.format != "json" {
		return o, fmt.Errorf("--format must be table or json, got %q", o.format)
	}
	return o, nil
}
