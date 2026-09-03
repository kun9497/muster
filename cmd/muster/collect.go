//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	// Importing the collectors registers them; nothing here calls into the
	// package directly.
	_ "github.com/kun9497/muster/internal/collect/collectors"
	"github.com/kun9497/muster/internal/controls"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	co, err := parseCollectFlags(args)
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n%s", err, collectUsage)
		return exitError
	}
	if co.listActions {
		// The action list is the whole output: the document a
		// change-control reviewer reads, and stdout carries nothing else.
		if err := collect.WriteActions(stdout, collect.ListActions(), co.format); err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		return exitOK
	}
	// R47/R76: --deep is accepted so a stage-3 command line runs today, but
	// the walk itself is stage 3 and run.deep stays false.
	if co.deep {
		fmt.Fprintln(stderr, "muster: warning: deep walk arrives in stage 3; walk facts not collected")
	}
	if os.Geteuid() != 0 && !co.requireRoot {
		fmt.Fprintln(stderr, "muster: warning: not running as root; expect denied facts")
	}
	// R67: the header records which control set the collecting binary
	// carried, so a snapshot and a later check can be compared. collect
	// never parses a control file on the host — this is the embedded set.
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	out, err := collect.Run(context.Background(), collect.Options{
		Out: co.out, Force: co.force, Timeout: co.timeout, RequireRoot: co.requireRoot,
		Version: version, Commit: commit,
		ControlsVersion: set.Version, ControlsDigest: set.Digest,
	}, stdout)
	if err != nil {
		// The writer's own refusals already say what happened and which
		// path it happened to; "collect failed:" in front of them would
		// only bury the sentence the operator has to act on (R83).
		if errors.Is(err, collect.ErrLocked) || errors.Is(err, collect.ErrNotRoot) ||
			errors.Is(err, collect.ErrExists) || errors.Is(err, collect.ErrOutputSymlink) {
			fmt.Fprintf(stderr, "muster: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "muster: collect failed: %v\n", err)
		}
		return exitError
	}
	for _, w := range out.Warnings {
		fmt.Fprintf(stderr, "muster: warning: %s\n", w)
	}
	if out.Complete {
		fmt.Fprintf(stderr, "muster: wrote %s (complete)\n", out.Path)
	} else {
		fmt.Fprintf(stderr, "muster: wrote %s (partial: %s)\n", out.Path, strings.Join(out.Partial, ", "))
	}
	return collect.ExitCodeFor(out, nil, co.requireComplete)
}
