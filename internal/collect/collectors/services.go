//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	systemctlPath = "/usr/bin/systemctl"
	systemdMarker = "/run/systemd/system"
	inetdConf     = "/etc/inetd.conf"
	xinetdGlob    = "/etc/xinetd.d/*"
	telnetPort    = 23
)

// showCmd is the single systemctl invocation this collector makes per unit.
// The four properties are one round trip; stage 1 reads LoadState and
// ActiveState from the answer, and asking for UnitFileState and SubState
// here keeps the declared command — the one --list-actions prints and a
// change-control reviewer approves — the same one stage 2 will keep using.
func showCmd(unit string) collect.Command {
	return collect.Command{
		Path: systemctlPath,
		Args: []string{"show", "-p", "LoadState,ActiveState,UnitFileState,SubState", unit},
	}
}

// unitRef is one systemd unit and whether its being loaded proves the
// logical service is installed. R63: inetd and xinetd are asked about so
// that "systemd did not answer at all" can be told apart from "systemd says
// there is no telnet unit", but a loaded super-server does not by itself
// mean telnet is installed — only a telnet unit does, or a telnet entry in
// the super-server's own configuration.
type unitRef struct {
	name          string
	provesInstall bool
}

// logicalUnits maps the logical service a control asks about to the units
// that may implement it. Every use iterates it in sorted key order (R48) so
// the commands run, and the keys are written, in the same order each run.
var logicalUnits = map[string][]unitRef{
	"ssh": {
		{"ssh.service", true},
		{"sshd.service", true},
		{"ssh.socket", true},
	},
	"telnet": {
		{"telnet.socket", true},
		{"telnet.service", true},
		{"telnetd.service", true},
		{"inetd.service", false},
		{"xinetd.service", false},
	},
}

// declaredShowCommands lists every systemctl invocation the collector may
// make, derived from logicalUnits so the declaration can never drift from
// the commands actually run.
func declaredShowCommands() []collect.Command {
	var out []collect.Command
	for _, name := range slices.Sorted(maps.Keys(logicalUnits)) {
		for _, u := range logicalUnits[name] {
			out = append(out, showCmd(u.name))
		}
	}
	return out
}

var servicesCollector = collect.Collector{
	Name: "services",
	Declare: collect.Declaration{
		Reads:    append([]string{systemdMarker, inetdConf, xinetdGlob}, procNetPaths()...),
		Commands: declaredShowCommands(),
		Needs:    "none",
	},
	Run: runServices,
}

// xinetdTelnet matches the two non-comment shapes a telnet service takes in
// an xinetd fragment (R63).
var xinetdTelnet = regexp.MustCompile(`^service\s+telnet\b|^server\s*=.*telnetd`)

// showValues parses the "Key=Value" lines systemctl show prints.
func showValues(stdout []byte) (load, active string) {
	for _, line := range splitLines(stdout) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			load = v
		case "ActiveState":
			active = v
		}
	}
	return load, active
}

// groupState is what systemd said about one logical service.
type groupState struct {
	// complete is false as soon as ONE queried unit did not answer. The
	// judgement has to be made unit by unit, not over the group as a
	// whole: if ssh.service times out and sshd.service answers not-found,
	// a group-level "something answered" would publish installed=false on
	// evidence that never covered ssh.service — the unit most likely to
	// have been the one that mattered. Any gap therefore means the caller
	// writes firstFailure instead of a value.
	complete  bool
	installed bool
	active    bool
	truncated bool
	src       *facts.Source

	// firstFailure is the FIRST unit that did not answer: the one whose
	// absence from the evidence a reader has to know about. Later failures
	// are usually the same cause repeated.
	firstFailure facts.Envelope
}

// fail records a unit that did not answer, keeping the first one only.
func (g *groupState) fail(e facts.Envelope) {
	if g.complete {
		g.complete, g.firstFailure = false, e
	}
}

// probeUnits asks systemctl about each unit of a logical service in turn.
func probeUnits(ctx context.Context, a collect.Access, units []unitRef) groupState {
	g := groupState{complete: true}
	for _, u := range units {
		cmd := showCmd(u.name)
		out := a.Run(ctx, cmd)
		src := out.Source(cmd)
		switch {
		case out.TimedOut:
			e := collect.TimeoutEnv("systemctl show " + u.name + " timed out")
			e.Source = src
			g.fail(withTruncation(e, out.Truncated))
			continue
		case out.Err != nil, out.ExitCode != 0:
			g.fail(commandFailure("systemctl show "+u.name, out, src))
			continue
		}
		g.truncated = g.truncated || out.Truncated
		if g.src == nil {
			g.src = src
		}
		load, active := showValues(out.Stdout)
		if load == "loaded" && u.provesInstall && !g.installed {
			g.installed, g.src = true, src
		}
		// A socket unit that is listening reports ActiveState=active too,
		// so there is nothing else to look at here.
		if active == "active" {
			g.active = true
		}
	}
	return g
}

func runServices(ctx context.Context, a collect.Access, b *collect.Builder) error {
	if _, err := a.Stat(systemdMarker); err != nil {
		for _, k := range []string{
			"services.ssh.installed", "services.ssh.active",
			"services.telnet.installed", "services.telnet.reachable",
		} {
			b.Set(k, collect.Unsupported("no systemd on this host or inside this container"))
		}
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(logicalUnits)) {
		g := probeUnits(ctx, a, logicalUnits[name])
		switch name {
		case "ssh":
			setSSH(b, g)
		case "telnet":
			setTelnet(b, a, g)
		}
	}
	return nil
}

func setSSH(b *collect.Builder, g groupState) {
	if !g.complete {
		b.Set("services.ssh.installed", g.firstFailure)
		b.Set("services.ssh.active", g.firstFailure)
		return
	}
	b.Set("services.ssh.installed", withTruncation(collect.OK(g.installed, g.src), g.truncated))
	if !g.installed {
		b.Set("services.ssh.active", collect.Absent("no ssh unit is loaded on this host"))
		return
	}
	b.Set("services.ssh.active", withTruncation(collect.OK(g.active, g.src), g.truncated))
}

func setTelnet(b *collect.Builder, a collect.Access, g groupState) {
	setTelnetInstalled(b, a, g)
	setTelnetReachable(b, a)
}

func setTelnetInstalled(b *collect.Builder, a collect.Access, g groupState) {
	// systemd swept every telnet unit and found one loaded: the legacy
	// super-server configuration cannot make that less true, so it is not
	// read at all.
	if g.complete && g.installed {
		b.Set("services.telnet.installed", withTruncation(collect.OK(true, g.src), g.truncated))
		return
	}
	found, problem := telnetFromLegacy(a)
	switch {
	case found != nil:
		// Positive evidence stands on its own, whatever systemd managed.
		b.Set("services.telnet.installed", *found)
	case !g.complete:
		b.Set("services.telnet.installed", g.firstFailure)
	case problem != nil:
		// A super-server configuration we could not read might have named
		// telnet, so "not installed" would be a guess, not a fact.
		b.Set("services.telnet.installed", *problem)
	default:
		b.Set("services.telnet.installed", withTruncation(collect.OK(false, g.src), g.truncated))
	}
}

func setTelnetReachable(b *collect.Builder, a collect.Access) {
	// R41: reachable is decided by the listening-socket table alone and is
	// written as false only when that table was actually read. An unseen
	// table is never a PASS.
	t, err := listeningSockets(a)
	switch {
	case err != nil:
		b.Set("services.telnet.reachable", collect.FromReadError(err, collect.ReadMeta{}))
	case t.truncated:
		b.Set("services.telnet.reachable", collect.ErrorEnv("the listening-socket table was truncated at its read limit"))
	default:
		b.Set("services.telnet.reachable", collect.OK(hasNonLoopbackTCPPort(t.list, telnetPort), t.src))
	}
}

// telnetFromLegacy looks for telnet where it lived before systemd:
// /etc/inetd.conf and the xinetd fragment directory. Only a non-comment
// line counts (R63).
//
// found is the ready-made "installed" envelope when there is positive
// evidence, carrying the line it came from and that read's truncation flag
// (R70). problem is set instead when a file that could have carried the
// evidence was unreadable, so the caller does not report a "not installed"
// it cannot stand behind.
func telnetFromLegacy(a collect.Access) (found, problem *facts.Envelope) {
	data, meta, err := a.ReadFile(inetdConf, readLimit)
	switch {
	case err == nil:
		for i, raw := range splitLines(data) {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "telnet") {
				e := collect.OKRead(true, &facts.Source{
					Kind: "file", Path: inetdConf, Line: i + 1, Raw: sourceRaw(raw),
				}, meta)
				return &e, nil
			}
		}
	case !errors.Is(err, fs.ErrNotExist):
		e := collect.FromReadError(err, meta)
		return nil, &e
	}

	paths, _ := a.Glob(xinetdGlob)
	slices.Sort(paths)
	for _, p := range paths {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			// A directory or device the glob happened to name is not a
			// fragment and carries no evidence either way.
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, collect.ErrNotRegular) {
				continue
			}
			e := collect.FromReadError(err, meta)
			return nil, &e
		}
		for i, raw := range splitLines(data) {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if xinetdTelnet.MatchString(line) {
				e := collect.OKRead(true, &facts.Source{
					Kind: "file", Path: p, Line: i + 1, Raw: sourceRaw(raw),
				}, meta)
				return &e, nil
			}
		}
	}
	return nil, nil
}

// hasNonLoopbackTCPPort reports whether a listening TCP socket on port is
// bound somewhere reachable from off the host.
func hasNonLoopbackTCPPort(list []any, port int) bool {
	for _, s := range list {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		proto, _ := m["proto"].(string)
		p, _ := m["port"].(int)
		loopback, _ := m["loopback"].(bool)
		if strings.HasPrefix(proto, "tcp") && p == port && !loopback {
			return true
		}
	}
	return false
}
