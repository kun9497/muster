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
	// answered is false when not one query ran. Reporting "not installed"
	// on no answer at all would be a PASS on no evidence, so the caller
	// writes failure instead.
	answered  bool
	installed bool
	active    bool
	src       *facts.Source
	failure   facts.Envelope
}

// probeUnits asks systemctl about each unit of a logical service in turn.
func probeUnits(ctx context.Context, a collect.Access, units []unitRef) groupState {
	g := groupState{failure: collect.ErrorEnv("systemctl show did not run")}
	for _, u := range units {
		cmd := showCmd(u.name)
		out := a.Run(ctx, cmd)
		src := out.Source(cmd)
		switch {
		case out.TimedOut:
			g.failure = collect.TimeoutEnv("systemctl show " + u.name + " timed out")
			g.failure.Source = src
			continue
		case out.Err != nil, out.ExitCode != 0:
			g.failure = commandFailure("systemctl show "+u.name, out, src)
			continue
		}
		g.answered = true
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
	if !g.answered {
		b.Set("services.ssh.installed", g.failure)
		b.Set("services.ssh.active", g.failure)
		return
	}
	b.Set("services.ssh.installed", collect.OK(g.installed, g.src))
	if !g.installed {
		b.Set("services.ssh.active", collect.Absent("no ssh unit is loaded on this host"))
		return
	}
	b.Set("services.ssh.active", collect.OK(g.active, g.src))
}

func setTelnet(b *collect.Builder, a collect.Access, g groupState) {
	found, problem := telnetFromLegacy(a)
	switch {
	case g.answered && g.installed:
		b.Set("services.telnet.installed", collect.OK(true, g.src))
	case found != nil:
		b.Set("services.telnet.installed", *found)
	case !g.answered:
		b.Set("services.telnet.installed", g.failure)
	case problem != nil:
		// A super-server configuration we could not read might have named
		// telnet, so "not installed" would be a guess, not a fact.
		b.Set("services.telnet.installed", *problem)
	default:
		b.Set("services.telnet.installed", collect.OK(false, g.src))
	}

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
