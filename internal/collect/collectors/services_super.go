//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// superServerHostUnits are the systemd units that HOST inetd/xinetd entries.
// R227: an entry in /etc/inetd.conf or an /etc/xinetd.d/* fragment only starts
// when one of these is running, so an entry's enabled/active leaves are gated
// by the host's state, never asserted unconditionally. All four are probed
// once per run (provesInstall is irrelevant here — these do not prove any
// logical service installed). Debian/Ubuntu ship only openbsd-inetd.service or
// inetutils-inetd.service; inetd.service / xinetd.service are the RHEL-family
// and generic names. inetd.service and xinetd.service are already declared via
// telnet's unitRef list, so declaredShowCommands only needs to add the first
// two.
var superServerHostUnits = []string{
	"openbsd-inetd.service",
	"inetutils-inetd.service",
	"inetd.service",
	"xinetd.service",
}

// superServerExtraHostUnits are the host units NOT already named in the
// services table, so declaredShowCommands can add exactly the missing
// systemctl invocations to the collector's declaration.
var superServerExtraHostUnits = []string{
	"openbsd-inetd.service",
	"inetutils-inetd.service",
}

// superEntry is one inetd.conf line or one xinetd `service <name>` block.
type superEntry struct {
	name    string // inetd.conf field 0 / xinetd `service <name>`
	server  string // basename of the server-program field, "" when none
	enabled bool   // file-level enablement: an inetd line is always on;
	// a xinetd block is off only with `disable = yes`
	src       *facts.Source // the line the entry came from (installed evidence)
	truncated bool          // the read that produced this entry hit its cap (R70)
}

// superServers is the once-per-run super-server picture: every parsed entry,
// the aggregate host state, and (if any config file existed but could not be
// read) the read error that must not be laundered into a silent "absent".
//
// R237: the xinetd GLOBAL defaults in /etc/xinetd.conf (`defaults { disabled =
// … }` / a top-level `enabled = …` list) are NOT read here. A fragment with
// `disable = no` could still be globally disabled, so treating the fragment as
// on is over-strict — it can only produce a FAIL that a human waives, never a
// false PASS — which is the safe direction; no code reads the global file now.
type superServers struct {
	entries     []superEntry
	hostEnabled bool // some host super-server unit is enabled
	hostActive  bool // some host super-server unit is active
	hostProbed  bool // at least one host unit answered (state is known)
	readErr     *facts.Envelope

	// hit is scratch: match records the source (and truncation) of the entry
	// it matched so the caller can attribute the installed leaf to that exact
	// line. It is overwritten by every match call and read immediately after.
	hit          *facts.Source
	hitTruncated bool
}

// readSuperServers parses /etc/inetd.conf and every /etc/xinetd.d/* fragment
// ONCE, and probes the four super-server host units ONCE (R227). It never
// judges a service on its own — match does that per service — it only gathers
// the shared evidence a whole sweep reuses.
func readSuperServers(a collect.Access) superServers {
	var s superServers
	s.readInetd(a)
	s.readXinetd(a)
	s.probeHosts(a)
	return s
}

// readInetd appends one entry per non-comment /etc/inetd.conf line. A missing
// file is simply no entries; a file that exists but cannot be read is a read
// error (honest degradation — never a silent absent).
func (s *superServers) readInetd(a collect.Access) {
	data, meta, err := a.ReadFile(inetdConf, readLimit)
	switch {
	case err == nil:
		for i, raw := range splitLines(data) {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			e := superEntry{
				name:      f[0],
				enabled:   true, // inetd.conf has no per-line disable
				src:       &facts.Source{Kind: "file", Path: inetdConf, Line: i + 1, Raw: sourceRaw(raw)},
				truncated: meta.Truncated,
			}
			if len(f) > inetdServerField {
				e.server = path.Base(f[inetdServerField])
			}
			s.entries = append(s.entries, e)
		}
	case !errors.Is(err, fs.ErrNotExist):
		s.noteReadError(inetdConf, err)
	}
}

// readXinetd appends one entry per `service <name>` block across all fragments.
func (s *superServers) readXinetd(a collect.Access) {
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
			s.noteReadError(p, err)
			continue
		}
		s.parseXinetd(p, data, meta.Truncated)
	}
}

// parseXinetd walks one fragment, flushing a block at each new `service`
// directive, at a closing brace, and at end of file.
func (s *superServers) parseXinetd(p string, data []byte, truncated bool) {
	var cur *superEntry
	flush := func() {
		if cur != nil {
			s.entries = append(s.entries, *cur)
			cur = nil
		}
	}
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case f[0] == "service" && len(f) >= 2:
			flush()
			cur = &superEntry{
				name:      strings.TrimSuffix(f[1], "{"),
				enabled:   true,
				src:       &facts.Source{Kind: "file", Path: p, Line: i + 1, Raw: sourceRaw(raw)},
				truncated: truncated,
			}
		case cur == nil:
			// text outside any service block (e.g. a stray brace) — ignore
		case strings.HasPrefix(line, "}"):
			flush()
		case strings.HasPrefix(f[0], "disable"):
			if v, ok := attrValue(line); ok && v == "yes" {
				cur.enabled = false
			}
		case strings.HasPrefix(f[0], "server"):
			if v, ok := attrValue(line); ok {
				cur.server = path.Base(v)
			}
		}
	}
	flush()
}

// attrValue reads the right-hand side of a `key = value` xinetd attribute,
// returning the first token of the value.
func attrValue(line string) (string, bool) {
	_, rhs, ok := strings.Cut(line, "=")
	if !ok {
		return "", false
	}
	f := strings.Fields(rhs)
	if len(f) == 0 {
		return "", false
	}
	return f[0], true
}

// noteReadError keeps the FIRST read error only, path-prefixed (D16), as the
// envelope every leaf the file could have set must carry.
func (s *superServers) noteReadError(p string, err error) {
	if s.readErr == nil {
		e := readErrorEnv(p, err)
		s.readErr = &e
	}
}

// probeHosts runs systemctl show over the four host units once, folding their
// answers into the aggregate host state (R227). A unit that never answered
// (systemctl could not run, timed out, or is unknown to this build's command
// map) is simply not counted; hostProbed stays false only when NONE answered.
func (s *superServers) probeHosts(a collect.Access) {
	ctx := context.Background()
	for _, u := range superServerHostUnits {
		out := a.Run(ctx, showCmd(u))
		if out.TimedOut || out.Err != nil || out.ExitCode != 0 {
			continue // this unit did not answer
		}
		s.hostProbed = true
		load, active, unitFile := showValues(out.Stdout)
		if load == "not-found" {
			continue
		}
		isActive := active == "active"
		if isActive {
			s.hostActive = true
		}
		if enabledFromUnitFile(unitFile, isActive) {
			s.hostEnabled = true
		}
	}
}

// match looks the given inetd/xinetd names and server basenames up against the
// once-parsed entries and gates the result by the host state (R227/R233).
//
//   - installed: an entry is present at all — UNCONDITIONAL. The daemon is
//     configured whether or not the host super-server currently runs, and
//     installed is not host-gated.
//   - enabled: an ENABLED entry exists AND the host super-server is enabled,
//     OR the host state is unknown/unprobed (a stale config on a host we could
//     not inspect is reported, not silently passed).
//   - active: an ENABLED entry exists AND a host super-server is active. A
//     stale /etc/inetd.conf on a host whose inetd is stopped must not read as
//     active.
//
// R233: an entry matches by NAME (field 0 / xinetd `service <name>`) OR by its
// server-program BASENAME equalling one of servers — no `<name>d`/`in.<name>d`
// suffix heuristic (in.rshd is not "shelld").
//
// ev is the read error when a config file existed but could not be read: it is
// never nil-laundered into a false, so the caller surfaces it on the leaves
// that file could have set.
func (s *superServers) match(names, servers []string) (installed, enabled, active, found bool, ev *facts.Envelope) {
	var enabledEntry bool
	for _, e := range s.entries {
		if !entryMatches(e, names, servers) {
			continue
		}
		if !found {
			found = true
			s.hit = e.src
			s.hitTruncated = e.truncated
		}
		if e.enabled {
			enabledEntry = true
		}
	}
	installed = found
	enabled = enabledEntry && (s.hostEnabled || !s.hostProbed)
	active = enabledEntry && s.hostActive
	return installed, enabled, active, found, s.readErr
}

// entryMatches applies R233's NAME-or-server-basename rule.
func entryMatches(e superEntry, names, servers []string) bool {
	if slices.Contains(names, e.name) {
		return true
	}
	return e.server != "" && slices.Contains(servers, e.server)
}
