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

	// hostFailed is the FIRST host-unit probe that did not answer (timed out,
	// could not run, or exited non-zero), kept as the envelope match surfaces
	// on a found entry's enabled/active when the host state is not positively
	// enabled/active (R243). A host unit that failed might have been the one
	// hosting the entry, so "not enabled/active" would be a guess, not a fact.
	hostFailed *facts.Envelope

	// hit is scratch: match records the source (and truncation) of the entry
	// it matched so the caller can attribute the installed leaf to that exact
	// line. hitEnabled is the source of the first ENABLED matching entry, used
	// for the enabled/active leaves so their attribution never points at a
	// `disable = yes` block (R248). Both are overwritten by every match call
	// and read immediately after, in the same goroutine.
	hit          *facts.Source
	hitTruncated bool
	hitEnabled   *facts.Source
}

// readSuperServers parses /etc/inetd.conf and every /etc/xinetd.d/* fragment
// ONCE, and probes the four super-server host units ONCE (R227). It never
// judges a service on its own — match does that per service — it only gathers
// the shared evidence a whole sweep reuses.
func readSuperServers(ctx context.Context, a collect.Access) superServers {
	var s superServers
	s.readInetd(a)
	s.readXinetd(a)
	s.probeHosts(ctx, a)
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
		default:
			// R242: match the attribute key EXACTLY, never by prefix — otherwise
			// `server_args = -s …` overwrites cur.server with path.Base("-s"),
			// silently disabling the R233 server-basename channel, and `disabled
			// = …` would be read as `disable`.
			key, _, ok := strings.Cut(line, "=")
			if !ok {
				break
			}
			switch strings.TrimSpace(key) {
			case "disable":
				if v, ok := attrValue(line); ok && v == "yes" {
					cur.enabled = false
				}
			case "server":
				if v, ok := attrValue(line); ok {
					cur.server = path.Base(v)
				}
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

// noteHostFailure keeps the FIRST host-unit probe failure only (R243).
func (s *superServers) noteHostFailure(e facts.Envelope) {
	if s.hostFailed == nil {
		s.hostFailed = &e
	}
}

// probeHosts runs systemctl show over the four host units once, folding their
// answers into the aggregate host state (R227). A unit that never answered
// (systemctl could not run, timed out, or exited non-zero) is not counted
// toward the aggregate, but the FIRST such failure is kept in hostFailed so a
// found entry does not silently read as disabled/inactive when the very unit
// that might host it never answered (R243). hostProbed stays false only when
// NONE answered. R247: the sweep ctx is threaded in, not context.Background().
func (s *superServers) probeHosts(ctx context.Context, a collect.Access) {
	for _, u := range superServerHostUnits {
		cmd := showCmd(u)
		out := a.Run(ctx, cmd)
		switch {
		case out.TimedOut:
			e := collect.TimeoutEnv("systemctl show " + u + " timed out")
			e.Source = out.Source(cmd)
			s.noteHostFailure(withTruncation(e, out.Truncated))
			continue
		case out.Err != nil, out.ExitCode != 0:
			// services declares Needs: none, so a failure here is never a
			// privilege problem by virtue of this process's euid (R84).
			s.noteHostFailure(commandFailure("systemctl show "+u, out, out.Source(cmd), false))
			continue
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
// ev is the non-ok envelope the caller must surface rather than a silent false:
// the read error when a config file existed but could not be read (R227), or —
// when no read error stands — the first host-unit probe failure on a found,
// file-enabled entry whose host did not come back positively enabled/active
// (R243). It is never nil-laundered into a false.
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
			// R248: attribute enabled/active to the first ENABLED entry, never a
			// `disable = yes` block that merely matched by name/server.
			if s.hitEnabled == nil {
				s.hitEnabled = e.src
			}
		}
	}
	installed = found
	enabled = enabledEntry && (s.hostEnabled || !s.hostProbed)
	active = enabledEntry && s.hostActive
	ev = s.readErr
	// R243: a found, file-enabled entry that did not come back positively
	// enabled/active while a host probe failed could be live behind the unit
	// that never answered — surface that failure so enabled/active are not a
	// silent ok:false.
	if ev == nil && enabledEntry && s.hostFailed != nil && (!s.hostEnabled || !s.hostActive) {
		ev = s.hostFailed
	}
	return installed, enabled, active, found, ev
}

// entryMatches applies R233's NAME-or-server-basename rule.
func entryMatches(e superEntry, names, servers []string) bool {
	if slices.Contains(names, e.name) {
		return true
	}
	return e.server != "" && slices.Contains(servers, e.server)
}
