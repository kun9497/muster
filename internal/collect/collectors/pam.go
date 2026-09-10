//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	pwqualityConf = "/etc/security/pwquality.conf"
	// pwqualityConfDir is the drop-in directory mergeDropinsWith is given;
	// pwqualityConfD is the same directory as the glob the declaration lists
	// and the pattern a failed listing is reported against.
	pwqualityConfDir = "/etc/security/pwquality.conf.d"
	pwqualityConfD   = pwqualityConfDir + "/*.conf"
	faillockConf     = "/etc/security/faillock.conf"
	pwhistoryConf    = "/etc/security/pwhistory.conf"
)

// pamCollector reads the PAM configuration the login-facing services use.
// Everything it reads is world-readable on both distribution families, so
// it needs no privilege.
var pamCollector = collect.Collector{
	Name: "pam",
	Declare: collect.Declaration{Reads: []string{
		pamDirGlob,
		authselectDir + "/system-auth", authselectDir + "/password-auth", authselectDir + "/fingerprint-auth",
		authselectDir + "/smartcard-auth", authselectDir + "/postlogin",
		pwqualityConf, pwqualityConfD, faillockConf, pwhistoryConf,
	}, Needs: "none"},
	Run: runPAM,
}

// pamStacks is what the derivations of Tasks 2 and 3 consume: the expanded
// stacks of the published services, the expander (for parse problems and
// the files it read) and whether each service file exists.
type pamStacks struct {
	x      *pamExpander
	byName map[string][]pamLine
}

func (s pamStacks) has(service string) bool { _, ok := s.byName[service]; return ok }

// pamSource is the derived source every pam.* key carries: the files the
// expander actually read, sorted by path (R147). A fresh Source is built
// per key so no two envelopes share one pointer.
func pamSource(x *pamExpander) *facts.Source {
	return &facts.Source{Kind: "derived", Inputs: x.inputs()}
}

// managingLayer decides how the stacks are generated: a managed name that
// was a symlink resolved into /etc/authselect means authselect; the
// pam-auth-update marker in common-auth means pam-auth-update; otherwise
// manual. A common-auth that does not exist is not the marker, but one that
// exists and cannot be read is the read error (R163): nothing here can say
// whether the marker is in it, and "manual" would call the host unmanaged
// on the strength of a file nobody read.
func managingLayer(s pamStacks, a collect.Access) facts.Envelope {
	src := pamSource(s.x)
	if s.x.authselect {
		return collect.OK("authselect", src)
	}
	marker := pamDir + "/common-auth"
	data, _, err := a.ReadFile(marker, readLimit)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return readErrorEnv(marker, err)
	case err == nil && strings.Contains(string(data), "pam-auth-update"):
		// R155: the file the answer was read out of is cited, even when no
		// published service included it and the expander never read it.
		if !slices.ContainsFunc(src.Inputs, func(in facts.Source) bool { return in.Path == marker }) {
			src.Inputs = append(src.Inputs, facts.Source{Kind: "file", Path: marker})
		}
		return collect.OK("pam-auth-update", src)
	}
	return collect.OK("manual", src)
}

// incomplete is the envelope every derived key carries when the stacks
// could not be fully read: an error naming the first problem, never a
// value computed from a partial stack.
func incomplete(s pamStacks) (facts.Envelope, bool) {
	if len(s.x.problems) == 0 {
		return facts.Envelope{}, false
	}
	return collect.ErrorEnv("PAM stack incomplete: " + s.x.problems[0]), true
}

func runPAM(_ context.Context, a collect.Access, b *collect.Builder) error {
	// No /etc/pam.d at all (a container image without pam) is absent on
	// every key: there is nothing to expand and nothing to derive.
	names, err := a.Glob(pamDirGlob)
	if err != nil || len(names) == 0 {
		e := collect.Absent(pamDir + " has no readable entries")
		if err != nil {
			e = collect.FromReadError(err, collect.ReadMeta{})
			e.Reason = pamDir + ": " + e.Reason
		}
		b.Set("pam.stacks", e)
		b.Set("pam.managing_layer", e)
		b.Set("pam.parse_complete", e)
		deriveAbsent(b, e)
		return nil
	}
	s := pamStacks{x: newPAMExpander(a), byName: map[string][]pamLine{}}
	var all []pamLine
	for _, svc := range pamServices {
		p := pamDir + "/" + svc
		// A service with no file is simply not configured on this host and
		// is skipped in silence; a service whose file exists but cannot be
		// read is a parse problem (R143), never a silently shorter stack.
		if _, _, err := s.x.readService(p); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				s.x.problem(p + ": " + readReason(p, err))
			}
			continue
		}
		lines := s.x.expand(svc)
		s.byName[svc] = lines
		all = append(all, lines...)
	}
	b.Set("pam.stacks", collect.OK(stackRecords(all), pamSource(s.x)))
	b.Set("pam.managing_layer", managingLayer(s, a))
	complete := collect.OK(len(s.x.problems) == 0, pamSource(s.x))
	if len(s.x.problems) > 0 {
		complete.Reason = s.x.problems[0]
	}
	b.Set("pam.parse_complete", complete)
	derivePassword(s, a, b) // Task 2
	deriveAccess(s, a, b)   // Task 3
	return nil
}

// derivePassword writes the password-stack keys in a fixed order: an
// error naming the parse problem when the stacks are incomplete, absent
// when there is no passwd service, the derived values otherwise.
func derivePassword(s pamStacks, a collect.Access, b *collect.Builder) {
	if e, bad := incomplete(s); bad {
		for _, k := range passwordKeys {
			b.Set(k, e)
		}
		return
	}
	if !s.has("passwd") {
		for _, k := range passwordKeys {
			b.Set(k, collect.Absent(pamDir+"/passwd does not exist"))
		}
		return
	}
	vals := pwqualityFacts(s, a)
	for k, v := range passwordFacts(s, a) {
		vals[k] = v
	}
	for _, k := range passwordKeys {
		b.Set(k, vals[k])
	}
}

// deriveAccess writes the access-control keys in a fixed order, under the
// same incomplete-stack rule as derivePassword. Each of the four groups
// decides for itself whether its service exists, so a host without a su
// file still answers for faillock, umask and securetty.
func deriveAccess(s pamStacks, a collect.Access, b *collect.Builder) {
	if e, bad := incomplete(s); bad {
		for _, k := range accessKeys {
			b.Set(k, e)
		}
		return
	}
	vals := faillockFacts(s, a)
	maps.Copy(vals, suFacts(s))
	maps.Copy(vals, umaskFacts(s))
	vals["pam.securetty_enabled"] = securettyFact(s)
	for _, k := range accessKeys {
		b.Set(k, vals[k])
	}
}

// deriveAbsent writes every derived key as the given absent envelope
// (no /etc/pam.d at all).
func deriveAbsent(b *collect.Builder, e facts.Envelope) {
	for _, k := range passwordKeys {
		b.Set(k, e)
	}
	for _, k := range accessKeys {
		b.Set(k, e)
	}
}
