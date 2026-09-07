//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	pwqualityConf  = "/etc/security/pwquality.conf"
	pwqualityConfD = "/etc/security/pwquality.conf.d/*.conf"
	faillockConf   = "/etc/security/faillock.conf"
	pwhistoryConf  = "/etc/security/pwhistory.conf"
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
// manual. Unreadable common-auth is simply not the marker.
func managingLayer(s pamStacks, a collect.Access) facts.Envelope {
	src := pamSource(s.x)
	if s.x.authselect {
		return collect.OK("authselect", src)
	}
	if data, _, err := a.ReadFile(pamDir+"/common-auth", readLimit); err == nil && strings.Contains(string(data), "pam-auth-update") {
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

// derivePassword and deriveAccess are filled by Tasks 2 and 3; until then
// they write nothing, and deriveAbsent has nothing to write either.
func derivePassword(pamStacks, collect.Access, *collect.Builder) {}

func deriveAccess(pamStacks, collect.Access, *collect.Builder) {}

func deriveAbsent(*collect.Builder, facts.Envelope) {}
