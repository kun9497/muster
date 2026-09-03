//go:build linux

package collectors

import (
	"context"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	sshdConfigPath  = "/etc/ssh/sshd_config"
	sshdConfigDir   = "/etc/ssh/sshd_config.d/*.conf"
	permitRootLogin = "permitrootlogin"
	maxIncludeDepth = 8
)

var sshdT = collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}

var sshdCollector = collect.Collector{
	Name: "sshd",
	Declare: collect.Declaration{
		Reads:    []string{sshdConfigPath, sshdConfigDir},
		Commands: []collect.Command{sshdT},
		Needs:    "root",
	},
	Run: runSshd,
}

// runSshd fills sshd.* (spec §10.2). Stage 1 reports the daemon's global
// values only: sshd -T for the runtime side, the configuration files with
// Include expanded for the persisted side, and no Match personas at all.
func runSshd(ctx context.Context, a collect.Access, b *collect.Builder) error {
	b.Set("sshd.personas_collected", collect.OK(false, nil))

	var s facts.Setting
	out := a.Run(ctx, sshdT)
	src := out.Source(sshdT)
	method := "parse"
	switch {
	case out.TimedOut:
		e := collect.TimeoutEnv("sshd -T timed out")
		e.Source = src
		s.Runtime = &e
	case out.Err != nil:
		// The binary is not there, or not where it is declared: there is
		// no runtime side at all and the files have to answer.
	case out.ExitCode != 0:
		// R59: a daemon that refused to print its configuration is an
		// error (denied when it said so), never a missing value.
		e := commandFailure("sshd -T", out, src)
		s.Runtime = &e
	default:
		method = "T" // R59: the method records whether -T answered
		e := collect.ErrorEnv("sshd -T printed no " + permitRootLogin + " line")
		for _, line := range splitLines(out.Stdout) {
			f := strings.Fields(line)
			if len(f) >= 2 && strings.ToLower(f[0]) == permitRootLogin {
				e = collect.OK(f[1], src)
				break
			}
		}
		s.Runtime = &e
	}
	b.Set("sshd.collect_method", collect.OK(method, src))

	if persisted, found := parseSshdConfig(a, sshdConfigPath, permitRootLogin, 0); found {
		s.Persisted = &persisted
	}

	switch {
	case s.Runtime != nil && s.Runtime.Status == facts.StatusOK:
		eff := *s.Runtime
		s.Effective = &eff
	case s.Persisted != nil:
		// R59: a non-ok persisted side is copied UNCHANGED. Overwriting a
		// denied or absent reason with "parsed files" would replace the
		// explanation of why there is no value with a claim that there is.
		eff := *s.Persisted
		if eff.Status == facts.StatusOK {
			eff.Reason = "parsed files; sshd -T unavailable"
		}
		s.Effective = &eff
	case s.Runtime != nil:
		eff := *s.Runtime
		s.Effective = &eff
	default:
		eff := collect.Absent("no sshd -T output and no readable sshd_config")
		s.Effective = &eff
	}
	b.SetSetting("sshd.options.permit_root_login", s)
	return nil
}

// parseSshdConfig resolves keyword the way sshd itself does: an Include is
// read where the directive appears, its matches in sorted order, and the
// FIRST occurrence of a keyword anywhere in that walk wins. depth guards
// against an Include loop.
//
// The bool result distinguishes "this file answered" from "keep looking";
// only the top-level call turns a read failure into an envelope, because an
// included file that is missing is ordinary, while an unreadable
// sshd_config is the answer.
func parseSshdConfig(a collect.Access, file, keyword string, depth int) (facts.Envelope, bool) {
	if depth > maxIncludeDepth {
		return collect.ErrorEnv("Include nesting deeper than " + strconv.Itoa(maxIncludeDepth) + " levels"), true
	}
	data, meta, err := a.ReadFile(file, readLimit)
	if err != nil {
		if depth == 0 {
			return collect.FromReadError(err, meta), true
		}
		return facts.Envelope{}, false
	}
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		key := strings.ToLower(f[0])
		if key == "match" {
			break // stage 1 reports global values only; personas arrive in stage 2
		}
		if key == "include" && len(f) >= 2 {
			for _, pattern := range f[1:] {
				// R55/R75: an Include outside the declaration is recorded
				// and expansion stops. It is never requested, so it raises
				// no guard violation and the collector still succeeds.
				if !declared(a, pattern) {
					return collect.ErrorEnv("Include " + pattern + " is outside the collector's declaration"), true
				}
				matches, _ := a.Glob(pattern)
				slices.Sort(matches)
				for _, m := range matches {
					if env, ok := parseSshdConfig(a, path.Clean(m), keyword, depth+1); ok {
						return env, true
					}
				}
			}
			continue
		}
		if key == keyword && len(f) >= 2 {
			return collect.OKRead(f[1], &facts.Source{
				Kind: "file", Path: file, Line: i + 1, Raw: sourceRaw(raw),
			}, meta), true
		}
	}
	return facts.Envelope{}, false
}

// declared asks the guard whether pattern is inside the collector's
// declaration without the question itself counting as a violation (R55). A
// test double that does not offer Allowed counts everything as declared.
func declared(a collect.Access, pattern string) bool {
	al, ok := a.(interface{ Allowed(string) bool })
	return !ok || al.Allowed(pattern)
}
