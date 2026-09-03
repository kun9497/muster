//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
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

	// maxTokenValue caps a single keyword value muster stores (M16). A
	// keyword's value is a word — "yes", "prohibit-password" — and the read
	// and output limits above it are megabytes, so without this cap one
	// pathological line of a file or of a command's output would be copied
	// whole into the snapshot. A longer token is not a value that was
	// misread; it is not a value at all, so none of it is stored.
	maxTokenValue = 4 << 10
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
		e = withTruncation(e, out.Truncated)
		s.Runtime = &e
	case out.Err != nil:
		// The binary is not there, or not where it is declared: there is
		// no runtime side at all and the files have to answer.
	case out.ExitCode != 0:
		// R59: a daemon that refused to print its configuration is an
		// error (denied when it said so), never a missing value.
		// R84: sshd declares Needs: root, so a -T that failed while this
		// process is not root is a privilege problem, not a parse error.
		e := commandFailure("sshd -T", out, src, true)
		if e.Status == facts.StatusError {
			// R88 (spec §6.5 step 13): sshd -T can fail for reasons that
			// are not a parse error at all — most commonly a socket-
			// activated or freshly installed sshd that has never created
			// /run/sshd ("Missing privilege separation directory"). The
			// parsed sshd_config still answers the question, so this is
			// the same degradation as -T never having run: absent, not
			// error, and the run stays complete. A privilege failure
			// (Denied, above) is unchanged by this — R84 still applies.
			e.Status = facts.StatusAbsent
			e.Reason = "sshd -T unavailable: " + e.Reason
		}
		s.Runtime = &e
	default:
		method = "T" // R59: the method records whether -T answered
		e := collect.ErrorEnv("sshd -T printed no " + permitRootLogin + " line")
		for _, line := range splitLines(out.Stdout) {
			f := configTokens(line)
			if len(f) >= 2 && strings.ToLower(f[0]) == permitRootLogin {
				if oversized(f[1]) {
					e = collect.ErrorEnv(oversizedReason)
					break
				}
				e = collect.OK(keywordValue(permitRootLogin, f[1]), src)
				break
			}
		}
		// R70's command-side counterpart: a value read out of a capture
		// that hit the output cap is not the daemon's whole answer.
		e = withTruncation(e, out.Truncated)
		s.Runtime = &e
	}
	// The command is the evidence for "T", and for a "parse" that was
	// forced by a -T which ran and failed. A binary that never started has
	// no exit code to cite, so that envelope carries no source at all.
	methodSrc := src
	if out.Err != nil && out.ExitCode == -1 {
		methodSrc = nil
	}
	b.Set("sshd.collect_method", withTruncation(collect.OK(method, methodSrc), out.Truncated))

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
// The bool result distinguishes "this file answered" from "keep looking".
// Only a file that is NOT THERE may be skipped, and only below the top
// level: a drop-in that exists but could not be read — a symlink the
// primitive refuses, a non-regular file, EACCES — may have carried a
// higher-priority PermitRootLogin, so falling through to the main file and
// publishing its value as ok would be a PASS on evidence never seen. That
// read failure becomes the answer instead (the same rule services.go
// applies to an unreadable xinetd fragment).
func parseSshdConfig(a collect.Access, file, keyword string, depth int) (facts.Envelope, bool) {
	if depth > maxIncludeDepth {
		return collect.ErrorEnv("Include nesting deeper than " + strconv.Itoa(maxIncludeDepth) + " levels"), true
	}
	data, meta, err := a.ReadFile(file, readLimit)
	if err != nil {
		if depth == 0 || !errors.Is(err, fs.ErrNotExist) {
			return collect.FromReadError(err, meta), true
		}
		return facts.Envelope{}, false
	}
	for i, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := configTokens(line)
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
				matches, err := a.Glob(pattern)
				if err != nil {
					// A Glob that failed is not an Include that matched
					// nothing: each drop-in it would have named could have
					// carried a higher-priority value, so expanding to
					// nothing and publishing the main file's value as ok
					// would be a PASS on evidence never seen — the same rule
					// an unreadable drop-in gets just below.
					return collect.ErrorEnv("Include " + pattern + ": " + err.Error()), true
				}
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
			if oversized(f[1]) {
				return collect.ErrorEnv(oversizedReason), true
			}
			return collect.OKRead(keywordValue(key, f[1]), &facts.Source{
				Kind: "file", Path: file, Line: i + 1, Raw: sourceRaw(raw),
			}, meta), true
		}
	}
	return facts.Envelope{}, false
}

// oversizedReason is the reason an over-long value carries. It names the
// limit rather than the value, because the value is exactly what must not
// be stored (M16).
const oversizedReason = "value exceeds 4 KiB"

// oversized reports whether a single parsed value is too long to be one —
// the same rule for a value read out of a file and one printed by a
// command, so the two sides of a setting cannot disagree about it.
func oversized(v string) bool { return len(v) > maxTokenValue }

// configTokens splits an sshd_config line into its keyword and arguments.
//
// R85: sshd's own tokenizer (strdelim) counts "=" as a separator alongside
// whitespace for the first separator on a line, so all four of
//
//	Keyword value    Keyword=value    Keyword = value
//	Keyword =value   Keyword= value
//
// are one directive. Every spelling muster does not recognise reads as "the
// keyword is not configured", which is a PASS on a directive that is right
// there in the file — so the first "=" after the keyword is folded away
// here, wherever the spaces around it fall. A later "=" is left alone: it
// belongs to the value (an AuthorizedKeysCommand argument, say), not to the
// keyword.
func configTokens(line string) []string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return f
	}
	if k, v, ok := strings.Cut(f[0], "="); ok {
		// "Keyword=value" and "Keyword= value": the keyword carries the
		// separator, and the value may be empty (it is then the next field,
		// or the directive has no value at all).
		out := []string{k}
		if v != "" {
			out = append(out, v)
		}
		return append(out, f[1:]...)
	}
	if len(f) > 1 {
		if f[1] == "=" { // "Keyword = value"
			return append(f[:1], f[2:]...)
		}
		if v, ok := strings.CutPrefix(f[1], "="); ok { // "Keyword =value"
			f[1] = v
		}
	}
	return f
}

// multistate names the keywords whose value is one of a fixed set of words
// rather than free text. sshd matches those case-insensitively, so
// "PermitRootLogin No" and "permitrootlogin no" are one answer; the value
// is folded here so a control never has to match both spellings and two
// hosts that are configured identically cannot produce different facts.
// Paths, ciphers and command lines are NOT folded — their case is theirs.
var multistate = map[string]bool{permitRootLogin: true}

// keywordValue is the value stored for one parsed keyword.
func keywordValue(keyword, value string) string {
	if multistate[strings.ToLower(keyword)] {
		return strings.ToLower(value)
	}
	return value
}

// declared asks the guard whether pattern is inside the collector's
// declaration without the question itself counting as a violation (R55). A
// test double that does not offer Allowed counts everything as declared.
func declared(a collect.Access, pattern string) bool {
	al, ok := a.(interface{ Allowed(string) bool })
	return !ok || al.Allowed(pattern)
}
