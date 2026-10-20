//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	etcProfile   = "/etc/profile"
	profileDGlob = "/etc/profile.d/*.sh"
	bashBashrc   = "/etc/bash.bashrc" // Debian family
	etcBashrc    = "/etc/bashrc"      // RHEL family
	cshCshrc     = "/etc/csh.cshrc"

	// profileDLinkTargets is where a distribution's package data lives when
	// a /etc/profile.d entry is shipped as a symbolic link to it (O-85:
	// Ubuntu 24.04's libdebuginfod-common links debuginfod.sh to
	// /usr/share/libdebuginfod-common/). A link to anything else is declined.
	profileDLinkTargets = "/usr/share/*/*"
)

// rootDotfiles is the root account's login files, read after the system-wide
// profile so a root-scope PATH or umask there is seen last. Order matters
// because the last unconditional assignment wins, so it must be deterministic.
var rootDotfiles = []string{"/root/.bash_profile", "/root/.bashrc", "/root/.profile"}

// pathCandidateDirs is the fixed set of directories a system/root PATH may
// name; pathEntries stats only an element that is in this declared set (R175),
// so the collector never stats an arbitrary directory outside Declare.Reads.
var pathCandidateDirs = []string{
	"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
	"/sbin", "/bin", "/snap/bin", "/root/bin", "/usr/games", "/usr/local/games",
}

var envCollector = collect.Collector{
	Name: "env",
	Declare: collect.Declaration{
		Reads: append(append([]string{etcProfile, profileDGlob, profileDLinkTargets, bashBashrc, etcBashrc, cshCshrc}, rootDotfiles...), pathCandidateDirs...),
		Needs: "none",
	},
	Run: runEnv,
}

// envShellKeys are the seven env.shell.* leaves this collector writes; a
// profile file that is present but unreadable is the answer for every value it
// could set, so the read error is written to all of them (C3, R183).
var envShellKeys = []string{
	"env.shell.tmout", "env.shell.tmout_exported", "env.shell.tmout_readonly",
	"env.shell.tmout_settings", "env.shell.umask_settings",
	"env.shell.root_path_raw", "env.shell.root_path_entries",
}

func runEnv(_ context.Context, a collect.Access, b *collect.Builder) error {
	var all []shellAssignment
	order, err := profileReadOrder(a)
	if err != nil {
		// C3/M-10: the read ORDER itself is incomplete — /etc/profile.d could
		// not be listed, and a drop-in there is where a TMOUT or umask is
		// usually set. Every value those files could have set carries the
		// listing error, path-prefixed, exactly as a present-but-unreadable
		// profile file does below.
		e := readErrorEnv(profileDGlob, err)
		for _, k := range envShellKeys {
			b.Set(k, e)
		}
		return nil
	}
	for _, p := range order {
		data, _, err := a.ReadFile(p, readLimit)
		if err != nil && errors.Is(err, collect.ErrSymlink) && isProfileDEntry(p) {
			var answer *facts.Envelope
			data, answer, err = readProfileDLink(a, p)
			if answer != nil {
				for _, k := range envShellKeys {
					b.Set(k, *answer)
				}
				return nil
			}
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // a profile file that simply does not exist contributes nothing
			}
			// C3 (R183): a present-but-unreadable profile file — denied, or any
			// other error — is the answer for every value it could set; write
			// the path-prefixed read error to all seven keys and stop.
			// readErrorEnv (shared with the pam collector) prefixes the reason
			// with the path so the report names which file could not be read.
			e := readErrorEnv(p, err)
			for _, k := range envShellKeys {
				b.Set(k, e)
			}
			return nil
		}
		all = append(all, parseShellFile(data, p)...)
	}
	writeTMOUT(b, all)
	writeUmask(b, all)
	writeRootPath(a, b, all)
	return nil
}

// profileReadOrder returns the profile files that exist, in the fixed order,
// with profile.d sorted. Both distro bashrc names are included; only the one
// that exists contributes. A profile.d that cannot be LISTED is returned as
// an error rather than skipped (M-10): the caller cannot judge a value from
// the files it did manage to read when it does not know which files there
// were.
func profileReadOrder(a collect.Access) ([]string, error) {
	matches, err := a.Glob(profileDGlob)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := append([]string{etcProfile}, matches...)
	out = append(out, bashBashrc, etcBashrc, cshCshrc)
	out = append(out, rootDotfiles...)
	return out, nil
}

// isProfileDEntry reports whether p is one of the /etc/profile.d drop-ins
// the Glob listed, as opposed to a main configuration file, where a symlink
// stays the read's error (C4).
func isProfileDEntry(p string) bool {
	ok, _ := path.Match(profileDGlob, p)
	return ok
}

// readProfileDLink reads a /etc/profile.d entry that is a symbolic link
// through that one level, when its target is a distribution's package data:
// an absolute, clean /usr/share/<package>/<file> (O-85). The target is opened
// no-follow like every read, so a chained link is refused. The returned
// content is parsed as the entry's own (the shell sources the entry). Any
// other link — relative, elsewhere, chained, or to something that is not a
// regular file — is declined: the returned envelope is absent, naming the
// entry and its target (C4), never an error. A target that exists but cannot
// be read is that read's status (C3), also returned as the envelope. A target
// that does not exist is returned as err (fs.ErrNotExist) and contributes
// nothing, as an absent entry does; so is a failed Readlink, which the caller
// treats as a failed read of the entry.
func readProfileDLink(a collect.Access, p string) ([]byte, *facts.Envelope, error) {
	target, err := a.Readlink(p)
	if err != nil {
		return nil, nil, err
	}
	decline := func(why string) *facts.Envelope {
		e := collect.Absent(p + ": a symbolic link to " + target + why + ", outside what this collector reads")
		return &e
	}
	if !path.IsAbs(target) || path.Clean(target) != target {
		return nil, decline(""), nil
	}
	if ok, _ := path.Match(profileDLinkTargets, target); !ok {
		return nil, decline(""), nil
	}
	data, _, err := a.ReadFile(target, readLimit)
	switch {
	case err == nil:
		return data, nil, nil
	case errors.Is(err, collect.ErrSymlink):
		return nil, decline(" (itself a symbolic link)"), nil
	case errors.Is(err, collect.ErrNotRegular):
		return nil, decline(" (not a regular file)"), nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, err
	}
	// C3: a package-data target that exists but cannot be read is the
	// read's status for every value, naming the entry and the target.
	e := readErrorEnv(p+" (a symbolic link to "+target+")", err)
	return nil, &e, nil
}

func writeTMOUT(b *collect.Builder, all []shellAssignment) {
	rows := []any{}
	winnerIdx := -1
	for i := range all {
		s := all[i]
		if s.Kind != "tmout" {
			continue
		}
		rows = append(rows, map[string]any{
			"path": s.Path, "line": s.Line, "value": s.Value,
			"exported": s.Exported, "readonly": s.Readonly, "conditional": s.Conditional,
			"scope": s.Scope,
		})
		// env.shell.tmout is a SYSTEM-scope fact (R197): a TMOUT set only in
		// root's dotfiles must not decide the host-wide value, so only an
		// unconditional system-scope row with a value may win. Every row is
		// still recorded (with its scope) as evidence.
		if !s.Conditional && s.Value != "" && s.Scope == "system" {
			winnerIdx = i
		}
	}
	src := &facts.Source{Kind: "derived"}
	val := 0
	exported, readonly := false, false
	if winnerIdx >= 0 {
		w := all[winnerIdx]
		// exported/readonly come from the winning assignment itself plus any
		// LATER unconditional system-scope export/readonly of TMOUT — not OR'd
		// across every row, so a conditional or root-scope `export TMOUT` does
		// not falsely mark the system value (L4, R197).
		exported, readonly = w.Exported, w.Readonly
		for j := winnerIdx + 1; j < len(all); j++ {
			s := all[j]
			if s.Kind != "tmout" || s.Conditional || s.Scope != "system" {
				continue
			}
			exported = exported || s.Exported
			readonly = readonly || s.Readonly
		}
		if n, err := strconv.Atoi(strings.TrimSpace(w.Value)); err == nil {
			val = n
			src = &facts.Source{Kind: "file", Path: w.Path, Line: w.Line}
		}
	}
	b.Set("env.shell.tmout", collect.OK(val, src))
	b.Set("env.shell.tmout_exported", collect.OK(exported, src))
	b.Set("env.shell.tmout_readonly", collect.OK(readonly, src))
	b.Set("env.shell.tmout_settings", collect.OK(rows, &facts.Source{Kind: "derived"}))
}

func writeUmask(b *collect.Builder, all []shellAssignment) {
	rows := []any{}
	for _, s := range all {
		if s.Kind != "umask" {
			continue
		}
		rows = append(rows, map[string]any{
			"path": s.Path, "line": s.Line, "value": s.Value,
			"symbolic": s.Symbolic, "conditional": s.Conditional, "scope": s.Scope,
		})
	}
	b.Set("env.shell.umask_settings", collect.OK(rows, &facts.Source{Kind: "derived"}))
}

func writeRootPath(a collect.Access, b *collect.Builder, all []shellAssignment) {
	// Walk the unconditional PATH assignments in read order, splicing the
	// accumulated value in for a $PATH/${PATH} self-reference (R196). Without
	// this, a `PATH=$PATH:$HOME/bin` in /root/.bash_profile — the last winner
	// on stock RHEL/Alma — would mask an earlier `PATH=/usr/bin:.` in an
	// /etc/profile.d file, so U-14's `none where is_dot` / `world_writable`
	// clauses would judge only the $PATH/$HOME rows and never see the "."
	// element the item exists to catch. root_path_raw stays the VERBATIM last
	// winning line (evidence); only root_path_entries reflects the spliced value.
	var winner *shellAssignment
	spliced := ""
	for i := range all {
		if all[i].Kind != "path" || all[i].Conditional {
			continue
		}
		w := all[i]
		winner = &w
		spliced = splicePath(spliced, w.Value)
	}
	if winner == nil {
		e := collect.Absent("no PATH assignment in the system profile files")
		b.Set("env.shell.root_path_raw", e)
		b.Set("env.shell.root_path_entries", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: winner.Path, Line: winner.Line, Raw: sourceRaw("PATH=" + winner.Value)}
	b.Set("env.shell.root_path_raw", collect.OK(winner.Value, src))
	b.Set("env.shell.root_path_entries", collect.OK(pathEntries(a, spliced), src))
}

// splicePath returns value with every $PATH / ${PATH} self-reference replaced
// by acc, the PATH accumulated from the earlier unconditional assignments, so
// a `PATH=$PATH:…` line extends rather than masks what came before (R196).
// Only the $PATH token is expanded; a $HOME, other $var or ~ element is left
// verbatim for pathEntries to record as an unresolved variable (R180).
func splicePath(acc, value string) string {
	value = strings.ReplaceAll(value, "${PATH}", acc)
	var out strings.Builder
	for {
		i := strings.Index(value, "$PATH")
		if i < 0 {
			out.WriteString(value)
			break
		}
		after := i + len("$PATH")
		// Only a bare $PATH token, not the prefix of a longer name such as
		// $PATHOLOGICAL: the following byte must not continue an identifier.
		if after < len(value) && isIdentByte(value[after]) {
			out.WriteString(value[:after])
			value = value[after:]
			continue
		}
		out.WriteString(value[:i])
		out.WriteString(acc)
		value = value[after:]
	}
	return out.String()
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
