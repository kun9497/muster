//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
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
		Reads: append(append([]string{etcProfile, profileDGlob, bashBashrc, etcBashrc, cshCshrc}, rootDotfiles...), pathCandidateDirs...),
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
	for _, p := range profileReadOrder(a) {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // a profile file that simply does not exist contributes nothing
			}
			// C3 (R183): a present-but-unreadable profile file — denied, or any
			// other error — is the answer for every value it could set; write
			// the path-prefixed read error to all seven keys and stop.
			e := collect.FromReadError(err, meta)
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
// that exists contributes.
func profileReadOrder(a collect.Access) []string {
	out := []string{etcProfile}
	if matches, err := a.Glob(profileDGlob); err == nil {
		sort.Strings(matches)
		out = append(out, matches...)
	}
	out = append(out, bashBashrc, etcBashrc, cshCshrc)
	out = append(out, rootDotfiles...)
	return out
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
		})
		if !s.Conditional && s.Value != "" { // a bare `readonly TMOUT` has no value; it does not win
			winnerIdx = i
		}
	}
	src := &facts.Source{Kind: "derived"}
	val := 0
	exported, readonly := false, false
	if winnerIdx >= 0 {
		w := all[winnerIdx]
		// exported/readonly come from the winning assignment itself plus any
		// LATER unconditional export/readonly of TMOUT — not OR'd across every
		// row, so a conditional `export TMOUT` does not falsely mark it (L4).
		exported, readonly = w.Exported, w.Readonly
		for j := winnerIdx + 1; j < len(all); j++ {
			s := all[j]
			if s.Kind != "tmout" || s.Conditional {
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
	var winner *shellAssignment
	for i := range all {
		if all[i].Kind == "path" && !all[i].Conditional {
			w := all[i]
			winner = &w
		}
	}
	if winner == nil {
		e := collect.Absent("no PATH assignment in the system profile files")
		b.Set("env.shell.root_path_raw", e)
		b.Set("env.shell.root_path_entries", e)
		return
	}
	src := &facts.Source{Kind: "file", Path: winner.Path, Line: winner.Line, Raw: sourceRaw("PATH=" + winner.Value)}
	b.Set("env.shell.root_path_raw", collect.OK(winner.Value, src))
	b.Set("env.shell.root_path_entries", collect.OK(pathEntries(a, winner.Value), src))
}
