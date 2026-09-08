//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// dropinReadError is a file that EXISTS in a drop-in chain but could not be
// read. It keeps the path beside the errno so the caller can build the
// path-prefixed envelope readErrorEnv writes everywhere else; errors.Is/As
// still see the underlying error through Unwrap.
type dropinReadError struct {
	Path string
	Err  error
}

func (e *dropinReadError) Error() string { return e.Path + ": " + e.Err.Error() }
func (e *dropinReadError) Unwrap() error { return e.Err }

// dropinEnvelope turns a mergeDropins readErr into the envelope every value
// derived from that chain has to carry (C3/R148): a module's default is never
// the answer for a file that is there but this process cannot read.
func dropinEnvelope(err error) facts.Envelope {
	var de *dropinReadError
	if errors.As(err, &de) {
		return readErrorEnv(de.Path, de.Err)
	}
	return collect.ErrorEnv(err.Error())
}

// mergeDropins merges a systemd-style main configuration file with its
// drop-in directories, exactly the way systemd itself resolves one (spec's
// sysctl shadowing rule, Ruling I-5/I-19):
//
//   - the main file is applied first — a main file that is not there is not
//     an error, since the daemon's compiled-in defaults then apply;
//   - dirs are given in DESCENDING precedence (/etc, /run, /usr/local/lib,
//     /usr/lib): a file in an EARLIER directory SHADOWS a same-named file in
//     every later one, and the shadowed file is never opened or listed;
//   - the survivors are applied in lexicographic BASENAME order (10-… before
//     20-…, whichever directory each came from), last write wins.
//
// values holds every Key=Value seen, keyed by the bare key; the parser is
// section-agnostic (a caller looks a bare key up) but also records the
// qualified "Section/Key" form, so a caller that cares which section set a
// value can ask for that instead. An empty value RESETS the setting the way
// systemd does — it is stored as "", never dropped, so the reset survives
// last-write-wins. inputs lists the files actually read, in the order they
// were applied. readErr is the FIRST read error of a file that exists (R148:
// it poisons every value derived from the chain); a file that is simply
// absent is not one.
//
// The caller declares the main file and each dir's glob in its own
// Declaration.Reads — this helper never widens the declaration.
func mergeDropins(a collect.Access, main string, dirs []string, glob string) (map[string]string, []facts.Source, error) {
	values := map[string]string{}
	var inputs []facts.Source
	var readErr error
	fail := func(p string, err error) {
		if readErr == nil {
			readErr = &dropinReadError{Path: p, Err: err}
		}
	}
	read := func(p string) {
		data, _, err := a.ReadFile(p, readLimit)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				fail(p, err)
			}
			return
		}
		parseDropin(data, values)
		inputs = append(inputs, facts.Source{Kind: "file", Path: p})
	}
	read(main)

	// Shadowing: the first directory that offers a basename owns it.
	chosen := map[string]string{}
	var bases []string
	for _, d := range dirs {
		pattern := path.Join(d, glob)
		matches, err := a.Glob(pattern)
		if err != nil {
			fail(pattern, err)
			continue
		}
		slices.Sort(matches)
		for _, m := range matches {
			base := path.Base(m)
			if _, dup := chosen[base]; dup {
				continue
			}
			chosen[base] = m
			bases = append(bases, base)
		}
	}
	slices.Sort(bases)
	for _, base := range bases {
		read(chosen[base])
	}
	return values, inputs, readErr
}

// parseDropin parses systemd-style "Key=Value" lines into values, last write
// wins. Blank lines and #/; comments are skipped, a "[Section]" header is
// recorded so each key is stored under both its bare and its "Section/Key"
// name, and a line with no "=" is not a setting.
func parseDropin(data []byte, values map[string]string) {
	section := ""
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			continue
		}
		values[k] = v
		if section != "" {
			values[section+"/"+k] = v
		}
	}
}
